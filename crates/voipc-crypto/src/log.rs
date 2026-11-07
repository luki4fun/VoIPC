//! The conversation log: messages kept on the relay so they reach a member who
//! was offline, and every device of an account, while the relay reads none of
//! them (docs/ACCOUNTS.md has the bytes).
//!
//! - Each sender has, per conversation, epoch keys `K` (32 random bytes). An
//!   entry is the message envelope, the moment it was sent, and the sender's
//!   signature over both, sealed under `K` (AES-256-GCM) and bound to the
//!   conversation, the sender and the epoch.
//! - `K` reaches each member as a wrap: ECIES to the member's log key (X25519,
//!   HKDF-SHA256, AES-256-GCM), bound to conversation, owner, epoch and the
//!   recipient. The sender's wrap to itself, for its other devices, is not
//!   ECIES but sealed under a key only the account's devices hold
//!   (`self_wrap`): anyone with our public log key could make an ECIES wrap,
//!   and a key we write under must be one of our own devices made.
//! - The log key is a Curve25519 pair of its own (not the Signal identity),
//!   kept in the vault, published with a signature by the identity key, which
//!   peers check against the identity they pinned.
//!
//! What it does not do: hide who wrote to whom and when (the relay files the
//! entries), stop the relay from dropping or reordering entries, or give the
//! log forward secrecy — the vault's keys and the database together read it.
//!
//! On a relay at protocol 21 a channel writer's keys are chains and buckets
//! instead (direct conversations and older relays stay on epoch keys):
//!
//! - A chain starts from 32 random bytes and goes forward: each step mixes in
//!   32 fresh random bytes, sealed under the state before it (`Chain`). A
//!   holder reads from where it was given a state on, never below it, and a
//!   writer rolled back to an old state forks rather than hands out what
//!   followed. A new chain has no path from the old one, except a sharer's
//!   sealed back-link, which opens the older chain's start.
//! - A bucket is a random key for about 62 seats, whose members never grow: a
//!   leave makes a new version with a fresh key and a link down, anyone added
//!   gets a new bucket. A chain's state is sealed once per bucket (`Bucket`).
//! - The key reaches a member as a static wrap (`StaticKey`), and the writer's
//!   devices through the writer's own row, which also holds the digest of the
//!   sealed list of who is in the bucket.
//!
//! Every derivation takes one key in and gives one key out, so what two people
//! can open together is the union of what each can open. Every context names
//! the conversation, or a relay could carry a bucket into another channel and
//! a list's people would read there unnamed:
//!
//! ```text
//! voipc-chain/v1/<next|entry|step|link>|conv|owner|chain|index
//! voipc-seat/v1|conv|owner|bucket|version|recipient   static KEK, or self_key on the writer's own row
//! voipc-wrap/v2|conv|owner|epoch|recipient            static KEK, or self_key on the writer's own row
//! voipc-list/v1|conv|owner|bucket|version             self_key
//! voipc-seal/v1|conv|owner|bucket|version|chain|index HKDF(bucket key, "seal")
//! voipc-vlink/v1|conv|owner|bucket|new|old            HKDF(new bucket key, "vlink")
//! ```
//!
//! Each is the AAD of its row and, on a static KEK, the HKDF info too.
//!
//! A state reaches forward to the next leave. A bucket key reaches further, to
//! the next leave in its bucket, across other buckets' leaves: whoever is handed
//! one opens every chain sealed to that bucket until then.

use hkdf::Hkdf;
use libsignal_protocol::{IdentityKey, IdentityKeyPair, KeyPair, PrivateKey, PublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use voipc_protocol::conv::hex;
use zeroize::Zeroizing;

use crate::aead::random;

/// Longest a log entry may be (sealed), well under a control frame.
pub const MAX_ENTRY_BYTES: usize = 16 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum LogError {
    /// Does not decrypt: another key, or moved/altered by the relay.
    Sealed,
    /// Decrypts, but its signature is not the sender's.
    Forged,
    Malformed,
}

impl std::fmt::Display for LogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            LogError::Sealed => "a log entry or key does not decrypt",
            LogError::Forged => "a log entry is not signed by its sender",
            LogError::Malformed => "a log entry is malformed",
        })
    }
}

/// `iv (12) | ciphertext + tag`.
fn seal(key: &[u8; 32], aad: &str, plaintext: &[u8]) -> Vec<u8> {
    let (iv, ct) = crate::aead::seal(key, aad, plaintext);
    [&iv[..], &ct].concat()
}

fn open(key: &[u8; 32], aad: &str, sealed: &[u8]) -> Result<Vec<u8>, LogError> {
    if sealed.len() < 12 + 16 {
        return Err(LogError::Malformed);
    }
    crate::aead::open(key, aad, &sealed[..12], &sealed[12..]).ok_or(LogError::Sealed)
}

// ── Conversations ─────────────────────────────────────────────────────────

pub use voipc_protocol::conv::{dm_conv, dm_parties};

// ── The log key ───────────────────────────────────────────────────────────

/// An account's log key: what epoch keys are wrapped to and what entries are
/// signed with.
pub struct LogKey {
    pair: KeyPair,
}

impl LogKey {
    pub fn generate() -> LogKey {
        LogKey {
            pair: KeyPair::generate(&mut crate::rng()),
        }
    }

    /// The vault item's plaintext: the private key (32 bytes).
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.pair.private_key.serialize())
    }

    pub fn from_bytes(b: &[u8]) -> Option<LogKey> {
        let private_key = PrivateKey::deserialize(b).ok()?;
        let public_key = private_key.public_key().ok()?;
        Some(LogKey {
            pair: KeyPair::new(public_key, private_key),
        })
    }

    pub fn public(&self) -> Vec<u8> {
        self.pair.public_key.serialize().to_vec()
    }

    /// The identity's signature over this key, which peers check against the
    /// identity they pinned before trusting a wrap to it.
    pub fn endorse(&self, identity: &IdentityKeyPair) -> Vec<u8> {
        let msg = endorsement(&self.public());
        identity
            .private_key()
            .calculate_signature(&msg, &mut crate::rng())
            .expect("sign")
            .to_vec()
    }
}

fn endorsement(logkey: &[u8]) -> Vec<u8> {
    let mut m = b"voipc-logkey/v1|".to_vec();
    m.extend_from_slice(logkey);
    m
}

/// Whether `identity` endorsed `logkey` (`LogKey::endorse`).
pub fn endorsed(identity: &[u8], logkey: &[u8], signature: &[u8]) -> bool {
    match IdentityKey::decode(identity) {
        Ok(ik) => {
            log_public(logkey).is_some()
                && ik
                    .public_key()
                    .verify_signature(&endorsement(logkey), signature)
        }
        Err(_) => false,
    }
}

/// The Curve25519 points of low order, as X25519 reads them: it drops the top
/// bit. Every private key gets the same all-zero secret from these, so a wrap
/// to one would be open to anyone, and libsignal refuses to make it. Anyone
/// who published one would stop every writer in their channels from keeping
/// copies, at no cost to themselves.
const LOW_ORDER: [[u8; 32]; 7] = [
    [0; 32],
    {
        let mut u = [0; 32];
        u[0] = 1;
        u
    },
    [
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4,
        0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49,
        0xb8, 0x00,
    ],
    [
        0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef,
        0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f,
        0x11, 0x57,
    ],
    high_field_element(0xec),
    high_field_element(0xed),
    high_field_element(0xee),
];

/// `p - 1`, `p` and `p + 1`, little-endian.
const fn high_field_element(low_byte: u8) -> [u8; 32] {
    let mut u = [0xff; 32];
    u[0] = low_byte;
    u[31] = 0x7f;
    u
}

/// A log key as a key: exactly its 33 bytes, since libsignal also takes
/// trailing bytes and a signature covers them, and not of low order.
fn log_public(logkey: &[u8]) -> Option<PublicKey> {
    if logkey.len() != 33 {
        return None;
    }
    let key = PublicKey::deserialize(logkey).ok()?;
    let mut u = [0u8; 32];
    u.copy_from_slice(key.public_key_bytes());
    u[31] &= 0x7f;
    (!LOW_ORDER.contains(&u)).then_some(key)
}

// ── Wraps ─────────────────────────────────────────────────────────────────

fn wrap_ctx(conv: &str, owner: &[u8; 16], epoch: u32, recipient: &[u8; 16]) -> String {
    format!(
        "voipc-wrap/v1|{conv}|{}|{epoch}|{}",
        hex(owner),
        hex(recipient)
    )
}

/// `key` for `recipient`: `ephemeral public (33) | iv (12) | sealed key + tag (48)`.
pub fn wrap(
    recipient_logkey: &[u8],
    key: &[u8; 32],
    conv: &str,
    owner: &[u8; 16],
    epoch: u32,
    recipient: &[u8; 16],
) -> Option<Vec<u8>> {
    let them = PublicKey::deserialize(recipient_logkey).ok()?;
    let eph = KeyPair::generate(&mut crate::rng());
    let shared = Zeroizing::new(eph.private_key.calculate_agreement(&them).ok()?.to_vec());
    let eph_pub = eph.public_key.serialize();
    let ctx = wrap_ctx(conv, owner, epoch, recipient);
    let mut salt = eph_pub.to_vec();
    salt.extend_from_slice(recipient_logkey);
    let mut kek = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(&salt), &shared)
        .expand(ctx.as_bytes(), &mut *kek)
        .ok()?;
    let mut out = eph_pub.to_vec();
    out.extend_from_slice(&seal(&kek, &ctx, key));
    Some(out)
}

pub fn unwrap(
    own: &LogKey,
    wrapped: &[u8],
    conv: &str,
    owner: &[u8; 16],
    epoch: u32,
    recipient: &[u8; 16],
) -> Result<[u8; 32], LogError> {
    if wrapped.len() != 33 + 12 + 48 {
        return Err(LogError::Malformed);
    }
    let eph = PublicKey::deserialize(&wrapped[..33]).map_err(|_| LogError::Malformed)?;
    let shared = Zeroizing::new(
        own.pair
            .private_key
            .calculate_agreement(&eph)
            .map_err(|_| LogError::Malformed)?
            .to_vec(),
    );
    let ctx = wrap_ctx(conv, owner, epoch, recipient);
    let mut salt = wrapped[..33].to_vec();
    salt.extend_from_slice(&own.public());
    let mut kek = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(&salt), &shared)
        .expand(ctx.as_bytes(), &mut *kek)
        .map_err(|_| LogError::Malformed)?;
    open(&kek, &ctx, &wrapped[33..])?
        .try_into()
        .map_err(|_| LogError::Malformed)
}

/// The key our own devices seal what is only ours for each other under: from
/// the log key's private half, which only the account's vault holds.
fn self_key(own: &LogKey) -> Zeroizing<[u8; 32]> {
    let mut k = Zeroizing::new([0u8; 32]);
    let private = Zeroizing::new(own.pair.private_key.serialize());
    Hkdf::<Sha256>::new(None, &private)
        .expand(b"voipc-selfwrap/v1", &mut *k)
        .expect("32 bytes is a valid HKDF length");
    k
}

/// Our epoch `key` for our other devices: `iv (12) | sealed key + tag (48)`.
pub fn self_wrap(own: &LogKey, key: &[u8; 32], conv: &str, me: &[u8; 16], epoch: u32) -> Vec<u8> {
    seal(&self_key(own), &wrap_ctx(conv, me, epoch, me), key)
}

/// One of our own epoch keys back. An ECIES wrap made from our public key —
/// which the relay can make — does not open here.
pub fn self_unwrap(
    own: &LogKey,
    wrapped: &[u8],
    conv: &str,
    me: &[u8; 16],
    epoch: u32,
) -> Result<[u8; 32], LogError> {
    if wrapped.len() != 12 + 48 {
        return Err(LogError::Malformed);
    }
    open(&self_key(own), &wrap_ctx(conv, me, epoch, me), wrapped)?
        .try_into()
        .map_err(|_| LogError::Malformed)
}

/// A fresh epoch key, chain start or bucket key.
pub fn epoch_key() -> Zeroizing<[u8; 32]> {
    Zeroizing::new(random())
}

// ── Static wraps ──────────────────────────────────────────────────────────

/// A row sealing one key: `iv (12) | sealed key + tag (48)`.
pub const ROW_BYTES: usize = 12 + 48;
/// The writer's own row of a bucket: `iv (12) | sealed key and digest + tag (80)`.
pub const OWN_ROW_BYTES: usize = 12 + 80;

/// A row that opens for nobody: all a writer can give a member it cannot reach, which
/// counts as a row at the relay, so that member stops nobody's posts. Random, so a relay
/// cannot tell it from a real one.
pub fn blank_row() -> Vec<u8> {
    let row: [u8; ROW_BYTES] = random();
    row.to_vec()
}

fn hkdf32(salt: Option<&[u8]>, ikm: &[u8], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut k = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(salt, ikm)
        .expand(info, &mut *k)
        .expect("32 bytes is a valid HKDF length");
    k
}

fn open_row(key: &[u8; 32], ctx: &str, row: &[u8]) -> Result<Zeroizing<[u8; 32]>, LogError> {
    if row.len() != ROW_BYTES {
        return Err(LogError::Malformed);
    }
    let plain = Zeroizing::new(open(key, ctx, row)?);
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&plain);
    Ok(out)
}

fn state_ctx(conv: &str, owner: &[u8; 16], epoch: u32, recipient: &[u8; 16]) -> String {
    format!(
        "voipc-wrap/v2|{conv}|{}|{epoch}|{}",
        hex(owner),
        hex(recipient)
    )
}

/// What one X25519 with a peer's log key gives, kept per peer for the
/// connection. Rows are `iv | sealed key + tag` under
/// `HKDF-SHA256(salt = owner_pub | recipient_pub, ikm = X25519, info = ctx)`.
///
/// Both ends hold the same secret, so the salt and the context are all that
/// keep a row to them from reading as a row from them. The IV stays random: a
/// writer rolled back seals two states at one context, and under a fixed nonce
/// a reader given one recovers the other. Only the two of them can make a row,
/// where anyone with the public key can make an ECIES wrap.
pub struct StaticKey {
    shared: Zeroizing<Vec<u8>>,
    own: Box<[u8]>,
    them: Box<[u8]>,
}

impl StaticKey {
    /// `None` for what is no log key, and one of low order.
    pub fn new(own: &LogKey, their_logkey: &[u8]) -> Option<StaticKey> {
        let them = log_public(their_logkey)?;
        let shared = own.pair.private_key.calculate_agreement(&them).ok()?;
        Some(StaticKey {
            shared: Zeroizing::new(shared.into_vec()),
            own: own.pair.public_key.serialize(),
            them: them.serialize(),
        })
    }

    fn kek(&self, owner: &[u8], recipient: &[u8], ctx: &str) -> Zeroizing<[u8; 32]> {
        hkdf32(
            Some(&[owner, recipient].concat()),
            &self.shared,
            ctx.as_bytes(),
        )
    }

    fn seal_to_them(&self, ctx: &str, key: &[u8; 32]) -> Vec<u8> {
        seal(&self.kek(&self.own, &self.them, ctx), ctx, key)
    }

    fn open_from_them(&self, ctx: &str, row: &[u8]) -> Result<Zeroizing<[u8; 32]>, LogError> {
        open_row(&self.kek(&self.them, &self.own, ctx), ctx, row)
    }

    /// A bucket key for them: their seat row. `at.owner` is us.
    pub fn wrap_seat(&self, key: &[u8; 32], at: Bucket, recipient: &[u8; 16]) -> Vec<u8> {
        self.seal_to_them(&at.seat_ctx(recipient), key)
    }

    /// Their bucket key out of a seat row to us. `at.owner` is them.
    pub fn open_seat(
        &self,
        row: &[u8],
        at: Bucket,
        me: &[u8; 16],
    ) -> Result<Zeroizing<[u8; 32]>, LogError> {
        self.open_from_them(&at.seat_ctx(me), row)
    }

    /// A chain state for them: their direct row.
    pub fn wrap_state(
        &self,
        state: &[u8; 32],
        conv: &str,
        me: &[u8; 16],
        epoch: u32,
        recipient: &[u8; 16],
    ) -> Vec<u8> {
        self.seal_to_them(&state_ctx(conv, me, epoch, recipient), state)
    }

    /// Their chain state out of a direct row to us. Only the static shape
    /// opens: the relay can make an ECIES wrap to our key, and it must not get
    /// to choose a state we adopt.
    pub fn open_state(
        &self,
        row: &[u8],
        conv: &str,
        owner: &[u8; 16],
        epoch: u32,
        me: &[u8; 16],
    ) -> Result<Zeroizing<[u8; 32]>, LogError> {
        self.open_from_them(&state_ctx(conv, owner, epoch, me), row)
    }

    /// Whether our direct row to them proves they hold index 0 of `chain`: it
    /// opens at that index, to the start we hold. Never the relay's word for
    /// who holds what.
    pub fn row_holds_start(
        &self,
        row: &[u8],
        conv: &str,
        me: &[u8; 16],
        chain: u32,
        recipient: &[u8; 16],
        start: &[u8; 32],
    ) -> bool {
        let Some(epoch) = chain_epoch(chain, 0) else {
            return false;
        };
        let ctx = state_ctx(conv, me, epoch, recipient);
        open_row(&self.kek(&self.own, &self.them, &ctx), &ctx, row).is_ok_and(|s| *s == *start)
    }
}

/// A chain's start for our other devices: the chain's self-wrap, under the same
/// key as `self_wrap` and another label, so a random epoch key is never taken
/// for a chain state.
pub fn self_wrap_state(
    own: &LogKey,
    state: &[u8; 32],
    conv: &str,
    me: &[u8; 16],
    epoch: u32,
) -> Vec<u8> {
    seal(&self_key(own), &state_ctx(conv, me, epoch, me), state)
}

pub fn self_open_state(
    own: &LogKey,
    row: &[u8],
    conv: &str,
    me: &[u8; 16],
    epoch: u32,
) -> Result<Zeroizing<[u8; 32]>, LogError> {
    open_row(&self_key(own), &state_ctx(conv, me, epoch, me), row)
}

// ── Chains ────────────────────────────────────────────────────────────────

pub const MAX_CHAIN: u32 = (1 << 20) - 1;
pub const MAX_CHAIN_INDEX: u32 = (1 << 12) - 1;

/// The wire's `epoch` for a chain state: chain (20 bits), index (12 bits).
/// `None` past either, where the writer starts a new chain.
pub fn chain_epoch(chain: u32, index: u32) -> Option<u32> {
    (chain <= MAX_CHAIN && index <= MAX_CHAIN_INDEX).then_some(chain << 12 | index)
}

/// `(chain, index)` of an `epoch`.
pub fn epoch_parts(epoch: u32) -> (u32, u32) {
    (epoch >> 12, epoch & MAX_CHAIN_INDEX)
}

/// One writer's chain in one conversation.
#[derive(Clone, Copy)]
pub struct Chain<'a> {
    pub conv: &'a str,
    pub owner: &'a [u8; 16],
    pub chain: u32,
}

impl Chain<'_> {
    fn ctx(&self, label: &str, index: u32) -> String {
        format!(
            "voipc-chain/v1/{label}|{}|{}|{}|{index}",
            self.conv,
            hex(self.owner),
            self.chain
        )
    }

    fn key(&self, label: &str, index: u32, state: &[u8; 32]) -> Zeroizing<[u8; 32]> {
        hkdf32(None, state, self.ctx(label, index).as_bytes())
    }

    fn next(&self, index: u32, state: &[u8; 32], r: &[u8; 32]) -> Zeroizing<[u8; 32]> {
        hkdf32(Some(r), state, self.ctx("next", index + 1).as_bytes())
    }

    /// From `state` at `index`: the state at `index + 1`, and the row a holder
    /// of `state` follows it by. Fresh randomness each time: under a plain
    /// hash, a writer the relay rolled back would hand a listener it names
    /// every state since.
    pub fn step(&self, index: u32, state: &[u8; 32]) -> (Zeroizing<[u8; 32]>, Vec<u8>) {
        let r = Zeroizing::new(random::<32>());
        let row = seal(
            &self.key("step", index, state),
            &self.ctx("step", index),
            &*r,
        );
        (self.next(index, state, &r), row)
    }

    /// The state at `index + 1`, from the one at `index` and that step's row.
    pub fn follow(
        &self,
        index: u32,
        state: &[u8; 32],
        row: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, LogError> {
        let r = open_row(
            &self.key("step", index, state),
            &self.ctx("step", index),
            row,
        )?;
        Ok(self.next(index, state, &r))
    }

    fn link_aad(&self, older: u32) -> String {
        format!("{}|{older}", self.ctx("link", 0))
    }

    /// The back-link of a sharer's chain: whoever holds this chain's start also
    /// opens `older`'s. So it must not reach anyone who joined under the switch
    /// off, who is given index 1 of this chain instead.
    pub fn link(&self, start: &[u8; 32], older: u32, older_start: &[u8; 32]) -> Vec<u8> {
        seal(
            &self.key("link", 0, start),
            &self.link_aad(older),
            older_start,
        )
    }

    pub fn open_link(
        &self,
        start: &[u8; 32],
        older: u32,
        row: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, LogError> {
        open_row(&self.key("link", 0, start), &self.link_aad(older), row)
    }
}

// ── Buckets ───────────────────────────────────────────────────────────────

/// A new bucket's id: 64 random bits.
pub fn bucket_id() -> u64 {
    u64::from_be_bytes(random())
}

/// One version of one of a writer's buckets in one conversation.
#[derive(Clone, Copy)]
pub struct Bucket<'a> {
    pub conv: &'a str,
    pub owner: &'a [u8; 16],
    pub id: u64,
    pub version: u32,
}

/// A seat on a bucket's list. The tag is of the log key they held: someone new
/// on that account (`admin reclaim`) shows as someone new, and is named.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ListedSeat {
    pub account: [u8; 16],
    pub key_tag: [u8; 8],
}

impl ListedSeat {
    pub fn new(account: &[u8; 16], logkey: &[u8]) -> ListedSeat {
        let d = Sha256::new()
            .chain_update(b"voipc-list/v1/key|")
            .chain_update(logkey)
            .finalize();
        ListedSeat {
            account: *account,
            key_tag: d[..8].try_into().expect("8 bytes"),
        }
    }
}

impl Bucket<'_> {
    fn seat_ctx(&self, recipient: &[u8; 16]) -> String {
        format!(
            "voipc-seat/v1|{}|{}|{}|{}|{}",
            self.conv,
            hex(self.owner),
            self.id,
            self.version,
            hex(recipient)
        )
    }

    fn list_ctx(&self) -> String {
        format!(
            "voipc-list/v1|{}|{}|{}|{}",
            self.conv,
            hex(self.owner),
            self.id,
            self.version
        )
    }

    fn seal_ctx(&self, chain: u32, index: u32) -> String {
        format!(
            "voipc-seal/v1|{}|{}|{}|{}|{chain}|{index}",
            self.conv,
            hex(self.owner),
            self.id,
            self.version
        )
    }

    fn version_link_ctx(&self, old: u32) -> String {
        format!(
            "voipc-vlink/v1|{}|{}|{}|{}|{old}",
            self.conv,
            hex(self.owner),
            self.id,
            self.version
        )
    }

    /// The writer's own row: how its other devices get the key back, and the
    /// digest of the list, which tells a device whether it has named this list
    /// yet without fetching it.
    pub fn own_row(&self, own: &LogKey, key: &[u8; 32], digest: &[u8; 32]) -> Vec<u8> {
        let plain = Zeroizing::new([&key[..], &digest[..]].concat());
        seal(&self_key(own), &self.seat_ctx(self.owner), &plain)
    }

    /// The bucket key and the digest of its list.
    pub fn open_own_row(
        &self,
        own: &LogKey,
        row: &[u8],
    ) -> Result<(Zeroizing<[u8; 32]>, [u8; 32]), LogError> {
        if row.len() != OWN_ROW_BYTES {
            return Err(LogError::Malformed);
        }
        let plain = Zeroizing::new(open(&self_key(own), &self.seat_ctx(self.owner), row)?);
        let (key, digest) = plain.split_at(32);
        let mut k = Zeroizing::new([0u8; 32]);
        k.copy_from_slice(key);
        Ok((k, digest.try_into().map_err(|_| LogError::Malformed)?))
    }

    /// The digest binds the context too, so one set of people in two channels
    /// has two digests, and naming them in one is not naming them in the other.
    fn list_digest(&self, records: &[u8]) -> [u8; 32] {
        let ctx = self.list_ctx();
        Sha256::new()
            .chain_update((ctx.len() as u32).to_be_bytes())
            .chain_update(&ctx)
            .chain_update(records)
            .finalize()
            .into()
    }

    /// Who is in this version, in the writer's own word, and its digest for the
    /// writer's own row.
    pub fn seal_list(&self, own: &LogKey, seats: &[ListedSeat]) -> (Vec<u8>, [u8; 32]) {
        let mut seats = seats.to_vec();
        seats.sort_unstable();
        seats.dedup();
        let records: Vec<u8> = seats
            .iter()
            .flat_map(|s| s.account.into_iter().chain(s.key_tag))
            .collect();
        (
            seal(&self_key(own), &self.list_ctx(), &records),
            self.list_digest(&records),
        )
    }

    /// The list the writer's own row names: no other list opens as it, whatever
    /// a rolled-back relay has kept at this version.
    pub fn open_list(
        &self,
        own: &LogKey,
        sealed: &[u8],
        digest: &[u8; 32],
    ) -> Result<Vec<ListedSeat>, LogError> {
        let records = open(&self_key(own), &self.list_ctx(), sealed)?;
        if self.list_digest(&records) != *digest {
            return Err(LogError::Sealed);
        }
        let (seats, rest) = records.as_chunks::<24>();
        if !rest.is_empty() {
            return Err(LogError::Malformed);
        }
        Ok(seats
            .iter()
            .map(|s| {
                let (account, key_tag) = s.split_at(16);
                ListedSeat {
                    account: account.try_into().expect("16 bytes"),
                    key_tag: key_tag.try_into().expect("8 bytes"),
                }
            })
            .collect())
    }

    /// A chain's state for everyone in this version: `chain`'s row at `index`.
    pub fn seal_state(&self, key: &[u8; 32], chain: u32, index: u32, state: &[u8; 32]) -> Vec<u8> {
        seal(
            &hkdf32(None, key, b"seal"),
            &self.seal_ctx(chain, index),
            state,
        )
    }

    pub fn open_seal(
        &self,
        key: &[u8; 32],
        chain: u32,
        index: u32,
        row: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, LogError> {
        open_row(
            &hkdf32(None, key, b"seal"),
            &self.seal_ctx(chain, index),
            row,
        )
    }

    /// Whether this version's members held index 0 of `chain`: its seal there
    /// opens at that index, to the start we hold. Never the relay's word, and
    /// not a flag on the bucket, which a relay hiding all history once could
    /// earn falsely.
    pub fn seal_holds_start(
        &self,
        key: &[u8; 32],
        chain: u32,
        row: &[u8],
        start: &[u8; 32],
    ) -> bool {
        self.open_seal(key, chain, 0, row)
            .is_ok_and(|s| *s == *start)
    }

    /// This version's way down to `old`: everyone in this version held that
    /// one, since a bucket never grows. `key` is this version's.
    pub fn link_down(&self, key: &[u8; 32], old: u32, old_key: &[u8; 32]) -> Vec<u8> {
        seal(
            &hkdf32(None, key, b"vlink"),
            &self.version_link_ctx(old),
            old_key,
        )
    }

    pub fn open_link_down(
        &self,
        key: &[u8; 32],
        old: u32,
        row: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, LogError> {
        open_row(
            &hkdf32(None, key, b"vlink"),
            &self.version_link_ctx(old),
            row,
        )
    }
}

// ── Entries ───────────────────────────────────────────────────────────────

/// What a log entry carries, signed by the sender's log key.
#[derive(Serialize, Deserialize)]
struct Payload {
    /// The message envelope (`envelope::envelope`): id, text, timer.
    envelope: Vec<u8>,
    /// When the sender sent it (Unix ms). The receiver counts a timer from
    /// the earlier of this and the relay's own stamp: neither side can make a
    /// message outlive its timer.
    sent_at: u64,
    sig: Vec<u8>,
}

fn entry_aad(conv: &str, sender: &[u8; 16], epoch: u32) -> String {
    format!("voipc-log/v1|{conv}|{}|{epoch}", hex(sender))
}

fn chain_entry_aad(conv: &str, sender: &[u8; 16], epoch: u32) -> String {
    format!("voipc-log/v2|{conv}|{}|{epoch}", hex(sender))
}

fn signed_part(aad: &str, sent_at: u64, envelope: &[u8]) -> Vec<u8> {
    let mut m = aad.as_bytes().to_vec();
    m.push(b'|');
    m.extend_from_slice(&sent_at.to_be_bytes());
    m.extend_from_slice(envelope);
    m
}

fn seal_entry_under(
    key: &[u8; 32],
    aad: &str,
    signer: &LogKey,
    envelope: &[u8],
    sent_at: u64,
) -> Vec<u8> {
    let sig = signer
        .pair
        .calculate_signature(&signed_part(aad, sent_at, envelope), &mut crate::rng())
        .expect("sign")
        .to_vec();
    let payload = postcard::to_allocvec(&Payload {
        envelope: envelope.to_vec(),
        sent_at,
        sig,
    })
    .expect("encodes");
    seal(key, aad, &payload)
}

fn open_entry_under(
    key: &[u8; 32],
    aad: &str,
    sender_logkey: &[u8],
    sealed: &[u8],
) -> Result<(Vec<u8>, u64), LogError> {
    let plain = open(key, aad, sealed)?;
    let p: Payload = postcard::from_bytes(&plain).map_err(|_| LogError::Malformed)?;
    let pk = PublicKey::deserialize(sender_logkey).map_err(|_| LogError::Malformed)?;
    if !pk.verify_signature(&signed_part(aad, p.sent_at, &p.envelope), &p.sig) {
        return Err(LogError::Forged);
    }
    Ok((p.envelope, p.sent_at))
}

/// A log entry's sealed bytes.
pub fn seal_entry(
    key: &[u8; 32],
    conv: &str,
    sender: &[u8; 16],
    epoch: u32,
    signer: &LogKey,
    envelope: &[u8],
    sent_at: u64,
) -> Vec<u8> {
    let aad = entry_aad(conv, sender, epoch);
    seal_entry_under(key, &aad, signer, envelope, sent_at)
}

/// An entry opened and its signature checked against the sender's log key:
/// the envelope and when it was sent.
pub fn open_entry(
    key: &[u8; 32],
    conv: &str,
    sender: &[u8; 16],
    epoch: u32,
    sender_logkey: &[u8],
    sealed: &[u8],
) -> Result<(Vec<u8>, u64), LogError> {
    open_entry_under(key, &entry_aad(conv, sender, epoch), sender_logkey, sealed)
}

fn chain_entry_key(
    state: &[u8; 32],
    conv: &str,
    sender: &[u8; 16],
    epoch: u32,
) -> Zeroizing<[u8; 32]> {
    let (chain, index) = epoch_parts(epoch);
    let at = Chain {
        conv,
        owner: sender,
        chain,
    };
    at.key("entry", index, state)
}

/// `seal_entry` on a chain, under the entry key of the `state` at `epoch`.
pub fn seal_chain_entry(
    state: &[u8; 32],
    conv: &str,
    sender: &[u8; 16],
    epoch: u32,
    signer: &LogKey,
    envelope: &[u8],
    sent_at: u64,
) -> Vec<u8> {
    let key = chain_entry_key(state, conv, sender, epoch);
    let aad = chain_entry_aad(conv, sender, epoch);
    seal_entry_under(&key, &aad, signer, envelope, sent_at)
}

/// `open_entry` on a chain.
pub fn open_chain_entry(
    state: &[u8; 32],
    conv: &str,
    sender: &[u8; 16],
    epoch: u32,
    sender_logkey: &[u8],
    sealed: &[u8],
) -> Result<(Vec<u8>, u64), LogError> {
    let key = chain_entry_key(state, conv, sender, epoch);
    let aad = chain_entry_aad(conv, sender, epoch);
    open_entry_under(&key, &aad, sender_logkey, sealed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: [u8; 16] = [1; 16];
    const B: [u8; 16] = [2; 16];

    #[test]
    fn a_log_key_is_endorsed_by_its_identity_only() {
        let id = IdentityKeyPair::generate(&mut crate::rng());
        let other = IdentityKeyPair::generate(&mut crate::rng());
        let lk = LogKey::generate();
        let sig = lk.endorse(&id);
        assert!(endorsed(&id.public_key().serialize(), &lk.public(), &sig));
        assert!(
            !endorsed(&other.public_key().serialize(), &lk.public(), &sig),
            "another identity's"
        );
        assert!(
            !endorsed(
                &id.public_key().serialize(),
                &LogKey::generate().public(),
                &sig
            ),
            "another key"
        );
        let again = LogKey::from_bytes(&lk.to_bytes()).unwrap();
        assert_eq!(again.public(), lk.public());
    }

    #[test]
    fn a_wrap_opens_for_its_recipient_and_its_context_only() {
        let (alice, bob) = (LogKey::generate(), LogKey::generate());
        let k = epoch_key();
        let c = dm_conv(&A, &B);
        let w = wrap(&bob.public(), &k, &c, &A, 1, &B).unwrap();
        assert_eq!(unwrap(&bob, &w, &c, &A, 1, &B).unwrap(), *k);
        assert_eq!(
            unwrap(&alice, &w, &c, &A, 1, &B).err(),
            Some(LogError::Sealed),
            "not alice's"
        );
        assert_eq!(
            unwrap(&bob, &w, &c, &A, 2, &B).err(),
            Some(LogError::Sealed),
            "another epoch"
        );
        assert_eq!(
            unwrap(&bob, &w, &c, &B, 1, &B).err(),
            Some(LogError::Sealed),
            "another owner"
        );
        assert_eq!(
            unwrap(&bob, &w, "d:x", &A, 1, &B).err(),
            Some(LogError::Sealed),
            "another conversation"
        );
    }

    #[test]
    fn a_self_wrap_opens_for_our_own_devices_only() {
        let (me, other) = (LogKey::generate(), LogKey::generate());
        let k = epoch_key();
        let c = dm_conv(&A, &B);
        let w = self_wrap(&me, &k, &c, &A, 7);
        assert_eq!(w.len(), 60, "under the relay's 128-byte bound for a wrap");
        let again = LogKey::from_bytes(&me.to_bytes()).unwrap();
        assert_eq!(
            self_unwrap(&again, &w, &c, &A, 7).unwrap(),
            *k,
            "another device of the same account"
        );
        assert_eq!(
            self_unwrap(&other, &w, &c, &A, 7).err(),
            Some(LogError::Sealed),
            "another account's"
        );
        assert_eq!(
            self_unwrap(&me, &w, &c, &A, 8).err(),
            Some(LogError::Sealed),
            "another epoch"
        );
        assert_eq!(
            self_unwrap(&me, &w, "d:x", &A, 7).err(),
            Some(LogError::Sealed),
            "another conversation"
        );
        // What the relay can make: an ECIES wrap to our public log key, "from us".
        let forged = wrap(&me.public(), &epoch_key(), &c, &A, 7, &A).unwrap();
        assert!(
            self_unwrap(&me, &forged, &c, &A, 7).is_err(),
            "an ECIES wrap is never one of our own"
        );
    }

    #[test]
    fn an_entry_opens_with_its_key_and_proves_its_sender() {
        let (alice, mallory) = (LogKey::generate(), LogKey::generate());
        let k = epoch_key();
        let c = dm_conv(&A, &B);
        let env = crate::envelope::envelope("id1", "hello", Some(60));
        let sealed = seal_entry(&k, &c, &A, 1, &alice, &env, 1_700_000_000_000);
        let (back, at) = open_entry(&k, &c, &A, 1, &alice.public(), &sealed).unwrap();
        assert_eq!((back, at), (env.clone(), 1_700_000_000_000));
        // Moved to another conversation, sender or epoch by the relay: does not open.
        assert_eq!(
            open_entry(&k, "d:other", &A, 1, &alice.public(), &sealed).err(),
            Some(LogError::Sealed)
        );
        assert_eq!(
            open_entry(&k, &c, &B, 1, &alice.public(), &sealed).err(),
            Some(LogError::Sealed)
        );
        // A member holding K cannot write as alice: their signature is not hers.
        let forged = seal_entry(&k, &c, &A, 1, &mallory, &env, 1);
        assert_eq!(
            open_entry(&k, &c, &A, 1, &alice.public(), &forged).err(),
            Some(LogError::Forged)
        );
    }

    // ── Chains, buckets, static wraps ─────────────────────────────────────

    const KAT_CONV: &str = "c:kat";
    const KAT_CHAIN: Chain = Chain {
        conv: KAT_CONV,
        owner: &A,
        chain: 5,
    };
    const KAT_BUCKET: Bucket = Bucket {
        conv: KAT_CONV,
        owner: &A,
        id: 0x0123_4567_89ab_cdef,
        version: 3,
    };

    /// `from, from + 1, ...`: the known answers' inputs.
    fn run(from: u8) -> [u8; 32] {
        std::array::from_fn(|i| from + i as u8)
    }

    fn kat_writer() -> LogKey {
        LogKey::from_bytes(&run(192)).unwrap()
    }

    fn kat_reader() -> LogKey {
        LogKey::from_bytes(&run(224)).unwrap()
    }

    fn bytes(h: &str) -> Vec<u8> {
        (0..h.len() / 2)
            .map(|i| u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    /// From Python's hashlib and hmac, not from this code, and the same as the
    /// table in the design: an app that changes these cannot read what another
    /// wrote.
    #[test]
    fn chain_known_answers() {
        let (s0, r1, r2) = (run(0), run(32), run(64));
        let c = KAT_CHAIN;
        assert_eq!(
            c.ctx("next", 1),
            "voipc-chain/v1/next|c:kat|01010101010101010101010101010101|5|1"
        );
        let s1 = c.next(0, &s0, &r1);
        let s2 = c.next(1, &s1, &r2);
        assert_eq!(
            hex(&*s1),
            "492c47dd577aa3e3115b4ee26593b1dad7ab8e7737a5031214f79008e2d22129"
        );
        assert_eq!(
            hex(&*s2),
            "f89395f68f8daeb484028d97cfb98b0bd9c49e3f9b4f44f670dc8a25a485c877"
        );
        for (label, index, state, known) in [
            (
                "entry",
                0,
                &s0,
                "eb3cd4cdf33a7b0075eea0fc1aa94de0788135caefe9a73f5c1fd36eac312a6d",
            ),
            (
                "entry",
                1,
                &*s1,
                "8fd0c7fe0f08ec1fc5d96d00dbaae4fcb7d006feb0be1a82f50b2cf4cc2ea839",
            ),
            (
                "step",
                0,
                &s0,
                "5ee6bbcf28ec95d7eb94b5108d8a3b32fa60795b30bcbae8093df32676c28a0b",
            ),
            (
                "step",
                1,
                &*s1,
                "dcefec1634a043de7e7bae7c73a36b584933eac969d65cb779e6ebdd1919fd91",
            ),
            (
                "link",
                0,
                &s0,
                "e1b378eedca90ea71ba4f65ad8a0e1ac2776ce95c6a03475e9a5bb38277b033c",
            ),
        ] {
            assert_eq!(hex(&*c.key(label, index, state)), known, "{label} {index}");
        }
        assert_eq!(
            hex(&*chain_entry_key(&s1, KAT_CONV, &A, 0x5001)),
            "8fd0c7fe0f08ec1fc5d96d00dbaae4fcb7d006feb0be1a82f50b2cf4cc2ea839",
            "an entry's epoch is that chain and index"
        );
        assert_eq!(
            chain_entry_aad(KAT_CONV, &A, 0x5001),
            "voipc-log/v2|c:kat|01010101010101010101010101010101|20481"
        );
    }

    /// The same, with X25519 from an RFC 7748 ladder written in Python and
    /// checked against the RFC's vectors.
    #[test]
    fn static_kek_known_answers() {
        let (w, r) = (kat_writer(), kat_reader());
        let w_pub = "05dc2cca31e8e43bbd91dff7e475cca3347eb478107d5bd765aba4ae4a30c35d44";
        let r_pub = "05736845d54e87de09d6bb114aa7042c50a4a015bd9901d1a0026f5956533a1519";
        assert_eq!(hex(&w.public()), w_pub);
        assert_eq!(hex(&r.public()), r_pub);
        let (w_pub, r_pub) = (bytes(w_pub), bytes(r_pub));
        let from_w = StaticKey::new(&w, &r_pub).unwrap();
        let from_r = StaticKey::new(&r, &w_pub).unwrap();
        for k in [&from_w, &from_r] {
            assert_eq!(
                hex(&k.shared),
                "28150aa20f6f6c9c8177b9deded7464ebc5aac96029777ff7503cd8e8ca7143e"
            );
        }
        let seat = KAT_BUCKET.seat_ctx(&B);
        assert_eq!(
            seat,
            "voipc-seat/v1|c:kat|01010101010101010101010101010101|81985529216486895|3|\
             02020202020202020202020202020202"
        );
        let direct = state_ctx(KAT_CONV, &A, 0x5001, &B);
        assert_eq!(
            direct,
            "voipc-wrap/v2|c:kat|01010101010101010101010101010101|20481|\
             02020202020202020202020202020202"
        );
        let known_seat = "09aa05525492ab12aa82be2fcfb0bebb4bff30d8063f55d964b08b0d7ac79d50";
        assert_eq!(hex(&*from_w.kek(&w_pub, &r_pub, &seat)), known_seat);
        assert_eq!(hex(&*from_r.kek(&w_pub, &r_pub, &seat)), known_seat);
        assert_eq!(
            hex(&*from_w.kek(&w_pub, &r_pub, &direct)),
            "da9f729a42063dca4c8beac0ce29553efcf27174aa022b14db2004428e7be840"
        );
        assert_eq!(
            hex(&*from_w.kek(&r_pub, &w_pub, &seat)),
            "786714ee51b30752ac06abf70065502263b4f3d98985938f2d38a88f5d922ebf",
            "the same secret the other way round is another key"
        );
    }

    #[test]
    fn bucket_known_answers() {
        let (w, r) = (kat_writer(), kat_reader());
        let at = KAT_BUCKET;
        assert_eq!(
            hex(&w.to_bytes()),
            "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcddde5f",
            "the clamped private key is what self_key takes"
        );
        assert_eq!(
            hex(&*self_key(&w)),
            "7438dbec8c96d71b6b42089e70520f7b6b1a02daf627cb1eba658ee77935f872"
        );
        let bk = run(128);
        assert_eq!(
            hex(&*hkdf32(None, &bk, b"seal")),
            "485c075a91b8cabc701a2309cf5c8dd03233de18f41d931d713e5bf1d73f71a1"
        );
        assert_eq!(
            hex(&*hkdf32(None, &bk, b"vlink")),
            "3b2045c14daebc8459f8b8a0a173a10432074906514bafcc2a8e45e6b970e823"
        );
        assert_eq!(
            at.list_ctx(),
            "voipc-list/v1|c:kat|01010101010101010101010101010101|81985529216486895|3"
        );
        assert_eq!(
            at.seal_ctx(5, 1),
            "voipc-seal/v1|c:kat|01010101010101010101010101010101|81985529216486895|3|5|1"
        );
        assert_eq!(
            at.version_link_ctx(2),
            "voipc-vlink/v1|c:kat|01010101010101010101010101010101|81985529216486895|3|2"
        );
        let (me, them) = (
            ListedSeat::new(&A, &w.public()),
            ListedSeat::new(&B, &r.public()),
        );
        assert_eq!(hex(&me.key_tag), "5148db5042078a68");
        assert_eq!(hex(&them.key_tag), "6f4ba2b7a6de67b3");
        let (sealed, digest) = at.seal_list(&w, &[them, me, them]);
        assert_eq!(
            hex(&digest),
            "cda31659490f4bd03589d56955e731adea3a7ca3a2f4bff10378ff5bccc5acd3",
            "over the context and the seats in order, once each"
        );
        assert_eq!(at.open_list(&w, &sealed, &digest).unwrap(), [me, them]);
    }

    /// Sealed by OpenSSL through node, under the keys above and each row's
    /// context as AAD, at a fixed IV: so the layout and the AAD are pinned by
    /// something other than this code's own seal.
    #[test]
    fn rows_from_outside_this_code_open() {
        let (w, r) = (kat_writer(), kat_reader());
        let (at, c) = (KAT_BUCKET, KAT_CHAIN);
        let from_w = StaticKey::new(&r, &w.public()).unwrap();
        let bk = run(128);
        let digest: [u8; 32] =
            bytes("cda31659490f4bd03589d56955e731adea3a7ca3a2f4bff10378ff5bccc5acd3")
                .try_into()
                .unwrap();
        let s1 = c.next(0, &run(0), &run(32));

        let seat = bytes(
            "0c0d0e0f101112131415161732932642c50e4551dcb1731f0d713edc2c5b62ab\
             2aa768950462f3676a226f3c40cf2c29c6978a2fc547c81804c88b78",
        );
        assert_eq!(*from_w.open_seat(&seat, at, &B).unwrap(), bk);
        let direct = bytes(
            "0c0d0e0f1011121314151617806201fe2e4d7b0e64d37651070174e5bbda6a52\
             c7df6c9145d7b1d4505d6419e0f0b52e8bb4399f43369c4f4a576320",
        );
        assert_eq!(
            *from_w
                .open_state(&direct, KAT_CONV, &A, 0x5001, &B)
                .unwrap(),
            *s1
        );
        let own = bytes(
            "0c0d0e0f10111213141516173d62a3188431935d94e970a181cf9586b55d4ec2\
             ba54b316bc67c30414eeb99410272485b841e77bea17022c2d4451548215ebd4\
             50c3fd66dde74a0f964ff96981ffc3e8351b209d84e00de99fa0280e",
        );
        let (key, named) = at.open_own_row(&w, &own).unwrap();
        assert_eq!((*key, named), (bk, digest));
        let self_state = bytes(
            "0c0d0e0f1011121314151617bde2239804b113dd1469f021014f150635ddce42\
             3ad433963ce74384946e3914f476ec73116af8a7db021f72ca2cba09",
        );
        assert_eq!(
            *self_open_state(&w, &self_state, KAT_CONV, &A, 0x5000).unwrap(),
            run(0)
        );
        let list = bytes(
            "0c0d0e0f1011121314151617bce2209a01b514db1d61fb2b0c431a0874840701\
             6cc6afe926fc5b9d8a712509df8630def34caea9b0d575f2de7d074a9d9bb2da\
             1e02d1dd7ac81265f5570aa0",
        );
        assert_eq!(
            at.open_list(&w, &list, &digest).unwrap(),
            [
                ListedSeat::new(&A, &w.public()),
                ListedSeat::new(&B, &r.public())
            ]
        );
        let seal = bytes(
            "0c0d0e0f10111213141516170959f740e14242544afe29a94dfc86f05e80ef4e\
             c255a9f1c618ce004fc0885904a09ca1612ec6bc4ed6f6e0fe9ec3b8",
        );
        assert_eq!(*at.open_seal(&bk, 5, 1, &seal).unwrap(), *s1);
        let vlink = bytes(
            "0c0d0e0f10111213141516178dd53268f4ea5b2aa5cb63dd5869b39c5cd8dc70\
             7b7cc191fb22255bbf309c8e1754c9c495e8a106527b5199094629b1",
        );
        assert_eq!(*at.open_link_down(&bk, 2, &vlink).unwrap(), run(160));
        let step = bytes(
            "0c0d0e0f1011121314151617a4143d6676f1173db34386b5ad03d0c0fe9b8e11\
             9b92d90c14568b2c6f12efb70fb345d964fe6445061a406a1f607b20",
        );
        assert_eq!(*c.follow(0, &run(0), &step).unwrap(), *s1);
        let link = bytes(
            "0c0d0e0f101112131415161731995d4449b15a8a1161fb00f907eb80c70ba5da\
             b611e80937d31407b970fb0e14f651c8c56711b44a81fe36db9053bf",
        );
        assert_eq!(*c.open_link(&run(0), 4, &link).unwrap(), run(96));
    }

    /// A pair at one bucket version, and the writer's key to the reader and back.
    fn static_pair() -> (LogKey, LogKey, StaticKey, StaticKey) {
        let (w, r) = (LogKey::generate(), LogKey::generate());
        let to_r = StaticKey::new(&w, &r.public()).unwrap();
        let from_w = StaticKey::new(&r, &w.public()).unwrap();
        (w, r, to_r, from_w)
    }

    fn at(conv: &'static str) -> Bucket<'static> {
        Bucket {
            conv,
            owner: &A,
            id: 7,
            version: 2,
        }
    }

    /// With a fixed nonce, a writer rolled back seals two states at one context
    /// under one key, and a listener given one recovers the other from the XOR.
    #[test]
    fn a_blank_row_has_a_rows_size_and_opens_for_nobody() {
        let (_, _, ours, theirs) = static_pair();
        let (a, b) = (blank_row(), blank_row());
        assert_eq!(a.len(), ROW_BYTES);
        assert_ne!(a, b);
        let (me, them) = ([1u8; 16], [2u8; 16]);
        assert!(ours.open_state(&a, "c:x", &me, 4096, &them).is_err());
        assert!(theirs.open_state(&a, "c:x", &me, 4096, &them).is_err());
    }

    #[test]
    fn two_seals_never_share_an_iv() {
        let (w, _, to_r, _) = static_pair();
        let (k, b, c) = (
            epoch_key(),
            at("c:x"),
            Chain {
                conv: "c:x",
                owner: &A,
                chain: 3,
            },
        );
        let (_, digest) = b.seal_list(&w, &[ListedSeat::new(&B, &[5; 33])]);
        type Maker<'a> = Box<dyn Fn() -> Vec<u8> + 'a>;
        let makers: Vec<(&str, Maker)> = vec![
            ("seat", Box::new(|| to_r.wrap_seat(&k, b, &B))),
            ("direct", Box::new(|| to_r.wrap_state(&k, "c:x", &A, 1, &B))),
            (
                "self-wrap",
                Box::new(|| self_wrap_state(&w, &k, "c:x", &A, 1)),
            ),
            ("own row", Box::new(|| b.own_row(&w, &k, &digest))),
            ("list", Box::new(|| b.seal_list(&w, &[]).0)),
            ("seal", Box::new(|| b.seal_state(&k, 3, 0, &k))),
            ("version link", Box::new(|| b.link_down(&k, 1, &k))),
            ("step", Box::new(|| c.step(0, &k).1)),
            ("back-link", Box::new(|| c.link(&k, 2, &k))),
        ];
        for (what, make) in makers {
            let mut seen = std::collections::HashSet::new();
            for _ in 0..64 {
                let row = make();
                assert!(seen.insert(row[..12].to_vec()), "{what}: an IV came twice");
            }
        }
    }

    /// X25519 gives both ends one secret, so only the context and the salt tell
    /// a row to someone from a row from them.
    #[test]
    fn a_row_keeps_owner_and_recipient_apart() {
        let (_, _, to_r, from_w) = static_pair();
        let k = epoch_key();
        let (b, flipped) = (
            at("c:x"),
            Bucket {
                owner: &B,
                ..at("c:x")
            },
        );
        let seat = to_r.wrap_seat(&k, b, &B);
        assert_eq!(*from_w.open_seat(&seat, b, &B).unwrap(), *k);
        assert_eq!(
            to_r.open_seat(&seat, flipped, &A).err(),
            Some(LogError::Sealed),
            "shown to the writer as the reader's row to it"
        );
        assert_eq!(
            from_w.open_seat(&seat, flipped, &A).err(),
            Some(LogError::Sealed),
            "ids flipped, same reader"
        );
        assert_eq!(
            to_r.open_seat(&seat, b, &B).err(),
            Some(LogError::Sealed),
            "the salt alone, ids right"
        );
        let direct = to_r.wrap_state(&k, "c:x", &A, 9, &B);
        assert_eq!(*from_w.open_state(&direct, "c:x", &A, 9, &B).unwrap(), *k);
        assert_eq!(
            to_r.open_state(&direct, "c:x", &B, 9, &A).err(),
            Some(LogError::Sealed)
        );
        assert_eq!(
            to_r.open_state(&direct, "c:x", &A, 9, &B).err(),
            Some(LogError::Sealed)
        );
    }

    fn low_order_keys() -> Vec<Vec<u8>> {
        LOW_ORDER
            .iter()
            .flat_map(|u| {
                let mut high = *u;
                high[31] |= 0x80;
                [*u, high]
            })
            .map(|u| [&[5u8][..], &u].concat())
            .collect()
    }

    /// One member's low-order key stopped every writer in their channels.
    #[test]
    fn a_low_order_log_key_is_refused() {
        let id = IdentityKeyPair::generate(&mut crate::rng());
        let own = LogKey::generate();
        let keys = low_order_keys();
        assert_eq!(keys.len(), 14);
        for key in &keys {
            assert!(StaticKey::new(&own, key).is_none(), "{}", hex(key));
            let sig = id
                .private_key()
                .calculate_signature(&endorsement(key), &mut crate::rng())
                .unwrap();
            assert!(
                !endorsed(&id.public_key().serialize(), key, &sig),
                "its own identity's word does not help: {}",
                hex(key)
            );
        }
        // The control: only the point decides
        let good = LogKey::generate().public();
        assert!(StaticKey::new(&own, &good).is_some());
        assert!(endorsed(
            &id.public_key().serialize(),
            &good,
            &id.private_key()
                .calculate_signature(&endorsement(&good), &mut crate::rng())
                .unwrap()
        ));
    }

    /// The table above stands in front of this. A libsignal that stopped
    /// refusing would show here first, with a key the table does not list.
    #[test]
    fn an_all_zero_secret_is_refused() {
        let own = LogKey::generate();
        for key in low_order_keys() {
            let point = PublicKey::deserialize(&key).unwrap();
            assert!(
                own.pair.private_key.calculate_agreement(&point).is_err(),
                "{}",
                hex(&key)
            );
        }
    }

    #[test]
    fn what_is_no_key_is_refused() {
        let own = LogKey::generate();
        let good = LogKey::generate().public();
        let trailing = [&good[..], &[0]].concat();
        assert!(StaticKey::new(&own, &trailing).is_none(), "trailing bytes");
        assert!(StaticKey::new(&own, &good[..32]).is_none(), "too short");
        assert!(StaticKey::new(&own, &good[1..]).is_none(), "no type byte");
        assert!(StaticKey::new(&own, &[]).is_none());
        let mut wrong_type = good.clone();
        wrong_type[0] = 6;
        assert!(StaticKey::new(&own, &wrong_type).is_none());
    }

    /// What Fred, who left, and Jo, who came later, can open between them is no
    /// more than each opens alone: every row takes one key and gives one key.
    /// The dual chain, which needed two, failed exactly here. Real rows, all of
    /// them public, tried under every key held until nothing new opens.
    #[test]
    fn what_two_people_open_together_is_what_each_opens() {
        type Key = [u8; 32];
        let conv = "c:premise";
        let chain = |chain| Chain {
            conv,
            owner: &A,
            chain,
        };
        let (c1, c2) = (chain(1), chain(2));
        let b1 = Bucket {
            conv,
            owner: &A,
            id: 7,
            version: 1,
        };
        let b2 = Bucket { version: 2, ..b1 };
        let d = Bucket { id: 9, ..b1 };
        let (k_b1, k_b2, k_d) = (epoch_key(), epoch_key(), epoch_key());

        // Chain 1 goes to Fred and Alice. Fred leaves: a new version of the
        // bucket, a new chain, sealed to it, linked back as a sharer's is. Jo
        // comes in a bucket of their own at that chain's index 1.
        let s10 = epoch_key();
        let (s11, step10) = c1.step(0, &s10);
        let (s12, step11) = c1.step(1, &s11);
        let s20 = epoch_key();
        let (s21, step20) = c2.step(0, &s20);
        let (s22, step21) = c2.step(1, &s21);
        let seal_b1 = b1.seal_state(&k_b1, 1, 0, &s10);
        let seal_b2 = b2.seal_state(&k_b2, 2, 0, &s20);
        let seal_d = d.seal_state(&k_d, 2, 1, &s21);
        let down = b2.link_down(&k_b2, 1, &k_b1);
        let back = c2.link(&s20, 1, &s10);

        type Opens<'a> = Box<dyn Fn(&Key) -> Option<Key> + 'a>;
        let rows: Vec<Opens> = vec![
            Box::new(|k| b1.open_seal(k, 1, 0, &seal_b1).ok().map(|s| *s)),
            Box::new(|k| b2.open_seal(k, 2, 0, &seal_b2).ok().map(|s| *s)),
            Box::new(|k| d.open_seal(k, 2, 1, &seal_d).ok().map(|s| *s)),
            Box::new(|k| b2.open_link_down(k, 1, &down).ok().map(|s| *s)),
            Box::new(|k| c2.open_link(k, 1, &back).ok().map(|s| *s)),
            Box::new(|k| c1.follow(0, k, &step10).ok().map(|s| *s)),
            Box::new(|k| c1.follow(1, k, &step11).ok().map(|s| *s)),
            Box::new(|k| c2.follow(0, k, &step20).ok().map(|s| *s)),
            Box::new(|k| c2.follow(1, k, &step21).ok().map(|s| *s)),
        ];
        let reach = |held: &[&Key]| {
            let mut have: std::collections::BTreeSet<Key> = held.iter().map(|k| **k).collect();
            loop {
                let mut new = Vec::new();
                for open in &rows {
                    new.extend(have.iter().filter_map(open).filter(|k| !have.contains(k)));
                }
                if new.is_empty() {
                    return have;
                }
                have.extend(new);
            }
        };
        let set = |keys: &[&Key]| keys.iter().map(|k| **k).collect();

        let fred = reach(&[&k_b1]);
        let jo = reach(&[&k_d]);
        assert_eq!(fred, set(&[&k_b1, &s10, &s11, &s12]));
        assert_eq!(jo, set(&[&k_d, &s21, &s22]));
        let together = reach(&[&k_b1, &k_d]);
        assert_eq!(together, fred.union(&jo).copied().collect());
        for out_of_reach in [&*k_b2, &*s20] {
            assert!(!together.contains(out_of_reach));
        }
        // The control, so the rows do open for whoever should hold them.
        let alice = reach(&[&k_b2]);
        assert_eq!(
            alice,
            set(&[&k_b2, &k_b1, &s10, &s11, &s12, &s20, &s21, &s22]),
        );
    }

    /// The relay can make an ECIES wrap to anyone's public key, and would then
    /// choose the state a reader adopts. A chain row opens only as a static
    /// wrap, by length and by label.
    #[test]
    fn chain_rows_open_only_as_static_wraps() {
        let (w, r, to_r, from_w) = static_pair();
        let k = epoch_key();
        let b = at("c:x");
        let ecies = wrap(&r.public(), &k, "c:x", &A, 9, &B).unwrap();
        assert_eq!(ecies.len(), 93);
        assert_eq!(
            from_w.open_state(&ecies, "c:x", &A, 9, &B).err(),
            Some(LogError::Malformed)
        );
        assert_eq!(
            from_w.open_seat(&ecies, b, &B).err(),
            Some(LogError::Malformed)
        );
        // Under the static KEK and the old label, at the right length.
        let ctx = wrap_ctx("c:x", &A, 9, &B);
        let old_label = seal(&from_w.kek(&w.public(), &r.public(), &ctx), &ctx, &*k);
        assert_eq!(old_label.len(), ROW_BYTES);
        assert_eq!(
            from_w.open_state(&old_label, "c:x", &A, 9, &B).err(),
            Some(LogError::Sealed)
        );
        // The real label, from anyone but the writer: the relay, or another member.
        let mallory = StaticKey::new(&LogKey::generate(), &r.public()).unwrap();
        for forged in [
            mallory.wrap_state(&k, "c:x", &A, 9, &B),
            seal(&epoch_key(), &state_ctx("c:x", &A, 9, &B), &*k),
        ] {
            assert_eq!(
                from_w.open_state(&forged, "c:x", &A, 9, &B).err(),
                Some(LogError::Sealed)
            );
        }
        // A seat is not a direct row, and neither is any other length.
        let seat = to_r.wrap_seat(&k, b, &B);
        assert_eq!(
            from_w.open_state(&seat, "c:x", &A, 9, &B).err(),
            Some(LogError::Sealed)
        );
        let direct = to_r.wrap_state(&k, "c:x", &A, 9, &B);
        assert_eq!(*from_w.open_state(&direct, "c:x", &A, 9, &B).unwrap(), *k);
        assert_eq!(
            from_w.open_seat(&direct, b, &B).err(),
            Some(LogError::Sealed)
        );
        assert_eq!(
            from_w
                .open_state(&direct[..ROW_BYTES - 1], "c:x", &A, 9, &B)
                .err(),
            Some(LogError::Malformed)
        );
    }

    #[test]
    fn a_v2_wrap_does_not_open_as_v1() {
        let (w, r, to_r, _) = static_pair();
        let k = epoch_key();
        let direct = to_r.wrap_state(&k, "c:x", &A, 9, &B);
        assert_eq!(
            unwrap(&r, &direct, "c:x", &A, 9, &B).err(),
            Some(LogError::Malformed)
        );
        // One account's two self-wraps at one epoch number: a random epoch key
        // is never taken for a chain state, nor the reverse.
        let chain_row = self_wrap_state(&w, &k, "c:x", &A, 9);
        assert_eq!(chain_row.len(), ROW_BYTES);
        assert_eq!(*self_open_state(&w, &chain_row, "c:x", &A, 9).unwrap(), *k);
        assert_eq!(
            self_unwrap(&w, &chain_row, "c:x", &A, 9).err(),
            Some(LogError::Sealed)
        );
        let epoch_row = self_wrap(&w, &k, "c:x", &A, 9);
        assert_eq!(
            self_open_state(&w, &epoch_row, "c:x", &A, 9).err(),
            Some(LogError::Sealed)
        );
    }

    #[test]
    fn a_chains_self_wrap_opens_for_our_own_devices_only() {
        let (me, other) = (LogKey::generate(), LogKey::generate());
        let k = epoch_key();
        let row = self_wrap_state(&me, &k, "c:x", &A, 7);
        let again = LogKey::from_bytes(&me.to_bytes()).unwrap();
        assert_eq!(*self_open_state(&again, &row, "c:x", &A, 7).unwrap(), *k);
        for (who, conv, id, epoch) in [
            (&other, "c:x", &A, 7),
            (&me, "c:y", &A, 7),
            (&me, "c:x", &B, 7),
            (&me, "c:x", &A, 8),
        ] {
            assert_eq!(
                self_open_state(who, &row, conv, id, epoch).err(),
                Some(LogError::Sealed)
            );
        }
        // What the relay can make: a static row needs a private key, and an
        // ECIES wrap to us has the wrong length.
        let forged = wrap(&me.public(), &k, "c:x", &A, 7, &A).unwrap();
        assert_eq!(
            self_open_state(&me, &forged, "c:x", &A, 7).err(),
            Some(LogError::Malformed)
        );
    }

    #[test]
    fn a_state_opens_higher_indexes_only_with_their_steps() {
        let c = Chain {
            conv: "c:x",
            owner: &A,
            chain: 3,
        };
        let s0 = epoch_key();
        let (s1, step0) = c.step(0, &s0);
        let (s2, step1) = c.step(1, &s1);
        assert_eq!(*c.follow(0, &s0, &step0).unwrap(), *s1);
        assert_eq!(*c.follow(1, &s1, &step1).unwrap(), *s2);
        assert_eq!(
            c.follow(0, &s1, &step0).err(),
            Some(LogError::Sealed),
            "a later state does not open the step below it"
        );
        assert_eq!(
            c.follow(1, &s0, &step1).err(),
            Some(LogError::Sealed),
            "nor an earlier state a step it did not take"
        );
        assert_ne!(*s0, *s1);
        assert_ne!(*s1, *s2);
        assert_eq!(
            c.follow(0, &s0, &step0[1..]).err(),
            Some(LogError::Malformed)
        );
    }

    /// A writer the relay rolled back draws new randomness. The listener it
    /// names then holds a fork: nothing written since opens for them. Under a
    /// plain hash the two would be one state, and everything would.
    #[test]
    fn a_writer_rolled_back_forks() {
        let c = Chain {
            conv: "c:x",
            owner: &A,
            chain: 3,
        };
        let writer = LogKey::generate();
        let s0 = epoch_key();
        let (truly, truly_row) = c.step(0, &s0);
        let (fork, fork_row) = c.step(0, &s0);
        assert_ne!(*truly, *fork);
        assert_ne!(truly_row, fork_row);
        let epoch = chain_epoch(3, 1).unwrap();
        let entry = seal_chain_entry(&truly, "c:x", &A, epoch, &writer, b"since", 1);
        assert_eq!(
            open_chain_entry(&fork, "c:x", &A, epoch, &writer.public(), &entry).err(),
            Some(LogError::Sealed)
        );
        assert_eq!(
            c.follow(1, &fork, &truly_row).err(),
            Some(LogError::Sealed),
            "and the listener cannot step across from the fork"
        );
    }

    #[test]
    fn a_moved_step_does_not_open() {
        let c = Chain {
            conv: "c:x",
            owner: &A,
            chain: 3,
        };
        let s = epoch_key();
        let (_, row) = c.step(4, &s);
        assert!(c.follow(4, &s, &row).is_ok());
        assert_eq!(c.follow(5, &s, &row).err(), Some(LogError::Sealed), "index");
        for moved in [
            Chain { chain: 4, ..c },
            Chain { owner: &B, ..c },
            Chain { conv: "c:y", ..c },
        ] {
            assert_eq!(moved.follow(4, &s, &row).err(), Some(LogError::Sealed));
        }
        // Each of those moves the next state too, so a state taken across does
        // not read there.
        let r = [9u8; 32];
        assert_ne!(*c.next(4, &s, &r), *Chain { chain: 4, ..c }.next(4, &s, &r));
    }

    #[test]
    fn a_step_does_not_open_as_a_link() {
        let c = Chain {
            conv: "c:x",
            owner: &A,
            chain: 3,
        };
        let s = epoch_key();
        let older = epoch_key();
        let (_, step) = c.step(0, &s);
        let link = c.link(&s, 2, &older);
        assert_eq!(c.open_link(&s, 2, &step).err(), Some(LogError::Sealed));
        assert_eq!(c.follow(0, &s, &link).err(), Some(LogError::Sealed));
        assert_eq!(*c.open_link(&s, 2, &link).unwrap(), *older);
    }

    #[test]
    fn a_link_opens_the_older_chain_and_never_the_newer() {
        let (old, new) = (
            Chain {
                conv: "c:x",
                owner: &A,
                chain: 2,
            },
            Chain {
                conv: "c:x",
                owner: &A,
                chain: 3,
            },
        );
        let (s_old, s_new) = (epoch_key(), epoch_key());
        let link = new.link(&s_new, 2, &s_old);
        assert_eq!(*new.open_link(&s_new, 2, &link).unwrap(), *s_old);
        assert_eq!(
            new.open_link(&s_old, 2, &link).err(),
            Some(LogError::Sealed),
            "the older start opens nothing newer"
        );
        assert_eq!(
            new.open_link(&s_new, 1, &link).err(),
            Some(LogError::Sealed),
            "another older chain"
        );
        assert_eq!(
            old.open_link(&s_new, 2, &link).err(),
            Some(LogError::Sealed),
            "from another chain"
        );
        // A state further along does not hold the link key: only the start does.
        let (s1, _) = new.step(0, &s_new);
        assert_eq!(new.open_link(&s1, 2, &link).err(), Some(LogError::Sealed));
    }

    #[test]
    fn the_labels_never_collide() {
        let c = Chain {
            conv: "c:x",
            owner: &A,
            chain: 3,
        };
        let s = [7u8; 32];
        let keys = [
            *c.key("entry", 0, &s),
            *c.key("step", 0, &s),
            *c.key("link", 0, &s),
            *c.next(0, &s, &[0; 32]),
            *hkdf32(None, &s, b"seal"),
            *hkdf32(None, &s, b"vlink"),
        ];
        let distinct: std::collections::HashSet<_> = keys.iter().collect();
        assert_eq!(distinct.len(), keys.len());
        let b = at("c:x");
        let contexts = [
            c.ctx("entry", 0),
            b.seat_ctx(&B),
            state_ctx("c:x", &A, 0, &B),
            wrap_ctx("c:x", &A, 0, &B),
            b.list_ctx(),
            b.seal_ctx(0, 0),
            b.version_link_ctx(1),
            chain_entry_aad("c:x", &A, 0),
            entry_aad("c:x", &A, 0),
        ];
        let labels: std::collections::HashSet<_> = contexts
            .iter()
            .map(|c| c.split('|').next().unwrap())
            .collect();
        assert_eq!(labels.len(), contexts.len());
        for ctx in &contexts {
            assert!(ctx.contains("|c:x|"), "the conversation is in {ctx}");
        }
    }

    /// The relay answers W's read of its buckets in `secret` with a bucket and
    /// list from `pub`, and calls that list's people members of `secret`. If it
    /// opened, W would see no arrival and name nobody, then seal `secret` under
    /// a key Mallory holds from `pub`.
    #[test]
    fn a_bucket_moved_to_another_channel_does_not_open_for_its_writer() {
        let w = LogKey::generate();
        let (public, secret) = (at("c:pub"), at("c:secret"));
        let k = epoch_key();
        let (list, digest) = public.seal_list(&w, &[ListedSeat::new(&B, &[5; 33])]);
        let own = public.own_row(&w, &k, &digest);
        assert!(public.open_own_row(&w, &own).is_ok());
        assert!(public.open_list(&w, &list, &digest).is_ok());
        assert_eq!(
            secret.open_own_row(&w, &own).err(),
            Some(LogError::Sealed),
            "the writer's own row"
        );
        assert_eq!(
            secret.open_list(&w, &list, &digest).err(),
            Some(LogError::Sealed),
            "its list"
        );
        // One set of people in two channels has two digests: naming them in one
        // is not naming them in the other.
        let (_, there) = secret.seal_list(&w, &[ListedSeat::new(&B, &[5; 33])]);
        assert_ne!(digest, there);
    }

    #[test]
    fn a_bucket_row_is_bound_to_its_whole_context() {
        let (w, _, to_r, from_w) = static_pair();
        let k = epoch_key();
        let b = at("c:x");
        let moved = [
            Bucket { conv: "c:y", ..b },
            Bucket { owner: &B, ..b },
            Bucket { id: 8, ..b },
            Bucket { version: 3, ..b },
        ];
        let seat = to_r.wrap_seat(&k, b, &B);
        let seal_row = b.seal_state(&k, 3, 1, &k);
        let down = b.link_down(&k, 1, &k);
        let (list, digest) = b.seal_list(&w, &[]);
        let own = b.own_row(&w, &k, &digest);
        for m in moved {
            assert!(from_w.open_seat(&seat, m, &B).is_err());
            assert!(m.open_seal(&k, 3, 1, &seal_row).is_err());
            assert!(m.open_link_down(&k, 1, &down).is_err());
            assert!(m.open_list(&w, &list, &digest).is_err());
            assert!(m.open_own_row(&w, &own).is_err());
        }
        assert!(from_w.open_seat(&seat, b, &A).is_err(), "another seat");
        assert!(b.open_seal(&k, 4, 1, &seal_row).is_err(), "another chain");
        assert!(b.open_seal(&k, 3, 0, &seal_row).is_err(), "another index");
        assert!(
            b.open_link_down(&k, 0, &down).is_err(),
            "another old version"
        );
    }

    #[test]
    fn a_version_link_opens_the_old_key_and_never_the_new() {
        let b = at("c:x");
        let (new, old) = (epoch_key(), epoch_key());
        let down = b.link_down(&new, 1, &old);
        assert_eq!(*b.open_link_down(&new, 1, &down).unwrap(), *old);
        assert_eq!(
            b.open_link_down(&old, 1, &down).err(),
            Some(LogError::Sealed),
            "whoever left, holding the old key"
        );
        // A seal and a link under one key do not read as each other.
        let seal_row = b.seal_state(&new, 1, 1, &old);
        assert!(b.open_link_down(&new, 1, &seal_row).is_err());
        assert!(b.open_seal(&new, 1, 1, &down).is_err());
    }

    /// Rule 7: a bucket or row counts as having held index 0 only if the writer
    /// can open it at index 0 and it is the start the writer holds. Never the
    /// relay's index, and not a flag a relay hiding all history once could earn.
    #[test]
    fn index_zero_only_on_proof() {
        let (_, _, to_r, _) = static_pair();
        let b = at("c:x");
        let (k, start, other) = (epoch_key(), epoch_key(), epoch_key());
        assert!(b.seal_holds_start(&k, 3, &b.seal_state(&k, 3, 0, &start), &start));
        assert!(
            !b.seal_holds_start(&k, 3, &b.seal_state(&k, 3, 1, &start), &start),
            "sealed at index 1"
        );
        assert!(
            !b.seal_holds_start(&k, 3, &b.seal_state(&k, 2, 0, &start), &start),
            "a seal from another chain"
        );
        assert!(
            !b.seal_holds_start(&k, 3, &b.seal_state(&k, 3, 0, &other), &start),
            "a member with the relay's help, forging under a key they hold"
        );
        assert!(
            !b.seal_holds_start(&other, 3, &b.seal_state(&k, 3, 0, &start), &start),
            "another bucket's key"
        );

        let epoch = chain_epoch(3, 0).unwrap();
        let held = to_r.wrap_state(&start, "c:x", &A, epoch, &B);
        assert!(to_r.row_holds_start(&held, "c:x", &A, 3, &B, &start));
        let above = to_r.wrap_state(&start, "c:x", &A, epoch + 1, &B);
        assert!(
            !to_r.row_holds_start(&above, "c:x", &A, 3, &B, &start),
            "a row at index 1"
        );
        let forged = to_r.wrap_state(&other, "c:x", &A, epoch, &B);
        assert!(
            !to_r.row_holds_start(&forged, "c:x", &A, 3, &B, &start),
            "another state"
        );
        assert!(
            !to_r.row_holds_start(&held, "c:x", &A, 3, &[3; 16], &start),
            "another reader's"
        );
        assert!(
            !to_r.row_holds_start(&held, "c:x", &A, MAX_CHAIN + 1, &B, &start),
            "past the chain numbers"
        );
    }

    #[test]
    fn a_list_opens_only_as_the_one_its_row_names() {
        let w = LogKey::generate();
        let b = at("c:x");
        let (bob, carol) = (
            ListedSeat::new(&B, &[5; 33]),
            ListedSeat::new(&[3; 16], &[6; 33]),
        );
        let (list, digest) = b.seal_list(&w, &[carol, bob]);
        assert_eq!(b.open_list(&w, &list, &digest).unwrap(), [bob, carol]);
        // A rolled-back relay keeps two lists the writer really wrote at one
        // version: only the one this row names opens.
        let (other_list, other_digest) = b.seal_list(&w, &[bob]);
        assert_eq!(
            b.open_list(&w, &other_list, &digest).err(),
            Some(LogError::Sealed)
        );
        assert_eq!(b.open_list(&w, &other_list, &other_digest).unwrap(), [bob]);
        assert_eq!(
            b.open_list(&LogKey::generate(), &list, &digest).err(),
            Some(LogError::Sealed),
            "another account's"
        );
        assert_eq!(
            b.open_list(&w, &[1; 3], &digest).err(),
            Some(LogError::Malformed)
        );
        // An empty bucket still has a list, and only that opens as it.
        let (none, no_digest) = b.seal_list(&w, &[]);
        assert_eq!(b.open_list(&w, &none, &no_digest).unwrap(), []);
    }

    #[test]
    fn a_new_log_key_makes_a_new_seat_on_the_list() {
        let (old, new) = (LogKey::generate(), LogKey::generate());
        let was = ListedSeat::new(&B, &old.public());
        assert_eq!(was, ListedSeat::new(&B, &old.public()));
        assert_ne!(was, ListedSeat::new(&B, &new.public()), "admin reclaim");
        assert_ne!(was, ListedSeat::new(&A, &old.public()));
    }

    #[test]
    fn the_writers_own_row_opens_for_its_devices_only() {
        let (w, other) = (LogKey::generate(), LogKey::generate());
        let (b, k, digest) = (at("c:x"), epoch_key(), [4u8; 32]);
        let row = b.own_row(&w, &k, &digest);
        assert_eq!(row.len(), OWN_ROW_BYTES);
        let again = LogKey::from_bytes(&w.to_bytes()).unwrap();
        let (key, named) = b.open_own_row(&again, &row).unwrap();
        assert_eq!((*key, named), (*k, digest));
        assert_eq!(b.open_own_row(&other, &row).err(), Some(LogError::Sealed));
        assert_eq!(
            b.open_own_row(&w, &row[1..]).err(),
            Some(LogError::Malformed)
        );
        // A static row needs a private key, and has the wrong length here anyway.
        let (_, _, to_r, _) = static_pair();
        let seat = to_r.wrap_seat(&k, b, &A);
        assert_eq!(b.open_own_row(&w, &seat).err(), Some(LogError::Malformed));
    }

    #[test]
    fn bucket_ids_are_random() {
        let ids: std::collections::HashSet<u64> = (0..64).map(|_| bucket_id()).collect();
        assert_eq!(ids.len(), 64);
        assert!(ids.iter().any(|id| id >> 32 != 0), "all 64 bits");
    }

    #[test]
    fn an_epoch_splits_into_its_chain_and_index() {
        assert_eq!(chain_epoch(5, 1), Some(0x5001));
        assert_eq!(epoch_parts(0x5001), (5, 1));
        assert_eq!(
            chain_epoch(MAX_CHAIN, MAX_CHAIN_INDEX),
            Some(u32::MAX),
            "all 32 bits"
        );
        assert_eq!(epoch_parts(u32::MAX), (MAX_CHAIN, MAX_CHAIN_INDEX));
        assert_eq!(chain_epoch(MAX_CHAIN + 1, 0), None);
        assert_eq!(chain_epoch(0, MAX_CHAIN_INDEX + 1), None);
    }

    #[test]
    fn a_chain_entry_opens_with_its_state_and_proves_its_sender() {
        let (alice, mallory) = (LogKey::generate(), LogKey::generate());
        let c = Chain {
            conv: "c:x",
            owner: &A,
            chain: 3,
        };
        let s0 = epoch_key();
        let (s1, _) = c.step(0, &s0);
        let e1 = chain_epoch(3, 1).unwrap();
        let env = crate::envelope::envelope("id1", "hello", Some(60));
        let sealed = seal_chain_entry(&s1, "c:x", &A, e1, &alice, &env, 1_700_000_000_000);
        let (back, at) = open_chain_entry(&s1, "c:x", &A, e1, &alice.public(), &sealed).unwrap();
        assert_eq!((back, at), (env.clone(), 1_700_000_000_000));
        for (state, conv, sender, epoch) in [
            (&*s0, "c:x", &A, e1),
            (&*s1, "c:y", &A, e1),
            (&*s1, "c:x", &B, e1),
            (&*s1, "c:x", &A, e1 + 1),
            (&*s1, "c:x", &A, chain_epoch(4, 1).unwrap()),
        ] {
            assert_eq!(
                open_chain_entry(state, conv, sender, epoch, &alice.public(), &sealed).err(),
                Some(LogError::Sealed)
            );
        }
        // A member holding the state cannot write as alice.
        let forged = seal_chain_entry(&s1, "c:x", &A, e1, &mallory, &env, 1);
        assert_eq!(
            open_chain_entry(&s1, "c:x", &A, e1, &alice.public(), &forged).err(),
            Some(LogError::Forged)
        );
    }

    /// An entry under one scheme's bytes never reads as the other's, even under
    /// the same key: the AAD and the signature's text both say which.
    #[test]
    fn an_epoch_entry_does_not_open_on_a_chain() {
        let alice = LogKey::generate();
        let s = epoch_key();
        let e = chain_epoch(3, 0).unwrap();
        let env = crate::envelope::envelope("id1", "hello", None);
        let key = chain_entry_key(&s, "c:x", &A, e);
        let on_epoch = seal_entry(&key, "c:x", &A, e, &alice, &env, 1);
        assert_eq!(
            open_chain_entry(&s, "c:x", &A, e, &alice.public(), &on_epoch).err(),
            Some(LogError::Sealed)
        );
        let on_chain = seal_chain_entry(&s, "c:x", &A, e, &alice, &env, 1);
        assert_eq!(
            open_entry(&key, "c:x", &A, e, &alice.public(), &on_chain).err(),
            Some(LogError::Sealed)
        );
        assert_ne!(
            signed_part(&entry_aad("c:x", &A, e), 1, &env),
            signed_part(&chain_entry_aad("c:x", &A, e), 1, &env)
        );
    }
}
