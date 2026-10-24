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

use hkdf::Hkdf;
use libsignal_protocol::{IdentityKey, IdentityKeyPair, KeyPair, PrivateKey, PublicKey};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
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
        LogKey { pair: KeyPair::generate(&mut crate::rng()) }
    }

    /// The vault item's plaintext: the private key (32 bytes).
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.pair.private_key.serialize())
    }

    pub fn from_bytes(b: &[u8]) -> Option<LogKey> {
        let private_key = PrivateKey::deserialize(b).ok()?;
        let public_key = private_key.public_key().ok()?;
        Some(LogKey { pair: KeyPair::new(public_key, private_key) })
    }

    pub fn public(&self) -> Vec<u8> {
        self.pair.public_key.serialize().to_vec()
    }

    /// The identity's signature over this key, which peers check against the
    /// identity they pinned before trusting a wrap to it.
    pub fn endorse(&self, identity: &IdentityKeyPair) -> Vec<u8> {
        let msg = endorsement(&self.public());
        identity.private_key().calculate_signature(&msg, &mut crate::rng()).expect("sign").to_vec()
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
        Ok(ik) => PublicKey::deserialize(logkey).is_ok() && ik.public_key().verify_signature(&endorsement(logkey), signature),
        Err(_) => false,
    }
}

// ── Wraps ─────────────────────────────────────────────────────────────────

fn wrap_ctx(conv: &str, owner: &[u8; 16], epoch: u32, recipient: &[u8; 16]) -> String {
    format!("voipc-wrap/v1|{conv}|{}|{epoch}|{}", hex(owner), hex(recipient))
}

/// `key` for `recipient`: `ephemeral public (33) | iv (12) | sealed key + tag (48)`.
pub fn wrap(recipient_logkey: &[u8], key: &[u8; 32], conv: &str, owner: &[u8; 16], epoch: u32, recipient: &[u8; 16]) -> Option<Vec<u8>> {
    let them = PublicKey::deserialize(recipient_logkey).ok()?;
    let eph = KeyPair::generate(&mut crate::rng());
    let shared = Zeroizing::new(eph.private_key.calculate_agreement(&them).ok()?.to_vec());
    let eph_pub = eph.public_key.serialize();
    let ctx = wrap_ctx(conv, owner, epoch, recipient);
    let mut salt = eph_pub.to_vec();
    salt.extend_from_slice(recipient_logkey);
    let mut kek = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(&salt), &shared).expand(ctx.as_bytes(), &mut *kek).ok()?;
    let mut out = eph_pub.to_vec();
    out.extend_from_slice(&seal(&kek, &ctx, key));
    Some(out)
}

pub fn unwrap(own: &LogKey, wrapped: &[u8], conv: &str, owner: &[u8; 16], epoch: u32, recipient: &[u8; 16]) -> Result<[u8; 32], LogError> {
    if wrapped.len() != 33 + 12 + 48 {
        return Err(LogError::Malformed);
    }
    let eph = PublicKey::deserialize(&wrapped[..33]).map_err(|_| LogError::Malformed)?;
    let shared = Zeroizing::new(own.pair.private_key.calculate_agreement(&eph).map_err(|_| LogError::Malformed)?.to_vec());
    let ctx = wrap_ctx(conv, owner, epoch, recipient);
    let mut salt = wrapped[..33].to_vec();
    salt.extend_from_slice(&own.public());
    let mut kek = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(&salt), &shared).expand(ctx.as_bytes(), &mut *kek).map_err(|_| LogError::Malformed)?;
    open(&kek, &ctx, &wrapped[33..])?.try_into().map_err(|_| LogError::Malformed)
}

/// The key our own devices seal our epoch keys for each other under: from
/// the log key's private half, which only the account's vault holds.
fn self_key(own: &LogKey) -> Zeroizing<[u8; 32]> {
    let mut k = Zeroizing::new([0u8; 32]);
    let private = Zeroizing::new(own.pair.private_key.serialize());
    Hkdf::<Sha256>::new(None, &private).expand(b"voipc-selfwrap/v1", &mut *k).expect("32 bytes is a valid HKDF length");
    k
}

/// Our epoch `key` for our other devices: `iv (12) | sealed key + tag (48)`.
pub fn self_wrap(own: &LogKey, key: &[u8; 32], conv: &str, me: &[u8; 16], epoch: u32) -> Vec<u8> {
    seal(&self_key(own), &wrap_ctx(conv, me, epoch, me), key)
}

/// One of our own epoch keys back. An ECIES wrap made from our public key —
/// which the relay can make — does not open here.
pub fn self_unwrap(own: &LogKey, wrapped: &[u8], conv: &str, me: &[u8; 16], epoch: u32) -> Result<[u8; 32], LogError> {
    if wrapped.len() != 12 + 48 {
        return Err(LogError::Malformed);
    }
    open(&self_key(own), &wrap_ctx(conv, me, epoch, me), wrapped)?.try_into().map_err(|_| LogError::Malformed)
}

/// A fresh epoch key.
pub fn epoch_key() -> Zeroizing<[u8; 32]> {
    Zeroizing::new(random())
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

fn signed_part(conv: &str, sender: &[u8; 16], epoch: u32, sent_at: u64, envelope: &[u8]) -> Vec<u8> {
    let mut m = entry_aad(conv, sender, epoch).into_bytes();
    m.push(b'|');
    m.extend_from_slice(&sent_at.to_be_bytes());
    m.extend_from_slice(envelope);
    m
}

/// A log entry's sealed bytes.
pub fn seal_entry(key: &[u8; 32], conv: &str, sender: &[u8; 16], epoch: u32, signer: &LogKey, envelope: &[u8], sent_at: u64) -> Vec<u8> {
    let sig = signer.pair.calculate_signature(&signed_part(conv, sender, epoch, sent_at, envelope), &mut crate::rng()).expect("sign").to_vec();
    let payload = postcard::to_allocvec(&Payload { envelope: envelope.to_vec(), sent_at, sig }).expect("encodes");
    seal(key, &entry_aad(conv, sender, epoch), &payload)
}

/// An entry opened and its signature checked against the sender's log key:
/// the envelope and when it was sent.
pub fn open_entry(key: &[u8; 32], conv: &str, sender: &[u8; 16], epoch: u32, sender_logkey: &[u8], sealed: &[u8]) -> Result<(Vec<u8>, u64), LogError> {
    let plain = open(key, &entry_aad(conv, sender, epoch), sealed)?;
    let p: Payload = postcard::from_bytes(&plain).map_err(|_| LogError::Malformed)?;
    let pk = PublicKey::deserialize(sender_logkey).map_err(|_| LogError::Malformed)?;
    if !pk.verify_signature(&signed_part(conv, sender, epoch, p.sent_at, &p.envelope), &p.sig) {
        return Err(LogError::Forged);
    }
    Ok((p.envelope, p.sent_at))
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
        assert!(!endorsed(&other.public_key().serialize(), &lk.public(), &sig), "another identity's");
        assert!(!endorsed(&id.public_key().serialize(), &LogKey::generate().public(), &sig), "another key");
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
        assert_eq!(unwrap(&alice, &w, &c, &A, 1, &B).err(), Some(LogError::Sealed), "not alice's");
        assert_eq!(unwrap(&bob, &w, &c, &A, 2, &B).err(), Some(LogError::Sealed), "another epoch");
        assert_eq!(unwrap(&bob, &w, &c, &B, 1, &B).err(), Some(LogError::Sealed), "another owner");
        assert_eq!(unwrap(&bob, &w, "d:x", &A, 1, &B).err(), Some(LogError::Sealed), "another conversation");
    }

    #[test]
    fn a_self_wrap_opens_for_our_own_devices_only() {
        let (me, other) = (LogKey::generate(), LogKey::generate());
        let k = epoch_key();
        let c = dm_conv(&A, &B);
        let w = self_wrap(&me, &k, &c, &A, 7);
        assert_eq!(w.len(), 60, "under the relay's 128-byte bound for a wrap");
        let again = LogKey::from_bytes(&me.to_bytes()).unwrap();
        assert_eq!(self_unwrap(&again, &w, &c, &A, 7).unwrap(), *k, "another device of the same account");
        assert_eq!(self_unwrap(&other, &w, &c, &A, 7).err(), Some(LogError::Sealed), "another account's");
        assert_eq!(self_unwrap(&me, &w, &c, &A, 8).err(), Some(LogError::Sealed), "another epoch");
        assert_eq!(self_unwrap(&me, &w, "d:x", &A, 7).err(), Some(LogError::Sealed), "another conversation");
        // What the relay can make: an ECIES wrap to our public log key, "from us".
        let forged = wrap(&me.public(), &epoch_key(), &c, &A, 7, &A).unwrap();
        assert!(self_unwrap(&me, &forged, &c, &A, 7).is_err(), "an ECIES wrap is never one of our own");
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
        assert_eq!(open_entry(&k, "d:other", &A, 1, &alice.public(), &sealed).err(), Some(LogError::Sealed));
        assert_eq!(open_entry(&k, &c, &B, 1, &alice.public(), &sealed).err(), Some(LogError::Sealed));
        // A member holding K cannot write as alice: their signature is not hers.
        let forged = seal_entry(&k, &c, &A, 1, &mallory, &env, 1);
        assert_eq!(open_entry(&k, &c, &A, 1, &alice.public(), &forged).err(), Some(LogError::Forged));
    }
}
