//! Relay accounts, on the client: the keys a password gives, the account's
//! vault, the device key, and the sign-in itself as a state machine without
//! I/O, so the desktop client and the browser (through wasm) run the same steps.
//!
//! One password, two keys. `derive` stretches it once (PBKDF2-SHA256, 600 000
//! rounds, salted with the relay id and the account name) and splits the
//! result: `auth_secret` is what the relay sees, as if it were the password,
//! and hashes again; `vault_key` never leaves this device. So the relay can
//! check a sign-in without being able to open the vault, and a person has one
//! secret to remember. The relay id, not its address, goes into the salt, so a
//! relay that moves keeps its accounts.
//!
//! The vault (see docs/ACCOUNTS.md for the bytes): a random 32-byte DEK
//! encrypts every item (AES-256-GCM); slots wrap the DEK, one under the
//! password's `vault_key` (`slot.pass`) and one under a recovery key shown
//! once (`slot.recovery`). Every wrap and item is bound to the relay, the
//! account name and its own key name, so the relay cannot move one between
//! accounts or swap two of them without decryption failing.

use std::num::NonZeroU32;

use hkdf::Hkdf;
use libsignal_protocol::IdentityKeyPair;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use sha2::{Digest, Sha256};
use voipc_protocol::conv::hex;
use voipc_protocol::messages::{
    AccountReply, AccountRequest, AuthContinue, AuthStep, ClientMessage, ServerMessage,
};
use voipc_protocol::types::{AccountStart, PowChallenge, PreKeyBundleData, VaultBlob};
pub use zeroize::Zeroizing;

use crate::aead::{open, random, seal};

/// PBKDF2 rounds: what l4f's vault requires of a passphrase slot.
pub const KDF_ROUNDS: u32 = 600_000;
const SLOT_PASS: &str = "slot.pass";
const SLOT_RECOVERY: &str = "slot.recovery";
/// The account's long-term identity (libsignal `IdentityKeyPair` bytes).
pub const ITEM_IDENTITY: &str = "item.identity";
/// Other accounts' identity keys as first seen (`Pins`, postcard).
pub const ITEM_PINS: &str = "item.pins";

// ── Names ─────────────────────────────────────────────────────────────────

/// An account name as the relay stores it (l4f's `username_shape`): lowercase
/// a-z, 0-9, `_` and `-`, 3 to 32 of them, starting with a letter or digit,
/// not all digits. The relay checks again; this is for the salt and the form.
pub fn normalize_name(raw: &str) -> Result<String, &'static str> {
    let name = raw.trim().to_ascii_lowercase();
    if !name
        .bytes()
        .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-'))
    {
        return Err("Only a-z, 0-9, _ and - are allowed in an account name.");
    }
    if !(3..=32).contains(&name.len()) {
        return Err("Pick an account name between 3 and 32 characters.");
    }
    if !name.starts_with(|c: char| c.is_ascii_alphanumeric()) {
        return Err("An account name must start with a letter or a digit.");
    }
    if name.bytes().all(|b| b.is_ascii_digit()) {
        return Err("An account name cannot be only digits.");
    }
    Ok(name)
}

/// The rules the relay holds a new password to; it never sees the password,
/// so the client is where they apply.
pub fn password_ok(password: &str) -> Result<(), &'static str> {
    if password.chars().count() < 10 {
        return Err("Use a password of at least 10 characters.");
    }
    if password.len() > 1024 {
        return Err("That password is too long.");
    }
    Ok(())
}

// ── Keys from the password ────────────────────────────────────────────────

pub struct Derived {
    /// Sent to the relay in place of the password.
    pub auth_secret: [u8; 32],
    /// Opens the vault's password slot; never sent.
    pub vault_key: Zeroizing<[u8; 32]>,
}

fn hkdf32(ikm: &[u8], salt: &[u8], info: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info.as_bytes(), &mut out)
        .expect("32 bytes is a valid HKDF length");
    out
}

/// The PBKDF2 salt: the relay id and the normalised account name.
pub fn kdf_salt(relay_id: &[u8; 16], name: &str) -> String {
    format!("voipc/v1|{}|{}", hex(relay_id), name)
}

/// The slow half of `derive`: PBKDF2-HMAC-SHA256, `KDF_ROUNDS`, 32 bytes. The
/// browser runs the same with WebCrypto's `deriveBits` (UTF-8 password and
/// salt), about eight times faster than this in wasm (1.0 audit H5-18).
pub fn stretch(password: &str, relay_id: &[u8; 16], name: &str) -> Zeroizing<[u8; 32]> {
    stretch_salted(password, &kdf_salt(relay_id, name))
}

/// `stretch` with the salt as `kdf_salt` (or `AccountSession::kdf_salt`) gave it.
pub fn stretch_salted(password: &str, salt: &str) -> Zeroizing<[u8; 32]> {
    let mut master = Zeroizing::new([0u8; 32]);
    ring::pbkdf2::derive(
        ring::pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(KDF_ROUNDS).expect("non-zero"),
        salt.as_bytes(),
        password.as_bytes(),
        &mut *master,
    );
    master
}

/// The fast half of `derive`, from `stretch`'s output.
pub fn derive_from_master(master: &[u8; 32]) -> Derived {
    Derived {
        auth_secret: hkdf32(master, b"", "voipc-auth/v1"),
        vault_key: Zeroizing::new(hkdf32(master, b"", "voipc-vault/v1")),
    }
}

/// `password` as the person typed it, NFC-normalised by the caller (the
/// browser and the desktop share one front end, which does it); `name`
/// normalised (`normalize_name`).
pub fn derive(password: &str, relay_id: &[u8; 16], name: &str) -> Derived {
    derive_from_master(&stretch(password, relay_id, name))
}

// ── The vault ─────────────────────────────────────────────────────────────

#[derive(Debug, PartialEq, Eq)]
pub enum VaultError {
    /// No slot of that kind, or the key does not open it.
    WrongKey,
    /// An item that does not decrypt: tampered with, or another vault's.
    Corrupt,
    Missing,
    /// An item a newer VoIPC wrote, in a format this one does not know.
    Newer,
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            VaultError::WrongKey => "the vault does not open with that key",
            VaultError::Corrupt => "a vault item does not decrypt",
            VaultError::Missing => "the vault has no such item",
            VaultError::Newer => "a newer VoIPC wrote this vault item",
        })
    }
}

/// An open vault: its DEK, and what every wrap and item is bound to.
pub struct Vault {
    dek: Zeroizing<[u8; 32]>,
    relay_id: [u8; 16],
    name: String,
}

impl Vault {
    /// A new, empty vault for an account about to be made.
    pub fn create(relay_id: [u8; 16], name: &str) -> Vault {
        Vault {
            dek: Zeroizing::new(random()),
            relay_id,
            name: name.to_string(),
        }
    }

    /// A vault this device opened before (its DEK kept with the device key).
    pub fn from_dek(relay_id: [u8; 16], name: &str, dek: [u8; 32]) -> Vault {
        Vault {
            dek: Zeroizing::new(dek),
            relay_id,
            name: name.to_string(),
        }
    }

    pub fn dek(&self) -> [u8; 32] {
        *self.dek
    }

    fn dek_id(&self) -> [u8; 8] {
        Sha256::digest(*self.dek)[..8].try_into().expect("8 bytes")
    }

    fn slot_aad(&self, key: &str) -> String {
        format!(
            "voipc-vault-slot/v1|{}|{}|{}",
            hex(&self.relay_id),
            self.name,
            key
        )
    }

    fn item_aad(&self, key: &str) -> String {
        format!(
            "voipc-vault-item/v1|{}|{}|{}",
            hex(&self.relay_id),
            self.name,
            key
        )
    }

    /// `slot.pass` under the password's vault key, or `slot.recovery` under a
    /// recovery key: `0x01 | salt(32) | dek_id(8) | iv(12) | wrapped DEK + tag(48)`.
    fn slot(&self, key: &str, secret: &[u8; 32]) -> VaultBlob {
        let salt = random::<32>();
        let kek = Zeroizing::new(hkdf32(secret, &salt, "voipc-vault-kek/v1"));
        let (iv, ct) = seal(&kek, &self.slot_aad(key), &*self.dek);
        let mut v = Vec::with_capacity(1 + 32 + 8 + 12 + ct.len());
        v.push(1);
        v.extend_from_slice(&salt);
        v.extend_from_slice(&self.dek_id());
        v.extend_from_slice(&iv);
        v.extend_from_slice(&ct);
        VaultBlob {
            k: key.into(),
            v,
            version: 0,
        }
    }

    pub fn pass_slot(&self, vault_key: &[u8; 32]) -> VaultBlob {
        self.slot(SLOT_PASS, vault_key)
    }

    pub fn recovery_slot(&self, recovery: &[u8; 32]) -> VaultBlob {
        self.slot(SLOT_RECOVERY, recovery)
    }

    fn open_slot(
        relay_id: [u8; 16],
        name: &str,
        blobs: &[VaultBlob],
        key: &str,
        secret: &[u8; 32],
    ) -> Result<Vault, VaultError> {
        let b = blobs
            .iter()
            .find(|b| b.k == key)
            .ok_or(VaultError::WrongKey)?;
        let v = &b.v;
        if v.len() != 1 + 32 + 8 + 12 + 48 || v[0] != 1 {
            return Err(VaultError::Corrupt);
        }
        let (salt, rest) = v[1..].split_at(32);
        let (dek_id, rest) = rest.split_at(8);
        let (iv, ct) = rest.split_at(12);
        let probe = Vault {
            dek: Zeroizing::new([0; 32]),
            relay_id,
            name: name.to_string(),
        };
        let kek = Zeroizing::new(hkdf32(secret, salt, "voipc-vault-kek/v1"));
        let dek: [u8; 32] = open(&kek, &probe.slot_aad(key), iv, ct)
            .and_then(|d| d.try_into().ok())
            .ok_or(VaultError::WrongKey)?;
        let vault = Vault {
            dek: Zeroizing::new(dek),
            ..probe
        };
        if vault.dek_id()[..] != *dek_id {
            return Err(VaultError::Corrupt);
        }
        Ok(vault)
    }

    pub fn open_with_password(
        relay_id: [u8; 16],
        name: &str,
        blobs: &[VaultBlob],
        vault_key: &[u8; 32],
    ) -> Result<Vault, VaultError> {
        Self::open_slot(relay_id, name, blobs, SLOT_PASS, vault_key)
    }

    pub fn open_with_recovery(
        relay_id: [u8; 16],
        name: &str,
        blobs: &[VaultBlob],
        recovery: &[u8; 32],
    ) -> Result<Vault, VaultError> {
        Self::open_slot(relay_id, name, blobs, SLOT_RECOVERY, recovery)
    }

    /// An item: `0x02 | dek_id(8) | iv(12) | ciphertext + tag`, sealing
    /// `format(2) | gen(8) | payload`. `gen` grows by one on every save, so a
    /// device that saw a newer one notices a relay handing back an older copy.
    pub fn seal_item(&self, key: &str, gen: u64, payload: &[u8]) -> VaultBlob {
        let mut plaintext = Vec::with_capacity(10 + payload.len());
        plaintext.extend_from_slice(&ITEM_FORMAT.to_be_bytes());
        plaintext.extend_from_slice(&gen.to_be_bytes());
        plaintext.extend_from_slice(payload);
        let (iv, ct) = seal(&self.dek, &self.item_aad(key), &plaintext);
        let mut v = Vec::with_capacity(1 + 8 + 12 + ct.len());
        v.push(ITEM_V2);
        v.extend_from_slice(&self.dek_id());
        v.extend_from_slice(&iv);
        v.extend_from_slice(&ct);
        VaultBlob {
            k: key.into(),
            v,
            version: 0,
        }
    }

    /// An item, telling apart missing, damaged and written by a newer VoIPC.
    /// 0.12's items (`0x01`, the payload only) read as generation 0.
    pub fn open_item(&self, blobs: &[VaultBlob], key: &str) -> Result<Item, VaultError> {
        let b = blobs
            .iter()
            .find(|b| b.k == key)
            .ok_or(VaultError::Missing)?;
        match b.v.first() {
            Some(&ITEM_V1) | Some(&ITEM_V2) => {}
            Some(_) => return Err(VaultError::Newer),
            None => return Err(VaultError::Corrupt),
        }
        if b.v.len() < 1 + 8 + 12 + 16 || b.v[1..9] != self.dek_id() {
            return Err(VaultError::Corrupt);
        }
        let plain = open(&self.dek, &self.item_aad(key), &b.v[9..21], &b.v[21..])
            .ok_or(VaultError::Corrupt)?;
        if b.v[0] == ITEM_V1 {
            return Ok(Item {
                gen: 0,
                payload: plain,
            });
        }
        if plain.len() < 10 {
            return Err(VaultError::Corrupt);
        }
        if u16::from_be_bytes([plain[0], plain[1]]) > ITEM_FORMAT {
            return Err(VaultError::Newer);
        }
        Ok(Item {
            gen: u64::from_be_bytes(plain[2..10].try_into().expect("8 bytes")),
            payload: plain[10..].to_vec(),
        })
    }
}

/// An opened vault item.
pub struct Item {
    /// How many times it was saved (0 for one 0.12 wrote).
    pub gen: u64,
    pub payload: Vec<u8>,
}

const ITEM_V1: u8 = 1;
const ITEM_V2: u8 = 2;
/// The newest item payload format this build reads (inside `ITEM_V2`). A 1.x
/// that changes what an item holds raises it, and older builds then leave
/// the item alone instead of overwriting it.
pub const ITEM_FORMAT: u16 = 1;

// ── Pinned identities ─────────────────────────────────────────────────────

/// The identity key each other account on this relay had when this account
/// first met it, and which account each name belonged to. Kept in the vault,
/// so every device of the account checks against the same pins: a relay that
/// hands one device a different key for someone is caught there too.
/// Postcard, about 75 bytes an account: the vault is bounded (it travels in
/// one frame at sign-in), and that is room for about 650 of them.
#[derive(Default, Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Pins {
    /// Account id → identity public key.
    keys: std::collections::BTreeMap<[u8; 16], Vec<u8>>,
    /// Account name → the account id first met under it. People know each
    /// other by name, and the id is only the relay's word: a relay showing
    /// "bob" under a new id, with a key of its own, would meet no pin by id.
    names: std::collections::BTreeMap<String, [u8; 16]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinCheck {
    /// Never met: pinned now (save the pins).
    New,
    Same,
    /// A different key than the pinned one: the person must be told. The new
    /// key is pinned from now on, so they are told once.
    Changed,
    /// The name was first met as another account: deleted and taken again,
    /// or a relay showing someone else under it. Told as such, once.
    Replaced,
}

impl PinCheck {
    /// The person must be told.
    pub fn warns(self) -> bool {
        matches!(self, PinCheck::Changed | PinCheck::Replaced)
    }
}

impl Pins {
    pub fn from_bytes(bytes: &[u8]) -> Option<Pins> {
        postcard::from_bytes(bytes).ok()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("a map of bytes encodes")
    }

    /// `account`, going by `name` (empty: not known), with identity `key`.
    /// `Changed` when the key is not the one pinned for the account, or the
    /// name belonged to another account; what was met now is pinned either way.
    pub fn check(&mut self, account: &[u8; 16], name: &str, key: &[u8]) -> PinCheck {
        let by_key = match self.keys.insert(*account, key.to_vec()) {
            None => PinCheck::New,
            Some(known) if known == key => PinCheck::Same,
            Some(_) => PinCheck::Changed,
        };
        let name = name.trim().to_ascii_lowercase();
        let by_name = match (name.is_empty(), self.names.get(&name)) {
            (true, _) => PinCheck::Same,
            (false, None) => PinCheck::New,
            (false, Some(a)) if a == account => PinCheck::Same,
            (false, Some(_)) => PinCheck::Changed,
        };
        if !name.is_empty() {
            self.names.insert(name, *account);
        }
        match (by_key, by_name) {
            (PinCheck::Changed, _) => PinCheck::Changed,
            (_, PinCheck::Changed) => PinCheck::Replaced,
            (PinCheck::Same, PinCheck::Same) => PinCheck::Same,
            _ => PinCheck::New,
        }
    }

    /// Another device's pins, written while this one held its own: the union,
    /// theirs winning where both met the same account (whichever pinned it
    /// first was here first, and a disagreement was reported where it arose).
    /// Returns the accounts (and a name each goes by) whose key or name the
    /// two disagreed on: adopted without a word, a relay could move a device
    /// to an old key through a conflict copy.
    pub fn merge(&mut self, theirs: Pins) -> Vec<([u8; 16], String)> {
        let mut changed: Vec<[u8; 16]> = theirs
            .keys
            .iter()
            .filter(|(a, k)| self.keys.get(*a).is_some_and(|ours| ours != *k))
            .map(|(a, _)| *a)
            .collect();
        changed.extend(
            theirs
                .names
                .iter()
                .filter(|(n, a)| self.names.get(*n).is_some_and(|ours| ours != *a))
                .map(|(_, a)| *a),
        );
        self.keys.extend(theirs.keys);
        self.names.extend(theirs.names);
        changed.sort();
        changed.dedup();
        changed.into_iter().map(|a| (a, self.name_of(&a))).collect()
    }

    fn name_of(&self, account: &[u8; 16]) -> String {
        self.names
            .iter()
            .find(|(_, a)| *a == account)
            .map(|(n, _)| n.clone())
            .unwrap_or_default()
    }

    /// Whether `name` (the part before any `#tag`) was first met as an account.
    pub fn knows_name(&self, name: &str) -> bool {
        let name = name
            .split('#')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        !name.is_empty() && self.names.contains_key(&name)
    }

    /// The key pinned for `account`, if any.
    pub fn get(&self, account: &[u8; 16]) -> Option<&[u8]> {
        self.keys.get(account).map(Vec::as_slice)
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// The safety number two accounts compare (in person, on a call) to know no
/// relay stands between them: libsignal's 60-digit fingerprint of both
/// identities, keyed by the account ids, in groups of five. The same string on
/// both sides.
pub fn safety_number(
    own_account: &[u8; 16],
    own_key: &[u8],
    peer_account: &[u8; 16],
    peer_key: &[u8],
) -> Option<String> {
    use libsignal_protocol::{Fingerprint, IdentityKey};
    let own = IdentityKey::decode(own_key).ok()?;
    let peer = IdentityKey::decode(peer_key).ok()?;
    let digits = Fingerprint::new(2, 5200, own_account, &own, peer_account, &peer)
        .ok()?
        .display_string()
        .ok()?;
    Some(
        digits
            .as_bytes()
            .chunks(5)
            .map(|c| std::str::from_utf8(c).expect("digits"))
            .collect::<Vec<_>>()
            .join(" "),
    )
}

// ── Reset with the recovery key ──────────────────────────────────────────

/// The vault item the relay checks a reset against: the public half of the
/// reset key. A `slot.` item, so no vault write after sign-up replaces it;
/// only `RecoveryKeyNew`, with the password, does.
pub const SLOT_RESET: &str = "slot.reset";

/// What a reset signs with the identity key: this relay, this account and the
/// relay's challenge. The relay takes it only from an account made before 1.3
/// (without `slot.reset`). The vault's DEK opens the identity, and a
/// remembered device keeps the DEK, so it proves less than the recovery key
/// (S-006).
fn reset_message(relay_id: &[u8; 16], name: &str, challenge: &[u8]) -> Vec<u8> {
    let mut m = format!(
        "voipc-reset/v1|{}|{}|",
        hex(relay_id),
        name.trim().to_ascii_lowercase()
    )
    .into_bytes();
    m.extend_from_slice(challenge);
    m
}

pub fn reset_proof(
    identity: &IdentityKeyPair,
    relay_id: &[u8; 16],
    name: &str,
    challenge: &[u8],
) -> Vec<u8> {
    identity
        .private_key()
        .calculate_signature(&reset_message(relay_id, name, challenge), &mut crate::rng())
        .expect("sign")
        .to_vec()
}

/// The reset key: Ed25519, derived from the recovery key alone, for this
/// relay and account. Nothing on any device or the relay holds the recovery
/// key, so nothing but the person who wrote it down can sign with this.
fn reset_signing_key(recovery: &[u8; 32], relay_id: &[u8; 16], name: &str) -> Ed25519KeyPair {
    let info = format!("voipc-reset-key/v1|{}", name.trim().to_ascii_lowercase());
    let seed = Zeroizing::new(hkdf32(recovery, relay_id, &info));
    Ed25519KeyPair::from_seed_unchecked(&seed[..]).expect("a 32-byte seed")
}

/// The reset key's public half, for `slot.reset`.
pub fn reset_key(recovery: &[u8; 32], relay_id: &[u8; 16], name: &str) -> [u8; 32] {
    reset_signing_key(recovery, relay_id, name)
        .public_key()
        .as_ref()
        .try_into()
        .expect("an Ed25519 public key is 32 bytes")
}

/// What a reset signs with the reset key.
fn reset_key_message(relay_id: &[u8; 16], name: &str, challenge: &[u8]) -> Vec<u8> {
    let mut m = format!(
        "voipc-reset/v2|{}|{}|",
        hex(relay_id),
        name.trim().to_ascii_lowercase()
    )
    .into_bytes();
    m.extend_from_slice(challenge);
    m
}

pub fn reset_key_proof(
    recovery: &[u8; 32],
    relay_id: &[u8; 16],
    name: &str,
    challenge: &[u8],
) -> Vec<u8> {
    reset_signing_key(recovery, relay_id, name)
        .sign(&reset_key_message(relay_id, name, challenge))
        .as_ref()
        .to_vec()
}

/// The relay's check of `reset_key_proof` against `slot.reset`.
pub fn reset_key_proof_ok(
    reset_key: &[u8],
    relay_id: &[u8; 16],
    name: &str,
    challenge: &[u8],
    signature: &[u8],
) -> bool {
    reset_key.len() == 32
        && ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, reset_key)
            .verify(&reset_key_message(relay_id, name, challenge), signature)
            .is_ok()
}

/// The relay's check of `reset_proof` against the identity on record.
pub fn reset_proof_ok(
    identity_key: &[u8],
    relay_id: &[u8; 16],
    name: &str,
    challenge: &[u8],
    signature: &[u8],
) -> bool {
    libsignal_protocol::IdentityKey::decode(identity_key).is_ok_and(|k| {
        k.public_key()
            .verify_signature(&reset_message(relay_id, name, challenge), signature)
    })
}

// ── Recovery key ──────────────────────────────────────────────────────────

const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// 32 random bytes as Base32 (RFC 4648, no padding) in groups of four, shown once.
pub fn recovery_text(key: &[u8; 32]) -> String {
    let mut bits = 0u32;
    let mut n = 0;
    let mut out = String::new();
    for &b in key {
        bits = (bits << 8) | u32::from(b);
        n += 8;
        while n >= 5 {
            n -= 5;
            out.push(B32[((bits >> n) & 31) as usize] as char);
        }
    }
    if n > 0 {
        out.push(B32[((bits << (5 - n)) & 31) as usize] as char);
    }
    out.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).expect("ascii"))
        .collect::<Vec<_>>()
        .join("-")
}

/// Reads a recovery key back, ignoring case, spaces and dashes.
pub fn recovery_parse(text: &str) -> Option<[u8; 32]> {
    let mut bits = 0u32;
    let mut n = 0;
    let mut out = Vec::with_capacity(32);
    for c in text.chars().filter(|c| !c.is_whitespace() && *c != '-') {
        let v = B32
            .iter()
            .position(|&a| a == c.to_ascii_uppercase() as u8)? as u32;
        bits = (bits << 5) | v;
        n += 5;
        if n >= 8 {
            n -= 8;
            out.push((bits >> n) as u8);
            bits &= (1 << n) - 1;
        }
    }
    out.try_into().ok()
}

// ── Device key ────────────────────────────────────────────────────────────

/// The key a device signs in with after one sign-in with the password (and a
/// second factor, where the account has one). Ed25519, as l4f's device keys.
pub struct DeviceKey {
    pub device_id: [u8; 16],
    pkcs8: Zeroizing<Vec<u8>>,
}

/// The origin a relay's device keys sign for (`Config.base_url` on the relay).
pub fn origin(relay_id: &[u8; 16]) -> String {
    format!("voipc://{}", hex(relay_id))
}

impl DeviceKey {
    pub fn generate() -> DeviceKey {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("Ed25519 key");
        DeviceKey {
            device_id: random(),
            pkcs8: Zeroizing::new(pkcs8.as_ref().to_vec()),
        }
    }

    pub fn from_parts(device_id: [u8; 16], pkcs8: Vec<u8>) -> Option<DeviceKey> {
        Ed25519KeyPair::from_pkcs8(&pkcs8).ok()?;
        Some(DeviceKey {
            device_id,
            pkcs8: Zeroizing::new(pkcs8),
        })
    }

    pub fn pkcs8(&self) -> &[u8] {
        &self.pkcs8
    }

    pub fn public_key(&self) -> Vec<u8> {
        Ed25519KeyPair::from_pkcs8(&self.pkcs8)
            .expect("checked")
            .public_key()
            .as_ref()
            .to_vec()
    }

    /// l4f's `devkey::message`: `"l4f-devkey-v1\0" || origin || "\0" ||
    /// device_id || "\0" || SHA-256(challenge)`.
    pub fn sign(&self, relay_id: &[u8; 16], challenge: &str) -> Vec<u8> {
        let mut m = b"l4f-devkey-v1\0".to_vec();
        m.extend_from_slice(origin(relay_id).as_bytes());
        m.push(0);
        m.extend_from_slice(&self.device_id);
        m.push(0);
        m.extend_from_slice(&Sha256::digest(challenge.as_bytes()));
        Ed25519KeyPair::from_pkcs8(&self.pkcs8)
            .expect("checked")
            .sign(&m)
            .as_ref()
            .to_vec()
    }
}

// ── The authenticator QR code ─────────────────────────────────────────────

/// An `otpauth://` link as an SVG QR code, made on this device: the relay
/// sends the link, never markup, so nothing it writes ends up in the page.
pub fn qr_svg(text: &str) -> Option<String> {
    let code =
        qrcode::QrCode::with_error_correction_level(text.as_bytes(), qrcode::EcLevel::M).ok()?;
    Some(
        code.render::<qrcode::render::svg::Color>()
            .min_dimensions(200, 200)
            .quiet_zone(true)
            .build(),
    )
}

// ── Proof of work ─────────────────────────────────────────────────────────

/// Solves the relay's ALTCHA challenge (SHA-256 of `salt || n`, n up to
/// `maxnumber`) and returns the payload the relay checks.
pub fn solve_pow(altcha: &str) -> Option<String> {
    let c: serde_json::Value = serde_json::from_str(altcha).ok()?;
    let salt = c["salt"].as_str()?;
    let challenge = c["challenge"].as_str()?;
    let max = c["maxnumber"].as_u64()?.min(10_000_000);
    (0..=max).find(|n| hex(&Sha256::digest(format!("{salt}{n}").as_bytes())) == challenge).map(|n| {
        serde_json::json!({
            "algorithm": c["algorithm"], "challenge": challenge, "number": n, "salt": salt, "signature": c["signature"]
        })
        .to_string()
    })
}

// ── Sign-in ───────────────────────────────────────────────────────────────

/// How this sign-in proves itself.
pub enum Method {
    /// With the password.
    Password { password: Zeroizing<String> },
    /// A new account, with an invite code where the relay wants one.
    Register {
        password: Zeroizing<String>,
        invite: Option<String>,
    },
    /// The key this device got at an earlier sign-in, and the vault's DEK
    /// kept with it (a device key opens no slot).
    Device {
        key: DeviceKey,
        relay_id: [u8; 16],
        dek: [u8; 32],
    },
    /// A forgotten password: the recovery key opens the vault, its identity
    /// signs the relay's challenge, and `password` becomes the new one. Ends
    /// in `Step::ResetDone`, not in a sign-in.
    Reset {
        recovery: Zeroizing<[u8; 32]>,
        password: Zeroizing<String>,
    },
}

/// What waits for the stretched password (`Step::Stretch`).
enum Pending {
    Salt(Option<PowChallenge>),
    Reset {
        challenge: Vec<u8>,
        blobs: Vec<VaultBlob>,
        second_factor: bool,
    },
}

/// What the host does next. Short-lived, one or two at a time: the size of
/// `Send` against the others does not matter.
#[allow(clippy::large_enum_variant)]
pub enum Step {
    Send(ClientMessage),
    /// Ask the person for a code from their authenticator app, then `totp`.
    NeedTotp,
    /// Build the pre-keys from `identity()` and send `keys(…)`.
    Keys,
    /// Only with `stretch_outside`: run PBKDF2 (`stretch`) on the password
    /// with this salt, then hand the result to `stretched`.
    Stretch {
        salt: String,
    },
    /// The reset went through: sign in with the new password (the relay ends
    /// this connection).
    ResetDone,
    /// Nothing to do with that message.
    Ignore,
}

/// What a finished sign-in leaves the device with.
pub struct SignedIn {
    pub relay_id: [u8; 16],
    pub name: String,
    pub vault: Vault,
    pub identity: IdentityKeyPair,
    /// A new account's recovery key, to show once.
    pub recovery: Option<String>,
    /// The vault items as the relay has them (with their versions).
    pub blobs: Vec<VaultBlob>,
}

/// One account sign-in, from `Authenticate` to `Authenticated`, as a state
/// machine the host feeds with server messages.
pub struct SignIn {
    name: String,
    method: Method,
    relay_id: Option<[u8; 16]>,
    /// The password's vault key, from `Salt` until the vault arrives.
    vault_key: Option<Zeroizing<[u8; 32]>>,
    vault: Option<Vault>,
    identity: Option<IdentityKeyPair>,
    recovery: Option<String>,
    blobs: Vec<VaultBlob>,
    totp_asked: bool,
    /// The relay id this address had before, and those other addresses have
    /// (`expect_relay`).
    relay_here: Option<[u8; 16]>,
    relay_elsewhere: Vec<([u8; 16], String)>,
    /// The host stretches the password itself (`Step::Stretch`).
    stretch_outside: bool,
    pending: Option<Pending>,
    /// A reset waiting for the person's code (`totp`, `recovery_code`).
    reset: Option<AuthContinue>,
}

impl SignIn {
    /// The machine and the `Authenticate` to open with. `name` must already
    /// be normalised (`normalize_name`).
    pub fn start(
        name: &str,
        method: Method,
        protocol_version: u32,
        app_version: &str,
    ) -> (SignIn, ClientMessage) {
        let account = match &method {
            Method::Password { .. } => AccountStart::Login,
            Method::Register { invite, .. } => AccountStart::Register {
                invite: invite.clone(),
            },
            Method::Device { key, .. } => AccountStart::DeviceKey {
                device_id: key.device_id.to_vec(),
            },
            Method::Reset { .. } => AccountStart::Reset,
        };
        let relay_id = match &method {
            Method::Device { relay_id, .. } => Some(*relay_id),
            _ => None,
        };
        let auth = ClientMessage::Authenticate {
            username: name.to_string(),
            protocol_version,
            app_version: app_version.to_string(),
            identity_key: None,
            prekey_bundle: None,
            account: Some(account),
        };
        let m = SignIn {
            name: name.to_string(),
            method,
            relay_id,
            vault_key: None,
            vault: None,
            identity: None,
            recovery: None,
            blobs: Vec::new(),
            totp_asked: false,
            relay_here: None,
            relay_elsewhere: Vec::new(),
            stretch_outside: false,
            pending: None,
            reset: None,
        };
        (m, auth)
    }

    /// The host runs PBKDF2 itself (the browser, with WebCrypto): the machine
    /// asks with `Step::Stretch` instead of stretching in `on_message`.
    pub fn stretch_outside(&mut self) {
        self.stretch_outside = true;
    }

    /// What this device knows of relay ids: the one this address said before,
    /// and the ones other addresses say. A `Salt` that disagrees ends the
    /// sign-in before anything of the password goes out. The secret is salted
    /// with the relay id the *server* names, so a server claiming another's id
    /// would get that server's secret from anyone with one password for both.
    pub fn expect_relay(&mut self, here: Option<[u8; 16]>, elsewhere: Vec<([u8; 16], String)>) {
        self.relay_here = here;
        self.relay_elsewhere = elsewhere;
    }

    fn relay_ok(&self, relay_id: &[u8; 16]) -> Result<(), String> {
        if let Some((_, addr)) = self.relay_elsewhere.iter().find(|(id, _)| id == relay_id) {
            return Err(format!(
                "This server says it is {addr}, another server you use. Signing in here could hand it what signs you in there. \
                 If {addr} moved here, forget its account id and try again."
            ));
        }
        if self.relay_here.is_some_and(|h| h != *relay_id) {
            return Err("This server's account id changed since you last signed in here. If it was reset or moved, forget its account id and try again.".into());
        }
        Ok(())
    }

    /// The account's identity, once known (for the host's pre-keys).
    pub fn identity(&self) -> Option<&IdentityKeyPair> {
        self.identity.as_ref()
    }

    /// The relay id, once the relay has said it.
    pub fn relay_id(&self) -> Option<[u8; 16]> {
        self.relay_id
    }

    /// Whether the relay asked for a code before (a repeated ask means the
    /// last code was wrong).
    pub fn totp_was_asked(&self) -> bool {
        self.totp_asked
    }

    pub fn totp(&self, code: &str) -> ClientMessage {
        let code = code.trim().replace(' ', "");
        match &self.reset {
            Some(AuthContinue::Reset {
                signature,
                key_signature,
                auth_secret,
                pass_slot,
                ..
            }) => ClientMessage::AuthContinue(AuthContinue::Reset {
                signature: signature.clone(),
                key_signature: key_signature.clone(),
                auth_secret: auth_secret.clone(),
                pass_slot: pass_slot.clone(),
                totp: Some(code),
                recovery_code: None,
            }),
            _ => ClientMessage::AuthContinue(AuthContinue::Totp { code }),
        }
    }

    pub fn recovery_code(&self, code: &str) -> ClientMessage {
        let code = code.trim().to_string();
        match &self.reset {
            Some(AuthContinue::Reset {
                signature,
                key_signature,
                auth_secret,
                pass_slot,
                ..
            }) => ClientMessage::AuthContinue(AuthContinue::Reset {
                signature: signature.clone(),
                key_signature: key_signature.clone(),
                auth_secret: auth_secret.clone(),
                pass_slot: pass_slot.clone(),
                totp: None,
                recovery_code: Some(code),
            }),
            _ => ClientMessage::AuthContinue(AuthContinue::Recovery { code }),
        }
    }

    /// `stretch`'s output for the salt `Step::Stretch` named.
    pub fn stretched(&mut self, master: &[u8; 32]) -> Result<Vec<Step>, String> {
        let relay_id = self.relay_id.ok_or("unexpected sign-in step")?;
        let d = derive_from_master(master);
        match (
            self.pending.take().ok_or("unexpected sign-in step")?,
            &self.method,
        ) {
            (Pending::Salt(_), Method::Password { .. }) => {
                self.vault_key = Some(d.vault_key);
                Ok(vec![Step::Send(ClientMessage::AuthContinue(
                    AuthContinue::Secret {
                        auth_secret: d.auth_secret.to_vec(),
                    },
                ))])
            }
            (Pending::Salt(pow), Method::Register { .. }) => {
                let (altcha, ts) = match pow {
                    Some(p) => (
                        solve_pow(&p.altcha).ok_or("The server's sign-up puzzle did not solve.")?,
                        p.ts,
                    ),
                    None => (String::new(), String::new()),
                };
                let vault = Vault::create(relay_id, &self.name);
                let recovery = random::<32>();
                let identity = IdentityKeyPair::generate(&mut crate::rng());
                let blobs = vec![
                    vault.pass_slot(&d.vault_key),
                    vault.recovery_slot(&recovery),
                    VaultBlob {
                        k: SLOT_RESET.into(),
                        v: reset_key(&recovery, &relay_id, &self.name).to_vec(),
                        version: 0,
                    },
                    vault.seal_item(ITEM_IDENTITY, 1, &identity.serialize()),
                ];
                self.recovery = Some(recovery_text(&recovery));
                self.vault = Some(vault);
                self.identity = Some(identity);
                self.blobs = blobs.clone();
                let register = AuthContinue::Register {
                    auth_secret: d.auth_secret.to_vec(),
                    altcha,
                    ts,
                    vault: blobs,
                };
                // The relay sends no vault back to a new account: the keys follow at once.
                Ok(vec![
                    Step::Send(ClientMessage::AuthContinue(register)),
                    Step::Keys,
                ])
            }
            (
                Pending::Reset {
                    challenge,
                    blobs,
                    second_factor,
                },
                Method::Reset { recovery, .. },
            ) => {
                let vault = Vault::open_with_recovery(relay_id, &self.name, &blobs, recovery)
                    .map_err(|e| match e {
                        VaultError::WrongKey => {
                            "That recovery key does not open this account.".to_string()
                        }
                        e => e.to_string(),
                    })?;
                let identity = vault
                    .open_item(&blobs, ITEM_IDENTITY)
                    .map_err(|e| e.to_string())?
                    .payload;
                let identity = IdentityKeyPair::try_from(&identity[..])
                    .map_err(|_| "The vault's identity key is damaged.".to_string())?;
                let reset = AuthContinue::Reset {
                    signature: reset_proof(&identity, &relay_id, &self.name, &challenge),
                    key_signature: reset_key_proof(recovery, &relay_id, &self.name, &challenge),
                    auth_secret: d.auth_secret.to_vec(),
                    pass_slot: vault.pass_slot(&d.vault_key).v,
                    totp: None,
                    recovery_code: None,
                };
                if second_factor {
                    self.reset = Some(reset);
                    self.totp_asked = true;
                    return Ok(vec![Step::NeedTotp]);
                }
                Ok(vec![Step::Send(ClientMessage::AuthContinue(reset))])
            }
            _ => Err("unexpected sign-in step".into()),
        }
    }

    /// The password to stretch, for `Step::Stretch` (the host may hold it
    /// already).
    fn password(&self) -> Option<&str> {
        match &self.method {
            Method::Password { password }
            | Method::Register { password, .. }
            | Method::Reset { password, .. } => Some(password),
            Method::Device { .. } => None,
        }
    }

    /// Stretches here, or asks the host to (`stretch_outside`).
    fn stretch_then(&mut self, pending: Pending) -> Result<Vec<Step>, String> {
        let relay_id = self.relay_id.ok_or("unexpected sign-in step")?;
        self.pending = Some(pending);
        if self.stretch_outside {
            return Ok(vec![Step::Stretch {
                salt: kdf_salt(&relay_id, &self.name),
            }]);
        }
        let master = stretch(
            self.password().ok_or("unexpected sign-in step")?,
            &relay_id,
            &self.name,
        );
        self.stretched(&master)
    }

    pub fn keys(&self, prekey_bundle: PreKeyBundleData) -> ClientMessage {
        let identity = self
            .identity
            .as_ref()
            .expect("Keys comes after the identity");
        ClientMessage::AuthContinue(AuthContinue::Keys {
            identity_key: identity.public_key().serialize().to_vec(),
            prekey_bundle,
            reset_identity: false,
        })
    }

    /// Feeds one server message. `Err` is the reason to show; it ends the
    /// sign-in (so does an `AuthError`, which comes back as `Err` too).
    pub fn on_message(&mut self, msg: &ServerMessage) -> Result<Vec<Step>, String> {
        match msg {
            ServerMessage::AuthError { reason } => Err(reason.clone()),
            ServerMessage::Refused { text, .. } => Err(text.clone()),
            ServerMessage::AuthStep(AuthStep::AccountRequired { .. }) => {
                Err("This server needs an account.".into())
            }
            ServerMessage::AuthStep(AuthStep::Salt { relay_id, pow }) => {
                if !matches!(
                    self.method,
                    Method::Password { .. } | Method::Register { .. }
                ) || self.relay_id.is_some()
                {
                    return Err("unexpected sign-in step".into());
                }
                self.relay_ok(relay_id)?;
                self.relay_id = Some(*relay_id);
                self.stretch_then(Pending::Salt(pow.clone()))
            }
            ServerMessage::AuthStep(AuthStep::ResetChallenge {
                relay_id,
                challenge,
                blobs,
                second_factor,
            }) => {
                if !matches!(self.method, Method::Reset { .. }) || self.relay_id.is_some() {
                    return Err("unexpected sign-in step".into());
                }
                self.relay_ok(relay_id)?;
                self.relay_id = Some(*relay_id);
                self.stretch_then(Pending::Reset {
                    challenge: challenge.clone(),
                    blobs: blobs.clone(),
                    second_factor: *second_factor,
                })
            }
            ServerMessage::AuthStep(AuthStep::ResetDone)
                if matches!(self.method, Method::Reset { .. }) =>
            {
                Ok(vec![Step::ResetDone])
            }
            ServerMessage::AuthStep(AuthStep::DeviceChallenge {
                relay_id,
                challenge,
            }) => match &self.method {
                Method::Device {
                    key,
                    relay_id: known,
                    ..
                } if known == relay_id => Ok(vec![Step::Send(ClientMessage::AuthContinue(
                    AuthContinue::DeviceSig {
                        signature: key.sign(relay_id, challenge),
                    },
                ))]),
                Method::Device { .. } => {
                    Err("This server is not the one this device was remembered by.".into())
                }
                _ => Err("unexpected sign-in step".into()),
            },
            ServerMessage::AuthStep(AuthStep::NeedTotp) => {
                self.totp_asked = true;
                Ok(vec![Step::NeedTotp])
            }
            ServerMessage::AuthStep(AuthStep::Vault { blobs }) => {
                let relay_id = self.relay_id.ok_or("unexpected sign-in step")?;
                let vault = match &self.method {
                    Method::Password { .. } => {
                        let key = self.vault_key.take().ok_or("unexpected sign-in step")?;
                        Vault::open_with_password(relay_id, &self.name, blobs, &key)
                            .map_err(|e| e.to_string())?
                    }
                    Method::Device { dek, .. } => Vault::from_dek(relay_id, &self.name, *dek),
                    Method::Register { .. } | Method::Reset { .. } => {
                        return Err("unexpected sign-in step".into())
                    }
                };
                let identity = vault
                    .open_item(blobs, ITEM_IDENTITY)
                    .map_err(|e| e.to_string())?
                    .payload;
                self.identity = Some(
                    IdentityKeyPair::try_from(&identity[..])
                        .map_err(|_| "The vault's identity key is damaged.".to_string())?,
                );
                self.vault = Some(vault);
                self.blobs = blobs.clone();
                Ok(vec![Step::Keys])
            }
            _ => Ok(vec![Step::Ignore]),
        }
    }

    /// After `Authenticated`: the open vault and the identity.
    pub fn finish(self) -> Result<SignedIn, String> {
        Ok(SignedIn {
            relay_id: self.relay_id.ok_or("the relay never said its id")?,
            name: self.name,
            vault: self.vault.ok_or("no vault")?,
            identity: self.identity.ok_or("no identity")?,
            recovery: self.recovery,
            blobs: self.blobs,
        })
    }
}

/// Remembering this device after a sign-in with the password: ask for a
/// challenge, sign it with a new key, and keep the key once the relay says so.
pub struct DeviceEnrol {
    pub key: DeviceKey,
    relay_id: [u8; 16],
}

impl DeviceEnrol {
    pub fn start(relay_id: [u8; 16]) -> (DeviceEnrol, ClientMessage) {
        (
            DeviceEnrol {
                key: DeviceKey::generate(),
                relay_id,
            },
            ClientMessage::Account(AccountRequest::DeviceChallenge),
        )
    }

    /// `Some(message)` to send, for the challenge; the key is the device's once
    /// `AccountReply::DeviceAdded` arrives.
    pub fn on_reply(&self, reply: &AccountReply) -> Option<ClientMessage> {
        match reply {
            AccountReply::DeviceChallenge { challenge } => {
                Some(ClientMessage::Account(AccountRequest::DeviceAdd {
                    device_id: self.key.device_id.to_vec(),
                    public_key: self.key.public_key(),
                    signature: self.key.sign(&self.relay_id, challenge),
                }))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RELAY: [u8; 16] = [0x11; 16];

    #[test]
    fn names_follow_the_relays_rules() {
        assert_eq!(normalize_name("  Luki_4Fun ").unwrap(), "luki_4fun");
        for bad in ["ab", "luki#0420", "-luki", "1234", "zoë", &"x".repeat(33)] {
            assert!(normalize_name(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_two_keys_differ_and_depend_on_relay_and_name() {
        let a = derive("correct horse battery", &RELAY, "luki");
        assert_ne!(
            a.auth_secret, *a.vault_key,
            "the relay's secret never opens the vault"
        );
        assert_eq!(
            a.auth_secret,
            derive("correct horse battery", &RELAY, "luki").auth_secret
        );
        assert_ne!(
            a.auth_secret,
            derive("correct horse battery", &[0x12; 16], "luki").auth_secret
        );
        assert_ne!(
            a.auth_secret,
            derive("correct horse battery", &RELAY, "lukas").auth_secret
        );
    }

    /// Pins the derivation: a client that changes it locks every account out.
    #[test]
    fn derivation_known_answer() {
        let d = derive("correct horse battery", &RELAY, "luki");
        assert_eq!(hex(&d.auth_secret), KNOWN_AUTH);
        assert_eq!(hex(&*d.vault_key), KNOWN_VAULT);
    }
    // From Python's hashlib (pbkdf2_hmac + HKDF by hand), not from this code.
    const KNOWN_AUTH: &str = "5ebcb75c54d09c37dc8603074d746268309cc2cc23c229028dc5fe0b753f134b";
    const KNOWN_VAULT: &str = "250f45306cdf7e0bac6cdbf8081604c2109ea0517464655e88bd2ac18750c965";

    #[test]
    fn a_vault_opens_with_the_password_or_the_recovery_key_and_nothing_else() {
        let v = Vault::create(RELAY, "luki");
        let d = derive("pw-pw-pw-pw", &RELAY, "luki");
        let rec = random::<32>();
        let identity = IdentityKeyPair::generate(&mut crate::rng());
        let blobs = vec![
            v.pass_slot(&d.vault_key),
            v.recovery_slot(&rec),
            v.seal_item(ITEM_IDENTITY, 1, &identity.serialize()),
        ];

        let by_pw = Vault::open_with_password(RELAY, "luki", &blobs, &d.vault_key).unwrap();
        assert_eq!(by_pw.dek(), v.dek());
        let by_rec = Vault::open_with_recovery(
            RELAY,
            "luki",
            &blobs,
            &recovery_parse(&recovery_text(&rec)).unwrap(),
        )
        .unwrap();
        assert_eq!(by_rec.dek(), v.dek());
        assert_eq!(
            by_rec.open_item(&blobs, ITEM_IDENTITY).unwrap().payload,
            identity.serialize().to_vec()
        );

        assert_eq!(
            Vault::open_with_password(RELAY, "luki", &blobs, &[0; 32]).err(),
            Some(VaultError::WrongKey)
        );
        // Bound to the relay and the name: the relay cannot hand it to another account.
        assert_eq!(
            Vault::open_with_password(RELAY, "lukas", &blobs, &d.vault_key).err(),
            Some(VaultError::WrongKey)
        );
        assert_eq!(
            Vault::open_with_password([0x12; 16], "luki", &blobs, &d.vault_key).err(),
            Some(VaultError::WrongKey)
        );
        // An item renamed is an item that does not open.
        let mut moved = blobs.clone();
        moved[2].k = "item.pins".into();
        assert_eq!(
            by_pw.open_item(&moved, "item.pins").err(),
            Some(VaultError::Corrupt)
        );
        let mut flipped = blobs;
        let last = flipped[2].v.len() - 1;
        flipped[2].v[last] ^= 1;
        assert_eq!(
            by_pw.open_item(&flipped, ITEM_IDENTITY).err(),
            Some(VaultError::Corrupt)
        );

        // A newer VoIPC's item is told apart from a damaged one, by its first
        // byte or by the format inside: never mistaken for "missing" and
        // replaced.
        let mut newer = vec![v.seal_item("item.x", 3, b"p")];
        let item = by_pw.open_item(&newer, "item.x").unwrap();
        assert_eq!((item.gen, item.payload.as_slice()), (3, &b"p"[..]));
        newer[0].v[0] = 3;
        assert_eq!(
            by_pw.open_item(&newer, "item.x").err(),
            Some(VaultError::Newer)
        );
        let mut inner = (ITEM_FORMAT + 1).to_be_bytes().to_vec();
        inner.extend_from_slice(&[0; 8]);
        let (iv, ct) = seal(&v.dek, &v.item_aad("item.x"), &inner);
        let blob = VaultBlob {
            k: "item.x".into(),
            v: [&[ITEM_V2][..], &v.dek_id(), &iv, &ct].concat(),
            version: 1,
        };
        assert_eq!(
            by_pw.open_item(&[blob], "item.x").err(),
            Some(VaultError::Newer)
        );
    }

    #[test]
    fn pins_trust_the_first_key_and_report_a_change_once() {
        let mut p = Pins::default();
        let (a, b) = ([1u8; 16], [2u8; 16]);
        assert_eq!(p.check(&a, "ann", &[5; 33]), PinCheck::New);
        assert_eq!(p.check(&a, "ann", &[5; 33]), PinCheck::Same);
        assert_eq!(p.check(&a, "ann", &[6; 33]), PinCheck::Changed);
        assert_eq!(p.check(&a, "ann", &[6; 33]), PinCheck::Same, "told once");
        let mut other = Pins::default();
        other.check(&b, "ben", &[7; 33]);
        other.check(&a, "ann", &[5; 33]);
        p.merge(Pins::from_bytes(&other.to_bytes()).unwrap());
        assert_eq!(p.len(), 2);
        assert_eq!(
            p.check(&a, "ann", &[5; 33]),
            PinCheck::Same,
            "theirs wins in a merge"
        );
    }

    #[test]
    fn a_server_claiming_another_servers_relay_id_gets_nothing_of_the_password() {
        let salt = |relay_id| {
            ServerMessage::AuthStep(AuthStep::Salt {
                relay_id,
                pow: None,
            })
        };
        let start = || {
            SignIn::start(
                "ann",
                Method::Password {
                    password: Zeroizing::new("correct horse battery".into()),
                },
                11,
                "t",
            )
            .0
        };
        let mut m = start();
        m.expect_relay(None, vec![([7; 16], "home.example:9987".into())]);
        let e = m.on_message(&salt([7; 16])).err().expect("refused");
        assert!(
            e.contains("home.example:9987") && e.contains("forget its account id"),
            "{e}"
        );
        let mut m = start();
        m.expect_relay(Some([1; 16]), Vec::new());
        assert!(m
            .on_message(&salt([2; 16]))
            .err()
            .expect("refused")
            .contains("changed"));
        let mut m = start();
        m.expect_relay(Some([1; 16]), vec![([7; 16], "home.example:9987".into())]);
        let steps = m.on_message(&salt([1; 16])).unwrap();
        assert!(
            matches!(
                steps[..],
                [Step::Send(ClientMessage::AuthContinue(
                    AuthContinue::Secret { .. }
                ))]
            ),
            "the known id signs in"
        );
    }

    #[test]
    fn a_name_that_turns_up_under_another_account_is_a_change() {
        let mut p = Pins::default();
        let (bob, fake) = ([1u8; 16], [9u8; 16]);
        assert_eq!(p.check(&bob, "bob", &[5; 33]), PinCheck::New);
        // The relay shows "bob" under a fresh id, with a key of its own: no
        // pin by id, but the name was bob's.
        assert_eq!(p.check(&fake, "Bob", &[6; 33]), PinCheck::Replaced);
        assert_eq!(p.check(&fake, "bob", &[6; 33]), PinCheck::Same, "told once");
        assert_eq!(
            p.check(&bob, "bob", &[5; 33]),
            PinCheck::Replaced,
            "and back again is a change too"
        );
        assert_eq!(
            p.check(&[3; 16], "", &[7; 33]),
            PinCheck::New,
            "no name: the key alone"
        );
    }

    #[test]
    fn both_sides_see_the_same_safety_number_and_another_key_changes_it() {
        let (a, b) = (
            IdentityKeyPair::generate(&mut crate::rng()),
            IdentityKeyPair::generate(&mut crate::rng()),
        );
        let (ka, kb) = (a.public_key().serialize(), b.public_key().serialize());
        let ab = safety_number(&[1; 16], &ka, &[2; 16], &kb).unwrap();
        let ba = safety_number(&[2; 16], &kb, &[1; 16], &ka).unwrap();
        assert_eq!(ab, ba);
        assert_eq!(ab.len(), 60 + 11, "12 groups of five");
        let m = IdentityKeyPair::generate(&mut crate::rng());
        assert_ne!(
            ab,
            safety_number(&[1; 16], &ka, &[2; 16], &m.public_key().serialize()).unwrap(),
            "a relay's key shows"
        );
    }

    #[test]
    fn recovery_keys_read_back_however_they_are_typed() {
        let k = random::<32>();
        let t = recovery_text(&k);
        assert_eq!(t.len(), 52 + 12, "52 Base32 characters in groups of four");
        assert_eq!(recovery_parse(&t), Some(k));
        assert_eq!(recovery_parse(&t.to_lowercase().replace('-', " ")), Some(k));
        assert_eq!(recovery_parse("AAAA"), None);
    }

    #[test]
    fn a_device_key_signs_what_l4f_checks() {
        let key = DeviceKey::generate();
        let sig = key.sign(&RELAY, "token");
        let mut m = b"l4f-devkey-v1\0".to_vec();
        m.extend_from_slice(origin(&RELAY).as_bytes());
        m.push(0);
        m.extend_from_slice(&key.device_id);
        m.push(0);
        m.extend_from_slice(&Sha256::digest(b"token"));
        let pk =
            ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, key.public_key());
        assert!(pk.verify(&m, &sig).is_ok());
        let again = DeviceKey::from_parts(key.device_id, key.pkcs8().to_vec()).unwrap();
        assert_eq!(again.public_key(), key.public_key());
    }
}
