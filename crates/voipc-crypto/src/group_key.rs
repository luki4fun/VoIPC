//! The group epoch key for text channels and voice rooms: the primitives of
//! docs/GROUP-KEY.md (draft v2), C1. Nothing here talks to a relay or keeps
//! state; the wire (C2), the clients (C3) and the database (C4) build on it.
//!
//! - A group (`Group`: kind, id, generation) has one epoch key `CK_e` per
//!   epoch. Keyholders hand it out by seals (`seal`), one per bucket version,
//!   under a bucket key `BK(b,v)` that reaches about 62 seats by rows
//!   (`RowBase::row`) or by a hybrid welcome (`welcome`).
//! - A welcome is Kyber1024 and X25519 under one KDF, with the keyholder's own
//!   static X25519 mixed in, so only a keyholder can make one that opens.
//! - Keyholders share a keyring (`keyring`), sealed under `KRK` and committed
//!   to by a hash chain in every header.
//! - Every header (`header`) is signed by a keyholder and carries `confirm`,
//!   a PRF of `CK_e`, so a member who opened a seal knows it is the key the
//!   header names. Its bucket root (`merkle`) commits to every seat list.
//! - Writers post under a libsignal sender key handed out in a writer blob
//!   (`writer`), sealed under `CK_e` and signed by the writer.
//! - `rules` holds what a member checks before it takes a header (§4.4) and
//!   the rollback floor (§5.7), as pure functions over the member's floor;
//!   a writer's fold of the gated names before it posts, a keyholder's
//!   checks of each list it takes and of a KeyholdersReplace, and the seed
//!   rolls by kind (§5.6).
//!
//! Every derivation names its whole context (§11.1): the label, then the
//! group's kind, id and generation, then the rest. The HKDF info and the
//! AES-GCM AAD of one value are the same string, so a value moved to any other
//! place does not open there.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

mod ctx;
mod derive;
mod header;
mod keyring;
mod keys;
mod merkle;
mod rules;
mod welcome;
mod writer;

pub mod build;
pub mod commit;
pub mod past;
pub mod timers;
pub mod tree;

#[cfg(test)]
mod kat;
#[cfg(test)]
mod tests;

pub use ctx::{
    valid_group_id, Epoch, Group, GroupKind, HolderId, KeyringWord, MemberId, SeatRef, Version,
    Writer, MAX_GROUP_BYTES,
};
pub use derive::{
    chain_seal, confirm, confirm_ok, history_row, media_key, member_secret, open_chain_seal,
    open_history_row, open_seal, open_self_row, ratchet, seal, self_row, HistoryEntry, RowBase,
};
pub use header::{
    digest, keyholder_set_digest, names_hash, names_list_digest, names_start, names_step, Added,
    AddedSeat, Header, HeaderV1, Keyholder, Kind, NamesList, NamesStep, Removed, SignedHeader,
    HEADER_MAX_BYTES, MAX_ADDED, MAX_KEYHOLDERS, MAX_REMOVED,
};
pub use keyring::{
    check_carried, keyring_hash_next, keyring_hash_start, open_keyring_part, seal_base, seal_delta,
    take_keyring, Keyring, KeyringBase, KeyringBucket, KeyringDelta, KeyringPart,
};
pub use keys::{
    tag, Endorsement, Holder, Me, OldSeat, Origin, SeatKeys, SeatPair, SeatPublic, Them,
    ITEM_SEAT_KEM,
};
pub use merkle::{
    bucket_root, check_reversion, inclusion_path, leaf_hash, list_digest, path_ok, seat_record,
    Leaf, Path, Pool, Via, BUCKET_SEATS,
};
pub use rules::{
    check_above, check_added, check_counters, check_form, check_gated, check_keyholder_change,
    check_link, check_new_generation, check_on_floor, check_regenesis, check_roll, check_signer,
    check_time, check_versions, check_voice_keyholders, check_walk, counter_flagged,
    epoch_bound_ok, fold_names, names_may_be_gone, replaced_entry, row_seed, Clock, Counters,
    Floor, Fold, Held, Known, NamesFloor, NamesFrom, PinThen, Pins, PinsAt, Refusal, RowSeed,
    SeedRolls, Seen, Shown, Swap, WalkLink, WalkTo, Walked, Warning, NAMES_KEPT, ROLL_GAP,
    SEED_MAX_AGE,
};
pub use welcome::{
    keyring_welcome, open_keyring_welcome, open_seat_welcome, open_seed_welcome, seat_welcome,
    seed_welcome, SEAT_WELCOME_BYTES, SMALL_WELCOME_BYTES,
};
pub use writer::{dist, open_post, open_writer_blob, post_plaintext, writer_blob, OpenedBlob};

/// What an opener says when it refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GkError {
    /// Does not open: another key, another context, or changed bytes.
    Sealed,
    /// Opens, but is not what its maker may give: a signature not its
    /// signer's, a version with a seat its source did not hold, or a keyring
    /// that carries a seed or bucket key other than this keyholder's own
    /// copy (§3.7).
    Forged,
    /// Not the shape this value has.
    Malformed,
    /// A key, seed or `KRK` of 32 zero bytes, or an X25519 key of low order:
    /// what nobody honest sends, and what would make the value open for anyone.
    WeakKey,
}

impl std::fmt::Display for GkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            GkError::Sealed => "a group key value does not open",
            GkError::Forged => "a group key value is not what its signer or maker may give",
            GkError::Malformed => "a group key value is malformed",
            GkError::WeakKey => "a group key value carries an all-zero or low-order key",
        })
    }
}

impl std::error::Error for GkError {}

/// A row and a seal: `iv (12) | sealed 32-byte key + tag (48)`.
pub const ROW_BYTES: usize = 12 + 32 + 16;
/// How far ahead of a member's clock a header's `time` may be (§4.4 rule 7).
pub const CLOCK_SLACK: u64 = 10 * 60;
/// The relay starts at most one opening commit per group in this many
/// seconds (§4.1), which bounds how far a walked header's epoch may run.
pub const EPOCH_MIN_GAP: u64 = 2;
/// How long no keyholder must have been online before a Regenesis (§4.3).
pub const REGENESIS_WAIT: u64 = 60 * 60;
/// A device that took a header this recently follows the group live (§5.7).
pub const LIVE_WINDOW: u64 = 10 * 60;
/// The longest keyholder chain a member walks (§4.4 rule 3).
pub const MAX_WALK: usize = 4096;
/// The generation ids a floor remembers (§5.7).
pub const RECENT_GENS: usize = 8;

/// HKDF-SHA256 with the given salt (`None`: empty), 32 bytes out.
fn hkdf32(salt: Option<&[u8]>, ikm: &[u8], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut k = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(salt, ikm)
        .expand(info, &mut *k)
        .expect("32 bytes is a valid HKDF length");
    k
}

/// `AEAD(HKDF(key, c), c, plaintext)`: `iv (12) | ciphertext + tag`.
fn seal_derived(key: &[u8; 32], c: &str, plaintext: &[u8]) -> Vec<u8> {
    seal_under(&hkdf32(None, key, c.as_bytes()), c, plaintext)
}

/// `AEAD(kek, c, plaintext)` under a key already derived for `c`.
fn seal_under(kek: &[u8; 32], c: &str, plaintext: &[u8]) -> Vec<u8> {
    let (iv, ct) = crate::aead::seal(kek, c, plaintext);
    [&iv[..], &ct].concat()
}

fn open_derived(key: &[u8; 32], c: &str, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, GkError> {
    open_under(&hkdf32(None, key, c.as_bytes()), c, sealed)
}

fn open_under(kek: &[u8; 32], c: &str, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, GkError> {
    if sealed.len() < 12 + 16 {
        return Err(GkError::Malformed);
    }
    crate::aead::open(kek, c, &sealed[..12], &sealed[12..])
        .map(Zeroizing::new)
        .ok_or(GkError::Sealed)
}

/// The postcard encoding of a value that holds secrets, written straight
/// into a buffer of its exact size: `postcard::to_allocvec` grows its buffer
/// as it goes and frees every smaller one unwiped, each holding a prefix of
/// the plaintext.
fn encode_secret<T: serde::Serialize + ?Sized>(value: &T) -> Zeroizing<Vec<u8>> {
    let n = postcard::experimental::serialized_size(value).expect("a value of ours encodes");
    let mut out = Zeroizing::new(vec![0u8; n]);
    postcard::to_slice(value, &mut out).expect("sized to fit");
    out
}

/// What the fuzz target seals its input as, so that it reaches the parsers
/// behind each AEAD: a fuzzer cannot forge a GCM tag.
#[cfg(any(test, fuzzing))]
pub(crate) mod fuzz_seal {
    use super::ctx::{self_history_ctx, writer_ctx, Epoch, Group, SeatRef, Writer};
    use super::keyring::{part_ctx, KeyringPart};

    /// `plain` as a writer blob's plaintext.
    pub(crate) fn writer(
        g: &Group,
        ep: &Epoch,
        w: &Writer,
        ck: &[u8; 32],
        plain: &[u8],
    ) -> Vec<u8> {
        super::seal_derived(ck, &writer_ctx(g, ep, w), plain)
    }

    /// `plain` as a keyring part's plaintext.
    pub(crate) fn keyring(
        g: &Group,
        e: u32,
        s: u32,
        ks: &[u8; 32],
        krk: &[u8; 32],
        part: KeyringPart,
        plain: &[u8],
    ) -> Vec<u8> {
        super::seal_derived(krk, &part_ctx(g, e, s, ks, part), plain)
    }

    /// `plain` as a history row's plaintext.
    pub(crate) fn history(
        g: &Group,
        s: u32,
        seat: &SeatRef,
        self_key: &[u8; 32],
        plain: &[u8],
    ) -> Vec<u8> {
        super::seal_derived(self_key, &self_history_ctx(g, s, seat), plain)
    }
}

/// A 32-byte secret out of an opened value, refused when all zero (§3).
fn secret32(bytes: &[u8]) -> Result<Zeroizing<[u8; 32]>, GkError> {
    let mut k = Zeroizing::new([0u8; 32]);
    k.copy_from_slice(bytes.get(..32).ok_or(GkError::Malformed)?);
    nonzero(&k)?;
    Ok(k)
}

fn nonzero(k: &[u8; 32]) -> Result<(), GkError> {
    if k.iter().all(|&b| b == 0) {
        Err(GkError::WeakKey)
    } else {
        Ok(())
    }
}

/// A 60-byte value carrying one 32-byte secret: a row, a seal, a chain seal,
/// a self-row.
fn open_row_shaped(key: &[u8; 32], c: &str, sealed: &[u8]) -> Result<Zeroizing<[u8; 32]>, GkError> {
    if sealed.len() != ROW_BYTES {
        return Err(GkError::Malformed);
    }
    secret32(&open_derived(key, c, sealed)?)
}
