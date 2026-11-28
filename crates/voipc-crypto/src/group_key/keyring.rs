//! The keyring (§3.7, §11.6): what keyholders share. A base at every opening
//! header and a delta at every Join, each sealed under `KRK`, chained by
//! hash into the header's `keyring_hash`.
//!
//! ```text
//! base_e    = AEAD(HKDF(KRK, c), c, base)    c = ctx(keyring; k, group, gen, e, 0, s, KS, base)
//! delta_e,j = AEAD(HKDF(KRK, c), c, delta)   c = ctx(keyring; k, group, gen, e, j, s, KS, delta)
//! H_e,0     = SHA-256("voipc-gk/v1/keyring-hash|" ‖ 0³² ‖ SHA-256(base_e))
//! H_e,j     = SHA-256("voipc-gk/v1/keyring-hash|" ‖ H_e,j-1 ‖ SHA-256(delta_e,j))
//! ```
//!
//! A keyholder takes a keyring only under its head: everything the context
//! binds comes from the head, never from the plaintext.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::ctx::{keyring_ctx, Group, KeyringWord, Version, KEYRING_HASH_LABEL};
use super::derive::confirm_ok;
use super::header::{keyholder_set_digest, SignedHeader};
use super::merkle::{bucket_root, Leaf, Pool, Via, BUCKET_SEATS};
use super::rules::SeedRolls;
use super::{encode_secret, nonzero, open_derived, seal_derived, GkError};

/// One bucket version as keyholders hold it (§11.6), sorted by `b`.
///
/// Every secret in the keyring is a `Zeroizing<[u8; 32]>`: it encodes as the
/// bare 32 bytes, wipes itself wherever it is dropped (a value that failed
/// to decode halfway included), and prints as nothing in `Debug`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyringBucket {
    pub b: u64,
    pub v: u64,
    pub pool: Pool,
    pub seats: u16,
    pub list: [u8; 32],
    pub via: Via,
    pub bk: Zeroizing<[u8; 32]>,
    /// Unix seconds; a ratchet version copies its source's (§3.5), so a
    /// promotion never puts off the hourly re-key by rows (§5.5).
    pub made: u64,
}

impl KeyringBucket {
    pub fn version(&self) -> Version {
        Version {
            b: self.b,
            v: self.v,
        }
    }

    pub fn leaf(&self) -> Leaf {
        Leaf {
            b: self.b,
            v: self.v,
            pool: self.pool,
            seats: self.seats,
            list: self.list,
            via: self.via,
        }
    }

    /// The version a promotion ratchets this one into (§3.5): new id `v_new`,
    /// `BK` ratcheted under epoch `e`, same seats and list, and the source's
    /// `made`. The list digest names `(b, v)`, so it is the caller's to
    /// recompute for the new id.
    pub fn ratcheted(&self, g: &Group, e: u32, v_new: u64, list: [u8; 32]) -> KeyringBucket {
        KeyringBucket {
            b: self.b,
            v: v_new,
            pool: self.pool,
            seats: self.seats,
            list,
            via: Via::Ratchet { from: self.v },
            bk: super::derive::ratchet(g, e, self.version(), v_new, &self.bk),
            made: self.made,
        }
    }
}

/// The keyring at `(e, 0)`. `seeds` holds `seed_floor..=seed`, ascending.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyringBase {
    pub gen: [u8; 16],
    pub epoch: u32,
    pub join: u32,
    pub seeds: Vec<(u32, Zeroizing<[u8; 32]>)>,
    pub ck: Zeroizing<[u8; 32]>,
    pub exits_upto: u64,
    pub buckets: Vec<KeyringBucket>,
    /// The seed rolls as of this epoch's opening header (§5.6): the `time` of
    /// the header that last raised `seed`, and whether a keyholder was removed
    /// since. Carried here, where the relay can neither read nor change it, so a
    /// keyholder that takes its keyring fresh counts a roll's 24 h and a seed's
    /// 30 days from the truth (RV review of the Q2 fix).
    pub rolls: SeedRolls,
}

/// The buckets a Join commit added at `(e, j)`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyringDelta {
    pub join: u32,
    pub buckets: Vec<KeyringBucket>,
}

/// Base or delta, sealed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyringPart {
    Base,
    Delta(u32),
}

pub(super) fn part_ctx(g: &Group, e: u32, s: u32, ks: &[u8; 32], part: KeyringPart) -> String {
    match part {
        KeyringPart::Base => keyring_ctx(g, e, 0, s, ks, KeyringWord::Base),
        KeyringPart::Delta(j) => keyring_ctx(g, e, j, s, ks, KeyringWord::Delta),
    }
}

/// The base under `KRK`. `s` is the head's seed, `ks` the digest of the
/// head's keyholder set.
pub fn seal_base(g: &Group, s: u32, ks: &[u8; 32], krk: &[u8; 32], base: &KeyringBase) -> Vec<u8> {
    let plain = encode_secret(base);
    seal_derived(
        krk,
        &part_ctx(g, base.epoch, s, ks, KeyringPart::Base),
        &plain,
    )
}

pub fn seal_delta(
    g: &Group,
    e: u32,
    s: u32,
    ks: &[u8; 32],
    krk: &[u8; 32],
    delta: &KeyringDelta,
) -> Vec<u8> {
    let plain = encode_secret(delta);
    seal_derived(
        krk,
        &part_ctx(g, e, s, ks, KeyringPart::Delta(delta.join)),
        &plain,
    )
}

/// One part's plaintext, opened under the context the caller builds from
/// the head. `KRK` of all zero is refused.
pub fn open_keyring_part(
    g: &Group,
    e: u32,
    s: u32,
    ks: &[u8; 32],
    krk: &[u8; 32],
    part: KeyringPart,
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, GkError> {
    nonzero(krk)?;
    open_derived(krk, &part_ctx(g, e, s, ks, part), sealed)
}

/// `H_e,0` from the sealed base.
pub fn keyring_hash_start(base: &[u8]) -> [u8; 32] {
    keyring_hash_next(&[0; 32], base)
}

/// `H_e,j` from `H_e,j-1` and the sealed delta at `j`.
pub fn keyring_hash_next(prev: &[u8; 32], sealed: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(KEYRING_HASH_LABEL)
        .chain_update(prev)
        .chain_update(Sha256::digest(sealed))
        .finalize()
        .into()
}

/// A keyring taken under its head.
pub struct Keyring {
    pub base: KeyringBase,
    /// Every current version: the base's and every delta's, sorted by `b`.
    pub buckets: Vec<KeyringBucket>,
}

impl Keyring {
    pub fn ck(&self) -> &[u8; 32] {
        &self.base.ck
    }

    pub fn seed(&self, s: u32) -> Option<&[u8; 32]> {
        self.base
            .seeds
            .iter()
            .find(|(n, _)| *n == s)
            .map(|(_, k)| &**k)
    }
}

/// Takes a keyring under `head` (§3.7), only if all of these hold:
/// - the hash chain over `base` and `deltas` is the head's `keyring_hash`,
///   with exactly one delta per join of the head's epoch;
/// - base and deltas open under contexts built from the head's `gen`, `e`
///   and `seed` and the `KS` of the head's keyholder set (`kh`, the header
///   that set it: the head itself, or the one its `kh_parent` names), each
///   delta at its own position `j`;
/// - the base's `gen` and `epoch` are the head's and its `join` is 0; its
///   `seeds` hold exactly `seed_floor..=seed`; each delta's `join` is its `j`;
/// - its `rolls` raise no later than the head's `time`: at a Genesis or a
///   Regenesis, the head's own with no removal; at a KeyholdersRemove, a
///   removal unless that header raised the seed itself;
/// - its `ck` passes the head's `confirm`;
/// - the root over its versions is the head's `bucket_root`, and the seats,
///   versions and connection-pool seats add up to the head's counts.
///
/// Also refused: any key, seed or `KRK` of all zero, a version with no seat
/// or more than 62, and a delta bucket that is not a new bucket by rows (a
/// Join only makes new buckets, §4.3).
pub fn take_keyring(
    g: &Group,
    head: &SignedHeader,
    kh: &SignedHeader,
    krk: &[u8; 32],
    base: &[u8],
    deltas: &[Vec<u8>],
) -> Result<Keyring, GkError> {
    let h = head.header();
    if h.gen != g.gen() || h.group != g.id() || h.group_kind != g.kind() {
        return Err(GkError::Malformed);
    }
    if kh.d() != head.kh() || !kh.header().kind.sets_keyholders() {
        return Err(GkError::Malformed);
    }
    if deltas.len() != h.join as usize {
        return Err(GkError::Sealed);
    }
    let mut chain = keyring_hash_start(base);
    for d in deltas {
        chain = keyring_hash_next(&chain, d);
    }
    if chain != h.keyring_hash {
        return Err(GkError::Sealed);
    }
    let ks = keyholder_set_digest(&kh.header().keyholders);
    let plain = open_keyring_part(g, h.epoch, h.seed, &ks, krk, KeyringPart::Base, base)?;
    let base: KeyringBase = postcard::from_bytes(&plain).map_err(|_| GkError::Malformed)?;
    if base.gen != h.gen || base.epoch != h.epoch || base.join != 0 {
        return Err(GkError::Sealed);
    }
    let numbers: Vec<u32> = base.seeds.iter().map(|(n, _)| *n).collect();
    if !numbers.iter().copied().eq(h.seed_floor..=h.seed) {
        return Err(GkError::Sealed);
    }
    for (_, seed) in &base.seeds {
        nonzero(seed)?;
    }
    if !base.rolls.fits(h) {
        return Err(GkError::Sealed);
    }
    nonzero(&base.ck)?;
    if !confirm_ok(g, h.epoch, h.join, &base.ck, &h.confirm) {
        return Err(GkError::Sealed);
    }
    let mut opened = Vec::with_capacity(deltas.len());
    for (i, sealed) in deltas.iter().enumerate() {
        let j = i as u32 + 1;
        let plain = open_keyring_part(g, h.epoch, h.seed, &ks, krk, KeyringPart::Delta(j), sealed)?;
        let delta: KeyringDelta = postcard::from_bytes(&plain).map_err(|_| GkError::Malformed)?;
        if delta.join != j || delta.buckets.iter().any(|b| b.via != Via::Row) {
            return Err(GkError::Sealed);
        }
        opened.push(delta);
    }
    // Every version holds its BK inline: sized once and sorted in place, so
    // no growing vector or sort buffer leaves a copy behind.
    let n = base.buckets.len() + opened.iter().map(|d| d.buckets.len()).sum::<usize>();
    let mut buckets = Vec::with_capacity(n);
    buckets.extend(base.buckets.iter().cloned());
    for delta in &opened {
        buckets.extend(delta.buckets.iter().cloned());
    }
    buckets.sort_unstable_by_key(|b| b.b);
    let leaves: Vec<Leaf> = buckets.iter().map(KeyringBucket::leaf).collect();
    if bucket_root(&leaves)? != h.bucket_root {
        return Err(GkError::Sealed);
    }
    let mut seats = 0u64;
    let mut conn_seats = 0u64;
    for b in &buckets {
        nonzero(&b.bk)?;
        if b.seats == 0 || b.seats > BUCKET_SEATS {
            return Err(GkError::Malformed);
        }
        seats += u64::from(b.seats);
        if b.pool == Pool::Conns {
            conn_seats += u64::from(b.seats);
        }
    }
    if seats != u64::from(h.seats)
        || buckets.len() as u64 != u64::from(h.buckets)
        || conn_seats != u64::from(h.conn_seats)
    {
        return Err(GkError::Sealed);
    }
    Ok(Keyring { base, buckets })
}

/// The last check of §3.7, for a keyholder that held the parent's keyring
/// (`own`): every seed the new keyring carries over, and every version it
/// keeps unchanged (the same `(b, v)`), is exactly this keyholder's own copy.
/// So no commit, a KeyholdersReplace from a pair the others never saw among
/// them, hands the other keyholders a seed or bucket key of its maker's
/// choosing (§4.3, §5.11). Refused as `Forged`: it opens, but it is not what
/// its maker may give.
///
/// A version id never stands for another key or seat set in a generation
/// (§4.1), so a kept version is compared whole, its `made` included.
pub fn check_carried(own: &Keyring, new: &Keyring) -> Result<(), GkError> {
    for (n, seed) in &new.base.seeds {
        if own.seed(*n).is_some_and(|mine| !same_secret(mine, seed)) {
            return Err(GkError::Forged);
        }
    }
    for b in &new.buckets {
        let kept = own.buckets.iter().find(|o| (o.b, o.v) == (b.b, b.v));
        if let Some(o) = kept {
            if o.leaf() != b.leaf() || o.made != b.made || !same_secret(&o.bk, &b.bk) {
                return Err(GkError::Forged);
            }
        }
    }
    Ok(())
}

/// Equality of two secrets in time that does not depend on where they differ.
fn same_secret(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
