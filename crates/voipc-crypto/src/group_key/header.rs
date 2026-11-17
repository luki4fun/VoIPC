//! Headers (§3.12, §4.2, §4.3, §11.3): the signed record of each commit.
//!
//! The body is postcard, and only its one canonical encoding is taken: lists
//! sorted by their encoded bytes with no duplicates, and a body that decodes
//! and encodes back to the very same bytes (no overlong varints, nothing
//! trailing). `D = SHA-256("voipc-gk/v1/digest|" ‖ body)` leaves the
//! signature out, and the signature's `S` must be below ℓ: libsignal also
//! takes `(R, S + ℓ)`, so a `D` over the signature would let anyone make a
//! second header with another digest.

use libsignal_protocol::IdentityKeyPair;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::ctx::{
    valid_group_id, GroupKind, MemberId, SeatRef, DIGEST_LABEL, HEADER_SIG_LABEL, KEYHOLDERS_LABEL,
    NAMES_LABEL,
};
use super::keys::{dh_public_raw, ik_raw, sign_with, verify, Origin};
use super::rules::Refusal;

/// A header body at most (§11.3).
pub const HEADER_MAX_BYTES: usize = 32 * 1024;
/// Keyholder entries in one set (§4.2).
pub const MAX_KEYHOLDERS: usize = 8;
/// `removed` entries in a gated header (§5.4).
pub const MAX_REMOVED: usize = 768;
/// `added` entries: a Join commit seats at most 256 joiners (§11.3).
pub const MAX_ADDED: usize = 256;

/// What a header does (§4.3). Postcard: Genesis 0 … KeyholdersRemove 5,
/// KeyholdersReplace 6.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Kind {
    Genesis,
    Regenesis,
    Fresh,
    Join,
    KeyholdersAdd,
    KeyholdersRemove,
    /// A desktop keyholder swapping its own pair at a seat-key rotation: a
    /// Fresh commit plus the swapped entry and a new `KRK`, never a seed
    /// change (§4.3, §5.11).
    KeyholdersReplace,
}

impl Kind {
    /// Every kind but Join begins an epoch: a new `CK` and `join = 0`.
    pub fn opens_epoch(self) -> bool {
        self != Kind::Join
    }

    /// The kinds whose header carries the keyholder set.
    pub fn sets_keyholders(self) -> bool {
        matches!(
            self,
            Kind::Genesis
                | Kind::Regenesis
                | Kind::KeyholdersAdd
                | Kind::KeyholdersRemove
                | Kind::KeyholdersReplace
        )
    }

    /// Genesis and Regenesis: signed by a volunteer, not by the set before.
    pub fn starts_anew(self) -> bool {
        matches!(self, Kind::Genesis | Kind::Regenesis)
    }
}

/// One keyholder entry (§11.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Keyholder {
    pub m: MemberId,
    /// The connection's user id: set for voice keyholders, else not.
    pub u: Option<u32>,
    /// 0x02 a connection's seat pair, 0x03 a desktop's keyholder pair.
    pub origin: u8,
    /// The endorsement's counter (§11.8).
    pub n: u32,
    pub ik: [u8; 32],
    pub kx: [u8; 32],
    pub tag_kk: [u8; 8],
}

/// One new seat in a gated header, with its endorsement's counter and time.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AddedSeat {
    pub m: MemberId,
    pub ik: [u8; 32],
    pub tag_sk: [u8; 8],
    pub tag_sx: [u8; 8],
    pub n: u32,
    pub made: u64,
}

impl AddedSeat {
    pub fn seat(&self) -> SeatRef {
        SeatRef {
            m: self.m,
            tag_sk: self.tag_sk,
            tag_sx: self.tag_sx,
        }
    }
}

/// New seats: a count in open groups, the names in gated ones.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Added {
    Count(u32),
    List(Vec<AddedSeat>),
}

/// Removed seats, likewise.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Removed {
    Count(u32),
    List(Vec<SeatRef>),
}

/// The header body (§11.3), field for field in its encoded order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderV1 {
    pub group_kind: GroupKind,
    pub group: String,
    pub gen: [u8; 16],
    pub epoch: u32,
    pub join: u32,
    pub kind: Kind,
    pub time: u64,
    pub parent: [u8; 32],
    pub epoch_parent: [u8; 32],
    pub kh_parent: [u8; 32],
    pub signer: MemberId,
    pub keyholders: Vec<Keyholder>,
    pub gated: bool,
    pub seed: u32,
    pub seed_floor: u32,
    pub exits_upto: u64,
    pub seats: u32,
    pub buckets: u32,
    pub conn_seats: u32,
    pub bucket_root: [u8; 32],
    pub keyring_hash: [u8; 32],
    pub names_hash: [u8; 32],
    pub added: Added,
    pub removed: Removed,
    pub confirm: [u8; 32],
}

/// `enum Header { V1(HeaderV1) }`: postcard writes the variant index first.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Header {
    V1(HeaderV1),
}

#[derive(Serialize)]
enum HeaderRef<'a> {
    V1(&'a HeaderV1),
}

fn encoded<T: Serialize>(x: &T) -> Vec<u8> {
    postcard::to_allocvec(x).expect("encodes")
}

/// Sorted by encoded bytes, ascending, each once.
fn sort_canonical<T: Serialize>(xs: &mut Vec<T>) {
    let mut keyed: Vec<(Vec<u8>, T)> = xs.drain(..).map(|x| (encoded(&x), x)).collect();
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    keyed.dedup_by(|a, b| a.0 == b.0);
    xs.extend(keyed.into_iter().map(|(_, x)| x));
}

fn is_canonical<T: Serialize>(xs: &[T]) -> bool {
    xs.windows(2).all(|w| encoded(&w[0]) < encoded(&w[1]))
}

impl HeaderV1 {
    /// The body: postcard of `Header::V1(self)`.
    pub fn encode(&self) -> Vec<u8> {
        encoded(&HeaderRef::V1(self))
    }

    /// Sorts every list the way the encoding requires, dropping duplicates.
    pub fn canonicalize(&mut self) {
        sort_canonical(&mut self.keyholders);
        if let Added::List(l) = &mut self.added {
            sort_canonical(l);
        }
        if let Removed::List(l) = &mut self.removed {
            sort_canonical(l);
        }
    }

    /// `D` of the header whose keyholder set this one is checked against and
    /// names: its own when it sets keyholders, else `kh_parent`.
    pub fn kh(&self, own_d: &[u8; 32]) -> [u8; 32] {
        if self.kind.sets_keyholders() {
            *own_d
        } else {
            self.kh_parent
        }
    }

    /// `D_e` of its epoch: its own on an opening header, else `epoch_parent`.
    pub fn d_e(&self, own_d: &[u8; 32]) -> [u8; 32] {
        if self.kind.opens_epoch() {
            *own_d
        } else {
            self.epoch_parent
        }
    }

    pub fn added_list(&self) -> &[AddedSeat] {
        match &self.added {
            Added::List(l) => l,
            Added::Count(_) => &[],
        }
    }

    /// The form a header has on its own, without its parent (§4.4 rule 1,
    /// and what §4.2, §4.3 and §11.3 say each field holds):
    ///
    /// - the group id has a valid shape; lists are sorted and each once;
    /// - an opening header has `join = 0` and no `epoch_parent`; a Join
    ///   header has `join ≥ 1`, a parent and an `epoch_parent`;
    /// - a Genesis is `epoch = 1`, `seed = seed_floor = 1`, with no parent and
    ///   no `kh_parent`; every other kind has both;
    /// - the kinds that set keyholders carry 1 to 8 entries, the others none;
    ///   an entry's origin is 0x02 or 0x03, a desktop pair (0x03) is an
    ///   account's and only in text groups (every voice keyholder is a
    ///   connection keyholder, §2, §5.9), its `u` is set exactly in voice
    ///   groups, and neither its `IK` nor its `KX` is a key of low order;
    /// - no `added` entry carries an `IK` of low order;
    /// - `1 ≤ seed_floor ≤ seed`;
    /// - open groups carry counts and a zero `names_hash`; gated groups carry
    ///   lists (at most 256 added, 768 removed) and `conn_seats = 0`.
    pub fn check_shape(&self) -> Result<(), Refusal> {
        let bad = |why| Err(Refusal::Form(why));
        if !valid_group_id(&self.group) {
            return bad("the group id has no valid shape");
        }
        if !is_canonical(&self.keyholders) {
            return bad("the keyholders are not sorted, or one is there twice");
        }
        let opening = self.kind.opens_epoch();
        if opening && (self.join != 0 || self.epoch_parent != [0; 32]) {
            return bad("an opening header has join 0 and no epoch parent");
        }
        if !opening && (self.join == 0 || self.epoch_parent == [0; 32]) {
            return bad("a Join header has join 1 or more and an epoch parent");
        }
        if self.kind == Kind::Genesis {
            if self.epoch != 1 || self.seed != 1 || self.seed_floor != 1 {
                return bad("a Genesis is epoch 1 under seed 1");
            }
            if self.parent != [0; 32] || self.kh_parent != [0; 32] {
                return bad("a Genesis has no parent");
            }
        } else if self.parent == [0; 32] || self.kh_parent == [0; 32] {
            return bad("only a Genesis has no parent");
        }
        // A voice room with no keyholder left makes a new Genesis at once
        // (§5.6, §5.9); a Regenesis waits out an hour on a relay with
        // accounts, and would set voice keyholders past §5.9's roster check.
        if self.kind == Kind::Regenesis && self.group_kind == GroupKind::Voice {
            return bad("a voice room makes a new Genesis, never a Regenesis");
        }
        if self.epoch == 0 {
            return bad("epochs count from 1");
        }
        if self.kind.sets_keyholders() {
            if self.keyholders.is_empty() || self.keyholders.len() > MAX_KEYHOLDERS {
                return bad("a header that sets keyholders names 1 to 8");
            }
        } else if !self.keyholders.is_empty() {
            return bad("only a header that sets keyholders names them");
        }
        let voice = self.group_kind == GroupKind::Voice;
        for k in &self.keyholders {
            match (Origin::from_byte(k.origin), &k.m) {
                (Some(Origin::Connection), _) => {}
                (Some(Origin::Desktop), MemberId::Account(_)) if !voice => {}
                _ => return bad("a keyholder entry has no origin its member can have"),
            }
            if k.u.is_some() != voice {
                return bad("a keyholder's user id is set in voice groups only");
            }
            if ik_raw(&k.ik).is_err() {
                return bad("a keyholder's IK is of low order");
            }
            if dh_public_raw(&k.kx).is_err() {
                return bad("a keyholder's KX is of low order");
            }
        }
        if self.seed_floor == 0 || self.seed_floor > self.seed {
            return bad("seed_floor is between 1 and seed");
        }
        match (&self.added, &self.removed, self.gated) {
            (Added::Count(_), Removed::Count(_), false) => {
                if self.names_hash != [0; 32] {
                    return bad("an open group carries no names");
                }
            }
            (Added::List(a), Removed::List(r), true) => {
                if a.len() > MAX_ADDED || r.len() > MAX_REMOVED {
                    return bad("too many names");
                }
                if a.iter().any(|a| ik_raw(&a.ik).is_err()) {
                    return bad("an added IK is of low order");
                }
                if !is_canonical(a) || !is_canonical(r) {
                    return bad("the names are not sorted, or one is there twice");
                }
                if self.conn_seats != 0 {
                    return Err(Refusal::GuestSeat(None));
                }
            }
            _ => return bad("lists in gated groups, counts in open ones"),
        }
        if self.conn_seats > self.seats {
            return bad("more connection seats than seats");
        }
        Ok(())
    }
}

/// `D = SHA-256("voipc-gk/v1/digest|" ‖ body)` (§3.12).
pub fn digest(body: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(DIGEST_LABEL)
        .chain_update(body)
        .finalize()
        .into()
}

fn sig_message(d: &[u8; 32]) -> Vec<u8> {
    [HEADER_SIG_LABEL, &d[..]].concat()
}

/// A header with its body, digest and signature, past rule 1.
///
/// The fields are read-only: `sign` and `decode` are the only ways to make
/// one, so `header` is always the decoding of `body`, `d` its digest, and a
/// header whose fields were changed after its signer signed it cannot pass
/// for one that verifies. Headers kept in local storage come back through
/// `decode`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedHeader {
    header: HeaderV1,
    body: Vec<u8>,
    d: [u8; 32],
    sig: [u8; 64],
}

impl SignedHeader {
    /// Signs a header after sorting its lists. Refused when its form is not
    /// one a member would take.
    pub fn sign(header: HeaderV1, ik: &IdentityKeyPair) -> Result<SignedHeader, Refusal> {
        SignedHeader::sign_with(header, ik, &mut crate::rng())
    }

    /// `sign` with a given RNG for XEdDSA's nonce: the known answers fix it.
    pub(crate) fn sign_with<R: rand::Rng + rand::CryptoRng>(
        mut header: HeaderV1,
        ik: &IdentityKeyPair,
        rng: &mut R,
    ) -> Result<SignedHeader, Refusal> {
        header.canonicalize();
        header.check_shape()?;
        let body = header.encode();
        if body.len() > HEADER_MAX_BYTES {
            return Err(Refusal::Form("the header is over 32 KiB"));
        }
        let d = digest(&body);
        let sig = sign_with(ik.private_key(), &sig_message(&d), rng);
        Ok(SignedHeader {
            header,
            body,
            d,
            sig,
        })
    }

    /// §4.4 rule 1: the body re-encodes to the same bytes, its lists are
    /// sorted and each once, it is within its size cap, its group kind and
    /// group are the ones expected, and the signature's `S` is below ℓ.
    /// Whose signature it is comes in rule 2 (`verify`).
    pub fn decode(
        body: &[u8],
        sig: &[u8],
        kind: GroupKind,
        group: &str,
    ) -> Result<SignedHeader, Refusal> {
        if body.len() > HEADER_MAX_BYTES {
            return Err(Refusal::Form("the header is over 32 KiB"));
        }
        let sig: [u8; 64] = sig
            .try_into()
            .map_err(|_| Refusal::Form("a signature is 64 bytes"))?;
        if !super::keys::s_canonical(&sig) {
            return Err(Refusal::Signature);
        }
        let Ok(Header::V1(header)) = postcard::from_bytes::<Header>(body) else {
            return Err(Refusal::Form("the body does not decode"));
        };
        if header.encode() != body {
            return Err(Refusal::Form("the body is not in its one encoding"));
        }
        if header.group_kind != kind || header.group != group {
            return Err(Refusal::WrongGroup);
        }
        header.check_shape()?;
        Ok(SignedHeader {
            header,
            d: digest(body),
            body: body.to_vec(),
            sig,
        })
    }

    /// Whether `ik` (32 raw bytes, as headers carry it) signed this. An `ik`
    /// of low order signs nothing.
    pub fn verify(&self, ik: &[u8; 32]) -> bool {
        let Ok(key) = ik_raw(ik) else {
            return false;
        };
        verify(&key, &sig_message(&self.d), &self.sig)
    }

    /// The decoded body.
    pub fn header(&self) -> &HeaderV1 {
        &self.header
    }

    /// The body as signed: what evidence of a fork compares (§3.12).
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// `D`, the digest of the body.
    pub fn d(&self) -> [u8; 32] {
        self.d
    }

    pub fn sig(&self) -> [u8; 64] {
        self.sig
    }

    /// The same header under another signature, past `decode`'s check of
    /// `S`: only for the tests of `verify`.
    #[cfg(test)]
    pub(crate) fn with_sig(&self, sig: [u8; 64]) -> SignedHeader {
        SignedHeader {
            sig,
            ..self.clone()
        }
    }

    pub fn kh(&self) -> [u8; 32] {
        self.header.kh(&self.d)
    }

    pub fn d_e(&self) -> [u8; 32] {
        self.header.d_e(&self.d)
    }
}

/// `KS = SHA-256("voipc-gk/v1/keyholders|" ‖ postcard(keyholders))` over the
/// sorted list of §11.3 (§11.6).
pub fn keyholder_set_digest(keyholders: &[Keyholder]) -> [u8; 32] {
    let mut sorted = keyholders.to_vec();
    sort_canonical(&mut sorted);
    Sha256::new()
        .chain_update(KEYHOLDERS_LABEL)
        .chain_update(encoded(&sorted))
        .finalize()
        .into()
}

/// `SHA-256(postcard(added))`, with `added` the header field exactly as the
/// body encodes it (§11.3): the `Added::List` variant index (1), the varint
/// length, then the entries sorted. A list given unsorted is sorted first, so
/// it hashes as the header carries it.
pub fn names_list_digest(added: &[AddedSeat]) -> [u8; 32] {
    let mut list = added.to_vec();
    sort_canonical(&mut list);
    Sha256::digest(encoded(&Added::List(list))).into()
}

/// One step of `names_hash` (§11.3), with its list already digested:
///
/// ```text
/// names_hash = SHA-256("voipc-gk/v1/names|" ‖ P ‖ time (u64 BE) ‖ epoch (u32 BE)
///                      ‖ join (u32 BE) ‖ SHA-256(postcard(added)))
/// ```
///
/// `time`, `epoch` and `join` are the header's own, so a list cannot be
/// moved to another header, and a tail of lists proves the time it covers.
/// A "gone" answer carries the step before the relay's 90-day tail in this
/// form, since the relay no longer holds that list (§4.4 rule 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamesStep {
    /// `P`: the `names_hash` before this step, 0³² at a start.
    pub before: [u8; 32],
    pub time: u64,
    pub epoch: u32,
    pub join: u32,
    /// `SHA-256(postcard(added))` of the step's list.
    pub list: [u8; 32],
}

impl NamesStep {
    /// The `names_hash` after this step: 98 bytes hashed.
    pub fn hash(&self) -> [u8; 32] {
        Sha256::new()
            .chain_update(NAMES_LABEL)
            .chain_update(self.before)
            .chain_update(self.time.to_be_bytes())
            .chain_update(self.epoch.to_be_bytes())
            .chain_update(self.join.to_be_bytes())
            .chain_update(self.list)
            .finalize()
            .into()
    }
}

/// One header's `added` list with what each step binds it to: the header's
/// `time`, `epoch` and `join` (§4.4 rule 4, §11.3). What a writer folds, from
/// the Join headers themselves or from the bare lists the relay sends.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamesList {
    pub time: u64,
    pub epoch: u32,
    pub join: u32,
    pub added: Vec<AddedSeat>,
}

impl NamesList {
    /// The list a header carries, at that header's place.
    pub fn of(h: &HeaderV1) -> NamesList {
        NamesList {
            time: h.time,
            epoch: h.epoch,
            join: h.join,
            added: h.added_list().to_vec(),
        }
    }

    /// The step this list makes from `before`, taken even when it is empty.
    pub fn step_from(&self, before: &[u8; 32]) -> NamesStep {
        step_of(before, self.time, self.epoch, self.join, &self.added)
    }
}

fn step_of(p: &[u8; 32], time: u64, epoch: u32, join: u32, added: &[AddedSeat]) -> NamesStep {
    NamesStep {
        before: *p,
        time,
        epoch,
        join,
        list: names_list_digest(added),
    }
}

/// `names_hash` at a Genesis, and at the opening header that turns `gated`
/// on: one step from 32 zero bytes, taken even when the list is empty
/// (§11.3).
pub fn names_start(list: &NamesList) -> [u8; 32] {
    list.step_from(&[0; 32]).hash()
}

/// `names_hash` at any other header: the parent's, stepped with a non-empty
/// list, or the parent's unchanged for an empty one. It runs on through a
/// Regenesis.
pub fn names_step(parent: &[u8; 32], list: &NamesList) -> [u8; 32] {
    if list.added.is_empty() {
        return *parent;
    }
    list.step_from(parent).hash()
}

/// The `names_hash` header `h` must carry after `parent` (None for a
/// Genesis): zero in open groups.
pub fn names_hash(parent: Option<&HeaderV1>, h: &HeaderV1) -> [u8; 32] {
    if !h.gated {
        return [0; 32];
    }
    let (time, epoch, join, added) = (h.time, h.epoch, h.join, h.added_list());
    match parent {
        Some(p) if p.gated && h.kind != Kind::Genesis => {
            if added.is_empty() {
                p.names_hash
            } else {
                step_of(&p.names_hash, time, epoch, join, added).hash()
            }
        }
        _ => step_of(&[0; 32], time, epoch, join, added).hash(),
    }
}
