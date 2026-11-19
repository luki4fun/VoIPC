//! The group epoch key's wire (protocol 26, docs/GROUP-KEY.md): the types the `Epoch*`,
//! `Keyring*` and `Keyhold*` messages carry, their codes, their byte caps, and what every
//! receiver runs before a value reaches `voipc_crypto::group_key`: the length checks, the
//! in-order part reassembler, the keyring stream, the `Keep` mask and the packed rows.
//!
//! The messages that carry them are in messages.rs; `types::GroupLoad` is the Load view's.
//!
//! Byte fields are `Vec<u8>` (serde has no `[u8; 64]`), `[u8; N]` for N ≤ 32. Postcard
//! gives each `Vec` the length its sender chose, so a receiver calls `check` before it
//! takes a value and refuses a wrong length. Codes are bare `u8` with frozen values; a
//! later build may add codes, so an unknown one is "other", never a decode error.

use std::fmt;
use std::mem;

use serde::{Deserialize, Serialize};

use crate::types::UserId;

// ── Sizes (§3, §11) ───────────────────────────────────────────────────────

/// `ser(Kyber1024 public)`: the type byte and 1568.
pub const KEM_PUBLIC_BYTES: usize = 1569;
/// `ser(ct_q)`, the Kyber1024 ciphertext a welcome starts with.
pub const KEM_CT_BYTES: usize = 1569;
/// `ser(X25519 public)`: `0x05` and 32.
pub const DH_PUBLIC_BYTES: usize = 33;
/// An XEdDSA signature.
pub const SIG_BYTES: usize = 64;
/// AES-256-GCM's nonce and tag around every sealed value.
pub const AEAD_OVERHEAD: usize = 12 + 16;
/// A seat welcome (§3.2), carrying `s_m ‖ BK(b,v)`.
pub const SEAT_WELCOME_BYTES: usize = KEM_CT_BYTES + DH_PUBLIC_BYTES + AEAD_OVERHEAD + 64;
/// A seed welcome (§3.2), carrying `s_m`.
pub const SEED_WELCOME_BYTES: usize = KEM_CT_BYTES + DH_PUBLIC_BYTES + AEAD_OVERHEAD + 32;
/// A keyring welcome (§3.2), carrying `KRK`.
pub const KRK_WELCOME_BYTES: usize = SEED_WELCOME_BYTES;
/// A row (§3.3): one sealed `BK`.
pub const ROW_BYTES: usize = AEAD_OVERHEAD + 32;
/// A seal (§3.4): one sealed `CK_e`.
pub const SEAL_BYTES: usize = ROW_BYTES;
/// A self-row (§3.11): one sealed `s_m`.
pub const SELF_ROW_BYTES: usize = ROW_BYTES;
/// A chain seal (§3.9): one sealed chain state.
pub const CHAIN_SEAL_BYTES: usize = ROW_BYTES;
/// A history row at most (§3.11): the row bases of the keyholders that made rows to a seat.
pub const HISTORY_ROW_MAX_BYTES: usize = 16 * 1024;
/// A header body at most (§11.3).
pub const HEADER_MAX_BYTES: usize = 32 * 1024;
/// A writer blob at most (`EpochPost.blob`).
pub const BLOB_MAX_BYTES: usize = 1024;
/// The longest group id (§11.1).
pub const MAX_GROUP_BYTES: usize = 128;
/// The longest `detail` of a decline, wait, stale answer or refusal.
pub const DETAIL_MAX_BYTES: usize = 200;

const _: () = assert!(SEAT_WELCOME_BYTES == 1694);
const _: () = assert!(SEED_WELCOME_BYTES == 1662);
const _: () = assert!(ROW_BYTES == 60);

// ── Caps (plan 1e) ────────────────────────────────────────────────────────

/// Senders cut each part of a multi-part message at this many encoded bytes (the whole
/// message, variant index and all); receivers refuse a part over it.
pub const PIECE_MAX_BYTES: usize = 56 * 1024;
const _: () = assert!(PIECE_MAX_BYTES < crate::codec::MAX_MSG_SIZE as usize);
/// Joiners a Join commit seats at most (§11.3), and so welcomes and refusals in one commit.
pub const MAX_JOINERS: usize = 256;
/// Seats in one bucket version at most (§5.3).
pub const BUCKET_SEATS: usize = 62;
/// Keyholder entries in one set (§4.2), and so `KRK` welcomes in one commit.
pub const MAX_KEYHOLDERS: usize = 8;
/// `removed` entries in a gated header (§5.4).
pub const MAX_REMOVED: usize = 768;
/// `added` entries in a gated header, and so in one `NamesListIn` (§11.3).
pub const MAX_ADDED: usize = 256;
/// One `AddedSeat` encoded at most: member id 17, `ik` 32, two tags 16, `n` 5, `made` 10.
pub const ADDED_SEAT_MAX_BYTES: usize = 17 + 32 + 8 + 8 + 5 + 10;
/// `NamesListIn.added` at most: the count (2 bytes up to 256) and the entries.
pub const NAMES_ADDED_MAX_BYTES: usize = 2 + MAX_ADDED * ADDED_SEAT_MAX_BYTES;
/// Siblings in an inclusion path at most: a tree of 2^32 leaves (`buckets` is a u32).
pub const PATH_MAX_SIBLINGS: usize = 32;
/// One commit, all its parts' encoded bytes together, at most (a full re-key at 100k
/// seats is about 6.4 MB).
pub const COMMIT_MAX_BYTES: usize = 12_000_000;
/// Open commits of one connection, all groups together, at most.
pub const CONN_OPEN_MAX_BYTES: usize = 12_000_000;
/// Open commits of all connections of one relay at most.
pub const RELAY_OPEN_MAX_BYTES: usize = 64_000_000;
/// The keyring stream of one `KeyringIn` sequence at most (a base at 100k is 147 KB).
pub const KEYRING_MAX_BYTES: usize = 4 * 1024 * 1024;
/// One `KeyringIn.stream` slice at most.
pub const KEYRING_SLICE_MAX_BYTES: usize = 48 * 1024;

/// The sequences of each multi-part kind at most, all parts together, each part charged
/// as `Parts` charges it (the larger of its encoded and its decoded bytes). The plan fixes
/// only the commit's; these hold the plan's worst cases with room.
/// `EpochIn`: a walk of `MAX_WALK` (4096) kh links of the usual 1.2 KB is 5 MB.
pub const IN_MAX_BYTES: usize = 12_000_000;
/// `EpochDue`: an opening due carries its whole closed exit batch, and only a gated batch
/// closes at a count (2d), so every seat of a non-gated 100k group leaving in one batch
/// (an admin revoking access) is one due: 4.6 MB encoded, 5.6 MB decoded. 256 joiners
/// and a page of 256 seed seats are 0.9 MB with their pairs.
pub const DUE_MAX_BYTES: usize = 12_000_000;
/// `KeyringIn`: the whole stream, a `KRK` welcome and each part's own fields.
pub const KEYRING_IN_MAX_BYTES: usize = KEYRING_MAX_BYTES + 64 * 1024;
/// `EpochNamesIn`: the names fold after a 100k re-seat is 7.1 MB.
pub const NAMES_IN_MAX_BYTES: usize = 12_000_000;
/// `VoiceSeats`: a room of 100k seats is 3.4 MB at 34 B a seat.
pub const VOICE_SEATS_MAX_BYTES: usize = 4 * 1024 * 1024;

// Per-frame counts of plan 1b–1d.

/// `EpochFetch.at` entries a frame.
pub const FETCH_AT_MAX: usize = 16;
/// `EpochWelcomes.welcomes` a frame.
pub const WELCOMES_PER_FRAME: usize = 33;
/// `EpochListsWanted.versions` a frame.
pub const LISTS_WANTED_MAX: usize = 64;
/// `EpochLists.lists` a frame.
pub const LISTS_PER_FRAME: usize = 13;
/// Writer blobs per writer per epoch, and so in one `EpochBlob`.
pub const BLOBS_MAX: usize = 2;
/// `VoiceSeats.seats` a frame.
pub const VOICE_SEATS_PER_FRAME: usize = 1000;
/// `SelfRowPut.rows`, and `SelfRowsList.limit` at most.
pub const SELF_ROWS_MAX: usize = 256;
/// `EpochChainKeys.chains` a request.
pub const CHAIN_KEYS_MAX: usize = 64;

// ── Codes (plan 1a; values frozen) ────────────────────────────────────────

macro_rules! codes {
    ($(#[$doc:meta])* $module:ident { $($name:ident = $value:expr),* $(,)? }) => {
        $(#[$doc])*
        pub mod $module {
            $(pub const $name: u8 = $value;)*

            /// The code's name for logs; `"unknown"` for one a later build added.
            pub fn name(code: u8) -> &'static str {
                match code {
                    $($name => stringify!($name),)*
                    _ => "unknown",
                }
            }
        }
    };
}

codes! {
    /// `EpochDue.kind`: what the relay asks a keyholder for.
    due {
        JOIN = 0,
        EXITS = 1,
        REFRESH = 2,
        PROMOTE = 3,
        REMOVE = 4,
        REPLACE = 5,
        GENESIS = 6,
        REGENESIS = 7,
        SEED_WELCOMES = 8,
        GATE = 9,
    }
}

codes! {
    /// `EpochStale.reason`. `STORE`: the relay failed to store a valid commit, never a miss.
    stale {
        NOT_HEAD = 0,
        NOT_KEYHOLDER = 1,
        NOT_DUE = 2,
        CHECK = 3,
        TIMED_OUT = 4,
        HEAD_MOVED = 5,
        TOO_LARGE = 6,
        STORE = 7,
    }
}

codes! {
    /// `EpochWait.why`.
    wait {
        QUEUED = 0,
        NO_KEYHOLDER = 1,
        REFUSED = 2,
        NO_SEAT_KEYS = 3,
        GUEST_IN_GATED = 4,
        NEW_GENERATION = 5,
    }
}

codes! {
    /// `EpochDecline.why`: a keyholder refusing a whole due (§5.4, §5.6).
    decline {
        PLATFORM = 0,
        GUEST_LIMIT = 1,
        CLOCK = 2,
        CONN_BUCKET = 3,
        CANDIDATE = 4,
        NOT_READY = 5,
    }
}

codes! {
    /// `EpochRefused.what`: the request refused.
    refused_what {
        FETCH = 0,
        POST = 1,
        BLOB = 2,
        NAMES = 3,
        COMMIT = 4,
        VOLUNTEER = 5,
        LEGACY = 6,
        ROWS = 7,
    }
}

codes! {
    /// `EpochRefused.why`.
    refused_why {
        OFF = 0,
        NOT_MEMBER = 1,
        OLD_EPOCH = 2,
        THIRD_BLOB = 3,
        RATE = 4,
        NOT_GATED = 5,
        LEGACY_PATH = 6,
        TOO_LARGE = 7,
        NOT_STORED = 8,
    }
}

codes! {
    /// `KeyholdVolunteer.platform`. `BROWSER_BUSY`: a browser whose page is hidden or in a
    /// call (choice 31). It holds text keys only as the fallback, ranked below every other
    /// text volunteer of its kind, and offers again with `BROWSER` or `BROWSER_BUSY` at each
    /// change; the relay takes that as its new rank. An app without it sends `{on: false}`.
    platform {
        DESKTOP = 1,
        PHONE = 2,
        BROWSER = 3,
        BROWSER_BUSY = 4,
    }
}

codes! {
    /// `JoinRefused.why`: why a keyholder seated a due joiner not.
    join_refused {
        ENDORSEMENT = 0,
        PIN = 1,
        OLD_COUNTER = 2,
        GUEST_IN_GATED = 3,
        ALREADY_SEATED = 4,
    }
}

codes! {
    /// `EndorsedPair.origin` (§11.8). Unlike the others, a receiver refuses any other value.
    origin {
        VAULT_SEAT = 0x01,
        CONNECTION = 0x02,
        DESKTOP = 0x03,
    }
}

codes! {
    /// `LeafIn.pool` and `VersionOut.pool`: C1's `Pool` (Accounts 0, Conns 1). A receiver
    /// refuses any other value.
    pool {
        ACCOUNTS = 0,
        CONNS = 1,
    }
}

codes! {
    /// `SelfRowIn.kind`. A receiver refuses any other value.
    self_row {
        SELF_ROW = 0,
        HISTORY_ROW = 1,
    }
}

codes! {
    /// `types::GroupLoad.kind`: C1's `GroupKind` (Text 0, Voice 1).
    group_kind {
        TEXT = 0,
        VOICE = 1,
    }
}

// ── Errors ────────────────────────────────────────────────────────────────

/// Why a received value is refused. Each names the field or the cap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bad {
    /// A byte field of the wrong length.
    Length(&'static str),
    /// Too many entries, or not the number required.
    Count(&'static str),
    /// A value out of its range, or not where it may be.
    Value(&'static str),
    /// Over a byte cap.
    TooLarge(&'static str),
    /// Ends inside an entry.
    Truncated(&'static str),
}

impl fmt::Display for Bad {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Bad::Length(w) => write!(f, "{w}: wrong length"),
            Bad::Count(w) => write!(f, "{w}: wrong count"),
            Bad::Value(w) => write!(f, "{w}: value out of range"),
            Bad::TooLarge(w) => write!(f, "{w}: too large"),
            Bad::Truncated(w) => write!(f, "{w}: truncated"),
        }
    }
}

impl std::error::Error for Bad {}

fn exact(what: &'static str, got: usize, want: usize) -> Result<(), Bad> {
    if got == want {
        Ok(())
    } else {
        Err(Bad::Length(what))
    }
}

fn at_most(what: &'static str, got: usize, cap: usize) -> Result<(), Bad> {
    if got <= cap {
        Ok(())
    } else {
        Err(Bad::Count(what))
    }
}

/// A group id's length: 1 to `MAX_GROUP_BYTES` bytes. Its shape (§11.1) is C1's to check.
pub fn check_group(group: &str) -> Result<(), Bad> {
    if group.is_empty() || group.len() > MAX_GROUP_BYTES {
        return Err(Bad::Length("group"));
    }
    Ok(())
}

/// A `detail` string: at most `DETAIL_MAX_BYTES`.
pub fn check_detail(detail: &str) -> Result<(), Bad> {
    if detail.len() > DETAIL_MAX_BYTES {
        return Err(Bad::TooLarge("detail"));
    }
    Ok(())
}

// ── Types (plan 1a) ───────────────────────────────────────────────────────

/// A member id (§2 `m`): an account, or a connection's own seat by its user id. The same
/// postcard as C1's `MemberId`: Account 0 (16 raw bytes), Conn 1 (varint).
///
/// The derived order is the seat records' order (§11.5): accounts first, by id bytes,
/// then connections by user id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum GkMember {
    Account([u8; 16]),
    Conn(u32),
}

impl GkMember {
    /// The seat id of §11.5: `0x01 ‖ account id`, or `0x02 ‖ 12 zero bytes ‖ u (BE)`.
    pub fn seat_id(&self) -> [u8; 17] {
        let mut out = [0u8; 17];
        match self {
            GkMember::Account(a) => {
                out[0] = 0x01;
                out[1..].copy_from_slice(a);
            }
            GkMember::Conn(u) => {
                out[0] = 0x02;
                out[13..].copy_from_slice(&u.to_be_bytes());
            }
        }
        out
    }

    pub fn account(&self) -> Option<[u8; 16]> {
        match self {
            GkMember::Account(a) => Some(*a),
            GkMember::Conn(_) => None,
        }
    }

    /// The pool its buckets are in (§5.2).
    pub fn pool(&self) -> u8 {
        match self {
            GkMember::Account(_) => pool::ACCOUNTS,
            GkMember::Conn(_) => pool::CONNS,
        }
    }
}

/// A seat: a member id with the tags of its two seat keys. C1's `SeatRef`, same postcard.
/// The derived order is list order (§11.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct GkSeat {
    pub m: GkMember,
    /// `tag(SK_m)`.
    pub sk: [u8; 8],
    /// `tag(SX_m)`.
    pub sx: [u8; 8],
}

impl GkSeat {
    /// The 33-byte seat record of §11.5: seat id, `tag_sk`, `tag_sx`.
    pub fn record(&self) -> [u8; 33] {
        let mut r = [0u8; 33];
        r[..17].copy_from_slice(&self.m.seat_id());
        r[17..25].copy_from_slice(&self.sk);
        r[25..].copy_from_slice(&self.sx);
        r
    }
}

/// Whether `seats` are in list order (§11.5: ascending seat records), each once.
pub fn in_list_order(seats: &[GkSeat]) -> bool {
    seats.windows(2).all(|w| w[0] < w[1])
}

/// A seat with its X25519 public key, as a keyholder needs it to make a row (`EpochLists`).
/// The keyholder checks `tag(dh) == seat.sx`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListSeat {
    pub seat: GkSeat,
    /// `ser(SX_m.pub)`, 33 bytes.
    pub dh: Vec<u8>,
}

impl ListSeat {
    pub fn check(&self) -> Result<(), Bad> {
        exact("list seat dh", self.dh.len(), DH_PUBLIC_BYTES)
    }
}

/// A writer (§2 `w`): its seat's member id and its connection's user id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GkWriter {
    pub m: GkMember,
    pub u: u32,
}

/// A keyholder entry by its member id and raw `KX` (32 bytes, §11.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HolderRef {
    pub m: GkMember,
    pub kx: [u8; 32],
}

/// A KEM and DH pair with `IK`'s endorsement (§11.8). `u` is the connection's user id for
/// origin 0x02 (the seat id it signs), else 0. The relay refuses a 0x02 pair whose `u` is
/// not the session's own user id.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndorsedPair {
    pub origin: u8,
    pub u: u32,
    /// `ser(KEM.pub)`, 1569 bytes.
    pub kem: Vec<u8>,
    /// `ser(DH.pub)`, 33 bytes.
    pub dh: Vec<u8>,
    /// The account's seat-key counter; 0 for a guest.
    pub n: u32,
    /// Unix seconds.
    pub made: u64,
    /// 64 bytes.
    pub sig: Vec<u8>,
}

impl EndorsedPair {
    /// Lengths and origin, and `u` set only for a connection pair.
    pub fn check(&self) -> Result<(), Bad> {
        if !(origin::VAULT_SEAT..=origin::DESKTOP).contains(&self.origin) {
            return Err(Bad::Value("pair origin"));
        }
        if self.origin != origin::CONNECTION && self.u != 0 {
            return Err(Bad::Value("pair u"));
        }
        exact("pair kem", self.kem.len(), KEM_PUBLIC_BYTES)?;
        exact("pair dh", self.dh.len(), DH_PUBLIC_BYTES)?;
        exact("pair sig", self.sig.len(), SIG_BYTES)
    }

    /// `check`, and whether this origin may stand for a seat or entry of `m` (§11.8): the
    /// vault and a desktop pair name an account; a connection pair names its connection,
    /// which is `m` itself for a connection seat, and any connection of the account for an
    /// account's voice seat or browser keyholder.
    pub fn check_for(&self, m: &GkMember) -> Result<(), Bad> {
        self.check()?;
        let fits = match m {
            GkMember::Account(_) => true,
            GkMember::Conn(u) => self.origin == origin::CONNECTION && *u == self.u,
        };
        if fits {
            Ok(())
        } else {
            Err(Bad::Value("pair origin for this member"))
        }
    }
}

/// A signed header: the postcard body (§11.3) and its XEdDSA signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderIn {
    /// 1 to `HEADER_MAX_BYTES` bytes.
    pub body: Vec<u8>,
    /// 64 bytes.
    pub sig: Vec<u8>,
}

impl HeaderIn {
    pub fn check(&self) -> Result<(), Bad> {
        if self.body.is_empty() {
            return Err(Bad::Length("header body"));
        }
        if self.body.len() > HEADER_MAX_BYTES {
            return Err(Bad::TooLarge("header body"));
        }
        exact("header sig", self.sig.len(), SIG_BYTES)
    }
}

/// One kh link of a walk (§4.4 rule 3); `parent` only for a Regenesis.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalkLinkIn {
    pub header: HeaderIn,
    pub parent: Option<HeaderIn>,
}

impl WalkLinkIn {
    pub fn check(&self) -> Result<(), Bad> {
        self.header.check()?;
        self.parent.as_ref().map_or(Ok(()), HeaderIn::check)
    }
}

/// The floor a member holds: its generation, place, header digest and the digest of the
/// header whose keyholder set it checks against.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FloorRef {
    pub gen: [u8; 16],
    pub epoch: u32,
    pub join: u32,
    pub d: [u8; 32],
    pub kh: [u8; 32],
}

/// An epoch of a generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EpochRef {
    pub gen: [u8; 16],
    pub epoch: u32,
}

/// A header's place, for `EpochNames`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NamesRef {
    pub gen: [u8; 16],
    pub epoch: u32,
    pub join: u32,
}

/// One current bucket version as the root commits to it: C1's `Leaf`, same postcard.
/// `pool` is C1's `Pool` as its variant index, and `via` C1's `Via` (`None` is `Row`,
/// `Some(from)` is `Ratchet { from }`): postcard writes both the same way.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LeafIn {
    pub b: u64,
    pub v: u64,
    pub pool: u8,
    pub seats: u16,
    pub list: [u8; 32],
    pub via: Option<u64>,
}

impl LeafIn {
    pub fn check(&self) -> Result<(), Bad> {
        if self.pool > pool::CONNS {
            return Err(Bad::Value("leaf pool"));
        }
        at_most("leaf seats", usize::from(self.seats), BUCKET_SEATS)
    }
}

/// An inclusion path (§11.4): siblings from the bottom up. C1's `Path` holds `index` and
/// `n` as u64; a header's `buckets` is a u32, so these are too.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathIn {
    pub index: u32,
    pub n: u32,
    pub siblings: Vec<[u8; 32]>,
}

impl PathIn {
    pub fn check(&self) -> Result<(), Bad> {
        if self.index >= self.n {
            return Err(Bad::Value("path index"));
        }
        at_most("path siblings", self.siblings.len(), PATH_MAX_SIBLINGS)
    }
}

/// One promotion's ratchet of a version (§3.5): `from` to `to` in epoch `e`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RatchetStep {
    pub e: u32,
    pub from: u64,
    pub to: u64,
}

/// How a member reaches `BK` of its current version: a seat welcome (1694) or a row (60)
/// to `(b, base_v)` under seed `s` from keyholder `from`, then the ratchet steps since.
///
/// Neither a welcome nor a row, only steps, when the member already holds `BK` of
/// `(b, base_v)`: a memory group keeps a welcome only until its `EpochIn` has gone out
/// (plan 2b), so after a lost push the ratchets since are all the relay can send. The
/// member takes such keying only for the version it holds; `s` and `from` are then unused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeatKeying {
    pub b: u64,
    pub base_v: u64,
    pub s: u32,
    pub from: HolderRef,
    pub welcome: Option<Vec<u8>>,
    pub row: Option<Vec<u8>>,
    pub ratchets: Vec<RatchetStep>,
}

impl SeatKeying {
    /// At most one of `welcome` and `row`, each of its length, and ratchet steps that
    /// chain on from `base_v`: at least one step when there is neither.
    pub fn check(&self) -> Result<(), Bad> {
        match (&self.welcome, &self.row) {
            (Some(w), None) => exact("seat welcome", w.len(), SEAT_WELCOME_BYTES)?,
            (None, Some(r)) => exact("seat row", r.len(), ROW_BYTES)?,
            (None, None) if !self.ratchets.is_empty() => {}
            (None, None) => return Err(Bad::Value("seat keying: nothing to reach a key")),
            (Some(_), Some(_)) => return Err(Bad::Value("seat keying: a welcome and a row")),
        }
        let mut at = self.base_v;
        for step in &self.ratchets {
            if step.from != at {
                return Err(Bad::Value("ratchet steps"));
            }
            at = step.to;
        }
        Ok(())
    }

    /// The version the steps end at: the member's current one.
    pub fn current_v(&self) -> u64 {
        self.ratchets.last().map_or(self.base_v, |r| r.to)
    }
}

/// A seed welcome for the member (§3.2), under seed `s`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeedWelcomeIn {
    pub s: u32,
    pub from: HolderRef,
    pub bytes: Vec<u8>,
}

impl SeedWelcomeIn {
    pub fn check(&self) -> Result<(), Bad> {
        exact("seed welcome", self.bytes.len(), SEED_WELCOME_BYTES)
    }
}

/// A self-row (kind 0, 60 B) or history row (kind 1, at most 16 KiB) an account keeps
/// (§3.11); stored `c:` groups only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelfRowIn {
    pub group: String,
    pub gen: [u8; 16],
    pub seed: u32,
    pub sk: [u8; 8],
    pub sx: [u8; 8],
    pub kind: u8,
    pub sealed: Vec<u8>,
}

impl SelfRowIn {
    pub fn check(&self) -> Result<(), Bad> {
        check_group(&self.group)?;
        match self.kind {
            self_row::SELF_ROW => exact("self-row", self.sealed.len(), SELF_ROW_BYTES),
            self_row::HISTORY_ROW => {
                if self.sealed.len() <= AEAD_OVERHEAD {
                    Err(Bad::Length("history row"))
                } else if self.sealed.len() > HISTORY_ROW_MAX_BYTES {
                    Err(Bad::TooLarge("history row"))
                } else {
                    Ok(())
                }
            }
            _ => Err(Bad::Value("self-row kind")),
        }
    }
}

/// How a commit makes a version's seat list. Postcard: Ratchet 0, Keep 1, Seats 2.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VersionMake {
    /// The same seats as `(b, from_v)`, `BK` ratcheted from it (§3.5).
    Ratchet { from_v: u64 },
    /// The seats of `(b, from_v)` whose bit is set: bit i is its i-th seat in list order.
    Keep { from_v: u64, mask: u64 },
    /// These seats, in list order: only for a merge or a new Join bucket.
    Seats(Vec<GkSeat>),
}

/// A version a commit makes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionOut {
    pub b: u64,
    pub v: u64,
    pub pool: u8,
    pub make: VersionMake,
}

impl VersionOut {
    /// Pool, at most 62 seats, a `Keep` mask with a bit set and none past seat 62, and
    /// `Seats` in list order of the version's pool. The mask against the source's list is
    /// `kept`'s to check, where that list is known.
    pub fn check(&self) -> Result<(), Bad> {
        if self.pool > pool::CONNS {
            return Err(Bad::Value("version pool"));
        }
        match &self.make {
            VersionMake::Ratchet { .. } => Ok(()),
            VersionMake::Keep { mask, .. } => check_mask(*mask, BUCKET_SEATS),
            VersionMake::Seats(seats) => {
                if seats.is_empty() {
                    return Err(Bad::Count("version seats"));
                }
                at_most("version seats", seats.len(), BUCKET_SEATS)?;
                if !in_list_order(seats) {
                    return Err(Bad::Value("version seats order"));
                }
                if seats.iter().any(|s| s.m.pool() != self.pool) {
                    return Err(Bad::Value("version seats pool"));
                }
                Ok(())
            }
        }
    }
}

/// A seat welcome a Join commit makes: `seat` into `(b, v)` under seed `s`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WelcomeOut {
    pub seat: GkSeat,
    pub b: u64,
    pub v: u64,
    pub s: u32,
    pub bytes: Vec<u8>,
}

impl WelcomeOut {
    pub fn check(&self) -> Result<(), Bad> {
        exact("welcome", self.bytes.len(), SEAT_WELCOME_BYTES)
    }
}

/// Rows to every seat of `(b, v)`, packed: 60 B per seat in the version's list order.
/// Bit i of `up` set: row i is under seed `s + 1` (a seed roll runs), else under `s`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RowsOut {
    pub b: u64,
    pub v: u64,
    pub s: u32,
    pub up: u64,
    pub rows: Vec<u8>,
}

/// A seal of `CK_e` for `(b, v)`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealOut {
    pub b: u64,
    pub v: u64,
    pub bytes: Vec<u8>,
}

impl SealOut {
    pub fn check(&self) -> Result<(), Bad> {
        exact("seal", self.bytes.len(), SEAL_BYTES)
    }
}

/// A keyring welcome to keyholder `to`; `from_kx` is its maker's `KX` (the old pair on a
/// KeyholdersReplace).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KrkOut {
    pub to: HolderRef,
    pub from_kx: [u8; 32],
    pub bytes: Vec<u8>,
}

impl KrkOut {
    pub fn check(&self) -> Result<(), Bad> {
        exact("keyring welcome", self.bytes.len(), KRK_WELCOME_BYTES)
    }
}

/// A due joiner the keyholder did not seat; `why` is a `join_refused` code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct JoinRefused {
    pub seat: GkSeat,
    pub why: u8,
}

/// One part of an `EpochCommit`. The header is in part 0 only; `keyring` is a slice of
/// the keyring stream (`put_keyring_entry`: an opening commit's base or a Join's delta);
/// `seed_welcomes` are for the seats whose seed the new floor drops (validator rule 13).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitPiece {
    pub header: Option<HeaderIn>,
    pub versions: Vec<VersionOut>,
    pub drops: Vec<u64>,
    pub welcomes: Vec<WelcomeOut>,
    pub rows: Vec<RowsOut>,
    pub seals: Vec<SealOut>,
    pub seed_welcomes: Vec<SeedWelcomeOut>,
    pub keyring: Vec<u8>,
    pub krk: Vec<KrkOut>,
    pub refused: Vec<JoinRefused>,
}

/// A seed welcome a commit or a seed-roll page makes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeedWelcomeOut {
    pub seat: GkSeat,
    pub bytes: Vec<u8>,
}

impl SeedWelcomeOut {
    pub fn check(&self) -> Result<(), Bad> {
        exact("seed welcome", self.bytes.len(), SEED_WELCOME_BYTES)
    }
}

/// A joiner in an `EpochDue`. `returning`: the relay holds a self-row or row under the
/// current seed, so it gets a row, not a welcome. A voice seat's user id is `keys.u`
/// (signed), never a relay field.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Joiner {
    pub seat: GkSeat,
    pub ik: [u8; 32],
    pub keys: EndorsedPair,
    pub returning: bool,
}

impl Joiner {
    pub fn check(&self) -> Result<(), Bad> {
        self.keys.check_for(&self.seat.m)
    }
}

/// An exit in an `EpochDue`: its sequence number, seat and bucket.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExitIn {
    pub seq: u64,
    pub seat: GkSeat,
    pub b: u64,
}

/// A keyholder candidate to promote; the entry's `u` is `pair.u`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Candidate {
    pub m: GkMember,
    pub ik: [u8; 32],
    pub pair: EndorsedPair,
}

impl Candidate {
    pub fn check(&self) -> Result<(), Bad> {
        self.pair.check_for(&self.m)
    }
}

/// A seat owed a seed welcome, with its KEM key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeedSeat {
    pub seat: GkSeat,
    pub ik: [u8; 32],
    pub keys: EndorsedPair,
}

impl SeedSeat {
    pub fn check(&self) -> Result<(), Bad> {
        self.keys.check_for(&self.seat.m)
    }
}

/// A version's seat list with each seat's DH key (`EpochLists`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListIn {
    pub b: u64,
    pub v: u64,
    pub seats: Vec<ListSeat>,
}

impl ListIn {
    /// 1 to 62 seats, in list order, each with a 33-byte key.
    pub fn check(&self) -> Result<(), Bad> {
        if self.seats.is_empty() {
            return Err(Bad::Count("list seats"));
        }
        at_most("list seats", self.seats.len(), BUCKET_SEATS)?;
        if !self.seats.windows(2).all(|w| w[0].seat < w[1].seat) {
            return Err(Bad::Value("list order"));
        }
        self.seats.iter().try_for_each(ListSeat::check)
    }
}

/// A keyring welcome to this keyholder, with its maker.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KrkIn {
    pub from: HolderRef,
    pub bytes: Vec<u8>,
}

impl KrkIn {
    pub fn check(&self) -> Result<(), Bad> {
        exact("keyring welcome", self.bytes.len(), KRK_WELCOME_BYTES)
    }
}

/// One gated header's `added` list at its place (C1's `NamesList`). `added` is the
/// postcard of C1's `Vec<AddedSeat>`, at most 256 entries, decoded by voipc-crypto.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamesListIn {
    pub time: u64,
    pub epoch: u32,
    pub join: u32,
    pub added: Vec<u8>,
}

impl NamesListIn {
    pub fn check(&self) -> Result<(), Bad> {
        names_added_count(&self.added).map(|_| ())
    }
}

/// The entry count a postcard `Vec<AddedSeat>` starts with, refused past `MAX_ADDED`, or
/// when the bytes are longer than that many entries can be.
pub fn names_added_count(added: &[u8]) -> Result<usize, Bad> {
    if added.len() > NAMES_ADDED_MAX_BYTES {
        return Err(Bad::TooLarge("names list"));
    }
    let (n, _) = varint_prefix(added, "names list count")?;
    if n > MAX_ADDED as u64 {
        return Err(Bad::Count("names list"));
    }
    Ok(n as usize)
}

/// A postcard varint (LEB128, at most 10 bytes for a u64) and the bytes it took.
fn varint_prefix(bytes: &[u8], what: &'static str) -> Result<(u64, usize), Bad> {
    let mut v: u64 = 0;
    for (i, &b) in bytes.iter().take(10).enumerate() {
        if i == 9 && b > 1 {
            return Err(Bad::Value(what));
        }
        v |= u64::from(b & 0x7f) << (7 * i);
        if b & 0x80 == 0 {
            return Ok((v, i + 1));
        }
    }
    if bytes.len() >= 10 {
        Err(Bad::Value(what))
    } else {
        Err(Bad::Truncated(what))
    }
}

/// One step of `names_hash` with its list digested: C1's `NamesStep`, same postcard.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NamesStepIn {
    pub before: [u8; 32],
    pub time: u64,
    pub epoch: u32,
    pub join: u32,
    pub list: [u8; 32],
}

/// A kept chain's key under an epoch (C4): the chain seal of `owner`'s chain `chain` with
/// `index` 0, or 1 for a chain with a sharer's back-link.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GkChainKey {
    pub owner: [u8; 16],
    pub chain: u32,
    pub index: u8,
    pub group: String,
    pub gen: [u8; 16],
    pub epoch: u32,
    pub sealed: Vec<u8>,
}

impl GkChainKey {
    pub fn check(&self) -> Result<(), Bad> {
        if self.index > 1 {
            return Err(Bad::Value("chain index"));
        }
        check_group(&self.group)?;
        exact("chain seal", self.sealed.len(), CHAIN_SEAL_BYTES)
    }
}

/// Who made a row to a seat (C4): history rows need that keyholder's `RB`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RowMaker {
    pub from: HolderRef,
    pub s: u32,
    pub b: u64,
    pub v: u64,
}

// ── The parts of the relay's multi-part messages (plan 1c) ────────────────
//
// Each message carries its sequence's group, part and last around one of these, as
// `EpochCommit` carries a `CommitPiece`; postcard writes a struct's fields inline, so a
// piece adds no byte. `Parts` takes them.

/// One part of `EpochIn`. Each `Option` sits in any one part, at most once a sequence;
/// `chain`, `walk` and `self_rows` spread over parts (plan 13). `chain`: contiguous
/// headers after the floor, oldest first; `walk`: kh links newest first; `kh`: the
/// header `have.kh` names, on the first answer per connection to a fetch with `have`;
/// `opening`: the head epoch's opening header when `head` is a Join; `past`: set when
/// this answers one `at` entry, never taken as a head.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InPiece {
    pub chain: Vec<HeaderIn>,
    pub walk: Vec<WalkLinkIn>,
    pub kh: Option<HeaderIn>,
    pub head: Option<WalkLinkIn>,
    pub opening: Option<HeaderIn>,
    pub own_join: Option<HeaderIn>,
    pub leaf: Option<LeafIn>,
    pub path: Option<PathIn>,
    pub seal: Option<Vec<u8>>,
    pub seat: Option<SeatKeying>,
    pub seed_welcome: Option<SeedWelcomeIn>,
    pub self_rows: Vec<SelfRowIn>,
    pub past: Option<EpochRef>,
    pub pushed: bool,
}

/// One part of `EpochDue`. `kind` is a `due` code; `gated`: what the header must carry;
/// `seed_seats`: the seats of a seed-welcome page, and in a commit due every seat whose
/// seed the new floor would drop. The last three are what an opening's builder takes
/// beyond plan 1c (`build::OpeningAsk`, `build::Holding`): `finish`, every seat holds
/// the head's seed, so a running roll may finish; `pairs`, the pair of each keyholder of
/// the set, for its `KRK` welcome; `held`, the seats holding an older seed than the
/// head's, with that seed, as of this ask (every other seat holds the head's).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DuePiece {
    pub kind: u8,
    pub parent: [u8; 32],
    pub deadline_ms: u32,
    pub keyring_at: (u32, u32),
    pub joins: Vec<Joiner>,
    pub exits: Vec<ExitIn>,
    pub exits_upto: u64,
    pub promote: Option<Candidate>,
    pub remove: Option<HolderRef>,
    pub gated: bool,
    pub roll_due: bool,
    pub seed_seats: Vec<SeedSeat>,
    pub finish: bool,
    pub pairs: Vec<EndorsedPair>,
    pub held: Vec<(GkSeat, u32)>,
}

/// One part of `KeyringIn`: a slice of the keyring stream, at most
/// `KEYRING_SLICE_MAX_BYTES`, and this keyholder's `KRK` welcome in one part.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyringPiece {
    pub krk: Option<KrkIn>,
    pub stream: Vec<u8>,
}

/// One part of `EpochNamesIn`: the `added` lists asked or pushed, the signed headers of
/// pushed gated Joins (`joins`), the opening headers with `removed` lists (`removals`),
/// and `gone`, the step before the oldest list kept.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamesPiece {
    pub lists: Vec<NamesListIn>,
    pub joins: Vec<HeaderIn>,
    pub removals: Vec<HeaderIn>,
    pub gone: Option<NamesStepIn>,
}

/// One part of `VoiceSeats`, at most `VOICE_SEATS_PER_FRAME` entries: each user's voice
/// seat, and who left. `whole`: the room's every seat, on the sequence to a joiner.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VoiceSeatsPiece {
    pub seats: Vec<(UserId, GkSeat)>,
    pub gone: Vec<UserId>,
    pub whole: bool,
}

// ── VersionMake::Keep ─────────────────────────────────────────────────────

fn check_mask(mask: u64, seats: usize) -> Result<(), Bad> {
    if mask == 0 {
        return Err(Bad::Value("keep mask empty"));
    }
    if seats < 64 && (mask >> seats) != 0 {
        return Err(Bad::Value("keep mask past the list"));
    }
    Ok(())
}

/// The `Keep` mask of the seats of `list` (a version's list, in list order) that `keep`
/// says stay: bit i is `list[i]`. At most 62 seats, and at least one kept: a bucket left
/// with no seat is dropped (`CommitPiece.drops`), never kept empty.
pub fn keep_mask<T>(list: &[T], mut keep: impl FnMut(&T) -> bool) -> Result<u64, Bad> {
    at_most("keep list", list.len(), BUCKET_SEATS)?;
    let mask = list
        .iter()
        .enumerate()
        .filter(|(_, x)| keep(x))
        .fold(0u64, |m, (i, _)| m | (1 << i));
    check_mask(mask, list.len())?;
    Ok(mask)
}

/// The seats a `Keep { mask }` takes from `list`, the source version's list in list
/// order, in that order. Refused for a list over 62 seats, an empty mask, or a bit past
/// the list's end.
pub fn kept<T>(list: &[T], mask: u64) -> Result<impl Iterator<Item = &T> + '_, Bad> {
    at_most("keep list", list.len(), BUCKET_SEATS)?;
    check_mask(mask, list.len())?;
    Ok(list
        .iter()
        .enumerate()
        .filter(move |(i, _)| (mask >> *i) & 1 == 1)
        .map(|(_, x)| x))
}

// ── RowsOut packing ───────────────────────────────────────────────────────

impl RowsOut {
    /// Packs one row per seat of `(b, v)`, in its list order, each with whether it is
    /// under `s + 1`.
    pub fn pack<'a>(
        b: u64,
        v: u64,
        s: u32,
        rows: impl IntoIterator<Item = (&'a [u8], bool)>,
    ) -> Result<RowsOut, Bad> {
        let mut out = RowsOut {
            b,
            v,
            s,
            up: 0,
            rows: Vec::new(),
        };
        for (i, (row, up)) in rows.into_iter().enumerate() {
            if i >= BUCKET_SEATS {
                return Err(Bad::Count("rows"));
            }
            exact("row", row.len(), ROW_BYTES)?;
            out.rows.extend_from_slice(row);
            if up {
                out.up |= 1 << i;
            }
        }
        out.check()?;
        Ok(out)
    }

    /// The rows it holds, once `check` passed.
    pub fn count(&self) -> usize {
        self.rows.len() / ROW_BYTES
    }

    /// 1 to 62 whole rows, no `up` bit past the last, and `s + 1` a seed.
    pub fn check(&self) -> Result<(), Bad> {
        if self.rows.is_empty() || !self.rows.len().is_multiple_of(ROW_BYTES) {
            return Err(Bad::Length("rows"));
        }
        let n = self.count();
        at_most("rows", n, BUCKET_SEATS)?;
        if (self.up >> n) != 0 {
            return Err(Bad::Value("rows up past the last row"));
        }
        if self.up != 0 && self.s == u32::MAX {
            return Err(Bad::Value("rows seed"));
        }
        Ok(())
    }

    /// `check`, and one row for each of the version's `seats`.
    pub fn check_for(&self, seats: usize) -> Result<(), Bad> {
        self.check()?;
        if self.count() != seats {
            return Err(Bad::Count("rows for the version's seats"));
        }
        Ok(())
    }

    /// Each row, in list order, with the seed it is under.
    pub fn each(&self) -> Result<impl Iterator<Item = (&[u8; ROW_BYTES], u32)> + '_, Bad> {
        self.check()?;
        Ok(self
            .rows
            .as_chunks::<ROW_BYTES>()
            .0
            .iter()
            .enumerate()
            .map(move |(i, row)| (row, self.s + ((self.up >> i) & 1) as u32)))
    }
}

// ── Keyring stream (plan 1e) ──────────────────────────────────────────────

const KEYRING_LEN_BYTES: usize = 4;

fn keyring_entry_len(n: usize) -> Result<(), Bad> {
    if n < AEAD_OVERHEAD {
        Err(Bad::Length("keyring entry"))
    } else if n > KEYRING_MAX_BYTES - KEYRING_LEN_BYTES {
        Err(Bad::TooLarge("keyring entry"))
    } else {
        Ok(())
    }
}

/// Appends one entry to a keyring stream: `u32 BE len ‖ sealed`, the base first, then each
/// Join's delta in order. Refused past `KEYRING_MAX_BYTES` in all.
pub fn put_keyring_entry(stream: &mut Vec<u8>, sealed: &[u8]) -> Result<(), Bad> {
    keyring_entry_len(sealed.len())?;
    if stream.len() + KEYRING_LEN_BYTES + sealed.len() > KEYRING_MAX_BYTES {
        return Err(Bad::TooLarge("keyring stream"));
    }
    stream.extend_from_slice(&(sealed.len() as u32).to_be_bytes());
    stream.extend_from_slice(sealed);
    Ok(())
}

/// The entries of a keyring stream, borrowed from it, in order. It stops at the first bad
/// entry (short, over the cap, or cut off), after yielding that error once.
pub struct KeyringEntries<'a> {
    rest: &'a [u8],
    failed: bool,
}

impl<'a> KeyringEntries<'a> {
    fn step(&mut self) -> Result<&'a [u8], Bad> {
        let (len, after) = self
            .rest
            .split_first_chunk::<KEYRING_LEN_BYTES>()
            .ok_or(Bad::Truncated("keyring entry length"))?;
        let n = u32::from_be_bytes(*len) as usize;
        keyring_entry_len(n)?;
        if after.len() < n {
            return Err(Bad::Truncated("keyring entry"));
        }
        let (entry, rest) = after.split_at(n);
        self.rest = rest;
        Ok(entry)
    }
}

impl<'a> Iterator for KeyringEntries<'a> {
    type Item = Result<&'a [u8], Bad>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.rest.is_empty() {
            return None;
        }
        let entry = self.step();
        self.failed = entry.is_err();
        Some(entry)
    }
}

/// Reads a keyring stream entry by entry, refused whole past `KEYRING_MAX_BYTES`.
pub fn keyring_entries(stream: &[u8]) -> Result<KeyringEntries<'_>, Bad> {
    if stream.len() > KEYRING_MAX_BYTES {
        return Err(Bad::TooLarge("keyring stream"));
    }
    Ok(KeyringEntries {
        rest: stream,
        failed: false,
    })
}

/// A `KeyringIn` sequence's stream, which runs from the receiver's `have` on: the entries
/// for joins `from..=to` of one epoch, join 0 being the base and join j > 0 that Join's
/// delta. Exactly that many entries, each with its join; none when `from > to`.
pub fn read_keyring(stream: &[u8], from: u32, to: u32) -> Result<Vec<(u32, &[u8])>, Bad> {
    let want = if from > to {
        0
    } else {
        u64::from(to - from) + 1
    };
    let mut out = Vec::new();
    for entry in keyring_entries(stream)? {
        let entry = entry?;
        if out.len() as u64 >= want {
            return Err(Bad::Count("keyring entries"));
        }
        out.push((from + out.len() as u32, entry));
    }
    if out.len() as u64 != want {
        return Err(Bad::Count("keyring entries"));
    }
    Ok(out)
}

/// A whole commit's `keyring`: exactly one entry, the base of an opening commit or the
/// delta of a Join.
pub fn commit_keyring(stream: &[u8]) -> Result<&[u8], Bad> {
    let mut entries = keyring_entries(stream)?;
    let one = entries.next().ok_or(Bad::Count("commit keyring"))??;
    if entries.next().is_some() {
        return Err(Bad::Count("commit keyring"));
    }
    Ok(one)
}

// ── Memory held (plan 1e caps) ────────────────────────────────────────────

/// The heap a decoded value holds beyond its own `size_of`. `Parts` charges each part
/// the larger of its frame's encoded bytes and this, so the caps of 1e bound memory as
/// well as the wire: a `Ratchet` version is 5 B encoded and 48 B decoded, a drop 1 B and
/// 8 B, and a part of 11,456 of them would otherwise hold ten times what it is charged.
///
/// Every type of this module has it; a part type sums its fields' `heap()`.
pub trait Footprint {
    /// No value of the type holds heap: a `Vec` of it is its capacity alone.
    const FLAT: bool = false;
    fn heap(&self) -> usize;
}

impl<T: Footprint> Footprint for Vec<T> {
    fn heap(&self) -> usize {
        let own = self.capacity().saturating_mul(mem::size_of::<T>());
        if T::FLAT {
            own
        } else {
            self.iter().fold(own, |n, x| n.saturating_add(x.heap()))
        }
    }
}

impl<T: Footprint> Footprint for Option<T> {
    const FLAT: bool = T::FLAT;
    fn heap(&self) -> usize {
        self.as_ref().map_or(0, Footprint::heap)
    }
}

impl<A: Footprint, B: Footprint> Footprint for (A, B) {
    const FLAT: bool = A::FLAT && B::FLAT;
    fn heap(&self) -> usize {
        self.0.heap().saturating_add(self.1.heap())
    }
}

impl Footprint for String {
    fn heap(&self) -> usize {
        self.capacity()
    }
}

impl<const N: usize> Footprint for [u8; N] {
    const FLAT: bool = true;
    fn heap(&self) -> usize {
        0
    }
}

/// Types that hold no heap. Each is `Copy`, which no type holding heap can be.
macro_rules! flat {
    ($($t:ty),* $(,)?) => {
        $(
            const _: () = {
                const fn copy<T: Copy>() {}
                copy::<$t>()
            };
            impl Footprint for $t {
                const FLAT: bool = true;
                fn heap(&self) -> usize {
                    0
                }
            }
        )*
    };
}

/// Types whose heap is their fields'. Every field is named (the pattern has no `..`), so
/// a field added later fails the build until it is listed here.
macro_rules! footprint {
    ($($t:ident { $($field:ident),* }),* $(,)?) => {
        $(impl Footprint for $t {
            fn heap(&self) -> usize {
                let $t { $($field),* } = self;
                0usize $(.saturating_add($field.heap()))*
            }
        })*
    };
}

flat!(
    (),
    bool,
    u8,
    u16,
    u32,
    u64,
    GkMember,
    GkSeat,
    GkWriter,
    HolderRef,
    FloorRef,
    EpochRef,
    NamesRef,
    LeafIn,
    RatchetStep,
    JoinRefused,
    ExitIn,
    NamesStepIn,
    RowMaker,
);

footprint!(
    ListSeat { seat, dh },
    EndorsedPair {
        origin,
        u,
        kem,
        dh,
        n,
        made,
        sig
    },
    HeaderIn { body, sig },
    WalkLinkIn { header, parent },
    PathIn { index, n, siblings },
    SeatKeying {
        b,
        base_v,
        s,
        from,
        welcome,
        row,
        ratchets
    },
    SeedWelcomeIn { s, from, bytes },
    SelfRowIn {
        group,
        gen,
        seed,
        sk,
        sx,
        kind,
        sealed
    },
    VersionOut { b, v, pool, make },
    WelcomeOut {
        seat,
        b,
        v,
        s,
        bytes
    },
    RowsOut { b, v, s, up, rows },
    SealOut { b, v, bytes },
    KrkOut { to, from_kx, bytes },
    SeedWelcomeOut { seat, bytes },
    Joiner {
        seat,
        ik,
        keys,
        returning
    },
    Candidate { m, ik, pair },
    SeedSeat { seat, ik, keys },
    ListIn { b, v, seats },
    KrkIn { from, bytes },
    NamesListIn {
        time,
        epoch,
        join,
        added
    },
    GkChainKey {
        owner,
        chain,
        index,
        group,
        gen,
        epoch,
        sealed
    },
    CommitPiece {
        header,
        versions,
        drops,
        welcomes,
        rows,
        seals,
        seed_welcomes,
        keyring,
        krk,
        refused
    },
    InPiece {
        chain,
        walk,
        kh,
        head,
        opening,
        own_join,
        leaf,
        path,
        seal,
        seat,
        seed_welcome,
        self_rows,
        past,
        pushed
    },
    DuePiece {
        kind,
        parent,
        deadline_ms,
        keyring_at,
        joins,
        exits,
        exits_upto,
        promote,
        remove,
        gated,
        roll_due,
        seed_seats,
        finish,
        pairs,
        held
    },
    KeyringPiece { krk, stream },
    NamesPiece {
        lists,
        joins,
        removals,
        gone
    },
    VoiceSeatsPiece { seats, gone, whole },
);

impl Footprint for VersionMake {
    fn heap(&self) -> usize {
        match self {
            VersionMake::Seats(seats) => seats.heap(),
            VersionMake::Ratchet { .. } | VersionMake::Keep { .. } => 0,
        }
    }
}

// ── In-order parts (plan 1e) ──────────────────────────────────────────────

/// The multi-part kinds, each with its byte cap for a whole sequence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Seq {
    /// `EpochCommit`, at the relay.
    Commit,
    /// `EpochIn`.
    In,
    /// `EpochDue`.
    Due,
    /// `KeyringIn`.
    Keyring,
    /// `EpochNamesIn`.
    Names,
    /// `VoiceSeats`.
    VoiceSeats,
}

impl Seq {
    pub const fn cap(self) -> usize {
        match self {
            Seq::Commit => COMMIT_MAX_BYTES,
            Seq::In => IN_MAX_BYTES,
            Seq::Due => DUE_MAX_BYTES,
            Seq::Keyring => KEYRING_IN_MAX_BYTES,
            Seq::Names => NAMES_IN_MAX_BYTES,
            Seq::VoiceSeats => VOICE_SEATS_MAX_BYTES,
        }
    }
}

/// Why a partial sequence was thrown away.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lost {
    /// A new part 0 came.
    Restart,
    /// A part did not follow it: a part is missing, or another sequence began without
    /// its part 0.
    Gap,
    /// It would pass its cap, or a part was over `PIECE_MAX_BYTES`.
    TooLarge,
}

/// Why a part was not taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotTaken {
    /// No sequence is open for it: the rest of a dropped one, or one whose part 0 never
    /// came. Ignore it; the drop was reported once.
    NotStarted,
    /// It did not follow the open sequence, which is dropped with it.
    Gap,
    /// Over `PIECE_MAX_BYTES`, or the sequence would pass its cap; dropped with it.
    TooLarge,
}

/// What became of this part.
#[derive(Debug, PartialEq, Eq)]
pub enum Part<K, T> {
    /// Held; the next part of its sequence may come.
    Held,
    /// The last part: every part of the sequence, in order.
    Whole(K, Vec<T>),
    NotTaken(NotTaken),
}

/// What one part did: the partial sequence it ended without finishing (if any), and what
/// became of the part itself. A receiver fetches again on a `dropped` sequence (the relay
/// sends none of a failed sequence's later parts), and answers a relay's own refusal.
#[must_use]
#[derive(Debug, PartialEq, Eq)]
pub struct Took<K, T> {
    pub dropped: Option<(K, Lost)>,
    pub part: Part<K, T>,
}

struct Open<K, T> {
    key: K,
    next: u16,
    charged: usize,
    parts: Vec<T>,
}

/// The parts of one (sender, group) and kind, taken in order (plan 1e): part k only right
/// after part k − 1 of the same sequence; a new part 0 drops a partial sequence; a part
/// that does not follow drops it; a sequence past its cap is dropped.
///
/// `K` tells two sequences of one group apart (a commit's `due`, a keyring's
/// `(gen, epoch, join)`; `()` where the group alone does). Each part is charged the larger
/// of its frame's encoded bytes and the heap its decoded value holds (`Footprint`), plus
/// `size_of::<T>()`: so neither the wire bytes nor the memory of a sequence passes its
/// cap, however small the parts or the items in them are.
pub struct Parts<K, T> {
    cap: usize,
    open: Option<Open<K, T>>,
}

impl<K: PartialEq, T: Footprint> Parts<K, T> {
    pub fn new(kind: Seq) -> Parts<K, T> {
        Parts::with_cap(kind.cap())
    }

    pub fn with_cap(cap: usize) -> Parts<K, T> {
        Parts { cap, open: None }
    }

    /// Bytes charged to the open sequence; 0 with none. For the per-connection and
    /// per-relay caps on open commits: it counts decoded memory, not only the wire.
    pub fn held(&self) -> usize {
        self.open.as_ref().map_or(0, |o| o.charged)
    }

    /// Drops the open sequence (a timeout, the head moved), returning its key.
    pub fn clear(&mut self) -> Option<K> {
        self.open.take().map(|o| o.key)
    }

    /// Takes part `part` of sequence `key`. `bytes` is the frame's encoded size; the part
    /// is charged the larger of that and `piece.heap()`, plus `size_of::<T>()`.
    pub fn take(&mut self, key: K, part: u16, last: bool, piece: T, bytes: usize) -> Took<K, T> {
        let charge = bytes.max(piece.heap()).saturating_add(mem::size_of::<T>());
        if part == 0 {
            let dropped = self.open.take().map(|o| (o.key, Lost::Restart));
            let part = if bytes > PIECE_MAX_BYTES || charge > self.cap {
                Part::NotTaken(NotTaken::TooLarge)
            } else if last {
                Part::Whole(key, vec![piece])
            } else {
                self.open = Some(Open {
                    key,
                    next: 1,
                    charged: charge,
                    parts: vec![piece],
                });
                Part::Held
            };
            return Took { dropped, part };
        }
        let Some(mut open) = self.open.take() else {
            return Took {
                dropped: None,
                part: Part::NotTaken(NotTaken::NotStarted),
            };
        };
        if open.key != key || open.next != part {
            return Took {
                dropped: Some((open.key, Lost::Gap)),
                part: Part::NotTaken(NotTaken::Gap),
            };
        }
        let charged = open.charged.saturating_add(charge);
        let next = part.checked_add(1);
        if bytes > PIECE_MAX_BYTES || charged > self.cap || (!last && next.is_none()) {
            return Took {
                dropped: Some((open.key, Lost::TooLarge)),
                part: Part::NotTaken(NotTaken::TooLarge),
            };
        }
        open.parts.push(piece);
        if last {
            return Took {
                dropped: None,
                part: Part::Whole(open.key, open.parts),
            };
        }
        open.charged = charged;
        open.next = next.unwrap_or(u16::MAX);
        self.open = Some(open);
        Took {
            dropped: None,
            part: Part::Held,
        }
    }
}

// ── Commits: cutting and joining ──────────────────────────────────────────

/// An `EpochCommit` frame around its piece at most: the variant index (2), the group's
/// length (2) and bytes, `due` (10), `part` (3), `last` (1).
pub fn commit_frame_overhead(group: &str) -> usize {
    2 + 2 + group.len() + 10 + 3 + 1
}

/// A piece with no items at most: the header's `Option` tag and nine `Vec` lengths, each
/// below 2^21 in one piece (3 bytes).
const PIECE_FIXED_BYTES: usize = 1 + 9 * 3;

fn encoded_len<T: Serialize + ?Sized>(x: &T) -> usize {
    postcard::serialize_with_flavor(x, postcard::ser_flavors::Size::default()).unwrap_or(usize::MAX)
}

struct Cutter {
    max: usize,
    done: Vec<CommitPiece>,
    cur: CommitPiece,
    used: usize,
}

impl Cutter {
    fn flush(&mut self) {
        self.done.push(mem::take(&mut self.cur));
        self.used = PIECE_FIXED_BYTES;
    }

    fn room(&mut self, n: usize) -> Result<(), Bad> {
        if n > self.max - PIECE_FIXED_BYTES {
            return Err(Bad::TooLarge("commit item"));
        }
        if self.used + n > self.max {
            self.flush();
        }
        self.used += n;
        Ok(())
    }
}

/// Cuts a whole commit into pieces of at most `max` encoded bytes each, in field order,
/// the header in the first: `max` is `PIECE_MAX_BYTES - commit_frame_overhead(group)`.
/// `join_commit` of the pieces gives the commit back.
pub fn cut_commit(whole: CommitPiece, max: usize) -> Result<Vec<CommitPiece>, Bad> {
    let header = whole.header.ok_or(Bad::Value("commit header"))?;
    let header_len = encoded_len(&header);
    if max <= PIECE_FIXED_BYTES + header_len {
        return Err(Bad::TooLarge("commit header"));
    }
    let mut cut = Cutter {
        max,
        done: Vec::new(),
        cur: CommitPiece {
            header: Some(header),
            ..CommitPiece::default()
        },
        used: PIECE_FIXED_BYTES + header_len,
    };
    macro_rules! fill {
        ($field:ident) => {
            for item in whole.$field {
                cut.room(encoded_len(&item))?;
                cut.cur.$field.push(item);
            }
        };
    }
    fill!(versions);
    fill!(drops);
    fill!(welcomes);
    fill!(rows);
    fill!(seals);
    fill!(seed_welcomes);
    let mut rest = &whole.keyring[..];
    while !rest.is_empty() {
        if cut.used >= cut.max {
            cut.flush();
        }
        let n = (cut.max - cut.used).min(rest.len());
        cut.cur.keyring.extend_from_slice(&rest[..n]);
        cut.used += n;
        rest = &rest[n..];
    }
    fill!(krk);
    fill!(refused);
    cut.done.push(cut.cur);
    Ok(cut.done)
}

impl CommitPiece {
    /// Every item's length and range; a receiver runs it on each part as it comes.
    pub fn check_items(&self) -> Result<(), Bad> {
        if let Some(h) = &self.header {
            h.check()?;
        }
        self.versions.iter().try_for_each(VersionOut::check)?;
        self.welcomes.iter().try_for_each(WelcomeOut::check)?;
        self.rows.iter().try_for_each(RowsOut::check)?;
        self.seals.iter().try_for_each(SealOut::check)?;
        self.seed_welcomes
            .iter()
            .try_for_each(SeedWelcomeOut::check)?;
        self.krk.iter().try_for_each(KrkOut::check)
    }

    /// A whole commit: a header, at most 256 welcomes and 256 refused joiners, at most one
    /// `KRK` welcome per keyholder, exactly one keyring entry, and every item's length.
    pub fn check_whole(&self) -> Result<(), Bad> {
        if self.header.is_none() {
            return Err(Bad::Value("commit header"));
        }
        at_most("commit welcomes", self.welcomes.len(), MAX_JOINERS)?;
        at_most("commit refused", self.refused.len(), MAX_JOINERS)?;
        at_most("commit keyring welcomes", self.krk.len(), MAX_KEYHOLDERS)?;
        commit_keyring(&self.keyring)?;
        self.check_items()
    }
}

/// The whole commit from its parts in order (`Part::Whole`): the header from part 0 and
/// no other, every list in part order, then `check_whole`. Each list grows once, to its
/// whole length, so the commit holds no more heap than its parts did (`Footprint`): at
/// most the sequence's charge again while the parts drain into it.
pub fn join_commit(parts: Vec<CommitPiece>) -> Result<CommitPiece, Bad> {
    let mut parts = parts.into_iter();
    let mut whole = parts.next().ok_or(Bad::Count("commit parts"))?;
    let rest = parts.as_slice();
    macro_rules! reserve {
        ($($field:ident),*) => {
            $(whole.$field.reserve_exact(rest.iter().map(|p| p.$field.len()).sum());)*
        };
    }
    reserve!(
        versions,
        drops,
        welcomes,
        rows,
        seals,
        seed_welcomes,
        keyring,
        krk,
        refused
    );
    for p in parts {
        if p.header.is_some() {
            return Err(Bad::Value("header after part 0"));
        }
        whole.versions.extend(p.versions);
        whole.drops.extend(p.drops);
        whole.welcomes.extend(p.welcomes);
        whole.rows.extend(p.rows);
        whole.seals.extend(p.seals);
        whole.seed_welcomes.extend(p.seed_welcomes);
        whole.keyring.extend(p.keyring);
        whole.krk.extend(p.krk);
        whole.refused.extend(p.refused);
    }
    whole.check_whole()?;
    Ok(whole)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::{ClientMessage, ServerMessage};
    use serde::de::DeserializeOwned;
    use std::fmt::Debug;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn rt<T: Serialize + DeserializeOwned + PartialEq + Debug>(v: &T) {
        let bytes = postcard::to_allocvec(v).unwrap();
        let (back, rest) = postcard::take_from_bytes::<T>(&bytes).unwrap();
        assert!(rest.is_empty(), "{v:?} left bytes over");
        assert_eq!(&back, v);
        assert_eq!(encoded_len(v), bytes.len());
    }

    /// splitmix64, for values that fill their varints.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }

        fn bytes<const N: usize>(&mut self) -> [u8; N] {
            let mut out = [0u8; N];
            for b in out.iter_mut() {
                *b = self.next() as u8;
            }
            out
        }
    }

    fn seat(n: u8) -> GkSeat {
        GkSeat {
            m: GkMember::Account([n; 16]),
            sk: [n ^ 0x10; 8],
            sx: [n ^ 0x20; 8],
        }
    }

    fn conn_seat(u: u32) -> GkSeat {
        GkSeat {
            m: GkMember::Conn(u),
            sk: [0x31; 8],
            sx: [0x32; 8],
        }
    }

    fn holder(n: u8) -> HolderRef {
        HolderRef {
            m: GkMember::Account([n; 16]),
            kx: [n; 32],
        }
    }

    fn pair(origin: u8, u: u32) -> EndorsedPair {
        EndorsedPair {
            origin,
            u,
            kem: vec![0x08; KEM_PUBLIC_BYTES],
            dh: vec![0x05; DH_PUBLIC_BYTES],
            n: 3,
            made: 1_763_000_000,
            sig: vec![0x55; SIG_BYTES],
        }
    }

    fn header(len: usize) -> HeaderIn {
        HeaderIn {
            body: vec![0x11; len],
            sig: vec![0x22; SIG_BYTES],
        }
    }

    fn row(n: u8) -> Vec<u8> {
        vec![n; ROW_BYTES]
    }

    #[test]
    fn codes_keep_their_values() {
        let frozen: &[(u8, u8)] = &[
            (due::JOIN, 0),
            (due::EXITS, 1),
            (due::REFRESH, 2),
            (due::PROMOTE, 3),
            (due::REMOVE, 4),
            (due::REPLACE, 5),
            (due::GENESIS, 6),
            (due::REGENESIS, 7),
            (due::SEED_WELCOMES, 8),
            (due::GATE, 9),
            (stale::NOT_HEAD, 0),
            (stale::NOT_KEYHOLDER, 1),
            (stale::NOT_DUE, 2),
            (stale::CHECK, 3),
            (stale::TIMED_OUT, 4),
            (stale::HEAD_MOVED, 5),
            (stale::TOO_LARGE, 6),
            (stale::STORE, 7),
            (wait::QUEUED, 0),
            (wait::NO_KEYHOLDER, 1),
            (wait::REFUSED, 2),
            (wait::NO_SEAT_KEYS, 3),
            (wait::GUEST_IN_GATED, 4),
            (wait::NEW_GENERATION, 5),
            (decline::PLATFORM, 0),
            (decline::GUEST_LIMIT, 1),
            (decline::CLOCK, 2),
            (decline::CONN_BUCKET, 3),
            (decline::CANDIDATE, 4),
            (decline::NOT_READY, 5),
            (refused_what::FETCH, 0),
            (refused_what::POST, 1),
            (refused_what::BLOB, 2),
            (refused_what::NAMES, 3),
            (refused_what::COMMIT, 4),
            (refused_what::VOLUNTEER, 5),
            (refused_what::LEGACY, 6),
            (refused_what::ROWS, 7),
            (refused_why::OFF, 0),
            (refused_why::NOT_MEMBER, 1),
            (refused_why::OLD_EPOCH, 2),
            (refused_why::THIRD_BLOB, 3),
            (refused_why::RATE, 4),
            (refused_why::NOT_GATED, 5),
            (refused_why::LEGACY_PATH, 6),
            (refused_why::TOO_LARGE, 7),
            (refused_why::NOT_STORED, 8),
            (platform::DESKTOP, 1),
            (platform::PHONE, 2),
            (platform::BROWSER, 3),
            (platform::BROWSER_BUSY, 4),
            (join_refused::ENDORSEMENT, 0),
            (join_refused::PIN, 1),
            (join_refused::OLD_COUNTER, 2),
            (join_refused::GUEST_IN_GATED, 3),
            (join_refused::ALREADY_SEATED, 4),
            (origin::VAULT_SEAT, 1),
            (origin::CONNECTION, 2),
            (origin::DESKTOP, 3),
            (pool::ACCOUNTS, 0),
            (pool::CONNS, 1),
            (self_row::SELF_ROW, 0),
            (self_row::HISTORY_ROW, 1),
            (group_kind::TEXT, 0),
            (group_kind::VOICE, 1),
        ];
        for (i, (got, want)) in frozen.iter().enumerate() {
            assert_eq!(got, want, "code #{i}");
        }
        assert_eq!(stale::name(stale::STORE), "STORE");
        assert_eq!(refused_why::name(8), "NOT_STORED");
        assert_eq!(due::name(10), "unknown");
    }

    #[test]
    fn every_type_round_trips() {
        let mut rng = Rng(7);
        let members = [
            GkMember::Account([0xa5; 16]),
            GkMember::Conn(0),
            GkMember::Conn(u32::MAX),
        ];
        for m in members {
            rt(&m);
            rt(&GkWriter { m, u: 42 });
            rt(&HolderRef { m, kx: [9; 32] });
        }
        rt(&seat(1));
        rt(&conn_seat(70_000));
        rt(&ListSeat {
            seat: seat(2),
            dh: vec![5; DH_PUBLIC_BYTES],
        });
        rt(&pair(origin::CONNECTION, 77));
        rt(&header(383));
        rt(&WalkLinkIn {
            header: header(1119),
            parent: Some(header(400)),
        });
        rt(&WalkLinkIn {
            header: header(1),
            parent: None,
        });
        rt(&FloorRef {
            gen: rng.bytes(),
            epoch: u32::MAX,
            join: 5,
            d: rng.bytes(),
            kh: rng.bytes(),
        });
        rt(&EpochRef {
            gen: rng.bytes(),
            epoch: 1,
        });
        rt(&NamesRef {
            gen: rng.bytes(),
            epoch: 2,
            join: 3,
        });
        rt(&LeafIn {
            b: rng.next(),
            v: rng.next(),
            pool: pool::CONNS,
            seats: 62,
            list: rng.bytes(),
            via: Some(rng.next()),
        });
        rt(&PathIn {
            index: 3,
            n: 1613,
            siblings: vec![[1; 32]; 11],
        });
        let keying = SeatKeying {
            b: rng.next(),
            base_v: 10,
            s: 4,
            from: holder(3),
            welcome: Some(vec![1; SEAT_WELCOME_BYTES]),
            row: None,
            ratchets: vec![
                RatchetStep {
                    e: 8,
                    from: 10,
                    to: 11,
                },
                RatchetStep {
                    e: 9,
                    from: 11,
                    to: 12,
                },
            ],
        };
        rt(&keying);
        rt(&SeedWelcomeIn {
            s: 5,
            from: holder(4),
            bytes: vec![2; SEED_WELCOME_BYTES],
        });
        rt(&SelfRowIn {
            group: "c:general".into(),
            gen: rng.bytes(),
            seed: 6,
            sk: [1; 8],
            sx: [2; 8],
            kind: self_row::HISTORY_ROW,
            sealed: vec![3; 500],
        });
        for make in [
            VersionMake::Ratchet { from_v: rng.next() },
            VersionMake::Keep {
                from_v: rng.next(),
                mask: (1 << 62) - 1,
            },
            VersionMake::Seats(vec![seat(1), seat(2)]),
        ] {
            rt(&make);
            rt(&VersionOut {
                b: rng.next(),
                v: rng.next(),
                pool: pool::ACCOUNTS,
                make,
            });
        }
        rt(&WelcomeOut {
            seat: seat(5),
            b: 1,
            v: 2,
            s: 3,
            bytes: vec![4; SEAT_WELCOME_BYTES],
        });
        rt(&RowsOut {
            b: 1,
            v: 2,
            s: 3,
            up: 0b101,
            rows: [row(1), row(2), row(3)].concat(),
        });
        rt(&SealOut {
            b: 1,
            v: 2,
            bytes: row(9),
        });
        rt(&KrkOut {
            to: holder(1),
            from_kx: [2; 32],
            bytes: vec![3; KRK_WELCOME_BYTES],
        });
        rt(&JoinRefused {
            seat: seat(6),
            why: join_refused::PIN,
        });
        rt(&SeedWelcomeOut {
            seat: seat(7),
            bytes: vec![8; SEED_WELCOME_BYTES],
        });
        let mut keyring = Vec::new();
        put_keyring_entry(&mut keyring, &[0x44; 300]).unwrap();
        rt(&CommitPiece {
            header: Some(header(1119)),
            versions: vec![VersionOut {
                b: 1,
                v: 2,
                pool: 0,
                make: VersionMake::Ratchet { from_v: 1 },
            }],
            drops: vec![u64::MAX, 3],
            welcomes: vec![WelcomeOut {
                seat: seat(5),
                b: 1,
                v: 2,
                s: 3,
                bytes: vec![4; SEAT_WELCOME_BYTES],
            }],
            rows: vec![RowsOut {
                b: 1,
                v: 2,
                s: 3,
                up: 0,
                rows: row(1),
            }],
            seals: vec![SealOut {
                b: 1,
                v: 2,
                bytes: row(9),
            }],
            seed_welcomes: vec![SeedWelcomeOut {
                seat: seat(7),
                bytes: vec![8; SEED_WELCOME_BYTES],
            }],
            keyring,
            krk: vec![KrkOut {
                to: holder(1),
                from_kx: [2; 32],
                bytes: vec![3; KRK_WELCOME_BYTES],
            }],
            refused: vec![JoinRefused {
                seat: seat(6),
                why: 4,
            }],
        });
        rt(&CommitPiece::default());
        rt(&Joiner {
            seat: seat(8),
            ik: [8; 32],
            keys: pair(origin::VAULT_SEAT, 0),
            returning: true,
        });
        rt(&ExitIn {
            seq: u64::MAX,
            seat: conn_seat(3),
            b: 4,
        });
        rt(&Candidate {
            m: GkMember::Conn(9),
            ik: [9; 32],
            pair: pair(origin::CONNECTION, 9),
        });
        rt(&SeedSeat {
            seat: seat(10),
            ik: [10; 32],
            keys: pair(origin::VAULT_SEAT, 0),
        });
        rt(&ListIn {
            b: 1,
            v: 2,
            seats: vec![
                ListSeat {
                    seat: seat(1),
                    dh: vec![5; 33],
                },
                ListSeat {
                    seat: seat(2),
                    dh: vec![5; 33],
                },
            ],
        });
        rt(&KrkIn {
            from: holder(2),
            bytes: vec![1; KRK_WELCOME_BYTES],
        });
        rt(&NamesListIn {
            time: 1_700_000_000,
            epoch: 1,
            join: 2,
            added: vec![0],
        });
        rt(&NamesStepIn {
            before: [1; 32],
            time: u64::MAX,
            epoch: 0,
            join: u32::MAX,
            list: [2; 32],
        });
        rt(&GkChainKey {
            owner: [1; 16],
            chain: (1 << 31) | 1,
            index: 1,
            group: "c:x".into(),
            gen: [2; 16],
            epoch: 3,
            sealed: row(4),
        });
        rt(&RowMaker {
            from: holder(5),
            s: 6,
            b: 7,
            v: 8,
        });
    }

    // ── C1's encodings ──
    //
    // The hex below is from voipc-crypto/src/group_key/kat.rs, the `PY` table that C1's
    // `python_known_answers` checks its own encodings against (C1 at 0f91a11).

    /// C1's `Keyholder`, field for field, to read "postcard(keyholders) for KS".
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct C1Keyholder {
        m: GkMember,
        u: Option<u32>,
        origin: u8,
        n: u32,
        ik: [u8; 32],
        kx: [u8; 32],
        tag_kk: [u8; 8],
    }

    /// C1's `Removed`, to read "postcard(removed) list".
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    enum C1Removed {
        Count(u32),
        List(Vec<GkSeat>),
    }

    const C1_KEYHOLDERS: &str = "0200020202020202020202020202020202020003043f3e5f6d86926c9c128cf84581574f96840d98ee5ab53b1ec3b76e2bb25b945edc2cca31e8e43bbd91dff7e475cca3347eb478107d5bd765aba4ae4a30c35d445890a708318c0bbd0109000200d89e3bad79437dbed9f843418304f460ff05c7fe81fe4a9577a804cb9367ff6634e42d4af5ef94a07a3a84201b889d4cd1a743cb27b11b6a10438a8feb8e58472acd85d268a738f8";
    const C1_REMOVED: &str = "010200010101010101010101010101010101014a7d5eaad621eda8fcb6d7fc1937f21f0003030303030303030303030303030303c3c3c3c3c3c3c3c3c4c4c4c4c4c4c4c4";

    #[test]
    fn member_encodes_as_c1_member_id() {
        let bytes = unhex(C1_KEYHOLDERS);
        let holders: Vec<C1Keyholder> = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(holders[0].m, GkMember::Account([2; 16]));
        assert_eq!(holders[1].m, GkMember::Conn(9));
        assert_eq!(postcard::to_allocvec(&holders).unwrap(), bytes);
        assert_eq!(hex(&postcard::to_allocvec(&holders[1].m).unwrap()), "0109");
        assert_eq!(
            hex(&postcard::to_allocvec(&holders[0].m).unwrap()),
            format!("00{}", "02".repeat(16))
        );
    }

    #[test]
    fn seat_encodes_as_c1_seat_ref() {
        let bytes = unhex(C1_REMOVED);
        let C1Removed::List(seats) = postcard::from_bytes::<C1Removed>(&bytes).unwrap() else {
            panic!("a list");
        };
        let m_seat = GkSeat {
            m: GkMember::Account([1; 16]),
            sk: unhex("4a7d5eaad621eda8").try_into().unwrap(),
            sx: unhex("fcb6d7fc1937f21f").try_into().unwrap(),
        };
        let other = GkSeat {
            m: GkMember::Account([3; 16]),
            sk: [0xc3; 8],
            sx: [0xc4; 8],
        };
        assert_eq!(seats, vec![m_seat, other]);
        assert_eq!(
            postcard::to_allocvec(&C1Removed::List(seats.clone())).unwrap(),
            bytes
        );
        // C1 sorts by encoded bytes; for seats that is list order.
        assert!(in_list_order(&seats));
    }

    #[test]
    fn leaf_encodes_as_c1_leaf() {
        let list_conn: [u8; 32] =
            unhex("7e5454bd7ac08c1c2e678b03fe0fb9491d1ba9cbc924cf7ea68003c1ff0f445e")
                .try_into()
                .unwrap();
        let list_kat: [u8; 32] =
            unhex("3d641aaedf83fb0452e3b04920492ceb243357e9f1fe5ec7dc10107d9ebad9c0")
                .try_into()
                .unwrap();
        let leaf = |b, v, pool, seats, list, via| LeafIn {
            b,
            v,
            pool,
            seats,
            list,
            via,
        };
        // "leaf L0 postcard" … "leaf L4 postcard", from kat.rs `In::leaves`.
        let cases = [
            (
                leaf(1, 16, pool::ACCOUNTS, 62, [0xa0; 32], None),
                "0110003ea0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a000",
            ),
            (
                leaf(200, 17, pool::CONNS, 1, list_conn, None),
                "c8011101017e5454bd7ac08c1c2e678b03fe0fb9491d1ba9cbc924cf7ea68003c1ff0f445e00",
            ),
            (
                leaf(0x0123_4567_89ab_cdef, 3, pool::ACCOUNTS, 2, list_kat, Some(2)),
                "ef9bafcdf8acd191010300023d641aaedf83fb0452e3b04920492ceb243357e9f1fe5ec7dc10107d9ebad9c00102",
            ),
            (
                leaf(1 << 63, (1 << 63) + 1, pool::ACCOUNTS, 61, [0xa3; 32], None),
                "8080808080808080800181808080808080808001003da3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a300",
            ),
            (
                leaf(
                    u64::MAX,
                    7,
                    pool::CONNS,
                    62,
                    [0xa4; 32],
                    Some(0xfedc_ba98_7654_3210),
                ),
                "ffffffffffffffffff0107013ea4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a40190e4d0b287d3aeeefe01",
            ),
        ];
        for (i, (leaf, want)) in cases.iter().enumerate() {
            assert_eq!(hex(&postcard::to_allocvec(leaf).unwrap()), *want, "L{i}");
            assert_eq!(
                postcard::from_bytes::<LeafIn>(&unhex(want)).unwrap(),
                *leaf,
                "L{i}"
            );
            leaf.check().unwrap();
        }
    }

    #[test]
    fn names_step_encodes_as_c1_names_step() {
        // F1's step of kat.rs `names_fold` ("names step preimage F1" holds its fields:
        // before = "names_hash H3", time 0x6553f11e, epoch 1, join 2, list = "list digest
        // F1"). The bytes are C1's `postcard::to_allocvec(&NamesStep { .. })` of those
        // fields, printed by a throwaway program linked against voipc-crypto at 0f91a11.
        let step = NamesStepIn {
            before: unhex("1a395c81280c2df332d8ede9a7f2076e85bf5c89f5d3e9f5a4c309958455ed40")
                .try_into()
                .unwrap(),
            time: 0x6553_f11e,
            epoch: 1,
            join: 2,
            list: unhex("6a6876586357d23f72d48db0ca514fc63f405745aaecd2be5afd7da72d2f0c93")
                .try_into()
                .unwrap(),
        };
        let want = C1_NAMES_STEP_F1;
        assert_eq!(hex(&postcard::to_allocvec(&step).unwrap()), want);
        assert_eq!(
            postcard::from_bytes::<NamesStepIn>(&unhex(want)).unwrap(),
            step
        );
    }

    const C1_NAMES_STEP_F1: &str = "1a395c81280c2df332d8ede9a7f2076e85bf5c89f5d3e9f5a4c309958455ed409ee2cfaa0601026a6876586357d23f72d48db0ca514fc63f405745aaecd2be5afd7da72d2f0c93";

    #[test]
    fn names_count_reads_c1_added_lists() {
        // "postcard(added) F2", "… H3" and "… empty list" are `Added::List`: drop its
        // variant index (01) for the bare `Vec<AddedSeat>`.
        let f2 = "0102000505050505050505050505050505050555555555555555555555555555555555555555555555555555555555555555555151515151515151525252525252525200ace4cfaa06000707070707070707070707070707070777777777777777777777777777777777777777777777777777777777777777777171717171717171727272727272727201dee4cfaa06";
        assert_eq!(names_added_count(&unhex(&f2[2..])), Ok(2));
        assert_eq!(names_added_count(&unhex("00")), Ok(0));
        let mut big = vec![0x81, 0x02]; // 257
        big.extend(vec![0; 100]);
        assert_eq!(names_added_count(&big), Err(Bad::Count("names list")));
        assert_eq!(names_added_count(&[0x80, 0x02]), Ok(256));
        assert!(matches!(names_added_count(&[]), Err(Bad::Truncated(_))));
        assert!(matches!(
            names_added_count(&[0x80; 3]),
            Err(Bad::Truncated(_))
        ));
        assert!(matches!(names_added_count(&[0xff; 11]), Err(Bad::Value(_))));
        assert_eq!(
            names_added_count(&vec![0; NAMES_ADDED_MAX_BYTES + 1]),
            Err(Bad::TooLarge("names list"))
        );
        let list = NamesListIn {
            time: 1,
            epoch: 1,
            join: 1,
            added: unhex(&f2[2..]),
        };
        list.check().unwrap();
    }

    #[test]
    fn record_order_is_list_order() {
        let mut rng = Rng(11);
        let mut seats: Vec<GkSeat> = (0..200)
            .map(|i| GkSeat {
                m: if i % 3 == 0 {
                    GkMember::Conn(rng.next() as u32)
                } else {
                    GkMember::Account(rng.bytes())
                },
                sk: rng.bytes(),
                sx: rng.bytes(),
            })
            .collect();
        let mut by_record = seats.clone();
        by_record.sort_by_key(GkSeat::record);
        seats.sort();
        assert_eq!(seats, by_record);
        assert!(in_list_order(&seats));
        assert_eq!(
            &seat(1).record()[..17],
            &GkMember::Account([1; 16]).seat_id()
        );
        assert_eq!(
            hex(&GkMember::Conn(0x0102_0304).seat_id()),
            "0200000000000000000000000001020304"
        );
    }

    // ── Checks ──

    #[test]
    fn checks_refuse_wrong_lengths() {
        pair(origin::VAULT_SEAT, 0).check().unwrap();
        pair(origin::DESKTOP, 0).check().unwrap();
        pair(origin::CONNECTION, 5).check().unwrap();
        let mut p = pair(origin::VAULT_SEAT, 0);
        p.kem.pop();
        assert_eq!(p.check(), Err(Bad::Length("pair kem")));
        let mut p = pair(origin::VAULT_SEAT, 0);
        p.dh.push(0);
        assert_eq!(p.check(), Err(Bad::Length("pair dh")));
        let mut p = pair(origin::VAULT_SEAT, 0);
        p.sig.truncate(63);
        assert_eq!(p.check(), Err(Bad::Length("pair sig")));
        assert_eq!(pair(0, 0).check(), Err(Bad::Value("pair origin")));
        assert_eq!(pair(4, 0).check(), Err(Bad::Value("pair origin")));
        assert_eq!(pair(origin::DESKTOP, 1).check(), Err(Bad::Value("pair u")));

        let acct = GkMember::Account([1; 16]);
        pair(origin::VAULT_SEAT, 0).check_for(&acct).unwrap();
        pair(origin::CONNECTION, 7).check_for(&acct).unwrap();
        pair(origin::CONNECTION, 7)
            .check_for(&GkMember::Conn(7))
            .unwrap();
        assert!(pair(origin::CONNECTION, 7)
            .check_for(&GkMember::Conn(8))
            .is_err());
        assert!(pair(origin::DESKTOP, 0)
            .check_for(&GkMember::Conn(0))
            .is_err());

        header(HEADER_MAX_BYTES).check().unwrap();
        assert_eq!(
            header(HEADER_MAX_BYTES + 1).check(),
            Err(Bad::TooLarge("header body"))
        );
        assert_eq!(header(0).check(), Err(Bad::Length("header body")));
        let mut h = header(10);
        h.sig.push(0);
        assert_eq!(h.check(), Err(Bad::Length("header sig")));
        let link = WalkLinkIn {
            header: header(10),
            parent: Some(header(0)),
        };
        assert!(link.check().is_err());

        assert!(ListSeat {
            seat: seat(1),
            dh: vec![5; 32]
        }
        .check()
        .is_err());

        let leaf = LeafIn {
            b: 1,
            v: 1,
            pool: 2,
            seats: 1,
            list: [0; 32],
            via: None,
        };
        assert_eq!(leaf.check(), Err(Bad::Value("leaf pool")));
        assert!(LeafIn {
            pool: 0,
            seats: 63,
            ..leaf
        }
        .check()
        .is_err());

        let path = PathIn {
            index: 0,
            n: 1,
            siblings: vec![],
        };
        path.check().unwrap();
        assert!(PathIn {
            index: 1,
            ..path.clone()
        }
        .check()
        .is_err());
        assert!(PathIn {
            index: 0,
            n: u32::MAX,
            siblings: vec![[0; 32]; PATH_MAX_SIBLINGS + 1],
        }
        .check()
        .is_err());

        let keying = SeatKeying {
            b: 1,
            base_v: 5,
            s: 1,
            from: holder(1),
            welcome: None,
            row: Some(row(1)),
            ratchets: vec![
                RatchetStep {
                    e: 2,
                    from: 5,
                    to: 6,
                },
                RatchetStep {
                    e: 3,
                    from: 6,
                    to: 7,
                },
            ],
        };
        keying.check().unwrap();
        assert_eq!(keying.current_v(), 7);
        let both = SeatKeying {
            welcome: Some(vec![0; SEAT_WELCOME_BYTES]),
            ..keying.clone()
        };
        assert!(both.check().is_err());
        // A memory group's member that holds BK of base_v: the steps alone (plan 2b, 2d).
        let steps_alone = SeatKeying {
            row: None,
            ..keying.clone()
        };
        steps_alone.check().unwrap();
        assert_eq!(steps_alone.current_v(), 7);
        let mut broken_alone = steps_alone.clone();
        broken_alone.ratchets[0].from = 4;
        assert_eq!(broken_alone.check(), Err(Bad::Value("ratchet steps")));
        let nothing = SeatKeying {
            ratchets: vec![],
            ..steps_alone.clone()
        };
        assert_eq!(
            nothing.check(),
            Err(Bad::Value("seat keying: nothing to reach a key"))
        );
        let short = SeatKeying {
            row: Some(vec![0; 59]),
            ..keying.clone()
        };
        assert_eq!(short.check(), Err(Bad::Length("seat row")));
        let welcome_short = SeatKeying {
            welcome: Some(vec![0; SEAT_WELCOME_BYTES - 1]),
            row: None,
            ..keying.clone()
        };
        assert_eq!(welcome_short.check(), Err(Bad::Length("seat welcome")));
        let mut broken = keying.clone();
        broken.ratchets[1].from = 9;
        assert_eq!(broken.check(), Err(Bad::Value("ratchet steps")));

        assert!(SeedWelcomeIn {
            s: 1,
            from: holder(1),
            bytes: vec![0; SEAT_WELCOME_BYTES]
        }
        .check()
        .is_err());

        let sr = SelfRowIn {
            group: "c:g".into(),
            gen: [0; 16],
            seed: 1,
            sk: [0; 8],
            sx: [0; 8],
            kind: self_row::SELF_ROW,
            sealed: row(1),
        };
        sr.check().unwrap();
        assert!(SelfRowIn {
            sealed: vec![0; 61],
            ..sr.clone()
        }
        .check()
        .is_err());
        SelfRowIn {
            kind: self_row::HISTORY_ROW,
            sealed: vec![0; HISTORY_ROW_MAX_BYTES],
            ..sr.clone()
        }
        .check()
        .unwrap();
        assert_eq!(
            SelfRowIn {
                kind: self_row::HISTORY_ROW,
                sealed: vec![0; HISTORY_ROW_MAX_BYTES + 1],
                ..sr.clone()
            }
            .check(),
            Err(Bad::TooLarge("history row"))
        );
        assert!(SelfRowIn {
            kind: self_row::HISTORY_ROW,
            sealed: vec![0; AEAD_OVERHEAD],
            ..sr.clone()
        }
        .check()
        .is_err());
        assert_eq!(
            SelfRowIn {
                kind: 2,
                ..sr.clone()
            }
            .check(),
            Err(Bad::Value("self-row kind"))
        );
        assert!(SelfRowIn {
            group: String::new(),
            ..sr.clone()
        }
        .check()
        .is_err());
        assert!(SelfRowIn {
            group: "c".repeat(MAX_GROUP_BYTES + 1),
            ..sr
        }
        .check()
        .is_err());

        let w = WelcomeOut {
            seat: seat(1),
            b: 1,
            v: 1,
            s: 1,
            bytes: vec![0; SEED_WELCOME_BYTES],
        };
        assert_eq!(w.check(), Err(Bad::Length("welcome")));
        assert!(SealOut {
            b: 1,
            v: 1,
            bytes: vec![0; 61]
        }
        .check()
        .is_err());
        assert!(KrkOut {
            to: holder(1),
            from_kx: [0; 32],
            bytes: vec![0; SEAT_WELCOME_BYTES]
        }
        .check()
        .is_err());
        assert!(KrkIn {
            from: holder(1),
            bytes: vec![0; KRK_WELCOME_BYTES + 1]
        }
        .check()
        .is_err());
        assert!(SeedWelcomeOut {
            seat: seat(1),
            bytes: vec![]
        }
        .check()
        .is_err());

        let chain = GkChainKey {
            owner: [0; 16],
            chain: 1,
            index: 0,
            group: "c:g".into(),
            gen: [0; 16],
            epoch: 1,
            sealed: row(0),
        };
        chain.check().unwrap();
        assert_eq!(
            GkChainKey {
                index: 2,
                ..chain.clone()
            }
            .check(),
            Err(Bad::Value("chain index"))
        );
        assert!(GkChainKey {
            sealed: vec![0; 59],
            ..chain
        }
        .check()
        .is_err());

        Joiner {
            seat: conn_seat(4),
            ik: [0; 32],
            keys: pair(origin::CONNECTION, 4),
            returning: false,
        }
        .check()
        .unwrap();
        assert!(Joiner {
            seat: conn_seat(4),
            ik: [0; 32],
            keys: pair(origin::VAULT_SEAT, 0),
            returning: false,
        }
        .check()
        .is_err());
        assert!(Candidate {
            m: GkMember::Conn(1),
            ik: [0; 32],
            pair: pair(origin::CONNECTION, 2),
        }
        .check()
        .is_err());
        assert!(SeedSeat {
            seat: seat(1),
            ik: [0; 32],
            keys: pair(origin::CONNECTION, 0),
        }
        .check()
        .is_ok());

        check_detail(&"x".repeat(DETAIL_MAX_BYTES)).unwrap();
        assert!(check_detail(&"x".repeat(DETAIL_MAX_BYTES + 1)).is_err());
    }

    #[test]
    fn versions_and_lists_check_their_seats() {
        let v = |make| VersionOut {
            b: 1,
            v: 2,
            pool: pool::ACCOUNTS,
            make,
        };
        v(VersionMake::Ratchet { from_v: 1 }).check().unwrap();
        v(VersionMake::Keep {
            from_v: 1,
            mask: (1 << 62) - 1,
        })
        .check()
        .unwrap();
        assert!(v(VersionMake::Keep {
            from_v: 1,
            mask: 1 << 62
        })
        .check()
        .is_err());
        assert!(v(VersionMake::Keep { from_v: 1, mask: 0 }).check().is_err());
        let seats: Vec<GkSeat> = (1..=62).map(seat).collect();
        v(VersionMake::Seats(seats.clone())).check().unwrap();
        let mut over = seats.clone();
        over.push(seat(63));
        assert_eq!(
            v(VersionMake::Seats(over)).check(),
            Err(Bad::Count("version seats"))
        );
        assert!(v(VersionMake::Seats(vec![])).check().is_err());
        assert!(v(VersionMake::Seats(vec![seat(2), seat(1)]))
            .check()
            .is_err());
        assert!(v(VersionMake::Seats(vec![seat(1), seat(1)]))
            .check()
            .is_err());
        assert!(v(VersionMake::Seats(vec![conn_seat(1)])).check().is_err());
        assert!(VersionOut {
            pool: 2,
            ..v(VersionMake::Ratchet { from_v: 1 })
        }
        .check()
        .is_err());

        let ls = |s| ListSeat {
            seat: s,
            dh: vec![5; DH_PUBLIC_BYTES],
        };
        let list = ListIn {
            b: 1,
            v: 2,
            seats: (1..=62).map(|n| ls(seat(n))).collect(),
        };
        list.check().unwrap();
        let mut over = list.clone();
        over.seats.push(ls(seat(63)));
        assert!(over.check().is_err());
        let mut unsorted = list.clone();
        unsorted.seats.swap(0, 1);
        assert_eq!(unsorted.check(), Err(Bad::Value("list order")));
        assert!(ListIn {
            seats: vec![],
            ..list
        }
        .check()
        .is_err());
    }

    #[test]
    fn keep_masks_name_seats_in_list_order() {
        let list: Vec<GkSeat> = (1..=5).map(seat).collect();
        let mask = keep_mask(&list, |s| s.m == seat(2).m || s.m == seat(4).m).unwrap();
        assert_eq!(mask, 0b01010);
        let kept_seats: Vec<GkSeat> = kept(&list, mask).unwrap().copied().collect();
        assert_eq!(kept_seats, vec![seat(2), seat(4)]);
        assert_eq!(kept(&list, 0b11111).unwrap().count(), 5);
        assert!(kept(&list, 0b100000).is_err());
        assert!(kept(&list, 0).is_err());
        assert!(keep_mask(&list, |_| false).is_err());

        let full: Vec<GkSeat> = (1..=62).map(seat).collect();
        assert_eq!(keep_mask(&full, |_| true).unwrap(), (1 << 62) - 1);
        assert_eq!(kept(&full, (1 << 62) - 1).unwrap().count(), 62);
        assert_eq!(
            kept(&full, 1 << 61).unwrap().copied().collect::<Vec<_>>(),
            vec![seat(62)]
        );
        let over: Vec<GkSeat> = (1..=63).map(seat).collect();
        assert_eq!(keep_mask(&over, |_| true), Err(Bad::Count("keep list")));
        assert!(kept(&over, 1).is_err());
    }

    #[test]
    fn rows_pack_with_their_seeds() {
        let rows = [row(1), row(2), row(3)];
        let packed = RowsOut::pack(
            7,
            8,
            41,
            rows.iter().map(|r| &r[..]).zip([false, true, false]),
        )
        .unwrap();
        assert_eq!(packed.up, 0b010);
        assert_eq!(packed.rows.len(), 3 * ROW_BYTES);
        assert_eq!(packed.count(), 3);
        packed.check_for(3).unwrap();
        assert!(packed.check_for(4).is_err());
        let each: Vec<(Vec<u8>, u32)> = packed
            .each()
            .unwrap()
            .map(|(r, s)| (r.to_vec(), s))
            .collect();
        assert_eq!(each, vec![(row(1), 41), (row(2), 42), (row(3), 41)]);

        let short = [vec![0u8; 59]];
        assert!(RowsOut::pack(1, 1, 1, short.iter().map(|r| (&r[..], false))).is_err());
        let many: Vec<Vec<u8>> = (0..63).map(|_| row(0)).collect();
        assert_eq!(
            RowsOut::pack(1, 1, 1, many.iter().map(|r| (&r[..], false))),
            Err(Bad::Count("rows"))
        );
        assert!(RowsOut::pack(1, 1, 1, std::iter::empty()).is_err());
        let one = [row(0)];
        assert!(RowsOut::pack(1, 1, u32::MAX, one.iter().map(|r| (&r[..], true))).is_err());
        RowsOut::pack(1, 1, u32::MAX, one.iter().map(|r| (&r[..], false))).unwrap();

        let bad = RowsOut {
            b: 1,
            v: 1,
            s: 1,
            up: 0b1000,
            rows: [row(1), row(2), row(3)].concat(),
        };
        assert_eq!(bad.check(), Err(Bad::Value("rows up past the last row")));
        let ragged = RowsOut {
            up: 0,
            rows: vec![0; 61],
            ..bad
        };
        assert_eq!(ragged.check(), Err(Bad::Length("rows")));
        let full = RowsOut {
            b: 1,
            v: 1,
            s: 1,
            up: (1 << 62) - 1,
            rows: vec![0; 62 * ROW_BYTES],
        };
        full.check_for(62).unwrap();
        assert!(full.each().unwrap().all(|(_, s)| s == 2));
    }

    // ── Keyring stream ──

    #[test]
    fn keyring_stream_reads_back() {
        let base = vec![0xb0; 1000];
        let d1 = vec![0xd1; 119];
        let d2 = vec![0xd2; AEAD_OVERHEAD];
        let mut stream = Vec::new();
        for e in [&base, &d1, &d2] {
            put_keyring_entry(&mut stream, e).unwrap();
        }
        assert_eq!(&stream[..4], &1000u32.to_be_bytes());
        let read = read_keyring(&stream, 0, 2).unwrap();
        assert_eq!(read, vec![(0, &base[..]), (1, &d1[..]), (2, &d2[..])]);
        // From `have` on, deltas only.
        let mut deltas = Vec::new();
        put_keyring_entry(&mut deltas, &d1).unwrap();
        put_keyring_entry(&mut deltas, &d2).unwrap();
        assert_eq!(
            read_keyring(&deltas, 1, 2).unwrap(),
            vec![(1, &d1[..]), (2, &d2[..])]
        );
        assert!(read_keyring(&[], 3, 2).unwrap().is_empty());
        assert_eq!(read_keyring(&[], 2, 2), Err(Bad::Count("keyring entries")));
        assert_eq!(
            read_keyring(&stream, 0, 1),
            Err(Bad::Count("keyring entries"))
        );
        assert_eq!(
            read_keyring(&stream, 0, 3),
            Err(Bad::Count("keyring entries"))
        );
        assert_eq!(
            read_keyring(&deltas, 5, 4),
            Err(Bad::Count("keyring entries"))
        );
        assert_eq!(
            read_keyring(&stream, u32::MAX - 2, u32::MAX).unwrap().len(),
            3
        );
        assert!(read_keyring(&stream, 0, u32::MAX).is_err());

        let mut one = Vec::new();
        put_keyring_entry(&mut one, &base).unwrap();
        assert_eq!(commit_keyring(&one), Ok(&base[..]));
        assert_eq!(commit_keyring(&stream), Err(Bad::Count("commit keyring")));
        assert_eq!(commit_keyring(&[]), Err(Bad::Count("commit keyring")));
    }

    #[test]
    fn keyring_stream_refuses_hostile_input() {
        let mut good = Vec::new();
        put_keyring_entry(&mut good, &[7; 100]).unwrap();

        // A length past the cap: refused before anything is read or allocated.
        let mut huge = u32::MAX.to_be_bytes().to_vec();
        huge.extend([0; 64]);
        assert_eq!(
            read_keyring(&huge, 0, 0),
            Err(Bad::TooLarge("keyring entry"))
        );
        // A length past what is there.
        let mut cut = 200u32.to_be_bytes().to_vec();
        cut.extend([0; 100]);
        assert_eq!(
            read_keyring(&cut, 0, 0),
            Err(Bad::Truncated("keyring entry"))
        );
        // A partial length after a good entry.
        let mut tail = good.clone();
        tail.extend([0, 0, 1]);
        assert_eq!(
            read_keyring(&tail, 0, 1),
            Err(Bad::Truncated("keyring entry length"))
        );
        // Entries too short to be sealed.
        for n in [0u32, 1, AEAD_OVERHEAD as u32 - 1] {
            let mut short = n.to_be_bytes().to_vec();
            short.extend(vec![0; n as usize]);
            assert_eq!(
                read_keyring(&short, 0, 0),
                Err(Bad::Length("keyring entry"))
            );
        }
        // The stream past its cap.
        assert_eq!(
            keyring_entries(&vec![0; KEYRING_MAX_BYTES + 1]).err(),
            Some(Bad::TooLarge("keyring stream"))
        );
        // Writing past the cap.
        let mut full = Vec::new();
        put_keyring_entry(&mut full, &vec![0; KEYRING_MAX_BYTES - 4]).unwrap();
        assert_eq!(
            put_keyring_entry(&mut full, &[0; 32]),
            Err(Bad::TooLarge("keyring stream"))
        );
        assert_eq!(
            put_keyring_entry(&mut Vec::new(), &[0; 27]),
            Err(Bad::Length("keyring entry"))
        );
        // The iterator stops after its first error.
        let mut entries = keyring_entries(&cut).unwrap();
        assert!(entries.next().unwrap().is_err());
        assert!(entries.next().is_none());

        // Random bytes never panic.
        let mut rng = Rng(3);
        for _ in 0..2000 {
            let len = (rng.next() % 300) as usize;
            let mut bytes: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
            if len >= 4 && rng.next().is_multiple_of(2) {
                let n = (rng.next() % 300) as u32;
                bytes[..4].copy_from_slice(&n.to_be_bytes());
            }
            let _ = read_keyring(&bytes, 0, (rng.next() % 4) as u32);
            let _ = commit_keyring(&bytes);
            let _ = names_added_count(&bytes);
        }
    }

    // ── Parts ──

    impl Footprint for &str {
        const FLAT: bool = true;
        fn heap(&self) -> usize {
            0
        }
    }

    fn whole<K, T>(t: Took<K, T>) -> (K, Vec<T>) {
        match t.part {
            Part::Whole(k, parts) => (k, parts),
            _ => panic!("not whole"),
        }
    }

    #[test]
    fn parts_come_in_order() {
        let mut p: Parts<u64, &str> = Parts::new(Seq::Commit);
        assert_eq!(p.take(5, 0, false, "a", 100).part, Part::Held);
        assert_eq!(p.take(5, 1, false, "b", 100).part, Part::Held);
        assert!(p.held() >= 200);
        let t = p.take(5, 2, true, "c", 100);
        assert_eq!(t.dropped, None);
        assert_eq!(whole(t), (5, vec!["a", "b", "c"]));
        assert_eq!(p.held(), 0);
        // A one-part sequence.
        assert_eq!(whole(p.take(6, 0, true, "x", 10)), (6, vec!["x"]));
    }

    #[test]
    fn a_gap_drops_the_sequence() {
        let mut p: Parts<u64, u8> = Parts::new(Seq::In);
        let _ = p.take(1, 0, false, 0, 10);
        let t = p.take(1, 2, false, 2, 10);
        assert_eq!(t.dropped, Some((1, Lost::Gap)));
        assert_eq!(t.part, Part::NotTaken(NotTaken::Gap));
        assert_eq!(p.held(), 0);
        // The rest of it is ignored, not reported again.
        let t = p.take(1, 3, true, 3, 10);
        assert_eq!(t.dropped, None);
        assert_eq!(t.part, Part::NotTaken(NotTaken::NotStarted));
        // A part repeated is a gap too.
        let _ = p.take(1, 0, false, 0, 10);
        let _ = p.take(1, 1, false, 1, 10);
        let t = p.take(1, 1, false, 1, 10);
        assert_eq!(t.dropped, Some((1, Lost::Gap)));
        // Another sequence without its part 0.
        let _ = p.take(1, 0, false, 0, 10);
        let t = p.take(2, 1, true, 1, 10);
        assert_eq!(t.dropped, Some((1, Lost::Gap)));
        assert_eq!(t.part, Part::NotTaken(NotTaken::Gap));
        // A first part that is not part 0.
        let t = p.take(3, 1, true, 1, 10);
        assert_eq!(t.dropped, None);
        assert_eq!(t.part, Part::NotTaken(NotTaken::NotStarted));
    }

    #[test]
    fn a_new_part_zero_restarts() {
        let mut p: Parts<u64, u8> = Parts::new(Seq::Due);
        let _ = p.take(1, 0, false, 10, 10);
        let _ = p.take(1, 1, false, 11, 10);
        let t = p.take(2, 0, false, 20, 10);
        assert_eq!(t.dropped, Some((1, Lost::Restart)));
        assert_eq!(t.part, Part::Held);
        assert_eq!(whole(p.take(2, 1, true, 21, 10)), (2, vec![20, 21]));
        // The same key restarts too, and a one-part restart is whole at once.
        let _ = p.take(3, 0, false, 30, 10);
        let t = p.take(3, 0, true, 31, 10);
        assert_eq!(t.dropped, Some((3, Lost::Restart)));
        assert_eq!(whole(t), (3, vec![31]));
    }

    #[test]
    fn parts_stay_inside_their_cap() {
        let per = 100 + mem::size_of::<u32>();
        let mut p: Parts<(), u32> = Parts::with_cap(3 * per);
        let _ = p.take((), 0, false, 0, 100);
        let _ = p.take((), 1, false, 1, 100);
        assert_eq!(p.held(), 2 * per);
        let t = p.take((), 2, false, 2, 101);
        assert_eq!(t.dropped, Some(((), Lost::TooLarge)));
        assert_eq!(t.part, Part::NotTaken(NotTaken::TooLarge));
        assert_eq!(p.held(), 0);
        // Right at the cap is taken.
        let _ = p.take((), 0, false, 0, 100);
        let _ = p.take((), 1, false, 1, 100);
        assert_eq!(whole(p.take((), 2, true, 2, 100)).1, vec![0, 1, 2]);
        // A part 0 over the cap alone holds nothing.
        let t = p.take((), 0, false, 0, 3 * per);
        assert_eq!(t.part, Part::NotTaken(NotTaken::TooLarge));
        assert_eq!(p.held(), 0);
        // A frame over the piece cap.
        let mut q: Parts<(), u32> = Parts::new(Seq::Commit);
        let t = q.take((), 0, true, 0, PIECE_MAX_BYTES + 1);
        assert_eq!(t.part, Part::NotTaken(NotTaken::TooLarge));
        let _ = q.take((), 0, false, 0, 10);
        let t = q.take((), 1, true, 1, PIECE_MAX_BYTES + 1);
        assert_eq!(t.dropped, Some(((), Lost::TooLarge)));
        // Tiny parts are charged their size in memory: 12 MB of empty parts is not 0 B.
        let mut r: Parts<(), CommitPiece> = Parts::with_cap(1000 * mem::size_of::<CommitPiece>());
        let mut dropped = None;
        for i in 0..2000u16 {
            let t = r.take((), i, false, CommitPiece::default(), 0);
            if t.dropped.is_some() {
                dropped = Some(i);
                break;
            }
        }
        assert_eq!(dropped, Some(1000));
        assert_eq!(p.clear(), None);
    }

    #[test]
    fn part_numbers_do_not_wrap() {
        let mut p: Parts<(), ()> = Parts::with_cap(usize::MAX);
        for i in 0..u16::MAX {
            assert_eq!(p.take((), i, false, (), 0).part, Part::Held, "part {i}");
        }
        let t = p.take((), u16::MAX, false, (), 0);
        assert_eq!(t.dropped, Some(((), Lost::TooLarge)));
        let mut q: Parts<(), ()> = Parts::with_cap(usize::MAX);
        for i in 0..u16::MAX {
            let _ = q.take((), i, false, (), 0);
        }
        assert_eq!(whole(q.take((), u16::MAX, true, (), 0)).1.len(), 65536);
    }

    // ── Commits ──

    fn commit_msg(
        group: &str,
        due: u64,
        part: usize,
        last: bool,
        piece: &CommitPiece,
    ) -> ClientMessage {
        ClientMessage::EpochCommit {
            group: group.into(),
            due,
            part: part as u16,
            last,
            piece: piece.clone(),
        }
    }

    fn frame(group: &str, part: usize, last: bool, piece: &CommitPiece) -> Vec<u8> {
        postcard::to_allocvec(&commit_msg(group, 9, part, last, piece)).unwrap()
    }

    /// The frame at its largest: `due` at full width.
    fn frame_len(group: &str, part: usize, last: bool, piece: &CommitPiece) -> usize {
        encoded_len(&commit_msg(group, u64::MAX, part, last, piece))
    }

    /// Cuts `whole`, checks every frame against the piece cap, decodes each frame as the
    /// relay would and runs it through `Parts` and `join_commit`, and returns the frames'
    /// bytes and count. The joined commit holds no more heap than its decoded parts.
    fn send_and_take(group: &str, whole: &CommitPiece) -> (usize, usize) {
        let max = PIECE_MAX_BYTES - commit_frame_overhead(group);
        let pieces = cut_commit(whole.clone(), max).unwrap();
        let n = pieces.len();
        let mut parts: Parts<u64, CommitPiece> = Parts::new(Seq::Commit);
        let mut total = 0;
        let mut parts_heap = 0;
        let mut out = None;
        for (i, piece) in pieces.into_iter().enumerate() {
            assert!(encoded_len(&piece) <= max, "piece {i}");
            piece.check_items().unwrap();
            let last = i + 1 == n;
            let bytes = frame_len(group, i, last, &piece);
            assert!(bytes <= PIECE_MAX_BYTES, "frame {i}: {bytes}");
            total += bytes;
            let ClientMessage::EpochCommit {
                group: got_group,
                due,
                part,
                last: got_last,
                piece,
            } = postcard::from_bytes(&frame(group, i, last, &piece)).unwrap()
            else {
                panic!("not EpochCommit");
            };
            assert_eq!((&got_group[..], part, got_last), (group, i as u16, last));
            parts_heap += piece.heap();
            let t = parts.take(due, part, got_last, piece, bytes);
            assert_eq!(t.dropped, None);
            match t.part {
                Part::Held => assert!(!last),
                Part::Whole(due, got) => {
                    assert_eq!(due, 9);
                    out = Some(join_commit(got).unwrap());
                }
                Part::NotTaken(why) => panic!("part {i}: {why:?}"),
            }
        }
        let out = out.unwrap();
        assert!(
            out.heap() <= parts_heap,
            "joined {} B, parts {parts_heap} B",
            out.heap()
        );
        assert_eq!(&out, whole);
        (total, n)
    }

    #[test]
    fn tiny_items_are_charged_their_decoded_size() {
        // A keyholder's parts of `Ratchet` versions of zeros: 5 B each encoded, 48 B
        // decoded, and every part passes `check_items`.
        let ratchet = VersionOut {
            b: 0,
            v: 0,
            pool: pool::ACCOUNTS,
            make: VersionMake::Ratchet { from_v: 0 },
        };
        assert_eq!(encoded_len(&ratchet), 5);
        let mut piece = CommitPiece {
            versions: vec![ratchet; PIECE_MAX_BYTES / 5],
            ..CommitPiece::default()
        };
        while frame_len("c:g", 1, false, &piece) > PIECE_MAX_BYTES {
            piece.versions.pop();
        }
        piece.versions.shrink_to_fit();
        piece.check_items().unwrap();
        let bytes = frame_len("c:g", 1, false, &piece);
        let decoded = piece.versions.len() * mem::size_of::<VersionOut>();
        assert!(decoded > 8 * bytes, "{decoded} B from {bytes} B");
        let mut parts: Parts<u64, CommitPiece> = Parts::new(Seq::Commit);
        let mut held = 0usize;
        loop {
            let t = parts.take(1, held as u16, false, piece.clone(), bytes);
            match t.part {
                Part::Held => held += 1,
                Part::NotTaken(NotTaken::TooLarge) => break,
                other => panic!("{other:?}"),
            }
            assert!(held * decoded <= COMMIT_MAX_BYTES, "{held} parts held");
        }
        assert!(held * decoded <= COMMIT_MAX_BYTES, "{held} parts held");
        assert_eq!(parts.held(), 0);
        // The same items as drops: 1 B encoded, 8 B decoded.
        let drops = CommitPiece {
            drops: vec![0; 40_000],
            ..CommitPiece::default()
        };
        assert_eq!(drops.heap(), 40_000 * 8);
        let mut q: Parts<u64, CommitPiece> = Parts::with_cap(1_000_000);
        let t = q.take(1, 0, false, drops, 40_010);
        assert_eq!(t.part, Part::Held);
        assert!(q.held() >= 320_000, "{}", q.held());
    }

    #[test]
    fn a_full_rekey_at_100k_fits_the_commit_cap() {
        // A KeyholdersRemove at 100k seats: 1613 buckets × 62 seats, every bucket
        // re-versioned by rows during a seed roll (every row under s + 1), a seal per
        // version, a keyring base of 147 KB (part 10: 91 B a version) and a new KRK to
        // each remaining keyholder. Ids are random u64, so every varint is full width.
        let mut rng = Rng(100_000);
        let group = format!("c:{}", "g".repeat(62));
        let full = (1u64 << 62) - 1;
        let mut whole = CommitPiece {
            header: Some(header(1119)),
            ..CommitPiece::default()
        };
        for _ in 0..1613 {
            let (b, v) = (rng.next() | (1 << 63), rng.next() | (1 << 63));
            whole.versions.push(VersionOut {
                b,
                v,
                pool: pool::ACCOUNTS,
                make: VersionMake::Keep {
                    from_v: rng.next() | (1 << 63),
                    mask: full,
                },
            });
            let rows: Vec<u8> = (0..62 * ROW_BYTES).map(|_| rng.next() as u8).collect();
            whole.rows.push(RowsOut {
                b,
                v,
                s: 1 << 28,
                up: full,
                rows,
            });
            whole.seals.push(SealOut {
                b,
                v,
                bytes: rng.bytes::<60>().to_vec(),
            });
        }
        assert_eq!(whole.versions.len() * BUCKET_SEATS, 100_006);
        put_keyring_entry(&mut whole.keyring, &vec![0x6b; 1613 * 91]).unwrap();
        for n in 0..7 {
            whole.krk.push(KrkOut {
                to: holder(n),
                from_kx: [0xee; 32],
                bytes: vec![n; KRK_WELCOME_BYTES],
            });
        }
        whole.check_whole().unwrap();
        let (bytes, parts) = send_and_take(&group, &whole);
        eprintln!("full re-key at 100k: {bytes} B in {parts} parts");
        assert!(bytes <= COMMIT_MAX_BYTES, "{bytes}");
        assert!(bytes < 6_600_000, "about 6.4 MB, got {bytes}");
        assert!((110..=125).contains(&parts), "{parts}");
    }

    #[test]
    fn a_join_of_256_cuts_and_joins() {
        let mut rng = Rng(256);
        let mut whole = CommitPiece {
            header: Some(header(256 * 71 + 400)),
            ..CommitPiece::default()
        };
        let seats: Vec<GkSeat> = (0..256)
            .map(|_| GkSeat {
                m: GkMember::Account(rng.bytes()),
                sk: rng.bytes(),
                sx: rng.bytes(),
            })
            .collect();
        let mut sorted = seats.clone();
        sorted.sort();
        for (i, chunk) in sorted.chunks(62).enumerate() {
            let (b, v) = (rng.next(), rng.next());
            whole.versions.push(VersionOut {
                b,
                v,
                pool: pool::ACCOUNTS,
                make: VersionMake::Seats(chunk.to_vec()),
            });
            let rows: Vec<Vec<u8>> = chunk.iter().map(|_| row(i as u8)).collect();
            whole
                .rows
                .push(RowsOut::pack(b, v, 3, rows.iter().map(|r| (&r[..], false))).unwrap());
            whole.seals.push(SealOut {
                b,
                v,
                bytes: row(0xcc),
            });
            for s in chunk {
                whole.welcomes.push(WelcomeOut {
                    seat: *s,
                    b,
                    v,
                    s: 3,
                    bytes: vec![i as u8; SEAT_WELCOME_BYTES],
                });
            }
        }
        put_keyring_entry(&mut whole.keyring, &[0x6c; 119 + 5 * 91]).unwrap();
        // A gated Join in a stored group, the fattest kind: 256 names in the header and a
        // row beside each welcome (open choice 24). Part 10's 434 KB is the welcomes alone.
        let (bytes, parts) = send_and_take("c:g", &whole);
        eprintln!("Join of 256: {bytes} B in {parts} parts");
        assert!(
            (256 * SEAT_WELCOME_BYTES..520_000).contains(&bytes),
            "{bytes}"
        );
        assert!(parts <= 10, "{parts}");
    }

    #[test]
    fn a_due_of_every_exit_at_100k_fits_its_cap() {
        // An admin revokes access for every member of a non-gated 100k group: only a
        // gated exit batch closes at a count, so one opening due lists every exit.
        let mut rng = Rng(92_000);
        let exits: Vec<ExitIn> = (0..100_000u64)
            .map(|seq| ExitIn {
                seq,
                seat: GkSeat {
                    m: GkMember::Account(rng.bytes()),
                    sk: rng.bytes(),
                    sx: rng.bytes(),
                },
                b: rng.next() | (1 << 63),
            })
            .collect();
        let group = format!("c:{}", "g".repeat(62));
        let frame = |part: u16, last: bool, exits: Vec<ExitIn>| ServerMessage::EpochDue {
            group: group.clone(),
            due: u64::MAX,
            part,
            last,
            piece: Box::new(DuePiece {
                kind: due::EXITS,
                parent: [0xd0; 32],
                deadline_ms: 4000,
                keyring_at: (u32::MAX, u32::MAX),
                exits,
                exits_upto: u64::MAX,
                roll_due: true,
                ..DuePiece::default()
            }),
        };
        // Cut as the relay would: as many exits a part as fit 56 KiB, a 3-byte `exits`
        // length counted.
        let fixed = encoded_len(&frame(u16::MAX, false, vec![])) + 2;
        let mut chunks = vec![Vec::new()];
        let mut used = fixed;
        for e in &exits {
            let n = encoded_len(e);
            if used + n > PIECE_MAX_BYTES {
                chunks.push(Vec::new());
                used = fixed;
            }
            used += n;
            chunks.last_mut().unwrap().push(*e);
        }
        let count = chunks.len();
        let mut parts: Parts<u64, DuePiece> = Parts::new(Seq::Due);
        let (mut wire, mut out) = (0, None);
        for (i, chunk) in chunks.into_iter().enumerate() {
            let last = i + 1 == count;
            let bytes = postcard::to_allocvec(&frame(i as u16, last, chunk)).unwrap();
            let len = bytes.len();
            assert!(len <= PIECE_MAX_BYTES, "frame {i}: {len}");
            wire += len;
            let ServerMessage::EpochDue {
                due,
                part,
                last: got_last,
                piece,
                ..
            } = postcard::from_bytes(&bytes).unwrap()
            else {
                panic!("not EpochDue");
            };
            let t = parts.take(due, part, got_last, *piece, len);
            assert_eq!(t.dropped, None);
            match t.part {
                Part::Held => assert!(!last),
                Part::Whole(_, got) => {
                    out = Some(got.into_iter().flat_map(|p| p.exits).collect::<Vec<_>>())
                }
                Part::NotTaken(why) => panic!("part {i} of {count}: {why:?}"),
            }
        }
        eprintln!("due of 100k exits: {wire} B in {count} parts");
        assert!(wire > 4 * 1024 * 1024, "{wire}");
        assert_eq!(out, Some(exits));
    }

    #[test]
    fn commits_refuse_misplaced_headers_and_counts() {
        let mut keyring = Vec::new();
        put_keyring_entry(&mut keyring, &[1; 40]).unwrap();
        let base = CommitPiece {
            header: Some(header(100)),
            keyring: keyring.clone(),
            ..CommitPiece::default()
        };
        join_commit(vec![base.clone()]).unwrap();
        assert!(join_commit(vec![]).is_err());
        let no_header = CommitPiece {
            header: None,
            ..base.clone()
        };
        assert_eq!(
            join_commit(vec![no_header.clone()]),
            Err(Bad::Value("commit header"))
        );
        assert_eq!(
            join_commit(vec![base.clone(), base.clone()]),
            Err(Bad::Value("header after part 0"))
        );
        // The keyring split over two parts is one entry.
        let (a, b) = keyring.split_at(10);
        let p0 = CommitPiece {
            keyring: a.to_vec(),
            ..base.clone()
        };
        let p1 = CommitPiece {
            header: None,
            keyring: b.to_vec(),
            ..CommitPiece::default()
        };
        assert_eq!(join_commit(vec![p0, p1.clone()]).unwrap(), base);
        // No keyring, or two entries.
        assert!(join_commit(vec![CommitPiece {
            keyring: vec![],
            ..base.clone()
        }])
        .is_err());
        let mut two = keyring.clone();
        put_keyring_entry(&mut two, &[2; 40]).unwrap();
        assert!(join_commit(vec![CommitPiece {
            keyring: two,
            ..base.clone()
        }])
        .is_err());
        // Nine KRK welcomes; 257 welcomes.
        let krk = KrkOut {
            to: holder(1),
            from_kx: [0; 32],
            bytes: vec![0; KRK_WELCOME_BYTES],
        };
        assert_eq!(
            join_commit(vec![CommitPiece {
                krk: vec![krk; MAX_KEYHOLDERS + 1],
                ..base.clone()
            }]),
            Err(Bad::Count("commit keyring welcomes"))
        );
        let welcome = WelcomeOut {
            seat: seat(1),
            b: 1,
            v: 1,
            s: 1,
            bytes: vec![0; SEAT_WELCOME_BYTES],
        };
        assert_eq!(
            join_commit(vec![CommitPiece {
                welcomes: vec![welcome; MAX_JOINERS + 1],
                ..base.clone()
            }]),
            Err(Bad::Count("commit welcomes"))
        );
        // An item of a wrong length.
        assert!(join_commit(vec![CommitPiece {
            seals: vec![SealOut {
                b: 1,
                v: 1,
                bytes: vec![0; 59]
            }],
            ..base.clone()
        }])
        .is_err());

        // Cutting: no header, a header that cannot fit, a tiny budget.
        assert!(cut_commit(no_header, 1000).is_err());
        assert_eq!(
            cut_commit(base.clone(), 100),
            Err(Bad::TooLarge("commit header"))
        );
        let pieces = cut_commit(base.clone(), 200).unwrap();
        assert!(pieces.len() > 1);
        assert!(pieces.iter().all(|p| encoded_len(p) <= 200));
        assert_eq!(join_commit(pieces).unwrap(), base);
        let fat = CommitPiece {
            welcomes: vec![WelcomeOut {
                seat: seat(1),
                b: 1,
                v: 1,
                s: 1,
                bytes: vec![0; SEAT_WELCOME_BYTES],
            }],
            ..base.clone()
        };
        assert_eq!(cut_commit(fat, 1000), Err(Bad::TooLarge("commit item")));
    }
}
