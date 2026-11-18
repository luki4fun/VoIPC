//! The commit validator (docs/GROUP-KEY.md §9, plan 2c): what the relay
//! checks before it takes a commit, and what a keyholder runs on its own
//! commit before it sends it. Pure: a `GroupView` of what the relay holds
//! (its head, its seat lists, the due it asked for, each seat's seed as of
//! the ask) and a reassembled `Commit` in, the new state (`Applied`) or the
//! first rule broken (`Bad`) out.
//!
//! The relay cannot open anything a commit carries. What it checks is the
//! shape around the secrets: who signed, that the header follows its head,
//! that every seat list it holds rebuilds the signed bucket root, that every
//! seat it seated or let go is where the due said, and that each secret is
//! there exactly once at its exact size. What only a keyholder can check
//! (the keyring's contents, `made` ages, welcomes from the old pair) is
//! C3c's, through `take_keyring` and `check_carried`.
//!
//! Rules, by the numbers the relay reports (`EpochStale{CHECK}`):
//! 1 form, 2 signer, 3 kind, 4 chain, 5 time, 6 gated, 7 keyholders,
//! 8 versions, 9 root, 10 seats, 11 names, 12 seeds, 13 material,
//! 14 keyring, 15 caps, 16 version ids.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use super::ctx::{Group, GroupKind, MemberId, SeatRef, Version};
use super::header::{
    names_hash, Added, AddedSeat, HeaderV1, Keyholder, Kind, Removed, SignedHeader,
};
use super::keyring::{keyring_hash_next, keyring_hash_start};
use super::keys::{tag, Endorsement, Origin, SeatPublic};
use super::merkle::{list_digest, seat_record, Leaf, Pool, Via, BUCKET_SEATS};
use super::rules::{
    check_form, check_gated, check_keyholder_change, check_link, check_roll, check_signer,
    check_time, check_versions, check_voice_keyholders, replaced_entry, row_seed, Refusal, RowSeed,
    SeedRolls,
};
use super::timers::{COMMIT_MAX_BYTES, JOIN_BATCH_MAX, MAX_GUEST_KEYHOLDERS, REFRESH_SLICE};
use super::tree::BucketTree;
use super::welcome::{SEAT_WELCOME_BYTES, SMALL_WELCOME_BYTES};
use super::{REGENESIS_WAIT, ROW_BYTES};

/// The relay holds no pins: a signer is checked against the set alone.
const NO_PINS: &dyn Fn(&[u8; 16]) -> Option<[u8; 32]> = &|_| None;

// ── What the relay asked for ──────────────────────────────────────────────

/// The commit dues of §9 `EpochDue`. A seed-welcome page is no commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DueKind {
    Join,
    Exits,
    Refresh,
    Promote,
    Remove,
    Replace,
    Genesis,
    Regenesis,
    /// The opening that turns `gated` on, once every connection seat and
    /// guest keyholder is gone (plan 2d).
    Gate,
}

impl DueKind {
    /// The header kind a commit for this due carries (rule 3).
    pub fn header_kind(self) -> Kind {
        match self {
            DueKind::Join => Kind::Join,
            DueKind::Exits | DueKind::Refresh | DueKind::Gate => Kind::Fresh,
            DueKind::Promote => Kind::KeyholdersAdd,
            DueKind::Remove => Kind::KeyholdersRemove,
            DueKind::Replace => Kind::KeyholdersReplace,
            DueKind::Genesis => Kind::Genesis,
            DueKind::Regenesis => Kind::Regenesis,
        }
    }

    /// The wire code (plan 1a `DUE_*`); 8 is the seed-welcome page.
    pub fn code(self) -> u8 {
        match self {
            DueKind::Join => 0,
            DueKind::Exits => 1,
            DueKind::Refresh => 2,
            DueKind::Promote => 3,
            DueKind::Remove => 4,
            DueKind::Replace => 5,
            DueKind::Genesis => 6,
            DueKind::Regenesis => 7,
            DueKind::Gate => 9,
        }
    }

    pub fn from_code(c: u8) -> Option<DueKind> {
        [
            DueKind::Join,
            DueKind::Exits,
            DueKind::Refresh,
            DueKind::Promote,
            DueKind::Remove,
            DueKind::Replace,
            DueKind::Genesis,
            DueKind::Regenesis,
            DueKind::Gate,
        ]
        .into_iter()
        .find(|d| d.code() == c)
    }
}

/// A keyholder entry as the relay names it: its member id and raw `KX`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HolderRef {
    pub m: MemberId,
    pub kx: [u8; 32],
}

impl HolderRef {
    pub fn of(k: &Keyholder) -> HolderRef {
        HolderRef { m: k.m, kx: k.kx }
    }
}

/// A pair with its endorsement (§11.8): a seat's, or a keyholder's.
#[derive(Clone)]
pub struct Pair {
    pub keys: SeatPublic,
    pub endorsement: Endorsement,
}

impl Pair {
    /// The raw 32 bytes of its X25519 key, as a header entry carries them.
    pub fn kx(&self) -> [u8; 32] {
        self.keys.dh_bytes()[1..].try_into().expect("33 bytes")
    }

    /// The keyholder entry this pair makes for `m` with identity `ik`, or
    /// `None` for a pair no keyholder of that kind of group may hold. The
    /// entry's `u` comes from the endorsement, never from a relay field: in
    /// voice every keyholder is a connection keyholder whose pair names
    /// `Conn(u)`; in text a desktop pair names the account itself.
    pub fn entry(&self, kind: GroupKind, m: MemberId, ik: [u8; 32]) -> Option<Keyholder> {
        let e = &self.endorsement;
        let u = match (kind, e.origin, e.m) {
            (GroupKind::Voice, Origin::Connection, MemberId::Conn(u)) => Some(u),
            (GroupKind::Text, Origin::Connection, MemberId::Conn(_)) => None,
            (GroupKind::Text, Origin::Desktop, a @ MemberId::Account(_)) if a == m => None,
            _ => return None,
        };
        Some(Keyholder {
            m,
            u,
            origin: e.origin as u8,
            n: e.n,
            ik,
            kx: self.kx(),
            tag_kk: self.keys.tag_kem(),
        })
    }
}

/// A seat the due asks to be seated: its keys, its endorsement and the `IK`
/// that made it. `returning`: the relay holds a self-row or row under the
/// current seed for it, so it gets a row, not a welcome.
#[derive(Clone)]
pub struct Joiner {
    pub seat: SeatRef,
    pub ik: [u8; 32],
    pub keys: SeatPublic,
    pub endorsement: Endorsement,
    pub returning: bool,
}

impl Joiner {
    /// Its entry in a gated header's `added`.
    pub fn added(&self) -> AddedSeat {
        AddedSeat {
            m: self.seat.m,
            ik: self.ik,
            tag_sk: self.seat.tag_sk,
            tag_sx: self.seat.tag_sx,
            n: self.endorsement.n,
            made: self.endorsement.made,
        }
    }
}

/// One exit of a closed batch (§5.4): its sequence number, its seat, the
/// bucket it sat in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Exit {
    pub seq: u64,
    pub seat: SeatRef,
    pub b: u64,
}

/// A keyholder the relay proposes (`Promote`), or the volunteer it asked
/// for a Genesis or Regenesis: member id, `IK` and keyholder pair.
#[derive(Clone)]
pub struct Candidate {
    pub m: MemberId,
    pub ik: [u8; 32],
    pub pair: Pair,
}

/// What `KeyholdReplace` asked: the old pair's `tag(KX)` and the new pair.
#[derive(Clone)]
pub struct ReplaceAsk {
    pub old: [u8; 8],
    pub pair: Pair,
}

/// One commit due, as the relay asked it (§9 `EpochDue`).
#[derive(Clone)]
pub struct Due {
    pub kind: DueKind,
    /// At most 256. A Genesis or Regenesis seats the volunteer's own seat
    /// this way: its one bucket (§5.1).
    pub joiners: Vec<Joiner>,
    /// The closed exit batch an opening due carries. A Join deals with
    /// none, and neither does a Genesis: a new generation seats nobody of
    /// the old one, so its header names no exit and the validator only
    /// reports the batch done (`Applied.exits_done`).
    pub exits: Vec<Exit>,
    /// The last `seq` of that batch: what the header's `exits_upto` becomes.
    pub exits_upto: u64,
    pub candidate: Option<Candidate>,
    pub remove: Option<HolderRef>,
    pub replace: Option<ReplaceAsk>,
    /// The `gated` the header must carry.
    pub gated: bool,
    pub volunteer: Option<Candidate>,
}

impl Due {
    /// A due of `kind` with nothing else in it.
    pub fn of(kind: DueKind, gated: bool) -> Due {
        Due {
            kind,
            joiners: vec![],
            exits: vec![],
            exits_upto: 0,
            candidate: None,
            remove: None,
            replace: None,
            gated,
            volunteer: None,
        }
    }
}

/// One current bucket version with its seat list, as the relay keeps it:
/// the seats sorted by their seat record (`list_order`), each once.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listed {
    pub leaf: Leaf,
    pub seats: Vec<SeatRef>,
}

impl Listed {
    pub fn version(&self) -> Version {
        Version {
            b: self.leaf.b,
            v: self.leaf.v,
        }
    }
}

/// The order every seat list is kept, packed and masked in: by seat record
/// (§11.5), each seat once. Rows of a version go in this order, and bit `i`
/// of a `Keep` mask names its `i`-th seat.
pub fn list_order(seats: &mut Vec<SeatRef>) {
    seats.sort_by_key(seat_record);
    seats.dedup();
}

/// Whether `bits` sets a bit at `n` or above: past a list of `n` seats.
fn bits_beyond(bits: u64, n: usize) -> bool {
    u32::try_from(n)
        .ok()
        .and_then(|n| bits.checked_shr(n))
        .is_some_and(|rest| rest != 0)
}

fn in_list_order(seats: &[SeatRef]) -> bool {
    seats
        .windows(2)
        .all(|w| seat_record(&w[0]) < seat_record(&w[1]))
}

/// The relay's head, and the keyholder header its `kh` names (the head
/// itself when it sets keyholders).
#[derive(Clone, Copy)]
pub struct HeadView<'a> {
    pub head: &'a SignedHeader,
    pub kh: &'a SignedHeader,
}

/// What the relay holds of a group when a commit's last part comes.
pub struct GroupView<'a> {
    pub kind: GroupKind,
    pub id: &'a str,
    /// A `c:` group on a relay with accounts: kept in its database.
    pub stored: bool,
    /// `None` for a group that has no generation yet.
    pub head: Option<HeadView<'a>>,
    /// The head's versions with their lists, sorted by `b`.
    pub leaves: &'a [Listed],
    /// The newest seed each seated seat holds, as of when the due was
    /// asked (a seed welcome stored meanwhile does not fail the commit).
    pub held: &'a dyn Fn(&SeatRef) -> Option<u32>,
    pub due: &'a Due,
    /// The keyholder entry of the connection that sent the commit.
    pub by: HolderRef,
    /// The seed rolls as of the head.
    pub rolls: SeedRolls,
    /// Every generation this group had (a Genesis reuses none).
    pub known_gens: &'a [[u8; 16]],
    /// Whether a version id was used in the head's generation (§4.1).
    pub used_v: &'a dyn Fn(u64) -> bool,
    /// The relay's clock, unix seconds.
    pub now: u64,
    /// Voice: the user ids in the room.
    pub roster: &'a [u32],
    /// Since when no keyholder has been online (a Regenesis waits an hour).
    pub no_keyholder_since: Option<u64>,
}

// ── What a keyholder sends ────────────────────────────────────────────────

/// How a commit makes a bucket version (plan 1a `VersionMake`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Make {
    /// A promotion's ratchet of the bucket's current version `from_v`, with
    /// its seats (§3.5).
    Ratchet { from_v: u64 },
    /// A re-version by rows: the seats of `(b, from_v)` whose bit is set, in
    /// list order.
    Keep { from_v: u64, mask: u64 },
    /// A new bucket: a Join's, or a merge or repack of other buckets' seats.
    /// In list order.
    Seats(Vec<SeatRef>),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionOut {
    pub b: u64,
    pub v: u64,
    pub pool: Pool,
    pub make: Make,
}

/// A seat welcome to a new seat, seating it in `(b, v)`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WelcomeOut {
    pub seat: SeatRef,
    pub b: u64,
    pub v: u64,
    pub s: u32,
    pub bytes: Vec<u8>,
}

/// Every row of one version, packed: 60 bytes per seat in list order; bit
/// `i` of `up` set puts row `i` under `s + 1` (a seed roll runs).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RowsOut {
    pub b: u64,
    pub v: u64,
    pub s: u32,
    pub up: u64,
    pub rows: Vec<u8>,
}

impl RowsOut {
    /// Row `i`, and the seed it is under.
    pub fn row(&self, i: usize) -> Option<(&[u8], u64)> {
        let r = self.rows.get(i * ROW_BYTES..(i + 1) * ROW_BYTES)?;
        Some((r, u64::from(self.s) + ((self.up >> i) & 1)))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealOut {
    pub b: u64,
    pub v: u64,
    pub bytes: Vec<u8>,
}

/// A seed welcome inside a commit: for a seat whose seed the new floor
/// drops, before any row to it (rule 13).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeedWelcomeOut {
    pub seat: SeatRef,
    pub bytes: Vec<u8>,
}

/// A `KRK` welcome to one keyholder of the new set; `from_kx` names its
/// maker, the old pair on a Replace.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KrkOut {
    pub to: HolderRef,
    pub from_kx: [u8; 32],
    pub bytes: Vec<u8>,
}

/// A joiner the keyholder left out, and why (plan 1a `JoinRefused` codes).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refused {
    pub seat: SeatRef,
    pub why: u8,
}

/// A commit, reassembled from its parts. `keyring` is the one sealed part
/// it uploads: the base at an opening, the delta at a Join (the wire frames
/// it with its length; that framing is the wire's).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commit {
    pub body: Vec<u8>,
    pub sig: Vec<u8>,
    pub versions: Vec<VersionOut>,
    pub drops: Vec<u64>,
    pub welcomes: Vec<WelcomeOut>,
    pub rows: Vec<RowsOut>,
    pub seals: Vec<SealOut>,
    pub seed_welcomes: Vec<SeedWelcomeOut>,
    pub keyring: Vec<u8>,
    pub krk: Vec<KrkOut>,
    pub refused: Vec<Refused>,
}

/// Bytes of a `SeatRef` on the wire, at most.
const SEAT_BYTES: usize = 17 + 8 + 8;

impl Commit {
    /// What the commit weighs: every byte field, and the fixed fields around
    /// each, at their largest. What the 12 MB cap is counted on.
    pub fn bytes(&self) -> usize {
        let versions: usize = self
            .versions
            .iter()
            .map(|v| {
                26 + match &v.make {
                    Make::Seats(s) => s.len() * SEAT_BYTES,
                    _ => 0,
                }
            })
            .sum();
        self.body.len()
            + self.sig.len()
            + versions
            + self.drops.len() * 10
            + self
                .welcomes
                .iter()
                .map(|w| SEAT_BYTES + 25 + w.bytes.len())
                .sum::<usize>()
            + self.rows.iter().map(|r| 40 + r.rows.len()).sum::<usize>()
            + self.seals.iter().map(|s| 20 + s.bytes.len()).sum::<usize>()
            + self
                .seed_welcomes
                .iter()
                .map(|w| SEAT_BYTES + 3 + w.bytes.len())
                .sum::<usize>()
            + self.keyring.len()
            + self
                .krk
                .iter()
                .map(|k| 17 + 64 + 3 + k.bytes.len())
                .sum::<usize>()
            + self.refused.len() * (SEAT_BYTES + 1)
    }
}

// ── What the validator says ───────────────────────────────────────────────

/// The first rule a commit broke, with what the relay tells the keyholder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bad {
    /// 1 to 16, as the module doc lists them.
    pub rule: u8,
    pub detail: String,
}

impl std::fmt::Display for Bad {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "rule {}: {}", self.rule, self.detail)
    }
}

impl std::error::Error for Bad {}

fn bad<T>(rule: u8, detail: &str) -> Result<T, Bad> {
    Err(Bad {
        rule,
        detail: detail.to_string(),
    })
}

fn refused(rule: u8, r: Refusal) -> Bad {
    Bad {
        rule,
        detail: format!("{r:?}"),
    }
}

/// A commit the relay takes: the new state, for its store and its pushes.
pub struct Applied {
    pub header: SignedHeader,
    /// Every current leaf after the commit, sorted by `b`.
    pub leaves: Vec<Leaf>,
    /// The tree over them, built once: the snapshot cuts members' paths
    /// from it.
    pub tree: BucketTree,
    /// The versions this commit made, with their lists.
    pub made: Vec<Listed>,
    /// The versions no longer current: re-versioned, dropped, or every one
    /// at a Genesis or Regenesis.
    pub gone: Vec<Version>,
    /// The seats seated, and the version each sits in.
    pub seated: Vec<(SeatRef, Version)>,
    pub refused: Vec<Refused>,
    /// The exits dealt with, by `seq` (at a Genesis, the batch it closed).
    pub exits_done: Vec<u64>,
    /// Their seats.
    pub removed: Vec<SeatRef>,
    /// The new keyholder set, when the header sets one.
    pub keyholders: Option<Vec<Keyholder>>,
    pub rolls: SeedRolls,
    /// Seats whose held seed this commit moved: the new seats and those
    /// given a seed welcome in it.
    pub held: Vec<(SeatRef, u32)>,
}

// ── The validator ─────────────────────────────────────────────────────────

/// Rule 2's refusals; the keyholder change `check_signer` also runs is
/// rule 7's, but for the two clauses about the signer itself.
fn signer_refusal(r: Refusal) -> Bad {
    match r {
        Refusal::KeyholderChange(
            "a keyholder never signs its own removal"
            | "a KeyholdersReplace swaps its signer's own entry",
        ) => refused(2, r),
        Refusal::KeyholderChange(_) => refused(7, r),
        r => refused(2, r),
    }
}

/// What `check_link` refuses, by the rule it belongs to here.
fn link_refusal(r: Refusal) -> Bad {
    match r {
        Refusal::Names => refused(11, r),
        Refusal::GatedChanged => refused(6, r),
        Refusal::Chain("the seed does not follow") => refused(12, r),
        r => refused(4, r),
    }
}

/// Takes `commit` against what the relay holds, or names the first rule
/// it breaks. See the module doc for what each rule is.
pub fn validate(view: &GroupView, c: &Commit) -> Result<Applied, Bad> {
    let due = view.due;

    // 15: what costs nothing to count goes first.
    if due.joiners.len() > JOIN_BATCH_MAX
        || c.refused.len() > JOIN_BATCH_MAX
        || c.welcomes.len() > JOIN_BATCH_MAX
    {
        return bad(15, "more than 256 joiners");
    }
    if c.bytes() > COMMIT_MAX_BYTES {
        return bad(15, "over 12 MB");
    }

    // 1: form.
    let sh = check_form(&c.body, &c.sig, view.kind, view.id).map_err(|r| refused(1, r))?;
    if view.kind == GroupKind::Voice && !view.id.starts_with("r:") {
        return bad(1, "a voice group's id is an r: id");
    }
    let h = sh.header();
    let g = Group::new(view.kind, view.id, h.gen).map_err(|_| Bad {
        rule: 1,
        detail: "the group id has no valid shape".into(),
    })?;

    // 3: the kind asked for.
    if h.kind != due.kind.header_kind() {
        return bad(3, "not the kind of commit the relay asked for");
    }
    let anew = h.kind.starts_anew();
    let genesis = h.kind == Kind::Genesis;
    let join_like = h.kind == Kind::Join || anew;

    // 4: the chain.
    let head = if genesis {
        None
    } else {
        match view.head {
            Some(hv) => Some(hv),
            None => return bad(4, "no head to follow"),
        }
    };
    let ph = head.map(|hv| hv.head.header());
    if genesis {
        let same_gen = view.head.is_some_and(|hv| hv.head.header().gen == h.gen);
        if same_gen || view.known_gens.contains(&h.gen) {
            return bad(4, "a Genesis starts a generation this group never had");
        }
    } else if let Some(hv) = head {
        check_link(hv.head, &sh).map_err(link_refusal)?;
        if h.kind == Kind::Regenesis
            && !view
                .no_keyholder_since
                .is_some_and(|t| view.now >= t.saturating_add(REGENESIS_WAIT))
        {
            return bad(4, "a Regenesis only after an hour with no keyholder online");
        }
    }

    // 2: the signer.
    let old_set: &[Keyholder] = head.map_or(&[], |hv| &hv.kh.header().keyholders[..]);
    let by = view.by;
    if anew {
        let Some(vol) = &due.volunteer else {
            return bad(2, "no volunteer was asked");
        };
        let ik = check_signer(&sh, None, NO_PINS).map_err(signer_refusal)?;
        if h.signer != vol.m || ik != vol.ik {
            return bad(2, "not signed by the volunteer asked");
        }
        if by
            != (HolderRef {
                m: vol.m,
                kx: vol.pair.kx(),
            })
        {
            return bad(2, "not sent by the volunteer asked");
        }
    } else if let Some(hv) = head {
        check_signer(&sh, Some(hv.kh), NO_PINS).map_err(signer_refusal)?;
        let entry = old_set.iter().find(|k| HolderRef::of(k) == by);
        if !entry.is_some_and(|e| h.signer == by.m && sh.verify(&e.ik)) {
            return bad(2, "not signed by the keyholder that sent it");
        }
        let stays = h.keyholders.iter().any(|k| HolderRef::of(k) == by);
        if h.kind == Kind::KeyholdersRemove && !stays {
            return bad(2, "a KeyholdersRemove's signer stays in the set");
        }
        if h.kind == Kind::KeyholdersReplace && stays {
            return bad(2, "a KeyholdersReplace swaps its signer's own entry");
        }
    }

    // 5: time.
    check_time(h, view.now).map_err(|r| refused(5, r))?;
    if ph.is_some_and(|p| h.time < p.time) {
        return bad(5, "earlier than its parent");
    }

    // 6: gated, as the header says it.
    check_gated(h, ph.map(|p| p.gated)).map_err(|r| match r {
        Refusal::GuestKeyholder => refused(7, r),
        r => refused(6, r),
    })?;
    if h.gated != due.gated {
        return bad(6, "not the gated the relay asked for");
    }

    // 7: keyholders.
    check_keyholders(view, h, old_set)?;

    // 8: versions.
    let before: &[Listed] = if anew { &[] } else { view.leaves };
    let by_b: HashMap<u64, &Listed> = before.iter().map(|l| (l.leaf.b, l)).collect();
    let in_use: HashSet<u64> = view.leaves.iter().map(|l| l.leaf.b).collect();
    let mut touched: HashSet<u64> = HashSet::new();
    for &b in &c.drops {
        if !by_b.contains_key(&b) || !touched.insert(b) {
            return bad(8, "a drop of a bucket not current, or twice");
        }
    }
    let mut made: Vec<Listed> = Vec::with_capacity(c.versions.len());
    for vo in &c.versions {
        if !touched.insert(vo.b) {
            return bad(8, "one bucket twice");
        }
        made.push(make_version(&g, &by_b, &in_use, vo)?);
    }
    let mut after: Vec<(Leaf, &[SeatRef])> = before
        .iter()
        .filter(|l| !touched.contains(&l.leaf.b))
        .map(|l| (l.leaf, &l.seats[..]))
        .chain(made.iter().map(|l| (l.leaf, &l.seats[..])))
        .collect();
    after.sort_by_key(|(l, _)| l.b);
    let after_leaves: Vec<Leaf> = after.iter().map(|(l, _)| *l).collect();
    let checked_before: Vec<Leaf> = if genesis {
        vec![]
    } else {
        view.leaves.iter().map(|l| l.leaf).collect()
    };
    check_versions(h.kind, &checked_before, &after_leaves).map_err(|r| refused(8, r))?;
    // The exits the header deals with; a Genesis closes the batch without
    // naming it (`Due.exits`).
    let done: &[Exit] = if h.kind == Kind::Join {
        &[]
    } else {
        &due.exits
    };
    let exits: &[Exit] = if genesis { &[] } else { done };
    let exit_seats: HashSet<SeatRef> = exits.iter().map(|e| e.seat).collect();
    match h.kind {
        // New buckets only: `check_versions` refuses a Join's drop or
        // re-version, and a start has no current version to drop or keep.
        Kind::Join | Kind::Genesis | Kind::Regenesis => {}
        Kind::KeyholdersAdd => {
            let exit_bs: HashSet<u64> = before
                .iter()
                .filter(|l| l.seats.iter().any(|s| exit_seats.contains(s)))
                .map(|l| l.leaf.b)
                .collect();
            for vo in &c.versions {
                match vo.make {
                    Make::Ratchet { .. } => {}
                    Make::Keep { .. } if exit_bs.contains(&vo.b) => {}
                    _ => return bad(8, "a KeyholdersAdd re-versions by rows only for exits"),
                }
            }
            if c.drops.iter().any(|b| !exit_bs.contains(b)) {
                return bad(8, "a KeyholdersAdd drops only buckets its exits empty");
            }
        }
        Kind::KeyholdersRemove => {}
        Kind::Fresh | Kind::KeyholdersReplace => {
            let by_rows = made.iter().filter(|m| m.leaf.via == Via::Row).count();
            if due.kind == DueKind::Refresh && by_rows < after_leaves.len().div_ceil(REFRESH_SLICE)
            {
                return bad(
                    8,
                    "a refresh re-keys at least a twelfth of the buckets by rows",
                );
            }
        }
    }

    // 6, again: a gated group has no connections pool.
    if h.gated && after_leaves.iter().any(|l| l.pool == Pool::Conns) {
        return bad(6, "a gated group keeps a connections-pool bucket");
    }

    // 16: version ids.
    let mut new_v = HashSet::new();
    for m in &made {
        if (view.used_v)(m.leaf.v) || !new_v.insert(m.leaf.v) {
            return bad(16, "a version id used before in this generation");
        }
    }

    // 10: seats, as a whole.
    let touched_seats: HashSet<SeatRef> = before
        .iter()
        .filter(|l| touched.contains(&l.leaf.b))
        .flat_map(|l| l.seats.iter().copied())
        .collect();
    let joiners: HashMap<SeatRef, &Joiner> = due.joiners.iter().map(|j| (j.seat, j)).collect();
    let mut refused_seats = HashSet::new();
    for r in &c.refused {
        if !joiners.contains_key(&r.seat) || !refused_seats.insert(r.seat) {
            return bad(10, "a refusal of a seat the due did not ask, or twice");
        }
    }
    let mut placed: HashMap<SeatRef, Version> = HashMap::new();
    for m in &made {
        for s in &m.seats {
            if placed.insert(*s, m.version()).is_some() {
                return bad(10, "a seat in two leaves");
            }
        }
    }
    for s in placed.keys() {
        if touched_seats.contains(s) {
            if exit_seats.contains(s) {
                return bad(10, "an exited seat stays in a leaf");
            }
        } else if joiners.contains_key(s) {
            if refused_seats.contains(s) {
                return bad(10, "a refused joiner seated");
            }
            if !anew && (view.held)(s).is_some() {
                return bad(10, "a joiner already seated: a seat in two leaves");
            }
            if !join_like {
                return bad(10, "only a Join seats someone new");
            }
        } else if (view.held)(s).is_some() {
            return bad(10, "a seat in two leaves");
        } else {
            return bad(10, "a seat that was never seated nor asked for");
        }
    }
    for s in &touched_seats {
        if !exit_seats.contains(s) && !placed.contains_key(s) {
            return bad(10, "a seat dropped from every leaf without an exit");
        }
    }
    for e in exits {
        if !anew && !touched.contains(&e.b) {
            return bad(10, "an exited seat stays in a leaf");
        }
    }
    for j in &due.joiners {
        if !placed.contains_key(&j.seat) && !refused_seats.contains(&j.seat) {
            return bad(10, "a due joiner neither seated nor refused");
        }
    }
    let head_upto = ph.map_or(0, |p| p.exits_upto);
    let upto = if exits.is_empty() {
        head_upto
    } else {
        due.exits_upto.max(head_upto)
    };
    if h.exits_upto != upto || exits.iter().any(|e| e.seq > upto) {
        return bad(10, "exits_upto is not the last exit of the closed batch");
    }

    // 9: the root.
    let tree = BucketTree::new(&after_leaves).map_err(|_| Bad {
        rule: 9,
        detail: "leaves out of order".into(),
    })?;
    let seats: u64 = after_leaves.iter().map(|l| u64::from(l.seats)).sum();
    let conn_seats: u64 = after_leaves
        .iter()
        .filter(|l| l.pool == Pool::Conns)
        .map(|l| u64::from(l.seats))
        .sum();
    if tree.root() != h.bucket_root {
        return bad(9, "the relay's lists do not rebuild the bucket root");
    }
    if seats != u64::from(h.seats)
        || after_leaves.len() as u64 != u64::from(h.buckets)
        || conn_seats != u64::from(h.conn_seats)
    {
        return bad(9, "the counts are not the leaves'");
    }

    // 11: names.
    let seated: Vec<&Joiner> = due
        .joiners
        .iter()
        .filter(|j| placed.contains_key(&j.seat))
        .collect();
    let removed: Vec<SeatRef> = exits.iter().map(|e| e.seat).collect();
    match (&h.added, &h.removed) {
        (Added::List(a), Removed::List(r)) => {
            if a.len() != seated.len() {
                return bad(11, "added does not list exactly the new seats");
            }
            for entry in a {
                let Some(j) = joiners
                    .get(&entry.seat())
                    .filter(|j| placed.contains_key(&j.seat))
                else {
                    return bad(11, "added lists a seat this commit did not seat");
                };
                if entry.ik != j.ik {
                    return bad(11, "an added IK unlike its joiner's");
                }
                if *entry != j.added() {
                    return bad(11, "an added entry unlike its joiner's endorsement");
                }
            }
            let named: HashSet<&SeatRef> = r.iter().collect();
            if r.len() != removed.len() || !removed.iter().all(|s| named.contains(s)) {
                return bad(11, "removed does not list exactly the seats removed");
            }
            if genesis && h.names_hash != names_hash(None, h) {
                return bad(11, "names_hash does not start from the Genesis");
            }
        }
        (Added::Count(a), Removed::Count(r)) => {
            if *a as usize != seated.len() || *r as usize != removed.len() {
                return bad(11, "the counts are not the seats added and removed");
            }
        }
        _ => return bad(11, "lists in gated groups, counts in open ones"),
    }

    // 12: seeds.
    let seed_welcomed: HashSet<SeatRef> = c.seed_welcomes.iter().map(|w| w.seat).collect();
    let held_now = |s: &SeatRef| -> u32 {
        if (joiners.contains_key(s) && placed.contains_key(s)) || seed_welcomed.contains(s) {
            h.seed
        } else {
            (view.held)(s).unwrap_or(0)
        }
    };
    if let Some(p) = ph {
        check_roll(view.rolls, p, h).map_err(|r| refused(12, r))?;
        let started = h.seed > p.seed;
        let text_start = view.kind == GroupKind::Text && started && h.kind != Kind::Regenesis;
        if text_start && p.seed_floor != p.seed {
            return bad(12, "a text roll never starts over a running one");
        }
        if !anew && h.seed_floor > p.seed_floor {
            for (_, list) in &after {
                if list.iter().any(|s| held_now(s) < h.seed_floor) {
                    return if started {
                        bad(13, "a seat on a dropped seed has no seed welcome")
                    } else {
                        bad(12, "seed_floor rises before every seat holds the seed")
                    };
                }
            }
        }
    }

    // 13: material.
    check_material(
        view,
        c,
        h,
        &made,
        &after_leaves,
        &placed,
        &joiners,
        &exit_seats,
    )?;

    // 14: the keyring.
    let chained = match (h.kind, ph) {
        (Kind::Join, Some(p)) => keyring_hash_next(&p.keyring_hash, &c.keyring),
        _ => keyring_hash_start(&c.keyring),
    };
    if chained != h.keyring_hash {
        return bad(14, "the keyring uploaded is not the one the header chains");
    }
    let new_krk = matches!(
        h.kind,
        Kind::Genesis
            | Kind::Regenesis
            | Kind::KeyholdersAdd
            | Kind::KeyholdersRemove
            | Kind::KeyholdersReplace
    );
    if new_krk {
        let mut to = HashSet::new();
        for k in &c.krk {
            if k.from_kx != by.kx {
                return bad(14, "a KRK welcome not from the signer's pair");
            }
            if k.bytes.len() != SMALL_WELCOME_BYTES {
                return bad(14, "a KRK welcome of another size");
            }
            if !h.keyholders.iter().any(|e| HolderRef::of(e) == k.to) || !to.insert(k.to) {
                return bad(14, "a KRK welcome to no entry of the new set, or twice");
            }
        }
        if to.len() != h.keyholders.len() {
            return bad(14, "an entry of the new set has no KRK welcome");
        }
    } else if !c.krk.is_empty() {
        return bad(14, "KRK welcomes where the KRK stays");
    }

    // A Genesis has no parent: `ph` is `None` there.
    let rolls = match ph {
        Some(p) => view.rolls.after(p, h),
        None => SeedRolls::at_start(h),
    };
    let mut held: Vec<(SeatRef, u32)> = seated.iter().map(|j| (j.seat, h.seed)).collect();
    held.extend(c.seed_welcomes.iter().map(|w| (w.seat, h.seed)));
    let gone: Vec<Version> = if anew {
        view.leaves.iter().map(Listed::version).collect()
    } else {
        before
            .iter()
            .filter(|l| touched.contains(&l.leaf.b))
            .map(Listed::version)
            .collect()
    };
    let seated = seated.iter().map(|j| (j.seat, placed[&j.seat])).collect();
    Ok(Applied {
        keyholders: h.kind.sets_keyholders().then(|| h.keyholders.clone()),
        leaves: after_leaves,
        tree,
        made,
        gone,
        seated,
        refused: c.refused.clone(),
        exits_done: done.iter().map(|e| e.seq).collect(),
        removed: done.iter().map(|e| e.seat).collect(),
        rolls,
        held,
        header: sh,
    })
}

/// The validator's fuzz entry (W1 wires it into `fuzz_group`): a commit
/// decoded from arbitrary bytes is checked against `view`. Whatever it
/// holds, the validator refuses it or takes it, and never panics. `None`
/// for bytes that are no commit, else the rule broken (0 for none).
#[cfg(any(test, fuzzing))]
pub fn fuzz_validate(view: &GroupView, data: &[u8]) -> Option<u8> {
    let c = postcard::from_bytes::<Commit>(data).ok()?;
    Some(validate(view, &c).map_or_else(|b| b.rule, |_| 0))
}

/// Rule 8 for one version: what it names exists, its seats come from where
/// its make says, it stays in its pool and holds at most 62.
fn make_version(
    g: &Group,
    by_b: &HashMap<u64, &Listed>,
    in_use: &HashSet<u64>,
    vo: &VersionOut,
) -> Result<Listed, Bad> {
    let current = |from_v: u64| -> Result<&Listed, Bad> {
        match by_b.get(&vo.b) {
            Some(o) if o.leaf.v == from_v && o.leaf.pool == vo.pool => Ok(o),
            _ => bad(8, "a version from one that is not current in its pool"),
        }
    };
    let (seats, via) = match &vo.make {
        Make::Ratchet { from_v } => (
            current(*from_v)?.seats.clone(),
            Via::Ratchet { from: *from_v },
        ),
        Make::Keep { from_v, mask } => {
            let o = current(*from_v)?;
            let n = o.seats.len();
            if *mask == 0 || bits_beyond(*mask, n) {
                return bad(8, "a Keep mask with no seat or past the list");
            }
            let seats = o
                .seats
                .iter()
                .enumerate()
                .filter(|(i, _)| (mask >> i) & 1 == 1)
                .map(|(_, s)| *s)
                .collect();
            (seats, Via::Row)
        }
        Make::Seats(list) => {
            if in_use.contains(&vo.b) {
                return bad(8, "a new bucket under a bucket id in use");
            }
            if list.is_empty() || !in_list_order(list) {
                return bad(8, "a new bucket's seats are empty or out of list order");
            }
            (list.clone(), Via::Row)
        }
    };
    if seats.len() > usize::from(BUCKET_SEATS) {
        return bad(8, "more than 62 seats in a version");
    }
    if seats.iter().any(|s| Pool::of(&s.m) != vo.pool) {
        return bad(8, "accounts and connections share a bucket");
    }
    let at = Version { b: vo.b, v: vo.v };
    Ok(Listed {
        leaf: Leaf {
            b: vo.b,
            v: vo.v,
            pool: vo.pool,
            seats: seats.len() as u16,
            list: list_digest(g, at, &seats),
            via,
        },
        seats,
    })
}

/// Rule 7: the keyholder set changes as the due asked, and only so.
fn check_keyholders(view: &GroupView, h: &HeaderV1, old: &[Keyholder]) -> Result<(), Bad> {
    let due = view.due;
    let kind = view.kind;
    let set: &[Keyholder] = if h.kind.sets_keyholders() {
        &h.keyholders
    } else {
        old
    };
    match h.kind {
        Kind::Genesis | Kind::Regenesis => {
            let Some(vol) = &due.volunteer else {
                return bad(7, "no volunteer was asked");
            };
            match vol.pair.entry(kind, vol.m, vol.ik) {
                Some(e) if h.keyholders == [e] => {}
                _ => return bad(7, "the set is not exactly the volunteer's pair"),
            }
        }
        Kind::KeyholdersAdd => {
            check_keyholder_change(old, h).map_err(|r| refused(7, r))?;
            let added: Vec<&Keyholder> = h.keyholders.iter().filter(|k| !old.contains(k)).collect();
            let Some(cand) = &due.candidate else {
                return bad(7, "no candidate was proposed");
            };
            match cand.pair.entry(kind, cand.m, cand.ik) {
                Some(e) if added == [&e] => {}
                _ => return bad(7, "the entry added is not the candidate's pair"),
            }
        }
        Kind::KeyholdersRemove => {
            check_keyholder_change(old, h).map_err(|r| refused(7, r))?;
            let gone: Vec<HolderRef> = old
                .iter()
                .filter(|k| !h.keyholders.contains(k))
                .map(HolderRef::of)
                .collect();
            if due.remove.is_none_or(|t| gone != [t]) {
                return bad(7, "the entry removed is not the one the relay named");
            }
        }
        Kind::KeyholdersReplace => {
            let swap = replaced_entry(old, h).map_err(|r| refused(7, r))?;
            let Some(ask) = &due.replace else {
                return bad(7, "no replacement was asked");
            };
            if ask.pair.entry(kind, swap.old.m, swap.old.ik) != Some(swap.new) {
                return bad(7, "the new entry is not the pair KeyholdReplace endorsed");
            }
            let old_ser = [&[0x05u8][..], &swap.old.kx].concat();
            if tag(&old_ser) != ask.old || swap.old.kx != view.by.kx {
                return bad(7, "the entry swapped is not the one KeyholdReplace named");
            }
        }
        Kind::Fresh | Kind::Join => {}
    }
    check_voice_keyholders(h, old, view.roster).map_err(|r| refused(7, r))?;
    if kind == GroupKind::Text
        && set.iter().filter(|k| k.m.is_conn()).count() > MAX_GUEST_KEYHOLDERS
    {
        return bad(7, "more than 2 guest keyholders");
    }
    if h.gated && set.iter().any(|k| k.m.is_conn()) {
        return bad(7, "a guest keyholder in a gated group");
    }
    Ok(())
}

/// Rule 13: every secret the commit owes is there once, at its size, and
/// nothing else is.
#[allow(clippy::too_many_arguments)]
fn check_material(
    view: &GroupView,
    c: &Commit,
    h: &HeaderV1,
    made: &[Listed],
    after: &[Leaf],
    placed: &HashMap<SeatRef, Version>,
    joiners: &HashMap<SeatRef, &Joiner>,
    exit_seats: &HashSet<SeatRef>,
) -> Result<(), Bad> {
    let is_new = |s: &SeatRef| joiners.contains_key(s) && placed.contains_key(s);
    let join_like = h.kind == Kind::Join || h.kind.starts_anew();

    // Seed welcomes: exactly the seats the new floor drops. A Join drops
    // none, and a Genesis or Regenesis seats nobody it did not welcome.
    if join_like && !c.seed_welcomes.is_empty() {
        return bad(13, "a Join, Genesis or Regenesis carries no seed welcome");
    }
    let mut seed_welcomed = HashSet::new();
    for w in &c.seed_welcomes {
        if w.bytes.len() != SMALL_WELCOME_BYTES {
            return bad(13, "a seed welcome of another size");
        }
        if !seed_welcomed.insert(w.seat) {
            return bad(13, "two seed welcomes to one seat");
        }
        let needed = !is_new(&w.seat)
            && !exit_seats.contains(&w.seat)
            && (view.held)(&w.seat).is_some_and(|s| s < h.seed_floor);
        if !needed {
            return bad(13, "a seed welcome the new floor does not need");
        }
    }

    // Welcomes: one to each new seat that is not returning.
    let mut welcomed = HashSet::new();
    for w in &c.welcomes {
        let Some(j) = joiners.get(&w.seat).filter(|_| is_new(&w.seat)) else {
            return bad(13, "a welcome to a seat this commit does not seat");
        };
        if j.returning {
            return bad(13, "a returning seat gets a row, not a welcome");
        }
        if !welcomed.insert(w.seat) {
            return bad(13, "two welcomes to one seat");
        }
        if w.s != h.seed || w.bytes.len() != SEAT_WELCOME_BYTES {
            return bad(13, "a welcome under another seed or of another size");
        }
        if placed.get(&w.seat) != Some(&Version { b: w.b, v: w.v }) {
            return bad(13, "a welcome to another version than its seat's");
        }
    }
    for (s, j) in joiners {
        if is_new(s) && !j.returning && !welcomed.contains(s) {
            return bad(13, "a new seat has no welcome");
        }
    }

    // Rows: one packed set per version re-keyed by rows, each row under the
    // seed its seat holds (or the new one, for a seat welcomed here).
    let needs_rows = |m: &Listed| match m.leaf.via {
        Via::Ratchet { .. } => false,
        Via::Row if join_like => {
            (view.stored && m.leaf.pool == Pool::Accounts)
                || m.seats
                    .iter()
                    .any(|s| joiners.get(s).is_some_and(|j| j.returning))
        }
        Via::Row => true,
    };
    let by_version: HashMap<Version, &Listed> = made.iter().map(|m| (m.version(), m)).collect();
    let mut rowed = HashSet::new();
    for r in &c.rows {
        let at = Version { b: r.b, v: r.v };
        let Some(m) = by_version.get(&at).filter(|m| needs_rows(m)) else {
            return bad(13, "rows to a version that takes none from this commit");
        };
        if !rowed.insert(at) {
            return bad(13, "two sets of rows to one version");
        }
        let n = m.seats.len();
        if r.rows.len() != n * ROW_BYTES || bits_beyond(r.up, n) {
            return bad(13, "rows that do not cover the version's seats exactly");
        }
        for (i, s) in m.seats.iter().enumerate() {
            let want = if is_new(s) || seed_welcomed.contains(s) {
                h.seed
            } else {
                match (view.held)(s).map(|held| row_seed(held, h)) {
                    Some(RowSeed::Row(x)) => x,
                    _ => return bad(13, "a row before the seat's seed welcome"),
                }
            };
            if u64::from(r.s) + ((r.up >> i) & 1) != u64::from(want) {
                return bad(13, "a row under another seed than its seat holds");
            }
        }
    }
    if made
        .iter()
        .any(|m| needs_rows(m) && !rowed.contains(&m.version()))
    {
        return bad(
            13,
            "a version re-keyed by rows has none, or a stored Join lacks its rows",
        );
    }

    // Seals: one per version made (a Join), or per current version.
    let sealed_to: HashSet<Version> = if h.kind == Kind::Join {
        by_version.keys().copied().collect()
    } else {
        after.iter().map(|l| Version { b: l.b, v: l.v }).collect()
    };
    let mut sealed = HashSet::new();
    for s in &c.seals {
        let at = Version { b: s.b, v: s.v };
        if s.bytes.len() != ROW_BYTES || !sealed_to.contains(&at) || !sealed.insert(at) {
            return bad(13, "a seal of another size, to another version, or twice");
        }
    }
    if sealed.len() != sealed_to.len() {
        return bad(13, "a version has no seal");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group_key::build::world::*;
    use crate::group_key::build::Built;
    use crate::group_key::header::HeaderV1;

    fn accounts(from: u32, n: u32) -> Vec<Member> {
        (from..from + n).map(Member::numbered).collect()
    }

    fn refs(ms: &[Member]) -> Vec<&Member> {
        ms.iter().collect()
    }

    /// The rule a check broke, 0 for none.
    fn rule(r: Result<Applied, Bad>) -> u8 {
        r.map_or_else(|b| b.rule, |_| 0)
    }

    /// The commit's header changed by `edit` and signed again by `by`, its
    /// names hash following from the head, as a keyholder would sign it.
    fn resign(w: &World, c: &mut Commit, by: &Holder, edit: impl FnOnce(&mut HeaderV1)) {
        let sh = SignedHeader::decode(&c.body, &c.sig, w.kind, w.id).unwrap();
        let mut h = sh.header().clone();
        edit(&mut h);
        h.canonicalize();
        if h.kind != Kind::Genesis {
            h.names_hash = names_hash(Some(w.head.header()), &h);
        }
        let sh = SignedHeader::sign(h, &by.ik).unwrap();
        c.body = sh.body().to_vec();
        c.sig = sh.sig().to_vec();
    }

    /// A stored text group of 70 accounts and 3 guests, keyholder desktop 1.
    fn group() -> (World, Vec<Member>, Vec<Member>) {
        let mut w = World::text(true, false);
        let people = accounts(10, 70);
        let guests: Vec<Member> = (100..103).map(Member::conn).collect();
        w.join(&refs(&people));
        w.join(&refs(&guests));
        (w, people, guests)
    }

    fn fresh_with_exits(w: &mut World, seats: &[SeatRef]) -> (Due, Built) {
        let due = w.exits(seats, DueKind::Exits);
        let b = w.opening(&due).unwrap();
        (due, b)
    }

    #[test]
    fn every_honest_kind_passes_and_says_what_it_did() {
        let (mut w, people, guests) = group();
        let by = w.holders[0].by();
        let more = accounts(200, 3);
        let due = w.join_due(&refs(&more));
        let b = w.build_join(&due, None).unwrap();
        let a = w.check(&due, by, &b.commit).unwrap();
        assert_eq!(a.seated.len(), 3);
        assert!(a.gone.is_empty() && a.exits_done.is_empty() && a.keyholders.is_none());
        assert_eq!(a.tree.root(), a.header.header().bucket_root);
        assert!(a.held.iter().all(|(_, s)| *s == 1));
        w.take(&due, a, &b);

        let (due, b) = fresh_with_exits(&mut w, &[people[3].seat, guests[0].seat]);
        let a = w.check(&due, by, &b.commit).unwrap();
        assert_eq!(a.exits_done, vec![1, 2]);
        assert_eq!(a.removed, vec![people[3].seat, guests[0].seat]);
        assert_eq!(a.gone.len(), 2);
        assert_eq!(a.made.len(), 2);
        assert_eq!(a.leaves.len(), w.leaves.len());
        w.take(&due, a, &b);

        let due = w.due(DueKind::Refresh);
        let b = w.opening(&due).unwrap();
        assert!(w.check(&due, by, &b.commit).unwrap().keyholders.is_none());
        w.take(&due, w.check(&due, by, &b.commit).unwrap(), &b);

        let cand = Holder::desktop(2);
        let due = w.promote_due(&cand);
        let b = w.opening(&due).unwrap();
        let a = w.check(&due, by, &b.commit).unwrap();
        assert_eq!(a.keyholders.as_ref().map(Vec::len), Some(2));
        assert!(a
            .made
            .iter()
            .all(|m| matches!(m.leaf.via, Via::Ratchet { .. })));
        w.take(&due, a, &b);
        w.holders.push(cand);

        let new = w.holders[0].rotated();
        let due = w.replace_due(&new);
        let b = w.opening_by(0, &due, false, Some(&new), None).unwrap();
        let a = w.check(&due, by, &b.commit).unwrap();
        w.take(&due, a, &b);
        w.holders[0] = new;

        let due = w.remove_due(1);
        let b = w.opening(&due).unwrap();
        let a = w.check(&due, w.holders[0].by(), &b.commit).unwrap();
        assert_eq!(
            a.made.len(),
            w.leaves.len(),
            "a removal re-keys every bucket"
        );
        assert_eq!(a.keyholders.as_ref().map(Vec::len), Some(1));
        w.take(&due, a, &b);
    }

    #[test]
    fn a_due_kind_reads_back_from_its_code() {
        for c in 0..=10u8 {
            match DueKind::from_code(c) {
                Some(d) => assert_eq!(d.code(), c),
                None => assert!(c == 8 || c == 10, "8 is the seed-welcome page"),
            }
        }
    }

    #[test]
    fn a_commit_breaking_rule_1_is_refused() {
        let (mut w, people, _) = group();
        let (due, mut b) = fresh_with_exits(&mut w, &[people[0].seat]);
        let by = w.holders[0].by();
        b.commit.body.push(0);
        assert_eq!(rule(w.check(&due, by, &b.commit)), 1, "bytes past the body");
        b.commit.body.pop();
        b.commit.sig.pop();
        assert_eq!(rule(w.check(&due, by, &b.commit)), 1, "a short signature");

        // A voice group's id is an r: id.
        let k = Holder::conn(3);
        let due = World::genesis_due(&k, false);
        let b = World::build_start(&k, GroupKind::Voice, "c:room", false, &due, T0, None).unwrap();
        let r = World::check_start(
            GroupKind::Voice,
            "c:room",
            false,
            &due,
            k.by(),
            &b.commit,
            T0,
            &[3],
        );
        assert_eq!(rule(r), 1);
        let b = World::build_start(&k, GroupKind::Voice, VOICE_ID, false, &due, T0, None).unwrap();
        let r = World::check_start(
            GroupKind::Voice,
            VOICE_ID,
            false,
            &due,
            k.by(),
            &b.commit,
            T0,
            &[3],
        );
        assert_eq!(rule(r), 0);
    }

    #[test]
    fn a_commit_breaking_rule_2_is_refused() {
        let (mut w, people, _) = group();
        let (due, mut b) = fresh_with_exits(&mut w, &[people[0].seat]);
        let k = &w.holders[0];
        let outsider = Holder::desktop(9);
        assert_eq!(
            rule(w.check(&due, outsider.by(), &b.commit)),
            2,
            "sent by no keyholder"
        );
        let mut other = b.commit.clone();
        resign(&w, &mut other, &outsider, |_| {});
        assert_eq!(
            rule(w.check(&due, k.by(), &other)),
            2,
            "signed by another identity"
        );
        resign(&w, &mut b.commit, k, |_| {});
        assert_eq!(rule(w.check(&due, k.by(), &b.commit)), 0);

        // A Remove's signer stays in the set.
        w.promote(Holder::desktop(2));
        let due = w.remove_due(0);
        let b = w.opening_by(1, &due, false, None, None).unwrap();
        let mut c = b.commit.clone();
        let (first, second) = (
            w.holders[0].entry(GroupKind::Text),
            w.holders[1].entry(GroupKind::Text),
        );
        resign(&w, &mut c, &w.holders[1], |h| h.keyholders = vec![first]);
        let due1 = Due {
            remove: Some(HolderRef::of(&second)),
            ..due.clone()
        };
        assert_eq!(rule(w.check(&due1, w.holders[1].by(), &c)), 2);
        assert_eq!(rule(w.check(&due, w.holders[1].by(), &b.commit)), 0);

        // A Genesis by someone other than the volunteer asked.
        let vol = Holder::desktop(5);
        let due = World::genesis_due(&vol, false);
        let b =
            World::build_start(&outsider, GroupKind::Text, TEXT_ID, false, &due, T0, None).unwrap();
        let r = World::check_start(
            GroupKind::Text,
            TEXT_ID,
            false,
            &due,
            vol.by(),
            &b.commit,
            T0,
            &[],
        );
        assert_eq!(rule(r), 2);
    }

    #[test]
    fn rule_2_takes_the_set_its_kh_parent_names_under_a_fresh_and_a_join_head() {
        let mut w = World::text(false, false);
        w.join(&refs(&accounts(10, 4)));
        assert_eq!(w.head.header().kind, Kind::Join);
        let by = w.holders[0].by();
        let due = w.due(DueKind::Refresh);
        let b = w.opening(&due).unwrap();
        assert_eq!(rule(w.check(&due, by, &b.commit)), 0);
        let kh = std::mem::replace(&mut w.kh, w.head.clone());
        assert_eq!(
            rule(w.check(&due, by, &b.commit)),
            2,
            "the Join head is no keyholder set"
        );
        w.kh = kh;
        w.step(&due, &b);

        assert_eq!(w.head.header().kind, Kind::Fresh);
        let due = w.join_due(&refs(&accounts(40, 2)));
        let b = w.build_join(&due, None).unwrap();
        assert_eq!(rule(w.check(&due, by, &b.commit)), 0);
        let kh = std::mem::replace(&mut w.kh, w.head.clone());
        assert_eq!(
            rule(w.check(&due, by, &b.commit)),
            2,
            "the Fresh head is no keyholder set"
        );
        w.kh = kh;
    }

    #[test]
    fn a_commit_breaking_rule_3_is_refused() {
        let (mut w, people, _) = group();
        let by = w.holders[0].by();
        let (due, b) = fresh_with_exits(&mut w, &[people[0].seat]);
        let join = Due {
            exits: vec![],
            ..w.due(DueKind::Join)
        };
        assert_eq!(rule(w.check(&join, by, &b.commit)), 3);
        let promote = Due {
            kind: DueKind::Promote,
            ..due.clone()
        };
        assert_eq!(rule(w.check(&promote, by, &b.commit)), 3);
        assert_eq!(rule(w.check(&due, by, &b.commit)), 0);
    }

    #[test]
    fn a_commit_breaking_rule_4_is_refused() {
        let (mut w, people, _) = group();
        let by = w.holders[0].by();
        let (due, b) = fresh_with_exits(&mut w, &[people[0].seat]);
        w.join(&refs(&accounts(300, 2)));
        assert_eq!(rule(w.check(&due, by, &b.commit)), 4, "the head moved");

        // A Genesis under a generation the group had.
        let vol = Holder::desktop(5);
        let due = World::genesis_due(&vol, false);
        let mut b =
            World::build_start(&vol, GroupKind::Text, TEXT_ID, true, &due, w.now, None).unwrap();
        assert_eq!(rule(w.check(&due, vol.by(), &b.commit)), 0);
        let gen = w.head.header().gen;
        let sh = SignedHeader::decode(&b.commit.body, &b.commit.sig, w.kind, w.id).unwrap();
        let mut h = sh.header().clone();
        h.gen = gen;
        let sh = SignedHeader::sign(h, &vol.ik).unwrap();
        b.commit.body = sh.body().to_vec();
        b.commit.sig = sh.sig().to_vec();
        assert_eq!(rule(w.check(&due, vol.by(), &b.commit)), 4);

        // A Regenesis only after an hour with no keyholder online.
        let due = Due {
            joiners: vec![vol.seat.joiner()],
            volunteer: Some(vol.candidate()),
            ..w.due(DueKind::Regenesis)
        };
        w.tick(3700);
        let head = w.head.clone();
        let b = World::build_start(&vol, w.kind, w.id, true, &due, w.now, Some(&head)).unwrap();
        w.no_keyholder_since = Some(w.now - 60);
        assert_eq!(rule(w.check(&due, vol.by(), &b.commit)), 4);
        w.no_keyholder_since = None;
        assert_eq!(rule(w.check(&due, vol.by(), &b.commit)), 4);
        w.no_keyholder_since = Some(w.now - 3600);
        assert_eq!(rule(w.check(&due, vol.by(), &b.commit)), 0);
    }

    #[test]
    fn a_commit_breaking_rule_5_is_refused() {
        let (mut w, people, _) = group();
        let (due, b) = fresh_with_exits(&mut w, &[people[0].seat]);
        let k = &w.holders[0];
        let mut ahead = b.commit.clone();
        let now = w.now;
        resign(&w, &mut ahead, k, |h| h.time = now + 601);
        assert_eq!(rule(w.check(&due, k.by(), &ahead)), 5);
        let mut early = b.commit.clone();
        let before = w.head.header().time - 1;
        resign(&w, &mut early, k, |h| h.time = before);
        assert_eq!(rule(w.check(&due, k.by(), &early)), 5);
        let mut ok = b.commit.clone();
        resign(&w, &mut ok, k, |h| h.time = now + 600);
        assert_eq!(rule(w.check(&due, k.by(), &ok)), 0);
    }

    #[test]
    fn a_commit_breaking_rule_6_is_refused() {
        let (mut w, people, guests) = group();
        let by = w.holders[0].by();
        let (due, b) = fresh_with_exits(&mut w, &[people[0].seat]);
        let gated = Due {
            gated: true,
            ..due.clone()
        };
        assert_eq!(
            rule(w.check(&gated, by, &b.commit)),
            6,
            "not the gated asked for"
        );

        // A gated header over a connections-pool bucket.
        let mut c = b.commit.clone();
        let exited = vec![people[0].seat];
        resign(&w, &mut c, &w.holders[0], |h| {
            h.gated = true;
            h.conn_seats = 0;
            h.added = Added::List(vec![]);
            h.removed = Removed::List(exited);
        });
        assert_eq!(rule(w.check(&gated, by, &c)), 6);
        let _ = guests;

        // `gated` changes only at an opening header.
        let more = accounts(300, 2);
        let due = w.join_due(&refs(&more));
        let mut b = w.build_join(&due, None).unwrap();
        let added: Vec<AddedSeat> = due.joiners.iter().map(Joiner::added).collect();
        resign(&w, &mut b.commit, &w.holders[0], |h| {
            h.gated = true;
            h.conn_seats = 0;
            h.added = Added::List(added);
            h.removed = Removed::List(vec![]);
        });
        let due = Due { gated: true, ..due };
        assert_eq!(rule(w.check(&due, by, &b.commit)), 6);
    }

    #[test]
    fn a_commit_breaking_rule_7_is_refused() {
        let (mut w, _, _) = group();
        let by = w.holders[0].by();
        let c1 = Holder::desktop(2);
        let c2 = Holder::desktop(3);
        let due = w.promote_due(&c1);
        let b = w.opening(&due).unwrap();
        let other = w.promote_due(&c2);
        assert_eq!(
            rule(w.check(&other, by, &b.commit)),
            7,
            "not the candidate proposed"
        );
        w.step(&due, &b);
        w.holders.push(c1);
        w.promote(c2);

        let due = w.remove_due(1);
        let b = w.opening(&due).unwrap();
        let other = w.remove_due(2);
        assert_eq!(
            rule(w.check(&other, by, &b.commit)),
            7,
            "not the entry named"
        );
        assert_eq!(rule(w.check(&due, by, &b.commit)), 0);

        // A Replace's new entry is the endorsed pair, its old entry the one named.
        let new = w.holders[0].rotated();
        let due = w.replace_due(&new);
        let b = w.opening_by(0, &due, false, Some(&new), None).unwrap();
        assert_eq!(rule(w.check(&due, by, &b.commit)), 0);
        let elsewhere = w.holders[0].rotated();
        let unlike = Due {
            replace: Some(ReplaceAsk {
                old: due.replace.as_ref().unwrap().old,
                pair: elsewhere.pair(),
            }),
            ..due.clone()
        };
        assert_eq!(
            rule(w.check(&unlike, by, &b.commit)),
            7,
            "a pair other than endorsed"
        );
        let other_old = Due {
            replace: Some(ReplaceAsk {
                old: [0; 8],
                pair: new.pair(),
            }),
            ..due.clone()
        };
        assert_eq!(
            rule(w.check(&other_old, by, &b.commit)),
            7,
            "another old tag"
        );

        // A Genesis set unlike the volunteer's pair, by the same identity.
        let vol = Holder::desktop(5);
        let due = World::genesis_due(&vol, false);
        let mut b =
            World::build_start(&vol, GroupKind::Text, TEXT_ID, false, &due, T0, None).unwrap();
        let sh =
            SignedHeader::decode(&b.commit.body, &b.commit.sig, GroupKind::Text, TEXT_ID).unwrap();
        let mut h = sh.header().clone();
        h.keyholders = vec![vol.rotated().entry(GroupKind::Text)];
        let sh = SignedHeader::sign(h, &vol.ik).unwrap();
        b.commit.body = sh.body().to_vec();
        b.commit.sig = sh.sig().to_vec();
        let r = World::check_start(
            GroupKind::Text,
            TEXT_ID,
            false,
            &due,
            vol.by(),
            &b.commit,
            T0,
            &[],
        );
        assert_eq!(rule(r), 7);
    }

    #[test]
    fn a_third_guest_keyholder_and_a_voice_keyholder_past_the_lowest_ids_are_refused() {
        let mut w = World::start(GroupKind::Text, TEXT_ID, false, false, Holder::conn(5));
        w.promote(Holder::conn(6));
        let due = w.promote_due(&Holder::conn(7));
        let b = w.opening(&due).unwrap();
        assert_eq!(rule(w.check(&due, w.holders[0].by(), &b.commit)), 7);

        let mut v = World::voice();
        v.join(&refs(&(10..20).map(Member::conn).collect::<Vec<_>>()));
        let due = v.promote_due(&Holder::conn(50));
        let b = v.opening(&due).unwrap();
        assert_eq!(rule(v.check(&due, v.holders[0].by(), &b.commit)), 7);
        let due = v.promote_due(&Holder::conn(4));
        let b = v.opening(&due).unwrap();
        v.roster.push(4);
        assert_eq!(rule(v.check(&due, v.holders[0].by(), &b.commit)), 0);
    }

    #[test]
    fn a_commit_breaking_rule_8_is_refused() {
        let (mut w, people, guests) = group();
        let by = w.holders[0].by();
        let (due, b) = fresh_with_exits(&mut w, &[people[0].seat]);
        let mut c = b.commit.clone();
        if let Make::Keep { from_v, .. } = &mut c.versions[0].make {
            *from_v ^= 1;
        }
        assert_eq!(
            rule(w.check(&due, by, &c)),
            8,
            "a Keep from no current version"
        );
        let mut c = b.commit.clone();
        c.drops.push(12345);
        assert_eq!(
            rule(w.check(&due, by, &c)),
            8,
            "a drop of no current bucket"
        );
        let mut c = b.commit.clone();
        c.versions.push(c.versions[0].clone());
        assert_eq!(rule(w.check(&due, by, &c)), 8, "one bucket twice");

        // A Join that makes more than 62 seats in one version, or mixes pools.
        let more = accounts(300, 63);
        let due = w.join_due(&refs(&more));
        let b = w.build_join(&due, None).unwrap();
        let mut c = b.commit.clone();
        let mut all: Vec<SeatRef> = more.iter().map(|m| m.seat).collect();
        list_order(&mut all);
        c.versions[0].make = Make::Seats(all);
        c.versions.truncate(1);
        assert_eq!(rule(w.check(&due, by, &c)), 8);
        let mut c = b.commit.clone();
        if let Make::Seats(s) = &mut c.versions[0].make {
            s.pop();
            s.push(guests[0].seat);
            list_order(s);
        }
        assert_eq!(
            rule(w.check(&due, by, &c)),
            8,
            "accounts and connections in one bucket"
        );
        let mut c = b.commit.clone();
        let current = w.leaves[0].version();
        c.versions[0] = VersionOut {
            b: current.b,
            v: 77,
            pool: Pool::Accounts,
            make: Make::Keep {
                from_v: current.v,
                mask: 1,
            },
        };
        assert_eq!(rule(w.check(&due, by, &c)), 8, "a Join re-versions nothing");

        // A promotion re-versions by rows only for exits.
        let cand = Holder::desktop(2);
        let due = w.promote_due(&cand);
        let b = w.opening(&due).unwrap();
        let mut c = b.commit.clone();
        let vo = &mut c.versions[0];
        let Make::Ratchet { from_v } = vo.make else {
            panic!("a promotion ratchets");
        };
        let n = w
            .leaves
            .iter()
            .find(|l| l.leaf.b == vo.b)
            .unwrap()
            .seats
            .len();
        vo.make = Make::Keep {
            from_v,
            mask: (1u64 << n) - 1,
        };
        assert_eq!(rule(w.check(&due, by, &c)), 8);

        // A refresh re-keys at least a twelfth by rows.
        let quiet = w.due(DueKind::Exits);
        let b = w.opening(&quiet).unwrap();
        assert!(b.commit.rows.is_empty());
        assert_eq!(rule(w.check(&quiet, by, &b.commit)), 0);
        let refresh = w.due(DueKind::Refresh);
        assert_eq!(rule(w.check(&refresh, by, &b.commit)), 8);
    }

    #[test]
    fn a_commit_breaking_rule_9_is_refused() {
        let (mut w, people, _) = group();
        let (due, mut b) = fresh_with_exits(&mut w, &[people[0].seat]);
        let k = &w.holders[0];
        let mut c = b.commit.clone();
        resign(&w, &mut c, k, |h| h.bucket_root = [9; 32]);
        assert_eq!(rule(w.check(&due, k.by(), &c)), 9);
        resign(&w, &mut b.commit, k, |h| h.seats += 1);
        assert_eq!(rule(w.check(&due, k.by(), &b.commit)), 9);
        let mut c = b.commit.clone();
        resign(&w, &mut c, k, |h| {
            h.seats -= 1;
            h.conn_seats -= 1;
        });
        assert_eq!(rule(w.check(&due, k.by(), &c)), 9);
    }

    #[test]
    fn a_commit_breaking_rule_10_is_refused() {
        let (mut w, people, _) = group();
        let by = w.holders[0].by();
        let (due, b) = fresh_with_exits(&mut w, &[people[0].seat]);
        assert_eq!(rule(w.check(&due, by, &b.commit)), 0);

        // A seat dropped from every leaf without an exit.
        let mut c = b.commit.clone();
        let Make::Keep { mask, .. } = &mut c.versions[0].make else {
            panic!("exits re-key by rows");
        };
        *mask &= *mask - 1;
        assert_eq!(rule(w.check(&due, by, &c)), 10);

        // A seat in two leaves.
        let untouched = w
            .leaves
            .iter()
            .find(|l| !l.seats.contains(&people[0].seat) && l.leaf.pool == Pool::Accounts)
            .unwrap();
        let mut c = b.commit.clone();
        c.versions.push(VersionOut {
            b: 4242,
            v: 4343,
            pool: Pool::Accounts,
            make: Make::Seats(vec![untouched.seats[0]]),
        });
        assert_eq!(rule(w.check(&due, by, &c)), 10);

        // A merge seat never seated before.
        let stranger = Member::numbered(900);
        let mut c = b.commit.clone();
        c.versions.push(VersionOut {
            b: 4242,
            v: 4343,
            pool: Pool::Accounts,
            make: Make::Seats(vec![stranger.seat]),
        });
        assert_eq!(rule(w.check(&due, by, &c)), 10);

        // An exited seat that stays in a leaf, and an exits_upto past the batch.
        let quiet = w.due(DueKind::Exits);
        let b0 = w.opening(&quiet).unwrap();
        assert_eq!(rule(w.check(&due, by, &b0.commit)), 10);
        let mut c = b.commit.clone();
        resign(&w, &mut c, &w.holders[0], |h| h.exits_upto += 1);
        assert_eq!(rule(w.check(&due, by, &c)), 10);

        // A Join seat the due did not name, and a due joiner left out.
        let (a, z) = (Member::numbered(500), Member::numbered(501));
        let due2 = w.join_due(&[&a, &z]);
        let b2 = w.build_join(&due2, None).unwrap();
        let only_a = w.join_due(&[&a]);
        assert_eq!(rule(w.check(&only_a, by, &b2.commit)), 10);
        let c3 = Member::numbered(502);
        let three = w.join_due(&[&a, &z, &c3]);
        assert_eq!(rule(w.check(&three, by, &b2.commit)), 10);
        let mut refusing = b2.commit.clone();
        refusing.refused.push(Refused {
            seat: c3.seat,
            why: 1,
        });
        assert_eq!(
            rule(w.check(&three, by, &refusing)),
            0,
            "a refused joiner is accounted for"
        );
        refusing.refused.push(Refused {
            seat: c3.seat,
            why: 1,
        });
        assert_eq!(rule(w.check(&three, by, &refusing)), 10, "refused twice");

        // A joiner already seated would sit in two leaves.
        let again = w.join_due(&[&people[5]]);
        let b3 = w.build_join(&again, None).unwrap();
        assert_eq!(rule(w.check(&again, by, &b3.commit)), 10);
    }

    #[test]
    fn a_commit_breaking_rule_11_is_refused() {
        let mut w = World::text(true, true);
        let by = w.holders[0].by();
        let people = accounts(10, 3);
        let due = w.join_due(&refs(&people));
        let b = w.build_join(&due, None).unwrap();
        assert_eq!(rule(w.check(&due, by, &b.commit)), 0);
        let mut c = b.commit.clone();
        let other = Member::numbered(77).ik_raw();
        resign(&w, &mut c, &w.holders[0], |h| {
            if let Added::List(l) = &mut h.added {
                l[0].ik = other;
            }
        });
        assert_eq!(
            rule(w.check(&due, by, &c)),
            11,
            "an added IK unlike its joiner's"
        );
        let mut c = b.commit.clone();
        resign(&w, &mut c, &w.holders[0], |h| {
            if let Added::List(l) = &mut h.added {
                l.pop();
            }
        });
        assert_eq!(rule(w.check(&due, by, &c)), 11, "a new seat unnamed");
        let mut c = b.commit.clone();
        resign(&w, &mut c, &w.holders[0], |h| {
            if let Added::List(l) = &mut h.added {
                l[0].n += 1;
            }
        });
        assert_eq!(
            rule(w.check(&due, by, &c)),
            11,
            "a counter unlike its endorsement's"
        );
        w.step(&due, &b);

        let due = w.exits(&[people[1].seat], DueKind::Exits);
        let b = w.opening(&due).unwrap();
        let mut c = b.commit.clone();
        resign(&w, &mut c, &w.holders[0], |h| {
            h.removed = Removed::List(vec![])
        });
        assert_eq!(rule(w.check(&due, by, &c)), 11, "a removed seat unnamed");

        // Open groups count.
        let mut o = World::text(false, false);
        let due = o.join_due(&refs(&accounts(10, 3)));
        let mut b = o.build_join(&due, None).unwrap();
        resign(&o, &mut b.commit, &o.holders[0], |h| {
            h.added = Added::Count(4)
        });
        assert_eq!(rule(o.check(&due, o.holders[0].by(), &b.commit)), 11);
    }

    #[test]
    fn a_commit_breaking_rule_12_is_refused() {
        let mut w = World::text(true, false);
        w.join(&refs(&accounts(10, 5)));
        let by = w.holders[0].by();
        // The seed rises with no roll due.
        let due = w.due(DueKind::Exits);
        let b = w.opening(&due).unwrap();
        let mut c = b.commit.clone();
        resign(&w, &mut c, &w.holders[0], |h| {
            h.seed = 2;
            h.seed_floor = 1;
        });
        assert_eq!(rule(w.check(&due, by, &c)), 12);

        // A removal 25 h on starts a roll; a Fresh may not finish it before
        // every seat holds the new seed.
        w.promote(Holder::desktop(2));
        w.tick(25 * 3600);
        w.remove(1);
        assert_eq!((w.head.header().seed, w.head.header().seed_floor), (2, 1));
        let due = w.due(DueKind::Exits);
        let b = w.opening(&due).unwrap();
        let mut c = b.commit.clone();
        resign(&w, &mut c, &w.holders[0], |h| h.seed_floor = 2);
        assert_eq!(
            rule(w.check(&due, by, &c)),
            12,
            "seed_floor raised before every seat holds it"
        );

        // A text roll never starts over a running one.
        w.promote(Holder::desktop(3));
        w.tick(25 * 3600);
        let due = w.remove_due(1);
        let b = w.opening(&due).unwrap();
        assert_eq!(
            b.header.header().seed,
            2,
            "the builder leaves the running roll be"
        );
        assert_eq!(rule(w.check(&due, by, &b.commit)), 0);
        let mut c = b.commit.clone();
        resign(&w, &mut c, &w.holders[0], |h| {
            h.seed = 3;
            h.seed_floor = 2;
        });
        assert_eq!(rule(w.check(&due, by, &c)), 12);
        w.step(&due, &b);
        w.holders.remove(1);

        // Once every seat holds it, the roll finishes.
        w.welcome_every_seat();
        let due = w.due(DueKind::Exits);
        let b = w.opening_by(0, &due, true, None, None).unwrap();
        assert_eq!(
            (b.header.header().seed, b.header.header().seed_floor),
            (2, 2)
        );
        assert_eq!(rule(w.check(&due, by, &b.commit)), 0);
    }

    #[test]
    fn a_text_roll_within_24_h_of_the_last_and_a_join_or_replace_raising_the_seed_are_refused() {
        let mut w = World::text(true, false);
        w.join(&refs(&accounts(10, 5)));
        let by = w.holders[0].by();
        w.promote(Holder::desktop(2));
        w.promote(Holder::desktop(3));
        w.tick(25 * 3600);
        w.remove(1);
        assert_eq!((w.head.header().seed, w.head.header().seed_floor), (2, 1));
        w.welcome_every_seat();
        let due = w.due(DueKind::Exits);
        let b = w.opening_by(0, &due, true, None, None).unwrap();
        w.step(&due, &b);
        assert_eq!((w.head.header().seed, w.head.header().seed_floor), (2, 2));

        // A removal within 24 h of that raise makes a roll due, not a start.
        let due = w.remove_due(1);
        let b = w.opening(&due).unwrap();
        assert_eq!(b.header.header().seed, 2);
        assert_eq!(rule(w.check(&due, by, &b.commit)), 0);
        let mut c = b.commit.clone();
        resign(&w, &mut c, &w.holders[0], |h| {
            h.seed = 3;
            h.seed_floor = 2;
        });
        assert_eq!(rule(w.check(&due, by, &c)), 12, "within 24 h");
        w.step(&due, &b);
        w.holders.remove(1);

        // Past the 24 h the due roll may start; a Join or Replace never.
        w.tick(25 * 3600);
        let due = w.join_due(&refs(&accounts(80, 2)));
        let b = w.build_join(&due, None).unwrap();
        let mut c = b.commit.clone();
        resign(&w, &mut c, &w.holders[0], |h| {
            h.seed = 3;
            h.seed_floor = 2;
        });
        assert_eq!(rule(w.check(&due, by, &c)), 12, "a Join");
        let new = w.holders[0].rotated();
        let due = w.replace_due(&new);
        let b = w.opening_by(0, &due, false, Some(&new), None).unwrap();
        assert_eq!(b.header.header().seed, 2);
        assert_eq!(rule(w.check(&due, by, &b.commit)), 0);
        let mut c = b.commit.clone();
        resign(&w, &mut c, &w.holders[0], |h| {
            h.seed = 3;
            h.seed_floor = 2;
        });
        assert_eq!(rule(w.check(&due, by, &c)), 12, "a Replace");
        let due = w.due(DueKind::Exits);
        let b = w.opening(&due).unwrap();
        assert_eq!(b.header.header().seed, 3, "the due roll starts");
        assert_eq!(rule(w.check(&due, by, &b.commit)), 0);
    }

    #[test]
    fn a_guest_keyholder_left_in_a_gated_set_is_refused() {
        let mut w = World::text(false, false);
        w.join(&refs(&accounts(10, 3)));
        w.promote(Holder::conn(7));
        let by = w.holders[0].by();
        let gate = Due {
            gated: true,
            ..w.due(DueKind::Gate)
        };
        assert_eq!(
            w.opening(&gate).err(),
            Some(crate::group_key::build::BuildError::Refuse(
                "a guest keyholder in a gated group"
            ))
        );
        let open = w.due(DueKind::Gate);
        let b = w.opening(&open).unwrap();
        let mut c = b.commit.clone();
        resign(&w, &mut c, &w.holders[0], |h| {
            h.gated = true;
            h.added = Added::List(vec![]);
            h.removed = Removed::List(vec![]);
        });
        assert_eq!(rule(w.check(&gate, by, &c)), 7);
    }

    #[test]
    fn a_replace_whose_krk_welcomes_come_from_the_new_pair_is_refused() {
        let (mut w, _, _) = group();
        let by = w.holders[0].by();
        let new = w.holders[0].rotated();
        let due = w.replace_due(&new);
        let b = w.opening_by(0, &due, false, Some(&new), None).unwrap();
        assert!(b.commit.krk.iter().all(|k| k.from_kx == by.kx));
        assert_eq!(rule(w.check(&due, by, &b.commit)), 0);
        let mut c = b.commit.clone();
        c.krk[0].from_kx = new.by().kx;
        assert_eq!(rule(w.check(&due, by, &c)), 14);
        assert_eq!(
            rule(w.check(&due, new.by(), &b.commit)),
            2,
            "sent from the new pair"
        );
    }

    #[test]
    fn a_commit_breaking_rule_13_is_refused() {
        // A stored Join without its rows, a welcome short or to another
        // version, a seal missing.
        let mut w = World::text(true, false);
        let by = w.holders[0].by();
        let people = accounts(10, 5);
        let due = w.join_due(&refs(&people));
        let b = w.build_join(&due, None).unwrap();
        assert_eq!(rule(w.check(&due, by, &b.commit)), 0);
        let mut c = b.commit.clone();
        c.rows.clear();
        assert_eq!(
            rule(w.check(&due, by, &c)),
            13,
            "a stored Join without its row"
        );
        let mut c = b.commit.clone();
        c.welcomes[0].bytes.pop();
        assert_eq!(rule(w.check(&due, by, &c)), 13);
        let mut c = b.commit.clone();
        c.welcomes[0].v ^= 1;
        assert_eq!(rule(w.check(&due, by, &c)), 13);
        let mut c = b.commit.clone();
        c.welcomes.pop();
        assert_eq!(
            rule(w.check(&due, by, &c)),
            13,
            "a new seat without its welcome"
        );
        let mut c = b.commit.clone();
        c.seals.clear();
        assert_eq!(rule(w.check(&due, by, &c)), 13);
        let mut c = b.commit.clone();
        c.rows[0].s += 1;
        assert_eq!(rule(w.check(&due, by, &c)), 13, "rows under another seed");
        let mut c = b.commit.clone();
        c.seed_welcomes.push(SeedWelcomeOut {
            seat: people[0].seat,
            bytes: vec![0; SMALL_WELCOME_BYTES],
        });
        assert_eq!(
            rule(w.check(&due, by, &c)),
            13,
            "a seed welcome nothing needs"
        );
        w.step(&due, &b);

        // In voice a removal over a running roll carries every seed welcome.
        let mut v = World::voice();
        v.join(&refs(&(10..20).map(Member::conn).collect::<Vec<_>>()));
        v.promote(Holder::conn(4));
        v.remove(1);
        v.promote(Holder::conn(5));
        let due = v.remove_due(1);
        let b = v.opening(&due).unwrap();
        let vby = v.holders[0].by();
        assert_eq!(rule(v.check(&due, vby, &b.commit)), 0);
        let mut c = b.commit.clone();
        c.seed_welcomes.pop();
        assert_eq!(rule(v.check(&due, vby, &c)), 13, "a missing seed welcome");
        let mut c = b.commit.clone();
        c.seed_welcomes.push(c.seed_welcomes[0].clone());
        assert_eq!(rule(v.check(&due, vby, &c)), 13, "two to one seat");
    }

    #[test]
    fn a_regenesis_or_genesis_carrying_a_seed_welcome_is_refused() {
        let mut w = World::text(true, false);
        let people = accounts(10, 5);
        w.join(&refs(&people));
        let vol = Holder::desktop(9);
        let due = Due {
            joiners: vec![vol.seat.joiner()],
            volunteer: Some(vol.candidate()),
            ..w.due(DueKind::Regenesis)
        };
        let head = w.head.clone();
        w.tick(3600);
        w.no_keyholder_since = Some(w.now - 3600);
        let b = World::build_start(&vol, w.kind, w.id, true, &due, w.now, Some(&head)).unwrap();
        assert_eq!(rule(w.check(&due, vol.by(), &b.commit)), 0);
        // An old seat the Regenesis does not seat would count as seated.
        let mut c = b.commit.clone();
        c.seed_welcomes.push(SeedWelcomeOut {
            seat: people[0].seat,
            bytes: vec![0; SMALL_WELCOME_BYTES],
        });
        assert_eq!(rule(w.check(&due, vol.by(), &c)), 13);

        let k = Holder::desktop(5);
        let due = World::genesis_due(&k, false);
        let mut b =
            World::build_start(&k, GroupKind::Text, TEXT_ID, false, &due, T0, None).unwrap();
        b.commit.seed_welcomes.push(SeedWelcomeOut {
            seat: k.seat.seat,
            bytes: vec![0; SMALL_WELCOME_BYTES],
        });
        let r = World::check_start(
            GroupKind::Text,
            TEXT_ID,
            false,
            &due,
            k.by(),
            &b.commit,
            T0,
            &[],
        );
        assert_eq!(rule(r), 13);
    }

    #[test]
    fn a_genesis_due_with_an_exit_batch_is_taken_and_its_header_names_no_exit() {
        let vol = Holder::desktop(5);
        let gone = Member::numbered(1).seat;
        let mut due = World::genesis_due(&vol, false);
        due.exits = vec![Exit {
            seq: 7,
            seat: gone,
            b: 99,
        }];
        due.exits_upto = 7;
        let check = |c: &Commit| {
            World::check_start(GroupKind::Text, TEXT_ID, false, &due, vol.by(), c, T0, &[])
        };
        let b = World::build_start(&vol, GroupKind::Text, TEXT_ID, false, &due, T0, None).unwrap();
        let a = check(&b.commit).unwrap();
        let h = a.header.header();
        assert_eq!((h.exits_upto, &h.removed), (0, &Removed::Count(0)));
        assert_eq!(a.exits_done, vec![7], "the new generation closes the batch");
        assert_eq!(a.removed, vec![gone]);
        // A Genesis naming the old generation's exit is refused.
        let sh =
            SignedHeader::decode(&b.commit.body, &b.commit.sig, GroupKind::Text, TEXT_ID).unwrap();
        let mut h = sh.header().clone();
        h.exits_upto = 7;
        let sh = SignedHeader::sign(h, &vol.ik).unwrap();
        let mut c = b.commit.clone();
        c.body = sh.body().to_vec();
        c.sig = sh.sig().to_vec();
        assert_eq!(rule(check(&c)), 10);
    }

    #[test]
    fn a_returning_joiner_gets_a_row_under_the_head_seed_and_no_welcome() {
        let mut w = World::text(false, false);
        let by = w.holders[0].by();
        let back = Member::numbered(40);
        let new = Member::numbered(41);
        let mut due = w.join_due(&[&back, &new]);
        due.joiners[0].returning = true;
        let b = w.build_join(&due, None).unwrap();
        assert_eq!(rule(w.check(&due, by, &b.commit)), 0);
        assert_eq!(b.commit.welcomes.len(), 1);
        assert_eq!(b.commit.welcomes[0].seat, new.seat);
        // The returning seat opens its row with the s_m it holds.
        let m = b
            .made
            .iter()
            .find(|m| m.seats.contains(&back.seat))
            .unwrap();
        let rows = m
            .rows
            .as_ref()
            .expect("a returning seat's version has rows");
        let i = m.seats.iter().position(|s| *s == back.seat).unwrap();
        let (row, s) = rows.row(i).unwrap();
        assert_eq!(s, 1);
        let s_m =
            crate::group_key::derive::member_secret(&w.g, 1, w.ring.seed(1).unwrap(), &back.seat);
        let rb = crate::group_key::derive::RowBase::member_side(
            &w.g,
            1,
            &back.me(),
            &w.holders[0].holder(),
            &s_m,
        )
        .unwrap();
        assert_eq!(*rb.open_row(m.bucket.version(), row).unwrap(), *m.bucket.bk);
        // A welcome to it, or its version without rows, is refused.
        let mut c = b.commit.clone();
        c.welcomes.push(WelcomeOut {
            seat: back.seat,
            ..c.welcomes[0].clone()
        });
        assert_eq!(rule(w.check(&due, by, &c)), 13);
        let mut c = b.commit.clone();
        c.rows.clear();
        assert_eq!(rule(w.check(&due, by, &c)), 13);
        // Without `returning`, the same commit owes it a welcome.
        let mut plain = due.clone();
        plain.joiners[0].returning = false;
        assert_eq!(rule(w.check(&plain, by, &b.commit)), 13);
    }

    #[test]
    fn a_commit_breaking_rule_14_is_refused() {
        let (mut w, _, _) = group();
        let by = w.holders[0].by();
        let due = w.due(DueKind::Exits);
        let b = w.opening(&due).unwrap();
        let mut c = b.commit.clone();
        c.keyring[20] ^= 1;
        assert_eq!(
            rule(w.check(&due, by, &c)),
            14,
            "another keyring than the header chains"
        );
        let mut c = b.commit.clone();
        c.krk.push(KrkOut {
            to: by,
            from_kx: by.kx,
            bytes: vec![0; SMALL_WELCOME_BYTES],
        });
        assert_eq!(
            rule(w.check(&due, by, &c)),
            14,
            "a KRK welcome where the KRK stays"
        );

        let due = w.promote_due(&Holder::desktop(2));
        let b = w.opening(&due).unwrap();
        assert_eq!(b.commit.krk.len(), 2);
        let mut c = b.commit.clone();
        c.krk.pop();
        assert_eq!(
            rule(w.check(&due, by, &c)),
            14,
            "an entry without its KRK welcome"
        );
        let mut c = b.commit.clone();
        c.krk[0].from_kx = [1; 32];
        assert_eq!(
            rule(w.check(&due, by, &c)),
            14,
            "not from the signer's pair"
        );
        let mut c = b.commit.clone();
        c.krk[1] = c.krk[0].clone();
        assert_eq!(rule(w.check(&due, by, &c)), 14, "twice to one entry");

        let due = w.join_due(&refs(&accounts(300, 2)));
        let b = w.build_join(&due, None).unwrap();
        let mut c = b.commit.clone();
        c.keyring.pop();
        assert_eq!(
            rule(w.check(&due, by, &c)),
            14,
            "a delta the header does not chain"
        );
    }

    #[test]
    fn a_commit_breaking_rule_15_is_refused() {
        let (mut w, people, _) = group();
        let by = w.holders[0].by();
        let one = Member::numbered(600);
        let due = Due {
            joiners: vec![one.joiner(); 257],
            ..w.due(DueKind::Join)
        };
        let small = w.join_due(&[&one]);
        let b = w.build_join(&small, None).unwrap();
        assert_eq!(rule(w.check(&due, by, &b.commit)), 15);
        let (due, mut b) = fresh_with_exits(&mut w, &[people[0].seat]);
        b.commit.keyring = vec![0; COMMIT_MAX_BYTES];
        assert_eq!(rule(w.check(&due, by, &b.commit)), 15, "over 12 MB");
    }

    #[test]
    fn a_commit_breaking_rule_16_is_refused() {
        let (mut w, people, _) = group();
        let by = w.holders[0].by();
        let (due, b) = fresh_with_exits(&mut w, &[people[0].seat]);
        assert_eq!(rule(w.check(&due, by, &b.commit)), 0);
        w.used_v.insert(b.made[0].bucket.v);
        assert_eq!(
            rule(w.check(&due, by, &b.commit)),
            16,
            "a version id used before"
        );
        w.used_v.remove(&b.made[0].bucket.v);
        let mut c = b.commit.clone();
        let mut twin = c.versions[0].clone();
        twin.b = 777;
        twin.make = Make::Seats(vec![people[1].seat]);
        c.versions.push(twin);
        assert_eq!(rule(w.check(&due, by, &c)), 16, "one id twice in a commit");
    }

    #[test]
    fn arbitrary_commits_are_refused_without_a_panic() {
        let (mut w, people, _) = group();
        let by = w.holders[0].by();
        let (due, b) = fresh_with_exits(&mut w, &[people[0].seat, people[63].seat]);
        let bytes = postcard::to_allocvec(&b.commit).unwrap();
        w.view_with(&due, by, |v| {
            assert_eq!(fuzz_validate(v, &bytes), Some(0));
            assert_eq!(fuzz_validate(v, &[]), None);
            let mut n = 0x9e37_79b9_u32;
            for i in 0..3000usize {
                let mut m = bytes.clone();
                n = n.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                let at = (n as usize) % m.len();
                m[at] ^= (n >> 24) as u8 | 1;
                if i % 7 == 0 {
                    m.truncate(at);
                }
                fuzz_validate(v, &m);
            }
            assert!(validate(v, &b.commit).is_ok());
        });
        let mut wide = b.commit.clone();
        wide.rows[0].up = u64::MAX;
        assert_eq!(rule(w.check(&due, by, &wide)), 13);
        let mut wide = b.commit.clone();
        if let Make::Keep { mask, .. } = &mut wide.versions[0].make {
            *mask = u64::MAX;
        }
        assert_eq!(rule(w.check(&due, by, &wide)), 8);
    }

    #[test]
    fn a_commit_weighs_every_field_it_carries_and_a_row_reads_its_seed() {
        let seat = Member::numbered(1).seat;
        let c = Commit {
            body: vec![0; 100],
            sig: vec![0; 64],
            versions: vec![
                VersionOut {
                    b: 1,
                    v: 2,
                    pool: Pool::Accounts,
                    make: Make::Seats(vec![seat, seat]),
                },
                VersionOut {
                    b: 3,
                    v: 4,
                    pool: Pool::Accounts,
                    make: Make::Keep { from_v: 5, mask: 1 },
                },
            ],
            drops: vec![1, 2, 3],
            welcomes: vec![
                WelcomeOut {
                    seat,
                    b: 1,
                    v: 2,
                    s: 1,
                    bytes: vec![0; 5],
                };
                2
            ],
            rows: vec![RowsOut {
                b: 1,
                v: 2,
                s: 1,
                up: 0,
                rows: vec![0; 7],
            }],
            seals: vec![SealOut {
                b: 1,
                v: 2,
                bytes: vec![0; 11],
            }],
            seed_welcomes: vec![SeedWelcomeOut {
                seat,
                bytes: vec![0; 13],
            }],
            keyring: vec![0; 17],
            krk: vec![KrkOut {
                to: HolderRef {
                    m: seat.m,
                    kx: [0; 32],
                },
                from_kx: [0; 32],
                bytes: vec![0; 19],
            }],
            refused: vec![Refused { seat, why: 1 }; 2],
        };
        // A seat ref weighs 33: body and signature 164, versions
        // (26 + 2 × 33) + 26, drops 3 × 10, welcomes 2 × (33 + 25 + 5),
        // rows 40 + 7, seals 20 + 11, seed welcomes 33 + 3 + 13, keyring
        // 17, KRK 17 + 64 + 3 + 19, refusals 2 × 34.
        assert_eq!(SEAT_BYTES, 33);
        assert_eq!(c.bytes(), 753);

        // Rows are 60 bytes each, in order; a set bit puts a row one seed up.
        let rows: Vec<u8> = (0..3u8).flat_map(|i| [i; ROW_BYTES]).collect();
        let r = RowsOut {
            b: 1,
            v: 2,
            s: 2,
            up: 0b010,
            rows,
        };
        for (i, seed) in [(0, 2), (1, 3), (2, 2)] {
            let (row, s) = r.row(i).unwrap();
            assert_eq!((row, s), (&[i as u8; ROW_BYTES][..], seed));
        }
        assert!(r.row(3).is_none());
    }

    #[test]
    fn a_pair_makes_an_entry_only_for_the_member_and_kind_its_endorsement_names() {
        let desk = Holder::desktop(2);
        let ik = raw_ik(&desk.ik);
        let e = desk.pair().entry(GroupKind::Text, desk.m, ik).unwrap();
        assert_eq!((e.m, e.u, e.ik, e.kx), (desk.m, None, ik, desk.pair().kx()));
        let other = MemberId::Account([3; 16]);
        assert!(desk.pair().entry(GroupKind::Text, other, ik).is_none());
        assert!(desk.pair().entry(GroupKind::Voice, desk.m, ik).is_none());
        let conn = Holder::conn(7);
        let ik = raw_ik(&conn.ik);
        let v = conn.pair().entry(GroupKind::Voice, conn.m, ik).unwrap();
        assert_eq!(v.u, Some(7));
        let t = conn.pair().entry(GroupKind::Text, conn.m, ik).unwrap();
        assert_eq!(t.u, None);
    }

    #[test]
    fn a_refusal_reads_as_its_rule_and_why() {
        let b = Bad {
            rule: 13,
            detail: "a version has no seal".into(),
        };
        assert_eq!(b.to_string(), "rule 13: a version has no seal");
    }

    #[test]
    fn the_caps_refuse_past_256_and_12_mb_and_not_at_them() {
        let (mut w, people, _) = group();
        let by = w.holders[0].by();
        let one = Member::numbered(600);
        let small = w.join_due(&[&one]);
        let b = w.build_join(&small, None).unwrap();
        let at = |n: usize| Due {
            joiners: vec![one.joiner(); n],
            ..w.due(DueKind::Join)
        };
        assert_eq!(rule(w.check(&at(257), by, &b.commit)), 15);
        assert_ne!(rule(w.check(&at(256), by, &b.commit)), 15);
        let refusals = |n: usize| {
            let mut c = b.commit.clone();
            c.refused = vec![
                Refused {
                    seat: one.seat,
                    why: 1
                };
                n
            ];
            c
        };
        assert_eq!(rule(w.check(&small, by, &refusals(257))), 15);
        assert_ne!(rule(w.check(&small, by, &refusals(256))), 15);
        let welcomes = |n: usize| {
            let mut c = b.commit.clone();
            c.welcomes = vec![c.welcomes[0].clone(); n];
            c
        };
        assert_eq!(rule(w.check(&small, by, &welcomes(257))), 15);
        assert_ne!(rule(w.check(&small, by, &welcomes(256))), 15);

        let (due, b) = fresh_with_exits(&mut w, &[people[0].seat]);
        let sized = |n: usize| {
            let mut c = b.commit.clone();
            let rest = c.bytes() - c.keyring.len();
            c.keyring = vec![0; n - rest];
            c
        };
        assert_eq!(rule(w.check(&due, by, &sized(COMMIT_MAX_BYTES + 1))), 15);
        assert_eq!(
            rule(w.check(&due, by, &sized(COMMIT_MAX_BYTES))),
            14,
            "12 MB is not over the cap"
        );
    }

    #[test]
    fn a_new_bucket_out_of_list_order_with_a_seat_twice_or_empty_is_refused() {
        let mut w = World::text(false, false);
        let by = w.holders[0].by();
        let people = accounts(10, 3);
        let due = w.join_due(&refs(&people));
        let b = w.build_join(&due, None).unwrap();
        assert_eq!(rule(w.check(&due, by, &b.commit)), 0);
        let with = |edit: &dyn Fn(&mut Vec<SeatRef>)| {
            let mut c = b.commit.clone();
            if let Make::Seats(s) = &mut c.versions[0].make {
                edit(s);
            }
            rule(w.check(&due, by, &c))
        };
        assert_eq!(with(&|s| s.reverse()), 8, "out of list order");
        assert_eq!(
            with(&|s| {
                let first = s[0];
                s.insert(0, first);
            }),
            8,
            "a seat twice"
        );
        assert_eq!(with(&|s| s.clear()), 8, "no seat");
    }

    #[test]
    fn a_names_hash_that_does_not_follow_its_parent_is_refused_under_rule_11() {
        let mut w = World::text(true, true);
        let by = w.holders[0].by();
        let due = w.join_due(&refs(&accounts(10, 2)));
        let mut b = w.build_join(&due, None).unwrap();
        let sh = SignedHeader::decode(&b.commit.body, &b.commit.sig, w.kind, w.id).unwrap();
        let mut h = sh.header().clone();
        h.names_hash = [7; 32];
        let sh = SignedHeader::sign(h, &w.holders[0].ik).unwrap();
        b.commit.body = sh.body().to_vec();
        b.commit.sig = sh.sig().to_vec();
        assert_eq!(rule(w.check(&due, by, &b.commit)), 11);
    }

    #[test]
    fn a_replace_that_swaps_another_keyholders_entry_is_refused_under_rule_2() {
        let mut w = World::text(false, false);
        w.promote(Holder::desktop(2));
        let by = w.holders[0].by();
        let new = w.holders[0].rotated();
        let due = w.replace_due(&new);
        let b = w.opening_by(0, &due, false, Some(&new), None).unwrap();
        assert_eq!(rule(w.check(&due, by, &b.commit)), 0);
        let theirs = w.holders[1].rotated().entry(GroupKind::Text);
        let mine = w.holders[0].entry(GroupKind::Text);
        let mut c = b.commit.clone();
        resign(&w, &mut c, &w.holders[0], |h| {
            h.keyholders = vec![mine, theirs];
        });
        assert_eq!(rule(w.check(&due, by, &c)), 2);
    }

    /// Why a check refused, empty for none.
    fn detail(r: Result<Applied, Bad>) -> String {
        r.err().map_or_else(String::new, |b| b.detail)
    }

    #[test]
    fn a_commit_at_its_parents_time_is_taken() {
        let (mut w, people, _) = group();
        let (due, b) = fresh_with_exits(&mut w, &[people[0].seat]);
        let k = &w.holders[0];
        let t = w.head.header().time;
        let mut c = b.commit.clone();
        resign(&w, &mut c, k, |h| h.time = t);
        assert_eq!(rule(w.check(&due, k.by(), &c)), 0);
    }

    #[test]
    fn a_genesis_under_a_generation_the_group_had_or_its_heads_is_refused() {
        let mut w = World::text(false, false);
        let first = w.head.header().gen;
        let gd = World::genesis_due(&w.holders[0], false);
        let gb = World::build_start(&w.holders[0], w.kind, w.id, false, &gd, w.now, None).unwrap();
        let a = w.check(&gd, w.holders[0].by(), &gb.commit).unwrap();
        w.take(&gd, a, &gb);
        let vol = Holder::desktop(5);
        let due = World::genesis_due(&vol, false);
        let b = World::build_start(&vol, w.kind, w.id, false, &due, w.now, None).unwrap();
        let with_gen = |gen: [u8; 16]| {
            let sh = SignedHeader::decode(&b.commit.body, &b.commit.sig, w.kind, w.id).unwrap();
            let mut h = sh.header().clone();
            h.gen = gen;
            let sh = SignedHeader::sign(h, &vol.ik).unwrap();
            Commit {
                body: sh.body().to_vec(),
                sig: sh.sig().to_vec(),
                ..b.commit.clone()
            }
        };
        assert_eq!(rule(w.check(&due, vol.by(), &b.commit)), 0);
        assert_eq!(
            rule(w.check(&due, vol.by(), &with_gen(first))),
            4,
            "a generation the group had before its head's"
        );
        let head_gen = w.head.header().gen;
        w.gens.clear();
        assert_eq!(
            rule(w.check(&due, vol.by(), &with_gen(head_gen))),
            4,
            "the head's own, though the relay lists none"
        );
    }

    #[test]
    fn a_genesis_signed_by_another_identity_of_the_volunteers_account_is_refused() {
        let vol = Holder::desktop(5);
        let other = Holder::desktop(5);
        let due = World::genesis_due(&vol, false);
        let b =
            World::build_start(&other, GroupKind::Text, TEXT_ID, false, &due, T0, None).unwrap();
        let r = World::check_start(
            GroupKind::Text,
            TEXT_ID,
            false,
            &due,
            vol.by(),
            &b.commit,
            T0,
            &[],
        );
        assert_eq!(rule(r), 2);
    }

    #[test]
    fn a_commit_sent_by_one_device_and_signed_by_another_of_its_account_is_refused() {
        let mut w = World::text(false, false);
        w.join(&refs(&accounts(10, 3)));
        w.promote(Holder::desktop(2));
        w.promote(Holder::desktop(2));
        let due = w.due(DueKind::Exits);
        let b = w.opening_by(2, &due, false, None, None).unwrap();
        assert_eq!(rule(w.check(&due, w.holders[2].by(), &b.commit)), 0);
        assert_eq!(rule(w.check(&due, w.holders[1].by(), &b.commit)), 2);
    }

    #[test]
    fn a_promotion_with_exits_rekeys_and_drops_only_their_buckets() {
        let (mut w, people, guests) = group();
        let by = w.holders[0].by();
        let mut seats: Vec<SeatRef> = guests.iter().map(|g| g.seat).collect();
        seats.push(people[0].seat);
        let due = Due {
            candidate: Some(Holder::desktop(2).candidate()),
            ..w.exits(&seats, DueKind::Promote)
        };
        let b = w.opening(&due).unwrap();
        assert_eq!(b.commit.drops.len(), 1, "the guests' bucket empties");
        assert!(b
            .commit
            .versions
            .iter()
            .any(|v| matches!(v.make, Make::Keep { .. })));
        assert_eq!(rule(w.check(&due, by, &b.commit)), 0);
        let kept = b
            .commit
            .versions
            .iter()
            .find(|v| matches!(v.make, Make::Ratchet { .. }))
            .unwrap()
            .b;
        let mut c = b.commit.clone();
        c.versions.retain(|v| v.b != kept);
        c.drops.push(kept);
        assert_eq!(rule(w.check(&due, by, &c)), 8, "a drop no exit empties");
    }

    #[test]
    fn an_exit_whose_bucket_the_commit_leaves_alone_is_refused() {
        let (mut w, people, _) = group();
        let by = w.holders[0].by();
        let due = w.exits(&[people[0].seat], DueKind::Exits);
        let quiet = w.due(DueKind::Exits);
        let b = w.opening(&quiet).unwrap();
        let upto = due.exits_upto;
        let mut c = b.commit.clone();
        resign(&w, &mut c, &w.holders[0], |h| {
            h.exits_upto = upto;
            h.removed = Removed::Count(1);
        });
        assert_eq!(rule(w.check(&due, by, &c)), 10);
    }

    #[test]
    fn a_gated_removed_list_naming_another_seat_is_refused() {
        let mut w = World::text(true, true);
        let people = accounts(10, 3);
        w.join(&refs(&people));
        let by = w.holders[0].by();
        let due = w.exits(&[people[1].seat], DueKind::Exits);
        let b = w.opening(&due).unwrap();
        assert_eq!(rule(w.check(&due, by, &b.commit)), 0);
        let other = people[2].seat;
        let mut c = b.commit.clone();
        resign(&w, &mut c, &w.holders[0], |h| {
            h.removed = Removed::List(vec![other])
        });
        assert_eq!(rule(w.check(&due, by, &c)), 11);
    }

    #[test]
    fn a_running_text_roll_keeps_its_floor_and_starts_no_other() {
        let mut w = World::text(true, false);
        w.join(&refs(&accounts(10, 5)));
        let by = w.holders[0].by();
        w.promote(Holder::desktop(2));
        w.promote(Holder::desktop(3));
        w.tick(25 * 3600);
        w.remove(1);
        w.tick(25 * 3600);
        let due = w.remove_due(1);
        let b = w.opening(&due).unwrap();
        assert_eq!(
            (b.header.header().seed, b.header.header().seed_floor),
            (2, 1)
        );
        assert_eq!(rule(w.check(&due, by, &b.commit)), 0);
        // Every bucket is re-keyed, yet no seat holds seed 2.
        let mut c = b.commit.clone();
        resign(&w, &mut c, &w.holders[0], |h| h.seed_floor = 2);
        assert_eq!(rule(w.check(&due, by, &c)), 12);
        let mut c = b.commit.clone();
        resign(&w, &mut c, &w.holders[0], |h| {
            h.seed = 3;
            h.seed_floor = 2;
        });
        assert_eq!(
            detail(w.check(&due, by, &c)),
            "a text roll never starts over a running one"
        );
    }

    #[test]
    fn a_commit_that_keeps_the_floor_reads_no_seats_seed() {
        let (mut w, people, _) = group();
        let by = w.holders[0].by();
        w.held.remove(&people[5].seat);
        let due = w.due(DueKind::Exits);
        let b = w.opening(&due).unwrap();
        assert!(b.commit.rows.is_empty());
        assert_eq!(rule(w.check(&due, by, &b.commit)), 0);
    }

    #[test]
    fn a_krk_welcome_to_no_entry_of_the_new_set_is_refused() {
        let (mut w, _, _) = group();
        let by = w.holders[0].by();
        let due = w.promote_due(&Holder::desktop(2));
        let b = w.opening(&due).unwrap();
        let mut c = b.commit.clone();
        c.krk[0].to = HolderRef {
            m: MemberId::Account([9; 16]),
            kx: [9; 32],
        };
        assert_eq!(rule(w.check(&due, by, &c)), 14);
    }

    #[test]
    fn a_seed_welcome_to_a_seat_on_the_new_floor_or_to_an_exiting_one_is_refused() {
        let mut v = World::voice();
        let first: Vec<Member> = (10..20).map(Member::conn).collect();
        v.join(&refs(&first));
        v.promote(Holder::conn(4));
        v.remove(1);
        let late: Vec<Member> = (30..33).map(Member::conn).collect();
        v.join(&refs(&late));
        v.promote(Holder::conn(5));
        let due = Due {
            remove: Some(v.holders[1].by()),
            ..v.exits(&[first[0].seat], DueKind::Remove)
        };
        let b = v.opening(&due).unwrap();
        let by = v.holders[0].by();
        assert_eq!(rule(v.check(&due, by, &b.commit)), 0);
        let welcomed: Vec<SeatRef> = b.commit.seed_welcomes.iter().map(|x| x.seat).collect();
        assert!(!welcomed.contains(&late[0].seat) && !welcomed.contains(&first[0].seat));
        let extra = |seat: SeatRef| {
            let mut c = b.commit.clone();
            c.seed_welcomes.push(SeedWelcomeOut {
                seat,
                bytes: vec![0; SMALL_WELCOME_BYTES],
            });
            detail(v.check(&due, by, &c))
        };
        let unneeded = "a seed welcome the new floor does not need";
        assert_eq!(extra(late[0].seat), unneeded, "a seat already on it");
        assert_eq!(extra(first[0].seat), unneeded, "an exiting seat");
    }

    #[test]
    fn rows_short_of_their_version_or_across_two_seeds_are_checked_row_by_row() {
        let mut w = World::text(true, false);
        let people = accounts(10, 6);
        w.join(&refs(&people));
        let by = w.holders[0].by();
        w.promote(Holder::desktop(2));
        w.promote(Holder::desktop(3));
        w.tick(25 * 3600);
        w.remove(1);
        // Two seats took their seed welcome under 2; the rest hold 1.
        for p in &people[1..3] {
            w.held.insert(p.seat, 2);
        }
        let due = w.exits(&[people[0].seat], DueKind::Exits);
        let b = w.opening(&due).unwrap();
        let r = b.commit.rows.iter().find(|r| r.up != 0).unwrap();
        assert_eq!(r.s, 1);
        assert_eq!(rule(w.check(&due, by, &b.commit)), 0);
        let mut c = b.commit.clone();
        c.rows[0].rows.pop();
        assert_eq!(rule(w.check(&due, by, &c)), 13, "a byte short");
    }

    #[test]
    fn a_seal_of_another_size_twice_or_to_another_version_is_refused() {
        let (mut w, people, _) = group();
        let by = w.holders[0].by();
        let (due, b) = fresh_with_exits(&mut w, &[people[0].seat]);
        let mut c = b.commit.clone();
        c.seals[0].bytes.pop();
        assert_eq!(rule(w.check(&due, by, &c)), 13, "short");
        let mut c = b.commit.clone();
        c.seals.push(c.seals[0].clone());
        assert_eq!(rule(w.check(&due, by, &c)), 13, "twice");
        let mut c = b.commit.clone();
        c.seals[0].v ^= 1;
        assert_eq!(rule(w.check(&due, by, &c)), 13, "another version");
    }
}
