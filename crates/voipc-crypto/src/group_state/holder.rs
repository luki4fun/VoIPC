//! Keyholder duty (3g): volunteering, the relay's dues taken whole and checked, the keyring
//! brought up to the head, the lists a build needs, commits built off the lock
//! (`take_build` → `BuildJob::step` → `built`), checked by the validator over this device's
//! own view and paced out in parts (`next_frame`), rebased on `HEAD_MOVED`, declined where
//! the rules forbid, and a desktop pair's `KeyholdersReplace` at a seat-key rotation.
//!
//! What it keeps on the device (`HolderKeep`, in `gk_local.bin`): a desktop's keyholder
//! pair, the old one until its Replace is done, and the seats its Joins sealed to that no
//! header named yet (§5.2). Every check of a joiner or candidate is C1's or C3b's
//! (`take_endorsement`); every commit is `group_key::build`'s and passes
//! `commit::validate` before it goes.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Duration;

use libsignal_protocol::{IdentityKey, IdentityKeyPair};
use serde::{Deserialize, Serialize};
use voipc_protocol::gk::{
    self, decline, due as due_code, join_refused, stale, DuePiece, EndorsedPair, GkMember,
    KeyringPiece, Part, Parts, Seq,
};
use voipc_protocol::messages::{ClientMessage, ServerMessage};
use zeroize::{Zeroize, Zeroizing};

use super::member::Member;
use super::{
    seat_keys, take_endorsement, EndorsementBad, GkCtx, GkEvent, GkOut, Platform, Warn, Who,
};
use crate::group_key::build::{
    self, build_genesis, build_join, build_opening, build_regenesis, build_seed_welcomes, kx_tag,
    plan_opening, BucketNow, Holding, Lists, OpeningAsk, Replacing, RowBases, Start,
};
use crate::group_key::commit::{
    self, list_order, validate, Candidate, Due, DueKind, Exit, GroupView, HeadView, HolderRef,
    Joiner, Listed, Pair, ReplaceAsk,
};
use crate::group_key::timers::{
    BROWSER_MAX_SEATS, EPOCH_AGE_MAX_SECS, KEYHOLDER_SKEW_SECS, MAX_GUEST_KEYHOLDERS,
    OLD_KEYS_SECS, PIECE_MAX_BYTES, SEED_WELCOMES_A_FRAME,
};
use crate::group_key::{
    check_carried, counter_flagged, keyholder_set_digest, open_keyring_welcome, take_keyring, wire,
    Endorsement, Group, GroupKind, Keyholder, Keyring, Kind, Me, MemberId, Origin, Pool, SeatPair,
    SeatPublic, SeatRef, SeedRolls, Seen, SignedHeader, Version, CLOCK_SLACK, MAX_KEYHOLDERS,
};

/// A KeyholdReplace is done once no tracked group names the old pair this long after it
/// went: the relay asks the Replaces at once, so a group still to swap shows by then.
const REPLACE_SETTLE_MS: u64 = 5_000;

// ── What the device keeps ─────────────────────────────────────────────────

/// Private key bytes that wipe themselves and never print.
#[derive(Clone, Default, Serialize, Deserialize)]
struct Secret(Vec<u8>);

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(..)")
    }
}

/// A desktop keyholder pair (0x03) with its endorsement, as kept.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct KeptPair {
    account: [u8; 16],
    keys: Secret,
    n: u32,
    made: u64,
    sig: Vec<u8>,
    /// For the old pair: when the rotation replaced it (unix seconds).
    since: u64,
}

/// A pair this device holds keys with, opened.
#[derive(Clone)]
struct Mine {
    m: MemberId,
    pair: SeatPair,
    wire: Pair,
}

impl Mine {
    fn kx(&self) -> [u8; 32] {
        self.wire.kx()
    }

    fn by(&self) -> HolderRef {
        HolderRef {
            m: self.m,
            kx: self.kx(),
        }
    }
}

impl KeptPair {
    /// A new desktop pair of `account`, endorsed 0x03 with its counter `n` now.
    fn make(identity: &IdentityKeyPair, account: [u8; 16], n: u32, now: u64) -> Option<KeptPair> {
        let pair = SeatPair::generate();
        let e = Endorsement::sign(
            identity,
            Origin::Desktop,
            MemberId::Account(account),
            n,
            now,
            &pair.public(),
        )?;
        Some(KeptPair {
            account,
            keys: Secret(pair.to_bytes().to_vec()),
            n,
            made: e.made,
            sig: e.sig.to_vec(),
            since: now,
        })
    }

    fn open(&self) -> Option<Mine> {
        let pair = SeatPair::from_bytes(&self.keys.0)?;
        let m = MemberId::Account(self.account);
        let endorsement = Endorsement {
            origin: Origin::Desktop,
            m,
            n: self.n,
            made: self.made,
            sig: self.sig[..].try_into().ok()?,
        };
        let wire = Pair {
            keys: pair.public(),
            endorsement,
        };
        Some(Mine { m, pair, wire })
    }
}

/// Seats a Join of this device sealed to, until a later header descends from it (§5.2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Unnamed {
    group: String,
    gen: [u8; 16],
    epoch: u32,
    join: u32,
    d: [u8; 32],
    seats: u32,
    /// When it went, unix seconds.
    at: u64,
    /// The member took it.
    taken: bool,
}

/// What a keyholder keeps on this device (3d `gk_local.bin`: its pair, the old one until its
/// Replace is done, the seats it sealed that no header named yet).
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct HolderKeep {
    pair: Option<KeptPair>,
    old: Option<KeptPair>,
    unnamed: Vec<Unnamed>,
}

impl std::fmt::Debug for HolderKeep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HolderKeep")
            .field("pair", &self.pair.as_ref().map(|p| p.n))
            .field("old", &self.old.as_ref().map(|p| p.n))
            .field("unnamed", &self.unnamed.len())
            .finish()
    }
}

// ── Jobs ──────────────────────────────────────────────────────────────────

/// What a job makes.
enum What {
    Commit,
    /// A seed-welcome page under the head's seed.
    Welcomes(Vec<(SeatRef, SeatPublic)>),
}

/// Everything a build needs, owned.
struct Task {
    what: What,
    kind: GroupKind,
    id: String,
    stored: bool,
    due: Due,
    refused: Vec<commit::Refused>,
    head: Option<SignedHeader>,
    kh: Option<SignedHeader>,
    ring: Option<Keyring>,
    krk: Zeroizing<[u8; 32]>,
    rolls: SeedRolls,
    me: Mine,
    ik: IdentityKeyPair,
    /// A Replace's new pair and entry.
    new: Option<(Mine, Keyholder)>,
    lists: Lists,
    held: HashMap<SeatRef, u32>,
    pairs: Vec<SeatPublic>,
    seed_seats: HashMap<SeatRef, SeatPublic>,
    finish: bool,
    now: u64,
    roster: Vec<u32>,
    reuse: Option<build::Built>,
    cache: RowBases,
}

/// What a job made.
enum Done {
    Commit(Box<build::Built>),
    Welcomes {
        gen: [u8; 16],
        s: u32,
        list: Vec<commit::SeedWelcomeOut>,
    },
}

/// A commit to build off the `SignalState` lock: owned and `Send`.
pub struct BuildJob {
    group: String,
    due: u64,
    attempt: u64,
    task: Option<Box<Task>>,
}

impl BuildJob {
    /// Works on for at most `budget`; the job finished or failed once it says so. A build
    /// runs whole at its first step: the builders are not cut into slices yet.
    pub fn step(&mut self, _budget: Duration) -> Option<Built> {
        let mut t = self.task.take()?;
        let out = t.run();
        Some(Built {
            group: std::mem::take(&mut self.group),
            due: self.due,
            attempt: self.attempt,
            out,
            cache: std::mem::take(&mut t.cache),
        })
    }
}

/// A finished or failed job, for `GroupKeying::built`.
pub struct Built {
    group: String,
    due: u64,
    attempt: u64,
    out: Result<Done, String>,
    cache: RowBases,
}

fn build_error(e: build::BuildError) -> String {
    match e {
        build::BuildError::Key(k) => k.to_string(),
        build::BuildError::Header(r) => r.to_string(),
        build::BuildError::Refuse(why) => why.to_string(),
    }
}

impl Task {
    fn run(&mut self) -> Result<Done, String> {
        if let What::Welcomes(seats) = &self.what {
            let head = self.head.as_ref().ok_or("no head")?;
            let ring = self.ring.as_ref().ok_or("no keyring")?;
            let h = head.header();
            let g = Group::new(self.kind, &self.id, h.gen).map_err(|e| e.to_string())?;
            let seed = ring.seed(h.seed).ok_or("the keyring holds no head seed")?;
            let me = Me {
                m: self.me.m,
                keys: &self.me.pair,
            };
            let list = build_seed_welcomes(&g, h.seed, seed, &me, seats).map_err(build_error)?;
            return Ok(Done::Welcomes {
                gen: h.gen,
                s: h.seed,
                list,
            });
        }
        let b = self.build().map_err(build_error)?;
        self.check(&b)?;
        Ok(Done::Commit(Box::new(b)))
    }

    fn build(&mut self) -> Result<build::Built, build::BuildError> {
        let me = Me {
            m: self.me.m,
            keys: &self.me.pair,
        };
        let refuse = build::BuildError::Refuse;
        match self.due.kind {
            DueKind::Genesis | DueKind::Regenesis => {
                let entry = self
                    .me
                    .wire
                    .entry(self.kind, self.me.m, raw(&self.ik))
                    .ok_or(refuse("this pair holds no keys of this kind of group"))?;
                let joiners: Vec<&Joiner> = self.due.joiners.iter().collect();
                let st = Start {
                    kind: self.kind,
                    id: &self.id,
                    me,
                    ik: &self.ik,
                    entry,
                    joiners: &joiners,
                    gated: self.due.gated,
                    stored: self.stored,
                    now: self.now,
                };
                if self.due.kind == DueKind::Genesis {
                    build_genesis(&st, &mut self.cache)
                } else {
                    let head = self.head.as_ref().ok_or(refuse("no head"))?;
                    build_regenesis(
                        &st,
                        head,
                        &self.due.exits,
                        self.due.exits_upto,
                        &mut self.cache,
                    )
                }
            }
            dk => {
                let (Some(head), Some(kh), Some(ring)) = (&self.head, &self.kh, &self.ring) else {
                    return Err(refuse("no keyring at the head"));
                };
                let g = Group::new(self.kind, &self.id, head.header().gen)?;
                let seed = head.header().seed;
                let held_map = &self.held;
                let held = |s: &SeatRef| held_map.get(s).copied().or(Some(seed));
                let hold = Holding {
                    g: &g,
                    head,
                    kh,
                    ring,
                    krk: &self.krk,
                    me,
                    ik: &self.ik,
                    lists: &self.lists,
                    held: &held,
                    rolls: self.rolls,
                    stored: self.stored,
                };
                if dk == DueKind::Join {
                    let out: HashSet<SeatRef> = self.refused.iter().map(|r| r.seat).collect();
                    let seat: Vec<&Joiner> = self
                        .due
                        .joiners
                        .iter()
                        .filter(|j| !out.contains(&j.seat))
                        .collect();
                    build_join(
                        &hold,
                        &seat,
                        self.refused.clone(),
                        self.now,
                        &mut self.cache,
                        self.reuse.as_ref(),
                    )
                } else {
                    let pairs = &self.pairs;
                    let pair_of = |k: &Keyholder| {
                        pairs
                            .iter()
                            .find(|p| p.dh_bytes()[1..] == k.kx && p.tag_kem() == k.tag_kk)
                            .cloned()
                    };
                    let replace = self.new.as_ref().map(|(n, entry)| Replacing {
                        me: Me {
                            m: n.m,
                            keys: &n.pair,
                        },
                        entry: *entry,
                    });
                    let ask = OpeningAsk {
                        kind: dk.header_kind(),
                        exits: &self.due.exits,
                        exits_upto: self.due.exits_upto,
                        refresh: dk == DueKind::Refresh,
                        gated: self.due.gated,
                        candidate: self.due.candidate.as_ref(),
                        remove: self.due.remove,
                        replace,
                        finish: self.finish,
                        seed_seats: &self.seed_seats,
                        pairs: &pair_of,
                        now: self.now,
                    };
                    build_opening(&hold, &ask, &mut self.cache, self.reuse.as_ref())
                }
            }
        }
    }

    /// The validator over this device's own view (plan 2c): the head and keyring it built
    /// on, the lists it fetched (a version whose list it did not need shows by its leaf
    /// alone), each seat's seed as the due said.
    fn check(&self, b: &build::Built) -> Result<(), String> {
        let anew = matches!(self.due.kind, DueKind::Genesis | DueKind::Regenesis);
        let leaves: Vec<Listed> = match (&self.ring, anew) {
            (Some(ring), false) => ring
                .buckets
                .iter()
                .map(|kb| {
                    let mut seats: Vec<SeatRef> = self
                        .lists
                        .get(&kb.version())
                        .map(|l| l.iter().map(|x| x.seat).collect())
                        .unwrap_or_default();
                    list_order(&mut seats);
                    Listed {
                        leaf: kb.leaf(),
                        seats,
                    }
                })
                .collect(),
            _ => vec![],
        };
        let joiners: HashSet<SeatRef> = self.due.joiners.iter().map(|j| j.seat).collect();
        let seed = self.head.as_ref().map_or(0, |h| h.header().seed);
        let held =
            |s: &SeatRef| (!joiners.contains(s)).then(|| self.held.get(s).copied().unwrap_or(seed));
        let used = |_: u64| false;
        let head = match (self.due.kind, &self.head, &self.kh) {
            (DueKind::Genesis, _, _) => None,
            (_, Some(head), Some(kh)) => Some(HeadView { head, kh }),
            _ => return Err("no head to check against".into()),
        };
        let view = GroupView {
            kind: self.kind,
            id: &self.id,
            stored: self.stored,
            head,
            leaves: &leaves,
            held: &held,
            due: &self.due,
            by: self.me.by(),
            rolls: self.rolls,
            known_gens: &[],
            used_v: &used,
            now: self.now,
            roster: &self.roster,
            no_keyholder_since: (self.due.kind == DueKind::Regenesis).then_some(0),
        };
        validate(&view, &b.commit)
            .map(|_| ())
            .map_err(|bad| format!("own check: {bad}"))
    }
}

// ── Per group ─────────────────────────────────────────────────────────────

/// The keyring at a head, as this keyholder holds it.
struct Ring {
    head: SignedHeader,
    kh: SignedHeader,
    ring: Keyring,
    krk: Zeroizing<[u8; 32]>,
    rolls: SeedRolls,
}

enum Stage {
    /// Waiting for the head the due was asked on, and the keyring at it.
    Head,
    /// Waiting for the lists the build needs.
    Lists,
    /// A job is out (`take_build`).
    Building,
    /// The commit went; until the relay shows it taken, or stale.
    Sent(Box<build::Built>),
}

/// The due in hand.
struct Work {
    due: u64,
    piece: DuePiece,
    /// The build's time (unix seconds), fixed at the ask so the lists asked are the build's.
    now: u64,
    stage: Stage,
    attempt: u64,
    lists_asked: bool,
    /// The attempt the head moved under, for a rebase.
    stale: Option<Box<build::Built>>,
    /// Joins of this due that went stale, by `D`, with the seats they sealed: the rebase
    /// names them again, else they are told once the due is let go (§5.2).
    rebased: Vec<([u8; 32], Vec<SeatRef>)>,
}

/// A `KeyringIn` sequence's key: `(gen, epoch, join)`.
type RingAt = ([u8; 16], u32, u32);

#[derive(Default)]
struct Hold {
    kind: Option<GroupKind>,
    dues: Option<Parts<u64, DuePiece>>,
    keyring: Option<Parts<RingAt, KeyringPiece>>,
    keyring_asked: Option<RingAt>,
    ring: Option<Ring>,
    cache: Option<RowBases>,
    lists: Lists,
    lists_gen: [u8; 16],
    lists_out: usize,
    work: Option<Work>,
    /// One of this device's pairs is in the head's keyholder set.
    in_set: bool,
    /// `KX` of the pair this device holds keys with here now.
    kx: Option<[u8; 32]>,
    resigned: bool,
}

impl Hold {
    fn dues(&mut self) -> &mut Parts<u64, DuePiece> {
        self.dues.get_or_insert_with(|| Parts::new(Seq::Due))
    }

    fn keyring_parts(&mut self) -> &mut Parts<RingAt, KeyringPiece> {
        self.keyring.get_or_insert_with(|| Parts::new(Seq::Keyring))
    }
}

/// The rolls at `h`, from those at the header before it where that is its parent; else
/// what can be said for sure (§5.6): a raise seen sets the age from `h`, which only starts a
/// roll later than the relay would, never earlier.
fn rolls_to(before: Option<(SeedRolls, &SignedHeader)>, h: &SignedHeader) -> SeedRolls {
    let hd = h.header();
    if hd.kind.starts_anew() {
        return SeedRolls::at_start(hd);
    }
    match before {
        Some((r, p)) if hd.parent == p.d() => r.after(p.header(), hd),
        Some((r, p)) if p.header().gen == hd.gen && hd.seed == p.header().seed => SeedRolls {
            raised: r.raised,
            removal: r.removal || hd.kind == Kind::KeyholdersRemove,
        },
        _ => SeedRolls {
            raised: hd.time,
            removal: hd.kind == Kind::KeyholdersRemove,
        },
    }
}

fn raw(ik: &IdentityKeyPair) -> [u8; 32] {
    ik.public_key()
        .public_key_bytes()
        .try_into()
        .expect("an X25519 key is 32 bytes")
}

fn same_ik(ik: &IdentityKeyPair) -> IdentityKeyPair {
    IdentityKeyPair::new(*ik.identity_key(), *ik.private_key())
}

fn kx_of(pair: &SeatPair) -> [u8; 32] {
    pair.public().dh_bytes()[1..].try_into().expect("33 bytes")
}

/// A due's parts as one: its scalars from the first, its lists in part order.
fn merge_due(parts: Vec<DuePiece>) -> Option<DuePiece> {
    let mut it = parts.into_iter();
    let mut p = it.next()?;
    for q in it {
        p.joins.extend(q.joins);
        p.exits.extend(q.exits);
        p.pairs.extend(q.pairs);
        p.held.extend(q.held);
        p.seed_seats.extend(q.seed_seats);
        p.promote = p.promote.or(q.promote);
        p.remove = p.remove.or(q.remove);
    }
    Some(p)
}

fn encoded<T: Serialize>(x: &T) -> usize {
    postcard::experimental::serialized_size(x).unwrap_or(usize::MAX)
}

/// Why a due joiner is left out (`join_refused`), or `None` to seat it (§5.2): its
/// endorsement under its `IK` for this kind of seat, the pin or TOFU, a gated group's
/// accounts only, and the counter rules (`take_endorsement`: §11.8's time rule at `at`, the
/// Join's own time, a guest's counter 0), which count it toward its account's highest once
/// it passes.
fn joiner_why(
    kind: GroupKind,
    gated: bool,
    j: &Joiner,
    at: u64,
    c: &mut GkCtx,
    seated: &HashSet<SeatRef>,
) -> Option<u8> {
    let e = &j.endorsement;
    let fits = match (kind, j.seat.m, e.origin, e.m) {
        (GroupKind::Text, MemberId::Account(a), Origin::VaultSeat, MemberId::Account(b)) => a == b,
        (GroupKind::Text, MemberId::Conn(u), Origin::Connection, MemberId::Conn(v)) => u == v,
        (GroupKind::Voice, MemberId::Account(_), Origin::Connection, MemberId::Conn(_)) => true,
        (GroupKind::Voice, MemberId::Conn(u), Origin::Connection, MemberId::Conn(v)) => u == v,
        _ => false,
    };
    let signed = super::ik_serialized(&j.ik)
        .and_then(|b| IdentityKey::decode(&b).ok())
        .is_some_and(|ik| e.verify(&ik, &j.keys));
    if !fits || !signed || j.keys.seat(j.seat.m) != j.seat {
        return Some(join_refused::ENDORSEMENT);
    }
    if kind == GroupKind::Text && gated && j.seat.m.is_conn() {
        return Some(join_refused::GUEST_IN_GATED);
    }
    if seated.contains(&j.seat) {
        return Some(join_refused::ALREADY_SEATED);
    }
    let account = j.seat.m.account();
    let pinned = account.and_then(|a| c.pins.pin(&a));
    if pinned.is_some_and(|p| p != j.ik) {
        return Some(join_refused::PIN);
    }
    // A voice seat is the connection's pair, made once a connection (plan §5): an older one
    // is held to the counter rule alone and raises nothing (P3 finding 5's earliest `made`)
    let aged = kind == GroupKind::Voice
        && e.origin == Origin::Connection
        && e.made < at.saturating_sub(CLOCK_SLACK);
    let taken = match account {
        Some(a) if aged => match counter_flagged(e.n, at, c.pins.seen(&a)) {
            Some(highest) => Err(EndorsementBad::OldCounter { n: e.n, highest }),
            None => Ok(()),
        },
        // A voice seat named by its connection is a guest's or, in an anonymous room, a
        // signed-in member's (§11.8: its pair carries the account's counter); no account is
        // named to hold that counter to, so it is taken as it comes and raises nothing
        None if kind == GroupKind::Voice => Ok(()),
        _ => take_endorsement(c.pins, account, e, at),
    };
    match taken {
        Ok(()) => {}
        Err(EndorsementBad::OldCounter { .. }) => return Some(join_refused::OLD_COUNTER),
        Err(_) => return Some(join_refused::ENDORSEMENT),
    }
    if let (Some(a), None) = (account, pinned) {
        c.pins.pin_new(a, j.ik, c.now);
    }
    None
}

/// Whether the candidate of a Promote may be added (§5.6): an entry its pair may make in
/// this kind of group, endorsed by its `IK` (pinned, or pinned now), a counter not below the
/// highest seen for its account at this time (a guest's 0), and no guest past the limits.
/// Seating is the relay's word. A desktop pair is made once and kept, so its `made` is not
/// held to the ask's time as a joiner's is; a higher counter counts toward its account.
fn candidate_ok(
    kind: GroupKind,
    gated: bool,
    set: &[Keyholder],
    cand: &Candidate,
    c: &mut GkCtx,
) -> bool {
    let e = &cand.pair.endorsement;
    if cand.pair.entry(kind, cand.m, cand.ik).is_none() || set.len() >= MAX_KEYHOLDERS {
        return false;
    }
    let signed = super::ik_serialized(&cand.ik)
        .and_then(|b| IdentityKey::decode(&b).ok())
        .is_some_and(|ik| e.verify(&ik, &cand.pair.keys));
    if !signed {
        return false;
    }
    match cand.m.account() {
        Some(a) => {
            let pinned = c.pins.pin(&a);
            if pinned.is_some_and(|p| p != cand.ik) {
                return false;
            }
            let seen = c.pins.seen(&a);
            if counter_flagged(e.n, c.secs(), seen).is_some() {
                return false;
            }
            if pinned.is_none() {
                c.pins.pin_new(a, cand.ik, c.now);
            }
            if seen.is_none_or(|s| e.n > s.n) {
                let s = Seen {
                    n: e.n,
                    made: e.made,
                };
                c.pins.raise(a, s, false);
            }
            true
        }
        None => {
            let guests = set.iter().filter(|k| k.m.is_conn()).count();
            e.n == 0 && (kind == GroupKind::Voice || (!gated && guests < MAX_GUEST_KEYHOLDERS))
        }
    }
}

// ── The duty ──────────────────────────────────────────────────────────────

/// This connection's keyholder duty, across its groups.
#[derive(Default)]
pub(super) struct Duty {
    keep: HolderKeep,
    /// `keep` moved since it was last handed out (`take_keep`).
    dirty: bool,
    desk: Option<Mine>,
    old: Option<Mine>,
    /// `KeyholdVolunteer{on}` went and no `{on: false}` since.
    offered: bool,
    /// This connection asked `KeyholdReplace`; and from when, by the ticks' clock (ms).
    replacing: Option<Option<u64>>,
    /// The relay's clock less this device's, seconds, at `GroupKeys`.
    skew: i64,
    in_call: bool,
    holds: HashMap<String, Hold>,
    /// Commit parts and welcome pages to go, in order: (group, due, frame).
    upload: VecDeque<(String, u64, ClientMessage)>,
    jobs: VecDeque<BuildJob>,
    attempts: u64,
}

impl Duty {
    /// What this device kept (`LocalGk::holder`), at `GroupKeys`.
    pub(super) fn keep_in(&mut self, keep: &HolderKeep) {
        self.keep = keep.clone();
        self.desk = keep.pair.as_ref().and_then(KeptPair::open);
        self.old = keep.old.as_ref().and_then(KeptPair::open);
        self.dirty = false;
    }

    /// What to keep, when it moved since last asked.
    pub(super) fn take_keep(&mut self) -> Option<HolderKeep> {
        std::mem::take(&mut self.dirty).then(|| self.keep.clone())
    }

    /// At `GroupKeys`: a volunteer offers itself (`KeyholdVolunteer`).
    pub(super) fn start(&mut self, who: &mut Who, out: &mut GkOut) {
        let now = crate::time::now_millis();
        self.skew = who.relay_clock as i64 - (now / 1000) as i64;
        self.volunteer(who, now, out);
    }

    fn uses_desk(who: &Who) -> bool {
        who.platform == Platform::Desktop && who.account.is_some()
    }

    /// The desktop pair, made at its first need and replaced when the account's counter
    /// moved past it (§5.11): the old one is kept until its Replace is done.
    fn desk(&mut self, who: &Who, now: u64) -> Option<()> {
        let (account, n) = (who.account?, who.seat_keys.as_ref()?.n);
        let behind = self.desk.as_ref().is_some_and(|d| d.wire.endorsement.n < n);
        if self.desk.is_some() && !(behind && self.old.is_none()) {
            return Some(());
        }
        let kept = KeptPair::make(&who.identity, account, n, now / 1000)?;
        let mine = kept.open()?;
        if behind {
            let mut old = self.keep.pair.take()?;
            old.since = now / 1000;
            self.keep.old = Some(old);
            self.old = self.desk.take();
            self.replacing = None;
        }
        self.keep.pair = Some(kept);
        self.desk = Some(mine);
        self.dirty = true;
        Some(())
    }

    /// The connection's pair, opened (0x02).
    fn conn(who: &mut Who, now: u64) -> Option<Mine> {
        let ep = seat_keys::conn_pair(who, now)?;
        let wire = wire::pair(&ep, GkMember::Conn(who.user_id)).ok()?;
        let pair = who.conn.pair()?.clone();
        let m = who
            .account
            .map_or(MemberId::Conn(who.user_id), MemberId::Account);
        Some(Mine { m, pair, wire })
    }

    /// The pair this device volunteers with: a signed-in desktop's own (the old one while
    /// its Replace is out), else the connection's.
    fn volunteer_pair(&mut self, who: &mut Who, now: u64) -> Option<Mine> {
        if Self::uses_desk(who) {
            self.desk(who, now)?;
            return self.old.clone().or_else(|| self.desk.clone());
        }
        Self::conn(who, now)
    }

    /// This device's pairs a group of `kind` may name, the one it holds keys with now first.
    fn my_kxs(&self, who: &Who, kind: GroupKind) -> Vec<[u8; 32]> {
        if kind == GroupKind::Text && Self::uses_desk(who) {
            return self.desk.iter().chain(&self.old).map(Mine::kx).collect();
        }
        who.conn.pair().map(kx_of).into_iter().collect()
    }

    /// The pair of this device a set names: the one its entry holds.
    fn pair_in(&self, who: &mut Who, kind: GroupKind, set: &[Keyholder], now: u64) -> Option<Mine> {
        let named = |m: &Mine| set.iter().any(|k| k.kx == m.kx() && k.m == m.m);
        if kind == GroupKind::Text && Self::uses_desk(who) {
            return self
                .old
                .iter()
                .chain(&self.desk)
                .find(|m| named(m))
                .cloned();
        }
        Self::conn(who, now).filter(named)
    }

    fn volunteer(&mut self, who: &mut Who, now: u64, out: &mut GkOut) {
        if !who.on || !who.help || who.platform == Platform::Phone {
            return;
        }
        if who.platform == Platform::Browser && (!who.visible || self.in_call) {
            return;
        }
        let Some(mine) = self.volunteer_pair(who, now) else {
            return;
        };
        out.send.push(ClientMessage::KeyholdVolunteer {
            on: true,
            platform: who.platform.code(),
            pair: Some(EndorsedPair::from(&mine.wire)),
        });
        self.offered = true;
        self.ask_replace(out);
    }

    /// `KeyholdReplace` from the connection volunteering with the old pair (R1: it must).
    fn ask_replace(&mut self, out: &mut GkOut) {
        if let (Some(old), Some(new), true) = (&self.old, &self.desk, self.offered) {
            out.send.push(ClientMessage::KeyholdReplace {
                old: kx_tag(&old.kx()),
                pair: EndorsedPair::from(&new.wire),
            });
            self.replacing = Some(None);
        }
    }

    /// `EpochDue`, `EpochStale`, `EpochLists`, `KeyringIn`.
    pub(super) fn frame(
        &mut self,
        who: &mut Who,
        groups: &mut std::collections::BTreeMap<String, Member>,
        msg: &ServerMessage,
        c: &mut GkCtx,
        out: &mut GkOut,
    ) {
        if !who.on {
            return;
        }
        match msg {
            ServerMessage::EpochDue {
                group,
                due,
                part,
                last,
                piece,
            } => {
                let Some(m) = groups.get(group) else {
                    return;
                };
                self.sync(who, m, out);
                let bytes = encoded(&**piece);
                let hold = self.holds.entry(group.clone()).or_default();
                let took = hold
                    .dues()
                    .take(*due, *part, *last, (**piece).clone(), bytes);
                if let Part::Whole(d, parts) = took.part {
                    if let Some(p) = merge_due(parts) {
                        self.on_due(who, m, d, p, c, out);
                    }
                }
            }
            ServerMessage::EpochStale {
                group,
                due,
                reason,
                detail,
                head,
            } => {
                let Some(m) = groups.get(group) else {
                    return;
                };
                self.sync(who, m, out);
                self.on_stale(m, *due, *reason, detail, head.as_ref());
                self.advance(who, m, c, out);
            }
            ServerMessage::EpochLists {
                group,
                gen,
                lists,
                more,
            } => {
                let Some(m) = groups.get(group) else {
                    return;
                };
                let Some(hold) = self.holds.get_mut(group) else {
                    return;
                };
                if *gen == hold.lists_gen {
                    for l in lists.iter().filter(|l| l.check().is_ok()) {
                        let (v, seats) = wire::list(l.clone());
                        hold.lists.insert(v, seats);
                    }
                }
                if !more {
                    hold.lists_out = hold.lists_out.saturating_sub(1);
                }
                self.advance(who, m, c, out);
            }
            ServerMessage::KeyringIn {
                group,
                gen,
                epoch,
                join,
                part,
                last,
                piece,
            } => {
                let Some(m) = groups.get(group) else {
                    return;
                };
                let bytes = encoded(piece);
                let hold = self.holds.entry(group.clone()).or_default();
                let took = hold.keyring_parts().take(
                    (*gen, *epoch, *join),
                    *part,
                    *last,
                    piece.clone(),
                    bytes,
                );
                if let Part::Whole(at, parts) = took.part {
                    if let Err(why) = self.take_ring(who, m, at, parts, c.now) {
                        tracing::warn!(%group, why, "the keyring did not open");
                        self.give_up(m, decline::NOT_READY, why, out);
                        return;
                    }
                    self.advance(who, m, c, out);
                }
            }
            _ => {}
        }
    }

    /// Whether this device holds keys in `group`: it then reads every name it takes.
    pub(super) fn holds(&self, group: &str) -> bool {
        self.holds.get(group).is_some_and(|h| h.in_set)
    }

    /// The `KX` of this device's own entry in `group`, if it holds one: the pair it holds
    /// keys with now, so a Replace of its own is no swap it did not make.
    pub(super) fn own_kx(&self, group: &str) -> Option<[u8; 32]> {
        self.holds.get(group).and_then(|h| h.kx)
    }

    /// The member took a header (`EpochIn`): each pushed head is seen, so a Join of ours is
    /// met as the head or its parent however fast the next ones come (§5.2).
    pub(super) fn head_taken(&mut self, who: &mut Who, m: &Member, out: &mut GkOut) {
        if who.on {
            self.sync(who, m, out);
        }
    }

    /// Where this device stands in `m`'s group: in its set or not, a commit of its own the
    /// member took, a resignation the rules want (§5.6).
    fn sync(&mut self, who: &mut Who, m: &Member, out: &mut GkOut) {
        let kind = m.t.kind;
        let kxs = self.my_kxs(who, kind);
        let hold = self.holds.entry(m.t.group.clone()).or_default();
        hold.kind = Some(kind);
        let set: &[Keyholder] = m.kh.as_ref().map_or(&[], |k| &k.header().keyholders);
        let mine = set.iter().find(|k| kxs.contains(&k.kx));
        hold.in_set = mine.is_some();
        hold.kx = mine.and(kxs.first().copied());
        // Our commit the member took
        let taken = match (&hold.work, &m.head) {
            (
                Some(Work {
                    stage: Stage::Sent(b),
                    ..
                }),
                Some(h),
            ) => b.header.d() == h.d(),
            _ => false,
        };
        if taken {
            if let Some(Work {
                stage: Stage::Sent(b),
                ..
            }) = hold.work.take()
            {
                adopt(hold, *b);
            }
        }
        // A guest gives way to an account keyholder, a browser to a desktop (§5.6)
        if let (Some(k), GroupKind::Text, false) = (mine, kind, hold.resigned) {
            let guest = k.m.is_conn() && set.iter().any(|x| x.m.account().is_some());
            let browser = who.platform == Platform::Browser
                && set.iter().any(|x| x.origin == Origin::Desktop as u8);
            if guest || browser {
                out.send.push(ClientMessage::KeyholdResign {
                    group: m.t.group.clone(),
                    entry: None,
                });
                hold.resigned = true;
            }
        }
        if !hold.in_set {
            hold.resigned = false;
        }
        // The seats our Joins sealed, met at the head or among the headers taken since the
        // last look (a catch-up carries many)
        let head = m.head.as_ref().map(|h| (h.d(), h.header().parent));
        for u in self
            .keep
            .unnamed
            .iter_mut()
            .filter(|u| u.group == m.t.group)
        {
            let met = head
                .iter()
                .chain(m.took.iter())
                .any(|(d, parent)| u.d == *d || u.d == *parent);
            if !u.taken && met {
                u.taken = true;
                self.dirty = true;
            }
        }
    }

    /// A whole `EpochDue`.
    fn on_due(
        &mut self,
        who: &mut Who,
        m: &Member,
        due: u64,
        p: DuePiece,
        c: &mut GkCtx,
        out: &mut GkOut,
    ) {
        let group = m.t.group.clone();
        let hold = self.holds.entry(group.clone()).or_default();
        // The relay asks the next due on the commit it took: ours, taken
        if let Some(Work {
            stage: Stage::Sent(b),
            ..
        }) = &hold.work
        {
            if b.header.d() == p.parent {
                if let Some(Work {
                    stage: Stage::Sent(b),
                    ..
                }) = hold.work.take()
                {
                    adopt(hold, *b);
                }
            }
        }
        // A new due replaces what was in hand
        self.drop_work(&group);
        if let Some((why, detail)) = self.refuses(who, m, &p, out) {
            out.send.push(ClientMessage::EpochDecline {
                group,
                due,
                why,
                detail: detail.into(),
            });
            return;
        }
        self.attempts += 1;
        let hold = self.holds.entry(group).or_default();
        hold.work = Some(Work {
            due,
            piece: p,
            now: c.secs(),
            stage: Stage::Head,
            attempt: self.attempts,
            lists_asked: false,
            stale: None,
            rebased: vec![],
        });
        self.advance(who, m, c, out);
    }

    /// A decline the rules want for this due, before anything is fetched or built; with
    /// the resignations they also want (§5.6 "refuses or resigns").
    fn refuses(
        &mut self,
        who: &Who,
        m: &Member,
        p: &DuePiece,
        out: &mut GkOut,
    ) -> Option<(u8, &'static str)> {
        let text = m.t.kind == GroupKind::Text;
        let resign = |out: &mut GkOut| {
            out.send.push(ClientMessage::KeyholdResign {
                group: m.t.group.clone(),
                entry: None,
            })
        };
        if text && who.platform == Platform::Phone {
            return Some((decline::PLATFORM, "a phone holds no text group's keys"));
        }
        if self.skew.unsigned_abs() > KEYHOLDER_SKEW_SECS {
            return Some((decline::CLOCK, "this device's clock is off the relay's"));
        }
        let gated = p.gated || m.head.as_ref().is_some_and(|h| h.header().gated);
        if text && who.platform == Platform::Browser {
            if !who.visible || self.in_call {
                return Some((decline::NOT_READY, "the page is hidden or in a call"));
            }
            if m.head
                .as_ref()
                .is_some_and(|h| h.header().seats > BROWSER_MAX_SEATS)
            {
                resign(out);
                return Some((
                    decline::PLATFORM,
                    "a browser holds no group past 10 000 seats",
                ));
            }
        }
        if text && who.account.is_none() && gated {
            resign(out);
            return Some((decline::GUEST_LIMIT, "a guest holds no gated group's keys"));
        }
        None
    }

    /// Takes the due in hand as far as it goes now.
    fn advance(&mut self, who: &mut Who, m: &Member, c: &mut GkCtx, out: &mut GkOut) {
        let group = m.t.group.clone();
        let Some(hold) = self.holds.get_mut(&group) else {
            return;
        };
        let Some(w) = hold.work.as_mut() else {
            return;
        };
        if matches!(w.stage, Stage::Head) {
            let kind = w.piece.kind;
            if kind != due_code::GENESIS {
                let Some(head) = m.head.as_ref().filter(|h| h.d() == w.piece.parent) else {
                    return;
                };
                if kind != due_code::REGENESIS
                    && !hold.ring.as_ref().is_some_and(|r| r.head.d() == head.d())
                {
                    let h = head.header();
                    let at = (h.gen, h.epoch, h.join);
                    if hold.keyring_asked != Some(at) {
                        hold.keyring_asked = Some(at);
                        out.send.push(ClientMessage::KeyringWanted {
                            group,
                            gen: h.gen,
                            have: None,
                        });
                    }
                    return;
                }
            }
            w.stage = Stage::Lists;
        }
        if matches!(w.stage, Stage::Lists) {
            let needed = match &hold.ring {
                Some(r) if !matches!(w.piece.kind, due_code::GENESIS | due_code::REGENESIS) => {
                    lists_needed(&r.ring, &w.piece, w.now)
                }
                _ => vec![],
            };
            let gen = hold.ring.as_ref().map(|r| r.head.header().gen);
            if gen.is_some_and(|g| g != hold.lists_gen) {
                hold.lists.clear();
                hold.lists_gen = gen.unwrap_or_default();
            }
            let missing: Vec<Version> = needed
                .into_iter()
                .filter(|v| !hold.lists.contains_key(v))
                .collect();
            if !missing.is_empty() {
                if hold.lists_out > 0 {
                    return;
                }
                if w.lists_asked {
                    let why = "the relay did not send a list the build needs";
                    self.give_up(m, decline::NOT_READY, why, out);
                    return;
                }
                w.lists_asked = true;
                for chunk in missing.chunks(gk::LISTS_WANTED_MAX) {
                    hold.lists_out += 1;
                    out.send.push(ClientMessage::EpochListsWanted {
                        group: group.clone(),
                        gen: hold.lists_gen,
                        versions: chunk.iter().map(|v| (v.b, v.v)).collect(),
                    });
                }
                return;
            }
            self.job(who, m, c, out);
        }
    }

    /// Declines the due in hand and lets it go.
    fn give_up(&mut self, m: &Member, why: u8, detail: &str, out: &mut GkOut) {
        let Some(hold) = self.holds.get_mut(&m.t.group) else {
            return;
        };
        if let Some(w) = hold.work.take() {
            out.send.push(ClientMessage::EpochDecline {
                group: m.t.group.clone(),
                due: w.due,
                why,
                detail: detail.into(),
            });
        }
    }

    /// The due in hand, checked, as a job.
    fn job(&mut self, who: &mut Who, m: &Member, c: &mut GkCtx, out: &mut GkOut) {
        match self.task(who, m, c) {
            Ok((task, due, attempt)) => {
                if let Some(w) = self.holds.get_mut(&m.t.group).and_then(|h| h.work.as_mut()) {
                    w.stage = Stage::Building;
                }
                self.jobs.push_back(BuildJob {
                    group: m.t.group.clone(),
                    due,
                    attempt,
                    task: Some(Box::new(task)),
                });
                out.build_ready = true;
            }
            Err((why, detail)) => self.give_up(m, why, detail, out),
        }
    }

    fn task(
        &mut self,
        who: &mut Who,
        m: &Member,
        c: &mut GkCtx,
    ) -> Result<(Task, u64, u64), (u8, &'static str)> {
        let not_ready = |d: &'static str| (decline::NOT_READY, d);
        let kind = m.t.kind;
        let hold = self.holds.get(&m.t.group).ok_or(not_ready("no due"))?;
        let w = hold.work.as_ref().ok_or(not_ready("no due"))?;
        let p = &w.piece;
        let anew = matches!(p.kind, due_code::GENESIS | due_code::REGENESIS);
        let ring = hold.ring.as_ref().filter(|_| !anew);
        let set: Vec<Keyholder> = ring.map_or_else(Vec::new, |r| r.kh.header().keyholders.clone());
        let now_ms = c.now;
        // The pair this device signs with: the volunteer's for a new start of a text group,
        // the connection's in voice (plan §5: any platform, a desktop's 0x03 pair holds no
        // voice keys), else its entry's
        let me = if anew && kind == GroupKind::Voice {
            Self::conn(who, now_ms)
        } else if anew {
            self.volunteer_pair(who, now_ms)
        } else {
            self.pair_in(who, kind, &set, now_ms)
        }
        .ok_or(not_ready("this device holds no pair the due names"))?;
        let hold = self.holds.get(&m.t.group).ok_or(not_ready("no due"))?;
        let w = hold.work.as_ref().ok_or(not_ready("no due"))?;
        let p = &w.piece;
        let ring = hold.ring.as_ref().filter(|_| !anew);
        let (head, kh) = match (anew, ring, &m.head, &m.kh) {
            (true, _, h, k) => (
                h.clone().filter(|_| p.kind == due_code::REGENESIS),
                k.clone(),
            ),
            (false, Some(r), _, _) => (Some(r.head.clone()), Some(r.kh.clone())),
            _ => return Err(not_ready("no keyring at the head")),
        };
        let gated_head = head.as_ref().is_some_and(|h| h.header().gated);
        let mut due = Due::of(
            DueKind::from_code(p.kind).unwrap_or(DueKind::Refresh),
            p.gated,
        );
        let mut what = What::Commit;
        // Seats owed a seed welcome: each to the keys its seat is named by, so the relay
        // cannot point one seat's `s_m` at keys of its own
        let mut owed = Vec::with_capacity(p.seed_seats.len());
        for s in &p.seed_seats {
            let seat = SeatRef::from(s.seat);
            match SeatPublic::from_bytes(&s.keys.kem, &s.keys.dh) {
                Ok(keys) if keys.seat(seat.m) == seat => owed.push((seat, keys)),
                _ => return Err(not_ready("a seat's keys are not its own")),
            }
        }
        let mut seed_seats = HashMap::new();
        if p.kind == due_code::SEED_WELCOMES {
            what = What::Welcomes(owed);
        } else {
            seed_seats.extend(owed);
            for j in &p.joins {
                due.joiners
                    .push(Joiner::try_from(j).map_err(|_| not_ready("a joiner is malformed"))?);
            }
            due.exits = p.exits.iter().cloned().map(Exit::from).collect();
            due.exits_upto = p.exits_upto;
            due.remove = p.remove.map(Into::into);
            if let Some(cand) = &p.promote {
                let cand = Candidate::try_from(cand)
                    .map_err(|_| (decline::CANDIDATE, "the candidate is malformed"))?;
                if !candidate_ok(kind, p.gated || gated_head, &set, &cand, c) {
                    return Err((decline::CANDIDATE, "the candidate fails the checks"));
                }
                due.candidate = Some(cand);
            }
        }
        let mut new = None;
        match due.kind {
            DueKind::Genesis | DueKind::Regenesis => {
                let own = self.own_seat(who, kind);
                if due.joiners.len() != 1 || Some(due.joiners[0].seat) != own {
                    return Err(not_ready("a new start seats this device's own seat only"));
                }
                due.volunteer = Some(Candidate {
                    m: me.m,
                    ik: raw(&who.identity),
                    pair: me.wire.clone(),
                });
            }
            DueKind::Replace => {
                let (Some(old), Some(desk)) = (&self.old, &self.desk) else {
                    return Err(not_ready("no Replace of this device is out"));
                };
                if old.kx() != me.kx() {
                    return Err(not_ready("the old pair is not the entry"));
                }
                let entry = desk
                    .wire
                    .entry(kind, desk.m, raw(&who.identity))
                    .ok_or(not_ready("the new pair makes no entry"))?;
                due.replace = Some(ReplaceAsk {
                    old: kx_tag(&old.kx()),
                    pair: desk.wire.clone(),
                });
                new = Some((desk.clone(), entry));
            }
            _ => {}
        }
        // A gated header with a connections-pool bucket left (§5.6)
        if let (true, Some(r)) = (p.gated, ring) {
            let mut leaving: HashMap<u64, usize> = HashMap::new();
            for x in &p.exits {
                *leaving.entry(x.b).or_default() += 1;
            }
            let conns_left = r.ring.buckets.iter().any(|b| {
                b.pool == Pool::Conns
                    && usize::from(b.seats) > leaving.get(&b.b).copied().unwrap_or(0)
            });
            if conns_left {
                return Err((
                    decline::CONN_BUCKET,
                    "a gated header over a connections bucket",
                ));
            }
        }
        // The joiners this keyholder seats (§5.2)
        let mut refused = Vec::new();
        if due.kind == DueKind::Join {
            // Seated now: in a list of a version the keyring still holds, not a superseded one
            let current: HashSet<Version> = ring
                .map(|r| r.ring.buckets.iter().map(|k| k.version()).collect())
                .unwrap_or_default();
            let seated: HashSet<SeatRef> = hold
                .lists
                .iter()
                .filter(|(v, _)| current.contains(v))
                .flat_map(|(_, l)| l.iter().map(|s| s.seat))
                .collect();
            for j in &due.joiners {
                if let Some(why) = joiner_why(kind, gated_head, j, w.now, c, &seated) {
                    refused.push(commit::Refused { seat: j.seat, why });
                }
            }
        }
        let (ring_copy, krk, rolls) = match ring {
            Some(r) => (
                Some(Keyring {
                    base: r.ring.base.clone(),
                    buckets: r.ring.buckets.clone(),
                }),
                r.krk.clone(),
                SeedRolls {
                    removal: r.rolls.removal || p.roll_due,
                    ..r.rolls
                },
            ),
            None => (
                None,
                Zeroizing::new([0; 32]),
                SeedRolls {
                    raised: 0,
                    removal: false,
                },
            ),
        };
        let needed: HashSet<Version> = match ring {
            Some(r) => lists_needed(&r.ring, p, w.now).into_iter().collect(),
            None => HashSet::new(),
        };
        let lists: Lists = hold
            .lists
            .iter()
            .filter(|(v, _)| needed.contains(v))
            .map(|(v, l)| (*v, l.clone()))
            .collect();
        let task = Task {
            what,
            kind,
            id: m.t.group.clone(),
            stored: m.stored(),
            refused,
            head,
            kh,
            ring: ring_copy,
            krk,
            rolls,
            me,
            ik: same_ik(&who.identity),
            new,
            lists,
            held: p
                .held
                .iter()
                .map(|(s, n)| (SeatRef::from(*s), *n))
                .collect(),
            pairs: p
                .pairs
                .iter()
                .filter_map(|x| SeatPublic::from_bytes(&x.kem, &x.dh).ok())
                .collect(),
            seed_seats,
            finish: p.finish,
            now: w.now,
            roster: m.voice_seats.keys().copied().collect(),
            reuse: None,
            cache: RowBases::new(),
            due,
        };
        let (due_id, attempt) = (w.due, w.attempt);
        let hold = self.holds.get_mut(&m.t.group).ok_or(not_ready("no due"))?;
        let w = hold.work.as_mut().ok_or(not_ready("no due"))?;
        let mut task = task;
        task.reuse = w.stale.take().map(|b| *b);
        task.cache = hold.cache.take().unwrap_or_default();
        Ok((task, due_id, attempt))
    }

    /// This device's own seat in a group of `kind`: the account's seat keys in text, else
    /// the connection's pair (as the relay seats a volunteer, gk/session.rs `volunteer`).
    fn own_seat(&self, who: &Who, kind: GroupKind) -> Option<SeatRef> {
        match (who.account, kind) {
            (Some(a), GroupKind::Text) => Some(
                who.seat_keys
                    .as_ref()?
                    .pair
                    .public()
                    .seat(MemberId::Account(a)),
            ),
            (a, _) => {
                let m = a.map_or(MemberId::Conn(who.user_id), MemberId::Account);
                Some(who.conn.pair()?.public().seat(m))
            }
        }
    }

    /// `EpochStale`: on `HEAD_MOVED` the commit is made again on the new head (reusing what
    /// may be, `build`'s `reuse`), else the due is let go and the next one waited for.
    fn on_stale(
        &mut self,
        m: &Member,
        due: u64,
        reason: u8,
        detail: &str,
        head: Option<&gk::WalkLinkIn>,
    ) {
        let group = &m.t.group;
        let Some(hold) = self.holds.get_mut(group) else {
            return;
        };
        if !hold.work.as_ref().is_some_and(|w| w.due == due) {
            return;
        }
        self.upload.retain(|(g, d, _)| !(g == group && *d == due));
        let new = head.and_then(|l| {
            crate::group_key::check_form(&l.header.body, &l.header.sig, m.t.kind, group).ok()
        });
        let (Some(new), stale::HEAD_MOVED) = (new, reason) else {
            tracing::info!(%group, due, reason = stale::name(reason), detail, "a commit went stale");
            hold.work = None;
            return;
        };
        self.attempts += 1;
        let w = hold.work.as_mut().expect("checked");
        if let Stage::Sent(b) = std::mem::replace(&mut w.stage, Stage::Head) {
            // The relay's word alone: what the Join sealed stays kept until named (§5.2)
            if !b.sealed_to.is_empty() {
                w.rebased.push((b.header.d(), b.sealed_to.clone()));
            }
            w.stale = Some(b);
        }
        w.piece.parent = new.d();
        // A Fresh sent meanwhile may have dealt with this due's exits (R1)
        let upto = new.header().exits_upto;
        w.piece.exits.retain(|x| x.seq > upto);
        w.lists_asked = false;
        w.attempt = self.attempts;
    }

    /// A whole `KeyringIn` at `at`: taken under the member's head with the `KRK` this device
    /// holds or opens now (§3.7), and checked against the keyring it held (`check_carried`).
    fn take_ring(
        &mut self,
        who: &mut Who,
        m: &Member,
        at: RingAt,
        parts: Vec<KeyringPiece>,
        now: u64,
    ) -> Result<(), &'static str> {
        let head = m.head.as_ref().ok_or("no head")?;
        let h = head.header();
        if (h.gen, h.epoch, h.join) != at {
            return Ok(());
        }
        let kh =
            m.kh.as_ref()
                .filter(|k| k.d() == head.kh())
                .ok_or("no keyholder header")?;
        let g = Group::new(m.t.kind, &m.t.group, h.gen).map_err(|_| "a malformed group")?;
        let set = &kh.header().keyholders;
        let me = self
            .pair_in(who, m.t.kind, set, now)
            .ok_or("this device is in no set")?;
        let hold = self.holds.get_mut(&m.t.group).ok_or("no group")?;
        let held = hold.ring.as_ref().filter(|r| r.kh.d() == kh.d());
        let krk = match (held, parts.first().and_then(|p| p.krk.as_ref())) {
            (Some(r), _) => r.krk.clone(),
            (None, Some(w)) => {
                let from: MemberId = w.from.m.into();
                if from != kh.header().signer {
                    return Err("a KRK welcome from another than its maker");
                }
                let maker = crate::group_key::Holder::from_raw(from, &w.from.kx)
                    .map_err(|_| "a malformed maker")?;
                let ks = keyholder_set_digest(set);
                let me = Me {
                    m: me.m,
                    keys: &me.pair,
                };
                let kh_h = kh.header();
                open_keyring_welcome(&g, kh_h.seed, kh_h.epoch, &ks, &me, &maker, &w.bytes)
                    .map_err(|_| "the KRK welcome does not open")?
            }
            _ => return Err("no KRK welcome"),
        };
        let stream: Vec<u8> = parts
            .iter()
            .flat_map(|p| p.stream.iter().copied())
            .collect();
        let entries = gk::read_keyring(&stream, 0, h.join).map_err(|_| "a malformed keyring")?;
        let (base, deltas) = entries.split_first().ok_or("no keyring base")?;
        let deltas: Vec<Vec<u8>> = deltas.iter().map(|(_, d)| d.to_vec()).collect();
        let ring = take_keyring(&g, head, kh, &krk, base.1, &deltas)
            .map_err(|_| "the keyring is not the head's")?;
        if let Some(own) = hold.ring.as_ref().filter(|r| r.head.header().gen == h.gen) {
            check_carried(&own.ring, &ring)
                .map_err(|_| "the keyring carries what this device did not hold")?;
        }
        let rolls = rolls_to(hold.ring.as_ref().map(|r| (r.rolls, &r.head)), head);
        let current: HashSet<Version> = ring.buckets.iter().map(|k| k.version()).collect();
        hold.lists.retain(|v, _| current.contains(v));
        hold.ring = Some(Ring {
            head: head.clone(),
            kh: kh.clone(),
            ring,
            krk,
            rolls,
        });
        Ok(())
    }

    /// The due's work of a group goes: its parts not sent, its jobs not taken, and what it
    /// waited for. A keyholder's own asks refused (as `COMMIT`'s, which reach the member, not
    /// the duty) or answered too late then stall no later due: the next one asks again.
    fn drop_work(&mut self, group: &str) {
        if let Some(hold) = self.holds.get_mut(group) {
            hold.work = None;
            hold.lists_out = 0;
            hold.keyring_asked = None;
        }
        self.upload.retain(|(g, _, _)| g != group);
        self.jobs.retain(|j| j.group != group);
    }

    pub(super) fn tick(
        &mut self,
        who: &mut Who,
        groups: &mut std::collections::BTreeMap<String, Member>,
        c: &mut GkCtx,
        out: &mut GkOut,
    ) {
        if !who.on {
            return;
        }
        for m in groups.values() {
            self.sync(who, m, out);
            self.advance(who, m, c, out);
        }
        self.unnamed(groups, c, out);
        self.replaced(who, groups, c, out);
    }

    /// §5.2: the seats a Join of ours sealed are named once a later header descends from it;
    /// the head moving on without it, or no later header in 70 min, is told.
    fn unnamed(
        &mut self,
        groups: &std::collections::BTreeMap<String, Member>,
        c: &GkCtx,
        out: &mut GkOut,
    ) {
        let now = c.secs();
        let before = self.keep.unnamed.len();
        let mut events = vec![];
        // Joins whose due is in hand and being made again: their rebase may name them yet
        let rebasing: HashSet<[u8; 32]> = self
            .holds
            .values()
            .filter_map(|h| h.work.as_ref())
            .flat_map(|w| w.rebased.iter().map(|(d, _)| *d))
            .collect();
        self.keep.unnamed.retain(|u| {
            let late = now >= u.at.saturating_add(EPOCH_AGE_MAX_SECS);
            let Some(m) = groups.get(&u.group) else {
                return !late;
            };
            if !late && rebasing.contains(&u.d) {
                return true;
            }
            let warn = match m.head.as_ref() {
                Some(h) if h.d() == u.d => late,
                // Taken, and the head moved on from it: named (a new generation too)
                Some(_) if u.taken => return false,
                Some(h) if h.header().gen != u.gen => true,
                Some(h) if (h.header().epoch, h.header().join) >= (u.epoch, u.join) => true,
                _ => late,
            };
            if warn {
                events.push(GkEvent::Warning {
                    channel_id: m.t.channel_id,
                    kind: Warn::UnnamedSeats,
                    n: u.seats,
                });
            }
            !warn
        });
        out.events.extend(events);
        if self.keep.unnamed.len() != before {
            self.dirty = true;
        }
    }

    /// A Replace done in every tracked group that named the old pair, or 7 days past: the
    /// old pair goes (resigning where it was not swapped) and the new one volunteers.
    fn replaced(
        &mut self,
        who: &mut Who,
        groups: &std::collections::BTreeMap<String, Member>,
        c: &GkCtx,
        out: &mut GkOut,
    ) {
        let (Some(old), Some(asked)) = (&self.old, self.replacing) else {
            return;
        };
        let Some(asked) = asked else {
            self.replacing = Some(Some(c.now));
            return;
        };
        let since = self.keep.old.as_ref().map_or(0, |o| o.since);
        let expired = c.secs() >= since.saturating_add(OLD_KEYS_SECS);
        let kx = old.kx();
        let pending: Vec<String> = groups
            .values()
            .filter(|m| {
                m.t.kind == GroupKind::Text
                    && m.kh
                        .as_ref()
                        .is_some_and(|k| k.header().keyholders.iter().any(|e| e.kx == kx))
            })
            .map(|m| m.t.group.clone())
            .collect();
        if !expired && !(pending.is_empty() && c.now >= asked.saturating_add(REPLACE_SETTLE_MS)) {
            return;
        }
        if expired {
            for group in pending {
                out.send
                    .push(ClientMessage::KeyholdResign { group, entry: None });
            }
        }
        self.old = None;
        self.keep.old = None;
        self.replacing = None;
        self.dirty = true;
        if self.offered {
            self.offered = false;
            self.volunteer(who, c.now, out);
        }
    }

    pub(super) fn next_frame(&mut self, _now: u64, _in_call: bool) -> Option<ClientMessage> {
        self.upload.pop_front().map(|(_, _, m)| m)
    }

    pub(super) fn take_build(&mut self) -> Option<BuildJob> {
        self.jobs.pop_front()
    }

    pub(super) fn built(
        &mut self,
        who: &mut Who,
        groups: &mut std::collections::BTreeMap<String, Member>,
        b: Built,
        c: &mut GkCtx,
        out: &mut GkOut,
    ) {
        let Built {
            group,
            due,
            attempt,
            out: done,
            cache,
        } = b;
        let Some(hold) = self.holds.get_mut(&group) else {
            return;
        };
        hold.cache = Some(cache);
        let Some(w) = hold
            .work
            .as_mut()
            .filter(|w| w.due == due && w.attempt == attempt)
        else {
            return;
        };
        match done {
            Ok(Done::Commit(b)) => {
                let piece = match gk::CommitPiece::try_from(b.commit.clone()) {
                    Ok(p) => p,
                    Err(_) => return self.failed(&group, due, "the commit does not encode", out),
                };
                let max = PIECE_MAX_BYTES - gk::commit_frame_overhead(&group);
                let parts = match gk::cut_commit(piece, max) {
                    Ok(p) => p,
                    Err(_) => return self.failed(&group, due, "the commit does not cut", out),
                };
                let n = parts.len();
                for (i, piece) in parts.into_iter().enumerate() {
                    let msg = ClientMessage::EpochCommit {
                        group: group.clone(),
                        due,
                        part: i as u16,
                        last: i + 1 == n,
                        piece,
                    };
                    self.upload.push_back((group.clone(), due, msg));
                }
                let h = b.header.header();
                if h.kind == Kind::Join && !b.sealed_to.is_empty() {
                    self.keep.unnamed.push(Unnamed {
                        group: group.clone(),
                        gen: h.gen,
                        epoch: h.epoch,
                        join: h.join,
                        d: b.header.d(),
                        seats: b.sealed_to.len() as u32,
                        at: c.secs(),
                        taken: false,
                    });
                    // A stale Join of this due whose seats this one seals again: its record
                    // is this one's now
                    let now_sealed: HashSet<&SeatRef> = b.sealed_to.iter().collect();
                    let again: Vec<[u8; 32]> = w
                        .rebased
                        .iter()
                        .filter(|(_, seats)| seats.iter().all(|s| now_sealed.contains(s)))
                        .map(|(d, _)| *d)
                        .collect();
                    w.rebased.retain(|(d, _)| !again.contains(d));
                    self.keep.unnamed.retain(|u| !again.contains(&u.d));
                    self.dirty = true;
                }
                w.stage = Stage::Sent(b);
            }
            Ok(Done::Welcomes { gen, s, list }) => {
                for page in list.chunks(SEED_WELCOMES_A_FRAME) {
                    let msg = ClientMessage::EpochWelcomes {
                        group: group.clone(),
                        due,
                        gen,
                        seed: s,
                        welcomes: page
                            .iter()
                            .map(|w| gk::SeedWelcomeOut {
                                seat: w.seat.into(),
                                bytes: w.bytes.clone(),
                            })
                            .collect(),
                    };
                    self.upload.push_back((group.clone(), due, msg));
                }
                hold.work = None;
            }
            Err(detail) => {
                tracing::warn!(%group, due, detail, "a keyholder job failed");
                self.failed(&group, due, &detail, out);
            }
        }
        if let Some(m) = groups.get(&group) {
            self.sync(who, m, out);
        }
    }

    fn failed(&mut self, group: &str, due: u64, detail: &str, out: &mut GkOut) {
        if let Some(hold) = self.holds.get_mut(group) {
            hold.work = None;
        }
        let mut detail = detail.to_string();
        detail.truncate(gk::DETAIL_MAX_BYTES);
        out.send.push(ClientMessage::EpochDecline {
            group: group.to_string(),
            due,
            why: decline::NOT_READY,
            detail,
        });
    }

    /// "Help hold keys" switched: off resigns every text group held (before the volunteer
    /// goes, so the relay still knows whose entry each resign names).
    pub(super) fn set_volunteer(
        &mut self,
        who: &mut Who,
        _groups: &mut std::collections::BTreeMap<String, Member>,
        on: bool,
        out: &mut GkOut,
    ) {
        if !who.on {
            return;
        }
        if on {
            if !self.offered {
                self.volunteer(who, crate::time::now_millis(), out);
            }
            return;
        }
        let mut held: Vec<&String> = self
            .holds
            .iter()
            .filter(|(_, h)| h.in_set && h.kind == Some(GroupKind::Text))
            .map(|(g, _)| g)
            .collect();
        held.sort();
        for group in held {
            out.send.push(ClientMessage::KeyholdResign {
                group: group.clone(),
                entry: None,
            });
        }
        self.unoffer(who, out);
    }

    fn unoffer(&mut self, who: &Who, out: &mut GkOut) {
        if std::mem::take(&mut self.offered) {
            out.send.push(ClientMessage::KeyholdVolunteer {
                on: false,
                platform: who.platform.code(),
                pair: None,
            });
        }
    }

    /// The account's seat keys settled, or rotated: a signed-in device that could not offer
    /// itself at `GroupKeys` (its keys not yet in the vault) volunteers now, a desktop
    /// keyholder replaces its pair (§5.11).
    pub(super) fn seat_keys_changed(
        &mut self,
        who: &mut Who,
        groups: &mut std::collections::BTreeMap<String, Member>,
        out: &mut GkOut,
    ) {
        if !who.on {
            return;
        }
        let now = crate::time::now_millis();
        if !self.offered {
            // Its Replace goes after it where the kept pair is behind (`volunteer`)
            self.volunteer(who, now, out);
        } else if !Self::uses_desk(who)
            || self.desk.is_none()
            || self.old.is_some()
            || self.desk(who, now).is_none()
        {
            return;
        } else {
            self.ask_replace(out);
        }
        // The pair it holds keys with is the new one from now (`own_kx`)
        for m in groups.values() {
            self.sync(who, m, out);
        }
    }

    /// The browser page was hidden or shown, or a call began or ended: a browser offers to
    /// hold text keys only while shown and out of a call (3g).
    pub(super) fn visibility(
        &mut self,
        who: &mut Who,
        _groups: &mut std::collections::BTreeMap<String, Member>,
        visible: bool,
        in_call: bool,
        out: &mut GkOut,
    ) {
        self.in_call = in_call;
        if !who.on || who.platform != Platform::Browser {
            return;
        }
        if visible && !in_call {
            if !self.offered {
                self.volunteer(who, crate::time::now_millis(), out);
            }
        } else {
            self.unoffer(who, out);
        }
    }

    pub(super) fn untrack(&mut self, group: &str) {
        self.drop_work(group);
        self.holds.remove(group);
    }

    pub(super) fn end(&mut self, _who: &mut Who, _out: &mut GkOut) {
        self.offered = false;
        self.replacing = None;
        self.holds.clear();
        self.upload.clear();
        self.jobs.clear();
    }
}

/// The lists an opening on `ring` needs (`plan_opening`, as `build_opening` plans it at the
/// same time); a Join, a new start and a welcome page need none.
fn lists_needed(ring: &Keyring, p: &DuePiece, now: u64) -> Vec<Version> {
    let kind = match DueKind::from_code(p.kind) {
        Some(DueKind::Join | DueKind::Genesis | DueKind::Regenesis) | None => return vec![],
        Some(k) => k,
    };
    let mut exits: HashMap<u64, HashSet<SeatRef>> = HashMap::new();
    for x in &p.exits {
        exits.entry(x.b).or_default().insert(x.seat.into());
    }
    let buckets: Vec<BucketNow> = ring
        .buckets
        .iter()
        .map(|kb| BucketNow {
            b: kb.b,
            v: kb.v,
            pool: kb.pool,
            seats: kb.seats,
            made: kb.made,
            exits: exits.get(&kb.b).map_or(0, |x| x.len() as u16),
        })
        .collect();
    plan_opening(kind.header_kind(), &buckets, kind == DueKind::Refresh, now).lists_needed(&buckets)
}

/// Our commit was taken: its keyring, `KRK` and rolls are the group's now.
fn adopt(hold: &mut Hold, b: build::Built) {
    let h = b.header.header();
    let prev = hold.ring.take();
    let kh = if h.kind.sets_keyholders() {
        b.header.clone()
    } else {
        match &prev {
            Some(r) => r.kh.clone(),
            None => return,
        }
    };
    let rolls = rolls_to(prev.as_ref().map(|r| (r.rolls, &r.head)), &b.header);
    if prev.as_ref().is_none_or(|r| r.head.header().gen != h.gen) {
        hold.lists.clear();
    }
    let current: HashSet<Version> = b.ring.buckets.iter().map(|k| k.version()).collect();
    hold.lists.retain(|v, _| current.contains(v));
    hold.lists_gen = h.gen;
    hold.ring = Some(Ring {
        head: b.header,
        kh,
        ring: b.ring,
        krk: b.krk,
        rolls,
    });
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::group_key::build::world::{self, World, T0, TEXT_ID};
    use crate::group_key::commit::{Applied, Commit};
    use crate::group_key::{open_seed_welcome, tag, SeatKeys};
    use crate::group_state::{GkPins, GkTrack, MemoryPins};

    const CH: u32 = 7;
    const U: u32 = 3;

    fn track() -> GkTrack {
        GkTrack {
            channel_id: CH,
            group: TEXT_ID.into(),
            kind: GroupKind::Text,
            anonymous: false,
            hide_members: false,
            viewer_admin: false,
            keeps_history: true,
        }
    }

    /// One connection's duty and its member of `TEXT_ID`, at `T0`.
    struct Rig {
        duty: Duty,
        who: Who,
        groups: BTreeMap<String, Member>,
        pins: MemoryPins,
        now: u64,
    }

    impl Rig {
        fn new(account: Option<[u8; 16]>, platform: Platform) -> Rig {
            let who = Who {
                on: true,
                run: [1; 16],
                relay_clock: crate::time::now_millis() / 1000,
                platform,
                help: true,
                visible: true,
                user_id: U,
                identity: IdentityKeyPair::generate(&mut crate::rng()),
                account,
                seat_keys: account.map(|_| SeatKeys::generate(1, T0)),
                conn: Default::default(),
            };
            let mut groups = BTreeMap::new();
            groups.insert(TEXT_ID.to_string(), Member::new(track(), None));
            Rig {
                duty: Duty::default(),
                who,
                groups,
                pins: MemoryPins::default(),
                now: T0 * 1000,
            }
        }

        fn start(&mut self) -> Vec<ClientMessage> {
            let mut out = GkOut::default();
            self.duty.start(&mut self.who, &mut out);
            out.send
        }

        fn frame(&mut self, msg: ServerMessage) -> GkOut {
            let mut out = GkOut::default();
            let mut c = GkCtx {
                pins: &mut self.pins,
                now: self.now,
            };
            self.duty
                .frame(&mut self.who, &mut self.groups, &msg, &mut c, &mut out);
            out
        }

        fn tick(&mut self) -> GkOut {
            let mut out = GkOut::default();
            let mut c = GkCtx {
                pins: &mut self.pins,
                now: self.now,
            };
            self.duty
                .tick(&mut self.who, &mut self.groups, &mut c, &mut out);
            out
        }

        fn due(&mut self, id: u64, p: DuePiece) -> GkOut {
            self.frame(ServerMessage::EpochDue {
                group: TEXT_ID.into(),
                due: id,
                part: 0,
                last: true,
                piece: Box::new(p),
            })
        }

        /// Every job run and handed back, as the host does off the lock.
        fn jobs(&mut self) -> GkOut {
            let mut all = GkOut::default();
            while let Some(mut job) = self.duty.take_build() {
                let b = job.step(Duration::from_millis(8)).expect("a job finishes");
                let mut c = GkCtx {
                    pins: &mut self.pins,
                    now: self.now,
                };
                let mut out = GkOut::default();
                self.duty
                    .built(&mut self.who, &mut self.groups, b, &mut c, &mut out);
                all.send.extend(out.send);
                all.events.extend(out.events);
            }
            all
        }

        fn uploads(&mut self) -> Vec<ClientMessage> {
            std::iter::from_fn(|| self.duty.next_frame(self.now, false)).collect()
        }

        /// The jobs run, and the commit their parts make.
        fn commit(&mut self) -> Commit {
            let out = self.jobs();
            assert!(
                !out.send
                    .iter()
                    .any(|m| matches!(m, ClientMessage::EpochDecline { .. })),
                "declined: {:?}",
                out.send
            );
            let parts: Vec<gk::CommitPiece> = self
                .uploads()
                .into_iter()
                .filter_map(|m| match m {
                    ClientMessage::EpochCommit { piece, .. } => Some(piece),
                    _ => None,
                })
                .collect();
            assert!(!parts.is_empty(), "a commit went");
            Commit::try_from(gk::join_commit(parts).unwrap()).unwrap()
        }

        fn sent(&self) -> &build::Built {
            match &self.duty.holds[TEXT_ID].work {
                Some(Work {
                    stage: Stage::Sent(b),
                    ..
                }) => b,
                _ => panic!("no commit out"),
            }
        }

        fn member(&mut self) -> &mut Member {
            self.groups.get_mut(TEXT_ID).unwrap()
        }

        /// The member took `h` (as a keyholder's push of `chain: [h]`).
        fn took(&mut self, h: &SignedHeader) {
            let m = self.member();
            if h.header().kind.sets_keyholders() {
                m.kh = Some(h.clone());
            }
            m.head = Some(h.clone());
            m.took.push((h.d(), h.header().parent));
        }

        /// The pair it volunteered with.
        fn volunteered(sent: &[ClientMessage]) -> EndorsedPair {
            sent.iter()
                .find_map(|m| match m {
                    ClientMessage::KeyholdVolunteer {
                        on: true,
                        pair: Some(p),
                        ..
                    } => Some(p.clone()),
                    _ => None,
                })
                .expect("a volunteer")
        }
    }

    /// The relay's `EpochDue` for `d` on `head`, as gk/group.rs `send_due` makes it.
    fn piece(kind: u8, d: &Due, w: Option<&World>, pairs: Vec<EndorsedPair>) -> DuePiece {
        let held: Vec<(gk::GkSeat, u32)> = w.map_or_else(Vec::new, |w| {
            let s = w.head.header().seed;
            w.held
                .iter()
                .filter(|(_, n)| **n < s)
                .map(|(seat, n)| ((*seat).into(), *n))
                .collect()
        });
        DuePiece {
            kind,
            parent: w.map_or([0; 32], |w| w.head.d()),
            deadline_ms: 0,
            keyring_at: w.map_or((0, 0), |w| (w.head.header().epoch, w.head.header().join)),
            joins: d
                .joiners
                .iter()
                .map(|j| gk::Joiner {
                    seat: j.seat.into(),
                    ik: j.ik,
                    keys: (&Pair {
                        keys: j.keys.clone(),
                        endorsement: j.endorsement.clone(),
                    })
                        .into(),
                    returning: j.returning,
                })
                .collect(),
            exits: d
                .exits
                .iter()
                .map(|x| gk::ExitIn {
                    seq: x.seq,
                    seat: x.seat.into(),
                    b: x.b,
                })
                .collect(),
            exits_upto: d.exits_upto,
            promote: d.candidate.as_ref().map(|c| gk::Candidate {
                m: c.m.into(),
                ik: c.ik,
                pair: (&c.pair).into(),
            }),
            remove: d.remove.map(Into::into),
            gated: d.gated,
            roll_due: false,
            seed_seats: vec![],
            finish: held.is_empty(),
            pairs,
            held,
        }
    }

    /// `EpochLists` for every version asked in `sent`, from the relay's lists.
    fn lists_for(w: &World, sent: &[ClientMessage]) -> Option<ServerMessage> {
        let all = w.lists();
        let asked: Vec<(u64, u64)> = sent
            .iter()
            .filter_map(|m| match m {
                ClientMessage::EpochListsWanted { versions, .. } => Some(versions.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        if asked.is_empty() {
            return None;
        }
        let lists = asked
            .iter()
            .filter_map(|(b, v)| {
                let l = all.get(&Version { b: *b, v: *v })?;
                Some(gk::ListIn {
                    b: *b,
                    v: *v,
                    seats: l
                        .iter()
                        .map(|s| gk::ListSeat {
                            seat: s.seat.into(),
                            dh: s.dh.clone(),
                        })
                        .collect(),
                })
            })
            .collect();
        Some(ServerMessage::EpochLists {
            group: TEXT_ID.into(),
            gen: w.g.gen(),
            lists,
            more: false,
        })
    }

    /// The relay after a Genesis it took.
    fn world_after(due: &Due, a: Applied, b: &build::Built) -> World {
        let h = a.header.header().clone();
        let mut w = World {
            kind: GroupKind::Text,
            id: TEXT_ID,
            stored: true,
            g: Group::new(GroupKind::Text, TEXT_ID, h.gen).unwrap(),
            head: a.header.clone(),
            kh: a.header.clone(),
            leaves: vec![],
            keys: HashMap::new(),
            held: HashMap::new(),
            used_v: HashSet::new(),
            rolls: a.rolls,
            gens: vec![],
            ring: world::copy_ring(&b.ring),
            krk: b.krk.clone(),
            holders: vec![],
            cache: RowBases::new(),
            now: T0,
            roster: vec![],
            no_keyholder_since: None,
            seq: 0,
        };
        w.take(due, a, b);
        w
    }

    /// A guest keyholder's Genesis, checked and taken by the relay.
    fn genesis(rig: &mut Rig) -> (World, Pair) {
        let sent = rig.start();
        let ep = Rig::volunteered(&sent);
        let me = MemberId::Conn(U);
        let pair = wire::pair(&ep, me.into()).unwrap();
        let joiner = Joiner {
            seat: pair.keys.seat(me),
            ik: raw(&rig.who.identity),
            keys: pair.keys.clone(),
            endorsement: pair.endorsement.clone(),
            returning: false,
        };
        let due = Due {
            joiners: vec![joiner],
            volunteer: Some(Candidate {
                m: me,
                ik: raw(&rig.who.identity),
                pair: pair.clone(),
            }),
            ..Due::of(DueKind::Genesis, false)
        };
        let out = rig.due(1, piece(due_code::GENESIS, &due, None, vec![]));
        assert!(out.build_ready);
        let c = rig.commit();
        let by = HolderRef {
            m: me,
            kx: pair.kx(),
        };
        let a = World::check_start(GroupKind::Text, TEXT_ID, true, &due, by, &c, T0, &[])
            .unwrap_or_else(|bad| panic!("{bad}"));
        let h = a.header.clone();
        let w = world_after(&due, a, rig.sent());
        rig.took(&h);
        rig.now = w.now * 1000;
        rig.tick();
        assert!(
            rig.duty.holds(TEXT_ID),
            "in the set once its Genesis is taken"
        );
        assert_eq!(rig.duty.own_kx(TEXT_ID), Some(pair.kx()));
        (w, pair)
    }

    /// What the relay made of a commit it took.
    struct Landed {
        header: SignedHeader,
        seated: usize,
        refused: Vec<(SeatRef, u8)>,
        removed: Vec<SeatRef>,
        /// What the member's next tick told.
        events: Vec<GkEvent>,
    }

    /// Checks the commit as the relay would for `due`, takes it, and shows it to the member.
    fn land(rig: &mut Rig, w: &mut World, due: &Due, by: HolderRef, c: &Commit) -> Landed {
        let a = w.check(due, by, c).unwrap_or_else(|bad| panic!("{bad}"));
        let mut landed = Landed {
            header: a.header.clone(),
            seated: a.seated.len(),
            refused: a.refused.iter().map(|r| (r.seat, r.why)).collect(),
            removed: a.removed.clone(),
            events: vec![],
        };
        w.take(due, a, rig.sent());
        rig.took(&landed.header);
        rig.now = w.now * 1000;
        landed.events = rig.tick().events;
        landed
    }

    /// `EpochStale` for `due`, naming `head`.
    fn stale_on(due: u64, reason: u8, head: Option<&SignedHeader>) -> ServerMessage {
        ServerMessage::EpochStale {
            group: TEXT_ID.into(),
            due,
            reason,
            detail: String::new(),
            head: head.map(|h| gk::WalkLinkIn {
                header: gk::HeaderIn {
                    body: h.body().to_vec(),
                    sig: h.sig().to_vec(),
                },
                parent: None,
            }),
        }
    }

    /// `KeyringIn` at `head`: its epoch's opening keyring, then each Join's delta since.
    fn keyring_at(head: &SignedHeader, entries: &[&[u8]]) -> ServerMessage {
        let mut stream = vec![];
        for e in entries {
            gk::put_keyring_entry(&mut stream, e).unwrap();
        }
        let h = head.header();
        ServerMessage::KeyringIn {
            group: TEXT_ID.into(),
            gen: h.gen,
            epoch: h.epoch,
            join: h.join,
            part: 0,
            last: true,
            piece: KeyringPiece { krk: None, stream },
        }
    }

    /// The promotion of a second keyholder (a desktop of account 9), whose commits win the
    /// races below: its keyring entry, for a `KeyringIn` from it.
    fn second_keyholder(rig: &mut Rig, w: &mut World, pair: &Pair) -> Vec<u8> {
        let by = HolderRef {
            m: MemberId::Conn(U),
            kx: pair.kx(),
        };
        let cand = world::Holder::desktop(9);
        let promote = w.promote_due(&cand);
        let own: EndorsedPair = pair.into();
        let out = rig.due(90, piece(due_code::PROMOTE, &promote, Some(w), vec![own]));
        if let Some(lists) = lists_for(w, &out.send) {
            rig.frame(lists);
        }
        let c = rig.commit();
        land(rig, w, &promote, by, &c);
        w.holders.push(cand);
        c.keyring
    }

    fn sent_kinds(sent: &[ClientMessage]) -> Vec<&'static str> {
        sent.iter()
            .map(|m| match m {
                ClientMessage::KeyholdVolunteer { on: true, .. } => "volunteer",
                ClientMessage::KeyholdVolunteer { on: false, .. } => "unvolunteer",
                ClientMessage::KeyholdResign { .. } => "resign",
                ClientMessage::KeyholdReplace { .. } => "replace",
                ClientMessage::EpochDecline { .. } => "decline",
                ClientMessage::KeyringWanted { .. } => "keyring",
                ClientMessage::EpochListsWanted { .. } => "lists",
                _ => "other",
            })
            .collect()
    }

    fn declined(out: &GkOut) -> Option<u8> {
        out.send.iter().find_map(|m| match m {
            ClientMessage::EpochDecline { why, .. } => Some(*why),
            _ => None,
        })
    }

    #[test]
    fn a_keyholder_starts_seats_drops_promotes_and_rebases_a_commit_the_relay_takes() {
        let mut rig = Rig::new(None, Platform::Desktop);
        let (mut w, pair) = genesis(&mut rig);
        let by = HolderRef {
            m: MemberId::Conn(U),
            kx: pair.kx(),
        };

        // A Join: three accounts seated, one whose endorsement is not its IK's left out
        let people: Vec<world::Member> = (10..13).map(world::Member::account).collect();
        let refs: Vec<&world::Member> = people.iter().collect();
        let mut join = w.join_due(&refs);
        let forged = world::Member::account(20);
        let mut j = forged.joiner();
        j.ik = people[0].ik_raw();
        join.joiners.push(j);
        rig.due(2, piece(due_code::JOIN, &join, Some(&w), vec![]));
        let c = rig.commit();
        let a = land(&mut rig, &mut w, &join, by, &c);
        assert_eq!(a.seated, 3);
        assert_eq!(a.refused, vec![(forged.seat, join_refused::ENDORSEMENT)]);

        // An exit: the lists it needs asked, its opening taken
        let exits = w.exits(&[people[0].seat], DueKind::Exits);
        let out = rig.due(3, piece(due_code::EXITS, &exits, Some(&w), vec![]));
        assert_eq!(sent_kinds(&out.send), vec!["lists"]);
        let lists = lists_for(&w, &out.send).unwrap();
        rig.frame(lists);
        let c = rig.commit();
        let a = land(&mut rig, &mut w, &exits, by, &c);
        assert_eq!(a.removed, vec![people[0].seat]);

        // A second keyholder promoted: a desktop of another account
        let cand = world::Holder::desktop(9);
        let promote = w.promote_due(&cand);
        let own: EndorsedPair = (&pair).into();
        let out = rig.due(
            4,
            piece(due_code::PROMOTE, &promote, Some(&w), vec![own.clone()]),
        );
        if let Some(lists) = lists_for(&w, &out.send) {
            rig.frame(lists);
        }
        let c = rig.commit();
        let add_keyring = c.keyring.clone();
        land(&mut rig, &mut w, &promote, by, &c);
        w.holders.push(cand);
        assert_eq!(w.head.header().keyholders.len(), 2);

        // A refresh due loses the head to the other keyholder's Join, and is rebased
        let refresh = w.due(DueKind::Refresh);
        let refresh_piece = piece(due_code::REFRESH, &refresh, Some(&w), vec![own]);
        let out = rig.due(5, refresh_piece);
        if let Some(lists) = lists_for(&w, &out.send) {
            rig.frame(lists);
        }
        let first = rig.commit();
        let late = world::Member::account(30);
        let jb = w.join(&[&late]);
        rig.took(&jb.header);
        rig.now = w.now * 1000;
        let out = rig.frame(ServerMessage::EpochStale {
            group: TEXT_ID.into(),
            due: 5,
            reason: stale::HEAD_MOVED,
            detail: String::new(),
            head: Some(gk::WalkLinkIn {
                header: gk::HeaderIn {
                    body: jb.header.body().to_vec(),
                    sig: jb.header.sig().to_vec(),
                },
                parent: None,
            }),
        });
        assert_eq!(
            sent_kinds(&out.send),
            vec!["keyring"],
            "the keyring at the new head"
        );
        let mut stream = vec![];
        gk::put_keyring_entry(&mut stream, &add_keyring).unwrap();
        gk::put_keyring_entry(&mut stream, &jb.commit.keyring).unwrap();
        let h = jb.header.header();
        let out = rig.frame(ServerMessage::KeyringIn {
            group: TEXT_ID.into(),
            gen: h.gen,
            epoch: h.epoch,
            join: h.join,
            part: 0,
            last: true,
            piece: KeyringPiece { krk: None, stream },
        });
        if let Some(lists) = lists_for(&w, &out.send) {
            rig.frame(lists);
        }
        let again = rig.commit();
        assert_ne!(again.body, first.body, "made again on the new head");
        let a = land(&mut rig, &mut w, &refresh, by, &again);
        assert_eq!(a.header.header().parent, jb.header.d());
        assert!(
            rig.duty.keep.unnamed.is_empty(),
            "the Join's seats are named: {:?}",
            rig.duty.keep.unnamed
        );
    }

    #[test]
    fn a_desktop_replaces_its_pair_before_it_volunteers_with_the_new_one() {
        let a = [5; 16];
        let mut rig = Rig::new(Some(a), Platform::Desktop);
        let sent = rig.start();
        let ep = Rig::volunteered(&sent);
        assert_eq!(ep.origin, gk::origin::DESKTOP);
        let me = MemberId::Account(a);
        let old = wire::pair(&ep, me.into()).unwrap();
        // The Genesis seats the account's own seat
        let keys = rig.who.seat_keys.as_ref().unwrap();
        let public = keys.pair.public();
        let e =
            Endorsement::sign(&rig.who.identity, Origin::VaultSeat, me, 1, T0, &public).unwrap();
        let due = Due {
            joiners: vec![Joiner {
                seat: public.seat(me),
                ik: raw(&rig.who.identity),
                keys: public,
                endorsement: e,
                returning: false,
            }],
            volunteer: Some(Candidate {
                m: me,
                ik: raw(&rig.who.identity),
                pair: old.clone(),
            }),
            ..Due::of(DueKind::Genesis, false)
        };
        rig.due(1, piece(due_code::GENESIS, &due, None, vec![]));
        let c = rig.commit();
        let by_old = HolderRef {
            m: me,
            kx: old.kx(),
        };
        let ap = World::check_start(GroupKind::Text, TEXT_ID, true, &due, by_old, &c, T0, &[])
            .unwrap_or_else(|bad| panic!("{bad}"));
        let h = ap.header.clone();
        let mut w = world_after(&due, ap, rig.sent());
        rig.took(&h);
        rig.now = w.now * 1000;
        rig.tick();

        // The account's seat keys rotate: the Replace is asked with the old pair still
        // volunteered, and no new volunteer goes yet
        let rotated = SeatKeys::from_bytes(&rig.who.seat_keys.as_ref().unwrap().to_bytes())
            .unwrap()
            .rotate(T0 + 10)
            .unwrap();
        rig.who.seat_keys = Some(rotated);
        let mut out = GkOut::default();
        rig.duty
            .seat_keys_changed(&mut rig.who, &mut rig.groups, &mut out);
        assert_eq!(sent_kinds(&out.send), vec!["replace"]);
        let ClientMessage::KeyholdReplace { old: tag_old, pair } = out.send[0].clone() else {
            unreachable!()
        };
        assert_eq!(tag_old, kx_tag(&old.kx()));
        assert_eq!(pair.n, 2);
        let new = wire::pair(&pair, me.into()).unwrap();
        assert_eq!(
            rig.duty.own_kx(TEXT_ID),
            Some(new.kx()),
            "its own Replace is no swap it did not make"
        );
        let kept = rig.duty.take_keep().expect("the keep moved");
        assert!(kept.old.is_some() && kept.pair.as_ref().unwrap().n == 2);

        // The Replace due: built from the old pair's entry, taken
        let replace = Due {
            replace: Some(ReplaceAsk {
                old: tag_old,
                pair: new.clone(),
            }),
            ..w.due(DueKind::Replace)
        };
        let out = rig.due(2, piece(due_code::REPLACE, &replace, Some(&w), vec![]));
        if let Some(lists) = lists_for(&w, &out.send) {
            rig.frame(lists);
        }
        let c = rig.commit();
        land(&mut rig, &mut w, &replace, by_old, &c);
        assert!(w.head.header().keyholders.iter().any(|k| k.kx == new.kx()));
        // Settled: the new pair volunteers, the old one is gone
        rig.now += REPLACE_SETTLE_MS;
        let out = rig.tick();
        assert_eq!(sent_kinds(&out.send), vec!["volunteer"]);
        assert_eq!(Rig::volunteered(&out.send).dh, new.keys.dh_bytes().to_vec());
        assert!(rig.duty.take_keep().unwrap().old.is_none());
        assert_eq!(rig.duty.own_kx(TEXT_ID), Some(new.kx()));
    }

    #[test]
    fn a_desktop_keeps_its_pair_across_connections_and_a_phone_offers_nothing() {
        let a = [6; 16];
        let mut rig = Rig::new(Some(a), Platform::Desktop);
        let first = Rig::volunteered(&rig.start());
        let keep = rig.duty.take_keep().expect("the pair is kept");
        let mut next = Rig::new(Some(a), Platform::Desktop);
        next.who.identity = same_ik(&rig.who.identity);
        next.duty.keep_in(&keep);
        let again = Rig::volunteered(&next.start());
        assert_eq!(first, again, "the same pair and endorsement");
        assert!(next.duty.take_keep().is_none(), "nothing new to keep");
        // Through serde, as gk_local.bin holds it
        let bytes = postcard::to_allocvec(&keep).unwrap();
        let back: HolderKeep = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(
            back.pair.as_ref().and_then(KeptPair::open).map(|m| m.kx()),
            keep.pair.as_ref().and_then(KeptPair::open).map(|m| m.kx())
        );

        let mut phone = Rig::new(Some(a), Platform::Phone);
        assert!(phone.start().is_empty(), "a phone holds no text keys");
        let out = phone.due(1, DuePiece::default());
        assert_eq!(declined(&out), Some(decline::PLATFORM));
    }

    #[test]
    fn help_switched_off_resigns_each_text_group_held_before_the_volunteer_goes() {
        let mut rig = Rig::new(None, Platform::Desktop);
        genesis(&mut rig);
        let mut out = GkOut::default();
        rig.duty
            .set_volunteer(&mut rig.who, &mut rig.groups, false, &mut out);
        assert_eq!(sent_kinds(&out.send), vec!["resign", "unvolunteer"]);
    }

    #[test]
    fn a_due_is_declined_off_the_relays_clock_on_a_hidden_browser_and_for_an_old_counter() {
        let mut rig = Rig::new(None, Platform::Desktop);
        let (w, pair) = genesis(&mut rig);
        rig.duty.skew = KEYHOLDER_SKEW_SECS as i64 + 1;
        let out = rig.due(
            9,
            piece(
                due_code::REFRESH,
                &w.due(DueKind::Refresh),
                Some(&w),
                vec![],
            ),
        );
        assert_eq!(declined(&out), Some(decline::CLOCK));
        rig.duty.skew = 0;

        // A candidate whose counter is below one this keyholder saw for its account
        let cand = world::Holder::desktop(9);
        let account = [9; 16];
        rig.pins.raise(
            account,
            Seen {
                n: 5,
                made: T0 - 3600,
            },
            true,
        );
        let promote = w.promote_due(&cand);
        let own: EndorsedPair = (&pair).into();
        let out = rig.due(10, piece(due_code::PROMOTE, &promote, Some(&w), vec![own]));
        if let Some(lists) = lists_for(&w, &out.send) {
            let out = rig.frame(lists);
            assert_eq!(declined(&out), Some(decline::CANDIDATE));
        } else {
            assert_eq!(declined(&out), Some(decline::CANDIDATE));
        }

        let mut browser = Rig::new(None, Platform::Browser);
        let _ = browser.start();
        let mut out = GkOut::default();
        browser.duty.visibility(
            &mut browser.who,
            &mut browser.groups,
            false,
            false,
            &mut out,
        );
        assert_eq!(sent_kinds(&out.send), vec!["unvolunteer"]);
        browser.who.visible = false;
        let out = browser.due(1, DuePiece::default());
        assert_eq!(declined(&out), Some(decline::NOT_READY));
    }

    #[test]
    fn seats_a_join_sealed_that_no_header_names_in_70_minutes_are_told() {
        let mut rig = Rig::new(None, Platform::Desktop);
        let (w, _) = genesis(&mut rig);
        let people: Vec<world::Member> = (10..12).map(world::Member::account).collect();
        let refs: Vec<&world::Member> = people.iter().collect();
        let join = w.join_due(&refs);
        rig.due(2, piece(due_code::JOIN, &join, Some(&w), vec![]));
        let _ = rig.commit();
        assert_eq!(rig.duty.keep.unnamed.len(), 1);
        rig.now += EPOCH_AGE_MAX_SECS * 1000;
        let out = rig.tick();
        assert_eq!(
            out.events,
            vec![GkEvent::Warning {
                channel_id: CH,
                kind: Warn::UnnamedSeats,
                n: 2
            }]
        );
        assert!(rig.duty.keep.unnamed.is_empty());
    }

    #[test]
    fn a_volunteer_starts_a_stored_group_anew_by_a_regenesis_after_an_hour_with_no_keyholder() {
        let mut w = World::text(true, false);
        let people: Vec<world::Member> = (10..13).map(world::Member::account).collect();
        w.join(&people.iter().collect::<Vec<_>>());
        let a = [5; 16];
        let mut rig = Rig::new(Some(a), Platform::Desktop);
        rig.took(&w.kh.clone());
        rig.took(&w.head.clone());
        w.tick(3600);
        w.no_keyholder_since = Some(w.now - 3600);
        rig.now = w.now * 1000;

        let ep = Rig::volunteered(&rig.start());
        let me = MemberId::Account(a);
        let pair = wire::pair(&ep, me.into()).unwrap();
        let public = rig.who.seat_keys.as_ref().unwrap().pair.public();
        let e =
            Endorsement::sign(&rig.who.identity, Origin::VaultSeat, me, 1, T0, &public).unwrap();
        let due = Due {
            joiners: vec![Joiner {
                seat: public.seat(me),
                ik: raw(&rig.who.identity),
                keys: public,
                endorsement: e,
                returning: false,
            }],
            volunteer: Some(Candidate {
                m: me,
                ik: raw(&rig.who.identity),
                pair: pair.clone(),
            }),
            ..w.due(DueKind::Regenesis)
        };
        let out = rig.due(1, piece(due_code::REGENESIS, &due, Some(&w), vec![]));
        assert!(
            out.build_ready,
            "no keyring asked: {:?}",
            sent_kinds(&out.send)
        );
        let c = rig.commit();
        let by = HolderRef {
            m: me,
            kx: pair.kx(),
        };
        let landed = land(&mut rig, &mut w, &due, by, &c);
        let h = landed.header.header();
        assert_eq!((h.kind, h.seed, h.seats), (Kind::Regenesis, 2, 1));
        assert_eq!(h.keyholders.len(), 1);
        assert!(rig.duty.holds(TEXT_ID));
        assert_eq!(rig.duty.own_kx(TEXT_ID), Some(pair.kx()));
    }

    #[test]
    fn a_text_removal_a_day_on_rolls_the_seed_and_a_page_gives_each_seat_its_seed_welcome() {
        let mut rig = Rig::new(None, Platform::Desktop);
        let (mut w, pair) = genesis(&mut rig);
        let by = HolderRef {
            m: MemberId::Conn(U),
            kx: pair.kx(),
        };
        let own: EndorsedPair = (&pair).into();
        let people: Vec<world::Member> = (10..13).map(world::Member::account).collect();
        let join = w.join_due(&people.iter().collect::<Vec<_>>());
        rig.due(2, piece(due_code::JOIN, &join, Some(&w), vec![]));
        let c = rig.commit();
        land(&mut rig, &mut w, &join, by, &c);

        let cand = world::Holder::desktop(9);
        let promote = w.promote_due(&cand);
        let out = rig.due(
            3,
            piece(due_code::PROMOTE, &promote, Some(&w), vec![own.clone()]),
        );
        if let Some(lists) = lists_for(&w, &out.send) {
            rig.frame(lists);
        }
        let c = rig.commit();
        land(&mut rig, &mut w, &promote, by, &c);
        w.holders.push(cand);

        // A day on, the other keyholder's removal starts the roll unasked
        w.tick(86_400);
        rig.now = w.now * 1000;
        let remove = w.remove_due(0);
        let out = rig.due(4, piece(due_code::REMOVE, &remove, Some(&w), vec![own]));
        if let Some(lists) = lists_for(&w, &out.send) {
            rig.frame(lists);
        }
        let c = rig.commit();
        let landed = land(&mut rig, &mut w, &remove, by, &c);
        let h = landed.header.header();
        assert_eq!(
            (h.kind, h.seed, h.seed_floor),
            (Kind::KeyholdersRemove, 2, 1)
        );

        // A seed-welcome page: one welcome per seat, under the new seed, each its own
        let seed_seats: Vec<gk::SeedSeat> = people
            .iter()
            .map(|p| gk::SeedSeat {
                seat: p.seat.into(),
                ik: p.ik_raw(),
                keys: (&Pair {
                    keys: p.pair.public(),
                    endorsement: p.endorsement.clone(),
                })
                    .into(),
            })
            .collect();
        let page = DuePiece {
            kind: due_code::SEED_WELCOMES,
            parent: w.head.d(),
            seed_seats: seed_seats.clone(),
            ..DuePiece::default()
        };
        assert!(rig.due(5, page.clone()).build_ready);
        assert_eq!(declined(&rig.jobs()), None);
        let frames = rig.uploads();
        let [ClientMessage::EpochWelcomes {
            due: 5,
            gen,
            seed: 2,
            welcomes,
            ..
        }] = &frames[..]
        else {
            panic!("one page: {}", frames.len());
        };
        assert_eq!(*gen, w.g.gen());
        assert_eq!(welcomes.len(), people.len());
        let from = crate::group_key::Holder::from_raw(by.m, &by.kx).unwrap();
        for p in &people {
            let sent = welcomes
                .iter()
                .find(|x| SeatRef::from(x.seat) == p.seat)
                .expect("a welcome for every seat asked");
            assert!(open_seed_welcome(&w.g, 2, &p.me(), &from, &sent.bytes).is_ok());
        }

        // A seat whose keys are not its own gets nothing
        let mut forged = page;
        forged.seed_seats[0].keys = seed_seats[1].keys.clone();
        assert_eq!(declined(&rig.due(6, forged)), Some(decline::NOT_READY));
        assert!(rig.uploads().is_empty());
    }

    #[test]
    fn a_lists_ask_left_unanswered_stalls_no_later_due() {
        let mut rig = Rig::new(None, Platform::Desktop);
        let (mut w, pair) = genesis(&mut rig);
        let by = HolderRef {
            m: MemberId::Conn(U),
            kx: pair.kx(),
        };
        let people: Vec<world::Member> = (10..13).map(world::Member::account).collect();
        let join = w.join_due(&people.iter().collect::<Vec<_>>());
        rig.due(2, piece(due_code::JOIN, &join, Some(&w), vec![]));
        let c = rig.commit();
        land(&mut rig, &mut w, &join, by, &c);

        // The lists ask is refused (as a `COMMIT`'s, which the duty never sees)
        let exits = w.exits(&[people[0].seat], DueKind::Exits);
        let out = rig.due(3, piece(due_code::EXITS, &exits, Some(&w), vec![]));
        assert_eq!(sent_kinds(&out.send), vec!["lists"]);
        // The relay asks again: the lists are asked again, and the commit is taken
        let out = rig.due(4, piece(due_code::EXITS, &exits, Some(&w), vec![]));
        assert_eq!(sent_kinds(&out.send), vec!["lists"]);
        rig.frame(lists_for(&w, &out.send).unwrap());
        let c = rig.commit();
        let a = land(&mut rig, &mut w, &exits, by, &c);
        assert_eq!(a.removed, vec![people[0].seat]);
    }

    #[test]
    fn a_signed_in_device_whose_seat_keys_settle_late_volunteers_then_and_replaces_a_pair_behind() {
        let a = [5; 16];
        // An account's first connection under the group key: no keys at `GroupKeys` yet
        for platform in [Platform::Desktop, Platform::Browser] {
            let mut rig = Rig::new(Some(a), platform);
            let keys = rig.who.seat_keys.take();
            assert!(rig.start().is_empty(), "nothing to offer without seat keys");
            rig.who.seat_keys = keys;
            let mut out = GkOut::default();
            rig.duty
                .seat_keys_changed(&mut rig.who, &mut rig.groups, &mut out);
            assert_eq!(sent_kinds(&out.send), vec!["volunteer"], "{platform:?}");
        }
        // The keys rotated at sign-in: the kept pair volunteers, then its Replace goes
        let mut first = Rig::new(Some(a), Platform::Desktop);
        let old = Rig::volunteered(&first.start());
        let keep = first.duty.take_keep().unwrap();
        let rotated = SeatKeys::from_bytes(&first.who.seat_keys.as_ref().unwrap().to_bytes())
            .unwrap()
            .rotate(T0 + 10)
            .unwrap();
        let mut next = Rig::new(Some(a), Platform::Desktop);
        next.who.identity = same_ik(&first.who.identity);
        next.duty.keep_in(&keep);
        next.who.seat_keys = None;
        assert!(next.start().is_empty());
        next.who.seat_keys = Some(rotated);
        let mut out = GkOut::default();
        next.duty
            .seat_keys_changed(&mut next.who, &mut next.groups, &mut out);
        assert_eq!(sent_kinds(&out.send), vec!["volunteer", "replace"]);
        assert_eq!(
            Rig::volunteered(&out.send),
            old,
            "the pair its entries name"
        );
    }

    #[test]
    fn a_voice_joiners_connection_pair_of_any_age_is_seated_but_not_below_a_counter_seen() {
        let (a, u) = ([8; 16], 21);
        let ik = IdentityKeyPair::generate(&mut crate::rng());
        let joiner = |n: u32, made: u64| {
            let keys = SeatPair::generate().public();
            let e = Endorsement::sign(&ik, Origin::Connection, MemberId::Conn(u), n, made, &keys)
                .unwrap();
            Joiner {
                seat: keys.seat(MemberId::Account(a)),
                ik: raw(&ik),
                keys,
                endorsement: e,
                returning: false,
            }
        };
        let at = T0 + 7200;
        let mut pins = MemoryPins::default();
        let mut c = GkCtx {
            pins: &mut pins,
            now: at * 1000,
        };
        fn why(j: &Joiner, c: &mut GkCtx<'_>) -> Option<u8> {
            joiner_why(GroupKind::Voice, false, j, T0 + 7200, c, &HashSet::new())
        }
        // Made with the connection, two hours before this join
        assert_eq!(why(&joiner(1, T0), &mut c), None);
        // Never ahead of the join
        let ahead = joiner(1, at + CLOCK_SLACK + 1);
        assert_eq!(why(&ahead, &mut c), Some(join_refused::ENDORSEMENT));
        // Below a counter seen before the join
        c.pins.raise(
            a,
            Seen {
                n: 2,
                made: T0 + 60,
            },
            true,
        );
        assert_eq!(why(&joiner(1, T0), &mut c), Some(join_refused::OLD_COUNTER));
    }

    /// §11.8, plan 16: in an anonymous room a signed-in member's voice seat is named by its
    /// connection, and its 0x02 pair carries the account's counter: seated as it comes, with
    /// every other check kept. A text seat named by a connection is a guest's, counter 0.
    #[test]
    fn a_voice_seat_named_by_its_connection_is_seated_with_its_accounts_counter() {
        let u = 21;
        let ik = IdentityKeyPair::generate(&mut crate::rng());
        let joiner = |n: u32, signed_for: u32| {
            let keys = SeatPair::generate().public();
            let e = Endorsement::sign(
                &ik,
                Origin::Connection,
                MemberId::Conn(signed_for),
                n,
                T0,
                &keys,
            )
            .unwrap();
            Joiner {
                seat: keys.seat(MemberId::Conn(u)),
                ik: raw(&ik),
                keys,
                endorsement: e,
                returning: false,
            }
        };
        let mut pins = MemoryPins::default();
        let mut c = GkCtx {
            pins: &mut pins,
            now: (T0 + 7200) * 1000,
        };
        let why = |kind: GroupKind, j: &Joiner, c: &mut GkCtx<'_>| {
            joiner_why(kind, false, j, T0 + 7200, c, &HashSet::new())
        };
        assert_eq!(why(GroupKind::Voice, &joiner(3, u), &mut c), None);
        assert_eq!(
            why(GroupKind::Voice, &joiner(0, u), &mut c),
            None,
            "a guest"
        );
        let other = joiner(3, u + 1);
        assert_eq!(
            why(GroupKind::Voice, &other, &mut c),
            Some(join_refused::ENDORSEMENT),
            "another connection's pair"
        );
        assert_eq!(
            why(GroupKind::Text, &joiner(3, u), &mut c),
            Some(join_refused::ENDORSEMENT),
            "a text guest's counter is 0"
        );
        assert_eq!(why(GroupKind::Text, &joiner(0, u), &mut c), None);
    }

    #[test]
    fn a_signed_in_desktop_starts_a_voice_room_with_its_connection_pair() {
        let a = [5; 16];
        let mut rig = Rig::new(Some(a), Platform::Desktop);
        let _ = rig.start();
        let me = MemberId::Account(a);
        let ep = seat_keys::conn_pair(&mut rig.who, rig.now).unwrap();
        let pair = wire::pair(&ep, GkMember::Conn(U)).unwrap();
        let mut m = Member::new(
            GkTrack {
                group: world::VOICE_ID.into(),
                kind: GroupKind::Voice,
                ..track()
            },
            None,
        );
        m.voice_seats.insert(U, pair.keys.seat(me).into());
        rig.groups.insert(world::VOICE_ID.into(), m);
        let due = Due {
            joiners: vec![Joiner {
                seat: pair.keys.seat(me),
                ik: raw(&rig.who.identity),
                keys: pair.keys.clone(),
                endorsement: pair.endorsement.clone(),
                returning: false,
            }],
            volunteer: Some(Candidate {
                m: me,
                ik: raw(&rig.who.identity),
                pair: pair.clone(),
            }),
            ..Due::of(DueKind::Genesis, false)
        };
        let out = rig.frame(ServerMessage::EpochDue {
            group: world::VOICE_ID.into(),
            due: 1,
            part: 0,
            last: true,
            piece: Box::new(piece(due_code::GENESIS, &due, None, vec![])),
        });
        assert!(out.build_ready, "{:?}", sent_kinds(&out.send));
        let c = rig.commit();
        let by = HolderRef {
            m: me,
            kx: pair.kx(),
        };
        let ap = World::check_start(
            GroupKind::Voice,
            world::VOICE_ID,
            false,
            &due,
            by,
            &c,
            T0,
            &[U],
        )
        .unwrap_or_else(|bad| panic!("{bad}"));
        assert_eq!(ap.header.header().keyholders[0].u, Some(U));
    }

    #[test]
    fn a_stale_join_is_told_unless_its_rebase_seals_its_seats_again() {
        let mut rig = Rig::new(None, Platform::Desktop);
        let (mut w, pair) = genesis(&mut rig);
        let by = HolderRef {
            m: MemberId::Conn(U),
            kx: pair.kx(),
        };
        let kh_ring = second_keyholder(&mut rig, &mut w, &pair);

        // Our Join loses the head to the other keyholder's, is made again on it and taken:
        // nothing told meanwhile, its record is the rebased one's
        let people: Vec<world::Member> = (10..12).map(world::Member::account).collect();
        let join = w.join_due(&people.iter().collect::<Vec<_>>());
        rig.due(3, piece(due_code::JOIN, &join, Some(&w), vec![]));
        let _ = rig.commit();
        let late = world::Member::account(30);
        let jb = w.join(&[&late]);
        rig.took(&jb.header);
        rig.now = w.now * 1000;
        let out = rig.frame(stale_on(3, stale::HEAD_MOVED, Some(&jb.header)));
        assert_eq!(sent_kinds(&out.send), vec!["keyring"]);
        assert_eq!(rig.tick().events, vec![], "not told while it is made again");
        rig.frame(keyring_at(&jb.header, &[&kh_ring, &jb.commit.keyring]));
        let again = rig.commit();
        let landed = land(&mut rig, &mut w, &join, by, &again);
        assert_eq!(landed.seated, 2);
        assert_eq!(landed.events, vec![]);
        let kept: Vec<[u8; 32]> = rig.duty.keep.unnamed.iter().map(|u| u.d).collect();
        assert_eq!(kept, vec![landed.header.d()]);

        // A Join the relay calls stale on an old head it never moves to: kept, and told once
        // the due is let go and the head moves on without it
        let more: Vec<world::Member> = (40..43).map(world::Member::account).collect();
        let join2 = w.join_due(&more.iter().collect::<Vec<_>>());
        rig.due(4, piece(due_code::JOIN, &join2, Some(&w), vec![]));
        let _ = rig.commit();
        rig.frame(stale_on(4, stale::HEAD_MOVED, Some(&w.kh.clone())));
        assert_eq!(rig.tick().events, vec![]);
        rig.frame(stale_on(4, stale::TIMED_OUT, None));
        let x = world::Member::account(31);
        let jx = w.join(&[&x]);
        rig.took(&jx.header);
        rig.now = w.now * 1000;
        assert_eq!(
            rig.tick().events,
            vec![GkEvent::Warning {
                channel_id: CH,
                kind: Warn::UnnamedSeats,
                n: 3
            }]
        );
        assert!(rig.duty.keep.unnamed.is_empty());
    }

    #[test]
    fn a_join_seats_again_a_seat_only_a_superseded_list_held() {
        let mut rig = Rig::new(None, Platform::Desktop);
        let (mut w, pair) = genesis(&mut rig);
        let by = HolderRef {
            m: MemberId::Conn(U),
            kx: pair.kx(),
        };
        let people: Vec<world::Member> = (10..13).map(world::Member::account).collect();
        let join = w.join_due(&people.iter().collect::<Vec<_>>());
        rig.due(2, piece(due_code::JOIN, &join, Some(&w), vec![]));
        let c = rig.commit();
        land(&mut rig, &mut w, &join, by, &c);
        second_keyholder(&mut rig, &mut w, &pair);

        // This keyholder fetches the list of an exit it then loses
        let exits = w.exits(&[people[0].seat], DueKind::Exits);
        let out = rig.due(4, piece(due_code::EXITS, &exits, Some(&w), vec![]));
        rig.frame(lists_for(&w, &out.send).expect("lists asked"));
        let listed = |rig: &Rig| {
            rig.duty.holds[TEXT_ID]
                .lists
                .values()
                .any(|l| l.iter().any(|s| s.seat == people[0].seat))
        };
        assert!(listed(&rig));
        rig.frame(stale_on(4, stale::TIMED_OUT, None));
        // The other keyholder re-keys the bucket without the seat, which then comes back
        let o = w.open(&exits);
        rig.took(&o.header);
        rig.now = w.now * 1000;
        let back = w.join_due(&[&people[0]]);
        let out = rig.due(5, piece(due_code::JOIN, &back, Some(&w), vec![]));
        assert_eq!(sent_kinds(&out.send), vec!["keyring"]);
        rig.frame(keyring_at(&o.header, &[&o.commit.keyring]));
        let c = rig.commit();
        let a = land(&mut rig, &mut w, &back, by, &c);
        assert_eq!((a.seated, a.refused), (1, vec![]));
    }

    #[test]
    fn a_join_named_between_ticks_or_before_a_new_generation_is_not_told() {
        // Pushed heads come faster than the ticks: each is seen as it is taken
        let mut rig = Rig::new(None, Platform::Desktop);
        let (mut w, pair) = genesis(&mut rig);
        let by = HolderRef {
            m: MemberId::Conn(U),
            kx: pair.kx(),
        };
        second_keyholder(&mut rig, &mut w, &pair);
        let people: Vec<world::Member> = (10..12).map(world::Member::account).collect();
        let join = w.join_due(&people.iter().collect::<Vec<_>>());
        rig.due(3, piece(due_code::JOIN, &join, Some(&w), vec![]));
        let c = rig.commit();
        let a = w.check(&join, by, &c).unwrap_or_else(|bad| panic!("{bad}"));
        let j = a.header.clone();
        w.take(&join, a, rig.sent());
        let next: Vec<world::Member> = (20..22).map(world::Member::account).collect();
        let j2 = w.join(&[&next[0]]).header;
        let j3 = w.join(&[&next[1]]).header;
        for h in [&j, &j2, &j3] {
            rig.took(h);
            let mut out = GkOut::default();
            let m = &rig.groups[TEXT_ID];
            rig.duty.head_taken(&mut rig.who, m, &mut out);
        }
        rig.now = w.now * 1000;
        assert_eq!(rig.tick().events, vec![]);
        assert!(rig.duty.keep.unnamed.is_empty());

        // Named, then a new generation
        let mut rig = Rig::new(None, Platform::Desktop);
        let (mut w, pair) = genesis(&mut rig);
        let by = HolderRef {
            m: MemberId::Conn(U),
            kx: pair.kx(),
        };
        let join = w.join_due(&people.iter().collect::<Vec<_>>());
        rig.due(2, piece(due_code::JOIN, &join, Some(&w), vec![]));
        let c = rig.commit();
        land(&mut rig, &mut w, &join, by, &c);
        assert_eq!(rig.duty.keep.unnamed.len(), 1);
        let anew = World::text(true, false);
        rig.took(&anew.head);
        assert_eq!(rig.tick().events, vec![]);
        assert!(rig.duty.keep.unnamed.is_empty());
    }

    #[test]
    fn a_join_of_ours_inside_a_catch_up_the_duty_sees_once_is_not_told() {
        // A reconnect's catch-up: one `EpochIn` carries our Join and two headers after it,
        // and the duty looks once, at the last
        let mut rig = Rig::new(None, Platform::Desktop);
        let (mut w, pair) = genesis(&mut rig);
        let by = HolderRef {
            m: MemberId::Conn(U),
            kx: pair.kx(),
        };
        second_keyholder(&mut rig, &mut w, &pair);
        let people: Vec<world::Member> = (10..12).map(world::Member::account).collect();
        let join = w.join_due(&people.iter().collect::<Vec<_>>());
        rig.due(3, piece(due_code::JOIN, &join, Some(&w), vec![]));
        let c = rig.commit();
        let a = w.check(&join, by, &c).unwrap_or_else(|bad| panic!("{bad}"));
        let j = a.header.clone();
        w.take(&join, a, rig.sent());
        let next: Vec<world::Member> = (20..22).map(world::Member::account).collect();
        let j2 = w.join(&[&next[0]]).header;
        let j3 = w.join(&[&next[1]]).header;
        for h in [&j, &j2, &j3] {
            rig.took(h);
        }
        let mut out = GkOut::default();
        let m = &rig.groups[TEXT_ID];
        rig.duty.head_taken(&mut rig.who, m, &mut out);
        rig.now = w.now * 1000;
        assert_eq!(rig.tick().events, vec![]);
        assert!(rig.duty.keep.unnamed.is_empty());
    }

    #[test]
    fn a_job_and_its_result_cross_threads() {
        fn send<T: Send>() {}
        send::<BuildJob>();
        send::<Built>();
        let _ = tag(&[0x05; 33]);
    }
}
