//! One group on the relay (plan 2b–2f): pure state, no IO. Each event takes the relay's
//! clock (unix ms) and an `Out` list of frames to queue; a commit is checked here
//! (`commit_part` → `Taken`), stored by the actor, then taken (`apply`). The actor reads
//! the store where an answer needs material (seat keying, keyring) and runs the timers
//! (`wake`, `tick`).

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use dashmap::DashMap;
use tracing::warn;
use voipc_crypto::group_key::build::kx_tag;
use voipc_crypto::group_key::commit::{
    validate, Applied, Commit, Due, DueKind, Exit, GroupView, HeadView as CommitHead, HolderRef,
    Joiner, Listed, Make, Pair, ReplaceAsk,
};
use voipc_crypto::group_key::timers::{
    deadline_ms, refresh_ms, BLOBS_PER_WRITER, BLOB_MAX_BYTES, DEADLINE_SLOW_MS,
    EPOCH_AGE_MAX_SECS, EPOCH_MIN_GAP_MS, FLOOR_AHEAD_GAP_SECS, OPEN_COMMIT_MS,
    OPEN_PER_CONN_BYTES, OPEN_PER_RELAY_BYTES, REGENESIS_AFTER_MS, RETRY_ALL_MISSED_MS,
    SEED_PAGE_EVERY_MS, SEED_PAGE_SEATS,
};
use voipc_crypto::group_key::tree::BucketTree;
use voipc_crypto::group_key::{
    GroupKind, Kind, MemberId, SeatRef, SeedRolls, SignedHeader, SEED_MAX_AGE,
};
use voipc_protocol::gk::{
    self, refused_what, refused_why, stale, wait, CommitPiece, DuePiece, FloorRef, GkWriter,
    HeaderIn, InPiece, Lost, NamesPiece, NamesRef, Part, Parts, RatchetStep, Seq, LISTS_PER_FRAME,
    LISTS_WANTED_MAX,
};
use voipc_protocol::messages::ServerMessage;
use voipc_protocol::types::UserId;

use super::due::{DueOut, Exits, Joins, Waiting};
use super::holders::{self, Holders, Volunteer};
use super::names::Names;
use super::push;
use super::snapshot::{header_in, link, HeadSnapshot, HeadView, Ver};

/// Why a seat exits (`EpochExit`'s cause, kept with the exit).
pub mod cause {
    pub const LEAVE: u8 = 0;
    pub const KICK: u8 = 1;
    pub const BAN: u8 = 2;
    pub const GATE: u8 = 3;
    pub const RESET: u8 = 4;
    pub const DELETED: u8 = 5;
    pub const ROTATION: u8 = 6;
    pub const EXPIRY: u8 = 7;
    pub const DISCONNECT: u8 = 8;
    pub const RESTART: u8 = 10;
    /// A memory group's seat whose welcome is gone, asked from a new connection: it exits
    /// and joins again (plan 2b).
    pub const REJOIN: u8 = 11;
}

/// What an admin is warned of (plan 2j), one line a kind, at most every
/// `WARN_EVERY_MS`.
pub mod warn_kind {
    pub const NO_KEYHOLDER: u8 = 0;
    pub const LATE: u8 = 1;
    pub const MISSED: u8 = 2;
    pub const AHEAD: u8 = 3;
}

/// A warning of a kind is logged and shown at most this often, and shown this long.
pub const WARN_EVERY_MS: u64 = 10 * 60 * 1000;

/// Eager seats queued at most, per group, unless the relay says otherwise (`kept_seats`).
pub const KEPT_SEATS: usize = 5000;

/// Seed welcomes to store, each with its seat.
pub type Welcomed = Vec<(SeatRef, Vec<u8>)>;

/// A seed-welcome page out to one keyholder (plan 2d "Seed rolls"): not a commit, so it
/// runs beside any due.
#[derive(Clone, Debug)]
pub struct Page {
    pub id: u64,
    pub sid: UserId,
    pub by: HolderRef,
    pub seed: u32,
    pub seats: HashSet<SeatRef>,
    pub deadline: u64,
}

/// Frames to one session, queued as one unit in this order.
#[derive(Debug)]
pub struct Out(pub UserId, pub Vec<ServerMessage>);

/// Open commits' bytes, by connection and relay-wide (1e: ≤ 12 MB and ≤ 64 MB).
#[derive(Default)]
pub struct OpenCaps {
    pub by_conn: DashMap<UserId, usize>,
    pub relay: AtomicUsize,
}

impl OpenCaps {
    fn charge(&self, sid: UserId, before: usize, after: usize) {
        if after >= before {
            let d = after - before;
            *self.by_conn.entry(sid).or_default() += d;
            self.relay.fetch_add(d, Ordering::Relaxed);
        } else {
            let d = before - after;
            if let Some(mut c) = self.by_conn.get_mut(&sid) {
                *c = c.saturating_sub(d);
            }
            let mut cur = self.relay.load(Ordering::Relaxed);
            while let Err(was) = self.relay.compare_exchange_weak(
                cur,
                cur.saturating_sub(d),
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                cur = was;
            }
            self.by_conn.remove_if(&sid, |_, c| *c == 0);
        }
    }

    fn room(&self, sid: UserId, more: usize) -> bool {
        let conn = self.by_conn.get(&sid).map_or(0, |c| *c);
        conn + more <= OPEN_PER_CONN_BYTES
            && self.relay.load(Ordering::Relaxed) + more <= OPEN_PER_RELAY_BYTES
    }
}

#[derive(Clone)]
pub struct Head {
    pub sh: SignedHeader,
    pub kh: SignedHeader,
    pub opening: SignedHeader,
    /// A Regenesis head's parent.
    pub parent: Option<SignedHeader>,
    /// When its epoch opened, relay ms.
    pub opened_ms: u64,
}

/// A seated seat: what a row to it needs (`dh`), where it sits, the seed it holds.
#[derive(Clone, Debug)]
pub struct Seat {
    pub b: u64,
    pub seed: u32,
    pub dh: [u8; 33],
    pub account: Option<[u8; 16]>,
}

/// A follower's session.
#[derive(Clone, Debug, Default)]
pub struct Member {
    pub account: Option<[u8; 16]>,
    pub seat: Option<SeatRef>,
    /// Wrote a blob in the head epoch.
    pub writer: bool,
    /// Waits for keys since a fetch.
    pub waiting: bool,
    /// The floor its last queued fetch named: the answer once it is seated walks from here
    /// (2d, "walk+head since `have`"), not from the generation's start.
    pub have: Option<FloorRef>,
    /// The last exit `seq` it was told as a writer: `EpochExit` goes once per exit.
    pub told: u64,
}

/// What a fetch asks, as the caller resolved it.
#[derive(Clone, Default)]
pub struct Fetch {
    pub have: Option<FloorRef>,
    /// The seat pair the session may be seated with: an account's seat keys (text), else
    /// the connection's (`EpochFetch.seat`).
    pub pair: Option<Pair>,
    pub ik: Option<[u8; 32]>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Fetched {
    /// Seated at the head: answer from the snapshot.
    Seated(SeatRef),
    /// Queued, refused or waiting: the outs say so.
    Not,
}

/// A commit checked and not yet stored.
pub struct Taken {
    pub due: DueOut,
    pub commit: Commit,
    pub applied: Applied,
    pub sid: UserId,
    /// Who made its welcomes and rows: the signer's entry, a Replace's new one.
    pub maker: HolderRef,
    pub vers: Vec<((u64, u64), Ver)>,
    /// The head it was built on.
    pub was: Option<[u8; 32]>,
    pub head: Head,
    pub new_gen: bool,
}

/// How many headers stay in a row behind the head beside its epoch's (§4.4).
const RECENT: usize = 64;

pub struct GroupState {
    pub id: String,
    pub kind: GroupKind,
    /// A `c:` group on a relay with accounts: its store is the database.
    pub stored: bool,
    /// The channel's gate as the relay holds it; the head's may lag (plan 2d).
    pub gate: bool,
    pub head: Option<Head>,
    pub gens: Vec<[u8; 16]>,
    pub gen_time: u64,
    pub used_v: HashSet<u64>,
    pub rolls: SeedRolls,
    pub leaves: Arc<Vec<Listed>>,
    pub tree: Arc<BucketTree>,
    pub vers: HashMap<(u64, u64), Ver>,
    pub seals: HashMap<(u64, u64), Vec<u8>>,
    pub seats: HashMap<SeatRef, Seat>,
    pub khs: super::snapshot::Khs,
    pub recent: VecDeque<SignedHeader>,
    pub members: HashMap<UserId, Member>,
    pub vols: HashMap<UserId, Volunteer>,
    pub holders: Holders,
    pub joins: Joins,
    pub exits: Exits,
    pub dues: Vec<DueOut>,
    pub open: HashMap<UserId, (Parts<u64, CommitPiece>, u64)>,
    pub caps: Arc<OpenCaps>,
    pub replaces: Vec<(UserId, ReplaceAsk)>,
    pub resigns: Vec<HolderRef>,
    /// Seats that exited while the due seating them was out (due id, seat, cause): they
    /// exit once it lands.
    exit_late: Vec<(u64, SeatRef, u8)>,
    next_due: u64,
    /// Keyholders that missed or declined since the last commit landed: pass-over skips them.
    passed: Vec<UserId>,
    retry_at: Option<u64>,
    pub blobs: HashMap<(u32, GkWriter), Vec<Vec<u8>>>,
    pub last_opening: u64,
    pub next_refresh: Option<u64>,
    pub no_keyholder_since: Option<u64>,
    pub last_commit: u64,
    pub missed_total: u32,
    /// A new generation is due: the next fetch asks a Genesis (floor ahead, an old
    /// incarnation, the switch back on).
    pub new_gen: bool,
    floor_ahead_at: Option<u64>,
    pub names: Names,
    /// Connection seats' identity keys and pairs, from their joins: their seed welcomes'
    /// KEM keys (an account seat's are its published seat keys).
    pub conn_keys: HashMap<SeatRef, ([u8; 32], Pair)>,
    /// The seed-welcome page out, and when the next may be asked.
    pub page: Option<Page>,
    pub next_page: u64,
    /// Seats behind a running roll that fetched: first in the next page, without waiting
    /// for its pace.
    pub seed_first: HashSet<SeatRef>,
    /// The keyholder that declined the last page: the next goes to another if one is online.
    page_declined: Option<UserId>,
    /// Memory seats whose welcome is gone, re-joining once their exit is taken (2b).
    pub rejoins: Vec<Waiting>,
    /// Eager seats queued at most (`kept_seats`).
    pub kept_seats: usize,
    /// The device each volunteering session named, for its entry (plan 2d).
    pub devices: HashMap<UserId, Vec<u8>>,
    /// Admin warnings by kind: the text and when it was raised (plan 2j).
    pub warns: HashMap<u8, (String, u64)>,
}

impl GroupState {
    pub fn new(id: String, kind: GroupKind, stored: bool, caps: Arc<OpenCaps>) -> GroupState {
        GroupState {
            id,
            kind,
            stored,
            gate: false,
            head: None,
            gens: vec![],
            gen_time: 0,
            used_v: HashSet::new(),
            rolls: SeedRolls {
                raised: 0,
                removal: false,
            },
            leaves: Arc::new(vec![]),
            tree: Arc::new(BucketTree::new(&[]).expect("an empty tree")),
            vers: HashMap::new(),
            seals: HashMap::new(),
            seats: HashMap::new(),
            khs: HashMap::new(),
            recent: VecDeque::new(),
            members: HashMap::new(),
            vols: HashMap::new(),
            holders: Holders::default(),
            joins: Joins::default(),
            exits: Exits::new(1),
            dues: vec![],
            open: HashMap::new(),
            caps,
            replaces: vec![],
            resigns: vec![],
            exit_late: vec![],
            next_due: 1,
            passed: vec![],
            retry_at: None,
            blobs: HashMap::new(),
            last_opening: 0,
            next_refresh: None,
            no_keyholder_since: None,
            last_commit: 0,
            missed_total: 0,
            new_gen: false,
            floor_ahead_at: None,
            names: Names::default(),
            conn_keys: HashMap::new(),
            page: None,
            next_page: 0,
            seed_first: HashSet::new(),
            page_declined: None,
            rejoins: vec![],
            kept_seats: KEPT_SEATS,
            devices: HashMap::new(),
            warns: HashMap::new(),
        }
    }

    // ── Frames ────────────────────────────────────────────────────────────

    fn wait(&self, out: &mut Vec<Out>, sid: UserId, why: u8, detail: &str) {
        out.push(Out(
            sid,
            vec![ServerMessage::EpochWait {
                group: self.id.clone(),
                why,
                detail: detail.into(),
            }],
        ));
    }

    pub fn refuse(&self, out: &mut Vec<Out>, sid: UserId, what: u8, why: u8) {
        out.push(Out(
            sid,
            vec![ServerMessage::EpochRefused {
                group: self.id.clone(),
                what,
                why,
                detail: String::new(),
            }],
        ));
    }

    fn stale(&self, out: &mut Vec<Out>, sid: UserId, due: u64, reason: u8, detail: &str) {
        let mut detail = detail.to_string();
        detail.truncate(gk::DETAIL_MAX_BYTES);
        out.push(Out(
            sid,
            vec![ServerMessage::EpochStale {
                group: self.id.clone(),
                due,
                reason,
                detail,
                head: self.head.as_ref().map(|h| link(&h.sh, h.parent.as_ref())),
            }],
        ));
    }

    fn pushed(&self, out: &mut Vec<Out>, sid: UserId, piece: InPiece) {
        out.push(Out(
            sid,
            push::epoch_in(
                &self.id,
                InPiece {
                    pushed: true,
                    ..piece
                },
            ),
        ));
    }

    // ── Who is here ───────────────────────────────────────────────────────

    pub fn gen(&self) -> Option<[u8; 16]> {
        self.head.as_ref().map(|h| h.sh.header().gen)
    }

    fn head_gated(&self) -> bool {
        self.head.as_ref().is_some_and(|h| h.sh.header().gated)
    }

    pub fn follow(&mut self, sid: UserId, account: Option<[u8; 16]>) {
        self.members.entry(sid).or_insert(Member {
            account,
            ..Member::default()
        });
    }

    /// A session leaves the group (unfollow, kick, disconnect): its seat exits when no
    /// other session holds it, but going offline is no exit for an account's text seat
    /// (§5.4); a due it was asked goes to another keyholder.
    pub fn leave(&mut self, sid: UserId, cause: u8, now: u64, out: &mut Vec<Out>) {
        let Some(m) = self.members.remove(&sid) else {
            return;
        };
        self.vols.remove(&sid);
        if let Some((p, _)) = self.open.remove(&sid) {
            self.caps.charge(sid, p.held(), 0);
        }
        self.joins.drop_sid(sid);
        let stored = self.stored;
        self.joins
            .queue
            .retain(|w| !w.sids.is_empty() || (stored && w.account.is_some()));
        if let Some(seat) = m.seat {
            let offline =
                cause == cause::DISCONNECT && !seat.m.is_conn() && self.kind == GroupKind::Text;
            if !offline && !self.members.values().any(|o| o.seat == Some(seat)) {
                self.exit(seat, cause, now, out);
            }
        }
        if let Some(i) = self.dues.iter().position(|d| d.sid == sid) {
            self.dues.remove(i);
        }
        if self.page.as_ref().is_some_and(|p| p.sid == sid) {
            self.page = None;
            self.next_page = now;
        }
        self.devices.remove(&sid);
        for w in &mut self.rejoins {
            w.sids.retain(|s| *s != sid);
        }
        self.holders.seen(&self.vols, now);
        self.ask(now, out);
    }

    /// Every seat of `account` exits (log leave, ban, reset, deletion, rotation, expiry),
    /// a seat a due out is seating once that lands. A ban, reset or deletion takes its
    /// keyholder entries too: the signed head names them, so each one's Remove is asked of
    /// another online entry, and a due out that would add or swap in an entry of it goes.
    pub fn account_exit(&mut self, account: &[u8; 16], cause: u8, now: u64, out: &mut Vec<Out>) {
        if matches!(cause, cause::BAN | cause::RESET | cause::DELETED) {
            let ours = |m: &MemberId| m.account().as_ref() == Some(account);
            for k in &self.holders.set {
                let r = HolderRef::of(k);
                if ours(&k.m) && !self.holders.forced.contains(&r) {
                    self.holders.forced.push(r);
                }
            }
            let gone: Vec<(UserId, u64)> = self
                .dues
                .iter()
                .filter(|d| {
                    d.due.candidate.as_ref().is_some_and(|c| ours(&c.m))
                        || (d.due.replace.is_some() && ours(&d.by.m))
                })
                .map(|d| (d.sid, d.id))
                .collect();
            self.dues.retain(|d| !gone.contains(&(d.sid, d.id)));
            for (sid, id) in gone {
                self.drop_open(sid);
                self.stale(out, sid, id, stale::NOT_DUE, "");
            }
            let members = &self.members;
            self.replaces.retain(|(sid, _)| {
                members
                    .get(sid)
                    .is_none_or(|m| m.account.as_ref() != Some(account))
            });
            // Its sessions still up after a reset hold the old identity (a reset at a sign-in
            // elsewhere ends none): they volunteer no more, or their old seat and pair would
            // be seated and promoted again
            if cause == cause::RESET {
                self.vols.retain(|_, v| !ours(&v.m));
            }
        }
        let mut seats: Vec<SeatRef> = self
            .seats
            .iter()
            .filter(|(_, s)| s.account.as_ref() == Some(account))
            .map(|(r, _)| *r)
            .collect();
        seats.extend(
            self.dues
                .iter()
                .flat_map(|d| &d.due.joiners)
                .map(|j| j.seat)
                .filter(|s| s.m.account() == Some(*account)),
        );
        for s in seats {
            self.exit(s, cause, now, out);
        }
        self.joins
            .queue
            .retain(|w| w.account.as_ref() != Some(account));
        self.rejoins.retain(|w| w.account.as_ref() != Some(account));
        for m in self.members.values_mut() {
            if m.account.as_ref() == Some(account) {
                m.seat = None;
            }
        }
        self.ask(now, out);
    }

    /// A seat enters the open exit batch; writers of the epoch hear of it at once (1f.6).
    /// A seat a due out is seating exits once that lands.
    pub fn exit(&mut self, seat: SeatRef, cause: u8, now: u64, out: &mut Vec<Out>) {
        if self.joins.has(&seat) {
            self.joins.queue.retain(|w| w.joiner.seat != seat);
        }
        if !self.seats.contains_key(&seat) {
            let seating = self
                .dues
                .iter()
                .find(|d| d.due.joiners.iter().any(|j| j.seat == seat));
            if let Some(d) = seating {
                if !self.exit_late.iter().any(|(_, s, _)| *s == seat) {
                    self.exit_late.push((d.id, seat, cause));
                }
            }
            return;
        }
        let (Some(s), Some(gen)) = (self.seats.get(&seat), self.gen()) else {
            return;
        };
        if self.exits.has(&seat) {
            return;
        }
        let seq = self.exits.add(seat, s.b, cause, now);
        for (sid, m) in self.members.iter_mut() {
            if m.writer {
                m.told = m.told.max(seq);
                out.push(Out(
                    *sid,
                    vec![ServerMessage::EpochExit {
                        group: self.id.clone(),
                        gen,
                        seq,
                    }],
                ));
            }
        }
    }

    /// A session's `KeyholdVolunteer`, or its end (`None`).
    pub fn volunteer(&mut self, sid: UserId, v: Option<Volunteer>, now: u64, out: &mut Vec<Out>) {
        if !self.members.contains_key(&sid) {
            return;
        }
        match v {
            Some(v) => {
                self.vols.insert(sid, v);
            }
            None => {
                self.vols.remove(&sid);
            }
        }
        self.holders.seen(&self.vols, now);
        self.ask(now, out);
    }

    // ── Fetch ─────────────────────────────────────────────────────────────

    pub fn fetch(&mut self, sid: UserId, f: Fetch, now: u64, out: &mut Vec<Out>) -> Fetched {
        let Some(m) = self.members.get(&sid).cloned() else {
            self.refuse(out, sid, refused_what::FETCH, refused_why::NOT_MEMBER);
            return Fetched::Not;
        };
        if let (Some(seat), Some(_), false) = (m.seat, &self.head, self.new_gen) {
            if self.rejoins.iter().any(|w| w.joiner.seat == seat) {
                if let Some(mm) = self.members.get_mut(&sid) {
                    mm.have = f.have;
                    mm.waiting = true;
                }
                self.wait(out, sid, wait::QUEUED, "");
                return Fetched::Not;
            }
            if self.seats.contains_key(&seat) {
                return Fetched::Seated(seat);
            }
            if self.joins.has(&seat)
                || self
                    .dues
                    .iter()
                    .any(|d| d.due.joiners.iter().any(|j| j.seat == seat))
            {
                if let Some(mm) = self.members.get_mut(&sid) {
                    mm.have = f.have;
                }
                self.wait(out, sid, wait::QUEUED, "");
                return Fetched::Not;
            }
        }
        if m.account.is_none() && self.head_gated() {
            self.wait(out, sid, wait::GUEST_IN_GATED, "");
            return Fetched::Not;
        }
        let (Some(pair), Some(ik)) = (f.pair, f.ik) else {
            self.wait(out, sid, wait::NO_SEAT_KEYS, "");
            return Fetched::Not;
        };
        let member = match m.account {
            Some(a) => MemberId::Account(a),
            None => MemberId::Conn(sid),
        };
        let seat = pair.keys.seat(member);
        if let Some(mm) = self.members.get_mut(&sid) {
            mm.seat = Some(seat);
        }
        // A seat already seated (another session of the account) is answered now; only a
        // queued fetch waits, so no stray answer follows at the next commit
        if self.seats.contains_key(&seat) && self.head.is_some() && !self.new_gen {
            return Fetched::Seated(seat);
        }
        if let Some(mm) = self.members.get_mut(&sid) {
            mm.waiting = true;
            mm.have = f.have;
        }
        self.joins.add(
            Waiting {
                joiner: Joiner {
                    seat,
                    ik,
                    keys: pair.keys,
                    endorsement: pair.endorsement,
                    returning: false,
                },
                sids: vec![sid],
                account: m.account,
            },
            now,
        );
        let why = if self.head.is_none() || self.new_gen {
            if holders::starter(self.kind, &self.vols, self.gate).is_some() {
                wait::NEW_GENERATION
            } else {
                wait::NO_KEYHOLDER
            }
        } else if self.holders.online(&self.vols).is_empty() {
            wait::NO_KEYHOLDER
        } else {
            wait::QUEUED
        };
        self.wait(out, sid, why, "");
        self.ask(now, out);
        Fetched::Not
    }

    /// An eager seat (plan 2d): queued with no session waiting for it.
    pub fn eager(&mut self, joiner: Joiner, account: [u8; 16], now: u64, out: &mut Vec<Out>) {
        if self.seats.contains_key(&joiner.seat) {
            return;
        }
        // At most `kept_seats` eager seats wait (plan 2d), however many sources queue them
        let eager = self
            .joins
            .queue
            .iter()
            .filter(|w| w.sids.is_empty())
            .count();
        if eager >= self.kept_seats && !self.joins.has(&joiner.seat) {
            return;
        }
        self.joins.add(
            Waiting {
                joiner,
                sids: vec![],
                account: Some(account),
            },
            now,
        );
        self.ask(now, out);
    }

    pub fn is_keyholder(&self, sid: UserId) -> bool {
        self.vols
            .get(&sid)
            .is_some_and(|v| self.holders.entry_of(v).is_some())
    }

    // ── Asking dues ───────────────────────────────────────────────────────

    fn held_now(&self) -> (HashMap<SeatRef, u32>, u32) {
        let s = self.head.as_ref().map_or(0, |h| h.sh.header().seed);
        let behind = self
            .seats
            .iter()
            .filter(|(_, x)| x.seed < s)
            .map(|(r, x)| (*r, x.seed))
            .collect();
        (behind, s)
    }

    /// Sends due `d` to its keyholder.
    fn send_due(&self, d: &DueOut, out: &mut Vec<Out>) {
        let h = self.head.as_ref().map(|h| h.sh.header());
        let roll_due = h.is_some_and(|h| {
            self.rolls.removal
                || (self.kind == GroupKind::Text && h.time >= self.rolls.raised + SEED_MAX_AGE)
        });
        let pairs = self
            .holders
            .set
            .iter()
            .filter_map(|k| self.holders.pairs.get(&k.kx))
            .chain(d.due.candidate.as_ref().map(|c| &c.pair))
            .map(gk::EndorsedPair::from)
            .collect();
        let piece = DuePiece {
            kind: d.due.kind.code(),
            parent: self.head.as_ref().map_or([0; 32], |h| h.sh.d()),
            deadline_ms: deadline_ms(d.due.kind) as u32,
            keyring_at: h.map_or((0, 0), |h| (h.epoch, h.join)),
            joins: d
                .due
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
                .due
                .exits
                .iter()
                .map(|x| gk::ExitIn {
                    seq: x.seq,
                    seat: x.seat.into(),
                    b: x.b,
                })
                .collect(),
            exits_upto: d.due.exits_upto,
            promote: d.due.candidate.as_ref().map(|c| gk::Candidate {
                m: c.m.into(),
                ik: c.ik,
                pair: (&c.pair).into(),
            }),
            remove: d.due.remove.map(Into::into),
            gated: d.due.gated,
            roll_due,
            seed_seats: vec![],
            finish: d.held.is_empty(),
            pairs,
            held: d.held.iter().map(|(s, n)| ((*s).into(), *n)).collect(),
        };
        out.push(Out(d.sid, push::epoch_due(&self.id, d.id, piece)));
    }

    fn put_due(&mut self, due: Due, to: &Volunteer, now: u64, out: &mut Vec<Out>) {
        let (held, head_seed) = self.held_now();
        let d = DueOut {
            id: self.next_due,
            deadline: now + deadline_ms(due.kind),
            due,
            sid: to.sid,
            by: to.by(),
            held,
            head_seed,
        };
        self.next_due += 1;
        self.send_due(&d, out);
        self.dues.push(d);
    }

    /// The gated an opening asks: the head's while the gate is on (only `DUE_GATE` turns
    /// it on), off at the next opening once the gate is off.
    fn opening_gated(&self) -> bool {
        self.gate && self.head_gated()
    }

    /// Asks the next due if one is wanted and none is out (plan 2d, "How dues interleave").
    pub fn ask(&mut self, now: u64, out: &mut Vec<Out>) {
        if self.retry_at.is_some_and(|t| now < t) {
            return;
        }
        self.retry_at = None;
        let wanted = !self.joins.queue.is_empty() || self.members.values().any(|m| m.waiting);
        if self.head.is_none() || self.new_gen {
            self.ask_start(Kind::Genesis, wanted, now, out);
            return;
        }
        if self.holders.online(&self.vols).is_empty() {
            self.no_keyholder_since.get_or_insert(now);
            if (wanted || self.exits.waiting() > 0) && self.dues.is_empty() {
                if !self.stored {
                    // Voice rooms and memory groups: a new generation at once
                    if holders::starter(self.kind, &self.vols, self.gate).is_some() {
                        self.new_gen = true;
                        self.ask_start(Kind::Genesis, true, now, out);
                    }
                } else if now >= self.no_keyholder_since.unwrap_or(now) + REGENESIS_AFTER_MS {
                    self.ask_start(Kind::Regenesis, true, now, out);
                }
            }
            return;
        }
        self.no_keyholder_since = None;
        // An exit batch that closed while a 60 s due is out goes to another keyholder; a
        // batch the slow due carries is not asked twice
        let slow = match &self.dues[..] {
            [d] if d.slow() => Some((d.sid, d.due.exits_upto)),
            _ => None,
        };
        if let Some((slow, carried)) = slow {
            if self
                .exits
                .closed
                .front()
                .is_some_and(|b| b.upto() > carried)
                && now >= self.last_opening + EPOCH_MIN_GAP_MS
            {
                if let Some(v) = self
                    .holders
                    .pick(self.kind, &self.vols, &[slow], now)
                    .cloned()
                {
                    let due = self.exits_due(DueKind::Exits);
                    self.put_due(due, &v, now, out);
                }
            }
        }
        if !self.dues.is_empty() {
            return;
        }
        let Some((due, only)) = self.next_due_kind(now) else {
            return;
        };
        let mut skip = self.passed.clone();
        if let Some(r) = due.remove {
            skip.extend(self.vols.values().filter(|v| v.by() == r).map(|v| v.sid));
        }
        let to = match only {
            Some(sid) => self
                .vols
                .get(&sid)
                .cloned()
                .filter(|_| !skip.contains(&sid)),
            None => self
                .holders
                .pick(self.kind, &self.vols, &skip, now)
                .cloned(),
        };
        match to {
            Some(v) => self.put_due(due, &v, now, out),
            None => {
                if !self.passed.is_empty() {
                    warn!(group = %self.id, missed = self.passed.len(), "every online keyholder missed its deadline");
                    self.passed.clear();
                    self.retry_at = Some(now + RETRY_ALL_MISSED_MS);
                }
            }
        }
    }

    /// An opening due of `kind` carrying the oldest closed exit batch, each exit in the
    /// bucket its seat sits in now (an opening since it entered may have moved it).
    fn exits_due(&self, kind: DueKind) -> Due {
        let gated = if kind == DueKind::Gate {
            true
        } else {
            self.opening_gated()
        };
        let mut due = Due::of(kind, gated);
        if let Some(b) = self.exits.closed.front() {
            due.exits = b
                .exits
                .iter()
                .map(|l| Exit {
                    b: self.seats.get(&l.exit.seat).map_or(l.exit.b, |s| s.b),
                    ..l.exit
                })
                .collect();
            due.exits_upto = b.upto();
        }
        due
    }

    /// The due wanted now by priority: Remove > Promote > Replace > Exits > Join > Gate >
    /// Refresh. With the session it must go to, if only one may take it.
    fn next_due_kind(&mut self, now: u64) -> Option<(Due, Option<UserId>)> {
        let gap_ok = now >= self.last_opening + EPOCH_MIN_GAP_MS;
        let seats = self.seats.len();
        if gap_ok {
            // A Remove is signed by another online entry (rule 2): one only its own entry
            // could sign waits, and the dues behind it go on (its Replace among them)
            let online: Vec<HolderRef> = self
                .holders
                .online(&self.vols)
                .iter()
                .map(|v| v.by())
                .collect();
            let signable = |r: &HolderRef| online.iter().any(|b| b != r);
            // A sole keyholder stays until a promotion lands
            let resign = self
                .resigns
                .iter()
                .copied()
                .find(|r| signable(r))
                .filter(|_| self.holders.set.len() > 1);
            let gated = self.opening_gated();
            let gate_wanted = self.gate && !self.head_gated();
            if let Some(r) = resign
                .or_else(|| {
                    self.holders
                        .removal_where(&self.vols, seats, gate_wanted, now, signable)
                })
                .or_else(|| {
                    self.holders
                        .swap_out(self.kind, &self.vols, gated, seats)
                        .filter(signable)
                })
            {
                return Some((
                    Due {
                        remove: Some(r),
                        ..self.exits_due(DueKind::Remove)
                    },
                    None,
                ));
            }
            if let Some(v) = self
                .holders
                .promotion(self.kind, &self.vols, self.opening_gated(), seats)
                .cloned()
            {
                let seated = self
                    .members
                    .get(&v.sid)
                    .and_then(|m| m.seat)
                    .is_some_and(|s| self.seats.contains_key(&s));
                if seated {
                    return Some((
                        Due {
                            candidate: Some(v.candidate()),
                            ..self.exits_due(DueKind::Promote)
                        },
                        None,
                    ));
                }
                if let Some(j) = v.seat.clone().filter(|j| !self.joins.has(&j.seat)) {
                    self.joins.add(
                        Waiting {
                            account: j.seat.m.account(),
                            joiner: j,
                            sids: vec![v.sid],
                        },
                        now,
                    );
                    if let Some(m) = self.members.get_mut(&v.sid) {
                        m.seat = v.seat.as_ref().map(|j| j.seat);
                    }
                }
            }
            // A Replace goes to the keyholder whose entry it swaps, while that entry is in
            // the set and its session volunteers; one that missed lets the rest go first
            let (vols, holders) = (&self.vols, &self.holders);
            self.replaces.retain(|(sid, a)| {
                vols.get(sid)
                    .and_then(|v| holders.entry_of(v))
                    .is_some_and(|k| kx_tag(&k.kx) == a.old)
            });
            let passed = &self.passed;
            if let Some((sid, ask)) = self
                .replaces
                .iter()
                .find(|(s, _)| !passed.contains(s))
                .cloned()
            {
                return Some((
                    Due {
                        replace: Some(ask),
                        ..self.exits_due(DueKind::Replace)
                    },
                    Some(sid),
                ));
            }
            if !self.exits.closed.is_empty() {
                return Some((self.exits_due(DueKind::Exits), None));
            }
        }
        if self.joins.closes_at(self.kind).is_some_and(|t| now >= t) {
            let due = Due {
                joiners: self.joins.batch().into_iter().map(|w| w.joiner).collect(),
                ..Due::of(DueKind::Join, self.head_gated())
            };
            return Some((due, None));
        }
        if !gap_ok {
            return None;
        }
        let conns = self.seats.keys().any(|s| s.m.is_conn());
        let guests = self.holders.set.iter().any(|k| k.m.is_conn());
        if self.gate && !self.head_gated() && !conns && !guests && self.exits.waiting() == 0 {
            return Some((self.exits_due(DueKind::Gate), None));
        }
        if self.next_refresh.is_some_and(|t| now >= t) {
            return Some((self.exits_due(DueKind::Refresh), None));
        }
        None
    }

    /// A Genesis (no generation, or a new one due) or a Regenesis, to the best volunteer.
    fn ask_start(&mut self, kind: Kind, wanted: bool, now: u64, out: &mut Vec<Out>) {
        if !self.dues.is_empty() || !wanted {
            return;
        }
        let skip = self.passed.clone();
        let Some(v) = holders::allowed(self.kind, &self.vols, self.gate, 0)
            .filter(|v| v.seat.is_some() && v.entry(self.kind).is_some() && !skip.contains(&v.sid))
            .min_by_key(|v| (v.rank(self.kind), v.sid))
            .cloned()
        else {
            if !self.passed.is_empty() {
                self.passed.clear();
                self.retry_at = Some(now + RETRY_ALL_MISSED_MS);
            }
            return;
        };
        let dk = if kind == Kind::Regenesis {
            DueKind::Regenesis
        } else {
            DueKind::Genesis
        };
        let joiner = v.seat.clone().expect("checked");
        let mut due = self.exits_due(dk);
        due.gated = self.gate;
        due.joiners = vec![joiner];
        due.volunteer = Some(v.candidate());
        if let Some(m) = self.members.get_mut(&v.sid) {
            m.seat = Some(due.joiners[0].seat);
        }
        self.put_due(due, &v, now, out);
    }

    // ── Commits ───────────────────────────────────────────────────────────

    /// One part of a keyholder's commit for `due`. The whole commit, checked, comes back as
    /// `Taken` for the actor to store and then `apply`.
    #[allow(clippy::too_many_arguments)]
    pub fn commit_part(
        &mut self,
        sid: UserId,
        due: u64,
        part: u16,
        last: bool,
        piece: CommitPiece,
        bytes: usize,
        now: u64,
        out: &mut Vec<Out>,
    ) -> Option<Taken> {
        let Some(at) = self.dues.iter().position(|d| d.id == due && d.sid == sid) else {
            if part == 0 || last {
                self.stale(out, sid, due, stale::NOT_DUE, "");
            }
            return None;
        };
        if piece.check_items().is_err() {
            self.drop_open(sid);
            self.stale(out, sid, due, stale::CHECK, "a commit item is malformed");
            return None;
        }
        if let Some(h) = &piece.header {
            if let (Ok(sh), Some(head)) = (
                SignedHeader::decode(&h.body, &h.sig, self.kind, &self.id),
                &self.head,
            ) {
                let anew = sh.header().kind == Kind::Genesis;
                if !anew && sh.header().parent != head.sh.d() {
                    self.drop_open(sid);
                    self.stale(out, sid, due, stale::HEAD_MOVED, "");
                    return None;
                }
            }
        }
        if !self.caps.room(sid, bytes.max(piece_heap(&piece))) {
            self.drop_open(sid);
            self.stale(out, sid, due, stale::TOO_LARGE, "");
            return None;
        }
        let (parts, started) = self
            .open
            .entry(sid)
            .or_insert_with(|| (Parts::new(Seq::Commit), now));
        if part == 0 {
            *started = now;
        }
        let before = parts.held();
        let took = parts.take(due, part, last, piece, bytes);
        let after = parts.held();
        self.caps.charge(sid, before, after);
        if let Some((_, Lost::TooLarge)) = took.dropped {
            self.stale(out, sid, due, stale::TOO_LARGE, "");
        }
        let pieces = match took.part {
            Part::Held => return None,
            Part::NotTaken(gk::NotTaken::NotStarted) => return None,
            Part::NotTaken(gk::NotTaken::TooLarge) => {
                self.stale(out, sid, due, stale::TOO_LARGE, "");
                return None;
            }
            Part::NotTaken(gk::NotTaken::Gap) => {
                self.stale(out, sid, due, stale::CHECK, "a part is missing");
                return None;
            }
            Part::Whole(_, pieces) => pieces,
        };
        let commit = match gk::join_commit(pieces)
            .map_err(|e| e.to_string())
            .and_then(|c| Commit::try_from(c).map_err(|e| e.to_string()))
        {
            Ok(c) => c,
            Err(e) => {
                self.miss(at, now);
                self.stale(out, sid, due, stale::CHECK, &e);
                self.ask(now, out);
                return None;
            }
        };
        // The last part sees the head too: another due may have landed meanwhile (no miss)
        if let (Ok(sh), Some(head)) = (
            SignedHeader::decode(&commit.body, &commit.sig, self.kind, &self.id),
            &self.head,
        ) {
            if sh.header().kind != Kind::Genesis && sh.header().parent != head.sh.d() {
                self.stale(out, sid, due, stale::HEAD_MOVED, "");
                return None;
            }
        }
        let d = &self.dues[at];
        let checked = self.check(d, &commit, now);
        match checked {
            Ok(applied) => {
                let d = self.dues.remove(at);
                Some(self.taken(d, commit, applied, sid, now))
            }
            Err(bad) => {
                self.miss(at, now);
                self.stale(out, sid, due, stale::CHECK, &bad.to_string());
                self.ask(now, out);
                None
            }
        }
    }

    fn drop_open(&mut self, sid: UserId) {
        if let Some((p, _)) = self.open.remove(&sid) {
            self.caps.charge(sid, p.held(), 0);
        }
    }

    fn check(
        &self,
        d: &DueOut,
        c: &Commit,
        now: u64,
    ) -> Result<Applied, voipc_crypto::group_key::commit::Bad> {
        let held = |s: &SeatRef| {
            self.seats
                .contains_key(s)
                .then(|| d.held.get(s).copied().unwrap_or(d.head_seed))
        };
        let used = |v: u64| self.used_v.contains(&v);
        let head = self.head.as_ref().map(|h| CommitHead {
            head: &h.sh,
            kh: &h.kh,
        });
        let view = GroupView {
            kind: self.kind,
            id: &self.id,
            stored: self.stored,
            head,
            leaves: &self.leaves,
            held: &held,
            due: &d.due,
            by: d.by,
            rolls: self.rolls,
            known_gens: &self.gens,
            used_v: &used,
            now: now / 1000,
            roster: &[],
            no_keyholder_since: self.no_keyholder_since.map(|t| t / 1000),
        };
        validate(&view, c)
    }

    /// Misses due `at`: its keyholder is passed over, the due is asked again.
    fn miss(&mut self, at: usize, now: u64) {
        let d = self.dues.remove(at);
        self.holders.missed(&d.by.kx, now);
        self.missed_total += 1;
        let n = self.missed_total;
        self.warn(warn_kind::MISSED, format!("missed {n} deadlines"), now);
        self.passed.push(d.sid);
        self.drop_open(d.sid);
        // A Join due's joiners stay queued; a resign or replace stays wanted
    }

    fn taken(&self, due: DueOut, commit: Commit, applied: Applied, sid: UserId, now: u64) -> Taken {
        let sh = applied.header.clone();
        let h = sh.header();
        let maker = match &due.due.replace {
            Some(r) => HolderRef {
                m: due.by.m,
                kx: r.pair.kx(),
            },
            None => due.by,
        };
        let vers = commit
            .versions
            .iter()
            .map(|vo| {
                let ver = match vo.make {
                    Make::Ratchet { from_v } => {
                        let from = self.vers.get(&(vo.b, from_v));
                        let mut ratchets = from.map_or_else(Vec::new, |f| f.ratchets.clone());
                        ratchets.push(RatchetStep {
                            e: h.epoch,
                            from: from_v,
                            to: vo.v,
                        });
                        Ver {
                            base_v: from.map_or(from_v, |f| f.base_v),
                            ratchets,
                            made: (h.epoch, h.join),
                            maker: from.map_or(maker, |f| f.maker),
                        }
                    }
                    _ => Ver {
                        base_v: vo.v,
                        ratchets: vec![],
                        made: (h.epoch, h.join),
                        maker,
                    },
                };
                ((vo.b, vo.v), ver)
            })
            .collect();
        let new_gen = !self.gens.contains(&h.gen);
        let old = self.head.as_ref();
        let head = Head {
            sh: sh.clone(),
            kh: if h.kind.sets_keyholders() {
                sh.clone()
            } else {
                old.map_or_else(|| sh.clone(), |o| o.kh.clone())
            },
            opening: if h.kind.opens_epoch() {
                sh.clone()
            } else {
                old.map_or_else(|| sh.clone(), |o| o.opening.clone())
            },
            parent: (h.kind == Kind::Regenesis)
                .then(|| old.map(|o| o.sh.clone()))
                .flatten(),
            opened_ms: if h.kind.opens_epoch() {
                now
            } else {
                old.map_or(now, |o| o.opened_ms)
            },
        };
        Taken {
            was: old.map(|o| o.sh.d()),
            due,
            commit,
            applied,
            sid,
            maker,
            vers,
            head,
            new_gen,
        }
    }

    /// The store failed a valid commit (`STORE`, never a miss): the due is asked again.
    pub fn store_failed(&mut self, t: Taken, now: u64, out: &mut Vec<Out>) {
        self.stale(out, t.sid, t.due.id, stale::STORE, "");
        self.ask(now, out);
    }

    /// Takes a stored commit: the new head and seats, its pushes (2f), and the next due.
    /// Gives the sessions to answer in full now (joiners seated, fetchers waiting).
    pub fn apply(&mut self, t: Taken, now: u64, out: &mut Vec<Out>) -> Vec<(UserId, bool)> {
        let Taken {
            due,
            commit,
            applied: a,
            sid: by_sid,
            vers,
            head,
            new_gen,
            maker,
            ..
        } = t;
        let sh = a.header.clone();
        let h = sh.header().clone();
        let was_gated = self.head_gated() && self.gens.contains(&h.gen);
        let was_seed = self
            .head
            .as_ref()
            .map(|x| x.sh.header())
            .filter(|x| x.gen == h.gen)
            .map(|x| x.seed);
        let before_online: Vec<UserId> = self
            .members
            .iter()
            .filter(|(_, m)| m.seat.is_some_and(|s| self.seats.contains_key(&s)))
            .map(|(s, _)| *s)
            .collect();
        let writers: Vec<UserId> = self
            .members
            .iter()
            .filter(|(_, m)| m.writer)
            .map(|(s, _)| *s)
            .collect();
        if new_gen {
            self.gens.push(h.gen);
            self.gen_time = now;
            self.used_v.clear();
            self.khs.clear();
            self.recent.clear();
            self.vers.clear();
            self.new_gen = false;
        }
        if h.kind.starts_anew() {
            self.seats.clear();
            self.seals.clear();
            self.blobs.clear();
            self.conn_keys.clear();
        }
        // Leaves and versions
        let gone: HashSet<(u64, u64)> = a.gone.iter().map(|v| (v.b, v.v)).collect();
        let mut leaves: Vec<Listed> = if h.kind.starts_anew() {
            vec![]
        } else {
            self.leaves
                .iter()
                .filter(|l| !gone.contains(&(l.leaf.b, l.leaf.v)))
                .cloned()
                .collect()
        };
        leaves.extend(a.made.iter().cloned());
        leaves.sort_by_key(|l| l.leaf.b);
        for g in &gone {
            self.vers.remove(g);
        }
        for (k, v) in vers {
            self.used_v.insert(k.1);
            self.vers.insert(k, v);
        }
        // Seats
        for s in &a.removed {
            self.seats.remove(s);
            self.conn_keys.remove(s);
        }
        let joiners: HashMap<SeatRef, &Joiner> =
            due.due.joiners.iter().map(|j| (j.seat, j)).collect();
        for (s, v) in &a.seated {
            if let Some(j) = joiners.get(s) {
                if s.m.is_conn() {
                    let pair = Pair {
                        keys: j.keys.clone(),
                        endorsement: j.endorsement.clone(),
                    };
                    self.conn_keys.insert(*s, (j.ik, pair));
                }
                self.seats.insert(
                    *s,
                    Seat {
                        b: v.b,
                        seed: h.seed,
                        dh: j.keys.dh_bytes()[..].try_into().unwrap_or([0; 33]),
                        account: s.m.account(),
                    },
                );
            }
        }
        for l in &a.made {
            for s in &l.seats {
                if let Some(x) = self.seats.get_mut(s) {
                    x.b = l.leaf.b;
                }
            }
        }
        for (s, n) in &a.held {
            if let Some(x) = self.seats.get_mut(s) {
                x.seed = *n;
            }
        }
        self.leaves = Arc::new(leaves);
        self.tree = Arc::new(a.tree);
        // Seals: an opening's replace the epoch's, a Join's add to them
        if h.kind.opens_epoch() {
            self.seals.clear();
        }
        for s in &commit.seals {
            self.seals.insert((s.b, s.v), s.bytes.clone());
        }
        // Exits dealt with (a Genesis or Regenesis closes the batch it carried, and the
        // seats a new start left behind need none)
        if let Some(upto) = a.exits_done.iter().max() {
            self.exits.done(*upto);
        }
        // A due still out keeps only the exits past the new head's: its keyholder rebases
        // without the rest (holder.rs `on_stale`), and is checked against what it was asked
        for d in &mut self.dues {
            d.due.exits.retain(|e| e.seq > h.exits_upto);
        }
        if h.kind.starts_anew() {
            let seats = &self.seats;
            self.exits.keep(|s| seats.contains_key(s));
        }
        // Joins dealt with
        let mut dealt: Vec<SeatRef> = a.seated.iter().map(|(s, _)| *s).collect();
        dealt.extend(a.refused.iter().map(|r| r.seat));
        self.joins.done(&dealt, now);
        for r in &a.refused {
            let detail = gk::join_refused::name(r.why);
            for (sid, m) in self.members.iter_mut() {
                if m.seat == Some(r.seat) {
                    m.seat = None;
                    m.waiting = false;
                    out.push(Out(
                        *sid,
                        vec![ServerMessage::EpochWait {
                            group: self.id.clone(),
                            why: wait::REFUSED,
                            detail: detail.into(),
                        }],
                    ));
                }
            }
        }
        // Keyholders
        if let Some(set) = &a.keyholders {
            let mut pairs: HashMap<[u8; 32], Pair> = HashMap::new();
            for v in self.vols.values() {
                pairs.insert(v.pair.kx(), v.pair.clone());
            }
            for c in due.due.candidate.iter().chain(due.due.volunteer.iter()) {
                pairs.insert(c.pair.kx(), c.pair.clone());
            }
            if let Some(r) = &due.due.replace {
                pairs.insert(r.pair.kx(), r.pair.clone());
                self.replaces
                    .retain(|(s, x)| !(*s == by_sid && x.old == r.old));
            }
            if h.kind.starts_anew() {
                self.holders.clear();
            }
            self.holders
                .set_to(set.clone(), |kx| pairs.get(kx).cloned());
            // A new entry's rank and device, from the session that volunteered it
            for k in set {
                if self.holders.rank.contains_key(&k.kx) {
                    continue;
                }
                if let Some(v) = self.vols.values().find(|v| v.pair.kx() == k.kx) {
                    if let Some(r) = v.rank(self.kind) {
                        self.holders.rank.insert(k.kx, r);
                    }
                    if let Some(d) = self.devices.get(&v.sid) {
                        self.holders.device.insert(k.kx, d.clone());
                    }
                }
            }
            self.resigns
                .retain(|r| set.iter().any(|k| HolderRef::of(k) == *r));
            self.holders.seen(&self.vols, now);
        }
        self.rolls = a.rolls;
        // A roll: a page of another seed is let go, a new roll's first is asked soon
        if self.page.as_ref().is_some_and(|p| p.seed != h.seed) {
            self.page = None;
        }
        if h.seed_floor == h.seed {
            self.seed_first.clear();
        } else if was_seed.is_some_and(|w| w < h.seed) {
            self.next_page = now;
        }
        let seats = &self.seats;
        self.seed_first.retain(|s| seats.contains_key(s));
        // Re-joins whose exit was taken join now (2b)
        let (back, wait): (Vec<Waiting>, Vec<Waiting>) = std::mem::take(&mut self.rejoins)
            .into_iter()
            .partition(|w| !self.seats.contains_key(&w.joiner.seat));
        self.rejoins = wait;
        for w in back {
            self.joins.add(w, now);
        }
        // Headers kept
        if h.kind.sets_keyholders() {
            self.khs.insert(sh.d(), (sh.clone(), head.parent.clone()));
        }
        self.recent.push_back(sh.clone());
        while self.recent.len() > RECENT
            && self
                .recent
                .front()
                .is_some_and(|f| f.header().epoch < h.epoch)
        {
            self.recent.pop_front();
        }
        self.head = Some(head);
        self.last_commit = now;
        self.passed.clear();
        self.retry_at = None;
        if h.kind.opens_epoch() {
            self.last_opening = now;
            self.next_refresh = Some(now + refresh_ms(h.buckets));
            self.blobs.retain(|(e, _), _| e + 1 >= h.epoch);
            for m in self.members.values_mut() {
                m.writer = false;
            }
        }
        let names = self.names.take(&sh, was_gated);
        self.names.sweep(&h.gen, now / 1000);
        let snap = self.snapshot().expect("a head");

        // ── Pushes (2f) ──
        let piece = InPiece {
            chain: vec![header_in(&sh)],
            ..InPiece::default()
        };
        let holders: Vec<UserId> = self
            .holders
            .online(&self.vols)
            .iter()
            .map(|v| v.sid)
            .collect();
        for sid in &holders {
            self.pushed(out, *sid, piece.clone());
        }
        // A member's push carries its leaf, path and seal, and its keying when this header
        // made its version (a re-key by rows, a ratchet): the pushed header moves its floor,
        // so a later fetch from there would never be told the version moved (3f)
        let at = (h.epoch, h.join);
        let piece_for = |sid: &UserId| {
            let mut p = InPiece {
                head: Some(link(&sh, snap.parent.as_ref())),
                ..InPiece::default()
            };
            if let Some(seat) = self
                .members
                .get(sid)
                .and_then(|m| m.seat)
                .filter(|s| self.seats.contains_key(s))
            {
                snap.seat_piece(&seat, &mut p);
                p.seat = snap.pushed_keying(&seat, at, &commit, maker);
            }
            p
        };
        let mut pushed: Vec<(UserId, InPiece)> = vec![];
        if h.kind.opens_epoch() {
            for sid in writers.iter().filter(|s| !holders.contains(s)) {
                pushed.push((*sid, piece_for(sid)));
            }
        }
        if h.kind.sets_keyholders() {
            let mut to: Vec<UserId> = before_online;
            to.extend(
                self.members
                    .iter()
                    .filter(|(_, m)| m.seat.is_some_and(|s| self.seats.contains_key(&s)))
                    .map(|(s, _)| *s),
            );
            to.sort_unstable();
            to.dedup();
            for sid in to.iter().filter(|s| !holders.contains(s)) {
                if !pushed.iter().any(|(x, _)| x == sid) {
                    pushed.push((*sid, piece_for(sid)));
                }
            }
        }
        for (sid, p) in pushed {
            self.pushed(out, sid, p);
        }
        if let (Some(list), Kind::Join) = (names, h.kind) {
            let p = NamesPiece {
                lists: vec![list],
                joins: vec![header_in(&sh)],
                ..NamesPiece::default()
            };
            for sid in &writers {
                out.push(Out(*sid, push::names_in(&self.id, p.clone())));
            }
        }
        // Seed welcomes in a memory group go to the online seat at once
        if !self.stored {
            for w in &commit.seed_welcomes {
                for (sid, m) in &self.members {
                    if m.seat == Some(w.seat) {
                        self.pushed(
                            out,
                            *sid,
                            InPiece {
                                seed_welcome: Some(gk::SeedWelcomeIn {
                                    s: h.seed,
                                    from: maker.into(),
                                    bytes: w.bytes.clone(),
                                }),
                                ..InPiece::default()
                            },
                        );
                    }
                }
            }
        }
        // Who gets a full answer now: the joiners seated, and every waiting fetcher seated
        let seated: HashSet<SeatRef> = a.seated.iter().map(|(s, _)| *s).collect();
        let mut answer = vec![];
        for (sid, m) in self.members.iter_mut() {
            let Some(seat) = m.seat else { continue };
            if !self.seats.contains_key(&seat) {
                continue;
            }
            if seated.contains(&seat) || m.waiting {
                m.waiting = false;
                answer.push((*sid, seated.contains(&seat) && h.kind == Kind::Join));
            }
        }
        // A new start unseats everyone else: they fetch again and are queued
        if h.kind.starts_anew() {
            for m in self.members.values_mut() {
                if m.seat
                    .is_some_and(|s| !self.seats.contains_key(&s) && !self.joins.has(&s))
                {
                    m.seat = None;
                }
            }
        }
        // A seat that exited while this due seating it was out exits now
        let late: Vec<(SeatRef, u8)> = self
            .exit_late
            .iter()
            .filter(|(id, s, _)| *id == due.id && seated.contains(s))
            .map(|(_, s, c)| (*s, *c))
            .collect();
        let dues = &self.dues;
        self.exit_late
            .retain(|(id, _, _)| dues.iter().any(|d| d.id == *id));
        for (s, c) in late {
            self.exit(s, c, now, out);
        }
        self.ask(now, out);
        answer.sort_unstable();
        answer
    }

    // ── Timers ────────────────────────────────────────────────────────────

    /// When `tick` has something to do next. `ticked`: the clock of the last `tick`. A time
    /// that only lets `ask` start a due counts while it is later than that: at or before
    /// it, `ask` ran and could not start one (none online, a due out), and a message or a
    /// later timer asks again, so the actor never wakes for it in a loop.
    pub fn wake(&self, ticked: u64) -> Option<u64> {
        let seats = self.seats.len() as u64;
        let paging = self.roll_runs() && self.page.is_none();
        // Once the gap after an opening ends, `ask` may start what waited for it (exits, a
        // removal, a promotion, a resign, a replace)
        let asks = [
            self.joins.closes_at(self.kind),
            self.next_refresh,
            Some(self.last_opening + EPOCH_MIN_GAP_MS),
            self.no_keyholder_since
                .filter(|_| self.stored)
                .map(|t| t + REGENESIS_AFTER_MS),
            paging.then_some(self.next_page),
        ];
        [
            self.dues.iter().map(|d| d.deadline).min(),
            self.page.as_ref().map(|p| p.deadline),
            self.exits.closes_at(self.kind, seats, self.head_gated()),
            self.retry_at,
            self.open.values().map(|(_, t)| t + OPEN_COMMIT_MS).min(),
        ]
        .into_iter()
        .chain(asks.into_iter().map(|t| t.filter(|t| *t > ticked)))
        .flatten()
        .min()
    }

    pub fn tick(&mut self, now: u64, out: &mut Vec<Out>) {
        // Deadlines passed: a miss, the next keyholder is asked
        while let Some(at) = self.dues.iter().position(|d| d.deadline <= now) {
            let d = &self.dues[at];
            let (sid, id) = (d.sid, d.id);
            self.miss(at, now);
            self.stale(out, sid, id, stale::TIMED_OUT, "");
        }
        // A seed-welcome page past its deadline: a miss, asked again of another
        if let Some(p) = self.page.take_if(|p| p.deadline <= now) {
            self.holders.missed(&p.by.kx, now);
            self.missed_total += 1;
            self.next_page = now;
            self.stale(out, p.sid, p.id, stale::TIMED_OUT, "");
        }
        self.check_warnings(now);
        // Open commits past 30 s
        let late: Vec<UserId> = self
            .open
            .iter()
            .filter(|(_, (_, t))| now >= t + OPEN_COMMIT_MS)
            .map(|(s, _)| *s)
            .collect();
        for sid in late {
            self.drop_open(sid);
        }
        let seats = self.seats.len() as u64;
        if self
            .exits
            .closes_at(self.kind, seats, self.head_gated())
            .is_some_and(|t| now >= t)
        {
            self.exits.close(self.head_gated());
            // No 60 s due holds them up: with no other keyholder, the slow due is asked
            // again with the batch merged, once (plan 2d)
            let merge = match &self.dues[..] {
                [slow] => {
                    let others = self
                        .holders
                        .online(&self.vols)
                        .iter()
                        .any(|v| v.sid != slow.sid);
                    slow.slow()
                        && !others
                        && slow.due.exits.is_empty()
                        && !matches!(slow.due.kind, DueKind::Genesis | DueKind::Regenesis)
                }
                _ => false,
            };
            if merge {
                {
                    let mut d = self.dues.remove(0);
                    let merged = self.exits_due(d.due.kind);
                    d.due.exits = merged.exits;
                    d.due.exits_upto = merged.exits_upto;
                    d.id = self.next_due;
                    self.next_due += 1;
                    d.deadline = now + deadline_ms(d.due.kind);
                    self.drop_open(d.sid);
                    self.send_due(&d, out);
                    self.dues.push(d);
                }
            }
        }
        self.holders.seen(&self.vols, now);
        self.ask(now, out);
    }

    // ── Keyholders' other asks ────────────────────────────────────────────

    /// `EpochDecline`: no miss for pass-over (the keyholder is skipped for this due), but
    /// every decline except `CANDIDATE` counts toward its hourly count.
    pub fn decline(&mut self, sid: UserId, due: u64, why: u8, now: u64, out: &mut Vec<Out>) {
        // A seed-welcome page declined: asked again at once of another keyholder, if one is
        // online (a page is no commit: `passed` stays the dues')
        if let Some(p) = self.page.take_if(|p| p.id == due && p.sid == sid) {
            if why != gk::decline::CANDIDATE {
                self.holders.declined(&p.by.kx, now);
            }
            self.page_declined = Some(sid);
            self.next_page = now;
            return;
        }
        let Some(at) = self.dues.iter().position(|d| d.id == due && d.sid == sid) else {
            return;
        };
        let d = self.dues.remove(at);
        if why != gk::decline::CANDIDATE {
            self.holders.declined(&d.by.kx, now);
        }
        self.passed.push(sid);
        self.drop_open(sid);
        self.ask(now, out);
    }

    /// `KeyholdResign`: the session's entry goes by a Remove due to another keyholder.
    pub fn resign(&mut self, sid: UserId, entry: Option<[u8; 32]>, now: u64, out: &mut Vec<Out>) {
        let Some(v) = self.vols.get(&sid) else {
            return;
        };
        let kx = entry.unwrap_or_else(|| v.pair.kx());
        let Some(k) = self.holders.set.iter().find(|k| k.kx == kx && k.m == v.m) else {
            return;
        };
        let r = HolderRef::of(k);
        if !self.resigns.contains(&r) {
            self.resigns.push(r);
        }
        self.ask(now, out);
    }

    /// `KeyholdReplace`: a Replace due to that keyholder where its old entry is in the set.
    /// Only the keyholder itself asks it, for its own entry.
    pub fn replace(&mut self, sid: UserId, ask: ReplaceAsk, now: u64, out: &mut Vec<Out>) {
        let own = self
            .vols
            .get(&sid)
            .and_then(|v| self.holders.entry_of(v))
            .is_some_and(|k| kx_tag(&k.kx) == ask.old);
        if own
            && !self
                .replaces
                .iter()
                .any(|(s, a)| *s == sid && a.old == ask.old)
        {
            self.replaces.push((sid, ask));
            self.ask(now, out);
        }
    }

    /// `EpochListsWanted` from a keyholder: the lists of current versions, 13 a frame.
    pub fn lists(&self, sid: UserId, gen: [u8; 16], versions: &[(u64, u64)], out: &mut Vec<Out>) {
        if !self.is_keyholder(sid) || self.gen() != Some(gen) {
            self.refuse(out, sid, refused_what::COMMIT, refused_why::NOT_MEMBER);
            return;
        }
        let lists: Vec<gk::ListIn> = versions
            .iter()
            .take(LISTS_WANTED_MAX)
            .filter_map(|(b, v)| {
                let l = self
                    .leaves
                    .iter()
                    .find(|l| l.leaf.b == *b && l.leaf.v == *v)?;
                Some(gk::ListIn {
                    b: *b,
                    v: *v,
                    seats: l
                        .seats
                        .iter()
                        .map(|s| gk::ListSeat {
                            seat: (*s).into(),
                            dh: self.seats.get(s).map_or_else(Vec::new, |x| x.dh.to_vec()),
                        })
                        .collect(),
                })
            })
            .collect();
        let n = lists.len().div_ceil(LISTS_PER_FRAME).max(1);
        let mut frames = Vec::with_capacity(n);
        let mut chunks = lists.chunks(LISTS_PER_FRAME).peekable();
        if chunks.peek().is_none() {
            frames.push(ServerMessage::EpochLists {
                group: self.id.clone(),
                gen,
                lists: vec![],
                more: false,
            });
        }
        while let Some(c) = chunks.next() {
            frames.push(ServerMessage::EpochLists {
                group: self.id.clone(),
                gen,
                lists: c.to_vec(),
                more: chunks.peek().is_some(),
            });
        }
        out.push(Out(sid, frames));
    }

    // ── Posts ─────────────────────────────────────────────────────────────

    pub fn head_view(&self) -> Option<HeadView> {
        self.head.as_ref().map(|h| HeadView {
            gen: h.sh.header().gen,
            epoch: h.sh.header().epoch,
            opened_ms: h.opened_ms,
        })
    }

    /// A post carrying a blob (1f.2): checked, the blob kept, the session a writer of the
    /// epoch and told of the exits pending. `Err` is a `refused_why` code.
    pub fn post_blob(
        &mut self,
        sid: UserId,
        gen: [u8; 16],
        epoch: u32,
        blob: Vec<u8>,
        now: u64,
        out: &mut Vec<Out>,
    ) -> Result<(), u8> {
        let Some(m) = self.members.get(&sid) else {
            return Err(refused_why::NOT_MEMBER);
        };
        if !self
            .head_view()
            .is_some_and(|v| v.post_ok(&gen, epoch, now))
        {
            return Err(refused_why::OLD_EPOCH);
        }
        if blob.len() > BLOB_MAX_BYTES {
            return Err(refused_why::TOO_LARGE);
        }
        let Some(seat) = m.seat else {
            return Err(refused_why::NOT_MEMBER);
        };
        let w = GkWriter {
            m: seat.m.into(),
            u: sid,
        };
        let kept = self.blobs.entry((epoch, w)).or_default();
        if kept.len() >= BLOBS_PER_WRITER {
            return Err(refused_why::THIRD_BLOB);
        }
        kept.push(blob);
        let told = self.members.get(&sid).map_or(0, |m| m.told);
        if let Some(m) = self.members.get_mut(&sid) {
            m.writer = true;
        }
        if let Some(seq) = self.exits.pending().filter(|s| *s > told) {
            if let Some(m) = self.members.get_mut(&sid) {
                m.told = seq;
            }
            out.push(Out(
                sid,
                vec![ServerMessage::EpochExit {
                    group: self.id.clone(),
                    gen,
                    seq,
                }],
            ));
        }
        Ok(())
    }

    /// `EpochBlobWanted`.
    pub fn blobs(
        &self,
        sid: UserId,
        gen: [u8; 16],
        epoch: u32,
        writer: GkWriter,
        out: &mut Vec<Out>,
    ) {
        if !self.members.contains_key(&sid) {
            self.refuse(out, sid, refused_what::BLOB, refused_why::NOT_MEMBER);
            return;
        }
        let blobs = if self.gen() == Some(gen) {
            self.blobs
                .get(&(epoch, writer))
                .cloned()
                .unwrap_or_default()
        } else {
            vec![]
        };
        out.push(Out(
            sid,
            vec![ServerMessage::EpochBlob {
                group: self.id.clone(),
                gen,
                epoch,
                writer,
                blobs,
            }],
        ));
    }

    /// `EpochNames` (gated groups only).
    pub fn names(
        &self,
        sid: UserId,
        from: &NamesRef,
        to: &NamesRef,
        removals: bool,
        out: &mut Vec<Out>,
    ) {
        if !self.members.contains_key(&sid) {
            self.refuse(out, sid, refused_what::NAMES, refused_why::NOT_MEMBER);
        } else if !self.head_gated() {
            self.refuse(out, sid, refused_what::NAMES, refused_why::NOT_GATED);
        } else {
            out.push(Out(
                sid,
                push::names_in(&self.id, self.names.answer(from, to, removals)),
            ));
        }
    }

    /// `EpochFloorAhead` (plan 2d): a header past the head, signed by a keyholder this
    /// generation had, starts a new generation (at most one an hour). A generation the
    /// relay does not know changes nothing.
    pub fn floor_ahead(&mut self, sid: UserId, header: &HeaderIn, now: u64, out: &mut Vec<Out>) {
        if !self.members.contains_key(&sid) {
            return;
        }
        let Ok(sh) = SignedHeader::decode(&header.body, &header.sig, self.kind, &self.id) else {
            return;
        };
        let Some(head) = &self.head else { return };
        let (h, hd) = (sh.header(), head.sh.header());
        if h.gen != hd.gen {
            self.warn(
                warn_kind::AHEAD,
                "a member reports it ahead of this database".into(),
                now,
            );
            return;
        }
        let signer = self
            .khs
            .values()
            .flat_map(|(k, _)| k.header().keyholders.iter())
            .find(|k| k.m == h.signer && sh.verify(&k.ik));
        if signer.is_none() || (h.epoch, h.join) <= (hd.epoch, hd.join) {
            return;
        }
        if self
            .floor_ahead_at
            .is_some_and(|t| now < t + FLOOR_AHEAD_GAP_SECS * 1000)
        {
            return;
        }
        self.floor_ahead_at = Some(now);
        self.new_gen = true;
        warn!(group = %self.id, "a member holds a header past this relay's head: a new generation");
        self.ask(now, out);
    }

    /// The channel's gate changed (plan 2d): on, connection seats exit and guest entries
    /// go before `DUE_GATE`; off, the next opening clears it.
    pub fn set_gate(&mut self, gated: bool, now: u64, out: &mut Vec<Out>) {
        self.gate = gated;
        if gated {
            let conns: Vec<SeatRef> = self
                .seats
                .keys()
                .filter(|s| s.m.is_conn())
                .copied()
                .collect();
            for s in conns {
                self.exit(s, cause::GATE, now, out);
            }
        }
        self.ask(now, out);
    }

    // ── Seed rolls (plan 2d "Seed rolls") ─────────────────────────────────

    /// Whether a roll runs: the head's floor is below its seed.
    pub fn roll_runs(&self) -> bool {
        self.head.as_ref().is_some_and(|h| {
            let x = h.sh.header();
            x.seed_floor < x.seed
        })
    }

    /// The seats the next seed-welcome page asks, when one is wanted now: a roll runs, no
    /// page is out, a keyholder is online, and a seat behind fetched (those alone, at
    /// once) or the 10 s pace allows a scan of every seat. A seat already exiting is not
    /// asked. At most `SEED_PAGE_SEATS`.
    pub fn page_wanted(&mut self, now: u64) -> Option<Vec<SeatRef>> {
        if !self.roll_runs() || self.page.is_some() || self.holders.online(&self.vols).is_empty() {
            return None;
        }
        let paced = now >= self.next_page;
        if self.seed_first.is_empty() && !paced {
            return None;
        }
        let s = self.head.as_ref()?.sh.header().seed;
        let exiting = self.exits.seats();
        let behind =
            |x: &SeatRef| self.seats.get(x).is_some_and(|st| st.seed < s) && !exiting.contains(x);
        let first: Vec<SeatRef> = self
            .seed_first
            .iter()
            .take(SEED_PAGE_SEATS)
            .copied()
            .collect();
        let mut seats: Vec<SeatRef> = first.iter().copied().filter(|x| behind(x)).collect();
        if paced && seats.len() < SEED_PAGE_SEATS {
            let chosen: HashSet<SeatRef> = seats.iter().copied().collect();
            let more = self
                .seats
                .keys()
                .filter(|x| behind(x) && !chosen.contains(x))
                .take(SEED_PAGE_SEATS - seats.len())
                .copied()
                .collect::<Vec<_>>();
            seats.extend(more);
        }
        for x in &first {
            self.seed_first.remove(x);
        }
        if seats.is_empty() {
            if paced {
                self.next_page = now + SEED_PAGE_EVERY_MS;
            }
            return None;
        }
        Some(seats)
    }

    /// A seat that fetched behind a running roll: first in the next page. One that holds
    /// the head's seed (seated by a Join during the roll) is no page's.
    pub fn seed_wanted(&mut self, seat: SeatRef) {
        let Some(s) = self.head.as_ref().map(|h| h.sh.header().seed) else {
            return;
        };
        if self.roll_runs() && self.seats.get(&seat).is_some_and(|x| x.seed < s) {
            self.seed_first.insert(seat);
        }
    }

    /// Asks a page of the `wanted` seats the relay found keys of (`keyed`: each seat's
    /// identity key and pair) of an online keyholder, with a 60 s deadline. A seat in
    /// `gone` (its account's current seat keys make another seat, or it has none) can get
    /// no seed welcome: it exits with that cause, so the roll can finish (§5.6).
    pub fn ask_page(
        &mut self,
        keyed: Vec<(SeatRef, [u8; 32], Pair)>,
        gone: Vec<(SeatRef, u8)>,
        now: u64,
        out: &mut Vec<Out>,
    ) {
        for (seat, why) in gone {
            self.exit(seat, why, now, out);
        }
        // Not one passed over, nor the keyholder that just declined a page
        let mut skip = self.passed.clone();
        skip.extend(self.page_declined.take());
        let to = self
            .holders
            .pick(self.kind, &self.vols, &skip, now)
            .cloned();
        let (Some(head), Some(v), false) = (&self.head, to, keyed.is_empty()) else {
            self.next_page = now + SEED_PAGE_EVERY_MS;
            return;
        };
        let hd = head.sh.header();
        let id = self.next_due;
        self.next_due += 1;
        let piece = DuePiece {
            kind: gk::due::SEED_WELCOMES,
            parent: head.sh.d(),
            deadline_ms: DEADLINE_SLOW_MS as u32,
            keyring_at: (hd.epoch, hd.join),
            seed_seats: keyed
                .iter()
                .map(|(s, ik, p)| gk::SeedSeat {
                    seat: (*s).into(),
                    ik: *ik,
                    keys: p.into(),
                })
                .collect(),
            ..DuePiece::default()
        };
        out.push(Out(v.sid, push::epoch_due(&self.id, id, piece)));
        self.page = Some(Page {
            id,
            sid: v.sid,
            by: v.by(),
            seed: hd.seed,
            seats: keyed.iter().map(|(s, _, _)| *s).collect(),
            deadline: now + DEADLINE_SLOW_MS,
        });
    }

    /// `EpochWelcomes` for page `due` from the keyholder it went to: the welcomes to store,
    /// each to a seat of the page under its seed, and who made them. Any other is refused
    /// `NOT_DUE`, one under another generation or seed `CHECK`.
    #[allow(clippy::too_many_arguments)]
    pub fn take_welcomes(
        &mut self,
        sid: UserId,
        due: u64,
        gen: [u8; 16],
        seed: u32,
        welcomes: Vec<gk::SeedWelcomeOut>,
        out: &mut Vec<Out>,
    ) -> Option<(HolderRef, Welcomed)> {
        let Some(p) = self.page.as_ref().filter(|p| p.id == due && p.sid == sid) else {
            self.stale(out, sid, due, stale::NOT_DUE, "");
            return None;
        };
        if self.gen() != Some(gen) || seed != p.seed {
            self.stale(out, sid, due, stale::CHECK, "a page under another seed");
            return None;
        }
        let took = welcomes
            .into_iter()
            .filter(|w| w.check().is_ok())
            .filter_map(|w| {
                let seat = SeatRef::from(w.seat);
                p.seats.contains(&seat).then_some((seat, w.bytes))
            })
            .collect();
        Some((p.by, took))
    }

    /// Seed welcomes stored for `seats` under `seed`: each seat holds it from now on (§5.6),
    /// and its online sessions get it at once (2f). The page is done once each of its
    /// seats has one.
    pub fn seeded(
        &mut self,
        by: HolderRef,
        seed: u32,
        seats: &[(SeatRef, Vec<u8>)],
        now: u64,
        out: &mut Vec<Out>,
    ) {
        for (seat, bytes) in seats {
            if let Some(x) = self.seats.get_mut(seat) {
                x.seed = x.seed.max(seed);
            }
            if let Some(p) = self.page.as_mut() {
                p.seats.remove(seat);
            }
            let to: Vec<UserId> = self
                .members
                .iter()
                .filter(|(_, m)| m.seat == Some(*seat))
                .map(|(sid, _)| *sid)
                .collect();
            for sid in to {
                self.pushed(
                    out,
                    sid,
                    InPiece {
                        seed_welcome: Some(gk::SeedWelcomeIn {
                            s: seed,
                            from: by.into(),
                            bytes: bytes.clone(),
                        }),
                        ..InPiece::default()
                    },
                );
            }
        }
        if self.page.as_ref().is_some_and(|p| p.seats.is_empty()) {
            self.page = None;
            self.next_page = now + SEED_PAGE_EVERY_MS;
        }
    }

    // ── Other relay events ────────────────────────────────────────────────

    /// A seat whose keying a new connection cannot get (a memory group's welcome went to an
    /// earlier connection, 2b): it exits, and joins again with `f`'s pair once that exit is
    /// taken.
    pub fn rejoin(&mut self, sid: UserId, f: Fetch, now: u64, out: &mut Vec<Out>) {
        let seat = self.members.get(&sid).and_then(|m| m.seat);
        let (Some(seat), Some(pair), Some(ik)) = (seat, f.pair, f.ik) else {
            return;
        };
        if pair.keys.seat(seat.m) != seat {
            return;
        }
        if let Some(m) = self.members.get_mut(&sid) {
            m.waiting = true;
            m.have = f.have;
        }
        match self.rejoins.iter_mut().find(|w| w.joiner.seat == seat) {
            Some(w) if !w.sids.contains(&sid) => w.sids.push(sid),
            Some(_) => {}
            None => {
                self.exit(seat, cause::REJOIN, now, out);
                self.rejoins.push(Waiting {
                    joiner: Joiner {
                        seat,
                        ik,
                        keys: pair.keys,
                        endorsement: pair.endorsement,
                        returning: false,
                    },
                    sids: vec![sid],
                    account: seat.m.account(),
                });
            }
        }
        self.wait(out, sid, wait::QUEUED, "");
        self.ask(now, out);
    }

    /// A device removed from `account`: the entries it made are proposed for removal.
    pub fn device_removed(
        &mut self,
        account: &[u8; 16],
        device: &[u8],
        now: u64,
        out: &mut Vec<Out>,
    ) {
        self.holders.device_removed(account, device);
        self.ask(now, out);
    }

    /// `account`'s newest seat-key counter `n`, since `since` (unix ms): its entries below
    /// it are proposed for removal after seven days.
    pub fn counter(&mut self, account: [u8; 16], n: u32, since: u64, now: u64, out: &mut Vec<Out>) {
        let e = self.holders.newest.entry(account).or_insert((n, since));
        if n > e.0 {
            *e = (n, since);
        }
        self.ask(now, out);
    }

    /// `account`'s seat keys rotated (plan 2d "Rotation"): each of its seats but `keep`
    /// exits (cause `ROTATION`), and its sessions are seated anew at their next fetch.
    pub fn rotated(&mut self, account: &[u8; 16], keep: &SeatRef, now: u64, out: &mut Vec<Out>) {
        let old: Vec<SeatRef> = self
            .seats
            .iter()
            .filter(|(r, s)| s.account.as_ref() == Some(account) && *r != keep)
            .map(|(r, _)| *r)
            .collect();
        for s in &old {
            self.exit(*s, cause::ROTATION, now, out);
        }
        self.rejoins
            .retain(|w| w.joiner.seat == *keep || w.account.as_ref() != Some(account));
        for m in self.members.values_mut() {
            if m.seat.is_some_and(|s| old.contains(&s)) {
                m.seat = None;
            }
        }
        self.ask(now, out);
    }

    /// Seats unused for 90 days exit (the daily sweep), unless a session holds one now.
    pub fn expire(&mut self, seats: &[SeatRef], now: u64, out: &mut Vec<Out>) {
        for s in seats {
            let held = self.members.values().any(|m| m.seat == Some(*s));
            if !held && self.seats.contains_key(s) {
                self.exit(*s, cause::EXPIRY, now, out);
            }
        }
        self.ask(now, out);
    }

    // ── What an admin sees (plan 2j) ──────────────────────────────────────

    /// Raises a warning of `kind`, at most once in `WARN_EVERY_MS`, logged at warn.
    fn warn(&mut self, kind: u8, text: String, now: u64) {
        if self
            .warns
            .get(&kind)
            .is_some_and(|(_, at)| now < at + WARN_EVERY_MS)
        {
            return;
        }
        warn!(group = %self.id, "{text}");
        self.warns.insert(kind, (text, now));
    }

    /// The conditions a tick warns of: no keyholder online for a minute or more, and the
    /// head epoch older than 70 min, each while members are here.
    fn check_warnings(&mut self, now: u64) {
        if self.members.is_empty() {
            return;
        }
        if let Some(since) = self.no_keyholder_since {
            let min = now.saturating_sub(since) / 60_000;
            if min >= 1 {
                let text = format!("no keyholder online for {min} min");
                self.warn(warn_kind::NO_KEYHOLDER, text, now);
            }
        }
        let late = self
            .head
            .as_ref()
            .is_some_and(|h| now >= h.opened_ms + EPOCH_AGE_MAX_SECS * 1000);
        if late {
            self.warn(warn_kind::LATE, "keys late".into(), now);
        }
    }

    /// The warnings raised in the last `WARN_EVERY_MS`, by kind.
    pub fn warnings(&self, now: u64) -> Vec<String> {
        let mut w: Vec<(u8, &String)> = self
            .warns
            .iter()
            .filter(|(_, (_, at))| now < at + WARN_EVERY_MS)
            .map(|(k, (t, _))| (*k, t))
            .collect();
        w.sort();
        w.into_iter().map(|(_, t)| t.clone()).collect()
    }

    /// About what this group holds in memory, from its counts alone (each event publishes
    /// it): seats and their list places, leaves, seals, kept headers, sessions, and joiners'
    /// and connection seats' pairs.
    pub fn mem_bytes(&self) -> u64 {
        let n = self.seats.len() * (160 + 33)
            + self.leaves.len() * 120
            + self.vers.len() * 96
            + self.seals.len() * 120
            + (self.recent.len() + self.khs.len()) * 1200
            + self.members.len() * 160
            + (self.joins.queue.len() + self.rejoins.len() + self.conn_keys.len()) * 1400;
        n as u64
    }

    /// The snapshot of the head for fetches outside the actor.
    pub fn snapshot(&self) -> Option<HeadSnapshot> {
        let h = self.head.as_ref()?;
        Some(HeadSnapshot {
            head: h.sh.clone(),
            parent: h.parent.clone(),
            opening: h.opening.clone(),
            khs: Arc::new(self.khs.clone()),
            recent: Arc::new(self.recent.iter().cloned().collect()),
            leaves: self.leaves.clone(),
            tree: self.tree.clone(),
            vers: Arc::new(self.vers.clone()),
            seals: Arc::new(self.seals.clone()),
        })
    }

    /// Whether the actor may stop: nobody follows and nothing is out. A forced removal
    /// another entry can sign keeps it up: only memory holds it (a ban, reset or deletion is
    /// not told again).
    pub fn idle(&self) -> bool {
        let forced = &self.holders.forced;
        self.members.is_empty()
            && self.dues.is_empty()
            && self.open.is_empty()
            && self.joins.queue.is_empty()
            && self.rejoins.is_empty()
            && (forced.is_empty() || forced.len() >= self.holders.set.len())
    }

    /// Who is seated, for the fetches answered outside the actor.
    pub fn seated_sids(&self) -> Vec<(UserId, SeatRef)> {
        self.members
            .iter()
            .filter_map(|(sid, m)| {
                m.seat
                    .filter(|s| self.seats.contains_key(s))
                    .map(|s| (*sid, s))
            })
            .collect()
    }

    /// The keyholder's `KX`, if `sid` is an online keyholder.
    pub fn holder_kx(&self, sid: UserId) -> Option<[u8; 32]> {
        self.vols
            .get(&sid)
            .filter(|v| self.holders.entry_of(v).is_some())
            .map(|v| v.pair.kx())
    }
}

fn piece_heap(p: &CommitPiece) -> usize {
    use voipc_protocol::gk::Footprint;
    p.heap()
}
