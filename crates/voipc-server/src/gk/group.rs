//! One group on the relay (plan 2b–2f): pure state, no IO. Each event takes the relay's
//! clock (unix ms) and an `Out` list of frames to queue; a commit is checked here
//! (`commit_part` → `Taken`), stored by the actor, then taken (`apply`). The actor reads
//! the store where an answer needs material (seat keying, keyring) and runs the timers
//! (`wake`, `tick`).

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use dashmap::DashMap;
use tracing::{debug, warn};
use voipc_crypto::group_key::build::kx_tag;
use voipc_crypto::group_key::commit::{
    validate, Applied, Commit, Due, DueKind, Exit, GroupView, HeadView as CommitHead, HolderRef,
    Joiner, Listed, Make, Pair, ReplaceAsk,
};
use voipc_crypto::group_key::timers::{
    deadline_ms, refresh_ms, regenesis_after_ms, BLOBS_PER_WRITER, BLOB_MAX_BYTES,
    DEADLINE_SLOW_MS, EPOCH_AGE_MAX_SECS, EPOCH_MIN_GAP_MS, FLOOR_AHEAD_GAP_SECS,
    MATERIAL_SWEEP_MS, OPEN_COMMIT_MS, OPEN_PER_CONN_BYTES, OPEN_PER_RELAY_BYTES, REFRESH_MS,
    REGENESIS_AFTER_MS, REGENESIS_FAST_AFTER_MS, RETRY_ALL_MISSED_MS, SEAT_EXPIRY_SECS,
    SEED_PAGE_EVERY_MS, SEED_PAGE_SEATS,
};
use voipc_crypto::group_key::tree::BucketTree;
use voipc_crypto::group_key::{
    GroupKind, Keyholder, Kind, MemberId, SeatRef, SeedRolls, SignedHeader, SEED_MAX_AGE,
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
    /// The head it was asked at (its `DuePiece::parent`): a keyholder builds it there only
    /// (holder.rs `advance`).
    pub parent: [u8; 32],
    /// The head moved off `parent` under the same seed before the page came (`apply`).
    pub moved: bool,
}

/// How long a page the head moved under still waits for an answer already on its way: one
/// the keyholder built at its parent comes within a round trip, one that waited for the
/// keyring there never does (the relay hands the ring at the head it holds now).
const PAGE_MOVED_MS: u64 = 5_000;

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
    /// A voice room's member that was sent the whole roster (`VoiceSeats`): each change
    /// goes to it from then on.
    pub roster: bool,
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

/// Keyholder headers a generation keeps before it starts anew (`ask`): a walk back to its
/// start stays within a member's `MAX_WALK` links, with room for the keyholder changes made
/// until a volunteer can start the new one. Past `MAX_WALK` a device with no floor, or one
/// whose floor is far behind, could never take the head again in this generation.
pub const KH_RESTART: usize = voipc_crypto::group_key::MAX_WALK / 2;
/// How soon a long chain's new generation is asked again after nobody took it.
pub const KH_RESTART_RETRY_MS: u64 = 10 * 60_000;
/// How long before the writers' epoch age limit a group with nobody to refresh it asks a
/// new start (as soon as its wait allows).
pub const AGED_LEAD_MS: u64 = 10 * 60_000;
/// An opening this long after the last one re-keys every bucket version (their 1 h age).
pub const FULL_REKEY_AFTER_MS: u64 = 60 * 60_000;

pub struct GroupState {
    pub id: String,
    pub kind: GroupKind,
    /// A `c:` group on a relay with accounts: its store is the database.
    pub stored: bool,
    /// The channel's gate as the relay holds it; the head's may lag (plan 2d).
    pub gate: bool,
    /// A voice room's `anonymous` flag, as its last join found it: it names the seats taken
    /// from then on (voice.rs `room_seat_m`).
    pub anonymous: bool,
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
    /// Tests: no refresh is due while set (`Groups::hold_refresh_for_test`).
    #[cfg(test)]
    pub refresh_held: bool,
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
    /// A text roll ended at its 24 h with seats still behind the head's seed (GROUP-KEY
    /// §5.6): the pages go on until each holds it or exits, as while a roll runs. Cleared
    /// by a paced scan that finds none behind.
    pub left_behind: bool,
    /// A stored text group's account seats a Join seated with no session waiting for them
    /// (eager seats, plan 2d), each owed a seed welcome under the head seed (dive 3 P3): no
    /// device opened its seat welcome, the only other place its member secret under that
    /// seed is, and once its bucket is re-keyed by rows and the seed rolls, the kept posts
    /// in between open only with that secret. Paged like a roll's seats, roll or not;
    /// dropped when the seed rises (the roll's pages take over) or at a new start.
    pub seed_owed: HashSet<SeatRef>,
    /// The keyholder that declined the last page: the next goes to another if one is online.
    page_declined: Option<UserId>,
    /// When a page's welcomes last failed to store (relay ms, `page_unstored`).
    page_failed_at: u64,
    /// Memory seats whose welcome is gone, re-joining once their exit is taken (2b).
    pub rejoins: Vec<Waiting>,
    /// The highest seat-key counter each account rotated to, as `supersede` heard it: an
    /// eager seat of it below that comes late and is not queued.
    superseded: HashMap<[u8; 16], u32>,
    /// Eager seats queued at most (`kept_seats`).
    pub kept_seats: usize,
    /// The device each volunteering session named, for its entry (plan 2d).
    pub devices: HashMap<UserId, Vec<u8>>,
    /// Admin warnings by kind: the text and when it was raised (plan 2j).
    pub warns: HashMap<u8, (String, u64)>,
    /// A memory text group's account seats that no session holds, since when (relay ms):
    /// their 90-day expiry, which a stored group reads from its database (§5.4).
    pub away: HashMap<SeatRef, u64>,
    /// When a long keyholder chain's new generation may be asked (again) (relay ms).
    pub kh_restart_at: u64,
}

impl GroupState {
    pub fn new(id: String, kind: GroupKind, stored: bool, caps: Arc<OpenCaps>) -> GroupState {
        GroupState {
            id,
            kind,
            stored,
            gate: false,
            anonymous: false,
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
            #[cfg(test)]
            refresh_held: false,
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
            left_behind: false,
            seed_owed: HashSet::new(),
            page_declined: None,
            page_failed_at: 0,
            rejoins: vec![],
            superseded: HashMap::new(),
            kept_seats: KEPT_SEATS,
            devices: HashMap::new(),
            warns: HashMap::new(),
            away: HashMap::new(),
            kh_restart_at: 0,
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

    pub(super) fn head_gated(&self) -> bool {
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
    /// (§5.4); a due it was asked goes to another keyholder. A voice room's members hear it
    /// left, and a voice keyholder's leave closes the exit batch at once, so its removal
    /// carries its seat's exit (§5.9).
    pub fn leave(&mut self, sid: UserId, cause: u8, now: u64, out: &mut Vec<Out>) {
        let Some(m) = self.members.remove(&sid) else {
            return;
        };
        self.holders.unable.remove(&sid);
        let voice = self.kind == GroupKind::Voice;
        let keyholder = voice && self.is_keyholder(sid);
        let rostered = voice && self.vols.contains_key(&sid);
        self.vols.remove(&sid);
        if let Some((p, _)) = self.open.remove(&sid) {
            self.caps.charge(sid, p.held(), 0);
        }
        self.joins.leave(sid, self.stored);
        if let Some(seat) = m.seat {
            let offline =
                cause == cause::DISCONNECT && !seat.m.is_conn() && self.kind == GroupKind::Text;
            if !self.members.values().any(|o| o.seat == Some(seat)) {
                if !offline {
                    self.exit(seat, cause, now, out);
                } else if !self.stored {
                    self.away.insert(seat, now);
                }
            }
        }
        if rostered {
            self.room_gone(sid, out);
        }
        if keyholder {
            self.exits.close(self.head_gated());
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
        self.accounts_exit(&HashMap::from([(*account, cause)]), now, out);
    }

    /// Every seat of each account `asks` names exits with that account's cause (`account_exit`
    /// past a ban's, reset's or deletion's keyholder entries: a log leave, a gate, a new
    /// password, a kick or leave asked ahead), in one walk of the seats, the dues and the
    /// sessions however many accounts it names: a new password can take 100k, and a walk each
    /// was 1e10 steps there. A seat already on its way out is not looked for in the batches
    /// again.
    pub fn accounts_exit(&mut self, asks: &HashMap<[u8; 16], u8>, now: u64, out: &mut Vec<Out>) {
        if asks.is_empty() {
            return;
        }
        let cause_of = |a: Option<&[u8; 16]>| a.and_then(|a| asks.get(a).copied());
        let mut seats: Vec<(SeatRef, u8)> = self
            .seats
            .iter()
            .filter_map(|(r, s)| Some((*r, cause_of(s.account.as_ref())?)))
            .collect();
        seats.extend(
            self.dues
                .iter()
                .flat_map(|d| &d.due.joiners)
                .filter_map(|j| Some((j.seat, cause_of(j.seat.m.account().as_ref())?))),
        );
        // Its sessions' seats, whatever they are named by: a voice seat in an anonymous room
        // that is not gated is its connection's (open choice 11)
        seats.extend(
            self.members
                .values()
                .filter_map(|m| Some((m.seat?, cause_of(m.account.as_ref())?))),
        );
        let mut exiting = self.exits.seats();
        for (s, c) in seats {
            let was = !exiting.insert(s);
            self.exit_if(s, c, now, out, |_| was);
        }
        let ours = |a: &Option<[u8; 16]>| a.as_ref().is_some_and(|a| asks.contains_key(a));
        self.joins.retain(|w| !ours(&w.account));
        self.rejoins.retain(|w| !ours(&w.account));
        for m in self.members.values_mut() {
            if ours(&m.account) {
                m.seat = None;
            }
        }
        self.ask(now, out);
    }

    /// `accounts_exit` for each of `asks` no session here holds a seat of (a leave or kick
    /// asked ahead of an account that keeps no log: its own session's `Leave` went first, and
    /// a seat another of its sessions holds stays, as `leave` keeps it).
    pub fn accounts_exit_unheld(
        &mut self,
        asks: &HashMap<[u8; 16], u8>,
        now: u64,
        out: &mut Vec<Out>,
    ) {
        let held: HashSet<[u8; 16]> = self
            .members
            .values()
            .filter(|m| m.seat.is_some())
            .filter_map(|m| m.account)
            .collect();
        let unheld: HashMap<[u8; 16], u8> = asks
            .iter()
            .filter(|(a, _)| !held.contains(*a))
            .map(|(a, c)| (*a, *c))
            .collect();
        self.accounts_exit(&unheld, now, out);
    }

    /// Whether a seat of `account` exits only once the due seating it lands (`exit_late`):
    /// its exit is in memory alone until then.
    pub fn exiting_late(&self, account: &[u8; 16]) -> bool {
        self.exit_late
            .iter()
            .any(|(_, s, _)| s.m.account().as_ref() == Some(account))
    }

    /// A seat enters the open exit batch; writers of the epoch hear of it at once (1f.6),
    /// and in a voice room every seated member, who all hear the room under the epoch's key
    /// whether they wrote or not (§5.9). A seat a due out is seating exits once that lands.
    pub fn exit(&mut self, seat: SeatRef, cause: u8, now: u64, out: &mut Vec<Out>) {
        self.exit_if(seat, cause, now, out, |e| e.has(&seat))
    }

    /// `exit`, `exiting` telling whether the seat is in an exit batch already.
    fn exit_if(
        &mut self,
        seat: SeatRef,
        cause: u8,
        now: u64,
        out: &mut Vec<Out>,
        exiting: impl FnOnce(&super::due::Exits) -> bool,
    ) {
        self.joins.take(&seat);
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
        if exiting(&self.exits) {
            return;
        }
        let seq = self.exits.add(seat, s.b, cause, now);
        let voice = self.kind == GroupKind::Voice;
        let seats = &self.seats;
        for (sid, m) in self.members.iter_mut() {
            if m.writer || (voice && m.seat.is_some_and(|s| seats.contains_key(&s))) {
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

    /// A session's `KeyholdVolunteer`, or its end (`None`). A voice room takes none: every
    /// member offers its seat's pair by its fetch (voice.rs `room_seat`).
    pub fn volunteer(&mut self, sid: UserId, v: Option<Volunteer>, now: u64, out: &mut Vec<Out>) {
        if !self.members.contains_key(&sid) || self.kind == GroupKind::Voice {
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
        let seat = match self.kind {
            GroupKind::Voice => self.room_seat(sid, m.account, &pair, ik, now, out),
            GroupKind::Text => pair
                .keys
                .seat(m.account.map_or(MemberId::Conn(sid), MemberId::Account)),
        };
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
            if holders::starter(self.kind, &self.vols, self.gate, &self.holders.unable).is_some() {
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

    /// A seat-key rotation of `account` to counter `n` (`Groups::on_seat_keys`): its seats at
    /// a lower counter (0x01) not yet seated go, and one a due out seats exits once it lands.
    /// Keys published before the rotation, a thief's among them, are not seated after it
    /// where nothing exits the account (no seat of it here, or the same keys again above
    /// another's, RV q8-q11). Once a rotation, so a walk of the queue. Eager seats below it
    /// queued later are not taken (`eager`): two rotations' walks may cross.
    pub fn supersede(&mut self, account: &[u8; 16], n: u32, now: u64, out: &mut Vec<Out>) {
        let top = self.superseded.entry(*account).or_insert(n);
        *top = (*top).max(n);
        let n = *top;
        let below = |j: &Joiner| {
            j.seat.m.account() == Some(*account)
                && j.endorsement.origin == voipc_crypto::group_key::Origin::VaultSeat
                && j.endorsement.n < n
        };
        let seating: Vec<SeatRef> = self
            .dues
            .iter()
            .flat_map(|d| &d.due.joiners)
            .filter(|j| below(j))
            .map(|j| j.seat)
            .collect();
        for s in seating {
            self.exit(s, cause::ROTATION, now, out);
        }
        self.joins.retain(|w| !below(&w.joiner));
    }

    /// An eager seat (plan 2d): queued with no session waiting for it.
    pub fn eager(&mut self, joiner: Joiner, account: [u8; 16], now: u64, out: &mut Vec<Out>) {
        if self.seats.contains_key(&joiner.seat) {
            return;
        }
        // Below a rotation heard already (`supersede`): another walk's, late
        let e = &joiner.endorsement;
        if e.origin == voipc_crypto::group_key::Origin::VaultSeat
            && self.superseded.get(&account).is_some_and(|n| e.n < *n)
        {
            return;
        }
        // At most `kept_seats` eager seats wait (plan 2d), however many sources queue them
        if self.joins.eager() >= self.kept_seats && !self.joins.has(&joiner.seat) {
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
            deadline_ms: d.span as u32,
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
            // A voice Remove rolls the seed in its own commit (§5.6): the seats behind get
            // their seed welcomes in it
            seed_seats: match (self.kind, d.due.remove) {
                (GroupKind::Voice, Some(_)) => self.room_seed_seats(&d.held),
                _ => vec![],
            },
            finish: d.held.is_empty(),
            pairs,
            held: d.held.iter().map(|(s, n)| ((*s).into(), *n)).collect(),
        };
        out.push(Out(d.sid, push::epoch_due(&self.id, d.id, piece)));
    }

    /// The id the next due or page takes: an actor turn notes it before it works.
    pub fn due_mark(&self) -> u64 {
        self.next_due
    }

    /// The dues and the page asked since `mark` count their deadline from `sent`, when the
    /// turn sends them, not from `asked`, its clock read: the relay's own store writes in
    /// between are not the keyholder's time.
    pub fn sent_at(&mut self, mark: u64, asked: u64, sent: u64) {
        let lag = sent.saturating_sub(asked);
        if lag == 0 {
            return;
        }
        for d in self.dues.iter_mut().filter(|d| d.id >= mark) {
            d.deadline += lag;
        }
        if let Some(p) = self.page.as_mut().filter(|p| p.id >= mark) {
            p.deadline += lag;
        }
    }

    /// How long a due of `kind` is given. An exits opening after an hour with none re-keys
    /// every bucket version by rows (`plan_opening`), which in a big channel takes longer than
    /// an exits due's 4 s: it gets the slow deadline, so a miss does not throw that work away
    /// again and again (dive 2 F4). Writers hold their posts 46 s after a named exit anyway.
    fn span(&self, kind: DueKind, now: u64) -> u64 {
        let full = self
            .head
            .as_ref()
            .is_some_and(|h| now >= h.opened_ms + FULL_REKEY_AFTER_MS);
        if kind == DueKind::Exits && full {
            DEADLINE_SLOW_MS
        } else {
            deadline_ms(kind)
        }
    }

    fn put_due(&mut self, due: Due, to: &Volunteer, now: u64, out: &mut Vec<Out>) {
        let (held, head_seed) = self.held_now();
        let span = self.span(due.kind, now);
        let d = DueOut {
            id: self.next_due,
            deadline: now + span,
            span,
            due,
            sid: to.sid,
            by: to.by(),
            held,
            head_seed,
        };
        self.next_due += 1;
        debug!(group = %self.id, due = d.id, kind = ?d.due.kind, to = d.sid, joins = d.due.joiners.len(), exits = d.due.exits.len(), "a due asked");
        // A keyholder works one due of a group at a time, and a page is one: a new due drops
        // what it had in hand (holder.rs `on_due`). So the page out to it is let go here, no
        // miss, and asked again once a keyholder is free (`page_wanted`); else it waited out
        // its 60 s and counted toward a healthy keyholder's removal (dive 3 P3)
        if self.page.as_ref().is_some_and(|p| p.sid == to.sid) {
            self.page = None;
            self.next_page = now;
        }
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
        let wanted = !self.joins.is_empty() || self.members.values().any(|m| m.waiting);
        if self.head.is_none() || self.new_gen {
            // A voice room's leaver waits on the start as a joiner would: a start one member
            // declined goes to the next (review C-P7)
            let voice_exit = self.kind == GroupKind::Voice && self.exits.waiting() > 0;
            self.ask_start(Kind::Genesis, wanted || voice_exit, now, out);
            return;
        }
        // A generation whose keyholder chain grew long (`KH_RESTART`) starts anew
        let long = self.khs.len() >= KH_RESTART;
        if self.holders.online(&self.vols).is_empty() {
            self.no_keyholder_since.get_or_insert(now);
            // Seated members are not "waiting", but past the writers' age limit (§5.5) none
            // of them can post: an epoch near it with anyone following asks the new start
            // as a waiting seat would (dive 2 F1)
            let aged = !self.members.is_empty() && self.aged_at().is_some_and(|t| now >= t);
            if (wanted || self.exits.waiting() > 0 || aged) && self.dues.is_empty() {
                if !self.stored {
                    // Voice rooms and memory groups: a new generation at once
                    if holders::starter(self.kind, &self.vols, self.gate, &self.holders.unable)
                        .is_some()
                    {
                        self.new_gen = true;
                        self.ask_start(Kind::Genesis, true, now, out);
                    }
                } else if self.regenesis_at().is_some_and(|t| now >= t) {
                    // A long chain starts a new generation instead: a Regenesis adds to it
                    let kind = if long { Kind::Genesis } else { Kind::Regenesis };
                    self.ask_start(kind, true, now, out);
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
        // A long chain, with a keyholder online: a new generation though nobody waits. Past
        // `MAX_WALK` links a device with no floor, or one whose floor is far behind, could
        // never take the head again. The head is served until the Genesis lands, and what
        // else is due goes on when nobody takes it (asked again `KH_RESTART_RETRY_MS` on)
        if long && now >= self.kh_restart_at {
            self.kh_restart_at = now.saturating_add(KH_RESTART_RETRY_MS);
            warn!(group = %self.id, headers = self.khs.len(), "the keyholder chain is long: a new generation");
            self.ask_start(Kind::Genesis, true, now, out);
            if !self.dues.is_empty() {
                return;
            }
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
    /// Refresh, but in a text group a Refresh a whole refresh period late goes before a Join:
    /// a newcomer is never seated into an epoch a keyholder's absence or a join storm let age
    /// past two refresh periods (§6 "A newcomer"). With the session it must go to, if only
    /// one may take it.
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
            let promote = match self.kind {
                GroupKind::Voice => self.room_candidate(),
                GroupKind::Text => self
                    .holders
                    .promotion(self.kind, &self.vols, self.opening_gated(), seats)
                    .cloned(),
            };
            if let Some(v) = promote {
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
        // A Join goes before a Refresh that is due (lazy seating: a newcomer opens the post
        // that made it ask), but not once the Refresh is a whole refresh period late: a join
        // storm or a keyholder's absence never lets the epoch a newcomer is seated into age
        // past two of them. Text only: a voice room keeps no posts to read back
        let r = self
            .head
            .as_ref()
            .map_or(REFRESH_MS, |h| refresh_ms(h.sh.header().buckets));
        let refresh_late = gap_ok
            && self.kind == GroupKind::Text
            && self
                .refresh_at()
                .is_some_and(|t| now >= t.saturating_add(r));
        if !refresh_late && self.joins.closes_at(self.kind).is_some_and(|t| now >= t) {
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
        if self.refresh_at().is_some_and(|t| now >= t) {
            return Some((self.exits_due(DueKind::Refresh), None));
        }
        None
    }

    /// When a stored group with no keyholder online may be asked a Regenesis (relay ms):
    /// once the wait the head's set allows is out (`regenesis_after_ms`, "Fast new start").
    /// The hour counts from when no keyholder was online and from the head's own `time`,
    /// as the volunteer and every member count it (`time ≥ parent.time + wait`). None, for
    /// a set of connection entries alone that no Regenesis started in the last hour, counts
    /// from when no keyholder was online alone: the volunteer dates the Regenesis no
    /// earlier than the head (`build_regenesis`), so a head dated ahead of the relay's
    /// clock holds nothing back. And never within the gap after the last opening
    /// (`EPOCH_MIN_GAP_MS`, as every opening). `None` with a keyholder online, or no head.
    /// When the next refresh is due; none while a test holds refreshes.
    fn refresh_at(&self) -> Option<u64> {
        #[cfg(test)]
        if self.refresh_held {
            return None;
        }
        self.next_refresh
    }

    /// When the head epoch comes within `AGED_LEAD_MS` of the writers' age limit (§5.5).
    fn aged_at(&self) -> Option<u64> {
        let h = self.head.as_ref()?;
        Some((h.opened_ms + EPOCH_AGE_MAX_SECS * 1000).saturating_sub(AGED_LEAD_MS))
    }

    /// The group's actor starts over the store (a restart, or the next start after an idle
    /// stop), `now`. The hour a Regenesis waits (§5.6) counts the keyholders' absence before
    /// the stop (`Store::load` restores `no_keyholder_since` from the entries' `last_online`),
    /// but not the relay's own downtime, in which no device could come back: it ends no sooner
    /// than one sweep after this start (`MATERIAL_SWEEP_MS`, the period an online entry's
    /// `last_online` is written in), so keyholders online at the stop reconnect before a
    /// volunteer is asked to replace them (review R2-2). Under a set of connection entries
    /// alone (no wait) the Regenesis is asked at once still: those never come back. A relay
    /// that starts again more often than every 10 minutes holds a desktop set's Regenesis off.
    pub fn restarted(&mut self, now: u64) {
        let floor = now
            .saturating_sub(REGENESIS_AFTER_MS)
            .saturating_add(MATERIAL_SWEEP_MS);
        if let Some(t) = self.no_keyholder_since.as_mut() {
            *t = (*t).max(floor);
        }
    }

    pub fn regenesis_at(&self) -> Option<u64> {
        let since = self.no_keyholder_since?;
        let head = self.head.as_ref()?;
        let set = head.kh.header();
        let base = since.max(head.sh.header().time.saturating_mul(1000));
        // The churn bound lets a set a Regenesis started go fast an hour after it
        let gap = set
            .time
            .saturating_add(voipc_crypto::group_key::REGENESIS_FAST_GAP)
            .saturating_mul(1000);
        let fast = since.saturating_add(REGENESIS_FAST_AFTER_MS);
        let from = |wait: u64| if wait == 0 { since } else { base };
        [fast, fast.max(gap), base.saturating_add(REGENESIS_AFTER_MS)]
            .into_iter()
            .filter(|t| {
                let wait = regenesis_after_ms(set, *t);
                *t >= from(wait).saturating_add(wait)
            })
            .min()
            .map(|t| t.max(self.last_opening.saturating_add(EPOCH_MIN_GAP_MS)))
    }

    /// A Genesis (no generation, or a new one due) or a Regenesis, to the best volunteer.
    fn ask_start(&mut self, kind: Kind, wanted: bool, now: u64, out: &mut Vec<Out>) {
        if !self.dues.is_empty() || !wanted {
            return;
        }
        let skip = self.passed.clone();
        let Some(v) = holders::allowed(self.kind, &self.vols, self.gate, 0, &self.holders.unable)
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
        // A Regenesis builds on the head (its parent), which a volunteer never seated was
        // never shown: the head from its floor first, as a fetch's answer would carry it
        if dk == DueKind::Regenesis && !self.seats.contains_key(&joiner.seat) {
            let have = self.members.get(&v.sid).and_then(|m| m.have);
            if let Some(snap) = self.snapshot() {
                self.pushed(out, v.sid, snap.head_piece(have.as_ref(), None, false));
            }
        }
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
        let roster = match self.kind {
            GroupKind::Voice => self.room_roster(),
            GroupKind::Text => vec![],
        };
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
            dh: &|s| self.seats.get(s).map(|x| x.dh),
            held: &held,
            due: &d.due,
            by: d.by,
            rolls: self.rolls,
            known_gens: &self.gens,
            used_v: &used,
            now: now / 1000,
            roster: &roster,
            no_keyholder_since: self.no_keyholder_since.map(|t| t / 1000),
        };
        validate(&view, c)
    }

    /// Misses due `at`: its keyholder is passed over, the due is asked again.
    fn miss(&mut self, at: usize, now: u64) {
        let d = self.dues.remove(at);
        debug!(group = %self.id, due = d.id, kind = ?d.due.kind, by = d.sid, late_ms = now.saturating_sub(d.deadline), "a due missed");
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
        let was_floor = self
            .head
            .as_ref()
            .map(|x| x.sh.header())
            .filter(|x| x.gen == h.gen)
            .map(|x| x.seed_floor);
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
        // A seed welcome under the old seed can no longer be made once the seed rose (pages
        // go under the head's): the owed seats are behind now, the roll's pages' (dive 3 P3)
        if h.kind.starts_anew() || was_seed.is_some_and(|w| w < h.seed) {
            self.seed_owed.clear();
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
                // A voice seat is its connection's pair, an account's too
                if s.m.is_conn() || self.kind == GroupKind::Voice {
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
        // An account seat seated with no session waiting for it: no device takes its seat
        // welcome, so it is owed a seed welcome under this seed (dive 3 P3)
        if self.stored && self.kind == GroupKind::Text {
            for (s, _) in &a.seated {
                if s.m.account().is_some() && self.joins.idle_account(s) {
                    self.seed_owed.insert(*s);
                }
            }
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
        // The head moved under the page's seed: a keyholder that fetches the keyring builds the
        // page at its parent only, and no ring comes for that any more, so it never would. One
        // built is waited for a little; then the page goes with no miss (a healthy keyholder's
        // 60 s and a miss toward its removal, fix review P3-R3) and is asked again at the head
        if let Some(p) = self.page.as_mut().filter(|p| p.parent != sh.d()) {
            p.moved = true;
            p.deadline = p.deadline.min(now + PAGE_MOVED_MS);
        }
        // A roll that ended at its 24 h may leave seats behind: their pages go on (§5.6)
        let ended = h.seed_floor == h.seed && was_floor.is_some_and(|f| f < h.seed_floor);
        if h.kind.starts_anew() {
            self.left_behind = false;
        } else if ended {
            self.left_behind = self.seats.values().any(|x| x.seed < h.seed);
        }
        if h.seed_floor == h.seed && !self.left_behind {
            self.seed_first.clear();
        } else if was_seed.is_some_and(|w| w < h.seed) || (ended && self.left_behind) {
            self.next_page = now;
        }
        let seats = &self.seats;
        self.seed_first.retain(|s| seats.contains_key(s));
        self.seed_owed.retain(|s| seats.contains_key(s));
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
        // A voice keyholder is a member who hears the room too: its push carries its seal
        // as well, so it moves to the new epoch with the others, not a fetch later (§5.9)
        for sid in &holders {
            let p = match self.kind {
                GroupKind::Voice => InPiece {
                    chain: piece.chain.clone(),
                    ..piece_for(sid)
                },
                GroupKind::Text => piece.clone(),
            };
            self.pushed(out, *sid, p);
        }
        let mut pushed: Vec<(UserId, InPiece)> = vec![];
        if h.kind.opens_epoch() {
            // A voice room's every member takes an opening at once, writer or not (§5.9)
            let to = match self.kind {
                GroupKind::Voice => self.seated_sids().into_iter().map(|(s, _)| s).collect(),
                GroupKind::Text => writers.clone(),
            };
            for sid in to.iter().filter(|s| !holders.contains(s)) {
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
            // A gated voice room's every member folds each Join's names (§5.9)
            let to = match self.kind {
                GroupKind::Voice => self.seated_sids().into_iter().map(|(s, _)| s).collect(),
                GroupKind::Text => writers.clone(),
            };
            for sid in &to {
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
        // A voice room's new start seats every member whose pair the relay holds, with no
        // fetch (§5.9); in a text group it unseats everyone else: they fetch again and are
        // queued
        if h.kind.starts_anew() && self.kind == GroupKind::Voice {
            self.room_reseat(now, out);
        }
        // A gate's end opened the head: an anonymous room's signed-in members sit by their
        // connection again (voice.rs `room_seat_m`)
        if self.kind == GroupKind::Voice && was_gated && !h.gated {
            self.room_rename(cause::GATE, now, out);
        }
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
        let paging = (self.paging() || !self.seed_owed.is_empty()) && self.page.is_none();
        // Once the gap after an opening ends, `ask` may start what waited for it (exits, a
        // removal, a promotion, a resign, a replace)
        let asks = [
            self.joins.closes_at(self.kind),
            self.refresh_at(),
            Some(self.last_opening + EPOCH_MIN_GAP_MS),
            self.regenesis_at().filter(|_| self.stored),
            self.aged_at().filter(|_| !self.members.is_empty()),
            paging.then_some(self.next_page),
            (self.khs.len() >= KH_RESTART).then_some(self.kh_restart_at),
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
        // A seed-welcome page past its deadline: a miss, asked again of another. One the head
        // moved under is no miss: it could not be built (`apply`)
        if let Some(p) = self.page.take_if(|p| p.deadline <= now) {
            if !p.moved {
                self.holders.missed(&p.by.kx, now);
                self.missed_total += 1;
            }
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
                    d.span = self.span(d.due.kind, now);
                    d.deadline = now + d.span;
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
        debug!(group = %self.id, due, kind = ?d.due.kind, by = sid, why, "a due declined");
        if why != gk::decline::CANDIDATE {
            self.holders.declined(&d.by.kx, now);
        }
        match why {
            // It declines every due while its session lasts: not online, so another can be
            // promoted or a new start asked (dive 2 F2)
            gk::decline::CLOCK | gk::decline::PLATFORM => {
                self.holders.unable.insert(sid);
            }
            // Its candidate is not asked again while this set stands (dive 2 F3)
            gk::decline::CANDIDATE => {
                if let Some(c) = &d.due.candidate {
                    self.holders.refused.insert(c.pair.kx());
                }
            }
            _ => {}
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
        // Kept under the writer its post names (a voice room's by the post's epoch, as its
        // app names it), which readers ask it by
        let by = match self.kind {
            GroupKind::Voice => self.room_writer(sid, m.account, &gen, epoch),
            GroupKind::Text => seat.m,
        };
        let w = GkWriter {
            m: by.into(),
            u: sid,
        };
        // Under the epoch before the head, only a writer of it (pushed the opening) may start
        // another chain for `HOLD_MS`: a member that only read it was never pushed the
        // opening nor told of the exit it covers, and its first chain there would be one the
        // leaver opens (§5.4). Refused `OLD_EPOCH`, it fetches and writes under the head.
        let old = self.head_view().is_some_and(|v| epoch != v.epoch);
        if old && self.kind == GroupKind::Text && !self.blobs.contains_key(&(epoch, w)) {
            return Err(refused_why::OLD_EPOCH);
        }
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
    pub fn names(&self, sid: UserId, from: &NamesRef, to: &NamesRef, out: &mut Vec<Out>) {
        if !self.members.contains_key(&sid) {
            self.refuse(out, sid, refused_what::NAMES, refused_why::NOT_MEMBER);
        } else if !self.head_gated() {
            self.refuse(out, sid, refused_what::NAMES, refused_why::NOT_GATED);
        } else {
            out.push(Out(
                sid,
                push::names_in(&self.id, self.names.answer(from, to)),
            ));
        }
    }

    /// The channel's group id came back to this stored group (it was another's meanwhile: an
    /// anonymous or `hide_members` flip): a new generation, so no seat that should have gone
    /// while the channel ran under the other id (a kick there) is keyed here again.
    pub fn moved_back(&mut self, now: u64, out: &mut Vec<Out>) {
        if self.head.is_none() {
            return;
        }
        self.new_gen = true;
        self.ask(now, out);
    }

    /// `EpochFloorAhead` (plan 2d): a header past the head, signed by a keyholder in the
    /// head's set, starts a new generation (at most one an hour). One signed by an entry an
    /// earlier set of the generation had (removed, swapped out, or a set a Regenesis
    /// replaced) starts nothing: honouring it would let a removed keyholder force a re-seat
    /// every hour (§5.7). That, a generation the relay does not know, or a signer it holds no
    /// key of warns its admins: a restore that lost what members took looks so.
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
        if (h.epoch, h.join) <= (hd.epoch, hd.join) {
            return;
        }
        let signed = |k: &Keyholder| k.m == h.signer && sh.verify(&k.ik);
        if !head.kh.header().keyholders.iter().any(signed) {
            // Either is what a restore that lost a later keyholder change looks like (an
            // entry promoted again after the backup keeps its IK), or a removed keyholder's
            // fork: the admins are told, and only the operator starts anew
            let known = self
                .khs
                .values()
                .flat_map(|(k, _)| k.header().keyholders.iter())
                .any(signed);
            let text = if known {
                "a member reports a header past this database's head, signed by a keyholder \
                 no longer in its set"
            } else {
                "a member reports a header past this database's head, signed by a keyholder \
                 it holds no key of"
            };
            self.warn(warn_kind::AHEAD, text.into(), now);
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
        // A voice room's signed-in members sit by their connection while it is anonymous and
        // open: gated, each takes its account's seat in the open group first (voice.rs)
        if self.kind == GroupKind::Voice {
            self.room_rename(cause::GATE, now, out);
        }
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

    /// Whether seed-welcome pages are asked: while a roll runs, and after one that ended
    /// at its 24 h while seats were still behind (`left_behind`, §5.6).
    pub fn paging(&self) -> bool {
        self.roll_runs() || (self.left_behind && self.head.is_some())
    }

    /// The seats the next seed-welcome page asks, when one is wanted now: pages are asked
    /// (`paging`) or a seat is owed one (`seed_owed`), no page is out, a keyholder with no
    /// due out is online, and a seat behind fetched (those alone, at once) or the 10 s pace
    /// allows the owed seats and a scan of every seat. A seat already exiting is not asked.
    /// At most `SEED_PAGE_SEATS`.
    pub fn page_wanted(&mut self, now: u64) -> Option<Vec<SeatRef>> {
        let paging = self.paging();
        // A keyholder works one due of a group at a time, and a page is one (holder.rs
        // `on_due`): a page asked of one with a due out would drop that due (dive 3 P3)
        let dues = &self.dues;
        let free = self
            .holders
            .online(&self.vols)
            .iter()
            .any(|v| !dues.iter().any(|d| d.sid == v.sid));
        if !(paging || !self.seed_owed.is_empty()) || self.page.is_some() || !free {
            return None;
        }
        let paced = now >= self.next_page;
        if self.seed_first.is_empty() && !paced {
            return None;
        }
        let s = self.head.as_ref()?.sh.header().seed;
        let exiting = self.exits.seats();
        let behind = |x: &SeatRef| {
            paging && self.seats.get(x).is_some_and(|st| st.seed < s) && !exiting.contains(x)
        };
        // An owed seat holds the head seed (the owed go when it rises): its page is under it
        let owed =
            |x: &SeatRef| self.seats.get(x).is_some_and(|st| st.seed == s) && !exiting.contains(x);
        let first: Vec<SeatRef> = self
            .seed_first
            .iter()
            .take(SEED_PAGE_SEATS)
            .copied()
            .collect();
        let mut seats: Vec<SeatRef> = first.iter().copied().filter(|x| behind(x)).collect();
        // Seats that fetched first, then the owed, then the scan of a roll
        if paced && seats.len() < SEED_PAGE_SEATS {
            let chosen: HashSet<SeatRef> = seats.iter().copied().collect();
            let more = self
                .seed_owed
                .iter()
                .filter(|x| owed(x) && !chosen.contains(x))
                .take(SEED_PAGE_SEATS - seats.len())
                .copied()
                .collect::<Vec<_>>();
            seats.extend(more);
        }
        if paced && paging && seats.len() < SEED_PAGE_SEATS {
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
                // No seat is behind any more: the sweep after a roll that ended at its
                // 24 h is done (one on its way out keeps it going until its exit lands)
                if self.left_behind && !self.roll_runs() && !self.seats.values().any(|x| x.seed < s)
                {
                    self.left_behind = false;
                }
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
        if self.paging() && self.seats.get(&seat).is_some_and(|x| x.seed < s) {
            self.seed_first.insert(seat);
        }
    }

    /// Asks a page of the `wanted` seats the relay found keys of (`keyed`: each seat's
    /// identity key and pair) of an online keyholder, with a 60 s deadline. A seat in
    /// `gone` (its account's current seat keys make another seat, or it has none) can get
    /// no seed welcome: it exits with that cause, so the roll can finish (§5.6). An owed
    /// seat holds the head seed and holds no roll open: it is only let go (dive 3 P3).
    pub fn ask_page(
        &mut self,
        keyed: Vec<(SeatRef, [u8; 32], Pair)>,
        gone: Vec<(SeatRef, u8)>,
        now: u64,
        out: &mut Vec<Out>,
    ) {
        for (seat, why) in gone {
            if !self.seed_owed.remove(&seat) {
                self.exit(seat, why, now, out);
            }
        }
        // Not one passed over, nor the keyholder that just declined a page, nor one with a
        // due out: the page would drop it (dive 3 P3)
        let mut skip = self.passed.clone();
        skip.extend(self.page_declined.take());
        skip.extend(self.dues.iter().map(|d| d.sid));
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
            parent: head.sh.d(),
            moved: false,
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
        // One welcome per seat, the first: one store write cannot take a seat twice
        // (Postgres refuses the whole INSERT), which as the relay's failure counts no miss
        // and asks the page again, so a keyholder would hold its seats back for good (R2-3)
        let mut seen = HashSet::new();
        let took = welcomes
            .into_iter()
            .filter(|w| w.check().is_ok())
            .filter_map(|w| {
                let seat = SeatRef::from(w.seat);
                p.seats.contains(&seat).then_some((seat, w.bytes))
            })
            .filter(|(seat, _)| seen.insert(*seat))
            .collect();
        Some((p.by, took))
    }

    /// The welcomes of page `due` were not stored (the database write failed): the relay's
    /// failure, not its keyholder's, so the page goes with no miss (three in an hour propose a
    /// removal) and is asked again at once, rather than at its deadline 60 s later; while
    /// writes keep failing, once a pace, so no keyholder builds the same page in a loop.
    pub fn page_unstored(&mut self, due: u64, now: u64) {
        if self.page.take_if(|p| p.id == due).is_none() {
            return;
        }
        self.next_page = if now >= self.page_failed_at.saturating_add(SEED_PAGE_EVERY_MS) {
            now
        } else {
            now + SEED_PAGE_EVERY_MS
        };
        self.page_failed_at = now;
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
            // Its member secret under the head seed is kept now (dive 3 P3)
            self.seed_owed.remove(seat);
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

    /// The daily sweep of a memory text group: an account seat no session has held for
    /// `SEAT_EXPIRY_SECS` exits, as a stored group's does by its `last_use` (§5.4).
    pub fn expire_away(&mut self, now: u64, out: &mut Vec<Out>) {
        let held: HashSet<SeatRef> = self.members.values().filter_map(|m| m.seat).collect();
        let seats = &self.seats;
        self.away
            .retain(|s, _| seats.contains_key(s) && !held.contains(s));
        let before = now.saturating_sub(SEAT_EXPIRY_SECS * 1000);
        let gone: Vec<SeatRef> = self
            .away
            .iter()
            .filter(|(_, t)| **t <= before)
            .map(|(s, _)| *s)
            .collect();
        if gone.is_empty() {
            return;
        }
        for s in &gone {
            self.away.remove(s);
        }
        self.expire(&gone, now, out);
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
            + self.away.len() * 64
            + (self.joins.len() + self.rejoins.len() + self.conn_keys.len()) * 1400;
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
            left_behind: self.left_behind,
        })
    }

    /// Whether the actor may stop: nobody follows and nothing is out. A forced removal
    /// another entry can sign keeps it up, so it is asked as soon as one comes online (its
    /// store keeps it over a restart too, dive 4 F6).
    pub fn idle(&self) -> bool {
        let forced = &self.holders.forced;
        self.members.is_empty()
            && self.dues.is_empty()
            && self.open.is_empty()
            && self.joins.is_empty()
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
