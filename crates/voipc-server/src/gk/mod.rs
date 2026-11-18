//! The group epoch key on the relay (docs/GROUP-KEY.md, plan 2a): `Groups`, the registry of
//! every live group, each run by one tokio task (`actor`) over its `GroupState`. A group's
//! inbox is bounded by bytes, never blocking a session: past `INBOX_MAX_BYTES` fetches and
//! posts are refused `RATE`; commit parts take their own lane (their caps are the open
//! commit's). Seated fetches are answered from the published `HeadSnapshot` outside the
//! actor, plain posts checked against `HeadView`. Every multi-part sequence to a session
//! is queued whole under the group's send lock, so none interleaves with another.
//!
//! The hooks other slices call: `on_*` and `set_device`, `set_kept_seats` (R2: session.rs,
//! state.rs; K2: the accounts paths; V2: voice rooms), `past_epoch`, `rows_of`,
//! `row_makers` (K2), `stats`, `warnings` (R2's Load). Sweeps run on a task of their own
//! from `attach`.

pub mod due;
pub mod group;
pub mod holders;
pub mod names;
pub mod push;
pub mod session;
pub mod snapshot;
pub mod store;
pub mod voice;

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dashmap::{DashMap, DashSet};
use tokio::sync::{mpsc, oneshot};
use tracing::warn;
use voipc_crypto::group_key::commit::{Joiner, Pair, ReplaceAsk};
use voipc_crypto::group_key::timers::{
    ACTOR_IDLE_MS, INBOX_MAX_BYTES, MATERIAL_SWEEP_MS, OPEN_PER_CONN_BYTES, SEAT_EXPIRY_SECS,
};
use voipc_crypto::group_key::{seat_record, GroupKind, SeatRef};
use voipc_protocol::gk::{
    refused_what, refused_why, CommitPiece, EpochRef, FloorRef, GkWriter, HeaderIn, NamesRef,
    RowMaker,
};
use voipc_protocol::messages::ServerMessage;
use voipc_protocol::types::{ChannelId, GroupLoad, UserId};

use crate::control::ControlTx;
use group::{Fetch, Fetched, GroupState, OpenCaps, Out};
use holders::Volunteer;
use snapshot::{header_in, HeadSnapshot, HeadView};
use store::{DbStore, Fail, Store};

/// A message's charge to the inbox when it carries nothing large.
const SMALL: usize = 256;

/// The relay's clock for the group key, unix ms: the wall clock at start plus tokio's
/// monotonic time since (paused in tests).
#[derive(Clone, Copy)]
pub struct Clock {
    unix0: u64,
    t0: tokio::time::Instant,
}

impl Clock {
    fn new() -> Clock {
        Clock {
            unix0: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_millis() as u64),
            t0: tokio::time::Instant::now(),
        }
    }

    pub fn now(&self) -> u64 {
        self.unix0 + self.t0.elapsed().as_millis() as u64
    }

    fn at(&self, ms: u64) -> tokio::time::Instant {
        self.t0 + Duration::from_millis(ms.saturating_sub(self.unix0))
    }
}

/// What an actor is asked.
enum Msg {
    Follow {
        sid: UserId,
        account: Option<[u8; 16]>,
    },
    Leave {
        sid: UserId,
        cause: u8,
    },
    AccountExit {
        account: [u8; 16],
        cause: u8,
    },
    Eager {
        joiner: Joiner,
        account: [u8; 16],
    },
    Volunteer {
        sid: UserId,
        v: Option<Volunteer>,
        device: Option<Vec<u8>>,
    },
    Fetch {
        sid: UserId,
        f: Fetch,
    },
    Commit {
        sid: UserId,
        due: u64,
        part: u16,
        last: bool,
        piece: CommitPiece,
        bytes: usize,
    },
    Decline {
        sid: UserId,
        due: u64,
        why: u8,
    },
    Resign {
        sid: UserId,
        entry: Option<[u8; 32]>,
    },
    Replace {
        sid: UserId,
        ask: ReplaceAsk,
    },
    Lists {
        sid: UserId,
        gen: [u8; 16],
        versions: Vec<(u64, u64)>,
    },
    Keyring {
        sid: UserId,
        gen: [u8; 16],
        have: Option<(u32, u32)>,
    },
    PostBlob {
        sid: UserId,
        gen: [u8; 16],
        epoch: u32,
        blob: Vec<u8>,
        reply: oneshot::Sender<Result<(), u8>>,
    },
    Blobs {
        sid: UserId,
        gen: [u8; 16],
        epoch: u32,
        writer: GkWriter,
    },
    Names {
        sid: UserId,
        from: NamesRef,
        to: NamesRef,
        removals: bool,
    },
    FloorAhead {
        sid: UserId,
        header: HeaderIn,
    },
    Gate {
        gated: bool,
    },
    /// A seed-welcome page's welcomes (`EpochWelcomes`).
    Welcomes {
        sid: UserId,
        due: u64,
        gen: [u8; 16],
        seed: u32,
        welcomes: Vec<voipc_protocol::gk::SeedWelcomeOut>,
        /// What the commit lane carries for it.
        bytes: usize,
    },
    /// A seat behind a running roll fetched: first in the next page.
    SeedWanted {
        seat: SeatRef,
    },
    /// An account's newest seat-key counter, since when (unix ms).
    Counter {
        account: [u8; 16],
        n: u32,
        since: u64,
    },
    DeviceRemoved {
        account: [u8; 16],
        device: Vec<u8>,
    },
    /// Eager seats a page at a time, read off the actor.
    EagerMany(Vec<([u8; 16], Joiner)>),
    /// The 10-minute sweep (orphans), and the daily one (names).
    Sweep {
        daily: bool,
    },
    /// Seats unused for 90 days.
    Expire(Vec<SeatRef>),
    /// An account's seat keys rotated: its seats other than `keep` exit (a memory group's;
    /// a stored group's go by `AccountExit`).
    Rotated {
        account: [u8; 16],
        keep: SeatRef,
    },
}

/// A live group: its inbox, what is read outside its actor, its send lock.
pub struct Handle {
    pub id: String,
    pub kind: GroupKind,
    tx: mpsc::UnboundedSender<(Msg, usize)>,
    inbox: AtomicUsize,
    head: RwLock<Option<HeadView>>,
    snap: RwLock<Option<Arc<HeadSnapshot>>>,
    /// Sessions seated at the snapshot's head, with their seat.
    seated: DashMap<UserId, SeatRef>,
    /// Online keyholders' sessions.
    keyholders: DashSet<UserId>,
    /// Sessions with a due out: only their commit parts take the lane.
    asked: DashSet<UserId>,
    /// The `kh` header last sent to each session, by digest: sent again whenever a fetch's
    /// floor names another (a vault floor another device raised), never used up by an answer
    /// that carried none (1c).
    kh_sent: DashMap<UserId, [u8; 32]>,
    /// Sessions whose answers were built with their seat's keying: the first answer to a
    /// connection always is, since a new connection holds no `BK` whatever its floor (a
    /// restart, a second device of the account), then only when the version moved.
    keyed: DashSet<UserId>,
    /// One sequence at a time to this group's sessions (part 13).
    send: Mutex<()>,
    /// Told when the group is retired (its id moved, its conversation purged).
    stop: tokio::sync::Notify,
    store: Arc<Store>,
    stats: Mutex<GroupLoad>,
    /// The admin warnings its actor raised last (plan 2j).
    warnings: Mutex<Vec<String>>,
}

type Inbox = mpsc::UnboundedReceiver<(Msg, usize)>;

impl Handle {
    fn new(
        id: &str,
        kind: GroupKind,
        channel: ChannelId,
        store: Arc<Store>,
    ) -> (Arc<Handle>, Inbox) {
        let (tx, rx) = mpsc::unbounded_channel();
        let h = Arc::new(Handle {
            id: id.to_string(),
            kind,
            tx,
            inbox: AtomicUsize::new(0),
            head: RwLock::default(),
            snap: RwLock::default(),
            seated: DashMap::new(),
            keyholders: DashSet::new(),
            asked: DashSet::new(),
            kh_sent: DashMap::new(),
            keyed: DashSet::new(),
            send: Mutex::new(()),
            stop: tokio::sync::Notify::new(),
            store,
            stats: Mutex::new(GroupLoad {
                channel_id: channel,
                kind: match kind {
                    GroupKind::Text => voipc_protocol::gk::group_kind::TEXT,
                    GroupKind::Voice => voipc_protocol::gk::group_kind::VOICE,
                },
                ..GroupLoad::default()
            }),
            warnings: Mutex::default(),
        });
        (h, rx)
    }
}

/// The live group `id`, its actor started if it was not (a stored group whose channel
/// moved back to it starts a new generation), knowing its channel's gate from its first
/// due. A group a sweep or an account hook started takes its channel, and that channel's
/// gate, from the first hook that names one: no due goes before a follow, which names it.
/// So does a group another channel named before (a deleted one whose conversation came
/// back in a new channel).
fn start(shared: &Arc<Shared>, id: &str, kind: GroupKind, channel: ChannelId) -> Arc<Handle> {
    use dashmap::mapref::entry::Entry;
    let e = match shared.map.entry(id.to_string()) {
        Entry::Occupied(e) => {
            let h = e.get().clone();
            let mut s = h.stats.lock().unwrap_or_else(|e| e.into_inner());
            if channel != 0 && s.channel_id != channel {
                s.channel_id = channel;
                let gated = shared.gated.contains(&channel);
                let _ = h.tx.send((Msg::Gate { gated }, 0));
            }
            drop(s);
            return h;
        }
        Entry::Vacant(e) => e,
    };
    let store = match (id.starts_with("c:"), shared.db.get()) {
        (true, Some(db)) => Store::Db(db.clone()),
        _ => Store::memory(),
    };
    let (h, rx) = Handle::new(id, kind, channel, Arc::new(store));
    e.insert(h.clone());
    let mut g = GroupState::new(id.to_string(), kind, h.store.stored(), shared.caps.clone());
    g.new_gen = shared.moved_back.remove(id).is_some();
    g.kept_seats = shared.kept_seats.load(Ordering::Relaxed);
    g.gate = shared.gated.contains(&channel);
    tokio::spawn(actor(shared.clone(), h.clone(), rx, g));
    h
}

/// A seat used: its generation and record.
type Used = ([u8; 16], [u8; 33]);

/// What the actors share with the registry.
pub struct Shared {
    clock: Clock,
    conns: DashMap<UserId, ControlTx>,
    caps: Arc<OpenCaps>,
    /// Commit parts queued on the lanes, bytes per connection (≤ 12 MB, 1e).
    lane: DashMap<UserId, usize>,
    db: OnceLock<Arc<DbStore>>,
    map: DashMap<String, Arc<Handle>>,
    /// The account of each signed-in session this relay's groups met: `EpochReseated` goes
    /// to them.
    accounts: DashMap<UserId, [u8; 16]>,
    /// Rotations not yet re-seated everywhere, per account (2d "Rotation").
    reseat: DashMap<[u8; 16], Reseat>,
    /// Seats used (a fetch answered, a post) since the daily write of `last_use`, per
    /// stored group: `(gen, seat record)`.
    used: DashMap<String, HashSet<Used>>,
    /// The device each session signed in with, where it named one (`set_device`).
    devices: DashMap<UserId, Vec<u8>>,
    /// Eager seats queued at most per group (`[accounts] kept_seats`).
    kept_seats: AtomicUsize,
    /// Each stored group's bytes in the database, as the last sweep counted them.
    db_bytes: DashMap<String, u64>,
    /// Stored groups whose channel moved back to them: a new generation at their start.
    moved_back: DashSet<String>,
    /// The channels whose gate is on, as `on_gate` last told: a group's start reads its own.
    gated: DashSet<ChannelId>,
}

/// A rotation's progress: counter `n`, the new seat, the groups still to seat it.
pub struct Reseat {
    pub n: u32,
    pub seat: SeatRef,
    pub left: HashSet<String>,
}

impl Shared {
    /// `EpochReseated{n, left}` to every session of `account`.
    fn reseated(&self, account: &[u8; 16], n: u32, left: u32) {
        let msg = ServerMessage::EpochReseated { n, left };
        for e in self.accounts.iter().filter(|e| e.value() == account) {
            if let Some(tx) = self.conns.get(e.key()) {
                let _ = crate::session::send_msg(&tx, &msg);
            }
        }
    }

    /// `seat` is seated in group `id`, or can no longer be: a rotation waiting on it moves.
    fn reseat_done(&self, id: &str, seat: &SeatRef) {
        let Some(account) = seat.m.account() else {
            return;
        };
        let left = self
            .reseat
            .get_mut(&account)
            .and_then(|mut r| (r.seat == *seat && r.left.remove(id)).then(|| (r.n, r.left.len())));
        if let Some((n, left)) = left {
            if left == 0 {
                self.reseat.remove_if(&account, |_, r| r.left.is_empty());
            }
            self.reseated(&account, n, left as u32);
        }
    }
}

impl Shared {
    /// Charges `bytes` of commit parts to `sid`'s lane; `false` past its cap.
    fn lane_take(&self, sid: UserId, bytes: usize) -> bool {
        let mut q = self.lane.entry(sid).or_default();
        if *q + bytes > OPEN_PER_CONN_BYTES {
            return false;
        }
        *q += bytes;
        true
    }

    fn lane_free(&self, sid: UserId, bytes: usize) {
        if let Some(mut q) = self.lane.get_mut(&sid) {
            *q = q.saturating_sub(bytes);
        }
        self.lane.remove_if(&sid, |_, q| *q == 0);
    }
}

/// Every group with a key on this relay.
pub struct Groups {
    /// `group_key` in server.toml, read at start.
    pub on: bool,
    /// 16 random bytes per start: the run in every `r:<run>:<channel id>` group id.
    pub run: [u8; 16],
    shared: Arc<Shared>,
    by_channel: DashMap<ChannelId, String>,
    follows: DashMap<UserId, HashSet<String>>,
    vols: DashMap<UserId, Volunteer>,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A stored conversation's group id: the conversation id itself, which `log_conv` makes
/// `c:<…>` (spec §11.1; the app's `group_id` takes the log id as it is). A bare name is put
/// under `c:`.
fn stored_id(conv: &str) -> String {
    if conv.starts_with("c:") {
        conv.to_string()
    } else {
        format!("c:{conv}")
    }
}

impl Groups {
    pub fn new(on: bool) -> Groups {
        Groups {
            on,
            run: rand::random(),
            shared: Arc::new(Shared {
                clock: Clock::new(),
                conns: DashMap::new(),
                caps: Arc::default(),
                lane: DashMap::new(),
                db: OnceLock::new(),
                map: DashMap::new(),
                accounts: DashMap::new(),
                reseat: DashMap::new(),
                used: DashMap::new(),
                devices: DashMap::new(),
                kept_seats: AtomicUsize::new(group::KEPT_SEATS),
                db_bytes: DashMap::new(),
                moved_back: DashSet::new(),
                gated: DashSet::new(),
            }),
            by_channel: DashMap::new(),
            follows: DashMap::new(),
            vols: DashMap::new(),
        }
    }

    /// The frame right after `Authenticated` (plan 1f.8): which paths this relay uses.
    pub fn hello(&self) -> ServerMessage {
        ServerMessage::GroupKeys {
            on: self.on,
            run: self.run,
            clock: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
        }
    }

    /// The accounts database and its `gk_incarnation` (`accounts::gk::gk_start`): from
    /// here `c:` groups are stored, and swept every 10 minutes and daily by a task of their
    /// own (plan 2e). Without it every group is in memory (2h). With the switch off the
    /// relay attaches it too (any incarnation): kept reads are served read-only (1h).
    pub fn attach(&self, db: l4f_accounts::store::Store, incarnation: [u8; 16]) {
        if self
            .shared
            .db
            .set(Arc::new(DbStore { db, incarnation }))
            .is_ok()
            && self.on
        {
            if let Ok(rt) = tokio::runtime::Handle::try_current() {
                rt.spawn(sweeper(Arc::downgrade(&self.shared)));
            }
        }
    }

    /// Whether `attach` ran: the relay's own process, not a shell command's.
    pub fn attached(&self) -> bool {
        self.shared.db.get().is_some()
    }

    /// `[accounts] kept_seats`: eager seats queued at most per group (default 5000); 0 is
    /// no limit there, as the logs it caps take it.
    pub fn set_kept_seats(&self, n: u32) {
        let n = if n == 0 { usize::MAX } else { n as usize };
        self.shared.kept_seats.store(n, Ordering::Relaxed);
    }

    pub fn now(&self) -> u64 {
        self.shared.clock.now()
    }

    /// A channel's group id: `c:<conv>` for a stored conversation on a relay with
    /// accounts, else `r:<run>:<channel id>` (§11.1).
    pub fn id_for(&self, channel: ChannelId, stored_conv: Option<&str>) -> String {
        match (stored_conv, self.shared.db.get()) {
            (Some(conv), Some(_)) => stored_id(conv),
            _ => format!("r:{}:{channel}", hex(&self.run)),
        }
    }

    pub(crate) fn get(&self, id: &str) -> Option<Arc<Handle>> {
        self.shared.map.get(id).map(|h| h.clone())
    }

    /// The live group `id`, its actor started if it was not.
    fn live(&self, id: &str, kind: GroupKind, channel: ChannelId) -> Arc<Handle> {
        start(&self.shared, id, kind, channel)
    }

    /// Queues `msg` for group `id`'s actor; `false` when its inbox is full (`RATE`).
    fn post(&self, id: &str, msg: Msg, bytes: usize, lane: bool) -> bool {
        let Some(h) = self.get(id) else {
            return false;
        };
        if !lane && h.inbox.load(Ordering::Relaxed) + bytes > INBOX_MAX_BYTES {
            return false;
        }
        let charge = if lane { 0 } else { bytes };
        h.inbox.fetch_add(charge, Ordering::Relaxed);
        if h.tx.send((msg, charge)).is_err() {
            h.inbox.fetch_sub(charge, Ordering::Relaxed);
            return false;
        }
        true
    }

    fn send_now(&self, sid: UserId, msg: ServerMessage) {
        if let Some(tx) = self.shared.conns.get(&sid) {
            let _ = crate::session::send_msg(&tx, &msg);
        }
    }

    fn refuse(&self, sid: UserId, group: &str, what: u8, why: u8) {
        self.send_now(
            sid,
            ServerMessage::EpochRefused {
                group: group.to_string(),
                what,
                why,
                detail: String::new(),
            },
        );
    }

    // ── Hooks (R2: session.rs and state.rs) ──────────────────────────────

    /// A session's control queue, for what its groups send it.
    pub fn on_connect(&self, sid: UserId, tx: ControlTx) {
        self.shared.conns.insert(sid, tx);
    }

    /// A session follows a text channel (or joins a room, V2): it may fetch its group.
    pub fn on_follow(
        &self,
        channel: ChannelId,
        group: &str,
        kind: GroupKind,
        sid: UserId,
        account: Option<[u8; 16]>,
    ) {
        if !self.on {
            return;
        }
        self.by_channel.insert(channel, group.to_string());
        if let Some(a) = account {
            self.shared.accounts.insert(sid, a);
        }
        let _ = self.live(group, kind, channel);
        self.follows
            .entry(sid)
            .or_default()
            .insert(group.to_string());
        self.post(group, Msg::Follow { sid, account }, 0, true);
        if let Some(v) = self.vols.get(&sid).map(|v| v.clone()) {
            let device = self.shared.devices.get(&sid).map(|d| d.clone());
            let msg = Msg::Volunteer {
                sid,
                v: Some(v),
                device,
            };
            self.post(group, msg, 0, true);
        }
    }

    /// Whether the channel's gate is on, as `on_gate` last told.
    pub fn gated(&self, channel: ChannelId) -> bool {
        self.shared.gated.contains(&channel)
    }

    /// The device a session signed in with (a device-key sign-in): the keyholder entries it
    /// makes are that device's, so removing the device from its account removes them.
    pub fn set_device(&self, sid: UserId, device: Vec<u8>) {
        self.shared.devices.insert(sid, device);
    }

    fn leave_channel(&self, channel: ChannelId, sid: UserId, cause: u8) {
        let Some(id) = self.by_channel.get(&channel).map(|g| g.clone()) else {
            return;
        };
        if let Some(mut f) = self.follows.get_mut(&sid) {
            f.remove(&id);
        }
        self.post(&id, Msg::Leave { sid, cause }, 0, true);
    }

    pub fn on_unfollow(&self, channel: ChannelId, sid: UserId) {
        self.leave_channel(channel, sid, group::cause::LEAVE);
    }

    /// A kick, voice kick or eject from `channel`, with its `cause`.
    pub fn on_kick(&self, channel: ChannelId, sid: UserId, cause: u8) {
        self.leave_channel(channel, sid, cause);
    }

    /// The connection ended: it leaves every group, its volunteering ends.
    pub fn on_session_end(&self, sid: UserId) {
        self.vols.remove(&sid);
        self.shared.devices.remove(&sid);
        if let Some((_, groups)) = self.follows.remove(&sid) {
            for id in groups {
                self.post(
                    &id,
                    Msg::Leave {
                        sid,
                        cause: group::cause::DISCONNECT,
                    },
                    0,
                    true,
                );
            }
        }
        // Its open commits are let go by each group's `Leave`
        self.shared.conns.remove(&sid);
        self.shared.accounts.remove(&sid);
        self.shared.lane.remove(&sid);
    }

    /// The channel's gate turned on or off (or went with its channel): kept for the group's
    /// next start, and told to the live one.
    pub fn on_gate(&self, channel: ChannelId, gated: bool) {
        if gated {
            self.shared.gated.insert(channel);
        } else {
            self.shared.gated.remove(&channel);
        }
        if let Some(id) = self.by_channel.get(&channel).map(|g| g.clone()) {
            self.post(&id, Msg::Gate { gated }, 0, true);
        }
    }

    /// The channel's group id moved (anonymous or `hide_members` flip, `refresh_log`):
    /// the old group stops (an `r:` one is gone, a `c:` one is frozen in its store); the
    /// new one starts with no keyring; back to a stored `c:` group, a new generation.
    /// Followers follow again under the new id.
    pub fn on_group_moved(&self, channel: ChannelId, old: &str, new: &str) {
        self.retire(old);
        self.by_channel.insert(channel, new.to_string());
        for mut f in self.follows.iter_mut() {
            f.remove(old);
        }
        if new.starts_with("c:") {
            self.shared.moved_back.insert(new.to_string());
        }
    }

    /// The channel is deleted: its group stops as a moved one does, and the channel names
    /// it no more and keeps no gate, so a hook that starts the group again (its rows outlive
    /// the channel) takes no channel that is gone.
    pub fn on_channel_gone(&self, channel: ChannelId, id: &str) {
        self.on_group_moved(channel, id, id);
        self.by_channel.remove(&channel);
        self.shared.gated.remove(&channel);
    }

    /// A conversation is purged: its group stops (K2 deletes its rows in batches).
    pub fn on_purge(&self, conv: &str) {
        self.retire(&stored_id(conv));
    }

    /// Stops group `id`'s actor; what a memory group held is gone with it.
    fn retire(&self, id: &str) {
        if let Some((_, h)) = self.shared.map.remove(id) {
            h.stop.notify_one();
        }
    }

    // ── Hooks (K2: the accounts paths) ───────────────────────────────────
    //
    // With the switch off each returns at once: the database is attached for kept reads
    // alone (1h), so no group starts and no gk table is written.

    /// An account that keeps a channel's history is seated eagerly in its stored group
    /// (plan 2d), with its published seat keys. `ik`: its identity key, raw.
    pub async fn on_log_join(&self, conv: &str, account: [u8; 16], ik: [u8; 32]) {
        if !self.on {
            return;
        }
        let id = stored_id(conv);
        let Some(joiner) = self.account_joiner(account, ik).await else {
            return;
        };
        let channel = self.channel_of(&id);
        let _ = self.live(&id, GroupKind::Text, channel);
        self.post(&id, Msg::Eager { joiner, account }, 0, true);
    }

    /// Every seat of `account` in a stored conversation's group exits.
    pub fn on_log_leave(&self, conv: &str, account: [u8; 16], cause: u8) {
        if !self.on {
            return;
        }
        let id = stored_id(conv);
        let channel = self.channel_of(&id);
        let _ = self.live(&id, GroupKind::Text, channel);
        self.post(&id, Msg::AccountExit { account, cause }, 0, true);
    }

    /// A ban, identity reset or account deletion: its seats exit everywhere, online or not,
    /// and its keyholder entries go (each group it sits in or holds keys of).
    pub async fn on_account_gone(&self, account: [u8; 16], cause: u8) {
        if !self.on {
            return;
        }
        // Its sessions from before a reset volunteer no more, in no group they follow later
        // (`GroupState::account_exit`)
        if cause == group::cause::RESET {
            self.vols
                .retain(|_, v| v.m != voipc_crypto::group_key::MemberId::Account(account));
        }
        let mut ids: HashSet<String> = self.shared.map.iter().map(|h| h.key().clone()).collect();
        if let Some(db) = self.shared.db.get() {
            if let Ok(seats) = crate::accounts::gk::seats_of_account(&db.db, &account).await {
                ids.extend(seats.into_iter().map(|(grp, _, _)| grp));
            }
            let m = voipc_crypto::group_key::MemberId::Account(account).seat_id();
            if let Ok(rows) = crate::accounts::gk::holders_of(&db.db, &m, None).await {
                ids.extend(rows.into_iter().map(|(grp, _)| grp));
            }
        }
        for id in ids {
            let channel = self.channel_of(&id);
            let _ = self.live(&id, store_kind(&id), channel);
            self.post(&id, Msg::AccountExit { account, cause }, 0, true);
        }
    }

    /// A seat-key rotation (`SeatKeysPublish` with a higher `n`): in each group where an
    /// old seat of the account sits, it exits and the new seat is queued eagerly.
    pub async fn on_seat_keys(&self, account: [u8; 16], pair: Pair, ik: [u8; 32]) {
        let Some(db) = self.shared.db.get().filter(|_| self.on) else {
            return;
        };
        let Ok(seats) = crate::accounts::gk::seats_of_account(&db.db, &account).await else {
            return;
        };
        let new = pair
            .keys
            .seat(voipc_crypto::group_key::MemberId::Account(account));
        let joiner = Joiner {
            seat: new,
            ik,
            keys: pair.keys,
            endorsement: pair.endorsement,
            returning: false,
        };
        let groups: HashSet<String> = seats
            .iter()
            .filter(|(_, _, s)| s.seat != seat_record(&new))
            .map(|(grp, _, _)| grp.clone())
            .collect();
        // `EpochReseated{n, left}` as each group seats the new seat, `left = 0` at the end
        // (at once with none): the device drops its old seat keys then, not after 7 days
        let n = joiner.endorsement.n;
        if groups.is_empty() {
            self.shared.reseat.remove(&account);
            self.shared.reseated(&account, n, 0);
        } else {
            self.shared.reseat.insert(
                account,
                Reseat {
                    n,
                    seat: new,
                    left: groups.clone(),
                },
            );
            self.shared.reseated(&account, n, groups.len() as u32);
        }
        // A live memory group's old seat exits too (plan 2d "Rotation": in each group where
        // the old seat sits), so no seat sits whose keys no seed welcome can reach
        for h in self.shared.map.iter() {
            if h.kind == GroupKind::Text && !h.store.stored() {
                let _ = h.tx.send((Msg::Rotated { account, keep: new }, 0));
            }
        }
        for id in &groups {
            let channel = self.channel_of(id);
            let _ = self.live(id, GroupKind::Text, channel);
            self.post(
                id,
                Msg::AccountExit {
                    account,
                    cause: group::cause::ROTATION,
                },
                0,
                true,
            );
            self.post(
                id,
                Msg::Eager {
                    joiner: joiner.clone(),
                    account,
                },
                0,
                true,
            );
        }
        // Its keyholder entries are measured against this counter from now (removal after
        // seven days below it, plan 2d): every live group, and each stored one it holds keys of
        let since = self.now();
        let mut kh: HashSet<String> = self.shared.map.iter().map(|h| h.key().clone()).collect();
        let m = voipc_crypto::group_key::MemberId::Account(account).seat_id();
        if let Ok(rows) = crate::accounts::gk::holders_of(&db.db, &m, None).await {
            kh.extend(rows.into_iter().map(|(grp, _)| grp));
        }
        for id in kh {
            let channel = self.channel_of(&id);
            let _ = self.live(&id, store_kind(&id), channel);
            self.post(&id, Msg::Counter { account, n, since }, 0, true);
        }
        // Eager seats in every stored group of its conversations it has no seat in (plan 2d:
        // an account's first `SeatKeysPublish`), a page of conversations at a time
        let seated: HashSet<String> = seats.iter().map(|(grp, _, _)| grp.clone()).collect();
        let mut after: Option<String> = None;
        loop {
            let page =
                match store::member_convs(&db.db, &account, after.as_deref(), EAGER_PAGE).await {
                    Ok(p) => p,
                    Err(e) => {
                        warn!("reading an account's conversations failed: {e}");
                        break;
                    }
                };
            let n_page = page.len();
            for conv in page {
                let id = stored_id(&conv);
                after = Some(conv);
                if seated.contains(&id) || groups.contains(&id) {
                    continue;
                }
                let stored = self.get(&id).is_some()
                    || crate::accounts::gk::group(&db.db, &id)
                        .await
                        .is_ok_and(|g| g.is_some());
                if !stored {
                    continue;
                }
                let channel = self.channel_of(&id);
                let _ = self.live(&id, GroupKind::Text, channel);
                self.post(
                    &id,
                    Msg::Eager {
                        joiner: joiner.clone(),
                        account,
                    },
                    0,
                    true,
                );
            }
            if n_page < EAGER_PAGE as usize {
                break;
            }
        }
    }

    /// A device removed from `account` (`DeviceForget`): the keyholder entries it made are
    /// proposed for removal (plan 2d), in every live group and each stored group where the
    /// database names that device for one.
    pub async fn on_device_removed(&self, account: [u8; 16], device: &[u8]) {
        if !self.on {
            return;
        }
        let mut ids: HashSet<String> = self.shared.map.iter().map(|h| h.key().clone()).collect();
        if let Some(db) = self.shared.db.get() {
            let m = voipc_crypto::group_key::MemberId::Account(account).seat_id();
            if let Ok(rows) = crate::accounts::gk::holders_of(&db.db, &m, Some(device)).await {
                ids.extend(rows.into_iter().map(|(grp, _)| grp));
            }
        }
        for id in ids {
            let channel = self.channel_of(&id);
            let _ = self.live(&id, store_kind(&id), channel);
            let msg = Msg::DeviceRemoved {
                account,
                device: device.to_vec(),
            };
            self.post(&id, msg, 0, true);
        }
    }

    fn channel_of(&self, id: &str) -> ChannelId {
        self.by_channel
            .iter()
            .find(|e| e.value() == id)
            .map_or(0, |e| *e.key())
    }

    async fn account_joiner(&self, account: [u8; 16], ik: [u8; 32]) -> Option<Joiner> {
        let pair = self.account_pair(account).await?;
        Some(Joiner {
            seat: pair
                .keys
                .seat(voipc_crypto::group_key::MemberId::Account(account)),
            ik,
            keys: pair.keys,
            endorsement: pair.endorsement,
            returning: false,
        })
    }

    /// An account's published seat keys (origin 0x01), as a pair.
    pub async fn account_pair(&self, account: [u8; 16]) -> Option<Pair> {
        let db = self.shared.db.get()?;
        let k = crate::accounts::gk::seat_keys(&db.db, &account)
            .await
            .ok()??;
        let wire = voipc_protocol::gk::EndorsedPair {
            origin: voipc_protocol::gk::origin::VAULT_SEAT,
            u: 0,
            kem: k.kem,
            dh: k.dh,
            n: k.n,
            made: k.made,
            sig: k.sig,
        };
        voipc_crypto::group_key::wire::pair(&wire, voipc_protocol::gk::GkMember::Account(account))
            .ok()
    }

    // ── What other slices read ───────────────────────────────────────────

    /// The keyholders that made live rows to `seat` (C4 `RowMakers`).
    pub async fn row_makers(&self, group: &str, gen: &[u8; 16], seat: &SeatRef) -> Vec<RowMaker> {
        let Some(db) = self.shared.db.get() else {
            return vec![];
        };
        let rows = crate::accounts::gk::rows_of_seat(&db.db, group, gen, &seat_record(seat))
            .await
            .unwrap_or_default();
        rows.into_iter()
            .filter_map(|r| {
                let mut m = [0u8; 49];
                m.copy_from_slice(&r.maker);
                Some(RowMaker {
                    from: maker_ref(&m)?.into(),
                    s: r.s,
                    b: r.b,
                    v: r.v,
                })
            })
            .collect()
    }

    /// One row per live group, for `AdminLoad` (R2 picks which to show, 2j): `mem_bytes`
    /// as its actor last counted, `db_bytes` as the last sweep did (stored groups).
    pub fn stats(&self) -> Vec<GroupLoad> {
        self.shared
            .map
            .iter()
            .map(|h| {
                let mut s = h.stats.lock().unwrap_or_else(|e| e.into_inner()).clone();
                s.db_bytes = self.shared.db_bytes.get(h.key()).map_or(0, |b| *b);
                s
            })
            .collect()
    }

    /// The admin warnings of the live groups (plan 2j): each kind at most once in 10
    /// minutes, logged at warn when raised, as `(channel, "#<channel id>: <what>")`. R2's
    /// Load lists them with its warnings and shows the groups they name.
    pub fn warnings(&self) -> Vec<(ChannelId, String)> {
        let mut out = vec![];
        for h in self.shared.map.iter() {
            let channel = h.stats.lock().unwrap_or_else(|e| e.into_inner()).channel_id;
            for w in h.warnings.lock().unwrap_or_else(|e| e.into_inner()).iter() {
                out.push((channel, format!("#{channel}: {w}")));
            }
        }
        out
    }

    /// One `at` entry's answer for member `m` of stored group `group` (C4, plan 2d), from
    /// the database: `None` when it is not to be had (an `r:` group, material swept, no seat
    /// of `m` then). `have`: the member's floor, whose `kh` the keyholder links lead back
    /// from.
    pub async fn past_epoch(
        &self,
        group: &str,
        m: voipc_crypto::group_key::MemberId,
        at: EpochRef,
        have: Option<&FloorRef>,
    ) -> Option<voipc_protocol::gk::InPiece> {
        if !group.starts_with("c:") {
            return None;
        }
        let db = self.shared.db.get()?;
        let anchor = have.filter(|f| f.gen == at.gen).map(|f| f.kh);
        match store::past(&db.db, group, m, at, anchor).await {
            Ok(p) => p,
            Err(e) => {
                warn!(group, "reading a past epoch failed: {e}");
                None
            }
        }
    }

    /// An account's self-rows and history rows (`SelfRowsList`, §3.11), every group,
    /// generation and seed: at most `limit` (≤ 256) after `after`, the `next` of the page
    /// before; with the next page's `after` while more remain.
    pub async fn rows_of(
        &self,
        account: [u8; 16],
        after: Option<&[u8]>,
        limit: u16,
    ) -> (Vec<voipc_protocol::gk::SelfRowIn>, Option<Vec<u8>>) {
        let Some(db) = self.shared.db.get() else {
            return (vec![], None);
        };
        store::rows_of(&db.db, &account, after, limit.min(256))
            .await
            .unwrap_or_else(|e| {
                warn!("reading an account's self-rows failed: {e}");
                (vec![], None)
            })
    }

    /// Whether a post under `(gen, epoch)` of `group` may go out now (rule 1f.1).
    pub fn post_ok(&self, group: &str, gen: &[u8; 16], epoch: u32) -> bool {
        self.get(group).is_some_and(|h| {
            h.head
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .is_some_and(|v| v.post_ok(gen, epoch, self.now()))
        })
    }
}

fn maker_ref(m: &[u8; 49]) -> Option<voipc_crypto::group_key::commit::HolderRef> {
    let rec: [u8; 33] = {
        let mut r = [0u8; 33];
        r[..17].copy_from_slice(&m[..17]);
        r
    };
    Some(voipc_crypto::group_key::commit::HolderRef {
        m: store::seat_of(&rec)?.m,
        kx: m[17..].try_into().ok()?,
    })
}

fn store_kind(id: &str) -> GroupKind {
    if id.starts_with("c:") {
        GroupKind::Text
    } else {
        GroupKind::Voice
    }
}

// ── The actor ─────────────────────────────────────────────────────────────

/// Queues each session's frames whole, under the group's send lock; a failed send stops
/// that sequence (1e). `false` when one did not go whole.
fn deliver(shared: &Shared, h: &Handle, out: Vec<Out>) -> bool {
    if out.is_empty() {
        return true;
    }
    let _one = h.send.lock().unwrap_or_else(|e| e.into_inner());
    queue_all(shared, out)
}

/// One answer built from `snap`, queued whole unless the snapshot moved meanwhile (`None`):
/// the actor publishes a new one before it queues the new header's pushes, so an answer
/// from the old one is never queued after them (a member would take the push, then meet
/// the old head below its floor).
fn deliver_from(shared: &Shared, h: &Handle, snap: &Arc<HeadSnapshot>, out: Out) -> Option<bool> {
    let _one = h.send.lock().unwrap_or_else(|e| e.into_inner());
    let now = h.snap.read().unwrap_or_else(|e| e.into_inner()).clone();
    if !now.is_some_and(|x| Arc::ptr_eq(&x, snap)) {
        return None;
    }
    Some(queue_all(shared, vec![out]))
}

/// Under the send lock: each session's frames in order, a failed send ending its sequence.
fn queue_all(shared: &Shared, out: Vec<Out>) -> bool {
    let mut whole = true;
    for Out(sid, frames) in out {
        let Some(tx) = shared.conns.get(&sid).map(|t| t.clone()) else {
            whole = false;
            continue;
        };
        for f in &frames {
            if crate::session::send_msg(&tx, f).is_err() {
                whole = false;
                break;
            }
        }
    }
    whole
}

/// Publishes the snapshot fetches outside the actor are answered from, who is seated and
/// who holds keys: before the actor queues a new head's pushes, so no answer from the old
/// snapshot follows them (`deliver_from`).
fn publish_snap(h: &Handle, g: &GroupState) {
    let snap = g.snapshot().map(Arc::new);
    *h.snap.write().unwrap_or_else(|e| e.into_inner()) = snap;
    h.seated.clear();
    for (sid, seat) in g.seated_sids() {
        h.seated.insert(sid, seat);
    }
    h.keyholders.clear();
    for v in g.holders.online(&g.vols) {
        h.keyholders.insert(v.sid);
    }
}

/// Publishes the Load row, and the head view last, after the pushes were queued (1f.4).
fn publish(h: &Handle, g: &GroupState, now: u64) {
    {
        let mut s = h.stats.lock().unwrap_or_else(|e| e.into_inner());
        s.seats = g.seats.len() as u32;
        s.keyholders = g.holders.set.len() as u32;
        s.keyholders_online = h.keyholders.len() as u32;
        s.last_commit_secs = if g.last_commit == 0 {
            0
        } else {
            (now.saturating_sub(g.last_commit) / 1000) as u32
        };
        s.joins_waiting = g.joins.queue.len() as u32;
        s.exits_waiting = g.exits.waiting() as u32;
        s.missed_deadlines = g.missed_total;
        s.mem_bytes = g.mem_bytes() + h.store.mem_bytes();
    }
    *h.warnings.lock().unwrap_or_else(|e| e.into_inner()) = g.warnings(now);
    *h.head.write().unwrap_or_else(|e| e.into_inner()) = g.head_view();
}

/// One session's entries in what is read outside the actor.
fn touch(h: &Handle, g: &GroupState, sid: UserId) {
    match g
        .members
        .get(&sid)
        .and_then(|m| m.seat)
        .filter(|s| g.seats.contains_key(s))
    {
        Some(seat) if g.head.is_some() && !g.new_gen => {
            h.seated.insert(sid, seat);
        }
        _ => {
            h.seated.remove(&sid);
        }
    }
    if g.is_keyholder(sid) {
        h.keyholders.insert(sid);
    } else {
        h.keyholders.remove(&sid);
    }
}

/// What an answer sent that its connection remembers once it is queued: the `kh` header's
/// digest, and that it carried the seat's keying; and what the group learns of the seat:
/// it was used, and it is behind a running roll with no seed welcome stored.
struct Sent {
    kh: Option<[u8; 32]>,
    keyed: bool,
    behind: bool,
    gen: [u8; 16],
    /// The seed of the seed welcome it carried.
    seed: Option<u32>,
}

fn took(shared: &Shared, h: &Handle, sid: UserId, seat: &SeatRef, s: Sent) {
    if let Some(d) = s.kh {
        h.kh_sent.insert(sid, d);
    }
    if s.keyed {
        h.keyed.insert(sid);
    }
    if s.behind {
        let _ = h.tx.send((Msg::SeedWanted { seat: *seat }, 0));
    }
    if let Some(x) = s.seed {
        h.store.seed_sent(seat, x);
    }
    used(shared, h, s.gen, seat);
}

/// A stored group's seat was used (a fetch answered, a post): its `last_use` moves at the
/// daily write (plan 2d, at most once a day per seat).
fn used(shared: &Shared, h: &Handle, gen: [u8; 16], seat: &SeatRef) {
    if h.store.stored() {
        shared
            .used
            .entry(h.id.clone())
            .or_default()
            .insert((gen, seat_record(seat)));
    }
}

/// A seated session's answer (2d "Fetch"): the head since `have`, its leaf, path and seal,
/// its keying on the connection's first answer and whenever its version moved since `have`
/// (with the account's self-rows when the base is a row: a new connection lost `s_m`), a
/// seed welcome waiting.
async fn answer(
    h: &Handle,
    snap: &HeadSnapshot,
    sid: UserId,
    seat: &SeatRef,
    have: Option<&FloorRef>,
    own_join: bool,
) -> (Vec<ServerMessage>, Sent) {
    let kh_sent = h.kh_sent.get(&sid).map(|d| *d);
    let keyholder = h.keyholders.contains(&sid);
    let mut p = snap.head_piece(have, kh_sent, keyholder);
    let kh = p.kh.as_ref().and(have).map(|f| f.kh);
    snap.seat_piece(seat, &mut p);
    if own_join {
        p.own_join = Some(header_in(&snap.head));
    }
    let gen = snap.gen();
    let first = !h.keyed.contains(&sid);
    let keyed = own_join || first || snap.moved_since(seat, have);
    if keyed {
        let base = match snap.base_of(seat) {
            Some(at) => h.store.base(&h.id, &gen, seat, at).await,
            None => None,
        };
        if let Some((s, _, false, _)) = &base {
            p.self_rows = h.store.self_rows(&h.id, &gen, seat, *s).await;
        }
        p.seat = snap.keying(seat, base);
    }
    // The seed welcome under the seed of the row it is keyed by (a connection that never
    // took it, a seat offline through a roll, §5.6), else a running roll's
    let hd = snap.head.header();
    if let Some(s) = p.seat.as_ref().filter(|k| k.row.is_some()).map(|k| k.s) {
        p.seed_welcome = h.store.seed_welcome(&h.id, &gen, seat, s).await;
    }
    let rolls = hd.seed_floor < hd.seed;
    if rolls && p.seed_welcome.as_ref().is_none_or(|w| w.s != hd.seed) {
        p.seed_welcome = h
            .store
            .seed_welcome(&h.id, &gen, seat, hd.seed)
            .await
            .or(p.seed_welcome);
    }
    let behind = rolls && p.seed_welcome.as_ref().is_none_or(|w| w.s < hd.seed);
    let sent = Sent {
        kh,
        keyed,
        behind,
        gen,
        seed: p.seed_welcome.as_ref().map(|w| w.s),
    };
    (push::epoch_in(&h.id, p), sent)
}

async fn actor(
    shared: Arc<Shared>,
    h: Arc<Handle>,
    mut rx: mpsc::UnboundedReceiver<(Msg, usize)>,
    mut g: GroupState,
) {
    let clock = shared.clock;
    if let Err(e) = h.store.load(&mut g).await {
        warn!(group = %h.id, "loading the group failed: {e}");
        g.new_gen = true;
    }
    let mut out = vec![];
    let now = clock.now();
    let conns: Vec<SeatRef> = g.seats.keys().filter(|s| s.m.is_conn()).copied().collect();
    for s in conns {
        g.exit(s, group::cause::RESTART, now, &mut out);
    }
    publish_snap(&h, &g);
    publish(&h, &g, now);
    // The keyholder set and who of it is online, as the database last had them
    let mut kh_was = holders_now(&g);
    let mut idle_since: Option<u64> = None;
    // The snapshot and the seated map are rebuilt when the head moves; one session's
    // entry when only it changed (a 100k join storm is not 100k rebuilds)
    let mut was = g.head.as_ref().map(|x| x.sh.d());
    let mut ticked = 0;
    loop {
        let wake = g.wake(ticked);
        let idle_at = idle_since.map(|t| t + ACTOR_IDLE_MS);
        let next = [wake, idle_at].into_iter().flatten().min();
        let msg = tokio::select! {
            _ = h.stop.notified() => return,
            m = rx.recv() => match m {
                Some((m, charge)) => {
                    h.inbox.fetch_sub(charge, Ordering::Relaxed);
                    if let Msg::Commit { sid, bytes, .. } | Msg::Welcomes { sid, bytes, .. } = &m {
                        shared.lane_free(*sid, *bytes);
                    }
                    Some(m)
                }
                None => return,
            },
            _ = async {
                match next {
                    Some(t) => tokio::time::sleep_until(clock.at(t)).await,
                    None => std::future::pending().await,
                }
            } => None,
        };
        let now = clock.now();
        let exits_from = g.exits.next;
        let mut answers: Vec<(UserId, SeatRef, Option<FloorRef>, bool)> = vec![];
        let touched = match &msg {
            Some(
                Msg::Fetch { sid, .. }
                | Msg::Leave { sid, .. }
                | Msg::Volunteer { sid, .. }
                | Msg::Follow { sid, .. },
            ) => Some(*sid),
            _ => None,
        };
        let all = matches!(msg, Some(Msg::AccountExit { .. }));
        match msg {
            None => {
                g.tick(now, &mut out);
                ticked = now;
            }
            Some(m) => handle_msg(&shared, &h, &mut g, m, now, &mut out, &mut answers).await,
        }
        if g.exits.next != exits_from {
            h.store.exits_entered(&h.id, &g, exits_from, now).await;
        }
        // A seed-welcome page, with the KEM keys of its seats (plan 2d "Seed rolls")
        if let Some(want) = g.page_wanted(now) {
            let (keyed, gone) = page_keys(&shared, &g, &want).await;
            g.ask_page(keyed, gone, now, &mut out);
        }
        // The keyholder entries, their pairs and when each was last online outlive a
        // restart (2i): written when the set or who of it is online changes
        let kh_now = holders_now(&g);
        if kh_now != kh_was {
            h.store.put_holders(&g, now).await;
            kh_was = kh_now;
        }
        // Before the dues go out: a keyholder's first part may come back at once
        let page = g.page.as_ref().map(|p| p.sid);
        h.asked
            .retain(|s| g.dues.iter().any(|d| d.sid == *s) || page == Some(*s));
        for d in &g.dues {
            h.asked.insert(d.sid);
        }
        if let Some(s) = page {
            h.asked.insert(s);
        }
        let head = g.head.as_ref().map(|x| x.sh.d());
        if head != was || all {
            publish_snap(&h, &g);
        }
        deliver(&shared, &h, std::mem::take(&mut out));
        publish(&h, &g, now);
        was = head;
        if let Some(sid) = touched {
            touch(&h, &g, sid);
        }
        answer_all(&shared, &h, answers).await;
        if g.idle() {
            let since = *idle_since.get_or_insert(now);
            if now >= since + ACTOR_IDLE_MS {
                shared.map.remove_if(&h.id, |_, x| Arc::ptr_eq(x, &h));
                return;
            }
        } else {
            idle_since = None;
        }
    }
}

type Answer = (UserId, SeatRef, Option<FloorRef>, bool);

/// The keyholder set and its online entries, by KX.
fn holders_now(g: &GroupState) -> (Vec<[u8; 32]>, Vec<[u8; 32]>) {
    (
        g.holders.set.iter().map(|k| k.kx).collect(),
        g.holders
            .online(&g.vols)
            .iter()
            .map(|v| v.pair.kx())
            .collect(),
    )
}

/// A page's seats with their identity keys and pairs, and the seats no seed welcome can
/// reach.
type PageKeys = (Vec<(SeatRef, [u8; 32], Pair)>, Vec<(SeatRef, u8)>);

/// The identity keys and pairs of `seats` a seed-welcome page asks: an account seat's from
/// its published seat keys (`voipc_gk_seatkeys`), a connection seat's from its join. A seat
/// whose keys are not found, or make another seat (rotated since), is gone (cause
/// `ROTATION`): it can never take this seed, so it exits and the roll can end (plan 2d).
/// When the database read fails nobody is gone: the account seats wait for the next page.
async fn page_keys(shared: &Shared, g: &GroupState, seats: &[SeatRef]) -> PageKeys {
    let accounts: Vec<[u8; 16]> = seats.iter().filter_map(|s| s.m.account()).collect();
    let mut read = true;
    let found = match shared.db.get() {
        Some(db) if !accounts.is_empty() => match store::seat_kems(&db.db, &accounts).await {
            Ok(f) => f,
            Err(e) => {
                warn!(group = %g.id, "reading seat keys failed: {e}");
                read = false;
                HashMap::new()
            }
        },
        _ => HashMap::new(),
    };
    let (mut keyed, mut gone) = (vec![], vec![]);
    for s in seats {
        let keys = match s.m.account() {
            Some(_) if !read => continue,
            Some(a) => found.get(&a),
            None => g.conn_keys.get(s),
        };
        match keys.filter(|(_, pair)| pair.keys.seat(s.m) == *s) {
            Some((ik, pair)) => keyed.push((*s, *ik, pair.clone())),
            None => gone.push((*s, group::cause::ROTATION)),
        }
    }
    (keyed, gone)
}

/// Whether `seat`'s keying is gone for a new connection: a memory group keeps a welcome
/// only until it went out, rows only of re-keyed versions, and a seed welcome only until it
/// went out (2b), so a seat seated by a welcome another connection took has no base, and
/// one keyed by a row has no `s_m` to open it without its seed's welcome (no self-rows).
async fn lost(h: &Handle, seat: &SeatRef) -> bool {
    if h.store.stored() {
        return false;
    }
    let snap = h.snap.read().unwrap_or_else(|e| e.into_inner()).clone();
    let Some((snap, at)) = snap.and_then(|s| s.base_of(seat).map(|at| (s, at))) else {
        return false;
    };
    let gen = snap.gen();
    match h.store.base(&h.id, &gen, seat, at).await {
        None => true,
        Some((_, _, true, _)) => false,
        Some((s, _, false, _)) => h.store.seed_welcome(&h.id, &gen, seat, s).await.is_none(),
    }
}

/// The answers a taken commit owes (`apply`'s list), each from the floor its session's
/// queued fetch named, as a seated fetch's is (2d "walk+head since `have`"): one built from
/// no floor walks to the generation's start, past a same-generation floor, and the member
/// refuses it.
fn answers_after(g: &mut GroupState, applied: Vec<(UserId, bool)>) -> Vec<Answer> {
    let mut answers = vec![];
    for (sid, own_join) in applied {
        if let Some(m) = g.members.get_mut(&sid) {
            let have = m.have.take();
            if let Some(seat) = m.seat {
                answers.push((sid, seat, have, own_join));
            }
        }
    }
    answers
}

/// The actor's answers (joiners seated, fetchers it held) from the published snapshot. A
/// memory group's welcome goes once every session of its seat had its answer queued
/// whole; one not queued keeps it for the next fetch (2b).
async fn answer_all(shared: &Shared, h: &Handle, answers: Vec<Answer>) {
    if answers.is_empty() {
        return;
    }
    let snap = h.snap.read().unwrap_or_else(|e| e.into_inner()).clone();
    let Some(snap) = snap else { return };
    let mut sent: HashMap<SeatRef, bool> = HashMap::new();
    for (sid, seat, have, own_join) in answers {
        let (frames, s) = answer(h, &snap, sid, &seat, have.as_ref(), own_join).await;
        let whole = deliver(shared, h, vec![Out(sid, frames)]);
        if whole {
            took(shared, h, sid, &seat, s);
        }
        *sent.entry(seat).or_insert(true) &= whole;
    }
    for (seat, whole) in sent {
        if whole {
            h.store.welcomed(&seat);
        }
    }
}

/// Eager seats asked a page at a time (plan 2d).
const EAGER_PAGE: u32 = 256;

/// After a stored group's Genesis or Regenesis: every account that keeps its conversation's
/// log with published seat keys is queued eagerly, online or not (plan 2d "Eager seats"),
/// since they never send `LogJoin` again. Read a page at a time off the actor, at most
/// `kept_seats`, each page queued to it.
fn eager_all(h: &Handle, kept_seats: usize) {
    let Store::Db(db) = &*h.store else {
        return;
    };
    let (db, tx, conv) = (db.clone(), h.tx.clone(), h.id.clone());
    tokio::spawn(async move {
        let mut after: Option<[u8; 16]> = None;
        let mut queued = 0;
        while queued < kept_seats {
            // The group id is its conversation's (`stored_id`), as `voipc_members` names it
            let page = match store::eager_page(&db.db, &conv, after.as_ref(), EAGER_PAGE).await {
                Ok(p) => p,
                Err(e) => {
                    warn!(group = %conv, "reading the eager seats failed: {e}");
                    return;
                }
            };
            let full = page.len() == EAGER_PAGE as usize;
            queued += page.len();
            after = page.last().map(|(a, _)| *a);
            if page.is_empty() || tx.send((Msg::EagerMany(page), 0)).is_err() || !full {
                return;
            }
        }
    });
}

#[allow(clippy::too_many_arguments)]
async fn handle_msg(
    shared: &Shared,
    h: &Handle,
    g: &mut GroupState,
    m: Msg,
    now: u64,
    out: &mut Vec<Out>,
    answers: &mut Vec<(UserId, SeatRef, Option<FloorRef>, bool)>,
) {
    match m {
        Msg::Follow { sid, account } => g.follow(sid, account),
        Msg::Leave { sid, cause } => {
            h.kh_sent.remove(&sid);
            h.keyed.remove(&sid);
            g.leave(sid, cause, now, out)
        }
        Msg::AccountExit { account, cause } => g.account_exit(&account, cause, now, out),
        Msg::Eager { joiner, account } => {
            let seat = joiner.seat;
            g.eager(joiner, account, now, out);
            if g.seats.contains_key(&seat) {
                shared.reseat_done(&h.id, &seat);
            }
        }
        Msg::Volunteer { sid, v, device } => {
            if let Some(d) = device {
                g.devices.insert(sid, d);
            }
            g.volunteer(sid, v, now, out)
        }
        Msg::Fetch { sid, f } => {
            let have = f.have;
            let again = f.clone();
            if let Fetched::Seated(seat) = g.fetch(sid, f, now, out) {
                if !h.keyed.contains(&sid) && lost(h, &seat).await {
                    g.rejoin(sid, again, now, out);
                } else {
                    answers.push((sid, seat, have, false));
                }
            }
        }
        Msg::Commit {
            sid,
            due,
            part,
            last,
            piece,
            bytes,
        } => {
            let Some(t) = g.commit_part(sid, due, part, last, piece, bytes, now, out) else {
                return;
            };
            match h.store.commit(g, &t, now).await {
                Ok(()) => {
                    let dealt: Vec<SeatRef> = t
                        .applied
                        .seated
                        .iter()
                        .map(|(s, _)| *s)
                        .chain(t.applied.refused.iter().map(|r| r.seat))
                        .collect();
                    let anew = t.applied.header.header().kind.starts_anew();
                    let applied = g.apply(t, now, out);
                    answers.extend(answers_after(g, applied));
                    h.store.prune(g);
                    if let (Some(step), Some(gen)) = (g.names.take_swept(), g.gen()) {
                        h.store.names_step(&h.id, &gen, &step).await;
                    }
                    for s in &dealt {
                        shared.reseat_done(&h.id, s);
                    }
                    if anew && g.stored {
                        eager_all(h, g.kept_seats);
                    }
                }
                Err(Fail::Check(d)) => {
                    warn!(group = %h.id, "a commit's version ids were used: {d}");
                    g.store_failed(t, now, out);
                }
                Err(Fail::Store(e)) => {
                    warn!(group = %h.id, "storing a commit failed: {e}");
                    g.store_failed(t, now, out);
                }
            }
        }
        Msg::Decline { sid, due, why } => g.decline(sid, due, why, now, out),
        Msg::Resign { sid, entry } => g.resign(sid, entry, now, out),
        Msg::Replace { sid, ask } => g.replace(sid, ask, now, out),
        Msg::Lists { sid, gen, versions } => g.lists(sid, gen, &versions, out),
        Msg::Keyring { sid, gen, have } => {
            // A keyholder's own asks are refused as `COMMIT`'s, never as its fetch's, so a
            // member's live state never reads them (C3b member.rs says the same)
            let (Some(kx), Some(head)) = (g.holder_kx(sid), g.head.as_ref()) else {
                g.refuse(out, sid, refused_what::COMMIT, refused_why::NOT_MEMBER);
                return;
            };
            let hd = head.sh.header();
            if hd.gen != gen {
                g.refuse(out, sid, refused_what::COMMIT, refused_why::OLD_EPOCH);
                return;
            }
            let from = match have {
                Some((e, j)) if e == hd.epoch => j + 1,
                _ => 0,
            };
            let krk = h.store.krk(&h.id, &gen, head.kh.header().epoch, &kx).await;
            let stream = h.store.keyring(&h.id, &gen, hd.epoch, from).await;
            out.push(Out(
                sid,
                push::keyring_in(&h.id, gen, (hd.epoch, hd.join), krk, &stream),
            ));
        }
        Msg::PostBlob {
            sid,
            gen,
            epoch,
            blob,
            reply,
        } => {
            let _ = reply.send(g.post_blob(sid, gen, epoch, blob, now, out));
        }
        Msg::Blobs {
            sid,
            gen,
            epoch,
            writer,
        } => g.blobs(sid, gen, epoch, writer, out),
        Msg::Names {
            sid,
            from,
            to,
            removals,
        } => g.names(sid, &from, &to, removals, out),
        Msg::FloorAhead { sid, header } => g.floor_ahead(sid, &header, now, out),
        Msg::Gate { gated } => g.set_gate(gated, now, out),
        Msg::Welcomes {
            sid,
            due,
            gen,
            seed,
            welcomes,
            ..
        } => {
            let Some((by, took)) = g.take_welcomes(sid, due, gen, seed, welcomes, out) else {
                return;
            };
            if let Err(e) = h.store.seeds(&h.id, &gen, seed, &by, &took, now).await {
                warn!(group = %h.id, "storing seed welcomes failed: {e}");
                return;
            }
            let mut pushed = vec![];
            g.seeded(by, seed, &took, now, &mut pushed);
            if h.store.stored() {
                out.extend(pushed);
                return;
            }
            // A memory group pushes them and keeps one only for a seat a push missed (an
            // account seat offline, a full queue): 2b, so 100k seats keep no 110 MB
            let mut whole: HashMap<SeatRef, bool> = HashMap::new();
            for o in pushed {
                let seat = g.members.get(&o.0).and_then(|m| m.seat);
                let ok = deliver(shared, h, vec![o]);
                if let Some(seat) = seat {
                    *whole.entry(seat).or_insert(true) &= ok;
                }
            }
            for (seat, ok) in whole {
                if ok {
                    h.store.seed_sent(&seat, seed);
                }
            }
        }
        Msg::SeedWanted { seat } => g.seed_wanted(seat),
        Msg::Counter { account, n, since } => g.counter(account, n, since, now, out),
        Msg::DeviceRemoved { account, device } => g.device_removed(&account, &device, now, out),
        Msg::EagerMany(page) => {
            for (account, joiner) in page {
                g.eager(joiner, account, now, out);
            }
        }
        Msg::Sweep { daily } => h.store.sweep_live(g, now, daily).await,
        Msg::Expire(seats) => g.expire(&seats, now, out),
        Msg::Rotated { account, keep } => g.rotated(&account, &keep, now, out),
    }
}

// ── Sweeps (plan 2e) ──────────────────────────────────────────────────────

const DAY_MS: u64 = 24 * 60 * 60 * 1000;

/// The relay's sweeps, while its groups live: every 10 minutes, then daily too (`sweep`).
async fn sweeper(shared: std::sync::Weak<Shared>) {
    let mut tick = tokio::time::interval(Duration::from_millis(MATERIAL_SWEEP_MS));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // The first tick is at once: each actor sweeps its orphans as it starts
    tick.tick().await;
    let mut daily_at = 0;
    loop {
        tick.tick().await;
        let Some(shared) = shared.upgrade() else {
            return;
        };
        let now = shared.clock.now();
        let daily = now >= daily_at;
        if daily {
            daily_at = now + DAY_MS;
        }
        sweep(&shared, now, daily).await;
    }
}

/// Every 10 minutes: each live group's orphans (its actor, between commits) and each
/// stored group's epoch material, headers, keyrings and stale rows (`store::sweep_material`,
/// which spares a pending commit's), and its bytes for Load. Daily also: the `last_use` of
/// every seat used since (at most once a day per seat), names past 90 days (each live
/// group's actor), and seats unused for 90 days exit (their group's actor is started).
async fn sweep(shared: &Arc<Shared>, now: u64, daily: bool) {
    for h in shared.map.iter() {
        let _ = h.tx.send((Msg::Sweep { daily }, 0));
    }
    let Some(db) = shared.db.get() else {
        return;
    };
    if daily {
        let ids: Vec<String> = shared.used.iter().map(|e| e.key().clone()).collect();
        for id in ids {
            let Some((_, set)) = shared.used.remove(&id) else {
                continue;
            };
            let mut by_gen: HashMap<[u8; 16], Vec<[u8; 33]>> = HashMap::new();
            for (gen, rec) in set {
                by_gen.entry(gen).or_default().push(rec);
            }
            for (gen, recs) in by_gen {
                if let Err(e) =
                    crate::accounts::gk::touch_seats(&db.db, &id, &gen, &recs, now).await
                {
                    warn!(group = %id, "writing seats' last use failed: {e}");
                }
            }
        }
    }
    let grps = match crate::accounts::gk::groups(&db.db).await {
        Ok(g) => g,
        Err(e) => {
            warn!("listing the stored groups failed: {e}");
            return;
        }
    };
    for grp in grps {
        if let Err(e) = store::sweep_material(&db.db, &grp, now).await {
            warn!(group = %grp, "sweeping epoch material failed: {e}");
        }
        if let Ok(n) = crate::accounts::gk::stored_bytes(&db.db, &grp).await {
            shared.db_bytes.insert(grp.clone(), n);
        }
        if daily {
            let before = now.saturating_sub(SEAT_EXPIRY_SECS * 1000);
            match store::expired(&db.db, &grp, before).await {
                Ok(seats) if !seats.is_empty() => {
                    let h = start(shared, &grp, GroupKind::Text, 0);
                    let _ = h.tx.send((Msg::Expire(seats), 0));
                }
                Ok(_) => {}
                Err(e) => warn!(group = %grp, "reading expired seats failed: {e}"),
            }
        }
    }
}

#[cfg(test)]
impl Groups {
    /// One sweep now, as the timer runs it.
    pub async fn sweep_for_test(&self, daily: bool) {
        sweep(&self.shared, self.now(), daily).await;
    }
}

#[cfg(test)]
impl Handle {
    pub fn inbox_full_for_test(&self) {
        self.inbox.store(INBOX_MAX_BYTES, Ordering::Relaxed);
    }

    /// Seed welcomes a memory group keeps.
    pub fn seed_kept_for_test(&self) -> usize {
        self.store.seed_kept()
    }

    /// Whether a new connection of `seat` finds its keying gone (`lost`).
    pub async fn lost_for_test(&self, seat: &SeatRef) -> bool {
        lost(self, seat).await
    }
}

#[cfg(test)]
impl Groups {
    pub fn deliver_for_test(&self, id: &str, out: Vec<Out>) {
        let h = self.get(id).expect("live");
        deliver(&self.shared, &h, out);
    }

    pub fn lane_for_test(&self, sid: UserId) -> usize {
        self.shared.lane.get(&sid).map_or(0, |q| *q)
    }

    /// Whether `sid`'s offer is kept, for the groups it follows later.
    pub fn volunteers_for_test(&self, sid: UserId) -> bool {
        self.vols.contains_key(&sid)
    }

    /// The answers the actor sends after `g` took a commit (`apply`'s list), from a group
    /// over `store` showing `g`.
    pub async fn answer_for_test(
        &self,
        g: &mut GroupState,
        store: Arc<Store>,
        to: Vec<(UserId, bool)>,
    ) {
        let h = self.handle_for_test(g, store);
        let answers = answers_after(g, to);
        answer_all(&self.shared, &h, answers).await;
    }

    /// A handle showing `g`, for answers in rounds on one connection's bookkeeping.
    pub fn handle_for_test(&self, g: &GroupState, store: Arc<Store>) -> Arc<Handle> {
        let (h, _inbox) = Handle::new(&g.id, g.kind, 0, store);
        publish_snap(&h, g);
        publish(&h, g, self.now());
        h
    }

    /// Answers on `h` as fetches would get them: `(sid, have, own_join)` each.
    pub async fn answers_for_test(&self, h: &Handle, to: Vec<(UserId, Option<FloorRef>, bool)>) {
        let answers = to
            .into_iter()
            .filter_map(|(sid, have, own)| Some((sid, *h.seated.get(&sid)?, have, own)))
            .collect();
        answer_all(&self.shared, h, answers).await;
    }

    /// Whether an answer built from `h`'s snapshot, and one from `then`'s published after
    /// it, go: the first must not (a push of the newer head may be queued already).
    pub fn answers_go_for_test(&self, h: &Handle, then: &GroupState, sid: UserId) -> (bool, bool) {
        let old = h.snap.read().unwrap().clone().expect("a snapshot");
        publish_snap(h, then);
        let new = h.snap.read().unwrap().clone().expect("a snapshot");
        (
            deliver_from(&self.shared, h, &old, Out(sid, vec![])).is_some(),
            deliver_from(&self.shared, h, &new, Out(sid, vec![])).is_some(),
        )
    }

    /// A rotation's group `id` seated `seat`.
    pub fn reseat_done_for_test(&self, id: &str, seat: &SeatRef) {
        self.shared.reseat_done(id, seat);
    }

    /// A live group of `channel` whose actor raised `text` (plan 2j), with no actor behind it.
    pub fn warn_for_test(&self, channel: ChannelId, text: &str) {
        let id = format!("r:{}:{channel}", hex(&self.run));
        let (h, _inbox) = Handle::new(&id, GroupKind::Text, channel, Arc::new(Store::memory()));
        h.warnings.lock().unwrap().push(text.into());
        self.shared.map.insert(id, h);
    }
}

/// The session's answer from the snapshot, outside the actor, queued whole (part 13);
/// `false` when the actor must answer (not seated at the snapshot's head).
/// Built again from a newer snapshot this often at most, then left to the actor.
const ANSWER_TRIES: usize = 3;

async fn answer_seated(shared: &Shared, h: &Handle, sid: UserId, have: Option<&FloorRef>) -> bool {
    for _ in 0..ANSWER_TRIES {
        let Some(seat) = h.seated.get(&sid).map(|s| *s) else {
            return false;
        };
        let snap = h.snap.read().unwrap_or_else(|e| e.into_inner()).clone();
        let Some(snap) = snap else {
            return false;
        };
        if have.is_some_and(|f| {
            f.gen == snap.gen()
                && (f.epoch, f.join) > (snap.head.header().epoch, snap.head.header().join)
        }) {
            return false;
        }
        let (frames, s) = answer(h, &snap, sid, &seat, have, false).await;
        match deliver_from(shared, h, &snap, Out(sid, frames)) {
            Some(whole) => {
                if whole {
                    took(shared, h, sid, &seat, s);
                }
                return true;
            }
            None => continue,
        }
    }
    false
}

/// `EpochStale` for a commit part the lane does not take: `NOT_DUE` from a session with no
/// due out, `TOO_LARGE` past its connection's cap.
fn lane_refused(groups: &Groups, sid: UserId, group: &str, due: u64, reason: u8) {
    groups.send_now(
        sid,
        ServerMessage::EpochStale {
            group: group.to_string(),
            due,
            reason,
            detail: String::new(),
            head: None,
        },
    );
}
