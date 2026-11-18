//! The group epoch key on the relay (docs/GROUP-KEY.md, plan 2a): `Groups`, the registry of
//! every live group, each run by one tokio task (`actor`) over its `GroupState`. A group's
//! inbox is bounded by bytes, never blocking a session: past `INBOX_MAX_BYTES` fetches and
//! posts are refused `RATE`; commit parts take their own lane (their caps are the open
//! commit's). Seated fetches are answered from the published `HeadSnapshot` outside the
//! actor, plain posts checked against `HeadView`. Every multi-part sequence to a session
//! is queued whole under the group's send lock, so none interleaves with another.
//!
//! The hooks other slices call: `on_*` (R2: session.rs, state.rs; K2: the accounts paths;
//! V2: voice rooms), `chain_epoch_ref`, `row_makers`, `stats`.
#![cfg_attr(not(test), allow(dead_code))]

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
use voipc_crypto::group_key::timers::{ACTOR_IDLE_MS, INBOX_MAX_BYTES, OPEN_PER_CONN_BYTES};
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
        });
        (h, rx)
    }
}

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
    /// Stored groups whose channel moved back to them: a new generation at their start.
    moved_back: DashSet<String>,
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
            }),
            by_channel: DashMap::new(),
            follows: DashMap::new(),
            vols: DashMap::new(),
            moved_back: DashSet::new(),
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
    /// here `c:` groups are stored. Without it every group is in memory (2h).
    pub fn attach(&self, db: l4f_accounts::store::Store, incarnation: [u8; 16]) {
        let _ = self.shared.db.set(Arc::new(DbStore { db, incarnation }));
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
        use dashmap::mapref::entry::Entry;
        let e = match self.shared.map.entry(id.to_string()) {
            Entry::Occupied(e) => return e.get().clone(),
            Entry::Vacant(e) => e,
        };
        let store = match (id.starts_with("c:"), self.shared.db.get()) {
            (true, Some(db)) => Store::Db(db.clone()),
            _ => Store::memory(),
        };
        let (h, rx) = Handle::new(id, kind, channel, Arc::new(store));
        e.insert(h.clone());
        let mut g = GroupState::new(
            id.to_string(),
            kind,
            h.store.stored(),
            self.shared.caps.clone(),
        );
        g.new_gen = self.moved_back.remove(id).is_some();
        tokio::spawn(actor(self.shared.clone(), h.clone(), rx, g));
        h
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
            self.post(group, Msg::Volunteer { sid, v: Some(v) }, 0, true);
        }
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

    /// The channel's gate turned on or off.
    pub fn on_gate(&self, channel: ChannelId, gated: bool) {
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
            self.moved_back.insert(new.to_string());
        }
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

    /// An account that keeps a channel's history is seated eagerly in its stored group
    /// (plan 2d), with its published seat keys. `ik`: its identity key, raw.
    pub async fn on_log_join(&self, conv: &str, account: [u8; 16], ik: [u8; 32]) {
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
        let id = stored_id(conv);
        let channel = self.channel_of(&id);
        let _ = self.live(&id, GroupKind::Text, channel);
        self.post(&id, Msg::AccountExit { account, cause }, 0, true);
    }

    /// An identity reset or account deletion: its seats exit everywhere, online or not.
    pub async fn on_account_gone(&self, account: [u8; 16], cause: u8) {
        let mut ids: HashSet<String> = self.shared.map.iter().map(|h| h.key().clone()).collect();
        if let Some(db) = self.shared.db.get() {
            if let Ok(seats) = crate::accounts::gk::seats_of_account(&db.db, &account).await {
                ids.extend(seats.into_iter().map(|(grp, _, _)| grp));
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
        let Some(db) = self.shared.db.get() else {
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
            .into_iter()
            .filter(|(_, _, s)| s.seat != seat_record(&new))
            .map(|(grp, _, _)| grp)
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
        for id in groups {
            let channel = self.channel_of(&id);
            let _ = self.live(&id, GroupKind::Text, channel);
            self.post(
                &id,
                Msg::AccountExit {
                    account,
                    cause: group::cause::ROTATION,
                },
                0,
                true,
            );
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

    /// Whether a kept chain may name `(gen, epoch)` of `group` (C4): the head's generation,
    /// at or before its epoch. `Err` is a `refused_why` code.
    pub fn chain_epoch_ref(&self, group: &str, gen: &[u8; 16], epoch: u32) -> Result<(), u8> {
        if !group.starts_with("c:") {
            return Err(refused_why::NOT_STORED);
        }
        let h = self.get(group).ok_or(refused_why::NOT_MEMBER)?;
        let view =
            (*h.head.read().unwrap_or_else(|e| e.into_inner())).ok_or(refused_why::OLD_EPOCH)?;
        if view.gen == *gen && epoch <= view.epoch && epoch > 0 {
            Ok(())
        } else {
            Err(refused_why::OLD_EPOCH)
        }
    }

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

    /// One row per live group, for `AdminLoad` (R2 picks which to show, 2j).
    pub fn stats(&self) -> Vec<GroupLoad> {
        self.shared
            .map
            .iter()
            .map(|h| h.stats.lock().unwrap_or_else(|e| e.into_inner()).clone())
            .collect()
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
    }
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
/// digest, and that it carried the seat's keying.
struct Sent {
    kh: Option<[u8; 32]>,
    keyed: bool,
}

fn took(h: &Handle, sid: UserId, s: Sent) {
    if let Some(d) = s.kh {
        h.kh_sent.insert(sid, d);
    }
    if s.keyed {
        h.keyed.insert(sid);
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
    let hd = snap.head.header();
    if hd.seed_floor < hd.seed {
        p.seed_welcome = h.store.seed_welcome(&h.id, &gen, seat, hd.seed).await;
    }
    (push::epoch_in(&h.id, p), Sent { kh, keyed })
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
                    if let Msg::Commit { sid, bytes, .. } = &m {
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
        // Before the dues go out: a keyholder's first part may come back at once
        h.asked.retain(|s| g.dues.iter().any(|d| d.sid == *s));
        for d in &g.dues {
            h.asked.insert(d.sid);
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
            took(h, sid, s);
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
/// since they never send `LogJoin` again.
async fn eager_all(h: &Handle, g: &mut GroupState, now: u64, out: &mut Vec<Out>) {
    // The group id is its conversation's (`stored_id`), as `voipc_members` names it
    let conv = h.id.as_str();
    let mut after: Option<[u8; 16]> = None;
    loop {
        let page = match h.store.eager_seats(conv, after.as_ref(), EAGER_PAGE).await {
            Ok(p) => p,
            Err(e) => {
                warn!(group = %h.id, "reading the eager seats failed: {e}");
                return;
            }
        };
        let n = page.len();
        for (account, joiner) in page {
            after = Some(account);
            g.eager(joiner, account, now, out);
        }
        if n < EAGER_PAGE as usize {
            return;
        }
    }
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
        Msg::Volunteer { sid, v } => g.volunteer(sid, v, now, out),
        Msg::Fetch { sid, f } => {
            let have = f.have;
            if let Fetched::Seated(seat) = g.fetch(sid, f, now, out) {
                answers.push((sid, seat, have, false));
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
                        eager_all(h, g, now, out).await;
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
    }
}

#[cfg(test)]
impl Handle {
    pub fn inbox_full_for_test(&self) {
        self.inbox.store(INBOX_MAX_BYTES, Ordering::Relaxed);
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
                    took(h, sid, s);
                }
                return true;
            }
            None => continue,
        }
    }
    false
}

/// A fetch with `at` (kept history, C4) is not answered here yet. `EpochRefused{FETCH,
/// NOT_STORED}` is only ever this answer to `at`: C3b leaves a member's live state alone on
/// it (member.rs `on_refused`), and its live fetch is still answered.
fn past_refused(groups: &Groups, sid: UserId, group: &str, at: &[EpochRef]) -> bool {
    if at.is_empty() {
        return false;
    }
    groups.refuse(sid, group, refused_what::FETCH, refused_why::NOT_STORED);
    true
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
