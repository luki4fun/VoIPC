//! The group epoch key in the desktop and phone app (plan 3i). network.rs only routes: the
//! relay's `Epoch*` frames go to `voipc_crypto::group_state::GroupKeying` here, and what it
//! hands back (`GkOut`) is carried out here. Frames are sent, `gk-*` events emitted (U1's
//! contract, `GkEvent::to_wire`), posts shown, voice keys installed into the connection's
//! `MediaKeyRing`, floors kept in the vault and in `gk_local.bin`, and the kept copy of a
//! post filed under the epoch it went under (`group_state::Copies`, the browser's rule too).
//! A post to a channel whose group is not tracked yet waits for it (`group_state::Early`).
//! A keyholder's builds run on a blocking thread off the connection's lock (`take_build` →
//! `BuildJob::step` → `built`), and its uploads go out one frame at a time, yielding to voice
//! (`gk_task`, beside `live_task`).
//!
//! Which path a connection takes is the frame after `Authenticated`'s to say: `GroupKeys`
//! (protocol 26) starts the group key, with `on: false` only for reading kept history; any
//! other frame is a relay below 26, on the legacy and live paths.
//!
//! Everything here is one connection's (`SignalState::gk`): a frame from one relay never
//! reaches another relay's state, and `gk_local.bin` keeps each relay and account apart
//! (`gk_local::Scope`).

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, MutexGuard, PoisonError};
use std::time::Duration;

use serde_json::json;
use tauri::Manager;
use tokio::sync::Notify;
use tracing::warn;
use voipc_crypto::account_session::Actions;
use voipc_crypto::group_key::{GroupKind, MemberId, SeatKeys};
use voipc_crypto::group_state::{
    group_id, Copies, Early, EarlyPost, GkCtx, GkEpoch, GkNames, GkOut, GkPins, GkStart, GkTrack,
    GroupKeying, KeptCopy, LocalGk, MemoryPins, OpenedPost, PastEpoch, Platform, VaultFloor,
};
use voipc_crypto::media_keys::MediaKeyRing;
use voipc_crypto::SignalStores;
use voipc_protocol::messages::{ClientMessage, ServerMessage};
use voipc_protocol::types::{ChannelInfo, UserInfo};

use crate::account::AccountLink;
use crate::app_state::{ActiveConnection, AppState, SignalState};
use crate::gk_local::Scope;
use crate::network::{emit_server, ControlTx};

/// Floors moved are written at most this long after, and always before anything goes out
/// under the new head (3c).
const SAVE_WITHIN_MS: u64 = 250;
/// A build's slice of work per step (`BuildJob::step`).
const BUILD_STEP: Duration = Duration::from_millis(50);

#[cfg(target_os = "android")]
const PLATFORM: Platform = Platform::Phone;
#[cfg(not(target_os = "android"))]
const PLATFORM: Platform = Platform::Desktop;

/// What the frame after `Authenticated` made of this connection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Path {
    /// It has not come yet.
    #[default]
    Waiting,
    /// Not `GroupKeys`: a relay below protocol 26. The live and legacy paths only.
    Legacy,
    /// `GroupKeys { on: false }`: the live and legacy paths, and kept history read under the
    /// group key.
    Kept,
    /// `GroupKeys { on: true }`: channel chat under the group key.
    On,
}

/// Who goes by what here, as the rosters said (`GkNames`): names as sent, tag and all.
#[derive(Default)]
struct Roster {
    users: HashMap<u32, (Option<[u8; 16]>, String)>,
    own: u32,
    own_admin: bool,
}

impl Roster {
    fn note(&mut self, rows: &[UserInfo]) {
        for u in rows {
            self.users
                .insert(u.user_id, (u.account, u.username.clone()));
            if u.user_id == self.own {
                self.own_admin = u.is_admin;
            }
        }
    }
}

impl GkNames for Roster {
    fn name(&self, m: &MemberId) -> Option<String> {
        match m {
            MemberId::Account(a) => self
                .users
                .values()
                .find(|(account, _)| account.as_ref() == Some(a))
                .map(|(_, name)| name.clone()),
            MemberId::Conn(u) => self.users.get(u).map(|(_, name)| name.clone()),
        }
    }

    fn online(&self, m: &MemberId) -> bool {
        match m {
            MemberId::Account(a) => self
                .users
                .values()
                .any(|(account, _)| account.as_ref() == Some(a)),
            MemberId::Conn(u) => self.users.contains_key(u),
        }
    }
}

/// One connection's group key (`SignalState::gk`).
#[derive(Default)]
pub struct GkNet {
    pub keying: GroupKeying,
    path: Path,
    started: bool,
    /// The run of this relay's `r:` ids.
    run: [u8; 16],
    /// Whose `gk_local.bin` entry this connection's is: set at the sign-in.
    scope: Option<Scope>,
    /// A guest's book (an account's is its `AccountSync`).
    guest: MemoryPins,
    roster: Roster,
    /// The channels tracked, with their kind and group.
    tracked: HashMap<u32, (GroupKind, String)>,
    /// Our posts' kept copies, until they are filed (the browser's rule too).
    copies: Copies,
    /// Our posts to channels not tracked yet (their join not answered).
    early: Early,
    /// Seat keys settled before the start: `GkStart::seat_keys`.
    seat_keys: Option<SeatKeys>,
    /// The floors moved since this, unsaved (ms).
    dirty_since: Option<u64>,
    /// Wakes `gk_task`: a build or an upload waits.
    wake: Arc<Notify>,
}

impl GkNet {
    /// The frame after `Authenticated` decides the path, once.
    pub fn first_frame(&mut self, msg: &ServerMessage) {
        if self.path != Path::Waiting {
            return;
        }
        self.path = match msg {
            ServerMessage::GroupKeys { on: true, .. } => Path::On,
            ServerMessage::GroupKeys { on: false, .. } => Path::Kept,
            _ => Path::Legacy,
        };
    }

    /// Channel chat goes through the group key (`GroupKeying::post`): text channels and the
    /// chat of voice rooms both, and neither the legacy branch nor its rotation runs.
    pub fn on(&self) -> bool {
        self.path == Path::On
    }

    pub fn set_scope(&mut self, scope: Scope) {
        self.scope = Some(scope);
    }

    /// Whether a channel of `kind` is tracked: every one with the key on, only text ones for
    /// kept history with it off (voice rooms keep their logs on the old path, open choice 26).
    fn wants(&self, kind: GroupKind) -> bool {
        self.started
            && match self.path {
                Path::On => true,
                Path::Kept => kind == GroupKind::Text,
                Path::Waiting | Path::Legacy => false,
            }
    }

    /// At `GroupKeys`, on the path its frame chose, before `GroupKeying::start`. A guest's
    /// highest counters seen come from what this device kept.
    fn begin(&mut self, mut s: GkStart) -> GkStart {
        if s.account.is_none() {
            if let Some(local) = &s.local {
                self.guest.counters = local.counters.clone();
            }
        }
        if s.seat_keys.is_none() {
            s.seat_keys = self.seat_keys.take();
        }
        self.run = s.run;
        self.roster.own = s.user_id;
        self.started = true;
        s
    }

    /// The group a channel of `kind` has on this relay, as this connection sees it.
    fn track_of(&self, info: &ChannelInfo, kind: GroupKind) -> GkTrack {
        GkTrack {
            channel_id: info.channel_id,
            group: group_id(kind, &info.log, &self.run, info.channel_id),
            kind,
            anonymous: info.anonymous,
            hide_members: info.hide_members,
            viewer_admin: self.roster.own_admin,
            keeps_history: kind == GroupKind::Text && !info.log.is_empty(),
        }
    }

    fn track(&mut self, t: GkTrack, vault: VaultFloor) -> GkOut {
        self.tracked.insert(t.channel_id, (t.kind, t.group.clone()));
        self.keying.track(t, vault)
    }

    /// Out of a channel: its held posts are given up, and those that waited for it to be
    /// tracked.
    fn untrack(&mut self, channel_id: u32) -> Option<GkOut> {
        let early = self.early.gone(channel_id);
        match self.tracked.remove(&channel_id) {
            Some(_) => Some(then(self.keying.untrack(channel_id), early)),
            None => (!early.events.is_empty()).then_some(early),
        }
    }

    /// The relay did not let us into `channel_id` (`TextJoined.refused`): what waited for it
    /// is dropped, the refusal told first.
    fn join_refused(&mut self, channel_id: u32) -> GkOut {
        let refused = self.early.refused(channel_id);
        match self.untrack(channel_id) {
            Some(out) => then(refused, out),
            None => refused,
        }
    }

    /// A post of ours in `channel_id`: to the group key, or, while the channel is not
    /// tracked (its join not answered), held for it. `pins`: the account's book, else the
    /// guest's.
    fn post(
        &mut self,
        st: &mut SignalStores,
        pins: Option<&mut dyn GkPins>,
        channel_id: u32,
        post: EarlyPost,
        now: u64,
    ) -> GkOut {
        if !self.tracked.contains_key(&channel_id) {
            return self.early.hold(channel_id, post, now);
        }
        self.send(st, pins, channel_id, vec![post], now)
    }

    /// `channel_id` is tracked now: the posts that waited for it go.
    fn tracked_now(
        &mut self,
        st: &mut SignalStores,
        pins: Option<&mut dyn GkPins>,
        channel_id: u32,
        now: u64,
    ) -> GkOut {
        let posts = self.early.take(channel_id);
        if posts.is_empty() {
            return GkOut::default();
        }
        self.send(st, pins, channel_id, posts, now)
    }

    /// Posts to the group key, in order, each kept copy waiting for the epoch its post goes
    /// out under.
    fn send(
        &mut self,
        st: &mut SignalStores,
        pins: Option<&mut dyn GkPins>,
        channel_id: u32,
        posts: Vec<EarlyPost>,
        now: u64,
    ) -> GkOut {
        let GkNet {
            keying,
            guest,
            copies,
            ..
        } = self;
        let pins: &mut dyn GkPins = match pins {
            Some(p) => p,
            None => guest,
        };
        let mut out = GkOut::default();
        for p in posts {
            if let Some(copy) = p.copy {
                copies.wait(p.post_id, copy, now);
            }
            let c = GkCtx {
                pins: &mut *pins,
                now,
            };
            out = then(out, keying.post(st, channel_id, p.post_id, &p.envelope, c));
        }
        out
    }

    fn groups(&self) -> Vec<String> {
        self.tracked.values().map(|(_, g)| g.clone()).collect()
    }

    fn dirty(&mut self, now: u64) {
        self.dirty_since.get_or_insert(now);
    }

    /// The floors to keep, if they moved since the last save and this connection has a place
    /// for them. Taking them marks them saved (`gk_local::Store::save` writes them before a
    /// save asked after can see that).
    fn unsaved(&mut self, guest: bool) -> Option<(Scope, LocalGk)> {
        self.dirty_since.take()?;
        let scope = self.scope.clone()?;
        let mut local = self.keying.local()?.clone();
        if guest {
            local.counters = self.guest.counters.clone();
        }
        Some((scope, local))
    }
}

/// What carries one connection's group key out: its lock, its control stream, its account,
/// its media keys, the channel it stands in and its channel list.
#[derive(Clone)]
pub struct GkLink {
    pub app: tauri::AppHandle,
    pub server: Arc<str>,
    pub signal: Arc<std::sync::Mutex<SignalState>>,
    pub tcp_tx: ControlTx,
    pub account: Option<Arc<AccountLink>>,
    pub media_key: Arc<std::sync::Mutex<MediaKeyRing>>,
    pub channel_id: Arc<AtomicU32>,
    pub channels: Arc<std::sync::Mutex<Vec<ChannelInfo>>>,
    pub is_voice: Arc<AtomicBool>,
}

impl GkLink {
    pub fn of(app: &tauri::AppHandle, server: &str, c: &ActiveConnection) -> GkLink {
        GkLink {
            app: app.clone(),
            server: Arc::from(server),
            signal: c.signal.clone(),
            tcp_tx: c.tcp_tx.clone(),
            account: c.account.clone(),
            media_key: c.current_media_key.clone(),
            channel_id: c.current_channel_id.clone(),
            channels: c.channels.clone(),
            is_voice: c.is_voice.clone(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, SignalState> {
        self.signal.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn wake(&self) {
        self.lock().gk.wake.notify_one();
    }
}

/// `f` on the keying, the stores, and the book the checks read (the account's, or the
/// guest's), under the connection's lock (held by the caller). Floors `f` moved are marked
/// unsaved under that lock, so a send under the new head from another task saves them
/// first. `None`: no stores.
fn on_keying(
    conn: &GkLink,
    sig: &mut SignalState,
    f: impl FnOnce(&mut GroupKeying, &mut SignalStores, GkCtx) -> GkOut,
) -> Option<GkOut> {
    let SignalState { stores, gk, .. } = sig;
    let stores = stores.as_mut()?;
    let GkNet {
        keying,
        guest,
        dirty_since,
        ..
    } = gk;
    let now = voipc_crypto::time::now_millis();
    let out = match &conn.account {
        Some(link) => {
            let mut session = link.session();
            f(
                keying,
                stores,
                GkCtx {
                    pins: session.gk_pins(),
                    now,
                },
            )
        }
        None => f(keying, stores, GkCtx { pins: guest, now }),
    };
    if out.local_dirty {
        dirty_since.get_or_insert(now);
    }
    Some(out)
}

/// `f` on this connection's `GkNet`, with the stores and the account's book (`None`: a
/// guest's, `GkNet::guest`), under the connection's lock (held by the caller). `None`: no
/// stores.
fn on_net(
    conn: &GkLink,
    sig: &mut SignalState,
    f: impl FnOnce(&mut GkNet, &mut SignalStores, Option<&mut dyn GkPins>, u64) -> GkOut,
) -> Option<GkOut> {
    let SignalState { stores, gk, .. } = sig;
    let stores = stores.as_mut()?;
    let now = voipc_crypto::time::now_millis();
    let out = match &conn.account {
        Some(link) => {
            let mut session = link.session();
            f(gk, stores, Some(session.gk_pins()), now)
        }
        None => f(gk, stores, None, now),
    };
    if out.local_dirty {
        gk.dirty(now);
    }
    Some(out)
}

/// `on_keying` under the connection's lock, on a thread that may block.
fn with_gk(
    conn: &GkLink,
    f: impl FnOnce(&mut GroupKeying, &mut SignalStores, GkCtx) -> GkOut,
) -> Option<GkOut> {
    tokio::task::block_in_place(|| on_keying(conn, &mut conn.lock(), f))
}

/// What a keyholder keeps (its pair, the seats a Join of its sealed: `HolderKeep`) reaches
/// `local()` only at a tick, and it must be on disk before what moved it goes out: the pair
/// before it is offered, a Join's seats before its commit (3d). So a call that may move it
/// (`start`, `built`, `set_volunteer`, `seat_keys_changed`) is followed by a tick at once:
/// the floors are saved before the call's frames go, and the tick's go after them.
fn and_keep(
    k: &mut GroupKeying,
    st: &mut SignalStores,
    c: GkCtx,
    call: impl FnOnce(&mut GroupKeying, GkCtx) -> GkOut,
) -> GkOut {
    let GkCtx { pins, now } = c;
    let out = call(
        k,
        GkCtx {
            pins: &mut *pins,
            now,
        },
    );
    then(out, k.tick(st, GkCtx { pins, now }))
}

/// `b` after `a`, as one.
fn then(mut a: GkOut, b: GkOut) -> GkOut {
    let GkOut {
        send,
        posts,
        events,
        vault_floors,
        local_dirty,
        voice,
        past_ready,
        self_rows,
        released,
        build_ready,
        seat_keys_wanted,
    } = b;
    a.send.extend(send);
    a.posts.extend(posts);
    a.events.extend(events);
    a.vault_floors.extend(vault_floors);
    a.local_dirty |= local_dirty;
    a.voice.extend(voice);
    a.past_ready.extend(past_ready);
    a.self_rows.extend(self_rows);
    a.released.extend(released);
    a.build_ready |= build_ready;
    a.seat_keys_wanted |= seat_keys_wanted;
    a
}

// ── What comes back ───────────────────────────────────────────────────────

/// What the keying and the account hand each other, until neither has more.
enum Work {
    Gk(GkOut),
    Account(Box<Actions>),
}

impl Work {
    fn acct(a: Actions) -> Work {
        Work::Account(Box::new(a))
    }
}

/// Carries out what `GroupKeying` handed back.
pub(crate) async fn carry_out(conn: &GkLink, out: GkOut) {
    carry(conn, Work::Gk(out)).await;
}

/// What the account's session asked for (`account::run`), and its group key's part: seat
/// keys handed over (`seat_keys_changed`), vault floors in (`floors_in`), past epochs kept
/// history needs (`past_epoch`, then `past_asks`).
pub(crate) async fn account_news(conn: &GkLink, a: Actions) {
    carry(conn, Work::acct(a)).await;
}

async fn carry(conn: &GkLink, first: Work) {
    let mut todo = VecDeque::from([first]);
    while let Some(work) = todo.pop_front() {
        match work {
            Work::Gk(out) => gk_out(conn, out, &mut todo),
            Work::Account(a) => account(conn, *a, &mut todo).await,
        }
    }
}

/// What goes out under a head the floor names: the floor is on disk first (3c), and so is
/// what a keyholder keeps before it offers its pair or sends a commit (`and_keep`).
fn under_head(m: &ClientMessage) -> bool {
    matches!(
        m,
        ClientMessage::EpochPost { .. }
            | ClientMessage::EpochCommit { .. }
            | ClientMessage::EpochWelcomes { .. }
            | ClientMessage::KeyholdVolunteer { .. }
            | ClientMessage::KeyholdReplace { .. }
    )
}

fn gk_out(conn: &GkLink, out: GkOut, todo: &mut VecDeque<Work>) {
    // Each post's send noted before it goes, so its refusal never comes first
    if !out.released.is_empty() {
        let now = voipc_crypto::time::now_millis();
        conn.lock().gk.copies.sent(&out, now);
    }
    let GkOut {
        send,
        posts,
        events,
        vault_floors,
        local_dirty,
        voice,
        past_ready,
        self_rows,
        released: _,
        build_ready,
        seat_keys_wanted,
    } = out;
    if local_dirty {
        conn.lock().gk.dirty(voipc_crypto::time::now_millis());
    }
    if send.iter().any(under_head) {
        save(conn);
    }
    for m in &send {
        let _ = conn.tcp_tx.send(m);
    }
    if !events.is_empty() {
        let shown: Vec<_> = {
            let sig = conn.lock();
            events.iter().map(|e| e.to_wire(&sig.gk.roster)).collect()
        };
        for (name, payload) in shown {
            emit_server(&conn.app, &conn.server, name, payload);
        }
    }
    for p in &posts {
        emit_server(
            &conn.app,
            &conn.server,
            "channel-chat-message",
            post_event(p),
        );
    }
    if !voice.is_empty() {
        let own = conn.channel_id.load(Ordering::Relaxed);
        install_voice(&conn.media_key, &voice, own, |payload| {
            emit_server(&conn.app, &conn.server, "media-key-installed", payload);
        });
    }
    if build_ready {
        conn.wake();
    }
    let Some(link) = &conn.account else {
        return;
    };
    // On a post, someone may be named here first (the live path's `TextPost` does the same)
    for p in &posts {
        todo.push_back(Work::acct(link.session().note_person(
            p.user_id,
            p.account,
            &p.username,
        )));
    }
    if !vault_floors.is_empty() {
        todo.push_back(Work::acct(link.session().gk_put_floors(vault_floors)));
    }
    if !self_rows.is_empty() {
        todo.push_back(Work::acct(link.session().gk_self_rows(self_rows)));
    }
    if seat_keys_wanted {
        todo.push_back(Work::acct(link.session().seat_keys_wanted()));
    }
    for (group, gen, epoch) in past_ready {
        past(conn, link, &group, gen, epoch, todo);
    }
}

/// The room's voice keys from its epoch key into the ring (`MediaKeyRing::install_gk`), and,
/// once the ring's lock is let go, `media-key-installed` said once if it took any, as a key a
/// member handed over says it (`install_media_key`): the "waiting for the channel's key" line
/// the voice thread raised after 2 s goes when the keys come. The voice thread's own take-back
/// (`network::key_news`) may say it again; the front end ignores the second.
fn install_voice(
    ring: &std::sync::Mutex<MediaKeyRing>,
    voice: &[voipc_crypto::group_state::VoiceKeys],
    own: u32,
    emit: impl FnOnce(serde_json::Value),
) {
    let key_id = {
        let mut ring = ring.lock().unwrap_or_else(PoisonError::into_inner);
        let mut took = false;
        for keys in voice {
            took |= ring.install_gk(keys, own);
        }
        took.then(|| ring.current().map_or(0, |k| k.key_id))
    };
    if let Some(key_id) = key_id {
        emit(json!({ "channel_id": own, "key_id": key_id }));
    }
}

/// A past epoch kept history needs: its key into the account's sync, or word that there is
/// none. One still asked comes back in `GkOut::past_ready`.
fn past(
    conn: &GkLink,
    link: &AccountLink,
    group: &str,
    gen: [u8; 16],
    epoch: u32,
    todo: &mut VecDeque<Work>,
) {
    let got = conn.lock().gk.keying.past_epoch(group, gen, epoch);
    match got {
        PastEpoch::Ready(k) => todo.push_back(Work::acct(link.session().gk_past_in(&k))),
        PastEpoch::Unknown => {
            todo.push_back(Work::acct(link.session().gk_past_none(group, gen, epoch)))
        }
        PastEpoch::Asked => {}
    }
}

async fn account(conn: &GkLink, mut a: Actions, todo: &mut VecDeque<Work>) {
    let seat_keys = a.seat_keys.take();
    let floors = std::mem::take(&mut a.gk_floors);
    let asked = std::mem::take(&mut a.gk_past);
    crate::account::run(&conn.app, &conn.server, &conn.tcp_tx, a).await;
    let Some(link) = &conn.account else {
        return;
    };
    if let Some(keys) = seat_keys {
        let keys = {
            let mut sig = conn.lock();
            if sig.gk.started {
                Some(keys)
            } else {
                sig.gk.seat_keys = Some(keys);
                None
            }
        };
        let out = keys.and_then(|keys| {
            with_gk(conn, |k, st, c| {
                and_keep(k, st, c, |k, _| k.seat_keys_changed(keys))
            })
        });
        todo.extend(out.map(Work::Gk));
    }
    if floors {
        let tracked = conn.lock().gk.groups();
        let moved = link.session().gk_floors_moved(&tracked);
        let mut sig = conn.lock();
        for (group, f) in moved {
            todo.push_back(Work::Gk(sig.gk.keying.floors_in(&group, f)));
        }
    }
    if !asked.is_empty() {
        for (group, gen, epoch) in asked {
            past(conn, link, &group, gen, epoch, todo);
        }
        todo.push_back(Work::Gk(conn.lock().gk.keying.past_asks()));
    }
}

/// A post that opened, as the front end takes a channel post.
fn post_event(p: &OpenedPost) -> serde_json::Value {
    let msg = voipc_crypto::open_envelope(&p.envelope);
    json!({
        "channel_id": p.channel_id,
        "user_id": p.user_id,
        "username": p.username,
        "account": p.account,
        "is_admin": p.is_admin,
        "is_moderator": p.is_moderator,
        "content": msg.text,
        "timestamp": p.timestamp,
        "message_id": msg.id,
        "ttl_secs": msg.ttl_secs,
        "reply_to": msg.extras.reply,
        "thread": msg.extras.thread,
        "file": msg.extras.file,
        "fwd": msg.extras.fwd,
        "event": msg.extras.event,
        "encrypted": true,
    })
}

/// The floors to `gk_local.bin`, if they moved and this connection has a place there. One
/// being written by another task is on disk when this returns.
fn save(conn: &GkLink) {
    let state = conn.app.state::<AppState>();
    let guest = conn.account.is_none();
    let saved =
        tokio::task::block_in_place(|| state.gk_local.save(|| conn.lock().gk.unsaved(guest)));
    if let Err(e) = saved {
        warn!(server = %conn.server, "group key floors not kept: {e}");
    }
}

/// Our posts' kept copies, each under the epoch it went out under (C4), or offered again
/// under the head (`Copies::file`).
async fn file(conn: &GkLink, copies: Vec<(KeptCopy, GkEpoch)>) {
    let Some(link) = &conn.account else {
        return;
    };
    for (k, ep) in copies {
        let a = link
            .session()
            .outgoing_channel_gk(&k.log, k.envelope, k.sent_at, k.ttl_secs, ep);
        account_news(conn, a).await;
    }
}

// ── Frames ────────────────────────────────────────────────────────────────

/// `GroupKeys`: the group key starts, on the path the frame after `Authenticated` chose.
/// The account's seat keys come along, and after a reset with the recovery key they rotate
/// (3e): the first sign-in after one does it.
pub(crate) async fn group_keys(conn: &GkLink, on: bool, run: [u8; 16], clock: u64) {
    {
        let sig = conn.lock();
        if sig.gk.started || !matches!(sig.gk.path, Path::On | Path::Kept) {
            return;
        }
    }
    let state = conn.app.state::<AppState>();
    let mut first = None;
    let mut rotated = None;
    let mut account = None;
    if let Some(link) = &conn.account {
        let mut session = link.session();
        account = Some(session.account_id());
        first = Some(session.gk_on(on));
        let reset = (conn.server.to_string(), session.name().to_string());
        let rotate = on
            && state
                .gk_rotate
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(&reset);
        if rotate {
            rotated = Some(session.seat_keys_rotate());
        }
    }
    let seat_keys = first.as_mut().and_then(|a| a.seat_keys.take());
    let scope = conn.lock().gk.scope.clone();
    let local = scope
        .as_ref()
        .and_then(|s| tokio::task::block_in_place(|| state.gk_local.load(s)));
    let help_hold_keys = state.config().help_hold_keys;
    let out = tokio::task::block_in_place(|| {
        let mut sig = conn.lock();
        let identity = sig
            .stores
            .as_ref()
            .and_then(|s| s.identity.key_pair.to_identity_key_pair().ok());
        let Some(identity) = identity else {
            warn!(server = %conn.server, "no identity yet: the group key does not start");
            return None;
        };
        let user_id = sig.own_user_id.unwrap_or(0);
        let s = sig.gk.begin(GkStart {
            on,
            run,
            relay_clock: clock,
            platform: PLATFORM,
            help_hold_keys,
            user_id,
            identity,
            account,
            seat_keys,
            local,
            visible: true,
        });
        on_keying(conn, &mut sig, |k, st, c| {
            and_keep(k, st, c, |k, _| k.start(s))
        })
    });
    let Some(out) = out else {
        return;
    };
    carry_out(conn, out).await;
    for a in first.into_iter().chain(rotated) {
        account_news(conn, a).await;
    }
    conn.wake();
}

/// One of the group key's frames.
pub(crate) async fn frame(conn: &GkLink, msg: &ServerMessage) {
    if let ServerMessage::EpochReseated { n, left } = msg {
        if let Some(link) = &conn.account {
            let a = link.session().gk_reseated(*n, *left);
            account_news(conn, a).await;
        }
        return;
    }
    let taken = {
        let mut sig = conn.lock();
        if !sig.gk.started {
            return;
        }
        // A post's refusal to the copies before the group key sends it again
        sig.gk.copies.refused(msg);
        sig.gk.copies.taken(msg)
    };
    if matches!(msg, ServerMessage::EpochPostTaken { .. }) {
        // The relay took a post of ours: its kept copy is filed now, not at the next tick, so
        // an app closed a moment after posting still keeps it
        file(conn, taken.into_iter().collect()).await;
        return;
    }
    if let Some(out) = with_gk(conn, |k, st, c| k.frame(st, msg, c)) {
        carry_out(conn, out).await;
    }
    // A due, a keyring or a list may have left the keyholder work to do
    conn.wake();
}

/// Who is who here, from every roster the relay sends.
pub(crate) fn note_roster(conn: &GkLink, rows: &[UserInfo]) {
    if !rows.is_empty() {
        conn.lock().gk.roster.note(rows);
    }
}

/// Someone left a voice room, or the server: not online for the keyholder line.
pub(crate) fn user_gone(conn: &GkLink, user_id: u32) {
    conn.lock().gk.roster.users.remove(&user_id);
}

/// Tracks `channel_id` as a group of `kind`, if this connection keys such channels and the
/// list knows it. The account's vault floor for a stored group comes along, and the posts
/// that waited for it go.
fn track_channel(conn: &GkLink, sig: &mut SignalState, channel_id: u32, kind: GroupKind) -> GkOut {
    if !sig.gk.wants(kind) {
        return GkOut::default();
    }
    let t = {
        let list = conn.channels.lock().unwrap_or_else(PoisonError::into_inner);
        match list.iter().find(|c| c.channel_id == channel_id) {
            Some(info) => sig.gk.track_of(info, kind),
            None => return GkOut::default(),
        }
    };
    let vault = match &conn.account {
        Some(link) if kind == GroupKind::Text => link.session().gk_floor(&t.group),
        _ => VaultFloor::None,
    };
    let out = sig.gk.track(t, vault);
    let posts = on_net(conn, sig, |net, st, pins, now| {
        net.tracked_now(st, pins, channel_id, now)
    });
    then(out, posts.unwrap_or_default())
}

/// `TextJoined`: the text channels this connection is in now, and those refused.
pub(crate) async fn text_joined(conn: &GkLink, joined: &[(u32, bool, bool, u64)], refused: &[u32]) {
    let outs: Vec<GkOut> = {
        let mut sig = conn.lock();
        let gone = refused
            .iter()
            .map(|c| sig.gk.join_refused(*c))
            .collect::<Vec<_>>();
        let mut outs = gone;
        for (channel_id, ..) in joined {
            outs.push(track_channel(conn, &mut sig, *channel_id, GroupKind::Text));
        }
        outs
    };
    for out in outs {
        carry_out(conn, out).await;
    }
}

/// The channel list moved (a whole list, one channel updated): each tracked channel is
/// tracked again as it stands now, and one that is gone is not.
pub(crate) async fn channels_changed(conn: &GkLink) {
    let outs: Vec<GkOut> = {
        let mut sig = conn.lock();
        let tracked: Vec<(u32, GroupKind)> = sig
            .gk
            .tracked
            .iter()
            .map(|(c, (kind, _))| (*c, *kind))
            .collect();
        let mut outs = Vec::new();
        for (channel_id, kind) in tracked {
            let listed = conn
                .channels
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .iter()
                .any(|c| c.channel_id == channel_id);
            if listed {
                outs.push(track_channel(conn, &mut sig, channel_id, kind));
            } else {
                outs.extend(sig.gk.untrack(channel_id));
            }
        }
        outs
    };
    for out in outs {
        carry_out(conn, out).await;
    }
}

/// Out of a channel (left, evicted, deleted): its held posts are given up.
pub(crate) async fn untrack(conn: &GkLink, channel_id: u32) {
    let out = conn.lock().gk.untrack(channel_id);
    if let Some(out) = out {
        carry_out(conn, out).await;
    }
}

/// The relay confirmed a move between voice rooms: the room left is no group of ours any
/// more, and the one entered is (its chat; its voice keys are V3's).
pub(crate) async fn room_changed(conn: &GkLink, old: u32, new: u32) {
    let outs: Vec<GkOut> = {
        let mut sig = conn.lock();
        let mut outs: Vec<GkOut> = sig.gk.untrack(old).into_iter().collect();
        if new != 0 {
            outs.push(track_channel(conn, &mut sig, new, GroupKind::Voice));
        }
        outs
    };
    for out in outs {
        carry_out(conn, out).await;
    }
}

// ── Posts and switches ────────────────────────────────────────────────────

/// A post of ours in `channel_id` under the group key. `kept`: its log's copy, filed under
/// the epoch it goes under once it does (`GkOut::released`, C4), with when it was written
/// and its timer. A channel whose group is not tracked yet (its join not answered) holds it
/// until it is (`Early`).
pub(crate) async fn post(
    conn: &GkLink,
    channel_id: u32,
    envelope: &[u8],
    kept: Option<(String, u64, Option<u32>)>,
) -> Result<(), String> {
    if let Some(said) = not_sent(channel_id, envelope) {
        emit_server(&conn.app, &conn.server, "channel-not-sent", said);
        return Ok(());
    }
    let post = EarlyPost {
        post_id: rand::random(),
        envelope: envelope.to_vec(),
        copy: kept.map(|(log, sent_at, ttl_secs)| KeptCopy {
            log,
            envelope: envelope.to_vec(),
            sent_at,
            ttl_secs,
        }),
    };
    let out = tokio::task::block_in_place(|| {
        on_net(conn, &mut conn.lock(), |net, st, pins, now| {
            net.post(st, pins, channel_id, post, now)
        })
    })
    .ok_or("E2E encryption not initialized")?;
    carry_out(conn, out).await;
    Ok(())
}

/// A post the relay would refuse as too large, sealed under the key (a forward of a long
/// message, say: the composer counts only what is typed), goes nowhere, its kept copy with it:
/// `channel-not-sent`, under the message id its envelope carries, so its row (shown as sent by
/// `send_channel_message`, before or after this) says so. The relay's refusal would name no
/// message (`EarlyPost::fits`, the group key's own rule). `None`: it goes.
fn not_sent(channel_id: u32, envelope: &[u8]) -> Option<serde_json::Value> {
    if EarlyPost::fits(envelope.len(), true) {
        return None;
    }
    let id = voipc_crypto::open_envelope(envelope).id;
    Some(not_sent_said(channel_id, id))
}

/// `channel-not-sent` for message `id` in `channel_id`, in the relay's words (also the old
/// path's, network.rs `drain_pending_channel_messages`).
pub(crate) fn not_sent_said(channel_id: u32, id: Option<String>) -> serde_json::Value {
    json!({ "channel_id": channel_id, "message_id": id, "reason": EarlyPost::TOO_LARGE })
}

/// "Help hold keys" switched while connected.
pub(crate) async fn set_volunteer(conn: &GkLink, on: bool) {
    if !conn.lock().gk.started {
        return;
    }
    let out = with_gk(conn, |k, st, c| {
        and_keep(k, st, c, |k, _| k.set_volunteer(on))
    });
    if let Some(out) = out {
        carry_out(conn, out).await;
    }
    conn.wake();
}

/// The connection ends: posts still held are given up, a keyholder's resigns go before the
/// `Disconnect`, copies the relay did not say it took are given up (`Copies::end`), and the
/// floors are kept.
pub(crate) async fn end(conn: &GkLink) {
    let out = {
        let mut sig = conn.lock();
        if !sig.gk.started {
            return;
        }
        sig.gk.started = false;
        // A copy is kept only on the relay's word that it took the post (`Copies::end`)
        sig.gk.copies.end();
        let early = sig.gk.early.end();
        then(sig.gk.keying.end(), early)
    };
    carry_out(conn, out).await;
    save(conn);
}

// ── The task ──────────────────────────────────────────────────────────────

/// The group key's own clock beside `live_task`: a tick a second (and the past epochs kept
/// history asked for), a keyholder's builds on a blocking thread off the lock, its uploads
/// one frame at a time and in a call a pause as long as the frame took (`live_task`'s
/// rule), and the floors saved. Ends on a relay below 26 and with the connection.
pub(crate) async fn gk_task(conn: GkLink) {
    let wake = conn.lock().gk.wake.clone();
    let mut second = tokio::time::interval(Duration::from_secs(1));
    second.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        let save_in =
            conn.lock().gk.dirty_since.map(|since| {
                (since + SAVE_WITHIN_MS).saturating_sub(voipc_crypto::time::now_millis())
            });
        tokio::select! {
            _ = second.tick() => {
                let path = conn.lock().gk.path;
                match path {
                    Path::Legacy => return,
                    Path::Waiting => continue,
                    Path::On | Path::Kept => tick(&conn).await,
                }
            }
            _ = wake.notified() => {}
            _ = tokio::time::sleep(Duration::from_millis(save_in.unwrap_or(0))), if save_in.is_some() => {}
        }
        if conn.tcp_tx.is_closed() {
            return;
        }
        let due = conn
            .lock()
            .gk
            .dirty_since
            .is_some_and(|since| voipc_crypto::time::now_millis() >= since + SAVE_WITHIN_MS);
        if due {
            save(&conn);
        }
        builds(&conn).await;
        if !uploads(&conn).await {
            return;
        }
    }
}

async fn tick(conn: &GkLink) {
    let started = conn.lock().gk.started;
    if !started {
        return;
    }
    if let Some(out) = with_gk(conn, |k, st, c| k.tick(st, c)) {
        carry_out(conn, out).await;
    }
    let (out, due) = {
        let mut sig = conn.lock();
        let now = voipc_crypto::time::now_millis();
        let GkNet {
            keying,
            copies,
            early,
            ..
        } = &mut sig.gk;
        let out = then(keying.past_asks(), early.tick(now));
        let due = copies.file(now, |group| keying.current_epoch(group));
        (out, due)
    };
    carry_out(conn, out).await;
    file(conn, due).await;
}

/// Every keyholder job waiting, each stepped to its end on a blocking thread while the lock is
/// free (a job whose due went stops at its next step).
async fn builds(conn: &GkLink) {
    loop {
        let job = conn.lock().gk.keying.take_build();
        let Some(mut job) = job else {
            return;
        };
        let built = tokio::task::spawn_blocking(move || loop {
            if let Some(b) = job.step(BUILD_STEP) {
                return b;
            }
        })
        .await;
        let b = match built {
            Ok(b) => b,
            Err(e) => {
                warn!(server = %conn.server, "a keyholder build failed: {e}");
                continue;
            }
        };
        if let Some(out) = with_gk(conn, |k, st, c| and_keep(k, st, c, |k, c| k.built(b, c))) {
            carry_out(conn, out).await;
        }
    }
}

/// A keyholder's uploads, paced: one frame queued at a time. `false`: the connection went.
async fn uploads(conn: &GkLink) -> bool {
    loop {
        conn.tcp_tx.drained().await;
        let in_call = conn.is_voice.load(Ordering::Relaxed);
        let now = voipc_crypto::time::now_millis();
        let frame = conn.lock().gk.keying.next_frame(now, in_call);
        let Some(frame) = frame else {
            return true;
        };
        if under_head(&frame) {
            save(conn);
        }
        let sent = std::time::Instant::now();
        if conn.tcp_tx.send(&frame).is_err() {
            return false;
        }
        conn.tcp_tx.drained().await;
        if in_call {
            let pause = sent.elapsed().min(Duration::from_secs(10));
            tokio::time::sleep(pause).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use voipc_crypto::group_state::GkEvent;
    use voipc_protocol::gk::{refused_what, refused_why};

    fn group_keys(on: bool, run: [u8; 16]) -> ServerMessage {
        ServerMessage::GroupKeys {
            on,
            run,
            clock: 1_700_000_000,
        }
    }

    fn started(path_frame: ServerMessage, run: [u8; 16]) -> GkNet {
        let mut net = GkNet::default();
        net.first_frame(&path_frame);
        let on = net.path == Path::On;
        let s = net.begin(GkStart {
            on,
            run,
            relay_clock: 1_700_000_000,
            platform: Platform::Phone,
            help_hold_keys: false,
            user_id: 5,
            identity: voipc_crypto::generate_identity_key_pair(),
            account: None,
            seat_keys: None,
            local: None,
            visible: true,
        });
        let _ = net.keying.start(s);
        net
    }

    fn channel(channel_id: u32, text: bool, log: &str) -> ChannelInfo {
        ChannelInfo {
            channel_id,
            text,
            log: log.into(),
            ..Default::default()
        }
    }

    #[test]
    fn the_frame_after_authenticated_chooses_the_path_once() {
        let mut on = GkNet::default();
        on.first_frame(&group_keys(true, [1; 16]));
        on.first_frame(&ServerMessage::ChannelList { channels: vec![] });
        assert_eq!(on.path, Path::On);
        assert!(on.on());

        let mut off = GkNet::default();
        off.first_frame(&group_keys(false, [1; 16]));
        assert_eq!(off.path, Path::Kept);
        assert!(
            !off.on(),
            "off: posts take the legacy paths, kept history is read"
        );

        // A relay below 26 sends no GroupKeys: whatever comes first is the old paths', and a
        // GroupKeys after it starts nothing
        let mut old = GkNet::default();
        old.first_frame(&ServerMessage::ChannelList { channels: vec![] });
        old.first_frame(&group_keys(true, [1; 16]));
        assert_eq!(old.path, Path::Legacy);
        assert!(!old.on());
    }

    #[test]
    fn with_the_key_off_only_text_channels_are_tracked_for_kept_history() {
        let on = started(group_keys(true, [1; 16]), [1; 16]);
        assert!(on.wants(GroupKind::Text) && on.wants(GroupKind::Voice));
        let off = started(group_keys(false, [1; 16]), [1; 16]);
        assert!(off.wants(GroupKind::Text) && !off.wants(GroupKind::Voice));
        let mut old = GkNet::default();
        old.first_frame(&ServerMessage::ChannelList { channels: vec![] });
        assert!(!old.wants(GroupKind::Text) && !old.wants(GroupKind::Voice));
    }

    #[test]
    fn a_channel_with_a_log_is_its_stored_group_and_a_voice_room_never_is() {
        let net = started(group_keys(true, [0xab; 16]), [0xab; 16]);
        let stored = net.track_of(&channel(7, true, "c:77"), GroupKind::Text);
        assert_eq!(stored.group, "c:77");
        assert!(stored.keeps_history);
        let run = "ab".repeat(16);
        let memory = net.track_of(&channel(8, true, ""), GroupKind::Text);
        assert_eq!(memory.group, format!("r:{run}:8"));
        let room = net.track_of(&channel(9, false, "c:99"), GroupKind::Voice);
        assert_eq!(room.group, format!("r:{run}:9"));
        assert!(!room.keeps_history);
    }

    #[test]
    fn a_frame_for_one_servers_group_never_reaches_another_servers() {
        // Two relays, the same channel id on both: two connections, two groups
        let (run_a, run_b) = ([1; 16], [2; 16]);
        let mut a = started(group_keys(true, run_a), run_a);
        let mut b = started(group_keys(true, run_b), run_b);
        for net in [&mut a, &mut b] {
            let t = net.track_of(&channel(7, true, ""), GroupKind::Text);
            let _ = net.track(t, VaultFloor::None);
        }
        assert_ne!(a.groups(), b.groups());
        let refused = ServerMessage::EpochRefused {
            group: a.groups()[0].clone(),
            what: refused_what::POST,
            why: refused_why::NOT_MEMBER,
            detail: "not a member".into(),
        };
        let identity = voipc_crypto::generate_identity_key_pair();
        let mut stores = SignalStores::new(&identity, 1);
        let mut frame = |net: &mut GkNet| {
            let GkNet { keying, guest, .. } = net;
            let c = GkCtx {
                pins: guest,
                now: voipc_crypto::time::now_millis(),
            };
            keying.frame(&mut stores, &refused, c).events
        };
        let told = frame(&mut a);
        assert!(
            told.iter()
                .any(|e| matches!(e, GkEvent::State { channel_id: 7, .. })),
            "{told:?}"
        );
        assert!(
            frame(&mut b).is_empty(),
            "the other relay's group is untouched"
        );
    }

    #[test]
    fn untracking_a_channel_not_tracked_says_nothing() {
        let mut net = started(group_keys(true, [1; 16]), [1; 16]);
        assert!(net.untrack(3).is_none());
        let t = net.track_of(&channel(3, true, ""), GroupKind::Text);
        let _ = net.track(t, VaultFloor::None);
        assert!(net.untrack(3).is_some());
        assert!(net.groups().is_empty());
    }

    fn early(id: u8) -> EarlyPost {
        EarlyPost {
            post_id: [id; 16],
            envelope: voipc_crypto::envelope::envelope(&format!("m{id}"), "hi", None),
            copy: Some(KeptCopy {
                log: "c:77".into(),
                envelope: vec![id],
                sent_at: 1,
                ttl_secs: None,
            }),
        }
    }

    fn dropped(out: &GkOut) -> usize {
        out.events
            .iter()
            .filter(|e| matches!(e, GkEvent::PostDropped { .. }))
            .count()
    }

    /// G (J8F): a post sent before its channel's group is tracked (its `TextJoined` not in
    /// yet) is not dropped at once as "late": it waits, and goes to the group key once the
    /// channel is tracked, its kept copy with it. One to a channel the relay does not let us
    /// into is dropped then, the refusal told first.
    #[test]
    fn a_post_before_its_channel_is_tracked_goes_to_the_group_key_once_it_is() {
        use voipc_crypto::group_state::{GkState, JOIN_REFUSED};
        let mut net = started(group_keys(true, [1; 16]), [1; 16]);
        let identity = voipc_crypto::generate_identity_key_pair();
        let mut stores = SignalStores::new(&identity, 5);
        let now = voipc_crypto::time::now_millis();
        let out = net.post(&mut stores, None, 7, early(1), now);
        assert_eq!(dropped(&out), 0, "not dropped: {:?}", out.events);
        assert!(out.send.is_empty());
        assert_eq!(
            out.events,
            [GkEvent::State {
                channel_id: 7,
                state: GkState::Late { waiting: true }
            }]
        );
        // Tracked: the post goes to the group key, which holds it for the channel's keys
        let t = net.track_of(&channel(7, true, "c:77"), GroupKind::Text);
        let _ = net.track(t, VaultFloor::None);
        let out = net.tracked_now(&mut stores, None, 7, now);
        assert_eq!(dropped(&out), 0);
        assert!(
            out.events.contains(&GkEvent::State {
                channel_id: 7,
                state: GkState::Late { waiting: true }
            }),
            "the group key holds it: {:?}",
            out.events
        );
        assert!(net.tracked_now(&mut stores, None, 7, now).events.is_empty());
        assert_eq!(
            net.copies.went_under(&[1; 16]),
            Some(None),
            "its copy waits"
        );
        // The group key has it: it gives it up at `HOLD_MS` with no keys
        let c = GkCtx {
            pins: &mut net.guest,
            now: now + voipc_crypto::group_key::timers::HOLD_MS,
        };
        assert_eq!(dropped(&net.keying.tick(&mut stores, c)), 1);
        // A channel that does not let us in
        let _ = net.post(&mut stores, None, 8, early(2), now);
        let out = net.join_refused(8);
        assert_eq!(
            out.events,
            [
                GkEvent::State {
                    channel_id: 8,
                    state: GkState::Refused(JOIN_REFUSED.into())
                },
                GkEvent::PostDropped {
                    channel_id: 8,
                    why: voipc_crypto::group_state::Dropped::Refused
                }
            ]
        );
    }

    /// Item J9W-1: a post past what the relay takes, sealed under the key, is said not sent
    /// under its envelope's message id, the relay's words why; one that fits goes.
    #[test]
    fn a_post_too_large_sealed_is_said_not_sent_under_its_message_id() {
        let id = voipc_crypto::new_message_id();
        let long = voipc_crypto::envelope::envelope(&id, &"z".repeat(16 * 1024), None);
        assert_eq!(
            not_sent(7, &long),
            Some(json!({
                "channel_id": 7,
                "message_id": id,
                "reason": "post too large: one message holds at most 16 KiB",
            }))
        );
        let short = voipc_crypto::envelope::envelope(&id, &"z".repeat(15 * 1024), None);
        assert_eq!(not_sent(7, &short), None);
    }

    #[test]
    fn what_a_keyholder_keeps_is_saved_before_its_pair_is_offered() {
        let identity = voipc_crypto::generate_identity_key_pair();
        let now = voipc_crypto::time::now_millis();
        let start = |local: Option<LocalGk>, help_hold_keys: bool| GkStart {
            on: true,
            run: [1; 16],
            relay_clock: now / 1000,
            platform: Platform::Desktop,
            help_hold_keys,
            user_id: 5,
            identity,
            account: Some([9; 16]),
            seat_keys: Some(SeatKeys::generate(1, now / 1000)),
            local,
            visible: true,
        };
        let offered = |send: &[ClientMessage]| {
            send.iter().find_map(|m| match m {
                ClientMessage::KeyholdVolunteer { pair: Some(p), .. } => Some(p.clone()),
                _ => None,
            })
        };
        let mut stores = SignalStores::new(&identity, 1);
        let mut pins = MemoryPins::default();
        // At the start, and when "Help hold keys" is switched on later
        for later in [false, true] {
            let mut k = GroupKeying::default();
            let ctx = GkCtx {
                pins: &mut pins,
                now,
            };
            let out = if later {
                let _ = k.start(start(None, false));
                and_keep(&mut k, &mut stores, ctx, |k, _| k.set_volunteer(true))
            } else {
                and_keep(&mut k, &mut stores, ctx, |k, _| k.start(start(None, true)))
            };
            let pair = offered(&out.send).expect("a desktop account volunteers its pair");
            assert!(out.local_dirty, "saved before the volunteer goes");
            // The app is killed once it went: what was saved is all the next run has
            let mut next = GroupKeying::default();
            let again = next.start(start(k.local().cloned(), true));
            assert_eq!(
                offered(&again.send),
                Some(pair),
                "the pair the relay holds, not a new one"
            );
        }
    }

    /// V3's gap: the room's keys from its epoch key say `media-key-installed`, once for what
    /// one `GkOut` hands over and with the ring's lock let go, so the "waiting for the
    /// channel's key" line the voice thread raised goes when they come. Keys the ring does not
    /// take (another room's) say nothing.
    #[test]
    fn voice_keys_the_ring_takes_say_media_key_installed_once() {
        use crate::network::tests::{voice_keys, Epoch, ROOM};
        let e1: Epoch = (1, rand::random(), rand::random());
        let ring = std::sync::Mutex::new(MediaKeyRing::default());
        // A welcome and a roster update in one out
        let keys = [
            voice_keys(1, &[e1], &[1, 2]),
            voice_keys(1, &[e1], &[1, 2, 3]),
        ];
        let mut said = Vec::new();
        install_voice(&ring, &keys, ROOM, |payload| {
            assert!(ring.try_lock().is_ok(), "told with the ring's lock let go");
            said.push(payload);
        });
        assert_eq!(said, [json!({ "channel_id": ROOM, "key_id": 1 })]);
        assert!(
            ring.lock().unwrap().current().is_some(),
            "and the ring took them"
        );

        said.clear();
        install_voice(&ring, &keys, ROOM + 1, |payload| said.push(payload));
        assert!(said.is_empty(), "another room's keys: {said:?}");
    }
}
