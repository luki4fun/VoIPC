//! Dive 2 (keyholder liveness, 2026-11-25): states in which a kept channel cannot move on.
//! New file, product code unchanged. The harness below is `gk_e2e_j10b.rs`'s, copied (its
//! items are private to that module): an accounts relay, each account's browser page with
//! its `AccountSync` and vault, "Help hold keys" on, builds run whole, a paused tokio clock
//! that moves only by the test's steps. Added here: `World::pass` (a long quiet time in
//! large steps) and `World::post_goes`.
//!
//! The tests are at the end of the file.
#![allow(dead_code)]

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use l4f_accounts::model::{AccountId, NewUser};
use l4f_accounts::store::Store;
use voipc_crypto::account::{SignedIn, Vault};
use voipc_crypto::envelope::{envelope, open_envelope};
use voipc_crypto::group_key::wire::post_digest;
use voipc_crypto::group_key::GroupKind;
use voipc_crypto::group_state::{
    GkCtx, GkEpoch, GkEvent, GkOut, GkStart, GkTrack, GroupKeying, LocalGk, MemoryPins, PastEpoch,
    Platform, VaultFloor,
};
use voipc_crypto::log::LogKey;
use voipc_crypto::sync::{AccountSync, Event, LogMemory, Prefs, ITEM_LOGKEY};
use voipc_crypto::{generate_identity_key_pair, IdentityKeyPair, SignalStores};
use voipc_protocol::codec::PROTOCOL_VERSION;
use voipc_protocol::gk::{refused_what, refused_why, GkMember};
use voipc_protocol::messages::{AccountRequest, ClientMessage, ServerMessage};
use voipc_protocol::types::{ChannelId, GroupLoad, UserId, VaultBlob};

use super::gk_e2e_tests::{account_session, drop_db, scratch_db, show, tracing_on};
use crate::config::{AccountsConfig, AccountsMode, ServerConfig};
use crate::control::{ControlRx, ControlTx};
use crate::settings::ServerSettings;
use crate::state::{RateLimiter, ServerState};

const CHAN: ChannelId = 12;
const CONV: &str = "c:d2kept";

use super::gk_e2e_j8h::SEATED_AT_ONCE_MS;

/// F2 in a voice room: its own harness (`gk_e2e_v2.rs`'s, copied).
#[path = "gk_e2e_d2_voice.rs"]
mod voice;
/// The longest the relay's work may stay under way before a step (`gk_e2e_j8h.rs`).
const BUSY_MAX: Duration = Duration::from_secs(120);

fn raw(ik: &IdentityKeyPair) -> [u8; 32] {
    ik.public_key().public_key_bytes().try_into().unwrap()
}

/// N1's kept copy of one post of ours (gk_net.rs `KeptPost`).
struct KeptCopy {
    envelope: Vec<u8>,
    sent_at: u64,
    /// Its latest `released`: under what, and `post_digest` of the bytes it went as.
    went: Option<(GkEpoch, [u8; 16])>,
}

/// One account's browser page on one connection.
struct Person {
    name: String,
    a: [u8; 16],
    signed: SignedIn,
    sid: UserId,
    sync: AccountSync,
    keying: GroupKeying,
    st: SignalStores,
    pins: MemoryPins,
    out: VecDeque<ClientMessage>,
    /// Past epochs handed to `GroupKeying` whose key has not come yet.
    past: Vec<(String, [u8; 16], u32)>,
    /// What its kept reads opened.
    texts: Vec<String>,
    online: bool,
    copies: HashMap<[u8; 16], KeptCopy>,
    /// Past epochs the relay said it does not keep (`EpochRefused{FETCH, NOT_STORED}`).
    not_stored: usize,
    /// What the group key told the page (`gk-state` and the rest).
    events: Vec<GkEvent>,
    /// The app it runs in: a browser page, or a desktop app (its own keyholder pair, 0x03).
    platform: Platform,
    /// How far its device's clock is ahead of the relay's, seconds (`Duty::start` reads
    /// the relay's clock off `GroupKeys` against the device's own).
    clock_ahead: i64,
    /// The dues the relay asked it, by kind (`due_code`), first parts only.
    dues: Vec<u8>,
    /// `EpochFetch`es it sent.
    fetches: usize,
    /// What the device kept from its last run (a desktop's `gk_local.bin`: its keyholder
    /// pair), handed to the next start. A browser page keeps nothing.
    local: Option<LocalGk>,
    /// `EpochDecline`s it sent, by reason (`gk::decline`).
    declines: Vec<u8>,
    /// How far the device's clock is off the true time, ms (ahead when positive): every
    /// call of its group keying reads the time off this clock, as an app does.
    clock_off_ms: i64,
}

impl Person {
    /// One `GkOut`, and what its builds make: a browser's build loop runs each job to its end
    /// (session.ts `gkBuild`), its commit parts and pages go as `next_frame` hands them.
    fn took(&mut self, out: GkOut, now: u64) {
        let mut outs = vec![out];
        while let Some(out) = outs.pop() {
            // The `EpochPost`s and `released` go one for one (`group_state::Copies::sent`)
            let mut posts = out.send.iter().filter_map(|m| match m {
                ClientMessage::EpochPost { ciphertext, .. } => Some(post_digest(ciphertext)),
                _ => None,
            });
            for (_, post_id, ep) in out.released {
                let Some(post) = posts.next() else {
                    break;
                };
                if let Some(c) = self.copies.get_mut(&post_id) {
                    c.went = Some((ep, post));
                }
            }
            self.events.extend(out.events);
            self.out.extend(out.send);
            if !out.vault_floors.is_empty() {
                let put = self.sync.gk_put_floors(out.vault_floors);
                self.out.extend(put);
            }
            if !out.self_rows.is_empty() {
                let rows = self.sync.gk_self_rows(out.self_rows);
                self.out.extend(rows);
            }
            if out.seat_keys_wanted {
                let again = self.sync.seat_keys_wanted();
                self.out.extend(again);
            }
            while let Some(mut job) = self.keying.take_build() {
                let b = loop {
                    if let Some(b) = job.step(Duration::from_millis(8)) {
                        break b;
                    }
                };
                let c = GkCtx {
                    pins: &mut self.pins,
                    now,
                };
                outs.push(self.keying.built(b, c));
            }
        }
        while let Some(m) = self.keying.next_frame(now, false) {
            self.out.push_back(m);
        }
    }

    fn sync_events(&mut self, events: Vec<Event>) {
        for e in events {
            if let Event::ChannelMessage { envelope, .. } = e {
                self.texts.push(open_envelope(&envelope).text);
            }
        }
    }

    /// The time by this device's clock.
    fn dev(&self, now: u64) -> u64 {
        (now as i64 + self.clock_off_ms) as u64
    }

    fn frame(&mut self, f: &ServerMessage, now: u64) {
        let now = self.dev(now);
        if tracing_on() {
            eprintln!("[{now}] {} {} <- {}", self.name, self.sid, show(f));
        }
        match f {
            ServerMessage::Account(r) => {
                if let Some((out, events)) = self.sync.on_reply(r) {
                    self.out.extend(out);
                    self.sync_events(events);
                }
            }
            ServerMessage::EpochReseated { n, left } => {
                let out = self.sync.gk_reseated(*n, *left);
                self.out.extend(out);
            }
            ServerMessage::EpochPostTaken { group, post } => {
                // As the apps do (`group_state::Copies::taken`): its copy is filed now, under
                // the epoch that send went under
                let id = self
                    .copies
                    .iter()
                    .find(|(_, c)| c.went.as_ref().is_some_and(|w| w.1 == *post))
                    .map(|(id, _)| *id)
                    .filter(|_| group == CONV);
                if let Some(c) = id.and_then(|id| self.copies.remove(&id)) {
                    let (ep, _) = c.went.expect("it went");
                    let kept = self
                        .sync
                        .send_channel_gk(CONV, c.envelope, c.sent_at, None, ep);
                    self.out.extend(kept);
                }
            }
            f => {
                if let ServerMessage::EpochDue { part: 0, piece, .. } = f {
                    self.dues.push(piece.kind);
                }
                match f {
                    ServerMessage::EpochRefused {
                        what: refused_what::POST,
                        why: refused_why::OLD_EPOCH | refused_why::RATE,
                        ..
                    } => {
                        for c in self.copies.values_mut() {
                            c.went = None;
                        }
                    }
                    ServerMessage::EpochRefused {
                        what: refused_what::FETCH,
                        why: refused_why::NOT_STORED,
                        ..
                    } => self.not_stored += 1,
                    _ => {}
                }
                let c = GkCtx {
                    pins: &mut self.pins,
                    now,
                };
                let out = self.keying.frame(&mut self.st, f, c);
                self.took(out, now);
            }
        }
    }

    fn tick(&mut self, now: u64) {
        let now = self.dev(now);
        let (out, events) = self.sync.tick();
        self.out.extend(out);
        self.sync_events(events);
        let c = GkCtx {
            pins: &mut self.pins,
            now,
        };
        let out = self.keying.tick(&mut self.st, c);
        self.took(out, now);
    }

    /// N1/W2's glue for a kept read, and the vault's floors to `GroupKeying` (gk.rs `settle`).
    fn pasts(&mut self, now: u64) {
        let now = self.dev(now);
        if self.sync.take_gk_news() {
            for (group, f) in self.sync.gk_floors_moved(&[CONV.to_string()]) {
                let out = self.keying.floors_in(&group, f);
                self.took(out, now);
            }
        }
        let new = self.sync.take_gk_past();
        self.past.extend(new);
        for (group, gen, epoch) in std::mem::take(&mut self.past) {
            match self.keying.past_epoch(&group, gen, epoch) {
                PastEpoch::Ready(ep) => {
                    let (out, events) = self.sync.gk_past_in(&ep);
                    self.out.extend(out);
                    self.sync_events(events);
                }
                PastEpoch::Unknown => {
                    let out = self.sync.gk_past_none(&group, gen, epoch);
                    self.out.extend(out);
                }
                PastEpoch::Asked => self.past.push((group, gen, epoch)),
            }
        }
        let out = self.keying.past_asks();
        self.took(out, now);
    }

    /// The head epoch it holds `CK` of.
    fn epoch(&self) -> Option<u32> {
        self.keying.current_epoch(CONV).map(|e| e.epoch)
    }

    /// A post in the channel, its kept copy waiting for the epoch it goes under.
    fn post(&mut self, id: u8, text: &str, now: u64) {
        let now = self.dev(now);
        let env = envelope(&format!("d2-{id}"), text, None);
        self.copies.insert(
            [id; 16],
            KeptCopy {
                envelope: env.clone(),
                sent_at: now,
                went: None,
            },
        );
        let c = GkCtx {
            pins: &mut self.pins,
            now,
        };
        let out = self.keying.post(&mut self.st, CHAN, [id; 16], &env, c);
        self.took(out, now);
    }

    fn read_done(&self) -> bool {
        self.past.is_empty()
    }
}

/// A relay with accounts, the group key on, and text channel `CHAN` keeping log `CONV`.
async fn hall(db: &Store) -> Arc<ServerState> {
    let cfg = AccountsConfig {
        mode: AccountsMode::Optional,
        ..Default::default()
    };
    let relay = crate::accounts::Relay::open_with(&cfg, db.clone(), &[9u8; 32])
        .await
        .unwrap();
    let mut state = ServerState::new(
        &ServerConfig {
            group_key: true,
            ..Default::default()
        },
        ServerSettings::default(),
        vec![],
        "test-admin-token".into(),
    );
    state.accounts = Some(Arc::new(relay));
    let state = Arc::new(state);
    crate::gk_switch(&state, db, true).await.unwrap();
    crate::state::test_support::put_in_channel(&state, CHAN, &[]).await;
    {
        let mut channels = state.channels.write().await;
        let c = channels.get_mut(&CHAN).unwrap();
        c.info.text = true;
        c.info.log = CONV.into();
        c.log_conv = CONV.into();
    }
    state
}

/// Paused time that moves only when the test advances it (`gk_e2e_j8h.rs` `Gate`): a
/// blocking task in flight keeps tokio from jumping a paused clock to the next timer while
/// the runtime waits on the database.
struct Gate(Option<std::sync::mpsc::Sender<()>>);

impl Gate {
    fn hold() -> Gate {
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        tokio::task::spawn_blocking(move || {
            let _ = rx.recv();
        });
        Gate(Some(tx))
    }

    /// Real time for the relay's work before the clock moves on by `every` ms: a millisecond
    /// for each 100 ms of it, one at least.
    async fn settle(every: u64) {
        let real = every.div_ceil(100).max(1);
        tokio::task::spawn_blocking(move || std::thread::sleep(Duration::from_millis(real)))
            .await
            .unwrap();
    }
}

impl Drop for Gate {
    fn drop(&mut self) {
        self.0.take();
    }
}

/// A future's output if it is ready at its first poll: the pages' queues are drained so, not
/// by a zero timeout, which a paused clock never reaches (`gk_e2e_j8h.rs` `now_or_never`).
fn now_or_never<F: std::future::Future>(f: F) -> Option<F::Output> {
    let mut f = std::pin::pin!(tokio::task::unconstrained(f));
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    match std::future::Future::poll(f.as_mut(), &mut cx) {
        std::task::Poll::Ready(v) => Some(v),
        std::task::Poll::Pending => None,
    }
}

/// The relay and the accounts' pages. No keyholder of its own: the pages hold the keys.
struct World {
    _gate: Gate,
    /// The clock is paused: steps advance it.
    paused: bool,
    state: Arc<ServerState>,
    file: std::path::PathBuf,
    queues: HashMap<UserId, (ControlTx, Option<ControlRx>)>,
    people: Vec<Person>,
    followers: Vec<UserId>,
    last_tick: u64,
}

impl Drop for World {
    fn drop(&mut self) {
        drop_db(&self.file);
    }
}

impl World {
    async fn new() -> World {
        let _ = tracing_on();
        let gate = Gate::hold();
        let (db, file) = scratch_db().await;
        let state = hall(&db).await;
        World {
            _gate: gate,
            paused: false,
            state,
            file,
            queues: HashMap::new(),
            people: vec![],
            followers: vec![],
            last_tick: 0,
        }
    }

    fn relay(&self) -> &crate::accounts::Relay {
        self.state.accounts.as_ref().unwrap()
    }

    fn now(&self) -> u64 {
        self.state.gk.now()
    }

    /// From here on the clock moves only by the steps of `until`.
    fn pause(&mut self) {
        tokio::time::pause();
        self.paused = true;
    }

    fn load(&self) -> Option<GroupLoad> {
        self.state
            .gk
            .stats()
            .into_iter()
            .find(|g| g.channel_id == CHAN)
    }

    /// `(keyholders, keyholders_online)` of the group.
    fn holders(&self) -> (u32, u32) {
        self.load()
            .map_or((0, 0), |l| (l.keyholders, l.keyholders_online))
    }

    /// A connection in the channel, signed in to `account`.
    async fn session(&mut self, ik: &IdentityKeyPair, account: [u8; 16]) -> UserId {
        let (uid, sid) = crate::state::test_support::add_user(
            &self.state,
            &format!("u{}", rand::random::<u32>()),
        );
        let (tx, rx) = crate::control::control_queue(Arc::default());
        {
            let mut s = self.state.sessions.get_mut(&sid).unwrap();
            s.identity_key = Some([&[0x05u8][..], &raw(ik)].concat());
            s.control_tx = tx.clone();
            s.account_rate = RateLimiter::new(10_000.0, 10_000.0);
            s.log_read_rate = RateLimiter::new(10_000.0, 10_000.0);
            s.account = Some(account_session(account));
        }
        self.state.account_sessions.insert(account, sid);
        crate::state::test_support::put_in_channel(&self.state, CHAN, &[(uid, sid)]).await;
        self.state.gk.on_connect(sid, tx.clone());
        self.queues.insert(sid, (tx, Some(rx)));
        sid
    }

    fn follow(&mut self, sid: UserId, account: [u8; 16]) {
        self.state
            .gk
            .on_follow(CHAN, CONV, GroupKind::Text, sid, Some(account));
        self.followers.push(sid);
    }

    async fn drain(&mut self, sid: UserId) -> Vec<ServerMessage> {
        let mut got = vec![];
        let Some((_, Some(rx))) = self.queues.get_mut(&sid) else {
            return got;
        };
        while let Some(Some(b)) = now_or_never(rx.recv()) {
            got.push(voipc_protocol::codec::decode_server_msg(&b[4..]).unwrap());
        }
        got
    }

    /// What a session sends, where session.rs hands it.
    async fn send(&mut self, sid: UserId, msg: ClientMessage) {
        let tx = self.queues[&sid].0.clone();
        match msg {
            ClientMessage::Account(req) => {
                crate::accounts::handle_request(&self.state, sid, req, &tx)
                    .await
                    .unwrap();
            }
            ClientMessage::EpochPost {
                channel_id,
                group,
                gen,
                epoch,
                blob,
                ciphertext,
            } => {
                let checked = self
                    .state
                    .gk
                    .post_check(sid, &group, gen, epoch, blob.clone())
                    .await;
                let account = self
                    .people
                    .iter()
                    .find(|p| p.online && p.sid == sid)
                    .map(|p| p.a);
                if let Err(why) = checked {
                    let refused = ServerMessage::EpochRefused {
                        group,
                        what: refused_what::POST,
                        why,
                        detail: String::new(),
                    };
                    let _ = crate::session::send_msg(&tx, &refused);
                    return;
                }
                let taken = (group.clone(), post_digest(&ciphertext));
                let msg = ServerMessage::EpochPostIn {
                    channel_id,
                    group,
                    gen,
                    epoch,
                    user_id: sid,
                    username: format!("u{sid}"),
                    account,
                    is_admin: false,
                    is_moderator: false,
                    writer: account.map_or(GkMember::Conn(sid), GkMember::Account),
                    blob,
                    ciphertext,
                    timestamp: self.now(),
                };
                for f in self.followers.clone() {
                    if f != sid {
                        let _ = crate::session::send_msg(&self.queues[&f].0, &msg);
                    }
                }
                // As session.rs does once a post went: its writer is told
                crate::session::post_taken(&tx, taken);
            }
            m => self.state.gk.handle(&self.state, sid, m, &tx).await,
        }
    }

    /// A new account, its first browser page signed in with "Help hold keys" on (as the
    /// lane's sign-up): its seat keys made and published by the app, the channel tracked and
    /// its log kept.
    async fn person(&mut self, name: &str) -> usize {
        self.person_as(name, Platform::Browser, 0).await
    }

    /// The same in the app `platform`, on a device whose clock is `clock_ahead` seconds
    /// ahead of the relay's.
    async fn person_as(&mut self, name: &str, platform: Platform, clock_ahead: i64) -> usize {
        let id = AccountId::new();
        self.relay()
            .store()
            .create_user(
                &NewUser {
                    id,
                    username: name.into(),
                    display_name: name.into(),
                    email_pending: None,
                    password_hash: None,
                    created_at: l4f_accounts::util::now(),
                },
                None,
            )
            .await
            .unwrap();
        let identity = generate_identity_key_pair();
        self.relay()
            .set_identity(id, &identity.public_key().serialize())
            .await
            .unwrap();
        let logkey = LogKey::generate();
        let vault = Vault::create(self.relay().relay_id, name);
        let blobs = vec![VaultBlob {
            version: 1,
            ..vault.seal_item(ITEM_LOGKEY, 1, &logkey.to_bytes())
        }];
        let signed = SignedIn {
            relay_id: self.relay().relay_id,
            name: name.into(),
            vault,
            identity,
            recovery: None,
            binding: None,
            keyed: false,
            login_key: None,
            blobs,
        };
        let publish = ClientMessage::Account(AccountRequest::LogKeyPublish {
            logkey: logkey.public().to_vec(),
            sig: logkey.endorse(&identity).to_vec(),
        });
        let i = self.connect(name, id.0, signed).await;
        self.people[i].platform = platform;
        self.people[i].clock_ahead = clock_ahead;
        let sid = self.people[i].sid;
        self.send(sid, publish).await;
        let _ = self.drain(sid).await;
        self.start(i).await;
        i
    }

    /// The account's page on a new connection, from what the relay keeps of its vault.
    async fn connect(&mut self, name: &str, a: [u8; 16], signed: SignedIn) -> usize {
        let sid = self.session(&signed.identity, a).await;
        let (mut sync, first) = AccountSync::start(&signed, a, LogMemory::default(), false);
        sync.set_protocol(PROTOCOL_VERSION);
        let mut out: VecDeque<ClientMessage> = sync.pins_first().into_iter().collect();
        out.extend(first);
        out.extend(sync.set_prefs(Prefs {
            cloud: true,
            asked: true,
        }));
        out.extend(sync.gk_on(true));
        self.people.push(Person {
            name: name.into(),
            a,
            st: SignalStores::new(&signed.identity, sid),
            signed,
            sid,
            sync,
            keying: GroupKeying::default(),
            pins: MemoryPins::default(),
            out,
            past: vec![],
            texts: vec![],
            online: true,
            copies: HashMap::new(),
            not_stored: 0,
            events: vec![],
            platform: Platform::Browser,
            clock_ahead: 0,
            dues: vec![],
            fetches: 0,
            local: None,
            declines: vec![],
            clock_off_ms: 0,
        });
        self.people.len() - 1
    }

    /// The page's group key starts as a browser's, "Help hold keys" on (it volunteers), with
    /// the seat keys its `AccountSync` publishes; it tracks the channel with the vault's floor
    /// and keeps its log (`enter`, as the page's follow does).
    async fn start(&mut self, i: usize) {
        let settled = self
            .until(15_000, |w| {
                w.people[i].sync.seat_keys().is_some() && w.people[i].out.is_empty()
            })
            .await;
        assert!(settled, "seat keys settled");
        let mut vault = VaultFloor::Pending;
        for _ in 0..1_500 {
            vault = self.people[i].sync.gk_floor(CONV);
            if !matches!(vault, VaultFloor::Pending) {
                break;
            }
            self.until(10, |_| false).await;
        }
        assert!(
            !matches!(vault, VaultFloor::Pending),
            "the vault's floors are in"
        );
        let seat_keys = self.people[i].sync.seat_keys();
        let now = self.people[i].dev(self.now());
        let run = self.state.gk.run;
        let p = &mut self.people[i];
        let out = p.keying.start(GkStart {
            on: true,
            run,
            // The page's clock agrees with the relay's, as two machines on real time do.
            // `Duty::start` reads the device's real clock for its skew (holder.rs), while
            // this harness's relay runs on the paused clock: a page started after a long
            // `pass` would otherwise count that whole time as skew and decline every due
            // with `CLOCK` (seen in this file's first run; not the product's behaviour)
            relay_clock: (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64
                - p.clock_ahead) as u64,
            platform: p.platform,
            help_hold_keys: true,
            user_id: p.sid,
            identity: p.signed.identity,
            account: Some(p.a),
            seat_keys,
            local: p.local.take(),
            visible: true,
        });
        p.took(out, now);
        let out = p.keying.track(
            GkTrack {
                channel_id: CHAN,
                group: CONV.into(),
                kind: GroupKind::Text,
                anonymous: false,
                hide_members: false,
                viewer_admin: false,
                keeps_history: true,
            },
            vault,
        );
        p.took(out, now);
        let keep = p.sync.enter(CONV);
        p.out.extend(keep);
        let (sid, a) = (p.sid, p.a);
        self.follow(sid, a);
    }

    /// The page closes: its connection ends.
    async fn close(&mut self, i: usize) {
        // What the vault waits for goes first (a page's floors are saved within the minute)
        let flush = self.people[i].sync.gk_flush();
        self.people[i].out.extend(flush);
        let saved = self
            .until(15_000, |w| {
                w.people[i].out.is_empty() && w.people[i].sync.gk_saved()
            })
            .await;
        assert!(saved, "the floors are saved");
        let old = self.people[i].sid;
        assert!(self.people[i].online, "{} is online", self.people[i].name);
        self.people[i].online = false;
        let _ = self.people[i].keying.end();
        self.state.gk.on_session_end(old);
        self.followers.retain(|s| *s != old);
    }

    /// The account signs in again on a new browser page ("remembered" sign-in, or a reload):
    /// nothing kept but what the relay holds (its vault, the log).
    async fn again(&mut self, i: usize) {
        if self.people[i].online {
            self.close(i).await;
        }
        let held = self
            .relay()
            .vault(AccountId(self.people[i].a))
            .await
            .unwrap();
        let p = &mut self.people[i];
        let mut signed = SignedIn {
            relay_id: p.signed.relay_id,
            name: p.signed.name.clone(),
            vault: Vault::create(p.signed.relay_id, &p.signed.name),
            identity: p.signed.identity,
            recovery: None,
            binding: None,
            keyed: false,
            login_key: None,
            blobs: p.signed.blobs.clone(),
        };
        std::mem::swap(&mut signed.vault, &mut p.signed.vault);
        signed.blobs.retain(|b| b.k == ITEM_LOGKEY);
        signed.blobs.extend(held);
        let (a, name) = (p.a, p.name.clone());
        let (platform, clock_ahead) = (p.platform, p.clock_ahead);
        // A desktop app keeps `gk_local.bin` across its runs (its keyholder pair among it)
        let local = (platform == Platform::Desktop)
            .then(|| p.keying.local().cloned())
            .flatten();
        let j = self.connect(&name, a, signed).await;
        let mut back = self.people.remove(j);
        back.platform = platform;
        back.clock_ahead = clock_ahead;
        back.local = local;
        self.people[i] = back;
        self.start(i).await;
    }

    /// One round: every page's queue drained into it, what it sends handed over.
    async fn step(&mut self) {
        let now = self.now();
        let tick = now >= self.last_tick + 1_000;
        for i in 0..self.people.len() {
            if !self.people[i].online {
                continue;
            }
            let sid = self.people[i].sid;
            let frames = self.drain(sid).await;
            let p = &mut self.people[i];
            for f in &frames {
                p.frame(f, now);
            }
            if tick {
                p.tick(now);
            }
            p.pasts(now);
            let out: Vec<ClientMessage> = self.people[i].out.drain(..).collect();
            for m in out {
                if tracing_on() {
                    let what = format!("{m:?}");
                    eprintln!("    {sid} -> {}", &what[..what.len().min(100)]);
                }
                if matches!(m, ClientMessage::EpochFetch { ref at, .. } if at.is_empty()) {
                    self.people[i].fetches += 1;
                }
                if let ClientMessage::EpochDecline { why, .. } = &m {
                    self.people[i].declines.push(*why);
                }
                self.send(sid, m).await;
            }
        }
        if tick {
            self.last_tick = now;
        }
    }

    /// Runs until `done`, at most `ms`; whether it was.
    /// Before the paused clock moves on by `every` ms: real time for the relay's work
    /// (`Gate::settle`), then, while some of it is still under way (an actor's turn on a store
    /// write, a message in an inbox), the clock moves at real time, as a relay's does while its
    /// database works (`gk_e2e_j8h.rs` `World::settle`, J10). Moving it by the steps' pace
    /// meanwhile made a slow store write outlast the Regenesis' deadline on the relay's clock:
    /// a Postgres 20 ms away each way failed "a page never seated makes the
    /// Regenesis it is asked" (PR #21 review).
    async fn settle(&self, every: u64) {
        Gate::settle(every).await;
        let start = std::time::Instant::now();
        let mut at = start;
        while self.state.gk.busy_for_test() {
            assert!(
                start.elapsed() < BUSY_MAX,
                "the relay's work stayed under way for {BUSY_MAX:?}"
            );
            Gate::settle(1).await;
            let now = std::time::Instant::now();
            tokio::time::advance(now - at).await;
            at = now;
        }
    }

    async fn until(&mut self, ms: u64, done: impl Fn(&World) -> bool) -> bool {
        let end = self.now() + ms;
        let every = if self.paused { 50 } else { 10 };
        while self.now() < end {
            if self.paused {
                self.settle(every).await;
                tokio::time::advance(Duration::from_millis(every)).await;
            } else {
                tokio::time::sleep(Duration::from_millis(every)).await;
            }
            self.step().await;
            if done(self) {
                return true;
            }
        }
        done(self)
    }

    async fn kept(&self) -> i64 {
        crate::accounts::raw(
            self.relay(),
            &format!("SELECT COUNT(*) FROM voipc_log WHERE conv = '{CONV}'"),
        )
        .await
        .unwrap()
    }

    /// `i` posts, and its kept copy is filed: `count` entries are kept in all.
    async fn post(&mut self, i: usize, id: u8, text: &str, count: i64) {
        let now = self.now();
        self.people[i].post(id, text, now);
        let end = self.now() + 15_000;
        while self.now() < end {
            self.until(100, |_| false).await;
            if self.kept().await >= count {
                return;
            }
        }
        panic!("the kept copy of {text} was not filed");
    }

    /// Its page reads the channel's kept history now (the channel opened: `read_now`), until
    /// it read every text of `want` or 20 s went by (the lane's wait), every past epoch it
    /// asked for answered; then a second more.
    async fn read(&mut self, i: usize, want: &[&str]) {
        let out = self.people[i].sync.read_now(CONV);
        self.people[i].out.extend(out);
        let want: Vec<String> = want.iter().map(|t| t.to_string()).collect();
        self.until(20_000, move |w| {
            let p = &w.people[i];
            want.iter().all(|t| p.texts.contains(t)) && p.read_done()
        })
        .await;
        self.until(1_000, |_| false).await;
    }
}

impl World {
    /// A long quiet time on the paused clock, in steps of `every` ms: real time for the
    /// relay's work at each step, the pages online stepping too.
    async fn pass(&mut self, ms: u64, every: u64) {
        assert!(self.paused, "the clock is paused");
        let end = self.now() + ms;
        while self.now() < end {
            self.settle(100).await;
            tokio::time::advance(Duration::from_millis(every)).await;
            self.step().await;
        }
    }

    /// `i` posts; whether the relay took the post (its kept copy filed: `count` entries
    /// kept in all) within `ms`.
    async fn post_goes(&mut self, i: usize, id: u8, text: &str, count: i64, ms: u64) -> bool {
        let now = self.now();
        self.people[i].post(id, text, now);
        let end = self.now() + ms;
        while self.now() < end {
            self.until(200, |_| false).await;
            if self.kept().await >= count {
                return true;
            }
        }
        false
    }

    /// What the group key told page `i` since `from`, short.
    fn told(&self, i: usize, from: usize) -> Vec<String> {
        self.people[i].events[from.min(self.people[i].events.len())..]
            .iter()
            .map(|e| {
                let s = format!("{e:?}");
                s[..s.len().min(90)].to_string()
            })
            .collect()
    }
}

/// ann's page starts the kept channel's group (the sole keyholder, by its connection's pair),
/// she writes, and the page closes. `away_ms` later she signs in again on a new page: her
/// account's seat is still seated, the set's only entry is her old page's, which can never
/// come back, and nobody else is there. She writes again. Whether that post goes within
/// `wait_ms`, with what her page was told and the relay's load row.
async fn back_after(
    away_ms: u64,
    wait_ms: u64,
) -> (bool, Vec<String>, Option<GroupLoad>, World, usize) {
    let mut w = World::new().await;
    let ann = w.person("ann").await;
    let keyed = w
        .until(20_000, |w| {
            w.people[ann].epoch().is_some() && w.holders() == (1, 1)
        })
        .await;
    assert!(keyed, "ann's first page started the group: {:?}", w.load());
    w.post(ann, 1, "before she left", 1).await;
    w.close(ann).await;
    w.pause();
    w.pass(away_ms, 5_000).await;
    w.again(ann).await;
    let seated = w.until(15_000, |w| w.people[ann].epoch().is_some()).await;
    assert!(
        seated,
        "back on a new page, ann's account seat is answered from the head: told {:?}",
        w.told(ann, 0)
    );
    let from = w.people[ann].events.len();
    let went = w.post_goes(ann, 2, "back again", 2, wait_ms).await;
    let told = w.told(ann, from);
    let load = w.load();
    (went, told, load, w, ann)
}

/// The control: away for two minutes only. The head epoch is still young, so her post goes
/// under it though no keyholder is online.
#[tokio::test]
async fn d2_control_a_seated_account_back_after_two_minutes_posts() {
    let (went, told, load, _w, _) = back_after(2 * 60_000, 150_000).await;
    assert!(went, "ann's post goes: told {told:?}, load {load:?}");
}

/// F1. Away for 71 minutes (one night is the same): the head epoch is past the writers' age
/// limit (70 min, §5.5), so ann's page holds her post and says the keys are late. Nothing can
/// open a new epoch: the set's only entry is a dead connection's. The spec's way out is the
/// fast new start (§5.6: none online, every entry a connection's, so a Regenesis "at once"),
/// and ann's page is an allowed volunteer. But the relay asks a start only while a seat or an
/// exit waits (`group.rs` `ask`: `wanted || exits.waiting() > 0`), and a seated member's
/// fetch is answered from the snapshot outside the actor and never counts as waiting. So no
/// Regenesis is asked, her post drops at `HOLD_MS`, and the channel stays unwritable for
/// every seated member until somebody who is not seated comes, or a seat exits.
#[tokio::test]
async fn d2_f1_a_seated_account_back_after_the_epoch_aged_out_posts_again() {
    let (went, told, load, mut w, ann) = back_after(71 * 60_000, 150_000).await;
    // Evidence for the report, gathered before the assert: still stuck 10 minutes on, and
    // what un-sticks it (a newcomer's queued seat makes the relay ask the Regenesis)
    let mut later = false;
    let mut after_newcomer = false;
    if !went {
        later = w.post_goes(ann, 3, "ten minutes on", 2, 10 * 60_000).await;
        let bob = w.person("bob").await;
        w.until(SEATED_AT_ONCE_MS, |w| w.people[bob].epoch().is_some())
            .await;
        let kept = w.kept().await;
        after_newcomer = w
            .post_goes(ann, 4, "after bob came", kept + 1, 150_000)
            .await;
    }
    assert!(
        went,
        "ann, seated, back 71 min after her page (the sole keyholder) closed, cannot post: \
         her post did not go within 150 s (told {told:?}; relay load {load:?}); \
         a post in the next 10 min went: {later}; a post after newcomer bob came went: \
         {after_newcomer}"
    );
}

// ── Second session (2026-11-25): F1 with a desktop keyholder, and F2 ─────────────────

/// F1 again, in the commonest small community: ann's desktop app holds the channel's keys
/// (the sole keyholder, its own pair, origin 0x03), bob reads and writes from a browser page
/// that stays online, with "Help hold keys" on. ann's app closes. `away_ms` later bob writes.
/// Whether that post goes within `wait_ms`, what bob's page was told, the relay's load row.
async fn desktop_away(
    away_ms: u64,
    wait_ms: u64,
) -> (bool, Vec<String>, Option<GroupLoad>, World, usize) {
    let mut w = World::new().await;
    let ann = w.person_as("ann", Platform::Desktop, 0).await;
    let keyed = w
        .until(20_000, |w| {
            w.people[ann].epoch().is_some() && w.holders() == (1, 1)
        })
        .await;
    assert!(keyed, "ann's desktop started the group: {:?}", w.load());
    let bob = w.person("bob").await;
    let seated = w
        .until(SEATED_AT_ONCE_MS, |w| w.people[bob].epoch().is_some())
        .await;
    assert!(seated, "bob is seated by ann's desktop: {:?}", w.load());
    w.post(bob, 1, "while ann is here", 1).await;
    w.close(ann).await;
    w.pause();
    w.pass(away_ms, 5_000).await;
    let from = w.people[bob].events.len();
    let went = w.post_goes(bob, 2, "ann is away", 2, wait_ms).await;
    let told = w.told(bob, from);
    let load = w.load();
    (went, told, load, w, bob)
}

/// The control: the desktop keyholder is away for 30 minutes. The head epoch is young enough
/// (under 70 min), so bob's post goes under it.
#[tokio::test]
async fn d2_control_a_seated_member_posts_while_the_desktop_keyholder_is_away_30_min() {
    let (went, told, load, _w, _) = desktop_away(30 * 60_000, 150_000).await;
    assert!(went, "bob's post goes: told {told:?}, load {load:?}");
}

/// F1 with a desktop keyholder. ann's desktop is away for 75 minutes (a night is the same).
/// §5.6 lets a volunteer start the channel anew once no keyholder was online for 1 h, and
/// bob's page is an allowed volunteer and online the whole time. But the relay asks that
/// Regenesis only while a seat or an exit waits, and bob is seated: his fetches are answered
/// with the old head. So at 70 min his page holds his posts ("keys late") and drops them, and
/// the channel stays unwritable until ann's desktop is back.
#[tokio::test]
async fn d2_f1_a_seated_member_posts_again_once_the_desktop_keyholder_was_away_over_an_hour() {
    let (went, told, load, mut w, bob) = desktop_away(75 * 60_000, 150_000).await;
    let mut later = false;
    if !went {
        later = w.post_goes(bob, 3, "ten minutes on", 2, 10 * 60_000).await;
    }
    let dues = w.people[bob].dues.clone();
    assert!(
        went,
        "bob, seated and online, cannot post 75 min after the sole (desktop) keyholder left,          though a volunteer may start anew after 1 h: his post did not go within 150 s (told          {told:?}; relay load {load:?}; dues the relay asked bob's page: {dues:?}); a post in          the next 10 min went: {later}"
    );
}

/// F2. ann's desktop app starts the channel and is its sole keyholder. The app restarts on
/// the same device (same keyholder pair, so the same entry), and from then on the device's
/// clock runs `clock_ahead` seconds ahead of the relay's. Then bob (a browser page) and carol
/// (a desktop app, "Help hold keys" on, clock right) come to the channel for the first time.
/// Whether both are seated within `wait_ms`; with what the relay asked ann and what she
/// answered.
async fn sole_keyholder_with_clock(clock_ahead: i64, wait_ms: u64) -> (bool, World, [usize; 3]) {
    let mut w = World::new().await;
    let ann = w.person_as("ann", Platform::Desktop, 0).await;
    let keyed = w
        .until(20_000, |w| {
            w.people[ann].epoch().is_some() && w.holders() == (1, 1)
        })
        .await;
    assert!(keyed, "ann's desktop started the group: {:?}", w.load());
    w.post(ann, 1, "before the restart", 1).await;
    w.people[ann].clock_ahead = clock_ahead;
    w.again(ann).await;
    let back = w
        .until(20_000, |w| {
            w.people[ann].epoch().is_some() && w.holders() == (1, 1)
        })
        .await;
    assert!(
        back,
        "ann's desktop is back as the online keyholder (the same entry): {:?}",
        w.load()
    );
    w.pause();
    let bob = w.person("bob").await;
    let carol = w.person_as("carol", Platform::Desktop, 0).await;
    let seated = w
        .until(wait_ms, |w| {
            w.people[bob].epoch().is_some() && w.people[carol].epoch().is_some()
        })
        .await;
    (seated, w, [ann, bob, carol])
}

/// The control: ann's clock is right. bob and carol are seated within seconds.
#[tokio::test]
async fn d2_control_newcomers_are_seated_by_a_sole_keyholder_whose_clock_is_right() {
    let (seated, w, [ann, ..]) = sole_keyholder_with_clock(0, 60_000).await;
    assert!(
        seated,
        "bob and carol are seated: load {:?}, ann was asked {:?} and declined {:?}",
        w.load(),
        w.people[ann].dues,
        w.people[ann].declines
    );
}

/// F2. ann's clock is 6 minutes ahead (past `KEYHOLDER_SKEW_SECS`, 5 min): her app declines
/// every due with `CLOCK` (`holder.rs` `refuses`) but goes on offering to hold keys, so the
/// relay counts her entry as online. It is the set's last entry, so the relay never proposes
/// its removal; carol's promotion needs ann's signature; and the relay starts a channel anew
/// only while no keyholder is online. So nobody new is ever seated while ann's app runs, and
/// nothing tells ann. 71 minutes on, ann cannot post either: her own app declined every
/// Refresh.
#[tokio::test]
async fn d2_f2_newcomers_are_seated_though_the_sole_keyholders_clock_is_six_minutes_off() {
    let (seated, mut w, [ann, bob, carol]) = sole_keyholder_with_clock(6 * 60, 5 * 60_000).await;
    let load = w.load();
    let asked = w.people[ann].dues.clone();
    let declined = w.people[ann].declines.clone();
    let told_ann = w.told(ann, 0);
    let told_bob = w.told(bob, 0);
    let carol_asked = w.people[carol].dues.clone();
    let mut ann_posts = true;
    if !seated {
        w.pass(71 * 60_000, 5_000).await;
        let kept = w.kept().await;
        ann_posts = w.post_goes(ann, 2, "an hour on", kept + 1, 150_000).await;
    }
    let seated_later = w.people[bob].epoch().is_some() || w.people[carol].epoch().is_some();
    // The fix (dive 2 F2): ann's entry, declining with CLOCK, counts as not online, so the
    // channel starts anew once the hour that a set with a desktop entry keeps has passed
    // (§5.6; members' own rules allow no sooner). Within 5 min stays impossible by design
    assert!(
        seated || (seated_later && ann_posts),
        "bob and carol were not seated within 5 min while ann's desktop, the sole keyholder,          was online with its clock 6 min ahead: relay load {load:?}; dues asked of ann (by          kind) {asked:?}; her declines (by reason; 2 is CLOCK) {declined:?}; dues asked of          carol {carol_asked:?}; ann's app was told {told_ann:?}; bob's page was told          {told_bob:?}; 71 min on either is seated: {seated_later}, and a post of ann's own          went: {ann_posts}"
    );
}

/// F3's steps. ann's desktop app is the channel's sole keyholder. mal's desktop app comes with
/// "Help hold keys" on and is seated. With `tamper`, the pair mal's app offers to hold keys
/// with carries a signature that does not verify under mal's identity key (one bit flipped
/// in the `KeyholdVolunteer` her app sends): the relay does not check it (gk/session.rs
/// `volunteer`: "the endorsement is the keyholder's to check"), so it proposes mal for
/// promotion, and ann's app declines her as a candidate. Then bob comes to the channel for
/// the first time. Whether bob is seated within `wait_ms`.
async fn refused_candidate(tamper: bool, wait_ms: u64) -> (bool, World, [usize; 3]) {
    let mut w = World::new().await;
    let ann = w.person_as("ann", Platform::Desktop, 0).await;
    let keyed = w
        .until(20_000, |w| {
            w.people[ann].epoch().is_some() && w.holders() == (1, 1)
        })
        .await;
    assert!(keyed, "ann's desktop started the group: {:?}", w.load());
    let mal = w.person_as("mal", Platform::Desktop, 0).await;
    let mut offered = false;
    for m in w.people[mal].out.iter_mut() {
        if let ClientMessage::KeyholdVolunteer { pair: Some(p), .. } = m {
            offered = true;
            if tamper {
                p.sig[0] ^= 1;
            }
        }
    }
    assert!(offered, "mal's app offers to hold keys, not yet sent");
    let seated = w
        .until(SEATED_AT_ONCE_MS, |w| w.people[mal].epoch().is_some())
        .await;
    assert!(seated, "mal is seated by ann's desktop: {:?}", w.load());
    w.pause();
    let bob = w.person("bob").await;
    let seated = w.until(wait_ms, |w| w.people[bob].epoch().is_some()).await;
    (seated, w, [ann, mal, bob])
}

/// The control: mal's offer is as her app made it. She is promoted, and bob is seated.
#[tokio::test]
async fn d2_control_a_newcomer_is_seated_beside_a_volunteer_the_keyholder_accepts() {
    let (seated, w, [ann, ..]) = refused_candidate(false, 60_000).await;
    assert!(
        seated,
        "bob is seated: load {:?}, ann was asked {:?} and declined {:?}",
        w.load(),
        w.people[ann].dues,
        w.people[ann].declines
    );
}

/// F3. A seated volunteer whom the keyholders refuse as a candidate (`CANDIDATE`) is proposed
/// again every 30 s, for as long as it is online, and a Promote goes before every Exits, Join
/// and Refresh due (group.rs `next_due_kind`): so nobody new is seated, no exit commits and
/// no epoch opens. Here the refusal is forced by a bad signature on the offered pair, which
/// any member's app can send; a desktop's old pair after a seat-key rotation is refused the
/// same way without any ill will (CHANGELOG Known, "stalls keyholders that know the new one").
#[tokio::test]
async fn d2_f3_a_newcomer_is_seated_though_a_seated_volunteer_is_refused_as_a_candidate() {
    let (seated, mut w, [ann, _mal, bob]) = refused_candidate(true, 5 * 60_000).await;
    let load = w.load();
    let asked = w.people[ann].dues.clone();
    let declined = w.people[ann].declines.clone();
    let told_bob = w.told(bob, 0);
    let mut ann_posts = true;
    if !seated {
        w.pass(71 * 60_000, 5_000).await;
        let kept = w.kept().await;
        ann_posts = w.post_goes(ann, 2, "an hour on", kept + 1, 150_000).await;
    }
    let seated_later = w.people[bob].epoch().is_some();
    assert!(
        seated,
        "bob was not seated within 5 min while a seated volunteer was refused as a candidate: \
         relay load {load:?}; dues asked of ann, the keyholder (by kind; 3 is a Promote, 0 a \
         Join, 2 a Refresh) {asked:?}; her declines (by reason; 4 is CANDIDATE) {declined:?}; \
         bob's page was told {told_bob:?}; 71 min on bob is seated: {seated_later}, and a post \
         of ann's own went: {ann_posts}"
    );
}

/// The lead the dive started from (J10-B), on the path GROUP-KEY.md §5.6 names as not yet
/// tested: a fast new start by a volunteer that was never seated, where the head it must
/// build on was reached through keyholder headers (a promotion, then refreshes), not straight
/// from the Genesis. ann's and bob's browser pages hold the keys (two connection entries);
/// both close. `back`: ann signs in again first (a seated account with a floor in her vault,
/// the volunteer the relay then asks). carol, who never held a seat, comes to the channel.
/// Whether carol is seated within `wait_ms`.
async fn new_start_after_a_promotion(back: bool, wait_ms: u64) -> (bool, World, usize) {
    let mut w = World::new().await;
    let ann = w.person("ann").await;
    let keyed = w
        .until(20_000, |w| {
            w.people[ann].epoch().is_some() && w.holders() == (1, 1)
        })
        .await;
    assert!(keyed, "ann's page started the group: {:?}", w.load());
    let bob = w.person("bob").await;
    let two = w
        .until(30_000, |w| {
            w.people[bob].epoch().is_some() && w.holders() == (2, 2)
        })
        .await;
    assert!(two, "bob is seated and promoted beside ann: {:?}", w.load());
    w.post(ann, 1, "with two keyholders", 1).await;
    // Refreshes on top of the promotion: the head is a few epochs past the last keyholder header
    w.pause();
    w.pass(11 * 60_000, 1_000).await;
    let at = w.people[bob].epoch();
    assert!(
        at.is_some_and(|e| e >= 4),
        "the head is refreshes past the promotion (Genesis 1, KeyholdersAdd 2): bob holds {at:?}"
    );
    w.close(ann).await;
    w.close(bob).await;
    if back {
        w.again(ann).await;
    }
    let carol = w.person("carol").await;
    let seated = w
        .until(wait_ms, |w| w.people[carol].epoch().is_some())
        .await;
    (seated, w, carol)
}

/// carol alone: she is asked the Regenesis herself, pushed the head first.
#[tokio::test]
async fn d2_a_page_never_seated_starts_anew_on_a_head_reached_through_keyholder_headers() {
    let (seated, w, carol) = new_start_after_a_promotion(false, 60_000).await;
    assert!(
        seated,
        "carol, never seated, is seated by her own new start: load {:?}; dues asked of her \
         {:?}; her declines {:?}; told {:?}",
        w.load(),
        w.people[carol].dues,
        w.people[carol].declines,
        w.told(carol, 0)
    );
}

/// ann is back on a new page first: her page makes the new start, and carol is seated.
#[tokio::test]
async fn d2_a_returning_page_starts_anew_on_a_head_reached_through_keyholder_headers() {
    let (seated, w, carol) = new_start_after_a_promotion(true, 60_000).await;
    assert!(
        seated,
        "carol is seated after ann's new page started anew: load {:?}; carol was asked {:?} \
         and told {:?}",
        w.load(),
        w.people[carol].dues,
        w.told(carol, 0)
    );
}

// ── A member's own clock ──────────────────────────────────────────────────────────────

/// ann's desktop holds the channel's keys and writes; every clock but bob's is right. bob's
/// browser page signs in on a device whose clock is `off_min` minutes off (ahead when
/// positive) and writes. Whether his post goes within `wait_ms`, and what his page was told.
async fn member_with_clock(off_min: i64, wait_ms: u64) -> (bool, Vec<String>, World, usize) {
    let mut w = World::new().await;
    let ann = w.person_as("ann", Platform::Desktop, 0).await;
    let keyed = w
        .until(20_000, |w| {
            w.people[ann].epoch().is_some() && w.holders() == (1, 1)
        })
        .await;
    assert!(keyed, "ann's desktop started the group: {:?}", w.load());
    w.post(ann, 1, "from ann", 1).await;
    // bob's page, as `person` makes it, on the device with the wrong clock
    let id = AccountId::new();
    w.relay()
        .store()
        .create_user(
            &NewUser {
                id,
                username: "bob".into(),
                display_name: "bob".into(),
                email_pending: None,
                password_hash: None,
                created_at: l4f_accounts::util::now(),
            },
            None,
        )
        .await
        .unwrap();
    let identity = generate_identity_key_pair();
    w.relay()
        .set_identity(id, &identity.public_key().serialize())
        .await
        .unwrap();
    let logkey = LogKey::generate();
    let vault = Vault::create(w.relay().relay_id, "bob");
    let blobs = vec![VaultBlob {
        version: 1,
        ..vault.seal_item(ITEM_LOGKEY, 1, &logkey.to_bytes())
    }];
    let signed = SignedIn {
        relay_id: w.relay().relay_id,
        name: "bob".into(),
        vault,
        identity,
        recovery: None,
        binding: None,
        keyed: false,
        login_key: None,
        blobs,
    };
    let publish = ClientMessage::Account(AccountRequest::LogKeyPublish {
        logkey: logkey.public().to_vec(),
        sig: logkey.endorse(&identity).to_vec(),
    });
    let bob = w.connect("bob", id.0, signed).await;
    w.people[bob].clock_off_ms = off_min * 60_000;
    w.people[bob].clock_ahead = off_min * 60;
    let sid = w.people[bob].sid;
    w.send(sid, publish).await;
    let _ = w.drain(sid).await;
    w.start(bob).await;
    w.pause();
    let from = w.people[bob].events.len();
    let went = w.post_goes(bob, 2, "from bob", 2, wait_ms).await;
    let told = w.told(bob, from);
    (went, told, w, bob)
}

/// The control: bob's clock is right, and his post goes.
#[tokio::test]
async fn d2_control_a_member_whose_clock_is_right_posts() {
    let (went, told, w, _) = member_with_clock(0, 150_000).await;
    assert!(went, "bob's post goes: told {told:?}, load {:?}", w.load());
}

/// A member whose clock is 15 minutes slow refuses every header a keyholder with a right
/// clock signs now (rule 7, `check_time`: at most `CLOCK_SLACK`, 10 min, ahead of its own
/// clock), so it gets no key and reads and writes nothing: that rule stays. Its page is told
/// why, not only that the keys are late (dive 2 F5).
#[tokio::test]
async fn d2_f5_a_member_whose_clock_is_fifteen_minutes_slow_posts() {
    let (went, told, w, bob) = member_with_clock(-15, 150_000).await;
    let key = w.people[bob].epoch().is_some();
    assert!(
        !went && told.iter().any(|t| t.contains("ClockSlow")),
        "bob's device clock is 15 min slow: his post went: {went}; he holds an epoch key: \
         {key}; his page was told {told:?}; relay load {:?}",
        w.load()
    );
}

/// A member whose clock is 75 minutes fast (a wrong time zone gives a whole hour or more)
/// takes the headers, but counts every epoch as older than the writers' 70 minutes
/// (`EpochKey::late`), so each of its posts is held and dropped: that rule stays. Its page is
/// told its clock is ahead, not only that the keys are late (dive 2 F5).
#[tokio::test]
async fn d2_f5_a_member_whose_clock_is_seventy_five_minutes_fast_posts() {
    let (went, told, w, bob) = member_with_clock(75, 150_000).await;
    let key = w.people[bob].epoch().is_some();
    assert!(
        !went && told.iter().any(|t| t.contains("ClockFast")),
        "bob's device clock is 75 min fast: his post went: {went}; he holds an epoch key: \
         {key}; his page was told {told:?}; relay load {:?}",
        w.load()
    );
}
