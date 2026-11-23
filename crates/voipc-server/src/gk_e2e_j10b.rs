//! End-to-end group-key scenarios added by investigation J10B (2026-11-21): a browser account
//! that comes back to a kept channel every keyholder of which was a browser page that left.
//! The relay's real `gk` code driven by the clients' real `voipc_crypto::group_state` and
//! `sync` code; the harness is `gk_e2e_j9m.rs`'s (an accounts relay, each account's app with
//! its `AccountSync` and vault, kept copies filed at `EpochPostTaken`, kept reads), with the
//! pages holding keys as browsers do: "Help hold keys" on, their builds run whole as the page's
//! build loop runs them, their commits uploaded (`gk_e2e_j8h.rs` `App::took`).
//!
//! test-ui.mjs's accounts lane: account `acct` signs up on page `up`, which tracks the kept
//! channel at once and so starts its group, the sole keyholder by its connection's pair (0x02);
//! `up` closes three seconds later. Every page after it comes while no keyholder is online:
//! the set's last entry is never removed and nothing online can sign a promotion. `back` (acct
//! again) is seated already (its account's seat is the Genesis's), but `two` (acctB) is not;
//! `back` writes, both leave, and acctB comes back on a new page. Until J10-B's option A (owner
//! 2026-11-22) the relay waited the fast new start's 2 minutes for a Regenesis (§5.6), and
//! `two` was never seated in the generation `back` wrote in; now a Regenesis comes at once.

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
    GkCtx, GkEpoch, GkEvent, GkOut, GkStart, GkTrack, GroupKeying, MemoryPins, PastEpoch, Platform,
    VaultFloor,
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
const CONV: &str = "c:j10bkept";

use super::gk_e2e_j8h::SEATED_AT_ONCE_MS;

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

    fn frame(&mut self, f: &ServerMessage, now: u64) {
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
        let env = envelope(&format!("j10b-{id}"), text, None);
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
        let now = self.now();
        let run = self.state.gk.run;
        let p = &mut self.people[i];
        let out = p.keying.start(GkStart {
            on: true,
            run,
            relay_clock: now / 1000,
            platform: Platform::Browser,
            help_hold_keys: true,
            user_id: p.sid,
            identity: p.signed.identity,
            account: Some(p.a),
            seat_keys,
            local: None,
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
        let j = self.connect(&name, a, signed).await;
        let back = self.people.remove(j);
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
                self.send(sid, m).await;
            }
        }
        if tick {
            self.last_tick = now;
        }
    }

    /// Runs until `done`, at most `ms`; whether it was.
    async fn until(&mut self, ms: u64, done: impl Fn(&World) -> bool) -> bool {
        let end = self.now() + ms;
        let every = if self.paused { 50 } else { 10 };
        while self.now() < end {
            if self.paused {
                Gate::settle(every).await;
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

/// The lane's choreography (test-ui.mjs, "a channel message written while they were away is
/// there when they come back"). `ann` is the lane's acct, `bob` its acctB.
///
/// `holder_stays`: the control. ann's first page stays until bob is seated, so a keyholder
/// is online when bob first comes; it closes then, and the rest runs as in the lane.
async fn away_and_back(holder_stays: bool) -> (World, usize) {
    let mut w = World::new().await;
    // ann signs up: her page tracks the channel and starts its group, the sole keyholder
    let ann = w.person("ann").await;
    let keyed = w
        .until(20_000, |w| {
            w.people[ann].epoch().is_some() && w.holders() == (1, 1)
        })
        .await;
    assert!(keyed, "ann's first page started the group: {:?}", w.load());
    if !holder_stays {
        // `up` closes once the browser is remembered; ann signs in again (`back`)
        w.again(ann).await;
    }
    // bob signs up
    let bob = w.person("bob").await;
    let bob_seated = w.until(15_000, |w| w.people[bob].epoch().is_some()).await;
    if holder_stays {
        assert!(
            bob_seated,
            "the control: bob is seated while ann's first page holds the keys"
        );
        let promoted = w.until(20_000, |w| w.holders().1 == 2).await;
        assert!(promoted, "bob's page is promoted beside it: {:?}", w.load());
        w.again(ann).await;
        let removed = w.until(20_000, |w| w.holders() == (2, 2)).await;
        assert!(
            removed,
            "the first page's entry is removed, ann's new page promoted: {:?}",
            w.load()
        );
    }
    // ann writes while bob is there, bob leaves, ann writes again, and leaves too
    w.post(ann, 1, "said in the kept channel", 1).await;
    w.until(1_500, |_| false).await;
    w.close(bob).await;
    w.post(ann, 2, "while you were away", 2).await;
    w.until(1_000, |_| false).await;
    w.close(ann).await;
    // bob comes back on a new page and opens the channel
    w.again(bob).await;
    w.read(bob, &["said in the kept channel", "while you were away"])
        .await;
    (w, bob)
}

/// The control: a keyholder is online when bob first comes, so his account's seat is made
/// then; whatever holds the keys later, his page reads both posts from the relay's copies when
/// he is back, every keyholder page gone.
#[tokio::test]
async fn e2e_j10b_an_account_seated_before_it_left_reads_the_kept_channel_when_back() {
    let (w, bob) = away_and_back(true).await;
    let p = &w.people[bob];
    let mut texts = p.texts.clone();
    texts.sort();
    assert_eq!(
        texts,
        vec!["said in the kept channel", "while you were away"],
        "bob reads both posts: holders {:?}, told {:?}",
        w.holders(),
        p.events
    );
}

/// The lane as it runs: ann's first page made the group and closed before bob ever came, so
/// no keyholder was online while bob was there. Every entry of the set in force is a
/// connection's and none is online, so a Regenesis comes at once (J10-B option A, owner
/// 2026-11-22): bob is seated in the generation ann writes in, and back on a new page, every
/// keyholder page gone, he reads both posts. Before, his seat waited the fast new start's 2
/// minutes, which ann's posts and both pages' leaving fell inside: he was never seated in
/// that generation and read neither post (the lane's red check).
#[tokio::test]
async fn e2e_j10b_an_account_first_come_while_no_keyholder_was_online_reads_the_kept_channel() {
    let (w, bob) = away_and_back(false).await;
    let p = &w.people[bob];
    let mut texts = p.texts.clone();
    texts.sort();
    assert_eq!(
        texts,
        vec!["said in the kept channel", "while you were away"],
        "bob reads both posts: holders {:?}, told {:?}",
        w.holders(),
        p.events
    );
    assert!(p.epoch().is_some(), "bob holds a key of the head");
}

/// bob's page is the only one online, never seated, and "Help hold keys" is on: ann's only
/// page made the group and closed for good. The relay asks bob's page for the fast new start's
/// Regenesis at once (its due names the head as its parent). The page builds a Regenesis on
/// the head it holds, and an unseated page held none: the relay answers its fetches with
/// `EpochWait` alone, so it waited for a head that never came, and the group stalled while
/// only unseated pages were online. The relay now sends it the head with the due (`group.rs`
/// `ask_start`); it makes the Regenesis and holds the keys from then on.
#[tokio::test]
async fn e2e_j10b_a_page_never_seated_makes_the_regenesis_it_is_asked() {
    let mut w = World::new().await;
    let ann = w.person("ann").await;
    let keyed = w
        .until(20_000, |w| {
            w.people[ann].epoch().is_some() && w.holders() == (1, 1)
        })
        .await;
    assert!(keyed, "ann's page started the group: {:?}", w.load());
    w.close(ann).await;
    let gone = w.until(5_000, |w| w.holders() == (1, 0)).await;
    assert!(gone, "the last entry stays, offline: {:?}", w.holders());
    let bob = w.person("bob").await;
    w.pause();
    let seated = w
        .until(SEATED_AT_ONCE_MS, |w| w.people[bob].epoch().is_some())
        .await;
    let p = &w.people[bob];
    assert!(
        seated,
        "bob's page made the Regenesis and is seated by it: holders {:?}, told {:?}",
        w.holders(),
        p.events
    );
    assert_eq!(w.holders(), (1, 1), "bob's page holds the keys");
}
