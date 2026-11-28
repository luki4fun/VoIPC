//! End-to-end group-key scenarios added by slice K2 (wave 3b): kept history through the
//! relay's real accounts + `gk` code and the clients' real `voipc_crypto` code. Shared
//! helpers live in `gk_e2e_tests.rs`.
//!
//! The relay is a `ServerState` with the group key on and an accounts database: every
//! `AccountRequest` goes through `accounts::handle_request` as session.rs hands it over, the
//! group key's messages through `Groups::handle`, and `EpochPost` through the group key's
//! checks and a fan-out to the channel's followers (R2's post helper, stood in as
//! `gk_e2e_tests.rs` does). Each account runs the app's two halves on one connection, glued
//! as N1/W2 glue them: K1's `AccountSync` (seat keys, kept copies, kept reads) and C3b's
//! `GroupKeying` (live keys, and the past epochs a kept read asks for). The keyholder is
//! `gk_e2e_tests.rs`'s guest, building honest commits on a task of its own (`Keyholder`).
//! Accounts with no app ("the crowd") keep the log only: seated by `LogJoin` alone, and each
//! going by another exit cause, they make the openings.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use l4f_accounts::model::{AccountId, NewUser};
use l4f_accounts::store::Store;
use voipc_crypto::account::{SignedIn, Vault};
use voipc_crypto::envelope::{envelope, open_envelope};
use voipc_crypto::group_key::{Endorsement, GroupKind, MemberId, Origin};
use voipc_crypto::group_state::{
    GkCtx, GkOut, GkStart, GkTrack, GroupKeying, MemoryPins, PastEpoch, Platform, VaultFloor,
};
use voipc_crypto::log::LogKey;
use voipc_crypto::sync::{AccountSync, Event, LogMemory, Prefs, ITEM_LOGKEY};
use voipc_crypto::{generate_identity_key_pair, IdentityKeyPair, SignalStores};
use voipc_protocol::codec::PROTOCOL_VERSION;
use voipc_protocol::gk::{refused_what, EpochRef, GkMember};
use voipc_protocol::messages::{AccountReply, AccountRequest, ClientMessage, ServerMessage};
use voipc_protocol::types::{ChannelId, UserId, VaultBlob};

use super::gk_e2e_tests::{account_session, drop_db, scratch_db, show, tracing_on, Holder};
use crate::accounts::{gk as db, log};
use crate::control::{ControlRx, ControlTx};
use crate::state::{RateLimiter, ServerState};

const CHAN: ChannelId = 9;
const CONV: &str = "c:k2hall";

fn wall_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn raw(ik: &IdentityKeyPair) -> [u8; 32] {
    ik.public_key().public_key_bytes().try_into().unwrap()
}

/// One account's app on one connection.
struct Person {
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
}

impl Person {
    fn took(&mut self, out: GkOut) {
        self.out.extend(out.send);
        if !out.self_rows.is_empty() {
            let rows = self.sync.gk_self_rows(out.self_rows);
            self.out.extend(rows);
        }
        if out.seat_keys_wanted {
            let again = self.sync.seat_keys_wanted();
            self.out.extend(again);
        }
    }

    fn events(&mut self, events: Vec<Event>) {
        for e in events {
            if let Event::ChannelMessage { envelope, .. } = e {
                self.texts.push(open_envelope(&envelope).text);
            }
        }
    }

    fn frame(&mut self, f: &ServerMessage, now: u64) {
        match f {
            ServerMessage::Account(r) => {
                if let Some((out, events)) = self.sync.on_reply(r) {
                    self.out.extend(out);
                    self.events(events);
                }
            }
            ServerMessage::EpochReseated { n, left } => {
                let out = self.sync.gk_reseated(*n, *left);
                self.out.extend(out);
            }
            f => {
                let c = GkCtx {
                    pins: &mut self.pins,
                    now,
                };
                let out = self.keying.frame(&mut self.st, f, c);
                self.took(out);
            }
        }
    }

    fn tick(&mut self, now: u64) {
        let (out, events) = self.sync.tick();
        self.out.extend(out);
        self.events(events);
        let c = GkCtx {
            pins: &mut self.pins,
            now,
        };
        let out = self.keying.tick(&mut self.st, c);
        self.took(out);
    }

    /// N1/W2's glue for a kept read: each past epoch `AccountSync` names goes to
    /// `GroupKeying::past_epoch`; what it has is handed back, what it asked for waits.
    fn pasts(&mut self) {
        let new = self.sync.take_gk_past();
        self.past.extend(new);
        for (group, gen, epoch) in std::mem::take(&mut self.past) {
            match self.keying.past_epoch(&group, gen, epoch) {
                PastEpoch::Ready(ep) => {
                    let (out, events) = self.sync.gk_past_in(&ep);
                    self.out.extend(out);
                    self.events(events);
                }
                PastEpoch::Unknown => {
                    let out = self.sync.gk_past_none(&group, gen, epoch);
                    self.out.extend(out);
                }
                PastEpoch::Asked => self.past.push((group, gen, epoch)),
            }
        }
        let out = self.keying.past_asks();
        self.took(out);
    }

    /// The head epoch it holds `CK` of.
    fn epoch(&self) -> Option<u32> {
        self.keying.current_epoch(CONV).map(|e| e.epoch)
    }

    /// A post in the channel, live only: it writes in this epoch, so the next opening is
    /// pushed to it (2f).
    fn post_live(&mut self, id: u8, text: &str, now: u64) -> Vec<u8> {
        let env = envelope(&format!("k2-{id}"), text, None);
        let c = GkCtx {
            pins: &mut self.pins,
            now,
        };
        let out = self.keying.post(&mut self.st, CHAN, [id; 16], &env, c);
        self.took(out);
        env
    }

    /// A post in the channel and its kept copy, under the epoch it holds now.
    fn post(&mut self, id: u8, text: &str, now: u64) {
        let env = self.post_live(id, text, now);
        let ep = self.keying.current_epoch(CONV).expect("its key");
        let kept = self.sync.send_channel_gk(CONV, env, now, None, ep);
        self.out.extend(kept);
    }
}

/// The guest keyholder as a client of its own: a task answers each frame as it comes, as a
/// keyholder in another process would, whatever the test awaits meanwhile. Stepped with the
/// apps instead, it heard nothing while the test wrote accounts: a Join due asked during
/// `crowd` (18 accounts' writes, over 6 s on a busy Postgres) passed its 5 s deadline
/// unheard, a miss, and with no other keyholder online the relay asks again only after
/// `RETRY_ALL_MISSED_MS` (30 s).
struct Keyholder {
    holder: Arc<Mutex<Holder>>,
    task: tokio::task::JoinHandle<()>,
}

impl Keyholder {
    fn run(state: Arc<ServerState>, holder: Holder, tx: ControlTx, mut rx: ControlRx) -> Keyholder {
        let sid = holder.sid;
        let holder = Arc::new(Mutex::new(holder));
        let h = holder.clone();
        let task = tokio::spawn(async move {
            while let Some(b) = rx.recv().await {
                let f = voipc_protocol::codec::decode_server_msg(&b[4..]).unwrap();
                let now = state.gk.now();
                if tracing_on() {
                    eprintln!("[{now}] holder {sid} <- {}", show(&f));
                }
                let send = h.lock().unwrap().frame(&f, now);
                for m in send {
                    state.gk.handle(&state, sid, m, &tx).await;
                }
            }
        });
        Keyholder { holder, task }
    }
}

/// The relay, its keyholder, and the accounts' apps.
struct World {
    state: Arc<ServerState>,
    db: Store,
    file: std::path::PathBuf,
    /// Each session's queue; the keyholder's own task takes its frames.
    queues: HashMap<UserId, (ControlTx, Option<ControlRx>)>,
    holder: Option<Keyholder>,
    people: Vec<Person>,
    followers: Vec<UserId>,
    last_tick: u64,
}

impl Drop for World {
    fn drop(&mut self) {
        drop_db(&self.file);
        // A keyholder that panicked after the last `step` still fails the test
        if let Some(mut k) = self.holder.take().filter(|k| k.task.is_finished()) {
            use std::future::Future;
            let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
            if let std::task::Poll::Ready(Err(e)) = std::pin::Pin::new(&mut k.task).poll(&mut cx) {
                if e.is_panic() && !std::thread::panicking() {
                    std::panic::resume_unwind(e.into_panic());
                }
            }
        }
    }
}

impl World {
    async fn new() -> World {
        let _ = tracing_on();
        let (db, file) = scratch_db().await;
        let inc = db::gk_start(&db, true).await.unwrap().unwrap();
        let cfg = crate::config::AccountsConfig {
            mode: crate::config::AccountsMode::Optional,
            ..Default::default()
        };
        let relay = crate::accounts::Relay::open_with(&cfg, db.clone(), &[9u8; 32])
            .await
            .unwrap();
        let mut state = ServerState::new(
            &crate::config::ServerConfig {
                group_key: true,
                ..Default::default()
            },
            crate::settings::ServerSettings::default(),
            vec![],
            "test-admin-token".into(),
        );
        state.accounts = Some(Arc::new(relay));
        let state = Arc::new(state);
        state.gk.attach(db.clone(), inc);
        crate::state::test_support::put_in_channel(&state, CHAN, &[]).await;
        {
            let mut channels = state.channels.write().await;
            let c = channels.get_mut(&CHAN).unwrap();
            c.info.text = true;
            c.info.log = CONV.into();
            c.log_conv = CONV.into();
        }
        let mut w = World {
            state,
            db,
            file,
            queues: HashMap::new(),
            holder: None,
            people: vec![],
            followers: vec![],
            last_tick: 0,
        };
        // A guest keyholder following the channel
        let ik = generate_identity_key_pair();
        let sid = w.session(&ik, None).await;
        w.follow(sid, None);
        let h = Holder::guest(sid, ik, CONV, true);
        w.send(sid, h.volunteer()).await;
        let (tx, rx) = w.queues.get_mut(&sid).unwrap();
        let (tx, rx) = (tx.clone(), rx.take().unwrap());
        w.holder = Some(Keyholder::run(w.state.clone(), h, tx, rx));
        w
    }

    fn relay(&self) -> &crate::accounts::Relay {
        self.state.accounts.as_ref().unwrap()
    }

    fn now(&self) -> u64 {
        self.state.gk.now()
    }

    /// The epoch of the head the keyholder holds.
    fn head(&self) -> u32 {
        let Some(k) = &self.holder else {
            return 0;
        };
        let h = k.holder.lock().unwrap();
        h.held.as_ref().map_or(0, |h| h.head.header().epoch)
    }

    /// A connection in the channel, signed in to `account` where given.
    async fn session(&mut self, ik: &IdentityKeyPair, account: Option<[u8; 16]>) -> UserId {
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
            if let Some(a) = account {
                s.account = Some(account_session(a));
            }
        }
        if let Some(a) = account {
            self.state.account_sessions.insert(a, sid);
        }
        crate::state::test_support::put_in_channel(&self.state, CHAN, &[(uid, sid)]).await;
        self.state.gk.on_connect(sid, tx.clone());
        self.queues.insert(sid, (tx, Some(rx)));
        sid
    }

    fn follow(&mut self, sid: UserId, account: Option<[u8; 16]>) {
        self.state
            .gk
            .on_follow(CHAN, CONV, GroupKind::Text, sid, account);
        self.followers.push(sid);
    }

    async fn drain(&mut self, sid: UserId) -> Vec<ServerMessage> {
        let mut got = vec![];
        let Some((_, Some(rx))) = self.queues.get_mut(&sid) else {
            return got;
        };
        while let Ok(Some(b)) = tokio::time::timeout(Duration::ZERO, rx.recv()).await {
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
                let account = self.people.iter().find(|p| p.sid == sid).map(|p| p.a);
                let msg = match checked {
                    Ok(()) => ServerMessage::EpochPostIn {
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
                    },
                    Err(why) => {
                        let refused = ServerMessage::EpochRefused {
                            group,
                            what: refused_what::POST,
                            why,
                            detail: String::new(),
                        };
                        let _ = crate::session::send_msg(&tx, &refused);
                        return;
                    }
                };
                for f in self.followers.clone() {
                    if f != sid {
                        let _ = crate::session::send_msg(&self.queues[&f].0, &msg);
                    }
                }
            }
            m => self.state.gk.handle(&self.state, sid, m, &tx).await,
        }
    }

    /// An account with its identity and log key here, its app on a connection in the channel,
    /// its seat keys made and published by the app: following and tracking the group.
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
        let i = self.connect(id.0, signed).await;
        let sid = self.people[i].sid;
        self.send(sid, publish).await;
        let _ = self.drain(sid).await;
        self.start(i).await;
        i
    }

    /// The account's app on a new connection, from what the relay keeps of its vault.
    async fn connect(&mut self, a: [u8; 16], signed: SignedIn) -> usize {
        let sid = self.session(&signed.identity, Some(a)).await;
        let (mut sync, first) = AccountSync::start(&signed, a, LogMemory::default(), false);
        sync.set_protocol(PROTOCOL_VERSION);
        let mut out: VecDeque<ClientMessage> = sync.pins_first().into_iter().collect();
        out.extend(first);
        out.extend(sync.set_prefs(Prefs {
            cloud: true,
            asked: true,
        }));
        // `GroupKeys{on}`: the seat keys are made (or taken from the vault) and published
        out.extend(sync.gk_on(true));
        self.people.push(Person {
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
        });
        self.people.len() - 1
    }

    /// Once its seat keys are published, its `GroupKeying` starts and tracks the group.
    async fn start(&mut self, i: usize) {
        let settled = self
            .until(15_000, |w| {
                w.people[i].sync.seat_keys().is_some() && w.people[i].out.is_empty()
            })
            .await;
        assert!(settled, "seat keys settled");
        let now = self.now();
        let p = &mut self.people[i];
        let _ = p.keying.start(GkStart {
            on: true,
            run: self.state.gk.run,
            relay_clock: now / 1000,
            platform: Platform::Desktop,
            help_hold_keys: false,
            user_id: p.sid,
            identity: p.signed.identity,
            account: Some(p.a),
            seat_keys: p.sync.seat_keys(),
            local: None,
            visible: true,
        });
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
            VaultFloor::None,
        );
        p.took(out);
        let (sid, a) = (p.sid, p.a);
        self.follow(sid, Some(a));
    }

    /// The account's app ends, and runs again on a new connection with nothing kept but
    /// what the relay holds (its vault, the log): a reinstall, a new browser.
    async fn reconnect(&mut self, i: usize) {
        let old = self.people[i].sid;
        self.people[i].online = false;
        self.state.gk.on_session_end(old);
        self.followers.retain(|s| *s != old);
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
        let a = p.a;
        let j = self.connect(a, signed).await;
        let back = self.people.remove(j);
        self.people[i] = back;
        self.start(i).await;
    }

    /// Accounts that keep the log and follow nothing live: their identity and seat keys
    /// published, a seat in the log taken on a connection of their own (`LogJoin` seats them
    /// in the group, plan 2d).
    async fn crowd(&mut self, n: usize) -> Vec<([u8; 16], UserId)> {
        let mut out = vec![];
        for k in 0..n {
            let id = AccountId::new();
            let name = format!("crowd{k}");
            self.relay()
                .store()
                .create_user(
                    &NewUser {
                        id,
                        username: name.clone(),
                        display_name: name,
                        email_pending: None,
                        password_hash: None,
                        created_at: l4f_accounts::util::now(),
                    },
                    None,
                )
                .await
                .unwrap();
            let ik = generate_identity_key_pair();
            self.relay()
                .set_identity(id, &ik.public_key().serialize())
                .await
                .unwrap();
            let keys = voipc_crypto::group_key::SeatKeys::generate(1, wall_ms() / 1000);
            let public = keys.pair.public();
            let e = Endorsement::sign(
                &ik,
                Origin::VaultSeat,
                MemberId::Account(id.0),
                keys.n,
                keys.made,
                &public,
            )
            .unwrap();
            let published = db::SeatKeys {
                n: keys.n,
                kem: public.kem_bytes().into(),
                dh: public.dh_bytes().into(),
                made: e.made,
                sig: e.sig.to_vec(),
                published: wall_ms(),
            };
            assert!(db::put_seat_keys(&self.db, &id.0, &published)
                .await
                .unwrap());
            let sid = self.session(&ik, Some(id.0)).await;
            let join = AccountRequest::LogJoin { conv: CONV.into() };
            self.send(sid, ClientMessage::Account(join)).await;
            let joined = self
                .drain(sid)
                .await
                .into_iter()
                .any(|f| matches!(f, ServerMessage::Account(AccountReply::LogJoined { .. })));
            assert!(joined);
            out.push((id.0, sid));
        }
        out
    }

    /// `sid`'s account stops keeping the log (`LogLeave`).
    async fn leave_log(&mut self, sid: UserId) {
        let ask = AccountRequest::LogLeave { conv: CONV.into() };
        self.send(sid, ClientMessage::Account(ask)).await;
        let left = self
            .drain(sid)
            .await
            .into_iter()
            .any(|f| matches!(f, ServerMessage::Account(AccountReply::LogLeft { .. })));
        assert!(left);
    }

    /// One round: every app's queue drained into it, what it sends handed over.
    async fn step(&mut self) {
        // A keyholder that panicked fails the test with its own message
        if self.holder.as_ref().is_some_and(|k| k.task.is_finished()) {
            let k = self.holder.take().unwrap();
            if let Err(e) = k.task.await {
                std::panic::resume_unwind(e.into_panic());
            }
        }
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
                if tracing_on() {
                    eprintln!("[{now}] {} <- {}", p.signed.name, show(f));
                }
                p.frame(f, now);
            }
            if tick {
                p.tick(now);
            }
            p.pasts();
            let out: Vec<ClientMessage> = p.out.drain(..).collect();
            for m in out {
                if tracing_on() {
                    let what = format!("{m:?}");
                    eprintln!(
                        "[{now}] {} -> {}",
                        self.people[i].signed.name,
                        &what[..what.len().min(100)]
                    );
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
        while self.now() < end {
            tokio::time::sleep(Duration::from_millis(10)).await;
            self.step().await;
            if done(self) {
                return true;
            }
        }
        done(self)
    }

    /// Runs until every one of `crowd` sits in the group.
    async fn crowd_seated(&mut self, crowd: &[([u8; 16], UserId)]) -> bool {
        let end = self.now() + 20_000;
        while self.now() < end {
            self.until(200, |_| false).await;
            let mut all = true;
            for (a, _) in crowd {
                all &= !db::seats_of_account(&self.db, a).await.unwrap().is_empty();
            }
            if all {
                return true;
            }
        }
        false
    }

    /// An opening after `before`, with `who` holding its key.
    async fn opened(&mut self, before: u32, who: &[usize]) -> bool {
        let who = who.to_vec();
        self.until(20_000, move |w| {
            let head = w.head();
            head > before && who.iter().all(|i| w.people[*i].epoch() == Some(head))
        })
        .await
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

    async fn kept(&self) -> i64 {
        crate::accounts::raw(
            self.relay(),
            &format!("SELECT COUNT(*) FROM voipc_log WHERE conv = '{CONV}'"),
        )
        .await
        .unwrap()
    }

    /// Its app reads the channel's kept history now.
    fn read(&mut self, i: usize) {
        let out = self.people[i].sync.enter(CONV);
        self.people[i].out.extend(out);
    }
}

/// K2 (C4): a member back on a new connection, with nothing kept but its vault, reads the
/// kept posts of epochs the group has moved past: their gk chains' seals come from the relay
/// (`EpochChainKeys`), each epoch's key by a past answer (`EpochFetch{at}`) its seat keys
/// open. Someone who left the channel, and with it the log (`LogLeave`: its seat exits by
/// `Groups::on_log_leave`), reads nothing kept after: no seat in that epoch, so no past answer
/// for it, and neither the log's entries nor its seals are served to it.
#[tokio::test]
async fn e2e_k2_a_member_back_on_a_new_connection_reads_kept_posts_of_past_epochs_and_a_leaver_reads_none_after(
) {
    let mut w = World::new().await;
    let ann = w.person("ann").await;
    let bob = w.person("bob").await;
    let cat = w.person("cat").await;
    let seated = w
        .until(20_000, |w| (0..3).all(|i| w.people[i].epoch().is_some()))
        .await;
    assert!(seated, "seated");
    // cat keeps the log too; ann writes, so each opening is pushed to it
    w.read(cat);
    let now = w.now();
    w.people[ann].post_live(0, "zero", now);
    let crowd = w.crowd(2).await;
    assert!(
        w.crowd_seated(&crowd).await,
        "the crowd is seated by its LogJoin"
    );
    // An opening the three sit in: a crowd account stops keeping the log
    let before = w.head();
    w.leave_log(crowd[0].1).await;
    assert!(w.opened(before, &[ann]).await, "opened by a log leave");
    let e1 = w.head();
    w.post(ann, 1, "one", 1).await;
    // cat leaves the channel, and its log with it
    let cat_sid = w.people[cat].sid;
    w.state.gk.on_unfollow(CHAN, cat_sid);
    w.followers.retain(|s| *s != cat_sid);
    let _ = w.people[cat].keying.untrack(CHAN);
    w.state
        .channels
        .write()
        .await
        .get_mut(&CHAN)
        .unwrap()
        .members
        .remove(&cat_sid);
    let out = w.people[cat].sync.leave(CONV, true);
    w.people[cat].out.extend(out);
    assert!(w.opened(e1, &[ann]).await, "cat's exit opened an epoch");
    let e2 = w.head();
    let gen = w.people[ann].keying.current_epoch(CONV).unwrap().gen;
    w.post(ann, 2, "two", 2).await;
    // And the head moves past both
    w.leave_log(crowd[1].1).await;
    assert!(w.opened(e2, &[ann]).await, "opened again");
    // bob comes back with nothing but its vault, and reads
    w.reconnect(bob).await;
    w.read(bob);
    let read = w.until(30_000, |w| w.people[bob].texts.len() >= 2).await;
    assert!(read, "read {:?}", w.people[bob].texts);
    let mut texts = w.people[bob].texts.clone();
    texts.sort();
    assert_eq!(texts, ["one", "two"]);
    // cat reads nothing kept after its exit: no past answer for the epoch it was out of,
    let at = vec![EpochRef { gen, epoch: e2 }];
    let fetch = ClientMessage::EpochFetch {
        group: CONV.into(),
        have: None,
        at,
        seat: None,
    };
    let _ = w.drain(cat_sid).await;
    w.send(cat_sid, fetch).await;
    let answered = w.drain(cat_sid).await;
    assert!(
        answered
            .iter()
            .all(|f| !matches!(f, ServerMessage::EpochIn { .. })),
        "{:?}",
        answered.iter().map(show).collect::<Vec<_>>()
    );
    assert!(answered.iter().any(|f| matches!(
        f,
        ServerMessage::EpochRefused { what, .. } if *what == refused_what::FETCH
    )));
    // and neither the log's entries nor the seals of its chains
    for ask in [
        AccountRequest::ChainFetch {
            conv: CONV.into(),
            after: 0,
        },
        AccountRequest::EpochChainKeys {
            conv: CONV.into(),
            chains: vec![(w.people[ann].a, u32::MAX >> 1)],
        },
    ] {
        w.send(cat_sid, ClientMessage::Account(ask)).await;
        let refused = w.drain(cat_sid).await.into_iter().any(|f| {
            matches!(f, ServerMessage::Account(AccountReply::Error { reason, .. })
                if reason == "not a conversation of yours")
        });
        assert!(refused);
    }
    assert!(!w.people[cat].texts.iter().any(|t| t == "two"));
}

/// The stone an account's deletion leaves (`RelayHost::delete_user`).
async fn tombstone(db: &Store, a: &[u8; 16]) {
    const Q: &str = "INSERT INTO voipc_tombstones (account, at) VALUES ($1, 1)";
    match db {
        Store::Lite(x) => sqlx::query(Q).bind(&a[..]).execute(&x.0).await.map(|_| ()),
        Store::Pg(x) => sqlx::query(Q).bind(&a[..]).execute(&x.0).await.map(|_| ()),
    }
    .unwrap();
}

/// Kept posts in this many epochs, read in one page.
const MANY: usize = 18;

/// K2 (C4, K1's note): one page of kept entries, each in an epoch of its own, hands the app
/// more past epochs than one `EpochFetch` asks for (16): every one is answered in order and
/// the whole page opens. The openings come from crowd accounts going by each exit cause the
/// accounts side has: a log leave, a gate, a ban, an identity reset, a deletion's tombstone,
/// and an identity reset the shell made (`reclaim`, in a process with no groups).
#[tokio::test]
async fn e2e_k2_a_page_handing_over_many_past_epochs_is_read_whole_and_every_exit_cause_opens_one()
{
    let mut w = World::new().await;
    let ann = w.person("ann").await;
    let bob = w.person("bob").await;
    let seated = w
        .until(20_000, |w| (0..2).all(|i| w.people[i].epoch().is_some()))
        .await;
    assert!(seated, "seated");
    let now = w.now();
    w.people[ann].post_live(200, "warm", now);
    let crowd = w.crowd(MANY).await;
    assert!(
        w.crowd_seated(&crowd).await,
        "the crowd is seated by its LogJoin"
    );
    for (k, (a, sid)) in crowd.iter().enumerate() {
        let before = w.head();
        match k % 6 {
            0 => w.leave_log(*sid).await,
            // A gate it no longer passes (`gates::enforce`)
            1 => w.relay().out_of_logs(a, &[CONV.to_string()]).await.unwrap(),
            2 => {
                let ban = crate::bans::Ban {
                    id: 0,
                    label: "x".into(),
                    reason: String::new(),
                    by: "test".into(),
                    created_at: 0,
                    expires_at: None,
                    addr: None,
                    alias: None,
                };
                w.relay()
                    .ban_put(&crate::bans::Key::Account(*a), &ban)
                    .await
                    .unwrap();
            }
            3 => w.relay().gk_identity_reset(a).await,
            4 => {
                // The shell's relay knows no groups: the running one hears of it with the bans
                let cfg = crate::config::AccountsConfig {
                    mode: crate::config::AccountsMode::Optional,
                    ..Default::default()
                };
                let shell = crate::accounts::Relay::open_with(&cfg, w.db.clone(), &[9u8; 32])
                    .await
                    .unwrap();
                shell.gk_identity_reset(a).await;
                crate::bans::load(&w.state).await.unwrap();
            }
            _ => {
                // As l4f's deletion leaves it (`Host::delete_user`), for the hourly sweep
                tombstone(&w.db, a).await;
                log::sweep(w.relay()).await.unwrap();
            }
        }
        assert!(w.opened(before, &[ann]).await, "exit {k} opened an epoch");
        w.post(ann, k as u8, &format!("p{k}"), k as i64 + 1).await;
    }
    w.reconnect(bob).await;
    w.read(bob);
    let read = w.until(60_000, |w| w.people[bob].texts.len() >= MANY).await;
    assert!(read, "read {} of {MANY}", w.people[bob].texts.len());
    let mut want: Vec<String> = (0..MANY).map(|k| format!("p{k}")).collect();
    let mut got = w.people[bob].texts.clone();
    want.sort();
    got.sort();
    assert_eq!(got, want);
}

/// Runs until `a` holds no seat in the group, at most 20 s; whether it does not.
async fn unseated(w: &mut World, a: &[u8; 16]) -> bool {
    let end = w.now() + 20_000;
    while w.now() < end {
        w.until(200, |_| false).await;
        if db::seats_of_account(&w.db, a).await.unwrap().is_empty() {
            return true;
        }
    }
    false
}

/// K2 (plan 2d "gate unseat"): an account seated by its live follow alone, with no seat in
/// the log (its `LogJoinMany` refused as full, or it keeps no history), keeps that seat when
/// it goes offline. A gate it fails or a new password takes it out of the group all the
/// same: its own prune at sign-in (`out_of_logs`), a new password (`log_keep_only`) and the
/// pass over every gated log (`prune_gated`), each only whom it names.
#[tokio::test]
async fn e2e_k2_a_live_follows_seat_alone_exits_at_a_gate_or_password_it_fails_while_offline() {
    let mut w = World::new().await;
    let people = [
        w.person("dan").await,
        w.person("eve").await,
        w.person("fay").await,
    ];
    let seated = w
        .until(20_000, |w| {
            people.iter().all(|i| w.people[*i].epoch().is_some())
        })
        .await;
    assert!(seated, "seated");
    let [dan, eve, fay] = people.map(|i| w.people[i].a);
    for i in people {
        let sid = w.people[i].sid;
        w.people[i].online = false;
        w.state.gk.on_session_end(sid);
        w.followers.retain(|s| *s != sid);
    }
    crate::accounts::raw(w.relay(), "DELETE FROM voipc_members")
        .await
        .unwrap();
    let held =
        async |w: &World, a: &[u8; 16]| !db::seats_of_account(&w.db, a).await.unwrap().is_empty();
    w.until(1_000, |_| false).await;
    for a in [&dan, &eve, &fay] {
        assert!(
            held(&w, a).await,
            "an account's text seat outlives its connection"
        );
    }
    w.relay()
        .out_of_logs(&fay, &[CONV.to_string()])
        .await
        .unwrap();
    assert!(unseated(&mut w, &fay).await, "out by its own prune");
    assert!(held(&w, &dan).await && held(&w, &eve).await);
    w.relay().log_keep_only(CONV, &[dan]).await.unwrap();
    assert!(unseated(&mut w, &eve).await, "out by a new password");
    assert!(held(&w, &dan).await);
    let relay = w.state.accounts.clone().unwrap();
    relay
        .prune_gated(&[(CONV.to_string(), vec!["crew".to_string()])])
        .await;
    assert!(
        unseated(&mut w, &dan).await,
        "out by the pass over gated logs"
    );
}

/// J4 review 1: an identity reset at a sign-in elsewhere ends none of the account's sessions.
/// One from before it volunteers no more: its offer is dropped (a group it follows later is
/// not told it), and a new one is refused, its identity no longer the account's.
#[tokio::test]
async fn e2e_k2_a_session_from_before_an_identity_reset_volunteers_no_more() {
    let mut w = World::new().await;
    let ann = w.person("ann").await;
    let p = &w.people[ann];
    let (sid, a, ik) = (p.sid, p.a, p.signed.identity);
    let offer = || ClientMessage::KeyholdVolunteer {
        on: true,
        platform: voipc_protocol::gk::platform::BROWSER,
        pair: Some((&crate::gk_e2e_r2::conn_pair(&ik, sid).1).into()),
    };
    w.send(sid, offer()).await;
    assert!(w.state.gk.volunteers_for_test(sid), "offered");
    let new = generate_identity_key_pair();
    w.relay()
        .set_identity(AccountId(a), &new.public_key().serialize())
        .await
        .unwrap();
    w.relay().gk_identity_reset(&a).await;
    assert!(!w.state.gk.volunteers_for_test(sid), "its offer went");
    let _ = w.drain(sid).await;
    w.send(sid, offer()).await;
    assert!(!w.state.gk.volunteers_for_test(sid), "a new one is refused");
    let refused = w.drain(sid).await.iter().any(|f| {
        matches!(
            f,
            ServerMessage::EpochRefused {
                what: refused_what::VOLUNTEER,
                ..
            }
        )
    });
    assert!(refused, "and told so");
}

// ── Dive 4 round 2, item 1 (d4-r2-plan.md) ────────────────────────────────

/// Runs `q` (no binds) on the scratch database.
async fn exec_sql(db: &Store, q: &str) {
    let q = sqlx::AssertSqlSafe(q.to_string());
    match db {
        Store::Lite(b) => {
            sqlx::query(q).execute(&b.0).await.unwrap();
        }
        Store::Pg(b) => {
            sqlx::query(q).execute(&b.0).await.unwrap();
        }
    }
}

/// The accounts path of a kick or a text channel left (`out_of_log` -> `leave_log`): the exit
/// of the account's seats in the conversation's group is asked in the store before anything
/// else, for a log member (its membership row goes) and for an account that follows the
/// channel without keeping its log (no row: its seat is the follow's alone). Here the group's
/// actor cannot load yet (a table out of reach), as one that is loading or stopped by a crash:
/// both asks are kept, with the cause. Once the group takes them and writes what they entered,
/// they go.
#[tokio::test]
async fn k2_d4r2_a_kick_asks_the_exit_ahead_for_a_member_and_a_follow_only_account() {
    let _ = tracing_on();
    let (db, file) = scratch_db().await;
    let inc = db::gk_start(&db, true).await.unwrap().unwrap();
    let cfg = crate::config::AccountsConfig {
        mode: crate::config::AccountsMode::Optional,
        ..Default::default()
    };
    let relay = crate::accounts::Relay::open_with(&cfg, db.clone(), &[9u8; 32])
        .await
        .unwrap();
    let mut state = ServerState::new(
        &crate::config::ServerConfig {
            group_key: true,
            ..Default::default()
        },
        crate::settings::ServerSettings::default(),
        vec![],
        "test-admin-token".into(),
    );
    state.accounts = Some(Arc::new(relay));
    let state = Arc::new(state);
    state.gk.attach(db.clone(), inc);
    state.accounts.as_ref().unwrap().bind_gk(&state.gk);
    crate::state::test_support::put_in_channel(&state, CHAN, &[]).await;
    {
        let mut channels = state.channels.write().await;
        let c = channels.get_mut(&CHAN).unwrap();
        c.info.text = true;
        c.info.log = CONV.into();
        c.log_conv = CONV.into();
    }
    let mut sids = vec![];
    for name in ["kim", "lou"] {
        let id = AccountId::new();
        state
            .accounts
            .as_ref()
            .unwrap()
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
        let (uid, sid) = crate::state::test_support::add_user(&state, name);
        state.sessions.get_mut(&sid).unwrap().account = Some(account_session(id.0));
        crate::state::test_support::put_in_channel(&state, CHAN, &[(uid, sid)]).await;
        sids.push((id.0, sid));
    }
    let (kim, lou) = (sids[0], sids[1]);
    // kim keeps the log; lou only follows the channel
    let hex: String = kim.0.iter().map(|x| format!("{x:02x}")).collect();
    let lit = match &db {
        Store::Lite(_) => format!("x'{hex}'"),
        Store::Pg(_) => format!("'\\x{hex}'::bytea"),
    };
    exec_sql(
        &db,
        &format!(
            "INSERT INTO voipc_members (conv, account, joined_at) VALUES ('{CONV}', {lit}, 0)"
        ),
    )
    .await;
    exec_sql(
        &db,
        "ALTER TABLE voipc_gk_groups RENAME TO voipc_gk_groups_away",
    )
    .await;
    crate::accounts::out_of_log(&state, CHAN, kim.1).await;
    crate::accounts::out_of_log(&state, CHAN, lou.1).await;
    let mut asked: Vec<([u8; 16], u8)> = db::exit_asks(&db, CONV)
        .await
        .unwrap()
        .into_iter()
        .map(|x| (x.account, x.cause))
        .collect();
    asked.sort_unstable();
    let mut want = vec![
        (kim.0, crate::gk::group::cause::LEAVE),
        (lou.0, crate::gk::group::cause::LEAVE),
    ];
    want.sort_unstable();
    let q = format!("SELECT COUNT(*) FROM voipc_members WHERE conv = '{CONV}' AND account = {lit}");
    let q = sqlx::AssertSqlSafe(q);
    let n: i64 = match &db {
        Store::Lite(b) => sqlx::query_scalar(q).fetch_one(&b.0).await.unwrap(),
        Store::Pg(b) => sqlx::query_scalar(q).fetch_one(&b.0).await.unwrap(),
    };
    let member_gone = n == 0;
    exec_sql(
        &db,
        "ALTER TABLE voipc_gk_groups_away RENAME TO voipc_gk_groups",
    )
    .await;
    let mut left = vec![];
    for _ in 0..200 {
        left = db::exit_asks(&db, CONV).await.unwrap();
        if left.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    state.gk.on_purge(CONV);
    drop_db(&file);
    assert!(
        asked == want && member_gone && left.is_empty(),
        "with the group not yet loaded the asks kept: {asked:?} (want {want:?}); kim's \
         membership gone: {member_gone}; once the group took them, asks left: {left:?}"
    );
}

/// Dive 4 round 2 review R2-1: an account's own `LogLeave` ("Stop keeping this channel") took
/// its membership row out before it asked its seats' exit, so a stop between the two left
/// neither: the next start kept the seat, keyed at every opening until its 90-day expiry. The
/// exit is asked first now, as every other way out of a log asks it. A probe in the database
/// reads, as the membership row goes, whether the ask is there: what a stop at that point
/// leaves for the next start. And a `LogLeave` that finds no membership row (the old order cut
/// off by a stop, asked again) still exits a seat no session here holds, and settles its ask.
#[tokio::test]
async fn e2e_k2_d4r2_a_log_leave_asks_the_exit_before_its_membership_goes() {
    let mut w = World::new().await;
    let crowd = w.crowd(2).await;
    assert!(
        w.crowd_seated(&crowd).await,
        "the crowd is seated by its LogJoin"
    );
    let probe: &[&str] = match &w.db {
        Store::Lite(_) => &[
            "CREATE TABLE d4r2_probe (n BIGINT)",
            "CREATE TRIGGER d4r2_probe AFTER DELETE ON voipc_members BEGIN
               INSERT INTO d4r2_probe SELECT COUNT(*) FROM voipc_gk_exit_asks WHERE account = OLD.account;
             END",
        ],
        Store::Pg(_) => &[
            "CREATE TABLE d4r2_probe (n BIGINT)",
            "CREATE FUNCTION d4r2_probe() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
               INSERT INTO d4r2_probe SELECT COUNT(*) FROM voipc_gk_exit_asks WHERE account = OLD.account;
               RETURN OLD;
             END $$",
            "CREATE TRIGGER d4r2_probe AFTER DELETE ON voipc_members FOR EACH ROW EXECUTE FUNCTION d4r2_probe()",
        ],
    };
    for q in probe {
        exec_sql(&w.db, q).await;
    }
    w.leave_log(crowd[0].1).await;
    let asked = crate::accounts::raw(w.relay(), "SELECT MAX(n) FROM d4r2_probe")
        .await
        .unwrap();
    let out = unseated(&mut w, &crowd[0].0).await;
    // The other's membership row gone with no ask, as the old order left it after a stop
    exec_sql(&w.db, "DELETE FROM voipc_members").await;
    w.leave_log(crowd[1].1).await;
    let out_again = unseated(&mut w, &crowd[1].0).await;
    let mut left = vec![];
    for _ in 0..100 {
        left = db::exit_asks(&w.db, CONV).await.unwrap();
        if left.is_empty() {
            break;
        }
        w.until(50, |_| false).await;
    }
    assert!(
        asked == 1 && out && out_again && left.is_empty(),
        "exit asks as the membership row went: {asked}; the leaver's seat exits: {out}; with \
         no membership row left, a LogLeave still exits the seat: {out_again}; asks left: \
         {left:?}"
    );
}
