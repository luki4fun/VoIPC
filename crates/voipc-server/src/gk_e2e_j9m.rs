//! End-to-end group-key scenarios added by wave-2 slice J9M (2026-11-19): member key intake: `s_m`
//! and `BK` kept, and the self-row written, only after `confirm`; kept reads after a browser
//! reload.
//! The relay's real `gk` code driven by the clients' real `voipc_crypto::group_state` code;
//! shared helpers live in `gk_e2e_tests.rs`.
//!
//! A browser reload, as the app does it: the page keeps nothing of its own, so the account's
//! `AccountSync` starts from what the relay keeps (its vault, the log), and `GroupKeying` tracks
//! the channel with the vault's floor (`AccountSync::gk_floor`; a floor with no keyholder header
//! held). Its kept read goes at once, often before the live fetch is answered.
//!
//! The harness is `gk_e2e_j8k.rs`'s (a trimmed copy of `gk_e2e_t1.rs`'s), with the vault floor
//! (`Person::vault`) and a live answer taken only once the first kept ask went
//! (`Person::live_late`).

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use l4f_accounts::model::{AccountId, NewUser};
use l4f_accounts::store::Store;
use voipc_crypto::account::{SignedIn, Vault};
use voipc_crypto::envelope::{envelope, open_envelope};
use voipc_crypto::group_key::wire::post_digest;
use voipc_crypto::group_key::{Endorsement, GroupKind, MemberId, Origin, SeatKeys, SignedHeader};
use voipc_crypto::group_state::{
    GkCtx, GkEpoch, GkOut, GkStart, GkTrack, GroupKeying, MemoryPins, PastEpoch, Platform,
    VaultFloor,
};
use voipc_crypto::log::LogKey;
use voipc_crypto::sync::{AccountSync, Event, LogMemory, Prefs, ITEM_LOGKEY};
use voipc_crypto::{generate_identity_key_pair, IdentityKeyPair, SignalStores};
use voipc_protocol::codec::PROTOCOL_VERSION;
use voipc_protocol::gk::{refused_what, refused_why, GkMember, InPiece};
use voipc_protocol::messages::{AccountReply, AccountRequest, ClientMessage, ServerMessage};
use voipc_protocol::types::{ChannelId, UserId, VaultBlob};

use super::gk_e2e_tests::{account_session, drop_db, scratch_db, show, tracing_on, Holder};
use crate::accounts::gk as db;
use crate::config::{AccountsConfig, AccountsMode, ServerConfig};
use crate::control::{ControlRx, ControlTx};
use crate::settings::ServerSettings;
use crate::state::{RateLimiter, ServerState};

const CHAN: ChannelId = 9;
const CONV: &str = "c:j9mhall";

fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn raw(ik: &IdentityKeyPair) -> [u8; 32] {
    ik.public_key().public_key_bytes().try_into().unwrap()
}

/// What a hostile relay does to a past answer for one epoch before the app takes it.
type Tamper = Box<dyn Fn(&mut InPiece) + Send>;

/// A past answer as it reached the app: its epoch, the `head`'s `(epoch, join)`, and whether
/// it carried the epoch's opening.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Answer {
    epoch: u32,
    head: (u32, u32),
    opening: bool,
}

/// N1's kept copy of one post of ours (gk_net.rs `KeptPost`).
struct KeptCopy {
    envelope: Vec<u8>,
    sent_at: u64,
    /// Its latest `released`: under what, and `post_digest` of the bytes it went as (what its
    /// `EpochPostTaken` names).
    went: Option<(GkEpoch, [u8; 16])>,
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
    copies: HashMap<[u8; 16], KeptCopy>,
    /// Past epochs the relay said it does not keep (`EpochRefused{FETCH, NOT_STORED}`).
    not_stored: usize,
    /// The past answers it took in, as they reached it.
    answers: Vec<Answer>,
    /// A hostile relay's change to the past answers of one epoch, and how often it changed one.
    tamper: Option<(u32, Tamper)>,
    tampered: usize,
    /// A hostile relay that answers no live fetch of this connection: it takes no head, so
    /// its kept reads go with no floor (`have: None`) and are taken on the binding alone.
    live_held: bool,
    /// The browser's start: the group is tracked with the vault's floor, and floors the vault
    /// raises later go to `GroupKeying::floors_in` (gk.rs `settle`).
    vault: bool,
    /// Live answers held back until the first kept ask went (`Some`): the page's kept read
    /// goes before its live fetch is answered, so it holds no keyholder header yet.
    live_late: Option<Vec<ServerMessage>>,
}

impl Person {
    fn took(&mut self, out: GkOut) {
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
        self.out.extend(out.send);
        // The floors to the vault, as the browser's page hands them (gk.rs `take`)
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
    }

    fn events(&mut self, events: Vec<Event>) {
        for e in events {
            if let Event::ChannelMessage { envelope, .. } = e {
                self.texts.push(open_envelope(&envelope).text);
            }
        }
    }

    /// A past answer, as the relay sent it, then as the hostile relay of a test changed it.
    fn past_answer(&mut self, f: &ServerMessage) -> ServerMessage {
        let mut f = f.clone();
        if let ServerMessage::EpochIn {
            piece, part, last, ..
        } = &mut f
        {
            if let Some(at) = piece.past {
                assert!(*part == 0 && *last, "a past answer here is one part");
                if let Some((epoch, tamper)) = &self.tamper {
                    if at.epoch == *epoch {
                        tamper(piece);
                        self.tampered += 1;
                    }
                }
                if let Some(h) = &piece.head {
                    let sh =
                        SignedHeader::decode(&h.header.body, &h.header.sig, GroupKind::Text, CONV)
                            .expect("a header");
                    self.answers.push(Answer {
                        epoch: at.epoch,
                        head: (sh.header().epoch, sh.header().join),
                        opening: piece.opening.is_some(),
                    });
                }
            }
        }
        f
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
            ServerMessage::EpochPostTaken { group, post } => {
                // As the apps do (`group_state::Copies::taken`): the relay took a post of
                // ours, its copy is filed now, under the epoch that send went under
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
                    // N1: what went waits for its next `released`
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
                let live =
                    matches!(f, ServerMessage::EpochIn { piece, .. } if piece.past.is_none());
                if self.live_held && live {
                    return;
                }
                if let (Some(late), true) = (self.live_late.as_mut(), live) {
                    late.push(f.clone());
                    return;
                }
                let f = self.past_answer(f);
                let c = GkCtx {
                    pins: &mut self.pins,
                    now,
                };
                let out = self.keying.frame(&mut self.st, &f, c);
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
        if self.vault && self.sync.take_gk_news() {
            for (group, f) in self.sync.gk_floors_moved(&[CONV.to_string()]) {
                let out = self.keying.floors_in(&group, f);
                self.took(out);
            }
        }
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

    /// A post in the channel, its kept copy waiting for the epoch it goes under.
    fn post(&mut self, id: u8, text: &str, now: u64) {
        let env = envelope(&format!("j9m-{id}"), text, None);
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
        self.took(out);
    }

    /// Its kept read is done: every past epoch it asked for was answered.
    fn read_done(&self) -> bool {
        self.past.is_empty()
    }
}

/// The guest keyholder as a client of its own: a task answers each frame as it comes.
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

/// The relay, its keyholder, and the accounts' apps.
struct World {
    state: Arc<ServerState>,
    db: Store,
    file: std::path::PathBuf,
    queues: HashMap<UserId, (ControlTx, Option<ControlRx>)>,
    holder: Option<Keyholder>,
    people: Vec<Person>,
    followers: Vec<UserId>,
    last_tick: u64,
}

impl Drop for World {
    fn drop(&mut self) {
        drop_db(&self.file);
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
        let state = hall(&db).await;
        let ik = generate_identity_key_pair();
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

    /// The head the keyholder holds: `(epoch, join)`.
    fn head_at(&self) -> (u32, u32) {
        let Some(k) = &self.holder else {
            return (0, 0);
        };
        let h = k.holder.lock().unwrap();
        h.held
            .as_ref()
            .map_or((0, 0), |h| (h.head.header().epoch, h.head.header().join))
    }

    fn head(&self) -> u32 {
        self.head_at().0
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
                let account = self
                    .people
                    .iter()
                    .find(|p| p.online && p.sid == sid)
                    .map(|p| p.a);
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
                let ServerMessage::EpochPostIn {
                    group, ciphertext, ..
                } = &msg
                else {
                    unreachable!()
                };
                let taken = (group.clone(), post_digest(ciphertext));
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
            copies: HashMap::new(),
            not_stored: 0,
            answers: vec![],
            tamper: None,
            tampered: 0,
            live_held: false,
            vault: false,
            live_late: None,
        });
        self.people.len() - 1
    }

    /// Its `GroupKeying` starts with the seat keys `AccountSync` publishes and tracks the
    /// group, which it follows.
    async fn start(&mut self, i: usize) {
        let settled = self
            .until(15_000, |w| {
                w.people[i].sync.seat_keys().is_some() && w.people[i].out.is_empty()
            })
            .await;
        assert!(settled, "seat keys settled");
        // A browser's page tracks the channel with the vault's floor (here once its pages
        // are in, so the floor names a keyholder header the page does not hold)
        let mut vault = VaultFloor::None;
        if self.people[i].vault {
            for _ in 0..1_500 {
                self.until(10, |_| false).await;
                vault = self.people[i].sync.gk_floor(CONV);
                if matches!(vault, VaultFloor::Some(..)) {
                    break;
                }
            }
            assert!(
                matches!(vault, VaultFloor::Some(..)),
                "the vault's floor is in"
            );
        }
        let seat_keys = self.people[i].sync.seat_keys();
        let now = self.now();
        let run = self.state.gk.run;
        let p = &mut self.people[i];
        let _ = p.keying.start(GkStart {
            on: true,
            run,
            relay_clock: now / 1000,
            platform: if p.vault {
                Platform::Browser
            } else {
                Platform::Desktop
            },
            help_hold_keys: false,
            user_id: p.sid,
            identity: p.signed.identity,
            account: Some(p.a),
            seat_keys,
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
            vault,
        );
        p.took(out);
        let (sid, a) = (p.sid, p.a);
        self.follow(sid, Some(a));
    }

    /// The account's app ends, and runs again on a new connection with nothing kept but what
    /// the relay holds (its vault, the log): a new device. `tamper`: what a hostile relay does
    /// to the past answers of one epoch it sends there.
    async fn reconnect(&mut self, i: usize, tamper: Option<(u32, Tamper)>) {
        self.again(i, tamper, false).await;
    }

    /// The account's page reloads in a browser: its app runs again from what the relay keeps,
    /// tracks the group with the vault's floor, and its kept read goes before its live fetch
    /// is answered (`Person::vault`, `Person::live_late`).
    async fn reload(&mut self, i: usize) {
        self.again(i, None, true).await;
    }

    async fn again(&mut self, i: usize, tamper: Option<(u32, Tamper)>, browser: bool) {
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
        if self.people[i].online {
            self.people[i].online = false;
            self.state.gk.on_session_end(old);
            self.followers.retain(|s| *s != old);
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
        let a = p.a;
        let j = self.connect(a, signed).await;
        let mut back = self.people.remove(j);
        back.tamper = tamper;
        if browser {
            back.vault = true;
            back.live_late = Some(vec![]);
        }
        self.people[i] = back;
        self.start(i).await;
    }

    /// Accounts that keep the log and follow nothing live, seated in the group by their
    /// `LogJoin` (plan 2d). Each one's `LogLeave` later opens an epoch.
    async fn crowd(&mut self, n: usize) -> Vec<([u8; 16], UserId)> {
        let mut out = vec![];
        for k in 0..n {
            let id = AccountId::new();
            let name = format!("crowd{}", rand::random::<u32>());
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
            let keys = SeatKeys::generate(1, wall_ms() / 1000);
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
            assert!(joined, "crowd {k} joined the log");
            out.push((id.0, sid));
        }
        out
    }

    /// `sid`'s account stops keeping the log (`LogLeave`): its seat exits.
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
            let out: Vec<ClientMessage> = self.people[i].out.drain(..).collect();
            let asked = out
                .iter()
                .any(|m| matches!(m, ClientMessage::EpochFetch { at, .. } if !at.is_empty()));
            for m in out {
                self.send(sid, m).await;
            }
            // The live answers that came before the first kept ask went, taken now: before
            // the kept answers, which the relay sends after them
            if asked {
                if let Some(late) = self.people[i].live_late.take() {
                    let p = &mut self.people[i];
                    for f in &late {
                        p.frame(f, now);
                    }
                    let out: Vec<ClientMessage> = self.people[i].out.drain(..).collect();
                    for m in out {
                        self.send(sid, m).await;
                    }
                }
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

    /// Its app reads the channel's kept history now: until it read every text of `want`, and
    /// `n` past epochs it asked for were answered and none waits (or 30 s); then a second
    /// more, for anything read late.
    async fn read_n(&mut self, i: usize, want: &[&str], n: usize) {
        let out = self.people[i].sync.enter(CONV);
        self.people[i].out.extend(out);
        let want: Vec<String> = want.iter().map(|t| t.to_string()).collect();
        self.until(30_000, move |w| {
            let p = &w.people[i];
            let read = want.iter().all(|t| p.texts.contains(t));
            read && p.read_done() && p.answers.len() + p.not_stored >= n
        })
        .await;
        self.until(1_000, |_| false).await;
    }

    /// The group's headers kept now, of its one generation, by `(epoch, join)`.
    async fn headers(&self) -> HashMap<(u32, u32), SignedHeader> {
        let row = db::group(&self.db, CONV).await.unwrap().unwrap();
        db::headers(&self.db, CONV, &row.head.gen)
            .await
            .unwrap()
            .into_iter()
            .map(|h| {
                let sh = SignedHeader::decode(&h.body, &h.sig, GroupKind::Text, CONV).unwrap();
                ((h.epoch, h.j), sh)
            })
            .collect()
    }

    /// A seated person, the head having moved by its seating Join: the Join's `(epoch, join)`.
    async fn seated(&mut self, i: usize) -> (u32, u32) {
        let ok = self.until(20_000, |w| w.people[i].epoch().is_some()).await;
        assert!(ok, "seated");
        self.head_at()
    }
}

fn sorted(mut t: Vec<String>) -> Vec<String> {
    t.sort();
    t
}

/// J9M item 1: a browser page that reloads tracks its channel with the vault's floor, whose
/// keyholder header it does not hold, and its kept read goes before its live fetch is
/// answered: every past epoch is taken on the binding alone. dan is seated by a Join after
/// epoch 2's opening (an exit's, which names the Genesis's keyholder set); carol writes in
/// epoch 2 after it, and in epoch 3, the head. Epoch 2 is answered at its last Join with the
/// opening (J8K), and that Join's signer is checked against the set the opening names. The
/// page sent its floor as `have` with no anchor held, so the relay walked back from the
/// floor's keyholder header (the very set: an empty walk) and sent no set, and the read was
/// refused. A kept ask names the floor only with its keyholder header held (`kept.rs` `send`).
/// The current epoch reads on the binding alone by the self-row's `s_m` (J8K's rule holds).
#[tokio::test]
async fn e2e_j9m_a_reloaded_browser_page_reads_its_kept_posts_before_its_live_answer() {
    let mut w = World::new().await;
    let ann = w.person("ann").await;
    w.seated(ann).await;
    let carol = w.person("carol").await;
    w.seated(carol).await;
    // carol writes in epoch 1, so its openings are pushed to her (dan, not seated then, is
    // told it is not stored here)
    w.post(carol, 1, "before dan", 1).await;
    let crowd = w.crowd(2).await;
    assert!(w.crowd_seated(&crowd).await, "the crowd is seated");
    let before = w.head();
    w.leave_log(crowd[0].1).await;
    assert!(w.opened(before, &[carol]).await, "epoch 2 opened");
    let dan = w.person("dan").await;
    let dan_join = w.seated(dan).await;
    assert_eq!(
        dan_join,
        (2, 1),
        "dan seated by a Join after epoch 2's opening"
    );
    let h = w.headers().await;
    assert!(
        !h[&(2, 0)].header().kind.sets_keyholders(),
        "epoch 2 opened by an exit: its set is the Genesis's"
    );
    w.post(carol, 2, "after dan", 2).await;
    let before = w.head();
    w.leave_log(crowd[1].1).await;
    assert!(w.opened(before, &[carol]).await, "epoch 3 opened");
    w.post(carol, 3, "now", 3).await;
    // The control: a new device that takes its head first reads both
    w.reconnect(dan, None).await;
    w.read_n(dan, &["after dan", "now"], 3).await;
    assert_eq!(
        (
            sorted(w.people[dan].texts.clone()),
            w.people[dan].not_stored
        ),
        (vec!["after dan".to_string(), "now".to_string()], 1),
        "the control: a new device"
    );
    // The reload
    w.reload(dan).await;
    w.read_n(dan, &["after dan", "now"], 3).await;
    let p = &w.people[dan];
    assert!(
        p.live_late.is_none(),
        "its kept read went before its live answer"
    );
    assert_eq!(
        (sorted(p.texts.clone()), p.not_stored),
        (vec!["after dan".to_string(), "now".to_string()], 1),
        "the reloaded page reads both: {:?}",
        p.answers
    );
}
