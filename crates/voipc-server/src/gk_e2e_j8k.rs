//! End-to-end group-key scenarios added by fix-round slice J8K (2026-11-19). The relay's real
//! `gk` code driven by the clients' real `voipc_crypto::group_state` code; shared helpers live in
//! `gk_e2e_tests.rs`.
//!
//! T1e A: a kept post made in the epoch its reader was seated in by a Join (`j` > 0) is read on
//! that reader's new device (§5.10 "a reader opens it from its seat at epoch `e`"). The relay
//! answers such a seat's past epoch at the epoch's last Join with the opening
//! (`gk/store.rs` `past`), and the app takes it there (`past.rs` `take_past_at`): checked as
//! that epoch's, so a relay that hands another epoch's Join, or a Join nobody of the epoch's
//! set signed, gets no post read.
//!
//! The harness is a trimmed copy of `gk_e2e_t1.rs`'s (its items are private there): a relay
//! with accounts, every `AccountRequest` through `accounts::handle_request`, the group key's
//! messages through `Groups::handle`, `EpochPost` through the group key's checks and a fan-out
//! to the channel's followers; each account K1's `AccountSync` and C3b's `GroupKeying` on one
//! connection, glued as N1 glues them (kept copies filed after N1's settle, shortened here as
//! T1e shortens it); the keyholder `gk_e2e_tests.rs`'s guest on a task of its own. Runs on
//! Postgres with `VOIPC_TEST_POSTGRES` set (`scratch_db`).

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use l4f_accounts::model::{AccountId, NewUser};
use l4f_accounts::store::Store;
use voipc_crypto::account::{SignedIn, Vault};
use voipc_crypto::envelope::{envelope, open_envelope};
use voipc_crypto::group_key::{Endorsement, GroupKind, MemberId, Origin, SeatKeys, SignedHeader};
use voipc_crypto::group_state::{
    GkCtx, GkEpoch, GkOut, GkStart, GkTrack, GroupKeying, MemoryPins, PastEpoch, Platform,
    VaultFloor,
};
use voipc_crypto::log::LogKey;
use voipc_crypto::sync::{AccountSync, Event, LogMemory, Prefs, ITEM_LOGKEY};
use voipc_crypto::{generate_identity_key_pair, IdentityKeyPair, SignalStores};
use voipc_protocol::codec::PROTOCOL_VERSION;
use voipc_protocol::gk::{self as wire, refused_what, refused_why, GkMember, InPiece};
use voipc_protocol::messages::{AccountReply, AccountRequest, ClientMessage, ServerMessage};
use voipc_protocol::types::{ChannelId, UserId, VaultBlob};

use super::gk_e2e_tests::{account_session, drop_db, scratch_db, show, tracing_on, Holder};
use crate::accounts::gk as db;
use crate::config::{AccountsConfig, AccountsMode, ServerConfig};
use crate::control::{ControlRx, ControlTx};
use crate::settings::ServerSettings;
use crate::state::{RateLimiter, ServerState};

const CHAN: ChannelId = 9;
const CONV: &str = "c:j8khall";

/// N1's settle as `gk_e2e_t1.rs` shortens it: a post's kept copy is filed once no refusal came
/// for it this long.
const KEPT_SETTLE_MS: u64 = 1_000;

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
    /// Its latest `released`: under what, when, in which order.
    went: Option<(GkEpoch, u64, u64)>,
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
    sends: u64,
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
}

impl Person {
    fn took(&mut self, out: GkOut, now: u64) {
        for (_, post_id, ep) in out.released {
            if let Some(c) = self.copies.get_mut(&post_id) {
                self.sends += 1;
                c.went = Some((ep, now, self.sends));
            }
        }
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
                if self.live_held
                    && matches!(f, ServerMessage::EpochIn { piece, .. } if piece.past.is_none())
                {
                    return;
                }
                let f = self.past_answer(f);
                let c = GkCtx {
                    pins: &mut self.pins,
                    now,
                };
                let out = self.keying.frame(&mut self.st, &f, c);
                self.took(out, now);
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
        self.took(out, now);
    }

    /// N1/W2's glue for a kept read: each past epoch `AccountSync` names goes to
    /// `GroupKeying::past_epoch`; what it has is handed back, what it asked for waits.
    fn pasts(&mut self, now: u64) {
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
        self.took(out, now);
    }

    /// N1's copies that settled, filed in the order their posts went, each under the epoch
    /// its latest `released` named.
    fn file(&mut self, now: u64) {
        let mut due: Vec<([u8; 16], u64)> = self
            .copies
            .iter()
            .filter_map(|(id, c)| {
                let (_, at, order) = c.went.as_ref()?;
                (now >= at + KEPT_SETTLE_MS).then_some((*id, *order))
            })
            .collect();
        due.sort_by_key(|d| d.1);
        for (id, _) in due {
            let c = self.copies.remove(&id).expect("due");
            let (ep, _, _) = c.went.expect("it went");
            let kept = self
                .sync
                .send_channel_gk(CONV, c.envelope, c.sent_at, None, ep);
            self.out.extend(kept);
        }
    }

    /// The head epoch it holds `CK` of.
    fn epoch(&self) -> Option<u32> {
        self.keying.current_epoch(CONV).map(|e| e.epoch)
    }

    /// A post in the channel, its kept copy waiting for the epoch it goes under.
    fn post(&mut self, id: u8, text: &str, now: u64) {
        let env = envelope(&format!("j8k-{id}"), text, None);
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
    /// The keyholder's identity: it signs the group's headers.
    holder_ik: IdentityKeyPair,
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
            holder_ik: ik,
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
            sends: 0,
            not_stored: 0,
            answers: vec![],
            tamper: None,
            tampered: 0,
            live_held: false,
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
        let seat_keys = self.people[i].sync.seat_keys();
        let now = self.now();
        let run = self.state.gk.run;
        let p = &mut self.people[i];
        let _ = p.keying.start(GkStart {
            on: true,
            run,
            relay_clock: now / 1000,
            platform: Platform::Desktop,
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
            VaultFloor::None,
        );
        p.took(out, now);
        let (sid, a) = (p.sid, p.a);
        self.follow(sid, Some(a));
    }

    /// The account's app ends, and runs again on a new connection with nothing kept but what
    /// the relay holds (its vault, the log): a new device. `tamper`: what a hostile relay does
    /// to the past answers of one epoch it sends there.
    async fn reconnect(&mut self, i: usize, tamper: Option<(u32, Tamper)>) {
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
            p.pasts(now);
            p.file(now);
            let out: Vec<ClientMessage> = self.people[i].out.drain(..).collect();
            for m in out {
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

    /// Its app reads the channel's kept history now: until it read every text of `want`, or
    /// both past epochs it asks for (1 and 2) were answered and none waits (or 30 s); then a
    /// second more, for anything read late.
    async fn read(&mut self, i: usize, want: &[&str]) {
        let out = self.people[i].sync.enter(CONV);
        self.people[i].out.extend(out);
        let want: Vec<String> = want.iter().map(|t| t.to_string()).collect();
        self.until(30_000, move |w| {
            let p = &w.people[i];
            let read = want.iter().all(|t| p.texts.contains(t));
            read && p.read_done() && p.answers.len() + p.not_stored >= 2
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

fn header_in(sh: &SignedHeader) -> wire::HeaderIn {
    wire::HeaderIn {
        body: sh.body().to_vec(),
        sig: sh.sig().to_vec(),
    }
}

fn sorted(mut t: Vec<String>) -> Vec<String> {
    t.sort();
    t
}

/// What `j8k_epochs` built: epoch 1 (the Genesis, then ann's Join, bob's Join, carol's Join,
/// the crowd's), with carol's kept post "joined"; epoch 2 (an opening, then a Join), with
/// carol's kept post "opened"; the head in epoch 3. ann and bob read carol's posts by the
/// group key (a writer's own chains open by its self-wrap).
struct Epochs {
    ann: usize,
    bob: usize,
    /// The Joins that seated ann and bob.
    ann_join: (u32, u32),
    bob_join: (u32, u32),
}

async fn j8k_epochs(w: &mut World) -> Epochs {
    let ann = w.person("ann").await;
    let ann_join = w.seated(ann).await;
    let bob = w.person("bob").await;
    let bob_join = w.seated(bob).await;
    let carol = w.person("carol").await;
    let carol_join = w.seated(carol).await;
    assert_eq!(ann_join, (1, 1), "ann seated by the Genesis's first Join");
    assert_eq!(bob_join, (1, 2), "bob seated by its second");
    assert_eq!(carol_join, (1, 3), "carol by its third");
    // carol writes in epoch 1, so its next opening is pushed to her
    w.post(carol, 1, "joined", 1).await;
    assert_eq!(w.people[carol].epoch(), Some(1));
    let crowd = w.crowd(2).await;
    assert!(w.crowd_seated(&crowd).await, "the crowd is seated");
    assert_eq!(w.head(), 1, "by Joins");
    let before = w.head();
    w.leave_log(crowd[0].1).await;
    assert!(w.opened(before, &[carol]).await, "epoch 2 opened");
    w.post(carol, 2, "opened", 2).await;
    assert_eq!(w.people[carol].epoch(), Some(2));
    let more = w.crowd(1).await;
    assert!(w.crowd_seated(&more).await);
    assert_eq!(w.head_at(), (2, 1), "a Join after epoch 2's opening");
    let before = w.head();
    w.leave_log(crowd[1].1).await;
    assert!(w.opened(before, &[carol]).await, "epoch 3 opened");
    Epochs {
        ann,
        bob,
        ann_join,
        bob_join,
    }
}

/// T1e A, §5.10: on a new device, bob (seated by the second Join of epoch 1) and ann (by the
/// first) read carol's kept post of epoch 1, which the relay answers at epoch 1's last Join
/// with its opening; and carol's post of epoch 2, made after its opening sealed to both and
/// followed by a Join, which is answered at the opening as before.
#[tokio::test]
async fn e2e_j8k_seats_a_join_added_and_seats_at_the_opening_read_their_epochs_kept_posts() {
    let mut w = World::new().await;
    let e = j8k_epochs(&mut w).await;
    let headers = w.headers().await;
    let last_of_1 = headers
        .keys()
        .filter(|(epoch, _)| *epoch == 1)
        .map(|k| k.1)
        .max()
        .unwrap();
    assert!(
        last_of_1 > e.bob_join.1,
        "the crowd's Join came after bob's"
    );
    for (who, join) in [(e.bob, e.bob_join), (e.ann, e.ann_join)] {
        w.reconnect(who, None).await;
        w.read(who, &["joined", "opened"]).await;
        let p = &w.people[who];
        assert_eq!(
            (sorted(p.texts.clone()), p.not_stored),
            (vec!["joined".to_string(), "opened".to_string()], 0),
            "seated by Join {join:?}, it reads both"
        );
        assert!(
            p.answers.contains(&Answer {
                epoch: 1,
                head: (1, last_of_1),
                opening: true,
            }),
            "epoch 1 at its last Join, with the opening: {:?}",
            p.answers
        );
        assert!(
            p.answers.contains(&Answer {
                epoch: 2,
                head: (2, 0),
                opening: false,
            }),
            "epoch 2 at its opening, as before: {:?}",
            p.answers
        );
    }
}

/// The hostile relay of the past path: bob's new device is handed, for epoch 1, a Join of
/// epoch 2; epoch 2's opening with epoch 1's last Join; that Join signed by someone outside
/// the epoch's set; and, for epoch 2, epoch 1's last Join moved by the group's own keyholder
/// into epoch 2 (named its opening's, re-signed). Each is refused, and only that epoch: bob
/// reads carol's post of the other. The control, untouched, reads both.
#[tokio::test]
async fn e2e_j8k_a_relay_that_hands_a_forged_or_out_of_epoch_join_gets_no_post_read() {
    let mut w = World::new().await;
    let e = j8k_epochs(&mut w).await;
    let h = w.headers().await;
    let last_of_1 = *h.keys().filter(|k| k.0 == 1).max().unwrap();
    let last = h[&last_of_1].clone();
    let open2 = h[&(2, 0)].clone();
    let join2 = h[&(2, 1)].clone();
    let outsider = generate_identity_key_pair();
    let by_outsider = {
        let mut x = last.header().clone();
        x.signer = MemberId::Conn(4242);
        SignedHeader::sign(x, &outsider).unwrap()
    };
    let moved = {
        let mut x = last.header().clone();
        x.epoch = 2;
        x.epoch_parent = open2.d();
        x.kh_parent = open2.kh();
        x.exits_upto = open2.header().exits_upto;
        SignedHeader::sign(x, &w.holder_ik).unwrap()
    };
    let head = |sh: &SignedHeader| {
        let j = header_in(sh);
        Box::new(move |p: &mut InPiece| p.head.as_mut().unwrap().header = j.clone()) as Tamper
    };
    let tampers: Vec<(&str, u32, Tamper, &str)> = vec![
        ("another epoch's Join", 1, head(&join2), "opened"),
        (
            "another epoch's opening",
            1,
            {
                let o = header_in(&open2);
                Box::new(move |p: &mut InPiece| p.opening = Some(o.clone()))
            },
            "opened",
        ),
        (
            "a Join no keyholder of the epoch signed",
            1,
            head(&by_outsider),
            "opened",
        ),
        (
            "a Join its keyholder moved to another epoch",
            2,
            {
                let (j, o) = (header_in(&moved), header_in(&open2));
                Box::new(move |p: &mut InPiece| {
                    p.head.as_mut().unwrap().header = j.clone();
                    p.opening = Some(o.clone());
                })
            },
            "joined",
        ),
    ];
    for (what, epoch, tamper, other) in tampers {
        w.reconnect(e.bob, Some((epoch, tamper))).await;
        w.read(e.bob, &[other]).await;
        let p = &w.people[e.bob];
        assert!(p.tampered >= 1, "{what}: the answer was changed");
        assert!(p.read_done(), "{what}: every past epoch answered");
        assert_eq!(
            (p.texts.clone(), p.not_stored),
            (vec![other.to_string()], 0),
            "{what}: refused, and only that epoch"
        );
    }
    // The control: the same answers, untouched
    w.reconnect(e.bob, None).await;
    w.read(e.bob, &["joined", "opened"]).await;
    assert_eq!(sorted(w.people[e.bob].texts.clone()), ["joined", "opened"]);
}

/// J8K review: a welcome binds its sender, and on the binding alone the relay names the sender.
/// This relay makes a keyholder pair of its own, seats bob's published seat keys under a `BK`
/// it chose, and answers epoch 2 with an opening of its own around a `CK` it chose (sealed to
/// that `BK`, its `confirm` that `CK`'s), over the real leaf and root. Bob's new device takes
/// no key of the relay's for epoch 2: on the binding alone a past epoch is taken only under the
/// device's own `BK`, which a welcome is only where its `s_m` is the account's self-row's
/// (`kept.rs` `bk_of`, `past.rs` `PastBk`). Epoch 1, untouched, still reads.
#[tokio::test]
async fn e2e_j8k_a_relay_that_seats_a_new_device_from_a_keyholder_pair_of_its_own_gets_no_key_taken(
) {
    use voipc_crypto::group_key::{
        confirm, seal, seat_welcome, Epoch, Group, Leaf, Me, SeatPair, Them, Version,
    };
    let mut w = World::new().await;
    let e = j8k_epochs(&mut w).await;
    let h = w.headers().await;
    let gen = h[&(2, 0)].header().gen;
    let bob = MemberId::Account(w.people[e.bob].a);
    let public = w.people[e.bob]
        .sync
        .seat_keys()
        .expect("bob's seat keys")
        .pair
        .public();
    let relay_ik = generate_identity_key_pair();
    let relay_pair = SeatPair::generate();
    let relay = MemberId::Account([0x4b; 16]);
    let kx: [u8; 32] = relay_pair.public().dh_bytes()[1..].try_into().unwrap();
    let (bk, ck) = ([0x5a; 32], [0xa5; 32]);
    let tamper: Tamper = Box::new(move |p: &mut InPiece| {
        let g = Group::new(GroupKind::Text, CONV, gen).unwrap();
        let head = &p.head.as_ref().expect("a head").header;
        let sh = SignedHeader::decode(&head.body, &head.sig, GroupKind::Text, CONV).unwrap();
        assert!(
            sh.header().kind.opens_epoch() && p.opening.is_none(),
            "bob is answered at epoch 2's opening"
        );
        let epoch = sh.header().epoch;
        let mut x = sh.header().clone();
        x.signer = relay;
        x.confirm = confirm(&g, epoch, 0, &ck);
        let forged = SignedHeader::sign(x, &relay_ik).unwrap();
        let leaf = Leaf::try_from(p.leaf.expect("a leaf")).unwrap();
        let at = Version {
            b: leaf.b,
            v: leaf.v,
        };
        let s = p.seat.as_ref().expect("its keying").s;
        let me = Me {
            m: relay,
            keys: &relay_pair,
        };
        let to = Them {
            m: bob,
            keys: &public,
        };
        p.head = Some(wire::WalkLinkIn {
            header: header_in(&forged),
            parent: None,
        });
        p.walk.clear();
        p.seal = Some(seal(
            &g,
            &Epoch {
                e: epoch,
                d_e: forged.d(),
            },
            at,
            &bk,
            &ck,
        ));
        p.seat = Some(wire::SeatKeying {
            b: at.b,
            base_v: at.v,
            s,
            from: wire::HolderRef {
                m: relay.into(),
                kx,
            },
            welcome: Some(seat_welcome(&g, s, at, &me, &to, &[0x33; 32], &bk).unwrap()),
            row: None,
            ratchets: vec![],
        });
        p.seed_welcome = None;
    });
    // The relay answers no live fetch either: bob's new device takes no head, and reads on
    // the binding alone
    w.reconnect(e.bob, Some((2, tamper))).await;
    w.people[e.bob].live_held = true;
    w.read(e.bob, &["joined"]).await;
    let p = &mut w.people[e.bob];
    assert!(p.tampered >= 1, "the answer was changed");
    assert!(p.read_done(), "every past epoch answered");
    assert_eq!(p.epoch(), None, "no head taken");
    assert_eq!(
        (p.texts.clone(), p.not_stored),
        (vec!["joined".to_string()], 0),
        "epoch 1 reads (by bob's welcome, its s_m the self-row's), epoch 2 does not"
    );
    let taken = match p.keying.past_epoch(CONV, gen, 2) {
        PastEpoch::Ready(k) => Some(*k.ck),
        _ => None,
    };
    assert_eq!(taken, None, "no key of the relay's taken for epoch 2");
    // The control: the same answers, untouched, on the binding alone too
    w.reconnect(e.bob, None).await;
    w.people[e.bob].live_held = true;
    w.read(e.bob, &["joined", "opened"]).await;
    assert_eq!(w.people[e.bob].epoch(), None, "no head taken");
    assert_eq!(sorted(w.people[e.bob].texts.clone()), ["joined", "opened"]);
}
