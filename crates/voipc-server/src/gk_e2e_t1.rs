//! End-to-end group-key scenarios added by slice T1e (Track C tests): what earlier slices
//! asked T1 for. Shared helpers live in `gk_e2e_tests.rs` and `gk_e2e_r2.rs`.
//!
//! The first two run on a relay with accounts, built as `gk_e2e_k2.rs` builds it: every
//! `AccountRequest` through `accounts::handle_request`, the group key's messages through
//! `Groups::handle`, `EpochPost` through the group key's checks and a fan-out to the
//! channel's followers. Each account runs the app's two halves on one connection: K1's
//! `AccountSync` and C3b's `GroupKeying`, glued as both apps glue them, kept copies included:
//! `group_state::Copies` (J8F), the one filing rule the desktop (gk_net.rs) and the browser
//! (voipc-web gk.rs) both use, each copy filed once, under the epoch its latest `released`
//! names, once no refusal came for it, and offered again under the head when the relay refused
//! that epoch's chain start as gone. The keyholder is `gk_e2e_tests.rs`'s guest on a task of
//! its own.
//!
//! The third runs a voice room through the relay's real session path (`handle_connection`
//! over a duplex, as `gk_e2e_v2.rs` serves it), every member an app of its own whose
//! keyholder duty takes the room's dues, each stepped in turn with no slow await between.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use l4f_accounts::model::{AccountId, NewUser};
use l4f_accounts::store::Store;
use voipc_crypto::account::{SignedIn, Vault};
use voipc_crypto::envelope::{envelope, open_envelope};
use voipc_crypto::group_key::{Endorsement, GroupKind, MemberId, Origin, SeatKeys};
use voipc_crypto::group_state::{
    group_id, Copies, GkCtx, GkOut, GkStart, GkTrack, GroupKeying, KeptCopy, MemoryPins,
    OpenedPost, PastEpoch, Platform, VaultFloor,
};
use voipc_crypto::log::LogKey;
use voipc_crypto::sync::{AccountSync, Event, LogMemory, Prefs, ITEM_LOGKEY};
use voipc_crypto::{
    build_aad, generate_identity_key_pair, media_decrypt, media_encrypt, IdentityKeyPair,
    MediaKeyRing, SignalStores,
};
use voipc_protocol::codec::PROTOCOL_VERSION;
use voipc_protocol::gk::{refused_what, refused_why, GkMember};
use voipc_protocol::messages::{AccountReply, AccountRequest, ClientMessage, ServerMessage};
use voipc_protocol::types::{ChannelId, GroupLoad, UserId, VaultBlob};

use super::gk_e2e_tests::{account_session, drop_db, scratch_db, show, tracing_on, Holder};
use crate::accounts::gk as db;
use crate::channels::ChannelEntry;
use crate::config::{AccountsConfig, AccountsMode, ServerConfig};
use crate::control::{ControlRx, ControlTx};
use crate::gk_e2e_r2::Conn;
use crate::settings::ServerSettings;
use crate::state::{RateLimiter, ServerState};

const CHAN: ChannelId = 9;
const CONV: &str = "c:t1hall";

/// The apps' settle (`group_state::SETTLE_MS`): a post's kept copy is filed once no refusal
/// came for it this long.
const KEPT_SETTLE_MS: u64 = voipc_crypto::group_state::SETTLE_MS;

/// N1's settle before J8F (gk_net.rs `SETTLE_MS`, 10 s), which two openings could outlast.
const N1_SETTLE_MS: u64 = 10_000;

fn wall_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn raw(ik: &IdentityKeyPair) -> [u8; 32] {
    ik.public_key().public_key_bytes().try_into().unwrap()
}

// ── An account's app ──────────────────────────────────────────────────────

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
    /// Frames to it are in flight: it takes none, what it sends still goes.
    held: bool,
    /// Its posts' kept copies, by the apps' one rule.
    copies: Copies,
    /// The seat keys its `GroupKeying` started with: their public KEM key.
    started_with: Option<Vec<u8>>,
    /// Past epochs the relay said it does not keep (`EpochRefused{FETCH, NOT_STORED}`).
    not_stored: usize,
    /// Everything it sent, in order.
    sent: Vec<ClientMessage>,
    /// What `AccountSync` said was not kept (`Event::NotKept`).
    not_kept: Vec<String>,
}

impl Person {
    fn took(&mut self, out: GkOut, now: u64) {
        // Each post's send noted before it goes, so its refusal never comes first
        self.copies.sent(&out, now);
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
            match e {
                Event::ChannelMessage { envelope, .. } => {
                    self.texts.push(open_envelope(&envelope).text);
                }
                Event::NotKept { reason } => self.not_kept.push(reason),
                _ => {}
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
                // As both apps do: a post's refusal goes to the copies before the group key
                // takes it, so what it sends again is noted after
                self.copies.refused(f);
                if let ServerMessage::EpochRefused {
                    what: refused_what::FETCH,
                    why: refused_why::NOT_STORED,
                    ..
                } = f
                {
                    self.not_stored += 1;
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

    /// The copies `Copies::file` hands back, each filed under its epoch, as both apps file
    /// them (`AccountSync::send_channel_gk`): those whose post settled, in the order their
    /// posts went, and those offered again under the head.
    fn file(&mut self, now: u64) {
        let keying = &self.keying;
        let due = self.copies.file(now, |group| keying.current_epoch(group));
        for (c, ep) in due {
            let kept = self
                .sync
                .send_channel_gk(&c.log, c.envelope, c.sent_at, c.ttl_secs, ep);
            self.out.extend(kept);
        }
    }

    /// The head epoch it holds `CK` of.
    fn epoch(&self) -> Option<u32> {
        self.keying.current_epoch(CONV).map(|e| e.epoch)
    }

    /// A post in the channel, live only: it writes in this epoch, so the next opening is
    /// pushed to it (2f).
    fn post_live(&mut self, id: u8, text: &str, now: u64) {
        let env = envelope(&format!("t1-{id}"), text, None);
        let c = GkCtx {
            pins: &mut self.pins,
            now,
        };
        let out = self.keying.post(&mut self.st, CHAN, [id; 16], &env, c);
        self.took(out, now);
    }

    /// A post in the channel, its kept copy waiting for the epoch it goes under.
    fn post(&mut self, id: u8, text: &str, now: u64) {
        let env = envelope(&format!("t1-{id}"), text, None);
        let copy = KeptCopy {
            log: CONV.into(),
            envelope: env.clone(),
            sent_at: now,
            ttl_secs: None,
        };
        self.copies.wait([id; 16], copy, now);
        let c = GkCtx {
            pins: &mut self.pins,
            now,
        };
        let out = self.keying.post(&mut self.st, CHAN, [id; 16], &env, c);
        self.took(out, now);
    }

    /// `EpochChainStart`s it sent from `mark` on: (chain epoch, gk epoch).
    fn chain_starts(&self, mark: usize) -> Vec<(u32, u32)> {
        self.sent[mark..]
            .iter()
            .filter_map(|m| match m {
                ClientMessage::Account(AccountRequest::EpochChainStart {
                    epoch, gk_epoch, ..
                }) => Some((*epoch, *gk_epoch)),
                _ => None,
            })
            .collect()
    }

    /// The chain epochs of the `LogAppend`s it sent from `mark` on.
    fn appends(&self, mark: usize) -> Vec<u32> {
        self.sent[mark..]
            .iter()
            .filter_map(|m| match m {
                ClientMessage::Account(AccountRequest::LogAppend { epoch, .. }) => Some(*epoch),
                _ => None,
            })
            .collect()
    }

    /// The epochs of the `EpochPost`s it sent from `mark` on.
    fn posts(&self, mark: usize) -> Vec<u32> {
        self.sent[mark..]
            .iter()
            .filter_map(|m| match m {
                ClientMessage::EpochPost { epoch, .. } => Some(*epoch),
                _ => None,
            })
            .collect()
    }
}

/// The guest keyholder as a client of its own: a task answers each frame as it comes, as a
/// keyholder in another process would, whatever the test awaits meanwhile (part 17).
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

/// A relay with accounts, the group key `on`, and text channel `CHAN` keeping log `CONV`.
async fn hall(db: &Store, on: bool) -> Arc<ServerState> {
    let cfg = AccountsConfig {
        mode: AccountsMode::Optional,
        ..Default::default()
    };
    let relay = crate::accounts::Relay::open_with(&cfg, db.clone(), &[9u8; 32])
        .await
        .unwrap();
    let mut state = ServerState::new(
        &ServerConfig {
            group_key: on,
            ..Default::default()
        },
        ServerSettings::default(),
        vec![],
        "test-admin-token".into(),
    );
    state.accounts = Some(Arc::new(relay));
    let state = Arc::new(state);
    // main.rs's start: the switch noted, the database attached (read-only when off)
    crate::gk_switch(&state, db, on).await.unwrap();
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
    /// Whether the relay uses the group key (`GroupKeys{on}`).
    on: bool,
    /// Each session's queue; the keyholder's own task takes its frames.
    queues: HashMap<UserId, (ControlTx, Option<ControlRx>)>,
    holder: Option<Keyholder>,
    people: Vec<Person>,
    followers: Vec<UserId>,
    /// Every `EpochRefused{POST}` the post path sent: (writer, why).
    post_refusals: Vec<(UserId, u8)>,
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
        let state = hall(&db, true).await;
        let mut w = World {
            state,
            db,
            file,
            on: true,
            queues: HashMap::new(),
            holder: None,
            people: vec![],
            followers: vec![],
            post_refusals: vec![],
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

    /// The relay restarts on the same database with the group key off (`group_key = false`):
    /// every connection ends with it, and its keyholder with them.
    async fn restart_off(&mut self) {
        if let Some(k) = self.holder.take() {
            k.task.abort();
        }
        for p in &mut self.people {
            p.online = false;
        }
        self.state = hall(&self.db, false).await;
        self.on = false;
        self.queues.clear();
        self.followers.clear();
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
                        self.post_refusals.push((sid, why));
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
        // `GroupKeys{on}`: on, the seat keys are made (or taken from the vault) and
        // published; off, the vault's are handed over as they are
        out.extend(sync.gk_on(self.on));
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
            held: false,
            copies: Copies::default(),
            started_with: None,
            not_stored: 0,
            sent: vec![],
            not_kept: vec![],
        });
        self.people.len() - 1
    }

    /// Its `GroupKeying` starts with the seat keys `AccountSync` hands over and tracks the
    /// group: once they are published with the key on, at once from the vault with it off
    /// (J5: kept reads only, nothing followed live).
    async fn start(&mut self, i: usize) {
        let seat_keys = if self.on {
            let settled = self
                .until(15_000, |w| {
                    w.people[i].sync.seat_keys().is_some() && w.people[i].out.is_empty()
                })
                .await;
            assert!(settled, "seat keys settled");
            self.people[i].sync.seat_keys()
        } else {
            self.people[i].sync.take_seat_keys()
        };
        let now = self.now();
        let (on, run) = (self.on, self.state.gk.run);
        let p = &mut self.people[i];
        p.started_with = seat_keys
            .as_ref()
            .map(|k| k.pair.public().kem_bytes().to_vec());
        let _ = p.keying.start(GkStart {
            on,
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
        if on {
            self.follow(sid, Some(a));
        }
    }

    /// The account's app ends, and runs again on a new connection with nothing kept but
    /// what the relay holds (its vault, the log): a reinstall, a new browser.
    async fn reconnect(&mut self, i: usize) {
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
        let back = self.people.remove(j);
        self.people[i] = back;
        self.start(i).await;
    }

    /// Accounts that keep the log and follow nothing live: their identity and seat keys
    /// published, a seat in the log taken on a connection of their own (`LogJoin` seats them
    /// in the group, plan 2d). Each one's `LogLeave` later opens an epoch.
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
            assert!(joined);
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

    /// One round: every app's queue drained into it (a held one's left in flight), what it
    /// sends handed over.
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
            if !self.people[i].held {
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
            }
            let out: Vec<ClientMessage> = self.people[i].out.drain(..).collect();
            for m in out {
                if tracing_on() {
                    let what = format!("{m:?}");
                    eprintln!(
                        "[{now}] {} -> {}",
                        self.people[i].signed.name,
                        &what[..what.len().min(100)]
                    );
                }
                self.people[i].sent.push(m.clone());
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

    /// The group-key chains kept under group epoch `epoch` (`voipc_gk_chains`).
    async fn chains_at(&self, epoch: u32) -> i64 {
        crate::accounts::raw(
            self.relay(),
            &format!(
                "SELECT COUNT(*) FROM voipc_gk_chains WHERE grp = '{CONV}' AND epoch = {epoch}"
            ),
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

/// Seated, and the head opened once past the Join epoch they were seated in: `ann` writes
/// in the epoch first (live only), so each opening is pushed to it; the first crowd account
/// leaves the log. Kept posts from here go under openings every account sat in; see
/// `e2e_t1_kept_posts_of_the_epoch_a_member_was_joined_in_open_on_its_new_device` for the
/// Join epoch itself.
async fn opened_past_the_join(w: &mut World, ann: usize, crowd: usize) -> Vec<([u8; 16], UserId)> {
    let seated = w
        .until(20_000, |w| (0..2).all(|i| w.people[i].epoch().is_some()))
        .await;
    assert!(seated, "seated");
    let now = w.now();
    w.people[ann].post_live(200, "warm", now);
    let crowd = w.crowd(crowd).await;
    assert!(
        w.crowd_seated(&crowd).await,
        "the crowd is seated by its LogJoin"
    );
    let before = w.head();
    w.leave_log(crowd[0].1).await;
    assert!(w.opened(before, &[ann]).await, "opened by a log leave");
    crowd
}

/// T1 (N1's note): a writer posts under epoch X while the head has moved two openings on
/// (its pushes still in flight). The relay answers `EpochRefused{POST, OLD_EPOCH}`; the app
/// fetches and posts again under the head Y. The kept copy, waiting for its post's latest
/// `released` (N1), is filed once, under Y: one `EpochChainStart` (a chain lives inside one
/// epoch) and one `LogAppend` on it, none under X; the copy of the post before, filed under
/// X already, is not filed again though that post went again too (with the live-only one
/// before it). A reader back with only its vault reads both, each once. Both apps file by
/// this rule (`group_state::Copies`, J8F); see also
/// `e2e_t1_a_browsers_first_post_in_an_epoch_refused_as_old_is_kept_under_the_head`.
#[tokio::test]
async fn e2e_t1_a_post_refused_as_old_epoch_is_kept_once_under_the_epoch_it_went_again_under() {
    let mut w = World::new().await;
    let ann = w.person("ann").await;
    let bob = w.person("bob").await;
    let crowd = opened_past_the_join(&mut w, ann, 3).await;
    // ann's first kept post and its copy, under the epoch it holds
    let x = w.people[ann].epoch().unwrap();
    w.post(ann, 1, "one", 1).await;
    let first = w.people[ann].chain_starts(0);
    assert_eq!(
        first.iter().map(|c| c.1).collect::<Vec<_>>(),
        vec![x],
        "one chain for the first post, under X"
    );
    let one_chain = first[0].0;
    // From here ann's frames are in flight; two openings go by
    w.people[ann].held = true;
    for &(_, sid) in &crowd[1..] {
        let before = w.head();
        w.leave_log(sid).await;
        let opened = w.until(20_000, |w| w.head() > before).await;
        assert!(opened, "a log leave opened an epoch");
    }
    let y = w.head();
    assert!(y >= x + 2, "the head moved two openings on: {x} -> {y}");
    assert_eq!(w.people[ann].epoch(), Some(x), "ann took none of them");
    // ann posts under X: refused, the refusal queued behind the pushes
    let mark = w.people[ann].sent.len();
    let now = w.now();
    w.people[ann].post(2, "two", now);
    w.step().await;
    assert_eq!(w.people[ann].posts(mark), vec![x], "the post went under X");
    assert_eq!(
        w.post_refusals,
        vec![(w.people[ann].sid, refused_why::OLD_EPOCH)]
    );
    let mark = w.people[ann].sent.len();
    w.people[ann].held = false;
    let filed = w
        .until(20_000, |w| !w.people[ann].appends(mark).is_empty())
        .await;
    assert!(
        filed,
        "the copy is filed once its post went again; ann sent {:?}",
        w.people[ann].sent[mark..]
            .iter()
            .map(|m| format!("{m:?}").chars().take(60).collect::<String>())
            .collect::<Vec<_>>()
    );
    // Past the settle again, with nothing in flight: nothing else is filed
    let quiet = w.now() + 3 * KEPT_SETTLE_MS;
    w.until(5 * KEPT_SETTLE_MS, |w| w.now() >= quiet).await;
    assert_eq!(
        w.people[ann].posts(mark),
        vec![y, y, y],
        "the posts of the last HOLD_MS (warm, one, two) went again, under the head"
    );
    assert_eq!(w.post_refusals.len(), 1, "nothing refused under the head");
    let starts = w.people[ann].chain_starts(mark);
    assert_eq!(starts.len(), 1, "one chain start: {starts:?}");
    let (chain, at) = starts[0];
    assert_eq!(
        at, y,
        "the chain starts under the epoch the post went again under"
    );
    assert_ne!(chain, one_chain);
    assert_eq!(
        w.people[ann].appends(mark),
        vec![chain],
        "one entry, on the new chain"
    );
    assert_eq!(w.kept().await, 2, "two posts, two entries");
    assert_eq!((w.chains_at(x).await, w.chains_at(y).await), (1, 1));
    // bob comes back with nothing but its vault, and reads each once
    w.reconnect(bob).await;
    w.read(bob);
    let read = w.until(30_000, |w| w.people[bob].texts.len() >= 2).await;
    assert!(
        read,
        "read {:?}, not stored {}",
        w.people[bob].texts, w.people[bob].not_stored
    );
    let mut texts = w.people[bob].texts.clone();
    texts.sort();
    assert_eq!(texts, ["one", "two"]);
}

/// T1 (N1's note, J5): history kept under the group key, read on a relay that turned the key
/// off (`GroupKeys{on: false}`). The account's app makes, rotates and publishes no seat keys;
/// `AccountSync::gk_on(false)` hands the vault's over as they are, `GroupKeying` starts with
/// them for kept reads only, and each past epoch's key comes in a past answer
/// (`EpochFetch{at}`, served read-only) that those keys open.
#[tokio::test]
async fn e2e_t1_an_account_on_a_relay_with_the_key_off_reads_kept_history_with_its_vaults_seat_keys(
) {
    let mut w = World::new().await;
    let ann = w.person("ann").await;
    let bob = w.person("bob").await;
    let crowd = opened_past_the_join(&mut w, ann, 2).await;
    let e1 = w.people[ann].epoch().unwrap();
    w.post(ann, 1, "one", 1).await;
    let before = w.head();
    w.leave_log(crowd[1].1).await;
    assert!(w.opened(before, &[ann]).await, "opened by a log leave");
    let e2 = w.people[ann].epoch().unwrap();
    w.post(ann, 2, "two", 2).await;
    assert!(e2 > e1);
    assert_eq!((w.chains_at(e1).await, w.chains_at(e2).await), (1, 1));
    let published = w.people[bob].started_with.clone().expect("bob's seat keys");
    // The relay comes back with the key off; bob with nothing but its vault
    w.restart_off().await;
    w.reconnect(bob).await;
    assert_eq!(
        w.people[bob].started_with.as_ref(),
        Some(&published),
        "the vault's seat keys, handed over"
    );
    w.read(bob);
    let read = w.until(30_000, |w| w.people[bob].texts.len() >= 2).await;
    assert!(
        read,
        "read {:?}, not stored {}; bob sent {:?}",
        w.people[bob].texts,
        w.people[bob].not_stored,
        w.people[bob]
            .sent
            .iter()
            .map(|m| format!("{m:?}").chars().take(60).collect::<String>())
            .collect::<Vec<_>>()
    );
    let mut texts = w.people[bob].texts.clone();
    texts.sort();
    assert_eq!(texts, ["one", "two"]);
    let sent = &w.people[bob].sent;
    assert!(
        sent.iter().any(|m| matches!(
            m,
            ClientMessage::EpochFetch { at, .. } if !at.is_empty()
        )),
        "the past epochs were asked"
    );
    assert!(
        !sent.iter().any(|m| matches!(
            m,
            ClientMessage::Account(AccountRequest::SeatKeysPublish { .. })
        )),
        "no seat keys published with the key off"
    );
}

/// The app's first kept post in an epoch, made when the head has moved two openings on: ann
/// holds X and has no chain in it (her pushes in flight; a writer is pushed only the opening
/// after the epoch it wrote in, 2f), the relay answers `EpochRefused{POST, OLD_EPOCH}` and
/// the post goes again under the head Y. Its copy is kept once, under Y, and nothing is
/// lost (`NotKept`).
async fn first_post_in_an_old_epoch() {
    let mut w = World::new().await;
    let ann = w.person("ann").await;
    let _bob = w.person("bob").await;
    let crowd = opened_past_the_join(&mut w, ann, 3).await;
    let x = w.people[ann].epoch().unwrap();
    w.people[ann].held = true;
    for &(_, sid) in &crowd[1..] {
        let before = w.head();
        w.leave_log(sid).await;
        let opened = w.until(20_000, |w| w.head() > before).await;
        assert!(opened, "a log leave opened an epoch");
    }
    let y = w.head();
    assert!(y >= x + 2, "the head moved two openings on: {x} -> {y}");
    assert_eq!(w.people[ann].epoch(), Some(x), "ann took none of them");
    assert_eq!(w.chains_at(x).await, 0, "no chain of ann's in X");
    let mark = w.people[ann].sent.len();
    let now = w.now();
    w.people[ann].post(1, "one", now);
    w.step().await;
    assert_eq!(w.people[ann].posts(mark), vec![x], "the post went under X");
    w.people[ann].held = false;
    let again = w
        .until(20_000, |w| w.people[ann].posts(mark).contains(&y))
        .await;
    assert!(again, "the post went again under the head");
    let done = w
        .until(20_000, |w| {
            !w.people[ann].appends(mark).is_empty() || !w.people[ann].not_kept.is_empty()
        })
        .await;
    assert!(done, "its copy filed, or given up");
    // Past the settle again, with nothing in flight
    let quiet = w.now() + 3 * KEPT_SETTLE_MS;
    w.until(5 * KEPT_SETTLE_MS, |w| w.now() >= quiet).await;
    let p = &w.people[ann];
    assert_eq!(p.not_kept, Vec::<String>::new(), "no kept copy lost");
    let starts = p.chain_starts(mark);
    assert_eq!(
        starts.iter().map(|s| s.1).collect::<Vec<_>>(),
        vec![y],
        "one chain start, under the head the post went again under"
    );
    assert_eq!(p.appends(mark), vec![starts[0].0], "one entry, on it");
    assert_eq!(w.kept().await, 1);
    assert_eq!((w.chains_at(x).await, w.chains_at(y).await), (0, 1));
}

/// Found by T1e fix, fixed by J8F: `first_post_in_an_old_epoch` as the browser files. W2
/// filed a post's kept copy at its first `released` (voipc-web gk.rs `take`), which C3b sends
/// with the post, before the relay's verdict (writer.rs `send`), and its copies never heard
/// `EpochRefused{POST}`. So the copy went as `EpochChainStart` under X, which the relay refuses
/// ("That epoch's key is gone here", accounts/log.rs `chain_start`: the head, or the one
/// before within `HOLD_MS`), K1 dropped it with `NotKept`, and the post's next `released`,
/// under Y, found no copy. Now the browser files by the desktop's rule, `group_state::Copies`,
/// which this harness runs: once, under the epoch the post finally went out under, once no
/// refusal came for it.
#[tokio::test]
async fn e2e_t1_a_browsers_first_post_in_an_epoch_refused_as_old_is_kept_under_the_head() {
    first_post_in_an_old_epoch().await;
}

/// Found by T1e fix, fixed by J8F: N1 filed a kept copy 10 s (`N1_SETTLE_MS`) after its post's
/// `released`, assuming the relay still starts a chain under the epoch for `HOLD_MS` after the
/// next one opened. It does, but only for the head's predecessor (accounts/log.rs
/// `chain_start`: the head, or head - 1 while the head's opening is younger than `HOLD_MS`):
/// two openings inside the settle (2 s apart at least, `EPOCH_MIN_GAP`; an exit batch or a
/// gate makes them), or a post under head - 1 in the last 10 s of its window, and the chain
/// start was refused, K1 dropped the copy with `NotKept`, and nothing filed it again. Here
/// ann's first kept post in X is taken under the head, then two log leaves open two epochs
/// within N1's old settle. The apps' settle (`group_state::SETTLE_MS`) is shorter than
/// `EPOCH_MIN_GAP`, so the copy meets X still open; one that does not is filed again under the
/// head (`gk_e2e_j8f`).
#[tokio::test]
async fn e2e_t1_a_kept_copy_whose_post_two_openings_follow_within_n1s_settle_is_kept() {
    two_openings_after_a_post().await;
}

/// ann's first kept post in X goes under the head, and two openings follow at once, within
/// N1's old settle; the app files its copy by the apps' rule. The copy is kept once, under X,
/// and nothing is lost.
async fn two_openings_after_a_post() {
    let mut w = World::new().await;
    let ann = w.person("ann").await;
    let _bob = w.person("bob").await;
    let crowd = opened_past_the_join(&mut w, ann, 3).await;
    let x = w.people[ann].epoch().unwrap();
    assert_eq!(w.head(), x, "ann holds the head");
    let mark = w.people[ann].sent.len();
    let t0 = w.now();
    w.people[ann].post(1, "one", t0);
    w.step().await;
    assert_eq!(w.people[ann].posts(mark), vec![x], "the post went under X");
    for &(_, sid) in &crowd[1..] {
        let before = w.head();
        w.leave_log(sid).await;
        let opened = w.until(20_000, |w| w.head() > before).await;
        assert!(opened, "a log leave opened an epoch");
    }
    let y = w.head();
    assert!(y >= x + 2, "two openings: {x} -> {y}");
    assert!(w.post_refusals.is_empty(), "the post was taken");
    let took = w.now() - t0;
    assert!(
        took < N1_SETTLE_MS,
        "both openings came within N1's old settle ({took} ms)"
    );
    let done = w
        .until(N1_SETTLE_MS + 20_000, |w| {
            !w.people[ann].appends(mark).is_empty() || !w.people[ann].not_kept.is_empty()
        })
        .await;
    assert!(done, "its copy filed, or given up");
    let p = &w.people[ann];
    assert_eq!(p.not_kept, Vec::<String>::new(), "no kept copy lost");
    let starts = p.chain_starts(mark);
    assert_eq!(
        starts.iter().map(|s| s.1).collect::<Vec<_>>(),
        vec![x],
        "one chain start, under the epoch the post went under"
    );
    assert_eq!(p.appends(mark), vec![starts[0].0], "one entry, on it");
    assert_eq!(w.kept().await, 1);
}

/// J8F (`gk_e2e_j8f`): a kept copy filed only after its epoch's window for a chain start
/// closed is not lost. ann's post is taken under X; then her app takes and files nothing (its
/// frames in flight, the app asleep) while two openings go by, so its copy, settled, is filed
/// under X at last, and the relay refuses that chain start as gone. K1 lets the copy go, and
/// `Copies` offers it again under the head ann holds by then: it is kept once, under that
/// head, and a reader seated there reads it.
pub(super) async fn a_copy_filed_after_its_epochs_window_is_kept_under_the_head() {
    let mut w = World::new().await;
    let ann = w.person("ann").await;
    let bob = w.person("bob").await;
    let crowd = opened_past_the_join(&mut w, ann, 3).await;
    let x = w.people[ann].epoch().unwrap();
    assert_eq!(w.head(), x, "ann holds the head");
    let mark = w.people[ann].sent.len();
    let now = w.now();
    w.people[ann].post(1, "late copy", now);
    w.step().await;
    assert_eq!(w.people[ann].posts(mark), vec![x], "the post went under X");
    w.people[ann].held = true;
    for &(_, sid) in &crowd[1..] {
        let before = w.head();
        w.leave_log(sid).await;
        let opened = w.until(20_000, |w| w.head() > before).await;
        assert!(opened, "a log leave opened an epoch");
    }
    let y = w.head();
    assert!(y >= x + 2, "two openings: {x} -> {y}");
    assert!(w.post_refusals.is_empty(), "the post was taken under X");
    assert!(
        w.people[ann].chain_starts(mark).is_empty(),
        "its copy waits"
    );
    w.people[ann].held = false;
    let done = w
        .until(20_000, |w| {
            !w.people[ann].appends(mark).is_empty() || !w.people[ann].not_kept.is_empty()
        })
        .await;
    assert!(done, "its copy filed, or given up");
    // Past the settle again, with nothing in flight: nothing else is filed
    let quiet = w.now() + 3 * KEPT_SETTLE_MS;
    w.until(5 * KEPT_SETTLE_MS, |w| w.now() >= quiet).await;
    let p = &w.people[ann];
    assert_eq!(p.not_kept, Vec::<String>::new(), "no kept copy lost");
    let starts = p.chain_starts(mark);
    let at: Vec<u32> = starts.iter().map(|s| s.1).collect();
    assert_eq!(at.len(), 2, "refused under X, then filed again: {at:?}");
    assert_eq!(at[0], x, "first under the epoch its post went under");
    let again = at[1];
    assert!(
        again > x && again <= y,
        "again under the head ann holds: {at:?}, head {y}"
    );
    assert_eq!(p.appends(mark), vec![starts[1].0], "one entry, on it");
    assert_eq!(w.kept().await, 1);
    assert_eq!((w.chains_at(x).await, w.chains_at(again).await), (0, 1));
    // bob comes back with nothing but his vault, and reads it
    w.reconnect(bob).await;
    w.read(bob);
    let read = w.until(30_000, |w| !w.people[bob].texts.is_empty()).await;
    assert!(
        read,
        "read {:?}, not stored {}",
        w.people[bob].texts, w.people[bob].not_stored
    );
    assert_eq!(w.people[bob].texts, ["late copy"]);
}

/// Found by T1e, fixed by J8K: a kept post made in the epoch its readers were seated in by a
/// Join (header `j` > 0), after that Join. Each reader opened it live, under the `CK` the Join
/// gave it (§5.10: "a reader opens it from its seat at epoch `e`"), and on a new device it
/// reads it kept too: the relay answers such a seat's past epoch at the epoch's last Join with
/// the opening (`gk/store.rs` `past`), which the app takes as that epoch's (C1 `past.rs`
/// `take_past_at`, K1 `kept.rs`); it was answered `EpochRefused{FETCH, NOT_STORED}`, a past
/// epoch being taken only at its opening header, whose leaves hold no seat a later Join
/// added. Here ann and bob are seated by Joins after the Genesis. More in `gk_e2e_j8k.rs`.
#[tokio::test]
async fn e2e_t1_kept_posts_of_the_epoch_a_member_was_joined_in_open_on_its_new_device() {
    let mut w = World::new().await;
    let ann = w.person("ann").await;
    let bob = w.person("bob").await;
    let seated = w
        .until(20_000, |w| (0..2).all(|i| w.people[i].epoch().is_some()))
        .await;
    assert!(seated, "seated");
    w.post(ann, 1, "joined", 1).await;
    let crowd = w.crowd(1).await;
    assert!(w.crowd_seated(&crowd).await);
    let before = w.head();
    w.leave_log(crowd[0].1).await;
    assert!(w.opened(before, &[ann]).await, "the head moves on");
    w.reconnect(bob).await;
    w.read(bob);
    w.until(30_000, |w| {
        !w.people[bob].texts.is_empty() || w.people[bob].not_stored > 0
    })
    .await;
    assert_eq!(
        (w.people[bob].texts.clone(), w.people[bob].not_stored),
        (vec!["joined".to_string()], 0),
        "bob read the post live, and reads it kept"
    );
}

// ── A voice room ──────────────────────────────────────────────────────────

/// The one voice room.
const ROOM: ChannelId = 1;

/// How long a room may take to settle before a test calls it hung.
const ROOM_LIMIT_MS: u64 = 30_000;

/// A relay with the group key on, no accounts, and voice room `ROOM`.
fn room_state(anonymous: bool) -> Arc<ServerState> {
    let room = ChannelEntry {
        name: "room".into(),
        anonymous,
        ..Default::default()
    };
    Arc::new(ServerState::new(
        &ServerConfig {
            group_key: true,
            ..ServerConfig::default()
        },
        ServerSettings::default(),
        vec![room],
        "test-admin-token".into(),
    ))
}

/// One app in the room: its connection, its group keying and its media ring.
struct Device {
    conn: Conn,
    sid: UserId,
    account: Option<[u8; 16]>,
    keying: GroupKeying,
    st: SignalStores,
    pins: MemoryPins,
    ring: MediaKeyRing,
    group: String,
    anonymous: bool,
    /// Every frame the relay sent it, in order.
    log: Vec<ServerMessage>,
    posts: Vec<OpenedPost>,
    ticked: u64,
}

impl Device {
    /// Connects, signed in to `account` where given (its session as session.rs sets it at
    /// sign-in, in group `crew`, its seat keys made), as a desktop that helps hold keys.
    async fn open(state: &Arc<ServerState>, account: Option<[u8; 16]>, anonymous: bool) -> Device {
        let ik = generate_identity_key_pair();
        let name = format!("v{}", rand::random::<u32>());
        let conn = Conn::open(state, &name, &ik).await;
        let sid = conn.sid;
        if let Some(a) = account {
            let mut session = account_session(a);
            session.standing.groups = vec!["crew".into()];
            state.sessions.get_mut(&sid).unwrap().account = Some(session);
        }
        let mut keying = GroupKeying::default();
        let out = keying.start(GkStart {
            on: conn.on,
            run: conn.run,
            relay_clock: wall_ms() / 1000,
            platform: Platform::Desktop,
            help_hold_keys: true,
            user_id: sid,
            identity: ik,
            account,
            seat_keys: account.map(|_| SeatKeys::generate(1, wall_ms() / 1000)),
            local: None,
            visible: true,
        });
        let group = group_id(GroupKind::Voice, "", &conn.run, ROOM);
        let mut d = Device {
            conn,
            sid,
            account,
            keying,
            st: SignalStores::new(&ik, sid),
            pins: MemoryPins::default(),
            ring: MediaKeyRing::default(),
            group,
            anonymous,
            log: vec![],
            posts: vec![],
            ticked: 0,
        };
        let send = d.took(out, wall_ms());
        d.send_all(send).await;
        d
    }

    /// What a call handed back: voice keys into the ring, build jobs run whole as the host
    /// runs them off the lock, uploads taken; what goes now.
    fn took(&mut self, out: GkOut, now: u64) -> Vec<ClientMessage> {
        let mut outs = vec![out];
        let mut send = vec![];
        while let Some(out) = outs.pop() {
            self.posts.extend(out.posts);
            for v in &out.voice {
                self.ring.install_gk(v, ROOM);
            }
            send.extend(out.send);
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
            send.push(m);
        }
        send
    }

    async fn send_all(&mut self, send: Vec<ClientMessage>) {
        for m in send {
            if tracing_on() {
                let what = format!("{m:?}");
                eprintln!("app {} -> {}", self.sid, &what[..what.len().min(100)]);
            }
            self.conn.send(&m).await;
        }
    }

    /// The room is confirmed (its roster came): the app tracks the room's group.
    fn track(&mut self, now: u64) -> Vec<ClientMessage> {
        let out = self.keying.track(
            GkTrack {
                channel_id: ROOM,
                group: self.group.clone(),
                kind: GroupKind::Voice,
                anonymous: self.anonymous,
                hide_members: false,
                viewer_admin: false,
                keeps_history: false,
            },
            VaultFloor::None,
        );
        self.took(out, now)
    }

    /// Takes what the relay sent, ticks, sends what it answers.
    async fn step(&mut self, now: u64) {
        let mut send = vec![];
        for f in self.conn.drain().await {
            if tracing_on() {
                eprintln!("[{now}] app {} <- {}", self.sid, show(&f));
            }
            let c = GkCtx {
                pins: &mut self.pins,
                now,
            };
            let out = self.keying.frame(&mut self.st, &f, c);
            self.log.push(f);
            send.extend(self.took(out, now));
        }
        if now >= self.ticked + 200 {
            self.ticked = now;
            let c = GkCtx {
                pins: &mut self.pins,
                now,
            };
            let out = self.keying.tick(&mut self.st, c);
            send.extend(self.took(out, now));
        }
        self.send_all(send).await;
    }

    /// A post in the room's chat, as the app sends one.
    async fn post(&mut self, id: u8, text: &[u8], now: u64) {
        let c = GkCtx {
            pins: &mut self.pins,
            now,
        };
        let out = self.keying.post(&mut self.st, ROOM, [id; 16], text, c);
        let send = self.took(out, now);
        self.send_all(send).await;
    }

    /// The head epoch this app holds the key of: generation and epoch.
    fn epoch(&self) -> Option<([u8; 16], u32)> {
        self.keying
            .current_epoch(&self.group)
            .map(|e| (e.gen, e.epoch))
    }

    /// Whether the head it holds is gated, as its header says.
    fn gated(&self) -> Option<bool> {
        let (gen, epoch) = self.epoch()?;
        let mut gated = None;
        for f in &self.log {
            let ServerMessage::EpochIn { piece, .. } = f else {
                continue;
            };
            let links = piece.walk.iter().chain(&piece.head).map(|l| &l.header);
            for h in piece.chain.iter().chain(links) {
                let Ok(sh) = voipc_crypto::group_key::SignedHeader::decode(
                    &h.body,
                    &h.sig,
                    GroupKind::Voice,
                    &self.group,
                ) else {
                    continue;
                };
                let hd = sh.header();
                if (hd.gen, hd.epoch) == (gen, epoch) {
                    gated = Some(hd.gated);
                }
            }
        }
        gated
    }

    /// Whether the relay told it the room's roster.
    fn roomed(&self) -> bool {
        self.log
            .iter()
            .any(|f| matches!(f, ServerMessage::UserList { channel_id, .. } if *channel_id == ROOM))
    }

    /// The `EpochPostIn` it was sent of `from`'s under `epoch`: (writer, account).
    fn post_in(&self, from: UserId, at: u32) -> Option<(GkMember, Option<[u8; 16]>)> {
        self.log.iter().find_map(|f| match f {
            ServerMessage::EpochPostIn {
                user_id,
                epoch,
                writer,
                account,
                ..
            } if *user_id == from && *epoch == at => Some((*writer, *account)),
            _ => None,
        })
    }

    /// The post of `from`'s it opened with `text`: the account it shows.
    fn opened(&self, from: UserId, text: &[u8]) -> Option<Option<[u8; 16]>> {
        self.posts
            .iter()
            .find(|p| p.user_id == from && p.envelope == text)
            .map(|p| p.account)
    }
}

/// Whether `to` opens a voice packet `from` sends now, under the key `from` sends with.
fn hears(from: &Device, to: &mut Device) -> bool {
    let Some(k) = from.ring.current().cloned() else {
        return false;
    };
    let stream = from.ring.stream_id();
    let aad = build_aad(ROOM, 1, from.sid);
    let Ok(ct) = media_encrypt(&k, stream, 7, 0, &aad, b"voice") else {
        return false;
    };
    let Some(theirs) = to.ring.get_for(ROOM, from.sid, stream, k.key_id).cloned() else {
        return false;
    };
    media_decrypt(&theirs, stream, 7, 0, &aad, &ct).is_ok_and(|p| p == b"voice")
}

fn pair_mut(v: &mut [Device], a: usize, b: usize) -> (&mut Device, &mut Device) {
    assert_ne!(a, b);
    if a < b {
        let (x, y) = v.split_at_mut(b);
        (&mut x[a], &mut y[0])
    } else {
        let (x, y) = v.split_at_mut(a);
        (&mut y[0], &mut x[b])
    }
}

/// The room and its apps.
struct Room {
    state: Arc<ServerState>,
    devices: Vec<Device>,
    anonymous: bool,
}

impl Room {
    fn new(anonymous: bool) -> Room {
        let _ = tracing_on();
        Room {
            state: room_state(anonymous),
            devices: vec![],
            anonymous,
        }
    }

    async fn step(&mut self) {
        let now = wall_ms();
        for d in &mut self.devices {
            d.step(now).await;
        }
    }

    /// Steps every app until `done` or `ms` passed; whether it was done.
    async fn until(&mut self, ms: u64, mut done: impl FnMut(&mut Room) -> bool) -> bool {
        let end = wall_ms() + ms;
        while wall_ms() < end {
            self.step().await;
            if done(self) {
                return true;
            }
        }
        false
    }

    /// A new app, `account`'s where given, joins the room and tracks its group once its
    /// roster comes.
    async fn join(&mut self, account: Option<[u8; 16]>) -> usize {
        let d = Device::open(&self.state, account, self.anonymous).await;
        self.devices.push(d);
        let i = self.devices.len() - 1;
        let join = ClientMessage::JoinChannel {
            channel_id: ROOM,
            password: None,
        };
        self.devices[i].conn.send(&join).await;
        assert!(
            self.until(ROOM_LIMIT_MS, |r| r.devices[i].roomed()).await,
            "the join was confirmed"
        );
        let send = self.devices[i].track(wall_ms());
        self.devices[i].send_all(send).await;
        i
    }

    /// The room's gate (group `crew`) turns on or off, as gates.rs turns it
    /// (`gate_changed`): the channel's groups, every member outside them evicted, then the
    /// group key told.
    async fn gate(&mut self, on: bool) {
        let groups: Vec<String> = if on { vec!["crew".into()] } else { vec![] };
        let members = {
            let mut channels = self.state.channels.write().await;
            let c = channels.get_mut(&ROOM).unwrap();
            c.gate.groups = groups.clone();
            c.members.clone()
        };
        for uid in members {
            if !self.state.passes(uid, &groups) {
                crate::session::evict(&self.state, ROOM, uid).await;
            }
        }
        self.state.gk.on_gate(ROOM, on);
    }

    /// The room turns anonymous or back, by the channel's options (state.rs
    /// `set_channel_options`), and each app tracks it so, as at `ChannelUpdated`.
    async fn anonymous(&mut self, anonymous: bool) {
        let options = voipc_protocol::types::ChannelOptions {
            anonymous: Some(anonymous),
            ..Default::default()
        };
        self.state
            .set_channel_options(ROOM, 0, options, true)
            .await
            .expect("the flip");
        self.anonymous = anonymous;
        let now = wall_ms();
        for d in &mut self.devices {
            d.anonymous = anonymous;
            let send = d.track(now);
            d.send_all(send).await;
        }
    }

    fn all_hear(&mut self, who: &[usize]) -> bool {
        for &a in who {
            for &b in who {
                if a == b {
                    continue;
                }
                let (from, to) = pair_mut(&mut self.devices, a, b);
                if !hears(from, to) {
                    return false;
                }
            }
        }
        true
    }

    /// The room is at rest with `who` in it: two keyholders online, nothing waiting, every
    /// one of them seated, on one head epoch whose `gated` is `gated`, and heard by every
    /// other.
    fn settled(&mut self, who: &[usize], gated: bool) -> bool {
        let rest = self.room().is_some_and(|g| {
            (
                g.keyholders,
                g.keyholders_online,
                g.joins_waiting,
                g.exits_waiting,
            ) == (2, 2, 0, 0)
                && g.seats == who.len() as u32
        });
        let e = self.devices[who[0]].epoch();
        rest && e.is_some()
            && who
                .iter()
                .all(|&i| self.devices[i].epoch() == e && self.devices[i].gated() == Some(gated))
            && self.all_hear(who)
    }

    /// The room as the relay's Load shows it and each app holds it, for a failure.
    fn show(&mut self) -> String {
        let held: Vec<_> = self
            .devices
            .iter()
            .map(|d| (d.sid, d.epoch().map(|e| e.1), d.gated()))
            .collect();
        let hear = self.all_hear(&(0..self.devices.len()).collect::<Vec<_>>());
        format!(
            "{:?}; apps (sid, epoch, gated) {held:?}; all hear: {hear}",
            self.room()
        )
    }

    fn room(&self) -> Option<GroupLoad> {
        self.state
            .gk
            .stats()
            .into_iter()
            .find(|g| g.channel_id == ROOM)
    }
}

/// T1 (V2's note): a voice room of signed-in members, gated, turned anonymous, whose gate
/// then comes off. A post made before the next opening goes under the head that is still
/// gated: the writer's app names itself by that epoch's gate (writer.rs `writer_m`), so does
/// the relay (session.rs `finish_epoch_post` through `Groups::room_gated`), and the readers
/// open it under the account. After the opening that ungates the head the naming follows
/// the ungated rule of an anonymous room: by the connection, with no account behind the
/// pseudonym. (The room turns anonymous while gated, its seats named by their accounts all
/// along. Two T1e tests below cover the other cases: an anonymous room of signed-in members
/// alone starts, its seats named by their connections, and one whose guest keyholder a gate
/// evicts settles.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_t1_a_rooms_post_under_a_gated_head_after_its_gate_came_off_is_named_by_that_epochs_gate(
) {
    let mut r = Room::new(false);
    for a in [0xa1, 0xb2, 0xc3, 0xd4] {
        r.join(Some([a; 16])).await;
    }
    let (writer, leaver) = (2, 3);
    assert!(
        r.until(ROOM_LIMIT_MS, |r| r.settled(&[0, 1, 2, 3], false))
            .await,
        "the room settled: {}",
        r.show()
    );
    r.gate(true).await;
    assert!(
        r.until(ROOM_LIMIT_MS, |r| r.settled(&[0, 1, 2, 3], true))
            .await,
        "every member holds the gated head: {}",
        r.show()
    );
    r.anonymous(true).await;
    // The gate comes off; no opening yet, the head is gated still
    r.gate(false).await;
    let (gen, gated_at) = r.devices[writer].epoch().unwrap();
    assert!(r
        .state
        .gk
        .room_gated(&r.devices[writer].group, &gen, gated_at));
    let now = wall_ms();
    r.devices[writer]
        .post(1, b"under the gated head", now)
        .await;
    let from = r.devices[writer].sid;
    let account = r.devices[writer].account;
    let readers = [0, 1, leaver];
    let read = r
        .until(ROOM_LIMIT_MS, |r| {
            readers
                .iter()
                .all(|&i| r.devices[i].opened(from, b"under the gated head").is_some())
        })
        .await;
    assert!(read, "every reader opens the post under the gated head");
    for i in readers {
        let d = &r.devices[i];
        assert_eq!(
            d.post_in(from, gated_at),
            Some((GkMember::Account(account.unwrap()), account)),
            "named by its account, as the epoch's gate says"
        );
        assert_eq!(d.opened(from, b"under the gated head"), Some(account));
    }
    assert_eq!(
        r.devices[writer].epoch(),
        Some((gen, gated_at)),
        "it went before the next opening"
    );
    // A member leaves: its exit's opening ungates the head, the seats go back to the
    // connections
    r.devices[leaver]
        .conn
        .send(&ClientMessage::JoinChannel {
            channel_id: 0,
            password: None,
        })
        .await;
    assert!(
        r.until(ROOM_LIMIT_MS, |r| r.settled(&[0, 1, 2], false))
            .await,
        "the head is open again: {}",
        r.show()
    );
    let (gen, open_at) = r.devices[writer].epoch().unwrap();
    assert!(open_at > gated_at);
    assert!(!r
        .state
        .gk
        .room_gated(&r.devices[writer].group, &gen, open_at));
    let now = wall_ms();
    r.devices[writer].post(2, b"under the open head", now).await;
    let readers = [0, 1];
    let read = r
        .until(ROOM_LIMIT_MS, |r| {
            readers
                .iter()
                .all(|&i| r.devices[i].opened(from, b"under the open head").is_some())
        })
        .await;
    assert!(read, "every reader opens the post under the open head");
    for i in readers {
        let d = &r.devices[i];
        assert_eq!(
            d.post_in(from, open_at),
            Some((GkMember::Conn(from), None)),
            "named by its connection once the head is open"
        );
        assert_eq!(d.opened(from, b"under the open head"), Some(None));
    }
}

/// Found by T1e, fixed by J8H: a gate on an anonymous voice room whose keyholder is a guest.
/// The gate evicts the guest (gates.rs `gate_changed`); the relay then asks the one keyholder
/// left a Join of the account seats, the guest's Remove, the seed welcomes, and a PROMOTE
/// due carrying the connection seats' exits. That KeyholdersAdd drops the one-seat buckets
/// those exits empty, which rule 8 allows; the keyholder's own check saw a bucket whose list
/// its build did not need by its leaf alone, so it refused its own commit ("rule 8: a
/// KeyholdersAdd drops only buckets its exits empty") and the room stalled. The duty now asks
/// a KeyholdersAdd's dropped buckets' lists too (holder.rs `lists_needed`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_t1_a_gate_on_an_anonymous_room_whose_keyholder_is_a_guest_settles() {
    let mut r = Room::new(true);
    r.join(None).await;
    for a in [0xa1, 0xb2, 0xc3] {
        r.join(Some([a; 16])).await;
    }
    assert!(
        r.until(ROOM_LIMIT_MS, |r| r.settled(&[0, 1, 2, 3], false))
            .await,
        "the open room settled: {}",
        r.show()
    );
    r.gate(true).await;
    assert!(
        r.until(ROOM_LIMIT_MS, |r| r.settled(&[1, 2, 3], true))
            .await,
        "every member holds the gated head, seated by its account: {}",
        r.show()
    );
}

/// Found by T1e, fixed by J8H: an anonymous voice room that is not gated, whose members are
/// all signed in (a relay where accounts are required), got no keys. The relay seats a
/// signed-in member there by its connection (`room_seat_m`, open choice 11), so the Genesis
/// it asks a volunteer for seats `Conn(u)`; the volunteer's app took its own seat to be its
/// account's and declined every new start (`NOT_READY`, "a new start seats this device's own
/// seat only"). No Genesis, no voice. The keyholder now takes either name of its
/// connection's pair as its own voice seat (holder.rs `own_seats`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_t1_an_anonymous_room_of_signed_in_members_alone_starts_its_keys() {
    let mut r = Room::new(true);
    for a in [0xa1, 0xb2, 0xc3] {
        r.join(Some([a; 16])).await;
    }
    assert!(
        r.until(ROOM_LIMIT_MS, |r| r.settled(&[0, 1, 2], false))
            .await,
        "the room settled: {}",
        r.show()
    );
    // Every seat the rosters named is a connection's: no account behind a pseudonym
    for d in &r.devices {
        for f in &d.log {
            if let ServerMessage::VoiceSeats { piece, .. } = f {
                for (u, seat) in &piece.seats {
                    assert_eq!(
                        seat.m,
                        GkMember::Conn(*u),
                        "app {} was told {u}'s seat",
                        d.sid
                    );
                }
            }
        }
    }
}
