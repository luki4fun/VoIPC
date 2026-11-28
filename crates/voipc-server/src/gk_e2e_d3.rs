//! Deep dive d3 (kept history over time): end-to-end scenarios through the relay's real
//! accounts + `gk` code and the clients' real `voipc_crypto` code, asking how long each link
//! from a device to an old epoch key lives. The harness is `gk_e2e_k2.rs`'s (copied: its
//! items are private to that file), with the one piece of host glue K2 leaves out: settled
//! seat keys go from `AccountSync` to `GroupKeying` (`take_seat_keys` ->
//! `seat_keys_changed`), as `AccountSession::gk_news` and the hosts do, so a seat-key
//! rotation runs end to end here.

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
use crate::accounts::gk as db;
use crate::control::{ControlRx, ControlTx};
use crate::state::{RateLimiter, ServerState};

const CHAN: ChannelId = 9;
const CONV: &str = "c:d3hall";

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
    /// Kept reads handed to `GroupKeying` as the hosts do (`gk_net.rs` `past`, `account`):
    /// when `AccountSync` names an epoch (first, or again at its retry) or `GkOut::past_ready`
    /// does, not again at every step while it is still asked.
    host_glue: bool,
    /// `GkOut::past_ready` since the last `pasts`.
    ready: Vec<(String, [u8; 16], u32)>,
}

impl Person {
    fn took(&mut self, out: GkOut) {
        self.ready.extend(out.past_ready);
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

    /// The hosts' glue K2 leaves out (`AccountSession::gk_news` -> `Actions::seat_keys` ->
    /// `GroupKeying::seat_keys_changed`): seat keys settled since the last look (rotated, or
    /// the old ones dropped) go to the group keying. Before `GroupKeying::start` it is a
    /// no-op there, and `World::start` reads the keys itself.
    fn handover(&mut self) {
        if let Some(keys) = self.sync.take_seat_keys() {
            let out = self.keying.seat_keys_changed(keys);
            self.took(out);
        }
    }

    /// N1/W2's glue for a kept read: each past epoch `AccountSync` names goes to
    /// `GroupKeying::past_epoch`; what it has is handed back, what it asked for waits.
    fn pasts(&mut self) {
        let new = self.sync.take_gk_past();
        let handed = !new.is_empty();
        let ready = std::mem::take(&mut self.ready);
        let asked = if self.host_glue {
            let mut asked = new;
            for k in ready {
                if !asked.contains(&k) {
                    asked.push(k);
                }
            }
            asked
        } else {
            self.past.extend(new);
            std::mem::take(&mut self.past)
        };
        for (group, gen, epoch) in asked {
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
                PastEpoch::Asked if self.host_glue => {}
                PastEpoch::Asked => self.past.push((group, gen, epoch)),
            }
        }
        if handed || !self.host_glue {
            let out = self.keying.past_asks();
            self.took(out);
        }
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
    /// d3 control: for this account's kept reads (`EpochFetch{at}`), the harness answers
    /// with the relay's own past answer (`Groups::past_epoch`), except that a seat keyed
    /// there by its seat welcome is keyed by the row the relay stores beside it instead
    /// (`voipc_gk_rows`, same version, same maker, same seed). Nothing is made up: every
    /// byte is the relay's own stored material. The account, and its seat then.
    row_instead: Option<([u8; 16], voipc_crypto::group_key::SeatRef)>,
    /// Accounts whose apps hand kept reads over as the hosts do (`Person::host_glue`).
    host_glue: Vec<[u8; 16]>,
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
            row_instead: None,
            host_glue: vec![],
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
            ClientMessage::EpochFetch {
                group,
                have,
                at,
                seat: _,
            } if !at.is_empty()
                && self
                    .row_instead
                    .is_some_and(|(a, _)| self.people.iter().any(|p| p.sid == sid && p.a == a)) =>
            {
                let (a, seat) = self.row_instead.unwrap();
                let rec = voipc_crypto::group_key::seat_record(&seat);
                for e in at {
                    let piece = self
                        .state
                        .gk
                        .past_epoch(&group, MemberId::Account(a), e, have.as_ref())
                        .await;
                    let frames = match piece {
                        Some(mut p) => {
                            if let Some(k) = p.seat.as_mut().filter(|k| k.welcome.is_some()) {
                                let row = db::row(&self.db, &group, &e.gen, k.b, k.base_v, &rec)
                                    .await
                                    .unwrap()
                                    .expect("a row beside the welcome is stored");
                                assert_eq!(
                                    row.s, k.s,
                                    "the row beside is under the welcome's seed"
                                );
                                assert_eq!(
                                    &row.maker[17..],
                                    &k.from.kx[..],
                                    "the row beside is from the welcome's maker"
                                );
                                k.welcome = None;
                                k.row = Some(row.bytes);
                            }
                            crate::gk::push::epoch_in(&group, p)
                        }
                        None => vec![ServerMessage::EpochRefused {
                            group: group.clone(),
                            what: refused_what::FETCH,
                            why: voipc_protocol::gk::refused_why::NOT_STORED,
                            detail: String::new(),
                        }],
                    };
                    for f in frames {
                        let _ = crate::session::send_msg(&tx, &f);
                    }
                }
            }
            m => self.state.gk.handle(&self.state, sid, m, &tx).await,
        }
    }

    /// An account with its identity and log key here, its app on a connection in the channel,
    /// its seat keys made and published by the app: following and tracking the group.
    async fn person(&mut self, name: &str) -> usize {
        self.person_as(name, true).await
    }

    /// `person`, or with `start` false an account whose app signed in (vault, log key, seat
    /// keys published) but follows and tracks nothing: its group keying never runs.
    async fn person_as(&mut self, name: &str, start: bool) -> usize {
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
        if start {
            self.start(i).await;
        }
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
            host_glue: self.host_glue.contains(&a),
            ready: vec![],
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
        let made = self.crowd_made(n).await;
        for (_, sid) in &made {
            self.crowd_joins(*sid).await;
        }
        made
    }

    /// `crowd`'s accounts and connections, made ahead: they join the log by `crowd_joins`,
    /// so a scene that times its joins pays only for the joins.
    async fn crowd_made(&mut self, n: usize) -> Vec<([u8; 16], UserId)> {
        let mut out = vec![];
        for k in 0..n {
            let id = AccountId::new();
            // A name of its own: the F5 scene calls this once per joiner
            let name = format!("crowd{k}x{:08x}", rand::random::<u32>());
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
            out.push((id.0, sid));
        }
        out
    }

    /// A `crowd_made` account's connection `sid` joins the log (`LogJoin`).
    async fn crowd_joins(&mut self, sid: UserId) {
        let join = AccountRequest::LogJoin { conv: CONV.into() };
        self.send(sid, ClientMessage::Account(join)).await;
        let joined = self
            .drain(sid)
            .await
            .into_iter()
            .any(|f| matches!(f, ServerMessage::Account(AccountReply::LogJoined { .. })));
        assert!(joined);
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
            p.handover();
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

// ── d3 helpers ────────────────────────────────────────────────────────────

/// The relay's past answer for account `a` at `(gen, epoch)`, as `EpochFetch{at}` reads it
/// (`gk/store.rs` `past`, no anchor).
async fn past_piece(
    w: &World,
    a: [u8; 16],
    gen: [u8; 16],
    epoch: u32,
) -> Option<voipc_protocol::gk::InPiece> {
    let at = EpochRef { gen, epoch };
    crate::gk::store::past(&w.db, CONV, MemberId::Account(a), at, None)
        .await
        .unwrap()
}

/// Whether the relay stores a row to `seat` in version `(b, v)` of `gen`.
async fn row_stored(
    w: &World,
    gen: &[u8; 16],
    seat: &voipc_crypto::group_key::SeatRef,
    b: u64,
    v: u64,
) -> bool {
    let rec = voipc_crypto::group_key::seat_record(seat);
    db::row(&w.db, CONV, gen, b, v, &rec)
        .await
        .unwrap()
        .is_some()
}

/// `i`'s app reads the channel's kept history until it has opened `want`, at most `ms`.
async fn reads(w: &mut World, i: usize, want: &str, ms: u64) -> bool {
    w.read(i);
    let want = want.to_string();
    w.until(ms, move |w| w.people[i].texts.contains(&want))
        .await
}

/// `i`'s seat keys rotate (§5.11: every 30 days, a password change, a device removed) and
/// the rotation runs to its end: the relay seats the new seat, the app seals its kept rows
/// again, and the old private parts go (step 4). Returns the old and the new seat.
async fn rotate_to_the_end(
    w: &mut World,
    i: usize,
) -> (
    voipc_crypto::group_key::SeatRef,
    voipc_crypto::group_key::SeatRef,
) {
    let me = MemberId::Account(w.people[i].a);
    let before = w.people[i].sync.seat_keys().expect("settled seat keys");
    assert!(before.old.is_none(), "no rotation is under way");
    let old = before.pair.public().seat(me);
    let out = w.people[i].sync.seat_keys_rotate();
    assert!(!out.is_empty(), "the rotation's vault write goes out");
    w.people[i].out.extend(out);
    let n = before.n + 1;
    let done = w
        .until(60_000, move |w| {
            w.people[i]
                .sync
                .seat_keys()
                .is_some_and(|k| k.n == n && k.old.is_none())
        })
        .await;
    assert!(
        done,
        "the rotation ran to its end: re-seated, re-sealed, the old private parts gone"
    );
    let new = w.people[i].sync.seat_keys().unwrap().pair.public().seat(me);
    assert_ne!(old, new);
    (old, new)
}

// ── F1 ────────────────────────────────────────────────────────────────────

/// The F1 scene, up to the end of bob's rotation. ann and bob join; an opening both sit in;
/// ann posts "one", kept under that epoch (`e1`). bob's version there is still the one its
/// Join made: the relay holds its seat welcome and the Join's row beside it (open choice
/// 24), and its past answer hands the welcome. A new device of bob reads "one" (the
/// control inside the scene). Then bob's seat keys rotate and the rotation runs to its
/// end. Returns bob, `e1`, the generation, and bob's seat before the rotation.
async fn joined_posted_rotated(
    w: &mut World,
) -> (usize, u32, [u8; 16], voipc_crypto::group_key::SeatRef) {
    let ann = w.person("ann").await;
    let bob = w.person("bob").await;
    let seated = w
        .until(20_000, |w| (0..2).all(|i| w.people[i].epoch().is_some()))
        .await;
    assert!(seated, "seated");
    // ann writes, so each opening is pushed to it
    let now = w.now();
    w.people[ann].post_live(0, "zero", now);
    let crowd = w.crowd(1).await;
    assert!(w.crowd_seated(&crowd).await, "the crowd is seated");
    let before = w.head();
    w.leave_log(crowd[0].1).await;
    assert!(w.opened(before, &[ann]).await, "opened by a log leave");
    let e1 = w.head();
    let gen = w.people[ann].keying.current_epoch(CONV).unwrap().gen;
    w.post(ann, 1, "one", 1).await;
    let bob_a = w.people[bob].a;
    let seat1 = w.people[bob]
        .sync
        .seat_keys()
        .unwrap()
        .pair
        .public()
        .seat(MemberId::Account(bob_a));

    // What the relay holds for bob's seat at e1: the Join's seat welcome, and beside it the
    // Join's row to the same version (open choice 24). Its past answer hands one of them:
    // the row once bob's account holds the seed's self-row (dive 3 F1), which it does here.
    let p = past_piece(w, bob_a, gen, e1).await.expect("a past answer");
    let k = p.seat.expect("a keying");
    assert!(
        k.welcome.is_some() != k.row.is_some(),
        "the past answer keys bob's seat at e1 by its seat welcome or by the row beside it"
    );
    assert!(
        row_stored(w, &gen, &seat1, k.b, k.base_v).await,
        "the Join's row to bob's seat beside the welcome is stored (choice 24)"
    );

    // Control: a new device of bob reads "one" before any rotation
    w.reconnect(bob).await;
    assert!(
        reads(w, bob, "one", 30_000).await,
        "control: before the rotation a new device reads it, got {:?}",
        w.people[bob].texts
    );

    // The rotation, to its end
    let (old, _new) = rotate_to_the_end(w, bob).await;
    assert_eq!(old, seat1);
    // The app kept what §5.11 step 2 says it keeps, and the relay what §5.2 says: the row
    // to the old seat beside its welcome is still stored, and the old seat's self-row is
    // still served (sealed again under the new self key)
    assert!(
        row_stored(w, &gen, &seat1, k.b, k.base_v).await,
        "the row to the old seat is still stored after the rotation"
    );
    let p = past_piece(w, bob_a, gen, e1)
        .await
        .expect("a past answer after the rotation");
    assert!(
        p.self_rows
            .iter()
            .any(|r| r.kind == voipc_protocol::gk::self_row::SELF_ROW
                && (r.sk, r.sx) == (seat1.tag_sk, seat1.tag_sx)),
        "the old seat's self-row is still served"
    );
    let k = p.seat.expect("a keying");
    assert!(
        k.welcome.is_some() != k.row.is_some(),
        "after the rotation the past answer keys the old seat by its welcome or its row"
    );
    (bob, e1, gen, seat1)
}

/// d3 F1. A kept post of an epoch in which the reader's bucket version was the one its
/// Join made must stay readable after the reader's seat keys rotate and the old private
/// parts go (§3.13 "Who still reads ... this holds across rotations within retention";
/// §5.2: a stored Join "also makes a 60-byte row to each new account seat beside its
/// welcome ... so kept epochs stay readable from `s_m` (its self-row) after the welcome or
/// the old KEM key is gone").
///
/// After the scene (`joined_posted_rotated`), a new device of bob, from its vault, must
/// still read "one": the post is minutes old.
#[tokio::test]
async fn e2e_d3_a_kept_post_of_the_version_a_join_made_stays_readable_after_a_seat_key_rotation() {
    let mut w = World::new().await;
    let (bob, e1, _gen, _seat1) = joined_posted_rotated(&mut w).await;
    w.reconnect(bob).await;
    let read = reads(&mut w, bob, "one", 30_000).await;
    assert!(
        read,
        "after its seat keys rotated, bob no longer reads the kept post of epoch {e1}: it opened {:?}. The relay's past answer keys the old seat by its seat welcome, which no key the account still holds opens, and leaves out the row it stores beside it",
        w.people[bob].texts,
    );
}

/// d3 F1, the control that pins the cause: the same scene, but bob's kept reads are
/// answered with the relay's own past answer in which the seat welcome is swapped for the
/// row the relay stores beside it (`World::row_instead`). bob's new device then reads
/// "one" from its self-row's `s_m` and that row. So everything needed is kept on both
/// sides; only the relay's choice of base (`gk/store.rs` `member_bases`: the welcome wins)
/// closes the epoch. Passes today.
#[tokio::test]
async fn e2e_d3_control_the_row_beside_the_welcome_opens_that_post_after_the_rotation() {
    let mut w = World::new().await;
    let (bob, e1, _gen, seat1) = joined_posted_rotated(&mut w).await;
    w.row_instead = Some((w.people[bob].a, seat1));
    w.reconnect(bob).await;
    let read = reads(&mut w, bob, "one", 30_000).await;
    assert!(
        read,
        "with the row beside the welcome, bob reads the kept post of epoch {e1}: {:?}",
        w.people[bob].texts
    );
}

// ── F2: an account seated while it is away ────────────────────────────────

impl World {
    /// `i`'s app ends: its connection is gone, nothing of it runs.
    fn away(&mut self, i: usize) {
        let old = self.people[i].sid;
        self.people[i].online = false;
        self.state.gk.on_session_end(old);
        self.followers.retain(|s| *s != old);
    }

    async fn self_rows(&self) -> i64 {
        crate::accounts::raw(
            self.relay(),
            &format!("SELECT COUNT(*) FROM voipc_gk_self WHERE grp = '{CONV}'"),
        )
        .await
        .unwrap()
    }
}

/// The F2 scene. bob keeps the channel's history, so the relay seats it eagerly, online
/// or not (§5.10 `kept_seats`, plan 2d): here by its `LogJoin`, on an app that does not
/// follow the channel; a new start of the group seats every such account the same way
/// (`gk/mod.rs` `eager_all`). With `opened`, bob's app follows the channel once before it
/// goes away: it opens its seat welcome and writes its self-row (the control). Then bob is
/// away, and its bucket gets a new version by rows (a seat of the same Join leaves here; a
/// Refresh's slice and the 1 h bucket age do the same, §5.5). ann posts "away1", kept.
/// bob's app comes back, from its vault. Returns whether it took the head's key, whether
/// it read "away1", what it opened, and whether the relay still stored bob's seat welcome
/// when it came back.
async fn seated_away_rekeyed_back(w: &mut World, opened: bool) -> (bool, bool, Vec<String>, bool) {
    let ann = w.person("ann").await;
    let seated = w.until(20_000, |w| w.people[0].epoch().is_some()).await;
    assert!(seated, "ann seated");
    let now = w.now();
    w.people[ann].post_live(0, "zero", now);
    // bob: signed in, keeps the log, follows nothing
    let bob = w.person_as("bob", false).await;
    let settled = w
        .until(15_000, |w| {
            w.people[bob].sync.seat_keys().is_some() && w.people[bob].out.is_empty()
        })
        .await;
    assert!(settled, "bob's seat keys settled");
    let bob_a = w.people[bob].a;
    w.read(bob);
    w.step().await;
    // A crowd account joins the log in the same join batch: the same bucket
    let crowd = w.crowd(1).await;
    assert!(w.crowd_seated(&crowd).await, "the crowd is seated");
    let mut bob_seated = false;
    for _ in 0..100 {
        w.until(200, |_| false).await;
        if !db::seats_of_account(&w.db, &bob_a)
            .await
            .unwrap()
            .is_empty()
        {
            bob_seated = true;
            break;
        }
    }
    assert!(bob_seated, "bob is seated by its LogJoin");
    let gen = w.people[ann].keying.current_epoch(CONV).unwrap().gen;
    let seat = w.people[bob]
        .sync
        .seat_keys()
        .unwrap()
        .pair
        .public()
        .seat(MemberId::Account(bob_a));
    if opened {
        // The control: bob's app follows the channel once, opens its welcome, and its
        // self-row reaches the relay
        let rows0 = w.self_rows().await;
        w.start(bob).await;
        let keyed = w.until(20_000, |w| w.people[bob].epoch().is_some()).await;
        assert!(keyed, "control: bob's app opens its seat welcome");
        let mut written = false;
        for _ in 0..100 {
            w.until(100, |_| false).await;
            if w.self_rows().await > rows0 {
                written = true;
                break;
            }
        }
        assert!(written, "control: bob's self-row is stored");
    }
    // bob goes away
    w.away(bob);
    // The crowd account leaves: bob's bucket gets a new version by rows
    let before = w.head();
    w.leave_log(crowd[0].1).await;
    assert!(w.opened(before, &[ann]).await, "opened by a log leave");
    let e1 = w.head();
    let p = past_piece(w, bob_a, gen, e1)
        .await
        .expect("a past answer for bob");
    let k = p.seat.expect("a keying");
    assert!(
        k.row.is_some() && k.ratchets.is_empty(),
        "harness: bob's bucket was re-keyed by rows at epoch {e1}"
    );
    // No seed roll ran, but bob's seat was seated with no session waiting for it: the relay
    // paged it a seed welcome under the head seed, which carries its member secret beside
    // the row (dive 3 P3). With `opened` bob's self-row carries it as well
    assert!(
        opened || p.seed_welcome.as_ref().is_some_and(|w| w.s == 1),
        "harness: the relay paged bob's eager seat a seed welcome under seed 1 (dive 3 P3)"
    );
    w.post(ann, 1, "away1", 1).await;
    // What the relay still stores of the welcome that seated bob
    let rec = voipc_crypto::group_key::seat_record(&seat);
    let welcome_stored = db::welcomes_of(&w.db, CONV, &gen, &rec)
        .await
        .unwrap()
        .iter()
        .any(|x| x.kind == db::WelcomeKind::Seat);
    // bob comes back, from its vault
    w.reconnect(bob).await;
    let keyed = w.until(25_000, |w| w.people[bob].epoch().is_some()).await;
    let read = reads(w, bob, "away1", 30_000).await;
    (keyed, read, w.people[bob].texts.clone(), welcome_stored)
}

/// d3 F2. An account that keeps a channel's history is seated whether it is online or
/// not, so that it can read the channel when it is back (§5.10 `kept_seats`; §5.6 "A seat
/// that is offline for weeks opens its welcome when it is back"). Its member secret `s_m`
/// reaches it only inside the seat welcome of the version its Join made (§3.2). Once that
/// bucket has a later version made by rows, the relay keys the seat by its row alone, and
/// a row opens only with `s_m` (§3.3): an account none of whose devices opened the welcome
/// in time takes no key, live or kept.
#[tokio::test]
async fn e2e_d3_an_account_seated_while_away_takes_the_key_and_reads_once_its_bucket_was_rekeyed() {
    let mut w = World::new().await;
    let (keyed, read, texts, welcome_stored) = seated_away_rekeyed_back(&mut w, false).await;
    assert!(
        keyed && read,
        "bob was seated while its app was away, and its bucket was re-keyed by rows before it came back: took the head's key: {keyed}; read what was written meanwhile: {read} (opened {texts:?}). The relay answers with the row alone; the seat welcome that holds bob's member secret was still stored: {welcome_stored}"
    );
}

/// d3 F2, the control that pins the cause: the same scene, but bob's app followed the
/// channel once before it went away, so it opened its seat welcome and its self-row is on
/// the relay. Back from its vault after the same re-key by rows, it takes the head's key
/// and reads "away1". Passes today.
#[tokio::test]
async fn e2e_d3_control_an_account_whose_app_opened_its_welcome_reads_after_the_same_rekey() {
    let mut w = World::new().await;
    let (keyed, read, texts, _) = seated_away_rekeyed_back(&mut w, true).await;
    assert!(
        keyed && read,
        "control: with its self-row stored, bob takes the head's key ({keyed}) and reads what was written while it was away ({read}): {texts:?}"
    );
}

// ── F3: an account away while a whole seed came and went ──────────────────

const HOUR_MS: u64 = 60 * 60 * 1000;
const DAY_MS: u64 = 24 * HOUR_MS;

impl World {
    /// The relay's clock (tokio's, `gk/mod.rs` `Clock`) moves `ms` ahead at once, as if that
    /// long had passed with nothing happening: every timer of the relay due by then fires.
    /// The apps' and the keyholder's group keying read the same clock (`World::now`); the
    /// accounts' own timers read the wall clock and do not move (no seat-key rotation runs).
    async fn jump(&mut self, ms: u64) {
        // What is under way ends first, so no deadline passes inside the jump
        for _ in 0..200 {
            self.until(50, |_| false).await;
            if !self.state.gk.busy_for_test() {
                break;
            }
        }
        tokio::time::pause();
        tokio::time::advance(Duration::from_millis(ms)).await;
        tokio::time::resume();
    }

    /// `(epoch, seed, seed_floor)` of the head the keyholder holds.
    fn head_seeds(&self) -> (u32, u32, u32) {
        let Some(k) = &self.holder else {
            return (0, 0, 0);
        };
        let h = k.holder.lock().unwrap();
        h.held.as_ref().map_or((0, 0, 0), |h| {
            let x = h.head.header();
            (x.epoch, x.seed, x.seed_floor)
        })
    }

    /// Runs until the head's `(seed, seed_floor)` is `want` and `who` holds the head's key,
    /// at most `ms`.
    async fn seeds_at(&mut self, want: (u32, u32), who: usize, ms: u64) -> bool {
        self.until(ms, move |w| {
            let (e, s, f) = w.head_seeds();
            (s, f) == want && w.people[who].epoch() == Some(e)
        })
        .await
    }

    /// The newest seed the relay says `seat` holds (`voipc_gk_seats.seed`).
    async fn seat_seed(&self, gen: &[u8; 16], seat: &voipc_crypto::group_key::SeatRef) -> u32 {
        let rec = voipc_crypto::group_key::seat_record(seat);
        db::seat(&self.db, CONV, gen, &rec)
            .await
            .unwrap()
            .map_or(0, |s| s.seed)
    }

    /// Whether the relay stores a seed welcome to `seat` under seed `s`.
    async fn seed_welcome_stored(
        &self,
        gen: &[u8; 16],
        seat: &voipc_crypto::group_key::SeatRef,
        s: u32,
    ) -> bool {
        let rec = voipc_crypto::group_key::seat_record(seat);
        db::welcome(&self.db, CONV, gen, &rec, db::WelcomeKind::Seed, s)
            .await
            .unwrap()
            .is_some()
    }
}

/// One seed roll by the seed's age, from the head's seed `s` to `s + 1`, to its end: the
/// clock moves 30 days and an hour (the text seed's maximum age, §5.6), the keyholder's next
/// opening starts the roll, the relay's pages give `bob`'s seat (and every other) a seed
/// welcome under `s + 1`, the clock moves 25 h and the next opening ends the roll
/// (`seed_floor = s + 1`) and re-keys every bucket by rows (every version is over 1 h old,
/// §5.5), now under `s + 1`. `ann` writes before each move of the clock, so each opening is
/// pushed to it (2f). Returns the epoch of the opening that ended the roll.
async fn seed_roll(
    w: &mut World,
    ann: usize,
    gen: &[u8; 16],
    bob_seat: &voipc_crypto::group_key::SeatRef,
    s: u32,
    id: u8,
) -> u32 {
    assert_eq!(
        w.head_seeds().1,
        s,
        "harness: the head's seed before the roll"
    );
    let now = w.now();
    w.people[ann].post_live(id, "before the roll", now);
    w.until(500, |_| false).await;
    w.jump(30 * DAY_MS + HOUR_MS).await;
    let started = w.seeds_at((s + 1, s), ann, 120_000).await;
    assert!(
        started,
        "harness: an opening 30 days on starts the roll to seed {}: head {:?}",
        s + 1,
        w.head_seeds()
    );
    // The relay's pages: bob's seat holds the new seed once its seed welcome is stored
    let mut holds = false;
    for _ in 0..120 {
        w.until(500, |_| false).await;
        if w.seat_seed(gen, bob_seat).await == s + 1 {
            holds = true;
            break;
        }
    }
    assert!(
        holds,
        "harness: the relay's page gave bob's seat a seed welcome under seed {}",
        s + 1
    );
    assert!(w.seed_welcome_stored(gen, bob_seat, s + 1).await);
    let now = w.now();
    w.people[ann].post_live(id + 1, "during the roll", now);
    w.until(500, |_| false).await;
    w.jump(25 * HOUR_MS).await;
    let ended = w.seeds_at((s + 1, s + 1), ann, 120_000).await;
    assert!(
        ended,
        "harness: the opening a day on ends the roll: head {:?}",
        w.head_seeds()
    );
    w.head_seeds().0
}

/// The F3 scene. ann and bob keep the channel's history and sit in it; bob's app opened
/// its seat welcome, so its self-row under seed 1 is on the relay. Then bob is away. The
/// seed rolls to 2 by its age (30 days), and bob's seat is given its seed welcome under
/// seed 2 by the relay's page, as §5.6 says an offline seat is. ann posts "mid", kept, in
/// an epoch in which bob's seat is keyed by a row under seed 2. With `back_between`, bob's
/// app comes back here once, reads "mid", and goes away again (the control). The seed rolls
/// again, to 3, and the relay's sweep runs. bob's app comes back, from its vault. Returns
/// whether it took the head's key, whether it read "mid", what it opened, and what the
/// relay's past answer for the epoch of "mid" held for bob just before it came back:
/// `(the row's seed, a seed welcome under it, a self-row under it)`.
async fn away_across_a_seed(
    w: &mut World,
    back_between: bool,
) -> (bool, bool, Vec<String>, (u32, bool, bool)) {
    let ann = w.person("ann").await;
    let bob = w.person("bob").await;
    let seated = w
        .until(20_000, |w| (0..2).all(|i| w.people[i].epoch().is_some()))
        .await;
    assert!(seated, "seated");
    let gen = w.people[ann].keying.current_epoch(CONV).unwrap().gen;
    let bob_a = w.people[bob].a;
    let bob_seat = w.people[bob]
        .sync
        .seat_keys()
        .unwrap()
        .pair
        .public()
        .seat(MemberId::Account(bob_a));
    // bob's self-row under seed 1 reaches the relay
    let mut written = false;
    for _ in 0..100 {
        w.until(100, |_| false).await;
        let n: i64 = crate::accounts::raw(
            w.relay(),
            &format!(
                "SELECT COUNT(*) FROM voipc_gk_self WHERE grp = '{CONV}' AND seed = 1 AND kind = 0"
            ),
        )
        .await
        .unwrap();
        if n >= 2 {
            written = true;
            break;
        }
    }
    assert!(
        written,
        "harness: ann's and bob's self-rows under seed 1 are stored"
    );
    w.away(bob);

    // The first roll, to seed 2
    let e_mid = seed_roll(w, ann, &gen, &bob_seat, 1, 10).await;
    w.post(ann, 1, "mid", 1).await;
    let p = past_piece(w, bob_a, gen, e_mid)
        .await
        .expect("a past answer for bob");
    let k = p.seat.expect("a keying");
    assert!(
        k.row.is_some() && k.s == 2,
        "harness: at the epoch of \"mid\" bob's seat is keyed by a row under seed 2 (seed {})",
        k.s
    );
    assert!(
        p.seed_welcome.is_some(),
        "harness: before the next roll the relay hands bob its seed welcome under seed 2"
    );

    if back_between {
        // The control: bob's app comes back while the seed welcome is stored
        w.reconnect(bob).await;
        let keyed = w.until(25_000, |w| w.people[bob].epoch().is_some()).await;
        assert!(
            keyed,
            "control: back between the rolls, bob takes the head's key"
        );
        assert!(
            reads(w, bob, "mid", 30_000).await,
            "control: back between the rolls, bob reads \"mid\": {:?}",
            w.people[bob].texts
        );
        w.until(1_000, |_| false).await;
        w.away(bob);
    }

    // The second roll, to seed 3, and the relay's sweep (every 10 min: the clock moves on
    // until it has run)
    seed_roll(w, ann, &gen, &bob_seat, 2, 20).await;
    let mut swept = false;
    for _ in 0..12 {
        if !w.seed_welcome_stored(&gen, &bob_seat, 2).await {
            swept = true;
            break;
        }
        w.jump(11 * 60 * 1000).await;
        w.until(1_500, |_| false).await;
    }
    // Once the floor passed seed 2 the sweep takes bob's seed welcome under it only where
    // bob's account holds that seed's self-row (it came back between the rolls); else that
    // welcome is the one place its member secret is, and stays (dive 3 F3)
    assert_eq!(
        swept, back_between,
        "harness: the relay's sweep took bob's seed welcome under seed 2 once the floor passed \
         it ({swept}), as it should only where bob came back between the rolls ({back_between})"
    );
    let p = past_piece(w, bob_a, gen, e_mid)
        .await
        .expect("a past answer for bob");
    let k = p.seat.as_ref().expect("a keying");
    let self_row = p.self_rows.iter().any(|r| {
        r.kind == voipc_protocol::gk::self_row::SELF_ROW
            && r.seed == k.s
            && (r.sk, r.sx) == (bob_seat.tag_sk, bob_seat.tag_sx)
    });
    let held = (k.s, p.seed_welcome.is_some(), self_row);

    // bob comes back, from its vault
    w.reconnect(bob).await;
    let keyed = w.until(25_000, |w| w.people[bob].epoch().is_some()).await;
    let read = reads(w, bob, "mid", 30_000).await;
    (keyed, read, w.people[bob].texts.clone(), held)
}

/// d3 F3. An account that only went offline stays seated, and is to read what was kept
/// meanwhile when it is back (§5.6 "A seat that is offline for weeks opens its welcome when
/// it is back; it does not hold the roll open"; §5.11 "Offline accounts": "every re-key
/// reaches it by rows"; §6 "An account that only went offline ... read them all when
/// back"). bob is away for about 62 days, under the 90-day seat expiry, while the seed
/// rolls twice by its 30-day age. "mid" was kept in between, 31 days before bob is back
/// (`retention_days` defaults to 365).
#[tokio::test]
async fn e2e_d3_an_account_away_while_a_seed_came_and_went_reads_what_was_kept_under_it() {
    let mut w = World::new().await;
    let (keyed, read, texts, (s, seed_welcome, self_row)) = away_across_a_seed(&mut w, false).await;
    assert!(
        keyed,
        "harness: back after both rolls, bob takes the head's key"
    );
    assert!(
        read,
        "bob was away while seed {s} came and went, and no longer reads the post kept under it: it opened {texts:?}. The relay's past answer keys bob's seat there by a row under seed {s}; a seed welcome under it is still stored: {seed_welcome}; a self-row under it exists: {self_row}. bob's member secret of that seed was only ever in that seed welcome, which the sweep deleted when the seed floor passed it"
    );
}

/// d3 F3, the control that pins the cause: the same scene, but bob's app came back once
/// between the two rolls, while its seed welcome under seed 2 was stored. It read "mid"
/// then, and its self-row under seed 2 reached the relay; back after the second roll and
/// the sweep, it reads "mid" again. Passes today.
#[tokio::test]
async fn e2e_d3_control_an_account_back_once_between_two_rolls_reads_what_was_kept_under_the_seed()
{
    let mut w = World::new().await;
    let (keyed, read, texts, (s, seed_welcome, self_row)) = away_across_a_seed(&mut w, true).await;
    assert!(
        keyed && read,
        "control: bob was back once under seed {s}; after the next roll and the sweep it takes the head's key ({keyed}) and reads \"mid\" ({read}): {texts:?}; seed welcome stored: {seed_welcome}; self-row: {self_row}"
    );
    assert!(
        !seed_welcome && self_row,
        "control: the seed welcome is gone all the same, and the self-row is what opens it"
    );
}

// ── F4: a rotation whose kept rows were never sealed again ────────────────

/// Writes into `i`'s vault what `AccountSync::seat_keys_rotate` saves at a seat-key rotation
/// made `days` days ago: new seat keys under the next counter, the old ones kept beside
/// them (`SeatKeys::rotate`). That is the vault a device leaves that rotated and then went
/// away (closed, crashed, lost its link) before it sealed the account's kept rows again
/// (§5.11 step 2): the vault write is the rotation's first step, the re-seal comes after.
/// `i`'s app is away meanwhile.
async fn rotation_left_unfinished(w: &mut World, i: usize, days: u64) {
    use voipc_crypto::group_key::{SeatKeys, ITEM_SEAT_KEM};
    let (a, sid) = (w.people[i].a, w.people[i].sid);
    assert!(!w.people[i].online, "its app is away");
    let held = w.relay().vault(AccountId(a)).await.unwrap();
    let version = held
        .iter()
        .find(|b| b.k == ITEM_SEAT_KEM)
        .expect("item.seat_kem is in the vault")
        .version;
    let item = w.people[i]
        .signed
        .vault
        .open_item(&held, ITEM_SEAT_KEM)
        .expect("item.seat_kem opens");
    let k1 = SeatKeys::from_bytes(&item.payload).expect("seat keys");
    assert!(k1.old.is_none(), "no rotation is under way");
    let made = wall_ms() / 1000 - days * 24 * 60 * 60;
    let k2 = k1.rotate(made).expect("rotated");
    let sealed = w.people[i]
        .signed
        .vault
        .seal_item(ITEM_SEAT_KEM, item.gen + 1, &k2.to_bytes());
    let put = AccountRequest::VaultPut {
        k: sealed.k,
        v: sealed.v,
        expect: version,
    };
    let _ = w.drain(sid).await;
    w.send(sid, ClientMessage::Account(put)).await;
    let stored = w
        .drain(sid)
        .await
        .into_iter()
        .any(|f| matches!(f, ServerMessage::Account(AccountReply::VaultStored { .. })));
    assert!(stored, "the vault keeps the rotated seat keys");
}

impl World {
    /// `reconnect`, with the host's periodic tick (every 2 s on the desktop app,
    /// `client/src-tauri/src/account.rs`) coming once right after the sign-in's first batch
    /// went out, before any reply to it: the tick is a timer of its own.
    async fn reconnect_then_tick(&mut self, i: usize) {
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
        // The first batch goes, and the tick comes before its replies are read
        let sid = self.people[i].sid;
        let out: Vec<ClientMessage> = self.people[i].out.drain(..).collect();
        for m in out {
            self.send(sid, m).await;
        }
        let now = self.now();
        self.people[i].tick(now);
        self.start(i).await;
    }
}

/// The F4 scene: F2's control scene (bob sits in the channel, its app opened its seat
/// welcome and wrote its self-row, its bucket was re-keyed by rows, ann's kept post "away1"
/// is read by bob from its vault). Then bob's app is away, and bob's vault holds a seat-key
/// rotation made `days` days ago whose device never sealed the kept rows again
/// (`rotation_left_unfinished`). bob's app signs in again (`tick_first`: with the host's
/// tick coming before the sign-in's replies), the rotation runs to its end (re-seated, the
/// old private parts gone), and a new device of bob reads the channel's kept history.
/// Whether it read "away1", what it opened, and how many history rows (§3.11) the relay
/// holds for the channel then: the re-seal writes one for the seat the rotation left.
async fn unfinished_rotation_then_back(
    w: &mut World,
    days: u64,
    tick_first: bool,
) -> (bool, Vec<String>, i64) {
    let (keyed, read, texts, _) = seated_away_rekeyed_back(w, true).await;
    assert!(
        keyed && read,
        "harness: before any rotation bob reads \"away1\": {texts:?}"
    );
    let bob = 1;
    assert_eq!(w.people[bob].signed.name, "bob");
    w.until(1_000, |_| false).await;
    w.away(bob);
    rotation_left_unfinished(w, bob, days).await;
    if tick_first {
        w.reconnect_then_tick(bob).await;
    } else {
        w.reconnect(bob).await;
    }
    let ended = w
        .until(90_000, |w| {
            w.people[bob]
                .sync
                .seat_keys()
                .is_some_and(|k| k.n >= 2 && k.old.is_none())
        })
        .await;
    assert!(
        ended,
        "harness: the rotation ran to its end (re-seated, the old private parts gone): {:?}",
        w.people[bob]
            .sync
            .seat_keys()
            .map(|k| (k.n, k.old.is_some()))
    );
    w.until(1_000, |_| false).await;
    let history_rows: i64 = crate::accounts::raw(
        w.relay(),
        &format!("SELECT COUNT(*) FROM voipc_gk_self WHERE grp = '{CONV}' AND kind = 1"),
    )
    .await
    .unwrap();
    w.reconnect(bob).await;
    let read = reads(w, bob, "away1", 30_000).await;
    (read, w.people[bob].texts.clone(), history_rows)
}

/// d3 F4. A seat-key rotation seals the account's kept rows again under the new self key
/// and writes the old seat's history rows before the old private parts go (§5.11 steps 2
/// and 4; plan C4 "Rotation": "writes the history rows, re-seals, and only then lets
/// `drop_old` run"). Here the device that rotated went away before that, and the account's
/// next sign-in is 31 days later: its seat keys are 30 days old by then, so the app rotates
/// again first (§5.11 "rotates before anything else"), which drops the keys of the
/// unfinished rotation (`sync.rs` `gk_on`: "`SeatKeys::rotate` would drop the old keys").
/// The kept post is minutes old in the test's own time and well inside `retention_days`.
#[tokio::test]
async fn e2e_d3_a_rotation_left_unfinished_a_month_ago_keeps_what_was_kept_before_it_readable() {
    let mut w = World::new().await;
    let (read, texts, history_rows) = unfinished_rotation_then_back(&mut w, 31, false).await;
    assert!(
        read,
        "bob's seat keys rotated 31 days ago on a device that went away before it sealed the kept rows again; at the next sign-in the old self key went with no re-seal, and bob no longer reads what was kept before that rotation: it opened {texts:?}; history rows the relay holds for the channel: {history_rows}"
    );
}

/// d3 F4, the 7-to-30-day case: the next sign-in is 8 days after the unfinished rotation.
/// The old keys are past their 7 days, so the first tick drops them
/// (`sync.rs` `gk_tick`: `done || now >= at + OLD_KEYS_SECS`) whether or not the re-seal
/// that the sign-in started has finished. Here the host's tick comes before the sign-in's
/// first replies (`reconnect_then_tick`); how often it does in the field depends on how
/// long the re-seal takes (one ask at a time, one per group and generation) against the
/// host's 2 s tick.
#[tokio::test]
async fn e2e_d3_a_rotation_left_unfinished_8_days_ago_keeps_what_was_kept_before_it_readable() {
    let mut w = World::new().await;
    let (read, texts, history_rows) = unfinished_rotation_then_back(&mut w, 8, true).await;
    assert!(
        read,
        "bob's seat keys rotated 8 days ago on a device that went away before it sealed the kept rows again; at the next sign-in the first tick dropped the old self key before the re-seal ran, and bob no longer reads what was kept before that rotation: it opened {texts:?}; history rows the relay holds for the channel: {history_rows}"
    );
}

/// d3 F4, the control that pins the cause: the same scene, but the next sign-in is 6 days
/// after the unfinished rotation, inside the 7 days the old keys are kept. The sign-in
/// seals the kept rows again and writes the history row, the old keys go only then, and a
/// new device of bob reads "away1". Also with the tick coming first. Passes today.
#[tokio::test]
async fn e2e_d3_control_a_rotation_left_unfinished_6_days_ago_is_finished_at_the_next_sign_in() {
    let mut w = World::new().await;
    let (read, texts, history_rows) = unfinished_rotation_then_back(&mut w, 6, true).await;
    assert!(
        read && history_rows >= 1,
        "control: 6 days after the unfinished rotation the sign-in finishes it (history rows: {history_rows}), and bob reads \"away1\": {texts:?}"
    );
}

// ── F5: a kept copy filed just after the next opening ─────────────────────

/// The F5 scene. ann and bob sit in the channel. A new epoch `e` opens, and ann posts
/// "late" in it, live. People keep joining: 59 Join commits land in `e`, one after another
/// (a busy channel has a Join every 2 s, §5.2, and an epoch lasts up to 5 or 10 minutes,
/// §5.5). Then the next epoch opens, and 5 more Joins land in it: 64 headers after the
/// opening of `e`. ann's kept copy of "late" reaches the relay only now,
/// under `e`, the epoch the post went out under (§5.10 "Which epoch a copy goes under"): the
/// relay starts a kept chain under the epoch before the head for `HOLD_MS` after the head
/// opened. The relay's 10-minute sweep (`gk/store.rs` `sweep_material`, called here as the
/// sweeper calls it) runs once: with `sweep_first` between the opening and the copy, else
/// after the copy (the control). A new device of bob, who sat in `e`, reads the channel's
/// kept history. Returns whether it read "late", what it opened, and whether the relay
/// still held the opening header of `e` and the kept chain under `e` then.
async fn copy_after_the_next_opening(
    w: &mut World,
    sweep_first: bool,
) -> (bool, Vec<String>, bool, bool) {
    let ann = w.person("ann").await;
    let bob = w.person("bob").await;
    let seated = w
        .until(20_000, |w| (0..2).all(|i| w.people[i].epoch().is_some()))
        .await;
    assert!(seated, "seated");
    // The scene times its 64 joins against the relay's clock, which moves at real time
    // between the jumps: the joiners are made ahead, and no refresh opens an epoch on the
    // way (one is due 5 minutes after each opening, and on a slow database these joins take
    // longer than that, CI twin's slow-Postgres pass). The openings come from log leaves.
    let mut made = w.crowd_made(64).await.into_iter();
    w.state.gk.hold_refresh_for_test(true);
    let now = w.now();
    w.people[ann].post_live(0, "zero", now);
    let first = w.crowd(1).await;
    assert!(w.crowd_seated(&first).await, "the crowd is seated");
    let before = w.head();
    w.leave_log(first[0].1).await;
    assert!(w.opened(before, &[ann]).await, "opened by a log leave");
    let e = w.head();
    let ep = w.people[ann]
        .keying
        .current_epoch(CONV)
        .expect("ann's key of e");
    assert_eq!(ep.epoch, e);
    let gen = ep.gen;
    // ann's post in e, live: its kept copy comes later
    let now = w.now();
    let env = w.people[ann].post_live(1, "late", now);
    // 59 Joins in e, one commit each: the relay's clock moves past each 2 s join batch.
    // (Not more in e itself: the shared test keyholder asks every list it needs in one frame,
    // which carries 64 at most, and each Join makes a bucket.)
    let mut crowd = vec![];
    for _ in 0..59 {
        let c = vec![made.next().expect("made ahead")];
        w.crowd_joins(c[0].1).await;
        w.jump(2_100).await;
        assert!(w.crowd_seated(&c).await, "a joiner is seated");
        crowd.extend(c);
    }
    assert_eq!(w.head(), e, "harness: e is still the head");
    // The next epoch opens, and five more Joins land in it
    w.leave_log(crowd[0].1).await;
    let opened = w.until(20_000, move |w| w.head() > e).await;
    assert!(opened, "harness: the next epoch opened");
    assert_eq!(w.head(), e + 1);
    for _ in 0..5 {
        let c = vec![made.next().expect("made ahead")];
        w.crowd_joins(c[0].1).await;
        w.jump(2_100).await;
        assert!(w.crowd_seated(&c).await, "a joiner is seated");
    }
    assert_eq!(w.head(), e + 1, "harness: e + 1 is still the head");
    let after: i64 = crate::accounts::raw(
        w.relay(),
        &format!(
            "SELECT COUNT(*) FROM voipc_gk_headers WHERE grp = '{CONV}' AND (epoch > {e} OR (epoch = {e} AND j > 0))"
        ),
    )
    .await
    .unwrap();
    assert!(
        after >= 64,
        "harness: {after} headers after the opening of epoch {e}: 64 put it out of the last 64"
    );
    if sweep_first {
        crate::gk::store::sweep_material(&w.db, CONV, w.now())
            .await
            .unwrap();
    }
    // ann's kept copy of "late", under e
    let now = w.now();
    let kept = w.people[ann].sync.send_channel_gk(CONV, env, now, None, ep);
    w.people[ann].out.extend(kept);
    let mut filed = false;
    for _ in 0..150 {
        w.until(100, |_| false).await;
        if w.kept().await >= 1 {
            filed = true;
            break;
        }
    }
    assert!(filed, "harness: the relay took the kept copy of \"late\"");
    if !sweep_first {
        crate::gk::store::sweep_material(&w.db, CONV, w.now())
            .await
            .unwrap();
    }
    let chain_under_e: i64 = crate::accounts::raw(
        w.relay(),
        &format!("SELECT COUNT(*) FROM voipc_gk_chains WHERE grp = '{CONV}' AND epoch = {e}"),
    )
    .await
    .unwrap();
    let opening_kept = db::opening(&w.db, CONV, &gen, e).await.unwrap().is_some();
    w.reconnect(bob).await;
    let read = reads(w, bob, "late", 30_000).await;
    (
        read,
        w.people[bob].texts.clone(),
        opening_kept,
        chain_under_e == 1,
    )
}

/// d3 F5. A kept post that a member could read stays readable (§5.10 "How long the relay
/// keeps an epoch's header, seals and rows: as long as a kept chain starting in that epoch
/// is kept"). The relay files a kept chain under the epoch before the head for `HOLD_MS`
/// after the head opened; its sweep of the epoch's seals, lists and rows waits `HOLD_MS`
/// plus 2 minutes for that, but its sweep of headers does not wait: with 64 headers after
/// it, the opening header of the epoch before the head goes at the next sweep unless a
/// kept chain names the epoch already.
#[tokio::test]
async fn e2e_d3_a_kept_copy_filed_just_after_the_next_opening_stays_readable() {
    let mut w = World::new().await;
    let (read, texts, opening_kept, chain_under_e) =
        copy_after_the_next_opening(&mut w, true).await;
    assert!(
        read,
        "the relay filed ann's kept copy under the epoch before the head (a kept chain under it: {chain_under_e}), but bob, who sat in that epoch, cannot read it: it opened {texts:?}. The epoch's opening header is still stored: {opening_kept}; the sweep took it before the chain named the epoch"
    );
}

/// d3 F5, the control that pins the cause: the same scene, with the sweep run after the
/// kept copy was filed and not before it. The chain names the epoch, the sweep keeps its
/// opening header, and bob reads "late". Passes today.
#[tokio::test]
async fn e2e_d3_control_a_sweep_after_the_kept_copy_keeps_the_epochs_opening_header() {
    let mut w = World::new().await;
    let (read, texts, opening_kept, chain_under_e) =
        copy_after_the_next_opening(&mut w, false).await;
    assert!(
        read && opening_kept && chain_under_e,
        "control: swept after the copy was filed, the opening header stays ({opening_kept}), the chain is under the epoch ({chain_under_e}), and bob reads \"late\" ({read}): {texts:?}"
    );
}

// ── F6: a stored group after a restore, and an older generation's kept posts ──

/// How the relay comes back (`World::started_again`).
#[derive(Clone, Copy, Debug, PartialEq)]
enum Again {
    Same,
    Restored,
    SwitchedBackOn,
}

impl World {
    /// The relay stops, its database is restored (`db new-incarnation`, §5.7), and it starts
    /// again on it: a new `ServerState` on the same database under a new incarnation, the
    /// channel as before, and a new guest keyholder. Every app is away until it reconnects.
    async fn restored(&mut self) {
        self.started_again(Again::Restored).await;
    }

    /// The relay stops and starts again on its database, as `main.rs` `gk_switch` starts it
    /// (`accounts::gk::gk_start`, then `Groups::attach`): after nothing else (`Same`: the
    /// incarnation stays), after the operator's `db new-incarnation` (`Restored`, §5.7), or
    /// after a run with `group_key = false` in between (`SwitchedBackOn`, §5.14).
    async fn started_again(&mut self, how: Again) {
        if let Some(k) = self.holder.take() {
            k.task.abort();
        }
        for p in &mut self.people {
            p.online = false;
        }
        self.followers.clear();
        self.queues.clear();
        match how {
            Again::Same => {}
            Again::Restored => {
                db::new_incarnation(&self.db).await.unwrap();
            }
            Again::SwitchedBackOn => {
                assert!(db::gk_start(&self.db, false).await.unwrap().is_none());
            }
        }
        let inc = db::gk_start(&self.db, true).await.unwrap().unwrap();
        let cfg = crate::config::AccountsConfig {
            mode: crate::config::AccountsMode::Optional,
            ..Default::default()
        };
        let relay = crate::accounts::Relay::open_with(&cfg, self.db.clone(), &[9u8; 32])
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
        state.gk.attach(self.db.clone(), inc);
        crate::state::test_support::put_in_channel(&state, CHAN, &[]).await;
        {
            let mut channels = state.channels.write().await;
            let c = channels.get_mut(&CHAN).unwrap();
            c.info.text = true;
            c.info.log = CONV.into();
            c.log_conv = CONV.into();
        }
        self.state = state;
        self.last_tick = 0;
        let ik = generate_identity_key_pair();
        let sid = self.session(&ik, None).await;
        self.follow(sid, None);
        let h = Holder::guest(sid, ik, CONV, true);
        self.send(sid, h.volunteer()).await;
        let (tx, rx) = self.queues.get_mut(&sid).unwrap();
        let (tx, rx) = (tx.clone(), rx.take().unwrap());
        self.holder = Some(Keyholder::run(self.state.clone(), h, tx, rx));
    }
}

/// d3, a claim that holds (question 2, "a generation change followed by a sweep"). ann and
/// bob sit in the channel. ann's kept post "old1" lies in an epoch in which bob's bucket
/// version is the one its Join made (a seat welcome, and the Join's row beside it), "old2"
/// in a later epoch in which bob's bucket was re-keyed by rows (the hourly re-key, §5.5).
/// The relay's database is restored: a new incarnation, so the group starts a new
/// generation, and the reset takes every welcome of the old one (`accounts/gk.rs`
/// `reset_step`). Both come back and are seated in the new generation; the relay's sweep
/// runs. A new device of bob then reads both posts of the old generation, on the binding
/// alone, from its self-row and the rows the relay kept. bob's seat keys then rotate to the
/// end, and another new device of bob still reads both, from the history row. (With the
/// welcome gone the relay's past answer falls back to the row beside it, so F1 does not
/// bite in a generation a restore ended.)
///
/// Blocked by F6 today: the group never starts its new generation after the restore, so
/// this fails at "both are seated in the new generation". Run it (`-- --ignored`) once F6
/// is fixed; what it claims after that point is read from the code only so far.
#[tokio::test]
async fn e2e_d3_holds_an_older_generations_kept_posts_stay_readable_after_a_restore_a_sweep_and_a_rotation(
) {
    let mut w = World::new().await;
    let ann = w.person("ann").await;
    let bob = w.person("bob").await;
    let seated = w
        .until(20_000, |w| (0..2).all(|i| w.people[i].epoch().is_some()))
        .await;
    assert!(seated, "seated");
    let now = w.now();
    w.people[ann].post_live(0, "zero", now);
    let crowd = w.crowd(1).await;
    assert!(w.crowd_seated(&crowd).await, "the crowd is seated");
    let before = w.head();
    w.leave_log(crowd[0].1).await;
    assert!(w.opened(before, &[ann]).await, "opened by a log leave");
    let e1 = w.head();
    let gen = w.people[ann].keying.current_epoch(CONV).unwrap().gen;
    let bob_a = w.people[bob].a;
    w.post(ann, 1, "old1", 1).await;
    let k = past_piece(&w, bob_a, gen, e1).await.unwrap().seat.unwrap();
    assert!(
        k.welcome.is_some() || k.row.is_some(),
        "harness: at e1 bob's seat is keyed by its seat welcome or the row beside it"
    );
    // The hourly re-key: every version by rows
    w.jump(61 * 60 * 1000).await;
    assert!(
        w.opened(e1, &[ann]).await,
        "opened by the refresh an hour on"
    );
    let e2 = w.head();
    w.post(ann, 2, "old2", 2).await;
    let k = past_piece(&w, bob_a, gen, e2).await.unwrap().seat.unwrap();
    assert!(
        k.row.is_some(),
        "harness: at e2 bob's seat is keyed by a row"
    );
    w.until(1_000, |_| false).await;

    // The restore, and both back in the new generation
    w.restored().await;
    // The new relay's clock starts at the wall clock: moved past the hour the old one was
    // moved, so that it does not run behind the old generation's headers
    w.jump(62 * 60 * 1000).await;
    w.reconnect(ann).await;
    w.reconnect(bob).await;
    let seated = w
        .until(40_000, |w| (0..2).all(|i| w.people[i].epoch().is_some()))
        .await;
    assert!(seated, "both are seated in the new generation");
    let new_gen = w.people[ann].keying.current_epoch(CONV).unwrap().gen;
    assert_ne!(new_gen, gen, "harness: a new generation");
    crate::gk::store::sweep_material(&w.db, CONV, w.now())
        .await
        .unwrap();
    let k = past_piece(&w, bob_a, gen, e1)
        .await
        .expect("e1 is still answered")
        .seat
        .unwrap();
    assert!(
        k.welcome.is_none() && k.row.is_some(),
        "the reset took the old generation's welcomes, and e1 is answered by the row beside"
    );

    // A new device of bob reads the old generation's posts
    w.reconnect(bob).await;
    let one = reads(&mut w, bob, "old1", 30_000).await;
    let two = reads(&mut w, bob, "old2", 30_000).await;
    assert!(
        one && two,
        "after the restore and the sweep bob reads the old generation's posts: old1 {one}, old2 {two}: {:?}",
        w.people[bob].texts
    );

    // bob's seat keys rotate to the end; a new device still reads both
    rotate_to_the_end(&mut w, bob).await;
    w.until(1_000, |_| false).await;
    w.reconnect(bob).await;
    let one = reads(&mut w, bob, "old1", 30_000).await;
    let two = reads(&mut w, bob, "old2", 30_000).await;
    assert!(
        one && two,
        "after a seat-key rotation on top, bob still reads the old generation's posts: old1 {one}, old2 {two}: {:?}",
        w.people[bob].texts
    );
}

/// The F6 scene: ann sits in the stored channel and holds its key. The relay stops and
/// starts again on its database (`how`), a volunteer is online, and ann's app comes back.
/// Returns whether ann holds a head's key within 40 s, whether the database's group row
/// names another generation than before, and how many generations it knows for the group.
async fn back_after(w: &mut World, how: Again) -> (bool, bool, i64) {
    let ann = w.person("ann").await;
    let seated = w.until(20_000, |w| w.people[0].epoch().is_some()).await;
    assert!(seated, "ann seated");
    let gen = w.people[ann].keying.current_epoch(CONV).unwrap().gen;
    w.until(500, |_| false).await;
    w.started_again(how).await;
    w.reconnect(ann).await;
    let keyed = w.until(40_000, |w| w.people[0].epoch().is_some()).await;
    let row = db::group(&w.db, CONV)
        .await
        .unwrap()
        .expect("the group's row");
    let gens: i64 = crate::accounts::raw(
        w.relay(),
        &format!("SELECT COUNT(*) FROM voipc_gk_gens WHERE grp = '{CONV}'"),
    )
    .await
    .unwrap();
    (keyed, row.head.gen != gen, gens)
}

/// d3 F6. After a restore the operator runs `db new-incarnation`, and "at start, every
/// stored group from an older incarnation loses its keyring, `KRK` welcomes, seeds and
/// pending joins. Its next fetch starts a new generation, and members take it under the
/// rules for a new generation" (GROUP-KEY §5.7 "Restore"; OPERATING §7).
#[tokio::test]
async fn e2e_d3_a_stored_group_starts_a_new_generation_after_a_restore() {
    let mut w = World::new().await;
    let (keyed, new_gen, gens) = back_after(&mut w, Again::Restored).await;
    assert!(
        keyed && new_gen,
        "after `db new-incarnation` and a restart, ann holds a key of the channel: {keyed}; the group's row names a new generation: {new_gen} (generations known: {gens}). The relay asks a volunteer for a Genesis, the store refuses each one (`move_head`: the group's row holds the old head, the commit names none: `OtherHead`), and the relay asks again at once"
    );
}

/// d3 F6, the switch: "a start with the switch on after a run with it off begins a new
/// generation for every group, as a new incarnation does" (GROUP-KEY §5.14 "Back on").
#[tokio::test]
async fn e2e_d3_a_stored_group_starts_a_new_generation_after_the_switch_went_off_and_on() {
    let mut w = World::new().await;
    let (keyed, new_gen, gens) = back_after(&mut w, Again::SwitchedBackOn).await;
    assert!(
        keyed && new_gen,
        "after a run with group_key off and a start with it on again, ann holds a key of the channel: {keyed}; the group's row names a new generation: {new_gen} (generations known: {gens})"
    );
}

/// d3 F6, the control that pins the cause: the same scene with a plain restart (the same
/// incarnation). The group loads its head from the database, ann's account seat is still
/// seated, and its new connection is answered with the head and takes its key again, in
/// the same generation. Passes today.
#[tokio::test]
async fn e2e_d3_control_a_stored_group_goes_on_after_a_plain_restart() {
    let mut w = World::new().await;
    let (keyed, new_gen, gens) = back_after(&mut w, Again::Same).await;
    assert!(
        keyed && !new_gen && gens == 1,
        "control: after a plain restart ann holds a key again ({keyed}) in the same generation (new: {new_gen}, known: {gens})"
    );
}

// ── Holds: two rotations ──────────────────────────────────────────────────

/// d3, a claim that holds (question 2, "two rotations in one window"; "a device added
/// after a rotation"). bob's kept read of "away1" goes through a row to its seat and its
/// self-row (F2's control scene). bob's seat keys then rotate twice, each rotation run to
/// its end (re-seated, the kept rows sealed again, the old private parts gone), and a new
/// device of bob reads "away1" after each: from the first seat's history row, sealed again
/// under each new self key (§3.11, §5.11 step 2).
#[tokio::test]
async fn e2e_d3_holds_a_kept_post_keyed_by_a_row_stays_readable_across_two_rotations() {
    let mut w = World::new().await;
    let (keyed, read, texts, _) = seated_away_rekeyed_back(&mut w, true).await;
    assert!(
        keyed && read,
        "harness: before any rotation bob reads \"away1\": {texts:?}"
    );
    let bob = 1;
    assert_eq!(w.people[bob].signed.name, "bob");
    for round in 1..=2 {
        w.until(1_000, |_| false).await;
        rotate_to_the_end(&mut w, bob).await;
        w.until(1_000, |_| false).await;
        w.reconnect(bob).await;
        let read = reads(&mut w, bob, "away1", 30_000).await;
        assert!(
            read,
            "after rotation {round}, run to its end, a new device of bob reads \"away1\": {:?}",
            w.people[bob].texts
        );
    }
}

// ── P3: an eager seat away across a seed roll (fix review) ────────────────

/// Where bob comes back in the P3 scene.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Back {
    /// After the roll ended and the sweep ran.
    AfterTheRoll,
    /// While the roll runs: its seat holds seed 2 already, its head keying is still a row
    /// under seed 1 (the roll's first opening re-keyed every bucket under the old seed).
    MidRoll,
    /// After the roll, as `AfterTheRoll`, with its vault's seat keys 31 days old: its app
    /// rotates them first at the sign-in (§5.11), and the rotation runs to its end before
    /// anything reads the channel.
    KeysDue,
}

/// What the P3 scene found.
struct P3 {
    bob: usize,
    /// The relay stored a seed welcome under seed 1 for bob's seat while no roll ran.
    paged: bool,
    /// A seed welcome under seed 1 was still stored for bob's seat when it came back.
    kept: bool,
    keyed: bool,
    read: bool,
}

/// The P3 scene (dive 3 F2/F3 fix review, B-P3). bob keeps the channel's history and follows
/// nothing (`person_as(false)`): its LogJoin seats it eagerly, a crowd account in the same
/// Join, and no device of bob ever opens that seat welcome, the only place its member secret
/// under seed 1 was. The relay pages such a seat a seed welcome under the head seed as soon as
/// it is seated, though no roll runs (`paged`). bob is away; the crowd account leaves, so e1
/// re-keys bob's bucket by rows under seed 1; ann posts "away1", kept. Then the seed rolls
/// 1 -> 2 by its age, and bob comes back `back`, from its vault: it is to take the head's key
/// and read "away1" (§5.6 "A seat that is offline for weeks opens its welcome when it is back",
/// §5.11 "every re-key reaches it by rows").
async fn eager_away_across_a_roll(w: &mut World, back: Back) -> P3 {
    let ann = w.person("ann").await;
    let seated = w.until(20_000, |w| w.people[0].epoch().is_some()).await;
    assert!(seated, "ann seated");
    let now = w.now();
    w.people[ann].post_live(0, "zero", now);
    // bob: signed in, keeps the log, follows nothing
    let bob = w.person_as("bob", false).await;
    let settled = w
        .until(15_000, |w| {
            w.people[bob].sync.seat_keys().is_some() && w.people[bob].out.is_empty()
        })
        .await;
    assert!(settled, "bob's seat keys settled");
    let bob_a = w.people[bob].a;
    w.read(bob);
    w.step().await;
    // A crowd account joins the log in the same join batch: the same bucket
    let crowd = w.crowd(1).await;
    assert!(w.crowd_seated(&crowd).await, "the crowd is seated");
    let mut bob_seated = false;
    for _ in 0..100 {
        w.until(200, |_| false).await;
        if !db::seats_of_account(&w.db, &bob_a)
            .await
            .unwrap()
            .is_empty()
        {
            bob_seated = true;
            break;
        }
    }
    assert!(bob_seated, "bob is seated by its LogJoin");
    let gen = w.people[ann].keying.current_epoch(CONV).unwrap().gen;
    let seat = w.people[bob]
        .sync
        .seat_keys()
        .unwrap()
        .pair
        .public()
        .seat(MemberId::Account(bob_a));
    // The relay's page for the seat no device opened: under the head seed, no roll
    let mut paged = false;
    for _ in 0..60 {
        if w.seed_welcome_stored(&gen, &seat, 1).await {
            paged = true;
            break;
        }
        w.until(500, |_| false).await;
    }
    let (_, s, f) = w.head_seeds();
    assert_eq!((s, f), (1, 1), "harness: no roll ran while bob was seated");
    // bob goes away
    w.away(bob);
    // The crowd account leaves: bob's bucket gets a new version by rows
    let before = w.head();
    w.leave_log(crowd[0].1).await;
    assert!(w.opened(before, &[ann]).await, "opened by a log leave");
    let e1 = w.head();
    let p = past_piece(w, bob_a, gen, e1)
        .await
        .expect("a past answer for bob");
    let k = p.seat.expect("a keying");
    assert!(
        k.row.is_some() && k.ratchets.is_empty() && k.s == 1,
        "harness: bob's bucket was re-keyed by rows under seed 1 at epoch {e1} (seed {})",
        k.s
    );
    w.post(ann, 1, "away1", 1).await;
    match back {
        Back::AfterTheRoll | Back::KeysDue => {
            seed_roll(w, ann, &gen, &seat, 1, 10).await;
            // The relay's sweep, every 10 min: the floor passed seed 1
            for _ in 0..3 {
                w.jump(11 * 60 * 1000).await;
                w.until(1_500, |_| false).await;
            }
        }
        Back::MidRoll => {
            let now = w.now();
            w.people[ann].post_live(10, "before the roll", now);
            w.until(500, |_| false).await;
            w.jump(30 * DAY_MS + HOUR_MS).await;
            let started = w.seeds_at((2, 1), ann, 120_000).await;
            assert!(
                started,
                "harness: an opening 30 days on starts the roll: head {:?}",
                w.head_seeds()
            );
            let mut holds = false;
            for _ in 0..120 {
                w.until(500, |_| false).await;
                if w.seat_seed(&gen, &seat).await == 2 {
                    holds = true;
                    break;
                }
            }
            assert!(
                holds,
                "harness: the relay's page gave bob's seat a seed welcome under seed 2"
            );
            let (e, s, f) = w.head_seeds();
            assert_eq!((s, f), (2, 1), "harness: the roll still runs");
            let p = past_piece(w, bob_a, gen, e)
                .await
                .expect("a past answer for bob at the head epoch");
            let k = p.seat.expect("a keying");
            assert!(
                k.row.is_some() && k.s == 1,
                "harness: at the head epoch {e} bob's seat is keyed by a row under seed 1 (seed {})",
                k.s
            );
        }
    }
    let kept = w.seed_welcome_stored(&gen, &seat, 1).await;
    if back == Back::KeysDue {
        seat_keys_dated_back(w, bob, 31).await;
        w.host_glue.push(bob_a);
    }
    // bob comes back, from its vault
    w.reconnect(bob).await;
    let keyed = w.until(25_000, |w| w.people[bob].epoch().is_some()).await;
    if back == Back::KeysDue {
        // Its app rotated first; the rotation runs to its end with nothing read
        let ended = w
            .until(90_000, |w| {
                w.people[bob]
                    .sync
                    .seat_keys()
                    .is_some_and(|k| k.n == 2 && k.old.is_none())
            })
            .await;
        assert!(
            ended,
            "harness: the rotation at the sign-in ran to its end: {:?}",
            w.people[bob]
                .sync
                .seat_keys()
                .map(|k| (k.n, k.old.is_some()))
        );
        w.until(1_000, |_| false).await;
        w.reconnect(bob).await;
    }
    let read = reads(w, bob, "away1", 30_000).await;
    P3 {
        bob,
        paged,
        kept,
        keyed,
        read,
    }
}

/// `i`'s vault seat keys, dated `days` back (`made`), as one that has not signed in since: its
/// next sign-in rotates them first (§5.11 "older than that rotates before anything else").
/// `i`'s app is away meanwhile.
async fn seat_keys_dated_back(w: &mut World, i: usize, days: u64) {
    use voipc_crypto::group_key::{SeatKeys, ITEM_SEAT_KEM};
    let (a, sid) = (w.people[i].a, w.people[i].sid);
    assert!(!w.people[i].online, "its app is away");
    let held = w.relay().vault(AccountId(a)).await.unwrap();
    let version = held
        .iter()
        .find(|b| b.k == ITEM_SEAT_KEM)
        .expect("item.seat_kem is in the vault")
        .version;
    let item = w.people[i]
        .signed
        .vault
        .open_item(&held, ITEM_SEAT_KEM)
        .expect("item.seat_kem opens");
    let mut k = SeatKeys::from_bytes(&item.payload).expect("seat keys");
    assert!(k.old.is_none(), "no rotation is under way");
    k.made = wall_ms() / 1000 - days * 24 * 60 * 60;
    let sealed = w.people[i]
        .signed
        .vault
        .seal_item(ITEM_SEAT_KEM, item.gen + 1, &k.to_bytes());
    let put = AccountRequest::VaultPut {
        k: sealed.k,
        v: sealed.v,
        expect: version,
    };
    let _ = w.drain(sid).await;
    w.send(sid, ClientMessage::Account(put)).await;
    let stored = w
        .drain(sid)
        .await
        .into_iter()
        .any(|f| matches!(f, ServerMessage::Account(AccountReply::VaultStored { .. })));
    assert!(stored, "the vault keeps the seat keys dated back");
}

/// d3 P3. An account that keeps the channel's history, seated eagerly while no device of it
/// was there, away while its bucket was re-keyed by rows and then while the seed rolled:
/// back after the roll, it takes the head's key and reads what was kept before the roll.
#[tokio::test]
async fn e2e_d3_p3_an_eager_seat_away_across_a_seed_roll_reads_what_was_kept_before_it() {
    let mut w = World::new().await;
    let p = eager_away_across_a_roll(&mut w, Back::AfterTheRoll).await;
    assert!(
        p.keyed && p.read,
        "bob was seated eagerly, never opened that welcome, and was away while seed 1 rolled to 2: took the head's key: {}; read \"away1\", kept under a row under seed 1: {} (opened {:?}). A seed welcome under seed 1 was stored for bob's seat before the roll: {}; still stored when it came back: {}",
        p.keyed,
        p.read,
        w.people[p.bob].texts,
        p.paged,
        p.kept
    );
    assert!(
        p.paged && p.kept,
        "the relay paged bob's seat under seed 1 with no roll running ({}), and the sweep kept that welcome past the floor ({})",
        p.paged,
        p.kept
    );
}

/// d3 P3, back while the roll runs: bob's seat holds seed 2 (the roll's page), but its head
/// keying is still a row under seed 1, which only the seed welcome under seed 1 opens. The
/// relay hands that one, not the head seed's, so bob takes the head's key at once (not up to
/// an hour later, at its bucket's next re-key) and reads "away1".
#[tokio::test]
async fn e2e_d3_p3_an_eager_seat_back_while_the_roll_runs_takes_the_head_key_and_reads() {
    let mut w = World::new().await;
    let p = eager_away_across_a_roll(&mut w, Back::MidRoll).await;
    assert!(
        p.keyed && p.read,
        "bob came back while the roll ran, its head keying a row under seed 1: took the head's key: {}; read \"away1\": {} (opened {:?}); paged under seed 1: {}",
        p.keyed,
        p.read,
        w.people[p.bob].texts,
        p.paged
    );
}

/// d3 P3, then a rotation: bob back after the roll reads "away1" through the seed welcome under
/// seed 1 (a kept read: its live keying is under seed 2). That read writes bob's self-row under
/// seed 1, so the rotation's step 2 (§5.11) makes a history row for seed 1, and after the old
/// private parts are gone a new device of bob still reads "away1". Without the self-row the
/// seed welcome went to the old seat's KEM key, which the rotation deletes.
#[tokio::test]
async fn e2e_d3_p3_what_an_eager_seat_read_by_its_seed_welcome_stays_readable_after_a_rotation() {
    let mut w = World::new().await;
    let p = eager_away_across_a_roll(&mut w, Back::AfterTheRoll).await;
    assert!(
        p.keyed && p.read,
        "harness: back after the roll bob reads \"away1\": {:?}",
        w.people[p.bob].texts
    );
    let bob = p.bob;
    let rows1: i64 = crate::accounts::raw(
        w.relay(),
        &format!(
            "SELECT COUNT(*) FROM voipc_gk_self WHERE grp = '{CONV}' AND seed = 1 AND kind = 0"
        ),
    )
    .await
    .unwrap();
    w.until(1_000, |_| false).await;
    rotate_to_the_end(&mut w, bob).await;
    w.until(1_000, |_| false).await;
    w.reconnect(bob).await;
    let read = reads(&mut w, bob, "away1", 30_000).await;
    assert!(
        read,
        "after the rotation, run to its end, a new device of bob reads \"away1\": {:?}; self-rows under seed 1 stored before the rotation: {rows1}",
        w.people[bob].texts
    );
}

/// Fix review P3-R1 (open): bob back after the roll with seat keys 31 days old rotates them
/// first (§5.11). "away1" opens only by the seed welcome under seed 1 to the old seat, which
/// only the old KEM key opens, and only a kept read that is anchored counts that welcome. The
/// sign-in's own catch-up reads the channel (no explicit read here before the rotation's end),
/// but its first ask goes before the live answer brought an anchor, and in a rotation that
/// answer comes with the new seat's Join: the commit whose `EpochReseated{left: 0}` lets the
/// old keys go once the re-seal ended (it has no self-row of the old seat to work from). bob's
/// app hands kept reads over as the hosts do (`host_glue`): the ask, left waiting for an anchor
/// now (`kept.rs` `past_in`), goes again only at `AccountSync`'s retry, after the old keys
/// went, and a new device of bob reads "away1" no more. With the harness's own glue (every
/// step) it passes by timing alone. The fix needs `sync.rs`: the old keys kept until such a
/// group's kept reads are done, outside this fix's files.
#[tokio::test]
async fn e2e_d3_p3_an_eager_seat_back_with_seat_keys_due_reads_what_was_kept_before_the_roll() {
    let mut w = World::new().await;
    let p = eager_away_across_a_roll(&mut w, Back::KeysDue).await;
    assert!(
        p.keyed && p.read,
        "bob back after the roll with seat keys 31 days old, rotated first, the rotation run to its end, then a new device: took the head's key: {}; read \"away1\": {} (opened {:?})",
        p.keyed,
        p.read,
        w.people[p.bob].texts
    );
}
