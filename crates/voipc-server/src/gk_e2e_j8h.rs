//! End-to-end group-key scenarios added by fix-round slice J8H (2026-11-19). The relay's real
//! `gk` code driven by the clients' real `voipc_crypto::group_state` code; shared helpers live
//! in `gk_e2e_tests.rs`.
//!
//! Keyholder availability (deep-dive-candidates.md, dive 2, leads a and b): a stored text
//! channel whose only keyholder is an account's browser. A browser holds text keys with its
//! connection's pair (0x02), which goes with the connection: after a reload, or a relay
//! restart, its entry can never be online again. The keyholder's app runs on a task of its
//! own, answering each frame as it comes (as `gk_e2e_k2.rs` runs its keyholder); every
//! member's app is stepped by the test.
//!
//! Time: the group starts in real time, as the other e2e tests run; then tokio's clock is
//! paused for what is measured (the 1 h Regenesis wait among it). The relay stores in a
//! database (a stored group needs one), so `Store::slow_commits` (memory groups only) does
//! not apply. Paused, the clock moves only by the test's own `advance` (`Gate`): tokio does
//! not jump it to the next timer while the database works (which timed out the pool's
//! connections under `start_paused`). Each step leaves a millisecond of real time first for
//! the relay's and the keyholder's work, and while some of it is still under way (a store
//! write on Postgres under load), the clock moves at real time, as a relay's does
//! (`World::settle`).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use l4f_accounts::store::Store;
use voipc_crypto::group_key::{Endorsement, GroupKind, MemberId, Origin, SeatKeys};
use voipc_crypto::group_state::{
    GkCtx, GkEvent, GkOut, GkStart, GkTrack, GroupKeying, LocalGk, MemoryPins, Platform, VaultFloor,
};
use voipc_crypto::{IdentityKeyPair, SignalStores};
use voipc_protocol::messages::{ClientMessage, ServerMessage};
use voipc_protocol::types::{ChannelId, GroupLoad, UserId};

use super::gk_e2e_tests::{account_session, drop_db, scratch_db, show, tracing_on};
use crate::control::{ControlRx, ControlTx};
use crate::state::ServerState;

pub(super) const CHAN: ChannelId = 11;
pub(super) const CONV: &str = "c:j8hall";

/// How long a newcomer may wait for its seat while a keyholder's account is online in the
/// channel again: a Join due and its commit, with room for a fetch's retry.
const SEATED_WITHIN_MS: u64 = 2 * 60_000;
/// The same after the set's last entry went for good ("Fast new start", owner 2026-11-19; at
/// once, J10-B option A, owner 2026-11-22): every entry of the set in force is a connection's
/// and none is online, so the relay asks a Regenesis as the newcomer comes
/// (`REGENESIS_FAST_AFTER_MS`, none); the Regenesis (30 s deadline, and a retry 30 s after a
/// miss), a Join batch (2 s) and its commit (5 s) seat it. Under the old fast wait's 2 min
/// (the seat came at about 2.1 min alone, 3.0 min on Postgres under load before J10's
/// `World::settle`), so that wait and the hour both fail it.
pub(super) const SEATED_AT_ONCE_MS: u64 = 90_000;
/// How long the tests watch for the newcomer's seat at most: past the 1 h Regenesis.
pub(super) const WATCH_MS: u64 = 75 * 60_000;

fn wall_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn raw(ik: &IdentityKeyPair) -> [u8; 32] {
    ik.public_key().public_key_bytes().try_into().unwrap()
}

/// An account with its identity and published seat keys (counter 1), as `gk_e2e_tests.rs`
/// makes one.
pub(super) struct Account {
    a: [u8; 16],
    ik: IdentityKeyPair,
    keys: SeatKeys,
}

impl Account {
    pub(super) async fn new(db: &Store, name: &str) -> Account {
        let id = l4f_accounts::model::AccountId::new();
        db.create_user(
            &l4f_accounts::model::NewUser {
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
        let ik = voipc_crypto::generate_identity_key_pair();
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
        crate::accounts::gk::put_seat_keys(
            db,
            &id.0,
            &crate::accounts::gk::SeatKeys {
                n: keys.n,
                kem: public.kem_bytes().into(),
                dh: public.dh_bytes().into(),
                made: e.made,
                sig: e.sig.to_vec(),
                published: wall_ms(),
            },
        )
        .await
        .unwrap();
        Account { a: id.0, ik, keys }
    }

    fn keys(&self) -> SeatKeys {
        SeatKeys::from_bytes(&self.keys.to_bytes()).unwrap()
    }
}

/// One connection's `GroupKeying` as an app runs it: build jobs run whole as the host runs
/// them off the lock, its uploads taken.
pub(super) struct App {
    pub(super) sid: UserId,
    name: &'static str,
    pub(super) keying: GroupKeying,
    st: SignalStores,
    pins: MemoryPins,
    pub(super) events: Vec<GkEvent>,
}

impl App {
    /// `acc`'s app on connection `sid`: a desktop that does not hold keys, or (`browser`) a
    /// browser page with "Help hold keys" on. Started and tracking the channel's group; what
    /// it sends.
    fn new(
        state: &ServerState,
        sid: UserId,
        name: &'static str,
        acc: &Account,
        browser: bool,
        local: Option<LocalGk>,
    ) -> (App, Vec<ClientMessage>) {
        let platform = if browser {
            Platform::Browser
        } else {
            Platform::Desktop
        };
        App::with(state, sid, name, acc, platform, browser, local)
    }

    /// `acc`'s app on connection `sid` on `platform`, "Help hold keys" `holds`.
    fn with(
        state: &ServerState,
        sid: UserId,
        name: &'static str,
        acc: &Account,
        platform: Platform,
        holds: bool,
        local: Option<LocalGk>,
    ) -> (App, Vec<ClientMessage>) {
        let mut app = App {
            sid,
            name,
            keying: GroupKeying::default(),
            st: SignalStores::new(&acc.ik, sid),
            pins: MemoryPins::default(),
            events: vec![],
        };
        let now = state.gk.now();
        let out = app.keying.start(GkStart {
            on: true,
            run: state.gk.run,
            relay_clock: now / 1000,
            platform,
            help_hold_keys: holds,
            user_id: sid,
            identity: acc.ik,
            account: Some(acc.a),
            seat_keys: Some(acc.keys()),
            local,
            visible: true,
        });
        let mut send = app.took(out, now);
        let out = app.keying.track(
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
        send.extend(app.took(out, now));
        (app, send)
    }

    fn took(&mut self, out: GkOut, now: u64) -> Vec<ClientMessage> {
        let mut outs = vec![out];
        let mut send = vec![];
        while let Some(out) = outs.pop() {
            self.events.extend(out.events);
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

    fn frame(&mut self, f: &ServerMessage, now: u64) -> Vec<ClientMessage> {
        if tracing_on() {
            eprintln!("[{now}] {} {} <- {}", self.name, self.sid, show(f));
        }
        let c = GkCtx {
            pins: &mut self.pins,
            now,
        };
        let out = self.keying.frame(&mut self.st, f, c);
        self.took(out, now)
    }

    fn tick(&mut self, now: u64) -> Vec<ClientMessage> {
        let c = GkCtx {
            pins: &mut self.pins,
            now,
        };
        let out = self.keying.tick(&mut self.st, c);
        self.took(out, now)
    }

    /// The head epoch it holds `CK` of.
    pub(super) fn epoch(&self) -> Option<u32> {
        self.keying.current_epoch(CONV).map(|e| e.epoch)
    }
}

/// What a session sends, where session.rs hands a group-key message over.
pub(super) async fn handle(
    state: &Arc<ServerState>,
    sid: UserId,
    tx: &ControlTx,
    send: Vec<ClientMessage>,
) {
    for m in send {
        if tracing_on() {
            let what = format!("{m:?}");
            eprintln!("    {sid} -> {}", &what[..what.len().min(100)]);
        }
        state.gk.handle(state, sid, m, tx).await;
    }
}

/// The keyholder's app on a task of its own: each frame answered as it comes, a tick every
/// 500 ms, whatever the test awaits meanwhile.
pub(super) struct OnTask {
    pub(super) app: Arc<Mutex<App>>,
    pub(super) task: tokio::task::JoinHandle<()>,
    /// Its connection's queue, the frames it has not taken counted in it.
    tx: ControlTx,
    /// From a frame or tick taken until what it sends was handed over.
    busy: Arc<AtomicBool>,
}

impl OnTask {
    fn run(state: Arc<ServerState>, app: App, tx: ControlTx, mut rx: ControlRx) -> OnTask {
        let sid = app.sid;
        let app = Arc::new(Mutex::new(app));
        let busy = Arc::new(AtomicBool::new(false));
        let (a, on, queue) = (app.clone(), busy.clone(), tx.clone());
        let task = tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_millis(500));
            loop {
                let send = tokio::select! {
                    b = rx.recv() => {
                        let Some(b) = b else { return };
                        on.store(true, Ordering::Relaxed);
                        let f = voipc_protocol::codec::decode_server_msg(&b[4..]).unwrap();
                        let now = state.gk.now();
                        a.lock().unwrap().frame(&f, now)
                    }
                    _ = tick.tick() => {
                        on.store(true, Ordering::Relaxed);
                        let now = state.gk.now();
                        a.lock().unwrap().tick(now)
                    }
                };
                handle(&state, sid, &tx, send).await;
                on.store(false, Ordering::Relaxed);
            }
        });
        OnTask {
            app,
            task,
            tx: queue,
            busy,
        }
    }

    /// Nothing queued for it, nothing it took still being handed over.
    fn idle(&self) -> bool {
        !self.busy.load(Ordering::Relaxed) && self.tx.queued_bytes() == 0
    }

    /// The page goes (a reload, a closed tab): its task stops with its connection.
    pub(super) async fn stop(self) -> App {
        self.task.abort();
        let _ = self.task.await;
        let mut app = Arc::try_unwrap(self.app)
            .ok()
            .expect("the task is gone")
            .into_inner()
            .unwrap();
        let _ = app.keying.end();
        app
    }
}

/// Paused time that moves only when the test advances it. A blocking task in flight keeps
/// tokio from jumping a paused clock to the next timer while the runtime waits (on the
/// database, say): a pool's acquire would time out at once, and a store write's real time
/// would be charged to a keyholder's deadline.
struct Gate(Option<std::sync::mpsc::Sender<()>>);

impl Gate {
    fn hold() -> Gate {
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        tokio::task::spawn_blocking(move || {
            let _ = rx.recv();
        });
        Gate(Some(tx))
    }

    /// Real time for what the relay and the keyholder's task have to do before the clock
    /// moves on by `every` ms: a millisecond for each 100 ms of it, one at least
    /// (`World::settle` waits on for what is still under way then).
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

/// A future's output if it is ready at its first poll. The members' queues are drained so,
/// not by a zero timeout: once the clock is paused between two milliseconds (`World::pause`
/// mid-run) that timeout's deadline rounds up to the next tick, which a clock that moves only
/// by `advance` never reaches while the step waits on it.
fn now_or_never<F: std::future::Future>(f: F) -> Option<F::Output> {
    let mut f = std::pin::pin!(tokio::task::unconstrained(f));
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    match std::future::Future::poll(f.as_mut(), &mut cx) {
        std::task::Poll::Ready(v) => Some(v),
        std::task::Poll::Pending => None,
    }
}

/// A member's app, stepped by the test.
pub(super) struct Stepped {
    pub(super) app: App,
    tx: ControlTx,
    rx: ControlRx,
}

/// The relay over `db`, the browser keyholder's app on its task, the members' apps.
pub(super) struct World {
    _gate: Gate,
    /// The clock is paused: steps advance it.
    paused: bool,
    pub(super) state: Arc<ServerState>,
    pub(super) db: Store,
    file: std::path::PathBuf,
    pub(super) keyholder: Option<OnTask>,
    pub(super) members: HashMap<&'static str, Stepped>,
    last_tick: u64,
}

impl Drop for World {
    fn drop(&mut self) {
        drop_db(&self.file);
    }
}

/// A relay with the group key on over `db`.
pub(super) async fn relay(db: &Store) -> Arc<ServerState> {
    let inc = crate::accounts::gk::gk_start(db, true)
        .await
        .unwrap()
        .unwrap();
    let state = Arc::new(ServerState::new(
        &crate::config::ServerConfig {
            group_key: true,
            ..Default::default()
        },
        crate::settings::ServerSettings::default(),
        vec![],
        "test-admin-token".into(),
    ));
    state.gk.attach(db.clone(), inc);
    state
}

/// How long the relay's and the keyholder's work may stay under way, in real time, before a
/// step gives up on it: far past any store write's, so a count that never ends shows.
const BUSY_MAX: Duration = Duration::from_secs(120);

impl World {
    pub(super) async fn new() -> World {
        let _ = tracing_on();
        let gate = Gate::hold();
        let (db, file) = scratch_db().await;
        World {
            _gate: gate,
            paused: false,
            state: relay(&db).await,
            db,
            file,
            keyholder: None,
            members: HashMap::new(),
            last_tick: 0,
        }
    }

    pub(super) fn now(&self) -> u64 {
        self.state.gk.now()
    }

    /// From here on the clock moves only by the steps of `until`.
    pub(super) fn pause(&mut self) {
        tokio::time::pause();
        self.paused = true;
    }

    /// Before the paused clock moves on by `every` ms: real time for the relay's and the
    /// keyholder's work (`Gate::settle`), then, while some of it is still under way (an
    /// actor's turn on a store write, a message in an inbox, a frame the keyholder has not
    /// taken), the clock moves at real time, as a relay's does while its database works.
    /// Moving it by the steps' pace meanwhile made a store write's real time 40 to 100 times
    /// as long on the relay's clock: on Postgres under the other tests' load, a newcomer
    /// whose Join the relay took at once was seated only when that turn ended, 6 to 20
    /// minutes on (J10).
    async fn settle(&self, every: u64) {
        Gate::settle(every).await;
        let start = Instant::now();
        let mut at = start;
        while self.busy() {
            assert!(
                start.elapsed() < BUSY_MAX,
                "the relay's or the keyholder's work stayed under way for {BUSY_MAX:?}"
            );
            Gate::settle(1).await;
            let now = Instant::now();
            tokio::time::advance(now - at).await;
            at = now;
        }
    }

    /// Whether the relay or the keyholder's task has work under way.
    fn busy(&self) -> bool {
        self.state.gk.busy_for_test() || self.keyholder.as_ref().is_some_and(|k| !k.idle())
    }

    /// A connection of `acc` following the channel's group.
    fn session(&self, acc: &Account) -> (UserId, ControlTx, ControlRx) {
        let (_, sid) = crate::state::test_support::add_user(
            &self.state,
            &format!("u{}", rand::random::<u32>()),
        );
        let (tx, rx) = crate::control::control_queue(Arc::default());
        {
            let mut s = self.state.sessions.get_mut(&sid).unwrap();
            s.identity_key = Some([&[0x05u8][..], &raw(&acc.ik)].concat());
            s.control_tx = tx.clone();
            s.account = Some(account_session(acc.a));
        }
        self.state.gk.on_connect(sid, tx.clone());
        self.state
            .gk
            .on_follow(CHAN, CONV, GroupKind::Text, sid, Some(acc.a));
        (sid, tx, rx)
    }

    /// `acc`'s browser page, holding keys, on its task.
    pub(super) async fn browser(&mut self, acc: &Account) {
        let (sid, tx, rx) = self.session(acc);
        let (app, send) = App::new(&self.state, sid, "kay", acc, true, None);
        handle(&self.state, sid, &tx, send).await;
        self.keyholder = Some(OnTask::run(self.state.clone(), app, tx, rx));
    }

    /// `acc`'s desktop app with "Help hold keys" on (its own keyholder pair, 0x03), on the
    /// keyholder's task.
    pub(super) async fn desktop_keyholder(&mut self, acc: &Account) {
        let (sid, tx, rx) = self.session(acc);
        let (app, send) = App::with(&self.state, sid, "dex", acc, Platform::Desktop, true, None);
        handle(&self.state, sid, &tx, send).await;
        self.keyholder = Some(OnTask::run(self.state.clone(), app, tx, rx));
    }

    /// The keyholder's app goes for good: its task stops with its connection.
    pub(super) async fn keyholder_goes(&mut self) {
        let old = self.keyholder.take().expect("a keyholder").stop().await;
        self.state.gk.on_session_end(old.sid);
    }

    /// The browser page reloads: its connection ends, and the page comes back on a new one.
    pub(super) async fn reload(&mut self, acc: &Account) {
        let old = self.keyholder.take().expect("a page").stop().await;
        self.state.gk.on_session_end(old.sid);
        self.browser(acc).await;
    }

    /// `acc`'s desktop app, holding no keys, stepped by the test.
    pub(super) async fn member(
        &mut self,
        name: &'static str,
        acc: &Account,
        local: Option<LocalGk>,
    ) {
        let (sid, tx, rx) = self.session(acc);
        let (app, send) = App::new(&self.state, sid, name, acc, false, local);
        handle(&self.state, sid, &tx, send).await;
        self.members.insert(name, Stepped { app, tx, rx });
    }

    /// One round: each member's frames taken, a tick each second, what it sends handed over.
    async fn step(&mut self) {
        let now = self.now();
        let tick = now >= self.last_tick + 1_000;
        for m in self.members.values_mut() {
            let mut frames = vec![];
            while let Some(Some(b)) = now_or_never(m.rx.recv()) {
                frames.push(voipc_protocol::codec::decode_server_msg(&b[4..]).unwrap());
            }
            let mut send = vec![];
            for f in &frames {
                send.extend(m.app.frame(f, now));
            }
            if tick {
                send.extend(m.app.tick(now));
            }
            handle(&self.state, m.app.sid, &m.tx, send).await;
        }
        if tick {
            self.last_tick = now;
        }
        // A keyholder that panicked fails the test with its own message
        if self
            .keyholder
            .as_ref()
            .is_some_and(|k| k.task.is_finished())
        {
            let k = self.keyholder.take().unwrap();
            if let Err(e) = k.task.await {
                if e.is_panic() {
                    std::panic::resume_unwind(e.into_panic());
                }
            }
        }
    }

    /// Runs in steps of `every` ms until `done`, at most `ms`: how long it took, if it was.
    pub(super) async fn until(
        &mut self,
        ms: u64,
        every: u64,
        done: impl Fn(&World) -> bool,
    ) -> Option<u64> {
        let start = self.now();
        while self.now() < start + ms {
            if self.paused {
                self.settle(every).await;
                tokio::time::advance(Duration::from_millis(every)).await;
            } else {
                tokio::time::sleep(Duration::from_millis(every)).await;
            }
            self.step().await;
            if done(self) {
                return Some(self.now() - start);
            }
        }
        None
    }

    pub(super) fn epoch(&self, name: &str) -> Option<u32> {
        self.members[name].app.epoch()
    }

    pub(super) fn keyholder_epoch(&self) -> Option<u32> {
        let k = self.keyholder.as_ref()?;
        let app = k.app.lock().unwrap();
        app.epoch()
    }

    pub(super) fn load(&self) -> Option<GroupLoad> {
        self.state
            .gk
            .stats()
            .into_iter()
            .find(|g| g.channel_id == CHAN)
    }

    /// The group starts with the browser keyholder and member ann; newcomer nan is seated
    /// by a Join (the control: the browser holds the keys).
    pub(super) async fn started(&mut self, kay: &Account, ann: &Account, nan: &Account) {
        self.browser(kay).await;
        self.member("ann", ann, None).await;
        let keyed = self
            .until(30_000, 10, |w| {
                w.epoch("ann").is_some() && w.keyholder_epoch().is_some()
            })
            .await;
        assert!(keyed.is_some(), "the group started: {:?}", self.load());
        let l = self.load().unwrap();
        assert_eq!(
            (l.keyholders, l.keyholders_online),
            (1, 1),
            "the browser alone holds the keys"
        );
        self.member("nan", nan, None).await;
        let seated = self.until(30_000, 10, |w| w.epoch("nan").is_some()).await;
        assert!(
            seated.is_some(),
            "the control: a newcomer is seated while the browser keyholder is online: {:?}",
            self.load()
        );
    }

    /// Newcomer neo comes in; how long its seat takes, watched past the 1 h Regenesis.
    async fn newcomer_waits(&mut self, neo: &Account) -> Option<u64> {
        self.newcomer_waits_as("neo", neo, SEATED_AT_ONCE_MS).await
    }

    /// Newcomer `name` comes in; how long its seat takes: watched closely for `close` ms,
    /// then past the 1 h Regenesis.
    pub(super) async fn newcomer_waits_as(
        &mut self,
        name: &'static str,
        acc: &Account,
        close: u64,
    ) -> Option<u64> {
        self.member(name, acc, None).await;
        if let Some(t) = self.until(close, 50, |w| w.epoch(name).is_some()).await {
            return Some(t);
        }
        // Watched on in coarser steps: the apps tick each second still
        self.until(WATCH_MS - close, 500, |w| w.epoch(name).is_some())
            .await
            .map(|t| t + close)
    }
}

pub(super) fn minutes(t: Option<u64>) -> String {
    t.map_or_else(
        || format!("not within {} min", WATCH_MS / 60_000),
        |t| format!("{:.1} min", t as f64 / 60_000.0),
    )
}

/// Dive 2, lead (a): a stored text channel whose only keyholder is an account's browser
/// page. The page reloads. Its old entry names the old connection's pair (0x02), which is
/// gone for good, and it is the set's last entry, so nothing removes it (holders.rs
/// `removal_where`: never the last entry, and only one another online entry can sign); the
/// page on its new connection volunteers, but promoting it is a KeyholdersAdd only an entry of
/// the set can sign. Before "Fast new start" (owner 2026-11-19) the relay waited
/// `REGENESIS_AFTER_MS` (1 h) before it asked a Regenesis, and members held a Regenesis to
/// that hour: a newcomer waited about an hour for its seat (J8H measured 60.1 min); from then
/// to J10-B's option A (owner 2026-11-22), 2 minutes. A set of connection entries alone, none
/// online, now starts anew at once (`rules::regenesis_wait`): the page on its new connection
/// makes the Regenesis, holds the keys from then on, and the newcomer is seated within
/// `SEATED_AT_ONCE_MS`.
#[tokio::test]
async fn e2e_j8h_a_newcomer_is_seated_soon_after_the_sole_browser_keyholder_reloads() {
    let mut w = World::new().await;
    let kay = Account::new(&w.db, "kay").await;
    let ann = Account::new(&w.db, "ann").await;
    let nan = Account::new(&w.db, "nan").await;
    let neo = Account::new(&w.db, "neo").await;
    w.started(&kay, &ann, &nan).await;

    w.reload(&kay).await;
    // The page is back on its account's seat; its old entry is offline
    let back = w.until(30_000, 10, |w| w.keyholder_epoch().is_some()).await;
    assert!(back.is_some(), "the page holds the head again");
    let l = w.load().unwrap();
    assert_eq!(
        (l.keyholders, l.keyholders_online),
        (1, 0),
        "the old entry stays, offline"
    );

    w.pause();
    let waited = w.newcomer_waits(&neo).await;
    assert!(
        waited.is_some_and(|t| t <= SEATED_AT_ONCE_MS),
        "the newcomer was seated after {} (within {} s wanted); load {:?}",
        minutes(waited),
        SEATED_AT_ONCE_MS / 1000,
        w.load()
    );
    // The page on its new connection started anew and holds the keys: the old entry is gone
    let l = w.load().unwrap();
    assert_eq!(
        (l.keyholders, l.keyholders_online),
        (1, 1),
        "the new page's entry alone, online"
    );
}

/// Dive 2, lead (b): the same channel across a relay restart (or self-update). The relay
/// loads the set from the database with the browser's entry offline (store.rs `load`); the
/// page comes back on a new connection with a new pair, and nothing online can sign its
/// promotion or the old entry's removal. Before "Fast new start" a newcomer waited for the
/// 1 h Regenesis, as after a reload: every browser-only stored channel stalled its joins and
/// exits for an hour after each restart (2 minutes from "Fast new start" to J10-B's option A).
/// Now it is seated at once, the page on its new connection the keyholder.
#[tokio::test]
async fn e2e_j8h_a_newcomer_is_seated_soon_after_a_relay_restart_of_a_browser_held_channel() {
    let mut w = World::new().await;
    let kay = Account::new(&w.db, "kay").await;
    let ann = Account::new(&w.db, "ann").await;
    let nan = Account::new(&w.db, "nan").await;
    let neo = Account::new(&w.db, "neo").await;
    w.started(&kay, &ann, &nan).await;

    // The relay stops: every connection ends with it, each desktop keeps its local floor
    w.keyholder.take().expect("a page").stop().await;
    let mut locals = HashMap::new();
    for (name, m) in w.members.drain() {
        let mut app = m.app;
        let _ = app.keying.end();
        locals.insert(name, app.keying.local().cloned());
    }
    w.state.gk.on_purge(CONV);

    // It starts again over the same database
    w.state = relay(&w.db).await;
    w.browser(&kay).await;
    w.member("ann", &ann, locals.remove("ann").flatten()).await;
    w.member("nan", &nan, locals.remove("nan").flatten()).await;
    let back = w
        .until(30_000, 10, |w| {
            w.keyholder_epoch().is_some() && w.epoch("ann").is_some() && w.epoch("nan").is_some()
        })
        .await;
    assert!(
        back.is_some(),
        "everyone holds the head again: {:?}",
        w.load()
    );
    let l = w.load().unwrap();
    assert_eq!(
        (l.keyholders, l.keyholders_online),
        (1, 0),
        "the old entry, loaded, offline"
    );

    w.pause();
    let waited = w.newcomer_waits(&neo).await;
    assert!(
        waited.is_some_and(|t| t <= SEATED_AT_ONCE_MS),
        "the newcomer was seated after {} (within {} s wanted); load {:?}",
        minutes(waited),
        SEATED_AT_ONCE_MS / 1000,
        w.load()
    );
    // The page on its new connection started anew and holds the keys: the old entry is gone
    let l = w.load().unwrap();
    assert_eq!(
        (l.keyholders, l.keyholders_online),
        (1, 1),
        "the new page's entry alone, online"
    );
}

/// The control of the two above, on the same harness: while the browser keyholder stays,
/// a newcomer two minutes on is seated at once by a Join. Its set stays the one entry, online;
/// nothing waits, and nothing starts anew: a set with an entry online is never replaced by a
/// Regenesis, however fast one may come once none is.
#[tokio::test]
async fn e2e_j8h_a_newcomer_is_seated_at_once_while_the_sole_browser_keyholder_stays() {
    let mut w = World::new().await;
    let kay = Account::new(&w.db, "kay").await;
    let ann = Account::new(&w.db, "ann").await;
    let nan = Account::new(&w.db, "nan").await;
    let neo = Account::new(&w.db, "neo").await;
    w.started(&kay, &ann, &nan).await;
    w.pause();
    w.until(2 * 60_000, 50, |_| false).await;
    let waited = w.newcomer_waits(&neo).await;
    assert!(
        waited.is_some_and(|t| t <= SEATED_WITHIN_MS),
        "seated after {}; load {:?}",
        minutes(waited),
        w.load()
    );
    let l = w.load().unwrap();
    assert_eq!(
        (l.keyholders, l.keyholders_online, l.joins_waiting),
        (1, 1, 0)
    );
    for m in ["ann", "nan", "neo"] {
        let anew = w.members[m]
            .app
            .events
            .iter()
            .any(|e| matches!(e, GkEvent::Anew { .. }));
        assert!(!anew, "{m} was never told the keys were made anew");
    }
}

/// The harness itself (J10): a store write that takes real time, as Postgres can under the
/// other tests' load, costs the paused clock that real time, as it costs a relay's, not the
/// steps' pace. Before, each 50 ms step left the relay a millisecond of real time whether its
/// turn had ended or not: a 3 s write moved the relay's clock about two minutes, and the
/// newcomer whose Join it was storing waited all of it (J8H's and J9N's newcomers were seated
/// 6 to 20 minutes on, 1 run in 3 or more on Postgres).
#[tokio::test]
async fn e2e_j8h_a_slow_store_write_costs_the_paused_clock_only_its_real_time() {
    const STALL_MS: u64 = 3_000;
    let mut w = World::new().await;
    let kay = Account::new(&w.db, "kay").await;
    let ann = Account::new(&w.db, "ann").await;
    let nan = Account::new(&w.db, "nan").await;
    let neo = Account::new(&w.db, "neo").await;
    w.started(&kay, &ann, &nan).await;
    w.pause();
    // The next commit is neo's Join (its batch closes 2 s on; the head epoch is fresh)
    let seen = w.state.gk.stall_next_commit_for_test(STALL_MS);
    let waited = w.newcomer_waits_as("neo", &neo, SEATED_AT_ONCE_MS).await;
    let (from, to, real) = seen.lock().unwrap().expect("a commit was stalled");
    let moved = Duration::from_millis(to - from);
    assert!(
        moved <= real + Duration::from_millis(500),
        "the relay's clock moved {moved:?} while its store write took {real:?}"
    );
    assert!(
        waited.is_some_and(|t| t <= STALL_MS + 30_000),
        "the newcomer was seated after {}; load {:?}",
        minutes(waited),
        w.load()
    );
}
