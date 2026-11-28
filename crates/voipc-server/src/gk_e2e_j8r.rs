//! End-to-end group-key scenarios added by fix-round slice J8R (2026-11-19). The relay's real
//! `gk` code driven by the clients' real `voipc_crypto::group_state` code; shared helpers live in
//! `gk_e2e_tests.rs`.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use voipc_crypto::group_key::timers::ACTOR_IDLE_MS;
use voipc_crypto::group_key::{Endorsement, GroupKind, MemberId, Origin, SeatKeys};
use voipc_crypto::group_state::{
    GkCtx, GkOut, GkStart, GkTrack, GroupKeying, MemoryPins, Platform, VaultFloor,
};
use voipc_crypto::{IdentityKeyPair, SignalStores};
use voipc_protocol::gk::{refused_what, refused_why};
use voipc_protocol::messages::{ClientMessage, ServerMessage};
use voipc_protocol::types::UserId;

use super::gk_e2e_tests::{drop_db, scratch_db, show, tracing_on, Holder, Member, Relay, CHANNEL};
use crate::gk::group::cause;

fn wall_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// An account with its identity and published seat keys (counter 1), as `gk_e2e_tests` makes
/// one.
struct Account {
    a: [u8; 16],
    ik: IdentityKeyPair,
    keys: SeatKeys,
}

impl Account {
    async fn new(db: &l4f_accounts::store::Store, name: &str) -> Account {
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

async fn count(db: &l4f_accounts::store::Store, q: &str) -> i64 {
    let q = q.to_string();
    match db {
        l4f_accounts::store::Store::Lite(b) => sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(q))
            .fetch_one(&b.0)
            .await
            .unwrap(),
        l4f_accounts::store::Store::Pg(b) => sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(q))
            .fetch_one(&b.0)
            .await
            .unwrap(),
    }
}

/// A keyholder and members over one relay, each round's frames handed to them.
struct Lounge {
    relay: Relay,
    holder: Holder,
    members: Vec<Member>,
    last_tick: u64,
}

impl Lounge {
    async fn step(&mut self) {
        let now = self.relay.groups.now();
        let sid = self.holder.sid;
        let frames = self.relay.drain(sid).await;
        let mut send = vec![];
        for f in &frames {
            if tracing_on() {
                eprintln!("[{now}] holder {sid} <- {}", show(f));
            }
            send.extend(self.holder.frame(f, now));
        }
        for m in send {
            self.relay.send(sid, m).await;
        }
        let tick = now >= self.last_tick + 1_000;
        for i in 0..self.members.len() {
            let sid = self.members[i].sid;
            let frames = self.relay.drain(sid).await;
            let mut send = vec![];
            for f in &frames {
                if tracing_on() {
                    eprintln!("[{now}] member {sid} <- {}", show(f));
                }
                send.extend(self.members[i].frame(f, now));
            }
            if tick {
                send.extend(self.members[i].tick(now));
            }
            for m in send {
                self.relay.send(sid, m).await;
            }
        }
        if tick {
            self.last_tick = now;
        }
    }

    /// Runs until every member holds an epoch's key, at most `ms`.
    async fn seated(&mut self, ms: u64) -> bool {
        let end = self.relay.groups.now() + ms;
        while self.relay.groups.now() < end {
            tokio::time::sleep(Duration::from_millis(10)).await;
            self.step().await;
            if self.members.iter().all(|m| m.epoch().is_some()) {
                return true;
            }
        }
        false
    }
}

/// Actors here stop after this much idle, not 10 minutes.
const IDLE_MS: u64 = 300;

/// Stored group `c:lounge`: a guest keyholder and account ann, seated. Actors stop after
/// `IDLE_MS`.
async fn lounge() -> (
    Lounge,
    Account,
    l4f_accounts::store::Store,
    std::path::PathBuf,
    String,
) {
    let (db, file) = scratch_db().await;
    let inc = crate::accounts::gk::gk_start(&db, true)
        .await
        .unwrap()
        .unwrap();
    let ann = Account::new(&db, "ann").await;
    let mut relay = Relay::new();
    relay.groups.attach(db.clone(), inc);
    relay.groups.idle_ms_for_test(IDLE_MS);
    let id = relay.groups.id_for(CHANNEL, Some("lounge"));
    let ik = voipc_crypto::generate_identity_key_pair();
    let hsid = relay.session(&ik, None);
    relay.follow(hsid, &id);
    let holder = Holder::guest(hsid, ik, &id, true);
    relay.send(hsid, holder.volunteer()).await;
    let asid = relay.session(&ann.ik, Some(ann.a));
    let mut m = Member::new(
        &relay,
        asid,
        ann.ik,
        Some(ann.a),
        Some(ann.keys()),
        None,
        &id,
    );
    relay.follow(asid, &id);
    for msg in m.track() {
        relay.send(asid, msg).await;
    }
    let mut w = Lounge {
        relay,
        holder,
        members: vec![m],
        last_tick: 0,
    };
    assert!(
        w.seated(15_000).await,
        "ann is seated; events {:?}",
        w.members[0].events
    );
    (w, ann, db, file, id)
}

/// Rows of exits group `id` keeps for `cause`.
async fn exits(db: &l4f_accounts::store::Store, id: &str, why: u8) -> i64 {
    count(
        db,
        &format!("SELECT COUNT(*) FROM voipc_gk_exits WHERE grp = '{id}' AND cause = {why}"),
    )
    .await
}

/// Waits up to 5 s for ann's `LEAVE` exit in `c:lounge`'s rows.
async fn exit_kept(db: &l4f_accounts::store::Store, id: &str) -> bool {
    for _ in 0..100 {
        if exits(db, id, cause::LEAVE).await > 0 {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

/// Item 1 (a): a group's actor, idle, runs a last turn before it stops; a Follow sent into its
/// inbox meanwhile was taken (`post` said yes) and dropped with the inbox, so the follower's
/// fetch found no group (`NOT_MEMBER`) and it never read there.
#[tokio::test(start_paused = true)]
async fn j8r_a_follow_that_reaches_an_idle_actor_in_its_last_turn_is_not_lost() {
    let mut relay = Relay::new();
    let id = relay.groups.id_for(CHANNEL, None);
    let ik = voipc_crypto::generate_identity_key_pair();
    let a = relay.session(&ik, None);
    relay.follow(a, &id);
    tokio::time::sleep(Duration::from_millis(50)).await;
    relay.unfollow(a, &id);
    let (reached, go) = relay.groups.gate_idle_stop_for_test();
    tokio::time::timeout(
        Duration::from_millis(ACTOR_IDLE_MS + 60_000),
        reached.notified(),
    )
    .await
    .expect("the idle actor comes to its stop");
    // Bob follows while that last turn runs
    let ik_b = voipc_crypto::generate_identity_key_pair();
    let b = relay.session(&ik_b, None);
    let mut m = Member::new(&relay, b, ik_b, None, None, None, &id);
    relay.follow(b, &id);
    go.notify_one();
    tokio::time::sleep(Duration::from_millis(50)).await;
    for msg in m.track() {
        relay.send(b, msg).await;
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    let frames = relay.drain(b).await;
    let shown: Vec<String> = frames.iter().map(show).collect();
    assert!(
        !frames.iter().any(|f| matches!(
            f,
            ServerMessage::EpochRefused { what, why, .. }
                if *what == refused_what::FETCH && *why == refused_why::NOT_MEMBER
        )),
        "the group knows bob follows: {shown:?}"
    );
    assert!(
        frames
            .iter()
            .any(|f| matches!(f, ServerMessage::EpochWait { .. })),
        "his fetch waits for a keyholder: {shown:?}"
    );
    assert!(relay.groups.get(&id).is_some(), "the group runs on");
}

/// Item 1 (a), the one that matters: an account taken out of a stored conversation's log
/// while its group's idle actor runs its last turn. The `AccountExit` was taken into that
/// inbox and dropped with it, so the account kept its seat (and every key a later commit
/// gave it) until a Regenesis or 90 days unused.
#[tokio::test]
async fn j8r_an_account_exit_sent_in_an_idle_actors_last_turn_lands() {
    let (w, ann, db, file, id) = lounge().await;
    let (reached, go) = w.relay.groups.gate_idle_stop_for_test();
    w.relay.groups.on_session_end(w.holder.sid);
    w.relay.groups.on_session_end(w.members[0].sid);
    tokio::time::timeout(Duration::from_secs(10), reached.notified())
        .await
        .expect("the idle actor comes to its stop");
    assert_eq!(exits(&db, &id, cause::LEAVE).await, 0);
    w.relay
        .groups
        .on_log_leave("lounge", ann.a, cause::LEAVE)
        .await;
    go.notify_one();
    let kept = exit_kept(&db, &id).await;
    drop_db(&file);
    assert!(
        kept,
        "ann's seat exits, her exit kept for the next keyholder"
    );
}

/// Item 1 (b): the hook found the group's actor (`live`) and posted to it a moment later; the
/// actor stopped in between, so the post found no group and the `AccountExit` went nowhere.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn j8r_an_account_exit_whose_actor_stopped_after_the_lookup_lands() {
    let (w, ann, db, file, id) = lounge().await;
    let (reached, go) = w.relay.groups.gate_idle_stop_for_test();
    w.relay.groups.on_session_end(w.holder.sid);
    w.relay.groups.on_session_end(w.members[0].sid);
    tokio::time::timeout(Duration::from_secs(10), reached.notified())
        .await
        .expect("the idle actor comes to its stop");
    w.relay.groups.stop_between_for_test(go);
    w.relay
        .groups
        .on_log_leave("lounge", ann.a, cause::LEAVE)
        .await;
    let kept = exit_kept(&db, &id).await;
    drop_db(&file);
    assert!(
        kept,
        "ann's seat exits, her exit kept for the next keyholder"
    );
}

// ── Item 2: a promotion that takes an exit batch ──────────────────────────

/// A guest's desktop app as it runs: one `GroupKeying` that reads, writes and, with "Help
/// hold keys" on, holds keys (holder.rs, the app's own keyholder), its build jobs run whole.
struct Desk {
    sid: UserId,
    keying: GroupKeying,
    st: SignalStores,
    pins: MemoryPins,
    group: String,
    sent: Vec<ClientMessage>,
    /// Frames to it wait in its queue while set (a slow link).
    hold: bool,
    gone: bool,
}

impl Desk {
    fn took(&mut self, out: GkOut, now: u64) -> Vec<ClientMessage> {
        let mut send = out.send;
        while let Some(mut job) = self.keying.take_build() {
            let b = loop {
                if let Some(b) = job.step(Duration::from_millis(50)) {
                    break b;
                }
            };
            let c = GkCtx {
                pins: &mut self.pins,
                now,
            };
            send.extend(self.keying.built(b, c).send);
        }
        while let Some(m) = self.keying.next_frame(now, false) {
            send.push(m);
        }
        self.sent.extend(send.iter().cloned());
        send
    }

    fn epoch(&self) -> Option<u32> {
        self.keying.current_epoch(&self.group).map(|e| e.epoch)
    }

    /// The `EpochDecline`s it sent: (why, detail).
    fn declines(&self) -> Vec<(u8, String)> {
        self.sent
            .iter()
            .filter_map(|m| match m {
                ClientMessage::EpochDecline { why, detail, .. } => Some((*why, detail.clone())),
                _ => None,
            })
            .collect()
    }
}

struct Desks {
    relay: Relay,
    desks: Vec<Desk>,
    last_tick: u64,
}

impl Desks {
    fn now(&self) -> u64 {
        self.relay.groups.now()
    }

    /// A guest's desktop app following `group`, holding keys when `holds`.
    async fn desk(&mut self, group: &str, holds: bool) -> usize {
        let ik = voipc_crypto::generate_identity_key_pair();
        let sid = self.relay.session(&ik, None);
        self.relay.follow(sid, group);
        let now = self.now();
        let mut d = Desk {
            sid,
            keying: GroupKeying::default(),
            st: SignalStores::new(&ik, sid),
            pins: MemoryPins::default(),
            group: group.to_string(),
            sent: vec![],
            hold: false,
            gone: false,
        };
        let out = d.keying.start(GkStart {
            on: true,
            run: self.relay.groups.run,
            relay_clock: now / 1000,
            platform: Platform::Desktop,
            help_hold_keys: holds,
            user_id: sid,
            identity: ik,
            account: None,
            seat_keys: None,
            local: None,
            visible: true,
        });
        let mut send = d.took(out, now);
        let out = d.keying.track(
            GkTrack {
                channel_id: CHANNEL,
                group: group.to_string(),
                kind: GroupKind::Text,
                anonymous: false,
                hide_members: false,
                viewer_admin: false,
                keeps_history: false,
            },
            VaultFloor::None,
        );
        send.extend(d.took(out, now));
        for msg in send {
            self.relay.send(sid, msg).await;
        }
        self.desks.push(d);
        self.desks.len() - 1
    }

    /// "Help hold keys" switched on in desk `i`.
    async fn volunteer(&mut self, i: usize) {
        let now = self.now();
        let out = self.desks[i].keying.set_volunteer(true);
        let sid = self.desks[i].sid;
        for msg in self.desks[i].took(out, now) {
            self.relay.send(sid, msg).await;
        }
    }

    /// Desk `i`'s connection ends.
    fn end(&mut self, i: usize) {
        self.relay.groups.on_session_end(self.desks[i].sid);
        self.desks[i].gone = true;
    }

    async fn step(&mut self) {
        let now = self.now();
        let tick = now >= self.last_tick + 1_000;
        for i in 0..self.desks.len() {
            if self.desks[i].hold || self.desks[i].gone {
                continue;
            }
            let sid = self.desks[i].sid;
            let frames = self.relay.drain(sid).await;
            let mut send = vec![];
            for f in &frames {
                if tracing_on() {
                    eprintln!("[{now}] desk {sid} <- {}", show(f));
                }
                let d = &mut self.desks[i];
                let c = GkCtx {
                    pins: &mut d.pins,
                    now,
                };
                let out = d.keying.frame(&mut d.st, f, c);
                send.extend(d.took(out, now));
            }
            if tick {
                let d = &mut self.desks[i];
                let c = GkCtx {
                    pins: &mut d.pins,
                    now,
                };
                let out = d.keying.tick(&mut d.st, c);
                send.extend(d.took(out, now));
            }
            for msg in send {
                if tracing_on() {
                    eprintln!(
                        "[{now}] desk {sid} -> {}",
                        format!("{msg:?}").chars().take(100).collect::<String>()
                    );
                }
                self.relay.send(sid, msg).await;
            }
        }
        if tick {
            self.last_tick = now;
        }
    }

    async fn until(&mut self, ms: u64, done: impl Fn(&Desks) -> bool) -> bool {
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

    async fn run(&mut self, ms: u64) {
        self.until(ms, |_| false).await;
    }
}

/// Item 2, found by J8R, fixed by J8H (community lane, key on: newcomer gina never seated in
/// lobby-chat; the same defect as T1e C). A promotion
/// due that an exit batch closed behind is asked again with the batch merged (plan 2d,
/// "exits never wait behind a 60 s due"); the exits empty a bucket, which the KeyholdersAdd
/// drops. The keyholder's own check (holder.rs `Task::check`, validate rule 8,
/// group_key/commit.rs) reads a bucket's seats only from the lists the build asked, and
/// `lists_needed` asks none for a dropped bucket: so it finds the drop names no exit, refuses
/// its own commit and declines (`NOT_READY`, "own check: rule 8: a KeyholdersAdd drops only
/// buckets its exits empty"). The relay asks the same promotion every 30 s (all online
/// keyholders passed over), and a Promote outranks a Join: no newcomer was seated again.
/// `lists_needed` now asks the list of each bucket an opening drops, taken only when the
/// keyring names it.
#[tokio::test(start_paused = true)]
async fn j8r_a_promotion_that_takes_an_exit_batch_commits_and_a_newcomer_is_seated() {
    let mut w = Desks {
        relay: Relay::new(),
        desks: vec![],
        last_tick: 0,
    };
    let id = w.relay.groups.id_for(CHANNEL, None);
    let ann = w.desk(&id, true).await;
    assert!(
        w.until(15_000, |w| w.desks[ann].epoch().is_some()).await,
        "ann starts the group"
    );
    // Each Join makes buckets of its own (§5.3): g's holds g alone
    let g = w.desk(&id, false).await;
    assert!(w.until(15_000, |w| w.desks[g].epoch().is_some()).await);
    let bob = w.desk(&id, false).await;
    assert!(w.until(15_000, |w| w.desks[bob].epoch().is_some()).await);
    w.run(3_000).await;
    let before = w.desks[ann].epoch();
    // Bob offers to hold keys: the promotion goes to ann, whose link is slow; g leaves at once,
    // and its exit batch closes behind the promotion while she still has it in hand
    w.desks[ann].hold = true;
    w.volunteer(bob).await;
    w.end(g);
    w.run(1_000).await;
    w.desks[ann].hold = false;
    let promoted = w
        .until(20_000, |w| {
            w.desks[bob].epoch() > before && w.desks[ann].epoch() == w.desks[bob].epoch()
        })
        .await;
    let dan = w.desk(&id, false).await;
    let seated = w.until(90_000, |w| w.desks[dan].epoch().is_some()).await;
    assert_eq!(
        w.desks[ann].declines(),
        vec![],
        "ann builds the promotion with the exits"
    );
    assert!(promoted, "the promotion lands, bob reads its epoch");
    assert!(seated, "the newcomer is seated within 90 s");
}

// ── Dive 4 round 2, item 1 (d4-r2-plan.md) ────────────────────────────────

/// The relay's real actor, stopped for good: ann's account leaves the log while the group's
/// idle actor is in its last turn (held at its gate), so the hook's exit goes into an inbox
/// nothing reads again, as a crash leaves it. Nothing in the database told her seat from a
/// live follower's then: a new relay over the same database kept her seated. The hook asked
/// the exit in the store first: the new relay's start enters it, writes it, and the ask goes.
#[tokio::test]
async fn j8r_d4r2_a_log_leave_cut_off_by_a_stop_exits_at_the_next_start() {
    let (w, ann, db, file, id) = lounge().await;
    let (reached, _go) = w.relay.groups.gate_idle_stop_for_test();
    w.relay.groups.on_session_end(w.holder.sid);
    w.relay.groups.on_session_end(w.members[0].sid);
    tokio::time::timeout(Duration::from_secs(10), reached.notified())
        .await
        .expect("the idle actor comes to its stop");
    w.relay
        .groups
        .on_log_leave("lounge", ann.a, cause::LEAVE)
        .await;
    // The relay stops there; another starts over the same database and someone follows
    let inc = crate::accounts::gk::gk_incarnation(&db)
        .await
        .unwrap()
        .unwrap();
    let mut again = Relay::new();
    again.groups.attach(db.clone(), inc);
    again.groups.idle_ms_for_test(IDLE_MS);
    let ik = voipc_crypto::generate_identity_key_pair();
    let sid = again.session(&ik, None);
    again.follow(sid, &id);
    let kept = exit_kept(&db, &id).await;
    let mut left = vec![];
    for _ in 0..100 {
        left = crate::accounts::gk::exit_asks(&db, &id).await.unwrap();
        if left.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    drop_db(&file);
    assert!(
        kept && left.is_empty(),
        "after the restart ann's exit is kept: {kept}; asks left: {left:?}"
    );
}
