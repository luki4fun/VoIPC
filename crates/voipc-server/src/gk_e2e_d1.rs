//! Dive 1 (a hostile relay against everything a member accepts), end to end: the relay's
//! real `gk` code, the apps' real `voipc_crypto::group_state` code, and a keyholder that is
//! the app's own duty (an account's desktop with "Help hold keys" on), as `gk_e2e_c3c.rs`
//! runs one. The shared helpers are `gk_e2e_tests.rs`'s (`Relay`, `Member`).
//!
//! A gated channel's gate turned off and on again, while a writer's app is away. Whoever is
//! seated while the gate is off is named in no header (an open group's `added` is a count),
//! the opening that turns the gate back on names nobody, and `names_hash` starts over at
//! that opening. What the spec sets against this is §4.4 rule 6: "A device with a floor
//! reports a change from gated to open." A member reports it only when it takes the opening
//! that turned the gate off as a header of its own. One that takes a later, gated head by a
//! walk (as every member that is no keyholder does on a fetch) reports nothing, and does
//! not learn that the gated period it folds in began anew.
//!
//! - F5, under the honest relay: that writer's fold never reaches the head, and every post
//!   of hers in the channel is held for a minute and given up.
//! - F4, under a hostile relay: the relay answers her names ask with the lists of the
//!   current gated period only (each one it holds, unchanged). Her fold passes, the account
//!   seated while the gate was off reads what she writes, and her app says nothing. The
//!   relay forges nothing: every due it sends the keyholder is one the honest relay sends.
//!
//! Run (in the worktree):
//! `TMPDIR=$PWD/target/tmp flock /home/luki/unfug/voipc/target/heavy.lock cargo test -p voipc-server --bin voipc-server gk_e2e_d1`

use std::time::Duration;

use voipc_crypto::group_key::{Endorsement, GroupKind, MemberId, Origin, SeatKeys};
use voipc_crypto::group_state::{
    GkCtx, GkEvent, GkOut, GkStart, GkTrack, GroupKeying, LocalGk, MemoryPins, Platform,
    VaultFloor, Warn,
};
use voipc_crypto::{IdentityKeyPair, SignalStores};
use voipc_protocol::messages::{ClientMessage, ServerMessage};
use voipc_protocol::types::UserId;

use super::gk_e2e_tests::{drop_db, scratch_db, show, tracing_on, Relay, CHANNEL};

fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// An account with its identity and published seat keys (counter 1), as `gk_e2e_tests.rs`
/// makes one.
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

/// An account's desktop app on one connection: its `GroupKeying` as the host runs it. With
/// `holds`, "Help hold keys" is on: its duty volunteers, takes each due, builds off the lock
/// and paces its commit out, as the native app runs it. What it hands back for the account's
/// vault (`GkOut::self_rows`) is kept for the test to store, as the host sends `SelfRowPut`.
struct App {
    sid: UserId,
    account: [u8; 16],
    keying: GroupKeying,
    st: SignalStores,
    pins: MemoryPins,
    group: String,
    events: Vec<GkEvent>,
    texts: Vec<Vec<u8>>,
    self_rows: Vec<voipc_protocol::gk::SelfRowIn>,
    /// Its connection ended: nothing reaches it any more.
    gone: bool,
    /// The relay answers its `EpochNames` with the lists from this epoch on only: the ones it
    /// kept of the gated period the head is in, and none of an earlier one.
    names_from: Option<u32>,
    /// Each names answer it took: the place of every list in it.
    names_got: Vec<Vec<(u32, u32)>>,
}

impl App {
    fn new(
        relay: &Relay,
        sid: UserId,
        acc: &Account,
        group: &str,
        holds: bool,
        local: Option<LocalGk>,
    ) -> (App, Vec<ClientMessage>) {
        let mut k = App {
            sid,
            account: acc.a,
            keying: GroupKeying::default(),
            st: SignalStores::new(&acc.ik, sid),
            pins: MemoryPins::default(),
            group: group.to_string(),
            events: vec![],
            texts: vec![],
            self_rows: vec![],
            gone: false,
            names_from: None,
            names_got: vec![],
        };
        let now = relay.groups.now();
        let out = k.keying.start(GkStart {
            on: true,
            run: relay.groups.run,
            relay_clock: now / 1000,
            platform: Platform::Desktop,
            help_hold_keys: holds,
            user_id: sid,
            identity: acc.ik,
            account: Some(acc.a),
            seat_keys: Some(acc.keys()),
            local,
            visible: true,
        });
        let mut send = k.took(out, now);
        let out = k.keying.track(
            GkTrack {
                channel_id: CHANNEL,
                group: group.to_string(),
                kind: GroupKind::Text,
                anonymous: false,
                hide_members: false,
                viewer_admin: false,
                keeps_history: group.starts_with("c:"),
            },
            VaultFloor::None,
        );
        send.extend(k.took(out, now));
        (k, send)
    }

    fn took(&mut self, out: GkOut, now: u64) -> Vec<ClientMessage> {
        let mut outs = vec![out];
        let mut send = vec![];
        while let Some(out) = outs.pop() {
            self.events.extend(out.events);
            self.texts.extend(out.posts.into_iter().map(|p| p.envelope));
            self.self_rows.extend(out.self_rows);
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

    fn post(&mut self, id: u8, text: &[u8], now: u64) -> Vec<ClientMessage> {
        let c = GkCtx {
            pins: &mut self.pins,
            now,
        };
        let out = self.keying.post(&mut self.st, CHANNEL, [id; 16], text, c);
        self.took(out, now)
    }

    /// The head epoch it holds `CK` of.
    fn epoch(&self) -> Option<u32> {
        self.keying.current_epoch(&self.group).map(|e| e.epoch)
    }

    /// The head it stands on: `(epoch, join, gated)`.
    fn head(&self) -> Option<(u32, u32, bool)> {
        let f = &self.keying.local()?.floors.get(&self.group)?.floor;
        Some((f.epoch, f.join, f.gated))
    }
}

/// The relay, the keyholder's app (index 0) and the members' apps.
struct World {
    relay: Relay,
    db: l4f_accounts::store::Store,
    apps: Vec<App>,
    group: String,
    last_tick: u64,
}

impl World {
    fn now(&self) -> u64 {
        self.relay.groups.now()
    }

    /// `acc`'s desktop app on a new connection, following the group and tracking it, with
    /// `local` kept from an earlier connection.
    async fn app(&mut self, acc: &Account, holds: bool, local: Option<LocalGk>) -> usize {
        let sid = self.relay.session(&acc.ik, Some(acc.a));
        self.relay.follow(sid, &self.group.clone());
        let (app, send) = App::new(&self.relay, sid, acc, &self.group, holds, local);
        for msg in send {
            self.relay.send(sid, msg).await;
        }
        self.apps.push(app);
        self.apps.len() - 1
    }

    async fn post(&mut self, i: usize, id: u8, text: &[u8]) {
        let now = self.now();
        let sid = self.apps[i].sid;
        for msg in self.apps[i].post(id, text, now) {
            self.relay.send(sid, msg).await;
        }
    }

    /// One round: each app's frames, a tick each second, what it sends handed over, and
    /// its self-rows stored for its account.
    async fn step(&mut self) {
        let now = self.now();
        let tick = now >= self.last_tick + 1_000;
        for i in 0..self.apps.len() {
            let sid = self.apps[i].sid;
            let frames = self.relay.drain(sid).await;
            let d = &mut self.apps[i];
            if d.gone {
                continue;
            }
            let mut send = vec![];
            for f in frames {
                if tracing_on() {
                    eprintln!("[{now}] app {i} <- {}", show(&f));
                }
                let f = match f {
                    ServerMessage::EpochNamesIn {
                        group,
                        part,
                        last,
                        mut piece,
                    } => {
                        if let Some(from) = d.names_from {
                            piece.lists.retain(|l| l.epoch >= from);
                        }
                        d.names_got
                            .push(piece.lists.iter().map(|l| (l.epoch, l.join)).collect());
                        ServerMessage::EpochNamesIn {
                            group,
                            part,
                            last,
                            piece,
                        }
                    }
                    f => f,
                };
                send.extend(d.frame(&f, now));
            }
            if tick {
                send.extend(d.tick(now));
            }
            let rows = std::mem::take(&mut d.self_rows);
            let account = d.account;
            for msg in send {
                if tracing_on() {
                    let what = format!("{msg:?}");
                    eprintln!("[{now}] app {i} -> {}", &what[..what.len().min(110)]);
                }
                self.relay.send(sid, msg).await;
            }
            if !rows.is_empty() {
                crate::accounts::gk::put_self_rows(&self.db, &account, &rows)
                    .await
                    .unwrap();
            }
        }
        if tick {
            self.last_tick = now;
        }
    }

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

    fn read(&self, i: usize, text: &[u8]) -> bool {
        self.apps[i].texts.iter().any(|t| t == text)
    }
}

/// What the writer's app told its user, and what the account seated meanwhile read.
struct Outcome {
    /// `Warn::GatedOpened` reached the writer's app.
    told_open: bool,
    /// A `Readers` event of the writer's app named the account seated meanwhile.
    named: bool,
    /// That account read the writer's post made after the gate was back on.
    read: bool,
    /// The writer's app gave a post up.
    dropped: bool,
    /// The keyholder's own app was told the gate opened.
    keyholder_told_open: bool,
    writer_events: Vec<GkEvent>,
    /// Each names answer the writer's app took: the place of every list in it.
    names_got: Vec<Vec<(u32, u32)>>,
    /// The epoch of the opening that turned the gate back on.
    gate_on: u32,
}

/// A gated channel: kim's desktop holds the keys, ann writes, tom is a member who leaves.
/// The gate goes off; tom's exit brings the opening that carries it; gus is seated while
/// the group is open; the gate goes on again. Then ann writes again.
///
/// `away`: ann's connection ends before the gate goes off, and her app comes back on a new
/// connection, with what it kept (`gk_local.bin` on a desktop), once the gate is on again.
/// An account's seat outlives its connections (§5.4), so she stays seated throughout.
///
/// `current_period_only`: the relay answers ann's `EpochNames` with the lists of the gated
/// period the head is in, and with none of the gated period before it. Every list it sends
/// is one it holds, unchanged.
async fn gate_off_and_on(away: bool, current_period_only: bool) -> Outcome {
    let _ = tracing_on();
    let (db, file) = scratch_db().await;
    let inc = crate::accounts::gk::gk_start(&db, true)
        .await
        .unwrap()
        .unwrap();
    let kim = Account::new(&db, "kim").await;
    let ann = Account::new(&db, "ann").await;
    let tom = Account::new(&db, "tom").await;
    let gus = Account::new(&db, "gus").await;
    let relay = Relay::new();
    relay.groups.attach(db.clone(), inc);
    // A stored group (a channel that keeps history): an account's seat there outlives its
    // connections
    let group = relay.groups.id_for(CHANNEL, Some("c:d1gate"));
    assert_eq!(group, "c:d1gate");
    let mut w = World {
        relay,
        db: db.clone(),
        apps: vec![],
        group: group.clone(),
        last_tick: 0,
    };
    // kim's desktop follows first and holds the keys; the channel is gated from the start
    let ksid = w.relay.session(&kim.ik, Some(kim.a));
    w.relay.follow(ksid, &group);
    w.relay.groups.on_gate(CHANNEL, true);
    let (k, send) = App::new(&w.relay, ksid, &kim, &group, true, None);
    for m in send {
        w.relay.send(ksid, m).await;
    }
    w.apps.push(k);
    const K: usize = 0;
    let mut a = w.app(&ann, false, None).await;
    let t = w.app(&tom, false, None).await;
    let seated = w
        .until(30_000, |w| {
            w.apps[a].epoch().is_some() && w.apps[t].epoch().is_some()
        })
        .await;
    assert!(seated, "ann and tom are seated: {:?}", w.apps[a].events);
    assert_eq!(
        w.apps[K].head().map(|h| h.2),
        Some(true),
        "the head is gated"
    );

    // ann writes in the gated group: her fold passes
    w.post(a, 1, b"one").await;
    let read = w.until(30_000, |w| w.read(t, b"one")).await;
    assert!(read, "tom reads ann's first post: {:?}", w.apps[a].events);
    let mut events_before = vec![];

    // ann's connection ends; her app keeps its floors
    let mut kept = None;
    if away {
        let d = &mut w.apps[a];
        let _ = d.keying.end();
        kept = Some(d.keying.local().cloned().expect("what the app kept"));
        events_before = d.events.clone();
        d.gone = true;
        let sid = d.sid;
        w.relay.groups.on_session_end(sid);
    }

    // The gate goes off, and tom's exit brings the opening that carries it
    let before = w.apps[K].head().expect("a head");
    w.relay.groups.on_gate(CHANNEL, false);
    let tsid = w.apps[t].sid;
    w.relay.unfollow(tsid, &group);
    let _ = w.apps[t].keying.untrack(CHANNEL);
    let open = w
        .until(30_000, |w| {
            w.apps[K].head().is_some_and(|h| !h.2 && h.0 > before.0)
        })
        .await;
    assert!(open, "an opening with the gate off: {:?}", w.apps[K].head());

    // gus is seated while the group is open
    let g = w.app(&gus, false, None).await;
    let seated = w.until(30_000, |w| w.apps[g].epoch().is_some()).await;
    assert!(seated, "gus is seated: {:?}", w.apps[g].events);
    let open_at = w.apps[K].head().expect("a head");
    assert!(!open_at.2, "gus was seated in the open group");

    // The gate goes on again
    w.relay.groups.on_gate(CHANNEL, true);
    let gated = w
        .until(30_000, |w| {
            w.apps[K].head().is_some_and(|h| h.2 && h.0 > open_at.0)
        })
        .await;
    assert!(gated, "the gate is on again: {:?}", w.apps[K].head());
    let gate_on = w.apps[K].head().expect("a head").0;

    // ann's app is back, on a new connection, and she writes
    if away {
        a = w.app(&ann, false, kept).await;
    }
    if current_period_only {
        w.apps[a].names_from = Some(gate_on);
    }
    w.post(a, 2, b"two").await;
    let read = w
        .until(75_000, |w| {
            w.read(g, b"two")
                || w.apps[a]
                    .events
                    .iter()
                    .any(|e| matches!(e, GkEvent::PostDropped { .. }))
        })
        .await
        && w.read(g, b"two");

    let ghost = MemberId::Account(w.apps[g].account);
    let mut events = events_before;
    events.extend(w.apps[a].events.clone());
    let opened = |e: &GkEvent| {
        matches!(
            e,
            GkEvent::Warning {
                kind: Warn::GatedOpened,
                ..
            }
        )
    };
    let out = Outcome {
        told_open: events.iter().any(opened),
        named: events
            .iter()
            .any(|e| matches!(e, GkEvent::Readers { named, .. } if named.contains(&ghost))),
        read,
        dropped: events
            .iter()
            .any(|e| matches!(e, GkEvent::PostDropped { .. })),
        keyholder_told_open: w.apps[K].events.iter().any(opened),
        writer_events: events,
        names_got: w.apps[a].names_got.clone(),
        gate_on,
    };
    eprintln!(
        "d1 gate_off_and_on(away: {away}, current_period_only: {current_period_only}): gate on \
         at epoch {}, names answers {:?}, read {}, dropped {}, told_open {}, named {}, \
         keyholder told {}, writer events {:?}, post refusals {:?}",
        out.gate_on,
        out.names_got,
        out.read,
        out.dropped,
        out.told_open,
        out.named,
        out.keyholder_told_open,
        out.writer_events,
        w.relay.post_refusals,
    );
    drop(w);
    drop_db(&file);
    out
}

/// The control: ann's app stays connected. She wrote in the epoch the gate went off in, so
/// the relay pushed her the opening that carries it, and her app told her the channel is
/// open. Her next post goes. It passes today.
#[tokio::test]
async fn e2e_d1_control_a_writer_pushed_the_opening_is_told_the_gate_went_off() {
    let o = gate_off_and_on(false, false).await;
    assert!(
        o.told_open,
        "the writer's app says the channel opened: {:?}",
        o.writer_events
    );
    assert!(o.keyholder_told_open, "and so does the keyholder's");
    assert!(o.read && !o.dropped, "and her next post is read");
}

/// F4: ann's app is away while the gate is off, and the relay answers her names ask with
/// the current gated period's lists only. Her app takes the gated head by a walk, as the
/// honest relay answers every member that is no keyholder; its fold starts over at the
/// opening that turned the gate on again, which names nobody. gus, seated while the gate
/// was off, reads what she writes from then on, and her app has told her neither that the
/// gate was off nor that gus reads.
#[tokio::test]
async fn e2e_d1_f4_a_gate_turned_off_and_on_between_two_heads_a_writer_takes_is_reported() {
    let o = gate_off_and_on(true, true).await;
    assert!(
        !o.read || o.told_open || o.named,
        "an account seated while the gate was off reads the writer's next post (read: {}), \
         and the writer's app said neither that the gate went off (GatedOpened: {}) nor named \
         that account as a new reader (named: {}). The gate went on again at epoch {}; the \
         relay's names answers held lists at these places: {:?}. The keyholder's own app was \
         told the gate opened: {}. Everything the writer's app told its user: {:?}",
        o.read,
        o.told_open,
        o.named,
        o.gate_on,
        o.names_got,
        o.keyholder_told_open,
        o.writer_events
    );
}

/// F5: no hostile relay. ann's app is away while the gate is off (offline, as any account
/// may be), and the relay answers every ask as it does. Her post after the gate is on again
/// must go: a names floor from the gated period before folds from the opening that turned
/// the gate on again (§4.4 rule 4).
#[tokio::test]
async fn e2e_d1_f5_a_writer_away_while_the_gate_was_off_can_post_once_it_is_on_again() {
    let o = gate_off_and_on(true, false).await;
    assert!(
        o.read && !o.dropped,
        "the writer's post after the gate came back on reached nobody (read by the other \
         member: {}; given up by her app: {}). The gate went on again at epoch {}. The \
         relay's names answers held lists at these places: {:?}. Everything the writer's app \
         told its user: {:?}",
        o.read,
        o.dropped,
        o.gate_on,
        o.names_got,
        o.writer_events
    );
}
