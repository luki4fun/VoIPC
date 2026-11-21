//! End-to-end group-key scenarios added by wave-2 slice J9S (2026-11-19): stepped keyholder builds:
//! `BuildJob::step` keeps to its budget.
//! The relay's real `gk` code driven by the clients' real `voipc_crypto::group_state` code;
//! shared helpers live in `gk_e2e_tests.rs`.
//!
//! The keyholder is the app's own duty (C3c, as in `gk_e2e_c3c.rs`), its jobs stepped at a
//! zero budget, the smallest a host can ask: each step does one unit of work (a row, a
//! welcome, a seal, a list read; `build::steps`) and stops, as a browser keyholder's page
//! would with its own budget, until the job is done.

use std::time::Duration;

use voipc_crypto::group_key::GroupKind;
use voipc_crypto::group_state::{
    GkCtx, GkOut, GkStart, GkTrack, GroupKeying, MemoryPins, Platform, VaultFloor,
};
use voipc_crypto::{IdentityKeyPair, SignalStores};
use voipc_protocol::gk;
use voipc_protocol::messages::{ClientMessage, ServerMessage};
use voipc_protocol::types::UserId;

use super::gk_e2e_tests::{show, tracing_on, Member, Relay, CHANNEL};

/// What one of the keyholder's jobs did: its steps, its units of work, the most units one
/// step did.
#[derive(Debug, Clone, Copy)]
struct Ran {
    steps: u64,
    units: u64,
    most: u64,
}

/// A keyholder app: C3c's duty in the app's own `GroupKeying`, its jobs run in steps of
/// `budget` as a host steps them, its uploads handed out one frame a call.
struct Keyholder {
    sid: UserId,
    keying: GroupKeying,
    st: SignalStores,
    pins: MemoryPins,
    group: String,
    budget: Duration,
    sent: Vec<ClientMessage>,
    /// Due kinds asked and stale reasons told, in order.
    asked: Vec<u8>,
    stales: Vec<u8>,
    jobs: Vec<Ran>,
}

impl Keyholder {
    fn new(relay: &Relay, sid: UserId, ik: IdentityKeyPair, group: &str, budget: Duration) -> Self {
        let mut k = Keyholder {
            sid,
            keying: GroupKeying::default(),
            st: SignalStores::new(&ik, sid),
            pins: MemoryPins::default(),
            group: group.to_string(),
            budget,
            sent: vec![],
            asked: vec![],
            stales: vec![],
            jobs: vec![],
        };
        let out = k.keying.start(GkStart {
            on: true,
            run: relay.groups.run,
            relay_clock: relay.groups.now() / 1000,
            platform: Platform::Desktop,
            help_hold_keys: true,
            user_id: sid,
            identity: ik,
            account: None,
            seat_keys: None,
            local: None,
            visible: true,
        });
        let _ = k.took(out, relay.groups.now());
        k
    }

    /// What a call handed back, its jobs stepped to their end and its uploads taken.
    fn took(&mut self, out: GkOut, now: u64) -> Vec<ClientMessage> {
        let mut send = out.send;
        while let Some(mut job) = self.keying.take_build() {
            let mut ran = Ran {
                steps: 0,
                units: 0,
                most: 0,
            };
            let b = loop {
                let before = job.units();
                let b = job.step(self.budget);
                ran.steps += 1;
                ran.most = ran.most.max(job.units() - before);
                if let Some(b) = b {
                    break b;
                }
                assert!(ran.steps < 10_000_000, "a job ends");
            };
            ran.units = job.units();
            self.jobs.push(ran);
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

    fn track(&mut self, now: u64) -> Vec<ClientMessage> {
        let mut send: Vec<ClientMessage> = self.sent.clone();
        let out = self.keying.track(
            GkTrack {
                channel_id: CHANNEL,
                group: self.group.clone(),
                kind: GroupKind::Text,
                anonymous: false,
                hide_members: false,
                viewer_admin: false,
                keeps_history: false,
            },
            VaultFloor::None,
        );
        send.extend(self.took(out, now));
        send
    }

    fn frame(&mut self, f: &ServerMessage, now: u64) -> Vec<ClientMessage> {
        match f {
            ServerMessage::EpochDue { part: 0, piece, .. } => self.asked.push(piece.kind),
            ServerMessage::EpochStale { reason, .. } => self.stales.push(*reason),
            _ => {}
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

    fn epoch(&self) -> Option<u32> {
        self.keying.current_epoch(&self.group).map(|e| e.epoch)
    }

    /// The seat welcomes of every commit it sent.
    fn welcomes(&self) -> usize {
        self.sent
            .iter()
            .map(|m| match m {
                ClientMessage::EpochCommit { piece, .. } => piece.welcomes.len(),
                _ => 0,
            })
            .sum()
    }
}

struct World {
    relay: Relay,
    kh: Option<Keyholder>,
    members: Vec<Member>,
    last_tick: u64,
}

impl World {
    fn now(&self) -> u64 {
        self.relay.groups.now()
    }

    async fn keyholder(&mut self, group: &str, budget: Duration) {
        let ik = voipc_crypto::generate_identity_key_pair();
        let sid = self.relay.session(&ik, None);
        self.relay.follow(sid, group);
        let mut k = Keyholder::new(&self.relay, sid, ik, group, budget);
        for msg in k.track(self.now()) {
            self.relay.send(sid, msg).await;
        }
        self.kh = Some(k);
    }

    async fn guest(&mut self, group: &str) {
        let ik = voipc_crypto::generate_identity_key_pair();
        let sid = self.relay.session(&ik, None);
        let mut m = Member::new(&self.relay, sid, ik, None, None, None, group);
        self.relay.follow(sid, group);
        for msg in m.track() {
            self.relay.send(sid, msg).await;
        }
        self.members.push(m);
    }

    async fn post(&mut self, i: usize, id: u8, text: &[u8]) {
        let now = self.now();
        let sid = self.members[i].sid;
        for msg in self.members[i].post(id, text, now) {
            self.relay.send(sid, msg).await;
        }
    }

    /// One round: every queue drained into its app, what each sends handed back.
    async fn step(&mut self) {
        let now = self.now();
        let tick = now >= self.last_tick + 1_000;
        if let Some(k) = self.kh.as_mut() {
            let sid = k.sid;
            let frames = self.relay.drain(sid).await;
            let mut send = vec![];
            for f in &frames {
                if tracing_on() {
                    eprintln!("[{now}] keyholder {sid} <- {}", show(f));
                }
                send.extend(k.frame(f, now));
            }
            if tick {
                send.extend(k.tick(now));
            }
            for msg in send {
                self.relay.send(sid, msg).await;
            }
        }
        for i in 0..self.members.len() {
            let sid = self.members[i].sid;
            let frames = self.relay.drain(sid).await;
            let mut send = vec![];
            for f in &frames {
                send.extend(self.members[i].frame(f, now));
            }
            if tick {
                send.extend(self.members[i].tick(now));
            }
            for msg in send {
                self.relay.send(sid, msg).await;
            }
        }
        if tick {
            self.last_tick = now;
        }
    }

    async fn run(&mut self, ms: u64) {
        let end = self.now() + ms;
        while self.now() < end {
            tokio::time::sleep(Duration::from_millis(10)).await;
            self.step().await;
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
}

/// A keyholder whose host steps its builds at a zero budget seats 300 guests, by Joins of
/// 256 and 44 (`JOIN_BATCH_MAX`), each built one unit of work a step: a step for each seat's
/// agreement and row, one for its welcome, one for each seal. The relay takes each commit,
/// every guest holds the epoch key, and a post opens for another guest.
#[tokio::test]
async fn e2e_j9s_a_keyholder_stepping_at_a_zero_budget_seats_300_guests_and_they_read() {
    let mut w = World {
        relay: Relay::new(),
        kh: None,
        members: vec![],
        last_tick: 0,
    };
    let id = w.relay.groups.id_for(CHANNEL, None);
    assert!(id.starts_with("r:"));
    w.keyholder(&id, Duration::ZERO).await;
    for _ in 0..300 {
        w.guest(&id).await;
    }
    let seated = w
        .until(60_000, |w| {
            w.kh.as_ref().is_some_and(|k| k.epoch().is_some())
                && w.members.iter().all(|m| m.epoch().is_some())
        })
        .await;
    let k = w.kh.as_ref().unwrap();
    let held = w.members.iter().filter(|m| m.epoch().is_some()).count();
    assert!(
        seated,
        "every guest holds the epoch key: {held} of 300; asked {:?}, stales {:?}, jobs {:?}",
        k.asked, k.stales, k.jobs
    );
    assert!(k.stales.is_empty(), "no commit went stale: {:?}", k.stales);
    let joins = k.asked.iter().filter(|d| **d == gk::due::JOIN).count();
    assert!(
        joins >= 2,
        "300 seats take two Joins at least: {:?}",
        k.asked
    );
    assert_eq!(
        k.welcomes(),
        1 + 300,
        "a seat welcome to its own seat (the Genesis) and to each guest"
    );
    // Each job in steps of one unit: the last step ends it with none
    for ran in &k.jobs {
        assert!(ran.most <= 1, "one unit a step: {ran:?}");
        assert_eq!(ran.steps, ran.units + 1, "{ran:?}");
    }
    let steps: u64 = k.jobs.iter().map(|r| r.steps).sum();
    assert!(
        steps > 2 * 300,
        "a step for each guest's row and one for its welcome at least: {:?}",
        k.jobs
    );

    w.post(0, 1, b"stepped").await;
    w.post(299, 2, b"and read").await;
    let read = w
        .until(10_000, |w| {
            w.members[299].texts().contains(&b"stepped".to_vec())
                && w.members[0].texts().contains(&b"and read".to_vec())
        })
        .await;
    assert!(read, "the posts open for the others");
    w.run(100).await;
}
