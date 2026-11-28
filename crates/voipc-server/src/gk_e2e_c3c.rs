//! End-to-end group-key scenarios added by slice C3C (wave 3): the relay's real
//! `gk` code driven by the clients' real `voipc_crypto::group_state` code. Shared
//! helpers live in `gk_e2e_tests.rs`.
//!
//! The keyholders here are the app's own: a `GroupKeying` with "Help hold keys" on, whose
//! duty (C3c, group_state/holder.rs) volunteers, takes each due, fetches the keyring and the
//! lists it needs, builds off the lock (`take_build` → `BuildJob::step` → `built`) and
//! paces its commit out (`next_frame`), as the native `gk_task` will run it. Members are
//! C3b's (`gk_e2e_tests::Member`).
//!
//! A stored group's Regenesis waits an hour of the relay's clock with no keyholder online;
//! these tests run on the wall clock (`tokio`'s `test-util` is not on for voipc-server), so
//! the new start after every keyholder left is a memory group's Genesis of a new generation,
//! made by a volunteer that came after. The Regenesis itself is tested in holder.rs
//! (`a_volunteer_starts_a_stored_group_anew_by_a_regenesis_after_an_hour_with_no_keyholder`),
//! checked by the validator as the relay runs it.

use std::time::Duration;

use voipc_crypto::group_key::GroupKind;
use voipc_crypto::group_state::{
    GkCtx, GkEvent, GkOut, GkStart, GkTrack, GroupKeying, MemoryPins, Platform, VaultFloor,
};
use voipc_crypto::{IdentityKeyPair, SignalStores};
use voipc_protocol::gk::{self, stale};
use voipc_protocol::messages::{ClientMessage, ServerMessage};
use voipc_protocol::types::UserId;

use super::gk_e2e_tests::{show, tracing_on, Member, Relay, CHANNEL};

/// A keyholder app: C3c's duty in the app's own `GroupKeying`, its jobs run whole as the
/// host runs them off the lock, its uploads handed out one frame a call.
struct Keyholder {
    sid: UserId,
    keying: GroupKeying,
    st: SignalStores,
    pins: MemoryPins,
    group: String,
    events: Vec<GkEvent>,
    sent: Vec<ClientMessage>,
    /// Due kinds asked and stale reasons told, in order.
    asked: Vec<u8>,
    stales: Vec<u8>,
    /// A due of this kind makes it keep its uploads back (`held`) until `release`.
    stall: Option<u8>,
    stalled: bool,
    held: Vec<ClientMessage>,
}

impl Keyholder {
    fn new(relay: &Relay, sid: UserId, ik: IdentityKeyPair, group: &str) -> Keyholder {
        let mut k = Keyholder {
            sid,
            keying: GroupKeying::default(),
            st: SignalStores::new(&ik, sid),
            pins: MemoryPins::default(),
            group: group.to_string(),
            events: vec![],
            sent: vec![],
            asked: vec![],
            stales: vec![],
            stall: None,
            stalled: false,
            held: vec![],
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

    /// What a call handed back, its jobs run and its uploads taken; what goes now.
    fn took(&mut self, out: GkOut, now: u64) -> Vec<ClientMessage> {
        self.events.extend(out.events);
        let mut send = out.send;
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
            let out = self.keying.built(b, c);
            self.events.extend(out.events);
            send.extend(out.send);
        }
        while let Some(m) = self.keying.next_frame(now, false) {
            if self.stalled {
                self.held.push(m);
            } else {
                send.push(m);
            }
        }
        self.sent.extend(send.iter().cloned());
        send
    }

    /// Its fresh start's sends (the volunteer), then its group tracked.
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
            ServerMessage::EpochDue { part: 0, piece, .. } => {
                self.asked.push(piece.kind);
                if self.stall == Some(piece.kind) {
                    self.stalled = true;
                }
            }
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

    /// The uploads it kept back go.
    fn release(&mut self) -> Vec<ClientMessage> {
        self.stalled = false;
        self.stall = None;
        std::mem::take(&mut self.held)
    }

    fn epoch(&self) -> Option<u32> {
        self.keying.current_epoch(&self.group).map(|e| e.epoch)
    }

    fn sent_any(&self, f: impl Fn(&ClientMessage) -> bool) -> bool {
        self.sent.iter().any(f)
    }
}

struct World {
    relay: Relay,
    khs: Vec<Keyholder>,
    /// Keyholders whose connection ended.
    gone: Vec<UserId>,
    members: Vec<Member>,
    last_tick: u64,
}

/// The size of the keyholder set in the last `Keyholders` event `m` was told.
fn set_size(m: &Member) -> Option<usize> {
    m.events.iter().rev().find_map(|e| match e {
        GkEvent::Keyholders { holders, .. } => Some(holders.len()),
        _ => None,
    })
}

impl World {
    fn now(&self) -> u64 {
        self.relay.groups.now()
    }

    /// A guest keyholder app following `group`: it volunteers and tracks the group.
    async fn keyholder(&mut self, group: &str) -> usize {
        let ik = voipc_crypto::generate_identity_key_pair();
        let sid = self.relay.session(&ik, None);
        self.relay.follow(sid, group);
        let mut k = Keyholder::new(&self.relay, sid, ik, group);
        for msg in k.track(self.now()) {
            self.relay.send(sid, msg).await;
        }
        self.khs.push(k);
        self.khs.len() - 1
    }

    /// A guest member following `group`.
    async fn guest(&mut self, group: &str) -> usize {
        let ik = voipc_crypto::generate_identity_key_pair();
        let sid = self.relay.session(&ik, None);
        let mut m = Member::new(&self.relay, sid, ik, None, None, None, group);
        self.relay.follow(sid, group);
        for msg in m.track() {
            self.relay.send(sid, msg).await;
        }
        self.members.push(m);
        self.members.len() - 1
    }

    /// Keyholder `i`'s connection ends.
    fn leave(&mut self, i: usize, group: &str) {
        let sid = self.khs[i].sid;
        let _ = self.khs[i].keying.end();
        self.relay.unfollow(sid, group);
        self.relay.groups.on_session_end(sid);
        self.gone.push(sid);
    }

    async fn post(&mut self, i: usize, id: u8, text: &[u8]) {
        let now = self.now();
        let sid = self.members[i].sid;
        for msg in self.members[i].post(id, text, now) {
            self.relay.send(sid, msg).await;
        }
    }

    async fn release(&mut self, i: usize) {
        let sid = self.khs[i].sid;
        for msg in self.khs[i].release() {
            self.relay.send(sid, msg).await;
        }
    }

    /// One round: every queue drained into its app, what each sends handed back.
    async fn step(&mut self) {
        let now = self.now();
        let tick = now >= self.last_tick + 1_000;
        for i in 0..self.khs.len() {
            let sid = self.khs[i].sid;
            if self.gone.contains(&sid) {
                continue;
            }
            let frames = self.relay.drain(sid).await;
            let mut send = vec![];
            for f in &frames {
                if tracing_on() {
                    eprintln!("[{now}] keyholder {sid} <- {}", show(f));
                }
                send.extend(self.khs[i].frame(f, now));
            }
            if tick {
                send.extend(self.khs[i].tick(now));
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
                if tracing_on() {
                    eprintln!("[{now}] member {sid} <- {}", show(f));
                }
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

    fn report(&self) -> String {
        let khs: Vec<String> = self
            .khs
            .iter()
            .map(|k| {
                format!(
                    "keyholder {}: asked {:?}, stales {:?}, epoch {:?}, events {:?}",
                    k.sid,
                    k.asked,
                    k.stales,
                    k.epoch(),
                    k.events
                )
            })
            .collect();
        let members: Vec<String> = self
            .members
            .iter()
            .map(|m| {
                format!(
                    "member {}: epoch {:?}, events {:?}",
                    m.sid,
                    m.epoch(),
                    m.events
                )
            })
            .collect();
        format!("{khs:#?}\n{members:#?}")
    }
}

/// A memory group's world with the real keyholder app 0 and guest members `n`, each
/// holding the head epoch: the volunteer's Genesis and one Join batch.
async fn started(n: usize) -> (World, String) {
    let mut w = World {
        relay: Relay::new(),
        khs: vec![],
        gone: vec![],
        members: vec![],
        last_tick: 0,
    };
    let id = w.relay.groups.id_for(CHANNEL, None);
    w.keyholder(&id).await;
    for _ in 0..n {
        w.guest(&id).await;
    }
    let seated = w
        .until(15_000, |w| {
            w.khs[0].epoch().is_some() && w.members.iter().all(|m| m.epoch().is_some())
        })
        .await;
    assert!(seated, "everyone holds the epoch key: {}", w.report());
    (w, id)
}

/// The keyholder app's Genesis seats its own seat, its Join seats the members, an exit's
/// opening drops the leaver; a second volunteer is promoted by the first's KeyholdersAdd and
/// takes over with a KeyholdersRemove once the first leaves (its keyring fetched and opened
/// through the KRK welcome the Add made it); with every keyholder gone a later volunteer
/// starts a new generation, and the members post and read under it.
#[tokio::test]
async fn e2e_c3c_the_apps_keyholders_start_seat_drop_promote_hand_over_and_start_anew() {
    let (mut w, id) = started(3).await;
    assert_eq!(w.khs[0].asked[..2], [gk::due::GENESIS, gk::due::JOIN]);
    assert!(w.khs[0].stales.is_empty());
    let e = w.members[0].epoch().unwrap();
    w.post(0, 1, b"hello").await;
    w.run(300).await;
    assert_eq!(w.members[1].texts(), vec![b"hello".to_vec()]);

    // An exit and its opening
    let leaver = w.members[2].sid;
    w.relay.kick(leaver, &id);
    let opened = w
        .until(15_000, |w| w.members[0].epoch().is_some_and(|x| x > e))
        .await;
    assert!(opened, "the writer takes the opening: {}", w.report());
    assert!(w.khs[0].asked.contains(&gk::due::EXITS));
    w.post(0, 2, b"after the exit").await;
    w.run(1_000).await;
    assert_eq!(
        w.members[1].texts(),
        vec![b"hello".to_vec(), b"after the exit".to_vec()]
    );

    // A second volunteer: seated, then promoted by the first
    let k2 = w.keyholder(&id).await;
    let added = w
        .until(20_000, |w| set_size(&w.members[0]) == Some(2))
        .await;
    assert!(added, "the set names two keyholders: {}", w.report());
    assert!(w.khs[0].asked.contains(&gk::due::PROMOTE));
    assert!(w.khs[0].stales.is_empty(), "{}", w.report());

    // The first leaves: the second removes its entry, through the keyring it fetches
    w.leave(0, &id);
    let removed = w
        .until(20_000, |w| set_size(&w.members[0]) == Some(1))
        .await;
    assert!(removed, "{}", w.report());
    assert!(w.khs[k2].asked.contains(&gk::due::REMOVE));
    assert!(w.khs[k2].stales.is_empty(), "{}", w.report());
    assert!(
        w.khs[k2].sent_any(|m| matches!(m, ClientMessage::KeyringWanted { .. })),
        "the promoted keyholder fetched the keyring"
    );
    w.post(0, 3, b"under the second keyholder").await;
    let read = w.until(10_000, |w| w.members[1].texts().len() == 3).await;
    assert!(read, "{}", w.report());

    // Every keyholder gone; a volunteer that comes later starts anew
    w.leave(k2, &id);
    w.run(500).await;
    let k3 = w.keyholder(&id).await;
    let anew = w
        .until(20_000, |w| {
            w.khs[k3].asked.contains(&gk::due::GENESIS)
                && w.members.iter().take(2).all(|m| {
                    m.events.iter().any(|e| matches!(e, GkEvent::Anew { .. }))
                        && m.epoch().is_some()
                })
        })
        .await;
    assert!(
        anew,
        "a new generation, the members seated in it: {}",
        w.report()
    );
    w.post(0, 4, b"anew").await;
    let read = w
        .until(10_000, |w| {
            w.members[1].texts().last().map(Vec::as_slice) == Some(&b"anew"[..])
        })
        .await;
    assert!(read, "{}", w.report());
    assert!(
        w.relay.post_refusals.is_empty(),
        "{:?}",
        w.relay.post_refusals
    );
}

/// Two keyholders; the second resigns, and the Remove due (a 60 s one) goes to the first,
/// which builds it but keeps the upload back. An exit meanwhile: the relay asks the second
/// an Exits Fresh at once (no exit waits behind a 60 s due), which lands. The held commit
/// then meets `HEAD_MOVED`; its keyholder fetches the keyring at the new head, asks the
/// lists again, rebuilds on it, and its KeyholdersRemove is taken.
#[tokio::test]
async fn e2e_c3c_a_commit_that_meets_head_moved_is_rebased_on_the_new_head_and_taken() {
    let (mut w, id) = started(2).await;
    let k2 = w.keyholder(&id).await;
    let two = w
        .until(20_000, |w| set_size(&w.members[0]) == Some(2))
        .await;
    assert!(two, "{}", w.report());
    w.run(2_500).await;
    w.khs[0].stall = Some(gk::due::REMOVE);
    let sid2 = w.khs[k2].sid;
    let resign = ClientMessage::KeyholdResign {
        group: id.clone(),
        entry: None,
    };
    w.relay.send(sid2, resign).await;
    let held = w.until(20_000, |w| !w.khs[0].held.is_empty()).await;
    assert!(held, "a Remove built and held back: {}", w.report());
    // Member 0 writes, so it is pushed the next opening
    w.post(0, 1, b"before the race").await;
    w.run(300).await;
    let e = w.members[0].epoch().unwrap();
    // The exit: the second keyholder's Fresh lands first
    let leaver = w.members[1].sid;
    w.relay.kick(leaver, &id);
    let fresh = w
        .until(15_000, |w| w.members[0].epoch().is_some_and(|x| x > e))
        .await;
    assert!(fresh, "{}", w.report());
    assert_eq!(w.khs[k2].asked.last(), Some(&gk::due::EXITS));
    // The held commit goes: HEAD_MOVED, a rebase, taken
    w.release(0).await;
    let taken = w
        .until(20_000, |w| set_size(&w.members[0]) == Some(1))
        .await;
    assert!(taken, "{}", w.report());
    assert_eq!(w.khs[0].stales, vec![stale::HEAD_MOVED], "{}", w.report());
    assert!(w.khs[0].sent_any(|m| matches!(m, ClientMessage::KeyringWanted { .. })));
    let lists = w.khs[0]
        .sent
        .iter()
        .filter(|m| matches!(m, ClientMessage::EpochListsWanted { .. }))
        .count();
    assert!(lists >= 2, "the lists asked again for the rebase");
    w.post(0, 2, b"after the rebase").await;
    w.run(1_000).await;
    assert!(
        w.relay.post_refusals.is_empty(),
        "{:?}",
        w.relay.post_refusals
    );
}
