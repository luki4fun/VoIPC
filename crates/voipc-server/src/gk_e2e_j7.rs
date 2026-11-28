//! End-to-end group-key scenarios added by slice J7 (choice 31, owner 2026-11-19): a
//! browser hidden or in a call holds text keys as the fallback when no other text
//! keyholder is online. The relay's real `gk` code driven by the clients' real
//! `voipc_crypto::group_state` code; shared helpers live in `gk_e2e_tests.rs`.

use std::time::Duration;

use voipc_crypto::group_key::GroupKind;
use voipc_crypto::group_state::{
    GkCtx, GkOut, GkStart, GkTrack, GroupKeying, MemoryPins, OpenedPost, Platform, VaultFloor,
};
use voipc_crypto::{IdentityKeyPair, SignalStores};
use voipc_protocol::gk;
use voipc_protocol::messages::{ClientMessage, ServerMessage};
use voipc_protocol::types::UserId;

use super::gk_e2e_tests::{show, tracing_on, Relay, CHANNEL};

/// A browser page in a call, as voipc-web runs it: one `GroupKeying` that writes, reads and
/// (with "Help hold keys" on) holds keys, its jobs run in the 2 ms steps of a call.
struct Browser {
    sid: UserId,
    keying: GroupKeying,
    st: SignalStores,
    pins: MemoryPins,
    group: String,
    posts: Vec<OpenedPost>,
    sent: Vec<ClientMessage>,
}

impl Browser {
    /// Started in a call as voipc-web's `gk_start` does (shown, so `visible` and then its
    /// page state), its group tracked; what it sends.
    fn new(
        relay: &Relay,
        sid: UserId,
        ik: IdentityKeyPair,
        group: &str,
    ) -> (Browser, Vec<ClientMessage>) {
        let mut b = Browser {
            sid,
            keying: GroupKeying::default(),
            st: SignalStores::new(&ik, sid),
            pins: MemoryPins::default(),
            group: group.to_string(),
            posts: vec![],
            sent: vec![],
        };
        let now = relay.groups.now();
        let out = b.keying.start(GkStart {
            on: true,
            run: relay.groups.run,
            relay_clock: now / 1000,
            platform: Platform::Browser,
            help_hold_keys: true,
            user_id: sid,
            identity: ik,
            account: None,
            seat_keys: None,
            local: None,
            visible: false,
        });
        let mut send = b.took(out, now);
        let out = b.keying.visibility(true, true);
        send.extend(b.took(out, now));
        let out = b.keying.track(
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
        send.extend(b.took(out, now));
        (b, send)
    }

    /// What a call handed back, its jobs run in 2 ms steps and its uploads taken.
    fn took(&mut self, out: GkOut, now: u64) -> Vec<ClientMessage> {
        self.posts.extend(out.posts);
        let mut send = out.send;
        while let Some(mut job) = self.keying.take_build() {
            let b = loop {
                if let Some(b) = job.step(Duration::from_millis(2)) {
                    break b;
                }
            };
            let c = GkCtx {
                pins: &mut self.pins,
                now,
            };
            let out = self.keying.built(b, c);
            self.posts.extend(out.posts);
            send.extend(out.send);
        }
        while let Some(m) = self.keying.next_frame(now, true) {
            send.push(m);
        }
        self.sent.extend(send.iter().cloned());
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

    fn epoch(&self) -> Option<u32> {
        self.keying.current_epoch(&self.group).map(|e| e.epoch)
    }

    fn texts(&self) -> Vec<Vec<u8>> {
        self.posts.iter().map(|p| p.envelope.clone()).collect()
    }

    /// The `platform` of each offer it made.
    fn offers(&self) -> Vec<u8> {
        self.sent
            .iter()
            .filter_map(|m| match m {
                ClientMessage::KeyholdVolunteer {
                    on: true, platform, ..
                } => Some(*platform),
                _ => None,
            })
            .collect()
    }

    fn dues(&self) -> usize {
        self.sent
            .iter()
            .filter(|m| matches!(m, ClientMessage::EpochCommit { last: true, .. }))
            .count()
    }
}

struct World {
    relay: Relay,
    pages: Vec<Browser>,
    last_tick: u64,
}

impl World {
    fn now(&self) -> u64 {
        self.relay.groups.now()
    }

    /// A guest's browser page in a call, following `group`.
    async fn page(&mut self, group: &str) -> usize {
        let ik = voipc_crypto::generate_identity_key_pair();
        let sid = self.relay.session(&ik, None);
        self.relay.follow(sid, group);
        let (b, send) = Browser::new(&self.relay, sid, ik, group);
        for msg in send {
            self.relay.send(sid, msg).await;
        }
        self.pages.push(b);
        self.pages.len() - 1
    }

    async fn post(&mut self, i: usize, id: u8, text: &[u8]) {
        let now = self.now();
        let sid = self.pages[i].sid;
        for msg in self.pages[i].post(id, text, now) {
            self.relay.send(sid, msg).await;
        }
    }

    /// One round: every queue drained into its page, what each sends handed back.
    async fn step(&mut self) {
        let now = self.now();
        let tick = now >= self.last_tick + 1_000;
        for i in 0..self.pages.len() {
            let sid = self.pages[i].sid;
            let frames = self.relay.drain(sid).await;
            let mut send = vec![];
            for f in &frames {
                if tracing_on() {
                    eprintln!("[{now}] page {sid} <- {}", show(f));
                }
                send.extend(self.pages[i].frame(f, now));
            }
            if tick {
                send.extend(self.pages[i].tick(now));
            }
            for msg in send {
                self.relay.send(sid, msg).await;
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

    fn report(&self) -> String {
        let pages: Vec<String> = self
            .pages
            .iter()
            .map(|b| {
                format!(
                    "page {}: offers {:?}, commits {}, epoch {:?}, texts {}",
                    b.sid,
                    b.offers(),
                    b.dues(),
                    b.epoch(),
                    b.posts.len()
                )
            })
            .collect();
        format!("{pages:#?}")
    }
}

/// Two browsers, both in a call and no other keyholder online (T1's browser-only group):
/// both offer as the fallback (`BROWSER_BUSY`), the relay starts the group with one and
/// seats the other, and each reads the other's text under the key.
#[tokio::test]
async fn e2e_j7_two_browsers_in_a_call_hold_the_key_and_read_each_others_text() {
    let mut w = World {
        relay: Relay::new(),
        pages: vec![],
        last_tick: 0,
    };
    let id = w.relay.groups.id_for(CHANNEL, None);
    let alice = w.page(&id).await;
    let bob = w.page(&id).await;
    let keyed = w
        .until(20_000, |w| w.pages.iter().all(|b| b.epoch().is_some()))
        .await;
    assert!(keyed, "both hold the epoch key: {}", w.report());
    for b in &w.pages {
        assert_eq!(b.offers(), [gk::platform::BROWSER_BUSY], "{}", w.report());
    }
    assert!(
        w.pages.iter().any(|b| b.dues() > 0),
        "a page in a call built the commits: {}",
        w.report()
    );

    w.post(alice, 1, b"from alice, in a call").await;
    w.post(bob, 2, b"from bob, in a call").await;
    let read = w
        .until(10_000, |w| {
            w.pages[bob].texts() == [b"from alice, in a call".to_vec()]
                && w.pages[alice].texts() == [b"from bob, in a call".to_vec()]
        })
        .await;
    assert!(read, "each read the other's text: {}", w.report());
    assert!(
        w.relay.post_refusals.is_empty(),
        "{:?}",
        w.relay.post_refusals
    );
}
