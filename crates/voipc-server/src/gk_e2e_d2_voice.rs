//! Dive 2 (keyholder liveness, 2026-11-25), voice rooms: F2 in a room. New file, product
//! code unchanged. The harness is `gk_e2e_v2.rs`'s, copied (its items are private to that
//! module): a relay without accounts, one voice room, each member a real app's group keying
//! on its own connection, real time. Changed here: an app may join with its device's clock
//! ahead of the relay's (`World::clock_ahead`). The tests are at the end of the file.
#![allow(dead_code, unused_imports)]

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use voipc_crypto::group_key::{GroupKind, HeaderV1, Kind, SeatKeys, SignedHeader};
use voipc_crypto::group_state::{
    group_id, GkCtx, GkOut, GkStart, GkTrack, GroupKeying, MemoryPins, OpenedPost, PastEpoch,
    Platform, VaultFloor,
};
use voipc_crypto::{
    build_aad, generate_identity_key_pair, media_decrypt, media_encrypt, MediaKeyRing, SignalStores,
};
use voipc_protocol::gk::{refused_what, refused_why, GkMember};
use voipc_protocol::messages::{ClientMessage, ServerMessage};
use voipc_protocol::types::{ChannelId, GroupLoad, UserId};

use crate::channels::ChannelEntry;
use crate::config::ServerConfig;
use crate::gk_e2e_r2::Conn;
use crate::gk_e2e_tests::{account_session, tracing_on};
use crate::settings::ServerSettings;
use crate::state::ServerState;

/// The one voice room.
const ROOM: ChannelId = 1;

/// How long a scenario may take to settle before a test calls it failed.
const SETTLE_MS: u64 = 30_000;

fn wall_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// A relay with the group key `on`, no accounts, and voice room `ROOM`.
fn room_state(on: bool, anonymous: bool) -> Arc<ServerState> {
    let room = ChannelEntry {
        name: "room".into(),
        anonymous,
        ..Default::default()
    };
    Arc::new(ServerState::new(
        &ServerConfig {
            group_key: on,
            ..ServerConfig::default()
        },
        ServerSettings::default(),
        vec![room],
        "test-admin-token".into(),
    ))
}

// ── A member's app ───────────────────────────────────────────────────────

/// One app in the room: its connection, its group keying and its media ring.
struct Device {
    conn: Conn,
    sid: UserId,
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
    /// sign-in, its seat keys made), as a `platform` app with "Help hold keys" `help`.
    async fn open(
        state: &Arc<ServerState>,
        account: Option<[u8; 16]>,
        platform: Platform,
        help: bool,
        anonymous: bool,
        clock_ahead: i64,
    ) -> Device {
        let ik = generate_identity_key_pair();
        let name = format!("v{}", rand::random::<u32>());
        let conn = Conn::open(state, &name, &ik).await;
        let sid = conn.sid;
        if let Some(a) = account {
            state.sessions.get_mut(&sid).unwrap().account = Some(account_session(a));
        }
        let mut keying = GroupKeying::default();
        let out = keying.start(GkStart {
            on: conn.on,
            run: conn.run,
            // `Duty::start` reads this against the device's own clock: a device whose clock
            // runs `clock_ahead` seconds ahead sees the relay's that far behind its own
            relay_clock: (wall_ms() as i64 / 1000 - clock_ahead) as u64,
            platform,
            help_hold_keys: help,
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

    /// The head epoch this app holds the key of: generation and epoch.
    fn epoch(&self) -> Option<([u8; 16], u32)> {
        self.keying
            .current_epoch(&self.group)
            .map(|e| (e.gen, e.epoch))
    }

    /// Every header the relay sent it, in order.
    fn headers(&self) -> Vec<HeaderV1> {
        self.headers_from(0)
    }

    /// The epoch an exit asked, by the headers it was sent from `log[from..]`: the first
    /// opening of generation `gen` that seats `seats`.
    fn opening_since(&self, from: usize, gen: [u8; 16], seats: u32) -> Option<u32> {
        self.headers_from(from)
            .iter()
            .find(|h| h.gen == gen && h.kind.opens_epoch() && h.seats == seats)
            .map(|h| h.epoch)
    }

    /// Every header the relay sent it from `log[from..]`, in order.
    fn headers_from(&self, from: usize) -> Vec<HeaderV1> {
        let mut hs = vec![];
        for f in &self.log[from..] {
            let ServerMessage::EpochIn { piece, .. } = f else {
                continue;
            };
            let links = piece.walk.iter().chain(&piece.head).map(|l| &l.header);
            for h in piece.chain.iter().chain(links) {
                if let Ok(sh) = SignedHeader::decode(&h.body, &h.sig, GroupKind::Voice, &self.group)
                {
                    hs.push(sh.header().clone());
                }
            }
        }
        hs
    }

    /// The headers it was sent, shortly (kind, epoch, join, exits covered, seats), for a
    /// failure's message.
    fn trail(&self) -> Vec<String> {
        self.headers()
            .iter()
            .map(|h| {
                format!(
                    "{:?} e{} j{} upto{} seats{}",
                    h.kind, h.epoch, h.join, h.exits_upto, h.seats
                )
            })
            .collect()
    }

    /// Whether the relay told it the room's roster.
    fn roomed(&self) -> bool {
        self.log
            .iter()
            .any(|f| matches!(f, ServerMessage::UserList { channel_id, .. } if *channel_id == ROOM))
    }
}

/// Whether `to` opens a voice packet `from` sends now, under the key `from` sends with: the
/// one its ring derives for itself, the other's from the room's roster.
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

// ── The world ─────────────────────────────────────────────────────────────

/// `GK_E2E_LAG_MS=<ms>`: each step's check waits this long first. The relay takes a commit
/// sent in the step meanwhile and shows it in its Load before any app took the push, as it
/// does now and then when the test's thread is slow: soak controls widen that window with it.
async fn lag() {
    static MS: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    let ms = *MS.get_or_init(|| {
        std::env::var("GK_E2E_LAG_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    });
    if ms > 0 {
        tokio::time::sleep(Duration::from_millis(ms)).await;
    }
}

struct World {
    state: Arc<ServerState>,
    devices: Vec<Device>,
    anonymous: bool,
    /// How far the clock of the next app to join runs ahead of the relay's, seconds.
    clock_ahead: i64,
}

impl World {
    fn new(anonymous: bool) -> World {
        let _ = tracing_on();
        World {
            state: room_state(true, anonymous),
            devices: vec![],
            anonymous,
            clock_ahead: 0,
        }
    }

    async fn step(&mut self) {
        let now = wall_ms();
        for d in &mut self.devices {
            d.step(now).await;
        }
    }

    /// Steps every app until `done` or `ms` passed; whether it was done.
    async fn until(&mut self, ms: u64, mut done: impl FnMut(&mut World) -> bool) -> bool {
        let end = wall_ms() + ms;
        while wall_ms() < end {
            self.step().await;
            lag().await;
            if done(self) {
                return true;
            }
        }
        false
    }

    /// A new app, `account`'s where given, joins the room and tracks its group once its
    /// roster comes; its index.
    async fn join(&mut self, account: Option<[u8; 16]>, platform: Platform, help: bool) -> usize {
        let ahead = self.clock_ahead;
        let d = Device::open(&self.state, account, platform, help, self.anonymous, ahead).await;
        self.devices.push(d);
        let i = self.devices.len() - 1;
        let join = ClientMessage::JoinChannel {
            channel_id: ROOM,
            password: None,
        };
        self.devices[i].conn.send(&join).await;
        assert!(
            self.until(SETTLE_MS, |w| w.devices[i].roomed()).await,
            "the join was confirmed"
        );
        let send = self.devices[i].track(wall_ms());
        self.devices[i].send_all(send).await;
        i
    }

    /// `i` goes back to the lobby: out of the room, its app still holding what it held.
    async fn leave(&mut self, i: usize) {
        let lobby = ClientMessage::JoinChannel {
            channel_id: 0,
            password: None,
        };
        self.devices[i].conn.send(&lobby).await;
    }

    /// Whether each of `who` hears each other.
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
    /// one of them seated, on one head epoch, and heard by every other.
    fn settled(&mut self, who: &[usize]) -> bool {
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
            && who.iter().all(|&i| self.devices[i].epoch() == e)
            && self.all_hear(who)
    }

    /// The room's group as the relay's Load shows it.
    fn room(&self) -> Option<GroupLoad> {
        self.state
            .gk
            .stats()
            .into_iter()
            .find(|g| g.channel_id == ROOM)
    }
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

// ── Scenarios ─────────────────────────────────────────────────────────────

// ── Dive 2 scenarios ──────────────────────────────────────────────────────

/// Three guests in a room: `a` (the lowest user id) starts it and holds its keys, `b` joins
/// next and is promoted beside it, `c` joins third. `b`'s device clock runs `b_ahead` seconds
/// ahead of the relay's. Then `a` leaves the room and `d` joins. Whether `c` and `d` hear
/// each other within `wait_ms`; the world, and the indices of b, c and d.
async fn room_after_the_first_keyholder_left(
    b_ahead: i64,
    wait_ms: u64,
) -> (bool, World, [usize; 3]) {
    let mut w = World::new(false);
    let a = w.join(None, Platform::Desktop, true).await;
    w.clock_ahead = b_ahead;
    let b = w.join(None, Platform::Desktop, true).await;
    w.clock_ahead = 0;
    let c = w.join(None, Platform::Desktop, true).await;
    let ready = w
        .until(SETTLE_MS, |w| {
            w.room().is_some_and(|g| g.keyholders == 2 && g.seats == 3) && w.all_hear(&[a, b, c])
        })
        .await;
    assert!(
        ready,
        "a, b and c hear each other and two of them hold the keys: {:?}",
        w.room()
    );
    w.leave(a).await;
    let d = w.join(None, Platform::Desktop, true).await;
    let heard = w.until(wait_ms, |w| w.all_hear(&[c, d])).await;
    (heard, w, [b, c, d])
}

/// The control: every clock is right. After `a` left, `d` joins and hears `c`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn d2_control_a_newcomer_hears_the_room_after_the_first_keyholder_left() {
    let (heard, w, _) = room_after_the_first_keyholder_left(0, SETTLE_MS).await;
    assert!(heard, "d and c hear each other: {:?}", w.room());
}

/// F2 in a voice room. `b`'s clock is 6 minutes ahead. The relay promotes `b` all the same (a
/// promotion needs nothing from the candidate), and `b`'s app declines every due it is asked
/// (`CLOCK`). While `a` is there, `a` signs. Once `a` leaves the room, `b` is the only
/// keyholder online: `a`'s removal, `d`'s seat and every later change wait on a signature
/// `b` refuses, and the relay starts a room anew only when no keyholder is online. So `d`
/// gets no key: it hears nobody and nobody hears it, for as long as `b` stays in the room.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn d2_f2_a_newcomer_hears_the_room_though_the_keyholder_left_in_it_has_a_clock_six_minutes_off(
) {
    let (heard, mut w, [b, c, d]) = room_after_the_first_keyholder_left(6 * 60, 75_000).await;
    let room = w.room();
    let d_epoch = w.devices[d].epoch().is_some();
    // What ends it: b leaves the room
    let mut after_b_left = false;
    if !heard {
        w.leave(b).await;
        after_b_left = w.until(SETTLE_MS, |w| w.all_hear(&[c, d])).await;
    }
    assert!(
        heard,
        "d joined a room whose only keyholder left in it has its clock 6 min ahead, and did \
         not hear c (nor c it) within 75 s: the room on the relay {room:?}; d holds an epoch \
         key: {d_epoch}; after b left the room, c and d hear each other: {after_b_left}"
    );
}
