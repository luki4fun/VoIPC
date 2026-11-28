//! End-to-end group-key scenarios added by slice V2 (wave 4): voice rooms. The relay's real
//! session path (`handle_connection` over a duplex, as `gk_e2e_r2.rs` serves it: session.rs's
//! arms, state.rs's room hooks, the room's group in `gk`), and every member an app of its own:
//! the clients' real `voipc_crypto::group_state::GroupKeying`, whose keyholder duty (C3c) takes
//! the room's dues on any platform, and whose voice keys (V1) go into a `MediaKeyRing` in
//! group-key mode, as the native and browser hosts install them. Every member is stepped in
//! turn with no slow await between (part 17), so a keyholder meets its deadlines.

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
            relay_clock: wall_ms() / 1000,
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
}

impl World {
    fn new(anonymous: bool) -> World {
        let _ = tracing_on();
        World {
            state: room_state(true, anonymous),
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
        let d = Device::open(&self.state, account, platform, help, self.anonymous).await;
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

/// Three apps in a room: each seated by its connection pair, the two lowest user ids holding
/// the room's keys, and every one opening every other's voice under the key it derives for
/// that sender from the room's epoch key and roster.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_a_three_member_room_derives_equal_media_keys_and_its_two_lowest_hold_the_keys() {
    let mut w = World::new(false);
    for _ in 0..3 {
        w.join(None, Platform::Desktop, true).await;
    }
    assert!(
        w.until(SETTLE_MS, |w| w.settled(&[0, 1, 2])).await,
        "every member hears every other, with two keyholders"
    );
}

/// A member leaves: its seat's exit is covered by an opening within a few seconds, under
/// which the others hear each other; handed every frame a member who stayed got, the leaver
/// still derives no key of that epoch.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_a_leaver_cannot_derive_the_next_epochs_key_while_the_others_hear_each_other() {
    let mut w = World::new(false);
    for _ in 0..3 {
        w.join(None, Platform::Desktop, true).await;
    }
    assert!(w.until(SETTLE_MS, |w| w.settled(&[0, 1, 2])).await);
    let (gen, was) = w.devices[2].epoch().expect("the leaver's epoch");
    let mark = w.devices[1].log.len();
    w.leave(2).await;
    // The epoch the exit asked is the first opening after the leave that seats the two left,
    // not where the two stand once the relay's Load is at rest: the Load shows a commit as
    // soon as its pushes are queued, a step before an app may take them, so the two can
    // still stand on an opening made before the exit, whose key the leaver holds
    let covering = |w: &World| w.devices[1].opening_since(mark, gen, 2);
    assert!(
        w.until(SETTLE_MS, |w| covering(w)
            .is_some_and(|e| w.devices[1].epoch() == Some((gen, e)))
            && w.settled(&[0, 1]))
            .await,
        "an opening covers the exit and the two left hear each other under it"
    );
    let now = covering(&w).unwrap();
    assert!(now > was, "the exit's opening e{now} is past e{was}");
    // A sender moves to the new epoch a moment after taking it (`SWITCH_MS`)
    let sends_now = |w: &World| {
        w.devices[0]
            .ring
            .current()
            .is_some_and(|k| k.key_id == now as u16)
    };
    assert!(w.until(SETTLE_MS, |w| sends_now(w)).await);
    let (stream, key, sid) = {
        let sender = &w.devices[0];
        let k = sender.ring.current().unwrap().key_id;
        (sender.ring.stream_id(), k, sender.sid)
    };
    let had = (
        w.devices[2].epoch(),
        w.devices[2].ring.get_for(ROOM, sid, stream, key).is_some(),
    );
    let seen: Vec<ServerMessage> = w.devices[1].log[mark..].to_vec();
    let leaver = &mut w.devices[2];
    for f in &seen {
        let c = GkCtx {
            pins: &mut leaver.pins,
            now: wall_ms(),
        };
        let out = leaver.keying.frame(&mut leaver.st, f, c);
        let _ = leaver.took(out, wall_ms());
    }
    let after = leaver.epoch().map(|(_, e)| e);
    let why = format!(
        "was e{was}, now e{now}; the leaver before the frames: epoch {:?}, media key {}; \
         after: epoch {after:?}; the leaver was sent {:?}; the member who stayed {:?}",
        had.0.map(|(_, e)| e),
        had.1,
        w.devices[2].trail(),
        w.devices[1].trail()
    );
    let leaver = &mut w.devices[2];
    assert!(
        leaver.epoch().is_none_or(|(_, e)| e < now),
        "the leaver holds no key of the epoch its exit asked; {why}"
    );
    // Its head is that epoch's once it took the frames (`epoch()` is then none): nor does
    // it hold that epoch's key below its head
    let group = leaver.group.clone();
    assert!(
        !matches!(
            leaver.keying.past_epoch(&group, gen, now),
            PastEpoch::Ready(_)
        ),
        "nor below its head; {why}"
    );
    assert!(
        leaver.ring.get_for(ROOM, sid, stream, key).is_none(),
        "nor a media key for a packet under it; {why}"
    );
}

/// Both keyholders leave: the lowest user id left makes a Genesis at once, the relay seats
/// every member whose pair it holds, and the room hears again under a new generation within
/// a bound, with two keyholders again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_both_keyholders_leave_and_the_room_hears_again_under_a_new_generation() {
    let mut w = World::new(false);
    for _ in 0..4 {
        w.join(None, Platform::Desktop, true).await;
    }
    assert!(w.until(SETTLE_MS, |w| w.settled(&[0, 1, 2, 3])).await);
    let (gen, _) = w.devices[2].epoch().unwrap();
    w.leave(0).await;
    w.leave(1).await;
    let left = wall_ms();
    assert!(
        w.until(SETTLE_MS, |w| {
            w.devices[2].epoch().is_some_and(|(g, _)| g != gen)
                && w.devices[3].epoch().is_some_and(|(g, _)| g != gen)
                && w.all_hear(&[2, 3])
        })
        .await,
        "a new generation seats both who stayed"
    );
    let took = wall_ms() - left;
    assert!(took < 10_000, "voice came back in {took} ms");
    assert!(
        w.until(SETTLE_MS, |w| w.settled(&[2, 3])).await,
        "both who stayed hold the keys"
    );
}

/// A voice kick (to the lobby) exits the kicked member's seat: an opening covers it, under
/// which the others hear each other, and the kicked member's app, still taking what the
/// relay sent it before the kick, holds no key of that epoch nor a media key under it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_a_voice_kick_exits_the_seat_and_the_others_move_to_an_epoch_it_cannot_derive() {
    let mut w = World::new(false);
    for _ in 0..3 {
        w.join(None, Platform::Desktop, true).await;
    }
    assert!(w.until(SETTLE_MS, |w| w.settled(&[0, 1, 2])).await);
    let (gen, was) = w.devices[2].epoch().unwrap();
    let admin = ClientMessage::AdminLogin {
        token: "test-admin-token".into(),
    };
    w.devices[0].conn.send(&admin).await;
    let target = w.devices[2].sid;
    let kick = ClientMessage::KickUser {
        channel_id: ROOM,
        user_id: target,
    };
    let mark = w.devices[0].log.len();
    w.devices[0].conn.send(&kick).await;
    // The kick's opening: the first after it that seats the two left (as the leaver's above:
    // the relay's Load at rest does not say the others took it yet). A push sent before the
    // kick may still move the kicked app past `was`, never to that epoch
    let covering = |w: &World| w.devices[0].opening_since(mark, gen, 2);
    assert!(
        w.until(SETTLE_MS, |w| covering(w)
            .is_some_and(|e| w.devices[0].epoch() == Some((gen, e)))
            && w.settled(&[0, 1]))
            .await,
        "an opening covers the kicked seat"
    );
    assert!(w.devices[2]
        .log
        .iter()
        .any(|f| matches!(f, ServerMessage::Kicked { channel_id, .. } if *channel_id == ROOM)));
    let now = covering(&w).unwrap();
    assert!(now > was, "the kick's opening e{now} is past e{was}");
    let sends_now = |w: &World| {
        w.devices[1]
            .ring
            .current()
            .is_some_and(|k| k.key_id == now as u16)
    };
    assert!(w.until(SETTLE_MS, |w| sends_now(w)).await);
    assert!(
        w.devices[2].epoch().is_none_or(|(_, e)| e < now),
        "the kicked app holds no key of the epoch that covered it"
    );
    let sender = &w.devices[1];
    let (stream, key) = (
        sender.ring.stream_id(),
        sender.ring.current().unwrap().key_id,
    );
    let sid = sender.sid;
    assert!(
        w.devices[2].ring.get_for(ROOM, sid, stream, key).is_none(),
        "nor a media key for a packet under it"
    );
}

/// The member that made the room's Genesis leaves once another holds the keys: its removal
/// rolls the seed, the next lowest is promoted, and a later joiner takes the head from the
/// keyholders that are left, in the same generation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_a_joiner_of_a_room_whose_genesis_signer_left_takes_the_head() {
    let mut w = World::new(false);
    for _ in 0..3 {
        w.join(None, Platform::Desktop, true).await;
    }
    assert!(w.until(SETTLE_MS, |w| w.settled(&[0, 1, 2])).await);
    let (gen, _) = w.devices[1].epoch().unwrap();
    let seed = w.devices[1].headers().last().unwrap().seed;
    w.leave(0).await;
    assert!(
        w.until(SETTLE_MS, |w| w.settled(&[1, 2])).await,
        "the starter's entry is removed and the other member promoted"
    );
    let removal = w.devices[2]
        .headers()
        .into_iter()
        .find(|h| h.kind == Kind::KeyholdersRemove)
        .expect("its removal");
    assert_eq!(removal.seed, seed + 1, "which rolled the seed");
    let j = w.join(None, Platform::Desktop, true).await;
    assert!(
        w.until(SETTLE_MS, |w| w.settled(&[1, 2, j])).await,
        "the joiner hears and is heard"
    );
    assert_eq!(w.devices[j].epoch().unwrap().0, gen, "the same generation");
}

/// A connection that ends takes its voice seat with it, a signed-in member's too; a
/// keyholder's end removes its entry, and the room hears again with two keyholders.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_a_disconnect_exits_the_voice_seat_and_a_keyholders_brings_its_removal() {
    let mut w = World::new(false);
    w.join(None, Platform::Desktop, true).await;
    w.join(None, Platform::Desktop, true).await;
    w.join(Some([0xc3; 16]), Platform::Desktop, true).await;
    w.join(None, Platform::Desktop, true).await;
    assert!(w.until(SETTLE_MS, |w| w.settled(&[0, 1, 2, 3])).await);
    let (gen, was) = w.devices[3].epoch().unwrap();
    // The account's connection ends: no session holds its seat, which exits
    drop(w.devices.remove(2));
    assert!(
        w.until(SETTLE_MS, |w| w.settled(&[0, 1, 2])
            && w.devices[2]
                .epoch()
                .is_some_and(|(g, e)| g == gen && e > was))
            .await,
        "an opening covers the account's seat"
    );
    // A keyholder's connection ends: its entry is removed, the next lowest promoted
    drop(w.devices.remove(0));
    assert!(
        w.until(SETTLE_MS, |w| w.settled(&[0, 1])).await,
        "two keyholders again, and the two left hear each other"
    );
}

/// A room of phones and browsers, none of which offers to hold text keys: its members hold
/// the room's keys all the same (§5.6), and hear each other.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_a_room_of_phones_and_browsers_gets_keyholders_and_hears() {
    let mut w = World::new(false);
    w.join(None, Platform::Phone, false).await;
    w.join(None, Platform::Browser, false).await;
    w.join(None, Platform::Phone, true).await;
    assert!(
        w.until(SETTLE_MS, |w| w.settled(&[0, 1, 2])).await,
        "phones and browsers hold the keys and hear each other"
    );
}

/// An anonymous room that is not gated names every seat by its connection, signed in or
/// not: the roster every member is told, and each post's writer, name no account, and a
/// post goes under the writer's pseudonym.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_an_anonymous_rooms_roster_and_posts_name_no_account() {
    let mut w = World::new(true);
    w.join(None, Platform::Desktop, true).await;
    let a = w.join(Some([0xa1; 16]), Platform::Desktop, true).await;
    let b = w.join(Some([0xb2; 16]), Platform::Desktop, true).await;
    let ids: Vec<UserId> = w.devices.iter().map(|d| d.sid).collect();
    let rostered = |d: &Device| {
        let mut seen: Vec<UserId> = d
            .log
            .iter()
            .filter_map(|f| match f {
                ServerMessage::VoiceSeats { piece, .. } => Some(piece.seats.clone()),
                _ => None,
            })
            .flatten()
            .map(|(u, _)| u)
            .collect();
        seen.sort_unstable();
        seen.dedup();
        seen
    };
    assert!(
        w.until(SETTLE_MS, |w| w.devices[0].epoch().is_some()
            && w.devices.iter().all(|d| rostered(d) == ids))
            .await,
        "every member is told every seat, its own among them"
    );
    for d in &w.devices {
        for f in &d.log {
            if let ServerMessage::VoiceSeats { piece, .. } = f {
                for (u, seat) in &piece.seats {
                    assert_eq!(seat.m, GkMember::Conn(*u), "a seat named by its connection");
                }
            }
        }
    }
    // A post in the room's chat under its head epoch, as the writer's app sends one
    let (gen, epoch) = w.devices[0].epoch().unwrap();
    let post = ClientMessage::EpochPost {
        channel_id: ROOM,
        group: w.devices[a].group.clone(),
        gen,
        epoch,
        blob: None,
        ciphertext: b"anonymous".to_vec(),
    };
    w.devices[a].conn.send(&post).await;
    let writer = w.devices[a].sid;
    let (real, _) = w.state.names_of_in(ROOM, writer).await;
    let got = |d: &Device| {
        d.log.iter().find_map(|f| match f {
            ServerMessage::EpochPostIn {
                user_id,
                username,
                account,
                writer,
                ..
            } if *user_id == ids[a] => Some((username.clone(), *account, *writer)),
            _ => None,
        })
    };
    assert!(
        w.until(SETTLE_MS, |w| got(&w.devices[0]).is_some()
            && got(&w.devices[b]).is_some())
            .await,
        "the post reaches the room"
    );
    for d in [&w.devices[0], &w.devices[b]] {
        let (name, account, by) = got(d).unwrap();
        assert_eq!((account, by), (None, GkMember::Conn(writer)));
        assert_ne!(name, real, "under its pseudonym");
    }
}

/// With the key on, a voice room's old key paths (`DistributeMediaKey`,
/// `DistributeSenderKey`, `SendEncryptedChannelMessage`) reach nobody, and the app is told
/// once; with it off they go as before.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_a_voice_rooms_old_key_paths_are_refused_with_the_key_on_only() {
    for on in [true, false] {
        let state = room_state(on, false);
        let ik = [generate_identity_key_pair(), generate_identity_key_pair()];
        let mut a = Conn::open(&state, "a", &ik[0]).await;
        let mut b = Conn::open(&state, "b", &ik[1]).await;
        for c in [&mut a, &mut b] {
            let join = ClientMessage::JoinChannel {
                channel_id: ROOM,
                password: None,
            };
            c.send(&join).await;
            c.settled().await;
        }
        let old = [
            ClientMessage::DistributeMediaKey {
                channel_id: ROOM,
                target_user_id: b.sid,
                encrypted_media_key: vec![1; 64],
                message_type: 2,
            },
            ClientMessage::DistributeSenderKey {
                channel_id: ROOM,
                target_user_id: b.sid,
                distribution_message: vec![2; 64],
                message_type: 2,
            },
            ClientMessage::SendEncryptedChannelMessage {
                channel_id: ROOM,
                ciphertext: vec![3; 64],
            },
        ];
        for m in &old {
            a.send(m).await;
        }
        let told = a.settled().await;
        let refused = told
            .iter()
            .filter(|f| {
                matches!(
                    f,
                    ServerMessage::EpochRefused {
                        what: refused_what::LEGACY,
                        why: refused_why::LEGACY_PATH,
                        ..
                    }
                )
            })
            .count();
        let reached = b.settled().await.iter().any(|f| {
            matches!(
                f,
                ServerMessage::EncryptedChannelChatMessage { .. }
                    | ServerMessage::MediaKeyReceived { .. }
                    | ServerMessage::SenderKeyReceived { .. }
            )
        });
        assert_eq!((refused, reached), (usize::from(on), !on), "key on: {on}");
    }
}

/// A room turned anonymous with signed-in members in it names their seats by their
/// connections at once (open choice 11): every member is told each seat under its new name,
/// and a newcomer is told no account. The renamed seats are seated and heard though the
/// keyholders still track the room as it was: the rename's due can reach them before the
/// flip's `ChannelUpdated` (at once from 256 renamed seats), and a refused member does not
/// fetch again, so the joiner check does not hang on the room's flag.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_an_anonymous_flip_renames_every_seat_before_a_newcomer_looks() {
    let mut w = World::new(false);
    for a in [0xa1, 0xb2, 0xc3] {
        w.join(Some([a; 16]), Platform::Desktop, true).await;
    }
    assert!(w.until(SETTLE_MS, |w| w.settled(&[0, 1, 2])).await);
    let marks: Vec<usize> = w.devices.iter().map(|d| d.log.len()).collect();
    let anonymous = voipc_protocol::types::ChannelOptions {
        anonymous: Some(true),
        ..Default::default()
    };
    w.state
        .set_channel_options(ROOM, 0, anonymous, true)
        .await
        .expect("the flip");
    w.anonymous = true;
    let ids: Vec<UserId> = w.devices.iter().map(|d| d.sid).collect();
    let renamed = |w: &World| {
        w.devices.iter().zip(&marks).all(|(d, m)| {
            let mut told: Vec<UserId> = d.log[*m..]
                .iter()
                .filter_map(|f| match f {
                    ServerMessage::VoiceSeats { piece, .. } => Some(piece.seats.clone()),
                    _ => None,
                })
                .flatten()
                .filter(|(u, s)| s.m == GkMember::Conn(*u))
                .map(|(u, _)| u)
                .collect();
            told.sort_unstable();
            told.dedup();
            told == ids
        })
    };
    assert!(
        w.until(SETTLE_MS, |w| renamed(w)).await,
        "every member is told every seat by its connection"
    );
    let j = w.join(None, Platform::Desktop, true).await;
    let whole = |w: &World| {
        w.devices[j].log.iter().any(|f| {
            matches!(f, ServerMessage::VoiceSeats { piece, .. } if piece.whole && piece.seats.len() == 4)
        })
    };
    assert!(
        w.until(SETTLE_MS, |w| whole(w)).await,
        "the newcomer's roster"
    );
    for f in &w.devices[j].log {
        if let ServerMessage::VoiceSeats { piece, .. } = f {
            for (u, seat) in &piece.seats {
                assert_eq!(seat.m, GkMember::Conn(*u), "no account behind a pseudonym");
            }
        }
    }
    assert!(
        w.until(SETTLE_MS, |w| w.settled(&[0, 1, 2, j])).await,
        "the renamed seats are seated and heard by keyholders not told of the flip"
    );
}

/// Signed-in members of an anonymous room that is not gated sit by their connections and
/// hear each other: the keyholder's joiner check (`joiner_why`) takes a voice seat named by a
/// connection whose pair carries its account's counter, not a guest's counter 0.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_an_anonymous_rooms_signed_in_members_sit_by_connection_and_hear() {
    let mut w = World::new(true);
    w.join(None, Platform::Desktop, true).await;
    w.join(Some([0xa1; 16]), Platform::Desktop, true).await;
    w.join(Some([0xb2; 16]), Platform::Desktop, true).await;
    assert!(w.until(SETTLE_MS, |w| w.settled(&[0, 1, 2])).await);
}
