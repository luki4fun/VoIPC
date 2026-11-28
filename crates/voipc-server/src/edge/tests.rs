use super::*;

use std::net::Ipv4Addr;

use bytes::BytesMut;
use serde::Serialize;
use voipc_protocol::pool::{
    decode_edge_msg, decode_edge_view_msg, encode_core_msg, encode_viewer_msg, CoreMsg,
    EdgeViewMsg, ViewerMsg, MAX_POOL_FRAME, POOL_PATH, POOL_VERSION,
};
use voipc_protocol::video::{RecordReader, ScreenShareAudioPacket, VideoPacket};

const SECRET: &str = "edge-one-secret-of-at-least-32-chars";
const OTHER: &str = "edge-two-secret-of-at-least-32-chars";
/// The test link's id, and the core's clock when it welcomed the edge.
const LINK: u64 = 0x5eed_0001;
const WELCOME_MS: u64 = 1_000;
/// What a wait for something that must come allows: past it the edge hung, a slow machine
/// is not.
const HANG: Duration = Duration::from_secs(60);
const VIEWER: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

fn settings(max_viewers: u32, max_shares: u32) -> Settings {
    Settings {
        core_host: "127.0.0.1".into(),
        core_port: 9987,
        core_pin: Some([0; 32]),
        name: "e1".into(),
        secret: SECRET.into(),
        bind: "127.0.0.1:0".parse().unwrap(),
        public_host: "127.0.0.1".into(),
        public_port: 9991,
        max_viewers,
        egress_mbit: 8000,
        max_shares,
        max_connections_per_ip: 32,
    }
}

/// An edge with these limits, linked as `LINK` at `t0` (the core's clock then at
/// `WELCOME_MS`), with no connection: what it tells its core arrives on the queue.
fn linked(max_viewers: u32, max_shares: u32, t0: Instant) -> (Edge, mpsc::Receiver<EdgeMsg>) {
    let settings = settings(max_viewers, max_shares);
    let limits = Arc::new(ConnLimits::new(
        max_viewers + SETUP_ROOM,
        settings.max_connections_per_ip,
    ));
    let edge = Edge::new(&settings, limits);
    let (tx, rx) = mpsc::channel(1024);
    edge.link_up(LINK, WELCOME_MS, tx, None, t0);
    (edge, rx)
}

/// The ticket of `slot` for `share` on `link`, made at `made_ms` on the core's clock.
fn ticket(link: u64, share: SessionId, slot: u64, made_ms: u64) -> Vec<u8> {
    pool_keys::seal(
        &pool_keys::ticket_key(SECRET),
        &pool_keys::mint(link, share, slot, made_ms),
    )
}

/// What the edge told its core since the last look.
fn told(core: &mut mpsc::Receiver<EdgeMsg>) -> Vec<EdgeMsg> {
    let mut said = Vec::new();
    while let Ok(msg) = core.try_recv() {
        said.push(msg);
    }
    said
}

fn fragment(key: bool, share: SessionId, frame: u32, index: u8, count: u8) -> Bytes {
    VideoPacket::encrypted_fragment(key, share, frame, index, count, 0, 1, 0x5EED, vec![9; 16])
        .to_bytes()
        .into()
}

/// A whole frame of `count` fragments.
fn frame(key: bool, share: SessionId, id: u32, count: u8) -> Vec<Bytes> {
    (0..count)
        .map(|i| fragment(key, share, id, i, count))
        .collect()
}

fn audio(share: SessionId) -> Bytes {
    ScreenShareAudioPacket::new_encrypted(share, 1, 0, 1, 0x5EED, vec![7; 40])
        .to_bytes()
        .into()
}

/// Packets as a frame stream carries them: each behind its u16-BE length.
fn records(packets: &[Bytes]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for packet in packets {
        bytes.extend_from_slice(&(packet.len() as u16).to_be_bytes());
        bytes.extend_from_slice(packet);
    }
    bytes
}

// ── edge.toml ──────────────────────────────────────────────────────────

const MINIMAL: &str = r#"
core = "relay.example.org:9987"
name = "e1"
secret = "edge-one-secret-of-at-least-32-chars"
public = "edge1.example.org:9987"
"#;

fn base() -> EdgeConfig {
    toml::from_str(MINIMAL).unwrap()
}

/// `base()` changed by `change`, checked: what is wrong with it, or `None`.
fn wrong(change: impl FnOnce(&mut EdgeConfig)) -> Option<String> {
    let mut config = base();
    change(&mut config);
    config.check().err().map(|e| format!("{e:#}"))
}

#[test]
fn an_edge_toml_needs_its_core_its_name_and_secret_and_its_address_and_defaults_the_rest() {
    let settings = base().check().unwrap();
    assert_eq!(
        (settings.core_host.as_str(), settings.core_port),
        ("relay.example.org", 9987)
    );
    assert_eq!(settings.core_pin, None, "the public CAs vouch for the core");
    assert_eq!(settings.bind, "[::]:9987".parse().unwrap());
    assert_eq!(
        (settings.public_host.as_str(), settings.public_port),
        ("edge1.example.org", 9987)
    );
    assert_eq!(
        (
            settings.max_viewers,
            settings.egress_mbit,
            settings.max_shares,
            settings.max_connections_per_ip
        ),
        (1000, 8000, 16, 32)
    );
    assert!(
        toml::from_str::<EdgeConfig>(&format!("{MINIMAL}max_viewer = 5\n")).is_err(),
        "a typo fails the start instead of meaning a default"
    );
    for key in ["core", "name", "secret", "public"] {
        let without: String = MINIMAL
            .lines()
            .filter(|line| !line.starts_with(&format!("{key} =")))
            .map(|line| format!("{line}\n"))
            .collect();
        assert!(
            toml::from_str::<EdgeConfig>(&without).is_err(),
            "{key} has a default"
        );
    }
}

#[test]
fn an_edge_toml_is_checked_before_the_edge_starts() {
    let printed = "AB:".repeat(31) + "CD";
    let has = |change: fn(&mut EdgeConfig), words: &str| {
        let why = wrong(change).unwrap_or_else(|| panic!("taken, expected {words:?}"));
        assert!(why.contains(words), "{why:?} does not say {words:?}");
    };
    has(|c| c.core = "relay.example.org".into(), "core:");
    has(
        |c| c.core = "relay.example.org:0".into(),
        "port must not be 0",
    );
    has(|c| c.core = "::1:9987".into(), "brackets");
    has(
        |c| c.core = "relay_example.org:9987".into(),
        "not a DNS name",
    );
    has(|c| c.core = "[::1]:9987".into(), "core_fingerprint");
    has(|c| c.core = "192.0.2.1:9987".into(), "core_fingerprint");
    has(|c| c.core_fingerprint = Some("AB:CD".into()), "32 bytes");
    has(|c| c.core_fingerprint = Some("zz".repeat(32)), "32 bytes");
    has(|c| c.name = "E1".into(), "a-z");
    has(|c| c.name = "e".repeat(33), "a-z");
    has(|c| c.secret = "s".repeat(31), "at least 32");
    has(|c| c.udp_port = 0, "udp_port");
    has(|c| c.public = "edge1.example.org".into(), "public:");
    has(
        |c| c.public = "-edge.example.org:9987".into(),
        "not a DNS name",
    );
    has(|c| c.max_viewers = 0, "at least 1");
    has(|c| c.egress_mbit = 0, "at least 1");
    has(|c| c.max_shares = 0, "1 to 64");
    has(|c| c.max_shares = 65, "1 to 64");
    has(|c| c.max_connections_per_ip = 1, "at least 2");

    // The fingerprint as `cert fingerprint` prints it, or bare; an IP core with one
    let pinned = |core: &str, fingerprint: &str| {
        let mut config = base();
        config.core = core.into();
        config.core_fingerprint = Some(fingerprint.into());
        config.check().unwrap()
    };
    let settings = pinned("[::1]:9987", &printed);
    assert_eq!(settings.core_host, "::1");
    let mut expected = [0xAB; 32];
    expected[31] = 0xCD;
    assert_eq!(settings.core_pin, Some(expected));
    let bare = pinned("192.0.2.1:9987", &printed.replace(':', "").to_lowercase());
    assert_eq!(bare.core_pin, Some(expected));
    // Viewers may be sent to an IPv6 address, without its brackets
    let mut config = base();
    config.public = "[2001:db8::1]:9991".into();
    config.max_shares = 64;
    config.max_connections_per_ip = 2;
    let settings = config.check().unwrap();
    assert_eq!(
        (settings.public_host.as_str(), settings.public_port),
        ("2001:db8::1", 9991)
    );
}

#[test]
fn a_printed_edge_toml_shows_no_secret() {
    let printed = format!("{:?}", base());
    assert!(printed.contains("e1"), "{printed}");
    assert!(printed.contains("<secret>"), "{printed}");
    assert!(!printed.contains(SECRET), "{printed}");
}

/// toml's own message quotes the line it stopped on, so an edge.toml whose secret line is
/// mistyped would print the secret, and under systemd into the journal.
#[test]
fn a_mistyped_edge_toml_says_where_and_never_shows_the_secret() {
    let quoted = format!("\"{SECRET}\"");
    for wrong in [
        format!("\"{SECRET}"),
        format!("{quoted} {quoted}"),
        SECRET.to_string(),
    ] {
        let text = MINIMAL.replace(&quoted, &wrong);
        let error = format!(
            "{:#}",
            crate::config::parse::<EdgeConfig>(&text).unwrap_err()
        );
        assert!(!error.contains(SECRET), "{error}");
        assert!(error.contains("line 4"), "{error}");
    }
}

// ── Tickets ────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_good_ticket_lets_a_viewer_in_and_asks_the_core_for_its_share() {
    let t0 = Instant::now();
    let (edge, mut core) = linked(10, 4, t0);
    let first = edge
        .admit(&ticket(LINK, 7, 1, WELCOME_MS), VIEWER, t0)
        .unwrap();
    assert_eq!(first.share, 7);
    assert_eq!(
        told(&mut core),
        [
            EdgeMsg::Subscribe { share: 7 },
            EdgeMsg::KeyframeWanted { share: 7 }
        ]
    );
    // A second viewer of it: the share is asked for once, its keyframe at most once a second
    let _second = edge
        .admit(&ticket(LINK, 7, 2, WELCOME_MS), VIEWER, t0 + ms(100))
        .unwrap();
    assert_eq!(told(&mut core), []);
    edge.tick(t0 + ms(999));
    assert_eq!(told(&mut core), []);
    edge.tick(t0 + ms(1_000));
    assert_eq!(told(&mut core), [EdgeMsg::KeyframeWanted { share: 7 }]);
    assert_eq!(edge.carried(), (2, 1));
    assert_eq!(
        edge.limits.total.load(Ordering::Relaxed),
        2,
        "both count in the main pool"
    );
}

#[tokio::test]
async fn a_ticket_of_another_link_is_refused() {
    let t0 = Instant::now();
    let (edge, _core) = linked(10, 4, t0);
    assert_eq!(
        edge.admit(&ticket(LINK + 1, 7, 1, WELCOME_MS), VIEWER, t0)
            .err(),
        Some("another link")
    );
    // A ticket of this link, once it is lost: not before the next Welcome, nor after it
    let before = ticket(LINK, 7, 2, WELCOME_MS);
    edge.link_lost(LINK);
    assert_eq!(edge.admit(&before, VIEWER, t0).err(), Some("another link"));
    let (tx, _next) = mpsc::channel(16);
    edge.link_up(LINK + 2, WELCOME_MS, tx, None, t0);
    assert_eq!(edge.admit(&before, VIEWER, t0).err(), Some("another link"));
    assert!(edge
        .admit(&ticket(LINK + 2, 7, 2, WELCOME_MS), VIEWER, t0)
        .is_ok());
    assert_eq!(edge.stats.tickets_refused.load(Ordering::Relaxed), 3);
    assert_eq!(
        edge.limits
            .take_counts()
            .get(&("ticket refused", "another link")),
        Some(&3)
    );
}

#[tokio::test]
async fn a_used_ticket_is_refused() {
    let t0 = Instant::now();
    let (edge, _core) = linked(10, 4, t0);
    let shown = ticket(LINK, 7, 1, WELCOME_MS);
    let first = edge.admit(&shown, VIEWER, t0).unwrap();
    let elsewhere = IpAddr::V4(Ipv4Addr::new(10, 9, 9, 9));
    assert_eq!(edge.admit(&shown, elsewhere, t0).err(), Some("used"));
    // Also once its viewer left, for as long as the ticket is good
    edge.leave(first.share, first.viewer, t0);
    edge.tick(t0 + ms(29_000));
    assert_eq!(
        edge.admit(&shown, elsewhere, t0 + ms(29_000)).err(),
        Some("used")
    );
    // Then it is forgotten, being past its time anyway
    edge.tick(t0 + ms(30_000));
    assert!(edge.lock().slots.is_empty());
    assert_eq!(
        edge.admit(&shown, elsewhere, t0 + ms(30_000)).err(),
        Some("expired")
    );
}

#[tokio::test]
async fn a_ticket_expires_on_the_cores_clock() {
    // The core's clock read WELCOME_MS when its Welcome came: a ticket it made then is good
    // for 30 s of the edge's own time, one it made 5 s later for 5 s more
    let t0 = Instant::now();
    let (edge, _core) = linked(10, 4, t0);
    let at_welcome = ticket(LINK, 7, 1, WELCOME_MS);
    assert_eq!(
        edge.admit(&at_welcome, VIEWER, t0 + ms(30_000)).err(),
        Some("expired")
    );
    assert!(edge.admit(&at_welcome, VIEWER, t0 + ms(29_999)).is_ok());
    let later = ticket(LINK, 7, 2, WELCOME_MS + 5_000);
    assert!(edge.admit(&later, VIEWER, t0 + ms(34_999)).is_ok());
    let late = ticket(LINK, 7, 3, WELCOME_MS + 5_000);
    assert_eq!(
        edge.admit(&late, VIEWER, t0 + ms(35_000)).err(),
        Some("expired")
    );
    // A link welcomed later, at a later reading of the same clock, reads it the same
    let (tx, _next) = mpsc::channel(16);
    let t1 = t0 + ms(60_000);
    edge.link_up(LINK + 1, 61_000, tx, None, t1);
    let made = ticket(LINK + 1, 7, 1, 50_000);
    assert!(edge.admit(&made, VIEWER, t1 + ms(18_999)).is_ok());
    let made = ticket(LINK + 1, 7, 2, 50_000);
    assert_eq!(
        edge.admit(&made, VIEWER, t1 + ms(19_000)).err(),
        Some("expired")
    );
}

#[tokio::test]
async fn a_revoked_slot_ends_its_viewer_or_refuses_its_ticket() {
    let t0 = Instant::now();
    let (edge, _core) = linked(10, 4, t0);
    let mut watching = edge
        .admit(&ticket(LINK, 7, 1, WELCOME_MS), VIEWER, t0)
        .unwrap();
    edge.revoke(1, WELCOME_MS, t0);
    assert_eq!(watching.end.try_recv(), Ok(End::Say("revoked")));
    assert_eq!(edge.carried(), (0, 1));
    // Its queue is out of the share's fan, the only other holder
    assert!(matches!(
        watching.media.try_recv(),
        Err(mpsc::error::TryRecvError::Disconnected)
    ));
    // A slot revoked before its ticket came: the ticket is refused when it does
    edge.revoke(2, WELCOME_MS, t0);
    assert_eq!(
        edge.admit(&ticket(LINK, 7, 2, WELCOME_MS), VIEWER, t0)
            .err(),
        Some("revoked")
    );
    // A viewer watching past its ticket's time keeps its slot, so a Revoke still finds it
    let mut long = edge
        .admit(&ticket(LINK, 7, 3, WELCOME_MS), VIEWER, t0)
        .unwrap();
    edge.tick(t0 + ms(120_000));
    edge.revoke(3, WELCOME_MS + 120_000, t0 + ms(120_000));
    assert_eq!(long.end.try_recv(), Ok(End::Say("revoked")));
}

#[tokio::test]
async fn an_ended_share_ends_its_viewers_and_refuses_the_tickets_made_before() {
    let t0 = Instant::now();
    let (edge, _core) = linked(10, 4, t0);
    let mut seven = edge
        .admit(&ticket(LINK, 7, 1, WELCOME_MS), VIEWER, t0)
        .unwrap();
    let mut eight = edge
        .admit(&ticket(LINK, 8, 2, WELCOME_MS), VIEWER, t0)
        .unwrap();
    let in_flight = ticket(LINK, 7, 3, WELCOME_MS + 2_000);
    edge.share_ended(7, WELCOME_MS + 2_000);
    assert_eq!(seven.end.try_recv(), Ok(End::Say("share ended")));
    assert!(eight.end.try_recv().is_err(), "another share was ended");
    assert_eq!(edge.carried(), (1, 1));
    assert_eq!(
        edge.admit(&in_flight, VIEWER, t0 + ms(3_000)).err(),
        Some("share ended")
    );
    // Shared again by the same sharer, it is a share of its own: its tickets are good
    assert!(edge
        .admit(
            &ticket(LINK, 7, 4, WELCOME_MS + 2_001),
            VIEWER,
            t0 + ms(3_000)
        )
        .is_ok());
    // Once every ticket of the ended one is past its time, it is forgotten
    edge.tick(t0 + ms(31_999));
    assert!(edge.lock().ended.contains_key(&7));
    edge.tick(t0 + ms(32_000));
    assert!(!edge.lock().ended.contains_key(&7));
}

/// The edge reads the core's clock behind the core's own, by however long the `Welcome`
/// took: a `Revoke` or a `ShareEnded` holds by the core's word of when it was said, so a
/// ticket stays refused for as long as the edge would take it, however late the word came.
#[tokio::test]
async fn a_revoke_or_an_end_heard_late_holds_for_as_long_as_its_tickets_live() {
    let t0 = Instant::now();
    let (edge, _core) = linked(10, 4, t0);
    // The Welcome took 5 s: at t0 the core's clock reads 5 s past what the edge reads
    let core_at_t0 = WELCOME_MS + 5_000;

    // A share ended then: a ticket of it made just before is refused, one made after is good
    let before = ticket(LINK, 8, 10, core_at_t0 - 100);
    edge.share_ended(8, core_at_t0);
    assert_eq!(
        edge.admit(&before, VIEWER, t0 + ms(200)).err(),
        Some("share ended")
    );
    assert!(edge
        .admit(&ticket(LINK, 8, 11, core_at_t0 + 1), VIEWER, t0 + ms(200))
        .is_ok());

    // Slot 9's ticket, made just before its revoke, is good here until t0 + 34.9 s
    let revoked = ticket(LINK, 7, 9, core_at_t0 - 100);
    edge.revoke(9, core_at_t0, t0 + ms(200));
    edge.tick(t0 + ms(31_000));
    assert_eq!(
        edge.admit(&revoked, VIEWER, t0 + ms(31_000)).err(),
        Some("revoked")
    );
    // Forgotten only once the ticket is past its time on the edge's clock too
    edge.tick(t0 + ms(35_000));
    assert!(!edge.lock().slots.contains_key(&9));
    assert_eq!(
        edge.admit(&revoked, VIEWER, t0 + ms(35_000)).err(),
        Some("expired")
    );
}

#[tokio::test]
async fn a_ticket_of_another_edge_or_changed_is_refused() {
    let t0 = Instant::now();
    let (edge, _core) = linked(10, 4, t0);
    let theirs = pool_keys::seal(
        &pool_keys::ticket_key(OTHER),
        &pool_keys::mint(LINK, 7, 1, WELCOME_MS),
    );
    assert_eq!(edge.admit(&theirs, VIEWER, t0).err(), Some("bad ticket"));
    let mut changed = ticket(LINK, 7, 1, WELCOME_MS);
    changed[0] ^= 1;
    assert_eq!(edge.admit(&changed, VIEWER, t0).err(), Some("bad ticket"));
    assert_eq!(edge.admit(&[], VIEWER, t0).err(), Some("bad ticket"));
    assert_eq!(edge.admit(&[1; 300], VIEWER, t0).err(), Some("bad ticket"));
    // None of that used the slot up
    assert!(edge
        .admit(&ticket(LINK, 7, 1, WELCOME_MS), VIEWER, t0)
        .is_ok());
}

#[tokio::test]
async fn an_edge_takes_no_more_viewers_or_shares_than_it_may() {
    let t0 = Instant::now();
    let (edge, _core) = linked(2, 1, t0);
    let _first = edge
        .admit(&ticket(LINK, 7, 1, WELCOME_MS), VIEWER, t0)
        .unwrap();
    assert_eq!(
        edge.admit(&ticket(LINK, 8, 2, WELCOME_MS), VIEWER, t0)
            .err(),
        Some("edge full"),
        "a second share"
    );
    let second = edge
        .admit(&ticket(LINK, 7, 3, WELCOME_MS), VIEWER, t0)
        .unwrap();
    let third = ticket(LINK, 7, 4, WELCOME_MS);
    assert_eq!(
        edge.admit(&third, VIEWER, t0).err(),
        Some("edge full"),
        "a third viewer"
    );
    // A ticket refused for room is not used up
    edge.leave(second.share, second.viewer, t0);
    assert!(edge.admit(&third, VIEWER, t0).is_ok());
}

#[tokio::test]
async fn viewers_past_1024_and_past_16_per_address_are_admitted() {
    // As the edge's endpoint holds them: each connection takes a pre-authentication slot
    // when it comes (`ConnLimits::acquire_slot`, in `web::WebTransport::serve`), which a
    // good ticket moves to the main pool
    let t0 = Instant::now();
    let settings = settings(2000, 16);
    let limits = Arc::new(ConnLimits::new(2000 + SETUP_ROOM, 32));
    let edge = Edge::new(&settings, limits.clone());
    let (tx, _core) = mpsc::channel(16);
    edge.link_up(LINK, WELCOME_MS, tx, None, t0);
    // 32 viewers on each of 62 addresses, and the last 16 on one more
    let address = |i: u64| IpAddr::V4(Ipv4Addr::new(10, 0, 0, (i / 32) as u8));
    let mut watching = Vec::new();
    for i in 0..2000u64 {
        let ip = address(i);
        let slot = limits
            .acquire_slot(ip)
            .unwrap_or_else(|why| panic!("viewer {i} not let connect: {why}"));
        let admitted = edge
            .admit(&ticket(LINK, 7, i, WELCOME_MS), ip, t0)
            .unwrap_or_else(|why| panic!("viewer {i} refused: {why}"));
        watching.push((ip, slot, admitted));
    }
    assert_eq!(edge.carried(), (2000, 1));
    assert_eq!(limits.total.load(Ordering::Relaxed), 2000);
    assert_eq!(limits.pre_total.load(Ordering::Relaxed), 0);
    assert_eq!(
        edge.admit(&ticket(LINK, 7, 2000, WELCOME_MS), address(2000), t0)
            .err(),
        Some("edge full"),
        "one past max_viewers"
    );
    // With room for one more, the 33rd from one address is one past max_connections_per_ip
    let (ip, slot, gone) = watching.pop().unwrap();
    edge.leave(gone.share, gone.viewer, t0);
    limits.demote(ip);
    drop(slot);
    let _waiting = limits.acquire_slot(address(0)).unwrap();
    assert_eq!(
        edge.admit(&ticket(LINK, 7, 2001, WELCOME_MS), address(0), t0)
            .err(),
        Some("edge full")
    );
    let _coming = limits.acquire_slot(address(1999)).unwrap();
    assert!(edge
        .admit(&ticket(LINK, 7, 2002, WELCOME_MS), address(1999), t0)
        .is_ok());

    // Without the move the pre pool alone would have stopped them, at 16 from one address
    // and 1024 in all
    let control = Arc::new(ConnLimits::new(2000 + SETUP_ROOM, 32));
    let at = |a: u8| IpAddr::V4(Ipv4Addr::new(10, 1, 0, a));
    let mut held = Vec::new();
    for _ in 0..16 {
        held.push(control.acquire_slot(at(0)).unwrap());
    }
    assert_eq!(
        control.acquire_slot(at(0)).err(),
        Some("per-IP limit reached")
    );
    for a in 1..64u8 {
        for _ in 0..16 {
            held.push(control.acquire_slot(at(a)).unwrap());
        }
    }
    assert_eq!(held.len(), 1024);
    assert_eq!(
        control.acquire_slot(at(64)).err(),
        Some("pre-authentication limit reached")
    );
}

#[test]
fn keyframe_asks_for_a_share_are_merged_to_one_a_second() {
    let t0 = Instant::now();
    let mut merge = KeyframeMerge::default();
    assert!(merge.ask(t0), "the first goes at once");
    assert!(!merge.ask(t0 + ms(200)));
    assert!(!merge.ask(t0 + ms(900)));
    assert!(!merge.due(t0 + ms(999)));
    assert!(merge.due(t0 + ms(1_000)), "those waiting go as one");
    assert!(!merge.due(t0 + ms(5_000)), "and nothing waits after");
    assert!(merge.ask(t0 + ms(5_000)), "a lone ask goes at once");
}

#[tokio::test]
async fn frames_a_viewers_queue_dropped_ask_for_a_keyframe_through_the_same_merge() {
    let t0 = Instant::now();
    let (edge, mut core) = linked(10, 4, t0);
    let edge = Arc::new(edge);
    let _watching = edge
        .admit(&ticket(LINK, 7, 1, WELCOME_MS), VIEWER, t0)
        .unwrap();
    // Fed, so the share is not asked for again
    edge.datagram(audio(7));
    told(&mut core);
    let KeyframeHook::Edge(dropped) = edge.keyframe_hook() else {
        panic!("not an edge's hook");
    };
    // Within a second of the join's ask: they wait, and go as one
    dropped(7);
    dropped(7);
    assert_eq!(told(&mut core), []);
    assert_eq!(edge.stats.frames_dropped.load(Ordering::Relaxed), 2);
    edge.tick(Instant::now() + ms(1_000));
    assert_eq!(told(&mut core), [EdgeMsg::KeyframeWanted { share: 7 }]);
    // Of a share not carried here: nothing to ask
    dropped(8);
    edge.tick(Instant::now() + ms(5_000));
    assert_eq!(told(&mut core), []);
}

#[tokio::test]
async fn a_share_without_viewers_is_let_go_10_s_later() {
    let t0 = Instant::now();
    let (edge, mut core) = linked(10, 4, t0);
    let first = edge
        .admit(&ticket(LINK, 7, 1, WELCOME_MS), VIEWER, t0)
        .unwrap();
    told(&mut core);
    edge.leave(first.share, first.viewer, t0 + ms(1_000));
    edge.tick(t0 + ms(10_999));
    assert_eq!(told(&mut core), []);
    // One who comes back within that needs no new Subscribe
    let back = edge
        .admit(&ticket(LINK, 7, 2, WELCOME_MS), VIEWER, t0 + ms(5_000))
        .unwrap();
    edge.leave(back.share, back.viewer, t0 + ms(6_000));
    told(&mut core);
    edge.tick(t0 + ms(15_999));
    assert_eq!(told(&mut core), []);
    edge.tick(t0 + ms(16_000));
    assert_eq!(told(&mut core), [EdgeMsg::Unsubscribe { share: 7 }]);
    assert_eq!(edge.carried(), (0, 0));
    // Its next viewer asks for it again
    let _again = edge
        .admit(&ticket(LINK, 7, 3, WELCOME_MS), VIEWER, t0 + ms(17_000))
        .unwrap();
    assert_eq!(
        told(&mut core),
        [
            EdgeMsg::Subscribe { share: 7 },
            EdgeMsg::KeyframeWanted { share: 7 }
        ]
    );
}

/// A share asked for and not fed, while viewers here wait for it, is asked for again: an
/// ask the core did not take, as one past its rate, would leave them waiting for good.
#[tokio::test]
async fn a_share_its_core_does_not_feed_is_asked_for_again() {
    let t0 = Instant::now();
    let (edge, mut core) = linked(10, 4, t0);
    let _watching = edge
        .admit(&ticket(LINK, 7, 1, WELCOME_MS), VIEWER, t0)
        .unwrap();
    told(&mut core);
    edge.tick(t0 + ms(4_999));
    assert_eq!(told(&mut core), []);
    edge.tick(t0 + ms(5_000));
    assert_eq!(told(&mut core), [EdgeMsg::Subscribe { share: 7 }]);
    edge.tick(t0 + ms(9_999));
    assert_eq!(told(&mut core), []);
    edge.tick(t0 + ms(10_000));
    assert_eq!(told(&mut core), [EdgeMsg::Subscribe { share: 7 }]);
    // A frame stream of it came: fed, so asked no more
    assert!(edge.inbox(7).is_some());
    edge.tick(t0 + ms(20_000));
    assert_eq!(told(&mut core), []);
    // Nor is a share whose viewers left: it is let go instead
    let left = edge
        .admit(&ticket(LINK, 8, 2, WELCOME_MS), VIEWER, t0)
        .unwrap();
    told(&mut core);
    edge.leave(left.share, left.viewer, t0);
    edge.tick(t0 + ms(5_000));
    assert_eq!(told(&mut core), []);
}

#[tokio::test]
async fn a_lost_link_ends_every_viewer_and_forgets_everything() {
    let t0 = Instant::now();
    let (edge, mut core) = linked(10, 4, t0);
    let mut seven = edge
        .admit(&ticket(LINK, 7, 1, WELCOME_MS), VIEWER, t0)
        .unwrap();
    let mut eight = edge
        .admit(&ticket(LINK, 8, 2, WELCOME_MS), VIEWER, t0)
        .unwrap();
    edge.revoke(3, WELCOME_MS, t0);
    edge.share_ended(9, WELCOME_MS);
    assert_eq!(edge.link_lost(LINK + 1), 0, "another link's end changed it");
    assert_eq!(edge.link_lost(LINK), 2);
    assert_eq!(seven.end.try_recv(), Ok(End::Say("core lost")));
    assert_eq!(eight.end.try_recv(), Ok(End::Say("core lost")));
    assert_eq!(edge.carried(), (0, 0));
    {
        let state = edge.lock();
        assert!(state.link.is_none() && state.slots.is_empty() && state.ended.is_empty());
    }
    // Nothing is said to the core until the next Welcome
    told(&mut core);
    edge.datagram(audio(7));
    edge.revoke(4, WELCOME_MS, t0);
    edge.tick(t0 + ms(20_000));
    assert_eq!(told(&mut core), []);
    assert!(edge.lock().slots.is_empty());
}

#[tokio::test]
async fn the_load_tells_the_core_what_the_edge_carries() {
    let t0 = Instant::now();
    let (edge, _core) = linked(10, 4, t0);
    let _a = edge
        .admit(&ticket(LINK, 7, 1, WELCOME_MS), VIEWER, t0)
        .unwrap();
    let _b = edge
        .admit(&ticket(LINK, 7, 2, WELCOME_MS), VIEWER, t0)
        .unwrap();
    let _c = edge
        .admit(&ticket(LINK, 8, 3, WELCOME_MS), VIEWER, t0)
        .unwrap();
    let _ = edge.admit(&ticket(LINK, 8, 3, WELCOME_MS), VIEWER, t0);
    let EdgeMsg::Load {
        viewers,
        mut per_share,
        egress_kbps,
        tickets_refused,
        ..
    } = edge.load(1234)
    else {
        panic!("not a load");
    };
    per_share.sort();
    assert_eq!(viewers, 3);
    assert_eq!(per_share, [(7, 2), (8, 1)]);
    assert_eq!(egress_kbps, 1234);
    assert_eq!(tickets_refused, 1);
}

#[test]
fn the_minute_line_is_written_only_when_something_happened() {
    let none = std::collections::BTreeMap::new();
    assert_eq!(minute_line(0, 0, 0, 0, 0, &none, 0), None);
    let mut counts = std::collections::BTreeMap::new();
    counts.insert(("ticket refused", "expired"), 2);
    counts.insert(("ticket refused", "used"), 1);
    let line = minute_line(3, 1, 60_000_000, 4, 0, &counts, 5).unwrap();
    assert_eq!(
        line,
        "last minute: 3 viewers of 1 shares, 8.0 Mbit/s, 4 frames dropped; \
         ticket refused: expired 2, used 1; \
         UDP datagrams dropped 5 (buffer full, see OPERATING.md 10a)"
    );
}

// ── Feeds ──────────────────────────────────────────────────────────────

/// The next `n` packets in `queue`.
async fn next(queue: &mut mpsc::Receiver<Bytes>, n: usize) -> Vec<Bytes> {
    let mut got = Vec::new();
    for _ in 0..n {
        got.push(
            tokio::time::timeout(HANG, queue.recv())
                .await
                .expect("a packet that did not come")
                .expect("the queue closed"),
        );
    }
    got
}

#[tokio::test]
async fn a_feed_stream_goes_to_the_share_its_first_record_names() {
    let t0 = Instant::now();
    let (edge, _core) = linked(10, 4, t0);
    let mut seven = edge
        .admit(&ticket(LINK, 7, 1, WELCOME_MS), VIEWER, t0)
        .unwrap();
    let mut eight = edge
        .admit(&ticket(LINK, 8, 2, WELCOME_MS), VIEWER, t0)
        .unwrap();
    let stream = |packets: &[Bytes]| -> Box<dyn tokio::io::AsyncRead + Send + Unpin> {
        Box::new(std::io::Cursor::new(records(packets)))
    };
    let key = frame(true, 7, 1, 3);
    let delta = frame(false, 8, 1, 2);
    link::route_stream(&edge, stream(&key)).await;
    link::route_stream(&edge, stream(&delta)).await;
    // Of a share not carried here
    link::route_stream(&edge, stream(&frame(true, 9, 1, 2))).await;
    // Of no share at all: screen audio has no business on a stream
    link::route_stream(&edge, stream(&[audio(7)])).await;
    // One that turns into another share's halfway is cut there
    let mixed = vec![
        fragment(false, 7, 2, 0, 2),
        fragment(false, 8, 2, 0, 2),
        fragment(false, 7, 2, 1, 2),
    ];
    link::route_stream(&edge, stream(&mixed)).await;
    // And the next stream of a share still comes after
    let next_key = frame(true, 7, 3, 1);
    link::route_stream(&edge, stream(&next_key)).await;

    let mut expected = key.clone();
    expected.push(mixed[0].clone());
    expected.extend(next_key);
    assert_eq!(next(&mut seven.media, 5).await, expected);
    assert_eq!(next(&mut eight.media, 2).await, delta);
    tokio::time::sleep(ms(50)).await;
    assert!(seven.media.try_recv().is_err(), "more reached share 7");
    assert!(eight.media.try_recv().is_err(), "more reached share 8");
    let counts = edge.limits.take_counts();
    assert_eq!(
        counts.get(&("edge", "feed of a share not carried")),
        Some(&1)
    );
    assert_eq!(counts.get(&("edge", "feed stream of no share")), Some(&1));
    assert!(edge.stats.egress_bytes.load(Ordering::Relaxed) > 0);
}

#[tokio::test]
async fn screen_audio_reaches_the_viewers_of_its_share_only() {
    let t0 = Instant::now();
    let (edge, _core) = linked(10, 4, t0);
    let mut seven = edge
        .admit(&ticket(LINK, 7, 1, WELCOME_MS), VIEWER, t0)
        .unwrap();
    let mut eight = edge
        .admit(&ticket(LINK, 8, 2, WELCOME_MS), VIEWER, t0)
        .unwrap();
    edge.datagram(audio(7));
    edge.datagram(audio(9));
    // Video comes on streams; a fragment as a datagram is dropped
    edge.datagram(fragment(true, 7, 1, 0, 1));
    edge.datagram(Bytes::from_static(&[0x15, 0, 0, 0, 7]));
    assert_eq!(seven.media.try_recv().unwrap(), audio(7));
    assert!(seven.media.try_recv().is_err());
    assert!(eight.media.try_recv().is_err());
}

#[test]
fn a_refusal_from_a_later_core_is_read_for_its_version() {
    /// A later pool version, as far as this one can tell: a field more in `Refused`.
    #[derive(Serialize)]
    enum CoreMsg2 {
        _Welcome,
        Refused {
            pool_version: u32,
            reason: String,
            retry_secs: u32,
        },
    }
    let later = postcard::to_allocvec(&CoreMsg2::Refused {
        pool_version: 2,
        reason: "this relay speaks pool version 2".into(),
        retry_secs: 60,
    })
    .unwrap();
    assert_eq!(
        link::first_answer(&later),
        link::Answer::Refused {
            pool_version: 2,
            reason: None
        }
    );
    let payload = |msg: &CoreMsg| encode_core_msg(msg).unwrap()[4..].to_vec();
    let today = payload(&CoreMsg::Refused {
        pool_version: POOL_VERSION,
        reason: "its public port is 0".into(),
    });
    assert_eq!(
        link::first_answer(&today),
        link::Answer::Refused {
            pool_version: POOL_VERSION,
            reason: Some("its public port is 0".into())
        }
    );
    let welcome = payload(&CoreMsg::Welcome {
        link: 9,
        core_ms: 77,
    });
    assert_eq!(
        link::first_answer(&welcome),
        link::Answer::Welcome {
            link: 9,
            core_ms: 77
        }
    );
    let revoke = payload(&CoreMsg::Revoke {
        slot: 1,
        core_ms: 2,
    });
    assert_eq!(link::first_answer(&revoke), link::Answer::Unreadable);
    assert_eq!(link::first_answer(&[0xff; 8]), link::Answer::Unreadable);
}

// ── Over QUIC ──────────────────────────────────────────────────────────

mod over_quic {
    use super::*;

    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::io::AsyncReadExt as _;
    use wtransport::endpoint::endpoint_side::Client;
    use wtransport::tls::client::ServerHashVerification;
    use wtransport::tls::Sha256Digest;
    use wtransport::{ClientConfig, Endpoint, Identity, RecvStream, SendStream};

    use crate::web::{quic_binding, read_frame};

    /// A port free on 127.0.0.1 a moment ago: an endpoint does not tell the one it got.
    fn free_port() -> u16 {
        std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    /// A core's end of an edge's link, past its Welcome.
    struct CoreEnd {
        conn: Connection,
        send: SendStream,
        recv: RecvStream,
        buf: BytesMut,
        hello: EdgeMsg,
    }

    impl CoreEnd {
        /// The next thing the edge says that is not its Load.
        async fn word(&mut self) -> EdgeMsg {
            loop {
                let frame = tokio::time::timeout(
                    HANG,
                    read_frame(&mut self.recv, &mut self.buf, MAX_POOL_FRAME),
                )
                .await
                .expect("the edge said nothing")
                .ok()
                .expect("the link ended");
                match decode_edge_msg(&frame).unwrap() {
                    EdgeMsg::Load { .. } => continue,
                    msg => return msg,
                }
            }
        }

        async fn tell(&mut self, msg: CoreMsg) {
            self.send
                .write_all(&encode_core_msg(&msg).unwrap())
                .await
                .unwrap();
        }
    }

    /// A core on 127.0.0.1 with an operator certificate of its own, which welcomes an edge
    /// that proves `SECRET` on its link as `LINK`: its port, the SHA-256 of its certificate,
    /// and the links it took (or why not).
    fn core() -> (u16, [u8; 32], mpsc::Receiver<Result<CoreEnd, String>>) {
        let operator = Identity::self_signed(["localhost"]).unwrap();
        let der = operator.certificate_chain().as_slice()[0].der().to_vec();
        let pin: [u8; 32] = ring::digest::digest(&ring::digest::SHA256, &der)
            .as_ref()
            .try_into()
            .unwrap();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            operator.private_key().secret_der().to_vec(),
        ));
        let port = free_port();
        let web = WebTransport::bind_with(
            ([127, 0, 0, 1], port).into(),
            Some((vec![CertificateDer::from(der)], key)),
            Role::Relay,
        )
        .unwrap();
        let (links_tx, links) = mpsc::channel(4);
        let routes = Routes::new(None).at(POOL_PATH, move |conn, _peer, _slot| {
            let links = links_tx.clone();
            async move {
                let _ = links.send(welcome(conn).await).await;
            }
        });
        tokio::spawn(web.serve(Arc::new(ConnLimits::new(64, 32)), Arc::new(routes)));
        (port, pin, links)
    }

    async fn welcome(conn: Connection) -> Result<CoreEnd, String> {
        let (mut send, mut recv) = conn.accept_bi().await.map_err(|e| e.to_string())?;
        let mut buf = BytesMut::new();
        let frame = read_frame(&mut recv, &mut buf, MAX_POOL_FRAME)
            .await
            .map_err(|_| "no hello".to_string())?;
        let hello = decode_edge_msg(&frame).map_err(|e| e.to_string())?;
        let EdgeMsg::Hello { name, proof, .. } = &hello else {
            return Err(format!("not a hello: {hello:?}"));
        };
        let binding = quic_binding(&conn).ok_or("no exporter")?;
        if !pool_keys::proof_ok(&pool_keys::proof_key(SECRET), &binding, name, proof) {
            return Err("a wrong proof".into());
        }
        let welcome = CoreMsg::Welcome {
            link: LINK,
            core_ms: WELCOME_MS,
        };
        send.write_all(&encode_core_msg(&welcome).unwrap())
            .await
            .map_err(|e| e.to_string())?;
        Ok(CoreEnd {
            conn,
            send,
            recv,
            buf,
            hello,
        })
    }

    /// A viewer's end of a session with the edge on `port`, its hello sent with `ticket`.
    struct ViewerEnd {
        _endpoint: Endpoint<Client>,
        conn: Connection,
        _send: SendStream,
        recv: RecvStream,
        buf: BytesMut,
    }

    impl ViewerEnd {
        /// Connects as the apps do, trusting only the certificate of `pin`.
        async fn open(port: u16, pin: [u8; 32], ticket: Vec<u8>) -> Self {
            let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(ServerHashVerification::new([
                Sha256Digest::new(pin),
            ])))
            .with_no_client_auth();
            tls.alpn_protocols = vec![b"h3".to_vec()];
            let config = ClientConfig::builder()
                .with_bind_address("127.0.0.1:0".parse().unwrap())
                .with_custom_tls(tls)
                .build();
            let endpoint = Endpoint::client(config).unwrap();
            let conn = tokio::time::timeout(
                HANG,
                endpoint.connect(format!("https://127.0.0.1:{port}{VIEW_PATH}")),
            )
            .await
            .expect("the connect neither went through nor failed")
            .expect("the edge refused the session");
            let (mut send, recv) = conn.open_bi().await.unwrap().await.unwrap();
            send.write_all(&encode_viewer_msg(&ViewerMsg::Hello { ticket }).unwrap())
                .await
                .unwrap();
            Self {
                _endpoint: endpoint,
                conn,
                _send: send,
                recv,
                buf: BytesMut::new(),
            }
        }

        async fn word(&mut self) -> EdgeViewMsg {
            let frame = tokio::time::timeout(HANG, read_frame(&mut self.recv, &mut self.buf, 1024))
                .await
                .expect("the edge said nothing")
                .ok()
                .expect("the edge closed without a word");
            decode_edge_view_msg(&frame).unwrap()
        }
    }

    fn ended(reason: &str) -> EdgeViewMsg {
        EdgeViewMsg::Ended {
            reason: reason.into(),
        }
    }

    #[tokio::test]
    async fn an_edge_links_to_its_core_and_serves_the_viewers_it_sends() {
        let (core_port, pin, mut links) = core();
        let port = free_port();
        let running = start(Settings {
            core_host: "127.0.0.1".into(),
            core_port,
            core_pin: Some(pin),
            name: "e1".into(),
            secret: SECRET.into(),
            bind: ([127, 0, 0, 1], port).into(),
            public_host: "127.0.0.1".into(),
            public_port: port,
            max_viewers: 10,
            egress_mbit: 100,
            max_shares: 4,
            max_connections_per_ip: 32,
        })
        .unwrap();
        let mut core = tokio::time::timeout(HANG, links.recv())
            .await
            .expect("the edge did not link")
            .unwrap()
            .unwrap();
        let EdgeMsg::Hello {
            pool_version,
            public_host,
            public_port,
            cert_hashes,
            max_viewers,
            egress_mbit,
            max_shares,
            ..
        } = &core.hello
        else {
            unreachable!("checked in welcome");
        };
        assert_eq!(*pool_version, POOL_VERSION);
        assert_eq!((public_host.as_str(), *public_port), ("127.0.0.1", port));
        assert_eq!(*cert_hashes, running.cert_hashes());
        assert_eq!((*max_viewers, *egress_mbit, *max_shares), (10, 100, 4));
        tokio::time::timeout(HANG, async {
            while !running.is_linked() {
                tokio::time::sleep(ms(10)).await;
            }
        })
        .await
        .expect("the edge did not take the Welcome");
        let viewers_pin = running.cert_hashes()[0];

        // A viewer the core sent: Ready, and the edge asks for its share and a keyframe
        let mut viewer = ViewerEnd::open(port, viewers_pin, ticket(LINK, 7, 1, WELCOME_MS)).await;
        assert_eq!(viewer.word().await, EdgeViewMsg::Ready);
        assert_eq!(core.word().await, EdgeMsg::Subscribe { share: 7 });
        assert_eq!(core.word().await, EdgeMsg::KeyframeWanted { share: 7 });

        // The core feeds a keyframe on a stream, as to a viewer of its own: the viewer gets
        // it on one of its own
        let key = frame(true, 7, 1, 3);
        let mut feed = core.conn.open_uni().await.unwrap().await.unwrap();
        feed.write_all(&records(&key)).await.unwrap();
        feed.finish().await.unwrap();
        let mut got = tokio::time::timeout(HANG, viewer.conn.accept_uni())
            .await
            .expect("no frame came")
            .unwrap();
        let mut bytes = Vec::new();
        tokio::time::timeout(HANG, got.read_to_end(&mut bytes))
            .await
            .expect("the frame did not end")
            .unwrap();
        let fragments: Vec<Bytes> = RecordReader::default()
            .push(&bytes)
            .into_iter()
            .map(Bytes::from)
            .collect();
        assert_eq!(fragments, key);
        // And screen audio as a datagram
        core.conn.send_datagram(audio(7)).unwrap();
        let datagram = tokio::time::timeout(HANG, viewer.conn.receive_datagram())
            .await
            .expect("no screen audio came")
            .unwrap();
        assert_eq!(datagram.payload(), audio(7));

        // The core revokes it
        core.tell(CoreMsg::Revoke {
            slot: 1,
            core_ms: WELCOME_MS,
        })
        .await;
        assert_eq!(viewer.word().await, ended("revoked"));

        // A ticket the core did not make for this link
        let mut stranger =
            ViewerEnd::open(port, viewers_pin, ticket(LINK + 1, 7, 2, WELCOME_MS)).await;
        assert_eq!(stranger.word().await, ended("ticket refused"));

        // The core goes: its viewers are told, and the edge links again
        let mut third = ViewerEnd::open(port, viewers_pin, ticket(LINK, 7, 3, WELCOME_MS)).await;
        assert_eq!(third.word().await, EdgeViewMsg::Ready);
        core.conn.close(VarInt::from_u32(0), b"");
        assert_eq!(third.word().await, ended("core lost"));
        let _core = tokio::time::timeout(HANG, links.recv())
            .await
            .expect("the edge did not link again")
            .unwrap()
            .unwrap();
        tokio::time::timeout(HANG, async {
            while !running.is_linked() {
                tokio::time::sleep(ms(10)).await;
            }
        })
        .await
        .expect("the edge did not take the second Welcome");

        // The edge stops: its viewers are told why
        let mut last = ViewerEnd::open(port, viewers_pin, ticket(LINK, 7, 4, WELCOME_MS)).await;
        assert_eq!(last.word().await, EdgeViewMsg::Ready);
        running.stop().await;
        assert_eq!(last.word().await, ended("edge stopping"));
    }

    #[tokio::test]
    async fn an_edge_links_to_a_relay_that_lists_it_in_its_pool() {
        // The relay itself, not a stand-in: its check of the hello is the one that counts
        let mut config = crate::config::ServerConfig::default();
        config.pool.edges.insert("e1".into(), SECRET.into());
        let state = Arc::new(crate::state::ServerState::new(
            &config,
            crate::settings::ServerSettings::default(),
            Vec::new(),
            "test-admin-token".into(),
        ));
        let core_port = free_port();
        let relay =
            WebTransport::bind_with(([127, 0, 0, 1], core_port).into(), None, Role::Relay).unwrap();
        // Without an operator certificate the relay shows every name its browser one
        let pin = relay.cert_hashes().borrow()[0];
        tokio::spawn(relay.run(state.clone(), state.limits.clone()));
        let port = free_port();
        let running = start(Settings {
            core_host: "127.0.0.1".into(),
            core_port,
            core_pin: Some(pin),
            name: "e1".into(),
            secret: SECRET.into(),
            bind: ([127, 0, 0, 1], port).into(),
            public_host: "127.0.0.1".into(),
            public_port: port,
            max_viewers: 10,
            egress_mbit: 100,
            max_shares: 4,
            max_connections_per_ip: 32,
        })
        .unwrap();
        let pool = state.pool.clone().unwrap();
        let edge = tokio::time::timeout(HANG, async {
            loop {
                let (edges, _) = pool.report();
                if edges[0].online && running.is_linked() {
                    return edges[0].clone();
                }
                tokio::time::sleep(ms(10)).await;
            }
        })
        .await
        .expect("the relay never linked the edge");
        assert_eq!(edge.name, "e1");
        assert_eq!(edge.address, format!("127.0.0.1:{port}"));
        assert_eq!((edge.max_viewers, edge.max_shares), (10, 4));
        assert_eq!(edge.budget_kbps, 100_000);
        running.stop().await;
    }
}
