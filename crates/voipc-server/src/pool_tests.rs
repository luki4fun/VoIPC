//! The media edge pool end to end, in one process over loopback QUIC (1.15): a relay with
//! `[pool]`, a real edge linked to it (`edge::start`, pinning the relay's certificate as
//! `core_fingerprint` does), and a sharer and viewers that speak to both as the native app
//! does. session_tests.rs proves the relay's side with edges that are queues, and
//! edge/tests.rs the edge's with a stand-in relay; here the two meet. The relay's tickets
//! open on the edge, its feed reaches the edge's viewers, and when the edge dies its viewers
//! are back on the relay within the link's idle timeout.
//!
//! An edge, or a relay, that is to die as `kill -9` would runs on a tokio runtime of its own
//! (`Process`): shutting that runtime down stops every task and timer it had, so nothing
//! more leaves it, not even a close, and its peers learn of it only by their idle timeout.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::BytesMut;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::io::AsyncReadExt as _;
use tokio::sync::mpsc;
use voipc_protocol::codec::{
    decode_server_msg, encode_client_msg, try_decode_frame, APP_VERSION, PROTOCOL_VERSION,
};
use voipc_protocol::messages::{ClientMessage, ServerMessage};
use voipc_protocol::pool::{
    decode_edge_view_msg, encode_viewer_msg, EdgeViewMsg, ViewerMsg, VIEW_PATH,
};
use voipc_protocol::types::{ChannelId, EdgeView, ProximityMode, SessionId, UserId, VideoCodec};
use voipc_protocol::video::{RecordReader, VideoPacket};
use wtransport::config::{DnsLookupFuture, DnsResolver};
use wtransport::endpoint::endpoint_side::Client;
use wtransport::tls::client::ServerHashVerification;
use wtransport::tls::Sha256Digest;
use wtransport::{ClientConfig, Connection, Endpoint, Identity, RecvStream, SendStream};

use crate::config::ServerConfig;
use crate::edge::{self, Running, Settings};
use crate::settings::ServerSettings;
use crate::state::ServerState;
use crate::web::{read_frame, Role, WebTransport, NATIVE_SNI};

/// What a wait for something that must come allows: past it something hung, a slow machine
/// is not (the lanes' rule 1).
const HANG: Duration = Duration::from_secs(60);
const SECRET: &str = "the-secret-of-edge-one-0123456789";
/// The link's idle timeout is 6 s (`edge::link`): a dead edge's viewers must have frames
/// from the relay again within this of its death.
const BACK_WITHIN: Duration = Duration::from_secs(8);
/// Fragments in each of the sharer's frames.
const FRAGMENTS: u8 = 3;

// ── Processes ──────────────────────────────────────────────────────────

/// A runtime of its own for an edge or a relay, so that it can die as a process does.
struct Process(Option<tokio::runtime::Runtime>);

impl Process {
    fn new() -> Self {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        Self(Some(rt))
    }

    /// Runs `start` inside this runtime: what it binds and spawns lives and dies with it.
    fn enter<T>(&self, start: impl FnOnce() -> T) -> T {
        let _in = self.0.as_ref().expect("not killed").enter();
        start()
    }

    /// As `kill -9`: every task stops where it is, and nobody is told.
    fn kill(&mut self) {
        if let Some(rt) = self.0.take() {
            rt.shutdown_background();
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        self.kill();
    }
}

/// The relay's operator certificate: what native apps and edges are shown, and its SHA-256,
/// what an edge's `core_fingerprint` pins.
struct Operator {
    der: Vec<u8>,
    key: Vec<u8>,
    pin: [u8; 32],
}

impl Operator {
    fn new() -> Self {
        let identity = Identity::self_signed(["localhost"]).unwrap();
        let der = identity.certificate_chain().as_slice()[0].der().to_vec();
        let pin = ring::digest::digest(&ring::digest::SHA256, &der)
            .as_ref()
            .try_into()
            .unwrap();
        let key = identity.private_key().secret_der().to_vec();
        Self { der, key, pin }
    }

    fn identity(&self) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        (
            vec![CertificateDer::from(self.der.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key.clone())),
        )
    }
}

/// A port free on 127.0.0.1 a moment ago: an endpoint does not tell the one it got.
fn free_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A relay with `e1` in `[pool]`, keeping the first `local_first` viewers of a share
/// itself, serving on 127.0.0.1:`port` with `operator`'s certificate, on the runtime the
/// caller is in. `Err` while the port is still taken.
fn relay(port: u16, operator: &Operator, local_first: u32) -> anyhow::Result<Arc<ServerState>> {
    let web = WebTransport::bind_with(
        ([127, 0, 0, 1], port).into(),
        Some(operator.identity()),
        Role::Relay,
    )?;
    let mut config = ServerConfig::default();
    config.pool.edges.insert("e1".into(), SECRET.into());
    config.pool.local_first = local_first;
    config.validate().unwrap();
    let state = Arc::new(ServerState::new(
        &config,
        ServerSettings::default(),
        Vec::new(),
        "test-admin-token".into(),
    ));
    tokio::spawn(web.run(state.clone(), state.limits.clone()));
    Ok(state)
}

/// Edge `e1` with `secret`, linking to the relay on `core_port` by its pin, serving viewers
/// on 127.0.0.1:`port`.
fn edge_settings(core_port: u16, pin: [u8; 32], secret: &str, port: u16) -> Settings {
    Settings {
        core_host: "127.0.0.1".into(),
        core_port,
        core_pin: Some(pin),
        name: "e1".into(),
        secret: secret.into(),
        bind: ([127, 0, 0, 1], port).into(),
        public_host: "127.0.0.1".into(),
        public_port: port,
        max_viewers: 100,
        egress_mbit: 1000,
        max_shares: 4,
        max_connections_per_ip: 32,
    }
}

/// Until the relay has `e1` linked and the edge took its `Welcome`.
async fn linked(state: &ServerState, edge: &Running) {
    let pool = state.pool.as_ref().expect("a relay with a pool");
    tokio::time::timeout(HANG, async {
        while !(pool.report().0[0].online && edge.is_linked()) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the edge never linked");
}

// ── A native app ───────────────────────────────────────────────────────

/// Takes whatever certificate the relay shows: these tests are about what comes after.
#[derive(Debug)]
struct AnyCert;

impl ServerCertVerifier for AnyCert {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::ED25519,
        ]
    }
}

/// Resolves every name to the relay, so the URL can carry `NATIVE_SNI` while dialing an IP,
/// as the app does.
#[derive(Debug)]
struct Fixed(SocketAddr);

impl DnsResolver for Fixed {
    fn resolve(&self, _host: &str) -> Pin<Box<dyn DnsLookupFuture>> {
        let addr = self.0;
        Box::pin(async move { Ok(Some(addr)) })
    }
}

fn tls(verifier: Arc<dyn ServerCertVerifier>) -> rustls::ClientConfig {
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .dangerous()
    .with_custom_certificate_verifier(verifier)
    .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls
}

/// A guest's session with the relay: what the relay tells it arrives in `inbox`, its
/// keep-alive pings answered on the way.
struct App {
    _endpoint: Endpoint<Client>,
    conn: Connection,
    out: mpsc::UnboundedSender<Vec<u8>>,
    inbox: mpsc::UnboundedReceiver<ServerMessage>,
    user_id: UserId,
    session_id: SessionId,
}

impl App {
    async fn connect(port: u16, name: &str) -> Self {
        let addr: SocketAddr = ([127, 0, 0, 1], port).into();
        let config = ClientConfig::builder()
            .with_bind_address("127.0.0.1:0".parse().unwrap())
            .with_custom_tls(tls(Arc::new(AnyCert)))
            .dns_resolver(Fixed(addr))
            .build();
        let endpoint = Endpoint::client(config).unwrap();
        let conn = tokio::time::timeout(
            HANG,
            endpoint.connect(format!("https://{NATIVE_SNI}:{port}/voipc")),
        )
        .await
        .expect("the connect neither went through nor failed")
        .expect("the relay refused the session");
        let (mut send, mut recv) = conn.open_bi().await.unwrap().await.unwrap();
        let auth = ClientMessage::Authenticate {
            username: name.into(),
            protocol_version: PROTOCOL_VERSION,
            app_version: APP_VERSION.to_string(),
            identity_key: None,
            prekey_bundle: None,
            account: None,
        };
        send.write_all(&encode_client_msg(&auth).unwrap())
            .await
            .unwrap();
        let mut buf = BytesMut::new();
        let (user_id, session_id) = tokio::time::timeout(HANG, async {
            loop {
                if let Some(payload) = try_decode_frame(&mut buf).unwrap() {
                    if let ServerMessage::Authenticated {
                        user_id,
                        session_id,
                        ..
                    } = decode_server_msg(&payload).unwrap()
                    {
                        return (user_id, session_id);
                    }
                    continue;
                }
                assert!(
                    recv.read_buf(&mut buf).await.unwrap() > 0,
                    "the relay hung up"
                );
            }
        })
        .await
        .expect("never signed in");

        let (out, mut outgoing) = mpsc::unbounded_channel::<Vec<u8>>();
        tokio::spawn(async move {
            while let Some(bytes) = outgoing.recv().await {
                if send.write_all(&bytes).await.is_err() {
                    return;
                }
            }
        });
        let (inbox_tx, inbox) = mpsc::unbounded_channel();
        let pings = out.clone();
        tokio::spawn(async move {
            loop {
                match try_decode_frame(&mut buf) {
                    Ok(Some(payload)) => {
                        let Ok(msg) = decode_server_msg(&payload) else {
                            continue;
                        };
                        if let ServerMessage::Ping { timestamp } = msg {
                            let answer = ClientMessage::Ping { timestamp };
                            let _ = pings.send(encode_client_msg(&answer).unwrap());
                        } else if inbox_tx.send(msg).is_err() {
                            return;
                        }
                        continue;
                    }
                    Ok(None) => {}
                    Err(_) => return,
                }
                if !matches!(recv.read_buf(&mut buf).await, Ok(n) if n > 0) {
                    return;
                }
            }
        });
        Self {
            _endpoint: endpoint,
            conn,
            out,
            inbox,
            user_id,
            session_id,
        }
    }

    fn send(&self, msg: &ClientMessage) {
        self.out.send(encode_client_msg(msg).unwrap()).unwrap();
    }

    /// The next message `what` that `pick` takes, the others before it dropped.
    async fn until(&mut self, what: &str, pick: impl Fn(&ServerMessage) -> bool) -> ServerMessage {
        tokio::time::timeout(HANG, async {
            loop {
                let msg = self.inbox.recv().await.expect("the session ended");
                if pick(&msg) {
                    return msg;
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("no {what} came"))
    }

    /// All the relay sent until now: a ping it answers in order comes back after it.
    async fn drained(&mut self) -> Vec<ServerMessage> {
        let stamp: u64 = rand::random();
        self.send(&ClientMessage::Ping { timestamp: stamp });
        tokio::time::timeout(HANG, async {
            let mut seen = Vec::new();
            loop {
                match self.inbox.recv().await.expect("the session ended") {
                    ServerMessage::Pong { timestamp } if timestamp == stamp => return seen,
                    msg => seen.push(msg),
                }
            }
        })
        .await
        .expect("the relay did not answer a ping")
    }

    async fn join(&mut self, room: ChannelId) {
        self.send(&ClientMessage::JoinChannel {
            channel_id: room,
            password: None,
        });
        self.until(
            "UserList",
            |m| matches!(m, ServerMessage::UserList { channel_id, .. } if *channel_id == room),
        )
        .await;
        self.drained().await;
    }

    /// Asks to watch `sharer`: whether it is watching, and the edge it is to watch from.
    async fn watch(&mut self, sharer: UserId) -> (bool, Option<(u64, EdgeView)>) {
        self.send(&ClientMessage::WatchScreenShare {
            sharer_user_id: sharer,
        });
        let seen = self.drained().await;
        let watching = seen
            .iter()
            .any(|m| matches!(m, ServerMessage::WatchingScreenShare { sharer_user_id, .. } if *sharer_user_id == sharer));
        let at = seen.into_iter().find_map(|m| match m {
            ServerMessage::WatchAt {
                sharer_user_id,
                placement,
                edge: Some(view),
            } if sharer_user_id == sharer => Some((placement, view)),
            _ => None,
        });
        (watching, at)
    }
}

/// Alice makes a room and shares her screen into it at 1080, sending a frame every 33 ms,
/// a keyframe every 15, each on a stream of its own as the apps send them: Alice, and the
/// room.
async fn sharer(port: u16) -> (App, ChannelId) {
    let mut alice = App::connect(port, "alice").await;
    alice.send(&ClientMessage::CreateChannel {
        name: "room".into(),
        password: None,
        proximity: ProximityMode::Off,
        anonymous: false,
        text: false,
    });
    let ServerMessage::ChannelCreated { channel } = alice
        .until("ChannelCreated", |m| {
            matches!(m, ServerMessage::ChannelCreated { .. })
        })
        .await
    else {
        unreachable!()
    };
    alice.drained().await;
    alice.send(&ClientMessage::StartScreenShare {
        source: "portal".into(),
        resolution: 1080,
        codec: VideoCodec::H264,
    });
    let seen = alice.drained().await;
    assert!(
        !seen
            .iter()
            .any(|m| matches!(m, ServerMessage::ScreenShareError { .. })),
        "{seen:?}"
    );
    let (conn, session_id) = (alice.conn.clone(), alice.session_id);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_millis(33));
        for frame_id in 1u32.. {
            tick.tick().await;
            let key = frame_id % 15 == 1;
            let mut records = Vec::new();
            for index in 0..FRAGMENTS {
                let packet = VideoPacket::encrypted_fragment(
                    key,
                    session_id,
                    frame_id,
                    index,
                    FRAGMENTS,
                    frame_id * 33,
                    0,
                    0,
                    vec![0; 1000],
                )
                .to_bytes();
                records.extend_from_slice(&(packet.len() as u16).to_be_bytes());
                records.extend_from_slice(&packet);
            }
            let Ok(opening) = conn.open_uni().await else {
                return;
            };
            let Ok(mut stream) = opening.await else {
                return;
            };
            if stream.write_all(&records).await.is_err() {
                return;
            }
            let _ = stream.finish().await;
        }
    });
    (alice, channel.channel_id)
}

/// Whole frames of `sharer` that come on `conn`, a stream each, as the relay and the edge
/// send them.
fn count_frames(conn: Connection, sharer: SessionId) -> Arc<AtomicU64> {
    let count = Arc::new(AtomicU64::new(0));
    let counted = count.clone();
    tokio::spawn(async move {
        while let Ok(mut stream) = conn.accept_uni().await {
            let counted = counted.clone();
            tokio::spawn(async move {
                let mut bytes = Vec::new();
                if stream.read_to_end(&mut bytes).await.is_err() {
                    return;
                }
                let records = RecordReader::default().push(&bytes);
                let whole = records.len() == FRAGMENTS as usize
                    && records.iter().all(|r| {
                        VideoPacket::from_bytes(r)
                            .is_ok_and(|p| p.session_id == sharer && p.fragment_count == FRAGMENTS)
                    });
                if whole {
                    counted.fetch_add(1, Ordering::Relaxed);
                }
            });
        }
    });
    count
}

async fn frames_come(what: &str, count: &AtomicU64, past: u64) {
    tokio::time::timeout(HANG, async {
        while count.load(Ordering::Relaxed) <= past {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no frames came {what}"));
}

/// A viewer's session with the edge a `WatchAt` named, trusting only the certificates it
/// named, and `ticket` shown: the edge's first word.
struct EdgeSession {
    _endpoint: Endpoint<Client>,
    conn: Connection,
    _send: SendStream,
    recv: RecvStream,
    buf: BytesMut,
}

impl EdgeSession {
    async fn open(view: &EdgeView, ticket: &[u8]) -> (Self, EdgeViewMsg) {
        let pins = view.cert_hashes.iter().map(|h| Sha256Digest::new(*h));
        let config = ClientConfig::builder()
            .with_bind_address("127.0.0.1:0".parse().unwrap())
            .with_custom_tls(tls(Arc::new(ServerHashVerification::new(pins))))
            .build();
        let endpoint = Endpoint::client(config).unwrap();
        let conn = tokio::time::timeout(
            HANG,
            endpoint.connect(format!("https://{}:{}{VIEW_PATH}", view.host, view.port)),
        )
        .await
        .expect("the connect neither went through nor failed")
        .expect("the edge refused the session");
        let (mut send, recv) = conn.open_bi().await.unwrap().await.unwrap();
        let hello = ViewerMsg::Hello {
            ticket: ticket.to_vec(),
        };
        send.write_all(&encode_viewer_msg(&hello).unwrap())
            .await
            .unwrap();
        let mut session = Self {
            _endpoint: endpoint,
            conn,
            _send: send,
            recv,
            buf: BytesMut::new(),
        };
        let word = session.word().await;
        (session, word)
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

fn refused() -> EdgeViewMsg {
    EdgeViewMsg::Ended {
        reason: "ticket refused".into(),
    }
}

// ── The tests ──────────────────────────────────────────────────────────

/// Ten viewers of one share with `local_first = 2`: the first two watch from the relay,
/// the other eight from the edge, which the relay feeds one copy. The edge dies as a
/// process does, with no word: its link's idle timeout tells the relay, which seats its
/// eight viewers itself (`WatchAt` without an edge), and they have frames from it again
/// within 8 s.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn viewers_past_local_first_watch_through_the_edge_and_are_back_on_the_relay_when_it_dies() {
    let operator = Operator::new();
    let core_port = free_port();
    let state = relay(core_port, &operator, 2).unwrap();
    let edge_port = free_port();
    let mut process = Process::new();
    let edge = process
        .enter(|| edge::start(edge_settings(core_port, operator.pin, SECRET, edge_port)).unwrap());
    linked(&state, &edge).await;

    let (alice, room) = sharer(core_port).await;
    struct Viewer {
        app: App,
        from_relay: Arc<AtomicU64>,
        edge: Option<(EdgeSession, Arc<AtomicU64>)>,
    }
    let mut viewers = Vec::new();
    for i in 0..10 {
        let mut app = App::connect(core_port, &format!("viewer{i}")).await;
        app.join(room).await;
        let from_relay = count_frames(app.conn.clone(), alice.session_id);
        let (watching, at) = app.watch(alice.user_id).await;
        assert!(watching, "viewer {i} is not watching");
        let edge = match at {
            None => {
                assert!(i < 2, "viewer {i} was kept on the relay");
                None
            }
            Some((_, view)) => {
                assert!(i >= 2, "viewer {i} of the first two was sent to the edge");
                assert_eq!((view.host.as_str(), view.port), ("127.0.0.1", edge_port));
                assert_eq!(view.cert_hashes, edge.cert_hashes());
                let (session, word) = EdgeSession::open(&view, &view.ticket).await;
                assert_eq!(word, EdgeViewMsg::Ready, "viewer {i}");
                let from_edge = count_frames(session.conn.clone(), alice.session_id);
                Some((session, from_edge))
            }
        };
        viewers.push(Viewer {
            app,
            from_relay,
            edge,
        });
    }
    for (i, viewer) in viewers.iter().enumerate() {
        match &viewer.edge {
            None => {
                frames_come(
                    &format!("to viewer {i} from the relay"),
                    &viewer.from_relay,
                    0,
                )
                .await
            }
            Some((_, from_edge)) => {
                frames_come(&format!("to viewer {i} through the edge"), from_edge, 0).await
            }
        }
    }
    let pool = state.pool.as_ref().unwrap();
    let (edges, _) = pool.report();
    assert_eq!((edges[0].viewers, edges[0].shares), (8, 1));
    for (i, viewer) in viewers.iter().enumerate().skip(2) {
        assert_eq!(
            viewer.from_relay.load(Ordering::Relaxed),
            0,
            "viewer {i} on the edge got frames from the relay too"
        );
    }

    process.kill();
    let killed = Instant::now();
    for (i, viewer) in viewers.iter_mut().enumerate().skip(2) {
        let sharer = alice.user_id;
        let wait = tokio::time::timeout_at((killed + BACK_WITHIN).into(), async {
            viewer
                .app
                .until("WatchAt without an edge", |m| {
                    matches!(m, ServerMessage::WatchAt { sharer_user_id, edge: None, .. } if *sharer_user_id == sharer)
                })
                .await;
            while viewer.from_relay.load(Ordering::Relaxed) == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        assert!(
            wait.is_ok(),
            "viewer {i} had no frames from the relay {BACK_WITHIN:?} after the edge died"
        );
    }
    eprintln!(
        "the dead edge's viewers had frames from the relay again {:?} after it died",
        killed.elapsed()
    );
    let (edges, _) = pool.report();
    assert!(!edges[0].online);
    // The relay's own viewers never noticed
    for viewer in &viewers[..2] {
        let before = viewer.from_relay.load(Ordering::Relaxed);
        frames_come(
            "to the relay's own viewers after the edge died",
            &viewer.from_relay,
            before,
        )
        .await;
    }
}

/// A ticket the edge's secret did not seal, or one changed on the way, lets nobody in;
/// the ticket the relay sealed does, once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_forged_ticket_is_refused() {
    let operator = Operator::new();
    let core_port = free_port();
    let state = relay(core_port, &operator, 0).unwrap();
    let edge_port = free_port();
    let edge = edge::start(edge_settings(core_port, operator.pin, SECRET, edge_port)).unwrap();
    linked(&state, &edge).await;
    let (alice, room) = sharer(core_port).await;
    let mut bob = App::connect(core_port, "bob").await;
    bob.join(room).await;
    let (_, Some((_, view))) = bob.watch(alice.user_id).await else {
        panic!("bob was not sent to the edge");
    };

    // What the relay put in it, sealed with a secret guessed
    let body = crate::pool_keys::open(&crate::pool_keys::ticket_key(SECRET), &view.ticket).unwrap();
    let guessed = crate::pool_keys::ticket_key("a-guessed-secret-of-at-least-32-chars");
    let forged = crate::pool_keys::seal(&guessed, &body);
    assert_eq!(EdgeSession::open(&view, &forged).await.1, refused());
    // Its own ticket with one bit changed
    let mut changed = view.ticket.clone();
    changed[0] ^= 1;
    assert_eq!(EdgeSession::open(&view, &changed).await.1, refused());

    let (session, word) = EdgeSession::open(&view, &view.ticket).await;
    assert_eq!(word, EdgeViewMsg::Ready);
    frames_come(
        "through the edge",
        &count_frames(session.conn.clone(), alice.session_id),
        0,
    )
    .await;
    assert_eq!(
        EdgeSession::open(&view, &view.ticket).await.1,
        refused(),
        "shown twice"
    );
}

/// An edge whose secret is not the relay's is closed at its hello, counted, and never
/// linked: the viewers it would have had watch from the relay.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_edge_with_a_bad_secret_is_refused() {
    let operator = Operator::new();
    let core_port = free_port();
    let state = relay(core_port, &operator, 0).unwrap();
    let edge_port = free_port();
    let edge = edge::start(edge_settings(
        core_port,
        operator.pin,
        "not-the-secret-of-edge-one-0123456",
        edge_port,
    ))
    .unwrap();
    tokio::time::timeout(HANG, async {
        while !state
            .limits
            .take_counts()
            .contains_key(&("refused", "edge proof"))
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the relay never refused the edge's proof");
    assert!(!edge.is_linked());
    assert!(!state.pool.as_ref().unwrap().report().0[0].online);

    let (alice, room) = sharer(core_port).await;
    let mut bob = App::connect(core_port, "bob").await;
    bob.join(room).await;
    let from_relay = count_frames(bob.conn.clone(), alice.session_id);
    let (watching, at) = bob.watch(alice.user_id).await;
    assert!(watching);
    assert!(
        at.is_none(),
        "bob was sent to an edge the relay never linked"
    );
    frames_come("from the relay", &from_relay, 0).await;
    assert!(!edge.is_linked());
}

/// A relay that restarts starts its clocks, its slots and its user ids again, so a ticket of
/// its run before would read as good on the new one. The new link's id is random, which no
/// ticket of the old run holds: the edge refuses it, and takes the new run's own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_ticket_from_before_a_core_restart_is_refused() {
    let operator = Operator::new();
    let core_port = free_port();
    let mut first_run = Process::new();
    let first = first_run.enter(|| relay(core_port, &operator, 0).unwrap());
    let edge_port = free_port();
    let edge = edge::start(edge_settings(core_port, operator.pin, SECRET, edge_port)).unwrap();
    linked(&first, &edge).await;
    let (alice, room) = sharer(core_port).await;
    let mut bob = App::connect(core_port, "bob").await;
    bob.join(room).await;
    let (_, Some((_, old))) = bob.watch(alice.user_id).await else {
        panic!("bob was not sent to the edge");
    };

    // The relay dies with its state, and starts again on its port and certificate
    first_run.kill();
    drop((first, alice, bob));
    let second = tokio::time::timeout(HANG, async {
        loop {
            match relay(core_port, &operator, 0) {
                Ok(state) => return state,
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
    })
    .await
    .expect("the port stayed taken");
    linked(&second, &edge).await;

    assert_eq!(EdgeSession::open(&old, &old.ticket).await.1, refused());
    // The new run's own ticket for the same share, slot and viewer ids
    let (alice, room) = sharer(core_port).await;
    let mut bob = App::connect(core_port, "bob").await;
    bob.join(room).await;
    let (_, Some((_, new))) = bob.watch(alice.user_id).await else {
        panic!("bob was not sent to the edge");
    };
    let key = crate::pool_keys::ticket_key(SECRET);
    let (was, is) = (
        crate::pool_keys::open(&key, &old.ticket).unwrap(),
        crate::pool_keys::open(&key, &new.ticket).unwrap(),
    );
    assert_eq!(
        (was.share, was.slot),
        (is.share, is.slot),
        "the counters began again"
    );
    assert_ne!(was.link, is.link);
    assert_eq!(
        EdgeSession::open(&new, &new.ticket).await.1,
        EdgeViewMsg::Ready
    );
}
