//! Link to the server — the Rust twin of `client/src/web/backend/transport.ts`.
//!
//! QUIC first. One bidirectional stream carries the control channel in the
//! native framing (u32 big-endian length + postcard payload), QUIC datagrams
//! carry voice and screen-audio packets, and each video frame travels on its
//! own unidirectional stream as `[u16 big-endian len][packet]` records — in
//! both directions. Everything rides one UDP flow, so NAT rebinds and address
//! changes are handled by QUIC's connection migration.
//!
//! When something on the way drops UDP, the same session runs through a
//! WebSocket on the server's TLS port instead — the TCP fallback, if the
//! server has `tcp_fallback` on (`crates/voipc-server/src/tunnel.rs` has the
//! wire format). [`connect`] gives QUIC a head start and then races the tunnel
//! against it; whichever connects first carries the session. Either way the
//! rest of the client gets a [`Link`]: control as a byte stream, media through
//! the senders and inputs below.
//!
//! Certificate trust is what it was on TCP: either TOFU pinning of the
//! operator certificate keyed by `host:port` (`accept_invalid_certs`) or the
//! WebPKI roots. Over QUIC the server presents that certificate when the TLS
//! server name is [`NATIVE_SNI`] (browsers get a rotating hash-pinned one
//! instead), so the URL host is `NATIVE_SNI` and a fixed resolver dials the
//! real address. The TLS port presents it to everyone.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{info, warn};
use wtransport::config::{DnsLookupFuture, DnsResolver, QuicTransportConfig};
use wtransport::endpoint::endpoint_side::Client;
use wtransport::{ClientConfig, Connection, Endpoint, RecvStream, VarInt};

use voipc_protocol::video::RecordReader;
use voipc_protocol::ws::{self, Decoder, Message};

/// TLS server name that makes the server present its operator certificate
/// (`crates/voipc-server/src/web.rs::NATIVE_SNI`).
pub const NATIVE_SNI: &str = "voipc-native";

/// Bound for each connect phase (resolve, handshake, control stream, auth).
/// Without a deadline a black-holed host keeps the reconnect loop (and its
/// Cancel button) stuck for minutes.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long QUIC has the connect to itself before the TCP fallback joins the
/// race. A QUIC handshake, the server's address-validation Retry included, is
/// three round trips — far less than this on any link people talk over. With
/// UDP blocked it never finishes, and this is what that costs every connect.
const TCP_HEAD_START: Duration = Duration::from_secs(2);

/// Largest per-frame video stream we accept (a 1080p keyframe is well under 1 MiB).
const MAX_FRAME_STREAM_BYTES: u64 = 8 * 1024 * 1024;

/// What a server without the fallback answers the tunnel's TLS handshake with
/// (it offers no `http/1.1`), in words.
const NO_FALLBACK: &str = "this server has no TCP fallback (if UDP to it is blocked, \
     its operator can turn on tcp_fallback)";

/// The QUIC handles that outlive the per-stream tasks.
pub struct Quic {
    pub endpoint: Endpoint<Client>,
    pub connection: Connection,
}

impl Quic {
    /// Close the connection and give the endpoint a moment to put
    /// CONNECTION_CLOSE on the wire, so the server frees the username right
    /// away instead of after its 30 s idle timeout.
    pub async fn close(&self) {
        self.connection.close(VarInt::from_u32(0), b"");
        let _ = tokio::time::timeout(Duration::from_millis(500), self.endpoint.wait_idle()).await;
    }
}

/// What carries a session.
pub enum Conn {
    Quic(Quic),
    Tunnel(Tunnel),
}

impl Conn {
    /// Whether the session runs over the TCP fallback.
    pub fn is_tunnel(&self) -> bool {
        matches!(self, Conn::Tunnel(_))
    }

    /// Close so the server frees the username right away rather than after
    /// its idle timeout and a quick reconnect gets "already taken".
    pub async fn close(&mut self) {
        match self {
            Conn::Quic(quic) => quic.close().await,
            Conn::Tunnel(tunnel) => tunnel.close().await,
        }
    }
}

/// An established session: the transport plus its control channel.
pub struct Link {
    pub conn: Conn,
    pub control_send: Box<dyn AsyncWrite + Send + Unpin>,
    pub control_recv: Box<dyn AsyncRead + Send + Unpin>,
}

/// Resolve `host` and connect: QUIC first, the TCP fallback once QUIC has
/// had [`TCP_HEAD_START`] to itself or has failed. The first to connect
/// carries the session; when neither does, the error names both.
///
/// `VOIPC_TRANSPORT=tcp` skips QUIC, to test the fallback without blocking UDP.
/// With the link, the fingerprint pinned on this connect when it was the
/// first sight of the server's certificate, for the person to compare with
/// what the server's operator gives them (`voipc-server cert fingerprint`).
pub async fn connect(
    host: &str,
    port: u16,
    accept_invalid_certs: bool,
) -> Result<(Link, Option<String>), String> {
    let (link, first_sight) = connect_any(host, port, accept_invalid_certs).await?;
    let pinned = if accept_invalid_certs {
        tofu_pin(&tofu_key(host, port), &first_sight)
    } else {
        None
    };
    Ok((link, pinned))
}

/// SHA-256 as the server prints it: colon-separated upper-case hex.
fn fingerprint_text(fp: &[u8]) -> String {
    fp.iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// What one attempt's verifier saw of a certificate never pinned before. Its
/// own, per attempt: the QUIC and TCP attempts race, and only the one that
/// carries the session may be pinned (a loser verified last must not be).
type FirstSight = Arc<std::sync::Mutex<Option<Vec<u8>>>>;

async fn connect_any(
    host: &str,
    port: u16,
    accept_invalid_certs: bool,
) -> Result<(Link, FirstSight), String> {
    let addrs: Vec<SocketAddr> =
        tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::lookup_host((host, port)))
            .await
            .map_err(|_| format!("Timed out resolving {host}"))?
            .map_err(|e| format!("Could not resolve {host}: {e}"))?
            .collect();
    if addrs.is_empty() {
        return Err(format!("No addresses found for {host}"));
    }

    // One budget for every attempt on either transport, so a black-holed
    // address cannot stretch the connect past what the reconnect loop (and
    // its Cancel button) expects.
    let deadline = Instant::now() + CONNECT_TIMEOUT;
    if std::env::var("VOIPC_TRANSPORT").is_ok_and(|t| t == "tcp") {
        info!("VOIPC_TRANSPORT=tcp: skipping QUIC");
        return connect_tunnel(host, port, &addrs, accept_invalid_certs, deadline).await;
    }

    let quic = connect_quic(host, port, &addrs, accept_invalid_certs, deadline);
    tokio::pin!(quic);
    let quic_failed = tokio::select! {
        result = &mut quic => match result {
            Ok(link) => return Ok(link),
            Err(e) => Some(e),
        },
        _ = tokio::time::sleep(TCP_HEAD_START) => None,
    };
    let tcp = connect_tunnel(host, port, &addrs, accept_invalid_certs, deadline);
    tokio::pin!(tcp);
    let both = |quic: String, tcp: String| format!("{quic} (QUIC over UDP). TCP fallback: {tcp}");
    match quic_failed {
        Some(quic) => tcp.await.map_err(|tcp| both(quic, tcp)),
        None => tokio::select! {
            result = &mut quic => match result {
                Ok(link) => Ok(link),
                Err(quic) => tcp.await.map_err(|tcp| both(quic, tcp)),
            },
            result = &mut tcp => match result {
                Ok(link) => {
                    info!("QUIC did not get through within {TCP_HEAD_START:?}, using the TCP fallback");
                    Ok(link)
                }
                Err(tcp) => quic.await.map_err(|quic| both(quic, tcp)),
            },
        },
    }
}

/// Open the QUIC connection and the control stream.
///
/// Every resolved address is tried in order, not just the first: a name with
/// both an A and an AAAA record may well have a server listening on only one
/// of the two, and the resolver's order decides which one we see first.
async fn connect_quic(
    host: &str,
    port: u16,
    addrs: &[SocketAddr],
    accept_invalid_certs: bool,
    deadline: Instant,
) -> Result<(Link, FirstSight), String> {
    let mut last_err = format!("Could not connect to {host}:{port}");
    let mut established = None;
    for &server_addr in addrs {
        let (tls, sight) = tls_config(host, port, accept_invalid_certs, b"h3")?;
        // Bind in the server's address family: a v6 wildcard socket is not
        // available everywhere and a v4 one cannot reach a v6 server.
        let bind: SocketAddr = if server_addr.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        }
        .parse()
        .expect("literal bind address");
        // Few video frames in flight, sent in order, and a cap on what the
        // server may make us hold across every stream (by default nothing caps
        // the sum, so a hostile server could park ~155 MB here per open
        // server): see server_config in crates/voipc-server/src/web.rs for why.
        let mut transport = QuicTransportConfig::default();
        transport
            .max_concurrent_uni_streams(24u32.into())
            .receive_window((2u32 * 1024 * 1024).into())
            .send_fairness(false)
            // Stale voice is dropped, oldest first, instead of a 1 MiB backlog
            // bursting out after a stall (as on the relay, web.rs)
            .datagram_send_buffer_size(64 * 1024);
        let config = ClientConfig::builder()
            .with_bind_address(bind)
            .with_custom_tls_and_transport(tls, transport)
            // Keeps NAT mappings alive through silent channels; a vanished
            // server trips the 30 s idle timeout and surfaces as a read error.
            .keep_alive_interval(Some(Duration::from_secs(10)))
            .dns_resolver(Fixed(server_addr))
            .build();
        let endpoint = match Endpoint::client(config) {
            Ok(endpoint) => endpoint,
            Err(e) => {
                last_err = format!("Could not create QUIC endpoint for {server_addr}: {e}");
                warn!("{last_err}");
                continue;
            }
        };

        info!("connecting to {server_addr} over QUIC");
        let remaining = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(
            remaining,
            endpoint.connect(format!("https://{NATIVE_SNI}:{port}/voipc")),
        )
        .await
        {
            Ok(Ok(connection)) => {
                established = Some((endpoint, connection, sight));
                break;
            }
            Ok(Err(e)) => {
                last_err = format!("Could not connect to {host}:{port} ({server_addr}): {e}");
                warn!("{last_err}");
            }
            Err(_) => {
                last_err = format!("Timed out connecting to {host}:{port}");
                break;
            }
        }
    }
    let (endpoint, connection, sight) = established.ok_or(last_err)?;
    info!("QUIC handshake complete (rtt {:?})", connection.rtt());

    let (control_send, control_recv) = tokio::time::timeout(CONNECT_TIMEOUT, async {
        let opening = connection.open_bi().await.map_err(|e| e.to_string())?;
        opening.await.map_err(|e| e.to_string())
    })
    .await
    .map_err(|_| "Timed out opening the control stream".to_string())?
    .map_err(|e| format!("Could not open the control stream: {e}"))?;
    // Control messages must not wait behind video frames, which go out in order.
    control_send.set_priority(1);

    Ok((
        Link {
            conn: Conn::Quic(Quic {
                endpoint,
                connection,
            }),
            control_send: Box::new(control_send),
            control_recv: Box::new(control_recv),
        },
        sight,
    ))
}

// ── Media inputs ─────────────────────────────────────────────────────────

/// Server → client media datagrams: QUIC's, or the tunnel's.
pub enum DatagramIn {
    Quic(Connection),
    Tunnel(mpsc::Receiver<Bytes>),
}

impl DatagramIn {
    /// The next datagram; `None` once the link is gone.
    pub async fn recv(&mut self) -> Option<Bytes> {
        match self {
            DatagramIn::Quic(connection) => match connection.receive_datagram().await {
                Ok(datagram) => Some(datagram.payload()),
                Err(e) => {
                    info!("datagram receive ended: {e}");
                    None
                }
            },
            DatagramIn::Tunnel(rx) => rx.recv().await,
        }
    }
}

/// Server → client video records (`[u16 len]`-framed packets), in arrival
/// order: QUIC's per-frame streams read one after another, or the tunnel's
/// messages, one record each.
pub enum VideoIn {
    Quic {
        connection: Connection,
        /// The frame stream being read, its record reader and its size so far.
        frame: Option<(RecvStream, RecordReader, u64)>,
        chunk: Vec<u8>,
    },
    Tunnel(mpsc::Receiver<Vec<u8>>),
}

impl VideoIn {
    pub fn quic(connection: Connection) -> Self {
        VideoIn::Quic {
            connection,
            frame: None,
            chunk: vec![0; 16 * 1024],
        }
    }

    /// The records that arrived next — none, when a read ended mid-record —
    /// or `None` once the link is gone. Records are handed on as they arrive:
    /// waiting for a frame's FIN would add its whole transmission time to the
    /// latency.
    pub async fn next(&mut self) -> Option<Vec<Vec<u8>>> {
        let (connection, frame, chunk) = match self {
            VideoIn::Tunnel(rx) => return rx.recv().await.map(|record| vec![record]),
            VideoIn::Quic {
                connection,
                frame,
                chunk,
            } => (connection, frame, chunk),
        };
        loop {
            if frame.is_none() {
                match connection.accept_uni().await {
                    Ok(stream) => *frame = Some((stream, RecordReader::default(), 0)),
                    Err(e) => {
                        info!("video stream accept ended: {e}");
                        return None;
                    }
                }
            }
            let (stream, reader, total) = frame.as_mut().expect("opened above");
            // Err = reset by the server: the frame is lost, the assembler sees the gap
            match stream.read(chunk).await {
                Ok(Some(n)) => {
                    *total += n as u64;
                    if *total > MAX_FRAME_STREAM_BYTES {
                        *frame = None;
                        continue;
                    }
                    let records = reader.push(&chunk[..n]);
                    if reader.is_broken() {
                        *frame = None;
                    }
                    return Some(records);
                }
                Ok(None) | Err(_) => *frame = None,
            }
        }
    }
}

// ── TCP fallback ─────────────────────────────────────────────────────────

/// Largest tunnel message: a 64 KiB control chunk plus its tag (the server's
/// limit too).
const TUNNEL_MAX_MESSAGE: usize = 64 * 1024 + 1;
/// Control bytes per message we send.
const TUNNEL_CONTROL_CHUNK: usize = 16 * 1024;
/// Control bytes the tunnel can hold for the session's control reader. Large,
/// because that reader does Signal work: a join burst must not stall the
/// tunnel's reader — which reads the voice too — behind it. Over QUIC the two
/// are separate streams with flow control of their own.
const TUNNEL_CONTROL_BUFFER: usize = 1024 * 1024;
/// Nothing at all from the server for this long ends the tunnel. Its pongs
/// answer our keepalive ping every 10 s (network.rs `latency_task`).
const TUNNEL_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// The client end of the TCP fallback: one TLS stream carrying the
/// WebSocket, read and written by two tasks of its own, so the control
/// channel works from the first byte on (authentication runs over it).
pub struct Tunnel {
    /// Voice, screen audio and pings, sent ahead of everything else. A full
    /// lane drops the packet, as UDP would.
    pub datagrams: mpsc::Sender<Vec<u8>>,
    /// Video fragments, sent after control. Small: the backpressure belongs
    /// in the sharer's own queue (network.rs `video_tx`), where it is measured.
    pub video: mpsc::Sender<Vec<u8>>,
    /// What the server sent, each taken once by its receiver task.
    pub datagrams_in: Option<mpsc::Receiver<Bytes>>,
    pub video_in: Option<mpsc::Receiver<Vec<u8>>>,
    reader: JoinHandle<()>,
    writer: JoinHandle<()>,
}

impl Tunnel {
    /// Let the writer deliver what is still queued — the `Disconnect`
    /// teardown sent — and close the WebSocket, which it does once the
    /// control channel's sender is gone (teardown aborted its task); then
    /// stop reading. Bounded like [`Quic::close`].
    async fn close(&mut self) {
        let _ = tokio::time::timeout(Duration::from_millis(500), &mut self.writer).await;
        self.reader.abort();
    }
}

impl Drop for Tunnel {
    /// A link dropped without `close` — a refused login — must not leave
    /// tasks behind that hold the socket.
    fn drop(&mut self) {
        self.reader.abort();
        self.writer.abort();
    }
}

/// Connect over the TCP fallback: every resolved address in turn, within
/// the connect's deadline.
async fn connect_tunnel(
    host: &str,
    port: u16,
    addrs: &[SocketAddr],
    accept_invalid_certs: bool,
    deadline: Instant,
) -> Result<(Link, FirstSight), String> {
    // One attempt at a time below, so the slot holds the last one tried: the
    // one that connected.
    let (tls, sight) = tls_config(host, port, accept_invalid_certs, b"http/1.1")?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls));
    // The real name, unlike QUIC's NATIVE_SNI: the TLS port shows everyone
    // the operator certificate, and a proxy routing by SNI needs the name.
    // An IP literal sends none.
    let name = server_name(host)?;
    let host_header = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let mut last_err = format!("Could not connect to {host}:{port} over TCP");
    for &addr in addrs {
        info!("connecting to {addr} over the TCP fallback");
        let remaining = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(
            remaining,
            open_tunnel(&connector, name.clone(), addr, &host_header),
        )
        .await
        {
            Ok(Ok(link)) => return Ok((link, sight)),
            Ok(Err(e)) => {
                warn!("{e}");
                last_err = e;
            }
            Err(_) => {
                last_err = format!("Timed out connecting to {host}:{port} over TCP");
                break;
            }
        }
    }
    Err(last_err)
}

/// TCP, TLS, then the WebSocket upgrade at `/voipc`.
async fn open_tunnel(
    connector: &tokio_rustls::TlsConnector,
    name: ServerName<'static>,
    addr: SocketAddr,
    host_header: &str,
) -> Result<Link, String> {
    let tcp = TcpStream::connect(addr)
        .await
        .map_err(|e| format!("Could not connect to {addr} over TCP: {e}"))?;
    tune(&tcp);
    let mut tls = connector.connect(name, tcp).await.map_err(|e| {
        let e = e.to_string();
        if e.contains("NoApplicationProtocol") {
            NO_FALLBACK.to_string()
        } else {
            format!("TLS handshake with {addr} failed: {e}")
        }
    })?;

    use base64::Engine as _;
    let key = base64::engine::general_purpose::STANDARD.encode(rand::random::<[u8; 16]>());
    let request = format!(
        "GET /voipc HTTP/1.1\r\nHost: {host_header}\r\nUpgrade: websocket\r\n\
         Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    let upgrade_failed =
        |e: std::io::Error| format!("TCP fallback upgrade with {addr} failed: {e}");
    tls.write_all(request.as_bytes())
        .await
        .map_err(upgrade_failed)?;
    tls.flush().await.map_err(upgrade_failed)?;

    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    let end = loop {
        let n = tls.read(&mut chunk).await.map_err(upgrade_failed)?;
        if n == 0 {
            return Err(format!(
                "{addr} closed the connection during the TCP fallback upgrade"
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(end) = ws::find_header_end(&buf) {
            break end;
        }
        if buf.len() > 8 * 1024 {
            return Err(format!(
                "{addr} answered the TCP fallback upgrade with junk"
            ));
        }
    };
    let head = String::from_utf8_lossy(&buf[..end]).into_owned();
    if !head.starts_with("HTTP/1.1 101") {
        let status = head.lines().next().unwrap_or_default();
        return Err(format!("the server refused the TCP fallback ({status})"));
    }
    if ws::header(&head, "sec-websocket-accept") != Some(accept_key(&key).as_str()) {
        return Err(format!("{addr} answered the TCP fallback upgrade wrongly"));
    }
    info!("connected to {addr} over the TCP fallback");
    Ok(start_tunnel(tls, buf.split_off(end)))
}

/// No Nagle delay on small voice packets; on Linux and Android, also a short
/// unsent queue, so voice waits behind at most that much video in the kernel
/// (the server's tunnel.rs explains). Best effort.
fn tune(tcp: &TcpStream) {
    if let Err(e) = tcp.set_nodelay(true) {
        warn!("TCP_NODELAY: {e}");
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if let Err(e) = socket2::SockRef::from(tcp).set_tcp_notsent_lowat(16 * 1024) {
        warn!("TCP_NOTSENT_LOWAT: {e}");
    }
}

/// Start the tunnel's reader and writer over `stream` (TLS, or a pipe in the
/// tests) and hand out the session's ends. Control travels through two
/// one-way pipes rather than one duplex split in two: the reader ending (the
/// server closed, or went quiet) must read as the end of the control channel
/// at once, whatever the writer is doing.
fn start_tunnel<S>(stream: S, leftover: Vec<u8>) -> Link
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (tls_read, tls_write) = tokio::io::split(stream);
    let (control_down, control_recv) = tokio::io::duplex(TUNNEL_CONTROL_BUFFER);
    let (control_send, control_up) = tokio::io::duplex(TUNNEL_CONTROL_CHUNK * 4);
    let (datagrams, datagrams_rx) = mpsc::channel(64);
    let (video, video_rx) = mpsc::channel(16);
    let (datagrams_in_tx, datagrams_in) = mpsc::channel(256);
    let (video_in_tx, video_in) = mpsc::channel(512);
    let reader = tokio::spawn(tunnel_reader(
        tls_read,
        leftover,
        control_down,
        datagrams_in_tx,
        video_in_tx,
    ));
    let writer = tokio::spawn(tunnel_writer(tls_write, control_up, datagrams_rx, video_rx));
    Link {
        conn: Conn::Tunnel(Tunnel {
            datagrams,
            video,
            datagrams_in: Some(datagrams_in),
            video_in: Some(video_in),
            reader,
            writer,
        }),
        control_send: Box::new(control_send),
        control_recv: Box::new(control_recv),
    }
}

/// Server → client: control into the session's control channel, media to the
/// receiver tasks. Media that finds its queue full is dropped, as on the
/// wire: a slow video decoder must not stop the voice being read. Ending —
/// the server closed or went quiet — closes the control channel, which the
/// session reports as a lost connection.
async fn tunnel_reader<R: AsyncRead + Unpin>(
    mut tls: R,
    leftover: Vec<u8>,
    mut control: DuplexStream,
    datagrams: mpsc::Sender<Bytes>,
    video: mpsc::Sender<Vec<u8>>,
) {
    let mut decoder = Decoder::new(false, TUNNEL_MAX_MESSAGE);
    decoder.feed(&leftover);
    let mut chunk = vec![0u8; 16 * 1024];
    loop {
        loop {
            match decoder.next() {
                Ok(Some(Message::Binary(data))) => match data.first() {
                    Some(0x00) => {
                        if control.write_all(&data[1..]).await.is_err() {
                            return;
                        }
                    }
                    Some(0x13 | 0x14) => {
                        let _ = video.try_send(data);
                    }
                    Some(_) => {
                        let _ = datagrams.try_send(Bytes::from(data));
                    }
                    None => {}
                },
                Ok(Some(Message::Close)) => {
                    info!("the server closed the TCP fallback tunnel");
                    return;
                }
                // Text, pings, pongs: none of it is part of the tunnel
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(e) => {
                    warn!("TCP fallback framing broken: {e}");
                    return;
                }
            }
        }
        match tokio::time::timeout(TUNNEL_IDLE_TIMEOUT, tls.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => decoder.feed(&chunk[..n]),
            Ok(Ok(_)) => {
                info!("the server closed the TCP connection");
                return;
            }
            Ok(Err(e)) => {
                info!("TCP fallback read failed: {e}");
                return;
            }
            Err(_) => {
                info!("nothing from the server for {TUNNEL_IDLE_TIMEOUT:?}, giving the tunnel up");
                return;
            }
        }
    }
}

/// Client → server, one message at a time: datagrams first, then control,
/// then video, each masked (RFC 6455 asks it of a client) and flushed as it
/// is written — crates/voipc-server/src/tunnel.rs says why. Ends once the
/// session's control sender is gone, after a Close.
async fn tunnel_writer<W: AsyncWrite + Unpin>(
    mut tls: W,
    mut control: DuplexStream,
    mut datagrams: mpsc::Receiver<Vec<u8>>,
    mut video: mpsc::Receiver<Vec<u8>>,
) {
    let mut buf = vec![0u8; TUNNEL_CONTROL_CHUNK];
    let (mut datagrams_open, mut video_open) = (true, true);
    let mut out = Vec::with_capacity(TUNNEL_CONTROL_CHUNK + 16);
    loop {
        out.clear();
        // Only receiving happens in the select (recv and read are
        // cancel-safe), and the control branch is never disabled.
        tokio::select! {
            biased;
            packet = datagrams.recv(), if datagrams_open => match packet {
                Some(packet) => ws::encode_frame(&mut out, ws::OP_BINARY, &[&packet], Some(rand::random())),
                None => {
                    datagrams_open = false;
                    continue;
                }
            },
            read = control.read(&mut buf) => match read {
                Ok(0) | Err(_) => break,
                Ok(n) => ws::encode_frame(
                    &mut out,
                    ws::OP_BINARY,
                    &[&[0x00], &buf[..n]],
                    Some(rand::random()),
                ),
            },
            packet = video.recv(), if video_open => match packet {
                Some(packet) => ws::encode_frame(&mut out, ws::OP_BINARY, &[&packet], Some(rand::random())),
                None => {
                    video_open = false;
                    continue;
                }
            },
        }
        if send_frame(&mut tls, &out).await.is_err() {
            return;
        }
    }
    out.clear();
    ws::encode_frame(
        &mut out,
        ws::OP_CLOSE,
        &[&1000u16.to_be_bytes()],
        Some(rand::random()),
    );
    let _ = send_frame(&mut tls, &out).await;
    let _ = tls.shutdown().await;
}

async fn send_frame<W: AsyncWrite + Unpin>(tls: &mut W, frame: &[u8]) -> std::io::Result<()> {
    tls.write_all(frame).await?;
    tls.flush().await
}

/// RFC 6455: `Sec-WebSocket-Accept` is base64(SHA-1(key + GUID)). Shared
/// with the game SDK's socket.
pub(crate) fn accept_key(key: &str) -> String {
    use base64::Engine as _;
    let digest = ring::digest::digest(
        &ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
        format!("{key}{}", ws::GUID).as_bytes(),
    );
    base64::engine::general_purpose::STANDARD.encode(digest.as_ref())
}

fn server_name(host: &str) -> Result<ServerName<'static>, String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        Ok(ServerName::IpAddress(ip.into()))
    } else {
        ServerName::try_from(host.to_string())
            .map_err(|e| format!("Invalid server name '{host}': {e}"))
    }
}

fn tls_config(
    host: &str,
    port: u16,
    accept_invalid_certs: bool,
    alpn: &[u8],
) -> Result<(rustls::ClientConfig, FirstSight), String> {
    let sight = FirstSight::default();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| format!("TLS configuration error: {e}"))?;

    let mut config = if accept_invalid_certs {
        warn!("Using TOFU certificate pinning (self-signed mode)");
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(TofuCertVerifier {
                key: tofu_key(host, port),
                seen: sight.clone(),
            }))
            .with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let inner = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
            .build()
            .map_err(|e| format!("TLS configuration error: {e}"))?;
        let name = server_name(host)?;
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(VerifyAs { inner, name }))
            .with_no_client_auth()
    };
    config.alpn_protocols = vec![alpn.to_vec()];
    Ok((config, sight))
}

/// Resolves any host name to the server address, so the URL can carry
/// [`NATIVE_SNI`] as the server name while dialing what the user typed.
#[derive(Debug)]
struct Fixed(SocketAddr);

impl DnsResolver for Fixed {
    fn resolve(&self, _host: &str) -> Pin<Box<dyn DnsLookupFuture>> {
        let addr = self.0;
        Box::pin(async move { Ok(Some(addr)) })
    }
}

/// WebPKI verification against the real host name: the server name on the
/// wire is [`NATIVE_SNI`], which no public certificate carries.
#[derive(Debug)]
struct VerifyAs {
    inner: Arc<WebPkiServerVerifier>,
    name: ServerName<'static>,
}

impl ServerCertVerifier for VerifyAs {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.inner
            .verify_server_cert(end_entity, intermediates, &self.name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

// ── TOFU certificate pinning ────────────────────────────────────────────

/// TOFU (Trust On First Use) certificate pinning store.
/// Maps `host:port` to the SHA-256 fingerprint of the server's certificate.
/// On first connect, the cert is trusted and stored. On subsequent connects,
/// the cert must match the stored fingerprint or the connection is rejected.
/// Persisted to `tofu_pins.json` in the VoIPC data directory.
static TOFU_STORE: std::sync::LazyLock<std::sync::Mutex<HashMap<String, Vec<u8>>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(tofu_load_from_disk()));

/// The pin file could not be read. It is left as it is, nothing is pinned or
/// saved, and self-signed servers are refused until "Forget pinned
/// certificate" starts the list over: with no pins, every server would be a
/// first sight, and a man in the middle would be pinned unseen.
static TOFU_BROKEN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Pin what the verifier of the connection that carries the session saw, on
/// first sight. The verifier runs before the handshake proves the server holds
/// the key, so pinning there let anybody on the path who could show *a*
/// certificate — with no key behind it — pin theirs, and lock the real server
/// out as "fingerprint changed".
fn tofu_pin(key: &str, seen: &FirstSight) -> Option<String> {
    let fingerprint = seen.lock().unwrap_or_else(|p| p.into_inner()).take()?;
    let mut store = TOFU_STORE.lock().unwrap_or_else(|p| p.into_inner());
    if store.contains_key(key) {
        return None;
    }
    info!("TOFU: pinning certificate for {} (first connection)", key);
    let text = fingerprint_text(&fingerprint);
    store.insert(key.to_string(), fingerprint);
    tofu_save_to_disk(&store);
    Some(text)
}

fn tofu_path() -> std::path::PathBuf {
    crate::config::data_dir().join("tofu_pins.json")
}

/// Load TOFU pins from disk: none for a missing file; for one that does not
/// read, none and `TOFU_BROKEN`.
/// The pin file: `{ "host:port": "base64 fingerprint", ... }`, the shape
/// since 0.x (an older build fails open on any other); `None` if any of it
/// does not read.
pub(crate) fn tofu_parse(data: &str) -> Option<HashMap<String, Vec<u8>>> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    serde_json::from_str::<HashMap<String, String>>(data)
        .ok()
        .and_then(|map| {
            map.into_iter()
                .map(|(k, v)| STANDARD.decode(&v).ok().map(|bytes| (k, bytes)))
                .collect()
        })
}

fn tofu_load_from_disk() -> HashMap<String, Vec<u8>> {
    let path = tofu_path();
    let data = match std::fs::read_to_string(&path) {
        Ok(data) => data,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return HashMap::new(),
        Err(e) => {
            warn!("TOFU: cannot read {}: {e}", path.display());
            TOFU_BROKEN.store(true, std::sync::atomic::Ordering::Relaxed);
            return HashMap::new();
        }
    };
    tofu_parse(&data).unwrap_or_else(|| {
        warn!("TOFU: {} does not read; it is kept, and self-signed servers are refused until the pins are reset", path.display());
        TOFU_BROKEN.store(true, std::sync::atomic::Ordering::Relaxed);
        HashMap::new()
    })
}

/// Save TOFU pins to disk, keeping the previous file as `.bak`. Errors are
/// logged but non-fatal; nothing is written over a file that did not read.
fn tofu_save_to_disk(store: &HashMap<String, Vec<u8>>) {
    use base64::{engine::general_purpose::STANDARD, Engine};
    if TOFU_BROKEN.load(std::sync::atomic::Ordering::Relaxed) {
        return;
    }
    let path = tofu_path();
    if path.exists() {
        let _ = std::fs::copy(&path, path.with_file_name("tofu_pins.json.bak"));
    }
    let b64_map: HashMap<&str, String> = store
        .iter()
        .map(|(k, v)| (k.as_str(), STANDARD.encode(v)))
        .collect();
    match serde_json::to_string_pretty(&b64_map) {
        Ok(json) => {
            if let Err(e) = crate::config::write_atomic(&path, json.as_bytes()) {
                warn!("Failed to save TOFU pins: {}", e);
            }
        }
        Err(e) => warn!("Failed to serialize TOFU pins: {}", e),
    }
}

/// Pin store key: `host:port`, lowercase. Per port, so two self-signed
/// servers on one box do not read as a MITM of each other.
fn tofu_key(host: &str, port: u16) -> String {
    format!("{}:{}", host.to_lowercase(), port)
}

/// Forget the pinned certificate for a server (after a legitimate cert
/// rotation). The next connect pins the new certificate.
pub fn tofu_forget(host: &str, port: u16) -> bool {
    let mut store = TOFU_STORE.lock().unwrap_or_else(|p| {
        warn!("mutex poisoned, recovering");
        p.into_inner()
    });
    // A pin list that did not read starts over here, by the person's choice:
    // the old file is kept beside it.
    if TOFU_BROKEN.load(std::sync::atomic::Ordering::Relaxed) {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let path = tofu_path();
        if std::fs::rename(
            &path,
            path.with_file_name(format!("tofu_pins.json.unreadable-{secs}")),
        )
        .is_ok()
        {
            TOFU_BROKEN.store(false, std::sync::atomic::Ordering::Relaxed);
            store.clear();
            return true;
        }
        return false;
    }
    let removed = store.remove(&tofu_key(host, port)).is_some();
    if removed {
        tofu_save_to_disk(&store);
    }
    removed
}

/// Certificate verifier that accepts self-signed certs with TOFU pinning.
/// First connection to a host:port: accept and pin the certificate fingerprint.
/// Subsequent connections: reject if the certificate fingerprint changes.
#[derive(Debug)]
struct TofuCertVerifier {
    key: String,
    seen: FirstSight,
}

impl ServerCertVerifier for TofuCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // Compute SHA-256 fingerprint of the server's certificate
        use ring::digest;
        let fingerprint = digest::digest(&digest::SHA256, end_entity.as_ref());
        let fp_bytes = fingerprint.as_ref().to_vec();
        let host_key = &self.key;

        let store = TOFU_STORE.lock().unwrap_or_else(|p| {
            warn!("mutex poisoned, recovering");
            p.into_inner()
        });
        // The UI matches on "fingerprint changed" to offer forgetting the
        // pin, which is also what starts an unreadable pin list over.
        if TOFU_BROKEN.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(rustls::Error::General(
                "The saved certificate fingerprint changed state: the pin file (tofu_pins.json) could not be read. \
                 It is kept as it is, and self-signed servers are refused until you use \"Forget pinned certificate\", \
                 which starts the pin list over."
                    .into(),
            ));
        }

        if let Some(pinned) = store.get(host_key) {
            // We've connected to this host before — verify the fingerprint matches
            if *pinned != fp_bytes {
                warn!(
                    "TOFU: certificate fingerprint changed for {}! Possible MITM attack.",
                    host_key
                );
                // The UI matches on "fingerprint changed" to offer forgetting the
                // pin, and reads the two fingerprints out of the message to show
                // them side by side before anyone trusts the new one.
                return Err(rustls::Error::General(format!(
                    "Server certificate fingerprint changed for {}. \
                     This could indicate a man-in-the-middle attack. \
                     Only if you know the server's certificate was replaced, \
                     use \"Forget pinned certificate\" and connect again. \
                     (remembered SHA-256 {}; offered SHA-256 {})",
                    host_key,
                    fingerprint_text(pinned),
                    fingerprint_text(&fp_bytes)
                )));
            }
            info!("TOFU: certificate fingerprint matches for {}", host_key);
        } else {
            // First connection: pinned by `connect` once the handshake has
            // proved the key, and only for the attempt that won (`tofu_pin`)
            *self.seen.lock().unwrap_or_else(|p| p.into_inner()) = Some(fp_bytes);
        }

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The verifier sees the certificate before the handshake proves the
    /// server holds its key, so it must not pin by itself: only a connect
    /// that went through does (`tofu_settle`).
    #[test]
    fn first_sight_pins_nothing_until_the_connection_is_up() {
        let key = tofu_key("tofu-test.invalid", 1);
        let verifier = TofuCertVerifier {
            key: key.clone(),
            seen: FirstSight::default(),
        };
        let cert = CertificateDer::from(vec![1u8, 2, 3]);
        let name = ServerName::try_from("tofu-test.invalid").unwrap();
        verifier
            .verify_server_cert(&cert, &[], &name, &[], UnixTime::now())
            .unwrap();
        assert!(!TOFU_STORE.lock().unwrap().contains_key(&key));
        assert!(
            verifier.seen.lock().unwrap().is_some(),
            "seen, for the connect to pin if it wins"
        );
    }

    /// H4-04: the QUIC and TCP attempts race. A loser that verifies last (an
    /// injected certificate with no key behind it) must not be what is
    /// pinned; the winner's own slot is.
    #[test]
    fn only_the_attempt_that_carries_the_session_is_pinned() {
        // Pinning saves: never into the real data directory (config::data_dir)
        assert!(crate::config::data_dir().starts_with(std::env::temp_dir()));
        let key = tofu_key("tofu-race.invalid", 2);
        let name = ServerName::try_from("tofu-race.invalid").unwrap();
        let winner = TofuCertVerifier {
            key: key.clone(),
            seen: FirstSight::default(),
        };
        let loser = TofuCertVerifier {
            key: key.clone(),
            seen: FirstSight::default(),
        };
        winner
            .verify_server_cert(
                &CertificateDer::from(vec![1u8]),
                &[],
                &name,
                &[],
                UnixTime::now(),
            )
            .unwrap();
        loser
            .verify_server_cert(
                &CertificateDer::from(vec![6u8, 6, 6]),
                &[],
                &name,
                &[],
                UnixTime::now(),
            )
            .unwrap();
        tofu_pin(&key, &winner.seen);
        let pinned = TOFU_STORE.lock().unwrap().get(&key).cloned();
        assert_eq!(
            pinned.as_deref(),
            Some(ring::digest::digest(&ring::digest::SHA256, &[1u8]).as_ref())
        );
        TOFU_STORE.lock().unwrap().remove(&key);
    }

    #[test]
    fn accept_key_matches_the_rfc_example() {
        // RFC 6455 §1.3
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    /// The tunnel's two tasks against an in-memory server: routing by tag and
    /// packet type, masking by direction, voice ahead of control ahead of
    /// video, and either side closing showing on the other.
    #[tokio::test]
    async fn the_tunnel_routes_masks_orders_and_closes() {
        let (ours, mut server) = tokio::io::duplex(1 << 20);
        let Link {
            conn,
            mut control_send,
            mut control_recv,
        } = start_tunnel(ours, Vec::new());
        let Conn::Tunnel(mut tunnel) = conn else {
            unreachable!("start_tunnel builds a tunnel")
        };
        let mut datagrams_in = tunnel.datagrams_in.take().unwrap();
        let mut video_in = tunnel.video_in.take().unwrap();

        // Server → client, unmasked as a server's frames are
        let mut wire = Vec::new();
        ws::encode_frame(&mut wire, ws::OP_BINARY, &[&[0x00], b"hello"], None);
        ws::encode_frame(&mut wire, ws::OP_BINARY, &[&[0x05, 1, 2]], None);
        ws::encode_frame(&mut wire, ws::OP_BINARY, &[&[0x13, 3]], None);
        server.write_all(&wire).await.unwrap();
        let mut hello = [0u8; 5];
        control_recv.read_exact(&mut hello).await.unwrap();
        assert_eq!(&hello, b"hello");
        assert_eq!(&datagrams_in.recv().await.unwrap()[..], [0x05, 1, 2]);
        assert_eq!(video_in.recv().await.unwrap(), [0x13, 3]);

        // Client → server: all three queued before the writer runs, so the
        // order on the wire is its choice. Masked, or this decoder refuses.
        tunnel.video.try_send(vec![0x13, 9]).unwrap();
        control_send.write_all(b"ctl").await.unwrap();
        tunnel.datagrams.try_send(vec![0x05, 7]).unwrap();
        let mut decoder = Decoder::new(true, TUNNEL_MAX_MESSAGE);
        let mut got = Vec::new();
        let mut chunk = [0u8; 1024];
        while got.len() < 3 {
            let n = server.read(&mut chunk).await.unwrap();
            decoder.feed(&chunk[..n]);
            while let Some(message) = decoder.next().unwrap() {
                got.push(message);
            }
        }
        assert_eq!(
            got,
            [
                Message::Binary(vec![0x05, 7]),
                Message::Binary(b"\0ctl".to_vec()),
                Message::Binary(vec![0x13, 9])
            ]
        );

        // Our side closing — the session dropped its control sender — sends
        // a Close
        drop(control_send);
        loop {
            let n = server.read(&mut chunk).await.unwrap();
            assert!(n > 0, "closed without a Close frame");
            decoder.feed(&chunk[..n]);
            if let Some(message) = decoder.next().unwrap() {
                assert_eq!(message, Message::Close);
                break;
            }
        }

        // The server's Close ends the control channel: the session sees EOF
        let mut close = Vec::new();
        ws::encode_frame(&mut close, ws::OP_CLOSE, &[&1000u16.to_be_bytes()], None);
        server.write_all(&close).await.unwrap();
        let mut rest = Vec::new();
        control_recv.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
    }
}
