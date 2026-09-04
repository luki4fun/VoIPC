//! Browser client support.
//!
//! Two pieces: the HTTP/2-only static page served on the TLS port (the
//! embedded `client/dist-web` bundle plus `/wt.json`), and the WebTransport
//! bridge that maps a browser session onto the native paths — control bytes
//! go through an in-process duplex into `tcp::handle_connection`, media
//! packets through a loopback UDP socket into `udp::run_udp_loop`. The bridge
//! never parses control messages and reads only the frame header of video
//! fragments; all crypto happens in the browser.

use std::borrow::Cow;
use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::header::{self, HeaderValue};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rust_embed::Embed;
use tokio::io::{AsyncWriteExt, DuplexStream};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_rustls::server::TlsStream;
use tracing::{debug, info, warn};
use wtransport::config::Ipv6DualStackConfig;
use wtransport::endpoint::endpoint_side::Server;
use wtransport::error::SendDatagramError;
use wtransport::tls::Sha256Digest;
use wtransport::{Connection, Endpoint, Identity, SendStream, ServerConfig as WtServerConfig, VarInt};

use voipc_protocol::video::VIDEO_HEADER_SIZE;
use voipc_protocol::voice::VOICE_HEADER_SIZE;

use crate::config::ServerConfig;
use crate::state::ServerState;
use crate::{tcp, ConnLimits};

/// Largest UDP packet the media loop accepts (same as `udp::MAX_UDP_PACKET_SIZE`).
const MAX_PACKET_SIZE: usize = 1500;

/// Sent with every response. Scripts are the bundle's own (wasm needs
/// `wasm-unsafe-eval`), `connect-src https:` lets the page fetch `/wt.json`
/// and open the WebTransport session, media comes from blob: URLs, and
/// Svelte's component styles are inline.
const CSP: &str = "default-src 'self'; connect-src 'self' https:; \
    script-src 'self' 'wasm-unsafe-eval'; worker-src 'self' blob:; \
    img-src 'self' data: blob:; media-src blob:; style-src 'self' 'unsafe-inline'";

/// The built web client (`./build-web.sh`), embedded at compile time.
#[derive(Embed)]
#[folder = "../../client/dist-web/"]
struct WebAssets;

/// What the page needs to open the WebTransport session, published at `/wt.json`.
pub struct WtInfo {
    port: u16,
    /// SHA-256 of the current QUIC certificate; replaced on rotation.
    cert_hash: RwLock<Sha256Digest>,
}

// ── HTTP/2 static page ──────────────────────────────────────────────────

/// Serve the web client over HTTP/2 on a TLS stream that negotiated `h2`.
pub async fn serve_h2(tls: TlsStream<TcpStream>, wt: Option<Arc<WtInfo>>, peer: SocketAddr) {
    let service = service_fn(move |req: Request<Incoming>| {
        let wt = wt.clone();
        async move { Ok::<_, Infallible>(handle_request(&req, wt.as_deref())) }
    });
    if let Err(e) = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
        .serve_connection(TokioIo::new(tls), service)
        .await
    {
        debug!(%peer, "h2 connection ended: {e}");
    }
}

fn handle_request(req: &Request<Incoming>, wt: Option<&WtInfo>) -> Response<Full<Bytes>> {
    let head_only = req.method() == Method::HEAD;
    let mut resp = if req.method() == Method::GET || head_only {
        route(req.uri().path(), wt)
    } else {
        let mut resp = plain(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
        resp.headers_mut()
            .insert(header::ALLOW, HeaderValue::from_static("GET, HEAD"));
        resp
    };
    let headers = resp.headers_mut();
    headers.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(CSP));
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    if head_only {
        *resp.body_mut() = Full::new(Bytes::new());
    }
    resp
}

fn route(path: &str, wt: Option<&WtInfo>) -> Response<Full<Bytes>> {
    // web_port = 0: the web client is disabled, so the page does not exist.
    let Some(wt) = wt else {
        return plain(StatusCode::NOT_FOUND, "not found");
    };

    if path == "/wt.json" {
        let hash = wt.cert_hash.read().unwrap_or_else(PoisonError::into_inner);
        let hash: &[u8; 32] = hash.as_ref();
        let body = format!(r#"{{"port":{},"hash":"{}"}}"#, wt.port, hex::encode(hash));
        let mut resp = Response::new(Full::new(Bytes::from(body)));
        let headers = resp.headers_mut();
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        return resp;
    }

    let rel = if path == "/" {
        "index.html"
    } else {
        path.trim_start_matches('/')
    };
    // The embed is a fixed map so nothing outside the bundle can be reached,
    // but be explicit at the trust boundary anyway.
    if rel
        .split('/')
        .any(|seg| seg.is_empty() || seg == "." || seg == "..")
    {
        return plain(StatusCode::NOT_FOUND, "not found");
    }

    match WebAssets::get(rel) {
        Some(file) => {
            let body = match file.data {
                Cow::Borrowed(bytes) => Bytes::from_static(bytes),
                Cow::Owned(vec) => Bytes::from(vec),
            };
            let mut resp = Response::new(Full::new(body));
            let mime = HeaderValue::from_str(file.metadata.mimetype())
                .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream"));
            resp.headers_mut().insert(header::CONTENT_TYPE, mime);
            resp
        }
        None if rel == "index.html" && WebAssets::iter().next().is_none() => plain(
            StatusCode::NOT_FOUND,
            "web client not built: run ./build-web.sh",
        ),
        None => plain(StatusCode::NOT_FOUND, "not found"),
    }
}

fn plain(status: StatusCode, text: &'static str) -> Response<Full<Bytes>> {
    let mut resp = Response::new(Full::new(Bytes::from_static(text.as_bytes())));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    resp
}

// ── WebTransport endpoint ───────────────────────────────────────────────

/// The QUIC endpoint browsers connect to, with its rotating self-signed identity.
pub struct WebTransport {
    endpoint: Endpoint<Server>,
    bind_addr: SocketAddr,
    sans: Vec<String>,
    info: Arc<WtInfo>,
}

impl WebTransport {
    /// Bind on `host:web_port` with a fresh certificate.
    pub fn bind(config: &ServerConfig) -> Result<Self> {
        let bind_addr: SocketAddr = format!("{}:{}", config.host, config.web_port)
            .parse()
            .with_context(|| {
                format!(
                    "invalid WebTransport address {}:{}",
                    config.host, config.web_port
                )
            })?;

        // Browsers pin the certificate by hash (serverCertificateHashes), the
        // SANs just keep it honest: the bind IP when it is a concrete one,
        // plus localhost.
        let mut sans = Vec::new();
        if !bind_addr.ip().is_unspecified() {
            sans.push(bind_addr.ip().to_string());
        }
        sans.push("localhost".to_string());

        let identity = self_signed_identity(&sans)?;
        let cert_hash = certificate_hash(&identity);
        let endpoint = Endpoint::server(server_config(bind_addr, identity))
            .with_context(|| format!("failed to bind WebTransport on {bind_addr}"))?;

        Ok(Self {
            endpoint,
            bind_addr,
            sans,
            info: Arc::new(WtInfo {
                port: config.web_port,
                cert_hash: RwLock::new(cert_hash),
            }),
        })
    }

    pub fn info(&self) -> Arc<WtInfo> {
        self.info.clone()
    }

    /// Accept sessions forever. The certificate is replaced every 7 days
    /// (`VOIPC_WT_ROTATE_SECS` overrides the interval for testing); running
    /// sessions keep their old one.
    pub async fn run(self, state: Arc<ServerState>, media_addr: SocketAddr, limits: Arc<ConnLimits>) {
        let rotate_every = std::env::var("VOIPC_WT_ROTATE_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|secs| *secs > 0)
            .map(Duration::from_secs)
            .unwrap_or(Duration::from_secs(7 * 24 * 60 * 60));
        let mut rotate = tokio::time::interval(rotate_every);
        rotate.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        rotate.tick().await; // the first tick fires immediately

        loop {
            let incoming = tokio::select! {
                incoming = self.endpoint.accept() => incoming,
                _ = rotate.tick() => {
                    self.rotate_certificate();
                    continue;
                }
            };

            let peer = incoming.remote_address();
            if state.is_banned(peer.ip()) {
                debug!(%peer, "refusing WebTransport session: banned");
                incoming.refuse();
                continue;
            }
            if let Err(reason) = limits.acquire(peer.ip()) {
                warn!(%peer, "rejecting WebTransport session: {reason}");
                incoming.refuse();
                continue;
            }

            let state = state.clone();
            let limits = limits.clone();
            tokio::spawn(async move {
                // Same deadline as the TLS handshake on the TCP side.
                match tokio::time::timeout(Duration::from_secs(10), incoming).await {
                    Ok(Ok(request)) => {
                        if request.path() != "/voipc" {
                            warn!(%peer, path = request.path(), "rejecting WebTransport session: unknown path");
                            request.not_found().await;
                        } else {
                            match request.accept().await {
                                Ok(connection) => run_session(connection, state, media_addr, peer).await,
                                Err(e) => warn!(%peer, "WebTransport session accept failed: {e}"),
                            }
                        }
                    }
                    Ok(Err(e)) => warn!(%peer, "WebTransport handshake failed: {e}"),
                    Err(_) => warn!(%peer, "WebTransport handshake timed out"),
                }
                limits.release(peer.ip());
            });
        }
    }

    fn rotate_certificate(&self) {
        let identity = match self_signed_identity(&self.sans) {
            Ok(identity) => identity,
            Err(e) => {
                warn!("WebTransport certificate rotation failed: {e}");
                return;
            }
        };
        let cert_hash = certificate_hash(&identity);
        if let Err(e) = self
            .endpoint
            .reload_config(server_config(self.bind_addr, identity), false)
        {
            warn!("WebTransport certificate rotation failed: {e}");
            return;
        }
        *self
            .info
            .cert_hash
            .write()
            .unwrap_or_else(PoisonError::into_inner) = cert_hash;
        info!("rotated WebTransport certificate");
    }
}

/// ECDSA P-256, 14 days: what browsers require for hash-pinned certificates.
fn self_signed_identity(sans: &[String]) -> Result<Identity> {
    Identity::self_signed(sans).context("failed to generate WebTransport certificate")
}

fn certificate_hash(identity: &Identity) -> Sha256Digest {
    identity
        .certificate_chain()
        .as_slice()
        .first()
        .expect("self-signed identity carries one certificate")
        .hash()
}

fn server_config(bind_addr: SocketAddr, identity: Identity) -> WtServerConfig {
    let builder = match bind_addr {
        SocketAddr::V4(_) => WtServerConfig::builder().with_bind_address(bind_addr),
        // Dual-stack, like the media socket in main.rs
        SocketAddr::V6(addr) => {
            WtServerConfig::builder().with_bind_address_v6(addr, Ipv6DualStackConfig::Allow)
        }
    };
    builder
        .with_identity(identity)
        // An idle tab must not hit the browser's idle timeout; a vanished
        // peer still trips ours (30 s default) because it never acks.
        .keep_alive_interval(Some(Duration::from_secs(10)))
        .build()
}

// ── Per-session bridge ──────────────────────────────────────────────────

/// Bridge one WebTransport session onto the native control and media paths
/// until either side goes away.
async fn run_session(
    connection: Connection,
    state: Arc<ServerState>,
    media_addr: SocketAddr,
    peer: SocketAddr,
) {
    let label = format!("web:{}", peer.ip());

    let loopback = match bind_loopback(media_addr).await {
        Ok(socket) => socket,
        Err(e) => {
            warn!(peer = %label, "failed to create media loopback socket: {e}");
            connection.close(VarInt::from_u32(1), b"media socket");
            return;
        }
    };
    let bridge_ip = match loopback.local_addr() {
        Ok(addr) => addr.ip(),
        Err(e) => {
            warn!(peer = %label, "failed to read media loopback address: {e}");
            connection.close(VarInt::from_u32(1), b"media socket");
            return;
        }
    };
    info!(peer = %label, bridge = %bridge_ip, "WebTransport session established");

    // The control handler starts now, so its 5 s authentication deadline
    // covers the browser opening the control stream as well.
    let (handler_end, bridge_end) = tokio::io::duplex(65536);
    let mut handler = tokio::spawn(tcp::handle_connection(
        handler_end,
        label.clone(),
        peer.ip(),
        bridge_ip,
        state,
    ));

    let loopback = Arc::new(loopback);
    let (video_tx, video_rx) = mpsc::channel::<Bytes>(512);
    let mut pumps = JoinSet::new();
    pumps.spawn(pump_control(connection.clone(), bridge_end));
    pumps.spawn(pump_datagrams_in(connection.clone(), loopback.clone()));
    pumps.spawn(pump_media_out(connection.clone(), loopback, video_tx));
    pumps.spawn(pump_video_streams(connection.clone(), video_rx));

    tokio::select! {
        _ = pumps.join_next() => debug!(peer = %label, "bridge leg ended"),
        _ = &mut handler => debug!(peer = %label, "control handler ended"),
        e = connection.closed() => debug!(peer = %label, "session closed: {e}"),
    }

    // Aborting the pumps drops the bridge end of the duplex: the control
    // handler sees EOF and runs its normal session cleanup.
    pumps.shutdown().await;
    connection.close(VarInt::from_u32(0), b"");
    if !handler.is_finished()
        && tokio::time::timeout(Duration::from_secs(10), &mut handler)
            .await
            .is_err()
    {
        warn!(peer = %label, "control handler did not exit after EOF, aborting");
        handler.abort();
    }
    info!(peer = %label, "WebTransport session ended");
}

/// A loopback socket standing in for the browser on the server's own media
/// socket. `udp::resolve_session` checks the packet source IP against the
/// session's peer IP, so the socket must be bound to the exact IP the media
/// socket will see: the media socket's own address when it is bound to a
/// concrete IP (such a socket is not reachable via 127.0.0.1), otherwise the
/// loopback of the same family (a dual-stack IPv6 socket would report an
/// IPv4 sender as `::ffff:127.0.0.1`).
async fn bind_loopback(media_addr: SocketAddr) -> std::io::Result<UdpSocket> {
    let ip = match media_addr.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    let socket = UdpSocket::bind(SocketAddr::new(ip, 0)).await?;
    socket
        .connect(SocketAddr::new(ip, media_addr.port()))
        .await?;
    Ok(socket)
}

/// Control leg: the browser's single bidirectional stream carries the native
/// TCP framing byte for byte.
async fn pump_control(connection: Connection, bridge_end: DuplexStream) {
    let (mut quic_send, mut quic_recv) = match connection.accept_bi().await {
        Ok(stream) => stream,
        Err(e) => {
            debug!("no control stream: {e}");
            return;
        }
    };
    let (mut bridge_read, mut bridge_write) = tokio::io::split(bridge_end);
    tokio::select! {
        r = tokio::io::copy(&mut quic_recv, &mut bridge_write) => debug!("browser → server control ended: {r:?}"),
        r = tokio::io::copy(&mut bridge_read, &mut quic_send) => debug!("server → browser control ended: {r:?}"),
    }
}

/// Browser → server media: datagrams are raw UDP media packets.
async fn pump_datagrams_in(connection: Connection, loopback: Arc<UdpSocket>) {
    loop {
        let datagram = match connection.receive_datagram().await {
            Ok(datagram) => datagram,
            Err(e) => {
                debug!("datagram receive ended: {e}");
                return;
            }
        };
        // Same bounds as the UDP path: at least a media header, at most one packet.
        if !(VOICE_HEADER_SIZE..=MAX_PACKET_SIZE).contains(&datagram.len()) {
            continue;
        }
        // A full loopback send buffer drops the packet, as UDP would.
        let _ = loopback.try_send(&datagram);
    }
}

/// Server → browser media, read from the loopback socket. Everything but
/// video goes out as a datagram right here (`send_datagram` never blocks);
/// video fragments are queued for the stream writer, dropped when the queue
/// is full so this loop never stalls on the QUIC side.
async fn pump_media_out(
    connection: Connection,
    loopback: Arc<UdpSocket>,
    video_tx: mpsc::Sender<Bytes>,
) {
    let mut buf = vec![0u8; MAX_PACKET_SIZE];
    let mut warned_oversize = false;
    loop {
        let len = match loopback.recv(&mut buf).await {
            Ok(len) => len,
            Err(e) => {
                warn!("media loopback receive failed: {e}");
                return;
            }
        };
        if len == 0 {
            continue;
        }
        let packet = &buf[..len];
        match packet[0] {
            0x13 | 0x14 => {
                if let Err(mpsc::error::TrySendError::Closed(_)) =
                    video_tx.try_send(Bytes::copy_from_slice(packet))
                {
                    return;
                }
            }
            _ => {
                let max = connection.max_datagram_size().unwrap_or(1200);
                if len > max {
                    if !warned_oversize {
                        warn!(len, max, "dropping media packet larger than the datagram limit");
                        warned_oversize = true;
                    }
                    continue;
                }
                match connection.send_datagram(packet) {
                    Ok(()) | Err(SendDatagramError::TooLarge) => {}
                    Err(SendDatagramError::UnsupportedByPeer) => {
                        warn!("browser does not support datagrams, media disabled");
                        return;
                    }
                    Err(SendDatagramError::NotConnected) => return,
                }
            }
        }
    }
}

/// Video fragments → one unidirectional stream per frame, each fragment
/// prefixed with its u16-BE length (fragments exceed the datagram MTU).
async fn pump_video_streams(connection: Connection, mut video_rx: mpsc::Receiver<Bytes>) {
    let mut grouper = FrameGrouper::default();
    let mut stream: Option<SendStream> = None;
    while let Some(packet) = video_rx.recv().await {
        let Some(place) = grouper.place(&packet) else {
            continue;
        };
        if place.new_frame {
            finish(stream.take()).await;
            stream = match connection.open_uni().await {
                Ok(opening) => match opening.await {
                    Ok(stream) => Some(stream),
                    Err(e) => {
                        debug!("video stream refused: {e}");
                        None
                    }
                },
                Err(e) => {
                    debug!("video stream open ended: {e}");
                    return;
                }
            };
        }
        // No stream: the frame's opening failed or an earlier write did;
        // drop the rest of this frame, the browser requests a keyframe.
        let Some(current) = stream.as_mut() else {
            continue;
        };
        let len = (packet.len() as u16).to_be_bytes();
        if current.write_all(&len).await.is_err() || current.write_all(&packet).await.is_err() {
            stream = None;
            continue;
        }
        if place.last {
            finish(stream.take()).await;
        }
    }
}

/// Send FIN on a frame stream. `shutdown` is quinn's synchronous `finish`;
/// wtransport's `SendStream::finish` would wait for the peer's ack, one RTT
/// per frame.
async fn finish(stream: Option<SendStream>) {
    if let Some(mut stream) = stream {
        let _ = stream.shutdown().await;
    }
}

/// Where a video fragment goes: a new per-frame stream or the current one,
/// and whether that stream is complete after it.
#[derive(Debug, PartialEq, Eq)]
struct Placement {
    new_frame: bool,
    last: bool,
}

/// Groups relayed video fragments into per-frame streams by `frame_id`,
/// reading only `frame_id` (bytes 13..17) and `fragment_count` (byte 18) of
/// the header (`voipc_protocol::video`). A frame's stream is complete once
/// `fragment_count` fragments were placed, or as soon as a different
/// `frame_id` shows up.
#[derive(Default)]
struct FrameGrouper {
    /// (frame_id, fragments placed) of the open stream.
    current: Option<(u32, u8)>,
}

impl FrameGrouper {
    /// `None` for packets too short to carry a video header (dropped).
    fn place(&mut self, packet: &[u8]) -> Option<Placement> {
        if packet.len() < VIDEO_HEADER_SIZE {
            return None;
        }
        let frame_id = u32::from_be_bytes([packet[13], packet[14], packet[15], packet[16]]);
        let count = packet[18];
        let (new_frame, placed) = match self.current {
            Some((id, placed)) if id == frame_id => (false, placed.saturating_add(1)),
            _ => (true, 1),
        };
        let last = count != 0 && placed >= count;
        self.current = if last { None } else { Some((frame_id, placed)) };
        Some(Placement { new_frame, last })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fragment(frame_id: u32, index: u8, count: u8) -> Vec<u8> {
        let mut packet = vec![0x13u8; 13]; // type + session_id + udp_token
        packet.extend_from_slice(&frame_id.to_be_bytes());
        packet.push(index);
        packet.push(count);
        packet.extend_from_slice(&[0u8; 4]); // timestamp
        packet.push(index); // payload marker
        packet
    }

    /// Applies placements the way the stream writer does and returns the
    /// records of every stream that was opened.
    fn group(packets: &[Vec<u8>]) -> Vec<Vec<Vec<u8>>> {
        let mut grouper = FrameGrouper::default();
        let mut streams: Vec<Vec<Vec<u8>>> = Vec::new();
        for packet in packets {
            let place = grouper.place(packet).unwrap();
            if place.new_frame {
                streams.push(Vec::new());
            }
            streams.last_mut().unwrap().push(packet.clone());
        }
        streams
    }

    #[test]
    fn finishes_on_fragment_count() {
        let mut grouper = FrameGrouper::default();
        assert_eq!(
            grouper.place(&fragment(1, 0, 2)),
            Some(Placement { new_frame: true, last: false })
        );
        assert_eq!(
            grouper.place(&fragment(1, 1, 2)),
            Some(Placement { new_frame: false, last: true })
        );
        // The frame is closed: a late duplicate opens a new stream
        assert_eq!(
            grouper.place(&fragment(1, 1, 2)),
            Some(Placement { new_frame: true, last: false })
        );
    }

    #[test]
    fn interleaved_frames_become_two_streams() {
        // Frame 7 is cut short by frame 8 arriving, frame 8 completes by count
        let streams = group(&[
            fragment(7, 0, 3),
            fragment(7, 1, 3),
            fragment(8, 0, 2),
            fragment(8, 1, 2),
        ]);
        assert_eq!(
            streams,
            vec![
                vec![fragment(7, 0, 3), fragment(7, 1, 3)],
                vec![fragment(8, 0, 2), fragment(8, 1, 2)],
            ]
        );
        // Frame 7's straggler starts a stream of its own
        let mut grouper = FrameGrouper::default();
        for packet in [fragment(7, 0, 3), fragment(8, 0, 1)] {
            grouper.place(&packet);
        }
        assert_eq!(
            grouper.place(&fragment(7, 2, 3)),
            Some(Placement { new_frame: true, last: false })
        );
    }

    #[test]
    fn short_packets_are_dropped() {
        assert_eq!(FrameGrouper::default().place(&[0x13; VIDEO_HEADER_SIZE - 1]), None);
    }
}
