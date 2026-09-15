//! Client transport: the QUIC (WebTransport) endpoint every client connects
//! to, and the HTTP/2-only static page browsers load first (the embedded
//! `client/dist-web` bundle plus `/wt.json`).
//!
//! One session maps onto the native paths: control bytes go through an
//! in-process duplex into `tcp::handle_connection`, media packets go
//! straight to `media::handle_packet` and come back through the session's
//! `media_tx` queue. The bridge never parses control messages and reads only
//! the frame header of video fragments; all crypto happens in the client.
//!
//! Certificates: browsers pin the endpoint certificate by hash
//! (`serverCertificateHashes`, which requires a short-lived ECDSA cert), so
//! they get a self-signed one the server rotates itself. Native clients pin
//! the operator's certificate (`cert_path`/`key_path`, trust-on-first-use)
//! and ask for it by sending [`NATIVE_SNI`] as the TLS server name.

use std::borrow::Cow;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::header::{self, HeaderValue};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use http_body_util::BodyExt as _;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rust_embed::Embed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio::io::{AsyncWriteExt, DuplexStream};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use voipc_protocol::types::UserId;
use tokio::task::JoinSet;
use tokio_rustls::server::TlsStream;
use tracing::{debug, info, warn};
use wtransport::config::Ipv6DualStackConfig;
use wtransport::endpoint::endpoint_side::Server;
use wtransport::error::SendDatagramError;
use wtransport::tls::Sha256Digest;
use wtransport::{Connection, Endpoint, Identity, SendStream, ServerConfig as WtServerConfig, VarInt};

use voipc_protocol::types::SessionId;
use voipc_protocol::video::{FrameGrouper, RecordReader};

use crate::config::ServerConfig;
use crate::media;
use crate::state::ServerState;
use crate::{tcp, ConnLimits};

/// TLS server name native clients send to receive the operator certificate
/// instead of the browser-pinned one.
pub const NATIVE_SNI: &str = "voipc-native";

/// Largest per-frame video stream accepted from a sharer (a 1080p keyframe
/// is well under 1 MiB).
const MAX_FRAME_STREAM_BYTES: u64 = 8 * 1024 * 1024;

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
    /// SHA-256 of the current browser certificate; replaced on rotation.
    cert_hash: RwLock<Sha256Digest>,
}

// ── HTTP/2 static page ──────────────────────────────────────────────────

/// Serve the web client over HTTP/2 on a TLS stream that negotiated `h2`.
pub async fn serve_h2(
    tls: TlsStream<TcpStream>,
    wt: Arc<WtInfo>,
    state: Arc<ServerState>,
    peer: SocketAddr,
) {
    let service = service_fn(move |req: Request<Incoming>| {
        let wt = wt.clone();
        let state = state.clone();
        async move { Ok::<_, Infallible>(handle_request(req, &wt, &state).await) }
    });
    if let Err(e) = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
        .serve_connection(TokioIo::new(tls), service)
        .await
    {
        debug!(%peer, "h2 connection ended: {e}");
    }
}

async fn handle_request(
    req: Request<Incoming>,
    wt: &WtInfo,
    state: &ServerState,
) -> Response<Full<Bytes>> {
    let head_only = req.method() == Method::HEAD;
    let mut resp = if req.method() == Method::GET || head_only {
        route(req.uri().path(), wt)
    } else if req.method() == Method::POST && req.uri().path() == GAME_ROUTES_PATH {
        game_routes(req, state).await
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

// ── The game server's routing API ───────────────────────────────────────
//
// A game server telling the relay who may hear whom, for a channel whose
// `routed` flag is on. Everything about the shape of this is chosen so the
// relay learns as little as it can while still being able to enforce:
//
// - **Buses are opaque.** The game server hashes and salts its own names
//   (per run — that is what `boot` is for) before sending them. We hash them
//   again to a `u64`, resolve them to "who hears whom" here, and forget them.
//   There is no map from a bus id to anything, and an id means nothing between
//   one run and the next.
// - **No coordinates.** `deny_unknown_fields` means a well-meaning mod cannot
//   even send one by accident — the POST is refused rather than silently
//   carrying a position into a log.
// - **No reading back.** There is deliberately no `GET /sessions`: it would
//   walk straight past the pseudonyms an anonymous channel hands out and the
//   member list `hide_members` hides. A game token is not an admin token.

const GAME_ROUTES_PATH: &str = "/game/v1/routes";
/// Largest routing POST accepted. A full server's worth of ids and buses is a
/// few tens of kilobytes; this is generous and still bounded.
const MAX_ROUTES_BODY: usize = 512 * 1024;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RoutesBody {
    /// The channel by name, as the mod names it in `hello`.
    channel: String,
    /// Rises with every POST of one run, so a late one cannot overwrite a
    /// newer one.
    epoch: u64,
    /// This run of the game server. A new one resets `epoch`, so a server
    /// whose epoch is a tick counter can restart without being refused
    /// for ever — and then the channel would quietly fall back to full
    /// fan-out with nothing to notice.
    #[serde(default)]
    boot: String,
    /// How long this answer is good for, capped at `routing::MAX_TTL`.
    #[serde(default = "default_ttl_ms")]
    ttl_ms: u64,
    players: Vec<RoutesPlayer>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RoutesPlayer {
    /// VoIPC user id.
    user: UserId,
    /// Buses this player talks on.
    #[serde(default, rename = "pub")]
    publishes: Vec<String>,
    /// Buses this player listens to.
    #[serde(default, rename = "sub")]
    subscribes: Vec<String>,
}

fn default_ttl_ms() -> u64 {
    3_000
}

async fn game_routes(req: Request<Incoming>, state: &ServerState) -> Response<Full<Bytes>> {
    let Some(expected) = state.settings.game_token.as_deref() else {
        return plain(StatusCode::NOT_FOUND, "not found");
    };
    let presented = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    // Constant time, exactly as the admin token is compared: a timing oracle
    // on this one would hand somebody the ability to silence a channel.
    let ok: bool = {
        use subtle::ConstantTimeEq;
        presented.as_bytes().ct_eq(expected.as_bytes()).into()
    };
    if !ok {
        return plain(StatusCode::UNAUTHORIZED, "bad token");
    }

    let body = match http_body_util::Limited::new(req.into_body(), MAX_ROUTES_BODY)
        .collect()
        .await
    {
        Ok(b) => b.to_bytes(),
        Err(_) => return plain(StatusCode::PAYLOAD_TOO_LARGE, "body too large"),
    };
    let parsed: RoutesBody = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => {
            return owned(StatusCode::BAD_REQUEST, Bytes::from(format!("bad body: {e}")))
        }
    };
    if let Err(reason) = routes_within_bounds(parsed.players.len(), state.max_users) {
        return plain(StatusCode::BAD_REQUEST, reason);
    }

    let channel_id = {
        let channels = state.channels.read().await;
        match channels
            .iter()
            .find(|(_, ch)| ch.info.name == parsed.channel && ch.info.routed)
        {
            Some((id, _)) => *id,
            None => {
                return plain(
                    StatusCode::NOT_FOUND,
                    "no routed channel by that name — is `routed` on in channels.json?",
                )
            }
        }
    };

    let forwarded = parsed.players.len();
    let routes = resolve(parsed);
    match state
        .routing
        .set_routes(channel_id, routes, tokio::time::Instant::now())
    {
        Ok(()) => {
            state.routing.log_accepted(channel_id);
            owned(StatusCode::OK, Bytes::from(format!("{forwarded} players")))
        }
        // Logged rather than silent: a game server stuck behind its own epoch
        // would otherwise stop enforcing with nothing to see. Once per run of
        // refusals, though — this arrives a few times a second from a remote
        // party, and a line per POST is a log somebody else can grow.
        Err(crate::routing::RoutesError::Stale) => {
            if state.routing.log_refused(channel_id) {
                warn!(
                    channel_id,
                    "game routes refused: epoch is not newer than the one held \
                     (further refusals for this channel are not logged)"
                );
            }
            plain(StatusCode::CONFLICT, "epoch is not newer than the one held")
        }
    }
}

/// Does this body name a plausible number of players?
///
/// [`resolve`] intersects every listener with every speaker, so its cost — and
/// the size of the table it leaves behind — is the square of this number. The
/// body limit alone allows about fifteen thousand of them, which is a quarter of
/// a second of a runtime worker and a gigabyte of sets, per POST, from a party
/// holding nothing but the game token. Nobody can hear more people than the
/// server can hold, so the roster is the bound.
fn routes_within_bounds(players: usize, max_users: u32) -> Result<(), &'static str> {
    if players > max_users.max(1) as usize {
        return Err("more players than this server can hold");
    }
    Ok(())
}

/// Turn buses into "who may hear whom", and forget the buses.
///
/// The intersection is the whole model: geometry, radio channels, phone calls
/// and job gating all collapse to "do these two share a bus", which is why the
/// relay can enforce them without being told what any of them are.
fn resolve(body: RoutesBody) -> crate::routing::Routes {
    use std::collections::{HashMap, HashSet};
    let bus = |name: &str| -> u64 {
        let digest = <sha2::Sha256 as sha2::Digest>::digest(name.as_bytes());
        u64::from_be_bytes(digest[..8].try_into().expect("sha256 is 32 bytes"))
    };
    let speakers: Vec<(UserId, HashSet<u64>)> = body
        .players
        .iter()
        .map(|p| (p.user, p.publishes.iter().map(|b| bus(b)).collect()))
        .collect();
    let mut hear: HashMap<UserId, HashSet<UserId>> = HashMap::with_capacity(body.players.len());
    for listener in &body.players {
        let subs: HashSet<u64> = listener.subscribes.iter().map(|b| bus(b)).collect();
        let audible = speakers
            .iter()
            .filter(|(uid, pubs)| *uid != listener.user && !subs.is_disjoint(pubs))
            .map(|(uid, _)| *uid)
            .collect();
        hear.insert(listener.user, audible);
    }
    crate::routing::Routes {
        epoch: body.epoch,
        boot: body.boot,
        ttl: std::time::Duration::from_millis(body.ttl_ms),
        hear,
    }
}

fn route(path: &str, wt: &WtInfo) -> Response<Full<Bytes>> {
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
    owned(status, Bytes::from_static(text.as_bytes()))
}

/// The same, for a message built at runtime (a parse error, a count).
fn owned(status: StatusCode, body: Bytes) -> Response<Full<Bytes>> {
    let mut resp = Response::new(Full::new(body));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    resp
}

// ── Certificate selection ───────────────────────────────────────────────

/// Serves the operator certificate to native clients (by SNI) and the
/// rotating self-signed one to everyone else.
struct CertPicker {
    native: Arc<CertifiedKey>,
    browser: RwLock<Arc<CertifiedKey>>,
}

impl std::fmt::Debug for CertPicker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CertPicker")
    }
}

impl ResolvesServerCert for CertPicker {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if hello.server_name() == Some(NATIVE_SNI) {
            Some(self.native.clone())
        } else {
            Some(
                self.browser
                    .read()
                    .unwrap_or_else(PoisonError::into_inner)
                    .clone(),
            )
        }
    }
}

/// A fresh ECDSA P-256 certificate valid 14 days — what browsers require
/// for hash-pinned certificates — as a rustls key plus the hash `/wt.json`
/// publishes.
fn browser_key(sans: &[String]) -> Result<(Arc<CertifiedKey>, Sha256Digest)> {
    let identity =
        Identity::self_signed(sans).context("failed to generate browser certificate")?;
    let cert = identity
        .certificate_chain()
        .as_slice()
        .first()
        .expect("self-signed identity carries one certificate");
    let hash = cert.hash();
    let certs = vec![CertificateDer::from(cert.der().to_vec())];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        identity.private_key().secret_der().to_vec(),
    ));
    Ok((certified_key(certs, key)?, hash))
}

fn certified_key(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<CertifiedKey>> {
    let signing = rustls::crypto::ring::sign::any_supported_type(&key)
        .context("unsupported private key type")?;
    Ok(Arc::new(CertifiedKey::new(certs, signing)))
}

// ── QUIC endpoint ───────────────────────────────────────────────────────

/// The QUIC endpoint all clients connect to.
pub struct WebTransport {
    endpoint: Endpoint<Server>,
    picker: Arc<CertPicker>,
    sans: Vec<String>,
    info: Arc<WtInfo>,
}

impl WebTransport {
    /// Bind on `host:udp_port`. `certs`/`key` is the operator identity
    /// served to native clients; the browser certificate is generated here.
    pub fn bind(
        config: &ServerConfig,
        certs: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Result<Self> {
        let bind_addr = config.bind_addr(config.udp_port)?;

        // Browsers pin the certificate by hash (serverCertificateHashes), the
        // SANs just keep it honest: the bind IP when it is a concrete one,
        // plus localhost.
        let mut sans = Vec::new();
        if !bind_addr.ip().is_unspecified() {
            sans.push(bind_addr.ip().to_string());
        }
        sans.push("localhost".to_string());

        let (browser, cert_hash) = browser_key(&sans)?;
        let native = certified_key(certs, key)
            .context("invalid TLS certificate/key for the QUIC endpoint")?;
        let picker = Arc::new(CertPicker {
            native,
            browser: RwLock::new(browser),
        });
        let endpoint = Endpoint::server(server_config(bind_addr, picker.clone()))
            .with_context(|| format!("failed to bind QUIC on {bind_addr}"))?;

        Ok(Self {
            endpoint,
            picker,
            sans,
            info: Arc::new(WtInfo {
                port: config.udp_port,
                cert_hash: RwLock::new(cert_hash),
            }),
        })
    }

    pub fn info(&self) -> Arc<WtInfo> {
        self.info.clone()
    }

    #[cfg(test)]
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }

    /// Accept sessions forever. The browser certificate is replaced every
    /// 7 days (`VOIPC_WT_ROTATE_SECS` overrides the interval for testing);
    /// running sessions keep their old one.
    pub async fn run(self, state: Arc<ServerState>, limits: Arc<ConnLimits>) {
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
            // Spoofed Initials must not pin connection slots (a slot is held for
            // the whole 10 s handshake timeout): make an unvalidated source prove
            // it can receive at that address first. Costs one round trip per
            // connect — quinn only skips it with NEW_TOKENs, which need its
            // `bloom` feature, and wtransport does not enable it.
            if !incoming.remote_address_validated() {
                incoming.retry();
                continue;
            }
            if state.is_banned(peer.ip()) {
                debug!(%peer, "refusing session: banned");
                incoming.refuse();
                continue;
            }
            if let Err(reason) = limits.acquire(peer.ip()) {
                warn!(%peer, "rejecting session: {reason}");
                incoming.refuse();
                continue;
            }

            let state = state.clone();
            let limits = limits.clone();
            tokio::spawn(async move {
                // Same deadline as the TLS handshake on the page port.
                match tokio::time::timeout(Duration::from_secs(10), incoming).await {
                    Ok(Ok(request)) => {
                        if request.path() != "/voipc" {
                            warn!(%peer, path = request.path(), "rejecting session: unknown path");
                            request.not_found().await;
                        } else {
                            match request.accept().await {
                                Ok(connection) => run_session(connection, state, peer).await,
                                Err(e) => warn!(%peer, "session accept failed: {e}"),
                            }
                        }
                    }
                    Ok(Err(e)) => warn!(%peer, "QUIC handshake failed: {e}"),
                    Err(_) => warn!(%peer, "QUIC handshake timed out"),
                }
                limits.release(peer.ip());
            });
        }
    }

    fn rotate_certificate(&self) {
        let (key, cert_hash) = match browser_key(&self.sans) {
            Ok(fresh) => fresh,
            Err(e) => {
                warn!("browser certificate rotation failed: {e}");
                return;
            }
        };
        *self
            .picker
            .browser
            .write()
            .unwrap_or_else(PoisonError::into_inner) = key;
        *self
            .info
            .cert_hash
            .write()
            .unwrap_or_else(PoisonError::into_inner) = cert_hash;
        info!("rotated browser certificate");
    }
}

fn server_config(bind_addr: SocketAddr, picker: Arc<CertPicker>) -> WtServerConfig {
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("ring supports TLS 1.3")
    .with_no_client_auth()
    .with_cert_resolver(picker);
    tls.alpn_protocols = vec![b"h3".to_vec()];

    let builder = match bind_addr {
        SocketAddr::V4(_) => WtServerConfig::builder().with_bind_address(bind_addr),
        SocketAddr::V6(addr) => {
            WtServerConfig::builder().with_bind_address_v6(addr, Ipv6DualStackConfig::Allow)
        }
    };
    builder
        .with_custom_tls(tls)
        // An idle client must not hit its own idle timeout; a vanished peer
        // still trips ours (30 s default) because it never acks.
        .keep_alive_interval(Some(Duration::from_secs(10)))
        .build()
}

// ── Per-session bridge ──────────────────────────────────────────────────

/// Bridge one QUIC session onto the control handler and the media relay
/// until either side goes away.
async fn run_session(connection: Connection, state: Arc<ServerState>, peer: SocketAddr) {
    let label = format!("quic:{}", peer.ip());
    info!(peer = %label, "session established");

    let (handler_end, bridge_end) = tokio::io::duplex(65536);
    let (media_tx, media_rx) = mpsc::channel::<Bytes>(512);
    let (sid_tx, sid_rx) = oneshot::channel::<SessionId>();
    // The control handler starts now, so its 5 s authentication deadline
    // covers the client opening the control stream as well.
    let mut handler = tokio::spawn(tcp::handle_connection(
        handler_end,
        label.clone(),
        peer.ip(),
        media_tx,
        sid_tx,
        state.clone(),
    ));

    let (video_tx, video_rx) = mpsc::channel::<Bytes>(512);
    // The control leg is kept apart from the media pumps: it is the one that
    // still has something to deliver when a session ends, and waiting for
    // "any pump" would not wait for it. On a kick the media relay ends first
    // (cleanup drops the session's sender before the handler returns), so
    // that wait used to return at once and abort the control leg mid-flush —
    // the client then saw a dead connection instead of the kick reason.
    let mut control = tokio::spawn(pump_control(connection.clone(), bridge_end));
    let mut pumps = JoinSet::new();
    pumps.spawn(pump_media_out(connection.clone(), media_rx, video_tx));
    pumps.spawn(pump_video_streams(connection.clone(), video_rx));
    pumps.spawn(pump_media_in(connection.clone(), sid_rx, state));

    // Let the control leg deliver what the handler queued last (a kick or ban
    // reason): it drains the duplex, FINs the stream and waits for the ack
    // before ending (see pump_control).
    let drain = Duration::from_secs(2);
    tokio::select! {
        _ = &mut control => debug!(peer = %label, "control leg ended"),
        _ = pumps.join_next() => {
            debug!(peer = %label, "media leg ended");
            let _ = tokio::time::timeout(drain, &mut control).await;
        }
        _ = &mut handler => {
            debug!(peer = %label, "control handler ended");
            let _ = tokio::time::timeout(drain, &mut control).await;
        }
        e = connection.closed() => debug!(peer = %label, "session closed: {e}"),
    }

    // Aborting the pumps drops the bridge end of the duplex: the control
    // handler sees EOF and runs its normal session cleanup.
    control.abort();
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
    info!(peer = %label, "session ended");
}

/// Control leg: the client's single bidirectional stream carries the native
/// control framing byte for byte.
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
        r = tokio::io::copy(&mut quic_recv, &mut bridge_write) => debug!("client → server control ended: {r:?}"),
        r = tokio::io::copy(&mut bridge_read, &mut quic_send) => {
            debug!("server → client control ended: {r:?}");
            // The handler hung up: FIN the stream and wait for the client's
            // ack, so its last message (a Disconnected reason) is not
            // discarded when the connection is closed right after.
            let _ = tokio::time::timeout(Duration::from_secs(2), quic_send.finish()).await;
        }
    }
}

/// Client → server media. Waits for authentication (the relay routes by
/// session id), then reads datagrams (voice, screen audio, pings) and
/// per-frame unidirectional streams (video) until the session ends.
async fn pump_media_in(
    connection: Connection,
    sid_rx: oneshot::Receiver<SessionId>,
    state: Arc<ServerState>,
) {
    let Ok(session_id) = sid_rx.await else {
        return; // authentication failed; the handler is ending the session
    };
    tokio::select! {
        _ = pump_datagrams_in(&connection, session_id, &state) => {}
        _ = pump_video_in(&connection, session_id, &state) => {}
    }
}

async fn pump_datagrams_in(connection: &Connection, session_id: SessionId, state: &ServerState) {
    loop {
        let datagram = match connection.receive_datagram().await {
            Ok(datagram) => datagram,
            Err(e) => {
                debug!("datagram receive ended: {e}");
                return;
            }
        };
        media::handle_packet(session_id, datagram.payload(), state).await;
    }
}

/// A sharer's video: one unidirectional stream per frame, each fragment
/// prefixed with its u16-BE length. Frames are read one after another so
/// fragments reach viewers in order, and each fragment is relayed as soon as it
/// arrives — waiting for the frame's FIN would add its whole transmission time
/// to the viewers' latency.
async fn pump_video_in(connection: &Connection, session_id: SessionId, state: &ServerState) {
    let mut chunk = vec![0u8; 16 * 1024];
    loop {
        let mut stream = match connection.accept_uni().await {
            Ok(stream) => stream,
            Err(e) => {
                debug!("video stream accept ended: {e}");
                return;
            }
        };
        let mut reader = RecordReader::default();
        let mut total: u64 = 0;
        loop {
            // Err = reset by the sharer: the frame is lost, viewers request a
            // keyframe. Dropping the stream stops the peer for the size cap.
            let read = match stream.read(&mut chunk).await {
                Ok(Some(n)) => n,
                Ok(None) | Err(_) => break,
            };
            total += read as u64;
            if total > MAX_FRAME_STREAM_BYTES {
                break;
            }
            for packet in reader.push(&chunk[..read]) {
                media::handle_packet(session_id, Bytes::from(packet), state).await;
            }
            if reader.is_broken() {
                break;
            }
        }
    }
}

/// Server → client media, read from the session's relay queue. Everything
/// but video goes out as a datagram right here (`send_datagram` never
/// blocks); video fragments are queued for the stream writer, dropped when
/// the queue is full so this loop never stalls on the QUIC side.
async fn pump_media_out(
    connection: Connection,
    mut media_rx: mpsc::Receiver<Bytes>,
    video_tx: mpsc::Sender<Bytes>,
) {
    let mut warned_oversize = false;
    while let Some(packet) = media_rx.recv().await {
        if packet.is_empty() {
            continue;
        }
        match packet[0] {
            0x13 | 0x14 => {
                if let Err(mpsc::error::TrySendError::Closed(_)) = video_tx.try_send(packet) {
                    return;
                }
            }
            _ => {
                let max = connection.max_datagram_size().unwrap_or(1200);
                if packet.len() > max {
                    if !warned_oversize {
                        warn!(len = packet.len(), max, "dropping media packet larger than the datagram limit");
                        warned_oversize = true;
                    }
                    continue;
                }
                match connection.send_datagram(packet) {
                    Ok(()) | Err(SendDatagramError::TooLarge) => {}
                    Err(SendDatagramError::UnsupportedByPeer) => {
                        warn!("peer does not support datagrams, media disabled");
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
        // drop the rest of this frame, the viewer requests a keyframe.
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

#[cfg(test)]
mod tests {
    use super::*;

    use std::pin::Pin;
    use std::sync::Mutex;

    use bytes::BytesMut;
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use tokio::io::AsyncReadExt;
    use rustls::pki_types::{ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, SignatureScheme};
    use sha2::{Digest, Sha256};
    use wtransport::config::{DnsLookupFuture, DnsResolver};
    use wtransport::endpoint::endpoint_side::Client;
    use wtransport::ClientConfig;

    use voipc_protocol::codec::{
        decode_server_msg, encode_client_msg, try_decode_frame, APP_VERSION, PROTOCOL_VERSION,
    };
    use voipc_protocol::messages::{ClientMessage, ServerMessage};
    use voipc_protocol::video::VideoPacket;
    use voipc_protocol::voice::{VoicePacket, VoicePacketType};

    use crate::settings::ServerSettings;

    /// Resolves every host name to the one test endpoint address — the same
    /// trick the native client uses to send `NATIVE_SNI` while dialing an IP.
    #[derive(Debug)]
    struct Fixed(SocketAddr);

    impl DnsResolver for Fixed {
        fn resolve(&self, _host: &str) -> Pin<Box<dyn DnsLookupFuture>> {
            let addr = self.0;
            Box::pin(async move { Ok(Some(addr)) })
        }
    }

    /// Accepts any certificate and records the SHA-256 of the leaf.
    #[derive(Debug)]
    struct Capture(Arc<Mutex<Option<[u8; 32]>>>);

    impl ServerCertVerifier for Capture {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: &ServerName<'_>,
            _: &[u8],
            _: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            *self.0.lock().unwrap() = Some(Sha256::digest(end_entity.as_ref()).into());
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

    /// An endpoint on 127.0.0.1 with a throwaway operator identity; returns
    /// the SHA-256 of that operator certificate too.
    fn test_server() -> (WebTransport, Arc<ServerState>, [u8; 32]) {
        let operator = Identity::self_signed(["localhost"]).unwrap();
        let der = operator.certificate_chain().as_slice()[0].der().to_vec();
        let native_hash: [u8; 32] = Sha256::digest(&der).into();
        let certs = vec![CertificateDer::from(der)];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            operator.private_key().secret_der().to_vec(),
        ));
        let config = ServerConfig {
            host: "127.0.0.1".into(),
            udp_port: 0,
            ..ServerConfig::default()
        };
        let web = WebTransport::bind(&config, certs, key).unwrap();
        let state = Arc::new(ServerState::new(
            &config,
            ServerSettings::default(),
            Vec::new(),
            "test-admin-token".into(),
        ));
        (web, state, native_hash)
    }

    /// Connects with `sni` as the TLS server name. The endpoint must outlive
    /// the connection, so it is returned as well.
    async fn connect(
        addr: SocketAddr,
        sni: &str,
        seen: Arc<Mutex<Option<[u8; 32]>>>,
    ) -> (Endpoint<Client>, Connection) {
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Capture(seen)))
        .with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let config = ClientConfig::builder()
            .with_bind_address("127.0.0.1:0".parse().unwrap())
            .with_custom_tls(tls)
            .dns_resolver(Fixed(addr))
            .build();
        let endpoint = Endpoint::client(config).unwrap();
        let connection = tokio::time::timeout(
            Duration::from_secs(5),
            endpoint.connect(format!("https://{sni}:{}/voipc", addr.port())),
        )
        .await
        .expect("handshake within 5 s")
        .unwrap();
        (endpoint, connection)
    }

    #[test]
    fn a_routing_post_is_bounded_by_the_roster() {
        // `resolve` intersects every listener with every speaker, so a body the
        // 512 KiB limit allows — about fifteen thousand players — is a quarter
        // of a second of a runtime worker and a gigabyte of sets, per POST.
        assert!(routes_within_bounds(64, 64).is_ok());
        assert!(routes_within_bounds(0, 64).is_ok());
        assert!(routes_within_bounds(65, 64).is_err(), "an oversized table was accepted");
        // A server with no configured limit still bounds the endpoint
        assert!(routes_within_bounds(2, 0).is_err());
    }

    #[test]
    fn buses_resolve_to_who_hears_whom_and_nothing_else() {
        // Two players share a bus, a third shares none: the whole enforcement
        // model, and the reason the relay never learns what a bus is.
        let body: RoutesBody = serde_json::from_str(
            r#"{"channel":"Ingame","epoch":1,"boot":"a","players":[
                 {"user":1,"pub":["w:7f"],"sub":["w:7f","r:police"]},
                 {"user":2,"pub":["r:police"],"sub":["w:7f"]},
                 {"user":3,"pub":["w:aa"],"sub":["w:aa"]}]}"#,
        )
        .unwrap();
        let routes = resolve(body);
        assert_eq!(routes.hear[&1], [2].into_iter().collect());
        assert_eq!(routes.hear[&2], [1].into_iter().collect());
        assert!(routes.hear[&3].is_empty(), "a player heard somebody off their buses");
        // Nobody hears themselves through this table; that is the mixer's job
        assert!(!routes.hear[&1].contains(&1));

        // A field this endpoint does not know is refused rather than ignored:
        // that is what keeps a coordinate from arriving by accident.
        assert!(serde_json::from_str::<RoutesBody>(
            r#"{"channel":"I","epoch":1,"players":[{"user":1,"pos":[1,2,3]}]}"#
        )
        .is_err());
    }

    #[tokio::test]
    async fn sni_selects_the_certificate() {
        let (web, state, native_hash) = test_server();
        let addr = web.local_addr().unwrap();
        let browser_hash: [u8; 32] = *web.info().cert_hash.read().unwrap().as_ref();
        tokio::spawn(web.run(state, Arc::new(ConnLimits::new())));

        let seen = Arc::new(Mutex::new(None));
        let (_endpoint, connection) = connect(addr, NATIVE_SNI, seen.clone()).await;
        assert_eq!(seen.lock().unwrap().unwrap(), native_hash);
        connection.close(VarInt::from_u32(0), b"");

        let seen = Arc::new(Mutex::new(None));
        let (_endpoint, connection) = connect(addr, "localhost", seen.clone()).await;
        assert_eq!(seen.lock().unwrap().unwrap(), browser_hash);
        assert_ne!(browser_hash, native_hash);
        connection.close(VarInt::from_u32(0), b"");
    }

    #[tokio::test]
    async fn native_session_authenticates_and_relays_media() {
        let (web, state, _) = test_server();
        let addr = web.local_addr().unwrap();
        tokio::spawn(web.run(state.clone(), Arc::new(ConnLimits::new())));
        let (_endpoint, connection) = connect(addr, NATIVE_SNI, Arc::default()).await;

        // Control: Authenticate → Authenticated
        let (mut send, mut recv) = connection.open_bi().await.unwrap().await.unwrap();
        let auth = ClientMessage::Authenticate {
            username: "native".into(),
            protocol_version: PROTOCOL_VERSION,
            app_version: APP_VERSION.to_string(),
            identity_key: None,
            prekey_bundle: None,
        };
        send.write_all(&encode_client_msg(&auth).unwrap()).await.unwrap();
        let mut buf = BytesMut::new();
        let session_id = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(payload) = try_decode_frame(&mut buf).unwrap() {
                    match decode_server_msg(&payload).unwrap() {
                        ServerMessage::Authenticated { session_id, .. } => return session_id,
                        other => panic!("unexpected reply: {other:?}"),
                    }
                }
                assert!(recv.read_buf(&mut buf).await.unwrap() > 0, "control stream closed");
            }
        })
        .await
        .expect("Authenticated within 5 s");
        assert_eq!(state.sessions.len(), 1);

        // Media: a ping datagram comes back as a pong
        connection
            .send_datagram(VoicePacket::ping(session_id, 77).to_bytes())
            .unwrap();
        let pong = tokio::time::timeout(Duration::from_secs(5), connection.receive_datagram())
            .await
            .expect("pong within 5 s")
            .unwrap();
        let pong = VoicePacket::from_bytes(&pong).unwrap();
        assert_eq!(pong.packet_type, VoicePacketType::Pong);
        assert_eq!(pong.sequence, 77);

        // A foreign session id in the header is dropped, not answered
        connection
            .send_datagram(VoicePacket::ping(session_id + 1, 78).to_bytes())
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(300), connection.receive_datagram())
                .await
                .is_err()
        );

        // Video: a two-fragment frame on its own stream is accepted (no
        // viewers, so it goes nowhere) and the session stays healthy
        let mut frame = connection.open_uni().await.unwrap().await.unwrap();
        for index in 0..2u8 {
            let packet =
                VideoPacket::encrypted_fragment(true, session_id, 1, index, 2, 0, 1, vec![7; 100])
                    .to_bytes();
            frame.write_all(&(packet.len() as u16).to_be_bytes()).await.unwrap();
            frame.write_all(&packet).await.unwrap();
        }
        frame.shutdown().await.unwrap();
        connection
            .send_datagram(VoicePacket::ping(session_id, 79).to_bytes())
            .unwrap();
        let pong = tokio::time::timeout(Duration::from_secs(5), connection.receive_datagram())
            .await
            .expect("pong after video within 5 s")
            .unwrap();
        assert_eq!(VoicePacket::from_bytes(&pong).unwrap().sequence, 79);

        // Closing the connection cleans the session up
        connection.close(VarInt::from_u32(0), b"");
        tokio::time::timeout(Duration::from_secs(5), async {
            while !state.sessions.is_empty() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("session removed within 5 s");
    }

}
