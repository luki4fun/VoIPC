//! The edge's link to its core (`pool::POOL_PATH`, on the core's UDP port). The edge dials
//! out, so it needs no rule in the core's firewall. It proves itself with its secret, bound
//! to this TLS session's exporter so a copy of the proof is worth nothing, and from the
//! core's `Welcome` on it asks for the shares its viewers watch, takes the core's
//! revocations, and reads the feeds: a stream per frame, as a viewer of the core gets them,
//! and screen audio as datagrams.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::io::{AsyncRead, AsyncReadExt as _};
use tokio::sync::{mpsc, watch};
use tracing::{error, info, warn};
use voipc_protocol::codec::APP_VERSION;
use voipc_protocol::pool::{
    decode_core_msg, encode_edge_msg, refused_version, CoreMsg, EdgeMsg, MAX_POOL_FRAME, POOL_PATH,
    POOL_VERSION,
};
use voipc_protocol::types::SessionId;
use voipc_protocol::video::{RecordReader, VideoPacketType, VIDEO_HEADER_SIZE};
use wtransport::config::{DnsLookupFuture, DnsResolver, QuicTransportConfig};
use wtransport::endpoint::endpoint_side::Client;
use wtransport::error::{ConnectingError, ConnectionError};
use wtransport::{ClientConfig, Connection, Endpoint, RecvStream, SendStream, VarInt};

use super::{Edge, Fan, Stats};
use crate::pool_keys;
use crate::session::NoFrame;
use crate::web::{quic_binding, read_frame, MAX_FRAME_STREAM_BYTES, NATIVE_SNI};

/// The first wait after a link failed to come up, doubled each time to `LAST_RETRY`; a link
/// that was up and went down is tried again after the first.
const FIRST_RETRY: Duration = Duration::from_secs(1);
const LAST_RETRY: Duration = Duration::from_secs(30);
/// A core that refused this edge's pool version is asked again this much later: it takes
/// an update of one of the two.
const REFUSED_RETRY: Duration = Duration::from_secs(60);
/// The link's keep-alive and idle timeout. Both ends close at the lower of their idle
/// timeouts, so a core whose edge died seats its viewers again 6 s later.
const KEEP_ALIVE: Duration = Duration::from_secs(2);
const IDLE: Duration = Duration::from_secs(6);
/// The handshake with one of the core's addresses, the link's stream, and the answer to its
/// `Hello`.
const CONNECT_WAIT: Duration = Duration::from_secs(10);
const ANSWER_WAIT: Duration = Duration::from_secs(10);
/// What may wait for the link's writer. Full means the link is stuck (`Link::tell`).
const LINK_QUEUE: usize = 1024;
/// How often the edge tells its core what it carries.
const LOAD_EVERY: Duration = Duration::from_secs(2);
/// A frame stream must show its first record within this, and then go on without a pause
/// as long: the core writes a frame's fragments one after another.
const STREAM_WAIT: Duration = Duration::from_secs(2);
/// A share's frame streams waiting for its reader.
const FEED_STREAMS: usize = 32;
/// Frames in flight on the link, per share it may carry: as many as a viewer of the core
/// may have (`web::server_config`).
const STREAMS_PER_SHARE: u32 = 24;
/// What the core may have in flight to this edge, per share and at most: a share's
/// keyframe and the frames behind it.
const WINDOW_PER_SHARE: u32 = 2 * 1024 * 1024;
const WINDOW_MAX: u32 = 64 * 1024 * 1024;
/// Screen audio waiting to be read.
const DATAGRAM_BUFFER: usize = 1024 * 1024;

/// Where the core is, and how its certificate is checked.
pub(super) struct Core {
    pub host: String,
    pub port: u16,
    /// The SHA-256 of its certificate (`core_fingerprint`); `None`: the public CAs vouch
    /// for `host`.
    pub pin: Option<[u8; 32]>,
}

impl std::fmt::Display for Core {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

/// How one link ended.
enum Ended {
    /// It never came up: why, to try again later.
    NotLinked(String),
    /// The core refused this edge (`CoreMsg::Refused`): logged already.
    Refused,
    /// It was up and went down: why, and how many viewers that ended.
    Lost(String, u32),
}

/// Links to the core for as long as the edge runs, again after every loss. `hashes`: the
/// viewers' certificate hashes, sent in each `Hello` and on each change.
pub(super) async fn run(edge: Arc<Edge>, core: Core, mut hashes: watch::Receiver<Vec<[u8; 32]>>) {
    let mut backoff = FIRST_RETRY;
    loop {
        let wait = match link_once(&edge, &core, &mut hashes).await {
            Ended::NotLinked(why) => {
                warn!(
                    "could not link to the core at {core}: {why}; trying again in {} s",
                    backoff.as_secs()
                );
                let wait = backoff;
                backoff = (backoff * 2).min(LAST_RETRY);
                wait
            }
            Ended::Refused => {
                backoff = FIRST_RETRY;
                REFUSED_RETRY
            }
            Ended::Lost(why, viewers) => {
                info!("link to the core at {core} down ({why}); {viewers} viewers here ended");
                backoff = FIRST_RETRY;
                FIRST_RETRY
            }
        };
        tokio::time::sleep(wait).await;
    }
}

async fn link_once(
    edge: &Arc<Edge>,
    core: &Core,
    hashes: &mut watch::Receiver<Vec<[u8; 32]>>,
) -> Ended {
    let addrs: Vec<SocketAddr> =
        match tokio::net::lookup_host((core.host.as_str(), core.port)).await {
            Ok(addrs) => addrs.collect(),
            Err(e) => return Ended::NotLinked(format!("{} does not resolve: {e}", core.host)),
        };
    // Every address in turn: a name with an A and an AAAA record may have the core on one
    let mut last = format!("{} resolves to no address", core.host);
    let mut linked = None;
    for addr in addrs {
        match connect(edge, core, addr).await {
            Ok(up) => {
                linked = Some(up);
                break;
            }
            // Which of its addresses, when its name has several
            Err(why) if core.host.parse::<std::net::IpAddr>().is_ok() => last = why,
            Err(why) => last = format!("{why} ({addr})"),
        }
    }
    let Some((_endpoint, conn)) = linked else {
        return Ended::NotLinked(last);
    };
    let ended = hello_and_serve(edge, core, &conn, hashes).await;
    conn.close(VarInt::from_u32(0), b"");
    ended
}

/// The link from its connection on: the `Hello`, the core's answer, then the link's life.
async fn hello_and_serve(
    edge: &Arc<Edge>,
    core: &Core,
    conn: &Connection,
    hashes: &mut watch::Receiver<Vec<[u8; 32]>>,
) -> Ended {
    let opened = tokio::time::timeout(CONNECT_WAIT, async {
        let opening = conn.open_bi().await.ok()?;
        opening.await.ok()
    })
    .await;
    let Ok(Some((mut send, mut recv))) = opened else {
        return Ended::NotLinked("the link's stream did not open".into());
    };
    let Some(binding) = quic_binding(conn) else {
        return Ended::NotLinked(
            "TLS gave this connection no exporter to prove the secret on".into(),
        );
    };
    let hello = EdgeMsg::Hello {
        pool_version: POOL_VERSION,
        name: edge.name.clone(),
        proof: pool_keys::proof(&edge.proof_key, &binding, &edge.name),
        public_host: edge.public_host.clone(),
        public_port: edge.public_port,
        cert_hashes: hashes.borrow_and_update().clone(),
        max_viewers: edge.max_viewers,
        egress_mbit: edge.egress_mbit,
        max_shares: edge.max_shares,
        version: APP_VERSION.into(),
    };
    let Ok(bytes) = encode_edge_msg(&hello) else {
        return Ended::NotLinked("the hello does not encode".into());
    };
    let mut buf = BytesMut::new();
    let answer = tokio::time::timeout(ANSWER_WAIT, async {
        send.write_all(&bytes).await.ok()?;
        read_frame(&mut recv, &mut buf, MAX_POOL_FRAME).await.ok()
    })
    .await;
    let frame = match answer {
        Ok(Some(frame)) => frame,
        // The core closes a hello it does not take with no word: for a wrong proof, an
        // unknown name or a frame it cannot read
        Ok(None) => {
            return Ended::NotLinked(
                "the core closed the link without a word (are this edge's name and secret \
                 a pair in the core's [pool] edges?)"
                    .into(),
            )
        }
        Err(_) => return Ended::NotLinked("no answer to the hello".into()),
    };
    let (id, core_ms) = match first_answer(&frame) {
        Answer::Welcome { link, core_ms } => (link, core_ms),
        Answer::Refused {
            pool_version,
            reason,
        } => {
            let first = if pool_version > POOL_VERSION {
                "update this edge"
            } else {
                "update the core first, then this edge"
            };
            match reason {
                Some(reason) if pool_version == POOL_VERSION => {
                    error!(
                        "the core at {core} refused this edge: {reason}; asking again in a minute"
                    )
                }
                _ => error!(
                    "the core at {core} refused this edge: it speaks pool version {pool_version}, \
                     this edge {POOL_VERSION}; {first}. Its viewers stay on the core"
                ),
            }
            return Ended::Refused;
        }
        Answer::Unreadable => {
            return Ended::NotLinked("the core's answer is not one this edge reads".into())
        }
    };

    info!(
        "linked to the core at {core} as {} (pool v{POOL_VERSION}, {} viewers, {} Mbit/s)",
        edge.name, edge.max_viewers, edge.egress_mbit
    );
    let (tx, rx) = mpsc::channel(LINK_QUEUE);
    edge.link_up(id, core_ms, tx.clone(), Some(conn.clone()), Instant::now());
    let why = tokio::select! {
        why = write_link(send, rx) => why,
        why = read_core(edge, &mut recv, &mut buf, conn) => why,
        why = accept_feeds(edge, conn) => why,
        why = read_datagrams(edge, conn) => why,
        why = report(edge, &tx, hashes) => why,
    };
    let viewers = edge.link_lost(id);
    Ended::Lost(why, viewers)
}

/// A QUIC connection to the core at `addr`, at the edges' path: as a native app connects,
/// by `NATIVE_SNI`, to get the operator certificate, which `core`'s pin or the public CAs
/// vouch for.
async fn connect(
    edge: &Edge,
    core: &Core,
    addr: SocketAddr,
) -> Result<(Endpoint<Client>, Connection), String> {
    let config = ClientConfig::builder()
        .with_bind_address(bind_for(addr))
        .with_custom_tls_and_transport(tls_config(core)?, transport(edge.max_shares))
        .keep_alive_interval(Some(KEEP_ALIVE))
        .max_idle_timeout(Some(IDLE))
        .map_err(|_| "the link's idle timeout is out of range".to_string())?
        .dns_resolver(Fixed(addr))
        .build();
    let endpoint = Endpoint::client(config).map_err(|e| format!("no QUIC endpoint: {e}"))?;
    let url = format!("https://{NATIVE_SNI}:{}{POOL_PATH}", addr.port());
    match tokio::time::timeout(CONNECT_WAIT, endpoint.connect(url)).await {
        Ok(Ok(conn)) => Ok((endpoint, conn)),
        Ok(Err(ConnectingError::SessionRejected)) => {
            Err("it takes no edges (no [pool] edges there, or a relay older than 1.15)".into())
        }
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err(format!("no answer within {} s", CONNECT_WAIT.as_secs())),
    }
}

/// The link's QUIC settings. The core opens a stream per frame of every share it feeds, so
/// this edge takes as many streams as a viewer of the core does, per share; and it lets
/// the core have a share's keyframe and the frames behind it in flight for each.
fn transport(max_shares: u32) -> QuicTransportConfig {
    let mut transport = QuicTransportConfig::default();
    transport
        .max_concurrent_uni_streams((STREAMS_PER_SHARE * max_shares).into())
        .receive_window(
            WINDOW_PER_SHARE
                .saturating_mul(max_shares)
                .min(WINDOW_MAX)
                .into(),
        )
        .datagram_receive_buffer_size(Some(DATAGRAM_BUFFER));
    transport
}

/// Bind in the core's address family: a v6 wildcard socket is not there everywhere, and a
/// v4 one cannot reach a v6 address.
fn bind_for(addr: SocketAddr) -> SocketAddr {
    if addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    }
    .parse()
    .expect("literal bind address")
}

/// Resolves any name to the core's address, so the URL can carry `NATIVE_SNI` as the
/// server name while dialing the core.
#[derive(Debug)]
struct Fixed(SocketAddr);

impl DnsResolver for Fixed {
    fn resolve(&self, _host: &str) -> Pin<Box<dyn DnsLookupFuture>> {
        let addr = self.0;
        Box::pin(async move { Ok(Some(addr)) })
    }
}

fn tls_config(core: &Core) -> Result<rustls::ClientConfig, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier: Arc<dyn ServerCertVerifier> = match core.pin {
        Some(pin) => Arc::new(Pinned {
            pin,
            algorithms: provider.signature_verification_algorithms,
        }),
        None => {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let inner =
                WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
                    .build()
                    .map_err(|e| format!("TLS configuration error: {e}"))?;
            let name = ServerName::try_from(core.host.clone())
                .map_err(|e| format!("{:?} is no server name: {e}", core.host))?;
            Arc::new(VerifyAs { inner, name })
        }
    };
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| format!("TLS configuration error: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    Ok(tls)
}

/// Takes the one certificate of `core_fingerprint`, and checks the handshake was signed
/// with its key. Neither name nor dates matter: the operator named this certificate.
#[derive(Debug)]
struct Pinned {
    pin: [u8; 32],
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let seen = ring::digest::digest(&ring::digest::SHA256, end_entity.as_ref());
        if seen.as_ref() == self.pin.as_slice() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "the core's certificate is not the one of core_fingerprint (it offered {})",
                hex::encode_upper(seen.as_ref())
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// The public CAs, for the core's real name: the name on the wire is `NATIVE_SNI`, which no
/// public certificate carries (the app's `VerifyAs`, client/src-tauri/src/transport.rs).
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

/// What the core's first frame says.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Answer {
    Welcome {
        link: u64,
        core_ms: u64,
    },
    /// Refused, by a core of `pool_version`. `reason` only from a core of this pool version:
    /// of another, only the version is read (`pool::refused_version`), whatever follows it.
    Refused {
        pool_version: u32,
        reason: Option<String>,
    },
    Unreadable,
}

/// The core's first frame, read whole if it is of this pool version, else for the version
/// of its refusal alone, so a core of any later version can tell this edge it is out of
/// date.
pub(super) fn first_answer(payload: &[u8]) -> Answer {
    match decode_core_msg(payload) {
        Ok(CoreMsg::Welcome { link, core_ms }) => Answer::Welcome { link, core_ms },
        Ok(CoreMsg::Refused {
            pool_version,
            reason,
        }) => Answer::Refused {
            pool_version,
            reason: Some(reason),
        },
        Ok(_) => Answer::Unreadable,
        Err(_) => match refused_version(payload) {
            Some(pool_version) => Answer::Refused {
                pool_version,
                reason: None,
            },
            None => Answer::Unreadable,
        },
    }
}

/// The link's writer: what the edge tells the core, a frame each, in order.
async fn write_link(mut send: SendStream, mut rx: mpsc::Receiver<EdgeMsg>) -> String {
    while let Some(msg) = rx.recv().await {
        let Ok(bytes) = encode_edge_msg(&msg) else {
            continue;
        };
        if let Err(e) = send.write_all(&bytes).await {
            return format!("its stream failed: {e}");
        }
    }
    "its writer stopped".into()
}

/// What the core tells this edge, past its `Welcome`.
async fn read_core(
    edge: &Edge,
    recv: &mut RecvStream,
    buf: &mut BytesMut,
    conn: &Connection,
) -> String {
    loop {
        let frame = match read_frame(recv, buf, MAX_POOL_FRAME).await {
            Ok(frame) => frame,
            Err(NoFrame::Malformed) => return "the core sent a frame too long".into(),
            Err(_) => return closed_why(conn).await.into(),
        };
        match decode_core_msg(&frame) {
            Ok(CoreMsg::Revoke { slot, core_ms }) => edge.revoke(slot, core_ms, Instant::now()),
            Ok(CoreMsg::ShareEnded { share, core_ms }) => edge.share_ended(share, core_ms),
            Ok(CoreMsg::Welcome { .. }) => return "the core sent a second welcome".into(),
            Ok(CoreMsg::Refused { reason, .. }) => return format!("refused: {reason}"),
            Err(_) => return "the core sent a frame this edge does not read".into(),
        }
    }
}

/// Why the link's stream ended, from its connection.
async fn closed_why(conn: &Connection) -> &'static str {
    match tokio::time::timeout(Duration::from_millis(500), conn.closed()).await {
        Ok(ConnectionError::TimedOut) => "timed out",
        Ok(ConnectionError::ApplicationClosed(_) | ConnectionError::ConnectionClosed(_)) => {
            "closed by the core"
        }
        Ok(ConnectionError::LocallyClosed) => "closed here",
        Ok(_) => "QUIC error",
        Err(_) => "its stream ended",
    }
}

/// The core's frame streams, each handed to its share's reader once its first record says
/// which share it is. One at a time, so the streams of a share reach its reader in the
/// order the core opened them, which `accept_uni` keeps; a first record almost always
/// came with its stream, and none waits longer than `STREAM_WAIT`.
async fn accept_feeds(edge: &Edge, conn: &Connection) -> String {
    loop {
        let stream = match conn.accept_uni().await {
            Ok(stream) => stream,
            Err(e) => return format!("{e}"),
        };
        route_stream(edge, Box::new(stream)).await;
    }
}

/// Screen audio (0x15) from the core, to the viewers of its share.
async fn read_datagrams(edge: &Edge, conn: &Connection) -> String {
    loop {
        match conn.receive_datagram().await {
            Ok(datagram) => edge.datagram(datagram.payload()),
            Err(e) => return format!("{e}"),
        }
    }
}

/// Every `LOAD_EVERY`, what the edge carries; on each rotation of the viewers' certificate,
/// the hashes viewers are to be sent from now on.
async fn report(
    edge: &Edge,
    tx: &mpsc::Sender<EdgeMsg>,
    hashes: &mut watch::Receiver<Vec<[u8; 32]>>,
) -> String {
    let mut every = tokio::time::interval(LOAD_EVERY);
    every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    every.tick().await;
    let mut sent_before = edge.stats.egress_bytes.load(Ordering::Relaxed);
    let mut at = Instant::now();
    loop {
        let msg = tokio::select! {
            _ = every.tick() => {
                let now = Instant::now();
                let sent = edge.stats.egress_bytes.load(Ordering::Relaxed);
                let ms = now.saturating_duration_since(at).as_millis().max(1) as u64;
                // bits per ms is kbit/s
                let kbps = sent.saturating_sub(sent_before).saturating_mul(8) / ms;
                (sent_before, at) = (sent, now);
                edge.load(kbps)
            }
            changed = hashes.changed() => {
                if changed.is_err() {
                    return "the viewers' endpoint stopped".into();
                }
                EdgeMsg::CertRotated {
                    cert_hashes: hashes.borrow_and_update().clone(),
                }
            }
        };
        if tx.try_send(msg).is_err() {
            return "its queue is full".into();
        }
    }
}

/// A frame stream of the core's, read as far as its first records, for its share's reader.
pub(super) struct FeedStream {
    stream: Box<dyn AsyncRead + Send + Unpin>,
    reader: RecordReader,
    first: Vec<Bytes>,
    read: u64,
}

/// The share a stream's first record is of: a video fragment's sharer, bytes 1..5.
fn share_of(packet: &[u8]) -> Option<SessionId> {
    let video = [
        VideoPacketType::EncryptedVideoFragment as u8,
        VideoPacketType::EncryptedVideoKeyframeFragment as u8,
    ];
    (packet.len() >= VIDEO_HEADER_SIZE && video.contains(&packet[0]))
        .then(|| u32::from_be_bytes([packet[1], packet[2], packet[3], packet[4]]))
}

/// Reads `stream`'s first records (within `STREAM_WAIT`) and hands it to the reader of the
/// share they are of. A stream of a share this edge does not carry, one without a first
/// record, or one its share's reader has no room for is dropped, which tells the core to
/// stop writing it.
pub(super) async fn route_stream(edge: &Edge, mut stream: Box<dyn AsyncRead + Send + Unpin>) {
    let mut reader = RecordReader::default();
    // A record is at most 1502 bytes with its length
    let mut chunk = [0u8; 2048];
    let mut read = 0u64;
    let first = tokio::time::timeout(STREAM_WAIT, async {
        loop {
            let n = stream.read(&mut chunk).await.ok().filter(|&n| n > 0)?;
            read += n as u64;
            let records = reader.push(&chunk[..n]);
            if !records.is_empty() {
                return Some(records);
            }
            if reader.is_broken() {
                return None;
            }
        }
    })
    .await;
    let Ok(Some(first)) = first else {
        edge.limits
            .count("edge", "feed stream without a first record");
        return;
    };
    let Some(share) = share_of(&first[0]) else {
        edge.limits.count("edge", "feed stream of no share");
        return;
    };
    let Some(inbox) = edge.inbox(share) else {
        edge.limits.count("edge", "feed of a share not carried");
        return;
    };
    let first = first.into_iter().map(Bytes::from).collect();
    let feed = FeedStream {
        stream,
        reader,
        first,
        read,
    };
    if inbox.try_send(feed).is_err() {
        edge.limits.count("edge", "feed streams behind");
    }
}

/// Starts the reader of `share`'s frame streams, which fans each record out to `fan` as it
/// arrives (waiting for a frame's end would add its whole transmission time to every
/// viewer's latency). Its inbox is returned; the reader ends once that is dropped.
pub(super) fn spawn_reader(
    share: SessionId,
    fan: Arc<Fan>,
    stats: Arc<Stats>,
) -> mpsc::Sender<FeedStream> {
    let (tx, rx) = mpsc::channel(FEED_STREAMS);
    tokio::spawn(read_share(share, fan, stats, rx));
    tx
}

/// One share's frame streams, one after another, in the order the core opened them. A
/// record of anything but this share's video ends its stream: the core sends a feed
/// nothing else.
async fn read_share(
    share: SessionId,
    fan: Arc<Fan>,
    stats: Arc<Stats>,
    mut rx: mpsc::Receiver<FeedStream>,
) {
    let mut chunk = vec![0u8; 16 * 1024];
    while let Some(feed) = rx.recv().await {
        let FeedStream {
            mut stream,
            mut reader,
            first,
            mut read,
        } = feed;
        let mut sent = 0;
        let mut whole = true;
        for packet in &first {
            if share_of(packet) != Some(share) {
                whole = false;
                break;
            }
            sent += fan.send(packet, &stats);
        }
        while whole && !reader.is_broken() {
            let n = match tokio::time::timeout(STREAM_WAIT, stream.read(&mut chunk)).await {
                Ok(Ok(n)) if n > 0 => n,
                _ => break,
            };
            read += n as u64;
            if read > MAX_FRAME_STREAM_BYTES {
                break;
            }
            for record in reader.push(&chunk[..n]) {
                if share_of(&record) != Some(share) {
                    whole = false;
                    break;
                }
                sent += fan.send(&Bytes::from(record), &stats);
            }
        }
        stats.egress_bytes.fetch_add(sent, Ordering::Relaxed);
    }
}
