//! The TCP fallback: a whole client session — control, voice, screen audio
//! and video — tunnelled through one WebSocket on the page's TLS port, for
//! clients that cannot reach the QUIC endpoint because something on the way
//! drops UDP. Offered only with `tcp_fallback`, at `GET /voipc` on TLS ALPN
//! `http/1.1` (which the relay always offers, for files on `/f/`: see
//! `alpn_protocols` in main.rs); browsers and the native client speak the
//! same thing.
//!
//! It is the QUIC session on another carrier (`web::run_session`): the same
//! control handler behind an in-process duplex, the same relay, the same
//! whole-frame video admission. Every binary message is one of two kinds: a
//! first byte 0x00 tags a chunk of the control byte stream (the framing of
//! the QUIC control stream, unchanged), anything else is one media packet
//! exactly as it travels as a QUIC datagram or a video stream record — no
//! media packet type is 0x00.
//!
//! What QUIC did by itself, and a TCP stream does not, is done here:
//! - **Priority.** quinn sends datagrams ahead of stream data and the control
//!   stream ahead of video; the writer takes datagrams (voice) first, then
//!   control, then video, one message at a time.
//! - **No queue behind the priority.** Every message is flushed as it is
//!   written: when the socket is full, tokio-rustls would otherwise take up
//!   to 64 KiB more into rustls's own buffer, first in, first out.
//!   TCP_NOTSENT_LOWAT keeps the kernel's unsent queue short, so voice waits
//!   behind at most that much video.
//! - **Liveness from the peer's kernel.** Keepalive (main.rs) and
//!   TCP_USER_TIMEOUT find a dead peer in about 30 s, like QUIC's idle
//!   timeout — not page timers, which a background tab runs once a minute.
//! - **A lingering close.** The writer delivers the handler's last message (a
//!   kick reason, an `AuthError`) and closes the WebSocket, and the reader
//!   keeps reading until the client answers: a socket closed with unread data
//!   makes Linux send a reset, which discards that message on its way out.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf,
};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};

use voipc_protocol::types::SessionId;
use voipc_protocol::ws::{self, Decoder, Message};

use crate::media;
use crate::state::ServerState;
use crate::web::{self, DatagramSink, SessionStart};

/// Where the tunnel is, the WebTransport session's twin.
const PATH: &str = "/voipc";
/// Largest upgrade request read before giving up.
const MAX_HEAD: usize = 8 * 1024;
/// A connection has this long to send a request head.
pub(crate) const HEAD_TIMEOUT: Duration = Duration::from_secs(5);
/// Largest message accepted: a 64 KiB control chunk plus its tag. Clients
/// send smaller ones, and media packets are far smaller still
/// (`media::MAX_PACKET_SIZE`).
const MAX_MESSAGE: usize = 64 * 1024 + 1;
/// Control bytes per message sent, so a voice packet never waits long behind one.
const CONTROL_CHUNK: usize = 16 * 1024;
/// No message at all for this long ends the session. Only a backstop: the
/// server's control Ping every 60 s draws a reply from every client, and a
/// dead peer is found by keepalive and TCP_USER_TIMEOUT long before this.
const IDLE_TIMEOUT: Duration = Duration::from_secs(150);
/// Datagram lane, in packets: voice from every speaker, pongs, screen audio.
/// A full lane drops the new packet, as UDP would.
const DATAGRAM_LANE: usize = 64;
/// Video lane, in fragments. `VideoAdmission` admits a delta only with room
/// left for a whole keyframe (255 fragments) behind it, as in the QUIC bridge.
const VIDEO_LANE: usize = 512;
/// How long each side of a closing session waits for the other.
const DRAIN: Duration = Duration::from_secs(2);

/// Socket options the tunnel needs and the page does not: no Nagle delay on
/// small voice packets, a short unsent queue, and a dead peer found in about
/// 30 s. Best effort: a failure costs latency or detection time, nothing else.
pub fn tune(tcp: &TcpStream, peer: SocketAddr) {
    if let Err(e) = tcp.set_nodelay(true) {
        debug!(%peer, "TCP_NODELAY: {e}");
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        // Voice waits behind at most this much video in the kernel
        const NOTSENT_LOWAT: u32 = 16 * 1024;
        // A peer whose kernel stops acknowledging is gone, like QUIC's idle timeout
        const USER_TIMEOUT: Duration = Duration::from_secs(30);
        let sock = socket2::SockRef::from(tcp);
        if let Err(e) = sock.set_tcp_notsent_lowat(NOTSENT_LOWAT) {
            debug!(%peer, "TCP_NOTSENT_LOWAT: {e}");
        }
        if let Err(e) = sock.set_tcp_user_timeout(Some(USER_TIMEOUT)) {
            debug!(%peer, "TCP_USER_TIMEOUT: {e}");
        }
    }
}

/// Serve one connection that negotiated `http/1.1`: files on `/f/`
/// (`files::serve_http1`, always), the tunnel on `GET /voipc` (with
/// `tcp_fallback` on), a short refusal for anything else.
pub async fn serve<S>(mut stream: S, state: Arc<ServerState>, peer: SocketAddr)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut buf = Vec::new();
    let head = match tokio::time::timeout(HEAD_TIMEOUT, read_head(&mut stream, &mut buf)).await {
        Ok(Head::Got(head)) => head,
        Ok(Head::TooLarge) => {
            refuse(&mut stream, "431 Request Header Fields Too Large").await;
            debug!(%peer, "request head too large");
            return;
        }
        Ok(Head::Closed) => return,
        Err(_) => {
            debug!(%peer, "request head timed out");
            return;
        }
    };
    let target = head.lines().next().and_then(|l| l.split(' ').nth(1));
    if target.is_some_and(crate::files::is_file_path) {
        crate::files::serve_http1(stream, head, buf, state, peer).await;
        return;
    }
    if let Err(e) = upgrade(&mut stream, &head, state.tcp_fallback).await {
        debug!(%peer, "tunnel refused: {e}");
        return;
    }
    run(stream, buf, state, peer).await;
}

/// What `read_head` found.
pub(crate) enum Head {
    Got(String),
    /// Over `MAX_HEAD` without its end.
    TooLarge,
    /// The connection ended (or failed) before a whole head.
    Closed,
}

/// Read one request head into `buf` and take it out: what arrived after it
/// stays in `buf`, since a client may send a body or its first frame right
/// behind the request.
pub(crate) async fn read_head<S: AsyncRead + Unpin>(stream: &mut S, buf: &mut Vec<u8>) -> Head {
    let mut chunk = [0u8; 1024];
    let end = loop {
        if let Some(end) = ws::find_header_end(buf) {
            break end;
        }
        if buf.len() > MAX_HEAD {
            return Head::TooLarge;
        }
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return Head::Closed,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };
    let rest = buf.split_off(end);
    let head = String::from_utf8_lossy(buf).into_owned();
    *buf = rest;
    Head::Got(head)
}

/// Answer the request head: 101 for the tunnel, a status line for anything
/// else. With the fallback off the path is refused with 403, which the
/// native client reads as "this server has no TCP fallback" (since `http/1.1`
/// is offered for files anyway, the TLS handshake no longer says it).
async fn upgrade<S>(stream: &mut S, head: &str, enabled: bool) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = match ws::parse_upgrade(head) {
        Ok(request) if request.path != PATH => {
            refuse(stream, "404 Not Found").await;
            anyhow::bail!("not the tunnel's path");
        }
        Ok(_) if !enabled => {
            refuse(stream, "403 Forbidden").await;
            anyhow::bail!("the TCP fallback is off");
        }
        Ok(request) => request,
        Err(status) => {
            refuse(stream, status).await;
            anyhow::bail!("bad upgrade request: {status}");
        }
    };
    // No Sec-WebSocket-Extensions in the answer: nothing is negotiated, so a
    // browser's permessage-deflate offer is declined
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
         Connection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
        accept_key(&request.key)
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

/// Answer a request we will not upgrade, then let the caller hang up.
async fn refuse<S: AsyncWrite + Unpin>(stream: &mut S, status: &str) {
    let _ = stream
        .write_all(
            format!(
                "HTTP/1.1 {status}\r\nSec-WebSocket-Version: 13\r\n\
                 Content-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await;
    let _ = stream.shutdown().await;
}

/// RFC 6455: base64(SHA-1(key + GUID)).
fn accept_key(key: &str) -> String {
    use base64::Engine as _;
    let digest = ring::digest::digest(
        &ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
        format!("{key}{}", ws::GUID).as_bytes(),
    );
    base64::engine::general_purpose::STANDARD.encode(digest.as_ref())
}

/// Bridge one tunnelled session onto the control handler and the media relay
/// until either side goes away (the twin of `web::run_session`).
async fn run<S>(stream: S, leftover: Vec<u8>, state: Arc<ServerState>, peer: SocketAddr)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let label = format!("tcp:{}", peer.ip());
    // test-web.sh counts this line; the address only at debug
    info!("session established over the TCP fallback");
    debug!(peer = %label, "tunnel opened");

    let SessionStart {
        mut handler,
        bridge,
        media_rx,
        sid_rx,
    } = web::start_session(&label, peer.ip(), &state);
    let (bridge_read, bridge_write) = tokio::io::split(bridge);
    let (stream_read, stream_write) = tokio::io::split(stream);
    let (datagram_tx, datagram_rx) = mpsc::channel(DATAGRAM_LANE);
    let (video_tx, video_rx) = mpsc::channel(VIDEO_LANE);

    let mut reader = tokio::spawn(read_side(
        stream_read,
        leftover,
        bridge_write,
        sid_rx,
        state.clone(),
    ));
    let mut writer = tokio::spawn(write_side(stream_write, bridge_read, datagram_rx, video_rx));
    // Ends only with the session (cleanup drops its media queue) or with the
    // writer (the lanes close), so nothing waits on it.
    let media = tokio::spawn(web::pump_media_out(
        DatagramSink::Tunnel(datagram_tx),
        media_rx,
        video_tx,
        state,
    ));

    tokio::select! {
        // The client closed, broke the framing or went away: there is nobody
        // left to deliver anything to.
        _ = &mut reader => debug!(peer = %label, "client side ended"),
        // A write failed, or the handler is done and the goodbye went out
        _ = &mut writer => {
            debug!(peer = %label, "server side ended");
            let _ = tokio::time::timeout(DRAIN, &mut reader).await;
        }
        // Kick, ban, failed authentication, shutdown: the writer delivers
        // what the handler wrote last and closes the tunnel, then the reader
        // waits for the client's answer so the socket never closes unread.
        _ = &mut handler => {
            debug!(peer = %label, "control handler ended");
            let _ = tokio::time::timeout(DRAIN, &mut writer).await;
            let _ = tokio::time::timeout(DRAIN, &mut reader).await;
        }
    }

    // Dropping both halves of the bridge is the handler's EOF: it runs its
    // normal session cleanup.
    reader.abort();
    writer.abort();
    media.abort();
    if !handler.is_finished()
        && tokio::time::timeout(Duration::from_secs(10), &mut handler)
            .await
            .is_err()
    {
        warn!(peer = %label, "control handler did not exit after EOF, aborting");
        handler.abort();
    }
    debug!(peer = %label, "session ended");
}

/// Client → server: control chunks into the handler's duplex, media packets
/// into the relay once the session id is known (before that there is nobody
/// to relay them for). Runs until the client closes, goes away or breaks the
/// framing — and goes on reading after the handler is gone, so the socket is
/// never closed with unread data.
async fn read_side<R: AsyncRead + Unpin>(
    mut stream: R,
    leftover: Vec<u8>,
    mut bridge: WriteHalf<DuplexStream>,
    mut sid_rx: oneshot::Receiver<SessionId>,
    state: Arc<ServerState>,
) {
    let mut decoder = Decoder::new(true, MAX_MESSAGE);
    decoder.feed(&leftover);
    let mut session: Option<SessionId> = None;
    let mut bridge_open = true;
    let mut chunk = vec![0u8; 16 * 1024];
    loop {
        loop {
            let message = match decoder.next() {
                Ok(Some(message)) => message,
                Ok(None) => break,
                Err(e) => {
                    debug!("tunnel framing broken: {e}");
                    return;
                }
            };
            match message {
                Message::Binary(data) => match data.split_first() {
                    Some((0x00, control)) => {
                        // A write fails once the handler is gone: what the
                        // client still says goes nowhere, but it is read
                        if bridge_open && bridge.write_all(control).await.is_err() {
                            bridge_open = false;
                        }
                    }
                    Some(_) => {
                        if session.is_none() {
                            session = sid_rx.try_recv().ok();
                        }
                        if let Some(session_id) = session {
                            media::handle_packet(session_id, Bytes::from(data), &state).await;
                        }
                    }
                    None => {}
                },
                Message::Close => return,
                // Text is not part of the protocol
                Message::Text(_) => return,
                // Nothing we ship sends pings: neither side of the tunnel
                // uses them, and a page cannot
                Message::Ping(_) | Message::Pong(_) => {}
            }
        }
        let read = tokio::time::timeout(IDLE_TIMEOUT, stream.read(&mut chunk)).await;
        let n = match read {
            Ok(Ok(n)) if n > 0 => n,
            _ => return,
        };
        decoder.feed(&chunk[..n]);
    }
}

/// Server → client, one message at a time: datagrams (voice) first, then
/// control, then video, and every message flushed as it is written.
///
/// Ends on control EOF — the handler is done — after delivering everything
/// it wrote and closing the tunnel, or on a write error. A closed media lane
/// only disables its branch: on a kick the relay lets go of the session
/// before the handler has written the reason.
async fn write_side<W: AsyncWrite + Unpin>(
    mut stream: W,
    mut bridge: ReadHalf<DuplexStream>,
    mut datagrams: mpsc::Receiver<Bytes>,
    mut video: mpsc::Receiver<Bytes>,
) {
    let mut control = vec![0u8; CONTROL_CHUNK];
    let (mut datagrams_open, mut video_open) = (true, true);
    let mut out = Vec::with_capacity(CONTROL_CHUNK + 16);
    loop {
        out.clear();
        // Every branch only receives (recv and read are cancel-safe); the
        // write happens below, outside the select. The control branch is
        // never disabled, so the select always has something to wait on.
        tokio::select! {
            biased;
            packet = datagrams.recv(), if datagrams_open => match packet {
                Some(packet) => ws::encode_frame(&mut out, ws::OP_BINARY, &[&packet], None),
                None => {
                    datagrams_open = false;
                    continue;
                }
            },
            read = bridge.read(&mut control) => match read {
                Ok(0) | Err(_) => break,
                Ok(n) => ws::encode_frame(&mut out, ws::OP_BINARY, &[&[0x00], &control[..n]], None),
            },
            packet = video.recv(), if video_open => match packet {
                Some(packet) => ws::encode_frame(&mut out, ws::OP_BINARY, &[&packet], None),
                None => {
                    video_open = false;
                    continue;
                }
            },
        }
        if send(&mut stream, &out).await.is_err() {
            return;
        }
    }
    // Everything the handler wrote went out: close properly, so the client
    // reads the last message rather than a reset
    out.clear();
    ws::encode_frame(&mut out, ws::OP_CLOSE, &[&1000u16.to_be_bytes()], None);
    let _ = send(&mut stream, &out).await;
    let _ = stream.shutdown().await;
}

/// Write one frame and flush it through TLS into the socket.
async fn send<W: AsyncWrite + Unpin>(stream: &mut W, frame: &[u8]) -> std::io::Result<()> {
    stream.write_all(frame).await?;
    stream.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    use bytes::BytesMut;

    use voipc_protocol::codec::{
        decode_server_msg, encode_client_msg, encode_server_msg, try_decode_frame, PROTOCOL_VERSION,
    };
    use voipc_protocol::messages::{ClientMessage, ServerMessage};
    use voipc_protocol::video::VideoPacket;
    use voipc_protocol::voice::{VoicePacket, VoicePacketType};

    use crate::config::ServerConfig;
    use crate::settings::ServerSettings;

    const KEY: [u8; 4] = [0x11, 0x22, 0x33, 0x44];
    const UPGRADE: &str = "GET /voipc HTTP/1.1\r\nHost: test\r\nUpgrade: websocket\r\n\
         Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n\r\n";

    fn test_state() -> Arc<ServerState> {
        let config = ServerConfig {
            tcp_fallback: true,
            ..ServerConfig::default()
        };
        Arc::new(ServerState::new(
            &config,
            ServerSettings::default(),
            Vec::new(),
            "test-admin-token".into(),
        ))
    }

    /// Serve one in-memory connection; returns the client's end.
    fn open(state: &Arc<ServerState>) -> DuplexStream {
        let (client, server) = tokio::io::duplex(1 << 20);
        tokio::spawn(serve(server, state.clone(), "127.0.0.1:1".parse().unwrap()));
        client
    }

    async fn read_head(io: &mut DuplexStream) -> (String, Vec<u8>) {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let n = io.read(&mut chunk).await.unwrap();
            assert!(n > 0, "closed before the answer ended");
            buf.extend_from_slice(&chunk[..n]);
            if let Some(end) = ws::find_header_end(&buf) {
                let rest = buf.split_off(end);
                return (String::from_utf8(buf).unwrap(), rest);
            }
        }
    }

    /// A tunnel client over an in-memory pipe.
    struct Client {
        io: DuplexStream,
        decoder: Decoder,
        control: BytesMut,
    }

    impl Client {
        async fn connect(state: &Arc<ServerState>) -> Self {
            let mut io = open(state);
            io.write_all(UPGRADE.as_bytes()).await.unwrap();
            let (head, rest) = read_head(&mut io).await;
            assert!(head.starts_with("HTTP/1.1 101"), "{head}");
            // RFC 6455 §1.3's example key and answer
            assert_eq!(
                ws::header(&head, "sec-websocket-accept"),
                Some("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
            );
            let mut decoder = Decoder::new(false, MAX_MESSAGE);
            decoder.feed(&rest);
            Self {
                io,
                decoder,
                control: BytesMut::new(),
            }
        }

        async fn send(&mut self, parts: &[&[u8]]) {
            let mut out = Vec::new();
            ws::encode_frame(&mut out, ws::OP_BINARY, parts, Some(KEY));
            self.io.write_all(&out).await.unwrap();
        }

        async fn send_control(&mut self, msg: &ClientMessage) {
            self.send(&[&[0x00], &encode_client_msg(msg).unwrap()])
                .await;
        }

        async fn authenticate(&mut self, protocol_version: u32) {
            self.send_control(&ClientMessage::Authenticate {
                username: "tunnel".into(),
                protocol_version,
                app_version: "1.0.0".into(),
                identity_key: None,
                prekey_bundle: None,
                account: None,
            })
            .await;
        }

        /// The next message, `None` once the tunnel is closed.
        async fn next(&mut self) -> Option<Message> {
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    if let Some(message) = self.decoder.next().unwrap() {
                        return Some(message);
                    }
                    let mut chunk = [0u8; 4096];
                    let n = self.io.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        return None;
                    }
                    self.decoder.feed(&chunk[..n]);
                }
            })
            .await
            .expect("the tunnel answered within 5 s")
        }

        /// The next control message from the server; media is skipped.
        async fn next_control(&mut self) -> ServerMessage {
            loop {
                if let Some(payload) = try_decode_frame(&mut self.control).unwrap() {
                    return decode_server_msg(&payload).unwrap();
                }
                match self.next().await {
                    Some(Message::Binary(data)) if data[0] == 0x00 => {
                        self.control.extend_from_slice(&data[1..])
                    }
                    Some(Message::Binary(_)) => {}
                    other => panic!("expected a control message, got {other:?}"),
                }
            }
        }

        /// The next media packet within `wait`; control is skipped.
        async fn next_media(&mut self, wait: Duration) -> Option<Vec<u8>> {
            tokio::time::timeout(wait, async {
                loop {
                    match self.next().await {
                        Some(Message::Binary(data)) if data[0] != 0x00 => return data,
                        Some(Message::Binary(data)) => self.control.extend_from_slice(&data[1..]),
                        other => panic!("expected media, got {other:?}"),
                    }
                }
            })
            .await
            .ok()
        }
    }

    #[tokio::test]
    async fn a_tunnelled_session_authenticates_and_relays_media() {
        let state = test_state();
        let mut client = Client::connect(&state).await;

        client.authenticate(PROTOCOL_VERSION).await;
        let session_id = match client.next_control().await {
            ServerMessage::Authenticated { session_id, .. } => session_id,
            other => panic!("unexpected reply: {other:?}"),
        };
        assert_eq!(state.sessions.len(), 1);

        // Media: a ping comes back as a pong
        client
            .send(&[&VoicePacket::ping(session_id, 77).to_bytes()])
            .await;
        let pong = client
            .next_media(Duration::from_secs(5))
            .await
            .expect("pong");
        let pong = VoicePacket::from_bytes(&pong).unwrap();
        assert_eq!(pong.packet_type, VoicePacketType::Pong);
        assert_eq!(pong.sequence, 77);

        // A foreign session id in the header is dropped, not answered
        client
            .send(&[&VoicePacket::ping(session_id + 1, 78).to_bytes()])
            .await;
        assert!(client
            .next_media(Duration::from_millis(300))
            .await
            .is_none());

        // Video: fragments, one message each, are accepted (no viewers, so
        // they go nowhere) and the session stays healthy
        for index in 0..2u8 {
            let packet = VideoPacket::encrypted_fragment(
                true,
                session_id,
                1,
                index,
                2,
                0,
                1,
                0x5EED,
                vec![7; 100],
            )
            .to_bytes();
            client.send(&[&packet]).await;
        }
        client
            .send(&[&VoicePacket::ping(session_id, 79).to_bytes()])
            .await;
        let pong = client
            .next_media(Duration::from_secs(5))
            .await
            .expect("pong after video");
        assert_eq!(VoicePacket::from_bytes(&pong).unwrap().sequence, 79);

        // Closing the tunnel cleans the session up
        let mut close = Vec::new();
        ws::encode_frame(
            &mut close,
            ws::OP_CLOSE,
            &[&1000u16.to_be_bytes()],
            Some(KEY),
        );
        client.io.write_all(&close).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while !state.sessions.is_empty() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("session removed within 5 s");
    }

    /// The handler's last word must not be lost to a reset: the client reads
    /// it, then the server's Close, then the end of the stream.
    #[tokio::test]
    async fn a_refused_login_hears_why_before_the_tunnel_closes() {
        let state = test_state();
        let mut client = Client::connect(&state).await;
        client.authenticate(PROTOCOL_VERSION - 1).await;
        match client.next_control().await {
            ServerMessage::Refused { text, .. } => {
                assert!(text.contains("version mismatch"), "{text}")
            }
            other => panic!("unexpected reply: {other:?}"),
        }
        assert_eq!(client.next().await, Some(Message::Close));
        assert_eq!(client.next().await, None);
    }

    #[tokio::test]
    async fn a_kick_reason_arrives_before_the_tunnel_closes() {
        let state = test_state();
        let mut client = Client::connect(&state).await;
        client.authenticate(PROTOCOL_VERSION).await;
        let session_id = match client.next_control().await {
            ServerMessage::Authenticated { session_id, .. } => session_id,
            other => panic!("unexpected reply: {other:?}"),
        };

        // What an admin kick does (tcp::force_disconnect)
        let close = {
            let session = state.sessions.get(&session_id).unwrap();
            let reason = ServerMessage::Disconnected {
                reason: "bye".into(),
            };
            session
                .tcp_tx
                .try_send(encode_server_msg(&reason).unwrap())
                .unwrap();
            session.close.clone()
        };
        close.notify_one();

        loop {
            if let ServerMessage::Disconnected { reason } = client.next_control().await {
                assert_eq!(reason, "bye");
                break;
            }
        }
        assert_eq!(client.next().await, Some(Message::Close));
    }

    #[tokio::test]
    async fn anything_but_the_tunnel_upgrade_is_refused() {
        let state = test_state();
        for (request, status) in [
            (UPGRADE.replacen("/voipc", "/other", 1), "404"),
            (UPGRADE.replacen("GET", "POST", 1), "405"),
            (
                UPGRADE.replacen("Sec-WebSocket-Version: 13", "Sec-WebSocket-Version: 8", 1),
                "426",
            ),
            (
                "GET /voipc HTTP/1.1\r\nHost: test\r\n\r\n".to_string(),
                "400",
            ),
        ] {
            let mut io = open(&state);
            io.write_all(request.as_bytes()).await.unwrap();
            let (head, _) = read_head(&mut io).await;
            assert!(
                head.starts_with(&format!("HTTP/1.1 {status}")),
                "{request:?} got {head}"
            );
        }
        assert!(state.sessions.is_empty());
    }

    #[tokio::test]
    async fn an_unmasked_frame_ends_the_tunnel() {
        // RFC 6455 §5.1: the server must close on an unmasked client frame
        let state = test_state();
        let mut client = Client::connect(&state).await;
        let mut frame = Vec::new();
        ws::encode_frame(&mut frame, ws::OP_BINARY, &[&[0x05; 20]], None);
        client.io.write_all(&frame).await.unwrap();
        assert_eq!(client.next().await, None);
    }

    /// quinn sends datagrams ahead of stream data, and the control stream
    /// ahead of video: so must the writer, or voice queues behind a share.
    #[tokio::test]
    async fn the_writer_sends_voice_then_control_then_video() {
        let (handler_end, bridge) = tokio::io::duplex(1024);
        let (bridge_read, _bridge_write) = tokio::io::split(bridge);
        let (handler_read, mut handler_write) = tokio::io::split(handler_end);
        let (datagram_tx, datagram_rx) = mpsc::channel(8);
        let (video_tx, video_rx) = mpsc::channel(8);
        for i in 0..3u8 {
            video_tx.send(Bytes::from(vec![0x13, i])).await.unwrap();
        }
        handler_write.write_all(b"ctl").await.unwrap();
        datagram_tx
            .send(Bytes::from_static(&[0x05, 9]))
            .await
            .unwrap();

        let (mut client, server) = tokio::io::duplex(1 << 16);
        let writer = tokio::spawn(write_side(server, bridge_read, datagram_rx, video_rx));
        let mut decoder = Decoder::new(false, MAX_MESSAGE);
        let mut got = Vec::new();
        let mut chunk = [0u8; 1024];
        while got.len() < 5 {
            let n = client.read(&mut chunk).await.unwrap();
            decoder.feed(&chunk[..n]);
            while let Some(message) = decoder.next().unwrap() {
                got.push(message);
            }
        }
        let binary = |b: &[u8]| Message::Binary(b.to_vec());
        assert_eq!(
            got,
            [
                binary(&[0x05, 9]),
                binary(b"\0ctl"),
                binary(&[0x13, 0]),
                binary(&[0x13, 1]),
                binary(&[0x13, 2])
            ]
        );

        // Closed media lanes do not end it; the handler hanging up does, and
        // a Close goes out first
        drop((datagram_tx, video_tx));
        tokio::task::yield_now().await;
        assert!(!writer.is_finished());
        drop((handler_read, handler_write));
        loop {
            let n = client.read(&mut chunk).await.unwrap();
            assert!(n > 0, "closed without a Close frame");
            decoder.feed(&chunk[..n]);
            if let Some(message) = decoder.next().unwrap() {
                assert_eq!(message, Message::Close);
                break;
            }
        }
        writer.await.unwrap();
    }

    // ── Files on http/1.1 ────────────────────────────────────────────────

    use crate::files::test_support::{blob, path_of, read_ticket, state_with_files, upload_ticket};

    /// One answer: the head, and a body of its Content-Length.
    async fn answer(io: &mut DuplexStream, rest: &mut Vec<u8>) -> (String, Vec<u8>) {
        let mut chunk = [0u8; 4096];
        let end = loop {
            if let Some(end) = ws::find_header_end(rest) {
                break end;
            }
            let n = io.read(&mut chunk).await.unwrap();
            assert!(n > 0, "closed before the answer");
            rest.extend_from_slice(&chunk[..n]);
        };
        let after = rest.split_off(end);
        let head = String::from_utf8(std::mem::replace(rest, after)).unwrap();
        let len: usize = ws::header(&head, "content-length").map_or(0, |v| v.parse().unwrap());
        while rest.len() < len {
            let n = io.read(&mut chunk).await.unwrap();
            assert!(n > 0, "closed inside the body");
            rest.extend_from_slice(&chunk[..n]);
        }
        let after = rest.split_off(len);
        (head, std::mem::replace(rest, after))
    }

    /// A native client's file transfer: one connection, several requests,
    /// whether or not the TCP fallback is on.
    #[tokio::test]
    async fn files_go_over_http1_with_the_fallback_off() {
        let (state, _dir) = state_with_files(|_| {});
        assert!(!state.tcp_fallback);
        let (bytes, hash) = blob(1024 * 1024 + 500, 1);
        let up = upload_ticket(&state, hash, bytes.len() as u64);
        let mut io = open(&state);
        let mut rest = Vec::new();
        for (i, chunk) in bytes.chunks(1024 * 1024).enumerate() {
            let head = format!(
                "PUT {}?offset={} HTTP/1.1\r\nHost: test\r\nAuthorization: Bearer {up}\r\n\
                 Content-Length: {}\r\n\r\n",
                path_of(&hash),
                i * 1024 * 1024,
                chunk.len()
            );
            io.write_all(head.as_bytes()).await.unwrap();
            io.write_all(chunk).await.unwrap();
            let (head, _) = answer(&mut io, &mut rest).await;
            let want = if i == 0 {
                "HTTP/1.1 204"
            } else {
                "HTTP/1.1 201"
            };
            assert!(head.starts_with(want), "{head}");
            assert!(head.contains("connection: keep-alive"), "{head}");
        }

        let down = read_ticket(&state, hash);
        let mut got = Vec::new();
        while got.len() < bytes.len() {
            let head = format!(
                "GET {} HTTP/1.1\r\nHost: test\r\nAuthorization: Bearer {down}\r\n\
                 Range: bytes={}-\r\n\r\n",
                path_of(&hash),
                got.len()
            );
            io.write_all(head.as_bytes()).await.unwrap();
            let (head, body) = answer(&mut io, &mut rest).await;
            assert!(head.starts_with("HTTP/1.1 206"), "{head}");
            got.extend_from_slice(&body);
        }
        assert_eq!(got, bytes);
        // Asked to close: answered, then closed
        let head = format!(
            "GET {} HTTP/1.1\r\nAuthorization: Bearer wrong\r\nConnection: close\r\n\r\n",
            path_of(&hash)
        );
        io.write_all(head.as_bytes()).await.unwrap();
        let (head, _) = answer(&mut io, &mut rest).await;
        assert!(head.starts_with("HTTP/1.1 401"), "{head}");
        let mut end = [0u8; 1];
        assert_eq!(io.read(&mut end).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn a_file_request_must_be_plain_and_small() {
        let (state, _dir) = state_with_files(|_| {});
        let (_, hash) = blob(10, 2);
        let up = upload_ticket(&state, hash, 10);
        for (head, status) in [
            (
                format!(
                    "PUT {} HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
                    path_of(&hash)
                ),
                "501",
            ),
            // More than the upload has left: refused before a byte is read
            (
                format!(
                    "PUT {}?offset=0 HTTP/1.1\r\nAuthorization: Bearer {up}\r\nContent-Length: 11\r\n\r\n",
                    path_of(&hash)
                ),
                "413",
            ),
            // No ticket: refused before the body too, however large
            (
                format!(
                    "PUT {}?offset=0 HTTP/1.1\r\nContent-Length: 1048577\r\n\r\n",
                    path_of(&hash)
                ),
                "401",
            ),
            (
                format!(
                    "PUT {} HTTP/1.1\r\nContent-Length: ten\r\n\r\n",
                    path_of(&hash)
                ),
                "400",
            ),
            (format!("GET {}\r\n\r\n", path_of(&hash)), "400"),
            ("GET /f/v1/nothex HTTP/1.1\r\n\r\n".to_string(), "404"),
            (format!("DELETE {} HTTP/1.1\r\n\r\n", path_of(&hash)), "405"),
        ] {
            let mut io = open(&state);
            io.write_all(head.as_bytes()).await.unwrap();
            let (answer, _) = answer(&mut io, &mut Vec::new()).await;
            assert!(
                answer.starts_with(&format!("HTTP/1.1 {status}")),
                "{head:?} -> {answer}"
            );
        }
    }

    /// With the fallback off, the tunnel's path says so in a status the
    /// native client reads as "this server has no TCP fallback".
    #[tokio::test]
    async fn the_tunnel_is_refused_with_403_when_the_fallback_is_off() {
        let (state, _dir) = state_with_files(|_| {});
        let mut io = open(&state);
        io.write_all(UPGRADE.as_bytes()).await.unwrap();
        let (head, _) = read_head(&mut io).await;
        assert!(head.starts_with("HTTP/1.1 403"), "{head}");
        // The other refusals keep their meaning
        let mut io = open(&state);
        io.write_all(UPGRADE.replacen("/voipc", "/other", 1).as_bytes())
            .await
            .unwrap();
        let (head, _) = read_head(&mut io).await;
        assert!(head.starts_with("HTTP/1.1 404"), "{head}");
    }
}
