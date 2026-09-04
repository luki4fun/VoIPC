use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;

use bytes::BytesMut;
use ringbuf::traits::Producer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use tauri::Emitter;
#[cfg(not(target_os = "android"))]
use tauri::Manager;
use tracing::{error, info, warn};

use voipc_crypto::media_keys::MediaKey;
use voipc_protocol::codec::{
    decode_server_msg, encode_client_msg, try_decode_frame, APP_VERSION, PROTOCOL_VERSION,
};
use voipc_protocol::messages::{ClientMessage, ServerMessage};
use voipc_protocol::types::*;
use voipc_protocol::video::{
    FrameAssembler, ScreenShareAudioPacket, VideoPacket, SCREEN_AUDIO_HEADER_SIZE,
    VIDEO_HEADER_SIZE,
};
use voipc_protocol::voice::VoicePacket;

use crate::app_state::{ActiveConnection, AppState, PendingTarget, SignalState};
use crate::screenshare;

/// Bound for each connect phase (TCP, TLS, auth response).
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// The server pings every 60 s; two missed pings plus margin means the path
/// is dead even though the socket never reported it (roam, sleep, NAT expiry).
const TCP_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(150);

/// Connect to the server, authenticate, spawn background tasks, and store the connection.
/// Returns the assigned user_id on success.
pub async fn connect_to_server(
    state: &AppState,
    app_handle: tauri::AppHandle,
    address: String,
    username: String,
    accept_invalid_certs: bool,
) -> Result<u32, String> {
    // Serialize connects: the reconnect loop and a manual connect can race,
    // and the write lock below is released before the network phase — the
    // loser's tasks would otherwise be overwritten without teardown and leak.
    let _connect_guard = state.connect_lock.lock().await;

    // Tear down any existing connection first (e.g. after webview reload)
    {
        let mut conn = state.connection.write().await;
        if let Some(mut old) = conn.take() {
            old.transmitting.store(false, std::sync::atomic::Ordering::Relaxed);
            old.screen_share_active.store(false, std::sync::atomic::Ordering::Relaxed);
            if let Some(task) = old.capture_task.take() { let _ = task.await; }
            if let Some(task) = old.screen_capture_task.take() { let _ = task.await; }
            let _ = send_tcp_message(&old.tcp_tx, &ClientMessage::Disconnect).await;
            drop(old.tcp_tx);
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            for task in old.tasks { task.abort(); }
            drop(old.voice_tx);
            drop(old.video_tx);
            drop(old.screen_audio_tx);
            info!("cleaned up stale connection before reconnecting");
        }
    }

    // Fresh Signal identity per connection (ephemeral by design — no accounts,
    // nothing to fingerprint). Also required for correctness: the server
    // reassigns user ids on restart, and libsignal pins identities to
    // "user_N", so a kept store would reject the new holder of an old id.
    {
        let mut signal = state.signal.lock().map_err(|e| e.to_string())?;
        signal.stores = None;
        signal.initialized = false;
    }

    let (host, port) = parse_address(&address)?;

    // TCP connect. Every phase below is bounded: without a deadline a
    // black-holed host keeps the reconnect loop (and its Cancel button)
    // stuck in SYN retries for minutes.
    let tcp_stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((&*host, port)))
        .await
        .map_err(|_| format!("Timed out connecting to {}", address))?
        .map_err(|e| format!("Could not connect to {}: {}", address, e))?;

    info!("TCP connected to {}", address);

    // TLS handshake
    let tls_config = if accept_invalid_certs {
        warn!("Using TOFU certificate pinning (self-signed mode)");
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(TofuCertVerifier {
                key: tofu_key(&host, port),
            }))
            .with_no_client_auth()
    } else {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    let connector = TlsConnector::from(Arc::new(tls_config));
    let server_name = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        rustls::pki_types::ServerName::IpAddress(ip.into())
    } else {
        rustls::pki_types::ServerName::try_from(host.clone())
            .map_err(|e| format!("Invalid server name '{}': {}", host, e))?
    };

    let mut tls_stream = tokio::time::timeout(CONNECT_TIMEOUT, connector.connect(server_name, tcp_stream))
        .await
        .map_err(|_| format!("Timed out in TLS handshake with {}", address))?
        .map_err(|e| format!("TLS handshake failed: {}", e))?;

    info!("TLS handshake complete");

    // Initialize Signal Protocol state if not already done
    {
        let mut signal = state.signal.lock().map_err(|e| e.to_string())?;
        if !signal.initialized {
            info!("initializing Signal Protocol state");
            let identity_key_pair = voipc_crypto::generate_identity_key_pair();
            let registration_id: u32 = rand::Rng::gen(&mut rand::thread_rng());
            let mut stores =
                voipc_crypto::SignalStores::new(&identity_key_pair, registration_id);

            // Generate prekeys synchronously (libsignal stores are !Send)
            let _prekey_set = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(
                    voipc_crypto::prekey::generate_prekeys(
                        &mut stores,
                        &identity_key_pair,
                        1,
                        voipc_crypto::prekey::INITIAL_PREKEY_COUNT,
                    ),
                )
            })
            .map_err(|e| format!("failed to generate prekeys: {e}"))?;

            signal.stores = Some(stores);
            signal.initialized = true;
            info!("Signal Protocol state initialized");
        }
    }

    // Extract identity key and prekey bundle from Signal stores for authentication
    let (identity_key, prekey_bundle) = {
        let signal = state.signal.lock().map_err(|e| e.to_string())?;
        if let Some(ref stores) = signal.stores {
            let ik_bytes = stores.identity.key_pair.public_key.clone();

            // Extract signed prekey from the store
            let signed_prekey_data = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    use libsignal_protocol::{GenericSignedPreKey, SignedPreKeyId, SignedPreKeyStore};
                    let record = stores
                        .signed_prekey
                        .get_signed_pre_key(SignedPreKeyId::from(1u32))
                        .await
                        .ok()?;
                    let pub_key = record.public_key().ok()?.serialize().to_vec();
                    let signature = record.signature().ok()?.to_vec();
                    Some((pub_key, signature))
                })
            });

            let (spk_public, spk_signature) = match signed_prekey_data {
                Some(data) => data,
                None => {
                    warn!("failed to extract signed prekey — bundle will have empty signed prekey");
                    (Vec::new(), Vec::new())
                }
            };

            // Extract one-time prekeys from the store
            let mut one_time_prekeys = Vec::new();
            for (&id, bytes) in &stores.prekey.prekeys {
                if let Ok(record) = libsignal_protocol::PreKeyRecord::deserialize(bytes) {
                    if let Ok(pub_key) = record.public_key() {
                        one_time_prekeys.push(OneTimePreKey {
                            id,
                            public_key: pub_key.serialize().to_vec(),
                        });
                    }
                }
            }

            let bundle = PreKeyBundleData {
                registration_id: stores.identity.registration_id,
                device_id: 1,
                identity_key: ik_bytes.clone(),
                signed_prekey_id: 1,
                signed_prekey: spk_public,
                signed_prekey_signature: spk_signature,
                prekeys: one_time_prekeys,
            };

            (Some(ik_bytes), Some(bundle))
        } else {
            (None, None)
        }
    };

    let auth_msg = ClientMessage::Authenticate {
        username: username.clone(),
        protocol_version: PROTOCOL_VERSION,
        app_version: APP_VERSION.to_string(),
        identity_key,
        prekey_bundle,
    };
    let data =
        encode_client_msg(&auth_msg).map_err(|e| format!("Failed to encode auth: {}", e))?;
    tls_stream
        .write_all(&data)
        .await
        .map_err(|e| format!("Failed to send auth: {}", e))?;

    // Read until we get the Authenticated or AuthError response
    let mut buf = BytesMut::with_capacity(4096);
    let (user_id, session_id, udp_port, udp_token) = loop {
        let n = tokio::time::timeout(CONNECT_TIMEOUT, tls_stream.read_buf(&mut buf))
            .await
            .map_err(|_| "Timed out waiting for the authentication response".to_string())?
            .map_err(|e| format!("Failed to read auth response: {}", e))?;

        if n == 0 {
            return Err("Server closed connection during authentication".into());
        }

        if let Some(payload) =
            try_decode_frame(&mut buf).map_err(|e| format!("Frame decode error: {}", e))?
        {
            let msg = decode_server_msg(&payload)
                .map_err(|e| format!("Failed to decode response: {}", e))?;

            match msg {
                ServerMessage::Authenticated {
                    user_id,
                    session_id,
                    udp_port,
                    udp_token,
                } => break (user_id, session_id, udp_port, udp_token),
                ServerMessage::AuthError { reason } => {
                    return Err(format!("Authentication failed: {}", reason));
                }
                other => {
                    warn!("unexpected message during auth: {:?}", other);
                }
            }
        }
    };

    info!(user_id, session_id, udp_port, "authenticated with server");

    // Reset Signal tracking state for the new connection.
    // User IDs are allocated fresh by the server, so old session tracking is stale.
    // Keep `stores` and `initialized` — identity key persists within app session,
    // and old sessions in the store will be overwritten on re-establishment.
    {
        let mut signal = state.signal.lock().map_err(|e| e.to_string())?;
        signal.own_user_id = Some(user_id);
        signal.established_sessions.clear();
        signal.pending_sessions.clear();
        signal.sender_key_distributed.clear();
        signal.sender_key_received.clear();
        signal.pending_messages.clear();
    }

    // Resolve UDP server address first to determine address family
    let udp_addr = format!("{}:{}", host, udp_port);
    let server_addr: std::net::SocketAddr = tokio::net::lookup_host(&udp_addr)
        .await
        .map_err(|e| format!("Failed to resolve UDP addr {}: {}", udp_addr, e))?
        .next()
        .ok_or_else(|| format!("No addresses found for {}", udp_addr))?;

    info!("UDP target resolved to {}", server_addr);

    // Set up UDP socket matching server address family, with large buffers
    let udp_socket = {
        let (domain, bind_addr) = if server_addr.is_ipv4() {
            (socket2::Domain::IPV4, "0.0.0.0:0")
        } else {
            (socket2::Domain::IPV6, "[::]:0")
        };
        let sock = socket2::Socket::new(
            domain,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .map_err(|e| format!("Failed to create UDP socket: {}", e))?;
        // 2MB buffers — absorbs ~1400 packets of burst without kernel drops
        if let Err(e) = sock.set_recv_buffer_size(2 * 1024 * 1024) {
            warn!("failed to set UDP recv buffer to 2MB: {e}");
        }
        if let Err(e) = sock.set_send_buffer_size(2 * 1024 * 1024) {
            warn!("failed to set UDP send buffer to 2MB: {e}");
        }
        sock.bind(&bind_addr.parse::<std::net::SocketAddr>().unwrap().into())
            .map_err(|e| format!("Failed to bind UDP socket: {}", e))?;
        sock.set_nonblocking(true)
            .map_err(|e| format!("Failed to set non-blocking: {}", e))?;
        let std_sock: std::net::UdpSocket = sock.into();
        Arc::new(
            UdpSocket::from_std(std_sock)
                .map_err(|e| format!("Failed to wrap UDP socket: {}", e))?,
        )
    };

    // Send an initial UDP ping so the server learns our UDP address
    let ping_packet = VoicePacket::ping(session_id, udp_token, 0);
    match udp_socket.send_to(&ping_packet.to_bytes(), server_addr).await {
        Ok(n) => info!("UDP ping sent ({} bytes) to {}", n, server_addr),
        Err(e) => error!("UDP ping send failed: {}", e),
    }

    // Start audio playback stream (output to speakers). Failure is not fatal:
    // the mixer task retries via the restart flag and surfaces an event.
    let settings = state.settings.read().await;
    let output_device = settings.output_device.clone();
    let saved_volume = settings.volume;
    drop(settings);

    let playback_restart = Arc::new(AtomicBool::new(false));
    let (playback_stream, playback_producer) =
        match voipc_audio::playback::start_playback(output_device.as_deref(), playback_restart.clone()) {
            Ok((s, p)) => (Some(s), Some(p)),
            Err(e) => {
                error!("Failed to start audio playback (will retry): {}", e);
                playback_restart.store(true, Ordering::Relaxed);
                (None, None)
            }
        };
    let output_device_live = Arc::new(std::sync::Mutex::new(output_device));
    let master_volume = Arc::new(AtomicU32::new(saved_volume.to_bits()));

    // Split TLS stream into reader/writer halves
    let (read_half, write_half) = tokio::io::split(tls_stream);

    // TCP writer channel
    let (tcp_tx, tcp_rx) = mpsc::channel::<Vec<u8>>(64);
    // UDP voice channel
    let (voice_tx, voice_rx) = mpsc::channel::<Vec<u8>>(256);
    // UDP video channel (separate from voice to avoid blocking).
    // 1024 slots ≈ ~68 frames at 15 fragments/frame — gives ~2s of headroom
    // before the non-blocking try_send in FrameProcessor starts dropping frames.
    let (video_tx, video_rx) = mpsc::channel::<Vec<u8>>(1024);
    // UDP screen share audio channel
    let (screen_audio_tx, screen_audio_rx) = mpsc::channel::<Vec<u8>>(128);

    // Shared state for media encryption, screen audio, and transmit control
    let screen_audio_send_count = Arc::new(AtomicU32::new(0));
    let screen_audio_recv_count = Arc::new(AtomicU32::new(0));
    let transmitting = Arc::new(AtomicBool::new(false));
    let screen_audio_enabled = Arc::new(AtomicBool::new(true));
    let current_media_key = Arc::new(std::sync::Mutex::new(None));
    let current_channel_id = Arc::new(AtomicU32::new(0));

    // Screen share video stats
    let screen_video_frames_sent = Arc::new(AtomicU32::new(0));
    let screen_video_bytes_sent = Arc::new(AtomicU64::new(0));
    let screen_video_frames_received = Arc::new(AtomicU32::new(0));
    let screen_video_frames_dropped = Arc::new(AtomicU32::new(0));
    let screen_video_bytes_received = Arc::new(AtomicU64::new(0));
    let screen_video_resolution = Arc::new(AtomicU32::new(0));

    // Video decode channel — assembled H.265 frames sent to a blocking decode task
    // to avoid stalling the UDP receiver (which also handles voice).
    // Tuple: (frame_data, is_keyframe) — the decode task needs is_keyframe to know
    // when it's safe to resume rendering after corruption suppression.
    let (video_decode_tx, video_decode_rx) = mpsc::channel::<(Vec<u8>, bool)>(64);

    // Render suppression flag — set by UDP receiver on frame loss, cleared by decode
    // task when a keyframe is successfully decoded. Prevents displaying gray/corrupted
    // delta frames that the H.265 decoder produces after reference chain breakage.
    let needs_keyframe = Arc::new(AtomicBool::new(false));

    // Shared screen share state — created early so TCP reader can reset on channel change
    let screen_share_active = Arc::new(AtomicBool::new(false));
    let watching_user_id_shared = Arc::new(AtomicU32::new(0));

    // Per-user volume control — shared between voice mixer and commands
    let user_volumes: Arc<std::sync::Mutex<HashMap<u32, f32>>> =
        Arc::new(std::sync::Mutex::new(HashMap::new()));

    // Per-user jitter buffers + decoders — UDP receiver pushes, mixer pops
    let mix_sources: MixSources = Arc::new(std::sync::Mutex::new(HashMap::new()));

    // Mute/deafen — initialize from persisted settings
    let (saved_muted, saved_deafened, saved_voice_mode, saved_vad_db, saved_ns) = {
        let s = state.settings.read().await;
        (
            s.muted,
            s.deafened,
            s.voice_mode.clone(),
            s.vad_threshold_db,
            s.noise_suppression,
        )
    };
    let is_muted = Arc::new(AtomicBool::new(saved_muted));
    let is_deafened = Arc::new(AtomicBool::new(saved_deafened));

    // Spawn background tasks
    let writer_handle = tokio::spawn(tcp_writer_task(write_half, tcp_rx));
    let reader_handle = tokio::spawn(tcp_reader_task(
        read_half,
        buf,
        app_handle.clone(),
        current_media_key.clone(),
        current_channel_id.clone(),
        state.signal.clone(),
        tcp_tx.clone(),
        user_id,
        screen_share_active.clone(),
        watching_user_id_shared.clone(),
    ));
    let udp_send_handle = tokio::spawn(udp_sender_task(udp_socket.clone(), voice_rx, server_addr));
    let video_send_handle = tokio::spawn(udp_sender_task(udp_socket.clone(), video_rx, server_addr));
    let screen_audio_send_handle =
        tokio::spawn(udp_sender_task(udp_socket.clone(), screen_audio_rx, server_addr));
    let video_decode_handle = tokio::task::spawn_blocking({
        let app_handle = app_handle.clone();
        let tcp_tx = tcp_tx.clone();
        let watching_uid = watching_user_id_shared.clone();
        let video_res = screen_video_resolution.clone();
        let needs_kf = needs_keyframe.clone();
        move || video_decode_render_task(video_decode_rx, app_handle, tcp_tx, watching_uid, video_res, needs_kf)
    });

    // Voice quality stats (read by the get_voice_stats command)
    let voice_frames_played = Arc::new(AtomicU32::new(0));
    let voice_frames_lost = Arc::new(AtomicU32::new(0));
    // Dead-UDP watchdog state: last Pong arrival, epoch ms
    let last_pong = Arc::new(AtomicU64::new(0));

    let udp_recv_handle = tokio::spawn(udp_receiver_task(
        udp_socket.clone(),
        server_addr,
        app_handle.clone(),
        session_id,
        mix_sources.clone(),
        video_decode_tx,
        screen_audio_recv_count.clone(),
        current_media_key.clone(),
        current_channel_id.clone(),
        screen_video_frames_received.clone(),
        screen_video_frames_dropped.clone(),
        screen_video_bytes_received.clone(),
        tcp_tx.clone(),
        watching_user_id_shared.clone(),
        needs_keyframe,
        last_pong.clone(),
    ));

    // Voice mixer — pops one frame per user per 20ms tick, mixes, and feeds
    // the playback ring. Owns the playback stream (rebuilds it on error).
    let mixer_handle = tokio::spawn(voice_mixer_task(
        mix_sources,
        playback_stream,
        playback_producer,
        playback_restart.clone(),
        output_device_live.clone(),
        is_deafened.clone(),
        user_volumes.clone(),
        master_volume.clone(),
        voice_frames_played.clone(),
        voice_frames_lost.clone(),
        app_handle.clone(),
    ));

    // UDP keepalive — keeps the NAT mapping alive through silent channels
    // and doubles as an RTT probe (server echoes the sequence in its Pong).
    let keepalive_handle = tokio::spawn(udp_keepalive_task(
        udp_socket,
        server_addr,
        session_id,
        udp_token,
        last_pong,
        app_handle.clone(),
    ));

    // Store the active connection
    let connection = ActiveConnection {
        user_id,
        username,
        session_id,
        is_muted,
        is_deafened,
        tcp_tx,
        voice_tx,
        video_tx,
        screen_audio_tx,
        tasks: vec![
            writer_handle,
            reader_handle,
            udp_send_handle,
            video_send_handle,
            screen_audio_send_handle,
            udp_recv_handle,
            video_decode_handle,
            mixer_handle,
            keepalive_handle,
        ],
        transmitting,
        capture_task: None,
        voice_sequence: Arc::new(AtomicU32::new(0)),
        master_volume,
        voice_frames_played,
        voice_frames_lost,
        output_device_live,
        playback_restart,
        udp_token,
        is_screen_sharing: false,
        screen_capture_task: None,
        screen_share_active,
        keyframe_requested: Arc::new(AtomicBool::new(false)),
        watching_user_id: None,
        watching_user_id_shared,
        capture_session: None,
        screen_audio_enabled,
        screen_audio_send_count,
        screen_audio_recv_count,
        screen_video_frames_sent,
        screen_video_bytes_sent,
        screen_video_frames_received,
        screen_video_frames_dropped,
        screen_video_bytes_received,
        screen_video_resolution,
        current_media_key,
        current_channel_id,
        voice_mode: Arc::new(AtomicU8::new(
            crate::app_state::VoiceMode::from_str(&saved_voice_mode) as u8,
        )),
        vad_threshold_db: Arc::new(AtomicI32::new(saved_vad_db as i32)),
        current_audio_level: Arc::new(AtomicI32::new(-9600)),
        noise_suppression: Arc::new(AtomicBool::new(saved_ns)),
        user_volumes,
    };

    let mut conn = state.connection.write().await;
    *conn = Some(connection);

    // Notify server of persisted mute/deafen state
    if saved_muted {
        if let Some(c) = conn.as_ref() {
            let _ = send_tcp_message(&c.tcp_tx, &ClientMessage::SetMuted { muted: true }).await;
        }
    }
    if saved_deafened {
        if let Some(c) = conn.as_ref() {
            let _ =
                send_tcp_message(&c.tcp_tx, &ClientMessage::SetDeafened { deafened: true }).await;
        }
    }

    Ok(user_id)
}

/// Send a client message over the TCP control channel.
pub async fn send_tcp_message(
    tcp_tx: &mpsc::Sender<Vec<u8>>,
    msg: &ClientMessage,
) -> Result<(), String> {
    let data =
        encode_client_msg(msg).map_err(|e| format!("Failed to encode message: {}", e))?;
    tcp_tx
        .send(data)
        .await
        .map_err(|_| "TCP send channel closed".to_string())
}

fn parse_address(address: &str) -> Result<(String, u16), String> {
    let (host, port_str) = if address.starts_with('[') {
        // IPv6: [::1]:9987
        let bracket_end = address
            .find("]:")
            .ok_or("Invalid IPv6 address format, expected [host]:port")?;
        let host = &address[1..bracket_end];
        let port_str = &address[bracket_end + 2..];
        (host.to_string(), port_str)
    } else {
        let parts: Vec<&str> = address.rsplitn(2, ':').collect();
        if parts.len() != 2 {
            return Err("Invalid address format, expected host:port".into());
        }
        (parts[1].to_string(), parts[0])
    };
    let port: u16 = port_str
        .parse()
        .map_err(|_| "Invalid port number".to_string())?;
    if host.is_empty() {
        return Err("Host cannot be empty".into());
    }
    Ok((host, port))
}

/// TCP writer task: sends encoded messages from the channel to the TCP stream.
async fn tcp_writer_task(
    mut write_half: tokio::io::WriteHalf<TlsStream<TcpStream>>,
    mut rx: mpsc::Receiver<Vec<u8>>,
) {
    while let Some(data) = rx.recv().await {
        if let Err(e) = write_half.write_all(&data).await {
            error!("TCP write error: {}", e);
            break;
        }
    }
    info!("TCP writer task ended");
}

/// TCP reader task: reads server messages, handles E2E encryption orchestration,
/// and emits Tauri events to the frontend.
async fn tcp_reader_task(
    mut read_half: tokio::io::ReadHalf<TlsStream<TcpStream>>,
    mut buf: BytesMut,
    app_handle: tauri::AppHandle,
    media_key: Arc<std::sync::Mutex<Option<MediaKey>>>,
    channel_id: Arc<AtomicU32>,
    signal: Arc<std::sync::Mutex<SignalState>>,
    tcp_tx: mpsc::Sender<Vec<u8>>,
    own_user_id: u32,
    screen_share_active: Arc<AtomicBool>,
    watching_user_id_shared: Arc<AtomicU32>,
) {
    'read: loop {
        match tokio::time::timeout(TCP_IDLE_TIMEOUT, read_half.read_buf(&mut buf)).await {
            Ok(Ok(0)) => {
                info!("server closed TCP connection");
                let _ = app_handle.emit(
                    "connection-lost",
                    serde_json::json!({"reason": "Server closed connection"}),
                );
                break;
            }
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                error!("TCP read error: {}", e);
                let _ = app_handle.emit(
                    "connection-lost",
                    serde_json::json!({"reason": format!("Read error: {}", e)}),
                );
                break;
            }
            Err(_) => {
                error!("no data from server for {:?}", TCP_IDLE_TIMEOUT);
                let _ = app_handle.emit(
                    "connection-lost",
                    serde_json::json!({"reason": "Connection timed out (no data from server)"}),
                );
                break;
            }
        }

        loop {
            match try_decode_frame(&mut buf) {
                Ok(Some(payload)) => match decode_server_msg(&payload) {
                    Ok(msg) => {
                        handle_server_message(
                            msg,
                            &app_handle,
                            &media_key,
                            &channel_id,
                            &signal,
                            &tcp_tx,
                            own_user_id,
                            &screen_share_active,
                            &watching_user_id_shared,
                        )
                        .await;
                    }
                    Err(e) => warn!("failed to decode server message: {}", e),
                },
                Ok(None) => break,
                Err(e) => {
                    // The bad length prefix is never consumed; reading on
                    // would only grow `buf` forever. Treat as a dead link.
                    error!("frame decode error: {}", e);
                    let _ = app_handle.emit(
                        "connection-lost",
                        serde_json::json!({"reason": format!("Protocol error: {}", e)}),
                    );
                    break 'read;
                }
            }
        }
    }
    info!("TCP reader task ended");
}

/// Dispatch a server message to the appropriate Tauri event.
/// Also handles E2E encryption orchestration (session establishment, sender key
/// distribution, and automatic decryption of encrypted messages).
async fn handle_server_message(
    msg: ServerMessage,
    app_handle: &tauri::AppHandle,
    media_key: &Arc<std::sync::Mutex<Option<MediaKey>>>,
    channel_id_store: &Arc<AtomicU32>,
    signal: &Arc<std::sync::Mutex<SignalState>>,
    tcp_tx: &mpsc::Sender<Vec<u8>>,
    own_user_id: u32,
    screen_share_active: &Arc<AtomicBool>,
    watching_user_id_shared: &Arc<AtomicU32>,
) {
    match msg {
        ServerMessage::ChannelList { channels } => {
            let _ = app_handle.emit("channel-list", &channels);
        }
        ServerMessage::UserList { channel_id, users } => {
            // Update the Rust-side channel tracking so commands (PTT, chat, etc.)
            // know which channel we're in. This handles server-initiated moves
            // (create_channel auto-join, kicks, invites, etc.)
            let old_ch = channel_id_store.swap(channel_id, Ordering::Relaxed);
            if old_ch != channel_id {
                // Clear media key — the new channel's key comes from an
                // existing member over Signal, or we generate one if alone
                // (see below, after the user list is known)
                {
                    let mut mk = media_key.lock().unwrap_or_else(|p| { warn!("mutex poisoned, recovering"); p.into_inner() });
                    *mk = None;
                }
                // Reset sender key state for the new channel
                {
                    let mut sig = signal.lock().unwrap_or_else(|p| { warn!("mutex poisoned, recovering"); p.into_inner() });
                    sig.sender_key_distributed.remove(&channel_id);
                    sig.sender_key_received.remove(&channel_id);
                    // Members already here → ask the first one we key up with for recent chat
                    sig.history_wanted_channel = if users.len() > 1 { channel_id } else { 0 };
                }
                info!(old_ch, channel_id, "channel changed via UserList");

                // Stop screen share and watching on channel change
                if screen_share_active.swap(false, Ordering::Relaxed) {
                    // Was sharing — tell server to stop
                    let _ = send_tcp_message(tcp_tx, &ClientMessage::StopScreenShare).await;
                    let _ = app_handle.emit("screen-share-force-stopped", ());
                    info!("screen share force-stopped due to channel change");
                }
                if watching_user_id_shared.swap(0, Ordering::Relaxed) != 0 {
                    let _ = send_tcp_message(tcp_tx, &ClientMessage::StopWatchingScreenShare).await;
                    let _ = app_handle.emit("screen-share-force-stopped", ());
                }
            }

            // Auto-request prekey bundles for users we don't have sessions with.
            // This must happen for ALL channels (including Channel 0) because
            // pairwise sessions are needed for DMs and pokes, not just channel chat.
            request_prekey_bundles_for_users(
                &users,
                own_user_id,
                signal,
                tcp_tx,
            )
            .await;

            // Media keys never touch the server: the first member of a
            // channel generates one; everyone else receives it from an
            // existing member over a pairwise Signal session
            // (distribute_sender_key_to_user → distribute_media_key_to_user).
            let alone = users.len() == 1 && users[0].user_id == own_user_id;
            if channel_id != 0 && alone {
                let have_key = media_key
                    .lock()
                    .map(|g| g.as_ref().is_some_and(|k| k.channel_id == channel_id))
                    .unwrap_or(false);
                if !have_key {
                    match MediaKey::generate(channel_id, 0) {
                        Ok(key) => {
                            install_media_key(media_key, key, app_handle);
                            info!(channel_id, "generated media key (first member)");
                        }
                        Err(e) => error!(channel_id, "media key generation failed: {}", e),
                    }
                }
            }

            let _ = app_handle.emit(
                "user-list",
                serde_json::json!({"channel_id": channel_id, "users": users}),
            );
        }
        ServerMessage::UserJoined { ref user } => {
            // Auto-request prekey bundle for new user (all channels, needed for DMs/pokes)
            if user.user_id != own_user_id {
                request_prekey_bundles_for_users(
                    &[user.clone()],
                    own_user_id,
                    signal,
                    tcp_tx,
                )
                .await;
            }

            let _ = app_handle.emit("user-joined", &user);
        }
        ServerMessage::UserLeft {
            user_id,
            channel_id,
        } => {
            // Clean up E2E state for departing user
            {
                let mut sig = signal.lock().unwrap_or_else(|p| { warn!("mutex poisoned, recovering"); p.into_inner() });
                sig.pending_sessions.remove(&user_id);
                sig.established_sessions.remove(&user_id);
                for set in sig.sender_key_distributed.values_mut() {
                    set.remove(&user_id);
                }
                for set in sig.sender_key_received.values_mut() {
                    set.remove(&user_id);
                }
            }

            let _ = app_handle.emit(
                "user-left",
                serde_json::json!({"user_id": user_id, "channel_id": channel_id}),
            );
        }
        ServerMessage::UserMuted { user_id, muted } => {
            let _ = app_handle.emit(
                "user-muted",
                serde_json::json!({"user_id": user_id, "muted": muted}),
            );
        }
        ServerMessage::UserDeafened { user_id, deafened } => {
            let _ = app_handle.emit(
                "user-deafened",
                serde_json::json!({"user_id": user_id, "deafened": deafened}),
            );
        }
        ServerMessage::Ping { timestamp } => {
            // Reply to server keepalive ping to prevent idle disconnect
            let _ = send_tcp_message(tcp_tx, &ClientMessage::Ping { timestamp }).await;
        }
        ServerMessage::Pong { timestamp: _ } => {
            // Displayed latency comes from the UDP keepalive RTT instead:
            // this Pong also answers our echo of the server's keepalive ping,
            // where the timestamp is the SERVER's clock — computing a "RTT"
            // from it yielded clock skew, not latency.
        }
        ServerMessage::ServerShutdown { reason } => {
            let _ = app_handle.emit(
                "connection-lost",
                serde_json::json!({"reason": format!("Server shutdown: {}", reason)}),
            );
        }
        ServerMessage::MovedToChannel { channel_id } => {
            info!("moved to channel {}", channel_id);
        }
        ServerMessage::ChannelCreated { channel } => {
            let _ = app_handle.emit("channel-created", &channel);
        }
        ServerMessage::ChannelDeleted { channel_id } => {
            let _ = app_handle.emit(
                "channel-deleted",
                serde_json::json!({"channel_id": channel_id}),
            );
        }
        ServerMessage::ChannelError { reason } => {
            let _ = app_handle.emit(
                "channel-error",
                serde_json::json!({"reason": reason}),
            );
        }
        ServerMessage::ChannelUpdated { channel } => {
            let _ = app_handle.emit("channel-updated", &channel);
        }
        ServerMessage::Kicked { channel_id, reason } => {
            let _ = app_handle.emit(
                "kicked",
                serde_json::json!({"channel_id": channel_id, "reason": reason}),
            );
        }
        ServerMessage::ChannelUsers { channel_id, users } => {
            let _ = app_handle.emit(
                "channel-users",
                serde_json::json!({"channel_id": channel_id, "users": users}),
            );
        }
        ServerMessage::InviteReceived {
            channel_id,
            channel_name,
            invited_by,
        } => {
            let _ = app_handle.emit(
                "invite-received",
                serde_json::json!({"channel_id": channel_id, "channel_name": channel_name, "invited_by": invited_by}),
            );
        }
        ServerMessage::InviteAccepted {
            channel_id,
            user_id,
        } => {
            let _ = app_handle.emit(
                "invite-accepted",
                serde_json::json!({"channel_id": channel_id, "user_id": user_id}),
            );
        }
        ServerMessage::InviteDeclined {
            channel_id,
            user_id,
        } => {
            let _ = app_handle.emit(
                "invite-declined",
                serde_json::json!({"channel_id": channel_id, "user_id": user_id}),
            );
        }
        ServerMessage::PokeReceived {
            from_user_id,
            from_username,
            ciphertext,
            message_type,
        } => {
            // Decrypt the poke message using Signal Protocol
            let message = {
                let result = tokio::task::block_in_place(|| {
                    let mut sig = signal.lock().map_err(|e| format!("signal lock: {e}"))?;
                    let stores = sig.stores.as_mut()
                        .ok_or_else(|| "Signal not initialized".to_string())?;
                    tokio::runtime::Handle::current()
                        .block_on(voipc_crypto::session::decrypt_message(
                            stores,
                            from_user_id,
                            &ciphertext,
                            message_type,
                        ))
                        .map_err(|e| format!("decrypt poke: {e}"))
                });
                match result {
                    Ok(plaintext) => {
                        // If PreKeySignalMessage, mark session as established
                        if message_type == 1 {
                            let mut sig = signal.lock().unwrap_or_else(|p| { warn!("mutex poisoned, recovering"); p.into_inner() });
                            sig.established_sessions.insert(from_user_id);
                            sig.pending_sessions.remove(&from_user_id);
                        }
                        String::from_utf8_lossy(&plaintext).to_string()
                    }
                    Err(e) => {
                        tracing::warn!(from_user_id, "failed to decrypt poke: {e}");
                        String::new()
                    }
                }
            };

            let _ = app_handle.emit(
                "poke-received",
                serde_json::json!({
                    "from_user_id": from_user_id,
                    "from_username": from_username,
                    "message": message,
                }),
            );

            // Also inject the poke as a DM so it appears in chat history
            if !message.is_empty() {
                let timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;
                let _ = app_handle.emit(
                    "direct-chat-message",
                    serde_json::json!({
                        "from_user_id": from_user_id,
                        "from_username": from_username,
                        "to_user_id": own_user_id,
                        "content": format!("[Poke] {}", message),
                        "timestamp": timestamp,
                    }),
                );
            }

            // Flash/blink the window to get user attention (desktop only)
            #[cfg(not(target_os = "android"))]
            if let Some(window) = app_handle.get_webview_window("main") {
                let _ = window.request_user_attention(
                    Some(tauri::UserAttentionType::Informational),
                );
            }
        }
        // ── Screenshare events ──
        ServerMessage::ScreenShareStarted {
            user_id,
            username,
            resolution,
        } => {
            let _ = app_handle.emit(
                "screenshare-started",
                serde_json::json!({"user_id": user_id, "username": username, "resolution": resolution}),
            );
        }
        ServerMessage::ScreenShareStopped { user_id } => {
            let _ = app_handle.emit(
                "screenshare-stopped",
                serde_json::json!({"user_id": user_id}),
            );
        }
        ServerMessage::WatchingScreenShare { sharer_user_id } => {
            let _ = app_handle.emit(
                "watching-screenshare",
                serde_json::json!({"sharer_user_id": sharer_user_id}),
            );
        }
        ServerMessage::StoppedWatchingScreenShare { reason } => {
            let _ = app_handle.emit(
                "stopped-watching-screenshare",
                serde_json::json!({"reason": reason}),
            );
        }
        ServerMessage::ViewerCountChanged { viewer_count } => {
            let _ = app_handle.emit(
                "viewer-count-changed",
                serde_json::json!({"viewer_count": viewer_count}),
            );
        }
        ServerMessage::KeyframeRequested => {
            let _ = app_handle.emit("keyframe-requested", ());
        }
        ServerMessage::ScreenShareError { reason } => {
            let _ = app_handle.emit(
                "screenshare-error",
                serde_json::json!({"reason": reason}),
            );
        }
        // ── E2E Encryption: PreKeyBundle → establish session + distribute sender keys ──
        ServerMessage::PreKeyBundle { user_id, bundle } => {
            handle_prekey_bundle(
                user_id,
                &bundle,
                own_user_id,
                signal,
                media_key,
                tcp_tx,
                channel_id_store,
            )
            .await;
        }
        ServerMessage::PreKeyBundleUnavailable { user_id } => {
            info!(user_id, "prekey bundle unavailable — cannot establish E2E session");
            // Remove from pending so we don't loop
            let mut sig = signal.lock().unwrap_or_else(|p| { warn!("mutex poisoned, recovering"); p.into_inner() });
            sig.pending_sessions.remove(&user_id);
        }
        ServerMessage::IdentityKeyChanged {
            user_id,
            new_identity_key,
        } => {
            let _ = app_handle.emit(
                "identity-key-changed",
                serde_json::json!({"user_id": user_id, "new_identity_key": new_identity_key}),
            );
        }
        // ── E2E: Encrypted direct message → decrypt and emit as plaintext ──
        ServerMessage::EncryptedDirectChatMessage {
            from_user_id,
            from_username,
            to_user_id,
            ciphertext,
            message_type,
            timestamp,
        } => {
            handle_encrypted_direct_message(
                from_user_id,
                &from_username,
                to_user_id,
                &ciphertext,
                message_type,
                timestamp,
                own_user_id,
                signal,
                app_handle,
            );
        }
        // ── E2E: Encrypted channel message → decrypt and emit as plaintext ──
        ServerMessage::EncryptedChannelChatMessage {
            channel_id,
            user_id,
            username,
            ciphertext,
            timestamp,
        } => {
            handle_encrypted_channel_message(
                channel_id,
                user_id,
                &username,
                &ciphertext,
                timestamp,
                signal,
                app_handle,
            );
        }
        // ── E2E: Sender key received → decrypt pairwise, process, reciprocate ──
        ServerMessage::SenderKeyReceived {
            channel_id,
            from_user_id,
            distribution_message,
            message_type,
        } => {
            handle_sender_key_received(
                channel_id,
                from_user_id,
                &distribution_message,
                message_type,
                own_user_id,
                signal,
                media_key,
                tcp_tx,
            )
            .await;
        }
        ServerMessage::MediaKeyReceived {
            channel_id,
            from_user_id,
            encrypted_media_key,
            message_type,
        } => {
            handle_media_key_received(
                channel_id,
                from_user_id,
                &encrypted_media_key,
                message_type,
                signal,
                media_key,
                channel_id_store,
                app_handle,
            )
            .await;
        }
        // ── Moderation ──
        ServerMessage::AdminStatus { user_id, is_admin } => {
            let _ = app_handle.emit(
                "admin-status",
                serde_json::json!({"user_id": user_id, "is_admin": is_admin}),
            );
        }
        ServerMessage::AdminError { reason } => {
            let _ = app_handle.emit("admin-error", serde_json::json!({"reason": reason}));
        }
        ServerMessage::AdminBans { bans } => {
            let _ = app_handle.emit("admin-bans", serde_json::json!({"bans": bans}));
        }
        ServerMessage::Disconnected { reason } => {
            // The server closes the socket next; the UI must not auto-reconnect
            info!("disconnected by server: {}", reason);
            let _ = app_handle.emit(
                "server-disconnected",
                serde_json::json!({"reason": reason}),
            );
        }
        // ── Channel history hand-off ──
        ServerMessage::ChannelHistoryRequested {
            channel_id,
            from_user_id,
        } => {
            let _ = app_handle.emit(
                "channel-history-requested",
                serde_json::json!({"channel_id": channel_id, "from_user_id": from_user_id}),
            );
        }
        ServerMessage::ChannelHistoryReceived {
            channel_id,
            from_user_id,
            from_username,
            ciphertext,
            message_type,
        } => {
            handle_channel_history_received(
                channel_id,
                from_user_id,
                &from_username,
                &ciphertext,
                message_type,
                signal,
                app_handle,
            );
        }
        ServerMessage::Authenticated { .. } | ServerMessage::AuthError { .. } => {}
    }
}

/// Decrypt a member's channel-history blob (JSON `{ v, messages }`) and hand
/// the messages to the UI, which validates and merges them.
fn handle_channel_history_received(
    channel_id: u32,
    from_user_id: u32,
    from_username: &str,
    ciphertext: &[u8],
    message_type: u8,
    signal: &Arc<std::sync::Mutex<SignalState>>,
    app_handle: &tauri::AppHandle,
) {
    let result = tokio::task::block_in_place(|| {
        let mut sig = signal.lock().map_err(|e| format!("signal lock: {e}"))?;
        let stores = sig
            .stores
            .as_mut()
            .ok_or_else(|| "Signal not initialized".to_string())?;
        tokio::runtime::Handle::current()
            .block_on(voipc_crypto::session::decrypt_message(
                stores,
                from_user_id,
                ciphertext,
                message_type,
            ))
            .map_err(|e| format!("decrypt history: {e}"))
    });
    let plaintext = match result {
        Ok(p) => p,
        Err(e) => {
            warn!(from_user_id, channel_id, "channel history rejected: {}", e);
            return;
        }
    };
    if message_type == 1 {
        let mut sig = signal.lock().unwrap_or_else(|p| { warn!("mutex poisoned, recovering"); p.into_inner() });
        sig.established_sessions.insert(from_user_id);
        sig.pending_sessions.remove(&from_user_id);
    }
    let messages = match serde_json::from_slice::<serde_json::Value>(&plaintext) {
        Ok(serde_json::Value::Object(mut map)) => match map.remove("messages") {
            Some(serde_json::Value::Array(list)) => list,
            _ => return,
        },
        _ => {
            warn!(from_user_id, channel_id, "channel history: malformed payload");
            return;
        }
    };
    let _ = app_handle.emit(
        "channel-history-received",
        serde_json::json!({
            "channel_id": channel_id,
            "from_user_id": from_user_id,
            "from_username": from_username,
            "messages": messages,
        }),
    );
}

// ── E2E Helper functions ─────────────────────────────────────────────────

/// Request prekey bundles for users we don't yet have sessions with.
async fn request_prekey_bundles_for_users(
    users: &[UserInfo],
    own_user_id: u32,
    signal: &Arc<std::sync::Mutex<SignalState>>,
    tcp_tx: &mpsc::Sender<Vec<u8>>,
) {
    let mut to_request = Vec::new();

    {
        let mut sig = signal.lock().unwrap_or_else(|p| { warn!("mutex poisoned, recovering"); p.into_inner() });
        if !sig.initialized {
            return;
        }
        for user in users {
            if user.user_id == own_user_id {
                continue;
            }
            if sig.established_sessions.contains(&user.user_id) {
                continue;
            }
            if sig.pending_sessions.contains(&user.user_id) {
                continue;
            }
            sig.pending_sessions.insert(user.user_id);
            to_request.push(user.user_id);
        }
    }

    for uid in to_request {
        info!(target_user_id = uid, "requesting prekey bundle for E2E session");
        let msg = ClientMessage::RequestPreKeyBundle {
            target_user_id: uid,
        };
        if let Err(e) = send_tcp_message(tcp_tx, &msg).await {
            warn!(uid, "failed to request prekey bundle: {}", e);
        }
    }
}

/// Handle a PreKeyBundle response: establish pairwise session, then distribute
/// our sender key for the current channel.
async fn handle_prekey_bundle(
    remote_user_id: u32,
    bundle: &PreKeyBundleData,
    own_user_id: u32,
    signal: &Arc<std::sync::Mutex<SignalState>>,
    media_key: &Arc<std::sync::Mutex<Option<MediaKey>>>,
    tcp_tx: &mpsc::Sender<Vec<u8>>,
    channel_id_store: &Arc<AtomicU32>,
) {
    // Extract one-time prekey if available
    let (otp_id, otp_bytes): (Option<u32>, Option<Vec<u8>>) = if let Some(otp) = bundle.prekeys.first() {
        (Some(otp.id), Some(otp.public_key.clone()))
    } else {
        (None, None)
    };

    // Establish the pairwise session using block_in_place for !Send futures
    let session_result = tokio::task::block_in_place(|| {
        let mut sig = signal.lock().map_err(|e| format!("signal lock: {e}"))?;
        let stores = sig
            .stores
            .as_mut()
            .ok_or_else(|| "Signal not initialized".to_string())?;

        tokio::runtime::Handle::current().block_on(voipc_crypto::session::establish_session(
            stores,
            remote_user_id,
            bundle.registration_id,
            bundle.device_id,
            &bundle.identity_key,
            bundle.signed_prekey_id,
            &bundle.signed_prekey,
            &bundle.signed_prekey_signature,
            otp_id,
            otp_bytes.as_deref(),
        ))
        .map_err(|e| format!("establish_session failed: {e}"))
    });

    match session_result {
        Ok(()) => {
            info!(remote_user_id, "E2E session established");
            {
                let mut sig = signal.lock().unwrap_or_else(|p| { warn!("mutex poisoned, recovering"); p.into_inner() });
                sig.pending_sessions.remove(&remote_user_id);
                sig.established_sessions.insert(remote_user_id);
            }

            // Drain any pending direct messages for this user
            drain_pending_dms(remote_user_id, own_user_id, signal, tcp_tx).await;

            // Distribute our sender key (and the channel media key) for the current channel
            let current_channel = channel_id_store.load(Ordering::Relaxed);
            if current_channel != 0 {
                distribute_sender_key_to_user(
                    current_channel,
                    remote_user_id,
                    own_user_id,
                    signal,
                    media_key,
                    tcp_tx,
                )
                .await;
            }
        }
        Err(e) => {
            warn!(remote_user_id, "failed to establish E2E session: {}", e);
            let mut sig = signal.lock().unwrap_or_else(|p| { warn!("mutex poisoned, recovering"); p.into_inner() });
            sig.pending_sessions.remove(&remote_user_id);
        }
    }
}

/// Create our sender key distribution message for a channel, encrypt it pairwise,
/// and send it to a specific user. On success also hands them the channel's
/// media key (if we hold one) over the same pairwise session.
async fn distribute_sender_key_to_user(
    channel_id: u32,
    target_user_id: u32,
    own_user_id: u32,
    signal: &Arc<std::sync::Mutex<SignalState>>,
    media_key: &Arc<std::sync::Mutex<Option<MediaKey>>>,
    tcp_tx: &mpsc::Sender<Vec<u8>>,
) {
    let result = tokio::task::block_in_place(|| {
        let mut sig = signal.lock().map_err(|e| format!("signal lock: {e}"))?;
        let stores = sig
            .stores
            .as_mut()
            .ok_or_else(|| "Signal not initialized".to_string())?;
        let handle = tokio::runtime::Handle::current();

        // Create the sender key distribution message
        let dist_msg = handle
            .block_on(voipc_crypto::group::create_distribution_message(
                stores,
                own_user_id,
                channel_id,
            ))
            .map_err(|e| format!("create_distribution_message: {e}"))?;

        // Encrypt it pairwise for the target user
        let (ciphertext, msg_type) = handle
            .block_on(voipc_crypto::session::encrypt_message(
                stores,
                target_user_id,
                &dist_msg,
            ))
            .map_err(|e| format!("encrypt sender key: {e}"))?;

        Ok::<_, String>((ciphertext, msg_type))
    });

    match result {
        Ok((ciphertext, msg_type)) => {
            let msg = ClientMessage::DistributeSenderKey {
                channel_id,
                target_user_id,
                distribution_message: ciphertext,
                message_type: msg_type,
            };
            if let Err(e) = send_tcp_message(tcp_tx, &msg).await {
                warn!(target_user_id, "failed to send sender key: {}", e);
            } else {
                info!(target_user_id, channel_id, "sender key distributed");
                distribute_media_key_to_user(channel_id, target_user_id, signal, media_key, tcp_tx)
                    .await;
                let mut sig = signal.lock().unwrap_or_else(|p| { warn!("mutex poisoned, recovering"); p.into_inner() });
                sig.sender_key_distributed
                    .entry(channel_id)
                    .or_default()
                    .insert(target_user_id);
            }
        }
        Err(e) => {
            warn!(target_user_id, channel_id, "failed to distribute sender key: {}", e);
        }
    }
}

/// Store a media key for voice/video and tell the UI (clears any
/// "waiting for media key" warning).
fn install_media_key(
    media_key: &Arc<std::sync::Mutex<Option<MediaKey>>>,
    key: MediaKey,
    app_handle: &tauri::AppHandle,
) {
    let (channel_id, key_id) = (key.channel_id, key.key_id);
    let mut guard = media_key.lock().unwrap_or_else(|p| {
        warn!("media key mutex poisoned — recovering");
        p.into_inner()
    });
    *guard = Some(key);
    drop(guard);
    let _ = app_handle.emit(
        "media-key-installed",
        serde_json::json!({"channel_id": channel_id, "key_id": key_id}),
    );
}

/// Encrypt our current media key for `channel_id` with the pairwise session
/// to `target_user_id` and send it. Silently does nothing if we hold no key
/// for that channel (then we are waiting for one ourselves).
async fn distribute_media_key_to_user(
    channel_id: u32,
    target_user_id: u32,
    signal: &Arc<std::sync::Mutex<SignalState>>,
    media_key: &Arc<std::sync::Mutex<Option<MediaKey>>>,
    tcp_tx: &mpsc::Sender<Vec<u8>>,
) {
    let key_bytes = {
        let guard = media_key.lock().unwrap_or_else(|p| {
            warn!("media key mutex poisoned — recovering");
            p.into_inner()
        });
        match guard.as_ref() {
            Some(k) if k.channel_id == channel_id => k.to_bytes(),
            _ => return,
        }
    };

    let result = tokio::task::block_in_place(|| {
        let mut sig = signal.lock().map_err(|e| format!("signal lock: {e}"))?;
        let stores = sig
            .stores
            .as_mut()
            .ok_or_else(|| "Signal not initialized".to_string())?;
        tokio::runtime::Handle::current()
            .block_on(voipc_crypto::session::encrypt_message(
                stores,
                target_user_id,
                &key_bytes,
            ))
            .map_err(|e| format!("encrypt media key: {e}"))
    });

    match result {
        Ok((encrypted_media_key, message_type)) => {
            let msg = ClientMessage::DistributeMediaKey {
                channel_id,
                target_user_id,
                encrypted_media_key,
                message_type,
            };
            match send_tcp_message(tcp_tx, &msg).await {
                Ok(()) => info!(target_user_id, channel_id, "media key distributed"),
                Err(e) => warn!(target_user_id, "failed to send media key: {}", e),
            }
        }
        Err(e) => warn!(target_user_id, channel_id, "failed to distribute media key: {}", e),
    }
}

/// Decrypt a media key sent by a channel member and install it if it is for
/// our current channel and not older than what we already hold.
async fn handle_media_key_received(
    channel_id: u32,
    from_user_id: u32,
    ciphertext: &[u8],
    message_type: u8,
    signal: &Arc<std::sync::Mutex<SignalState>>,
    media_key: &Arc<std::sync::Mutex<Option<MediaKey>>>,
    channel_id_store: &Arc<AtomicU32>,
    app_handle: &tauri::AppHandle,
) {
    let result = tokio::task::block_in_place(|| {
        let mut sig = signal.lock().map_err(|e| format!("signal lock: {e}"))?;
        let stores = sig
            .stores
            .as_mut()
            .ok_or_else(|| "Signal not initialized".to_string())?;
        let plaintext = tokio::runtime::Handle::current()
            .block_on(voipc_crypto::session::decrypt_message(
                stores,
                from_user_id,
                ciphertext,
                message_type,
            ))
            .map_err(|e| format!("decrypt media key: {e}"))?;
        MediaKey::from_bytes(&plaintext).map_err(|e| format!("parse media key: {e}"))
    });

    let key = match result {
        Ok(k) => k,
        Err(e) => {
            warn!(from_user_id, channel_id, "media key rejected: {}", e);
            return;
        }
    };

    // A PreKeySignalMessage establishes the session on our side as well
    if message_type == 1 {
        let mut sig = signal.lock().unwrap_or_else(|p| { warn!("mutex poisoned, recovering"); p.into_inner() });
        sig.established_sessions.insert(from_user_id);
        sig.pending_sessions.remove(&from_user_id);
    }

    let current = channel_id_store.load(Ordering::Relaxed);
    if key.channel_id != channel_id || channel_id != current {
        info!(from_user_id, channel_id, current, "ignoring media key for another channel");
        return;
    }
    let newer = media_key
        .lock()
        .map(|g| g.as_ref().map_or(true, |k| k.channel_id != channel_id || key.key_id >= k.key_id))
        .unwrap_or(true);
    if newer {
        let key_id = key.key_id;
        install_media_key(media_key, key, app_handle);
        info!(from_user_id, channel_id, key_id, "media key installed");
    }
}

/// Handle a received sender key: decrypt pairwise, process distribution message,
/// and reciprocate by sending our own sender key if needed.
async fn handle_sender_key_received(
    channel_id: u32,
    from_user_id: u32,
    ciphertext: &[u8],
    message_type: u8,
    own_user_id: u32,
    signal: &Arc<std::sync::Mutex<SignalState>>,
    media_key: &Arc<std::sync::Mutex<Option<MediaKey>>>,
    tcp_tx: &mpsc::Sender<Vec<u8>>,
) {
    let result = tokio::task::block_in_place(|| {
        let mut sig = signal.lock().map_err(|e| format!("signal lock: {e}"))?;
        let stores = sig
            .stores
            .as_mut()
            .ok_or_else(|| "Signal not initialized".to_string())?;
        let handle = tokio::runtime::Handle::current();

        // Decrypt the pairwise-encrypted sender key blob
        let plaintext = handle
            .block_on(voipc_crypto::session::decrypt_message(
                stores,
                from_user_id,
                ciphertext,
                message_type,
            ))
            .map_err(|e| format!("decrypt sender key: {e}"))?;

        // Process the sender key distribution message
        handle
            .block_on(voipc_crypto::group::process_distribution_message(
                stores,
                from_user_id,
                channel_id,
                &plaintext,
            ))
            .map_err(|e| format!("process distribution message: {e}"))?;

        Ok::<_, String>(())
    });

    match result {
        Ok(()) => {
            info!(from_user_id, channel_id, "sender key received and processed");

            // If PreKeySignalMessage, session was auto-established on our side
            if message_type == 1 {
                let mut sig = signal.lock().unwrap_or_else(|p| { warn!("mutex poisoned, recovering"); p.into_inner() });
                sig.established_sessions.insert(from_user_id);
                sig.pending_sessions.remove(&from_user_id);
            }

            // Track the received sender key
            {
                let mut sig = signal.lock().unwrap_or_else(|p| { warn!("mutex poisoned, recovering"); p.into_inner() });
                sig.sender_key_received
                    .entry(channel_id)
                    .or_default()
                    .insert(from_user_id);
            }

            // Reciprocate: send our sender key if we haven't already
            let need_reciprocate = {
                let sig = signal.lock().unwrap_or_else(|p| { warn!("mutex poisoned, recovering"); p.into_inner() });
                !sig.sender_key_distributed
                    .get(&channel_id)
                    .map_or(false, |s| s.contains(&from_user_id))
            };

            if need_reciprocate {
                distribute_sender_key_to_user(
                    channel_id,
                    from_user_id,
                    own_user_id,
                    signal,
                    media_key,
                    tcp_tx,
                )
                .await;
            }

            // Drain any pending channel messages now that we have sender keys
            drain_pending_channel_messages(channel_id, own_user_id, signal, tcp_tx).await;

            // Newcomer: the first member whose sender key arrives holds a
            // pairwise session with us (they just used it), so ask them for
            // recent chat. Once per channel entry.
            let ask = {
                let mut sig = signal.lock().unwrap_or_else(|p| { warn!("mutex poisoned, recovering"); p.into_inner() });
                if channel_id != 0 && sig.history_wanted_channel == channel_id {
                    sig.history_wanted_channel = 0;
                    true
                } else {
                    false
                }
            };
            if ask {
                let _ = send_tcp_message(
                    tcp_tx,
                    &ClientMessage::RequestChannelHistory {
                        channel_id,
                        target_user_id: from_user_id,
                    },
                )
                .await;
            }
        }
        Err(e) => {
            warn!(from_user_id, channel_id, "failed to process sender key: {}", e);
        }
    }
}

/// Drain and send pending direct messages for a specific user whose session was just established.
async fn drain_pending_dms(
    target_user_id: u32,
    _own_user_id: u32,
    signal: &Arc<std::sync::Mutex<SignalState>>,
    tcp_tx: &mpsc::Sender<Vec<u8>>,
) {
    // Extract pending DMs for this target
    let pending: Vec<String> = {
        let mut sig = signal.lock().unwrap_or_else(|p| { warn!("mutex poisoned, recovering"); p.into_inner() });
        let mut remaining = Vec::new();
        let mut to_send = Vec::new();
        let mut expired = 0u32;
        for msg in sig.pending_messages.drain(..) {
            match &msg.target {
                PendingTarget::Direct { target_user_id: tid } if *tid == target_user_id => {
                    // Only send if queued less than 60 seconds ago
                    if msg.queued_at.elapsed().as_secs() < 60 {
                        to_send.push(msg.content);
                    } else {
                        expired += 1;
                    }
                }
                _ => remaining.push(msg),
            }
        }
        if expired > 0 {
            warn!(target_user_id, expired, "dropped expired pending DMs");
        }
        sig.pending_messages = remaining;
        to_send
    };

    for content in pending {
        let result = tokio::task::block_in_place(|| {
            let mut sig = signal.lock().map_err(|e| format!("lock: {e}"))?;
            let stores = sig.stores.as_mut().ok_or("not initialized")?;
            tokio::runtime::Handle::current()
                .block_on(voipc_crypto::session::encrypt_message(
                    stores,
                    target_user_id,
                    content.as_bytes(),
                ))
                .map_err(|e| format!("encrypt: {e}"))
        });

        match result {
            Ok((ciphertext, message_type)) => {
                let msg = ClientMessage::SendEncryptedDirectMessage {
                    target_user_id,
                    ciphertext,
                    message_type,
                };
                if let Err(e) = send_tcp_message(tcp_tx, &msg).await {
                    warn!(target_user_id, "failed to send queued DM: {}", e);
                } else {
                    info!(target_user_id, "sent queued DM");
                }
            }
            Err(e) => {
                warn!(target_user_id, "failed to encrypt queued DM: {}", e);
            }
        }
    }
}

/// Drain and send pending channel messages for a channel whose sender keys are now ready.
async fn drain_pending_channel_messages(
    channel_id: u32,
    own_user_id: u32,
    signal: &Arc<std::sync::Mutex<SignalState>>,
    tcp_tx: &mpsc::Sender<Vec<u8>>,
) {
    // Extract pending channel messages
    let pending: Vec<String> = {
        let mut sig = signal.lock().unwrap_or_else(|p| { warn!("mutex poisoned, recovering"); p.into_inner() });
        let mut remaining = Vec::new();
        let mut to_send = Vec::new();
        let mut expired = 0u32;
        for msg in sig.pending_messages.drain(..) {
            match &msg.target {
                PendingTarget::Channel { channel_id: cid } if *cid == channel_id => {
                    if msg.queued_at.elapsed().as_secs() < 60 {
                        to_send.push(msg.content);
                    } else {
                        expired += 1;
                    }
                }
                _ => remaining.push(msg),
            }
        }
        if expired > 0 {
            warn!(channel_id, expired, "dropped expired pending channel messages");
        }
        sig.pending_messages = remaining;
        to_send
    };

    for content in pending {
        let result = tokio::task::block_in_place(|| {
            let mut sig = signal.lock().map_err(|e| format!("lock: {e}"))?;
            let stores = sig.stores.as_mut().ok_or("not initialized")?;
            tokio::runtime::Handle::current()
                .block_on(voipc_crypto::group::encrypt_group_message(
                    stores,
                    own_user_id,
                    channel_id,
                    content.as_bytes(),
                ))
                .map_err(|e| format!("group encrypt: {e}"))
        });

        match result {
            Ok(ciphertext) => {
                let msg = ClientMessage::SendEncryptedChannelMessage { ciphertext };
                if let Err(e) = send_tcp_message(tcp_tx, &msg).await {
                    warn!(channel_id, "failed to send queued channel msg: {}", e);
                } else {
                    info!(channel_id, "sent queued channel message");
                }
            }
            Err(e) => {
                warn!(channel_id, "failed to encrypt queued channel msg: {}", e);
            }
        }
    }
}

/// Decrypt an encrypted direct message and emit it as a plaintext event to the frontend.
/// Note: Server echoes encrypted DMs back to the sender, but the sender cannot decrypt
/// their own ciphertext (ratchet has advanced). We skip those — the sender emits locally.
fn handle_encrypted_direct_message(
    from_user_id: u32,
    from_username: &str,
    to_user_id: u32,
    ciphertext: &[u8],
    message_type: u8,
    timestamp: u64,
    own_user_id: u32,
    signal: &Arc<std::sync::Mutex<SignalState>>,
    app_handle: &tauri::AppHandle,
) {
    // Skip our own echoed messages — the sender emits locally in commands.rs.
    // Attempting to decrypt would corrupt the Signal ratchet state.
    if from_user_id == own_user_id {
        return;
    }

    let result = tokio::task::block_in_place(|| {
        let mut sig = signal.lock().map_err(|e| format!("signal lock: {e}"))?;
        let stores = sig
            .stores
            .as_mut()
            .ok_or_else(|| "Signal not initialized".to_string())?;

        tokio::runtime::Handle::current()
            .block_on(voipc_crypto::session::decrypt_message(
                stores,
                from_user_id,
                ciphertext,
                message_type,
            ))
            .map_err(|e| format!("decrypt DM: {e}"))
    });

    match result {
        Ok(plaintext) => {
            let content = String::from_utf8_lossy(&plaintext);

            // If this was a PreKeySignalMessage, mark session as established
            if message_type == 1 {
                let mut sig = signal.lock().unwrap_or_else(|p| { warn!("mutex poisoned, recovering"); p.into_inner() });
                sig.established_sessions.insert(from_user_id);
                sig.pending_sessions.remove(&from_user_id);
            }

            // Emit as a regular plaintext DM event — frontend is unchanged
            let _ = app_handle.emit(
                "direct-chat-message",
                serde_json::json!({
                    "from_user_id": from_user_id,
                    "from_username": from_username,
                    "to_user_id": to_user_id,
                    "content": content,
                    "timestamp": timestamp,
                    "encrypted": true,
                }),
            );

            // Flash/blink the window like a poke does (desktop only)
            #[cfg(not(target_os = "android"))]
            if let Some(window) = app_handle.get_webview_window("main") {
                let _ = window.request_user_attention(
                    Some(tauri::UserAttentionType::Informational),
                );
            }
        }
        Err(e) => {
            warn!(from_user_id, "failed to decrypt direct message: {}", e);
            let _ = app_handle.emit(
                "direct-chat-message",
                serde_json::json!({
                    "from_user_id": from_user_id,
                    "from_username": from_username,
                    "to_user_id": to_user_id,
                    "content": "[encrypted message — decryption failed]",
                    "timestamp": timestamp,
                    "encrypted": true,
                    "decryption_failed": true,
                }),
            );
        }
    }
}

/// Decrypt an encrypted channel message and emit it as a plaintext event to the frontend.
fn handle_encrypted_channel_message(
    channel_id: u32,
    user_id: u32,
    username: &str,
    ciphertext: &[u8],
    timestamp: u64,
    signal: &Arc<std::sync::Mutex<SignalState>>,
    app_handle: &tauri::AppHandle,
) {
    let result = tokio::task::block_in_place(|| {
        let mut sig = signal.lock().map_err(|e| format!("signal lock: {e}"))?;
        let stores = sig
            .stores
            .as_mut()
            .ok_or_else(|| "Signal not initialized".to_string())?;

        tokio::runtime::Handle::current()
            .block_on(voipc_crypto::group::decrypt_group_message(
                stores,
                user_id,
                channel_id,
                ciphertext,
            ))
            .map_err(|e| format!("decrypt channel msg: {e}"))
    });

    match result {
        Ok(plaintext) => {
            let content = String::from_utf8_lossy(&plaintext);
            let _ = app_handle.emit(
                "channel-chat-message",
                serde_json::json!({
                    "channel_id": channel_id,
                    "user_id": user_id,
                    "username": username,
                    "content": content,
                    "timestamp": timestamp,
                    "encrypted": true,
                }),
            );
        }
        Err(e) => {
            warn!(user_id, channel_id, "failed to decrypt channel message: {}", e);
            let _ = app_handle.emit(
                "channel-chat-message",
                serde_json::json!({
                    "channel_id": channel_id,
                    "user_id": user_id,
                    "username": username,
                    "content": "[encrypted message — decryption failed]",
                    "timestamp": timestamp,
                    "encrypted": true,
                    "decryption_failed": true,
                }),
            );
        }
    }
}

/// UDP sender task: sends voice packets from the channel to the server.
async fn udp_sender_task(
    socket: Arc<UdpSocket>,
    mut rx: mpsc::Receiver<Vec<u8>>,
    server_addr: std::net::SocketAddr,
) {
    while let Some(data) = rx.recv().await {
        if let Err(e) = socket.send_to(&data, server_addr).await {
            error!("UDP send error: {}", e);
        }
    }
}

/// UDP receiver task: receives voice and video packets, decrypting if encrypted.
/// One remote audio stream feeding the mixer: voice per session, or a
/// screen-share audio stream (keyed with [`SCREEN_AUDIO_FLAG`] set).
struct MixSource {
    jitter: voipc_audio::jitter::JitterBuffer,
    decoder: voipc_audio::decoder::Decoder,
    /// EndOfTransmission seen — the mixer resets the jitter buffer once the
    /// buffered tail has fully drained (an immediate reset would clip it).
    eot_received: bool,
    last_activity: std::time::Instant,
}

impl MixSource {
    fn new() -> anyhow::Result<Self> {
        Ok(Self {
            jitter: voipc_audio::jitter::JitterBuffer::new(2),
            decoder: voipc_audio::decoder::Decoder::new()?,
            eot_received: false,
            last_activity: std::time::Instant::now(),
        })
    }
}

/// Set on the key of screen-share audio sources (session_ids are small counters).
const SCREEN_AUDIO_FLAG: u32 = 0x8000_0000;
/// Sources with no packets for this long are dropped (also covers user leave).
const SOURCE_IDLE_PRUNE: std::time::Duration = std::time::Duration::from_secs(60);

type MixSources = Arc<std::sync::Mutex<HashMap<u32, MixSource>>>;

/// Milliseconds since the Unix epoch, truncated to u32 — used as the ping
/// sequence so the server's Pong echo yields a real UDP RTT.
fn now_millis_u32() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u32
}

/// Milliseconds since the Unix epoch as u64 (for the UDP-dead watchdog).
fn now_millis_u64() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// No Pong for this long (3 missed 10s keepalives + margin) = UDP path dead.
const UDP_DEAD_AFTER_MS: u64 = 35_000;

/// Periodic UDP ping: keeps the NAT mapping alive through silent channels
/// (mappings commonly expire after ~30s) and measures media-path RTT.
/// Doubles as a dead-UDP watchdog: if Pongs stop while TCP stays up, the
/// user is silently mute/deaf — emit `udp-dead` / `udp-restored` so the UI
/// can say so.
async fn udp_keepalive_task(
    socket: Arc<UdpSocket>,
    server_addr: std::net::SocketAddr,
    session_id: u32,
    udp_token: u64,
    last_pong: Arc<AtomicU64>,
    app_handle: tauri::AppHandle,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Baseline for the watchdog before the first Pong arrives
    let started = now_millis_u64();
    let mut udp_dead = false;
    loop {
        interval.tick().await;
        let ping = VoicePacket::ping(session_id, udp_token, now_millis_u32());
        if let Err(e) = socket.send_to(&ping.to_bytes(), server_addr).await {
            warn!("UDP keepalive send failed: {}", e);
        }

        let last = last_pong.load(Ordering::Relaxed).max(started);
        let stale = now_millis_u64().saturating_sub(last) > UDP_DEAD_AFTER_MS;
        if stale && !udp_dead {
            udp_dead = true;
            warn!("no UDP Pong for {}ms — media path considered dead", UDP_DEAD_AFTER_MS);
            let _ = app_handle.emit("udp-dead", ());
        } else if !stale && udp_dead {
            udp_dead = false;
            info!("UDP Pongs resumed — media path restored");
            let _ = app_handle.emit("udp-restored", ());
        }
    }
}

/// Clocked voice mixer: every 20ms, pop one frame per active source, decode
/// (FEC/PLC on loss), sum with per-user and master gain, and push the mixed
/// frame to the playback ring. Owns the playback stream and rebuilds it when
/// `playback_restart` is set (device error or output device change).
#[allow(clippy::too_many_arguments)]
#[allow(unused_assignments)] // playback_stream is a hold-to-keep-alive handle
async fn voice_mixer_task(
    sources: MixSources,
    mut playback_stream: Option<voipc_audio::playback::PlaybackStream>,
    mut producer: Option<ringbuf::HeapProd<f32>>,
    playback_restart: Arc<AtomicBool>,
    output_device_live: Arc<std::sync::Mutex<Option<String>>>,
    is_deafened: Arc<AtomicBool>,
    user_volumes: Arc<std::sync::Mutex<HashMap<u32, f32>>>,
    master_volume: Arc<AtomicU32>,
    voice_frames_played: Arc<AtomicU32>,
    voice_frames_lost: Arc<AtomicU32>,
    app_handle: tauri::AppHandle,
) {
    use ringbuf::traits::Observer;
    use voipc_audio::jitter::JitterFrame;

    let mut interval = tokio::time::interval(std::time::Duration::from_millis(20));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    // Resampler for output devices that can't run 48kHz
    let mut out_rate = playback_stream.as_ref().map_or(48_000, |s| s.sample_rate());
    let mut resampler = (out_rate != 48_000)
        .then(|| voipc_audio::resample::LinearResampler::new(48_000, out_rate));
    let mut last_restart_attempt: Option<std::time::Instant> = None;
    let mut error_emitted = false;
    let mut frames: Vec<(u32, Vec<f32>)> = Vec::new();
    let mut resampled: Vec<f32> = Vec::new();

    loop {
        interval.tick().await;

        // Rebuild the playback stream if the device died or was switched
        if playback_restart.swap(false, Ordering::Relaxed) {
            if last_restart_attempt.is_some_and(|t| t.elapsed() < std::time::Duration::from_secs(1)) {
                playback_restart.store(true, Ordering::Relaxed); // retry later
            } else {
                last_restart_attempt = Some(std::time::Instant::now());
                let device_name = output_device_live
                    .lock()
                    .map(|d| d.clone())
                    .unwrap_or_default();
                // Drop the old stream before opening the device again
                playback_stream = None;
                producer = None;
                match voipc_audio::playback::start_playback(
                    device_name.as_deref(),
                    playback_restart.clone(),
                ) {
                    Ok((stream, prod)) => {
                        out_rate = stream.sample_rate();
                        resampler = (out_rate != 48_000).then(|| {
                            voipc_audio::resample::LinearResampler::new(48_000, out_rate)
                        });
                        playback_stream = Some(stream);
                        producer = Some(prod);
                        info!("playback stream (re)started at {}Hz", out_rate);
                        if error_emitted {
                            error_emitted = false;
                            let _ = app_handle.emit("audio-device-restored", ());
                        }
                    }
                    Err(e) => {
                        warn!("playback restart failed (retrying): {}", e);
                        if !error_emitted {
                            error_emitted = true;
                            let _ = app_handle.emit(
                                "audio-device-error",
                                serde_json::json!({"error": e.to_string()}),
                            );
                        }
                        playback_restart.store(true, Ordering::Relaxed);
                    }
                }
            }
        }

        // Backpressure: if the ring already holds >3 frames, skip this tick
        // (caps clock drift between our timer and the device clock)
        let frame_out = (out_rate as usize * 20) / 1000;
        if let Some(p) = producer.as_ref() {
            if p.occupied_len() > 3 * frame_out {
                continue;
            }
        }

        // Pull + decode one frame per source
        frames.clear();
        {
            let mut map = match sources.lock() {
                Ok(m) => m,
                Err(poisoned) => poisoned.into_inner(),
            };
            map.retain(|_, s| s.last_activity.elapsed() < SOURCE_IDLE_PRUNE);
            for (&key, src) in map.iter_mut() {
                if src.eot_received && src.jitter.is_empty() {
                    src.jitter.reset();
                    src.eot_received = false;
                    continue;
                }
                let MixSource { jitter, decoder, .. } = src;
                let pcm = match jitter.pop() {
                    None => continue, // buffering or idle
                    Some(JitterFrame::Ready(data)) => {
                        voice_frames_played.fetch_add(1, Ordering::Relaxed);
                        decoder.decode(&data)
                    }
                    Some(JitterFrame::Lost) => {
                        voice_frames_lost.fetch_add(1, Ordering::Relaxed);
                        match jitter.peek_next() {
                            // The next packet carries in-band FEC for the lost frame
                            Some(next) => decoder.decode_fec(next),
                            None => decoder.decode_lost(),
                        }
                    }
                };
                match pcm {
                    Ok(pcm) => frames.push((key, pcm)),
                    Err(e) => warn!("Opus decode error from source {:#x}: {}", key, e),
                }
            }
        }

        if frames.is_empty() || is_deafened.load(Ordering::Relaxed) {
            continue; // ring drains to silence; decode above kept Opus state
        }

        // Mix with per-user gain × master volume
        let master = f32::from_bits(master_volume.load(Ordering::Relaxed));
        let mixed = {
            let volumes = user_volumes
                .lock()
                .map(|v| v.clone())
                .unwrap_or_default();
            let weighted: Vec<(&[f32], f32)> = frames
                .iter()
                .map(|(key, pcm)| {
                    let vol = volumes
                        .get(&(key & !SCREEN_AUDIO_FLAG))
                        .copied()
                        .unwrap_or(1.0);
                    (pcm.as_slice(), vol * master)
                })
                .collect();
            voipc_audio::mixer::mix_streams_weighted(&weighted)
        };

        if let Some(p) = producer.as_mut() {
            match resampler.as_mut() {
                Some(r) => {
                    resampled.clear();
                    r.process(&mixed, &mut resampled);
                    let _ = p.push_slice(&resampled);
                }
                None => {
                    let _ = p.push_slice(&mixed);
                }
            }
        }
    }
}

async fn udp_receiver_task(
    socket: Arc<UdpSocket>,
    server_addr: std::net::SocketAddr,
    app_handle: tauri::AppHandle,
    _own_session_id: SessionId,
    sources: MixSources,
    video_decode_tx: mpsc::Sender<(Vec<u8>, bool)>,
    screen_audio_recv_count: Arc<AtomicU32>,
    media_key: Arc<std::sync::Mutex<Option<MediaKey>>>,
    channel_id: Arc<AtomicU32>,
    screen_video_frames_received: Arc<AtomicU32>,
    screen_video_frames_dropped: Arc<AtomicU32>,
    screen_video_bytes_received: Arc<AtomicU64>,
    tcp_tx: mpsc::Sender<Vec<u8>>,
    watching_user_id: Arc<AtomicU32>,
    needs_keyframe: Arc<AtomicBool>,
    last_pong: Arc<AtomicU64>,
) {
    let mut video_assembler = FrameAssembler::new();
    let mut current_video_session: Option<u32> = None;
    let mut buf = vec![0u8; 2048];
    let mut last_keyframe_request = std::time::Instant::now() - std::time::Duration::from_secs(10);

    let mut recv_count: u64 = 0;
    let mut recv_errors: u32 = 0;
    let mut foreign_src_logged = false;
    // Track last voice packet time per user for speaking timeout
    let mut last_voice_time: HashMap<u32, std::time::Instant> = HashMap::new();
    let mut speaking_timeout = tokio::time::interval(std::time::Duration::from_millis(300));
    speaking_timeout.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    const SPEAKING_TIMEOUT_MS: u128 = 500;

    loop {
        tokio::select! {
            result = socket.recv_from(&mut buf) => {
        match result {
            Ok((n, src_addr)) => {
                recv_errors = 0;
                // The socket is unconnected: anyone who learns our endpoint
                // (LAN, full-cone NAT) could otherwise inject packets or
                // spoof Pongs. Only the server is a valid source.
                if src_addr != server_addr {
                    if !foreign_src_logged {
                        foreign_src_logged = true;
                        warn!("ignoring UDP from {} (server is {})", src_addr, server_addr);
                    }
                    continue;
                }
                if n == 0 {
                    continue;
                }
                recv_count += 1;
                let packet_type = buf[0];

                // Log first packet to confirm UDP reception is working
                if recv_count == 1 {
                    info!(
                        "UDP recv established: type=0x{:02x} len={} from={}",
                        packet_type, n, src_addr
                    );
                }

                match packet_type {
                    // Encrypted voice only. Plaintext types (0x01, 0x10-0x12)
                    // are never produced by a keyed client and are dropped on
                    // receive so nothing unauthenticated can reach the mixer.
                    0x05 => {
                        let header_size = voipc_protocol::voice::ENCRYPTED_VOICE_HEADER_SIZE;
                        if n < header_size {
                            continue;
                        }
                        let session_id =
                            u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
                        let sequence =
                            u32::from_be_bytes([buf[13], buf[14], buf[15], buf[16]]);

                        // Decrypt if encrypted, otherwise use raw data
                        let opus_data: Vec<u8> = if packet_type == 0x05 {
                            let raw_encrypted = &buf[header_size..n];
                            let key_guard = media_key.lock().unwrap_or_else(|poisoned| {
                                warn!("media key mutex poisoned — recovering");
                                poisoned.into_inner()
                            });
                            let key_opt = key_guard.as_ref();
                            if let Some(key) = key_opt {
                                let ch_id = channel_id.load(Ordering::Relaxed);
                                let aad = voipc_crypto::build_aad(ch_id, 0x05);
                                match voipc_crypto::media_decrypt(
                                    key,
                                    session_id,
                                    sequence,
                                    0,
                                    &aad,
                                    raw_encrypted,
                                ) {
                                    Ok(decrypted) => decrypted,
                                    Err(e) => {
                                        warn!(
                                            "Voice decryption failed from session {}: {}",
                                            session_id, e
                                        );
                                        continue;
                                    }
                                }
                            } else {
                                warn!("Received encrypted voice but no media key available");
                                continue;
                            }
                        } else {
                            continue;
                        };

                        // Enqueue into the per-user jitter buffer; the mixer
                        // task pops, decodes, and mixes on its 20ms clock
                        {
                            let mut map = match sources.lock() {
                                Ok(m) => m,
                                Err(poisoned) => poisoned.into_inner(),
                            };
                            let src = match map.entry(session_id) {
                                std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
                                std::collections::hash_map::Entry::Vacant(v) => {
                                    match MixSource::new() {
                                        Ok(s) => v.insert(s),
                                        Err(e) => {
                                            warn!("Failed to create Opus decoder for session {session_id}: {e}");
                                            continue;
                                        }
                                    }
                                }
                            };
                            src.jitter.push(sequence, opus_data);
                            src.eot_received = false;
                            src.last_activity = std::time::Instant::now();
                        }

                        // Edge-triggered speaking indicator: emit only on the
                        // first packet of a burst (the 300ms sweep and the EOT
                        // branch emit speaking:false and clear the entry)
                        if last_voice_time
                            .insert(session_id, std::time::Instant::now())
                            .is_none()
                        {
                            let _ = app_handle.emit(
                                "user-speaking",
                                serde_json::json!({"user_id": session_id, "speaking": true}),
                            );
                        }
                    }
                    // Voice: EndOfTransmission
                    0x02 => {
                        if n < voipc_protocol::voice::VOICE_HEADER_SIZE {
                            continue;
                        }
                        let session_id =
                            u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
                        // Mark EOT — the mixer resets the jitter buffer after
                        // draining the buffered tail (an immediate reset here
                        // would clip the end of the last word).
                        // The decoder stays alive for continuity across bursts.
                        if let Ok(mut map) = sources.lock() {
                            if let Some(src) = map.get_mut(&session_id) {
                                src.eot_received = true;
                            }
                        }
                        last_voice_time.remove(&session_id);
                        let _ = app_handle.emit(
                            "user-speaking",
                            serde_json::json!({"user_id": session_id, "speaking": false}),
                        );
                    }
                    // Voice: Ping from server — reply with a Pong
                    0x03 => {
                        buf[0] = 0x04;
                        let _ = socket.send_to(&buf[..n], src_addr).await;
                    }
                    // Voice: Pong — echo of our keepalive ping; the sequence
                    // field carries our send time, so this is real UDP RTT
                    0x04 => {
                        if n >= voipc_protocol::voice::VOICE_HEADER_SIZE {
                            last_pong.store(now_millis_u64(), Ordering::Relaxed);
                            let sent =
                                u32::from_be_bytes([buf[13], buf[14], buf[15], buf[16]]);
                            let rtt = now_millis_u32().wrapping_sub(sent);
                            // Guard against clock weirdness producing huge values
                            if rtt < 60_000 {
                                let _ = app_handle.emit(
                                    "latency-update",
                                    serde_json::json!({"ms": rtt}),
                                );
                            }
                        }
                    }
                    // Video: VideoFragment / VideoKeyframeFragment (unencrypted + encrypted)
                    0x13 | 0x14 => {
                        if n < VIDEO_HEADER_SIZE {
                            continue;
                        }
                        let mut packet = match VideoPacket::from_bytes(&buf[..n]) {
                            Ok(p) => p,
                            Err(_) => continue,
                        };

                        screen_video_bytes_received.fetch_add(n as u64, Ordering::Relaxed);

                        // Decrypt encrypted video fragments
                        if packet.packet_type.is_encrypted() {
                            let key_guard = media_key.lock().unwrap_or_else(|poisoned| {
                                warn!("media key mutex poisoned — recovering");
                                poisoned.into_inner()
                            });
                            let key_opt = key_guard.as_ref();
                            if let Some(key) = key_opt {
                                let ch_id = channel_id.load(Ordering::Relaxed);
                                let aad = voipc_crypto::build_aad(ch_id, packet_type);
                                match voipc_crypto::media_decrypt(
                                    key,
                                    packet.session_id,
                                    packet.frame_id,
                                    packet.fragment_index as u32,
                                    &aad,
                                    &packet.payload,
                                ) {
                                    Ok(decrypted) => packet.payload = decrypted,
                                    Err(e) => {
                                        warn!("Video decryption failed: {}", e);
                                        continue;
                                    }
                                }
                            } else {
                                warn!("Received encrypted video but no media key");
                                continue;
                            }
                        }

                        // Detect sharer change — reset assembler (the old
                        // sharer's audio source just goes idle and is pruned)
                        if current_video_session != Some(packet.session_id) {
                            video_assembler.reset();
                            current_video_session = Some(packet.session_id);
                        }

                        let result = video_assembler.add_fragment(&packet);

                        // Incomplete frame was dropped — signal render suppression
                        // and request keyframe to recover
                        if result.frame_dropped {
                            screen_video_frames_dropped.fetch_add(1, Ordering::Relaxed);
                            needs_keyframe.store(true, Ordering::Release);
                            if last_keyframe_request.elapsed() >= std::time::Duration::from_secs(1) {
                                let sharer_id = watching_user_id.load(Ordering::Relaxed);
                                if sharer_id != 0 {
                                    let msg = ClientMessage::RequestKeyframe { sharer_user_id: sharer_id };
                                    if let Ok(data) = encode_client_msg(&msg) {
                                        let _ = tcp_tx.try_send(data);
                                        info!("auto-requested keyframe (frame loss detected)");
                                    }
                                    last_keyframe_request = std::time::Instant::now();
                                }
                            }
                        }

                        if let Some((frame_data, is_keyframe)) = result.frame {
                            screen_video_frames_received.fetch_add(1, Ordering::Relaxed);
                            // Send to decode task — drop if full to avoid stalling voice
                            if video_decode_tx.try_send((frame_data, is_keyframe)).is_err() {
                                screen_video_frames_dropped.fetch_add(1, Ordering::Relaxed);
                                warn!("video decode channel full — dropping assembled frame");
                            }
                        }
                    }
                    // Screen share audio (encrypted only)
                    0x15 => {
                        if n < SCREEN_AUDIO_HEADER_SIZE {
                            continue;
                        }
                        let packet = match ScreenShareAudioPacket::from_bytes(&buf[..n]) {
                            Ok(p) => p,
                            Err(_) => continue,
                        };

                        // Decrypt encrypted screen audio
                        let opus_data = if packet.encrypted {
                            let key_guard = media_key.lock().unwrap_or_else(|poisoned| {
                                warn!("media key mutex poisoned — recovering");
                                poisoned.into_inner()
                            });
                            let key_opt = key_guard.as_ref();
                            if let Some(key) = key_opt {
                                let ch_id = channel_id.load(Ordering::Relaxed);
                                let aad = voipc_crypto::build_aad(ch_id, 0x15);
                                match voipc_crypto::media_decrypt(
                                    key,
                                    packet.session_id,
                                    packet.sequence,
                                    0,
                                    &aad,
                                    &packet.opus_data,
                                ) {
                                    Ok(decrypted) => decrypted,
                                    Err(e) => {
                                        warn!("Screen audio decryption failed: {}", e);
                                        continue;
                                    }
                                }
                            } else {
                                warn!("Received encrypted screen audio but no media key");
                                continue;
                            }
                        } else {
                            continue;
                        };

                        // Feed the mixer like a voice stream (flagged key) —
                        // screen audio gains jitter/reorder protection and is
                        // mixed correctly with simultaneous voice.
                        {
                            let mut map = match sources.lock() {
                                Ok(m) => m,
                                Err(poisoned) => poisoned.into_inner(),
                            };
                            let key = packet.session_id | SCREEN_AUDIO_FLAG;
                            let src = match map.entry(key) {
                                std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
                                std::collections::hash_map::Entry::Vacant(v) => {
                                    match MixSource::new() {
                                        Ok(s) => v.insert(s),
                                        Err(e) => {
                                            warn!("Failed to create screen audio decoder: {e}");
                                            continue;
                                        }
                                    }
                                }
                            };
                            src.jitter.push(packet.sequence, opus_data);
                            src.last_activity = std::time::Instant::now();
                        }
                        screen_audio_recv_count.fetch_add(1, Ordering::Relaxed);
                    }
                    _ => {}
                }
            }
            Err(e) => {
                // Not fatal: on Windows an ICMP unreachable for any earlier
                // send surfaces here as WSAECONNRESET; leaving would kill
                // voice for the rest of the session while TCP stays up.
                recv_errors += 1;
                error!("UDP recv error ({}): {}", recv_errors, e);
                if recv_errors >= 10 {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
            }
            // Periodically check for users who stopped sending voice (VAD mode timeout)
            _ = speaking_timeout.tick() => {
                let now = std::time::Instant::now();
                let expired: Vec<u32> = last_voice_time.iter()
                    .filter(|(_, t)| now.duration_since(**t).as_millis() > SPEAKING_TIMEOUT_MS)
                    .map(|(id, _)| *id)
                    .collect();
                for user_id in expired {
                    last_voice_time.remove(&user_id);
                    let _ = app_handle.emit(
                        "user-speaking",
                        serde_json::json!({"user_id": user_id, "speaking": false}),
                    );
                }
            }
        }
    }
}

/// Video decode + render task: runs on a blocking thread to avoid stalling
/// the UDP receiver. Decodes ALL H.265 frames to maintain codec state, but only
/// JPEG-encodes and emits the most recent frame (frame skipping).
///
/// **Render suppression:** When UDP packet loss breaks the H.265 reference chain,
/// all subsequent delta frames decode to gray/corrupted pixels. Instead of displaying
/// these, we suppress rendering until a keyframe arrives and resets the decoder state.
/// The viewer sees the last good frame (frozen) instead of gray corruption.
fn video_decode_render_task(
    mut decode_rx: mpsc::Receiver<(Vec<u8>, bool)>,
    app_handle: tauri::AppHandle,
    tcp_tx: mpsc::Sender<Vec<u8>>,
    watching_user_id: Arc<AtomicU32>,
    screen_video_resolution: Arc<AtomicU32>,
    needs_keyframe: Arc<AtomicBool>,
) {
    let mut decoder: Option<voipc_video::decoder::Decoder> = None;
    let mut buffers = match screenshare::FrameDecodeBuffers::new() {
        Ok(b) => b,
        Err(e) => {
            error!("Failed to init frame decode buffers: {e}");
            return;
        }
    };
    let mut last_keyframe_request = std::time::Instant::now() - std::time::Duration::from_secs(10);
    let mut suppress_render = false;

    while let Some((frame_data, is_keyframe)) = decode_rx.blocking_recv() {
        // Check shared flag from UDP receiver (frame loss detected)
        if needs_keyframe.load(Ordering::Acquire) {
            suppress_render = true;
        }

        let dec = match decoder.as_mut() {
            Some(d) => d,
            None => match voipc_video::decoder::Decoder::new() {
                Ok(d) => decoder.insert(d),
                Err(e) => {
                    warn!("H.265 decoder creation failed: {e} — skipping frame");
                    needs_keyframe.store(true, Ordering::Release);
                    continue;
                }
            },
        };

        // ALWAYS decode — maintains codec reference state even when render is suppressed.
        // Skipping decode would cause even more corruption when rendering resumes.
        let mut latest_decoded = match dec.decode(&frame_data) {
            Ok(d) => d,
            Err(e) => {
                warn!("H.265 decode error: {}", e);
                suppress_render = true;
                needs_keyframe.store(true, Ordering::Release);
                // Auto-request keyframe on decode failure (max once per second)
                if last_keyframe_request.elapsed() >= std::time::Duration::from_secs(1) {
                    let sharer_id = watching_user_id.load(Ordering::Relaxed);
                    if sharer_id != 0 {
                        let msg = ClientMessage::RequestKeyframe { sharer_user_id: sharer_id };
                        if let Ok(data) = encode_client_msg(&msg) {
                            let _ = tcp_tx.try_send(data);
                            info!("auto-requested keyframe from sharer {}", sharer_id);
                        }
                        last_keyframe_request = std::time::Instant::now();
                    }
                }
                continue;
            }
        };

        // Track whether any keyframe was decoded in this batch
        let mut keyframe_seen = is_keyframe;

        // Drain any queued frames — decode all to maintain codec state,
        // but only keep the latest decoded result for rendering
        while let Ok((next_frame, next_is_keyframe)) = decode_rx.try_recv() {
            if next_is_keyframe {
                keyframe_seen = true;
            }
            match dec.decode(&next_frame) {
                Ok(d) => latest_decoded = d,
                Err(e) => {
                    warn!("H.265 decode error (drain): {}", e);
                    suppress_render = true;
                    needs_keyframe.store(true, Ordering::Release);
                }
            }
        }

        // Keyframe decoded in this batch → reference chain is clean, resume rendering
        if suppress_render && keyframe_seen {
            suppress_render = false;
            needs_keyframe.store(false, Ordering::Release);
            info!("render resumed after keyframe");
        }

        // JPEG-encode and emit only if not suppressed
        if !suppress_render {
            for df in &latest_decoded {
                let packed = ((df.width as u32) << 16) | (df.height as u32);
                screen_video_resolution.store(packed, Ordering::Relaxed);
                screenshare::render_frame(df, &app_handle, &mut buffers);
            }
        }
    }
    info!("video decode+render task ended");
}

/// Capture+encode task: reads from mic, encodes to Opus, encrypts with
/// AES-256-GCM if a media key is available, then sends via UDP.
/// Runs on a blocking thread since it polls the ring buffer.
#[allow(unused_assignments)] // capture_stream is a hold-to-keep-alive handle
pub fn spawn_capture_encode_task(
    device_name: Option<String>,
    session_id: u32,
    udp_token: u64,
    transmitting: Arc<AtomicBool>,
    voice_tx: mpsc::Sender<Vec<u8>>,
    media_key: Arc<std::sync::Mutex<Option<MediaKey>>>,
    channel_id: Arc<AtomicU32>,
    voice_mode: Arc<AtomicU8>,
    vad_threshold_db: Arc<AtomicI32>,
    current_audio_level: Arc<AtomicI32>,
    noise_suppression: Arc<AtomicBool>,
    is_muted: Arc<AtomicBool>,
    voice_sequence: Arc<AtomicU32>,
    input_gain: Arc<AtomicU32>,
    app_handle: tauri::AppHandle,
) -> tokio::task::JoinHandle<()> {
    tokio::task::spawn_blocking(move || {
        let capture_error = Arc::new(AtomicBool::new(false));
        let (mut _capture_stream, mut consumer) =
            match voipc_audio::capture::start_capture(
                device_name.as_deref(),
                capture_error.clone(),
                input_gain.clone(),
            ) {
                Ok(result) => result,
                Err(e) => {
                    error!("Failed to start audio capture: {}", e);
                    transmitting.store(false, Ordering::Relaxed);
                    let _ = app_handle.emit(
                        "audio-device-error",
                        serde_json::json!({"error": e.to_string()}),
                    );
                    return;
                }
            };
        let mut encoder = match voipc_audio::encoder::Encoder::new() {
            Ok(e) => e,
            Err(e) => {
                error!("Failed to create Opus encoder: {}", e);
                return;
            }
        };

        let frame_size = encoder.frame_size(); // 960 samples
        let mut pcm_buf = vec![0.0f32; frame_size];
        let mut accumulated: usize = 0;
        let mut stream_dead = false;
        let mut last_rebuild = std::time::Instant::now();
        // "Waiting for media key" UI warning, emitted once per gap
        let mut key_missing_since: Option<std::time::Instant> = None;
        let mut key_missing_emitted = false;

        // Voice activity detector for VAD mode
        let mut vad = voipc_audio::vad::VoiceActivityDetector::new(
            vad_threshold_db.load(Ordering::Relaxed) as f32,
            300, // 300ms hold time
            20,  // 20ms frame duration
        );

        // RNNoise-based noise suppression
        let mut denoiser = voipc_audio::denoise::Denoiser::new();

        info!("capture+encode task started");

        while transmitting.load(Ordering::Relaxed) {
            // Rebuild the capture stream if the device died (unplug etc.)
            if capture_error.swap(false, Ordering::Relaxed) && !stream_dead {
                stream_dead = true;
                warn!("capture device error — attempting recovery");
                let _ = app_handle.emit(
                    "audio-device-error",
                    serde_json::json!({"error": "capture device error"}),
                );
            }
            if stream_dead {
                if last_rebuild.elapsed() >= std::time::Duration::from_secs(1) {
                    last_rebuild = std::time::Instant::now();
                    match voipc_audio::capture::start_capture(
                        device_name.as_deref(),
                        capture_error.clone(),
                        input_gain.clone(),
                    ) {
                        Ok((stream, cons)) => {
                            _capture_stream = stream;
                            consumer = cons;
                            stream_dead = false;
                            accumulated = 0;
                            info!("capture stream restored");
                            let _ = app_handle.emit("audio-device-restored", ());
                        }
                        Err(e) => warn!("capture restart failed (retrying): {}", e),
                    }
                }
                if stream_dead {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                    continue;
                }
            }

            // Read into the remaining portion of pcm_buf
            let read = ringbuf::traits::Consumer::pop_slice(
                &mut consumer,
                &mut pcm_buf[accumulated..],
            );
            accumulated += read;

            if accumulated < frame_size {
                // Not enough samples yet — wait ~5ms for more audio data
                std::thread::sleep(std::time::Duration::from_millis(5));
                continue;
            }

            // Apply noise suppression before VAD and encoding
            denoiser.set_enabled(noise_suppression.load(Ordering::Relaxed));
            denoiser.process(&mut pcm_buf);

            // Update VAD threshold from shared state (user may adjust in real-time)
            let threshold = vad_threshold_db.load(Ordering::Relaxed) as f32;
            vad.set_threshold_db(threshold);

            // Run VAD to compute audio level (always, for the UI meter)
            let voice_detected = vad.process(&pcm_buf);

            // Store current level for UI (×100 for fixed-point precision)
            let level_fixed = (vad.current_level_db() * 100.0) as i32;
            current_audio_level.store(level_fixed, Ordering::Relaxed);

            // Check voice mode to decide whether to send
            let mode = crate::app_state::VoiceMode::from_u8(voice_mode.load(Ordering::Relaxed));
            let should_send = match mode {
                crate::app_state::VoiceMode::Ptt => true,       // PTT: always send while transmitting
                crate::app_state::VoiceMode::Vad => voice_detected,
                crate::app_state::VoiceMode::AlwaysOn => true,
            };

            if !should_send || is_muted.load(Ordering::Relaxed) {
                accumulated = 0;
                continue;
            }

            // We have a full frame — encode and send.
            // The sequence counter lives on the connection so it never
            // restarts within a session: a restart would reuse AES-GCM
            // nonces under the channel key and desync receivers' jitter
            // buffers when the EndOfTransmission packet is lost.
            let sequence = voice_sequence.fetch_add(1, Ordering::Relaxed);
            match encoder.encode(&pcm_buf) {
                Ok(opus_data) => {
                    let packet = {
                        let key_guard = media_key.lock().unwrap_or_else(|poisoned| {
                            warn!("media key mutex poisoned — recovering");
                            poisoned.into_inner()
                        });
                        let key_opt = key_guard.as_ref();

                        if let Some(key) = key_opt {
                            key_missing_since = None;
                            key_missing_emitted = false;
                            let ch_id = channel_id.load(Ordering::Relaxed);
                            let aad = voipc_crypto::build_aad(ch_id, 0x05);
                            match voipc_crypto::media_encrypt(
                                key, session_id, sequence, 0, &aad, &opus_data,
                            ) {
                                Ok(encrypted) => VoicePacket::encrypted_voice(
                                    session_id,
                                    udp_token,
                                    sequence,
                                    key.key_id,
                                    encrypted,
                                ),
                                Err(e) => {
                                    warn!("Voice encryption failed (seq {}): {}", sequence, e);
                                    // Do NOT fall back to plaintext — skip this
                                    // frame (the sequence was already consumed,
                                    // receivers treat the gap as loss).
                                    accumulated = 0;
                                    continue;
                                }
                            }
                        } else {
                            // Never fall back to plaintext. We are waiting for
                            // the channel's media key (channel switch, or the
                            // member holding it is still establishing our
                            // Signal session); warn the UI once if it drags on.
                            let since = *key_missing_since
                                .get_or_insert_with(std::time::Instant::now);
                            if !key_missing_emitted
                                && since.elapsed() > std::time::Duration::from_secs(2)
                            {
                                key_missing_emitted = true;
                                warn!("no media key for 2s — voice frames are being dropped");
                                let _ = app_handle.emit("media-key-missing", ());
                            }
                            accumulated = 0;
                            continue;
                        }
                    };

                    if voice_tx.blocking_send(packet.to_bytes()).is_err() {
                        break;
                    }
                }
                Err(e) => {
                    warn!("Opus encode error: {}", e);
                }
            }

            accumulated = 0;
        }

        info!("capture+encode task stopped");
    })
}

/// TOFU (Trust On First Use) certificate pinning store.
/// Maps server hostname to SHA-256 fingerprint of the server's certificate.
/// On first connect, the cert is trusted and stored. On subsequent connects,
/// the cert must match the stored fingerprint or the connection is rejected.
/// Persisted to `tofu_pins.json` in the VoIPC data directory.
static TOFU_STORE: std::sync::LazyLock<std::sync::Mutex<HashMap<String, Vec<u8>>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(tofu_load_from_disk()));

/// Load TOFU pins from disk. Returns empty map on any error.
fn tofu_load_from_disk() -> HashMap<String, Vec<u8>> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let path = crate::config::data_dir().join("tofu_pins.json");
    let Ok(data) = std::fs::read_to_string(&path) else {
        return HashMap::new();
    };
    // Stored as { "host": "base64-encoded-fingerprint", ... }
    let Ok(map): Result<HashMap<String, String>, _> = serde_json::from_str(&data) else {
        return HashMap::new();
    };
    map.into_iter()
        .filter_map(|(k, v)| STANDARD.decode(&v).ok().map(|bytes| (k, bytes)))
        .collect()
}

/// Save TOFU pins to disk. Errors are logged but non-fatal.
fn tofu_save_to_disk(store: &HashMap<String, Vec<u8>>) {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let path = crate::config::data_dir().join("tofu_pins.json");
    let b64_map: HashMap<&str, String> = store
        .iter()
        .map(|(k, v)| (k.as_str(), STANDARD.encode(v)))
        .collect();
    match serde_json::to_string_pretty(&b64_map) {
        Ok(json) => {
            if let Err(e) = std::fs::write(&path, json) {
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
    let mut store = TOFU_STORE.lock().unwrap_or_else(|p| { warn!("mutex poisoned, recovering"); p.into_inner() });
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
}

impl rustls::client::danger::ServerCertVerifier for TofuCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // Compute SHA-256 fingerprint of the server's certificate
        use ring::digest;
        let fingerprint = digest::digest(&digest::SHA256, end_entity.as_ref());
        let fp_bytes = fingerprint.as_ref().to_vec();
        let host_key = &self.key;

        let mut store = TOFU_STORE.lock().unwrap_or_else(|p| { warn!("mutex poisoned, recovering"); p.into_inner() });

        if let Some(pinned) = store.get(host_key) {
            // We've connected to this host before — verify the fingerprint matches
            if *pinned != fp_bytes {
                warn!(
                    "TOFU: certificate fingerprint changed for {}! Possible MITM attack.",
                    host_key
                );
                return Err(rustls::Error::General(format!(
                    "Server certificate fingerprint changed for {}. \
                     This could indicate a man-in-the-middle attack. \
                     Only if you know the server's certificate was replaced, \
                     use \"Forget pinned certificate\" and connect again.",
                    host_key
                )));
            }
            info!("TOFU: certificate fingerprint matches for {}", host_key);
        } else {
            // First connection — pin the certificate and persist to disk
            info!("TOFU: pinning certificate for {} (first connection)", host_key);
            store.insert(host_key.clone(), fp_bytes);
            tofu_save_to_disk(&store);
        }

        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
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
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
        ]
    }
}
