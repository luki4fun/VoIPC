use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;

use bytes::BytesMut;
use ringbuf::traits::Producer;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tauri::Emitter;
#[cfg(not(target_os = "android"))]
use tauri::Manager;
use tracing::{error, info, warn};
use wtransport::error::SendDatagramError;
use wtransport::{Connection, SendStream};

use voipc_crypto::media_keys::MediaKey;
use voipc_protocol::codec::{
    decode_server_msg, encode_client_msg, try_decode_frame, APP_VERSION, PROTOCOL_VERSION,
};
use voipc_protocol::messages::{ClientMessage, ServerMessage};
use voipc_protocol::types::*;
use voipc_protocol::video::{
    FrameAssembler, FrameGrouper, RecordReader, ScreenShareAudioPacket, VideoPacket,
    SCREEN_AUDIO_HEADER_SIZE, VIDEO_HEADER_SIZE,
};
use voipc_protocol::voice::VoicePacket;

use crate::app_state::{ActiveConnection, AppState, LossTally, PendingTarget, SignalState};
use crate::screenshare;
use crate::transport::CONNECT_TIMEOUT;

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
            old.quic.close().await;
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

    // QUIC connect + control stream (every phase bounded, see transport.rs)
    let crate::transport::Link {
        quic,
        mut control_send,
        mut control_recv,
    } = crate::transport::connect(&host, port, accept_invalid_certs).await?;

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
    control_send
        .write_all(&data)
        .await
        .map_err(|e| format!("Failed to send auth: {}", e))?;

    // Read until we get the Authenticated or AuthError response
    let mut buf = BytesMut::with_capacity(4096);
    let (user_id, session_id) = loop {
        let n = tokio::time::timeout(CONNECT_TIMEOUT, control_recv.read_buf(&mut buf))
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
                } => break (user_id, session_id),
                ServerMessage::AuthError { reason } => {
                    return Err(format!("Authentication failed: {}", reason));
                }
                other => {
                    warn!("unexpected message during auth: {:?}", other);
                }
            }
        }
    };

    info!(user_id, session_id, "authenticated with server");

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

    // Control writer channel
    let (tcp_tx, tcp_rx) = mpsc::channel::<Vec<u8>>(64);
    // Voice datagram channel
    let (voice_tx, voice_rx) = mpsc::channel::<Vec<u8>>(256);
    // Video channel (separate from voice to avoid blocking).
    // 512 slots ≈ ~34 frames at 15 fragments/frame — ~1s of headroom before the
    // non-blocking try_send in FrameProcessor reports backpressure, and still
    // room for a full 255-fragment keyframe. Deeper only delays that signal.
    let (video_tx, video_rx) = mpsc::channel::<Vec<u8>>(512);
    // Screen share audio datagram channel
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

    // Last frame-loss signal for our own share (viewer reports, our own path
    // stats); read by the encode thread to step quality down. The tally decides
    // which viewer reports count as loss.
    let share_loss_ms = Arc::new(AtomicU64::new(0));
    let share_loss_tally = Arc::new(std::sync::Mutex::new(LossTally::default()));

    // Shared screen share state — created early so the control reader can reset on channel change
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
    let connection = quic.connection.clone();
    let writer_handle = tokio::spawn(control_writer_task(control_send, tcp_rx));
    let reader_handle = tokio::spawn(control_reader_task(
        control_recv,
        buf,
        app_handle.clone(),
        current_media_key.clone(),
        current_channel_id.clone(),
        state.signal.clone(),
        tcp_tx.clone(),
        user_id,
        screen_share_active.clone(),
        watching_user_id_shared.clone(),
        share_loss_ms.clone(),
        share_loss_tally.clone(),
    ));
    let udp_send_handle = tokio::spawn(datagram_sender_task(connection.clone(), voice_rx));
    let video_send_handle = tokio::spawn(video_stream_sender_task(connection.clone(), video_rx));
    let screen_audio_send_handle =
        tokio::spawn(datagram_sender_task(connection.clone(), screen_audio_rx));
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

    let udp_recv_handle = tokio::spawn(datagram_receiver_task(
        connection.clone(),
        app_handle.clone(),
        mix_sources.clone(),
        screen_audio_recv_count.clone(),
        current_media_key.clone(),
        current_channel_id.clone(),
    ));
    let video_recv_handle = tokio::spawn(video_stream_receiver_task(
        connection.clone(),
        video_decode_tx,
        current_media_key.clone(),
        current_channel_id.clone(),
        screen_video_frames_received.clone(),
        screen_video_frames_dropped.clone(),
        screen_video_bytes_received.clone(),
        tcp_tx.clone(),
        watching_user_id_shared.clone(),
        needs_keyframe,
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

    // Latency display from QUIC's RTT estimate (NAT keepalives are QUIC's job)
    let latency_handle = tokio::spawn(latency_task(connection.clone(), app_handle.clone()));
    // Our own uplink's congestion, which viewer reports cannot see
    let congestion_handle = tokio::spawn(congestion_task(
        connection,
        screen_share_active.clone(),
        share_loss_ms.clone(),
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
        quic,
        tasks: vec![
            writer_handle,
            reader_handle,
            udp_send_handle,
            video_send_handle,
            screen_audio_send_handle,
            udp_recv_handle,
            video_recv_handle,
            video_decode_handle,
            mixer_handle,
            latency_handle,
            congestion_handle,
        ],
        transmitting,
        capture_task: None,
        voice_sequence: Arc::new(AtomicU32::new(0)),
        master_volume,
        voice_frames_played,
        voice_frames_lost,
        output_device_live,
        playback_restart,
        is_screen_sharing: false,
        screen_capture_task: None,
        screen_share_active,
        keyframe_requested: Arc::new(AtomicBool::new(false)),
        share_loss_ms,
        share_loss_tally,
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

/// Send a client message over the control stream.
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

/// Control writer task: sends encoded messages from the channel to the control stream.
async fn control_writer_task<W: AsyncWrite + Unpin>(
    mut write_half: W,
    mut rx: mpsc::Receiver<Vec<u8>>,
) {
    while let Some(data) = rx.recv().await {
        if let Err(e) = write_half.write_all(&data).await {
            error!("control write error: {}", e);
            break;
        }
    }
    info!("control writer task ended");
}

/// Control reader task: reads server messages, handles E2E encryption
/// orchestration, and emits Tauri events to the frontend. A dead link shows
/// up here as a read error: QUIC's idle timeout (30 s without acks) closes
/// the connection even when the OS never reports anything (roam, sleep).
#[allow(clippy::too_many_arguments)]
async fn control_reader_task<R: AsyncRead + Unpin>(
    mut read_half: R,
    mut buf: BytesMut,
    app_handle: tauri::AppHandle,
    media_key: Arc<std::sync::Mutex<Option<MediaKey>>>,
    channel_id: Arc<AtomicU32>,
    signal: Arc<std::sync::Mutex<SignalState>>,
    tcp_tx: mpsc::Sender<Vec<u8>>,
    own_user_id: u32,
    screen_share_active: Arc<AtomicBool>,
    watching_user_id_shared: Arc<AtomicU32>,
    share_loss_ms: Arc<AtomicU64>,
    share_loss_tally: Arc<std::sync::Mutex<LossTally>>,
) {
    'read: loop {
        match read_half.read_buf(&mut buf).await {
            Ok(0) => {
                info!("server closed the control stream");
                let _ = app_handle.emit(
                    "connection-lost",
                    serde_json::json!({"reason": "Server closed connection"}),
                );
                break;
            }
            Ok(_) => {}
            Err(e) => {
                error!("control read error: {}", e);
                let _ = app_handle.emit(
                    "connection-lost",
                    serde_json::json!({"reason": format!("Connection lost: {}", e)}),
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
                            &share_loss_ms,
                            &share_loss_tally,
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
    info!("control reader task ended");
}

/// Dispatch a server message to the appropriate Tauri event.
/// Also handles E2E encryption orchestration (session establishment, sender key
/// distribution, and automatic decryption of encrypted messages).
#[allow(clippy::too_many_arguments)]
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
    share_loss_ms: &Arc<AtomicU64>,
    share_loss_tally: &Arc<std::sync::Mutex<LossTally>>,
) {
    match msg {
        ServerMessage::VideoLossReported {
            viewer_user_id,
            frames_dropped,
            frames_received,
        } => {
            // A viewer lost frames. Only a majority of the current viewers
            // steps the encoder down (screenshare::FrameProcessor::adapt) — one
            // viewer on a bad link is that viewer's problem, not the share's.
            if frames_dropped > 0 {
                let now = screenshare::epoch_ms();
                let mut tally = share_loss_tally
                    .lock()
                    .unwrap_or_else(|p| { warn!("mutex poisoned, recovering"); p.into_inner() });
                tally.reports.insert(viewer_user_id, now);
                tally
                    .reports
                    .retain(|_, at| now.saturating_sub(*at) < LOSS_REPORT_TTL_MS);
                let (reporters, viewers) = (tally.reports.len(), tally.viewer_count);
                drop(tally);
                if majority_reached(reporters, viewers) {
                    share_loss_ms.store(now, Ordering::Relaxed);
                }
                info!(
                    viewer_user_id,
                    frames_dropped, frames_received, reporters, viewers, "viewer reported frame loss"
                );
            }
        }
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
            // Displayed latency comes from QUIC's RTT estimate (latency_task)
            // instead: this Pong also answers our echo of the server's
            // keepalive ping, where the timestamp is the SERVER's clock —
            // computing a "RTT" from it yielded clock skew, not latency.
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
            share_loss_tally
                .lock()
                .unwrap_or_else(|p| { warn!("mutex poisoned, recovering"); p.into_inner() })
                .viewer_count = viewer_count;
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

/// Voice / screen-audio packets → QUIC datagrams (unreliable and unordered,
/// like the UDP they replace).
async fn datagram_sender_task(connection: Connection, mut rx: mpsc::Receiver<Vec<u8>>) {
    let mut warned_oversize = false;
    while let Some(data) = rx.recv().await {
        match connection.send_datagram(data) {
            Ok(()) => {}
            Err(SendDatagramError::TooLarge) => {
                if !warned_oversize {
                    warned_oversize = true;
                    warn!(
                        "media packet exceeds the datagram limit ({:?}) — dropped",
                        connection.max_datagram_size()
                    );
                }
            }
            Err(SendDatagramError::UnsupportedByPeer) => {
                error!("server does not accept datagrams — media disabled");
                return;
            }
            Err(SendDatagramError::NotConnected) => return,
        }
    }
}

/// Video fragments → one unidirectional stream per frame, each fragment
/// prefixed with its u16-BE length (fragments exceed the datagram MTU).
/// Mirror of the server's stream writer.
async fn video_stream_sender_task(connection: Connection, mut rx: mpsc::Receiver<Vec<u8>>) {
    let mut grouper = FrameGrouper::default();
    let mut stream: Option<SendStream> = None;
    while let Some(packet) = rx.recv().await {
        let Some(place) = grouper.place(&packet) else {
            continue;
        };
        if place.new_frame {
            finish_frame(stream.take()).await;
            stream = match connection.open_uni().await {
                Ok(opening) => match opening.await {
                    Ok(stream) => Some(stream),
                    Err(e) => {
                        warn!("video stream refused: {}", e);
                        None
                    }
                },
                Err(e) => {
                    info!("video stream open ended: {}", e);
                    return;
                }
            };
        }
        // No stream: the frame's opening failed or an earlier write did;
        // drop the rest of this frame, viewers request a keyframe.
        let Some(current) = stream.as_mut() else {
            continue;
        };
        let len = (packet.len() as u16).to_be_bytes();
        if current.write_all(&len).await.is_err() || current.write_all(&packet).await.is_err() {
            stream = None;
            continue;
        }
        if place.last {
            finish_frame(stream.take()).await;
        }
    }
}

/// FIN a frame stream without waiting for the peer's ack (`shutdown` is
/// quinn's synchronous finish; wtransport's `finish` would cost one RTT per frame).
async fn finish_frame(stream: Option<SendStream>) {
    if let Some(mut stream) = stream {
        let _ = stream.shutdown().await;
    }
}

/// A viewer's loss report counts for this long; older ones are pruned before
/// the majority is counted (viewers report every 2 s).
const LOSS_REPORT_TTL_MS: u64 = 2_000;

/// Whether enough of the current viewers report loss to step the share down.
/// With no viewer count yet (nothing received), a single report is enough.
fn majority_reached(reporters: usize, viewers: u32) -> bool {
    reporters as u32 >= ((viewers + 1) / 2).max(1)
}

/// One second of this connection's QUIC path statistics.
#[derive(Clone, Copy, Default)]
struct PathSample {
    rtt: std::time::Duration,
    lost_packets: u64,
    sent_packets: u64,
}

/// Whether our own uplink looks congested between two samples: real packet loss,
/// or an RTT well above the session's minimum (a queue building somewhere on the
/// path). cwnd is deliberately not used — quinn's is app-limited most of the
/// time, so it stays small and would read as congestion whenever we send little.
/// ponytail: a fixed 1% loss floor rather than a loss estimator; if shares still
/// step down on healthy links, switch to ECN (`PathStats::congestion_events`).
fn congested(prev: &PathSample, cur: &PathSample, min_rtt: std::time::Duration) -> bool {
    let lost = cur.lost_packets.saturating_sub(prev.lost_packets);
    let sent = cur.sent_packets.saturating_sub(prev.sent_packets);
    if lost > 0 && lost * 100 >= sent {
        return true;
    }
    cur.rtt > (min_rtt * 2).max(min_rtt + std::time::Duration::from_millis(100))
}

/// Watches our own path stats while sharing: congestion on the way *to* the
/// server never reaches the viewers' loss reports, it only shows up once the
/// send queue is already a second deep. A hit here feeds the same `share_loss_ms`
/// the encoder's ladder reads.
async fn congestion_task(
    connection: Connection,
    screen_share_active: Arc<AtomicBool>,
    share_loss_ms: Arc<AtomicU64>,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut prev = PathSample::default();
    let mut min_rtt = std::time::Duration::MAX;
    let mut reported = false;
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let path = connection.quic_connection().stats().path;
                let cur = PathSample {
                    rtt: path.rtt,
                    lost_packets: path.lost_packets,
                    sent_packets: path.sent_packets,
                };
                min_rtt = min_rtt.min(cur.rtt);
                if !screen_share_active.load(Ordering::Relaxed) {
                    prev = cur;
                    reported = false;
                    continue;
                }
                if congested(&prev, &cur, min_rtt) {
                    share_loss_ms.store(screenshare::epoch_ms(), Ordering::Relaxed);
                    if !reported {
                        reported = true;
                        info!(
                            rtt_ms = cur.rtt.as_millis() as u64,
                            min_rtt_ms = min_rtt.as_millis() as u64,
                            lost = cur.lost_packets.saturating_sub(prev.lost_packets),
                            sent = cur.sent_packets.saturating_sub(prev.sent_packets),
                            "own uplink congested — stepping the share down"
                        );
                    }
                } else if reported {
                    reported = false;
                    info!("own uplink recovered");
                }
                prev = cur;
            }
            _ = connection.closed() => return,
        }
    }
}

/// Latency for the status bar from QUIC's own RTT estimate, every 10 s.
async fn latency_task(connection: Connection, app_handle: tauri::AppHandle) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let ms = connection.rtt().as_millis() as u64;
                let _ = app_handle.emit("latency-update", serde_json::json!({"ms": ms}));
            }
            _ = connection.closed() => return,
        }
    }
}

/// Server → client datagrams: voice (0x05), end-of-transmission (0x02) and
/// screen-share audio (0x15), decrypted and fed to the mixer's per-source
/// jitter buffers; also drives the speaking indicator. Video arrives on
/// streams (`video_stream_receiver_task`).
async fn datagram_receiver_task(
    connection: Connection,
    app_handle: tauri::AppHandle,
    sources: MixSources,
    screen_audio_recv_count: Arc<AtomicU32>,
    media_key: Arc<std::sync::Mutex<Option<MediaKey>>>,
    channel_id: Arc<AtomicU32>,
) {
    let mut recv_count: u64 = 0;
    // Track last voice packet time per user for speaking timeout
    let mut last_voice_time: HashMap<u32, std::time::Instant> = HashMap::new();
    let mut speaking_timeout = tokio::time::interval(std::time::Duration::from_millis(300));
    speaking_timeout.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    const SPEAKING_TIMEOUT_MS: u128 = 500;

    loop {
        tokio::select! {
            result = connection.receive_datagram() => {
                let datagram = match result {
                    Ok(datagram) => datagram,
                    Err(e) => {
                        info!("datagram receive ended: {}", e);
                        break;
                    }
                };
                let buf: &[u8] = &datagram;
                let n = buf.len();
                if n == 0 {
                    continue;
                }
                recv_count += 1;
                let packet_type = buf[0];

                if recv_count == 1 {
                    info!("media path established: first datagram type=0x{:02x} len={}", packet_type, n);
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
                            u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]);

                        let opus_data: Vec<u8> = {
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
                    // Screen share audio (encrypted only)
                    0x15 => {
                        if n < SCREEN_AUDIO_HEADER_SIZE {
                            continue;
                        }
                        let packet = match ScreenShareAudioPacket::from_bytes(buf) {
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

/// Largest per-frame video stream we accept (a 1080p keyframe is well under 1 MiB).
const MAX_FRAME_STREAM_BYTES: u64 = 8 * 1024 * 1024;
/// Viewer loss reports to the sharer cover this window.
const LOSS_REPORT_WINDOW: std::time::Duration = std::time::Duration::from_secs(2);

/// Server → client video: each unidirectional stream is one frame as
/// `[u16 BE len][packet]` records, fed to the assembler as they arrive (waiting
/// for the frame's FIN would add its whole transmission time to the latency).
/// Decrypts, reassembles, hands complete frames to the decode task, requests a
/// keyframe on loss and reports the loss to the sharer every 2 s so it can
/// lower its bitrate/fps.
#[allow(clippy::too_many_arguments)]
async fn video_stream_receiver_task(
    connection: Connection,
    video_decode_tx: mpsc::Sender<(Vec<u8>, bool)>,
    media_key: Arc<std::sync::Mutex<Option<MediaKey>>>,
    channel_id: Arc<AtomicU32>,
    screen_video_frames_received: Arc<AtomicU32>,
    screen_video_frames_dropped: Arc<AtomicU32>,
    screen_video_bytes_received: Arc<AtomicU64>,
    tcp_tx: mpsc::Sender<Vec<u8>>,
    watching_user_id: Arc<AtomicU32>,
    needs_keyframe: Arc<AtomicBool>,
) {
    let mut video_assembler = FrameAssembler::new();
    let mut current_video_session: Option<u32> = None;
    let mut last_keyframe_request = std::time::Instant::now() - std::time::Duration::from_secs(10);
    let mut window_started = std::time::Instant::now();
    let mut window_dropped: u32 = 0;
    let mut window_received: u32 = 0;
    let mut chunk = vec![0u8; 16 * 1024];

    loop {
        let mut stream = match connection.accept_uni().await {
            Ok(stream) => stream,
            Err(e) => {
                info!("video stream accept ended: {}", e);
                return;
            }
        };
        // Frames are read one after another so fragments reach the assembler in order.
        let mut reader = RecordReader::default();
        let mut total: u64 = 0;

        loop {
            // Err = reset by the server: the frame is lost, the assembler sees the gap
            let read = match stream.read(&mut chunk).await {
                Ok(Some(n)) => n,
                Ok(None) | Err(_) => break,
            };
            total += read as u64;
            if total > MAX_FRAME_STREAM_BYTES {
                break;
            }

            for packet_bytes in reader.push(&chunk[..read]) {
                let n = packet_bytes.len();
                if n < VIDEO_HEADER_SIZE {
                    continue;
                }
                let packet_type = packet_bytes[0];
                if packet_type != 0x13 && packet_type != 0x14 {
                    continue;
                }
                let mut packet = match VideoPacket::from_bytes(&packet_bytes) {
                    Ok(p) => p,
                    Err(_) => continue,
                };

                screen_video_bytes_received.fetch_add(n as u64, Ordering::Relaxed);

                // Decrypt (plaintext video is never relayed)
                {
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
                    window_dropped += 1;
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
                    window_received += 1;
                    // Send to decode task — drop if full to avoid stalling voice
                    if video_decode_tx.try_send((frame_data, is_keyframe)).is_err() {
                        screen_video_frames_dropped.fetch_add(1, Ordering::Relaxed);
                        window_dropped += 1;
                        warn!("video decode channel full — dropping assembled frame");
                    }
                }
            }
            if reader.is_broken() {
                break;
            }
        }

        // Loss report: tell the sharer what this window lost so it can adapt
        if window_started.elapsed() >= LOSS_REPORT_WINDOW {
            let sharer_id = watching_user_id.load(Ordering::Relaxed);
            if window_dropped > 0 && sharer_id != 0 {
                let msg = ClientMessage::VideoLossReport {
                    sharer_user_id: sharer_id,
                    frames_dropped: window_dropped,
                    frames_received: window_received,
                };
                if let Ok(data) = encode_client_msg(&msg) {
                    let _ = tcp_tx.try_send(data);
                }
                info!(
                    dropped = window_dropped,
                    received = window_received,
                    "reported frame loss to the sharer"
                );
            }
            window_started = std::time::Instant::now();
            window_dropped = 0;
            window_received = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn sample(rtt_ms: u64, lost: u64, sent: u64) -> PathSample {
        PathSample {
            rtt: Duration::from_millis(rtt_ms),
            lost_packets: lost,
            sent_packets: sent,
        }
    }

    #[test]
    fn congestion_needs_real_loss_or_a_growing_queue() {
        let min_rtt = Duration::from_millis(20);
        let prev = sample(20, 0, 1_000);

        // A quiet second: no loss, RTT at the session minimum
        assert!(!congested(&prev, &sample(20, 0, 1_500), min_rtt));
        // One lost packet in 500 is normal wireless noise, not congestion
        assert!(!congested(&prev, &sample(20, 1, 1_500), min_rtt));
        // 1% of the window lost
        assert!(congested(&prev, &sample(20, 5, 1_500), min_rtt));
        // RTT doubled (the 2× branch, which decides while min_rtt is large)
        assert!(congested(&prev, &sample(200, 0, 1_500), min_rtt));
        // Doubling a tiny min_rtt is not enough on its own: +100 ms is the floor
        assert!(!congested(&prev, &sample(50, 0, 1_500), min_rtt));
        assert!(congested(&prev, &sample(150, 0, 1_500), min_rtt));
        // On a link whose minimum is already high, doubling is the wider bound,
        // so +100 ms of jitter is not yet congestion
        let far = Duration::from_millis(300);
        assert!(!congested(&prev, &sample(450, 0, 1_500), far));
        assert!(congested(&prev, &sample(700, 0, 1_500), far));
    }

    #[test]
    fn majority_of_viewers_steps_the_share_down() {
        assert!(majority_reached(1, 1)); // the only viewer
        assert!(majority_reached(1, 2)); // half of two is a majority here
        assert!(!majority_reached(1, 3)); // one of three is not
        assert!(majority_reached(2, 3));
        assert!(!majority_reached(2, 5));
        assert!(majority_reached(3, 5));
        // No viewer count seen yet: trust the report we did get
        assert!(majority_reached(1, 0));
        assert!(!majority_reached(0, 0));
    }
}

/// Video decode + render task: runs on a blocking thread to avoid stalling
/// the media receivers. Decodes ALL H.265 frames to maintain codec state, but only
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
/// AES-256-GCM if a media key is available, then sends as datagrams.
/// Runs on a blocking thread since it polls the ring buffer.
#[allow(unused_assignments)] // capture_stream is a hold-to-keep-alive handle
#[allow(clippy::too_many_arguments)]
pub fn spawn_capture_encode_task(
    device_name: Option<String>,
    session_id: u32,
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

