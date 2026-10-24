use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;

use bytes::BytesMut;
use ringbuf::traits::Producer;
use tauri::Emitter;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
// Not desktop-only any more: the SDK event publishers reach for AppState
// through the handle, and those run on every platform even though the SDK
// listener itself does not exist on Android.
use tauri::Manager;
use tracing::{debug, error, info, warn};
use wtransport::error::SendDatagramError;
use wtransport::{Connection, SendStream};

use crate::transport::{Conn, DatagramIn, VideoIn};

use voipc_crypto::media_keys::{MediaKey, MediaKeyRing};
use voipc_protocol::codec::{
    decode_server_msg, encode_client_msg, try_decode_frame, APP_VERSION, PROTOCOL_VERSION,
};
use voipc_protocol::messages::{AuthStep, ClientMessage, ServerMessage};
use voipc_protocol::types::*;
use voipc_protocol::video::{
    FrameAssembler, FrameGrouper, ScreenShareAudioPacket, VideoPacket, SCREEN_AUDIO_HEADER_SIZE,
    VIDEO_HEADER_SIZE,
};
use voipc_protocol::voice::{PositionPayload, VoicePacket, VoicePacketType};

use crate::app_state::{
    ActiveConnection, AppState, LossTally, PendingTarget, SdkEvent, SignalState,
};
use crate::screenshare;
use crate::transport::CONNECT_TIMEOUT;

/// Emit an event that belongs to one server, as `{server, data}` with `data`
/// exactly the payload it always had, so the UI files it under that server.
pub fn emit_server<S: serde::Serialize + Clone>(
    app: &tauri::AppHandle,
    server: &str,
    event: &str,
    data: S,
) {
    #[derive(serde::Serialize, Clone)]
    struct Tagged<'a, S> {
        server: &'a str,
        data: S,
    }
    let _ = app.emit(event, Tagged { server, data });
}

/// Connect to the server, authenticate, spawn background tasks, and store the connection.
/// Returns the assigned user_id on success.
pub async fn connect_to_server(
    state: &AppState,
    app_handle: tauri::AppHandle,
    address: String,
    username: String,
    accept_invalid_certs: bool,
    account: Option<crate::account::AccountArgs>,
) -> Result<u32, String> {
    // Serialize connects to this server: the reconnect loop and a manual
    // connect can race, and the map lock is not held through the network
    // phase — the loser's tasks would otherwise be overwritten without
    // teardown and leak. Other servers connect in parallel.
    let connect_lock = state
        .connect_locks
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .entry(address.clone())
        .or_default()
        .clone();
    let _connect_guard = connect_lock.lock().await;

    // Replace only this server's connection (e.g. after webview reload). Out of
    // the map under the lock, torn down outside it.
    let old = state.connections.write().await.remove(&address);
    if let Some(old) = old {
        teardown(state, &app_handle, &address, old).await;
        info!(server = %address, "cleaned up stale connection before reconnecting");
    }

    // Signal stores are this connection's own, always: the server reassigns
    // user ids on restart, and libsignal pins identities to "user_N", so a kept
    // store would reject the new holder of an old id. What an account keeps
    // across connections is only its identity key, from its vault.
    let signal = Arc::new(std::sync::Mutex::new(SignalState::default()));

    let (host, port) = parse_address(&address)?;

    // QUIC and its control stream, or the TCP fallback when UDP does not get
    // through (every phase bounded, see transport.rs)
    let (
        crate::transport::Link {
            mut conn,
            mut control_send,
            mut control_recv,
        },
        first_pin,
    ) = crate::transport::connect(&host, port, accept_invalid_certs).await?;
    // A self-signed server met for the first time: what was pinned, for the
    // person to compare with the operator's `voipc-server cert fingerprint`
    if let Some(fingerprint) = first_pin {
        emit_server(
            &app_handle,
            &address,
            "tofu-pinned",
            serde_json::json!({ "fingerprint": fingerprint }),
        );
    }

    // Whatever arrives after the sign-in in the same read goes on to the
    // reader with the rest.
    let mut buf = BytesMut::with_capacity(4096);
    // Guests get a fresh identity per connection (ephemeral by design); an
    // account's comes out of its vault during the sign-in, and its stores are
    // made then (`account::sign_in` calls `init_signal` itself).
    let (user_id, session_id, account) = match account {
        Some(args) => {
            let (user_id, session_id, link) = crate::account::sign_in(
                state,
                &app_handle,
                &address,
                &username,
                args,
                &signal,
                &mut control_send,
                &mut control_recv,
                &mut buf,
            )
            .await?;
            (user_id, session_id, Some(link))
        }
        None => {
            let (identity_key, prekey_bundle) = {
                let bundle = init_signal(&signal, &voipc_crypto::generate_identity_key_pair())?;
                (Some(bundle.identity_key.clone()), Some(bundle))
            };
            let auth_msg = ClientMessage::Authenticate {
                username: username.clone(),
                protocol_version: PROTOCOL_VERSION,
                app_version: APP_VERSION.to_string(),
                identity_key,
                prekey_bundle,
                account: None,
            };
            let data = encode_client_msg(&auth_msg)
                .map_err(|e| format!("Failed to encode auth: {}", e))?;
            control_send
                .write_all(&data)
                .await
                .map_err(|e| format!("Failed to send auth: {}", e))?;

            // Read until we get the Authenticated or AuthError response
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
                            accounts,
                            ..
                        } => {
                            // A guest on a relay with accounts: the UI can offer one.
                            if let Some(accounts) = accounts {
                                emit_server(&app_handle, &address, "relay-accounts", accounts);
                            }
                            break (user_id, session_id);
                        }
                        ServerMessage::AuthError { reason } => {
                            return Err(format!("Authentication failed: {}", reason));
                        }
                        ServerMessage::Refused { ref text, .. } => {
                            note_refusal(&app_handle, &address, &msg);
                            return Err(text.clone());
                        }
                        ServerMessage::AuthStep(AuthStep::AccountRequired { .. }) => {
                            return Err(crate::account::ACCOUNT_REQUIRED.into());
                        }
                        other => {
                            warn!("unexpected message during auth: {:?}", other);
                        }
                    }
                }
            };
            (user_id, session_id, None)
        }
    };

    info!(user_id, session_id, "authenticated with server");

    // The Signal state is this connection's own from birth, so all it needs
    // now is to know who we are here.
    {
        let mut sig = signal.lock().map_err(|e| e.to_string())?;
        sig.own_user_id = Some(user_id);
        // libsignal binds both parties' ids into every pairwise message
        if let Some(stores) = sig.stores.as_mut() {
            stores.own_user_id = user_id;
        }
    }

    // No playback stream yet: the mixer opens one when this connection takes
    // voice, and nothing here is audible before that.
    let output_device = state.settings.read().await.output_device.clone();
    let playback_restart = Arc::new(AtomicBool::new(false));
    // The device tells the mixer it took a frame, so the mixer refills on the
    // device's clock instead of on a timer that drifts against it.
    let playback_wake = Arc::new(tokio::sync::Notify::new());
    let output_device_live = Arc::new(std::sync::Mutex::new(output_device));
    let server: Arc<str> = Arc::from(address.as_str());
    let is_voice = Arc::new(AtomicBool::new(false));
    let voice_asked_at = Arc::new(AtomicU64::new(0));

    // Control writer channel.
    //
    // Unbounded, which is the one queue here that has to be. It holds a whole
    // connect — on a full server that is a pre-key bundle request per person
    // and then a key per person per channel, which is thousands of messages on
    // a large one — and the writer lets them out at the rate the server accepts
    // (`ControlPacer`) rather than all at once. The queue is what decouples the
    // two, and a bounded one does not decouple them at all: the task that
    // produces most of those sends is the control *reader*, so a full queue
    // parks it mid-send and it stops reading the socket, for as long as the
    // pacer takes to drain — while the server, its own queue full, silently
    // drops the keys arriving for us. What bounds it is the other end: every
    // message in here answers something the server sent.
    let (tcp_tx, tcp_rx) = mpsc::unbounded_channel::<Vec<u8>>();
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
    let current_media_key = Arc::new(std::sync::Mutex::new(MediaKeyRing::default()));
    let current_channel_id = Arc::new(AtomicU32::new(0));

    // Screen share video stats
    let screen_video_frames_sent = Arc::new(AtomicU32::new(0));
    let screen_video_bytes_sent = Arc::new(AtomicU64::new(0));
    let screen_video_frames_received = Arc::new(AtomicU32::new(0));
    let screen_video_frames_dropped = Arc::new(AtomicU32::new(0));
    let screen_video_bytes_received = Arc::new(AtomicU64::new(0));
    let screen_video_resolution = Arc::new(AtomicU32::new(0));

    // Video decode channel — assembled video frames sent to a blocking decode task
    // to avoid stalling the UDP receiver (which also handles voice).
    // Tuple: (frame_data, is_keyframe, gap_before), in order, so the decode task
    // sees each loss exactly where it happened.
    let (video_decode_tx, video_decode_rx) = mpsc::channel::<(Vec<u8>, bool, bool)>(64);

    // Render suppression flag — set by the decode task while its reference chain
    // is broken; the stream receiver re-requests a keyframe while it is set.
    let needs_keyframe = Arc::new(AtomicBool::new(false));

    // Last frame-loss signal for our own share (viewer reports, our own path
    // stats); read by the encode thread to step quality down. The tally decides
    // which viewer reports count as loss.
    let share_loss_ms = Arc::new(AtomicU64::new(0));
    let share_loss_tally = Arc::new(std::sync::Mutex::new(LossTally::default()));
    // People watching our share, as the server last counted them. The tally's
    // majority reads it, and the capture task sends nothing while it is 0 —
    // capture may run for the sharer's own preview alone.
    let share_viewers = Arc::new(AtomicU32::new(0));

    // Shared screen share state — created early so the control reader can reset on channel change
    let screen_share_active = Arc::new(AtomicBool::new(false));
    let watching_user_id_shared = Arc::new(AtomicU32::new(0));
    // Codec of the share we are watching (VideoCodec as u8), set from
    // WatchingScreenShare before its first frame arrives.
    let watching_codec = Arc::new(AtomicU8::new(voipc_protocol::types::VideoCodec::H264 as u8));

    // Per-user volume control — shared between voice mixer and commands
    let user_volumes: Arc<std::sync::Mutex<HashMap<u32, f32>>> =
        Arc::new(std::sync::Mutex::new(HashMap::new()));
    // Per-user effect the listener chose, same sharing, same lifetime
    let user_fx: Arc<std::sync::Mutex<HashMap<u32, crate::app_state::LaneFx>>> =
        Arc::new(std::sync::Mutex::new(HashMap::new()));
    let source_levels: Arc<std::sync::Mutex<HashMap<u32, f32>>> =
        Arc::new(std::sync::Mutex::new(HashMap::new()));

    // Proximity chat: positions and the current channel's mode. Seeded from
    // the persisted client settings; the channel's mode arrives with the
    // channel list.
    let spatial = {
        let s = state.settings.read().await;
        Arc::new(std::sync::Mutex::new(crate::app_state::SpatialState {
            enabled: s.spatial_audio,
            screen_audio_spatial: s.screen_audio_spatial,
            ..Default::default()
        }))
    };
    let channels_snapshot: Arc<std::sync::Mutex<Vec<voipc_protocol::types::ChannelInfo>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));

    // Per-user jitter buffers + decoders — UDP receiver pushes, mixer pops
    let mix_sources: MixSources = Arc::new(std::sync::Mutex::new(HashMap::new()));

    // Spawn background tasks. Sending and receiving media is all that
    // depends on the transport.
    let tunnel = conn.is_tunnel();
    let (udp_send_handle, video_send_handle, screen_audio_send_handle, datagram_in, video_in) =
        match &mut conn {
            Conn::Quic(quic) => {
                let connection = &quic.connection;
                (
                    tokio::spawn(datagram_sender_task(connection.clone(), voice_rx)),
                    tokio::spawn(video_stream_sender_task(connection.clone(), video_rx)),
                    tokio::spawn(datagram_sender_task(connection.clone(), screen_audio_rx)),
                    DatagramIn::Quic(connection.clone()),
                    VideoIn::quic(connection.clone()),
                )
            }
            Conn::Tunnel(lanes) => (
                tokio::spawn(tunnel_datagram_task(lanes.datagrams.clone(), voice_rx)),
                tokio::spawn(tunnel_video_task(lanes.video.clone(), video_rx)),
                tokio::spawn(tunnel_datagram_task(
                    lanes.datagrams.clone(),
                    screen_audio_rx,
                )),
                DatagramIn::Tunnel(lanes.datagrams_in.take().expect("taken once")),
                VideoIn::Tunnel(lanes.video_in.take().expect("taken once")),
            ),
        };
    let writer_handle = tokio::spawn(control_writer_task(control_send, tcp_rx));
    let reader_handle = tokio::spawn(control_reader_task(
        control_recv,
        buf,
        app_handle.clone(),
        current_media_key.clone(),
        current_channel_id.clone(),
        signal.clone(),
        tcp_tx.clone(),
        user_id,
        screen_share_active.clone(),
        watching_user_id_shared.clone(),
        watching_codec.clone(),
        share_loss_ms.clone(),
        share_loss_tally.clone(),
        share_viewers.clone(),
        spatial.clone(),
        channels_snapshot.clone(),
        server.clone(),
        is_voice.clone(),
        voice_asked_at.clone(),
        transmitting.clone(),
        account.clone(),
    ));
    if let Some(link) = &account {
        crate::account::after_connect(&app_handle, &address, link, &tcp_tx).await;
    }
    let video_decode_handle = tokio::task::spawn_blocking({
        let app_handle = app_handle.clone();
        let watching_uid = watching_user_id_shared.clone();
        let watch_codec = watching_codec.clone();
        let video_res = screen_video_resolution.clone();
        let needs_kf = needs_keyframe.clone();
        let server = server.clone();
        move || {
            video_decode_render_task(
                video_decode_rx,
                app_handle,
                watching_uid,
                watch_codec,
                video_res,
                needs_kf,
                server,
            )
        }
    });

    // Voice quality stats (read by the get_voice_stats command)
    let voice_frames_played = Arc::new(AtomicU32::new(0));
    let voice_frames_lost = Arc::new(AtomicU32::new(0));

    let udp_recv_handle = tokio::spawn(datagram_receiver_task(
        datagram_in,
        tunnel,
        app_handle.clone(),
        mix_sources.clone(),
        screen_audio_recv_count.clone(),
        current_media_key.clone(),
        current_channel_id.clone(),
        spatial.clone(),
        server.clone(),
        is_voice.clone(),
    ));
    let video_recv_handle = tokio::spawn(video_stream_receiver_task(
        video_in,
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

    // Voice mixer — pops one 20ms frame per user whenever the playback ring
    // has room, mixes, and feeds it. Owns the playback stream, which it holds
    // only while this connection has voice (rebuilds it on error).
    let mixer_handle = tokio::spawn(voice_mixer_task(
        mix_sources,
        playback_restart.clone(),
        playback_wake,
        output_device_live.clone(),
        state.is_deafened.clone(),
        user_volumes.clone(),
        user_fx.clone(),
        source_levels.clone(),
        spatial.clone(),
        state.master_volume.clone(),
        voice_frames_played.clone(),
        voice_frames_lost.clone(),
        app_handle.clone(),
        is_voice.clone(),
    ));

    // A ping every 10 s on the media path, either transport: its pong is
    // the latency display, and on the TCP fallback also the keepalive
    let latency_handle = tokio::spawn(latency_task(voice_tx.clone(), session_id));
    // Re-announce our position once a second while syncing it. The beacons
    // have their own sequence counter, their own nonce domain: it must never
    // be the voice one.
    let position_sequence = Arc::new(AtomicU32::new(0));
    let beacon_handle = tokio::spawn(position_beacon_task(
        spatial.clone(),
        voice_tx.clone(),
        current_media_key.clone(),
        session_id,
        current_channel_id.clone(),
        position_sequence.clone(),
    ));
    // Our own uplink's congestion, which viewer reports cannot see. QUIC's
    // path statistics only: over the TCP fallback a congested uplink shows as
    // backpressure on video_tx, which the encoder reads as loss.
    let congestion_handle = match &conn {
        Conn::Quic(quic) => Some(tokio::spawn(congestion_task(
            quic.connection.clone(),
            screen_share_active.clone(),
            share_loss_ms.clone(),
        ))),
        Conn::Tunnel(_) => None,
    };

    // No PTT reset here any more: the holds belong to the voice connection,
    // and another server connecting must not drop them. They are released
    // where voice ends instead (`release_holds`).

    // Store the active connection
    let tcp = tcp_tx.clone();
    let connection = ActiveConnection {
        account: account.clone(),
        user_id,
        username,
        server_address: address.clone(),
        session_id,
        is_muted: state.is_muted.clone(),
        is_deafened: state.is_deafened.clone(),
        signal,
        is_voice,
        voice_asked_at,
        tcp_tx,
        voice_tx,
        video_tx,
        screen_audio_tx,
        conn,
        tasks: [
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
            beacon_handle,
        ]
        .into_iter()
        .chain(congestion_handle)
        .collect(),
        transmitting,
        capture_task: None,
        voice_sequence: Arc::new(AtomicU32::new(0)),
        voice_frames_played,
        voice_frames_lost,
        output_device_live,
        playback_restart,
        is_screen_sharing: false,
        screen_share_codec: voipc_protocol::types::VideoCodec::H264,
        screen_capture_task: None,
        screen_share_active,
        keyframe_requested: Arc::new(AtomicBool::new(false)),
        share_loss_ms,
        share_loss_tally,
        share_viewers,
        share_preview: Arc::new(AtomicBool::new(false)),
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
        voice_mode: state.voice_mode.clone(),
        vad_threshold_db: state.vad_threshold_db.clone(),
        current_audio_level: Arc::new(AtomicI32::new(-9600)),
        noise_suppression: state.noise_suppression.clone(),
        user_volumes,
        user_fx,
        source_levels,
        spatial,
        channels: channels_snapshot,
    };

    state
        .connections
        .write()
        .await
        .insert(address.clone(), connection);

    // Notify server of our mute/deafen state
    if state.is_muted.load(Ordering::Relaxed) {
        let _ = send_tcp_message(&tcp, &ClientMessage::SetMuted { muted: true }).await;
    }
    if state.is_deafened.load(Ordering::Relaxed) {
        let _ = send_tcp_message(&tcp, &ClientMessage::SetDeafened { deafened: true }).await;
    }
    // ...and whether we answer requests for recent chat, so the people here
    // can see who asking would reach.
    let enabled = state.config().share_channel_history;
    let _ = send_tcp_message(&tcp, &ClientMessage::SetHistorySharing { enabled }).await;

    Ok(user_id)
}

/// Close one connection for good: its microphone and screen capture, the
/// server's view of us, every task, and QUIC.
///
/// Called with the entry already out of `AppState::connections`, never under
/// that lock: this awaits the capture tasks, sleeps and closes QUIC for up to
/// half a second, and PTT and every other server would wait behind it.
pub async fn teardown(
    state: &AppState,
    app: &tauri::AppHandle,
    server: &str,
    mut connection: ActiveConnection,
) {
    connection.is_voice.store(false, Ordering::Relaxed);
    if clear_voice(state, server) {
        release_holds(app);
    }

    // Stop any ongoing voice and screen capture. Bounded, as `stop_capture`
    // is: a wedged device must not hang the disconnect — and with it, through
    // the connect lock, every reconnect to this server.
    connection.transmitting.store(false, Ordering::Relaxed);
    connection
        .screen_share_active
        .store(false, Ordering::Relaxed);
    for task in [
        connection.capture_task.take(),
        connection.screen_capture_task.take(),
    ]
    .into_iter()
    .flatten()
    {
        let mut task = task;
        if tokio::time::timeout(std::time::Duration::from_secs(2), &mut task)
            .await
            .is_err()
        {
            warn!("capture task did not stop within 2 s, leaving it behind");
            task.abort();
        }
    }

    // Close capture session (stops screen capture)
    connection.capture_session = None;

    // Send graceful disconnect, then drop tcp_tx so writer can flush and exit
    let _ = send_tcp_message(&connection.tcp_tx, &ClientMessage::Disconnect).await;
    drop(connection.tcp_tx);

    // Give the writer task a moment to flush the disconnect message
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Now abort remaining background tasks
    for task in connection.tasks {
        task.abort();
    }

    // Drop voice/video/screen-audio channels (the aborted mixer task
    // owned and released the playback stream)
    drop(connection.voice_tx);
    drop(connection.video_tx);
    drop(connection.screen_audio_tx);

    // Tell the server right away (otherwise it holds the username until
    // its idle timeout and a quick reconnect gets "already taken")
    connection.conn.close().await;
}

/// Forget that `server` holds voice, if it does. Returns whether it did.
fn clear_voice(state: &AppState, server: &str) -> bool {
    let mut voice = state.voice_server.lock().unwrap_or_else(|p| p.into_inner());
    if voice.as_deref() == Some(server) {
        *voice = None;
        true
    } else {
        false
    }
}

/// Voice ended, so nobody is holding the microphone any more: not the user's
/// key, not a game's. Both flags outlive a connection (they are app state),
/// and a game's hold that survived would sit there refusing to let the user's
/// own key close the next capture.
pub(crate) fn release_holds(app: &tauri::AppHandle) {
    let state = app.state::<AppState>();
    state.ptt_user.store(false, Ordering::Relaxed);
    if state.ptt_sdk.swap(false, Ordering::Relaxed) {
        let _ = app.emit("sdk-transmit", serde_json::json!({ "held": false }));
    }
}

/// Our side of a screen share on a connection that is leaving voice. The
/// capture stops on its flag by itself (nobody here may wait for it), and the
/// portal session goes with it, so the system's "sharing your screen"
/// indicator does not outlive the call. Returns whether a share was running.
fn end_screen_share(c: &mut ActiveConnection) -> bool {
    c.screen_share_active.store(false, Ordering::Relaxed);
    c.screen_capture_task = None;
    c.capture_session = None;
    c.watching_user_id = None;
    std::mem::replace(&mut c.is_screen_sharing, false)
}

/// This connection's server confirmed a voice channel: voice is here now.
///
/// The latest confirmation wins. If another server held voice, it is left
/// right here — its microphone stops, its mixer closes the playback stream,
/// and its server is asked to take us out of the room. This is the one place
/// the backend leaves voice on its own, which also covers joins the UI never
/// asked for (a game's `hello`, the auto-join after creating a channel).
async fn claim_voice(app: &tauri::AppHandle, server: &str, is_voice: &Arc<AtomicBool>) {
    let state = app.state::<AppState>();
    let mut conns = state.connections.write().await;
    // A connection on its way out is no longer the entry under its id, and a
    // join it confirms while dying must not take voice from anybody.
    if !conns
        .get(server)
        .is_some_and(|c| Arc::ptr_eq(&c.is_voice, is_voice))
    {
        return;
    }
    let previous = state
        .voice_server
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .replace(server.to_string());
    let moved = previous.filter(|p| p != server);
    if let Some(other) = moved.as_deref().and_then(|p| conns.get_mut(p)) {
        other.is_voice.store(false, Ordering::Relaxed);
        if other.transmitting.swap(false, Ordering::Relaxed) {
            // So the room we leave hears the phrase end rather than a stall
            let eot = VoicePacket::end_of_transmission(other.session_id, 0);
            let _ = other.voice_tx.try_send(eot.to_bytes());
        }
        if end_screen_share(other) {
            let _ = send_tcp_message(&other.tcp_tx, &ClientMessage::StopScreenShare).await;
        }
        if other.watching_user_id_shared.swap(0, Ordering::Relaxed) != 0 {
            let _ = send_tcp_message(&other.tcp_tx, &ClientMessage::StopWatchingScreenShare).await;
        }
        // A game driving the old room is detached now, before this claim
        // lets a `hello` waiting on this server return and subscribe afresh.
        // Left for the old server's leave to do, the Detached would land on
        // that new subscription and wipe the hello it just completed.
        if disarm_spatial(&other.spatial) {
            state.sdk_event(crate::app_state::SdkEvent::Detached);
        }
        // ponytail: asked once, never retried. A refusal (the join budget is
        // channel_budget+4 with a 2/s refill) leaves us standing in that room
        // with nothing open — the microphone and the speakers there closed
        // above — until the user leaves it themselves.
        let _ = send_tcp_message(
            &other.tcp_tx,
            &ClientMessage::JoinChannel {
                channel_id: 0,
                password: None,
            },
        )
        .await;
        info!(from = ?moved, to = server, "voice moved to another server");
    }
    // Still under the lock: two servers confirming at once must end with one
    // of them audible, and the later claim is the one that clears the other.
    is_voice.store(true, Ordering::Relaxed);
    drop(conns);
    if moved.is_some() {
        release_holds(app);
    }
}

/// This connection is in no voice channel any more — its server confirmed
/// channel 0 (the leave we asked for, a kick, an admin move), or the link
/// died. The microphone closes whatever held it open: a voice-activated
/// capture would otherwise go on sending into nowhere.
async fn leave_voice(
    app: &tauri::AppHandle,
    server: &str,
    is_voice: &Arc<AtomicBool>,
    transmitting: &AtomicBool,
) {
    transmitting.store(false, Ordering::Relaxed);
    is_voice.store(false, Ordering::Relaxed);
    let state = app.state::<AppState>();
    if let Some(c) = state
        .connections
        .write()
        .await
        .get_mut(server)
        .filter(|c| Arc::ptr_eq(&c.is_voice, is_voice))
    {
        end_screen_share(c);
    }
    if clear_voice(&state, server) {
        release_holds(app);
    }
}

/// How long an ask for a voice seat stays good: the server's answer is one
/// round trip away, a game's `hello` waits up to its own join timeout.
const VOICE_ASK_TTL_MS: u64 = 10_000;

/// We are about to ask this connection's server for a voice seat. Called
/// before the request goes out, so the answer cannot beat it.
pub fn ask_voice(asked_at: &AtomicU64) {
    asked_at.store(screenshare::epoch_ms().max(1), Ordering::Relaxed);
}

/// Whether a voice seat the server just gave us was asked for, spending the
/// ask: one ask pays for one seat.
fn take_voice_ask(asked_at: &AtomicU64) -> bool {
    voice_ask_fresh(asked_at.swap(0, Ordering::Relaxed), screenshare::epoch_ms())
}

fn voice_ask_fresh(asked_at: u64, now: u64) -> bool {
    asked_at != 0 && now.saturating_sub(asked_at) < VOICE_ASK_TTL_MS
}

/// Send a client message over the control stream.
/// `send_tcp_message` for a caller that is not async; a failure is a closed
/// connection, which its reader reports.
pub fn send_tcp_message_sync(tcp_tx: &mpsc::UnboundedSender<Vec<u8>>, msg: &ClientMessage) {
    if let Ok(data) = encode_client_msg(msg) {
        let _ = tcp_tx.send(data);
    }
}

pub async fn send_tcp_message(
    tcp_tx: &mpsc::UnboundedSender<Vec<u8>>,
    msg: &ClientMessage,
) -> Result<(), String> {
    let data = encode_client_msg(msg).map_err(|e| format!("Failed to encode message: {}", e))?;
    // Never waits: the queue is unbounded and the pacer downstream is what
    // decides when this actually goes out. Still `async` because every caller
    // is, and because what it does is send a message over a network.
    tcp_tx
        .send(data)
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
        // `::1:9987` would be host `::1`, port 9987 — or host `:`, port 1
        if parts[1].contains(':') {
            return Err("An IPv6 address needs brackets: [host]:port".into());
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

/// Paces our control messages to just under what the server accepts.
///
/// The server charges a token per frame before it decodes one, and a frame
/// that cannot pay is dropped — silently, because answering a flood is one
/// more message going out. An honest client can reach that rate without
/// meaning any harm: arriving on a busy server is a pre-key bundle request per
/// person, then a sender key per person per channel. What it loses there is
/// exactly what it cannot afford to lose — a key that never arrives is a
/// member who cannot read the channel, with nothing on screen to say why.
///
/// So the budget is known at both ends (`CONTROL_MSGS_PER_SEC`) and we stay
/// under it: a burst goes out at once, and the rest waits its turn in the
/// queue that already exists between the app and this task.
struct ControlPacer {
    tokens: f64,
    last: tokio::time::Instant,
}

impl ControlPacer {
    /// Four fifths of what the server allows. The fifth is for the difference
    /// between two clocks and for the keepalives we do not count here.
    const RATE: f64 = voipc_protocol::codec::CONTROL_MSGS_PER_SEC as f64 * 0.8;

    fn new(now: tokio::time::Instant) -> Self {
        Self {
            tokens: Self::RATE,
            last: now,
        }
    }

    /// Take a token for one message and say how long it has to wait for it.
    /// Pure, so the arithmetic is checkable without a clock.
    fn take(&mut self, now: tokio::time::Instant) -> std::time::Duration {
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * Self::RATE).min(Self::RATE);
        self.last = now;
        let wait = if self.tokens < 1.0 {
            let deficit = 1.0 - self.tokens;
            self.tokens = 1.0;
            self.last = now + std::time::Duration::from_secs_f64(deficit / Self::RATE);
            std::time::Duration::from_secs_f64(deficit / Self::RATE)
        } else {
            std::time::Duration::ZERO
        };
        self.tokens -= 1.0;
        wait
    }

    /// Wait until one more message may go out.
    async fn acquire(&mut self) {
        let wait = self.take(tokio::time::Instant::now());
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
    }
}

/// Control writer task: sends encoded messages from the channel to the control
/// stream, at a rate the server will accept (see `ControlPacer`).
async fn control_writer_task<W: AsyncWrite + Unpin>(
    mut write_half: W,
    mut rx: mpsc::UnboundedReceiver<Vec<u8>>,
) {
    let mut pacer = ControlPacer::new(tokio::time::Instant::now());
    while let Some(data) = rx.recv().await {
        pacer.acquire().await;
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
    media_key: Arc<std::sync::Mutex<MediaKeyRing>>,
    channel_id: Arc<AtomicU32>,
    signal: Arc<std::sync::Mutex<SignalState>>,
    tcp_tx: mpsc::UnboundedSender<Vec<u8>>,
    own_user_id: u32,
    screen_share_active: Arc<AtomicBool>,
    watching_user_id_shared: Arc<AtomicU32>,
    watching_codec: Arc<AtomicU8>,
    share_loss_ms: Arc<AtomicU64>,
    share_loss_tally: Arc<std::sync::Mutex<LossTally>>,
    share_viewers: Arc<AtomicU32>,
    spatial: Arc<std::sync::Mutex<crate::app_state::SpatialState>>,
    channels_snapshot: Arc<std::sync::Mutex<Vec<ChannelInfo>>>,
    server: Arc<str>,
    is_voice: Arc<AtomicBool>,
    voice_asked_at: Arc<AtomicU64>,
    transmitting: Arc<AtomicBool>,
    account: Option<Arc<crate::account::AccountLink>>,
) {
    let mut inbound = Inbound::new(std::time::Instant::now());
    'read: loop {
        match read_half.read_buf(&mut buf).await {
            Ok(0) => {
                info!("server closed the control stream");
                emit_server(
                    &app_handle,
                    &server,
                    "connection-lost",
                    serde_json::json!({"reason": "Server closed connection"}),
                );
                break;
            }
            Ok(_) => {}
            Err(e) => {
                error!("control read error: {}", e);
                emit_server(
                    &app_handle,
                    &server,
                    "connection-lost",
                    serde_json::json!({"reason": format!("Connection lost: {}", e)}),
                );
                break;
            }
        }

        loop {
            match try_decode_frame(&mut buf) {
                Ok(Some(payload)) => match decode_server_msg(&payload) {
                    Ok(_) if !inbound.take(std::time::Instant::now()) => {
                        warn!("server sent more than the inbound budget; disconnecting");
                        emit_server(
                            &app_handle,
                            &server,
                            "connection-lost",
                            serde_json::json!({"reason": "This server is flooding the app"}),
                        );
                        break 'read;
                    }
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
                            &watching_codec,
                            &share_loss_ms,
                            &share_loss_tally,
                            &share_viewers,
                            &spatial,
                            &channels_snapshot,
                            &server,
                            &is_voice,
                            &voice_asked_at,
                            &transmitting,
                            account.as_deref(),
                        )
                        .await;
                        crate::account::check_seen(
                            &app_handle,
                            &server,
                            account.as_deref(),
                            &signal,
                            &tcp_tx,
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
                    emit_server(
                        &app_handle,
                        &server,
                        "connection-lost",
                        serde_json::json!({"reason": format!("Protocol error: {}", e)}),
                    );
                    break 'read;
                }
            }
        }
    }
    // A dead link is not a call: the UI stops treating this server as the
    // voice one on `connection-lost`, and so does everything here.
    leave_voice(&app_handle, &server, &is_voice, &transmitting).await;
    info!("control reader task ended");
}

/// Control messages a server may send per second, sustained, and in one
/// burst. A real relay sends a few dozen a second at its busiest (a big
/// channel's join churn, a kept-log catch-up). Nearly every message becomes an
/// event on the webview's one thread, so a relay that sends them at line rate
/// freezes the window — Disconnect button included — while the call on another
/// server plays on. It is cut off instead (H4-21).
const INBOUND_PER_SEC: f64 = 1000.0;
const INBOUND_BURST: f64 = 5000.0;

/// A token bucket over one connection's control messages.
struct Inbound {
    tokens: f64,
    at: std::time::Instant,
}

impl Inbound {
    fn new(now: std::time::Instant) -> Self {
        Self {
            tokens: INBOUND_BURST,
            at: now,
        }
    }

    /// Take one message; false once the server has outrun the budget.
    fn take(&mut self, now: std::time::Instant) -> bool {
        let refill = now.saturating_duration_since(self.at).as_secs_f64() * INBOUND_PER_SEC;
        self.tokens = (self.tokens + refill).min(INBOUND_BURST);
        self.at = now;
        if self.tokens < 1.0 {
            return false;
        }
        self.tokens -= 1.0;
        true
    }
}

/// Replace the cached channel list.
fn set_channels(cache: &Arc<std::sync::Mutex<Vec<ChannelInfo>>>, channels: Vec<ChannelInfo>) {
    if let Ok(mut list) = cache.lock() {
        *list = channels;
    }
}

/// Insert or replace one channel in the cache.
fn upsert_channel(cache: &Arc<std::sync::Mutex<Vec<ChannelInfo>>>, channel: ChannelInfo) {
    if let Ok(mut list) = cache.lock() {
        match list.iter_mut().find(|c| c.channel_id == channel.channel_id) {
            Some(existing) => *existing = channel,
            None => list.push(channel),
        }
    }
}

/// A channel switch: drop the old room and take on the new channel's mode.
/// Mirrors `AudioEngine.onChannelChanged` in the browser backend — a layout
/// (and our own sharing) belongs to the channel it was made in, even when the
/// next channel happens to have the same mode.
fn on_channel_changed(
    spatial: &Arc<std::sync::Mutex<crate::app_state::SpatialState>>,
    cache: &Arc<std::sync::Mutex<Vec<ChannelInfo>>>,
    channel_id: u32,
    app_handle: &tauri::AppHandle,
    server: &str,
    is_voice: &AtomicBool,
) {
    let was_driven = disarm_spatial(spatial);
    // Told rather than inferred: a mod that has gone quiet would otherwise keep
    // receiving who-speaks-when for the channel the user just moved into, right
    // up until its socket dies.
    //
    // Only when a game was actually driving. A `hello` that has to join its
    // channel *causes* this call, and telling the socket it was detached from
    // the join it just asked for left it with no user id: no talk pushes, and
    // `transmit` answered "send hello first" until the mod said hello twice.
    //
    // Not gated on voice like the other SDK events: only the connection a
    // game drives has `sdk_channel` set. When voice moves to another server,
    // `claim_voice` disarms the old one on the spot, so its leave arriving
    // later finds nothing driven here and cannot detach a hello made since.
    app_handle.state::<AppState>().sdk_event(if was_driven {
        crate::app_state::SdkEvent::Detached
    } else {
        crate::app_state::SdkEvent::Moved
    });
    apply_channel_proximity(spatial, cache, channel_id, app_handle, server, is_voice);
}

/// Take the game's hands off a connection's spatial state: the channel it
/// drove is gone, or voice is. Returns whether a game was driving it.
fn disarm_spatial(spatial: &std::sync::Mutex<crate::app_state::SpatialState>) -> bool {
    let mut sp = match spatial.lock() {
        Ok(s) => s,
        Err(poisoned) => poisoned.into_inner(),
    };
    // A game drives one channel: somewhere else its ids match nobody, and
    // leaving culling armed would silence everyone here. The mod's next
    // update is refused and tells it to say hello again.
    let was_driven = sp.sdk_channel.is_some();
    sp.sdk_active = false;
    // Before `sync`, not after: `clear_positions` hands a beaconing game's
    // borrowed sharing back to whatever the user's own switch said, and
    // doing it the other way round re-armed their position sync in the
    // channel they just walked into.
    sp.clear_positions();
    sp.sync = false;
    was_driven
}

/// The members of a roster we would ask for recent chat, picked by
/// `voipc_crypto::history_sources` — this only turns rosters into the pairs it
/// asks for. An empty answer means nobody here shares, and nothing is sent.
fn history_sources_of(users: &[UserInfo], own_user_id: u32) -> HashSet<u32> {
    let pairs: Vec<(u32, bool)> = users
        .iter()
        .map(|u| (u.user_id, u.shares_history))
        .collect();
    voipc_crypto::history_sources(&pairs, own_user_id)
}

/// Whether a channel id names a text channel, according to the list the
/// server sent. Unknown ids read as "not text", which is the safe way round:
/// the voice path is what every existing channel takes.
fn is_text_channel(cache: &Arc<std::sync::Mutex<Vec<ChannelInfo>>>, channel_id: u32) -> bool {
    cache
        .lock()
        .ok()
        .map(|list| list.iter().any(|c| c.channel_id == channel_id && c.text))
        .unwrap_or(false)
}

/// Point the mixer at the proximity mode of the channel we are in. Leaving a
/// proximity channel drops every placement, so a stale layout can never leak
/// into the next channel.
fn apply_channel_proximity(
    spatial: &Arc<std::sync::Mutex<crate::app_state::SpatialState>>,
    cache: &Arc<std::sync::Mutex<Vec<ChannelInfo>>>,
    channel_id: u32,
    app_handle: &tauri::AppHandle,
    server: &str,
    is_voice: &AtomicBool,
) {
    let mode = cache
        .lock()
        .ok()
        .and_then(|list| {
            list.iter()
                .find(|c| c.channel_id == channel_id)
                .map(|c| c.proximity)
        })
        .unwrap_or(ProximityMode::Off);

    let changed = {
        let mut sp = match spatial.lock() {
            Ok(s) => s,
            Err(poisoned) => poisoned.into_inner(),
        };
        if sp.mode == mode {
            return;
        }
        sp.mode = mode;
        if mode == ProximityMode::Off {
            sp.sync = false;
            sp.clear_positions();
        }
        true
    };
    if changed {
        emit_server(
            app_handle,
            server,
            "proximity-mode",
            serde_json::json!({"channel_id": channel_id, "mode": mode}),
        );
        // The same news for a game: `proximity` is the field docs/SDK.md tells
        // a mod to read, and until now it was only ever answered, never pushed.
        // Only from the voice connection — a game plays in that one call.
        if is_voice.load(Ordering::Relaxed) {
            app_handle
                .state::<AppState>()
                .sdk_event(crate::app_state::SdkEvent::Proximity { mode });
        }
    }
}

/// A refused connection's facts, for the "update" panel: which version the
/// server runs and which one we do (`update-needed`).
pub(crate) fn note_refusal(app: &tauri::AppHandle, server: &str, msg: &ServerMessage) {
    if let ServerMessage::Refused {
        code,
        server_protocol,
        server_version,
        ..
    } = msg
    {
        emit_server(
            app,
            server,
            "update-needed",
            serde_json::json!({
                "code": code,
                "server_protocol": server_protocol,
                "server_version": server_version,
                "our_protocol": PROTOCOL_VERSION,
                "our_version": APP_VERSION,
            }),
        );
    }
}

/// Signal stores for `identity` with a fresh signed pre-key and one-time
/// pre-keys, kept in `signal`, and the bundle the server hands to peers.
pub(crate) fn init_signal(
    signal: &Arc<std::sync::Mutex<SignalState>>,
    identity_key_pair: &libsignal_protocol::IdentityKeyPair,
) -> Result<PreKeyBundleData, String> {
    let mut signal = signal.lock().map_err(|e| e.to_string())?;
    info!("initializing Signal Protocol state");
    let registration_id: u32 = rand::random();
    let mut stores = voipc_crypto::SignalStores::new(identity_key_pair, registration_id);
    voipc_crypto::prekey::generate_prekeys(&mut stores, identity_key_pair)
        .map_err(|e| format!("failed to generate prekeys: {e}"))?;
    let bundle = voipc_crypto::prekey::bundle(&stores)
        .map_err(|e| format!("failed to read the pre-key bundle: {e}"))?;
    signal.stores = Some(stores);
    signal.initialized = true;
    info!("Signal Protocol state initialized");
    Ok(bundle)
}

/// Dispatch a server message to the appropriate Tauri event.
/// Also handles E2E encryption orchestration (session establishment, sender key
/// distribution, and automatic decryption of encrypted messages).
#[allow(clippy::too_many_arguments)]
async fn handle_server_message(
    msg: ServerMessage,
    app_handle: &tauri::AppHandle,
    media_key: &Arc<std::sync::Mutex<MediaKeyRing>>,
    channel_id_store: &Arc<AtomicU32>,
    signal: &Arc<std::sync::Mutex<SignalState>>,
    tcp_tx: &mpsc::UnboundedSender<Vec<u8>>,
    own_user_id: u32,
    screen_share_active: &Arc<AtomicBool>,
    watching_user_id_shared: &Arc<AtomicU32>,
    watching_codec: &Arc<AtomicU8>,
    share_loss_ms: &Arc<AtomicU64>,
    share_loss_tally: &Arc<std::sync::Mutex<LossTally>>,
    share_viewers: &AtomicU32,
    spatial: &Arc<std::sync::Mutex<crate::app_state::SpatialState>>,
    channels_snapshot: &Arc<std::sync::Mutex<Vec<ChannelInfo>>>,
    server: &str,
    is_voice: &Arc<AtomicBool>,
    voice_asked_at: &AtomicU64,
    transmitting: &Arc<AtomicBool>,
    account: Option<&crate::account::AccountLink>,
) {
    // Everything a game hears about comes from the voice connection only: a
    // user id here means nothing on the server the game is playing on.
    let in_voice = || is_voice.load(Ordering::Relaxed);
    // Who is which account, for the pins. The server never sends an account
    // behind a pseudonym, so an anonymous channel adds nothing here.
    let seen: &[UserInfo] = match &msg {
        ServerMessage::UserList { users, .. } => users,
        ServerMessage::UserJoined { user } => std::slice::from_ref(user),
        _ => &[],
    };
    if let Some(link) = account {
        let a = link.session().note_roster(seen);
        crate::account::run(app_handle, server, tcp_tx, a).await;
    }
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
                let mut tally = share_loss_tally.lock().unwrap_or_else(|p| {
                    warn!("mutex poisoned, recovering");
                    p.into_inner()
                });
                tally.reports.insert(viewer_user_id, now);
                tally
                    .reports
                    .retain(|_, at| now.saturating_sub(*at) < LOSS_REPORT_TTL_MS);
                let (reporters, viewers) =
                    (tally.reports.len(), share_viewers.load(Ordering::Relaxed));
                drop(tally);
                if majority_reached(reporters, viewers) {
                    share_loss_ms.store(now, Ordering::Relaxed);
                }
                info!(
                    viewer_user_id,
                    frames_dropped,
                    frames_received,
                    reporters,
                    viewers,
                    "viewer reported frame loss"
                );
            }
        }
        ServerMessage::ChannelList { channels } => {
            set_channels(channels_snapshot, channels.clone());
            apply_channel_proximity(
                spatial,
                channels_snapshot,
                channel_id_store.load(Ordering::Relaxed),
                app_handle,
                server,
                is_voice,
            );
            emit_server(app_handle, server, "channel-list", &channels);
        }
        ServerMessage::UserList { channel_id, users } => {
            // In a channel with a log: keep it (with cloud copies on), and
            // read what it kept since last time.
            if let Some(link) = account {
                let log = channels_snapshot
                    .lock()
                    .ok()
                    .and_then(|c| {
                        c.iter()
                            .find(|ch| ch.channel_id == channel_id)
                            .map(|ch| ch.log.clone())
                    })
                    .unwrap_or_default();
                if !log.is_empty() {
                    let a = link.session().enter(&log);
                    crate::account::run(app_handle, server, tcp_tx, a).await;
                }
            }
            // A text channel is a subscription: it does not move us, so none
            // of the channel-change teardown below applies — no media key, no
            // room, no screen share, and the channel we stand in is untouched.
            if is_text_channel(channels_snapshot, channel_id) {
                let newly = {
                    let mut sig = signal.lock().unwrap_or_else(|p| {
                        warn!("mutex poisoned, recovering");
                        p.into_inner()
                    });
                    let newly = sig.channels.join_text(channel_id);
                    // Who a sender key may go to here, and who one may come
                    // from (send_sender_key and handle_sender_key_received
                    // both ask).
                    sig.channels
                        .set_members(channel_id, users.iter().map(|u| u.user_id));
                    if newly {
                        let SignalState {
                            stores, channels, ..
                        } = &mut *sig;
                        channels.reset_channel(stores.as_mut(), own_user_id, channel_id);
                        let sources = history_sources_of(&users, own_user_id);
                        sig.channels.want_history_from(channel_id, sources);
                    }
                    newly
                };
                if newly {
                    info!(channel_id, members = users.len(), "joined text channel");
                }

                request_prekey_bundles_for_users(&users, own_user_id, signal, tcp_tx).await;

                // A voice channel gets its sender keys through the join dance:
                // everyone already there reciprocates when the newcomer's key
                // arrives. Here nobody moved, so the subscriber keys up with
                // the members it already holds a session with.
                let established: Vec<u32> = {
                    let sig = signal.lock().unwrap_or_else(|p| {
                        warn!("mutex poisoned, recovering");
                        p.into_inner()
                    });
                    users
                        .iter()
                        .map(|u| u.user_id)
                        .filter(|uid| *uid != own_user_id && sig.established_sessions.contains(uid))
                        .collect()
                };
                for uid in established {
                    distribute_sender_key_to_user(
                        channel_id,
                        uid,
                        own_user_id,
                        signal,
                        media_key,
                        tcp_tx,
                    )
                    .await;
                }

                emit_server(
                    app_handle,
                    server,
                    "user-list",
                    serde_json::json!({"channel_id": channel_id, "users": users}),
                );
                return;
            }

            // A voice seat we did not ask this server for is refused, before
            // anything here changes. Taking voice ends the call on whichever
            // server had it and opens the microphone into this room — whose
            // members, and so whose media key, the server chooses. An honest
            // server only seats us where we asked (a join, a created channel,
            // an accepted invite, a game's hello); one that already carries
            // our voice may still move us between its own rooms.
            if channel_id != 0
                && !is_voice.load(Ordering::Relaxed)
                && !take_voice_ask(voice_asked_at)
            {
                warn!(
                    server,
                    channel_id, "server seated us in a voice channel we did not join; leaving it"
                );
                let _ = send_tcp_message(
                    tcp_tx,
                    &ClientMessage::JoinChannel {
                        channel_id: 0,
                        password: None,
                    },
                )
                .await;
                emit_server(
                    app_handle,
                    server,
                    "channel-error",
                    serde_json::json!({
                        "reason": "The server put you in a voice channel you did not join — you were taken out of it again"
                    }),
                );
                return;
            }

            // Update the Rust-side channel tracking so commands (PTT, chat, etc.)
            // know which channel we're in. This handles server-initiated moves
            // (create_channel auto-join, kicks, invites, etc.)
            let old_ch = channel_id_store.swap(channel_id, Ordering::Relaxed);
            {
                let mut sig = signal.lock().unwrap_or_else(|p| {
                    warn!("mutex poisoned, recovering");
                    p.into_inner()
                });
                // The room we left is not ours to key any more: its roster,
                // the record of who holds our chain there and the chain itself
                // all go, exactly as walking out of a text channel does. (The
                // roster alone used to go, which left a pending rotation and a
                // usable chain behind for a room we were no longer in.)
                if old_ch != channel_id {
                    let SignalState {
                        stores, channels, ..
                    } = &mut *sig;
                    channels.forget_channel(stores.as_mut(), own_user_id, old_ch);
                }
                sig.channels
                    .set_members(channel_id, users.iter().map(|u| u.user_id));
            }
            if old_ch != channel_id {
                // Clear media key — the new channel's key comes from an
                // existing member over Signal, or we generate one if alone
                // (see below, after the user list is known)
                {
                    let mut mk = media_key.lock().unwrap_or_else(|p| {
                        warn!("mutex poisoned, recovering");
                        p.into_inner()
                    });
                    mk.clear();
                }
                // Reset sender key state for the new channel
                {
                    let mut sig = signal.lock().unwrap_or_else(|p| {
                        warn!("mutex poisoned, recovering");
                        p.into_inner()
                    });
                    let SignalState {
                        stores, channels, ..
                    } = &mut *sig;
                    channels.reset_channel(stores.as_mut(), own_user_id, channel_id);
                    // Ask the members who share, as each one's key arrives
                    let sources = history_sources_of(&users, own_user_id);
                    sig.channels.want_history_from(channel_id, sources);
                }
                info!(old_ch, channel_id, "channel changed via UserList");

                // Stop screen share and watching on channel change
                if screen_share_active.swap(false, Ordering::Relaxed) {
                    // Was sharing — tell server to stop
                    let _ = send_tcp_message(tcp_tx, &ClientMessage::StopScreenShare).await;
                    emit_server(app_handle, server, "screen-share-force-stopped", ());
                    info!("screen share force-stopped due to channel change");
                }
                if watching_user_id_shared.swap(0, Ordering::Relaxed) != 0 {
                    let _ = send_tcp_message(tcp_tx, &ClientMessage::StopWatchingScreenShare).await;
                    emit_server(app_handle, server, "screen-share-force-stopped", ());
                }

                // Voice follows the latest voice channel any server confirms.
                // Before `on_channel_changed`, so what that tells a game comes
                // from the connection that has voice by then.
                if channel_id != 0 {
                    claim_voice(app_handle, server, is_voice).await;
                } else {
                    leave_voice(app_handle, server, is_voice, transmitting).await;
                }

                // The room belongs to the channel we just left; the new
                // channel's mode is what the mixer renders from here on.
                // This is the only place a join reaches the spatial state:
                // the server sends ChannelList once at login and
                // ChannelUpdated only on a settings change.
                on_channel_changed(
                    spatial,
                    channels_snapshot,
                    channel_id,
                    app_handle,
                    server,
                    is_voice,
                );
            } else if channel_id != 0 && !is_voice.load(Ordering::Relaxed) {
                // The same room confirmed again while voice is elsewhere: the
                // leave the handover asked for was refused, and the user has
                // joined this room anew (the ask was checked above — a mere
                // roster refresh of that room does not get here). It is a
                // confirmation like any other — the front end and the browser
                // backend take voice on it too, and all three have to agree on
                // where the call is.
                claim_voice(app_handle, server, is_voice).await;
                // A game the user walked away from may be waiting for them
                // here (sdk.rs `returned`)
                app_handle
                    .state::<AppState>()
                    .sdk_event(crate::app_state::SdkEvent::Moved);
            }

            // Auto-request prekey bundles for users we don't have sessions with.
            // This must happen for ALL channels (including Channel 0) because
            // pairwise sessions are needed for DMs and pokes, not just channel chat.
            request_prekey_bundles_for_users(&users, own_user_id, signal, tcp_tx).await;

            // Media keys never touch the server: one member of a channel
            // generates one; everyone else receives it from an existing member
            // over a pairwise Signal session (distribute_sender_key_to_user →
            // distribute_media_key_to_user).
            //
            // Which member is the same election that picks who re-keys after
            // somebody leaves: the lowest user id in the roster. "Whoever is
            // alone here" would be the obvious rule and was the old one, but
            // two people arriving in the same instant each see the other in
            // their first roster, so neither is alone, neither mints, and the
            // channel has no key at all until somebody leaves and comes back.
            // Ids only ever increase, so the lowest is the longest-present
            // member and a newcomer never mints over a key that already
            // exists; if two do mint at once, `MediaKeyRing::install` settles
            // it the same way on every client.
            let have_key = media_key
                .lock()
                .map(|g| g.has_channel(channel_id))
                .unwrap_or(false);
            let we_mint = {
                let sig = signal.lock().unwrap_or_else(|p| {
                    warn!("mutex poisoned, recovering");
                    p.into_inner()
                });
                sig.channels.media_key_minter(channel_id) == Some(own_user_id)
            };
            if channel_id != 0 && !have_key && we_mint {
                match MediaKey::generate(channel_id, 0, own_user_id) {
                    Ok(key) => {
                        install_media_key(media_key, channel_id, key, app_handle, server);
                        info!(channel_id, members = users.len(), "generated media key");
                    }
                    Err(e) => error!(channel_id, "media key generation failed: {}", e),
                }
            }

            emit_server(
                app_handle,
                server,
                "user-list",
                serde_json::json!({"channel_id": channel_id, "users": users}),
            );
        }
        ServerMessage::UserJoined { ref user } => {
            // Auto-request prekey bundle for new user (all channels, needed for DMs/pokes)
            if user.user_id != own_user_id {
                request_prekey_bundles_for_users(
                    std::slice::from_ref(user),
                    own_user_id,
                    signal,
                    tcp_tx,
                )
                .await;
            }

            // Somebody joined a channel we are in. Nobody else will tell them
            // our sender key: a text channel does not move us, so we get no
            // UserList of our own, and waiting for them to key us first only
            // works if they happen to have no session with us yet. So the
            // member does it, here, for voice and text alike.
            let keyed_up = {
                let own_channel = channel_id_store.load(Ordering::Relaxed);
                let mut sig = signal.lock().unwrap_or_else(|p| {
                    warn!("mutex poisoned, recovering");
                    p.into_inner()
                });
                // The same question the browser asks, in the same words: is
                // this a channel we are in? (It used to be "do we hold a
                // roster for it", which is the same answer by a different
                // route — one question, one predicate.)
                if user.user_id != own_user_id
                    && sig.channels.in_channel(own_channel, user.channel_id)
                {
                    sig.channels.add_member(user.channel_id, user.user_id);
                    sig.established_sessions.contains(&user.user_id)
                } else {
                    false
                }
            };
            // Never for channel 0: it is where everybody stands who is in no
            // voice channel, and there is nothing there to encrypt.
            if keyed_up && user.channel_id != 0 {
                distribute_sender_key_to_user(
                    user.channel_id,
                    user.user_id,
                    own_user_id,
                    signal,
                    media_key,
                    tcp_tx,
                )
                .await;
            }

            emit_server(app_handle, server, "user-joined", user);
        }
        ServerMessage::UserLeft {
            user_id,
            channel_id,
        } => {
            // Leaving a text channel is not leaving the server: the person is
            // still online, still someone we DM, still in our voice channel
            // perhaps. Only that channel's group keys go.
            if is_text_channel(channels_snapshot, channel_id) {
                {
                    let mut sig = signal.lock().unwrap_or_else(|p| {
                        warn!("mutex poisoned, recovering");
                        p.into_inner()
                    });
                    sig.channels.drop_member(channel_id, user_id);
                    if user_id == own_user_id {
                        // Our own chain there goes with the subscription. It
                        // used to be left behind, so re-joining wrote on the
                        // key every former member still had.
                        let SignalState {
                            stores, channels, ..
                        } = &mut *sig;
                        channels.forget_channel(stores.as_mut(), own_user_id, channel_id);
                    } else if sig.channels.is_text(channel_id) {
                        // Somebody else walked out of a channel we are in: the
                        // chain key they hold must stop working, so our next
                        // message there starts a new one (rotate_sender_key_if_stale).
                        sig.channels.note_stale(channel_id);
                    }
                }
                // Out of the channel's log too: the relay took us out of it
                // (1.0, D10), and a rejoin keeps it again
                if user_id == own_user_id {
                    if let Some(link) = account {
                        let log = channels_snapshot
                            .lock()
                            .ok()
                            .and_then(|c| {
                                c.iter()
                                    .find(|ch| ch.channel_id == channel_id)
                                    .map(|ch| ch.log.clone())
                            })
                            .unwrap_or_default();
                        if !log.is_empty() {
                            let a = link.session().leave(&log, false);
                            crate::account::run(app_handle, server, tcp_tx, a).await;
                        }
                    }
                }
                emit_server(
                    app_handle,
                    server,
                    "user-left",
                    serde_json::json!({"user_id": user_id, "channel_id": channel_id}),
                );
                return;
            }

            // Clean up E2E state for departing user
            let left_our_room;
            {
                let mut sig = signal.lock().unwrap_or_else(|p| {
                    warn!("mutex poisoned, recovering");
                    p.into_inner()
                });
                // The pairwise session stays. It is per person and per
                // connection, not per room: they are still someone we DM, and
                // now they may be in text channels with us that a voice leave
                // says nothing about. Forgetting it made their next appearance
                // anywhere run X3DH a second time — two session states for one
                // person, which is the `MAC verification failed` followed by a
                // decrypt "with PREVIOUS session state" — and made us skip
                // handing them our sender key when they turned up next door.
                // Only the channel they left. Walking out of a voice room says
                // nothing about the text channels we still share with them, and
                // forgetting those keys there would leave both sides unable to
                // read the other with nothing left to trigger a re-key.
                sig.channels.drop_member(channel_id, user_id);
                // They kept the chain key of every channel we shared; our next
                // message in the one we stand in starts a fresh one.
                if user_id != own_user_id && channel_id == channel_id_store.load(Ordering::Relaxed)
                {
                    sig.channels.note_stale(channel_id);
                }
                left_our_room = user_id != own_user_id
                    && channel_id == channel_id_store.load(Ordering::Relaxed);
            }
            // Their copy of the room's media key stops working from the next
            // generation on; the sender-key half of the same idea is the
            // `note_stale` above. Channel 0 has no media key to rotate: it is
            // no room, only where people stand who are in none.
            if left_our_room && channel_id != 0 {
                rotate_media_key_if_minter(
                    channel_id,
                    own_user_id,
                    signal,
                    media_key,
                    tcp_tx,
                    app_handle,
                    server,
                )
                .await;
            }

            // Forget where they stood — the id is reused for the next joiner,
            // and so are the extra ways a game had us hearing them, and the
            // glide that was carrying them there.
            if let Ok(mut sp) = spatial.lock() {
                sp.sources.remove(&user_id);
                sp.layers.remove(&user_id);
                sp.motion.remove(&user_id);
            }

            emit_server(
                app_handle,
                server,
                "user-left",
                serde_json::json!({"user_id": user_id, "channel_id": channel_id}),
            );
        }
        ServerMessage::UserMuted { user_id, muted } => {
            emit_server(
                app_handle,
                server,
                "user-muted",
                serde_json::json!({"user_id": user_id, "muted": muted}),
            );
            if in_voice() {
                app_handle
                    .state::<AppState>()
                    .sdk_event(SdkEvent::Muted { user_id, muted });
            }
        }
        ServerMessage::UserHistorySharing { user_id, enabled } => {
            emit_server(
                app_handle,
                server,
                "user-history-sharing",
                serde_json::json!({"user_id": user_id, "enabled": enabled}),
            );
        }
        ServerMessage::UserDeafened { user_id, deafened } => {
            emit_server(
                app_handle,
                server,
                "user-deafened",
                serde_json::json!({"user_id": user_id, "deafened": deafened}),
            );
            if in_voice() {
                app_handle
                    .state::<AppState>()
                    .sdk_event(SdkEvent::Deafened { user_id, deafened });
            }
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
            emit_server(
                app_handle,
                server,
                "connection-lost",
                serde_json::json!({"reason": format!("Server shutdown: {}", reason)}),
            );
        }
        ServerMessage::MovedToChannel { channel_id } => {
            info!("moved to channel {}", channel_id);
        }
        ServerMessage::ChannelCreated { channel } => {
            upsert_channel(channels_snapshot, channel.clone());
            emit_server(app_handle, server, "channel-created", &channel);
        }
        ServerMessage::ChannelDeleted { channel_id } => {
            if let Ok(mut list) = channels_snapshot.lock() {
                list.retain(|c| c.channel_id != channel_id);
            }
            {
                let mut sig = signal.lock().unwrap_or_else(|p| {
                    warn!("mutex poisoned, recovering");
                    p.into_inner()
                });
                let own = sig.own_user_id.unwrap_or(0);
                let SignalState {
                    stores, channels, ..
                } = &mut *sig;
                channels.forget_channel(stores.as_mut(), own, channel_id);
            }
            emit_server(
                app_handle,
                server,
                "channel-deleted",
                serde_json::json!({"channel_id": channel_id}),
            );
        }
        ServerMessage::ChannelError { reason } => {
            emit_server(
                app_handle,
                server,
                "channel-error",
                serde_json::json!({"reason": reason.clone()}),
            );
            // A mod waiting for its `hello` join learns why it failed — the
            // one event every connection publishes, because the join it waits
            // for is not on the voice connection yet; it names the server.
            app_handle
                .state::<AppState>()
                .sdk_event(SdkEvent::ChannelError {
                    server: server.to_string(),
                    reason,
                });
        }
        ServerMessage::ChannelUpdated { channel } => {
            upsert_channel(channels_snapshot, channel.clone());
            apply_channel_proximity(
                spatial,
                channels_snapshot,
                channel_id_store.load(Ordering::Relaxed),
                app_handle,
                server,
                is_voice,
            );
            emit_server(app_handle, server, "channel-updated", &channel);
        }
        ServerMessage::Kicked { channel_id, reason } => {
            emit_server(
                app_handle,
                server,
                "kicked",
                serde_json::json!({"channel_id": channel_id, "reason": reason}),
            );
        }
        ServerMessage::ChannelUsers { channel_id, users } => {
            emit_server(
                app_handle,
                server,
                "channel-users",
                serde_json::json!({"channel_id": channel_id, "users": users}),
            );
        }
        ServerMessage::InviteReceived {
            channel_id,
            channel_name,
            invited_by,
        } => {
            emit_server(
                app_handle,
                server,
                "invite-received",
                serde_json::json!({"channel_id": channel_id, "channel_name": channel_name, "invited_by": invited_by}),
            );
        }
        ServerMessage::InviteAccepted {
            channel_id,
            user_id,
        } => {
            emit_server(
                app_handle,
                server,
                "invite-accepted",
                serde_json::json!({"channel_id": channel_id, "user_id": user_id}),
            );
        }
        ServerMessage::InviteDeclined {
            channel_id,
            user_id,
        } => {
            emit_server(
                app_handle,
                server,
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
                    let stores = sig
                        .stores
                        .as_mut()
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
                            let mut sig = signal.lock().unwrap_or_else(|p| {
                                warn!("mutex poisoned, recovering");
                                p.into_inner()
                            });
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

            emit_server(
                app_handle,
                server,
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
                emit_server(
                    app_handle,
                    server,
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
                let _ =
                    window.request_user_attention(Some(tauri::UserAttentionType::Informational));
            }
        }
        // ── Screenshare events ──
        ServerMessage::ScreenShareStarted {
            user_id,
            username,
            resolution,
        } => {
            emit_server(
                app_handle,
                server,
                "screenshare-started",
                serde_json::json!({"user_id": user_id, "username": username, "resolution": resolution}),
            );
        }
        ServerMessage::ScreenShareStopped { user_id } => {
            emit_server(
                app_handle,
                server,
                "screenshare-stopped",
                serde_json::json!({"user_id": user_id}),
            );
        }
        ServerMessage::WatchingScreenShare {
            sharer_user_id,
            codec,
        } => {
            // Before the first fragment arrives: the decode task builds its
            // decoder from this and rebuilds it when the value changes.
            watching_codec.store(codec as u8, Ordering::Relaxed);
            emit_server(
                app_handle,
                server,
                "watching-screenshare",
                serde_json::json!({"sharer_user_id": sharer_user_id, "codec": format!("{codec:?}")}),
            );
        }
        ServerMessage::StoppedWatchingScreenShare { reason } => {
            emit_server(
                app_handle,
                server,
                "stopped-watching-screenshare",
                serde_json::json!({"reason": reason}),
            );
        }
        ServerMessage::ViewerCountChanged { viewer_count } => {
            share_viewers.store(viewer_count, Ordering::Relaxed);
            emit_server(
                app_handle,
                server,
                "viewer-count-changed",
                serde_json::json!({"viewer_count": viewer_count}),
            );
        }
        ServerMessage::KeyframeRequested => {
            emit_server(app_handle, server, "keyframe-requested", ());
        }
        ServerMessage::ScreenShareError { reason } => {
            emit_server(
                app_handle,
                server,
                "screenshare-error",
                serde_json::json!({"reason": reason}),
            );
        }
        // ── E2E Encryption: PreKeyBundle → establish session + distribute sender keys ──
        ServerMessage::PreKeyBundle { user_id, bundle } => {
            // Their identity against the one first seen for their account.
            if let Some(link) = account {
                let a = link.session().check_identity(user_id, &bundle.identity_key);
                crate::account::run(app_handle, server, tcp_tx, a).await;
            }
            handle_prekey_bundle(
                user_id,
                &bundle,
                own_user_id,
                signal,
                media_key,
                tcp_tx,
                channel_id_store,
                (app_handle, server),
            )
            .await;
        }
        ServerMessage::PreKeyBundleUnavailable { user_id } => {
            info!(
                user_id,
                "prekey bundle unavailable — cannot establish E2E session"
            );
            // Remove from pending so we don't loop
            let mut sig = signal.lock().unwrap_or_else(|p| {
                warn!("mutex poisoned, recovering");
                p.into_inner()
            });
            sig.pending_sessions.remove(&user_id);
        }
        ServerMessage::PreKeysLow { .. } => {
            // The relay has handed out most of our one-time pre-keys
            let more = {
                let mut sig = signal.lock().unwrap_or_else(|p| {
                    warn!("mutex poisoned, recovering");
                    p.into_inner()
                });
                sig.stores.as_mut().map(|s| {
                    voipc_crypto::prekey::more_prekeys(s, voipc_crypto::prekey::PREKEY_REFILL_COUNT)
                })
            };
            match more {
                Some(Ok(prekeys)) => {
                    match encode_client_msg(&ClientMessage::UploadPreKeys { prekeys }) {
                        Ok(data) => {
                            let _ = tcp_tx.send(data);
                        }
                        Err(e) => warn!("could not encode the pre-key refill: {e}"),
                    }
                }
                Some(Err(e)) => warn!("could not make more pre-keys: {e}"),
                None => {}
            }
        }
        ServerMessage::DirectMessageUndelivered { target_user_id } => {
            // Between two accounts with cloud copies on, it went into the stored
            // log as well (send_direct_message): they read it when they are back.
            let kept = account.is_some_and(|l| l.session().kept_for(target_user_id));
            emit_server(
                app_handle,
                server,
                "dm-undelivered",
                serde_json::json!({"user_id": target_user_id, "kept": kept}),
            );
        }
        ServerMessage::IdentityKeyChanged {
            user_id,
            new_identity_key,
        } => {
            emit_server(
                app_handle,
                server,
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
                server,
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
                own_user_id,
                channel_id_store.load(Ordering::Relaxed),
                signal,
                app_handle,
                server,
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
                channel_id_store.load(Ordering::Relaxed),
                signal,
                media_key,
                tcp_tx,
                (app_handle, server),
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
                server,
            )
            .await;
        }
        // ── Moderation ──
        ServerMessage::AdminStatus { user_id, is_admin } => {
            emit_server(
                app_handle,
                server,
                "admin-status",
                serde_json::json!({"user_id": user_id, "is_admin": is_admin}),
            );
        }
        ServerMessage::AdminError { reason } => {
            emit_server(
                app_handle,
                server,
                "admin-error",
                serde_json::json!({"reason": reason}),
            );
        }
        ServerMessage::AdminBans { bans } => {
            emit_server(
                app_handle,
                server,
                "admin-bans",
                serde_json::json!({"bans": bans}),
            );
        }
        ServerMessage::Disconnected { reason } => {
            // The server closes the socket next; the UI must not auto-reconnect
            info!("disconnected by server: {}", reason);
            emit_server(
                app_handle,
                server,
                "server-disconnected",
                serde_json::json!({"reason": reason}),
            );
        }
        // ── Channel history hand-off ──
        ServerMessage::ChannelHistoryRequested {
            channel_id,
            from_user_id,
        } => {
            emit_server(
                app_handle,
                server,
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
                channel_id_store.load(Ordering::Relaxed),
                signal,
                app_handle,
                server,
            );
        }
        ServerMessage::Account(reply) => match account {
            Some(link) => crate::account::on_reply(app_handle, server, link, tcp_tx, reply).await,
            None => debug!("account reply on a guest connection, ignoring"),
        },
        ServerMessage::Authenticated { .. }
        | ServerMessage::AuthError { .. }
        | ServerMessage::AuthStep(_)
        | ServerMessage::Refused { .. } => {}
    }
}

/// Decrypt a member's channel-history blob (JSON `{ v, messages }`) and hand
/// the messages to the UI, which validates and merges them.
#[allow(clippy::too_many_arguments)]
fn handle_channel_history_received(
    channel_id: u32,
    from_user_id: u32,
    from_username: &str,
    ciphertext: &[u8],
    message_type: u8,
    own_channel_id: u32,
    signal: &Arc<std::sync::Mutex<SignalState>>,
    app_handle: &tauri::AppHandle,
    server: &str,
) {
    // A conversation arriving from somebody the roster does not put in that
    // channel with us is not history, it is an injection: we file it, show it
    // and hand it on to the next newcomer as `shared`. The two other pairwise
    // paths ask the same question.
    {
        let sig = signal.lock().unwrap_or_else(|p| {
            warn!("mutex poisoned, recovering");
            p.into_inner()
        });
        if !sig
            .channels
            .shares_channel_with(own_channel_id, channel_id, from_user_id)
        {
            debug!(
                from_user_id,
                channel_id, "history from a non-member, dropped"
            );
            return;
        }
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
        let mut sig = signal.lock().unwrap_or_else(|p| {
            warn!("mutex poisoned, recovering");
            p.into_inner()
        });
        sig.established_sessions.insert(from_user_id);
        sig.pending_sessions.remove(&from_user_id);
    }
    let messages = match voipc_crypto::open_history_payload(channel_id, &plaintext) {
        Ok(list) => list,
        Err(e) => {
            warn!(from_user_id, channel_id, "channel history rejected: {}", e);
            return;
        }
    };
    emit_server(
        app_handle,
        server,
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
    tcp_tx: &mpsc::UnboundedSender<Vec<u8>>,
) {
    let mut to_request = Vec::new();

    {
        let mut sig = signal.lock().unwrap_or_else(|p| {
            warn!("mutex poisoned, recovering");
            p.into_inner()
        });
        if !sig.initialized {
            return;
        }
        for user in users {
            // Nobody: a join or leave the server would not name, because the
            // channel hides who is in it. It is a count, not a person.
            if user.user_id == 0 || user.user_id == own_user_id {
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
        info!(
            target_user_id = uid,
            "requesting prekey bundle for E2E session"
        );
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
#[allow(clippy::too_many_arguments)]
async fn handle_prekey_bundle(
    remote_user_id: u32,
    bundle: &PreKeyBundleData,
    own_user_id: u32,
    signal: &Arc<std::sync::Mutex<SignalState>>,
    media_key: &Arc<std::sync::Mutex<MediaKeyRing>>,
    tcp_tx: &mpsc::UnboundedSender<Vec<u8>>,
    channel_id_store: &Arc<AtomicU32>,
    ui: (&tauri::AppHandle, &str),
) {
    // Establish the pairwise session using block_in_place for !Send futures
    let session_result = tokio::task::block_in_place(|| {
        let mut sig = signal.lock().map_err(|e| format!("signal lock: {e}"))?;
        let stores = sig
            .stores
            .as_mut()
            .ok_or_else(|| "Signal not initialized".to_string())?;

        tokio::runtime::Handle::current()
            .block_on(voipc_crypto::session::establish_session(
                stores,
                remote_user_id,
                bundle,
            ))
            .map_err(|e| format!("establish_session failed: {e}"))
    });

    match session_result {
        Ok(()) => {
            info!(remote_user_id, "E2E session established");
            {
                let mut sig = signal.lock().unwrap_or_else(|p| {
                    warn!("mutex poisoned, recovering");
                    p.into_inner()
                });
                sig.pending_sessions.remove(&remote_user_id);
                sig.established_sessions.insert(remote_user_id);
            }

            // Drain any pending direct messages for this user
            drain_pending_dms(remote_user_id, signal, tcp_tx, ui).await;

            // Distribute our sender key (and the channel media key) for the
            // channel we stand in and for every text channel we are in — the
            // server drops a distribution for a channel either of us is not in.
            let mut channels = vec![channel_id_store.load(Ordering::Relaxed)];
            {
                let sig = signal.lock().unwrap_or_else(|p| {
                    warn!("mutex poisoned, recovering");
                    p.into_inner()
                });
                channels.extend(sig.channels.text_channels());
            }
            for channel in channels {
                if channel == 0 {
                    continue;
                }
                distribute_sender_key_to_user(
                    channel,
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
            let mut sig = signal.lock().unwrap_or_else(|p| {
                warn!("mutex poisoned, recovering");
                p.into_inner()
            });
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
    media_key: &Arc<std::sync::Mutex<MediaKeyRing>>,
    tcp_tx: &mpsc::UnboundedSender<Vec<u8>>,
) {
    if send_sender_key(channel_id, target_user_id, own_user_id, signal, tcp_tx).await {
        distribute_media_key_to_user(channel_id, target_user_id, signal, media_key, tcp_tx).await;
    }
}

/// Rotate our own sender key for a channel somebody has left, and hand the new
/// one to the members still there.
///
/// Called before sending, so an idle member never pays for it: the cost is one
/// key per remaining member, and only for whoever actually writes next.
pub async fn rotate_sender_key_if_stale(
    channel_id: u32,
    own_user_id: u32,
    signal: &Arc<std::sync::Mutex<SignalState>>,
    tcp_tx: &mpsc::UnboundedSender<Vec<u8>>,
) {
    let targets: Vec<u32> = {
        let mut sig = signal.lock().unwrap_or_else(|p| {
            warn!("mutex poisoned, recovering");
            p.into_inner()
        });
        let SignalState {
            stores, channels, ..
        } = &mut *sig;
        channels.take_rotation_targets(stores.as_mut(), own_user_id, channel_id)
    };
    if targets.is_empty() {
        return;
    }
    info!(
        channel_id,
        members = targets.len(),
        "rotating sender key after a member left"
    );
    for target_user_id in targets {
        send_sender_key(channel_id, target_user_id, own_user_id, signal, tcp_tx).await;
    }
}

/// Hand our sender key for `channel_id` to one member. Returns whether it went.
async fn send_sender_key(
    channel_id: u32,
    target_user_id: u32,
    own_user_id: u32,
    signal: &Arc<std::sync::Mutex<SignalState>>,
    tcp_tx: &mpsc::UnboundedSender<Vec<u8>>,
) -> bool {
    // The server relays a distribution only between two members of the channel
    // it names, and drops the rest without a word. Recording one of those as
    // distributed is what makes reciprocation skip a member who never received
    // anything — so membership is checked here, once, for every caller.
    {
        let sig = signal.lock().unwrap_or_else(|p| {
            warn!("mutex poisoned, recovering");
            p.into_inner()
        });
        if !sig.channels.is_member(channel_id, target_user_id) {
            debug!(
                target_user_id,
                channel_id, "not a member, sender key not sent"
            );
            return false;
        }
    }

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
                false
            } else {
                info!(target_user_id, channel_id, "sender key distributed");
                let mut sig = signal.lock().unwrap_or_else(|p| {
                    warn!("mutex poisoned, recovering");
                    p.into_inner()
                });
                sig.channels.record_distributed(channel_id, target_user_id);
                true
            }
        }
        Err(e) => {
            warn!(
                target_user_id,
                channel_id, "failed to distribute sender key: {}", e
            );
            false
        }
    }
}

/// Mint the channel's next media key and hand it to whoever is left, if we are
/// the one elected to.
///
/// A member who walks out keeps the AES-256-GCM key of the room they were in,
/// and the relay could go on forwarding them packets — or somebody could have
/// been recording the traffic and be handed the key later. So the key does not
/// outlive the membership it was given for.
///
/// Nobody is asked who should do it: every member elects the lowest remaining
/// user id from the roster they hold. Two members whose rosters disagree for a
/// moment both mint, and `MediaKeyRing::install` settles it the same way on
/// every client. The generation before this one stays usable for a moment so a
/// packet already in flight is not a gap in the audio.
async fn rotate_media_key_if_minter(
    channel_id: u32,
    own_user_id: u32,
    signal: &Arc<std::sync::Mutex<SignalState>>,
    media_key: &Arc<std::sync::Mutex<MediaKeyRing>>,
    tcp_tx: &mpsc::UnboundedSender<Vec<u8>>,
    app_handle: &tauri::AppHandle,
    server: &str,
) {
    let remaining: Vec<u32> = {
        let sig = signal.lock().unwrap_or_else(|p| {
            warn!("mutex poisoned, recovering");
            p.into_inner()
        });
        if sig.channels.media_key_minter(channel_id) != Some(own_user_id) {
            return;
        }
        sig.channels.others_in(channel_id, own_user_id)
    };

    // The one after ours, or the channel's first where we hold none — the
    // member who held it has left and nobody else is going to send one. The
    // rule lives in `MediaKeyRing` because the browser needs the same answer.
    let next_id = {
        let guard = media_key.lock().unwrap_or_else(|p| {
            warn!("mutex poisoned, recovering");
            p.into_inner()
        });
        guard.next_generation(channel_id)
    };

    match MediaKey::generate(channel_id, next_id, own_user_id) {
        Ok(key) => install_media_key(media_key, channel_id, key, app_handle, server),
        Err(e) => {
            error!(channel_id, "media key rotation failed: {}", e);
            return;
        }
    }
    info!(
        channel_id,
        key_id = next_id,
        members = remaining.len(),
        "rotated media key after a member left"
    );
    for target in remaining {
        distribute_media_key_to_user(channel_id, target, signal, media_key, tcp_tx).await;
    }
}

/// Store a media key for voice/video and tell the UI (clears any
/// "waiting for media key" warning).
///
/// `own_channel` is the room we are standing in: the ring refuses a key for
/// anywhere else, because the channel named inside a key is its sender's claim
/// and `has_channel` gates every media path there is.
fn install_media_key(
    media_key: &Arc<std::sync::Mutex<MediaKeyRing>>,
    own_channel: u32,
    key: MediaKey,
    app_handle: &tauri::AppHandle,
    server: &str,
) {
    let (channel_id, key_id) = (key.channel_id, key.key_id);
    let installed = {
        let mut guard = media_key.lock().unwrap_or_else(|p| {
            warn!("media key mutex poisoned — recovering");
            p.into_inner()
        });
        guard.install(key, own_channel)
    };
    if !installed {
        return;
    }
    emit_server(
        app_handle,
        server,
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
    media_key: &Arc<std::sync::Mutex<MediaKeyRing>>,
    tcp_tx: &mpsc::UnboundedSender<Vec<u8>>,
) {
    let key_bytes = {
        let guard = media_key.lock().unwrap_or_else(|p| {
            warn!("media key mutex poisoned — recovering");
            p.into_inner()
        });
        match guard.current() {
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
        Err(e) => warn!(
            target_user_id,
            channel_id, "failed to distribute media key: {}", e
        ),
    }
}

/// Decrypt a media key sent by a channel member and install it if it is for
/// our current channel and not older than what we already hold.
#[allow(clippy::too_many_arguments)]
async fn handle_media_key_received(
    channel_id: u32,
    from_user_id: u32,
    ciphertext: &[u8],
    message_type: u8,
    signal: &Arc<std::sync::Mutex<SignalState>>,
    media_key: &Arc<std::sync::Mutex<MediaKeyRing>>,
    channel_id_store: &Arc<AtomicU32>,
    app_handle: &tauri::AppHandle,
    server: &str,
) {
    let current = channel_id_store.load(Ordering::Relaxed);
    // The same check the sender key makes, and for a bigger prize: this is the
    // key our microphone encrypts under. The server relays a media key only
    // between two members of the channel it names — but the server is the
    // adversary here, so without this anybody who can get a pairwise session
    // with us (which is anybody on the server) hands us the key we then speak
    // under, and the relay forwards our packets to them.
    {
        let sig = signal.lock().unwrap_or_else(|p| {
            warn!("mutex poisoned, recovering");
            p.into_inner()
        });
        if !sig
            .channels
            .shares_channel_with(current, channel_id, from_user_id)
        {
            debug!(
                from_user_id,
                channel_id, "media key from a non-member, dropped"
            );
            return;
        }
    }

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
        let mut sig = signal.lock().unwrap_or_else(|p| {
            warn!("mutex poisoned, recovering");
            p.into_inner()
        });
        sig.established_sessions.insert(from_user_id);
        sig.pending_sessions.remove(&from_user_id);
    }

    if key.channel_id != channel_id || channel_id != current {
        info!(
            from_user_id,
            channel_id, current, "ignoring media key for another channel"
        );
        return;
    }
    // `install` decides: a later generation wins, and within one generation
    // the lower minter does, so two members who disagreed about the roster for
    // a moment converge on the same key instead of going deaf to each other.
    let key_id = key.key_id;
    install_media_key(media_key, current, key, app_handle, server);
    info!(from_user_id, channel_id, key_id, "media key offered");
}

/// Handle a received sender key: decrypt pairwise, process distribution message,
/// and reciprocate by sending our own sender key if needed.
#[allow(clippy::too_many_arguments)]
async fn handle_sender_key_received(
    channel_id: u32,
    from_user_id: u32,
    ciphertext: &[u8],
    message_type: u8,
    own_user_id: u32,
    own_channel_id: u32,
    signal: &Arc<std::sync::Mutex<SignalState>>,
    media_key: &Arc<std::sync::Mutex<MediaKeyRing>>,
    tcp_tx: &mpsc::UnboundedSender<Vec<u8>>,
    ui: (&tauri::AppHandle, &str),
) {
    // The mirror of the check `send_sender_key` makes outbound. The server
    // relays a distribution only between two members — but the server is the
    // adversary here, and without this a stranger with a colluding relay
    // installs a key for a channel they were never in and then writes to it.
    {
        let sig = signal.lock().unwrap_or_else(|p| {
            warn!("mutex poisoned, recovering");
            p.into_inner()
        });
        if !sig
            .channels
            .shares_channel_with(own_channel_id, channel_id, from_user_id)
        {
            debug!(
                from_user_id,
                channel_id, "sender key from a non-member, dropped"
            );
            return;
        }
    }

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
            info!(
                from_user_id,
                channel_id, "sender key received and processed"
            );

            // If PreKeySignalMessage, session was auto-established on our side
            if message_type == 1 {
                let mut sig = signal.lock().unwrap_or_else(|p| {
                    warn!("mutex poisoned, recovering");
                    p.into_inner()
                });
                sig.established_sessions.insert(from_user_id);
                sig.pending_sessions.remove(&from_user_id);
            }

            // Track the received sender key
            {
                let mut sig = signal.lock().unwrap_or_else(|p| {
                    warn!("mutex poisoned, recovering");
                    p.into_inner()
                });
                sig.channels.record_received(channel_id, from_user_id);
            }

            // Reciprocate: send our sender key if we haven't already
            let need_reciprocate = {
                let sig = signal.lock().unwrap_or_else(|p| {
                    warn!("mutex poisoned, recovering");
                    p.into_inner()
                });
                !sig.channels.has_distributed(channel_id, from_user_id)
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
            drain_pending_channel_messages(channel_id, own_user_id, signal, tcp_tx, ui).await;

            // A member whose sender key arrives holds a pairwise session with
            // us (they just used it), so this is the moment to ask them for
            // recent chat — once each, for as many sharers as we lined up.
            let ask = {
                let mut sig = signal.lock().unwrap_or_else(|p| {
                    warn!("mutex poisoned, recovering");
                    p.into_inner()
                });
                let asked = sig.channels.take_history_wanted(channel_id, from_user_id);
                channel_id != 0 && asked
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
            warn!(
                from_user_id,
                channel_id, "failed to process sender key: {}", e
            );
        }
    }
}

/// Drain and send pending direct messages for a specific user whose session was just established.
async fn drain_pending_dms(
    target_user_id: u32,
    signal: &Arc<std::sync::Mutex<SignalState>>,
    tcp_tx: &mpsc::UnboundedSender<Vec<u8>>,
    (app_handle, server): (&tauri::AppHandle, &str),
) {
    // Extract pending DMs for this target, each with the id it was shown under
    // and the destruction timer it was written under
    let pending: Vec<(String, String, Option<u32>)> = {
        let mut sig = signal.lock().unwrap_or_else(|p| {
            warn!("mutex poisoned, recovering");
            p.into_inner()
        });
        let mut remaining = Vec::new();
        let mut to_send = Vec::new();
        let mut expired = 0u32;
        for msg in sig.pending_messages.drain(..) {
            match &msg.target {
                PendingTarget::Direct {
                    target_user_id: tid,
                } if *tid == target_user_id => {
                    // Only send if queued less than 60 seconds ago
                    if msg.queued_at.elapsed().as_secs() < 60 {
                        to_send.push((msg.id, msg.content, msg.ttl_secs));
                    } else {
                        expired += 1;
                    }
                }
                _ => remaining.push(msg),
            }
        }
        if expired > 0 {
            warn!(target_user_id, expired, "dropped expired pending DMs");
            // Shown as sent when it was typed; say that it was not (H4-10)
            emit_server(
                app_handle,
                server,
                "dm-undelivered",
                serde_json::json!({"user_id": target_user_id, "expired": expired}),
            );
        }
        sig.pending_messages = remaining;
        to_send
    };

    for (id, content, ttl_secs) in pending {
        let payload = crate::crypto::envelope(&id, &content, ttl_secs);
        let result = tokio::task::block_in_place(|| {
            let mut sig = signal.lock().map_err(|e| format!("lock: {e}"))?;
            let stores = sig.stores.as_mut().ok_or("not initialized")?;
            tokio::runtime::Handle::current()
                .block_on(voipc_crypto::session::encrypt_message(
                    stores,
                    target_user_id,
                    &payload,
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
    tcp_tx: &mpsc::UnboundedSender<Vec<u8>>,
    (app_handle, server): (&tauri::AppHandle, &str),
) {
    // Extract pending channel messages, each with the id it was shown under and
    // the destruction timer it was written under
    let pending: Vec<(String, String, Option<u32>)> = {
        let mut sig = signal.lock().unwrap_or_else(|p| {
            warn!("mutex poisoned, recovering");
            p.into_inner()
        });
        let mut remaining = Vec::new();
        let mut to_send = Vec::new();
        let mut expired = 0u32;
        for msg in sig.pending_messages.drain(..) {
            match &msg.target {
                PendingTarget::Channel { channel_id: cid } if *cid == channel_id => {
                    if msg.queued_at.elapsed().as_secs() < 60 {
                        to_send.push((msg.id, msg.content, msg.ttl_secs));
                    } else {
                        expired += 1;
                    }
                }
                _ => remaining.push(msg),
            }
        }
        if expired > 0 {
            warn!(
                channel_id,
                expired, "dropped expired pending channel messages"
            );
            emit_server(
                app_handle,
                server,
                "channel-undelivered",
                serde_json::json!({"channel_id": channel_id, "expired": expired}),
            );
        }
        sig.pending_messages = remaining;
        to_send
    };

    if pending.is_empty() {
        return;
    }
    // These were written before we had anybody to send them to, and somebody
    // may have left the channel in between — in which case our chain is stale
    // and the leaver can still read along it. Sending is the moment that costs
    // a rotation, and this is a send; `send_channel_message` does the same
    // thing for a message typed now.
    rotate_sender_key_if_stale(channel_id, own_user_id, signal, tcp_tx).await;

    for (id, content, ttl_secs) in pending {
        let payload = crate::crypto::envelope(&id, &content, ttl_secs);
        let result = tokio::task::block_in_place(|| {
            let mut sig = signal.lock().map_err(|e| format!("lock: {e}"))?;
            let stores = sig.stores.as_mut().ok_or("not initialized")?;
            tokio::runtime::Handle::current()
                .block_on(voipc_crypto::group::encrypt_group_message(
                    stores,
                    own_user_id,
                    channel_id,
                    &payload,
                ))
                .map_err(|e| format!("group encrypt: {e}"))
        });

        match result {
            Ok(ciphertext) => {
                let msg = ClientMessage::SendEncryptedChannelMessage {
                    channel_id,
                    ciphertext,
                };
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
#[allow(clippy::too_many_arguments)]
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
    server: &str,
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
            // A DM carries the same envelope a channel message does since
            // 0.9.0; anything else reads as the text itself.
            let msg = crate::crypto::open_envelope(&plaintext);

            // If this was a PreKeySignalMessage, mark session as established
            if message_type == 1 {
                let mut sig = signal.lock().unwrap_or_else(|p| {
                    warn!("mutex poisoned, recovering");
                    p.into_inner()
                });
                sig.established_sessions.insert(from_user_id);
                sig.pending_sessions.remove(&from_user_id);
            }

            // Emit as a regular plaintext DM event
            emit_server(
                app_handle,
                server,
                "direct-chat-message",
                serde_json::json!({
                    "from_user_id": from_user_id,
                    "from_username": from_username,
                    "to_user_id": to_user_id,
                    "content": msg.text,
                    "timestamp": timestamp,
                    "message_id": msg.id,
                    "ttl_secs": msg.ttl_secs,
                    "encrypted": true,
                }),
            );

            // Flash/blink the window like a poke does (desktop only)
            #[cfg(not(target_os = "android"))]
            if let Some(window) = app_handle.get_webview_window("main") {
                let _ =
                    window.request_user_attention(Some(tauri::UserAttentionType::Informational));
            }
        }
        Err(e) => {
            warn!(from_user_id, "failed to decrypt direct message: {}", e);
            emit_server(
                app_handle,
                server,
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
#[allow(clippy::too_many_arguments)]
fn handle_encrypted_channel_message(
    channel_id: u32,
    user_id: u32,
    username: &str,
    ciphertext: &[u8],
    timestamp: u64,
    own_user_id: u32,
    own_channel_id: u32,
    signal: &Arc<std::sync::Mutex<SignalState>>,
    app_handle: &tauri::AppHandle,
    server: &str,
) {
    // Our own message, echoed back. The local copy was shown when it was sent;
    // a second one only has our own sender chain to decrypt with and would
    // land in our archive as "decryption failed". The DM path already skips it.
    if user_id == own_user_id {
        return;
    }
    // A message for a channel we are not in has no business being shown, let
    // alone written to the archive under that channel's name. Checked before
    // the decrypt and not inside it: folding the two together is what turned
    // an ordinary leave racing an in-flight message into an
    // "[encrypted message — decryption failed]" line in the user's archive,
    // with an unread badge and a sound to go with it.
    {
        let sig = signal.lock().unwrap_or_else(|p| {
            warn!("mutex poisoned, recovering");
            p.into_inner()
        });
        if !sig.channels.in_channel(own_channel_id, channel_id) {
            debug!(channel_id, "dropped a message for a channel we are not in");
            return;
        }
    }

    let result = tokio::task::block_in_place(|| {
        let mut sig = signal.lock().map_err(|e| format!("signal lock: {e}"))?;
        let stores = sig
            .stores
            .as_mut()
            .ok_or_else(|| "Signal not initialized".to_string())?;

        tokio::runtime::Handle::current()
            .block_on(voipc_crypto::group::decrypt_group_message(
                stores, user_id, channel_id, ciphertext,
            ))
            .map_err(|e| format!("decrypt channel msg: {e}"))
    });

    match result {
        Ok(plaintext) => {
            // The id rides inside the ciphertext, so two members sharing their
            // history of the same conversation agree on what is the same message.
            let msg = crate::crypto::open_envelope(&plaintext);
            emit_server(
                app_handle,
                server,
                "channel-chat-message",
                serde_json::json!({
                    "channel_id": channel_id,
                    "user_id": user_id,
                    "username": username,
                    "content": msg.text,
                    "timestamp": timestamp,
                    "message_id": msg.id,
                    // What the sender says this message's life is. The front
                    // end takes the shorter of this and the channel's own
                    // timer — see expiryFor in chat-rules.ts.
                    "ttl_secs": msg.ttl_secs,
                    "encrypted": true,
                }),
            );
        }
        Err(e) => {
            warn!(
                user_id,
                channel_id, "failed to decrypt channel message: {}", e
            );
            emit_server(
                app_handle,
                server,
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
    /// This lane's whole chain — effect, room, gains — so the next frame
    /// carries on from where the last one left off instead of stepping.
    chain: voipc_audio::mixer::SourceChain,
    /// Extra renders of this same voice, in the order the game listed them.
    /// Grown on demand: a chain carries about 22 kB of delay line, so nobody
    /// who is heard once pays for the three they are not.
    layers: Vec<LayerMix>,
    /// The frame a surplus shed dropped after the one it kept, to be faded
    /// into the frame that follows (H3-10).
    shed: Option<Vec<f32>>,
}

impl MixSource {
    fn new() -> anyhow::Result<Self> {
        Ok(Self {
            jitter: voipc_audio::jitter::JitterBuffer::new(2),
            decoder: voipc_audio::decoder::Decoder::new()?,
            eot_received: false,
            last_activity: std::time::Instant::now(),
            chain: voipc_audio::mixer::SourceChain::default(),
            layers: Vec::new(),
            shed: None,
        })
    }
}

/// One extra render of a source: the same decoded frame, mixed again through
/// its own chain, with its own placement, ear and delay.
#[derive(Default)]
struct LayerMix {
    chain: voipc_audio::mixer::SourceChain,
    /// Frames held back by `delay_frames`; empty while the layer is not
    /// delayed, which is the common case and costs nothing.
    ring: std::collections::VecDeque<Vec<f32>>,
}

impl LayerMix {
    /// Put this frame into the delay line and take out whichever one is now
    /// due. `None` means nothing to play yet: the line is still filling, or —
    /// with `pcm` `None` — it has drained after the speaker stopped.
    ///
    /// A delay of zero keeps no line at all, so the overwhelmingly common
    /// layer costs one branch.
    fn delayed(&mut self, pcm: Option<&[f32]>, delay_frames: u8) -> Option<Vec<f32>> {
        if delay_frames == 0 {
            self.ring.clear();
            return None;
        }
        if let Some(pcm) = pcm {
            self.ring.push_back(pcm.to_vec());
        }
        // A shorter delay takes effect now, not at the next pause. The line
        // pops exactly one frame per push, so without this it keeps whatever
        // length it grew to and the layer stays late for the rest of the
        // sentence. Dropping the surplus is a cut, which is what asking for a
        // shorter delay means.
        while self.ring.len() > delay_frames as usize + 1 {
            self.ring.pop_front();
        }
        if self.ring.len() > delay_frames as usize || (pcm.is_none() && !self.ring.is_empty()) {
            self.ring.pop_front()
        } else {
            None
        }
    }
}

/// Mix one source's extra renders into this frame, and say whether any of them
/// put anything there.
///
/// `pcm` is the frame just decoded, or `None` when the speaker has nothing to
/// play — a delayed layer still owes whatever is in its line, which is exactly
/// how a radio double outlives the voice that caused it.
#[allow(clippy::too_many_arguments)]
fn mix_layers(
    layers: &mut Vec<LayerMix>,
    specs: &[voipc_audio::spatial::Source],
    sp: &crate::app_state::SpatialState,
    stereo: &mut [f32],
    pcm: Option<&[f32]>,
    vol: f32,
    drained: bool,
    deafened: bool,
    water: u8,
    reverb: u8,
    now: std::time::Instant,
) -> bool {
    // A game adds and drops layers between ticks. Resizing here is also what
    // frees the chains of a layer it dropped; its reverb tail goes with it,
    // which is the price of not keeping a chain per layer anyone ever had.
    if layers.len() != specs.len() {
        layers.resize_with(specs.len(), LayerMix::default);
    }
    let mut played = false;
    for (layer, spec) in layers.iter_mut().zip(specs) {
        let delayed = layer.delayed(pcm, spec.delay_frames);
        let frame = if spec.delay_frames == 0 {
            pcm
        } else {
            delayed.as_deref()
        };
        match frame {
            Some(f) if !deafened => {
                let g = sp.render_gains(spec, now);
                layer.chain.render(
                    stereo,
                    f,
                    (g.l * vol, g.r * vol),
                    g.lp_a,
                    spec.fx,
                    water,
                    reverb,
                );
                played = true;
            }
            // Nothing this frame: close the squelch and let the tail run.
            // Deafened decodes and drops, exactly as the base render does.
            _ => {
                let mut nothing: [f32; 0] = [];
                let out: &mut [f32] = if deafened { &mut nothing } else { stereo };
                if layer.chain.stop(out, spec.fx, drained, water, reverb) {
                    played = true;
                }
            }
        }
    }
    played
}

/// Set on the key of screen-share audio sources (session_ids are small counters).
const SCREEN_AUDIO_FLAG: u32 = 0x8000_0000;
/// Sources with no packets for this long are dropped (also covers user leave).
const SOURCE_IDLE_PRUNE: std::time::Duration = std::time::Duration::from_secs(60);

type MixSources = Arc<std::sync::Mutex<HashMap<u32, MixSource>>>;

/// Most sources the mixer holds at once — talkers and shares heard in the
/// last [`SOURCE_IDLE_PRUNE`]. The session id a source is keyed by is not
/// covered by the media encryption, so a relay rewriting it could otherwise
/// make one valid packet into a decoder each, without end.
const MAX_MIX_SOURCES: usize = 256;

/// True at most once a second per `last`: a line per packet is fifty a
/// second per speaker while a key is missing — every join, until it arrives.
fn log_due(last: &mut Option<std::time::Instant>) -> bool {
    let now = std::time::Instant::now();
    if last.is_some_and(|t| now.duration_since(t) < std::time::Duration::from_secs(1)) {
        return false;
    }
    *last = Some(now);
    true
}

/// Whether the mixer is at [`MAX_MIX_SOURCES`]; says so once a second.
fn full_sources(map: &HashMap<u32, MixSource>, log: &mut Option<std::time::Instant>) -> bool {
    let full = map.len() >= MAX_MIX_SOURCES;
    if full && log_due(log) {
        warn!(
            sources = map.len(),
            "mixer is full, dropping audio from a new source"
        );
    }
    full
}

/// Device-clocked voice mixer: whenever the playback ring has room, pop one
/// 20ms frame per active source, decode (FEC/PLC on loss), sum with per-user
/// and master gain, and push the mixed frame. Owns the playback stream and
/// rebuilds it when `playback_restart` is set (device error or output device
/// change).
///
/// Holds a stream only while this connection has voice, or runs the settings
/// panel's spatial test. One stream per open server was that many low-latency
/// streams on one device — on Android, battery and fast-track budget — and
/// every mixer drained the process-wide underrun statistics, stealing the
/// voice stream's readings. With no stream it keeps its 20 ms clock, so the
/// jitter buffers still drain.
///
/// Pulled by the device rather than driven by a timer: a 20ms `interval` and
/// the device clock drift against each other, and cpal's ALSA backend asks for
/// every free frame per wake (25ms periods, more when the thread woke late),
/// so a timer-fed ring sits one late tick away from a hole at all times. That
/// hole is zero-filled into the device buffer, which is the crack people hear.
#[allow(clippy::too_many_arguments)]
#[allow(unused_assignments)] // _playback_stream is a hold-to-keep-alive handle
async fn voice_mixer_task(
    sources: MixSources,
    playback_restart: Arc<AtomicBool>,
    wake: Arc<tokio::sync::Notify>,
    output_device_live: Arc<std::sync::Mutex<Option<String>>>,
    is_deafened: Arc<AtomicBool>,
    user_volumes: Arc<std::sync::Mutex<HashMap<u32, f32>>>,
    user_fx: Arc<std::sync::Mutex<HashMap<u32, crate::app_state::LaneFx>>>,
    source_levels: Arc<std::sync::Mutex<HashMap<u32, f32>>>,
    spatial: Arc<std::sync::Mutex<crate::app_state::SpatialState>>,
    master_volume: Arc<AtomicU32>,
    voice_frames_played: Arc<AtomicU32>,
    voice_frames_lost: Arc<AtomicU32>,
    app_handle: tauri::AppHandle,
    is_voice: Arc<AtomicBool>,
) {
    use ringbuf::traits::Observer;
    use voipc_audio::decoder::Decoder;
    use voipc_audio::jitter::{JitterBuffer, JitterFrame};

    /// Least cushion kept in the playback ring, in 20ms frames. Also what is
    /// used until the device has said how much it takes at once. 60ms matches
    /// what the old timer-driven mixer held while audio was flowing, so this
    /// is not a latency change — it is the same depth, never allowed to drain.
    const MIN_FILL_FRAMES: usize = 3;
    /// Runaway guard, and it must stay below the ring's 10-frame capacity: a
    /// cushion that could not fit another whole frame would have `push_slice`
    /// write half of one, and half a stereo frame swaps the channels for the
    /// rest of the session.
    const MAX_FILL_FRAMES: usize = 8;
    /// How long to wait for the device before looking around anyway: a dead
    /// device stops calling back, and `playback_restart` still has to be seen.
    const WAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(20);
    /// How often the device's appetite is re-read.
    const STATS_WINDOW: std::time::Duration = std::time::Duration::from_secs(1);

    // Opened through the restart path below, once this connection is audible
    let mut _playback_stream: Option<voipc_audio::playback::PlaybackStream> = None;
    let mut producer: Option<ringbuf::HeapProd<f32>> = None;
    // Resamplers for output devices that can't run 48kHz — one per channel,
    // each carrying its own interpolation state
    let mut out_rate = 48_000;
    let mut resampler: Option<(
        voipc_audio::resample::Resampler,
        voipc_audio::resample::Resampler,
    )> = None;
    let mut last_restart_attempt: Option<std::time::Instant> = None;
    let mut limiter = voipc_audio::mixer::Limiter::default();
    #[cfg(not(target_os = "android"))]
    let echo_reference = app_handle.state::<AppState>().echo_reference.clone();
    // Frames pushed since this connection stopped being audible
    let mut idle_frames = 0usize;
    let mut error_emitted = false;
    let mut decode_log = None;
    // Interleaved stereo mix for one 20 ms frame
    let mut stereo: Vec<f32> = Vec::new();
    // One frame of the settings panel's spatial test, when it runs
    let mut test_frame: Vec<f32> = Vec::new();
    let mut chan_l: Vec<f32> = Vec::new();
    let mut chan_r: Vec<f32> = Vec::new();
    let mut out_l: Vec<f32> = Vec::new();
    let mut out_r: Vec<f32> = Vec::new();
    let mut resampled: Vec<f32> = Vec::new();
    // The device's appetite over the last two windows. Two rather than one so
    // the reading survives a roll, and rolling rather than an all-time maximum
    // so the outsized first callback of a stream is forgotten again.
    let mut last_stats_roll = std::time::Instant::now();
    let mut request_max = (0u32, 0u32);

    loop {
        let testing = match spatial.lock() {
            Ok(s) => s.test.is_some(),
            Err(poisoned) => poisoned.into_inner().test.is_some(),
        };
        let wanted = is_voice.load(Ordering::Relaxed) || testing;
        if wanted {
            idle_frames = 0;
            if producer.is_none() {
                playback_restart.store(true, Ordering::Relaxed);
            }
        } else if producer.is_some() {
            // Played out rather than cut: what is still in the ring is the
            // tail of the call, or the test's own fade, and dropping the
            // stream under it clicks. A full cushion later the ring holds
            // only what was mixed after.
            idle_frames += 1;
            if idle_frames > MAX_FILL_FRAMES {
                _playback_stream = None;
                producer = None;
                // Rejoining a moment from now must not wait out the throttle
                last_restart_attempt = None;
                info!("playback stream closed: no voice on this connection");
            }
        }

        // ×2: the ring carries interleaved stereo
        let frame_out = (out_rate as usize * 20) / 1000 * 2;
        // Only the stream the voice plays on reads the device's statistics:
        // they are process-wide, and a read resets them.
        if wanted && producer.is_some() && last_stats_roll.elapsed() >= STATS_WINDOW {
            last_stats_roll = std::time::Instant::now();
            request_max = (voipc_audio::take_request_max(), request_max.0);
            let gaps = voipc_audio::take_underruns();
            if gaps > 0 {
                // Never expected: the cushion is sized off this same device's
                // own callbacks. If this fires, it is the crack people hear.
                warn!("playback underruns in the last second: {}", gaps);
            }
        }
        // Enough for the biggest callback this device has taken lately, and a
        // frame in hand. cpal's ALSA backend swallows 40ms+ at a time, WASAPI
        // about 10ms, so this is not a number worth guessing.
        let cushion = (request_max.0.max(request_max.1) as usize + frame_out)
            .clamp(MIN_FILL_FRAMES * frame_out, MAX_FILL_FRAMES * frame_out);
        // Wait until the device has taken enough for another frame to fit
        // under the cushion. With no device at all, fall back to the clock so
        // the jitter buffers still drain and the restart below still runs.
        loop {
            // Read the fill and drop the borrow before any await: the ring's
            // producer half is not Send, and this task is spawned.
            let room = producer.as_ref().map(|p| p.occupied_len() < cushion);
            match room {
                None => {
                    tokio::time::sleep(WAKE_TIMEOUT).await;
                    break;
                }
                Some(true) => break,
                Some(false) => {
                    let _ = tokio::time::timeout(WAKE_TIMEOUT, wake.notified()).await;
                }
            }
            if playback_restart.load(Ordering::Relaxed) {
                break; // the device is gone; stop waiting on its callbacks
            }
        }

        // Rebuild the playback stream if the device died or was switched, or
        // open it for voice. Never for a connection nobody is listening to.
        if wanted && playback_restart.swap(false, Ordering::Relaxed) {
            if last_restart_attempt.is_some_and(|t| t.elapsed() < std::time::Duration::from_secs(1))
            {
                playback_restart.store(true, Ordering::Relaxed); // retry later
            } else {
                last_restart_attempt = Some(std::time::Instant::now());
                let device_name = output_device_live
                    .lock()
                    .map(|d| d.clone())
                    .unwrap_or_default();
                // Drop the old stream before opening the device again
                _playback_stream = None;
                producer = None;
                match voipc_audio::playback::start_playback(
                    device_name.as_deref(),
                    playback_restart.clone(),
                    Some(wake.clone()),
                ) {
                    Ok((stream, prod)) => {
                        out_rate = stream.sample_rate();
                        resampler = (out_rate != 48_000).then(|| {
                            (
                                voipc_audio::resample::Resampler::new(48_000, out_rate),
                                voipc_audio::resample::Resampler::new(48_000, out_rate),
                            )
                        });
                        _playback_stream = Some(stream);
                        producer = Some(prod);
                        // The old device's appetite says nothing about the new one
                        request_max = (0, 0);
                        last_stats_roll = std::time::Instant::now();
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

        // Pull, decode and mix one frame per source. Mixing runs under the
        // same lock as the decode so each source's gain ramp state stays with
        // it — a per-frame gain step would click.
        // Silent while nobody listens here. Every lane's gain ramps to it over
        // one frame, so the old room fades out instead of being played on top
        // of the new one, and the stream closes on silence rather than being
        // cut from under live speech — that cut would click.
        let master = if wanted {
            f32::from_bits(master_volume.load(Ordering::Relaxed))
        } else {
            0.0
        };
        let deafened = is_deafened.load(Ordering::Relaxed);
        let volumes = user_volumes.lock().map(|v| v.clone()).unwrap_or_default();
        let listener_fx = user_fx.lock().map(|v| v.clone()).unwrap_or_default();
        // bernd: the spatial state is locked for the whole 20 ms mix; the
        // writers (room drags, SDK updates) hold it for microseconds
        let mut sp = match spatial.lock() {
            Ok(s) => s,
            Err(poisoned) => poisoned.into_inner(),
        };
        let sdk_room = sp.sdk_room();

        stereo.clear();
        stereo.resize(voipc_protocol::voice::OPUS_FRAME_SIZE * 2, 0.0);
        // Rebuilt from scratch each frame: an entry left behind by a pruned
        // source would light a meter for somebody who is no longer here.
        let mut levels: Vec<(u32, f32)> = Vec::new();
        // One clock for the whole frame: every glide is read against it
        let now = std::time::Instant::now();
        {
            let mut map = match sources.lock() {
                Ok(m) => m,
                Err(poisoned) => poisoned.into_inner(),
            };
            map.retain(|_, s| s.last_activity.elapsed() < SOURCE_IDLE_PRUNE);
            // One frame out of a lane's jitter buffer, concealed if it was lost
            let decode = |jitter: &JitterBuffer, decoder: &mut Decoder, frame: JitterFrame| {
                match frame {
                    JitterFrame::Ready(data) => {
                        voice_frames_played.fetch_add(1, Ordering::Relaxed);
                        decoder.decode(&data)
                    }
                    JitterFrame::Lost => {
                        voice_frames_lost.fetch_add(1, Ordering::Relaxed);
                        match jitter.peek_next() {
                            // The next packet carries in-band FEC for the lost frame
                            Some(next) => decoder.decode_fec(next),
                            None => decoder.decode_lost(),
                        }
                    }
                }
            };
            for (&key, src) in map.iter_mut() {
                let is_screen_audio = key & SCREEN_AUDIO_FLAG != 0;
                let user_id = key & !SCREEN_AUDIO_FLAG;
                // This lane's own controls, or the game's while it drives the
                // mix; a screen share is never given an effect.
                let local = if is_screen_audio || sp.sdk_active {
                    None
                } else {
                    listener_fx.get(&user_id).copied()
                };
                let fx = if is_screen_audio {
                    voipc_audio::spatial::Effect::None
                } else {
                    local.map_or_else(|| sp.effect_for(user_id), |l| l.effect)
                };
                // A game that says the listener is in a cave puts every lane in
                // it; otherwise each lane carries its own.
                let (water, reverb) = match sdk_room {
                    Some(room) if !is_screen_audio => room,
                    _ => local.map_or((0, 0), |l| (l.water, l.reverb)),
                };

                // End of transmission: the buffered tail has drained
                let drained = src.eot_received && src.jitter.is_empty();
                if drained {
                    src.jitter.reset();
                    src.eot_received = false;
                }
                let MixSource {
                    jitter, decoder, ..
                } = src;
                let popped = if drained { None } else { jitter.pop() };
                let pcm = match popped {
                    // Nothing to play: a radio closes its squelch, at once on
                    // an end-of-transmission and after a pause otherwise
                    None => {
                        src.shed = None; // nothing follows it now
                        let mut nothing: [f32; 0] = [];
                        let out: &mut [f32] = if deafened { &mut nothing } else { &mut stereo };
                        src.chain.stop(out, fx, drained, water, reverb);
                        // A delayed layer still owes what is in its line: the
                        // radio double outlives the voice that caused it.
                        let vol = volumes.get(&user_id).copied().unwrap_or(1.0) * master;
                        mix_layers(
                            &mut src.layers,
                            sp.layers_for(user_id),
                            &sp,
                            &mut stereo,
                            None,
                            vol,
                            drained,
                            deafened,
                            water,
                            reverb,
                            now,
                        );
                        continue;
                    }
                    Some(frame) => decode(jitter, decoder, frame),
                };
                let mut pcm = match pcm {
                    Ok(pcm) => pcm,
                    Err(e) => {
                        if log_due(&mut decode_log) {
                            warn!("Opus decode error from source {:#x}: {}", key, e);
                        }
                        continue;
                    }
                };
                if let Some(dropped) = src.shed.take() {
                    voipc_audio::mixer::crossfade_into(&dropped, &mut pcm);
                }
                // A stream that never pauses has no reset to lose latency at,
                // so a standing surplus is shed here instead. Both frames are
                // decoded so Opus runs on, and the cut lands on the quieter
                // one — faded from the frame that would have played, so the
                // joint does not click: at once when the second frame is
                // kept, at the start of the next one when the first is.
                if jitter.take_surplus() {
                    if let Some(Ok(mut next)) = jitter.pop().map(|f| decode(jitter, decoder, f)) {
                        let energy = |pcm: &[f32]| pcm.iter().map(|s| s * s).sum::<f32>();
                        if energy(&next) > energy(&pcm) {
                            voipc_audio::mixer::crossfade_into(&pcm, &mut next);
                            pcm = next;
                        } else {
                            src.shed = Some(next);
                        }
                    }
                }
                if deafened {
                    continue; // decoded to keep the Opus state, then dropped
                }

                let vol = volumes.get(&user_id).copied().unwrap_or(1.0) * master;
                let g = sp.gains_for(user_id, is_screen_audio, now);
                // The listener's own muffle is the filter only, never a level
                // cut: the volume slider sits right beside it in the panel.
                let lp_a = match local {
                    Some(l) if l.muffle > 0 => {
                        g.lp_a.min(voipc_audio::spatial::muffle_lp_a(l.muffle))
                    }
                    _ => g.lp_a,
                };
                src.chain.render(
                    &mut stereo,
                    &pcm,
                    (g.l * vol, g.r * vol),
                    lp_a,
                    fx,
                    water,
                    reverb,
                );
                // Then again, once per extra way this voice is being heard.
                // The meter stays on the base render: one person, one strip.
                mix_layers(
                    &mut src.layers,
                    sp.layers_for(user_id),
                    &sp,
                    &mut stereo,
                    Some(&pcm),
                    vol,
                    drained,
                    deafened,
                    water,
                    reverb,
                    now,
                );
                if !is_screen_audio {
                    levels.push((user_id, src.chain.mix.level));
                }
            }
        }

        if let Ok(mut map) = source_levels.lock() {
            map.clear();
            map.extend(levels.iter().copied());
        }

        // The settings panel's spatial test: a synthetic voice on the test
        // orbit, rendered by the same gains() and the same ramped mix as a
        // real speaker. Always relative to the default listener — the test is
        // about the headphones, not about where the user stands in the room —
        // and it honours the spatial-audio toggle, so flipping that while it
        // runs is the A/B comparison.
        let spatial_enabled = sp.enabled;
        let mut test_finished = false;
        if let Some(test) = sp.test.as_mut() {
            if deafened {
                // Phase frozen: undeafening resumes without a click
                test_finished = test.stopping;
            } else {
                test_frame.resize(voipc_protocol::voice::OPUS_FRAME_SIZE, 0.0);
                voipc_audio::spatial::test_voice_frame(test.sample, &mut test_frame);
                test.sample += test_frame.len() as u64;
                let (target, lp_a) = test.frame_target(
                    spatial_enabled,
                    master,
                    test.started.elapsed().as_secs_f32(),
                );
                voipc_audio::mixer::mix_source_stereo(
                    &mut stereo,
                    &test_frame,
                    &mut test.mix,
                    target,
                    lp_a,
                );
                test_finished = test.stopping;
            }
        }
        if test_finished {
            sp.test = None;
        }
        drop(sp);

        // A quiet frame is still pushed. The ring is what the device eats
        // from, so letting it run dry between talk bursts throws the cushion
        // away and re-rolls the underrun phase at every burst start — and in
        // this pull model an unfed ring never reports room, so the loop would
        // spin. The limiter runs on quiet frames too, so its release carries
        // on between bursts.
        limiter.process(&mut stereo, 2);
        // …and exactly this is what the microphone's echo canceller takes out,
        // from the mixer that is feeding a device: every connection runs one
        #[cfg(not(target_os = "android"))]
        if producer.is_some() {
            echo_reference.push_stereo(&stereo);
        }

        if let Some(p) = producer.as_mut() {
            match resampler.as_mut() {
                Some((rl, rr)) => {
                    // Resample each channel on its own state, then re-interleave
                    chan_l.clear();
                    chan_r.clear();
                    for pair in stereo.as_chunks::<2>().0 {
                        chan_l.push(pair[0]);
                        chan_r.push(pair[1]);
                    }
                    out_l.clear();
                    out_r.clear();
                    rl.process(&chan_l, &mut out_l);
                    rr.process(&chan_r, &mut out_r);
                    resampled.clear();
                    for (l, r) in out_l.iter().zip(out_r.iter()) {
                        resampled.push(*l);
                        resampled.push(*r);
                    }
                    let _ = p.push_slice(&resampled);
                }
                None => {
                    let _ = p.push_slice(&stereo);
                }
            }
        }
    }
}

/// Encrypt and send one position beacon for this client.
///
/// Positions ride the media path like voice: AES-256-GCM under the channel
/// key, so the relay carries 39 opaque bytes and learns nothing but that a
/// member is sharing a position. They have their own sequence counter because
/// the AAD's packet-type byte puts them in their own nonce domain, and because
/// gaps in the voice counter would look like packet loss to receivers.
///
/// Best effort: a full queue or a missing key drops the beacon, and the next
/// one (or the 1 s keepalive) carries the position instead.
fn send_position_parts(
    voice_tx: &mpsc::Sender<Vec<u8>>,
    media_key: &Arc<std::sync::Mutex<MediaKeyRing>>,
    session_id: u32,
    channel_id: &AtomicU32,
    position_sequence: &AtomicU32,
    pos: [f32; 3],
) {
    let (key, stream_id) = {
        let guard = match media_key.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        match guard.current() {
            Some(k) => (k.clone(), guard.stream_id()),
            None => return, // no channel key yet
        }
    };

    let sequence = position_sequence.fetch_add(1, Ordering::Relaxed);
    let aad = voipc_crypto::build_aad(
        channel_id.load(Ordering::Relaxed),
        VoicePacketType::Position as u8,
        session_id,
    );
    let payload = PositionPayload {
        x: pos[0],
        y: pos[1],
        z: pos[2],
    };
    let encrypted = match voipc_crypto::media_encrypt(
        &key,
        stream_id,
        sequence,
        0,
        &aad,
        &payload.to_bytes(),
    ) {
        Ok(bytes) => bytes,
        Err(e) => {
            warn!("position encryption failed: {e}");
            return;
        }
    };
    let packet = VoicePacket::position(session_id, sequence, key.key_id, stream_id, encrypted);
    let _ = voice_tx.try_send(packet.to_bytes());
}

/// How often the beacon task looks at our position: a move is announced on the
/// next tick, so a drag can never exceed ten beacons a second.
const POSITION_TICK: std::time::Duration = std::time::Duration::from_millis(100);
/// Re-announce even a position that has not moved this often, so a member who
/// joins later converges.
const POSITION_KEEPALIVE: std::time::Duration = std::time::Duration::from_secs(1);

/// Sends our position while we are syncing it: within 100 ms of a move, and
/// once a second regardless.
///
/// Beacons are unreliable datagrams and a member who joins later has missed
/// every earlier one, so the keepalive is what makes the room converge.
async fn position_beacon_task(
    spatial: Arc<std::sync::Mutex<crate::app_state::SpatialState>>,
    voice_tx: mpsc::Sender<Vec<u8>>,
    media_key: Arc<std::sync::Mutex<MediaKeyRing>>,
    session_id: u32,
    channel_id: Arc<AtomicU32>,
    position_sequence: Arc<AtomicU32>,
) {
    let mut interval = tokio::time::interval(POSITION_TICK);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_sent = tokio::time::Instant::now() - POSITION_KEEPALIVE;
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let pos = {
                    let mut sp = match spatial.lock() {
                        Ok(s) => s,
                        Err(poisoned) => poisoned.into_inner(),
                    };
                    if !sp.sync || sp.mode == ProximityMode::Off {
                        continue;
                    }
                    // A move goes out on the next tick (≤10/s, the rate the
                    // server relays); otherwise the keepalive carries it.
                    //
                    // While a game is beaconing, every tick goes out whether
                    // the player moved or not. The relay cannot read a
                    // position, but it can count packets — and "ten a second
                    // while walking, one a second while still" tells it when
                    // each member is moving and when they are away from the
                    // keyboard. A constant cadence tells it nothing.
                    let due =
                        sp.beacon || sp.dirty || last_sent.elapsed() >= POSITION_KEEPALIVE;
                    if !due {
                        continue;
                    }
                    sp.dirty = false;
                    sp.listener.pos
                };
                last_sent = tokio::time::Instant::now();
                send_position_parts(
                    &voice_tx,
                    &media_key,
                    session_id,
                    &channel_id,
                    &position_sequence,
                    pos,
                );
            }
            // The link is gone (its datagram sender ended)
            _ = voice_tx.closed() => return,
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

/// Voice / screen-audio packets → the TCP fallback's datagram lane, which
/// goes out ahead of everything else. A full lane drops the packet, like
/// the UDP these replace.
async fn tunnel_datagram_task(lane: mpsc::Sender<Vec<u8>>, mut rx: mpsc::Receiver<Vec<u8>>) {
    while let Some(data) = rx.recv().await {
        if let Err(mpsc::error::TrySendError::Closed(_)) = lane.try_send(data) {
            return;
        }
    }
}

/// Video fragments → the TCP fallback's video lane. It waits for room, so
/// a slow uplink backs up into video_tx, where the encoder sees it as loss
/// and steps the share down (screenshare::FrameProcessor).
async fn tunnel_video_task(lane: mpsc::Sender<Vec<u8>>, mut rx: mpsc::Receiver<Vec<u8>>) {
    while let Some(packet) = rx.recv().await {
        if lane.send(packet).await.is_err() {
            return;
        }
    }
}

/// A viewer's loss report counts for this long; older ones are pruned before
/// the majority is counted (viewers report every 2 s).
const LOSS_REPORT_TTL_MS: u64 = 2_000;

/// Whether enough of the current viewers report loss to step the share down.
/// With no viewer count yet (nothing received), a single report is enough.
fn majority_reached(reporters: usize, viewers: u32) -> bool {
    reporters as u32 >= viewers.div_ceil(2).max(1)
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
/// bernd: a fixed 1% loss floor rather than a loss estimator; if shares still
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

/// A ping on the media path every 10 s, its sequence our send time — the
/// browser's keepalive too. The server answers it with a pong, whose round
/// trip `datagram_receiver_task` shows as the latency. The same on either
/// transport, and on the TCP fallback it is also what keeps the tunnel from
/// looking idle (transport.rs `TUNNEL_IDLE_TIMEOUT`).
async fn latency_task(voice_tx: mpsc::Sender<Vec<u8>>, session_id: u32) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        let ping = VoicePacket::ping(session_id, screenshare::epoch_ms() as u32).to_bytes();
        if let Err(mpsc::error::TrySendError::Closed(_)) = voice_tx.try_send(ping) {
            return;
        }
    }
}

/// Server → client datagrams: voice (0x05), end-of-transmission (0x02) and
/// screen-share audio (0x15), decrypted and fed to the mixer's per-source
/// jitter buffers; also drives the speaking indicator, and turns the pong to
/// our keepalive ping (0x04) into the latency display. Video arrives on its
/// own (`video_stream_receiver_task`). `tunnel`: the link is the TCP fallback,
/// which the latency display says.
#[allow(clippy::too_many_arguments)]
async fn datagram_receiver_task(
    mut input: DatagramIn,
    tunnel: bool,
    app_handle: tauri::AppHandle,
    sources: MixSources,
    screen_audio_recv_count: Arc<AtomicU32>,
    media_key: Arc<std::sync::Mutex<MediaKeyRing>>,
    channel_id: Arc<AtomicU32>,
    spatial: Arc<std::sync::Mutex<crate::app_state::SpatialState>>,
    server: Arc<str>,
    is_voice: Arc<AtomicBool>,
) {
    // A game hears who talks only in the call it is placing people in
    let in_voice = || is_voice.load(Ordering::Relaxed);
    let mut recv_count: u64 = 0;
    let (mut key_log, mut decrypt_log, mut source_log) = (None, None, None);
    // Track last voice packet time per user for speaking timeout
    let mut last_voice_time: HashMap<u32, std::time::Instant> = HashMap::new();
    let mut speaking_timeout = tokio::time::interval(std::time::Duration::from_millis(300));
    speaking_timeout.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    const SPEAKING_TIMEOUT_MS: u128 = 500;

    loop {
        tokio::select! {
            received = input.recv() => {
                let Some(datagram) = received else {
                    break;
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

                        // The key generation and the sender's own nonce prefix,
                        // both from the packet: a rotation leaves packets in
                        // flight under the old key_id, and every sender has its
                        // own stream_id under the one channel key.
                        let key_id = u16::from_be_bytes([buf[9], buf[10]]);
                        let stream_id =
                            u32::from_be_bytes([buf[11], buf[12], buf[13], buf[14]]);

                        let opus_data: Vec<u8> = {
                            let raw_encrypted = &buf[header_size..n];
                            let ch_id = channel_id.load(Ordering::Relaxed);
                            let key_guard = media_key.lock().unwrap_or_else(|poisoned| {
                                warn!("media key mutex poisoned — recovering");
                                poisoned.into_inner()
                            });
                            if let Some(key) = key_guard.get(ch_id, key_id) {
                                let aad = voipc_crypto::build_aad(ch_id, 0x05, session_id);
                                match voipc_crypto::media_decrypt(
                                    key,
                                    stream_id,
                                    sequence,
                                    0,
                                    &aad,
                                    raw_encrypted,
                                ) {
                                    Ok(decrypted) => decrypted,
                                    Err(e) => {
                                        if log_due(&mut decrypt_log) {
                                            warn!(
                                                "Voice decryption failed from session {}: {}",
                                                session_id, e
                                            );
                                        }
                                        continue;
                                    }
                                }
                            } else {
                                if log_due(&mut key_log) {
                                    warn!("Received encrypted voice but no media key available");
                                }
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
                            if !map.contains_key(&session_id) && full_sources(&map, &mut source_log) {
                                continue;
                            }
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
                            emit_server(
                                &app_handle,
                                &server,
                                "user-speaking",
                                serde_json::json!({"user_id": session_id, "speaking": true}),
                            );
                            if in_voice() {
                                app_handle.state::<AppState>().sdk_event(SdkEvent::Talk {
                                    user_id: session_id,
                                    speaking: true,
                                });
                            }
                        }
                    }
                    // Position beacon from a member who syncs their position
                    0x06 => {
                        let header_size = voipc_protocol::voice::ENCRYPTED_VOICE_HEADER_SIZE;
                        if n != voipc_protocol::voice::POSITION_PACKET_SIZE {
                            continue;
                        }
                        // Before the decrypt, not after: while our own layout
                        // is authoritative we are going to throw this away,
                        // and a member beaconing at us costs an AES-GCM open
                        // per packet if we find that out too late.
                        {
                            let sp = match spatial.lock() {
                                Ok(s) => s,
                                Err(poisoned) => poisoned.into_inner(),
                            };
                            if !sp.sync || sp.sdk_active {
                                continue;
                            }
                        }
                        let session_id = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
                        let sequence = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]);

                        let key_id = u16::from_be_bytes([buf[9], buf[10]]);
                        let stream_id =
                            u32::from_be_bytes([buf[11], buf[12], buf[13], buf[14]]);

                        let plaintext = {
                            let ch_id = channel_id.load(Ordering::Relaxed);
                            let key_guard = media_key.lock().unwrap_or_else(|poisoned| {
                                warn!("media key mutex poisoned — recovering");
                                poisoned.into_inner()
                            });
                            let Some(key) = key_guard.get(ch_id, key_id) else { continue };
                            let aad = voipc_crypto::build_aad(
                                ch_id,
                                VoicePacketType::Position as u8,
                                session_id,
                            );
                            match voipc_crypto::media_decrypt(
                                key,
                                stream_id,
                                sequence,
                                0,
                                &aad,
                                &buf[header_size..n],
                            ) {
                                Ok(decrypted) => decrypted,
                                Err(e) => {
                                    if log_due(&mut decrypt_log) {
                                        warn!("position decryption failed from session {session_id}: {e}");
                                    }
                                    continue;
                                }
                            }
                        };
                        let Ok(payload) = PositionPayload::from_bytes(&plaintext) else {
                            continue;
                        };

                        // While we are not syncing, our own layout of the room
                        // is authoritative and peers' positions are ignored.
                        let accepted = {
                            let mut sp = match spatial.lock() {
                                Ok(s) => s,
                                Err(poisoned) => poisoned.into_inner(),
                            };
                            if sp.sync && !sp.sdk_active {
                                let src = sp
                                    .sources
                                    .entry(session_id)
                                    .or_insert_with(voipc_audio::spatial::Source::default);
                                src.pos = [payload.x, payload.y, payload.z];
                                true
                            } else {
                                false
                            }
                        };
                        if accepted {
                            emit_server(
                                &app_handle,
                                &server,
                                "user-position",
                                serde_json::json!({
                                    "user_id": session_id,
                                    "x": payload.x,
                                    "y": payload.y,
                                    "z": payload.z,
                                }),
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
                        emit_server(
                            &app_handle,
                            &server,
                            "user-speaking",
                            serde_json::json!({"user_id": session_id, "speaking": false}),
                        );
                        if in_voice() {
                            app_handle.state::<AppState>().sdk_event(SdkEvent::Talk {
                                user_id: session_id,
                                speaking: false,
                            });
                        }
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
                            let ch_id = channel_id.load(Ordering::Relaxed);
                            if let Some(key) = key_guard.get(ch_id, packet.key_id) {
                                let aad = voipc_crypto::build_aad(ch_id, 0x15, packet.session_id);
                                match voipc_crypto::media_decrypt(
                                    key,
                                    packet.stream_id,
                                    packet.sequence,
                                    0,
                                    &aad,
                                    &packet.opus_data,
                                ) {
                                    Ok(decrypted) => decrypted,
                                    Err(e) => {
                                        if log_due(&mut decrypt_log) {
                                            warn!("Screen audio decryption failed: {}", e);
                                        }
                                        continue;
                                    }
                                }
                            } else {
                                if log_due(&mut key_log) {
                                    warn!("Received encrypted screen audio but no media key");
                                }
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
                            if !map.contains_key(&key) && full_sources(&map, &mut source_log) {
                                continue;
                            }
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
                    // The pong to our keepalive ping (latency_task)
                    0x04 => {
                        if let Ok(pong) = VoicePacket::from_bytes(buf) {
                            let rtt = (screenshare::epoch_ms() as u32).wrapping_sub(pong.sequence);
                            // A wrapped or stale sequence would read as minutes
                            if rtt < 60_000 {
                                emit_server(
                                    &app_handle,
                                    &server,
                                    "latency-update",
                                    serde_json::json!({"ms": rtt, "tcp": tunnel}),
                                );
                            }
                        }
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
                    emit_server(
                        &app_handle,
                        &server,
                        "user-speaking",
                        serde_json::json!({"user_id": user_id, "speaking": false}),
                    );
                    if in_voice() {
                        app_handle
                            .state::<AppState>()
                            .sdk_event(SdkEvent::Talk { user_id, speaking: false });
                    }
                }
            }
        }
    }
}

/// Viewer loss reports to the sharer cover this window.
const LOSS_REPORT_WINDOW: std::time::Duration = std::time::Duration::from_secs(2);

/// Server → client video: the packets of every frame in arrival order
/// (`VideoIn`: QUIC's per-frame streams or the tunnel's messages), fed to the
/// assembler as they arrive.
/// Decrypts, reassembles, hands complete frames to the decode task, requests a
/// keyframe on loss and keeps asking while there is nothing clean to show, and
/// reports the loss to the sharer every 2 s so it can lower its bitrate/fps.
#[allow(clippy::too_many_arguments)]
async fn video_stream_receiver_task(
    mut input: VideoIn,
    video_decode_tx: mpsc::Sender<(Vec<u8>, bool, bool)>,
    media_key: Arc<std::sync::Mutex<MediaKeyRing>>,
    channel_id: Arc<AtomicU32>,
    screen_video_frames_received: Arc<AtomicU32>,
    screen_video_frames_dropped: Arc<AtomicU32>,
    screen_video_bytes_received: Arc<AtomicU64>,
    tcp_tx: mpsc::UnboundedSender<Vec<u8>>,
    watching_user_id: Arc<AtomicU32>,
    needs_keyframe: Arc<AtomicBool>,
) {
    let mut video_assembler = FrameAssembler::new();
    let mut current_video_session: Option<u32> = None;
    let (mut key_log, mut decrypt_log) = (None, None);
    let mut last_keyframe_request = std::time::Instant::now() - std::time::Duration::from_secs(10);
    // A frame went missing since the last one handed to the decode task
    let mut gap = false;
    let mut window_started = std::time::Instant::now();
    let mut window_dropped: u32 = 0;
    let mut window_received: u32 = 0;
    // At most once a second, which is also all the server relays: a request
    // that went unanswered (rate-limited, or its keyframe lost) is made again.
    let request_keyframe = |last: &mut std::time::Instant| {
        let sharer_id = watching_user_id.load(Ordering::Relaxed);
        if sharer_id == 0 || last.elapsed() < std::time::Duration::from_secs(1) {
            return;
        }
        let msg = ClientMessage::RequestKeyframe {
            sharer_user_id: sharer_id,
        };
        if let Ok(data) = encode_client_msg(&msg) {
            let _ = tcp_tx.send(data);
            info!("requested a keyframe from sharer {}", sharer_id);
        }
        *last = std::time::Instant::now();
    };

    while let Some(records) = input.next().await {
        for packet_bytes in records {
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
                let ch_id = channel_id.load(Ordering::Relaxed);
                if let Some(key) = key_guard.get(ch_id, packet.key_id) {
                    let aad = voipc_crypto::build_aad(ch_id, packet_type, packet.session_id);
                    match voipc_crypto::media_decrypt(
                        key,
                        packet.stream_id,
                        packet.frame_id,
                        packet.fragment_index as u32,
                        &aad,
                        &packet.payload,
                    ) {
                        Ok(decrypted) => packet.payload = decrypted,
                        Err(e) => {
                            if log_due(&mut decrypt_log) {
                                warn!("Video decryption failed: {}", e);
                            }
                            continue;
                        }
                    }
                } else {
                    if log_due(&mut key_log) {
                        warn!("Received encrypted video but no media key");
                    }
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

            // A frame was lost: the next one handed on carries the gap, and
            // the decode task suppresses rendering from there
            if result.frame_dropped {
                screen_video_frames_dropped.fetch_add(1, Ordering::Relaxed);
                window_dropped += 1;
                gap = true;
                request_keyframe(&mut last_keyframe_request);
            }

            if let Some((frame_data, is_keyframe)) = result.frame {
                screen_video_frames_received.fetch_add(1, Ordering::Relaxed);
                window_received += 1;
                // Send to decode task — drop if full to avoid stalling voice.
                // Lost here is lost like on the wire.
                match video_decode_tx.try_send((frame_data, is_keyframe, gap)) {
                    Ok(()) => gap = false,
                    Err(_) => {
                        gap = true;
                        screen_video_frames_dropped.fetch_add(1, Ordering::Relaxed);
                        window_dropped += 1;
                        warn!("video decode channel full — dropping assembled frame");
                        request_keyframe(&mut last_keyframe_request);
                    }
                }
            }

            // Keep asking while there is nothing clean to show: the server
            // rate-limits keyframe relays, so the one a join or a loss
            // triggered may never have come.
            if needs_keyframe.load(Ordering::Acquire) || !video_assembler.has_keyframe() {
                request_keyframe(&mut last_keyframe_request);
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
                    let _ = tcp_tx.send(data);
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

/// The most frames decoded between two renders (about 130 ms at 60 fps).
const MAX_DECODE_BATCH: usize = 8;

/// Video decode + render task: runs on a blocking thread to avoid stalling
/// the media receivers. Decodes ALL frames to maintain codec state, but only
/// JPEG-encodes and emits the most recent frame (frame skipping).
///
/// **Render suppression:** When loss breaks the decoder's reference chain, all
/// subsequent delta frames decode to gray/corrupted pixels. Instead of displaying
/// these, we suppress rendering until a keyframe decodes and resets the decoder
/// state. Judged frame by frame in arrival order (`chain_intact`), so a keyframe
/// queued before a loss does not vouch for the frames after it. While suppressed,
/// `needs_keyframe` is set and the stream receiver keeps asking for a keyframe.
/// The viewer sees the last good frame (frozen) instead of gray corruption.
fn video_decode_render_task(
    mut decode_rx: mpsc::Receiver<(Vec<u8>, bool, bool)>,
    app_handle: tauri::AppHandle,
    watching_user_id: Arc<AtomicU32>,
    watching_codec: Arc<AtomicU8>,
    screen_video_resolution: Arc<AtomicU32>,
    needs_keyframe: Arc<AtomicBool>,
    server: Arc<str>,
) {
    let mut decoder: Option<voipc_video::decoder::Decoder> = None;
    let mut buffers = match screenshare::FrameDecodeBuffers::new() {
        Ok(b) => b,
        Err(e) => {
            error!("Failed to init frame decode buffers: {e}");
            return;
        }
    };
    let mut suppress_render = false;
    // The share the current decoder belongs to (sharer, codec); a change in
    // either invalidates its reference frames.
    let mut decoder_for: Option<(u32, voipc_protocol::types::VideoCodec)> = None;
    let mut reported_missing_decoder: Option<voipc_protocol::types::VideoCodec> = None;

    while let Some(first) = decode_rx.blocking_recv() {
        // A different codec cannot be read by this decoder at all, and a
        // different sharer's deltas would decode against the previous share's
        // reference frames. Either way: start over and wait for a keyframe.
        let want_codec =
            voipc_protocol::types::VideoCodec::from_u8(watching_codec.load(Ordering::Relaxed));
        let want_sharer = watching_user_id.load(Ordering::Relaxed);
        if decoder_for.is_some_and(|had| had != (want_sharer, want_codec)) {
            info!("screen share changed (sharer {want_sharer}, {want_codec:?}) — rebuilding the decoder");
            decoder = None;
            suppress_render = true;
        }

        let dec = match decoder.as_mut() {
            Some(d) => d,
            None => match voipc_video::decoder::Decoder::new(want_codec) {
                Ok(d) => {
                    decoder_for = Some((want_sharer, want_codec));
                    reported_missing_decoder = None;
                    decoder.insert(d)
                }
                Err(e) => {
                    warn!("{want_codec:?} decoder creation failed: {e} — skipping frame");
                    suppress_render = true;
                    needs_keyframe.store(true, Ordering::Release);
                    // Tell the user once per codec instead of logging per frame
                    if reported_missing_decoder != Some(want_codec) {
                        reported_missing_decoder = Some(want_codec);
                        emit_server(
                            &app_handle,
                            &server,
                            "screenshare-error",
                            serde_json::json!({
                                "reason": format!(
                                    "This device cannot decode the {want_codec:?} video this share uses"
                                )
                            }),
                        );
                    }
                    continue;
                }
            },
        };

        // ALWAYS decode — maintains codec reference state even when render is suppressed.
        // Skipping decode would cause even more corruption when rendering resumes.
        // Everything queued is decoded in order, but only the latest result is
        // kept for rendering.
        let mut latest_decoded = Vec::new();
        let mut next = Some(first);
        let mut batch = 0;
        while let Some((frame_data, is_keyframe, gap_before)) = next {
            batch += 1;
            let decoded = dec.decode(&frame_data);
            if let Err(e) = &decoded {
                warn!("{want_codec:?} decode error: {}", e);
            }
            let intact = chain_intact(!suppress_render, gap_before, is_keyframe, decoded.is_ok());
            if intact && suppress_render {
                info!("render resumed after keyframe");
            }
            suppress_render = !intact;
            if let Ok(d) = decoded {
                latest_decoded = d;
            }
            // Show a picture every few frames even when the stream outruns
            // the decoder: draining "everything queued" never ends then, and
            // the viewer stays on "Waiting for video stream" for good
            next = if batch < MAX_DECODE_BATCH {
                decode_rx.try_recv().ok()
            } else {
                None
            };
        }
        needs_keyframe.store(suppress_render, Ordering::Release);

        // JPEG-encode and emit only if not suppressed
        if !suppress_render {
            for df in &mut latest_decoded {
                let packed = (df.width << 16) | df.height;
                screen_video_resolution.store(packed, Ordering::Relaxed);
                screenshare::render_frame(df, &app_handle, &mut buffers);
            }
        }
    }
    info!("video decode+render task ended");
}

/// Whether the decoder's reference chain is intact after one more frame: a
/// keyframe that decoded mends it; a gap in front of a frame, or a frame that
/// failed to decode, breaks it.
fn chain_intact(intact: bool, gap_before: bool, is_keyframe: bool, decoded: bool) -> bool {
    decoded && (is_keyframe || (intact && !gap_before))
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
    media_key: Arc<std::sync::Mutex<MediaKeyRing>>,
    channel_id: Arc<AtomicU32>,
    voice_mode: Arc<AtomicU8>,
    vad_threshold_db: Arc<AtomicI32>,
    current_audio_level: Arc<AtomicI32>,
    noise_suppression: Arc<AtomicBool>,
    is_muted: Arc<AtomicBool>,
    voice_sequence: Arc<AtomicU32>,
    sender_lane: Arc<AtomicU32>,
    input_gain: Arc<AtomicU32>,
    app_handle: tauri::AppHandle,
    server: Arc<str>,
) -> tokio::task::JoinHandle<()> {
    tokio::task::spawn_blocking(move || {
        // Whether voice was going out on the previous frame (talk edges)
        let mut was_on_air = false;
        let capture_error = Arc::new(AtomicBool::new(false));
        let (mut _capture_stream, mut consumer) = match voipc_audio::capture::start_capture(
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
        let mut mic_limiter = voipc_audio::mixer::Limiter::default();
        // The echo canceller, fed with what the mixer plays from now on
        #[cfg(not(target_os = "android"))]
        let (mut echo, echo_reference) = {
            let reference = app_handle.state::<AppState>().echo_reference.clone();
            reference.clear();
            (voipc_audio::echo::EchoCanceller::new(), reference)
        };
        let mut accumulated: usize = 0;
        let mut stream_dead = false;
        let mut last_rebuild = std::time::Instant::now();
        // Whether the UI was told the microphone is gone
        let mut capture_error_said = false;
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

        // Our own microphone's lane: the same chain, in the same order, that
        // renders somebody else's voice on the way in.
        let mut mic_chain = voipc_audio::mixer::SourceChain::default();

        info!("capture+encode task started");

        while transmitting.load(Ordering::Relaxed) {
            // Rebuild the capture stream if the device died (unplug etc.)
            // Said only when the reopen fails, as for playback: Android
            // disconnects the stream on every route change, the call's own
            // mode switch included, and a reopen a moment later is no news.
            if capture_error.swap(false, Ordering::Relaxed) && !stream_dead {
                stream_dead = true;
                warn!("capture device error — attempting recovery");
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
                            if std::mem::take(&mut capture_error_said) {
                                let _ = app_handle.emit("audio-device-restored", ());
                            }
                        }
                        Err(e) => {
                            warn!("capture restart failed (retrying): {}", e);
                            if !std::mem::replace(&mut capture_error_said, true) {
                                let _ = app_handle.emit(
                                    "audio-device-error",
                                    serde_json::json!({"error": "capture device error"}),
                                );
                            }
                        }
                    }
                }
                if stream_dead {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                    continue;
                }
            }

            // Read into the remaining portion of pcm_buf
            let read =
                ringbuf::traits::Consumer::pop_slice(&mut consumer, &mut pcm_buf[accumulated..]);
            accumulated += read;

            if accumulated < frame_size {
                // Not enough samples yet — wait ~5ms for more audio data
                std::thread::sleep(std::time::Duration::from_millis(5));
                continue;
            }

            // The speakers' echo out first: RNNoise is non-linear, and after it
            // the echo is no longer the reference passed through a room
            #[cfg(not(target_os = "android"))]
            echo.process(&echo_reference, &mut pcm_buf);

            // Apply noise suppression before VAD and encoding
            denoiser.set_enabled(noise_suppression.load(Ordering::Relaxed));
            let voice = denoiser.process(&mut pcm_buf);

            // Update VAD threshold from shared state (user may adjust in real-time)
            let threshold = vad_threshold_db.load(Ordering::Relaxed) as f32;
            vad.set_threshold_db(threshold);

            // Run VAD to compute audio level (always, for the UI meter)
            let voice_detected = vad.process(&pcm_buf, voice);

            // Store current level for UI (×100 for fixed-point precision)
            let level_fixed = (vad.current_level_db() * 100.0) as i32;
            current_audio_level.store(level_fixed, Ordering::Relaxed);

            // Our own lane, applied here and nowhere else.
            //
            // Below the VAD and the meter: a radio's hiss and its squelch
            // burst sit at or above the default threshold of −40 dB, so a
            // gate that heard them would latch open and transmit forever.
            //
            // Above the on-air gate, and unconditional: the filters and the
            // reverb tail have to keep advancing through silence, exactly as
            // the denoiser does, or the first frame after a pause steps them
            // and clicks. With nothing switched on the chain is bit-exact, so
            // this costs nothing.
            let packed = sender_lane.load(Ordering::Relaxed);
            let fx = voipc_audio::spatial::Effect::from_u8((packed & 0xff) as u8);
            let muffle = ((packed >> 8) & 0xff) as u8;
            mic_chain.render_mono(
                &mut pcm_buf,
                fx,
                if muffle > 0 {
                    voipc_audio::spatial::muffle_lp_a(muffle)
                } else {
                    1.0
                },
                ((packed >> 24) & 0xff) as u8,
                ((packed >> 16) & 0xff) as u8,
            );

            // Check voice mode to decide whether to send
            let mode = crate::app_state::VoiceMode::from_u8(voice_mode.load(Ordering::Relaxed));
            let should_send = match mode {
                crate::app_state::VoiceMode::Ptt => true, // PTT: always send while transmitting
                crate::app_state::VoiceMode::Vad => voice_detected,
                crate::app_state::VoiceMode::AlwaysOn => true,
            };

            // Voice actually on the wire, which is what a mod means by
            // "speaking": `transmitting` is always true in VAD and always-on
            // mode, so only this gate knows. Published on the edges.
            let on_air = should_send && !is_muted.load(Ordering::Relaxed);
            if on_air != was_on_air {
                was_on_air = on_air;
                if !on_air {
                    // Say the phrase ended, exactly as releasing push-to-talk
                    // does. A voice-activated sender otherwise just stops, and
                    // a pause is then indistinguishable from a network stall:
                    // every receiver conceals its way into the silence before
                    // its jitter buffer re-arms, and a radio's squelch waits
                    // out the full idle timeout instead of closing on the end.
                    let eot = VoicePacket::end_of_transmission(session_id, 0);
                    let _ = voice_tx.blocking_send(eot.to_bytes());
                }
                // Not gated on voice like the receive side: a capture only
                // ever starts on the voice connection, and its closing edge
                // has to reach the mod even when voice has just moved on.
                app_handle.state::<AppState>().sdk_event(SdkEvent::Talk {
                    user_id: session_id,
                    speaking: on_air,
                });
            }

            if !on_air {
                // Close the transmission so the next one opens its squelch
                // again. The empty buffer takes the mixer's documented
                // "drop the burst rather than owe it" path: `talking` clears,
                // nothing is written, and the filters keep their state.
                mic_chain.stop(&mut [], fx, true, 0, 0);
                accumulated = 0;
                continue;
            }

            // We have a full frame — encode and send.
            // The sequence counter lives on the connection so it never
            // restarts within a session: a restart would reuse AES-GCM
            // nonces under the channel key and desync receivers' jitter
            // buffers when the EndOfTransmission packet is lost.
            // The input gain is not clamped any more (it would square the
            // peaks before RNNoise, H3-09): the limit is here, last
            mic_limiter.process(&mut pcm_buf, 1);
            let sequence = voice_sequence.fetch_add(1, Ordering::Relaxed);
            match encoder.encode(&pcm_buf) {
                Ok(opus_data) => {
                    let packet = {
                        let key_guard = media_key.lock().unwrap_or_else(|poisoned| {
                            warn!("media key mutex poisoned — recovering");
                            poisoned.into_inner()
                        });
                        let stream_id = key_guard.stream_id();
                        if let Some(key) = key_guard.current() {
                            key_missing_since = None;
                            key_missing_emitted = false;
                            let ch_id = channel_id.load(Ordering::Relaxed);
                            let aad = voipc_crypto::build_aad(ch_id, 0x05, session_id);
                            match voipc_crypto::media_encrypt(
                                key, stream_id, sequence, 0, &aad, &opus_data,
                            ) {
                                Ok(encrypted) => VoicePacket::encrypted_voice(
                                    session_id, sequence, key.key_id, stream_id, encrypted,
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
                            let since =
                                *key_missing_since.get_or_insert_with(std::time::Instant::now);
                            if !key_missing_emitted
                                && since.elapsed() > std::time::Duration::from_secs(2)
                            {
                                key_missing_emitted = true;
                                warn!("no media key for 2s — voice frames are being dropped");
                                emit_server(&app_handle, &server, "media-key-missing", ());
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

        // PTT released (or the stream died) mid-word: a mod must not be left
        // drawing a talking icon forever.
        if was_on_air {
            app_handle.state::<AppState>().sdk_event(SdkEvent::Talk {
                user_id: session_id,
                speaking: false,
            });
        }
        info!("capture+encode task stopped");
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_address_is_split_only_where_it_is_unambiguous() {
        assert_eq!(
            parse_address("example.com:9987"),
            Ok(("example.com".into(), 9987))
        );
        assert_eq!(parse_address("[::1]:9000"), Ok(("::1".into(), 9000)));
        // H5-09: this was host ":" and port 1
        assert!(parse_address("::1").is_err());
        assert!(parse_address("::1:9987").is_err());
        assert!(
            parse_address("example.com").is_err(),
            "the port is required here"
        );
        assert!(parse_address(":9987").is_err());
    }

    #[test]
    fn a_flooding_server_runs_out_of_budget_and_an_honest_one_never_does() {
        let t0 = std::time::Instant::now();
        let mut inbound = Inbound::new(t0);
        // A burst the size of the bucket goes through at once…
        for _ in 0..INBOUND_BURST as usize {
            assert!(inbound.take(t0));
        }
        // …and the next message in the same instant is over
        assert!(!inbound.take(t0), "a line-rate flood was never cut off");
        // A second later there is a second's worth again
        let t1 = t0 + std::time::Duration::from_secs(1);
        for _ in 0..INBOUND_PER_SEC as usize {
            assert!(inbound.take(t1));
        }
        assert!(!inbound.take(t1));
        // A busy relay at a tenth of the rate, for a minute, is never refused
        let mut honest = Inbound::new(t0);
        for i in 0..6000u64 {
            let at = t0 + std::time::Duration::from_millis(i * 10);
            assert!(
                honest.take(at),
                "an honest relay was cut off at message {i}"
            );
        }
    }

    /// The pacer is what keeps an honest client's busy connect — a pre-key
    /// bundle per person, then a sender key per person per channel — from
    /// being dropped frame by frame by a budget it cannot see.
    #[test]
    fn the_control_pacer_stays_under_what_the_server_accepts() {
        assert!(
            ControlPacer::RATE < voipc_protocol::codec::CONTROL_MSGS_PER_SEC as f64,
            "pacing at or above the server's own rate paces nothing"
        );
        let start = tokio::time::Instant::now();
        let mut pacer = ControlPacer::new(start);
        // A burst goes out at once — that is what a connect looks like...
        let burst = ControlPacer::RATE as usize;
        for _ in 0..burst {
            assert!(pacer.take(start).is_zero());
        }
        // ...and the rest is spread, at the rate and not faster.
        let mut waited = std::time::Duration::ZERO;
        for _ in 0..burst * 2 {
            waited += pacer.take(start + waited);
        }
        let seconds = waited.as_secs_f64();
        assert!(
            (1.9..2.1).contains(&seconds),
            "{seconds} s for two seconds' traffic"
        );
    }

    /// The media receive path reads the key generation and the sender's nonce
    /// prefix straight out of the datagram, because parsing a whole
    /// `VoicePacket` per packet would allocate on the hot path. Nothing in the
    /// compiler checks those two offsets against what the sender writes, and
    /// getting either wrong is silent: every packet simply fails to decrypt,
    /// which looks exactly like a key that has not arrived yet.
    #[test]
    fn the_hand_parsed_media_header_matches_what_a_sender_writes() {
        use voipc_protocol::voice::{VoicePacket, ENCRYPTED_VOICE_HEADER_SIZE};

        let (session_id, sequence, key_id, stream_id) = (7u32, 99u32, 3u16, 0xDEAD_BEEFu32);
        let buf =
            VoicePacket::encrypted_voice(session_id, sequence, key_id, stream_id, vec![1, 2, 3])
                .to_bytes();

        assert_eq!(
            u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]),
            session_id
        );
        assert_eq!(
            u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]),
            sequence
        );
        assert_eq!(u16::from_be_bytes([buf[9], buf[10]]), key_id);
        assert_eq!(
            u32::from_be_bytes([buf[11], buf[12], buf[13], buf[14]]),
            stream_id
        );
        assert_eq!(&buf[ENCRYPTED_VOICE_HEADER_SIZE..], &[1, 2, 3]);
    }
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

    /// A state with no geometry, so a layer's gains are its own volume and pan
    /// and nothing else — which is what makes the sums below readable.
    fn flat_state() -> crate::app_state::SpatialState {
        crate::app_state::SpatialState::default()
    }

    fn layer(volume: f32, pan: f32, delay_frames: u8) -> voipc_audio::spatial::Source {
        voipc_audio::spatial::Source {
            volume,
            pan,
            delay_frames,
            direct: true,
            ..Default::default()
        }
    }

    #[test]
    fn every_layer_is_another_render_of_the_same_voice() {
        // One speaker, heard twice at once: the phone in the left ear and the
        // person themselves across the room. Both come out of one Opus frame.
        let sp = flat_state();
        let mut layers = Vec::new();
        let specs = [layer(1.0, -1.0, 0), layer(0.5, 1.0, 0)];
        let pcm = vec![0.25f32; 960];
        let mut stereo = vec![0.0f32; 1920];

        let played = mix_layers(
            &mut layers,
            &specs,
            &sp,
            &mut stereo,
            Some(&pcm),
            1.0,
            false,
            false,
            0,
            0,
            std::time::Instant::now(),
        );
        assert!(played);
        assert_eq!(layers.len(), 2, "a chain per layer, grown on demand");
        // Hard left and hard right, so each ear carries exactly one of them
        let root2 = core::f32::consts::SQRT_2;
        assert!(
            (stereo[0] - 0.25 * root2).abs() < 1e-5,
            "left ear: {}",
            stereo[0]
        );
        assert!(
            (stereo[1] - 0.25 * 0.5 * root2).abs() < 1e-5,
            "right ear: {}",
            stereo[1]
        );
    }

    #[test]
    fn a_delayed_layer_arrives_late_and_keeps_playing_after_the_voice_stops() {
        // The radio double: one voice reaching you twice, once through the air
        // and once a beat later over the radio.
        let sp = flat_state();
        let mut layers = Vec::new();
        let specs = [layer(1.0, 0.0, 2)];
        let pcm = vec![0.25f32; 960];
        let now = std::time::Instant::now();
        let mut run = |frame: Option<&[f32]>| {
            let mut stereo = vec![0.0f32; 1920];
            mix_layers(
                &mut layers,
                &specs,
                &sp,
                &mut stereo,
                frame,
                1.0,
                false,
                false,
                0,
                0,
                now,
            );
            stereo[0]
        };

        // Two frames held back: nothing comes out yet
        assert_eq!(run(Some(&pcm)), 0.0);
        assert_eq!(run(Some(&pcm)), 0.0);
        assert!(run(Some(&pcm)).abs() > 0.1, "the delay never let go");
        // And the line drains after the speaker stops, rather than being cut
        assert!(run(None).abs() > 0.1, "the tail of the delay was dropped");
        assert!(run(None).abs() > 0.1);
        assert_eq!(run(None), 0.0, "a drained line kept playing");
    }

    #[test]
    fn a_shorter_delay_takes_effect_without_waiting_for_a_pause() {
        // The line pops one frame per push, so it keeps whatever length it grew
        // to: a mod dropping `delay` from 100 ms to 40 left the layer arriving
        // 100 ms late for the rest of the sentence.
        let mut layer = LayerMix::default();
        let frame = |n: f32| vec![n; 4];
        for i in 0..5 {
            layer.delayed(Some(&frame(i as f32)), 5);
        }
        assert_eq!(layer.ring.len(), 5, "the line did not fill");
        // Same tick the mod shortens it: the surplus is dropped, and what comes
        // out is one frame old rather than five
        let out = layer
            .delayed(Some(&frame(5.0)), 1)
            .expect("nothing came out");
        assert_eq!(out[0], 4.0, "the layer stayed at the old delay");
        assert_eq!(layer.ring.len(), 1);
        // And zero clears it entirely, as it always did
        assert!(layer.delayed(Some(&frame(6.0)), 0).is_none());
        assert!(layer.ring.is_empty());
    }

    #[test]
    fn dropping_a_layer_drops_its_chain() {
        let sp = flat_state();
        let mut layers = Vec::new();
        let pcm = vec![0.25f32; 960];
        let mut stereo = vec![0.0f32; 1920];
        let now = std::time::Instant::now();
        let three = [layer(1.0, 0.0, 0), layer(1.0, 0.0, 0), layer(1.0, 0.0, 0)];
        mix_layers(
            &mut layers,
            &three,
            &sp,
            &mut stereo,
            Some(&pcm),
            1.0,
            false,
            false,
            0,
            0,
            now,
        );
        assert_eq!(layers.len(), 3);
        mix_layers(
            &mut layers,
            &[],
            &sp,
            &mut stereo,
            Some(&pcm),
            1.0,
            false,
            false,
            0,
            0,
            now,
        );
        assert!(layers.is_empty(), "a layer the game dropped kept its chain");
    }

    #[test]
    fn only_an_ask_we_made_lately_lets_a_server_seat_us() {
        assert!(!voice_ask_fresh(0, 50_000), "never asked");
        assert!(voice_ask_fresh(40_000, 40_000));
        assert!(voice_ask_fresh(40_000, 40_000 + VOICE_ASK_TTL_MS - 1));
        assert!(!voice_ask_fresh(40_000, 40_000 + VOICE_ASK_TTL_MS), "stale");
        // A clock that stepped back is not an ask from the future
        assert!(voice_ask_fresh(40_000, 39_000));
    }

    #[test]
    fn only_a_keyframe_after_the_last_gap_resumes_rendering() {
        // (gap_before, is_keyframe) per frame, every one decoding fine
        let run = |fs: &[(bool, bool)]| {
            fs.iter()
                .fold(true, |ok, &(gap, key)| chain_intact(ok, gap, key, true))
        };
        // A keyframe queued before a loss does not vouch for what follows it
        assert!(!run(&[(false, true), (true, false), (false, false)]));
        assert!(run(&[(true, false), (false, true), (false, false)]));
        assert!(run(&[(true, true)]));
        assert!(
            !chain_intact(true, false, false, false),
            "a failed decode breaks it"
        );
    }
}
