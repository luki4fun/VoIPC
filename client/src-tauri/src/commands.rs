use std::collections::HashMap;
use std::sync::atomic::Ordering;

use serde::Serialize;
use tauri::{Emitter, State};

use voipc_protocol::messages::ClientMessage;
use voipc_protocol::voice::VoicePacket;

use crate::app_state::{AppState, PendingMessage, PendingTarget};
use crate::crypto::{self, ChatArchive, ChatMessage};
use crate::network;
use crate::screenshare;

#[derive(Debug, Clone, Serialize)]
pub struct AudioDeviceInfo {
    pub name: String,
    pub is_default: bool,
}

/// Connect to a VoIPC server. Returns the assigned user_id.
///
/// `accept_invalid_certs`: If true, accept self-signed/invalid TLS certificates.
/// Default should be false for security; set to true only for development.
#[tauri::command]
pub async fn connect(
    state: State<'_, AppState>,
    app_handle: tauri::AppHandle,
    address: String,
    username: String,
    accept_invalid_certs: Option<bool>,
) -> Result<u32, String> {
    // Install the ring crypto provider (idempotent — only the first call succeeds)
    let _ = rustls::crypto::ring::default_provider().install_default();

    network::connect_to_server(
        &state,
        app_handle,
        address,
        username,
        accept_invalid_certs.unwrap_or(false),
    )
    .await
}

/// Disconnect from the current server.
#[tauri::command]
pub async fn disconnect(state: State<'_, AppState>) -> Result<(), String> {
    let mut conn = state.connection.write().await;
    if let Some(mut connection) = conn.take() {
        // Stop any ongoing voice capture
        connection.transmitting.store(false, Ordering::Relaxed);
        if let Some(task) = connection.capture_task.take() {
            let _ = task.await;
        }

        // Stop any ongoing screen capture
        connection.screen_share_active.store(false, Ordering::Relaxed);
        if let Some(task) = connection.screen_capture_task.take() {
            let _ = task.await;
        }

        // Close capture session (stops screen capture)
        connection.capture_session = None;

        // Send graceful disconnect, then drop tcp_tx so writer can flush and exit
        let _ = network::send_tcp_message(&connection.tcp_tx, &ClientMessage::Disconnect).await;
        drop(connection.tcp_tx);

        // Give the writer task a moment to flush the disconnect message
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Now abort remaining background tasks
        for task in connection.tasks {
            task.abort();
        }

        // Drop playback stream and voice/video/screen-audio channels
        drop(connection.voice_tx);
        drop(connection.video_tx);
        drop(connection.screen_audio_tx);
        drop(connection.playback_stream);

        tracing::info!("disconnected gracefully");
    }
    Ok(())
}

/// Join a channel by ID (with optional password).
#[tauri::command]
pub async fn join_channel(
    state: State<'_, AppState>,
    channel_id: u32,
    password: Option<String>,
) -> Result<(), String> {
    let mut conn = state.connection.write().await;
    let connection = conn.as_mut().ok_or("Not connected")?;
    network::send_tcp_message(
        &connection.tcp_tx,
        &ClientMessage::JoinChannel {
            channel_id,
            password,
        },
    )
    .await?;
    // Track locally so start_transmit can check (server confirms via user-list event).
    // NOTE: The TCP reader task also updates current_channel_id when it receives
    // UserList from the server, which handles server-initiated moves (create, kick, etc.)
    connection.current_channel_id.store(channel_id, std::sync::atomic::Ordering::Relaxed);

    // Clear the current media key — server will send a fresh ChannelMediaKey
    // for the new channel via the TCP control channel.
    if let Ok(mut mk) = connection.current_media_key.lock() {
        *mk = None;
    }

    // Reset sender key state for the new channel (fresh distribution needed)
    {
        let mut sig = state.signal.lock().unwrap_or_else(|p| p.into_inner());
        sig.sender_key_distributed.remove(&channel_id);
        sig.sender_key_received.remove(&channel_id);
    }

    // Clean up screen share state when switching channels
    if connection.is_screen_sharing {
        connection.screen_share_active.store(false, Ordering::Relaxed);
        if let Some(task) = connection.screen_capture_task.take() {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(1), task).await;
        }
        connection.capture_session = None;
        connection.is_screen_sharing = false;
    }
    connection.watching_user_id = None;
    connection.watching_user_id_shared.store(0, Ordering::Relaxed);

    Ok(())
}

/// Create a new channel.
#[tauri::command]
pub async fn create_channel(
    state: State<'_, AppState>,
    name: String,
    password: Option<String>,
) -> Result<(), String> {
    let conn = state.connection.read().await;
    let connection = conn.as_ref().ok_or("Not connected")?;
    network::send_tcp_message(
        &connection.tcp_tx,
        &ClientMessage::CreateChannel { name, password },
    )
    .await
}

/// Change a channel's password (creator only).
#[tauri::command]
pub async fn set_channel_password(
    state: State<'_, AppState>,
    channel_id: u32,
    password: Option<String>,
) -> Result<(), String> {
    let conn = state.connection.read().await;
    let connection = conn.as_ref().ok_or("Not connected")?;
    network::send_tcp_message(
        &connection.tcp_tx,
        &ClientMessage::SetChannelPassword {
            channel_id,
            password,
        },
    )
    .await
}

/// Kick a user from a channel (creator only).
#[tauri::command]
pub async fn kick_user(
    state: State<'_, AppState>,
    channel_id: u32,
    user_id: u32,
) -> Result<(), String> {
    let conn = state.connection.read().await;
    let connection = conn.as_ref().ok_or("Not connected")?;
    network::send_tcp_message(
        &connection.tcp_tx,
        &ClientMessage::KickUser {
            channel_id,
            user_id,
        },
    )
    .await
}

/// Request the user list of a channel without joining it (preview).
#[tauri::command]
pub async fn request_channel_users(
    state: State<'_, AppState>,
    channel_id: u32,
) -> Result<(), String> {
    let conn = state.connection.read().await;
    let connection = conn.as_ref().ok_or("Not connected")?;
    network::send_tcp_message(
        &connection.tcp_tx,
        &ClientMessage::RequestChannelUsers { channel_id },
    )
    .await
}

/// Invite a user to your channel (creator only).
#[tauri::command]
pub async fn send_invite(
    state: State<'_, AppState>,
    channel_id: u32,
    target_user_id: u32,
) -> Result<(), String> {
    let conn = state.connection.read().await;
    let connection = conn.as_ref().ok_or("Not connected")?;
    network::send_tcp_message(
        &connection.tcp_tx,
        &ClientMessage::SendInvite {
            channel_id,
            target_user_id,
        },
    )
    .await
}

/// Accept a channel invite.
#[tauri::command]
pub async fn accept_invite(
    state: State<'_, AppState>,
    channel_id: u32,
) -> Result<(), String> {
    let mut conn = state.connection.write().await;
    let connection = conn.as_mut().ok_or("Not connected")?;

    // Clean up screen share state before switching channels
    if connection.is_screen_sharing {
        let _ = network::send_tcp_message(
            &connection.tcp_tx,
            &ClientMessage::StopScreenShare,
        ).await;
        connection.screen_share_active.store(false, Ordering::Relaxed);
        if let Some(task) = connection.screen_capture_task.take() {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(1), task).await;
        }
        connection.capture_session = None;
        connection.is_screen_sharing = false;
    }
    connection.watching_user_id = None;
    connection.watching_user_id_shared.store(0, Ordering::Relaxed);

    network::send_tcp_message(
        &connection.tcp_tx,
        &ClientMessage::AcceptInvite { channel_id },
    )
    .await
}

/// Decline a channel invite.
#[tauri::command]
pub async fn decline_invite(
    state: State<'_, AppState>,
    channel_id: u32,
) -> Result<(), String> {
    let conn = state.connection.read().await;
    let connection = conn.as_ref().ok_or("Not connected")?;
    network::send_tcp_message(
        &connection.tcp_tx,
        &ClientMessage::DeclineInvite { channel_id },
    )
    .await
}

/// Send a chat message to the current channel.
/// Tries Sender Key encryption if available, falls back to plaintext.
#[tauri::command]
pub async fn send_channel_message(
    state: State<'_, AppState>,
    app_handle: tauri::AppHandle,
    content: String,
) -> Result<(), String> {
    let (user_id, username, channel_id, tcp_tx) = {
        let conn = state.connection.read().await;
        let connection = conn.as_ref().ok_or("Not connected")?;
        (
            connection.user_id,
            connection.username.clone(),
            connection.current_channel_id.load(std::sync::atomic::Ordering::Relaxed),
            connection.tcp_tx.clone(),
        )
    };

    if channel_id == 0 {
        return Err("Chat is not available in the lobby".into());
    }

    // Try encrypted channel message via Sender Keys
    let encrypted_result = tokio::task::block_in_place(|| {
        let sig = state.signal.lock().map_err(|e| e.to_string())?;
        if !sig.initialized {
            return Err("not initialized".to_string());
        }
        // Check if we have distributed sender keys to anyone in this channel
        let has_distributed = sig
            .sender_key_distributed
            .get(&channel_id)
            .map_or(false, |s| !s.is_empty());
        if !has_distributed {
            return Err("no sender keys distributed".to_string());
        }
        drop(sig);

        let mut sig = state.signal.lock().map_err(|e| e.to_string())?;
        let stores = sig
            .stores
            .as_mut()
            .ok_or_else(|| "Signal not initialized".to_string())?;
        tokio::runtime::Handle::current()
            .block_on(voipc_crypto::group::encrypt_group_message(
                stores,
                user_id,
                channel_id,
                content.as_bytes(),
            ))
            .map_err(|e| format!("group encryption: {e}"))
    });

    match encrypted_result {
        Ok(ciphertext) => {
            tracing::info!(channel_id, "sending encrypted channel message");
            network::send_tcp_message(
                &tcp_tx,
                &ClientMessage::SendEncryptedChannelMessage { ciphertext },
            )
            .await?;

            // Emit locally for the sender — the server excludes us from the
            // encrypted channel broadcast (we can't decrypt our own sender key ciphertext).
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
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
            Ok(())
        }
        Err(reason) => {
            tracing::info!(channel_id, "encryption not ready ({}), queueing message", reason);
            // Queue the message — it will be sent when sender key distribution completes
            {
                let mut sig = state.signal.lock().unwrap_or_else(|p| p.into_inner());
                sig.pending_messages.push(PendingMessage {
                    target: PendingTarget::Channel { channel_id },
                    content: content.clone(),
                    queued_at: std::time::Instant::now(),
                });
            }

            // Show the message locally immediately (optimistic display)
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            let _ = app_handle.emit(
                "channel-chat-message",
                serde_json::json!({
                    "channel_id": channel_id,
                    "user_id": user_id,
                    "username": username,
                    "content": content,
                    "timestamp": timestamp,
                    "pending": true,
                }),
            );
            Ok(())
        }
    }
}

/// Send a direct message to another user.
/// Tries pairwise Signal encryption if session exists, queues if not ready.
#[tauri::command]
pub async fn send_direct_message(
    state: State<'_, AppState>,
    app_handle: tauri::AppHandle,
    target_user_id: u32,
    content: String,
) -> Result<(), String> {
    let (tcp_tx, own_user_id, own_username) = {
        let conn = state.connection.read().await;
        let connection = conn.as_ref().ok_or("Not connected")?;
        (connection.tcp_tx.clone(), connection.user_id, connection.username.clone())
    };

    // Try encrypted direct message via pairwise Signal session
    let encrypted_result = tokio::task::block_in_place(|| {
        let sig = state.signal.lock().map_err(|e| e.to_string())?;
        if !sig.initialized || !sig.established_sessions.contains(&target_user_id) {
            return Err("no session".to_string());
        }
        drop(sig);

        let mut sig = state.signal.lock().map_err(|e| e.to_string())?;
        let stores = sig
            .stores
            .as_mut()
            .ok_or_else(|| "Signal not initialized".to_string())?;
        tokio::runtime::Handle::current()
            .block_on(voipc_crypto::session::encrypt_message(
                stores,
                target_user_id,
                content.as_bytes(),
            ))
            .map_err(|e| format!("pairwise encryption: {e}"))
    });

    match encrypted_result {
        Ok((ciphertext, message_type)) => {
            tracing::info!(target_user_id, "sending encrypted direct message");
            network::send_tcp_message(
                &tcp_tx,
                &ClientMessage::SendEncryptedDirectMessage {
                    target_user_id,
                    ciphertext,
                    message_type,
                },
            )
            .await?;

            // Emit locally for the sender — the server echo of encrypted DMs
            // cannot be decrypted by the sender (ratchet has advanced).
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            let _ = app_handle.emit(
                "direct-chat-message",
                serde_json::json!({
                    "from_user_id": own_user_id,
                    "from_username": own_username,
                    "to_user_id": target_user_id,
                    "content": content,
                    "timestamp": timestamp,
                    "encrypted": true,
                }),
            );
            Ok(())
        }
        Err(reason) => {
            tracing::info!(target_user_id, "encryption not ready ({}), queueing DM", reason);
            // Queue the message — it will be sent when pairwise session is established
            {
                let mut sig = state.signal.lock().unwrap_or_else(|p| p.into_inner());
                sig.pending_messages.push(PendingMessage {
                    target: PendingTarget::Direct { target_user_id },
                    content: content.clone(),
                    queued_at: std::time::Instant::now(),
                });
            }

            // Show the message locally immediately (optimistic display)
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            let _ = app_handle.emit(
                "direct-chat-message",
                serde_json::json!({
                    "from_user_id": own_user_id,
                    "from_username": own_username,
                    "to_user_id": target_user_id,
                    "content": content,
                    "timestamp": timestamp,
                    "pending": true,
                }),
            );
            Ok(())
        }
    }
}

/// Start transmitting voice (PTT pressed).
#[tauri::command]
pub async fn start_transmit(state: State<'_, AppState>) -> Result<(), String> {
    let mut conn = state.connection.write().await;
    let connection = conn.as_mut().ok_or("Not connected")?;

    if connection.transmitting.load(Ordering::Relaxed) {
        return Ok(()); // Already transmitting
    }

    if connection.current_channel_id.load(Ordering::Relaxed) == 0 {
        return Err("Voice is disabled in the General lobby".into());
    }

    if connection.is_muted.load(Ordering::Relaxed) {
        return Ok(()); // Don't transmit while muted
    }

    let settings = state.settings.read().await;
    let input_device = settings.input_device.clone();
    drop(settings);

    connection.transmitting.store(true, Ordering::Relaxed);

    let task = network::spawn_capture_encode_task(
        input_device,
        connection.session_id,
        connection.udp_token,
        connection.transmitting.clone(),
        connection.voice_tx.clone(),
        connection.current_media_key.clone(),
        connection.current_channel_id.clone(),
        connection.voice_mode.clone(),
        connection.vad_threshold_db.clone(),
        connection.current_audio_level.clone(),
        connection.noise_suppression.clone(),
        connection.is_muted.clone(),
    );
    connection.capture_task = Some(task);

    tracing::info!("PTT pressed — capture started");
    Ok(())
}

/// Stop transmitting voice (PTT released).
#[tauri::command]
pub async fn stop_transmit(state: State<'_, AppState>) -> Result<(), String> {
    let mut conn = state.connection.write().await;
    let connection = conn.as_mut().ok_or("Not connected")?;

    if !connection.transmitting.load(Ordering::Relaxed) {
        return Ok(()); // Not transmitting
    }

    // Signal the capture task to stop
    connection.transmitting.store(false, Ordering::Relaxed);

    // Wait for the capture task to finish
    if let Some(task) = connection.capture_task.take() {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), task).await;
    }

    // Send EndOfTransmission so other clients know we stopped talking
    let eot = VoicePacket::end_of_transmission(connection.session_id, connection.udp_token, 0);
    let _ = connection.voice_tx.send(eot.to_bytes()).await;

    tracing::info!("PTT released — capture stopped");
    Ok(())
}

/// Toggle self-mute.
#[tauri::command]
pub async fn toggle_mute(state: State<'_, AppState>) -> Result<bool, String> {
    let conn = state.connection.read().await;
    if let Some(conn) = conn.as_ref() {
        let was_muted = conn.is_muted.load(Ordering::Relaxed);
        let new_muted = !was_muted;
        conn.is_muted.store(new_muted, Ordering::Relaxed);
        let _ = network::send_tcp_message(
            &conn.tcp_tx,
            &ClientMessage::SetMuted {
                muted: new_muted,
            },
        )
        .await;
        Ok(new_muted)
    } else {
        Err("Not connected".into())
    }
}

/// Toggle self-deafen.
#[tauri::command]
pub async fn toggle_deafen(state: State<'_, AppState>) -> Result<bool, String> {
    let conn = state.connection.read().await;
    if let Some(conn) = conn.as_ref() {
        let was_deafened = conn.is_deafened.load(Ordering::Relaxed);
        let new_deafened = !was_deafened;
        conn.is_deafened.store(new_deafened, Ordering::Relaxed);
        let _ = network::send_tcp_message(
            &conn.tcp_tx,
            &ClientMessage::SetDeafened {
                deafened: new_deafened,
            },
        )
        .await;
        Ok(new_deafened)
    } else {
        Err("Not connected".into())
    }
}

/// Send a ping to measure latency.
#[tauri::command]
pub async fn ping(state: State<'_, AppState>) -> Result<(), String> {
    let conn = state.connection.read().await;
    let connection = conn.as_ref().ok_or("Not connected")?;
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    network::send_tcp_message(&connection.tcp_tx, &ClientMessage::Ping { timestamp }).await
}

/// Get available audio input devices.
#[tauri::command]
pub fn get_input_devices() -> Result<Vec<AudioDeviceInfo>, String> {
    let devices = voipc_audio::device::list_input_devices().map_err(|e| e.to_string())?;
    Ok(devices
        .into_iter()
        .map(|d| AudioDeviceInfo {
            name: d.name,
            is_default: d.is_default,
        })
        .collect())
}

/// Get available audio output devices.
#[tauri::command]
pub fn get_output_devices() -> Result<Vec<AudioDeviceInfo>, String> {
    let devices = voipc_audio::device::list_output_devices().map_err(|e| e.to_string())?;
    Ok(devices
        .into_iter()
        .map(|d| AudioDeviceInfo {
            name: d.name,
            is_default: d.is_default,
        })
        .collect())
}

/// Set the active input device.
#[tauri::command]
pub async fn set_input_device(
    state: State<'_, AppState>,
    device_name: String,
) -> Result<(), String> {
    let mut settings = state.settings.write().await;
    settings.input_device = Some(device_name);
    Ok(())
}

/// Set the active output device.
#[tauri::command]
pub async fn set_output_device(
    state: State<'_, AppState>,
    device_name: String,
) -> Result<(), String> {
    let mut settings = state.settings.write().await;
    settings.output_device = Some(device_name);
    Ok(())
}

/// Set output volume (0.0 to 1.0).
#[tauri::command]
pub async fn set_volume(
    state: State<'_, AppState>,
    volume: f32,
) -> Result<(), String> {
    let mut settings = state.settings.write().await;
    settings.volume = volume.clamp(0.0, 1.0);
    Ok(())
}

// ---------------------------------------------------------------------------
// Screen share commands
// ---------------------------------------------------------------------------

/// Start screen sharing — opens the XDG Desktop Portal screen picker, then
/// sends the TCP announcement. Capture task is NOT started yet; it begins when
/// the frontend receives `viewer-count-changed` with count > 0.
#[tauri::command]
pub async fn start_screen_share(
    state: State<'_, AppState>,
    resolution: u16,
    _fps: u32,
) -> Result<(), String> {
    // Open the screen capture picker (portal on Linux, display selection on Windows).
    // This must happen BEFORE acquiring the connection lock because it may await
    // user interaction (e.g. portal dialog on Linux).
    // (fps is stored in the frontend and passed to start_screen_capture later)
    let session = screenshare::request_screencast().await?;

    let mut conn = state.connection.write().await;
    let connection = conn.as_mut().ok_or("Not connected")?;

    if connection.current_channel_id.load(Ordering::Relaxed) == 0 {
        return Err("Screen sharing is disabled in the General lobby".into());
    }

    if connection.is_screen_sharing {
        return Err("Already screen sharing".into());
    }

    connection.capture_session = Some(session);

    network::send_tcp_message(
        &connection.tcp_tx,
        &ClientMessage::StartScreenShare {
            source: "portal".into(),
            resolution,
        },
    )
    .await?;

    connection.is_screen_sharing = true;
    Ok(())
}

/// Stop screen sharing — stops capture, closes portal session, sends TCP stop.
#[tauri::command]
pub async fn stop_screen_share(state: State<'_, AppState>) -> Result<(), String> {
    let mut conn = state.connection.write().await;
    let connection = conn.as_mut().ok_or("Not connected")?;

    if !connection.is_screen_sharing {
        return Ok(());
    }

    // Stop the capture task
    connection.screen_share_active.store(false, Ordering::Relaxed);
    if let Some(task) = connection.screen_capture_task.take() {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), task).await;
    }

    // Close the capture session (stops screen capture)
    connection.capture_session = None;

    network::send_tcp_message(&connection.tcp_tx, &ClientMessage::StopScreenShare).await?;
    connection.is_screen_sharing = false;
    Ok(())
}

/// Start watching another user's screen share.
#[tauri::command]
pub async fn watch_screen_share(
    state: State<'_, AppState>,
    sharer_user_id: u32,
) -> Result<(), String> {
    let mut conn = state.connection.write().await;
    let connection = conn.as_mut().ok_or("Not connected")?;

    network::send_tcp_message(
        &connection.tcp_tx,
        &ClientMessage::WatchScreenShare { sharer_user_id },
    )
    .await?;

    connection.watching_user_id = Some(sharer_user_id);
    connection.watching_user_id_shared.store(sharer_user_id, Ordering::Relaxed);

    // Reset receiver stats for this new viewing session
    connection.screen_video_frames_received.store(0, Ordering::Relaxed);
    connection.screen_video_frames_dropped.store(0, Ordering::Relaxed);
    connection.screen_video_bytes_received.store(0, Ordering::Relaxed);
    connection.screen_video_resolution.store(0, Ordering::Relaxed);

    Ok(())
}

/// Stop watching the current screen share.
#[tauri::command]
pub async fn stop_watching_screen_share(state: State<'_, AppState>) -> Result<(), String> {
    let mut conn = state.connection.write().await;
    let connection = conn.as_mut().ok_or("Not connected")?;

    if connection.watching_user_id.is_none() {
        return Ok(()); // Already not watching
    }

    network::send_tcp_message(&connection.tcp_tx, &ClientMessage::StopWatchingScreenShare).await?;
    connection.watching_user_id = None;
    connection.watching_user_id_shared.store(0, Ordering::Relaxed);
    Ok(())
}

/// Request a keyframe from a sharer (e.g. after packet loss).
#[tauri::command]
pub async fn request_keyframe(
    state: State<'_, AppState>,
    sharer_user_id: u32,
) -> Result<(), String> {
    let conn = state.connection.read().await;
    let connection = conn.as_ref().ok_or("Not connected")?;
    network::send_tcp_message(
        &connection.tcp_tx,
        &ClientMessage::RequestKeyframe { sharer_user_id },
    )
    .await
}

/// Toggle screen share audio on/off. Returns the new enabled state.
#[tauri::command]
pub async fn toggle_screen_audio(state: State<'_, AppState>) -> Result<bool, String> {
    let conn = state.connection.read().await;
    let connection = conn.as_ref().ok_or("Not connected")?;
    let was_enabled = connection
        .screen_audio_enabled
        .fetch_xor(true, Ordering::Relaxed);
    let now_enabled = !was_enabled;
    tracing::info!("Screen audio toggled: {}", if now_enabled { "on" } else { "off" });
    Ok(now_enabled)
}

/// Returns (send_count, recv_count) for screen audio packet counters.
/// Frontend polls this to determine if screen audio is actively flowing.
#[tauri::command]
pub async fn get_screen_audio_status(
    state: State<'_, AppState>,
) -> Result<(u32, u32), String> {
    let conn = state.connection.read().await;
    let connection = conn.as_ref().ok_or("Not connected")?;
    let send = connection
        .screen_audio_send_count
        .load(Ordering::Relaxed);
    let recv = connection
        .screen_audio_recv_count
        .load(Ordering::Relaxed);
    Ok((send, recv))
}

/// Returns screen share video stats for the frontend stats overlay.
/// (frames_sent, bytes_sent, frames_received, frames_dropped, bytes_received, resolution_packed)
/// resolution_packed: (width << 16) | height; 0 if unknown.
#[tauri::command]
pub async fn get_screen_share_stats(
    state: State<'_, AppState>,
) -> Result<(u32, u64, u32, u32, u64, u32), String> {
    let conn = state.connection.read().await;
    let c = conn.as_ref().ok_or("Not connected")?;
    Ok((
        c.screen_video_frames_sent.load(Ordering::Relaxed),
        c.screen_video_bytes_sent.load(Ordering::Relaxed),
        c.screen_video_frames_received.load(Ordering::Relaxed),
        c.screen_video_frames_dropped.load(Ordering::Relaxed),
        c.screen_video_bytes_received.load(Ordering::Relaxed),
        c.screen_video_resolution.load(Ordering::Relaxed),
    ))
}

/// Start the screen capture task — called from frontend when viewer_count goes from 0 to N.
#[tauri::command]
pub async fn start_screen_capture(
    state: State<'_, AppState>,
    resolution: u16,
    fps: u32,
) -> Result<(), String> {
    let mut conn = state.connection.write().await;
    let connection = conn.as_mut().ok_or("Not connected")?;

    if connection.screen_capture_task.is_some() {
        return Ok(()); // Already capturing
    }

    let session = connection
        .capture_session
        .as_ref()
        .ok_or("No capture session — call start_screen_share first")?;

    let res = voipc_video::Resolution::from_height(resolution)
        .ok_or_else(|| format!("Unsupported resolution: {}", resolution))?;

    connection.screen_share_active.store(true, Ordering::Relaxed);

    // Reset sender stats for this new capture session
    connection.screen_video_frames_sent.store(0, Ordering::Relaxed);
    connection.screen_video_bytes_sent.store(0, Ordering::Relaxed);

    let task = screenshare::spawn_capture_task(
        session,
        res.width(),
        res.height(),
        fps,
        res.bitrate_kbps(),
        connection.session_id,
        connection.udp_token,
        connection.screen_share_active.clone(),
        connection.keyframe_requested.clone(),
        connection.video_tx.clone(),
        connection.screen_audio_tx.clone(),
        connection.screen_audio_enabled.clone(),
        connection.screen_audio_send_count.clone(),
        connection.current_media_key.clone(),
        connection.current_channel_id.clone(),
        connection.screen_video_frames_sent.clone(),
        connection.screen_video_bytes_sent.clone(),
    )?;

    connection.screen_capture_task = Some(task);
    Ok(())
}

/// Stop the screen capture task — called from frontend when viewer_count goes to 0.
#[tauri::command]
pub async fn stop_screen_capture(state: State<'_, AppState>) -> Result<(), String> {
    let mut conn = state.connection.write().await;
    let connection = conn.as_mut().ok_or("Not connected")?;

    connection.screen_share_active.store(false, Ordering::Relaxed);
    if let Some(task) = connection.screen_capture_task.take() {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), task).await;
    }
    Ok(())
}

/// Set the keyframe_requested flag — called from frontend on KeyframeRequested event.
#[tauri::command]
pub async fn set_keyframe_requested(state: State<'_, AppState>) -> Result<(), String> {
    let conn = state.connection.read().await;
    let connection = conn.as_ref().ok_or("Not connected")?;
    connection.keyframe_requested.store(true, Ordering::Relaxed);
    Ok(())
}

// ---------------------------------------------------------------------------
// Voice activation (VAD) commands
// ---------------------------------------------------------------------------

/// Set voice mode: "ptt", "vad", or "always_on".
#[tauri::command]
pub async fn set_voice_mode(state: State<'_, AppState>, mode: String) -> Result<(), String> {
    let conn = state.connection.read().await;
    let connection = conn.as_ref().ok_or("Not connected")?;
    let vm = crate::app_state::VoiceMode::from_str(&mode);
    connection.voice_mode.store(vm as u8, Ordering::Relaxed);
    Ok(())
}

/// Set the VAD threshold in dB (typically -60 to 0).
#[tauri::command]
pub async fn set_vad_threshold(state: State<'_, AppState>, threshold_db: f32) -> Result<(), String> {
    let conn = state.connection.read().await;
    let connection = conn.as_ref().ok_or("Not connected")?;
    connection.vad_threshold_db.store(threshold_db as i32, Ordering::Relaxed);
    Ok(())
}

/// Get the current audio input level in dB.
#[tauri::command]
pub async fn get_audio_level(state: State<'_, AppState>) -> Result<f32, String> {
    let conn = state.connection.read().await;
    let connection = conn.as_ref().ok_or("Not connected")?;
    let raw = connection.current_audio_level.load(Ordering::Relaxed);
    Ok(raw as f32 / 100.0)
}

// ---------------------------------------------------------------------------
// Noise suppression
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn toggle_noise_suppression(state: State<'_, AppState>) -> Result<bool, String> {
    let conn = state.connection.read().await;
    let connection = conn.as_ref().ok_or("Not connected")?;
    let prev = connection.noise_suppression.load(Ordering::Relaxed);
    let new_val = !prev;
    connection.noise_suppression.store(new_val, Ordering::Relaxed);
    Ok(new_val)
}

// ---------------------------------------------------------------------------
// Per-user volume control
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn set_user_volume(
    state: State<'_, AppState>,
    user_id: u32,
    volume: f32,
) -> Result<(), String> {
    let conn = state.connection.read().await;
    let connection = conn.as_ref().ok_or("Not connected")?;
    let vol = volume.clamp(0.0, 2.0);
    let mut volumes = connection.user_volumes.lock().map_err(|e| e.to_string())?;
    if (vol - 1.0).abs() < f32::EPSILON {
        volumes.remove(&user_id);
    } else {
        volumes.insert(user_id, vol);
    }
    Ok(())
}

#[tauri::command]
pub async fn get_user_volume(
    state: State<'_, AppState>,
    user_id: u32,
) -> Result<f32, String> {
    let conn = state.connection.read().await;
    let connection = conn.as_ref().ok_or("Not connected")?;
    let volumes = connection.user_volumes.lock().map_err(|e| e.to_string())?;
    Ok(volumes.get(&user_id).copied().unwrap_or(1.0))
}

// ---------------------------------------------------------------------------
// Chat history (encrypted file) commands
// ---------------------------------------------------------------------------

/// JSON-friendly representation of ChatArchive for the frontend.
#[derive(Serialize)]
pub struct ChatArchivePayload {
    pub channels: HashMap<String, Vec<ChatMessage>>,
    pub dms: HashMap<String, Vec<ChatMessage>>,
}

impl From<&ChatArchive> for ChatArchivePayload {
    fn from(a: &ChatArchive) -> Self {
        Self {
            channels: a.channels.clone(),
            dms: a.dms.clone(),
        }
    }
}

/// Check whether an encrypted chat history file exists.
#[tauri::command]
pub async fn chat_history_exists(
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let exe_dir = std::env::current_exe()
        .map_err(|e| format!("failed to get executable path: {e}"))?
        .parent()
        .ok_or("executable has no parent dir")?
        .to_path_buf();
    let file_path = exe_dir.join("chat_history.bin");

    // Store the resolved path for later use
    {
        let mut chat = state.chat.write().await;
        chat.file_path = file_path.clone();
    }

    if !file_path.exists() {
        return Ok(false);
    }

    let data = std::fs::read(&file_path).map_err(|e| format!("failed to read file: {e}"))?;
    Ok(crypto::has_valid_header(&data))
}

/// Decrypt an existing chat history file with the given password.
/// Returns the full archive so the frontend can populate its stores.
#[tauri::command]
pub async fn unlock_chat_history(
    state: State<'_, AppState>,
    password: String,
) -> Result<ChatArchivePayload, String> {
    let mut chat = state.chat.write().await;

    let data =
        std::fs::read(&chat.file_path).map_err(|e| format!("failed to read file: {e}"))?;

    let (archive, salt, key) =
        crypto::decrypt_archive(&data, &password).map_err(|e| e.to_string())?;

    let payload = ChatArchivePayload::from(&archive);

    chat.archive = archive;
    chat.salt = salt;
    chat.sealing_key = Some(key);
    chat.dirty = false;

    Ok(payload)
}

/// Create a new encrypted chat history file with the given password.
#[tauri::command]
pub async fn create_chat_history(
    state: State<'_, AppState>,
    password: String,
) -> Result<(), String> {
    let mut chat = state.chat.write().await;

    let salt = crypto::generate_salt();
    let key = crypto::derive_key(&password, &salt);
    let archive = ChatArchive::default();

    // Write the initial (empty) encrypted file
    let file_data =
        crypto::encrypt_archive(&archive, &key, &salt).map_err(|e| e.to_string())?;

    if let Some(parent) = chat.file_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create data dir: {e}"))?;
    }
    std::fs::write(&chat.file_path, &file_data)
        .map_err(|e| format!("failed to write file: {e}"))?;

    chat.archive = archive;
    chat.salt = salt;
    chat.sealing_key = Some(key);
    chat.dirty = false;

    Ok(())
}

/// Save chat messages from the frontend stores into the encrypted archive.
/// The actual disk write is handled by the background flush task.
#[tauri::command]
pub async fn save_chat_messages(
    state: State<'_, AppState>,
    channel_messages: HashMap<String, Vec<ChatMessage>>,
    dm_messages: HashMap<String, Vec<ChatMessage>>,
) -> Result<(), String> {
    let mut chat = state.chat.write().await;

    // If no encryption key is set (user skipped password), do nothing
    if chat.sealing_key.is_none() {
        return Ok(());
    }

    chat.archive.channels = channel_messages;
    chat.archive.dms = dm_messages;
    chat.dirty = true;

    Ok(())
}

/// Clear all chat history: empties the archive and re-encrypts the file.
#[tauri::command]
pub async fn clear_chat_history(state: State<'_, AppState>) -> Result<(), String> {
    let mut chat = state.chat.write().await;

    chat.archive = ChatArchive::default();

    // If we have an encryption key, write the empty archive to disk immediately
    if let Some(ref key) = chat.sealing_key {
        let file_data =
            crypto::encrypt_archive(&chat.archive, key, &chat.salt).map_err(|e| e.to_string())?;
        std::fs::write(&chat.file_path, &file_data)
            .map_err(|e| format!("failed to write file: {e}"))?;
    }

    chat.dirty = false;
    Ok(())
}

// ---------------------------------------------------------------------------
// E2E Encryption commands
// ---------------------------------------------------------------------------

/// Request another user's pre-key bundle for establishing an encrypted session.
#[tauri::command]
pub async fn request_prekey_bundle(
    state: State<'_, AppState>,
    target_user_id: u32,
) -> Result<(), String> {
    let conn = state.connection.read().await;
    let connection = conn.as_ref().ok_or("Not connected")?;
    network::send_tcp_message(
        &connection.tcp_tx,
        &ClientMessage::RequestPreKeyBundle { target_user_id },
    )
    .await
}

/// Send an encrypted direct message to another user.
/// Encrypts the plaintext using the pairwise Signal session, then sends ciphertext.
#[tauri::command]
pub async fn send_encrypted_direct_message(
    state: State<'_, AppState>,
    target_user_id: u32,
    content: String,
) -> Result<(), String> {
    // Encrypt with Signal Protocol pairwise session.
    // Use block_in_place because libsignal store traits are !Send.
    let (ciphertext, message_type) = tokio::task::block_in_place(|| {
        let mut signal = state.signal.lock().map_err(|e| e.to_string())?;
        let stores = signal.stores.as_mut().ok_or("E2E encryption not initialized".to_string())?;
        tokio::runtime::Handle::current().block_on(
            voipc_crypto::session::encrypt_message(stores, target_user_id, content.as_bytes()),
        )
        .map_err(|e| format!("encryption failed: {e}"))
    })?;

    let conn = state.connection.read().await;
    let connection = conn.as_ref().ok_or("Not connected")?;
    network::send_tcp_message(
        &connection.tcp_tx,
        &ClientMessage::SendEncryptedDirectMessage {
            target_user_id,
            ciphertext,
            message_type,
        },
    )
    .await
}

/// Send an encrypted channel message using Sender Keys.
/// Encrypts the plaintext using the channel's sender key, then sends ciphertext.
#[tauri::command]
pub async fn send_encrypted_channel_message(
    state: State<'_, AppState>,
    content: String,
) -> Result<(), String> {
    let user_id = {
        let conn = state.connection.read().await;
        let connection = conn.as_ref().ok_or("Not connected")?;
        connection.user_id
    };

    let channel_id = {
        let conn = state.connection.read().await;
        let connection = conn.as_ref().ok_or("Not connected")?;
        connection.current_channel_id.load(std::sync::atomic::Ordering::Relaxed)
    };

    if channel_id == 0 {
        return Err("Chat is not available in the lobby".into());
    }

    // Encrypt with Sender Key.
    // Use block_in_place because libsignal store traits are !Send.
    let ciphertext = tokio::task::block_in_place(|| {
        let mut signal = state.signal.lock().map_err(|e| e.to_string())?;
        let stores = signal
            .stores
            .as_mut()
            .ok_or("E2E encryption not initialized".to_string())?;
        tokio::runtime::Handle::current().block_on(
            voipc_crypto::group::encrypt_group_message(
                stores,
                user_id,
                channel_id,
                content.as_bytes(),
            ),
        )
        .map_err(|e| format!("group encryption failed: {e}"))
    })?;

    let conn = state.connection.read().await;
    let connection = conn.as_ref().ok_or("Not connected")?;
    network::send_tcp_message(
        &connection.tcp_tx,
        &ClientMessage::SendEncryptedChannelMessage { ciphertext },
    )
    .await
}

/// Distribute a sender key to a channel member (for group encryption).
#[tauri::command]
pub async fn distribute_sender_key(
    state: State<'_, AppState>,
    channel_id: u32,
    target_user_id: u32,
    distribution_message: Vec<u8>,
    message_type: Option<u8>,
) -> Result<(), String> {
    let conn = state.connection.read().await;
    let connection = conn.as_ref().ok_or("Not connected")?;
    network::send_tcp_message(
        &connection.tcp_tx,
        &ClientMessage::DistributeSenderKey {
            channel_id,
            target_user_id,
            distribution_message,
            message_type: message_type.unwrap_or(0),
        },
    )
    .await
}

/// Distribute a media encryption key to a channel member.
#[tauri::command]
pub async fn distribute_media_key(
    state: State<'_, AppState>,
    channel_id: u32,
    target_user_id: u32,
    encrypted_media_key: Vec<u8>,
) -> Result<(), String> {
    let conn = state.connection.read().await;
    let connection = conn.as_ref().ok_or("Not connected")?;
    network::send_tcp_message(
        &connection.tcp_tx,
        &ClientMessage::DistributeMediaKey {
            channel_id,
            target_user_id,
            encrypted_media_key,
        },
    )
    .await
}

/// Upload replenished one-time pre-keys to the server.
#[tauri::command]
pub async fn upload_prekeys(
    state: State<'_, AppState>,
    prekeys: Vec<voipc_protocol::types::OneTimePreKey>,
) -> Result<(), String> {
    let conn = state.connection.read().await;
    let connection = conn.as_ref().ok_or("Not connected")?;
    network::send_tcp_message(
        &connection.tcp_tx,
        &ClientMessage::UploadPreKeys { prekeys },
    )
    .await
}

/// Flush dirty chat state to disk. Called by the background task and on exit.
pub async fn flush_chat_to_disk(state: &AppState) {
    let mut chat = state.chat.write().await;
    if !chat.dirty {
        return;
    }
    if let Some(ref key) = chat.sealing_key {
        match crypto::encrypt_archive(&chat.archive, key, &chat.salt) {
            Ok(file_data) => {
                if let Err(e) = std::fs::write(&chat.file_path, &file_data) {
                    tracing::error!("failed to flush chat history: {e}");
                } else {
                    chat.dirty = false;
                }
            }
            Err(e) => {
                tracing::error!("failed to encrypt chat archive: {e}");
            }
        }
    }
}
