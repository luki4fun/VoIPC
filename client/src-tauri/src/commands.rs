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

/// Poke another user. They see a popup + sound + window flash.
/// The poke message is E2E encrypted with the pairwise Signal session.
#[tauri::command]
pub async fn send_poke(
    state: State<'_, AppState>,
    app_handle: tauri::AppHandle,
    target_user_id: u32,
    message: String,
) -> Result<(), String> {
    // Encrypt the poke message with Signal Protocol pairwise session
    let (ciphertext, message_type) = tokio::task::block_in_place(|| {
        let mut signal = state.signal.lock().map_err(|e| e.to_string())?;
        let stores = signal
            .stores
            .as_mut()
            .ok_or_else(|| "E2E encryption not initialized".to_string())?;
        tokio::runtime::Handle::current()
            .block_on(voipc_crypto::session::encrypt_message(
                stores,
                target_user_id,
                message.as_bytes(),
            ))
            .map_err(|e| format!("poke encryption failed: {e}"))
    })?;

    let (tcp_tx, own_user_id, own_username) = {
        let conn = state.connection.read().await;
        let connection = conn.as_ref().ok_or("Not connected")?;
        (connection.tcp_tx.clone(), connection.user_id, connection.username.clone())
    };

    network::send_tcp_message(
        &tcp_tx,
        &ClientMessage::SendPoke {
            target_user_id,
            ciphertext,
            message_type,
        },
    )
    .await?;

    // Emit the poke as a local DM for the sender's chat history
    if !message.is_empty() {
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
                "content": format!("[Poke] {}", message),
                "timestamp": timestamp,
            }),
        );
    }

    Ok(())
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

/// Core start-transmit logic, callable from both the Tauri command and the global shortcut handler.
pub(crate) async fn do_start_transmit(state: &AppState) -> Result<(), String> {
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

/// Core stop-transmit logic, callable from both the Tauri command and the global shortcut handler.
pub(crate) async fn do_stop_transmit(state: &AppState) -> Result<(), String> {
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

/// Start transmitting voice (PTT pressed).
#[tauri::command]
pub async fn start_transmit(state: State<'_, AppState>) -> Result<(), String> {
    do_start_transmit(&state).await
}

/// Stop transmitting voice (PTT released).
#[tauri::command]
pub async fn stop_transmit(state: State<'_, AppState>) -> Result<(), String> {
    do_stop_transmit(&state).await
}

/// Check if a JS KeyboardEvent.code string is a recognized key code.
fn is_valid_key_code(code: &str) -> bool {
    matches!(
        code,
        "Space"
            | "Tab"
            | "Escape"
            | "CapsLock"
            | "KeyA"
            | "KeyB"
            | "KeyC"
            | "KeyD"
            | "KeyE"
            | "KeyF"
            | "KeyG"
            | "KeyH"
            | "KeyI"
            | "KeyJ"
            | "KeyK"
            | "KeyL"
            | "KeyM"
            | "KeyN"
            | "KeyO"
            | "KeyP"
            | "KeyQ"
            | "KeyR"
            | "KeyS"
            | "KeyT"
            | "KeyU"
            | "KeyV"
            | "KeyW"
            | "KeyX"
            | "KeyY"
            | "KeyZ"
            | "Digit0"
            | "Digit1"
            | "Digit2"
            | "Digit3"
            | "Digit4"
            | "Digit5"
            | "Digit6"
            | "Digit7"
            | "Digit8"
            | "Digit9"
            | "F1"
            | "F2"
            | "F3"
            | "F4"
            | "F5"
            | "F6"
            | "F7"
            | "F8"
            | "F9"
            | "F10"
            | "F11"
            | "F12"
            | "ShiftLeft"
            | "ShiftRight"
            | "ControlLeft"
            | "ControlRight"
            | "AltLeft"
            | "AltRight"
            | "Backquote"
            | "Minus"
            | "Equal"
            | "BracketLeft"
            | "BracketRight"
            | "Backslash"
            | "Semicolon"
            | "Quote"
            | "Comma"
            | "Period"
            | "Slash"
    )
}

/// Parse a PTT binding string like "Ctrl+Space" or "ControlLeft" into a PttBinding.
pub(crate) fn parse_ptt_binding(binding_str: &str) -> Option<crate::app_state::PttBinding> {
    let parts: Vec<&str> = binding_str.split('+').collect();
    let mut ctrl = false;
    let mut alt = false;
    let mut shift = false;
    let mut key_code = "";

    for part in &parts {
        match *part {
            "Ctrl" => ctrl = true,
            "Alt" => alt = true,
            "Shift" => shift = true,
            code => key_code = code,
        }
    }

    if !is_valid_key_code(key_code) {
        return None;
    }

    Some(crate::app_state::PttBinding {
        ctrl,
        alt,
        shift,
        code: key_code.to_string(),
    })
}

/// Change the PTT key binding. Updates both settings and the shared binding for the global key listener.
#[tauri::command]
pub async fn set_ptt_key(
    state: State<'_, AppState>,
    key_code: String,
) -> Result<(), String> {
    // Parse and validate the binding
    let binding = parse_ptt_binding(&key_code)
        .ok_or_else(|| format!("Unsupported key binding: {key_code}"))?;

    // Update stored settings
    {
        let mut settings = state.settings.write().await;
        settings.ptt_key = key_code.clone();
    }

    // Update the shared PttBinding for the global key listener
    {
        let mut ptt = state.ptt_binding.write().unwrap();
        *ptt = binding;
    }

    // Persist to config
    {
        let mut config = state.config.lock().unwrap();
        config.ptt_key = key_code.clone();
        let _ = crate::config::save_config(&config);
    }

    tracing::info!("PTT key changed to: {key_code}");
    Ok(())
}

/// Set PTT hold mode. When true, for combo bindings (e.g. Ctrl+Space), holding the modifier
/// keeps PTT active after releasing the trigger key. When false, releasing the trigger key
/// immediately stops PTT.
#[tauri::command]
pub async fn set_ptt_hold_mode(
    state: State<'_, AppState>,
    hold_mode: bool,
) -> Result<(), String> {
    state.ptt_hold_mode.store(hold_mode, Ordering::Relaxed);
    {
        let mut config = state.config.lock().unwrap();
        config.ptt_hold_mode = hold_mode;
        let _ = crate::config::save_config(&config);
    }
    tracing::info!("PTT hold mode set to: {hold_mode}");
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
        // Persist
        {
            let mut config = state.config.lock().unwrap();
            config.muted = new_muted;
            let _ = crate::config::save_config(&config);
        }
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
        // Persist
        {
            let mut config = state.config.lock().unwrap();
            config.deafened = new_deafened;
            let _ = crate::config::save_config(&config);
        }
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
    settings.input_device = Some(device_name.clone());
    drop(settings);
    {
        let mut config = state.config.lock().unwrap();
        config.input_device = Some(device_name);
        let _ = crate::config::save_config(&config);
    }
    Ok(())
}

/// Set the active output device.
#[tauri::command]
pub async fn set_output_device(
    state: State<'_, AppState>,
    device_name: String,
) -> Result<(), String> {
    let mut settings = state.settings.write().await;
    settings.output_device = Some(device_name.clone());
    drop(settings);
    {
        let mut config = state.config.lock().unwrap();
        config.output_device = Some(device_name);
        let _ = crate::config::save_config(&config);
    }
    Ok(())
}

/// Set output volume (0.0 to 1.0).
#[tauri::command]
pub async fn set_volume(
    state: State<'_, AppState>,
    volume: f32,
) -> Result<(), String> {
    let clamped = volume.clamp(0.0, 1.0);
    let mut settings = state.settings.write().await;
    settings.volume = clamped;
    drop(settings);
    {
        let mut config = state.config.lock().unwrap();
        config.volume = clamped;
        let _ = crate::config::save_config(&config);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Screen share commands
// ---------------------------------------------------------------------------

/// Start screen sharing — opens the XDG Desktop Portal screen picker, then
/// sends the TCP announcement. Capture task is NOT started yet; it begins when
/// Return the current platform name ("linux" or "windows").
#[tauri::command]
pub fn get_platform() -> String {
    std::env::consts::OS.to_string()
}

/// Enumerate available displays for screen capture.
#[tauri::command]
pub fn enumerate_displays() -> Vec<screenshare::DisplayInfo> {
    screenshare::enumerate_displays()
}

/// Enumerate available windows for screen capture.
#[tauri::command]
pub fn enumerate_windows() -> Vec<screenshare::WindowInfo> {
    screenshare::enumerate_windows()
}

/// Start sharing the screen — opens the capture session for the selected source.
/// The actual capture task starts lazily when
/// the frontend receives `viewer-count-changed` with count > 0.
#[tauri::command]
pub async fn start_screen_share(
    state: State<'_, AppState>,
    source_type: String,
    source_id: String,
    resolution: u16,
    _fps: u32,
) -> Result<(), String> {
    // Open the screen capture session for the selected source.
    // This must happen BEFORE acquiring the connection lock because it may await
    // user interaction (e.g. portal dialog on Linux).
    // (fps is stored in the frontend and passed to start_screen_capture later)
    let session = screenshare::request_screencast(&source_type, &source_id).await?;

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

/// Switch the screen share source without stopping/restarting the share.
/// Stops the current capture, replaces the session, and restarts capture
/// if viewers are present. The server is not notified — the stream continues.
#[tauri::command]
pub async fn switch_screen_share_source(
    state: State<'_, AppState>,
    source_type: String,
    source_id: String,
    resolution: u16,
    fps: u32,
) -> Result<(), String> {
    // Acquire the new capture session BEFORE locking (may show portal on Linux).
    let new_session = screenshare::request_screencast(&source_type, &source_id).await?;

    let mut conn = state.connection.write().await;
    let connection = conn.as_mut().ok_or("Not connected")?;

    if !connection.is_screen_sharing {
        return Err("Not currently screen sharing".into());
    }

    // Stop current capture if running
    let had_active_capture = connection.screen_capture_task.is_some();
    connection
        .screen_share_active
        .store(false, Ordering::Relaxed);
    if let Some(task) = connection.screen_capture_task.take() {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), task).await;
    }

    // Replace capture session
    connection.capture_session = Some(new_session);

    // Restart capture if viewers were watching
    if had_active_capture {
        let session = connection
            .capture_session
            .as_ref()
            .ok_or("No capture session after switch")?;

        let res = voipc_video::Resolution::from_height(resolution)
            .ok_or_else(|| format!("Unsupported resolution: {}", resolution))?;

        connection
            .screen_share_active
            .store(true, Ordering::Relaxed);

        // Reset sender stats for the new source
        connection
            .screen_video_frames_sent
            .store(0, Ordering::Relaxed);
        connection
            .screen_video_bytes_sent
            .store(0, Ordering::Relaxed);

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
    // Always persist to settings + config (even when disconnected)
    {
        let mut settings = state.settings.write().await;
        settings.voice_mode = mode.clone();
    }
    {
        let mut config = state.config.lock().unwrap();
        config.voice_mode = mode.clone();
        let _ = crate::config::save_config(&config);
    }
    // Apply to active connection if connected
    let conn = state.connection.read().await;
    if let Some(connection) = conn.as_ref() {
        let vm = crate::app_state::VoiceMode::from_str(&mode);
        connection.voice_mode.store(vm as u8, Ordering::Relaxed);
    }
    Ok(())
}

/// Set the VAD threshold in dB (typically -60 to 0).
#[tauri::command]
pub async fn set_vad_threshold(state: State<'_, AppState>, threshold_db: f32) -> Result<(), String> {
    // Always persist
    {
        let mut settings = state.settings.write().await;
        settings.vad_threshold_db = threshold_db;
    }
    {
        let mut config = state.config.lock().unwrap();
        config.vad_threshold_db = threshold_db;
        let _ = crate::config::save_config(&config);
    }
    // Apply to active connection if connected
    let conn = state.connection.read().await;
    if let Some(connection) = conn.as_ref() {
        connection.vad_threshold_db.store(threshold_db as i32, Ordering::Relaxed);
    }
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
    // Read current value from settings (works even when disconnected)
    let prev = {
        let settings = state.settings.read().await;
        settings.noise_suppression
    };
    let new_val = !prev;

    // Update settings + config
    {
        let mut settings = state.settings.write().await;
        settings.noise_suppression = new_val;
    }
    {
        let mut config = state.config.lock().unwrap();
        config.noise_suppression = new_val;
        let _ = crate::config::save_config(&config);
    }

    // Apply to active connection if connected
    let conn = state.connection.read().await;
    if let Some(connection) = conn.as_ref() {
        connection.noise_suppression.store(new_val, Ordering::Relaxed);
    }
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

/// Status of the chat history file system.
#[derive(Serialize)]
pub struct ChatHistoryStatus {
    /// Whether a path is configured in settings.json.
    pub path_configured: bool,
    /// The currently resolved file path (for display).
    pub current_path: String,
    /// Whether a valid VoIPC chat history file exists at the resolved path.
    pub file_exists: bool,
}

/// Get the current chat history status (path configuration + file existence).
#[tauri::command]
pub async fn get_chat_history_status(
    state: State<'_, AppState>,
) -> Result<ChatHistoryStatus, String> {
    let config = state.config.lock().unwrap().clone();
    let path_configured = config.chat_history_path.is_some();
    let file_path = crate::config::resolve_chat_history_path(&config);

    // Store the resolved path in ChatState for later use
    {
        let mut chat = state.chat.write().await;
        chat.file_path = file_path.clone();
    }

    let file_exists = if file_path.exists() {
        match std::fs::read(&file_path) {
            Ok(data) => crypto::has_valid_header(&data),
            Err(_) => false,
        }
    } else {
        false
    };

    Ok(ChatHistoryStatus {
        path_configured,
        current_path: file_path.to_string_lossy().to_string(),
        file_exists,
    })
}

/// Result of setting or checking a chat history path.
#[derive(Serialize)]
pub struct SetPathResult {
    /// The full path to chat_history.bin in the chosen directory.
    pub full_path: String,
    /// Whether a valid VoIPC file already exists at this path.
    pub file_exists: bool,
}

/// Open a native directory picker for chat history storage location.
#[tauri::command]
pub async fn browse_chat_history_directory() -> Option<String> {
    let result = rfd::AsyncFileDialog::new()
        .set_title("Select chat history storage directory")
        .pick_folder()
        .await;
    result.map(|f| f.path().to_string_lossy().to_string())
}

/// Set the chat history storage directory. Validates the directory,
/// persists to config, and updates ChatState.
#[tauri::command]
pub async fn set_chat_history_path(
    state: State<'_, AppState>,
    directory: String,
) -> Result<SetPathResult, String> {
    let dir_path = std::path::PathBuf::from(&directory);

    // Create directory if it doesn't exist
    if !dir_path.exists() {
        std::fs::create_dir_all(&dir_path)
            .map_err(|e| format!("Cannot create directory: {e}"))?;
    }
    if !dir_path.is_dir() {
        return Err("Selected path is not a directory".into());
    }

    // Test write permission
    let test_file = dir_path.join(".voipc_write_test");
    std::fs::write(&test_file, b"test")
        .map_err(|e| format!("Directory is not writable: {e}"))?;
    let _ = std::fs::remove_file(&test_file);

    let full_path = dir_path.join("chat_history.bin");
    let full_path_str = full_path.to_string_lossy().to_string();

    // Check if a valid file already exists there
    let file_exists = if full_path.exists() {
        match std::fs::read(&full_path) {
            Ok(data) => {
                if !crypto::has_valid_header(&data) {
                    return Err(
                        "A file named chat_history.bin exists at this location but is not a valid VoIPC chat history file. Please choose a different directory.".into()
                    );
                }
                true
            }
            Err(_) => false,
        }
    } else {
        false
    };

    // Persist to config
    {
        let mut config = state.config.lock().unwrap();
        config.chat_history_path = Some(full_path_str.clone());
        crate::config::save_config(&config)
            .map_err(|e| format!("Failed to save config: {e}"))?;
    }

    // Update ChatState
    {
        let mut chat = state.chat.write().await;
        chat.file_path = full_path;
    }

    Ok(SetPathResult {
        full_path: full_path_str,
        file_exists,
    })
}

/// Delete the chat history file from disk and reset all in-memory state.
#[tauri::command]
pub async fn delete_chat_history(
    state: State<'_, AppState>,
) -> Result<String, String> {
    let mut chat = state.chat.write().await;
    let path = chat.file_path.clone();

    if path.exists() {
        std::fs::remove_file(&path)
            .map_err(|e| format!("Failed to delete file: {e}"))?;
    }

    // Reset in-memory state
    chat.archive = ChatArchive::default();
    chat.sealing_key = None;
    chat.salt = [0u8; 32];
    chat.dirty = false;

    // Clear the configured path so user is prompted fresh
    {
        let mut config = state.config.lock().unwrap();
        config.chat_history_path = None;
        let _ = crate::config::save_config(&config);
    }

    Ok(path.to_string_lossy().to_string())
}

/// Check whether a valid VoIPC chat history file exists in a given directory.
/// Does NOT modify any state.
#[tauri::command]
pub async fn check_path_status(directory: String) -> Result<SetPathResult, String> {
    let dir_path = std::path::PathBuf::from(&directory);
    if !dir_path.is_dir() {
        return Err("Not a valid directory".into());
    }
    let full_path = dir_path.join("chat_history.bin");
    let full_path_str = full_path.to_string_lossy().to_string();

    let file_exists = if full_path.exists() {
        match std::fs::read(&full_path) {
            Ok(data) => {
                if !crypto::has_valid_header(&data) {
                    return Err(
                        "A file exists at this location but is not a valid VoIPC chat history file".into()
                    );
                }
                true
            }
            Err(_) => false,
        }
    } else {
        false
    };

    Ok(SetPathResult {
        full_path: full_path_str,
        file_exists,
    })
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

// ---------------------------------------------------------------------------
// Persistent config commands
// ---------------------------------------------------------------------------

/// Return the full persisted config to the frontend (called once on init).
#[tauri::command]
pub fn load_config(state: State<'_, AppState>) -> crate::config::AppConfig {
    state.config.lock().unwrap().clone()
}

/// Save connection details for pre-filling on next launch.
#[tauri::command]
pub fn save_connection_info(
    state: State<'_, AppState>,
    host: String,
    port: u16,
    username: String,
    accept_self_signed: bool,
    remember: bool,
) -> Result<(), String> {
    let mut config = state.config.lock().unwrap();
    config.remember_connection = remember;
    if remember {
        config.last_host = Some(host);
        config.last_port = Some(port);
        config.last_username = Some(username);
        config.last_accept_self_signed = Some(accept_self_signed);
    } else {
        config.last_host = None;
        config.last_port = None;
        config.last_username = None;
        config.last_accept_self_signed = None;
        config.auto_connect = false;
    }
    crate::config::save_config(&config)
}

/// Reset all settings to defaults and delete the config file.
#[tauri::command]
pub async fn reset_config(state: State<'_, AppState>) -> Result<(), String> {
    let default_config = crate::config::AppConfig::default();

    // Reset in-memory settings
    {
        let mut settings = state.settings.write().await;
        *settings = crate::app_state::UserSettings::default();
    }
    {
        let mut ptt = state.ptt_binding.write().unwrap();
        *ptt = crate::app_state::PttBinding::default();
    }
    state.ptt_hold_mode.store(true, Ordering::Relaxed);

    // Reset config
    {
        let mut config = state.config.lock().unwrap();
        *config = default_config;
    }
    crate::config::delete_config();
    tracing::info!("User config reset to defaults");
    Ok(())
}

// ---------------------------------------------------------------------------
// Notification sounds
// ---------------------------------------------------------------------------

/// Allowed sound file extensions.
const ALLOWED_SOUND_EXTENSIONS: &[&str] = &["mp3", "wav", "ogg"];

/// Validate a sound file path: must exist, have an allowed extension, and be a regular file.
fn validate_sound_path(path_str: &str) -> Result<std::path::PathBuf, String> {
    let path = std::path::PathBuf::from(path_str);

    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase())
        .unwrap_or_default();
    if !ALLOWED_SOUND_EXTENSIONS.contains(&ext.as_str()) {
        return Err(format!("Unsupported audio format: .{ext}"));
    }

    if !path.is_file() {
        return Err(format!("Sound file not found: {}", path.display()));
    }

    path.canonicalize()
        .map_err(|e| format!("Failed to resolve path: {e}"))
}

/// Play an audio file in a background thread via rodio.
fn play_audio_file(path: std::path::PathBuf) {
    std::thread::spawn(move || {
        let Ok((_stream, handle)) = rodio::OutputStream::try_default() else {
            tracing::warn!("Failed to open audio output for notification sound");
            return;
        };
        let Ok(file) = std::fs::File::open(&path) else {
            tracing::warn!("Failed to open sound file: {}", path.display());
            return;
        };
        let Ok(source) = rodio::Decoder::new(std::io::BufReader::new(file)) else {
            tracing::warn!("Failed to decode sound file: {}", path.display());
            return;
        };
        let Ok(sink) = rodio::Sink::try_new(&handle) else {
            tracing::warn!("Failed to create audio sink for notification");
            return;
        };
        sink.append(source);
        sink.sleep_until_end();
    });
}

/// Play a notification sound for the given event name.
/// Reads sound settings from AppConfig. Silently returns Ok if disabled or no file configured.
#[tauri::command]
pub fn play_notification_sound(
    state: State<'_, AppState>,
    name: String,
) -> Result<(), String> {
    let config = state.config.lock().unwrap();
    let entry = match name.as_str() {
        "channel_switch" => &config.sounds.channel_switch,
        "user_joined" => &config.sounds.user_joined,
        "user_left" => &config.sounds.user_left,
        "disconnected" => &config.sounds.disconnected,
        "direct_message" => &config.sounds.direct_message,
        "channel_message" => &config.sounds.channel_message,
        "poke" => &config.sounds.poke,
        _ => return Err(format!("Unknown sound event: {name}")),
    };

    if !entry.enabled {
        return Ok(());
    }

    let path = match &entry.path {
        Some(p) if !p.is_empty() => match validate_sound_path(p) {
            Ok(canonical) => canonical,
            Err(_) => return Ok(()), // File missing/invalid — silently skip
        },
        _ => return Ok(()), // No path configured
    };

    drop(config); // Release the lock before spawning
    play_audio_file(path);
    Ok(())
}

/// Open a native file picker dialog for selecting a sound file.
/// Returns the selected path, or None if the user cancelled.
#[tauri::command]
pub async fn browse_sound_file() -> Option<String> {
    let result = rfd::AsyncFileDialog::new()
        .set_title("Select notification sound")
        .add_filter("Audio files", &["mp3", "wav", "ogg"])
        .pick_file()
        .await;

    result.map(|f| f.path().to_string_lossy().to_string())
}

/// Update the full sound settings from the frontend.
#[tauri::command]
pub fn set_sound_settings(
    state: State<'_, AppState>,
    settings: crate::config::SoundSettings,
) -> Result<(), String> {
    let mut config = state.config.lock().unwrap();
    config.sounds = settings;
    crate::config::save_config(&config)
}

/// Play a sound file for preview purposes (path provided directly, ignoring config).
#[tauri::command]
pub fn preview_sound(path: String) -> Result<(), String> {
    let canonical = validate_sound_path(&path)?;
    play_audio_file(canonical);
    Ok(())
}

/// Update a boolean config field from the frontend (for frontend-only settings).
#[tauri::command]
pub fn set_config_bool(
    state: State<'_, AppState>,
    key: String,
    value: bool,
) -> Result<(), String> {
    let mut config = state.config.lock().unwrap();
    match key.as_str() {
        "auto_connect" => config.auto_connect = value,
        "remember_connection" => config.remember_connection = value,
        _ => return Err(format!("Unknown config key: {key}")),
    }
    crate::config::save_config(&config)
}
