use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use bytes::BytesMut;
use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::server::TlsStream;
use tracing::{error, info, warn};

use voipc_protocol::codec::{
    decode_client_msg, encode_server_msg, try_decode_frame, APP_VERSION, PROTOCOL_VERSION,
};
use voipc_protocol::messages::{ClientMessage, ServerMessage};
use voipc_protocol::types::*;

use crate::state::ServerState;

/// Handle a single TCP client connection (already TLS-wrapped).
pub async fn handle_connection(
    mut tls_stream: TlsStream<TcpStream>,
    state: Arc<ServerState>,
) {
    let peer_addr = tls_stream
        .get_ref()
        .0
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "unknown".into());

    info!(peer = %peer_addr, "new TCP connection");

    // --- Authentication phase (with timeout) ---
    let mut buf = BytesMut::with_capacity(4096);
    let auth_result = tokio::time::timeout(
        Duration::from_secs(5),
        authenticate(&mut tls_stream, &mut buf, &state, &peer_addr),
    )
    .await;
    let (user_id, session_id) = match auth_result {
        Ok(Ok(ids)) => ids,
        Ok(Err(e)) => {
            warn!(peer = %peer_addr, "authentication failed: {}", e);
            return;
        }
        Err(_) => {
            warn!(peer = %peer_addr, "authentication timed out");
            return;
        }
    };

    info!(peer = %peer_addr, user_id, session_id, "user authenticated");

    // --- Split into reader/writer ---
    let (read_half, mut write_half) = tokio::io::split(tls_stream);

    // Writer task: receives serialized messages from a channel and writes to TCP
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(64);

    let writer_handle = tokio::spawn(async move {
        while let Some(data) = rx.recv().await {
            if let Err(e) = write_half.write_all(&data).await {
                error!("TCP write error: {}", e);
                break;
            }
        }
    });

    // Store the sender in the session
    if let Some(mut session) = state.sessions.get_mut(&session_id) {
        session.tcp_tx = tx.clone();
    }

    // Send channel list
    let channel_list = state.channel_list().await;
    let _ = send_msg(&tx, &ServerMessage::ChannelList { channels: channel_list }).await;

    // Auto-join General (channel 0)
    if let Err(e) = handle_join_channel(&state, user_id, session_id, 0, None, &tx).await {
        error!("failed to auto-join General: {}", e);
    }

    // --- Message loop ---
    let mut read_half = read_half;
    loop {
        match read_half.read_buf(&mut buf).await {
            Ok(0) => {
                info!(user_id, "client disconnected (EOF)");
                break;
            }
            Ok(_) => {}
            Err(e) => {
                error!(user_id, "TCP read error: {}", e);
                break;
            }
        }

        // Process complete messages in the buffer (max 20 per read to prevent burst DoS)
        let mut msgs_this_read = 0u32;
        loop {
            if msgs_this_read >= 20 {
                // Yield to the async runtime before processing more
                tokio::task::yield_now().await;
                msgs_this_read = 0;
            }
            match try_decode_frame(&mut buf) {
                Ok(Some(payload)) => {
                    msgs_this_read += 1;
                    match decode_client_msg(&payload) {
                        Ok(msg) => {
                            if let Err(e) =
                                handle_message(msg, &state, user_id, session_id, &tx).await
                            {
                                error!(user_id, "error handling message: {}", e);
                            }
                        }
                        Err(e) => {
                            warn!(user_id, "failed to decode client message: {}", e);
                        }
                    }
                }
                Ok(None) => break, // need more data
                Err(e) => {
                    error!(user_id, "frame decode error: {}", e);
                    break;
                }
            }
        }
    }

    // --- Cleanup ---
    cleanup_session(&state, user_id, session_id).await;
    writer_handle.abort();
}

/// Perform the authentication handshake.
async fn authenticate(
    stream: &mut TlsStream<TcpStream>,
    buf: &mut BytesMut,
    state: &ServerState,
    peer_addr: &str,
) -> Result<(UserId, SessionId)> {
    // Read until we get a complete message
    loop {
        stream.read_buf(buf).await?;

        if let Some(payload) = try_decode_frame(buf)? {
            let msg = decode_client_msg(&payload)?;

            match msg {
                ClientMessage::Authenticate {
                    username,
                    protocol_version,
                    app_version,
                    identity_key,
                    prekey_bundle,
                } => {
                    if protocol_version != PROTOCOL_VERSION {
                        let err_msg = ServerMessage::AuthError {
                            reason: format!(
                                "protocol version mismatch: client={}, server={}",
                                protocol_version, PROTOCOL_VERSION
                            ),
                        };
                        let data = encode_server_msg(&err_msg)?;
                        stream.write_all(&data).await?;
                        anyhow::bail!("protocol version mismatch");
                    }

                    if app_version != APP_VERSION {
                        let err_msg = ServerMessage::AuthError {
                            reason: format!(
                                "version mismatch: client={}, server={}",
                                app_version, APP_VERSION
                            ),
                        };
                        let data = encode_server_msg(&err_msg)?;
                        stream.write_all(&data).await?;
                        anyhow::bail!("app version mismatch");
                    }

                    let username = username.trim().to_string();
                    let char_count = username.chars().count();
                    if char_count == 0 || char_count > 32 {
                        let err_msg = ServerMessage::AuthError {
                            reason: "username must be 1-32 characters".into(),
                        };
                        let data = encode_server_msg(&err_msg)?;
                        stream.write_all(&data).await?;
                        anyhow::bail!("invalid username");
                    }

                    if username.chars().any(|c| c.is_control()) {
                        let err_msg = ServerMessage::AuthError {
                            reason: "username contains invalid characters".into(),
                        };
                        let data = encode_server_msg(&err_msg)?;
                        stream.write_all(&data).await?;
                        anyhow::bail!("invalid username characters");
                    }

                    if state.is_username_taken(&username) {
                        let err_msg = ServerMessage::AuthError {
                            reason: "username already taken".into(),
                        };
                        let data = encode_server_msg(&err_msg)?;
                        stream.write_all(&data).await?;
                        anyhow::bail!("username taken");
                    }

                    if state.user_count() >= state.max_users as usize {
                        let err_msg = ServerMessage::AuthError {
                            reason: "server is full".into(),
                        };
                        let data = encode_server_msg(&err_msg)?;
                        stream.write_all(&data).await?;
                        anyhow::bail!("server full");
                    }

                    let user_id = state.next_user_id();
                    let session_id = state.next_session_id();
                    let udp_token: u64 = rand::thread_rng().gen();

                    // Extract E2E encryption fields from the pre-key bundle
                    let (prekeys, signed_prekey_id, signed_prekey, signed_prekey_signature, registration_id, device_id) =
                        if let Some(ref bundle) = prekey_bundle {
                            (
                                bundle.prekeys.clone(),
                                Some(bundle.signed_prekey_id),
                                Some(bundle.signed_prekey.clone()),
                                Some(bundle.signed_prekey_signature.clone()),
                                bundle.registration_id,
                                bundle.device_id,
                            )
                        } else {
                            (Vec::new(), None, None, None, 0, 1)
                        };

                    // Create a placeholder sender (will be replaced after split)
                    let (placeholder_tx, _) = mpsc::channel(1);

                    let session = crate::state::UserSession {
                        user_id,
                        session_id,
                        username: username.clone(),
                        channel_id: 0,
                        is_muted: false,
                        is_deafened: false,
                        tcp_tx: placeholder_tx,
                        udp_addr: None,
                        udp_token,
                        chat_rate: crate::state::RateLimiter::new(5.0, 5.0),
                        create_channel_rate: crate::state::RateLimiter::new(1.0, 0.2),
                        prekey_rate: crate::state::RateLimiter::new(1.0, 0.2),
                        is_screen_sharing: false,
                        watching_screenshare: None,
                        identity_key,
                        prekeys,
                        signed_prekey_id,
                        signed_prekey,
                        signed_prekey_signature,
                        registration_id,
                        device_id,
                    };

                    state.sessions.insert(session_id, session);
                    state.user_to_session.insert(user_id, session_id);

                    let auth_msg = ServerMessage::Authenticated {
                        user_id,
                        session_id,
                        udp_port: state.udp_port,
                        udp_token,
                    };
                    let data = encode_server_msg(&auth_msg)?;
                    stream.write_all(&data).await?;

                    info!(
                        peer = %peer_addr,
                        username = %username,
                        user_id,
                        session_id,
                        "authenticated"
                    );

                    return Ok((user_id, session_id));
                }
                _ => {
                    anyhow::bail!("expected Authenticate message, got {:?}", msg);
                }
            }
        }
    }
}

/// Handle a client message after authentication.
async fn handle_message(
    msg: ClientMessage,
    state: &Arc<ServerState>,
    user_id: UserId,
    session_id: SessionId,
    tx: &mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    match msg {
        ClientMessage::JoinChannel {
            channel_id,
            password,
        } => {
            handle_join_channel(state, user_id, session_id, channel_id, password.as_deref(), tx)
                .await?;
        }
        ClientMessage::CreateChannel { name, password } => {
            let allowed = state
                .sessions
                .get_mut(&session_id)
                .map(|mut s| s.create_channel_rate.try_consume())
                .unwrap_or(false);
            if !allowed {
                let _ = send_msg(tx, &ServerMessage::ChannelError {
                    reason: "rate limit exceeded, try again later".into(),
                }).await;
            } else {
                handle_create_channel(state, user_id, session_id, name, password, tx).await?;
            }
        }
        ClientMessage::Disconnect => {
            info!(user_id, "client sent disconnect");
            // Cleanup will happen when the connection loop ends
        }
        ClientMessage::SetMuted { muted } => {
            if let Some(mut session) = state.sessions.get_mut(&session_id) {
                session.is_muted = muted;
            }

            // Broadcast to channel members
            let channel_id = state
                .sessions
                .get(&session_id)
                .map(|s| s.channel_id)
                .unwrap_or(0);

            let msg = ServerMessage::UserMuted { user_id, muted };
            broadcast_to_channel(state, channel_id, &msg, Some(user_id)).await;
        }
        ClientMessage::SetDeafened { deafened } => {
            if let Some(mut session) = state.sessions.get_mut(&session_id) {
                session.is_deafened = deafened;
            }

            // Broadcast to channel members
            let channel_id = state
                .sessions
                .get(&session_id)
                .map(|s| s.channel_id)
                .unwrap_or(0);

            let msg = ServerMessage::UserDeafened { user_id, deafened };
            broadcast_to_channel(state, channel_id, &msg, Some(user_id)).await;
        }
        ClientMessage::RequestChannelList => {
            let channels = state.channel_list().await;
            let _ = send_msg(tx, &ServerMessage::ChannelList { channels }).await;
        }
        ClientMessage::Ping { timestamp } => {
            let _ = send_msg(tx, &ServerMessage::Pong { timestamp }).await;
        }
        ClientMessage::SetChannelPassword {
            channel_id,
            password,
        } => {
            handle_set_channel_password(state, user_id, channel_id, password, tx).await?;
        }
        ClientMessage::KickUser {
            channel_id,
            user_id: target_id,
        } => {
            handle_kick_user(state, user_id, session_id, channel_id, target_id, tx).await?;
        }
        ClientMessage::RequestChannelUsers { channel_id } => {
            let allowed = state.is_channel_public_or_member(channel_id, user_id).await;
            let users = if allowed {
                state.users_in_channel(channel_id).await
            } else {
                vec![]
            };
            let _ = send_msg(tx, &ServerMessage::ChannelUsers { channel_id, users }).await;
        }
        ClientMessage::SendInvite {
            channel_id,
            target_user_id,
        } => {
            handle_send_invite(state, user_id, channel_id, target_user_id, tx).await?;
        }
        ClientMessage::AcceptInvite { channel_id } => {
            // Join with no password — validate_join will check invite set
            handle_join_channel(state, user_id, session_id, channel_id, None, tx).await?;
            // Notify the channel creator that the invite was accepted
            let creator_id = {
                let channels = state.channels.read().await;
                channels.get(&channel_id).and_then(|ch| ch.created_by)
            };
            if let Some(creator_id) = creator_id {
                if let Some(creator_sid) = state.user_to_session.get(&creator_id) {
                    if let Some(session) = state.sessions.get(&*creator_sid) {
                        let _ = send_msg(
                            &session.tcp_tx,
                            &ServerMessage::InviteAccepted {
                                channel_id,
                                user_id,
                            },
                        )
                        .await;
                    }
                }
            }
        }
        ClientMessage::DeclineInvite { channel_id } => {
            handle_decline_invite(state, user_id, channel_id).await?;
        }
        ClientMessage::SendPoke {
            target_user_id,
            ciphertext,
            message_type,
        } => {
            handle_send_poke(state, user_id, session_id, target_user_id, ciphertext, message_type, tx).await?;
        }
        ClientMessage::StartScreenShare { source: _, resolution } => {
            let clamped_resolution = resolution.min(4320); // cap at 8K
            handle_start_screen_share(state, user_id, session_id, clamped_resolution, tx).await?;
        }
        ClientMessage::StopScreenShare => {
            handle_stop_screen_share(state, user_id, session_id, tx).await?;
        }
        ClientMessage::WatchScreenShare { sharer_user_id } => {
            handle_watch_screen_share(state, user_id, session_id, sharer_user_id, tx).await?;
        }
        ClientMessage::StopWatchingScreenShare => {
            handle_stop_watching(state, user_id, session_id, tx).await?;
        }
        ClientMessage::RequestKeyframe { sharer_user_id } => {
            handle_request_keyframe(state, sharer_user_id).await?;
        }
        ClientMessage::Authenticate { .. } => {
            warn!(user_id, "received duplicate Authenticate message, ignoring");
        }

        // ── E2E Encryption handlers ──────────────────────────────────────
        ClientMessage::RequestPreKeyBundle { target_user_id } => {
            handle_request_prekey_bundle(state, target_user_id, tx).await?;
        }
        ClientMessage::UploadPreKeys { prekeys } => {
            let allowed = state
                .sessions
                .get_mut(&session_id)
                .map(|mut s| s.prekey_rate.try_consume())
                .unwrap_or(false);
            if allowed {
                handle_upload_prekeys(state, session_id, prekeys).await;
            }
        }
        ClientMessage::SendEncryptedDirectMessage {
            target_user_id,
            ciphertext,
            message_type,
        } => {
            let allowed = state
                .sessions
                .get_mut(&session_id)
                .map(|mut s| s.chat_rate.try_consume())
                .unwrap_or(false);
            if !allowed {
                let _ = send_msg(tx, &ServerMessage::ChannelError {
                    reason: "sending too fast, slow down".into(),
                }).await;
            } else {
                handle_encrypted_direct_message(
                    state, user_id, session_id, target_user_id, ciphertext, message_type, tx,
                ).await?;
            }
        }
        ClientMessage::SendEncryptedChannelMessage { ciphertext } => {
            let allowed = state
                .sessions
                .get_mut(&session_id)
                .map(|mut s| s.chat_rate.try_consume())
                .unwrap_or(false);
            if !allowed {
                let _ = send_msg(tx, &ServerMessage::ChannelError {
                    reason: "sending too fast, slow down".into(),
                }).await;
            } else {
                handle_encrypted_channel_message(
                    state, user_id, session_id, ciphertext, tx,
                ).await?;
            }
        }
        ClientMessage::DistributeSenderKey {
            channel_id,
            target_user_id,
            distribution_message,
            message_type,
        } => {
            handle_distribute_sender_key(
                state, user_id, channel_id, target_user_id, distribution_message, message_type,
            ).await?;
        }
        ClientMessage::DistributeMediaKey {
            channel_id,
            target_user_id,
            encrypted_media_key,
        } => {
            handle_distribute_media_key(
                state, user_id, channel_id, target_user_id, encrypted_media_key,
            ).await?;
        }
    }
    Ok(())
}

/// Handle a channel join request.
async fn handle_join_channel(
    state: &Arc<ServerState>,
    user_id: UserId,
    session_id: SessionId,
    channel_id: ChannelId,
    password: Option<&str>,
    tx: &mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    // Validate the join BEFORE leaving the current channel.
    // This way, if the password is wrong or the channel is full,
    // the user stays where they are instead of being dumped into General.
    if let Err(e) = state.validate_join(channel_id, password, user_id).await {
        let _ = send_msg(
            tx,
            &ServerMessage::ChannelError {
                reason: e.to_string(),
            },
        )
        .await;
        return Ok(());
    }

    // Capture the old channel BEFORE leaving so we can clean up screenshare state
    let old_channel_id = state
        .sessions
        .get(&session_id)
        .map(|s| s.channel_id)
        .unwrap_or(0);

    // Clean up screenshare state from the old channel before leaving
    if old_channel_id != channel_id && old_channel_id != 0 {
        let cleanup = state
            .cleanup_screen_shares_for_user(user_id, session_id, old_channel_id)
            .await;

        // Notify viewers that the share stopped
        for viewer_sid in &cleanup.viewers_to_notify_stopped {
            if let Some(session) = state.sessions.get(viewer_sid) {
                let _ = send_msg(
                    &session.tcp_tx,
                    &ServerMessage::StoppedWatchingScreenShare {
                        reason: "sharer_left".into(),
                    },
                )
                .await;
            }
        }

        // Broadcast ScreenShareStopped to old channel
        if let Some(sharer_uid) = cleanup.stopped_sharer_user_id {
            let msg = ServerMessage::ScreenShareStopped {
                user_id: sharer_uid,
            };
            for &sid in &cleanup.channel_member_sessions {
                if let Some(session) = state.sessions.get(&sid) {
                    let _ = send_msg(&session.tcp_tx, &msg).await;
                }
            }
        }

        // Notify sharer of viewer count change (if we were watching someone)
        if let Some((sharer_sid, new_count)) = cleanup.sharer_viewer_count_changed {
            if let Some(session) = state.sessions.get(&sharer_sid) {
                let _ = send_msg(
                    &session.tcp_tx,
                    &ServerMessage::ViewerCountChanged {
                        viewer_count: new_count,
                    },
                )
                .await;
            }
        }
    }

    // Now leave the current channel
    if let Some((left_channel_id, _remaining, remaining_count)) =
        state.leave_current_channel(user_id, session_id).await
    {
        let leave_msg = ServerMessage::UserLeft {
            user_id,
            channel_id: left_channel_id,
        };
        broadcast_to_all(state, &leave_msg, Some(user_id)).await;

        if remaining_count == 0 && left_channel_id != 0 {
            start_channel_delete_timer(state, left_channel_id).await;
        }
    }

    // Join the new channel (should succeed since we validated above)
    if let Err(e) = state
        .join_channel(user_id, session_id, channel_id, password)
        .await
    {
        // Shouldn't happen, but handle gracefully
        warn!(user_id, "join failed after validation: {}", e);
        let _ = state.join_channel(user_id, session_id, 0, None).await;
        let users = state.users_in_channel(0).await;
        let _ = send_msg(
            tx,
            &ServerMessage::UserList {
                channel_id: 0,
                users,
            },
        )
        .await;
        return Ok(());
    }

    // Send user list for the new channel to the joining user
    let users = state.users_in_channel(channel_id).await;
    let _ = send_msg(
        tx,
        &ServerMessage::UserList {
            channel_id,
            users,
        },
    )
    .await;

    // Send the channel's media encryption key (for voice/video AES-256-GCM)
    if let Some((key_id, key_bytes)) = state.get_channel_media_key(channel_id).await {
        let _ = send_msg(
            tx,
            &ServerMessage::ChannelMediaKey {
                channel_id,
                key_id,
                key_bytes: key_bytes.to_vec(),
            },
        )
        .await;
    }

    // Build user info for the join notification
    let user_info = UserInfo {
        user_id,
        username: state
            .sessions
            .get(&session_id)
            .map(|s| s.username.clone())
            .unwrap_or_default(),
        channel_id,
        is_muted: state
            .sessions
            .get(&session_id)
            .map(|s| s.is_muted)
            .unwrap_or(false),
        is_deafened: state
            .sessions
            .get(&session_id)
            .map(|s| s.is_deafened)
            .unwrap_or(false),
        is_screen_sharing: false,
    };

    let join_msg = ServerMessage::UserJoined { user: user_info };
    broadcast_to_all(state, &join_msg, Some(user_id)).await;

    Ok(())
}

/// Handle a create channel request.
async fn handle_create_channel(
    state: &Arc<ServerState>,
    user_id: UserId,
    session_id: SessionId,
    name: String,
    password: Option<String>,
    tx: &mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    // Validate and sanitize name
    let name = name.trim().to_string();
    if name.is_empty() || name.len() > state.settings.max_channel_name_len {
        let _ = send_msg(
            tx,
            &ServerMessage::ChannelError {
                reason: format!(
                    "channel name must be 1-{} characters",
                    state.settings.max_channel_name_len
                ),
            },
        )
        .await;
        return Ok(());
    }

    if name.chars().any(|c| c.is_control()) {
        let _ = send_msg(
            tx,
            &ServerMessage::ChannelError {
                reason: "channel name contains invalid characters".into(),
            },
        )
        .await;
        return Ok(());
    }

    // Store password for the join call (create_channel takes ownership)
    let join_password = password.clone();

    match state.create_channel(name, password, user_id).await {
        Ok(info) => {
            let channel_id = info.channel_id;
            // Broadcast ChannelCreated to all users
            let msg = ServerMessage::ChannelCreated { channel: info };
            broadcast_to_all(state, &msg, None).await;

            // Auto-join the creator into the new channel
            handle_join_channel(
                state,
                user_id,
                session_id,
                channel_id,
                join_password.as_deref(),
                tx,
            )
            .await?;
        }
        Err(e) => {
            let _ = send_msg(
                tx,
                &ServerMessage::ChannelError {
                    reason: e.to_string(),
                },
            )
            .await;
        }
    }

    Ok(())
}

/// Handle a password change request from the channel creator.
async fn handle_set_channel_password(
    state: &Arc<ServerState>,
    user_id: UserId,
    channel_id: ChannelId,
    password: Option<String>,
    tx: &mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    match state.set_channel_password(channel_id, user_id, password).await {
        Ok(updated_info) => {
            let msg = ServerMessage::ChannelUpdated {
                channel: updated_info,
            };
            broadcast_to_all(state, &msg, None).await;
        }
        Err(e) => {
            let _ = send_msg(
                tx,
                &ServerMessage::ChannelError {
                    reason: e.to_string(),
                },
            )
            .await;
        }
    }
    Ok(())
}

/// Handle a kick request from the channel creator.
async fn handle_kick_user(
    state: &Arc<ServerState>,
    requester_id: UserId,
    _requester_session_id: SessionId,
    channel_id: ChannelId,
    target_id: UserId,
    tx: &mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    match state.kick_user(channel_id, requester_id, target_id).await {
        Ok((target_session_id, remaining_count)) => {
            // Notify the kicked user
            if let Some(session) = state.sessions.get(&target_session_id) {
                let _ = send_msg(
                    &session.tcp_tx,
                    &ServerMessage::Kicked {
                        channel_id,
                        reason: "You were kicked by the channel creator".into(),
                    },
                )
                .await;
            }

            // Broadcast UserLeft to everyone
            let leave_msg = ServerMessage::UserLeft {
                user_id: target_id,
                channel_id,
            };
            broadcast_to_all(state, &leave_msg, Some(target_id)).await;

            // Move the kicked user to General (channel 0)
            let _ = state.join_channel(target_id, target_session_id, 0, None).await;
            let general_users = state.users_in_channel(0).await;

            if let Some(session) = state.sessions.get(&target_session_id) {
                let _ = send_msg(
                    &session.tcp_tx,
                    &ServerMessage::UserList {
                        channel_id: 0,
                        users: general_users,
                    },
                )
                .await;
            }

            // Broadcast UserJoined (to General) to everyone
            let user_info = UserInfo {
                user_id: target_id,
                username: state
                    .sessions
                    .get(&target_session_id)
                    .map(|s| s.username.clone())
                    .unwrap_or_default(),
                channel_id: 0,
                is_muted: state
                    .sessions
                    .get(&target_session_id)
                    .map(|s| s.is_muted)
                    .unwrap_or(false),
                is_deafened: state
                    .sessions
                    .get(&target_session_id)
                    .map(|s| s.is_deafened)
                    .unwrap_or(false),
                is_screen_sharing: false,
            };
            let join_msg = ServerMessage::UserJoined { user: user_info };
            broadcast_to_all(state, &join_msg, Some(target_id)).await;

            // Start auto-delete timer if the channel is now empty
            if remaining_count == 0 {
                start_channel_delete_timer(state, channel_id).await;
            }
        }
        Err(e) => {
            let _ = send_msg(
                tx,
                &ServerMessage::ChannelError {
                    reason: e.to_string(),
                },
            )
            .await;
        }
    }
    Ok(())
}

/// Handle a channel invite from the channel creator.
async fn handle_send_invite(
    state: &Arc<ServerState>,
    requester_id: UserId,
    channel_id: ChannelId,
    target_user_id: UserId,
    tx: &mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    match state.add_invite(channel_id, requester_id, target_user_id).await {
        Ok((channel_name, invited_by)) => {
            // Send InviteReceived to the target user
            if let Some(target_sid) = state.user_to_session.get(&target_user_id) {
                if let Some(session) = state.sessions.get(&*target_sid) {
                    let _ = send_msg(
                        &session.tcp_tx,
                        &ServerMessage::InviteReceived {
                            channel_id,
                            channel_name,
                            invited_by,
                        },
                    )
                    .await;
                }
            }
        }
        Err(e) => {
            let _ = send_msg(
                tx,
                &ServerMessage::ChannelError {
                    reason: e.to_string(),
                },
            )
            .await;
        }
    }
    Ok(())
}

/// Handle a poke from one user to another.
/// The server only relays the opaque ciphertext — it cannot read the poke message.
async fn handle_send_poke(
    state: &Arc<ServerState>,
    from_user_id: UserId,
    from_session_id: SessionId,
    target_user_id: UserId,
    ciphertext: Vec<u8>,
    message_type: u8,
    tx: &mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    // Look up sender username
    let from_username = state
        .sessions
        .get(&from_session_id)
        .map(|s| s.username.clone())
        .unwrap_or_default();

    // Find the target user's session and relay the encrypted poke
    match state.user_to_session.get(&target_user_id) {
        Some(target_sid) => {
            if let Some(session) = state.sessions.get(&*target_sid) {
                let _ = send_msg(
                    &session.tcp_tx,
                    &ServerMessage::PokeReceived {
                        from_user_id,
                        from_username,
                        ciphertext,
                        message_type,
                    },
                )
                .await;
            }
        }
        None => {
            let _ = send_msg(
                tx,
                &ServerMessage::ChannelError {
                    reason: "User not found".into(),
                },
            )
            .await;
        }
    }
    Ok(())
}

/// Handle a declined channel invite.
async fn handle_decline_invite(
    state: &Arc<ServerState>,
    user_id: UserId,
    channel_id: ChannelId,
) -> Result<()> {
    // Look up the channel creator to notify them
    let creator_id = {
        let channels = state.channels.read().await;
        channels
            .get(&channel_id)
            .and_then(|ch| ch.created_by)
    };

    state.remove_invite(channel_id, user_id).await;

    // Notify the creator
    if let Some(creator_id) = creator_id {
        if let Some(creator_sid) = state.user_to_session.get(&creator_id) {
            if let Some(session) = state.sessions.get(&*creator_sid) {
                let _ = send_msg(
                    &session.tcp_tx,
                    &ServerMessage::InviteDeclined {
                        channel_id,
                        user_id,
                    },
                )
                .await;
            }
        }
    }

    Ok(())
}

// ── Screen share handlers ──────────────────────────────────────────────

/// Handle a screen share start request.
async fn handle_start_screen_share(
    state: &Arc<ServerState>,
    user_id: UserId,
    session_id: SessionId,
    resolution: u16,
    tx: &mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    let channel_id = state
        .sessions
        .get(&session_id)
        .map(|s| s.channel_id)
        .unwrap_or(0);

    match state
        .start_screen_share(user_id, session_id, channel_id, resolution)
        .await
    {
        Ok(member_sessions) => {
            let username = state
                .sessions
                .get(&session_id)
                .map(|s| s.username.clone())
                .unwrap_or_default();

            let msg = ServerMessage::ScreenShareStarted {
                user_id,
                username,
                resolution,
            };

            // Broadcast to all channel members (including sender for confirmation)
            for sid in &member_sessions {
                if let Some(session) = state.sessions.get(sid) {
                    let _ = send_msg(&session.tcp_tx, &msg).await;
                }
            }
            // Also send to the sharer themselves
            let _ = send_msg(tx, &msg).await;
        }
        Err(e) => {
            let _ = send_msg(
                tx,
                &ServerMessage::ScreenShareError {
                    reason: e.to_string(),
                },
            )
            .await;
        }
    }
    Ok(())
}

/// Handle a screen share stop request.
async fn handle_stop_screen_share(
    state: &Arc<ServerState>,
    user_id: UserId,
    session_id: SessionId,
    tx: &mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    let channel_id = state
        .sessions
        .get(&session_id)
        .map(|s| s.channel_id)
        .unwrap_or(0);

    match state
        .stop_screen_share(user_id, session_id, channel_id)
        .await
    {
        Ok((viewer_sessions, member_sessions)) => {
            // Notify each viewer that their watch stopped
            for (_, viewer_sid) in &viewer_sessions {
                if let Some(session) = state.sessions.get(viewer_sid) {
                    let _ = send_msg(
                        &session.tcp_tx,
                        &ServerMessage::StoppedWatchingScreenShare {
                            reason: "sharer_stopped".into(),
                        },
                    )
                    .await;
                }
            }

            // Broadcast ScreenShareStopped to all channel members
            let msg = ServerMessage::ScreenShareStopped { user_id };
            for sid in &member_sessions {
                if let Some(session) = state.sessions.get(sid) {
                    let _ = send_msg(&session.tcp_tx, &msg).await;
                }
            }
            let _ = send_msg(tx, &msg).await;
        }
        Err(e) => {
            let _ = send_msg(
                tx,
                &ServerMessage::ScreenShareError {
                    reason: e.to_string(),
                },
            )
            .await;
        }
    }
    Ok(())
}

/// Handle a request to watch a screen share.
async fn handle_watch_screen_share(
    state: &Arc<ServerState>,
    viewer_user_id: UserId,
    viewer_session_id: SessionId,
    sharer_user_id: UserId,
    tx: &mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    let channel_id = state
        .sessions
        .get(&viewer_session_id)
        .map(|s| s.channel_id)
        .unwrap_or(0);

    match state
        .watch_screen_share(viewer_user_id, viewer_session_id, sharer_user_id, channel_id)
        .await
    {
        Ok((sharer_sid, old_count, new_count, prev_unwatch)) => {
            // Confirm to viewer
            let _ = send_msg(
                tx,
                &ServerMessage::WatchingScreenShare { sharer_user_id },
            )
            .await;

            // Notify sharer of new viewer count
            if let Some(session) = state.sessions.get(&sharer_sid) {
                let _ = send_msg(
                    &session.tcp_tx,
                    &ServerMessage::ViewerCountChanged {
                        viewer_count: new_count,
                    },
                )
                .await;

                // If this is the first viewer, also request a keyframe
                if old_count == 0 && new_count > 0 {
                    let _ =
                        send_msg(&session.tcp_tx, &ServerMessage::KeyframeRequested)
                            .await;
                }
            }

            // If viewer was auto-unwatched from a previous sharer, notify that sharer
            if let Some((prev_sharer_id, prev_sharer_sid, prev_new_count)) = prev_unwatch {
                if prev_sharer_id != sharer_user_id {
                    if let Some(session) = state.sessions.get(&prev_sharer_sid) {
                        let _ = send_msg(
                            &session.tcp_tx,
                            &ServerMessage::ViewerCountChanged {
                                viewer_count: prev_new_count,
                            },
                        )
                        .await;
                    }
                }
            }
        }
        Err(e) => {
            let _ = send_msg(
                tx,
                &ServerMessage::ScreenShareError {
                    reason: e.to_string(),
                },
            )
            .await;
        }
    }
    Ok(())
}

/// Handle a stop watching request.
async fn handle_stop_watching(
    state: &Arc<ServerState>,
    viewer_user_id: UserId,
    viewer_session_id: SessionId,
    tx: &mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    let channel_id = state
        .sessions
        .get(&viewer_session_id)
        .map(|s| s.channel_id)
        .unwrap_or(0);

    match state
        .stop_watching_screen_share(viewer_user_id, viewer_session_id, channel_id)
        .await
    {
        Ok((_sharer_uid, sharer_sid, _old_count, new_count)) => {
            // Confirm to viewer
            let _ = send_msg(
                tx,
                &ServerMessage::StoppedWatchingScreenShare {
                    reason: "requested".into(),
                },
            )
            .await;

            // Notify sharer of updated viewer count
            if let Some(session) = state.sessions.get(&sharer_sid) {
                let _ = send_msg(
                    &session.tcp_tx,
                    &ServerMessage::ViewerCountChanged {
                        viewer_count: new_count,
                    },
                )
                .await;
            }
        }
        Err(e) => {
            let _ = send_msg(
                tx,
                &ServerMessage::ScreenShareError {
                    reason: e.to_string(),
                },
            )
            .await;
        }
    }
    Ok(())
}

/// Handle a keyframe request — relay to the sharer.
async fn handle_request_keyframe(
    state: &Arc<ServerState>,
    sharer_user_id: UserId,
) -> Result<()> {
    if let Some(sharer_sid) = state.user_to_session.get(&sharer_user_id) {
        if let Some(session) = state.sessions.get(&*sharer_sid) {
            let _ = send_msg(&session.tcp_tx, &ServerMessage::KeyframeRequested).await;
        }
    }
    Ok(())
}

// ── E2E Encryption handler functions ──────────────────────────────────

/// Handle a pre-key bundle request — return the target user's bundle (consuming one pre-key).
async fn handle_request_prekey_bundle(
    state: &Arc<ServerState>,
    target_user_id: UserId,
    tx: &mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    let target_sid = match state.user_to_session.get(&target_user_id) {
        Some(sid) => *sid,
        None => {
            let _ = send_msg(tx, &ServerMessage::PreKeyBundleUnavailable {
                user_id: target_user_id,
            }).await;
            return Ok(());
        }
    };

    let bundle = {
        let mut session = match state.sessions.get_mut(&target_sid) {
            Some(s) => s,
            None => {
                let _ = send_msg(tx, &ServerMessage::PreKeyBundleUnavailable {
                    user_id: target_user_id,
                }).await;
                return Ok(());
            }
        };

        // Need identity key + signed pre-key at minimum
        let identity_key = match &session.identity_key {
            Some(k) => k.clone(),
            None => {
                let _ = send_msg(tx, &ServerMessage::PreKeyBundleUnavailable {
                    user_id: target_user_id,
                }).await;
                return Ok(());
            }
        };

        let signed_prekey = match &session.signed_prekey {
            Some(k) => k.clone(),
            None => {
                let _ = send_msg(tx, &ServerMessage::PreKeyBundleUnavailable {
                    user_id: target_user_id,
                }).await;
                return Ok(());
            }
        };

        let signed_prekey_signature = session.signed_prekey_signature.clone().unwrap_or_default();
        let signed_prekey_id = session.signed_prekey_id.unwrap_or(0);

        // Pop one one-time pre-key (consumed by the requester)
        let prekeys = if session.prekeys.is_empty() {
            vec![]
        } else {
            vec![session.prekeys.remove(0)]
        };

        PreKeyBundleData {
            registration_id: session.registration_id,
            device_id: session.device_id,
            identity_key,
            signed_prekey_id,
            signed_prekey,
            signed_prekey_signature,
            prekeys,
        }
    };

    let _ = send_msg(tx, &ServerMessage::PreKeyBundle {
        user_id: target_user_id,
        bundle,
    }).await;

    Ok(())
}

/// Handle uploaded pre-keys — replenish the user's one-time pre-key supply.
/// Caps total stored pre-keys at 100 per user to prevent memory exhaustion.
async fn handle_upload_prekeys(
    state: &Arc<ServerState>,
    session_id: SessionId,
    prekeys: Vec<OneTimePreKey>,
) {
    const MAX_PREKEYS: usize = 100;
    if let Some(mut session) = state.sessions.get_mut(&session_id) {
        let remaining_capacity = MAX_PREKEYS.saturating_sub(session.prekeys.len());
        if remaining_capacity > 0 {
            session
                .prekeys
                .extend(prekeys.into_iter().take(remaining_capacity));
        }
    }
}

/// Handle an encrypted direct message — relay opaquely to the target user.
async fn handle_encrypted_direct_message(
    state: &Arc<ServerState>,
    from_user_id: UserId,
    from_session_id: SessionId,
    target_user_id: UserId,
    ciphertext: Vec<u8>,
    message_type: u8,
    tx: &mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    let from_username = state
        .sessions
        .get(&from_session_id)
        .map(|s| s.username.clone())
        .unwrap_or_default();

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let msg = ServerMessage::EncryptedDirectChatMessage {
        from_user_id,
        from_username,
        to_user_id: target_user_id,
        ciphertext,
        message_type,
        timestamp,
    };

    // Send to target
    if let Some(target_sid) = state.user_to_session.get(&target_user_id) {
        if let Some(session) = state.sessions.get(&*target_sid) {
            let _ = send_msg(&session.tcp_tx, &msg).await;
        } else {
            let _ = send_msg(tx, &ServerMessage::ChannelError {
                reason: "User not found".into(),
            }).await;
            return Ok(());
        }
    } else {
        let _ = send_msg(tx, &ServerMessage::ChannelError {
            reason: "User not found".into(),
        }).await;
        return Ok(());
    }

    // Echo back to sender
    let _ = send_msg(tx, &msg).await;

    Ok(())
}

/// Handle an encrypted channel message — relay opaquely to channel members.
async fn handle_encrypted_channel_message(
    state: &Arc<ServerState>,
    user_id: UserId,
    session_id: SessionId,
    ciphertext: Vec<u8>,
    tx: &mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    let (channel_id, username) = {
        let session = state.sessions.get(&session_id);
        match session {
            Some(s) => (s.channel_id, s.username.clone()),
            None => return Ok(()),
        }
    };

    if channel_id == 0 {
        let _ = send_msg(tx, &ServerMessage::ChannelError {
            reason: "Chat is not available in the lobby".into(),
        }).await;
        return Ok(());
    }

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let msg = ServerMessage::EncryptedChannelChatMessage {
        channel_id,
        user_id,
        username,
        ciphertext,
        timestamp,
    };

    // Encrypted channel messages go to channel members except the sender
    // (sender can't decrypt their own sender key ciphertext)
    broadcast_to_channel(state, channel_id, &msg, Some(user_id)).await;

    Ok(())
}

/// Handle a sender key distribution — relay to the target user.
async fn handle_distribute_sender_key(
    state: &Arc<ServerState>,
    from_user_id: UserId,
    channel_id: ChannelId,
    target_user_id: UserId,
    distribution_message: Vec<u8>,
    message_type: u8,
) -> Result<()> {
    if let Some(target_sid) = state.user_to_session.get(&target_user_id) {
        if let Some(session) = state.sessions.get(&*target_sid) {
            let _ = send_msg(
                &session.tcp_tx,
                &ServerMessage::SenderKeyReceived {
                    channel_id,
                    from_user_id,
                    distribution_message,
                    message_type,
                },
            ).await;
        }
    }
    Ok(())
}

/// Handle a media key distribution — relay to the target user.
async fn handle_distribute_media_key(
    state: &Arc<ServerState>,
    from_user_id: UserId,
    channel_id: ChannelId,
    target_user_id: UserId,
    encrypted_media_key: Vec<u8>,
) -> Result<()> {
    if let Some(target_sid) = state.user_to_session.get(&target_user_id) {
        if let Some(session) = state.sessions.get(&*target_sid) {
            let _ = send_msg(
                &session.tcp_tx,
                &ServerMessage::MediaKeyReceived {
                    channel_id,
                    from_user_id,
                    encrypted_media_key,
                },
            ).await;
        }
    }
    Ok(())
}

/// Clean up when a user disconnects.
async fn cleanup_session(state: &Arc<ServerState>, user_id: UserId, session_id: SessionId) {
    // Clean up screen share state before leaving the channel
    let channel_id = state
        .sessions
        .get(&session_id)
        .map(|s| s.channel_id)
        .unwrap_or(0);

    if channel_id != 0 {
        let cleanup = state
            .cleanup_screen_shares_for_user(user_id, session_id, channel_id)
            .await;

        // Notify viewers that the share stopped
        for viewer_sid in &cleanup.viewers_to_notify_stopped {
            if let Some(session) = state.sessions.get(viewer_sid) {
                let _ = send_msg(
                    &session.tcp_tx,
                    &ServerMessage::StoppedWatchingScreenShare {
                        reason: "sharer_left".into(),
                    },
                )
                .await;
            }
        }

        // Broadcast ScreenShareStopped to channel
        if let Some(sharer_uid) = cleanup.stopped_sharer_user_id {
            let msg = ServerMessage::ScreenShareStopped {
                user_id: sharer_uid,
            };
            for &sid in &cleanup.channel_member_sessions {
                if let Some(session) = state.sessions.get(&sid) {
                    let _ = send_msg(&session.tcp_tx, &msg).await;
                }
            }
        }

        // Notify sharer of viewer count change
        if let Some((sharer_sid, new_count)) = cleanup.sharer_viewer_count_changed {
            if let Some(session) = state.sessions.get(&sharer_sid) {
                let _ = send_msg(
                    &session.tcp_tx,
                    &ServerMessage::ViewerCountChanged {
                        viewer_count: new_count,
                    },
                )
                .await;
            }
        }
    }

    // Leave channel and notify ALL users
    if let Some((left_channel_id, _remaining, remaining_count)) =
        state.leave_current_channel(user_id, session_id).await
    {
        let leave_msg = ServerMessage::UserLeft {
            user_id,
            channel_id: left_channel_id,
        };
        broadcast_to_all(state, &leave_msg, Some(user_id)).await;

        // Start auto-delete timer if channel is now empty and not General
        if remaining_count == 0 && left_channel_id != 0 {
            start_channel_delete_timer(state, left_channel_id).await;
        }
    }

    state.remove_session(session_id).await;
    info!(user_id, session_id, "session cleaned up");
}

/// Start an auto-delete timer for an empty channel.
async fn start_channel_delete_timer(state: &Arc<ServerState>, channel_id: ChannelId) {
    let state_for_task = state.clone();
    let timeout_secs = state.settings.empty_channel_timeout_secs;

    let handle = tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(timeout_secs)).await;

        match state_for_task.delete_channel(channel_id).await {
            Ok(()) => {
                info!(channel_id, "auto-deleted empty channel after timeout");
                let msg = ServerMessage::ChannelDeleted { channel_id };
                broadcast_to_all(&state_for_task, &msg, None).await;
            }
            Err(_) => {
                // Channel not empty or already deleted — no action needed
            }
        }
    });

    state.set_channel_delete_timer(channel_id, handle).await;
}

/// Broadcast a message to ALL connected users, optionally excluding one.
async fn broadcast_to_all(
    state: &ServerState,
    msg: &ServerMessage,
    exclude_user: Option<UserId>,
) {
    for entry in state.sessions.iter() {
        let session = entry.value();
        if Some(session.user_id) == exclude_user {
            continue;
        }
        let _ = send_msg(&session.tcp_tx, msg).await;
    }
}

/// Broadcast a message to all members of a channel, optionally excluding one user.
async fn broadcast_to_channel(
    state: &ServerState,
    channel_id: ChannelId,
    msg: &ServerMessage,
    exclude_user: Option<UserId>,
) {
    let channels = state.channels.read().await;
    if let Some(channel) = channels.get(&channel_id) {
        for &uid in &channel.members {
            if Some(uid) == exclude_user {
                continue;
            }
            if let Some(sid) = state.user_to_session.get(&uid) {
                if let Some(session) = state.sessions.get(&*sid) {
                    let _ = send_msg(&session.tcp_tx, msg).await;
                }
            }
        }
    }
}

/// Send a server message to a client via their TCP sender.
async fn send_msg(tx: &mpsc::Sender<Vec<u8>>, msg: &ServerMessage) -> Result<()> {
    let data = encode_server_msg(msg)?;
    tx.send(data).await.map_err(|_| anyhow::anyhow!("TCP send channel closed"))?;
    Ok(())
}
