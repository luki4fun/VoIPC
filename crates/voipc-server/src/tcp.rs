use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info, warn};

use voipc_protocol::codec::{
    decode_client_msg, encode_server_msg, try_decode_frame, APP_VERSION, PROTOCOL_VERSION,
};
use voipc_protocol::messages::{ClientMessage, ServerMessage};
use voipc_protocol::types::*;

use crate::state::ServerState;

/// A TLS connection on the page port that offered no ALPN is a pre-0.5
/// native client speaking the old TCP control protocol. Answer with the one
/// message it understands so it shows a clear error and stops reconnecting
/// (its reconnect loop gives up on "version mismatch").
pub async fn reject_legacy<S>(mut stream: S)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Let it send its Authenticate first, so the reply is not lost to a
    // reset on its own write.
    let mut scratch = [0u8; 4096];
    let _ = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut scratch)).await;
    let msg = ServerMessage::AuthError {
        reason: "version mismatch: this server runs VoIPC 0.5+, which connects over QUIC (UDP) — \
                 please update your client"
            .into(),
    };
    if let Ok(data) = encode_server_msg(&msg) {
        let _ = stream.write_all(&data).await;
        let _ = stream.shutdown().await;
    }
}

/// Handle a single control connection carrying the native wire format.
///
/// `stream` is one end of an in-process duplex fed by the QUIC session
/// bridge (`web::run_session`). `peer_label` is only used for logging;
/// `peer_ip` is the client's address (bans); `media_tx` is where the relay
/// queues media for this client; `sid_tx` tells the bridge the session id
/// once authentication succeeded (dropped unresolved on failure).
pub async fn handle_connection<S>(
    mut stream: S,
    peer_label: String,
    peer_ip: IpAddr,
    media_tx: mpsc::Sender<Bytes>,
    sid_tx: oneshot::Sender<SessionId>,
    state: Arc<ServerState>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let peer_addr = peer_label;

    info!(peer = %peer_addr, "new connection");

    // --- Authentication phase (with timeout) ---
    let mut buf = BytesMut::with_capacity(4096);
    let auth_result = tokio::time::timeout(
        Duration::from_secs(5),
        authenticate(&mut stream, &mut buf, &state, &peer_addr, peer_ip, media_tx, sid_tx),
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
    let (read_half, mut write_half) = tokio::io::split(stream);

    // Writer task: receives serialized messages from a channel and writes to TCP
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(256);

    let mut writer_handle = tokio::spawn(async move {
        while let Some(data) = rx.recv().await {
            if let Err(e) = write_half.write_all(&data).await {
                error!("TCP write error: {}", e);
                break;
            }
        }
    });

    // Store the sender in the session; keep the admin close handle
    let close = match state.sessions.get_mut(&session_id) {
        Some(mut session) => {
            session.tcp_tx = tx.clone();
            session.close.clone()
        }
        None => {
            // Session vanished between authenticate() and here — nothing to serve
            writer_handle.abort();
            return;
        }
    };

    // Sent from here (not inside authenticate) so that a failed write
    // still flows through cleanup_session below instead of leaking the
    // registered session and username.
    let _ = send_msg(
        &tx,
        &ServerMessage::Authenticated {
            user_id,
            session_id,
        },
    )
    .await;

    // Send channel list
    let channel_list = state.channel_list().await;
    let _ = send_msg(&tx, &ServerMessage::ChannelList { channels: channel_list }).await;

    // Auto-join General (channel 0)
    if let Err(e) = handle_join_channel(&state, user_id, session_id, 0, None, &tx).await {
        error!("failed to auto-join General: {}", e);
    }

    // --- Message loop with keepalive ---
    let idle_timeout = Duration::from_secs(300); // 5 min idle disconnect
    let keepalive_interval = Duration::from_secs(60);
    let mut last_activity = Instant::now();
    let mut keepalive_timer = tokio::time::interval(keepalive_interval);
    keepalive_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Skip the immediate first tick
    keepalive_timer.tick().await;

    let mut read_half = read_half;
    'conn: loop {
        let got_data = tokio::select! {
            result = read_half.read_buf(&mut buf) => {
                match result {
                    Ok(0) => {
                        info!(user_id, "client disconnected (EOF)");
                        break;
                    }
                    Ok(_) => {
                        last_activity = Instant::now();
                        true
                    }
                    Err(e) => {
                        error!(user_id, "TCP read error: {}", e);
                        break;
                    }
                }
            }
            _ = keepalive_timer.tick() => {
                if last_activity.elapsed() >= idle_timeout {
                    info!(user_id, "client idle timeout, disconnecting");
                    break;
                }
                // Send keepalive ping to client
                let timestamp = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;
                let ping = ServerMessage::Ping { timestamp };
                let _ = send_msg(&tx, &ping).await;
                debug!(user_id, "sent keepalive ping");
                false
            }
            _ = close.notified() => {
                info!(user_id, "connection closed by admin");
                break;
            }
        };

        if !got_data {
            continue; // keepalive tick, no data to decode
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
                            // Global per-session rate limiter
                            let allowed = state
                                .sessions
                                .get_mut(&session_id)
                                .map(|mut s| s.global_rate.try_consume())
                                .unwrap_or(false);
                            if !allowed {
                                warn!(user_id, "global rate limit exceeded, dropping message");
                                continue;
                            }
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
                    // The bad length prefix is never consumed: keep reading
                    // and the buffer grows without bound. Drop the client.
                    error!(user_id, "frame decode error, disconnecting: {}", e);
                    break 'conn;
                }
            }
        }
    }

    // --- Cleanup ---
    cleanup_session(&state, user_id, session_id).await;
    // Let the writer flush what is queued (a Disconnected reason, for one):
    // cleanup_session dropped the session's tcp_tx clone, ours goes here, so
    // the writer sees the channel close once the queue is empty.
    drop(tx);
    if tokio::time::timeout(Duration::from_secs(2), &mut writer_handle)
        .await
        .is_err()
    {
        writer_handle.abort();
    }
}

/// Perform the authentication handshake.
async fn authenticate<S>(
    stream: &mut S,
    buf: &mut BytesMut,
    state: &ServerState,
    peer_addr: &str,
    peer_ip: IpAddr,
    media_tx: mpsc::Sender<Bytes>,
    sid_tx: oneshot::Sender<SessionId>,
) -> Result<(UserId, SessionId)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Read until we get a complete message
    loop {
        let n = stream.read_buf(buf).await?;
        if n == 0 {
            anyhow::bail!("client disconnected during authentication");
        }

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
                                "version mismatch: the server runs VoIPC {}, you run {} — \
                                 please install the matching version",
                                APP_VERSION, app_version
                            ),
                        };
                        let data = encode_server_msg(&err_msg)?;
                        stream.write_all(&data).await?;
                        anyhow::bail!("app version mismatch");
                    }

                    let username = username.trim().to_string();
                    if username.is_empty() || username.len() > 32 {
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

                    if state.user_count() >= state.max_users as usize {
                        let err_msg = ServerMessage::AuthError {
                            reason: "server is full".into(),
                        };
                        let data = encode_server_msg(&err_msg)?;
                        stream.write_all(&data).await?;
                        anyhow::bail!("server full");
                    }

                    let user_id = state.next_user_id();
                    // Deliberately the same value: the client keys per-user
                    // volume and speaking state by the session_id in voice
                    // packets, but its UI only knows user_ids.
                    let session_id = user_id;

                    // Atomic username reservation — prevents race between two
                    // simultaneous registrations with the same name
                    let username_lower = username.to_lowercase();
                    match state.username_to_session.entry(username_lower) {
                        dashmap::mapref::entry::Entry::Occupied(_) => {
                            let err_msg = ServerMessage::AuthError {
                                reason: "username already taken".into(),
                            };
                            let data = encode_server_msg(&err_msg)?;
                            stream.write_all(&data).await?;
                            anyhow::bail!("username taken");
                        }
                        dashmap::mapref::entry::Entry::Vacant(entry) => {
                            entry.insert(session_id);
                        }
                    }

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
                        media_tx,
                        peer_ip,
                        is_admin: false,
                        admin_login_failures: 0,
                        close: Default::default(),
                        history_request_rate: crate::state::RateLimiter::new(3.0, 0.5),
                        udp_voice_rate: crate::state::RateLimiter::new(55.0, 55.0),
                        // Position beacons: senders coalesce to 10 Hz, so 12/s
                        // with a matching burst is plenty and keeps them off
                        // the voice budget.
                        position_rate: crate::state::RateLimiter::new(12.0, 12.0),
                        // 1200 pkt/s ≈ 12 Mbps at 1280B packets: covers 1080p60
                        // video (~7.5 Mbps) + screen audio with headroom; burst
                        // 400 absorbs a full keyframe (up to 255 fragments).
                        udp_video_rate: crate::state::RateLimiter::new(400.0, 1200.0),
                        global_rate: crate::state::RateLimiter::new(50.0, 50.0),
                        password_attempt_rate: crate::state::RateLimiter::new(3.0, 1.0),
                        chat_rate: crate::state::RateLimiter::new(5.0, 5.0),
                        keyframe_relay_rate: crate::state::RateLimiter::new(2.0, 1.0),
                        loss_report_rate: crate::state::RateLimiter::new(2.0, 1.0),
                        create_channel_rate: crate::state::RateLimiter::new(1.0, 0.2),
                        prekey_rate: crate::state::RateLimiter::new(1.0, 0.2),
                        // Burst covers joining a full channel; refill limits draining
                        prekey_bundle_rate: crate::state::RateLimiter::new(60.0, 1.0),
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
                    // The bridge can start routing this session's media now
                    let _ = sid_tx.send(session_id);

                    // No network I/O after this point: every failure past the
                    // inserts must run cleanup_session (handle_connection does).
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
                    anyhow::bail!("expected Authenticate message, got unexpected message type");
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
        ClientMessage::CreateChannel {
            name,
            password,
            proximity,
        } => {
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
                handle_create_channel(state, user_id, session_id, name, password, proximity, tx)
                    .await?;
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
            handle_set_channel_password(state, user_id, session_id, channel_id, password, tx)
                .await?;
        }
        ClientMessage::SetChannelProximity {
            channel_id,
            proximity,
        } => {
            handle_set_channel_proximity(state, user_id, session_id, channel_id, proximity, tx)
                .await?;
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
            // Pokes play a sound and raise an OS notification — same budget as chat
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
                handle_send_poke(state, user_id, session_id, target_user_id, ciphertext, message_type, tx).await?;
            }
        }
        ClientMessage::StartScreenShare { source: _, resolution, codec } => {
            let clamped_resolution = resolution.clamp(240, 4320);
            handle_start_screen_share(state, user_id, session_id, clamped_resolution, codec, tx)
                .await?;
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
            // Forcing IDRs is expensive for the sharer — only viewers of that
            // share may ask, and the relay is capped per share (not per
            // viewer, see handle_request_keyframe). Dropped silently: the
            // client re-requests within a second anyway.
            let watching = state
                .sessions
                .get(&session_id)
                .map(|s| s.watching_screenshare == Some(sharer_user_id))
                .unwrap_or(false);
            if watching {
                handle_request_keyframe(state, sharer_user_id).await?;
            }
        }
        ClientMessage::VideoLossReport {
            sharer_user_id,
            frames_dropped,
            frames_received,
        } => {
            // Relayed to the sharer, which lowers its bitrate/fps. Only
            // viewers of that share may report, at most ~1/s each.
            let allowed = state
                .sessions
                .get_mut(&session_id)
                .map(|mut s| {
                    s.watching_screenshare == Some(sharer_user_id)
                        && s.loss_report_rate.try_consume()
                })
                .unwrap_or(false);
            if allowed {
                let sharer_tx = state
                    .user_to_session
                    .get(&sharer_user_id)
                    .map(|sid| *sid)
                    .and_then(|sid| state.sessions.get(&sid).map(|s| s.tcp_tx.clone()));
                if let Some(sharer_tx) = sharer_tx {
                    let _ = send_msg(
                        &sharer_tx,
                        &ServerMessage::VideoLossReported {
                            viewer_user_id: user_id,
                            frames_dropped,
                            frames_received,
                        },
                    )
                    .await;
                }
            }
        }
        ClientMessage::Authenticate { .. } => {
            warn!(user_id, "received duplicate Authenticate message, ignoring");
        }

        // ── E2E Encryption handlers ──────────────────────────────────────
        ClientMessage::RequestPreKeyBundle { target_user_id } => {
            // Each bundle consumes one of the target's one-time pre-keys
            // (100 stored, replenished at 0.2 uploads/s) — unthrottled, one
            // user could drain anyone's supply in seconds.
            let allowed = state
                .sessions
                .get_mut(&session_id)
                .map(|mut s| s.prekey_bundle_rate.try_consume())
                .unwrap_or(false);
            if allowed {
                handle_request_prekey_bundle(state, target_user_id, tx).await?;
            } else {
                let _ = send_msg(
                    tx,
                    &ServerMessage::PreKeyBundleUnavailable {
                        user_id: target_user_id,
                    },
                )
                .await;
            }
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
            message_type,
        } => {
            handle_distribute_media_key(
                state, user_id, channel_id, target_user_id, encrypted_media_key, message_type,
            ).await?;
        }

        // ── Moderation ─────────────────────────────────────────────────
        ClientMessage::AdminLogin { token } => {
            handle_admin_login(state, user_id, session_id, &token, tx).await;
        }
        ClientMessage::AdminKick { user_id: target_id, reason } => {
            if state.is_admin(session_id) {
                handle_admin_kick(state, user_id, target_id, reason, false, 0, tx).await;
            } else {
                admin_error(tx, "not an admin").await;
            }
        }
        ClientMessage::AdminBan { user_id: target_id, reason, duration_secs } => {
            if state.is_admin(session_id) {
                handle_admin_kick(state, user_id, target_id, reason, true, duration_secs, tx).await;
            } else {
                admin_error(tx, "not an admin").await;
            }
        }
        ClientMessage::AdminUnban { ip } => {
            if !state.is_admin(session_id) {
                admin_error(tx, "not an admin").await;
            } else if let Ok(ip) = ip.parse::<IpAddr>() {
                state.unban(ip);
                info!(user_id, %ip, "admin unban");
                let _ = send_msg(tx, &ServerMessage::AdminBans { bans: state.list_bans() }).await;
            } else {
                admin_error(tx, "invalid IP address").await;
            }
        }
        ClientMessage::AdminListBans => {
            if state.is_admin(session_id) {
                let _ = send_msg(tx, &ServerMessage::AdminBans { bans: state.list_bans() }).await;
            } else {
                admin_error(tx, "not an admin").await;
            }
        }

        // ── Channel history hand-off ───────────────────────────────────
        ClientMessage::RequestChannelHistory { channel_id, target_user_id } => {
            let allowed = state
                .sessions
                .get_mut(&session_id)
                .map(|mut s| s.history_request_rate.try_consume())
                .unwrap_or(false);
            if allowed {
                handle_request_channel_history(state, user_id, channel_id, target_user_id).await;
            }
        }
        ClientMessage::SendChannelHistory { channel_id, target_user_id, ciphertext, message_type } => {
            let allowed = state
                .sessions
                .get_mut(&session_id)
                .map(|mut s| s.chat_rate.try_consume())
                .unwrap_or(false);
            if allowed {
                handle_send_channel_history(
                    state, user_id, session_id, channel_id, target_user_id, ciphertext, message_type,
                )
                .await;
            }
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
    // Rate-limit password attempts to prevent brute force
    if password.is_some() {
        let allowed = state
            .sessions
            .get_mut(&session_id)
            .map(|mut s| s.password_attempt_rate.try_consume())
            .unwrap_or(false);
        if !allowed {
            let _ = send_msg(
                tx,
                &ServerMessage::ChannelError {
                    reason: "too many password attempts, slow down".into(),
                },
            )
            .await;
            return Ok(());
        }
    }

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
        cleanup_and_notify_screen_shares(state, user_id, session_id, old_channel_id).await;
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

    // Media keys are generated by clients and exchanged over pairwise Signal
    // sessions (DistributeMediaKey) — the server never sees them.

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
        is_admin: state.is_admin(session_id),
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
    proximity: ProximityMode,
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

    match state.create_channel(name, password, proximity, user_id).await {
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
    session_id: SessionId,
    channel_id: ChannelId,
    password: Option<String>,
    tx: &mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    let is_admin = state.is_admin(session_id);
    match state
        .set_channel_password(channel_id, user_id, password, is_admin)
        .await
    {
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

/// Handle a proximity-mode change from the channel creator or an admin.
async fn handle_set_channel_proximity(
    state: &Arc<ServerState>,
    user_id: UserId,
    session_id: SessionId,
    channel_id: ChannelId,
    proximity: ProximityMode,
    tx: &mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    let is_admin = state.is_admin(session_id);
    match state
        .set_channel_proximity(channel_id, user_id, proximity, is_admin)
        .await
    {
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
    requester_session_id: SessionId,
    channel_id: ChannelId,
    target_id: UserId,
    tx: &mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    let by_admin = state.is_admin(requester_session_id);
    match state
        .kick_user(channel_id, requester_id, target_id, by_admin)
        .await
    {
        Ok((target_session_id, remaining_count)) => {
            // Same teardown as leave/disconnect: otherwise a kicked viewer
            // keeps receiving the share's video and a kicked sharer leaves
            // its viewers stuck.
            cleanup_and_notify_screen_shares(state, target_id, target_session_id, channel_id)
                .await;

            // Notify the kicked user
            if let Some(session) = state.sessions.get(&target_session_id) {
                let _ = send_msg(
                    &session.tcp_tx,
                    &ServerMessage::Kicked {
                        channel_id,
                        reason: if by_admin {
                            "You were kicked from the channel by an admin".into()
                        } else {
                            "You were kicked by the channel creator".into()
                        },
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
                is_admin: state.is_admin(target_session_id),
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
    _tx: &mpsc::Sender<Vec<u8>>,
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
            // Silently drop pokes to offline users — prevents user enumeration
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

// ── Moderation handlers ────────────────────────────────────────────────

async fn admin_error(tx: &mpsc::Sender<Vec<u8>>, reason: &str) {
    let _ = send_msg(
        tx,
        &ServerMessage::AdminError {
            reason: reason.into(),
        },
    )
    .await;
}

/// Constant-time token check; the third failure closes the connection.
async fn handle_admin_login(
    state: &Arc<ServerState>,
    user_id: UserId,
    session_id: SessionId,
    token: &str,
    tx: &mpsc::Sender<Vec<u8>>,
) {
    use subtle::ConstantTimeEq;
    let ok: bool = token
        .as_bytes()
        .ct_eq(state.admin_token.as_bytes())
        .into();
    if ok {
        if let Some(mut session) = state.sessions.get_mut(&session_id) {
            session.is_admin = true;
            session.admin_login_failures = 0;
        }
        info!(user_id, "admin login");
        broadcast_to_all(
            state,
            &ServerMessage::AdminStatus {
                user_id,
                is_admin: true,
            },
            None,
        )
        .await;
        return;
    }
    let failures = state
        .sessions
        .get_mut(&session_id)
        .map(|mut s| {
            s.admin_login_failures = s.admin_login_failures.saturating_add(1);
            s.admin_login_failures
        })
        .unwrap_or(0);
    warn!(user_id, failures, "admin login failed");
    admin_error(tx, "wrong admin token").await;
    if failures >= 3 {
        force_disconnect(state, session_id, "too many failed admin logins").await;
    }
}

/// Send `Disconnected` to a session and wake its connection loop, which
/// exits and runs the normal cleanup.
async fn force_disconnect(state: &Arc<ServerState>, session_id: SessionId, reason: &str) {
    let close = {
        let Some(session) = state.sessions.get(&session_id) else {
            return;
        };
        let _ = send_msg(
            &session.tcp_tx,
            &ServerMessage::Disconnected {
                reason: reason.to_string(),
            },
        )
        .await;
        session.close.clone()
    };
    close.notify_one();
}

/// Admin kick, optionally with an IP ban. A ban closes every session from
/// that IP, not just the target's.
async fn handle_admin_kick(
    state: &Arc<ServerState>,
    admin_user_id: UserId,
    target_id: UserId,
    reason: String,
    ban: bool,
    duration_secs: u32,
    tx: &mpsc::Sender<Vec<u8>>,
) {
    if target_id == admin_user_id {
        admin_error(tx, "you cannot kick yourself").await;
        return;
    }
    let Some(target_sid) = state.user_to_session.get(&target_id).map(|s| *s) else {
        admin_error(tx, "user not found").await;
        return;
    };
    let reason: String = reason.trim().chars().take(200).collect();
    let reason = if reason.is_empty() {
        "no reason given".to_string()
    } else {
        reason
    };

    if !ban {
        info!(admin = admin_user_id, target = target_id, "admin kick");
        force_disconnect(
            state,
            target_sid,
            &format!("You were kicked from this server: {reason}"),
        )
        .await;
        return;
    }

    let Some(ip) = state.sessions.get(&target_sid).map(|s| s.peer_ip) else {
        admin_error(tx, "user not found").await;
        return;
    };
    let duration = (duration_secs > 0).then(|| Duration::from_secs(u64::from(duration_secs)));
    state.ban(ip, duration);
    info!(admin = admin_user_id, target = target_id, %ip, duration_secs, "admin ban");
    let text = format!("You were banned from this server: {reason}");
    let sids: Vec<SessionId> = state
        .sessions
        .iter()
        .filter(|e| e.value().peer_ip == ip)
        .map(|e| *e.key())
        .collect();
    for sid in sids {
        force_disconnect(state, sid, &text).await;
    }
    let _ = send_msg(
        tx,
        &ServerMessage::AdminBans {
            bans: state.list_bans(),
        },
    )
    .await;
}

// ── Channel history hand-off (relay only, payload opaque) ──────────────

async fn both_in_channel(
    state: &Arc<ServerState>,
    channel_id: ChannelId,
    a: UserId,
    b: UserId,
) -> bool {
    let channels = state.channels.read().await;
    channels
        .get(&channel_id)
        .map_or(false, |ch| ch.members.contains(&a) && ch.members.contains(&b))
}

async fn handle_request_channel_history(
    state: &Arc<ServerState>,
    from_user_id: UserId,
    channel_id: ChannelId,
    target_user_id: UserId,
) {
    if from_user_id == target_user_id
        || !both_in_channel(state, channel_id, from_user_id, target_user_id).await
    {
        return;
    }
    if let Some(target_sid) = state.user_to_session.get(&target_user_id) {
        if let Some(session) = state.sessions.get(&*target_sid) {
            let _ = send_msg(
                &session.tcp_tx,
                &ServerMessage::ChannelHistoryRequested {
                    channel_id,
                    from_user_id,
                },
            )
            .await;
        }
    }
}

async fn handle_send_channel_history(
    state: &Arc<ServerState>,
    from_user_id: UserId,
    from_session_id: SessionId,
    channel_id: ChannelId,
    target_user_id: UserId,
    ciphertext: Vec<u8>,
    message_type: u8,
) {
    if !both_in_channel(state, channel_id, from_user_id, target_user_id).await {
        return;
    }
    let from_username = state
        .sessions
        .get(&from_session_id)
        .map(|s| s.username.clone())
        .unwrap_or_default();
    if let Some(target_sid) = state.user_to_session.get(&target_user_id) {
        if let Some(session) = state.sessions.get(&*target_sid) {
            let _ = send_msg(
                &session.tcp_tx,
                &ServerMessage::ChannelHistoryReceived {
                    channel_id,
                    from_user_id,
                    from_username,
                    ciphertext,
                    message_type,
                },
            )
            .await;
        }
    }
}

// ── Screen share handlers ──────────────────────────────────────────────

/// Handle a screen share start request.
async fn handle_start_screen_share(
    state: &Arc<ServerState>,
    user_id: UserId,
    session_id: SessionId,
    resolution: u16,
    codec: VideoCodec,
    tx: &mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    let channel_id = state
        .sessions
        .get(&session_id)
        .map(|s| s.channel_id)
        .unwrap_or(0);

    match state
        .start_screen_share(user_id, session_id, channel_id, resolution, codec)
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
        Ok((sharer_sid, _old_count, new_count, prev_unwatch, codec)) => {
            // Confirm to viewer, with the codec its decoder needs
            let _ = send_msg(
                tx,
                &ServerMessage::WatchingScreenShare { sharer_user_id, codec },
            )
            .await;

            // Notify the sharer of the new viewer count and get the newcomer a
            // keyframe: it would otherwise wait up to 4 s for the periodic one.
            // Capped per share like viewer requests (a burst of joiners is one
            // IDR per second, not one each). The guard is dropped before awaiting.
            let sharer = state.sessions.get_mut(&sharer_sid).map(|mut session| {
                let want_keyframe = new_count > 0 && session.keyframe_relay_rate.try_consume();
                (session.tcp_tx.clone(), want_keyframe)
            });
            if let Some((sharer_tx, want_keyframe)) = sharer {
                let _ = send_msg(
                    &sharer_tx,
                    &ServerMessage::ViewerCountChanged {
                        viewer_count: new_count,
                    },
                )
                .await;
                if want_keyframe {
                    let _ = send_msg(&sharer_tx, &ServerMessage::KeyframeRequested).await;
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

/// Handle a keyframe request — relay to the sharer, at most ~1/s per share
/// however many viewers ask (each relayed request forces an IDR).
async fn handle_request_keyframe(
    state: &Arc<ServerState>,
    sharer_user_id: UserId,
) -> Result<()> {
    let Some(sharer_sid) = state.user_to_session.get(&sharer_user_id).map(|s| *s) else {
        return Ok(());
    };
    let sharer_tx = match state.sessions.get_mut(&sharer_sid) {
        Some(mut session) => {
            if !session.keyframe_relay_rate.try_consume() {
                return Ok(());
            }
            session.tcp_tx.clone()
        }
        None => return Ok(()),
    };
    let _ = send_msg(&sharer_tx, &ServerMessage::KeyframeRequested).await;
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

    // Attempt delivery to target (silently fail if offline — prevents user enumeration)
    if let Some(target_sid) = state.user_to_session.get(&target_user_id) {
        if let Some(session) = state.sessions.get(&*target_sid) {
            let _ = send_msg(&session.tcp_tx, &msg).await;
        }
    }

    // Always echo back to sender regardless of delivery success
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
/// Verifies both sender and target are members of the specified channel.
async fn handle_distribute_sender_key(
    state: &Arc<ServerState>,
    from_user_id: UserId,
    channel_id: ChannelId,
    target_user_id: UserId,
    distribution_message: Vec<u8>,
    message_type: u8,
) -> Result<()> {
    // Verify both users are in the channel before relaying
    {
        let channels = state.channels.read().await;
        if let Some(channel) = channels.get(&channel_id) {
            if !channel.members.contains(&from_user_id)
                || !channel.members.contains(&target_user_id)
            {
                // debug, not warn: clients hand their sender key to every
                // peer they establish a session with, wherever that peer
                // is; this check is the filter, not an anomaly.
                debug!(
                    from_user_id,
                    target_user_id,
                    channel_id,
                    "sender key distribution rejected: membership check failed"
                );
                return Ok(());
            }
        } else {
            return Ok(());
        }
    }

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
/// Verifies both sender and target are members of the specified channel.
async fn handle_distribute_media_key(
    state: &Arc<ServerState>,
    from_user_id: UserId,
    channel_id: ChannelId,
    target_user_id: UserId,
    encrypted_media_key: Vec<u8>,
    message_type: u8,
) -> Result<()> {
    // Verify both users are in the channel before relaying
    {
        let channels = state.channels.read().await;
        if let Some(channel) = channels.get(&channel_id) {
            if !channel.members.contains(&from_user_id)
                || !channel.members.contains(&target_user_id)
            {
                // debug for the same reason as the sender key above
                debug!(
                    from_user_id,
                    target_user_id,
                    channel_id,
                    "media key distribution rejected: membership check failed"
                );
                return Ok(());
            }
        } else {
            return Ok(());
        }
    }

    if let Some(target_sid) = state.user_to_session.get(&target_user_id) {
        if let Some(session) = state.sessions.get(&*target_sid) {
            let _ = send_msg(
                &session.tcp_tx,
                &ServerMessage::MediaKeyReceived {
                    channel_id,
                    from_user_id,
                    encrypted_media_key,
                    message_type,
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
        cleanup_and_notify_screen_shares(state, user_id, session_id, channel_id).await;
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

/// Tear down a user's screen-share state in `channel_id` (their own share
/// and/or the share they were watching) and notify everyone affected.
/// Used by every path that removes a user from a channel: leave, kick,
/// disconnect.
async fn cleanup_and_notify_screen_shares(
    state: &Arc<ServerState>,
    user_id: UserId,
    session_id: SessionId,
    channel_id: ChannelId,
) {
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

    // Broadcast ScreenShareStopped to the channel
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

    // Notify sharer of viewer count change (if the user was watching someone)
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

/// Start an auto-delete timer for an empty channel.
/// Persistent channels (from channels.json) are never auto-deleted.
async fn start_channel_delete_timer(state: &Arc<ServerState>, channel_id: ChannelId) {
    // Skip persistent channels — they must never be auto-deleted
    {
        let channels = state.channels.read().await;
        if let Some(ch) = channels.get(&channel_id) {
            if ch.persistent {
                return;
            }
        }
    }

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
///
/// Never awaits: callers hold DashMap shard guards (broadcasts iterate
/// `sessions`), so a client that stops reading its socket must not be able
/// to park the whole server behind its full queue. A client that cannot
/// drain 256 control messages is dead anyway.
async fn send_msg(tx: &mpsc::Sender<Vec<u8>>, msg: &ServerMessage) -> Result<()> {
    let data = encode_server_msg(msg)?;
    tx.try_send(data).map_err(|e| match e {
        mpsc::error::TrySendError::Full(_) => {
            anyhow::anyhow!("TCP send queue full (client not reading)")
        }
        mpsc::error::TrySendError::Closed(_) => anyhow::anyhow!("TCP send channel closed"),
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    use voipc_protocol::codec::{decode_server_msg, encode_client_msg};

    use crate::config::ServerConfig;
    use crate::settings::ServerSettings;

    /// Drives `handle_connection` over an in-memory duplex without QUIC —
    /// exactly how the session bridge feeds it.
    #[tokio::test]
    async fn authenticates_over_duplex() {
        let config = ServerConfig::default();
        let state = Arc::new(ServerState::new(
            &config,
            ServerSettings::default(),
            Vec::new(),
            "test-admin-token".into(),
        ));
        let (mut client, server) = tokio::io::duplex(65536);
        let (media_tx, _media_rx) = mpsc::channel(8);
        let (sid_tx, sid_rx) = oneshot::channel();
        let mut handler = tokio::spawn(handle_connection(
            server,
            "test".into(),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            media_tx,
            sid_tx,
            state.clone(),
        ));

        let auth = ClientMessage::Authenticate {
            username: "web".into(),
            protocol_version: PROTOCOL_VERSION,
            app_version: APP_VERSION.to_string(),
            identity_key: None,
            prekey_bundle: None,
        };
        client
            .write_all(&encode_client_msg(&auth).unwrap())
            .await
            .unwrap();

        let mut buf = BytesMut::new();
        let mut replies = Vec::new();
        let read_replies = async {
            while replies.len() < 3 {
                let n = client.read_buf(&mut buf).await.unwrap();
                assert!(n > 0, "server closed the connection");
                while let Some(payload) = try_decode_frame(&mut buf).unwrap() {
                    replies.push(decode_server_msg(&payload).unwrap());
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(5), read_replies)
            .await
            .expect("replies within 5 s");

        let ServerMessage::Authenticated { session_id, .. } = replies[0] else {
            panic!("expected Authenticated, got {:?}", replies[0]);
        };
        assert!(matches!(replies[1], ServerMessage::ChannelList { .. }));
        assert!(matches!(
            replies[2],
            ServerMessage::UserList { channel_id: 0, .. }
        ));
        assert_eq!(state.sessions.len(), 1);
        // The bridge learns the session id as soon as the session exists
        assert_eq!(sid_rx.await.unwrap(), session_id);

        // Dropping our end is what the bridge does on teardown: the handler
        // must see EOF and clean the session up.
        drop(client);
        tokio::time::timeout(Duration::from_secs(5), &mut handler)
            .await
            .expect("handler exits after EOF")
            .unwrap();
        assert!(state.sessions.is_empty());
    }

    // ── Moderation ─────────────────────────────────────────────────────

    struct Client {
        stream: tokio::io::DuplexStream,
        handler: tokio::task::JoinHandle<()>,
        buf: BytesMut,
    }

    impl Client {
        async fn send(&mut self, msg: &ClientMessage) {
            self.stream
                .write_all(&encode_client_msg(msg).unwrap())
                .await
                .unwrap();
        }

        /// Next server message, or None once the server closed the stream.
        async fn next(&mut self) -> Option<ServerMessage> {
            loop {
                if let Some(payload) = try_decode_frame(&mut self.buf).unwrap() {
                    return Some(decode_server_msg(&payload).unwrap());
                }
                let n = tokio::time::timeout(
                    Duration::from_secs(5),
                    self.stream.read_buf(&mut self.buf),
                )
                .await
                .expect("a server message within 5 s")
                .unwrap();
                if n == 0 {
                    return None;
                }
            }
        }

        /// Skips messages (broadcasts about other users) until `pred` matches.
        async fn expect(
            &mut self,
            what: &str,
            pred: impl Fn(&ServerMessage) -> bool,
        ) -> ServerMessage {
            loop {
                match self.next().await {
                    Some(msg) if pred(&msg) => return msg,
                    Some(_) => continue,
                    None => panic!("connection closed while waiting for {what}"),
                }
            }
        }

        async fn assert_closed(mut self) {
            assert!(self.next().await.is_none(), "server should close the stream");
            tokio::time::timeout(Duration::from_secs(5), &mut self.handler)
                .await
                .expect("handler exits")
                .unwrap();
        }
    }

    fn admin_state() -> Arc<ServerState> {
        Arc::new(ServerState::new(
            &ServerConfig::default(),
            ServerSettings::default(),
            Vec::new(),
            "test-admin-token".into(),
        ))
    }

    /// Authenticates `username` from `ip` over a duplex.
    async fn connect(state: &Arc<ServerState>, username: &str, ip: IpAddr) -> Client {
        let (stream, server) = tokio::io::duplex(65536);
        let (media_tx, _media_rx) = mpsc::channel(8);
        let (sid_tx, _sid_rx) = oneshot::channel();
        let handler = tokio::spawn(handle_connection(
            server,
            username.into(),
            ip,
            media_tx,
            sid_tx,
            state.clone(),
        ));
        let mut client = Client {
            stream,
            handler,
            buf: BytesMut::new(),
        };
        client
            .send(&ClientMessage::Authenticate {
                username: username.into(),
                protocol_version: PROTOCOL_VERSION,
                app_version: APP_VERSION.to_string(),
                identity_key: None,
                prekey_bundle: None,
            })
            .await;
        client
            .expect("Authenticated", |m| matches!(m, ServerMessage::Authenticated { .. }))
            .await;
        client
    }

    #[tokio::test]
    async fn admin_login_ban_and_unban() {
        let state = admin_state();
        let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let far = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        let mut alice = connect(&state, "alice", lo).await; // user 1
        let mut bob = connect(&state, "bob", far).await; // user 2

        // Not an admin: refused
        bob.send(&ClientMessage::AdminKick { user_id: 1, reason: String::new() })
            .await;
        bob.expect("AdminError", |m| matches!(m, ServerMessage::AdminError { .. }))
            .await;

        // Wrong token, then the right one; everyone learns about the login
        alice
            .send(&ClientMessage::AdminLogin { token: "nope".into() })
            .await;
        alice
            .expect("AdminError", |m| matches!(m, ServerMessage::AdminError { .. }))
            .await;
        alice
            .send(&ClientMessage::AdminLogin { token: "test-admin-token".into() })
            .await;
        let is_login = |m: &ServerMessage| {
            matches!(m, ServerMessage::AdminStatus { user_id: 1, is_admin: true })
        };
        alice.expect("AdminStatus", is_login).await;
        bob.expect("AdminStatus broadcast", is_login).await;
        assert!(state.is_admin(1));

        // Ban bob: he gets the reason, his stream closes, his IP is blocked,
        // alice gets the updated ban list
        alice
            .send(&ClientMessage::AdminBan {
                user_id: 2,
                reason: "spam".into(),
                duration_secs: 60,
            })
            .await;
        let gone = bob
            .expect("Disconnected", |m| matches!(m, ServerMessage::Disconnected { .. }))
            .await;
        assert!(matches!(gone, ServerMessage::Disconnected { reason } if reason.contains("spam")));
        bob.assert_closed().await;
        assert!(state.is_banned(far));
        assert!(!state.is_banned(lo));
        assert_eq!(state.sessions.len(), 1);
        let bans = alice
            .expect("AdminBans", |m| matches!(m, ServerMessage::AdminBans { .. }))
            .await;
        assert!(matches!(&bans, ServerMessage::AdminBans { bans } if bans.len() == 1 && bans[0].ip == "10.0.0.5"));

        // Unban
        alice
            .send(&ClientMessage::AdminUnban { ip: "10.0.0.5".into() })
            .await;
        let bans = alice
            .expect("AdminBans", |m| matches!(m, ServerMessage::AdminBans { .. }))
            .await;
        assert!(matches!(&bans, ServerMessage::AdminBans { bans } if bans.is_empty()));
        assert!(!state.is_banned(far));
    }

    #[tokio::test]
    async fn three_failed_admin_logins_disconnect() {
        let state = admin_state();
        let mut dave = connect(&state, "dave", IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
        for _ in 0..3 {
            dave.send(&ClientMessage::AdminLogin { token: "wrong".into() })
                .await;
            dave.expect("AdminError", |m| matches!(m, ServerMessage::AdminError { .. }))
                .await;
        }
        dave.expect("Disconnected", |m| matches!(m, ServerMessage::Disconnected { .. }))
            .await;
        dave.assert_closed().await;
        assert!(state.sessions.is_empty());
    }

    /// A viewer must be told which codec the share it just joined uses: it is
    /// the only thing that reaches a late joiner before the first frame, and
    /// building the wrong decoder means a black window.
    #[tokio::test]
    async fn watchers_learn_the_share_codec() {
        let state = admin_state();
        let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut alice = connect(&state, "alice", lo).await; // user 1
        let mut bob = connect(&state, "bob", lo).await; // user 2

        // Sharing needs a real channel; General never carries media.
        alice
            .send(&ClientMessage::CreateChannel { name: "room".into(), password: None, proximity: ProximityMode::Off })
            .await;
        let created = alice
            .expect("ChannelCreated", |m| matches!(m, ServerMessage::ChannelCreated { .. }))
            .await;
        let ServerMessage::ChannelCreated { channel } = created else { unreachable!() };
        let channel_id = channel.channel_id;
        bob.send(&ClientMessage::JoinChannel { channel_id, password: None })
            .await;
        bob.expect("UserList", |m| matches!(m, ServerMessage::UserList { channel_id: c, .. } if *c == channel_id))
            .await;

        // Alice shares in a codec that is not the default
        alice
            .send(&ClientMessage::StartScreenShare {
                source: "portal".into(),
                resolution: 720,
                codec: VideoCodec::Vp9,
            })
            .await;
        bob.expect("ScreenShareStarted", |m| {
            matches!(m, ServerMessage::ScreenShareStarted { user_id: 1, .. })
        })
        .await;

        bob.send(&ClientMessage::WatchScreenShare { sharer_user_id: 1 })
            .await;
        let watching = bob
            .expect("WatchingScreenShare", |m| {
                matches!(m, ServerMessage::WatchingScreenShare { .. })
            })
            .await;
        assert!(
            matches!(
                watching,
                ServerMessage::WatchingScreenShare { sharer_user_id: 1, codec: VideoCodec::Vp9 }
            ),
            "the viewer was told the wrong codec: {watching:?}"
        );
    }

    #[tokio::test]
    async fn bans_expire() {
        let state = admin_state();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
        state.ban(ip, Some(Duration::from_millis(50)));
        assert!(state.is_banned(ip));
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert!(!state.is_banned(ip));
        assert!(state.list_bans().is_empty());
        state.ban(ip, None);
        assert_eq!(state.list_bans()[0].expires_in_secs, None);
    }
}
