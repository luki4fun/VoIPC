use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info, warn};

use voipc_protocol::codec::{
    decode_client_msg, encode_server_msg, try_decode_frame, APP_VERSION, MAX_RELAY_CIPHERTEXT,
    PROTOCOL_VERSION,
};
use voipc_protocol::messages::{ClientMessage, ServerMessage};
use voipc_protocol::types::*;

use crate::state::ServerState;

/// One-time pre-keys stored per user. A bundle request consumes one and
/// uploads replenish them at 0.2/s, so 100 is a deep supply — and it is also
/// the point past which a client is no longer replenishing but filling our
/// memory with blobs we never read. Applied at every door: the upload handler
/// and the pre-key bundle a client offers at authentication, which is the
/// same list arriving under another name.
const MAX_PREKEYS: usize = 100;

/// Longest public key we will store on a client's behalf, and longest
/// signature.
///
/// Every one of these is opaque to us — a Curve25519 public key is 33 bytes on
/// the wire and an Ed25519 signature 64 — but they arrive as byte strings with
/// no length in the type, and we hold them until the session ends and hand them
/// to whoever asks for a bundle. Unbounded, one client can park 100 pre-keys of
/// 60 KiB each in our memory, and a bundle built from them comes back out as a
/// message too long to frame: `encode_server_msg` refuses it, the requester is
/// told nothing, and they can never open a session with that person again.
const MAX_KEY_BYTES: usize = 64;
const MAX_SIGNATURE_BYTES: usize = 128;

/// Whether a pre-key bundle is the shape a client is supposed to send.
fn bundle_is_sane(bundle: &PreKeyBundleData) -> bool {
    bundle.identity_key.len() <= MAX_KEY_BYTES
        && bundle.signed_prekey.len() <= MAX_KEY_BYTES
        && bundle.signed_prekey_signature.len() <= MAX_SIGNATURE_BYTES
        && bundle
            .prekeys
            .iter()
            .all(|k| k.public_key.len() <= MAX_KEY_BYTES)
}

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
                    // The global per-session budget is spent on the frame, not
                    // on what the frame turns out to contain. Charging only
                    // the ones that decode leaves a peer free to send framed
                    // garbage at line rate: it costs us a read and a postcard
                    // pass every time and costs them nothing.
                    let allowed = state
                        .sessions
                        .get_mut(&session_id)
                        .map(|mut s| s.global_rate.try_consume())
                        .unwrap_or(false);
                    if !allowed {
                        // debug, not warn: by construction this fires once per
                        // dropped message, so a peer over its budget would be
                        // writing our log for us at whatever rate it chose.
                        debug!(user_id, "global rate limit exceeded, dropping message");
                        continue;
                    }
                    match decode_client_msg(&payload) {
                        Ok(msg) => {
                            if let Err(e) =
                                handle_message(msg, &state, user_id, session_id, &tx).await
                            {
                                error!(user_id, "error handling message: {}", e);
                            }
                        }
                        Err(e) => {
                            // Same reason: a malformed frame is now paid for,
                            // but a line of log per frame is not a price we
                            // let the sender set.
                            debug!(user_id, "failed to decode client message: {}", e);
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

                    if prekey_bundle.as_ref().is_some_and(|b| !bundle_is_sane(b)) {
                        let err_msg = ServerMessage::AuthError {
                            reason: "pre-key bundle is malformed".into(),
                        };
                        let data = encode_server_msg(&err_msg)?;
                        stream.write_all(&data).await?;
                        anyhow::bail!("oversized pre-key bundle");
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
                                bundle.prekeys.iter().take(MAX_PREKEYS).cloned().collect(),
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

                    let mut session = crate::state::UserSession::new(
                        user_id,
                        session_id,
                        username.clone(),
                        placeholder_tx,
                        media_tx,
                        peer_ip,
                        state.max_users,
                        state.channel_budget,
                    );
                    // What this particular client brought with it; the budgets
                    // and the rest are the same for everybody (state.rs).
                    session.identity_key = identity_key;
                    session.prekeys = prekeys;
                    session.signed_prekey_id = signed_prekey_id;
                    session.signed_prekey = signed_prekey;
                    session.signed_prekey_signature = signed_prekey_signature;
                    session.registration_id = registration_id;
                    session.device_id = device_id;

                    // An id that is already taken means the counter wrapped
                    // and came back round to a session that is still live.
                    // Inserting over it would drop that connection's writer on
                    // the floor and leave its loop serving somebody else's
                    // state, so refuse the new connection instead: the one
                    // arriving can be told to try again, the one already here
                    // cannot be told anything.
                    if state.sessions.contains_key(&session_id) {
                        state.username_to_session.remove(&username.to_lowercase());
                        let err_msg = ServerMessage::AuthError {
                            reason: "session id already in use, please reconnect".into(),
                        };
                        let data = encode_server_msg(&err_msg)?;
                        stream.write_all(&data).await?;
                        anyhow::bail!("session id {} already in use", session_id);
                    }
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

/// Whether a blob a client asked us to pass on is small enough to come back
/// out as a frame somebody can read.
///
/// The inbound limit is not the outbound one: everything relayed is re-wrapped
/// with the sender's id, the name they go by and a timestamp, so a blob that
/// only just fit through `try_decode_frame` on the way in makes a message no
/// recipient can decode on the way out — and their clients drop the connection
/// over it, which is how one message takes a whole channel down. See
/// `MAX_RELAY_CIPHERTEXT`.
///
/// The sender is told rather than dropped silently: an honest client that hit
/// this has a message it believes was sent.
async fn relayable(ciphertext: &[u8], tx: &mpsc::Sender<Vec<u8>>) -> bool {
    if ciphertext.len() <= MAX_RELAY_CIPHERTEXT {
        return true;
    }
    let _ = send_msg(
        tx,
        &ServerMessage::ChannelError {
            reason: "message too large".into(),
        },
    )
    .await;
    false
}

/// Spend one of this session's `state_change_rate` tokens, or say no.
///
/// Every message that has to ask is a flag the server keeps about the sender
/// and then announces to other people: nothing to store, a fan-out to tell.
/// A refusal is silent — no honest client comes near the budget, and answering
/// would be one more message going out.
fn may_change_state(state: &Arc<ServerState>, session_id: SessionId, user_id: UserId) -> bool {
    let allowed = state
        .sessions
        .get_mut(&session_id)
        .map(|mut s| s.state_change_rate.try_consume())
        .unwrap_or(false);
    if !allowed {
        debug!(user_id, "state change rate limit exceeded, dropping");
    }
    allowed
}

/// Whether both users are members of the channel a relay names.
async fn both_in_channel(
    state: &Arc<ServerState>,
    channel_id: ChannelId,
    a: UserId,
    b: UserId,
) -> bool {
    let channels = state.channels.read().await;
    channels
        .get(&channel_id)
        .is_some_and(|ch| ch.members.contains(&a) && ch.members.contains(&b))
}

/// Whether a key distribution may be relayed: both ends in the channel it
/// names, and the sender still inside their budget **for that target**.
///
/// The membership check comes first and is what bounds the budget map — it can
/// only grow an entry for somebody this user really shares a channel with.
/// A refusal is silent: an honest client hands its key to each peer once per
/// channel and never comes near this, and a dishonest one is owed nothing.
async fn may_relay_key(
    state: &Arc<ServerState>,
    session_id: SessionId,
    from_user_id: UserId,
    channel_id: ChannelId,
    target_user_id: UserId,
) -> bool {
    if !both_in_channel(state, channel_id, from_user_id, target_user_id).await {
        // debug, not warn: clients hand their sender key to every peer they
        // establish a session with, wherever that peer is; this check is the
        // filter, not an anomaly.
        debug!(from_user_id, target_user_id, channel_id, "key relay rejected: not both members");
        return false;
    }
    let allowed = state
        .sessions
        .get_mut(&session_id)
        .map(|mut s| s.may_relay_key_to(target_user_id))
        .unwrap_or(false);
    if !allowed {
        debug!(from_user_id, target_user_id, "key relay rate limit exceeded, dropping");
    }
    allowed
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
        ClientMessage::LeaveChannel { channel_id } => {
            handle_leave_text_channel(state, user_id, session_id, channel_id, tx).await?;
        }
        ClientMessage::CreateChannel {
            name,
            password,
            proximity,
            anonymous,
            text,
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
                handle_create_channel(
                    state, user_id, session_id, name, password, proximity, anonymous, text, tx,
                )
                .await?;
            }
        }
        ClientMessage::Disconnect => {
            info!(user_id, "client sent disconnect");
            // Cleanup will happen when the connection loop ends
        }
        ClientMessage::SetMuted { muted } => {
            if !may_change_state(state, session_id, user_id) {
                return Ok(());
            }
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
        ClientMessage::SetHistorySharing { enabled } => {
            if !may_change_state(state, session_id, user_id) {
                return Ok(());
            }
            // Setting the flag to what it already holds is news to nobody,
            // and this particular announcement goes to every session on the
            // server — so a client re-sending its state on reconnect, or
            // toggling a switch back and forth, must not cost a fan-out each
            // time.
            let changed = state
                .sessions
                .get_mut(&session_id)
                .map(|mut s| {
                    let changed = s.shares_history != enabled;
                    s.shares_history = enabled;
                    changed
                })
                .unwrap_or(false);
            // To everyone, unlike mute and deafen, and including the sender.
            // Everyone, because a text channel's subscribers are standing in
            // voice channels of their own, so "this channel" is not a place
            // the news would reach them. The sender too, because their own row
            // in their own member list has to show what everyone else sees —
            // the mute flag not being echoed is exactly what made that one
            // disagree with itself.
            if changed {
                broadcast_to_all(
                    state,
                    &ServerMessage::UserHistorySharing { user_id, enabled },
                    None,
                )
                .await;
            }
        }
        ClientMessage::SetDeafened { deafened } => {
            if !may_change_state(state, session_id, user_id) {
                return Ok(());
            }
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
            if !may_change_state(state, session_id, user_id) {
                return Ok(());
            }
            handle_set_channel_password(state, user_id, session_id, channel_id, password, tx)
                .await?;
        }
        ClientMessage::SetChannelProximity {
            channel_id,
            proximity,
        } => {
            if !may_change_state(state, session_id, user_id) {
                return Ok(());
            }
            handle_set_channel_proximity(state, user_id, session_id, channel_id, proximity, tx)
                .await?;
        }
        ClientMessage::SetChannelOptions {
            channel_id,
            hidden,
            anonymous,
            screen_share,
            hide_members,
            routed,
            message_ttl_secs,
        } => {
            if !may_change_state(state, session_id, user_id) {
                return Ok(());
            }
            handle_set_channel_options(
                state,
                user_id,
                session_id,
                channel_id,
                hidden,
                anonymous,
                screen_share,
                hide_members,
                routed,
                message_ttl_secs,
                tx,
            )
            .await?;
        }
        ClientMessage::KickUser {
            channel_id,
            user_id: target_id,
        } => {
            handle_kick_user(state, user_id, session_id, channel_id, target_id, tx).await?;
        }
        ClientMessage::SetAudioFilter { allow } => {
            // Its own budget, not the one for flags the server announces: a
            // game drives this one, and dropping an update silently leaves the
            // relay culling by a filter the game has moved on from. See
            // `audio_filter_rate`.
            let allowed = state
                .sessions
                .get_mut(&session_id)
                .map(|mut s| s.audio_filter_rate.try_consume())
                .unwrap_or(false);
            if !allowed {
                debug!(user_id, "audio filter rate limit exceeded, dropping");
                return Ok(());
            }
            // Only honoured in a channel that says it is routed; everywhere
            // else the client is told nothing about it and we keep nothing
            // about them, which is the point of the flag being opt-in.
            let here = state
                .sessions
                .get(&session_id)
                .map(|s| s.channel_id)
                .unwrap_or(0);
            let routed = {
                let channels = state.channels.read().await;
                channels.get(&here).is_some_and(|ch| ch.info.routed)
            };
            if routed {
                // Bounded by the roster: a client cannot make us hold a set
                // larger than the server can ever have members.
                let allow = allow.map(|mut ids| {
                    // Truncate first. Sorting and deduplicating a list whose
                    // length the client chose is work done on ids we have
                    // already decided not to keep — and the list is a
                    // `Vec<u32>` that arrived over the wire, so its length is
                    // bounded only by the 64 KiB frame.
                    ids.truncate(state.max_users as usize);
                    ids.sort_unstable();
                    ids.dedup();
                    ids
                });
                state.routing.set_filter(session_id, allow);
            } else {
                state.routing.clear_session(session_id);
            }
        }
        ClientMessage::RequestChannelUsers { channel_id } => {
            let allowed = state.is_channel_public_or_member(channel_id, user_id).await
                || state.is_admin(session_id);
            let users = if allowed {
                state.users_in_channel_for(channel_id, session_id).await
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
            if relayable(&ciphertext, tx).await {
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
        }
        ClientMessage::StartScreenShare { source: _, resolution, codec } => {
            // Starting and stopping each tell a whole channel, so they cost
            // what the other "something about me changed" messages cost.
            if !may_change_state(state, session_id, user_id) {
                return Ok(());
            }
            let clamped_resolution = resolution.clamp(240, 4320);
            handle_start_screen_share(state, user_id, session_id, clamped_resolution, codec, tx)
                .await?;
        }
        ClientMessage::StopScreenShare => {
            if !may_change_state(state, session_id, user_id) {
                return Ok(());
            }
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
            // debug, like the other things a client can repeat at line rate:
            // a log line is the cheapest thing on a server to make somebody
            // else write.
            debug!(user_id, "received duplicate Authenticate message, ignoring");
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
            if relayable(&ciphertext, tx).await {
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
        }
        ClientMessage::SendEncryptedChannelMessage {
            channel_id,
            ciphertext,
        } => {
            if relayable(&ciphertext, tx).await {
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
                        state, user_id, session_id, channel_id, ciphertext, tx,
                    ).await?;
                }
            }
        }
        ClientMessage::DistributeSenderKey {
            channel_id,
            target_user_id,
            distribution_message,
            message_type,
        } => {
            if relayable(&distribution_message, tx).await
                && may_relay_key(state, session_id, user_id, channel_id, target_user_id).await
            {
                handle_distribute_sender_key(
                    state, user_id, channel_id, target_user_id, distribution_message, message_type,
                ).await?;
            }
        }
        ClientMessage::DistributeMediaKey {
            channel_id,
            target_user_id,
            encrypted_media_key,
            message_type,
        } => {
            if relayable(&encrypted_media_key, tx).await
                && may_relay_key(state, session_id, user_id, channel_id, target_user_id).await
            {
                handle_distribute_media_key(
                    state, user_id, channel_id, target_user_id, encrypted_media_key, message_type,
                ).await?;
            }
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
            if relayable(&ciphertext, tx).await {
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

    // Either kind of join announces itself to every session on the server —
    // a voice one twice, being a leave and a join — so both draw on the same
    // budget. See `join_rate`.
    let allowed = state
        .sessions
        .get_mut(&session_id)
        .map(|mut s| s.join_rate.try_consume())
        .unwrap_or(false);
    if !allowed {
        let _ = send_msg(
            tx,
            &ServerMessage::ChannelError {
                reason: "joining and leaving too fast, slow down".into(),
            },
        )
        .await;
        return Ok(());
    }

    // A text channel is a subscription, not a move: the user keeps the voice
    // channel they stand in, and every other text channel they are in. It
    // needs no separate validation pass either — there is no current channel to
    // protect, and `join_text_channel` checks the password, the capacity and
    // the per-user subscription cap itself, after the membership check that
    // makes a repeated join a no-op.
    if state.is_text_channel(channel_id).await {
        match state.join_text_channel(user_id, channel_id, password).await {
            Ok(joined) => {
                // Even a repeated join answers with the roster: a client that
                // lost track asks again rather than going without one.
                let users = state.users_in_channel_for(channel_id, session_id).await;
                let _ = send_msg(tx, &ServerMessage::UserList { channel_id, users }).await;

                if joined {
                    let user_info = user_info_for(state, user_id, session_id, channel_id);
                    broadcast_user_joined(state, user_info).await;
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
        return Ok(());
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
        broadcast_user_left(state, user_id, left_channel_id, Some(user_id)).await;

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
        let users = state.users_in_channel_for(0, session_id).await;
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
    let users = state.users_in_channel_for(channel_id, session_id).await;
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
    let user_info = user_info_for(state, user_id, session_id, channel_id);

    broadcast_user_joined(state, user_info).await;

    Ok(())
}

/// The joiner, as the join notification describes them. `channel_id` is the
/// channel they joined — the voice room they moved into, or the text channel
/// they subscribed to.
fn user_info_for(
    state: &Arc<ServerState>,
    user_id: UserId,
    session_id: SessionId,
    channel_id: ChannelId,
) -> UserInfo {
    // Everything off the one guard: `state.is_admin` would take the same shard
    // again while this one is still held, which is the re-entry the invite
    // handler documents working around.
    let session = state.sessions.get(&session_id);
    UserInfo {
        user_id,
        username: session.as_ref().map(|s| s.username.clone()).unwrap_or_default(),
        channel_id,
        is_muted: session.as_ref().map(|s| s.is_muted).unwrap_or(false),
        is_deafened: session.as_ref().map(|s| s.is_deafened).unwrap_or(false),
        is_screen_sharing: false,
        is_admin: session.as_ref().is_some_and(|s| s.is_admin),
        shares_history: session.as_ref().is_some_and(|s| s.shares_history),
    }
}

/// Unsubscribe from a text channel.
///
/// The `UserLeft` goes to everyone including the leaver: it is what tells
/// their own client the subscription is gone, and everyone else's that the
/// member list shrank.
async fn handle_leave_text_channel(
    state: &Arc<ServerState>,
    user_id: UserId,
    session_id: SessionId,
    channel_id: ChannelId,
    tx: &mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    // Same budget as the join, and for the same reason: leaving is also a
    // broadcast to every session plus a write of the channel map, and a
    // subscription can be dropped and retaken as fast as a client likes.
    let allowed = state
        .sessions
        .get_mut(&session_id)
        .map(|mut s| s.join_rate.try_consume())
        .unwrap_or(false);
    if !allowed {
        let _ = send_msg(
            tx,
            &ServerMessage::ChannelError {
                reason: "joining and leaving too fast, slow down".into(),
            },
        )
        .await;
        return Ok(());
    }
    match state.leave_text_channel(user_id, channel_id).await {
        Some(remaining) => {
            broadcast_user_left(state, user_id, channel_id, None).await;
            if remaining == 0 {
                start_channel_delete_timer(state, channel_id).await;
            }
        }
        None => {
            let _ = send_msg(
                tx,
                &ServerMessage::ChannelError {
                    reason: "not a text channel you are in".into(),
                },
            )
            .await;
        }
    }
    Ok(())
}

/// Announce a join to everyone but the joiner, each recipient getting the
/// name they may see. `user.username` carries the real name.
///
/// This goes to every session, not just the channel's, because it doubles as
/// the user-count update — so a recipient who is not in the channel gets no
/// name at all. Otherwise moving between an anonymous channel and an ordinary
/// one would hand outsiders both names for the same id, and the members left
/// behind would learn who the pseudonym had been.
async fn broadcast_user_joined(state: &Arc<ServerState>, user: UserInfo) {
    let (real, alias) = state.names_of_in(user.channel_id, user.user_id).await;
    let roster = roster_audience(state, user.channel_id).await;
    for entry in state.sessions.iter() {
        let session = entry.value();
        if session.user_id == user.user_id {
            continue;
        }
        // Two different questions. The name goes to the channel's own people
        // only, always has, and that is what keeps a move between an anonymous
        // channel and an ordinary one from handing outsiders both names for
        // one person. The *id* is the narrower rule below: a channel that
        // hides its members hides them here too.
        let username = if roster.knows_them(session.user_id) || session.is_admin {
            crate::state::pick_name(&real, &alias, session.is_admin)
        } else {
            // The client only renders this for its own channel anyway
            String::new()
        };
        let may_name = roster.may_name(session.user_id, user.user_id) || session.is_admin;
        let info = UserInfo {
            username,
            user_id: roster.tell(may_name, user.user_id),
            ..user.clone()
        };
        let _ = send_msg(&session.tcp_tx, &ServerMessage::UserJoined { user: info }).await;
    }
}

/// Tell every session that somebody left a channel, under the same rule as
/// the join above: an outsider gets the count and nothing else.
///
/// `exclude` is for the leaver themselves, where something better is already
/// on its way to them (a `UserList` for the room they moved into, or the end
/// of their connection). Leaving a *text* channel passes `None`: that
/// broadcast is what drops the subscription on their own side.
async fn broadcast_user_left(
    state: &Arc<ServerState>,
    user_id: UserId,
    channel_id: ChannelId,
    exclude: Option<UserId>,
) {
    let roster = roster_audience(state, channel_id).await;
    for entry in state.sessions.iter() {
        let session = entry.value();
        if Some(session.user_id) == exclude {
            continue;
        }
        let may_name = roster.may_name(session.user_id, user_id) || session.is_admin;
        let msg = ServerMessage::UserLeft {
            user_id: roster.tell(may_name, user_id),
            channel_id,
        };
        let _ = send_msg(&session.tcp_tx, &msg).await;
    }
}

/// Who may learn *who* is in a channel, as opposed to how many.
///
/// `is_channel_public_or_member` is that rule and the roster query has always
/// honoured it. The join and leave broadcasts did not: they go to every
/// session, because they double as the user-count update, and they carried the
/// user id even where the name was blanked. One `#general` everybody is in
/// maps every id to a name, so a client that kept the ids could rebuild
/// exactly the roster a `hide_members` or password channel withholds. An
/// outsider now gets the count and nothing else.
struct RosterAudience {
    members: std::collections::HashSet<UserId>,
    private: bool,
}

impl RosterAudience {
    /// Whether this recipient is one of the channel's own people, who may be
    /// told the name. Membership rather than `session.channel_id`: for a text
    /// channel those people are its subscribers, who are all standing in voice
    /// channels of their own.
    fn knows_them(&self, recipient: UserId) -> bool {
        self.members.contains(&recipient)
    }

    /// Whether this recipient may be told *which person* it is. Everyone
    /// learns of a join or leave, because the same message is the member
    /// count — but in a channel that keeps its roster to itself, an outsider
    /// learns only that the count moved. You always learn about yourself:
    /// leaving is a thing your own client has to act on.
    fn may_name(&self, recipient: UserId, subject: UserId) -> bool {
        recipient == subject || self.knows_them(recipient) || !self.private
    }

    /// The id to put on the wire: nobody, for a recipient who may not be told
    /// (user ids start at 1).
    fn tell(&self, may_name: bool, user_id: UserId) -> UserId {
        if may_name {
            user_id
        } else {
            0
        }
    }
}

async fn roster_audience(state: &ServerState, channel_id: ChannelId) -> RosterAudience {
    let channels = state.channels.read().await;
    match channels.get(&channel_id) {
        Some(channel) => RosterAudience {
            members: channel.members.clone(),
            private: channel.info.hide_members || channel.password.is_some(),
        },
        None => RosterAudience {
            members: Default::default(),
            private: false,
        },
    }
}

/// Handle a create channel request.
async fn handle_create_channel(
    state: &Arc<ServerState>,
    user_id: UserId,
    session_id: SessionId,
    name: String,
    password: Option<String>,
    proximity: ProximityMode,
    anonymous: bool,
    text: bool,
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

    match state
        .create_channel(name, password, proximity, anonymous, text, user_id)
        .await
    {
        Ok(info) => {
            let channel_id = info.channel_id;
            // Broadcast ChannelCreated to all users
            let msg = ServerMessage::ChannelCreated { channel: info };
            broadcast_to_all(state, &msg, None).await;

            // Before the auto-join, not after it: the join below can be
            // refused — the creator is out of join budget, the password they
            // set is wrong for the channel they just made — and a channel that
            // nobody ever joined has no leave to start its timer from. It would
            // then sit in the map with no members for as long as the server
            // ran, and enough of them fill `max_channels` for everybody. A join
            // that does go through aborts this timer (`join_channel`).
            start_channel_delete_timer(state, channel_id).await;

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
        // None: the password it already had. Re-sending the options a channel
        // has is something a client may do, and every one of those would
        // otherwise be a message to every session on the server.
        Ok(None) => {}
        Ok(Some(updated_info)) => {
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
        // None: the mode it was already in — see the password handler above.
        Ok(None) => {}
        Ok(Some(updated_info)) => {
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

/// Handle a change to the other channel options (creator or admin).
#[allow(clippy::too_many_arguments)]
async fn handle_set_channel_options(
    state: &Arc<ServerState>,
    user_id: UserId,
    session_id: SessionId,
    channel_id: ChannelId,
    hidden: Option<bool>,
    anonymous: Option<bool>,
    screen_share: Option<bool>,
    hide_members: Option<bool>,
    routed: Option<bool>,
    message_ttl_secs: Option<u32>,
    tx: &mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    let is_admin = state.is_admin(session_id);
    match state
        .set_channel_options(
            channel_id,
            user_id,
            hidden,
            anonymous,
            screen_share,
            hide_members,
            routed,
            message_ttl_secs,
            is_admin,
        )
        .await
    {
        Ok((updated_info, changed)) => {
            let sharing_off = !updated_info.screen_share;
            // Nothing moved means nothing to tell anybody, and this one goes
            // to every session on the server: a client re-sending the options
            // a channel already has must not cost a fan-out each time.
            if changed.any {
                let msg = ServerMessage::ChannelUpdated {
                    channel: updated_info,
                };
                broadcast_to_all(state, &msg, None).await;
            }

            // Switching sharing off stops the shares already running: leaving
            // them relaying would make the option a lie, and the sharer's UI
            // has no reason to keep a Stop button for a channel that forbids it.
            if sharing_off {
                let sharers: Vec<(UserId, SessionId)> = {
                    let channels = state.channels.read().await;
                    channels
                        .get(&channel_id)
                        .map(|ch| {
                            ch.screen_shares
                                .values()
                                .map(|s| (s.sharer_user_id, s.sharer_session_id))
                                .collect()
                        })
                        .unwrap_or_default()
                };
                for (sharer_uid, sharer_sid) in sharers {
                    cleanup_and_notify_screen_shares(state, sharer_uid, sharer_sid, channel_id)
                        .await;
                    // Tell the sharer's own client to stop capturing
                    if let Some(session) = state.sessions.get(&sharer_sid) {
                        let _ = send_msg(
                            &session.tcp_tx,
                            &ServerMessage::ScreenShareError {
                                reason: "screen sharing was switched off in this channel".into(),
                            },
                        )
                        .await;
                    }
                }
            }

            // Anonymity changed the names the members go by, and their client
            // stores hold the old ones: hand each member a fresh list. Only
            // when it really flipped — this builds one roster per member and
            // re-takes the channels lock for each of them, and being asked to
            // set `anonymous` to what it already is must not cost that.
            if changed.anonymity {
                resend_user_list(state, channel_id).await;
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

/// Send every member of a channel the member list as they may now see it.
async fn resend_user_list(state: &Arc<ServerState>, channel_id: ChannelId) {
    let members: Vec<SessionId> = {
        let channels = state.channels.read().await;
        let Some(channel) = channels.get(&channel_id) else {
            return;
        };
        channel
            .members
            .iter()
            .filter_map(|uid| state.user_to_session.get(uid).map(|s| *s))
            .collect()
    };
    for sid in members {
        let users = state.users_in_channel_for(channel_id, sid).await;
        if let Some(session) = state.sessions.get(&sid) {
            let _ = send_msg(
                &session.tcp_tx,
                &ServerMessage::UserList { channel_id, users },
            )
            .await;
        }
    }
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
    let is_text = state.is_text_channel(channel_id).await;
    match state
        .kick_user(channel_id, requester_id, target_id, by_admin)
        .await
    {
        Ok((target_session_id, remaining_count)) => {
            // Same teardown as leave/disconnect: otherwise a kicked viewer
            // keeps receiving the share's video and a kicked sharer leaves
            // its viewers stuck. A text channel carries neither.
            if !is_text {
                cleanup_and_notify_screen_shares(state, target_id, target_session_id, channel_id)
                    .await;
            }

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

            // Broadcast UserLeft to everyone, the leaver included: for a
            // text channel that broadcast is what drops the subscription on
            // their side, and they always learn about themselves.
            broadcast_user_left(state, target_id, channel_id, None).await;

            // Being kicked out of a text channel costs the subscription and
            // nothing else — the user stays where they stand.
            if !is_text {
                // Move the kicked user to General (channel 0)
                let _ = state.join_channel(target_id, target_session_id, 0, None).await;
                let general_users = state.users_in_channel_for(0, target_session_id).await;

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
                let user_info = user_info_for(state, target_id, target_session_id, 0);
                broadcast_user_joined(state, user_info).await;
            }

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
        Ok((channel_name, mut invited_by)) => {
            // Bound to a `let` first: in an `if let` the DashMap guard lives
            // to the end of the block, and `display_name` takes the channels
            // lock (and this shard again) while it is held.
            let target_sid = state.user_to_session.get(&target_user_id).map(|s| *s);
            if let Some(sid) = target_sid {
                invited_by = state.display_name(requester_id, sid).await;
            }
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
    // The name the target may see: a poke from an anonymous channel must not
    // carry the real one
    let target_session = state.user_to_session.get(&target_user_id).map(|s| *s);
    let from_username = match target_session {
        Some(sid) => state.display_name(from_user_id, sid).await,
        None => String::new(),
    };
    let _ = from_session_id;

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

    // A decline for a channel nobody invited us to is a message of the
    // sender's choosing aimed at a creator of their choosing; there is nothing
    // to decline and nobody to tell.
    if !state.remove_invite(channel_id, user_id).await {
        return Ok(());
    }

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
    // No hand-off in an anonymous channel: the names in an archive are inside
    // the ciphertext, where the server cannot substitute them
    if state.is_anonymous_channel(channel_id).await {
        return;
    }
    let Some(target_sid) = state.user_to_session.get(&target_user_id).map(|s| *s) else {
        return;
    };
    // Two answers from the target's own session, and both of them are theirs
    // to give. `shares_history` is the flag they set and the server has been
    // announcing all along — until now nothing on this side ever read it, so a
    // client could ask anybody and the client at the other end was the only
    // thing deciding whether to answer. `history_serve_rate` is the budget of
    // the one being asked rather than the one asking: `history_request_rate`
    // bounds a single requester, but every member of a channel may aim at the
    // same person at once, and each request costs them an encrypt and up to
    // ~48 KiB. A non-sharer spends no token — there is nothing to protect them
    // from beyond the question itself.
    let serve = state
        .sessions
        .get_mut(&target_sid)
        .map(|mut s| s.shares_history && s.history_serve_rate.try_consume())
        .unwrap_or(false);
    if !serve {
        return;
    }
    if let Some(session) = state.sessions.get(&target_sid) {
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
    // An archive carries the names its owner stored, inside the ciphertext
    // where the server cannot substitute them — so an anonymous channel gets
    // no history hand-off at all.
    if state.is_anonymous_channel(channel_id).await {
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
            let (real, alias) = state.names_of_in(channel_id, user_id).await;

            // Broadcast to all channel members (including sender for confirmation),
            // each under the name they may see
            for sid in &member_sessions {
                if let Some(session) = state.sessions.get(sid) {
                    let msg = ServerMessage::ScreenShareStarted {
                        user_id,
                        username: crate::state::pick_name(&real, &alias, session.is_admin),
                        resolution,
                    };
                    let _ = send_msg(&session.tcp_tx, &msg).await;
                }
            }
            // Also send to the sharer themselves, under their own name here
            let _ = send_msg(
                tx,
                &ServerMessage::ScreenShareStarted {
                    user_id,
                    username: crate::state::pick_name(&real, &alias, state.is_admin(session_id)),
                    resolution,
                },
            )
            .await;
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
            // Any of them will do — a one-time pre-key has no order — and
            // taking the last one is a move instead of shifting the other 99
            // down on every bundle request.
            vec![session.prekeys.pop().expect("checked non-empty just above")]
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
    if let Some(mut session) = state.sessions.get_mut(&session_id) {
        let remaining_capacity = MAX_PREKEYS.saturating_sub(session.prekeys.len());
        if remaining_capacity > 0 {
            session.prekeys.extend(
                prekeys
                    .into_iter()
                    // The same bound the bundle at authentication passes. A key
                    // longer than this is not one we could hand on in a
                    // frameable message, so storing it only buys the memory and
                    // a bundle request nobody can answer.
                    .filter(|k| k.public_key.len() <= MAX_KEY_BYTES)
                    .take(remaining_capacity),
            );
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
    let (real, alias) = state.names_of(from_user_id).await;

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let message = |username: String| ServerMessage::EncryptedDirectChatMessage {
        from_user_id,
        from_username: username,
        to_user_id: target_user_id,
        ciphertext: ciphertext.clone(),
        message_type,
        timestamp,
    };

    // Attempt delivery to target (silently fail if offline — prevents user enumeration)
    if let Some(target_sid) = state.user_to_session.get(&target_user_id) {
        if let Some(session) = state.sessions.get(&*target_sid) {
            let name = crate::state::pick_name(&real, &alias, session.is_admin);
            let _ = send_msg(&session.tcp_tx, &message(name)).await;
        }
    }

    // Always echo back to sender regardless of delivery success, under the
    // name the sender themselves goes by
    let own = crate::state::pick_name(&real, &alias, state.is_admin(from_session_id));
    let _ = send_msg(tx, &message(own)).await;

    Ok(())
}

/// Handle an encrypted channel message — relay opaquely to channel members.
async fn handle_encrypted_channel_message(
    state: &Arc<ServerState>,
    user_id: UserId,
    session_id: SessionId,
    channel_id: ChannelId,
    ciphertext: Vec<u8>,
    tx: &mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    if state.sessions.get(&session_id).is_none() {
        return Ok(());
    }

    if channel_id == 0 {
        let _ = send_msg(tx, &ServerMessage::ChannelError {
            reason: "Chat is not available in the lobby".into(),
        }).await;
        return Ok(());
    }

    // The sender names the channel now (they may be in several text channels
    // at once), so membership is what decides whether they may write there.
    if !state.is_member(channel_id, user_id).await {
        let _ = send_msg(tx, &ServerMessage::ChannelError {
            reason: "you are not in that channel".into(),
        }).await;
        return Ok(());
    }

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    // Encrypted channel messages go to channel members except the sender
    // (sender can't decrypt their own sender key ciphertext), each under the
    // name they may see
    let (real, alias) = state.names_of_in(channel_id, user_id).await;
    let members: Vec<SessionId> = {
        let channels = state.channels.read().await;
        match channels.get(&channel_id) {
            Some(channel) => channel
                .members
                .iter()
                .filter(|&&uid| uid != user_id)
                .filter_map(|uid| state.user_to_session.get(uid).map(|s| *s))
                .collect(),
            None => Vec::new(),
        }
    };
    for sid in members {
        if let Some(session) = state.sessions.get(&sid) {
            let msg = ServerMessage::EncryptedChannelChatMessage {
                channel_id,
                user_id,
                username: crate::state::pick_name(&real, &alias, session.is_admin),
                ciphertext: ciphertext.clone(),
                timestamp,
            };
            let _ = send_msg(&session.tcp_tx, &msg).await;
        }
    }

    Ok(())
}

/// Relay a sender key to the target user. Admission — both ends in the
/// channel, and the sender inside their budget for this target — is
/// `may_relay_key`, which the caller has already asked.
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

/// Relay a media key to the target user. Admission is `may_relay_key`, as for
/// the sender key above.
async fn handle_distribute_media_key(
    state: &Arc<ServerState>,
    from_user_id: UserId,
    channel_id: ChannelId,
    target_user_id: UserId,
    encrypted_media_key: Vec<u8>,
    message_type: u8,
) -> Result<()> {
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

    // Text subscriptions go first: they are not the channel the session names,
    // so nothing else would ever clear them.
    for (text_channel_id, remaining) in state.leave_all_text_channels(user_id).await {
        broadcast_user_left(state, user_id, text_channel_id, Some(user_id)).await;
        if remaining == 0 {
            start_channel_delete_timer(state, text_channel_id).await;
        }
    }

    // Leave channel and notify ALL users
    if let Some((left_channel_id, _remaining, remaining_count)) =
        state.leave_current_channel(user_id, session_id).await
    {
        broadcast_user_left(state, user_id, left_channel_id, Some(user_id)).await;

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
///
/// Serialized once rather than once per recipient: this is the widest fan-out
/// the server has — every join, leave and channel change goes through it — and
/// it runs while holding a shard of the session map.
async fn broadcast_to_all(
    state: &ServerState,
    msg: &ServerMessage,
    exclude_user: Option<UserId>,
) {
    let Ok(data) = encode_server_msg(msg) else {
        return;
    };
    for entry in state.sessions.iter() {
        let session = entry.value();
        if Some(session.user_id) == exclude_user {
            continue;
        }
        let _ = session.tcp_tx.try_send(data.clone());
    }
}

/// Broadcast a message to all members of a channel, optionally excluding one user.
async fn broadcast_to_channel(
    state: &ServerState,
    channel_id: ChannelId,
    msg: &ServerMessage,
    exclude_user: Option<UserId>,
) {
    // Collect the recipients under the channels read lock, send after
    // releasing it — the same shape, and for the same reason, as the voice
    // fan-out in `media.rs`. The lock is write-preferring, so a queued join or
    // leave stalls every reader behind it, and holding it across a loop that
    // serializes the message once per recipient puts that stall in the path of
    // every voice packet on the server.
    let member_txs: Vec<mpsc::Sender<Vec<u8>>> = {
        let channels = state.channels.read().await;
        let Some(channel) = channels.get(&channel_id) else {
            return;
        };
        channel
            .members
            .iter()
            .filter(|&&uid| Some(uid) != exclude_user)
            .filter_map(|uid| {
                let sid = *state.user_to_session.get(uid)?;
                Some(state.sessions.get(&sid)?.tcp_tx.clone())
            })
            .collect()
    };
    for tx in member_txs {
        let _ = send_msg(&tx, msg).await;
    }
}

/// Send a server message to a client via their TCP sender.
///
/// Never awaits: callers hold DashMap shard guards (broadcasts iterate
/// `sessions`), so a client that stops reading its socket must not be able
/// to park the whole server behind its full queue. A client that cannot
/// drain 256 control messages is dead anyway.
async fn send_msg(tx: &mpsc::Sender<Vec<u8>>, msg: &ServerMessage) -> Result<()> {
    let data = encode_server_msg(msg).inspect_err(|e| {
        // Every caller discards this Result, and for the ordinary reason —
        // a client that has stopped reading is not our problem. A message too
        // long to frame is a different thing: we built it, nobody asked for it
        // to be dropped, and the symptom at the other end is a channel list or
        // a key bundle that simply never arrives.
        warn!("refusing to send a message that cannot be framed: {e}");
    })?;
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

    /// A channel is created and then joined, and the join can be refused —
    /// the creator is out of join budget, or their password is wrong for the
    /// channel they have just made. Before 0.9.0 the timer that removes an
    /// empty channel was started only by a *leave*, so a channel nobody ever
    /// joined stayed in the map for the life of the server. Enough of them, at
    /// one channel per five seconds, and nobody on the server can create one
    /// again.
    #[tokio::test]
    async fn a_channel_whose_creator_never_joined_it_goes_away_on_its_own() {
        let state = Arc::new(ServerState::new(
            &ServerConfig::default(),
            ServerSettings {
                empty_channel_timeout_secs: 0,
                ..ServerSettings::default()
            },
            Vec::new(),
            "test-admin-token".into(),
        ));
        let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut alice = connect(&state, "alice", lo).await;

        // Spend the joins, so the auto-join that follows the creation cannot.
        {
            let mut session = state.sessions.get_mut(&1).unwrap();
            while session.join_rate.try_consume() {}
        }

        alice
            .send(&ClientMessage::CreateChannel {
                name: "Orphan".into(),
                password: None,
                proximity: ProximityMode::Off,
                anonymous: false,
                text: true,
            })
            .await;
        alice
            .expect("ChannelCreated", |m| matches!(m, ServerMessage::ChannelCreated { .. }))
            .await;

        // The timer is spawned with a zero timeout, so it only needs the
        // scheduler to come round to it.
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            if state.channel_list().await.len() == 1 {
                break;
            }
        }
        let names: Vec<String> = state
            .channel_list()
            .await
            .into_iter()
            .map(|c| c.name)
            .collect();
        assert_eq!(names, vec!["General".to_string()], "the orphan stayed behind");
    }

    /// The key material a client uploads is opaque to us and we hold it until
    /// they disconnect. Unbounded, one client parks a hundred 60 KiB blobs in
    /// our memory — and a bundle built from them is a message too long to
    /// frame, so whoever asked for it is told nothing at all and can never open
    /// a session with that person.
    #[tokio::test]
    async fn an_oversized_prekey_bundle_is_refused_at_the_door() {
        let state = admin_state();
        let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let (stream, server) = tokio::io::duplex(65536);
        let (media_tx, _media_rx) = mpsc::channel(8);
        let (sid_tx, _sid_rx) = oneshot::channel();
        let handler = tokio::spawn(handle_connection(
            server,
            "mallory".into(),
            lo,
            media_tx,
            sid_tx,
            state.clone(),
        ));
        let mut client = Client { stream, handler, buf: BytesMut::new() };
        client
            .send(&ClientMessage::Authenticate {
                username: "mallory".into(),
                protocol_version: PROTOCOL_VERSION,
                app_version: APP_VERSION.to_string(),
                identity_key: None,
                prekey_bundle: Some(PreKeyBundleData {
                    registration_id: 1,
                    device_id: 1,
                    identity_key: vec![0u8; 60_000],
                    signed_prekey_id: 1,
                    signed_prekey: vec![0u8; 33],
                    signed_prekey_signature: vec![0u8; 64],
                    prekeys: Vec::new(),
                }),
            })
            .await;
        client
            .expect("AuthError", |m| matches!(m, ServerMessage::AuthError { .. }))
            .await;
        assert_eq!(state.user_count(), 0, "the session was registered anyway");
    }

    /// ...and the same bound on the ones uploaded later, which arrive by
    /// another door and used to be counted but not measured.
    #[tokio::test]
    async fn an_oversized_uploaded_prekey_is_not_stored() {
        let state = admin_state();
        let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut alice = connect(&state, "alice", lo).await;
        alice
            .send(&ClientMessage::UploadPreKeys {
                prekeys: vec![
                    OneTimePreKey { id: 1, public_key: vec![0u8; 33] },
                    OneTimePreKey { id: 2, public_key: vec![0u8; 60_000] },
                ],
            })
            .await;
        // Answered by nothing, so measure it against a round trip that is.
        alice.send(&ClientMessage::Ping { timestamp: 7 }).await;
        alice.expect("Pong", |m| matches!(m, ServerMessage::Pong { .. })).await;

        let session = state.sessions.get(&1).unwrap();
        assert_eq!(session.prekeys.len(), 1, "the oversized key was stored");
        assert_eq!(session.prekeys[0].id, 1);
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
            .send(&ClientMessage::CreateChannel { name: "room".into(), password: None, proximity: ProximityMode::Off, anonymous: false, text: false })
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

    /// A text channel is a subscription: joining one does not move anybody out
    /// of the voice channel they stand in, both parties keep receiving its
    /// chat, and the channel a message names is what decides who gets it.
    #[tokio::test]
    async fn text_channel_chat_reaches_members_without_moving_them() {
        let state = admin_state();
        let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut alice = connect(&state, "alice", lo).await; // user 1
        let mut bob = connect(&state, "bob", lo).await; // user 2

        // A voice room for alice to stand in, and a text channel for both
        alice
            .send(&ClientMessage::CreateChannel { name: "room".into(), password: None, proximity: ProximityMode::Off, anonymous: false, text: false })
            .await;
        let ServerMessage::ChannelCreated { channel: voice } = alice
            .expect("ChannelCreated", |m| matches!(m, ServerMessage::ChannelCreated { .. }))
            .await
        else {
            unreachable!()
        };
        alice
            .expect("UserList for the voice room", |m| {
                matches!(m, ServerMessage::UserList { channel_id: c, .. } if *c == voice.channel_id)
            })
            .await;

        bob.send(&ClientMessage::CreateChannel { name: "lounge".into(), password: None, proximity: ProximityMode::Off, anonymous: false, text: true })
            .await;
        let ServerMessage::ChannelCreated { channel: text } = bob
            .expect("ChannelCreated", |m| {
                matches!(m, ServerMessage::ChannelCreated { channel } if channel.text)
            })
            .await
        else {
            unreachable!()
        };
        bob.expect("UserList for the text channel", |m| {
            matches!(m, ServerMessage::UserList { channel_id: c, .. } if *c == text.channel_id)
        })
        .await;
        // Creating a text channel did not move bob out of the lobby
        assert_eq!(state.sessions.get(&2).unwrap().channel_id, 0);

        alice
            .send(&ClientMessage::JoinChannel { channel_id: text.channel_id, password: None })
            .await;
        alice
            .expect("UserList for the text channel", |m| {
                matches!(m, ServerMessage::UserList { channel_id: c, .. } if *c == text.channel_id)
            })
            .await;
        // ...and joining it did not take alice out of the voice room
        assert_eq!(state.sessions.get(&1).unwrap().channel_id, voice.channel_id);
        assert!(state.is_member(text.channel_id, 1).await);

        // A message naming the text channel reaches its other member
        alice
            .send(&ClientMessage::SendEncryptedChannelMessage {
                channel_id: text.channel_id,
                ciphertext: vec![1, 2, 3],
            })
            .await;
        let got = bob
            .expect("EncryptedChannelChatMessage", |m| {
                matches!(m, ServerMessage::EncryptedChannelChatMessage { .. })
            })
            .await;
        assert!(matches!(
            got,
            ServerMessage::EncryptedChannelChatMessage { channel_id, user_id: 1, .. }
                if channel_id == text.channel_id
        ));

        // A message naming a channel the sender is not in is refused
        bob.send(&ClientMessage::SendEncryptedChannelMessage {
            channel_id: voice.channel_id,
            ciphertext: vec![4],
        })
        .await;
        let refused = bob
            .expect("ChannelError", |m| matches!(m, ServerMessage::ChannelError { .. }))
            .await;
        assert!(matches!(refused, ServerMessage::ChannelError { reason } if reason.contains("not in")));

        // Leaving is its own message, and everybody hears about it
        alice
            .send(&ClientMessage::LeaveChannel { channel_id: text.channel_id })
            .await;
        alice
            .expect("UserLeft for ourselves", |m| {
                matches!(m, ServerMessage::UserLeft { user_id: 1, channel_id: c } if *c == text.channel_id)
            })
            .await;
        assert!(!state.is_member(text.channel_id, 1).await);
        // Still standing where they were
        assert_eq!(state.sessions.get(&1).unwrap().channel_id, voice.channel_id);

        // Leaving a voice channel is still JoinChannel(0), never this
        alice
            .send(&ClientMessage::LeaveChannel { channel_id: voice.channel_id })
            .await;
        let refused = alice
            .expect("ChannelError", |m| matches!(m, ServerMessage::ChannelError { .. }))
            .await;
        assert!(matches!(refused, ServerMessage::ChannelError { reason } if reason.contains("text channel")));
        assert_eq!(state.sessions.get(&1).unwrap().channel_id, voice.channel_id);
    }

    /// Who answers a request for recent chat is the one thing about chat the
    /// server is told, and everybody is told it — including the person whose
    /// flag it is, whose own member list has to agree with everyone else's.
    #[tokio::test]
    async fn history_sharing_is_announced_to_everyone() {
        let state = admin_state();
        let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut alice = connect(&state, "alice", lo).await; // user 1
        let mut bob = connect(&state, "bob", lo).await; // user 2

        alice
            .send(&ClientMessage::SetHistorySharing { enabled: true })
            .await;
        alice
            .expect("our own UserHistorySharing", |m| {
                matches!(m, ServerMessage::UserHistorySharing { user_id: 1, enabled: true })
            })
            .await;
        bob.expect("UserHistorySharing", |m| {
            matches!(m, ServerMessage::UserHistorySharing { user_id: 1, enabled: true })
        })
        .await;
        assert!(state.sessions.get(&1).unwrap().shares_history);

        // ...and it rides in the roster, which is what a member list draws
        let roster = state.users_in_channel_for(0, 2).await;
        assert!(roster.iter().any(|u| u.user_id == 1 && u.shares_history));
        assert!(roster.iter().any(|u| u.user_id == 2 && !u.shares_history));

        alice
            .send(&ClientMessage::SetHistorySharing { enabled: false })
            .await;
        bob.expect("UserHistorySharing, off again", |m| {
            matches!(m, ServerMessage::UserHistorySharing { user_id: 1, enabled: false })
        })
        .await;
        assert!(!state.sessions.get(&1).unwrap().shares_history);
    }

    /// Creates a text channel owned by `owner` and subscribes `other` to it.
    /// Both ends are left drained of the join traffic.
    async fn text_channel_with_two(
        owner: &mut Client,
        other: &mut Client,
        name: &str,
    ) -> ChannelId {
        owner
            .send(&ClientMessage::CreateChannel {
                name: name.into(),
                password: None,
                proximity: ProximityMode::Off,
                anonymous: false,
                text: true,
            })
            .await;
        let ServerMessage::ChannelCreated { channel } = owner
            .expect("ChannelCreated", |m| {
                matches!(m, ServerMessage::ChannelCreated { channel } if channel.text)
            })
            .await
        else {
            unreachable!()
        };
        let channel_id = channel.channel_id;
        owner
            .expect("UserList", |m| {
                matches!(m, ServerMessage::UserList { channel_id: c, .. } if *c == channel_id)
            })
            .await;
        other
            .send(&ClientMessage::JoinChannel { channel_id, password: None })
            .await;
        other
            .expect("UserList", |m| {
                matches!(m, ServerMessage::UserList { channel_id: c, .. } if *c == channel_id)
            })
            .await;
        channel_id
    }

    /// The whole point of the size chain: a blob the relay could not re-wrap
    /// into a readable frame is refused at the sender, not delivered to
    /// everybody else as a length prefix their decoders reject and their
    /// clients hang up over.
    #[tokio::test]
    async fn an_oversized_message_is_refused_instead_of_dropping_the_channel() {
        let state = admin_state();
        let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut alice = connect(&state, "alice", lo).await; // user 1
        let mut bob = connect(&state, "bob", lo).await; // user 2
        let channel_id = text_channel_with_two(&mut alice, &mut bob, "lounge").await;

        alice
            .send(&ClientMessage::SendEncryptedChannelMessage {
                channel_id,
                ciphertext: vec![0u8; MAX_RELAY_CIPHERTEXT + 1],
            })
            .await;
        let refused = alice
            .expect("ChannelError", |m| matches!(m, ServerMessage::ChannelError { .. }))
            .await;
        assert!(matches!(refused, ServerMessage::ChannelError { reason } if reason.contains("too large")));

        // Bob is the one this protects: his connection is still there and
        // still carrying the channel's chat.
        alice
            .send(&ClientMessage::SendEncryptedChannelMessage {
                channel_id,
                ciphertext: vec![1, 2, 3],
            })
            .await;
        let got = bob
            .expect("EncryptedChannelChatMessage", |m| {
                matches!(m, ServerMessage::EncryptedChannelChatMessage { .. })
            })
            .await;
        assert!(matches!(
            got,
            ServerMessage::EncryptedChannelChatMessage { channel_id: c, user_id: 1, .. }
                if c == channel_id
        ));
    }

    /// `hide_members` and a password both mean "nobody outside learns who is
    /// in here", and the roster query has always honoured that. The join and
    /// leave broadcasts go to *every* session, because they double as the
    /// user-count update — and they used to carry the user id even where the
    /// name was blanked. With one `#general` everybody is in, every id has a
    /// name, so the ids alone rebuild the withheld roster.
    #[tokio::test]
    async fn a_join_to_a_hidden_member_channel_names_nobody_to_outsiders() {
        let state = admin_state();
        let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut alice = connect(&state, "alice", lo).await; // user 1
        let mut bob = connect(&state, "bob", lo).await; // user 2

        alice
            .send(&ClientMessage::CreateChannel {
                name: "back room".into(),
                password: Some("pw".into()),
                proximity: ProximityMode::Off,
                anonymous: false,
                text: false,
            })
            .await;
        let ServerMessage::ChannelCreated { channel } = alice
            .expect("ChannelCreated", |m| matches!(m, ServerMessage::ChannelCreated { .. }))
            .await
        else {
            unreachable!()
        };

        // Bob is not in it: he learns that the count went up and no more.
        let joined = bob
            .expect("UserJoined", |m| {
                matches!(m, ServerMessage::UserJoined { user } if user.channel_id == channel.channel_id)
            })
            .await;
        let ServerMessage::UserJoined { user } = joined else { unreachable!() };
        assert_eq!(user.user_id, 0, "an outsider was told who joined");
        assert_eq!(user.username, "");

        // And the same on the way out.
        alice
            .send(&ClientMessage::JoinChannel { channel_id: 0, password: None })
            .await;
        let left = bob
            .expect("UserLeft", |m| {
                matches!(m, ServerMessage::UserLeft { channel_id, .. } if *channel_id == channel.channel_id)
            })
            .await;
        assert!(matches!(left, ServerMessage::UserLeft { user_id: 0, .. }));

        // A member is told, because that is the roster they are allowed.
        bob.send(&ClientMessage::JoinChannel {
            channel_id: channel.channel_id,
            password: Some("pw".into()),
        })
        .await;
        bob.expect("UserList", |m| {
            matches!(m, ServerMessage::UserList { channel_id, .. } if *channel_id == channel.channel_id)
        })
        .await;
        alice
            .send(&ClientMessage::JoinChannel {
                channel_id: channel.channel_id,
                password: Some("pw".into()),
            })
            .await;
        let joined = bob
            .expect("UserJoined", |m| {
                matches!(m, ServerMessage::UserJoined { user } if user.channel_id == channel.channel_id)
            })
            .await;
        let ServerMessage::UserJoined { user } = joined else { unreachable!() };
        assert_eq!((user.user_id, user.username.as_str()), (1, "alice"));
    }

    /// The id rule above must not widen the *name* rule it sits next to: an
    /// ordinary channel's joins carry an id to everybody, and have never
    /// carried a name to anybody outside it. That is what stops a move between
    /// an anonymous channel and an ordinary one from handing an outsider both
    /// names for one person.
    #[tokio::test]
    async fn an_ordinary_channel_still_names_its_members_to_nobody_outside() {
        let state = admin_state();
        let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut alice = connect(&state, "alice", lo).await; // user 1
        let mut bob = connect(&state, "bob", lo).await; // user 2

        alice
            .send(&ClientMessage::CreateChannel {
                name: "lounge".into(),
                password: None,
                proximity: ProximityMode::Off,
                anonymous: false,
                text: false,
            })
            .await;
        let ServerMessage::ChannelCreated { channel } = alice
            .expect("ChannelCreated", |m| matches!(m, ServerMessage::ChannelCreated { .. }))
            .await
        else {
            unreachable!()
        };
        let joined = bob
            .expect("UserJoined", |m| {
                matches!(m, ServerMessage::UserJoined { user } if user.channel_id == channel.channel_id)
            })
            .await;
        let ServerMessage::UserJoined { user } = joined else { unreachable!() };
        assert_eq!(user.user_id, 1, "the count has to be attributable");
        assert_eq!(user.username, "", "an outsider was told the name");
    }

    /// A game drives the audio filter in a routed channel — `docs/SDK.md`
    /// documents up to 20 updates a second — while the budget it drew on
    /// allows two. The surplus was dropped without a word, so the relay went
    /// on culling by a filter the game had moved on from.
    #[tokio::test]
    async fn a_game_can_update_its_audio_filter_as_fast_as_the_sdk_allows() {
        let state = admin_state();
        let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut alice = connect(&state, "alice", lo).await; // user 1, session 1
        alice
            .send(&ClientMessage::CreateChannel {
                name: "ingame".into(),
                password: None,
                proximity: ProximityMode::Off,
                anonymous: false,
                text: false,
            })
            .await;
        let ServerMessage::ChannelCreated { channel } = alice
            .expect("ChannelCreated", |m| matches!(m, ServerMessage::ChannelCreated { .. }))
            .await
        else {
            unreachable!()
        };
        alice
            .send(&ClientMessage::SetChannelOptions {
                channel_id: channel.channel_id,
                hidden: None,
                anonymous: None,
                screen_share: None,
                hide_members: None,
                routed: Some(true),
                message_ttl_secs: None,
            })
            .await;
        alice
            .expect("ChannelUpdated", |m| {
                matches!(m, ServerMessage::ChannelUpdated { channel: c } if c.routed)
            })
            .await;

        // One update per player the game moved past, at the documented rate.
        // The last one is the one that has to be in force.
        for speaker in 1..=20u32 {
            alice
                .send(&ClientMessage::SetAudioFilter { allow: Some(vec![speaker]) })
                .await;
        }
        // Driven by a message that must come back, so the filters ahead of it
        // have all been handled rather than merely sent.
        alice.send(&ClientMessage::Ping { timestamp: 1 }).await;
        alice
            .expect("Pong", |m| matches!(m, ServerMessage::Pong { timestamp: 1 }))
            .await;

        let now = tokio::time::Instant::now();
        assert!(
            state.routing.may_hear(channel.channel_id, 1, 1, 20, now),
            "the last filter the game sent was dropped"
        );
        assert!(
            !state.routing.may_hear(channel.channel_id, 1, 1, 19, now),
            "an earlier filter is still in force"
        );
    }

    /// The budget for relaying keys belongs to the pair, not the sender: an
    /// honest client hands a key to every member of every channel it shares
    /// with them, which is a wide burst at many people and never a burst at
    /// one. A single per-session budget could only be set wide enough for the
    /// first or tight enough for the second — and set wide, a flood at one
    /// member fills the queue their real keys have to arrive through.
    #[tokio::test]
    async fn keys_to_many_members_pass_while_a_flood_at_one_is_capped() {
        // A small server on purpose: the per-target burst is sized from how
        // many channels can exist here, and on a 50-channel one it is wider
        // than the per-frame control budget — which would then be the thing
        // this test measured.
        let state = Arc::new(ServerState::new(
            &ServerConfig::default(),
            ServerSettings {
                max_channels: 4,
                ..ServerSettings::default()
            },
            Vec::new(),
            "test-admin-token".into(),
        ));
        let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut alice = connect(&state, "alice", lo).await; // user 1
        let mut bob = connect(&state, "bob", lo).await; // user 2
        let mut carol = connect(&state, "carol", lo).await; // user 3
        let channel_id = text_channel_with_two(&mut alice, &mut bob, "lounge").await;
        carol
            .send(&ClientMessage::JoinChannel { channel_id, password: None })
            .await;
        carol
            .expect("UserList", |m| {
                matches!(m, ServerMessage::UserList { channel_id: c, .. } if *c == channel_id)
            })
            .await;

        // Past one target's budget, aimed at Bob — and deliberately still
        // inside the per-frame control budget, so it is this limiter being
        // measured and not that one.
        let burst = state
            .sessions
            .get(&1)
            .map(|s| s.key_relay_burst as usize)
            .expect("alice has a session");
        let flood = burst + 5;
        for i in 0..flood {
            alice
                .send(&ClientMessage::DistributeSenderKey {
                    channel_id,
                    target_user_id: 2,
                    distribution_message: vec![i as u8],
                    message_type: 1,
                })
                .await;
        }
        // Carol's key is sent last and must still arrive: her budget is her
        // own, and the flood at Bob has not touched it.
        alice
            .send(&ClientMessage::DistributeSenderKey {
                channel_id,
                target_user_id: 3,
                distribution_message: vec![0xAA],
                message_type: 1,
            })
            .await;
        let got = carol
            .expect("SenderKeyReceived", |m| {
                matches!(m, ServerMessage::SenderKeyReceived { .. })
            })
            .await;
        assert!(matches!(
            got,
            ServerMessage::SenderKeyReceived { from_user_id: 1, distribution_message, .. }
                if distribution_message == vec![0xAA]
        ));

        // Bob got his burst and no more. Counted against a message that must
        // arrive after them rather than against a timeout.
        alice
            .send(&ClientMessage::SendEncryptedChannelMessage {
                channel_id,
                ciphertext: vec![7],
            })
            .await;
        let mut relayed = 0usize;
        loop {
            match bob.next().await {
                Some(ServerMessage::SenderKeyReceived { .. }) => relayed += 1,
                Some(ServerMessage::EncryptedChannelChatMessage { .. }) => break,
                Some(_) => continue,
                None => panic!("connection closed"),
            }
        }
        assert!(
            relayed < flood && relayed <= burst + 2,
            "{relayed} of {flood} keys relayed at one member"
        );
        assert!(relayed > 0, "an honest key to a member must still pass");
    }

    /// `shares_history` is a flag the server has always stored and announced
    /// and never read: a request could be aimed at anybody, and the client on
    /// the other end was the only thing deciding whether to answer.
    #[tokio::test]
    async fn a_history_request_stops_at_a_member_who_does_not_share() {
        let state = admin_state();
        let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut alice = connect(&state, "alice", lo).await; // user 1
        let mut bob = connect(&state, "bob", lo).await; // user 2
        let channel_id = text_channel_with_two(&mut alice, &mut bob, "lounge").await;

        // Bob shares nothing, so the question must not reach him at all.
        alice
            .send(&ClientMessage::RequestChannelHistory { channel_id, target_user_id: 2 })
            .await;
        // Driven by a message that must arrive rather than by a timeout: if
        // the request was forwarded it is already in Bob's queue ahead of it.
        alice
            .send(&ClientMessage::SendEncryptedChannelMessage {
                channel_id,
                ciphertext: vec![7],
            })
            .await;
        loop {
            match bob.next().await {
                Some(ServerMessage::ChannelHistoryRequested { .. }) => {
                    panic!("the request reached a member who does not share history")
                }
                Some(ServerMessage::EncryptedChannelChatMessage { .. }) => break,
                Some(_) => continue,
                None => panic!("connection closed"),
            }
        }

        // ...and it is the flag doing the work: switch it on and the same
        // request goes through.
        bob.send(&ClientMessage::SetHistorySharing { enabled: true })
            .await;
        bob.expect("our own UserHistorySharing", |m| {
            matches!(m, ServerMessage::UserHistorySharing { user_id: 2, enabled: true })
        })
        .await;
        alice
            .send(&ClientMessage::RequestChannelHistory { channel_id, target_user_id: 2 })
            .await;
        let asked = bob
            .expect("ChannelHistoryRequested", |m| {
                matches!(m, ServerMessage::ChannelHistoryRequested { .. })
            })
            .await;
        assert!(matches!(
            asked,
            ServerMessage::ChannelHistoryRequested { channel_id: c, from_user_id: 1 }
                if c == channel_id
        ));
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
