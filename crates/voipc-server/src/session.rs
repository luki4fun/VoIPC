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
use voipc_protocol::messages::{
    AuthStep, ClientMessage, ServerMessage, FIRST_STRUCTURED_REFUSAL, REFUSED_VERSION,
};
use voipc_protocol::types::*;

use crate::accounts::modlog;
use crate::accounts::Powers;
use crate::control::{control_queue, ControlTx};
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
/// A Kyber1024 public key: a type byte and 1568 bytes (protocol v12).
const MAX_KEM_KEY_BYTES: usize = 1569;

/// When a bundle request leaves this many one-time pre-keys, the owner is
/// asked for more (`PreKeysLow`). Once per crossing, so it cannot be used to
/// make a client spin.
const PREKEYS_LOW: usize = 10;
/// A post on the live path, at most: all the client will show of one, and all a kept copy
/// of it may be (`accounts/log.rs`). One goes to everyone online, whatever it weighs.
const MAX_TEXT_POST: usize = crate::accounts::log::MAX_ENTRY;
/// The longest direct message echoed to its sender.
const MAX_DM_ECHO: usize = 1024;
/// What channels may fill one list's frame, less what goes around them.
const CHANNELS_FRAME_BYTES: usize = 60 * 1024;

/// Shared with the desktop importer (`voipc_protocol::names`).
pub(crate) use voipc_protocol::names::bad_name_char;

/// Whether a pre-key bundle is the shape a client is supposed to send.
fn bundle_is_sane(bundle: &PreKeyBundleData) -> bool {
    bundle.identity_key.len() <= MAX_KEY_BYTES
        && bundle.signed_prekey.len() <= MAX_KEY_BYTES
        && bundle.signed_prekey_signature.len() <= MAX_SIGNATURE_BYTES
        && bundle.kyber_prekey.len() <= MAX_KEM_KEY_BYTES
        && bundle.kyber_prekey_signature.len() <= MAX_SIGNATURE_BYTES
        && bundle
            .prekeys
            .iter()
            .all(|k| k.public_key.len() <= MAX_KEY_BYTES)
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
    binding: Option<[u8; voipc_crypto::bind::BIND_LEN]>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let peer_addr = peer_label;

    debug!(peer = %peer_addr, "new connection");

    // --- Authentication phase (each step with its own timeout) ---
    let mut buf = BytesMut::with_capacity(4096);
    let auth_result = authenticate(
        &mut stream,
        &mut buf,
        &state,
        &peer_addr,
        peer_ip,
        media_tx,
        sid_tx,
        binding,
    )
    .await;
    let Admitted {
        user_id,
        session_id,
        account,
    } = match auth_result {
        Ok(admitted) => admitted,
        Err(e) => {
            // A stranger can repeat this as fast as it can dial: debug only
            debug!(peer = %peer_addr, "authentication failed: {}", e);
            return;
        }
    };

    info!(user_id, session_id, "user authenticated");
    // From here the session is listed: whatever ends this task, a panic
    // included, takes it out again (a ghost would keep its name, its seat and
    // its roster entry until a restart)
    let mut cleanup = CleanupGuard {
        state: Some(state.clone()),
        user_id,
        session_id,
    };

    // --- Split into reader/writer ---
    let (read_half, mut write_half) = tokio::io::split(stream);

    // Session vanished between authenticate() and here — nothing to serve
    let Some(close) = state.sessions.get(&session_id).map(|s| s.close.clone()) else {
        return;
    };

    // Writer task: receives serialized messages from a channel and writes them to the stream
    let (tx, mut rx) = control_queue(close.clone());

    let mut writer_handle = tokio::spawn(async move {
        while let Some(data) = rx.recv().await {
            if let Err(e) = write_half.write_all(&data).await {
                error!("control write error: {}", e);
                break;
            }
        }
    });

    // Store the sender in the session
    match state.sessions.get_mut(&session_id) {
        Some(mut session) => session.control_tx = tx.clone(),
        None => {
            writer_handle.abort();
            return;
        }
    }

    // Sent from here (not inside authenticate) so that a failed write
    // still flows through cleanup_session below instead of leaking the
    // registered session and username.
    let _ = send_msg(
        &tx,
        &ServerMessage::Authenticated {
            user_id,
            session_id,
            accounts: state.accounts.as_ref().map(|r| r.info()),
            account,
            files: state.files.as_ref().map(|f| f.limits()),
            emotes: state.emotes.as_ref().map(|e| e.access(session_id)),
        },
    );

    // Send channel list
    let channel_list = state.channel_list_for(session_id).await;
    send_channel_list(&tx, channel_list);
    crate::layout::send(&state, session_id).await;
    if let Some(emotes) = &state.emotes {
        let _ = send_msg(&tx, &emotes.list());
    }
    crate::layout::send_styles(&state, &tx).await;
    crate::accounts::profile::send_server_profile(&state, &tx).await;
    crate::accounts::mention_power_at_connect(&state, session_id, user_id, &tx).await;
    crate::accounts::chat_mods_at_connect(&state, &tx).await;
    crate::accounts::modlog::send_marks(&state, &tx).await;
    crate::restrict::at_connect(&state, session_id, user_id, &tx);

    // Auto-join General (channel 0)
    if let Err(e) = handle_join_channel(&state, user_id, session_id, 0, None, &tx).await {
        error!("failed to auto-join General: {}", e);
    }

    // An account that holds the admin role is admin from its first message
    // on. The client learns that only from AdminStatus, as after a token
    // login; the others already read it in the roster.
    if state.is_admin(session_id) {
        let _ = send_msg(
            &tx,
            &ServerMessage::AdminStatus {
                user_id,
                is_admin: true,
            },
        );
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
                        error!(user_id, "control read error: {}", e);
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
                let _ = send_msg(&tx, &ping);
                debug!(user_id, "sent keepalive ping");
                false
            }
            _ = close.notified() => {
                info!(user_id, "connection closed by the relay");
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
                    let allowed = state.spend(session_id, |s| &mut s.global_rate);
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
    cleanup.state = None;
    cleanup_session(&state, user_id, session_id).await;
    // Let the writer flush what is queued (a Disconnected reason, for one):
    // cleanup_session dropped the session's control_tx clone, ours goes here, so
    // the writer sees the channel close once the queue is empty.
    drop(tx);
    if tokio::time::timeout(Duration::from_secs(2), &mut writer_handle)
        .await
        .is_err()
    {
        writer_handle.abort();
    }
}

/// Runs `cleanup_session` if the connection task ends without doing it
/// itself: on a panic, or when it is cancelled from outside (a relay shutting
/// down, a handler aborted after its connection ended), since the normal path
/// disarms it first.
struct CleanupGuard {
    state: Option<Arc<ServerState>>,
    user_id: UserId,
    session_id: SessionId,
}

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        if let Some(state) = self.state.take() {
            let (user_id, session_id) = (self.user_id, self.session_id);
            // Only a panic is an error: a shutdown cancels every connection's task, and
            // said one ERROR per client
            if std::thread::panicking() {
                error!(
                    user_id,
                    session_id, "connection task ended without cleaning up; cleaning up now"
                );
            } else {
                debug!(
                    user_id,
                    session_id, "connection task cancelled; cleaning up"
                );
            }
            tokio::spawn(async move { cleanup_session(&state, user_id, session_id).await });
        }
    }
}

/// What a finished handshake hands the connection loop.
struct Admitted {
    user_id: UserId,
    session_id: SessionId,
    account: Option<AccountInfo>,
}

/// The ASCII name `name` would pass for: each character outside ASCII
/// replaced by its look-alike (UTS #39 confusables), or `None` when `name` is
/// ASCII already or holds a character with no ASCII look-alike (`ü` stays
/// `ü`, so "Jürgen" passes for nobody's account).
pub(crate) fn ascii_look_alike(name: &str) -> Option<String> {
    if name.is_ascii() {
        return None;
    }
    let mut out = String::with_capacity(name.len());
    for c in name.chars() {
        if c.is_ascii() {
            out.push(c);
            continue;
        }
        let like: String = unicode_security::skeleton(c.encode_utf8(&mut [0; 4])).collect();
        if !like.is_ascii() {
            return None;
        }
        out.push_str(&like);
    }
    Some(out)
}

/// The protocol version a client's first frame names, read the way every
/// version since v2 lays it out: for a client older than this server, whose
/// `Authenticate` no longer decodes, so it can still be told to update.
fn legacy_protocol_version(payload: &[u8]) -> Option<u32> {
    #[derive(serde::Deserialize)]
    #[allow(dead_code)]
    enum First {
        Authenticate {
            username: String,
            protocol_version: u32,
        },
    }
    postcard::take_from_bytes::<First>(payload).ok().map(
        |(
            First::Authenticate {
                protocol_version, ..
            },
            _,
        )| protocol_version,
    )
}

/// Why no frame came (`read_frame`).
pub(crate) enum NoFrame {
    Closed,
    TimedOut,
    Malformed,
}

/// The next whole frame on a connection not split into reader and writer yet
/// (the sign-in), within `wait`.
pub(crate) async fn read_frame<S: AsyncRead + Unpin>(
    stream: &mut S,
    buf: &mut BytesMut,
    wait: Duration,
) -> std::result::Result<Vec<u8>, NoFrame> {
    let read = async {
        loop {
            match try_decode_frame(buf) {
                Ok(Some(payload)) => return Ok(payload),
                Ok(None) => {}
                Err(_) => return Err(NoFrame::Malformed),
            }
            match stream.read_buf(buf).await {
                Ok(0) | Err(_) => return Err(NoFrame::Closed),
                Ok(_) => {}
            }
        }
    };
    tokio::time::timeout(wait, read)
        .await
        .map_err(|_| NoFrame::TimedOut)?
}

/// One message on a connection not split yet (the sign-in).
pub(crate) async fn write_msg<S: AsyncWrite + Unpin>(
    stream: &mut S,
    msg: &ServerMessage,
) -> Result<()> {
    stream.write_all(&encode_server_msg(msg)?).await?;
    Ok(())
}

async fn refuse<S: AsyncWrite + Unpin>(stream: &mut S, reason: &str) -> Result<()> {
    write_msg(
        stream,
        &ServerMessage::AuthError {
            reason: reason.to_string(),
        },
    )
    .await
}

/// A client of another protocol, told which side has to update. Clients only
/// ever stop reconnecting on the words "version mismatch", so both forms carry
/// them; one before protocol 12 cannot decode `Refused`.
async fn refuse_version<S: AsyncWrite + Unpin>(stream: &mut S, client_protocol: u32) -> Result<()> {
    let text = if client_protocol > PROTOCOL_VERSION {
        format!("version mismatch: this server runs VoIPC {APP_VERSION} (protocol {PROTOCOL_VERSION}), older than your app — the server needs an update")
    } else {
        format!("version mismatch: this server runs VoIPC {APP_VERSION} (protocol {PROTOCOL_VERSION}) — please update your app")
    };
    if client_protocol < FIRST_STRUCTURED_REFUSAL {
        return refuse(stream, &text).await;
    }
    let refused = ServerMessage::Refused {
        code: REFUSED_VERSION,
        server_protocol: PROTOCOL_VERSION,
        server_version: APP_VERSION.into(),
        text,
    };
    write_msg(stream, &refused).await
}

/// Perform the authentication handshake: one `Authenticate` for a guest, and
/// for an account the steps in `accounts::sign_in` after it.
#[allow(clippy::too_many_arguments)]
async fn authenticate<S>(
    stream: &mut S,
    buf: &mut BytesMut,
    state: &Arc<ServerState>,
    peer_addr: &str,
    peer_ip: IpAddr,
    media_tx: mpsc::Sender<Bytes>,
    sid_tx: oneshot::Sender<SessionId>,
    binding: Option<[u8; voipc_crypto::bind::BIND_LEN]>,
) -> Result<Admitted>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // The first frame within 5 s; an account's later steps keep their own
    // clocks (a person typing a code gets two minutes).
    let payload = match read_frame(stream, buf, Duration::from_secs(5)).await {
        Ok(payload) => payload,
        Err(NoFrame::TimedOut) => anyhow::bail!("authentication timed out"),
        Err(NoFrame::Malformed) => anyhow::bail!("malformed frame during authentication"),
        Err(NoFrame::Closed) => anyhow::bail!("client disconnected during authentication"),
    };

    let msg = match decode_client_msg(&payload) {
        Ok(msg) => msg,
        Err(e) => {
            if let Some(v) = legacy_protocol_version(&payload).filter(|v| *v != PROTOCOL_VERSION) {
                refuse_version(stream, v).await?;
                anyhow::bail!("protocol version mismatch");
            }
            return Err(e.into());
        }
    };
    let ClientMessage::Authenticate {
        username,
        protocol_version,
        app_version,
        identity_key,
        prekey_bundle,
        account,
    } = msg
    else {
        anyhow::bail!("expected Authenticate message, got unexpected message type");
    };

    // A relay admits only its own protocol (1.0); any app version that speaks
    // it is in, and since 1.6 a newer app comes back speaking this one
    // (voipc_protocol::compat). `app_version` still names the client to l4f.
    if protocol_version != PROTOCOL_VERSION {
        refuse_version(stream, protocol_version).await?;
        anyhow::bail!("protocol version mismatch");
    }

    // Before an account's sign-in, which costs a hash and database work.
    if state.user_count() >= state.max_users as usize {
        refuse(stream, "server is full").await?;
        anyhow::bail!("server full");
    }

    let relay = state.accounts.clone();
    let signed_in = match (&relay, account) {
        (None, Some(_)) => {
            refuse(stream, "this server has no accounts").await?;
            anyhow::bail!("account sign-in on a server without accounts");
        }
        (Some(relay), Some(start)) => {
            // Permits are taken inside, around the relay's own work only
            match crate::accounts::sign_in(
                state,
                relay,
                stream,
                buf,
                &username,
                start,
                peer_ip,
                &app_version,
                binding,
            )
            .await
            {
                Ok(s) => Some(s),
                Err(reason) => {
                    refuse(stream, &reason).await?;
                    anyhow::bail!("account sign-in refused: {reason}");
                }
            }
        }
        (Some(relay), None) if relay.required => {
            write_msg(
                stream,
                &ServerMessage::AuthStep(AuthStep::AccountRequired {
                    registration: relay.info().registration,
                }),
            )
            .await?;
            anyhow::bail!("guest on a server that requires accounts");
        }
        _ => None,
    };

    // An account's name is the account's (l4f checked it); a guest's is
    // checked here.
    let (username, identity_key, prekey_bundle) = match &signed_in {
        Some(s) => (
            s.user.username.clone(),
            Some(s.identity_key.clone()),
            Some(s.prekey_bundle.clone()),
        ),
        None => (username.trim().to_string(), identity_key, prekey_bundle),
    };
    // A name may carry a "#1234" tag (the client adds one) so that two people
    // can go by the same name; only the name counts against the limit.
    // Uniqueness is on the whole. Without accounts the tag is optional, so
    // tools and tests can log in bare; with them a guest needs one, and the
    // name part must not be an account's.
    let tagged = username
        .rsplit_once('#')
        .filter(|(_, tag)| tag.len() == 4 && tag.bytes().all(|b| b.is_ascii_digit()));
    let name = tagged.map_or(username.as_str(), |(name, _)| name);
    if name.trim().is_empty() || name.len() > 32 {
        refuse(stream, "username must be 1-32 characters").await?;
        anyhow::bail!("invalid username");
    }

    if username.chars().any(bad_name_char) {
        refuse(stream, "username contains invalid characters").await?;
        anyhow::bail!("invalid username characters");
    }

    if let (Some(relay), None) = (&relay, &signed_in) {
        if tagged.is_none() {
            refuse(stream, "a guest's name needs a #tag on this server").await?;
            anyhow::bail!("untagged guest name");
        }
        // Account names are ASCII (`normalize_username`), so a guest's in
        // another script can only pass for one: a Cyrillic `а` for `a`. The
        // name its look-alikes spell is checked like the name itself (S-014).
        let look = ascii_look_alike(name);
        if [Some(name), look.as_deref()]
            .into_iter()
            .flatten()
            .any(crate::accounts::placeholder::kept_for_the_move)
        {
            refuse(stream, crate::accounts::placeholder::KEPT_FOR_THE_MOVE).await?;
            anyhow::bail!("guest took the move's name shape");
        }
        if let Some(look) = look {
            if relay.is_account_name(&look).await? {
                refuse(stream, "that name looks like an account's on this server").await?;
                anyhow::bail!("guest name looks like an account's");
            }
        }
        if relay.is_account_name(name).await? {
            refuse(
                stream,
                "that name belongs to an account here — sign in, or pick another",
            )
            .await?;
            anyhow::bail!("guest took an account's name");
        }
    }

    // An account's ban, then the address's; someone holding a role here gets
    // past an address ban (1.0 audit H1-07)
    if let Some(why) = crate::bans::refusal(
        state,
        peer_ip,
        signed_in
            .as_ref()
            .map(|s| (s.user.id.0, crate::accounts::holds_power(&s.scopes))),
    ) {
        end_unused_sign_in(state, signed_in.as_ref().map(|s| s.token.as_str())).await;
        refuse(stream, &why).await?;
        anyhow::bail!("banned");
    }

    if prekey_bundle.as_ref().is_some_and(|b| !bundle_is_sane(b)) {
        end_unused_sign_in(state, signed_in.as_ref().map(|s| s.token.as_str())).await;
        refuse(stream, "pre-key bundle is malformed").await?;
        anyhow::bail!("oversized pre-key bundle");
    }

    let user_id = state.next_user_id();
    // Deliberately the same value: the client keys per-user
    // volume and speaking state by the session_id in voice
    // packets, but its UI only knows user_ids.
    let session_id = user_id;

    // A guest a moderator took off posts does not get to say it in a name instead, as an
    // account is refused a display name. Not for the wait: that would rename any waiting
    // guest who reloads, and stop no first visit.
    let username = if signed_in.is_none() && crate::restrict::guest_text_held(state, peer_ip) {
        tagged.map_or_else(|| "guest".to_string(), |(_, tag)| format!("guest#{tag}"))
    } else {
        username
    };
    let username_lower = username.to_lowercase();
    let account_id = signed_in.as_ref().map(|s| s.user.id.0);
    match &signed_in {
        // An account signing in again takes over: the name and the account
        // move to this connection, and the old one is told why it closes.
        Some(s) => {
            state
                .username_to_session
                .insert(username_lower.clone(), session_id);
            if let Some(old) = state.account_sessions.insert(s.user.id.0, session_id) {
                force_disconnect(state, old, "signed in on another device").await;
            }
        }
        // Atomic username reservation — prevents race between two
        // simultaneous registrations with the same name
        None => match state.username_to_session.entry(username_lower.clone()) {
            dashmap::mapref::entry::Entry::Occupied(_) => {
                refuse(stream, "username already taken").await?;
                anyhow::bail!("username taken");
            }
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                entry.insert(session_id);
            }
        },
    }

    // Create a placeholder sender (will be replaced after split)
    let placeholder_tx = ControlTx::placeholder();

    let mut session = crate::state::UserSession::new(
        user_id,
        username.clone(),
        placeholder_tx,
        media_tx,
        peer_ip,
        state.max_users,
        state
            .channel_budget
            .load(std::sync::atomic::Ordering::Relaxed),
    );
    // What this particular client brought with it; the budgets
    // and the rest are the same for everybody (state.rs).
    session.identity_key = identity_key;
    session.bundle = prekey_bundle.map(|mut b| {
        b.prekeys.truncate(MAX_PREKEYS);
        b
    });
    // Someone the move knows has their own start for the wait. Only read where there is a
    // wait, and a failed read refuses the sign-in: counting from `created_at` would be the
    // wrong answer without saying so.
    let wait_mins = i64::from(state.settings.new_member_wait_mins);
    let wait_from = match (&signed_in, &state.accounts) {
        (Some(s), Some(relay)) if wait_mins > 0 => relay.wait_from(s.user.id, wait_mins * 60).await,
        _ => Ok(None),
    };
    if let Err(e) = &wait_from {
        warn!("reading when an account's wait starts: {e:#}");
    }
    let wait_unread = wait_from.is_err();
    let account = signed_in.map(|s| {
        session.account = Some(crate::state::AccountSession {
            user: s.user.clone(),
            token: s.token,
            info: s.info,
            scopes: Vec::new(),
            needs_2fa: s.account.needs_2fa,
            device_challenge: None,
            wait_from: wait_from.ok().flatten(),
            standing: s.standing,
            step_up_at: None,
            vault_proven: s.vault_proven,
            binding,
            key_challenge: None,
            key_stepped: None,
            by_secret: s.by_secret,
        });
        session.set_scopes(s.user, s.scopes);
        s.account
    });

    let refused = if state.sessions.contains_key(&session_id) {
        // An id that is already taken means the counter wrapped
        // and came back round to a session that is still live.
        // Inserting over it would drop that connection's writer on
        // the floor and leave its loop serving somebody else's
        // state, so refuse the new connection instead: the one
        // arriving can be told to try again, the one already here
        // cannot be told anything.
        Some("session id already in use, please reconnect")
    } else if wait_unread {
        Some("Something went wrong. Please try again.")
    } else if state.user_count() >= state.max_users as usize {
        Some("server is full")
    } else {
        // Out of the pre-authentication pool, which page loads and handshakes
        // share, into the one signed-in sessions use (main.rs `ConnLimits`). The
        // server may have filled up while an account signed in (1.0 audit H1-18).
        state.limits.promote(peer_ip).err()
    };
    if let Some(reason) = refused {
        state
            .username_to_session
            .remove_if(&username_lower, |_, sid| *sid == session_id);
        if let Some(a) = &session.account {
            state
                .account_sessions
                .remove_if(&a.user.id.0, |_, sid| *sid == session_id);
        }
        end_unused_sign_in(state, session.account.as_ref().map(|a| a.token.as_str())).await;
        refuse(stream, reason).await?;
        anyhow::bail!("{reason} (session {session_id})");
    }
    state.sessions.insert(session_id, session);
    // Two sign-ins of one account that finish together: the takeover above
    // ran before either was listed, so the later one found nothing to close.
    // Whichever does not hold the account now steps aside (1.0 audit H1-10).
    if let Some(id) = account_id {
        if state
            .account_sessions
            .get(&id)
            .is_some_and(|sid| *sid != session_id)
        {
            force_disconnect(state, session_id, "signed in on another device").await;
        }
    }
    // A ban that landed while this sign-in was under way found no session to
    // end (`bans::enforce`): look again now that this one is listed (S-019)
    let held = state.sessions.get(&session_id).and_then(|s| {
        s.account
            .as_ref()
            .map(|a| (a.user.id.0, crate::accounts::holds_power(&a.scopes)))
    });
    if let Some(why) = crate::bans::refusal(state, peer_ip, held) {
        force_disconnect(state, session_id, &why).await;
    }
    crate::restrict::admit(state, session_id);
    crate::gates::prune_own(state, session_id).await;
    // The bridge can start routing this session's media now
    let _ = sid_tx.send(session_id);

    // No network I/O after this point: every failure past the
    // inserts must run cleanup_session (handle_connection does).
    debug!(
        peer = %peer_addr,
        username = %username,
        user_id,
        session_id,
        account = account.is_some(),
        "authenticated"
    );

    Ok(Admitted {
        user_id,
        session_id,
        account,
    })
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
async fn relayable(ciphertext: &[u8], tx: &ControlTx) -> bool {
    if ciphertext.len() <= MAX_RELAY_CIPHERTEXT {
        return true;
    }
    channel_error(tx, "message too large").await;
    false
}

/// Spend one of this session's `state_change_rate` tokens, or say no.
///
/// Every message that has to ask is a flag the server keeps about the sender
/// and then announces to other people: nothing to store, a fan-out to tell.
/// A refusal is silent — no honest client comes near the budget, and answering
/// would be one more message going out.
fn may_change_state(state: &Arc<ServerState>, session_id: SessionId, user_id: UserId) -> bool {
    let allowed = state.spend(session_id, |s| &mut s.state_change_rate);
    if !allowed {
        debug!(user_id, "state change rate limit exceeded, dropping");
    }
    allowed
}

/// A restriction or the wait holds their words: a poke rings, an invite pops up, and
/// a channel's name is public text.
fn text_held(state: &ServerState, session_id: SessionId) -> bool {
    state
        .sessions
        .get(&session_id)
        .is_some_and(|s| s.silence.text())
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
        debug!(
            from_user_id,
            target_user_id, channel_id, "key relay rejected: not both members"
        );
        return false;
    }
    let allowed = state
        .sessions
        .get_mut(&session_id)
        .map(|mut s| s.may_relay_key_to(target_user_id))
        .unwrap_or(false);
    if !allowed {
        debug!(
            from_user_id,
            target_user_id, "key relay rate limit exceeded, dropping"
        );
    }
    allowed
}

/// Handle a client message after authentication.
async fn handle_message(
    msg: ClientMessage,
    state: &Arc<ServerState>,
    user_id: UserId,
    session_id: SessionId,
    tx: &ControlTx,
) -> Result<()> {
    match msg {
        ClientMessage::JoinChannel {
            channel_id,
            password,
        } => {
            handle_join_channel(
                state,
                user_id,
                session_id,
                channel_id,
                password.as_deref(),
                tx,
            )
            .await?;
        }
        ClientMessage::LeaveChannel { channel_id } => {
            handle_leave_text_channel(state, user_id, session_id, channel_id, tx).await?;
        }
        // One token however many: it tells nobody, which is what the budget pays for
        ClientMessage::JoinTextChannels { channels, quiet } => {
            // A line that says which path a client's text goes by: a device pass found none
            debug!(
                user_id,
                channels = channels.len(),
                quiet = quiet.len(),
                "following text channels on the live path"
            );
            if state.spend(session_id, |s| &mut s.join_rate) {
                state
                    .follow_text_channels(user_id, &channels, &quiet, tx)
                    .await;
            } else {
                channel_error(tx, "joining and leaving too fast, slow down").await;
            }
        }
        ClientMessage::SetQuiet { channels, quiet } => {
            if state.spend(session_id, |s| &mut s.join_rate) {
                state.set_quiet(user_id, &channels, quiet, tx).await;
            } else {
                channel_error(tx, "joining and leaving too fast, slow down").await;
            }
        }
        ClientMessage::KeyCheck {
            channel_id,
            restart,
        } => {
            handle_key_check(state, user_id, session_id, channel_id, restart, tx).await;
        }
        ClientMessage::OpenSessions {
            channel_id,
            targets,
        } => {
            handle_open_sessions(state, user_id, session_id, channel_id, targets, tx).await;
        }
        ClientMessage::SessionHello {
            to,
            message_type,
            ciphertext,
        } => {
            if relayable(&ciphertext, tx).await {
                handle_session_hello(state, user_id, session_id, to, message_type, ciphertext);
            }
        }
        ClientMessage::DistributeSenderKeys { channel_id, keys } => {
            handle_distribute_sender_keys(state, user_id, session_id, channel_id, keys).await;
        }
        ClientMessage::RenewSessionKeys {
            signed_prekey_id,
            signed_prekey,
            signed_prekey_signature,
            kyber_prekey_id,
            kyber_prekey,
            kyber_prekey_signature,
        } => {
            // The bounds a bundle at authentication passes
            let fits = signed_prekey.len() <= MAX_KEY_BYTES
                && signed_prekey_signature.len() <= MAX_SIGNATURE_BYTES
                && kyber_prekey.len() <= MAX_KEM_KEY_BYTES
                && kyber_prekey_signature.len() <= MAX_SIGNATURE_BYTES;
            if fits && state.spend(session_id, |s| &mut s.renew_keys_rate) {
                if let Some(b) = state
                    .sessions
                    .get_mut(&session_id)
                    .as_deref_mut()
                    .and_then(|s| s.bundle.as_mut())
                {
                    b.signed_prekey_id = signed_prekey_id;
                    b.signed_prekey = signed_prekey;
                    b.signed_prekey_signature = signed_prekey_signature;
                    b.kyber_prekey_id = kyber_prekey_id;
                    b.kyber_prekey = kyber_prekey;
                    b.kyber_prekey_signature = kyber_prekey_signature;
                }
            }
        }
        ClientMessage::KeyWanted {
            channel_id,
            from,
            reset,
        } => {
            let whole = state
                .channels
                .read()
                .await
                .get(&channel_id)
                .is_some_and(|c| c.follow.joined.contains_key(&from));
            if whole && may_relay_key(state, session_id, user_id, channel_id, from).await {
                if let Some(session) = state.sessions.get(&from) {
                    let _ = send_msg(
                        &session.control_tx,
                        &ServerMessage::KeyWanted {
                            channel_id,
                            from: user_id,
                            reset,
                        },
                    );
                }
            }
        }
        // The same rule as `RequestChannelUsers`, and no log: a gated list asked for says
        // which channel a person is looking at
        ClientMessage::RequestChannelPage { channel_id, after } => {
            // Silent: an honest app stays under it, and an empty page would read as nobody here
            if !state.spend(session_id, |s| &mut s.roster_rate) {
                return Ok(());
            }
            let allowed = state.is_channel_public_or_member(channel_id, user_id).await
                || state.is_admin(session_id);
            let (ids, rows, next, total) = if allowed {
                state.channel_page(channel_id, session_id, after).await
            } else {
                (Vec::new(), Vec::new(), 0, 0)
            };
            let _ = send_msg(
                tx,
                &ServerMessage::ChannelPage {
                    channel_id,
                    ids,
                    rows,
                    next,
                    total,
                },
            );
        }
        ClientMessage::CreateChannel {
            name,
            password,
            proximity,
            anonymous,
            text,
        } => {
            if text_held(state, session_id) {
                channel_error(tx, crate::restrict::TEXT_HELD).await;
                return Ok(());
            }
            let allowed = state.spend(session_id, |s| &mut s.create_channel_rate);
            if !allowed {
                channel_error(tx, "rate limit exceeded, try again later").await;
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
            //
            // Where there are accounts it takes the privilege too (`may_share_history`
            // says the same for the app): a `true` without it changes nothing here.
            let changed = state
                .sessions
                .get_mut(&session_id)
                .map(|mut s| {
                    let on = enabled
                        && (state.accounts.is_none() || crate::accounts::holds_share_history(&s));
                    let changed = s.shares_history != on;
                    s.shares_history = on;
                    changed.then_some(on)
                })
                .unwrap_or(None);
            // Kept at rest too, even with nothing changed here: a switch turned off
            // on a device away from this relay reaches it as this `false` at connect
            let at_rest = state
                .sessions
                .get(&session_id)
                .and_then(|s| s.account.as_ref().map(|a| (a.user.id.0, s.shares_history)));
            if let (Some(relay), Some((account, on))) = (state.accounts.as_ref(), at_rest) {
                if let Err(e) = crate::accounts::log::set_shares(relay.store(), &account, on).await
                {
                    tracing::warn!("keeping who shares: {e:#}");
                }
            }
            // To everyone, unlike mute and deafen, and including the sender.
            // Everyone, because a text channel's subscribers are standing in
            // voice channels of their own, so "this channel" is not a place
            // the news would reach them. The sender too, because their own row
            // in their own member list has to show what everyone else sees —
            // the mute flag not being echoed is exactly what made that one
            // disagree with itself.
            if let Some(enabled) = changed {
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
            let channels = state.channel_list_for(session_id).await;
            send_channel_list(tx, channels);
            crate::layout::send(state, session_id).await;
        }
        ClientMessage::Ping { timestamp } => {
            let _ = send_msg(tx, &ServerMessage::Pong { timestamp });
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
            options,
        } => {
            if !may_change_state(state, session_id, user_id) {
                return Ok(());
            }
            handle_set_channel_options(state, user_id, session_id, channel_id, options, tx).await?;
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
            let allowed = state.spend(session_id, |s| &mut s.audio_filter_rate);
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
        ClientMessage::ProfilesGet { accounts } => {
            crate::accounts::profile::answer_profiles(state, session_id, &accounts, tx).await;
        }
        ClientMessage::ProfilePictureGet { hash } => {
            crate::accounts::profile::answer_picture(state, session_id, hash, tx).await;
        }
        ClientMessage::ReportTakersGet => {
            if !state.spend(session_id, |s| &mut s.report_rate) {
                channel_error(tx, crate::report::ASKED_TOO_OFTEN).await;
                return Ok(());
            }
            let takers = crate::report::takers_for(state, session_id, user_id).await;
            let _ = send_msg(tx, &ServerMessage::ReportTakers { takers });
        }
        ClientMessage::RequestChannelUsers { channel_id } => {
            if !state.spend(session_id, |s| &mut s.roster_rate) {
                return Ok(());
            }
            let allowed = state.is_channel_public_or_member(channel_id, user_id).await
                || state.is_admin(session_id);
            let users = if allowed {
                state.users_in_channel_for(channel_id, session_id).await
            } else {
                vec![]
            };
            send_roster(tx, channel_id, users, |channel_id, users| {
                ServerMessage::ChannelUsers { channel_id, users }
            });
        }
        ClientMessage::SendInvite {
            channel_id,
            target_user_id,
        } => {
            if text_held(state, session_id) {
                channel_error(tx, crate::restrict::TEXT_HELD).await;
                return Ok(());
            }
            // An invite raises a popup on the target's screen, every time it
            // is sent — the invite set dedupes, the notification does not. The
            // same budget as a poke, for the same reason.
            let allowed = state.spend(session_id, |s| &mut s.chat_rate);
            if !allowed {
                channel_error(tx, "sending too fast, slow down").await;
            } else {
                handle_send_invite(state, user_id, session_id, channel_id, target_user_id, tx)
                    .await?;
            }
        }
        ClientMessage::AcceptInvite { channel_id } => {
            // Whether there is anything to accept, and who asked, read before the
            // join spends the invite. The join answers Ok whether or not it went
            // through, so without this anybody could make anyone's client say that
            // somebody of their choosing had accepted.
            let inviter = state
                .channels
                .read()
                .await
                .get(&channel_id)
                .filter(|ch| ch.invited_users.contains(&user_id))
                .map(|ch| ch.inviter_of(user_id));
            let Some(inviter) = inviter else {
                return Ok(());
            };
            // Join with no password — validate_join will check invite set
            handle_join_channel(state, user_id, session_id, channel_id, None, tx).await?;
            // Notify who asked, if the join really happened
            let joined = state
                .channels
                .read()
                .await
                .get(&channel_id)
                .is_some_and(|ch| ch.members.contains(&user_id));
            if joined {
                if let Some(session) = inviter.and_then(|id| state.sessions.get(&id)) {
                    let _ = send_msg(
                        &session.control_tx,
                        &ServerMessage::InviteAccepted {
                            channel_id,
                            user_id,
                        },
                    );
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
            if text_held(state, session_id) {
                channel_error(tx, crate::restrict::TEXT_HELD).await;
                return Ok(());
            }
            if relayable(&ciphertext, tx).await {
                // Pokes play a sound and raise an OS notification — same budget as chat
                let allowed = state.spend(session_id, |s| &mut s.chat_rate);
                if !allowed {
                    channel_error(tx, "sending too fast, slow down").await;
                } else {
                    handle_send_poke(
                        state,
                        user_id,
                        session_id,
                        target_user_id,
                        ciphertext,
                        message_type,
                        tx,
                    )
                    .await?;
                }
            }
        }
        ClientMessage::StartScreenShare {
            source: _,
            resolution,
            codec,
        } => {
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
                    .sessions
                    .get(&sharer_user_id)
                    .map(|s| s.control_tx.clone());
                if let Some(sharer_tx) = sharer_tx {
                    let _ = send_msg(
                        &sharer_tx,
                        &ServerMessage::VideoLossReported {
                            viewer_user_id: user_id,
                            frames_dropped,
                            frames_received,
                        },
                    );
                }
            }
        }
        ClientMessage::Authenticate { .. } | ClientMessage::AuthContinue(_) => {
            // debug, like the other things a client can repeat at line rate:
            // a log line is the cheapest thing on a server to make somebody
            // else write.
            debug!(
                user_id,
                "received a sign-in message after sign-in, ignoring"
            );
        }
        ClientMessage::Account(req) => {
            crate::accounts::handle_request(state, session_id, req, tx).await?;
        }

        // ── Files (protocol v13): negotiation only, bytes over HTTPS ─────
        ClientMessage::FileUpload { conv, size, hash } => {
            crate::files::handle_upload(state, session_id, conv, size, hash, tx).await;
        }
        ClientMessage::FileFetch { conv, hash } => {
            crate::files::handle_fetch(state, session_id, conv, hash, tx).await;
        }
        ClientMessage::FileCancel { hash } => {
            crate::files::handle_cancel(state, session_id, hash).await;
        }

        ClientMessage::EmoteAdd { emote } => {
            crate::emotes::handle_add(state, session_id, emote, tx).await;
        }
        ClientMessage::EmoteRemove { names } => {
            crate::emotes::handle_remove(state, session_id, names, tx).await;
        }
        ClientMessage::EmoteMove {
            names,
            pack,
            sticker,
        } => {
            crate::emotes::handle_move(state, session_id, names, pack, sticker, tx).await;
        }
        ClientMessage::EmoteStickers { on } => {
            crate::emotes::handle_stickers(state, session_id, on, tx).await;
        }
        ClientMessage::EmoteRename { from, to } => {
            crate::emotes::handle_rename(state, session_id, from, to, tx).await;
        }

        // ── E2E Encryption handlers ──────────────────────────────────────
        ClientMessage::RequestPreKeyBundle { target_user_id } => {
            // Each bundle consumes one of the target's one-time pre-keys
            // (100 stored, replenished at 0.2 uploads/s) — unthrottled, one
            // user could drain anyone's supply in seconds.
            let allowed = state.spend(session_id, |s| &mut s.prekey_bundle_rate);
            if allowed {
                handle_request_prekey_bundle(state, target_user_id, tx).await?;
            } else {
                let _ = send_msg(
                    tx,
                    &ServerMessage::PreKeyBundleUnavailable {
                        user_id: target_user_id,
                    },
                );
            }
        }
        ClientMessage::UploadPreKeys { prekeys } => {
            let allowed = state.spend(session_id, |s| &mut s.prekey_rate);
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
                let allowed = state.spend(session_id, |s| &mut s.chat_rate);
                if !allowed {
                    channel_error(tx, "sending too fast, slow down").await;
                } else {
                    handle_encrypted_direct_message(
                        state,
                        user_id,
                        session_id,
                        target_user_id,
                        ciphertext,
                        message_type,
                        tx,
                    )
                    .await?;
                }
            }
        }
        ClientMessage::SendEncryptedChannelMessage {
            channel_id,
            ciphertext,
        } => {
            if relayable(&ciphertext, tx).await {
                let allowed = state.spend(session_id, |s| &mut s.chat_rate);
                if !allowed {
                    channel_error(tx, "sending too fast, slow down").await;
                } else {
                    handle_encrypted_channel_message(
                        state, user_id, session_id, channel_id, ciphertext, tx,
                    )
                    .await?;
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
                    state,
                    user_id,
                    channel_id,
                    target_user_id,
                    distribution_message,
                    message_type,
                )
                .await?;
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
                    state,
                    user_id,
                    channel_id,
                    target_user_id,
                    encrypted_media_key,
                    message_type,
                )
                .await?;
            }
        }

        // ── Moderation ─────────────────────────────────────────────────
        ClientMessage::AdminLogin { token } => {
            handle_admin_login(state, user_id, session_id, &token, tx).await;
        }
        ClientMessage::AdminKick {
            user_id: target_id,
            reason,
        } => {
            if state.can(session_id, Powers::KICK) {
                handle_admin_kick(
                    state,
                    user_id,
                    state.is_admin(session_id),
                    target_id,
                    reason,
                    None,
                    tx,
                )
                .await;
            } else {
                admin_error(tx, "not an admin").await;
            }
        }
        ClientMessage::AdminBan {
            user_id: target_id,
            reason,
            duration_secs,
            account,
        } => {
            if state.can(session_id, Powers::BAN) {
                handle_admin_kick(
                    state,
                    user_id,
                    state.is_admin(session_id),
                    target_id,
                    reason,
                    Some((duration_secs, account)),
                    tx,
                )
                .await;
            } else {
                admin_error(tx, "not an admin").await;
            }
        }
        // The ban list is `voipc:bans` (before 1.7 an admin's alone, the 0.12
        // decision): banning someone in sight does not come with it.
        ClientMessage::AdminUnban { id } => {
            if !state.can(session_id, Powers::BANS) {
                admin_error(tx, "not an admin").await;
            } else {
                handle_admin_unban(state, session_id, id, tx).await;
            }
        }
        ClientMessage::AdminListBans => {
            if state.can(session_id, Powers::BANS) {
                let admin = state.is_admin(session_id);
                let _ = send_msg(tx, &crate::bans::page(state, admin, "", 0));
            } else {
                admin_error(tx, "not an admin").await;
            }
        }
        ClientMessage::AdminBansPage { search, offset } => {
            if state.can(session_id, Powers::BANS) {
                let admin = state.is_admin(session_id);
                let _ = send_msg(tx, &crate::bans::page(state, admin, &search, offset));
            } else {
                admin_error(tx, "not an admin").await;
            }
        }
        ClientMessage::AdminBanAccount {
            name,
            reason,
            duration_secs,
        } => {
            if state.can(session_id, Powers::BANS) {
                handle_admin_ban_account(state, session_id, &name, reason, duration_secs, tx).await;
            } else {
                admin_error(tx, "not an admin").await;
            }
        }
        // Top-level as the kick and the ban are: a token admin on a relay without
        // accounts acts too, and an AccountRequest needs an account
        ClientMessage::AdminRestrict {
            user_id: target_id,
            voice,
            text,
            duration_secs,
            reason,
        } => {
            if !state.can(session_id, Powers::RESTRICT) {
                admin_error(tx, "not an admin").await;
            } else if may_change_state(state, session_id, user_id) {
                crate::restrict::handle(
                    state,
                    session_id,
                    target_id,
                    voice,
                    text,
                    duration_secs,
                    reason,
                    tx,
                )
                .await;
            }
        }

        // ── Channel history hand-off ───────────────────────────────────
        ClientMessage::RequestChannelHistory {
            channel_id,
            target_user_id,
        } => {
            let allowed = state.spend(session_id, |s| &mut s.history_request_rate);
            if allowed {
                handle_request_channel_history(state, user_id, channel_id, target_user_id).await;
            }
        }
        ClientMessage::SendChannelHistory {
            channel_id,
            target_user_id,
            ciphertext,
            message_type,
        } => {
            if relayable(&ciphertext, tx).await {
                let allowed = state.spend(session_id, |s| &mut s.chat_rate);
                if allowed {
                    handle_send_channel_history(
                        state,
                        user_id,
                        session_id,
                        channel_id,
                        target_user_id,
                        ciphertext,
                        message_type,
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
    tx: &ControlTx,
) -> Result<()> {
    // Rate-limit password attempts to prevent brute force
    if password.is_some() {
        let allowed = state.spend(session_id, |s| &mut s.password_attempt_rate);
        if !allowed {
            channel_error(tx, "too many password attempts, slow down").await;
            return Ok(());
        }
    }

    // Either kind of join announces itself to every session on the server —
    // a voice one twice, being a leave and a join — so both draw on the same
    // budget. See `join_rate`.
    let allowed = state.spend(session_id, |s| &mut s.join_rate);
    if !allowed {
        channel_error(tx, "joining and leaving too fast, slow down").await;
        return Ok(());
    }

    // A password for a channel from channels.json is checked against its hash
    // here, before the channel lock (Argon2 is slow)
    let checked = state
        .channel_password_attempt(channel_id, user_id, password)
        .await;
    let password = checked.as_deref().map(|p| p.as_str());

    // A text channel is a subscription, not a move: the user keeps the voice
    // channel they stand in, and every other text channel they are in. It
    // needs no separate validation pass either — there is no current channel to
    // protect, and `join_text_channel` checks the password, the capacity and
    // the per-user subscription cap itself, after the membership check that
    // makes a repeated join a no-op.
    if state.is_text_channel(channel_id).await {
        match state.join_text_channel(user_id, channel_id, password).await {
            // Nobody is told and no roster comes: the admission was this, and following it
            // is one more frame's work
            Ok(_) => {
                state
                    .follow_text_channels(user_id, &[channel_id], &[], tx)
                    .await;
            }
            Err(e) => {
                channel_error(tx, e.to_string()).await;
            }
        }
        return Ok(());
    }

    // Validate the join BEFORE leaving the current channel.
    // This way, if the password is wrong or the channel is full,
    // the user stays where they are instead of being dumped into General.
    if let Err(e) = state.validate_join(channel_id, password, user_id).await {
        channel_error(tx, e.to_string()).await;
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
        crate::files::left_channel(state, session_id, left_channel_id);
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
        send_roster(tx, 0, users, user_list);
        return Ok(());
    }

    // Send user list for the new channel to the joining user
    let users = state.users_in_channel_for(channel_id, session_id).await;
    send_roster(tx, channel_id, users, user_list);
    tell_listen_only(state, session_id, channel_id, tx);

    // Media keys are generated by clients and exchanged over pairwise Signal
    // sessions (DistributeMediaKey) — the server never sees them.

    // Build user info for the join notification
    let user_info = user_info_for(state, user_id, session_id, channel_id);

    broadcast_user_joined(state, user_info).await;

    Ok(())
}

fn user_list(channel_id: ChannelId, users: Vec<UserInfo>) -> ServerMessage {
    ServerMessage::UserList { channel_id, users }
}

/// A roster to one person: what a frame holds, in id order, as `first`, and any more behind
/// it as `ChannelPage`s. Past some 800 rows the old way was no list at all.
fn send_roster(
    tx: &ControlTx,
    channel_id: ChannelId,
    mut users: Vec<UserInfo>,
    first: fn(ChannelId, Vec<UserInfo>) -> ServerMessage,
) {
    users.sort_unstable_by_key(|u| u.user_id);
    let total = users.len() as u32;
    let (head, mut rest) = crate::state::cut_rows(users);
    let _ = send_msg(tx, &first(channel_id, head));
    while !rest.is_empty() {
        let (rows, more) = crate::state::cut_rows(rest);
        let next = if more.is_empty() {
            0
        } else {
            rows.last().map_or(0, |u| u.user_id)
        };
        let _ = send_msg(
            tx,
            &ServerMessage::ChannelPage {
                channel_id,
                ids: Vec::new(),
                rows,
                next,
                total,
            },
        );
        rest = more;
    }
}

/// The channel list: in one `ChannelList` while it fits, and past that all of it as
/// `ChannelListMore`, so a `ChannelList` is always the whole list.
pub(crate) fn send_channel_list(tx: &ControlTx, channels: Vec<ChannelInfo>) {
    let whole = ServerMessage::ChannelList { channels };
    if let Ok(data) = encode_server_msg(&whole) {
        let _ = tx.try_send(data);
        return;
    }
    let ServerMessage::ChannelList { channels } = whole else {
        return;
    };
    let mut frames: Vec<Vec<ChannelInfo>> = vec![Vec::new()];
    let mut bytes = 0;
    for channel in channels {
        let cost = postcard::to_allocvec(&channel).map_or(0, |b| b.len());
        if bytes + cost > CHANNELS_FRAME_BYTES {
            frames.push(Vec::new());
            bytes = 0;
        }
        bytes += cost;
        if let Some(frame) = frames.last_mut() {
            frame.push(channel);
        }
    }
    let last = frames.len() - 1;
    for (i, channels) in frames.into_iter().enumerate() {
        let msg = ServerMessage::ChannelListMore {
            channels,
            more: i < last,
        };
        let _ = send_msg(tx, &msg);
    }
}

/// A join into a channel where its gate lets them only listen says so: the
/// relay drops what they say there, and that must never be silent.
fn tell_listen_only(
    state: &ServerState,
    session_id: SessionId,
    channel_id: ChannelId,
    tx: &ControlTx,
) {
    let listen = state
        .sessions
        .get(&session_id)
        .is_some_and(|s| s.listen_only.contains(&channel_id));
    if listen {
        let _ = send_msg(
            tx,
            &ServerMessage::ListenOnly {
                channel_id,
                on: true,
            },
        );
    }
}

/// The joiner, as the join notification describes them. `channel_id` is the
/// channel they joined — the voice room they moved into, or the text channel
/// they subscribed to.
pub(crate) fn user_info_for(
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
        username: session
            .as_ref()
            .map(|s| s.username.clone())
            .unwrap_or_default(),
        channel_id,
        is_muted: session.as_ref().map(|s| s.is_muted).unwrap_or(false),
        is_deafened: session.as_ref().map(|s| s.is_deafened).unwrap_or(false),
        is_screen_sharing: false,
        is_admin: session.as_ref().is_some_and(|s| s.is_admin),
        shares_history: session.as_ref().is_some_and(|s| s.shares_history),
        account: session
            .as_ref()
            .and_then(|s| s.account.as_ref().map(|a| a.user.id.0)),
        is_moderator: session
            .as_ref()
            .is_some_and(|s| s.powers.has(Powers::CHANNELS)),
        badges: session
            .as_ref()
            .map(|s| s.badges_with(s.account_id()))
            .unwrap_or_default(),
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
    tx: &ControlTx,
) -> Result<()> {
    // Same budget as the join, and for the same reason: leaving is also a
    // broadcast to every session plus a write of the channel map, and a
    // subscription can be dropped and retaken as fast as a client likes.
    let allowed = state.spend(session_id, |s| &mut s.join_rate);
    if !allowed {
        channel_error(tx, "joining and leaving too fast, slow down").await;
        return Ok(());
    }
    match state.leave_text_channel(user_id, channel_id).await {
        Some(remaining) => {
            // Out of its log too: what is written there from now on is not
            // for them (1.0, D10)
            crate::accounts::out_of_log(state, channel_id, session_id).await;
            crate::files::left_channel(state, session_id, channel_id);
            let _ = send_msg(
                tx,
                &ServerMessage::UserLeft {
                    user_id,
                    channel_id,
                },
            );
            member_gone(state, channel_id, user_id).await;
            if remaining == 0 {
                start_channel_delete_timer(state, channel_id).await;
            }
        }
        None => {
            channel_error(tx, "not a text channel you are in").await;
        }
    }
    Ok(())
}

/// `user_id` is out of a channel where a device asks who is here: it answers them nothing
/// from now on, whatever its last list says. To its followers, and only where a list exists
/// to go stale: in an open channel anyone online may read anyway.
async fn member_gone(state: &ServerState, channel_id: ChannelId, user_id: UserId) {
    let txs: Vec<ControlTx> = {
        let channels = state.channels.read().await;
        let Some(channel) = channels.get(&channel_id).filter(|c| c.tells_who_left()) else {
            return;
        };
        let followers = channel.follow.joined.keys();
        followers
            .chain(channel.follow.quiet.keys())
            .filter_map(|uid| Some(state.sessions.get(uid)?.control_tx.clone()))
            .collect()
    };
    let msg = ServerMessage::MemberGone {
        channel_id,
        user_id,
    };
    if let Ok(data) = encode_server_msg(&msg) {
        for tx in txs {
            let _ = tx.try_send(data.clone());
        }
    }
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
    broadcast_user(state, user, false).await;
}

/// A member's badges or privileges changed (`UserUpdated`): told, under the
/// join's rules, to the people whose roster shows them.
pub(crate) async fn broadcast_user_updated(state: &Arc<ServerState>, user: UserInfo) {
    broadcast_user(state, user, true).await;
}

async fn broadcast_user(state: &Arc<ServerState>, user: UserInfo, updated: bool) {
    let (real, alias) = state.names_of_in(user.channel_id, user.user_id).await;
    let roster = roster_audience(state, user.channel_id).await;
    for entry in state.sessions.iter() {
        let session = entry.value();
        if session.user_id == user.user_id || !crate::gates::passes(session, &roster.gate) {
            continue;
        }
        // Two different questions. The name goes to the channel's own people
        // only, always has, and that is what keeps a move between an anonymous
        // channel and an ordinary one from handing outsiders both names for
        // one person. The *id* is the narrower rule below: a channel that
        // hides its members hides them here too.
        //
        // A public room is told by name to everyone inside its gate: anyone may ask its
        // list, and every app would, so a blank protected nothing and each join cost an
        // ask. A bare id in `KeysOwed` leans on this.
        let told_name = roster.knows_them(session.user_id) || roster.public;
        if updated && !(told_name || session.is_admin) {
            continue;
        }
        let username = if told_name || session.is_admin {
            crate::state::pick_name(&real, &alias, session.is_admin)
        } else {
            // The client only renders this for its own channel anyway
            String::new()
        };
        let may_name = roster.may_name(session.user_id, user.user_id) || session.is_admin;
        let account = crate::state::account_shown(
            user.account,
            told_name && alias.is_none(),
            session.is_admin,
        );
        let info = UserInfo {
            username,
            user_id: roster.tell(may_name, user.user_id),
            account,
            // Where the account is withheld, so are the badges that would name it
            badges: if account.is_some() {
                user.badges.clone()
            } else {
                Vec::new()
            },
            ..user.clone()
        };
        let msg = if updated {
            ServerMessage::UserUpdated { user: info }
        } else {
            ServerMessage::UserJoined { user: info }
        };
        let _ = send_msg(&session.control_tx, &msg);
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
        // Outside a gate, not even the count: the channel is not there
        if session.user_id != user_id && !crate::gates::passes(session, &roster.gate) {
            continue;
        }
        let may_name = roster.may_name(session.user_id, user_id) || session.is_admin;
        let msg = ServerMessage::UserLeft {
            user_id: roster.tell(may_name, user_id),
            channel_id,
        };
        let _ = send_msg(&session.control_tx, &msg);
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
    /// A room whose list anyone inside its gate may ask for.
    public: bool,
    /// The groups that see the channel at all (`ChannelGate::groups`).
    gate: Vec<String>,
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
            public: !channel.info.text
                && !channel.info.anonymous
                && !channel.info.hide_members
                && channel.password.is_none(),
            gate: channel.gate.groups.clone(),
        },
        None => RosterAudience {
            members: Default::default(),
            private: false,
            public: false,
            gate: Vec::new(),
        },
    }
}

/// Handle a create channel request.
#[allow(clippy::too_many_arguments)]
async fn handle_create_channel(
    state: &Arc<ServerState>,
    user_id: UserId,
    session_id: SessionId,
    name: String,
    password: Option<String>,
    proximity: ProximityMode,
    anonymous: bool,
    text: bool,
    tx: &ControlTx,
) -> Result<()> {
    // Validate and sanitize name
    let name = name.trim().to_string();
    if name.is_empty() || name.chars().count() > state.settings.max_channel_name_len {
        channel_error(
            tx,
            format!(
                "channel name must be 1-{} characters",
                state.settings.max_channel_name_len
            ),
        )
        .await;
        return Ok(());
    }

    // One of only what draws nothing is a blank row in everyone's list (W1-36)
    if name.chars().any(bad_name_char) || !voipc_protocol::names::draws_something(&name) {
        channel_error(tx, "channel name contains invalid characters").await;
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
            channel_error(tx, e.to_string()).await;
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
    tx: &ControlTx,
) -> Result<()> {
    // Nobody reaches into a channel they cannot see, by id either
    if !state.may_reach(session_id, channel_id).await {
        channel_error(tx, "channel does not exist").await;
        return Ok(());
    }
    let overrides = state.can(session_id, Powers::CHANNELS);
    let locks = password.is_some();
    match state
        .set_channel_password(channel_id, user_id, password, overrides)
        .await
    {
        // None: the password it already had. Re-sending the options a channel
        // has is something a client may do, and every one of those would
        // otherwise be a message to every session on the server.
        Ok(None) => {}
        Ok(Some(updated_info)) => {
            if locks {
                crate::accounts::locked_log(state, channel_id).await;
            }
            channel_updated(state, updated_info).await;
            if locks {
                crate::layout::welcome_locked(state, channel_id).await;
            }
        }
        Err(e) => {
            channel_error(tx, e.to_string()).await;
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
    tx: &ControlTx,
) -> Result<()> {
    // Nobody reaches into a channel they cannot see, by id either
    if !state.may_reach(session_id, channel_id).await {
        channel_error(tx, "channel does not exist").await;
        return Ok(());
    }
    let overrides = state.can(session_id, Powers::CHANNELS);
    match state
        .set_channel_proximity(channel_id, user_id, proximity, overrides)
        .await
    {
        // None: the mode it was already in — see the password handler above.
        Ok(None) => {}
        Ok(Some(updated_info)) => {
            channel_updated(state, updated_info).await;
        }
        Err(e) => {
            channel_error(tx, e.to_string()).await;
        }
    }
    Ok(())
}

/// Handle a change to the other channel options (creator or admin).
async fn handle_set_channel_options(
    state: &Arc<ServerState>,
    user_id: UserId,
    session_id: SessionId,
    channel_id: ChannelId,
    request: ChannelOptions,
    tx: &ControlTx,
) -> Result<()> {
    // Nobody reaches into a channel they cannot see, by id either
    if !state.may_reach(session_id, channel_id).await {
        channel_error(tx, "channel does not exist").await;
        return Ok(());
    }
    // Turning anonymity off shows everyone in there by their real name: an
    // unmasking, so an admin's or the channel creator's alone.
    if request.anonymous == Some(false) && !state.is_admin(session_id) {
        let unmasks = state
            .channels
            .read()
            .await
            .get(&channel_id)
            .is_some_and(|c| c.info.anonymous && c.info.created_by != Some(user_id));
        if unmasks {
            channel_error(
                tx,
                "only an admin or the channel's creator can turn anonymity off".to_string(),
            )
            .await;
            return Ok(());
        }
    }
    // A hidden member list is the admins' to see (THREAT-MODEL): switched off for a moment,
    // it would hand the list to someone standing outside, with no row in the log (W1-26)
    if request.hide_members == Some(false) && !state.is_admin(session_id) {
        let shows = state
            .channels
            .read()
            .await
            .get(&channel_id)
            .is_some_and(|c| c.info.hide_members && c.info.created_by != Some(user_id));
        if shows {
            channel_error(
                tx,
                "only an admin or the channel's creator can show its member list again".to_string(),
            )
            .await;
            return Ok(());
        }
    }
    let overrides = state.can(session_id, Powers::CHANNELS);
    match state
        .set_channel_options(channel_id, user_id, request, overrides)
        .await
    {
        Ok((updated_info, changed)) => {
            let sharing_off = !updated_info.screen_share;
            // Nothing moved means nothing to tell anybody, and this one goes
            // to every session on the server: a client re-sending the options
            // a channel already has must not cost a fan-out each time.
            if changed.any {
                channel_updated(state, updated_info).await;
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
                            &session.control_tx,
                            &ServerMessage::ScreenShareError {
                                reason: "screen sharing was switched off in this channel".into(),
                            },
                        );
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
            channel_error(tx, e.to_string()).await;
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
            .filter_map(|uid| state.sessions.contains_key(uid).then_some(*uid))
            .collect()
    };
    for sid in members {
        let users = state.users_in_channel_for(channel_id, sid).await;
        if let Some(session) = state.sessions.get(&sid) {
            send_roster(&session.control_tx, channel_id, users, user_list);
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
    tx: &ControlTx,
) -> Result<()> {
    // Nobody reaches into a channel they cannot see, by id either
    if !state.may_reach(requester_session_id, channel_id).await {
        channel_error(tx, "channel does not exist").await;
        return Ok(());
    }
    let admin = state.is_admin(requester_session_id);
    let moderates = state.can(requester_session_id, Powers::KICK);
    // A moderator moderates people, not the ones who moderate (but still
    // has a creator's say in their own channel).
    let spared = moderates
        && !admin
        && state
            .sessions
            .get(&target_id)
            .is_some_and(|t| t.is_admin || t.is_moderator);
    let is_text = state.is_text_channel(channel_id).await;
    let (creator, channel_key, channel_name) = state
        .channels
        .read()
        .await
        .get(&channel_id)
        .map(|c| {
            (
                c.info.created_by == Some(requester_id),
                c.gate_key.clone(),
                c.info.name.clone(),
            )
        })
        .unwrap_or_default();
    // A creator's kick in their own channel takes no privilege, whatever else they
    // hold, and leaves no row
    if moderates && !creator {
        if let Err(e) = state
            .may_kick(channel_id, requester_id, target_id, moderates, spared)
            .await
        {
            channel_error(tx, e.to_string()).await;
            return Ok(());
        }
        let (target, target_name) = modlog::target_of(state, target_id, Some(channel_id)).await;
        let row = modlog::Entry {
            action: "channel_kick",
            target,
            target_name: &target_name,
            channel_key: &channel_key,
            channel_name: &channel_name,
            ..Default::default()
        };
        if let Err(e) = modlog::put(state, requester_session_id, row).await {
            warn!("keeping a kick: {e:#}");
            channel_error(tx, "the kick could not be kept").await;
            return Ok(());
        }
    }
    match state
        .kick_user(channel_id, requester_id, target_id, moderates, spared)
        .await
    {
        Ok((target_session_id, remaining_count, moved)) => {
            let reason = if admin {
                "You were kicked from the channel by an admin"
            } else if moderates {
                "You were kicked from the channel by a moderator"
            } else {
                "You were kicked by the channel creator"
            };
            after_kick(
                state,
                channel_id,
                target_id,
                target_session_id,
                remaining_count,
                moved,
                is_text,
                false,
                reason.into(),
            )
            .await;
        }
        Err(e) => {
            channel_error(tx, e.to_string()).await;
        }
    }
    Ok(())
}

/// Out of a channel, as a kick does it: the log, files and shares go, the
/// room is told, a voice member lands in General.
#[allow(clippy::too_many_arguments)]
async fn after_kick(
    state: &Arc<ServerState>,
    channel_id: ChannelId,
    target_id: UserId,
    target_session_id: SessionId,
    remaining_count: usize,
    moved: bool,
    is_text: bool,
    evicted: bool,
    reason: String,
) {
    if evicted {
        crate::accounts::gated_out_of_log(state, channel_id, target_session_id).await;
    } else {
        crate::accounts::out_of_log(state, channel_id, target_session_id).await;
    }
    crate::files::left_channel(state, target_session_id, channel_id);
    // Same teardown as leave/disconnect: otherwise a kicked viewer
    // keeps receiving the share's video and a kicked sharer leaves
    // its viewers stuck. A text channel carries neither.
    if !is_text {
        cleanup_and_notify_screen_shares(state, target_id, target_session_id, channel_id).await;
    }

    // Notify the kicked user. A kick leaves a mark and they stay out, and a lost gate leaves
    // none: they follow it again if they win it back.
    if let Some(session) = state.sessions.get(&target_session_id) {
        let msg = if evicted {
            ServerMessage::Evicted { channel_id, reason }
        } else {
            ServerMessage::Kicked { channel_id, reason }
        };
        let _ = send_msg(&session.control_tx, &msg);
    }

    if is_text {
        if let Some(session) = state.sessions.get(&target_session_id) {
            let _ = send_msg(
                &session.control_tx,
                &ServerMessage::UserLeft {
                    user_id: target_id,
                    channel_id,
                },
            );
        }
        member_gone(state, channel_id, target_id).await;
    } else {
        // Broadcast UserLeft to everyone, the leaver included: they always learn about
        // themselves.
        broadcast_user_left(state, target_id, channel_id, None).await;
    }

    // `kick_user` moved them to General under the channel lock; out of
    // a text channel nobody moves. Not told if they have moved on
    // since: their own join has already said where they are.
    let still_there = moved
        && state
            .sessions
            .get(&target_session_id)
            .is_some_and(|s| s.channel_id == 0);
    if still_there {
        let general_users = state.users_in_channel_for(0, target_session_id).await;

        if let Some(session) = state.sessions.get(&target_session_id) {
            send_roster(&session.control_tx, 0, general_users, user_list);
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

/// Out of a channel they may no longer enter (`gates`), as a kick does it,
/// and the channel is gone from their list.
pub(crate) async fn evict(state: &Arc<ServerState>, channel_id: ChannelId, target_id: UserId) {
    let is_text = state.is_text_channel(channel_id).await;
    // User ids start at 1, so 0 is nobody's: the relay itself, which moderates
    if let Ok((sid, remaining, moved)) =
        state.kick_user(channel_id, 0, target_id, true, false).await
    {
        after_kick(
            state,
            channel_id,
            target_id,
            sid,
            remaining,
            moved,
            is_text,
            true,
            "You no longer have access to this channel".into(),
        )
        .await;
    }
    if let Some(s) = state.sessions.get(&target_id) {
        let _ = send_msg(&s.control_tx, &ServerMessage::ChannelDeleted { channel_id });
    }
}

/// Handle a channel invite: from the channel creator, or a summon, from a holder of
/// `voipc:channels` standing in the room (`check_invite`). Nothing happens to whoever
/// is asked without their yes. A summon writes its row first, as a moderator's channel
/// kick does; a creator's invite takes no privilege and leaves no row.
async fn handle_send_invite(
    state: &Arc<ServerState>,
    requester_id: UserId,
    session_id: SessionId,
    channel_id: ChannelId,
    target_user_id: UserId,
    tx: &ControlTx,
) -> Result<()> {
    // Nobody reaches into a channel they cannot see, by id either
    if !state.may_reach(session_id, channel_id).await {
        channel_error(tx, "channel does not exist").await;
        return Ok(());
    }
    let manages = state.can(session_id, Powers::CHANNELS);
    let takes_a_row = match state
        .may_invite(channel_id, requester_id, target_user_id, manages)
        .await
    {
        Ok(takes_a_row) => takes_a_row,
        Err(e) => {
            channel_error(tx, e.to_string()).await;
            return Ok(());
        }
    };
    if takes_a_row {
        // By any channel: someone picked from an anonymous room's roster stays masked
        let (target, target_name) = modlog::target_of(state, target_user_id, None).await;
        let (channel_key, channel_name) = state
            .channels
            .read()
            .await
            .get(&channel_id)
            .map(|c| (c.gate_key.clone(), c.info.name.clone()))
            .unwrap_or_default();
        let row = modlog::Entry {
            action: "summon",
            target,
            target_name: &target_name,
            channel_key: &channel_key,
            channel_name: &channel_name,
            ..Default::default()
        };
        if let Err(e) = modlog::put(state, session_id, row).await {
            warn!("keeping a summon: {e:#}");
            channel_error(tx, "the invite could not be kept").await;
            return Ok(());
        }
    }
    match state
        .add_invite(channel_id, requester_id, target_user_id, manages)
        .await
    {
        Ok((channel_name, mut invited_by)) => {
            // Bound to a `let` first: in an `if let` the DashMap guard lives
            // to the end of the block, and `display_name` takes the channels
            // lock (and this shard again) while it is held.
            let target_sid = state
                .sessions
                .contains_key(&target_user_id)
                .then_some(target_user_id);
            if let Some(sid) = target_sid {
                invited_by = state.display_name(requester_id, sid).await;
            }
            // Send InviteReceived to the target user
            if let Some(session) = state.sessions.get(&target_user_id) {
                let _ = send_msg(
                    &session.control_tx,
                    &ServerMessage::InviteReceived {
                        channel_id,
                        channel_name,
                        invited_by,
                    },
                );
            }
        }
        Err(e) => {
            channel_error(tx, e.to_string()).await;
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
    _tx: &ControlTx,
) -> Result<()> {
    // The name the target may see: a poke from an anonymous channel must not
    // carry the real one
    let target_session = state
        .sessions
        .contains_key(&target_user_id)
        .then_some(target_user_id);
    let from_username = match target_session {
        Some(sid) => state.display_name(from_user_id, sid).await,
        None => String::new(),
    };
    let _ = from_session_id;

    // Relay the encrypted poke. One to an offline user is dropped silently,
    // which prevents user enumeration.
    if let Some(session) = state.sessions.get(&target_user_id) {
        let _ = send_msg(
            &session.control_tx,
            &ServerMessage::PokeReceived {
                from_user_id,
                from_username,
                ciphertext,
                message_type,
            },
        );
    }
    Ok(())
}

/// Handle a declined channel invite.
async fn handle_decline_invite(
    state: &Arc<ServerState>,
    user_id: UserId,
    channel_id: ChannelId,
) -> Result<()> {
    // Look up who asked, to notify them
    let inviter_id = {
        let channels = state.channels.read().await;
        channels
            .get(&channel_id)
            .and_then(|ch| ch.inviter_of(user_id))
    };

    // A decline for a channel nobody invited us to is a message of the
    // sender's choosing aimed at a creator of their choosing; there is nothing
    // to decline and nobody to tell.
    if !state.remove_invite(channel_id, user_id).await {
        return Ok(());
    }

    // Notify them
    if let Some(inviter_id) = inviter_id {
        if let Some(session) = state.sessions.get(&inviter_id) {
            let _ = send_msg(
                &session.control_tx,
                &ServerMessage::InviteDeclined {
                    channel_id,
                    user_id,
                },
            );
        }
    }

    Ok(())
}

// ── Moderation handlers ────────────────────────────────────────────────

/// A channel change that went through: every session that sees the channel
/// hears of it.
pub(crate) async fn channel_updated(state: &Arc<ServerState>, channel: ChannelInfo) {
    crate::layout::keep_through(state, channel.channel_id).await;
    let gate = {
        let channels = state.channels.read().await;
        channels
            .get(&channel.channel_id)
            .map(|c| c.gate.groups.clone())
            .unwrap_or_default()
    };
    let Ok(data) = encode_server_msg(&ServerMessage::ChannelUpdated { channel }) else {
        return;
    };
    for entry in state.sessions.iter() {
        if crate::gates::passes(entry.value(), &gate) {
            let _ = entry.value().control_tx.try_send(data.clone());
        }
    }
}

/// An account session this connection will not use after all: ended now,
/// rather than by the idle sweep weeks later.
async fn end_unused_sign_in(state: &ServerState, token: Option<&str>) {
    if let (Some(relay), Some(token)) = (state.accounts.as_ref(), token) {
        let _ = relay.accounts.logout(token).await;
    }
}

/// A `ChannelError` for the sender alone: what they asked for was refused.
async fn channel_error(tx: &ControlTx, reason: impl Into<String>) {
    let _ = send_msg(
        tx,
        &ServerMessage::ChannelError {
            reason: reason.into(),
        },
    );
}

pub(crate) async fn admin_error(tx: &ControlTx, reason: &str) {
    let _ = send_msg(
        tx,
        &ServerMessage::AdminError {
            reason: reason.into(),
        },
    );
}

/// Constant-time token check; the third failure closes the connection.
async fn handle_admin_login(
    state: &Arc<ServerState>,
    user_id: UserId,
    session_id: SessionId,
    token: &str,
    tx: &ControlTx,
) {
    use subtle::ConstantTimeEq;
    let (has_account, peer_ip) = state
        .sessions
        .get(&session_id)
        .map_or((false, None), |s| (s.account.is_some(), Some(s.peer_ip)));
    // Before the comparison: answering a guest differently for a right token
    // than for a wrong one confirmed the token (1.0 audit H1-09)
    if state.accounts.is_some() && !has_account {
        admin_error(tx, "sign in with an account: on this server the admin token makes an account its first admin").await;
        return;
    }
    if peer_ip.is_some_and(|ip| !state.token_guess_allowed(ip)) {
        admin_error(
            tx,
            "too many wrong admin tokens from your address; try again later",
        )
        .await;
        return;
    }
    let ok: bool = token.as_bytes().ct_eq(state.admin_token.as_bytes()).into();
    // With accounts the token is no session-long admin pass: it makes the
    // signed-in account the first admin, while there is none, and then stops
    // working. That admin's rights wait for two-factor codes like any admin's.
    if let (true, Some(relay)) = (ok, state.accounts.clone()) {
        let account = state
            .sessions
            .get(&session_id)
            .and_then(|s| s.account.as_ref().map(|a| (a.user.id, s.peer_ip)));
        let Some((account, peer_ip)) = account else {
            admin_error(tx, "sign in with an account: on this server the admin token makes an account its first admin").await;
            return;
        };
        let ctx = relay.ctx(peer_ip, APP_VERSION);
        match relay.accounts.bootstrap_grant(&ctx, account).await {
            Ok(true) => {
                info!(user_id, "admin token: account made the first admin");
                if let Err(e) = crate::accounts::refresh(state, &relay, session_id, account).await {
                    warn!(user_id, "after the admin grant: {e}");
                }
            }
            Ok(false) => {
                admin_error(
                    tx,
                    "this server has an admin account already; the token no longer works here",
                )
                .await
            }
            Err(e) => {
                warn!(user_id, "admin grant: {}", e.message());
                admin_error(tx, e.message()).await;
            }
        }
        return;
    }
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
        // Whatever the wait is set to: a row on this address held them as a guest
        crate::restrict::settle(state, session_id).await;
        crate::restrict::reasons_for(state, tx);
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
    if let Some(ip) = peer_ip {
        state.token_guess_failed(ip);
    }
    warn!(user_id, failures, "admin login failed");
    admin_error(tx, "wrong admin token").await;
    if failures >= 3 {
        force_disconnect(state, session_id, "too many failed admin logins").await;
    }
}

/// Send `Disconnected` to a session and wake its connection loop, which
/// exits and runs the normal cleanup.
pub(crate) async fn force_disconnect(state: &ServerState, session_id: SessionId, reason: &str) {
    let close = {
        let Some(session) = state.sessions.get(&session_id) else {
            return;
        };
        let _ = send_msg(
            &session.control_tx,
            &ServerMessage::Disconnected {
                reason: reason.to_string(),
            },
        );
        session.close.clone()
    };
    close.notify_one();
}

/// `force_disconnect` for someone put out, not someone who simply goes: whoever keyed them
/// starts a new chain. (A device's changed password or another sign-in tells nobody.)
pub(crate) async fn eject(state: &ServerState, session_id: SessionId, reason: &str) {
    if let Some(mut session) = state.sessions.get_mut(&session_id) {
        session.ejected = true;
    }
    force_disconnect(state, session_id, reason).await;
}

/// Who a ban says banned: the account's name, or the admin token's holder.
pub(crate) fn banned_by(state: &ServerState, session_id: SessionId) -> String {
    state
        .sessions
        .get(&session_id)
        .and_then(|s| s.account.as_ref().map(|a| a.user.username.clone()))
        .unwrap_or_else(|| "admin token".into())
}

/// What a step keeps as its reason, its row and its ban alike: Postgres refuses a NUL.
pub(crate) fn ban_reason(reason: String) -> String {
    let reason: String = reason.chars().filter(|c| !c.is_control()).collect();
    let reason: String = reason.trim().chars().take(200).collect();
    if reason.is_empty() {
        "no reason given".to_string()
    } else {
        reason
    }
}

/// Kicks `target_id`; with `ban` (`duration_secs`, 0 = permanent, and
/// whether their account goes too), bans their address first.
async fn handle_admin_kick(
    state: &Arc<ServerState>,
    admin_user_id: UserId,
    by_admin: bool,
    target_id: UserId,
    reason: String,
    ban: Option<(u32, bool)>,
    tx: &ControlTx,
) {
    if target_id == admin_user_id {
        admin_error(tx, "you cannot kick yourself").await;
        return;
    }
    let Some(target_sid) = state.sessions.contains_key(&target_id).then_some(target_id) else {
        admin_error(tx, "user not found").await;
        return;
    };
    // A moderator moderates people, not the ones who moderate.
    if !by_admin
        && state
            .sessions
            .get(&target_sid)
            .is_some_and(|s| s.is_admin || s.is_moderator)
    {
        admin_error(
            tx,
            "only an admin can kick or ban an admin or someone with privileges",
        )
        .await;
        return;
    }
    let reason = ban_reason(reason);
    let (row_target, row_name) = modlog::target_of(state, target_sid, None).await;

    let Some((duration_secs, with_account)) = ban else {
        let row = modlog::Entry {
            action: "kick",
            target: row_target,
            target_name: &row_name,
            reason: &reason,
            ..Default::default()
        };
        if let Err(e) = modlog::put(state, admin_user_id, row).await {
            warn!("keeping a kick: {e:#}");
            admin_error(tx, "the kick could not be kept").await;
            return;
        }
        info!(admin = admin_user_id, target = target_id, "admin kick");
        eject(
            state,
            target_sid,
            &format!("You were kicked from this server: {reason}"),
        )
        .await;
        return;
    };

    let Some((ip, account)) = state
        .sessions
        .get(&target_sid)
        .map(|s| (s.peer_ip, s.account.as_ref().map(|a| a.user.id.0)))
    else {
        admin_error(tx, "user not found").await;
        return;
    };
    // The name this banner may see: the ban list must not tie a pseudonym to
    // the person it hides for whoever reads the list next.
    let (real, alias) = state.names_of(target_sid).await;
    let label = crate::state::pick_name(&real, &alias, by_admin);
    let duration = (duration_secs > 0).then(|| Duration::from_secs(u64::from(duration_secs)));
    let by = banned_by(state, admin_user_id);
    let mut targets = vec![crate::bans::Target::Addr(ip)];
    if let (true, Some(a)) = (with_account, account) {
        targets.push(crate::bans::Target::Account(a));
    }
    let covers = if targets.len() > 1 {
        "address and account"
    } else {
        "address"
    };
    let row = modlog::Entry {
        action: "ban",
        target: row_target,
        target_name: &row_name,
        reason: &reason,
        detail: &modlog::ban_detail(covers, u64::from(duration_secs)),
        ..Default::default()
    };
    if let Err(e) = modlog::put(state, admin_user_id, row).await {
        warn!("keeping a ban: {e:#}");
        admin_error(tx, "the ban could not be kept").await;
        return;
    }
    for t in targets {
        let behind = alias.as_deref().filter(|_| by_admin);
        if let Err(e) = crate::bans::add_as(state, t, &label, behind, &reason, &by, duration).await
        {
            warn!("keeping a ban: {e:#}");
            admin_error(tx, "the ban could not be kept").await;
            return;
        }
    }
    info!(
        admin = admin_user_id,
        target = target_id,
        duration_secs,
        account = with_account && account.is_some(),
        "admin ban"
    );
    // The one banned goes whatever their role; then whoever else the ban
    // covers (their address, but not a role holder there)
    eject(
        state,
        target_sid,
        &format!("You were banned from this server: {reason}"),
    )
    .await;
    crate::bans::enforce(state, Some(target_sid)).await;
    if by_admin {
        let _ = send_msg(tx, &crate::bans::page(state, true, "", 0));
    }
}

/// Bans an account by name, online or not (admin only).
async fn handle_admin_ban_account(
    state: &Arc<ServerState>,
    session_id: SessionId,
    name: &str,
    reason: String,
    duration_secs: u32,
    tx: &ControlTx,
) {
    let Some(relay) = state.accounts.clone() else {
        admin_error(tx, "this server has no accounts").await;
        return;
    };
    let Ok(clean) = l4f_accounts::scope::normalize_username(name, &[]) else {
        admin_error(tx, "no account of that name").await;
        return;
    };
    let user = match relay.store().user_by_username(&clean).await {
        Ok(Some(u)) => u,
        Ok(None) => return admin_error(tx, "no account of that name").await,
        Err(e) => {
            warn!("looking an account up: {e}");
            return admin_error(tx, "the ban could not be kept").await;
        }
    };
    if state
        .sessions
        .get(&session_id)
        .and_then(|s| s.account.as_ref().map(|a| a.user.id))
        == Some(user.id)
    {
        return admin_error(tx, "you cannot ban yourself").await;
    }
    // A moderator moderates people, not the ones who moderate: by name as in a
    // kick, and here they may not even be online.
    if !state.is_admin(session_id) {
        match relay.store().user_scopes(user.id).await {
            Ok(scopes) if crate::accounts::holds_power(&scopes) => {
                return admin_error(
                    tx,
                    "only an admin can kick or ban an admin or someone with privileges",
                )
                .await;
            }
            Ok(_) => {}
            Err(e) => {
                warn!("reading an account's privileges: {e}");
                return admin_error(tx, "the ban could not be kept").await;
            }
        }
    }
    let duration = (duration_secs > 0).then(|| Duration::from_secs(u64::from(duration_secs)));
    let reason = ban_reason(reason);
    let row = modlog::Entry {
        action: "ban",
        target: Some(user.id.0),
        target_name: &user.username,
        reason: &reason,
        detail: &modlog::ban_detail("account", u64::from(duration_secs)),
        ..Default::default()
    };
    if let Err(e) = modlog::put(state, session_id, row).await {
        warn!("keeping a ban: {e:#}");
        return admin_error(tx, "the ban could not be kept").await;
    }
    if let Err(e) = crate::bans::add(
        state,
        crate::bans::Target::Account(user.id.0),
        &user.username,
        &reason,
        &banned_by(state, session_id),
        duration,
    )
    .await
    {
        warn!("keeping a ban: {e:#}");
        return admin_error(tx, "the ban could not be kept").await;
    }
    info!(admin = session_id, duration_secs, "admin account ban");
    crate::bans::enforce(state, None).await;
    let admin = state.is_admin(session_id);
    let _ = send_msg(tx, &crate::bans::page(state, admin, "", 0));
}

/// Lifts ban `id`. Only a ban the list shows, so that its row can say whose: one
/// the shell made a moment ago can be lifted once it is in the list. That name may
/// be a pseudonym, so the row never ties it to the account.
async fn handle_admin_unban(
    state: &Arc<ServerState>,
    session_id: SessionId,
    id: u64,
    tx: &ControlTx,
) {
    let ban = state.bans.iter().find(|e| e.value().id == id).map(|e| {
        let covers = match e.key() {
            crate::bans::Key::Account(_) => "account",
            crate::bans::Key::Addr(_) => "address",
        };
        (e.value().log_name().to_string(), covers)
    });
    if let Some((name, covers)) = ban {
        let row = modlog::Entry {
            action: "unban",
            target_name: &name,
            detail: covers,
            ..Default::default()
        };
        if let Err(e) = modlog::put(state, session_id, row).await {
            warn!("keeping an unban: {e:#}");
            return admin_error(tx, "the unban could not be kept").await;
        }
        match crate::bans::remove(state, id).await {
            Ok(true) => info!(session_id, id, "admin unban"),
            Ok(false) => {}
            Err(e) => warn!("lifting a ban: {e:#}"),
        }
    }
    let admin = state.is_admin(session_id);
    let _ = send_msg(tx, &crate::bans::page(state, admin, "", 0));
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
    let Some(target_sid) = state
        .sessions
        .contains_key(&target_user_id)
        .then_some(target_user_id)
    else {
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
    // Someone held would be refused the answer, so they are not asked and do not
    // pay for the encrypt.
    let serve = state
        .sessions
        .get_mut(&target_sid)
        .map(|mut s| s.shares_history && !s.silence.text() && s.history_serve_rate.try_consume())
        .unwrap_or(false);
    if !serve {
        return;
    }
    if let Some(session) = state.sessions.get(&target_sid) {
        let _ = send_msg(
            &session.control_tx,
            &ServerMessage::ChannelHistoryRequested {
                channel_id,
                from_user_id,
            },
        );
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
    // Recent chat handed to a newcomer is speech too, and only someone who shares offers it
    if state.sessions.get(&from_session_id).is_some_and(|s| {
        !s.shares_history || s.listen_only.contains(&channel_id) || s.silence.text()
    }) {
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
    if let Some(session) = state.sessions.get(&target_user_id) {
        let _ = send_msg(
            &session.control_tx,
            &ServerMessage::ChannelHistoryReceived {
                channel_id,
                from_user_id,
                from_username,
                ciphertext,
                message_type,
            },
        );
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
    tx: &ControlTx,
) -> Result<()> {
    let channel_id = state
        .sessions
        .get(&session_id)
        .map(|s| s.channel_id)
        .unwrap_or(0);

    match state
        .start_screen_share(user_id, session_id, channel_id, codec)
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
                    let _ = send_msg(&session.control_tx, &msg);
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
            );
        }
        Err(e) => {
            let _ = send_msg(
                tx,
                &ServerMessage::ScreenShareError {
                    reason: e.to_string(),
                },
            );
        }
    }
    Ok(())
}

/// Handle a screen share stop request.
pub(crate) async fn handle_stop_screen_share(
    state: &Arc<ServerState>,
    user_id: UserId,
    session_id: SessionId,
    tx: &ControlTx,
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
                        &session.control_tx,
                        &ServerMessage::StoppedWatchingScreenShare {
                            reason: "sharer_stopped".into(),
                        },
                    );
                }
            }

            // Broadcast ScreenShareStopped to all channel members
            let msg = ServerMessage::ScreenShareStopped { user_id };
            for sid in &member_sessions {
                if let Some(session) = state.sessions.get(sid) {
                    let _ = send_msg(&session.control_tx, &msg);
                }
            }
            let _ = send_msg(tx, &msg);
        }
        Err(e) => {
            let _ = send_msg(
                tx,
                &ServerMessage::ScreenShareError {
                    reason: e.to_string(),
                },
            );
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
    tx: &ControlTx,
) -> Result<()> {
    let channel_id = state
        .sessions
        .get(&viewer_session_id)
        .map(|s| s.channel_id)
        .unwrap_or(0);

    match state
        .watch_screen_share(
            viewer_user_id,
            viewer_session_id,
            sharer_user_id,
            channel_id,
        )
        .await
    {
        Ok((sharer_sid, _old_count, new_count, prev_unwatch, codec)) => {
            // Confirm to viewer, with the codec its decoder needs
            let _ = send_msg(
                tx,
                &ServerMessage::WatchingScreenShare {
                    sharer_user_id,
                    codec,
                },
            );

            // Notify the sharer of the new viewer count and get the newcomer a
            // keyframe: it would otherwise wait up to 4 s for the periodic one.
            // Capped per share like viewer requests (a burst of joiners is one
            // IDR per second, not one each). The guard is dropped before awaiting.
            let sharer = state.sessions.get_mut(&sharer_sid).map(|mut session| {
                let want_keyframe = new_count > 0 && session.keyframe_relay_rate.try_consume();
                (session.control_tx.clone(), want_keyframe)
            });
            if let Some((sharer_tx, want_keyframe)) = sharer {
                let _ = send_msg(
                    &sharer_tx,
                    &ServerMessage::ViewerCountChanged {
                        viewer_count: new_count,
                    },
                );
                if want_keyframe {
                    let _ = send_msg(&sharer_tx, &ServerMessage::KeyframeRequested);
                }
            }

            // If viewer was auto-unwatched from a previous sharer, notify that sharer
            if let Some((prev_sharer_id, prev_sharer_sid, prev_new_count)) = prev_unwatch {
                if prev_sharer_id != sharer_user_id {
                    if let Some(session) = state.sessions.get(&prev_sharer_sid) {
                        let _ = send_msg(
                            &session.control_tx,
                            &ServerMessage::ViewerCountChanged {
                                viewer_count: prev_new_count,
                            },
                        );
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
            );
        }
    }
    Ok(())
}

/// Handle a stop watching request.
async fn handle_stop_watching(
    state: &Arc<ServerState>,
    viewer_user_id: UserId,
    viewer_session_id: SessionId,
    tx: &ControlTx,
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
            );

            // Notify sharer of updated viewer count
            if let Some(session) = state.sessions.get(&sharer_sid) {
                let _ = send_msg(
                    &session.control_tx,
                    &ServerMessage::ViewerCountChanged {
                        viewer_count: new_count,
                    },
                );
            }
        }
        Err(e) => {
            let _ = send_msg(
                tx,
                &ServerMessage::ScreenShareError {
                    reason: e.to_string(),
                },
            );
        }
    }
    Ok(())
}

/// Handle a keyframe request — relay to the sharer, at most ~1/s per share
/// however many viewers ask (each relayed request forces an IDR).
async fn handle_request_keyframe(state: &Arc<ServerState>, sharer_user_id: UserId) -> Result<()> {
    let Some(sharer_sid) = state
        .sessions
        .contains_key(&sharer_user_id)
        .then_some(sharer_user_id)
    else {
        return Ok(());
    };
    relay_keyframe_request(state, sharer_sid).await;
    Ok(())
}

/// Ask a sharer for a keyframe, within the per-share budget every viewer's
/// request shares (a burst of joiners or of losses is one IDR a second).
pub(crate) async fn relay_keyframe_request(state: &ServerState, sharer_sid: SessionId) {
    let sharer_tx = match state.sessions.get_mut(&sharer_sid) {
        Some(mut session) => {
            if !session.keyframe_relay_rate.try_consume() {
                return;
            }
            session.control_tx.clone()
        }
        None => return,
    };
    let _ = send_msg(&sharer_tx, &ServerMessage::KeyframeRequested);
}

// ── E2E Encryption handler functions ──────────────────────────────────

/// Handle a pre-key bundle request — return the target user's bundle (consuming one pre-key).
async fn handle_request_prekey_bundle(
    state: &Arc<ServerState>,
    target_user_id: UserId,
    tx: &ControlTx,
) -> Result<()> {
    let msg = match take_bundle(state, target_user_id) {
        Some(bundle) => ServerMessage::PreKeyBundle {
            user_id: target_user_id,
            bundle,
        },
        None => ServerMessage::PreKeyBundleUnavailable {
            user_id: target_user_id,
        },
    };
    let _ = send_msg(tx, &msg);
    Ok(())
}

/// One bundle of `owner`'s, spending one of their one-time pre-keys, which they are told
/// to refill as the pool runs low. `None`: they are gone, or brought none.
fn take_bundle(state: &ServerState, owner: UserId) -> Option<PreKeyBundleData> {
    let (bundle, running_low) = {
        let mut session = state.sessions.get_mut(&owner)?;

        // Need the identity key and a bundle at minimum
        let (Some(identity_key), Some(b)) = (session.identity_key.clone(), session.bundle.as_mut())
        else {
            return None;
        };

        // Pop one one-time pre-key (consumed by the requester). Any of them
        // will do — a one-time pre-key has no order — and taking the last one
        // is a move instead of shifting the other 99 down on every request.
        let prekeys: Vec<OneTimePreKey> = b.prekeys.pop().into_iter().collect();
        let running_low = !prekeys.is_empty() && b.prekeys.len() == PREKEYS_LOW;

        let bundle = PreKeyBundleData {
            registration_id: b.registration_id,
            device_id: b.device_id,
            identity_key,
            signed_prekey_id: b.signed_prekey_id,
            signed_prekey: b.signed_prekey.clone(),
            signed_prekey_signature: b.signed_prekey_signature.clone(),
            prekeys,
            kyber_prekey_id: b.kyber_prekey_id,
            kyber_prekey: b.kyber_prekey.clone(),
            kyber_prekey_signature: b.kyber_prekey_signature.clone(),
        };
        (bundle, running_low.then(|| session.control_tx.clone()))
    };
    if let Some(owner) = running_low {
        let _ = send_msg(
            &owner,
            &ServerMessage::PreKeysLow {
                remaining: PREKEYS_LOW as u32,
            },
        );
    }
    Some(bundle)
}

/// Handle uploaded pre-keys — replenish the user's one-time pre-key supply.
/// Caps total stored pre-keys at 100 per user to prevent memory exhaustion.
async fn handle_upload_prekeys(
    state: &Arc<ServerState>,
    session_id: SessionId,
    prekeys: Vec<OneTimePreKey>,
) {
    if let Some(b) = state
        .sessions
        .get_mut(&session_id)
        .as_deref_mut()
        .and_then(|s| s.bundle.as_mut())
    {
        let remaining_capacity = MAX_PREKEYS.saturating_sub(b.prekeys.len());
        if remaining_capacity > 0 {
            b.prekeys.extend(
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
    tx: &ControlTx,
) -> Result<()> {
    if state
        .sessions
        .get(&from_session_id)
        .is_some_and(|s| s.silence.direct())
    {
        channel_error(tx, crate::restrict::DIRECT_HELD).await;
        return Ok(());
    }
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

    let mut delivered = false;
    if let Some(session) = state.sessions.get(&target_user_id) {
        let name = crate::state::pick_name(&real, &alias, session.is_admin);
        let _ = send_msg(&session.control_tx, &message(name));
        // A full queue is a client still here and not reading; a closed
        // one is a session on its way out
        delivered = !session.control_tx.is_closed();
    }
    // Nobody to hand it to: they left. The sender is told, or they go on
    // writing to somebody who is gone. It says nothing an id's owner did not
    // already make public by leaving — ids are never reused, and
    // RequestPreKeyBundle answers the same question.
    if !delivered {
        let _ = send_msg(
            tx,
            &ServerMessage::DirectMessageUndelivered { target_user_id },
        );
    }

    // Echo back to sender regardless of delivery success, under the name the sender
    // themselves goes by. Their app shows its own copy and reads none of this: past a
    // short one it is a sealed history answer coming back up to 48 KiB for nothing.
    if ciphertext.len() <= MAX_DM_ECHO {
        let own = crate::state::pick_name(&real, &alias, state.is_admin(from_session_id));
        let _ = send_msg(tx, &message(own));
    }

    Ok(())
}

/// Handle an encrypted channel message — relay opaquely to channel members.
async fn handle_encrypted_channel_message(
    state: &Arc<ServerState>,
    user_id: UserId,
    session_id: SessionId,
    channel_id: ChannelId,
    ciphertext: Vec<u8>,
    tx: &ControlTx,
) -> Result<()> {
    if state.sessions.get(&session_id).is_none() {
        return Ok(());
    }

    let text = state.is_text_channel(channel_id).await;
    if text {
        if ciphertext.len() > MAX_TEXT_POST {
            channel_error(tx, "message too large").await;
            return Ok(());
        }
        let bytes = ciphertext.len() as f64;
        let budget = state
            .sessions
            .get_mut(&session_id)
            .is_some_and(|mut s| s.post_bytes_rate.try_consume_n(bytes));
        if !budget {
            channel_error(tx, "sending too fast, slow down").await;
            return Ok(());
        }
    }

    // The same rules hold the channel's stored log to (accounts.rs LogAppend).
    if let Err(reason) = state
        .post_rules(
            session_id,
            user_id,
            channel_id,
            crate::state::PostStamp::Live,
        )
        .await
    {
        channel_error(tx, reason).await;
        return Ok(());
    }

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    if text {
        post_to_keyed(
            state, user_id, session_id, channel_id, ciphertext, timestamp,
        )
        .await;
        return Ok(());
    }

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
                .filter_map(|uid| state.sessions.contains_key(uid).then_some(*uid))
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
            let _ = send_msg(&session.control_tx, &msg);
        }
    }

    Ok(())
}

/// A post on the live path: to whoever its writer has been told of, so a key is always ahead
/// of its message. With what a reader would read off a roster, and the same bytes to each:
/// a text channel has no pseudonyms.
async fn post_to_keyed(
    state: &ServerState,
    user_id: UserId,
    session_id: SessionId,
    channel_id: ChannelId,
    ciphertext: Vec<u8>,
    timestamp: u64,
) {
    let readers: Vec<ControlTx> = {
        let channels = state.channels.read().await;
        let Some(channel) = channels.get(&channel_id) else {
            return;
        };
        channel
            .follow
            .last_post_ms
            .store(timestamp, std::sync::atomic::Ordering::Relaxed);
        channel
            .follow
            .readers_of(user_id)
            .into_iter()
            .filter_map(|uid| Some(state.sessions.get(&uid)?.control_tx.clone()))
            .collect()
    };
    let Some(msg) = state
        .sessions
        .get(&session_id)
        .map(|s| ServerMessage::TextPost {
            channel_id,
            user_id,
            username: s.username.clone(),
            account: s.account_id(),
            is_admin: s.is_admin,
            is_moderator: s.powers.has(Powers::CHANNELS),
            ciphertext,
            timestamp,
        })
    else {
        return;
    };
    if let Ok(data) = encode_server_msg(&msg) {
        for tx in readers {
            let _ = tx.try_send(data.clone());
        }
    }
}

/// A writer asks whom it owes its key before a post. Someone who may not post wraps
/// nothing, and hears so here as well as why: their post is waiting on this answer.
async fn handle_key_check(
    state: &Arc<ServerState>,
    user_id: UserId,
    session_id: SessionId,
    channel_id: ChannelId,
    restart: bool,
    tx: &ControlTx,
) {
    let refused = || ServerMessage::KeysOwed {
        channel_id,
        ids: Vec::new(),
        rows: Vec::new(),
        more: false,
        refused: true,
    };
    if !state.spend(session_id, |s| &mut s.key_check_rate) {
        channel_error(tx, "sending too fast, slow down").await;
        let _ = send_msg(tx, &refused());
        return;
    }
    if let Err(reason) = state
        .post_rules(
            session_id,
            user_id,
            channel_id,
            crate::state::PostStamp::Check,
        )
        .await
    {
        channel_error(tx, reason).await;
        let _ = send_msg(tx, &refused());
        return;
    }
    let Some(frames) = state.keys_owed(channel_id, user_id, restart).await else {
        let _ = send_msg(tx, &refused());
        return;
    };
    if frames.is_empty() {
        let _ = send_msg(
            tx,
            &ServerMessage::KeysOwed {
                channel_id,
                ids: Vec::new(),
                rows: Vec::new(),
                more: false,
                refused: false,
            },
        );
        return;
    }
    let last = frames.len() - 1;
    for (i, (ids, rows)) in frames.into_iter().enumerate() {
        let _ = send_msg(
            tx,
            &ServerMessage::KeysOwed {
                channel_id,
                ids,
                rows,
                more: i < last,
                refused: false,
            },
        );
    }
}

/// The reader opens the session: each of these followers gets the writer's bundle and is
/// asked to. Only someone whole: a quiet member is owed no key, and uploads nothing for one.
/// Each costs the writer a bundle token and a one-time key, and notes the pair, which is
/// the one thing a hello may then answer. Past the budget the rest are just not asked: the
/// writer tries them again, and a reader who never hears gets a ring.
async fn handle_open_sessions(
    state: &Arc<ServerState>,
    user_id: UserId,
    session_id: SessionId,
    channel_id: ChannelId,
    targets: Vec<UserId>,
    tx: &ControlTx,
) {
    if let Err(reason) = state
        .post_rules(
            session_id,
            user_id,
            channel_id,
            crate::state::PostStamp::Keys,
        )
        .await
    {
        channel_error(tx, reason).await;
        return;
    }
    let targets: Vec<UserId> = {
        let channels = state.channels.read().await;
        let Some(channel) = channels.get(&channel_id) else {
            return;
        };
        targets
            .into_iter()
            .filter(|t| *t != user_id && channel.follow.joined.contains_key(t))
            .collect()
    };
    let Some((account, name)) = state
        .sessions
        .get(&session_id)
        .map(|s| (s.account_id(), s.username.clone()))
    else {
        return;
    };
    for target in targets {
        if !state.sessions.contains_key(&target) {
            continue;
        }
        if !state.spend(session_id, |s| &mut s.prekey_bundle_rate) {
            debug!(user_id, "session opening rate limit exceeded");
            return;
        }
        let Some(bundle) = take_bundle(state, user_id) else {
            return;
        };
        if let Some(mut reader) = state.sessions.get_mut(&target) {
            reader.session_asked.insert(user_id);
            let _ = send_msg(
                &reader.control_tx,
                &ServerMessage::SessionAsked {
                    channel_id,
                    from: user_id,
                    account,
                    name: name.clone(),
                    bundle,
                },
            );
        }
    }
}

/// A follower's first message of a session it was asked to open. Goes only for that ask,
/// which it uses up: otherwise it is a way to make anyone decrypt a post-quantum handshake.
fn handle_session_hello(
    state: &ServerState,
    user_id: UserId,
    session_id: SessionId,
    to: UserId,
    message_type: u8,
    ciphertext: Vec<u8>,
) {
    let asked = state
        .sessions
        .get_mut(&session_id)
        .is_some_and(|mut s| s.session_asked.remove(&to));
    if !asked {
        debug!(user_id, "a session hello nobody asked for: dropped");
        return;
    }
    if let Some(writer) = state.sessions.get(&to) {
        let _ = send_msg(
            &writer.control_tx,
            &ServerMessage::SessionHello {
                from: user_id,
                message_type,
                ciphertext,
            },
        );
    }
}

/// A writer's sender key, wrapped for each of these: each target checked against one view
/// of the channel, and against the writer's budget for them, which is what
/// `DistributeSenderKey` does one frame at a time.
async fn handle_distribute_sender_keys(
    state: &Arc<ServerState>,
    user_id: UserId,
    session_id: SessionId,
    channel_id: ChannelId,
    keys: Vec<(UserId, u8, Vec<u8>)>,
) {
    let keys: Vec<(UserId, u8, Vec<u8>)> = {
        let channels = state.channels.read().await;
        let Some(channel) = channels
            .get(&channel_id)
            .filter(|c| c.info.text && c.members.contains(&user_id))
        else {
            return;
        };
        keys.into_iter()
            .filter(|(target, _, ciphertext)| {
                channel.follow.joined.contains_key(target)
                    && ciphertext.len() <= MAX_RELAY_CIPHERTEXT
            })
            .collect()
    };
    let (keys, account) = {
        let Some(mut session) = state.sessions.get_mut(&session_id) else {
            return;
        };
        let keys: Vec<_> = keys
            .into_iter()
            .filter(|(target, _, _)| session.may_relay_key_to(*target))
            .collect();
        (keys, session.account_id())
    };
    for (target, message_type, ciphertext) in keys {
        if let Some(session) = state.sessions.get(&target) {
            let _ = send_msg(
                &session.control_tx,
                &ServerMessage::TextKeyReceived {
                    channel_id,
                    from: user_id,
                    account,
                    message_type,
                    ciphertext,
                },
            );
        }
    }
}

/// How often exits go out. A ban across 300 channels is then one frame per writer.
pub(crate) const EXITS_EVERY_SECS: u64 = 1;
/// How often a quiet channel's news goes out.
pub(crate) const MARKS_EVERY_SECS: u64 = 60;

/// The exits queued since the last tick, each to the writer it concerns.
pub(crate) fn send_exits(state: &ServerState) {
    let due: Vec<UserId> = state.exits_due.iter().map(|e| *e.key()).collect();
    for writer in due {
        let Some((_, channels)) = state.exits_due.remove(&writer) else {
            continue;
        };
        let Some(session) = state.sessions.get(&writer) else {
            continue;
        };
        let channels: Vec<ChannelId> = channels.into_iter().collect();
        for channels in channels.chunks(10_000) {
            let _ = send_msg(
                &session.control_tx,
                &ServerMessage::ChannelExits {
                    channels: channels.to_vec(),
                },
            );
        }
    }
}

/// Quiet channels with a post since `since`, each to whoever is quiet there, only those.
/// A push, so a mark shows nothing about when an app is in front. When this ran, for the next.
pub(crate) async fn send_marks(state: &ServerState, since: u64) -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let mut marks: std::collections::HashMap<UserId, Vec<(ChannelId, u64)>> = Default::default();
    {
        let channels = state.channels.read().await;
        for channel in channels.values() {
            let at = channel
                .follow
                .last_post_ms
                .load(std::sync::atomic::Ordering::Relaxed);
            if at == 0 || at < since {
                continue;
            }
            for uid in channel.follow.quiet.keys() {
                marks
                    .entry(*uid)
                    .or_default()
                    .push((channel.info.channel_id, at));
            }
        }
    }
    for (uid, marks) in marks {
        if let Some(session) = state.sessions.get(&uid) {
            for marks in marks.chunks(4000) {
                let _ = send_msg(
                    &session.control_tx,
                    &ServerMessage::ChannelMarks {
                        marks: marks.to_vec(),
                    },
                );
            }
        }
    }
    now
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
    if let Some(session) = state.sessions.get(&target_user_id) {
        let _ = send_msg(
            &session.control_tx,
            &ServerMessage::SenderKeyReceived {
                channel_id,
                from_user_id,
                distribution_message,
                message_type,
            },
        );
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
    if let Some(session) = state.sessions.get(&target_user_id) {
        let _ = send_msg(
            &session.control_tx,
            &ServerMessage::MediaKeyReceived {
                channel_id,
                from_user_id,
                encrypted_media_key,
                message_type,
            },
        );
    }
    Ok(())
}

/// Clean up when a user disconnects.
async fn cleanup_session(state: &Arc<ServerState>, user_id: UserId, session_id: SessionId) {
    // Clean up screen share state before leaving the channel
    let (channel_id, peer_ip) = state
        .sessions
        .get(&session_id)
        .map(|s| (s.channel_id, Some(s.peer_ip)))
        .unwrap_or((0, None));
    // Its connection slot back to the pre pool, which the accept loop releases
    if let Some(ip) = peer_ip {
        state.limits.demote(ip);
    }

    if channel_id != 0 {
        cleanup_and_notify_screen_shares(state, user_id, session_id, channel_id).await;
    }

    // Text subscriptions go first: they are not the channel the session names,
    // so nothing else would ever clear them. It tells nobody.
    for (text_channel_id, remaining) in state.leave_all_text_channels(user_id).await {
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

    // Its file tickets, uploads and waits: the slot of an upload it held
    // passes to the next member with the same file
    crate::files::session_ended(state, session_id).await;
    if let Some(emotes) = &state.emotes {
        emotes.forget(session_id);
    }

    let removed = state.remove_session(session_id).await;
    // The account's l4f session ends with the connection: rows for every
    // reconnect would otherwise wait for the sweep.
    if let (Some(relay), Some(account)) = (state.accounts.clone(), removed.and_then(|s| s.account))
    {
        if let Err(e) = relay.accounts.logout(&account.token).await {
            warn!(user_id, "ending the account session: {e}");
        }
    }
    info!(user_id, session_id, "session cleaned up");
}

/// Tear down a user's screen-share state in `channel_id` (their own share
/// and/or the share they were watching) and notify everyone affected.
/// Used by every path that removes a user from a channel: leave, kick,
/// disconnect.
pub(crate) async fn cleanup_and_notify_screen_shares(
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
                &session.control_tx,
                &ServerMessage::StoppedWatchingScreenShare {
                    reason: "sharer_left".into(),
                },
            );
        }
    }

    // Broadcast ScreenShareStopped to the channel
    if let Some(sharer_uid) = cleanup.stopped_sharer_user_id {
        let msg = ServerMessage::ScreenShareStopped {
            user_id: sharer_uid,
        };
        for &sid in &cleanup.channel_member_sessions {
            if let Some(session) = state.sessions.get(&sid) {
                let _ = send_msg(&session.control_tx, &msg);
            }
        }
    }

    // Notify sharer of viewer count change (if the user was watching someone)
    if let Some((sharer_sid, new_count)) = cleanup.sharer_viewer_count_changed {
        if let Some(session) = state.sessions.get(&sharer_sid) {
            let _ = send_msg(
                &session.control_tx,
                &ServerMessage::ViewerCountChanged {
                    viewer_count: new_count,
                },
            );
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
pub(crate) async fn broadcast_to_all(
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
        let _ = session.control_tx.try_send(data.clone());
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
    let member_txs: Vec<ControlTx> = {
        let channels = state.channels.read().await;
        let Some(channel) = channels.get(&channel_id) else {
            return;
        };
        channel
            .members
            .iter()
            .filter(|&&uid| Some(uid) != exclude_user)
            .filter_map(|uid| Some(state.sessions.get(uid)?.control_tx.clone()))
            .collect()
    };
    let Ok(data) = encode_server_msg(msg)
        .inspect_err(|e| warn!("refusing to broadcast a message that cannot be framed: {e}"))
    else {
        return;
    };
    for tx in member_txs {
        let _ = tx.try_send(data.clone());
    }
}

/// Send a server message to a client's control stream.
///
/// Never awaits: callers hold DashMap shard guards (broadcasts iterate
/// `sessions`), so a client that stops reading its socket must not be able
/// to park the whole server behind its full queue. A client that cannot
/// drain 256 control messages is dead anyway.
pub(crate) fn send_msg(tx: &ControlTx, msg: &ServerMessage) -> Result<()> {
    let data = encode_server_msg(msg).inspect_err(|e| {
        // Every caller discards this Result, and for the ordinary reason —
        // a client that has stopped reading is not our problem. A message too
        // long to frame is a different thing: we built it, nobody asked for it
        // to be dropped, and the symptom at the other end is a channel list or
        // a key bundle that simply never arrives.
        warn!("refusing to send a message that cannot be framed: {e}");
    })?;
    Ok(tx.try_send(data)?)
}

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;
