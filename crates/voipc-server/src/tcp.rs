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

/// A character no user or channel name may contain: control characters, and
/// the ones that print as nothing or reorder what follows them — with those,
/// "admin\u{200B}" passes for "admin" and an RTL override turns a tag around.
/// Look-alike letters from other scripts are not caught here.
pub(crate) fn bad_name_char(c: char) -> bool {
    c.is_control()
        || matches!(c,
            '\u{00AD}'                      // soft hyphen
            | '\u{115F}' | '\u{1160}' | '\u{3164}' | '\u{FFA0}' // Hangul fillers
            | '\u{200B}'..='\u{200F}'       // zero-width space/joiners, LRM, RLM
            | '\u{202A}'..='\u{202E}'       // bidi embeddings and overrides
            | '\u{2060}'..='\u{2064}'       // word joiner, invisible operators
            | '\u{2066}'..='\u{2069}'       // bidi isolates
            | '\u{FEFF}'                    // zero-width no-break space
        )
}

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
            accounts: state.accounts.as_ref().map(|r| r.info()),
            account,
            files: state.files.as_ref().map(|f| f.limits()),
        },
    )
    .await;

    // Send channel list
    let channel_list = state.channel_list().await;
    let _ = send_msg(
        &tx,
        &ServerMessage::ChannelList {
            channels: channel_list,
        },
    )
    .await;

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
        )
        .await;
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
    cleanup.state = None;
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

/// Runs `cleanup_session` if the connection task ends without doing it
/// itself: only on a panic, since the normal path disarms it first.
struct CleanupGuard {
    state: Option<Arc<ServerState>>,
    user_id: UserId,
    session_id: SessionId,
}

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        if let Some(state) = self.state.take() {
            let (user_id, session_id) = (self.user_id, self.session_id);
            error!(
                user_id,
                session_id, "connection task ended without cleaning up; cleaning up now"
            );
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

/// The protocol version a client's first frame names, read the way every
/// version since v2 lays it out: for a client older than this server, whose
/// `Authenticate` no longer decodes, so it can still be told to update.
/// The ASCII name `name` would pass for: each character outside ASCII
/// replaced by its look-alike (UTS #39 confusables), or `None` when `name` is
/// ASCII already or holds a character with no ASCII look-alike (`ü` stays
/// `ü`, so "Jürgen" passes for nobody's account).
fn ascii_look_alike(name: &str) -> Option<String> {
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
async fn authenticate<S>(
    stream: &mut S,
    buf: &mut BytesMut,
    state: &Arc<ServerState>,
    peer_addr: &str,
    peer_ip: IpAddr,
    media_tx: mpsc::Sender<Bytes>,
    sid_tx: oneshot::Sender<SessionId>,
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

    // Protocol match only (1.0): any app version that speaks this protocol is
    // in. `app_version` still names the client to l4f (accounts.rs).
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
        if let Some(look) = ascii_look_alike(name) {
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
            .map(|s| (s.user.id.0, !s.scopes.is_empty())),
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
    let (placeholder_tx, _) = mpsc::channel(1);

    let mut session = crate::state::UserSession::new(
        user_id,
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
    session.bundle = prekey_bundle.map(|mut b| {
        b.prekeys.truncate(MAX_PREKEYS);
        b
    });
    let account = signed_in.map(|s| {
        session.account = Some(crate::state::AccountSession {
            user: s.user.clone(),
            token: s.token,
            info: s.info,
            scopes: Vec::new(),
            needs_2fa: s.account.needs_2fa,
            device_challenge: None,
        });
        session.set_scopes(s.user, s.scopes);
        s.account
    });

    // An id that is already taken means the counter wrapped
    // and came back round to a session that is still live.
    // Inserting over it would drop that connection's writer on
    // the floor and leave its loop serving somebody else's
    // state, so refuse the new connection instead: the one
    // arriving can be told to try again, the one already here
    // cannot be told anything.
    if state.sessions.contains_key(&session_id) {
        state
            .username_to_session
            .remove_if(&username_lower, |_, sid| *sid == session_id);
        if let Some(a) = &session.account {
            state
                .account_sessions
                .remove_if(&a.user.id.0, |_, sid| *sid == session_id);
        }
        end_unused_sign_in(state, session.account.as_ref().map(|a| a.token.as_str())).await;
        refuse(stream, "session id already in use, please reconnect").await?;
        anyhow::bail!("session id {} already in use", session_id);
    }
    // Out of the pre-authentication pool, which page loads and handshakes
    // share, into the one signed-in sessions use (main.rs `ConnLimits`). The
    // server may have filled up while an account signed in (1.0 audit H1-18).
    let admitted = if state.user_count() >= state.max_users as usize {
        Err("server is full")
    } else {
        state.limits.promote(peer_ip)
    };
    if let Err(reason) = admitted {
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
        anyhow::bail!("{reason}");
    }
    state.sessions.insert(session_id, session);
    state.user_to_session.insert(user_id, session_id);
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
            .map(|a| (a.user.id.0, !a.scopes.is_empty()))
    });
    if let Some(why) = crate::bans::refusal(state, peer_ip, held) {
        force_disconnect(state, session_id, &why).await;
    }
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
async fn relayable(ciphertext: &[u8], tx: &mpsc::Sender<Vec<u8>>) -> bool {
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
    tx: &mpsc::Sender<Vec<u8>>,
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
            // An invite raises a popup on the target's screen, every time it
            // is sent — the invite set dedupes, the notification does not. The
            // same budget as a poke, for the same reason.
            let allowed = state
                .sessions
                .get_mut(&session_id)
                .map(|mut s| s.chat_rate.try_consume())
                .unwrap_or(false);
            if !allowed {
                channel_error(tx, "sending too fast, slow down").await;
            } else {
                handle_send_invite(state, user_id, channel_id, target_user_id, tx).await?;
            }
        }
        ClientMessage::AcceptInvite { channel_id } => {
            // Whether there is anything to accept, read before the join spends
            // the invite. The join answers Ok whether or not it went through,
            // so without this anybody could make any creator's client say that
            // somebody of their choosing had accepted.
            let invited = {
                let channels = state.channels.read().await;
                channels
                    .get(&channel_id)
                    .is_some_and(|ch| ch.invited_users.contains(&user_id))
            };
            if !invited {
                return Ok(());
            }
            // Join with no password — validate_join will check invite set
            handle_join_channel(state, user_id, session_id, channel_id, None, tx).await?;
            // Notify the channel creator, if the join really happened
            let creator_id = {
                let channels = state.channels.read().await;
                channels
                    .get(&channel_id)
                    .filter(|ch| ch.members.contains(&user_id))
                    .and_then(|ch| ch.info.created_by)
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
                let allowed = state
                    .sessions
                    .get_mut(&session_id)
                    .map(|mut s| s.chat_rate.try_consume())
                    .unwrap_or(false);
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
            if state.can_moderate(session_id) {
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
            if state.can_moderate(session_id) {
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
        // The ban list is an admin's, never a moderator's (the 0.12 decision).
        ClientMessage::AdminUnban { id } => {
            if !state.is_admin(session_id) {
                admin_error(tx, "not an admin").await;
            } else {
                match crate::bans::remove(state, id).await {
                    Ok(true) => info!(user_id, id, "admin unban"),
                    Ok(false) => {}
                    Err(e) => warn!("lifting a ban: {e:#}"),
                }
                let _ = send_msg(
                    tx,
                    &ServerMessage::AdminBans {
                        bans: crate::bans::list(state),
                    },
                )
                .await;
            }
        }
        ClientMessage::AdminListBans => {
            if state.is_admin(session_id) {
                let _ = send_msg(
                    tx,
                    &ServerMessage::AdminBans {
                        bans: crate::bans::list(state),
                    },
                )
                .await;
            } else {
                admin_error(tx, "not an admin").await;
            }
        }
        ClientMessage::AdminBanAccount {
            name,
            reason,
            duration_secs,
        } => {
            if state.is_admin(session_id) {
                handle_admin_ban_account(state, session_id, &name, reason, duration_secs, tx).await;
            } else {
                admin_error(tx, "not an admin").await;
            }
        }

        // ── Channel history hand-off ───────────────────────────────────
        ClientMessage::RequestChannelHistory {
            channel_id,
            target_user_id,
        } => {
            let allowed = state
                .sessions
                .get_mut(&session_id)
                .map(|mut s| s.history_request_rate.try_consume())
                .unwrap_or(false);
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
                let allowed = state
                    .sessions
                    .get_mut(&session_id)
                    .map(|mut s| s.chat_rate.try_consume())
                    .unwrap_or(false);
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
            channel_error(tx, "too many password attempts, slow down").await;
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
        channel_error(tx, "joining and leaving too fast, slow down").await;
        return Ok(());
    }

    // A password for a channel from channels.json is checked against its hash
    // here, before the channel lock (Argon2 is slow)
    let checked = state.channel_password_attempt(channel_id, password).await;
    let password = checked.as_deref().map(|p| p.as_str());

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
    let _ = send_msg(tx, &ServerMessage::UserList { channel_id, users }).await;

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
        is_moderator: session.as_ref().is_some_and(|s| s.is_moderator),
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
        channel_error(tx, "joining and leaving too fast, slow down").await;
        return Ok(());
    }
    match state.leave_text_channel(user_id, channel_id).await {
        Some(remaining) => {
            // Out of its log too: what is written there from now on is not
            // for them (1.0, D10)
            crate::accounts::out_of_log(state, channel_id, session_id).await;
            crate::files::left_channel(state, session_id, channel_id);
            broadcast_user_left(state, user_id, channel_id, None).await;
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
        let account = crate::state::account_shown(
            user.account,
            roster.knows_them(session.user_id) && alias.is_none(),
            session.is_admin,
        );
        let info = UserInfo {
            username,
            user_id: roster.tell(may_name, user.user_id),
            account,
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
    tx: &mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    // Validate and sanitize name
    let name = name.trim().to_string();
    if name.is_empty() || name.len() > state.settings.max_channel_name_len {
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

    if name.chars().any(bad_name_char) {
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
    tx: &mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    let is_admin = state.can_moderate(session_id);
    let locks = password.is_some();
    match state
        .set_channel_password(channel_id, user_id, password, is_admin)
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
    tx: &mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    let is_admin = state.can_moderate(session_id);
    match state
        .set_channel_proximity(channel_id, user_id, proximity, is_admin)
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
    tx: &mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    let is_admin = state.can_moderate(session_id);
    match state
        .set_channel_options(channel_id, user_id, request, is_admin)
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
    let admin = state.is_admin(requester_session_id);
    let moderates = state.can_moderate(requester_session_id);
    // A moderator moderates people, not the ones who moderate (but still
    // has a creator's say in their own channel).
    let spared = moderates
        && !admin
        && state.user_to_session.get(&target_id).is_some_and(|sid| {
            state
                .sessions
                .get(&*sid)
                .is_some_and(|t| t.is_admin || t.is_moderator)
        });
    let is_text = state.is_text_channel(channel_id).await;
    match state
        .kick_user(channel_id, requester_id, target_id, moderates, spared)
        .await
    {
        Ok((target_session_id, remaining_count, moved)) => {
            crate::accounts::out_of_log(state, channel_id, target_session_id).await;
            crate::files::left_channel(state, target_session_id, channel_id);
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
                        reason: if admin {
                            "You were kicked from the channel by an admin".into()
                        } else if moderates {
                            "You were kicked from the channel by a moderator".into()
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
            channel_error(tx, e.to_string()).await;
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
    match state
        .add_invite(channel_id, requester_id, target_user_id)
        .await
    {
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
        channels.get(&channel_id).and_then(|ch| ch.info.created_by)
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

/// A channel change that went through: every session hears of it.
async fn channel_updated(state: &Arc<ServerState>, channel: ChannelInfo) {
    broadcast_to_all(state, &ServerMessage::ChannelUpdated { channel }, None).await;
}

/// An account session this connection will not use after all: ended now,
/// rather than by the idle sweep weeks later.
async fn end_unused_sign_in(state: &ServerState, token: Option<&str>) {
    if let (Some(relay), Some(token)) = (state.accounts.as_ref(), token) {
        let _ = relay.accounts.logout(token).await;
    }
}

/// A `ChannelError` for the sender alone: what they asked for was refused.
async fn channel_error(tx: &mpsc::Sender<Vec<u8>>, reason: impl Into<String>) {
    let _ = send_msg(
        tx,
        &ServerMessage::ChannelError {
            reason: reason.into(),
        },
    )
    .await;
}

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

/// Who a ban says banned: the account's name, or the admin token's holder.
fn banned_by(state: &ServerState, session_id: SessionId) -> String {
    state
        .sessions
        .get(&session_id)
        .and_then(|s| s.account.as_ref().map(|a| a.user.username.clone()))
        .unwrap_or_else(|| "admin token".into())
}

fn ban_reason(reason: String) -> String {
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
    // A moderator moderates people, not the ones who moderate.
    if !by_admin
        && state
            .sessions
            .get(&target_sid)
            .is_some_and(|s| s.is_admin || s.is_moderator)
    {
        admin_error(tx, "only an admin can kick or ban an admin or a moderator").await;
        return;
    }
    let reason = ban_reason(reason);

    let Some((duration_secs, with_account)) = ban else {
        info!(admin = admin_user_id, target = target_id, "admin kick");
        force_disconnect(
            state,
            target_sid,
            &format!("You were kicked from this server: {reason}"),
        )
        .await;
        return;
    };

    let Some((ip, label, account)) = state.sessions.get(&target_sid).map(|s| {
        (
            s.peer_ip,
            s.username.clone(),
            s.account.as_ref().map(|a| a.user.id.0),
        )
    }) else {
        admin_error(tx, "user not found").await;
        return;
    };
    let duration = (duration_secs > 0).then(|| Duration::from_secs(u64::from(duration_secs)));
    let by = banned_by(state, admin_user_id);
    let mut targets = vec![crate::bans::Target::Addr(ip)];
    if let (true, Some(a)) = (with_account, account) {
        targets.push(crate::bans::Target::Account(a));
    }
    for t in targets {
        if let Err(e) = crate::bans::add(state, t, &label, &reason, &by, duration).await {
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
    force_disconnect(
        state,
        target_sid,
        &format!("You were banned from this server: {reason}"),
    )
    .await;
    crate::bans::enforce(state, Some(target_sid)).await;
    if by_admin {
        let _ = send_msg(
            tx,
            &ServerMessage::AdminBans {
                bans: crate::bans::list(state),
            },
        )
        .await;
    }
}

/// Bans an account by name, online or not (admin only).
async fn handle_admin_ban_account(
    state: &Arc<ServerState>,
    session_id: SessionId,
    name: &str,
    reason: String,
    duration_secs: u32,
    tx: &mpsc::Sender<Vec<u8>>,
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
    let duration = (duration_secs > 0).then(|| Duration::from_secs(u64::from(duration_secs)));
    let reason = ban_reason(reason);
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
    let _ = send_msg(
        tx,
        &ServerMessage::AdminBans {
            bans: crate::bans::list(state),
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
async fn handle_request_keyframe(state: &Arc<ServerState>, sharer_user_id: UserId) -> Result<()> {
    let Some(sharer_sid) = state.user_to_session.get(&sharer_user_id).map(|s| *s) else {
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
            session.tcp_tx.clone()
        }
        None => return,
    };
    let _ = send_msg(&sharer_tx, &ServerMessage::KeyframeRequested).await;
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
            let _ = send_msg(
                tx,
                &ServerMessage::PreKeyBundleUnavailable {
                    user_id: target_user_id,
                },
            )
            .await;
            return Ok(());
        }
    };

    let (bundle, running_low) = {
        let mut session = match state.sessions.get_mut(&target_sid) {
            Some(s) => s,
            None => {
                let _ = send_msg(
                    tx,
                    &ServerMessage::PreKeyBundleUnavailable {
                        user_id: target_user_id,
                    },
                )
                .await;
                return Ok(());
            }
        };

        // Need the identity key and a bundle at minimum
        let (Some(identity_key), Some(b)) = (session.identity_key.clone(), session.bundle.as_mut())
        else {
            let _ = send_msg(
                tx,
                &ServerMessage::PreKeyBundleUnavailable {
                    user_id: target_user_id,
                },
            )
            .await;
            return Ok(());
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
        (bundle, running_low.then(|| session.tcp_tx.clone()))
    };
    if let Some(owner) = running_low {
        let _ = send_msg(
            &owner,
            &ServerMessage::PreKeysLow {
                remaining: PREKEYS_LOW as u32,
            },
        )
        .await;
    }

    let _ = send_msg(
        tx,
        &ServerMessage::PreKeyBundle {
            user_id: target_user_id,
            bundle,
        },
    )
    .await;

    Ok(())
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

    let mut delivered = false;
    if let Some(target_sid) = state.user_to_session.get(&target_user_id) {
        if let Some(session) = state.sessions.get(&*target_sid) {
            let name = crate::state::pick_name(&real, &alias, session.is_admin);
            let _ = send_msg(&session.tcp_tx, &message(name)).await;
            // A full queue is a client still here and not reading; a closed
            // one is a session on its way out
            delivered = !session.tcp_tx.is_closed();
        }
    }
    // Nobody to hand it to: they left. The sender is told, or they go on
    // writing to somebody who is gone. It says nothing an id's owner did not
    // already make public by leaving — ids are never reused, and
    // RequestPreKeyBundle answers the same question.
    if !delivered {
        let _ = send_msg(
            tx,
            &ServerMessage::DirectMessageUndelivered { target_user_id },
        )
        .await;
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
            )
            .await;
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
            )
            .await;
        }
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

    // Its file tickets, uploads and waits: the slot of an upload it held
    // passes to the next member with the same file
    crate::files::session_ended(state, session_id).await;

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
async fn broadcast_to_all(state: &ServerState, msg: &ServerMessage, exclude_user: Option<UserId>) {
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
pub(crate) async fn send_msg(tx: &mpsc::Sender<Vec<u8>>, msg: &ServerMessage) -> Result<()> {
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

    #[test]
    fn names_refuse_invisible_and_reordering_characters() {
        let bad = |name: &str| name.chars().any(bad_name_char);
        assert!(bad("admin\u{200B}"), "zero-width space");
        assert!(bad("Luki\u{202E}0240#"), "RTL override");
        assert!(
            bad("\u{3164}"),
            "Hangul filler, a name that prints as nothing"
        );
        assert!(bad("tab\there"), "control characters, as before");
        for fine in [
            "Luki#0420",
            "Zoë",
            "Ærøskøbing",
            "名前",
            "Ελένη",
            "a b-c_d.e",
        ] {
            assert!(!bad(fine), "{fine} must pass");
        }
    }

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
            account: None,
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
            assert!(
                self.next().await.is_none(),
                "server should close the stream"
            );
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
        let mut client = open(state, username, ip).await;
        client
            .expect("Authenticated", |m| {
                matches!(m, ServerMessage::Authenticated { .. })
            })
            .await;
        client
    }

    /// Why the server turned `username` away.
    async fn refusal(state: &Arc<ServerState>, username: &str) -> String {
        let mut client = open(state, username, IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
        match client.next().await {
            Some(ServerMessage::AuthError { reason }) => reason,
            other => panic!("{username} was not refused: {other:?}"),
        }
    }

    /// Sends the `Authenticate` for `username` from `ip`, and no more.
    async fn open(state: &Arc<ServerState>, username: &str, ip: IpAddr) -> Client {
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
                account: None,
            })
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
            .expect("ChannelCreated", |m| {
                matches!(m, ServerMessage::ChannelCreated { .. })
            })
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
        assert_eq!(
            names,
            vec!["General".to_string()],
            "the orphan stayed behind"
        );
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
        let mut client = Client {
            stream,
            handler,
            buf: BytesMut::new(),
        };
        client
            .send(&ClientMessage::Authenticate {
                username: "mallory".into(),
                protocol_version: PROTOCOL_VERSION,
                app_version: APP_VERSION.to_string(),
                identity_key: None,
                prekey_bundle: Some(PreKeyBundleData {
                    identity_key: vec![0u8; 60_000],
                    ..test_bundle(0)
                }),
                account: None,
            })
            .await;
        client
            .expect("AuthError", |m| {
                matches!(m, ServerMessage::AuthError { .. })
            })
            .await;
        assert_eq!(state.user_count(), 0, "the session was registered anyway");
    }

    /// ...and the same bound on the ones uploaded later, which arrive by
    /// another door and used to be counted but not measured.
    #[tokio::test]
    async fn an_oversized_uploaded_prekey_is_not_stored() {
        let state = admin_state();
        let (mut alice, _) = connect_with_bundle(&state, "alice", test_bundle(0)).await;
        alice
            .send(&ClientMessage::UploadPreKeys {
                prekeys: vec![
                    OneTimePreKey {
                        id: 1,
                        public_key: vec![0u8; 33],
                    },
                    OneTimePreKey {
                        id: 2,
                        public_key: vec![0u8; 60_000],
                    },
                ],
            })
            .await;
        // Answered by nothing, so measure it against a round trip that is.
        alice.send(&ClientMessage::Ping { timestamp: 7 }).await;
        alice
            .expect("Pong", |m| matches!(m, ServerMessage::Pong { .. }))
            .await;

        let session = state.sessions.get(&1).unwrap();
        let prekeys = &session.bundle.as_ref().unwrap().prekeys;
        assert_eq!(prekeys.len(), 1, "the oversized key was stored");
        assert_eq!(prekeys[0].id, 1);
    }

    /// H1-08: a connection task that ends without its own cleanup (a panic)
    /// still takes its session out, through the guard.
    #[tokio::test]
    async fn a_connection_task_that_dies_still_cleans_up() {
        let state = admin_state();
        let _alice = connect(&state, "alice", IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
        assert_eq!(state.user_count(), 1);
        drop(CleanupGuard {
            state: Some(state.clone()),
            user_id: 1,
            session_id: 1,
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            while state.user_count() > 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the session was cleaned up");
    }

    /// A bundle with `n` one-time keys and a Kyber key of the real size.
    fn test_bundle(n: u32) -> PreKeyBundleData {
        PreKeyBundleData {
            registration_id: 1,
            device_id: 1,
            identity_key: vec![5u8; 33],
            signed_prekey_id: 1,
            signed_prekey: vec![0u8; 33],
            signed_prekey_signature: vec![0u8; 64],
            prekeys: (1..=n)
                .map(|id| OneTimePreKey {
                    id,
                    public_key: vec![id as u8; 33],
                })
                .collect(),
            kyber_prekey_id: 1,
            kyber_prekey: vec![7u8; MAX_KEM_KEY_BYTES],
            kyber_prekey_signature: vec![9u8; 64],
        }
    }

    /// Authenticates `username` with `bundle`; the client and its user id.
    async fn connect_with_bundle(
        state: &Arc<ServerState>,
        username: &str,
        bundle: PreKeyBundleData,
    ) -> (Client, UserId) {
        let (stream, server) = tokio::io::duplex(65536);
        let (media_tx, _media_rx) = mpsc::channel(8);
        let (sid_tx, _sid_rx) = oneshot::channel();
        let handler = tokio::spawn(handle_connection(
            server,
            username.into(),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
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
                identity_key: Some(bundle.identity_key.clone()),
                prekey_bundle: Some(bundle),
                account: None,
            })
            .await;
        let ServerMessage::Authenticated { user_id, .. } = client
            .expect("Authenticated", |m| {
                matches!(m, ServerMessage::Authenticated { .. })
            })
            .await
        else {
            unreachable!()
        };
        (client, user_id)
    }

    /// The Kyber key goes to whoever asks, with one one-time key; the owner is
    /// asked for more once, when the pool reaches the low mark.
    #[tokio::test]
    async fn a_bundle_carries_the_kyber_key_and_a_low_pool_asks_for_more() {
        let state = admin_state();
        let (mut alice, alice_id) =
            connect_with_bundle(&state, "alice", test_bundle(PREKEYS_LOW as u32 + 1)).await;
        let (mut bob, _) = connect_with_bundle(&state, "bob", test_bundle(0)).await;

        bob.send(&ClientMessage::RequestPreKeyBundle {
            target_user_id: alice_id,
        })
        .await;
        let ServerMessage::PreKeyBundle { bundle, .. } = bob
            .expect("PreKeyBundle", |m| {
                matches!(m, ServerMessage::PreKeyBundle { .. })
            })
            .await
        else {
            unreachable!()
        };
        assert_eq!(bundle.prekeys.len(), 1);
        assert_eq!(
            (
                bundle.kyber_prekey_id,
                bundle.kyber_prekey.len(),
                bundle.kyber_prekey_signature.len()
            ),
            (1, MAX_KEM_KEY_BYTES, 64)
        );
        alice.expect("PreKeysLow", |m| matches!(m, ServerMessage::PreKeysLow { remaining } if *remaining == PREKEYS_LOW as u32)).await;

        // Below the mark: no second ask
        bob.send(&ClientMessage::RequestPreKeyBundle {
            target_user_id: alice_id,
        })
        .await;
        bob.expect("PreKeyBundle", |m| {
            matches!(m, ServerMessage::PreKeyBundle { .. })
        })
        .await;
        alice.send(&ClientMessage::Ping { timestamp: 1 }).await;
        let next = alice
            .expect("Pong or PreKeysLow", |m| {
                matches!(
                    m,
                    ServerMessage::Pong { .. } | ServerMessage::PreKeysLow { .. }
                )
            })
            .await;
        assert!(
            matches!(next, ServerMessage::Pong { .. }),
            "asked again: {next:?}"
        );
    }

    /// A Kyber key larger than Kyber1024 is refused at the door like any key.
    #[test]
    fn an_oversized_kyber_key_is_refused() {
        let b = PreKeyBundleData {
            kyber_prekey: vec![0u8; MAX_KEM_KEY_BYTES + 1],
            ..test_bundle(0)
        };
        assert!(!bundle_is_sane(&b));
        assert!(bundle_is_sane(&test_bundle(3)));
    }

    /// H1-09: wrong admin tokens are counted per address, not per session, so
    /// reconnecting does not buy more guesses; once spent, even the right
    /// token is refused for a while.
    #[tokio::test]
    async fn wrong_admin_tokens_are_counted_per_address() {
        let state = admin_state();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
        for round in 0..4 {
            let mut c = connect(&state, &format!("g{round}"), ip).await;
            for _ in 0..3 {
                c.send(&ClientMessage::AdminLogin {
                    token: "wrong-wrong-wrong".into(),
                })
                .await;
                c.expect("AdminError", |m| {
                    matches!(m, ServerMessage::AdminError { .. })
                })
                .await;
            }
        }
        let mut c = connect(&state, "last", ip).await;
        c.send(&ClientMessage::AdminLogin {
            token: "test-admin-token".into(),
        })
        .await;
        let ServerMessage::AdminError { reason } = c
            .expect("AdminError", |m| {
                matches!(m, ServerMessage::AdminError { .. })
            })
            .await
        else {
            unreachable!()
        };
        assert!(reason.contains("too many wrong"), "{reason}");
        // Somebody else's address has its own budget
        let mut other = connect(&state, "other", IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10))).await;
        other
            .send(&ClientMessage::AdminLogin {
                token: "test-admin-token".into(),
            })
            .await;
        other
            .expect("AdminStatus", |m| {
                matches!(m, ServerMessage::AdminStatus { is_admin: true, .. })
            })
            .await;
    }

    #[tokio::test]
    async fn admin_login_ban_and_unban() {
        let state = admin_state();
        let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let far = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        let mut alice = connect(&state, "alice", lo).await; // user 1
        let mut bob = connect(&state, "bob", far).await; // user 2

        // Not an admin: refused
        bob.send(&ClientMessage::AdminKick {
            user_id: 1,
            reason: String::new(),
        })
        .await;
        bob.expect("AdminError", |m| {
            matches!(m, ServerMessage::AdminError { .. })
        })
        .await;

        // Wrong token, then the right one; everyone learns about the login
        alice
            .send(&ClientMessage::AdminLogin {
                token: "nope".into(),
            })
            .await;
        alice
            .expect("AdminError", |m| {
                matches!(m, ServerMessage::AdminError { .. })
            })
            .await;
        alice
            .send(&ClientMessage::AdminLogin {
                token: "test-admin-token".into(),
            })
            .await;
        let is_login = |m: &ServerMessage| {
            matches!(
                m,
                ServerMessage::AdminStatus {
                    user_id: 1,
                    is_admin: true
                }
            )
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
                account: true,
            })
            .await;
        let gone = bob
            .expect("Disconnected", |m| {
                matches!(m, ServerMessage::Disconnected { .. })
            })
            .await;
        assert!(matches!(gone, ServerMessage::Disconnected { reason } if reason.contains("spam")));
        bob.assert_closed().await;
        assert!(crate::bans::refused_at_accept(&state, far));
        assert!(!crate::bans::refused_at_accept(&state, lo));
        assert_eq!(state.sessions.len(), 1);
        let bans = alice
            .expect("AdminBans", |m| {
                matches!(m, ServerMessage::AdminBans { .. })
            })
            .await;
        let ServerMessage::AdminBans { bans } = bans else {
            unreachable!()
        };
        assert_eq!(bans.len(), 1, "a guest has no account to ban");
        assert!(
            !bans[0].account
                && bans[0].label == "bob"
                && bans[0].reason == "spam"
                && bans[0].by == "admin token",
            "{bans:?}"
        );
        assert!(
            format!("{bans:?}").find("10.0.0.5").is_none(),
            "the list names no address"
        );

        // Unban
        alice
            .send(&ClientMessage::AdminUnban { id: bans[0].id })
            .await;
        let bans = alice
            .expect("AdminBans", |m| {
                matches!(m, ServerMessage::AdminBans { .. })
            })
            .await;
        assert!(matches!(&bans, ServerMessage::AdminBans { bans } if bans.is_empty()));
        assert!(!crate::bans::refused_at_accept(&state, far));
    }

    #[tokio::test]
    async fn three_failed_admin_logins_disconnect() {
        let state = admin_state();
        let mut dave = connect(&state, "dave", IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
        for _ in 0..3 {
            dave.send(&ClientMessage::AdminLogin {
                token: "wrong".into(),
            })
            .await;
            dave.expect("AdminError", |m| {
                matches!(m, ServerMessage::AdminError { .. })
            })
            .await;
        }
        dave.expect("Disconnected", |m| {
            matches!(m, ServerMessage::Disconnected { .. })
        })
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
            .send(&ClientMessage::CreateChannel {
                name: "room".into(),
                password: None,
                proximity: ProximityMode::Off,
                anonymous: false,
                text: false,
            })
            .await;
        let created = alice
            .expect("ChannelCreated", |m| {
                matches!(m, ServerMessage::ChannelCreated { .. })
            })
            .await;
        let ServerMessage::ChannelCreated { channel } = created else {
            unreachable!()
        };
        let channel_id = channel.channel_id;
        bob.send(&ClientMessage::JoinChannel {
            channel_id,
            password: None,
        })
        .await;
        bob.expect(
            "UserList",
            |m| matches!(m, ServerMessage::UserList { channel_id: c, .. } if *c == channel_id),
        )
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
                ServerMessage::WatchingScreenShare {
                    sharer_user_id: 1,
                    codec: VideoCodec::Vp9
                }
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
            .send(&ClientMessage::CreateChannel {
                name: "room".into(),
                password: None,
                proximity: ProximityMode::Off,
                anonymous: false,
                text: false,
            })
            .await;
        let ServerMessage::ChannelCreated { channel: voice } = alice
            .expect("ChannelCreated", |m| {
                matches!(m, ServerMessage::ChannelCreated { .. })
            })
            .await
        else {
            unreachable!()
        };
        alice
            .expect("UserList for the voice room", |m| {
                matches!(m, ServerMessage::UserList { channel_id: c, .. } if *c == voice.channel_id)
            })
            .await;

        bob.send(&ClientMessage::CreateChannel {
            name: "lounge".into(),
            password: None,
            proximity: ProximityMode::Off,
            anonymous: false,
            text: true,
        })
        .await;
        let ServerMessage::ChannelCreated { channel: text } = bob
            .expect(
                "ChannelCreated",
                |m| matches!(m, ServerMessage::ChannelCreated { channel } if channel.text),
            )
            .await
        else {
            unreachable!()
        };
        bob.expect(
            "UserList for the text channel",
            |m| matches!(m, ServerMessage::UserList { channel_id: c, .. } if *c == text.channel_id),
        )
        .await;
        // Creating a text channel did not move bob out of the lobby
        assert_eq!(state.sessions.get(&2).unwrap().channel_id, 0);

        alice
            .send(&ClientMessage::JoinChannel {
                channel_id: text.channel_id,
                password: None,
            })
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
            .expect("ChannelError", |m| {
                matches!(m, ServerMessage::ChannelError { .. })
            })
            .await;
        assert!(
            matches!(refused, ServerMessage::ChannelError { reason } if reason.contains("not in"))
        );

        // Leaving is its own message, and everybody hears about it
        alice
            .send(&ClientMessage::LeaveChannel {
                channel_id: text.channel_id,
            })
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
            .send(&ClientMessage::LeaveChannel {
                channel_id: voice.channel_id,
            })
            .await;
        let refused = alice
            .expect("ChannelError", |m| {
                matches!(m, ServerMessage::ChannelError { .. })
            })
            .await;
        assert!(
            matches!(refused, ServerMessage::ChannelError { reason } if reason.contains("text channel"))
        );
        assert_eq!(state.sessions.get(&1).unwrap().channel_id, voice.channel_id);
    }

    /// An announcement channel takes posts only from its managers, and slow
    /// mode holds everybody else to one post per interval — both decided by
    /// the relay from who posts where and when, without reading a word.
    #[tokio::test]
    async fn announce_and_slow_mode_hold_back_members_but_not_managers() {
        let state = admin_state();
        let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut alice = connect(&state, "alice", lo).await; // user 1
        let mut bob = connect(&state, "bob", lo).await; // user 2

        // bob's text channel, so bob is its creator and manages it
        bob.send(&ClientMessage::CreateChannel {
            name: "news".into(),
            password: None,
            proximity: ProximityMode::Off,
            anonymous: false,
            text: true,
        })
        .await;
        let ServerMessage::ChannelCreated { channel } = bob
            .expect("ChannelCreated", |m| {
                matches!(m, ServerMessage::ChannelCreated { .. })
            })
            .await
        else {
            unreachable!()
        };
        let news = channel.channel_id;
        alice
            .send(&ClientMessage::JoinChannel {
                channel_id: news,
                password: None,
            })
            .await;
        alice
            .expect(
                "UserList for news",
                |m| matches!(m, ServerMessage::UserList { channel_id: c, .. } if *c == news),
            )
            .await;

        let set = |announce: Option<bool>, slow_mode_secs: Option<u32>| {
            ClientMessage::SetChannelOptions {
                channel_id: news,
                options: ChannelOptions {
                    announce,
                    slow_mode_secs,
                    ..Default::default()
                },
            }
        };
        let post = |byte: u8| ClientMessage::SendEncryptedChannelMessage {
            channel_id: news,
            ciphertext: vec![byte],
        };
        let is_post = |byte: u8| move |m: &ServerMessage| matches!(m, ServerMessage::EncryptedChannelChatMessage { ciphertext, .. } if ciphertext == &vec![byte]);
        let is_refusal = |what: &'static str| move |m: &ServerMessage| matches!(m, ServerMessage::ChannelError { reason } if reason.contains(what));

        // Announcements: alice is refused, the creator gets through
        bob.send(&set(Some(true), None)).await;
        bob.expect(
            "ChannelUpdated",
            |m| matches!(m, ServerMessage::ChannelUpdated { channel } if channel.announce),
        )
        .await;
        alice.send(&post(1)).await;
        alice
            .expect("announce refusal", is_refusal("only moderators"))
            .await;
        bob.send(&post(2)).await;
        alice.expect("bob's announcement", is_post(2)).await;

        // Slow mode: one post from alice, the next one too soon is refused
        bob.send(&set(Some(false), Some(60))).await;
        bob.expect("ChannelUpdated", |m| {
            matches!(m, ServerMessage::ChannelUpdated { channel } if !channel.announce && channel.slow_mode_secs == 60)
        })
        .await;
        alice.send(&post(3)).await;
        alice.send(&post(4)).await;
        alice
            .expect("slow mode refusal", is_refusal("slow mode"))
            .await;
        // The first post bob gets from alice is 3, so 1 never left the relay
        let got = bob
            .expect("a post", |m| {
                matches!(m, ServerMessage::EncryptedChannelChatMessage { .. })
            })
            .await;
        assert!(
            is_post(3)(&got),
            "a refused announcement was relayed: {got:?}"
        );

        // The creator is not held back, nor is a moderator
        bob.send(&post(5)).await;
        bob.send(&post(6)).await;
        alice.expect("bob's first post", is_post(5)).await;
        alice.expect("bob's second post", is_post(6)).await;
        state.sessions.get_mut(&1).unwrap().is_moderator = true;
        alice.send(&post(7)).await;
        // ...and the next one is 7, so 4 did not either
        let got = bob
            .expect("a post", |m| {
                matches!(m, ServerMessage::EncryptedChannelChatMessage { .. })
            })
            .await;
        assert!(
            is_post(7)(&got),
            "a post refused by slow mode was relayed: {got:?}"
        );
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
                matches!(
                    m,
                    ServerMessage::UserHistorySharing {
                        user_id: 1,
                        enabled: true
                    }
                )
            })
            .await;
        bob.expect("UserHistorySharing", |m| {
            matches!(
                m,
                ServerMessage::UserHistorySharing {
                    user_id: 1,
                    enabled: true
                }
            )
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
            matches!(
                m,
                ServerMessage::UserHistorySharing {
                    user_id: 1,
                    enabled: false
                }
            )
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
            .expect(
                "ChannelCreated",
                |m| matches!(m, ServerMessage::ChannelCreated { channel } if channel.text),
            )
            .await
        else {
            unreachable!()
        };
        let channel_id = channel.channel_id;
        owner
            .expect(
                "UserList",
                |m| matches!(m, ServerMessage::UserList { channel_id: c, .. } if *c == channel_id),
            )
            .await;
        other
            .send(&ClientMessage::JoinChannel {
                channel_id,
                password: None,
            })
            .await;
        other
            .expect(
                "UserList",
                |m| matches!(m, ServerMessage::UserList { channel_id: c, .. } if *c == channel_id),
            )
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
            .expect("ChannelError", |m| {
                matches!(m, ServerMessage::ChannelError { .. })
            })
            .await;
        assert!(
            matches!(refused, ServerMessage::ChannelError { reason } if reason.contains("too large"))
        );

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

    /// A name is unique together with its tag, not on its own: two people can
    /// both be alice as long as their tags differ. The tag rides on top of the
    /// 32 bytes a name may have, and only a real tag does.
    #[tokio::test]
    async fn a_tag_lets_two_people_share_a_name() {
        let state = admin_state();
        let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let _first = connect(&state, "alice#0001", lo).await;
        let _second = connect(&state, "alice#0002", lo).await;
        let _longest = connect(&state, &format!("{}#1234", "x".repeat(32)), lo).await;

        assert!(refusal(&state, "ALICE#0001").await.contains("taken"));
        assert!(refusal(&state, &"x".repeat(33)).await.contains("1-32"));
        // Five digits are no tag, so all of it is the name
        assert!(refusal(&state, &format!("{}#12345", "x".repeat(32)))
            .await
            .contains("1-32"));
        assert!(refusal(&state, "#0001").await.contains("1-32"));
    }

    /// A direct message to somebody who has left used to vanish: the server
    /// dropped it, and the sender's client had already shown it as sent. The
    /// sender is told now, and only then.
    #[tokio::test]
    async fn a_direct_message_to_somebody_who_left_is_answered() {
        let state = admin_state();
        let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut alice = connect(&state, "alice", lo).await; // user 1
        let bob = connect(&state, "bob", lo).await; // user 2
        let dm = ClientMessage::SendEncryptedDirectMessage {
            target_user_id: 2,
            ciphertext: vec![1, 2, 3],
            message_type: 2,
        };
        let answer = |m: &ServerMessage| {
            matches!(
                m,
                ServerMessage::EncryptedDirectChatMessage { .. }
                    | ServerMessage::DirectMessageUndelivered { .. }
            )
        };

        // Delivered: the echo comes back, with no "undelivered" ahead of it
        alice.send(&dm).await;
        let got = alice.expect("the echo", answer).await;
        assert!(matches!(
            got,
            ServerMessage::EncryptedDirectChatMessage { to_user_id: 2, .. }
        ));

        drop(bob);
        tokio::time::timeout(Duration::from_secs(5), async {
            while state.user_to_session.contains_key(&2) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("bob's session is cleaned up");

        alice.send(&dm).await;
        let got = alice.expect("the answer", answer).await;
        assert!(matches!(
            got,
            ServerMessage::DirectMessageUndelivered { target_user_id: 2 }
        ));
    }

    /// An `AcceptInvite` for a channel that never invited you joined nothing,
    /// and used to tell the channel's creator you had accepted all the same.
    #[tokio::test]
    async fn an_acceptance_without_an_invite_reaches_nobody() {
        let state = admin_state();
        let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut alice = connect(&state, "alice", lo).await;
        let mut bob = connect(&state, "bob", lo).await; // user 2
        alice
            .send(&ClientMessage::CreateChannel {
                name: "Room".into(),
                password: Some("pw".into()),
                proximity: ProximityMode::Off,
                anonymous: false,
                text: false,
            })
            .await;
        let created = alice
            .expect("ChannelCreated", |m| {
                matches!(m, ServerMessage::ChannelCreated { .. })
            })
            .await;
        let ServerMessage::ChannelCreated { channel } = created else {
            unreachable!()
        };
        let room = channel.channel_id;
        let pong = |m: &ServerMessage| {
            matches!(
                m,
                ServerMessage::Pong { .. } | ServerMessage::InviteAccepted { .. }
            )
        };

        // Uninvited: bob's handler is done with it once his Pong is back, and
        // anything it sent alice is then queued ahead of hers
        bob.send(&ClientMessage::AcceptInvite { channel_id: room })
            .await;
        bob.send(&ClientMessage::Ping { timestamp: 1 }).await;
        bob.expect("Pong", |m| matches!(m, ServerMessage::Pong { .. }))
            .await;
        alice.send(&ClientMessage::Ping { timestamp: 2 }).await;
        let got = alice.expect("Pong", pong).await;
        assert!(
            matches!(got, ServerMessage::Pong { .. }),
            "fake acceptance: {got:?}"
        );

        // Invited: the acceptance does go through
        alice
            .send(&ClientMessage::SendInvite {
                channel_id: room,
                target_user_id: 2,
            })
            .await;
        bob.expect("InviteReceived", |m| {
            matches!(m, ServerMessage::InviteReceived { .. })
        })
        .await;
        bob.send(&ClientMessage::AcceptInvite { channel_id: room })
            .await;
        let got = alice.expect("InviteAccepted", pong).await;
        assert!(matches!(
            got,
            ServerMessage::InviteAccepted { user_id: 2, .. }
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
            .expect("ChannelCreated", |m| {
                matches!(m, ServerMessage::ChannelCreated { .. })
            })
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
        let ServerMessage::UserJoined { user } = joined else {
            unreachable!()
        };
        assert_eq!(user.user_id, 0, "an outsider was told who joined");
        assert_eq!(user.username, "");

        // And the same on the way out.
        alice
            .send(&ClientMessage::JoinChannel {
                channel_id: 0,
                password: None,
            })
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
        let ServerMessage::UserJoined { user } = joined else {
            unreachable!()
        };
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
            .expect("ChannelCreated", |m| {
                matches!(m, ServerMessage::ChannelCreated { .. })
            })
            .await
        else {
            unreachable!()
        };
        let joined = bob
            .expect("UserJoined", |m| {
                matches!(m, ServerMessage::UserJoined { user } if user.channel_id == channel.channel_id)
            })
            .await;
        let ServerMessage::UserJoined { user } = joined else {
            unreachable!()
        };
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
            .expect("ChannelCreated", |m| {
                matches!(m, ServerMessage::ChannelCreated { .. })
            })
            .await
        else {
            unreachable!()
        };
        alice
            .send(&ClientMessage::SetChannelOptions {
                channel_id: channel.channel_id,
                options: ChannelOptions {
                    routed: Some(true),
                    ..Default::default()
                },
            })
            .await;
        alice
            .expect(
                "ChannelUpdated",
                |m| matches!(m, ServerMessage::ChannelUpdated { channel: c } if c.routed),
            )
            .await;

        // One update per player the game moved past, at the documented rate.
        // The last one is the one that has to be in force.
        for speaker in 1..=20u32 {
            alice
                .send(&ClientMessage::SetAudioFilter {
                    allow: Some(vec![speaker]),
                })
                .await;
        }
        // Driven by a message that must come back, so the filters ahead of it
        // have all been handled rather than merely sent.
        alice.send(&ClientMessage::Ping { timestamp: 1 }).await;
        alice
            .expect("Pong", |m| {
                matches!(m, ServerMessage::Pong { timestamp: 1 })
            })
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
            .send(&ClientMessage::JoinChannel {
                channel_id,
                password: None,
            })
            .await;
        carol
            .expect(
                "UserList",
                |m| matches!(m, ServerMessage::UserList { channel_id: c, .. } if *c == channel_id),
            )
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
            .send(&ClientMessage::RequestChannelHistory {
                channel_id,
                target_user_id: 2,
            })
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
            matches!(
                m,
                ServerMessage::UserHistorySharing {
                    user_id: 2,
                    enabled: true
                }
            )
        })
        .await;
        alice
            .send(&ClientMessage::RequestChannelHistory {
                channel_id,
                target_user_id: 2,
            })
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
        crate::bans::add(
            &state,
            crate::bans::Target::Addr(ip),
            "x",
            "r",
            "admin token",
            Some(Duration::from_secs(1)),
        )
        .await
        .unwrap();
        assert!(crate::bans::refused_at_accept(&state, ip));
        tokio::time::sleep(Duration::from_millis(2100)).await;
        assert!(!crate::bans::refused_at_accept(&state, ip));
        assert!(crate::bans::list(&state).is_empty());
        crate::bans::add(
            &state,
            crate::bans::Target::Addr(ip),
            "x",
            "r",
            "admin token",
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            crate::bans::list(&state)[0].expires_in_secs,
            None,
            "permanent"
        );
    }

    /// A relay without accounts keeps its bans in bans.json, with the plain
    /// addresses, and reads them again after a restart. An IPv6 ban covers
    /// the /64.
    #[tokio::test]
    async fn bans_outlive_a_restart_without_accounts() {
        let path = std::env::temp_dir().join(format!(
            "voipc-bans-{}.json",
            hex::encode(rand::random::<[u8; 8]>())
        ));
        let mut first = ServerState::new(
            &ServerConfig::default(),
            ServerSettings::default(),
            Vec::new(),
            "test-admin-token".into(),
        );
        first.bans_file = Some(path.clone());
        let v6: IpAddr = "2001:db8:1:2::77".parse().unwrap();
        crate::bans::add(
            &first,
            crate::bans::Target::Addr(v6),
            "eve#0001",
            "spam",
            "admin token",
            None,
        )
        .await
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let mut second = ServerState::new(
            &ServerConfig::default(),
            ServerSettings::default(),
            Vec::new(),
            "test-admin-token".into(),
        );
        second.bans_file = Some(path.clone());
        crate::bans::load(&second).await.unwrap();
        assert!(
            crate::bans::refused_at_accept(&second, "2001:db8:1:2:ffff::1".parse().unwrap()),
            "the same /64"
        );
        assert!(
            !crate::bans::refused_at_accept(&second, "2001:db8:1:3::77".parse().unwrap()),
            "another /64"
        );
        let id = crate::bans::list(&second)[0].id;
        assert!(crate::bans::remove(&second, id).await.unwrap());
        crate::bans::load(&first).await.unwrap();
        assert!(
            !crate::bans::refused_at_accept(&first, v6),
            "lifted in the file, so for the other reader too"
        );
        let _ = std::fs::remove_file(&path);
    }

    // ── Accounts ───────────────────────────────────────────────────────

    use crate::config::{AccountsMode, RegistrationMode};
    use voipc_protocol::messages::{AccountReply, AccountRequest, AuthContinue};

    const SECRET: [u8; 32] = [7; 32];
    const IDENTITY: [u8; 33] = [5; 33];

    /// A SQLite file in the temp dir, removed with its WAL when dropped. A file
    /// rather than `:memory:`, as a relay runs: the boot lock's connection
    /// leaves the pool for good, and an in-memory database dies with the last
    /// connection to it.
    struct TempDb(std::path::PathBuf);

    impl Drop for TempDb {
        fn drop(&mut self) {
            for suffix in ["", "-wal", "-shm", ".lock"] {
                let _ = std::fs::remove_file(format!("{}{suffix}", self.0.display()));
            }
        }
    }

    /// A relay with accounts on a fresh SQLite database.
    async fn relay_state(
        mode: AccountsMode,
        registration: RegistrationMode,
    ) -> (Arc<ServerState>, TempDb) {
        relay_state_then(mode, registration, |_| {}).await
    }

    /// `relay_state`, with `then` done to the state before it is shared.
    async fn relay_state_then(
        mode: AccountsMode,
        registration: RegistrationMode,
        then: impl FnOnce(&mut ServerState),
    ) -> (Arc<ServerState>, TempDb) {
        let mut config = ServerConfig::default();
        config.accounts.mode = mode;
        config.accounts.registration = registration;
        let db = TempDb(std::env::temp_dir().join(format!(
            "voipc-relay-{}.db",
            hex::encode(rand::random::<[u8; 8]>())
        )));
        let store = l4f_accounts::store::Store::connect(&format!("sqlite://{}", db.0.display()))
            .await
            .unwrap();
        let relay = crate::accounts::Relay::open_with(&config.accounts, store, &[9u8; 32])
            .await
            .unwrap();
        let mut state = ServerState::new(
            &config,
            ServerSettings::default(),
            Vec::new(),
            "test-admin-token".into(),
        );
        state.accounts = Some(Arc::new(relay));
        then(&mut state);
        (Arc::new(state), db)
    }

    fn bundle() -> PreKeyBundleData {
        PreKeyBundleData {
            registration_id: 1,
            device_id: 1,
            identity_key: IDENTITY.to_vec(),
            signed_prekey_id: 1,
            signed_prekey: vec![0u8; 33],
            signed_prekey_signature: vec![0u8; 64],
            prekeys: Vec::new(),
            kyber_prekey_id: 1,
            kyber_prekey: vec![0u8; 1569],
            kyber_prekey_signature: vec![0u8; 64],
        }
    }

    fn keys(identity: &[u8], reset_identity: bool) -> ClientMessage {
        ClientMessage::AuthContinue(AuthContinue::Keys {
            identity_key: identity.to_vec(),
            prekey_bundle: bundle(),
            reset_identity,
        })
    }

    async fn open_account(state: &Arc<ServerState>, name: &str, start: AccountStart) -> Client {
        let (stream, server) = tokio::io::duplex(65536);
        let (media_tx, _media_rx) = mpsc::channel(8);
        let (sid_tx, _sid_rx) = oneshot::channel();
        let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let handler = tokio::spawn(handle_connection(
            server,
            name.into(),
            lo,
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
                username: name.into(),
                protocol_version: PROTOCOL_VERSION,
                app_version: APP_VERSION.to_string(),
                identity_key: None,
                prekey_bundle: None,
                account: Some(start),
            })
            .await;
        client
    }

    /// What `pow.js` does, from the relay's challenge JSON.
    fn solve(altcha: &str) -> String {
        use sha2::Digest;
        let c: serde_json::Value = serde_json::from_str(altcha).unwrap();
        let (salt, challenge) = (
            c["salt"].as_str().unwrap(),
            c["challenge"].as_str().unwrap(),
        );
        for n in 0..=c["maxnumber"].as_u64().unwrap() {
            if hex::encode(sha2::Sha256::digest(format!("{salt}{n}").as_bytes())) == challenge {
                return serde_json::json!({
                    "algorithm": c["algorithm"], "challenge": challenge,
                    "number": n, "salt": salt, "signature": c["signature"]
                })
                .to_string();
            }
        }
        panic!("unsolvable challenge");
    }

    fn reply(m: &ServerMessage) -> Option<&AccountReply> {
        match m {
            ServerMessage::Account(r) => Some(r),
            _ => None,
        }
    }

    /// What every 1.3 sign-up carries: the reset key (S-006).
    fn reset_slot() -> VaultBlob {
        VaultBlob {
            k: "slot.reset".into(),
            v: vec![7; 32],
            version: 0,
        }
    }

    /// Signs up `name` on an open relay; returns the signed-in connection.
    async fn register(state: &Arc<ServerState>, name: &str) -> (Client, AccountInfo) {
        let mut c = open_account(state, name, AccountStart::Register { invite: None }).await;
        let Some(ServerMessage::AuthStep(AuthStep::Salt { pow: Some(pow), .. })) = c.next().await
        else {
            panic!("an open relay hands out a proof of work");
        };
        let vault = vec![
            VaultBlob {
                k: "slot.hkdf".into(),
                v: vec![1, 2, 3],
                version: 0,
            },
            reset_slot(),
        ];
        let altcha = solve(&pow.altcha);
        c.send(&ClientMessage::AuthContinue(AuthContinue::Register {
            auth_secret: SECRET.to_vec(),
            altcha,
            ts: pow.ts,
            vault,
        }))
        .await;
        c.send(&keys(&IDENTITY, false)).await;
        let ServerMessage::Authenticated {
            account: Some(info),
            accounts: Some(relay),
            ..
        } = c
            .expect("Authenticated", |m| {
                matches!(m, ServerMessage::Authenticated { .. })
            })
            .await
        else {
            panic!("an account sign-in says which account and which relay");
        };
        assert_eq!(relay.relay_id, state.accounts.as_ref().unwrap().relay_id);
        (c, info)
    }

    /// Signs `name` in with the password secret; answers a code with `code`.
    async fn login(state: &Arc<ServerState>, name: &str, identity: &[u8], reset: bool) -> Client {
        let mut c = open_account(state, name, AccountStart::Login).await;
        assert!(matches!(
            c.next().await,
            Some(ServerMessage::AuthStep(AuthStep::Salt { pow: None, .. }))
        ));
        c.send(&ClientMessage::AuthContinue(AuthContinue::Secret {
            auth_secret: SECRET.to_vec(),
        }))
        .await;
        c.send(&keys(identity, reset)).await;
        c
    }

    #[tokio::test]
    async fn an_account_signs_up_and_signs_in_with_its_vault_and_identity() {
        let (state, _db_state) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let (alice, info) = register(&state, "alice").await;
        assert_eq!(info.name, "alice");
        assert!(info.scopes.is_empty() && !info.needs_2fa && !info.totp_enabled);
        let session = state.sessions.iter().next().unwrap();
        assert_eq!(session.username, "alice", "an account's name is bare");
        assert!(session.account.is_some());
        drop(session);
        drop(alice);

        // Signing in again: the vault comes back, the identity must match.
        let mut c = login(&state, "Alice", &IDENTITY, false).await;
        let ServerMessage::AuthStep(AuthStep::Vault { blobs }) = c
            .expect("Vault", |m| matches!(m, ServerMessage::AuthStep(_)))
            .await
        else {
            unreachable!()
        };
        assert_eq!(
            (blobs[0].k.as_str(), blobs[0].v.as_slice()),
            ("slot.hkdf", &[1, 2, 3][..])
        );
        c.expect("Authenticated", |m| {
            matches!(
                m,
                ServerMessage::Authenticated {
                    account: Some(_),
                    ..
                }
            )
        })
        .await;

        let mut other = login(&state, "alice", &[6; 33], false).await;
        let ServerMessage::AuthError { reason } = other
            .expect("refusal", |m| matches!(m, ServerMessage::AuthError { .. }))
            .await
        else {
            unreachable!()
        };
        assert!(reason.contains("identity"), "{reason}");
        let mut reset = login(&state, "alice", &[6; 33], true).await;
        reset
            .expect("Authenticated", |m| {
                matches!(
                    m,
                    ServerMessage::Authenticated {
                        account: Some(_),
                        ..
                    }
                )
            })
            .await;
        assert_eq!(
            state
                .accounts
                .as_ref()
                .unwrap()
                .identity(l4f_accounts::model::AccountId(info.id))
                .await
                .unwrap(),
            Some(vec![6; 33])
        );

        let mut wrong = open_account(&state, "alice", AccountStart::Login).await;
        wrong.next().await;
        wrong
            .send(&ClientMessage::AuthContinue(AuthContinue::Secret {
                auth_secret: vec![8; 32],
            }))
            .await;
        assert!(
            matches!(wrong.next().await, Some(ServerMessage::AuthError { reason }) if reason.contains("Wrong"))
        );
    }

    #[tokio::test]
    async fn a_second_sign_in_takes_over_and_the_first_is_told_not_to_return() {
        let (state, _db_state) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let (mut first, _) = register(&state, "bob").await;
        let mut second = login(&state, "bob", &IDENTITY, false).await;
        second
            .expect("Authenticated", |m| {
                matches!(m, ServerMessage::Authenticated { .. })
            })
            .await;
        let ServerMessage::Disconnected { reason } = first
            .expect("Disconnected", |m| {
                matches!(m, ServerMessage::Disconnected { .. })
            })
            .await
        else {
            unreachable!()
        };
        assert!(reason.contains("another device"), "{reason}");
        // News about the new session may still be on its way to the old one.
        while first.next().await.is_some() {}
        first.assert_closed().await;
        // The old session's cleanup must not take the name or the account from the new one.
        assert_eq!(state.sessions.len(), 1);
        let sid = *state.username_to_session.get("bob").unwrap();
        assert!(state.sessions.contains_key(&sid));
        assert_eq!(
            state.account_sessions.iter().next().map(|e| *e.value()),
            Some(sid)
        );
    }

    #[tokio::test]
    async fn guests_need_a_tag_and_cannot_take_an_accounts_name() {
        let (state, _db_state) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let (_carol, _) = register(&state, "carol").await;
        assert!(refusal(&state, "dave").await.contains("#tag"));
        assert!(refusal(&state, "Carol#1234")
            .await
            .contains("belongs to an account"));
        // S-014: a look-alike in another script is no account's name, and
        // would pass for one; a name in another script that looks like no
        // account is anybody's to take
        assert!(refusal(&state, "\u{441}arol#1234")
            .await
            .contains("looks like"));
        assert!(refusal(&state, "c\u{430}rol#1234")
            .await
            .contains("looks like"));
        connect(&state, "J\u{fc}rgen#1234", IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
        connect(
            &state,
            "\u{43c}\u{430}\u{448}\u{430}#1234",
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        )
        .await;
        let mut guest = connect(&state, "dave#1234", IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
        guest
            .send(&ClientMessage::AdminLogin {
                token: "test-admin-token".into(),
            })
            .await;
        let ServerMessage::AdminError { reason } = guest
            .expect("AdminError", |m| {
                matches!(m, ServerMessage::AdminError { .. })
            })
            .await
        else {
            unreachable!()
        };
        assert!(
            reason.contains("account"),
            "a guest cannot claim admin with the token: {reason}"
        );

        let (required, _db_required) =
            relay_state(AccountsMode::Required, RegistrationMode::Invite).await;
        let mut g = open(&required, "erin#1234", IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
        assert!(matches!(
            g.next().await,
            Some(ServerMessage::AuthStep(AuthStep::AccountRequired {
                registration: Registration::Invite
            }))
        ));
        g.assert_closed().await;
    }

    #[tokio::test]
    async fn invites_are_the_way_in_when_sign_up_is_not_open() {
        use sha2::Digest;
        let (state, _db_state) =
            relay_state(AccountsMode::Optional, RegistrationMode::Invite).await;
        let mut c = open_account(&state, "frank", AccountStart::Register { invite: None }).await;
        assert!(
            matches!(c.next().await, Some(ServerMessage::AuthError { reason }) if reason.contains("invite"))
        );

        let raw = [3u8; 16];
        let hash: [u8; 32] = sha2::Sha256::digest(raw).into();
        let relay = state.accounts.as_ref().unwrap();
        relay
            .store()
            .insert_invite(&hash, None, Some("frank"), l4f_accounts::util::now() + 3600)
            .await
            .unwrap();
        let code = l4f_accounts::util::b64u(&raw);
        let mut c = open_account(
            &state,
            "frank",
            AccountStart::Register { invite: Some(code) },
        )
        .await;
        assert!(
            matches!(
                c.next().await,
                Some(ServerMessage::AuthStep(AuthStep::Salt { pow: None, .. }))
            ),
            "no proof of work with an invite"
        );
        c.send(&ClientMessage::AuthContinue(AuthContinue::Register {
            auth_secret: SECRET.to_vec(),
            altcha: String::new(),
            ts: String::new(),
            vault: vec![reset_slot()],
        }))
        .await;
        c.send(&keys(&IDENTITY, false)).await;
        c.expect("Authenticated", |m| {
            matches!(
                m,
                ServerMessage::Authenticated {
                    account: Some(_),
                    ..
                }
            )
        })
        .await;
    }

    async fn totp_on(c: &mut Client) -> Vec<u8> {
        c.send(&ClientMessage::Account(AccountRequest::TotpSetup))
            .await;
        let ServerMessage::Account(AccountReply::TotpSetup { secret, sealed, .. }) =
            c.expect("TotpSetup", |m| reply(m).is_some()).await
        else {
            panic!("TotpSetup")
        };
        let secret = l4f_accounts::totp::base32_decode(&secret).unwrap();
        let code = format!(
            "{:06}",
            l4f_accounts::totp::code_at(&secret, l4f_accounts::util::now() / 30)
        );
        c.send(&ClientMessage::Account(AccountRequest::TotpEnable {
            sealed,
            code,
        }))
        .await;
        let msg = c.expect("TotpEnabled", |m| reply(m).is_some()).await;
        assert!(
            matches!(msg, ServerMessage::Account(AccountReply::TotpEnabled { ref recovery_codes }) if recovery_codes.len() == 10),
            "{msg:?}"
        );
        secret
    }

    #[tokio::test]
    async fn the_admin_token_makes_the_first_admin_whose_rights_wait_for_codes() {
        let (state, _db_state) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let (mut gina, _) = register(&state, "gina").await;
        gina.send(&ClientMessage::AdminLogin {
            token: "test-admin-token".into(),
        })
        .await;
        let ServerMessage::Account(AccountReply::Info(info)) =
            gina.expect("Info", |m| reply(m).is_some()).await
        else {
            panic!("the new admin is told what changed")
        };
        assert!(
            info.needs_2fa && info.scopes.is_empty(),
            "admin rights wait for a second factor: {info:?}"
        );
        assert!(!state.can_moderate(*state.username_to_session.get("gina").unwrap()));

        let secret = totp_on(&mut gina).await;
        let ServerMessage::Account(AccountReply::Info(info)) = gina
            .expect("Info", |m| {
                matches!(m, ServerMessage::Account(AccountReply::Info(_)))
            })
            .await
        else {
            unreachable!()
        };
        assert_eq!(info.scopes, ["*"]);
        gina.expect("AdminStatus", |m| {
            matches!(m, ServerMessage::AdminStatus { is_admin: true, .. })
        })
        .await;

        // The token is spent once an admin exists.
        let (mut hank, _) = register(&state, "hank").await;
        hank.send(&ClientMessage::AdminLogin {
            token: "test-admin-token".into(),
        })
        .await;
        let ServerMessage::AdminError { reason } = hank
            .expect("AdminError", |m| {
                matches!(m, ServerMessage::AdminError { .. })
            })
            .await
        else {
            unreachable!()
        };
        assert!(reason.contains("already"), "{reason}");

        // A new device: password, then a code; a wrong code asks again.
        let mut c = open_account(&state, "gina", AccountStart::Login).await;
        c.next().await;
        c.send(&ClientMessage::AuthContinue(AuthContinue::Secret {
            auth_secret: SECRET.to_vec(),
        }))
        .await;
        assert!(matches!(
            c.next().await,
            Some(ServerMessage::AuthStep(AuthStep::NeedTotp))
        ));
        c.send(&ClientMessage::AuthContinue(AuthContinue::Totp {
            code: "000000".into(),
        }))
        .await;
        assert!(
            matches!(
                c.next().await,
                Some(ServerMessage::AuthStep(AuthStep::NeedTotp))
            ),
            "a wrong code asks again"
        );
        let code = format!(
            "{:06}",
            l4f_accounts::totp::code_at(&secret, l4f_accounts::util::now() / 30 + 1)
        );
        c.send(&ClientMessage::AuthContinue(AuthContinue::Totp { code }))
            .await;
        c.expect("Vault", |m| {
            matches!(m, ServerMessage::AuthStep(AuthStep::Vault { .. }))
        })
        .await;
        c.send(&keys(&IDENTITY, false)).await;
        let ServerMessage::Authenticated {
            account: Some(info),
            ..
        } = c
            .expect("Authenticated", |m| {
                matches!(m, ServerMessage::Authenticated { .. })
            })
            .await
        else {
            unreachable!()
        };
        assert_eq!(info.scopes, ["*"]);
        let sid = *state.username_to_session.get("gina").unwrap();
        assert!(state.is_admin(sid) && state.can_moderate(sid));
        // The app shows its admin controls only on AdminStatus: a later
        // sign-in needs it as much as the first.
        let uid = state.sessions.get(&sid).unwrap().user_id;
        c.expect("AdminStatus", |m| matches!(m, ServerMessage::AdminStatus { user_id, is_admin: true } if *user_id == uid)).await;
    }

    #[tokio::test]
    async fn a_remembered_device_signs_in_alone_and_its_signature_does_not_replay() {
        use ring::signature::KeyPair;
        let (state, _db_state) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let relay_id = state.accounts.as_ref().unwrap().relay_id;
        let (mut ivy, _) = register(&state, "ivy").await;
        let pkcs8 =
            ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
                .unwrap();
        let key = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let device_id = vec![0x42u8; 16];
        let origin = format!("voipc://{}", hex::encode(relay_id));
        let sign = |challenge: &str| {
            let msg = l4f_accounts::verify::devkey::message(
                &origin,
                &device_id,
                &l4f_accounts::challenge::challenge_bytes(challenge),
            );
            key.sign(&msg).as_ref().to_vec()
        };
        ivy.send(&ClientMessage::Account(AccountRequest::DeviceChallenge))
            .await;
        let ServerMessage::Account(AccountReply::DeviceChallenge { challenge }) =
            ivy.expect("challenge", |m| reply(m).is_some()).await
        else {
            panic!("a fresh sign-in may remember its device")
        };
        let signature = sign(&challenge);
        ivy.send(&ClientMessage::Account(AccountRequest::DeviceAdd {
            device_id: device_id.clone(),
            public_key: key.public_key().as_ref().to_vec(),
            signature,
        }))
        .await;
        assert!(matches!(
            ivy.expect("added", |m| reply(m).is_some()).await,
            ServerMessage::Account(AccountReply::DeviceAdded)
        ));

        let mut d = open_account(
            &state,
            "ivy",
            AccountStart::DeviceKey {
                device_id: device_id.clone(),
            },
        )
        .await;
        let Some(ServerMessage::AuthStep(AuthStep::DeviceChallenge {
            challenge,
            relay_id: rid,
        })) = d.next().await
        else {
            panic!("a device challenge")
        };
        assert_eq!(rid, relay_id);
        let first_sig = sign(&challenge);
        d.send(&ClientMessage::AuthContinue(AuthContinue::DeviceSig {
            signature: first_sig.clone(),
        }))
        .await;
        d.expect("Vault", |m| {
            matches!(m, ServerMessage::AuthStep(AuthStep::Vault { .. }))
        })
        .await;
        d.send(&keys(&IDENTITY, false)).await;
        d.expect("Authenticated", |m| {
            matches!(
                m,
                ServerMessage::Authenticated {
                    account: Some(_),
                    ..
                }
            )
        })
        .await;

        // The same signature on another connection: another challenge, another nonce.
        let mut replay = open_account(
            &state,
            "ivy",
            AccountStart::DeviceKey {
                device_id: device_id.clone(),
            },
        )
        .await;
        replay.next().await;
        replay
            .send(&ClientMessage::AuthContinue(AuthContinue::DeviceSig {
                signature: first_sig,
            }))
            .await;
        assert!(
            matches!(replay.next().await, Some(ServerMessage::AuthError { .. })),
            "a replayed signature is refused"
        );

        // H1-14: a remembered device alone cannot replace the identity every
        // contact pinned; that takes the password
        let mut reset = open_account(
            &state,
            "ivy",
            AccountStart::DeviceKey {
                device_id: device_id.clone(),
            },
        )
        .await;
        let Some(ServerMessage::AuthStep(AuthStep::DeviceChallenge { challenge, .. })) =
            reset.next().await
        else {
            panic!("a device challenge")
        };
        reset
            .send(&ClientMessage::AuthContinue(AuthContinue::DeviceSig {
                signature: sign(&challenge),
            }))
            .await;
        reset
            .expect("Vault", |m| {
                matches!(m, ServerMessage::AuthStep(AuthStep::Vault { .. }))
            })
            .await;
        reset.send(&keys(&[7u8; 33], true)).await;
        let Some(ServerMessage::AuthError { reason }) = reset.next().await else {
            panic!("the reset went through")
        };
        assert!(reason.contains("password"), "{reason}");
    }

    /// A 0.12 app (protocol 11) reads only `AuthError`, and stops
    /// reconnecting on its words.
    #[tokio::test]
    async fn a_pre_1_0_client_is_told_to_update() {
        #[derive(serde::Serialize)]
        enum Old {
            Authenticate {
                username: String,
                protocol_version: u32,
                app_version: String,
                identity_key: Option<Vec<u8>>,
                prekey_bundle: Option<PreKeyBundleData>,
            },
        }
        let state = admin_state();
        let (mut stream, server) = tokio::io::duplex(65536);
        let (media_tx, _media_rx) = mpsc::channel(8);
        let (sid_tx, _sid_rx) = oneshot::channel();
        let handler = tokio::spawn(handle_connection(
            server,
            "old".into(),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            media_tx,
            sid_tx,
            state.clone(),
        ));
        let payload = postcard::to_allocvec(&Old::Authenticate {
            username: "old".into(),
            protocol_version: FIRST_STRUCTURED_REFUSAL - 1,
            app_version: "0.12.0".into(),
            identity_key: None,
            prekey_bundle: None,
        })
        .unwrap();
        stream
            .write_all(&(payload.len() as u32).to_be_bytes())
            .await
            .unwrap();
        stream.write_all(&payload).await.unwrap();
        let mut c = Client {
            stream,
            handler,
            buf: BytesMut::new(),
        };
        let Some(ServerMessage::AuthError { reason }) = c.next().await else {
            panic!("an old client hears why")
        };
        // The words a 0.12 client stops reconnecting on (connect.ts)
        assert!(
            reason.contains("version mismatch") && reason.contains("please update your app"),
            "{reason}"
        );
    }

    /// Protocol match only: another app version on the same protocol is in.
    #[tokio::test]
    async fn another_app_version_on_the_same_protocol_is_admitted() {
        let state = admin_state();
        let first = ClientMessage::Authenticate {
            username: "newer-patch".into(),
            protocol_version: PROTOCOL_VERSION,
            app_version: "1.0.7".into(),
            identity_key: None,
            prekey_bundle: None,
            account: None,
        };
        let mut c = open_raw(&state, &first).await;
        c.expect("Authenticated", |m| {
            matches!(m, ServerMessage::Authenticated { .. })
        })
        .await;
    }

    /// A 1.x app one protocol behind (12, the first that reads `Refused`)
    /// hears that it is the one to update.
    #[tokio::test]
    async fn a_client_one_protocol_behind_is_told_to_update() {
        let state = admin_state();
        let first = ClientMessage::Authenticate {
            username: "older".into(),
            protocol_version: PROTOCOL_VERSION - 1,
            app_version: "1.2.0".into(),
            identity_key: None,
            prekey_bundle: None,
            account: None,
        };
        let mut c = open_raw(&state, &first).await;
        let Some(ServerMessage::Refused {
            code,
            server_protocol,
            text,
            ..
        }) = c.next().await
        else {
            panic!("not refused")
        };
        assert_eq!((code, server_protocol), (REFUSED_VERSION, PROTOCOL_VERSION));
        assert!(
            text.contains("version mismatch") && text.contains("please update your app"),
            "{text}"
        );
    }

    /// A newer client hears, in a form it can read, that the server is the
    /// one behind.
    #[tokio::test]
    async fn a_newer_client_is_told_the_server_needs_an_update() {
        let state = admin_state();
        let first = ClientMessage::Authenticate {
            username: "future".into(),
            protocol_version: PROTOCOL_VERSION + 1,
            app_version: "1.1.0".into(),
            identity_key: None,
            prekey_bundle: None,
            account: None,
        };
        let mut c = open_raw(&state, &first).await;
        let Some(ServerMessage::Refused {
            code,
            server_protocol,
            server_version,
            text,
        }) = c.next().await
        else {
            panic!("not refused")
        };
        assert_eq!(
            (code, server_protocol, server_version.as_str()),
            (REFUSED_VERSION, PROTOCOL_VERSION, APP_VERSION)
        );
        assert!(
            text.contains("version mismatch") && text.contains("the server needs an update"),
            "{text}"
        );
    }

    /// Runs the client's sign-in machine (voipc-crypto) against this relay.
    async fn drive(
        c: &mut Client,
        m: &mut voipc_crypto::account::SignIn,
    ) -> Result<AccountInfo, String> {
        use voipc_crypto::account::Step;
        loop {
            let msg = c.next().await.ok_or("closed")?;
            if let ServerMessage::Authenticated {
                account: Some(info),
                ..
            } = &msg
            {
                return Ok(info.clone());
            }
            for step in m.on_message(&msg)? {
                match step {
                    Step::Send(out) => c.send(&out).await,
                    Step::Keys => {
                        let ik = m.identity().unwrap().public_key().serialize().to_vec();
                        let b = PreKeyBundleData {
                            identity_key: ik,
                            ..bundle()
                        };
                        c.send(&m.keys(b)).await;
                    }
                    Step::NeedTotp => return Err("asked for a code".into()),
                    Step::Stretch { .. } | Step::ResetDone => {
                        return Err("not a sign-in step".into())
                    }
                    Step::Ignore => {}
                }
            }
        }
    }

    /// Runs a reset with the recovery key through the client's machine;
    /// `code` answers a second factor.
    async fn reset_with(
        state: &Arc<ServerState>,
        name: &str,
        recovery: &str,
        password: &str,
        code: Option<&str>,
    ) -> Result<(), String> {
        use voipc_crypto::account::{recovery_parse, Method, SignIn, Step};
        let recovery =
            zeroize::Zeroizing::new(recovery_parse(recovery).ok_or("not a recovery key")?);
        let method = Method::Reset {
            recovery,
            password: zeroize::Zeroizing::new(password.into()),
        };
        let (mut m, first) = SignIn::start(name, method, PROTOCOL_VERSION, APP_VERSION);
        let mut c = open_raw(state, &first).await;
        loop {
            let msg = c.next().await.ok_or("closed")?;
            for step in m.on_message(&msg)? {
                match step {
                    Step::Send(out) => c.send(&out).await,
                    Step::NeedTotp => c.send(&m.totp(code.ok_or("asked for a code")?)).await,
                    Step::ResetDone => return Ok(()),
                    _ => {}
                }
            }
        }
    }

    async fn password_sign_in(
        state: &Arc<ServerState>,
        name: &str,
        password: &str,
    ) -> Result<voipc_crypto::account::SignedIn, String> {
        use voipc_crypto::account::{Method, SignIn};
        let (mut m, first) = SignIn::start(
            name,
            Method::Password {
                password: zeroize::Zeroizing::new(password.into()),
            },
            PROTOCOL_VERSION,
            APP_VERSION,
        );
        drive(&mut open_raw(state, &first).await, &mut m).await?;
        m.finish()
    }

    /// 1.0 (A4): a forgotten password, set anew with the recovery key. The
    /// relay hands out only what the key opens, checks the identity's
    /// signature, and signs every device out.
    #[tokio::test]
    async fn the_recovery_key_sets_a_new_password_and_signs_every_device_out() {
        use voipc_crypto::account::{DeviceEnrol, DeviceKey, Method, SignIn};
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let (mut c, _, signed) = register_with(&state, "kim").await;
        let recovery = signed.recovery.clone().unwrap();
        let identity = signed.identity.public_key().serialize().to_vec();
        let (enrol, ask) = DeviceEnrol::start(signed.relay_id);
        c.send(&ask).await;
        let ServerMessage::Account(r) = c.expect("challenge", |m| reply(m).is_some()).await else {
            unreachable!()
        };
        c.send(&enrol.on_reply(&r).unwrap()).await;
        assert!(matches!(
            c.expect("added", |m| reply(m).is_some()).await,
            ServerMessage::Account(AccountReply::DeviceAdded)
        ));

        // Another key opens nothing; the client stops there.
        let other = voipc_crypto::account::recovery_text(&[7u8; 32]);
        let e = reset_with(&state, "kim", &other, "a brand new password", None)
            .await
            .unwrap_err();
        assert!(e.contains("recovery key"), "{e}");
        // The relay hands out no password slot, and refuses another identity's signature.
        let mut raw = open_account(&state, "kim", AccountStart::Reset).await;
        let Some(ServerMessage::AuthStep(AuthStep::ResetChallenge {
            blobs,
            second_factor: false,
            ..
        })) = raw.next().await
        else {
            panic!("a challenge")
        };
        assert!(
            blobs
                .iter()
                .all(|b| b.k == "slot.recovery" || b.k == "item.identity")
                && blobs.len() == 2,
            "{blobs:?}"
        );
        let forged = voipc_crypto::account::reset_proof(
            &voipc_crypto::generate_identity_key_pair(),
            &signed.relay_id,
            "kim",
            b"x",
        );
        raw.send(&ClientMessage::AuthContinue(AuthContinue::Reset {
            signature: forged,
            key_signature: vec![0; 64],
            auth_secret: SECRET.to_vec(),
            pass_slot: vec![1; 101],
            totp: None,
            recovery_code: None,
        }))
        .await;
        let ServerMessage::AuthError { reason } = raw
            .expect("refusal", |m| matches!(m, ServerMessage::AuthError { .. }))
            .await
        else {
            unreachable!()
        };
        assert!(reason.contains("not this account's"), "{reason}");

        reset_with(&state, "kim", &recovery, "a brand new password", None)
            .await
            .unwrap();
        c.expect("signed out", |m| {
            matches!(m, ServerMessage::Disconnected { .. })
        })
        .await;
        assert!(password_sign_in(&state, "kim", "correct horse battery")
            .await
            .err()
            .unwrap()
            .contains("Wrong"));
        let key = DeviceKey::from_parts(enrol.key.device_id, enrol.key.pkcs8().to_vec()).unwrap();
        let (mut m, first) = SignIn::start(
            "kim",
            Method::Device {
                key,
                relay_id: signed.relay_id,
                dek: signed.vault.dek(),
            },
            PROTOCOL_VERSION,
            APP_VERSION,
        );
        assert!(
            drive(&mut open_raw(&state, &first).await, &mut m)
                .await
                .is_err(),
            "the remembered device is forgotten"
        );
        // The new password opens the same vault: the same identity, so nobody's pins break.
        let again = password_sign_in(&state, "kim", "a brand new password")
            .await
            .unwrap();
        assert_eq!(again.identity.public_key().serialize().to_vec(), identity);
    }

    /// S-006: the vault's DEK, which a remembered device keeps, opens the
    /// identity, so it can make the old reset proof. An account with a reset
    /// key refuses that proof: only the recovery key resets its password.
    #[tokio::test]
    async fn a_device_that_holds_the_vault_key_cannot_reset_the_password() {
        use voipc_crypto::account::{reset_proof, Vault};
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let (_c, _, signed) = register_with(&state, "ida").await;
        let mut raw = open_account(&state, "ida", AccountStart::Reset).await;
        let Some(ServerMessage::AuthStep(AuthStep::ResetChallenge {
            relay_id,
            challenge,
            blobs,
            ..
        })) = raw.next().await
        else {
            panic!("a challenge")
        };
        let opened = Vault::from_dek(relay_id, "ida", signed.vault.dek())
            .open_item(&blobs, "item.identity")
            .unwrap()
            .payload;
        assert_eq!(opened, signed.identity.serialize().to_vec());
        raw.send(&ClientMessage::AuthContinue(AuthContinue::Reset {
            signature: reset_proof(&signed.identity, &relay_id, "ida", &challenge),
            key_signature: vec![0; 64],
            auth_secret: SECRET.to_vec(),
            pass_slot: vec![1; 101],
            totp: None,
            recovery_code: None,
        }))
        .await;
        let ServerMessage::AuthError { reason } = raw
            .expect("refusal", |m| matches!(m, ServerMessage::AuthError { .. }))
            .await
        else {
            unreachable!()
        };
        assert!(reason.contains("not this account's"), "{reason}");
        let recovery = signed.recovery.clone().unwrap();
        reset_with(&state, "ida", &recovery, "a brand new password", None)
            .await
            .unwrap();
    }

    /// S-006: a new recovery key, with the password, replaces the old one:
    /// the old stops working, the new resets. It is how an account made
    /// before 1.3 gets its reset key.
    #[tokio::test]
    async fn a_new_recovery_key_replaces_the_old_one() {
        use voipc_crypto::account::{derive_from_master, recovery_text, reset_key, stretch, Vault};
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let (mut c, _, signed) = register_with(&state, "joe").await;
        let old = signed.recovery.clone().unwrap();
        let fresh = [9u8; 32];
        let ask = |password: &str| {
            let master = stretch(password, &signed.relay_id, "joe");
            let vault = Vault::from_dek(signed.relay_id, "joe", signed.vault.dek());
            ClientMessage::Account(AccountRequest::RecoveryKeyNew {
                secret: derive_from_master(&master).auth_secret.to_vec(),
                recovery_slot: vault.recovery_slot(&fresh).v,
                reset_key: reset_key(&fresh, &signed.relay_id, "joe").to_vec(),
                totp: None,
                recovery_code: None,
            })
        };
        c.send(&ask("not the password")).await;
        assert!(matches!(
            c.expect("refused", |m| reply(m).is_some()).await,
            ServerMessage::Account(AccountReply::Error { .. })
        ));
        c.send(&ask("correct horse battery")).await;
        assert!(matches!(
            c.expect("changed", |m| reply(m).is_some()).await,
            ServerMessage::Account(AccountReply::RecoveryKeyChanged)
        ));
        assert!(
            reset_with(&state, "joe", &old, "a brand new password", None)
                .await
                .is_err()
        );
        reset_with(
            &state,
            "joe",
            &recovery_text(&fresh),
            "a brand new password",
            None,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn a_reset_of_an_account_with_codes_needs_a_code() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let (mut c, _, signed) = register_with(&state, "lou").await;
        let secret = totp_on(&mut c).await;
        let recovery = signed.recovery.clone().unwrap();
        assert_eq!(
            reset_with(&state, "lou", &recovery, "a brand new password", None)
                .await
                .unwrap_err(),
            "asked for a code"
        );
        assert!(reset_with(
            &state,
            "lou",
            &recovery,
            "a brand new password",
            Some("000000")
        )
        .await
        .is_err());
        let code = format!(
            "{:06}",
            l4f_accounts::totp::code_at(&secret, l4f_accounts::util::now() / 30 + 1)
        );
        reset_with(
            &state,
            "lou",
            &recovery,
            "a brand new password",
            Some(&code),
        )
        .await
        .unwrap();
        assert_eq!(
            password_sign_in(&state, "lou", "a brand new password")
                .await
                .err()
                .as_deref(),
            Some("asked for a code"),
            "codes stay on"
        );
        assert!(password_sign_in(&state, "lou", "correct horse battery")
            .await
            .err()
            .unwrap()
            .contains("Wrong"));
    }

    #[tokio::test]
    async fn a_password_change_keeps_this_connection_and_forgets_the_device_keys() {
        use voipc_crypto::account::stretch;
        use voipc_crypto::account::{DeviceEnrol, DeviceKey, Method, SignIn};
        use voipc_crypto::account_session::AccountSession;
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let (mut c, info, signed) = register_with(&state, "max").await;
        let (enrol, ask) = DeviceEnrol::start(signed.relay_id);
        c.send(&ask).await;
        let ServerMessage::Account(r) = c.expect("challenge", |m| reply(m).is_some()).await else {
            unreachable!()
        };
        c.send(&enrol.on_reply(&r).unwrap()).await;
        assert!(matches!(
            c.expect("added", |m| reply(m).is_some()).await,
            ServerMessage::Account(AccountReply::DeviceAdded)
        ));
        let (relay_id, dek) = (signed.relay_id, signed.vault.dek());
        let (mut session, _) =
            AccountSession::start(signed, &info, Default::default(), false, true);
        let old = stretch("correct horse battery", &relay_id, "max");
        let new = stretch("another good password", &relay_id, "max");
        for m in session.password_change(&new, &new, None, None).send {
            c.send(&m).await;
        }
        let msg = c.expect("refused", |m| reply(m).is_some()).await;
        assert!(
            matches!(msg, ServerMessage::Account(AccountReply::Error { ref request, .. }) if request == "PasswordChange"),
            "the old password must be right: {msg:?}"
        );
        for m in session.password_change(&old, &new, None, None).send {
            c.send(&m).await;
        }
        let ServerMessage::Account(changed) = c.expect("changed", |m| reply(m).is_some()).await
        else {
            unreachable!()
        };
        assert!(
            matches!(changed, AccountReply::PasswordChanged),
            "{changed:?}"
        );
        // Every device key went with the old password, this one's too: the
        // session asks to remember this device again.
        let again = session.on_reply(&changed);
        assert!(again
            .send
            .iter()
            .any(|m| matches!(m, ClientMessage::Account(AccountRequest::DeviceChallenge))));
        // This connection's token was swapped with l4f's, so it stays.
        crate::accounts::revalidate(&state).await;
        c.send(&ClientMessage::Account(AccountRequest::VaultPut {
            k: "item.still".into(),
            v: b"here".to_vec(),
            expect: 0,
        }))
        .await;
        assert!(matches!(
            c.expect("stored", |m| reply(m).is_some()).await,
            ServerMessage::Account(AccountReply::VaultStored { .. })
        ));
        let key = DeviceKey::from_parts(enrol.key.device_id, enrol.key.pkcs8().to_vec()).unwrap();
        let (mut m, first) = SignIn::start(
            "max",
            Method::Device { key, relay_id, dek },
            PROTOCOL_VERSION,
            APP_VERSION,
        );
        assert!(
            drive(&mut open_raw(&state, &first).await, &mut m)
                .await
                .is_err(),
            "the old device key is forgotten"
        );
        assert!(password_sign_in(&state, "max", "correct horse battery")
            .await
            .err()
            .unwrap()
            .contains("Wrong"));
        let again = password_sign_in(&state, "max", "another good password")
            .await
            .expect("the new password opens the vault");
        assert_eq!(again.vault.dek(), dek, "the same vault: the DEK stays");
    }

    /// A password change that l4f refuses after the slot was written puts the
    /// old slot back, so the vault still opens with the password that signs in.
    #[tokio::test]
    async fn a_failed_password_change_puts_the_old_slot_back() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let (_c, info, _) = register_with(&state, "ned").await;
        let relay = state.accounts.clone().unwrap();
        let id = l4f_accounts::model::AccountId(info.id);
        let slot = |v: &[VaultBlob]| v.iter().find(|b| b.k == "slot.pass").unwrap().v.clone();
        let before = relay.vault(id).await.unwrap();
        let failed =
            crate::accounts::replace_pass_slot(&relay, id, &before, &[1u8; 101], || async {
                Err(l4f_accounts::service::Error::Invalid("refused"))
            })
            .await;
        assert_eq!(failed.unwrap_err(), "refused");
        assert_eq!(slot(&relay.vault(id).await.unwrap()), slot(&before));
        password_sign_in(&state, "ned", "correct horse battery")
            .await
            .expect("the old password still opens the vault");
    }

    async fn open_raw(state: &Arc<ServerState>, first: &ClientMessage) -> Client {
        let (stream, server) = tokio::io::duplex(65536);
        let (media_tx, _media_rx) = mpsc::channel(8);
        let (sid_tx, _sid_rx) = oneshot::channel();
        let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let handler = tokio::spawn(handle_connection(
            server,
            "raw".into(),
            lo,
            media_tx,
            sid_tx,
            state.clone(),
        ));
        let mut c = Client {
            stream,
            handler,
            buf: BytesMut::new(),
        };
        c.send(first).await;
        c
    }

    async fn epoch_put(c: &mut Client, conv: &str, epoch: u32, to: &[[u8; 16]]) -> ServerMessage {
        let wraps = to
            .iter()
            .map(|r| voipc_protocol::messages::WrapIn {
                recipient: *r,
                wrapped: vec![0xAB; 92],
            })
            .collect();
        c.send(&ClientMessage::Account(AccountRequest::EpochPut {
            conv: conv.into(),
            epoch,
            wraps,
        }))
        .await;
        c.expect("an EpochPut answer", |m| {
            matches!(
                m,
                ServerMessage::Account(
                    AccountReply::EpochStored { .. } | AccountReply::Error { .. }
                )
            )
        })
        .await
    }

    /// H1-03: new epochs per writer and conversation are capped per hour; an
    /// epoch already there can still take more wraps.
    #[tokio::test]
    async fn new_epochs_are_capped_per_hour() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let relay = state.accounts.clone().unwrap();
        let (mut eve, e) = register(&state, "eve").await;
        let (_bob, b) = register(&state, "bob").await;
        let conv = voipc_protocol::conv::dm_conv(&e.id, &b.id);
        let now = l4f_accounts::util::now();
        for epoch in 0..60 {
            crate::accounts::raw(&relay, &format!(
                "INSERT INTO voipc_wraps (conv, owner, epoch, recipient, wrapped, created_at) VALUES ('{conv}', x'{}', {epoch}, x'{}', x'00', {now})",
                hex::encode(e.id), hex::encode(b.id)
            )).await.unwrap();
        }
        let refused = epoch_put(&mut eve, &conv, 1000, &[e.id, b.id]).await;
        assert!(
            matches!(refused, ServerMessage::Account(AccountReply::Error { ref reason, .. }) if reason.contains("Too many new keys")),
            "{refused:?}"
        );
        let known = epoch_put(&mut eve, &conv, 5, &[e.id, b.id]).await;
        assert!(
            matches!(
                known,
                ServerMessage::Account(AccountReply::EpochStored { .. })
            ),
            "{known:?}"
        );
    }

    /// H1-04: one member minting epochs no longer pushes another writer's key
    /// out of what a reader fetches.
    #[tokio::test]
    async fn one_writer_cannot_crowd_another_out_of_the_wraps() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let relay = state.accounts.clone().unwrap();
        let (mut alice, a) = register(&state, "alice").await;
        let (mut bob, b) = register(&state, "bob").await;
        let (_eve, e) = register(&state, "eve").await;
        let conv = "c:00112233445566778899aabbccddeeff";
        for id in [a.id, b.id, e.id] {
            crate::accounts::raw(&relay, &format!("INSERT INTO voipc_members (conv, account, joined_at) VALUES ('{conv}', x'{}', 0)", hex::encode(id))).await.unwrap();
        }
        assert!(matches!(
            epoch_put(&mut alice, conv, 1, &[a.id, b.id, e.id]).await,
            ServerMessage::Account(AccountReply::EpochStored { .. })
        ));
        let later = l4f_accounts::util::now() + 10;
        for epoch in 0..400 {
            crate::accounts::raw(&relay, &format!(
                "INSERT INTO voipc_wraps (conv, owner, epoch, recipient, wrapped, created_at) VALUES ('{conv}', x'{}', {epoch}, x'{}', x'00', {later})",
                hex::encode(e.id), hex::encode(b.id)
            )).await.unwrap();
        }
        bob.send(&ClientMessage::Account(AccountRequest::WrapsFetch {
            conv: conv.into(),
        }))
        .await;
        let ServerMessage::Account(AccountReply::Wraps { wraps, .. }) = bob
            .expect("Wraps", |m| {
                matches!(m, ServerMessage::Account(AccountReply::Wraps { .. }))
            })
            .await
        else {
            unreachable!()
        };
        assert!(
            wraps.iter().any(|w| w.owner == a.id),
            "alice's key was pushed out"
        );
        assert!(wraps.len() <= 400);
    }

    /// H1-02: a sign-in waiting for its client holds no permit, so sign-ins
    /// that stall (or are made to) cannot lock everybody else out.
    #[tokio::test]
    async fn stalled_sign_ins_hold_no_permit() {
        use voipc_crypto::account::{Method, SignIn};
        use zeroize::Zeroizing;
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let pw = || Zeroizing::new("correct horse battery".to_string());
        let (mut m, first) = SignIn::start(
            "kim",
            Method::Register {
                password: pw(),
                invite: None,
            },
            PROTOCOL_VERSION,
            APP_VERSION,
        );
        drive(&mut open_raw(&state, &first).await, &mut m)
            .await
            .unwrap();

        // More stalled sign-ins from this address than it has permits
        let mut stalled = Vec::new();
        for _ in 0..4 + 2 {
            let mut c = open_account(&state, "kim", AccountStart::Login).await;
            assert!(matches!(
                c.next().await,
                Some(ServerMessage::AuthStep(AuthStep::Salt { .. }))
            ));
            stalled.push(c);
        }
        let (mut m, first) = SignIn::start(
            "kim",
            Method::Password { password: pw() },
            PROTOCOL_VERSION,
            APP_VERSION,
        );
        drive(&mut open_raw(&state, &first).await, &mut m)
            .await
            .expect("signs in beside the stalled ones");
    }

    #[tokio::test]
    async fn the_clients_sign_in_machine_signs_up_remembers_the_device_and_signs_in_both_ways() {
        use voipc_crypto::account::{DeviceEnrol, Method, SignIn};
        use zeroize::Zeroizing;
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let pw = || Zeroizing::new("correct horse battery".to_string());

        let (mut m, first) = SignIn::start(
            "jules",
            Method::Register {
                password: pw(),
                invite: None,
            },
            PROTOCOL_VERSION,
            APP_VERSION,
        );
        let mut c = open_raw(&state, &first).await;
        drive(&mut c, &mut m).await.unwrap();
        let signed = m.finish().unwrap();
        assert!(
            signed.recovery.is_some(),
            "a new account gets its recovery key"
        );
        let identity = signed.identity.public_key().serialize().to_vec();

        // Remember this device.
        let (enrol, ask) = DeviceEnrol::start(signed.relay_id);
        c.send(&ask).await;
        let ServerMessage::Account(r) = c.expect("challenge", |m| reply(m).is_some()).await else {
            unreachable!()
        };
        c.send(&enrol.on_reply(&r).expect("a challenge to sign"))
            .await;
        assert!(matches!(
            c.expect("added", |m| reply(m).is_some()).await,
            ServerMessage::Account(AccountReply::DeviceAdded)
        ));
        let dek = signed.vault.dek();

        // A new device: the password opens the same vault and the same identity.
        let (mut m, first) = SignIn::start(
            "jules",
            Method::Password { password: pw() },
            PROTOCOL_VERSION,
            APP_VERSION,
        );
        let mut c2 = open_raw(&state, &first).await;
        drive(&mut c2, &mut m).await.unwrap();
        assert_eq!(
            m.finish()
                .unwrap()
                .identity
                .public_key()
                .serialize()
                .to_vec(),
            identity
        );

        // The remembered device: no password.
        let key = voipc_crypto::account::DeviceKey::from_parts(
            enrol.key.device_id,
            enrol.key.pkcs8().to_vec(),
        )
        .unwrap();
        let (mut m, first) = SignIn::start(
            "jules",
            Method::Device {
                key,
                relay_id: signed.relay_id,
                dek,
            },
            PROTOCOL_VERSION,
            APP_VERSION,
        );
        let mut c3 = open_raw(&state, &first).await;
        drive(&mut c3, &mut m).await.unwrap();
        assert_eq!(
            m.finish()
                .unwrap()
                .identity
                .public_key()
                .serialize()
                .to_vec(),
            identity
        );

        // A wrong password does not open the vault the relay would never hand out anyway.
        let (mut m, first) = SignIn::start(
            "jules",
            Method::Password {
                password: Zeroizing::new("wrong wrong wrong".into()),
            },
            PROTOCOL_VERSION,
            APP_VERSION,
        );
        let mut c4 = open_raw(&state, &first).await;
        assert!(drive(&mut c4, &mut m).await.unwrap_err().contains("Wrong"));
    }

    #[tokio::test]
    async fn vault_items_are_written_compare_and_set() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let (mut c, _) = register(&state, "kim").await;
        let put = |k: &str, v: &[u8], expect: i64| {
            ClientMessage::Account(AccountRequest::VaultPut {
                k: k.into(),
                v: v.to_vec(),
                expect,
            })
        };
        c.send(&put("item.pins", b"one", 0)).await;
        let ServerMessage::Account(AccountReply::VaultStored { version, .. }) =
            c.expect("stored", |m| reply(m).is_some()).await
        else {
            panic!("a new item is stored")
        };
        assert_eq!(version, 1);
        // A second writer that did not see version 1 gets it back to merge with.
        c.send(&put("item.pins", b"two", 0)).await;
        let ServerMessage::Account(AccountReply::VaultConflict { blob: Some(b), .. }) =
            c.expect("conflict", |m| reply(m).is_some()).await
        else {
            panic!("a stale write is refused with what is there")
        };
        assert_eq!((b.v.as_slice(), b.version), (&b"one"[..], 1));
        c.send(&put("item.pins", b"two", 1)).await;
        assert!(matches!(
            c.expect("stored", |m| reply(m).is_some()).await,
            ServerMessage::Account(AccountReply::VaultStored { version: 2, .. })
        ));
        c.send(&put("Bad Name!", b"x", 0)).await;
        assert!(matches!(
            c.expect("refused", |m| reply(m).is_some()).await,
            ServerMessage::Account(AccountReply::Error { .. })
        ));
        // One item, and the whole vault, stay under the frame a sign-in sends them in.
        c.send(&put("item.big", &vec![0u8; 49 * 1024], 0)).await;
        assert!(matches!(
            c.expect("refused", |m| reply(m).is_some()).await,
            ServerMessage::Account(AccountReply::Error { .. })
        ));
        c.send(&put("item.a", &vec![0u8; 40 * 1024], 0)).await;
        assert!(matches!(
            c.expect("stored", |m| reply(m).is_some()).await,
            ServerMessage::Account(AccountReply::VaultStored { .. })
        ));
        c.send(&put("item.b", &vec![0u8; 20 * 1024], 0)).await;
        assert!(matches!(
            c.expect("refused", |m| reply(m).is_some()).await,
            ServerMessage::Account(AccountReply::Error { .. })
        ));
        // And it still fits the frame at sign-in.
        drop(c);
        let mut again = login(&state, "kim", &IDENTITY, false).await;
        let ServerMessage::AuthStep(AuthStep::Vault { blobs }) = again
            .expect("Vault", |m| matches!(m, ServerMessage::AuthStep(_)))
            .await
        else {
            unreachable!()
        };
        assert!(blobs.iter().any(|b| b.k == "item.a"));
        // A guest has no vault.
        let mut g = connect(&state, "lee#1234", IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
        g.send(&put("item.pins", b"x", 0)).await;
        assert!(matches!(
            g.expect("refused", |m| reply(m).is_some()).await,
            ServerMessage::Account(AccountReply::Error { .. })
        ));
    }

    /// Registers `name` with a real identity (so its log key can be endorsed).
    async fn register_with(
        state: &Arc<ServerState>,
        name: &str,
    ) -> (Client, AccountInfo, voipc_crypto::account::SignedIn) {
        use voipc_crypto::account::{Method, SignIn};
        use zeroize::Zeroizing;
        let (mut m, first) = SignIn::start(
            name,
            Method::Register {
                password: Zeroizing::new("correct horse battery".into()),
                invite: None,
            },
            PROTOCOL_VERSION,
            APP_VERSION,
        );
        let mut c = open_raw(state, &first).await;
        let info = drive(&mut c, &mut m).await.unwrap();
        (c, info, m.finish().unwrap())
    }

    #[tokio::test]
    async fn a_dm_kept_for_somebody_offline_reaches_them_sealed_end_to_end() {
        use voipc_crypto::log::{
            dm_conv, endorsed, epoch_key, open_entry, seal_entry, unwrap, wrap, LogKey,
        };
        use voipc_protocol::messages::WrapIn;
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let (mut alice, a, alice_id) = register_with(&state, "alice").await;
        let (mut bob, b, bob_id) = register_with(&state, "bob").await;
        let (alice_lk, bob_lk) = (LogKey::generate(), LogKey::generate());
        let ask = |r: AccountRequest| ClientMessage::Account(r);
        for (c, lk, id) in [
            (&mut alice, &alice_lk, &alice_id),
            (&mut bob, &bob_lk, &bob_id),
        ] {
            c.send(&ask(AccountRequest::LogKeyPublish {
                logkey: lk.public(),
                sig: lk.endorse(&id.identity),
            }))
            .await;
            assert!(matches!(
                c.expect("stored", |m| reply(m).is_some()).await,
                ServerMessage::Account(AccountReply::LogKeyStored)
            ));
        }
        // Alice looks bob's log key up and checks it is his identity's.
        alice
            .send(&ask(AccountRequest::LogKeys {
                accounts: vec![b.id],
            }))
            .await;
        let ServerMessage::Account(AccountReply::LogKeysFound { keys }) =
            alice.expect("keys", |m| reply(m).is_some()).await
        else {
            panic!()
        };
        assert_eq!(keys.len(), 1);
        assert!(
            endorsed(&keys[0].identity, &keys[0].logkey, &keys[0].sig),
            "bob's log key is endorsed by bob's identity"
        );
        let conv = dm_conv(&a.id, &b.id);
        let k = epoch_key();
        let wraps = vec![
            WrapIn {
                recipient: a.id,
                wrapped: wrap(&alice_lk.public(), &k, &conv, &a.id, 1, &a.id).unwrap(),
            },
            WrapIn {
                recipient: b.id,
                wrapped: wrap(&keys[0].logkey, &k, &conv, &a.id, 1, &b.id).unwrap(),
            },
        ];
        alice
            .send(&ask(AccountRequest::EpochPut {
                conv: conv.clone(),
                epoch: 1,
                wraps,
            }))
            .await;
        assert!(matches!(
            alice.expect("epoch", |m| reply(m).is_some()).await,
            ServerMessage::Account(AccountReply::EpochStored { epoch: 1, .. })
        ));
        let env = voipc_crypto::envelope::envelope("m1", "while you were away", None);
        let ct = seal_entry(&k, &conv, &a.id, 1, &alice_lk, &env, 1_700_000_000_000);
        alice
            .send(&ask(AccountRequest::LogAppend {
                conv: conv.clone(),
                epoch: 1,
                ct,
                ttl_secs: None,
            }))
            .await;
        let ServerMessage::Account(AccountReply::LogAppended { seq, .. }) =
            alice.expect("appended", |m| reply(m).is_some()).await
        else {
            panic!()
        };
        // A message whose timer is zero is never handed out.
        let gone = seal_entry(
            &k,
            &conv,
            &a.id,
            1,
            &alice_lk,
            &voipc_crypto::envelope::envelope("m0", "gone", Some(1)),
            1,
        );
        alice
            .send(&ask(AccountRequest::LogAppend {
                conv: conv.clone(),
                epoch: 1,
                ct: gone,
                ttl_secs: Some(0),
            }))
            .await;
        alice.expect("appended", |m| reply(m).is_some()).await;

        // Bob, later: the index names the conversation, the wrap and the entry open.
        bob.send(&ask(AccountRequest::LogIndex)).await;
        // (Past the news of alice's key for him, pushed when she filed it.)
        let ServerMessage::Account(AccountReply::LogConvs { convs }) = bob
            .expect("index", |m| {
                matches!(m, ServerMessage::Account(AccountReply::LogConvs { .. }))
            })
            .await
        else {
            panic!()
        };
        assert!(
            convs.iter().any(|(c, last)| *c == conv && *last >= seq),
            "{convs:?}"
        );
        bob.send(&ask(AccountRequest::WrapsFetch { conv: conv.clone() }))
            .await;
        let ServerMessage::Account(AccountReply::Wraps { wraps, .. }) =
            bob.expect("wraps", |m| reply(m).is_some()).await
        else {
            panic!()
        };
        assert_eq!(wraps.len(), 1, "only the wrap for bob");
        let key = unwrap(
            &bob_lk,
            &wraps[0].wrapped,
            &conv,
            &wraps[0].owner,
            wraps[0].epoch,
            &b.id,
        )
        .unwrap();
        bob.send(&ask(AccountRequest::LogFetch {
            conv: conv.clone(),
            after: 0,
        }))
        .await;
        let ServerMessage::Account(AccountReply::LogPage { entries, more, .. }) =
            bob.expect("page", |m| reply(m).is_some()).await
        else {
            panic!()
        };
        assert!(!more);
        assert_eq!(entries.len(), 1, "the zero-timer entry is not handed out");
        let (envelope, _) = open_entry(
            &key,
            &conv,
            &entries[0].sender,
            entries[0].epoch,
            &alice_lk.public(),
            &entries[0].ct,
        )
        .unwrap();
        assert_eq!(
            voipc_crypto::envelope::open_envelope(&envelope).text,
            "while you were away"
        );

        // Nobody else reads it, and wraps go to members only.
        let (mut carol, c, _) = register_with(&state, "carol").await;
        carol
            .send(&ask(AccountRequest::LogFetch {
                conv: conv.clone(),
                after: 0,
            }))
            .await;
        assert!(matches!(
            carol.expect("refused", |m| reply(m).is_some()).await,
            ServerMessage::Account(AccountReply::Error { .. })
        ));
        let outsider = vec![WrapIn {
            recipient: c.id,
            wrapped: vec![0; 93],
        }];
        alice
            .send(&ask(AccountRequest::EpochPut {
                conv: conv.clone(),
                epoch: 2,
                wraps: outsider,
            }))
            .await;
        assert!(matches!(
            alice.expect("refused", |m| reply(m).is_some()).await,
            ServerMessage::Account(AccountReply::Error { .. })
        ));
        let mut guest = connect(&state, "dan#1234", IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
        guest
            .send(&ask(AccountRequest::LogFetch { conv, after: 0 }))
            .await;
        assert!(matches!(
            guest.expect("refused", |m| reply(m).is_some()).await,
            ServerMessage::Account(AccountReply::Error { .. })
        ));
    }

    #[tokio::test]
    async fn a_relay_that_keeps_no_messages_refuses_them() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        // `cloud = false`, after the fact: the flag the operator sets.
        let mut relay = std::sync::Arc::try_unwrap(state)
            .ok()
            .expect("one owner")
            .accounts
            .take()
            .unwrap();
        std::sync::Arc::get_mut(&mut relay).unwrap().cloud = false;
        let mut s = ServerState::new(
            &ServerConfig::default(),
            ServerSettings::default(),
            Vec::new(),
            "t".into(),
        );
        s.accounts = Some(relay);
        let state = Arc::new(s);
        let (mut a, info) = register(&state, "erin").await;
        let conv = voipc_protocol::conv::dm_conv(&info.id, &[0xff; 16]);
        a.send(&ClientMessage::Account(AccountRequest::LogAppend {
            conv,
            epoch: 1,
            ct: vec![1; 40],
            ttl_secs: None,
        }))
        .await;
        let ServerMessage::Account(AccountReply::Error { reason, .. }) =
            a.expect("refused", |m| reply(m).is_some()).await
        else {
            panic!()
        };
        assert!(reason.contains("keeps no messages"), "{reason}");
    }

    /// Feeds every account reply to `sync` and sends what it answers, until
    /// the relay has been quiet for a moment. Returns the events.
    async fn pump(
        c: &mut Client,
        sync: &mut voipc_crypto::sync::AccountSync,
        first: Vec<ClientMessage>,
    ) -> Vec<voipc_crypto::sync::Event> {
        for m in first {
            c.send(&m).await;
        }
        let mut events = Vec::new();
        loop {
            let next = async {
                loop {
                    if let Some(payload) = try_decode_frame(&mut c.buf).unwrap() {
                        return Some(decode_server_msg(&payload).unwrap());
                    }
                    if c.stream.read_buf(&mut c.buf).await.unwrap() == 0 {
                        return None;
                    }
                }
            };
            let Ok(Some(msg)) = tokio::time::timeout(Duration::from_millis(400), next).await else {
                return events;
            };
            if let ServerMessage::Account(r) = msg {
                if let Some((out, ev)) = sync.on_reply(&r) {
                    for m in out {
                        c.send(&m).await;
                    }
                    events.extend(ev);
                }
            }
        }
    }

    async fn sign_in_password(
        state: &Arc<ServerState>,
        name: &str,
    ) -> (Client, AccountInfo, voipc_crypto::account::SignedIn) {
        use voipc_crypto::account::{Method, SignIn};
        let (mut m, first) = SignIn::start(
            name,
            Method::Password {
                password: zeroize::Zeroizing::new("correct horse battery".into()),
            },
            PROTOCOL_VERSION,
            APP_VERSION,
        );
        let mut c = open_raw(state, &first).await;
        let info = drive(&mut c, &mut m).await.unwrap();
        (c, info, m.finish().unwrap())
    }

    #[tokio::test]
    async fn a_dm_written_while_they_were_away_is_read_on_every_device_once() {
        use voipc_crypto::sync::{AccountSync, Event, Prefs};
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let (mut alice, a, alice_signed) = register_with(&state, "alice").await;
        let (mut bob, b, bob_signed) = register_with(&state, "bob").await;
        let (mut sa, first) = AccountSync::start(&alice_signed, a.id, Default::default(), true);
        pump(&mut alice, &mut sa, first).await;
        let (mut sb, first) = AccountSync::start(&bob_signed, b.id, Default::default(), true);
        pump(&mut bob, &mut sb, first).await;
        drop(bob);

        // Off by default: nothing is kept until alice says so.
        let env = voipc_crypto::envelope::envelope("m1", "hi bob, while you were away", None);
        assert!(
            sa.send_dm(b.id, env.clone(), 1_700_000_000_000, None)
                .is_empty(),
            "opt-in"
        );
        let save = sa.set_prefs(Prefs {
            cloud: true,
            asked: true,
        });
        pump(&mut alice, &mut sa, save).await;
        let out = sa.send_dm(b.id, env, 1_700_000_000_000, None);
        let events = pump(&mut alice, &mut sa, out).await;
        assert!(
            events.iter().any(|e| matches!(e, Event::Kept { .. })),
            "{events:?}"
        );

        // Bob comes back: it is there, from alice, opened and proven.
        let (mut bob2, _, bob_signed2) = sign_in_password(&state, "bob").await;
        let (mut sb2, first) = AccountSync::start(&bob_signed2, b.id, Default::default(), true);
        let events = pump(&mut bob2, &mut sb2, first).await;
        let got: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                Event::Message {
                    envelope,
                    from_me,
                    peer,
                    peer_name,
                    ..
                } => Some((
                    voipc_crypto::envelope::open_envelope(envelope).text,
                    *from_me,
                    *peer,
                    peer_name.clone(),
                )),
                _ => None,
            })
            .collect();
        assert_eq!(
            got,
            vec![(
                "hi bob, while you were away".to_string(),
                false,
                a.id,
                "alice".to_string()
            )]
        );
        // Read once: with this device's cursors it is not handed over again.
        let memory = sb2.memory();
        drop(bob2);
        let (mut bob3, _, bob_signed3) = sign_in_password(&state, "bob").await;
        let (mut sb3, first) = AccountSync::start(&bob_signed3, b.id, memory, true);
        let again = pump(&mut bob3, &mut sb3, first).await;
        assert!(
            !again.iter().any(|e| matches!(e, Event::Message { .. })),
            "{again:?}"
        );
        // And alice's other device sees her own message as hers.
        drop(alice);
        let (mut alice2, _, alice_signed2) = sign_in_password(&state, "alice").await;
        let (mut sa2, first) = AccountSync::start(&alice_signed2, a.id, Default::default(), true);
        let mine = pump(&mut alice2, &mut sa2, first).await;
        assert!(
            mine.iter()
                .any(|e| matches!(e, Event::Message { from_me: true, peer, .. } if *peer == b.id)),
            "{mine:?}"
        );
        assert!(
            sa2.prefs().cloud,
            "the choice followed her to the other device"
        );
    }

    // ── channel logs ──

    /// A relay with accounts and one persistent text channel (id 1), which
    /// keeps a log; returns the log's conversation id too.
    async fn relay_with_log() -> (Arc<ServerState>, TempDb, String) {
        let mut config = ServerConfig::default();
        config.accounts.mode = AccountsMode::Optional;
        config.accounts.registration = RegistrationMode::Open;
        let db = TempDb(std::env::temp_dir().join(format!(
            "voipc-relay-{}.db",
            hex::encode(rand::random::<[u8; 8]>())
        )));
        let store = l4f_accounts::store::Store::connect(&format!("sqlite://{}", db.0.display()))
            .await
            .unwrap();
        let relay = crate::accounts::Relay::open_with(&config.accounts, store, &[9u8; 32])
            .await
            .unwrap();
        let lounge = crate::channels::ChannelEntry {
            name: "lounge".into(),
            text: true,
            ..Default::default()
        };
        let mut state = ServerState::new(
            &config,
            ServerSettings::default(),
            vec![lounge],
            "test-admin-token".into(),
        );
        state.accounts = Some(Arc::new(relay));
        let log = state.channels.get_mut()[&1].info.log.clone();
        assert!(
            log.starts_with("c:"),
            "a persistent channel on a relay with accounts keeps a log: {log:?}"
        );
        (Arc::new(state), db, log)
    }

    /// Puts the session `account` has into channel 1.
    async fn into_lounge(state: &Arc<ServerState>, account: &[u8; 16]) {
        let sid = *state.account_sessions.get(account).unwrap();
        let uid = state.sessions.get(&sid).unwrap().user_id;
        crate::state::test_support::put_in_channel(state, 1, &[(uid, sid)]).await;
    }

    /// Signs `name` up with cloud copies on, in channel 1, keeping its log.
    async fn member(
        state: &Arc<ServerState>,
        log: &str,
        name: &str,
        share: bool,
    ) -> (Client, AccountInfo, voipc_crypto::sync::AccountSync) {
        use voipc_crypto::sync::{AccountSync, Prefs};
        let (mut c, info, signed) = register_with(state, name).await;
        let (mut s, first) = AccountSync::start(&signed, info.id, Default::default(), share);
        pump(&mut c, &mut s, first).await;
        let save = s.set_prefs(Prefs {
            cloud: true,
            asked: true,
        });
        pump(&mut c, &mut s, save).await;
        into_lounge(state, &info.id).await;
        let out = s.enter(log);
        pump(&mut c, &mut s, out).await;
        (c, info, s)
    }

    /// (writer, text) of each stored channel message among `events`.
    fn channel_texts(events: &[voipc_crypto::sync::Event]) -> Vec<(String, String)> {
        events
            .iter()
            .filter_map(|e| match e {
                voipc_crypto::sync::Event::ChannelMessage {
                    sender_name,
                    envelope,
                    ..
                } => Some((
                    sender_name.clone(),
                    voipc_crypto::envelope::open_envelope(envelope).text,
                )),
                _ => None,
            })
            .collect()
    }

    /// The names in each `Readers` event, and whether it came with history.
    fn readers(events: &[voipc_crypto::sync::Event]) -> Vec<(Vec<String>, bool)> {
        events
            .iter()
            .filter_map(|e| match e {
                voipc_crypto::sync::Event::Readers {
                    accounts, history, ..
                } => Some((accounts.iter().map(|(_, n)| n.clone()).collect(), *history)),
                _ => None,
            })
            .collect()
    }

    fn say(id: &str, text: &str) -> Vec<u8> {
        voipc_crypto::envelope::envelope(id, text, None)
    }

    #[tokio::test]
    async fn a_channel_log_is_read_by_members_who_were_away() {
        use voipc_crypto::sync::{AccountSync, Event};
        let (state, _db, log) = relay_with_log().await;
        let (mut alice, _, mut sa) = member(&state, &log, "alice", true).await;
        let (bob, b, _) = member(&state, &log, "bob", true).await;
        drop(bob);

        // Nobody else is here: alice writes for whoever reads it later, and is
        // told who that is.
        let out = sa.send_channel(&log, say("m1", "for later"), 1_700_000_000_000, None);
        let events = pump(&mut alice, &mut sa, out).await;
        assert!(
            events.iter().any(|e| matches!(e, Event::Kept { .. })),
            "{events:?}"
        );
        assert_eq!(readers(&events), vec![(vec!["bob".to_string()], false)]);

        // Bob, on another device and not in the channel: it is there for him.
        let (mut bob2, _, signed) = sign_in_password(&state, "bob").await;
        let (mut sb2, first) = AccountSync::start(&signed, b.id, Default::default(), true);
        let events = pump(&mut bob2, &mut sb2, first).await;
        assert_eq!(
            channel_texts(&events),
            vec![("alice".to_string(), "for later".to_string())]
        );
        // Read once.
        let memory = sb2.memory();
        drop(bob2);
        let (mut bob3, _, signed) = sign_in_password(&state, "bob").await;
        let (mut sb3, first) = AccountSync::start(&signed, b.id, memory, true);
        assert!(channel_texts(&pump(&mut bob3, &mut sb3, first).await).is_empty());

        // Somebody who never kept the channel reads nothing of it, and cannot
        // start keeping it from outside.
        let (mut carol, _, _) = register_with(&state, "carol").await;
        let ask = |r: AccountRequest| ClientMessage::Account(r);
        carol
            .send(&ask(AccountRequest::LogFetch {
                conv: log.clone(),
                after: 0,
            }))
            .await;
        assert!(matches!(
            carol.expect("refused", |m| reply(m).is_some()).await,
            ServerMessage::Account(AccountReply::Error { .. })
        ));
        carol
            .send(&ask(AccountRequest::LogJoin { conv: log.clone() }))
            .await;
        let ServerMessage::Account(AccountReply::Error { reason, .. }) =
            carol.expect("refused", |m| reply(m).is_some()).await
        else {
            panic!()
        };
        assert!(reason.contains("Join the channel"), "{reason}");
    }

    /// The shell is another process: what it ends in the database reaches a
    /// connection that is already open at the next check.
    #[tokio::test]
    async fn a_session_ended_from_the_shell_ends_the_connection_too() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let (mut c, info) = register(&state, "sam").await;
        crate::accounts::revalidate(&state).await;
        assert!(
            state.account_sessions.contains_key(&info.id),
            "nothing changed, nothing ends"
        );
        // What `voipc-server admin reset-2fa` does to the account's sessions.
        let relay = state.accounts.clone().unwrap();
        relay
            .store()
            .delete_sessions_of(l4f_accounts::model::AccountId(info.id), None)
            .await
            .unwrap();
        crate::accounts::revalidate(&state).await;
        let msg = c
            .expect("Disconnected", |m| {
                matches!(m, ServerMessage::Disconnected { .. })
            })
            .await;
        assert!(
            matches!(msg, ServerMessage::Disconnected { reason } if reason.contains("signed out"))
        );
    }

    /// A role given from the shell to an account without codes changes none of
    /// its rights yet, so no scope changes; the account is still asked to set
    /// codes up at the next check, not at its next sign-in.
    #[tokio::test]
    async fn a_role_given_from_the_shell_asks_for_codes_at_the_next_check() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let (mut c, info) = register(&state, "rita").await;
        let relay = state.accounts.clone().unwrap();
        let ctx = relay.ctx(IpAddr::V4(Ipv4Addr::LOCALHOST), "test");
        relay
            .accounts
            .grant_role_as_host(&ctx, l4f_accounts::model::AccountId(info.id), "moderator")
            .await
            .unwrap();
        crate::accounts::revalidate(&state).await;
        let ServerMessage::Account(AccountReply::Info(now)) = c
            .expect("Info", |m| {
                matches!(m, ServerMessage::Account(AccountReply::Info(_)))
            })
            .await
        else {
            unreachable!()
        };
        assert!(now.needs_2fa && now.scopes.is_empty(), "{now:?}");
        // Told once: the next check finds nothing new.
        crate::accounts::revalidate(&state).await;
        c.send(&ClientMessage::Account(AccountRequest::LogKeys {
            accounts: Vec::new(),
        }))
        .await;
        let msg = c.expect("a reply", |m| reply(m).is_some()).await;
        assert!(
            matches!(
                msg,
                ServerMessage::Account(AccountReply::LogKeysFound { .. })
            ),
            "{msg:?}"
        );
    }

    /// Codes are the account's first second factor: l4f ends its other
    /// sessions and gives this one a new token, which the connection keeps.
    #[tokio::test]
    async fn turning_codes_on_keeps_the_connection_signed_in() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let (mut c, _) = register(&state, "tess").await;
        totp_on(&mut c).await;
        crate::accounts::revalidate(&state).await;
        c.send(&ClientMessage::Account(AccountRequest::LogKeys {
            accounts: Vec::new(),
        }))
        .await;
        let msg = c
            .expect("a reply", |m| {
                matches!(
                    m,
                    ServerMessage::Account(AccountReply::LogKeysFound { .. })
                        | ServerMessage::Disconnected { .. }
                )
            })
            .await;
        assert!(matches!(msg, ServerMessage::Account(_)), "{msg:?}");
    }

    /// An account id is as good as the name (any account can look the name
    /// up), so it goes where the name goes and no further.
    #[tokio::test]
    async fn an_account_goes_only_where_the_name_goes() {
        let (state, _db, _log) = relay_with_log().await;
        let (mut out, _) = register(&state, "outsider").await;
        let (mut inside, i) = register(&state, "insider").await;
        let (_joiner, j) = register(&state, "joiner").await;
        let sid = |a: &[u8; 16]| *state.account_sessions.get(a).unwrap();
        let uid = |s: u32| state.sessions.get(&s).unwrap().user_id;
        let (si, sj) = (sid(&i.id), sid(&j.id));
        crate::state::test_support::put_in_channel(&state, 1, &[(uid(si), si)]).await;
        let joined_one = |m: &ServerMessage| matches!(m, ServerMessage::UserJoined { user } if user.channel_id == 1);
        for hide in [false, true] {
            state
                .channels
                .write()
                .await
                .get_mut(&1)
                .unwrap()
                .info
                .hide_members = hide;
            broadcast_user_joined(&state, user_info_for(&state, uid(sj), sj, 1)).await;
            let ServerMessage::UserJoined { user } = out.expect("UserJoined", joined_one).await
            else {
                unreachable!()
            };
            assert_eq!(
                (user.account, user.username.as_str()),
                (None, ""),
                "an outsider gets the count, no account (hide_members={hide})"
            );
            let ServerMessage::UserJoined { user } = inside.expect("UserJoined", joined_one).await
            else {
                unreachable!()
            };
            assert_eq!(
                user.account,
                Some(j.id),
                "a member sees who joined (hide_members={hide})"
            );
        }
    }

    #[tokio::test]
    async fn one_address_holds_only_a_few_of_the_sign_in_slots() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let relay = state.accounts.clone().unwrap();
        let a: IpAddr = "203.0.113.5".parse().unwrap();
        let held: Vec<_> = (0..4)
            .map(|_| relay.pending_slot(a).expect("a share"))
            .collect();
        assert!(
            relay.pending_slot(a).is_none(),
            "that address's share is used up"
        );
        assert!(
            relay.pending_slot("203.0.113.6".parse().unwrap()).is_some(),
            "another address still gets in"
        );
        let v6: Vec<_> = (0..4)
            .map(|i| {
                relay
                    .pending_slot(format!("2001:db8::{i}").parse().unwrap())
                    .expect("a share")
            })
            .collect();
        assert!(
            relay
                .pending_slot("2001:db8::99".parse().unwrap())
                .is_none(),
            "one /64 is one address"
        );
        drop((held, v6));
        assert!(relay.pending_slot(a).is_some(), "given back when they end");
    }

    #[tokio::test]
    async fn an_open_sign_up_needs_its_puzzle_solved() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let mut c = open_account(&state, "gus", AccountStart::Register { invite: None }).await;
        let Some(ServerMessage::AuthStep(AuthStep::Salt { pow: Some(pow), .. })) = c.next().await
        else {
            panic!("an open relay hands out a proof of work");
        };
        let register = AuthContinue::Register {
            auth_secret: SECRET.to_vec(),
            altcha: String::new(),
            ts: pow.ts,
            vault: vec![reset_slot()],
        };
        c.send(&ClientMessage::AuthContinue(register)).await;
        assert!(
            matches!(c.next().await, Some(ServerMessage::AuthError { reason }) if reason.contains("puzzle"))
        );
    }

    /// 1.0 (A5): bans with accounts. The account goes wherever it signs in
    /// from; the address keeps out guests and accounts without a role, but
    /// not someone holding one there (H1-07). The list names no address and
    /// lives in the database.
    #[tokio::test]
    async fn account_bans_follow_the_account_and_roles_pass_address_bans() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let (mut gina, _) = register(&state, "gina").await;
        gina.send(&ClientMessage::AdminLogin {
            token: "test-admin-token".into(),
        })
        .await;
        gina.expect("Info", |m| reply(m).is_some()).await;
        let secret = totp_on(&mut gina).await;
        gina.expect("AdminStatus", |m| {
            matches!(m, ServerMessage::AdminStatus { is_admin: true, .. })
        })
        .await;
        let (mut hank, hi) = register(&state, "hank").await;
        let hank_uid = state
            .sessions
            .get(&*state.account_sessions.get(&hi.id).unwrap())
            .unwrap()
            .user_id;
        let bans_reply = |m: &ServerMessage| {
            matches!(
                m,
                ServerMessage::AdminBans { .. } | ServerMessage::AdminError { .. }
            )
        };

        gina.send(&ClientMessage::AdminBan {
            user_id: hank_uid,
            reason: "spam".into(),
            duration_secs: 0,
            account: true,
        })
        .await;
        hank.expect(
            "Disconnected",
            |m| matches!(m, ServerMessage::Disconnected { reason } if reason.contains("spam")),
        )
        .await;
        let ServerMessage::AdminBans { bans } = gina.expect("the list", bans_reply).await else {
            panic!("refused")
        };
        assert_eq!(bans.len(), 2, "{bans:?}");
        assert!(
            bans[0].account
                && bans[0].label == "hank"
                && bans[0].by == "gina"
                && bans[0].expires_in_secs.is_none(),
            "accounts first: {bans:?}"
        );
        assert!(!bans[1].account && bans[1].label == "hank", "{bans:?}");
        let gina_sid = *state
            .account_sessions
            .get(
                &state
                    .sessions
                    .iter()
                    .find(|e| e.value().username == "gina")
                    .unwrap()
                    .account
                    .as_ref()
                    .unwrap()
                    .user
                    .id
                    .0,
            )
            .unwrap();
        assert!(
            state.sessions.contains_key(&gina_sid),
            "the admin on the same address stays"
        );
        assert!(
            refusal(&state, "lee#1234").await.contains("You are banned"),
            "a guest from the address is kept out"
        );

        // The admin signs in again from the banned address: password, code, in.
        let mut c = open_account(&state, "gina", AccountStart::Login).await;
        c.next().await;
        c.send(&ClientMessage::AuthContinue(AuthContinue::Secret {
            auth_secret: SECRET.to_vec(),
        }))
        .await;
        assert!(matches!(
            c.next().await,
            Some(ServerMessage::AuthStep(AuthStep::NeedTotp))
        ));
        let code = format!(
            "{:06}",
            l4f_accounts::totp::code_at(&secret, l4f_accounts::util::now() / 30 + 1)
        );
        c.send(&ClientMessage::AuthContinue(AuthContinue::Totp { code }))
            .await;
        c.expect("Vault", |m| {
            matches!(m, ServerMessage::AuthStep(AuthStep::Vault { .. }))
        })
        .await;
        c.send(&keys(&IDENTITY, false)).await;
        c.expect("Authenticated", |m| {
            matches!(
                m,
                ServerMessage::Authenticated {
                    account: Some(_),
                    ..
                }
            )
        })
        .await;

        // The address lifted, the account still goes, from anywhere.
        c.send(&ClientMessage::AdminUnban { id: bans[1].id }).await;
        let ServerMessage::AdminBans { bans: left } = c.expect("the list", bans_reply).await else {
            panic!("refused")
        };
        assert_eq!(left.len(), 1);
        let mut again = login(&state, "hank", &IDENTITY, false).await;
        let ServerMessage::AuthError { reason } = again
            .expect("refusal", |m| matches!(m, ServerMessage::AuthError { .. }))
            .await
        else {
            unreachable!()
        };
        assert!(
            reason.contains("This account is banned") && reason.contains("spam"),
            "{reason}"
        );
        drop(connect(&state, "lee#1234", lo).await); // guests are back

        // Kept in the database: a restarted relay reads it back.
        let mut restarted = ServerState::new(
            &ServerConfig::default(),
            ServerSettings::default(),
            Vec::new(),
            "t".into(),
        );
        restarted.accounts = state.accounts.clone();
        crate::bans::load(&restarted).await.unwrap();
        assert!(crate::bans::refusal(
            &restarted,
            "198.51.100.1".parse().unwrap(),
            Some((hi.id, false))
        )
        .is_some());

        // An account that is not here, by name.
        let (ivy, _) = register(&state, "ivy").await;
        drop(ivy);
        c.send(&ClientMessage::AdminBanAccount {
            name: "Ivy".into(),
            reason: "later".into(),
            duration_secs: 3600,
        })
        .await;
        let ServerMessage::AdminBans { bans } = c.expect("the list", bans_reply).await else {
            panic!("refused")
        };
        assert!(
            bans.iter().any(|b| b.account
                && b.label == "ivy"
                && b.expires_in_secs.is_some_and(|s| s <= 3600)),
            "{bans:?}"
        );
        c.send(&ClientMessage::AdminBanAccount {
            name: "nobody".into(),
            reason: String::new(),
            duration_secs: 0,
        })
        .await;
        assert!(matches!(
            c.expect("refused", bans_reply).await,
            ServerMessage::AdminError { .. }
        ));
    }

    /// Moderators moderate people: not admins, not each other, and never with
    /// the addresses the ban list is made of.
    #[tokio::test]
    async fn a_moderator_cannot_touch_admins_or_see_addresses() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let (mut m, mi) = register(&state, "molly").await;
        let (_boss, bi) = register(&state, "boss").await;
        let sid = |a: &[u8; 16]| *state.account_sessions.get(a).unwrap();
        state.sessions.get_mut(&sid(&mi.id)).unwrap().is_moderator = true;
        state.sessions.get_mut(&sid(&bi.id)).unwrap().is_admin = true;
        let boss_uid = state.sessions.get(&sid(&bi.id)).unwrap().user_id;
        let admin_reply = |m: &ServerMessage| {
            matches!(
                m,
                ServerMessage::AdminError { .. } | ServerMessage::AdminBans { .. }
            )
        };
        m.send(&ClientMessage::AdminKick {
            user_id: boss_uid,
            reason: String::new(),
        })
        .await;
        let ServerMessage::AdminError { reason } = m.expect("refused", admin_reply).await else {
            panic!("refused")
        };
        assert!(reason.contains("only an admin"), "{reason}");
        assert!(state.sessions.contains_key(&sid(&bi.id)), "the admin stays");
        m.send(&ClientMessage::AdminListBans).await;
        assert!(
            matches!(
                m.expect("refused", admin_reply).await,
                ServerMessage::AdminError { .. }
            ),
            "no addresses for a moderator"
        );
        // A guest from elsewhere: banned, and the moderator is told no address.
        let mut pat = connect(&state, "pat#1234", "203.0.113.9".parse().unwrap()).await;
        let pat_uid = state
            .sessions
            .iter()
            .find(|e| e.value().username == "pat#1234")
            .map(|e| e.value().user_id)
            .unwrap();
        // Out of a channel, too: the admin stays, the guest goes.
        let uid = |a: &[u8; 16]| state.sessions.get(&sid(a)).unwrap().user_id;
        let pat_sid = *state.user_to_session.get(&pat_uid).unwrap();
        crate::state::test_support::put_in_channel(
            &state,
            1,
            &[
                (uid(&mi.id), sid(&mi.id)),
                (boss_uid, sid(&bi.id)),
                (pat_uid, pat_sid),
            ],
        )
        .await;
        m.send(&ClientMessage::KickUser {
            channel_id: 1,
            user_id: boss_uid,
        })
        .await;
        let ServerMessage::ChannelError { reason } = m
            .expect("refused", |m| {
                matches!(m, ServerMessage::ChannelError { .. })
            })
            .await
        else {
            unreachable!()
        };
        assert!(reason.contains("only an admin"), "{reason}");
        assert!(
            state.channels.read().await[&1].members.contains(&boss_uid),
            "the admin stays in the channel"
        );
        m.send(&ClientMessage::KickUser {
            channel_id: 1,
            user_id: pat_uid,
        })
        .await;
        let ServerMessage::Kicked { reason, .. } = pat
            .expect("Kicked", |m| matches!(m, ServerMessage::Kicked { .. }))
            .await
        else {
            unreachable!()
        };
        assert!(reason.contains("by a moderator"), "{reason}");
        m.send(&ClientMessage::AdminBan {
            user_id: pat_uid,
            reason: String::new(),
            duration_secs: 60,
            account: true,
        })
        .await;
        m.send(&ClientMessage::AdminListBans).await;
        assert!(
            matches!(
                m.expect("refused", admin_reply).await,
                ServerMessage::AdminError { .. }
            ),
            "the ban came back without the list"
        );
        assert!(crate::bans::refusal(&state, "203.0.113.9".parse().unwrap(), None).is_some());
        drop(pat);
    }

    /// At boot, a channel that was locked in channels.json while the relay was
    /// down keeps none of the members its log had.
    #[tokio::test]
    async fn a_channel_locked_while_the_relay_was_down_starts_its_log_members_over() {
        let (state, _db, log) = relay_with_log().await;
        let (_alice, _, _) = member(&state, &log, "alice", true).await;
        let relay = state.accounts.clone().unwrap();
        let members = || async {
            crate::accounts::raw(&relay, "SELECT COUNT(*) FROM voipc_members")
                .await
                .unwrap()
        };
        crate::accounts::locked_logs_at_boot(&state).await.unwrap();
        assert_eq!(members().await, 1, "an open channel keeps its members");
        state.channels.write().await.get_mut(&1).unwrap().password = Some(zeroize::Zeroizing::new(
            crate::channels::hash_password("s3cret").unwrap(),
        ));
        crate::accounts::locked_logs_at_boot(&state).await.unwrap();
        assert_eq!(
            members().await,
            0,
            "nobody showed they know the new password"
        );
        let (_bob, _, _) = member(&state, &log, "bob", true).await;
        crate::accounts::locked_logs_at_boot(&state).await.unwrap();
        assert_eq!(
            members().await,
            1,
            "the same password again changes nothing"
        );
    }

    /// The stored copy of a channel post keeps to the channel's rules, as the
    /// post does: a log member could otherwise announce, flood a slow channel,
    /// or write from outside it.
    #[tokio::test]
    async fn a_channels_stored_copy_keeps_to_its_announce_and_slow_mode_rules() {
        use crate::state::{PostStamp, Poster};
        use voipc_crypto::sync::Event;
        let (state, _db, log) = relay_with_log().await;
        let (mut alice, a, mut sa) = member(&state, &log, "alice", true).await;
        let (_bob, _, _) = member(&state, &log, "bob", true).await;
        let not_kept = |events: &[Event]| {
            events.iter().find_map(|e| match e {
                Event::NotKept { reason } => Some(reason.clone()),
                _ => None,
            })
        };
        // Alice manages nothing here: in an announcement channel her copy is
        // refused like her post would be.
        state
            .channels
            .write()
            .await
            .get_mut(&1)
            .unwrap()
            .info
            .announce = true;
        let out = sa.send_channel(&log, say("a1", "not an announcement"), 1, None);
        let reason = not_kept(&pump(&mut alice, &mut sa, out).await).expect("refused");
        assert!(reason.contains("only moderators"), "{reason}");

        // Slow mode: one stored copy per interval, on a clock of its own.
        {
            let mut channels = state.channels.write().await;
            let c = channels.get_mut(&1).unwrap();
            c.info.announce = false;
            c.info.slow_mode_secs = 60;
        }
        let out = sa.send_channel(&log, say("s1", "first"), 2, None);
        let events = pump(&mut alice, &mut sa, out).await;
        assert!(
            events.iter().any(|e| matches!(e, Event::Kept { .. })),
            "{events:?}"
        );
        let out = sa.send_channel(&log, say("s2", "too soon"), 3, None);
        let reason = not_kept(&pump(&mut alice, &mut sa, out).await).expect("held back");
        assert!(reason.contains("slow mode"), "{reason}");
        let sid = *state.account_sessions.get(&a.id).unwrap();
        let uid = state.sessions.get(&sid).unwrap().user_id;
        assert!(
            state.post_rules(sid, uid, 1, PostStamp::Live).await.is_ok(),
            "the post itself is not held back by its copy"
        );
        assert!(state
            .post_rules(sid, uid, 1, PostStamp::Live)
            .await
            .is_err());
        assert!(
            state
                .post_marks
                .contains_key(&(1, Poster::Account(a.id), PostStamp::Live)),
            "an account's clock, which a reconnect does not reset"
        );

        // From outside the channel: refused too.
        state
            .channels
            .write()
            .await
            .get_mut(&1)
            .unwrap()
            .info
            .slow_mode_secs = 0;
        state.leave_text_channel(uid, 1).await;
        let out = sa.send_channel(&log, say("o1", "from outside"), 4, None);
        let reason = not_kept(&pump(&mut alice, &mut sa, out).await).expect("refused");
        assert!(reason.contains("not in that channel"), "{reason}");
    }

    #[tokio::test]
    async fn joiners_read_older_messages_only_from_writers_who_share() {
        let (state, _db, log) = relay_with_log().await;
        let (mut alice, _, mut sa) = member(&state, &log, "alice", true).await;
        let (mut bob, _, mut sb) = member(&state, &log, "bob", false).await;
        let out = sa.send_channel(&log, say("a1", "from alice, before"), 1, None);
        pump(&mut alice, &mut sa, out).await;
        let out = sb.send_channel(&log, say("b1", "from bob, before"), 2, None);
        pump(&mut bob, &mut sb, out).await;

        // Carol joins: both writers are here and answer her.
        let (mut carol, _, mut sc) = member(&state, &log, "carol", true).await;
        let from_alice = pump(&mut alice, &mut sa, Vec::new()).await;
        assert_eq!(
            readers(&from_alice),
            vec![(vec!["carol".to_string()], true)],
            "alice shares what she wrote before"
        );
        let from_bob = pump(&mut bob, &mut sb, Vec::new()).await;
        assert_eq!(
            readers(&from_bob),
            vec![(vec!["carol".to_string()], false)],
            "bob only lets her read what comes next"
        );
        let got = channel_texts(&pump(&mut carol, &mut sc, Vec::new()).await);
        assert_eq!(
            got,
            vec![("alice".to_string(), "from alice, before".to_string())],
            "bob's earlier message stays closed to her"
        );

        // What bob writes now, she reads.
        let out = sb.send_channel(&log, say("b2", "from bob, after"), 3, None);
        pump(&mut bob, &mut sb, out).await;
        let out = sc.enter(&log);
        let got = channel_texts(&pump(&mut carol, &mut sc, out).await);
        assert_eq!(
            got,
            vec![("bob".to_string(), "from bob, after".to_string())]
        );
    }

    #[tokio::test]
    async fn who_leaves_reads_nothing_after_and_every_new_reader_is_named() {
        let (state, _db, log) = relay_with_log().await;
        let (mut alice, _, mut sa) = member(&state, &log, "alice", true).await;
        let (mut bob, b, _) = member(&state, &log, "bob", true).await;
        let out = sa.send_channel(&log, say("m1", "both of us"), 1, None);
        pump(&mut alice, &mut sa, out).await;

        // Bob leaves: alice's next message needs a key he does not have.
        bob.send(&ClientMessage::Account(AccountRequest::LogLeave {
            conv: log.clone(),
        }))
        .await;
        // (Past the news of alice's key for him, which came first.)
        bob.expect("left", |m| {
            matches!(m, ServerMessage::Account(AccountReply::LogLeft { .. }))
        })
        .await;
        let out = sa.send_channel(&log, say("m2", "just me"), 2, None);
        let events = pump(&mut alice, &mut sa, out).await;
        assert!(
            events
                .iter()
                .any(|e| matches!(e, voipc_crypto::sync::Event::Kept { .. })),
            "kept after a new key: {events:?}"
        );
        let relay = state.accounts.clone().unwrap();
        let bobs = crate::accounts::raw(
            &relay,
            &format!("SELECT COUNT(*) FROM voipc_wraps w WHERE w.recipient = x'{}' AND w.epoch = (SELECT epoch FROM voipc_log ORDER BY seq DESC LIMIT 1)", hex::encode(b.id)),
        )
        .await
        .unwrap();
        assert_eq!(
            bobs, 0,
            "the key of what came after he left is not wrapped to him"
        );
        bob.send(&ClientMessage::Account(AccountRequest::LogFetch {
            conv: log.clone(),
            after: 0,
        }))
        .await;
        bob.expect("refused", |m| matches!(m, ServerMessage::Account(AccountReply::Error { request, .. }) if request == "LogFetch")).await;

        // A relay that makes up a member (eve, never in the channel) cannot
        // slip her in unseen: alice's client names her before her key is used.
        let (_eve, e, eve_signed) = register_with(&state, "eve").await;
        let (mut se, first) =
            voipc_crypto::sync::AccountSync::start(&eve_signed, e.id, Default::default(), true);
        let mut eve = _eve;
        pump(&mut eve, &mut se, first).await; // publishes her log key
        crate::accounts::log::join(&relay, l4f_accounts::model::AccountId(e.id), &log, true)
            .await
            .unwrap();
        let out = sa.send_channel(&log, say("m3", "who reads this?"), 3, None);
        let events = pump(&mut alice, &mut sa, out).await;
        assert!(
            readers(&events)
                .iter()
                .any(|(names, _)| names.contains(&"eve".to_string())),
            "{events:?}"
        );
    }

    #[tokio::test]
    async fn a_new_password_keeps_only_who_is_there_and_a_kick_removes_one() {
        let (state, _db, log) = relay_with_log().await;
        let (mut alice, _, _) = member(&state, &log, "alice", true).await;
        let (mut bob, b, _) = member(&state, &log, "bob", true).await;
        // Bob steps out; the channel gets a password.
        let uid = state
            .sessions
            .get(&*state.account_sessions.get(&b.id).unwrap())
            .unwrap()
            .user_id;
        state
            .channels
            .write()
            .await
            .get_mut(&1)
            .unwrap()
            .members
            .remove(&uid);
        crate::accounts::locked_log(&state, 1).await;
        let fetch = ClientMessage::Account(AccountRequest::LogFetch {
            conv: log.clone(),
            after: 0,
        });
        bob.send(&fetch).await;
        assert!(matches!(
            bob.expect("refused", |m| reply(m).is_some()).await,
            ServerMessage::Account(AccountReply::Error { .. })
        ));
        alice.send(&fetch).await;
        assert!(matches!(
            alice.expect("page", |m| reply(m).is_some()).await,
            ServerMessage::Account(AccountReply::LogPage { .. })
        ));
        // Alice is kicked from it.
        let sid = *state
            .account_sessions
            .get(
                &state
                    .sessions
                    .iter()
                    .find(|s| s.username == "alice")
                    .unwrap()
                    .account
                    .as_ref()
                    .unwrap()
                    .user
                    .id
                    .0,
            )
            .unwrap();
        crate::accounts::out_of_log(&state, 1, sid).await;
        alice.send(&fetch).await;
        assert!(matches!(
            alice.expect("refused", |m| reply(m).is_some()).await,
            ServerMessage::Account(AccountReply::Error { .. })
        ));
    }

    /// 1.0 (D10): leaving a text channel takes its account out of the log
    /// there, the relay doing it; a rejoin keeps it again.
    #[tokio::test]
    async fn leaving_a_text_channel_ends_its_readership() {
        let (state, _db, log) = relay_with_log().await;
        let (_alice, _, _) = member(&state, &log, "alice", true).await;
        let (mut bob, b, mut sb) = member(&state, &log, "bob", true).await;
        let fetch = ClientMessage::Account(AccountRequest::LogFetch {
            conv: log.clone(),
            after: 0,
        });
        bob.send(&ClientMessage::LeaveChannel { channel_id: 1 })
            .await;
        bob.expect("left", |m| {
            matches!(m, ServerMessage::UserLeft { channel_id: 1, .. })
        })
        .await;
        bob.send(&fetch).await;
        assert!(
            matches!(
                bob.expect("refused", |m| reply(m).is_some()).await,
                ServerMessage::Account(AccountReply::Error { .. })
            ),
            "no reader any more"
        );
        // His client forgets what this run knew of it, so a rejoin asks again.
        assert!(
            sb.leave(&log, false).is_empty(),
            "the relay did it: nothing to send"
        );
        into_lounge(&state, &b.id).await;
        let out = sb.enter(&log);
        assert!(
            out.iter()
                .any(|m| matches!(m, ClientMessage::Account(AccountRequest::LogJoin { .. }))),
            "{out:?}"
        );
        pump(&mut bob, &mut sb, out).await;
        bob.send(&fetch).await;
        assert!(matches!(
            bob.expect("page", |m| reply(m).is_some()).await,
            ServerMessage::Account(AccountReply::LogPage { .. })
        ));
    }

    /// 1.0 (A6): a writer deletes what they kept in a conversation; a
    /// tombstone tells the readers' devices to drop their copies too.
    #[tokio::test]
    async fn a_purge_deletes_what_i_wrote_and_a_tombstone_tells_the_readers() {
        let (state, _db, log) = relay_with_log().await;
        let (mut alice, a, mut sa) = member(&state, &log, "alice", true).await;
        let (mut bob, _, mut sb) = member(&state, &log, "bob", true).await;
        for (id, text) in [("m1", "one"), ("m2", "two")] {
            let out = sa.send_channel(&log, say(id, text), 1, None);
            pump(&mut alice, &mut sa, out).await;
        }
        let out = sb.send_channel(&log, say("b1", "bob's"), 2, None);
        pump(&mut bob, &mut sb, out).await;
        let relay = state.accounts.clone().unwrap();
        let mine = format!(
            "SELECT COUNT(*) FROM voipc_log WHERE sender = x'{}'",
            hex::encode(a.id)
        );
        assert_eq!(crate::accounts::raw(&relay, &mine).await.unwrap(), 2);

        alice
            .send(&ClientMessage::Account(AccountRequest::LogPurge {
                conv: Some(log.clone()),
            }))
            .await;
        let ServerMessage::Account(r) = alice
            .expect("purged", |m| {
                matches!(reply(m), Some(AccountReply::LogPurged { .. }))
            })
            .await
        else {
            unreachable!()
        };
        assert!(
            matches!(&r, AccountReply::LogPurged { entries: 2, .. }),
            "{r:?}"
        );
        assert_eq!(
            crate::accounts::raw(&relay, &mine).await.unwrap(),
            0,
            "hers are gone"
        );
        assert_eq!(
            crate::accounts::raw(&relay, "SELECT COUNT(*) FROM voipc_log")
                .await
                .unwrap(),
            1,
            "bob's stays: it is his"
        );
        assert!(sa.on_reply(&r).is_none(), "the front end hears of it too");
        // The tombstone, on a new key (the old one went with the purge).
        let out = sa.send_channel(
            &log,
            voipc_crypto::envelope::purge_envelope("t1", 9_000_000_000_000),
            9,
            None,
        );
        let events = pump(&mut alice, &mut sa, out).await;
        assert!(
            events
                .iter()
                .any(|e| matches!(e, voipc_crypto::sync::Event::Kept { .. })
                    || matches!(e, voipc_crypto::sync::Event::Readers { .. })),
            "{events:?}"
        );
        // Bob's device fetches it: a purge for alice, never past when the relay filed it.
        let out = sb.enter(&log);
        let events = pump(&mut bob, &mut sb, out).await;
        let wire: Vec<_> = events
            .iter()
            .filter_map(|e| e.to_wire())
            .filter(|(n, _)| *n == "stored-purge")
            .collect();
        assert_eq!(wire.len(), 1, "{events:?}");
        assert_eq!(wire[0].1["account"], hex::encode(a.id));
        assert!(
            wire[0].1["before"].as_u64().unwrap() < 9_000_000_000_000,
            "clamped to the relay's time"
        );
    }

    /// 1.0 (A6): an account deletes itself with its password; its rows go
    /// with it and its name is free again. The last admin cannot.
    #[tokio::test]
    async fn an_account_deletes_itself_and_its_name_is_free() {
        let (state, _db, log) = relay_with_log().await;
        let (mut dora, d, mut sd) = member(&state, &log, "dora", true).await;
        let out = sd.send_channel(&log, say("d1", "bye"), 1, None);
        pump(&mut dora, &mut sd, out).await;
        let relay = state.accounts.clone().unwrap();
        let secret = |pw: &str| {
            voipc_crypto::account::derive(pw, &relay.relay_id, "dora")
                .auth_secret
                .to_vec()
        };
        let delete = |secret: Vec<u8>| {
            ClientMessage::Account(AccountRequest::DeleteAccount {
                secret,
                totp: None,
                recovery_code: None,
            })
        };
        dora.send(&delete(secret("not her password"))).await;
        let msg = dora.expect("refused", |m| reply(m).is_some()).await;
        assert!(
            matches!(&msg, ServerMessage::Account(AccountReply::Error { request, .. }) if request == "DeleteAccount"),
            "{msg:?}"
        );
        dora.send(&delete(secret("correct horse battery"))).await;
        assert!(matches!(
            dora.expect("deleted", |m| reply(m).is_some()).await,
            ServerMessage::Account(AccountReply::AccountDeleted)
        ));
        dora.expect("closed", |m| {
            matches!(m, ServerMessage::Disconnected { .. })
        })
        .await;
        let id = hex::encode(d.id);
        for table in [
            "voipc_identity WHERE account",
            "voipc_logkeys WHERE account",
            "voipc_members WHERE account",
            "voipc_log WHERE sender",
            "voipc_wraps WHERE owner",
        ] {
            assert_eq!(
                crate::accounts::raw(&relay, &format!("SELECT COUNT(*) FROM {table} = x'{id}'"))
                    .await
                    .unwrap(),
                0,
                "{table}"
            );
        }
        let (_again, d2, _) = register_with(&state, "dora").await;
        assert_ne!(d2.id, d.id, "the name is free: a new account under it");

        // The only admin stays.
        let (mut gina, _) = register(&state, "gina").await;
        gina.send(&ClientMessage::AdminLogin {
            token: "test-admin-token".into(),
        })
        .await;
        gina.expect("Info", |m| reply(m).is_some()).await;
        let secret = totp_on(&mut gina).await;
        gina.expect("AdminStatus", |m| {
            matches!(m, ServerMessage::AdminStatus { is_admin: true, .. })
        })
        .await;
        let code = format!(
            "{:06}",
            l4f_accounts::totp::code_at(&secret, l4f_accounts::util::now() / 30 + 1)
        );
        gina.send(&ClientMessage::Account(AccountRequest::DeleteAccount {
            secret: SECRET.to_vec(),
            totp: Some(code),
            recovery_code: None,
        }))
        .await;
        let ServerMessage::Account(AccountReply::Error { reason, .. }) =
            gina.expect("refused", |m| reply(m).is_some()).await
        else {
            panic!("deleted the last admin")
        };
        assert!(reason.contains("last admin"), "{reason}");
    }

    #[tokio::test]
    async fn the_sweep_drops_keys_nothing_uses_any_more() {
        let (state, _db, log) = relay_with_log().await;
        let (mut alice, a, mut sa) = member(&state, &log, "alice", true).await;
        let out = sa.send_channel(&log, say("m1", "kept"), 1, None);
        pump(&mut alice, &mut sa, out).await;
        let relay = state.accounts.clone().unwrap();
        let me = hex::encode(a.id);
        // A key minted long ago that no entry uses, beside one that is used.
        crate::accounts::raw(&relay, &format!("INSERT INTO voipc_wraps (conv, owner, epoch, recipient, wrapped, created_at) VALUES ('{log}', x'{me}', 99, x'{me}', x'00', 0)")).await.unwrap();
        crate::accounts::raw(&relay, "UPDATE voipc_wraps SET created_at = 0")
            .await
            .unwrap();
        crate::accounts::log::sweep(&relay).await.unwrap();
        let count = |sql: String| {
            let relay = relay.clone();
            async move { crate::accounts::raw(&relay, &sql).await.unwrap() }
        };
        assert_eq!(
            count("SELECT COUNT(*) FROM voipc_wraps WHERE epoch = 99".into()).await,
            0,
            "the unused key went"
        );
        assert!(
            count("SELECT COUNT(*) FROM voipc_wraps".into()).await > 0,
            "the used one stayed"
        );
        assert_eq!(count("SELECT COUNT(*) FROM voipc_log".into()).await, 1);
    }

    /// An accounts database as 0.12.0 left it (tests/fixtures/0.12.0, written
    /// once by 0.12.0's own code, see its README): this version opens it with
    /// its key file and migrates it, bob signs in with his password, and he
    /// still reads the DM alice kept for him then.
    #[tokio::test]
    async fn a_0_12_accounts_database_opens_signs_in_and_keeps_its_messages() {
        use voipc_crypto::log::{open_entry, unwrap, LogKey};
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/0.12.0");
        let meta: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("accounts.json")).unwrap())
                .unwrap();
        let tmp = std::env::temp_dir().join(format!(
            "voipc-upgrade-{}",
            hex::encode(rand::random::<[u8; 8]>())
        ));
        std::fs::create_dir_all(&tmp).unwrap();
        for f in ["voipc.db", "accounts.key"] {
            std::fs::copy(dir.join(f), tmp.join(f)).unwrap();
        }
        let mut config = ServerConfig::default();
        config.accounts.mode = AccountsMode::Optional;
        config.accounts.registration = RegistrationMode::Open;
        config.accounts.database = format!("sqlite://{}", tmp.join("voipc.db").display());
        config.accounts.key_file = tmp.join("accounts.key").display().to_string();
        let relay = crate::accounts::Relay::open(&config.accounts)
            .await
            .unwrap();
        assert_eq!(hex::encode(relay.relay_id), meta["relay_id"]);
        let mut state = ServerState::new(
            &config,
            ServerSettings::default(),
            Vec::new(),
            "test-admin-token".into(),
        );
        state.accounts = Some(Arc::new(relay));
        let state = Arc::new(state);

        let (mut bob, b, _) = sign_in_password(&state, "bob").await;
        assert_eq!(hex::encode(b.id), meta["bob"]);
        let conv = meta["conv"].as_str().unwrap().to_string();
        bob.send(&ClientMessage::Account(AccountRequest::WrapsFetch {
            conv: conv.clone(),
        }))
        .await;
        let ServerMessage::Account(AccountReply::Wraps { wraps, .. }) =
            bob.expect("wraps", |m| reply(m).is_some()).await
        else {
            panic!()
        };
        let bob_lk =
            LogKey::from_bytes(&hex::decode(meta["bob_logkey"].as_str().unwrap()).unwrap())
                .unwrap();
        let key = unwrap(
            &bob_lk,
            &wraps[0].wrapped,
            &conv,
            &wraps[0].owner,
            wraps[0].epoch,
            &b.id,
        )
        .unwrap();
        bob.send(&ClientMessage::Account(AccountRequest::LogFetch {
            conv: conv.clone(),
            after: 0,
        }))
        .await;
        let ServerMessage::Account(AccountReply::LogPage { entries, .. }) =
            bob.expect("page", |m| reply(m).is_some()).await
        else {
            panic!()
        };
        let alice_lk = hex::decode(meta["alice_logkey_public"].as_str().unwrap()).unwrap();
        let (envelope, _) = open_entry(
            &key,
            &conv,
            &entries[0].sender,
            entries[0].epoch,
            &alice_lk,
            &entries[0].ct,
        )
        .unwrap();
        assert_eq!(
            voipc_crypto::envelope::open_envelope(&envelope).text,
            meta["text"]
        );
        drop(bob);
        drop(state);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ── Files (protocol v13) ─────────────────────────────────────────────

    use crate::files::test_support::{blob, path_of, state_with_files};

    const HERE: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

    /// One whole-blob `PUT` through the HTTP handler both carriers share.
    async fn put_blob(
        state: &Arc<ServerState>,
        hash: &[u8; 32],
        ticket: &str,
        bytes: &[u8],
    ) -> u16 {
        let target = format!("{}?offset=0", path_of(hash));
        let auth = format!("Bearer {ticket}");
        let body = Bytes::copy_from_slice(bytes);
        crate::files::http(state, HERE, "PUT", &target, Some(&auth), None, body)
            .await
            .status
    }

    async fn get_blob(state: &Arc<ServerState>, hash: &[u8; 32], ticket: &str) -> (u16, Bytes) {
        let auth = format!("Bearer {ticket}");
        let reply = crate::files::http(
            state,
            HERE,
            "GET",
            &path_of(hash),
            Some(&auth),
            None,
            Bytes::new(),
        )
        .await;
        (reply.status, reply.body)
    }

    async fn upload_ready(client: &mut Client) -> String {
        match client
            .expect("FileUploadReady", |m| {
                matches!(m, ServerMessage::FileUploadReady { .. })
            })
            .await
        {
            ServerMessage::FileUploadReady { ticket, .. } => ticket,
            _ => unreachable!(),
        }
    }

    async fn ready(client: &mut Client) -> (String, u64) {
        match client
            .expect("FileReady", |m| {
                matches!(m, ServerMessage::FileReady { .. })
            })
            .await
        {
            ServerMessage::FileReady { ticket, size, .. } => (ticket, size),
            _ => unreachable!(),
        }
    }

    async fn refused(client: &mut Client) -> String {
        match client
            .expect("FileRefused", |m| {
                matches!(m, ServerMessage::FileRefused { .. })
            })
            .await
        {
            ServerMessage::FileRefused { reason, .. } => reason,
            _ => unreachable!(),
        }
    }

    #[tokio::test]
    async fn a_relay_with_files_says_so_and_one_without_refuses_them() {
        let (state, _dir) = state_with_files(|c| c.max_size_mb = 3);
        let mut alice = open(&state, "alice", HERE).await;
        let ServerMessage::Authenticated { files, .. } = alice
            .expect("Authenticated", |m| {
                matches!(m, ServerMessage::Authenticated { .. })
            })
            .await
        else {
            unreachable!()
        };
        assert_eq!(files.map(|f| f.max_bytes), Some(3 * 1024 * 1024));

        let state = admin_state();
        let mut bob = open(&state, "bob", HERE).await;
        let ServerMessage::Authenticated { files, .. } = bob
            .expect("Authenticated", |m| {
                matches!(m, ServerMessage::Authenticated { .. })
            })
            .await
        else {
            unreachable!()
        };
        assert!(files.is_none());
        let (_, hash) = blob(10, 1);
        bob.send(&ClientMessage::FileFetch {
            conv: FileConv::Channel(1),
            hash,
        })
        .await;
        assert!(refused(&mut bob).await.contains("keeps no files"));
    }

    #[tokio::test]
    async fn a_file_posted_in_a_channel_reaches_its_members_only() {
        let (state, _dir) = state_with_files(|_| {});
        let mut alice = connect(&state, "alice", HERE).await;
        let mut bob = connect(&state, "bob", HERE).await;
        let mut carol = connect(&state, "carol", HERE).await;
        let channel = text_channel_with_two(&mut alice, &mut bob, "files").await;
        let conv = FileConv::Channel(channel);
        let (bytes, hash) = blob(3000, 2);

        // Carol is not in it: she may neither post nor fetch there
        carol
            .send(&ClientMessage::FileUpload {
                conv,
                size: 3000,
                hash,
            })
            .await;
        refused(&mut carol).await;
        alice
            .send(&ClientMessage::FileUpload {
                conv,
                size: 3000,
                hash,
            })
            .await;
        let ticket = upload_ready(&mut alice).await;
        assert_eq!(put_blob(&state, &hash, &ticket, &bytes).await, 201);
        alice
            .expect("FileStored", |m| {
                matches!(m, ServerMessage::FileStored { .. })
            })
            .await;

        bob.send(&ClientMessage::FileFetch { conv, hash }).await;
        let (ticket, size) = ready(&mut bob).await;
        assert_eq!(size, 3000);
        assert_eq!(
            get_blob(&state, &hash, &ticket).await,
            (206, Bytes::from(bytes))
        );
        carol.send(&ClientMessage::FileFetch { conv, hash }).await;
        refused(&mut carol).await;
        assert_eq!(get_blob(&state, &hash, "not-a-ticket").await.0, 401);
    }

    #[tokio::test]
    async fn a_file_in_a_direct_conversation_is_for_its_two_parties() {
        let (state, _dir) = state_with_files(|_| {});
        let mut alice = connect(&state, "alice", HERE).await;
        let mut bob = connect(&state, "bob", HERE).await;
        let mut carol = connect(&state, "carol", HERE).await;
        let id = |name: &str| {
            *state
                .user_to_session
                .get(&*state.username_to_session.get(name).unwrap())
                .unwrap()
        };
        let (alice_id, bob_id) = (id("alice"), id("bob"));
        let (bytes, hash) = blob(3000, 3);

        alice
            .send(&ClientMessage::FileUpload {
                conv: FileConv::Direct(bob_id),
                size: 3000,
                hash,
            })
            .await;
        let ticket = upload_ready(&mut alice).await;
        assert_eq!(put_blob(&state, &hash, &ticket, &bytes).await, 201);

        // Bob names the same conversation from his end
        bob.send(&ClientMessage::FileFetch {
            conv: FileConv::Direct(alice_id),
            hash,
        })
        .await;
        ready(&mut bob).await;
        // Carol's conversation with Alice is another one: the file is sought
        // there, and Alice's app answers only for a message there that names it
        carol
            .send(&ClientMessage::FileFetch {
                conv: FileConv::Direct(alice_id),
                hash,
            })
            .await;
        carol
            .expect("FileSeeking", |m| {
                matches!(m, ServerMessage::FileSeeking { .. })
            })
            .await;
        let carol_id = id("carol");
        alice
            .expect("FileWanted in carol's conversation", |m| {
                matches!(m, ServerMessage::FileWanted { conv: FileConv::Direct(who), .. } if *who == carol_id)
            })
            .await;
        // Nobody has a conversation with themselves
        alice
            .send(&ClientMessage::FileFetch {
                conv: FileConv::Direct(alice_id),
                hash,
            })
            .await;
        refused(&mut alice).await;
    }

    /// The blob has gone: the channel's other members are asked, without a
    /// word about who asked; the one who has it uploads it again, and the
    /// asker is served.
    #[tokio::test]
    async fn a_member_who_has_the_file_brings_it_back() {
        let (state, _dir) = state_with_files(|_| {});
        let mut alice = connect(&state, "alice", HERE).await;
        let mut bob = connect(&state, "bob", HERE).await;
        let channel = text_channel_with_two(&mut alice, &mut bob, "files").await;
        let conv = FileConv::Channel(channel);
        let (bytes, hash) = blob(3000, 4);
        alice
            .send(&ClientMessage::FileUpload {
                conv,
                size: 3000,
                hash,
            })
            .await;
        let ticket = upload_ready(&mut alice).await;
        put_blob(&state, &hash, &ticket, &bytes).await;
        alice
            .expect("FileStored", |m| {
                matches!(m, ServerMessage::FileStored { .. })
            })
            .await;
        // Long enough later for the blob to have gone
        let store = state.files.clone().unwrap();
        crate::files::deliver(
            &state,
            store.sweep(Instant::now() + Duration::from_secs(25 * 3600)),
        )
        .await;

        bob.send(&ClientMessage::FileFetch { conv, hash }).await;
        bob.expect("FileSeeking", |m| {
            matches!(m, ServerMessage::FileSeeking { .. })
        })
        .await;
        let wanted = alice
            .expect("FileWanted", |m| {
                matches!(m, ServerMessage::FileWanted { .. })
            })
            .await;
        assert!(matches!(
            wanted,
            ServerMessage::FileWanted { conv: FileConv::Channel(c), hash: h } if c == channel && h == hash
        ));
        alice
            .send(&ClientMessage::FileUpload {
                conv,
                size: 3000,
                hash,
            })
            .await;
        let ticket = upload_ready(&mut alice).await;
        assert_eq!(put_blob(&state, &hash, &ticket, &bytes).await, 201);
        let (ticket, _) = ready(&mut bob).await;
        assert_eq!(get_blob(&state, &hash, &ticket).await.1, Bytes::from(bytes));
    }

    /// An uploader who leaves hands the upload to the next member with it.
    #[tokio::test]
    async fn an_upload_left_behind_passes_to_the_next_member() {
        let (state, _dir) = state_with_files(|_| {});
        let mut alice = connect(&state, "alice", HERE).await;
        let mut bob = connect(&state, "bob", HERE).await;
        let channel = text_channel_with_two(&mut alice, &mut bob, "files").await;
        let conv = FileConv::Channel(channel);
        let (bytes, hash) = blob(3000, 5);
        alice
            .send(&ClientMessage::FileUpload {
                conv,
                size: 3000,
                hash,
            })
            .await;
        upload_ready(&mut alice).await;
        bob.send(&ClientMessage::FileUpload {
            conv,
            size: 3000,
            hash,
        })
        .await;
        // A session's messages are handled in order: past the Pong, Bob is
        // queued behind Alice. Then Alice goes.
        bob.send(&ClientMessage::Ping { timestamp: 7 }).await;
        bob.expect("Pong", |m| {
            matches!(m, ServerMessage::Pong { timestamp: 7 })
        })
        .await;
        drop(alice);
        let ticket = upload_ready(&mut bob).await;
        assert_eq!(put_blob(&state, &hash, &ticket, &bytes).await, 201);
        bob.expect("FileStored", |m| {
            matches!(m, ServerMessage::FileStored { .. })
        })
        .await;
    }

    #[tokio::test]
    async fn a_cancel_spends_the_ticket() {
        let (state, _dir) = state_with_files(|_| {});
        let mut alice = connect(&state, "alice", HERE).await;
        let mut bob = connect(&state, "bob", HERE).await;
        let channel = text_channel_with_two(&mut alice, &mut bob, "files").await;
        let conv = FileConv::Channel(channel);
        let (bytes, hash) = blob(3000, 6);
        alice
            .send(&ClientMessage::FileUpload {
                conv,
                size: 3000,
                hash,
            })
            .await;
        let ticket = upload_ready(&mut alice).await;
        alice.send(&ClientMessage::FileCancel { hash }).await;
        tokio::time::timeout(Duration::from_secs(5), async {
            while put_blob(&state, &hash, &ticket, &bytes).await != 401 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the ticket is spent");
    }

    /// A kept conversation is between two accounts that exist: a made-up
    /// one is refused, and so is a guest naming one.
    #[tokio::test]
    async fn a_file_for_an_away_account_needs_a_real_account() {
        let dir = crate::files::test_support::TempDir::new();
        let files = crate::files::test_support::config_in(&dir);
        let (state, _db) = relay_state_then(AccountsMode::Optional, RegistrationMode::Open, |s| {
            s.files = Some(Arc::new(crate::files::FileStore::open(&files).unwrap()));
        })
        .await;
        let (mut alice, _) = register(&state, "alice").await;
        let (away, bob) = register(&state, "bob").await;
        drop(away);
        let (_, hash) = blob(3000, 8);
        alice
            .send(&ClientMessage::FileUpload {
                conv: FileConv::Account([0x42; 16]),
                size: 3000,
                hash,
            })
            .await;
        refused(&mut alice).await;
        alice
            .send(&ClientMessage::FileUpload {
                conv: FileConv::Account(bob.id),
                size: 3000,
                hash,
            })
            .await;
        upload_ready(&mut alice).await;

        let mut guest = connect(&state, "dave#1234", HERE).await;
        guest
            .send(&ClientMessage::FileFetch {
                conv: FileConv::Account(bob.id),
                hash,
            })
            .await;
        refused(&mut guest).await;
    }

    /// Asking for a blob that has gone reaches the channel's other members,
    /// and nobody outside it.
    #[tokio::test]
    async fn only_members_are_asked_for_a_file() {
        let (state, _dir) = state_with_files(|_| {});
        let mut alice = connect(&state, "alice", HERE).await;
        let mut bob = connect(&state, "bob", HERE).await;
        let mut carol = connect(&state, "carol", HERE).await;
        let channel = text_channel_with_two(&mut alice, &mut bob, "files").await;
        let conv = FileConv::Channel(channel);
        let (bytes, hash) = blob(3000, 9);
        alice
            .send(&ClientMessage::FileUpload {
                conv,
                size: 3000,
                hash,
            })
            .await;
        let ticket = upload_ready(&mut alice).await;
        put_blob(&state, &hash, &ticket, &bytes).await;
        let store = state.files.clone().unwrap();
        crate::files::deliver(
            &state,
            store.sweep(Instant::now() + Duration::from_secs(25 * 3600)),
        )
        .await;
        bob.send(&ClientMessage::FileFetch { conv, hash }).await;
        bob.expect("FileSeeking", |m| {
            matches!(m, ServerMessage::FileSeeking { .. })
        })
        .await;
        alice
            .expect("FileWanted", |m| {
                matches!(m, ServerMessage::FileWanted { .. })
            })
            .await;
        // Carol's connection is in order: past her Pong, any FileWanted for
        // her would have arrived
        carol.send(&ClientMessage::Ping { timestamp: 9 }).await;
        loop {
            match carol.next().await {
                Some(ServerMessage::Pong { timestamp: 9 }) => break,
                Some(ServerMessage::FileWanted { .. }) => panic!("a non-member was asked"),
                Some(_) => {}
                None => panic!("carol's connection closed"),
            }
        }
    }
}
