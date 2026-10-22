//! Relay accounts on the desktop: the sign-in on a fresh control stream, the
//! code the person types in mid-way, and the commands the front end manages
//! its account with.
//!
//! The rules are shared with the browser: the sign-in is
//! `voipc_crypto::account::SignIn`, and what follows it — the stored log, the
//! pins, remembering this device — is `voipc_crypto::account_session`. This
//! file only moves their messages, asks the person, and keeps what they hand
//! over in the local archive.

use std::sync::Arc;

use bytes::BytesMut;
use serde::{Deserialize, Serialize};
use tauri::{Manager, State};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tracing::{info, warn};
use voipc_crypto::account::{normalize_name, password_ok, DeviceKey, Method, SignIn, Step, Zeroizing};
use voipc_crypto::account_session::{memory_key, AccountSession, Actions};
use voipc_crypto::sync::Prefs;
use voipc_protocol::codec::{decode_server_msg, encode_client_msg, try_decode_frame, APP_VERSION, PROTOCOL_VERSION};
use voipc_protocol::conv::{hex, unhex16};
use voipc_protocol::messages::{AccountReply, AccountRequest, ClientMessage, ServerMessage};

use crate::app_state::{AppState, SignalState};
use crate::crypto::DeviceRecord;
use crate::network::emit_server;
use crate::transport::CONNECT_TIMEOUT;

/// What a guest is told by a relay that takes none. connect.ts looks for it.
pub const ACCOUNT_REQUIRED: &str = "This server needs an account: sign in or create one.";

/// How the front end wants this connection to sign in.
#[derive(Deserialize, Clone)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum AccountArgs {
    /// With the password (a device the relay does not know yet).
    Login { password: String },
    /// Make the account.
    Register { password: String, invite: Option<String> },
    /// With the key this device was given here before.
    Device,
}

/// What an account connection keeps: the shared session, fed and carried
/// out here.
pub struct AccountLink {
    session: std::sync::Mutex<AccountSession>,
}

impl AccountLink {
    /// The session, for one call; what it returns goes to `run`.
    pub fn session(&self) -> std::sync::MutexGuard<'_, AccountSession> {
        self.session.lock().unwrap_or_else(|p| p.into_inner())
    }
}

/// What the session asked for: its messages out, its events to the front
/// end, and what this device keeps of it in the local archive (only in memory
/// while the archive is switched off).
pub async fn run(app: &tauri::AppHandle, server: &str, tcp_tx: &mpsc::UnboundedSender<Vec<u8>>, a: Actions) {
    for m in &a.send {
        crate::network::send_tcp_message_sync(tcp_tx, m);
    }
    for (name, payload) in a.emit {
        emit_server(app, server, name, payload);
    }
    if a.remember.is_none() && a.memory.is_none() {
        return;
    }
    let state = app.state::<AppState>();
    let mut chat = state.chat.write().await;
    if let Some(r) = a.remember {
        chat.archive.devices.retain(|d| !(d.relay_id == r.relay_id && d.name == r.name));
        chat.archive.devices.push(DeviceRecord {
            server: server.to_string(),
            relay_id: r.relay_id,
            name: r.name,
            device_id: r.device_id,
            device_key: r.device_key.to_vec(),
            dek: *r.dek,
        });
        info!(server, "this device is remembered");
    }
    if let Some((key, memory)) = a.memory {
        chat.archive.cursors.insert(key, memory);
    }
    chat.dirty = true;
}

/// The person's answer to "a code from your authenticator app".
pub struct TotpAnswer {
    pub code: String,
    pub recovery: bool,
}

async fn write<S: AsyncWrite + Unpin>(send: &mut S, msg: &ClientMessage) -> Result<(), String> {
    let data = encode_client_msg(msg).map_err(|e| format!("encode: {e}"))?;
    send.write_all(&data).await.map_err(|e| format!("Connection lost during sign-in: {e}"))
}

async fn read<R: AsyncRead + Unpin>(recv: &mut R, buf: &mut BytesMut) -> Result<ServerMessage, String> {
    loop {
        if let Some(payload) = try_decode_frame(buf).map_err(|e| format!("Frame decode error: {e}"))? {
            return decode_server_msg(&payload).map_err(|e| format!("Failed to decode response: {e}"));
        }
        let n = tokio::time::timeout(CONNECT_TIMEOUT, recv.read_buf(buf))
            .await
            .map_err(|_| "Timed out waiting for the server during sign-in".to_string())?
            .map_err(|e| format!("Failed to read from the server: {e}"))?;
        if n == 0 {
            return Err("Server closed connection during sign-in".into());
        }
    }
}

/// Signs in on a connection that has not sent `Authenticate` yet. Makes the
/// connection's Signal stores (with the account's identity) on the way.
#[allow(clippy::too_many_arguments)]
pub async fn sign_in<S: AsyncWrite + Unpin, R: AsyncRead + Unpin>(
    state: &AppState,
    app: &tauri::AppHandle,
    server: &str,
    username: &str,
    args: AccountArgs,
    signal: &Arc<std::sync::Mutex<SignalState>>,
    send: &mut S,
    recv: &mut R,
    buf: &mut BytesMut,
) -> Result<(u32, u32, Arc<AccountLink>), String> {
    let name = normalize_name(username)?;
    let method = match args {
        AccountArgs::Login { password } => Method::Password { password: Zeroizing::new(password) },
        AccountArgs::Register { password, invite } => {
            password_ok(&password)?;
            Method::Register { password: Zeroizing::new(password), invite }
        }
        AccountArgs::Device => {
            let chat = state.chat.read().await;
            let rec = chat
                .archive
                .devices
                .iter()
                .find(|d| d.server == server && d.name == name)
                .ok_or("This device is not remembered on this server. Sign in with your password.")?;
            let key = DeviceKey::from_parts(rec.device_id, rec.device_key.clone()).ok_or("This device's key is damaged. Sign in with your password.")?;
            Method::Device { key, relay_id: rec.relay_id, dek: rec.dek }
        }
    };
    let password_based = !matches!(method, Method::Device { .. });
    let (mut machine, first) = SignIn::start(&name, method, PROTOCOL_VERSION, APP_VERSION);
    let known_here = {
        let cfg = state.config();
        let here = cfg.relay_ids.get(server).and_then(|h| unhex16(h));
        let elsewhere = cfg.relay_ids.iter().filter(|(s, _)| s.as_str() != server).filter_map(|(s, h)| Some((unhex16(h)?, s.clone()))).collect();
        machine.expect_relay(here, elsewhere);
        here
    };
    write(send, &first).await?;

    let mut asked = 0u32;
    let (user_id, session_id, info) = loop {
        let msg = read(recv, buf).await?;
        if let ServerMessage::Authenticated { user_id, session_id, account: Some(info), accounts } = msg {
            if let Some(accounts) = accounts {
                emit_server(app, server, "relay-accounts", accounts);
            }
            break (user_id, session_id, info);
        }
        // The password's stretching runs here: half a second of CPU, kept
        // off the other tasks on this worker.
        let steps = tokio::task::block_in_place(|| machine.on_message(&msg))?;
        for step in steps {
            match step {
                Step::Send(out) => write(send, &out).await?,
                Step::Keys => {
                    let identity = *machine.identity().ok_or("no identity")?;
                    let bundle = crate::network::init_signal(signal, &identity)?;
                    write(send, &machine.keys(bundle)).await?;
                }
                Step::NeedTotp => {
                    let answer = ask_totp(state, app, server, asked > 0).await?;
                    asked += 1;
                    let out = if answer.recovery { machine.recovery_code(&answer.code) } else { machine.totp(&answer.code) };
                    write(send, &out).await?;
                }
                Step::Ignore => {}
            }
        }
    };

    let signed = machine.finish()?;
    if known_here != Some(signed.relay_id) {
        let mut cfg = state.config();
        cfg.relay_ids.insert(server.to_string(), hex(&signed.relay_id));
        if let Err(e) = crate::config::save_config(&cfg) {
            warn!(server, "could not remember the relay id: {e}");
        }
    }
    let memory = state.chat.read().await.archive.cursors.get(&memory_key(&signed.relay_id, &signed.name)).cloned().unwrap_or_default();
    // Joiners of a channel's log get our older keys on the same consent as
    // handing them the channel's history in person.
    let share = state.config().share_channel_history;
    info!(server, account = %signed.name, "signed in to account");
    let (session, started) = AccountSession::start(signed, &info, memory, share, password_based);
    // Nothing to send yet (the sync's first asks wait for `after_connect`);
    // the front end hears it signed in, its choices along with it.
    for (name, payload) in started.emit {
        emit_server(app, server, name, payload);
    }
    Ok((user_id, session_id, Arc::new(AccountLink { session: std::sync::Mutex::new(session) })))
}

/// Asks the front end for a code and waits for `account_totp`. The relay
/// waits two minutes; so does this.
async fn ask_totp(state: &AppState, app: &tauri::AppHandle, server: &str, retry: bool) -> Result<TotpAnswer, String> {
    let (tx, rx) = oneshot::channel();
    state.totp_answers.lock().unwrap_or_else(|p| p.into_inner()).insert(server.to_string(), tx);
    emit_server(app, server, "account-need-totp", retry);
    let answer = tokio::time::timeout(std::time::Duration::from_secs(115), rx).await;
    state.totp_answers.lock().unwrap_or_else(|p| p.into_inner()).remove(server);
    match answer {
        Ok(Ok(a)) => Ok(a),
        Ok(Err(_)) => Err("Sign-in cancelled.".into()),
        Err(_) => Err("No code was entered in time.".into()),
    }
}

/// Once the connection's writer runs: what the sync asks first, then the
/// second-factor setup a role waits for, or remembering this device.
pub async fn after_connect(app: &tauri::AppHandle, server: &str, link: &AccountLink, tcp_tx: &mpsc::UnboundedSender<Vec<u8>>) {
    let a = link.session().after_connect();
    run(app, server, tcp_tx, a).await;
}

/// The identities the Signal stores took in while one server message was
/// handled — a session a peer opened among them, which no bundle check sees —
/// against the pins, as a fetched bundle's is. Taken on every connection, so
/// a guest's list does not grow.
pub async fn check_seen(
    app: &tauri::AppHandle,
    server: &str,
    link: Option<&AccountLink>,
    signal: &std::sync::Mutex<SignalState>,
    tcp_tx: &mpsc::UnboundedSender<Vec<u8>>,
) {
    let seen = signal.lock().unwrap_or_else(|p| p.into_inner()).stores.as_mut().map(|s| s.identity.take_seen()).unwrap_or_default();
    let Some(link) = link else { return };
    for (user_id, key) in seen {
        let a = link.session().check_identity(user_id, &key);
        run(app, server, tcp_tx, a).await;
    }
}

/// An `AccountReply` on an account connection.
pub async fn on_reply(app: &tauri::AppHandle, server: &str, link: &AccountLink, tcp_tx: &mpsc::UnboundedSender<Vec<u8>>, reply: AccountReply) {
    if let AccountReply::Error { request, reason } = &reply {
        if request.starts_with("Device") {
            warn!(server, "could not remember this device: {reason}");
        }
    }
    let a = link.session().on_reply(&reply);
    run(app, server, tcp_tx, a).await;
}

// ── Commands ──────────────────────────────────────────────────────────────

/// The connection to `server` and the account it signed in with.
fn signed_in<'a>(connections: &'a crate::app_state::Connections, server: &str) -> Result<(&'a crate::app_state::ActiveConnection, &'a Arc<AccountLink>), String> {
    let connection = connections.get(server).ok_or("Not connected to that server")?;
    let link = connection.account.as_ref().ok_or("Not signed in to an account on that server")?;
    Ok((connection, link))
}

/// This account's choices (cloud copies), as its vault has them.
#[tauri::command]
pub async fn account_prefs(state: State<'_, AppState>, server: String) -> Result<Prefs, String> {
    let connections = state.connections.read().await;
    let (_, link) = signed_in(&connections, &server)?;
    let prefs = link.session().prefs();
    Ok(prefs)
}

/// A direct message for an account that is away (`account`, hex): kept in the
/// stored log only, which is the one way it reaches them. Returns its id, for
/// the front end's own copy.
#[tauri::command]
pub async fn send_kept_dm(
    state: State<'_, AppState>,
    app: tauri::AppHandle,
    server: String,
    account: String,
    content: String,
    ttl_secs: Option<u32>,
) -> Result<String, String> {
    let connections = state.connections.read().await;
    let (connection, link) = signed_in(&connections, &server)?;
    let id = crate::crypto::new_message_id();
    let payload = crate::crypto::envelope(&id, &content, ttl_secs);
    let a = link.session().kept_dm(&account, payload, crate::crypto::now_ms(), ttl_secs)?;
    run(&app, &server, &connection.tcp_tx, a).await;
    Ok(id)
}

/// Keep channel log `conv` from now on (cloud copies just turned on, while
/// already in the channel).
#[tauri::command]
pub async fn account_enter(state: State<'_, AppState>, app: tauri::AppHandle, server: String, conv: String) -> Result<(), String> {
    let connections = state.connections.read().await;
    let (connection, link) = signed_in(&connections, &server)?;
    let a = link.session().enter(&conv);
    run(&app, &server, &connection.tcp_tx, a).await;
    Ok(())
}

/// Forget the relay id remembered for `server` (it moved, or was set up
/// again); the next account sign-in there remembers the new one.
#[tauri::command]
pub fn forget_relay_id(state: State<'_, AppState>, server: String) -> Result<bool, String> {
    let mut cfg = state.config();
    let had = cfg.relay_ids.remove(&server).is_some();
    crate::config::save_config(&cfg)?;
    Ok(had)
}

#[tauri::command]
pub async fn account_set_prefs(state: State<'_, AppState>, app: tauri::AppHandle, server: String, prefs: Prefs) -> Result<(), String> {
    let connections = state.connections.read().await;
    let (connection, link) = signed_in(&connections, &server)?;
    let a = link.session().set_prefs(prefs);
    run(&app, &server, &connection.tcp_tx, a).await;
    Ok(())
}

/// The safety number with `user_id` on `server`: both of us signed in to
/// accounts there, and their identity pinned.
#[tauri::command]
pub async fn safety_number(state: State<'_, AppState>, server: String, user_id: u32) -> Result<String, String> {
    let connections = state.connections.read().await;
    let connection = connections.get(&server).ok_or("Not connected to that server")?;
    let link = connection.account.as_ref().ok_or("Sign in to an account to verify people")?;
    let (own_key, live) = {
        let sig = connection.signal.lock().map_err(|e| e.to_string())?;
        let stores = sig.stores.as_ref().ok_or("no identity yet")?;
        (stores.identity.key_pair.public_key.clone(), stores.identity.identity_of(user_id).map(<[u8]>::to_vec))
    };
    let number = link.session().safety_number(user_id, &own_key, live.as_deref());
    number
}

/// The authenticator app's QR code for an `otpauth://` link, drawn on this
/// device (an SVG from the relay would be markup the relay wrote).
#[tauri::command]
pub fn qr_svg(text: String) -> Result<String, String> {
    if !text.starts_with("otpauth://") || text.len() > 512 {
        return Err("not an authenticator link".into());
    }
    voipc_crypto::account::qr_svg(&text).ok_or_else(|| "could not draw the code".into())
}

/// The code (or a recovery code) for a sign-in waiting on one.
#[tauri::command]
pub async fn account_totp(state: State<'_, AppState>, server: String, code: String, recovery: Option<bool>) -> Result<(), String> {
    let waiting = state.totp_answers.lock().unwrap_or_else(|p| p.into_inner()).remove(&server);
    match waiting {
        Some(tx) => tx.send(TotpAnswer { code, recovery: recovery.unwrap_or(false) }).map_err(|_| "That sign-in is over.".to_string()),
        None => Err("No sign-in is waiting for a code.".into()),
    }
}

/// Ends a sign-in waiting for a code (the person closed the prompt).
#[tauri::command]
pub async fn account_cancel(state: State<'_, AppState>, server: String) -> Result<(), String> {
    state.totp_answers.lock().unwrap_or_else(|p| p.into_inner()).remove(&server);
    Ok(())
}

/// An account request on a signed-in connection (codes, the vault).
#[tauri::command]
pub async fn account_request(state: State<'_, AppState>, server: String, request: AccountRequest) -> Result<(), String> {
    let connections = state.connections.read().await;
    let (connection, _) = signed_in(&connections, &server)?;
    crate::network::send_tcp_message_sync(&connection.tcp_tx, &ClientMessage::Account(request));
    Ok(())
}

#[derive(Serialize)]
pub struct RememberedDevice {
    server: String,
    name: String,
    relay_id: String,
}

/// The servers this device is remembered on, and as whom.
#[tauri::command]
pub async fn account_devices(state: State<'_, AppState>) -> Result<Vec<RememberedDevice>, String> {
    let chat = state.chat.read().await;
    Ok(chat
        .archive
        .devices
        .iter()
        .map(|d| RememberedDevice { server: d.server.clone(), name: d.name.clone(), relay_id: hex(&d.relay_id) })
        .collect())
}

/// Forget this device's key for an account here (the relay keeps its half
/// until it expires or the account removes it).
#[tauri::command]
pub async fn forget_device(state: State<'_, AppState>, server: String, name: String) -> Result<(), String> {
    let mut chat = state.chat.write().await;
    // What it read there, and who it named as readers, goes with it.
    let relays: Vec<[u8; 16]> = chat.archive.devices.iter().filter(|d| d.server == server && d.name == name).map(|d| d.relay_id).collect();
    for relay_id in relays {
        chat.archive.cursors.remove(&memory_key(&relay_id, &name));
    }
    chat.archive.devices.retain(|d| !(d.server == server && d.name == name));
    chat.dirty = true;
    Ok(())
}
