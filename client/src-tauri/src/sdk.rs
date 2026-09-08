//! Game SDK: a loopback WebSocket a game mod connects to, so the game can
//! place every player in the voice mix.
//!
//! This is the open replacement for the TeamSpeak plugins RP servers use today
//! (SaltyChat, YACA, TokoVOIP): same shape — a page inside the game runtime
//! opens a socket to 127.0.0.1 and pushes a bulk position update a few times a
//! second — but no plugin to install, no license server, and players are
//! addressed by their VoIPC user id instead of by matching nicknames.
//!
//! Wire protocol (one JSON object per text frame), documented in docs/SDK.md:
//!
//! game → VoIPC
//!   {"type":"hello","sdk":1,"game":"fivem","resource":"my-voice",
//!    "server":"rp.example.com:9987","channel":"Ingame","password":"…"}
//!   {"type":"update","self":{"pos":[x,y,z],"fwd":[fx,fy],"range":8.0},
//!    "players":[{"id":42,"pos":[x,y,z],"range":8.0,"volume":1.0,"muffle":0},
//!               {"id":7,"mode":"radio","volume":0.8}]}
//!   {"type":"ping"} {"type":"bye"}
//!
//! VoIPC → game
//!   {"type":"state","state":"ingame","user_id":42,"username":"Luki",
//!    "channel":"Ingame","proximity":"3d","muted":false,"deafened":false,
//!    "version":"0.6.0","sdk":1,"capabilities":["spatial","direct","volume","muffle"]}
//!   {"type":"pong"} {"type":"error","reason":"…"}
//!
//! Security: the listener binds loopback only, is off until the user turns it
//! on in Settings, and rejects browser origins that are not a known game
//! runtime (any web page can open a WebSocket to localhost). It exposes
//! positions and talk state and nothing else — no chat, no keys, no channel
//! joins beyond the one named in `hello`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use base64::Engine as _;
use serde::Deserialize;
use tauri::{Emitter, Manager};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, warn};

use voipc_audio::spatial::{Listener, Source, DEFAULT_RANGE, MAX_MUFFLE};
use voipc_protocol::types::ProximityMode;

use crate::app_state::AppState;

/// RFC 6455 handshake constant.
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
/// Largest HTTP upgrade request we read before giving up.
const MAX_HANDSHAKE: usize = 8 * 1024;
/// Largest WebSocket frame we accept (a bulk update of a full server).
const MAX_FRAME: usize = 64 * 1024;
/// What this build actually renders; scripts read it instead of guessing.
/// No "talk": nothing pushes speaking or mute state to the mod yet.
const CAPABILITIES: &[&str] = &["spatial", "direct", "volume", "muffle"];

/// Origin prefixes allowed without configuration: the game runtimes' own web
/// views, whose origin carries the resource name after the prefix.
const DEFAULT_ORIGIN_PREFIXES: &[&str] = &[
    "https://cfx-nui-", // FiveM / RedM NUI
    "http://resource/", // alt:V
    "http://package/",  // RAGE:MP CEF
];

/// Hosts allowed without configuration. Matched exactly (a port may follow):
/// a prefix match would accept `https://localhost.attacker.example`, which is
/// an ordinary internet page that can reach loopback like any other.
const DEFAULT_ORIGIN_HOSTS: &[&str] = &[
    "http://localhost",
    "https://localhost",
    "http://127.0.0.1",
    "https://127.0.0.1",
];

// ── Wire types ───────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum GameMessage {
    Hello(Hello),
    Update(Update),
    Ping,
    Bye,
}

#[derive(Debug, Deserialize)]
struct Hello {
    /// SDK protocol version the mod speaks.
    #[serde(default = "one")]
    sdk: u32,
    #[serde(default)]
    game: String,
    #[serde(default)]
    resource: String,
    /// The server the mod expects us to be on, as `host:port`.
    #[serde(default)]
    server: Option<String>,
    /// Channel to join by name (the game's ingame channel).
    #[serde(default)]
    channel: Option<String>,
    #[serde(default)]
    password: Option<String>,
}

fn one() -> u32 {
    1
}

#[derive(Debug, Deserialize)]
struct Update {
    #[serde(rename = "self")]
    own: Option<SelfState>,
    #[serde(default)]
    players: Vec<PlayerState>,
}

#[derive(Debug, Deserialize)]
struct SelfState {
    pos: [f32; 3],
    /// Facing in the x/y plane. `yaw` (degrees, 0 = +y, counter-clockwise) is
    /// accepted instead, because that is what the GTA natives hand a script.
    #[serde(default)]
    fwd: Option<[f32; 2]>,
    #[serde(default)]
    yaw: Option<f32>,
}

#[derive(Debug, Deserialize)]
struct PlayerState {
    /// The player's VoIPC user id, published by the game server.
    id: u32,
    #[serde(default)]
    pos: Option<[f32; 3]>,
    /// Distance at which this player becomes inaudible (whisper/normal/shout).
    #[serde(default)]
    range: Option<f32>,
    #[serde(default)]
    volume: Option<f32>,
    /// Occlusion 0–10, as SaltyChat and YACA use it.
    #[serde(default)]
    muffle: Option<u8>,
    /// "spatial" (default), "direct", "radio" or "phone". Radio and phone
    /// render as direct for now; `capabilities` says so.
    #[serde(default)]
    mode: Option<String>,
}

// ── The listener ─────────────────────────────────────────────────────────

/// Watches the `sdk_enabled` setting and runs the listener while it is on.
pub fn spawn(app: tauri::AppHandle) {
    tauri::async_runtime::spawn(async move {
        let mut running: Option<tauri::async_runtime::JoinHandle<()>> = None;
        let mut bound_port: u16 = 0;
        loop {
            let (enabled, port) = {
                let state = app.state::<AppState>();
                let config = match state.config.lock() {
                    Ok(c) => c,
                    Err(poisoned) => poisoned.into_inner(),
                };
                (config.sdk_enabled, config.sdk_port)
            };

            let wants_restart = running.is_some() && (!enabled || port != bound_port);
            if wants_restart {
                if let Some(handle) = running.take() {
                    handle.abort();
                    info!("game SDK listener stopped");
                }
            }
            if enabled && running.is_none() {
                match TcpListener::bind(("127.0.0.1", port)).await {
                    Ok(listener) => {
                        info!(port, "game SDK listening on 127.0.0.1");
                        bound_port = port;
                        running = Some(tauri::async_runtime::spawn(accept_loop(
                            listener,
                            app.clone(),
                        )));
                    }
                    Err(e) => warn!(port, "game SDK could not bind 127.0.0.1: {e}"),
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    });
}

/// One game at a time: the newest connection that completes a `hello` owns the
/// mix, which is how a game restart should behave. Older sockets, and every
/// connection that never got that far (a port scan, a page from a refused
/// origin, `curl`), can no longer clear the owner's positions on their way out.
async fn accept_loop(listener: TcpListener, app: tauri::AppHandle) {
    // Generation of the connection that currently owns the mix; 0 = nobody.
    let owner = Arc::new(AtomicU64::new(0));
    let mut generation: u64 = 0;
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                warn!("game SDK accept failed: {e}");
                // A permanent error (out of file descriptors) would otherwise
                // spin this loop at full speed
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };
        if !peer.ip().is_loopback() {
            continue; // cannot happen on a loopback bind, but be explicit
        }
        generation += 1;
        let my_generation = generation;
        let app = app.clone();
        let owner = owner.clone();
        tauri::async_runtime::spawn(async move {
            if let Err(e) = serve(stream, &app, &owner, my_generation).await {
                info!("game SDK connection ended: {e}");
            }
            // Only the owner hands the mix back; a socket that was replaced by
            // a newer one, or never said hello, leaves the state alone.
            if owner
                .compare_exchange(my_generation, 0, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                clear_sdk_positions(&app).await;
                if let Ok(mut game) = app.state::<AppState>().sdk_game.lock() {
                    *game = None;
                }
                let _ = app.emit(
                    "sdk-status",
                    serde_json::json!({"connected": false, "game": "", "resource": ""}),
                );
            }
        });
    }
}

async fn serve(
    mut stream: TcpStream,
    app: &tauri::AppHandle,
    owner: &Arc<AtomicU64>,
    generation: u64,
) -> anyhow::Result<()> {
    let allowed = {
        let state = app.state::<AppState>();
        let config = match state.config.lock() {
            Ok(c) => c,
            Err(poisoned) => poisoned.into_inner(),
        };
        config.sdk_allowed_origins.clone()
    };
    handshake(&mut stream, &allowed).await?;

    let mut buf: Vec<u8> = Vec::new();
    let mut bad_messages = 0u8;
    // The VoIPC user id we had when this game said hello. The server hands out
    // new ids on every connection, so after a reconnect the mod's ids name
    // nobody — and every player it lists would fall out of the mix silently.
    let mut hello_user_id: Option<u32> = None;
    loop {
        let frame = match read_frame(&mut stream, &mut buf).await? {
            Some(f) => f,
            None => {
                // The peer closed: echo the close frame and go
                let _ = write_frame(&mut stream, 0x8, &1000u16.to_be_bytes()).await;
                return Ok(());
            }
        };
        let Frame::Text(text) = frame else { continue };

        match serde_json::from_str::<GameMessage>(&text) {
            Ok(GameMessage::Hello(hello)) => {
                bad_messages = 0;
                let game = if hello.game.is_empty() {
                    "a game".to_string()
                } else {
                    hello.game.clone()
                };
                let reply = on_hello(app, &hello).await;
                // Only a game that is actually in the channel owns the mix,
                // and only then does the panel say a game is connected
                if reply.get("state").and_then(|s| s.as_str()) == Some("ingame") {
                    owner.store(generation, Ordering::SeqCst);
                    hello_user_id = reply.get("user_id").and_then(|v| v.as_u64()).map(|v| v as u32);
                    if let Ok(mut current) = app.state::<AppState>().sdk_game.lock() {
                        *current = Some(game.clone());
                    }
                    let _ = app.emit(
                        "sdk-status",
                        serde_json::json!({
                            "connected": true,
                            "game": game,
                            "resource": hello.resource,
                        }),
                    );
                }
                send_text(&mut stream, &reply.to_string()).await?;
            }
            Ok(GameMessage::Update(update)) => {
                bad_messages = 0;
                if owner.load(Ordering::SeqCst) != generation {
                    send_text(
                        &mut stream,
                        r#"{"type":"error","reason":"send hello first"}"#,
                    )
                    .await?;
                    continue;
                }
                match apply_update(app, update, hello_user_id).await {
                    Ok(()) => {}
                    Err(reason) => {
                        send_text(
                            &mut stream,
                            &serde_json::json!({"type": "error", "reason": reason}).to_string(),
                        )
                        .await?;
                    }
                }
            }
            Ok(GameMessage::Ping) => {
                send_text(&mut stream, r#"{"type":"pong"}"#).await?;
            }
            Ok(GameMessage::Bye) => {
                // Close properly, so the mod sees a normal close instead of a
                // dropped connection and does not treat it as a crash
                let _ = write_frame(&mut stream, 0x8, &1000u16.to_be_bytes()).await;
                return Ok(());
            }
            Err(e) => {
                bad_messages += 1;
                send_text(
                    &mut stream,
                    &serde_json::json!({"type": "error", "reason": e.to_string()}).to_string(),
                )
                .await?;
                if bad_messages >= 3 {
                    anyhow::bail!("three malformed messages in a row");
                }
            }
        }
    }
}

/// Answer a `hello`: report who and where we are, and join the named channel.
async fn on_hello(app: &tauri::AppHandle, hello: &Hello) -> serde_json::Value {
    let state = app.state::<AppState>();
    let conn = state.connection.read().await;
    let Some(connection) = conn.as_ref() else {
        return state_message("disconnected", None, None);
    };

    // A mod that thinks we are on another server must not drive our audio: it
    // would place people using coordinates from a different game session. The
    // field is required, so a mod cannot skip the check by leaving it out.
    let actual = connection.server_address.clone();
    match hello.server.as_deref() {
        Some(expected) if actual.is_empty() || server_matches(expected, &actual) => {}
        _ => return state_message("wrong_server", Some(connection), None),
    }

    if hello.sdk != 1 {
        return serde_json::json!({
            "type": "error",
            "reason": format!("unsupported SDK version {}", hello.sdk),
        });
    }

    // Join the ingame channel by name, if the mod named one
    let channel = hello.channel.as_deref().and_then(|name| {
        connection
            .channels
            .lock()
            .ok()
            .and_then(|list| list.iter().find(|c| c.name == name).cloned())
    });
    if let (Some(name), None) = (hello.channel.as_deref(), channel.as_ref()) {
        return serde_json::json!({
            "type": "error",
            "reason": format!("no channel named {name}"),
        });
    }

    // From here on the game owns the positions
    if let Ok(mut spatial) = connection.spatial.lock() {
        spatial.sdk_active = true;
        spatial.sync = false;
        spatial.clear_positions();
    }

    let reply = state_message(
        "ingame",
        Some(connection),
        channel.as_ref().map(|c| c.name.clone()),
    );

    // Send the join without the connection guard: a stalled control stream
    // would otherwise park this task inside the lock, and the next
    // connect/disconnect would wait behind a game.
    let join = channel.as_ref().and_then(|target| {
        (connection.current_channel_id.load(Ordering::Relaxed) != target.channel_id)
            .then(|| (connection.tcp_tx.clone(), target.channel_id))
    });
    drop(conn);
    if let Some((tcp_tx, channel_id)) = join {
        let _ = crate::network::send_tcp_message(
            &tcp_tx,
            &voipc_protocol::messages::ClientMessage::JoinChannel {
                channel_id,
                password: hello.password.clone(),
            },
        )
        .await;
    }

    reply
}

/// Apply one bulk update. Players the game leaves out are silent — that is how
/// SaltyChat and YACA cull by distance, and scripts rely on it.
async fn apply_update(
    app: &tauri::AppHandle,
    update: Update,
    hello_user_id: Option<u32>,
) -> Result<(), String> {
    let state = app.state::<AppState>();
    let conn = state.connection.read().await;
    let connection = conn.as_ref().ok_or("not connected to a server")?;

    // The server issues fresh user ids on every connection: after a VoIPC
    // reconnect the mod's ids name nobody, and applying them would cull every
    // speaker out of the mix in silence. Tell the mod to say hello again.
    if let Some(id) = hello_user_id {
        if id != connection.user_id {
            return Err("reconnected to the server — send hello again".into());
        }
    }

    let mut spatial = connection.spatial.lock().unwrap_or_else(|p| p.into_inner());

    if let Some(own) = update.own {
        if !own.pos.iter().all(|c| c.is_finite()) {
            return Err("self position must be finite".into());
        }
        spatial.listener = Listener {
            pos: own.pos,
            fwd: facing(own.fwd, own.yaw),
        };
    }

    let mut sources: HashMap<u32, Source> = HashMap::with_capacity(update.players.len());
    for player in update.players {
        let direct = matches!(player.mode.as_deref(), Some("direct" | "radio" | "phone"));
        let pos = player.pos.unwrap_or([0.0; 3]);
        if !pos.iter().all(|c| c.is_finite()) {
            return Err(format!("position of player {} must be finite", player.id));
        }
        // Every float is checked: one NaN range would make the gains NaN and,
        // through the mixer's ramp state, silence that source for good.
        let range = player.range.filter(|r| r.is_finite()).unwrap_or(DEFAULT_RANGE);
        let volume = player.volume.filter(|v| v.is_finite()).unwrap_or(1.0);
        sources.insert(
            player.id,
            Source {
                pos,
                range: range.max(0.01),
                volume: volume.clamp(0.0, 2.0),
                muffle: player.muffle.unwrap_or(0).min(MAX_MUFFLE),
                direct,
            },
        );
    }
    spatial.sources = sources;
    spatial.sdk_active = true;
    Ok(())
}

/// The game is gone: hand the mix back to the plain per-user volumes. Waits
/// for the lock — a `try_read` that loses a race with connect/disconnect would
/// leave SDK culling armed with no game, i.e. everyone silent.
async fn clear_sdk_positions(app: &tauri::AppHandle) {
    let state = app.state::<AppState>();
    let conn = state.connection.read().await;
    if let Some(connection) = conn.as_ref() {
        let mut spatial = connection.spatial.lock().unwrap_or_else(|p| p.into_inner());
        spatial.sdk_active = false;
        spatial.clear_positions();
    }
}

fn state_message(
    state: &str,
    connection: Option<&crate::app_state::ActiveConnection>,
    channel: Option<String>,
) -> serde_json::Value {
    let mut msg = serde_json::json!({
        "type": "state",
        "state": state,
        "version": env!("CARGO_PKG_VERSION"),
        "sdk": 1,
        "capabilities": CAPABILITIES,
    });
    if let Some(c) = connection {
        let proximity = c
            .spatial
            .lock()
            .map(|s| s.mode)
            .unwrap_or(ProximityMode::Off);
        msg["user_id"] = c.user_id.into();
        msg["username"] = c.username.clone().into();
        msg["muted"] = c.is_muted.load(Ordering::Relaxed).into();
        msg["deafened"] = c.is_deafened.load(Ordering::Relaxed).into();
        msg["proximity"] = serde_json::to_value(proximity).unwrap_or(serde_json::Value::Null);
        if let Some(name) = channel {
            msg["channel"] = name.into();
        }
    }
    msg
}

/// Unit forward vector from either form the mod may send.
fn facing(fwd: Option<[f32; 2]>, yaw: Option<f32>) -> [f32; 2] {
    if let Some(f) = fwd {
        let len = (f[0] * f[0] + f[1] * f[1]).sqrt();
        if len.is_finite() && len > 1e-6 {
            return [f[0] / len, f[1] / len];
        }
    }
    if let Some(deg) = yaw.filter(|d| d.is_finite()) {
        // GTA heading: 0 faces +y, increasing counter-clockwise
        let rad = deg.to_radians();
        return [-rad.sin(), rad.cos()];
    }
    [0.0, 1.0]
}

/// Do two `host:port` strings name the same server? A missing port on either
/// side means "any port", so a mod may just say the host.
fn server_matches(expected: &str, actual: &str) -> bool {
    let split = |s: &str| -> (String, Option<String>) {
        match s.rsplit_once(':') {
            Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => {
                (h.to_ascii_lowercase(), Some(p.to_string()))
            }
            _ => (s.to_ascii_lowercase(), None),
        }
    };
    let (eh, ep) = split(expected);
    let (ah, ap) = split(actual);
    eh == ah && (ep.is_none() || ap.is_none() || ep == ap)
}

// ── WebSocket (the subset a game's web view speaks) ──────────────────────

// ponytail: text frames, no fragmentation, no extensions — a NUI page sends
// one small JSON object per frame. tokio-tungstenite if a client ever needs
// more than that.

enum Frame {
    Text(String),
    Other,
}

async fn handshake(stream: &mut TcpStream, extra_origins: &[String]) -> anyhow::Result<()> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    let head = loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            anyhow::bail!("client closed during handshake");
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(end) = find_header_end(&buf) {
            break String::from_utf8_lossy(&buf[..end]).into_owned();
        }
        if buf.len() > MAX_HANDSHAKE {
            anyhow::bail!("handshake too large");
        }
    };

    let mut key = None;
    let mut origin = None;
    for line in head.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        match name.trim().to_ascii_lowercase().as_str() {
            "sec-websocket-key" => key = Some(value.trim().to_string()),
            "origin" => origin = Some(value.trim().to_string()),
            _ => {}
        }
    }

    // Any web page can open a WebSocket to loopback, so only the game
    // runtimes' own origins (plus whatever the user allowed) get through.
    if let Some(origin) = origin.as_deref() {
        if !origin_allowed(origin, extra_origins) {
            let _ = stream
                .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                .await;
            warn!(origin, "game SDK rejected a connection from an unknown origin");
            anyhow::bail!("origin not allowed: {origin}");
        }
    }

    let key = key.ok_or_else(|| anyhow::anyhow!("no Sec-WebSocket-Key"))?;
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {}\r\n\r\n",
        accept_key(&key)
    );
    stream.write_all(response.as_bytes()).await?;
    Ok(())
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

/// RFC 6455: base64(SHA-1(key + GUID)).
fn accept_key(key: &str) -> String {
    let digest = ring::digest::digest(
        &ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
        format!("{key}{WS_GUID}").as_bytes(),
    );
    base64::engine::general_purpose::STANDARD.encode(digest.as_ref())
}

fn origin_allowed(origin: &str, extra: &[String]) -> bool {
    let origin = origin.trim();
    let host_match = |host: &str| {
        // Exactly the host, or the host followed by a port — never a longer
        // name that merely starts with it
        origin == host || origin.strip_prefix(host).is_some_and(|rest| rest.starts_with(':'))
    };
    DEFAULT_ORIGIN_PREFIXES.iter().any(|p| origin.starts_with(p))
        || DEFAULT_ORIGIN_HOSTS.iter().any(|h| host_match(h))
        // What the user typed into Settings is matched exactly, for the same reason
        || extra.iter().any(|p| p == origin)
}

/// Reads one frame. `Ok(None)` means the peer closed.
async fn read_frame(stream: &mut TcpStream, buf: &mut Vec<u8>) -> anyhow::Result<Option<Frame>> {
    let header = read_exact(stream, buf, 2).await?;
    let Some(header) = header else { return Ok(None) };
    let opcode = header[0] & 0x0f;
    let fin = header[0] & 0x80 != 0;
    let masked = header[1] & 0x80 != 0;
    let mut len = (header[1] & 0x7f) as usize;

    if !fin {
        anyhow::bail!("fragmented frames are not supported");
    }
    if len == 126 {
        let ext = read_exact(stream, buf, 2).await?.ok_or_else(eof)?;
        len = u16::from_be_bytes([ext[0], ext[1]]) as usize;
    } else if len == 127 {
        let ext = read_exact(stream, buf, 8).await?.ok_or_else(eof)?;
        len = u64::from_be_bytes(ext[..8].try_into().unwrap()) as usize;
    }
    if len > MAX_FRAME {
        anyhow::bail!("frame of {len} bytes exceeds the {MAX_FRAME} byte limit");
    }

    let mask = if masked {
        let m = read_exact(stream, buf, 4).await?.ok_or_else(eof)?;
        Some([m[0], m[1], m[2], m[3]])
    } else {
        None
    };
    let mut payload = read_exact(stream, buf, len).await?.ok_or_else(eof)?;
    if let Some(mask) = mask {
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[i % 4];
        }
    }

    match opcode {
        0x1 => Ok(Some(Frame::Text(String::from_utf8(payload)?))),
        0x8 => Ok(None),                                   // close
        0x9 => {                                           // ping
            write_frame(stream, 0xA, &payload).await?;
            Ok(Some(Frame::Other))
        }
        _ => Ok(Some(Frame::Other)),
    }
}

fn eof() -> anyhow::Error {
    anyhow::anyhow!("connection closed mid-frame")
}

async fn read_exact(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    n: usize,
) -> anyhow::Result<Option<Vec<u8>>> {
    while buf.len() < n {
        let mut chunk = [0u8; 4096];
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&chunk[..read]);
    }
    Ok(Some(buf.drain(..n).collect()))
}

async fn send_text(stream: &mut TcpStream, text: &str) -> anyhow::Result<()> {
    write_frame(stream, 0x1, text.as_bytes()).await
}

async fn write_frame(stream: &mut TcpStream, opcode: u8, payload: &[u8]) -> anyhow::Result<()> {
    let mut frame = Vec::with_capacity(payload.len() + 10);
    frame.push(0x80 | opcode);
    // Server frames are never masked
    if payload.len() < 126 {
        frame.push(payload.len() as u8);
    } else if payload.len() <= u16::MAX as usize {
        frame.push(126);
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        frame.push(127);
        frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    frame.extend_from_slice(payload);
    stream.write_all(&frame).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_key_matches_the_rfc_example() {
        // RFC 6455 §1.3
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn origins_are_limited_to_game_runtimes_unless_allowed() {
        assert!(origin_allowed("https://cfx-nui-my-voice", &[]));
        assert!(origin_allowed("http://resource/voice", &[]));
        assert!(origin_allowed("http://localhost:3000", &[]));
        assert!(origin_allowed("http://localhost", &[]));
        assert!(origin_allowed("http://127.0.0.1:8080", &[]));
        // A page from the internet cannot drive the mix, even from loopback
        assert!(!origin_allowed("https://evil.example", &[]));
        assert!(!origin_allowed("null", &[]));
        // …until the user allows it (a file:// test page sends "null")
        assert!(origin_allowed("null", &["null".to_string()]));
        assert!(origin_allowed(
            "https://evil.example",
            &["https://evil.example".to_string()]
        ));
    }

    #[test]
    fn an_ordinary_host_that_merely_starts_with_localhost_is_refused() {
        // Anyone can register localhost.attacker.example and point it anywhere;
        // the page it serves reaches 127.0.0.1 like any other page.
        for origin in [
            "https://localhost.attacker.example",
            "http://127.0.0.1.attacker.example",
            "http://localhost-evil.example",
        ] {
            assert!(!origin_allowed(origin, &[]), "{origin} must be refused");
        }
        // An allowed origin is matched exactly too, not as a prefix
        let allowed = vec!["https://my.game".to_string()];
        assert!(origin_allowed("https://my.game", &allowed));
        assert!(!origin_allowed("https://my.game.evil.example", &allowed));
    }

    #[test]
    fn server_match_ignores_a_missing_port() {
        assert!(server_matches("rp.example.com:9987", "rp.example.com:9987"));
        assert!(server_matches("rp.example.com", "rp.example.com:9987"));
        assert!(server_matches("RP.Example.com:9987", "rp.example.com:9987"));
        assert!(!server_matches("rp.example.com:9988", "rp.example.com:9987"));
        assert!(!server_matches("other.example.com", "rp.example.com:9987"));
    }

    #[test]
    fn facing_accepts_a_vector_or_a_gta_heading() {
        assert_eq!(facing(Some([0.0, 5.0]), None), [0.0, 1.0]);
        let east = facing(None, Some(270.0));
        assert!((east[0] - 1.0).abs() < 1e-5, "east = {east:?}");
        assert!(east[1].abs() < 1e-5);
        // Garbage falls back to "facing up the screen"
        assert_eq!(facing(Some([0.0, 0.0]), None), [0.0, 1.0]);
        assert_eq!(facing(None, Some(f32::NAN)), [0.0, 1.0]);
    }

    #[test]
    fn hello_and_update_parse_from_the_documented_shapes() {
        let hello: GameMessage = serde_json::from_str(
            r#"{"type":"hello","sdk":1,"game":"fivem","resource":"my-voice",
                "server":"rp.example.com:9987","channel":"Ingame"}"#,
        )
        .unwrap();
        match hello {
            GameMessage::Hello(h) => {
                assert_eq!(h.game, "fivem");
                assert_eq!(h.channel.as_deref(), Some("Ingame"));
            }
            _ => panic!("wrong variant"),
        }

        let update: GameMessage = serde_json::from_str(
            r#"{"type":"update","self":{"pos":[1,2,3],"yaw":90},
                "players":[{"id":42,"pos":[4,5,6],"range":8,"muffle":6},
                           {"id":7,"mode":"radio","volume":0.8}]}"#,
        )
        .unwrap();
        match update {
            GameMessage::Update(u) => {
                assert_eq!(u.players.len(), 2);
                assert_eq!(u.players[0].id, 42);
                assert_eq!(u.players[0].muffle, Some(6));
                assert_eq!(u.players[1].mode.as_deref(), Some("radio"));
                assert!(u.own.is_some());
            }
            _ => panic!("wrong variant"),
        }

        assert!(matches!(
            serde_json::from_str::<GameMessage>(r#"{"type":"ping"}"#).unwrap(),
            GameMessage::Ping
        ));
        assert!(serde_json::from_str::<GameMessage>(r#"{"type":"nonsense"}"#).is_err());
    }

    #[test]
    fn frames_are_written_with_the_right_length_form() {
        let short = frame_bytes(0x1, &vec![b'x'; 10]);
        assert_eq!(short[0], 0x81);
        assert_eq!(short[1], 10);

        let medium = frame_bytes(0x1, &vec![b'x'; 200]);
        assert_eq!(medium[1], 126);
        assert_eq!(u16::from_be_bytes([medium[2], medium[3]]), 200);

        let long = frame_bytes(0x1, &vec![b'x'; 70_000]);
        assert_eq!(long[1], 127);
        assert_eq!(
            u64::from_be_bytes(long[2..10].try_into().unwrap()),
            70_000
        );
    }

    /// The framing half of `write_frame`, without a socket.
    fn frame_bytes(opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.push(0x80 | opcode);
        if payload.len() < 126 {
            frame.push(payload.len() as u8);
        } else if payload.len() <= u16::MAX as usize {
            frame.push(126);
            frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        } else {
            frame.push(127);
            frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        }
        frame.extend_from_slice(payload);
        frame
    }
}
