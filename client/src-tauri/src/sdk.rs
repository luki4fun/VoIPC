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
//!    "version":"0.7.0","sdk":1,
//!    "capabilities":["spatial","direct","volume","muffle","radio","phone","talk"]}
//!   {"type":"talk","user_id":42,"speaking":true}
//!   {"type":"self","muted":false,"deafened":false,"speaking":true}
//!   {"type":"user","user_id":7,"muted":true}
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

use voipc_audio::spatial::{Effect, Listener, Source, DEFAULT_RANGE, MAX_MUFFLE};
use voipc_protocol::types::ProximityMode;

use crate::app_state::{AppState, Motion, SdkEvent, MAX_GLIDE, MIN_GLIDE};

/// RFC 6455 handshake constant.
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
/// Largest HTTP upgrade request we read before giving up.
const MAX_HANDSHAKE: usize = 8 * 1024;
/// Largest WebSocket frame we accept (a bulk update of a full server).
const MAX_FRAME: usize = 64 * 1024;
/// A connection has this long to finish its HTTP upgrade.
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// No frame at all for this long (a live mod pings) closes the socket.
const IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// Sockets served at once. One game needs one; the rest is slack for a
/// reconnect racing a dying socket.
const MAX_CONNECTIONS: usize = 4;
/// How long `hello` waits for the server to confirm the channel join.
const JOIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
/// What this build actually renders; scripts read it instead of guessing.
const CAPABILITIES: &[&str] = &["spatial", "direct", "volume", "muffle", "radio", "phone", "talk"];

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
    /// "spatial" (default), "direct", "radio" or "phone". The last three
    /// ignore position; radio and phone add an effect chain.
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
                    // Aborting takes the connections with it, and an aborted
                    // task runs no teardown: hand the mix back here.
                    clear_sdk_positions(&app).await;
                    if let Ok(mut game) = app.state::<AppState>().sdk_game.lock() {
                        *game = None;
                    }
                    let _ = app.emit(
                        "sdk-status",
                        serde_json::json!({"connected": false, "game": "", "resource": ""}),
                    );
                }
            }
            if !enabled {
                publish_listening(&app, None);
            }
            if enabled && running.is_none() {
                match TcpListener::bind(("127.0.0.1", port)).await {
                    Ok(listener) => {
                        info!(port, "game SDK listening on 127.0.0.1");
                        bound_port = port;
                        publish_listening(&app, None);
                        running = Some(tauri::async_runtime::spawn(accept_loop(
                            listener,
                            app.clone(),
                        )));
                    }
                    Err(e) => {
                        // Retried every second, so the message is published
                        // only when it changes — otherwise this would spam
                        // the UI once a second forever.
                        warn!(port, "game SDK could not bind 127.0.0.1: {e}");
                        publish_listening(
                            &app,
                            Some(format!("could not listen on 127.0.0.1:{port}: {e}")),
                        );
                    }
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    });
}

/// Record why the listener is not running (or that it is), and tell Settings
/// when that changes. Called once a second, so it must stay quiet otherwise.
fn publish_listening(app: &tauri::AppHandle, error: Option<String>) {
    let state = app.state::<AppState>();
    let mut slot = match state.sdk_listen_error.lock() {
        Ok(s) => s,
        Err(poisoned) => poisoned.into_inner(),
    };
    if *slot == error {
        return;
    }
    *slot = error.clone();
    let _ = app.emit(
        "sdk-status",
        serde_json::json!({"listening": error.is_none(), "error": error}),
    );
}

/// One game at a time: the newest connection that completes a `hello` owns the
/// mix, which is how a game restart should behave. Older sockets, and every
/// connection that never got that far (a port scan, a page from a refused
/// origin, `curl`), can no longer clear the owner's positions on their way out.
async fn accept_loop(listener: TcpListener, app: tauri::AppHandle) {
    // Generation of the connection that currently owns the mix; 0 = nobody.
    let owner = Arc::new(AtomicU64::new(0));
    let mut generation: u64 = 0;
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    // The connections belong to this loop: dropping the set (which is what
    // aborting this task does) aborts them too, so switching the integration
    // off in Settings really does disconnect the game rather than leaving it
    // driving the mix through a listener that no longer accepts.
    let mut connections = tokio::task::JoinSet::new();
    loop {
        // Reap finished connections so the set does not grow for the session
        while connections.try_join_next().is_some() {}
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
        // Nothing else limits sockets: without this a local process could open
        // them in a loop until the app runs out of file descriptors.
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            connections.spawn(async move {
                let mut stream = stream;
                reject(&mut stream, "503 Service Unavailable").await;
            });
            continue;
        };
        generation += 1;
        let my_generation = generation;
        let app = app.clone();
        let owner = owner.clone();
        connections.spawn(async move {
            let _permit = permit; // released when this connection ends
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
    // A socket that connects and then says nothing must not pin a task
    let mut buf = tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake(&mut stream, &allowed))
        .await
        .map_err(|_| anyhow::anyhow!("handshake timed out"))??;
    let (mut rd, mut wr) = stream.into_split();

    let mut bad_messages = 0u8;
    // The VoIPC user id we had when this game said hello. The server hands out
    // new ids on every connection, so after a reconnect the mod's ids name
    // nobody — and every player it lists would fall out of the mix silently.
    let mut hello_user_id: Option<u32> = None;
    // Mute, deafen and speaking as this socket last heard them, so every
    // `self` message it receives is complete.
    let mut own = Own::default();
    let mut events = app.state::<AppState>().sdk_events.subscribe();
    // A deadline, not a per-iteration timeout: the select loop goes round on
    // every talk event too, and a fresh `timeout` would restart the clock each
    // time — a wedged socket would then live as long as anyone kept talking.
    let mut deadline = tokio::time::Instant::now() + IDLE_TIMEOUT;

    loop {
        tokio::select! {
            // Nothing at all for IDLE_TIMEOUT means the mod (or the game) is
            // gone; a live one pings well inside that.
            read = tokio::time::timeout_at(deadline, read_frame(&mut rd, &mut buf)) => {
                deadline = tokio::time::Instant::now() + IDLE_TIMEOUT;
                let frame = match read {
                    Err(_) => { close(&mut wr, 1001).await; anyhow::bail!("idle for {IDLE_TIMEOUT:?}"); }
                    Ok(Err(e)) => { close(&mut wr, 1002).await; return Err(e); }
                    Ok(Ok(None)) => { close(&mut wr, 1000).await; return Ok(()); }
                    Ok(Ok(Some(f))) => f,
                };
                let text = match frame {
                    Frame::Text(text) => text,
                    Frame::Ping(payload) => { write_frame(&mut wr, 0xA, &payload).await?; continue; }
                    Frame::Close | Frame::Other => continue,
                };

                match serde_json::from_str::<GameMessage>(&text) {
                    Ok(GameMessage::Hello(hello)) => {
                        bad_messages = 0;
                        let game = if hello.game.is_empty() {
                            "a game".to_string()
                        } else {
                            hello.game.clone()
                        };
                        let reply = on_hello(app, &hello).await;
                        // Only a game that is actually in the channel owns the
                        // mix, and only then does the panel say one is connected
                        if reply.get("state").and_then(|s| s.as_str()) == Some("ingame") {
                            owner.store(generation, Ordering::SeqCst);
                            hello_user_id =
                                reply.get("user_id").and_then(|v| v.as_u64()).map(|v| v as u32);
                            own.muted = reply.get("muted").and_then(|v| v.as_bool()).unwrap_or(false);
                            own.deafened =
                                reply.get("deafened").and_then(|v| v.as_bool()).unwrap_or(false);
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
                        send_text(&mut wr, &reply.to_string()).await?;
                    }
                    Ok(GameMessage::Update(update)) => {
                        bad_messages = 0;
                        if owner.load(Ordering::SeqCst) != generation {
                            send_text(&mut wr, r#"{"type":"error","reason":"send hello first"}"#)
                                .await?;
                            continue;
                        }
                        if let Err(reason) = apply_update(app, update, hello_user_id).await {
                            send_text(
                                &mut wr,
                                &serde_json::json!({"type": "error", "reason": reason}).to_string(),
                            )
                            .await?;
                        }
                    }
                    Ok(GameMessage::Ping) => send_text(&mut wr, r#"{"type":"pong"}"#).await?,
                    Ok(GameMessage::Bye) => {
                        // Close properly, so the mod sees a normal close instead
                        // of a dropped connection and does not treat it as a crash
                        close(&mut wr, 1000).await;
                        return Ok(());
                    }
                    Err(e) => {
                        bad_messages += 1;
                        send_text(
                            &mut wr,
                            &serde_json::json!({"type": "error", "reason": e.to_string()})
                                .to_string(),
                        )
                        .await?;
                        if bad_messages >= 3 {
                            anyhow::bail!("three malformed messages in a row");
                        }
                    }
                }
            }

            // Talk and mute edges, pushed as they happen
            event = events.recv() => match event {
                Ok(ev) => {
                    if let Some(msg) = event_message(&ev, hello_user_id, &mut own) {
                        send_text(&mut wr, &msg).await?;
                    }
                }
                // Missed a burst of edges: the next one re-syncs the mod
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {}
            },
        }
    }
}

/// Mute, deafen and speaking as one socket last heard them.
#[derive(Debug, Default, Clone, Copy)]
struct Own {
    muted: bool,
    deafened: bool,
    speaking: bool,
}

/// The push message for one event, or `None` when this socket has no game
/// behind it yet (no `hello`) or the event is not the mod's business.
fn event_message(ev: &SdkEvent, own_id: Option<u32>, own: &mut Own) -> Option<String> {
    let own_id = own_id?;
    let me = |own: &Own| {
        serde_json::json!({
            "type": "self",
            "muted": own.muted,
            "deafened": own.deafened,
            "speaking": own.speaking,
        })
    };
    let msg = match *ev {
        SdkEvent::Talk { user_id, speaking } if user_id == own_id => {
            own.speaking = speaking;
            me(own)
        }
        SdkEvent::Talk { user_id, speaking } => {
            serde_json::json!({"type": "talk", "user_id": user_id, "speaking": speaking})
        }
        SdkEvent::Muted { user_id, muted } if user_id == own_id => {
            own.muted = muted;
            me(own)
        }
        SdkEvent::Muted { user_id, muted } => {
            serde_json::json!({"type": "user", "user_id": user_id, "muted": muted})
        }
        SdkEvent::Deafened { user_id, deafened } if user_id == own_id => {
            own.deafened = deafened;
            me(own)
        }
        SdkEvent::Deafened { user_id, deafened } => {
            serde_json::json!({"type": "user", "user_id": user_id, "deafened": deafened})
        }
        // Consumed by the `hello` that is waiting for its join, not forwarded
        SdkEvent::ChannelError(_) => return None,
    };
    Some(msg.to_string())
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

    // Everything needed after the guard is dropped: a stalled control stream
    // would otherwise park this task inside the lock, and the next
    // connect/disconnect would wait behind a game.
    let tcp_tx = connection.tcp_tx.clone();
    let current_channel = connection.current_channel_id.clone();
    let user_id = connection.user_id;
    let target = channel.map(|c| (c.channel_id, c.name));
    // Subscribed before the join is sent, so its refusal cannot be missed
    let mut events = state.sdk_events.subscribe();
    drop(conn);

    // Wait for the join before claiming to be ingame. Arming the SDK on a
    // join that never happened would leave distance culling on with nobody
    // driving it, i.e. everyone silent.
    if let Some((channel_id, name)) = &target {
        if current_channel.load(Ordering::Relaxed) != *channel_id {
            let _ = crate::network::send_tcp_message(
                &tcp_tx,
                &voipc_protocol::messages::ClientMessage::JoinChannel {
                    channel_id: *channel_id,
                    password: hello.password.clone(),
                },
            )
            .await;

            let deadline = tokio::time::Instant::now() + JOIN_TIMEOUT;
            loop {
                if current_channel.load(Ordering::Relaxed) == *channel_id {
                    break;
                }
                if tokio::time::Instant::now() >= deadline {
                    return serde_json::json!({
                        "type": "error",
                        "reason": format!("could not join {name}: timed out"),
                    });
                }
                tokio::select! {
                    // The channel id is swapped when the server's UserList
                    // arrives, so a short poll is all this needs
                    _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => {}
                    event = events.recv() => {
                        if let Ok(SdkEvent::ChannelError(reason)) = event {
                            return serde_json::json!({
                                "type": "error",
                                "reason": format!("could not join {name}: {reason}"),
                            });
                        }
                    }
                }
            }
        }
    }

    // In the channel: from here on the game owns the positions. The connection
    // may have been replaced while we waited, so check it is still ours.
    let conn = state.connection.read().await;
    let Some(connection) = conn.as_ref().filter(|c| c.user_id == user_id) else {
        return state_message("disconnected", None, None);
    };
    if let Ok(mut spatial) = connection.spatial.lock() {
        spatial.clear_positions();
        spatial.sdk_active = true;
        spatial.sync = false;
        // Remember where the game is driving, so leaving that channel disarms
        // it rather than culling the next channel's members to silence
        spatial.sdk_channel = Some(connection.current_channel_id.load(Ordering::Relaxed));
    }
    state_message("ingame", Some(connection), target.map(|(_, name)| name))
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

    // We left the channel the game said hello for (the user switched, or an
    // admin moved us). Its player ids mean nothing here, and applying them
    // would cull everyone in the new channel to silence.
    let here = connection.current_channel_id.load(Ordering::Relaxed);
    if spatial.sdk_channel != Some(here) {
        spatial.sdk_active = false;
        spatial.clear_positions();
        return Err("left the channel this game joined — send hello again".into());
    }

    // Updates arrive 4-10 times a second; each one is glided over the gap to
    // the previous, so the mix does not step at the mod's tick rate.
    let now = std::time::Instant::now();
    let over = spatial
        .last_update
        .map_or(std::time::Duration::from_millis(100), |t| {
            now.duration_since(t)
        })
        .clamp(MIN_GLIDE, MAX_GLIDE);
    spatial.last_update = Some(now);

    if let Some(own) = update.own {
        if !own.pos.iter().all(|c| c.is_finite()) {
            return Err("self position must be finite".into());
        }
        let target = Listener {
            pos: own.pos,
            fwd: facing(own.fwd, own.yaw),
        };
        let motion = match spatial.listener_motion {
            Some(prev) => Motion {
                fwd: Some((prev.fwd_at(now), target.fwd)),
                ..Motion::glide(&prev, target.pos, over, now)
            },
            None => Motion {
                fwd: Some((target.fwd, target.fwd)),
                ..Motion::snap(target.pos, now)
            },
        };
        spatial.listener = target;
        spatial.listener_motion = Some(motion);
    }

    let mut sources: HashMap<u32, Source> = HashMap::with_capacity(update.players.len());
    let mut motion: HashMap<u32, Motion> = HashMap::with_capacity(update.players.len());
    for player in update.players {
        let fx = match player.mode.as_deref() {
            Some("radio") => Effect::Radio,
            Some("phone") => Effect::Phone,
            _ => Effect::None,
        };
        let direct = fx != Effect::None || player.mode.as_deref() == Some("direct");
        let pos = player.pos.unwrap_or([0.0; 3]);
        if !pos.iter().all(|c| c.is_finite()) {
            return Err(format!("position of player {} must be finite", player.id));
        }
        // Every float is checked: one NaN range would make the gains NaN and,
        // through the mixer's ramp state, silence that source for good.
        let range = player.range.filter(|r| r.is_finite()).unwrap_or(DEFAULT_RANGE);
        let volume = player.volume.filter(|v| v.is_finite()).unwrap_or(1.0);
        if !direct {
            // Someone the game listed before glides on; a newcomer, or someone
            // who was culled and came back, snaps.
            motion.insert(
                player.id,
                match spatial.motion.get(&player.id) {
                    Some(prev) => Motion::glide(prev, pos, over, now),
                    None => Motion::snap(pos, now),
                },
            );
        }
        sources.insert(
            player.id,
            Source {
                pos,
                range: range.max(0.01),
                volume: volume.clamp(0.0, 2.0),
                muffle: player.muffle.unwrap_or(0).min(MAX_MUFFLE),
                direct,
                fx,
            },
        );
    }
    // Both replaced wholesale, so a culled player leaves no glide behind
    spatial.sources = sources;
    spatial.motion = motion;
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

#[derive(Debug)]
enum Frame {
    Text(String),
    Ping(Vec<u8>),
    Close,
    Other,
}

/// What the upgrade request carried, once it passed validation.
#[derive(Debug, PartialEq, Eq)]
struct Upgrade {
    key: String,
    origin: Option<String>,
}

/// Parse the HTTP upgrade request. `Err` is the status line to answer with.
fn parse_handshake(head: &str) -> Result<Upgrade, &'static str> {
    let mut lines = head.lines();
    if !lines.next().unwrap_or("").starts_with("GET ") {
        return Err("405 Method Not Allowed");
    }
    let (mut key, mut origin, mut upgrade, mut version) = (None, None, false, false);
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match name.trim().to_ascii_lowercase().as_str() {
            "sec-websocket-key" => key = Some(value.to_string()),
            "origin" => origin = Some(value.to_string()),
            "upgrade" => upgrade = value.eq_ignore_ascii_case("websocket"),
            "sec-websocket-version" => version = value == "13",
            _ => {}
        }
    }
    if !upgrade {
        return Err("400 Bad Request");
    }
    if !version {
        // RFC 6455 §4.2.2: the reply names the version we do speak
        return Err("426 Upgrade Required");
    }
    Ok(Upgrade {
        key: key.ok_or("400 Bad Request")?,
        origin,
    })
}

/// One frame from the front of `buf`, and how many bytes it used; `None` while
/// it is still incomplete.
///
/// Pure, which is what makes [`read_frame`] cancel-safe: nothing leaves `buf`
/// until a whole frame is there, so a `select!` that drops the future mid-read
/// loses nothing.
fn parse_frame(buf: &[u8]) -> anyhow::Result<Option<(Frame, usize)>> {
    if buf.len() < 2 {
        return Ok(None);
    }
    let (fin, opcode, masked) = (buf[0] & 0x80 != 0, buf[0] & 0x0f, buf[1] & 0x80 != 0);
    if !fin || opcode == 0 {
        anyhow::bail!("fragmented frames are not supported");
    }
    // RFC 6455 §5.1: a client frame that is not masked fails the connection
    if !masked {
        anyhow::bail!("unmasked client frame");
    }
    let mut len = (buf[1] & 0x7f) as usize;
    let mut at = 2;
    if len == 126 {
        if buf.len() < 4 {
            return Ok(None);
        }
        len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        at = 4;
    } else if len == 127 {
        if buf.len() < 10 {
            return Ok(None);
        }
        len = u64::from_be_bytes(buf[2..10].try_into().unwrap()) as usize;
        at = 10;
    }
    // Checked before the payload arrives, so a huge claim costs nothing
    if len > MAX_FRAME {
        anyhow::bail!("frame of {len} bytes exceeds the {MAX_FRAME} byte limit");
    }
    if buf.len() < at + 4 + len {
        return Ok(None);
    }
    let mask = [buf[at], buf[at + 1], buf[at + 2], buf[at + 3]];
    at += 4;
    let payload: Vec<u8> = buf[at..at + len]
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ mask[i % 4])
        .collect();
    at += len;
    let frame = match opcode {
        0x1 => Frame::Text(String::from_utf8(payload)?),
        0x8 => Frame::Close,
        0x9 => Frame::Ping(payload),
        _ => Frame::Other,
    };
    Ok(Some((frame, at)))
}

/// Read and answer the upgrade request.
///
/// Returns whatever arrived after the header block: a client may pipeline its
/// first frame behind the request, and those bytes used to be dropped on the
/// floor. Browsers wait for the 101, a hand-rolled client need not.
async fn handshake(stream: &mut TcpStream, extra_origins: &[String]) -> anyhow::Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    let end = loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            anyhow::bail!("client closed during handshake");
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(end) = find_header_end(&buf) {
            break end;
        }
        if buf.len() > MAX_HANDSHAKE {
            anyhow::bail!("handshake too large");
        }
    };
    let head = String::from_utf8_lossy(&buf[..end]).into_owned();
    let leftover = buf.split_off(end);

    let upgrade = match parse_handshake(&head) {
        Ok(u) => u,
        Err(status) => {
            reject(stream, status).await;
            anyhow::bail!("bad upgrade request: {status}");
        }
    };

    // Any web page can open a WebSocket to loopback, so only the game
    // runtimes' own origins (plus whatever the user allowed) get through.
    // A request without an Origin is a native client (a plugin, curl), which
    // the documented trust model already allows: see docs/SDK.md.
    if let Some(origin) = upgrade.origin.as_deref() {
        if !origin_allowed(origin, extra_origins) {
            reject(stream, "403 Forbidden").await;
            warn!(origin, "game SDK rejected a connection from an unknown origin");
            anyhow::bail!("origin not allowed: {origin}");
        }
    }

    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {}\r\n\r\n",
        accept_key(&upgrade.key)
    );
    stream.write_all(response.as_bytes()).await?;
    Ok(leftover)
}

/// Answer an upgrade we will not perform, then let the caller hang up.
async fn reject(stream: &mut TcpStream, status: &str) {
    let _ = stream
        .write_all(
            format!(
                "HTTP/1.1 {status}\r\nSec-WebSocket-Version: 13\r\n\
                 Content-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await;
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
async fn read_frame<R: tokio::io::AsyncRead + Unpin>(
    rd: &mut R,
    buf: &mut Vec<u8>,
) -> anyhow::Result<Option<Frame>> {
    loop {
        if let Some((frame, used)) = parse_frame(buf)? {
            buf.drain(..used);
            return Ok(match frame {
                Frame::Close => None,
                other => Some(other),
            });
        }
        let mut chunk = [0u8; 4096];
        let n = rd.read(&mut chunk).await?;
        if n == 0 {
            if buf.is_empty() {
                return Ok(None);
            }
            anyhow::bail!("connection closed mid-frame");
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

async fn send_text<W: tokio::io::AsyncWrite + Unpin>(
    stream: &mut W,
    text: &str,
) -> anyhow::Result<()> {
    write_frame(stream, 0x1, text.as_bytes()).await
}

/// Close with an RFC 6455 status code (1000 normal, 1001 idle, 1002 protocol).
async fn close<W: tokio::io::AsyncWrite + Unpin>(stream: &mut W, code: u16) {
    let _ = write_frame(stream, 0x8, &code.to_be_bytes()).await;
}

async fn write_frame<W: tokio::io::AsyncWrite + Unpin>(
    stream: &mut W,
    opcode: u8,
    payload: &[u8],
) -> anyhow::Result<()> {
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

    /// A client frame, which unlike a server frame must be masked.
    fn masked_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mask = [0xA1u8, 0xB2, 0xC3, 0xD4];
        let mut frame = Vec::new();
        frame.push(0x80 | opcode);
        assert!(payload.len() < 126, "test helper only does short frames");
        frame.push(0x80 | payload.len() as u8);
        frame.extend_from_slice(&mask);
        frame.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
        frame
    }

    const UPGRADE: &str = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\n\
         Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n\r\n";

    #[test]
    fn the_handshake_requires_a_websocket_upgrade() {
        let ok = parse_handshake(UPGRADE).expect("a valid upgrade was refused");
        assert_eq!(ok.key, "dGhlIHNhbXBsZSBub25jZQ==");
        assert!(ok.origin.is_none(), "a native client sends no Origin");

        let without = |header: &str| {
            UPGRADE
                .lines()
                .filter(|l| !l.to_ascii_lowercase().starts_with(header))
                .collect::<Vec<_>>()
                .join("\r\n")
        };
        assert_eq!(parse_handshake(&without("upgrade")), Err("400 Bad Request"));
        assert_eq!(parse_handshake(&without("sec-websocket-key")), Err("400 Bad Request"));
        // A version we do not speak gets 426, and the reply names 13
        assert_eq!(
            parse_handshake(&UPGRADE.replace("Version: 13", "Version: 8")),
            Err("426 Upgrade Required")
        );
        assert_eq!(
            parse_handshake(&UPGRADE.replace("GET /", "POST /")),
            Err("405 Method Not Allowed")
        );
    }

    #[test]
    fn frames_must_be_masked_and_whole() {
        let frame = masked_frame(0x1, b"{\"type\":\"ping\"}");
        let (parsed, used) = parse_frame(&frame).unwrap().expect("a complete frame");
        assert_eq!(used, frame.len());
        assert!(matches!(parsed, Frame::Text(t) if t == "{\"type\":\"ping\"}"));

        // Incomplete: nothing is consumed, so the caller reads on
        assert!(parse_frame(&frame[..frame.len() - 1]).unwrap().is_none());
        assert!(parse_frame(&[]).unwrap().is_none());

        // RFC 6455: a client frame must be masked
        assert!(parse_frame(&frame_bytes(0x1, b"hello")).is_err(), "unmasked frame accepted");
        // Fragments are refused rather than half-read
        let mut fragment = masked_frame(0x1, b"x");
        fragment[0] &= 0x7f;
        assert!(parse_frame(&fragment).is_err());
    }

    #[test]
    fn an_oversized_frame_is_refused_before_its_payload_arrives() {
        // A 64-bit length claiming 1 GiB: only the 10-byte header is present
        let mut header = vec![0x81, 0xFF];
        header.extend_from_slice(&(1u64 << 30).to_be_bytes());
        let err = parse_frame(&header).unwrap_err().to_string();
        assert!(err.contains("exceeds"), "{err}");
    }

    #[test]
    fn a_close_frame_ends_the_connection() {
        let (parsed, _) = parse_frame(&masked_frame(0x8, &1000u16.to_be_bytes()))
            .unwrap()
            .unwrap();
        assert!(matches!(parsed, Frame::Close));
    }

    #[test]
    fn push_messages_fold_our_own_state() {
        let mut own = Own::default();
        // Somebody else: a plain talk message, our own state untouched
        let msg = event_message(&SdkEvent::Talk { user_id: 7, speaking: true }, Some(42), &mut own);
        assert_eq!(
            msg.unwrap(),
            r#"{"speaking":true,"type":"talk","user_id":7}"#
        );
        assert!(!own.speaking);

        // Ourselves: a `self` message carrying every field
        event_message(&SdkEvent::Muted { user_id: 42, muted: true }, Some(42), &mut own);
        let msg = event_message(&SdkEvent::Talk { user_id: 42, speaking: true }, Some(42), &mut own).unwrap();
        assert!(msg.contains(r#""muted":true"#), "{msg}");
        assert!(msg.contains(r#""speaking":true"#), "{msg}");
        assert!(msg.contains(r#""type":"self""#), "{msg}");

        // A socket that never said hello, and events that are not the mod's
        assert!(event_message(&SdkEvent::Talk { user_id: 7, speaking: true }, None, &mut own).is_none());
        assert!(event_message(&SdkEvent::ChannelError("nope".into()), Some(42), &mut own).is_none());
    }

    #[tokio::test]
    async fn a_pipelined_first_frame_survives_the_handshake() {
        // A client that writes its upgrade and its first frame in one go used
        // to lose the frame: the handshake read it and threw it away.
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = handshake(&mut stream, &[]).await.unwrap();
            let (mut rd, _wr) = stream.into_split();
            read_frame(&mut rd, &mut buf).await.unwrap()
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let mut request = UPGRADE.as_bytes().to_vec();
        request.extend_from_slice(&masked_frame(0x1, b"{\"type\":\"ping\"}"));
        client.write_all(&request).await.unwrap();

        let frame = server.await.unwrap();
        assert!(
            matches!(frame, Some(Frame::Text(t)) if t == "{\"type\":\"ping\"}"),
            "the pipelined frame was lost"
        );
    }

    #[tokio::test]
    async fn an_unmasked_frame_is_refused() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = handshake(&mut stream, &[]).await.unwrap();
            let (mut rd, _wr) = stream.into_split();
            read_frame(&mut rd, &mut buf).await
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(UPGRADE.as_bytes()).await.unwrap();
        client.write_all(&frame_bytes(0x1, b"hi")).await.unwrap();
        assert!(server.await.unwrap().is_err(), "an unmasked frame was accepted");
    }
}
