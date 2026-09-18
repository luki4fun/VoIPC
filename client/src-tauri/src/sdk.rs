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
//!   {"type":"update","self":{"pos":[x,y,z],"fwd":[fx,fy],"reverb":0,"underwater":0},
//!    "players":[{"id":42,"pos":[x,y,z],"range":8.0,"volume":1.0,"muffle":0},
//!               {"id":7,"mode":"radio","volume":0.8}]}
//!   {"type":"ping"} {"type":"bye"}
//!
//! VoIPC → game
//!   {"type":"state","state":"ingame","user_id":42,"username":"Luki",
//!    "channel":"Ingame","proximity":"3d","muted":false,"deafened":false,
//!    "version":"0.9.1","sdk":1,
//!    "capabilities":["spatial","direct","volume","muffle","radio","phone","talk",
//!                    "reverb","underwater"]}
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
use std::sync::atomic::Ordering;
use std::sync::Arc;

use base64::Engine as _;
use serde::Deserialize;
use tauri::{Emitter, Manager};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, warn};

use voipc_audio::spatial::{
    effect_from_str, Effect, Listener, Source, DEFAULT_RANGE, MAX_MUFFLE, MAX_REVERB,
    MAX_UNDERWATER,
};
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
/// Sockets served at once, across every origin. One game needs one; the rest is
/// slack for a reconnect racing a dying socket, and for the shims and test
/// pages a server may have open beside it. The cap that actually protects the
/// game is [`MAX_PER_ORIGIN`]; this one only bounds file descriptors.
const MAX_CONNECTIONS: usize = 8;
/// Sockets **one origin** may hold at once. Every `https://cfx-nui-*` page on a
/// FiveM server is a trusted origin, so without this any third-party script
/// there could open the lot and keep them alive with `ping` — and the voice
/// resource's next restart would be answered 503 for the rest of the session,
/// with nothing in Settings to say why. Two, because a resource restarting
/// opens its new socket while its old one is still dying.
const MAX_PER_ORIGIN: usize = 2;
/// How long `hello` waits for the server to confirm the channel join.
const JOIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
/// Shortest gap between two `update` frames we will act on. The documented
/// ceiling is 20 Hz and a real mod sends 4–10, so this is pure slack — but
/// without it a mod (or a page on an allowed origin) can hold the spatial
/// mutex, which the mixer needs every 20 ms, at loopback line rate.
const MIN_UPDATE_GAP: std::time::Duration = std::time::Duration::from_millis(20);
/// Shortest gap between two `hello` frames. Each one may send a JoinChannel to
/// the server, whose password limiter is 3 burst / 1 per second, and each
/// refusal raises a toast — so a hello loop is a way to paper the UI.
const MIN_HELLO_GAP: std::time::Duration = std::time::Duration::from_secs(1);
/// Longest `game` / `resource` string kept. They are attacker-controlled and
/// end up in a toast and a banner; a name is a name, not a paragraph.
const MAX_NAME: usize = 32;
/// Extra renders one voice may have on top of its own. Four voices from one
/// speaker is already more than anybody can follow, and each one costs a
/// filter chain and a reverb bank in the mixer.
const MAX_LAYERS: usize = 3;
/// Longest `delay` honoured, in milliseconds. Bounds the ring a delayed layer
/// keeps: without a cap, `delay` is a request to allocate.
const MAX_DELAY_MS: u32 = 100;
/// One mixer frame, in milliseconds — the resolution `delay` is quantised to.
const FRAME_MS: u32 = 20;
/// Longest a game may hold the user's push-to-talk down before it has to ask
/// again. A radio key nobody is pressing must not be able to leave a
/// microphone open, whatever the mod believes about its own state.
const TRANSMIT_HOLD_MAX: std::time::Duration = std::time::Duration::from_secs(60);
/// What this build actually renders; scripts read it instead of guessing.
const CAPABILITY_BASE: &[&str] = &[
    "spatial",
    "direct",
    "volume",
    "muffle",
    "talk",
    "reverb",
    "underwater",
    "layers",
    "pan",
    "delay",
    // Both need the user's consent as well as this build's support, and the
    // refusal names the setting. Advertised anyway: a mod that cannot tell
    // "this build cannot" from "this player has not allowed it" would give up
    // on the first, and the second is the player's to change while it runs.
    "beacon",
    "transmit",
];

/// The base list plus every preset id, so a mod can probe for exactly the chain
/// it wants to use. Built from the table rather than written out, so adding a
/// chain cannot forget to announce it. `radio` and `phone` are still in here —
/// they are preset ids — so no existing feature probe changes meaning.
fn capabilities() -> &'static Vec<&'static str> {
    static CAPABILITIES: std::sync::OnceLock<Vec<&'static str>> = std::sync::OnceLock::new();
    CAPABILITIES.get_or_init(|| {
        CAPABILITY_BASE
            .iter()
            .copied()
            .chain(voipc_audio::mixer::PRESETS.iter().map(|p| p.id))
            .collect()
    })
}

/// Everything a `mode` may be, which is not the same list as `capabilities`:
/// that one carries feature flags too, and a mod offering its user a dropdown
/// of "radio, phone, layers, pan" is what happens when the two are conflated.
fn modes() -> &'static Vec<&'static str> {
    static MODES: std::sync::OnceLock<Vec<&'static str>> = std::sync::OnceLock::new();
    MODES.get_or_init(|| {
        ["spatial", "direct", "off"]
            .into_iter()
            .chain(voipc_audio::mixer::PRESETS.iter().map(|p| p.id))
            .collect()
    })
}

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
    // MTA:SA's CEF. An origin is scheme + host + port and nothing else
    // (RFC 6454), so this one has no trailing path to match a prefix against —
    // it belongs here, where the host is matched exactly, and not with the
    // runtimes above whose origin carries the resource name.
    "http://mta",
];

// ── Wire types ───────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum GameMessage {
    Hello(Hello),
    Update(Update),
    /// Press or release the user's push-to-talk, because they pressed their
    /// in-game radio key. Refused unless the user allowed it in Settings.
    Transmit { on: bool },
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
    /// `"players"` (the default): the mod places everybody, and VoIPC culls to
    /// what it lists. `"beacon"`: the mod can only see where its own player
    /// stands, so VoIPC broadcasts that position to the channel — encrypted
    /// like voice — and the other members' beacons place them. Beacon mode
    /// needs the user's consent, because it is the one thing here that puts
    /// something on the wire.
    #[serde(default)]
    mode: Option<String>,
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
    /// Reverberation of the room the listener is in, 0–10: 0 outdoors, 4 a
    /// room, 7 a garage, 10 a cathedral. Applied to the whole mix.
    #[serde(default)]
    reverb: Option<u8>,
    /// How submerged the listener is, 0–10. Muffles and quietens everything.
    #[serde(default)]
    underwater: Option<u8>,
}

/// The listener's surroundings from one `self` object, clamped to the
/// documented range. A field the mod leaves out is off, like every other
/// omitted field. Free-standing so the clamp is testable without an app.
fn reverb_water_from(own: &SelfState) -> (u8, u8) {
    (
        own.underwater.unwrap_or(0).min(MAX_UNDERWATER),
        own.reverb.unwrap_or(0).min(MAX_REVERB),
    )
}

/// One render of one voice: a player as they are heard, or one of the extra
/// ways they are heard at the same moment.
///
/// The same seven fields either way — that symmetry is the point, so a mod
/// never has to learn two shapes. The one rule that differs is `mode`; see
/// [`source_from`].
#[derive(Debug, Clone, Default, Deserialize)]
struct RenderSpec {
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
    /// "spatial" (default), "direct", "off", or the id of an effect chain.
    #[serde(default)]
    mode: Option<String>,
    /// Which ear: −1 left, 0 centred (the default), +1 right. A phone held to
    /// an ear, or ACRE2's LEFT/CENTER/RIGHT for a radio.
    #[serde(default)]
    pan: Option<f32>,
    /// Hold this render back by up to [`MAX_DELAY_MS`], quantised to 20 ms
    /// frames: the radio arriving a beat after the voice in the room.
    #[serde(default)]
    delay: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
struct PlayerState {
    /// The player's VoIPC user id, published by the game server.
    id: u32,
    /// How this voice is heard. `mode: "off"` silences it, which is what a
    /// caller on the far side of the map needs: no base render, layers only.
    #[serde(flatten)]
    spec: RenderSpec,
    /// Up to [`MAX_LAYERS`] further renders of the same voice, each a full
    /// spec of its own. Over the cap they are dropped, never refused —
    /// rejecting a tick freezes the whole mix.
    #[serde(default)]
    layers: Vec<RenderSpec>,
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
                let config = state.config();
                (config.sdk_enabled, config.sdk_port)
            };

            let wants_restart = running.is_some() && (!enabled || port != bound_port);
            if wants_restart {
                if let Some(handle) = running.take() {
                    handle.abort();
                    info!("game SDK listener stopped");
                    // Aborting takes the connections with it, and an aborted
                    // task runs no teardown: hand the mix back here — the
                    // microphone first. Switching the integration off is the
                    // documented escape hatch, so it must not be the one path
                    // that leaves a game's push-to-talk held for ever.
                    release_transmit(&app).await;
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

/// Who owns the mix right now.
///
/// One game at a time, and **one origin** at a time: the newest connection
/// from the owner's own origin takes over (that is a resource restarting),
/// while a connection from a different origin is refused for as long as the
/// owner's socket lives. Without that second half, every `https://cfx-nui-*`
/// page on the server — any third-party script, or a compromised one — could
/// take the mix off the voice resource, and each takeover clears every
/// placement, so two scripts fighting is silence.
///
/// `None` in `origin` is a native client (a plugin, `curl`); they are one
/// class between themselves, exactly as the origin check already treats them.
#[derive(Default, Clone)]
struct Owner {
    /// Generation of the owning connection; 0 = nobody owns the mix.
    generation: u64,
    origin: Option<String>,
}

type OwnerSlot = Arc<std::sync::Mutex<Owner>>;

fn owner_slot(owner: &OwnerSlot) -> Owner {
    owner.lock().unwrap_or_else(|p| p.into_inner()).clone()
}

/// Must this `hello` be refused because another game already owns the mix?
///
/// Free-standing so the rule can be read and tested on its own: everything
/// around it in `serve` is a socket. Nobody owning it, or the owner being this
/// same connection, or a newer socket from the **same origin** (a resource
/// restarting) all go through; a different origin does not, for as long as the
/// owner's socket lives.
fn owner_conflict(held: &Owner, generation: u64, origin: &Option<String>) -> bool {
    held.generation != 0 && held.generation != generation && &held.origin != origin
}

/// How many live sockets each origin holds. A native client sends no `Origin`,
/// and they are one class between themselves, exactly as the ownership rule
/// already treats them.
type OriginCounts = Arc<std::sync::Mutex<HashMap<Option<String>, usize>>>;

/// Is this origin already holding as many sockets as it may?
///
/// Free-standing so the rule can be read and tested without a listener.
fn origin_slots_full(counts: &HashMap<Option<String>, usize>, origin: &Option<String>) -> bool {
    counts.get(origin).copied().unwrap_or(0) >= MAX_PER_ORIGIN
}

/// One origin's slot, released however the connection ends — including a task
/// aborted when the integration is switched off.
struct OriginSlot {
    counts: OriginCounts,
    origin: Option<String>,
}

/// Claim a slot for this origin, or `None` if it already holds its share.
fn take_origin_slot(counts: &OriginCounts, origin: &Option<String>) -> Option<OriginSlot> {
    let mut map = counts.lock().unwrap_or_else(|p| p.into_inner());
    if origin_slots_full(&map, origin) {
        return None;
    }
    *map.entry(origin.clone()).or_insert(0) += 1;
    Some(OriginSlot {
        counts: counts.clone(),
        origin: origin.clone(),
    })
}

impl Drop for OriginSlot {
    fn drop(&mut self) {
        let mut map = self.counts.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(n) = map.get_mut(&self.origin) {
            *n -= 1;
            // Dropped at zero rather than left at zero: `cfx-nui-<anything>` is
            // an allowed prefix, so a loop of fresh names would otherwise grow
            // this map for the life of the app.
            if *n == 0 {
                map.remove(&self.origin);
            }
        }
    }
}

/// Connections that never completed a `hello` (a port scan, a page from a
/// refused origin, `curl`) can no longer clear the owner's positions on their
/// way out.
async fn accept_loop(listener: TcpListener, app: tauri::AppHandle) {
    let owner: OwnerSlot = Arc::new(std::sync::Mutex::new(Owner::default()));
    let mut generation: u64 = 0;
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    let per_origin: OriginCounts = Arc::new(std::sync::Mutex::new(HashMap::new()));
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
        let per_origin = per_origin.clone();
        connections.spawn(async move {
            let _permit = permit; // released when this connection ends
            if let Err(e) = serve(stream, &app, &owner, my_generation, &per_origin).await {
                info!("game SDK connection ended: {e}");
            }
            // Only the owner hands the mix back; a socket that was replaced by
            // a newer one, or never said hello, leaves the state alone.
            let was_owner = {
                let mut slot = owner.lock().unwrap_or_else(|p| p.into_inner());
                if slot.generation == my_generation {
                    *slot = Owner::default();
                    true
                } else {
                    false
                }
            };
            if was_owner {
                // Whatever it was holding goes with it: a socket that dies
                // mid-transmission must not leave the microphone open.
                release_transmit(&app).await;
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
    owner: &OwnerSlot,
    generation: u64,
    per_origin: &OriginCounts,
) -> anyhow::Result<()> {
    let allowed = {
        let state = app.state::<AppState>();
        let config = state.config();
        config.sdk_allowed_origins.clone()
    };
    // A socket that connects and then says nothing must not pin a task. The
    // third value is this origin's slot (see `MAX_PER_ORIGIN`), held for the
    // life of the connection and released by its `Drop` however it ends.
    let (mut buf, origin, _origin_slot) =
        tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake(&mut stream, &allowed, per_origin))
            .await
            .map_err(|_| anyhow::anyhow!("handshake timed out"))??;
    let (mut rd, mut wr) = stream.into_split();

    let mut bad_messages = 0u8;
    // The VoIPC user id we had when this game said hello. The server hands out
    // new ids on every connection, so after a reconnect the mod's ids name
    // nobody — and every player it lists would fall out of the mix silently.
    //
    // It is also the gate on every push: cleared when we stop driving (the
    // user changed channel, the server reconnected, another socket took the
    // mix), so a mod cannot keep reading who talks when in a channel the user
    // walked away from it into.
    let mut hello_user_id: Option<u32> = None;
    // The ids this socket listed in its last update. A mod is told about the
    // players it placed, and about the user — not about everybody else in the
    // channel, which it has no other way to enumerate.
    let mut listed: std::collections::HashSet<u32> = std::collections::HashSet::new();
    // Rate gates; see MIN_UPDATE_GAP / MIN_HELLO_GAP.
    let mut last_update: Option<tokio::time::Instant> = None;
    let mut last_hello: Option<tokio::time::Instant> = None;
    // Consecutive `hello`s refused by the rate limit; see the arm below.
    let mut hello_floods = 0u8;
    // Is this socket holding the user's push-to-talk down, and since when?
    let mut holding_tx = false;
    let mut last_tx: Option<tokio::time::Instant> = None;
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
                        let now = tokio::time::Instant::now();
                        if last_hello.is_some_and(|t| now.duration_since(t) < MIN_HELLO_GAP) {
                            send_text(
                                &mut wr,
                                r#"{"type":"error","reason":"one hello per second"}"#,
                            )
                            .await?;
                            // A mod that answers the refusal with another hello
                            // is a loop at loopback line rate, and both ends
                            // parse JSON for as long as it runs. Ten of them and
                            // the socket goes, as for any other client that
                            // cannot be talked to.
                            hello_floods = hello_floods.saturating_add(1);
                            if hello_floods >= 10 {
                                close(&mut wr, 1008).await;
                                anyhow::bail!("hello loop: ten refusals in a row");
                            }
                            continue;
                        }
                        hello_floods = 0;
                        last_hello = Some(now);
                        // Another game already has the mix. Checked before the
                        // join, so a refused hello cannot move the user.
                        if owner_conflict(&owner_slot(owner), generation, &origin) {
                            warn!(?origin, "game SDK refused a second game the mix");
                            send_text(
                                &mut wr,
                                r#"{"type":"error","reason":"another game is already placing people"}"#,
                            )
                            .await?;
                            continue;
                        }
                        let game = short_name(&hello.game, "a game");
                        let resource = short_name(&hello.resource, "");
                        let reply = on_hello(app, &hello).await;
                        // Only a game that is actually in the channel owns the
                        // mix, and only then does the panel say one is connected
                        if reply.get("state").and_then(|s| s.as_str()) == Some("ingame") {
                            // A fresh hello starts from "not holding the mic",
                            // whoever was holding it before.
                            release_transmit(app).await;
                            holding_tx = false;
                            *owner.lock().unwrap_or_else(|p| p.into_inner()) = Owner {
                                generation,
                                origin: origin.clone(),
                            };
                            hello_user_id =
                                reply.get("user_id").and_then(|v| v.as_u64()).map(|v| v as u32);
                            listed.clear();
                            // Start listening from *now*. The join this hello
                            // just made is itself a channel change, and its
                            // `Detached` is sitting in the queue: acting on it
                            // would drop the user id we have this instant, and
                            // the mod would get no talk pushes and "send hello
                            // first" for every `transmit` until it said hello
                            // a second time. Edges from before the hello were
                            // never this mod's to hear anyway.
                            events = app.state::<AppState>().sdk_events.subscribe();
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
                                    "resource": resource,
                                    // Named so the user is told where a game
                                    // just put them, not merely that one did
                                    "channel": reply.get("channel").cloned(),
                                    // …and what they already allowed it to do
                                    // to them, in the same breath: a switch
                                    // ticked once months ago is not consent
                                    // anybody remembers giving.
                                    "beacon": reply.get("beacon").cloned(),
                                    "transmit": transmit_allowed(app),
                                }),
                            );
                        }
                        send_text(&mut wr, &reply.to_string()).await?;
                    }
                    Ok(GameMessage::Update(update)) => {
                        bad_messages = 0;
                        if owner_slot(owner).generation != generation {
                            send_text(&mut wr, r#"{"type":"error","reason":"send hello first"}"#)
                                .await?;
                            continue;
                        }
                        let now = tokio::time::Instant::now();
                        if last_update.is_some_and(|t| now.duration_since(t) < MIN_UPDATE_GAP) {
                            // Silently: a mod that overshoots the documented
                            // rate wants its updates applied, not an argument,
                            // and an error per frame is its own flood.
                            continue;
                        }
                        last_update = Some(now);
                        match apply_update(app, update, hello_user_id).await {
                            Ok(ids) => listed = ids,
                            Err(reason) => {
                                // "Send hello again" means we are not driving
                                // this channel any more, so the pushes stop
                                // here too — not when the socket finally dies.
                                if reason.contains("hello") {
                                    hello_user_id = None;
                                    listed.clear();
                                }
                                send_text(
                                    &mut wr,
                                    &serde_json::json!({"type": "error", "reason": reason})
                                        .to_string(),
                                )
                                .await?;
                            }
                        }
                    }
                    Ok(GameMessage::Transmit { on }) => {
                        bad_messages = 0;
                        // Only the game that is driving this channel, only
                        // with the user's blessing, and never as a way to keep
                        // the microphone open: the hold is released when this
                        // socket loses the mix, when the user leaves the
                        // channel, when the socket closes, and after
                        // TRANSMIT_HOLD_MAX of no one re-asking for it.
                        if hello_user_id.is_none()
                            || owner_slot(owner).generation != generation
                        {
                            send_text(&mut wr, r#"{"type":"error","reason":"send hello first"}"#)
                                .await?;
                            continue;
                        }
                        if !transmit_allowed(app) {
                            send_text(
                                &mut wr,
                                r#"{"type":"error","reason":"the player has not allowed a game to press their push-to-talk (Settings → Game Integration)"}"#,
                            )
                            .await?;
                            continue;
                        }
                        let now = tokio::time::Instant::now();
                        // The microphone's actual state, not this socket's
                        // belief about it: the user may have taken their consent
                        // back under us, in which case the next `transmit: true`
                        // has to be acted on rather than skipped as a repeat.
                        let held = app.state::<AppState>().ptt_sdk.load(Ordering::Relaxed);
                        match transmit_step(on, held, last_tx, now) {
                            // Nothing to churn — but a repeated press still
                            // pushes the 60 second deadline out, which is what
                            // docs/SDK.md tells a mod to do to keep talking.
                            TxStep::Repeat => {
                                holding_tx = on;
                                if on {
                                    last_tx = Some(now);
                                }
                            }
                            TxStep::RateLimited => {}
                            TxStep::Act => {
                                last_tx = Some(now);
                                holding_tx = on;
                                let _ = crate::commands::sdk_set_transmit(
                                    &app.state::<AppState>(),
                                    app.clone(),
                                    on,
                                )
                                .await;
                            }
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
                // We are no longer driving: the user changed channel, or the
                // integration was switched off. Everything below is gated on
                // `hello_user_id`, so clearing it here stops the pushes at the
                // moment they stop being this mod's business.
                Ok(SdkEvent::Detached) => {
                    hello_user_id = None;
                    listed.clear();
                    if holding_tx {
                        holding_tx = false;
                        // Only if the microphone is still ours to let go of:
                        // see `releases_transmit`.
                        if releases_transmit(owner_slot(owner).generation, generation) {
                            release_transmit(app).await;
                        }
                    }
                }
                Ok(ev) => {
                    // Losing the mix to another socket ends the pushes too
                    if hello_user_id.is_some() && owner_slot(owner).generation != generation {
                        hello_user_id = None;
                        listed.clear();
                        // Dropped, never released: the socket that took the mix
                        // may be holding the microphone itself by now, and this
                        // one letting go would cut it off mid-word.
                        holding_tx = false;
                    }
                    if let Some(msg) = event_message(&ev, hello_user_id, &mut own, &listed) {
                        send_text(&mut wr, &msg).await?;
                    }
                }
                // Missed a burst of edges: the next one re-syncs the mod
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {}
            },

            // A held radio key that nobody re-asserts. A mod that crashes
            // mid-transmission, or believes a key is still down, must not be
            // able to leave a microphone open indefinitely.
            _ = tokio::time::sleep_until(
                last_tx.unwrap_or_else(tokio::time::Instant::now) + TRANSMIT_HOLD_MAX,
            ), if holding_tx => {
                holding_tx = false;
                if releases_transmit(owner_slot(owner).generation, generation) {
                    release_transmit(app).await;
                }
                send_text(
                    &mut wr,
                    r#"{"type":"error","reason":"push-to-talk released after 60s — send transmit again to keep talking"}"#,
                )
                .await?;
            }
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
///
/// `listed` is the set of players the mod placed in its last update. Somebody
/// else's edge only goes out if they are in it: a mod is told about the people
/// it already knows about, never handed the rest of the channel. Without that
/// the socket is a live directory of who is in the room with the user and when
/// each of them speaks — which a mod has no other way to learn, and no reason
/// to. Our own edges always go out; they are about the user, to their own game.
fn event_message(
    ev: &SdkEvent,
    own_id: Option<u32>,
    own: &mut Own,
    listed: &std::collections::HashSet<u32>,
) -> Option<String> {
    let own_id = own_id?;
    let me = |own: &Own| {
        serde_json::json!({
            "type": "self",
            "muted": own.muted,
            "deafened": own.deafened,
            "speaking": own.speaking,
        })
    };
    let about = |user_id: u32| listed.contains(&user_id);
    let msg = match *ev {
        SdkEvent::Talk { user_id, speaking } if user_id == own_id => {
            own.speaking = speaking;
            me(own)
        }
        SdkEvent::Talk { user_id, speaking } if about(user_id) => {
            serde_json::json!({"type": "talk", "user_id": user_id, "speaking": speaking})
        }
        SdkEvent::Muted { user_id, muted } if user_id == own_id => {
            own.muted = muted;
            me(own)
        }
        SdkEvent::Muted { user_id, muted } if about(user_id) => {
            serde_json::json!({"type": "user", "user_id": user_id, "muted": muted})
        }
        SdkEvent::Deafened { user_id, deafened } if user_id == own_id => {
            own.deafened = deafened;
            me(own)
        }
        SdkEvent::Deafened { user_id, deafened } if about(user_id) => {
            serde_json::json!({"type": "user", "user_id": user_id, "deafened": deafened})
        }
        // The channel's positional mode changed under the mod. Sent as a
        // partial `state`, because this is a sync function with no connection
        // to build the whole one from — `proximity` is the field that moved.
        SdkEvent::Proximity { mode } => serde_json::json!({
            "type": "state",
            "state": "ingame",
            "proximity": mode,
        }),
        // Somebody the mod did not place; consumed by the `hello` that is
        // waiting for its join; or handled by the caller.
        _ => return None,
    };
    Some(msg.to_string())
}

/// Which `hello.mode` this is, or why it is refused.
///
/// Free-standing for the same reason as [`owner_conflict`]: this is the gate
/// on the only thing a mod can ask for that leaves the machine, and a gate
/// worth having is a gate worth testing without a socket and an app around it.
fn beacon_mode(mode: Option<&str>, allowed: bool) -> Result<bool, String> {
    match mode {
        None | Some("players") => Ok(false),
        Some("beacon") if allowed => Ok(true),
        Some("beacon") => Err("the player has not allowed a game to broadcast their position \
                               (Settings → Game Integration)"
            .into()),
        Some(other) => Err(format!("unknown hello mode {other}")),
    }
}

/// What one `transmit` frame does.
#[derive(Debug, PartialEq, Eq)]
enum TxStep {
    /// The microphone is already in that state.
    Repeat,
    /// A press too soon after the last one; dropped.
    RateLimited,
    /// Press or release the microphone.
    Act,
}

/// Should this `transmit` frame be acted on?
///
/// Free-standing so the rule can be read and tested without a socket — the two
/// mistakes it exists to prevent are both invisible from inside `serve`:
///
/// - **Only a press is rate-limited.** Each edge takes the connection write
///   lock and restarts the capture device, so a flood of them is a denial of
///   service — but rate-limiting the *release* too meant a key tapped inside
///   [`MIN_UPDATE_GAP`] left the microphone open until the 60 second cap, and a
///   game's key handling runs per frame (~16 ms at 60 fps). A dropped press is
///   "I was not heard", which the player notices at once; a dropped release is
///   a hot mic, which they do not. Releases need no gate of their own: an
///   accepted one always follows an accepted press, so the press gate bounds
///   both.
/// - **A repeat is not a no-op.** `docs/SDK.md` tells a mod to re-send
///   `transmit: true` to keep a transmission past 60 seconds, so the caller
///   refreshes the deadline on one.
fn transmit_step(
    on: bool,
    held: bool,
    last_tx: Option<tokio::time::Instant>,
    now: tokio::time::Instant,
) -> TxStep {
    if on == held {
        TxStep::Repeat
    } else if on && last_tx.is_some_and(|t| now.duration_since(t) < MIN_UPDATE_GAP) {
        TxStep::RateLimited
    } else {
        TxStep::Act
    }
}

/// May this socket let go of the microphone on the user's behalf?
///
/// Only while it still owns the mix. A socket that was replaced by a newer one
/// (a resource restarting) still believes it is holding the key it pressed, and
/// its next event — or its 60 second timer — would otherwise release a hold the
/// *new* socket has since taken, cutting a radio transmission mid-sentence.
/// `ptt_sdk` is one flag for the whole app, so there is nobody else to ask.
fn releases_transmit(owner_generation: u64, generation: u64) -> bool {
    owner_generation == generation
}

/// Has the user allowed a game to press their push-to-talk? Read fresh every
/// time, so unticking the box in Settings stops the next frame rather than the
/// next connection.
fn transmit_allowed(app: &tauri::AppHandle) -> bool {
    let state = app.state::<AppState>();
    let config = state.config();
    config.sdk_transmit_allowed
}

/// Let go of the microphone on this socket's behalf, if it was holding it.
async fn release_transmit(app: &tauri::AppHandle) {
    let _ = crate::commands::sdk_set_transmit(&app.state::<AppState>(), app.clone(), false).await;
}

/// An attacker-controlled name on its way to a toast and a banner: capped, and
/// stripped of anything that is not a printable character. A newline or a
/// right-to-left override in a resource name is how "VoIPC: re-enter your
/// password" gets drawn in VoIPC's own colours.
fn short_name(raw: &str, fallback: &str) -> String {
    let clean: String = raw
        .chars()
        .filter(|c| {
            // Controls, the bidi embedding/override marks, the bidi isolates
            // (U+2066–2069, which do the same job and are what a modern shaper
            // actually honours), and the zero-width joiners and marks a name
            // can hide a second name behind.
            !c.is_control()
                && !('\u{200b}'..='\u{200f}').contains(c)
                && !('\u{202a}'..='\u{202e}').contains(c)
                && !('\u{2066}'..='\u{2069}').contains(c)
        })
        .take(MAX_NAME)
        .collect();
    let clean = clean.trim();
    if clean.is_empty() {
        fallback.to_string()
    } else {
        clean.to_string()
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
    //
    // The refusal carries **no** connection: this is the one reply an origin
    // that has never been near this server can provoke, and filling it in told
    // any allowed page the user's id, name, mute state and — by guessing
    // `server` until the answer changes — which server they are on.
    let actual = connection.server_address.clone();
    match hello.server.as_deref() {
        Some(expected) if actual.is_empty() || server_matches(expected, &actual) => {}
        _ => return state_message("wrong_server", None, None),
    }

    if hello.sdk != 1 {
        return serde_json::json!({
            "type": "error",
            "reason": format!("unsupported SDK version {}", hello.sdk),
        });
    }

    // Beacon mode is the one thing a game can ask for that puts something on
    // the wire, so the user has to have said yes to it first.
    let beacon_allowed = state.config().sdk_beacon_allowed;
    let beacon = match beacon_mode(hello.mode.as_deref(), beacon_allowed) {
        Ok(b) => b,
        Err(reason) => return serde_json::json!({ "type": "error", "reason": reason }),
    };

    // Naming the channel is required. Without it a mod armed itself on
    // whichever channel the user happened to be in — including a private,
    // non-positional one, where the room view shows no "a game is placing
    // people" banner and yet every voice can still be given an effect.
    let Some(wanted) = hello.channel.as_deref().filter(|n| !n.is_empty()) else {
        return serde_json::json!({
            "type": "error",
            "reason": "hello needs the channel your players talk in",
        });
    };
    let channel = connection
        .channels
        .lock()
        .ok()
        .and_then(|list| list.iter().find(|c| c.name == wanted).cloned());
    let Some(channel) = channel else {
        return serde_json::json!({
            "type": "error",
            "reason": format!("no channel named {wanted}"),
        });
    };

    // Everything needed after the guard is dropped: a stalled control stream
    // would otherwise park this task inside the lock, and the next
    // connect/disconnect would wait behind a game.
    let tcp_tx = connection.tcp_tx.clone();
    let current_channel = connection.current_channel_id.clone();
    let user_id = connection.user_id;
    let (channel_id, name) = (channel.channel_id, channel.name);
    // Subscribed before the join is sent, so its refusal cannot be missed
    let mut events = state.sdk_events.subscribe();
    drop(conn);

    // Wait for the join before claiming to be ingame. Arming the SDK on a
    // join that never happened would leave distance culling on with nobody
    // driving it, i.e. everyone silent.
    if current_channel.load(Ordering::Relaxed) != channel_id {
        let _ = crate::network::send_tcp_message(
            &tcp_tx,
            &voipc_protocol::messages::ClientMessage::JoinChannel {
                channel_id,
                password: hello.password.clone(),
            },
        )
        .await;

        let deadline = tokio::time::Instant::now() + JOIN_TIMEOUT;
        loop {
            if current_channel.load(Ordering::Relaxed) == channel_id {
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

    // In the channel: from here on the game owns the positions. The connection
    // may have been replaced while we waited, so check it is still ours.
    let conn = state.connection.read().await;
    let Some(connection) = conn.as_ref().filter(|c| c.user_id == user_id) else {
        return state_message("disconnected", None, None);
    };
    if let Ok(mut spatial) = connection.spatial.lock() {
        spatial.clear_positions();
        spatial.sdk_channel = Some(connection.current_channel_id.load(Ordering::Relaxed));
        if beacon {
            // The mod can only see its own player, so nobody is culled and the
            // peers place themselves: this is the user's own *Sync my
            // position*, switched on by a game they allowed to do it. Their
            // own setting is remembered, and handed back when the game goes.
            spatial.sdk_active = false;
            spatial.user_sync = spatial.sync;
            spatial.beacon = true;
            spatial.sync = true;
        } else {
            spatial.sdk_active = true;
            spatial.sync = false;
        }
    }
    let mut msg = state_message("ingame", Some(connection), Some(name));
    // Confirms which mode the mod actually got — it asked, the user's settings
    // answered — and is what the toast reads to tell them what they allowed.
    msg["beacon"] = beacon.into();
    msg
}

/// Apply one bulk update. Players the game leaves out are silent — that is how
/// SaltyChat and YACA cull by distance, and scripts rely on it.
///
/// Returns the ids the mod just placed, which is both what it may be told
/// about (see [`event_message`]) and what the UI greys out: a game silences
/// people by leaving them out, and the user is entitled to see that happening.
async fn apply_update(
    app: &tauri::AppHandle,
    update: Update,
    hello_user_id: Option<u32>,
) -> Result<std::collections::HashSet<u32>, String> {
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

    let here = connection.current_channel_id.load(Ordering::Relaxed);
    // The lock is held for exactly this block: everything below it talks to
    // the network, and the mixer needs this mutex every 20 ms.
    let (audible, changed) = {
        let mut spatial = connection.spatial.lock().unwrap_or_else(|p| p.into_inner());

        // We left the channel the game said hello for (the user switched, or an
        // admin moved us). Its player ids mean nothing here, and applying them
        // would cull everyone in the new channel to silence.
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
            // The room the listener is standing in. Kept apart from the user's own
            // pair, so closing the game hands their settings straight back.
            let (underwater, reverb) = reverb_water_from(&own);
            spatial.sdk_underwater = underwater;
            spatial.sdk_reverb = reverb;
        }

        // In beacon mode the mod knows only where its own player is; the other
        // members place themselves over the encrypted position packets. Anything
        // it does send about them is ignored rather than half-applied, because
        // half-applying it would cull everybody it could not see.
        if spatial.beacon {
            spatial.dirty = true;
            return Ok(std::collections::HashSet::new());
        }

        let placed = sources_from(update.players, &spatial.motion, over, now)?;
        let audible = placed.audible();
        let was: std::collections::HashSet<u32> = spatial
            .sources
            .keys()
            .chain(spatial.layers.keys())
            .copied()
            .collect();
        let changed = was != audible;
        // All replaced wholesale, so a culled player leaves no glide behind
        spatial.sources = placed.sources;
        spatial.layers = placed.layers;
        spatial.motion = placed.motion;
        spatial.sdk_active = true;
        (audible, changed)
    };

    // Who the game is letting the user hear, for the member list and the
    // mixer. On the change only — this runs up to 20 times a second.
    if changed {
        let mut ids: Vec<u32> = audible.iter().copied().collect();
        ids.sort_unstable();
        let _ = app.emit("sdk-audible", serde_json::json!({ "ids": ids }));
        // And, in a channel that says it is routed, to the relay: it can then
        // stop forwarding the rest, which is what keeps a busy map from
        // sending every listener every talker. Only there — everywhere else
        // the server is told nothing about who hears whom, and a channel has
        // to say so before we volunteer it. See `routing.rs` on the server.
        if channel_is_routed(connection, here) {
            let _ = crate::network::send_tcp_message(
                &connection.tcp_tx,
                &voipc_protocol::messages::ClientMessage::SetAudioFilter { allow: Some(ids) },
            )
            .await;
        }
    }
    Ok(audible)
}

/// Does this channel ask the relay to forward voice selectively?
fn channel_is_routed(connection: &crate::app_state::ActiveConnection, channel_id: u32) -> bool {
    connection
        .channels
        .lock()
        .ok()
        .is_some_and(|list| {
            list.iter()
                .any(|c| c.channel_id == channel_id && c.routed)
        })
}

/// Stop asking the relay to cull for us. Sent whenever the game stops driving
/// — it left, the user changed channel, the integration was switched off — so
/// the escape hatch is always "turn the game off and hear everyone again",
/// never "hope the relay forgets".
async fn clear_audio_filter(connection: &crate::app_state::ActiveConnection) {
    let _ = crate::network::send_tcp_message(
        &connection.tcp_tx,
        &voipc_protocol::messages::ClientMessage::SetAudioFilter { allow: None },
    )
    .await;
}

/// Turn one update's `players` into placements and glides.
///
/// Free-standing and synchronous, so every rule below can be tested without an
/// app, a connection or a socket: the whole of `apply_update` around it is
/// locks and `await`s.
fn sources_from(
    players: Vec<PlayerState>,
    prev_motion: &HashMap<u32, Motion>,
    over: std::time::Duration,
    now: std::time::Instant,
) -> Result<Placements, String> {
    let mut out = Placements {
        sources: HashMap::with_capacity(players.len()),
        layers: HashMap::new(),
        motion: HashMap::with_capacity(players.len()),
    };
    let mut seen: std::collections::HashSet<u32> = std::collections::HashSet::new();
    for player in players {
        // Two entries for one id is not a mod being sloppy: on a game server
        // where players publish their own VoIPC id (which is the documented
        // trust model), it is how one player claims another's — the second
        // entry would win the insert, and that speaker would be heard at the
        // claimer's position, or culled. Refuse the whole update instead.
        if !seen.insert(player.id) {
            return Err(format!("player {} is listed twice", player.id));
        }
        // Over the cap they are dropped rather than refused: a tick the mixer
        // never applies is a frozen mix, which is worse than a missing layer.
        let extra: Vec<Source> = player
            .layers
            .iter()
            .take(MAX_LAYERS)
            .map(|spec| source_from(spec, false, player.id))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect();
        if !extra.is_empty() {
            out.layers.insert(player.id, extra);
        }
        // `mode: "off"` leaves the base render out, which is how a mod says
        // "you hear this person only through the layers" — the caller across
        // the map, who has no position in your world at all.
        let Some(src) = source_from(&player.spec, true, player.id)? else {
            continue;
        };
        if !src.direct {
            // Someone the game listed before glides on; a newcomer, or someone
            // who was culled and came back, snaps.
            out.motion.insert(
                player.id,
                match prev_motion.get(&player.id) {
                    Some(prev) => Motion::glide(prev, src.pos, over, now),
                    None => Motion::snap(src.pos, now),
                },
            );
        }
        out.sources.insert(player.id, src);
    }
    Ok(out)
}

/// What one update places: a base render per player, the extra renders some of
/// them carry, and the glides for whatever is positional.
#[derive(Debug)]
struct Placements {
    sources: HashMap<u32, Source>,
    layers: HashMap<u32, Vec<Source>>,
    motion: HashMap<u32, Motion>,
}

impl Placements {
    /// Everybody the game is letting through, base render or layer. A player
    /// heard only through a layer is still heard.
    fn audible(&self) -> std::collections::HashSet<u32> {
        self.sources.keys().chain(self.layers.keys()).copied().collect()
    }
}

/// One render from one spec, or `None` for `mode: "off"`.
///
/// `base` picks between the two `mode` rules:
///
/// - On the **base** render a chain implies `direct`. That is documented, and
///   mods rely on it: `mode: "radio"` means "not coming from the world".
/// - On a **layer**, `pos` decides. A layer may therefore be positional *and*
///   carry a chain, which is the whole unlock for the case nobody else does:
///   the tinny earpiece leaking out of the phone at the speaker's own head,
///   two metres away from you, while their real voice carries across the room.
fn source_from(spec: &RenderSpec, base: bool, id: u32) -> Result<Option<Source>, String> {
    let mode = spec.mode.as_deref();
    if mode == Some("off") {
        return Ok(None);
    }
    let fx = mode.map_or(Effect::None, effect_from_str);
    let direct = if base {
        fx != Effect::None || mode == Some("direct")
    } else {
        spec.pos.is_none() || mode == Some("direct")
    };
    let pos = spec.pos.unwrap_or([0.0; 3]);
    if !pos.iter().all(|c| c.is_finite()) {
        return Err(format!("position of player {id} must be finite"));
    }
    // Every float is checked: one NaN would make the gains NaN and, through
    // the mixer's ramp state, silence that source for good.
    let range = spec.range.filter(|r| r.is_finite()).unwrap_or(DEFAULT_RANGE);
    let volume = spec.volume.filter(|v| v.is_finite()).unwrap_or(1.0);
    let pan = spec.pan.filter(|p| p.is_finite()).unwrap_or(0.0);
    Ok(Some(Source {
        pos,
        range: range.max(0.01),
        volume: volume.clamp(0.0, 2.0),
        muffle: spec.muffle.unwrap_or(0).min(MAX_MUFFLE),
        direct,
        fx,
        pan: pan.clamp(-1.0, 1.0),
        // Capped before it is divided, so `delay` cannot ask for a ring
        delay_frames: (spec.delay.unwrap_or(0).min(MAX_DELAY_MS) / FRAME_MS) as u8,
    }))
}

/// The game is gone: hand the mix back to the plain per-user volumes. Waits
/// for the lock — a `try_read` that loses a race with connect/disconnect would
/// leave SDK culling armed with no game, i.e. everyone silent.
async fn clear_sdk_positions(app: &tauri::AppHandle) {
    let state = app.state::<AppState>();
    let conn = state.connection.read().await;
    if let Some(connection) = conn.as_ref() {
        {
            let mut spatial = connection.spatial.lock().unwrap_or_else(|p| p.into_inner());
            spatial.sdk_active = false;
            spatial.clear_positions();
        }
        clear_audio_filter(connection).await;
    }
    let _ = app.emit("sdk-audible", serde_json::json!({ "ids": serde_json::Value::Null }));
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
        "capabilities": capabilities(),
        "modes": modes(),
    });
    if let Some(c) = connection {
        // What the user will actually hear, not what the channel is set to:
        // with *Hear people where they stand* off, nothing is placed, and a
        // mod reading "3d" here would blame itself for a mix that never moves.
        let proximity = c
            .spatial
            .lock()
            .map(|s| s.proximity_for_sdk())
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

// bernd: text frames, no fragmentation, no extensions — a NUI page sends
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
/// Returns whatever arrived after the header block — a client may pipeline its
/// first frame behind the request, and those bytes used to be dropped on the
/// floor; browsers wait for the 101, a hand-rolled client need not — plus the
/// `Origin` the browser stamped on it. The page cannot forge that header, so
/// it is the one thing that tells two resources in the same game runtime apart.
async fn handshake(
    stream: &mut TcpStream,
    extra_origins: &[String],
    per_origin: &OriginCounts,
) -> anyhow::Result<(Vec<u8>, Option<String>, OriginSlot)> {
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

    // Before the 101, so a page hoarding sockets is answered with a status line
    // rather than an open WebSocket it can keep alive with `ping`.
    let Some(slot) = take_origin_slot(per_origin, &upgrade.origin) else {
        reject(stream, "503 Service Unavailable").await;
        warn!(
            origin = ?upgrade.origin,
            "game SDK refused a socket: this origin already holds {MAX_PER_ORIGIN}"
        );
        anyhow::bail!("origin already holds {MAX_PER_ORIGIN} sockets");
    };

    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {}\r\n\r\n",
        accept_key(&upgrade.key)
    );
    stream.write_all(response.as_bytes()).await?;
    Ok((leftover, upgrade.origin, slot))
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
        assert!(origin_allowed("http://mta", &[]), "MTA:SA's CEF was refused");
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
            // MTA's origin is a bare host, which makes it exactly the shape a
            // registrable domain can imitate
            "http://mta.attacker.example",
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
            r#"{"type":"update","self":{"pos":[1,2,3],"yaw":90,"underwater":4,"reverb":11},
                "players":[{"id":42,"pos":[4,5,6],"range":8,"muffle":6},
                           {"id":7,"mode":"radio","volume":0.8},
                           {"id":9,"pos":[1,2,3],
                            "layers":[{"mode":"mobile","pan":-0.9},
                                      {"mode":"badvoip","pos":[1,2,4],"range":2.5,
                                       "volume":0.35,"muffle":3,"delay":40}]}]}"#,
        )
        .unwrap();
        match update {
            GameMessage::Update(u) => {
                assert_eq!(u.players.len(), 3);
                assert_eq!(u.players[0].id, 42);
                assert_eq!(u.players[0].spec.muffle, Some(6));
                assert_eq!(u.players[1].spec.mode.as_deref(), Some("radio"));
                // The documented layered player, field for field
                let layers = &u.players[2].layers;
                assert_eq!(layers.len(), 2);
                assert_eq!(layers[0].mode.as_deref(), Some("mobile"));
                assert_eq!(layers[0].pan, Some(-0.9));
                assert_eq!(layers[1].pos, Some([1.0, 2.0, 4.0]));
                assert_eq!(layers[1].delay, Some(40));
                assert_eq!(layers[1].volume, Some(0.35));
                assert!(u.players[0].layers.is_empty(), "layers default to none");
                let own = u.own.expect("self");
                // (underwater, reverb), and the out-of-range reverb is clamped
                assert_eq!(reverb_water_from(&own), (4, MAX_REVERB));
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
    fn the_room_levels_are_clamped_and_default_to_zero() {
        let own = |json: &str| serde_json::from_str::<SelfState>(json).unwrap();
        assert_eq!(reverb_water_from(&own(r#"{"pos":[0,0,0]}"#)), (0, 0));
        assert_eq!(
            reverb_water_from(&own(r#"{"pos":[0,0,0],"underwater":250,"reverb":3}"#)),
            (MAX_UNDERWATER, 3)
        );
        // A negative or fractional level is refused at the serde layer, which
        // is what turns it into the documented error reply
        assert!(serde_json::from_str::<SelfState>(r#"{"pos":[0,0,0],"reverb":-1}"#).is_err());
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

    /// The set of ids a mod placed in its last update.
    fn placed(ids: &[u32]) -> std::collections::HashSet<u32> {
        ids.iter().copied().collect()
    }

    #[test]
    fn push_messages_fold_our_own_state() {
        let mut own = Own::default();
        let listed = placed(&[7]);
        // Somebody else: a plain talk message, our own state untouched
        let msg = event_message(
            &SdkEvent::Talk { user_id: 7, speaking: true },
            Some(42),
            &mut own,
            &listed,
        );
        assert_eq!(
            msg.unwrap(),
            r#"{"speaking":true,"type":"talk","user_id":7}"#
        );
        assert!(!own.speaking);

        // Ourselves: a `self` message carrying every field
        event_message(&SdkEvent::Muted { user_id: 42, muted: true }, Some(42), &mut own, &listed);
        let msg = event_message(
            &SdkEvent::Talk { user_id: 42, speaking: true },
            Some(42),
            &mut own,
            &listed,
        )
        .unwrap();
        assert!(msg.contains(r#""muted":true"#), "{msg}");
        assert!(msg.contains(r#""speaking":true"#), "{msg}");
        assert!(msg.contains(r#""type":"self""#), "{msg}");

        // A socket that never said hello, and events that are not the mod's
        assert!(event_message(
            &SdkEvent::Talk { user_id: 7, speaking: true },
            None,
            &mut own,
            &listed
        )
        .is_none());
        assert!(
            event_message(&SdkEvent::ChannelError("nope".into()), Some(42), &mut own, &listed)
                .is_none()
        );
    }

    #[test]
    fn a_mod_only_hears_about_the_players_it_placed() {
        // The socket is not a directory of the room: a mod is told when the
        // people it placed speak, and when the user does, and nothing else.
        // Otherwise a resource on any allowed origin can sit in a channel and
        // learn who is in it with the user, and when each of them talks.
        let mut own = Own::default();
        let listed = placed(&[7]);
        let talk = |id: u32, own: &mut Own| {
            event_message(&SdkEvent::Talk { user_id: id, speaking: true }, Some(42), own, &listed)
        };
        assert!(talk(7, &mut own).is_some(), "a placed player must be reported");
        assert!(talk(9, &mut own).is_none(), "an unplaced player leaked");
        // Ours always goes out: it is the user's own state, to the user's game
        assert!(talk(42, &mut own).is_some());
        assert!(
            event_message(&SdkEvent::Muted { user_id: 9, muted: true }, Some(42), &mut own, &listed)
                .is_none(),
            "an unplaced player's mute leaked"
        );

        // And with nothing placed yet, only our own state is pushed
        let empty = placed(&[]);
        assert!(event_message(
            &SdkEvent::Talk { user_id: 7, speaking: true },
            Some(42),
            &mut own,
            &empty
        )
        .is_none());
    }

    #[test]
    fn a_proximity_change_is_pushed_as_a_partial_state() {
        let mut own = Own::default();
        let msg = event_message(
            &SdkEvent::Proximity { mode: ProximityMode::Off },
            Some(42),
            &mut own,
            &placed(&[]),
        )
        .expect("a proximity change must reach the mod");
        assert!(msg.contains(r#""type":"state""#), "{msg}");
        assert!(msg.contains(r#""proximity":"off""#), "{msg}");
    }

    #[test]
    fn a_detached_socket_is_handled_by_the_caller_not_the_message() {
        // `serve` clears `hello_user_id` on this one; there is nothing to send
        let mut own = Own::default();
        assert!(
            event_message(&SdkEvent::Detached, Some(42), &mut own, &placed(&[7])).is_none(),
            "Detached must not be forwarded to the mod"
        );
    }

    #[test]
    fn one_origin_owns_the_mix_at_a_time() {
        // Every `cfx-nui-*` page on a FiveM server is a trusted origin, so
        // without this any other script there could take placement off the
        // voice resource — and each takeover clears every placement, so two of
        // them fighting sounds like silence.
        let nobody = Owner::default();
        let fivem = Some("https://cfx-nui-my-voice".to_string());
        let other = Some("https://cfx-nui-some-menu".to_string());
        let held = Owner { generation: 7, origin: fivem.clone() };

        assert!(!owner_conflict(&nobody, 9, &fivem), "an idle mix was refused");
        assert!(!owner_conflict(&held, 7, &fivem), "the owner was refused its own mix");
        // A resource restarting: same origin, newer socket, takes over
        assert!(!owner_conflict(&held, 9, &fivem));
        // Anybody else waits until that socket dies
        assert!(owner_conflict(&held, 9, &other), "a second origin took the mix");
        assert!(owner_conflict(&held, 9, &None), "a native client took the mix");
        // Native clients have no Origin to tell apart, so they are one class
        let native = Owner { generation: 7, origin: None };
        assert!(!owner_conflict(&native, 9, &None));
        assert!(owner_conflict(&native, 9, &fivem));
    }

    #[test]
    fn one_origin_cannot_hold_every_socket() {
        // Every `cfx-nui-*` page is a trusted origin, so a third-party script
        // on the same game server could otherwise open every slot, keep them
        // alive with `ping`, and the voice resource's next restart would be
        // answered 503 for the rest of the session.
        let counts: OriginCounts = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let voice = Some("https://cfx-nui-my-voice".to_string());
        let menu = Some("https://cfx-nui-some-menu".to_string());

        let first = take_origin_slot(&counts, &menu).expect("the first socket was refused");
        let second = take_origin_slot(&counts, &menu).expect("a resource restart was refused");
        assert!(
            take_origin_slot(&counts, &menu).is_none(),
            "one origin held a third socket"
        );
        // …and the game's own resource still gets in
        let theirs = take_origin_slot(&counts, &voice).expect("another origin was refused");

        // A socket ending gives its slot back, whatever ended it
        drop(second);
        let third = take_origin_slot(&counts, &menu).expect("a slot was never released");
        drop(third);
        drop(first);
        drop(theirs);
        // `cfx-nui-<anything>` is an allowed prefix, so the map must not keep a
        // row per name a loop of fresh ones has used
        assert!(
            counts.lock().unwrap().is_empty(),
            "origins with no sockets kept their rows"
        );
    }

    #[test]
    fn a_tapped_radio_key_is_never_left_holding_the_microphone() {
        let t0 = tokio::time::Instant::now();
        let soon = t0 + MIN_UPDATE_GAP / 2;

        // A tap: press and release inside one rate-limit window, which is what
        // a game's per-frame key handling produces at 60 fps. Both are acted
        // on — rate-limiting the release left the microphone open until the
        // 60 second cap, out of a key the player tapped once.
        assert_eq!(transmit_step(true, false, None, t0), TxStep::Act);
        assert_eq!(
            transmit_step(false, true, Some(t0), soon),
            TxStep::Act,
            "a release was dropped: that is a hot mic"
        );

        // A press that soon after a press is still a flood, and still refused
        assert_eq!(transmit_step(true, false, Some(t0), soon), TxStep::RateLimited);
        // …and once the window has passed it goes through
        assert_eq!(
            transmit_step(true, false, Some(t0), t0 + MIN_UPDATE_GAP),
            TxStep::Act
        );

        // Re-sending a press the microphone is already holding is the
        // documented way to keep talking past 60 s: not an edge, but not
        // nothing either — the caller refreshes the deadline on it.
        assert_eq!(transmit_step(true, true, Some(t0), soon), TxStep::Repeat);
        assert_eq!(transmit_step(false, false, Some(t0), soon), TxStep::Repeat);
    }

    #[test]
    fn a_socket_that_lost_the_mix_does_not_let_go_of_the_microphone() {
        // A resource restarting leaves the old socket believing it still holds
        // the key it pressed. Its next event — or its 60 second timer — would
        // release a hold the *new* socket has since taken, cutting a radio
        // transmission mid-sentence; `ptt_sdk` is one flag for the whole app.
        assert!(releases_transmit(7, 7), "the owner could not let go");
        assert!(!releases_transmit(9, 7), "a replaced socket released the new owner's hold");
        assert!(!releases_transmit(0, 7), "a socket released a mix nobody owns");
    }

    #[test]
    fn beacon_mode_needs_the_players_consent() {
        // The one thing a mod can ask for that leaves the machine.
        assert_eq!(beacon_mode(None, false), Ok(false));
        assert_eq!(beacon_mode(Some("players"), false), Ok(false));
        assert_eq!(beacon_mode(Some("beacon"), true), Ok(true));

        let refused = beacon_mode(Some("beacon"), false).expect_err("beaconing without consent");
        assert!(refused.contains("Settings"), "{refused}");
        // An unknown mode is refused rather than quietly treated as `players`:
        // a mod asking for something this build does not have should hear so.
        assert!(beacon_mode(Some("mirror"), true).is_err());
    }

    #[test]
    fn a_refusal_never_names_the_user() {
        // `wrong_server` is the one reply an origin that has never been near
        // this VoIPC server can provoke. Filling in the connection told any
        // allowed page — every `cfx-nui-*` resource on every FiveM server, any
        // localhost page, any local process — the user's id, name and mute
        // state, and let it find their server by guessing `server` until the
        // answer changed.
        let msg = state_message("wrong_server", None, None);
        for field in ["user_id", "username", "muted", "deafened", "proximity", "channel"] {
            assert!(msg.get(field).is_none(), "{field} leaked in a refusal: {msg}");
        }
        // What a mod legitimately needs to report the problem stays
        assert_eq!(msg["state"], "wrong_server");
        assert!(msg.get("version").is_some() && msg.get("capabilities").is_some());
    }

    #[test]
    fn a_name_from_a_mod_cannot_paint_the_ui() {
        // `game` and `resource` are attacker strings on their way to a toast
        // and a banner. A newline plus a right-to-left override is how
        // "VoIPC: re-enter your password" gets drawn in VoIPC's own colours.
        assert_eq!(short_name("fivem", "a game"), "fivem");
        assert_eq!(short_name("", "a game"), "a game");
        assert_eq!(short_name("   ", "a game"), "a game");
        assert_eq!(short_name("a\nb\u{202e}c", ""), "abc");
        assert_eq!(short_name(&"x".repeat(200), "").len(), MAX_NAME);
    }

    /// A player with nothing but a position, ready to be `..`-overridden.
    fn player(id: u32) -> PlayerState {
        PlayerState {
            id,
            spec: RenderSpec { pos: Some([1.0, 2.0, 3.0]), ..RenderSpec::default() },
            layers: Vec::new(),
        }
    }

    fn place(players: Vec<PlayerState>) -> Result<Placements, String> {
        sources_from(players, &HashMap::new(), MIN_GLIDE, std::time::Instant::now())
    }

    #[test]
    fn one_player_may_not_be_listed_twice() {
        // On a game server where players publish their own VoIPC id — the
        // documented trust model — a second entry for somebody else's id is
        // how one player takes over another's voice: last insert wins, so the
        // victim is heard at the claimer's position, or culled outright.
        let err = place(vec![player(7), player(7)]).expect_err("a duplicate id was accepted");
        assert!(err.contains("twice"), "{err}");
        // Two different players are of course fine
        let placed = place(vec![player(7), player(9)]).unwrap();
        assert_eq!(placed.sources.len(), 2);
        assert_eq!(placed.motion.len(), 2);
        // …and a duplicate is caught even when neither has a base render
        let silent = |id| PlayerState {
            spec: RenderSpec { mode: Some("off".into()), ..RenderSpec::default() },
            ..player(id)
        };
        assert!(place(vec![silent(7), silent(7)]).is_err());
    }

    #[test]
    fn a_placement_is_clamped_and_a_nan_is_refused() {
        let one = |spec: RenderSpec| {
            place(vec![PlayerState { spec, ..player(1) }])
                .map(|p| (p.sources[&1], p.motion.len()))
        };
        let base = RenderSpec { pos: Some([0.0; 3]), ..RenderSpec::default() };

        let (src, glides) = one(base.clone()).unwrap();
        assert_eq!((src.range, src.volume, src.muffle), (DEFAULT_RANGE, 1.0, 0));
        assert_eq!((src.pan, src.delay_frames), (0.0, 0));
        assert!(!src.direct);
        assert_eq!(glides, 1, "a positional player needs a glide");

        // Out of range in every direction, and every one of them clamped
        let (src, _) = one(RenderSpec {
            range: Some(0.0),
            volume: Some(9.0),
            muffle: Some(250),
            pan: Some(-4.0),
            delay: Some(10_000),
            ..base.clone()
        })
        .unwrap();
        assert!(src.range > 0.0, "a zero range divides by zero downstream");
        assert_eq!((src.volume, src.muffle, src.pan), (2.0, MAX_MUFFLE, -1.0));
        assert_eq!(
            src.delay_frames as u32,
            MAX_DELAY_MS / FRAME_MS,
            "an unbounded delay is a request to allocate"
        );

        // A chain implies `direct` on the base, and a direct source gets no glide
        let (src, glides) = one(RenderSpec { mode: Some("walkie".into()), ..base.clone() }).unwrap();
        assert!(src.direct && src.fx == Effect::Walkie);
        assert_eq!(glides, 0);
        // An unknown mode stays positional, so a mod written against a later
        // VoIPC keeps working here
        let (src, _) = one(RenderSpec { mode: Some("hologram".into()), ..base.clone() }).unwrap();
        assert!(!src.direct && src.fx == Effect::None);

        // NaN would make the gains NaN and, through the ramp, silence that
        // source for good — so it is refused rather than clamped
        assert!(one(RenderSpec { pos: Some([f32::NAN, 0.0, 0.0]), ..base.clone() }).is_err());
        // …while a NaN range, volume or pan falls back to the default
        let (src, _) = one(RenderSpec {
            range: Some(f32::NAN),
            volume: Some(f32::INFINITY),
            pan: Some(f32::NAN),
            ..base.clone()
        })
        .unwrap();
        assert_eq!((src.range, src.volume, src.pan), (DEFAULT_RANGE, 1.0, 0.0));
    }

    #[test]
    fn a_layer_is_positional_and_effected_at_the_same_time() {
        // The case no other proximity plugin can express: somebody is on the
        // phone to you *and* standing across the room. Their voice arrives
        // twice — the earpiece in one ear, their real voice where they stand.
        let placed = place(vec![PlayerState {
            spec: RenderSpec { pos: Some([10.0, 0.0, 0.0]), ..RenderSpec::default() },
            layers: vec![
                RenderSpec { mode: Some("mobile".into()), pan: Some(-0.9), ..RenderSpec::default() },
                RenderSpec {
                    mode: Some("badvoip".into()),
                    pos: Some([10.0, 0.0, 1.6]),
                    range: Some(2.5),
                    volume: Some(0.35),
                    ..RenderSpec::default()
                },
            ],
            ..player(7)
        }])
        .unwrap();

        let base = placed.sources[&7];
        assert!(!base.direct && base.fx == Effect::None, "the base is still a person");
        let layers = &placed.layers[&7];
        assert_eq!(layers.len(), 2);
        // The phone: no position, so direct, and in the left ear
        assert!(layers[0].direct && layers[0].fx == Effect::Mobile && layers[0].pan == -0.9);
        // The earpiece leaking at their head: positional *and* effected, which
        // is the one rule a layer does not share with the base render
        assert!(!layers[1].direct, "a layer with a position must stay positional");
        assert_eq!(layers[1].fx, Effect::BadVoip);
        assert_eq!((layers[1].range, layers[1].volume), (2.5, 0.35));
        // Only the base glides
        assert_eq!(placed.motion.len(), 1);
        assert_eq!(placed.audible(), [7].into_iter().collect());
    }

    #[test]
    fn a_voice_can_be_heard_only_through_its_layers() {
        // A call partner on the other side of the map has no position in your
        // world at all, so the mod sends no base render for them. `volume: 0`
        // is not the way to say that: in a channel that is not positional the
        // gains never reach `volume`, and they would play at full level.
        let placed = place(vec![PlayerState {
            spec: RenderSpec { mode: Some("off".into()), ..RenderSpec::default() },
            layers: vec![RenderSpec { mode: Some("landline".into()), ..RenderSpec::default() }],
            ..player(7)
        }])
        .unwrap();
        assert!(placed.sources.is_empty(), "mode:off still placed the speaker");
        assert!(placed.motion.is_empty());
        assert_eq!(placed.layers[&7].len(), 1);
        // Heard, though — the member list must not grey them out
        assert_eq!(placed.audible(), [7].into_iter().collect());
    }

    #[test]
    fn too_many_layers_are_dropped_rather_than_refused() {
        // Refusing the tick would freeze the whole mix, which is much worse
        // than one missing render.
        let placed = place(vec![PlayerState {
            layers: vec![RenderSpec { mode: Some("radio".into()), ..RenderSpec::default() }; 9],
            ..player(7)
        }])
        .unwrap();
        assert_eq!(placed.layers[&7].len(), MAX_LAYERS);
    }

    #[tokio::test]
    async fn a_pipelined_first_frame_survives_the_handshake() {
        // A client that writes its upgrade and its first frame in one go used
        // to lose the frame: the handshake read it and threw it away.
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let counts: OriginCounts = Arc::new(std::sync::Mutex::new(HashMap::new()));
            let (mut buf, _origin, _slot) = handshake(&mut stream, &[], &counts).await.unwrap();
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
            let counts: OriginCounts = Arc::new(std::sync::Mutex::new(HashMap::new()));
            let (mut buf, _origin, _slot) = handshake(&mut stream, &[], &counts).await.unwrap();
            let (mut rd, _wr) = stream.into_split();
            read_frame(&mut rd, &mut buf).await
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(UPGRADE.as_bytes()).await.unwrap();
        client.write_all(&frame_bytes(0x1, b"hi")).await.unwrap();
        assert!(server.await.unwrap().is_err(), "an unmasked frame was accepted");
    }
}
