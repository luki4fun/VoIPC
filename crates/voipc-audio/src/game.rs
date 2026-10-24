//! The pure half of game integration: what a game mod or a MumbleLink block
//! sends, and the rules that turn it into placements. No app, socket or
//! device here, so the rules are testable on their own and fuzzable
//! (`client/src-tauri/src/sdk.rs` and `mumblelink.rs` are the I/O around it).

use std::collections::HashMap;

use serde::Deserialize;
use voipc_protocol::ws;

use crate::spatial::{
    effect_from_str, Effect, Source, DEFAULT_RANGE, MAX_MUFFLE, MAX_REVERB, MAX_UNDERWATER,
};

/// Largest WebSocket frame we accept (a bulk update of a full server).
pub const MAX_FRAME: usize = 64 * 1024;

/// Shortest gap between two `update` frames we will act on. The documented
/// ceiling is 20 Hz and a real mod sends 4–10, so this is pure slack — but
/// without it a mod (or a page on an allowed origin) can hold the spatial
/// mutex, which the mixer needs every 20 ms, at loopback line rate.
pub const MIN_UPDATE_GAP: std::time::Duration = std::time::Duration::from_millis(20);

/// Longest `game` / `resource` string kept. They are attacker-controlled and
/// end up in a toast and a banner; a name is a name, not a paragraph.
pub const MAX_NAME: usize = 32;

/// Extra renders one voice may have on top of its own. Four voices from one
/// speaker is already more than anybody can follow, and each one costs a
/// filter chain and a reverb bank in the mixer.
pub const MAX_LAYERS: usize = 3;

/// Longest `delay` honoured, in milliseconds. Bounds the ring a delayed layer
/// keeps: without a cap, `delay` is a request to allocate.
pub const MAX_DELAY_MS: u32 = 100;

/// One mixer frame, in milliseconds — the resolution `delay` is quantised to.
pub const FRAME_MS: u32 = 20;

/// FiveM / RedM NUI: the resource name follows this prefix, and nothing else
/// may. A host name is free to *start* with `cfx-nui-`, so a bare prefix match
/// let `https://cfx-nui-x.evil.example` — an ordinary internet page — drive the
/// mix; a single label with no dot, port or path cannot be served from the
/// internet. See [`origin_allowed`].
pub const FIVEM_ORIGIN_PREFIX: &str = "https://cfx-nui-";

/// Hosts allowed without configuration. Matched exactly (a port may follow):
/// a prefix match would accept `https://localhost.attacker.example`, which is
/// an ordinary internet page that can reach loopback like any other.
pub const DEFAULT_ORIGIN_HOSTS: &[&str] = &[
    "http://localhost",
    "https://localhost",
    "http://127.0.0.1",
    "https://127.0.0.1",
    // The CEF runtimes. An origin is scheme + host + port and nothing else
    // (RFC 6454): a page at `http://resource/voice/index.html` sends
    // `http://resource`, so these are bare hosts, matched exactly.
    "http://mta",      // MTA:SA
    "http://resource", // alt:V
    "http://package",  // RAGE:MP
];

// ── Wire types ───────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum GameMessage {
    Hello(Hello),
    Update(Update),
    /// Press or release the user's push-to-talk, because they pressed their
    /// in-game radio key. Refused unless the user allowed it in Settings.
    Transmit { on: bool },
    Ping,
    Bye,
}

#[derive(Debug, Deserialize)]
pub struct Hello {
    /// SDK protocol version the mod speaks.
    #[serde(default = "one")]
    pub sdk: u32,
    #[serde(default)]
    pub game: String,
    #[serde(default)]
    pub resource: String,
    /// `"players"` (the default): the mod places everybody, and VoIPC culls to
    /// what it lists. `"beacon"`: the mod can only see where its own player
    /// stands, so VoIPC broadcasts that position to the channel — encrypted
    /// like voice — and the other members' beacons place them. Beacon mode
    /// needs the user's consent, because it is the one thing here that puts
    /// something on the wire.
    #[serde(default)]
    pub mode: Option<String>,
    /// The server the mod expects us to be on, as `host:port`.
    #[serde(default)]
    pub server: Option<String>,
    /// Channel to join by name (the game's ingame channel).
    #[serde(default)]
    pub channel: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
}

fn one() -> u32 {
    1
}

#[derive(Debug, Deserialize)]
pub struct Update {
    #[serde(rename = "self")]
    pub own: Option<SelfState>,
    #[serde(default)]
    pub players: Vec<PlayerState>,
}

#[derive(Debug, Deserialize)]
pub struct SelfState {
    pub pos: [f32; 3],
    /// Facing in the x/y plane. `yaw` (degrees, 0 = +y, counter-clockwise) is
    /// accepted instead, because that is what the GTA natives hand a script.
    #[serde(default)]
    pub fwd: Option<[f32; 2]>,
    #[serde(default)]
    pub yaw: Option<f32>,
    /// Reverberation of the room the listener is in, 0–10: 0 outdoors, 4 a
    /// room, 7 a garage, 10 a cathedral. Applied to the whole mix.
    #[serde(default)]
    pub reverb: Option<u8>,
    /// How submerged the listener is, 0–10. Muffles and quietens everything.
    #[serde(default)]
    pub underwater: Option<u8>,
}

/// The listener's surroundings from one `self` object, clamped to the
/// documented range. A field the mod leaves out is off, like every other
/// omitted field. Free-standing so the clamp is testable without an app.
pub fn reverb_water_from(own: &SelfState) -> (u8, u8) {
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
pub struct RenderSpec {
    #[serde(default)]
    pub pos: Option<[f32; 3]>,
    /// Distance at which this player becomes inaudible (whisper/normal/shout).
    #[serde(default)]
    pub range: Option<f32>,
    #[serde(default)]
    pub volume: Option<f32>,
    /// Occlusion 0–10, as SaltyChat and YACA use it.
    #[serde(default)]
    pub muffle: Option<u8>,
    /// "spatial" (default), "direct", "off", or the id of an effect chain.
    #[serde(default)]
    pub mode: Option<String>,
    /// Which ear: −1 left, 0 centred (the default), +1 right. A phone held to
    /// an ear, or ACRE2's LEFT/CENTER/RIGHT for a radio.
    #[serde(default)]
    pub pan: Option<f32>,
    /// Hold this render back by up to [`MAX_DELAY_MS`], quantised to 20 ms
    /// frames: the radio arriving a beat after the voice in the room.
    #[serde(default)]
    pub delay: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PlayerState {
    /// The player's VoIPC user id, published by the game server.
    pub id: u32,
    /// How this voice is heard. `mode: "off"` silences it, which is what a
    /// caller on the far side of the map needs: no base render, layers only.
    #[serde(flatten)]
    pub spec: RenderSpec,
    /// Up to [`MAX_LAYERS`] further renders of the same voice, each a full
    /// spec of its own. Over the cap they are dropped, never refused —
    /// rejecting a tick freezes the whole mix.
    #[serde(default)]
    pub layers: Vec<RenderSpec>,
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
pub struct Owner {
    /// Generation of the owning connection; 0 = nobody owns the mix.
    pub generation: u64,
    pub origin: Option<String>,
}

/// Must this `hello` be refused because another game already owns the mix?
///
/// Free-standing so the rule can be read and tested on its own: everything
/// around it in `serve` is a socket. Nobody owning it, or the owner being this
/// same connection, or a newer socket from the **same origin** (a resource
/// restarting) all go through; a different origin does not, for as long as the
/// owner's socket lives.
pub fn owner_conflict(held: &Owner, generation: u64, origin: &Option<String>) -> bool {
    held.generation != 0 && held.generation != generation && &held.origin != origin
}

/// Which `hello.mode` this is, or why it is refused.
///
/// Free-standing for the same reason as [`owner_conflict`]: this is the gate
/// on the only thing a mod can ask for that leaves the machine, and a gate
/// worth having is a gate worth testing without a socket and an app around it.
pub fn beacon_mode(mode: Option<&str>, allowed: bool) -> Result<bool, String> {
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
pub enum TxStep {
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
pub fn transmit_step(
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
pub fn releases_transmit(owner_generation: u64, generation: u64) -> bool {
    owner_generation == generation
}

/// May a game's `hello` move the player into its channel?
///
/// Not once they have moved by their own hand since this socket's last
/// `hello`: `at_hello` is the user's move counter then (`None` before the
/// first), `now` is the counter now. The player leaving a game's channel is a
/// choice, and a mod that answers every "say hello again" with a `hello` would
/// otherwise pull them straight back — with the microphone open, in VAD.
pub fn may_move(at_hello: Option<u64>, now: u64) -> bool {
    at_hello.is_none_or(|at| at == now)
}

/// An attacker-controlled name on its way to a toast and a banner: capped, and
/// stripped of anything that is not a printable character. A newline or a
/// right-to-left override in a resource name is how "VoIPC: re-enter your
/// password" gets drawn in VoIPC's own colours.
pub fn short_name(raw: &str, fallback: &str) -> String {
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

/// Which open server a `hello` means. `server_matches` lets a mod leave the
/// port out, so several open servers can match one `hello.server`: the one on
/// exactly that `host:port` wins, then the one we are in voice on. `None` when
/// nothing matches, which is the only case that answers `wrong_server`.
pub fn pick_server<'a>(
    expected: &str,
    open: impl Iterator<Item = &'a str>,
    voice: Option<&str>,
) -> Option<&'a str> {
    open.filter(|id| server_matches(expected, id))
        .max_by_key(|id| (id.eq_ignore_ascii_case(expected), Some(*id) == voice))
}

/// Turn one update's `players` into placements and glides.
///
/// Free-standing and synchronous, so every rule below can be tested without an
/// app, a connection or a socket: the whole of `apply_update` around it is
/// locks and `await`s.
pub fn sources_from(
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
pub struct Placements {
    pub sources: HashMap<u32, Source>,
    pub layers: HashMap<u32, Vec<Source>>,
    pub motion: HashMap<u32, Motion>,
}

impl Placements {
    /// Everybody the game is letting through, base render or layer. A player
    /// heard only through a layer is still heard.
    pub fn audible(&self) -> std::collections::HashSet<u32> {
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
pub fn source_from(spec: &RenderSpec, base: bool, id: u32) -> Result<Option<Source>, String> {
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

/// Unit forward vector from either form the mod may send.
pub fn facing(fwd: Option<[f32; 2]>, yaw: Option<f32>) -> [f32; 2] {
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
pub fn server_matches(expected: &str, actual: &str) -> bool {
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

#[derive(Debug)]
pub enum Frame {
    Text(String),
    Ping(Vec<u8>),
    Close,
    Other,
}

/// One frame from the front of `buf`, and how many bytes it used; `None` while
/// it is still incomplete.
///
/// Pure, which is what makes [`read_frame`] cancel-safe: nothing leaves `buf`
/// until a whole frame is there, so a `select!` that drops the future mid-read
/// loses nothing.
pub fn parse_frame(buf: &[u8]) -> anyhow::Result<Option<(Frame, usize)>> {
    // RFC 6455 §5.1: a client frame that is not masked fails the connection
    let Some((frame, used)) = ws::parse_frame(buf, true, MAX_FRAME)? else {
        return Ok(None);
    };
    if !frame.fin || frame.opcode == ws::OP_CONTINUATION {
        anyhow::bail!("fragmented frames are not supported");
    }
    let frame = match frame.opcode {
        ws::OP_TEXT => Frame::Text(String::from_utf8(frame.payload)?),
        ws::OP_CLOSE => Frame::Close,
        ws::OP_PING => Frame::Ping(frame.payload),
        _ => Frame::Other,
    };
    Ok(Some((frame, used)))
}

/// Is this browser `Origin` a game runtime's, or one the user allowed?
pub fn origin_allowed(origin: &str, extra: &[String]) -> bool {
    let origin = origin.trim();
    let host_match = |host: &str| {
        // Exactly the host, or the host followed by a port — never a longer
        // name that merely starts with it
        origin == host
            || origin.strip_prefix(host).and_then(|rest| rest.strip_prefix(':')).is_some_and(
                |port| !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()),
            )
    };
    let fivem = origin.strip_prefix(FIVEM_ORIGIN_PREFIX).is_some_and(|name| {
        !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    });
    fivem
        || DEFAULT_ORIGIN_HOSTS.iter().any(|h| host_match(h))
        // What the user typed into Settings is matched exactly, for the same reason
        || extra.iter().any(|p| p == origin)
}

// ── MumbleLink ───────────────────────────────────────────────────────────

/// Bytes of the block we read: `uiVersion` (4) + `uiTick` (4) + three
/// `[f32; 3]` vectors (36). Everything after this is text about the player.
pub const LINK_HEAD: usize = 44;

/// The only version of the layout anyone writes.
pub const LINK_VERSION: u32 = 2;

/// The part of `LinkedMem` this reads.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Link {
    pub tick: u32,
    /// Metres, VoIPC's frame: x/y on the ground, z up.
    pub pos: [f32; 3],
    /// Unit forward vector in the ground plane.
    pub fwd: [f32; 2],
}

/// Parse the head of a MumbleLink block, or `None` if it is not one we trust.
///
/// Free-standing and pure, so every rule above can be checked without a game,
/// a mapping or an app.
pub fn parse_link(buf: &[u8]) -> Option<Link> {
    if buf.len() < LINK_HEAD {
        return None;
    }
    let u32_at = |i: usize| u32::from_le_bytes(buf[i..i + 4].try_into().expect("4 bytes"));
    let f32_at = |i: usize| f32::from_le_bytes(buf[i..i + 4].try_into().expect("4 bytes"));
    if u32_at(0) != LINK_VERSION {
        return None;
    }
    let tick = u32_at(4);
    // A block nobody has written yet reads as zeroes, which is a valid
    // position at the origin — the tick is what tells the two apart.
    if tick == 0 {
        return None;
    }
    let avatar_pos = [f32_at(8), f32_at(12), f32_at(16)];
    let avatar_front = [f32_at(20), f32_at(24), f32_at(28)];
    if !avatar_pos.iter().chain(avatar_front.iter()).all(|c| c.is_finite()) {
        return None;
    }
    // Mumble's frame is the one games render in: Y up, and metres. VoIPC's is
    // the one games *simulate* in, which GTA and every mod so far agree on:
    // x/y on the ground, z up. So y and z swap.
    let pos = [avatar_pos[0], avatar_pos[2], avatar_pos[1]];
    let fwd = {
        let (x, y) = (avatar_front[0], avatar_front[2]);
        let len = (x * x + y * y).sqrt();
        if len.is_finite() && len > 1e-6 {
            [x / len, y / len]
        } else {
            // Looking straight up or down: keep the default rather than
            // dividing by nothing.
            [0.0, 1.0]
        }
    };
    Some(Link { tick, pos, fwd })
}

/// Longest glide between two SDK updates: later than this is a stall, not
/// motion, so the source waits where it is instead of crawling.
pub const MAX_GLIDE: std::time::Duration = std::time::Duration::from_millis(250);
pub const MIN_GLIDE: std::time::Duration = std::time::Duration::from_millis(20);
/// Further than this in one update is a teleport (respawn, warp), not a walk.
/// A car at 50 m/s covers 12.5 m per 4 Hz tick, so the bar is deliberately high.
pub const TELEPORT_M: f32 = 50.0;

/// A placement on its way from where the game last had it to where it is now.
///
/// Updates arrive 4–10 times a second; rendered as they come, the pan and the
/// volume step at that rate. The mixer reads the interpolated pose instead, so
/// a 4 Hz mod sounds continuous. Room drags and position beacons do not use
/// this — they snap, as they always did.
#[derive(Debug, Clone, Copy)]
pub struct Motion {
    pub from: [f32; 3],
    pub to: [f32; 3],
    /// Facing at both ends; only the listener turns.
    pub fwd: Option<([f32; 2], [f32; 2])>,
    pub at: std::time::Instant,
    pub over: std::time::Duration,
}

impl Motion {
    pub fn snap(pos: [f32; 3], now: std::time::Instant) -> Self {
        Self {
            from: pos,
            to: pos,
            fwd: None,
            at: now,
            over: std::time::Duration::ZERO,
        }
    }

    /// Glide on from wherever `prev` is right now: an update that arrives
    /// mid-flight must not jump back to the previous start.
    pub fn glide(
        prev: &Motion,
        to: [f32; 3],
        over: std::time::Duration,
        now: std::time::Instant,
    ) -> Self {
        let from = prev.pos_at(now);
        let d = [to[0] - from[0], to[1] - from[1], to[2] - from[2]];
        if (d[0] * d[0] + d[1] * d[1] + d[2] * d[2]).sqrt() > TELEPORT_M {
            return Self::snap(to, now);
        }
        Self {
            from,
            to,
            fwd: None,
            at: now,
            over,
        }
    }

    fn t(&self, now: std::time::Instant) -> f32 {
        if self.over.is_zero() {
            return 1.0;
        }
        (now.saturating_duration_since(self.at).as_secs_f32() / self.over.as_secs_f32()).min(1.0)
    }

    pub fn pos_at(&self, now: std::time::Instant) -> [f32; 3] {
        let t = self.t(now);
        [
            self.from[0] + (self.to[0] - self.from[0]) * t,
            self.from[1] + (self.to[1] - self.from[1]) * t,
            self.from[2] + (self.to[2] - self.from[2]) * t,
        ]
    }

    /// Lerp and renormalise. An exact U-turn passes through zero length, which
    /// has no direction, so it faces the new way instead.
    pub fn fwd_at(&self, now: std::time::Instant) -> [f32; 2] {
        let Some((a, b)) = self.fwd else {
            return [0.0, 1.0];
        };
        let t = self.t(now);
        let v = [a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t];
        let len = (v[0] * v[0] + v[1] * v[1]).sqrt();
        if len > 1e-3 {
            [v[0] / len, v[1] / len]
        } else {
            b
        }
    }
}
