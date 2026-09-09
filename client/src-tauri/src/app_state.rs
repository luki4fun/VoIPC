use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, AtomicU8};
use std::sync::Arc;

use ring::aead::LessSafeKey;
use tokio::sync::{mpsc, RwLock};

use voipc_audio::spatial::{Effect, Gains, Listener, Source};
use voipc_crypto::media_keys::MediaKey;
use voipc_crypto::stores::SignalStores;
use voipc_protocol::types::*;

use crate::crypto::ChatArchive;

/// PTT key binding — stores the configured key/combination for push-to-talk.
/// Uses `std::sync::RwLock` (not tokio) so the global key listener thread can read it synchronously.
#[derive(Clone)]
pub struct PttBinding {
    pub ctrl: bool,
    pub alt: bool,
    pub shift: bool,
    /// JS `KeyboardEvent.code` of the main key, e.g. "Space", "KeyV", "ControlLeft".
    pub code: String,
}

impl Default for PttBinding {
    fn default() -> Self {
        Self {
            ctrl: false,
            alt: false,
            shift: false,
            code: "Space".into(),
        }
    }
}

/// Application state managed by Tauri.
pub struct AppState {
    pub connection: RwLock<Option<ActiveConnection>>,
    /// Held for the whole of `connect_to_server` so concurrent connects
    /// (reconnect loop vs. manual) run one after the other.
    pub connect_lock: tokio::sync::Mutex<()>,
    pub settings: RwLock<UserSettings>,
    pub chat: RwLock<ChatState>,
    pub signal: Arc<std::sync::Mutex<SignalState>>,
    /// PTT binding shared with the global key listener (std RwLock for sync access).
    pub ptt_binding: Arc<std::sync::RwLock<PttBinding>>,
    /// When true, for combo bindings (e.g. Ctrl+Space), PTT stays active as long as the
    /// modifier is held — releasing the trigger key alone doesn't stop PTT.
    /// When false, releasing the trigger key immediately stops PTT.
    pub ptt_hold_mode: Arc<AtomicBool>,
    /// Optional global hotkeys: toggle mute / toggle deafen (None = unbound).
    pub mute_binding: Arc<std::sync::RwLock<Option<PttBinding>>>,
    pub deafen_binding: Arc<std::sync::RwLock<Option<PttBinding>>>,
    /// Persistent user configuration (std Mutex — config saves are fast sync ops).
    pub config: std::sync::Mutex<crate::config::AppConfig>,
    /// Set while the settings-panel mic test runs; cleared to stop it.
    pub mic_test_active: Arc<AtomicBool>,
    /// Capture-side mic gain as f32 bits (1.0 = unity), applied in the
    /// audio callback of both the voice capture and the mic test.
    pub input_gain: Arc<AtomicU32>,
    /// The game currently driving positions over the SDK socket, by name.
    /// `get_sdk_status` reads it, so Settings opened after the game connected
    /// still shows it (the `sdk-status` event alone would have been missed).
    pub sdk_game: Arc<std::sync::Mutex<Option<String>>>,
    /// Fan-out to every open SDK socket. It lives here rather than on the
    /// connection because the listener outlives connections: a socket
    /// subscribes once and keeps receiving across a reconnect.
    pub sdk_events: tokio::sync::broadcast::Sender<SdkEvent>,
    /// Why the SDK listener could not bind, for Settings; None while it listens.
    pub sdk_listen_error: Arc<std::sync::Mutex<Option<String>>>,
}

/// What the game SDK pushes to a connected mod, fanned out from wherever it
/// happens: the datagram receiver, the capture task, the mute toggles.
#[derive(Debug, Clone)]
pub enum SdkEvent {
    Talk { user_id: UserId, speaking: bool },
    Muted { user_id: UserId, muted: bool },
    Deafened { user_id: UserId, deafened: bool },
    /// The server refused something (a channel join, most importantly), so a
    /// mod waiting for its `hello` to complete learns why.
    ChannelError(String),
}

impl AppState {
    pub fn new() -> Self {
        Self {
            connection: RwLock::new(None),
            connect_lock: tokio::sync::Mutex::new(()),
            settings: RwLock::new(UserSettings::default()),
            chat: RwLock::new(ChatState::default()),
            signal: Arc::new(std::sync::Mutex::new(SignalState::default())),
            ptt_binding: Arc::new(std::sync::RwLock::new(PttBinding::default())),
            ptt_hold_mode: Arc::new(AtomicBool::new(true)),
            mute_binding: Arc::new(std::sync::RwLock::new(None)),
            deafen_binding: Arc::new(std::sync::RwLock::new(None)),
            config: std::sync::Mutex::new(crate::config::AppConfig::default()),
            mic_test_active: Arc::new(AtomicBool::new(false)),
            input_gain: Arc::new(AtomicU32::new(1.0f32.to_bits())),
            sdk_game: Arc::new(std::sync::Mutex::new(None)),
            // Enough for a burst of talk edges; a lagging socket skips ahead
            sdk_events: tokio::sync::broadcast::channel(64).0,
            sdk_listen_error: Arc::new(std::sync::Mutex::new(None)),
        }
    }

    /// Publish to the SDK sockets. Nobody listening is the normal case.
    pub fn sdk_event(&self, event: SdkEvent) {
        let _ = self.sdk_events.send(event);
    }
}

/// A message waiting for encryption to become available.
pub struct PendingMessage {
    /// Channel message (channel_id) or direct message (target_user_id).
    pub target: PendingTarget,
    /// The plaintext message content.
    pub content: String,
    /// When the message was queued (for timeout/cleanup).
    pub queued_at: std::time::Instant,
}

/// Target of a pending (queued) message.
pub enum PendingTarget {
    /// Channel message — waiting for sender key distribution.
    Channel { channel_id: u32 },
    /// Direct message — waiting for pairwise Signal session.
    Direct { target_user_id: u32 },
}

/// E2E encryption state using Signal Protocol.
pub struct SignalState {
    /// Signal Protocol stores (identity, pre-keys, sessions, sender keys).
    pub stores: Option<SignalStores>,
    /// Whether Signal state has been initialized.
    pub initialized: bool,
    /// Our own user_id (set after authentication).
    pub own_user_id: Option<u32>,
    /// Users we've requested prekey bundles for but haven't established sessions with yet.
    pub pending_sessions: HashSet<u32>,
    /// Users we have established pairwise Signal sessions with.
    pub established_sessions: HashSet<u32>,
    /// channel_id → set of user_ids we've sent our sender key to.
    pub sender_key_distributed: HashMap<u32, HashSet<u32>>,
    /// channel_id → set of user_ids whose sender keys we've received.
    pub sender_key_received: HashMap<u32, HashSet<u32>>,
    /// Messages queued while waiting for encryption to be established.
    pub pending_messages: Vec<PendingMessage>,
    /// Channel we entered with members already in it: ask the first member
    /// whose sender key arrives for recent chat (once per entry, 0 = none).
    pub history_wanted_channel: u32,
}

impl Default for SignalState {
    fn default() -> Self {
        Self {
            stores: None,
            initialized: false,
            own_user_id: None,
            pending_sessions: HashSet::new(),
            established_sessions: HashSet::new(),
            sender_key_distributed: HashMap::new(),
            sender_key_received: HashMap::new(),
            pending_messages: Vec::new(),
            history_wanted_channel: 0,
        }
    }
}

/// Encrypted chat history state.
pub struct ChatState {
    /// In-memory chat data (authoritative during session).
    pub archive: ChatArchive,
    /// Derived AES-256-GCM key (set after password entry).
    pub sealing_key: Option<LessSafeKey>,
    /// PBKDF2 salt (loaded from file or generated fresh).
    pub salt: [u8; 32],
    /// Path to the encrypted history file.
    pub file_path: PathBuf,
    /// Whether there are unsaved changes.
    pub dirty: bool,
}

impl Default for ChatState {
    fn default() -> Self {
        Self {
            archive: ChatArchive::default(),
            sealing_key: None,
            salt: [0u8; 32],
            file_path: PathBuf::new(),
            dirty: false,
        }
    }
}

/// State of an active server connection.
#[allow(dead_code)]
pub struct ActiveConnection {
    pub user_id: UserId,
    pub username: String,
    /// The `host:port` we connected to, as the user typed it. The game SDK
    /// checks a mod's expectation against it before letting the game drive
    /// the mix.
    pub server_address: String,
    pub session_id: SessionId,
    pub is_muted: Arc<AtomicBool>,
    pub is_deafened: Arc<AtomicBool>,
    /// Sender for control messages (framed, onto the control stream).
    pub tcp_tx: mpsc::Sender<Vec<u8>>,
    /// Sender for voice packets (QUIC datagrams).
    pub voice_tx: mpsc::Sender<Vec<u8>>,
    /// Sender for video fragments (one QUIC stream per frame).
    pub video_tx: mpsc::Sender<Vec<u8>>,
    /// Sender for screen share audio packets (QUIC datagrams).
    pub screen_audio_tx: mpsc::Sender<Vec<u8>>,
    /// QUIC endpoint + connection; closed explicitly on disconnect.
    pub quic: crate::transport::Quic,
    /// Join handles for cleanup on disconnect.
    pub tasks: Vec<tokio::task::JoinHandle<()>>,
    /// Flag to signal the capture+encode loop to stop.
    pub transmitting: Arc<AtomicBool>,
    /// Handle to the capture+encode task (only active while PTT held).
    pub capture_task: Option<tokio::task::JoinHandle<()>>,
    /// Voice packet sequence counter — persists across PTT presses so the
    /// AES-GCM nonce (session_id ‖ sequence) is never reused under the
    /// channel key and receivers never see a backwards jump.
    pub voice_sequence: Arc<AtomicU32>,
    /// Master output volume as f32 bits (applied by the voice mixer task).
    pub master_volume: Arc<AtomicU32>,
    /// Voice frames played / concealed (jitter-buffer loss) — for the quality indicator.
    pub voice_frames_played: Arc<AtomicU32>,
    pub voice_frames_lost: Arc<AtomicU32>,
    /// Output device override read by the mixer when rebuilding playback.
    pub output_device_live: Arc<std::sync::Mutex<Option<String>>>,
    /// Set to make the mixer (re)build the playback stream — by the cpal
    /// error callback on device failure, or after an output device change.
    pub playback_restart: Arc<AtomicBool>,
    // ── Screen share state ──
    /// Whether this client is currently screen sharing.
    pub is_screen_sharing: bool,
    /// Codec of our own share, taken from the config when it starts. Fixed for
    /// the share's life, so a source switch re-uses it and the viewers who were
    /// told this codec on watch stay correct.
    pub screen_share_codec: VideoCodec,
    /// Handle to the screen capture task (when sharing).
    pub screen_capture_task: Option<tokio::task::JoinHandle<()>>,
    /// Flag to signal the capture task to stop.
    pub screen_share_active: Arc<AtomicBool>,
    /// Flag set when a viewer requests a keyframe.
    pub keyframe_requested: Arc<AtomicBool>,
    /// Epoch ms of the last frame-loss signal for our screen share (a
    /// viewer's report, our own path stats or local send backpressure); the
    /// encoder steps its bitrate/fps down while these keep coming. 0 = none.
    pub share_loss_ms: Arc<AtomicU64>,
    /// Recent viewer loss reports; only a majority of viewers steps the share
    /// down, so one flaky (or hostile) viewer cannot degrade it for everyone.
    pub share_loss_tally: Arc<std::sync::Mutex<LossTally>>,
    /// The user_id of the screenshare we're currently watching (if any).
    pub watching_user_id: Option<UserId>,
    /// Shared atomic version of watching_user_id for cross-task access (0 = not watching).
    pub watching_user_id_shared: Arc<AtomicU32>,
    /// Active capture session (keeps screen capture alive while sharing).
    pub capture_session: Option<crate::screenshare::CaptureSession>,
    /// Whether screen share audio is enabled (toggle for the sharer).
    pub screen_audio_enabled: Arc<AtomicBool>,
    /// Counter of screen audio packets sent (for activity indicator).
    pub screen_audio_send_count: Arc<AtomicU32>,
    /// Counter of screen audio packets received (for activity indicator).
    pub screen_audio_recv_count: Arc<AtomicU32>,
    // ── Screen share video stats ──
    /// Total video frames successfully encoded and sent (sender side).
    pub screen_video_frames_sent: Arc<AtomicU32>,
    /// Total bytes sent as video fragments (sender side, for bitrate calc).
    pub screen_video_bytes_sent: Arc<AtomicU64>,
    /// Total video frames assembled from fragments (receiver side).
    pub screen_video_frames_received: Arc<AtomicU32>,
    /// Video frames dropped because decode channel was full (receiver side).
    pub screen_video_frames_dropped: Arc<AtomicU32>,
    /// Total bytes received as video fragments (receiver side, for bitrate calc).
    pub screen_video_bytes_received: Arc<AtomicU64>,
    /// Resolution of the screen share: packed as (width << 16) | height (receiver side).
    pub screen_video_resolution: Arc<AtomicU32>,
    /// Current channel's media encryption key (shared with capture/receive tasks).
    /// Updated when the user joins a channel or receives a new media key.
    pub current_media_key: Arc<std::sync::Mutex<Option<MediaKey>>>,
    /// Current channel ID — tracked for AAD construction in media encryption.
    pub current_channel_id: Arc<AtomicU32>,
    // ── Voice activation state ──
    /// Voice mode: 0 = PTT, 1 = VAD, 2 = Always On. Shared with capture task.
    pub voice_mode: Arc<AtomicU8>,
    /// VAD threshold in dB, stored as i32 (e.g. -40). Shared with capture task.
    pub vad_threshold_db: Arc<AtomicI32>,
    /// Current audio input level in dB × 100 (fixed-point). Updated by capture task.
    pub current_audio_level: Arc<AtomicI32>,
    // ── Noise suppression ──
    /// Whether noise suppression is enabled. Shared with capture task.
    pub noise_suppression: Arc<AtomicBool>,
    // ── Per-user volume ──
    /// Per-user volume multiplier (0.0 = muted, 1.0 = default, 2.0 = max).
    pub user_volumes: Arc<std::sync::Mutex<HashMap<u32, f32>>>,
    // ── Proximity chat ──
    /// Where everyone stands, and how the mixer should render them.
    pub spatial: Arc<std::sync::Mutex<SpatialState>>,
    /// The channel list as last received, so the backend can resolve a
    /// channel's proximity mode (and, for the game SDK, a channel by name)
    /// without asking the UI.
    pub channels: Arc<std::sync::Mutex<Vec<ChannelInfo>>>,
    /// Sequence counter for position beacons. Their own nonce domain, so it
    /// must never share the voice counter.
    pub position_sequence: Arc<AtomicU32>,
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

/// Everything the mixer needs to render voices positionally.
///
/// Positions are local state: the room UI and the game SDK both write here,
/// and only the room's "sync my position" puts anything on the wire.
pub struct SpatialState {
    /// The current channel's mode. Off disables everything below.
    pub mode: ProximityMode,
    /// User setting: spatial audio may be switched off per client.
    pub enabled: bool,
    /// User setting: does a screen share's audio follow its sharer's position
    /// or stay centred?
    pub screen_audio_spatial: bool,
    /// A game is driving positions. Members it does not list are silent
    /// (distance culling), and the room view stops accepting drags.
    pub sdk_active: bool,
    /// The channel the game said hello for. Leaving it must disarm the SDK:
    /// its player ids belong to that room, and culling by them everywhere else
    /// would silence the whole channel we moved to.
    pub sdk_channel: Option<ChannelId>,
    /// Broadcasting our own position, and accepting the other members'.
    pub sync: bool,
    /// Our position moved since the last beacon. The beacon task sends at most
    /// ten times a second, so a drag cannot outrun the server's budget.
    pub dirty: bool,
    /// Our own pose.
    pub listener: Listener,
    /// Where each other user is, keyed by user_id (== session_id, the id the
    /// media packets carry), like `user_volumes`.
    pub sources: HashMap<u32, Source>,
    /// The settings panel's spatial test, while it runs.
    pub test: Option<SpatialTest>,
    /// Glides for the SDK's placements, keyed like `sources`. A source without
    /// one renders where `sources` says it is.
    pub motion: HashMap<u32, Motion>,
    pub listener_motion: Option<Motion>,
    /// When the last SDK update arrived, for the observed update rate.
    pub last_update: Option<std::time::Instant>,
}

/// A synthetic voice orbiting the listener, mixed by `voice_mixer_task` like
/// any other source, so what the user hears is what proximity chat does.
///
/// It carries its own mode (the button they pressed), runs in any channel, and
/// is always rendered relative to the default listener — the test is about the
/// headphones, not about where they dragged themselves in the room.
impl SpatialTest {
    /// What the mixer applies to this frame: the stereo gains it ramps to, and
    /// the low-pass coefficient. Always relative to the default listener, and
    /// flat when the user has spatial audio switched off, so toggling it while
    /// the test runs is the A/B comparison.
    pub fn frame_target(
        &self,
        spatial_enabled: bool,
        master: f32,
        elapsed_secs: f32,
    ) -> ((f32, f32), f32) {
        let source = voipc_audio::spatial::test_source(self.mode, elapsed_secs);
        let g = if spatial_enabled {
            voipc_audio::spatial::gains(self.mode, &Listener::default(), Some(&source))
        } else {
            voipc_audio::spatial::FLAT
        };
        // Stopping: one frame ramped to silence, then the test is dropped
        let target = if self.stopping {
            (0.0, 0.0)
        } else {
            (g.l * master, g.r * master)
        };
        (target, g.lp_a)
    }
}

pub struct SpatialTest {
    pub mode: ProximityMode,
    pub started: std::time::Instant,
    /// Samples rendered so far: the generator's phase. Survives a mode switch,
    /// so switching 2D↔3D does not click.
    pub sample: u64,
    /// Stopping: the mixer ramps this source to silence over one frame, then
    /// drops it. A hard cut would click.
    pub stopping: bool,
    pub mix: voipc_audio::mixer::SourceMixState,
}

impl Default for SpatialState {
    fn default() -> Self {
        Self {
            mode: ProximityMode::Off,
            enabled: true,
            screen_audio_spatial: true,
            sdk_active: false,
            sdk_channel: None,
            sync: false,
            dirty: false,
            listener: Listener::default(),
            sources: HashMap::new(),
            test: None,
            motion: HashMap::new(),
            listener_motion: None,
            last_update: None,
        }
    }
}

impl SpatialState {
    /// Whether any spatial rendering happens at all right now.
    pub fn active(&self) -> bool {
        self.mode != ProximityMode::Off && self.enabled
    }

    /// Gains for one mixer source key (voice or screen audio), as of `now`.
    ///
    /// The single place a glide is read: the SDK's targets stay in `sources`
    /// and `listener`, so every other writer (room drags, position beacons)
    /// keeps snapping the way it always did.
    pub fn gains_for(&self, key: u32, screen_audio: bool, now: std::time::Instant) -> Gains {
        if !self.active() || (screen_audio && !self.screen_audio_spatial) {
            return voipc_audio::spatial::FLAT;
        }
        match self.sources.get(&key) {
            Some(src) => {
                let listener = match &self.listener_motion {
                    Some(m) => Listener {
                        pos: m.pos_at(now),
                        fwd: m.fwd_at(now),
                    },
                    None => self.listener,
                };
                let placed = match self.motion.get(&key) {
                    // A direct source has no position to interpolate
                    Some(m) if !src.direct => Source {
                        pos: m.pos_at(now),
                        ..*src
                    },
                    _ => *src,
                };
                voipc_audio::spatial::gains(self.mode, &listener, Some(&placed))
            }
            // A game lists everyone who should be audible; anyone else is out
            // of range. Without a game, an unplaced user just sounds flat.
            None if self.sdk_active => Gains { l: 0.0, r: 0.0, lp_a: 1.0 },
            None => voipc_audio::spatial::FLAT,
        }
    }

    /// The effect chain a source is rendered through. Not gated on `active()`:
    /// a radio is a radio whether or not the channel is positional.
    pub fn effect_for(&self, key: u32) -> Effect {
        self.sources.get(&key).map_or(Effect::None, |s| s.fx)
    }

    /// Forget every placement (channel change, room reset, game disconnect).
    /// The settings panel's test is not a placement and keeps running.
    pub fn clear_positions(&mut self) {
        self.sources.clear();
        self.sdk_channel = None;
        self.listener = Listener::default();
        self.motion.clear();
        self.listener_motion = None;
        self.last_update = None;
    }
}

/// Who reported frame loss on our screen share, and how many viewers there are
/// to compare that against. See `network::majority_reached`.
#[derive(Default)]
pub struct LossTally {
    pub viewer_count: u32,
    /// Viewer user id → epoch ms of its last report of dropped frames.
    pub reports: HashMap<UserId, u64>,
}

/// Voice activation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VoiceMode {
    Ptt = 0,
    Vad = 1,
    AlwaysOn = 2,
}

impl VoiceMode {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Vad,
            2 => Self::AlwaysOn,
            _ => Self::Ptt,
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "vad" => Self::Vad,
            "always_on" => Self::AlwaysOn,
            _ => Self::Ptt,
        }
    }
}

/// Config string → codec for our own screen share. Anything unknown is H.264,
/// the codec every viewer can decode. Sharing is desktop-only.
#[cfg(not(target_os = "android"))]
pub fn share_codec_from_str(s: &str) -> VideoCodec {
    match s {
        "h265" => VideoCodec::H265,
        _ => VideoCodec::H264,
    }
}

/// User settings (in-memory, initialized from config on startup).
#[allow(dead_code)]
pub struct UserSettings {
    pub input_device: Option<String>,
    pub output_device: Option<String>,
    pub volume: f32,
    pub ptt_key: String,
    pub voice_mode: String,
    pub vad_threshold_db: f32,
    pub noise_suppression: bool,
    pub muted: bool,
    pub deafened: bool,
    /// Render proximity channels positionally (see `AppConfig::spatial_audio`).
    pub spatial_audio: bool,
    /// Place a screen share's audio at its sharer's position.
    pub screen_audio_spatial: bool,
}

impl Default for UserSettings {
    fn default() -> Self {
        Self {
            input_device: None,
            output_device: None,
            volume: 1.0,
            ptt_key: "Space".into(),
            voice_mode: "ptt".into(),
            vad_threshold_db: -40.0,
            noise_suppression: true,
            muted: false,
            deafened: false,
            spatial_audio: true,
            screen_audio_spatial: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};
    use voipc_audio::spatial::{FLAT, MAX_MUFFLE, Source};

    fn test_state(mode: ProximityMode, stopping: bool) -> SpatialTest {
        SpatialTest {
            mode,
            started: std::time::Instant::now(),
            sample: 0,
            stopping,
            mix: Default::default(),
        }
    }

    #[test]
    fn the_spatial_test_pans_and_follows_the_master_volume() {
        let test = test_state(ProximityMode::TwoD, false);
        // A quarter into the orbit the voice is on the right
        let ((l, r), lp_a) = test.frame_target(true, 1.0, 2.0);
        assert!(r > l * 5.0, "l = {l}, r = {r}");
        assert_eq!(lp_a, 1.0, "the test is never muffled");
        // Master volume scales it like any other source
        let ((half_l, half_r), _) = test.frame_target(true, 0.5, 2.0);
        assert!((half_l - l * 0.5).abs() < 1e-6 && (half_r - r * 0.5).abs() < 1e-6);
    }

    #[test]
    fn switching_spatial_audio_off_centres_the_test() {
        let test = test_state(ProximityMode::ThreeD, false);
        let ((l, r), _) = test.frame_target(false, 1.0, 2.0);
        assert_eq!((l, r), (FLAT.l, FLAT.r));
    }

    #[test]
    fn stopping_ramps_the_test_to_silence() {
        let test = test_state(ProximityMode::TwoD, true);
        assert_eq!(test.frame_target(true, 1.0, 2.0).0, (0.0, 0.0));
    }

    #[test]
    fn an_unplaced_user_is_flat_unless_a_game_is_culling() {
        let mut state = SpatialState {
            mode: ProximityMode::TwoD,
            ..Default::default()
        };
        assert_eq!(state.gains_for(7, false, Instant::now()), FLAT);
        // A game lists everyone audible, so anyone missing is out of range
        state.sdk_active = true;
        assert_eq!(state.gains_for(7, false, Instant::now()).l, 0.0);
    }

    #[test]
    fn screen_audio_follows_the_sharer_only_when_the_viewer_wants_it() {
        let mut state = SpatialState {
            mode: ProximityMode::TwoD,
            ..Default::default()
        };
        state.sources.insert(
            7,
            Source {
                pos: [5.0, 0.0, 0.0],
                ..Source::default()
            },
        );
        let voice = state.gains_for(7, false, Instant::now());
        assert!(voice.r > voice.l * 5.0);
        assert_eq!(state.gains_for(7, true, Instant::now()), voice, "the share follows its sharer");
        state.screen_audio_spatial = false;
        assert_eq!(state.gains_for(7, true, Instant::now()), FLAT, "…until the viewer centres it");
        assert_eq!(state.gains_for(7, false, Instant::now()), voice, "which leaves the voice alone");
    }

    // ── Glides between SDK updates ──────────────────────────────────────

    #[test]
    fn a_glide_is_linear_and_stops_at_the_target() {
        let t0 = Instant::now();
        let m = Motion {
            from: [0.0; 3],
            to: [10.0, 0.0, 0.0],
            fwd: None,
            at: t0,
            over: Duration::from_millis(100),
        };
        assert_eq!(m.pos_at(t0)[0], 0.0);
        assert!((m.pos_at(t0 + Duration::from_millis(50))[0] - 5.0).abs() < 1e-3);
        assert_eq!(m.pos_at(t0 + Duration::from_millis(100))[0], 10.0);
        // A late update does not overshoot: the source waits at the target
        assert_eq!(m.pos_at(t0 + Duration::from_secs(1))[0], 10.0);
    }

    #[test]
    fn a_new_update_glides_on_from_mid_flight() {
        let t0 = Instant::now();
        let first = Motion {
            from: [0.0; 3],
            to: [10.0, 0.0, 0.0],
            fwd: None,
            at: t0,
            over: Duration::from_millis(100),
        };
        let halfway = t0 + Duration::from_millis(50);
        let second = Motion::glide(&first, [0.0; 3], Duration::from_millis(100), halfway);
        assert!((second.from[0] - 5.0).abs() < 1e-3, "jumped back to {}", second.from[0]);
    }

    #[test]
    fn a_teleport_snaps_instead_of_gliding() {
        let t0 = Instant::now();
        let here = Motion::snap([0.0; 3], t0);
        // A respawn across the map: sliding through it would sweep the pan
        let jump = Motion::glide(&here, [0.0, TELEPORT_M + 10.0, 0.0], MAX_GLIDE, t0);
        assert_eq!(jump.from, jump.to);
        assert!(jump.over.is_zero());
        // A normal step still glides
        let step = Motion::glide(&here, [0.0, 2.0, 0.0], MAX_GLIDE, t0);
        assert_ne!(step.from, step.to);
    }

    #[test]
    fn facing_interpolates_and_survives_a_u_turn() {
        let t0 = Instant::now();
        // A snap has no duration, so it is already at its target
        let snapped = Motion {
            fwd: Some(([0.0, 1.0], [1.0, 0.0])),
            ..Motion::snap([0.0; 3], t0)
        };
        assert_eq!(snapped.fwd_at(t0), [1.0, 0.0]);
        // Without a facing at all, straight ahead
        assert_eq!(Motion::snap([0.0; 3], t0).fwd_at(t0), [0.0, 1.0]);

        let quarter = Motion {
            at: t0,
            over: Duration::from_millis(100),
            fwd: Some(([0.0, 1.0], [1.0, 0.0])),
            ..Motion::snap([0.0; 3], t0)
        };
        let mid = quarter.fwd_at(t0 + Duration::from_millis(50));
        assert!((mid[0].hypot(mid[1]) - 1.0).abs() < 1e-3, "not a unit vector: {mid:?}");
        assert!((mid[0] - mid[1]).abs() < 1e-3, "not 45 degrees: {mid:?}");

        // An exact about-turn passes through zero length, which has no
        // direction: face the new way rather than something arbitrary
        let about = Motion {
            at: t0,
            over: Duration::from_millis(100),
            fwd: Some(([0.0, 1.0], [0.0, -1.0])),
            ..Motion::snap([0.0; 3], t0)
        };
        assert_eq!(about.fwd_at(t0 + Duration::from_millis(50)), [0.0, -1.0]);
    }

    #[test]
    fn the_mixer_reads_the_glide_and_direct_sources_ignore_it() {
        let t0 = Instant::now();
        let over = Duration::from_millis(100);
        let mut state = SpatialState {
            mode: ProximityMode::TwoD,
            ..Default::default()
        };
        state.sources.insert(
            7,
            Source {
                pos: [5.0, 0.0, 0.0],
                ..Source::default()
            },
        );
        state.motion.insert(
            7,
            Motion {
                from: [-5.0, 0.0, 0.0],
                to: [5.0, 0.0, 0.0],
                fwd: None,
                at: t0,
                over,
            },
        );

        // At the start of the glide the voice is still on the left
        let start = state.gains_for(7, false, t0);
        assert!(start.l > start.r * 5.0, "{start:?}");
        // At the end it has arrived on the right
        let end = state.gains_for(7, false, t0 + over);
        assert!(end.r > end.l * 5.0, "{end:?}");

        // A radio has no position to glide along
        state.sources.get_mut(&7).unwrap().direct = true;
        let direct = state.gains_for(7, false, t0);
        assert!((direct.l - direct.r).abs() < 1e-6, "{direct:?}");
    }

    #[test]
    fn clearing_placements_drops_the_glides() {
        let mut state = SpatialState::default();
        state.motion.insert(7, Motion::snap([1.0, 2.0, 3.0], Instant::now()));
        state.listener_motion = Some(Motion::snap([0.0; 3], Instant::now()));
        state.last_update = Some(Instant::now());
        state.clear_positions();
        assert!(state.motion.is_empty());
        assert!(state.listener_motion.is_none());
        assert!(state.last_update.is_none());
    }

    #[test]
    fn the_effect_follows_the_source() {
        let mut state = SpatialState::default();
        assert_eq!(state.effect_for(7), Effect::None);
        state.sources.insert(
            7,
            Source {
                fx: Effect::Radio,
                direct: true,
                ..Source::default()
            },
        );
        // Not gated on the channel being positional: a radio is a radio
        assert_eq!(state.effect_for(7), Effect::Radio);
        assert_eq!(state.effect_for(9), Effect::None);
    }

    #[test]
    fn clearing_placements_leaves_the_test_running() {
        let mut state = SpatialState {
            mode: ProximityMode::TwoD,
            test: Some(test_state(ProximityMode::TwoD, false)),
            ..Default::default()
        };
        state.sources.insert(
            7,
            Source {
                muffle: MAX_MUFFLE,
                ..Source::default()
            },
        );
        state.clear_positions();
        assert!(state.sources.is_empty());
        assert!(state.test.is_some(), "the settings-panel test is not a placement");
    }
}
