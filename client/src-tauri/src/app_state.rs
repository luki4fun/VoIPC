use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, AtomicU8};
use std::sync::Arc;

use ring::aead::LessSafeKey;
use tokio::sync::{mpsc, RwLock};

use voipc_crypto::media_keys::MediaKey;
use voipc_crypto::stores::SignalStores;
use voipc_protocol::types::*;

use crate::crypto::ChatArchive;

/// Application state managed by Tauri.
pub struct AppState {
    pub connection: RwLock<Option<ActiveConnection>>,
    pub settings: RwLock<UserSettings>,
    pub chat: RwLock<ChatState>,
    pub signal: Arc<std::sync::Mutex<SignalState>>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            connection: RwLock::new(None),
            settings: RwLock::new(UserSettings::default()),
            chat: RwLock::new(ChatState::default()),
            signal: Arc::new(std::sync::Mutex::new(SignalState::default())),
        }
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
    pub session_id: SessionId,
    pub is_muted: Arc<AtomicBool>,
    pub is_deafened: Arc<AtomicBool>,
    /// Sender for TCP control messages.
    pub tcp_tx: mpsc::Sender<Vec<u8>>,
    /// Sender for UDP voice packets.
    pub voice_tx: mpsc::Sender<Vec<u8>>,
    /// Sender for UDP video packets (screen share).
    pub video_tx: mpsc::Sender<Vec<u8>>,
    /// Sender for UDP screen share audio packets.
    pub screen_audio_tx: mpsc::Sender<Vec<u8>>,
    /// Join handles for cleanup on disconnect.
    pub tasks: Vec<tokio::task::JoinHandle<()>>,
    /// Flag to signal the capture+encode loop to stop.
    pub transmitting: Arc<AtomicBool>,
    /// Handle to the capture+encode task (only active while PTT held).
    pub capture_task: Option<tokio::task::JoinHandle<()>>,
    /// Playback ring buffer producer — UDP receiver writes decoded PCM here.
    pub playback_producer: Arc<std::sync::Mutex<ringbuf::HeapProd<f32>>>,
    /// Playback stream handle — held to keep the cpal output alive.
    #[allow(dead_code)]
    pub playback_stream: Option<voipc_audio::playback::PlaybackStream>,
    /// Token for authenticating UDP voice packets.
    pub udp_token: u64,
    // ── Screen share state ──
    /// Whether this client is currently screen sharing.
    pub is_screen_sharing: bool,
    /// Handle to the screen capture task (when sharing).
    pub screen_capture_task: Option<tokio::task::JoinHandle<()>>,
    /// Flag to signal the capture task to stop.
    pub screen_share_active: Arc<AtomicBool>,
    /// Flag set when a viewer requests a keyframe.
    pub keyframe_requested: Arc<AtomicBool>,
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

/// Persisted user settings.
#[allow(dead_code)]
pub struct UserSettings {
    pub input_device: Option<String>,
    pub output_device: Option<String>,
    pub volume: f32,
    pub ptt_key: String,
}

impl Default for UserSettings {
    fn default() -> Self {
        Self {
            input_device: None,
            output_device: None,
            volume: 1.0,
            ptt_key: "Space".into(),
        }
    }
}
