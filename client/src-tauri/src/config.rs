use std::path::PathBuf;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

/// Overridden data directory (set via init_data_dir on Android).
static DATA_DIR_OVERRIDE: OnceLock<PathBuf> = OnceLock::new();

/// Set the data directory explicitly. Called from lib.rs setup on Android
/// with Tauri's app_data_dir(). Must be called before any other config function.
#[allow(dead_code)]
pub fn init_data_dir(dir: PathBuf) {
    let _ = DATA_DIR_OVERRIDE.set(dir);
}

/// Settings for a single notification sound event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SoundEntry {
    pub enabled: bool,
    /// Absolute path to audio file (.mp3, .wav, or .ogg). None = no sound.
    pub path: Option<String>,
}

impl Default for SoundEntry {
    fn default() -> Self {
        Self {
            enabled: true,
            path: None,
        }
    }
}

/// All notification sound settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SoundSettings {
    pub channel_switch: SoundEntry,
    pub user_joined: SoundEntry,
    pub user_left: SoundEntry,
    pub disconnected: SoundEntry,
    pub direct_message: SoundEntry,
    pub channel_message: SoundEntry,
    pub poke: SoundEntry,
}

impl Default for SoundSettings {
    fn default() -> Self {
        Self {
            channel_switch: SoundEntry::default(),
            user_joined: SoundEntry::default(),
            user_left: SoundEntry::default(),
            disconnected: SoundEntry::default(),
            direct_message: SoundEntry::default(),
            channel_message: SoundEntry::default(),
            poke: SoundEntry::default(),
        }
    }
}

/// A saved server entry shown in the connect dialog.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedServer {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    #[serde(default)]
    pub accept_self_signed: bool,
}

/// Persistent user configuration, saved as `settings.json` in the VoIPC data directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    // Audio
    pub input_device: Option<String>,
    pub output_device: Option<String>,
    pub volume: f32,
    /// Capture-side microphone gain (1.0 = unity, clamped 0.0–4.0).
    pub input_gain: f32,
    pub noise_suppression: bool,

    // Voice mode
    pub voice_mode: String,
    pub vad_threshold_db: f32,

    // PTT
    pub ptt_key: String,
    pub ptt_hold_mode: bool,
    /// Optional global hotkeys (binding strings like "Ctrl+M"; None = unbound).
    pub mute_key: Option<String>,
    pub deafen_key: Option<String>,

    // Mute/Deafen (restored on next connect)
    pub muted: bool,
    pub deafened: bool,

    // Optional connection info
    pub remember_connection: bool,
    pub last_host: Option<String>,
    pub last_port: Option<u16>,
    pub last_username: Option<String>,
    pub last_accept_self_signed: Option<bool>,
    /// Saved servers for the connect dialog (keyed by host:port).
    pub saved_servers: Vec<SavedServer>,

    // Screen share
    /// Codec our own screen share is encoded with: "h264" (default — every
    /// viewer decodes it, browsers included) or "h265" (smaller, but no browser
    /// on Linux and no Firefox anywhere can decode it).
    pub screen_share_codec: String,

    // Proximity chat
    /// Render voices positionally in proximity channels. Off gives everyone
    /// the plain centred mix (mono headsets, hearing in one ear, preference).
    pub spatial_audio: bool,
    /// Whether a screen share's audio is placed at its sharer's position or
    /// stays centred. Each viewer decides for themselves.
    pub screen_audio_spatial: bool,
    /// Our own microphone's lane: the effect it is sent through, plus three
    /// 0–10 levels. Everybody hears all of it — it is rendered into the voice
    /// before Opus, so no listener can turn it off.
    ///
    /// The lanes we listen through carry the same four controls, but those are
    /// per connection and are not saved: a user id is a session id.
    pub mic_effect: String,
    pub mic_muffle: u8,
    pub mic_reverb: u8,
    pub mic_water: u8,
    /// Which version of the first-run audio setup this user has been through;
    /// 0 (the default) means never.
    ///
    /// A version rather than a bool so a later release that adds a step can
    /// ask again. It cannot be derived from the other settings: `voice_mode`
    /// defaults to `"ptt"` whether or not anybody chose it, and a null
    /// `input_device` legitimately means "whatever the system picks".
    #[serde(default)]
    pub audio_setup_version: u32,
    /// Accept connections from a game on the local SDK port.
    pub sdk_enabled: bool,
    /// Port the game SDK listens on (loopback only).
    pub sdk_port: u16,
    /// Extra browser origins allowed to connect to the SDK, on top of the
    /// built-in game-runtime patterns. `"null"` covers a `file://` page.
    pub sdk_allowed_origins: Vec<String>,
    /// Follow MumbleLink: a block of shared memory some games write their own
    /// player's position into. Off by default — any local process can write
    /// one, so it is an input the user opts into like the SDK socket.
    ///
    /// Reading it only places people locally. Peers see the position only if
    /// `sdk_beacon_allowed` is on as well, exactly as for a game in beacon
    /// mode, because it is the same broadcast.
    #[serde(default)]
    pub mumblelink_enabled: bool,
    /// May a game broadcast the user's position to the channel?
    ///
    /// Off by default, and the *only* way `sync` is ever turned on by anything
    /// but the user's own switch. Positions a game feeds in stay on the
    /// machine unless this is on; with it on, one's own position goes out
    /// encrypted like voice, and every member of the channel receives it.
    #[serde(default)]
    pub sdk_beacon_allowed: bool,
    /// May a game press the user's push-to-talk, so the in-game radio key is
    /// the only key they have to hold? Off by default. It can never override
    /// mute, and it is released the moment the game stops driving.
    #[serde(default)]
    pub sdk_transmit_allowed: bool,

    // QoL
    pub sounds: SoundSettings,
    pub auto_connect: bool,
    /// Answer newcomers' requests for recent channel chat (E2E, pairwise).
    pub share_channel_history: bool,

    // Appearance
    /// Everything the UI remembers about how it looks: which layout, which
    /// palette and any per-colour overrides, panel widths, message density,
    /// zoom.
    ///
    /// Deliberately opaque to Rust and round-tripped verbatim. Nothing here has
    /// a second owner — no Rust code reads a byte of it — so unlike the audio
    /// and hotkey settings it is written as one blob rather than through a
    /// command per field. That also means a new palette colour is a TypeScript
    /// change and nothing else, and a client that meets a file written by a
    /// newer one keeps the keys it does not understand instead of dropping
    /// them on the next save.
    ///
    /// A `Value` rather than a `String` so `settings.json` stays readable and
    /// hand-editable instead of carrying one long escaped line.
    #[serde(default)]
    pub ui_prefs: serde_json::Value,

    // Storage
    /// Path to the encrypted chat history file. None = not yet configured (first run).
    pub chat_history_path: Option<String>,
    /// User chose to skip the encrypted chat vault — chat stays in-memory
    /// only and the first-run setup gate is not shown.
    pub chat_history_disabled: bool,
    /// How many conversations the archive keeps — channels and people
    /// together, across every server. 0 keeps all of them.
    ///
    /// What it bounds is the whole map being re-serialised on each save, not
    /// anything about the chat itself: a conversation is capped at 500 messages
    /// wherever it came from, and a history hand-off at 50. So the honest
    /// default is a large number and the honest option is none at all — what
    /// this drops is somebody's oldest conversations off their own disk.
    #[serde(default = "default_max_conversations")]
    pub max_conversations: u32,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            input_device: None,
            output_device: None,
            volume: 1.0,
            input_gain: 1.0,
            noise_suppression: true,
            voice_mode: "ptt".into(),
            vad_threshold_db: -40.0,
            ptt_key: "Space".into(),
            ptt_hold_mode: true,
            mute_key: None,
            deafen_key: None,
            muted: false,
            deafened: false,
            remember_connection: false,
            last_host: None,
            last_port: None,
            last_username: None,
            last_accept_self_signed: None,
            saved_servers: Vec::new(),
            screen_share_codec: "h264".into(),
            spatial_audio: true,
            screen_audio_spatial: true,
            mic_effect: "none".into(),
            mic_muffle: 0,
            mic_reverb: 0,
            mic_water: 0,
            audio_setup_version: 0,
            sdk_enabled: false,
            sdk_port: 39987,
            sdk_allowed_origins: Vec::new(),
            mumblelink_enabled: false,
            sdk_beacon_allowed: false,
            sdk_transmit_allowed: false,
            sounds: SoundSettings::default(),
            auto_connect: false,
            share_channel_history: true,
            // Null, not `{}`: "nothing has been chosen yet" is the state the
            // whole appearance blob starts in, and an empty object would be
            // indistinguishable from a user who reset every preference. What
            // the first-run picker itself keys on is `layout_asked_version`,
            // which is 0 either way.
            ui_prefs: serde_json::Value::Null,
            chat_history_path: None,
            chat_history_disabled: false,
            max_conversations: default_max_conversations(),
        }
    }
}

/// Returns the VoIPC data directory.
/// - Desktop: `~/.config/VoIPC/` (Linux) or `%APPDATA%/VoIPC` (Windows)
/// - Android: Tauri's `app_data_dir()` (set via `init_data_dir` in setup)
/// Creates the directory if it doesn't exist.
pub fn data_dir() -> PathBuf {
    let dir = if let Some(d) = DATA_DIR_OVERRIDE.get() {
        d.clone()
    } else {
        dirs::config_dir()
            .unwrap_or_else(|| std::env::temp_dir().join("voipc_fallback"))
            .join("VoIPC")
    };
    if !dir.exists() {
        if let Err(e) = std::fs::create_dir_all(&dir) {
            tracing::error!("failed to create VoIPC config directory {:?}: {e}", dir);
            // Fall back to temp directory
            let fallback = std::env::temp_dir().join("VoIPC");
            let _ = std::fs::create_dir_all(&fallback);
            return fallback;
        }
    }
    dir
}

/// Returns the path to `settings.json` in the VoIPC data directory.
pub fn config_path() -> PathBuf {
    data_dir().join("settings.json")
}

/// Returns the default path to `chat_history.bin` in the VoIPC data directory.
pub fn default_max_conversations() -> u32 {
    1000
}

pub fn default_chat_history_path() -> PathBuf {
    data_dir().join("chat_history.bin")
}

/// Resolves the chat history file path from config.
/// If `chat_history_path` is set, uses that; otherwise falls back to the default.
pub fn resolve_chat_history_path(config: &AppConfig) -> PathBuf {
    match &config.chat_history_path {
        Some(p) => PathBuf::from(p),
        None => default_chat_history_path(),
    }
}

/// Migrate settings.json and chat_history.bin from the old location (next to executable)
/// to the new XDG-compliant directory. Only runs once — skips if files already exist
/// at the new location or if old files don't exist.
pub fn migrate_legacy_paths() {
    let Ok(exe) = std::env::current_exe() else { return };
    let Some(exe_dir) = exe.parent() else { return };

    let new_dir = data_dir();
    for filename in &["settings.json", "chat_history.bin"] {
        let old = exe_dir.join(filename);
        let new = new_dir.join(filename);
        if old.exists() && !new.exists() {
            match std::fs::rename(&old, &new) {
                Ok(()) => tracing::info!("Migrated {filename} → {}", new.display()),
                Err(_) => {
                    // rename fails across filesystems, fall back to copy+delete
                    if let Ok(data) = std::fs::read(&old) {
                        if std::fs::write(&new, &data).is_ok() {
                            let _ = std::fs::remove_file(&old);
                            tracing::info!("Migrated {filename} → {}", new.display());
                        }
                    }
                }
            }
        }
    }
}

/// Load config from disk. Returns defaults on any error (missing file, parse error).
pub fn load_config() -> AppConfig {
    let path = config_path();
    match std::fs::read_to_string(&path) {
        Ok(contents) => match serde_json::from_str(&contents) {
            Ok(config) => config,
            Err(e) => {
                tracing::warn!("Failed to parse {}: {e} — using defaults", path.display());
                AppConfig::default()
            }
        },
        Err(e) => {
            tracing::info!("Could not read config {}: {e} — using defaults", path.display());
            AppConfig::default()
        }
    }
}

/// Save config to disk atomically (write to .tmp, then rename).
pub fn save_config(config: &AppConfig) -> Result<(), String> {
    let path = config_path();
    let tmp_path = path.with_extension("json.tmp");
    let json = serde_json::to_string_pretty(config)
        .map_err(|e| format!("Failed to serialize config: {e}"))?;
    std::fs::write(&tmp_path, json)
        .map_err(|e| format!("Failed to write {}: {e}", tmp_path.display()))?;
    std::fs::rename(&tmp_path, &path)
        .map_err(|e| format!("Failed to rename config: {e}"))?;
    Ok(())
}

/// Delete the config file (for reset).
pub fn delete_config() {
    let path = config_path();
    let _ = std::fs::remove_file(&path);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The appearance blob is the one field this side never reads, which is
    /// exactly why it is worth pinning: if it stopped round-tripping, nothing
    /// in Rust would notice and the user would just find their layout reset.
    #[test]
    fn ui_prefs_round_trip_verbatim() {
        let mut config = AppConfig::default();
        config.ui_prefs = serde_json::json!({
            "layout": "modern",
            "palette_overrides": { "--accent": "#ff0000" },
            // A key a newer build wrote and this one knows nothing about. It
            // has to survive, or running two versions against one config file
            // loses a setting on every save.
            "something_from_the_future": [1, 2, 3],
        });

        let text = serde_json::to_string_pretty(&config).expect("serialize");
        let back: AppConfig = serde_json::from_str(&text).expect("deserialize");

        assert_eq!(back.ui_prefs, config.ui_prefs);
        // Readable, not one long escaped line — the reason the field is a
        // `Value` rather than a `String`.
        assert!(text.contains("\"--accent\": \"#ff0000\""), "{text}");
    }

    /// A config written before this field existed must still load.
    #[test]
    fn a_config_without_ui_prefs_still_loads() {
        let older = r#"{ "volume": 0.5, "ptt_key": "KeyV" }"#;
        let config: AppConfig = serde_json::from_str(older).expect("deserialize");
        assert_eq!(config.ui_prefs, serde_json::Value::Null);
        assert_eq!(config.ptt_key, "KeyV");
    }
}
