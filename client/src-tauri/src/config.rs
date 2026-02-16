use std::path::PathBuf;

use serde::{Deserialize, Serialize};

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

/// Persistent user configuration, saved as `settings.json` in the VoIPC data directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    // Audio
    pub input_device: Option<String>,
    pub output_device: Option<String>,
    pub volume: f32,
    pub noise_suppression: bool,

    // Voice mode
    pub voice_mode: String,
    pub vad_threshold_db: f32,

    // PTT
    pub ptt_key: String,
    pub ptt_hold_mode: bool,

    // Mute/Deafen (restored on next connect)
    pub muted: bool,
    pub deafened: bool,

    // Optional connection info
    pub remember_connection: bool,
    pub last_host: Option<String>,
    pub last_port: Option<u16>,
    pub last_username: Option<String>,
    pub last_accept_self_signed: Option<bool>,

    // QoL
    pub sounds: SoundSettings,
    pub auto_connect: bool,

    // Storage
    /// Path to the encrypted chat history file. None = not yet configured (first run).
    pub chat_history_path: Option<String>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            input_device: None,
            output_device: None,
            volume: 1.0,
            noise_suppression: true,
            voice_mode: "ptt".into(),
            vad_threshold_db: -40.0,
            ptt_key: "Space".into(),
            ptt_hold_mode: true,
            muted: false,
            deafened: false,
            remember_connection: false,
            last_host: None,
            last_port: None,
            last_username: None,
            last_accept_self_signed: None,
            sounds: SoundSettings::default(),
            auto_connect: false,
            chat_history_path: None,
        }
    }
}

/// Returns the VoIPC data directory (~/.config/VoIPC/ on Linux, %APPDATA%/VoIPC on Windows).
/// Creates the directory if it doesn't exist.
pub fn data_dir() -> PathBuf {
    let dir = dirs::config_dir()
        .expect("failed to determine config directory")
        .join("VoIPC");
    if !dir.exists() {
        std::fs::create_dir_all(&dir).expect("failed to create VoIPC config directory");
    }
    dir
}

/// Returns the path to `settings.json` in the VoIPC data directory.
pub fn config_path() -> PathBuf {
    data_dir().join("settings.json")
}

/// Returns the default path to `chat_history.bin` in the VoIPC data directory.
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
        Err(_) => AppConfig::default(),
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
