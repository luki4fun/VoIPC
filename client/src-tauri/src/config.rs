use std::path::PathBuf;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

/// Overridden data directory (set via init_data_dir on Android).
static DATA_DIR_OVERRIDE: OnceLock<PathBuf> = OnceLock::new();

/// Set the data directory explicitly. Called from lib.rs setup on Android
/// with Tauri's app_data_dir(). Must be called before any other config function.
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
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
#[derive(Default)]
pub struct SoundSettings {
    pub channel_switch: SoundEntry,
    pub user_joined: SoundEntry,
    pub user_left: SoundEntry,
    pub disconnected: SoundEntry,
    pub direct_message: SoundEntry,
    pub channel_message: SoundEntry,
    pub poke: SoundEntry,
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
    /// `username` is a relay account there, signed in with this device's key.
    #[serde(default)]
    pub account: bool,
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
    /// The servers that were open when the app last changed them, in the order
    /// they were opened: what a start with `auto_connect` reconnects. Empty in
    /// a config written before several servers could be open at once.
    #[serde(default)]
    pub open_servers: Vec<SavedServer>,

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
    /// The relay id each address said at its last account sign-in (address →
    /// hex). A server that names the id another address has here is refused
    /// before any password secret goes to it (`SignIn::expect_relay`).
    #[serde(default)]
    pub relay_ids: std::collections::BTreeMap<String, String>,
    /// Look for a new VoIPC once a day (desktop NSIS and AppImage builds).
    /// Each look tells GitHub this address and version, hence the switch.
    pub check_updates: bool,
    /// The file's format. A newer VoIPC that changes the meaning of a key
    /// raises it; this version then reads what it can and saves nothing.
    pub format: u32,
    /// Keys this version does not know, written back as they are, so an
    /// older VoIPC does not delete a newer one's settings.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// The `settings.json` format this build writes.
pub const SETTINGS_FORMAT: u32 = 1;

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
            open_servers: Vec::new(),
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
            relay_ids: Default::default(),
            check_updates: true,
            format: SETTINGS_FORMAT,
            extra: serde_json::Map::new(),
        }
    }
}

/// Returns the VoIPC data directory.
/// - Desktop: `~/.config/VoIPC/` (Linux) or `%APPDATA%/VoIPC` (Windows)
/// - Android: Tauri's `app_data_dir()` (set via `init_data_dir` in setup)
///
/// Creates the directory if it doesn't exist.
pub fn data_dir() -> PathBuf {
    let dir = if let Some(d) = DATA_DIR_OVERRIDE.get() {
        d.clone()
    } else if cfg!(test) {
        // Tests never touch the person's real settings, pins or history
        std::env::temp_dir().join(format!("voipc-test-{}", std::process::id()))
    } else {
        dirs::config_dir()
            .unwrap_or_else(|| std::env::temp_dir().join("voipc_fallback"))
            .join("VoIPC")
    };
    // Private to this user: it holds the servers, names and pins, and the
    // history's salt. No fallback into a shared temp directory, where another
    // user could have made it first and swap what we read.
    static TIGHTENED: std::sync::Once = std::sync::Once::new();
    TIGHTENED.call_once(|| {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        if let Err(e) = builder.create(&dir) {
            tracing::error!("failed to create VoIPC config directory {:?}: {e}", dir);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        }
    });
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

/// Load config from disk. Returns defaults on any error (missing file, parse
/// error). A file that does not parse is kept aside first
/// (`settings.json.unreadable-<unix>`): the next save would otherwise replace
/// it, and with it the remembered servers and relay ids.
pub fn load_config() -> AppConfig {
    let path = config_path();
    match std::fs::read_to_string(&path) {
        Ok(contents) => match serde_json::from_str(&contents) {
            Ok(config) => config,
            Err(e) => {
                let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
                let aside = path.with_file_name(format!("settings.json.unreadable-{secs}"));
                let kept = std::fs::rename(&path, &aside);
                tracing::warn!("Failed to parse {}: {e} — using defaults (the file is kept as {}: {kept:?})", path.display(), aside.display());
                AppConfig::default()
            }
        },
        Err(e) => {
            tracing::info!("Could not read config {}: {e} — using defaults", path.display());
            AppConfig::default()
        }
    }
}

/// Replace `path` with `data` whole or not at all: write a `.tmp` beside it,
/// flush it to the disk, then rename it over. A crash or power cut part way
/// through a plain write leaves a truncated file — for the chat vault, one
/// AES-GCM refuses entirely, which loses the whole history.
pub fn write_atomic(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut tmp_name = path.file_name().unwrap_or_default().to_os_string();
    tmp_name.push(".tmp");
    let tmp_path = path.with_file_name(tmp_name);
    // Readable by this user only, made fresh (a stale one from a crash is
    // removed first): the rename gives the file the same mode.
    let _ = std::fs::remove_file(&tmp_path);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(&tmp_path)?;
    file.write_all(data)?;
    file.sync_all()?;
    std::fs::rename(&tmp_path, path)
}

/// Save config to disk atomically.
pub fn save_config(config: &AppConfig) -> Result<(), String> {
    let path = config_path();
    if config.format > SETTINGS_FORMAT {
        return Err("Settings were saved by a newer VoIPC: changes are not saved by this one".into());
    }
    let json = serde_json::to_string_pretty(config)
        .map_err(|e| format!("Failed to serialize config: {e}"))?;
    // Never write a file the next start cannot read: a float that is not
    // finite becomes `null`, which then fails the whole parse.
    serde_json::from_str::<AppConfig>(&json).map_err(|e| format!("Refusing to save settings that would not load again: {e}"))?;
    write_atomic(&path, json.as_bytes())
        .map_err(|e| format!("Failed to write {}: {e}", path.display()))
}

/// Delete the config file (for reset).
pub fn delete_config() {
    let path = config_path();
    let _ = std::fs::remove_file(&path);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_atomic_replaces_the_file_and_leaves_no_tmp() {
        let dir = std::env::temp_dir().join(format!("voipc-atomic-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("chat_history.bin");
        write_atomic(&path, b"first").unwrap();
        write_atomic(&path, b"second, longer").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second, longer");
        let names: Vec<_> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(names, ["chat_history.bin"], "the .tmp was renamed over, not left behind");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600, "readable by this user only");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A key a newer VoIPC added survives this one's save; a newer format is
    /// read but never saved over; a value that would not load again is not
    /// written (H4-12: one `inf` used to reset the whole file).
    #[test]
    fn settings_keep_what_they_do_not_know_and_never_write_what_will_not_load() {
        let mut config: AppConfig = serde_json::from_str(r#"{"volume": 0.5, "from_1_1": {"x": 1}}"#).unwrap();
        assert_eq!(config.format, SETTINGS_FORMAT, "a 0.12 file is format 1");
        let text = serde_json::to_string(&config).unwrap();
        assert!(text.contains("from_1_1"), "{text}");

        let newer: AppConfig = serde_json::from_str(r#"{"format": 2}"#).unwrap();
        assert!(save_config(&newer).unwrap_err().contains("newer VoIPC"));

        config.volume = f32::INFINITY;
        assert!(save_config(&config).unwrap_err().contains("would not load"));
    }

    /// D15: checking for updates is on unless the user switched it off, also
    /// for a settings file from before the switch existed.
    #[test]
    fn update_checks_are_on_until_switched_off() {
        let old: AppConfig = serde_json::from_str(r#"{"volume": 0.5}"#).unwrap();
        assert!(old.check_updates);
        let off: AppConfig = serde_json::from_str(r#"{"check_updates": false}"#).unwrap();
        assert!(!off.check_updates);
    }

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

    /// Every config written before several servers could be open lacks the
    /// list. It must load as "none open" — the front end then counts the last
    /// server as the one — and never as a parse error, which would reset
    /// every other setting to its default.
    #[test]
    fn open_servers_default_to_none_and_round_trip() {
        let older = r#"{ "last_host": "voice.example", "last_port": 9987 }"#;
        let config: AppConfig = serde_json::from_str(older).expect("deserialize");
        assert!(config.open_servers.is_empty());
        assert_eq!(config.last_host.as_deref(), Some("voice.example"));

        let mut config = AppConfig::default();
        config.open_servers = vec![
            SavedServer {
                name: "one".into(),
                host: "a.example".into(),
                port: 9987,
                username: "luki".into(),
                accept_self_signed: false,
                account: false,
            },
            SavedServer {
                name: "two".into(),
                host: "b.example".into(),
                port: 9988,
                username: "luki".into(),
                accept_self_signed: true,
                account: true,
            },
        ];
        let text = serde_json::to_string(&config).expect("serialize");
        let back: AppConfig = serde_json::from_str(&text).expect("deserialize");
        let hosts: Vec<_> = back.open_servers.iter().map(|s| (s.host.as_str(), s.port)).collect();
        assert_eq!(hosts, [("a.example", 9987), ("b.example", 9988)], "order is the opening order");
        assert!(back.open_servers[1].accept_self_signed);
    }
}
