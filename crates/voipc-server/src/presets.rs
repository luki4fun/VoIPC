//! Ready-made channel layouts: `voipc-server channels presets` lists them,
//! `voipc-server channels init <preset>` writes one to `channels.json`.
//!
//! A preset is a `channels.json` with a little around it (`presets/*.json`,
//! built into the binary). Where a secret belongs it says
//! [`PRESET_PLACEHOLDER`], and `init` puts a fresh one there: a password that
//! shipped in the preset would be the same on every server that used it. The
//! file it writes keeps only the hashes; the passwords are printed once.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use rand::Rng;
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::channels::{self, ChannelEntry, PRESET_PLACEHOLDER};
use crate::settings::ServerSettings;

/// Every preset, in the order `channels presets` lists them.
const SOURCES: &[&str] = &[
    include_str!("../presets/starter.json"),
    include_str!("../presets/gaming.json"),
    include_str!("../presets/roleplay.json"),
    include_str!("../presets/mmo.json"),
    include_str!("../presets/competitive.json"),
    include_str!("../presets/tabletop.json"),
    include_str!("../presets/study.json"),
    include_str!("../presets/lan.json"),
    include_str!("../presets/project.json"),
    include_str!("../presets/family.json"),
    include_str!("../presets/community.json"),
];

/// Letters and digits nobody misreads when a password is read out over voice
/// or copied off a screen: no 0/o, 1/l/i.
const PASSWORD_ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Preset {
    pub id: String,
    pub label: String,
    pub summary: String,
    /// `server_settings.json` values this layout needs, by key.
    #[serde(default)]
    pub settings: Map<String, Value>,
    /// What to do next, printed after `init`.
    #[serde(default)]
    pub notes: Vec<String>,
    pub channels: Vec<ChannelEntry>,
}

/// A preset with its placeholders filled in.
pub struct Instance {
    /// Ready for `channels.json`: hashes only, no plaintext.
    pub channels: Vec<ChannelEntry>,
    /// Channel name and the password it was given, to print once.
    pub passwords: Vec<(String, String)>,
    /// The preset's settings with fresh secrets in them.
    pub settings: Map<String, Value>,
    /// Settings keys that were given a fresh secret.
    pub secrets: Vec<String>,
}

#[derive(clap::Subcommand)]
pub enum ChannelsCommand {
    /// List the built-in channel presets.
    Presets,
    /// Write channels.json from a preset (and server_settings.json, if there
    /// is none and the preset needs one). Locked channels get fresh passwords,
    /// printed once.
    Init {
        /// The preset's id, as `channels presets` lists it.
        preset: String,
        /// Where to write the channels [default: --channels, else ./channels.json]
        #[arg(long)]
        out: Option<PathBuf>,
        /// Replace an existing file; the old one is kept as <file>.bak.
        #[arg(long)]
        force: bool,
        /// Print the preset as it would be written, placeholders and all, and
        /// write nothing.
        #[arg(long)]
        dry_run: bool,
    },
}

pub fn all() -> Vec<Preset> {
    SOURCES
        .iter()
        .map(|src| serde_json::from_str(src).expect("built-in presets parse (presets::tests)"))
        .collect()
}

pub fn by_id(id: &str) -> Option<Preset> {
    all().into_iter().find(|p| p.id.eq_ignore_ascii_case(id.trim()))
}

/// Twelve characters as `xxxx-xxxx-xxxx`: about 59 bits, and short enough to
/// read out to somebody.
pub fn generate_password() -> String {
    let mut rng = rand::thread_rng();
    let mut out = String::with_capacity(14);
    for i in 0..12 {
        if i > 0 && i % 4 == 0 {
            out.push('-');
        }
        out.push(PASSWORD_ALPHABET[rng.gen_range(0..PASSWORD_ALPHABET.len())] as char);
    }
    out
}

pub fn instantiate(preset: &Preset) -> Instance {
    let mut passwords = Vec::new();
    let channels = preset
        .channels
        .iter()
        .cloned()
        .map(|mut entry| {
            if let Some(password) = entry.password.take() {
                let password = if password == PRESET_PLACEHOLDER { generate_password() } else { password };
                entry.password_hash = Some(channels::hash_password(&password).expect("a preset's passwords are 1 to 512 characters"));
                passwords.push((entry.name.clone(), password));
            }
            entry
        })
        .collect();
    let mut secrets = Vec::new();
    let settings = preset
        .settings
        .iter()
        .map(|(key, value)| {
            let value = if value.as_str() == Some(PRESET_PLACEHOLDER) {
                secrets.push(key.clone());
                // The same shape as a generated admin token.
                Value::String(hex::encode(rand::random::<[u8; 32]>()))
            } else {
                value.clone()
            };
            (key.clone(), value)
        })
        .collect();
    Instance { channels, passwords, settings, secrets }
}

/// `ServerSettings::default()` with `overrides` on top, refused if a key is
/// not a setting or a value does not fit it.
fn settings_with(overrides: &Map<String, Value>) -> anyhow::Result<ServerSettings> {
    let Value::Object(mut merged) = serde_json::to_value(ServerSettings::default())? else {
        unreachable!("ServerSettings serializes to an object")
    };
    for (key, value) in overrides {
        if !merged.contains_key(key) {
            bail!("the preset sets {key:?}, which is not a server setting");
        }
        merged.insert(key.clone(), value.clone());
    }
    serde_json::from_value(Value::Object(merged)).context("the preset's settings do not fit")
}

/// One line about a channel: its kind and whatever is not plain about it.
fn describe(entry: &ChannelEntry) -> String {
    let mut parts = vec![if entry.text { "text" } else { "voice" }.to_string()];
    if entry.auto_join {
        parts.push("auto-join".into());
    }
    if entry.announce {
        parts.push("announcements".into());
    }
    if entry.slow_mode_secs > 0 {
        parts.push(format!("slow mode {} s", entry.slow_mode_secs));
    }
    if entry.message_ttl_secs > 0 {
        parts.push(format!("messages live {}", duration(entry.message_ttl_secs)));
    }
    if entry.proximity != voipc_protocol::types::ProximityMode::Off {
        let mode = serde_json::to_value(entry.proximity).ok();
        parts.push(format!("{} proximity", mode.as_ref().and_then(Value::as_str).unwrap_or("?")));
    }
    if entry.routed {
        parts.push("routed".into());
    }
    if entry.max_users > 0 {
        parts.push(format!("max {}", entry.max_users));
    }
    if entry.hidden {
        parts.push("hidden".into());
    }
    if entry.hide_members {
        parts.push("members hidden".into());
    }
    if entry.anonymous {
        parts.push("anonymous".into());
    }
    if !entry.text && !entry.screen_share {
        parts.push("no screen share".into());
    }
    if entry.nsfw {
        parts.push("18+".into());
    }
    if entry.password.is_some() || entry.password_hash.is_some() {
        parts.push("password".into());
    }
    parts.join(", ")
}

fn duration(secs: u32) -> String {
    match secs {
        s if s % 86_400 == 0 => format!("{} d", s / 86_400),
        s if s % 3_600 == 0 => format!("{} h", s / 3_600),
        s if s % 60 == 0 => format!("{} min", s / 60),
        s => format!("{s} s"),
    }
}

fn channel_label(entry: &ChannelEntry) -> String {
    if entry.text {
        format!("#{}", entry.name)
    } else {
        entry.name.clone()
    }
}

fn counts(channels: &[ChannelEntry]) -> (usize, usize) {
    let text = channels.iter().filter(|c| c.text).count();
    (text, channels.len() - text)
}

/// `voipc-server channels …`. Needs no certificate, config or database, so it
/// runs before any of them are looked at (server.toml included).
pub fn run(
    command: ChannelsCommand,
    channels_path: Option<&str>,
    settings_path: Option<&str>,
) -> anyhow::Result<()> {
    match command {
        ChannelsCommand::Presets => {
            for preset in all() {
                let (text, voice) = counts(&preset.channels);
                println!("{:<12} {}", preset.id, preset.label);
                println!("{:<12} {} ({text} text, {voice} voice)", "", preset.summary);
            }
            println!("\nvoipc-server channels init <id> writes one to channels.json.");
            Ok(())
        }
        ChannelsCommand::Init { preset, out, force, dry_run } => {
            let Some(preset) = by_id(&preset) else {
                let ids: Vec<String> = all().into_iter().map(|p| p.id).collect();
                bail!("no preset called {preset:?}; there are: {}", ids.join(", "));
            };
            let out = out
                .or_else(|| channels_path.map(PathBuf::from))
                .unwrap_or_else(|| PathBuf::from("channels.json"));
            let settings_path = PathBuf::from(settings_path.unwrap_or("server_settings.json"));
            if dry_run {
                println!("{}", serde_json::to_string_pretty(&preset.channels)?);
                if !preset.settings.is_empty() {
                    println!("\nserver_settings.json needs:");
                    println!("{}", serde_json::to_string_pretty(&preset.settings)?);
                }
                return Ok(());
            }
            init(&preset, &out, &settings_path, force)
        }
    }
}

fn init(preset: &Preset, out: &Path, settings_path: &Path, force: bool) -> anyhow::Result<()> {
    if out.exists() && !force {
        bail!(
            "{} already exists; pass --force to replace it (the old one is kept as {}.bak)",
            out.display(),
            out.display()
        );
    }
    let instance = instantiate(preset);
    channels::validate_entries(&instance.channels).context("the preset does not validate")?;
    let settings = settings_with(&instance.settings)?;

    // The settings file first: if anything is to fail, it fails before
    // channels.json holds passwords nobody was shown.
    // A settings file of the server's own is left exactly as it is: it may
    // hold a game token a game server already uses.
    let settings_note = if instance.settings.is_empty() {
        None
    } else if settings_path.exists() {
        Some(format!(
            "{} was left alone. This preset needs, in it:\n{}",
            settings_path.display(),
            serde_json::to_string_pretty(&instance.settings)?
        ))
    } else {
        let json = serde_json::to_string_pretty(&settings)?;
        // A game token: for the server's own user only.
        crate::fsutil::atomic_write(settings_path, json.as_bytes(), true).with_context(|| format!("writing {}", settings_path.display()))?;
        let mut note = format!("Wrote {}.", settings_path.display());
        for key in &instance.secrets {
            if let Some(value) = instance.settings.get(key).and_then(Value::as_str) {
                note.push_str(&format!("\n{key}: {value}"));
            }
        }
        Some(note)
    };

    if out.exists() {
        // Never over an older copy: a second `--force` keeps the first original.
        let backup = (1..)
            .map(|n| PathBuf::from(if n == 1 { format!("{}.bak", out.display()) } else { format!("{}.bak.{n}", out.display()) }))
            .find(|p| !p.exists())
            .expect("a free name");
        // Private from the start: a channels.json from before 0.12 was written
        // world-readable, and its password hashes are not
        std::fs::read(out)
            .and_then(|old| crate::fsutil::create_private(&backup, &old))
            .with_context(|| format!("keeping a copy of {} as {}", out.display(), backup.display()))?;
        println!("Kept the old file as {}", backup.display());
    }
    channels::atomic_rewrite(out, &instance.channels)
        .with_context(|| format!("writing {}", out.display()))?;

    let (text, voice) = counts(&instance.channels);
    println!(
        "Wrote {} from the {:?} preset: {text} text and {voice} voice channels.\n",
        out.display(),
        preset.id
    );
    let width = instance.channels.iter().map(|c| channel_label(c).chars().count()).max().unwrap_or(0);
    for entry in &instance.channels {
        println!("  {:<width$}  {}", channel_label(entry), describe(entry));
    }
    if !instance.passwords.is_empty() {
        println!("\nPasswords — shown this once; {} keeps only their hashes:", out.display());
        let width = instance.passwords.iter().map(|(n, _)| n.chars().count()).max().unwrap_or(0);
        for (name, password) in &instance.passwords {
            println!("  {name:<width$}  {password}");
        }
    }
    if let Some(note) = settings_note {
        println!("\n{note}");
    }
    println!("\nRestart the server to load it. To change a password for good, put");
    println!("\"password\": \"…\" in place of that channel's \"password_hash\".");
    if !preset.notes.is_empty() {
        println!();
        for note in &preset.notes {
            println!("- {note}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Every key a `ChannelEntry` knows. Not `deny_unknown_fields` on the type
    /// itself — a server must keep loading a file with a key it has since
    /// dropped — so the presets are held to it here instead: a typo there
    /// would quietly leave a staff room open.
    fn channel_keys() -> HashSet<String> {
        let entry = ChannelEntry {
            password: Some(String::new()),
            password_hash: Some(String::new()),
            ..Default::default()
        };
        let Value::Object(map) = serde_json::to_value(entry).unwrap() else { unreachable!() };
        map.keys().cloned().collect()
    }

    #[test]
    fn every_preset_parses_and_its_keys_are_real() {
        let known = channel_keys();
        let mut ids = HashSet::new();
        for src in SOURCES {
            let raw: Value = serde_json::from_str(src).unwrap();
            let preset: Preset = serde_json::from_str(src).unwrap();
            assert!(ids.insert(preset.id.clone()), "two presets are called {}", preset.id);
            for channel in raw["channels"].as_array().unwrap() {
                for key in channel.as_object().unwrap().keys() {
                    assert!(known.contains(key), "{}: unknown channel key {key:?}", preset.id);
                }
            }
        }
        assert_eq!(all().len(), SOURCES.len());
    }

    #[test]
    fn every_preset_instantiates_into_a_valid_channels_file() {
        for preset in all() {
            let id = &preset.id;
            let instance = instantiate(&preset);
            channels::validate_entries(&instance.channels).unwrap_or_else(|e| panic!("{id}: {e}"));
            settings_with(&instance.settings).unwrap_or_else(|e| panic!("{id}: {e}"));

            for entry in &instance.channels {
                // What a user may type for a channel of their own, so a preset
                // never shows names the server would refuse at runtime.
                assert!(entry.name.chars().count() <= 32, "{id}: {:?} is too long", entry.name);
                assert!(entry.password.is_none(), "{id}: plaintext left in {}", entry.name);
            }
            let json = serde_json::to_string(&instance.channels).unwrap();
            assert!(!json.contains(PRESET_PLACEHOLDER), "{id}: a placeholder survived");
            let settings = serde_json::to_string(&instance.settings).unwrap();
            assert!(!settings.contains(PRESET_PLACEHOLDER), "{id}: a placeholder survived");

            // The lobby has no chat, so somebody arriving needs somewhere to land
            assert!(
                instance.channels.iter().any(|c| c.text && c.auto_join),
                "{id}: no auto-join text channel"
            );
            // Every locked channel got its own password, and none is shared
            let distinct: HashSet<&String> = instance.passwords.iter().map(|(_, p)| p).collect();
            assert_eq!(distinct.len(), instance.passwords.len(), "{id}: a password repeats");
        }
    }

    #[test]
    fn instantiating_twice_gives_different_secrets() {
        let preset = by_id("roleplay").expect("the roleplay preset");
        let (a, b) = (instantiate(&preset), instantiate(&preset));
        assert!(!a.passwords.is_empty() && !a.secrets.is_empty());
        assert_ne!(a.passwords, b.passwords);
        assert_ne!(a.settings.get("game_token"), b.settings.get("game_token"));
    }

    #[test]
    fn generated_passwords_are_readable() {
        for _ in 0..100 {
            let pw = generate_password();
            assert_eq!(pw.len(), 14, "{pw}");
            let groups: Vec<&str> = pw.split('-').collect();
            assert_eq!(groups.len(), 3, "{pw}");
            assert!(groups.iter().all(|g| g.len() == 4 && g.bytes().all(|b| PASSWORD_ALPHABET.contains(&b))));
        }
    }

    #[test]
    fn init_writes_hashes_and_keeps_an_existing_settings_file() {
        let dir = std::env::temp_dir().join(format!("voipc-presets-{}", hex::encode(rand::random::<[u8; 6]>())));
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("channels.json");
        let settings = dir.join("server_settings.json");
        let preset = by_id("roleplay").unwrap();

        init(&preset, &out, &settings, false).unwrap();
        let loaded = channels::load_and_prepare_channels(&out).unwrap();
        assert_eq!(loaded.len(), preset.channels.len());
        let written = std::fs::read_to_string(&out).unwrap();
        assert!(!written.contains("\"password\""), "plaintext reached the file");
        let token = ServerSettings::load_from_file(&settings).unwrap().game_token;
        assert!(token.is_some_and(|t| t.len() == 64));

        // Not over an existing file without --force, and with it, a backup
        assert!(init(&preset, &out, &settings, false).is_err());
        let before = std::fs::read_to_string(&settings).unwrap();
        init(&preset, &out, &settings, true).unwrap();
        assert_eq!(std::fs::read_to_string(dir.join("channels.json.bak")).unwrap(), written);
        assert_eq!(std::fs::read_to_string(&settings).unwrap(), before, "settings were rewritten");
        // A second --force keeps the first copy of the original.
        init(&preset, &out, &settings, true).unwrap();
        assert_eq!(std::fs::read_to_string(dir.join("channels.json.bak")).unwrap(), written);
        assert!(dir.join("channels.json.bak.2").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for f in [&out, &settings] {
                assert_eq!(std::fs::metadata(f).unwrap().permissions().mode() & 0o777, 0o600, "{}", f.display());
            }
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_settings_file_that_cannot_be_written_leaves_channels_json_alone() {
        let dir = std::env::temp_dir().join(format!("voipc-presets-{}", hex::encode(rand::random::<[u8; 6]>())));
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("channels.json");
        std::fs::write(&out, "[]").unwrap();
        // The game token's file cannot be made: its folder is not there.
        let settings = dir.join("missing").join("server_settings.json");
        assert!(init(&by_id("roleplay").unwrap(), &out, &settings, true).is_err());
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "[]", "no channel passwords that were never shown");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unknown_setting_in_a_preset_is_refused() {
        let mut overrides = Map::new();
        overrides.insert("max_chanels".into(), Value::from(10));
        assert!(settings_with(&overrides).is_err());
        overrides.clear();
        overrides.insert("max_channels".into(), Value::from(10));
        assert_eq!(settings_with(&overrides).unwrap().max_channels, 10);
    }
}
