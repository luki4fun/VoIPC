use std::collections::HashSet;
use std::path::Path;

use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tracing::info;
use voipc_protocol::types::ProximityMode;

const SHA256_PREFIX: &str = "sha256:";
const ARGON2_PREFIX: &str = "$argon2id$";

/// What a preset writes where a secret belongs. `voipc-server channels init`
/// replaces it with a fresh one; a file that still carries it was copied by
/// hand, and starting with it would hand every server that did so the same
/// password — so it is refused instead.
pub const PRESET_PLACEHOLDER: &str = "<generate>";

/// Refuses a secret that is still the preset's placeholder; `what` names it.
pub fn refuse_placeholder(what: &str, value: Option<&str>) -> anyhow::Result<()> {
    if value == Some(PRESET_PLACEHOLDER) {
        bail!("{what} is still the preset placeholder {PRESET_PLACEHOLDER:?}: set a real one, or write the file with `voipc-server channels init`");
    }
    Ok(())
}

/// The longest slow mode a channel may ask for (6 h). Past that it stops being
/// a pace and becomes a ban on talking, which is what `announce` is for.
pub const MAX_SLOW_MODE_SECS: u32 = 6 * 60 * 60;

/// A single channel entry as read from channels.json.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelEntry {
    pub name: String,

    #[serde(default)]
    pub description: String,

    /// Plaintext password — hashed to `password_hash` on first load and removed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,

    /// The password's hash (`hash_password`): Argon2id as a PHC string, or
    /// `"sha256:<64 hex chars>"` as written before 1.0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_hash: Option<String>,

    /// Maximum users (0 = unlimited).
    #[serde(default)]
    pub max_users: u32,

    /// Positional audio mode: "off" (default), "2d" or "3d".
    #[serde(default)]
    pub proximity: ProximityMode,

    /// Keep the channel out of the sidebar for non-admins. It can still be
    /// joined by id, so invite links and the game SDK keep working.
    #[serde(default)]
    pub hidden: bool,

    /// Members see each other under a random pseudonym; admins see the real
    /// names. Chat history is not handed over in such a channel.
    #[serde(default)]
    pub anonymous: bool,

    /// Whether screen sharing is allowed here (default: yes).
    #[serde(default = "default_true")]
    pub screen_share: bool,

    /// Hide the member list from non-admins; they still see whoever speaks.
    #[serde(default)]
    pub hide_members: bool,

    /// Forward voice only to the people who should hear it, instead of to
    /// every member. For a channel a game drives, where "every member" can be
    /// a whole map; it is also the only setting that tells this server
    /// anything about who hears whom, so it is off unless asked for.
    #[serde(default)]
    pub routed: bool,

    /// A text channel: joining it is a subscription rather than a move, so
    /// several can be open at once and none of them costs the user their voice
    /// channel. Voice, screen share and proximity do not apply.
    #[serde(default)]
    pub text: bool,

    /// Clients join this text channel on connect. Only meaningful with
    /// `text`; a user who leaves it is not re-joined, which the client
    /// remembers — the server joins nobody by itself.
    #[serde(default)]
    pub auto_join: bool,

    /// Seconds a message written here is meant to live; 0 (the default) is no
    /// timer. The server stores no chat and enforces nothing — this is what
    /// the channel tells its members, and each client stamps it on what it
    /// sends and applies it to what it keeps.
    #[serde(default)]
    pub message_ttl_secs: u32,

    /// Only the channel's managers (admins and moderators, for a channel from
    /// this file) may post; the relay refuses everybody else. Text channels
    /// only.
    #[serde(default)]
    pub announce: bool,

    /// A member may post once per this many seconds; 0 (the default) is off.
    /// Admins and moderators are exempt. Up to six hours.
    #[serde(default)]
    pub slow_mode_secs: u32,

    /// Marked 18+: clients ask for consent before joining or showing it.
    #[serde(default)]
    pub nsfw: bool,

    /// What names this channel's stored-message log (relays with accounts).
    /// Without one the log is named after the channel, so renaming the
    /// channel starts a new log; set it (letters, digits, `-`, `_`) to keep
    /// one log across renames.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,

    /// Keys this version does not know, kept as they are: the server rewrites
    /// the file when it hashes a password, and must not delete what a newer
    /// version wrote.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl ChannelEntry {
    /// The conversation id of this channel's stored-message log.
    pub fn log_conv(&self) -> String {
        match &self.uid {
            Some(uid) => format!("c:{uid}"),
            None => {
                let digest = Sha256::digest(format!("voipc-channel/v1|{}", self.name.trim().to_lowercase()).as_bytes());
                format!("c:{}", hex::encode(&digest[..16]))
            }
        }
    }
}

fn default_true() -> bool {
    true
}

impl Default for ChannelEntry {
    /// A plain public channel. Tests build on this so a new option does not
    /// have to be added to a dozen literals.
    fn default() -> Self {
        Self {
            name: String::new(),
            description: String::new(),
            password: None,
            password_hash: None,
            max_users: 0,
            proximity: ProximityMode::Off,
            hidden: false,
            anonymous: false,
            screen_share: true,
            hide_members: false,
            routed: false,
            text: false,
            auto_join: false,
            message_ttl_secs: 0,
            announce: false,
            slow_mode_secs: 0,
            nsfw: false,
            uid: None,
            extra: serde_json::Map::new(),
        }
    }
}

/// A channel password as `channels.json` keeps it: Argon2id, as a PHC string
/// (`$argon2id$v=19$…`, l4f's parameters). Before 1.0 it was unsalted SHA-256
/// (`sha256:<hex>`), which `verify_password` still reads (1.0 audit H1-16).
pub fn hash_password(plaintext: &str) -> anyhow::Result<String> {
    if plaintext.is_empty() || plaintext.chars().nth(l4f_accounts::password::MAX_LEN).is_some() {
        bail!("a channel password must be 1 to {} characters", l4f_accounts::password::MAX_LEN);
    }
    Ok(l4f_accounts::password::hash(plaintext))
}

/// Whether `attempt` is the password `stored` (`hash_password`'s, or a
/// `sha256:` one from before 1.0). Argon2: tens of milliseconds, so never
/// under the channel lock (`ServerState::channel_password_attempt`).
pub fn verify_password(attempt: &str, stored: &str) -> bool {
    if let Some(hex) = stored.strip_prefix(SHA256_PREFIX) {
        let digest = Sha256::digest(attempt.as_bytes());
        let mine: String = digest.iter().map(|b| format!("{:02x}", b)).collect();
        return mine.as_bytes().ct_eq(hex.to_ascii_lowercase().as_bytes()).into();
    }
    stored.starts_with(ARGON2_PREFIX) && l4f_accounts::password::verify(attempt, stored).ok
}

/// Load, validate, and prepare persistent channel entries from a JSON file.
///
/// If any plaintext passwords are found, they are hashed and the file is atomically
/// rewritten with `password_hash` fields. If the JSON is invalid or validation fails,
/// an error is returned and the file is **never** modified.
pub fn load_and_prepare_channels(path: &Path) -> anyhow::Result<Vec<ChannelEntry>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read channels file: {}", path.display()))?;

    let mut entries: Vec<ChannelEntry> = serde_json::from_str(&content)
        .with_context(|| format!("invalid JSON in channels file: {}", path.display()))?;

    validate_entries(&entries)?;

    let needs_rewrite = hash_plaintext_passwords(&mut entries)?;

    if needs_rewrite {
        atomic_rewrite(path, &entries)
            .with_context(|| format!("failed to rewrite channels file: {}", path.display()))?;
        info!("hashed plaintext passwords in {}", path.display());
    }

    Ok(entries)
}

pub(crate) fn validate_entries(entries: &[ChannelEntry]) -> anyhow::Result<()> {
    let mut seen_names: HashSet<String> = HashSet::new();
    let mut seen_logs: HashSet<String> = HashSet::new();

    for (i, entry) in entries.iter().enumerate() {
        let name = entry.name.trim();
        if name.is_empty() {
            bail!("channel entry {} has an empty name", i);
        }
        // Reserved for the built-in lobby, which is a voice channel (id 0).
        // A *text* channel called general is a different thing and cannot be
        // confused with it — it is the one `channels.example.json` ships and
        // auto-joins everybody into, and until this distinction existed the
        // server refused to start on its own example file.
        if !entry.text && name.to_lowercase() == "general" {
            bail!("channel entry {} uses reserved name 'General'", i);
        }
        if name.chars().any(crate::tcp::bad_name_char) {
            bail!("channel {:?} contains control or invisible characters", name);
        }
        if name.len() > 64 {
            bail!("channel '{}' name exceeds 64 characters", name);
        }
        // The channel list is one message to every client on every connect,
        // and a message over 64 KiB cannot be framed at all — so it is not
        // sent, and everybody arrives at a server that appears to have no
        // channels. The name is bounded above; the description is the other
        // field big enough to get there on its own.
        if entry.description.len() > 256 {
            bail!("channel '{}' description exceeds 256 characters", name);
        }
        // The same bound a message's own timer gets, and the same reason: a
        // channel advertising a year is advertising "never" in a way that reads
        // like a setting.
        if entry.message_ttl_secs > 30 * 24 * 60 * 60 {
            bail!(
                "channel '{}' message_ttl_secs exceeds 30 days ({})",
                name,
                entry.message_ttl_secs
            );
        }
        let lower = name.to_lowercase();
        if !seen_names.insert(lower) {
            bail!("duplicate channel name: '{}'", name);
        }
        if let Some(uid) = &entry.uid {
            if uid.is_empty() || uid.len() > 64 || !uid.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
                bail!("channel '{}' uid must be 1-64 letters, digits, '-' or '_'", name);
            }
        }
        if !seen_logs.insert(entry.log_conv()) {
            bail!("channel '{}' has the same uid as another channel", name);
        }
        if entry.auto_join && !entry.text {
            bail!("channel '{}' has 'auto_join' without 'text'", name);
        }
        if entry.announce && !entry.text {
            bail!("channel '{}' has 'announce' without 'text'", name);
        }
        if entry.slow_mode_secs > MAX_SLOW_MODE_SECS {
            bail!(
                "channel '{}' slow_mode_secs exceeds 6 hours ({})",
                name,
                entry.slow_mode_secs
            );
        }
        refuse_placeholder(&format!("channel '{name}' password"), entry.password.as_deref())?;
        if entry.text && entry.anonymous {
            // A pseudonym only hides someone who is nowhere else. A text
            // channel is one you are in besides the voice channel you stand
            // in, and the user id is the same in both rosters.
            bail!("channel '{}' cannot be both 'text' and 'anonymous'", name);
        }
        if entry.password.is_some() && entry.password_hash.is_some() {
            bail!(
                "channel '{}' has both 'password' and 'password_hash' — use only one",
                name
            );
        }
        if let Some(ref hash) = entry.password_hash {
            if let Some(hex_part) = hash.strip_prefix(SHA256_PREFIX) {
                if hex_part.len() != 64 || !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
                    bail!("channel '{}' password_hash has invalid SHA-256 hex", name);
                }
            } else if !hash.starts_with(ARGON2_PREFIX) {
                bail!("channel '{}' password_hash must start with '{}' (or '{}', before 1.0)", name, ARGON2_PREFIX, SHA256_PREFIX);
            }
        }
    }

    Ok(())
}

/// Convert any plaintext passwords to hashed form. Returns `true` if any were converted.
fn hash_plaintext_passwords(entries: &mut [ChannelEntry]) -> anyhow::Result<bool> {
    let mut changed = false;
    for entry in entries.iter_mut() {
        if let Some(plaintext) = entry.password.take() {
            entry.password_hash = Some(hash_password(&plaintext)?);
            changed = true;
        }
    }
    Ok(changed)
}

/// Write entries to a temp file then atomically rename over the original.
pub(crate) fn atomic_rewrite(path: &Path, entries: &[ChannelEntry]) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(entries).context("failed to serialize channels")?;

    // Password hashes: for the server's own user only.
    crate::fsutil::atomic_write(path, json.as_bytes(), true).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 1.0 audit H1-16: Argon2id and salted; a `sha256:` hash from before
    /// 1.0 still lets its password in, whatever case its hex is in.
    #[test]
    fn channel_passwords_are_argon2id_and_old_hashes_still_work() {
        let hash = hash_password("secretpass").unwrap();
        assert!(hash.starts_with("$argon2id$"), "{hash}");
        assert_ne!(hash, hash_password("secretpass").unwrap(), "salted");
        assert!(verify_password("secretpass", &hash));
        assert!(!verify_password("secretpas", &hash));
        let old = "sha256:2BB80D537B1DA3E38BD30361AA855686BDE0EACD7162FEF6A25FE97BF527A25B"; // "secret"
        assert!(verify_password("secret", old) && verify_password("secret", &old.to_ascii_lowercase()));
        assert!(!verify_password("secret2", old));
        assert!(!verify_password("secret", "md5:5ebe2294ecd0e0f08eab7690d2a6ee69"));
        assert!(hash_password("").is_err());
    }

    #[test]
    fn validate_empty_name_fails() {
        let entries = vec![ChannelEntry {
            name: "".into(),
            description: String::new(),
            password: None,
            password_hash: None,
            max_users: 0,
            proximity: ProximityMode::Off,
            ..Default::default()
        }];
        assert!(validate_entries(&entries).is_err());
    }

    #[test]
    fn validate_general_name_fails() {
        let entries = vec![ChannelEntry {
            name: "General".into(),
            description: String::new(),
            password: None,
            password_hash: None,
            max_users: 0,
            proximity: ProximityMode::Off,
            ..Default::default()
        }];
        assert!(validate_entries(&entries).is_err());
    }

    #[test]
    fn validate_duplicate_names_fails() {
        let entries = vec![
            ChannelEntry {
                name: "Music".into(),
                description: String::new(),
                password: None,
                password_hash: None,
                max_users: 0,
                proximity: ProximityMode::Off,
                ..Default::default()
            },
            ChannelEntry {
                name: "music".into(),
                description: String::new(),
                password: None,
                password_hash: None,
                max_users: 0,
                proximity: ProximityMode::Off,
                ..Default::default()
            },
        ];
        assert!(validate_entries(&entries).is_err());
    }

    #[test]
    fn validate_both_password_fields_fails() {
        let entries = vec![ChannelEntry {
            name: "Test".into(),
            description: String::new(),
            password: Some("plain".into()),
            password_hash: Some("sha256:abc".into()),
            max_users: 0,
            proximity: ProximityMode::Off,
            ..Default::default()
        }];
        assert!(validate_entries(&entries).is_err());
    }

    #[test]
    fn validate_valid_entries_succeeds() {
        let entries = vec![
            ChannelEntry {
                name: "Music".into(),
                description: "tunes".into(),
                password: None,
                password_hash: None,
                max_users: 10,
                proximity: ProximityMode::TwoD,
                ..Default::default()
            },
            ChannelEntry {
                name: "AFK".into(),
                description: String::new(),
                password: None,
                password_hash: Some(hash_password("test").unwrap()),
                max_users: 0,
                proximity: ProximityMode::Off,
                ..Default::default()
            },
        ];
        assert!(validate_entries(&entries).is_ok());
    }

    #[test]
    fn hash_plaintext_passwords_converts() {
        let mut entries = vec![ChannelEntry {
            name: "Test".into(),
            description: String::new(),
            password: Some("secret".into()),
            password_hash: None,
            max_users: 0,
            proximity: ProximityMode::Off,
            ..Default::default()
        }];
        let changed = hash_plaintext_passwords(&mut entries).unwrap();
        assert!(changed);
        assert!(entries[0].password.is_none());
        assert!(entries[0]
            .password_hash
            .as_ref()
            .unwrap()
            .starts_with("$argon2id$"));
    }

    #[test]
    fn hash_plaintext_passwords_no_change_when_already_hashed() {
        let hash = hash_password("test").unwrap();
        let mut entries = vec![ChannelEntry {
            name: "Test".into(),
            description: String::new(),
            password: None,
            password_hash: Some(hash.clone()),
            max_users: 0,
            proximity: ProximityMode::Off,
            ..Default::default()
        }];
        let changed = hash_plaintext_passwords(&mut entries).unwrap();
        assert!(!changed);
        assert_eq!(entries[0].password_hash.as_ref().unwrap(), &hash);
    }

    #[test]
    fn validate_invalid_hash_format_fails() {
        let entries = vec![ChannelEntry {
            name: "Test".into(),
            description: String::new(),
            password: None,
            password_hash: Some("md5:abcdef".into()),
            max_users: 0,
            proximity: ProximityMode::Off,
            ..Default::default()
        }];
        assert!(validate_entries(&entries).is_err());
    }

    #[test]
    fn validate_empty_array_succeeds() {
        assert!(validate_entries(&[]).is_ok());
    }

    #[test]
    fn proximity_parses_and_defaults_to_off() {
        let entries: Vec<ChannelEntry> = serde_json::from_str(
            r#"[{"name":"Ingame","proximity":"3d"},{"name":"AFK"}]"#,
        )
        .unwrap();
        assert_eq!(entries[0].proximity, ProximityMode::ThreeD);
        assert_eq!(entries[1].proximity, ProximityMode::Off);
        // An unknown mode is a load error, not a silent Off
        assert!(serde_json::from_str::<Vec<ChannelEntry>>(r#"[{"name":"X","proximity":"4d"}]"#).is_err());
    }

    #[test]
    fn channel_options_load_and_default() {
        let entries: Vec<ChannelEntry> = serde_json::from_str(
            r#"[{"name":"Ingame","proximity":"3d","hidden":true,"anonymous":true,
                 "screen_share":false,"hide_members":true},
                {"name":"Music"}]"#,
        )
        .unwrap();
        assert!(entries[0].hidden && entries[0].anonymous && entries[0].hide_members);
        assert!(!entries[0].screen_share);
        // A file written before these options existed must give a plain room
        // that still allows sharing
        assert!(!entries[1].hidden && !entries[1].anonymous && !entries[1].hide_members);
        assert!(entries[1].screen_share);
    }

    #[test]
    fn options_survive_the_password_rewrite() {
        // hash_plaintext_passwords + atomic_rewrite serialize through ChannelEntry,
        // so everything set in the file must still be there afterwards.
        let mut entries = vec![ChannelEntry {
            name: "Ingame".into(),
            description: String::new(),
            password: Some("secret".into()),
            password_hash: None,
            max_users: 0,
            proximity: ProximityMode::TwoD,
            hidden: true,
            anonymous: true,
            screen_share: false,
            hide_members: true,
            routed: true,
            text: false,
            auto_join: false,
            message_ttl_secs: 0,
            announce: false,
            slow_mode_secs: 45,
            nsfw: true,
            uid: Some("ingame-1".into()),
            // What a newer version wrote, which this one must not delete
            extra: serde_json::from_str(r#"{"later_option": {"x": 7}}"#).unwrap(),
        }];
        assert!(hash_plaintext_passwords(&mut entries).unwrap());
        let json = serde_json::to_string(&entries).unwrap();
        let back: Vec<ChannelEntry> = serde_json::from_str(&json).unwrap();
        assert_eq!(back[0].proximity, ProximityMode::TwoD);
        assert!(back[0].hidden && back[0].anonymous && back[0].hide_members && back[0].routed);
        assert!(!back[0].screen_share, "sharing must stay switched off");
        assert!(back[0].nsfw && back[0].slow_mode_secs == 45);
        assert_eq!(back[0].extra["later_option"]["x"], 7, "an unknown key was dropped");
        assert_eq!(back[0].uid.as_deref(), Some("ingame-1"));
    }

    #[test]
    fn a_log_is_named_by_uid_or_else_by_the_channel_name() {
        let named = |json: &str| serde_json::from_str::<Vec<ChannelEntry>>(json).unwrap();
        let a = named(r#"[{"name":"Lounge"}]"#);
        let b = named(r#"[{"name":"lounge "}]"#);
        assert_eq!(a[0].log_conv(), b[0].log_conv(), "case and spaces do not make a new log");
        assert!(a[0].log_conv().starts_with("c:") && a[0].log_conv().len() == 34);
        let kept = named(r#"[{"name":"Renamed","uid":"lounge-1"}]"#);
        assert_eq!(kept[0].log_conv(), "c:lounge-1");
        assert!(validate_entries(&named(r#"[{"name":"a","uid":"x y"}]"#)).is_err(), "uid characters");
        assert!(validate_entries(&named(r#"[{"name":"a","uid":"same"},{"name":"b","uid":"same"}]"#)).is_err(), "uid twice");
    }

    #[test]
    fn text_and_auto_join_load_and_validate() {
        let entries: Vec<ChannelEntry> = serde_json::from_str(
            r#"[{"name":"general","text":true,"auto_join":true},
                {"name":"offtopic","text":true},
                {"name":"Music"}]"#,
        )
        .unwrap();
        assert!(entries[0].text && entries[0].auto_join);
        assert!(entries[1].text && !entries[1].auto_join);
        // A file written before text channels existed gives a voice room
        assert!(!entries[2].text && !entries[2].auto_join);
        assert!(validate_entries(&entries).is_ok());

        // auto_join is meaningless without text, and silently ignoring it
        // would leave an admin wondering why nobody lands there
        let bad: Vec<ChannelEntry> =
            serde_json::from_str(r#"[{"name":"Music","auto_join":true}]"#).unwrap();
        let err = validate_entries(&bad).unwrap_err().to_string();
        assert!(err.contains("auto_join"), "{err}");
    }

    #[test]
    fn a_text_channel_cannot_be_anonymous() {
        // Pseudonyms cannot hide anybody there: the same user id appears in
        // the voice channel the member stands in, under their real name.
        let bad: Vec<ChannelEntry> =
            serde_json::from_str(r#"[{"name":"secrets","text":true,"anonymous":true}]"#).unwrap();
        let err = validate_entries(&bad).unwrap_err().to_string();
        assert!(err.contains("anonymous"), "{err}");
    }

    #[test]
    fn announce_slow_mode_and_nsfw_load_and_validate() {
        let entries: Vec<ChannelEntry> = serde_json::from_str(
            r#"[{"name":"news","text":true,"announce":true,"auto_join":true},
                {"name":"general","text":true,"slow_mode_secs":10},
                {"name":"After Dark","nsfw":true},
                {"name":"Music"}]"#,
        )
        .unwrap();
        assert!(entries[0].announce && entries[1].slow_mode_secs == 10 && entries[2].nsfw);
        assert!(!entries[3].announce && entries[3].slow_mode_secs == 0 && !entries[3].nsfw);
        assert!(validate_entries(&entries).is_ok());

        // A voice room has no posts of its own to keep for its managers
        let bad: Vec<ChannelEntry> =
            serde_json::from_str(r#"[{"name":"Stage","announce":true}]"#).unwrap();
        let err = validate_entries(&bad).unwrap_err().to_string();
        assert!(err.contains("announce"), "{err}");

        let slow = ChannelEntry {
            name: "x".into(),
            text: true,
            slow_mode_secs: MAX_SLOW_MODE_SECS + 1,
            ..Default::default()
        };
        assert!(validate_entries(&[slow]).is_err());
    }

    #[test]
    fn a_preset_placeholder_password_is_refused() {
        // Somebody copied a preset by hand: starting would give every such
        // server the same, published password.
        let entries = vec![ChannelEntry {
            name: "Staff".into(),
            password: Some(PRESET_PLACEHOLDER.into()),
            ..Default::default()
        }];
        let err = validate_entries(&entries).unwrap_err().to_string();
        assert!(err.contains("channels init"), "{err}");
    }

    #[test]
    fn the_example_file_loads() {
        // The server once refused to start on its own example; keep it honest.
        let entries: Vec<ChannelEntry> =
            serde_json::from_str(include_str!("../../../channels.example.json")).unwrap();
        validate_entries(&entries).unwrap();
        assert!(entries.iter().any(|e| e.announce) && entries.iter().any(|e| e.slow_mode_secs > 0));
    }
}
