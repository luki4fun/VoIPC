use serde::{Deserialize, Serialize};
use std::path::Path;

/// Runtime server settings, loaded from a JSON file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSettings {
    /// Timeout in seconds before an empty channel is auto-deleted.
    #[serde(default = "default_empty_channel_timeout")]
    pub empty_channel_timeout_secs: u64,

    /// Maximum number of user-created channels.
    #[serde(default = "default_max_channels")]
    pub max_channels: u32,

    /// Maximum channel name length.
    #[serde(default = "default_max_channel_name_len")]
    pub max_channel_name_len: usize,

    /// Whether channels may use proximity (positional) audio at all. When
    /// false, every channel is served as `off`, requests to enable it are
    /// refused, and position beacons are not relayed.
    #[serde(default = "default_proximity_enabled")]
    pub proximity_enabled: bool,

    /// Bearer token a **game server** presents to `POST /game/v1/routes`,
    /// which tells the relay who may hear whom in a channel whose `routed`
    /// flag is on. Unset (the default) means the endpoint answers 404 and
    /// this server has no idea games exist.
    ///
    /// Not the admin token, and deliberately much weaker: it can narrow who
    /// hears whom inside one routed channel, and nothing else. No session
    /// list, no names, no kick, no bans.
    #[serde(default)]
    pub game_token: Option<String>,

    /// What this server calls itself, on a relay without accounts. On one with
    /// them an admin sets it in the app, and that goes first.
    #[serde(default)]
    pub server_name: Option<String>,
    #[serde(default)]
    pub server_description: Option<String>,

    /// Minutes a new member waits before they may speak, post or write directly,
    /// counted from the account's creation or the guest's first connection from
    /// that address. 0 (the default): no wait. Restart to change.
    #[serde(default)]
    pub new_member_wait_mins: u32,
}

fn default_empty_channel_timeout() -> u64 {
    300
}
fn default_max_channels() -> u32 {
    50
}
fn default_max_channel_name_len() -> usize {
    32
}
fn default_proximity_enabled() -> bool {
    true
}

/// A week: past that an account is hardly new.
pub const MAX_NEW_MEMBER_WAIT_MINS: u32 = 10_080;

impl Default for ServerSettings {
    fn default() -> Self {
        Self {
            empty_channel_timeout_secs: default_empty_channel_timeout(),
            max_channels: default_max_channels(),
            max_channel_name_len: default_max_channel_name_len(),
            proximity_enabled: default_proximity_enabled(),
            game_token: None,
            server_name: None,
            server_description: None,
            new_member_wait_mins: 0,
        }
    }
}

impl ServerSettings {
    pub fn load_from_file(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let mut settings: Self = serde_json::from_str(&content)?;
        settings.normalise();
        // A preset's stand-in, copied by hand: as a token it would be the same
        // published string on every server that did so.
        crate::channels::refuse_placeholder("game_token", settings.game_token.as_deref())?;
        if !(1..=64).contains(&settings.max_channel_name_len) {
            anyhow::bail!("max_channel_name_len must be between 1 and 64");
        }
        if settings.new_member_wait_mins > MAX_NEW_MEMBER_WAIT_MINS {
            anyhow::bail!(
                "new_member_wait_mins must be at most {MAX_NEW_MEMBER_WAIT_MINS} (a week)"
            );
        }
        if settings
            .game_token
            .as_ref()
            .is_some_and(|t| t.chars().count() < crate::state::MIN_TOKEN_LEN)
        {
            anyhow::bail!(
                "game_token is shorter than {} characters, which can be guessed: set a long random one (`openssl rand -hex 32`)",
                crate::state::MIN_TOKEN_LEN
            );
        }
        Ok(settings)
    }

    /// An empty `game_token` is no token, exactly as it is for the admin one.
    ///
    /// Without this, `""` in a settings file made `POST /game/v1/routes` answer
    /// a request carrying *no* `Authorization` header at all: the comparison is
    /// "" against "", which passes. Anybody who could reach the port could then
    /// post an empty table and silence a routed channel, invisibly, because a
    /// live table that lists nobody means nobody hears anybody.
    pub fn normalise(&mut self) {
        if self
            .game_token
            .as_deref()
            .is_some_and(|t| t.trim().is_empty())
        {
            self.game_token = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_settings_values() {
        let settings = ServerSettings::default();
        assert_eq!(settings.empty_channel_timeout_secs, 300);
        assert_eq!(settings.max_channels, 50);
        assert_eq!(settings.max_channel_name_len, 32);
        assert!(settings.proximity_enabled);
    }

    #[test]
    fn proximity_can_be_disabled() {
        let settings: ServerSettings =
            serde_json::from_str(r#"{"proximity_enabled": false}"#).unwrap();
        assert!(!settings.proximity_enabled);
        // A pre-0.7 settings file keeps proximity available
        let old: ServerSettings = serde_json::from_str(r#"{"max_channels": 10}"#).unwrap();
        assert!(old.proximity_enabled);
    }

    #[test]
    fn an_empty_game_token_is_no_game_token() {
        // "" versus a request with no Authorization header compares "" to "",
        // which passes — so a placeholder in a settings file would have turned
        // the routing endpoint into an unauthenticated one.
        let mut settings: ServerSettings =
            serde_json::from_str(r#"{"game_token": "   "}"#).unwrap();
        settings.normalise();
        assert!(
            settings.game_token.is_none(),
            "an empty token stayed a token"
        );

        let mut real: ServerSettings = serde_json::from_str(r#"{"game_token": "s3cret"}"#).unwrap();
        real.normalise();
        assert_eq!(real.game_token.as_deref(), Some("s3cret"));
    }

    #[test]
    fn settings_json_deserialization() {
        let json = r#"{
            "empty_channel_timeout_secs": 600,
            "max_channels": 100,
            "max_channel_name_len": 64
        }"#;
        let settings: ServerSettings = serde_json::from_str(json).unwrap();
        assert_eq!(settings.empty_channel_timeout_secs, 600);
        assert_eq!(settings.max_channels, 100);
        assert_eq!(settings.max_channel_name_len, 64);
    }

    #[test]
    fn a_preset_placeholder_game_token_is_refused() {
        let dir = std::env::temp_dir().join(format!("voipc-settings-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("server_settings.json");
        std::fs::write(&path, r#"{"game_token": "<generate>"}"#).unwrap();
        let err = ServerSettings::load_from_file(&path)
            .unwrap_err()
            .to_string();
        assert!(err.contains("channels init"), "{err}");
        // H1-09: a short token is refused at the start, however real
        std::fs::write(&path, r#"{"game_token": "a-real-token"}"#).unwrap();
        assert!(ServerSettings::load_from_file(&path)
            .unwrap_err()
            .to_string()
            .contains("shorter than 16"));
        std::fs::write(&path, r#"{"game_token": "a-real-token-of-length"}"#).unwrap();
        assert!(ServerSettings::load_from_file(&path).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn new_member_wait_mins_over_the_limit_refuses_to_start() {
        let dir = std::env::temp_dir().join(format!("voipc-wait-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("server_settings.json");
        std::fs::write(&path, r#"{"new_member_wait_mins": 10081}"#).unwrap();
        let err = ServerSettings::load_from_file(&path)
            .unwrap_err()
            .to_string();
        assert!(err.contains("new_member_wait_mins"), "{err}");
        std::fs::write(&path, r#"{"new_member_wait_mins": 10080}"#).unwrap();
        assert_eq!(
            ServerSettings::load_from_file(&path)
                .unwrap()
                .new_member_wait_mins,
            10_080
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_old_settings_file_defaults_to_no_wait() {
        let old: ServerSettings = serde_json::from_str(r#"{"max_channels": 10}"#).unwrap();
        assert_eq!(old.new_member_wait_mins, 0);
    }
}
