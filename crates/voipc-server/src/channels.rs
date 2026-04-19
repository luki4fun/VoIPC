use std::collections::HashSet;
use std::path::Path;

use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::info;

const SHA256_PREFIX: &str = "sha256:";

/// A single channel entry as read from channels.json.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelEntry {
    pub name: String,

    #[serde(default)]
    pub description: String,

    /// Plaintext password — hashed to `password_hash` on first load and removed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,

    /// SHA-256 hash of the password: `"sha256:<64 hex chars>"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_hash: Option<String>,

    /// Maximum users (0 = unlimited).
    #[serde(default)]
    pub max_users: u32,
}

/// Hash a plaintext password to `"sha256:<64 hex chars>"`.
pub fn hash_password(plaintext: &str) -> String {
    let digest = Sha256::digest(plaintext.as_bytes());
    let hex: String = digest.iter().map(|b| format!("{:02x}", b)).collect();
    format!("{}{}", SHA256_PREFIX, hex)
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

    let needs_rewrite = hash_plaintext_passwords(&mut entries);

    if needs_rewrite {
        atomic_rewrite(path, &entries)
            .with_context(|| format!("failed to rewrite channels file: {}", path.display()))?;
        info!("hashed plaintext passwords in {}", path.display());
    }

    Ok(entries)
}

fn validate_entries(entries: &[ChannelEntry]) -> anyhow::Result<()> {
    let mut seen_names: HashSet<String> = HashSet::new();

    for (i, entry) in entries.iter().enumerate() {
        let name = entry.name.trim();
        if name.is_empty() {
            bail!("channel entry {} has an empty name", i);
        }
        if name.to_lowercase() == "general" {
            bail!("channel entry {} uses reserved name 'General'", i);
        }
        if name.chars().any(|c| c.is_control()) {
            bail!("channel '{}' contains control characters", name);
        }
        if name.len() > 64 {
            bail!("channel '{}' name exceeds 64 characters", name);
        }
        let lower = name.to_lowercase();
        if !seen_names.insert(lower) {
            bail!("duplicate channel name: '{}'", name);
        }
        if entry.password.is_some() && entry.password_hash.is_some() {
            bail!(
                "channel '{}' has both 'password' and 'password_hash' — use only one",
                name
            );
        }
        if let Some(ref hash) = entry.password_hash {
            if !hash.starts_with(SHA256_PREFIX) {
                bail!(
                    "channel '{}' password_hash must start with '{}'",
                    name,
                    SHA256_PREFIX
                );
            }
            let hex_part = &hash[SHA256_PREFIX.len()..];
            if hex_part.len() != 64 || !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
                bail!("channel '{}' password_hash has invalid SHA-256 hex", name);
            }
        }
    }

    Ok(())
}

/// Convert any plaintext passwords to hashed form. Returns `true` if any were converted.
fn hash_plaintext_passwords(entries: &mut [ChannelEntry]) -> bool {
    let mut changed = false;
    for entry in entries.iter_mut() {
        if let Some(plaintext) = entry.password.take() {
            entry.password_hash = Some(hash_password(&plaintext));
            changed = true;
        }
    }
    changed
}

/// Write entries to a temp file then atomically rename over the original.
fn atomic_rewrite(path: &Path, entries: &[ChannelEntry]) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(entries).context("failed to serialize channels")?;

    let tmp_path = path.with_extension("json.tmp");
    std::fs::write(&tmp_path, json.as_bytes())
        .with_context(|| format!("failed to write temp file: {}", tmp_path.display()))?;
    std::fs::rename(&tmp_path, path)
        .with_context(|| format!("failed to rename temp file to {}", path.display()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_password_produces_correct_format() {
        let hash = hash_password("secretpass");
        assert!(hash.starts_with("sha256:"));
        assert_eq!(hash.len(), 7 + 64); // "sha256:" + 64 hex chars
    }

    #[test]
    fn hash_password_is_deterministic() {
        assert_eq!(hash_password("test"), hash_password("test"));
    }

    #[test]
    fn validate_empty_name_fails() {
        let entries = vec![ChannelEntry {
            name: "".into(),
            description: String::new(),
            password: None,
            password_hash: None,
            max_users: 0,
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
            },
            ChannelEntry {
                name: "music".into(),
                description: String::new(),
                password: None,
                password_hash: None,
                max_users: 0,
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
            },
            ChannelEntry {
                name: "AFK".into(),
                description: String::new(),
                password: None,
                password_hash: Some(hash_password("test")),
                max_users: 0,
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
        }];
        let changed = hash_plaintext_passwords(&mut entries);
        assert!(changed);
        assert!(entries[0].password.is_none());
        assert!(entries[0]
            .password_hash
            .as_ref()
            .unwrap()
            .starts_with("sha256:"));
    }

    #[test]
    fn hash_plaintext_passwords_no_change_when_already_hashed() {
        let hash = hash_password("test");
        let mut entries = vec![ChannelEntry {
            name: "Test".into(),
            description: String::new(),
            password: None,
            password_hash: Some(hash.clone()),
            max_users: 0,
        }];
        let changed = hash_plaintext_passwords(&mut entries);
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
        }];
        assert!(validate_entries(&entries).is_err());
    }

    #[test]
    fn validate_empty_array_succeeds() {
        assert!(validate_entries(&[]).is_ok());
    }
}
