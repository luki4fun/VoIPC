//! What a 0.12.0 relay's operator has on disk still loads in this version:
//! every preset's channels.json and server_settings.json, written by 0.12.0's
//! own `channels init`, and its documented server.toml. The files in
//! tests/fixtures/0.12.0/ were written once and are never regenerated (see the
//! README there). The accounts database is checked in tcp.rs
//! (`a_0_12_accounts_database_opens_signs_in_and_keeps_its_messages`).

use crate::channels::{load_and_prepare_channels, verify_password};
use crate::config::ServerConfig;
use crate::settings::ServerSettings;
use std::path::{Path, PathBuf};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/0.12.0")
}

/// The passwords `channels init` printed once ("name   password" lines after
/// the "Passwords" heading); the file keeps only their hashes.
fn printed_passwords(init: &str) -> Vec<(String, String)> {
    init.lines()
        .skip_while(|l| !l.starts_with("Passwords"))
        .skip(1)
        .take_while(|l| !l.trim().is_empty())
        .filter_map(|l| {
            let (name, password) = l.trim().rsplit_once(' ')?;
            Some((name.trim().to_string(), password.to_string()))
        })
        .collect()
}

#[test]
fn every_0_12_preset_still_loads_and_its_passwords_still_open() {
    let mut presets = 0;
    for dir in std::fs::read_dir(fixtures().join("presets")).unwrap().flatten() {
        let dir = dir.path();
        // A copy: loading may rewrite the file
        let tmp = std::env::temp_dir().join(format!("voipc-preset-{}.json", hex::encode(rand::random::<[u8; 8]>())));
        std::fs::copy(dir.join("channels.json"), &tmp).unwrap();
        let entries = load_and_prepare_channels(&tmp).unwrap_or_else(|e| panic!("{}: {e:#}", dir.display()));
        let _ = std::fs::remove_file(&tmp);
        assert!(!entries.is_empty(), "{}", dir.display());
        for (name, password) in printed_passwords(&std::fs::read_to_string(dir.join("init.txt")).unwrap()) {
            let entry = entries.iter().find(|e| e.name == name).unwrap_or_else(|| panic!("{name} in {}", dir.display()));
            let stored = entry.password_hash.as_deref().expect("kept as a hash");
            assert!(verify_password(&password, stored), "{name} in {}", dir.display());
        }
        if dir.join("server_settings.json").exists() {
            ServerSettings::load_from_file(&dir.join("server_settings.json")).unwrap_or_else(|e| panic!("{}: {e:#}", dir.display()));
        }
        presets += 1;
    }
    assert_eq!(presets, 11, "all of 0.12.0's presets");
}

#[test]
fn the_0_12_documented_server_toml_still_loads() {
    let text = std::fs::read_to_string(fixtures().join("server.toml")).unwrap();
    let config: ServerConfig = toml::from_str(&text).unwrap();
    config.validate().unwrap();
    assert_eq!(config.accounts.retention_days, 365);
}
