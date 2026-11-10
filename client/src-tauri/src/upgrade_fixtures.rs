//! What earlier versions left on a desktop still reads in this version, nothing
//! lost: 0.12.0's chat history (archive v4), settings.json and tofu_pins.json;
//! 1.1.0's history (v5), 1.6.0's (v6) and 1.11.0's (v7) with its settings.json.
//! Each tests/fixtures/<version>/ was written once by that version's own code
//! (see the README there) and is never regenerated.

use serde_json::Value;
use std::path::{Path, PathBuf};

const PASSWORD: &str = "correct horse battery staple";

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/0.12.0")
        .join(name)
}

/// As JSON text and back, so an f32 compares as the number it was written as.
fn json<T: serde::Serialize>(v: &T) -> Value {
    serde_json::from_str(&serde_json::to_string(v).unwrap()).unwrap()
}

/// Every key and value of `want` is in `got`; objects may have grown keys.
fn keeps(got: &Value, want: &Value) -> bool {
    match (got, want) {
        (Value::Object(g), Value::Object(w)) => {
            w.iter().all(|(k, v)| g.get(k).is_some_and(|g| keeps(g, v)))
        }
        (Value::Array(g), Value::Array(w)) => {
            g.len() == w.len() && g.iter().zip(w).all(|(g, w)| keeps(g, w))
        }
        _ => got == want,
    }
}

#[test]
fn a_0_12_chat_history_opens_and_keeps_everything_through_a_save() {
    use crate::crypto::{decrypt_archive, encrypt_archive, file_kind, FileKind};
    assert!(matches!(
        file_kind(&fixture("chat_history.bin")),
        FileKind::Ours(4)
    ));
    let want: Value =
        serde_json::from_str(&std::fs::read_to_string(fixture("expected.json")).unwrap()).unwrap();
    let (archive, salt, key, _) = decrypt_archive(
        &std::fs::read(fixture("chat_history.bin")).unwrap(),
        PASSWORD,
    )
    .unwrap();
    assert!(
        keeps(&json(&archive), &want),
        "the 0.12 history lost something on opening"
    );
    // Saved by this version (its own format) and opened again
    let (again, ..) =
        decrypt_archive(&encrypt_archive(&archive, &key, &salt).unwrap(), PASSWORD).unwrap();
    assert!(
        keeps(&json(&again), &want),
        "the 0.12 history lost something on saving"
    );
}

/// 1.0 and 1.1 wrote archive v5; 1.2 reads it and saves v6, nothing lost
#[test]
fn a_1_1_chat_history_opens_and_keeps_everything_through_a_save() {
    use crate::crypto::{decrypt_archive, encrypt_archive, file_kind, FileKind, ARCHIVE_VERSION};
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/1.1.0");
    assert!(matches!(
        file_kind(&path.join("chat_history.bin")),
        FileKind::Ours(5)
    ));
    let want: Value =
        serde_json::from_str(&std::fs::read_to_string(path.join("expected.json")).unwrap())
            .unwrap();
    let (archive, salt, key, version) = decrypt_archive(
        &std::fs::read(path.join("chat_history.bin")).unwrap(),
        PASSWORD,
    )
    .unwrap();
    assert_eq!(version, 5);
    assert!(
        keeps(&json(&archive), &want),
        "the 1.1 history lost something on opening"
    );
    let saved = encrypt_archive(&archive, &key, &salt).unwrap();
    assert_eq!(saved[4], ARCHIVE_VERSION);
    let (again, ..) = decrypt_archive(&saved, PASSWORD).unwrap();
    assert!(
        keeps(&json(&again), &want),
        "the 1.1 history lost something on saving"
    );
}

#[test]
fn a_0_12_settings_file_loads_and_saves_every_key_back() {
    let text = std::fs::read_to_string(fixture("settings.json")).unwrap();
    let want: Value = serde_json::from_str(&text).unwrap();
    let config: crate::config::AppConfig = serde_json::from_str(&text).unwrap();
    assert!(
        keeps(&json(&config), &want),
        "a 0.12 setting is dropped or changed"
    );
}

/// Reading keeps every key, as above. A start then turns the switch off, once.
#[test]
fn a_0_12_settings_file_goes_off_once_through_load() {
    let text = std::fs::read_to_string(fixture("settings.json")).unwrap();
    let want: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(want["share_channel_history"], true, "what 0.12 wrote");
    let dir = std::env::temp_dir().join(format!("voipc-fixture-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("settings.json");
    std::fs::write(&path, &text).unwrap();
    let config = crate::config::load_config_at(&path);
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(!config.share_channel_history && config.share_off_notice);
    assert!(config.share_off_once);
}

#[test]
fn a_0_12_pin_file_keeps_every_pin() {
    let pins =
        crate::transport::tofu_parse(&std::fs::read_to_string(fixture("tofu_pins.json")).unwrap())
            .unwrap();
    assert_eq!(pins.get("voice.example.org:9987"), Some(&vec![0xab; 32]));
    assert_eq!(pins.get("192.168.1.20:9987"), Some(&vec![0x01; 32]));
}

/// A history `version` left in tests/fixtures/`dir`: it opens with everything
/// in its expected.json, and a save in this version's format keeps all of it.
fn history_keeps(dir: &str, version: u8) {
    use crate::crypto::{decrypt_archive, encrypt_archive, file_kind, FileKind, ARCHIVE_VERSION};
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(dir);
    assert_eq!(
        file_kind(&path.join("chat_history.bin")),
        FileKind::Ours(version)
    );
    let want: Value =
        serde_json::from_str(&std::fs::read_to_string(path.join("expected.json")).unwrap())
            .unwrap();
    let (archive, salt, key, read) = decrypt_archive(
        &std::fs::read(path.join("chat_history.bin")).unwrap(),
        PASSWORD,
    )
    .unwrap();
    assert_eq!(read, version);
    assert!(
        keeps(&json(&archive), &want),
        "the {dir} history lost something on opening"
    );
    let saved = encrypt_archive(&archive, &key, &salt).unwrap();
    assert_eq!(saved[4], ARCHIVE_VERSION);
    let (again, ..) = decrypt_archive(&saved, PASSWORD).unwrap();
    assert!(
        keeps(&json(&again), &want),
        "the {dir} history lost something on saving"
    );
}

/// 1.3.1 to 1.10 wrote archive v6 (`extra` on a message); 1.6.0 is the last
/// final release among them, so most desktops upgrade from this file.
#[test]
fn a_1_6_chat_history_opens_and_keeps_everything_through_a_save() {
    history_keeps("1.6.0", 6);
}

/// 1.11 writes v7 (the bucket lists a device has named, protocol 21), with
/// every `extra` field the 1.11 front end keeps and one it does not know.
#[test]
fn a_1_11_chat_history_opens_and_keeps_everything_through_a_save() {
    history_keeps("1.11.0", 7);
}

/// Every key 1.11 writes, none at its default: read, and loaded through a
/// start (which changes nothing here), all of them stay, and a save (the same
/// serde_json of the config) is allowed and writes them back.
#[test]
fn a_1_11_settings_file_loads_and_saves_every_key_back() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/1.11.0/settings.json");
    let text = std::fs::read_to_string(&fixture).unwrap();
    let want: Value = serde_json::from_str(&text).unwrap();
    let config: crate::config::AppConfig = serde_json::from_str(&text).unwrap();
    assert!(
        keeps(&json(&config), &want),
        "a 1.11 setting is dropped or changed on reading"
    );
    let dir = std::env::temp_dir().join(format!("voipc-fixture-1-11-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("settings.json");
    std::fs::write(&path, &text).unwrap();
    let loaded = crate::config::load_config_at(&path);
    let after = std::fs::read_to_string(&path).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    assert_eq!(after, text, "a start rewrote the 1.11 settings");
    assert!(
        loaded.format <= crate::config::SETTINGS_FORMAT,
        "saving is allowed"
    );
    assert!(
        keeps(&json(&loaded), &want),
        "a 1.11 setting is changed by a start, or dropped on saving"
    );
}
