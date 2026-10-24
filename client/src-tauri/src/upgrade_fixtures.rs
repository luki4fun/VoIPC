//! What 0.12.0 left on a desktop still reads in this version, nothing lost:
//! the chat history (archive v4), settings.json and tofu_pins.json. The files
//! in tests/fixtures/0.12.0/ were written once by 0.12.0's own code (see the
//! README there) and are never regenerated.

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

#[test]
fn a_0_12_pin_file_keeps_every_pin() {
    let pins =
        crate::transport::tofu_parse(&std::fs::read_to_string(fixture("tofu_pins.json")).unwrap())
            .unwrap();
    assert_eq!(pins.get("voice.example.org:9987"), Some(&vec![0xab; 32]));
    assert_eq!(pins.get("192.168.1.20:9987"), Some(&vec![0x01; 32]));
}
