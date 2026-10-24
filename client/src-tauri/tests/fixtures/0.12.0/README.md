# 0.12.0 desktop data (upgrade fixtures)

Written on 2026-10-23 by VoIPC **0.12.0's own code** (`49bf256`, a `git archive` copy), never by a
later version. They are never regenerated. `src/upgrade_fixtures.rs` checks that this version
opens them without losing anything.

| File | Written by (0.12.0) | Content |
|---|---|---|
| `chat_history.bin` | `crypto::encrypt_archive` | archive v4: two channel messages (one with an account, a timer and a history marker), a DM, a cleared mark, a remembered device, log memory |
| `expected.json` | `serde_json` of that `ChatArchive` | what the archive must still contain |
| `settings.json` | `config::save_config` | servers, `relay_ids`, `ui_prefs`, voice settings |
| `tofu_pins.json` | `transport::tofu_save_to_disk` | two pins |

The archive password is `correct horse battery staple`. The browser's log-memory JSON that the
same run wrote is `crates/voipc-crypto/tests/fixtures/0.12.0/log_memory.json`.

## How they were made

The test below was appended to 0.12.0's `client/src-tauri/src/transport.rs`. It ran in that tree
with `--ignored --exact transport::upgrade_fixture_writer::write_upgrade_fixtures`, with
`VOIPC_FIXTURE_DIR` pointing here. It cannot compile against later versions, so it is kept as text.

```rust
/// Track C (1.0 upgrade fixtures): what 0.12.0 writes on a desktop, written by
/// its own code into $VOIPC_FIXTURE_DIR. Run alone, once, with --ignored.
#[cfg(test)]
mod upgrade_fixture_writer {
    use std::collections::HashMap;

    #[test]
    #[ignore]
    fn write_upgrade_fixtures() {
        let out = std::path::PathBuf::from(std::env::var("VOIPC_FIXTURE_DIR").expect("VOIPC_FIXTURE_DIR"));
        std::fs::create_dir_all(&out).unwrap();
        crate::config::init_data_dir(out.clone());

        // settings.json, by save_config
        let mut cfg = crate::config::AppConfig::default();
        cfg.input_device = Some("USB Mic".into());
        cfg.volume = 0.8;
        cfg.voice_mode = "vad".into();
        cfg.vad_threshold_db = -42.5;
        cfg.ptt_key = "KeyV".into();
        cfg.last_host = Some("voice.example.org".into());
        cfg.last_port = Some(9987);
        cfg.last_username = Some("luki".into());
        cfg.saved_servers = vec![crate::config::SavedServer {
            name: "Home".into(),
            host: "voice.example.org".into(),
            port: 9987,
            username: "luki".into(),
            accept_self_signed: true,
            account: true,
        }];
        cfg.sdk_allowed_origins = vec!["null".into()];
        cfg.ui_prefs = serde_json::json!({ "layout": "modern", "zoom": 1.1, "panel": { "left": 240 } });
        cfg.chat_history_path = Some("/home/luki/voipc/chat_history.bin".into());
        cfg.relay_ids.insert("voice.example.org:9987".into(), "5a".repeat(16));
        crate::config::save_config(&cfg).unwrap();

        // tofu_pins.json, by tofu_save_to_disk
        let pins: HashMap<String, Vec<u8>> = [
            ("voice.example.org:9987".to_string(), vec![0xab; 32]),
            ("192.168.1.20:9987".to_string(), vec![0x01; 32]),
        ]
        .into_iter()
        .collect();
        super::tofu_save_to_disk(&pins);

        // chat_history.bin (archive v4), by encrypt_archive
        use crate::crypto::{ChatArchive, ChatMessage, DeviceRecord};
        let msg = |user_id, username: &str, content: &str, timestamp, kind: Option<&str>, account: Option<&str>| ChatMessage {
            user_id,
            username: username.into(),
            content: content.into(),
            timestamp,
            kind: kind.map(Into::into),
            id: Some(format!("m{timestamp}")),
            expires_at: if timestamp % 2 == 0 { Some(4_102_444_800_000) } else { None },
            account: account.map(Into::into),
        };
        let mut memory = voipc_crypto::sync::LogMemory::default();
        memory.cursors.insert("d:0101".into(), 5);
        memory.readers.insert("c:abcd".into(), vec![[2; 16]]);
        let mut archive = ChatArchive::default();
        archive.channels.insert(
            "voice.example.org:9987/general".into(),
            vec![
                msg(1, "luki", "hello channel", 1_760_000_000_001, None, Some(&"5b".repeat(16))),
                msg(2, "guest", "", 1_760_000_000_002, Some("history-marker"), None),
            ],
        );
        archive.dms.insert("voice.example.org:9987/anna".into(), vec![msg(3, "anna", "hi, a DM", 1_760_000_000_004, None, None)]);
        archive.cleared.insert("voice.example.org:9987/old".into(), 1_750_000_000_000);
        archive.devices.push(DeviceRecord {
            server: "voice.example.org:9987".into(),
            relay_id: [0x5a; 16],
            name: "luki".into(),
            device_id: [0x0d; 16],
            device_key: vec![0x30; 85],
            dek: [0x0e; 32],
        });
        archive.cursors.insert(format!("{}|luki", "5a".repeat(16)), memory.clone());
        let password = "correct horse battery staple";
        let salt = crate::crypto::generate_salt();
        let key = crate::crypto::derive_key(password, &salt);
        std::fs::write(out.join("chat_history.bin"), crate::crypto::encrypt_archive(&archive, &key, &salt).unwrap()).unwrap();
        std::fs::write(out.join("expected.json"), serde_json::to_string_pretty(&archive).unwrap()).unwrap();

        // The browser's voipc.cursors.* value: the same LogMemory as JSON
        std::fs::write(out.join("log_memory.json"), serde_json::to_string(&memory).unwrap()).unwrap();
    }
}
```
