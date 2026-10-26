# 1.1.0 desktop chat history (upgrade fixture)

Written on 2026-10-26 by the archive code of VoIPC **1.1.0** (`4660a9a`): `crypto::encrypt_archive`
writing archive **v5**, run in the 1.2.0 working tree just before the v6 change, when
`client/src-tauri/src/crypto.rs` still differed from `4660a9a` only in one re-export line. It is
never regenerated. `src/upgrade_fixtures.rs` checks that this version opens it without losing
anything, and that a save writes it in the current format.

| File | Written by (1.1.0) | Content |
|---|---|---|
| `chat_history.bin` | `crypto::encrypt_archive` | archive v5: three channel messages (one with an account and a timer, a history marker, a shared one), a DM, a cleared mark, a remembered device, log memory with a vault generation |
| `expected.json` | `serde_json` of that `ChatArchive` | what the archive must still contain |

The archive password is `correct horse battery staple`.

## How it was made

This test was appended to `src/upgrade_fixtures.rs` and run once with
`VOIPC_FIXTURE_DIR=$PWD/tests/fixtures/1.1.0 cargo test --lib -- --ignored --exact upgrade_fixtures::write_1_1_fixture`,
then removed. It cannot compile against v6 (`ChatMessage` gained a field), so it is kept as text.

```rust
#[test]
#[ignore]
fn write_1_1_fixture() {
    use crate::crypto::{ChatArchive, ChatMessage, DeviceRecord};
    let out = std::path::PathBuf::from(std::env::var("VOIPC_FIXTURE_DIR").expect("VOIPC_FIXTURE_DIR"));
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
    memory.vault_gens.insert("item.pins".into(), 7);
    let mut archive = ChatArchive::default();
    archive.channels.insert(
        "voice.example.org:9987/general".into(),
        vec![
            msg(1, "luki", "hello channel, **not markdown yet**", 1_761_000_000_001, None, Some(&"5b".repeat(16))),
            msg(2, "guest#4821", "", 1_761_000_000_002, Some("history-marker"), None),
            msg(4, "anna", "second-hand", 1_761_000_000_003, Some("shared"), None),
        ],
    );
    archive.dms.insert("voice.example.org:9987/anna".into(), vec![msg(3, "anna", "hi, a DM", 1_761_000_000_004, None, None)]);
    archive.cleared.insert("voice.example.org:9987/old".into(), 1_750_000_000_000);
    archive.devices.push(DeviceRecord {
        server: "voice.example.org:9987".into(),
        relay_id: [0x5a; 16],
        name: "luki".into(),
        device_id: [0x0d; 16],
        device_key: vec![0x30; 85],
        dek: [0x0e; 32],
    });
    archive.cursors.insert(format!("{}|luki", "5a".repeat(16)), memory);
    let password = "correct horse battery staple";
    let salt = crate::crypto::generate_salt();
    let key = crate::crypto::derive_key(password, &salt);
    std::fs::write(out.join("chat_history.bin"), crate::crypto::encrypt_archive(&archive, &key, &salt).unwrap()).unwrap();
    std::fs::write(out.join("expected.json"), serde_json::to_string_pretty(&archive).unwrap()).unwrap();
}
```
