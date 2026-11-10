# 1.11.0 desktop data (upgrade fixtures)

Written on 2026-11-10 by VoIPC **1.11.0's own code**: the working tree at `4c5334c` (tag
`v1.11.0-rc.2`), whose code 1.11.0 is; only tests and docs differed. They are never regenerated.
`src/upgrade_fixtures.rs` checks that this version opens them without losing anything, and that a
save writes them back whole; `client/src/lib/archive-fixtures.test.ts` checks that the front end
reads every field the history's `extra` holds.

| File | Written by (1.11.0) | Content |
|---|---|---|
| `chat_history.bin` | `crypto::encrypt_archive` | archive **v7**: nine channel messages (a thread's start, an edited answer with reactions, a pin and the power to call on everybody, a file with a preview, a report, one a moderator hid with a ban, one holding a field from a later version, a history marker, a shared one, a deleted one), two DMs (one a reply with a file), a cleared mark, a remembered device, log memory with vault generations and the bucket lists named (`named`, new in v7) |
| `expected.json` | `serde_json` of that `ChatArchive` | what the archive must still contain |
| `settings.json` | `config::save_config` | every key of `AppConfig`, none at its default (`share_off_once`, `file_cache_mb`, `check_updates`, `format` are new since 0.12) |

The archive password is `correct horse battery staple`. The browser's log memory and an account's
vault from the same release are in `crates/voipc-crypto/tests/fixtures/1.11.0/`.

## How they were made

The `extra` strings are what 1.11's front end writes (`chat-rules.ts` `toArchived`), made by this
script, run from `client/` with `node --experimental-strip-types` into `extra.json`:

```ts
// One-off: the `extra` strings 1.11's front end writes into the desktop archive
// (chat-rules.ts toArchived), for the 1.11.0 history fixture.
import assert from "node:assert/strict";
import { toArchived, fromArchived } from "../../../client/src/lib/chat-rules.ts";

const T = 1_762_000_000_000;
const acct = (b: string) => b.repeat(16);
const px = Buffer.from(Array.from({ length: 768 }, (_, i) => (i * 7) % 256)).toString("base64");
const base = (o: Record<string, unknown>) => ({ user_id: 1, username: "luki", content: "", ...o });
const msgs: Record<string, any> = {
  replied: base({ content: "an answer in a thread, **edited**", timestamp: T + 1, id: "m2", account: acct("5b"),
    reply_to: "m1", thread: "m1", edited_at: T + 60_000,
    reactions: [{ emoji: "👍", by: [{ key: acct("5b"), name: "luki", on: true, at: T + 2 }, { key: acct("6c"), name: "anna", on: true, at: T + 3 }] }],
    pin: { on: true, at: T + 4, by: "anna" }, power: true }),
  file: base({ content: "the caption", timestamp: T + 5, id: "m3", account: acct("5b"),
    file: { hash: "ab".repeat(32), key: "cd".repeat(32), size: 123456, z: false, name: "holiday.png", mime: "image/png", w: 640, h: 480, px } }),
  report: base({ user_id: 2, username: "anna", content: "the reported words", timestamp: T + 6, id: "m4", account: acct("6c"),
    fwd: { name: "bert", at: T - 1000, report: { channel: "general", id: "m0", why: "spam", by: "anna" } } }),
  hidden: base({ user_id: 3, username: "bert", content: "collapsed by a moderator", timestamp: T + 7, id: "m5",
    hide: { on: true, at: T + 8, by: "anna", ban: true } }),
  future: base({ content: "a later 1.x kept something here", timestamp: T + 9, id: "m6", extra_kept: JSON.stringify({ later_field: { a: 1 } }) }),
  dm: base({ user_id: 2, username: "anna", content: "a DM answer with a file", timestamp: T + 10, id: "d2", account: acct("6c"), reply_to: "d1",
    file: { hash: "ef".repeat(32), key: "01".repeat(32), size: 42, z: true, name: "notes.txt", mime: "text/plain" } }),
};
const out: Record<string, string> = {};
for (const [k, m] of Object.entries(msgs)) {
  const a = toArchived(m);
  assert.ok(a.extra, k);
  assert.deepEqual(fromArchived(a), m, k);
  out[k] = a.extra!;
}
console.log(JSON.stringify(out, null, 2));
```

Then this test was appended to `src/upgrade_fixtures.rs` and run once with
`VOIPC_FIXTURE_DIR=$PWD/tests/fixtures/1.11.0 VOIPC_FIXTURE_EXTRA=<extra.json> cargo test -p voipc-client --lib -- --ignored --exact upgrade_fixtures::write_1_11_fixture`,
then removed:

```rust
#[test]
#[ignore]
fn write_1_11_fixture() {
    use crate::crypto::{ChatArchive, ChatMessage, DeviceRecord};
    let out = PathBuf::from(std::env::var("VOIPC_FIXTURE_DIR").expect("VOIPC_FIXTURE_DIR"));
    let extra: std::collections::HashMap<String, String> = serde_json::from_str(
        &std::fs::read_to_string(std::env::var("VOIPC_FIXTURE_EXTRA").expect("VOIPC_FIXTURE_EXTRA"))
            .unwrap(),
    )
    .unwrap();
    std::fs::create_dir_all(&out).unwrap();
    crate::config::init_data_dir(out.clone());

    // settings.json, by save_config: every key, none at its default
    let mut cfg = crate::config::AppConfig::default();
    cfg.input_device = Some("USB Mic".into());
    cfg.output_device = Some("Headset".into());
    cfg.volume = 0.8;
    cfg.input_gain = 1.25;
    cfg.noise_suppression = false;
    cfg.voice_mode = "vad".into();
    cfg.vad_threshold_db = -42.5;
    cfg.ptt_key = "KeyV".into();
    cfg.ptt_hold_mode = false;
    cfg.mute_key = Some("KeyM".into());
    cfg.deafen_key = Some("KeyN".into());
    cfg.muted = true;
    cfg.deafened = true;
    cfg.remember_connection = true;
    cfg.last_host = Some("voice.example.org".into());
    cfg.last_port = Some(9987);
    cfg.last_username = Some("luki#4821".into());
    cfg.last_accept_self_signed = Some(true);
    let server = |name: &str, host: &str, account: bool| crate::config::SavedServer {
        name: name.into(),
        host: host.into(),
        port: 9987,
        username: "luki".into(),
        accept_self_signed: !account,
        account,
    };
    cfg.saved_servers = vec![
        server("Home", "voice.example.org", true),
        server("LAN", "192.168.1.20", false),
    ];
    cfg.open_servers = vec![server("Home", "voice.example.org", true)];
    cfg.screen_share_codec = "av1".into();
    cfg.spatial_audio = true;
    cfg.screen_audio_spatial = true;
    cfg.mic_effect = "radio".into();
    cfg.mic_muffle = 30;
    cfg.mic_reverb = 40;
    cfg.mic_water = 50;
    cfg.audio_setup_version = 3;
    cfg.sdk_enabled = true;
    cfg.sdk_port = 39988;
    cfg.sdk_allowed_origins = vec!["null".into(), "https://game.example.org".into()];
    cfg.mumblelink_enabled = true;
    cfg.sdk_beacon_allowed = true;
    cfg.sdk_transmit_allowed = true;
    cfg.sounds.poke.enabled = false;
    cfg.sounds.direct_message.path = Some("/home/luki/sounds/dm.ogg".into());
    cfg.auto_connect = true;
    cfg.share_channel_history = true;
    cfg.share_off_once = true;
    cfg.share_off_notice = false;
    cfg.ui_prefs = serde_json::json!({ "layout": "modern", "zoom": 1.1, "theme": "day", "panel": { "left": 240 } });
    cfg.chat_history_path = Some("/home/luki/voipc/chat_history.bin".into());
    cfg.chat_history_disabled = true;
    cfg.max_conversations = 75;
    cfg.file_cache_mb = 2048;
    cfg.relay_ids.insert("voice.example.org:9987".into(), "5a".repeat(16));
    cfg.check_updates = false;
    crate::config::save_config(&cfg).unwrap();

    // chat_history.bin (archive v7), by encrypt_archive
    let msg = |user_id, username: &str, content: &str, timestamp: u64, kind: Option<&str>, which: Option<&str>| ChatMessage {
        user_id,
        username: username.into(),
        content: content.into(),
        timestamp,
        kind: kind.map(Into::into),
        id: Some(format!("m{timestamp}")),
        expires_at: if timestamp % 2 == 0 { Some(4_102_444_800_000) } else { None },
        account: (user_id == 1).then(|| "5b".repeat(16)),
        extra: which.map(|k| extra[k].clone()),
    };
    let t = 1_762_000_000_000;
    let mut memory = voipc_crypto::sync::LogMemory::default();
    memory.cursors.insert("d:0101".into(), 5);
    memory.cursors.insert("c:abcd".into(), 9);
    memory.readers.insert("c:abcd".into(), vec![[2; 16]]);
    memory.vault_gens.insert("item.pins".into(), 7);
    memory.vault_gens.insert("pins.0".into(), 2);
    memory.named.insert("c:abcd".into(), vec![[0x3c; 32], [0x4d; 32]]);
    let mut archive = ChatArchive::default();
    archive.channels.insert(
        "voice.example.org:9987/general".into(),
        vec![
            msg(1, "luki", "the thread's start", t, None, None),
            msg(1, "luki", "an answer in a thread, **edited**", t + 1, None, Some("replied")),
            msg(1, "luki", "the caption", t + 5, None, Some("file")),
            msg(2, "anna", "the reported words", t + 6, None, Some("report")),
            msg(3, "bert", "collapsed by a moderator", t + 7, None, Some("hidden")),
            msg(1, "luki", "a later 1.x kept something here", t + 9, None, Some("future")),
            msg(2, "guest#4821", "", t + 11, Some("history-marker"), None),
            msg(4, "anna", "second-hand", t + 13, Some("shared"), None),
            msg(1, "luki", "", t + 15, Some("deleted"), None),
        ],
    );
    archive.dms.insert(
        "voice.example.org:9987/anna".into(),
        vec![
            msg(2, "anna", "hi, a DM", t + 2, None, None),
            msg(2, "anna", "a DM answer with a file", t + 10, None, Some("dm")),
        ],
    );
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
    let salt = crate::crypto::generate_salt();
    let key = crate::crypto::derive_key(PASSWORD, &salt);
    std::fs::write(
        out.join("chat_history.bin"),
        crate::crypto::encrypt_archive(&archive, &key, &salt).unwrap(),
    )
    .unwrap();
    std::fs::write(
        out.join("expected.json"),
        serde_json::to_string_pretty(&archive).unwrap() + "\n",
    )
    .unwrap();
}
```
