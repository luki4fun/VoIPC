# 1.6.0 desktop chat history (upgrade fixture)

Written on 2026-11-10 by the archive code of VoIPC **1.6.0** (`f7e0d5d`, tag `v1.6.0`), never by a
later version, and never regenerated. 1.3.1 to 1.10 all wrote archive **v6**; 1.6.0 is the last
final release among them, so most desktops upgrade from a file like this one.
`src/upgrade_fixtures.rs` checks that this version opens it without losing anything and saves it in
its own format; `client/src/lib/archive-fixtures.test.ts` checks the front end reads its `extra`.

| File | Written by (1.6.0) | Content |
|---|---|---|
| `chat_history.bin` | `crypto::encrypt_archive` | archive v6: six channel messages (a thread's start, an edited answer with a reaction and a pin, a file, a forward, a history marker, a shared one), a DM, a cleared mark, a remembered device, log memory with a vault generation |
| `expected.json` | `serde_json` of that `ChatArchive` | what the archive must still contain |

The archive password is `correct horse battery staple`.

## How it was made

Not in a full 1.6.0 build: in a small crate outside the workspace (`target/scratch/`) holding
1.6.0's own archive code, with the dependency versions of 1.6.0's `Cargo.lock` (ring 0.17.14,
postcard 1.1.3, serde 1.0.229, serde_json 1.0.154, anyhow 1.0.104), built `--offline`:

- `src/crypto.rs`: `git show v1.6.0:client/src-tauri/src/crypto.rs`, cut before its envelope
  re-export and its tests (the only parts that need the rest of the app);
- a crate named `voipc-crypto` (lib `voipc_crypto`) whose `sync.rs` is `LogMemory` exactly as
  v1.6.0's `crates/voipc-crypto/src/sync.rs` defines it, which is all the archive uses of it.

The `extra` strings are what 1.6.0's front end wrote: its `chat-rules.ts` from
`git archive v1.6.0 client/src/lib`, run by this script into `extra-1.6.0.json`:

```ts
// One-off: the `extra` strings 1.6.0's front end wrote into the desktop archive
// (its chat-rules.ts toArchived, from `git archive v1.6.0`), for the 1.6.0 history fixture.
import assert from "node:assert/strict";
import { toArchived, fromArchived } from "./fe-1.6.0/client/src/lib/chat-rules.ts";

const T = 1_761_500_000_000;
const acct = (b: string) => b.repeat(16);
const base = (o: Record<string, unknown>) => ({ user_id: 1, username: "luki", content: "", ...o });
const msgs: Record<string, any> = {
  replied: base({ content: "an answer in a thread, edited", timestamp: T + 1, id: "m2", account: acct("5b"),
    reply_to: "m1", thread: "m1", edited_at: T + 60_000,
    reactions: [{ emoji: "🎉", by: [{ key: acct("6c"), name: "anna", on: true, at: T + 3 }] }],
    pin: { on: true, at: T + 4, by: "anna" } }),
  file: base({ content: "the caption", timestamp: T + 5, id: "m3", account: acct("5b"),
    file: { hash: "ab".repeat(32), key: "cd".repeat(32), size: 2048, z: true, name: "notes.txt", mime: "text/plain" } }),
  fwd: base({ user_id: 2, username: "anna", content: "passed on", timestamp: T + 6, id: "m4", account: acct("6c"),
    fwd: { name: "bert", at: T - 1000 } }),
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

`src/main.rs`, run as `cargo run --offline -- tests/fixtures/1.6.0 extra-1.6.0.json`:

```rust
//! Writes the 1.6.0 chat-history upgrade fixture with 1.6.0's own archive code:
//! `crypto.rs` is client/src-tauri/src/crypto.rs at v1.6.0, cut before its
//! envelope re-export and its tests; `voipc_crypto::sync::LogMemory` is the
//! struct as v1.6.0's crates/voipc-crypto/src/sync.rs defined it.
//! Run: cargo run --offline -- <out dir> <extra-1.6.0.json>
#[allow(dead_code)]
mod crypto;

fn main() {
    use crypto::{ChatArchive, ChatMessage, DeviceRecord};
    let mut args = std::env::args().skip(1);
    let out = std::path::PathBuf::from(args.next().expect("out dir"));
    let extra: std::collections::HashMap<String, String> =
        serde_json::from_str(&std::fs::read_to_string(args.next().expect("extra json")).unwrap()).unwrap();
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
    let t = 1_761_500_000_000;
    let mut memory = voipc_crypto::sync::LogMemory::default();
    memory.cursors.insert("d:0101".into(), 5);
    memory.readers.insert("c:abcd".into(), vec![[2; 16]]);
    memory.vault_gens.insert("item.pins".into(), 7);
    let mut archive = ChatArchive::default();
    archive.channels.insert(
        "voice.example.org:9987/general".into(),
        vec![
            msg(1, "luki", "the thread's start", t, None, None),
            msg(1, "luki", "an answer in a thread, edited", t + 1, None, Some("replied")),
            msg(1, "luki", "the caption", t + 5, None, Some("file")),
            msg(2, "anna", "passed on", t + 6, None, Some("fwd")),
            msg(2, "guest#4821", "", t + 7, Some("history-marker"), None),
            msg(4, "anna", "second-hand", t + 9, Some("shared"), None),
        ],
    );
    archive.dms.insert("voice.example.org:9987/anna".into(), vec![msg(3, "anna", "hi, a DM", t + 2, None, None)]);
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
    let salt = crypto::generate_salt();
    let key = crypto::derive_key(password, &salt);
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(out.join("chat_history.bin"), crypto::encrypt_archive(&archive, &key, &salt).unwrap()).unwrap();
    std::fs::write(out.join("expected.json"), serde_json::to_string_pretty(&archive).unwrap() + "\n").unwrap();
}
```
