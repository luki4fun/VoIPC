# 1.11.0 account data (upgrade fixtures)

Written on 2026-11-10 by **1.11.0's own voipc-crypto**: the working tree at `4c5334c` (tag
`v1.11.0-rc.2`), whose code 1.11.0 is; only tests and docs differed. Never regenerated.

| File | Written by (1.11.0) | Checked in |
|---|---|---|
| `kat.json` | the test below, through the public API: an account whose 1.10 vault held its pins in one item (generation 5) signs in at protocol 21; `AccountSync` folds the pins into page `pins.0` and writes `item.pins` as an index (format 2); prefs and two blocks are saved; a fourth person met is pinned into the page | `tests/upgrade.rs` `a_1_11_*`: both slots open the vault, every item reads at the `0x02` layout with its format and generation, and a new sign-in reads the pins from their page (a swapped key still warns), the prefs and the blocks |
| `log_memory.json` | `serde_json` of that device's `LogMemory`, as the browser keeps it, with `named` (new in 1.11) | `tests/upgrade_memory.rs` |

The password is `correct horse battery staple`, the recovery key `0x42` 32 times.

What this does not hold: the protocol-21 channel keys (`voipc-chain/v1/`, `voipc-seat/v1|`,
`voipc-wrap/v2|`, `voipc-list/v1|`, `voipc-seal/v1|`, `voipc-vlink/v1|`, `voipc-log/v2|`). Those are
pinned by the known answers in `src/log.rs`, computed by Python and OpenSSL rather than by this
code, which a file this code wrote could not add to.

## How they were made

This test was appended to `tests/upgrade.rs`, run once with
`cargo test -p voipc-crypto --test upgrade -- --ignored --exact write_1_11_fixtures`, then removed:

```rust
/// Temporary: writes fixtures/1.11.0/ with 1.11's code through its public API.
#[test]
#[ignore]
fn write_1_11_fixtures() {
    use std::collections::BTreeMap;
    use voipc_crypto::account::{Pins, SignedIn, ITEM_PINS};
    use voipc_crypto::sync::{AccountSync, LogMemory, Prefs};
    use voipc_protocol::messages::{AccountReply, AccountRequest, ClientMessage};
    let dir = format!("{}/tests/fixtures/1.11.0", env!("CARGO_MANIFEST_DIR"));
    std::fs::create_dir_all(&dir).unwrap();

    let relay = [0x5a; 16];
    let me = [0x11; 16];
    let (name, password) = ("luki", "correct horse battery staple");
    let recovery = [0x42; 32];
    let vault = Vault::create(relay, name);
    let identity = voipc_crypto::generate_identity_key_pair();
    let logkey = LogKey::generate();
    let d = derive(password, &relay, name);

    // Three people pinned in the single item a 1.10 account has (generation 5)
    let people: Vec<([u8; 16], String, Vec<u8>)> = (1..=3u8)
        .map(|n| {
            (
                [0x30 + n; 16],
                format!("person{n}"),
                voipc_crypto::generate_identity_key_pair()
                    .public_key()
                    .serialize()
                    .to_vec(),
            )
        })
        .collect();
    let mut old = Pins::default();
    for (a, n, k) in &people {
        old.check(a, n, k);
    }
    let mut blobs: BTreeMap<String, VaultBlob> = [
        vault.pass_slot(&d.vault_key),
        vault.recovery_slot(&recovery),
        vault.seal_item(ITEM_IDENTITY, 1, &identity.serialize()),
        vault.seal_item(ITEM_LOGKEY, 1, &logkey.to_bytes()),
        vault.seal_item(ITEM_PINS, 5, &old.to_bytes()),
    ]
    .into_iter()
    .enumerate()
    .map(|(i, b)| {
        (
            b.k.clone(),
            VaultBlob {
                version: i as i64 + 1,
                ..b
            },
        )
    })
    .collect();
    let signed = SignedIn {
        relay_id: relay,
        name: name.into(),
        vault: Vault::from_dek(relay, name, vault.dek()),
        identity,
        recovery: None,
        blobs: blobs.values().cloned().collect(),
    };
    let mut memory = LogMemory::default();
    memory.vault_gens.insert(ITEM_PINS.into(), 5);
    let (mut s, _) = AccountSync::start(&signed, me, memory, false);
    s.set_protocol(21);

    // Every write answered as a relay at 21 would, until nothing more goes
    let mut version = 100;
    let mut pump = |s: &mut AccountSync, mut out: Vec<ClientMessage>| {
        while let Some(m) = out.pop() {
            if let ClientMessage::Account(AccountRequest::VaultPut { k, v, .. }) = m {
                version += 1;
                blobs.insert(
                    k.clone(),
                    VaultBlob {
                        k: k.clone(),
                        v,
                        version,
                    },
                );
                let (more, _) = s
                    .on_reply(&AccountReply::VaultStored { k, version })
                    .unwrap();
                out.extend(more);
            }
        }
    };
    let out = s.pins_first();
    pump(&mut s, out);
    let out = s.set_prefs(Prefs {
        cloud: true,
        asked: true,
    });
    pump(&mut s, out);
    let blocked = format!("a:{}", hex(&[0x66; 16]));
    for (key, label) in [(blocked.as_str(), "mallory"), ("g:troll#0001", "Troll#0001")] {
        let out = s.set_block(key, label, true).unwrap();
        pump(&mut s, out);
    }
    // One more person met at 21: a new pin, into the page
    let fourth = (
        [0x34; 16],
        "person4".to_string(),
        voipc_crypto::generate_identity_key_pair()
            .public_key()
            .serialize()
            .to_vec(),
    );
    let (_, out) = s.check_peer(&fourth.0, &fourth.1, &fourth.2);
    pump(&mut s, out);
    let out = s.flush_pins();
    pump(&mut s, out);
    assert!(s.pins_saved());

    let mut memory = s.memory();
    memory.cursors.insert("c:abcd".into(), 9);
    memory.readers.insert("c:abcd".into(), vec![[2; 16]]);
    memory.named.insert("c:abcd".into(), vec![[0x3c; 32]]);
    let pins: Vec<serde_json::Value> = people
        .iter()
        .chain([&fourth])
        .map(|(a, n, k)| serde_json::json!({ "account": hex(a), "name": n, "key": hex(k) }))
        .collect();
    let kat = serde_json::json!({
        "made_by": "voipc 1.11.0 (v1.11.0-rc.2, 4c5334c), crates/voipc-crypto/tests/upgrade.rs write_1_11_fixtures",
        "relay_id": hex(&relay),
        "me": hex(&me),
        "name": name,
        "password": password,
        "recovery": hex(&recovery),
        "blobs": blobs.values().map(|b| serde_json::json!({ "k": b.k, "v": hex(&b.v), "version": b.version })).collect::<Vec<_>>(),
        "identity_public": hex(&signed.identity.public_key().serialize()),
        "logkey_public": hex(&logkey.public()),
        "pins": pins,
        "prefs": { "cloud": true, "asked": true },
        "blocks": s.blocks(),
        "vault_gens": s.memory().vault_gens,
    });
    std::fs::write(
        format!("{dir}/kat.json"),
        serde_json::to_string_pretty(&kat).unwrap() + "\n",
    )
    .unwrap();
    std::fs::write(
        format!("{dir}/log_memory.json"),
        serde_json::to_string(&memory).unwrap() + "\n",
    )
    .unwrap();
}
```
