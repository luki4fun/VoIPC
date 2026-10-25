# 0.12.0 relay data (upgrade fixtures)

Written on 2026-10-23 by VoIPC **0.12.0's own code** (`49bf256`, a `git archive` copy), never by a
later version. They are never regenerated.

| File | Written by (0.12.0) | Checked in |
|---|---|---|
| `voipc.db`, `accounts.key`, `accounts.json` | the test below: `Relay::open` makes the key file; alice and bob sign up with real vaults through the client's `SignIn`; log keys; a DM alice keeps for bob; then `VACUUM INTO` | `src/tcp.rs` `a_0_12_accounts_database_opens_signs_in_and_keeps_its_messages` |
| `presets/<name>/channels.json`, `server_settings.json` | `voipc-server channels init <name> --out channels.json` (the 0.12.0 binary) | `src/upgrade_fixtures.rs` |
| `presets/<name>/init.txt` | what that command printed, including the generated channel passwords | `src/upgrade_fixtures.rs` (the 0.12 `sha256:` hashes still verify) |
| `server.toml` | 0.12.0's README sample and `docs/ACCOUNTS.md` `[accounts]` block, verbatim | `src/upgrade_fixtures.rs` |

The account password is `correct horse battery`. `accounts.json` holds what the test needs to
open the kept DM: ids, the conversation, and bob's log key.

`admin_token = "change-me"` in `server.toml` parses, but 1.0 refuses to start with a token
shorter than 16 characters. That change is deliberate (docs/COMPATIBILITY.md).

## How the database was made

This test was appended to 0.12.0's `crates/voipc-server/src/tcp.rs` test module and run there with
`--ignored --exact tcp::tests::write_upgrade_fixtures`, with `VOIPC_FIXTURE_DIR` pointing here.

```rust
    /// Track C (1.0 upgrade fixtures): an accounts database as 0.12.0 leaves
    /// it, made by its own code into $VOIPC_FIXTURE_DIR: alice and bob signed
    /// up with real vaults, log keys published, and a DM kept for bob. The
    /// key file is the one Relay::open makes; the database a VACUUM INTO copy.
    #[tokio::test]
    #[ignore]
    async fn write_upgrade_fixtures() {
        use voipc_crypto::log::{dm_conv, epoch_key, seal_entry, wrap, LogKey};
        use voipc_protocol::messages::WrapIn;
        let out = std::path::PathBuf::from(std::env::var("VOIPC_FIXTURE_DIR").expect("VOIPC_FIXTURE_DIR"));
        std::fs::create_dir_all(&out).unwrap();
        let live = std::env::temp_dir().join(format!("voipc-fixture-{}.db", std::process::id()));
        let mut config = ServerConfig::default();
        config.accounts.mode = AccountsMode::Optional;
        config.accounts.registration = RegistrationMode::Open;
        config.accounts.database = format!("sqlite://{}?mode=rwc", live.display());
        config.accounts.key_file = out.join("accounts.key").display().to_string();
        let relay = crate::accounts::Relay::open(&config.accounts).await.unwrap();
        let relay_id = relay.relay_id;
        let mut state = ServerState::new(&config, ServerSettings::default(), Vec::new(), "test-admin-token".into());
        state.accounts = Some(Arc::new(relay));
        let state = Arc::new(state);

        let (mut alice, a, alice_id) = register_with(&state, "alice").await;
        let (mut bob, b, bob_id) = register_with(&state, "bob").await;
        let (alice_lk, bob_lk) = (LogKey::generate(), LogKey::generate());
        let ask = |r: AccountRequest| ClientMessage::Account(r);
        for (c, lk, id) in [(&mut alice, &alice_lk, &alice_id), (&mut bob, &bob_lk, &bob_id)] {
            c.send(&ask(AccountRequest::LogKeyPublish { logkey: lk.public(), sig: lk.endorse(&id.identity) })).await;
            assert!(matches!(c.expect("stored", |m| reply(m).is_some()).await, ServerMessage::Account(AccountReply::LogKeyStored)));
        }
        let conv = dm_conv(&a.id, &b.id);
        let k = epoch_key();
        let wraps = vec![
            WrapIn { recipient: a.id, wrapped: wrap(&alice_lk.public(), &k, &conv, &a.id, 1, &a.id).unwrap() },
            WrapIn { recipient: b.id, wrapped: wrap(&bob_lk.public(), &k, &conv, &a.id, 1, &b.id).unwrap() },
        ];
        alice.send(&ask(AccountRequest::EpochPut { conv: conv.clone(), epoch: 1, wraps })).await;
        assert!(matches!(alice.expect("epoch", |m| reply(m).is_some()).await, ServerMessage::Account(AccountReply::EpochStored { epoch: 1, .. })));
        let env = voipc_crypto::envelope::envelope("m1", "kept by 0.12.0", None);
        let ct = seal_entry(&k, &conv, &a.id, 1, &alice_lk, &env, 1_760_000_000_000);
        alice.send(&ask(AccountRequest::LogAppend { conv: conv.clone(), epoch: 1, ct, ttl_secs: None })).await;
        assert!(matches!(alice.expect("appended", |m| reply(m).is_some()).await, ServerMessage::Account(AccountReply::LogAppended { .. })));

        let store = state.accounts.as_ref().unwrap().store().clone();
        let l4f_accounts::store::Store::Lite(b0) = &store else { panic!("sqlite") };
        let copy = out.join("voipc.db");
        sqlx::query(sqlx::AssertSqlSafe(format!("VACUUM INTO '{}'", copy.display()))).execute(&b0.0).await.unwrap();
        let meta = serde_json::json!({
            "made_by": "voipc 0.12.0 (49bf256), crates/voipc-server/src/tcp.rs write_upgrade_fixtures",
            "relay_id": hex::encode(relay_id),
            "password": "correct horse battery",
            "alice": hex::encode(a.id),
            "bob": hex::encode(b.id),
            "conv": conv,
            "alice_logkey_public": hex::encode(alice_lk.public()),
            "bob_logkey": hex::encode(&*bob_lk.to_bytes()),
            "text": "kept by 0.12.0",
        });
        std::fs::write(out.join("accounts.json"), serde_json::to_string_pretty(&meta).unwrap()).unwrap();
        for suffix in ["", "-wal", "-shm", ".lock"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", live.display()));
        }
    }
```
