# 1.11.0 relay data (upgrade fixture)

Written on 2026-11-10 by **1.11.0's own relay code**: the working tree at `4c5334c` (tag
`v1.11.0-rc.2`), whose code 1.11.0 is; only tests and docs differed. Never regenerated.

| File | Written by (1.11.0) | Checked in |
|---|---|---|
| `voipc.db` | the test below: an import from Discord with something of everything (`moved`: groups, members as placeholders, a ban, a category, two channels, an emote, archive rows), dee come by Discord and claimed, dee hiding his own row, an excluded Discord id, an invite link; alice and bob with log keys and a DM alice kept for bob; alice's post kept in the imported lounge on chain 1, bucket 7 seating bob; bob restricted in text; then `VACUUM INTO` | `src/session_tests.rs` `a_1_11_accounts_database_opens_signs_in_and_keeps_everything` |
| `accounts.json` | what the test needs: ids, the DM's conversation, bob's log key, the lounge's log, and the rows of each table migrations 0006 to 0010 made | the same test |

The relay's key is the tests' fixed `[9; 32]` (`Relay::open_with`), so there is no key file; the
0.12.0 fixture covers loading one. The account password is `correct horse battery`. The kept DM
is real end-to-end crypto; the lounge's chain rows and its entry are stand-in bytes (the relay reads
none of them, and voipc-crypto's known answers pin those formats), checked byte for byte.

## How it was made

This test was appended to `src/session_tests.rs`'s `providers::import` module, run once with
`VOIPC_FIXTURE_DIR=$PWD/tests/fixtures/1.11.0 cargo test -p voipc-server --bin voipc-server write_1_11_fixture -- --ignored`,
then removed. `FIXTURE_1_11_TABLES` is the list beside the module's `count`.

```rust
/// Temporary: writes tests/fixtures/1.11.0/ (see its README), then removed.
#[tokio::test]
#[ignore]
async fn write_1_11_fixture() {
    use voipc_crypto::log::{dm_conv, epoch_key, seal_entry, wrap, LogKey, OWN_ROW_BYTES, ROW_BYTES};
    use voipc_protocol::messages::{BucketIn, ChainSeal, WrapIn};
    let out = std::path::PathBuf::from(std::env::var("VOIPC_FIXTURE_DIR").expect("VOIPC_FIXTURE_DIR"));
    std::fs::create_dir_all(&out).unwrap();
    async fn next(c: &mut Client, r: AccountRequest) -> AccountReply {
        c.send(&ClientMessage::Account(r)).await;
        let m = c
            .expect("an answer", |m| {
                matches!(m, ServerMessage::Account(r) if !matches!(
                    r,
                    AccountReply::LogNews { .. } | AccountReply::LogPending { .. } | AccountReply::Info(_)
                ))
            })
            .await;
        let ServerMessage::Account(r) = m else { unreachable!() };
        r
    }

    // An import with something of everything, its Discord member dee come and claimed
    let (state, _db, subject) = relay(RegistrationMode::Open).await;
    let mut m = moved(&state, &subject).await;
    let id = lounge(&state).await;
    enter(&mut m.dee, id).await;
    assert_eq!(mine_done(&mut m.dee, ArchiveAction::Hide, one_row(id, 100)).await, 1);
    let excluded = AdminOp::MoveExclude { dc_id: "1004".into(), on: true, erase: false };
    let r = op(&mut m.ann, excluded, Some(code(&m.secret))).await;
    assert!(!matches!(r, AccountReply::Error { .. }), "{r:?}");
    let link = AdminOp::InviteLinkNew { max_uses: 5, days: 0, group: None };
    let r = op(&mut m.ann, link, Some(code(&m.secret))).await;
    assert!(!matches!(r, AccountReply::Error { .. }), "{r:?}");

    // alice and bob, log keys published, and a DM alice kept for bob
    let (mut alice, a, alice_id) = register_with(&state, "alice").await;
    let (mut bob, b, bob_id) = register_with(&state, "bob").await;
    let (alice_lk, bob_lk) = (LogKey::generate(), LogKey::generate());
    for (c, lk, signed) in [(&mut alice, &alice_lk, &alice_id), (&mut bob, &bob_lk, &bob_id)] {
        let r = next(c, AccountRequest::LogKeyPublish { logkey: lk.public(), sig: lk.endorse(&signed.identity) }).await;
        assert!(matches!(r, AccountReply::LogKeyStored), "{r:?}");
    }
    let conv = dm_conv(&a.id, &b.id);
    let k = epoch_key();
    let wraps = vec![
        WrapIn { recipient: a.id, wrapped: wrap(&alice_lk.public(), &k, &conv, &a.id, 1, &a.id).unwrap() },
        WrapIn { recipient: b.id, wrapped: wrap(&bob_lk.public(), &k, &conv, &a.id, 1, &b.id).unwrap() },
    ];
    let r = next(&mut alice, AccountRequest::EpochPut { conv: conv.clone(), epoch: 1, wraps }).await;
    assert!(matches!(r, AccountReply::EpochStored { epoch: 1, .. }), "{r:?}");
    let env = voipc_crypto::envelope::envelope("m1", "kept by 1.11.0", None);
    let ct = seal_entry(&k, &conv, &a.id, 1, &alice_lk, &env, 1_762_000_000_000);
    let r = next(&mut alice, AccountRequest::LogAppend { conv: conv.clone(), epoch: 1, ct, ttl_secs: None }).await;
    assert!(matches!(r, AccountReply::LogAppended { .. }), "{r:?}");

    // A post kept in the lounge on chain 1, bucket 7 seating bob. The relay reads
    // none of these bytes, so they stand in (voipc-crypto's known answers pin them)
    enter(&mut alice, id).await;
    enter(&mut bob, id).await;
    let log = state.channels.read().await[&id].info.log.clone();
    for c in [&mut alice, &mut bob] {
        let r = next(c, AccountRequest::LogJoin { conv: log.clone() }).await;
        assert!(matches!(r, AccountReply::LogJoined { .. }), "{r:?}");
    }
    let put = AccountRequest::ChainPut {
        conv: log.clone(),
        epoch: 1 << 12,
        self_wrap: Some(vec![0xA1; ROW_BYTES]),
        step: None,
        link: None,
        wraps: vec![],
        buckets: vec![BucketIn {
            bucket: 7,
            version: 0,
            list: vec![0x11; 28 + 24],
            seats: vec![
                WrapIn { recipient: a.id, wrapped: vec![0xEE; OWN_ROW_BYTES] },
                WrapIn { recipient: b.id, wrapped: vec![0xB2; ROW_BYTES] },
            ],
            down: None,
        }],
        seals: vec![ChainSeal { bucket: 7, version: 0, index: 0, sealed: vec![0xC3; ROW_BYTES] }],
        last: true,
    };
    let r = next(&mut alice, put).await;
    assert!(matches!(r, AccountReply::ChainStored { behind: false, .. }), "{r:?}");
    let r = next(&mut alice, AccountRequest::LogAppend { conv: log.clone(), epoch: 1 << 12, ct: vec![0x55; 64], ttl_secs: None }).await;
    assert!(matches!(r, AccountReply::LogAppended { .. }), "{r:?}");

    // ann restricts bob in text, until lifted
    let bob_uid = state.sessions.get(&*state.account_sessions.get(&b.id).unwrap()).unwrap().user_id;
    m.ann.send(&ClientMessage::AdminRestrict { user_id: bob_uid, voice: false, text: true, duration_secs: 0, reason: "fixture".into() }).await;
    m.ann.expect("the row", |m| matches!(m, ServerMessage::Restrictions { list } if list.iter().any(|r| r.text))).await;

    let mut tables = serde_json::Map::new();
    for t in FIXTURE_1_11_TABLES {
        let n = count(&state, &format!("SELECT CAST(COUNT(*) AS BIGINT) FROM {t}")).await;
        assert!(n > 0, "{t} is empty");
        tables.insert(t.to_string(), n.into());
    }
    let copy = out.join("voipc.db");
    let _ = std::fs::remove_file(&copy);
    sql(&state, &format!("VACUUM INTO '{}'", copy.display())).await;
    let meta = serde_json::json!({
        "made_by": "voipc 1.11.0 (v1.11.0-rc.2, 4c5334c), crates/voipc-server/src/session_tests.rs providers::import::write_1_11_fixture",
        "relay_id": hex::encode(relay_of(&state).relay_id),
        "password": "correct horse battery",
        "alice": hex::encode(a.id),
        "bob": hex::encode(b.id),
        "conv": conv,
        "alice_logkey_public": hex::encode(alice_lk.public()),
        "bob_logkey": hex::encode(&*bob_lk.to_bytes()),
        "text": "kept by 1.11.0",
        "log": log,
        "tables": tables,
    });
    std::fs::write(out.join("accounts.json"), serde_json::to_string_pretty(&meta).unwrap() + "\n").unwrap();
}
```
