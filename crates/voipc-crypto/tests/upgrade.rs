//! What a released version stored must still open: each `fixtures/<version>/`
//! was written once by that version's code and is never regenerated. A failure
//! here means an upgrade (of libsignal, of a format) would lock people out of
//! their vaults or kept messages. `0.12.0/` holds a 0.12 account and its kept
//! entry; `1.11.0/` an account's vault as 1.11 leaves it (every item at the
//! `0x02` item layout, the pins as an index of pages, prefs and blocks).

use libsignal_protocol::IdentityKeyPair;
use serde::{Deserialize, Serialize};
use voipc_crypto::account::{derive, safety_number, Vault, ITEM_IDENTITY};
use voipc_crypto::log::{endorsed, open_entry, self_unwrap, unwrap, LogKey};
use voipc_crypto::sync::ITEM_LOGKEY;
use voipc_protocol::types::VaultBlob;

#[derive(Serialize, Deserialize)]
struct Blob {
    k: String,
    v: String,
}

/// Everything a 0.12 account leaves on a relay and in its peers' hands.
#[derive(Serialize, Deserialize)]
struct Kat {
    relay_id: String,
    name: String,
    password: String,
    recovery: String,
    blobs: Vec<Blob>,
    identity_public: String,
    logkey_public: String,
    endorsement: String,
    conv: String,
    sender: String,
    epoch: u32,
    epoch_key: String,
    envelope: String,
    sent_at: u64,
    sealed: String,
    recipient: String,
    wrapped: String,
    self_wrapped: String,
    peer_account: String,
    peer_identity_public: String,
    safety_number: String,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn arr<const N: usize>(s: &str) -> [u8; N] {
    unhex(s).try_into().expect("length")
}

fn load(version: &str) -> Kat {
    let path = format!(
        "{}/tests/fixtures/{version}/kat.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(path).expect("fixture")).expect("fixture json")
}

fn blobs(k: &Kat) -> Vec<VaultBlob> {
    k.blobs
        .iter()
        .map(|b| VaultBlob {
            k: b.k.clone(),
            v: unhex(&b.v),
            version: 1,
        })
        .collect()
}

#[test]
fn a_0_12_vault_opens_with_its_password_and_its_recovery_key() {
    let k = load("0.12.0");
    let relay = arr::<16>(&k.relay_id);
    let blobs = blobs(&k);
    let d = derive(&k.password, &relay, &k.name);
    let by_pw =
        Vault::open_with_password(relay, &k.name, &blobs, &d.vault_key).expect("password opens");
    let by_rec = Vault::open_with_recovery(relay, &k.name, &blobs, &arr::<32>(&k.recovery))
        .expect("recovery key opens");
    assert_eq!(by_pw.dek(), by_rec.dek());

    let identity = IdentityKeyPair::try_from(
        &by_pw
            .open_item(&blobs, ITEM_IDENTITY)
            .expect("identity item")
            .payload[..],
    )
    .expect("identity parses");
    assert_eq!(hex(&identity.public_key().serialize()), k.identity_public);
    let logkey = LogKey::from_bytes(
        &by_pw
            .open_item(&blobs, ITEM_LOGKEY)
            .expect("log key item")
            .payload,
    )
    .expect("log key parses");
    assert_eq!(hex(&logkey.public()), k.logkey_public);
}

#[test]
fn a_0_12_log_key_endorsement_and_kept_entry_still_verify() {
    let k = load("0.12.0");
    let (identity, logkey_pub) = (unhex(&k.identity_public), unhex(&k.logkey_public));
    assert!(
        endorsed(&identity, &logkey_pub, &unhex(&k.endorsement)),
        "endorsement"
    );

    let sender = arr::<16>(&k.sender);
    let key = arr::<32>(&k.epoch_key);
    let (envelope, sent_at) = open_entry(
        &key,
        &k.conv,
        &sender,
        k.epoch,
        &logkey_pub,
        &unhex(&k.sealed),
    )
    .expect("entry opens and verifies");
    assert_eq!(envelope, k.envelope.as_bytes());
    assert_eq!(sent_at, k.sent_at);
}

#[test]
fn a_0_12_epoch_key_unwraps_from_a_wrap_and_a_self_wrap() {
    let k = load("0.12.0");
    let relay = arr::<16>(&k.relay_id);
    let blobs = blobs(&k);
    let vault = Vault::open_with_password(
        relay,
        &k.name,
        &blobs,
        &derive(&k.password, &relay, &k.name).vault_key,
    )
    .unwrap();
    let own = LogKey::from_bytes(&vault.open_item(&blobs, ITEM_LOGKEY).unwrap().payload).unwrap();
    let sender = arr::<16>(&k.sender);
    let key = arr::<32>(&k.epoch_key);
    assert_eq!(
        unwrap(
            &own,
            &unhex(&k.wrapped),
            &k.conv,
            &sender,
            k.epoch,
            &arr::<16>(&k.recipient)
        )
        .expect("wrap"),
        key
    );
    assert_eq!(
        self_unwrap(&own, &unhex(&k.self_wrapped), &k.conv, &sender, k.epoch).expect("self-wrap"),
        key
    );
}

#[test]
fn a_0_12_safety_number_is_unchanged() {
    let k = load("0.12.0");
    let shown = safety_number(
        &arr::<16>(&k.sender),
        &unhex(&k.identity_public),
        &arr::<16>(&k.peer_account),
        &unhex(&k.peer_identity_public),
    );
    assert_eq!(shown.as_deref(), Some(k.safety_number.as_str()));
}

/// Writes `fixtures/$VOIPC_WRITE_FIXTURES/kat.json` with the current code.
/// `0.12.0/` was written by the 0.12.0 code (2026-10-22) before 1.0 changed
/// any format; run this once per release for the next one's directory, and
/// never against a directory that already exists.
#[test]
#[ignore]
fn write_fixtures() {
    use voipc_crypto::account::ITEM_PINS;
    use voipc_crypto::log::{epoch_key, seal_entry, self_wrap, wrap};
    let Ok(version) = std::env::var("VOIPC_WRITE_FIXTURES") else {
        return;
    };

    let relay = [0x5a; 16];
    let (name, password) = ("luki", "correct horse battery staple");
    let recovery = [0x42; 32];
    let vault = Vault::create(relay, name);
    let identity = voipc_crypto::generate_identity_key_pair();
    let logkey = LogKey::generate();
    let d = derive(password, &relay, name);
    let vblobs = [
        vault.pass_slot(&d.vault_key),
        vault.recovery_slot(&recovery),
        vault.seal_item(ITEM_IDENTITY, 1, &identity.serialize()),
        vault.seal_item(ITEM_LOGKEY, 1, &logkey.to_bytes()),
        vault.seal_item(
            ITEM_PINS,
            1,
            &voipc_crypto::account::Pins::default().to_bytes(),
        ),
    ];

    let sender = [0x11; 16];
    let (conv, epoch, sent_at) = ("c:00112233445566778899aabbccddeeff", 3, 1_761_120_000_000);
    let key = epoch_key();
    let envelope = r#"{"v":2,"id":7,"text":"kept in 0.12"}"#;
    let recipient = [0x22; 16];
    let peer = voipc_crypto::generate_identity_key_pair();
    let peer_account = [0x33; 16];
    let identity_public = identity.public_key().serialize();
    let peer_public = peer.public_key().serialize();

    let kat = Kat {
        relay_id: hex(&relay),
        name: name.into(),
        password: password.into(),
        recovery: hex(&recovery),
        blobs: vblobs
            .iter()
            .map(|b| Blob {
                k: b.k.clone(),
                v: hex(&b.v),
            })
            .collect(),
        identity_public: hex(&identity_public),
        logkey_public: hex(&logkey.public()),
        endorsement: hex(&logkey.endorse(&identity)),
        conv: conv.into(),
        sender: hex(&sender),
        epoch,
        epoch_key: hex(&*key),
        envelope: envelope.into(),
        sent_at,
        sealed: hex(&seal_entry(
            &key,
            conv,
            &sender,
            epoch,
            &logkey,
            envelope.as_bytes(),
            sent_at,
        )),
        recipient: hex(&recipient),
        wrapped: hex(
            &wrap(&logkey.public(), &key, conv, &sender, epoch, &recipient).expect("wrap"),
        ),
        self_wrapped: hex(&self_wrap(&logkey, &key, conv, &sender, epoch)),
        peer_account: hex(&peer_account),
        peer_identity_public: hex(&peer_public),
        safety_number: safety_number(&sender, &identity_public, &peer_account, &peer_public)
            .expect("safety number"),
    };
    let dir = format!("{}/tests/fixtures/{version}", env!("CARGO_MANIFEST_DIR"));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        format!("{dir}/kat.json"),
        serde_json::to_string_pretty(&kat).unwrap() + "\n",
    )
    .unwrap();
}

// ── 1.11.0: a vault as 1.11 leaves it on a relay at protocol 21 ──

fn kat_1_11() -> serde_json::Value {
    let path = format!(
        "{}/tests/fixtures/1.11.0/kat.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(path).expect("fixture")).expect("fixture json")
}

fn s<'a>(k: &'a serde_json::Value, field: &str) -> &'a str {
    k[field].as_str().expect(field)
}

fn blobs_1_11(k: &serde_json::Value) -> Vec<VaultBlob> {
    k["blobs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| VaultBlob {
            k: s(b, "k").into(),
            v: unhex(s(b, "v")),
            version: b["version"].as_i64().unwrap(),
        })
        .collect()
}

/// Both slots open the vault, and every item reads at the layout and the
/// generation 1.11 wrote: `item.pins` an index (format 2), the rest format 1.
#[test]
fn a_1_11_vault_opens_and_every_item_reads() {
    use voipc_crypto::account::{ITEM_FORMAT, ITEM_PINS};
    let k = kat_1_11();
    let relay = arr::<16>(s(&k, "relay_id"));
    let name = s(&k, "name");
    let blobs = blobs_1_11(&k);
    let by_pw = Vault::open_with_password(
        relay,
        name,
        &blobs,
        &derive(s(&k, "password"), &relay, name).vault_key,
    )
    .expect("password opens");
    let by_rec = Vault::open_with_recovery(relay, name, &blobs, &arr::<32>(s(&k, "recovery")))
        .expect("recovery key opens");
    assert_eq!(by_pw.dek(), by_rec.dek());
    let identity = IdentityKeyPair::try_from(
        &by_pw
            .open_item(&blobs, ITEM_IDENTITY)
            .expect("identity")
            .payload[..],
    )
    .expect("identity parses");
    assert_eq!(
        hex(&identity.public_key().serialize()),
        s(&k, "identity_public")
    );
    let logkey = LogKey::from_bytes(&by_pw.open_item(&blobs, ITEM_LOGKEY).unwrap().payload)
        .expect("log key parses");
    assert_eq!(hex(&logkey.public()), s(&k, "logkey_public"));
    for b in &blobs {
        if b.k.starts_with("slot.") {
            assert_eq!(b.v[0], 1, "{}: the slot layout", b.k);
            continue;
        }
        assert_eq!(b.v[0], 2, "{}: the item layout 1.0 to 1.11 write", b.k);
        let item = by_pw.open_item(&blobs, &b.k).expect(&b.k);
        let format = if b.k == ITEM_PINS { ITEM_FORMAT } else { 1 };
        assert_eq!(item.format, format, "{}", b.k);
        if let Some(gen) = k["vault_gens"][&b.k].as_u64() {
            assert_eq!(item.gen, gen, "{}", b.k);
        }
    }
}

/// Signed in again at protocol 21 with what that device kept: nothing reads as
/// a problem, the pins come in from their page and every one holds (a swapped
/// key still warns), and the prefs and the blocked list are as they were.
#[test]
fn a_1_11_account_reads_its_paged_pins_prefs_and_blocks() {
    use voipc_crypto::account::{PinCheck, SignedIn};
    use voipc_crypto::sync::{AccountSync, Event, LogMemory, Prefs};
    use voipc_protocol::messages::{AccountReply, AccountRequest, ClientMessage};
    let k = kat_1_11();
    let relay = arr::<16>(s(&k, "relay_id"));
    let name = s(&k, "name");
    let blobs = blobs_1_11(&k);
    let vault = Vault::open_with_password(
        relay,
        name,
        &blobs,
        &derive(s(&k, "password"), &relay, name).vault_key,
    )
    .unwrap();
    let identity =
        IdentityKeyPair::try_from(&vault.open_item(&blobs, ITEM_IDENTITY).unwrap().payload[..])
            .unwrap();
    let signed = SignedIn {
        relay_id: relay,
        name: name.into(),
        vault,
        identity,
        recovery: None,
        blobs: blobs.clone(),
    };
    let memory: LogMemory =
        serde_json::from_str(include_str!("fixtures/1.11.0/log_memory.json")).unwrap();
    let (mut sync, _) = AccountSync::start(&signed, arr::<16>(s(&k, "me")), memory, false);
    sync.set_protocol(21);
    assert!(!sync.pins_in(), "the pins wait for their pages");
    let asked: Vec<String> = sync
        .pins_first()
        .into_iter()
        .filter_map(|m| match m {
            ClientMessage::Account(AccountRequest::VaultPage { k }) => Some(k),
            _ => None,
        })
        .collect();
    assert_eq!(asked, ["pins.0"]);
    let page = blobs.iter().find(|b| b.k == "pins.0").cloned();
    let (_, events) = sync
        .on_reply(&AccountReply::VaultPageFound {
            k: "pins.0".into(),
            blob: page,
        })
        .unwrap();
    let problems: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            Event::VaultProblem { item, problem } => Some((*item, *problem)),
            _ => None,
        })
        .collect();
    assert!(problems.is_empty(), "{problems:?}");
    assert!(sync.pins_in());
    for p in k["pins"].as_array().unwrap() {
        let account = arr::<16>(s(p, "account"));
        let key = unhex(s(p, "key"));
        assert_eq!(sync.pinned(&account), Some(&key[..]), "{}", s(p, "name"));
        assert_eq!(
            sync.check_peer(&account, s(p, "name"), &key).0,
            PinCheck::Same
        );
    }
    let first = &k["pins"][0];
    let other = voipc_crypto::generate_identity_key_pair()
        .public_key()
        .serialize();
    assert_eq!(
        sync.check_peer(&arr::<16>(s(first, "account")), s(first, "name"), &other)
            .0,
        PinCheck::Changed
    );
    assert_eq!(
        sync.prefs(),
        Prefs {
            cloud: true,
            asked: true
        }
    );
    let blocks: Vec<(String, String)> = serde_json::from_value(k["blocks"].clone()).unwrap();
    assert_eq!(sync.blocks(), blocks);
}
