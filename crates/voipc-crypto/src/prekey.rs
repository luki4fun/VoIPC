//! Pre-keys: what a peer needs to start a session with us without us being
//! there (PQXDH). One signed Curve25519 key, one signed Kyber1024 last-resort
//! key, and one-time Curve25519 keys the relay hands out one per session.
//! All of them are new on every connect, like the stores that hold them.

use anyhow::Context;
use libsignal_protocol::{
    kem, GenericSignedPreKey, IdentityKeyPair, KeyPair, KyberPreKeyRecord, PreKeyId, PreKeyRecord,
    SignedPreKeyRecord, Timestamp,
};
use voipc_protocol::types::{OneTimePreKey, PreKeyBundleData};

use crate::stores::SignalStores;

/// One-time pre-keys at connect.
pub const INITIAL_PREKEY_COUNT: u32 = 100;
/// One-time pre-keys sent when the relay says it runs low (`PreKeysLow`).
pub const PREKEY_REFILL_COUNT: u32 = 50;

const SIGNED_PREKEY_ID: u32 = 1;
const KYBER_PREKEY_ID: u32 = 1;

/// The signed pre-key, the Kyber last-resort key and `INITIAL_PREKEY_COUNT`
/// one-time keys, into fresh stores.
pub fn generate_prekeys(stores: &mut SignalStores, identity: &IdentityKeyPair) -> anyhow::Result<()> {
    let now = Timestamp::from_epoch_millis(crate::time::now_millis());
    let signed = KeyPair::generate(&mut crate::rng());
    let signature = identity.private_key().calculate_signature(&signed.public_key.serialize(), &mut crate::rng())?;
    let record = SignedPreKeyRecord::new(SIGNED_PREKEY_ID.into(), now, &signed, &signature);
    stores.signed_prekey.signed_prekeys.insert(SIGNED_PREKEY_ID, record.serialize()?);

    // Built by hand rather than `KyberPreKeyRecord::generate`, which reads
    // SystemTime: that panics on wasm32
    let kyber = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut crate::rng());
    let signature = identity.private_key().calculate_signature(&kyber.public_key.serialize(), &mut crate::rng())?;
    let record = KyberPreKeyRecord::new(KYBER_PREKEY_ID.into(), now, &kyber, &signature);
    stores.kyber.keys.insert(KYBER_PREKEY_ID, record.serialize()?);

    more_prekeys(stores, INITIAL_PREKEY_COUNT)?;
    Ok(())
}

/// `count` new one-time keys, stored, and their public halves for the relay.
/// Ids only ever grow, so a key the relay still holds never names a new one.
pub fn more_prekeys(stores: &mut SignalStores, count: u32) -> anyhow::Result<Vec<OneTimePreKey>> {
    let mut out = Vec::with_capacity(count as usize);
    for _ in 0..count {
        stores.prekey.next_id = stores.prekey.next_id.max(1);
        let id = stores.prekey.next_id;
        stores.prekey.next_id = id.checked_add(1).context("pre-key ids exhausted")?;
        let pair = KeyPair::generate(&mut crate::rng());
        stores.prekey.prekeys.insert(id, PreKeyRecord::new(PreKeyId::from(id), &pair).serialize()?);
        out.push(OneTimePreKey { id, public_key: pair.public_key.serialize().to_vec() });
    }
    Ok(out)
}

/// What `Authenticate` (and an account's `Keys` step) carries, read back from
/// the stores so one-time keys an earlier session used are not offered again.
pub fn bundle(stores: &SignalStores) -> anyhow::Result<PreKeyBundleData> {
    let signed = stores.signed_prekey.signed_prekeys.get(&SIGNED_PREKEY_ID).context("signed pre-key missing")?;
    let signed = SignedPreKeyRecord::deserialize(signed)?;
    let kyber = stores.kyber.keys.get(&KYBER_PREKEY_ID).context("Kyber pre-key missing")?;
    let kyber = KyberPreKeyRecord::deserialize(kyber)?;
    let prekeys = stores
        .prekey
        .prekeys
        .iter()
        .map(|(&id, bytes)| Ok(OneTimePreKey { id, public_key: PreKeyRecord::deserialize(bytes)?.public_key()?.serialize().to_vec() }))
        .collect::<anyhow::Result<_>>()?;
    Ok(PreKeyBundleData {
        registration_id: stores.identity.registration_id,
        device_id: 1,
        identity_key: stores.identity.key_pair.public_key.clone(),
        signed_prekey_id: SIGNED_PREKEY_ID,
        signed_prekey: signed.public_key()?.serialize().to_vec(),
        signed_prekey_signature: signed.signature()?,
        prekeys,
        kyber_prekey_id: KYBER_PREKEY_ID,
        kyber_prekey: kyber.public_key()?.serialize().to_vec(),
        kyber_prekey_signature: kyber.signature()?,
    })
}
