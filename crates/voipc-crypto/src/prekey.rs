//! Pre-key and signed pre-key generation.
//!
//! Pre-keys are one-time-use Curve25519 key pairs used in the X3DH
//! key agreement protocol. Signed pre-keys are medium-term keys
//! signed by the identity key.

use libsignal_protocol::{
    GenericSignedPreKey, IdentityKeyPair, KeyPair, PreKeyId, PreKeyRecord, PreKeyStore,
    SignedPreKeyId, SignedPreKeyRecord, SignedPreKeyStore, Timestamp,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::stores::SignalStores;

/// Number of one-time pre-keys to generate initially.
pub const INITIAL_PREKEY_COUNT: u32 = 100;

/// Threshold below which we should replenish pre-keys.
pub const PREKEY_REPLENISH_THRESHOLD: u32 = 10;

/// A set of pre-keys ready to be uploaded to the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreKeySet {
    pub registration_id: u32,
    pub device_id: u32,
    pub signed_prekey_id: u32,
    pub signed_prekey_public: Vec<u8>,
    pub signed_prekey_signature: Vec<u8>,
    pub one_time_prekeys: Vec<SerializablePreKey>,
}

/// A one-time pre-key's public portion for protocol transmission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializablePreKey {
    pub id: u32,
    pub public_key: Vec<u8>,
}

/// Generate the initial set of pre-keys and store them.
pub async fn generate_prekeys(
    stores: &mut SignalStores,
    identity_key_pair: &IdentityKeyPair,
    start_id: u32,
    count: u32,
) -> anyhow::Result<PreKeySet> {
    let mut one_time_prekeys = Vec::with_capacity(count as usize);

    // Generate one-time pre-keys
    for i in 0..count {
        let id = PreKeyId::from(start_id + i);
        let key_pair = KeyPair::generate(&mut OsRng);
        let record = PreKeyRecord::new(id, &key_pair);
        stores.prekey.save_pre_key(id, &record).await?;
        one_time_prekeys.push(SerializablePreKey {
            id: id.into(),
            public_key: key_pair.public_key.serialize().to_vec(),
        });
    }

    // Generate signed pre-key
    let signed_prekey_id = SignedPreKeyId::from(1u32);
    let signed_key_pair = KeyPair::generate(&mut OsRng);
    let timestamp_millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let timestamp = Timestamp::from_epoch_millis(timestamp_millis);

    let signature = identity_key_pair
        .private_key()
        .calculate_signature(&signed_key_pair.public_key.serialize(), &mut OsRng)?;

    let signed_record = SignedPreKeyRecord::new(
        signed_prekey_id,
        timestamp,
        &signed_key_pair,
        &signature,
    );
    stores
        .signed_prekey
        .save_signed_pre_key(signed_prekey_id, &signed_record)
        .await?;

    Ok(PreKeySet {
        registration_id: stores.identity.registration_id,
        device_id: 1,
        signed_prekey_id: signed_prekey_id.into(),
        signed_prekey_public: signed_key_pair.public_key.serialize().to_vec(),
        signed_prekey_signature: signature.to_vec(),
        one_time_prekeys,
    })
}

/// Generate additional one-time pre-keys to replenish supply.
pub async fn generate_replenish_prekeys(
    stores: &mut SignalStores,
    start_id: u32,
    count: u32,
) -> anyhow::Result<Vec<SerializablePreKey>> {
    let mut prekeys = Vec::with_capacity(count as usize);

    for i in 0..count {
        let id = PreKeyId::from(start_id + i);
        let key_pair = KeyPair::generate(&mut OsRng);
        let record = PreKeyRecord::new(id, &key_pair);
        stores.prekey.save_pre_key(id, &record).await?;
        prekeys.push(SerializablePreKey {
            id: id.into(),
            public_key: key_pair.public_key.serialize().to_vec(),
        });
    }

    Ok(prekeys)
}
