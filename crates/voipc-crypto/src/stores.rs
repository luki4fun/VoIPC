//! In-memory implementations of Signal Protocol store traits.
//!
//! These wrap libsignal's `InMem*` stores and are persisted to disk
//! via the persistence module.

use std::collections::HashMap;

use libsignal_protocol::{
    Direction, GenericSignedPreKey, IdentityKey, IdentityKeyPair, IdentityKeyStore,
    KyberPreKeyId, KyberPreKeyRecord, KyberPreKeyStore, PreKeyId, PreKeyRecord, PreKeyStore,
    ProtocolAddress, SenderKeyRecord, SenderKeyStore, SessionRecord, SessionStore,
    SignalProtocolError, SignedPreKeyId, SignedPreKeyRecord, SignedPreKeyStore,
};
use serde::{Deserialize, Serialize};

use crate::identity::SerializableIdentityKeyPair;

/// All Signal Protocol stores bundled together.
#[derive(Serialize, Deserialize)]
pub struct SignalStores {
    pub identity: VoipcIdentityStore,
    pub prekey: VoipcPreKeyStore,
    pub signed_prekey: VoipcSignedPreKeyStore,
    pub session: VoipcSessionStore,
    pub sender_key: VoipcSenderKeyStore,
    pub kyber: VoipcKyberPreKeyStore,
}

impl SignalStores {
    pub fn new(identity_key_pair: &IdentityKeyPair, registration_id: u32) -> Self {
        Self {
            identity: VoipcIdentityStore {
                key_pair: SerializableIdentityKeyPair::from_identity_key_pair(identity_key_pair),
                registration_id,
                known_identities: HashMap::new(),
            },
            prekey: VoipcPreKeyStore {
                prekeys: HashMap::new(),
            },
            signed_prekey: VoipcSignedPreKeyStore {
                signed_prekeys: HashMap::new(),
            },
            session: VoipcSessionStore {
                sessions: HashMap::new(),
            },
            sender_key: VoipcSenderKeyStore {
                keys: HashMap::new(),
            },
            kyber: VoipcKyberPreKeyStore,
        }
    }
}

// ── Identity Key Store ──────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
pub struct VoipcIdentityStore {
    pub key_pair: SerializableIdentityKeyPair,
    pub registration_id: u32,
    /// Remote users' identity keys: "name.device_id" -> serialized public key
    pub known_identities: HashMap<String, Vec<u8>>,
}

fn address_key(addr: &ProtocolAddress) -> String {
    format!("{}.{}", addr.name(), addr.device_id())
}

#[async_trait::async_trait(?Send)]
impl IdentityKeyStore for VoipcIdentityStore {
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair, SignalProtocolError> {
        self.key_pair
            .to_identity_key_pair()
            .map_err(|e| SignalProtocolError::InvalidArgument(e.to_string()))
    }

    async fn get_local_registration_id(&self) -> Result<u32, SignalProtocolError> {
        Ok(self.registration_id)
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<bool, SignalProtocolError> {
        let key = address_key(address);
        let serialized = identity.serialize().to_vec();
        let existing = self.known_identities.insert(key, serialized.clone());
        // Return true if the identity key changed (trust-on-first-use)
        Ok(existing.map_or(false, |old| old != serialized))
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        _direction: Direction,
    ) -> Result<bool, SignalProtocolError> {
        let key = address_key(address);
        match self.known_identities.get(&key) {
            None => Ok(true), // Trust on first use
            Some(stored) => Ok(stored == &identity.serialize().to_vec()),
        }
    }

    async fn get_identity(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<IdentityKey>, SignalProtocolError> {
        let key = address_key(address);
        match self.known_identities.get(&key) {
            None => Ok(None),
            Some(bytes) => Ok(Some(IdentityKey::decode(bytes)?)),
        }
    }
}

// ── Kyber Pre-Key Store ────────────────────────────────────────────────
// VoIPC does not use post-quantum (Kyber) keys, but the Signal Protocol
// decrypt functions require a KyberPreKeyStore. This is a no-op stub.

#[derive(Serialize, Deserialize)]
pub struct VoipcKyberPreKeyStore;

#[async_trait::async_trait(?Send)]
impl KyberPreKeyStore for VoipcKyberPreKeyStore {
    async fn get_kyber_pre_key(
        &self,
        _kyber_prekey_id: KyberPreKeyId,
    ) -> Result<KyberPreKeyRecord, SignalProtocolError> {
        Err(SignalProtocolError::InvalidKyberPreKeyId)
    }

    async fn save_kyber_pre_key(
        &mut self,
        _kyber_prekey_id: KyberPreKeyId,
        _record: &KyberPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        Ok(())
    }

    async fn mark_kyber_pre_key_used(
        &mut self,
        _kyber_prekey_id: KyberPreKeyId,
    ) -> Result<(), SignalProtocolError> {
        Ok(())
    }
}

// ── Pre-Key Store ───────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
pub struct VoipcPreKeyStore {
    /// pre_key_id -> serialized PreKeyRecord
    pub prekeys: HashMap<u32, Vec<u8>>,
}

#[async_trait::async_trait(?Send)]
impl PreKeyStore for VoipcPreKeyStore {
    async fn get_pre_key(&self, id: PreKeyId) -> Result<PreKeyRecord, SignalProtocolError> {
        let bytes = self
            .prekeys
            .get(&id.into())
            .ok_or(SignalProtocolError::InvalidPreKeyId)?;
        PreKeyRecord::deserialize(bytes)
    }

    async fn save_pre_key(
        &mut self,
        id: PreKeyId,
        record: &PreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        self.prekeys.insert(id.into(), record.serialize()?);
        Ok(())
    }

    async fn remove_pre_key(&mut self, id: PreKeyId) -> Result<(), SignalProtocolError> {
        self.prekeys.remove(&id.into());
        Ok(())
    }
}

// ── Signed Pre-Key Store ────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
pub struct VoipcSignedPreKeyStore {
    /// signed_pre_key_id -> serialized SignedPreKeyRecord
    pub signed_prekeys: HashMap<u32, Vec<u8>>,
}

#[async_trait::async_trait(?Send)]
impl SignedPreKeyStore for VoipcSignedPreKeyStore {
    async fn get_signed_pre_key(
        &self,
        id: SignedPreKeyId,
    ) -> Result<SignedPreKeyRecord, SignalProtocolError> {
        let bytes = self
            .signed_prekeys
            .get(&id.into())
            .ok_or(SignalProtocolError::InvalidSignedPreKeyId)?;
        SignedPreKeyRecord::deserialize(bytes)
    }

    async fn save_signed_pre_key(
        &mut self,
        id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        self.signed_prekeys.insert(id.into(), record.serialize()?);
        Ok(())
    }
}

// ── Session Store ───────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
pub struct VoipcSessionStore {
    /// "name.device_id" -> serialized SessionRecord
    pub sessions: HashMap<String, Vec<u8>>,
}

#[async_trait::async_trait(?Send)]
impl SessionStore for VoipcSessionStore {
    async fn load_session(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<SessionRecord>, SignalProtocolError> {
        let key = address_key(address);
        match self.sessions.get(&key) {
            None => Ok(None),
            Some(bytes) => Ok(Some(SessionRecord::deserialize(bytes)?)),
        }
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> Result<(), SignalProtocolError> {
        let key = address_key(address);
        self.sessions.insert(key, record.serialize()?);
        Ok(())
    }
}

// ── Sender Key Store ────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
pub struct VoipcSenderKeyStore {
    /// "sender_name.sender_device_id::distribution_id" -> serialized SenderKeyRecord
    pub keys: HashMap<String, Vec<u8>>,
}

fn sender_key_key(sender: &ProtocolAddress, distribution_id: uuid::Uuid) -> String {
    format!(
        "{}.{}::{}",
        sender.name(),
        sender.device_id(),
        distribution_id
    )
}

#[async_trait::async_trait(?Send)]
impl SenderKeyStore for VoipcSenderKeyStore {
    async fn store_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: uuid::Uuid,
        record: &SenderKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        let key = sender_key_key(sender, distribution_id);
        self.keys.insert(key, record.serialize()?);
        Ok(())
    }

    async fn load_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: uuid::Uuid,
    ) -> Result<Option<SenderKeyRecord>, SignalProtocolError> {
        let key = sender_key_key(sender, distribution_id);
        match self.keys.get(&key) {
            None => Ok(None),
            Some(bytes) => Ok(Some(SenderKeyRecord::deserialize(bytes)?)),
        }
    }
}
