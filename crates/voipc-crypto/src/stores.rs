//! In-memory implementations of Signal Protocol store traits.
//!
//! These wrap libsignal's `InMem*` stores and are persisted to disk
//! via the persistence module.

use std::collections::{HashMap, HashSet};

use libsignal_protocol::{
    CiphertextMessageType, Direction, GenericSignedPreKey, IdentityChange, IdentityKey,
    IdentityKeyPair, IdentityKeyStore, KyberPreKeyId, KyberPreKeyRecord, KyberPreKeyStore,
    PreKeyId, PreKeyRecord, PreKeyStore, ProtocolAddress, PublicKey, SenderKeyRecord,
    SenderKeyStore, SessionRecord, SessionStore, SignalProtocolError, SignedPreKeyId,
    SignedPreKeyRecord, SignedPreKeyStore,
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
    /// Our user id on this connection, once `Authenticated` named it: libsignal
    /// binds both parties' addresses into every message.
    pub own_user_id: u32,
    /// Session keys renewed and not yet gone (`prekey::renew_session_keys`).
    #[serde(default)]
    pub retiring: Vec<crate::prekey::RetiringKeys>,
}

impl SignalStores {
    pub fn new(identity_key_pair: &IdentityKeyPair, registration_id: u32) -> Self {
        Self {
            identity: VoipcIdentityStore {
                key_pair: SerializableIdentityKeyPair::from_identity_key_pair(identity_key_pair),
                registration_id,
                known_identities: HashMap::new(),
                seen: Vec::new(),
            },
            prekey: VoipcPreKeyStore {
                prekeys: HashMap::new(),
                next_id: 1,
            },
            signed_prekey: VoipcSignedPreKeyStore {
                signed_prekeys: HashMap::new(),
                current: 0,
            },
            session: VoipcSessionStore {
                sessions: HashMap::new(),
            },
            sender_key: VoipcSenderKeyStore {
                keys: HashMap::new(),
                used: HashMap::new(),
            },
            kyber: VoipcKyberPreKeyStore::default(),
            own_user_id: 0,
            retiring: Vec::new(),
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
    /// Identities stored since the host last looked (`take_seen`), new or
    /// changed, in either direction: a session a peer opens with a PreKey
    /// message stores one too, and only the host knows the account pins to
    /// check it against.
    #[serde(skip, default)]
    pub seen: Vec<(String, Vec<u8>)>,
}

impl VoipcIdentityStore {
    /// `(user id, identity key)` for each identity stored since the last call.
    pub fn take_seen(&mut self) -> Vec<(u32, Vec<u8>)> {
        std::mem::take(&mut self.seen)
            .into_iter()
            .filter_map(|(name, key)| Some((crate::session::user_of(&name)?, key)))
            .collect()
    }

    /// The identity key the session with `user_id` runs on, if there is one.
    pub fn identity_of(&self, user_id: u32) -> Option<&[u8]> {
        let a = crate::session::user_address(user_id);
        self.known_identities
            .get(&address_key(&a))
            .map(Vec::as_slice)
    }
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
    ) -> Result<IdentityChange, SignalProtocolError> {
        let key = address_key(address);
        let serialized = identity.serialize().to_vec();
        let existing = self.known_identities.insert(key, serialized.clone());
        if existing.as_ref() != Some(&serialized) {
            self.seen
                .push((address.name().to_string(), serialized.clone()));
        }
        // Trust on first use: only a different key replaces one
        Ok(if existing.is_some_and(|old| old != serialized) {
            IdentityChange::ReplacedExisting
        } else {
            IdentityChange::NewOrUnchanged
        })
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

/// The post-quantum half of a session start (PQXDH). One last-resort key at a
/// time, kept until it is renewed and a minute after: a PreKey message that uses
/// it with a base key seen before is a replay and refused, and once it has gone
/// no message can use it at all.
#[derive(Serialize, Deserialize, Default)]
pub struct VoipcKyberPreKeyStore {
    /// kyber_pre_key_id -> serialized KyberPreKeyRecord
    pub keys: HashMap<u32, Vec<u8>>,
    /// The one a bundle offers now.
    #[serde(default)]
    pub current: u32,
    /// (kyber id, signed pre-key id, base key) of every session started on it
    pub used: HashSet<(u32, u32, Vec<u8>)>,
}

#[async_trait::async_trait(?Send)]
impl KyberPreKeyStore for VoipcKyberPreKeyStore {
    async fn get_kyber_pre_key(
        &self,
        id: KyberPreKeyId,
    ) -> Result<KyberPreKeyRecord, SignalProtocolError> {
        let bytes = self
            .keys
            .get(&id.into())
            .ok_or(SignalProtocolError::InvalidKyberPreKeyId)?;
        KyberPreKeyRecord::deserialize(bytes)
    }

    async fn save_kyber_pre_key(
        &mut self,
        id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        self.keys.insert(id.into(), record.serialize()?);
        Ok(())
    }

    async fn mark_kyber_pre_key_used(
        &mut self,
        id: KyberPreKeyId,
        ec_prekey_id: SignedPreKeyId,
        base_key: &PublicKey,
    ) -> Result<(), SignalProtocolError> {
        if !self.used.insert((
            id.into(),
            ec_prekey_id.into(),
            base_key.serialize().to_vec(),
        )) {
            return Err(SignalProtocolError::InvalidMessage(
                CiphertextMessageType::PreKey,
                "reused base key".into(),
            ));
        }
        Ok(())
    }
}

// ── Pre-Key Store ───────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
pub struct VoipcPreKeyStore {
    /// pre_key_id -> serialized PreKeyRecord
    pub prekeys: HashMap<u32, Vec<u8>>,
    /// The id the next new one-time key gets (`prekey::more_prekeys`)
    pub next_id: u32,
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
    /// The one a bundle offers now.
    #[serde(default)]
    pub current: u32,
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

impl VoipcSessionStore {
    fn key_of(user_id: u32) -> String {
        address_key(&crate::session::user_address(user_id))
    }

    pub fn has(&self, user_id: u32) -> bool {
        self.sessions.contains_key(&Self::key_of(user_id))
    }

    /// A session record, out of the store.
    pub fn take(&mut self, user_id: u32) -> Option<Vec<u8>> {
        self.sessions.remove(&Self::key_of(user_id))
    }

    /// A record from another connection, under who the peer is on this one. libsignal
    /// binds no address for a `user_N` name, only the two identity keys.
    pub fn put(&mut self, user_id: u32, record: Vec<u8>) {
        self.sessions.insert(Self::key_of(user_id), record);
    }

    /// Every session, by the user id it runs under.
    pub fn by_user(&self) -> impl Iterator<Item = (u32, &[u8])> {
        self.sessions.iter().filter_map(|(key, record)| {
            let name = key.strip_suffix(".1")?;
            Some((crate::session::user_of(name)?, record.as_slice()))
        })
    }
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
    /// When each last moved, for `evict`.
    #[serde(skip, default)]
    used: HashMap<String, u64>,
}

/// Sender keys a device holds at most: everyone in every channel adds up on a long
/// connection, and one that went comes back by `KeyWanted`.
const SENDER_KEYS_HELD: usize = 5000;
/// One this young is not evicted, since a post on it would be lost: a chain's longest life.
const SENDER_KEY_EVICT_AFTER_MS: u64 = 3_600_000;

fn sender_key_key(sender: &ProtocolAddress, distribution_id: uuid::Uuid) -> String {
    format!(
        "{}.{}::{}",
        sender.name(),
        sender.device_id(),
        distribution_id
    )
}

impl VoipcSenderKeyStore {
    /// Drop one sender key. Used to rotate our own after a member leaves;
    /// libsignal has no API for it because it never expects a key to go away.
    pub fn forget(&mut self, sender: &ProtocolAddress, distribution_id: uuid::Uuid) {
        let key = sender_key_key(sender, distribution_id);
        self.keys.remove(&key);
        self.used.remove(&key);
    }

    /// Past the limit, the one least recently used, if it is old enough to go.
    fn evict(&mut self, now: u64) {
        if self.keys.len() <= SENDER_KEYS_HELD {
            return;
        }
        let oldest = self
            .used
            .iter()
            .filter(|(_, at)| now.saturating_sub(**at) >= SENDER_KEY_EVICT_AFTER_MS)
            .min_by_key(|(_, at)| **at)
            .map(|(key, _)| key.clone());
        if let Some(key) = oldest {
            self.keys.remove(&key);
            self.used.remove(&key);
        }
    }
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
        let now = crate::time::now_millis();
        self.used.insert(key.clone(), now);
        self.keys.insert(key, record.serialize()?);
        self.evict(now);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn store(n: usize, at: u64) -> VoipcSenderKeyStore {
        let mut s = VoipcSenderKeyStore {
            keys: HashMap::new(),
            used: HashMap::new(),
        };
        for i in 0..n {
            s.keys.insert(format!("k{i}"), vec![0]);
            s.used.insert(format!("k{i}"), at + i as u64);
        }
        s
    }

    #[test]
    fn reader_sender_keys_go_least_used_first_past_the_limit() {
        let mut s = store(SENDER_KEYS_HELD + 2, 0);
        s.evict(SENDER_KEY_EVICT_AFTER_MS + SENDER_KEYS_HELD as u64 + 10);
        assert_eq!(s.keys.len(), SENDER_KEYS_HELD + 1);
        assert!(!s.keys.contains_key("k0"), "the oldest");
        assert!(s.keys.contains_key("k1"));
        // At the limit nothing goes, however old
        let mut at = store(SENDER_KEYS_HELD, 0);
        at.evict(u64::MAX);
        assert_eq!(at.keys.len(), SENDER_KEYS_HELD);
    }

    /// A post on one this young would be lost, and a raid of fake writers could cost a real
    /// writer's: the count may run over rather than that.
    #[test]
    fn a_sender_key_younger_than_a_chains_life_is_not_evicted() {
        let mut s = store(SENDER_KEYS_HELD + 10, 1_000);
        s.evict(1_000 + SENDER_KEY_EVICT_AFTER_MS - 1);
        assert_eq!(s.keys.len(), SENDER_KEYS_HELD + 10);
    }
}
