//! In-memory implementations of Signal Protocol store traits.
//!
//! These wrap libsignal's `InMem*` stores and are persisted to disk
//! via the persistence module.

use std::collections::{HashMap, HashSet, VecDeque};

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
                reads: Reads::default(),
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
    /// What was read on each record, kept past the record (`Reads`). Saved with the records it
    /// guards, should these stores ever be saved: nothing does today (lib.rs: Signal state is
    /// deliberately not persisted; no host serializes `SignalStores`), and records brought
    /// back without it would open again what was read on them.
    #[serde(default)]
    reads: Reads,
}

/// Sender keys a device holds at most: everyone in every channel adds up on a long
/// connection, and one that went comes back by `KeyWanted`.
const SENDER_KEYS_HELD: usize = 5000;

// ── What was read ───────────────────────────────────────────────────────
//
// libsignal keeps what a reader read only in a chain's state: its chain key moved past it, or
// a skipped message key it holds. A state it drops (five a record, the one taken least lately
// first: `SenderKeyRecord::add_sender_key_state`), or a record the store drops (`evict`), takes
// that along, and the same key handed again starts afresh at its position. A relay that kept a
// copy of the key and the posts could then open again what was read, an old edit with it
// (review 4 of CI soak 45269825608). So the reader keeps it apart, by record, chain and
// position, and `group::decrypt_group_message` refuses a post read before as libsignal refuses
// a duplicate, whatever libsignal holds by then. A chain is known by its id alone, which
// libsignal draws at random (31 bits): should a writer's new chain draw the id of one of their
// sixteen kept here, about 2^-27 a chain, its posts at positions read on the old one are refused.
//
// Two ways past it are left, as before it (review 5). Both need a key the relay held back, and
// a writer with an account. What was read lives in this connection's stores, and a record is
// filed under the user id the relay names the writer by:
// - A relay that names the same account under another id moves the reader's session with it
//   (`ChannelKeying::find_session`). The key then goes into a new record, with nothing read
//   in it.
// - A reconnect starts new stores but keeps the pairwise sessions. A key held back from before
//   then opens on the new connection.
// Either way, a post read before can open once more. Nothing is readable that was not.

/// Chains of one record whose reads are kept, the one read last kept longest. More than
/// libsignal's five states: while it holds a chain, at most eight others of the record can be
/// read (four it held before, four taken after; a fifth drops it), so with keys handed in
/// order the reads of no chain it can still open are forgotten. Past this many, those of the
/// chain read least lately are: a relay that kept a copy of its key, and saw this device read
/// sixteen newer chains of that writer in that channel since, can hand it back and replay its
/// posts, each once more. Forcing a chain a post takes the writer's posts as well as the
/// relay's exits.
const READ_CHAINS: usize = 16;
/// Runs of positions read on one chain, apart from one another: a post that never came leaves a
/// gap between two. Past this many, the lowest run folds into everything below it, gaps and
/// all, so a post in one of those can no longer open. Only a relay sends a writer's posts out
/// of order, and libsignal itself keeps no more than 2000 skipped keys of a chain
/// (`MAX_MESSAGE_KEYS`).
const READ_RUNS: usize = 8;
/// Records whose reads are kept: twice what the store holds, so what was read on one stays read
/// once `evict` dropped it and a `KeyWanted` brought its key back. Past this many, the reads of
/// the record read least lately go, of one the store no longer holds first. So at most
/// `READ_RECORDS` × `READ_CHAINS` chains of `READ_RUNS` + 1 runs of 8 bytes, about 2 KB a
/// record and 20 MB in all, which takes over a million posts read across gaps; a record read
/// in order holds one run, a few hundred bytes. libsignal's own records may hold 2000 skipped
/// keys a state, far more.
const READ_RECORDS: usize = 2 * SENDER_KEYS_HELD;

/// What was read, by record (`sender_key_key`).
#[derive(Serialize, Deserialize, Default)]
struct Reads {
    records: HashMap<String, RecordReads>,
    /// Counts the posts read, to tell which record was read least lately.
    clock: u64,
}

#[derive(Serialize, Deserialize, Default)]
struct RecordReads {
    /// `Reads::clock` at its last read.
    at: u64,
    /// The chain read last first, at most `READ_CHAINS`.
    chains: VecDeque<ChainReads>,
}

#[derive(Serialize, Deserialize)]
struct ChainReads {
    chain_id: u32,
    /// Every position below this counts as read.
    below: u64,
    /// The positions read past `below`, as `(first, last)` runs going up, at most `READ_RUNS`,
    /// none touching another or `below`.
    runs: Vec<(u32, u32)>,
}

impl ChainReads {
    fn new(chain_id: u32) -> Self {
        Self {
            chain_id,
            below: 0,
            runs: Vec::new(),
        }
    }

    fn has(&self, iteration: u32) -> bool {
        u64::from(iteration) < self.below
            || self
                .runs
                .iter()
                .any(|&(first, last)| first <= iteration && iteration <= last)
    }

    fn add(&mut self, iteration: u32) {
        if self.has(iteration) {
            return;
        }
        let at = self.runs.partition_point(|&(first, _)| first < iteration);
        let after = at > 0 && u64::from(self.runs[at - 1].1) + 1 == u64::from(iteration);
        let before = at < self.runs.len() && u64::from(iteration) + 1 == u64::from(self.runs[at].0);
        match (after, before) {
            (true, true) => {
                self.runs[at - 1].1 = self.runs[at].1;
                self.runs.remove(at);
            }
            (true, false) => self.runs[at - 1].1 = iteration,
            (false, true) => self.runs[at].0 = iteration,
            (false, false) => {
                // Room for one past the cap, once: it folds at once
                if self.runs.capacity() == 0 {
                    self.runs.reserve_exact(READ_RUNS + 1);
                }
                self.runs.insert(at, (iteration, iteration));
            }
        }
        // A run that reaches `below` is part of it
        if let Some(&(first, last)) = self.runs.first() {
            if u64::from(first) <= self.below {
                self.below = u64::from(last) + 1;
                self.runs.remove(0);
            }
        }
        if self.runs.len() > READ_RUNS {
            let (_, last) = self.runs.remove(0);
            self.below = u64::from(last) + 1;
        }
    }
}

impl Reads {
    fn was_read(&self, key: &str, chain_id: u32, iteration: u32) -> bool {
        self.records.get(key).is_some_and(|record| {
            record
                .chains
                .iter()
                .any(|chain| chain.chain_id == chain_id && chain.has(iteration))
        })
    }

    /// `held`: whether the store still holds a record, whose reads go last.
    fn mark(&mut self, key: String, chain_id: u32, iteration: u32, held: impl Fn(&str) -> bool) {
        self.clock += 1;
        let record = self.records.entry(key).or_default();
        record.at = self.clock;
        let chain = match record.chains.iter().position(|c| c.chain_id == chain_id) {
            Some(i) => record.chains.remove(i).expect("just found"),
            None => {
                if record.chains.len() >= READ_CHAINS {
                    record.chains.pop_back();
                }
                ChainReads::new(chain_id)
            }
        };
        record.chains.push_front(chain);
        if let Some(chain) = record.chains.front_mut() {
            chain.add(iteration);
        }
        if self.records.len() > READ_RECORDS {
            let mut least: Option<(&String, u64)> = None;
            let mut least_gone: Option<(&String, u64)> = None;
            for (key, record) in &self.records {
                if least.is_none_or(|(_, at)| record.at < at) {
                    least = Some((key, record.at));
                }
                if !held(key) && least_gone.is_none_or(|(_, at)| record.at < at) {
                    least_gone = Some((key, record.at));
                }
            }
            if let Some(key) = least_gone.or(least).map(|(key, _)| key.clone()) {
                self.records.remove(&key);
            }
        }
    }
}
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
    /// What was read on it stays read (`was_read`).
    pub fn forget(&mut self, sender: &ProtocolAddress, distribution_id: uuid::Uuid) {
        let key = sender_key_key(sender, distribution_id);
        self.keys.remove(&key);
        self.used.remove(&key);
    }

    /// Whether the post at `iteration` of `chain_id`, on `sender`'s record for
    /// `distribution_id`, was read here: so even if libsignal dropped that chain's state, or
    /// `evict` the record, and the key came back since, within the bounds of `READ_CHAINS`,
    /// `READ_RUNS` and `READ_RECORDS`.
    pub fn was_read(
        &self,
        sender: &ProtocolAddress,
        distribution_id: uuid::Uuid,
        chain_id: u32,
        iteration: u32,
    ) -> bool {
        self.reads.was_read(
            &sender_key_key(sender, distribution_id),
            chain_id,
            iteration,
        )
    }

    /// A post opened: it stays read (`was_read`).
    pub fn mark_read(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: uuid::Uuid,
        chain_id: u32,
        iteration: u32,
    ) {
        let keys = &self.keys;
        self.reads.mark(
            sender_key_key(sender, distribution_id),
            chain_id,
            iteration,
            |key| keys.contains_key(key),
        );
    }

    /// Past the limit, the one least recently used, if it is old enough to go. What was read
    /// on it stays read (`READ_RECORDS`).
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
            reads: Reads::default(),
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

    // ── What was read ───────────────────────────────────────────────────

    /// Positions read in order fold into `below`; posts that never came leave gaps, which
    /// stay unread until filled, and past `READ_RUNS` runs the lowest folds in, its gaps too.
    #[test]
    fn a_chains_reads_go_in_runs_and_the_lowest_folds_past_the_cap() {
        let mut c = ChainReads::new(1);
        for i in 0..5 {
            c.add(i);
        }
        assert_eq!((c.below, c.runs.len()), (5, 0));
        // Every other position from 10: a gap before each
        let runs = READ_RUNS as u32;
        for k in 0..runs {
            c.add(10 + 2 * k);
        }
        assert_eq!(c.runs.len(), READ_RUNS);
        assert!(c.has(4) && c.has(10) && c.has(12));
        assert!(!c.has(5) && !c.has(9) && !c.has(11), "gaps stay unread");
        // Filling a gap joins two runs, and a run that reaches `below` folds into it
        c.add(11);
        assert_eq!(c.runs.len(), READ_RUNS - 1);
        c.add(11 + 2 * runs);
        assert_eq!(c.runs.len(), READ_RUNS);
        assert!(!c.has(5), "{READ_RUNS} runs: nothing folds");
        (5..10).for_each(|i| c.add(i));
        assert_eq!(c.below, 13, "0..=12 in a row");
        assert_eq!(c.runs.len(), READ_RUNS - 1);
        // One run past the cap: the lowest goes into `below`, the gap before it with it
        let mut d = ChainReads::new(1);
        for k in 0..=runs {
            d.add(10 + 2 * k);
        }
        assert_eq!(d.runs.len(), READ_RUNS);
        assert_eq!(d.below, 11);
        assert!(
            d.has(0) && d.has(10),
            "folded: the gap below counts as read"
        );
        assert!(!d.has(11) && d.has(12));
        // The last position there is
        d.add(u32::MAX);
        assert!(d.has(u32::MAX) && !d.has(u32::MAX - 1));
    }

    /// A record keeps the reads of the sixteen chains read last: one read again stays.
    #[test]
    fn a_records_reads_keep_the_chains_read_last() {
        let mut r = Reads::default();
        let held = |_: &str| true;
        let chains = READ_CHAINS as u32;
        for chain in 0..chains {
            r.mark("w".into(), chain, 0, held);
        }
        assert!(r.was_read("w", 0, 0), "the first of {READ_CHAINS}");
        assert!(!r.was_read("w", 0, 1) && !r.was_read("v", 0, 0));
        r.mark("w".into(), 0, 1, held);
        r.mark("w".into(), chains, 0, held);
        assert!(
            r.was_read("w", 0, 0) && r.was_read("w", 0, 1),
            "read again lately"
        );
        assert!(!r.was_read("w", 1, 0), "the chain read least lately went");
        assert!(r.was_read("w", 2, 0) && r.was_read("w", chains, 0));
        assert_eq!(r.records["w"].chains.len(), READ_CHAINS);
    }

    /// Reads outlive their record, up to `READ_RECORDS`: past it, the reads of the record read
    /// least lately go, of one the store no longer holds first.
    #[test]
    fn reads_outlive_their_record_and_the_least_lately_read_go_past_the_limit() {
        let mut r = Reads::default();
        let held = |key: &str| key == "r0";
        for n in 0..READ_RECORDS {
            r.mark(format!("r{n}"), 1, 0, held);
        }
        assert_eq!(r.records.len(), READ_RECORDS);
        assert!(r.was_read("r0", 1, 0) && r.was_read("r1", 1, 0));
        r.mark("new".into(), 1, 0, held);
        assert_eq!(r.records.len(), READ_RECORDS);
        assert!(r.was_read("r0", 1, 0), "still held by the store");
        assert!(
            !r.was_read("r1", 1, 0),
            "read least lately, and gone from the store"
        );
        assert!(r.was_read("r2", 1, 0) && r.was_read("new", 1, 0));
        // All held: the least lately read goes anyway
        r.mark("newer".into(), 1, 0, |_| true);
        assert!(!r.was_read("r0", 1, 0) && r.was_read("r2", 1, 0));
    }

    /// A record read again lately is not the one that goes past `READ_RECORDS`, though it was
    /// first read before all the others (review 5).
    #[test]
    fn a_record_read_again_lately_stays_past_the_limit() {
        let mut r = Reads::default();
        let held = |_: &str| false;
        for n in 0..READ_RECORDS {
            r.mark(format!("r{n}"), 1, 0, held);
        }
        r.mark("r0".into(), 1, 1, held);
        r.mark("new".into(), 1, 0, held);
        assert!(r.was_read("r0", 1, 0), "read again lately");
        assert!(!r.was_read("r1", 1, 0), "read least lately");
    }

    /// `evict` drops a record, not what was read on it.
    #[test]
    fn what_was_read_stays_when_evict_drops_the_record() {
        let mut s = store(SENDER_KEYS_HELD + 1, 0);
        s.reads.mark("k0".into(), 3, 7, |_| true);
        s.evict(u64::MAX);
        assert!(!s.keys.contains_key("k0"));
        assert!(s.reads.was_read("k0", 3, 7));
    }
}
