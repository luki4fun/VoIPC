//! In-memory implementations of Signal Protocol store traits.
//!
//! These wrap libsignal's `InMem*` stores and are persisted to disk
//! via the persistence module.

use std::collections::{BTreeMap, HashMap, HashSet};

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
    /// What was read, kept apart from the records (`Reads`). Saved with them, should these
    /// stores ever be saved: nothing does today (lib.rs: Signal state is deliberately not
    /// persisted; no host serializes `SignalStores`), and records brought back without it would
    /// open again what was read on them.
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
// (review 4 of CI soak 45269825608). So the reader keeps it apart, by chain and position, and
// `group::open_once` refuses a post read before as libsignal refuses a duplicate, whatever
// libsignal holds by then. Both paths open posts by it: the old sender-key path
// (`group::decrypt_group_message`) and the group key's (group_state/reader.rs `open`).
//
// A chain is known by the public key its posts are signed with (`Signer`), read out of the
// state libsignal is about to open the post by (`signer_of`). The writer draws that key pair
// at random for each chain, only the writer's own key message names it, inside a pairwise
// session or a writer blob, and the relay can neither rename it nor make one up. So nothing the
// relay names counts: not the user id it files the record under, nor which record. A relay that
// names a writer's account under another id, which moves the reader's session there
// (`ChannelKeying::find_session`), installs the old chain in a new record, and its posts are
// still read. Nor can two writers' chains, or a writer's two, be taken for each other, as by
// the 31-bit chain id they also carry. Every state libsignal holds has its key in it, however
// it came (a wrap, a writer blob, our own `create`): nothing is kept beside the records to
// miss one, and a post that opens under a state not found so is refused (`open_once`).
//
// What was read goes with the sessions a connection hands to the next (`KeptSessions`, which
// both apps keep in memory for an account across a reconnect, `kept_reads` and
// `adopt_reads`): a key held back from before then opens nothing read before on the new
// connection either.
//
// Under the group key a chain is kept read by the writer its blob binds too (`Signer::under`):
// a member who passes another writer's chain off as its own uses up nothing of theirs. On the
// old path the relay names the writer, so a chain is kept by its key alone, and a member who
// gets the writer's post to a reader first, as its own, has the writer's own copy refused there.
//
// What a fresh start has nothing of: a disconnect the person chose, a sign-out, a restart, a
// reload of the browser app (the native app keeps what a reloaded page's connections hand on),
// and every reconnect of a guest, which keeps nothing (kept sessions are an account's).
// On the old sender-key path no key from before opens there, as the pairwise sessions it came by
// went too. Under the group key a writer's blob rides on its post, so a relay can show such a
// connection a post of an epoch it holds the key for once more, as it can a new device of the
// same account.

/// A chain, by the public key its posts are signed with, as libsignal verifies by it: the
/// point's 32 bytes, the top bit not counted (curve25519.rs `verify_signature` goes by dalek's
/// `MontgomeryPoint::to_edwards`, which drops it).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub(crate) struct Signer([u8; 32]);

impl Signer {
    fn of(key: &PublicKey) -> Option<Signer> {
        let mut bytes: [u8; 32] = key.public_key_bytes().try_into().ok()?;
        bytes[31] &= 0x7f;
        Some(Signer(bytes))
    }

    /// The chain as one writer of the group key's, whose name the writer's blob binds and the
    /// relay cannot move: a member who passes another writer's chain off as its own, in its
    /// own blob, and sends that writer's post first, uses up nothing of the writer's (review
    /// 6). The old path keeps a chain by its key alone, as the relay names its writer there.
    pub(crate) fn under(self, writer: &str) -> Signer {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"voipc read under\0");
        h.update(writer.as_bytes());
        h.update([0]);
        h.update(self.0);
        Signer(h.finalize().into())
    }
}

/// Chains whose reads are kept, of every writer, channel and group, the one read least lately
/// going past this many. Measured on the heap (x86-64, round 6 of the GK=0 fix): 17.4 MB for
/// as many chains read in order, 173 bytes a chain, and 24.6 MB with `READ_RUNS` runs each, 245
/// bytes; a chain's runs never take more room, taken over from a connection before or not
/// (`a_chains_runs_never_take_more_room_than_the_cap`). That is per connection's stores: the
/// copy for the next one (`kept_reads`) holds as much again while it waits, one per server and
/// account.
/// What it gives up: a relay that kept a copy of a chain's key, and had this device read this
/// many other chains since it read that one last, can hand the key back once libsignal let it
/// go and replay its posts, each once more. The relay gets there alone: a guest it makes up on
/// the old sender-key path, or a seat it asks a keyholder for under the group key, starts a new
/// chain with each post, and so does a writer's post the relay refuses (`RATE`) again and
/// again. Review 6 did it in about half a minute of this device's time, some 40 MB to it, and
/// the posts of one message id show as one (chat-rules.ts `sameMessage`). More room only makes
/// it dearer; closing it needs a limit on what a chain met late may bring, in 1.15. libsignal
/// itself holds five a record (`MAX_SENDER_KEY_STATES`).
const READ_CHAINS: usize = 100_000;
/// Runs of positions read on one chain, apart from one another: a post that never came leaves a
/// gap between two. Past this many, the lowest run folds into everything below it, gaps and
/// all, so a post in one of those can no longer open. Only a relay sends a writer's posts out
/// of order, and libsignal itself keeps no more than 2000 skipped keys of a chain
/// (`MAX_MESSAGE_KEYS`).
const READ_RUNS: usize = 8;

/// What was read, by chain.
#[derive(Default, Clone)]
pub(crate) struct Reads {
    chains: HashMap<Signer, ChainReads>,
    /// Each chain by its `ChainReads::at`: the one read least lately first.
    order: BTreeMap<u64, Signer>,
    /// Counts the posts read, to tell which chain was read least lately.
    clock: u64,
}

#[derive(Clone)]
struct ChainReads {
    /// `Reads::clock` at its last read.
    at: u64,
    /// Every position below this counts as read.
    below: u64,
    /// The positions read past `below`, as `(first, last)` runs going up, at most `READ_RUNS`,
    /// none touching another or `below`.
    runs: Vec<(u32, u32)>,
}

impl ChainReads {
    fn new() -> Self {
        Self {
            at: 0,
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

    /// Positions `first..=last` read.
    fn add(&mut self, first: u32, last: u32) {
        if first > last || u64::from(last) < self.below {
            return;
        }
        // In order, the common case: `below` moves on, over every run it reaches
        if u64::from(first) <= self.below {
            self.below = u64::from(last) + 1;
            while let Some(&(a, b)) = self.runs.first() {
                if u64::from(a) > self.below {
                    break;
                }
                self.below = self.below.max(u64::from(b) + 1);
                self.runs.remove(0);
            }
            return;
        }
        // Past a gap: one run, with every run it overlaps or touches in it
        let (mut lo, mut hi) = (first, last);
        self.runs.retain(|&(a, b)| {
            let apart = u64::from(b) + 1 < u64::from(lo) || u64::from(hi) + 1 < u64::from(a);
            if !apart {
                lo = lo.min(a);
                hi = hi.max(b);
            }
            apart
        });
        // Room for one past the cap, once: it folds at once. A chain copied for the next
        // connection (`kept_reads`) has only room for what it holds (review 6)
        if self.runs.capacity() < READ_RUNS + 1 {
            self.runs.reserve_exact(READ_RUNS + 1 - self.runs.len());
        }
        let at = self.runs.partition_point(|&(a, _)| a < lo);
        self.runs.insert(at, (lo, hi));
        if self.runs.len() > READ_RUNS {
            let (_, last) = self.runs.remove(0);
            self.below = u64::from(last) + 1;
        }
    }

    /// Everything `other` read, read here too.
    fn take_in(&mut self, other: &ChainReads) {
        if other.below > 0 {
            self.add(0, u32::try_from(other.below - 1).unwrap_or(u32::MAX));
        }
        for &(first, last) in &other.runs {
            self.add(first, last);
        }
    }
}

impl Reads {
    fn was_read(&self, signer: &Signer, iteration: u32) -> bool {
        self.chains
            .get(signer)
            .is_some_and(|chain| chain.has(iteration))
    }

    fn mark(&mut self, signer: Signer, iteration: u32) {
        self.read_now(signer).add(iteration, iteration);
    }

    /// `signer`'s chain, read now: the newest. A chain not here yet takes the place of the
    /// one read least lately, past `READ_CHAINS`.
    fn read_now(&mut self, signer: Signer) -> &mut ChainReads {
        self.clock += 1;
        match self.chains.get(&signer) {
            Some(chain) => {
                self.order.remove(&chain.at);
            }
            None if self.chains.len() >= READ_CHAINS => {
                if let Some((_, least)) = self.order.pop_first() {
                    self.chains.remove(&least);
                }
            }
            None => {}
        }
        self.order.insert(self.clock, signer);
        let chain = self.chains.entry(signer).or_insert_with(ChainReads::new);
        chain.at = self.clock;
        chain
    }

    /// What an earlier connection read, taken in under what this one read, which counts as
    /// read after it.
    fn adopt(&mut self, older: Reads) {
        let Reads { chains, order, .. } = std::mem::replace(self, older);
        for signer in order.into_values() {
            if let Some(chain) = chains.get(&signer) {
                self.read_now(signer).take_in(chain);
            }
        }
    }
}

/// A chain as `Reads` is saved: in the order read, the one read least lately first.
#[derive(Serialize)]
struct SavedChainRef<'a> {
    signer: &'a Signer,
    below: u64,
    runs: &'a [(u32, u32)],
}

#[derive(Deserialize)]
struct SavedChain {
    signer: Signer,
    below: u64,
    runs: Vec<(u32, u32)>,
}

impl Serialize for Reads {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq(self.order.values().filter_map(|signer| {
            let chain = self.chains.get(signer)?;
            Some(SavedChainRef {
                signer,
                below: chain.below,
                runs: &chain.runs,
            })
        }))
    }
}

impl<'de> Deserialize<'de> for Reads {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut reads = Reads::default();
        for saved in Vec::<SavedChain>::deserialize(d)? {
            let chain = ChainReads {
                at: 0,
                below: saved.below,
                runs: saved.runs,
            };
            reads.read_now(saved.signer).take_in(&chain);
        }
        Ok(reads)
    }
}

/// One field of a protobuf message, as far as `signer_in` needs it.
enum Field<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
    Fixed,
}

fn varint(buf: &mut &[u8]) -> Option<u64> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        let (&byte, rest) = buf.split_first()?;
        *buf = rest;
        value |= u64::from(byte & 0x7f) << shift;
        if byte < 0x80 {
            return Some(value);
        }
    }
    None
}

fn take<'a>(buf: &mut &'a [u8], n: usize) -> Result<&'a [u8], ()> {
    if buf.len() < n {
        return Err(());
    }
    let (taken, rest) = buf.split_at(n);
    *buf = rest;
    Ok(taken)
}

/// The next field of a message and its number, or None at its end. Err: not a message.
fn field<'a>(buf: &mut &'a [u8]) -> Result<Option<(u64, Field<'a>)>, ()> {
    if buf.is_empty() {
        return Ok(None);
    }
    let key = varint(buf).ok_or(())?;
    let value = match key & 7 {
        0 => Field::Varint(varint(buf).ok_or(())?),
        1 => take(buf, 8).map(|_| Field::Fixed)?,
        5 => take(buf, 4).map(|_| Field::Fixed)?,
        2 => {
            let n = usize::try_from(varint(buf).ok_or(())?).map_err(|_| ())?;
            Field::Bytes(take(buf, n)?)
        }
        _ => return Err(()),
    };
    Ok(Some((key >> 3, value)))
}

/// The `Signer` of chain `chain_id` in a record as libsignal stores it (storage.proto
/// `SenderKeyRecordStructure`: the states are field 1; in a state its chain id is field 1, its
/// `SenderSigningKey` field 3, and in that the public half field 1). The first state of that
/// chain, as `SenderKeyRecord::sender_key_state_for_chain_id` takes it, read as prost reads
/// one: a field given twice is its last, a message given twice is merged, an unknown field is
/// passed over, and a chain id not given is 0. None: no state of that chain, or none with a key
/// libsignal takes, so no post of it opens. Err: not a record.
fn signer_in(record: &[u8], chain_id: u32) -> Result<Option<Signer>, ()> {
    let mut rest = record;
    while let Some((number, value)) = field(&mut rest)? {
        let (1, Field::Bytes(mut state)) = (number, value) else {
            continue;
        };
        let (mut id, mut public) = (0u32, None);
        while let Some((number, value)) = field(&mut state)? {
            match (number, value) {
                // uint32, as prost takes a varint for one
                (1, Field::Varint(v)) => id = v as u32,
                (3, Field::Bytes(mut key)) => {
                    while let Some((number, value)) = field(&mut key)? {
                        if let (1, Field::Bytes(bytes)) = (number, value) {
                            public = Some(bytes);
                        }
                    }
                }
                _ => {}
            }
        }
        if id == chain_id {
            return Ok(public
                .and_then(|bytes| PublicKey::deserialize(bytes).ok())
                .and_then(|key| Signer::of(&key)));
        }
    }
    Ok(None)
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

    /// The key the posts of chain `chain_id` in `sender`'s record for `distribution_id` are
    /// signed with, from the state libsignal would open one of them by now (`signer_in`). None:
    /// no post of that chain opens here now. An error: the record does not read as libsignal
    /// stores one.
    pub(crate) fn signer_of(
        &self,
        sender: &ProtocolAddress,
        distribution_id: uuid::Uuid,
        chain_id: u32,
    ) -> Result<Option<Signer>, SignalProtocolError> {
        match self.keys.get(&sender_key_key(sender, distribution_id)) {
            None => Ok(None),
            Some(record) => signer_in(record, chain_id)
                .map_err(|()| SignalProtocolError::InvalidProtobufEncoding),
        }
    }

    /// Whether the post at `iteration` of the chain `signer` signs was read here: so even once
    /// libsignal let that chain's state go, or `evict` the record, or under another sender
    /// name, or on an earlier connection whose sessions this one took over, and the key came
    /// back since, within the bounds of `READ_CHAINS` and `READ_RUNS`.
    pub(crate) fn was_read(&self, signer: &Signer, iteration: u32) -> bool {
        self.reads.was_read(signer, iteration)
    }

    /// A post opened: it stays read (`was_read`).
    pub(crate) fn mark_read(&mut self, signer: Signer, iteration: u32) {
        self.reads.mark(signer, iteration);
    }

    /// What was read here, for the next connection (`KeptSessions`).
    pub(crate) fn kept_reads(&self) -> Reads {
        self.reads.clone()
    }

    /// What an earlier connection read (`kept_reads`), read here too.
    pub(crate) fn adopt_reads(&mut self, older: Reads) {
        self.reads.adopt(older);
    }

    /// Past the limit, the one least recently used, if it is old enough to go. What was read
    /// on it stays read.
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

    fn signer(n: usize) -> Signer {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&(n as u64).to_le_bytes());
        Signer(bytes)
    }

    /// Positions read in order fold into `below`; posts that never came leave gaps, which
    /// stay unread until filled, and past `READ_RUNS` runs the lowest folds in, its gaps too.
    #[test]
    fn a_chains_reads_go_in_runs_and_the_lowest_folds_past_the_cap() {
        let mut c = ChainReads::new();
        for i in 0..5 {
            c.add(i, i);
        }
        assert_eq!((c.below, c.runs.len()), (5, 0));
        assert_eq!(c.runs.capacity(), 0, "read in order, it holds no run");
        // Every other position from 10: a gap before each
        let runs = READ_RUNS as u32;
        for k in 0..runs {
            c.add(10 + 2 * k, 10 + 2 * k);
        }
        assert_eq!(c.runs.len(), READ_RUNS);
        assert!(c.has(4) && c.has(10) && c.has(12));
        assert!(!c.has(5) && !c.has(9) && !c.has(11), "gaps stay unread");
        // Filling a gap joins two runs, and a run that reaches `below` folds into it
        c.add(11, 11);
        assert_eq!(c.runs.len(), READ_RUNS - 1);
        c.add(11 + 2 * runs, 11 + 2 * runs);
        assert_eq!(c.runs.len(), READ_RUNS);
        assert!(!c.has(5), "{READ_RUNS} runs: nothing folds");
        (5..10).for_each(|i| c.add(i, i));
        assert_eq!(c.below, 13, "0..=12 in a row");
        assert_eq!(c.runs.len(), READ_RUNS - 1);
        // One run past the cap: the lowest goes into `below`, the gap before it with it
        let mut d = ChainReads::new();
        for k in 0..=runs {
            d.add(10 + 2 * k, 10 + 2 * k);
        }
        assert_eq!(d.runs.len(), READ_RUNS);
        assert_eq!(d.below, 11);
        assert!(
            d.has(0) && d.has(10),
            "folded: the gap below counts as read"
        );
        assert!(!d.has(11) && d.has(12));
        // The last position there is
        d.add(u32::MAX, u32::MAX);
        assert!(d.has(u32::MAX) && !d.has(u32::MAX - 1));
        // A run over several, and over `below`
        let mut e = ChainReads::new();
        e.add(4, 4);
        e.add(8, 9);
        e.add(12, 12);
        e.add(3, 10);
        assert_eq!((e.below, e.runs.clone()), (0, vec![(3, 10), (12, 12)]));
        e.add(0, 11);
        assert_eq!((e.below, e.runs.len()), (13, 0));
    }

    /// The chains read last are kept, `READ_CHAINS` of them across every writer: one more,
    /// and the reads of the chain read least lately go.
    #[test]
    fn the_chains_read_last_are_kept_past_the_bound() {
        let mut r = Reads::default();
        for n in 0..READ_CHAINS {
            r.mark(signer(n), 0);
        }
        assert_eq!(r.chains.len(), READ_CHAINS);
        assert!(r.was_read(&signer(0), 0), "the first of {READ_CHAINS}");
        assert!(!r.was_read(&signer(0), 1) && !r.was_read(&signer(READ_CHAINS), 0));
        r.mark(signer(READ_CHAINS), 0);
        assert_eq!((r.chains.len(), r.order.len()), (READ_CHAINS, READ_CHAINS));
        assert!(
            !r.was_read(&signer(0), 0),
            "the chain read least lately went"
        );
        assert!(r.was_read(&signer(1), 0) && r.was_read(&signer(READ_CHAINS), 0));
    }

    /// A chain read again lately is not the one that goes past `READ_CHAINS`, though it was
    /// first read before all the others.
    #[test]
    fn a_chain_read_again_lately_stays_past_the_bound() {
        let mut r = Reads::default();
        for n in 0..READ_CHAINS {
            r.mark(signer(n), 0);
        }
        r.mark(signer(0), 1);
        r.mark(signer(READ_CHAINS), 0);
        assert!(
            r.was_read(&signer(0), 0) && r.was_read(&signer(0), 1),
            "read again lately"
        );
        assert!(!r.was_read(&signer(1), 0), "read least lately");
        assert_eq!((r.chains.len(), r.order.len()), (READ_CHAINS, READ_CHAINS));
    }

    /// What an earlier connection read comes along under what this one read, which counts
    /// as read later: past the bound the earlier connection's go first.
    #[test]
    fn reads_taken_over_count_as_read_before_this_connections() {
        let mut older = Reads::default();
        older.mark(signer(1), 0);
        older.mark(signer(2), 5);
        older.mark(signer(2), 9);
        let mut r = Reads::default();
        r.mark(signer(3), 0);
        r.mark(signer(2), 6);
        r.adopt(older);
        assert!(r.was_read(&signer(1), 0) && r.was_read(&signer(3), 0));
        assert!(
            r.was_read(&signer(2), 5) && r.was_read(&signer(2), 6) && r.was_read(&signer(2), 9)
        );
        assert!(!r.was_read(&signer(2), 7) && !r.was_read(&signer(2), 0));
        for n in 0..READ_CHAINS - 3 {
            r.mark(signer(100 + n), 0);
        }
        r.mark(signer(99), 0);
        assert!(
            !r.was_read(&signer(1), 0),
            "the earlier connection's, read least lately"
        );
        assert!(r.was_read(&signer(3), 0) && r.was_read(&signer(2), 9));
        r.mark(signer(98), 0);
        assert!(!r.was_read(&signer(3), 0) && r.was_read(&signer(2), 9));
    }

    /// Saved and brought back, what was read is the same, in the same order.
    #[test]
    fn what_was_read_is_saved_with_the_records() {
        let mut s = store(0, 0);
        s.mark_read(signer(1), 0);
        s.mark_read(signer(2), 3);
        s.mark_read(signer(1), 7);
        let saved = serde_json::to_string(&s).unwrap();
        let back: VoipcSenderKeyStore = serde_json::from_str(&saved).unwrap();
        for (n, i, read) in [
            (1, 0, true),
            (1, 7, true),
            (1, 3, false),
            (2, 3, true),
            (2, 0, false),
        ] {
            assert_eq!(back.was_read(&signer(n), i), read, "{n} {i}");
        }
        let order: Vec<Signer> = back.reads.order.values().copied().collect();
        assert_eq!(order, vec![signer(2), signer(1)]);
    }

    /// `evict` and `forget` drop a record, not what was read on it.
    #[test]
    fn what_was_read_stays_when_evict_drops_the_record() {
        let mut s = store(SENDER_KEYS_HELD + 1, 0);
        s.mark_read(signer(3), 7);
        s.evict(u64::MAX);
        assert!(!s.keys.contains_key("k0"));
        s.keys.clear();
        assert!(s.was_read(&signer(3), 7));
    }

    /// However many gaps a chain's reads have, its runs take room for `READ_RUNS` and one,
    /// once: so a chain costs at most that, and one read in order no room at all.
    #[test]
    fn a_chains_runs_never_take_more_room_than_the_cap() {
        let mut c = ChainReads::new();
        for k in 0..100 {
            c.add(1 + 2 * k, 1 + 2 * k);
            assert!(c.runs.len() <= READ_RUNS);
            assert_eq!(c.runs.capacity(), READ_RUNS + 1);
        }
        assert_eq!(c.runs.len(), READ_RUNS);
        // Nor once it went to the next connection, a copy with room for what it holds (review 6)
        let mut older = Reads::default();
        for k in 0..20 {
            older.mark(signer(1), 1 + 2 * k);
        }
        let mut r = Reads::default();
        r.adopt(older.clone());
        let mut cap = r.chains[&signer(1)].runs.capacity();
        assert!(cap <= READ_RUNS + 1, "copied: {cap}");
        for k in 20..100 {
            r.mark(signer(1), 1 + 2 * k);
            cap = r.chains[&signer(1)].runs.capacity();
            assert_eq!(cap, READ_RUNS + 1, "read on after the adopt");
        }
    }

    /// A chain's signer, read out of records as libsignal makes them: its own, one taken from
    /// a key message, one past five states, with skipped keys, a chain numbered 0, and one
    /// whose chain id came back under another key.
    #[test]
    fn a_chains_signer_is_read_as_libsignal_holds_it() {
        use crate::group::{
            channel_distribution_id, create_distribution_message, decrypt_group_message,
            encrypt_group_message, process_distribution_message,
        };
        use libsignal_protocol::{
            process_sender_key_distribution_message, KeyPair, SenderKeyDistributionMessage,
        };
        fn ready<T>(fut: impl std::future::Future<Output = T>) -> T {
            match std::pin::pin!(fut)
                .poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
            {
                std::task::Poll::Ready(v) => v,
                std::task::Poll::Pending => panic!("in-memory stores never pend"),
            }
        }
        let stores = |u: u32| SignalStores::new(&crate::generate_identity_key_pair(), u);
        let skdm = |bytes: &[u8]| SenderKeyDistributionMessage::try_from(bytes).unwrap();
        let signer = |m: &SenderKeyDistributionMessage| Signer::of(m.signing_key().unwrap());
        let (dist, alice, bob) = (channel_distribution_id(7), 1, 2);
        let addr = crate::session::user_address(alice);
        let mut a = stores(alice);
        let mut b = stores(bob);
        let mut chains = Vec::new();
        for _ in 0..6 {
            a.sender_key.forget(&addr, dist);
            let m = ready(create_distribution_message(&mut a, alice, 7)).unwrap();
            ready(process_distribution_message(&mut b, alice, 7, &m)).unwrap();
            let m = skdm(&m);
            // Our own record holds the private half too
            let own = a.sender_key.signer_of(&addr, dist, m.chain_id().unwrap());
            assert_eq!(own.unwrap(), signer(&m));
            chains.push(m);
        }
        // libsignal holds the five newest
        let of = |s: &SignalStores, chain_id: u32| {
            s.sender_key.signer_of(&addr, dist, chain_id).unwrap()
        };
        assert_eq!(of(&b, chains[0].chain_id().unwrap()), None);
        for m in &chains[1..] {
            assert_eq!(of(&b, m.chain_id().unwrap()), signer(m));
        }
        // Skipped keys: the third post read first leaves two in the state
        let posts: Vec<Vec<u8>> = (0..3)
            .map(|_| ready(encrypt_group_message(&mut a, alice, 7, b"x")).unwrap())
            .collect();
        ready(decrypt_group_message(&mut b, alice, 7, &posts[2])).unwrap();
        let newest = chains.last().unwrap();
        assert_eq!(of(&b, newest.chain_id().unwrap()), signer(newest));
        // A chain numbered 0, which a record writes no number for; then that number under
        // another key, which libsignal takes in its place
        let mut c = stores(3);
        for _ in 0..2 {
            let key = KeyPair::generate(&mut crate::rng()).public_key;
            let m = SenderKeyDistributionMessage::new(3, dist, 0, 0, vec![7; 32], key).unwrap();
            ready(process_sender_key_distribution_message(
                &addr,
                &m,
                &mut c.sender_key,
            ))
            .unwrap();
            assert_eq!(of(&c, 0), Signer::of(&key));
        }
        assert_eq!(of(&c, 1), None);
        let elsewhere = c.sender_key.signer_of(&addr, channel_distribution_id(8), 0);
        assert_eq!(elsewhere.unwrap(), None);
        // Not a record
        c.sender_key
            .keys
            .insert(sender_key_key(&addr, dist), vec![0x0a, 0x05, 0x08]);
        assert!(c.sender_key.signer_of(&addr, dist, 0).is_err());
        // The top bit of the point is not the key's: libsignal verifies by the other 255
        let key = KeyPair::generate(&mut crate::rng()).public_key;
        let mut flipped = key.serialize().to_vec();
        flipped[32] ^= 0x80;
        assert_eq!(
            Signer::of(&PublicKey::deserialize(&flipped).unwrap()),
            Signer::of(&key)
        );
    }
}
