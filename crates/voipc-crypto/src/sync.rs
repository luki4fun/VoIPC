//! Everything a signed-in account keeps up with after its sign-in, as a state
//! machine without I/O that the desktop client and the browser both drive:
//! the vault items it writes back (pinned identities, preferences, the log
//! key), and the stored-message log (`log`) — publishing its log key, sealing
//! what it sends, and fetching and opening what was kept for it.
//!
//! A log is a conversation: a direct one (`d:`, its two parties) or a
//! channel's (`c:`, the accounts that asked to keep it). Each writer seals
//! under its own epoch key, wrapped to every member. Who joins a channel's log
//! waits for each writer's answer: their older keys too when that writer
//! shares history with joiners, or only a new key when not. Who leaves makes
//! every writer start a new key (the relay refuses entries under a key that
//! still reaches them).
//!
//! The host feeds every `AccountReply` to `on_reply` and sends whatever comes
//! back; stored messages come out as `Event::Message` / `Event::ChannelMessage`.

use std::collections::{HashMap, HashSet, VecDeque};

use libsignal_protocol::IdentityKeyPair;
use serde::{Deserialize, Serialize};
use voipc_protocol::conv::{dm_conv, dm_parties};
use voipc_protocol::messages::{AccountReply, AccountRequest, ClientMessage, LogEntry, LogKeyInfo, WrapIn};
use voipc_protocol::types::VaultBlob;
use zeroize::Zeroizing;

use crate::account::{PinCheck, Pins, SignedIn, Vault, ITEM_PINS};
use crate::log::{endorsed, epoch_key, open_entry, seal_entry, self_unwrap, self_wrap, unwrap, wrap, LogKey};

pub const ITEM_LOGKEY: &str = "item.logkey";
pub const ITEM_PREFS: &str = "item.prefs";

/// Most accounts one `LogKeys` asks about (the relay's own bound).
const KEYS_PER_ASK: usize = 64;
/// Rekeys in a row for one log before giving up on what waits for it.
const MAX_REKEYS: u32 = 2;

/// What the person chose about their account, kept in its vault so every
/// device follows it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Prefs {
    /// Keep an encrypted copy of my messages on the relay (opt-in).
    pub cloud: bool,
    /// Whether the first-connect setup asked this already.
    pub asked: bool,
}

/// What a device remembers of the log between runs; the host keeps it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogMemory {
    /// Newest entry read per conversation.
    pub cursors: HashMap<String, i64>,
    /// Per channel log, the accounts this device has told its user can read
    /// what they write there (`Event::Readers`).
    pub readers: HashMap<String, Vec<[u8; 16]>>,
}

/// What comes out besides messages to send.
#[derive(Debug)]
pub enum Event {
    /// A stored direct message, opened and its sender proven: the other party
    /// of the conversation (`peer`, by account) and whether we wrote it.
    Message { conv: String, peer: [u8; 16], peer_name: String, from_me: bool, envelope: Vec<u8>, sent_at: u64, server_at: u64, seq: i64 },
    /// A stored channel message, opened and its writer proven.
    ChannelMessage { conv: String, sender: [u8; 16], sender_name: String, from_me: bool, envelope: Vec<u8>, sent_at: u64, server_at: u64, seq: i64 },
    /// `account` (going by `name`) has another identity than the one pinned,
    /// or the name belonged to another account: told once.
    IdentityChanged { account: [u8; 16], name: String },
    /// A message we sent is kept for its recipient (`id` from its envelope).
    Kept { conv: String, seq: i64 },
    /// The relay refused to keep something (over quota, no storage).
    NotKept { reason: String },
    /// These accounts can read what we write in channel log `conv` from now
    /// on (`history`: what we wrote there before, too). Shown to the user, so
    /// nobody — a member the relay made up included — gets our keys unseen.
    Readers { conv: String, accounts: Vec<([u8; 16], String)>, history: bool },
}

impl Event {
    /// The front end's event for this, as both backends emit it: its name and
    /// payload, with the envelope opened and the moment a timer counts from —
    /// the earlier of the two stamps, so neither the sender nor the relay can
    /// make a message outlive its timer. `IdentityChanged` is the host's to
    /// word (it knows which user id the account is here); `None` for it.
    pub fn to_wire(&self) -> Option<(&'static str, serde_json::Value)> {
        use voipc_protocol::conv::hex;
        let opened = |envelope: &[u8], sent_at: u64, server_at: u64| {
            let m = crate::envelope::open_envelope(envelope);
            (m.id, m.text, m.ttl_secs, sent_at.min(server_at))
        };
        Some(match self {
            Event::Message { conv, peer, peer_name, from_me, envelope, sent_at, server_at, seq } => {
                let (id, text, ttl, at) = opened(envelope, *sent_at, *server_at);
                let payload = serde_json::json!({
                    "conv": conv, "seq": seq, "peer_account": hex(peer), "peer_name": peer_name, "from_me": from_me,
                    "message_id": id, "content": text, "ttl_secs": ttl, "timestamp": at,
                });
                ("stored-dm", payload)
            }
            Event::ChannelMessage { conv, sender, sender_name, from_me, envelope, sent_at, server_at, seq } => {
                let (id, text, ttl, at) = opened(envelope, *sent_at, *server_at);
                let payload = serde_json::json!({
                    "conv": conv, "seq": seq, "sender_account": hex(sender), "sender_name": sender_name, "from_me": from_me,
                    "message_id": id, "content": text, "ttl_secs": ttl, "timestamp": at,
                });
                ("stored-channel-message", payload)
            }
            Event::Readers { conv, accounts, history } => {
                let names: Vec<&str> = accounts.iter().map(|(_, n)| n.as_str()).collect();
                ("log-readers", serde_json::json!({ "conv": conv, "names": names, "history": history }))
            }
            Event::Kept { conv, seq } => ("dm-kept", serde_json::json!({ "conv": conv, "seq": seq })),
            Event::NotKept { reason } => ("stored-not-kept", serde_json::json!({ "reason": reason })),
            Event::IdentityChanged { .. } => return None,
        })
    }

    /// Whether it moved this device's read cursors (they are saved after it).
    pub fn reads(&self) -> bool {
        matches!(self, Event::Message { .. } | Event::ChannelMessage { .. } | Event::Readers { .. })
    }
}

/// A message waiting for what sealing it needs (the members' log keys, our
/// epoch for the conversation).
struct Outgoing {
    conv: String,
    /// The other party of a direct conversation; `None` for a channel.
    peer: Option<[u8; 16]>,
    envelope: Vec<u8>,
    sent_at: u64,
    ttl_secs: Option<u32>,
}

/// One of the other accounts, as far as the log is concerned.
struct Peer {
    name: String,
    logkey: Vec<u8>,
}

/// How far a conversation's fetch has come.
#[derive(PartialEq, Eq, Clone, Copy)]
enum Fetch {
    /// Asked for the wraps.
    Wraps,
    /// Asked for the other party's log key.
    Keys,
    /// Paging through the entries.
    Entries,
}

fn is_channel(conv: &str) -> bool {
    conv.starts_with("c:")
}

pub struct AccountSync {
    me: [u8; 16],
    name: String,
    identity: IdentityKeyPair,
    vault: Vault,
    pins: Pins,
    pins_version: i64,
    prefs: Prefs,
    prefs_version: i64,
    /// Our older keys go to whoever joins a channel's log (the same consent
    /// as handing history over in person).
    share: bool,
    /// One write per item at a time; `dirty` says another is due after it.
    saving: HashSet<&'static str>,
    dirty: HashSet<&'static str>,
    logkey: LogKey,
    logkey_version: i64,
    /// A log key made this run: published only once the vault keeps it, and
    /// nothing is sealed or signed with it before that (another device's may
    /// win the vault, and a key the relay hands out must be the one we keep).
    logkey_unsettled: bool,
    peers: HashMap<[u8; 16], Peer>,
    /// Accounts whose keys do not check out; nothing of theirs is trusted.
    distrusted: HashSet<[u8; 16]>,
    asked_keys: HashSet<[u8; 16]>,
    /// Each `LogKeys` not answered yet, in order: an account the relay has
    /// no key for is judged by the answer to the request that named it.
    key_asks: VecDeque<Vec<[u8; 16]>>,
    /// Our own current epoch per conversation.
    own_epochs: HashMap<String, (u32, Zeroizing<[u8; 32]>)>,
    /// Every epoch key we hold: (conversation, owner, epoch).
    keys: HashMap<(String, [u8; 16], u32), Zeroizing<[u8; 32]>>,
    wraps_known: HashSet<String>,
    outbox: Vec<Outgoing>,
    /// Appends the relay has not answered yet, in order: the log, the epoch
    /// it went under, and (for a channel) the message, to send again on a rekey.
    in_flight: VecDeque<(String, u32, Option<Outgoing>)>,
    rekeys: HashMap<String, u32>,
    /// A channel log's members with trusted keys (us included), as last asked.
    members: HashMap<String, Vec<[u8; 16]>>,
    asked_members: HashSet<String>,
    /// Channel logs this session asked to keep.
    joined: HashSet<String>,
    /// Who joined a channel's log and waits for our answer.
    joiners: HashMap<String, HashSet<[u8; 16]>>,
    /// Writers who still owe us their answer, per channel log.
    owed: HashMap<String, HashSet<[u8; 16]>>,
    readers: HashMap<String, HashSet<[u8; 16]>>,
    cursors: HashMap<String, i64>,
    /// The newest entry fetched this run, per conversation.
    fetched: HashMap<String, i64>,
    fetching: HashMap<String, Fetch>,
    /// Conversations whose entries are to be fetched once their keys are in.
    target: HashSet<String>,
    /// Entries waiting for a key (a wrap or a log key not yet in).
    waiting: Vec<(String, LogEntry)>,
    /// Entries opened this run: a fetch again (a key came in) hands them over once.
    opened: HashSet<(String, i64)>,
    /// Events from a send, handed out with the next reply.
    later: Vec<Event>,
}

fn ask(r: AccountRequest) -> ClientMessage {
    ClientMessage::Account(r)
}

impl AccountSync {
    /// Starts after a sign-in: loads the vault items (making the log key if
    /// the account has none yet), publishes the log key, and asks which
    /// conversations kept something. `memory` is what this device kept last
    /// time; `share` is whether joiners get our older keys.
    pub fn start(signed: &SignedIn, me: [u8; 16], memory: LogMemory, share: bool) -> (AccountSync, Vec<ClientMessage>) {
        let blobs = &signed.blobs;
        let version = |k: &str| blobs.iter().find(|b| b.k == k).map_or(0, |b| b.version);
        let item = |k: &str| signed.vault.open_item(blobs, k).ok();
        let mut out = Vec::new();
        let pins = item(ITEM_PINS).and_then(|b| Pins::from_bytes(&b)).unwrap_or_default();
        let prefs = item(ITEM_PREFS).and_then(|b| postcard::from_bytes(&b).ok()).unwrap_or_default();
        let (logkey, logkey_version, fresh) = match item(ITEM_LOGKEY).and_then(|b| LogKey::from_bytes(&b)) {
            Some(k) => (k, version(ITEM_LOGKEY), false),
            None => (LogKey::generate(), 0, true),
        };
        let mut s = AccountSync {
            me,
            name: signed.name.clone(),
            identity: signed.identity,
            vault: Vault::from_dek(signed.relay_id, &signed.name, signed.vault.dek()),
            pins,
            pins_version: version(ITEM_PINS),
            prefs,
            prefs_version: version(ITEM_PREFS),
            share,
            saving: HashSet::new(),
            dirty: HashSet::new(),
            logkey,
            logkey_version,
            logkey_unsettled: fresh,
            peers: HashMap::new(),
            distrusted: HashSet::new(),
            asked_keys: HashSet::new(),
            key_asks: VecDeque::new(),
            own_epochs: HashMap::new(),
            keys: HashMap::new(),
            wraps_known: HashSet::new(),
            outbox: Vec::new(),
            in_flight: VecDeque::new(),
            rekeys: HashMap::new(),
            members: HashMap::new(),
            asked_members: HashSet::new(),
            joined: HashSet::new(),
            joiners: HashMap::new(),
            owed: HashMap::new(),
            readers: memory.readers.into_iter().map(|(c, r)| (c, r.into_iter().collect())).collect(),
            cursors: memory.cursors,
            fetched: HashMap::new(),
            fetching: HashMap::new(),
            target: HashSet::new(),
            waiting: Vec::new(),
            opened: HashSet::new(),
            later: Vec::new(),
        };
        if fresh {
            out.extend(s.save(ITEM_LOGKEY));
        } else {
            out.push(s.publish());
        }
        out.push(ask(AccountRequest::LogIndex));
        (s, out)
    }

    /// Our log key, for the relay to hand to the others, with our identity's
    /// endorsement.
    fn publish(&self) -> ClientMessage {
        ask(AccountRequest::LogKeyPublish { logkey: self.logkey.public(), sig: self.logkey.endorse(&self.identity) })
    }

    pub fn prefs(&self) -> Prefs {
        self.prefs
    }

    pub fn set_prefs(&mut self, prefs: Prefs) -> Vec<ClientMessage> {
        self.prefs = prefs;
        self.save(ITEM_PREFS)
    }

    pub fn set_share(&mut self, share: bool) {
        self.share = share;
    }

    /// What the host keeps for next time.
    pub fn memory(&self) -> LogMemory {
        LogMemory {
            cursors: self.cursors.clone(),
            readers: self.readers.iter().map(|(c, r)| (c.clone(), r.iter().copied().collect())).collect(),
        }
    }

    /// The key pinned for `account`, if any (for safety numbers).
    pub fn pinned(&self, account: &[u8; 16]) -> Option<&[u8]> {
        self.pins.get(account)
    }

    // ── vault items ──

    fn item_bytes(&self, k: &str) -> Vec<u8> {
        match k {
            ITEM_PINS => self.pins.to_bytes(),
            ITEM_PREFS => postcard::to_allocvec(&self.prefs).expect("prefs encode"),
            _ => self.logkey.to_bytes().to_vec(),
        }
    }

    fn version_of(&mut self, k: &str) -> &mut i64 {
        match k {
            ITEM_PINS => &mut self.pins_version,
            ITEM_PREFS => &mut self.prefs_version,
            _ => &mut self.logkey_version,
        }
    }

    fn save(&mut self, k: &'static str) -> Vec<ClientMessage> {
        if !self.saving.insert(k) {
            self.dirty.insert(k);
            return Vec::new();
        }
        self.dirty.remove(k);
        let blob = self.vault.seal_item(k, &self.item_bytes(k));
        let expect = *self.version_of(k);
        vec![ask(AccountRequest::VaultPut { k: blob.k, v: blob.v, expect })]
    }

    fn which(k: &str) -> Option<&'static str> {
        [ITEM_PINS, ITEM_PREFS, ITEM_LOGKEY].into_iter().find(|i| *i == k)
    }

    /// A vault answer for one of our items.
    fn on_vault(&mut self, k: &'static str, stored: Option<i64>, theirs: Option<&VaultBlob>) -> Vec<ClientMessage> {
        let mut settled = stored.is_some();
        match (stored, theirs) {
            (Some(v), _) => *self.version_of(k) = v,
            (None, Some(b)) => {
                // Another device wrote first: pins join, a log key or prefs of
                // theirs win (the log key: two would leave wraps to the wrong one).
                if let Ok(plain) = self.vault.open_item(std::slice::from_ref(b), k) {
                    match k {
                        ITEM_PINS => {
                            if let Some(p) = Pins::from_bytes(&plain) {
                                self.pins.merge(p);
                                self.dirty.insert(k);
                            }
                        }
                        ITEM_PREFS => {
                            if let Ok(p) = postcard::from_bytes(&plain) {
                                self.prefs = p;
                            }
                        }
                        _ => {
                            if let Some(lk) = LogKey::from_bytes(&plain) {
                                self.logkey = lk;
                                settled = true;
                            }
                        }
                    }
                }
                *self.version_of(k) = b.version;
            }
            (None, None) => {
                *self.version_of(k) = 0;
                self.dirty.insert(k);
            }
        }
        self.saving.remove(k);
        let mut out = if self.dirty.contains(k) { self.save(k) } else { Vec::new() };
        if k == ITEM_LOGKEY && settled && self.logkey_unsettled {
            // The vault keeps this key now: the relay may hand it out, and
            // what waited for it can go.
            self.logkey_unsettled = false;
            out.push(self.publish());
            out.extend(self.flush());
            out.extend(self.answer());
        }
        out
    }

    // ── pins ──

    /// `account`'s identity, and the name it goes by, against the pins (from
    /// a pre-key bundle, a session the peer opened, or the relay's key list).
    /// A change is reported once and drops what was learned under the old one.
    pub fn check_peer(&mut self, account: &[u8; 16], name: &str, identity: &[u8]) -> (PinCheck, Vec<ClientMessage>) {
        let check = self.pins.check(account, name, identity);
        let out = if check == PinCheck::Same { Vec::new() } else { self.save(ITEM_PINS) };
        if check == PinCheck::Changed {
            // Keys learned under the old identity are not good any more.
            self.peers.remove(account);
            self.asked_keys.remove(account);
        }
        (check, out)
    }

    /// Takes in the relay's word for some accounts' keys: the log key is
    /// checked against the identity, then the identity and the name against
    /// the pins. Returns the accounts now trusted.
    fn learn(&mut self, keys: &[LogKeyInfo], out: &mut Vec<ClientMessage>, events: &mut Vec<Event>) -> Vec<[u8; 16]> {
        let mut trusted = Vec::new();
        for LogKeyInfo { account, name, identity, logkey, sig } in keys {
            if *account == self.me {
                continue;
            }
            // Junk the identity never signed is not pinned over a good pin.
            if !endorsed(identity, logkey, sig) {
                self.distrusted.insert(*account);
                continue;
            }
            let (check, save) = self.check_peer(account, name, identity);
            out.extend(save);
            if check == PinCheck::Changed {
                events.push(Event::IdentityChanged { account: *account, name: name.clone() });
            }
            self.peers.insert(*account, Peer { name: name.clone(), logkey: logkey.clone() });
            self.distrusted.remove(account);
            trusted.push(*account);
        }
        trusted
    }

    fn ask_keys(&mut self, accounts: impl IntoIterator<Item = [u8; 16]>) -> Vec<ClientMessage> {
        let want: Vec<[u8; 16]> =
            accounts.into_iter().filter(|a| *a != self.me && !self.peers.contains_key(a) && !self.distrusted.contains(a) && self.asked_keys.insert(*a)).collect();
        want.chunks(KEYS_PER_ASK)
            .map(|c| {
                self.key_asks.push_back(c.to_vec());
                ask(AccountRequest::LogKeys { accounts: c.to_vec() })
            })
            .collect()
    }

    // ── sending ──

    /// A direct message to `peer` to keep for them too, when cloud copies
    /// are on. Nothing goes out while what it needs is still being fetched.
    pub fn send_dm(&mut self, peer: [u8; 16], envelope: Vec<u8>, sent_at: u64, ttl_secs: Option<u32>) -> Vec<ClientMessage> {
        if !self.prefs.cloud || peer == self.me {
            return Vec::new();
        }
        self.outbox.push(Outgoing { conv: dm_conv(&self.me, &peer), peer: Some(peer), envelope, sent_at, ttl_secs });
        self.flush()
    }

    /// A message written in a channel with a log (`ChannelInfo::log`), kept
    /// for its members when cloud copies are on.
    pub fn send_channel(&mut self, conv: &str, envelope: Vec<u8>, sent_at: u64, ttl_secs: Option<u32>) -> Vec<ClientMessage> {
        if !self.prefs.cloud || !is_channel(conv) {
            return Vec::new();
        }
        let mut out = Vec::new();
        if self.joined.insert(conv.to_string()) {
            out.push(ask(AccountRequest::LogJoin { conv: conv.to_string() }));
        }
        self.outbox.push(Outgoing { conv: conv.to_string(), peer: None, envelope, sent_at, ttl_secs });
        out.extend(self.flush());
        out
    }

    /// We are in a channel with a log: keep it (once a run), and read what it
    /// kept since last time.
    pub fn enter(&mut self, conv: &str) -> Vec<ClientMessage> {
        if !self.prefs.cloud || !is_channel(conv) {
            return Vec::new();
        }
        if self.joined.insert(conv.to_string()) {
            // The fetch follows `LogJoined`.
            return vec![ask(AccountRequest::LogJoin { conv: conv.to_string() })];
        }
        self.fetch(conv)
    }

    /// Starts reading `conv` from our cursor: its wraps first, then entries.
    fn fetch(&mut self, conv: &str) -> Vec<ClientMessage> {
        self.target.insert(conv.to_string());
        if self.fetching.contains_key(conv) {
            return Vec::new();
        }
        self.fetching.insert(conv.to_string(), Fetch::Wraps);
        vec![ask(AccountRequest::WrapsFetch { conv: conv.to_string() })]
    }

    fn flush(&mut self) -> Vec<ClientMessage> {
        if self.logkey_unsettled {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut keep = Vec::new();
        for o in std::mem::take(&mut self.outbox) {
            let conv = o.conv.clone();
            match o.peer {
                Some(peer) if !self.peers.contains_key(&peer) => {
                    if !self.distrusted.contains(&peer) {
                        out.extend(self.ask_keys([peer]));
                        keep.push(o);
                    }
                    continue;
                }
                None if !self.members.contains_key(&conv) => {
                    if self.asked_members.insert(conv.clone()) {
                        out.push(ask(AccountRequest::LogMembers { conv: conv.clone() }));
                    }
                    keep.push(o);
                    continue;
                }
                _ => {}
            }
            if !self.own_epochs.contains_key(&conv) {
                // First our own wraps, in case another device already holds an epoch here.
                if !self.wraps_known.contains(&conv) {
                    if !self.fetching.contains_key(&conv) {
                        out.push(ask(AccountRequest::WrapsFetch { conv: conv.clone() }));
                        self.fetching.insert(conv.clone(), Fetch::Wraps);
                    }
                    keep.push(o);
                    continue;
                }
                out.extend(self.mint(&conv));
            }
            let Some((epoch, key)) = self.own_epochs.get(&conv) else {
                keep.push(o);
                continue;
            };
            let epoch = *epoch;
            let ct = seal_entry(key, &conv, &self.me, epoch, &self.logkey, &o.envelope, o.sent_at);
            out.push(ask(AccountRequest::LogAppend { conv: conv.clone(), epoch, ct, ttl_secs: o.ttl_secs }));
            self.in_flight.push_back((conv, epoch, o.peer.is_none().then_some(o)));
        }
        self.outbox = keep;
        out
    }

    /// Who `conv` is for: us and the other party, or a channel log's members.
    fn recipients(&self, conv: &str) -> Vec<[u8; 16]> {
        match self.other_party(conv) {
            Some(p) => vec![self.me, p],
            None => {
                let mut m = self.members.get(conv).cloned().unwrap_or_default();
                if !m.contains(&self.me) {
                    m.push(self.me);
                }
                m
            }
        }
    }

    fn logkey_of(&self, account: &[u8; 16]) -> Option<Vec<u8>> {
        if *account == self.me {
            Some(self.logkey.public())
        } else {
            self.peers.get(account).map(|p| p.logkey.clone())
        }
    }

    /// Our epoch `key` wrapped to each of `recipients` whose log key we hold:
    /// ECIES to the others, a self-wrap to us.
    fn wraps_for(&self, recipients: &[[u8; 16]], key: &[u8; 32], conv: &str, epoch: u32) -> Vec<WrapIn> {
        recipients
            .iter()
            .filter_map(|r| {
                let wrapped =
                    if *r == self.me { self_wrap(&self.logkey, key, conv, &self.me, epoch) } else { wrap(&self.logkey_of(r)?, key, conv, &self.me, epoch, r)? };
                Some(WrapIn { recipient: *r, wrapped })
            })
            .collect()
    }

    /// A new epoch of ours for `conv`, wrapped to everyone it is for (us
    /// included, for our other devices). Random, so two devices of one
    /// account starting at once make two epochs rather than overwriting each other.
    fn mint(&mut self, conv: &str) -> Vec<ClientMessage> {
        let recipients = self.recipients(conv);
        let epoch: u32 = rand::random::<u32>() | 1;
        let k = epoch_key();
        let wraps = self.wraps_for(&recipients, &k, conv, epoch);
        self.keys.insert((conv.to_string(), self.me, epoch), Zeroizing::new(*k));
        self.own_epochs.insert(conv.to_string(), (epoch, k));
        self.announce(conv, &recipients, false);
        vec![ask(AccountRequest::EpochPut { conv: conv.to_string(), epoch, wraps })]
    }

    /// Tells the user about readers of a channel log this device has not
    /// named to them before.
    fn announce(&mut self, conv: &str, accounts: &[[u8; 16]], history: bool) {
        if !is_channel(conv) {
            return;
        }
        let seen = self.readers.entry(conv.to_string()).or_default();
        let new: Vec<[u8; 16]> = accounts.iter().filter(|a| **a != self.me && !seen.contains(*a)).copied().collect();
        if new.is_empty() {
            return;
        }
        seen.extend(new.iter().copied());
        let accounts = new.iter().map(|a| (*a, self.peers.get(a).map(|p| p.name.clone()).unwrap_or_default())).collect();
        self.later.push(Event::Readers { conv: conv.to_string(), accounts, history });
    }

    /// Answers whoever joined a channel log since we last wrapped there:
    /// our older keys when we share with joiners, else a new epoch for all.
    fn answer(&mut self) -> Vec<ClientMessage> {
        if self.logkey_unsettled {
            return Vec::new();
        }
        let mut out = Vec::new();
        let convs: Vec<String> = self.joiners.keys().cloned().collect();
        for conv in convs {
            let joiners: Vec<[u8; 16]> = self.joiners[&conv].iter().copied().collect();
            out.extend(self.ask_keys(joiners.iter().copied()));
            if joiners.iter().any(|j| !self.peers.contains_key(j) && !self.distrusted.contains(j)) {
                continue; // their keys are on the way
            }
            if !self.wraps_known.contains(&conv) {
                if !self.fetching.contains_key(&conv) {
                    self.fetching.insert(conv.clone(), Fetch::Wraps);
                    out.push(ask(AccountRequest::WrapsFetch { conv: conv.clone() }));
                }
                continue;
            }
            let trusted: Vec<[u8; 16]> = joiners.into_iter().filter(|j| self.peers.contains_key(j)).collect();
            let mine: Vec<(u32, Zeroizing<[u8; 32]>)> =
                self.keys.iter().filter(|((c, o, _), _)| *c == conv && *o == self.me).map(|((_, _, e), k)| (*e, k.clone())).collect();
            if self.share && !mine.is_empty() {
                for (epoch, k) in mine {
                    let wraps = self.wraps_for(&trusted, &k, &conv, epoch);
                    if !wraps.is_empty() {
                        out.push(ask(AccountRequest::EpochPut { conv: conv.clone(), epoch, wraps }));
                    }
                }
                self.announce(&conv, &trusted, true);
            } else {
                if !self.members.contains_key(&conv) {
                    if self.asked_members.insert(conv.clone()) {
                        out.push(ask(AccountRequest::LogMembers { conv: conv.clone() }));
                    }
                    continue;
                }
                // Nothing before their joining is theirs: a key they never had.
                self.own_epochs.remove(&conv);
                out.extend(self.mint(&conv));
            }
            self.joiners.remove(&conv);
        }
        out
    }

    // ── receiving ──

    fn other_party(&self, conv: &str) -> Option<[u8; 16]> {
        let (a, b) = dm_parties(conv)?;
        Some(if a == self.me { b } else { a })
    }

    /// Opens what it can of the waiting entries; asks for what is missing.
    fn drain(&mut self, out: &mut Vec<ClientMessage>, events: &mut Vec<Event>) {
        let me = self.me;
        let mut still = Vec::new();
        let mut unknown = Vec::new();
        for (conv, e) in std::mem::take(&mut self.waiting) {
            // A direct conversation is its two parties' and nobody else's: an
            // entry a third account signed (the relay can make one) would
            // otherwise be filed as the other party's.
            if dm_parties(&conv).is_some_and(|(a, b)| !(a == me || b == me) || !(e.sender == a || e.sender == b)) {
                continue;
            }
            let Some(key) = self.keys.get(&(conv.clone(), e.sender, e.epoch)) else {
                // Not ours to read, unless its writer still owes us an answer.
                if self.owed.get(&conv).is_some_and(|o| o.contains(&e.sender)) {
                    still.push((conv, e));
                }
                continue;
            };
            let Some(signer) = self.logkey_of(&e.sender) else {
                if !self.distrusted.contains(&e.sender) {
                    unknown.push(e.sender);
                    still.push((conv, e));
                }
                continue;
            };
            // Sealed or forged entries are dropped: the relay moved or made them.
            let Ok((envelope, sent_at)) = open_entry(key, &conv, &e.sender, e.epoch, &signer, &e.ct) else { continue };
            if !self.opened.insert((conv.clone(), e.seq)) {
                continue;
            }
            let from_me = e.sender == me;
            let name_of = |a: &[u8; 16]| self.peers.get(a).map(|p| p.name.clone()).unwrap_or_default();
            if let Some(peer) = self.other_party(&conv) {
                events.push(Event::Message { conv, peer, peer_name: name_of(&peer), from_me, envelope, sent_at, server_at: e.server_at, seq: e.seq });
            } else {
                let sender_name = if from_me { self.name.clone() } else { name_of(&e.sender) };
                events.push(Event::ChannelMessage { conv, sender: e.sender, sender_name, from_me, envelope, sent_at, server_at: e.server_at, seq: e.seq });
            }
        }
        self.waiting = still;
        out.extend(self.ask_keys(unknown));
        // Read up to the first entry still waiting: it may open next time.
        for (conv, last) in &self.fetched {
            let held = self.waiting.iter().filter(|(c, _)| c == conv).map(|(_, e)| e.seq).min();
            let upto = held.map_or(*last, |h| (h - 1).min(*last));
            let c = self.cursors.entry(conv.clone()).or_insert(0);
            *c = (*c).max(upto);
        }
    }

    /// One `AccountReply`: what to send, and what happened. Replies this does
    /// not handle (codes, the device key) come back as `None` for the host.
    pub fn on_reply(&mut self, reply: &AccountReply) -> Option<(Vec<ClientMessage>, Vec<Event>)> {
        let mut out = Vec::new();
        let mut events = Vec::new();
        match reply {
            AccountReply::VaultStored { k, version } => out.extend(self.on_vault(Self::which(k)?, Some(*version), None)),
            AccountReply::VaultConflict { k, blob } => out.extend(self.on_vault(Self::which(k)?, None, blob.as_ref())),
            AccountReply::Error { request, reason } if request == "VaultPut" => {
                self.saving.clear();
                events.push(Event::NotKept { reason: reason.clone() });
            }
            AccountReply::Error { request, reason } if request.starts_with("Log") || request.starts_with("Epoch") || request.starts_with("Wraps") => {
                if request == "LogAppend" {
                    self.in_flight.pop_front();
                }
                if request == "LogKeys" {
                    self.key_asks.pop_front();
                }
                events.push(Event::NotKept { reason: reason.clone() });
            }
            AccountReply::LogKeyStored | AccountReply::EpochStored { .. } | AccountReply::LogLeft { .. } => {}
            AccountReply::LogConvs { convs } => {
                for (conv, last) in convs {
                    if *last > self.cursors.get(conv).copied().unwrap_or(0) && (dm_parties(conv).is_some() || is_channel(conv)) {
                        out.extend(self.fetch(conv));
                    }
                }
            }
            AccountReply::LogJoined { conv } => out.extend(self.fetch(conv)),
            AccountReply::Wraps { conv, wraps } => {
                self.wraps_known.insert(conv.clone());
                // Newest first: the first of ours is the epoch to go on with.
                // Ours open only as self-wraps, which only our own devices can
                // make: an epoch the relay made up is never one we write under.
                for w in wraps {
                    let opened = if w.owner == self.me {
                        self_unwrap(&self.logkey, &w.wrapped, conv, &self.me, w.epoch)
                    } else {
                        unwrap(&self.logkey, &w.wrapped, conv, &w.owner, w.epoch, &self.me)
                    };
                    if let Ok(k) = opened {
                        self.keys.insert((conv.clone(), w.owner, w.epoch), Zeroizing::new(k));
                        if w.owner == self.me && !self.own_epochs.contains_key(conv) {
                            self.own_epochs.insert(conv.clone(), (w.epoch, Zeroizing::new(k)));
                        }
                    }
                }
                // The other party's log key, for their signatures and for wrapping
                // to them; a channel's writers are asked for as their entries come.
                let want = self.ask_keys(self.other_party(conv));
                let target = self.target.contains(conv);
                if !want.is_empty() {
                    out.extend(want);
                    self.fetching.insert(conv.clone(), Fetch::Keys);
                } else if target {
                    self.fetching.insert(conv.clone(), Fetch::Entries);
                    out.push(ask(AccountRequest::LogFetch { conv: conv.clone(), after: self.cursors.get(conv).copied().unwrap_or(0) }));
                } else {
                    self.fetching.remove(conv);
                }
                self.drain(&mut out, &mut events);
                out.extend(self.flush());
                out.extend(self.answer());
            }
            AccountReply::LogKeysFound { keys } => {
                self.learn(keys, &mut out, &mut events);
                // Asked, and the relay had nothing for some: they cannot be written to.
                for a in self.key_asks.pop_front().unwrap_or_default() {
                    if !self.peers.contains_key(&a) && !keys.iter().any(|k| k.account == a) {
                        self.distrusted.insert(a);
                    }
                }
                let ready: Vec<String> = self.fetching.iter().filter(|(_, f)| **f == Fetch::Keys).map(|(c, _)| c.clone()).collect();
                for conv in ready {
                    if self.target.contains(&conv) {
                        self.fetching.insert(conv.clone(), Fetch::Entries);
                        out.push(ask(AccountRequest::LogFetch { conv: conv.clone(), after: self.cursors.get(&conv).copied().unwrap_or(0) }));
                    } else {
                        self.fetching.remove(&conv);
                    }
                }
                self.drain(&mut out, &mut events);
                out.extend(self.flush());
                out.extend(self.answer());
            }
            AccountReply::LogPage { conv, entries, more, owed } => {
                self.owed.insert(conv.clone(), owed.iter().copied().collect());
                for e in entries {
                    if !self.opened.contains(&(conv.clone(), e.seq)) && !self.waiting.iter().any(|(c, w)| c == conv && w.seq == e.seq) {
                        self.waiting.push((conv.clone(), e.clone()));
                    }
                }
                if let Some(last) = entries.last() {
                    let f = self.fetched.entry(conv.clone()).or_insert(0);
                    *f = (*f).max(last.seq);
                }
                self.drain(&mut out, &mut events);
                if *more {
                    out.push(ask(AccountRequest::LogFetch { conv: conv.clone(), after: self.fetched.get(conv).copied().unwrap_or(0) }));
                } else {
                    self.fetching.remove(conv);
                    self.target.remove(conv);
                }
            }
            AccountReply::LogAppended { conv, seq, .. } => {
                self.in_flight.pop_front();
                self.rekeys.remove(conv);
                // Ours: nothing to fetch back up to here.
                let c = self.cursors.entry(conv.clone()).or_insert(0);
                if *c + 1 >= *seq {
                    *c = *seq;
                }
                events.push(Event::Kept { conv: conv.clone(), seq: *seq });
            }
            AccountReply::LogRekey { conv } => {
                // Somebody joined or left since our key: ask who is there now,
                // start a new key for them, and send it again.
                let (_, epoch, again) = self.in_flight.pop_front().unwrap_or_default();
                // Counted once per refused key: the messages sent under it
                // come back one by one, and only the first starts a new one.
                if self.own_epochs.get(conv).is_some_and(|(e, _)| *e == epoch) {
                    self.own_epochs.remove(conv);
                    self.members.remove(conv);
                    self.asked_members.remove(conv);
                    *self.rekeys.entry(conv.clone()).or_insert(0) += 1;
                }
                if self.rekeys.get(conv).is_some_and(|n| *n > MAX_REKEYS) {
                    self.rekeys.remove(conv);
                    self.outbox.retain(|o| o.conv != *conv);
                    events.push(Event::NotKept { reason: "the people this channel keeps messages for could not all be reached".into() });
                } else if let Some(o) = again {
                    // In the order they were written.
                    let at = self.outbox.iter().position(|x| x.sent_at > o.sent_at).unwrap_or(self.outbox.len());
                    self.outbox.insert(at, o);
                }
                out.extend(self.flush());
            }
            AccountReply::LogMembersFound { conv, members } => {
                let mut list = self.learn(members, &mut out, &mut events);
                list.push(self.me);
                self.members.insert(conv.clone(), list);
                self.asked_members.remove(conv);
                out.extend(self.flush());
                out.extend(self.answer());
            }
            AccountReply::LogPending { conv, joiners } => {
                self.joiners.entry(conv.clone()).or_default().extend(joiners.iter().copied().filter(|j| *j != self.me));
                // The members we knew are from before they joined.
                self.members.remove(conv);
                self.asked_members.remove(conv);
                out.extend(self.answer());
            }
            AccountReply::LogNews { conv } => {
                // A key for us: what waited for it, and what came after.
                self.wraps_known.remove(conv);
                self.fetching.remove(conv);
                out.extend(self.fetch(conv));
            }
            _ => return None,
        }
        let mut all = std::mem::take(&mut self.later);
        all.extend(events);
        Some((out, all))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::{SignedIn, Vault};
    use crate::envelope::envelope;
    use crate::log::{dm_conv, open_entry};
    use rand::rngs::OsRng;
    use voipc_protocol::messages::WrapOut;

    const RELAY: [u8; 16] = [9; 16];

    struct Account {
        id: [u8; 16],
        identity: IdentityKeyPair,
        logkey: LogKey,
    }

    fn account(n: u8) -> Account {
        Account { id: [n; 16], identity: IdentityKeyPair::generate(&mut OsRng), logkey: LogKey::generate() }
    }

    impl Account {
        /// The relay's word for this account's keys.
        fn info(&self, name: &str) -> LogKeyInfo {
            LogKeyInfo {
                account: self.id,
                name: name.into(),
                identity: self.identity.public_key().serialize().to_vec(),
                logkey: self.logkey.public(),
                sig: self.logkey.endorse(&self.identity),
            }
        }
    }

    /// `me`'s sync with cloud copies on and its log key already in the vault,
    /// so nothing waits for a vault answer.
    fn sync_for(me: &Account) -> AccountSync {
        let vault = Vault::create(RELAY, "me");
        let blobs = vec![VaultBlob { version: 1, ..vault.seal_item(ITEM_LOGKEY, &me.logkey.to_bytes()) }];
        let signed = SignedIn { relay_id: RELAY, name: "me".into(), vault, identity: me.identity, recovery: None, blobs };
        let (mut s, _) = AccountSync::start(&signed, me.id, LogMemory::default(), false);
        s.prefs.cloud = true;
        s
    }

    fn sent<'a>(out: &'a [ClientMessage], what: &str) -> Vec<&'a AccountRequest> {
        out.iter()
            .filter_map(|m| match m {
                ClientMessage::Account(r) if format!("{r:?}").starts_with(what) => Some(r),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn an_epoch_the_relay_makes_up_for_us_is_never_written_under() {
        let (me, bob) = (account(1), account(2));
        let mut s = sync_for(&me);
        let conv = dm_conv(&me.id, &bob.id);
        let out = s.send_dm(bob.id, envelope("m1", "for bob only", None), 1, None);
        assert_eq!(sent(&out, "LogKeys").len(), 1);
        let (out, _) = s.on_reply(&AccountReply::LogKeysFound { keys: vec![bob.info("bob")] }).unwrap();
        assert_eq!(sent(&out, "WrapsFetch").len(), 1, "first our own wraps, in case another device has an epoch here");
        // The relay answers with a key it made, wrapped to our public log key "from us".
        let evil = epoch_key();
        let forged = wrap(&me.logkey.public(), &evil, &conv, &me.id, 7, &me.id).unwrap();
        let (out, _) = s.on_reply(&AccountReply::Wraps { conv: conv.clone(), wraps: vec![WrapOut { owner: me.id, epoch: 7, wrapped: forged }] }).unwrap();
        let Some(AccountRequest::EpochPut { epoch, wraps, .. }) = sent(&out, "EpochPut").first().copied() else {
            panic!("a fresh epoch of our own is minted: {out:?}");
        };
        assert_ne!(*epoch, 7);
        let Some(AccountRequest::LogAppend { epoch: used, ct, .. }) = sent(&out, "LogAppend").first().copied() else {
            panic!("the message goes out: {out:?}");
        };
        assert_eq!(used, epoch);
        assert!(open_entry(&evil, &conv, &me.id, *used, &me.logkey.public(), ct).is_err(), "the relay's key does not open it");
        // Bob's wrap of the new epoch opens the entry; ours is a self-wrap.
        let to_bob = wraps.iter().find(|w| w.recipient == bob.id).unwrap();
        let k = unwrap(&bob.logkey, &to_bob.wrapped, &conv, &me.id, *epoch, &bob.id).unwrap();
        let (env, _) = open_entry(&k, &conv, &me.id, *epoch, &me.logkey.public(), ct).unwrap();
        assert_eq!(crate::envelope::open_envelope(&env).text, "for bob only");
        let to_me = wraps.iter().find(|w| w.recipient == me.id).unwrap();
        assert_eq!(self_unwrap(&me.logkey, &to_me.wrapped, &conv, &me.id, *epoch).unwrap(), k);
    }

    #[test]
    fn a_direct_message_only_comes_from_its_two_parties() {
        let (me, bob, carol) = (account(1), account(2), account(3));
        let mut s = sync_for(&me);
        let conv = dm_conv(&me.id, &bob.id);
        s.on_reply(&AccountReply::LogKeysFound { keys: vec![bob.info("bob"), carol.info("carol")] }).unwrap();
        let page = |s: &mut AccountSync, owner: &Account, epoch: u32, seq: i64, text: &str| {
            let k = epoch_key();
            let wrapped = wrap(&me.logkey.public(), &k, &conv, &owner.id, epoch, &me.id).unwrap();
            s.on_reply(&AccountReply::Wraps { conv: conv.clone(), wraps: vec![WrapOut { owner: owner.id, epoch, wrapped }] }).unwrap();
            let ct = seal_entry(&k, &conv, &owner.id, epoch, &owner.logkey, &envelope(text, text, None), 1);
            let entries = vec![LogEntry { seq, sender: owner.id, epoch, server_at: 1, ct }];
            s.on_reply(&AccountReply::LogPage { conv: conv.clone(), entries, more: false, owed: Vec::new() }).unwrap().1
        };
        // Carol (an account the relay made) signs an entry and files it between bob and us.
        let events = page(&mut s, &carol, 5, 1, "carol posing as bob");
        assert!(!events.iter().any(|e| matches!(e, Event::Message { .. })), "{events:?}");
        let events = page(&mut s, &bob, 6, 2, "really bob");
        assert!(events.iter().any(|e| matches!(e, Event::Message { peer, from_me: false, .. } if *peer == bob.id)), "{events:?}");
    }

    #[test]
    fn a_new_log_key_is_published_only_once_the_vault_keeps_it() {
        let me = account(1);
        let signed = SignedIn { relay_id: RELAY, name: "me".into(), vault: Vault::create(RELAY, "me"), identity: me.identity, recovery: None, blobs: Vec::new() };
        let (mut s, first) = AccountSync::start(&signed, me.id, LogMemory::default(), false);
        assert!(sent(&first, "LogKeyPublish").is_empty(), "not before the vault answers");
        assert_eq!(sent(&first, "VaultPut").len(), 1);
        s.prefs.cloud = true;
        // Nothing is sealed with a key the vault may not keep.
        let out = s.send_dm([2; 16], envelope("m", "waits", None), 1, None);
        assert!(out.is_empty(), "{out:?}");
        // Another device's key won the vault meanwhile: that one is published.
        let other = LogKey::generate();
        let theirs = VaultBlob { version: 3, ..signed.vault.seal_item(ITEM_LOGKEY, &other.to_bytes()) };
        let (out, _) = s.on_reply(&AccountReply::VaultConflict { k: ITEM_LOGKEY.into(), blob: Some(theirs) }).unwrap();
        let Some(AccountRequest::LogKeyPublish { logkey, .. }) = sent(&out, "LogKeyPublish").first().copied() else {
            panic!("published: {out:?}");
        };
        assert_eq!(*logkey, other.public());
        assert_eq!(sent(&out, "LogKeys").len(), 1, "and the waiting message goes on");
    }
}
