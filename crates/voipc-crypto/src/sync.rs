//! Everything a signed-in account keeps up with after its sign-in, as a state
//! machine without I/O that the desktop client and the browser both drive:
//! the vault items it writes back (pinned identities, preferences, the log
//! key, who it blocked), and the stored-message log (`log`) — publishing its log key, sealing
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
//! On a relay at protocol 21 a channel's log goes on chains and buckets instead:
//! the `chains` module below. Direct conversations stay as above everywhere. And
//! there the pins go in pages outside the sign-in frame: the `pins` module.
//!
//! The host feeds every `AccountReply` to `on_reply` and sends whatever comes
//! back; stored messages come out as `Event::Message` / `Event::ChannelMessage`.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::Arc;

use libsignal_protocol::IdentityKeyPair;
use serde::{Deserialize, Serialize};
use voipc_protocol::conv::{dm_conv, dm_parties};
use voipc_protocol::messages::{
    AccountReply, AccountRequest, ClientMessage, LogEntry, LogKeyInfo, WrapIn,
};
use voipc_protocol::types::VaultBlob;
use zeroize::Zeroizing;

use crate::account::{Item, PinCheck, Pins, SignedIn, Vault, VaultError, ITEM_PINS};
use crate::log::{
    endorsed, epoch_key, open_entry, seal_entry, self_unwrap, self_wrap, unwrap, wrap, LogKey,
    StaticKey,
};

mod chains;
mod pins;

pub use pins::KeptPins;

pub const ITEM_LOGKEY: &str = "item.logkey";
pub const ITEM_PREFS: &str = "item.prefs";
pub const ITEM_BLOCKS: &str = "item.blocks";

/// The most people one account's blocked list holds.
pub const BLOCKS_MAX: usize = 200;
/// The characters kept of a blocked person's name: only a label, and a relay's to choose.
const BLOCK_NAME_MAX: usize = 64;
/// What the blocked list's payload is padded to a multiple of: the relay sees
/// an item's size, and must not read how many people are on it from that.
const BLOCKS_BUCKET: usize = 1024;

/// Most accounts one `LogKeys` asks about (the relay's own bound).
const KEYS_PER_ASK: usize = 64;
/// Rekeys in a row for one log before giving up on what waits for it.
const MAX_REKEYS: u32 = 2;
/// A first read starts this many entries back (`LogFetch`): what a client holds
/// of a conversation (`MAX_MESSAGES` in chat-rules.ts). A browser reads its
/// conversations back after every reload.
const READ_BACK: i64 = 500;
/// `AccountSync::tick`s without an answer before a read counts as lost.
const LOST_AFTER_TICKS: u32 = 3;
/// And before what went out to be kept counts as lost, at about 30 s. Sent again it would
/// be kept twice if only the answer was lost, so this waits longer than a read does.
const APPEND_LOST_AFTER_TICKS: u32 = 15;
/// Joiners waiting for our answer, across every log, at most; and those seen before that set
/// starts over, which only says whether one is new.
const MOST_PENDING: usize = 65_536;

/// How the relay says its budget ran out for now (`accounts.rs`).
const SLOW_DOWN: &str = "slow down";

/// What the person chose about their account, kept in its vault so every
/// device follows it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Prefs {
    /// Keep an encrypted copy of my messages on the relay (opt-in).
    pub cloud: bool,
    /// Whether the first-connect setup asked this already.
    pub asked: bool,
}

/// Who the person blocked here, kept sealed in the vault so every device
/// follows it. Its own item, never a field of `Prefs`: that one is positional,
/// and a new field makes every saved copy unreadable.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Blocks {
    /// By account, with the name it went by.
    accounts: BTreeMap<[u8; 16], String>,
    /// Guests, who have only a name, as it was written.
    guests: BTreeSet<String>,
}

impl Blocks {
    fn len(&self) -> usize {
        self.accounts.len() + self.guests.len()
    }

    /// As the front end keys them (`block-rules.ts`): `a:<hex>` and
    /// `g:<lowercase name>`, each with what to call them.
    fn entries(&self) -> Vec<(String, String)> {
        let accounts = self
            .accounts
            .iter()
            .map(|(a, name)| (format!("a:{}", voipc_protocol::conv::hex(a)), name.clone()));
        let guests = self
            .guests
            .iter()
            .map(|name| (format!("g:{}", name.to_lowercase()), name.clone()));
        accounts.chain(guests).collect()
    }

    /// Blocks or unblocks the person `key` names: whether that changed anything.
    fn set(&mut self, key: &str, label: &str, on: bool) -> Result<bool, String> {
        let name: String = label.chars().take(BLOCK_NAME_MAX).collect();
        let full = on && self.len() >= BLOCKS_MAX;
        let refused = || format!("You can block at most {BLOCKS_MAX} people here.");
        if let Some(hex) = key.strip_prefix("a:") {
            let account = voipc_protocol::conv::unhex16(hex).ok_or("not an account id")?;
            if !on {
                return Ok(self.accounts.remove(&account).is_some());
            }
            if self.accounts.get(&account) == Some(&name) {
                return Ok(false);
            }
            if full && !self.accounts.contains_key(&account) {
                return Err(refused());
            }
            self.accounts.insert(account, name);
            return Ok(true);
        }
        let guest = key.strip_prefix("g:").ok_or("not a person to block")?;
        let same = |g: &String| g.to_lowercase() == guest;
        if !on {
            let had = self.guests.len();
            self.guests.retain(|g| !same(g));
            return Ok(self.guests.len() != had);
        }
        if name.to_lowercase() != guest {
            return Err("not a person to block".into());
        }
        if self.guests.iter().any(same) {
            return Ok(false);
        }
        if full {
            return Err(refused());
        }
        self.guests.insert(name);
        Ok(true)
    }

    /// Another device's list as well: a lost unblock stays blocked, the safe
    /// way round. Past the cap the guests go first: an account is the surer name.
    fn join(&mut self, theirs: Blocks) {
        self.accounts.extend(theirs.accounts);
        self.guests.extend(theirs.guests);
        self.trim();
    }

    fn trim(&mut self) {
        while self.len() > BLOCKS_MAX {
            if self.guests.pop_last().is_none() {
                self.accounts.pop_last();
            }
        }
    }

    /// Padded to a whole bucket: postcard reads what it needs and leaves the rest.
    fn to_padded(&self) -> Vec<u8> {
        let mut bytes = postcard::to_allocvec(self).expect("blocks encode");
        bytes.resize(
            bytes.len().div_ceil(BLOCKS_BUCKET).max(1) * BLOCKS_BUCKET,
            0,
        );
        bytes
    }

    /// What the vault holds, or `None` for something else.
    fn from_bytes(bytes: &[u8]) -> Option<Blocks> {
        let mut blocks: Blocks = postcard::from_bytes(bytes).ok()?;
        blocks.trim();
        Some(blocks)
    }
}

/// What a device remembers of the log between runs; the host keeps it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogMemory {
    /// Newest entry read per conversation.
    pub cursors: HashMap<String, i64>,
    /// Per channel log, the accounts this device has told its user can read
    /// what they write there (`Event::Readers`).
    #[serde(default)]
    pub readers: HashMap<String, Vec<[u8; 16]>>,
    /// Per vault item, the newest generation this device has seen: an older
    /// one, or none, from the relay later is a rollback.
    #[serde(default)]
    pub vault_gens: HashMap<String, u64>,
    /// Per channel log, the bucket lists this device has named to its user, by digest
    /// (`log::Bucket::seal_list`): what it may seal to without reading the list again.
    #[serde(default)]
    pub named: HashMap<String, Vec<[u8; 32]>>,
}

/// What comes out besides messages to send.
#[derive(Debug)]
pub enum Event {
    /// A stored direct message, opened and its sender proven: the other party
    /// of the conversation (`peer`, by account) and whether we wrote it.
    Message {
        conv: String,
        peer: [u8; 16],
        peer_name: String,
        from_me: bool,
        envelope: Vec<u8>,
        sent_at: u64,
        server_at: u64,
        seq: i64,
    },
    /// A stored channel message, opened and its writer proven.
    ChannelMessage {
        conv: String,
        sender: [u8; 16],
        sender_name: String,
        from_me: bool,
        envelope: Vec<u8>,
        sent_at: u64,
        server_at: u64,
        seq: i64,
    },
    /// `account` (going by `name`) has another identity than the one pinned,
    /// or the name belonged to another account: told once.
    /// `replaced`: the name was another account's (`PinCheck::Replaced`).
    IdentityChanged {
        account: [u8; 16],
        name: String,
        replaced: bool,
    },
    /// A message we sent is kept for its recipient (`id` from its envelope).
    Kept { conv: String, seq: i64 },
    /// The relay refused to keep something (over quota, no storage).
    NotKept { reason: String },
    /// A conversation could not be read from the log, other than for now.
    NotRead { reason: String },
    /// These accounts can read what we write in channel log `conv` from now
    /// on (`history`: what we wrote there before, too). Shown to the user, so
    /// nobody — a member the relay made up included — gets our keys unseen.
    Readers {
        conv: String,
        accounts: Vec<([u8; 16], String)>,
        history: bool,
    },
    /// A vault item this device cannot use as the relay holds it ("missing",
    /// "older" than one seen before, "newer" VoIPC, "unreadable", or "hidden" in
    /// pages a relay this old cannot hand over): it is left alone this session,
    /// and the person is told.
    VaultProblem {
        item: &'static str,
        problem: &'static str,
    },
    /// Who is blocked now, as another device's list joined ours.
    Blocks { entries: Vec<(String, String)> },
    /// Entries in this channel log could not be opened: written before we joined, or before
    /// many people left. Said quietly, once a read.
    Unopened { conv: String },
    /// The relay no longer keeps what this device had not read of this channel log: it
    /// keeps the newest `window` entries.
    Clamped { conv: String, window: u32 },
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
            (m.id, m.text, m.ttl_secs, sent_at.min(server_at), m.extras)
        };
        // A tombstone: its writer's copies up to `before` go, wherever this
        // device keeps them. Never later than the relay filed it.
        let purge = |envelope: &[u8], server_at: u64| {
            crate::envelope::open_envelope(envelope)
                .purge_before
                .map(|b| b.min(server_at))
        };
        if let Event::Message {
            conv,
            peer,
            peer_name,
            from_me,
            envelope,
            server_at,
            ..
        } = self
        {
            if let Some(before) = purge(envelope, *server_at) {
                return Some((
                    "stored-purge",
                    serde_json::json!({ "conv": conv, "name": peer_name, "account": hex(peer), "from_me": from_me, "before": before }),
                ));
            }
        }
        if let Event::ChannelMessage {
            conv,
            sender,
            sender_name,
            from_me,
            envelope,
            server_at,
            ..
        } = self
        {
            if let Some(before) = purge(envelope, *server_at) {
                return Some((
                    "stored-purge",
                    serde_json::json!({ "conv": conv, "name": sender_name, "account": hex(sender), "from_me": from_me, "before": before }),
                ));
            }
        }
        // An edit, delete, reaction or pin: done to a message of the same
        // conversation by whoever sent it, named like a tombstone's writer
        // (the other party of a direct one, `from_me` for our own). Whether
        // they may is the front end's to check (`chat-rules.ts`).
        if let Event::Message {
            conv,
            peer: who,
            peer_name: name,
            from_me,
            envelope,
            sent_at,
            server_at,
            seq,
        }
        | Event::ChannelMessage {
            conv,
            sender: who,
            sender_name: name,
            from_me,
            envelope,
            sent_at,
            server_at,
            seq,
        } = self
        {
            let (id, text, ttl, at, extras) = opened(envelope, *sent_at, *server_at);
            if let Some(event) = extras.event {
                return Some((
                    "stored-event",
                    serde_json::json!({
                        "conv": conv, "seq": seq, "name": name, "account": hex(who), "from_me": from_me,
                        "message_id": id, "content": text, "ttl_secs": ttl, "timestamp": at, "event": event,
                    }),
                ));
            }
        }
        Some(match self {
            Event::Message {
                conv,
                peer,
                peer_name,
                from_me,
                envelope,
                sent_at,
                server_at,
                seq,
            } => {
                let (id, text, ttl, at, extras) = opened(envelope, *sent_at, *server_at);
                let payload = serde_json::json!({
                    "conv": conv, "seq": seq, "peer_account": hex(peer), "peer_name": peer_name, "from_me": from_me,
                    "message_id": id, "content": text, "ttl_secs": ttl, "timestamp": at,
                    "reply_to": extras.reply, "thread": extras.thread, "file": extras.file, "fwd": extras.fwd,
                });
                ("stored-dm", payload)
            }
            Event::ChannelMessage {
                conv,
                sender,
                sender_name,
                from_me,
                envelope,
                sent_at,
                server_at,
                seq,
            } => {
                let (id, text, ttl, at, extras) = opened(envelope, *sent_at, *server_at);
                let payload = serde_json::json!({
                    "conv": conv, "seq": seq, "sender_account": hex(sender), "sender_name": sender_name, "from_me": from_me,
                    "message_id": id, "content": text, "ttl_secs": ttl, "timestamp": at,
                    "reply_to": extras.reply, "thread": extras.thread, "file": extras.file, "fwd": extras.fwd,
                });
                ("stored-channel-message", payload)
            }
            Event::Readers {
                conv,
                accounts,
                history,
            } => {
                let names: Vec<&str> = accounts.iter().map(|(_, n)| n.as_str()).collect();
                (
                    "log-readers",
                    serde_json::json!({ "conv": conv, "names": names, "history": history }),
                )
            }
            Event::Kept { conv, seq } => {
                ("dm-kept", serde_json::json!({ "conv": conv, "seq": seq }))
            }
            Event::NotKept { reason } => {
                ("stored-not-kept", serde_json::json!({ "reason": reason }))
            }
            Event::NotRead { reason } => {
                ("stored-not-read", serde_json::json!({ "reason": reason }))
            }
            Event::VaultProblem { item, problem } => (
                "vault-problem",
                serde_json::json!({ "item": item, "problem": problem }),
            ),
            Event::Blocks { entries } => {
                ("account-blocks", serde_json::json!({ "blocks": entries }))
            }
            Event::Unopened { conv } => ("stored-unopened", serde_json::json!({ "conv": conv })),
            Event::Clamped { conv, window } => (
                "stored-clamped",
                serde_json::json!({ "conv": conv, "window": window }),
            ),
            Event::IdentityChanged { .. } => return None,
        })
    }

    /// Whether it moved this device's read cursors (they are saved after it).
    pub fn reads(&self) -> bool {
        matches!(
            self,
            Event::Message { .. }
                | Event::ChannelMessage { .. }
                | Event::Readers { .. }
                | Event::Unopened { .. }
        )
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
    blocks: Blocks,
    blocks_version: i64,
    /// Our older keys go to whoever joins a channel's log (the same consent
    /// as handing history over in person).
    share: bool,
    /// One write per item at a time; `dirty` says another is due after it.
    saving: HashSet<&'static str>,
    dirty: HashSet<&'static str>,
    /// Items the relay's copy of which we cannot use: never saved over.
    read_only: HashSet<&'static str>,
    /// `LogMemory::vault_gens`, and the generation each write in flight carries.
    gens: HashMap<String, u64>,
    writing_gen: HashMap<&'static str, u64>,
    /// `gens` moved since the host last kept the memory.
    memory_changed: bool,
    /// And of what it kept, `readers` or `named`.
    named_changed: bool,
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
    /// Those an empty `LogKeysFound` left without a key once, and asked for again.
    key_misses: HashSet<[u8; 16]>,
    /// Our own current epoch per conversation.
    own_epochs: HashMap<String, (u32, Zeroizing<[u8; 32]>)>,
    /// Every epoch key we hold: (conversation, owner, epoch).
    keys: HashMap<(String, [u8; 16], u32), Zeroizing<[u8; 32]>>,
    wraps_known: HashSet<String>,
    outbox: Vec<Outgoing>,
    /// Appends the relay has not answered yet, in order: the log, the epoch
    /// it went under, and (for a channel) the message, to send again on a rekey.
    in_flight: VecDeque<(String, u32, Option<Outgoing>)>,
    /// `tick`s since one of those last got an answer.
    append_idle: u32,
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
    /// Conversations waiting their turn: one read at a time, so a sign-in with
    /// many of them stays within the relay's budget.
    queue: VecDeque<String>,
    /// The read from `queue` now running.
    reading: Option<String>,
    /// Each `WrapsFetch` and `LogFetch` not answered yet, in order: a refusal
    /// names no conversation, so this says whose it is.
    fetch_asks: VecDeque<String>,
    /// News of a conversation being read: read it again when that ends.
    again: HashSet<String>,
    /// Refused for now: the queue waits for the next `tick`.
    held: bool,
    /// `tick`s since a read last got an answer.
    idle: u32,
    /// `LogIndex` asked and not answered yet, and asked again at the next `tick`.
    index_asked: bool,
    index_due: bool,
    /// The relay refused to keep the last copy we sent.
    copy_refused: bool,
    /// Entries waiting for a key (a wrap or a log key not yet in).
    waiting: Vec<(String, LogEntry)>,
    /// Entries opened this run: a fetch again (a key came in) hands them over once.
    opened: HashSet<(String, i64)>,
    /// Events from a send, handed out with the next reply.
    later: Vec<Event>,
    /// Our pins in pages, on a relay that keeps them so (`sync::pins`).
    book: pins::PinBook,
    /// `LogPendingMore`: another `LogIndex` once what it brought is answered. Only while one
    /// brings someone new: a joiner nobody can answer stays at the front of every page.
    pending_more: bool,
    pending_seen: HashSet<(String, [u8; 16])>,
    pending_new: bool,
    /// Channel logs with a gate: who is met there keeps the half of the pins' room open
    /// channels cannot fill.
    gated_logs: HashSet<String>,
    /// The relay keeps channel logs on chains and buckets (`sync::chains`).
    chains: bool,
    /// Per channel log, our chains and buckets as far as they were read back.
    writers: HashMap<String, chains::Writer>,
    /// The asks of `writers` not answered yet, in order, each with its request's name: a
    /// refusal names no conversation.
    writer_asks: VecDeque<(&'static str, String)>,
    /// Each `WrapsPage` not answered yet, in order.
    wraps_asked: VecDeque<chains::WrapsAsked>,
    /// Per channel log, what this device holds of every writer's chains.
    holds: HashMap<String, chains::Holds>,
    /// One X25519 per peer per connection: with the log key it was made from.
    statics: HashMap<[u8; 16], (Vec<u8>, Arc<StaticKey>)>,
    /// `LogMemory::named`.
    named: HashMap<String, HashSet<[u8; 32]>>,
    /// The `BucketLists` out, per channel log.
    lists_asked: HashMap<String, Vec<(u64, u32)>>,
    /// Whether the `ChainPage` being worked through says there is more, and where the last
    /// ask for one started.
    page_more: HashMap<String, bool>,
    page_after: HashMap<String, i64>,
    /// Entries of a read in progress that could not be opened.
    unopened: HashMap<String, u32>,
    /// Each `LogJoin` and `LogJoinMany` not answered yet, in order: a refusal names no
    /// conversation. And what to ask again at the next tick.
    join_asks: VecDeque<String>,
    join_many_asks: VecDeque<Vec<String>>,
    join_many_due: Vec<String>,
}

fn ask(r: AccountRequest) -> ClientMessage {
    ClientMessage::Account(r)
}

impl AccountSync {
    /// Starts after a sign-in: loads the vault items (making the log key if
    /// the account has none yet), publishes the log key, and asks which
    /// conversations kept something. `memory` is what this device kept last
    /// time; `share` is whether joiners get our older keys.
    pub fn start(
        signed: &SignedIn,
        me: [u8; 16],
        memory: LogMemory,
        share: bool,
    ) -> (AccountSync, Vec<ClientMessage>) {
        let blobs = &signed.blobs;
        let version = |k: &str| blobs.iter().find(|b| b.k == k).map_or(0, |b| b.version);
        let mut out = Vec::new();
        let mut gens = memory.vault_gens;
        let mut read_only = HashSet::new();
        let mut problems = Vec::new();
        // An item this device cannot use as the relay holds it is told about
        // and left alone: saving over it would let a relay (or an older
        // VoIPC) wipe it for every device of the account.
        let mut load = |k: &'static str, usable: &dyn Fn(&[u8]) -> bool| -> Option<Vec<u8>> {
            let seen = gens.get(k).copied().unwrap_or(0);
            let problem = match signed.vault.open_item(blobs, k) {
                Ok(item) if !usable(&item.payload) => "unreadable",
                Ok(item) if item.gen < seen => {
                    read_only.insert(k);
                    problems.push(Event::VaultProblem {
                        item: k,
                        problem: "older",
                    });
                    return Some(item.payload);
                }
                Ok(item) => {
                    gens.insert(k.to_string(), item.gen);
                    return Some(item.payload);
                }
                Err(VaultError::Missing) if seen == 0 => return None,
                Err(VaultError::Missing) => "missing",
                Err(VaultError::Newer) => "newer",
                Err(_) => "unreadable",
            };
            read_only.insert(k);
            problems.push(Event::VaultProblem { item: k, problem });
            None
        };
        // `item.pins` is the old single item or, as its format says, the index of pages
        let paged = matches!(signed.vault.open_item(blobs, ITEM_PINS), Ok(i) if i.format == pins::PIN_INDEX_FORMAT);
        let held = load(ITEM_PINS, &|b| {
            if paged {
                pins::PinIndex::from_bytes(b).is_some()
            } else {
                Pins::from_bytes(b).is_some()
            }
        });
        let (pins, index) = if paged {
            (
                Pins::default(),
                held.and_then(|b| pins::PinIndex::from_bytes(&b)),
            )
        } else {
            (
                held.and_then(|b| Pins::from_bytes(&b)).unwrap_or_default(),
                None,
            )
        };
        let prefs = load(ITEM_PREFS, &|b| postcard::from_bytes::<Prefs>(b).is_ok())
            .and_then(|b| postcard::from_bytes(&b).ok())
            .unwrap_or_default();
        let blocks = load(ITEM_BLOCKS, &|b| Blocks::from_bytes(b).is_some())
            .and_then(|b| Blocks::from_bytes(&b))
            .unwrap_or_default();
        let (logkey, logkey_version, fresh) =
            match load(ITEM_LOGKEY, &|b| LogKey::from_bytes(b).is_some())
                .and_then(|b| LogKey::from_bytes(&b))
            {
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
            blocks,
            blocks_version: version(ITEM_BLOCKS),
            share,
            saving: HashSet::new(),
            dirty: HashSet::new(),
            read_only,
            gens,
            writing_gen: HashMap::new(),
            memory_changed: true,
            named_changed: false,
            logkey,
            logkey_version,
            logkey_unsettled: fresh,
            peers: HashMap::new(),
            distrusted: HashSet::new(),
            asked_keys: HashSet::new(),
            key_asks: VecDeque::new(),
            key_misses: HashSet::new(),
            own_epochs: HashMap::new(),
            keys: HashMap::new(),
            wraps_known: HashSet::new(),
            outbox: Vec::new(),
            in_flight: VecDeque::new(),
            append_idle: 0,
            rekeys: HashMap::new(),
            members: HashMap::new(),
            asked_members: HashSet::new(),
            joined: HashSet::new(),
            joiners: HashMap::new(),
            owed: HashMap::new(),
            readers: memory
                .readers
                .into_iter()
                .map(|(c, r)| (c, r.into_iter().collect()))
                .collect(),
            cursors: memory.cursors,
            fetched: HashMap::new(),
            fetching: HashMap::new(),
            target: HashSet::new(),
            queue: VecDeque::new(),
            reading: None,
            fetch_asks: VecDeque::new(),
            again: HashSet::new(),
            held: false,
            idle: 0,
            index_asked: true,
            index_due: false,
            copy_refused: false,
            waiting: Vec::new(),
            opened: HashSet::new(),
            later: problems,
            book: pins::PinBook::reading(index),
            pending_more: false,
            pending_seen: HashSet::new(),
            pending_new: false,
            gated_logs: HashSet::new(),
            chains: false,
            writers: HashMap::new(),
            writer_asks: VecDeque::new(),
            wraps_asked: VecDeque::new(),
            holds: HashMap::new(),
            statics: HashMap::new(),
            named: memory
                .named
                .into_iter()
                .map(|(c, d)| (c, d.into_iter().collect()))
                .collect(),
            lists_asked: HashMap::new(),
            page_more: HashMap::new(),
            page_after: HashMap::new(),
            unopened: HashMap::new(),
            join_asks: VecDeque::new(),
            join_many_asks: VecDeque::new(),
            join_many_due: Vec::new(),
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
        ask(AccountRequest::LogKeyPublish {
            logkey: self.logkey.public(),
            sig: self.logkey.endorse(&self.identity),
        })
    }

    pub fn prefs(&self) -> Prefs {
        self.prefs
    }

    pub fn set_prefs(&mut self, prefs: Prefs) -> Vec<ClientMessage> {
        self.prefs = prefs;
        self.save(ITEM_PREFS)
    }

    /// Who is blocked, as the front end keys them (`Blocks::entries`).
    pub fn blocks(&self) -> Vec<(String, String)> {
        self.blocks.entries()
    }

    /// Blocks or unblocks the person `key` names (`a:<hex>`, `g:<lowercase
    /// name>`), under `label`. What goes to the relay is this one sealed item
    /// and nothing about anybody; nothing goes to the person. Refused where
    /// the list could not be kept: at the cap, or an item this device must not
    /// save over.
    pub fn set_block(
        &mut self,
        key: &str,
        label: &str,
        on: bool,
    ) -> Result<Vec<ClientMessage>, String> {
        if self.read_only.contains(ITEM_BLOCKS) {
            return Err(
                "Your blocked list could not be read here, so it cannot be changed now.".into(),
            );
        }
        Ok(if self.blocks.set(key, label, on)? {
            self.save(ITEM_BLOCKS)
        } else {
            Vec::new()
        })
    }

    pub fn set_share(&mut self, share: bool) {
        self.share = share;
    }

    /// The relay's protocol: from `KEPT_CHAINS_SINCE` channel logs go on chains and buckets.
    pub fn set_protocol(&mut self, proto: u32) {
        self.chains = proto >= voipc_protocol::types::KEPT_CHAINS_SINCE;
        self.pins_on_protocol(proto);
    }

    /// A channel log that has a gate (`TextJoined`).
    pub fn note_gated_log(&mut self, conv: &str) {
        self.gated_logs.insert(conv.to_string());
    }

    /// What the host keeps for next time.
    pub fn memory(&self) -> LogMemory {
        LogMemory {
            cursors: self.cursors.clone(),
            readers: self
                .readers
                .iter()
                .map(|(c, r)| (c.clone(), r.iter().copied().collect()))
                .collect(),
            vault_gens: self.gens.clone(),
            named: self
                .named
                .iter()
                .map(|(c, d)| (c.clone(), d.iter().copied().collect()))
                .collect(),
        }
    }

    /// Whether what `memory` returns moved in a way not tied to reading (a
    /// vault item's generation): the host keeps it again. Clears the flag.
    pub fn take_memory_changed(&mut self) -> bool {
        std::mem::take(&mut self.memory_changed)
    }

    /// Whether who it names as readers moved since this was last asked: thousands of ids a
    /// channel, which a host may keep apart. Clears the flag.
    pub fn take_named_changed(&mut self) -> bool {
        std::mem::take(&mut self.named_changed)
    }

    /// Whether `name` was first met as an account (a guest using it now is a
    /// warning: `AccountSession::note_roster`).
    pub fn knows_name(&self, name: &str) -> bool {
        self.pins.knows_name(name)
    }

    /// The relay refused to keep the last copy we sent (over quota, or
    /// written under a pseudonym): nobody is to be told it was kept.
    pub fn copy_refused(&self) -> bool {
        self.copy_refused
    }

    /// The key pinned for `account`, if any (for safety numbers).
    pub fn pinned(&self, account: &[u8; 16]) -> Option<&[u8]> {
        self.pins.get(account)
    }

    // ── vault items ──

    fn item_bytes(&self, k: &str) -> Vec<u8> {
        match k {
            ITEM_PINS if self.book.paged => self.book.index_bytes(),
            ITEM_PINS => self.pins.to_bytes(),
            ITEM_PREFS => postcard::to_allocvec(&self.prefs).expect("prefs encode"),
            ITEM_BLOCKS => self.blocks.to_padded(),
            _ => self.logkey.to_bytes().to_vec(),
        }
    }

    fn version_of(&mut self, k: &str) -> &mut i64 {
        match k {
            ITEM_PINS => &mut self.pins_version,
            ITEM_PREFS => &mut self.prefs_version,
            ITEM_BLOCKS => &mut self.blocks_version,
            _ => &mut self.logkey_version,
        }
    }

    fn save(&mut self, k: &'static str) -> Vec<ClientMessage> {
        if self.read_only.contains(k) {
            return Vec::new();
        }
        if !self.saving.insert(k) {
            self.dirty.insert(k);
            return Vec::new();
        }
        self.dirty.remove(k);
        let gen = self.gens.get(k).copied().unwrap_or(0) + 1;
        self.writing_gen.insert(k, gen);
        let blob = if k == ITEM_PINS && self.book.paged {
            self.vault
                .seal_item_as(k, gen, pins::PIN_INDEX_FORMAT, &self.item_bytes(k))
        } else {
            self.vault.seal_item(k, gen, &self.item_bytes(k))
        };
        let expect = *self.version_of(k);
        vec![ask(AccountRequest::VaultPut {
            k: blob.k,
            v: blob.v,
            expect,
        })]
    }

    fn which(k: &str) -> Option<&'static str> {
        [ITEM_PINS, ITEM_PREFS, ITEM_BLOCKS, ITEM_LOGKEY]
            .into_iter()
            .find(|i| *i == k)
    }

    /// A vault answer for one of our items.
    fn on_vault(
        &mut self,
        k: &'static str,
        stored: Option<i64>,
        theirs: Option<&VaultBlob>,
    ) -> Vec<ClientMessage> {
        let mut settled = stored.is_some();
        let written = self.writing_gen.remove(k);
        match (stored, theirs) {
            (Some(v), _) => {
                *self.version_of(k) = v;
                if let Some(gen) = written {
                    self.gens.insert(k.to_string(), gen);
                    self.memory_changed = true;
                }
            }
            (None, Some(b)) => {
                // Another device wrote first: pins and blocks join, a log key or
                // prefs of theirs win (the log key: two would leave wraps to the wrong one).
                // One we cannot use is left alone, as at start.
                match self.vault.open_item(std::slice::from_ref(b), k) {
                    Ok(item) => {
                        let seen = self.gens.entry(k.to_string()).or_insert(0);
                        *seen = (*seen).max(item.gen);
                        self.memory_changed = true;
                        let plain = item.payload;
                        match k {
                            ITEM_PINS => self.on_pins_conflict(Item {
                                format: item.format,
                                gen: item.gen,
                                payload: plain,
                            }),
                            ITEM_PREFS => {
                                if let Ok(p) = postcard::from_bytes(&plain) {
                                    self.prefs = p;
                                }
                            }
                            ITEM_BLOCKS => {
                                if let Some(theirs) = Blocks::from_bytes(&plain) {
                                    self.blocks.join(theirs);
                                    self.dirty.insert(k);
                                    self.later.push(Event::Blocks {
                                        entries: self.blocks.entries(),
                                    });
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
                    Err(e) => {
                        let problem = if e == VaultError::Newer {
                            "newer"
                        } else {
                            "unreadable"
                        };
                        self.read_only.insert(k);
                        self.dirty.remove(k);
                        self.later.push(Event::VaultProblem { item: k, problem });
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
        let mut out = if self.dirty.contains(k) {
            self.save(k)
        } else {
            Vec::new()
        };
        if k == ITEM_PINS {
            out.extend(self.pins_read_more());
        }
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
    pub fn check_peer(
        &mut self,
        account: &[u8; 16],
        name: &str,
        identity: &[u8],
    ) -> (PinCheck, Vec<ClientMessage>) {
        let name_was = self
            .book
            .paged
            .then(|| self.pins.owner_of_name(name))
            .flatten();
        let check = self.pins.check(account, name, identity);
        let out = if self.book.paged {
            self.pin_noted(account, name.len(), name_was, check)
        } else if check == PinCheck::Same {
            Vec::new()
        } else {
            self.save(ITEM_PINS)
        };
        if check.warns() {
            // Keys learned under the old identity are not good any more.
            self.peers.remove(account);
            self.asked_keys.remove(account);
        }
        (check, out)
    }

    /// Takes in the relay's word for some accounts' keys: the log key is
    /// checked against the identity, then the identity and the name against
    /// the pins. Returns the accounts now trusted.
    fn learn(
        &mut self,
        keys: &[LogKeyInfo],
        out: &mut Vec<ClientMessage>,
        events: &mut Vec<Event>,
    ) -> Vec<[u8; 16]> {
        let mut trusted = Vec::new();
        for LogKeyInfo {
            account,
            name,
            identity,
            logkey,
            sig,
        } in keys
        {
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
            if check.warns() {
                events.push(Event::IdentityChanged {
                    account: *account,
                    name: name.clone(),
                    replaced: check == PinCheck::Replaced,
                });
            }
            self.peers.insert(
                *account,
                Peer {
                    name: name.clone(),
                    logkey: logkey.clone(),
                },
            );
            self.distrusted.remove(account);
            trusted.push(*account);
        }
        trusted
    }

    fn ask_keys(&mut self, accounts: impl IntoIterator<Item = [u8; 16]>) -> Vec<ClientMessage> {
        let want: Vec<[u8; 16]> = accounts
            .into_iter()
            .filter(|a| {
                *a != self.me
                    && !self.peers.contains_key(a)
                    && !self.distrusted.contains(a)
                    && self.asked_keys.insert(*a)
            })
            .collect();
        want.chunks(KEYS_PER_ASK)
            .map(|c| {
                self.key_asks.push_back(c.to_vec());
                ask(AccountRequest::LogKeys {
                    accounts: c.to_vec(),
                })
            })
            .collect()
    }

    // ── sending ──

    /// A direct message to `peer` to keep for them too, when cloud copies
    /// are on. Nothing goes out while what it needs is still being fetched.
    pub fn send_dm(
        &mut self,
        peer: [u8; 16],
        envelope: Vec<u8>,
        sent_at: u64,
        ttl_secs: Option<u32>,
    ) -> Vec<ClientMessage> {
        if !self.prefs.cloud {
            return Vec::new();
        }
        self.keep_dm(peer, envelope, sent_at, ttl_secs)
    }

    /// One direct message to keep for `peer` whatever cloud copies say: a report
    /// to someone away, which its writer chose to keep sealed for that one
    /// message (`AccountSession::kept_dm`).
    pub fn keep_dm(
        &mut self,
        peer: [u8; 16],
        envelope: Vec<u8>,
        sent_at: u64,
        ttl_secs: Option<u32>,
    ) -> Vec<ClientMessage> {
        if peer == self.me {
            return Vec::new();
        }
        self.reserve_pin(peer);
        self.outbox.push(Outgoing {
            conv: dm_conv(&self.me, &peer),
            peer: Some(peer),
            envelope,
            sent_at,
            ttl_secs,
        });
        self.flush()
    }

    /// A message written in a channel with a log (`ChannelInfo::log`), kept
    /// for its members when cloud copies are on.
    pub fn send_channel(
        &mut self,
        conv: &str,
        envelope: Vec<u8>,
        sent_at: u64,
        ttl_secs: Option<u32>,
    ) -> Vec<ClientMessage> {
        if !self.prefs.cloud || !is_channel(conv) {
            return Vec::new();
        }
        let mut out = Vec::new();
        if self.joined.insert(conv.to_string()) {
            out.push(self.ask_join(conv));
        }
        self.outbox.push(Outgoing {
            conv: conv.to_string(),
            peer: None,
            envelope,
            sent_at,
            ttl_secs,
        });
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
            return vec![self.ask_join(conv)];
        }
        self.fetch(conv)
    }

    /// A key for us, or a message: what waited for it, and what came after. A burst of them
    /// while it is being read is one more read.
    fn read_news(&mut self, conv: &str) -> Vec<ClientMessage> {
        self.wraps_known.remove(conv);
        self.chain_news(conv);
        if self.fetching.contains_key(conv) {
            self.target.insert(conv.to_string());
            self.again.insert(conv.to_string());
            return Vec::new();
        }
        self.fetch(conv)
    }

    /// A channel that slept (quiet mode) came on screen. Nothing told us of what was written
    /// meanwhile: `LogNews` comes for a new key or seat, not for a post on a chain we hold.
    /// With no seat there is nothing to read, and opening a channel takes none.
    pub fn read_now(&mut self, conv: &str) -> Vec<ClientMessage> {
        if !self.joined.contains(conv) {
            return Vec::new();
        }
        self.read_news(conv)
    }

    fn ask_join(&mut self, conv: &str) -> ClientMessage {
        if self.chains {
            self.join_asks.push_back(conv.to_string());
        }
        ask(AccountRequest::LogJoin {
            conv: conv.to_string(),
        })
    }

    /// `enter` for channels newly followed, all in one frame where the relay takes that:
    /// joining tells nobody, and a silent follow takes a log only up to half its seats.
    pub fn enter_many(&mut self, convs: &[String]) -> Vec<ClientMessage> {
        if !self.prefs.cloud {
            return Vec::new();
        }
        if !self.chains {
            return convs.iter().flat_map(|c| self.enter(c)).collect();
        }
        self.enter_many_on_chains(convs)
    }

    /// `account` was put out of this channel's log, or left it (`MemberGone`; `None`: nobody
    /// with an account we can tell, so no seat we know of). If we could have reached them, our
    /// chain there ends at our next post, whatever the relay says, and they are named again
    /// if they come back.
    pub fn member_gone(&mut self, conv: &str, account: Option<[u8; 16]>) {
        if let (true, Some(a)) = (self.on_chains(conv), account) {
            self.someone_left(conv, &a);
        }
    }

    /// Out of a channel's log: the relay took us out (we left the text
    /// channel, or were kicked) or, with `tell`, is asked to ("Stop keeping
    /// this channel", for a voice channel's log, where moving between rooms
    /// keeps it). What this run knew of it goes, so a rejoin keeps it again
    /// and names its readers again; every remaining writer starts a new key
    /// on their next post. The keys already held stay: what was written
    /// while we were in is still ours to read.
    pub fn leave(&mut self, conv: &str, tell: bool) -> Vec<ClientMessage> {
        if !is_channel(conv) {
            return Vec::new();
        }
        self.joined.remove(conv);
        self.members.remove(conv);
        self.asked_members.remove(conv);
        self.own_epochs.remove(conv);
        self.target.remove(conv);
        self.again.remove(conv);
        self.owed.remove(conv);
        self.joiners.remove(conv);
        self.readers.remove(conv);
        self.rekeys.remove(conv);
        self.named.remove(conv);
        self.memory_changed = true;
        self.named_changed = true;
        self.writers.remove(conv);
        if self.on_chains(conv) {
            self.end_chain(conv, None);
        }
        if tell {
            vec![ask(AccountRequest::LogLeave {
                conv: conv.to_string(),
            })]
        } else {
            Vec::new()
        }
    }

    /// Reads `conv` from our cursor, in its turn: its wraps first, then entries.
    fn fetch(&mut self, conv: &str) -> Vec<ClientMessage> {
        self.target.insert(conv.to_string());
        if self.fetching.contains_key(conv) || self.queue.iter().any(|c| c == conv) {
            return Vec::new();
        }
        self.queue.push_back(conv.to_string());
        self.next_read()
    }

    /// The next read waiting, unless one runs or the relay asked us to wait.
    fn next_read(&mut self) -> Vec<ClientMessage> {
        if self.held || self.reading.is_some() {
            return Vec::new();
        }
        while let Some(conv) = self.queue.pop_front() {
            // Left since, or a send started on it meanwhile
            if !self.target.contains(&conv) || self.fetching.contains_key(&conv) {
                continue;
            }
            self.reading = Some(conv.clone());
            if self.on_chains(&conv) {
                // The rows follow from which chains its entries are on
                self.fetching.insert(conv.clone(), Fetch::Entries);
                return vec![self.first_page(&conv)];
            }
            self.fetching.insert(conv.clone(), Fetch::Wraps);
            return vec![self.ask_wraps(&conv)];
        }
        Vec::new()
    }

    /// A read of `conv` is over, however it went: the news that came during
    /// it, then the next one waiting.
    fn fetch_done(&mut self, conv: &str) -> Vec<ClientMessage> {
        self.fetching.remove(conv);
        if self.reading.as_deref() == Some(conv) {
            self.reading = None;
        }
        let mut out = Vec::new();
        if self.again.remove(conv) {
            out.extend(self.fetch(conv));
        }
        out.extend(self.next_read());
        out
    }

    /// An answer that will not come (refused for now, or lost): `conv` gets
    /// its turn again.
    fn ask_again(&mut self, conv: &str) {
        self.fetching.remove(conv);
        if self.reading.as_deref() == Some(conv) {
            self.reading = None;
        }
        if self.target.contains(conv) && !self.queue.iter().any(|c| c == conv) {
            self.queue.push_front(conv.to_string());
        }
    }

    fn ask_wraps(&mut self, conv: &str) -> ClientMessage {
        self.fetch_asks.push_back(conv.to_string());
        ask(AccountRequest::WrapsFetch {
            conv: conv.to_string(),
        })
    }

    fn ask_page(&mut self, conv: &str, after: i64) -> ClientMessage {
        self.fetch_asks.push_back(conv.to_string());
        let conv_name = conv.to_string();
        ask(if self.on_chains(conv) {
            self.page_after.insert(conv.to_string(), after);
            AccountRequest::ChainFetch {
                conv: conv_name,
                after,
            }
        } else {
            AccountRequest::LogFetch {
                conv: conv_name,
                after,
            }
        })
    }

    /// The `LogFetch` that starts a read of `conv`: past our cursor, or with
    /// none the newest entries.
    fn first_page(&mut self, conv: &str) -> ClientMessage {
        let after = match self.cursors.get(conv) {
            Some(c) if *c > 0 => *c,
            _ => -READ_BACK,
        };
        self.ask_page(conv, after)
    }

    /// `conv`'s read got its answer. Answers come in order, so an ask ahead of
    /// it never will.
    fn answered(&mut self, conv: &str) {
        self.idle = 0;
        let Some(at) = self.fetch_asks.iter().position(|c| c == conv) else {
            return;
        };
        let lost: Vec<String> = self.fetch_asks.drain(..=at).take(at).collect();
        for c in lost {
            self.ask_again(&c);
        }
    }

    /// What waited for log keys goes on to its entries.
    fn keys_in(&mut self) -> Vec<ClientMessage> {
        let ready: Vec<String> = self
            .fetching
            .iter()
            .filter(|(_, f)| **f == Fetch::Keys)
            .map(|(c, _)| c.clone())
            .collect();
        let mut out = Vec::new();
        for conv in ready {
            if self.target.contains(&conv) {
                if self.on_chains(&conv) {
                    out.extend(self.chain_read(&conv));
                    continue;
                }
                self.fetching.insert(conv.clone(), Fetch::Entries);
                out.push(self.first_page(&conv));
            } else {
                out.extend(self.fetch_done(&conv));
            }
        }
        out
    }

    /// Every couple of seconds while connected, from the host: goes on after
    /// the relay asked us to wait, and after an answer that never came (the
    /// relay drops a reply on a full queue). Nothing else ever would.
    pub fn tick(&mut self) -> (Vec<ClientMessage>, Vec<Event>) {
        self.held = false;
        // What it would go on with waits for the pages, and is no answer lost
        if !self.pins_in() {
            let out = self.pins_wait_tick();
            return (out, std::mem::take(&mut self.later));
        }
        if self.pending_more && self.joiners.is_empty() {
            self.pending_more = false;
            self.index_due = true;
        }
        self.tick_appends();
        let waiting = !self.fetch_asks.is_empty() || !self.key_asks.is_empty() || self.index_asked;
        self.idle = if waiting { self.idle + 1 } else { 0 };
        if self.idle >= LOST_AFTER_TICKS {
            self.idle = 0;
            for conv in std::mem::take(&mut self.fetch_asks) {
                self.ask_again(&conv);
            }
            self.wraps_asked.retain(chains::WrapsAsked::is_writer);
            for a in std::mem::take(&mut self.key_asks).into_iter().flatten() {
                self.asked_keys.remove(&a);
            }
            self.index_due |= std::mem::take(&mut self.index_asked);
        }
        let mut out = Vec::new();
        if std::mem::take(&mut self.index_due) {
            self.index_asked = true;
            out.push(ask(AccountRequest::LogIndex));
        }
        // The keys conversations wait for, if that ask was refused or lost
        let want: Vec<[u8; 16]> = self
            .fetching
            .iter()
            .filter(|(_, f)| **f == Fetch::Keys)
            .filter_map(|(c, _)| self.other_party(c))
            .collect();
        out.extend(self.ask_keys(want));
        // Their writers' on chains: `chain_read` asks again, once `keys_in` gets there
        // Nothing asked, because they came in some other way meanwhile
        if self.key_asks.is_empty() {
            out.extend(self.keys_in());
        }
        out.extend(self.next_read());
        let mut events = Vec::new();
        self.drain(&mut out, &mut events);
        out.extend(self.tick_writers());
        out.extend(self.flush());
        out.extend(self.answer());
        out.extend(self.pins_tick(crate::time::now_millis()));
        let mut all = std::mem::take(&mut self.later);
        all.extend(events);
        (out, all)
    }

    /// The relay drops an answer on a full queue, and what follows waits behind it: a
    /// refusal for all that went under its key never settles with one that will not come.
    fn tick_appends(&mut self) {
        if self.in_flight.is_empty() {
            self.append_idle = 0;
            return;
        }
        self.append_idle += 1;
        if self.append_idle >= APPEND_LOST_AFTER_TICKS {
            self.append_idle = 0;
            self.in_flight.clear();
            self.copy_refused = true;
            self.later.push(Event::NotKept {
                reason: "it did not answer in time, so a message may be missing there".into(),
            });
        }
    }

    fn flush(&mut self) -> Vec<ClientMessage> {
        if self.logkey_unsettled || !self.pins_in() {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut keep = Vec::new();
        let mut blocked = BTreeSet::new();
        for o in std::mem::take(&mut self.outbox) {
            let conv = o.conv.clone();
            if o.peer.is_none() && self.on_chains(&conv) {
                let Some((epoch, ct)) = self.seal_on_chain(&o) else {
                    blocked.insert(conv);
                    keep.push(o);
                    continue;
                };
                out.push(ask(AccountRequest::LogAppend {
                    conv: conv.clone(),
                    epoch,
                    ct,
                    ttl_secs: o.ttl_secs,
                }));
                self.in_flight.push_back((conv, epoch, Some(o)));
                continue;
            }
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
                        out.push(self.ask_wraps(&conv));
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
            let ct = seal_entry(
                key,
                &conv,
                &self.me,
                epoch,
                &self.logkey,
                &o.envelope,
                o.sent_at,
            );
            out.push(ask(AccountRequest::LogAppend {
                conv: conv.clone(),
                epoch,
                ct,
                ttl_secs: o.ttl_secs,
            }));
            self.in_flight
                .push_back((conv, epoch, o.peer.is_none().then_some(o)));
        }
        self.outbox = keep;
        for conv in blocked {
            out.extend(self.advance(&conv));
        }
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
    fn wraps_for(
        &self,
        recipients: &[[u8; 16]],
        key: &[u8; 32],
        conv: &str,
        epoch: u32,
    ) -> Vec<WrapIn> {
        recipients
            .iter()
            .filter_map(|r| {
                let wrapped = if *r == self.me {
                    self_wrap(&self.logkey, key, conv, &self.me, epoch)
                } else {
                    wrap(&self.logkey_of(r)?, key, conv, &self.me, epoch, r)?
                };
                Some(WrapIn {
                    recipient: *r,
                    wrapped,
                })
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
        self.keys
            .insert((conv.to_string(), self.me, epoch), Zeroizing::new(*k));
        self.own_epochs.insert(conv.to_string(), (epoch, k));
        self.announce(conv, &recipients, false);
        vec![ask(AccountRequest::EpochPut {
            conv: conv.to_string(),
            epoch,
            wraps,
        })]
    }

    /// Tells the user about readers of a channel log this device has not
    /// named to them before.
    fn announce(&mut self, conv: &str, accounts: &[[u8; 16]], history: bool) {
        if !is_channel(conv) {
            return;
        }
        let seen = self.readers.entry(conv.to_string()).or_default();
        let new: Vec<[u8; 16]> = accounts
            .iter()
            .filter(|a| **a != self.me && !seen.contains(*a))
            .copied()
            .collect();
        if new.is_empty() {
            return;
        }
        seen.extend(new.iter().copied());
        self.named_changed = true;
        let accounts = new
            .iter()
            .map(|a| {
                (
                    *a,
                    self.peers
                        .get(a)
                        .map(|p| p.name.clone())
                        .unwrap_or_default(),
                )
            })
            .collect();
        self.later.push(Event::Readers {
            conv: conv.to_string(),
            accounts,
            history,
        });
    }

    /// Answers whoever joined a channel log since we last wrapped there:
    /// our older keys when we share with joiners, else a new epoch for all.
    fn answer(&mut self) -> Vec<ClientMessage> {
        if self.logkey_unsettled || !self.pins_in() {
            return Vec::new();
        }
        let mut out = Vec::new();
        let convs: Vec<String> = self.joiners.keys().cloned().collect();
        for conv in convs {
            if self.on_chains(&conv) {
                out.extend(self.advance(&conv));
                continue;
            }
            let joiners: Vec<[u8; 16]> = self.joiners[&conv].iter().copied().collect();
            out.extend(self.ask_keys(joiners.iter().copied()));
            if joiners
                .iter()
                .any(|j| !self.peers.contains_key(j) && !self.distrusted.contains(j))
            {
                continue; // their keys are on the way
            }
            if !self.wraps_known.contains(&conv) {
                if !self.fetching.contains_key(&conv) {
                    self.fetching.insert(conv.clone(), Fetch::Wraps);
                    out.push(self.ask_wraps(&conv));
                }
                continue;
            }
            let trusted: Vec<[u8; 16]> = joiners
                .into_iter()
                .filter(|j| self.peers.contains_key(j))
                .collect();
            let mine: Vec<(u32, Zeroizing<[u8; 32]>)> = self
                .keys
                .iter()
                .filter(|((c, o, _), _)| *c == conv && *o == self.me)
                .map(|((_, _, e), k)| (*e, k.clone()))
                .collect();
            if self.share && !mine.is_empty() {
                for (epoch, k) in mine {
                    let wraps = self.wraps_for(&trusted, &k, &conv, epoch);
                    for chunk in wraps.chunks(chains::WRAPS_PER_FRAME) {
                        out.push(ask(AccountRequest::EpochPut {
                            conv: conv.clone(),
                            epoch,
                            wraps: chunk.to_vec(),
                        }));
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
            if dm_parties(&conv)
                .is_some_and(|(a, b)| !(a == me || b == me) || !(e.sender == a || e.sender == b))
            {
                continue;
            }
            // Read before: a relay that hands it out again (ignoring `after`)
            // must not bring back what the person cleared (1.0 audit H2-06)
            if e.seq <= self.cursors.get(&conv).copied().unwrap_or(0) {
                continue;
            }
            let waits_for_writer = self.owed.get(&conv).is_some_and(|o| o.contains(&e.sender))
                || self.again.contains(&conv);
            let (envelope, sent_at) = if self.on_chains(&conv) {
                let Some(signer) = self.logkey_of(&e.sender) else {
                    if self.distrusted.contains(&e.sender) {
                        self.count_unopened(&conv);
                    } else {
                        unknown.push(e.sender);
                        still.push((conv, e));
                    }
                    continue;
                };
                // What a version before chains kept, under a writer's epoch: signed over
                // its own label, so it opens only as what it was written as.
                let old = self
                    .keys
                    .get(&(conv.clone(), e.sender, e.epoch))
                    .and_then(|key| {
                        open_entry(key, &conv, &e.sender, e.epoch, &signer, &e.ct).ok()
                    });
                match old.map_or_else(|| self.open_on_chain(&conv, &e, &signer), |o| Ok(Some(o))) {
                    Ok(Some(opened)) => opened,
                    Ok(None) => {
                        still.push((conv, e));
                        continue;
                    }
                    Err(()) => {
                        // While its read asks for keys, it may open yet
                        if waits_for_writer || self.fetching.get(&conv) == Some(&Fetch::Wraps) {
                            still.push((conv, e));
                        } else {
                            self.count_unopened(&conv);
                        }
                        continue;
                    }
                }
            } else {
                let Some(key) = self.keys.get(&(conv.clone(), e.sender, e.epoch)) else {
                    // Not ours to read, unless its writer still owes us an answer,
                    // or told us of a key after we asked for the wraps.
                    if waits_for_writer {
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
                let Ok(opened) = open_entry(key, &conv, &e.sender, e.epoch, &signer, &e.ct) else {
                    continue;
                };
                opened
            };
            if !self.opened.insert((conv.clone(), e.seq)) {
                continue;
            }
            if let Some(peer) = self.other_party(&conv) {
                self.reserve_pin(peer);
            }
            let from_me = e.sender == me;
            let name_of = |a: &[u8; 16]| {
                self.peers
                    .get(a)
                    .map(|p| p.name.clone())
                    .unwrap_or_default()
            };
            if let Some(peer) = self.other_party(&conv) {
                events.push(Event::Message {
                    conv,
                    peer,
                    peer_name: name_of(&peer),
                    from_me,
                    envelope,
                    sent_at,
                    server_at: e.server_at,
                    seq: e.seq,
                });
            } else {
                let sender_name = if from_me {
                    self.name.clone()
                } else {
                    name_of(&e.sender)
                };
                events.push(Event::ChannelMessage {
                    conv,
                    sender: e.sender,
                    sender_name,
                    from_me,
                    envelope,
                    sent_at,
                    server_at: e.server_at,
                    seq: e.seq,
                });
            }
        }
        self.waiting = still;
        out.extend(self.ask_keys(unknown));
        // Read up to the first entry still waiting: it may open next time.
        for (conv, last) in &self.fetched {
            let held = self
                .waiting
                .iter()
                .filter(|(c, _)| c == conv)
                .map(|(_, e)| e.seq)
                .min();
            let upto = held.map_or(*last, |h| h.saturating_sub(1).min(*last));
            let c = self.cursors.entry(conv.clone()).or_insert(0);
            *c = (*c).max(upto);
        }
    }

    /// One `AccountReply`: what to send, and what happened. Replies this does
    /// not handle (codes, the device key) come back as `None` for the host.
    pub fn on_reply(&mut self, reply: &AccountReply) -> Option<(Vec<ClientMessage>, Vec<Event>)> {
        let mut out = Vec::new();
        let mut events = Vec::new();
        if self.holds_for_pages(reply) {
            return Some((out, std::mem::take(&mut self.later)));
        }
        match reply {
            AccountReply::VaultStored { k, version } if k.starts_with("pins.") => {
                out.extend(self.on_page_stored(k, *version))
            }
            AccountReply::VaultConflict { k, blob } if k.starts_with("pins.") => {
                out.extend(self.on_page_conflict(k, blob.as_ref()))
            }
            AccountReply::VaultPageFound { k, blob } => {
                self.on_pin_page(k, blob.as_ref(), &mut out, &mut events)
            }
            AccountReply::Error { request, reason } if request == "VaultPage" => {
                self.on_page_refused(reason, &mut out, &mut events)
            }
            AccountReply::LogPendingMore => {
                self.pending_more = std::mem::take(&mut self.pending_new);
            }
            AccountReply::VaultStored { k, version } => {
                out.extend(self.on_vault(Self::which(k)?, Some(*version), None))
            }
            AccountReply::VaultConflict { k, blob } => {
                out.extend(self.on_vault(Self::which(k)?, None, blob.as_ref()))
            }
            AccountReply::Error { request, reason } if request == "VaultPut" => {
                self.saving.clear();
                self.pin_write_refused(reason);
                // For now is not news when it goes again by itself
                if !self.book.paged || !reason.contains(SLOW_DOWN) {
                    events.push(Event::NotKept {
                        reason: reason.clone(),
                    });
                }
            }
            AccountReply::Error { request, reason }
                if request.starts_with("Log")
                    || request.starts_with("Epoch")
                    || request.starts_with("Wraps")
                    || request.starts_with("Chain")
                    || request.starts_with("Own")
                    || request == "BucketLists" =>
            {
                let for_now = reason.contains(SLOW_DOWN);
                // Whose `WrapsPage` it was: a read's goes on as a `LogFetch`'s does.
                let writers_page = request == "WrapsPage"
                    && self.wraps_asked.front().is_some_and(|a| a.is_writer());
                let writers_epoch = self.writer_asks.iter().any(|(what, _)| *what == "EpochPut");
                if request == "WrapsPage" {
                    self.wraps_asked.pop_front();
                }
                match request.as_str() {
                    "WrapsFetch" | "LogFetch" | "ChainFetch" | "WrapsPage" if !writers_page => {
                        self.idle = 0;
                        if let Some(conv) = self.fetch_asks.pop_front() {
                            if for_now {
                                self.held = true;
                                self.ask_again(&conv);
                            } else {
                                // Not ours, then: what waits for it would ask
                                // again at every tick.
                                self.target.remove(&conv);
                                self.joiners.remove(&conv);
                                self.outbox.retain(|o| o.conv != conv);
                                out.extend(self.fetch_done(&conv));
                                events.push(Event::NotRead {
                                    reason: reason.clone(),
                                });
                            }
                        }
                    }
                    "WrapsPage" | "OwnChains" | "OwnBuckets" | "BucketLists" | "OwnChainRows"
                    | "ChainPut" | "LogMemberIds" | "EpochPut"
                        if request != "EpochPut" || writers_epoch =>
                    {
                        let conv = self
                            .writer_asks
                            .iter()
                            .find(|(what, _)| what == request)
                            .map(|(_, conv)| conv.clone());
                        if let Some(conv) = conv {
                            if for_now {
                                // What it holds stays, and the next tick goes on
                                self.held = true;
                                self.writer_held(&conv, request);
                            } else if self.join_asks.contains(&conv) {
                                // Refused ahead of a seat on its way: goes on the same, for
                                // a round or two if that answer was lost
                                self.writer_held(&conv, request);
                                self.round(&conv, &mut events);
                            } else {
                                // Nothing waiting is nothing to tell: a seat refused has
                                // said so, or said nothing on purpose. A post is always told.
                                let posts = self.outbox.iter().any(|o| o.conv == conv);
                                let waited = posts || self.joiners.contains_key(&conv);
                                self.writer_refused(&conv, request);
                                if request == "ChainPut" || posts {
                                    self.copy_refused = true;
                                }
                                if posts || (waited && self.joined.contains(&conv)) {
                                    events.push(Event::NotKept {
                                        reason: reason.clone(),
                                    });
                                }
                            }
                        }
                    }
                    "LogJoinMany" => self.join_many_refused(for_now, reason),
                    "LogJoin" if self.chains => {
                        if let Some(conv) = self.join_asks.pop_front() {
                            // Just left holding a key: a wait, not news, unless a post is
                            // lost to it. The next time it is entered asks again.
                            let waits = reason.contains("again later");
                            if for_now || waits {
                                self.joined.remove(&conv);
                            }
                            self.held |= for_now;
                            let posts = self.outbox.iter().any(|o| o.conv == conv);
                            self.outbox.retain(|o| o.conv != conv);
                            self.copy_refused |= posts;
                            if posts || (!for_now && !waits) {
                                events.push(Event::NotKept {
                                    reason: reason.clone(),
                                });
                            }
                        }
                    }
                    "LogKeys" => {
                        self.idle = 0;
                        for a in self.key_asks.pop_front().unwrap_or_default() {
                            self.asked_keys.remove(&a);
                        }
                        if for_now {
                            self.held = true;
                        } else {
                            out.extend(self.keys_in());
                        }
                    }
                    "LogIndex" => {
                        self.index_asked = false;
                        if for_now {
                            self.held = true;
                            self.index_due = true;
                        } else {
                            events.push(Event::NotRead {
                                reason: reason.clone(),
                            });
                        }
                    }
                    "LogMembers" if for_now => {
                        self.held = true;
                        self.asked_members.clear();
                    }
                    _ => {
                        if request == "LogAppend" {
                            self.in_flight.pop_front();
                            self.append_idle = 0;
                            self.copy_refused = true;
                        }
                        events.push(Event::NotKept {
                            reason: reason.clone(),
                        });
                    }
                }
            }
            AccountReply::EpochStored { conv, .. } if self.on_chains(conv) => {
                self.on_chain_stored(conv, false, "EpochPut", &mut out, &mut events);
                out.extend(self.advance(conv));
                out.extend(self.flush());
                out.extend(self.answer());
            }
            AccountReply::LogKeyStored
            | AccountReply::EpochStored { .. }
            | AccountReply::LogLeft { .. } => {}
            // Our entries there are gone, and the keys we handed out with
            // them: the next post starts a new one. The front end hears of it
            // too (`account-reply`).
            AccountReply::LogPurged { conv, .. } => {
                match conv {
                    Some(c) => {
                        self.own_epochs.remove(c);
                    }
                    None => self.own_epochs.clear(),
                }
                self.purged(conv.as_deref());
                return None;
            }
            AccountReply::LogConvs { convs } => {
                self.index_asked = false;
                let unread: Vec<&String> = convs
                    .iter()
                    .filter(|(conv, last)| {
                        *last > self.cursors.get(conv).copied().unwrap_or(0)
                            && (dm_parties(conv).is_some() || is_channel(conv))
                    })
                    .map(|(conv, _)| conv)
                    .collect();
                // The other parties' keys in one ask, not one per conversation
                let peers: Vec<[u8; 16]> = unread
                    .iter()
                    .filter_map(|conv| self.other_party(conv))
                    .collect();
                for peer in &peers {
                    self.reserve_pin(*peer);
                }
                out.extend(self.ask_keys(peers));
                for conv in unread {
                    out.extend(self.fetch(conv));
                }
            }
            AccountReply::LogJoined { conv } => {
                if let Some(at) = self.join_asks.iter().position(|c| c == conv) {
                    self.join_asks.remove(at);
                }
                out.extend(self.fetch(conv))
            }
            AccountReply::LogJoinedMany { joined, refused } => {
                out.extend(self.on_joined_many(joined, refused))
            }
            AccountReply::ChainPage {
                conv,
                entries,
                more,
                owed,
                skipped,
                upto,
                floor,
                window,
            } if self.on_chains(conv) => {
                out.extend(
                    self.on_chain_page(
                        conv, entries, *more, owed, *skipped, *upto, *floor, *window,
                    ),
                );
                out.extend(self.flush());
            }
            AccountReply::WrapsPage { conv, keys, served } if self.on_chains(conv) => {
                out.extend(self.on_wraps_page(conv, keys, *served));
                out.extend(self.advance(conv));
                self.drain(&mut out, &mut events);
                out.extend(self.flush());
                out.extend(self.answer());
            }
            AccountReply::ChainStored { conv, behind, .. } if self.on_chains(conv) => {
                self.on_chain_stored(conv, *behind, "ChainPut", &mut out, &mut events);
                out.extend(self.advance(conv));
                out.extend(self.flush());
                out.extend(self.answer());
            }
            AccountReply::ChainRekey {
                conv,
                new_chain,
                missing,
                gone,
            } if self.on_chains(conv) => {
                self.on_chain_rekey(conv, *new_chain, missing, gone, &mut events);
                out.extend(self.advance(conv));
                out.extend(self.flush());
            }
            AccountReply::LogMemberIdsFound { conv, ids, more } if self.on_chains(conv) => {
                self.on_member_ids(conv, ids, *more);
                out.extend(self.advance(conv));
            }
            AccountReply::OwnChains {
                conv,
                newest,
                chains,
                more,
            } if self.on_chains(conv) => {
                self.on_own_chains(conv, *newest, chains, *more);
                out.extend(self.advance(conv));
                out.extend(self.flush());
                out.extend(self.answer());
            }
            AccountReply::OwnBuckets {
                conv,
                buckets,
                more,
            } if self.on_chains(conv) => {
                self.on_own_buckets(conv, buckets, *more);
                out.extend(self.advance(conv));
            }
            AccountReply::BucketLists { conv, lists } if self.on_chains(conv) => {
                self.on_bucket_lists(conv, lists);
                out.extend(self.advance(conv));
            }
            AccountReply::OwnChainRows {
                conv,
                chain,
                seals,
                direct,
                links,
                more,
            } if self.on_chains(conv) => {
                self.on_own_rows(conv, *chain, seals, direct, links, *more);
                out.extend(self.advance(conv));
            }
            AccountReply::Wraps { conv, wraps } => {
                self.answered(conv);
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
                        self.keys
                            .insert((conv.clone(), w.owner, w.epoch), Zeroizing::new(k));
                        if w.owner == self.me && !self.own_epochs.contains_key(conv) {
                            self.own_epochs
                                .insert(conv.clone(), (w.epoch, Zeroizing::new(k)));
                        }
                    }
                }
                // The other party's log key, for their signatures and for wrapping
                // to them; a channel's writers are asked for as their entries come.
                let want = self.ask_keys(self.other_party(conv));
                let target = self.target.contains(conv);
                if self.on_chains(conv) {
                    // Keys of a version before chains, for what chains did not open
                    out.extend(self.chain_read(conv));
                } else if !want.is_empty() {
                    out.extend(want);
                    self.fetching.insert(conv.clone(), Fetch::Keys);
                } else if target {
                    self.fetching.insert(conv.clone(), Fetch::Entries);
                    out.push(self.first_page(conv));
                } else {
                    out.extend(self.fetch_done(conv));
                }
                self.drain(&mut out, &mut events);
                out.extend(self.flush());
                out.extend(self.answer());
            }
            AccountReply::LogKeysFound { keys } => {
                self.idle = 0;
                // What was asked, or someone known already: keys of strangers nobody asked
                // for filled peers and pins without end from a relay that sent them (R1 F8).
                // A known person's key, swapped, is still weighed against the pin
                let asked: Vec<LogKeyInfo> = keys
                    .iter()
                    .filter(|k| {
                        self.asked_keys.contains(&k.account)
                            || self.peers.contains_key(&k.account)
                            || self.pinned(&k.account).is_some()
                    })
                    .cloned()
                    .collect();
                self.learn(&asked, &mut out, &mut events);
                // Answers come in order, so an ask ahead of the one this answers
                // was lost, which says nothing about the accounts it named.
                let at = self
                    .key_asks
                    .iter()
                    .position(|asked| keys.iter().any(|k| asked.contains(&k.account)));
                for a in self.key_asks.drain(..at.unwrap_or(0)).flatten() {
                    self.asked_keys.remove(&a);
                }
                let answered = if at.is_some() || keys.is_empty() {
                    self.key_asks.pop_front()
                } else {
                    None
                };
                // Asked, and the relay had nothing for some: they cannot be written to. An empty
                // answer names no ask, and may be the next one's with this one's lost. Since
                // whoever is judged here gets rows that open nothing, it takes asking again.
                let mut again = Vec::new();
                for a in answered.unwrap_or_default() {
                    if !self.peers.contains_key(&a) && !keys.iter().any(|k| k.account == a) {
                        if keys.is_empty() && self.key_misses.insert(a) {
                            self.asked_keys.remove(&a);
                            again.push(a);
                        } else {
                            self.key_misses.remove(&a);
                            self.distrusted.insert(a);
                        }
                    }
                }
                out.extend(self.ask_keys(again));
                out.extend(self.keys_in());
                self.drain(&mut out, &mut events);
                out.extend(self.advance_waiting());
                out.extend(self.flush());
                out.extend(self.answer());
            }
            AccountReply::LogPage {
                conv,
                entries,
                more,
                owed,
            } => {
                self.answered(conv);
                self.owed
                    .insert(conv.clone(), owed.iter().copied().collect());
                for e in entries {
                    if !self.opened.contains(&(conv.clone(), e.seq))
                        && !self
                            .waiting
                            .iter()
                            .any(|(c, w)| c == conv && w.seq == e.seq)
                    {
                        self.waiting.push((conv.clone(), e.clone()));
                    }
                }
                if let Some(last) = entries.last() {
                    let f = self.fetched.entry(conv.clone()).or_insert(0);
                    *f = (*f).max(last.seq);
                }
                self.drain(&mut out, &mut events);
                // Not a page more of a channel we left since: it would be refused
                if *more && self.target.contains(conv) {
                    let after = self.fetched.get(conv).copied().unwrap_or(0);
                    out.push(self.ask_page(conv, after));
                } else {
                    self.target.remove(conv);
                    out.extend(self.fetch_done(conv));
                }
            }
            AccountReply::LogAppended { conv, seq, .. } => {
                self.copy_refused = false;
                self.in_flight.pop_front();
                self.append_idle = 0;
                self.rekeys.remove(conv);
                if self.settle_rekey(conv, &mut events) {
                    out.extend(self.advance(conv));
                    out.extend(self.flush());
                }
                // The cursor stays where it is. It reaches disk ahead of this post, whose save
                // waits in the front end, and a crash between the two would lose the post on
                // this device for good. Read back once at the next read, it is one we hold.
                events.push(Event::Kept {
                    conv: conv.clone(),
                    seq: *seq,
                });
            }
            AccountReply::LogRekey { conv } => {
                // Somebody joined or left since our key: ask who is there now,
                // start a new key for them, and send it again.
                let (_, epoch, again) = self.in_flight.pop_front().unwrap_or_default();
                self.append_idle = 0;
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
                    events.push(Event::NotKept {
                        reason:
                            "the people this channel keeps messages for could not all be reached"
                                .into(),
                    });
                } else if let Some(o) = again {
                    // In the order they were written.
                    let at = self
                        .outbox
                        .iter()
                        .position(|x| x.sent_at > o.sent_at)
                        .unwrap_or(self.outbox.len());
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
                // So many at most, across every log: a relay's pushes grew both lists without
                // end (R1 F8). They come with the index too, before any log is joined, so
                // what bounds them is their number. An answer takes its joiners off
                if self.pending_seen.len() >= MOST_PENDING {
                    self.pending_seen.clear();
                }
                for j in joiners {
                    self.pending_new |= self.pending_seen.insert((conv.clone(), *j));
                }
                let mut room =
                    MOST_PENDING.saturating_sub(self.joiners.values().map(HashSet::len).sum());
                let waiting = self.joiners.entry(conv.clone()).or_default();
                for j in joiners.iter().copied().filter(|j| *j != self.me) {
                    if room == 0 {
                        break;
                    }
                    if waiting.insert(j) {
                        room -= 1;
                    }
                }
                // The members we knew are from before they joined.
                self.members.remove(conv);
                self.asked_members.remove(conv);
                out.extend(self.answer());
            }
            AccountReply::LogNews { conv } => out.extend(self.read_news(conv)),
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
    use voipc_protocol::messages::WrapOut;

    const RELAY: [u8; 16] = [9; 16];

    /// A stored reply reaches the front end as one: the cloud log is the
    /// third way in, next to the live message and the history hand-off.
    #[test]
    fn a_stored_message_keeps_what_it_answers_and_its_file() {
        let file = crate::envelope::FileRef {
            hash: "a".repeat(64),
            key: "b".repeat(64),
            size: 3,
            z: false,
            name: "a.txt".into(),
            mime: None,
            w: None,
            h: None,
            dur: None,
            px: None,
        };
        let extras = crate::envelope::Extras {
            reply: Some("r1".into()),
            thread: Some("t1".into()),
            file: Some(file),
            ..crate::envelope::Extras::default()
        };
        let stored = Event::ChannelMessage {
            conv: "c:1".into(),
            sender: [1; 16],
            sender_name: "ann".into(),
            from_me: false,
            envelope: crate::envelope::envelope_with("m1", "agreed", None, &extras),
            sent_at: 10,
            server_at: 20,
            seq: 1,
        };
        let (name, payload) = stored.to_wire().unwrap();
        assert_eq!(name, "stored-channel-message");
        assert_eq!(
            (payload["reply_to"].as_str(), payload["thread"].as_str()),
            (Some("r1"), Some("t1"))
        );
        assert_eq!(payload["file"]["name"], "a.txt");
        let plain = Event::Message {
            conv: "d:1".into(),
            peer: [1; 16],
            peer_name: "ann".into(),
            from_me: true,
            envelope: envelope("m2", "hi", None),
            sent_at: 10,
            server_at: 20,
            seq: 2,
        };
        let (_, plain) = plain.to_wire().unwrap();
        assert!(plain["reply_to"].is_null() && plain["file"].is_null() && plain["fwd"].is_null());
    }

    /// An edit, delete, reaction or pin from the stored log reaches the front
    /// end as `stored-event`, never as a message: who sent it (to check they
    /// may), the conversation's timer, and the earlier of the two stamps.
    #[test]
    fn a_stored_event_is_its_own_event_beside_stored_messages() {
        use crate::envelope::{ChatEvent, Extras};
        let ev = |event: ChatEvent, text: &str| {
            let extras = Extras {
                event: Some(event),
                ..Extras::default()
            };
            crate::envelope::envelope_with("e1", text, Some(3600), &extras)
        };
        let stored = Event::ChannelMessage {
            conv: "c:1".into(),
            sender: [1; 16],
            sender_name: "ann".into(),
            from_me: false,
            envelope: ev(
                ChatEvent::React {
                    target: "m1".into(),
                    emoji: "🔥".into(),
                    on: true,
                },
                "",
            ),
            sent_at: 30,
            server_at: 20,
            seq: 4,
        };
        let (name, p) = stored.to_wire().unwrap();
        assert_eq!(name, "stored-event");
        assert_eq!(
            (
                p["conv"].as_str(),
                p["name"].as_str(),
                p["from_me"].as_bool()
            ),
            (Some("c:1"), Some("ann"), Some(false))
        );
        assert_eq!(p["account"], voipc_protocol::conv::hex(&[1; 16]));
        assert_eq!(
            (p["timestamp"].as_u64(), p["ttl_secs"].as_u64()),
            (Some(20), Some(3600))
        );
        assert_eq!(
            p["event"],
            serde_json::json!({ "kind": "react", "target": "m1", "emoji": "🔥", "on": true })
        );
        // A moderator's hide likewise, never a message of the channel's
        let hide = Event::ChannelMessage {
            conv: "c:1".into(),
            sender: [1; 16],
            sender_name: "ann".into(),
            from_me: false,
            envelope: ev(
                ChatEvent::Hide {
                    target: "m1".into(),
                    on: true,
                },
                "",
            ),
            sent_at: 30,
            server_at: 20,
            seq: 6,
        };
        let (name, p) = hide.to_wire().unwrap();
        assert_eq!(name, "stored-event");
        assert_eq!(
            p["event"],
            serde_json::json!({ "kind": "hide", "target": "m1", "on": true })
        );
        let dm = Event::Message {
            conv: "d:1".into(),
            peer: [2; 16],
            peer_name: "bob".into(),
            from_me: true,
            envelope: ev(
                ChatEvent::Edit {
                    target: "m2".into(),
                },
                "better words",
            ),
            sent_at: 10,
            server_at: 20,
            seq: 5,
        };
        let (name, p) = dm.to_wire().unwrap();
        assert_eq!(name, "stored-event");
        assert_eq!(
            (p["content"].as_str(), p["event"]["kind"].as_str()),
            (Some("better words"), Some("edit"))
        );
        assert_eq!(
            (
                p["name"].as_str(),
                p["from_me"].as_bool(),
                p["timestamp"].as_u64()
            ),
            (Some("bob"), Some(true), Some(10))
        );
        // And a forwarded message is a message, with its label
        let fwd = Event::ChannelMessage {
            conv: "c:1".into(),
            sender: [1; 16],
            sender_name: "ann".into(),
            from_me: false,
            envelope: crate::envelope::envelope_with(
                "m3",
                "look",
                None,
                &Extras {
                    fwd: Some(crate::envelope::Forwarded {
                        name: "cy".into(),
                        at: 7,
                        report: None,
                    }),
                    ..Extras::default()
                },
            ),
            sent_at: 10,
            server_at: 20,
            seq: 6,
        };
        let (name, p) = fwd.to_wire().unwrap();
        assert_eq!(
            (name, p["fwd"]["name"].as_str()),
            ("stored-channel-message", Some("cy"))
        );
    }

    struct Account {
        id: [u8; 16],
        identity: IdentityKeyPair,
        logkey: LogKey,
    }

    fn account(n: u8) -> Account {
        Account {
            id: [n; 16],
            identity: IdentityKeyPair::generate(&mut crate::rng()),
            logkey: LogKey::generate(),
        }
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
        let blobs = vec![VaultBlob {
            version: 1,
            ..vault.seal_item(ITEM_LOGKEY, 1, &me.logkey.to_bytes())
        }];
        let signed = SignedIn {
            relay_id: RELAY,
            name: "me".into(),
            vault,
            identity: me.identity,
            recovery: None,
            blobs,
        };
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
        let (out, _) = s
            .on_reply(&AccountReply::LogKeysFound {
                keys: vec![bob.info("bob")],
            })
            .unwrap();
        assert_eq!(
            sent(&out, "WrapsFetch").len(),
            1,
            "first our own wraps, in case another device has an epoch here"
        );
        // The relay answers with a key it made, wrapped to our public log key "from us".
        let evil = epoch_key();
        let forged = wrap(&me.logkey.public(), &evil, &conv, &me.id, 7, &me.id).unwrap();
        let (out, _) = s
            .on_reply(&AccountReply::Wraps {
                conv: conv.clone(),
                wraps: vec![WrapOut {
                    owner: me.id,
                    epoch: 7,
                    wrapped: forged,
                }],
            })
            .unwrap();
        let Some(AccountRequest::EpochPut { epoch, wraps, .. }) =
            sent(&out, "EpochPut").first().copied()
        else {
            panic!("a fresh epoch of our own is minted: {out:?}");
        };
        assert_ne!(*epoch, 7);
        let Some(AccountRequest::LogAppend {
            epoch: used, ct, ..
        }) = sent(&out, "LogAppend").first().copied()
        else {
            panic!("the message goes out: {out:?}");
        };
        assert_eq!(used, epoch);
        assert!(
            open_entry(&evil, &conv, &me.id, *used, &me.logkey.public(), ct).is_err(),
            "the relay's key does not open it"
        );
        // Bob's wrap of the new epoch opens the entry; ours is a self-wrap.
        let to_bob = wraps.iter().find(|w| w.recipient == bob.id).unwrap();
        let k = unwrap(&bob.logkey, &to_bob.wrapped, &conv, &me.id, *epoch, &bob.id).unwrap();
        let (env, _) = open_entry(&k, &conv, &me.id, *epoch, &me.logkey.public(), ct).unwrap();
        assert_eq!(crate::envelope::open_envelope(&env).text, "for bob only");
        let to_me = wraps.iter().find(|w| w.recipient == me.id).unwrap();
        assert_eq!(
            self_unwrap(&me.logkey, &to_me.wrapped, &conv, &me.id, *epoch).unwrap(),
            k
        );
    }

    /// Keys as the relay answers them, to what this session asked: it learns no others.
    fn keys_answer(s: &mut AccountSync, keys: Vec<LogKeyInfo>) -> (Vec<ClientMessage>, Vec<Event>) {
        let _ = s.ask_keys(keys.iter().map(|k| k.account).collect::<Vec<_>>());
        s.on_reply(&AccountReply::LogKeysFound { keys }).unwrap()
    }

    /// R1 F8: frames nobody asked for grew what a session holds without end.
    #[test]
    fn keys_and_joiners_nobody_asked_for_are_not_kept() {
        let (me, bob) = (account(1), account(2));
        let mut s = sync_for(&me);
        s.on_reply(&AccountReply::LogKeysFound {
            keys: vec![bob.info("bob")],
        })
        .unwrap();
        assert!(s.peers.is_empty(), "never asked for");
        keys_answer(&mut s, vec![bob.info("bob")]);
        assert!(s.peers.contains_key(&bob.id), "the control");

        let joiners = |from: u32, n: u32| -> Vec<[u8; 16]> {
            (from..from + n)
                .map(|i| {
                    let mut id = [0u8; 16];
                    id[..4].copy_from_slice(&i.to_be_bytes());
                    id[15] = 0xee;
                    id
                })
                .collect()
        };
        let half = MOST_PENDING as u32 / 2;
        for (conv, from) in [("c:one", 0), ("c:two", half), ("c:three", 2 * half)] {
            s.on_reply(&AccountReply::LogPending {
                conv: conv.into(),
                joiners: joiners(from, half + 10),
            })
            .unwrap();
        }
        let held: usize = s.joiners.values().map(HashSet::len).sum();
        assert_eq!(held, MOST_PENDING, "across every log");
        assert!(s.pending_seen.len() <= MOST_PENDING);
    }

    #[test]
    fn a_direct_message_only_comes_from_its_two_parties() {
        let (me, bob, carol) = (account(1), account(2), account(3));
        let mut s = sync_for(&me);
        let conv = dm_conv(&me.id, &bob.id);
        keys_answer(&mut s, vec![bob.info("bob"), carol.info("carol")]);
        let page = |s: &mut AccountSync, owner: &Account, epoch: u32, seq: i64, text: &str| {
            let k = epoch_key();
            let wrapped = wrap(&me.logkey.public(), &k, &conv, &owner.id, epoch, &me.id).unwrap();
            s.on_reply(&AccountReply::Wraps {
                conv: conv.clone(),
                wraps: vec![WrapOut {
                    owner: owner.id,
                    epoch,
                    wrapped,
                }],
            })
            .unwrap();
            let ct = seal_entry(
                &k,
                &conv,
                &owner.id,
                epoch,
                &owner.logkey,
                &envelope(text, text, None),
                1,
            );
            let entries = vec![LogEntry {
                seq,
                sender: owner.id,
                epoch,
                server_at: 1,
                ct,
            }];
            s.on_reply(&AccountReply::LogPage {
                conv: conv.clone(),
                entries,
                more: false,
                owed: Vec::new(),
            })
            .unwrap()
            .1
        };
        // Carol (an account the relay made) signs an entry and files it between bob and us.
        let events = page(&mut s, &carol, 5, 1, "carol posing as bob");
        assert!(
            !events.iter().any(|e| matches!(e, Event::Message { .. })),
            "{events:?}"
        );
        let events = page(&mut s, &bob, 6, 2, "really bob");
        assert!(
            events.iter().any(
                |e| matches!(e, Event::Message { peer, from_me: false, .. } if *peer == bob.id)
            ),
            "{events:?}"
        );
    }

    /// `me`'s sync with cloud copies off: what most accounts have.
    fn sync_without_copies(me: &Account) -> AccountSync {
        let mut s = sync_for(me);
        s.prefs.cloud = false;
        s
    }

    #[test]
    fn a_plain_dm_is_still_not_kept_with_cloud_off() {
        let (me, bob) = (account(1), account(2));
        let mut s = sync_without_copies(&me);
        assert!(s
            .send_dm(bob.id, envelope("m", "hello", None), 1, None)
            .is_empty());
        assert!(s.outbox.is_empty(), "nothing waits to go out either");
    }

    #[test]
    fn a_marked_report_is_kept_once_with_cloud_copies_off() {
        let (me, bob) = (account(1), account(2));
        let mut s = sync_without_copies(&me);
        let out = s.keep_dm(bob.id, envelope("r1", "report", None), 1, None);
        assert_eq!(sent(&out, "LogKeys").len(), 1);
        let (out, _) = s
            .on_reply(&AccountReply::LogKeysFound {
                keys: vec![bob.info("bob")],
            })
            .unwrap();
        assert_eq!(sent(&out, "WrapsFetch").len(), 1);
        let conv = dm_conv(&me.id, &bob.id);
        let (out, _) = s
            .on_reply(&AccountReply::Wraps {
                conv: conv.clone(),
                wraps: Vec::new(),
            })
            .unwrap();
        assert_eq!(sent(&out, "LogAppend").len(), 1);
        assert_eq!(sent(&out, "EpochPut").len(), 1);
        // That one message: cloud copies are still off for the next
        assert!(!s.prefs.cloud);
        assert!(s
            .send_dm(bob.id, envelope("m", "hello", None), 2, None)
            .is_empty());
        // Nor to ourselves, as for any copy
        assert!(s
            .keep_dm(me.id, envelope("x", "me", None), 3, None)
            .is_empty());
    }

    #[test]
    fn a_kept_report_reaches_a_moderator_with_cloud_off() {
        let (carla, bob) = (account(1), account(2));
        let conv = dm_conv(&carla.id, &bob.id);
        let mut reporter = sync_without_copies(&carla);
        reporter.keep_dm(bob.id, envelope("r1", "report", None), 1, None);
        reporter
            .on_reply(&AccountReply::LogKeysFound {
                keys: vec![bob.info("bob")],
            })
            .unwrap();
        let (out, _) = reporter
            .on_reply(&AccountReply::Wraps {
                conv: conv.clone(),
                wraps: Vec::new(),
            })
            .unwrap();
        let Some(AccountRequest::EpochPut { epoch, wraps, .. }) =
            sent(&out, "EpochPut").first().copied()
        else {
            panic!("an epoch is minted: {out:?}");
        };
        let Some(AccountRequest::LogAppend { ct, .. }) = sent(&out, "LogAppend").first().copied()
        else {
            panic!("the report goes out: {out:?}");
        };
        let to_bob = wraps.iter().find(|w| w.recipient == bob.id).unwrap();

        // bob signs in with copies off: the index is read all the same
        let mut moderator = sync_without_copies(&bob);
        let (out, _) = moderator
            .on_reply(&AccountReply::LogConvs {
                convs: vec![(conv.clone(), 1)],
            })
            .unwrap();
        assert_eq!(sent(&out, "LogKeys").len(), 1, "{out:?}");
        assert_eq!(sent(&out, "WrapsFetch").len(), 1, "{out:?}");
        moderator
            .on_reply(&AccountReply::LogKeysFound {
                keys: vec![carla.info("carla")],
            })
            .unwrap();
        moderator
            .on_reply(&AccountReply::Wraps {
                conv: conv.clone(),
                wraps: vec![WrapOut {
                    owner: carla.id,
                    epoch: *epoch,
                    wrapped: to_bob.wrapped.clone(),
                }],
            })
            .unwrap();
        let (_, events) = moderator
            .on_reply(&AccountReply::LogPage {
                conv: conv.clone(),
                entries: vec![LogEntry {
                    seq: 1,
                    sender: carla.id,
                    epoch: *epoch,
                    server_at: 1,
                    ct: ct.clone(),
                }],
                more: false,
                owed: Vec::new(),
            })
            .unwrap();
        assert!(
            events
                .iter()
                .any(|e| matches!(e, Event::Message { peer, from_me: false, envelope, .. }
                    if *peer == carla.id && crate::envelope::open_envelope(envelope).text == "report")),
            "{events:?}"
        );
    }

    #[test]
    fn a_new_log_key_is_published_only_once_the_vault_keeps_it() {
        let me = account(1);
        let signed = SignedIn {
            relay_id: RELAY,
            name: "me".into(),
            vault: Vault::create(RELAY, "me"),
            identity: me.identity,
            recovery: None,
            blobs: Vec::new(),
        };
        let (mut s, first) = AccountSync::start(&signed, me.id, LogMemory::default(), false);
        assert!(
            sent(&first, "LogKeyPublish").is_empty(),
            "not before the vault answers"
        );
        assert_eq!(sent(&first, "VaultPut").len(), 1);
        s.prefs.cloud = true;
        // Nothing is sealed with a key the vault may not keep.
        let out = s.send_dm([2; 16], envelope("m", "waits", None), 1, None);
        assert!(out.is_empty(), "{out:?}");
        // Another device's key won the vault meanwhile: that one is published.
        let other = LogKey::generate();
        let theirs = VaultBlob {
            version: 3,
            ..signed.vault.seal_item(ITEM_LOGKEY, 1, &other.to_bytes())
        };
        let (out, _) = s
            .on_reply(&AccountReply::VaultConflict {
                k: ITEM_LOGKEY.into(),
                blob: Some(theirs),
            })
            .unwrap();
        let Some(AccountRequest::LogKeyPublish { logkey, .. }) =
            sent(&out, "LogKeyPublish").first().copied()
        else {
            panic!("published: {out:?}");
        };
        assert_eq!(*logkey, other.public());
        assert_eq!(
            sent(&out, "LogKeys").len(),
            1,
            "and the waiting message goes on"
        );
    }

    /// Whichever conversations `out` asks the wraps of.
    fn wraps_asked(out: &[ClientMessage]) -> Vec<String> {
        sent(out, "WrapsFetch")
            .iter()
            .filter_map(|r| match r {
                AccountRequest::WrapsFetch { conv } => Some(conv.clone()),
                _ => None,
            })
            .collect()
    }

    fn slow_down(request: &str) -> AccountReply {
        AccountReply::Error {
            request: request.into(),
            reason: "Too many requests at once; slow down.".into(),
        }
    }

    /// A sign-in with `n` conversations to read, the keys of their other
    /// parties in: returns the conversations in the order the relay listed them.
    fn with_convs(s: &mut AccountSync, me: &Account, n: u8) -> (Vec<String>, Vec<ClientMessage>) {
        let peers: Vec<Account> = (0..n).map(|i| account(10 + i)).collect();
        let convs: Vec<String> = peers.iter().map(|p| dm_conv(&me.id, &p.id)).collect();
        let (out, _) = s
            .on_reply(&AccountReply::LogConvs {
                convs: convs.iter().map(|c| (c.clone(), 9)).collect(),
            })
            .unwrap();
        assert_eq!(
            sent(&out, "LogKeys").len(),
            1,
            "one ask for every peer: {out:?}"
        );
        s.on_reply(&AccountReply::LogKeysFound {
            keys: peers.iter().map(|p| p.info("peer")).collect(),
        })
        .unwrap();
        (convs, out)
    }

    fn empty_wraps(conv: &str) -> AccountReply {
        AccountReply::Wraps {
            conv: conv.into(),
            wraps: Vec::new(),
        }
    }

    fn empty_page(conv: &str) -> AccountReply {
        AccountReply::LogPage {
            conv: conv.into(),
            entries: Vec::new(),
            more: false,
            owed: Vec::new(),
        }
    }

    /// A reload forgets the cursors in the browser: the conversation comes back
    /// from the newest entries, not from a year ago and not from nowhere.
    #[test]
    fn a_first_read_starts_at_the_newest_entries_and_a_cursor_past_itself() {
        let (me, bob) = (account(1), account(2));
        let mut s = sync_for(&me);
        let conv = dm_conv(&me.id, &bob.id);
        keys_answer(&mut s, vec![bob.info("bob")]);
        let (out, _) = s
            .on_reply(&AccountReply::LogConvs {
                convs: vec![(conv.clone(), 9)],
            })
            .unwrap();
        assert_eq!(wraps_asked(&out), vec![conv.clone()]);
        let (out, _) = s.on_reply(&empty_wraps(&conv)).unwrap();
        assert!(
            matches!(
                sent(&out, "LogFetch")[..],
                [AccountRequest::LogFetch { after: -500, .. }]
            ),
            "{out:?}"
        );
        s.on_reply(&empty_page(&conv)).unwrap();
        s.cursors.insert(conv.clone(), 7);
        s.wraps_known.remove(&conv);
        let (out, _) = s
            .on_reply(&AccountReply::LogNews { conv: conv.clone() })
            .unwrap();
        assert_eq!(wraps_asked(&out), vec![conv.clone()]);
        let (out, _) = s.on_reply(&empty_wraps(&conv)).unwrap();
        assert!(
            matches!(
                sent(&out, "LogFetch")[..],
                [AccountRequest::LogFetch { after: 7, .. }]
            ),
            "{out:?}"
        );
    }

    #[test]
    fn conversations_are_read_one_at_a_time() {
        let me = account(1);
        let mut s = sync_for(&me);
        let (convs, out) = with_convs(&mut s, &me, 3);
        assert_eq!(wraps_asked(&out), vec![convs[0].clone()]);
        s.on_reply(&empty_wraps(&convs[0])).unwrap();
        let (out, _) = s.on_reply(&empty_page(&convs[0])).unwrap();
        assert_eq!(
            wraps_asked(&out),
            vec![convs[1].clone()],
            "the next one, once"
        );
    }

    /// Over the relay's budget: no "not kept" toast, and the read goes on.
    #[test]
    fn a_read_refused_for_now_goes_on_at_the_next_tick() {
        let me = account(1);
        let mut s = sync_for(&me);
        let (convs, _) = with_convs(&mut s, &me, 2);
        let (out, events) = s.on_reply(&slow_down("WrapsFetch")).unwrap();
        assert!(out.is_empty(), "the queue waits: {out:?}");
        assert!(events.is_empty(), "nothing to tell anybody: {events:?}");
        let (out, _) = s.tick();
        assert_eq!(
            wraps_asked(&out),
            vec![convs[0].clone()],
            "from the same one"
        );
    }

    #[test]
    fn a_refused_index_is_asked_again() {
        let me = account(1);
        let mut s = sync_for(&me);
        s.on_reply(&slow_down("LogIndex")).unwrap();
        assert_eq!(sent(&s.tick().0, "LogIndex").len(), 1);
    }

    #[test]
    fn refused_keys_are_asked_again() {
        let (me, bob) = (account(1), account(2));
        let mut s = sync_for(&me);
        let conv = dm_conv(&me.id, &bob.id);
        let (out, _) = s
            .on_reply(&AccountReply::LogConvs {
                convs: vec![(conv.clone(), 9)],
            })
            .unwrap();
        assert_eq!(sent(&out, "LogKeys").len(), 1);
        s.on_reply(&slow_down("LogKeys")).unwrap();
        // The read reaches its wraps, asks once more, and now waits on the keys
        let (out, _) = s.on_reply(&empty_wraps(&conv)).unwrap();
        assert_eq!(sent(&out, "LogKeys").len(), 1);
        s.on_reply(&slow_down("LogKeys")).unwrap();
        let (out, _) = s.tick();
        assert_eq!(sent(&out, "LogKeys").len(), 1, "{out:?}");
    }

    /// The relay drops a reply on a full queue, and logs a database error:
    /// neither may stop every read after it for the rest of the session.
    #[test]
    fn a_reply_that_never_comes_does_not_stop_the_reads() {
        let me = account(1);
        let mut s = sync_for(&me);
        let (convs, _) = with_convs(&mut s, &me, 2);
        s.on_reply(&AccountReply::LogConvs { convs: Vec::new() })
            .unwrap();
        assert!(wraps_asked(&s.tick().0).is_empty());
        assert!(wraps_asked(&s.tick().0).is_empty());
        assert_eq!(wraps_asked(&s.tick().0), vec![convs[0].clone()]);
    }

    #[test]
    fn a_read_refused_for_good_moves_on_and_says_so() {
        let me = account(1);
        let mut s = sync_for(&me);
        let (convs, _) = with_convs(&mut s, &me, 2);
        let (out, events) = s
            .on_reply(&AccountReply::Error {
                request: "WrapsFetch".into(),
                reason: "not a conversation of yours".into(),
            })
            .unwrap();
        assert_eq!(wraps_asked(&out), vec![convs[1].clone()]);
        assert!(
            events.iter().any(|e| matches!(e, Event::NotRead { .. })),
            "{events:?}"
        );
    }

    /// A pseudonym's refusal of a kept copy has nothing to do with a read.
    #[test]
    fn a_refused_append_ends_no_read() {
        let me = account(1);
        let mut s = sync_for(&me);
        let (convs, _) = with_convs(&mut s, &me, 2);
        let (out, events) = s
            .on_reply(&AccountReply::Error {
                request: "LogAppend".into(),
                reason: "nothing is kept while you write under a pseudonym.".into(),
            })
            .unwrap();
        assert!(wraps_asked(&out).is_empty(), "{out:?}");
        assert!(
            events.iter().any(|e| matches!(e, Event::NotKept { .. })),
            "{events:?}"
        );
        let (out, _) = s.on_reply(&empty_wraps(&convs[0])).unwrap();
        assert_eq!(
            sent(&out, "LogFetch").len(),
            1,
            "the read still runs: {out:?}"
        );
    }

    /// A message is news now, and a burst of them is one more read.
    #[test]
    fn news_during_a_read_reads_again_once() {
        let (me, bob) = (account(1), account(2));
        let mut s = sync_for(&me);
        let conv = dm_conv(&me.id, &bob.id);
        keys_answer(&mut s, vec![bob.info("bob")]);
        let news = AccountReply::LogNews { conv: conv.clone() };
        assert_eq!(
            wraps_asked(&s.on_reply(&news).unwrap().0),
            vec![conv.clone()]
        );
        assert!(wraps_asked(&s.on_reply(&news).unwrap().0).is_empty());
        assert!(wraps_asked(&s.on_reply(&news).unwrap().0).is_empty());
        s.on_reply(&empty_wraps(&conv)).unwrap();
        let (out, _) = s.on_reply(&empty_page(&conv)).unwrap();
        assert_eq!(wraps_asked(&out), vec![conv.clone()]);
        s.on_reply(&empty_wraps(&conv)).unwrap();
        let (out, _) = s.on_reply(&empty_page(&conv)).unwrap();
        assert!(
            wraps_asked(&out).is_empty(),
            "and that is the end of it: {out:?}"
        );
    }

    /// Reading a long history back must not hold up what is written meanwhile.
    #[test]
    fn a_message_sent_during_a_read_is_kept() {
        let (me, bob) = (account(1), account(2));
        let mut s = sync_for(&me);
        let (convs, _) = with_convs(&mut s, &me, 2);
        let mine = dm_conv(&me.id, &bob.id);
        let out = s.send_dm(bob.id, envelope("m1", "hello", None), 1, None);
        assert_eq!(sent(&out, "LogKeys").len(), 1);
        let (out, _) = s
            .on_reply(&AccountReply::LogKeysFound {
                keys: vec![bob.info("bob")],
            })
            .unwrap();
        assert_eq!(
            wraps_asked(&out),
            vec![mine.clone()],
            "its own, past the queue"
        );
        // Answers come in order: the running read's first
        s.on_reply(&empty_wraps(&convs[0])).unwrap();
        let (out, _) = s.on_reply(&empty_wraps(&mine)).unwrap();
        assert_eq!(sent(&out, "LogAppend").len(), 1, "{out:?}");
    }

    /// A key they told us of while the read was on its way: its entry waits
    /// for the second read instead of being passed over for good.
    #[test]
    fn an_entry_under_a_key_that_is_on_its_way_waits_for_it() {
        let (me, bob) = (account(1), account(2));
        let mut s = sync_for(&me);
        let conv = dm_conv(&me.id, &bob.id);
        keys_answer(&mut s, vec![bob.info("bob")]);
        let news = AccountReply::LogNews { conv: conv.clone() };
        s.on_reply(&news).unwrap();
        s.on_reply(&empty_wraps(&conv)).unwrap();
        s.on_reply(&news).unwrap();
        let k = epoch_key();
        let ct = seal_entry(
            &k,
            &conv,
            &bob.id,
            5,
            &bob.logkey,
            &envelope("m", "first words", None),
            1,
        );
        let (_, events) = s
            .on_reply(&AccountReply::LogPage {
                conv: conv.clone(),
                entries: vec![LogEntry {
                    seq: 8,
                    sender: bob.id,
                    epoch: 5,
                    server_at: 1,
                    ct,
                }],
                more: false,
                owed: Vec::new(),
            })
            .unwrap();
        assert!(events.is_empty(), "{events:?}");
        let wrapped = wrap(&me.logkey.public(), &k, &conv, &bob.id, 5, &me.id).unwrap();
        let (_, events) = s
            .on_reply(&AccountReply::Wraps {
                conv: conv.clone(),
                wraps: vec![WrapOut {
                    owner: bob.id,
                    epoch: 5,
                    wrapped,
                }],
            })
            .unwrap();
        assert!(
            events.iter().any(|e| matches!(e, Event::Message { .. })),
            "{events:?}"
        );
    }

    /// The keys a read waits for arrive some other way while their own ask
    /// was refused: no answer is coming, and the queue must not wait for one.
    #[test]
    fn keys_learned_another_way_do_not_stop_the_reads() {
        let (me, bob) = (account(1), account(2));
        let mut s = sync_for(&me);
        let conv = dm_conv(&me.id, &bob.id);
        s.on_reply(&AccountReply::LogConvs {
            convs: vec![(conv.clone(), 9)],
        })
        .unwrap();
        s.on_reply(&slow_down("LogKeys")).unwrap();
        s.on_reply(&empty_wraps(&conv)).unwrap();
        s.on_reply(&slow_down("LogKeys")).unwrap();
        s.on_reply(&AccountReply::LogMembersFound {
            conv: "c:1".into(),
            members: vec![bob.info("bob")],
        })
        .unwrap();
        let (out, _) = s.tick();
        assert_eq!(sent(&out, "LogFetch").len(), 1, "{out:?}");
    }

    /// A reply the relay dropped says nothing about the accounts it named.
    #[test]
    fn a_lost_answer_about_keys_distrusts_nobody() {
        let me = account(1);
        let mut s = sync_for(&me);
        let peers: Vec<Account> = (0..70).map(|i| account(10 + i)).collect();
        let (first, second) = peers.split_at(64);
        s.ask_keys(peers.iter().map(|p| p.id));
        // The first ask's answer never comes
        s.on_reply(&AccountReply::LogKeysFound {
            keys: second.iter().map(|p| p.info("peer")).collect(),
        })
        .unwrap();
        assert!(first.iter().all(|p| !s.distrusted.contains(&p.id)));
        assert_eq!(
            sent(&s.ask_keys(first.iter().map(|p| p.id)), "LogKeys").len(),
            1,
            "and they can be asked again"
        );
        // Whereas an answer that lacks one means the relay has none for it
        s.on_reply(&AccountReply::LogKeysFound {
            keys: first[1..].iter().map(|p| p.info("peer")).collect(),
        })
        .unwrap();
        assert!(s.distrusted.contains(&first[0].id));
    }

    /// An empty answer names no ask, so the one in front may just have lost its own. Whoever is
    /// judged here gets rows that open nothing, and hears nothing of it.
    #[test]
    fn an_empty_answer_judges_nobody_until_it_comes_twice() {
        let me = account(1);
        let mut s = sync_for(&me);
        let (bob, cat, dee) = (account(2), account(3), account(4));
        s.ask_keys([bob.id]);
        s.ask_keys([cat.id]);
        // Bob's answer never comes, and cat's is empty
        let (out, _) = s
            .on_reply(&AccountReply::LogKeysFound { keys: Vec::new() })
            .unwrap();
        assert!(!s.distrusted.contains(&bob.id), "bob was only unlucky");
        assert_eq!(sent(&out, "LogKeys").len(), 1, "and is asked for again");
        s.on_reply(&AccountReply::LogKeysFound {
            keys: vec![bob.info("bob")],
        })
        .unwrap();
        assert!(s.peers.contains_key(&bob.id));
        assert!(!s.distrusted.contains(&bob.id));

        // Whereas someone with truly no key is found out at the second
        s.ask_keys([dee.id]);
        for _ in 0..2 {
            s.on_reply(&AccountReply::LogKeysFound { keys: Vec::new() })
                .unwrap();
        }
        assert!(s.distrusted.contains(&dee.id));
    }

    /// Refused for good: what waits for that conversation is let go, so it is
    /// not asked for and told about again every couple of seconds.
    #[test]
    fn what_waits_for_a_refused_conversation_does_not_ask_again() {
        let (me, bob) = (account(1), account(2));
        let mut s = sync_for(&me);
        let conv = "c:gone".to_string();
        s.joined.insert(conv.clone());
        s.on_reply(&AccountReply::LogPending {
            conv: conv.clone(),
            joiners: vec![bob.id],
        })
        .unwrap();
        keys_answer(&mut s, vec![bob.info("bob")]);
        assert_eq!(s.fetch_asks.len(), 1, "the wraps its answer needs");
        s.on_reply(&AccountReply::Error {
            request: "WrapsFetch".into(),
            reason: "not a conversation of yours".into(),
        })
        .unwrap();
        s.on_reply(&AccountReply::LogConvs { convs: Vec::new() })
            .unwrap();
        for _ in 0..4 {
            let (out, events) = s.tick();
            assert!(out.is_empty() && events.is_empty(), "{out:?} {events:?}");
        }
    }

    #[test]
    fn a_channel_left_during_a_read_is_asked_for_no_more() {
        let me = account(1);
        let mut s = sync_for(&me);
        let conv = "c:1".to_string();
        s.on_reply(&AccountReply::LogJoined { conv: conv.clone() })
            .unwrap();
        s.on_reply(&empty_wraps(&conv)).unwrap();
        s.leave(&conv, false);
        let (out, _) = s
            .on_reply(&AccountReply::LogPage {
                conv: conv.clone(),
                entries: Vec::new(),
                more: true,
                owed: Vec::new(),
            })
            .unwrap();
        assert!(sent(&out, "LogFetch").is_empty(), "{out:?}");
    }

    /// A refused copy must not be reported as kept (`AccountSession::kept_for`).
    #[test]
    fn a_refused_copy_is_remembered_until_one_is_kept() {
        let me = account(1);
        let mut s = sync_for(&me);
        assert!(!s.copy_refused());
        s.on_reply(&AccountReply::Error {
            request: "LogAppend".into(),
            reason: "nothing is kept while you write under a pseudonym.".into(),
        })
        .unwrap();
        assert!(s.copy_refused());
        s.on_reply(&AccountReply::LogAppended {
            conv: "d:1".into(),
            seq: 3,
            server_at: 1,
        })
        .unwrap();
        assert!(!s.copy_refused());
    }

    #[test]
    fn refused_members_are_asked_again() {
        let me = account(1);
        let mut s = sync_for(&me);
        s.prefs.cloud = true;
        s.joined.insert("c:1".into());
        let out = s.send_channel("c:1", envelope("m", "hello", None), 1, None);
        assert_eq!(sent(&out, "LogMembers").len(), 1);
        let (_, events) = s.on_reply(&slow_down("LogMembers")).unwrap();
        assert!(events.is_empty(), "{events:?}");
        assert_eq!(sent(&s.tick().0, "LogMembers").len(), 1);
    }

    /// `me` signed in with `pins` as the vault holds them, and this device's memory.
    fn start_with(
        me: &Account,
        dek: [u8; 32],
        pins: Option<VaultBlob>,
        memory: LogMemory,
    ) -> (AccountSync, SignedIn) {
        let vault = Vault::from_dek(RELAY, "me", dek);
        let mut blobs = vec![VaultBlob {
            version: 1,
            ..vault.seal_item(ITEM_LOGKEY, 1, &me.logkey.to_bytes())
        }];
        blobs.extend(pins);
        let signed = SignedIn {
            relay_id: RELAY,
            name: "me".into(),
            vault,
            identity: me.identity,
            recovery: None,
            blobs,
        };
        let (s, _) = AccountSync::start(&signed, me.id, memory, false);
        (s, signed)
    }

    /// The problems the first reply hands over.
    fn problems(s: &mut AccountSync) -> Vec<(&'static str, &'static str)> {
        let (_, events) = s
            .on_reply(&AccountReply::LogConvs { convs: Vec::new() })
            .unwrap();
        events
            .into_iter()
            .filter_map(|e| {
                if let Event::VaultProblem { item, problem } = e {
                    Some((item, problem))
                } else {
                    None
                }
            })
            .collect()
    }

    /// H2-01: pins this device cannot read, or an older copy than it saw, or
    /// none where it saw some, are never saved over (that would turn off every
    /// pin, for every device), and the person is told.
    #[test]
    fn vault_pins_it_cannot_trust_are_reported_and_never_saved_over() {
        let me = account(1);
        let peer = account(2);
        let key = peer.identity.public_key().serialize();
        let vault = Vault::create(RELAY, "me");

        // Damaged: the relay flipped a byte
        let mut damaged = VaultBlob {
            version: 4,
            ..vault.seal_item(ITEM_PINS, 3, &Pins::default().to_bytes())
        };
        let last = damaged.v.len() - 1;
        damaged.v[last] ^= 1;
        let (mut s, _) = start_with(&me, vault.dek(), Some(damaged), LogMemory::default());
        assert_eq!(problems(&mut s), vec![(ITEM_PINS, "unreadable")]);
        let (_, out) = s.check_peer(&peer.id, "bob", &key);
        assert!(
            sent(&out, "VaultPut").is_empty(),
            "saved over pins it could not read: {out:?}"
        );

        // Older than this device saw (the relay handed back an old copy)
        let old = VaultBlob {
            version: 2,
            ..vault.seal_item(ITEM_PINS, 1, &Pins::default().to_bytes())
        };
        let seen = LogMemory {
            vault_gens: [(ITEM_PINS.to_string(), 5)].into(),
            ..Default::default()
        };
        let (mut s, _) = start_with(&me, vault.dek(), Some(old), seen.clone());
        assert_eq!(problems(&mut s), vec![(ITEM_PINS, "older")]);
        assert!(sent(&s.check_peer(&peer.id, "bob", &key).1, "VaultPut").is_empty());

        // None at all, where this device saw some
        let (mut s, _) = start_with(&me, vault.dek(), None, seen);
        assert_eq!(problems(&mut s), vec![(ITEM_PINS, "missing")]);
        assert!(sent(&s.check_peer(&peer.id, "bob", &key).1, "VaultPut").is_empty());

        // A first device with no pins yet saves them, and remembers the
        // generation once the vault confirms it
        let (mut s, _) = start_with(&me, vault.dek(), None, LogMemory::default());
        assert!(problems(&mut s).is_empty());
        let (_, out) = s.check_peer(&peer.id, "bob", &key);
        assert_eq!(sent(&out, "VaultPut").len(), 1);
        s.on_reply(&AccountReply::VaultStored {
            k: ITEM_PINS.into(),
            version: 1,
        })
        .unwrap();
        assert_eq!(s.memory().vault_gens.get(ITEM_PINS), Some(&1));
        assert!(s.take_memory_changed());
    }

    /// H2-08: a conflict copy that pins someone to another key is not adopted
    /// silently.
    #[test]
    fn a_merged_pin_that_disagrees_is_reported() {
        let me = account(1);
        let peer = account(2);
        let (mut s, signed) = start_with(&me, [7; 32], None, LogMemory::default());
        problems(&mut s);
        s.check_peer(&peer.id, "bob", &peer.identity.public_key().serialize());
        let mut theirs = Pins::default();
        theirs.check(
            &peer.id,
            "bob",
            &account(3).identity.public_key().serialize(),
        );
        let blob = VaultBlob {
            version: 2,
            ..Vault::from_dek(RELAY, "me", signed.vault.dek()).seal_item(
                ITEM_PINS,
                1,
                &theirs.to_bytes(),
            )
        };
        let (_, events) = s
            .on_reply(&AccountReply::VaultConflict {
                k: ITEM_PINS.into(),
                blob: Some(blob),
            })
            .unwrap();
        assert!(
            events.iter().any(
                |e| matches!(e, Event::IdentityChanged { account, .. } if *account == peer.id)
            ),
            "{events:?}"
        );
    }

    impl Blocks {
        fn from_entries(entries: &[(String, String)]) -> Blocks {
            let mut b = Blocks::default();
            for (key, label) in entries {
                b.set(key, label, true).unwrap();
            }
            b
        }
    }

    /// `me` signed in with these vault items, sealed as an earlier save left them.
    fn start_with_items(
        me: &Account,
        items: &[(&str, u64, Vec<u8>)],
        memory: LogMemory,
    ) -> (AccountSync, Vault) {
        let vault = Vault::create(RELAY, "me");
        let mut blobs = vec![VaultBlob {
            version: 1,
            ..vault.seal_item(ITEM_LOGKEY, 1, &me.logkey.to_bytes())
        }];
        for (k, gen, payload) in items {
            blobs.push(VaultBlob {
                version: 1,
                ..vault.seal_item(k, *gen, payload)
            });
        }
        let dek = vault.dek();
        let signed = SignedIn {
            relay_id: RELAY,
            name: "me".into(),
            vault,
            identity: me.identity,
            recovery: None,
            blobs,
        };
        let (s, _) = AccountSync::start(&signed, me.id, memory, false);
        (s, Vault::from_dek(RELAY, "me", dek))
    }

    /// The one `VaultPut` of `out`.
    fn put_of(out: &[ClientMessage]) -> (&str, &[u8]) {
        match &sent(out, "VaultPut")[..] {
            [AccountRequest::VaultPut { k, v, .. }] => (k.as_str(), v.as_slice()),
            other => panic!("not one VaultPut: {other:?}"),
        }
    }

    const BOB: [u8; 16] = [0xb0; 16];

    fn bob_key() -> String {
        format!("a:{}", voipc_protocol::conv::hex(&BOB))
    }

    fn blocks_of(entries: &[(&str, &str)]) -> Vec<(String, String)> {
        entries
            .iter()
            .map(|(k, l)| (k.to_string(), l.to_string()))
            .collect()
    }

    #[test]
    fn a_blocked_list_survives_saving_and_signing_in_again() {
        let me = account(1);
        let (mut s, vault) = start_with_items(&me, &[], LogMemory::default());
        let out = s.set_block(&bob_key(), "bob", true).unwrap();
        assert_eq!(put_of(&out).0, ITEM_BLOCKS);
        assert!(
            s.set_block("g:eve#0001", "Eve#0001", true)
                .unwrap()
                .is_empty(),
            "one write at a time"
        );
        let (out, _) = s
            .on_reply(&AccountReply::VaultStored {
                k: ITEM_BLOCKS.into(),
                version: 2,
            })
            .unwrap();
        let (k, v) = put_of(&out);
        let saved = VaultBlob {
            k: k.to_string(),
            v: v.to_vec(),
            version: 3,
        };
        let item = vault.open_item(&[saved], ITEM_BLOCKS).unwrap();
        assert_eq!(item.gen, 2, "each save counts");

        // The next sign-in, on any device of the account
        let want = blocks_of(&[(&bob_key(), "bob"), ("g:eve#0001", "Eve#0001")]);
        let (mut s, _) = start_with_items(
            &me,
            &[(ITEM_BLOCKS, item.gen, item.payload)],
            LogMemory::default(),
        );
        assert_eq!(s.blocks(), want, "a guest as written, keyed in lower case");

        // An unblock is a save too, and no change is no write
        let out = s.set_block(&bob_key(), "bob", false).unwrap();
        assert_eq!(put_of(&out).0, ITEM_BLOCKS);
        assert_eq!(s.blocks(), blocks_of(&[("g:eve#0001", "Eve#0001")]));
        assert!(s.set_block(&bob_key(), "bob", false).unwrap().is_empty());
    }

    /// Why this is an item of its own: `Prefs` is positional, and a field added
    /// to it would turn every account's two saved bytes "unreadable" and read-only.
    #[test]
    fn saved_prefs_still_open_beside_a_blocked_list() {
        let me = account(1);
        let list = Blocks::from_entries(&blocks_of(&[(&bob_key(), "bob")])).to_padded();
        let (mut s, _) = start_with_items(
            &me,
            &[(ITEM_PREFS, 1, vec![1, 1]), (ITEM_BLOCKS, 1, list)],
            LogMemory::default(),
        );
        assert_eq!(
            s.prefs(),
            Prefs {
                cloud: true,
                asked: true
            }
        );
        assert_eq!(s.blocks().len(), 1);
        assert!(problems(&mut s).is_empty(), "nothing is reported");
        assert!(
            !s.read_only.contains(ITEM_PREFS),
            "and the cloud setting can still be saved"
        );
    }

    /// Two devices at once: theirs joins ours, is written back, and the front
    /// end hears. A lost unblock stays blocked.
    #[test]
    fn a_conflict_over_the_blocked_list_joins_both_and_saves_again() {
        let me = account(1);
        let (mut s, vault) = start_with_items(&me, &[], LogMemory::default());
        let out = s.set_block(&bob_key(), "bob", true).unwrap();
        assert_eq!(put_of(&out).0, ITEM_BLOCKS);
        let theirs = VaultBlob {
            version: 5,
            ..vault.seal_item(
                ITEM_BLOCKS,
                4,
                &Blocks::from_entries(&blocks_of(&[("g:eve#0001", "eve#0001")])).to_padded(),
            )
        };
        let (out, events) = s
            .on_reply(&AccountReply::VaultConflict {
                k: ITEM_BLOCKS.into(),
                blob: Some(theirs),
            })
            .unwrap();
        let want = blocks_of(&[(&bob_key(), "bob"), ("g:eve#0001", "eve#0001")]);
        assert_eq!(s.blocks(), want);
        assert!(
            matches!(
                &sent(&out, "VaultPut")[..],
                [AccountRequest::VaultPut { expect: 5, .. }]
            ),
            "saved over what the relay holds now: {out:?}"
        );
        let told = events
            .iter()
            .find_map(|e| match e {
                Event::Blocks { .. } => e.to_wire(),
                _ => None,
            })
            .expect("the front end is told");
        assert_eq!(told.0, "account-blocks");
        assert_eq!(told.1["blocks"], serde_json::json!(want));
    }

    /// One this device cannot use is left alone, and a change to it is refused
    /// out loud: a list that only looks changed comes back at the next sign-in.
    #[test]
    fn a_blocked_list_it_cannot_read_is_never_saved_over() {
        let me = account(1);
        let vault = Vault::create(RELAY, "me");
        let mut damaged = VaultBlob {
            version: 4,
            ..vault.seal_item(ITEM_BLOCKS, 3, &Blocks::default().to_padded())
        };
        let last = damaged.v.len() - 1;
        damaged.v[last] ^= 1;
        let (mut s, _) = start_with(&me, vault.dek(), Some(damaged), LogMemory::default());
        assert_eq!(problems(&mut s), vec![(ITEM_BLOCKS, "unreadable")]);
        assert!(s.set_block(&bob_key(), "bob", true).is_err());
        assert!(s.blocks().is_empty());
        // Withheld, where this device saw one
        let seen = LogMemory {
            vault_gens: [(ITEM_BLOCKS.to_string(), 5)].into(),
            ..Default::default()
        };
        let (mut s, _) = start_with(&me, vault.dek(), None, seen);
        assert_eq!(problems(&mut s), vec![(ITEM_BLOCKS, "missing")]);
        assert!(s.set_block(&bob_key(), "bob", true).is_err());
        // The control: a first device saves
        let (mut s, _) = start_with(&me, vault.dek(), None, LogMemory::default());
        assert_eq!(
            sent(&s.set_block(&bob_key(), "bob", true).unwrap(), "VaultPut").len(),
            1
        );
    }

    #[test]
    fn the_blocked_list_stops_at_its_cap() {
        let me = account(1);
        let (mut s, _) = start_with_items(&me, &[], LogMemory::default());
        for i in 0..BLOCKS_MAX {
            let name = format!("guest#{i:04}");
            s.set_block(&format!("g:{name}"), &name, true).unwrap();
        }
        assert_eq!(s.blocks().len(), BLOCKS_MAX);
        assert!(s.set_block(&bob_key(), "bob", true).is_err(), "one more");
        assert!(
            s.set_block("g:guest#0000", "guest#0000", true)
                .unwrap()
                .is_empty(),
            "one already on it is no more"
        );
        assert_eq!(s.blocks().len(), BLOCKS_MAX);
        // Unblocking makes room
        s.set_block("g:guest#0000", "guest#0000", false).unwrap();
        assert!(s.set_block(&bob_key(), "bob", true).is_ok());
        // Nor does a list another device saved get past it, the accounts staying
        let mut over = Blocks::default();
        for i in 0..(BLOCKS_MAX + 20) {
            over.guests.insert(format!("guest#{i:04}"));
        }
        over.accounts.insert(BOB, "bob".into());
        let bytes = postcard::to_allocvec(&over).unwrap();
        let read = Blocks::from_bytes(&bytes).unwrap();
        assert_eq!(read.len(), BLOCKS_MAX);
        assert!(read.accounts.contains_key(&BOB));
    }

    #[test]
    fn a_label_is_clipped_and_a_key_must_name_somebody() {
        let me = account(1);
        let (mut s, _) = start_with_items(&me, &[], LogMemory::default());
        s.set_block(&bob_key(), &"b".repeat(500), true).unwrap();
        assert_eq!(s.blocks()[0].1.chars().count(), BLOCK_NAME_MAX);
        for bad in ["", "bob", "a:zz", "x:bob", "g:other"] {
            assert!(s.set_block(bad, "bob", true).is_err(), "{bad}");
        }
    }

    /// The relay sees that the item changed and its bucket. How many people are
    /// on the list it must not read from the size.
    #[test]
    fn lists_of_different_lengths_in_a_bucket_seal_to_one_size() {
        let vault = Vault::create(RELAY, "me");
        let sealed = |names: &[&str]| {
            let mut b = Blocks::default();
            for n in names {
                b.guests.insert(n.to_string());
            }
            let padded = b.to_padded();
            assert_eq!(padded.len() % BLOCKS_BUCKET, 0);
            (
                padded.len(),
                vault.seal_item(ITEM_BLOCKS, 1, &padded).v.len(),
            )
        };
        let (one, none) = (sealed(&["bob#0001"]), sealed(&[]));
        let many = sealed(&["bob#0001", "eve#0002", "mallory#0003", "trudy#0004"]);
        assert_eq!(none, one, "nobody blocked looks like somebody");
        assert_eq!(one, many, "and one like four");
        // The control: a list past the bucket is the next one, and still opens
        let names: Vec<String> = (0..200).map(|i| format!("someone-long#{i:04}")).collect();
        let long: Vec<&str> = names.iter().map(String::as_str).collect();
        assert!(sealed(&long).0 > one.0);
        let mut b = Blocks::default();
        b.guests.extend(names);
        assert_eq!(Blocks::from_bytes(&b.to_padded()).unwrap(), b);
    }

    /// A block tells the relay nothing but that an item changed, and the blocked
    /// person nothing at all.
    #[test]
    fn a_block_sends_one_sealed_write_and_names_nobody() {
        let me = account(1);
        let hex = voipc_protocol::conv::hex(&BOB);
        let holds = |hay: &[u8], needle: &[u8]| hay.windows(needle.len()).any(|w| w == needle);
        let name = "eve-the-guest#0001";
        for (key, label, who) in [
            (bob_key(), "bob-the-person", &BOB[..]),
            (format!("g:{name}"), name, name.as_bytes()),
        ] {
            let (mut s, _) = start_with_items(&me, &[], LogMemory::default());
            let out = s.set_block(&key, label, true).unwrap();
            assert_eq!(out.len(), 1, "one message: {out:?}");
            let (k, v) = put_of(&out);
            assert_eq!(k, ITEM_BLOCKS, "and the only thing it names");
            for leak in [who, label.as_bytes(), hex.as_bytes()] {
                assert!(!holds(v, leak), "the sealed bytes hold {leak:?}");
            }
            let shown = format!("{out:?}");
            assert!(!shown.contains(label) && !shown.contains(&hex));
            // The control: unsealed, the same list does say who
            let plain = s.item_bytes(ITEM_BLOCKS);
            assert!(holds(&plain, who) && holds(&plain, label.as_bytes()));
        }
    }

    /// The vault is shared with the pins: a refused write reaches the person,
    /// or the block would be lost at the next sign-in without a word.
    #[test]
    fn a_refused_write_of_the_blocked_list_is_told() {
        let me = account(1);
        let (mut s, _) = start_with_items(&me, &[], LogMemory::default());
        s.set_block(&bob_key(), "bob", true).unwrap();
        let (_, events) = s
            .on_reply(&AccountReply::Error {
                request: "VaultPut".into(),
                reason: "The vault is full.".into(),
            })
            .unwrap();
        assert!(
            events
                .iter()
                .any(|e| matches!(e, Event::NotKept { reason } if reason.contains("full"))),
            "{events:?}"
        );
        // And it can be tried again
        assert_eq!(
            sent(
                &s.set_block("g:eve#0001", "eve#0001", true).unwrap(),
                "VaultPut"
            )
            .len(),
            1
        );
    }
}
