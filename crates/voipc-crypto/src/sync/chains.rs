//! A channel's keys on a relay at protocol 21, as `AccountSync` runs them. `crate::log` makes
//! and opens the rows, and the relay's `chain_put` says what it holds a writer to. Direct
//! conversations, and channels on an older relay, stay on epochs.
//!
//! The rules that carry the security, as a writer:
//!
//! - A key reaches a person only by a row this device made after naming them, or by a seal to
//!   a list it has read, checked against its own row's digest, and named. No list, no seal.
//! - A bucket never grows: someone gone means a new version with fewer people, someone new
//!   means a new bucket with no way down.
//! - Index 0 of a chain with a back-link goes only to who is proven to have held the start of
//!   the chain it names: their seal or row there opens to the start this device holds. Never
//!   the relay's word, and anything it left out fails to not index 0.
//! - Told someone is gone, this device ends the chain at its next post whatever the relay says.
//! - A member it cannot reach, with no log key or none it can trust, gets a blank row: random
//!   bytes that give them nothing and name nobody. So one person stops nobody's posts, and
//!   they read none of them until a real key means a real row.
//! - A sharer's answer counts when its last frame is stored. Until then the joiner still waits
//!   on us, and a lost answer is answered again at the next `LogIndex`.
//!
//! And as a reader: a row opens only as a static wrap, by length and label, and only once
//! an entry on that chain needs it, with the writer's log key in hand first.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::Arc;

use voipc_protocol::messages::{
    AccountRequest, BucketIn, ChainAsk, ChainKeys, ChainRow, ChainSeal, ClientMessage, LogEntry,
    OwnBucket, OwnChain, WrapIn,
};
use zeroize::Zeroizing;

use super::{ask, AccountSync, Event, Fetch, Outgoing, LOST_AFTER_TICKS, MAX_REKEYS};
use crate::log::{
    blank_row, bucket_id, chain_epoch, epoch_key, epoch_parts, open_chain_entry, seal_chain_entry,
    self_open_state, self_wrap_state, Bucket, Chain, ListedSeat, StaticKey,
};

type Id = [u8; 16];
type Key = Zeroizing<[u8; 32]>;

/// Seats a bucket is made up to.
const BUCKET_SEATS: usize = 62;
/// A bucket under this many seats is a small one, and this many small ones merge into one.
const SMALL_SEATS: usize = 16;
const SMALL_BUCKETS: usize = 16;
/// The newest index a chain takes: past it a writer starts a new chain (the relay's own bound).
const MAX_TOP: u32 = 128;
/// What one `ChainRekey` names at most. At these a writer goes by other means.
const MAX_MISSING: usize = 256;
const MAX_ARRIVALS: usize = 2048;
const MAX_GONE: usize = 1024;
/// New buckets in one `ChainPut` while the writer has a live one, lists and chain asks in one
/// ask, channels in one `LogJoinMany` (the relay's own bounds).
const MAX_NEW_BUCKETS: usize = 3;
const MAX_LISTS: usize = 32;
const MAX_CHAIN_ASKS: usize = 64;
const MAX_JOIN_MANY: usize = 512;
/// What one `ChainPut` carries, under the 64 KiB frame.
const FRAME_BYTES: usize = 56 * 1024;
/// Rows in one such frame, at 78 B a row, and wraps of a version before chains, at 110 B.
const ROWS_PER_FRAME: usize = FRAME_BYTES / 80;
pub(super) const WRAPS_PER_FRAME: usize = FRAME_BYTES / 112;
/// Readers a writer takes the relay's word for: where the pins stop anyway. Paged, the ids
/// would otherwise let a relay name a million people for a writer to upload a row to.
const MOST_READERS: usize = 32_000;
/// Hops a reader walks down a writer's run of links past what one answer holds.
const MAX_WALK: u32 = 4096;
/// `behind`s in a row before giving up on what waits. Each is a read back and another frame.
const MAX_BEHINDS: u32 = 3;

/// Where our newest chain in a channel stands.
struct Standing {
    chain: u32,
    index: u32,
    state: Key,
    start: Key,
}

/// A bucket the newest chain is sealed to, as our own row opened it.
struct LiveBucket {
    version: u32,
    key: Key,
    digest: [u8; 32],
    /// The relay's count until the list is read, which only chooses what to read.
    seats: usize,
    list: Option<Vec<ListedSeat>>,
}

/// Proven holders of the start of the chain a new one links to.
#[derive(Default)]
struct Proof {
    buckets: BTreeSet<u64>,
    people: BTreeSet<Id>,
}

/// What the next frames are to do.
#[derive(Default)]
struct Want {
    new_chain: bool,
    /// People to give a seat. `None`: find out, from all the ids less all the lists, and
    /// whoever is on a list and not among the ids has gone.
    arrivals: Option<BTreeSet<Id>>,
    ids: BTreeSet<Id>,
    ids_after: Option<Id>,
    ids_done: bool,
    /// Whoever the relay says is gone, and from which bucket.
    gone: BTreeSet<(Id, u64)>,
    proof: Proof,
    proof_after: Option<Id>,
    proof_done: bool,
}

/// `ChainRekey`s not acted on yet: posts under one key come back one by one.
#[derive(Default)]
struct Rekey {
    new_chain: bool,
    missing: BTreeSet<Id>,
    gone: BTreeSet<(Id, u64)>,
}

/// What the frames going out come to, once the last is stored.
enum Done {
    Chain {
        standing: Standing,
        live: BTreeMap<u64, LiveBucket>,
        info: OwnChain,
    },
    Step {
        index: u32,
        state: Key,
    },
    Rows {
        joiners: Vec<Id>,
    },
}

/// One writer's business in one channel, read back from the relay as far as a post needs.
#[derive(Default)]
pub(super) struct Writer {
    chains_read: bool,
    all_chains: bool,
    chains: BTreeMap<u32, OwnChain>,
    newest: Option<u32>,
    standing_read: bool,
    steps_asked: bool,
    now: Option<Standing>,
    buckets_read: bool,
    buckets_after: Option<u64>,
    live: BTreeMap<u64, LiveBucket>,
    /// A bucket the newest chain is sealed to that we could not open or read: its people
    /// are found from the ids.
    lost: bool,
    want: Option<Want>,
    /// The one ask out: its request's name.
    out: Option<&'static str>,
    idle: u32,
    /// The frame at the front is the one out, or the next to go.
    frames: VecDeque<AccountRequest>,
    done: Option<Done>,
    rekey: Option<Rekey>,
    /// Told someone is gone (`MemberGone`): a new chain at the next post.
    ended: bool,
    gone_seen: BTreeSet<Id>,
    last_missing: BTreeSet<Id>,
    /// `ChainStored { behind }` in a row.
    behinds: u32,
}

impl WrapsAsked {
    pub(super) fn is_writer(&self) -> bool {
        self.writer
    }
}

impl Writer {
    /// A post may go on `now`.
    fn ready(&self) -> bool {
        self.chains_read
            && self.standing_read
            && self.now.is_some()
            && !self.ended
            && self.want.is_none()
            && self.out.is_none()
            && self.frames.is_empty()
            && self.rekey.is_none()
    }

    /// What we took for true may not be: all of it again. What is wanted stays.
    fn read_again(&mut self) {
        self.chains_read = false;
        self.all_chains = false;
        self.chains.clear();
        self.newest = None;
        self.standing_read = false;
        self.steps_asked = false;
        self.now = None;
        self.buckets_read = false;
        self.buckets_after = None;
        self.live.clear();
        self.lost = false;
        self.out = None;
        self.idle = 0;
        self.frames.clear();
        self.done = None;
        if let Some(want) = &mut self.want {
            want.proof = Proof::default();
            want.proof_after = None;
            want.proof_done = false;
        }
    }

    fn highest(&self) -> Option<u32> {
        self.chains
            .keys()
            .next_back()
            .copied()
            .max(self.newest)
            .max(self.now.as_ref().map(|n| n.chain))
    }

    /// Which seats of a bucket are to go, on what is known before any key has come.
    fn leaving_said(&self, want: &Want, id: u64, seat: &ListedSeat) -> bool {
        want.gone.contains(&(seat.account, id))
            || self.gone_seen.contains(&seat.account)
            || (want.ids_done && !want.ids.contains(&seat.account))
    }

    /// How many seats a bucket comes to once who is gone has gone.
    fn seats_after(&self, want: &Want, id: u64, b: &LiveBucket) -> usize {
        match &b.list {
            Some(list) => list
                .iter()
                .filter(|s| !self.leaving_said(want, id, s))
                .count(),
            None => b.seats,
        }
    }

    /// The buckets to merge at the next chain: every small one once there are enough, and a
    /// re-pack of the smallest others up to a bucket's size once there are too many for the
    /// seats. Without the re-pack buckets only ever shrink, and a chain seals to more and
    /// more of them: 88 at a year where 32 were made.
    fn merges(&self, want: &Want) -> (BTreeSet<u64>, BTreeSet<u64>) {
        let sizes: Vec<(u64, usize)> = self
            .live
            .iter()
            .map(|(id, b)| (*id, self.seats_after(want, *id, b)))
            .filter(|(_, n)| *n > 0)
            .collect();
        let arrivals = want.arrivals.as_ref().map_or(0, BTreeSet::len);
        let small: BTreeSet<u64> = sizes
            .iter()
            .filter(|(_, n)| *n < SMALL_SEATS)
            .map(|(id, _)| *id)
            .collect();
        let new_small = usize::from(arrivals > 0 && arrivals < SMALL_SEATS);
        let small = if small.len() + new_small >= SMALL_BUCKETS {
            small
        } else {
            BTreeSet::new()
        };
        let seats: usize = sizes.iter().map(|(_, n)| n).sum::<usize>() + arrivals;
        let small_seats: usize = sizes
            .iter()
            .filter(|(id, _)| small.contains(id))
            .map(|(_, n)| n)
            .sum::<usize>();
        let buckets = sizes.len() - small.len()
            + (if small.is_empty() {
                arrivals
            } else {
                small_seats + arrivals
            })
            .div_ceil(BUCKET_SEATS);
        let mut repack = BTreeSet::new();
        // B > 1.5 x S/m + 16, in whole numbers
        if 2 * buckets * BUCKET_SEATS > 3 * seats + 32 * BUCKET_SEATS {
            let mut others: Vec<(u64, usize)> = sizes
                .iter()
                .filter(|(id, _)| !small.contains(id))
                .copied()
                .collect();
            others.sort_unstable_by_key(|(_, n)| *n);
            let mut sum = 0;
            for (id, n) in others {
                if sum + n > BUCKET_SEATS {
                    break;
                }
                sum += n;
                repack.insert(id);
            }
            if repack.len() < 2 {
                repack.clear();
            }
        }
        (small, repack)
    }
}

/// What this device holds of one writer's chain in one channel.
#[derive(Default)]
struct Held {
    /// Rows as they came: opened when an entry first needs them.
    rows: Vec<ChainKeys>,
    states: BTreeMap<u32, Key>,
    steps: BTreeMap<u32, Vec<u8>>,
    link: Option<(u32, Vec<u8>)>,
    /// Asks answered, for one more when an entry's chain was minted during a read, and the
    /// highest index an entry had when asking: a later step can only show under a later ask.
    asked: u8,
    asked_to: u32,
}

/// What this device holds of a channel's chains, from all its writers.
#[derive(Default)]
pub(super) struct Holds {
    chains: HashMap<(Id, u32), Held>,
    /// `(owner, older)`: the chain whose link opens that one.
    above: HashMap<(Id, u32), u32>,
    /// Bucket keys opened, at `(owner, bucket, version)`.
    bucket_keys: HashMap<(Id, u64, u32), Key>,
    /// `(owner, asked)`: a run of links too long for one answer goes on at this chain, after
    /// this many hops.
    walks: HashMap<(Id, u32), (u32, u32)>,
}

/// What opening an entry still takes.
enum Need {
    Have,
    Ask(ChainAsk),
    /// Nothing there will open it.
    No,
}

/// One `WrapsPage` not answered yet.
pub(super) struct WrapsAsked {
    conv: String,
    /// `(ask, the chain the entry is on, its index)`
    asks: Vec<(ChainAsk, u32, u32)>,
    /// The writer reading itself back, not a read.
    writer: bool,
}

/// A frame of an answer to joiners, on a finished chain. `last`: it ends their wait.
fn rows_frame(conv: &str, epoch: u32, wraps: Vec<ChainRow>, last: bool) -> AccountRequest {
    AccountRequest::ChainPut {
        conv: conv.to_string(),
        epoch,
        self_wrap: None,
        step: None,
        link: None,
        wraps,
        buckets: Vec::new(),
        seals: Vec::new(),
        last,
    }
}

/// What a writer's frame is asked and answered as.
fn frame_name(frame: &AccountRequest) -> &'static str {
    match frame {
        AccountRequest::EpochPut { .. } => "EpochPut",
        _ => "ChainPut",
    }
}

/// Entries that will not open, for the quiet line at the end of the read.
fn add_unopened(map: &mut HashMap<String, u32>, conv: &str, n: u32) {
    if n > 0 {
        *map.entry(conv.to_string()).or_default() += n;
    }
}

impl AccountSync {
    pub(super) fn on_chains(&self, conv: &str) -> bool {
        self.chains && conv.starts_with("c:")
    }

    /// Our secret with `who`, once per connection, if their log key is in.
    fn static_key(&mut self, who: &Id) -> Option<Arc<StaticKey>> {
        let logkey = self.peers.get(who).map(|p| p.logkey.clone())?;
        if let Some((known, key)) = self.statics.get(who) {
            if *known == logkey {
                return Some(key.clone());
            }
        }
        let key = Arc::new(StaticKey::new(&self.logkey, &logkey)?);
        self.statics.insert(*who, (logkey, key.clone()));
        Some(key)
    }

    fn own_ask(
        &mut self,
        conv: &str,
        w: &mut Writer,
        what: &'static str,
        request: AccountRequest,
    ) -> ClientMessage {
        self.writer_asks.push_back((what, conv.to_string()));
        w.out = Some(what);
        w.idle = 0;
        ask(request)
    }

    /// A writer's ask got its answer.
    fn own_answered(&mut self, conv: &str, what: &str, w: &mut Writer) {
        if let Some(at) = self
            .writer_asks
            .iter()
            .position(|(asked, c)| *asked == what && c == conv)
        {
            self.writer_asks.remove(at);
        }
        if w.out == Some(what) {
            w.out = None;
        }
        w.idle = 0;
    }

    // ── A writer ──────────────────────────────────────────────────────────

    /// What `conv`'s writer needs next, one ask at a time: all it knows is what the relay
    /// answered, so a lost or refused answer only means running this again.
    pub(super) fn advance(&mut self, conv: &str) -> Vec<ClientMessage> {
        if self.logkey_unsettled || self.held || !self.pins_in() {
            return Vec::new();
        }
        let mut w = self.writers.remove(conv).unwrap_or_default();
        let out = self.advance_writer(conv, &mut w);
        self.writers.insert(conv.to_string(), w);
        out
    }

    fn advance_writer(&mut self, conv: &str, w: &mut Writer) -> Vec<ClientMessage> {
        let mut out = Vec::new();
        if w.out.is_some() {
            return out;
        }
        if let Some(frame) = w.frames.front().cloned() {
            out.push(self.own_ask(conv, w, frame_name(&frame), frame));
            return out;
        }
        if !w.chains_read {
            let before = w.chains.keys().next().copied();
            let request = AccountRequest::OwnChains {
                conv: conv.to_string(),
                before,
            };
            out.push(self.own_ask(conv, w, "OwnChains", request));
            return out;
        }
        if !w.standing_read && self.read_standing(conv, w, &mut out) {
            return out;
        }
        if w.want.is_none() && self.outbox.iter().any(|o| o.conv == conv) {
            if w.now.is_none() {
                w.want = Some(Want {
                    new_chain: true,
                    ..Want::default()
                });
            } else if w.ended {
                // Nobody to add: who has no seat gets a step at the next post
                w.want = Some(Want {
                    new_chain: true,
                    arrivals: Some(BTreeSet::new()),
                    ..Want::default()
                });
            }
        }
        if w.want.is_some() {
            self.work_on_want(conv, w, &mut out);
        } else if self.joiners.contains_key(conv) {
            self.answer_joiners(conv, w, &mut out);
        }
        out
    }

    /// Goes on from the newest chain: whether an ask went out. A self-wrap that does not open
    /// is one we will not write under, whatever is claimed: the next post starts a new chain.
    fn read_standing(&mut self, conv: &str, w: &mut Writer, out: &mut Vec<ClientMessage>) -> bool {
        let me = self.me;
        let Some(n) = w.newest else {
            w.standing_read = true;
            return false;
        };
        let opened = w.chains.get(&n).and_then(|c| {
            let start =
                self_open_state(&self.logkey, &c.self_wrap, conv, &me, chain_epoch(n, 0)?).ok()?;
            Some((c.top, start))
        });
        let Some((top, start)) = opened else {
            w.standing_read = true;
            return false;
        };
        let steps = self
            .holds
            .get(conv)
            .and_then(|h| h.chains.get(&(me, n)))
            .map(|h| &h.steps);
        let at = Chain {
            conv,
            owner: &me,
            chain: n,
        };
        let mut state = start.clone();
        let mut walked = true;
        for i in 0..top {
            let next = steps
                .and_then(|s| s.get(&i))
                .and_then(|row| at.follow(i, &state, row).ok());
            match next {
                Some(s) => state = s,
                None => {
                    walked = false;
                    break;
                }
            }
        }
        if !walked && !w.steps_asked {
            w.steps_asked = true;
            let chain_ask = ChainAsk {
                owner: me,
                chain: n,
                from: None,
            };
            self.wraps_asked.push_back(WrapsAsked {
                conv: conv.to_string(),
                asks: vec![(chain_ask.clone(), n, top)],
                writer: true,
            });
            let request = AccountRequest::WrapsPage {
                conv: conv.to_string(),
                asks: vec![chain_ask],
            };
            out.push(self.own_ask(conv, w, "WrapsPage", request));
            return true;
        }
        w.standing_read = true;
        if walked {
            // Our own entries on it open from here too
            let held = self
                .holds
                .entry(conv.to_string())
                .or_default()
                .chains
                .entry((me, n))
                .or_default();
            held.states.insert(0, start.clone());
            held.states.insert(top, state.clone());
            w.now = Some(Standing {
                chain: n,
                index: top,
                state,
                start,
            });
        }
        false
    }

    fn work_on_want(&mut self, conv: &str, w: &mut Writer, out: &mut Vec<ClientMessage>) {
        let Some(mut want) = w.want.take() else {
            return;
        };
        if !want.new_chain {
            let many = want
                .arrivals
                .as_ref()
                .is_none_or(|a| a.len() >= MAX_MISSING);
            if many || w.now.as_ref().is_none_or(|n| n.index >= MAX_TOP) {
                want.new_chain = true;
            }
        }
        let finished = if want.new_chain {
            self.make_chain(conv, w, &mut want, out)
        } else {
            self.make_step(conv, w, &want, out)
        };
        if !finished {
            w.want = Some(want);
        }
    }

    /// Whether every one of `accounts` is in, or known not to be. Asks for those that are not.
    fn keys_in_hand(
        &mut self,
        conv: &str,
        accounts: &BTreeSet<Id>,
        out: &mut Vec<ClientMessage>,
    ) -> bool {
        if self.gated_logs.contains(conv) {
            for a in accounts {
                self.reserve_pin(*a);
            }
        }
        out.extend(self.ask_keys(accounts.iter().copied()));
        accounts
            .iter()
            .all(|a| *a == self.me || self.peers.contains_key(a) || self.distrusted.contains(a))
    }

    /// A fresh step, and a row to each person new here: they read from there on.
    fn make_step(
        &mut self,
        conv: &str,
        w: &mut Writer,
        want: &Want,
        out: &mut Vec<ClientMessage>,
    ) -> bool {
        let me = self.me;
        let arrivals = want.arrivals.clone().unwrap_or_default();
        if !self.keys_in_hand(conv, &arrivals, out) {
            return false;
        }
        let mut reached: Vec<(Id, Arc<StaticKey>)> = Vec::new();
        let mut blanks: Vec<Id> = Vec::new();
        for a in arrivals.iter().filter(|a| **a != me) {
            match self.static_key(a) {
                Some(key) => reached.push((*a, key)),
                None => blanks.push(*a),
            }
        }
        // The next post is refused again, which is what gives up in the end
        let Some(now) = w
            .now
            .as_ref()
            .filter(|_| !reached.is_empty() || !blanks.is_empty())
        else {
            return true;
        };
        let index = now.index + 1;
        let Some(epoch) = chain_epoch(now.chain, index) else {
            return true;
        };
        let names: Vec<Id> = reached.iter().map(|(a, _)| *a).collect();
        self.announce(conv, &names, false);
        let at = Chain {
            conv,
            owner: &me,
            chain: now.chain,
        };
        let (state, step) = at.step(now.index, &now.state);
        let wraps = reached
            .iter()
            .map(|(a, key)| ChainRow {
                recipient: *a,
                index,
                wrapped: key.wrap_state(&state, conv, &me, epoch, a),
            })
            .chain(blanks.iter().map(|a| ChainRow {
                recipient: *a,
                index,
                wrapped: blank_row(),
            }))
            .collect();
        w.done = Some(Done::Step { index, state });
        w.frames.push_back(AccountRequest::ChainPut {
            conv: conv.to_string(),
            epoch,
            self_wrap: None,
            step: Some(step),
            link: None,
            wraps,
            buckets: Vec::new(),
            seals: Vec::new(),
            // With the switch off this is all a joiner gets, so it is the whole answer
            last: !self.share,
        });
        self.send_next_frame(conv, w, out);
        true
    }

    fn send_next_frame(&mut self, conv: &str, w: &mut Writer, out: &mut Vec<ClientMessage>) {
        if let Some(frame) = w.frames.front().cloned() {
            out.push(self.own_ask(conv, w, frame_name(&frame), frame));
        }
    }

    /// Everything a new chain takes, one ask at a time; whether it went out.
    fn make_chain(
        &mut self,
        conv: &str,
        w: &mut Writer,
        want: &mut Want,
        out: &mut Vec<ClientMessage>,
    ) -> bool {
        let me = self.me;
        if !w.buckets_read {
            let request = AccountRequest::OwnBuckets {
                conv: conv.to_string(),
                after: w.buckets_after,
            };
            out.push(self.own_ask(conv, w, "OwnBuckets", request));
            return false;
        }
        if w.lost && !want.ids_done {
            want.arrivals = None;
        }
        if want.arrivals.is_none() && !want.ids_done {
            let request = AccountRequest::LogMemberIds {
                conv: conv.to_string(),
                after: want.ids_after,
            };
            out.push(self.own_ask(conv, w, "LogMemberIds", request));
            return false;
        }
        let wanted = self.lists_wanted(conv, w, want);
        if !wanted.is_empty() {
            self.lists_asked.insert(
                conv.to_string(),
                wanted.iter().take(MAX_LISTS).copied().collect(),
            );
            let request = AccountRequest::BucketLists {
                conv: conv.to_string(),
                wanted: wanted.into_iter().take(MAX_LISTS).collect(),
            };
            out.push(self.own_ask(conv, w, "BucketLists", request));
            return false;
        }
        if want.arrivals.is_none() {
            let seated: BTreeSet<Id> = w
                .live
                .values()
                .flat_map(|b| b.list.iter().flatten().map(|s| s.account))
                .collect();
            want.arrivals = Some(
                want.ids
                    .iter()
                    .filter(|a| **a != me && !seated.contains(*a))
                    .copied()
                    .collect(),
            );
            w.lost = false;
            // Whoever this device named and the ids leave out has gone: back, they are new
            if let Some(seen) = self.readers.get_mut(conv) {
                let before = seen.len();
                seen.retain(|a| want.ids.contains(a));
                self.named_changed |= seen.len() != before;
            }
        }
        let arrivals = want.arrivals.clone().unwrap_or_default();
        let mut wanted_keys = arrivals.clone();
        wanted_keys.extend(
            w.live
                .values()
                .flat_map(|b| b.list.iter().flatten().map(|s| s.account)),
        );
        if !self.keys_in_hand(conv, &wanted_keys, out) {
            return false;
        }
        // Named before any seal goes to them, who this device has not named yet
        let mut lists: Vec<(u64, [u8; 32], Vec<Id>)> = Vec::new();
        for (id, b) in &w.live {
            let Some(list) = &b.list else { continue };
            let staying = list
                .iter()
                .filter(|s| !self.leaving(w, want, *id, s))
                .map(|s| s.account)
                .collect();
            lists.push((*id, b.digest, staying));
        }
        for (_, digest, staying) in lists {
            let named = self.named.entry(conv.to_string()).or_default();
            if named.insert(digest) {
                self.memory_changed = true;
                self.named_changed = true;
                self.announce(conv, &staying, false);
            }
        }
        if self.share && !want.proof_done {
            if let Some(chain) = w.now.as_ref().map(|n| n.chain) {
                let request = AccountRequest::OwnChainRows {
                    conv: conv.to_string(),
                    chain,
                    after: want.proof_after,
                };
                out.push(self.own_ask(conv, w, "OwnChainRows", request));
                return false;
            }
        }
        self.build_chain(conv, w, want, &arrivals, out);
        true
    }

    /// Who of a list is to go: as the relay said, as this device was told, or on a log key
    /// other than the one they were seated under. Whoever holds that one keeps the bucket's
    /// key, until someone else in it leaves.
    fn leaving(&self, w: &Writer, want: &Want, id: u64, seat: &ListedSeat) -> bool {
        w.leaving_said(want, id, seat)
            || self
                .logkey_of(&seat.account)
                .is_none_or(|k| ListedSeat::new(&seat.account, &k).key_tag != seat.key_tag)
    }

    /// The lists to read before the next chain: of a bucket someone left, of one this device
    /// has not named, and of one to merge. All of them when nobody can say who has no seat.
    fn lists_wanted(&self, conv: &str, w: &Writer, want: &Want) -> Vec<(u64, u32)> {
        let named = self.named.get(conv);
        let everyone = want.arrivals.is_none() || !w.gone_seen.is_empty();
        let (small, repack) = w.merges(want);
        w.live
            .iter()
            .filter(|(id, b)| {
                b.list.is_none()
                    && (everyone
                        || !named.is_some_and(|n| n.contains(&b.digest))
                        || want.gone.iter().any(|(_, g)| g == *id)
                        || small.contains(id)
                        || repack.contains(id))
            })
            .map(|(id, b)| (*id, b.version))
            .collect()
    }

    /// A new version or bucket with these seats, each of whom we hold a key for.
    fn make_bucket(
        &mut self,
        conv: &str,
        id: u64,
        version: u32,
        seats: &[ListedSeat],
        down: Option<(u32, &[u8; 32])>,
    ) -> (BucketIn, Key, [u8; 32]) {
        let me = self.me;
        let at = Bucket {
            conv,
            owner: &me,
            id,
            version,
        };
        let key = epoch_key();
        let (list, digest) = at.seal_list(&self.logkey, seats);
        let mut rows = vec![WrapIn {
            recipient: me,
            wrapped: at.own_row(&self.logkey, &key, &digest),
        }];
        for s in seats {
            if let Some(sk) = self.static_key(&s.account) {
                rows.push(WrapIn {
                    recipient: s.account,
                    wrapped: sk.wrap_seat(&key, at, &s.account),
                });
            }
        }
        let bucket = BucketIn {
            bucket: id,
            version,
            list,
            seats: rows,
            down: down.map(|(old, old_key)| (old, at.link_down(&key, old, old_key))),
        };
        (bucket, key, digest)
    }

    /// New buckets for `seats`, a bucket's size each, as a merge or an arrival makes them.
    fn new_buckets(
        &mut self,
        conv: &str,
        seats: Vec<ListedSeat>,
        deep: bool,
        made: &mut Vec<(BucketIn, bool)>,
        live: &mut BTreeMap<u64, LiveBucket>,
    ) {
        let mut seats = seats;
        seats.sort_unstable();
        seats.dedup_by_key(|s| s.account);
        for chunk in seats.chunks(BUCKET_SEATS) {
            let id = bucket_id();
            let (bucket, key, digest) = self.make_bucket(conv, id, 0, chunk, None);
            made.push((bucket, deep));
            live.insert(
                id,
                LiveBucket {
                    version: 0,
                    key,
                    digest,
                    seats: chunk.len(),
                    list: Some(chunk.to_vec()),
                },
            );
        }
    }

    /// The chain itself. Who it names and whom it reaches is settled by now.
    fn build_chain(
        &mut self,
        conv: &str,
        w: &mut Writer,
        want: &Want,
        arrivals: &BTreeSet<Id>,
        out: &mut Vec<ClientMessage>,
    ) {
        let me = self.me;
        let chain = w.highest().map_or(1, |h| h.saturating_add(1));
        let Some(epoch0) = chain_epoch(chain, 0) else {
            self.outbox.retain(|o| o.conv != conv);
            self.later.push(Event::NotKept {
                reason: "This channel has used up its keys here.".into(),
            });
            return;
        };
        // At the moment it goes: a switch turned off a moment ago writes no link
        let older: Option<(u32, Key)> = w
            .now
            .as_ref()
            .filter(|_| self.share)
            .map(|o| (o.chain, o.start.clone()));
        let holds = |id: &u64| older.is_none() || want.proof.buckets.contains(id);
        let reachable = |s: &mut Self, seats: Vec<ListedSeat>| -> Vec<ListedSeat> {
            seats
                .into_iter()
                .filter(|seat| s.static_key(&seat.account).is_some())
                .collect()
        };
        let (small, repack) = w.merges(want);
        let mut next: BTreeMap<u64, LiveBucket> = BTreeMap::new();
        // What is new in this chain: rows to send, with whether its people held the start
        let mut made: Vec<(BucketIn, bool)> = Vec::new();
        let mut kept: Vec<(u64, bool)> = Vec::new();
        let (mut merge_small, mut small_deep) = (Vec::new(), true);
        let (mut merge_pack, mut pack_deep) = (Vec::new(), true);
        let ids: Vec<u64> = w.live.keys().copied().collect();
        for id in ids {
            let deep = holds(&id);
            let Some(b) = w.live.get(&id) else { continue };
            let (version, key, digest, seats) = (b.version, b.key.clone(), b.digest, b.seats);
            let Some(list) = b.list.clone() else {
                kept.push((id, deep));
                next.insert(
                    id,
                    LiveBucket {
                        version,
                        key,
                        digest,
                        seats,
                        list: None,
                    },
                );
                continue;
            };
            let staying: Vec<ListedSeat> = list
                .iter()
                .filter(|s| !self.leaving(w, want, id, s))
                .copied()
                .collect();
            let staying = reachable(self, staying);
            self.forget_named(
                conv,
                list.iter()
                    .map(|s| s.account)
                    .filter(|a| !staying.iter().any(|s| s.account == *a)),
            );
            if small.contains(&id) {
                merge_small.extend(staying);
                small_deep &= deep;
            } else if repack.contains(&id) {
                merge_pack.extend(staying);
                pack_deep &= deep;
            } else if staying.is_empty() {
                // Nobody left to seal to
            } else if staying.len() == list.len() {
                kept.push((id, deep));
                next.insert(
                    id,
                    LiveBucket {
                        version,
                        key,
                        digest,
                        seats: list.len(),
                        list: Some(list),
                    },
                );
            } else {
                let new_version = version + 1;
                let (bucket, new_key, new_digest) =
                    self.make_bucket(conv, id, new_version, &staying, Some((version, &key)));
                made.push((bucket, deep));
                next.insert(
                    id,
                    LiveBucket {
                        version: new_version,
                        key: new_key,
                        digest: new_digest,
                        seats: staying.len(),
                        list: Some(staying),
                    },
                );
            }
        }
        // Arrivals. Whoever holds the start of the chain linked to may share a bucket with
        // others who do; a bucket with anyone else in it counts as not holding it.
        let seat_of = |s: &mut Self, a: &Id| -> Option<ListedSeat> {
            s.static_key(a)?;
            let k = s.logkey_of(a)?;
            Some(ListedSeat::new(a, &k))
        };
        let mut deep_arrivals = Vec::new();
        let mut shallow_arrivals = Vec::new();
        let mut blanks: Vec<Id> = Vec::new();
        for a in arrivals {
            let Some(seat) = seat_of(self, a) else {
                if *a != me {
                    blanks.push(*a);
                }
                continue;
            };
            if older.is_none() || want.proof.people.contains(a) {
                deep_arrivals.push(seat);
            } else {
                shallow_arrivals.push(seat);
            }
        }
        let names: Vec<Id> = deep_arrivals
            .iter()
            .chain(&shallow_arrivals)
            .map(|s| s.account)
            .collect();
        self.announce(conv, &names, false);
        if small.is_empty() {
            self.new_buckets(conv, deep_arrivals, true, &mut made, &mut next);
            self.new_buckets(conv, shallow_arrivals, false, &mut made, &mut next);
        } else {
            small_deep &= shallow_arrivals.is_empty();
            merge_small.extend(deep_arrivals);
            merge_small.extend(shallow_arrivals);
        }
        self.new_buckets(conv, merge_small, small_deep, &mut made, &mut next);
        self.new_buckets(conv, merge_pack, pack_deep, &mut made, &mut next);

        let start = epoch_key();
        let at = Chain {
            conv,
            owner: &me,
            chain,
        };
        let self_wrap = self_wrap_state(&self.logkey, &start, conv, &me, epoch0);
        // A link only if someone can use it. Without one index 0 opens that chain alone, so
        // it goes to everyone.
        let any_deep = kept.iter().any(|(_, deep)| *deep) || made.iter().any(|(_, deep)| *deep);
        let link = older
            .as_ref()
            .filter(|_| any_deep)
            .map(|(chain, older_start)| (*chain, at.link(&start, *chain, older_start)));
        let any_shallow = link.is_some()
            && (kept.iter().any(|(_, deep)| !*deep) || made.iter().any(|(_, deep)| !*deep));
        // Whoever does not hold the start of the chain it names gets index 1, in the same put:
        // nothing is ever written at index 0 of such a chain, and the link stays out of reach.
        let (index, state, step) = if any_shallow {
            let (s1, row) = at.step(0, &start);
            (1, s1, Some(row))
        } else {
            (0, start.clone(), None)
        };
        let Some(epoch) = chain_epoch(chain, index) else {
            return;
        };
        let seal_to = |id: u64, version: u32, key: &[u8; 32], deep: bool| -> ChainSeal {
            let (seal_index, sealed_state) = if index == 1 && !deep {
                (1, &*state)
            } else {
                (0, &*start)
            };
            ChainSeal {
                bucket: id,
                version,
                index: seal_index,
                sealed: Bucket {
                    conv,
                    owner: &me,
                    id,
                    version,
                }
                .seal_state(key, chain, seal_index, sealed_state),
            }
        };
        let mut seals: VecDeque<ChainSeal> = VecDeque::new();
        for (id, deep) in &kept {
            if let Some(b) = next.get(id) {
                seals.push_back(seal_to(*id, b.version, &b.key, *deep));
            }
        }
        let mut frames: Vec<(Vec<BucketIn>, Vec<ChainSeal>)> = vec![(Vec::new(), Vec::new())];
        let frame_room = |f: &(Vec<BucketIn>, Vec<ChainSeal>), adding: usize| {
            let used: usize =
                f.0.iter()
                    .map(|b| 200 + b.list.len() + b.seats.len() * 112)
                    .sum::<usize>()
                    + f.1.len() * 96;
            used + adding <= FRAME_BYTES
        };
        // While a writer has a live bucket, a frame takes a few new ones only
        let new_cap = if w.newest.is_some() {
            MAX_NEW_BUCKETS
        } else {
            usize::MAX
        };
        for (bucket, deep) in made {
            let size = 200 + bucket.list.len() + bucket.seats.len() * 112 + 96;
            let is_new = bucket.down.is_none();
            let fits = frames.last().is_some_and(|f| {
                frame_room(f, size)
                    && (!is_new || f.0.iter().filter(|b| b.down.is_none()).count() < new_cap)
            });
            if !fits {
                frames.push((Vec::new(), Vec::new()));
            }
            let Some(b) = next.get(&bucket.bucket) else {
                continue;
            };
            let seal = seal_to(bucket.bucket, b.version, &b.key, deep);
            if let Some(f) = frames.last_mut() {
                f.0.push(bucket);
                f.1.push(seal);
            }
        }
        while let Some(seal) = seals.pop_front() {
            if !frames.last().is_some_and(|f| frame_room(f, 96)) {
                frames.push((Vec::new(), Vec::new()));
            }
            if let Some(f) = frames.last_mut() {
                f.1.push(seal);
            }
        }
        let blank_rows: Vec<ChainRow> = blanks
            .iter()
            .map(|a| ChainRow {
                recipient: *a,
                index,
                wrapped: blank_row(),
            })
            .collect();
        let count = frames.len() + blank_rows.chunks(ROWS_PER_FRAME).len();
        let whole = frames
            .into_iter()
            .map(|(buckets, seals)| (buckets, seals, Vec::new()))
            .chain(
                blank_rows
                    .chunks(ROWS_PER_FRAME)
                    .map(|rows| (Vec::new(), Vec::new(), rows.to_vec())),
            );
        let mut link = link;
        let mut step = step;
        let mut first_wrap = Some(self_wrap.clone());
        for (i, (buckets, seals, wraps)) in whole.enumerate() {
            w.frames.push_back(AccountRequest::ChainPut {
                conv: conv.to_string(),
                epoch,
                self_wrap: first_wrap.take(),
                step: step.take(),
                link: link.take().filter(|_| i == 0),
                wraps,
                buckets,
                seals,
                last: i + 1 == count,
            });
        }
        let older_chain = older.map(|(chain, _)| chain).filter(|_| any_deep);
        w.done = Some(Done::Chain {
            standing: Standing {
                chain,
                index,
                state,
                start,
            },
            live: next,
            info: OwnChain {
                chain,
                top: index,
                done: true,
                self_wrap,
                older: older_chain,
            },
        });
        self.send_next_frame(conv, w, out);
    }

    /// Who joined and waits for our answer. With the switch and the right on: the start of
    /// each chain no link reaches, so one row and the links open all we kept. Otherwise a
    /// fresh step: they read from there.
    fn answer_joiners(&mut self, conv: &str, w: &mut Writer, out: &mut Vec<ClientMessage>) {
        let me = self.me;
        let Some(joiners) = self.joiners.get(conv) else {
            return;
        };
        let joiners: BTreeSet<Id> = joiners.iter().copied().collect();
        if !self.keys_in_hand(conv, &joiners, out) {
            return;
        }
        if self.share && !w.all_chains {
            let before = w.chains.keys().next().copied();
            let request = AccountRequest::OwnChains {
                conv: conv.to_string(),
                before,
            };
            out.push(self.own_ask(conv, w, "OwnChains", request));
            return;
        }
        // And what a version before chains kept under our epochs, once they are in: a read
        // marks them known as it asks for them
        let wraps_due =
            !self.wraps_known.contains(conv) || self.fetching.get(conv) == Some(&Fetch::Wraps);
        if self.share && wraps_due {
            if !self.fetching.contains_key(conv) {
                self.fetching.insert(conv.to_string(), Fetch::Wraps);
                out.push(self.ask_wraps(conv));
            }
            return;
        }
        self.joiners.remove(conv);
        if !self.share {
            if w.now.is_some() && !joiners.is_empty() {
                w.want = Some(Want {
                    arrivals: Some(joiners),
                    ..Want::default()
                });
                self.work_on_want(conv, w, out);
            }
            return;
        }
        let people: Vec<(Id, Option<Arc<StaticKey>>)> =
            joiners.iter().map(|j| (*j, self.static_key(j))).collect();
        let names: Vec<Id> = people
            .iter()
            .filter(|(_, key)| key.is_some())
            .map(|(j, _)| *j)
            .collect();
        self.announce(conv, &names, true);
        let old: Vec<(u32, Key)> = self
            .keys
            .iter()
            .filter(|((c, o, _), _)| c == conv && *o == me)
            .map(|((_, _, e), k)| (*e, k.clone()))
            .collect();
        for (epoch, key) in old {
            let wraps = self.wraps_for(&names, &key, conv, epoch);
            for chunk in wraps.chunks(WRAPS_PER_FRAME) {
                w.frames.push_back(AccountRequest::EpochPut {
                    conv: conv.to_string(),
                    epoch,
                    wraps: chunk.to_vec(),
                });
            }
        }
        let linked: BTreeSet<u32> = w.chains.values().filter_map(|c| c.older).collect();
        let tops: Vec<(u32, u32, Key)> = w
            .chains
            .values()
            .filter(|c| c.done && !linked.contains(&c.chain))
            .filter_map(|c| {
                let start = self_open_state(
                    &self.logkey,
                    &c.self_wrap,
                    conv,
                    &me,
                    chain_epoch(c.chain, 0)?,
                )
                .ok()?;
                Some((c.chain, c.top, start))
            })
            .collect();
        // The blanks go once, in a frame that ends the answer: all they are for is to end
        // the wait of someone who can read none of this. Keys of nothing still end it.
        let fallback: Option<(u32, u32)> = w
            .chains
            .values()
            .rfind(|c| c.done)
            .map(|c| (c.chain, c.top))
            .filter(|_| tops.is_empty());
        for chunk in people.chunks(ROWS_PER_FRAME) {
            for (i, (chain, top, start)) in tops.iter().enumerate() {
                let (Some(at_top), Some(at_start)) =
                    (chain_epoch(*chain, *top), chain_epoch(*chain, 0))
                else {
                    continue;
                };
                let last = i + 1 == tops.len();
                let wraps: Vec<ChainRow> = chunk
                    .iter()
                    .filter_map(|(j, key)| match key {
                        Some(key) => Some(ChainRow {
                            recipient: *j,
                            index: 0,
                            wrapped: key.wrap_state(start, conv, &me, at_start, j),
                        }),
                        None => last.then(|| ChainRow {
                            recipient: *j,
                            index: *top,
                            wrapped: blank_row(),
                        }),
                    })
                    .collect();
                if !wraps.is_empty() {
                    w.frames.push_back(rows_frame(conv, at_top, wraps, last));
                }
            }
            if let Some((chain, top)) = fallback {
                if let Some(at_top) = chain_epoch(chain, top) {
                    let wraps = chunk
                        .iter()
                        .map(|(j, _)| ChainRow {
                            recipient: *j,
                            index: top,
                            wrapped: blank_row(),
                        })
                        .collect();
                    w.frames.push_back(rows_frame(conv, at_top, wraps, true));
                }
            }
        }
        if !w.frames.is_empty() {
            w.done = Some(Done::Rows {
                joiners: joiners.into_iter().collect(),
            });
            self.send_next_frame(conv, w, out);
        }
    }

    /// A post, sealed under the chain's state, if it can go now.
    pub(super) fn seal_on_chain(&mut self, o: &Outgoing) -> Option<(u32, Vec<u8>)> {
        let w = self.writers.get(&o.conv)?;
        if !w.ready() {
            return None;
        }
        let now = w.now.as_ref()?;
        let epoch = chain_epoch(now.chain, now.index)?;
        let ct = seal_chain_entry(
            &now.state,
            &o.conv,
            &self.me,
            epoch,
            &self.logkey,
            &o.envelope,
            o.sent_at,
        );
        Some((epoch, ct))
    }

    /// Counts a round that got nothing through; past `MAX_REKEYS`, what waits is given up on.
    pub(super) fn round(&mut self, conv: &str, events: &mut Vec<Event>) {
        let n = self.rekeys.entry(conv.to_string()).or_insert(0);
        *n += 1;
        if *n > MAX_REKEYS {
            self.give_up(conv, events);
        }
    }

    fn give_up(&mut self, conv: &str, events: &mut Vec<Event>) {
        self.rekeys.remove(conv);
        self.joiners.remove(conv);
        if let Some(w) = self.writers.get_mut(conv) {
            w.want = None;
        }
        if self.outbox.iter().any(|o| o.conv == conv) {
            self.outbox.retain(|o| o.conv != conv);
            events.push(Event::NotKept {
                reason: "the people this channel keeps messages for could not all be reached"
                    .into(),
            });
        }
    }

    /// Someone may have a new log key: asked afresh, so the row goes to that one, not the old.
    fn forget_keys(&mut self, accounts: &BTreeSet<Id>) {
        for a in accounts {
            self.peers.remove(a);
            self.asked_keys.remove(a);
            self.distrusted.remove(a);
        }
    }

    /// `ChainRekey`, in answer to a post or a frame.
    pub(super) fn on_chain_rekey(
        &mut self,
        conv: &str,
        new_chain: bool,
        missing: &[Id],
        gone: &[(Id, u64)],
        events: &mut Vec<Event>,
    ) {
        let mut w = self.writers.remove(conv).unwrap_or_default();
        let posted = self.in_flight.iter().position(|(c, ..)| c == conv);
        // Answering nothing of ours: a relay does not get to start a chain unasked
        if posted.is_none() && w.out != Some("ChainPut") {
            self.own_answered(conv, "ChainPut", &mut w);
            self.writers.insert(conv.to_string(), w);
            return;
        }
        if let Some(at) = posted {
            self.append_idle = 0;
            if let Some((_, _, Some(o))) = self.in_flight.remove(at) {
                // In the order they were written.
                let at = self
                    .outbox
                    .iter()
                    .position(|x| x.sent_at > o.sent_at)
                    .unwrap_or(self.outbox.len());
                self.outbox.insert(at, o);
            }
        } else {
            self.own_answered(conv, "ChainPut", &mut w);
        }
        let rekey = w.rekey.get_or_insert_with(Rekey::default);
        rekey.new_chain |= new_chain;
        rekey.missing.extend(missing.iter().copied());
        rekey.gone.extend(gone.iter().copied());
        // The rest of what went under this key come back one by one; a chain being made
        // answers it anyway
        let settled = !self.in_flight.iter().any(|(c, ..)| c == conv);
        if posted.is_none() || (settled && w.frames.is_empty()) {
            if posted.is_none() {
                // What was stored of the frames before this one is not what we took it for
                if let Some(Done::Rows { joiners }) = w.done.take() {
                    self.joiners
                        .entry(conv.to_string())
                        .or_default()
                        .extend(joiners);
                }
                w.read_again();
            }
            if let Some(r) = w.rekey.take() {
                self.writers.insert(conv.to_string(), w);
                self.apply_rekey(conv, r, events);
                return;
            }
        }
        self.writers.insert(conv.to_string(), w);
    }

    /// Out of what this device has named: if they come back, they are named again.
    fn forget_named(&mut self, conv: &str, gone: impl IntoIterator<Item = Id>) {
        if let Some(seen) = self.readers.get_mut(conv) {
            for a in gone {
                self.named_changed |= seen.remove(&a);
            }
        }
    }

    /// A refusal waited for the rest of what went under its key: that has come now, however
    /// it came. Whether it went on.
    pub(super) fn settle_rekey(&mut self, conv: &str, events: &mut Vec<Event>) -> bool {
        if self.in_flight.iter().any(|(c, ..)| c == conv) {
            return false;
        }
        let Some(w) = self.writers.get_mut(conv).filter(|w| w.frames.is_empty()) else {
            return false;
        };
        let Some(r) = w.rekey.take() else {
            return false;
        };
        self.apply_rekey(conv, r, events);
        true
    }

    fn apply_rekey(&mut self, conv: &str, r: Rekey, events: &mut Vec<Event>) {
        self.forget_keys(&r.missing);
        self.forget_named(conv, r.gone.iter().map(|(a, _)| *a));
        let new_chain = r.new_chain;
        let stuck = {
            let Some(w) = self.writers.get_mut(conv) else {
                return;
            };
            if new_chain {
                let whole = r.missing.len() < MAX_ARRIVALS && r.gone.len() < MAX_GONE;
                let arrivals = whole.then_some(r.missing.clone());
                w.want = Some(Want {
                    new_chain: true,
                    arrivals,
                    gone: r.gone,
                    ..Want::default()
                });
                true
            } else if !r.missing.is_empty() {
                // Only the same people again is no progress: a stream of new ones is
                let same = w.last_missing == r.missing;
                w.last_missing = r.missing.clone();
                w.want = Some(Want {
                    arrivals: Some(r.missing),
                    ..Want::default()
                });
                same
            } else {
                w.read_again();
                true
            }
        };
        if stuck {
            self.round(conv, events);
        }
    }

    /// `ChainStored`: the next frame, or what they all came to.
    pub(super) fn on_chain_stored(
        &mut self,
        conv: &str,
        behind: bool,
        what: &str,
        out: &mut Vec<ClientMessage>,
        events: &mut Vec<Event>,
    ) {
        let mut w = self.writers.remove(conv).unwrap_or_default();
        let ours = w.out == Some(what);
        self.own_answered(conv, what, &mut w);
        if !ours {
            self.writers.insert(conv.to_string(), w);
            return;
        }
        if behind {
            if let Some(Done::Rows { joiners }) = w.done.take() {
                self.joiners
                    .entry(conv.to_string())
                    .or_default()
                    .extend(joiners);
            }
            // What was wanted came of what we no longer take for true: the next refusal
            // says afresh. A relay that says this for ever gets nothing more than rounds.
            w.want = None;
            w.read_again();
            w.behinds += 1;
            let many = w.behinds > MAX_BEHINDS;
            if many {
                w.behinds = 0;
            }
            self.writers.insert(conv.to_string(), w);
            if many {
                self.give_up(conv, events);
            }
            return;
        }
        w.frames.pop_front();
        w.behinds = 0;
        if !w.frames.is_empty() {
            self.send_next_frame(conv, &mut w, out);
            self.writers.insert(conv.to_string(), w);
            return;
        }
        match w.done.take() {
            Some(Done::Chain {
                standing,
                live,
                info,
            }) => {
                let held = self
                    .holds
                    .entry(conv.to_string())
                    .or_default()
                    .chains
                    .entry((self.me, standing.chain))
                    .or_default();
                held.states.insert(0, standing.start.clone());
                held.states.insert(standing.index, standing.state.clone());
                let named = self.named.entry(conv.to_string()).or_default();
                named.clear();
                named.extend(live.values().map(|b| b.digest));
                self.memory_changed = true;
                self.named_changed = true;
                w.newest = Some(standing.chain);
                w.chains.insert(standing.chain, info);
                w.now = Some(standing);
                w.live = live;
                w.ended = false;
                w.gone_seen.clear();
            }
            Some(Done::Step { index, state }) => {
                if let Some(now) = w.now.as_mut() {
                    now.index = index;
                    now.state = state;
                    let (chain, state) = (now.chain, now.state.clone());
                    if let Some(c) = w.chains.get_mut(&chain) {
                        c.top = index;
                    }
                    self.holds
                        .entry(conv.to_string())
                        .or_default()
                        .chains
                        .entry((self.me, chain))
                        .or_default()
                        .states
                        .insert(index, state);
                }
            }
            Some(Done::Rows { .. }) => {
                self.rekeys.remove(conv);
            }
            None => {}
        }
        // A refusal from before what just went through says nothing about it
        w.rekey = None;
        self.writers.insert(conv.to_string(), w);
    }

    pub(super) fn on_own_chains(
        &mut self,
        conv: &str,
        newest: Option<u32>,
        chains: &[OwnChain],
        more: bool,
    ) {
        let mut w = self.writers.remove(conv).unwrap_or_default();
        self.own_answered(conv, "OwnChains", &mut w);
        w.newest = newest;
        let lowest = w.chains.keys().next().copied();
        w.chains.extend(chains.iter().map(|c| (c.chain, c.clone())));
        w.chains_read = true;
        // Each of these pages goes on only past the last: a page that does not is the end
        w.all_chains = !more || w.chains.keys().next().copied() == lowest;
        self.writers.insert(conv.to_string(), w);
    }

    /// Our buckets as they stand. Only one the newest chain is sealed to is one to go on
    /// with: the rest were merged away, or came of a chain never finished. A row that does
    /// not open, a dead one or one the relay moved here from another channel, is a bucket
    /// lost: nobody is sealed to on its strength.
    pub(super) fn on_own_buckets(&mut self, conv: &str, buckets: &[OwnBucket], more: bool) {
        let me = self.me;
        let mut w = self.writers.remove(conv).unwrap_or_default();
        self.own_answered(conv, "OwnBuckets", &mut w);
        for b in buckets.iter().filter(|b| b.sealed) {
            let at = Bucket {
                conv,
                owner: &me,
                id: b.bucket,
                version: b.version,
            };
            match at.open_own_row(&self.logkey, &b.own_row) {
                Ok((key, digest)) => {
                    w.live.insert(
                        b.bucket,
                        LiveBucket {
                            version: b.version,
                            key,
                            digest,
                            seats: b.seats as usize,
                            list: None,
                        },
                    );
                }
                Err(_) => w.lost = true,
            }
        }
        let last = buckets.last().map(|b| b.bucket);
        w.buckets_read = !more || last <= w.buckets_after;
        w.buckets_after = last;
        self.writers.insert(conv.to_string(), w);
    }

    /// The lists asked for. One absent, or not the one our own row names, is a bucket lost.
    pub(super) fn on_bucket_lists(&mut self, conv: &str, lists: &[(u64, u32, Vec<u8>)]) {
        let me = self.me;
        let mut w = self.writers.remove(conv).unwrap_or_default();
        self.own_answered(conv, "BucketLists", &mut w);
        for (id, version) in self.lists_asked.remove(conv).unwrap_or_default() {
            let sealed = lists
                .iter()
                .find(|(b, v, _)| *b == id && *v == version)
                .map(|(_, _, s)| s);
            let opened = w.live.get(&id).and_then(|b| {
                let at = Bucket {
                    conv,
                    owner: &me,
                    id,
                    version,
                };
                at.open_list(&self.logkey, sealed?, &b.digest).ok()
            });
            match opened {
                Some(list) => {
                    if let Some(b) = w.live.get_mut(&id) {
                        b.seats = list.len();
                        b.list = Some(list);
                    }
                }
                None => {
                    w.live.remove(&id);
                    w.lost = true;
                    if let Some(want) = w.want.as_mut() {
                        want.arrivals = None;
                    }
                }
            }
        }
        self.writers.insert(conv.to_string(), w);
    }

    pub(super) fn on_member_ids(&mut self, conv: &str, ids: &[Id], more: bool) {
        let mut w = self.writers.remove(conv).unwrap_or_default();
        self.own_answered(conv, "LogMemberIds", &mut w);
        let mut too_many = false;
        if let Some(want) = w.want.as_mut() {
            want.ids.extend(ids.iter().copied());
            let last = ids.last().copied();
            want.ids_done = !more || last <= want.ids_after;
            want.ids_after = last;
            too_many = want.ids.len() > MOST_READERS;
        }
        self.writers.insert(conv.to_string(), w);
        if too_many {
            self.writer_refused(conv, "LogMemberIds");
            self.later.push(Event::NotKept {
                reason: "This channel has more readers than an app can keep track of.".into(),
            });
        }
    }

    /// Who held the start of the chain a new one will link to, on the writer's own proof: a
    /// bucket whose seal there opens at index 0, down its links, to the start this device
    /// holds. So never the relay's index, and what it leaves out fails to not index 0.
    pub(super) fn on_own_rows(
        &mut self,
        conv: &str,
        chain: u32,
        seals: &[ChainSeal],
        direct: &[ChainRow],
        links: &[(u64, u32, u32, Vec<u8>)],
        more: bool,
    ) {
        let me = self.me;
        let mut w = self.writers.remove(conv).unwrap_or_default();
        self.own_answered(conv, "OwnChainRows", &mut w);
        let start = w
            .now
            .as_ref()
            .filter(|n| n.chain == chain)
            .map(|n| n.start.clone());
        let mut buckets = Vec::new();
        let mut people = Vec::new();
        if let Some(start) = &start {
            for s in seals.iter().filter(|s| s.index == 0) {
                let Some(b) = w.live.get(&s.bucket) else {
                    continue;
                };
                let (mut key, mut version) = (b.key.clone(), b.version);
                while version > s.version {
                    let Some((_, _, old, link)) = links
                        .iter()
                        .find(|(id, new, ..)| *id == s.bucket && *new == version)
                    else {
                        break;
                    };
                    let at = Bucket {
                        conv,
                        owner: &me,
                        id: s.bucket,
                        version,
                    };
                    let Ok(k) = at.open_link_down(&key, *old, link) else {
                        break;
                    };
                    key = k;
                    version = *old;
                }
                let at = Bucket {
                    conv,
                    owner: &me,
                    id: s.bucket,
                    version,
                };
                if version == s.version && at.seal_holds_start(&key, chain, &s.sealed, start) {
                    buckets.push(s.bucket);
                }
            }
            for r in direct.iter().filter(|r| r.index == 0) {
                let Some(sk) = self.static_key(&r.recipient) else {
                    continue;
                };
                if sk.row_holds_start(&r.wrapped, conv, &me, chain, &r.recipient, start) {
                    people.push(r.recipient);
                }
            }
        }
        if let Some(want) = w.want.as_mut() {
            want.proof.buckets.extend(buckets);
            want.proof.people.extend(people);
            let last = direct.last().map(|r| r.recipient);
            want.proof_done = !more || last <= want.proof_after;
            want.proof_after = last;
        }
        self.writers.insert(conv.to_string(), w);
    }

    /// A writer's ask was refused for now: it goes again at the next tick.
    pub(super) fn writer_held(&mut self, conv: &str, what: &str) {
        let mut w = self.writers.remove(conv).unwrap_or_default();
        self.own_answered(conv, what, &mut w);
        self.writers.insert(conv.to_string(), w);
    }

    /// What is waiting on log keys, now some came.
    pub(super) fn advance_waiting(&mut self) -> Vec<ClientMessage> {
        let due: Vec<String> = self
            .writers
            .iter()
            .filter(|(_, w)| w.out.is_none() && w.want.is_some())
            .map(|(conv, _)| conv.clone())
            .collect();
        due.iter().flat_map(|conv| self.advance(conv)).collect()
    }

    /// `conv`'s writer was refused, not for now: it starts over at the next post.
    pub(super) fn writer_refused(&mut self, conv: &str, what: &str) {
        let mut w = self.writers.remove(conv).unwrap_or_default();
        self.own_answered(conv, what, &mut w);
        w.want = None;
        w.rekey = None;
        w.read_again();
        self.writers.insert(conv.to_string(), w);
        self.outbox.retain(|o| o.conv != conv);
        self.joiners.remove(conv);
        self.rekeys.remove(conv);
    }

    /// Told someone is gone from this channel, or out of it ourselves. Whatever the relay
    /// says, this chain ends at the next post, and a list is named again before anything is
    /// sealed to it: a person the relay later seats again without a word is named that way.
    pub(super) fn end_chain(&mut self, conv: &str, account: Option<Id>) {
        if let Some(a) = account {
            if let Some(seen) = self.readers.get_mut(conv) {
                seen.remove(&a);
            }
        }
        self.named.remove(conv);
        self.memory_changed = true;
        self.named_changed = true;
        let w = self.writers.entry(conv.to_string()).or_default();
        w.ended = true;
        w.gone_seen.extend(account);
        // A chain being put together right now goes through with that person in it
        if w.out == Some("ChainPut") || !w.frames.is_empty() {
            // And the rest of an answer goes round again, or they wait for good
            if let Some(Done::Rows { joiners }) = w.done.take() {
                self.joiners
                    .entry(conv.to_string())
                    .or_default()
                    .extend(joiners);
            }
            w.frames.clear();
            w.read_again();
        }
    }

    /// Someone who was in a channel's list is gone from it (`MemberGone`). Out of any answer
    /// to joiners; and a chain ends here only if this device could have reached them, since
    /// a new chain costs from a budget of 60 an hour. Someone only another device of ours
    /// reached ends it by the relay's `ChainRekey`, which this device cannot tell from a
    /// relay hiding the leave anyway.
    pub(super) fn someone_left(&mut self, conv: &str, account: &Id) {
        if let Some(waiting) = self.joiners.get_mut(conv) {
            waiting.remove(account);
        }
        let w = self.writers.get_mut(conv);
        let listed = w.as_ref().is_some_and(|w| {
            w.live
                .values()
                .any(|b| b.list.iter().flatten().any(|s| s.account == *account))
        });
        if let Some(Done::Rows { joiners }) = w.and_then(|w| w.done.as_mut()) {
            joiners.retain(|j| j != account);
        }
        if listed || self.readers.get(conv).is_some_and(|r| r.contains(account)) {
            self.end_chain(conv, Some(*account));
        }
    }

    /// Our chains and buckets here are gone: the next post starts afresh, with no link.
    pub(super) fn purged(&mut self, conv: Option<&str>) {
        match conv {
            Some(c) => {
                self.writers.remove(c);
                self.named.remove(c);
            }
            None => {
                self.writers.clear();
                self.named.clear();
            }
        }
        self.memory_changed = true;
        self.named_changed = true;
    }

    /// Every couple of seconds: an answer that never came means reading back again, and what
    /// was refused for now goes on.
    pub(super) fn tick_writers(&mut self) -> Vec<ClientMessage> {
        let mut lost = Vec::new();
        for (conv, w) in &mut self.writers {
            if w.out.is_some() {
                w.idle += 1;
                if w.idle >= LOST_AFTER_TICKS {
                    if let Some(Done::Rows { joiners }) = w.done.take() {
                        self.joiners
                            .entry(conv.clone())
                            .or_default()
                            .extend(joiners);
                    }
                    w.read_again();
                    lost.push(conv.clone());
                }
            }
        }
        for conv in lost {
            self.writer_asks.retain(|(_, c)| *c != conv);
            self.wraps_asked.retain(|a| !(a.writer && a.conv == conv));
        }
        let waiting: Vec<String> = self
            .writers
            .iter()
            .filter(|(_, w)| w.rekey.is_some())
            .map(|(conv, _)| conv.clone())
            .collect();
        let mut events = Vec::new();
        for conv in waiting {
            self.settle_rekey(&conv, &mut events);
        }
        self.later.extend(events);
        let due: Vec<String> = self
            .writers
            .iter()
            .filter(|(conv, w)| {
                w.want.is_some()
                    || !w.frames.is_empty()
                    || self.outbox.iter().any(|o| o.conv == **conv)
                    || self.joiners.contains_key(*conv)
            })
            .map(|(conv, _)| conv.clone())
            .collect();
        let mut out = Vec::new();
        for conv in due {
            out.extend(self.advance(&conv));
        }
        out.extend(self.join_many_due());
        out
    }

    // ── Seating ───────────────────────────────────────────────────────────

    /// Channels newly followed, in one frame: a seat in each of their logs, if there is room
    /// for a silent follow. What it could not seat comes back in `refused`.
    pub(super) fn enter_many_on_chains(&mut self, convs: &[String]) -> Vec<ClientMessage> {
        let mut out = Vec::new();
        let mut new = Vec::new();
        for conv in convs.iter().filter(|c| c.starts_with("c:")) {
            if self.joined.insert(conv.clone()) {
                new.push(conv.clone());
            } else {
                out.extend(self.fetch(conv));
            }
        }
        for chunk in new.chunks(MAX_JOIN_MANY) {
            self.join_many_asks.push_back(chunk.to_vec());
            out.push(ask(AccountRequest::LogJoinMany {
                convs: chunk.to_vec(),
            }));
        }
        out
    }

    fn join_many_due(&mut self) -> Vec<ClientMessage> {
        let due = std::mem::take(&mut self.join_many_due);
        let mut out = Vec::new();
        for chunk in due.chunks(MAX_JOIN_MANY) {
            self.join_many_asks.push_back(chunk.to_vec());
            out.push(ask(AccountRequest::LogJoinMany {
                convs: chunk.to_vec(),
            }));
        }
        out
    }

    pub(super) fn on_joined_many(
        &mut self,
        joined: &[String],
        refused: &[String],
    ) -> Vec<ClientMessage> {
        let answered: BTreeSet<&String> = joined.iter().chain(refused).collect();
        if let Some(at) = self
            .join_many_asks
            .iter()
            .position(|a| a.iter().any(|c| answered.contains(c)))
        {
            self.join_many_asks.remove(at);
        }
        let mut out = Vec::new();
        for conv in refused {
            self.joined.remove(conv);
            // Following stops at half a log's seats, and a post is the other way to one
            if self.outbox.iter().any(|o| o.conv == *conv) {
                self.joined.insert(conv.clone());
                out.push(self.ask_join(conv));
            }
        }
        for conv in joined {
            if self.joined.contains(conv) {
                out.extend(self.fetch(conv));
            }
        }
        out
    }

    /// `LogJoinMany` was refused. Slowed down, it goes again at the next tick; otherwise this
    /// relay keeps nothing, and nobody asked for it.
    pub(super) fn join_many_refused(&mut self, for_now: bool, reason: &str) {
        let convs = self.join_many_asks.pop_front().unwrap_or_default();
        if for_now {
            self.held = true;
            self.join_many_due.extend(convs);
        } else {
            for conv in convs {
                self.joined.remove(&conv);
                if self.outbox.iter().any(|o| o.conv == conv) {
                    self.outbox.retain(|o| o.conv != conv);
                    self.copy_refused = true;
                    self.later.push(Event::NotKept {
                        reason: reason.to_string(),
                    });
                }
            }
        }
    }

    // ── A reader ──────────────────────────────────────────────────────────

    fn held_mut(&mut self, conv: &str, owner: Id, chain: u32) -> &mut Held {
        self.holds
            .entry(conv.to_string())
            .or_default()
            .chains
            .entry((owner, chain))
            .or_default()
    }

    /// Opens what came for this chain, now an entry needs it. Only the static shape opens:
    /// a relay can make an ECIES wrap to our key, and must not get to choose a state we adopt.
    fn open_rows(&mut self, conv: &str, owner: Id, chain: u32) {
        let me = self.me;
        let held = self.held_mut(conv, owner, chain);
        let rows = std::mem::take(&mut held.rows);
        for k in rows {
            let mut opened: Vec<(u32, Key)> = Vec::new();
            if owner == me {
                if let (Some(row), Some(epoch)) = (&k.self_wrap, chain_epoch(chain, 0)) {
                    if let Ok(s) = self_open_state(&self.logkey, row, conv, &me, epoch) {
                        opened.push((0, s));
                    }
                }
            } else {
                if let (Some((i, row)), Some(sk)) = (&k.direct, self.static_key(&owner)) {
                    if let Some(epoch) = chain_epoch(chain, *i) {
                        if let Ok(s) = sk.open_state(row, conv, &owner, epoch, &me) {
                            opened.push((*i, s));
                        }
                    }
                }
                if let Some(seal) = &k.seal {
                    if let Some(key) = self.seat_key(conv, owner, &k) {
                        let at = Bucket {
                            conv,
                            owner: &owner,
                            id: seal.bucket,
                            version: seal.version,
                        };
                        if let Ok(s) = at.open_seal(&key, chain, seal.index, &seal.sealed) {
                            opened.push((seal.index, s));
                        }
                    }
                }
            }
            self.held_mut(conv, owner, chain).states.extend(opened);
        }
    }

    /// The bucket key a seal is under, from our seat and down the version links.
    fn seat_key(&mut self, conv: &str, owner: Id, k: &ChainKeys) -> Option<Key> {
        let me = self.me;
        let seal = k.seal.as_ref()?;
        let id = seal.bucket;
        let cached = |s: &mut Self, version: u32| {
            s.holds
                .entry(conv.to_string())
                .or_default()
                .bucket_keys
                .get(&(owner, id, version))
                .cloned()
        };
        if let Some(key) = cached(self, seal.version) {
            return Some(key);
        }
        let (seat_version, row) = k.seat.as_ref()?;
        let at = |version: u32| Bucket {
            conv,
            owner: &owner,
            id,
            version,
        };
        let mut key = match cached(self, *seat_version) {
            Some(key) => key,
            None => self
                .static_key(&owner)?
                .open_seat(row, at(*seat_version), &me)
                .ok()?,
        };
        let mut version = *seat_version;
        let holds = self.holds.entry(conv.to_string()).or_default();
        holds.bucket_keys.insert((owner, id, version), key.clone());
        for (new, old, link) in &k.down {
            if version == seal.version {
                break;
            }
            if *new != version || *old >= *new {
                continue;
            }
            key = at(*new).open_link_down(&key, *old, link).ok()?;
            version = *old;
            holds.bucket_keys.insert((owner, id, version), key.clone());
        }
        (version == seal.version).then_some(key)
    }

    /// Down a run of links to `chain`, from the nearest chain above whose start we hold.
    fn down_links(&mut self, conv: &str, owner: Id, chain: u32) {
        let mut path = vec![chain];
        let mut at = chain;
        loop {
            let up = self
                .holds
                .get(conv)
                .and_then(|h| h.above.get(&(owner, at)))
                .copied();
            let Some(up) = up else {
                return;
            };
            self.open_rows(conv, owner, up);
            path.push(up);
            if self.held_mut(conv, owner, up).states.contains_key(&0) {
                break;
            }
            at = up;
        }
        for i in (0..path.len() - 1).rev() {
            let (lower, upper) = (path[i], path[i + 1]);
            let held = self.held_mut(conv, owner, upper);
            let (Some(state), Some((older, row))) =
                (held.states.get(&0).cloned(), held.link.clone())
            else {
                return;
            };
            if older != lower {
                return;
            }
            let walker = Chain {
                conv,
                owner: &owner,
                chain: upper,
            };
            let Ok(start) = walker.open_link(&state, lower, &row) else {
                return;
            };
            self.held_mut(conv, owner, lower).states.insert(0, start);
        }
    }

    /// The state of `owner`'s `chain` at `index`, walking up from the nearest one held.
    fn state_at(&mut self, conv: &str, owner: Id, chain: u32, index: u32) -> Option<Key> {
        self.open_rows(conv, owner, chain);
        if self
            .held_mut(conv, owner, chain)
            .states
            .range(..=index)
            .next()
            .is_none()
        {
            self.down_links(conv, owner, chain);
        }
        let held = self.held_mut(conv, owner, chain);
        let (from, state) = held.states.range(..=index).next_back()?;
        let (mut at, mut state) = (*from, state.clone());
        let walker = Chain {
            conv,
            owner: &owner,
            chain,
        };
        while at < index {
            let row = held.steps.get(&at)?;
            state = walker.follow(at, &state, row).ok()?;
            at += 1;
            held.states.insert(at, state.clone());
        }
        Some(state)
    }

    fn need(&mut self, conv: &str, owner: Id, chain: u32, index: u32) -> Need {
        if self.state_at(conv, owner, chain, index).is_some() {
            return Need::Have;
        }
        let holds = self.holds.entry(conv.to_string()).or_default();
        if let Some((next, hops)) = holds.walks.get(&(owner, chain)).copied() {
            return if hops < MAX_WALK {
                Need::Ask(ChainAsk {
                    owner,
                    chain: next,
                    from: Some(0),
                })
            } else {
                Need::No
            };
        }
        let held = holds.chains.entry((owner, chain)).or_default();
        if let Some((at, _)) = held.states.range(..=index).next_back() {
            return if held.asked == 0 || index > held.asked_to {
                Need::Ask(ChainAsk {
                    owner,
                    chain,
                    from: Some(*at),
                })
            } else {
                Need::No
            };
        }
        if held.asked < 2 {
            Need::Ask(ChainAsk {
                owner,
                chain,
                from: None,
            })
        } else {
            Need::No
        }
    }

    /// A `ChainPage` is in: the writers' log keys first, then what opens its chains, then
    /// the entries, then the next page. Each ask's answer comes back here.
    pub(super) fn chain_read(&mut self, conv: &str) -> Vec<ClientMessage> {
        let me = self.me;
        let mut out = Vec::new();
        let entries: Vec<(Id, u32)> = self
            .waiting
            .iter()
            .filter(|(c, _)| c == conv)
            .map(|(_, e)| (e.sender, e.epoch))
            .collect();
        let writers: BTreeSet<Id> = entries
            .iter()
            .map(|(s, _)| *s)
            .filter(|s| *s != me)
            .collect();
        if !self.keys_in_hand(conv, &writers, &mut out) {
            self.fetching.insert(conv.to_string(), Fetch::Keys);
            return out;
        }
        let mut asks: BTreeMap<(Id, u32), (ChainAsk, u32, u32)> = BTreeMap::new();
        let mut nothing = false;
        for (owner, epoch) in entries {
            if self.distrusted.contains(&owner)
                || self.keys.contains_key(&(conv.to_string(), owner, epoch))
            {
                continue;
            }
            let (chain, index) = epoch_parts(epoch);
            match self.need(conv, owner, chain, index) {
                Need::Ask(a) => {
                    if asks.len() < MAX_CHAIN_ASKS || asks.contains_key(&(owner, a.chain)) {
                        let e = asks.entry((owner, a.chain)).or_insert((a, chain, index));
                        e.2 = e.2.max(index);
                    }
                }
                Need::No => nothing = true,
                Need::Have => {}
            }
        }
        if !asks.is_empty() {
            self.fetching.insert(conv.to_string(), Fetch::Wraps);
            let asks: Vec<(ChainAsk, u32, u32)> = asks.into_values().collect();
            self.fetch_asks.push_back(conv.to_string());
            let request = AccountRequest::WrapsPage {
                conv: conv.to_string(),
                asks: asks.iter().map(|(a, ..)| a.clone()).collect(),
            };
            self.wraps_asked.push_back(WrapsAsked {
                conv: conv.to_string(),
                asks,
                writer: false,
            });
            out.push(ask(request));
            return out;
        }
        // Nothing on chains opens it: a key of a version before chains may, once a read
        if nothing && self.wraps_known.insert(conv.to_string()) {
            self.fetching.insert(conv.to_string(), Fetch::Wraps);
            out.push(self.ask_wraps(conv));
            return out;
        }
        self.fetching.insert(conv.to_string(), Fetch::Entries);
        let mut events = Vec::new();
        self.drain(&mut out, &mut events);
        self.later.extend(events);
        let after = self.fetched.get(conv).copied().unwrap_or(0);
        let more = self.page_more.remove(conv).unwrap_or(false);
        if more && self.target.contains(conv) {
            self.fetching.insert(conv.to_string(), Fetch::Entries);
            out.push(self.ask_page(conv, after));
        } else {
            self.target.remove(conv);
            if self.unopened.remove(conv).is_some() {
                self.later.push(Event::Unopened {
                    conv: conv.to_string(),
                });
            }
            out.extend(self.fetch_done(conv));
        }
        out
    }

    /// One `ChainPage`.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn on_chain_page(
        &mut self,
        conv: &str,
        entries: &[LogEntry],
        more: bool,
        owed: &[Id],
        skipped: u32,
        upto: i64,
        floor: i64,
        window: u32,
    ) -> Vec<ClientMessage> {
        self.answered(conv);
        self.owed
            .insert(conv.to_string(), owed.iter().copied().collect());
        for e in entries {
            let key = (conv.to_string(), e.seq);
            if !self.opened.contains(&key)
                && !self
                    .waiting
                    .iter()
                    .any(|(c, w)| c == conv && w.seq == e.seq)
            {
                self.waiting.push((conv.to_string(), e.clone()));
            }
        }
        add_unopened(&mut self.unopened, conv, skipped);
        // Cut down to the window: said once, if it passed over this device's own place
        if self
            .cursors
            .get(conv)
            .is_some_and(|c| *c > 0 && floor > c.saturating_add(1))
        {
            self.later.push(Event::Clamped {
                conv: conv.to_string(),
                window,
            });
        }
        let f = self.fetched.entry(conv.to_string()).or_insert(0);
        *f = (*f).max(upto);
        // A page that moves on nothing is a relay going round in circles
        let after = self.page_after.get(conv).copied().unwrap_or(i64::MIN);
        self.page_more
            .insert(conv.to_string(), more && upto > after);
        self.chain_read(conv)
    }

    /// One `WrapsPage`: the rows and steps go where they will be wanted, unopened. A writer
    /// we do not trust has its rows dropped here rather than retried at every entry.
    pub(super) fn on_wraps_page(
        &mut self,
        conv: &str,
        keys: &[ChainKeys],
        served: u32,
    ) -> Vec<ClientMessage> {
        let asked = self
            .wraps_asked
            .iter()
            .position(|a| a.conv == conv)
            .and_then(|at| self.wraps_asked.remove(at));
        let Some(asked) = asked else {
            return Vec::new();
        };
        let holds = self.holds.entry(conv.to_string()).or_default();
        for k in keys.iter().filter(|k| !self.distrusted.contains(&k.owner)) {
            let held = holds.chains.entry((k.owner, k.chain)).or_default();
            if let Some((older, row)) = &k.link {
                if *older < k.chain {
                    held.link = Some((*older, row.clone()));
                    holds.above.insert((k.owner, *older), k.chain);
                }
            }
            let held = holds.chains.entry((k.owner, k.chain)).or_default();
            held.steps
                .extend(k.steps.iter().map(|(i, s)| (*i, s.clone())));
            held.rows.push(ChainKeys {
                link: None,
                steps: Vec::new(),
                ..k.clone()
            });
        }
        // At least the first, or a relay answering nothing has us asking for ever
        for (ask, on, index) in asked.asks.iter().take((served as usize).max(1)) {
            let held = holds.chains.entry((ask.owner, ask.chain)).or_default();
            held.asked = held.asked.saturating_add(1);
            held.asked_to = held.asked_to.max(*index);
            let came = keys
                .iter()
                .any(|k| k.owner == ask.owner && k.chain == ask.chain);
            if ask.chain == *on && came {
                holds.walks.remove(&(ask.owner, *on));
                continue;
            }
            // A run too long for one answer stopped short of this chain: it goes on from
            // the last link it brought, past any links already held
            let from = if came {
                holds
                    .chains
                    .get(&(ask.owner, ask.chain))
                    .and_then(|h| h.link.as_ref())
                    .map(|(older, _)| *older)
            } else {
                keys.iter()
                    .rev()
                    .find(|k| k.owner == ask.owner)
                    .and_then(|k| k.link.as_ref())
                    .map(|(older, _)| *older)
            };
            let next = from.map(|mut n| {
                while n > *on {
                    let link = holds
                        .chains
                        .get(&(ask.owner, n))
                        .and_then(|h| h.link.as_ref());
                    match link {
                        Some((older, _)) => n = *older,
                        None => break,
                    }
                }
                n
            });
            let hops = holds.walks.get(&(ask.owner, *on)).map_or(0, |(_, h)| *h);
            match next.filter(|n| *n >= *on) {
                Some(n) => {
                    holds.walks.insert((ask.owner, *on), (n, hops + 1));
                }
                None => {
                    holds.walks.remove(&(ask.owner, *on));
                }
            }
        }
        if asked.writer {
            let mut w = self.writers.remove(conv).unwrap_or_default();
            self.own_answered(conv, "WrapsPage", &mut w);
            self.writers.insert(conv.to_string(), w);
            return Vec::new();
        }
        self.answered(conv);
        self.chain_read(conv)
    }

    /// An entry on a chain, opened if it can be. `None` in `Ok`: not yet.
    pub(super) fn open_on_chain(
        &mut self,
        conv: &str,
        e: &LogEntry,
        signer: &[u8],
    ) -> Result<Option<(Vec<u8>, u64)>, ()> {
        let (chain, index) = epoch_parts(e.epoch);
        match self.need(conv, e.sender, chain, index) {
            Need::Have => {}
            Need::Ask(_) => return Ok(None),
            Need::No => return Err(()),
        }
        let state = self.state_at(conv, e.sender, chain, index).ok_or(())?;
        open_chain_entry(&state, conv, &e.sender, e.epoch, signer, &e.ct)
            .map(Some)
            .map_err(|_| ())
    }

    pub(super) fn count_unopened(&mut self, conv: &str) {
        add_unopened(&mut self.unopened, conv, 1);
    }

    /// News of a key for us: what we found nothing for may have something now.
    pub(super) fn chain_news(&mut self, conv: &str) {
        if let Some(holds) = self.holds.get_mut(conv) {
            for held in holds.chains.values_mut() {
                held.asked = 0;
                held.asked_to = 0;
            }
        }
    }
}
