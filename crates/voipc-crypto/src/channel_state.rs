//! Who is in which channel, and which of them hold which of our keys.
//!
//! Text channels made this the only place it can live. Before them a client
//! was in exactly one channel, so "the members" and "the key group" were one
//! thing each and could sit next to the socket that learned about them. Now a
//! client holds several groups at once, and the same bookkeeping has to be
//! right in the native client and in the browser — which it was not, because
//! it was written twice: one side dropped a message for a foreign channel and
//! the other filed it as undecryptable, and one side cancelled a pending key
//! rotation the other performed.
//!
//! So it is written once, here, as plain state with no IO in it. The platform
//! keeps its own sockets and events and asks this the questions.

use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::task::{Context, Poll, Waker};

use serde_json::{json, Value};
use voipc_protocol::messages::{ClientMessage, ServerMessage};
use voipc_protocol::types::{PreKeyBundleData, UserInfo};
use zeroize::Zeroizing;

use crate::stores::SignalStores;
use crate::{group, prekey, session};

/// How many members one channel's recent chat is asked from.
///
/// More than one because people hold different parts of a conversation —
/// somebody who was away has the older half — and the merge puts them
/// together. Not many more because each answer costs a peer an encryption of
/// up to 48 KiB, and the third rarely adds anything the first two lack.
pub const HISTORY_SOURCES: usize = 3;

/// Per-channel membership and sender-key bookkeeping.
#[derive(Default)]
pub struct ChannelKeying {
    /// Text channels we are subscribed to. Several at a time, and none of them
    /// is the channel we stand in — that one is the caller's `own_channel`.
    text_channels: HashSet<u32>,
    /// channel_id → who is in it, for the channel we stand in and every text
    /// channel we are in.
    ///
    /// A sender key is only ever handed to a member, and only ever accepted
    /// from one: the server relays a distribution between two members and
    /// drops the rest, so recording a key we sent to a non-member would make
    /// reciprocation skip somebody who never received anything — and
    /// accepting one from a non-member is how a stranger with a colluding
    /// relay writes into a channel they were never in.
    members: HashMap<u32, HashSet<u32>>,
    /// channel_id → set of user_ids we have sent our sender key to.
    distributed: HashMap<u32, HashSet<u32>>,
    /// channel_id → set of user_ids whose sender keys we have received.
    received: HashMap<u32, HashSet<u32>>,
    /// Channels where somebody has left since we last sent: our own sender key
    /// there is rotated before the next message, so the leaver's copy of the
    /// chain stops being able to read along.
    stale: HashSet<u32>,
    /// channel_id → the members we still want recent chat from, as each one's
    /// sender key arrives. Only members who say they share it, at most a few.
    history_wanted: HashMap<u32, HashSet<u32>>,
    /// The live path (protocol 21), below.
    live: Live,
}

impl ChannelKeying {
    /// Drop everything. A new connection reuses none of it — user ids are
    /// handed out afresh and the channels may not even be the same channels.
    pub fn clear(&mut self) {
        self.text_channels.clear();
        self.members.clear();
        self.distributed.clear();
        self.received.clear();
        self.stale.clear();
        self.history_wanted.clear();
        self.live = Live::default();
    }

    /// Whether `channel_id` is one we are in: the voice channel we stand in,
    /// or any text channel we subscribe to.
    pub fn in_channel(&self, own_channel: u32, channel_id: u32) -> bool {
        channel_id == own_channel || self.text_channels.contains(&channel_id)
    }

    /// Whether `channel_id` is a channel we are in *and* `user_id` is in it
    /// with us.
    ///
    /// The inbound mirror of the check every outbound key already makes. A
    /// relay that wants past this has to put the stranger in the roster, where
    /// the member list shows them — which is the most an untrusted relay lets
    /// us ask for.
    pub fn shares_channel_with(&self, own_channel: u32, channel_id: u32, user_id: u32) -> bool {
        self.in_channel(own_channel, channel_id) && self.is_member(channel_id, user_id)
    }

    /// Whether `user_id` is in `channel_id`, as the last roster said.
    pub fn is_member(&self, channel_id: u32, user_id: u32) -> bool {
        self.members
            .get(&channel_id)
            .is_some_and(|m| m.contains(&user_id))
    }

    /// Whether we subscribe to `channel_id` as a text channel.
    pub fn is_text(&self, channel_id: u32) -> bool {
        self.text_channels.contains(&channel_id)
    }

    /// Every text channel we are subscribed to.
    pub fn text_channels(&self) -> Vec<u32> {
        self.text_channels.iter().copied().collect()
    }

    /// Who is in `channel_id`, as the last roster said.
    pub fn members_of(&self, channel_id: u32) -> Option<&HashSet<u32>> {
        self.members.get(&channel_id)
    }

    /// Everybody in `channel_id` except `own_user_id`.
    pub fn others_in(&self, channel_id: u32, own_user_id: u32) -> Vec<u32> {
        self.members
            .get(&channel_id)
            .map(|m| m.iter().copied().filter(|u| *u != own_user_id).collect())
            .unwrap_or_default()
    }

    /// Replace a channel's roster.
    pub fn set_members(&mut self, channel_id: u32, users: impl IntoIterator<Item = u32>) {
        self.members.insert(channel_id, users.into_iter().collect());
    }

    /// Note one arrival.
    pub fn add_member(&mut self, channel_id: u32, user_id: u32) {
        self.members.entry(channel_id).or_default().insert(user_id);
    }

    /// Note one departure: they are out of the roster and hold nothing of ours
    /// any more, but this says nothing about the other channels we share with
    /// them — see `note_stale` for what their leaving costs.
    pub fn drop_member(&mut self, channel_id: u32, user_id: u32) {
        if let Some(set) = self.members.get_mut(&channel_id) {
            set.remove(&user_id);
        }
        if let Some(set) = self.distributed.get_mut(&channel_id) {
            set.remove(&user_id);
        }
        if let Some(set) = self.received.get_mut(&channel_id) {
            set.remove(&user_id);
        }
    }

    /// Subscribe to a text channel. Returns whether it is new to us; a repeat
    /// must not wipe the key state we already built there.
    pub fn join_text(&mut self, channel_id: u32) -> bool {
        self.text_channels.insert(channel_id)
    }

    /// Start a channel's group keying from nothing: our own chain is forgotten
    /// and nobody is recorded as holding it.
    ///
    /// Forgetting is the half that used to be missing. Clearing the stale flag
    /// on its own — which is what leaving, re-joining and deleting each did —
    /// cancelled a pending rotation and left us writing on the chain a
    /// departed member still had.
    pub fn reset_channel(
        &mut self,
        stores: Option<&mut SignalStores>,
        own_user_id: u32,
        channel_id: u32,
    ) {
        if let Some(stores) = stores {
            group::forget_own_sender_key(stores, own_user_id, channel_id);
        }
        self.distributed.remove(&channel_id);
        self.received.remove(&channel_id);
        self.stale.remove(&channel_id);
        self.live.writing.remove(&channel_id);
    }

    /// Leave a channel entirely: its keys, its roster and anything we still
    /// wanted from it.
    pub fn forget_channel(
        &mut self,
        stores: Option<&mut SignalStores>,
        own_user_id: u32,
        channel_id: u32,
    ) {
        self.reset_channel(stores, own_user_id, channel_id);
        self.text_channels.remove(&channel_id);
        self.members.remove(&channel_id);
        self.history_wanted.remove(&channel_id);
        self.live.gated.remove(&channel_id);
        self.live.quiet.remove(&channel_id);
        self.live
            .wraps
            .retain(|(channel, _)| *channel != channel_id);
        self.live
            .opens
            .retain(|(channel, _)| *channel != channel_id);
        let held_bytes = &mut self.live.held_bytes;
        self.live.held.retain(|(channel, _), held| {
            if *channel == channel_id {
                *held_bytes -= held.bytes;
            }
            *channel != channel_id
        });
    }

    /// Somebody left a channel we are still in: our next message there starts
    /// a fresh chain.
    pub fn note_stale(&mut self, channel_id: u32) {
        self.stale.insert(channel_id);
    }

    /// If a rotation is pending for `channel_id`, perform it and return who
    /// needs the new key.
    ///
    /// The chain is forgotten before the target list is read, not after: in a
    /// two-person channel the one member who held our key is also the one who
    /// left, so the list is empty — and returning early on that without
    /// forgetting is how the next person to join was handed the chain the
    /// leaver still had.
    pub fn take_rotation_targets(
        &mut self,
        stores: Option<&mut SignalStores>,
        own_user_id: u32,
        channel_id: u32,
    ) -> Vec<u32> {
        if !self.stale.remove(&channel_id) {
            return Vec::new();
        }
        if let Some(stores) = stores {
            group::forget_own_sender_key(stores, own_user_id, channel_id);
        }
        // Everyone we had given the old key needs the new one; until they have
        // it they cannot read us, so the set starts empty again.
        self.distributed
            .remove(&channel_id)
            .map(|s| s.into_iter().collect())
            .unwrap_or_default()
    }

    /// Record that `user_id` now holds our sender key for `channel_id`.
    pub fn record_distributed(&mut self, channel_id: u32, user_id: u32) {
        self.distributed
            .entry(channel_id)
            .or_default()
            .insert(user_id);
    }

    /// Whether anybody at all holds our sender key for `channel_id` — i.e.
    /// whether a message sent there could be read by anyone.
    pub fn anyone_holds_our_key(&self, channel_id: u32) -> bool {
        self.distributed
            .get(&channel_id)
            .is_some_and(|s| !s.is_empty())
    }

    /// Whether `user_id` already holds our sender key for `channel_id`.
    pub fn has_distributed(&self, channel_id: u32, user_id: u32) -> bool {
        self.distributed
            .get(&channel_id)
            .is_some_and(|s| s.contains(&user_id))
    }

    /// Record that we hold `user_id`'s sender key for `channel_id`.
    pub fn record_received(&mut self, channel_id: u32, user_id: u32) {
        self.received.entry(channel_id).or_default().insert(user_id);
    }

    /// What a new session gets our key for: the room we stand in, and on an older relay
    /// every text channel too. On the live path a session opening names nobody.
    pub fn keyed_by_a_bundle(&self, own_channel: u32, live: bool) -> Vec<u32> {
        let mut channels = vec![own_channel];
        if !live {
            channels.extend(self.text_channels());
        }
        channels
    }

    /// Note who we mean to ask for a channel's recent chat.
    pub fn want_history_from(&mut self, channel_id: u32, who: HashSet<u32>) {
        if who.is_empty() {
            self.history_wanted.remove(&channel_id);
        } else {
            self.history_wanted.insert(channel_id, who);
        }
    }

    /// Whether we were still waiting to ask `user_id` for `channel_id`'s chat.
    /// Consumes the intent, so each member is asked once.
    pub fn take_history_wanted(&mut self, channel_id: u32, user_id: u32) -> bool {
        let Some(set) = self.history_wanted.get_mut(&channel_id) else {
            return false;
        };
        let wanted = set.remove(&user_id);
        if set.is_empty() {
            self.history_wanted.remove(&channel_id);
        }
        wanted
    }

    /// Who mints the next media key for a channel: the lowest remaining user
    /// id, so every member elects the same one from the roster they hold and
    /// nobody has to be asked.
    pub fn media_key_minter(&self, channel_id: u32) -> Option<u32> {
        self.members.get(&channel_id)?.iter().copied().min()
    }
}

/// Pick the members to ask for a channel's recent chat, from `(user_id,
/// shares_history)` pairs. Never ourselves, never somebody who says they do
/// not share.
pub fn history_sources(candidates: &[(u32, bool)], own_user_id: u32) -> HashSet<u32> {
    let sharers: Vec<u32> = candidates
        .iter()
        .filter(|(uid, shares)| *uid != own_user_id && *shares)
        .map(|(uid, _)| *uid)
        .collect();
    pick_history_sources(&sharers)
}

/// Of the members who offer recent chat, the few we actually ask.
///
/// At random rather than in roster order, which matters when a whole server
/// reconnects at once: taking the first few of a list every client holds in
/// the same order aims every request at the same two or three people, who
/// each owe an encryption of up to 48 KiB per asker and have a budget for
/// answering. Spread out, the same work lands on everybody who volunteered.
pub fn pick_history_sources(sharers: &[u32]) -> HashSet<u32> {
    use rand::seq::IndexedRandom;
    sharers
        .choose_multiple(&mut crate::rng(), HISTORY_SOURCES)
        .copied()
        .collect()
}

// ── The live path (protocol 21) ─────────────────────────────────────────────
//
// Being in a text channel is one frame, nobody is told, and nobody holds a key until
// somebody writes. Before a post a writer asks whom it owes (`KeyCheck`), makes one sender
// key message at the current position, holds it with the set just named (a round), sends
// the post, and only then hands the key out: those it has a session with at once, the rest
// by asking them to open one. A reader holds a post it has no key for. Every post asks, or
// posts that wait behind one ask: someone who came a moment after a check is told of only by
// the next, and no later key opens what went before it (CI run 42696335107).
//
// All of it is here, so a frame does the same in both backends: the host passes each frame
// to `live_frame`, a post to `live_post`, and a second's tick to `live_tick`, sends what
// `LiveOut` says, and pulls key frames from `live_next_frame` one at a time, at its own
// pace, since voice and joins share the queue they go into.

/// How long a round answers a late hello or `KeyWanted` from the position it was named at,
/// which is what opens the post that went before its key. As long as a reader holds a post.
const ROUND_LIFE_MS: u64 = 60_000;
/// A check unanswered this long drops the posts behind it, and says so.
const CHECK_WAIT_MS: u64 = 10_000;
/// A chain ends at its next post once this old, by the writer's own count of whom it named,
/// so a relay naming four million still gets an hour. What it covers is someone gone
/// offline, and a stolen chain key alone: a relay hiding that someone left simply names
/// them again at the restart.
const CHAIN_AGE_PER_NAMED_MS: u64 = 2_000;
const CHAIN_AGE_MIN_MS: u64 = 60_000;
const CHAIN_AGE_MAX_MS: u64 = 3_600_000;
/// Exits rotate at most once per this, per the same count: a raid of leavers can cost a
/// writer no more than it. Longer than a key job, so an exit cannot kill a round mid-job.
const EXIT_GAP_PER_NAMED_MS: u64 = 20;
const EXIT_GAP_MAX_MS: u64 = 36_000;
/// Wraps in one frame, and the bytes that end a frame sooner: a wrap in a session this
/// device opened is 1.9 KB until the peer answers once.
pub const WRAPS_A_FRAME: usize = 256;
const WRAP_FRAME_BYTES: usize = 56 * 1024;
/// In a browser, in a call: wraps run on the page thread that also feeds the microphone.
pub const WRAPS_A_FRAME_BROWSER_CALL: usize = 8;
/// People asked to open a session in one frame, and in a call, where each brings back a hello.
const OPENS_A_FRAME: usize = 256;
const OPENS_A_FRAME_IN_CALL: usize = 33;
/// The next `OpenSessions` goes when half of the last answered, or after this.
const OPEN_WAIT_MS: u64 = 1_000;
/// How long a job's last hellos are waited for before it counts as over.
const JOB_SETTLE_MS: u64 = 5_000;
/// New session keys after a key job, at most this often, and this often anyway.
const RENEW_GAP_MS: u64 = 2_000;
const RENEW_EVERY_MS: u64 = 3_600_000;
/// Posts with no key yet: per writer per channel, how long, and how many bytes in all.
const HOLD_PER_WRITER: usize = 20;
const HOLD_MS: u64 = 60_000;
const HOLD_BYTES: usize = 2 * 1024 * 1024;
/// A held post with no key after this long asks for one.
const KEY_WANTED_AFTER_MS: u64 = 10_000;
/// Reader: a writer's ask to open is taken once per this. Writer: a reset once per this.
const REOPEN_MS: u64 = 600_000;
/// Hand-off asks go at most this often: the relay gives direct messages a small burst.
const ASK_EVERY_MS: u64 = 1_000;
/// An ask with no session after this long is dropped, and an answer after it is not taken.
const ASK_LIFE_MS: u64 = 30_000;
/// How long the relay's "not delivered" counts as being about a hand-off.
const SEALED_UNDELIVERED_MS: u64 = 10_000;
/// Past this much in an hour on mobile data a key job asks first: by the hour, or a raid of
/// leavers costs a phone 35 MB in jobs each too small to ask about.
const METERED_JOB_BYTES: u64 = 2_000_000;
const METERED_HOUR_MS: u64 = 3_600_000;
const WRAP_BYTES: u64 = 176;
const OPEN_BYTES: u64 = 1_800;
/// Key frames held for the pages of pins: more than a job's, only from a relay.
const PIN_FRAMES_MOST: usize = 4096;
/// Pairwise frames a host holds for them (`waits_for_pins`). The oldest goes past this.
pub const PIN_HELD_MOST: usize = 1024;
/// A post waits this long for them: all 56 pages take about 22 s on 1 Mbit.
const PIN_POST_WAIT_MS: u64 = 60_000;
/// What a hello carries. It names nobody and says nothing.
const HELLO: &[u8] = b"hello";

/// A chain's limit, by whom it has named.
pub fn chain_age_limit(named: usize) -> u64 {
    (named as u64)
        .saturating_mul(CHAIN_AGE_PER_NAMED_MS)
        .clamp(CHAIN_AGE_MIN_MS, CHAIN_AGE_MAX_MS)
}

/// The least time between two rotations caused by exits.
pub fn exit_gap(named: usize) -> u64 {
    (named as u64)
        .saturating_mul(EXIT_GAP_PER_NAMED_MS)
        .min(EXIT_GAP_MAX_MS)
}

/// Stores are in memory, so a libsignal future is ready on its first poll.
fn ready<T>(fut: impl Future<Output = anyhow::Result<T>>) -> anyhow::Result<T> {
    match Box::pin(fut)
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(result) => result,
        Poll::Pending => anyhow::bail!("an in-memory store pended"),
    }
}

/// What the host does after a call on the live path.
#[derive(Default)]
pub struct LiveOut {
    pub send: Vec<ClientMessage>,
    /// Front-end events, name and payload, to emit as they are.
    pub emit: Vec<(&'static str, Value)>,
    /// People seen for the first time, or under another account: for the pin check.
    pub seen: Vec<Seen>,
    /// An identity someone showed, for the pin check: a bundle's.
    pub check: Vec<(u32, Vec<u8>)>,
    /// A direct message may use a session with these now.
    pub made: Vec<u32>,
    /// And no longer with these.
    pub gone: Vec<u32>,
    /// Text channels newly followed: the host keeps their logs.
    pub entered: Vec<u32>,
    /// Text channels found to have a gate, and accounts met in one: their pins keep the half
    /// of the room open channels cannot fill.
    pub gated: Vec<u32>,
    pub gated_people: Vec<[u8; 16]>,
    /// `live_next_frame` has something to send.
    pub work: bool,
}

impl LiveOut {
    fn absorb(&mut self, other: LiveOut) {
        self.send.extend(other.send);
        self.emit.extend(other.emit);
        self.seen.extend(other.seen);
        self.check.extend(other.check);
        self.made.extend(other.made);
        self.gone.extend(other.gone);
        self.entered.extend(other.entered);
        self.gated.extend(other.gated);
        self.gated_people.extend(other.gated_people);
        self.work |= other.work;
    }
}

/// One person a frame named, for the pins. The check an arrival would have had, which
/// `take_seen` gave before anyone knew whose id this was: the identity the session runs on,
/// if there is a session yet.
pub struct Seen {
    pub user_id: u32,
    pub account: Option<[u8; 16]>,
    pub name: String,
    pub identity: Option<Vec<u8>>,
}

/// A chain's sender key message at one position, and whom it was named to.
struct Round {
    message: Zeroizing<Vec<u8>>,
    started: u64,
    named: HashSet<u32>,
}

/// Our writing in one text channel.
#[derive(Default)]
struct Writing {
    /// When this chain started. None: no chain, the next post starts one.
    started: Option<u64>,
    /// Everyone this chain has been named to: its readers, by our own count.
    named: HashSet<u32>,
    rounds: Vec<Round>,
    /// Someone it reached is out. It ends at the next post `exit_gap` allows.
    exited: bool,
    /// A check is out: since when, and whether it asked for everyone.
    check_out: Option<(u64, bool)>,
    /// Who the frames of its answer named so far.
    owed: HashSet<u32>,
    /// Posts behind that check, or behind the question: in order, ready to encrypt.
    waiting: VecDeque<Zeroizing<Vec<u8>>>,
    /// Who was owed, while a person decides (`live_answer_job`).
    asking: Option<Vec<u32>>,
    /// An answer was not used, and the relay counts whom it named as told: the next check
    /// asks for everyone, and this chain's readers are taken off what comes.
    retell: bool,
    /// The last answer named someone no list had, which lists still on their way explain once.
    unlisted_once: bool,
}

impl Writing {
    /// A chain past its age, or an exit's gap, or none: it answers nobody, and the next
    /// post starts a new one.
    fn over(&self, now: u64) -> bool {
        let Some(started) = self.started else {
            return true;
        };
        let age = now.saturating_sub(started);
        age >= chain_age_limit(self.named.len())
            || (self.exited && age >= exit_gap(self.named.len()))
    }

    fn end_chain(&mut self) {
        self.started = None;
        self.named.clear();
        self.rounds.clear();
        self.exited = false;
    }
}

/// A post with no key yet.
struct HeldPost {
    username: String,
    account: Option<[u8; 16]>,
    is_admin: bool,
    is_moderator: bool,
    ciphertext: Vec<u8>,
    timestamp: u64,
    arrived: u64,
}

/// One writer's posts held in one channel, oldest first.
#[derive(Default)]
struct HeldPosts {
    posts: VecDeque<HeldPost>,
    bytes: usize,
    /// Asked for the key by `KeyWanted`.
    asked: bool,
}

/// A token bucket on the app's own clock.
#[derive(Default)]
struct Bucket {
    spent: f64,
    at: u64,
}

impl Bucket {
    fn take(&mut self, burst: f64, per_sec: f64, now: u64) -> bool {
        let refill = now.saturating_sub(self.at) as f64 / 1000.0 * per_sec;
        self.spent = (self.spent - refill).max(0.0);
        self.at = now;
        if self.spent + 1.0 > burst {
            return false;
        }
        self.spent += 1.0;
        true
    }
}

#[derive(Default)]
struct Live {
    /// When this connection started, which dates a session it made.
    connected_at: u64,
    /// On mobile data: asks before a large key job, and reader's bucket is smaller.
    metered: bool,
    /// What key jobs took on mobile data, and since when.
    metered_spent: u64,
    metered_since: u64,
    /// Gated channels: a guest is refused there, either way.
    gated: HashSet<u32>,
    /// Followed but quiet: no post, no key.
    quiet: HashSet<u32>,
    /// Who a list or a frame has named, and the account if it said one. A bare id means
    /// nothing without this: `check_identity` is a no-op off the roster.
    people: HashMap<u32, Option<[u8; 16]>>,
    /// What those lists call them, for naming a reader to whoever hands them a key.
    names: HashMap<u32, String>,
    /// Each account's last id here, and the id it had before: someone who reconnected while
    /// we stayed is found by that, since the session runs under the old one.
    last_id: HashMap<[u8; 16], u32>,
    prior_id: HashMap<u32, u32>,
    /// The warnings given once, by kind and channel.
    warned: HashSet<(&'static str, u32)>,
    /// Records from before this connection, and which of ours came from there, since
    /// when. Those read only as keys: a direct message needs a session both ends hold.
    kept: KeptSessions,
    moved: HashMap<u32, u64>,

    writing: HashMap<u32, Writing>,
    /// Wraps to make, and people to ask to open, in the order they were owed.
    wraps: VecDeque<(u32, u32)>,
    opens: VecDeque<(u32, u32)>,
    /// Asked to open, no hello yet. Out of how many, when.
    awaiting: HashSet<u32>,
    open_frame: usize,
    opens_sent_at: u64,
    /// New session keys are due, and when they last went.
    renew_due: bool,
    last_renew: u64,
    /// The relay ran low on our one-time keys: more go when the job ends.
    refill_due: bool,
    /// One reset per reader per ten minutes, and all `KeyWanted` under one budget.
    resets: HashMap<u32, u64>,
    wanted_bucket: Bucket,

    held: HashMap<(u32, u32), HeldPosts>,
    held_bytes: usize,
    /// Reader-wide: `KeyWanted`, and hellos made.
    key_wanted_bucket: Bucket,
    hello_bucket: Bucket,
    /// When each writer's ask to open was last taken. Ids change per connection, so a real
    /// reconnect is not held back.
    opened_for: HashMap<u32, u64>,
    /// Writers we asked for a key: their next ask to open is taken at once.
    key_asked: HashSet<u32>,

    /// Hand-offs to ask, as (target, channel, since when), and the last that went.
    asks: VecDeque<(u32, u32, u64)>,
    last_ask: u64,
    /// The sealed asks out, by (channel, target): an answer is taken only to one of these.
    asked: HashMap<(u32, u32), u64>,
    /// Sealed messages sent lately per target, which the relay may answer "not delivered".
    sealed_out: HashMap<u32, (u32, u64)>,
    /// Bundles we asked for an ask.
    bundle_asked: HashSet<u32>,

    /// The pages of pins are out (`sync::pins`): a key job would decide on pins not read,
    /// so its frames and the posts that start one wait here.
    pins_wait: bool,
    pin_frames: VecDeque<ServerMessage>,
    pin_posts: VecDeque<(u32, Zeroizing<Vec<u8>>, u64)>,
}

impl ChannelKeying {
    /// This connection is on the live path, from `now`.
    pub fn live_start(&mut self, now: u64) {
        self.live.connected_at = now;
        self.live.last_renew = now;
    }

    /// On mobile data or not. Off until a host says so.
    pub fn live_set_metered(&mut self, metered: bool) {
        self.live.metered = metered;
    }

    /// Take these channels whole or quiet.
    pub fn live_set_quiet(&mut self, channels: &[u32], quiet: bool) {
        for channel in channels {
            if quiet {
                self.live.quiet.insert(*channel);
            } else {
                self.live.quiet.remove(channel);
            }
        }
    }

    /// Takes over what an earlier connection of this account kept (`live_keep_sessions`).
    pub fn live_adopt_kept(&mut self, kept: KeptSessions) {
        self.live.kept = kept;
    }

    /// What this connection hands to the next: every session with an account, by account,
    /// over what it took over and did not use. Called before the stores go. A guest passes
    /// nothing on, and calls nothing.
    pub fn live_keep_sessions(&mut self, stores: &SignalStores, now: u64) -> KeptSessions {
        let mut kept = std::mem::take(&mut self.live.kept);
        // Oldest id first: a peer who reconnected here is the same account twice, and the
        // later session is the one both ends hold.
        let mut sessions: Vec<(u32, &[u8])> = stores.session.by_user().collect();
        sessions.sort_unstable_by_key(|(id, _)| *id);
        for (id, record) in sessions {
            if let Some(Some(account)) = self.live.people.get(&id) {
                let born = self
                    .live
                    .moved
                    .get(&id)
                    .copied()
                    .unwrap_or(self.live.connected_at);
                kept.put(*account, record, born, now);
            }
        }
        kept.trim(now);
        kept
    }

    /// Someone a list or a frame named. `true` the first time, or under another account.
    /// A row with no account does not take one away: an anonymous room's list shows none.
    pub fn live_note_person(&mut self, user_id: u32, account: Option<[u8; 16]>) -> bool {
        if user_id == 0 {
            return false;
        }
        match self.live.people.get(&user_id) {
            Some(known) if account.is_none() || *known == account => false,
            _ => {
                self.live.people.insert(user_id, account);
                if let Some(account) = account {
                    if let Some(before) = self.live.last_id.insert(account, user_id) {
                        if before != user_id {
                            self.live.prior_id.insert(user_id, before);
                        }
                    }
                }
                true
            }
        }
    }

    /// A session to wrap in or read by for `user_id`: one here, or one this account had
    /// under its last id, or one kept from before this connection. On need it goes under
    /// their current id, and `save_identity` runs it past the pins again. Those read only
    /// as keys. Voice rooms and direct messages never come this way.
    fn find_session(
        &mut self,
        stores: &mut SignalStores,
        user_id: u32,
        account: Option<[u8; 16]>,
        now: u64,
    ) -> bool {
        if stores.session.has(user_id) {
            return true;
        }
        let Some(account) = account else {
            return false;
        };
        let live = &mut self.live;
        if let Some(before) = live.prior_id.remove(&user_id) {
            if let Some(record) = stores.session.take(before) {
                let born = live.moved.remove(&before).unwrap_or(live.connected_at);
                if now.saturating_sub(born) < KEPT_MS {
                    stores.session.put(user_id, record);
                    live.moved.insert(user_id, born);
                    return true;
                }
            }
        }
        match live.kept.take(&account, now) {
            Some((record, born)) => {
                stores.session.put(user_id, record);
                live.moved.insert(user_id, born);
                true
            }
            None => false,
        }
    }

    /// The rows of a list, for the pins: those it is news of.
    pub fn live_note_rows(&mut self, stores: &SignalStores, rows: &[UserInfo]) -> Vec<Seen> {
        for row in rows.iter().filter(|row| !row.username.is_empty()) {
            self.live.names.insert(row.user_id, row.username.clone());
        }
        rows.iter()
            .filter(|row| self.live_note_person(row.user_id, row.account))
            .map(|row| Seen {
                user_id: row.user_id,
                account: row.account,
                name: row.username.clone(),
                identity: stores.identity.identity_of(row.user_id).map(<[u8]>::to_vec),
            })
            .collect()
    }

    /// A session with `user_id` came up that both ends hold: not one kept from earlier.
    pub fn live_session_up(&mut self, user_id: u32) {
        self.live.moved.remove(&user_id);
    }

    /// A kept session whose peer's key disagrees with their pin: gone, so what comes next
    /// opens afresh and is checked as anyone's is. `false`: it was no kept session.
    pub fn live_drop_kept_session(&mut self, stores: &mut SignalStores, user_id: u32) -> bool {
        if self.live.moved.remove(&user_id).is_none() {
            return false;
        }
        stores.session.take(user_id);
        true
    }

    /// No key job and no key frame until `live_pins_in`.
    pub fn live_wait_for_pins(&mut self) {
        self.live.pins_wait = true;
    }

    /// Whether the pages of pins are still out.
    pub fn live_pins_out(&self) -> bool {
        self.live.pins_wait
    }

    /// Whether a host holds this frame back now, and hands it on in order after `live_pins_in`.
    pub fn live_holds_frame(&self, msg: &ServerMessage) -> bool {
        self.live.pins_wait && waits_for_pins(msg)
    }

    /// The pages of pins are in: what waited for them, in the order it came.
    pub fn live_pins_in(
        &mut self,
        stores: &mut SignalStores,
        own_channel: u32,
        now: u64,
    ) -> LiveOut {
        let mut out = LiveOut::default();
        if !std::mem::take(&mut self.live.pins_wait) {
            return out;
        }
        for frame in std::mem::take(&mut self.live.pin_frames) {
            out.absorb(self.live_frame(stores, own_channel, &frame, now));
        }
        for (channel_id, payload, _) in std::mem::take(&mut self.live.pin_posts) {
            match self.live_post(stores, channel_id, payload.to_vec(), now) {
                Ok(more) => out.absorb(more),
                Err(e) => {
                    tracing::warn!(channel_id, "a post that waited could not go: {e}");
                    out.emit.push((
                        "channel-undelivered",
                        json!({ "channel_id": channel_id, "expired": 1 }),
                    ));
                }
            }
        }
        out.work |= self.live_has_work();
        out
    }

    /// A post in a text channel. It goes behind the check this starts, or behind the check
    /// already out. Its own row shows it as sent either way. `payload` is what the envelope
    /// holds.
    pub fn live_post(
        &mut self,
        stores: &mut SignalStores,
        channel_id: u32,
        payload: Vec<u8>,
        now: u64,
    ) -> Result<LiveOut, String> {
        let own = stores.own_user_id;
        let payload = Zeroizing::new(payload);
        if self.live.pins_wait {
            self.live.pin_posts.push_back((channel_id, payload, now));
            return Ok(LiveOut::default());
        }
        let w = self.live.writing.entry(channel_id).or_default();
        let mut out = LiveOut::default();
        if w.check_out.is_some() || w.asking.is_some() {
            w.waiting.push_back(payload);
            return Ok(out);
        }
        if w.over(now) {
            // Forgotten here, not when the answer comes: from now on it answers nobody
            group::forget_own_sender_key(stores, own, channel_id);
            w.end_chain();
            w.check_out = Some((now, true));
            w.waiting.push_back(payload);
            out.send.push(ClientMessage::KeyCheck {
                channel_id,
                restart: true,
            });
            return Ok(out);
        }
        let restart = std::mem::take(&mut w.retell);
        w.check_out = Some((now, restart));
        w.waiting.push_back(payload);
        out.send.push(ClientMessage::KeyCheck {
            channel_id,
            restart,
        });
        Ok(out)
    }

    /// A person's answer to "this key job is large, on mobile data". No: what waits is
    /// dropped, and said to be.
    pub fn live_answer_job(
        &mut self,
        stores: &mut SignalStores,
        channel_id: u32,
        go: bool,
        now: u64,
    ) -> LiveOut {
        let mut out = LiveOut::default();
        let Some(w) = self.live.writing.get_mut(&channel_id) else {
            return out;
        };
        let Some(named) = w.asking.take() else {
            return out;
        };
        if go {
            self.start_round(stores, channel_id, named, now, &mut out);
        } else {
            w.retell = true;
            drop_waiting(w, channel_id, &mut out);
        }
        out
    }

    /// A frame of the live path. Everything else is answered by nothing here.
    pub fn live_frame(
        &mut self,
        stores: &mut SignalStores,
        own_channel: u32,
        msg: &ServerMessage,
        now: u64,
    ) -> LiveOut {
        let mut out = LiveOut::default();
        if self.live.pins_wait
            && matches!(
                msg,
                ServerMessage::KeysOwed { .. }
                    | ServerMessage::SessionAsked { .. }
                    | ServerMessage::SessionHello { .. }
                    | ServerMessage::TextKeyReceived { .. }
                    | ServerMessage::KeyWanted { .. }
            )
        {
            if self.live.pin_frames.len() >= PIN_FRAMES_MOST {
                self.live.pin_frames.pop_front();
            }
            self.live.pin_frames.push_back(msg.clone());
            return out;
        }
        match msg {
            ServerMessage::TextJoined { joined, refused } => {
                self.text_joined(stores, joined, refused, &mut out);
            }
            ServerMessage::KeysOwed {
                channel_id,
                ids,
                rows,
                more,
                refused,
            } => {
                out.seen.extend(self.live_note_rows(stores, rows));
                self.note_gated_people(
                    *channel_id,
                    ids.iter().chain(rows.iter().map(|row| &row.user_id)),
                    &mut out,
                );
                self.keys_owed(
                    stores,
                    *channel_id,
                    (ids, rows),
                    *more,
                    *refused,
                    now,
                    &mut out,
                );
            }
            ServerMessage::SessionAsked {
                channel_id,
                from,
                account,
                name,
                bundle,
            } => {
                if self.live_note_person(*from, *account) {
                    out.seen.push(Seen {
                        user_id: *from,
                        account: *account,
                        name: name.clone(),
                        identity: None,
                    });
                }
                self.note_gated_people(*channel_id, [from], &mut out);
                self.session_asked(stores, *channel_id, *from, *account, bundle, now, &mut out);
            }
            ServerMessage::SessionHello {
                from,
                message_type,
                ciphertext,
            } => self.session_hello(stores, *from, *message_type, ciphertext, now, &mut out),
            ServerMessage::TextKeyReceived {
                channel_id,
                from,
                account,
                message_type,
                ciphertext,
            } => {
                if self.in_channel(own_channel, *channel_id) {
                    self.note_gated_people(*channel_id, [from], &mut out);
                    self.text_key(
                        stores,
                        *channel_id,
                        *from,
                        *account,
                        (*message_type, ciphertext),
                        now,
                        &mut out,
                    );
                }
            }
            ServerMessage::KeyWanted {
                channel_id,
                from,
                reset,
            } => self.key_wanted(stores, *channel_id, *from, *reset, now, &mut out),
            ServerMessage::ChannelExits { channels } => {
                for channel in channels {
                    if let Some(w) = self.live.writing.get_mut(channel) {
                        w.exited = true;
                    }
                }
            }
            ServerMessage::MemberGone {
                channel_id,
                user_id,
            } => {
                // Whatever the relay says about keys, this chain ends: a person told of as
                // gone and seated again without a word is named again that way.
                if let Some(w) = self.live.writing.get_mut(channel_id) {
                    w.exited = true;
                    w.named.remove(user_id);
                    for round in &mut w.rounds {
                        round.named.remove(user_id);
                    }
                }
                out.emit.push((
                    "member-gone",
                    json!({ "channel_id": channel_id, "user_id": user_id }),
                ));
            }
            ServerMessage::TextPost {
                channel_id,
                user_id,
                username,
                account,
                is_admin,
                is_moderator,
                ciphertext,
                timestamp,
            } => {
                let post = HeldPost {
                    username: username.clone(),
                    account: *account,
                    is_admin: *is_admin,
                    is_moderator: *is_moderator,
                    ciphertext: ciphertext.clone(),
                    timestamp: *timestamp,
                    arrived: now,
                };
                self.text_post(stores, own_channel, *channel_id, *user_id, post, &mut out);
                self.note_gated_people(*channel_id, [user_id], &mut out);
            }
            ServerMessage::ChannelPage {
                channel_id,
                ids,
                rows,
                next,
                total,
            } => {
                out.seen.extend(self.live_note_rows(stores, rows));
                self.note_gated_people(
                    *channel_id,
                    ids.iter().chain(rows.iter().map(|row| &row.user_id)),
                    &mut out,
                );
                out.emit.push((
                    "channel-page",
                    json!({ "channel_id": channel_id, "ids": ids, "rows": rows, "next": next, "total": total }),
                ));
            }
            ServerMessage::ChannelMarks { marks } => {
                let marks: Vec<Value> = marks
                    .iter()
                    .map(|(channel_id, at)| json!({ "channel_id": channel_id, "last_post_ms": at }))
                    .collect();
                out.emit.push(("channel-marks", json!({ "marks": marks })));
            }
            ServerMessage::Evicted { channel_id, reason } => {
                out.emit.push((
                    "evicted",
                    json!({ "channel_id": channel_id, "reason": reason }),
                ));
            }
            ServerMessage::PreKeysLow { .. } => {
                self.live.refill_due = true;
                out.work = true;
            }
            _ => {}
        }
        out
    }

    /// Who a gated channel's frame named, for the pins.
    fn note_gated_people<'a>(
        &self,
        channel_id: u32,
        ids: impl IntoIterator<Item = &'a u32>,
        out: &mut LiveOut,
    ) {
        if self.live.gated.contains(&channel_id) {
            out.gated_people.extend(
                ids.into_iter()
                    .filter_map(|id| self.live.people.get(id).copied().flatten()),
            );
        }
    }

    fn text_joined(
        &mut self,
        stores: &mut SignalStores,
        joined: &[(u32, bool, bool, u64)],
        refused: &[u32],
        out: &mut LiveOut,
    ) {
        let own = stores.own_user_id;
        let mut rows = Vec::with_capacity(joined.len());
        for (channel_id, listen_only, gated, last_post_ms) in joined.iter().copied() {
            if self.join_text(channel_id) {
                self.reset_channel(Some(&mut *stores), own, channel_id);
                out.entered.push(channel_id);
            }
            let had_gate = if gated {
                self.live.gated.insert(channel_id);
                out.gated.push(channel_id);
                false
            } else {
                self.live.gated.remove(&channel_id)
            };
            if had_gate {
                warn_of(out, "gate-gone", channel_id);
            }
            rows.push(json!({
                "channel_id": channel_id,
                "listen_only": listen_only,
                "gated": gated,
                "last_post_ms": last_post_ms,
            }));
        }
        out.emit
            .push(("text-joined", json!({ "joined": rows, "refused": refused })));
    }

    #[allow(clippy::too_many_arguments)]
    fn keys_owed(
        &mut self,
        stores: &mut SignalStores,
        channel_id: u32,
        (ids, rows): (&[u32], &[UserInfo]),
        more: bool,
        refused: bool,
        now: u64,
        out: &mut LiveOut,
    ) {
        let own = stores.own_user_id;
        let Some(w) = self.live.writing.get_mut(&channel_id) else {
            return;
        };
        // Nobody asked: a relay cannot make an app wrap by answering what it never asked
        let Some((_, restart)) = w.check_out else {
            return;
        };
        if refused {
            w.check_out = None;
            w.owed.clear();
            w.retell = true;
            drop_waiting(w, channel_id, out);
            return;
        }
        w.owed.extend(ids.iter().copied());
        w.owed.extend(rows.iter().map(|row| row.user_id));
        if more {
            return;
        }
        let owed = std::mem::take(&mut w.owed);
        w.check_out = None;
        let gated = self.live.gated.contains(&channel_id);
        let (mut named, mut unlisted, mut guests) = (Vec::with_capacity(owed.len()), false, false);
        for id in owed {
            if id == own {
                continue;
            }
            match self.live.people.get(&id) {
                // A bare id nobody listed: a stranger in waiting, unchecked by any pin
                None => unlisted = true,
                Some(None) if gated => guests = true,
                // Asked for everyone: who holds this chain already needs nothing
                Some(_) if restart && w.named.contains(&id) => {}
                Some(_) => named.push(id),
            }
        }
        // The relay counts them as told. Right after a connect the public lists may simply
        // not be here yet, so it takes a second answer to say so.
        let again = std::mem::replace(&mut w.unlisted_once, unlisted);
        w.retell |= unlisted;
        if unlisted && again && self.live.warned.insert(("unlisted", 0)) {
            warn_of(out, "unlisted", channel_id);
        }
        if guests && self.live.warned.insert(("guest-in-gate", channel_id)) {
            warn_of(out, "guest-in-gate", channel_id);
        }
        if self.live.metered {
            let bytes = self.job_bytes(stores, &named, now);
            if now.saturating_sub(self.live.metered_since) >= METERED_HOUR_MS {
                self.live.metered_since = now;
                self.live.metered_spent = 0;
            }
            if self.live.metered_spent + bytes > METERED_JOB_BYTES {
                out.emit.push((
                    "key-job-ask",
                    json!({ "channel_id": channel_id, "people": named.len(), "bytes": bytes }),
                ));
                if let Some(w) = self.live.writing.get_mut(&channel_id) {
                    w.asking = Some(named);
                }
                return;
            }
            self.live.metered_spent += bytes;
        }
        self.start_round(stores, channel_id, named, now, out);
    }

    /// What wrapping for these takes, on the link that pays for it.
    fn job_bytes(&self, stores: &SignalStores, named: &[u32], now: u64) -> u64 {
        named
            .iter()
            .map(|id| {
                let kept = matches!(
                    self.live.people.get(id),
                    Some(Some(account)) if self.live.kept.holds(account, now)
                );
                if stores.session.has(*id) || kept {
                    WRAP_BYTES
                } else {
                    WRAP_BYTES + OPEN_BYTES
                }
            })
            .sum()
    }

    /// The round: one sender key message at the current position, held with the set just
    /// named. Only then the posts, and the wraps behind them, so a reader's upload is not
    /// what a person's message waits for.
    fn start_round(
        &mut self,
        stores: &mut SignalStores,
        channel_id: u32,
        named: Vec<u32>,
        now: u64,
        out: &mut LiveOut,
    ) {
        let own = stores.own_user_id;
        let message = match ready(group::create_distribution_message(stores, own, channel_id)) {
            Ok(message) => Zeroizing::new(message),
            Err(e) => {
                tracing::warn!(channel_id, "could not make a sender key: {e}");
                if let Some(w) = self.live.writing.get_mut(&channel_id) {
                    w.retell = true;
                    drop_waiting(w, channel_id, out);
                }
                return;
            }
        };
        let Some(w) = self.live.writing.get_mut(&channel_id) else {
            return;
        };
        if w.started.is_none() && named.is_empty() {
            out.emit
                .push(("nobody-here", json!({ "channel_id": channel_id })));
        }
        w.started.get_or_insert(now);
        if !named.is_empty() {
            w.named.extend(named.iter().copied());
            w.rounds.push(Round {
                message,
                started: now,
                named: named.iter().copied().collect(),
            });
            // Only this device hands them a key, so only it can say who it just handed one
            // to. The front end says so where who reads is what matters.
            let readers: Vec<Value> = named
                .iter()
                .map(|id| {
                    json!({
                        "user_id": id,
                        "account": self.live.people.get(id).copied().flatten(),
                        "name": self.live.names.get(id).map_or("", String::as_str),
                    })
                })
                .collect();
            out.emit.push((
                "key-readers",
                json!({ "channel_id": channel_id, "readers": readers }),
            ));
            let mut sorted = named;
            sorted.sort_unstable();
            // By whether a session is there, then by id, and never by who was mentioned,
            // which would show the relay who was.
            for id in sorted {
                let account = self.live.people.get(&id).copied().flatten();
                if self.find_session(stores, id, account, now) {
                    self.live.wraps.push_back((channel_id, id));
                } else {
                    self.live.opens.push_back((channel_id, id));
                }
            }
            self.live.renew_due = true;
            out.work = true;
        }
        let Some(w) = self.live.writing.get_mut(&channel_id) else {
            return;
        };
        let (mut failed, waiting) = (0, std::mem::take(&mut w.waiting));
        for payload in waiting {
            match post_frame(stores, channel_id, &payload) {
                Ok(frame) => out.send.push(frame),
                Err(e) => {
                    tracing::warn!(channel_id, "could not encrypt a post: {e}");
                    failed += 1;
                }
            }
        }
        if failed > 0 {
            out.emit.push((
                "channel-undelivered",
                json!({ "channel_id": channel_id, "expired": failed }),
            ));
        }
    }

    /// A writer has no session with us and is about to write. A hello names nobody, so
    /// asking costs a writer nothing it can use to read: it costs us an upload, which is
    /// what the two limits are for.
    #[allow(clippy::too_many_arguments)]
    fn session_asked(
        &mut self,
        stores: &mut SignalStores,
        channel_id: u32,
        from: u32,
        account: Option<[u8; 16]>,
        bundle: &PreKeyBundleData,
        now: u64,
        out: &mut LiveOut,
    ) {
        if !self.text_channels.contains(&channel_id) || self.live.quiet.contains(&channel_id) {
            return;
        }
        if account.is_none() && self.live.gated.contains(&channel_id) {
            if self.live.warned.insert(("guest-in-gate", channel_id)) {
                warn_of(out, "guest-in-gate", channel_id);
            }
            return;
        }
        let we_asked = self.live.key_asked.remove(&from);
        let lately = self
            .live
            .opened_for
            .get(&from)
            .is_some_and(|at| now.saturating_sub(*at) < REOPEN_MS);
        if lately && !we_asked {
            return;
        }
        let (burst, per_sec) = if self.live.metered {
            (32.0, 0.25)
        } else {
            (128.0, 2.0)
        };
        if !self.live.hello_bucket.take(burst, per_sec, now) {
            return;
        }
        self.live.opened_for.insert(from, now);
        out.check.push((from, bundle.identity_key.clone()));
        // Beside what is there, which libsignal archives and decrypt still tries: that is
        // what makes two people opening each other at once safe.
        let hello = ready(session::establish_session(stores, from, bundle))
            .and_then(|()| ready(session::encrypt_message(stores, from, HELLO)));
        match hello {
            Ok((ciphertext, message_type)) => {
                self.live.moved.remove(&from);
                out.made.push(from);
                out.send.push(ClientMessage::SessionHello {
                    to: from,
                    message_type,
                    ciphertext,
                });
            }
            Err(e) => tracing::warn!(from, "could not open the session asked for: {e}"),
        }
    }

    /// A reader opened a session. It names nobody: a wrap goes only for a chain that has
    /// already named them, and only while that chain still answers.
    fn session_hello(
        &mut self,
        stores: &mut SignalStores,
        from: u32,
        message_type: u8,
        ciphertext: &[u8],
        now: u64,
        out: &mut LiveOut,
    ) {
        if let Err(e) = ready(session::decrypt_message(
            stores,
            from,
            ciphertext,
            message_type,
        )) {
            tracing::warn!(from, "a hello that does not open: {e}");
            return;
        }
        self.live.moved.remove(&from);
        self.live.awaiting.remove(&from);
        // What just answered it is in memory until the keys it used go
        self.live.renew_due = true;
        out.made.push(from);
        let Live { writing, wraps, .. } = &mut self.live;
        for (channel_id, w) in writing.iter() {
            if w.named.contains(&from) && !w.over(now) {
                wraps.push_back((*channel_id, from));
                out.work = true;
            }
        }
    }

    /// A writer's key. A relay lying about the account gets a failed MAC, and the same heal.
    #[allow(clippy::too_many_arguments)]
    fn text_key(
        &mut self,
        stores: &mut SignalStores,
        channel_id: u32,
        from: u32,
        account: Option<[u8; 16]>,
        (message_type, ciphertext): (u8, &[u8]),
        now: u64,
        out: &mut LiveOut,
    ) {
        self.find_session(stores, from, account, now);
        let opened = ready(session::decrypt_message(
            stores,
            from,
            ciphertext,
            message_type,
        ))
        .and_then(|plain| {
            ready(group::process_distribution_message(
                stores, from, channel_id, &plain,
            ))
        });
        match opened {
            Ok(()) => {
                if message_type == 1 {
                    self.live.moved.remove(&from);
                    out.made.push(from);
                }
                self.record_received(channel_id, from);
                self.open_held(stores, channel_id, from, out);
            }
            Err(e) => {
                tracing::info!(
                    from,
                    channel_id,
                    "a key that does not open, asking again: {e}"
                );
                // A kept record that fails is of no more use: their app has restarted
                if self.live.moved.remove(&from).is_some() {
                    stores.session.take(from);
                }
                self.ask_key(channel_id, from, true, now, out);
            }
        }
    }

    /// Asks a writer for their key, under one budget for all of them, so a raider's junk
    /// posts cannot make every reader send frames in the queue voice shares.
    fn ask_key(&mut self, channel_id: u32, from: u32, reset: bool, now: u64, out: &mut LiveOut) {
        if !self.live.key_wanted_bucket.take(8.0, 1.0, now) {
            return;
        }
        self.live.key_asked.insert(from);
        out.send.push(ClientMessage::KeyWanted {
            channel_id,
            from,
            reset,
        });
    }

    /// A reader lacks our key here. From a round naming them, or else at the current
    /// position; a stale chain answers nothing, and someone it never named gets nothing.
    fn key_wanted(
        &mut self,
        stores: &mut SignalStores,
        channel_id: u32,
        from: u32,
        reset: bool,
        now: u64,
        out: &mut LiveOut,
    ) {
        let Some(w) = self.live.writing.get(&channel_id) else {
            return;
        };
        if w.over(now) || !w.named.contains(&from) || !self.live.wanted_bucket.take(64.0, 2.0, now)
        {
            return;
        }
        out.work = true;
        if reset {
            if self
                .live
                .resets
                .get(&from)
                .is_some_and(|at| now.saturating_sub(*at) < REOPEN_MS)
            {
                return;
            }
            self.live.resets.insert(from, now);
            if stores.session.take(from).is_some() {
                self.live.moved.remove(&from);
                out.gone.push(from);
            }
            self.live.opens.push_back((channel_id, from));
            return;
        }
        let account = self.live.people.get(&from).copied().flatten();
        if self.find_session(stores, from, account, now) {
            self.live.wraps.push_back((channel_id, from));
        } else {
            self.live.opens.push_back((channel_id, from));
        }
    }

    /// A post, held if its key has not come.
    #[allow(clippy::too_many_arguments)]
    fn text_post(
        &mut self,
        stores: &mut SignalStores,
        own_channel: u32,
        channel_id: u32,
        from: u32,
        post: HeldPost,
        out: &mut LiveOut,
    ) {
        if from == stores.own_user_id
            || !self.in_channel(own_channel, channel_id)
            || self.live.quiet.contains(&channel_id)
        {
            return;
        }
        if self.live_note_person(from, post.account) {
            out.seen.push(Seen {
                user_id: from,
                account: post.account,
                name: post.username.clone(),
                identity: stores.identity.identity_of(from).map(<[u8]>::to_vec),
            });
        }
        // Whatever waits from them: a post on a chain whose key is here opens now, and
        // what is held waits for another key than this one.
        match ready(group::decrypt_group_message(
            stores,
            from,
            channel_id,
            &post.ciphertext,
        )) {
            Ok(plain) => {
                out.emit.push((
                    "channel-chat-message",
                    post_event(channel_id, from, &post, &plain),
                ));
                return;
            }
            Err(e) if !group::lacks_key(&e) => {
                tracing::info!(from, channel_id, "a post that cannot open: {e}");
                ring(out, channel_id, from, post.timestamp);
                return;
            }
            Err(_) => {}
        }
        self.hold_post(channel_id, from, post, out);
    }

    fn hold_post(&mut self, channel_id: u32, from: u32, post: HeldPost, out: &mut LiveOut) {
        let size = post.ciphertext.len();
        let held = self.live.held.entry((channel_id, from)).or_default();
        held.posts.push_back(post);
        held.bytes += size;
        self.live.held_bytes += size;
        if held.posts.len() > HOLD_PER_WRITER {
            self.evict_held((channel_id, from), out);
        }
        // The largest holder pays, so a raider's posts do not cost a real writer's
        while self.live.held_bytes > HOLD_BYTES {
            let largest = self
                .live
                .held
                .iter()
                .max_by_key(|(_, held)| held.bytes)
                .map(|(key, _)| *key);
            match largest {
                Some(key) => self.evict_held(key, out),
                None => break,
            }
        }
    }

    fn evict_held(&mut self, key: (u32, u32), out: &mut LiveOut) {
        let Some(held) = self.live.held.get_mut(&key) else {
            return;
        };
        if let Some(post) = held.posts.pop_front() {
            held.bytes -= post.ciphertext.len();
            self.live.held_bytes -= post.ciphertext.len();
            ring(out, key.0, key.1, post.timestamp);
        }
        if held.posts.is_empty() {
            self.live.held.remove(&key);
        }
    }

    /// A key came: whatever it opens, in order. A post from before its position never will.
    fn open_held(
        &mut self,
        stores: &mut SignalStores,
        channel_id: u32,
        from: u32,
        out: &mut LiveOut,
    ) {
        let Some(held) = self.live.held.remove(&(channel_id, from)) else {
            return;
        };
        self.live.held_bytes -= held.bytes;
        let mut left = HeldPosts {
            asked: held.asked,
            ..HeldPosts::default()
        };
        for post in held.posts {
            match ready(group::decrypt_group_message(
                stores,
                from,
                channel_id,
                &post.ciphertext,
            )) {
                Ok(plain) => {
                    let mut event = post_event(channel_id, from, &post, &plain);
                    // It waited: its place among the others is by its own time
                    event["held"] = json!(true);
                    out.emit.push(("channel-chat-message", event));
                }
                Err(e) if group::lacks_key(&e) => {
                    left.bytes += post.ciphertext.len();
                    left.posts.push_back(post);
                }
                Err(_) => ring(out, channel_id, from, post.timestamp),
            }
        }
        if !left.posts.is_empty() {
            self.live.held_bytes += left.bytes;
            self.live.held.insert((channel_id, from), left);
        }
    }

    /// A second's work: posts and rounds that ran out, the key a held post has waited for,
    /// and old session keys going.
    pub fn live_tick(&mut self, stores: &mut SignalStores, now: u64) -> LiveOut {
        let mut out = LiveOut::default();
        // Pages that do not come: what waited is said to be lost, as behind any answer
        while let Some((channel_id, ..)) = self
            .live
            .pin_posts
            .front()
            .filter(|(_, _, at)| now.saturating_sub(*at) >= PIN_POST_WAIT_MS)
        {
            out.emit.push((
                "channel-undelivered",
                json!({ "channel_id": channel_id, "expired": 1 }),
            ));
            self.live.pin_posts.pop_front();
        }
        for (channel_id, w) in &mut self.live.writing {
            w.rounds
                .retain(|round| now.saturating_sub(round.started) < ROUND_LIFE_MS);
            if w.check_out
                .is_some_and(|(at, _)| now.saturating_sub(at) >= CHECK_WAIT_MS)
            {
                w.check_out = None;
                w.owed.clear();
                w.retell = true;
                drop_waiting(w, *channel_id, &mut out);
            }
        }
        let mut asks = Vec::new();
        let mut lost = Vec::new();
        self.live.held.retain(|(channel_id, from), held| {
            while held
                .posts
                .front()
                .is_some_and(|post| now.saturating_sub(post.arrived) >= HOLD_MS)
            {
                if let Some(post) = held.posts.pop_front() {
                    held.bytes -= post.ciphertext.len();
                    lost.push((*channel_id, *from, post.timestamp, post.ciphertext.len()));
                }
            }
            let waited = held
                .posts
                .front()
                .is_some_and(|post| now.saturating_sub(post.arrived) >= KEY_WANTED_AFTER_MS);
            if waited && !held.asked {
                asks.push((*channel_id, *from));
            }
            !held.posts.is_empty()
        });
        for (channel_id, from, timestamp, size) in lost {
            self.live.held_bytes -= size;
            ring(&mut out, channel_id, from, timestamp);
        }
        for (channel_id, from) in asks {
            let before = out.send.len();
            self.ask_key(channel_id, from, false, now, &mut out);
            if out.send.len() > before {
                if let Some(held) = self.live.held.get_mut(&(channel_id, from)) {
                    held.asked = true;
                }
            }
        }
        prekey::retire_session_keys(stores, now);
        if now.saturating_sub(self.live.last_renew) >= RENEW_EVERY_MS {
            self.live.renew_due = true;
        }
        self.live
            .resets
            .retain(|_, at| now.saturating_sub(*at) < REOPEN_MS);
        self.live
            .opened_for
            .retain(|_, at| now.saturating_sub(*at) < REOPEN_MS);
        self.live
            .asked
            .retain(|_, at| now.saturating_sub(*at) < ASK_LIFE_MS);
        self.live
            .sealed_out
            .retain(|_, (_, at)| now.saturating_sub(*at) < SEALED_UNDELIVERED_MS);
        out.work = self.live_has_work();
        out
    }

    /// Whether `live_next_frame` could have something now.
    pub fn live_has_work(&self) -> bool {
        !self.live.pins_wait
            && (!self.live.wraps.is_empty()
                || !self.live.opens.is_empty()
                || !self.live.asks.is_empty()
                || self.live.renew_due
                || self.live.refill_due)
    }

    /// The next key frame, if one may go now. One at a time: `in_call` asks fewer people to
    /// open at once, and the host pauses behind each. `wraps_most`: how many wraps it makes.
    pub fn live_next_frame(
        &mut self,
        stores: &mut SignalStores,
        now: u64,
        in_call: bool,
        wraps_most: usize,
    ) -> Option<ClientMessage> {
        if self.live.pins_wait {
            return None;
        }
        self.next_ask(stores, now)
            .or_else(|| self.next_wraps(stores, now, wraps_most))
            .or_else(|| self.next_opens(now, in_call))
            .or_else(|| self.job_over(stores, now))
    }

    /// A job that is over gets what it put off: one-time keys, then new session keys.
    fn job_over(&mut self, stores: &mut SignalStores, now: u64) -> Option<ClientMessage> {
        if !self.live.wraps.is_empty() || !self.live.opens.is_empty() {
            return None;
        }
        let settled = self.live.awaiting.is_empty()
            || now.saturating_sub(self.live.opens_sent_at) >= JOB_SETTLE_MS;
        if !settled {
            return None;
        }
        if std::mem::take(&mut self.live.refill_due) {
            match prekey::more_prekeys(stores, prekey::PREKEY_REFILL_COUNT) {
                Ok(prekeys) => return Some(ClientMessage::UploadPreKeys { prekeys }),
                Err(e) => tracing::warn!("could not make more pre-keys: {e}"),
            }
        }
        if self.live.renew_due && now.saturating_sub(self.live.last_renew) >= RENEW_GAP_MS {
            self.live.renew_due = false;
            self.live.last_renew = now;
            match prekey::renew_session_keys(stores, now) {
                Ok(frame) => return Some(frame),
                Err(e) => tracing::warn!("could not renew session keys: {e}"),
            }
        }
        None
    }

    fn next_wraps(
        &mut self,
        stores: &mut SignalStores,
        now: u64,
        most: usize,
    ) -> Option<ClientMessage> {
        let own = stores.own_user_id;
        while let Some(&(channel_id, _)) = self.live.wraps.front() {
            let mut keys = Vec::new();
            let mut bytes = 0;
            // Made once per frame, and only if somebody needs it
            let mut current: Option<Zeroizing<Vec<u8>>> = None;
            while let Some(&(channel, id)) = self.live.wraps.front() {
                if channel != channel_id || keys.len() >= most || bytes >= WRAP_FRAME_BYTES {
                    break;
                }
                self.live.wraps.pop_front();
                let Some(w) = self.live.writing.get(&channel) else {
                    continue;
                };
                if w.over(now) || !w.named.contains(&id) {
                    continue;
                }
                let round = w.rounds.iter().rev().find(|round| {
                    round.named.contains(&id) && now.saturating_sub(round.started) < ROUND_LIFE_MS
                });
                let message = match round {
                    Some(round) => round.message.clone(),
                    None => {
                        if current.is_none() {
                            current =
                                ready(group::create_distribution_message(stores, own, channel_id))
                                    .map(Zeroizing::new)
                                    .ok();
                        }
                        match &current {
                            Some(message) => message.clone(),
                            None => continue,
                        }
                    }
                };
                match ready(session::encrypt_message(stores, id, &message)) {
                    Ok((ciphertext, message_type)) => {
                        bytes += ciphertext.len() + 8;
                        keys.push((id, message_type, ciphertext));
                    }
                    Err(e) => {
                        // A record that will not do: they open a new one
                        tracing::info!(id, channel_id, "could not wrap a key: {e}");
                        if stores.session.take(id).is_some() {
                            self.live.moved.remove(&id);
                        }
                        self.live.opens.push_back((channel_id, id));
                    }
                }
            }
            if !keys.is_empty() {
                return Some(ClientMessage::DistributeSenderKeys { channel_id, keys });
            }
        }
        None
    }

    fn next_opens(&mut self, now: u64, in_call: bool) -> Option<ClientMessage> {
        if self.live.opens.is_empty() {
            return None;
        }
        let answered = self.live.awaiting.len() * 2 <= self.live.open_frame;
        if !answered && now.saturating_sub(self.live.opens_sent_at) < OPEN_WAIT_MS {
            return None;
        }
        let most = if in_call {
            OPENS_A_FRAME_IN_CALL
        } else {
            OPENS_A_FRAME
        };
        while let Some(&(channel_id, _)) = self.live.opens.front() {
            let mut targets = Vec::new();
            while let Some(&(channel, id)) = self.live.opens.front() {
                if channel != channel_id || targets.len() >= most {
                    break;
                }
                self.live.opens.pop_front();
                let named = self
                    .live
                    .writing
                    .get(&channel)
                    .is_some_and(|w| !w.over(now) && w.named.contains(&id));
                if named {
                    targets.push(id);
                }
            }
            if !targets.is_empty() {
                self.live.awaiting = targets.iter().copied().collect();
                self.live.open_frame = targets.len();
                self.live.opens_sent_at = now;
                return Some(ClientMessage::OpenSessions {
                    channel_id,
                    targets,
                });
            }
        }
        None
    }

    /// Ask for a channel's recent chat, sealed. Of `targets`, a few at random, which go one
    /// a second. Who they are, for the pane to say.
    pub fn live_ask_history(&mut self, channel_id: u32, targets: &[u32], now: u64) -> Vec<u32> {
        let picked: Vec<u32> = pick_history_sources(targets).into_iter().collect();
        for target in &picked {
            self.live.asks.push_back((*target, channel_id, now));
        }
        picked
    }

    fn next_ask(&mut self, stores: &mut SignalStores, now: u64) -> Option<ClientMessage> {
        if now.saturating_sub(self.live.last_ask) < ASK_EVERY_MS {
            return None;
        }
        let mut waiting = VecDeque::with_capacity(self.live.asks.len());
        let mut frame = None;
        while let Some((target, channel_id, since)) = self.live.asks.pop_front() {
            if frame.is_some() {
                waiting.push_back((target, channel_id, since));
                continue;
            }
            if now.saturating_sub(since) >= ASK_LIFE_MS {
                self.live.bundle_asked.remove(&target);
                continue;
            }
            // Only a session both ends hold: an answer sealed in a stale one is lost for good
            if !stores.session.has(target) || self.live.moved.contains_key(&target) {
                waiting.push_back((target, channel_id, since));
                if self.live.bundle_asked.insert(target) {
                    frame = Some(ClientMessage::RequestPreKeyBundle {
                        target_user_id: target,
                    });
                }
                continue;
            }
            match ready(session::encrypt_message(
                stores,
                target,
                &crate::envelope::sealed_ask(channel_id),
            )) {
                Ok((ciphertext, message_type)) => {
                    self.live.last_ask = now;
                    self.live.bundle_asked.remove(&target);
                    self.live.asked.insert((channel_id, target), now);
                    let sent = self.live.sealed_out.entry(target).or_insert((0, now));
                    *sent = (sent.0 + 1, now);
                    frame = Some(ClientMessage::SendEncryptedDirectMessage {
                        target_user_id: target,
                        ciphertext,
                        message_type,
                    });
                }
                Err(e) => tracing::info!(target, "could not seal an ask: {e}"),
            }
        }
        self.live.asks = waiting;
        frame
    }

    /// A bundle came: whether the live path has something to send over a session with them.
    /// One opened for nothing is the writer's first message waiting to be sent on keys of
    /// theirs that retire within the hour, and on those no message starts. The host adds what
    /// it has queued for them; everyone else has a session opened when there is something to say.
    pub fn live_bundle_wanted(&self, user_id: u32, own_room: u32, now: u64) -> bool {
        (own_room != 0 && self.is_member(own_room, user_id))
            || self.live.asks.iter().any(|(target, _, since)| {
                *target == user_id && now.saturating_sub(*since) < ASK_LIFE_MS
            })
    }

    /// The connection ends: how many posts waited in each channel behind a check, a person's
    /// answer or the pins, showing as sent. They go with it, and the host says so.
    pub fn live_end(&mut self) -> Vec<(u32, usize)> {
        let mut lost: HashMap<u32, usize> = HashMap::new();
        for (channel_id, w) in &mut self.live.writing {
            if !w.waiting.is_empty() {
                *lost.entry(*channel_id).or_default() += w.waiting.len();
                w.waiting.clear();
            }
            w.asking = None;
        }
        for (channel_id, ..) in self.live.pin_posts.drain(..) {
            *lost.entry(channel_id).or_default() += 1;
        }
        let mut lost: Vec<(u32, usize)> = lost.into_iter().collect();
        lost.sort_unstable();
        lost
    }

    /// The relay has no bundle for them: what we meant to ask them goes, without a word.
    pub fn live_no_bundle(&mut self, user_id: u32) {
        self.live.bundle_asked.remove(&user_id);
        self.live.asks.retain(|(target, _, _)| *target != user_id);
    }

    /// An answer to an ask, sealed in the session the ask came through.
    pub fn live_seal_answer(
        &mut self,
        stores: &mut SignalStores,
        channel_id: u32,
        target: u32,
        messages: &Value,
        now: u64,
    ) -> anyhow::Result<ClientMessage> {
        anyhow::ensure!(!self.live.pins_wait, "the pins are not in yet");
        let payload = crate::envelope::sealed_answer(channel_id, messages);
        anyhow::ensure!(
            payload.len() <= voipc_protocol::codec::MAX_RELAY_CIPHERTEXT,
            "history payload too large"
        );
        let (ciphertext, message_type) = ready(session::encrypt_message(stores, target, &payload))?;
        let sent = self.live.sealed_out.entry(target).or_insert((0, now));
        *sent = (sent.0 + 1, now);
        Ok(ClientMessage::SendEncryptedDirectMessage {
            target_user_id: target,
            ciphertext,
            message_type,
        })
    }

    /// Whether an answer from `from` is one we asked for, which it uses up. Anyone else's
    /// second-hand rows are an injection, which `members` on a live path cannot stop.
    pub fn live_answer_wanted(&mut self, channel_id: u32, from: u32, now: u64) -> bool {
        self.live
            .asked
            .remove(&(channel_id, from))
            .is_some_and(|at| now.saturating_sub(at) < ASK_LIFE_MS)
    }

    /// A plain ask went for this channel (the new-member wait refuses a sealed one).
    pub fn live_note_asked(&mut self, channel_id: u32, from: u32, now: u64) {
        self.live.asked.insert((channel_id, from), now);
    }

    /// Whether the relay's "not delivered" is about a hand-off, which nobody is to see.
    pub fn live_undelivered_was_sealed(&mut self, target: u32, now: u64) -> bool {
        let Some((count, at)) = self.live.sealed_out.get_mut(&target) else {
            return false;
        };
        if now.saturating_sub(*at) >= SEALED_UNDELIVERED_MS || *count == 0 {
            return false;
        }
        *count -= 1;
        true
    }
}

/// The frames a host holds while the pages of pins are out: each opens a pairwise message or
/// starts a session, and what comes of it goes by a pin not read yet. A key taken in now is
/// warned of only later, so a person would read or answer a swapped key with no warning. Held,
/// each is opened and checked when the pins are in, and a warning still comes first.
pub fn waits_for_pins(msg: &ServerMessage) -> bool {
    matches!(
        msg,
        ServerMessage::PreKeyBundle { .. }
            | ServerMessage::EncryptedDirectChatMessage { .. }
            | ServerMessage::PokeReceived { .. }
            | ServerMessage::ChannelHistoryRequested { .. }
            | ServerMessage::ChannelHistoryReceived { .. }
            | ServerMessage::SenderKeyReceived { .. }
            | ServerMessage::MediaKeyReceived { .. }
    )
}

fn post_frame(
    stores: &mut SignalStores,
    channel_id: u32,
    payload: &[u8],
) -> Result<ClientMessage, String> {
    let own = stores.own_user_id;
    let ciphertext = ready(group::encrypt_group_message(
        stores, own, channel_id, payload,
    ))
    .map_err(|e| format!("group encryption: {e}"))?;
    Ok(ClientMessage::SendEncryptedChannelMessage {
        channel_id,
        ciphertext,
    })
}

/// Posts that will not go: they showed as sent, so it is said.
fn drop_waiting(w: &mut Writing, channel_id: u32, out: &mut LiveOut) {
    let expired = w.waiting.len();
    w.waiting.clear();
    if expired > 0 {
        out.emit.push((
            "channel-undelivered",
            json!({ "channel_id": channel_id, "expired": expired }),
        ));
    }
}

fn warn_of(out: &mut LiveOut, kind: &str, channel_id: u32) {
    out.emit.push((
        "key-warning",
        json!({ "kind": kind, "channel_id": channel_id }),
    ));
}

/// Someone wrote here and we will not read it: all a row can honestly show.
fn ring(out: &mut LiveOut, channel_id: u32, from: u32, timestamp: u64) {
    out.emit.push((
        "channel-ring",
        json!({ "channel_id": channel_id, "from_user_id": from, "timestamp": timestamp }),
    ));
}

/// A post as the front end takes it, with what it would otherwise read off a roster.
fn post_event(channel_id: u32, from: u32, post: &HeldPost, plain: &[u8]) -> Value {
    let msg = crate::envelope::open_envelope(plain);
    json!({
        "channel_id": channel_id,
        "user_id": from,
        "username": post.username,
        "account": post.account,
        "is_admin": post.is_admin,
        "is_moderator": post.is_moderator,
        "content": msg.text,
        "timestamp": post.timestamp,
        "message_id": msg.id,
        "ttl_secs": msg.ttl_secs,
        "reply_to": msg.extras.reply,
        "thread": msg.extras.thread,
        "file": msg.extras.file,
        "fwd": msg.extras.fwd,
        "event": msg.extras.event,
        "encrypted": true,
    })
}

/// How long a session with an account stays in memory, from when it was made.
const KEPT_MS: u64 = 7 * 24 * 60 * 60 * 1000;
/// How many, least recently used out.
const KEPT_MAX: usize = 5000;

/// One kept session: its record, when the session was made, when it was last in use.
struct KeptSession {
    record: Zeroizing<Vec<u8>>,
    born: u64,
    used: u64,
}

/// Sessions with accounts, kept in memory across a reconnect, by peer account alone: user
/// ids change, the identity keys a session's MAC binds do not. Both apps up, and a writer's
/// return costs 176 B a reader, not a new session. A reader that restarted fails the
/// wrap, and heals by one reset. Never on disk, wiped at sign-out, none for a guest.
#[derive(Default)]
pub struct KeptSessions {
    rows: HashMap<[u8; 16], KeptSession>,
}

impl KeptSessions {
    fn put(&mut self, account: [u8; 16], record: &[u8], born: u64, now: u64) {
        self.rows.insert(
            account,
            KeptSession {
                record: Zeroizing::new(record.to_vec()),
                born,
                used: now,
            },
        );
    }

    fn holds(&self, account: &[u8; 16], now: u64) -> bool {
        self.rows
            .get(account)
            .is_some_and(|row| now.saturating_sub(row.born) < KEPT_MS)
    }

    /// The record, out of here, and when its session was made. None past its week.
    fn take(&mut self, account: &[u8; 16], now: u64) -> Option<(Vec<u8>, u64)> {
        let row = self.rows.remove(account)?;
        (now.saturating_sub(row.born) < KEPT_MS).then(|| (row.record.to_vec(), row.born))
    }

    fn trim(&mut self, now: u64) {
        self.rows
            .retain(|_, row| now.saturating_sub(row.born) < KEPT_MS);
        if self.rows.len() > KEPT_MAX {
            let mut by_use: Vec<([u8; 16], u64)> =
                self.rows.iter().map(|(a, row)| (*a, row.used)).collect();
            by_use.sort_unstable_by_key(|(_, used)| *used);
            for (account, _) in &by_use[..by_use.len() - KEPT_MAX] {
                self.rows.remove(account);
            }
        }
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keying() -> ChannelKeying {
        let mut k = ChannelKeying::default();
        k.join_text(7);
        k.set_members(7, [1, 2]);
        k.set_members(5, [1, 3]); // the voice channel we stand in
        k
    }

    #[test]
    fn a_stranger_in_a_channel_we_are_in_is_not_one_of_its_members() {
        let k = keying();
        assert!(
            k.shares_channel_with(5, 7, 2),
            "a member of a text channel we are in"
        );
        assert!(
            k.shares_channel_with(5, 5, 3),
            "a member of the room we stand in"
        );
        assert!(
            !k.shares_channel_with(5, 7, 9),
            "a stranger the relay names"
        );
        assert!(
            !k.shares_channel_with(5, 8, 1),
            "a channel we are not in at all"
        );
    }

    #[test]
    fn leaving_a_channel_does_not_cancel_a_pending_rotation() {
        let mut k = keying();
        k.record_distributed(7, 2);
        k.note_stale(7);
        // Somebody leaves, then we leave before writing anything.
        k.forget_channel(None, 1, 7);
        // Re-subscribing must not find the old chain waiting to be reused.
        assert!(k.join_text(7), "re-joining is a fresh subscription");
        assert!(!k.has_distributed(7, 2));
        assert!(k.take_rotation_targets(None, 1, 7).is_empty());
    }

    #[test]
    fn a_rotation_with_nobody_left_to_tell_still_happens() {
        let mut k = keying();
        k.record_distributed(7, 2);
        k.note_stale(7);
        k.drop_member(7, 2); // the only holder of our key was the one who left
        assert!(k.take_rotation_targets(None, 1, 7).is_empty());
        // The flag is consumed either way; what matters is that it was consumed
        // by a rotation and not by an early return.
        assert!(k.take_rotation_targets(None, 1, 7).is_empty());
    }

    #[test]
    fn the_lowest_remaining_member_mints_the_next_media_key() {
        let mut k = keying();
        assert_eq!(k.media_key_minter(5), Some(1));
        k.drop_member(5, 1);
        assert_eq!(k.media_key_minter(5), Some(3));
        k.drop_member(5, 3);
        assert_eq!(k.media_key_minter(5), None);
    }

    #[test]
    fn history_is_asked_of_at_most_three_sharers() {
        let roster = [(1, true), (2, false), (3, true), (4, true), (5, true)];
        let who = history_sources(&roster, 1);
        assert_eq!(who.len(), HISTORY_SOURCES);
        assert!(!who.contains(&1), "never ourselves");
        assert!(!who.contains(&2), "never somebody who does not share");
        // Fewer sharers than the cap is the whole list, not an error
        assert_eq!(
            history_sources(&[(1, true), (9, true)], 1),
            HashSet::from([9])
        );
        assert!(history_sources(&roster, 9).len() == HISTORY_SOURCES);
    }

    /// Every client holds the roster in the same order, so taking the first
    /// few would aim a reconnecting server's every request at the same people.
    #[test]
    fn the_members_asked_are_not_always_the_first_ones() {
        let sharers: Vec<u32> = (1..=20).collect();
        let mut seen = HashSet::new();
        for _ in 0..50 {
            seen.extend(pick_history_sources(&sharers));
        }
        assert!(seen.len() > HISTORY_SOURCES, "always the same {seen:?}");
    }

    #[test]
    fn each_member_is_asked_for_history_once() {
        let mut k = keying();
        k.want_history_from(7, HashSet::from([2]));
        assert!(k.take_history_wanted(7, 2));
        assert!(!k.take_history_wanted(7, 2));
    }

    /// The live path, between real devices with real libsignal: `Net` stands in for the
    /// relay, which `voipc-server`'s `live_path` tests hold to the same frames.
    mod live {
        use super::*;
        use libsignal_protocol::IdentityKeyPair;
        use std::collections::BTreeMap;
        use voipc_protocol::types::OneTimePreKey;

        const CH: u32 = 7;

        struct Device {
            identity: IdentityKeyPair,
            stores: SignalStores,
            k: ChannelKeying,
            account: Option<[u8; 16]>,
            inbox: VecDeque<ServerMessage>,
            emitted: Vec<(&'static str, Value)>,
            sent: Vec<ClientMessage>,
            made: Vec<u32>,
            gone: Vec<u32>,
            checked: Vec<u32>,
        }

        impl Device {
            fn new(id: u32, account: Option<[u8; 16]>, identity: IdentityKeyPair) -> Device {
                let mut stores = SignalStores::new(&identity, 1000 + id);
                prekey::generate_prekeys(&mut stores, &identity).unwrap();
                stores.own_user_id = id;
                let mut k = ChannelKeying::default();
                k.live_start(0);
                k.join_text(CH);
                Device {
                    identity,
                    stores,
                    k,
                    account,
                    inbox: VecDeque::new(),
                    emitted: Vec::new(),
                    sent: Vec::new(),
                    made: Vec::new(),
                    gone: Vec::new(),
                    checked: Vec::new(),
                }
            }

            /// The messages shown here, in order.
            fn shown(&self) -> Vec<String> {
                self.emitted
                    .iter()
                    .filter(|(name, _)| *name == "channel-chat-message")
                    .map(|(_, v)| v["content"].as_str().unwrap().to_string())
                    .collect()
            }

            fn events(&self, name: &str) -> usize {
                self.emitted.iter().filter(|(n, _)| *n == name).count()
            }

            fn wrote(&self, what: fn(&ClientMessage) -> bool) -> usize {
                self.sent.iter().filter(|m| what(m)).count()
            }
        }

        fn is_check(m: &ClientMessage) -> bool {
            matches!(m, ClientMessage::KeyCheck { .. })
        }
        fn is_post(m: &ClientMessage) -> bool {
            matches!(m, ClientMessage::SendEncryptedChannelMessage { .. })
        }
        fn is_wraps(m: &ClientMessage) -> bool {
            matches!(m, ClientMessage::DistributeSenderKeys { .. })
        }
        fn is_open(m: &ClientMessage) -> bool {
            matches!(m, ClientMessage::OpenSessions { .. })
        }
        fn is_hello(m: &ClientMessage) -> bool {
            matches!(m, ClientMessage::SessionHello { .. })
        }
        fn is_wanted(m: &ClientMessage) -> bool {
            matches!(m, ClientMessage::KeyWanted { .. })
        }
        fn is_renewal(m: &ClientMessage) -> bool {
            matches!(m, ClientMessage::RenewSessionKeys { .. })
        }

        /// A relay, as much of it as these tests need: followers of `CH`, how far each writer
        /// has named them, and every frame passed on as it should be.
        #[derive(Default)]
        struct Net {
            devices: BTreeMap<u32, Device>,
            now: u64,
            /// Writer -> who a post of theirs reaches.
            keyed: HashMap<u32, HashSet<u32>>,
            /// Whom `KeyCheck` names on top of everyone, and who it leaves out: the relay's word.
            also_names: Vec<u32>,
            leaves_out: Vec<u32>,
            refuses_checks: bool,
            /// Frames held back from reaching anyone, to send later or never.
            hold_wraps: bool,
            held_wraps: Vec<(u32, ClientMessage)>,
            hold_hellos: bool,
            drop_opens: bool,
            /// One-time keys handed out, by whose and which.
            handed: HashSet<(u32, u32)>,
        }

        impl Net {
            fn with(ids: &[u32]) -> Net {
                let mut net = Net::default();
                for id in ids {
                    net.add(*id, Some([*id as u8; 16]));
                }
                net.list_everyone();
                net
            }

            fn add(&mut self, id: u32, account: Option<[u8; 16]>) {
                let identity = crate::generate_identity_key_pair();
                self.devices.insert(id, Device::new(id, account, identity));
            }

            /// What General's list tells everyone.
            fn list_everyone(&mut self) {
                let people: Vec<(u32, Option<[u8; 16]>)> = self
                    .devices
                    .iter()
                    .map(|(id, d)| (*id, d.account))
                    .collect();
                for d in self.devices.values_mut() {
                    for (id, account) in &people {
                        d.k.live_note_person(*id, *account);
                    }
                }
            }

            fn post(&mut self, from: u32, text: &str) {
                let now = self.now;
                let d = self.devices.get_mut(&from).unwrap();
                let payload = crate::envelope::envelope("id", text, None);
                let out = d.k.live_post(&mut d.stores, CH, payload, now).unwrap();
                self.apply(from, out);
            }

            fn apply(&mut self, id: u32, out: LiveOut) {
                let d = self.devices.get_mut(&id).unwrap();
                d.emitted.extend(out.emit);
                d.made.extend(out.made);
                d.gone.extend(out.gone);
                d.checked.extend(out.check.iter().map(|(who, _)| *who));
                d.sent.extend(out.send.iter().cloned());
                for msg in out.send {
                    self.deliver(id, msg);
                }
            }

            fn tell(&mut self, to: u32, msg: ServerMessage) {
                if let Some(d) = self.devices.get_mut(&to) {
                    d.inbox.push_back(msg);
                }
            }

            fn deliver(&mut self, from: u32, msg: ClientMessage) {
                match msg {
                    ClientMessage::KeyCheck {
                        channel_id,
                        restart,
                    } => {
                        if self.refuses_checks {
                            self.tell(
                                from,
                                ServerMessage::KeysOwed {
                                    channel_id,
                                    ids: vec![],
                                    rows: vec![],
                                    more: false,
                                    refused: true,
                                },
                            );
                            return;
                        }
                        let keyed = self.keyed.entry(from).or_default();
                        if restart {
                            keyed.clear();
                        }
                        let mut ids: Vec<u32> = self
                            .devices
                            .keys()
                            .copied()
                            .chain(self.also_names.iter().copied())
                            .filter(|id| {
                                *id != from && !keyed.contains(id) && !self.leaves_out.contains(id)
                            })
                            .collect();
                        ids.sort_unstable();
                        ids.dedup();
                        keyed.extend(ids.iter().copied());
                        self.tell(
                            from,
                            ServerMessage::KeysOwed {
                                channel_id,
                                ids,
                                rows: vec![],
                                more: false,
                                refused: false,
                            },
                        );
                    }
                    ClientMessage::SendEncryptedChannelMessage {
                        channel_id,
                        ciphertext,
                    } => {
                        let readers: Vec<u32> = self
                            .keyed
                            .get(&from)
                            .map(|k| k.iter().copied().collect())
                            .unwrap_or_default();
                        let (username, account) = {
                            let d = &self.devices[&from];
                            (format!("user{from}"), d.account)
                        };
                        let timestamp = self.now;
                        for reader in readers {
                            self.tell(
                                reader,
                                ServerMessage::TextPost {
                                    channel_id,
                                    user_id: from,
                                    username: username.clone(),
                                    account,
                                    is_admin: false,
                                    is_moderator: false,
                                    ciphertext: ciphertext.clone(),
                                    timestamp,
                                },
                            );
                        }
                    }
                    ClientMessage::OpenSessions {
                        channel_id,
                        targets,
                    } => {
                        if self.drop_opens {
                            return;
                        }
                        for target in targets {
                            let (mut bundle, account) = {
                                let d = &self.devices[&from];
                                (prekey::bundle(&d.stores).unwrap(), d.account)
                            };
                            // One one-time key at most, each once, as the relay hands out
                            let handed = &mut self.handed;
                            let one: Vec<OneTimePreKey> = bundle
                                .prekeys
                                .drain(..)
                                .filter(|k| handed.insert((from, k.id)))
                                .take(1)
                                .collect();
                            bundle.prekeys = one;
                            self.tell(
                                target,
                                ServerMessage::SessionAsked {
                                    channel_id,
                                    from,
                                    account,
                                    name: format!("user{from}"),
                                    bundle,
                                },
                            );
                        }
                    }
                    ClientMessage::SessionHello {
                        to,
                        message_type,
                        ciphertext,
                    } => {
                        if self.hold_hellos {
                            return;
                        }
                        self.tell(
                            to,
                            ServerMessage::SessionHello {
                                from,
                                message_type,
                                ciphertext,
                            },
                        );
                    }
                    ClientMessage::DistributeSenderKeys { channel_id, keys } => {
                        if self.hold_wraps {
                            self.held_wraps.push((
                                from,
                                ClientMessage::DistributeSenderKeys { channel_id, keys },
                            ));
                            return;
                        }
                        let account = self.devices[&from].account;
                        for (target, message_type, ciphertext) in keys {
                            self.tell(
                                target,
                                ServerMessage::TextKeyReceived {
                                    channel_id,
                                    from,
                                    account,
                                    message_type,
                                    ciphertext,
                                },
                            );
                        }
                    }
                    ClientMessage::KeyWanted {
                        channel_id,
                        from: writer,
                        reset,
                    } => self.tell(
                        writer,
                        ServerMessage::KeyWanted {
                            channel_id,
                            from,
                            reset,
                        },
                    ),
                    _ => {}
                }
            }

            /// Lets go of the wraps held back.
            fn release_wraps(&mut self) {
                self.hold_wraps = false;
                for (from, msg) in std::mem::take(&mut self.held_wraps) {
                    self.deliver(from, msg);
                }
            }

            fn pump(&mut self) {
                loop {
                    let mut moved = false;
                    let ids: Vec<u32> = self.devices.keys().copied().collect();
                    for id in ids {
                        let now = self.now;
                        while let Some(msg) = self.devices.get_mut(&id).unwrap().inbox.pop_front() {
                            moved = true;
                            let d = self.devices.get_mut(&id).unwrap();
                            let out = d.k.live_frame(&mut d.stores, 0, &msg, now);
                            self.apply(id, out);
                        }
                        loop {
                            let d = self.devices.get_mut(&id).unwrap();
                            let Some(frame) =
                                d.k.live_next_frame(&mut d.stores, now, false, WRAPS_A_FRAME)
                            else {
                                break;
                            };
                            moved = true;
                            d.sent.push(frame.clone());
                            self.deliver(id, frame);
                        }
                    }
                    if !moved {
                        return;
                    }
                }
            }

            fn tick(&mut self) {
                let now = self.now;
                let ids: Vec<u32> = self.devices.keys().copied().collect();
                for id in ids {
                    let d = self.devices.get_mut(&id).unwrap();
                    let out = d.k.live_tick(&mut d.stores, now);
                    self.apply(id, out);
                }
                self.pump();
            }

            /// `id`'s app comes back under `new`, as a reconnect does: a new id, new stores,
            /// everyone's chains gone, and what it kept handed over.
            fn reconnect(&mut self, id: u32, new: u32, keep: bool) {
                let now = self.now;
                let mut old = self.devices.remove(&id).unwrap();
                let kept = old.k.live_keep_sessions(&old.stores, now);
                let mut d = Device::new(new, old.account, old.identity);
                if keep {
                    d.k.live_adopt_kept(kept);
                }
                d.k.live_start(now);
                self.devices.insert(new, d);
                self.keyed.remove(&id);
                for keyed in self.keyed.values_mut() {
                    keyed.remove(&id);
                }
                self.list_everyone();
            }
        }

        // ── Sessions, against the real thing ────────────────────────────────

        /// The reason a reader opens the session, in libsignal's own behaviour: whoever
        /// starts one sends the whole Kyber ciphertext until the peer's first answer, and a
        /// reader never writes. So a writer-opened session never stops costing 1.9 KB.
        #[test]
        fn a_reader_who_never_answers_keeps_the_writer_on_pre_key_messages() {
            let mut net = Net::with(&[1, 2]);
            let bundle = prekey::bundle(&net.devices[&2].stores).unwrap();
            let w = net.devices.get_mut(&1).unwrap();
            ready(session::establish_session(&mut w.stores, 2, &bundle)).unwrap();
            for _ in 0..3 {
                let (ct, kind) =
                    ready(session::encrypt_message(&mut w.stores, 2, b"a key")).unwrap();
                assert_eq!(kind, 1);
                assert!(ct.len() > 1500, "{}", ct.len());
            }
        }

        #[test]
        fn a_reader_opened_session_wraps_short_from_the_first() {
            let mut net = Net::with(&[1, 2]);
            net.post(1, "hi");
            net.pump();
            let wraps: Vec<&ClientMessage> = net.devices[&1]
                .sent
                .iter()
                .filter(|m| is_wraps(m))
                .collect();
            assert_eq!(wraps.len(), 1);
            let ClientMessage::DistributeSenderKeys { keys, .. } = wraps[0] else {
                unreachable!()
            };
            let (_, kind, ct) = &keys[0];
            assert_eq!(*kind, 2, "no Kyber ciphertext on the writer's side");
            assert!(ct.len() < 400, "{} bytes", ct.len());
            assert_eq!(net.devices[&2].shown(), vec!["hi"]);
            assert_eq!(net.devices[&2].made, vec![1], "a session a DM may use");
            assert_eq!(net.devices[&1].made, vec![2]);
        }

        /// A session moved to a peer's new id: libsignal binds no address for `user_N`.
        #[test]
        fn a_session_moved_to_a_new_id_still_opens() {
            let mut net = Net::with(&[1, 2]);
            net.post(1, "first");
            net.pump();
            // Both apps stayed up, and the relay restarted: both ids change
            net.reconnect(1, 11, true);
            net.reconnect(2, 12, true);
            net.devices.get_mut(&12).unwrap().k.join_text(CH);
            net.post(11, "second");
            net.pump();
            let w = &net.devices[&11];
            assert_eq!(w.wrote(is_open), 0, "no bundle: found by account");
            let ClientMessage::DistributeSenderKeys { keys, .. } =
                w.sent.iter().find(|m| is_wraps(m)).unwrap()
            else {
                unreachable!()
            };
            assert_eq!(keys[0].1, 2);
            assert!(keys[0].2.len() < 400);
            assert_eq!(net.devices[&12].shown(), vec!["second"]);
            // And neither is a session a direct message may read
            assert!(net.devices[&12].made.is_empty());
            assert!(net.devices[&11].made.is_empty());
        }

        /// Only the reader's app went away and came back: the writer stayed, and its session
        /// is under the id they had. Found by account all the same.
        #[test]
        fn a_reader_back_under_a_new_id_is_found_by_account() {
            let mut net = Net::with(&[1, 2]);
            net.post(1, "first");
            net.pump();
            net.reconnect(2, 12, true);
            net.devices.get_mut(&12).unwrap().k.join_text(CH);
            net.now += chain_age_limit(1);
            net.post(1, "second");
            net.pump();
            let w = &net.devices[&1];
            assert_eq!(w.wrote(is_open), 1, "only the first time");
            assert!(w.k.live.moved.contains_key(&12), "a key's alone");
            assert_eq!(net.devices[&12].shown(), vec!["second"]);
            assert_eq!(net.devices[&12].wrote(is_hello), 0);
        }

        /// A reader back, or new, just after a writer's check reads the writer's next post,
        /// however soon it comes: a post reaches only whom its writer has been told of, and a
        /// later key cannot open an earlier post. CI run 42696335107: fay, back from a reload
        /// 0.1 s after annika's and bobby's last checks, never saw their posts 1.1 s later.
        #[test]
        fn a_reader_back_just_after_a_check_reads_the_next_post() {
            let mut net = Net::with(&[1, 2]);
            net.post(1, "first");
            net.pump();
            net.reconnect(2, 12, false);
            net.devices.get_mut(&12).unwrap().k.join_text(CH);
            net.now += 1_000;
            net.post(1, "second");
            net.pump();
            assert_eq!(net.devices[&12].shown(), vec!["second"]);
        }

        /// A guest has no account to be found by: a new id is someone new.
        #[test]
        fn a_guest_back_under_a_new_id_is_someone_new() {
            let mut net = Net::with(&[1]);
            net.add(2, None);
            net.list_everyone();
            net.post(1, "first");
            net.pump();
            net.reconnect(2, 12, false);
            net.devices.get_mut(&12).unwrap().k.join_text(CH);
            net.now += chain_age_limit(1);
            net.post(1, "second");
            net.pump();
            assert_eq!(net.devices[&1].wrote(is_open), 2);
            assert_eq!(net.devices[&12].wrote(is_hello), 1);
            assert_eq!(net.devices[&12].shown(), vec!["second"]);
        }

        #[test]
        fn a_late_wrap_opens_a_post_sent_before_it() {
            let mut net = Net::with(&[1, 2]);
            net.hold_wraps = true;
            net.post(1, "written before the key arrived");
            net.pump();
            assert!(
                net.devices[&2].shown().is_empty(),
                "held, and nothing on screen"
            );
            assert_eq!(net.devices[&2].events("channel-ring"), 0, "and no mark");
            net.release_wraps();
            net.pump();
            assert_eq!(
                net.devices[&2].shown(),
                vec!["written before the key arrived"]
            );
            let post = net.devices[&2]
                .emitted
                .iter()
                .find(|(name, _)| *name == "channel-chat-message")
                .map(|(_, v)| v.clone())
                .unwrap();
            assert_eq!(post["held"], true, "so it goes in at its own time");
        }

        /// A post that needed no wait says nothing of the kind.
        #[test]
        fn a_post_with_its_key_here_did_not_wait() {
            let mut net = Net::with(&[1, 2]);
            net.post(1, "first");
            net.pump();
            net.now += 3000;
            net.post(1, "second");
            net.pump();
            let posts: Vec<&Value> = net.devices[&2]
                .emitted
                .iter()
                .filter(|(name, _)| *name == "channel-chat-message")
                .map(|(_, v)| v)
                .collect();
            assert_eq!(posts.len(), 2);
            assert!(posts[1].get("held").is_none(), "{:?}", posts[1]);
        }

        /// Only the writer's device hands out a key, so it says to whom.
        #[test]
        fn a_writer_names_whom_it_hands_a_key_to() {
            let mut net = Net::with(&[1, 2, 3]);
            net.post(1, "hi");
            net.pump();
            let readers: Vec<&Value> = net.devices[&1]
                .emitted
                .iter()
                .filter(|(name, _)| *name == "key-readers")
                .map(|(_, v)| v)
                .collect();
            assert_eq!(readers.len(), 1);
            assert_eq!(readers[0]["channel_id"], CH);
            let named = readers[0]["readers"].as_array().unwrap();
            assert_eq!(named.len(), 2);
            assert!(
                named
                    .iter()
                    .all(|r| r["account"].is_array() && r["user_id"].is_u64()),
                "{named:?}"
            );
            assert_eq!(
                net.devices[&2].events("key-readers"),
                0,
                "a reader names nobody"
            );
        }

        /// Post first: the person's message is not what waits for the wraps.
        #[test]
        fn the_post_goes_before_the_keys() {
            let mut net = Net::with(&[1, 2, 3]);
            net.post(1, "hi");
            net.pump();
            let sent = &net.devices[&1].sent;
            let post = sent.iter().position(is_post).unwrap();
            let open = sent.iter().position(is_open).unwrap();
            let wraps = sent.iter().position(is_wraps).unwrap();
            assert!(post < open && post < wraps, "{sent:?}");
        }

        #[test]
        fn a_later_round_cannot_read_an_earlier_post() {
            let mut net = Net::with(&[1, 2]);
            net.post(1, "before you came");
            net.pump();
            // Recorded by the relay, and offered to someone named later
            let earlier = net.devices[&1]
                .sent
                .iter()
                .find_map(|m| match m {
                    ClientMessage::SendEncryptedChannelMessage { ciphertext, .. } => {
                        Some(ciphertext.clone())
                    }
                    _ => None,
                })
                .unwrap();
            net.add(3, Some([3; 16]));
            net.list_everyone();
            net.now += 2_000;
            net.post(1, "after");
            net.pump();
            assert_eq!(net.devices[&3].shown(), vec!["after"]);
            let timestamp = net.now;
            net.tell(
                3,
                ServerMessage::TextPost {
                    channel_id: CH,
                    user_id: 1,
                    username: "user1".into(),
                    account: Some([1; 16]),
                    is_admin: false,
                    is_moderator: false,
                    ciphertext: earlier,
                    timestamp,
                },
            );
            net.pump();
            assert_eq!(
                net.devices[&3].shown(),
                vec!["after"],
                "nothing further back"
            );
            assert_eq!(net.devices[&3].events("channel-ring"), 1);
        }

        #[test]
        fn two_people_opening_each_other_at_once_both_read() {
            let mut net = Net::with(&[1, 2]);
            net.post(1, "from one");
            net.post(2, "from two");
            net.pump();
            assert_eq!(net.devices[&1].shown(), vec!["from two"]);
            assert_eq!(net.devices[&2].shown(), vec!["from one"]);
            // And what follows on either side still opens
            net.now += 2_000;
            net.post(1, "again from one");
            net.post(2, "again from two");
            net.pump();
            assert_eq!(net.devices[&1].shown(), vec!["from two", "again from two"]);
            assert_eq!(net.devices[&2].shown(), vec!["from one", "again from one"]);
        }

        // ── Rounds ──────────────────────────────────────────────────────────

        #[test]
        fn a_round_ends_at_sixty_seconds_and_with_its_chain() {
            let mut net = Net::with(&[1, 2]);
            net.post(1, "hi");
            let w = net.devices.get_mut(&1).unwrap();
            assert_eq!(w.k.live.writing[&CH].rounds.len(), 0, "not till the answer");
            net.pump();
            let w = net.devices.get_mut(&1).unwrap();
            assert_eq!(w.k.live.writing[&CH].rounds.len(), 1);
            net.now = ROUND_LIFE_MS - 1;
            net.tick();
            assert_eq!(net.devices[&1].k.live.writing[&CH].rounds.len(), 1);
            net.now = ROUND_LIFE_MS;
            net.tick();
            assert_eq!(net.devices[&1].k.live.writing[&CH].rounds.len(), 0);

            // With its chain: a new round, then the chain ends, and the round with it
            net.post(1, "again");
            net.pump();
            let w = net.devices.get_mut(&1).unwrap();
            let chain_key_gone_at = w.k.live.writing[&CH].started.unwrap() + chain_age_limit(1);
            net.now = chain_key_gone_at;
            net.post(1, "on a new chain");
            let w = &net.devices[&1];
            assert!(w.k.live.writing[&CH].rounds.is_empty(), "forgotten at once");
            assert!(!w.k.live.writing[&CH].named.contains(&2));
        }

        /// The attack's rule for a key past its round: at the current position, so the post
        /// they missed stays missed, and it is a ring.
        #[test]
        fn past_a_round_a_late_person_gets_the_current_position() {
            let mut net = Net::with(&[1, 2]);
            net.hold_wraps = true;
            net.post(1, "held too long");
            net.pump();
            // A chain with enough readers to outlive its round
            let w = net.devices.get_mut(&1).unwrap().k.live.writing.get_mut(&CH);
            w.unwrap().named.extend(100..200);
            net.now = ROUND_LIFE_MS + 1;
            net.tick();
            assert_eq!(net.devices[&2].events("channel-ring"), 1);
            // The chain's key, at its current position: past the post it never read
            net.post(1, "still on this chain");
            net.pump();
            net.held_wraps.clear();
            net.hold_wraps = false;
            net.tell(
                1,
                ServerMessage::KeyWanted {
                    channel_id: CH,
                    from: 2,
                    reset: false,
                },
            );
            net.pump();
            let d = &net.devices[&2];
            assert_eq!(
                d.shown(),
                Vec::<String>::new(),
                "it too went before the key"
            );
            assert_eq!(d.events("channel-ring"), 2);
            net.now += 2_000;
            net.post(1, "after the key");
            net.pump();
            assert_eq!(net.devices[&2].shown(), vec!["after the key"]);
        }

        /// A restarted reader: the wrap fails, it asks for a reset, the writer asks it to
        /// open, and the round it was named in brings the post back.
        #[test]
        fn a_failed_wrap_still_brings_back_the_post() {
            let mut net = Net::with(&[1, 2]);
            net.post(1, "first");
            net.pump();
            net.now += 4_000;
            // The reader restarted: same id here, nothing kept
            net.reconnect(2, 2, false);
            net.devices
                .get_mut(&1)
                .unwrap()
                .k
                .live
                .writing
                .get_mut(&CH)
                .unwrap()
                .exited = true;
            net.keyed.remove(&1);
            net.now += chain_age_limit(1);
            net.post(1, "second");
            net.pump();
            let reader = &net.devices[&2];
            assert_eq!(reader.shown(), vec!["second"]);
            assert_eq!(reader.wrote(is_wanted), 1, "one reset");
            assert!(reader
                .sent
                .iter()
                .any(|m| matches!(m, ClientMessage::KeyWanted { reset: true, .. })));
            assert_eq!(net.devices[&1].gone, vec![2], "its record dropped");
        }

        /// The replacement for a device tag: nobody is told of a restart until it shows, and
        /// the control: a reader who did not restart sends nothing.
        #[test]
        fn a_restarted_reader_heals_by_one_reset() {
            let mut net = Net::with(&[1, 2, 3]);
            net.post(1, "first");
            net.pump();
            net.reconnect(3, 3, false);
            net.now += 2 * chain_age_limit(2);
            net.keyed.remove(&1);
            net.post(1, "second");
            net.pump();
            assert_eq!(net.devices[&3].shown(), vec!["second"]);
            assert_eq!(net.devices[&3].wrote(is_wanted), 1);
            assert_eq!(net.devices[&2].shown(), vec!["first", "second"]);
            assert_eq!(net.devices[&2].wrote(is_wanted), 0);
        }

        #[test]
        fn a_stale_chain_answers_no_hello_and_no_key_wanted() {
            let mut net = Net::with(&[1, 2, 3]);
            net.hold_hellos = true;
            net.post(1, "hi");
            net.pump();
            net.hold_hellos = false;
            // Someone left, and the gap has passed: the old key goes to nobody now
            net.tell(1, ServerMessage::ChannelExits { channels: vec![CH] });
            net.now += exit_gap(2);
            net.pump();
            let before = net.devices[&1].wrote(is_wraps);
            net.tell(
                1,
                ServerMessage::KeyWanted {
                    channel_id: CH,
                    from: 2,
                    reset: false,
                },
            );
            net.pump();
            assert_eq!(net.devices[&1].wrote(is_wraps), before, "KeyWanted");
            assert_eq!(net.devices[&1].wrote(is_open), 1, "no second ask either");

            // A hello that gets there now: a session, and no key
            let bundle = prekey::bundle(&net.devices[&1].stores).unwrap();
            let r = net.devices.get_mut(&2).unwrap();
            ready(session::establish_session(&mut r.stores, 1, &bundle)).unwrap();
            let (ciphertext, message_type) =
                ready(session::encrypt_message(&mut r.stores, 1, HELLO)).unwrap();
            net.tell(
                1,
                ServerMessage::SessionHello {
                    from: 2,
                    message_type,
                    ciphertext,
                },
            );
            net.pump();
            assert_eq!(net.devices[&1].wrote(is_wraps), before, "hello");
            assert_eq!(net.devices[&1].made, vec![2]);
        }

        /// A hello names nobody: a chain that never named them hands them nothing.
        #[test]
        fn a_hello_alone_gets_no_wrap() {
            let mut net = Net::with(&[1, 2, 3]);
            net.leaves_out = vec![3];
            net.post(1, "hi");
            net.pump();
            assert!(net.devices[&3].shown().is_empty());
            let bundle = prekey::bundle(&net.devices[&1].stores).unwrap();
            let r = net.devices.get_mut(&3).unwrap();
            ready(session::establish_session(&mut r.stores, 1, &bundle)).unwrap();
            let (ciphertext, message_type) =
                ready(session::encrypt_message(&mut r.stores, 1, HELLO)).unwrap();
            let wraps = net.devices[&1].wrote(is_wraps);
            net.tell(
                1,
                ServerMessage::SessionHello {
                    from: 3,
                    message_type,
                    ciphertext,
                },
            );
            net.pump();
            assert_eq!(net.devices[&1].wrote(is_wraps), wraps);
            // And a modified reader asking outright gets no further
            net.tell(
                1,
                ServerMessage::KeyWanted {
                    channel_id: CH,
                    from: 3,
                    reset: false,
                },
            );
            net.pump();
            assert_eq!(net.devices[&1].wrote(is_wraps), wraps);
        }

        // ── Age and exits ───────────────────────────────────────────────────

        #[test]
        fn a_chain_older_than_its_age_rotates_with_no_word_from_the_relay() {
            assert_eq!(chain_age_limit(0), 60_000);
            assert_eq!(chain_age_limit(30), 60_000);
            assert_eq!(chain_age_limit(500), 1_000_000);
            assert_eq!(chain_age_limit(1800), 3_600_000);
            // Our own count, so a relay naming millions still gets the hour
            assert_eq!(chain_age_limit(4_000_000), 3_600_000);

            let mut net = Net::with(&[1, 2]);
            net.post(1, "first");
            net.pump();
            assert_eq!(net.devices[&1].wrote(is_check), 1);
            net.now += chain_age_limit(1) - 1;
            net.post(1, "same chain");
            net.pump();
            net.now += 1;
            net.post(1, "new chain");
            net.pump();
            let checks: Vec<bool> = net.devices[&1]
                .sent
                .iter()
                .filter_map(|m| match m {
                    ClientMessage::KeyCheck { restart, .. } => Some(*restart),
                    _ => None,
                })
                .collect();
            assert_eq!(checks, vec![true, false, true]);
        }

        #[test]
        fn exits_rotate_at_most_once_per_online_times_twenty_ms() {
            assert_eq!(exit_gap(5), 100);
            assert_eq!(exit_gap(2000), 36_000);
            assert_eq!(exit_gap(4_000_000), 36_000);

            let mut w = Writing {
                started: Some(1_000),
                ..Writing::default()
            };
            w.named.extend(0..1000);
            let gap = exit_gap(1000);
            assert!(!w.over(1_000 + gap), "no exit yet");
            w.exited = true;
            assert!(!w.over(1_000 + gap - 1), "within the gap");
            assert!(w.over(1_000 + gap));
        }

        /// Exits do not end a round in the middle of its job, within the gap.
        #[test]
        fn an_exit_inside_the_gap_leaves_the_job_running() {
            let mut net = Net::with(&[1, 2, 3]);
            net.hold_hellos = true;
            net.post(1, "hi");
            net.pump();
            net.hold_hellos = false;
            let d = net.devices.get_mut(&1).unwrap();
            for id in 100..1100u32 {
                d.k.live.writing.get_mut(&CH).unwrap().named.insert(id);
            }
            net.tell(1, ServerMessage::ChannelExits { channels: vec![CH] });
            net.pump();
            net.reconnect(3, 3, false);
            net.tell(
                1,
                ServerMessage::KeyWanted {
                    channel_id: CH,
                    from: 2,
                    reset: false,
                },
            );
            net.pump();
            assert!(net.devices[&1].wrote(is_open) >= 1, "it still answers");
        }

        #[test]
        fn member_gone_ends_the_chain_and_takes_them_off_it() {
            let mut net = Net::with(&[1, 2, 3]);
            net.post(1, "hi");
            net.pump();
            net.tell(
                1,
                ServerMessage::MemberGone {
                    channel_id: CH,
                    user_id: 2,
                },
            );
            net.pump();
            assert_eq!(net.devices[&1].events("member-gone"), 1);
            let w = &net.devices[&1].k.live.writing[&CH];
            assert!(w.exited);
            assert!(!w.named.contains(&2));
            assert!(w.rounds.iter().all(|r| !r.named.contains(&2)));
            // So a re-seating with no word gets named as anyone is: by a new chain
            net.now += exit_gap(1);
            net.post(1, "next");
            let w = &net.devices[&1].k.live.writing[&CH];
            assert!(w.started.is_none(), "a new chain");
        }

        // ── Who is owed ─────────────────────────────────────────────────────

        #[test]
        fn a_bare_id_nobody_listed_gets_no_key() {
            let mut net = Net::with(&[1, 2]);
            net.also_names = vec![9999];
            net.post(1, "hi");
            net.pump();
            let w = &net.devices[&1];
            assert!(!w.k.live.writing[&CH].named.contains(&9999));
            let opened: Vec<u32> = w
                .sent
                .iter()
                .filter_map(|m| match m {
                    ClientMessage::OpenSessions { targets, .. } => Some(targets.clone()),
                    _ => None,
                })
                .flatten()
                .collect();
            assert_eq!(opened, vec![2]);
            assert_eq!(w.events("key-warning"), 0, "the lists may be on their way");
            // Still nobody's after asking again: now it is said
            net.now += 2_000;
            net.post(1, "again");
            net.pump();
            assert_eq!(net.devices[&1].events("key-warning"), 1);
            // Once, not per post
            net.now += 2_000;
            net.post(1, "and again");
            net.pump();
            assert_eq!(net.devices[&1].events("key-warning"), 1);
            assert!(!net.devices[&1].k.live.writing[&CH].named.contains(&9999));
        }

        #[test]
        fn a_guest_named_for_a_gated_channel_gets_no_key_and_warns() {
            let mut net = Net::with(&[1, 2]);
            net.add(3, None);
            net.list_everyone();
            let joined = ServerMessage::TextJoined {
                joined: vec![(CH, false, true, 0)],
                refused: vec![],
            };
            net.tell(1, joined.clone());
            net.tell(3, joined);
            net.pump();
            net.post(1, "hi");
            net.pump();
            let w = &net.devices[&1];
            assert!(!w.k.live.writing[&CH].named.contains(&3));
            assert!(w.k.live.writing[&CH].named.contains(&2), "the control");
            assert_eq!(w.events("key-warning"), 1);
            assert!(net.devices[&2].shown() == vec!["hi"]);

            // And on the reader's side: a guest writer there is opened nothing for
            let bundle = prekey::bundle(&net.devices[&3].stores).unwrap();
            net.tell(
                1,
                ServerMessage::SessionAsked {
                    channel_id: CH,
                    from: 3,
                    account: None,
                    name: "guest".into(),
                    bundle,
                },
            );
            let hellos = net.devices[&1].wrote(is_hello);
            net.pump();
            assert_eq!(net.devices[&1].wrote(is_hello), hellos);
        }

        /// A relay cannot make an app upload by answering what it never asked: with no chain
        /// here yet, and with one, naming someone it has not been named to.
        #[test]
        fn a_keys_owed_nobody_asked_for_wraps_nothing() {
            let owed = ServerMessage::KeysOwed {
                channel_id: CH,
                ids: vec![2, 3],
                rows: vec![],
                more: false,
                refused: false,
            };
            let mut net = Net::with(&[1, 2, 3]);
            net.tell(1, owed.clone());
            net.pump();
            assert!(net.devices[&1].sent.is_empty());

            net.leaves_out = vec![3];
            net.post(1, "hi");
            net.pump();
            let sent = net.devices[&1].sent.len();
            net.tell(1, owed);
            net.pump();
            assert_eq!(net.devices[&1].sent.len(), sent);
            assert!(!net.devices[&1].k.live.writing[&CH].named.contains(&3));
        }

        /// `more` frames add up, and a row names someone a list never did.
        #[test]
        fn keys_owed_merges_its_frames_and_rows() {
            let mut net = Net::with(&[1, 2, 3]);
            let row = UserInfo {
                user_id: 77,
                username: "hidden".into(),
                channel_id: CH,
                is_muted: false,
                is_deafened: false,
                is_screen_sharing: false,
                is_admin: false,
                shares_history: false,
                account: Some([77; 16]),
                is_moderator: false,
                badges: vec![],
            };
            let d = net.devices.get_mut(&1).unwrap();
            let payload = crate::envelope::envelope("id", "hi", None);
            d.k.live_post(&mut d.stores, CH, payload, 0).unwrap();
            for (ids, rows, more) in [
                (vec![2u32], vec![], true),
                (vec![3], vec![row.clone()], false),
            ] {
                let msg = ServerMessage::KeysOwed {
                    channel_id: CH,
                    ids,
                    rows,
                    more,
                    refused: false,
                };
                let d = net.devices.get_mut(&1).unwrap();
                let out = d.k.live_frame(&mut d.stores, 0, &msg, 0);
                if more_of(&msg) {
                    assert!(out.send.is_empty(), "nothing till the last frame");
                } else {
                    assert_eq!(out.seen.len(), 1, "the row, for the pins");
                    assert_eq!(out.seen[0].user_id, 77);
                    assert!(out.send.iter().any(is_post));
                }
            }
            let named: HashSet<u32> = net.devices[&1].k.live.writing[&CH].named.clone();
            assert_eq!(named, HashSet::from([2, 3, 77]));
        }

        fn more_of(m: &ServerMessage) -> bool {
            matches!(m, ServerMessage::KeysOwed { more: true, .. })
        }

        #[test]
        fn a_refused_check_drops_what_waits_and_says_so() {
            let mut net = Net::with(&[1, 2]);
            net.refuses_checks = true;
            net.post(1, "may not");
            net.post(1, "may not either");
            net.pump();
            let w = &net.devices[&1];
            assert_eq!(w.wrote(is_check), 1, "one check for both");
            assert_eq!(w.wrote(is_post), 0);
            assert_eq!(w.events("channel-undelivered"), 1);
            assert_eq!(w.emitted[0].1["expired"], 2);
            // And nothing stays stuck: a lifted hold posts again
            net.refuses_checks = false;
            net.post(1, "may now");
            net.pump();
            assert_eq!(net.devices[&2].shown(), vec!["may now"]);
        }

        #[test]
        fn an_unanswered_check_drops_the_queue_after_ten_seconds() {
            let mut net = Net::with(&[1, 2]);
            let d = net.devices.get_mut(&1).unwrap();
            let payload = crate::envelope::envelope("id", "stuck", None);
            let out = d.k.live_post(&mut d.stores, CH, payload, 0).unwrap();
            assert!(out.send.iter().any(is_check));
            // The answer never comes
            net.now = CHECK_WAIT_MS - 1;
            net.tick();
            assert_eq!(net.devices[&1].events("channel-undelivered"), 0);
            net.now = CHECK_WAIT_MS;
            net.tick();
            assert_eq!(net.devices[&1].events("channel-undelivered"), 1);
        }

        /// The relay counted them as told when it answered; the answer came too late for
        /// anyone to use it. Nothing else ever hands this reader the key.
        #[test]
        fn an_answer_that_came_too_late_is_asked_for_again_with_everyone() {
            let mut net = Net::with(&[1, 2]);
            net.post(1, "first");
            net.pump();
            assert_eq!(net.devices[&2].shown(), vec!["first"]);
            // Someone new, as a check on a stalling link is answered too late
            net.now += 2_000;
            net.add(3, Some([3; 16]));
            net.list_everyone();
            let now = net.now;
            let d = net.devices.get_mut(&1).unwrap();
            let payload = crate::envelope::envelope("id", "lost", None);
            let out = d.k.live_post(&mut d.stores, CH, payload, now).unwrap();
            assert!(matches!(
                out.send[0],
                ClientMessage::KeyCheck { restart: false, .. }
            ));
            net.now += CHECK_WAIT_MS;
            net.tick();
            assert_eq!(net.devices[&1].events("channel-undelivered"), 1);
            // The relay answers now: 3 is told, by its count
            net.keyed.get_mut(&1).unwrap().insert(3);
            let now = net.now;
            let d = net.devices.get_mut(&1).unwrap();
            let answer = ServerMessage::KeysOwed {
                channel_id: CH,
                ids: vec![3],
                rows: vec![],
                more: false,
                refused: false,
            };
            let out = d.k.live_frame(&mut d.stores, 0, &answer, now);
            assert!(out.send.is_empty(), "nobody asked any more");

            net.post(1, "second");
            let asked = net.devices[&1].sent.last().unwrap().clone();
            assert!(
                matches!(asked, ClientMessage::KeyCheck { restart: true, .. }),
                "{asked:?}"
            );
            net.pump();
            assert_eq!(net.devices[&3].shown(), vec!["second"]);
            assert_eq!(net.devices[&2].shown(), vec!["first", "second"]);
            assert_eq!(
                net.devices[&2].events("channel-ring"),
                0,
                "a reader who had it is not disturbed"
            );
            // Back to the usual after one
            net.now += 2_000;
            net.post(1, "third");
            assert!(matches!(
                net.devices[&1].sent.last().unwrap(),
                ClientMessage::KeyCheck { restart: false, .. }
            ));
        }

        /// Asking for everyone is not a new job: who holds this chain gets nothing again.
        #[test]
        fn asking_again_hands_the_key_only_to_who_lacks_it() {
            let mut net = Net::with(&[1, 2]);
            net.post(1, "first");
            net.pump();
            let wraps =
                |net: &Net| net.devices[&1].wrote(is_wraps) + net.devices[&1].wrote(is_open);
            let before = wraps(&net);
            net.refuses_checks = true;
            net.now += 2_000;
            net.post(1, "refused");
            net.pump();
            net.refuses_checks = false;
            net.now += 2_000;
            net.post(1, "again");
            assert!(matches!(
                net.devices[&1].sent.last().unwrap(),
                ClientMessage::KeyCheck { restart: true, .. }
            ));
            net.pump();
            assert_eq!(wraps(&net), before, "no key frame for someone who has it");
            assert_eq!(net.devices[&2].shown(), vec!["first", "again"]);
            assert_eq!(
                net.devices[&1].events("nobody-here"),
                0,
                "a chain with readers is not a first post with nobody here"
            );
        }

        /// No to the mobile data question: whoever it was about was counted as told.
        #[test]
        fn a_no_to_the_question_asks_for_everyone_next() {
            let mut net = Net::with(&[1, 2]);
            let ids: Vec<u32> = (1000..2200).collect();
            net.also_names = ids.clone();
            let d = net.devices.get_mut(&1).unwrap();
            for id in &ids {
                d.k.live_note_person(*id, None);
            }
            d.k.live_set_metered(true);
            net.drop_opens = true;
            net.post(1, "costly");
            net.pump();
            assert_eq!(net.devices[&1].events("key-job-ask"), 1);
            let now = net.now;
            let d = net.devices.get_mut(&1).unwrap();
            let out = d.k.live_answer_job(&mut d.stores, CH, false, now);
            net.apply(1, out);
            net.also_names.clear();
            net.now += 2_000;
            net.post(1, "cheaper");
            assert!(matches!(
                net.devices[&1].sent.last().unwrap(),
                ClientMessage::KeyCheck { restart: true, .. }
            ));
        }

        /// In the first moments of a connection the lists of public rooms are on their way, and
        /// a bare id says nothing yet. Asked again they are named; a stranger still is not, and
        /// only then is it said.
        #[test]
        fn a_reader_not_listed_yet_is_named_at_the_next_post() {
            let mut net = Net::with(&[1, 2]);
            net.add(3, Some([3; 16]));
            // 3 is in nobody's lists yet, on the writer's device
            net.post(1, "early");
            net.pump();
            assert_eq!(net.devices[&1].events("key-warning"), 0, "too early to say");
            assert!(net.devices[&3].shown().is_empty());
            net.list_everyone();
            net.now += 2_000;
            net.post(1, "later");
            assert!(matches!(
                net.devices[&1].sent.last().unwrap(),
                ClientMessage::KeyCheck { restart: true, .. }
            ));
            net.pump();
            assert_eq!(net.devices[&3].shown(), vec!["later"]);
            assert_eq!(net.devices[&1].events("key-warning"), 0);
        }

        /// What waited behind a check, a person's answer or the pins goes with the connection,
        /// and it showed as sent.
        #[test]
        fn what_waits_at_the_end_of_a_connection_is_counted_by_channel() {
            let mut net = Net::with(&[1, 2]);
            let now = net.now;
            let d = net.devices.get_mut(&1).unwrap();
            d.k.join_text(8);
            for channel in [CH, CH, 8] {
                let payload = crate::envelope::envelope("id", "behind a check", None);
                d.k.live_post(&mut d.stores, channel, payload, now).unwrap();
            }
            assert_eq!(d.k.live_end(), vec![(CH, 2), (8, 1)]);
            assert!(d.k.live_end().is_empty(), "once");

            let d = net.devices.get_mut(&2).unwrap();
            d.k.live_wait_for_pins();
            let payload = crate::envelope::envelope("id", "behind the pins", None);
            d.k.live_post(&mut d.stores, CH, payload, now).unwrap();
            assert_eq!(d.k.live_end(), vec![(CH, 1)]);
        }

        /// A question still open when the link goes: the post behind it counts, and a late
        /// Send finds nothing to send.
        #[test]
        fn a_post_behind_the_mobile_data_question_is_counted_at_the_end() {
            let mut net = Net::with(&[1, 2]);
            let ids: Vec<u32> = (1000..2200).collect();
            net.also_names = ids.clone();
            let d = net.devices.get_mut(&1).unwrap();
            for id in &ids {
                d.k.live_note_person(*id, None);
            }
            d.k.live_set_metered(true);
            net.drop_opens = true;
            net.post(1, "costly");
            net.pump();
            assert_eq!(net.devices[&1].events("key-job-ask"), 1);
            let now = net.now;
            let d = net.devices.get_mut(&1).unwrap();
            assert_eq!(d.k.live_end(), vec![(CH, 1)]);
            let out = d.k.live_answer_job(&mut d.stores, CH, true, now);
            assert!(out.send.is_empty() && out.emit.is_empty());
        }

        /// While the pages of pins are out nothing that opens or starts a session runs, and a
        /// sealed answer cannot go by any path.
        #[test]
        fn a_sealed_answer_is_refused_while_the_pins_are_out() {
            let mut net = Net::with(&[1, 2]);
            let d = net.devices.get_mut(&1).unwrap();
            d.k.live_wait_for_pins();
            assert!(d.k.live_pins_out());
            let refused =
                d.k.live_seal_answer(&mut d.stores, CH, 2, &json!([]), 0)
                    .unwrap_err();
            assert!(refused.to_string().contains("pins"), "{refused}");
            let dm = ServerMessage::EncryptedDirectChatMessage {
                from_user_id: 2,
                from_username: "bob".into(),
                to_user_id: 1,
                ciphertext: vec![],
                message_type: 1,
                timestamp: 0,
            };
            assert!(
                d.k.live_holds_frame(&dm),
                "a sealed ask comes as one of these"
            );
            let bundle = ServerMessage::PreKeyBundle {
                user_id: 2,
                bundle: prekey::bundle(&d.stores).unwrap(),
            };
            assert!(
                d.k.live_holds_frame(&bundle),
                "no session on a key not checked"
            );
            assert!(
                !d.k.live_holds_frame(&ServerMessage::Pong { timestamp: 0 }),
                "the rest of the connection goes on"
            );
            let mut stores = std::mem::replace(&mut d.stores, SignalStores::new(&d.identity, 1));
            d.k.live_pins_in(&mut stores, 0, 0);
            assert!(!d.k.live_holds_frame(&dm));
            assert!(
                d.k.live_seal_answer(&mut stores, CH, 2, &json!([]), 0)
                    .is_err(),
                "no session yet, which is the only reason left"
            );
        }

        /// A bundle with nothing to send over it opens nothing: what Verify asks for, and an
        /// ask that ran out. The keys such a session was made on retire within the hour, and
        /// no message starts on those.
        #[test]
        fn a_bundle_with_nothing_to_send_over_it_is_not_wanted() {
            let mut k = ChannelKeying::default();
            k.live_start(0);
            assert!(!k.live_bundle_wanted(5, 0, 0), "nothing asked of them");
            k.set_members(9, [1, 5]);
            assert!(
                k.live_bundle_wanted(5, 9, 0),
                "a room we stand in has a key dance"
            );
            assert!(!k.live_bundle_wanted(6, 9, 0), "and they are not in it");
            assert!(!k.live_bundle_wanted(5, 0, 0), "General has none");
            k.live.asks.push_back((5, CH, 1000));
            assert!(k.live_bundle_wanted(5, 0, 1000), "an ask waits for it");
            assert!(
                !k.live_bundle_wanted(5, 0, 1000 + ASK_LIFE_MS),
                "an ask past its life goes unsent"
            );
        }

        #[test]
        fn a_large_key_job_on_mobile_data_asks_first() {
            let mut net = Net::with(&[1, 2]);
            // A session each would take 2 MB: named by the thousand, with none
            let ids: Vec<u32> = (1000..2200).collect();
            net.also_names = ids.clone();
            let d = net.devices.get_mut(&1).unwrap();
            for id in &ids {
                d.k.live_note_person(*id, None);
            }
            d.k.live_set_metered(true);
            net.drop_opens = true;
            net.post(1, "costly");
            net.pump();
            let w = &net.devices[&1];
            assert_eq!(w.events("key-job-ask"), 1);
            assert_eq!(w.wrote(is_post), 0, "the queue held");
            net.post(1, "and this behind it");
            net.pump();
            assert_eq!(net.devices[&1].wrote(is_check), 1);
            // No: what waits goes, and it is said to
            let d = net.devices.get_mut(&1).unwrap();
            let out = d.k.live_answer_job(&mut d.stores, CH, false, 0);
            net.apply(1, out);
            assert_eq!(net.devices[&1].events("channel-undelivered"), 1);
            assert_eq!(net.devices[&1].wrote(is_post), 0);

            // Yes: as usual. And under the bytes nothing is asked (the control)
            net.keyed.remove(&1);
            net.now = chain_age_limit(0);
            net.post(1, "worth it");
            net.pump();
            let d = net.devices.get_mut(&1).unwrap();
            let out = d.k.live_answer_job(&mut d.stores, CH, true, 0);
            net.apply(1, out);
            net.pump();
            assert_eq!(net.devices[&1].wrote(is_post), 1);

            let mut small = Net::with(&[1, 2]);
            small.devices.get_mut(&1).unwrap().k.live_set_metered(true);
            small.post(1, "cheap");
            small.pump();
            assert_eq!(small.devices[&1].events("key-job-ask"), 0);
            assert_eq!(small.devices[&2].shown(), vec!["cheap"]);
        }

        /// Each job too small to ask about, and a raid of leavers makes a phone pay all of them.
        #[test]
        fn small_key_jobs_on_mobile_data_add_up_within_the_hour() {
            let mut net = Net::with(&[1, 2]);
            let ids: Vec<u32> = (1000..1600).collect();
            net.also_names = ids.clone();
            net.drop_opens = true;
            let d = net.devices.get_mut(&1).unwrap();
            for id in &ids {
                d.k.live_note_person(*id, None);
            }
            d.k.live_set_metered(true);
            // 600 people at about 2 KB each: 1.2 MB, under the line alone
            net.post(1, "first");
            net.pump();
            assert_eq!(net.devices[&1].events("key-job-ask"), 0);
            net.keyed.remove(&1);
            net.now = chain_age_limit(601);
            net.post(1, "second");
            net.pump();
            assert_eq!(net.devices[&1].events("key-job-ask"), 1, "not the second");
            let d = net.devices.get_mut(&1).unwrap();
            let out = d.k.live_answer_job(&mut d.stores, CH, false, net.now);
            net.apply(1, out);
            // The hour passes
            net.keyed.remove(&1);
            net.now = METERED_HOUR_MS + chain_age_limit(601);
            net.post(1, "third");
            net.pump();
            assert_eq!(net.devices[&1].events("key-job-ask"), 1);
        }

        // ── A reader's limits ───────────────────────────────────────────────

        fn raw_post(net: &mut Net, to: u32, from: u32, ciphertext: Vec<u8>) {
            net.tell(
                to,
                ServerMessage::TextPost {
                    channel_id: CH,
                    user_id: from,
                    username: "user".into(),
                    account: Some([from as u8; 16]),
                    is_admin: false,
                    is_moderator: false,
                    ciphertext,
                    timestamp: net.now,
                },
            );
        }

        /// What a post with no key looks like: a real one, from a chain nobody here holds.
        fn sealed_elsewhere(from: u32) -> Vec<u8> {
            let identity = crate::generate_identity_key_pair();
            let mut stores = SignalStores::new(&identity, 1);
            stores.own_user_id = from;
            ready(group::create_distribution_message(&mut stores, from, CH)).unwrap();
            ready(group::encrypt_group_message(&mut stores, from, CH, b"x")).unwrap()
        }

        #[test]
        fn a_post_with_no_key_is_held_asks_at_ten_seconds_and_rings_at_sixty() {
            let mut net = Net::with(&[1, 2]);
            raw_post(&mut net, 2, 1, sealed_elsewhere(1));
            net.pump();
            let r = &net.devices[&2];
            assert_eq!(r.events("channel-chat-message"), 0);
            assert_eq!(r.wrote(is_wanted), 0);
            net.now = KEY_WANTED_AFTER_MS - 1;
            net.tick();
            assert_eq!(net.devices[&2].wrote(is_wanted), 0);
            net.now = KEY_WANTED_AFTER_MS;
            net.tick();
            assert_eq!(net.devices[&2].wrote(is_wanted), 1);
            net.now = KEY_WANTED_AFTER_MS + 10_000;
            net.tick();
            assert_eq!(net.devices[&2].wrote(is_wanted), 1, "once");
            assert_eq!(net.devices[&2].events("channel-ring"), 0);
            net.now = HOLD_MS;
            net.tick();
            assert_eq!(net.devices[&2].events("channel-ring"), 1);
            assert!(net.devices[&2].k.live.held.is_empty());
            assert_eq!(net.devices[&2].k.live.held_bytes, 0);
        }

        #[test]
        fn a_writer_holds_twenty_and_the_largest_holder_pays_past_two_megabytes() {
            let mut net = Net::with(&[1, 2]);
            for _ in 0..HOLD_PER_WRITER + 3 {
                raw_post(&mut net, 2, 1, sealed_elsewhere(1));
            }
            net.pump();
            let r = &net.devices[&2];
            assert_eq!(r.k.live.held[&(CH, 1)].posts.len(), HOLD_PER_WRITER);
            assert_eq!(
                r.events("channel-ring"),
                3,
                "what fell out is at least a mark"
            );

            // A large holder against a small one
            let mut net = Net::with(&[1, 2, 3]);
            raw_post(&mut net, 2, 3, sealed_elsewhere(3));
            for _ in 0..HOLD_PER_WRITER {
                let mut huge = sealed_elsewhere(1);
                huge.resize(150_000, 0);
                raw_post(&mut net, 2, 1, huge);
            }
            net.pump();
            let r = &net.devices[&2];
            assert!(r.k.live.held_bytes <= HOLD_BYTES);
            assert!(r.k.live.held.contains_key(&(CH, 3)), "the small one stays");
        }

        /// What is held waits for its own key: a later post whose key is here does not wait
        /// behind it, and go the way of a post nobody can open.
        #[test]
        fn a_readable_post_is_not_held_behind_one_that_is_not() {
            let mut net = Net::with(&[1, 2]);
            net.post(1, "first");
            net.pump();
            assert_eq!(net.devices[&2].shown(), vec!["first"]);
            raw_post(&mut net, 2, 1, sealed_elsewhere(1));
            net.pump();
            assert_eq!(net.devices[&2].k.live.held.len(), 1);
            net.now += 2_000;
            net.post(1, "second");
            net.pump();
            assert_eq!(net.devices[&2].shown(), vec!["first", "second"]);
            assert_eq!(net.devices[&2].k.live.held[&(CH, 1)].posts.len(), 1);
        }

        #[test]
        fn key_wanted_goes_under_one_bucket_for_the_whole_reader() {
            let mut net = Net::with(&[1, 2]);
            for writer in 100..120u32 {
                raw_post(&mut net, 2, writer, sealed_elsewhere(writer));
            }
            net.pump();
            net.now = KEY_WANTED_AFTER_MS;
            net.tick();
            assert_eq!(net.devices[&2].wrote(is_wanted), 8, "the burst");
            net.now += 1000;
            net.tick();
            assert_eq!(net.devices[&2].wrote(is_wanted), 9, "and one a second");
        }

        #[test]
        fn a_writer_is_opened_for_once_in_ten_minutes_unless_a_key_was_asked() {
            let mut net = Net::with(&[1, 2]);
            let ask = |net: &mut Net| {
                let bundle = prekey::bundle(&net.devices[&1].stores).unwrap();
                net.tell(
                    2,
                    ServerMessage::SessionAsked {
                        channel_id: CH,
                        from: 1,
                        account: Some([1; 16]),
                        name: "user1".into(),
                        bundle,
                    },
                );
                net.pump();
            };
            ask(&mut net);
            assert_eq!(net.devices[&2].wrote(is_hello), 1);
            assert_eq!(net.devices[&2].checked, vec![1], "through the pin check");
            ask(&mut net);
            assert_eq!(net.devices[&2].wrote(is_hello), 1);
            // We asked for a key: the answer is taken
            let d = net.devices.get_mut(&2).unwrap();
            let mut out = LiveOut::default();
            d.k.ask_key(CH, 1, false, 0, &mut out);
            ask(&mut net);
            assert_eq!(net.devices[&2].wrote(is_hello), 2);
            net.now = REOPEN_MS;
            ask(&mut net);
            assert_eq!(net.devices[&2].wrote(is_hello), 3);
        }

        #[test]
        fn hellos_stop_at_the_readers_bucket_smaller_on_mobile_data() {
            for (metered, burst) in [(false, 128), (true, 32)] {
                let mut net_ = Net::with(&[2]);
                net_.devices
                    .get_mut(&2)
                    .unwrap()
                    .k
                    .live_set_metered(metered);
                for writer in 1000..1000 + 2 * burst {
                    net_.add(writer as u32, Some([9; 16]));
                }
                for writer in 1000..1000 + 2 * burst {
                    let bundle = prekey::bundle(&net_.devices[&(writer as u32)].stores).unwrap();
                    net_.tell(
                        2,
                        ServerMessage::SessionAsked {
                            channel_id: CH,
                            from: writer as u32,
                            account: Some([9; 16]),
                            name: "w".into(),
                            bundle,
                        },
                    );
                }
                net_.pump();
                assert_eq!(net_.devices[&2].wrote(is_hello), burst as usize);
            }
        }

        #[test]
        fn a_quiet_channel_opens_no_session_and_reads_no_post() {
            let mut net = Net::with(&[1, 2]);
            net.devices
                .get_mut(&2)
                .unwrap()
                .k
                .live_set_quiet(&[CH], true);
            net.post(1, "hi");
            net.pump();
            let r = &net.devices[&2];
            assert_eq!(r.wrote(is_hello), 0);
            assert_eq!(r.wrote(is_wanted), 0);
            assert!(r.k.live.held.is_empty());
            // Whole again, and it reads like anyone
            net.devices
                .get_mut(&2)
                .unwrap()
                .k
                .live_set_quiet(&[CH], false);
            net.now = chain_age_limit(1);
            net.keyed.remove(&1);
            net.post(1, "now");
            net.pump();
            assert_eq!(net.devices[&2].shown(), vec!["now"]);
        }

        // ── A writer's limits ───────────────────────────────────────────────

        #[test]
        fn resets_go_once_in_ten_minutes_per_reader_and_under_a_writers_bucket() {
            let mut net = Net::with(&[1, 2]);
            net.post(1, "hi");
            net.pump();
            let wanted = |net: &mut Net, from: u32| {
                net.tell(
                    1,
                    ServerMessage::KeyWanted {
                        channel_id: CH,
                        from,
                        reset: true,
                    },
                );
                net.pump();
            };
            let opens = net.devices[&1].wrote(is_open);
            net.now += OPEN_WAIT_MS;
            wanted(&mut net, 2);
            assert_eq!(net.devices[&1].wrote(is_open), opens + 1);
            net.now += OPEN_WAIT_MS;
            wanted(&mut net, 2);
            assert_eq!(net.devices[&1].wrote(is_open), opens + 1, "one per reader");

            let d = net.devices.get_mut(&1).unwrap();
            let w = d.k.live.writing.get_mut(&CH).unwrap();
            w.named.extend(1000..1200);
            let now = net.now;
            let mut asks = 0;
            for reader in 1000..1200u32 {
                let msg = ServerMessage::KeyWanted {
                    channel_id: CH,
                    from: reader,
                    reset: true,
                };
                let d = net.devices.get_mut(&1).unwrap();
                let before = d.k.live.opens.len();
                let _ = d.k.live_frame(&mut d.stores, 0, &msg, now);
                asks += d.k.live.opens.len() - before;
            }
            assert_eq!(asks, 63, "64 in all, one spent just above");
        }

        #[test]
        fn open_sessions_go_in_frames_and_the_next_waits_for_half_or_a_second() {
            let mut k = ChannelKeying::default();
            k.live_start(0);
            let identity = crate::generate_identity_key_pair();
            let mut stores = SignalStores::new(&identity, 1);
            stores.own_user_id = 1;
            let w = k.live.writing.entry(CH).or_default();
            w.started = Some(0);
            w.named.extend(10..710);
            k.live.opens.extend((10..710).map(|id| (CH, id)));

            let frame = |k: &mut ChannelKeying, s: &mut SignalStores, now, call| match k
                .live_next_frame(s, now, call, WRAPS_A_FRAME)
            {
                Some(ClientMessage::OpenSessions { targets, .. }) => targets,
                None => vec![],
                Some(other) => panic!("{other:?}"),
            };
            let first = frame(&mut k, &mut stores, 0, false);
            assert_eq!(first.len(), 256);
            assert!(frame(&mut k, &mut stores, 1, false).is_empty(), "waiting");
            // Half answered
            for id in &first[..128] {
                k.live.awaiting.remove(id);
            }
            let second = frame(&mut k, &mut stores, 2, false);
            assert_eq!(second.len(), 256);
            // A second passes with nobody answering
            assert!(frame(&mut k, &mut stores, 3, false).is_empty());
            let third = frame(&mut k, &mut stores, 2 + OPEN_WAIT_MS, true);
            assert_eq!(third.len(), 33, "fewer in a call");
        }

        #[test]
        fn wraps_go_in_frames_of_256_and_stop_short_of_the_frames_bytes() {
            let mut net = Net::with(&[1]);
            let ids: Vec<u32> = (100..460).collect();
            for id in &ids {
                net.add(*id, None);
            }
            net.list_everyone();
            let d = net.devices.get_mut(&1).unwrap();
            let w = d.k.live.writing.entry(CH).or_default();
            w.started = Some(0);
            w.named.extend(ids.iter().copied());
            // Writer-opened sessions: each wrap 1.9 KB, so bytes end the frame
            for id in &ids[..60] {
                let bundle = prekey::bundle(&net.devices[id].stores).unwrap();
                let d = net.devices.get_mut(&1).unwrap();
                ready(session::establish_session(&mut d.stores, *id, &bundle)).unwrap();
                d.k.live.wraps.push_back((CH, *id));
            }
            let d = net.devices.get_mut(&1).unwrap();
            let Some(ClientMessage::DistributeSenderKeys { keys, .. }) =
                d.k.live_next_frame(&mut d.stores, 0, false, WRAPS_A_FRAME)
            else {
                panic!("no frame");
            };
            assert!(keys.len() < 60 && keys.len() > 20, "{}", keys.len());
            let bytes: usize = keys.iter().map(|(_, _, c)| c.len() + 8).sum();
            assert!(bytes < voipc_protocol::codec::MAX_RELAY_CIPHERTEXT);
        }

        #[test]
        fn a_browser_in_a_call_wraps_eight_a_frame_and_the_rest_wait() {
            let mut net = Net::with(&[1]);
            let ids: Vec<u32> = (100..120).collect();
            for id in &ids {
                net.add(*id, None);
            }
            net.list_everyone();
            let d = net.devices.get_mut(&1).unwrap();
            let w = d.k.live.writing.entry(CH).or_default();
            w.started = Some(0);
            w.named.extend(ids.iter().copied());
            for id in &ids {
                let bundle = prekey::bundle(&net.devices[id].stores).unwrap();
                let d = net.devices.get_mut(&1).unwrap();
                ready(session::establish_session(&mut d.stores, *id, &bundle)).unwrap();
                d.k.live.wraps.push_back((CH, *id));
            }
            let d = net.devices.get_mut(&1).unwrap();
            for (made, left) in [(8, 12), (8, 4), (4, 0)] {
                let Some(ClientMessage::DistributeSenderKeys { keys, .. }) =
                    d.k.live_next_frame(&mut d.stores, 0, true, WRAPS_A_FRAME_BROWSER_CALL)
                else {
                    panic!("no frame");
                };
                assert_eq!(keys.len(), made);
                assert_eq!(d.k.live.wraps.len(), left);
            }
        }

        // ── New keys, and when ──────────────────────────────────────────────

        #[test]
        fn prekeys_refill_after_the_key_job_not_during_it() {
            let mut net = Net::with(&[1, 2, 3]);
            net.post(1, "hi");
            let d = net.devices.get_mut(&1).unwrap();
            let msg = ServerMessage::KeysOwed {
                channel_id: CH,
                ids: vec![2, 3],
                rows: vec![],
                more: false,
                refused: false,
            };
            let out = d.k.live_frame(&mut d.stores, 0, &msg, 5_000);
            assert!(out.send.iter().any(is_post));
            let out = d.k.live_frame(
                &mut d.stores,
                0,
                &ServerMessage::PreKeysLow { remaining: 3 },
                5_000,
            );
            assert!(out.send.is_empty(), "remembered, not sent");
            assert!(out.work);
            let frames: Vec<ClientMessage> = std::iter::from_fn(|| {
                d.k.live_next_frame(&mut d.stores, 5_000, false, WRAPS_A_FRAME)
            })
            .collect();
            let opens = frames.iter().position(is_open).unwrap();
            assert!(
                !frames[..=opens]
                    .iter()
                    .any(|f| matches!(f, ClientMessage::UploadPreKeys { .. })),
                "not during it: {frames:?}"
            );
            // Hellos waited for, or the job's settle time gone
            let frames: Vec<ClientMessage> = std::iter::from_fn(|| {
                d.k.live_next_frame(&mut d.stores, 5_000 + JOB_SETTLE_MS, false, WRAPS_A_FRAME)
            })
            .collect();
            assert!(frames
                .iter()
                .any(|f| matches!(f, ClientMessage::UploadPreKeys { .. })));
            assert!(frames.iter().any(is_renewal), "and new session keys");
        }

        #[test]
        fn new_session_keys_go_once_a_job_and_hourly_otherwise() {
            let mut net = Net::with(&[1, 2]);
            net.now = RENEW_GAP_MS;
            net.post(1, "hi");
            net.pump();
            assert_eq!(net.devices[&1].wrote(is_renewal), 1, "after the job");
            net.pump();
            assert_eq!(net.devices[&1].wrote(is_renewal), 1, "once");
            let old = net.devices[&1].stores.signed_prekey.current - 1;
            assert!(net.devices[&1]
                .stores
                .signed_prekey
                .signed_prekeys
                .contains_key(&old));

            net.now += prekey::OLD_KEYS_KEPT_MS;
            net.tick();
            assert!(
                !net.devices[&1]
                    .stores
                    .signed_prekey
                    .signed_prekeys
                    .contains_key(&old),
                "gone a minute later"
            );

            // Someone with no job: only the hour
            assert_eq!(
                net.devices[&2].wrote(is_renewal),
                0,
                "a hello it sent is no job"
            );
            let reader = net.devices[&2].stores.signed_prekey.current;
            net.now = RENEW_EVERY_MS + RENEW_GAP_MS;
            net.tick();
            assert!(net.devices[&2].stores.signed_prekey.current > reader);
        }

        // ── Kept sessions ───────────────────────────────────────────────────

        #[test]
        fn a_kept_session_older_than_a_week_opens_afresh() {
            let mut net = Net::with(&[1, 2]);
            net.post(1, "first");
            net.pump();
            net.now = KEPT_MS - 1;
            net.reconnect(1, 11, true);
            net.reconnect(2, 12, true);
            net.devices.get_mut(&12).unwrap().k.join_text(CH);
            net.post(11, "just inside");
            net.pump();
            assert_eq!(net.devices[&11].wrote(is_open), 0);

            // Its age goes on from when the session was made, across connections
            net.now = KEPT_MS;
            net.reconnect(11, 21, true);
            net.reconnect(12, 22, true);
            net.devices.get_mut(&22).unwrap().k.join_text(CH);
            net.post(21, "a week on");
            net.pump();
            assert_eq!(net.devices[&21].wrote(is_open), 1, "afresh");
            assert_eq!(net.devices[&22].shown(), vec!["a week on"]);
        }

        #[test]
        fn a_record_past_its_week_is_not_taken_and_not_held_to_be() {
            let account = [7u8; 16];
            let mut kept = KeptSessions::default();
            kept.put(account, b"record", 1_000, 1_000);
            assert!(kept.holds(&account, 1_000 + KEPT_MS - 1));
            assert!(!kept.holds(&account, 1_000 + KEPT_MS));
            assert!(kept.take(&account, 1_000 + KEPT_MS).is_none());
            assert!(
                kept.is_empty(),
                "and it is gone, not left to be asked again"
            );
            kept.put(account, b"record", 1_000, 1_000);
            let (record, born) = kept.take(&account, 1_000 + KEPT_MS - 1).unwrap();
            assert_eq!((record.as_slice(), born), (b"record".as_slice(), 1_000));
        }

        /// The same bound on a session still here, under the id a peer had: a connection
        /// that runs for a week does not stretch it.
        #[test]
        fn a_session_under_an_old_id_is_found_for_a_week_only() {
            let mut net = Net::with(&[1, 2]);
            net.post(1, "first");
            net.pump();
            net.now = KEPT_MS;
            net.reconnect(2, 12, true);
            net.devices.get_mut(&12).unwrap().k.join_text(CH);
            net.post(1, "a week on");
            net.pump();
            assert_eq!(net.devices[&1].wrote(is_open), 2, "afresh");
            assert_eq!(
                net.devices[&12].wrote(is_wanted),
                0,
                "with no wrap to fail first"
            );
            assert_eq!(net.devices[&12].wrote(is_hello), 1);
            assert_eq!(net.devices[&12].shown(), vec!["a week on"]);
        }

        #[test]
        fn a_guest_keeps_nothing_across_a_reconnect() {
            let mut net = Net::with(&[1]);
            net.add(2, None);
            net.list_everyone();
            net.post(1, "hi");
            net.pump();
            let d = net.devices.get_mut(&1).unwrap();
            let kept = d.k.live_keep_sessions(&d.stores, 0);
            assert!(
                kept.is_empty(),
                "a session with a guest has no account to go by"
            );

            // The control: the same with an account
            let mut net = Net::with(&[1, 2]);
            net.post(1, "hi");
            net.pump();
            let d = net.devices.get_mut(&1).unwrap();
            assert_eq!(d.k.live_keep_sessions(&d.stores, 0).len(), 1);
        }

        #[test]
        fn at_most_five_thousand_are_kept_the_least_used_going() {
            let mut kept = KeptSessions::default();
            let account = |n: u32| {
                let mut a = [0u8; 16];
                a[..4].copy_from_slice(&n.to_le_bytes());
                a
            };
            for n in 0..KEPT_MAX as u32 + 10 {
                kept.put(account(n), b"record", 1_000, 1_000 + n as u64);
            }
            kept.trim(2_000);
            assert_eq!(kept.len(), KEPT_MAX);
            assert!(!kept.holds(&account(0), 2_000));
            assert!(!kept.holds(&account(9), 2_000));
            assert!(kept.holds(&account(10), 2_000));
            let mut same = KeptSessions::default();
            for n in 0..KEPT_MAX as u32 + 10 {
                same.put(account(n), b"record", 1_000, 1_000);
            }
            same.trim(2_000);
            assert_eq!(same.len(), KEPT_MAX, "however many were used at once");
        }

        /// A relay naming the wrong account gets a failed MAC, and the same heal as a restart.
        #[test]
        fn a_kept_record_under_the_wrong_account_only_fails_and_heals() {
            let mut net = Net::with(&[1, 2, 3]);
            net.post(1, "from one");
            net.post(3, "from three");
            net.pump();
            net.reconnect(1, 11, true);
            net.reconnect(2, 12, true);
            net.devices.get_mut(&12).unwrap().k.join_text(CH);
            // The relay says 11 is account 3, whose record the reader kept too
            net.devices.get_mut(&11).unwrap().account = Some([3; 16]);
            net.post(11, "from who they say");
            net.pump();
            let r = &net.devices[&12];
            assert_eq!(r.wrote(is_wanted), 1, "the MAC failed");
            assert!(r.sent.iter().any(is_hello), "and it opened afresh");
            assert_eq!(
                r.shown(),
                vec!["from one", "from three", "from who they say"][2..]
            );
        }

        #[test]
        fn a_key_that_disagrees_with_the_pin_drops_a_kept_record() {
            let mut net = Net::with(&[1, 2]);
            net.post(1, "first");
            net.pump();
            net.reconnect(1, 11, true);
            net.reconnect(2, 12, true);
            net.devices.get_mut(&12).unwrap().k.join_text(CH);
            net.post(11, "second");
            net.pump();
            let r = net.devices.get_mut(&12).unwrap();
            assert!(r.stores.session.has(11));
            assert!(r.k.live_drop_kept_session(&mut r.stores, 11));
            assert!(!r.stores.session.has(11));
            // A session of this connection's own is not this function's to drop
            let w = net.devices.get_mut(&1);
            assert!(w.is_none());
            let mut fresh = Net::with(&[1, 2]);
            fresh.post(1, "hi");
            fresh.pump();
            let d = fresh.devices.get_mut(&2).unwrap();
            assert!(!d.k.live_drop_kept_session(&mut d.stores, 1));
            assert!(d.stores.session.has(1));
        }

        // ── Hand-offs ───────────────────────────────────────────────────────

        fn drain(net: &mut Net, id: u32) -> Vec<ClientMessage> {
            let now = net.now;
            let d = net.devices.get_mut(&id).unwrap();
            std::iter::from_fn(|| {
                d.k.live_next_frame(&mut d.stores, now, false, WRAPS_A_FRAME)
            })
            .collect()
        }

        #[test]
        fn a_hand_off_never_reads_a_kept_record() {
            let mut net = Net::with(&[1, 2]);
            net.post(1, "first");
            net.pump();
            net.reconnect(1, 11, true);
            net.reconnect(2, 12, true);
            net.devices.get_mut(&12).unwrap().k.join_text(CH);
            net.post(11, "second");
            net.pump();
            // 12 holds a record of 11 now, moved. It asks over a real session or not at all.
            net.now += ASK_EVERY_MS;
            let now = net.now;
            let d = net.devices.get_mut(&12).unwrap();
            d.k.live_ask_history(CH, &[11], now);
            let frames = drain(&mut net, 12);
            assert_eq!(frames.len(), 1, "{frames:?}");
            assert!(matches!(
                frames[0],
                ClientMessage::RequestPreKeyBundle { target_user_id: 11 }
            ));
            // A bundle came, and its session is one both ends hold
            let d = net.devices.get_mut(&12).unwrap();
            d.k.live_session_up(11);
            let frames = drain(&mut net, 12);
            assert!(matches!(
                frames[0],
                ClientMessage::SendEncryptedDirectMessage {
                    target_user_id: 11,
                    ..
                }
            ));
        }

        #[test]
        fn asks_go_one_a_second_and_an_old_one_goes_away() {
            let mut net = Net::with(&[1, 2, 3, 4]);
            for writer in [2, 3, 4] {
                let bundle = prekey::bundle(&net.devices[&writer].stores).unwrap();
                let d = net.devices.get_mut(&1).unwrap();
                ready(session::establish_session(&mut d.stores, writer, &bundle)).unwrap();
            }
            net.now = ASK_EVERY_MS;
            let now = net.now;
            let d = net.devices.get_mut(&1).unwrap();
            let asked = d.k.live_ask_history(CH, &[2, 3, 4], now);
            assert_eq!(asked.len(), 3);
            assert_eq!(drain(&mut net, 1).len(), 1);
            assert_eq!(drain(&mut net, 1).len(), 0, "the rest wait");
            net.now += ASK_EVERY_MS;
            assert_eq!(drain(&mut net, 1).len(), 1);
            net.now += ASK_LIFE_MS;
            assert_eq!(drain(&mut net, 1).len(), 0, "too late to be any use");
            assert!(net.devices[&1].k.live.asks.is_empty());
        }

        #[test]
        fn more_than_three_named_only_three_are_asked() {
            let mut net = Net::with(&[1]);
            let d = net.devices.get_mut(&1).unwrap();
            assert_eq!(d.k.live_ask_history(CH, &[2, 3, 4, 5, 6, 7], 0).len(), 3);
        }

        /// A member cannot inject second-hand rows by answering unasked. `members` on a
        /// live path never forgets, so this is what stands where a roster stood.
        #[test]
        fn an_answer_nobody_asked_for_is_not_taken() {
            let mut k = ChannelKeying::default();
            assert!(!k.live_answer_wanted(CH, 2, 0));
            k.live_note_asked(CH, 2, 0);
            assert!(!k.live_answer_wanted(CH, 3, 0), "someone else's");
            assert!(!k.live_answer_wanted(8, 2, 0), "another channel");
            assert!(k.live_answer_wanted(CH, 2, ASK_LIFE_MS - 1));
            assert!(!k.live_answer_wanted(CH, 2, ASK_LIFE_MS - 1), "used up");
            k.live_note_asked(CH, 2, 0);
            assert!(!k.live_answer_wanted(CH, 2, ASK_LIFE_MS), "too late");
        }

        /// "Not delivered" about a hand-off shows nowhere. The control: one about a person's
        /// own message still does, and so does one past the window.
        #[test]
        fn undelivered_about_a_hand_off_is_swallowed_once_per_send() {
            let mut net = Net::with(&[1, 2]);
            net.post(1, "hi");
            net.pump();
            let now = net.now;
            let d = net.devices.get_mut(&1).unwrap();
            d.k.live_seal_answer(&mut d.stores, CH, 2, &json!([]), now)
                .unwrap();
            assert!(d.k.live_undelivered_was_sealed(2, now));
            assert!(!d.k.live_undelivered_was_sealed(2, now), "one per send");
            assert!(!d.k.live_undelivered_was_sealed(3, now), "someone else");
            d.k.live_seal_answer(&mut d.stores, CH, 2, &json!([]), now)
                .unwrap();
            assert!(!d
                .k
                .live_undelivered_was_sealed(2, now + SEALED_UNDELIVERED_MS));
        }

        #[test]
        fn a_sealed_ask_and_answer_cross_a_real_session() {
            let mut net = Net::with(&[1, 2]);
            net.post(1, "hi");
            net.pump();
            net.now += ASK_EVERY_MS;
            let now = net.now;
            let d = net.devices.get_mut(&2).unwrap();
            d.k.live_ask_history(CH, &[1], now);
            let frames = drain(&mut net, 2);
            let ClientMessage::SendEncryptedDirectMessage {
                ciphertext,
                message_type,
                ..
            } = &frames[0]
            else {
                panic!("{frames:?}");
            };
            let w = net.devices.get_mut(&1).unwrap();
            let plain = ready(session::decrypt_message(
                &mut w.stores,
                2,
                ciphertext,
                *message_type,
            ))
            .unwrap();
            assert_eq!(
                crate::open_sealed(&plain),
                Some(crate::Sealed::Ask { channel_id: CH })
            );
            let messages = json!([{ "id": "a", "text": "hi" }]);
            let answer =
                w.k.live_seal_answer(&mut w.stores, CH, 2, &messages, now)
                    .unwrap();
            let ClientMessage::SendEncryptedDirectMessage {
                ciphertext,
                message_type,
                ..
            } = answer
            else {
                panic!("not a direct message");
            };
            let r = net.devices.get_mut(&2).unwrap();
            let plain = ready(session::decrypt_message(
                &mut r.stores,
                1,
                &ciphertext,
                message_type,
            ))
            .unwrap();
            assert!(matches!(
                crate::open_sealed(&plain),
                Some(crate::Sealed::Answer { channel_id: CH, .. })
            ));
            assert!(r.k.live_answer_wanted(CH, 1, now), "the ask stands");
        }

        // ── The pieces around it ────────────────────────────────────────────

        #[test]
        fn a_bundle_keys_no_text_channel() {
            let mut k = ChannelKeying::default();
            k.join_text(CH);
            assert_eq!(k.keyed_by_a_bundle(5, true), vec![5]);
            let older = k.keyed_by_a_bundle(5, false);
            assert!(older.contains(&5) && older.contains(&CH), "an older relay");
        }

        /// A key from someone no roster names is dropped by the older path's check, so an
        /// old frame on a live connection reciprocates nothing. The control: an older
        /// relay's roster lets it in.
        #[test]
        fn no_reciprocation_on_a_lazy_relay() {
            let mut k = ChannelKeying::default();
            k.join_text(CH);
            assert!(!k.shares_channel_with(0, CH, 2));
            k.set_members(CH, [1, 2]);
            assert!(k.shares_channel_with(0, CH, 2));
        }

        #[test]
        fn text_joined_starts_a_channel_once_and_says_when_a_gate_goes() {
            let mut net = Net::with(&[1]);
            net.devices
                .get_mut(&1)
                .unwrap()
                .k
                .forget_channel(None, 1, CH);
            let frame = |gated| ServerMessage::TextJoined {
                joined: vec![(CH, false, gated, 9)],
                refused: vec![8],
            };
            let d = net.devices.get_mut(&1).unwrap();
            let out = d.k.live_frame(&mut d.stores, 0, &frame(true), 0);
            assert_eq!(out.entered, vec![CH]);
            assert_eq!(out.emit[0].0, "text-joined");
            assert_eq!(out.emit[0].1["joined"][0]["last_post_ms"], 9);
            assert_eq!(out.emit[0].1["refused"][0], 8);
            let out = d.k.live_frame(&mut d.stores, 0, &frame(true), 0);
            assert!(out.entered.is_empty(), "a repeat does not start it over");
            let out = d.k.live_frame(&mut d.stores, 0, &frame(false), 0);
            assert_eq!(out.emit[0].0, "key-warning");
            assert_eq!(out.emit[0].1["kind"], "gate-gone");
            let out = d.k.live_frame(&mut d.stores, 0, &frame(false), 0);
            assert_eq!(out.emit.len(), 1, "said once");
        }

        #[test]
        fn a_post_reads_the_writers_facts_for_the_front_end() {
            let mut net = Net::with(&[1, 2]);
            net.post(1, "hi");
            net.pump();
            let event = net.devices[&2]
                .emitted
                .iter()
                .find(|(n, _)| *n == "channel-chat-message")
                .unwrap();
            assert_eq!(event.1["username"], "user1");
            assert_eq!(event.1["is_admin"], false);
            assert_eq!(event.1["account"][0], 1);
            assert_eq!(event.1["encrypted"], true);
        }

        #[test]
        fn a_writer_nobody_listed_is_noted_at_their_first_post_for_the_pins() {
            let mut net = Net::with(&[1]);
            let identity = crate::generate_identity_key_pair();
            net.devices
                .insert(2, Device::new(2, Some([2; 16]), identity));
            // 2 knows nobody, but a post of 1's comes
            raw_post(&mut net, 2, 1, sealed_elsewhere(1));
            let d = net.devices.get_mut(&2).unwrap();
            let msg = d.inbox.pop_front().unwrap();
            let out = d.k.live_frame(&mut d.stores, 0, &msg, 0);
            assert_eq!(out.seen.len(), 1);
            assert_eq!(out.seen[0].user_id, 1);
            assert_eq!(out.seen[0].account, Some([1; 16]));
            raw_post(&mut net, 2, 1, sealed_elsewhere(1));
            let d = net.devices.get_mut(&2).unwrap();
            let msg = d.inbox.pop_front().unwrap();
            let out = d.k.live_frame(&mut d.stores, 0, &msg, 0);
            assert!(out.seen.is_empty(), "once");
        }

        #[test]
        fn a_row_with_no_account_does_not_take_one_away() {
            let mut k = ChannelKeying::default();
            assert!(k.live_note_person(5, Some([1; 16])));
            assert!(!k.live_note_person(5, None), "an anonymous room's list");
            assert_eq!(k.live.people[&5], Some([1; 16]));
            assert!(
                k.live_note_person(5, Some([2; 16])),
                "another account: news"
            );
            assert!(
                !k.live_note_person(0, None),
                "nobody: a count, not a person"
            );
        }

        #[test]
        fn forgetting_a_channel_takes_what_was_held_for_it() {
            let mut net = Net::with(&[1, 2]);
            raw_post(&mut net, 2, 1, sealed_elsewhere(1));
            net.pump();
            assert!(net.devices[&2].k.live.held_bytes > 0);
            let d = net.devices.get_mut(&2).unwrap();
            d.k.forget_channel(Some(&mut d.stores), 2, CH);
            assert!(d.k.live.held.is_empty());
            assert_eq!(d.k.live.held_bytes, 0);
        }
    }
}
