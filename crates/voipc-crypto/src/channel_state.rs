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

use std::collections::{HashMap, HashSet};

use crate::group;
use crate::stores::SignalStores;

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
        self.in_channel(own_channel, channel_id)
            && self.is_member(channel_id, user_id)
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
    pub fn reset_channel(&mut self, stores: Option<&mut SignalStores>, own_user_id: u32, channel_id: u32) {
        if let Some(stores) = stores {
            group::forget_own_sender_key(stores, own_user_id, channel_id);
        }
        self.distributed.remove(&channel_id);
        self.received.remove(&channel_id);
        self.stale.remove(&channel_id);
    }

    /// Leave a channel entirely: its keys, its roster and anything we still
    /// wanted from it.
    pub fn forget_channel(&mut self, stores: Option<&mut SignalStores>, own_user_id: u32, channel_id: u32) {
        self.reset_channel(stores, own_user_id, channel_id);
        self.text_channels.remove(&channel_id);
        self.members.remove(&channel_id);
        self.history_wanted.remove(&channel_id);
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
        self.distributed.entry(channel_id).or_default().insert(user_id);
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
    use rand::seq::SliceRandom;
    sharers
        .choose_multiple(&mut rand::rngs::OsRng, HISTORY_SOURCES)
        .copied()
        .collect()
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
        assert!(k.shares_channel_with(5, 7, 2), "a member of a text channel we are in");
        assert!(k.shares_channel_with(5, 5, 3), "a member of the room we stand in");
        assert!(!k.shares_channel_with(5, 7, 9), "a stranger the relay names");
        assert!(!k.shares_channel_with(5, 8, 1), "a channel we are not in at all");
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
        assert_eq!(history_sources(&[(1, true), (9, true)], 1), HashSet::from([9]));
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
}
