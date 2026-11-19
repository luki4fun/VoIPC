//! Our posts on their way out, one rule for the desktop app (gk_net.rs) and the browser
//! (voipc-web gk.rs), plan 3b and C4:
//!
//! - `Copies`: a post's kept copy is filed once, under the epoch the post finally went out
//!   under (`GkOut::released`), once the relay took the post: `SETTLE_MS` after its last
//!   `released` with no `EpochRefused{POST}` for it (the relay names no post and sends no word
//!   when it takes one). At `OLD_EPOCH` and `RATE` what went in that group goes again, and its
//!   next `released` says under what; a refusal for good drops what the group key drops
//!   (`drop_refused`: the latest that started a chain, else the latest). The relay starts a
//!   kept chain under an epoch only while it is the head, or the one before for `HOLD_MS`
//!   after the head opened (accounts/log.rs `chain_start`): a copy whose chain start comes too
//!   late for that ("That epoch's key is gone here") is filed again under the head the app
//!   holds then. `AccountSync` keeps every copy once (`send_channel_gk`) and lets one go again
//!   only after that refusal, so offering a filed copy again under a newer head files only
//!   what was refused.
//! - `Early`: a post to a channel whose group is not tracked yet (the join is not answered) waits
//!   for it and then goes, instead of being dropped at once; it is dropped, and the app says
//!   so, if the join is refused, the channel is left, or `EARLY_WAIT_MS` passes.
//!
//! Plain state, no I/O: the host feeds it what it sent and what came, and files what it hands
//! back (`AccountSession::outgoing_channel_gk`).

use std::collections::{HashMap, VecDeque};

use voipc_protocol::gk::{refused_what, refused_why};
use voipc_protocol::messages::{ClientMessage, ServerMessage};

use super::{Dropped, GkEpoch, GkEvent, GkOut, GkState};
use crate::group_key::timers::{EPOCH_MIN_GAP_MS, HOLD_MS};

/// One out this long with no refusal was taken under its epoch: the relay refuses a post
/// within a round trip. Short on purpose: two openings come `EPOCH_MIN_GAP_MS` apart at least,
/// and a copy filed this soon after its post meets its epoch still the head or the one
/// before, where the relay starts a kept chain. One that comes later is filed again under the
/// head (`Copies::file`).
pub const SETTLE_MS: u64 = 1_000;
const _: () = assert!(SETTLE_MS < EPOCH_MIN_GAP_MS);

/// A copy whose post never went is given up this long after it was written: the group key
/// gives a held post up at `HOLD_MS`, and an early one waits as long before that.
pub const KEPT_WAIT_MS: u64 = 2 * HOLD_MS;

/// A filed copy is offered again under a newer head for this long: past it a refused chain
/// start has long been answered.
pub const AGAIN_MS: u64 = 2 * HOLD_MS;

/// Filed copies kept to be offered again, at most (oldest go first).
const AGAIN_MOST: usize = 256;

/// A post waits this long at most for its channel's group to be tracked (G).
pub const EARLY_WAIT_MS: u64 = HOLD_MS;

/// What `gk-state` says when a channel we posted to did not let us in.
pub const JOIN_REFUSED: &str = "you are not in this channel";

/// A post's kept copy: what `AccountSession::outgoing_channel_gk` files.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeptCopy {
    /// The channel's log (its stored group's id).
    pub log: String,
    pub envelope: Vec<u8>,
    /// When it was written (ms).
    pub sent_at: u64,
    pub ttl_secs: Option<u32>,
}

/// When a post last went out, in which order, under what, and whether it started a chain.
struct Went {
    ep: GkEpoch,
    at: u64,
    order: u64,
    blob: bool,
}

struct Waiting {
    copy: KeptCopy,
    since: u64,
    went: Option<Went>,
}

/// A copy filed, kept `AGAIN_MS` to be offered again under a newer head.
struct Filed {
    copy: KeptCopy,
    /// The epoch it was filed under.
    gen: [u8; 16],
    epoch: u32,
    at: u64,
}

/// Our posts' kept copies, from the post until the relay has surely kept them (module doc).
#[derive(Default)]
pub struct Copies {
    waiting: HashMap<[u8; 16], Waiting>,
    filed: VecDeque<Filed>,
    sends: u64,
}

impl Copies {
    /// A post of ours with a channel log, handed to the group key now (`GroupKeying::post`).
    pub fn wait(&mut self, post_id: [u8; 16], copy: KeptCopy, now: u64) {
        self.waiting.insert(
            post_id,
            Waiting {
                copy,
                since: now,
                went: None,
            },
        );
    }

    /// What a `GroupKeying` call handed back, before its frames go (so a post's refusal never
    /// comes before its send is noted): each `released` went out under its epoch, again if it
    /// went before. The `EpochPost`s and `released` go in the same order, one for one.
    pub fn sent(&mut self, out: &GkOut, now: u64) {
        if out.released.is_empty() {
            return;
        }
        let mut blobs = out.send.iter().filter_map(|m| match m {
            ClientMessage::EpochPost { blob, .. } => Some(blob.is_some()),
            _ => None,
        });
        for (_, post_id, ep) in &out.released {
            let blob = blobs.next().unwrap_or(false);
            if let Some(p) = self.waiting.get_mut(post_id) {
                self.sends += 1;
                p.went = Some(Went {
                    ep: ep.clone(),
                    at: now,
                    order: self.sends,
                    blob,
                });
            }
        }
    }

    /// A frame from the relay, before the group key takes it: `EpochRefused{POST}` for one of
    /// our groups. At `OLD_EPOCH` and `RATE` what went there waits for its next `released`;
    /// any other drops the copy of the post the group key drops.
    pub fn refused(&mut self, msg: &ServerMessage) {
        let ServerMessage::EpochRefused {
            group,
            what: refused_what::POST,
            why,
            ..
        } = msg
        else {
            return;
        };
        let out = self
            .waiting
            .iter_mut()
            .filter(|(_, p)| p.went.as_ref().is_some_and(|w| w.ep.group == *group));
        if matches!(*why, refused_why::OLD_EPOCH | refused_why::RATE) {
            for (_, p) in out {
                p.went = None;
            }
            return;
        }
        let dropped = out
            .max_by_key(|(_, p)| p.went.as_ref().map(|w| (w.blob, w.order)))
            .map(|(id, _)| *id);
        if let Some(id) = dropped {
            self.waiting.remove(&id);
        }
    }

    /// The copies to file now, each with the epoch to file it under, in order: those whose
    /// post settled (`SETTLE_MS` after its last `released`, in the order their posts went),
    /// then those filed before under an epoch older than the head the group is at now
    /// (`head`, `GroupKeying::current_epoch`), offered under that head. `AccountSync` files
    /// one of those only if the relay refused its chain start as gone. A copy whose post
    /// never went is given up with it.
    pub fn file(
        &mut self,
        now: u64,
        head: impl Fn(&str) -> Option<GkEpoch>,
    ) -> Vec<(KeptCopy, GkEpoch)> {
        self.waiting
            .retain(|_, p| p.went.is_some() || now.saturating_sub(p.since) < KEPT_WAIT_MS);
        let settled = self.take(|w| now >= w.at.saturating_add(SETTLE_MS));
        self.filed.retain(|f| now < f.at.saturating_add(AGAIN_MS));
        let mut out = Vec::new();
        for f in &self.filed {
            if let Some(h) = head(&f.copy.log).filter(|h| h.gen != f.gen || h.epoch > f.epoch) {
                out.push((f.copy.clone(), h));
            }
        }
        for (copy, ep) in &settled {
            self.filed.push_back(Filed {
                copy: copy.clone(),
                gen: ep.gen,
                epoch: ep.epoch,
                at: now,
            });
        }
        while self.filed.len() > AGAIN_MOST {
            self.filed.pop_front();
        }
        let mut all = settled;
        all.extend(out);
        all
    }

    /// The connection ended: whatever went is filed as it stands, in order; the rest is
    /// given up with the posts.
    pub fn end(&mut self) -> Vec<(KeptCopy, GkEpoch)> {
        let all = self.take(|_| true);
        *self = Copies::default();
        all
    }

    /// Whether a copy waits for `post_id`, and if its post went, under which epoch.
    pub fn went_under(&self, post_id: &[u8; 16]) -> Option<Option<u32>> {
        let p = self.waiting.get(post_id)?;
        Some(p.went.as_ref().map(|w| w.ep.epoch))
    }

    /// The waiting copies whose post went and `due`, out of `waiting`, in the order they went.
    fn take(&mut self, due: impl Fn(&Went) -> bool) -> Vec<(KeptCopy, GkEpoch)> {
        let ids: Vec<[u8; 16]> = self
            .waiting
            .iter()
            .filter(|(_, p)| p.went.as_ref().is_some_and(&due))
            .map(|(id, _)| *id)
            .collect();
        let mut due: Vec<(KeptCopy, Went)> = ids
            .iter()
            .filter_map(|id| self.waiting.remove(id))
            .filter_map(|p| Some((p.copy, p.went?)))
            .collect();
        due.sort_by_key(|(_, w)| w.order);
        due.into_iter().map(|(c, w)| (c, w.ep)).collect()
    }
}

/// A post of ours whose channel's group is not tracked yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EarlyPost {
    pub post_id: [u8; 16],
    pub envelope: Vec<u8>,
    /// Its kept copy, for `Copies::wait` once it goes to the group key.
    pub copy: Option<KeptCopy>,
}

/// Posts made before their channel's group was tracked (module doc).
#[derive(Default)]
pub struct Early {
    posts: Vec<(u32, u64, EarlyPost)>,
}

impl Early {
    /// A post to `channel_id`, whose group is not tracked yet: it waits for it, and the app
    /// says it waits.
    pub fn hold(&mut self, channel_id: u32, post: EarlyPost, now: u64) -> GkOut {
        self.posts.push((channel_id, now, post));
        GkOut {
            events: vec![GkEvent::State {
                channel_id,
                state: GkState::Late { waiting: true },
            }],
            ..GkOut::default()
        }
    }

    /// `channel_id`'s group is tracked now: its posts go, in the order they were written.
    pub fn take(&mut self, channel_id: u32) -> Vec<EarlyPost> {
        let (now, rest): (Vec<_>, Vec<_>) = std::mem::take(&mut self.posts)
            .into_iter()
            .partition(|(c, ..)| *c == channel_id);
        self.posts = rest;
        now.into_iter().map(|(.., p)| p).collect()
    }

    /// The relay refused to let us into `channel_id`: its posts are dropped, the refusal told
    /// first (U1: a refused drop has no line of its own).
    pub fn refused(&mut self, channel_id: u32) -> GkOut {
        let n = self.take(channel_id).len();
        let mut out = GkOut::default();
        if n > 0 {
            out.events.push(GkEvent::State {
                channel_id,
                state: GkState::Refused(JOIN_REFUSED.to_string()),
            });
        }
        dropped(&mut out, channel_id, Dropped::Refused, n);
        out
    }

    /// Out of `channel_id` before its group was tracked: its posts are given up.
    pub fn gone(&mut self, channel_id: u32) -> GkOut {
        let n = self.take(channel_id).len();
        let mut out = GkOut::default();
        dropped(&mut out, channel_id, Dropped::Late, n);
        out
    }

    /// Posts that waited `EARLY_WAIT_MS` are given up.
    pub fn tick(&mut self, now: u64) -> GkOut {
        let mut out = GkOut::default();
        let (late, rest): (Vec<_>, Vec<_>) = std::mem::take(&mut self.posts)
            .into_iter()
            .partition(|(_, since, _)| now >= since.saturating_add(EARLY_WAIT_MS));
        self.posts = rest;
        for (channel_id, ..) in late {
            dropped(&mut out, channel_id, Dropped::Late, 1);
        }
        out
    }

    /// The connection ended: every post still waiting is given up.
    pub fn end(&mut self) -> GkOut {
        let mut out = GkOut::default();
        for (channel_id, ..) in std::mem::take(&mut self.posts) {
            dropped(&mut out, channel_id, Dropped::Late, 1);
        }
        out
    }

    pub fn is_empty(&self) -> bool {
        self.posts.is_empty()
    }
}

fn dropped(out: &mut GkOut, channel_id: u32, why: Dropped, n: usize) {
    for _ in 0..n {
        out.events.push(GkEvent::PostDropped { channel_id, why });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: u64 = 1_700_000_000_000;
    const LOG: &str = "c:77";

    fn epoch(epoch: u32) -> GkEpoch {
        GkEpoch {
            group: LOG.into(),
            gen: [1; 16],
            epoch,
            d_e: [epoch as u8; 32],
            ck: [0; 32].into(),
        }
    }

    fn copy(id: u8) -> KeptCopy {
        KeptCopy {
            log: LOG.into(),
            envelope: vec![id],
            sent_at: T0,
            ttl_secs: None,
        }
    }

    /// `GroupKeying`'s out for posts that went: one `EpochPost` and one `released` each.
    fn went(posts: &[(u8, u32, bool)]) -> GkOut {
        let mut out = GkOut::default();
        for &(id, e, blob) in posts {
            out.send.push(ClientMessage::EpochPost {
                channel_id: 7,
                group: LOG.into(),
                gen: [1; 16],
                epoch: e,
                blob: blob.then(|| vec![1]),
                ciphertext: vec![2],
            });
            out.released.push((7, [id; 16], epoch(e)));
        }
        out
    }

    fn refused(group: &str, why: u8) -> ServerMessage {
        ServerMessage::EpochRefused {
            group: group.into(),
            what: refused_what::POST,
            why,
            detail: String::new(),
        }
    }

    fn filed(due: Vec<(KeptCopy, GkEpoch)>) -> Vec<(u8, u32)> {
        due.into_iter()
            .map(|(c, ep)| (c.envelope[0], ep.epoch))
            .collect()
    }

    fn no_head(_: &str) -> Option<GkEpoch> {
        None
    }

    /// T1e D: nothing is filed at the first `released`; a post refused as `OLD_EPOCH` and
    /// sent again under the head is filed once, under the head, once that send settled.
    #[test]
    fn a_post_sent_again_after_old_epoch_is_kept_once_under_the_epoch_it_went_again_under() {
        let mut c = Copies::default();
        c.wait([1; 16], copy(1), T0);
        c.sent(&went(&[(1, 4, true)]), T0);
        assert!(c.file(T0, no_head).is_empty(), "not at the release");
        assert!(
            c.file(T0 + SETTLE_MS - 1, no_head).is_empty(),
            "a refusal may still come"
        );
        // The head moved past epoch 4: refused, and sent again under the head
        c.refused(&refused(LOG, refused_why::OLD_EPOCH));
        assert_eq!(c.went_under(&[1; 16]), Some(None));
        assert!(c.file(T0 + SETTLE_MS, no_head).is_empty(), "not gone yet");
        c.sent(&went(&[(1, 6, true)]), T0 + 2_000);
        assert_eq!(filed(c.file(T0 + 2_000 + SETTLE_MS, no_head)), [(1, 6)]);
        // Sent again once more (another post's refusal): not filed again
        c.sent(&went(&[(1, 7, true)]), T0 + 3_000);
        assert!(c.end().is_empty());
    }

    #[test]
    fn a_refusal_in_another_group_leaves_these_copies_alone() {
        let mut c = Copies::default();
        c.wait([1; 16], copy(1), T0);
        c.sent(&went(&[(1, 4, true)]), T0);
        c.refused(&refused("c:other", refused_why::OLD_EPOCH));
        c.refused(&refused("c:other", refused_why::THIRD_BLOB));
        assert_eq!(filed(c.file(T0 + SETTLE_MS, no_head)), [(1, 4)]);
    }

    #[test]
    fn a_post_refused_for_good_is_never_kept() {
        let mut c = Copies::default();
        for id in [1, 2] {
            c.wait([id; 16], copy(id), T0);
        }
        // 1 started a chain, 2 went on it: the relay refused the blob, the group key drops 1
        c.sent(&went(&[(1, 4, true), (2, 4, false)]), T0);
        c.refused(&refused(LOG, refused_why::THIRD_BLOB));
        assert_eq!(filed(c.file(T0 + SETTLE_MS, no_head)), [(2, 4)]);
        // One that never went is given up with its post
        c.wait([3; 16], copy(3), T0);
        assert!(c.file(T0 + KEPT_WAIT_MS, no_head).is_empty());
        assert_eq!(c.went_under(&[3; 16]), None);
    }

    /// T1e E: a copy filed under X whose chain start the relay refused as gone (two openings
    /// came first) is offered again under the head; one filed under the head is not, nor
    /// one past `AGAIN_MS`.
    #[test]
    fn a_filed_copy_is_offered_again_under_a_newer_head_for_a_while() {
        let mut c = Copies::default();
        c.wait([1; 16], copy(1), T0);
        c.sent(&went(&[(1, 4, true)]), T0);
        let at = T0 + SETTLE_MS;
        let head4 = |_: &str| Some(epoch(4));
        assert_eq!(filed(c.file(at, head4)), [(1, 4)]);
        assert!(
            c.file(at + 100, head4).is_empty(),
            "the head it was filed under"
        );
        let head6 = |g: &str| (g == LOG).then(|| epoch(6));
        assert_eq!(filed(c.file(at + 200, head6)), [(1, 6)]);
        assert_eq!(
            filed(c.file(at + 300, head6)),
            [(1, 6)],
            "again at each call: the account files it once"
        );
        let mut regen = epoch(1);
        regen.gen = [2; 16];
        assert_eq!(filed(c.file(at + 400, |_| Some(regen.clone()))), [(1, 1)]);
        assert!(c.file(at + AGAIN_MS, head6).is_empty());
    }

    /// The copies settled together go in the order their posts went.
    #[test]
    fn copies_go_in_the_order_their_posts_went() {
        let mut c = Copies::default();
        for id in [3, 1, 2] {
            c.wait([id; 16], copy(id), T0);
        }
        c.sent(&went(&[(2, 4, true), (3, 4, false), (1, 4, false)]), T0);
        assert_eq!(
            filed(c.file(T0 + SETTLE_MS, no_head)),
            [(2, 4), (3, 4), (1, 4)]
        );
    }

    /// G: a post before its channel is tracked waits for it, and goes when it is; it is
    /// dropped, and said so, when the join is refused, the channel is left, or it waited
    /// `EARLY_WAIT_MS`.
    #[test]
    fn a_post_before_its_channel_is_tracked_waits_for_it() {
        let post = |id: u8| EarlyPost {
            post_id: [id; 16],
            envelope: vec![id],
            copy: Some(copy(id)),
        };
        let mut e = Early::default();
        let told = e.hold(3, post(1), T0);
        assert_eq!(
            told.events,
            [GkEvent::State {
                channel_id: 3,
                state: GkState::Late { waiting: true }
            }]
        );
        e.hold(4, post(2), T0);
        e.hold(3, post(3), T0 + 1);
        assert!(e.tick(T0 + EARLY_WAIT_MS - 1).events.is_empty());
        assert_eq!(e.take(3), [post(1), post(3)], "in order");
        assert!(e.take(3).is_empty());
        // Refused: told why, then dropped
        let refused = e.refused(4).events;
        assert_eq!(
            refused,
            [
                GkEvent::State {
                    channel_id: 4,
                    state: GkState::Refused(JOIN_REFUSED.into())
                },
                GkEvent::PostDropped {
                    channel_id: 4,
                    why: Dropped::Refused
                }
            ]
        );
        assert!(
            e.refused(4).events.is_empty(),
            "nothing waits: nothing said"
        );
        // Too long, or the channel left
        e.hold(5, post(4), T0);
        e.hold(6, post(5), T0 + 10);
        let late = e.tick(T0 + EARLY_WAIT_MS).events;
        assert_eq!(
            late,
            [GkEvent::PostDropped {
                channel_id: 5,
                why: Dropped::Late
            }]
        );
        assert_eq!(e.gone(6).events.len(), 1);
        assert!(e.is_empty());
        e.hold(7, post(6), T0);
        assert_eq!(e.end().events.len(), 1);
        assert!(e.is_empty());
    }
}
