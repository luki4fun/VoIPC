//! The group epoch key in the browser (plan 3i): the desktop app's own
//! `voipc_crypto::group_state::GroupKeying`, with what the page holds around it: the
//! account's book and floors (through `AccountLink`), the roster its events name people
//! from, the kept copy of a post that went (`group_state::Copies`, the desktop's rule too),
//! posts to a channel not tracked yet (`group_state::Early`), and the voice keys for
//! `MediaKeys`. Plain Rust, host-testable; lib.rs wraps it for JS.

use std::collections::HashMap;
use std::rc::Rc;
use std::sync::OnceLock;
use std::time::Duration;

use serde_json::{json, Value};
use voipc_crypto::account_session::{AccountSession, Actions};
use voipc_crypto::group_key::{GroupKind, MemberId};
use voipc_crypto::group_state::{
    group_id, BuildJob, Copies, Early, EarlyPost, GkCtx, GkEpoch, GkNames, GkOut, GkPins, GkStart,
    GkTrack, GroupKeying, KeptCopy, LocalGk, MemoryPins, OpenedPost, PastEpoch, Platform,
    VaultFloor, VoiceKeys,
};
use voipc_crypto::time::now_millis;
use voipc_crypto::{MediaKeyRing, SignalStores};
use voipc_protocol::messages::{ClientMessage, ServerMessage};
use voipc_protocol::types::UserInfo;

use crate::account::AccountLink;

/// Rounds of account news one call settles; what is left goes at the next call.
const SETTLE_ROUNDS: usize = 4;

/// The variant tags of the group key's frames: from the one after `GroupKeys` to
/// `EpochReseated`, the last (protocol 26 appended them in that order).
fn gk_tags() -> (u32, u32) {
    static TAGS: OnceLock<(u32, u32)> = OnceLock::new();
    *TAGS.get_or_init(|| {
        let tag = |m: &ServerMessage| {
            let bytes = postcard::to_allocvec(m).expect("a server message encodes");
            postcard::take_from_bytes::<u32>(&bytes).expect("a tag").0
        };
        let first = tag(&ServerMessage::GroupKeys {
            on: false,
            run: [0; 16],
            clock: 0,
        }) + 1;
        (first, tag(&ServerMessage::EpochReseated { n: 0, left: 0 }))
    })
}

/// Whether a frame's postcard bytes are one of the group key's frames, from its tag alone:
/// the page hands those here undecoded, so a 56 KiB part never becomes a JS array.
pub fn is_gk_frame(payload: &[u8]) -> bool {
    let (first, last) = gk_tags();
    postcard::take_from_bytes::<u32>(payload).is_ok_and(|(tag, _)| (first..=last).contains(&tag))
}

/// Who goes by what on this relay, and who is on it, as its lists said (`GkNames`).
#[derive(Default)]
pub struct Roster {
    users: HashMap<u32, (Option<[u8; 16]>, String, u32)>,
}

impl Roster {
    /// The rows of a list.
    pub fn note(&mut self, rows: &[UserInfo]) {
        for r in rows.iter().filter(|r| !r.username.is_empty()) {
            self.users
                .insert(r.user_id, (r.account, r.username.clone(), r.channel_id));
        }
    }

    /// `UserLeft`: out of the room they stood in, which a disconnect is. Leaving a text
    /// channel, or a room they already moved on from, leaves them here.
    pub fn left(&mut self, user_id: u32, channel_id: u32) {
        if self.users.get(&user_id).is_some_and(|u| u.2 == channel_id) {
            self.users.remove(&user_id);
        }
    }

    fn of(&self, m: &MemberId) -> Option<&String> {
        match m {
            MemberId::Conn(u) => self.users.get(u).map(|u| &u.1),
            MemberId::Account(a) => self
                .users
                .values()
                .find(|u| u.0.as_ref() == Some(a))
                .map(|u| &u.1),
        }
    }
}

impl GkNames for Roster {
    fn name(&self, m: &MemberId) -> Option<String> {
        self.of(m).cloned()
    }

    fn online(&self, m: &MemberId) -> bool {
        self.of(m).is_some()
    }
}

/// What the page does after a call: note who posted (the live path's `seen`), send these,
/// emit these, hand the voice keys to `MediaKeys` (`voice_into`), run the keyholder's build
/// (`build_step`), and with `held` call the account (what it holds goes with that call).
#[derive(Default)]
pub struct Out {
    pub seen: Vec<(u32, Option<[u8; 16]>, String)>,
    pub send: Vec<ClientMessage>,
    pub emit: Vec<(String, Value)>,
    pub voice: bool,
    pub build: bool,
    pub held: bool,
}

/// One connection's group keys in the browser.
#[derive(Default)]
pub struct Gk {
    keying: GroupKeying,
    /// A guest's book (an account's is its `AccountSync`).
    pins: MemoryPins,
    pub roster: Roster,
    /// The account signed in on this connection, shared with the page's `AccountSession`.
    pub(crate) account: Option<Rc<AccountLink>>,
    started: bool,
    run: [u8; 16],
    tracked: HashMap<u32, String>,
    job: Option<BuildJob>,
    voice: Vec<VoiceKeys>,
    /// Our posts' kept copies, until they are filed (C4).
    copies: Copies,
    /// Our posts to channels not tracked yet (their join not answered).
    early: Early,
}

/// A connection's start (`GroupKeys`), with the page's state.
pub struct Start {
    pub on: bool,
    pub run: [u8; 16],
    pub clock: u64,
    pub help: bool,
    pub visible: bool,
    pub in_call: bool,
    /// The floors an earlier connection to this relay kept, in this page.
    pub local: Option<LocalGk>,
}

impl Gk {
    /// `GroupKeys`: with `on` the relay uses the group key, else only kept history is read.
    /// A browser offers to hold text keys only while shown and out of a call (3g).
    pub fn start(&mut self, st: &SignalStores, s: Start) -> anyhow::Result<Out> {
        let mut out = Out::default();
        let identity = st.identity.key_pair.to_identity_key_pair()?;
        let mut account = None;
        let mut seat_keys = None;
        if let Some(link) = self.account.clone() {
            // After a reset with the recovery key, once the keys are on (§5.11)
            let rotate = s.on && link.take_reset();
            let on = self.with_session(|session| {
                let mut a = session.gk_on(s.on);
                if rotate {
                    let r = session.seat_keys_rotate();
                    a.send.extend(r.send);
                    a.emit.extend(r.emit);
                    a.seat_keys = r.seat_keys.or(a.seat_keys.take());
                }
                (session.account_id(), a)
            });
            if let Some((id, mut a)) = on {
                account = Some(id);
                seat_keys = a.seat_keys.take();
                self.actions(a, &mut out);
            }
        }
        // A guest's highest counters seen go on from the connection before (an account's are
        // its book's)
        if let (None, Some(local)) = (account, &s.local) {
            self.pins.counters = local.counters.clone();
        }
        let o = self.keying.start(GkStart {
            on: s.on,
            run: s.run,
            relay_clock: s.clock,
            platform: Platform::Browser,
            help_hold_keys: s.help,
            user_id: st.own_user_id,
            identity,
            account,
            seat_keys,
            local: s.local,
            visible: s.visible && !s.in_call,
        });
        self.take(o, &mut out);
        let o = self.keying.visibility(s.visible, s.in_call);
        self.take(o, &mut out);
        self.started = true;
        self.run = s.run;
        self.settle(&mut out);
        Ok(out)
    }

    /// A channel we are in: a text channel we follow, or the voice room we stand in. The
    /// same channel again takes what changed of it and keeps its keys.
    pub fn track(
        &mut self,
        channel_id: u32,
        text: bool,
        log: &str,
        anonymous: bool,
        hide_members: bool,
        viewer_admin: bool,
    ) -> Out {
        let mut out = Out::default();
        if !self.started {
            return out;
        }
        let kind = if text {
            GroupKind::Text
        } else {
            GroupKind::Voice
        };
        let group = group_id(kind, log, &self.run, channel_id);
        let vault = self
            .with_session(|s| s.gk_floor(&group))
            .unwrap_or(VaultFloor::None);
        let t = GkTrack {
            channel_id,
            group: group.clone(),
            kind,
            anonymous,
            hide_members,
            viewer_admin,
            keeps_history: text && !log.is_empty(),
        };
        let o = self.keying.track(t, vault);
        self.tracked.insert(channel_id, group);
        self.take(o, &mut out);
        self.settle(&mut out);
        out
    }

    /// Out of a channel: its held posts are given up, and those that waited for it to be
    /// tracked.
    pub fn untrack(&mut self, channel_id: u32) -> Out {
        let mut out = Out::default();
        self.tracked.remove(&channel_id);
        let o = self.keying.untrack(channel_id);
        self.take(o, &mut out);
        let o = self.early.gone(channel_id);
        self.take(o, &mut out);
        out
    }

    /// The relay did not let us into `channel_id` (`TextJoined.refused`): what waited for it
    /// is dropped, the refusal told first.
    pub fn join_refused(&mut self, channel_id: u32) -> Out {
        let mut out = Out::default();
        let o = self.early.refused(channel_id);
        self.take(o, &mut out);
        self.tracked.remove(&channel_id);
        let o = self.keying.untrack(channel_id);
        self.take(o, &mut out);
        out
    }

    /// A frame `is_gk_frame` named, as its postcard bytes.
    pub fn frame(&mut self, st: &mut SignalStores, payload: &[u8]) -> anyhow::Result<Out> {
        let mut out = Out::default();
        let msg = voipc_protocol::codec::decode_server_msg(payload)?;
        self.early_out(st, &mut out);
        if let ServerMessage::EpochReseated { n, left } = msg {
            if let Some(a) = self.with_session(|s| s.gk_reseated(n, left)) {
                self.actions(a, &mut out);
            }
        } else {
            // A post's refusal to the copies before the group key sends it again
            self.copies.refused(&msg);
            let o = self.call(|k, c| k.frame(st, &msg, c));
            self.take(o, &mut out);
        }
        self.settle(&mut out);
        Ok(out)
    }

    /// A post of ours (`post_id`: its message id). With a channel log its kept copy is
    /// filed once it went, under the epoch it went under (`Copies`). A channel whose group is
    /// not tracked yet (its join not answered) holds it until it is (`Early`).
    pub fn post(
        &mut self,
        st: &mut SignalStores,
        channel_id: u32,
        post_id: [u8; 16],
        envelope: Vec<u8>,
        log: String,
        ttl_secs: Option<u32>,
    ) -> Out {
        let mut out = Out::default();
        let now = now_millis();
        let copy = (self.account.is_some() && !log.is_empty()).then(|| KeptCopy {
            log,
            envelope: envelope.clone(),
            sent_at: now,
            ttl_secs,
        });
        let post = EarlyPost {
            post_id,
            envelope,
            copy,
        };
        if !self.tracked.contains_key(&channel_id) {
            let o = self.early.hold(channel_id, post, now);
            self.take(o, &mut out);
            return out;
        }
        self.early_out(st, &mut out);
        self.send(st, channel_id, vec![post], &mut out);
        self.settle(&mut out);
        out
    }

    /// Posts to the group key, in order, each kept copy waiting for the epoch its post goes
    /// out under.
    fn send(
        &mut self,
        st: &mut SignalStores,
        channel_id: u32,
        posts: Vec<EarlyPost>,
        out: &mut Out,
    ) {
        for p in posts {
            if let Some(copy) = p.copy {
                self.copies.wait(p.post_id, copy, now_millis());
            }
            let o = self.call(|k, c| k.post(st, channel_id, p.post_id, &p.envelope, c));
            self.take(o, out);
        }
    }

    /// The posts that waited for their channel, now tracked, go to the group key: at the
    /// first call with the stores after `track`, before anything else (the answer to the
    /// track's fetch, a post, a tick).
    fn early_out(&mut self, st: &mut SignalStores, out: &mut Out) {
        if self.early.is_empty() {
            return;
        }
        let mut channels: Vec<u32> = self.tracked.keys().copied().collect();
        channels.sort_unstable();
        for channel_id in channels {
            let posts = self.early.take(channel_id);
            self.send(st, channel_id, posts, out);
        }
    }

    /// Our posts' kept copies to the account, each under the epoch to file it under.
    fn file(&mut self, copies: Vec<(KeptCopy, GkEpoch)>, out: &mut Out) {
        for (k, ep) in copies {
            let a = self.with_session(|s| {
                s.outgoing_channel_gk(&k.log, k.envelope, k.sent_at, k.ttl_secs, ep)
            });
            if let Some(a) = a {
                self.actions(a, out);
            }
        }
    }

    /// Every second: what waits goes again, what waited too long is given up, and the past
    /// epochs kept history asked for are asked (part 16).
    pub fn tick(&mut self, st: &mut SignalStores) -> Out {
        let mut out = Out::default();
        if !self.started {
            return out;
        }
        let now = now_millis();
        self.early_out(st, &mut out);
        let o = self.early.tick(now);
        self.take(o, &mut out);
        let o = self.call(|k, c| k.tick(st, c));
        self.take(o, &mut out);
        let o = self.keying.past_asks();
        self.take(o, &mut out);
        let keying = &self.keying;
        let due = self.copies.file(now, |group| keying.current_epoch(group));
        self.file(due, &mut out);
        self.settle(&mut out);
        out
    }

    /// After the account's own calls (a reply, its tick): what they said for the group key.
    pub fn news(&mut self) -> Out {
        let mut out = Out::default();
        self.settle(&mut out);
        out
    }

    /// The keyholder's next upload, as postcard bytes.
    pub fn next_frame(&mut self, in_call: bool) -> Option<Vec<u8>> {
        let frame = self.keying.next_frame(now_millis(), in_call)?;
        Some(postcard::to_allocvec(&frame).expect("a client message encodes"))
    }

    /// One step of at most `budget_ms` of the keyholder's build; `None`: no build waits.
    /// `Out::build` says to step again.
    pub fn build_step(&mut self, budget_ms: f64) -> Option<Out> {
        if self.job.is_none() {
            self.job = self.keying.take_build();
        }
        let job = self.job.as_mut()?;
        let mut out = Out {
            build: true,
            ..Out::default()
        };
        let budget = Duration::from_secs_f64(budget_ms.max(0.0) / 1000.0);
        if let Some(b) = job.step(budget) {
            self.job = None;
            let o = self.call(|k, c| k.built(b, c));
            self.take(o, &mut out);
            self.settle(&mut out);
        }
        Some(out)
    }

    /// "Help hold keys" switched while connected.
    pub fn set_volunteer(&mut self, on: bool) -> Out {
        let mut out = Out::default();
        let o = self.keying.set_volunteer(on);
        self.take(o, &mut out);
        out
    }

    /// The page was hidden or shown, or a call began or ended.
    pub fn visibility(&mut self, visible: bool, in_call: bool) -> Out {
        let mut out = Out::default();
        let o = self.keying.visibility(visible, in_call);
        self.take(o, &mut out);
        out
    }

    /// The voice keys handed out since, into the room's ring (V1's gk mode). Whether the
    /// ring took any.
    pub fn voice_into(&mut self, ring: &mut MediaKeyRing, own_channel: u32) -> bool {
        let mut took = false;
        for keys in self.voice.drain(..) {
            took |= ring.install_gk(&keys, own_channel);
        }
        took
    }

    /// The connection ended: posts still held are given up, and those that waited for their
    /// channel; the copies of posts that went are filed as they stand.
    pub fn end(&mut self) -> Out {
        let mut out = Out::default();
        let o = self.early.end();
        self.take(o, &mut out);
        if !self.started {
            return out;
        }
        let o = self.keying.end();
        self.take(o, &mut out);
        let rest = self.copies.end();
        self.file(rest, &mut out);
        self.started = false;
        self.tracked.clear();
        self.job = None;
        self.voice.clear();
        out
    }

    /// The floors this connection took, for the next one to this relay in this page (3d),
    /// with a guest's highest counters seen.
    pub fn keep(&self) -> Option<LocalGk> {
        let mut local = self.keying.local()?.clone();
        if self.account.is_none() {
            local.counters = self.pins.counters.clone();
        }
        Some(local)
    }

    /// A call that checks against the book: the account's, else the guest's.
    fn call(&mut self, f: impl FnOnce(&mut GroupKeying, GkCtx) -> GkOut) -> GkOut {
        let now = now_millis();
        let mut session = self.account.as_ref().map(|l| l.session.borrow_mut());
        let pins: &mut dyn GkPins = match session.as_deref_mut().and_then(Option::as_mut) {
            Some(s) => s.gk_pins(),
            None => &mut self.pins,
        };
        f(&mut self.keying, GkCtx { pins, now })
    }

    fn with_session<R>(&self, f: impl FnOnce(&mut AccountSession) -> R) -> Option<R> {
        self.account.as_ref()?.session.borrow_mut().as_mut().map(f)
    }

    /// What a call handed back: frames and events out, the account's parts to the account.
    /// The posts that went are noted before their frames go (`Copies::sent`).
    fn take(&mut self, o: GkOut, out: &mut Out) {
        self.copies.sent(&o, now_millis());
        let GkOut {
            send,
            posts,
            events,
            vault_floors,
            voice,
            past_ready,
            self_rows,
            build_ready,
            seat_keys_wanted,
            ..
        } = o;
        out.send.extend(send);
        for p in &posts {
            // Someone may be named here first, as on the live path's `TextPost`
            out.seen.push((p.user_id, p.account, p.username.clone()));
            out.emit
                .push(("channel-chat-message".to_string(), post_event(p)));
        }
        for e in &events {
            let (name, payload) = e.to_wire(&self.roster);
            out.emit.push((name.to_string(), payload));
        }
        out.voice |= !voice.is_empty();
        self.voice.extend(voice);
        out.build |= build_ready;
        let done = self.account.as_ref().and_then(|link| {
            let mut session = link.session.borrow_mut();
            let s = session.as_mut()?;
            let mut done = Vec::new();
            if !vault_floors.is_empty() {
                done.push(s.gk_put_floors(vault_floors));
            }
            if !self_rows.is_empty() {
                done.push(s.gk_self_rows(self_rows));
            }
            if seat_keys_wanted {
                done.push(s.seat_keys_wanted());
            }
            Some(done)
        });
        for a in done.into_iter().flatten() {
            self.actions(a, out);
        }
        for (group, gen, epoch) in past_ready {
            self.past(&group, gen, epoch, out);
        }
    }

    /// A past epoch kept history waits for: its key to the account, or word that none comes.
    fn past(&mut self, group: &str, gen: [u8; 16], epoch: u32, out: &mut Out) {
        if self.account.is_none() {
            return;
        }
        let a = match self.keying.past_epoch(group, gen, epoch) {
            PastEpoch::Asked => return,
            PastEpoch::Ready(k) => self.with_session(|s| s.gk_past_in(&k)),
            PastEpoch::Unknown => self.with_session(|s| s.gk_past_none(group, gen, epoch)),
        };
        if let Some(a) = a {
            self.actions(a, out);
        }
    }

    /// An account action from here: its frames go out with the call's, what it says for the
    /// group key waits for `settle`, and its events, read cursors and remembering wait for
    /// the page's next call of the account (`Out::held`), whose `run` marks a replay and
    /// writes the cursors.
    fn actions(&self, mut a: Actions, out: &mut Out) {
        let Some(link) = &self.account else {
            return;
        };
        link.news.borrow_mut().take_from(&mut a);
        let mut held = link.held.borrow_mut();
        held.park(&mut a);
        out.held |= !held.is_empty();
        out.send.extend(a.send);
    }

    /// The account's news for the group key: new seat keys, floors that moved, past epochs
    /// kept history needs (`Actions`' own rules).
    fn settle(&mut self, out: &mut Out) {
        let Some(link) = self.account.clone() else {
            return;
        };
        if !self.started {
            return;
        }
        for _ in 0..SETTLE_ROUNDS {
            let news = std::mem::take(&mut *link.news.borrow_mut());
            if news.is_empty() {
                return;
            }
            if let Some(keys) = news.seat_keys {
                let o = self.keying.seat_keys_changed(keys);
                self.take(o, out);
            }
            if news.floors {
                let groups: Vec<String> = self.tracked.values().cloned().collect();
                let moved = self
                    .with_session(|s| s.gk_floors_moved(&groups))
                    .unwrap_or_default();
                for (group, f) in moved {
                    let o = self.keying.floors_in(&group, f);
                    self.take(o, out);
                }
            }
            if !news.past.is_empty() {
                for (group, gen, epoch) in news.past {
                    self.past(&group, gen, epoch, out);
                }
                let o = self.keying.past_asks();
                self.take(o, out);
            }
        }
    }
}

/// A post that opened, as the front end takes it: the live path's `channel-chat-message`
/// (channel_state.rs `post_event`).
fn post_event(p: &OpenedPost) -> Value {
    let msg = voipc_crypto::envelope::open_envelope(&p.envelope);
    json!({
        "channel_id": p.channel_id,
        "user_id": p.user_id,
        "username": p.username,
        "account": p.account,
        "is_admin": p.is_admin,
        "is_moderator": p.is_moderator,
        "content": msg.text,
        "timestamp": p.timestamp,
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

#[cfg(test)]
mod tests {
    use voipc_crypto::group_key::Seen;
    use voipc_crypto::group_state::{GkEvent, GkState};
    use voipc_crypto::sync::LogMemory;
    use voipc_protocol::gk::{self as wire, GkMember, GkWriter};
    use voipc_protocol::types::UserInfo;

    use super::*;
    use crate::account::reset_done;
    use crate::signal::SignalCore;

    const RUN: [u8; 16] = [0x22; 16];
    const TEXT: u32 = 3;
    const ROOM: u32 = 5;

    fn start(core: &mut SignalCore, in_call: bool) -> Out {
        core.set_own_user_id(7);
        let s = Start {
            on: true,
            run: RUN,
            clock: now_millis() / 1000,
            help: true,
            visible: true,
            in_call,
            local: None,
        };
        core.gk_start(s).unwrap()
    }

    /// Each `KeyholdVolunteer`'s `on` and `platform`.
    fn volunteers(out: &Out) -> Vec<(bool, u8)> {
        out.send
            .iter()
            .filter_map(|m| match m {
                ClientMessage::KeyholdVolunteer { on, platform, .. } => Some((*on, *platform)),
                _ => None,
            })
            .collect()
    }

    fn fetched(out: &Out) -> Vec<String> {
        out.send
            .iter()
            .filter_map(|m| match m {
                ClientMessage::EpochFetch { group, .. } => Some(group.clone()),
                _ => None,
            })
            .collect()
    }

    fn row(user_id: u32, name: &str, channel_id: u32, account: Option<[u8; 16]>) -> UserInfo {
        UserInfo {
            user_id,
            username: name.into(),
            channel_id,
            is_muted: false,
            is_deafened: false,
            is_screen_sharing: false,
            is_admin: false,
            shares_history: false,
            account,
            is_moderator: false,
            badges: vec![],
        }
    }

    #[test]
    fn every_group_key_frame_and_only_those_is_handed_over_undecoded() {
        let gk = [
            ServerMessage::EpochIn {
                group: "g".into(),
                part: 0,
                last: true,
                piece: Box::default(),
            },
            ServerMessage::EpochWait {
                group: "g".into(),
                why: 1,
                detail: String::new(),
            },
            ServerMessage::EpochDue {
                group: "g".into(),
                due: 1,
                part: 0,
                last: true,
                piece: Box::default(),
            },
            ServerMessage::EpochStale {
                group: "g".into(),
                due: 1,
                reason: 1,
                detail: String::new(),
                head: None,
            },
            ServerMessage::EpochLists {
                group: "g".into(),
                gen: [1; 16],
                lists: vec![],
                more: false,
            },
            ServerMessage::KeyringIn {
                group: "g".into(),
                gen: [1; 16],
                epoch: 1,
                join: 0,
                part: 0,
                last: true,
                piece: Default::default(),
            },
            ServerMessage::EpochExit {
                group: "g".into(),
                gen: [1; 16],
                seq: 1,
            },
            ServerMessage::EpochPostIn {
                channel_id: 1,
                group: "g".into(),
                gen: [1; 16],
                epoch: 1,
                user_id: 2,
                username: "a".into(),
                account: None,
                is_admin: false,
                is_moderator: false,
                writer: GkMember::Conn(2),
                blob: None,
                ciphertext: vec![1; 64],
                timestamp: 1,
            },
            ServerMessage::EpochBlob {
                group: "g".into(),
                gen: [1; 16],
                epoch: 1,
                writer: GkWriter {
                    m: GkMember::Conn(2),
                    u: 2,
                },
                blobs: vec![],
            },
            ServerMessage::EpochNamesIn {
                group: "g".into(),
                part: 0,
                last: true,
                piece: Default::default(),
            },
            ServerMessage::EpochRefused {
                group: "g".into(),
                what: 1,
                why: 1,
                detail: String::new(),
            },
            ServerMessage::VoiceSeats {
                channel_id: 1,
                group: "g".into(),
                part: 0,
                last: true,
                piece: Default::default(),
            },
            ServerMessage::EpochReseated { n: 1, left: 0 },
        ];
        for m in &gk {
            assert!(is_gk_frame(&postcard::to_allocvec(m).unwrap()), "{m:?}");
        }
        let others = [
            ServerMessage::GroupKeys {
                on: true,
                run: RUN,
                clock: 1,
            },
            ServerMessage::Ping { timestamp: 1 },
            ServerMessage::TextJoined {
                joined: vec![(1, false, false, 0)],
                refused: vec![],
            },
        ];
        for m in &others {
            assert!(!is_gk_frame(&postcard::to_allocvec(m).unwrap()), "{m:?}");
        }
        assert!(!is_gk_frame(&[]));
    }

    #[test]
    fn a_browser_offers_as_a_browser_while_shown_and_out_of_a_call_else_as_the_fallback() {
        const SHOWN: (bool, u8) = (true, wire::platform::BROWSER);
        const BUSY: (bool, u8) = (true, wire::platform::BROWSER_BUSY);
        let mut core = SignalCore::new().unwrap();
        assert_eq!(volunteers(&start(&mut core, true)), [BUSY], "in a call");
        assert_eq!(volunteers(&core.gk.visibility(true, false)), [SHOWN]);
        assert_eq!(volunteers(&core.gk.visibility(false, false)), [BUSY]);
        assert!(volunteers(&core.gk.visibility(false, true)).is_empty());
        assert_eq!(volunteers(&core.gk.visibility(true, false)), [SHOWN]);

        let mut shown = SignalCore::new().unwrap();
        assert_eq!(volunteers(&start(&mut shown, false)), [SHOWN]);
        assert_eq!(
            volunteers(&shown.gk.set_volunteer(false)),
            [(false, wire::platform::BROWSER)]
        );
    }

    #[test]
    fn a_text_channel_goes_by_its_log_and_a_voice_room_by_the_relays_run() {
        let mut core = SignalCore::new().unwrap();
        start(&mut core, false);
        assert_eq!(
            fetched(&core.gk.track(TEXT, true, "c:abc", false, false, false)),
            ["c:abc"]
        );
        let room = core.gk.track(ROOM, false, "c:ignored", false, false, false);
        let run = voipc_protocol::conv::hex(&RUN);
        assert_eq!(fetched(&room), [format!("r:{run}:{ROOM}")]);
        assert!(
            fetched(&core.gk.track(TEXT, true, "c:abc", false, false, true)).is_empty(),
            "the same channel again keeps what it holds"
        );
    }

    /// What `GkOut.voice` handed out goes into the ring of the room we stand in, once: keys
    /// of a room we left are dropped, not kept for the next.
    #[test]
    fn voice_keys_go_into_the_ring_of_the_room_we_stand_in_once() {
        let keys = |channel_id: u32| VoiceKeys {
            channel_id,
            group: format!("r:{}:{channel_id}", voipc_protocol::conv::hex(&RUN)),
            gen: [1; 16],
            epochs: vec![(1, [1; 32], [2; 32].into())],
            own: (MemberId::Conn(7), [7; 8]),
            seats: vec![(7, MemberId::Conn(7), [7; 8])],
            switch_at: 0,
            new_generation: true,
        };
        let (mut gk, mut ring) = (Gk::default(), MediaKeyRing::default());
        gk.voice.extend([keys(ROOM + 1), keys(ROOM)]);
        assert!(gk.voice_into(&mut ring, ROOM));
        assert!(ring.has_channel(ROOM) && ring.current().is_some_and(|k| k.key_id == 1));
        assert!(!gk.voice_into(&mut ring, ROOM), "once");
        gk.voice.push(keys(ROOM + 1));
        assert!(!gk.voice_into(&mut ring, ROOM));
        assert!(gk.voice.is_empty() && ring.has_channel(ROOM));
    }

    #[test]
    fn nothing_is_tracked_before_group_keys() {
        let mut core = SignalCore::new().unwrap();
        assert!(fetched(&core.gk.track(TEXT, true, "", false, false, false)).is_empty());
        assert!(core.gk_tick().send.is_empty());
    }

    #[test]
    fn a_post_without_the_key_waits_and_says_so() {
        let mut core = SignalCore::new().unwrap();
        start(&mut core, false);
        core.gk.track(TEXT, true, "", false, false, false);
        let out = core.gk_post(TEXT, [9; 16], b"hello".to_vec(), String::new(), None);
        let states: Vec<&Value> = out
            .emit
            .iter()
            .filter(|(n, _)| n == "gk-state")
            .map(|(_, v)| v)
            .collect();
        assert_eq!(
            states,
            [&json!({ "channel_id": TEXT, "state": "late", "why": "waiting" })]
        );
        assert!(!out
            .send
            .iter()
            .any(|m| matches!(m, ClientMessage::EpochPost { .. })));
        assert_eq!(
            core.gk.copies.went_under(&[9; 16]),
            None,
            "a guest files no kept copy"
        );
    }

    #[test]
    fn events_name_people_as_the_relays_lists_do() {
        let mut roster = Roster::default();
        let acct = [4; 16];
        roster.note(&[row(2, "ann#1", 0, Some(acct)), row(3, "bob#2", 9, None)]);
        let e = GkEvent::Keyholders {
            channel_id: TEXT,
            holders: vec![Some(MemberId::Conn(9)), Some(MemberId::Account(acct)), None],
        };
        let (name, v) = e.to_wire(&roster);
        assert_eq!(name, "gk-keyholders");
        assert_eq!(
            v["holders"][0],
            json!({ "name": "ann#1", "online": true, "kind": "" })
        );
        assert_eq!(v["holders"][1]["online"], false);
        // Leaving a text channel is not leaving the relay; the room they stood in is
        roster.left(2, 7);
        assert!(roster.online(&MemberId::Account(acct)));
        roster.left(2, 0);
        assert!(!roster.online(&MemberId::Account(acct)));
        assert_eq!(roster.name(&MemberId::Conn(3)).as_deref(), Some("bob#2"));

        let state = GkEvent::State {
            channel_id: TEXT,
            state: GkState::NoKeyholder,
        };
        assert_eq!(
            state.to_wire(&roster).1,
            json!({ "channel_id": TEXT, "state": "no_keyholder", "why": "" })
        );
    }

    #[test]
    fn an_opened_post_reads_as_the_live_paths_chat_message() {
        let p = OpenedPost {
            channel_id: TEXT,
            group: "c:abc".into(),
            user_id: 2,
            username: "ann#1".into(),
            account: Some([4; 16]),
            is_admin: true,
            is_moderator: false,
            envelope: voipc_crypto::envelope::envelope("0123", "hi there", Some(60)),
            timestamp: 77,
        };
        let v = post_event(&p);
        assert_eq!(v["content"], "hi there");
        assert_eq!(v["message_id"], "0123");
        assert_eq!(v["ttl_secs"], 60);
        assert_eq!(v["username"], "ann#1");
        assert_eq!(v["is_admin"], true);
        assert_eq!(v["encrypted"], true);
        assert_eq!(v["timestamp"], 77);
    }

    fn named<'a>(out: &'a Out, name: &str) -> Vec<&'a Value> {
        out.emit
            .iter()
            .filter(|(n, _)| n == name)
            .map(|(_, v)| v)
            .collect()
    }

    /// G (J8F): a post sent before its channel's group is tracked (its `TextJoined` not in
    /// yet, or before `GroupKeys`) is not dropped at once as "late": it waits, and goes to
    /// the group key at the first call after the channel is tracked. The group key holds it
    /// then for the channel's keys (and gives it up when the channel is left).
    #[test]
    fn a_post_before_its_channel_is_tracked_waits_and_goes_to_the_group_key_once_it_is() {
        let mut core = SignalCore::new().unwrap();
        let out = core.gk_post(TEXT, [8; 16], b"early".to_vec(), "c:abc".into(), None);
        assert!(named(&out, "gk-post-dropped").is_empty(), "{:?}", out.emit);
        start(&mut core, false);
        let out = core.gk_post(TEXT, [9; 16], b"hi".to_vec(), "c:abc".into(), None);
        assert!(named(&out, "gk-post-dropped").is_empty(), "{:?}", out.emit);
        assert_eq!(
            named(&out, "gk-state"),
            [&json!({ "channel_id": TEXT, "state": "late", "why": "waiting" })]
        );
        assert!(out.send.is_empty());
        core.gk.track(TEXT, true, "c:abc", false, false, false);
        let out = core.gk_tick();
        assert!(named(&out, "gk-post-dropped").is_empty(), "{:?}", out.emit);
        assert!(core.gk.early.is_empty(), "both went to the group key");
        // The group key holds them: leaving the channel gives both up
        let out = core.gk.untrack(TEXT);
        assert_eq!(
            named(&out, "gk-post-dropped"),
            [&json!({ "channel_id": TEXT, "why": "late" }); 2]
        );
    }

    /// G: a post to a channel the relay does not let us into is dropped then, the refusal
    /// told first; one to a channel left before it was tracked is given up.
    #[test]
    fn a_post_to_a_channel_whose_join_is_refused_is_dropped_and_says_why() {
        let mut core = SignalCore::new().unwrap();
        start(&mut core, false);
        core.gk_post(TEXT, [9; 16], b"hi".to_vec(), String::new(), None);
        let out = core.gk.join_refused(TEXT);
        assert_eq!(
            named(&out, "gk-state"),
            [&json!({
                "channel_id": TEXT,
                "state": "refused",
                "why": voipc_crypto::group_state::JOIN_REFUSED
            })]
        );
        assert_eq!(
            named(&out, "gk-post-dropped"),
            [&json!({ "channel_id": TEXT, "why": "refused" })]
        );
        assert!(core.gk.join_refused(TEXT).emit.is_empty(), "said once");
        core.gk_post(ROOM, [7; 16], b"hi".to_vec(), String::new(), None);
        assert_eq!(
            named(&core.gk.untrack(ROOM), "gk-post-dropped"),
            [&json!({ "channel_id": ROOM, "why": "late" })]
        );
    }

    /// T1e D (J8F): the browser files a post's kept copy by the desktop's rule
    /// (`group_state::Copies`), not at its first `released`: the copy waits for its post to
    /// settle, and a refusal as `OLD_EPOCH` sends it waiting for the post's next send.
    #[test]
    fn a_kept_copy_waits_for_its_post_to_settle_and_old_epoch_rearms_it() {
        let mut core = SignalCore::new().unwrap();
        core.gk.account = Some(Rc::new(AccountLink::default()));
        start(&mut core, false);
        core.gk.track(TEXT, true, "c:abc", false, false, false);
        core.gk_post(TEXT, [9; 16], b"hi".to_vec(), "c:abc".into(), None);
        assert_eq!(core.gk.copies.went_under(&[9; 16]), Some(None));
        let ep = GkEpoch {
            group: "c:abc".into(),
            gen: [1; 16],
            epoch: 4,
            d_e: [4; 32],
            ck: [0; 32].into(),
        };
        let went = GkOut {
            send: vec![ClientMessage::EpochPost {
                channel_id: TEXT,
                group: "c:abc".into(),
                gen: [1; 16],
                epoch: 4,
                blob: Some(vec![1]),
                ciphertext: vec![2],
            }],
            released: vec![(TEXT, [9; 16], ep)],
            ..GkOut::default()
        };
        let mut out = Out::default();
        core.gk.take(went, &mut out);
        assert_eq!(
            core.gk.copies.went_under(&[9; 16]),
            Some(Some(4)),
            "not filed at the release"
        );
        let refused = ServerMessage::EpochRefused {
            group: "c:abc".into(),
            what: wire::refused_what::POST,
            why: wire::refused_why::OLD_EPOCH,
            detail: String::new(),
        };
        core.gk_frame(&postcard::to_allocvec(&refused).unwrap())
            .unwrap();
        assert_eq!(core.gk.copies.went_under(&[9; 16]), Some(None));
    }

    #[test]
    fn what_the_accounts_actions_say_for_the_page_waits_for_its_next_call_of_the_account() {
        let link = Rc::new(AccountLink::default());
        let mut core = SignalCore::new().unwrap();
        core.gk.account = Some(link.clone());
        let past = Actions {
            send: vec![ClientMessage::Disconnect],
            emit: vec![(
                "stored-channel-message",
                json!({ "conv": "c:abc", "seq": 4 }),
            )],
            memory: Some(("k".into(), LogMemory::default())),
            memory_named: true,
            ..Actions::default()
        };
        let mut out = Out::default();
        core.gk.actions(past, &mut out);
        assert_eq!(out.send.len(), 1, "frames go at once");
        assert!(out.emit.is_empty(), "events only through the account's run");
        assert!(out.held);
        // The page's next call of the account, which marks a replay and writes the cursors
        let mut next = Actions {
            emit: vec![("dm-kept", json!({}))],
            ..Actions::default()
        };
        link.held.borrow_mut().give(&mut next);
        let names: Vec<&str> = next.emit.iter().map(|(n, _)| *n).collect();
        assert_eq!(names, ["stored-channel-message", "dm-kept"]);
        assert!(next.memory.is_some() && next.memory_named);
        assert!(link.held.borrow().is_empty());
    }

    #[test]
    fn whoever_posts_is_noted_against_the_pins_as_on_the_live_path() {
        let mut core = SignalCore::new().unwrap();
        let p = OpenedPost {
            channel_id: TEXT,
            group: "c:abc".into(),
            user_id: 2,
            username: "ann#1".into(),
            account: None,
            is_admin: false,
            is_moderator: false,
            envelope: voipc_crypto::envelope::envelope("0123", "hi", None),
            timestamp: 77,
        };
        let mut out = Out::default();
        let o = GkOut {
            posts: vec![p],
            ..GkOut::default()
        };
        core.gk.take(o, &mut out);
        assert_eq!(out.seen, [(2, None, "ann#1".to_string())]);
        assert_eq!(out.emit[0].0, "channel-chat-message");
    }

    #[test]
    fn a_reset_rotates_the_seat_keys_only_once_the_group_key_is_on() {
        let link = Rc::new(AccountLink::default());
        *link.whose.borrow_mut() = Some(([1; 16], "alice".into()));
        let begin = |on: bool| {
            let mut core = SignalCore::new().unwrap();
            core.gk.account = Some(link.clone());
            core.set_own_user_id(7);
            let s = Start {
                on,
                run: RUN,
                clock: now_millis() / 1000,
                help: true,
                visible: true,
                in_call: false,
                local: None,
            };
            core.gk_start(s).unwrap();
        };
        reset_done([1; 16], "alice".into());
        begin(false);
        begin(true);
        assert!(!link.take_reset(), "taken by the sign-in with the key on");
        reset_done([1; 16], "alice".into());
        begin(false);
        assert!(link.take_reset(), "kept past a relay with the key off");
    }

    #[test]
    fn a_guests_highest_counters_seen_go_on_to_the_next_connection_in_this_page() {
        let mut core = SignalCore::new().unwrap();
        start(&mut core, false);
        let seen = Seen { n: 3, made: 100 };
        core.gk.pins.counters.raise([4; 16], seen, true);
        core.gk.end();
        let kept = core.gk.keep().expect("kept");
        let mut next = SignalCore::new().unwrap();
        next.set_own_user_id(8);
        let s = Start {
            on: true,
            run: RUN,
            clock: now_millis() / 1000,
            help: false,
            visible: true,
            in_call: false,
            local: Some(kept),
        };
        next.gk_start(s).unwrap();
        assert_eq!(next.gk.pins.counters.seen(&[4; 16]).map(|s| s.n), Some(3));
    }

    #[test]
    fn floors_go_on_to_the_next_connection_in_this_page() {
        let mut core = SignalCore::new().unwrap();
        assert!(core.gk.keep().is_none(), "never started");
        start(&mut core, false);
        core.gk.end();
        let kept = core.gk.keep().expect("kept for the page's life");
        let mut next = SignalCore::new().unwrap();
        next.set_own_user_id(8);
        let s = Start {
            on: true,
            run: RUN,
            clock: now_millis() / 1000,
            help: false,
            visible: true,
            in_call: false,
            local: Some(kept),
        };
        assert!(
            volunteers(&next.gk_start(s).unwrap()).is_empty(),
            "help off"
        );
    }
}
