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

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use voipc_crypto::account_session::{AccountSession, Actions};
use voipc_crypto::group_key::{GroupKind, MemberId};
use voipc_crypto::group_state::{
    group_id, BuildJob, Copies, Early, EarlyPost, GkCtx, GkEpoch, GkNames, GkOut, GkPins, GkStart,
    GkTrack, GroupKeying, KeptCopy, LocalGk, MemoryPins, OpenedPost, PastEpoch, Platform, SeenBook,
    VaultFloor, VoiceKeys,
};
use voipc_crypto::time::now_millis;
use voipc_crypto::{MediaKeyRing, SignalStores};
use voipc_protocol::messages::{ClientMessage, ServerMessage};
use voipc_protocol::types::UserInfo;

use crate::account::AccountLink;

/// Rounds of account news one call settles; what is left goes at the next call.
const SETTLE_ROUNDS: usize = 4;

/// What this browser keeps of a signed-in account's `LocalGk::mirror` past the page (dive 1
/// F1): the seat-key counters its pages checked or raised, which a relay that withholds the
/// vault's group-key pages would otherwise take with them at a reload. gk-mirror.ts seals
/// these postcard bytes into IndexedDB. They name the relay and the account, and a sign-in
/// of another takes none of them.
#[derive(Serialize, Deserialize)]
struct StoredMirror<B> {
    version: u32,
    relay: [u8; 16],
    account: [u8; 16],
    book: B,
}

/// `StoredMirror::version`.
const MIRROR_VERSION: u32 = 1;
/// Stored bytes past this are not read. A mirror at its bound (`group_state::MIRROR_MOST`,
/// 32,768 accounts, and its slack) is about 1.1 MB: at most 32 bytes a row.
const MIRROR_MOST_BYTES: usize = 4 << 20;

impl StoredMirror<SeenBook> {
    fn read(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > MIRROR_MOST_BYTES {
            return None;
        }
        let m: Self = postcard::from_bytes(bytes).ok()?;
        (m.version == MIRROR_VERSION).then_some(m)
    }
}

fn mirror_bytes(relay: [u8; 16], account: [u8; 16], book: &SeenBook) -> Vec<u8> {
    let m = StoredMirror {
        version: MIRROR_VERSION,
        relay,
        account,
        book,
    };
    postcard::to_allocvec(&m).expect("a mirror encodes")
}

/// What to write over a stored mirror with ours (`Gk::mirror`'s bytes): of one relay and
/// account, the two as one, the higher of each counter standing and bounded as the mirror is,
/// so what another tab of this browser kept meanwhile is not lost; over one that does not read
/// (or none), ours alone. `None`: write nothing, over one of another relay or account, over
/// one a newer VoIPC wrote (an older build never writes over newer data, COMPATIBILITY.md), or
/// when ours do not read. Another account's is left because the account id is the relay's
/// word (`Authenticated`): one sign-in it names under another id must not cost the next
/// honest one these counters. The cost: a name a new account took after the old one was
/// deleted elsewhere keeps its counters only for the page, until the old row is forgotten
/// (gk-mirror.ts `forgetMirror`: the device forgotten, or the account deleted, here).
pub fn mirror_merge(stored: &[u8], ours: &[u8]) -> Option<Vec<u8>> {
    let b = StoredMirror::read(ours)?;
    let newer = postcard::take_from_bytes::<u32>(stored).is_ok_and(|(v, _)| v > MIRROR_VERSION);
    if newer {
        return None;
    }
    let Some(a) = StoredMirror::read(stored) else {
        return Some(ours.to_vec());
    };
    if (a.relay, a.account) != (b.relay, b.account) {
        return None;
    }
    let mut local = LocalGk {
        mirror: b.book,
        ..LocalGk::default()
    };
    local.mirror_in(&a.book);
    Some(mirror_bytes(b.relay, b.account, &local.mirror))
}

/// The variant tags of the group key's frames: from the one after `GroupKeys` to
/// `EpochPostTaken`, the last (protocol 26 appended them in that order).
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
        let last = ServerMessage::EpochPostTaken {
            group: String::new(),
            post: [0; 16],
        };
        (first, tag(&last))
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
    /// What this browser keeps of the account's counters may have moved: `Gk::mirror`.
    pub kept: bool,
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
    /// The relay and the account of a signed-in connection, whose counters this browser
    /// keeps past the page (`mirror`).
    mirror_of: Option<([u8; 16], [u8; 16])>,
    /// The bytes `mirror` last handed out, or `Start::mirror` handed in: those again are not.
    mirror_sent: Option<Vec<u8>>,
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
    /// A signed-in account's counters as this browser kept them past the page (`mirror`'s
    /// bytes): merged into `local`'s, the higher of each standing. A guest's are ignored.
    pub mirror: Option<Vec<u8>>,
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
            // After a reset with the recovery key, once the keys are on, before anything else
            // (§5.11)
            let rotate = s.on && link.take_reset();
            let on = self.with_session(|session| {
                (
                    session.account_id(),
                    session.gk_begin(s.on, s.clock, rotate),
                )
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
        let mut local = s.local;
        // An account's counters this browser kept past its last page, with what this page
        // kept (dive 1 F1): a reload no longer loses them to a relay that withholds the
        // vault's pages
        let relay = self
            .account
            .as_ref()
            .and_then(|l| l.whose.borrow().as_ref().map(|w| w.0));
        self.mirror_of = None;
        self.mirror_sent = None;
        if let (Some(id), Some(relay)) = (account, relay) {
            self.mirror_of = Some((relay, id));
            let stored = s.mirror.as_deref().and_then(StoredMirror::read);
            if let Some(m) = stored.filter(|m| m.relay == relay && m.account == id) {
                local
                    .get_or_insert_with(LocalGk::default)
                    .mirror_in(&m.book);
                self.mirror_sent = s.mirror;
            }
            out.kept = true;
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
            local,
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
        } else if let ServerMessage::EpochPostTaken { .. } = msg {
            // The relay took a post of ours: its kept copy is filed now, not at the next tick,
            // so a page closed a moment after posting still keeps it
            let due = self.copies.taken(&msg);
            self.file(due.into_iter().collect(), &mut out);
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
    /// filed once the relay took it, under the epoch it went under (`Copies`). A channel
    /// whose group is not tracked yet (its join not answered) holds it until it is (`Early`).
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
        // A copy is kept only on the relay's word that it took the post (`Copies::end`)
        self.copies.end();
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

    /// A signed-in account's counters (`LocalGk::mirror`, every one this page checked or
    /// raised), as bytes for `Start::mirror`, for this browser to keep past the page: when
    /// they differ from those last handed out or in. Also after `end`.
    pub fn mirror(&mut self) -> Option<Vec<u8>> {
        let (relay, account) = self.mirror_of?;
        let book = &self.keying.local()?.mirror;
        // Nothing met, and nothing kept to go on from
        if self.mirror_sent.is_none() && *book == SeenBook::default() {
            return None;
        }
        let bytes = mirror_bytes(relay, account, book);
        if self.mirror_sent.as_ref() == Some(&bytes) {
            return None;
        }
        self.mirror_sent = Some(bytes.clone());
        Some(bytes)
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
        out.kept |= o.local_dirty && self.mirror_of.is_some();
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
            mirror: None,
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
            ServerMessage::EpochPostTaken {
                group: "g".into(),
                post: [7; 16],
            },
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

    /// T1e D (J8F), J9: the browser files a post's kept copy by the desktop's rule
    /// (`group_state::Copies`), not at its first `released`: the copy waits for the relay to
    /// take its post (`EpochPostTaken`) and is filed in that frame's call, not at a tick; a
    /// refusal as `OLD_EPOCH` sends it waiting for the post's next send, and only that send's
    /// word files it, under the epoch it went under.
    #[test]
    fn a_kept_copy_is_filed_when_the_relay_takes_its_post_and_old_epoch_rearms_it() {
        let mut core = SignalCore::new().unwrap();
        core.gk.account = Some(Rc::new(AccountLink::default()));
        start(&mut core, false);
        core.gk.track(TEXT, true, "c:abc", false, false, false);
        core.gk_post(TEXT, [9; 16], b"hi".to_vec(), "c:abc".into(), None);
        assert_eq!(core.gk.copies.went_under(&[9; 16]), Some(None));
        let ep = |epoch: u32| GkEpoch {
            group: "c:abc".into(),
            gen: [1; 16],
            epoch,
            d_e: [epoch as u8; 32],
            ck: [0; 32].into(),
        };
        let went = |epoch: u32, ciphertext: Vec<u8>| GkOut {
            send: vec![ClientMessage::EpochPost {
                channel_id: TEXT,
                group: "c:abc".into(),
                gen: [1; 16],
                epoch,
                blob: Some(vec![1]),
                ciphertext,
            }],
            released: vec![(TEXT, [9; 16], ep(epoch))],
            ..GkOut::default()
        };
        let taken = |ciphertext: &[u8]| {
            let msg = ServerMessage::EpochPostTaken {
                group: "c:abc".into(),
                post: voipc_crypto::group_key::wire::post_digest(ciphertext),
            };
            postcard::to_allocvec(&msg).unwrap()
        };
        let mut out = Out::default();
        core.gk.take(went(4, vec![2]), &mut out);
        assert_eq!(
            core.gk.copies.went_under(&[9; 16]),
            Some(Some(4)),
            "not filed at the release"
        );
        core.gk_frame(&taken(&[5])).unwrap();
        assert_eq!(
            core.gk.copies.went_under(&[9; 16]),
            Some(Some(4)),
            "not for another post"
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
        core.gk.take(went(6, vec![3]), &mut out);
        core.gk_frame(&taken(&[2])).unwrap();
        assert_eq!(
            core.gk.copies.went_under(&[9; 16]),
            Some(Some(6)),
            "not for the send refused"
        );
        core.gk_frame(&taken(&[3])).unwrap();
        assert_eq!(
            core.gk.copies.went_under(&[9; 16]),
            None,
            "filed in the frame's call"
        );
        // Filed under epoch 6: offered again only under a newer head
        let now = now_millis();
        assert!(core.gk.copies.file(now, |_| Some(ep(6))).is_empty());
        let again = core.gk.copies.file(now, |_| Some(ep(7)));
        assert_eq!(again.len(), 1);
        assert_eq!(
            (again[0].0.envelope.as_slice(), again[0].1.epoch),
            (&b"hi"[..], 7)
        );
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
                mirror: None,
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
            mirror: None,
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
            mirror: None,
        };
        assert!(
            volunteers(&next.gk_start(s).unwrap()).is_empty(),
            "help off"
        );
    }
}

// Dive 1 F1 in the browser: a signed-in account's counters, past a reload. A page is a fresh
// `SignalCore` and a fresh `AccountSession` of the same account, fed by a relay that is this
// test; what the browser keeps between the two is `Gk::mirror`'s bytes (gk-mirror.ts keeps
// them in IndexedDB), and nothing else of the page.
#[cfg(test)]
mod reload_tests {
    use std::collections::{HashMap, VecDeque};

    use serde::Serialize;
    use voipc_crypto::account::{SignedIn, Vault};
    use voipc_crypto::group_key::commit::Pair;
    use voipc_crypto::group_key::{
        names_hash, Added, Endorsement, Keyholder, Kind, Origin, Removed, SeatPair, SignedHeader,
    };
    use voipc_crypto::group_key::{GroupKind, HeaderV1, MemberId, Seen};
    use voipc_crypto::sync::{Counter, GkIndex, LogMemory, ITEM_GK_FLOORS};
    use voipc_crypto::IdentityKeyPair;
    use voipc_protocol::gk::{HeaderIn, InPiece};
    use voipc_protocol::messages::{AccountReply, AccountRequest, ClientMessage, ServerMessage};
    use voipc_protocol::types::{AccountInfo, VaultBlob};

    use super::*;
    use crate::signal::SignalCore;

    const RELAY: [u8; 16] = [9; 16];
    const ME: [u8; 16] = [1; 16];
    const ALICE: [u8; 16] = [0xa1; 16];
    const K1: [u8; 16] = [0x11; 16];
    const RUN: [u8; 16] = [0x22; 16];
    const CHANNEL: u32 = 1;
    const GROUP: &str = "c:lounge-4";
    const DAY: u64 = 24 * 60 * 60;

    fn now() -> u64 {
        now_millis() / 1000
    }

    fn raw(ik: &IdentityKeyPair) -> [u8; 32] {
        ik.public_key().public_key_bytes().try_into().unwrap()
    }

    /// `sync::gk_floors::CounterRow`, field for field (postcard is positional): a `gkc.N` page
    /// is `Vec<CounterRow>`, sealed as that vault item.
    #[derive(Serialize)]
    struct CounterRow {
        account: [u8; 16],
        counter: Option<Counter>,
        pin: Option<(u64, [u8; 8])>,
    }

    /// The account's vault on the relay, and what the relay does with it.
    #[derive(Default)]
    struct Relay {
        items: HashMap<String, VaultBlob>,
        /// Hostile: the group key's index is left out of the sign-in frame, its pages are
        /// answered as not there (dive 1 F1).
        withholds_gk: bool,
    }

    impl Relay {
        fn hidden(&self, k: &str) -> bool {
            self.withholds_gk
                && (k == ITEM_GK_FLOORS || k.starts_with("gkf.") || k.starts_with("gkc."))
        }

        fn sign_in(&self) -> Vec<VaultBlob> {
            self.items
                .values()
                .filter(|b| b.k.starts_with("item.") && !self.hidden(&b.k))
                .cloned()
                .collect()
        }

        fn answer(&mut self, m: ClientMessage) -> Option<AccountReply> {
            match m {
                ClientMessage::Account(AccountRequest::VaultPut { k, v, expect }) => {
                    if self.hidden(&k) {
                        return None;
                    }
                    let held = self.items.get(&k).map_or(0, |b| b.version);
                    if held != expect {
                        return Some(AccountReply::VaultConflict {
                            blob: self.items.get(&k).cloned(),
                            k,
                        });
                    }
                    let version = held + 1;
                    self.items.insert(
                        k.clone(),
                        VaultBlob {
                            k: k.clone(),
                            v,
                            version,
                        },
                    );
                    Some(AccountReply::VaultStored { k, version })
                }
                ClientMessage::Account(AccountRequest::VaultPage { k }) => {
                    let blob = self.items.get(&k).filter(|_| !self.hidden(&k)).cloned();
                    Some(AccountReply::VaultPageFound { k, blob })
                }
                _ => None,
            }
        }
    }

    /// Alice's counter 5 in the account's vault, seen a month ago, as an honest relay holds it.
    struct World {
        relay: Relay,
        dek: [u8; 32],
        identity: IdentityKeyPair,
        alice: IdentityKeyPair,
        k1: IdentityKeyPair,
        seen_at: u64,
    }

    fn world() -> World {
        let vault = Vault::create(RELAY, "writer");
        let seen_at = now() - 30 * DAY;
        let mut relay = Relay::default();
        let rows = vec![CounterRow {
            account: ALICE,
            counter: Some(Counter {
                n: 5,
                made: seen_at,
                rotation: true,
            }),
            pin: None,
        }];
        let page = vault.seal_item("gkc.0", 1, &postcard::to_allocvec(&rows).unwrap());
        relay
            .items
            .insert("gkc.0".into(), VaultBlob { version: 1, ..page });
        let index = GkIndex {
            format: 1,
            floor_pages: vec![],
            counter_pages: vec![1],
        };
        relay.items.insert(
            ITEM_GK_FLOORS.into(),
            VaultBlob {
                version: 1,
                ..vault.seal_item(ITEM_GK_FLOORS, 1, &index.to_bytes())
            },
        );
        World {
            relay,
            dek: vault.dek(),
            identity: voipc_crypto::generate_identity_key_pair(),
            alice: voipc_crypto::generate_identity_key_pair(),
            k1: voipc_crypto::generate_identity_key_pair(),
            seen_at,
        }
    }

    /// One page of the account: signed in, the group key on with `mirror` handed in (what
    /// this browser kept), every page the relay gives read, and the channel followed.
    struct Page {
        core: SignalCore,
        link: Rc<AccountLink>,
    }

    impl Page {
        fn open(w: &mut World, mirror: Option<Vec<u8>>) -> Page {
            Page::open_with(w, None, mirror)
        }

        /// With `local`: what an earlier connection kept in this page (`Gk::keep`).
        fn open_with(w: &mut World, local: Option<LocalGk>, mirror: Option<Vec<u8>>) -> Page {
            Page::open_as(w, ME, local, mirror)
        }

        /// Signed in as the account the relay names `id` (`Authenticated`'s `AccountInfo`).
        fn open_as(
            w: &mut World,
            id: [u8; 16],
            local: Option<LocalGk>,
            mirror: Option<Vec<u8>>,
        ) -> Page {
            let signed = SignedIn {
                relay_id: RELAY,
                name: "writer".into(),
                vault: Vault::from_dek(RELAY, "writer", w.dek),
                identity: w.identity,
                recovery: None,
                blobs: w.relay.sign_in(),
                binding: None,
                keyed: false,
                login_key: None,
            };
            let info = AccountInfo {
                id,
                name: "writer".into(),
                scopes: Vec::new(),
                needs_2fa: false,
                totp_enabled: false,
            };
            let (session, _) = AccountSession::start(
                signed,
                &info,
                LogMemory::default(),
                false,
                false,
                voipc_protocol::codec::PROTOCOL_VERSION,
            );
            let link = Rc::new(AccountLink::default());
            *link.session.borrow_mut() = Some(session);
            *link.whose.borrow_mut() = Some((RELAY, "writer".into()));
            let mut core = SignalCore::with_identity(&w.identity).unwrap();
            core.gk.account = Some(link.clone());
            core.set_own_user_id(20);
            let mut page = Page { core, link };
            let first = page.session(|s| s.after_connect());
            page.serve(&mut w.relay, first.send);
            let out = page
                .core
                .gk_start(Start {
                    on: true,
                    run: RUN,
                    clock: now(),
                    help: false,
                    visible: true,
                    in_call: false,
                    local,
                    mirror,
                })
                .unwrap();
            assert!(out.kept, "a signed-in page keeps its counters");
            page.serve(&mut w.relay, out.send);
            for _ in 0..8 {
                let a = page.session(|s| s.tick());
                page.serve(&mut w.relay, a.send);
            }
            assert!(
                page.session(|s| s.gk_pins().ready()),
                "the pins and the group key's pages are in"
            );
            let out = page
                .core
                .gk
                .track(CHANNEL, true, GROUP, false, false, false);
            page.serve(&mut w.relay, out.send);
            page
        }

        fn session<R>(&self, f: impl FnOnce(&mut AccountSession) -> R) -> R {
            f(self.link.session.borrow_mut().as_mut().unwrap())
        }

        /// What goes out, answered as the relay answers until nothing more comes; what the
        /// account says for the group key goes to it, as account.ts and session.ts hand it.
        fn serve(&mut self, relay: &mut Relay, out: Vec<ClientMessage>) {
            let mut queue: VecDeque<ClientMessage> = out.into();
            while let Some(m) = queue.pop_front() {
                let Some(reply) = relay.answer(m) else {
                    continue;
                };
                let mut a = self.session(|s| s.on_reply(&reply));
                self.link.news.borrow_mut().take_from(&mut a);
                queue.extend(a.send);
                queue.extend(self.core.gk.news().send);
            }
        }

        /// The relay pushes `h`. Whether what this browser keeps may have moved (`Out::kept`).
        fn push(&mut self, relay: &mut Relay, h: &SignedHeader) -> bool {
            let msg = ServerMessage::EpochIn {
                group: GROUP.into(),
                part: 0,
                last: true,
                piece: Box::new(InPiece {
                    chain: vec![HeaderIn {
                        body: h.body().to_vec(),
                        sig: h.sig().to_vec(),
                    }],
                    ..InPiece::default()
                }),
            };
            let out = self
                .core
                .gk_frame(&postcard::to_allocvec(&msg).unwrap())
                .unwrap();
            self.serve(relay, out.send);
            out.kept
        }

        /// The header the page holds the group's floor at.
        fn floor(&self) -> Option<[u8; 32]> {
            self.core
                .gk
                .keying
                .local()
                .and_then(|l| l.floors.get(GROUP))
                .map(|f| f.floor.d)
        }

        /// The page goes (a reload, a closed tab): what this browser keeps of it.
        fn close(mut self, relay: &mut Relay) -> Option<Vec<u8>> {
            let out = self.core.gk.end();
            self.serve(relay, out.send);
            self.core.gk.mirror()
        }

        /// The counter the page checks `account` against now, book and mirror both.
        fn counter(&self, account: &[u8; 16]) -> Option<u32> {
            let mirror = self.core.gk.keying.local()?.mirror.seen(account);
            let book = self.session(|s| s.gk_pins().seen(account));
            mirror.into_iter().chain(book).map(|s| s.n).max()
        }
    }

    /// A desktop keyholder entry (origin 0x03) of `account` under its `ik`, at counter `n`.
    fn keyholder(account: [u8; 16], ik: &IdentityKeyPair, n: u32, made: u64) -> Keyholder {
        let pair = SeatPair::generate();
        let m = MemberId::Account(account);
        let endorsement =
            Endorsement::sign(ik, Origin::Desktop, m, n, made, &pair.public()).unwrap();
        Pair {
            keys: pair.public(),
            endorsement,
        }
        .entry(GroupKind::Text, m, raw(ik))
        .expect("a desktop keyholder entry")
    }

    /// A Genesis of generation `gen`, signed by K1, at `time`, with Alice's desktop pair of
    /// counter `n` (made `made`) among its keyholders.
    fn genesis(w: &World, gen: [u8; 16], time: u64, n: u32, made: u64) -> SignedHeader {
        let mut hd = HeaderV1 {
            group_kind: GroupKind::Text,
            group: GROUP.into(),
            gen,
            epoch: 1,
            join: 0,
            kind: Kind::Genesis,
            time,
            parent: [0; 32],
            epoch_parent: [0; 32],
            kh_parent: [0; 32],
            signer: MemberId::Account(K1),
            keyholders: vec![
                keyholder(K1, &w.k1, 1, time - 60),
                keyholder(ALICE, &w.alice, n, made),
            ],
            gated: true,
            seed: 1,
            seed_floor: 1,
            exits_upto: 0,
            seats: 2,
            buckets: 1,
            conn_seats: 0,
            bucket_root: [1; 32],
            keyring_hash: [1; 32],
            names_hash: [0; 32],
            added: Added::List(vec![]),
            removed: Removed::List(vec![]),
            confirm: [1; 32],
        };
        hd.names_hash = names_hash(None, &hd);
        SignedHeader::sign(hd, &w.k1).expect("a header of a valid shape")
    }

    /// The first page, under an honest relay: the vault holds Alice's counter 5, and the page
    /// checks a Genesis naming her current pair against it. What this browser kept of it.
    fn first_page(w: &mut World) -> Option<Vec<u8>> {
        let mut page = Page::open(w, None);
        let t = now();
        let g = genesis(w, [7; 16], t - 3000, 5, t - 4000);
        page.push(&mut w.relay, &g);
        assert_eq!(page.floor(), Some(g.d()), "the page took K1's Genesis");
        page.close(&mut w.relay)
    }

    /// The control: after a reload under an honest relay the vault's pages hold Alice's
    /// counter 5, and a new start naming her old pair (counter 3) is refused (§4.4 rule 8 on a
    /// keyholder entry). It passes today, and shows the page reaches the rule.
    #[test]
    fn control_after_a_reload_with_the_vault_handed_over_an_old_counter_is_refused() {
        let mut w = world();
        first_page(&mut w);
        let mut page = Page::open(&mut w, None);
        let old = genesis(&w, [8; 16], now() - 60, 3, w.seen_at - 30 * DAY);
        page.push(&mut w.relay, &old);
        assert_eq!(page.floor(), None, "refused");
    }

    /// Dive 1 F1, the browser: a page that met Alice's counter 5 is reloaded, and the relay
    /// leaves the group key's index and pages out of the next sign-in. The new page has no
    /// page memory of the last, and its book no counter of Alice's; what this browser kept
    /// (IndexedDB) still holds her 5, so her old pair (counter 3) is refused (§6 hostile relay,
    /// Cannot: "Seat an account's old seat keys again once a keyholder has seen its newer
    /// counter, or past a writer that has seen it"). Her current pair is taken: the refusal is
    /// the counter's.
    #[test]
    fn f1_after_a_reload_a_withheld_gk_index_does_not_let_an_old_counter_past_the_page() {
        let mut w = world();
        let kept = first_page(&mut w);
        w.relay.withholds_gk = true;
        let mut page = Page::open(&mut w, kept);
        assert_eq!(
            page.session(|s| s.gk_pins().seen(&ALICE)),
            None,
            "the book holds no counter for Alice now"
        );
        let old = genesis(&w, [8; 16], now() - 60, 3, w.seen_at - 30 * DAY);
        page.push(&mut w.relay, &old);
        assert_eq!(
            page.floor(),
            None,
            "a new start naming Alice's pair of counter 3 must be refused by a browser whose \
             last page met her counter 5; the reloaded page took it"
        );
        let current = genesis(&w, [9; 16], now() - 60, 5, now() - 120);
        page.push(&mut w.relay, &current);
        assert_eq!(
            page.floor(),
            Some(current.d()),
            "her pair of counter 5 is taken"
        );
    }

    /// The bytes name their relay and account: a copy of another's is not taken (here under
    /// the same keys in this browser, which gk-mirror.ts never hands over either).
    #[test]
    fn a_kept_copy_of_another_relay_or_account_is_not_taken() {
        let mut w = world();
        let kept = first_page(&mut w).expect("the first page met Alice's counter");
        let book = StoredMirror::read(&kept).expect("it reads").book;
        assert_eq!(book.seen(&ALICE).map(|s| s.n), Some(5));
        w.relay.withholds_gk = true;
        for other in [
            mirror_bytes([8; 16], ME, &book),
            mirror_bytes(RELAY, [2; 16], &book),
        ] {
            let mut page = Page::open(&mut w, Some(other));
            assert_eq!(page.counter(&ALICE), None, "nothing of it is taken");
            let old = genesis(&w, [8; 16], now() - 60, 3, w.seen_at - 30 * DAY);
            page.push(&mut w.relay, &old);
            assert_eq!(
                page.floor(),
                Some(old.d()),
                "taken: no counter of hers here"
            );
        }
    }

    /// The account id is the relay's word (`Authenticated`), bound to nothing the vault or
    /// the sign-in proofs hold. A relay that names another one at one sign-in gets that
    /// connection checked without what this browser kept, and what that page meets is not
    /// written over the account's copy (`mirror_merge`, as gk-mirror.ts `write` merges): the
    /// next sign-in under the real id, with the group key's pages withheld, still refuses
    /// Alice's old pair.
    #[test]
    fn a_sign_in_under_another_account_id_leaves_the_kept_counters_for_the_next() {
        let mut w = world();
        let stored = first_page(&mut w).expect("the first page met Alice's counter");
        let mut lie = Page::open_as(&mut w, [2; 16], None, Some(stored.clone()));
        let g = genesis(&w, [9; 16], now() - 60, 5, now() - 120);
        lie.push(&mut w.relay, &g);
        assert_eq!(lie.floor(), Some(g.d()), "it took her current pair");
        let ours = lie.close(&mut w.relay).expect("it met her counter");
        // gk-mirror.ts `write`: the stored row merged with ours; nothing written on `None`
        let row = mirror_merge(&stored, &ours).unwrap_or(stored);
        w.relay.withholds_gk = true;
        let mut page = Page::open(&mut w, Some(row));
        assert_eq!(
            page.counter(&ALICE),
            Some(5),
            "the account's copy is still there"
        );
        let old = genesis(&w, [8; 16], now() - 60, 3, w.seen_at - 30 * DAY);
        page.push(&mut w.relay, &old);
        assert_eq!(page.floor(), None, "refused");
    }

    /// What this page kept for its next connection (`keep`) and what the browser kept past
    /// its pages both count, the higher of each.
    #[test]
    fn a_reconnect_in_the_page_merges_its_kept_counters_with_the_browsers() {
        let mut w = world();
        let mut page = Page::open(&mut w, None);
        let t = now();
        let g = genesis(&w, [7; 16], t - 3000, 5, t - 4000);
        page.push(&mut w.relay, &g);
        page.core.gk.end();
        let local = page.core.gk.keep().expect("kept for the page's life");
        let mut other = SeenBook::default();
        other.raise(K1, Seen { n: 2, made: t - 50 }, true);
        other.raise(
            ALICE,
            Seen {
                n: 4,
                made: t - 9 * DAY,
            },
            true,
        );
        w.relay.withholds_gk = true;
        let next = Page::open_with(&mut w, Some(local), Some(mirror_bytes(RELAY, ME, &other)));
        assert_eq!(next.counter(&ALICE), Some(5), "the page's, the higher");
        assert_eq!(next.counter(&K1), Some(2), "the browser's");
    }

    /// The counters go out for the browser to keep when they moved, once; a page that met
    /// nothing new since it came in hands none out.
    #[test]
    fn the_counters_are_handed_out_once_each_time_they_move() {
        let mut w = world();
        let mut page = Page::open(&mut w, None);
        assert_eq!(page.core.gk.mirror(), None, "nothing met yet");
        let t = now();
        let g = genesis(&w, [7; 16], t - 3000, 5, t - 4000);
        assert!(page.push(&mut w.relay, &g));
        let first = page.core.gk.mirror().expect("Alice's counter met");
        assert_eq!(page.core.gk.mirror(), None, "handed out once");
        assert_eq!(page.close(&mut w.relay), None, "nothing moved since");
        let mut next = Page::open(&mut w, Some(first));
        assert_eq!(next.core.gk.mirror(), None, "what came in, as it came");
    }

    /// A guest keeps nothing past the page (no account to keep it under) and takes nothing.
    #[test]
    fn a_guest_keeps_no_counters_past_the_page_and_takes_none() {
        let mut book = SeenBook::default();
        book.raise(ALICE, Seen { n: 5, made: 100 }, true);
        let mut core = SignalCore::new().unwrap();
        core.set_own_user_id(7);
        let out = core
            .gk_start(Start {
                on: true,
                run: RUN,
                clock: now(),
                help: false,
                visible: true,
                in_call: false,
                local: None,
                mirror: Some(mirror_bytes(RELAY, ME, &book)),
            })
            .unwrap();
        assert!(!out.kept);
        assert_eq!(core.gk.keying.local().unwrap().mirror, SeenBook::default());
        assert_eq!(core.gk.pins.counters.seen(&ALICE), None);
        assert_eq!(core.gk.mirror(), None);
    }

    /// Two tabs' copies merge, the higher of each. Over one that does not read, ours go
    /// alone. Over a copy of another relay or account, nothing goes: the account id is the
    /// relay's word, and one sign-in under another must not cost the next honest one what
    /// this browser kept. Over one a newer VoIPC wrote, nothing goes either (COMPATIBILITY:
    /// an older build never writes over newer data).
    #[test]
    fn two_tabs_copies_merge_and_others_do_not() {
        let mut a = SeenBook::default();
        a.raise(ALICE, Seen { n: 5, made: 100 }, true);
        let mut b = SeenBook::default();
        b.raise(ALICE, Seen { n: 4, made: 10 }, true);
        b.raise(K1, Seen { n: 2, made: 50 }, true);
        let ours = mirror_bytes(RELAY, ME, &b);
        let merged = mirror_merge(&mirror_bytes(RELAY, ME, &a), &ours).expect("one account's");
        let m = StoredMirror::read(&merged).unwrap();
        assert_eq!((m.relay, m.account), (RELAY, ME));
        assert_eq!(m.book.seen(&ALICE), Some(Seen { n: 5, made: 100 }));
        assert_eq!(m.book.seen(&K1), Some(Seen { n: 2, made: 50 }));
        assert_eq!(
            mirror_merge(&mirror_bytes(RELAY, [2; 16], &a), &ours),
            None,
            "another account's is left alone"
        );
        assert_eq!(
            mirror_merge(&mirror_bytes([8; 16], ME, &a), &ours),
            None,
            "another relay's is left alone"
        );
        let alone = Some(ours.clone());
        assert_eq!(mirror_merge(&[1, 2, 3], &ours), alone, "unreadable");
        assert_eq!(mirror_merge(&[], &ours), alone, "empty");
        let mut v2 = mirror_bytes(RELAY, ME, &a);
        v2[0] = 2;
        assert!(StoredMirror::read(&v2).is_none(), "another version");
        assert_eq!(
            mirror_merge(&v2, &ours),
            None,
            "a newer VoIPC's is left alone"
        );
        assert_eq!(
            mirror_merge(&ours, &[1, 2, 3]),
            None,
            "ours do not read: nothing"
        );
        let mut big = ours.clone();
        big.resize(MIRROR_MOST_BYTES + 1, 0);
        assert!(StoredMirror::read(&big).is_none(), "past the bound");
    }
}
