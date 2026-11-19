//! One group as a member holds it (3c): its floor and the keyholder header the floor names,
//! taking headers by C1's rules (§4.4), and the keys a seat reaches: welcome or row to `BK`,
//! the ratchets since, the seal to `CK` and its `confirm`. Self-rows for the account's other
//! devices. Every check is C1's; this only runs them in order and keeps what passed.

use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use voipc_protocol::gk::{self, InPiece, Lost, Part, Parts, Seq, VoiceSeatsPiece};
use voipc_protocol::messages::ClientMessage;
use zeroize::Zeroizing;

use super::holder::Duty;
use super::kept::Kept;
use super::{
    seat_keys, Dropped, GkCtx, GkEpoch, GkEvent, GkOut, GkState, GkTrack, LocalFloor, Warn, Who,
};
use crate::group_key::timers::{CHECK_WAIT_MS, EPOCH_AGE_MAX_SECS, FLOOR_AHEAD_GAP_SECS};
use crate::group_key::{
    check_above, check_added, check_counters, check_form, check_gated, check_link,
    check_new_generation, check_on_floor, check_regenesis, check_signer, check_time,
    check_voice_keyholders, check_walk, confirm_ok, open_seal, open_seat_welcome,
    open_seed_welcome, open_self_row, path_ok, ratchet, self_row, Clock, Epoch, Floor, Group,
    GroupKind, Holder, HolderId, Keyholder, Kind, Leaf, Me, MemberId, NamesFloor, Path, Refusal,
    RowBase, SeatRef, SignedHeader, Version, WalkLink, WalkTo, Warning, LIVE_WINDOW,
};

/// The epoch keys a member keeps: the head epoch's and the one before (1f.7).
const KEYS_KEPT: usize = 2;
/// Keyholder headers kept to check removals by (`kh_seen`), at most.
const KH_SEEN_MOST: usize = 64;
/// Digests of the headers last taken, met again below the floor without a word (`recent`).
const RECENT_MOST: usize = 16;

/// `CK` of one epoch.
pub(super) struct EpochKey {
    pub(super) gen: [u8; 16],
    pub(super) epoch: u32,
    pub(super) d_e: [u8; 32],
    pub(super) ck: Zeroizing<[u8; 32]>,
    /// The `time` of the epoch's opening header, where known: an epoch past 70 min holds
    /// posts (3f).
    pub(super) opened: Option<u64>,
}

impl EpochKey {
    /// Over 70 min old by its opening header, or of an age not known (§5.5): a writer holds
    /// its posts and fetches, a reader is told the keys are late. A relay that leaves the
    /// opening header out would otherwise keep an epoch writable for ever.
    pub(super) fn late(&self, now_secs: u64) -> bool {
        self.opened
            .is_none_or(|t| now_secs > t.saturating_add(EPOCH_AGE_MAX_SECS))
    }
}

/// One group, as this connection holds it.
pub(super) struct Member {
    pub(super) t: GkTrack,
    /// The vault floor is not in yet: no header is taken (3d).
    pub(super) vault_pending: bool,
    pub(super) floor: Option<Floor>,
    /// The keyholder header the floor names (`floor.kh`), when held.
    pub(super) kh: Option<SignedHeader>,
    /// The header at the floor, when held this run.
    pub(super) head: Option<SignedHeader>,
    /// The floor's own header as this device kept it (`LocalFloor::head`): what
    /// `EpochFloorAhead` carries after a restart, when no head is held yet (§5.7).
    floor_hdr: Option<SignedHeader>,
    /// Headers taken this run, newest last: an answer built before a push it overtook is
    /// below the floor but no sign of a relay behind it (3c).
    recent: VecDeque<[u8; 32]>,
    /// Headers taken since the keyholder duty last looked (`D`, parent's `D`): one `EpochIn`
    /// may carry many (a reconnect's catch-up), and a Join of ours among them is named.
    pub(super) took: Vec<([u8; 32], [u8; 32])>,
    /// When this device last took a header, by its clock (unix seconds).
    pub(super) taken: Option<u64>,
    /// The head epoch's opening `time`, where known.
    pub(super) opened: Option<u64>,
    /// Keyholder headers met this run in the floor's generation, by `D`.
    pub(super) kh_seen: BTreeMap<[u8; 32], SignedHeader>,
    pub(super) keys: Vec<EpochKey>,
    /// `BK` of the versions this seat holds, in the floor's generation.
    pub(super) bks: HashMap<(u64, u64), Zeroizing<[u8; 32]>>,
    pub(super) leaf: Option<Leaf>,
    /// `s_m` per seat of ours and seed, in the floor's generation.
    s_m: HashMap<(SeatRef, u32), Zeroizing<[u8; 32]>>,
    /// Row bases by our seat, `(K, tag(KX_K))` and seed (§3.3).
    row_bases: HashMap<(SeatRef, HolderId, u32), RowBase>,
    /// Seeds whose self-row went out, per seat, in the floor's generation.
    self_rows_done: HashSet<(SeatRef, u32)>,
    parts: Parts<(), InPiece>,
    /// A whole `EpochIn` that waits for the vault floor or the pins.
    pub(super) waiting: Option<InPiece>,
    /// When the last `EpochFetch` went (ms), until answered.
    fetching: Option<u64>,
    /// No fetch before this (ms): an answer that opened no key, a `RATE`, a `kh` still
    /// missing after the answer that should have brought it. `tick` asks again then while a
    /// post waits.
    retry_at: Option<u64>,
    /// The last fetch was refused `RATE`: `tick` asks again once its pause is over while no
    /// key of the head is held, whether or not a post waits.
    rate_paced: bool,
    /// When the last fetch for a missing `kh` went (ms).
    need_kh_at: Option<u64>,
    /// The relay asked for the connection's seat pair (`NO_SEAT_KEYS`).
    seat_owed: bool,
    /// Why the relay said it cannot answer yet (`EpochWait`): what a dropped post says.
    pub(super) wait: Option<u8>,
    /// The relay's refusal of this group, its reason.
    pub(super) refused: Option<String>,
    floor_ahead_at: Option<u64>,
    /// A header was taken since `take_moved` last asked.
    moved: bool,
    voice_parts: Parts<(), VoiceSeatsPiece>,
    /// A voice room's seats by user id (`VoiceSeats`), and so its roster (§5.9).
    pub(super) voice_seats: BTreeMap<u32, gk::GkSeat>,
    pub(super) writer: super::writer::Writing,
    pub(super) reader: super::reader::Reading,
    pub(super) names: super::names::Names,
    /// The last state told, so each is told once.
    pub(super) told: Option<GkState>,
}

/// What a whole `EpochIn`'s headers came to.
enum Took {
    /// Its head is the floor, or was taken.
    Head,
    /// Its head is one this device took before and left behind.
    Stale,
}

/// Why a whole `EpochIn` was not taken.
enum Stop {
    /// A rule refused it.
    Refused(Refusal),
    /// The floor's keyholder header is not held: the next answer to a fetch with `have`
    /// brings it (1c).
    NeedKh,
}

impl From<Refusal> for Stop {
    fn from(r: Refusal) -> Stop {
        Stop::Refused(r)
    }
}

fn bad(why: &'static str) -> Refusal {
    Refusal::Form(why)
}

impl Member {
    pub(super) fn new(t: GkTrack, local: Option<LocalFloor>) -> Member {
        let mut m = Member {
            t,
            vault_pending: false,
            floor: None,
            kh: None,
            head: None,
            floor_hdr: None,
            recent: VecDeque::new(),
            took: Vec::new(),
            taken: None,
            opened: None,
            kh_seen: BTreeMap::new(),
            keys: Vec::new(),
            bks: HashMap::new(),
            leaf: None,
            s_m: HashMap::new(),
            row_bases: HashMap::new(),
            self_rows_done: HashSet::new(),
            parts: Parts::new(Seq::In),
            waiting: None,
            fetching: None,
            retry_at: None,
            rate_paced: false,
            need_kh_at: None,
            seat_owed: false,
            wait: None,
            refused: None,
            floor_ahead_at: None,
            moved: false,
            voice_parts: Parts::new(Seq::VoiceSeats),
            voice_seats: BTreeMap::new(),
            writer: Default::default(),
            reader: Default::default(),
            names: Default::default(),
            told: None,
        };
        if let Some(l) = local {
            let kh = l.kh.and_then(|(body, sig)| {
                check_form(&body, &sig, m.t.kind, &m.t.group)
                    .ok()
                    .filter(|h| h.d() == l.floor.kh)
            });
            m.kh = kh;
            m.floor_hdr = l.head.and_then(|(body, sig)| {
                check_form(&body, &sig, m.t.kind, &m.t.group)
                    .ok()
                    .filter(|h| h.d() == l.floor.d)
            });
            m.taken = Some(l.taken);
            m.names.floor = l.names;
            m.floor = Some(l.floor);
        }
        m
    }

    /// The vault's floor: the floor in use is the higher (3d).
    pub(super) fn vault_in(&mut self, floor: Floor, names: Option<NamesFloor>) {
        let pair = match self.floor.take() {
            Some(local) => crate::sync::higher_floor(&(local, self.names.floor), &(floor, names)),
            None => (floor, names),
        };
        if self.kh.as_ref().is_some_and(|k| k.d() != pair.0.kh) {
            self.kh = None;
        }
        if self.head.as_ref().is_some_and(|h| h.d() != pair.0.d) {
            self.head = None;
        }
        if self.floor_hdr.as_ref().is_some_and(|h| h.d() != pair.0.d) {
            self.floor_hdr = None;
        }
        self.names.floor = pair.1;
        self.floor = Some(pair.0);
    }

    /// What this device keeps of it locally.
    pub(super) fn local_floor(&self) -> Option<LocalFloor> {
        Some(LocalFloor {
            floor: self.floor.clone()?,
            kh: self
                .kh
                .as_ref()
                .map(|k| (k.body().to_vec(), k.sig().to_vec())),
            head: self
                .head
                .as_ref()
                .or(self.floor_hdr.as_ref())
                .filter(|h| self.floor.as_ref().is_some_and(|f| f.d == h.d()))
                .map(|h| (h.body().to_vec(), h.sig().to_vec())),
            names: self.names.floor,
            taken: self.taken.unwrap_or(0),
        })
    }

    pub(super) fn stored(&self) -> bool {
        self.t.group.starts_with("c:")
    }

    /// The head epoch's key, if held.
    pub(super) fn current_key(&self) -> Option<&EpochKey> {
        let f = self.floor.as_ref()?;
        self.keys
            .last()
            .filter(|k| k.gen == f.gen && k.epoch == f.epoch && k.d_e == f.d_e)
    }

    pub(super) fn key_of(&self, gen: &[u8; 16], epoch: u32) -> Option<&EpochKey> {
        self.keys
            .iter()
            .rev()
            .find(|k| k.gen == *gen && k.epoch == epoch)
    }

    pub(super) fn current(&self) -> Option<GkEpoch> {
        self.current_key().map(|k| self.epoch_of(k))
    }

    pub(super) fn epoch_key(&self, gen: &[u8; 16], epoch: u32) -> Option<GkEpoch> {
        self.key_of(gen, epoch).map(|k| self.epoch_of(k))
    }

    fn epoch_of(&self, k: &EpochKey) -> GkEpoch {
        GkEpoch {
            group: self.t.group.clone(),
            gen: k.gen,
            epoch: k.epoch,
            d_e: k.d_e,
            ck: k.ck.clone(),
        }
    }

    /// Whether a header was taken since this was last asked.
    pub(super) fn take_moved(&mut self) -> bool {
        std::mem::take(&mut self.moved)
    }

    /// The account's seat keys rotated: a new seat is welcomed anew.
    pub(super) fn reseated(&mut self) {
        self.fetching = None;
    }

    // ── fetching ──

    /// `EpochFetch`, unless one is out and not yet due again. `have` names the floor; `seat`
    /// carries the connection's pair where the relay needs it (1b): every voice fetch until
    /// seated, and a text fetch of a connection without an account until seated, and after
    /// `NO_SEAT_KEYS`. `have` is the floor even with no `BK` held (a restart, a second
    /// device, a pushed header): the relay sends the seat's keying on a connection's first
    /// answer, whenever its version was made at or after `have`, and in a push of the header
    /// that made it; `kh` whenever `have.kh` names one it did not send this connection (R1
    /// gk/mod.rs `answer` says the same).
    pub(super) fn fetch(&mut self, who: &mut Who, now: u64, out: &mut GkOut) {
        if !who.on || self.vault_pending {
            return;
        }
        if self
            .fetching
            .is_some_and(|at| now < at.saturating_add(CHECK_WAIT_MS))
            || self.retry_at.is_some_and(|t| now < t)
        {
            return;
        }
        self.fetching = Some(now);
        self.retry_at = None;
        self.rate_paced = false;
        let have = self.floor.as_ref().map(|f| gk::FloorRef {
            gen: f.gen,
            epoch: f.epoch,
            join: f.join,
            d: f.d,
            kh: f.kh,
        });
        let unseated = self.current_key().is_none();
        let wants = self.seat_owed
            || (unseated && (self.t.kind == GroupKind::Voice || who.account.is_none()));
        let seat = if wants {
            seat_keys::conn_pair(who, now)
        } else {
            None
        };
        out.send.push(ClientMessage::EpochFetch {
            group: self.t.group.clone(),
            have,
            at: Vec::new(),
            seat,
        });
    }

    /// Each second or so: a fetch nobody answered goes again, and a head epoch over 70 min
    /// old is late, to readers too (3f).
    pub(super) fn tick(&mut self, who: &mut Who, c: &mut GkCtx, out: &mut GkOut) {
        let unanswered = self
            .fetching
            .is_some_and(|at| c.now >= at.saturating_add(CHECK_WAIT_MS));
        let old = self.current_key().is_some_and(|k| k.late(c.secs()));
        if old {
            let waiting = !self.writer.is_empty();
            self.tell(GkState::Late { waiting }, out);
        }
        // Asked again once its pause is over, while a post of ours or one to read waits; a
        // voice room always waits for its keys (V1), and so does a member refused `RATE`
        // with no key of the head (not seated, or its keying lost): else it waited for the
        // next post, and every member the relay paced then fetched at once
        let again = self.retry_at.is_some_and(|t| c.now >= t)
            && (!self.writer.is_empty()
                || self.reader.waiting()
                || self.t.kind == GroupKind::Voice
                || (self.rate_paced && self.current_key().is_none()));
        if unanswered || old || again {
            self.fetch(who, c.now, out);
        }
    }

    /// A header was taken: a late or keyholder-less state is over once its key is held, and
    /// not late.
    pub(super) fn fresh(&mut self, now_secs: u64, out: &mut GkOut) {
        let refused_over = matches!(self.told, Some(GkState::Refused(_))) && self.refused.is_none();
        let over =
            refused_over || matches!(self.told, Some(GkState::Late { .. } | GkState::NoKeyholder));
        let held = self.current_key().is_some_and(|k| !k.late(now_secs));
        if over && held && self.writer.is_empty() {
            self.tell(GkState::Ok, out);
        }
    }

    // ── parts ──

    /// One part of an `EpochIn`: the whole once its last part is in, each field merged once.
    pub(super) fn part_in(&mut self, part: u16, last: bool, piece: &InPiece) -> Option<InPiece> {
        let bytes = postcard::experimental::serialized_size(piece).unwrap_or(usize::MAX);
        let took = self.parts.take((), part, last, piece.clone(), bytes);
        if took.dropped.is_some() || matches!(took.part, Part::NotTaken(_)) {
            // The relay sends none of a failed sequence's later parts: ask again
            self.fetching = None;
            if took.dropped.is_some_and(|(_, why)| why != Lost::Restart) {
                tracing::debug!(group = %self.t.group, "an EpochIn sequence was dropped");
            }
        }
        match took.part {
            Part::Whole((), parts) => match merge_in(parts) {
                Ok(p) => Some(p),
                Err(why) => {
                    tracing::warn!(group = %self.t.group, ?why, "an EpochIn did not merge");
                    self.fetching = None;
                    None
                }
            },
            _ => None,
        }
    }

    /// One part of `VoiceSeats`: whether a whole sequence came in.
    pub(super) fn voice_part_in(&mut self, part: u16, last: bool, piece: &VoiceSeatsPiece) -> bool {
        let bytes = postcard::experimental::serialized_size(piece).unwrap_or(usize::MAX);
        let Part::Whole((), parts) = self
            .voice_parts
            .take((), part, last, piece.clone(), bytes)
            .part
        else {
            return false;
        };
        for p in parts {
            if p.whole {
                self.voice_seats.clear();
            }
            for (u, seat) in p.seats {
                self.voice_seats.insert(u, seat);
            }
            for u in p.gone {
                self.voice_seats.remove(&u);
            }
        }
        true
    }

    // ── what the relay says ──

    /// `EpochWait`.
    pub(super) fn on_wait(
        &mut self,
        who: &mut Who,
        why: u8,
        detail: &str,
        c: &mut GkCtx,
        out: &mut GkOut,
    ) {
        self.fetching = None;
        self.wait = Some(why);
        match why {
            gk::wait::NO_KEYHOLDER => self.tell(GkState::NoKeyholder, out),
            gk::wait::REFUSED | gk::wait::GUEST_IN_GATED => {
                let reason = if detail.is_empty() {
                    match why {
                        gk::wait::GUEST_IN_GATED => "Guests cannot read this channel.",
                        _ => "A keyholder refused this device's seat.",
                    }
                } else {
                    detail
                };
                self.refused = Some(reason.to_string());
                self.tell(GkState::Refused(reason.to_string()), out);
            }
            gk::wait::NO_SEAT_KEYS => {
                if who.account.is_some() && self.t.kind == GroupKind::Text {
                    out.seat_keys_wanted = true;
                } else {
                    self.seat_owed = true;
                    // An account whose seat keys are not in yet has no pair to send: asked
                    // again at the pace of an unanswered fetch, not at once
                    if seat_keys::can_pair(who) {
                        self.fetch(who, c.now, out);
                    } else {
                        self.fetching = Some(c.now);
                    }
                }
            }
            _ => {}
        }
    }

    /// `EpochRefused`: what the relay will not do in this group. A refused post is told with
    /// the reason first, then dropped (U1).
    pub(super) fn on_refused(
        &mut self,
        who: &mut Who,
        what: u8,
        why: u8,
        detail: &str,
        c: &mut GkCtx,
        out: &mut GkOut,
    ) {
        let reason = if detail.is_empty() {
            format!(
                "it said {} to {}",
                gk::refused_why::name(why),
                gk::refused_what::name(what)
            )
        } else {
            detail.to_string()
        };
        // Which refusals are this group's for good: `RATE` is a pace, `NOT_STORED` to a fetch
        // only ever answers its `at` entries (kept history, K1: the live part is answered),
        // and a keyholder's own asks come back as `COMMIT`'s (R1 mod.rs says the same)
        match (what, why) {
            // The head moved past the epoch a post went under: ask, and send again under it
            (gk::refused_what::POST, gk::refused_why::OLD_EPOCH) => {
                self.keys.clear();
                self.writer.resend_after_old_epoch();
                self.fetching = None;
                self.fetch(who, c.now, out);
            }
            // The relay's inbox is full: what went in the last `HOLD_MS` goes again at the
            // next tick (a reader drops a repeated envelope), on a new chain whose blob is
            // stored this time
            (gk::refused_what::POST, gk::refused_why::RATE) => self.writer.resend_after_rate(),
            (gk::refused_what::POST, _) => {
                self.tell(GkState::Refused(reason), out);
                if self.writer.drop_refused() {
                    out.events.push(GkEvent::PostDropped {
                        channel_id: self.t.channel_id,
                        why: Dropped::Refused,
                    });
                }
            }
            // Paced at the fetch pace plus up to as long again, drawn by this device: the
            // members one full inbox refused do not come back together
            (gk::refused_what::FETCH, gk::refused_why::RATE) => {
                self.fetching = None;
                self.rate_paced = true;
                let jitter = rand::Rng::random_range(&mut crate::rng(), 0..CHECK_WAIT_MS);
                self.retry_at = Some(c.now.saturating_add(CHECK_WAIT_MS + jitter));
            }
            (gk::refused_what::FETCH, gk::refused_why::NOT_STORED) => {
                tracing::debug!(group = %self.t.group, "past epochs refused");
            }
            (gk::refused_what::FETCH, _) => {
                self.fetching = None;
                self.refused = Some(reason.clone());
                self.tell(GkState::Refused(reason), out);
            }
            (gk::refused_what::NAMES, gk::refused_why::RATE | gk::refused_why::NOT_GATED) => {
                self.names.paced(c.now)
            }
            (gk::refused_what::NAMES, _) => self.names.refused(),
            _ => tracing::debug!(group = %self.t.group, what, why, "refused"),
        }
    }

    /// `state`, once each time it changes.
    pub(super) fn tell(&mut self, state: GkState, out: &mut GkOut) {
        if self.told.as_ref() == Some(&state) {
            return;
        }
        self.told = Some(state.clone());
        out.events.push(GkEvent::State {
            channel_id: self.t.channel_id,
            state,
        });
    }

    // ── taking headers ──

    /// A whole `EpochIn` (3c).
    #[allow(clippy::too_many_arguments)]
    pub(super) fn take_in(
        &mut self,
        who: &mut Who,
        duty: &mut Duty,
        kept: &mut Kept,
        p: InPiece,
        c: &mut GkCtx,
        out: &mut GkOut,
    ) {
        // A push answers no fetch, nor does a past epoch (a kept read's): one out is still
        // awaited
        if !p.pushed && p.past.is_none() {
            self.fetching = None;
        }
        if p.past.is_some() {
            kept.past_in(who, self, &p, c, out);
            return;
        }
        if self.vault_pending || !c.pins.ready() {
            self.waiting = Some(p);
            return;
        }
        let was = self.floor.as_ref().map(|f| f.d);
        match self.take_headers(who, duty, &p, c, out) {
            Ok(Took::Head) => {}
            // An answer built before a push it overtook: nothing in it is ours to take
            Ok(Took::Stale) => return,
            Err(Stop::NeedKh) => {
                // The relay sends `kh` to a fetch whose floor names one it did not send this
                // connection (1c): once at once, then at the pace of an unanswered fetch
                let recent = self
                    .need_kh_at
                    .is_some_and(|t| c.now < t.saturating_add(CHECK_WAIT_MS));
                if recent {
                    self.retry_at = Some(c.now.saturating_add(CHECK_WAIT_MS));
                } else {
                    self.need_kh_at = Some(c.now);
                    self.fetch(who, c.now, out);
                }
                return;
            }
            Err(Stop::Refused(r)) => {
                self.header_refused(r, out);
                return;
            }
        }
        if let Err(why) = self.key_in(who, &p, out) {
            tracing::warn!(group = %self.t.group, ?why, "the seat's keys did not open");
        }
        if !p.self_rows.is_empty() {
            kept.history_rows(who, self, &p.self_rows, out);
        }
        if self.current_key().is_some() {
            self.wait = None;
            self.refused = None;
            self.retry_at = None;
        } else if p.pushed {
            // A pushed header moved the floor and brought no key: ask once
            if self.floor.as_ref().map(|f| f.d) != was {
                self.fetch(who, c.now, out);
            }
        } else {
            // An answer that opened no key would only come back the same: asked again at
            // the pace of an unanswered fetch, not once per round trip
            self.retry_at = Some(c.now.saturating_add(CHECK_WAIT_MS));
        }
    }

    fn decode(&self, h: &gk::HeaderIn) -> Result<SignedHeader, Refusal> {
        h.check().map_err(|_| bad("a header of the wrong size"))?;
        check_form(&h.body, &h.sig, self.t.kind, &self.t.group)
    }

    fn take_headers(
        &mut self,
        who: &Who,
        duty: &Duty,
        p: &InPiece,
        c: &mut GkCtx,
        out: &mut GkOut,
    ) -> Result<Took, Stop> {
        if let Some(kh) = &p.kh {
            let kh = self.decode(kh)?;
            if self.floor.as_ref().is_some_and(|f| f.kh == kh.d())
                && kh.header().kind.sets_keyholders()
            {
                self.kh_seen.insert(kh.d(), kh.clone());
                self.kh = Some(kh);
            }
        }
        // The floor's keyholder header met this run (another device raised the floor to it)
        if let Some(f) = &self.floor {
            if self.kh.as_ref().is_none_or(|k| k.d() != f.kh) {
                if let Some(k) = self.kh_seen.get(&f.kh) {
                    self.kh = Some(k.clone());
                }
            }
        }
        let mut walk = Vec::with_capacity(p.walk.len());
        for l in &p.walk {
            let parent = l.parent.as_ref().map(|h| self.decode(h)).transpose()?;
            walk.push((self.decode(&l.header)?, parent));
        }
        let mut list: Vec<(SignedHeader, Option<SignedHeader>)> = Vec::new();
        for h in &p.chain {
            list.push((self.decode(h)?, None));
        }
        if let Some(head) = &p.head {
            let h = self.decode(&head.header)?;
            let parent = head.parent.as_ref().map(|x| self.decode(x)).transpose()?;
            if !list.last().is_some_and(|(x, _)| x.d() == h.d()) {
                list.push((h, parent));
            }
        }
        let mut stale = false;
        for (h, parent) in &list {
            stale = false;
            if self.floor.as_ref().is_some_and(|f| f.d == h.d()) {
                // The floor's own header, after a restart or with only a vault floor: taken
                // before, so the head now, its keys open under it (3c)
                if self.head.is_none() {
                    self.head_at_floor(h);
                }
                continue;
            }
            // What the relay's head is below: the floor is ahead of it (3c). A header this
            // device took already is an answer a push overtook, no sign of that
            if let Some(f) = &self.floor {
                if h.header().gen == f.gen
                    && (h.header().epoch, h.header().join) < (f.epoch, f.join)
                {
                    if self.recent.contains(&h.d()) {
                        stale = true;
                        continue;
                    }
                    self.floor_ahead(c, out);
                    return Err(Refusal::BelowFloor.into());
                }
            }
            self.take_header(who, duty, h, parent.as_ref(), &walk, c, out)?;
        }
        if let Some(o) = &p.opening {
            let o = self.decode(o)?;
            let head = self.head.as_ref().map(SignedHeader::header);
            if head.is_some_and(|h| {
                h.epoch_parent == o.d() && h.gen == o.header().gen && h.epoch == o.header().epoch
            }) && o.header().kind.opens_epoch()
            {
                let (gen, epoch, time) = (o.header().gen, o.header().epoch, o.header().time);
                self.opened = Some(time);
                for k in self.keys.iter_mut() {
                    if (k.gen, k.epoch) == (gen, epoch) {
                        k.opened = Some(time);
                    }
                }
                // The opening is the head's own (its signed `epoch_parent`): the exits it
                // covers are done, as if it was taken (spec 5.4), and where it turned the
                // gate on, the fold from the start begins at it
                self.writer.opened(gen, o.header().exits_upto, false);
                self.names.opening_seen(&o);
            }
        }
        Ok(if stale { Took::Stale } else { Took::Head })
    }

    /// The header the floor names, met again: the head, as when it was taken.
    fn head_at_floor(&mut self, h: &SignedHeader) {
        let hd = h.header();
        if hd.kind.sets_keyholders() && self.kh.is_none() {
            self.kh_seen.insert(h.d(), h.clone());
            self.kh = Some(h.clone());
        }
        if hd.kind.opens_epoch() {
            self.opened = Some(hd.time);
        }
        self.names.header_taken(h, self.floor.as_ref());
        self.head = Some(h.clone());
    }

    /// The floor is above the relay's head: tell it, with the floor's header, at most once
    /// an hour (1b). After a restart the floor's header is the one this device kept, or the
    /// keyholder header when that is the floor; a floor from the vault alone has none to
    /// send, and is still told to the user (§5.7).
    fn floor_ahead(&mut self, c: &GkCtx, out: &mut GkOut) {
        let due = self
            .floor_ahead_at
            .is_none_or(|at| c.secs() >= at.saturating_add(FLOOR_AHEAD_GAP_SECS));
        if !due {
            return;
        }
        self.floor_ahead_at = Some(c.secs());
        let d = self.floor.as_ref().map(|f| f.d);
        let header = [
            self.head.as_ref(),
            self.floor_hdr.as_ref(),
            self.kh.as_ref(),
        ]
        .into_iter()
        .flatten()
        .find(|h| Some(h.d()) == d);
        if let Some(head) = header {
            out.send.push(ClientMessage::EpochFloorAhead {
                group: self.t.group.clone(),
                header: gk::HeaderIn {
                    body: head.body().to_vec(),
                    sig: head.sig().to_vec(),
                },
            });
        }
        out.events.push(GkEvent::Warning {
            channel_id: self.t.channel_id,
            kind: Warn::FloorAhead,
            n: 0,
        });
    }

    fn header_refused(&mut self, r: Refusal, out: &mut GkOut) {
        tracing::warn!(group = %self.t.group, ?r, "a header was refused");
        if let Refusal::OldCounter { own: true, n, .. } = r {
            out.events.push(GkEvent::Warning {
                channel_id: self.t.channel_id,
                kind: Warn::OldSeatKey,
                n,
            });
        }
        if !self.writer.is_empty() {
            self.tell(GkState::Late { waiting: true }, out);
        }
    }

    /// One header, after the floor (§4.4): rules 1–3 and 6–8 by C1, then the floor moves.
    #[allow(clippy::too_many_arguments)]
    fn take_header(
        &mut self,
        who: &Who,
        duty: &Duty,
        h: &SignedHeader,
        parent: Option<&SignedHeader>,
        walk: &[(SignedHeader, Option<SignedHeader>)],
        c: &mut GkCtx,
        out: &mut GkOut,
    ) -> Result<(), Stop> {
        let hd = h.header();
        let now = c.secs();
        check_time(hd, now)?;
        let clock = Clock {
            now,
            taken: self.taken,
        };
        let prev = self.floor.clone();
        let links: Vec<WalkLink> = walk
            .iter()
            .map(|(header, parent)| WalkLink {
                header,
                parent: parent.as_ref(),
            })
            .collect();
        let head = WalkLink { header: h, parent };
        let mut signers: Vec<(MemberId, [u8; 32])> = Vec::new();
        let mut gen_time = hd.time;
        let mut anew = None;
        let mut warnings = Vec::new();
        // The set in force before `h`, and the keyholder headers walked, oldest first: from the
        // floor's (taken already), or from a generation's start (whose own entries are new)
        let (before, walked, from_start): (Vec<Keyholder>, Vec<&SignedHeader>, bool) = {
            let pins = &*c.pins;
            let pin = |a: &[u8; 16]| pins.pin(a);
            match prev.as_ref() {
                Some(f) if hd.gen == f.gen && hd.parent == f.d => {
                    let kh = self
                        .kh
                        .as_ref()
                        .filter(|k| k.d() == f.kh)
                        .ok_or(Stop::NeedKh)?;
                    warnings = match self.head.as_ref().filter(|p| p.d() == f.d) {
                        Some(p) => check_link(p, h)?,
                        None => check_on_floor(f, h)?,
                    };
                    if hd.kind == Kind::Regenesis {
                        let p = parent
                            .or(self.head.as_ref().filter(|p| p.d() == f.d))
                            .ok_or(Refusal::Chain("a Regenesis comes with its parent"))?;
                        check_regenesis(Some(f), clock, h, p)?;
                        anew = Some(hd.signer);
                    }
                    let ik = check_signer(h, Some(kh), &pin)?;
                    if hd.kind.starts_anew() {
                        signers.push((hd.signer, ik));
                    }
                    (kh.header().keyholders.clone(), vec![], false)
                }
                Some(f) if hd.gen == f.gen => {
                    check_above(f, hd)?;
                    let kh = self
                        .kh
                        .as_ref()
                        .filter(|k| k.d() == f.kh)
                        .ok_or(Stop::NeedKh)?;
                    let w = check_walk(WalkTo::Floor { floor: f, kh }, &links, head, clock, &pin)?;
                    signers.extend(w.signers);
                    if hd.kind == Kind::Regenesis {
                        anew = Some(hd.signer);
                    }
                    let mut walked: Vec<&SignedHeader> = vec![kh];
                    walked.extend(walk.iter().rev().map(|(x, _)| x));
                    (set_named(&walked, &hd.kh_parent), walked, false)
                }
                _ if hd.kind == Kind::Genesis => {
                    check_new_generation(prev.as_ref(), clock, hd)?;
                    signers.push((hd.signer, check_signer(h, None, &pin)?));
                    anew = prev.as_ref().map(|_| hd.signer);
                    (vec![], vec![], false)
                }
                // A device with no floor may start at a Regenesis, on trust (§5.7)
                None if hd.kind == Kind::Regenesis && walk.is_empty() => {
                    let p = parent.ok_or(Refusal::Walk("a Regenesis needs its parent"))?;
                    check_regenesis(None, clock, h, p)?;
                    signers.push((hd.signer, check_signer(h, None, &pin)?));
                    (vec![], vec![], false)
                }
                _ => {
                    let w = check_walk(
                        WalkTo::Start {
                            floor: prev.as_ref(),
                        },
                        &links,
                        head,
                        clock,
                        &pin,
                    )?;
                    signers.extend(w.signers);
                    if let Some(s) = &w.start {
                        gen_time = s.header().time;
                        anew = prev.as_ref().map(|_| s.header().signer);
                    }
                    let walked: Vec<&SignedHeader> = walk.iter().rev().map(|(x, _)| x).collect();
                    (set_named(&walked, &hd.kh_parent), walked, true)
                }
            }
        };
        warnings.extend(check_gated(hd, None)?);
        // Rule 6: a gated floor reports the group open however its head was reached (a walk,
        // a new generation), not only at the opening header that turned it
        let opened_gate = prev.as_ref().is_some_and(|f| f.gated) && !hd.gated;
        if opened_gate && !warnings.contains(&Warning::GatedTurnedOff) {
            warnings.push(Warning::GatedTurnedOff);
        }
        {
            let pins = &*c.pins;
            let pin = |a: &[u8; 16]| pins.pin(a);
            let counters = |a: &[u8; 16]| pins.seen(a);
            // Rule 8 and a guest's counter 0, on every keyholder entry new to its set
            if let Some(start) = walked.first().filter(|_| from_start) {
                new_entries_ok(start.header(), &[], &counters, who.account)?;
            }
            for pair in walked.windows(2) {
                let (set, link) = (&pair[0].header().keyholders, pair[1].header());
                new_entries_ok(link, set, &counters, who.account)?;
            }
            if hd.kind.sets_keyholders() {
                new_entries_ok(hd, &before, &counters, who.account)?;
            }
            // A keyholder reads every name it takes (rule 6)
            if duty.holds(&self.t.group) {
                check_added(hd, &pin, &counters, who.account)?;
            }
        }
        // §5.9, only on Genesis and Add headers taken live (3c)
        let live_add = prev
            .as_ref()
            .is_some_and(|f| f.gen == hd.gen && hd.kind == Kind::KeyholdersAdd);
        let live_genesis =
            hd.kind == Kind::Genesis && self.taken.is_some_and(|t| now.abs_diff(t) <= LIVE_WINDOW);
        if self.t.kind == GroupKind::Voice && (live_add || live_genesis) {
            let roster: Vec<u32> = self.voice_seats.keys().copied().collect();
            check_voice_keyholders(hd, &before, &roster)?;
        }
        // Taken: the signers taken on their word are pinned now
        for (m, ik) in signers {
            if let Some(a) = m.account() {
                if c.pins.pin(&a).is_none() {
                    c.pins.pin_new(a, ik, c.now);
                }
            }
        }
        let walked: Vec<SignedHeader> = walked.into_iter().cloned().collect();
        self.moved_to(who, duty, h, prev, gen_time, &walked, c, out);
        if let Some(by) = anew {
            let by = self.t.shows_names().then_some(by);
            out.events.push(GkEvent::Anew {
                channel_id: self.t.channel_id,
                by,
            });
        }
        if warnings.contains(&Warning::GatedTurnedOff) {
            out.events.push(GkEvent::Warning {
                channel_id: self.t.channel_id,
                kind: Warn::GatedOpened,
                n: 0,
            });
        }
        Ok(())
    }

    /// The floor moves to `h`.
    #[allow(clippy::too_many_arguments)]
    fn moved_to(
        &mut self,
        who: &Who,
        duty: &Duty,
        h: &SignedHeader,
        prev: Option<Floor>,
        gen_time: u64,
        walked: &[SignedHeader],
        c: &GkCtx,
        out: &mut GkOut,
    ) {
        let hd = h.header();
        let new_gen = prev.as_ref().is_none_or(|f| f.gen != hd.gen);
        if new_gen {
            // A generation's keys are its own
            self.keys.clear();
            self.bks.clear();
            self.s_m.clear();
            self.row_bases.clear();
            self.self_rows_done.clear();
            self.kh_seen.clear();
            self.leaf = None;
        }
        // Our own entry swapped by a Replace this device did not make (§5.11)
        if hd.kind == Kind::KeyholdersReplace {
            if let (Some(kh), Some(own)) = (self.kh.as_ref(), duty.own_kx(&self.t.group)) {
                if let Ok(swap) = crate::group_key::replaced_entry(&kh.header().keyholders, hd) {
                    if swap.swaps(&own) && swap.new.kx != own {
                        out.send.push(ClientMessage::KeyholdResign {
                            group: self.t.group.clone(),
                            entry: Some(swap.new.kx),
                        });
                        out.events.push(GkEvent::Warning {
                            channel_id: self.t.channel_id,
                            kind: Warn::EntrySwapped,
                            n: 0,
                        });
                    }
                }
            }
        }
        let floor = Floor::after(prev.as_ref(), h, gen_time);
        for k in walked.iter().filter(|k| k.header().gen == hd.gen) {
            self.kh_seen.insert(k.d(), k.clone());
        }
        // The keyholder header the new floor names: this one, or one the walk took
        if hd.kind.sets_keyholders() {
            self.kh_seen.insert(h.d(), h.clone());
        }
        if self.kh.as_ref().is_none_or(|k| k.d() != floor.kh) {
            self.kh = self.kh_seen.get(&floor.kh).cloned();
        }
        while self.kh_seen.len() > KH_SEEN_MOST {
            let oldest = self
                .kh_seen
                .iter()
                .min_by_key(|(_, k)| (k.header().epoch, k.header().join))
                .map(|(d, _)| *d)
                .expect("not empty");
            self.kh_seen.remove(&oldest);
        }
        if hd.kind.sets_keyholders() {
            let show = self.t.shows_names();
            out.events.push(GkEvent::Keyholders {
                channel_id: self.t.channel_id,
                holders: hd.keyholders.iter().map(|k| show.then_some(k.m)).collect(),
            });
        }
        if hd.kind.opens_epoch() {
            self.opened = Some(hd.time);
            self.writer.opened(hd.gen, hd.exits_upto, new_gen);
        } else if new_gen {
            self.opened = None;
            self.writer.opened(hd.gen, hd.exits_upto, true);
        }
        self.names.header_taken(h, prev.as_ref());
        self.head = Some(h.clone());
        self.floor_hdr = None;
        self.recent.push_back(h.d());
        while self.recent.len() > RECENT_MOST {
            self.recent.pop_front();
        }
        self.took.push((h.d(), hd.parent));
        self.taken = Some(c.secs());
        self.moved = true;
        if self.stored() && who.account.is_some() {
            out.vault_floors
                .push((self.t.group.clone(), floor.clone(), self.names.floor));
        }
        self.floor = Some(floor);
    }

    /// The names floor moved (a fold): kept with the floor, locally and in the vault.
    pub(super) fn save_names(&mut self, who: &Who, out: &mut GkOut) {
        self.moved = true;
        if let (true, Some(_), Some(f)) = (self.stored(), who.account, self.floor.as_ref()) {
            out.vault_floors
                .push((self.t.group.clone(), f.clone(), self.names.floor));
        }
    }

    // ── keys ──

    /// The seat's material of an `EpochIn`, for its head (3c): leaf and path, `BK` from a
    /// welcome or a row and the ratchets since, `CK` from the seal and its `confirm`. Our seat
    /// is the account's in a text group (its `item.seat_kem`), else the connection's; after
    /// a rotation the old seat's material opens too until the relay re-seats it (§5.11).
    fn key_in(&mut self, who: &Who, p: &InPiece, out: &mut GkOut) -> Result<(), Refusal> {
        let Some(head) = self.head.clone() else {
            return Ok(());
        };
        let hd = head.header();
        let g = Group::new(self.t.kind, &self.t.group, hd.gen).map_err(|_| bad("group"))?;
        let seats: Vec<(Me, SeatRef)> = seat_keys::mine(who, self.t.kind)
            .into_iter()
            .map(|me| {
                let seat = me.keys.public().seat(me.m);
                (me, seat)
            })
            .collect();
        let Some((_, own)) = seats.first() else {
            return Ok(());
        };
        let own = *own;
        // An account's own self-rows: `s_m` its other devices opened (§3.11)
        if let Some(keys) = who
            .seat_keys
            .as_ref()
            .filter(|_| self.t.kind == GroupKind::Text)
        {
            for r in &p.self_rows {
                let ours = r.kind == gk::self_row::SELF_ROW
                    && r.group == self.t.group
                    && r.gen == hd.gen
                    && (r.sk, r.sx) == (own.tag_sk, own.tag_sx);
                if ours && r.check().is_ok() {
                    if let Ok(s_m) = open_self_row(&g, r.seed, &own, keys.self_key(), &r.sealed) {
                        self.s_m.insert((own, r.seed), s_m);
                        self.self_rows_done.insert((own, r.seed));
                    }
                }
            }
        }
        if let Some(sw) = &p.seed_welcome {
            sw.check().map_err(|_| bad("seed welcome"))?;
            let from = Holder::from_raw(sw.from.m.into(), &sw.from.kx).map_err(|_| bad("kx"))?;
            let opened = seats.iter().find_map(|(me, seat)| {
                let s_m = open_seed_welcome(&g, sw.s, me, &from, &sw.bytes).ok()?;
                Some((*seat, s_m))
            });
            if let Some((seat, s_m)) = opened {
                self.s_m.insert((seat, sw.s), s_m);
            }
        }
        if let (Some(leaf), Some(path)) = (&p.leaf, &p.path) {
            leaf.check().map_err(|_| bad("leaf"))?;
            path.check().map_err(|_| bad("path"))?;
            let leaf = Leaf::try_from(*leaf).map_err(|_| bad("leaf"))?;
            if !path_ok(
                &hd.bucket_root,
                hd.buckets,
                &leaf,
                &Path::from(path.clone()),
            ) {
                return Err(bad("the leaf is not in the bucket root"));
            }
            self.leaf = Some(leaf);
        }
        let mut used = None;
        if let Some(sk) = &p.seat {
            sk.check().map_err(|_| bad("seat keying"))?;
            let from = Holder::from_raw(sk.from.m.into(), &sk.from.kx).map_err(|_| bad("kx"))?;
            let base = Version {
                b: sk.b,
                v: sk.base_v,
            };
            let mut bk = match (&sk.welcome, &sk.row) {
                (Some(w), _) => {
                    let (seat, s_m, bk) = seats
                        .iter()
                        .find_map(|(me, seat)| {
                            let (s_m, bk) = open_seat_welcome(&g, sk.s, base, me, &from, w).ok()?;
                            Some((*seat, s_m, bk))
                        })
                        .ok_or(Refusal::Form("a seat welcome that does not open"))?;
                    self.s_m.insert((seat, sk.s), s_m);
                    used = Some(seat);
                    bk
                }
                (None, Some(row)) => {
                    let mut opened = None;
                    for (me, seat) in &seats {
                        let Some(s_m) = self.s_m.get(&(*seat, sk.s)) else {
                            continue;
                        };
                        let at = (*seat, from.id(), sk.s);
                        let rb = match self.row_bases.entry(at) {
                            Entry::Occupied(e) => e.into_mut(),
                            Entry::Vacant(e) => {
                                let Ok(rb) = RowBase::member_side(&g, sk.s, me, &from, s_m) else {
                                    continue;
                                };
                                e.insert(rb)
                            }
                        };
                        if let Ok(bk) = rb.open_row(base, row) {
                            opened = Some((*seat, bk));
                            break;
                        }
                    }
                    let (seat, bk) = opened
                        .ok_or(Refusal::Form("a row that does not open to a seat of ours"))?;
                    used = Some(seat);
                    bk
                }
                (None, None) => self
                    .bks
                    .get(&(sk.b, sk.base_v))
                    .cloned()
                    .ok_or(bad("ratchets from a version this seat holds no key of"))?,
            };
            let mut v = sk.base_v;
            for step in &sk.ratchets {
                bk = ratchet(&g, step.e, Version { b: sk.b, v }, step.to, &bk);
                v = step.to;
            }
            self.bks.insert((sk.b, v), bk);
        }
        let ep = Epoch {
            e: hd.epoch,
            d_e: head.d_e(),
        };
        let ck = match (&p.seal, &self.leaf) {
            (Some(seal), Some(leaf)) => {
                let at = Version {
                    b: leaf.b,
                    v: leaf.v,
                };
                let bk = self
                    .bks
                    .get(&(leaf.b, leaf.v))
                    .ok_or(bad("a seal to a version this seat holds no key of"))?;
                Some(
                    open_seal(&g, &ep, at, bk, seal)
                        .map_err(|_| Refusal::Form("a seal that does not open"))?,
                )
            }
            _ => self
                .key_of(&hd.gen, hd.epoch)
                .filter(|k| k.d_e == ep.d_e)
                .map(|k| k.ck.clone()),
        };
        let Some(ck) = ck else {
            return Ok(());
        };
        // Rule 5
        if !confirm_ok(&g, hd.epoch, hd.join, &ck, &hd.confirm) {
            return Err(Refusal::Confirm);
        }
        let opened = if hd.kind.opens_epoch() {
            Some(hd.time)
        } else {
            self.opened
        };
        if self.key_of(&hd.gen, hd.epoch).is_none() {
            self.keys.push(EpochKey {
                gen: hd.gen,
                epoch: hd.epoch,
                d_e: ep.d_e,
                ck,
                opened,
            });
            if self.keys.len() > KEYS_KEPT {
                self.keys.remove(0);
            }
        }
        self.seat_owed = false;
        // A self-row for the current seat only: the old one's are K1's to seal again
        if let Some(sk) = p.seat.as_ref().filter(|_| used == Some(own)) {
            self.write_self_row(who, &g, sk.s, &own, out);
        }
        Ok(())
    }

    /// A self-row for `s_m` of seed `s`, once a row or seal under it opened and `confirm`
    /// passed: stored groups of a signed-in account only (§3.11).
    fn write_self_row(&mut self, who: &Who, g: &Group, s: u32, own: &SeatRef, out: &mut GkOut) {
        let Some(keys) = who.seat_keys.as_ref() else {
            return;
        };
        let ours = self.t.kind == GroupKind::Text
            && self.stored()
            && own.m.account().is_some()
            && who.account == own.m.account();
        if !ours || self.self_rows_done.contains(&(*own, s)) {
            return;
        }
        let Some(s_m) = self.s_m.get(&(*own, s)) else {
            return;
        };
        self.self_rows_done.insert((*own, s));
        out.self_rows.push(gk::SelfRowIn {
            group: self.t.group.clone(),
            gen: g.gen(),
            seed: s,
            sk: own.tag_sk,
            sx: own.tag_sx,
            kind: gk::self_row::SELF_ROW,
            sealed: self_row(g, s, own, keys.self_key(), s_m),
        });
    }
}

/// The keyholders of the header `d` names among `walked` (empty: none held).
fn set_named(walked: &[&SignedHeader], d: &[u8; 32]) -> Vec<Keyholder> {
    walked
        .iter()
        .find(|h| h.d() == *d)
        .map(|h| h.header().keyholders.clone())
        .unwrap_or_default()
}

/// Rule 8 on every keyholder entry `h` brings into `before`, and a guest's counter 0 (C1
/// note 2): a connection keyholder of no account (`Conn`) endorses under its own `IK` with
/// counter 0, and no other.
pub(super) fn new_entries_ok(
    h: &crate::group_key::HeaderV1,
    before: &[Keyholder],
    counters: crate::group_key::Counters,
    own: Option<[u8; 16]>,
) -> Result<(), Refusal> {
    check_counters(h, before, counters, own)?;
    let guest_counter = h
        .keyholders
        .iter()
        .filter(|k| !before.contains(k))
        .any(|k| k.m.is_conn() && k.n != 0);
    if guest_counter {
        return Err(bad("a guest keyholder's counter is 0"));
    }
    Ok(())
}

/// The parts of one `EpochIn` as one (plan 13): each `Option` field from the one part that
/// carries it, refused when two do; `chain`, `walk` and `self_rows` in part order.
pub(super) fn merge_in(parts: Vec<InPiece>) -> Result<InPiece, gk::Bad> {
    fn once<T>(into: &mut Option<T>, from: Option<T>, what: &'static str) -> Result<(), gk::Bad> {
        match (into.is_some(), from) {
            (true, Some(_)) => Err(gk::Bad::Value(what)),
            (_, Some(x)) => {
                *into = Some(x);
                Ok(())
            }
            (_, None) => Ok(()),
        }
    }
    let mut w = InPiece::default();
    for p in parts {
        w.chain.extend(p.chain);
        w.walk.extend(p.walk);
        w.self_rows.extend(p.self_rows);
        once(&mut w.kh, p.kh, "kh twice")?;
        once(&mut w.head, p.head, "head twice")?;
        once(&mut w.opening, p.opening, "opening twice")?;
        once(&mut w.own_join, p.own_join, "own_join twice")?;
        once(&mut w.leaf, p.leaf, "leaf twice")?;
        once(&mut w.path, p.path, "path twice")?;
        once(&mut w.seal, p.seal, "seal twice")?;
        once(&mut w.seat, p.seat, "seat twice")?;
        once(&mut w.seed_welcome, p.seed_welcome, "seed welcome twice")?;
        once(&mut w.past, p.past, "past twice")?;
        w.pushed |= p.pushed;
    }
    if w.seal.as_ref().is_some_and(|s| s.len() != gk::SEAL_BYTES) {
        return Err(gk::Bad::Length("seal"));
    }
    Ok(w)
}

#[cfg(test)]
mod tests {
    use libsignal_protocol::IdentityKeyPair;
    use voipc_protocol::gk;
    use voipc_protocol::messages::{ClientMessage, ServerMessage};

    use super::super::{
        GkCtx, GkOut, GkStart, GkTrack, GroupKeying, MemoryPins, Platform, VaultFloor,
    };
    use crate::group_key::build::world::{T0, TEXT_ID};
    use crate::group_key::timers::CHECK_WAIT_MS;
    use crate::group_key::{GroupKind, SeatKeys};
    use crate::stores::SignalStores;

    fn fetches(out: &GkOut) -> usize {
        out.send
            .iter()
            .filter(|m| matches!(m, ClientMessage::EpochFetch { .. }))
            .count()
    }

    /// K1: a kept read's answer (`past`) answers no live fetch; the one out is still awaited,
    /// and asked again only once its wait is over.
    #[test]
    fn a_past_answer_leaves_the_live_fetch_out() {
        let ik = IdentityKeyPair::generate(&mut crate::rng());
        let mut keying = GroupKeying::default();
        let _ = keying.start(GkStart {
            on: true,
            run: [0x11; 16],
            relay_clock: T0,
            platform: Platform::Desktop,
            help_hold_keys: false,
            user_id: 20,
            identity: ik,
            account: Some([7; 16]),
            seat_keys: Some(SeatKeys::generate(1, T0)),
            local: None,
            visible: true,
        });
        let t = GkTrack {
            channel_id: 1,
            group: TEXT_ID.into(),
            kind: GroupKind::Text,
            anonymous: false,
            hide_members: false,
            viewer_admin: false,
            keeps_history: true,
        };
        assert_eq!(fetches(&keying.track(t, VaultFloor::None)), 1);
        let (mut st, mut pins) = (SignalStores::new(&ik, 20), MemoryPins::default());
        let now = crate::time::now_millis();
        let past = ServerMessage::EpochIn {
            group: TEXT_ID.into(),
            part: 0,
            last: true,
            piece: Box::new(gk::InPiece {
                past: Some(gk::EpochRef {
                    gen: [1; 16],
                    epoch: 1,
                }),
                ..gk::InPiece::default()
            }),
        };
        let c = GkCtx {
            pins: &mut pins,
            now,
        };
        let _ = keying.frame(&mut st, &past, c);
        assert_eq!(
            fetches(&keying.floors_in(TEXT_ID, None)),
            0,
            "the live fetch is still out"
        );
        let c = GkCtx {
            pins: &mut pins,
            now: now + CHECK_WAIT_MS,
        };
        let out = keying.tick(&mut st, c);
        assert_eq!(fetches(&out), 1, "asked again once its wait is over");
    }
}
