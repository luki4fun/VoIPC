//! Kept history under the group key (part 4): past epochs taken for reading (C1's
//! `take_past`), and the account's kept rows sealed again at a seat-key rotation (`Reseal`,
//! which `AccountSync` runs, since the relay answers it there; §5.11 step 2).
//!
//! What the relay sends for one `at` entry of an `EpochFetch`, each in the order asked (R1b),
//! inline with its budget's `RATE` refusal of a whole frame (R2 `gk_budget`): one `EpochIn`
//! sequence with `past` set, or one `EpochRefused{FETCH, NOT_STORED}` (`Kept::not_stored`).
//! In the `EpochIn` (`kh` and `chain` are not read):
//! - `head`: the header whose bucket root holds our seat's leaf then (§5.10 "from its seat
//!   at epoch `e`"): the past epoch's opening header, or for a seat a Join added after it,
//!   the epoch's last Join header, with `opening` then the epoch's opening header (C1
//!   `take_past_at`). An answer with no `head` has its opening header in `opening`;
//! - `walk`: the keyholder headers from the one `have.kh` names back to the one the past
//!   epoch's opening names, newest first, without the first (C1 `PastIn::khs`); with no
//!   `have`, or for another generation, the header is taken on the binding alone, and
//!   `walk` is empty, or for a Join under an opening that sets no keyholders, holds the
//!   header the opening names (the Join's signer is checked against it);
//! - `leaf` and `path`: our seat's leaf then, in the `head`'s bucket root;
//! - `seal`: that epoch's `CK` sealed to the leaf's version;
//! - `seat`: how our seat reaches `BK` of the leaf's version, a welcome or a row to its base
//!   under seed `s`, then the ratchets (only steps for a base this connection holds);
//! - `seed_welcome`: `s_m` of seed `s` for a row, from a seed roll;
//! - `self_rows`: the account's self-row of that seat and seed, and its history rows there.
//!
//! On the binding alone only our own `BK` counts (C1 `PastBk`, §5.10): by a row under the
//! self-row's `s_m` or a history row's `RB`, or by a welcome whose `s_m` is the self-row's.
//! A welcome or seed welcome alone binds only a sender the relay names (`bk_of`).
//!
//! Whatever does not come is given up by the reader (`AccountSync`).

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use voipc_protocol::gk::{self, InPiece, SelfRowIn};
use voipc_protocol::messages::{AccountRequest, ClientMessage};
use zeroize::Zeroizing;

use super::member::Member;
use super::{seat_keys, GkCtx, GkEpoch, GkOut, Who};
use crate::group_key::past::{anchors, take_past_at, PastBk, PastIn};
use crate::group_key::{
    check_form, history_row, open_history_row, open_seat_welcome, open_seed_welcome, open_self_row,
    ratchet, self_row, Group, GroupKind, HistoryEntry, Holder, Leaf, Me, MemberId, Path, Refusal,
    RowBase, SeatKeys, SeatRef, SignedHeader, Version,
};

/// Past epochs taken and not yet handed over, at most.
const TAKEN_MOST: usize = 1024;
/// Past epochs asked of the relay at once per group (four frames); the next frame goes once
/// as many are answered.
const OUT_MOST: usize = 4 * gk::FETCH_AT_MAX;
/// An ask out this long goes again when it is asked for again.
const AGAIN_MS: u64 = 10_000;
/// Kept frames a second across groups, and at once: under the relay's fetch budget (10/s,
/// burst 50, plan 1b), which the live fetches share.
const PACE_PER_SEC: u64 = 8;
const PACE_BURST: u64 = 16;
/// After a kept frame was refused `RATE`, none goes for this long.
const RATE_PAUSE_MS: u64 = 1_000;
/// Row bases one history row keeps at most (57 B each in 16 KiB).
const HISTORY_MOST: usize = 256;

/// A past epoch's key as a reader of kept history asks for it.
pub enum PastEpoch {
    Ready(GkEpoch),
    /// Asked: `GkOut::past_ready` says when it is answered (`past_epoch` then says how).
    Asked,
    /// Not to be had here: not a stored text group, or the relay had nothing that opens.
    Unknown,
}

/// A reply the relay owes for an `at` entry that went.
struct Owed {
    k: ([u8; 16], u32),
    /// The first entry of its frame.
    first: bool,
    /// The keyholder header the frame's `have.kh` named, where this device held it: the
    /// answer's walk leads back from it (C1's anchor). `None`: taken on the binding alone.
    anchor: Option<SignedHeader>,
}

/// A group's past epochs asked, `(gen, epoch)`.
#[derive(Default)]
struct Asks {
    /// Each not answered yet: when it went (ms), `None` while it waits to go (again).
    sent: BTreeMap<([u8; 16], u32), Option<u64>>,
    /// One per reply the relay owes, in the order the entries went: an entry asked again
    /// is owed twice. The relay answers in that order.
    order: VecDeque<Owed>,
}

impl Asks {
    /// The reply owed for `k`, taken from `order` with those before it (their replies were
    /// lost: a dropped sequence). `None` when none is owed for it.
    fn answered(&mut self, k: ([u8; 16], u32)) -> Option<Owed> {
        let at = self.order.iter().position(|o| o.k == k)?;
        self.order.drain(..at);
        self.order.pop_front()
    }
}

/// Kept frames that may go (`PACE_*`), in thousandths of a frame.
#[derive(Default)]
struct Pace {
    milli: u64,
    /// When `milli` was counted (ms), 0 before the first frame.
    at: u64,
    paused_until: u64,
}

impl Pace {
    /// Whether a frame may go at `now` (ms), counting it.
    fn take(&mut self, now: u64) -> bool {
        if now < self.paused_until {
            return false;
        }
        let full = PACE_BURST * 1000;
        self.milli = match self.at {
            0 => full,
            at => full.min(
                self.milli
                    .saturating_add(now.saturating_sub(at).saturating_mul(PACE_PER_SEC)),
            ),
        };
        self.at = now;
        if self.milli < 1000 {
            return false;
        }
        self.milli -= 1000;
        true
    }
}

/// What this connection holds of kept history.
#[derive(Default)]
pub(super) struct Kept {
    asks: HashMap<String, Asks>,
    /// Taken for reading, oldest first, for `past_epoch` to hand over.
    taken: VecDeque<GkEpoch>,
    /// Answered with nothing to take.
    none: HashSet<(String, [u8; 16], u32)>,
    pace: Pace,
}

fn bad(why: &'static str) -> Refusal {
    Refusal::Form(why)
}

impl Kept {
    /// An `EpochIn` with `past`: never a head, the floor never moves for it. Taken only as
    /// the epoch asked for (C1 leaves that check to its caller), walked back from the anchor
    /// its frame went with; either way the host hears it answered.
    pub(super) fn past_in(
        &mut self,
        who: &mut Who,
        m: &mut Member,
        p: &InPiece,
        _c: &mut GkCtx,
        out: &mut GkOut,
    ) {
        let Some(past) = p.past else {
            return;
        };
        let Some(asks) = self.asks.get_mut(&m.t.group) else {
            return;
        };
        let k = (past.gen, past.epoch);
        let owed = asks.answered(k);
        if asks.sent.remove(&k).is_none() {
            // Nobody waits for it (or it came twice): only its place in the order counts
            self.send(who, m, out);
            return;
        }
        let key = (m.t.group.clone(), past.gen, past.epoch);
        let anchor = owed.and_then(|o| o.anchor);
        match take(who, m, p, past, anchor.as_ref()) {
            Ok(k) => {
                self.taken.push_back(k);
                if self.taken.len() > TAKEN_MOST {
                    self.taken.pop_front();
                }
            }
            Err(why) => {
                tracing::debug!(group = %m.t.group, epoch = past.epoch, ?why, "a past epoch not taken");
                self.none.insert(key.clone());
            }
        }
        out.past_ready.push(key);
        self.send(who, m, out);
    }

    /// `EpochRefused{FETCH, NOT_STORED}`: the oldest reply owed, whose epoch is not to be had
    /// (the relay answers each `at` entry in the order asked); the next asks go.
    pub(super) fn not_stored(&mut self, who: &Who, m: &Member, out: &mut GkOut) {
        let Some(asks) = self.asks.get_mut(&m.t.group) else {
            return;
        };
        if let Some(o) = asks.order.pop_front() {
            if asks.sent.remove(&o.k).is_some() {
                let key = (m.t.group.clone(), o.k.0, o.k.1);
                self.none.insert(key.clone());
                out.past_ready.push(key);
            }
        }
        self.send(who, m, out);
    }

    /// `EpochRefused{FETCH, RATE}`: the oldest kept frame out, when none of it is answered
    /// yet. The relay refuses a fetch over its budget as it reads it, and answers every `at`
    /// entry of the frames before it first, so a `RATE` that finds the oldest frame
    /// unanswered is that frame's (unless a live fetch went just before it and was the one
    /// refused). Its asks go again after `RATE_PAUSE_MS`. `false`: the live fetch's.
    pub(super) fn rate(&mut self, m: &Member) -> bool {
        let Some(asks) = self.asks.get_mut(&m.t.group) else {
            return false;
        };
        if !asks.order.front().is_some_and(|o| o.first) {
            return false;
        }
        let mut first = true;
        while let Some(o) = asks.order.pop_front() {
            if !first && o.first {
                asks.order.push_front(o);
                break;
            }
            first = false;
            if let Some(sent) = asks.sent.get_mut(&o.k) {
                *sent = None;
            }
        }
        self.pace.paused_until = crate::time::now_millis().saturating_add(RATE_PAUSE_MS);
        true
    }

    /// History rows a live answer brought key nothing live: the relay seats the current seat
    /// there, and a past answer carries its own (`past_in`).
    pub(super) fn history_rows(
        &mut self,
        _who: &mut Who,
        _m: &mut Member,
        _rows: &[SelfRowIn],
        _out: &mut GkOut,
    ) {
    }

    /// A past epoch the member does not hold: taken, asked, or not to be had. An ask goes
    /// with the next `send` (`GroupKeying::past_asks`), and again once out `AGAIN_MS`.
    pub(super) fn past_epoch(
        &mut self,
        _who: &mut Who,
        m: &mut Member,
        gen: [u8; 16],
        epoch: u32,
    ) -> PastEpoch {
        let group = &m.t.group;
        if let Some(k) = self
            .taken
            .iter()
            .find(|k| k.group == *group && k.gen == gen && k.epoch == epoch)
        {
            return PastEpoch::Ready(k.clone());
        }
        let key = (group.clone(), gen, epoch);
        if m.t.kind != GroupKind::Text || !m.stored() || self.none.contains(&key) {
            return PastEpoch::Unknown;
        }
        let now = crate::time::now_millis();
        let asks = self.asks.entry(group.clone()).or_default();
        let sent = asks.sent.entry((gen, epoch)).or_insert(None);
        if sent.is_some_and(|t| now >= t.saturating_add(AGAIN_MS)) {
            // Its first reply stays owed: the relay answers both
            *sent = None;
        }
        PastEpoch::Asked
    }

    /// The asks of `m`'s group not out yet, in frames of 16 (fewer only when fewer wait),
    /// each once at most `OUT_MOST` are out with it and the pace lets one go. `have` is the
    /// floor where the relay uses the group key and this device holds the keyholder header it
    /// names, so the keyholder headers the relay sends lead back from that header (C1's anchor).
    pub(super) fn send(&mut self, who: &Who, m: &Member, out: &mut GkOut) {
        let Some(asks) = self.asks.get_mut(&m.t.group) else {
            return;
        };
        let now = crate::time::now_millis();
        loop {
            // Whole frames: the next goes once there is room for all of it
            let room = OUT_MOST.saturating_sub(asks.order.len());
            let due: Vec<([u8; 16], u32)> = asks
                .sent
                .iter()
                .filter(|(_, s)| s.is_none())
                .map(|(k, _)| *k)
                .take(gk::FETCH_AT_MAX)
                .collect();
            if due.is_empty() || due.len() > room || !self.pace.take(now) {
                return;
            }
            // `have` names the floor only with the keyholder header it names held here: the
            // relay walks back from that header, and the walk is checked from it. With none
            // held (a floor from the vault alone: a reloaded page before its live answer) the
            // answer is taken on the binding alone, and the relay sends it so (a Join's set)
            let anchor = m
                .floor
                .as_ref()
                .filter(|_| who.on)
                .and_then(|f| m.kh.as_ref().filter(|k| k.d() == f.kh))
                .cloned();
            let have = m
                .floor
                .as_ref()
                .filter(|_| anchor.is_some())
                .map(|f| gk::FloorRef {
                    gen: f.gen,
                    epoch: f.epoch,
                    join: f.join,
                    d: f.d,
                    kh: f.kh,
                });
            for (i, k) in due.iter().enumerate() {
                asks.sent.insert(*k, Some(now));
                asks.order.push_back(Owed {
                    k: *k,
                    first: i == 0,
                    anchor: anchor.clone(),
                });
            }
            out.send.push(ClientMessage::EpochFetch {
                group: m.t.group.clone(),
                have,
                at: due
                    .into_iter()
                    .map(|(gen, epoch)| gk::EpochRef { gen, epoch })
                    .collect(),
                seat: None,
            });
        }
    }

    /// The account's seat keys rotated: nothing here. Its kept rows are sealed again by
    /// `AccountSync` (`Reseal`), where the relay's answers come.
    pub(super) fn seat_keys_changed(
        &mut self,
        _who: &mut Who,
        _groups: &mut BTreeMap<String, Member>,
        _out: &mut GkOut,
    ) {
    }
}

/// A past answer's `CK`, by C1's `take_past_at`, as the epoch asked for, walked back from
/// `anchor` (or on the binding alone): at its opening header, or at a Join of it with the
/// opening.
fn take(
    who: &Who,
    m: &Member,
    p: &InPiece,
    past: gk::EpochRef,
    anchor: Option<&SignedHeader>,
) -> Result<GkEpoch, Refusal> {
    let group = &m.t.group;
    let form = |h: &gk::HeaderIn| {
        h.check().map_err(|_| bad("a header of the wrong size"))?;
        check_form(&h.body, &h.sig, GroupKind::Text, group)
    };
    // `head` and, with a Join there, `opening`; or the opening alone
    let (header, opening) = match (&p.head, &p.opening) {
        (Some(head), opening) => (form(&head.header)?, opening.as_ref().map(form).transpose()?),
        (None, Some(opening)) => (form(opening)?, None),
        (None, None) => return Err(bad("no opening header")),
    };
    if (header.header().gen, header.header().epoch) != (past.gen, past.epoch) {
        return Err(bad("not the epoch asked for"));
    }
    let khs = p
        .walk
        .iter()
        .map(|l| form(&l.header))
        .collect::<Result<Vec<_>, _>>()?;
    let (Some(leaf), Some(path), Some(seal)) = (&p.leaf, &p.path, &p.seal) else {
        return Err(bad("no leaf, path or seal"));
    };
    leaf.check().map_err(|_| bad("leaf"))?;
    path.check().map_err(|_| bad("path"))?;
    let leaf = Leaf::try_from(*leaf).map_err(|_| bad("leaf"))?;
    let path = Path::from(path.clone());
    let g = Group::new(GroupKind::Text, group, past.gen).map_err(|_| bad("group"))?;
    // On the binding alone, only a `BK` the relay could not have chosen
    let anchored = anchors(anchor, &header, opening.as_ref());
    let (bk, own) = bk_of(who, m, &g, &leaf, p, !anchored).ok_or(bad(if anchored {
        "no key of the leaf's version"
    } else {
        "no key of the leaf's version of our own"
    }))?;
    let bk = if own {
        PastBk::Own(&bk)
    } else {
        PastBk::Relayed(&bk)
    };
    let pin = PastIn {
        header: &header,
        khs: &khs,
        leaf: &leaf,
        path: &path,
        seal,
    };
    let pe = take_past_at(GroupKind::Text, group, anchor, &pin, opening.as_ref(), bk)?;
    if (pe.group.gen(), pe.epoch.e) != (past.gen, past.epoch) {
        return Err(bad("not the epoch asked for"));
    }
    Ok(GkEpoch {
        group: group.clone(),
        gen: past.gen,
        epoch: past.epoch,
        d_e: pe.epoch.d_e,
        ck: pe.ck,
    })
}

/// `BK` of the leaf's version, and whether it is the device's own (C1 `PastBk`): held this
/// run in the floor's generation, else from the answer's keying, a welcome to one of our
/// seats or a row (`row_key`), and its ratchets. A welcome binds no more than its sender,
/// whom the relay names: it is our own only where its `s_m` is our self-row's (`self_s_m`).
/// With `own_only` (no anchor reaches the header, §5.10) only our own is given: the key
/// held this run is not (`Member::key_in` keeps one only once its seal's key passed
/// `confirm`, so it could be, RV).
fn bk_of(
    who: &Who,
    m: &Member,
    g: &Group,
    leaf: &Leaf,
    p: &InPiece,
    own_only: bool,
) -> Option<(Zeroizing<[u8; 32]>, bool)> {
    let same_gen = m.floor.as_ref().is_some_and(|f| f.gen == g.gen()) && !own_only;
    if let Some(bk) = m.bks.get(&(leaf.b, leaf.v)).filter(|_| same_gen) {
        return Some((bk.clone(), false));
    }
    let sk = p.seat.as_ref().filter(|sk| sk.b == leaf.b)?;
    sk.check().ok()?;
    let from = Holder::from_raw(sk.from.m.into(), &sk.from.kx).ok()?;
    let base = Version {
        b: sk.b,
        v: sk.base_v,
    };
    let seats = seat_keys::mine(who, GroupKind::Text);
    let welcomed = sk.welcome.as_ref().and_then(|w| {
        let (seat, s_m, bk) = seats.iter().find_map(|me| {
            let (s_m, bk) = open_seat_welcome(g, sk.s, base, me, &from, w).ok()?;
            Some((me.keys.public().seat(me.m), s_m, bk))
        })?;
        let own = self_s_m(who, g, sk.s, &seat, p).is_some_and(|ours| same_secret(&ours, &s_m));
        (own || !own_only).then_some((bk, own))
    });
    let (mut bk, own) = match (welcomed, &sk.row) {
        (Some(got), _) => got,
        (None, Some(row)) => row_key(who, &seats, g, sk.s, &from, base, row, p, own_only)?,
        (None, None) if same_gen => (m.bks.get(&(sk.b, sk.base_v))?.clone(), false),
        (None, None) => return None,
    };
    let mut v = sk.base_v;
    for step in &sk.ratchets {
        bk = ratchet(g, step.e, Version { b: sk.b, v }, step.to, &bk);
        v = step.to;
    }
    (v == leaf.v).then_some((bk, own))
}

/// `s_m` of our seat `seat` under seed `s` from the account's self-row in the answer, under
/// the self key or the old one while a rotation keeps it: only the account's devices seal
/// one, once a key under it passed `confirm` (`Member::write_self_row`).
fn self_s_m(
    who: &Who,
    g: &Group,
    s: u32,
    seat: &SeatRef,
    p: &InPiece,
) -> Option<Zeroizing<[u8; 32]>> {
    let account = who.account?;
    let keys = who.seat_keys.as_ref()?;
    if seat.m != MemberId::Account(account) {
        return None;
    }
    let self_keys = std::iter::once(keys.self_key()).chain(keys.old.as_ref().map(|o| o.self_key()));
    let rows: Vec<&SelfRowIn> = p
        .self_rows
        .iter()
        .filter(|r| {
            r.kind == gk::self_row::SELF_ROW
                && r.group == g.id()
                && r.gen == g.gen()
                && r.seed == s
                && (r.sk, r.sx) == (seat.tag_sk, seat.tag_sx)
                && r.check().is_ok()
        })
        .collect();
    self_keys
        .flat_map(|key| rows.iter().map(move |r| (key, r)))
        .find_map(|(key, r)| open_self_row(g, s, seat, key, &r.sealed).ok())
}

/// Equality of two secrets in time that does not depend on where they differ.
fn same_secret(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// A row to one of our seats, opened by the row base `s_m` gives: from a seed welcome to it
/// (a seed roll), or for the account's seats by its rows (§3.11), a self-row's `s_m` with
/// that seat's private parts while this device holds them, or a history row once they are
/// gone. Rows are under the self key, or the old one while a rotation keeps it. With the
/// key, whether it is our own: by a self-row or history row it is; by a seed welcome, whose
/// maker the relay names, it is not, and with `own_only` that one is not tried.
#[allow(clippy::too_many_arguments)]
fn row_key(
    who: &Who,
    seats: &[Me],
    g: &Group,
    s: u32,
    from: &Holder,
    base: Version,
    row: &[u8],
    p: &InPiece,
    own_only: bool,
) -> Option<(Zeroizing<[u8; 32]>, bool)> {
    let sw = p
        .seed_welcome
        .as_ref()
        .filter(|w| !own_only && w.s == s && w.check().is_ok());
    if let Some(sw) = sw {
        let maker = Holder::from_raw(sw.from.m.into(), &sw.from.kx).ok()?;
        let bk = seats.iter().find_map(|me| {
            let s_m = open_seed_welcome(g, s, me, &maker, &sw.bytes).ok()?;
            RowBase::member_side(g, s, me, from, &s_m)
                .ok()?
                .open_row(base, row)
                .ok()
        });
        if let Some(bk) = bk {
            return Some((bk, false));
        }
    }
    let account = who.account?;
    let keys = who.seat_keys.as_ref()?;
    let self_keys: Vec<&[u8; 32]> = std::iter::once(keys.self_key())
        .chain(keys.old.as_ref().map(|o| o.self_key()))
        .collect();
    let ours = p
        .self_rows
        .iter()
        .filter(|r| r.group == g.id() && r.gen == g.gen() && r.seed == s && r.check().is_ok());
    for r in ours {
        let seat = SeatRef {
            m: MemberId::Account(account),
            tag_sk: r.sk,
            tag_sx: r.sx,
        };
        for key in &self_keys {
            let rb = if r.kind == gk::self_row::SELF_ROW {
                let Ok(s_m) = open_self_row(g, s, &seat, key, &r.sealed) else {
                    continue;
                };
                let me = seats.iter().find(|me| me.keys.public().seat(me.m) == seat);
                me.and_then(|me| RowBase::member_side(g, s, me, from, &s_m).ok())
            } else {
                let Ok(entries) = open_history_row(g, s, &seat, key, &r.sealed) else {
                    continue;
                };
                entries
                    .into_iter()
                    .find(|e| e.k == from.id())
                    .map(|e| RowBase::from_secret(g, s, seat.m, e.k, &e.rb))
            };
            if let Some(bk) = rb.and_then(|rb| rb.open_row(base, row).ok()) {
                return Some((bk, true));
            }
        }
    }
    None
}

// ── At a seat-key rotation (§5.11 step 2) ────────────────────────────────

/// The account's kept rows sealed again at a seat-key rotation, while the old keys are kept.
/// Every self-row and history row is listed (`SelfRowsList`), and those under the old self
/// key go again under the new one. For the old seat, a history row per group, generation and
/// seed keeps the row bases of every keyholder that made rows to it (`RowMakers`): its rows
/// open once its private parts are gone. Run one ask at a time by `AccountSync`; asking
/// again is harmless, since every row is kept once per seat, seed and kind.
#[derive(Default)]
pub(crate) struct Reseal {
    listed: bool,
    after: Option<Vec<u8>>,
    /// The old seat's `s_m` per group, generation and seed.
    s_m: BTreeMap<(String, [u8; 16], u32), Zeroizing<[u8; 32]>>,
    /// Groups and generations whose row makers are still to read, the first being read.
    makers: VecDeque<(String, [u8; 16])>,
    makers_after: Option<Vec<u8>>,
    /// Row bases of the group being read, per seed.
    entries: BTreeMap<u32, Vec<HistoryEntry>>,
}

impl Reseal {
    /// One whose listing is done: only row makers are read.
    pub(crate) fn listed() -> Reseal {
        Reseal {
            listed: true,
            ..Reseal::default()
        }
    }

    /// Self-rows this device writes for the old seat while its keys are kept (a welcome to
    /// it opened late, §5.11 step 2): their seeds get history rows too, by reading their
    /// group's row makers (again). `false` when none is the old seat's.
    pub(crate) fn own_rows(
        &mut self,
        keys: &SeatKeys,
        account: [u8; 16],
        rows: &[SelfRowIn],
    ) -> bool {
        let Some(old) = keys.old.as_ref() else {
            return false;
        };
        let old_seat = old.pair.public().seat(MemberId::Account(account));
        let mut any = false;
        for r in rows.iter().filter(|r| {
            r.kind == gk::self_row::SELF_ROW && (r.sk, r.sx) == (old_seat.tag_sk, old_seat.tag_sx)
        }) {
            let Ok(g) = Group::new(GroupKind::Text, &r.group, r.gen) else {
                continue;
            };
            let Ok(s_m) = open_self_row(&g, r.seed, &old_seat, keys.self_key(), &r.sealed) else {
                continue;
            };
            self.s_m.insert((r.group.clone(), r.gen, r.seed), s_m);
            // The group being read now is read again, for a seed its pages may have passed
            let at = (r.group.clone(), r.gen);
            if self.listed && !self.makers.iter().skip(1).any(|x| *x == at) {
                self.makers.push_back(at);
            }
            any = true;
        }
        any
    }

    /// Whether its next ask is a `SelfRowsList` page (else `RowMakers`).
    pub(crate) fn listing(&self) -> bool {
        !self.listed
    }

    /// The next ask; `None` once done, or once the old keys are gone (nothing opens then).
    pub(crate) fn next(&self, keys: &SeatKeys, account: [u8; 16]) -> Option<AccountRequest> {
        let old = keys.old.as_ref()?;
        if !self.listed {
            return Some(AccountRequest::SelfRowsList {
                after: self.after.clone(),
                limit: gk::SELF_ROWS_MAX as u16,
            });
        }
        let (group, gen) = self.makers.front()?;
        let seat = old.pair.public().seat(MemberId::Account(account));
        Some(AccountRequest::RowMakers {
            group: group.clone(),
            gen: *gen,
            sk: seat.tag_sk,
            sx: seat.tag_sx,
            after: self.makers_after.clone(),
        })
    }

    /// A page of `SelfRows`: what was under the old self key, sealed again under the new.
    pub(crate) fn rows_in(
        &mut self,
        keys: &SeatKeys,
        account: [u8; 16],
        rows: &[SelfRowIn],
        next: Option<Vec<u8>>,
    ) -> Vec<SelfRowIn> {
        let Some(old) = keys.old.as_ref() else {
            return Vec::new();
        };
        let me = MemberId::Account(account);
        let new_seat = keys.pair.public().seat(me);
        let old_seat = old.pair.public().seat(me);
        let mut again = Vec::new();
        for r in rows.iter().filter(|r| r.check().is_ok()) {
            let seat = SeatRef {
                m: me,
                tag_sk: r.sk,
                tag_sx: r.sx,
            };
            let Ok(g) = Group::new(GroupKind::Text, &r.group, r.gen) else {
                continue;
            };
            if seat == new_seat || !r.group.starts_with("c:") {
                continue;
            }
            let sealed = if r.kind == gk::self_row::SELF_ROW {
                // One already sealed again (an earlier pass) still gives the old seat's `s_m`
                let opened = open_self_row(&g, r.seed, &seat, old.self_key(), &r.sealed)
                    .map(|s_m| (s_m, true))
                    .or_else(|_| {
                        open_self_row(&g, r.seed, &seat, keys.self_key(), &r.sealed)
                            .map(|s_m| (s_m, false))
                    });
                let Ok((s_m, under_old)) = opened else {
                    continue;
                };
                let sealed = under_old.then(|| self_row(&g, r.seed, &seat, keys.self_key(), &s_m));
                if seat == old_seat {
                    self.s_m.insert((r.group.clone(), r.gen, r.seed), s_m);
                }
                sealed
            } else {
                open_history_row(&g, r.seed, &seat, old.self_key(), &r.sealed)
                    .ok()
                    .map(|e| history_row(&g, r.seed, &seat, keys.self_key(), &e))
            };
            if let Some(sealed) = sealed {
                again.push(SelfRowIn {
                    sealed,
                    ..r.clone()
                });
            }
        }
        // A page that moves on nothing is the end
        let more = next.is_some() && next != self.after && !rows.is_empty();
        self.after = next;
        if !more {
            self.listed = true;
            let mut groups: Vec<(String, [u8; 16])> = self
                .s_m
                .keys()
                .map(|(g, gen, _)| (g.clone(), *gen))
                .collect();
            groups.dedup();
            self.makers = groups.into();
        }
        again
    }

    /// A page of `RowMakers` for the group being read: at its last page, the old seat's
    /// history rows there, one per seed whose `s_m` it holds.
    pub(crate) fn makers_in(
        &mut self,
        keys: &SeatKeys,
        account: [u8; 16],
        makers: &[gk::RowMaker],
        next: Option<Vec<u8>>,
    ) -> Vec<SelfRowIn> {
        let (Some(old), Some((group, gen))) = (keys.old.as_ref(), self.makers.front().cloned())
        else {
            return Vec::new();
        };
        let Ok(g) = Group::new(GroupKind::Text, &group, gen) else {
            self.makers.pop_front();
            return Vec::new();
        };
        let me = Me {
            m: MemberId::Account(account),
            keys: &old.pair,
        };
        for mk in makers {
            let Some(s_m) = self.s_m.get(&(group.clone(), gen, mk.s)) else {
                continue;
            };
            let Ok(from) = Holder::from_raw(mk.from.m.into(), &mk.from.kx) else {
                continue;
            };
            let entries = self.entries.entry(mk.s).or_default();
            if entries.iter().any(|e| e.k == from.id()) {
                continue;
            }
            if let Ok(rb) = RowBase::member_side(&g, mk.s, &me, &from, s_m) {
                entries.push(HistoryEntry {
                    k: from.id(),
                    rb: Zeroizing::new(*rb.secret()),
                });
            }
        }
        let more = next.is_some() && next != self.makers_after && !makers.is_empty();
        self.makers_after = next;
        if more {
            return Vec::new();
        }
        self.makers.pop_front();
        self.makers_after = None;
        let seat = old.pair.public().seat(me.m);
        std::mem::take(&mut self.entries)
            .into_iter()
            .map(|(s, mut entries)| {
                entries.truncate(HISTORY_MOST);
                SelfRowIn {
                    group: group.clone(),
                    gen,
                    seed: s,
                    sk: seat.tag_sk,
                    sx: seat.tag_sx,
                    kind: gk::self_row::HISTORY_ROW,
                    sealed: history_row(&g, s, &seat, keys.self_key(), &entries),
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use libsignal_protocol::IdentityKeyPair;
    use voipc_protocol::gk;
    use voipc_protocol::messages::{ClientMessage, ServerMessage};

    use super::super::{
        seat_keys, GkCtx, GkStart, GkTrack, GroupKeying, MemoryPins, PastEpoch, Platform,
        VaultFloor,
    };
    use crate::group_key::build::world::{World, T0, TEXT_ID};
    use crate::group_key::build::Built;
    use crate::group_key::commit::{Due, DueKind, Joiner};
    use crate::group_key::{
        history_row, inclusion_path, open_seat_welcome, seed_welcome, self_row, Endorsement,
        GroupKind, HistoryEntry, Leaf, Me, MemberId, Origin, RowBase, SeatKeys, SeatRef,
        SignedHeader, Them, Version,
    };
    use crate::stores::SignalStores;

    const RUN: [u8; 16] = [0x11; 16];
    const A: [u8; 16] = [7; 16];

    fn header_in(h: &SignedHeader) -> gk::HeaderIn {
        gk::HeaderIn {
            body: h.body().to_vec(),
            sig: h.sig().to_vec(),
        }
    }

    /// A device of account `A` on a fresh connection, in the stored text group, that has
    /// taken no header of it.
    struct Device {
        keying: GroupKeying,
        st: SignalStores,
        pins: MemoryPins,
    }

    impl Device {
        fn new(ik: IdentityKeyPair, keys: SeatKeys) -> Device {
            let mut keying = GroupKeying::default();
            let _ = keying.start(GkStart {
                on: true,
                run: RUN,
                relay_clock: T0,
                platform: Platform::Desktop,
                help_hold_keys: false,
                user_id: 20,
                identity: ik,
                account: Some(A),
                seat_keys: Some(keys),
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
            let _ = keying.track(t, VaultFloor::None);
            Device {
                keying,
                st: SignalStores::new(&ik, 20),
                pins: MemoryPins::default(),
            }
        }

        fn take(&mut self, piece: gk::InPiece) -> super::GkOut {
            self.frame(ServerMessage::EpochIn {
                group: TEXT_ID.into(),
                part: 0,
                last: true,
                piece: Box::new(piece),
            })
        }

        fn not_stored(&mut self) -> super::GkOut {
            self.frame(ServerMessage::EpochRefused {
                group: TEXT_ID.into(),
                what: gk::refused_what::FETCH,
                why: gk::refused_why::NOT_STORED,
                detail: String::new(),
            })
        }

        fn rate(&mut self) -> super::GkOut {
            self.frame(ServerMessage::EpochRefused {
                group: TEXT_ID.into(),
                what: gk::refused_what::FETCH,
                why: gk::refused_why::RATE,
                detail: String::new(),
            })
        }

        fn frame(&mut self, msg: ServerMessage) -> super::GkOut {
            let c = GkCtx {
                pins: &mut self.pins,
                now: T0 * 1000,
            };
            self.keying.frame(&mut self.st, &msg, c)
        }

        fn tick(&mut self, now: u64) -> super::GkOut {
            let c = GkCtx {
                pins: &mut self.pins,
                now,
            };
            self.keying.tick(&mut self.st, c)
        }
    }

    /// Whether `out` sends a live fetch (no `at`).
    fn live_fetch(out: &super::GkOut) -> bool {
        out.send
            .iter()
            .any(|m| matches!(m, ClientMessage::EpochFetch { at, .. } if at.is_empty()))
    }

    /// The account's seat (`A`, its seat keys) and another account's, joined in one Join;
    /// then the other leaves, so the next opening re-keys their bucket by a row to ours.
    struct Case {
        w: World,
        ik: IdentityKeyPair,
        seat: SeatRef,
        joined: Built,
        past: Built,
    }

    fn joiner(ik: &IdentityKeyPair, a: [u8; 16], keys: &SeatKeys) -> Joiner {
        let public = keys.pair.public();
        let m = MemberId::Account(a);
        Joiner {
            seat: public.seat(m),
            ik: ik.public_key().public_key_bytes().try_into().unwrap(),
            endorsement: Endorsement::sign(ik, Origin::VaultSeat, m, keys.n, keys.made, &public)
                .unwrap(),
            keys: public,
            returning: false,
        }
    }

    fn case(keys: &SeatKeys) -> Case {
        let mut w = World::text(true, false);
        let ik = IdentityKeyPair::generate(&mut crate::rng());
        let other_ik = IdentityKeyPair::generate(&mut crate::rng());
        let other_keys = SeatKeys::generate(1, T0);
        let mine = joiner(&ik, A, keys);
        let other = joiner(&other_ik, [8; 16], &other_keys);
        let (seat, gone) = (mine.seat, other.seat);
        let due = Due {
            joiners: vec![mine, other],
            ..w.due(DueKind::Join)
        };
        let joined = w.build_join(&due, None).unwrap();
        w.step(&due, &joined);
        let due = w.exits(&[gone], DueKind::Exits);
        let past = w.open(&due);
        Case {
            w,
            ik,
            seat,
            joined,
            past,
        }
    }

    /// `s_m` of our seat from its welcome, with the seed.
    fn s_m(c: &Case, keys: &SeatKeys) -> (u32, zeroize::Zeroizing<[u8; 32]>) {
        let x = c
            .joined
            .commit
            .welcomes
            .iter()
            .find(|x| x.seat == c.seat)
            .unwrap();
        let me = Me {
            m: MemberId::Account(A),
            keys: &keys.pair,
        };
        let at = Version { b: x.b, v: x.v };
        let from = c.w.holders[0].holder();
        let (s_m, _) = open_seat_welcome(&c.w.g, x.s, at, &me, &from, &x.bytes).unwrap();
        (x.s, s_m)
    }

    /// What the relay sends for the past epoch: its opening header, our leaf then with its
    /// path, the seal, and the row to our seat's version (no anchor: a fresh device).
    fn answer(c: &Case, rows: Vec<gk::SelfRowIn>) -> gk::InPiece {
        let leaves: Vec<Leaf> = c.w.leaves.iter().map(|l| l.leaf).collect();
        let i =
            c.w.leaves
                .iter()
                .position(|l| l.seats.contains(&c.seat))
                .unwrap();
        let leaf = leaves[i];
        let r = c
            .past
            .commit
            .rows
            .iter()
            .find(|r| (r.b, r.v) == (leaf.b, leaf.v))
            .expect("our bucket is re-keyed by a row");
        let at = c.w.leaves[i]
            .seats
            .iter()
            .position(|x| *x == c.seat)
            .unwrap();
        let (row, s) = r.row(at).unwrap();
        let seal = c
            .past
            .commit
            .seals
            .iter()
            .find(|s| (s.b, s.v) == (leaf.b, leaf.v))
            .unwrap();
        gk::InPiece {
            head: Some(gk::WalkLinkIn {
                header: header_in(&c.past.header),
                parent: None,
            }),
            leaf: Some(leaf.into()),
            path: Some(inclusion_path(&leaves, i).unwrap().try_into().unwrap()),
            seal: Some(seal.bytes.clone()),
            seat: Some(gk::SeatKeying {
                b: r.b,
                base_v: r.v,
                s: s as u32,
                from: c.w.holders[0].by().into(),
                welcome: None,
                row: Some(row.to_vec()),
                ratchets: vec![],
            }),
            self_rows: rows,
            past: Some(gk::EpochRef {
                gen: c.w.g.gen(),
                epoch: c.past.header.header().epoch,
            }),
            ..Default::default()
        }
    }

    fn self_row_of(c: &Case, seat: &SeatRef, s: u32, kind: u8, sealed: Vec<u8>) -> gk::SelfRowIn {
        gk::SelfRowIn {
            group: TEXT_ID.into(),
            gen: c.w.g.gen(),
            seed: s,
            sk: seat.tag_sk,
            sx: seat.tag_sx,
            kind,
            sealed,
        }
    }

    fn asked(out: &super::GkOut) -> Vec<gk::EpochRef> {
        out.send
            .iter()
            .flat_map(|m| match m {
                ClientMessage::EpochFetch { at, .. } => at.clone(),
                _ => Vec::new(),
            })
            .collect()
    }

    /// Part 4, open choice 22: a device that took no header of the group reads a past epoch:
    /// asked by `at`, taken on the binding alone, from its row to our seat opened by the
    /// account's self-row; then handed over, and the floor never moved for it.
    #[test]
    fn a_past_epoch_is_asked_then_taken_by_its_row_and_self_row_and_handed_over() {
        let keys = SeatKeys::generate(1, T0);
        let c = case(&keys);
        let (s, s_m) = s_m(&c, &keys);
        let gen = c.w.g.gen();
        let e = c.past.header.header().epoch;
        let mut d = Device::new(c.ik, seat_keys::copy(&keys));
        assert!(matches!(
            d.keying.past_epoch(TEXT_ID, gen, e),
            PastEpoch::Asked
        ));
        let out = d.keying.past_asks();
        assert_eq!(asked(&out), vec![gk::EpochRef { gen, epoch: e }]);
        assert!(asked(&d.keying.past_asks()).is_empty(), "asked once");
        let row = self_row(&c.w.g, s, &c.seat, keys.self_key(), &s_m);
        let rows = vec![self_row_of(&c, &c.seat, s, gk::self_row::SELF_ROW, row)];
        let out = d.take(answer(&c, rows));
        assert_eq!(out.past_ready, vec![(TEXT_ID.to_string(), gen, e)]);
        let PastEpoch::Ready(k) = d.keying.past_epoch(TEXT_ID, gen, e) else {
            panic!("taken");
        };
        assert_eq!((*k.ck, k.d_e), (*c.past.ck, c.past.header.d()));
        assert!(d.keying.current_epoch(TEXT_ID).is_none(), "no head for it");
    }

    /// §5.11, §3.11: after a rotation and once the old keys are gone, the history row the
    /// rotation wrote under the new self key opens the rows made to the old seat.
    #[test]
    fn a_history_row_opens_a_row_to_the_old_seat_once_its_keys_are_gone() {
        let old = SeatKeys::generate(1, T0);
        let c = case(&old);
        let (s, s_m) = s_m(&c, &old);
        let me_old = Me {
            m: MemberId::Account(A),
            keys: &old.pair,
        };
        let from = c.w.holders[0].holder();
        let rb = RowBase::member_side(&c.w.g, s, &me_old, &from, &s_m).unwrap();
        let mut new = seat_keys::copy(&old).rotate(T0 + 60).unwrap();
        new.drop_old();
        let entries = [HistoryEntry {
            k: from.id(),
            rb: zeroize::Zeroizing::new(*rb.secret()),
        }];
        let sealed = history_row(&c.w.g, s, &c.seat, new.self_key(), &entries);
        let rows = vec![self_row_of(
            &c,
            &c.seat,
            s,
            gk::self_row::HISTORY_ROW,
            sealed,
        )];
        let gen = c.w.g.gen();
        let e = c.past.header.header().epoch;
        let mut d = Device::new(c.ik, new);
        d.keying.past_epoch(TEXT_ID, gen, e);
        d.keying.past_asks();
        let out = d.take(answer(&c, rows));
        assert_eq!(out.past_ready.len(), 1);
        assert!(matches!(
            d.keying.past_epoch(TEXT_ID, gen, e),
            PastEpoch::Ready(_)
        ));
    }

    /// R1b sends the seed welcome with a row to our seat after a seed roll: where the walk
    /// from the device's anchor reaches the epoch, the row opens by it with no self-row, and
    /// does not without it. On the binding alone it does not: the relay names the seed
    /// welcome's maker (J8K review), so only a self-row's `s_m` is our own there.
    #[test]
    fn a_row_opens_by_the_seed_welcome_its_answer_carries_where_an_anchor_reaches_the_epoch() {
        let keys = SeatKeys::generate(1, T0);
        let c = case(&keys);
        let (s, s_m) = s_m(&c, &keys);
        let gen = c.w.g.gen();
        let e = c.past.header.header().epoch;
        let holder = &c.w.holders[0];
        let public = keys.pair.public();
        let to = Them {
            m: MemberId::Account(A),
            keys: &public,
        };
        let bytes = seed_welcome(&c.w.g, s, &holder.me(), &to, &s_m).unwrap();
        assert_eq!(c.past.header.kh(), c.w.kh.d(), "the set the device holds");
        let read = |p: gk::InPiece, anchored: bool| {
            let mut d = Device::new(c.ik, seat_keys::copy(&keys));
            if anchored {
                // A floor at the past epoch's opening, with the keyholder header it names
                let m = d.keying.groups.get_mut(TEXT_ID).unwrap();
                m.floor = Some(crate::group_key::Floor::after(None, &c.past.header, T0));
                m.kh = Some(c.w.kh.clone());
            }
            d.keying.past_epoch(TEXT_ID, gen, e);
            d.keying.past_asks();
            assert_eq!(d.take(p).past_ready.len(), 1);
            matches!(d.keying.past_epoch(TEXT_ID, gen, e), PastEpoch::Ready(_))
        };
        assert!(
            !read(answer(&c, Vec::new()), true),
            "the control: no s_m, no key"
        );
        let mut p = answer(&c, Vec::new());
        p.seed_welcome = Some(gk::SeedWelcomeIn {
            s,
            from: holder.by().into(),
            bytes,
        });
        assert!(read(p.clone(), true));
        assert!(!read(p, false), "on the binding alone, no seed welcome");
    }

    /// J9M (a reloaded page's kept read): a floor whose keyholder header this device does not
    /// hold (the vault's, before the live answer brings the header) is no anchor. The kept ask
    /// goes without `have`, so the relay answers it in the binding alone's shape (for a Join,
    /// with the set its opening names) and does not walk back from a header this device cannot
    /// check a walk from. With the header held, the floor goes as `have`.
    #[test]
    fn a_kept_ask_names_the_floor_only_with_its_keyholder_header_held() {
        let keys = SeatKeys::generate(1, T0);
        let c = case(&keys);
        let gen = c.w.g.gen();
        let e = c.past.header.header().epoch;
        assert_eq!(c.past.header.kh(), c.w.kh.d(), "the set the floor names");
        let have = |held: bool| {
            let mut d = Device::new(c.ik, seat_keys::copy(&keys));
            let m = d.keying.groups.get_mut(TEXT_ID).unwrap();
            m.floor = Some(crate::group_key::Floor::after(None, &c.past.header, T0));
            if held {
                m.kh = Some(c.w.kh.clone());
            }
            d.keying.past_epoch(TEXT_ID, gen, e - 1);
            let out = d.keying.past_asks();
            out.send.iter().find_map(|m| match m {
                ClientMessage::EpochFetch { have, at, .. } if !at.is_empty() => {
                    Some(have.as_ref().map(|h| (h.epoch, h.kh)))
                }
                _ => None,
            })
        };
        assert_eq!(
            have(false),
            Some(None),
            "with no keyholder header held, no have"
        );
        assert_eq!(
            have(true),
            Some(Some((e, c.w.kh.d()))),
            "held: the floor goes as have"
        );
    }

    /// C1 leaves it to the caller (P1): an answer whose header is another epoch's than the
    /// one asked is not taken, and the epoch is then not to be had; an answer nobody asked
    /// for is not taken either. `NOT_STORED` answers the oldest ask out, and only that one.
    #[test]
    fn a_past_answer_is_taken_only_as_the_epoch_asked_for() {
        let keys = SeatKeys::generate(1, T0);
        let c = case(&keys);
        let (s, s_m) = s_m(&c, &keys);
        let row = self_row(&c.w.g, s, &c.seat, keys.self_key(), &s_m);
        let rows = vec![self_row_of(&c, &c.seat, s, gk::self_row::SELF_ROW, row)];
        let gen = c.w.g.gen();
        let e = c.past.header.header().epoch;
        let mut d = Device::new(c.ik, seat_keys::copy(&keys));
        assert!(
            d.take(answer(&c, rows.clone())).past_ready.is_empty(),
            "not asked"
        );
        d.keying.past_epoch(TEXT_ID, gen, e + 1);
        d.keying.past_asks();
        let mut swapped = answer(&c, rows);
        swapped.past = Some(gk::EpochRef { gen, epoch: e + 1 });
        let out = d.take(swapped);
        assert_eq!(out.past_ready, vec![(TEXT_ID.to_string(), gen, e + 1)]);
        assert!(matches!(
            d.keying.past_epoch(TEXT_ID, gen, e + 1),
            PastEpoch::Unknown
        ));
        // `NOT_STORED`, through the frame: the first of the two asked
        d.keying.past_epoch(TEXT_ID, gen, e + 2);
        d.keying.past_epoch(TEXT_ID, gen, e + 3);
        assert_eq!(asked(&d.keying.past_asks()).len(), 2);
        let out = d.not_stored();
        assert_eq!(out.past_ready, vec![(TEXT_ID.to_string(), gen, e + 2)]);
        assert!(matches!(
            d.keying.past_epoch(TEXT_ID, gen, e + 2),
            PastEpoch::Unknown
        ));
        assert!(matches!(
            d.keying.past_epoch(TEXT_ID, gen, e + 3),
            PastEpoch::Asked
        ));
        assert_eq!(d.not_stored().past_ready[0].2, e + 3);
        assert!(d.not_stored().past_ready.is_empty(), "none out");
    }

    /// The asks out are paced: 16 a frame, four frames out at once, the next once 16 are
    /// answered. A group not tracked has no past epoch here.
    #[test]
    fn past_asks_go_sixteen_a_frame_four_frames_at_once() {
        let keys = SeatKeys::generate(1, T0);
        let mut d = Device::new(IdentityKeyPair::generate(&mut crate::rng()), keys);
        for e in 0..100 {
            d.keying.past_epoch(TEXT_ID, [1; 16], e);
        }
        let out = d.keying.past_asks();
        let frames: Vec<usize> = out
            .send
            .iter()
            .map(|m| match m {
                ClientMessage::EpochFetch { at, have, .. } => {
                    assert!(have.is_none(), "no floor yet");
                    at.len()
                }
                _ => 0,
            })
            .collect();
        assert_eq!(frames, vec![16, 16, 16, 16]);
        assert!(d.keying.past_asks().send.is_empty());
        for _ in 0..15 {
            assert!(d.not_stored().send.is_empty(), "no room for a frame yet");
        }
        assert_eq!(asked(&d.not_stored()).len(), 16, "a whole frame");
        assert!(matches!(
            d.keying.past_epoch("c:other", [1; 16], 1),
            PastEpoch::Unknown
        ));
    }
    /// R2 refuses a fetch over its budget `RATE` as it reads it, and R1b answers `at` entries
    /// in order: a `RATE` that finds the oldest kept frame unanswered is that frame's. Its
    /// asks go again after a pause, and the live fetch is not held back for it; a `RATE` once
    /// that frame is being answered is the live fetch's.
    #[test]
    fn a_rate_to_an_unanswered_kept_frame_is_its_own_and_holds_back_no_live_fetch() {
        let keys = SeatKeys::generate(1, T0);
        let mut d = Device::new(IdentityKeyPair::generate(&mut crate::rng()), keys);
        for e in 0..20 {
            d.keying.past_epoch(TEXT_ID, [1; 16], e);
        }
        assert_eq!(asked(&d.keying.past_asks()).len(), 20);
        assert!(d.rate().send.is_empty(), "its asks wait out the pause");
        assert!(d.keying.past_asks().send.is_empty(), "paused");
        assert!(
            live_fetch(&d.tick(T0 * 1000)),
            "the live fetch, unanswered, goes again as before"
        );
        d.keying.kept.pace.paused_until = 0;
        let again = asked(&d.keying.past_asks());
        let epochs: Vec<u32> = again.iter().map(|r| r.epoch).collect();
        assert_eq!(
            epochs,
            (0..16).collect::<Vec<u32>>(),
            "the refused frame again"
        );
        assert_eq!(
            d.not_stored().past_ready,
            vec![(TEXT_ID.to_string(), [1; 16], 16)],
            "the second frame is answered first"
        );
        assert!(d.rate().send.is_empty());
        assert!(
            !live_fetch(&d.tick(T0 * 1000 + crate::group_key::timers::CHECK_WAIT_MS)),
            "the live fetch's own RATE paces it"
        );
        assert_eq!(
            d.not_stored().past_ready[0].2,
            17,
            "nothing of ours given up"
        );
    }

    /// The kept frames of every group together go at most `PACE_BURST` at once: the relay's
    /// fetch budget is the live fetches' too.
    #[test]
    fn kept_frames_of_every_group_go_under_the_relays_fetch_budget() {
        let keys = SeatKeys::generate(1, T0);
        let mut d = Device::new(IdentityKeyPair::generate(&mut crate::rng()), keys);
        let mut groups = vec![TEXT_ID.to_string()];
        for i in 2..=5 {
            let t = GkTrack {
                channel_id: i,
                group: format!("c:lounge-{i}"),
                kind: GroupKind::Text,
                anonymous: false,
                hide_members: false,
                viewer_admin: false,
                keeps_history: true,
            };
            groups.push(t.group.clone());
            let _ = d.keying.track(t, VaultFloor::None);
        }
        for g in &groups {
            for e in 0..64 {
                d.keying.past_epoch(g, [1; 16], e);
            }
        }
        let frames = d.keying.past_asks().send.len();
        assert_eq!(frames, super::PACE_BURST as usize, "not all 20 at once");
    }

    /// An ask that went with no floor (`have: None`) got no walk: its answer is taken on the
    /// binding alone, even when a live answer brought a newer keyholder header meanwhile.
    #[test]
    fn a_past_answer_is_walked_back_from_the_anchor_its_ask_went_with() {
        let keys = SeatKeys::generate(1, T0);
        let mut c = case(&keys);
        let (s, s_m) = s_m(&c, &keys);
        let row = self_row(&c.w.g, s, &c.seat, keys.self_key(), &s_m);
        let rows = vec![self_row_of(&c, &c.seat, s, gk::self_row::SELF_ROW, row)];
        let p = answer(&c, rows);
        let gen = c.w.g.gen();
        let e = c.past.header.header().epoch;
        let promoted =
            c.w.promote(crate::group_key::build::world::Holder::desktop(9));
        let h = promoted.header.header();
        assert!(h.kind.sets_keyholders() && h.gen == gen && h.epoch > e);
        let mut d = Device::new(c.ik, seat_keys::copy(&keys));
        d.keying.past_epoch(TEXT_ID, gen, e);
        d.keying.past_asks();
        // The live answer's keyholder header, taken while the ask was out
        d.keying.groups.get_mut(TEXT_ID).unwrap().kh = Some(promoted.header.clone());
        assert_eq!(d.take(p).past_ready.len(), 1);
        assert!(matches!(
            d.keying.past_epoch(TEXT_ID, gen, e),
            PastEpoch::Ready(_)
        ));
    }

    /// An ask sent again (out `AGAIN_MS`) leaves its first reply owed: a `NOT_STORED` to that
    /// first send is matched to it, the next ask's answer is still taken, and the reply to
    /// the second send answers nothing more.
    #[test]
    fn an_ask_sent_again_leaves_its_first_reply_owed() {
        let keys = SeatKeys::generate(1, T0);
        let c = case(&keys);
        let (s, s_m) = s_m(&c, &keys);
        let row = self_row(&c.w.g, s, &c.seat, keys.self_key(), &s_m);
        let rows = vec![self_row_of(&c, &c.seat, s, gk::self_row::SELF_ROW, row)];
        let gen = c.w.g.gen();
        let e = c.past.header.header().epoch;
        assert!(e >= 1);
        let mut d = Device::new(c.ik, seat_keys::copy(&keys));
        d.keying.past_epoch(TEXT_ID, gen, e - 1);
        d.keying.past_epoch(TEXT_ID, gen, e);
        assert_eq!(asked(&d.keying.past_asks()).len(), 2);
        let asks = d.keying.kept.asks.get_mut(TEXT_ID).unwrap();
        asks.sent.insert((gen, e - 1), Some(0));
        d.keying.past_epoch(TEXT_ID, gen, e - 1);
        assert_eq!(
            asked(&d.keying.past_asks()),
            vec![gk::EpochRef { gen, epoch: e - 1 }],
            "asked again"
        );
        assert_eq!(
            d.not_stored().past_ready,
            vec![(TEXT_ID.to_string(), gen, e - 1)]
        );
        let out = d.take(answer(&c, rows));
        assert_eq!(out.past_ready, vec![(TEXT_ID.to_string(), gen, e)]);
        assert!(matches!(
            d.keying.past_epoch(TEXT_ID, gen, e),
            PastEpoch::Ready(_)
        ));
        assert!(d.not_stored().past_ready.is_empty(), "the second send's");
    }

    /// T1e A, §5.10 "a reader opens it from its seat at epoch `e`": a seat a Join added
    /// after the epoch's opening (the Genesis here) is in no opening's root. The relay
    /// answers at the epoch's last Join with the opening (R1b `store::past`), and a fresh
    /// device takes the epoch's key from its welcome there, whose `s_m` is its account's
    /// self-row's; without the opening, or with a Join in its place, nothing is taken, nor
    /// by the welcome with no self-row to show it is ours (J8K review).
    #[test]
    fn a_past_epoch_a_join_seated_us_in_is_taken_at_its_last_join_with_its_opening() {
        let keys = SeatKeys::generate(1, T0);
        let mut w = World::text(true, false);
        let genesis = w.head.clone();
        let ik = IdentityKeyPair::generate(&mut crate::rng());
        let mine = joiner(&ik, A, &keys);
        let seat = mine.seat;
        let due = Due {
            joiners: vec![mine],
            ..w.due(DueKind::Join)
        };
        let joined = w.build_join(&due, None).unwrap();
        w.step(&due, &joined);
        let last = w.join(&[&crate::group_key::build::world::Member::account(8)]);
        assert_eq!(
            (last.header.header().epoch, last.header.header().join),
            (1, 2)
        );
        let x = joined
            .commit
            .welcomes
            .iter()
            .find(|x| x.seat == seat)
            .unwrap();
        let leaves: Vec<Leaf> = w.leaves.iter().map(|l| l.leaf).collect();
        let i = leaves
            .iter()
            .position(|l| (l.b, l.v) == (x.b, x.v))
            .unwrap();
        let seal = joined
            .commit
            .seals
            .iter()
            .find(|s| (s.b, s.v) == (x.b, x.v))
            .unwrap();
        let gen = w.g.gen();
        // The account's self-row of that seat and seed, as its device that took the
        // welcome live wrote it (`Member::write_self_row`)
        let me = Me {
            m: MemberId::Account(A),
            keys: &keys.pair,
        };
        let at = Version { b: x.b, v: x.v };
        let (s_m, _) =
            open_seat_welcome(&w.g, x.s, at, &me, &w.holders[0].holder(), &x.bytes).unwrap();
        let rows = vec![gk::SelfRowIn {
            group: TEXT_ID.into(),
            gen,
            seed: x.s,
            sk: seat.tag_sk,
            sx: seat.tag_sx,
            kind: gk::self_row::SELF_ROW,
            sealed: self_row(&w.g, x.s, &seat, keys.self_key(), &s_m),
        }];
        let answer_with =
            |opening: Option<&SignedHeader>, self_rows: Vec<gk::SelfRowIn>| gk::InPiece {
                head: Some(gk::WalkLinkIn {
                    header: header_in(&last.header),
                    parent: None,
                }),
                opening: opening.map(header_in),
                leaf: Some(leaves[i].into()),
                path: Some(inclusion_path(&leaves, i).unwrap().try_into().unwrap()),
                seal: Some(seal.bytes.clone()),
                seat: Some(gk::SeatKeying {
                    b: x.b,
                    base_v: x.v,
                    s: x.s,
                    from: w.holders[0].by().into(),
                    welcome: Some(x.bytes.clone()),
                    row: None,
                    ratchets: vec![],
                }),
                self_rows,
                past: Some(gk::EpochRef { gen, epoch: 1 }),
                ..Default::default()
            };
        let answer = |opening: Option<&SignedHeader>| answer_with(opening, rows.clone());
        let read = |p: gk::InPiece| {
            let mut d = Device::new(ik, seat_keys::copy(&keys));
            d.keying.past_epoch(TEXT_ID, gen, 1);
            d.keying.past_asks();
            assert_eq!(d.take(p).past_ready.len(), 1);
            match d.keying.past_epoch(TEXT_ID, gen, 1) {
                PastEpoch::Ready(k) => Some((k.ck, k.d_e)),
                _ => None,
            }
        };
        assert!(read(answer(None)).is_none(), "the control: no opening");
        assert!(
            read(answer(Some(&joined.header))).is_none(),
            "a Join is no opening"
        );
        let (ck, d_e) = read(answer(Some(&genesis))).expect("taken");
        assert_eq!((*ck, d_e), (*joined.ck, genesis.d()));
        assert!(
            read(answer_with(Some(&genesis), Vec::new())).is_none(),
            "on the binding alone, a welcome no self-row shows ours"
        );
    }

    /// J8K review: a welcome binds its sender, and with no anchor the relay names the
    /// sender. A relay that makes its own keyholder pair, seats our account's published
    /// seat keys under a `BK` of its choosing (a seat welcome; or a seed welcome and a row),
    /// and forges the epoch's header around a `CK` of its choosing (an opening of its own;
    /// or an opening naming it a keyholder with a Join it signs) hands a fresh device no key.
    /// On the binding alone a past epoch is taken only under the device's own `BK` (§5.10):
    /// a row under the `s_m` of its self-row, or its history row's, or a welcome whose `s_m`
    /// is the self-row's. The genuine answer, with that self-row, is taken.
    #[test]
    fn a_fresh_device_takes_no_past_epoch_on_a_welcome_from_a_keyholder_the_relay_made() {
        use crate::group_key::build::world::{Holder, Member};
        use crate::group_key::{confirm, seal, seat_welcome, Epoch};
        let keys = SeatKeys::generate(1, T0);
        let mut c = case(&keys);
        let (s, s_m) = s_m(&c, &keys);
        let row = self_row(&c.w.g, s, &c.seat, keys.self_key(), &s_m);
        let rows = vec![self_row_of(&c, &c.seat, s, gk::self_row::SELF_ROW, row)];
        let (ik, gen, g) = (c.ik, c.w.g.gen(), c.w.g.clone());
        let past = c.past.header.clone();
        let e = past.header().epoch;
        let real = answer(&c, rows);
        let read = |p: gk::InPiece| {
            let mut d = Device::new(ik, seat_keys::copy(&keys));
            d.keying.past_epoch(TEXT_ID, gen, e);
            d.keying.past_asks();
            assert_eq!(d.take(p).past_ready.len(), 1);
            match d.keying.past_epoch(TEXT_ID, gen, e) {
                PastEpoch::Ready(k) => Some(*k.ck),
                _ => None,
            }
        };
        assert_eq!(read(real.clone()), Some(*c.past.ck), "the control: genuine");
        // The relay's own keyholder pair, named a keyholder by an opening it signs
        let promoted = c.w.promote(Holder::desktop(9)).header;
        let join = c.w.join(&[&Member::account(41)]).header;
        let relay = c.w.holders.last().unwrap();
        let (bk, ck) = ([0x5a; 32], [0xa5; 32]);
        let leaf = Leaf::try_from(real.leaf.unwrap()).unwrap();
        let at = Version {
            b: leaf.b,
            v: leaf.v,
        };
        let sign = |h: crate::group_key::HeaderV1| SignedHeader::sign(h, &relay.ik).unwrap();
        let own_opening = sign({
            let mut h = past.header().clone();
            h.signer = relay.m;
            h.confirm = confirm(&g, e, 0, &ck);
            h
        });
        let named = sign({
            let mut h = promoted.header().clone();
            h.epoch = e;
            h.signer = relay.m;
            h.bucket_root = past.header().bucket_root;
            h.buckets = past.header().buckets;
            h.confirm = confirm(&g, e, 0, &ck);
            h
        });
        assert!(named
            .header()
            .keyholders
            .contains(&relay.entry(GroupKind::Text)));
        let signed_join = sign({
            let o = named.header();
            let mut h = join.header().clone();
            h.epoch = e;
            h.epoch_parent = named.d();
            h.kh_parent = named.kh();
            h.signer = relay.m;
            (h.gated, h.seed, h.seed_floor, h.exits_upto) =
                (o.gated, o.seed, o.seed_floor, o.exits_upto);
            h.bucket_root = past.header().bucket_root;
            h.buckets = past.header().buckets;
            h.confirm = confirm(&g, e, h.join, &ck);
            h
        });
        // Our account's seat keys, as the relay publishes them
        let public = keys.pair.public();
        let to = Them {
            m: MemberId::Account(A),
            keys: &public,
        };
        let welcome = seat_welcome(&g, s, at, &relay.me(), &to, &[0x33; 32], &bk).unwrap();
        let by_welcome = gk::SeatKeying {
            b: at.b,
            base_v: at.v,
            s,
            from: relay.by().into(),
            welcome: Some(welcome),
            row: None,
            ratchets: vec![],
        };
        let relay_s_m = [0x44; 32];
        let by_row = gk::SeatKeying {
            welcome: None,
            row: Some(
                RowBase::keyholder_side(&g, s, &relay.me(), &to, &relay_s_m)
                    .unwrap()
                    .row(at, &bk),
            ),
            ..by_welcome.clone()
        };
        let seed = gk::SeedWelcomeIn {
            s,
            from: relay.by().into(),
            bytes: seed_welcome(&g, s, &relay.me(), &to, &relay_s_m).unwrap(),
        };
        let forge = |head: &SignedHeader, opening: Option<&SignedHeader>, seat: &gk::SeatKeying| {
            let d_e = opening.unwrap_or(head).d();
            gk::InPiece {
                head: Some(gk::WalkLinkIn {
                    header: header_in(head),
                    parent: None,
                }),
                opening: opening.map(header_in),
                seal: Some(seal(&g, &Epoch { e, d_e }, at, &bk, &ck)),
                seat: Some(seat.clone()),
                ..real.clone()
            }
        };
        let mut seed_row = forge(&own_opening, None, &by_row);
        seed_row.seed_welcome = Some(seed);
        let taken: Vec<(&str, [u8; 32])> = [
            (
                "an opening, a seat welcome",
                forge(&own_opening, None, &by_welcome),
            ),
            ("an opening, a seed welcome and a row", seed_row),
            (
                "a Join it signs, under an opening naming it a keyholder",
                forge(&signed_join, Some(&named), &by_welcome),
            ),
        ]
        .into_iter()
        .filter_map(|(what, p)| read(p).map(|k| (what, k)))
        .collect();
        assert_eq!(taken, vec![], "no key of the relay's taken");
    }

    /// J8K review: the binding alone trusts the account's self-row to hold an `s_m` a key
    /// passed `confirm` under. `Member::key_in` wrote one for the `s_m` of whatever seat keying
    /// came with an answer whose head key it held, though no key came through that keying: a
    /// relay that rides a welcome of its own pair, under a seed number of its choosing, on a
    /// real push of the next Join got its `s_m` sealed as the account's (then a fresh device's
    /// past read under that seed counted the relay's welcome as its own). Now a keying's `s_m`
    /// is kept, and sealed, only once its own `BK` opened the seal of a confirmed key.
    #[test]
    fn no_self_row_is_written_for_an_s_m_no_confirmed_key_came_through() {
        use crate::group_key::build::world::{Holder, Member};
        use crate::group_key::{open_self_row, seat_welcome};
        let mut w = World::text(true, false);
        let genesis = w.head.clone();
        let keys = SeatKeys::generate(1, T0);
        let ik = IdentityKeyPair::generate(&mut crate::rng());
        let mine = joiner(&ik, A, &keys);
        let seat = mine.seat;
        let due = Due {
            joiners: vec![mine],
            ..w.due(DueKind::Join)
        };
        let joined = w.build_join(&due, None).unwrap();
        w.step(&due, &joined);
        let x = joined
            .commit
            .welcomes
            .iter()
            .find(|x| x.seat == seat)
            .unwrap();
        let leaves: Vec<Leaf> = w.leaves.iter().map(|l| l.leaf).collect();
        let i = leaves
            .iter()
            .position(|l| (l.b, l.v) == (x.b, x.v))
            .unwrap();
        let link = |h: &SignedHeader| gk::WalkLinkIn {
            header: header_in(h),
            parent: None,
        };
        let mut d = Device::new(ik, seat_keys::copy(&keys));
        let take = |d: &mut Device, piece: gk::InPiece, now: u64| {
            let msg = ServerMessage::EpochIn {
                group: TEXT_ID.into(),
                part: 0,
                last: true,
                piece: Box::new(piece),
            };
            let c = GkCtx {
                pins: &mut d.pins,
                now: now * 1000,
            };
            d.keying.frame(&mut d.st, &msg, c)
        };
        // Seated by the Join: its welcome opens, `confirm` passes, the self-row for seed `s`
        let out = take(
            &mut d,
            gk::InPiece {
                walk: vec![link(&genesis)],
                head: Some(link(&w.head)),
                opening: Some(header_in(&w.kh)),
                leaf: Some(leaves[i].into()),
                path: Some(inclusion_path(&leaves, i).unwrap().try_into().unwrap()),
                seal: joined
                    .commit
                    .seals
                    .iter()
                    .find(|s| (s.b, s.v) == (x.b, x.v))
                    .map(|s| s.bytes.clone()),
                seat: Some(gk::SeatKeying {
                    b: x.b,
                    base_v: x.v,
                    s: x.s,
                    from: w.holders[0].by().into(),
                    welcome: Some(x.bytes.clone()),
                    row: None,
                    ratchets: vec![],
                }),
                ..Default::default()
            },
            w.now,
        );
        assert!(d.keying.current_epoch(TEXT_ID).is_some(), "seated");
        assert_eq!(out.self_rows.len(), 1, "the self-row for seed s");
        // The next Join, pushed, with a welcome of the relay's own pair under seed s + 1
        w.join(&[&Member::account(8)]);
        let relay = Holder::desktop(9);
        let public = keys.pair.public();
        let to = Them {
            m: MemberId::Account(A),
            keys: &public,
        };
        let at = Version { b: x.b, v: x.v };
        let s2 = x.s + 1;
        let forged = seat_welcome(&w.g, s2, at, &relay.me(), &to, &[0x33; 32], &[0x5a; 32]);
        let out = take(
            &mut d,
            gk::InPiece {
                head: Some(link(&w.head)),
                pushed: true,
                seat: Some(gk::SeatKeying {
                    b: x.b,
                    base_v: x.v,
                    s: s2,
                    from: relay.by().into(),
                    welcome: Some(forged.unwrap()),
                    row: None,
                    ratchets: vec![],
                }),
                ..Default::default()
            },
            w.now,
        );
        assert_eq!(
            d.keying.current_epoch(TEXT_ID).map(|e| e.epoch),
            Some(w.head.header().epoch),
            "the push is taken"
        );
        let sealed: Vec<(u32, bool)> = out
            .self_rows
            .iter()
            .map(|r| {
                let s_m = open_self_row(&w.g, r.seed, &seat, keys.self_key(), &r.sealed).unwrap();
                (r.seed, *s_m == [0x33; 32])
            })
            .collect();
        assert_eq!(sealed, vec![], "no self-row for the relay's s_m");
    }
}
