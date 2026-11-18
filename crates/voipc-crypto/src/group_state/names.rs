//! A writer's fold of a gated group's names (§4.4 rule 4, 3f): before every post, every
//! `added` list from its names floor to the head folds by C1's `fold_names`, each entry
//! checked against the pins and counters as they stood then. A list missing is asked for
//! (`EpochNames`); a fold that holds asks for the removals after it; a names floor from an
//! earlier gated period of the generation folds from the start (C1 note 1).
//!
//! `EpochNames.from` is exclusive here: the names floor, folded already. The relay answers
//! from it inclusive (a list at `from` is skipped), so a fold from the start asks from
//! `(gated_start - 1, 0)`, or `(0, 0)` where the gate-on opening is not known, and the relay
//! keeps that opening's list (R1 names.rs says the same).

use std::collections::BTreeMap;

use voipc_protocol::gk::{self, NamesPiece, Part, Parts, Seq};
use voipc_protocol::messages::ClientMessage;

use super::member::Member;
use super::{GkCtx, GkEvent, GkOut, GkState, HeldWhy, Warn, Who};
use crate::group_key::timers::CHECK_WAIT_MS;
use crate::group_key::{
    check_form, check_signer, fold_names, names_start, Fold, GroupKind, Held, Known, NamesFloor,
    NamesFrom, NamesList, NamesStep, Refusal, Removed, SignedHeader, Warning,
};

/// What a fold says to a writer.
pub(super) enum Folded {
    /// Every name checks out: post.
    Ok,
    /// An entry failed: hold, and say why.
    Held(HeldWhy),
    /// The lists are not all in: asked for.
    Wait,
}

/// One group's names, as a writer holds them.
pub(super) struct Names {
    pub(super) floor: Option<NamesFloor>,
    /// The generation `lists` and `removals` are of.
    gen: [u8; 16],
    /// Lists since the names floor, by `(epoch, join)`.
    lists: BTreeMap<(u32, u32), NamesList>,
    /// Opening headers with `removed` lists, each signed by a set this device holds.
    removals: Vec<SignedHeader>,
    /// A "gone" answer: the step before the relay's 90-day tail.
    gone: Option<NamesStep>,
    /// The epoch of the opening header that last turned the group gated, where seen.
    gated_start: Option<u32>,
    parts: Parts<(), NamesPiece>,
    /// When the last `EpochNames` went (ms), until answered.
    asked: Option<u64>,
    /// The last ask, `(from, to, removals)`, and when it went (ms), answered or not.
    last: Option<((gk::NamesRef, gk::NamesRef, bool), u64)>,
    asked_removals: bool,
    /// An answer came and the fold from the names floor still did not reach the head: the
    /// floor is from an earlier gated period (C1 note 1), so the fold starts over.
    from_start: bool,
    answered: bool,
    /// The relay refused to send names.
    refused: bool,
    /// An answer came since a voice room last folded (voice.rs): a fold that waited for its
    /// lists goes again, though no header was taken.
    pub(super) fresh: bool,
}

impl Default for Names {
    fn default() -> Names {
        Names {
            floor: None,
            gen: [0; 16],
            lists: BTreeMap::new(),
            removals: Vec::new(),
            gone: None,
            gated_start: None,
            parts: Parts::new(Seq::Names),
            asked: None,
            last: None,
            asked_removals: false,
            from_start: false,
            answered: false,
            refused: false,
            fresh: false,
        }
    }
}

impl Names {
    /// A header taken: its list, a removal, and where a gated period starts.
    pub(super) fn header_taken(
        &mut self,
        h: &SignedHeader,
        prev: Option<&crate::group_key::Floor>,
    ) {
        let hd = h.header();
        if hd.gen != self.gen {
            self.gen = hd.gen;
            self.lists.clear();
            self.removals.clear();
            self.gated_start = None;
            self.gone = None;
            self.from_start = false;
            self.refused = false;
        }
        let was_gated = prev.is_some_and(|f| f.gen == hd.gen && f.gated);
        if hd.gated && hd.kind.opens_epoch() && !was_gated {
            self.gated_start = Some(hd.epoch);
            self.refused = false;
        }
        if hd.gated {
            self.lists.insert((hd.epoch, hd.join), NamesList::of(hd));
        }
        if hd.kind.opens_epoch() && matches!(&hd.removed, Removed::List(l) if !l.is_empty()) {
            self.removals.push(h.clone());
        }
        if self.floor.is_none() {
            // Where a device with no names floor starts, fetching nothing before it
            self.floor = Some(NamesFloor::of(hd));
        }
    }

    /// Where the fold starts (C1 note 1).
    fn from(&self, gen: &[u8; 16]) -> NamesFrom {
        let floor = self.floor.filter(|f| {
            !self.from_start
                && f.gen == *gen
                && f.names_hash != [0; 32]
                && self.gated_start.is_none_or(|s| (f.epoch, f.join) >= (s, 0))
        });
        match (floor, self.gone) {
            (Some(floor), Some(step)) => NamesFrom::Gone { floor, step },
            (Some(f), None) => NamesFrom::Floor(f),
            (None, _) => NamesFrom::Start,
        }
    }

    /// One part of `EpochNamesIn`: the whole once its last part is in.
    pub(super) fn part_in(
        &mut self,
        part: u16,
        last: bool,
        piece: &NamesPiece,
    ) -> Option<Vec<NamesPiece>> {
        let bytes = postcard::experimental::serialized_size(piece).unwrap_or(usize::MAX);
        let took = self.parts.take((), part, last, piece.clone(), bytes);
        if took.dropped.is_some() {
            self.asked = None;
        }
        match took.part {
            Part::Whole((), parts) => Some(parts),
            _ => None,
        }
    }

    /// The relay refused names for good (`NOT_MEMBER`, `OFF`): no more asks this gated period.
    pub(super) fn refused(&mut self) {
        self.asked = None;
        self.refused = true;
    }

    /// The relay refused names for now (`RATE`, or `NOT_GATED` from a head the gate since
    /// turned on again): asked again after `CHECK_WAIT_MS`, like an unanswered ask.
    pub(super) fn paced(&mut self, now: u64) {
        self.asked = Some(now);
    }

    /// The head epoch's opening header, met in an answer (`EpochIn.opening`) and checked
    /// against the head: where it turned the gate on (its `names_hash` one step from 0³²,
    /// §11.3), the fold from the start begins at its list, which this device may never have
    /// taken as a head.
    pub(super) fn opening_seen(&mut self, o: &SignedHeader) {
        let hd = o.header();
        if !hd.gated || hd.gen != self.gen || !hd.kind.opens_epoch() {
            return;
        }
        let list = NamesList::of(hd);
        if names_start(&list) != hd.names_hash {
            return;
        }
        if self.gated_start.is_none_or(|s| s < hd.epoch) {
            self.gated_start = Some(hd.epoch);
        }
        self.lists.entry((hd.epoch, hd.join)).or_insert(list);
    }
}

/// `EpochNamesIn`: lists, removals and a "gone" step. Pushed gated Joins come back as an
/// `EpochIn` chain for the member to take like any header.
pub(super) fn names_in(m: &mut Member, pieces: Vec<NamesPiece>) -> Option<gk::InPiece> {
    let n = &mut m.names;
    n.asked = None;
    n.answered = true;
    n.refused = false;
    n.fresh = true;
    let mut joins = Vec::new();
    for p in pieces {
        for l in &p.lists {
            if let Ok(list) = NamesList::try_from(l) {
                n.lists.insert((list.epoch, list.join), list);
            }
        }
        if let Some(step) = p.gone {
            n.gone = Some(NamesStep::from(step));
        }
        for r in &p.removals {
            if r.check().is_err() {
                continue;
            }
            let Ok(h) = check_form(&r.body, &r.sig, m.t.kind, &m.t.group) else {
                continue;
            };
            // A removal counts only signed by a keyholder set this device holds
            let signed = m
                .kh_seen
                .get(&h.header().kh_parent)
                .is_some_and(|set| check_signer(&h, Some(set), &|_| None).is_ok());
            let hd = h.header();
            if signed && hd.gen == n.gen && hd.kind.opens_epoch() && !n.removals.contains(&h) {
                n.removals.push(h);
            }
        }
        joins.extend(p.joins);
    }
    (!joins.is_empty()).then(|| gk::InPiece {
        chain: joins,
        pushed: true,
        ..Default::default()
    })
}

/// Asks for the lists from where the fold starts to the head, and with `removals` the
/// opening headers between that remove someone. At most one out, again after 10 s; the same
/// ask again after 10 s too, answered or not: its answer would come back the same, and a fold
/// it did not settle (a voice room folds at every answer) would ask once per round trip.
fn ask(m: &mut Member, removals: bool, c: &GkCtx, out: &mut GkOut) {
    let Some(head) = m.head.as_ref() else {
        return;
    };
    let hd = head.header();
    let n = &mut m.names;
    let recent = |at: u64| c.now < at.saturating_add(CHECK_WAIT_MS);
    if n.asked.is_some_and(recent) || n.refused {
        return;
    }
    // From the names floor, or from the generation's start (epoch 0)
    let from = match n.from(&hd.gen) {
        NamesFrom::Floor(f) | NamesFrom::Gone { floor: f, .. } => gk::NamesRef {
            gen: f.gen,
            epoch: f.epoch,
            join: f.join,
        },
        NamesFrom::Start => gk::NamesRef {
            gen: hd.gen,
            epoch: n.gated_start.map_or(0, |s| s.saturating_sub(1)),
            join: 0,
        },
    };
    let to = gk::NamesRef {
        gen: hd.gen,
        epoch: hd.epoch,
        join: hd.join,
    };
    let this = (from, to, removals);
    if n.last.is_some_and(|(last, at)| last == this && recent(at)) {
        return;
    }
    n.asked = Some(c.now);
    n.last = Some((this, c.now));
    n.asked_removals |= removals;
    out.send.push(ClientMessage::EpochNames {
        group: m.t.group.clone(),
        from,
        to,
        removals,
    });
}

/// The fold before a post in a gated group (3f).
pub(super) fn fold(m: &mut Member, who: &Who, c: &mut GkCtx, out: &mut GkOut) -> Folded {
    let Some(head) = m.head.clone() else {
        return Folded::Wait;
    };
    let hd = head.header();
    if !hd.gated {
        m.names.floor = Some(NamesFloor::of(hd));
        return Folded::Ok;
    }
    let from = m.names.from(&hd.gen);
    let after = match from {
        NamesFrom::Floor(f) => Some((f.epoch, f.join)),
        NamesFrom::Gone { step, .. } => Some((step.epoch, step.join)),
        NamesFrom::Start => None,
    };
    let start = m.names.gated_start.unwrap_or(0);
    let lists: Vec<NamesList> = m
        .names
        .lists
        .iter()
        .filter(|(at, _)| match after {
            Some(a) => **at > a,
            None => at.0 >= start,
        })
        .filter(|(at, _)| **at <= (hd.epoch, hd.join))
        .map(|(_, l)| l.clone())
        .collect();
    let folded = {
        let pins = &*c.pins;
        let pin_then = |a: &[u8; 16], t: u64| pins.pin_then(a, t);
        let counters = |a: &[u8; 16]| pins.seen(a);
        let known = Known {
            pins: &pin_then,
            counters: &counters,
            own: who.account,
            now: c.secs(),
        };
        fold_names(&from, &lists, &m.names.removals, hd, &known)
    };
    let show = m.t.shows_names();
    match folded {
        Ok(Fold::Take {
            floor,
            shown,
            warnings,
        }) => {
            moved(m, floor, who, out);
            readers(m, &shown, show, out);
            warn(m, &warnings, out);
            // Counters met at a fold: a text seat's entry is its vault seat (0x01)
            if m.t.kind == GroupKind::Text {
                for a in shown.named.iter().filter(|a| !shown.unchecked.contains(a)) {
                    if let Some(account) = a.m.account() {
                        let seen = crate::group_key::Seen {
                            n: a.n,
                            made: a.made,
                        };
                        c.pins.raise(account, seen, true);
                    }
                }
            }
            Folded::Ok
        }
        Ok(Fold::Hold {
            why,
            floor,
            shown,
            warnings,
        }) => {
            if let Some(f) = floor {
                moved(m, f, who, out);
            }
            readers(m, &shown, show, out);
            warn(m, &warnings, out);
            if !m.names.asked_removals {
                ask(m, true, c, out);
            }
            let why = match why {
                Held::Guest(_) => HeldWhy::Guest,
                Held::Pin(_) => HeldWhy::Pin,
                Held::Counter { seat, .. } => HeldWhy::OldCounter(show.then_some(seat.m)),
            };
            m.tell(GkState::Held(why), out);
            Folded::Held(why)
        }
        Err(Refusal::Names) if m.names.answered && !m.names.from_start => {
            m.names.from_start = true;
            m.names.answered = false;
            ask(m, false, c, out);
            Folded::Wait
        }
        Err(why) => {
            tracing::debug!(group = %m.t.group, ?why, "names do not fold yet");
            m.names.answered = false;
            ask(m, false, c, out);
            Folded::Wait
        }
    }
}

/// The names floor moved: lists at or before it are done with, and it is kept (3d).
fn moved(m: &mut Member, floor: NamesFloor, who: &Who, out: &mut GkOut) {
    let n = &mut m.names;
    if n.floor == Some(floor) {
        return;
    }
    n.floor = Some(floor);
    n.lists.retain(|at, _| *at > (floor.epoch, floor.join));
    n.from_start = false;
    n.gone = None;
    n.asked_removals = false;
    m.save_names(who, out);
}

fn readers(m: &Member, shown: &crate::group_key::Shown, show: bool, out: &mut GkOut) {
    if shown.named.is_empty() && !shown.older_unnamed {
        return;
    }
    let checked: Vec<_> = shown
        .named
        .iter()
        .filter(|a| !shown.unchecked.contains(a))
        .map(|a| a.m)
        .collect();
    let (named, unchecked) = if show {
        (checked, shown.unchecked.len())
    } else {
        (Vec::new(), shown.named.len())
    };
    out.events.push(GkEvent::Readers {
        channel_id: m.t.channel_id,
        named,
        unchecked: unchecked as u32,
        older_unnamed: shown.older_unnamed,
    });
}

fn warn(m: &Member, warnings: &[Warning], out: &mut GkOut) {
    for w in warnings {
        if let Warning::OldOwnSeat { n, .. } = w {
            out.events.push(GkEvent::Warning {
                channel_id: m.t.channel_id,
                kind: Warn::OldSeatKey,
                n: *n,
            });
        }
    }
}

/// An ask nobody answered goes again at the next fold.
pub(super) fn tick(m: &mut Member, c: &GkCtx) {
    if m.names
        .asked
        .is_some_and(|at| c.now >= at.saturating_add(CHECK_WAIT_MS))
    {
        m.names.asked = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group_key::build::world::World;
    use crate::group_key::commit::{Due, DueKind};
    use crate::group_key::Floor;

    fn take(n: &mut Names, h: &SignedHeader, floor: &mut Option<Floor>) {
        n.header_taken(h, floor.as_ref());
        *floor = Some(Floor::after(floor.as_ref(), h, h.header().time));
    }

    /// C1 note 1: a names floor from an earlier gated period of the generation (gated → open
    /// → gated) has no chain to the head, so the fold starts over; one taken in the current
    /// period folds from itself, and one of another generation from the start.
    #[test]
    fn a_names_floor_from_an_earlier_gated_period_folds_from_the_start() {
        let mut w = World::text(false, true);
        let mut n = Names::default();
        let mut floor = None;
        take(&mut n, &w.head.clone(), &mut floor);
        let gen = w.head.header().gen;
        let first = n.floor.expect("set at the first header taken");
        assert_eq!(n.from(&gen), NamesFrom::Floor(first));
        for gated in [false, true] {
            let due = Due {
                gated,
                ..w.due(DueKind::Gate)
            };
            w.open(&due);
            take(&mut n, &w.head.clone(), &mut floor);
        }
        assert_eq!(n.gated_start, Some(w.head.header().epoch));
        assert_eq!(n.from(&gen), NamesFrom::Start, "an earlier gated period");
        n.floor = Some(NamesFloor::of(w.head.header()));
        assert_eq!(n.from(&gen), NamesFrom::Floor(n.floor.unwrap()));
        assert_eq!(n.from(&[9; 16]), NamesFrom::Start, "another generation");
    }

    /// Finding: a member that never took the opening turning the gate on (it goes only to
    /// writers) folded from the start without its list. The head epoch's opening in an
    /// answer gives it: where the fold starts, and its list.
    #[test]
    fn the_gate_on_opening_met_in_an_answer_starts_the_fold() {
        use crate::group_key::{Counters, PinThen, PinsAt};
        let mut w = World::text(false, false);
        let mut n = Names::default();
        let mut floor = None;
        take(&mut n, &w.head.clone(), &mut floor);
        let due = Due {
            gated: true,
            ..w.due(DueKind::Gate)
        };
        w.open(&due);
        let o = w.head.clone();
        let late = crate::group_key::build::world::Member::account(9);
        w.join(&[&late]);
        let j = w.head.clone();
        // Only the Join is taken
        n.header_taken(&j, floor.as_ref());
        let gen = j.header().gen;
        assert_eq!(n.gated_start, None);
        let pins: PinsAt = &|_, _| PinThen::None;
        let counters: Counters = &|_| None;
        let known = Known {
            pins,
            counters,
            own: None,
            now: j.header().time,
        };
        let lists = |n: &Names| n.lists.values().cloned().collect::<Vec<_>>();
        assert!(fold_names(&n.from(&gen), &lists(&n), &[], j.header(), &known).is_err());
        n.opening_seen(&o);
        assert_eq!(n.gated_start, Some(o.header().epoch));
        assert!(fold_names(&n.from(&gen), &lists(&n), &[], j.header(), &known).is_ok());
    }
}
