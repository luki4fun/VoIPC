//! A gated group's names on the relay (plan 2d "Names"): each taken gated Join's `added`
//! list, the list of each header a fold may start from (a Genesis, a Regenesis, the opening
//! that turned `gated` on: §11.3, plan 2g "the gate-on opening is both 0 and 1"), and each
//! opening header that carries a `removed` list, kept `NAMES_KEPT` by the relay's clock, with
//! the step before the oldest list kept (a "gone" answer, §4.4 rule 4). A `removed` list
//! steps `names_hash` as an `added` one does, so such a header is a step of its own, and its
//! list goes bare among the others, `removed` and all: 33 B a seat and its place, as §8
//! counts an exit. Stored groups keep the same in `voipc_gk_names` and load it back (2e
//! "state is in the store").
//!
//! `EpochNames.from` is the writer's names floor, which it has folded already: the relay
//! answers from it inclusive (a list at `from` itself is one the writer skips), so a fold
//! from the start may ask from `(gated_start - 1, 0)` or `(0, 0)` (C3b names.rs says the
//! same).

use std::collections::BTreeMap;

use voipc_crypto::group_key::{
    names_start, NamesList, NamesStep, Removed, SignedHeader, NAMES_KEPT,
};
use voipc_protocol::gk::{NamesListIn, NamesPiece, NamesRef, NamesStepIn};

/// One kept list: its generation, the list, and the header's `names_hash` (the hash after
/// it), from which the step before the oldest is made when it is swept.
#[derive(Clone, Debug)]
pub struct Kept {
    pub gen: [u8; 16],
    pub list: NamesListIn,
    pub hash: [u8; 32],
}

#[derive(Default)]
pub struct Names {
    /// Lists by generation, oldest first.
    lists: Vec<Kept>,
    /// Opening headers with a `removed` list, oldest first.
    removals: Vec<([u8; 16], SignedHeader)>,
    /// The step of the newest list swept that moved the hash (§4.4 rule 4 "gone").
    step: Option<([u8; 16], NamesStepIn)>,
    /// A step made by the last sweep, for a stored group to keep (`take_swept`).
    swept: Option<NamesStepIn>,
}

fn at(gen: &[u8; 16], epoch: u32, join: u32, r: &NamesRef) -> bool {
    *gen == r.gen && (epoch, join) >= (r.epoch, r.join)
}

fn upto(epoch: u32, join: u32, r: &NamesRef) -> bool {
    (epoch, join) <= (r.epoch, r.join)
}

/// Whether `h`'s list is one a fold steps from 0³² (§11.3): a Genesis, or a gated opening
/// whose parent was open (`was_gated` false), a Regenesis of one included.
pub fn starts_names(h: &SignedHeader, was_gated: bool) -> bool {
    let hd = h.header();
    hd.gated && (hd.kind.starts_anew() || (hd.kind.opens_epoch() && !was_gated))
}

impl Names {
    /// Keeps what a taken header of a gated group names; the list of a Join, for its push.
    /// `was_gated`: the head before it was gated, in its generation.
    pub fn take(&mut self, sh: &SignedHeader, was_gated: bool) -> Option<NamesListIn> {
        let h = sh.header();
        if !h.gated {
            return None;
        }
        if let Removed::List(l) = &h.removed {
            if !l.is_empty() {
                self.removals.push((h.gen, sh.clone()));
            }
        }
        if h.kind.opens_epoch() && !starts_names(sh, was_gated) {
            return None;
        }
        let list = NamesListIn::from(&NamesList::of(h));
        self.keep(Kept {
            gen: h.gen,
            list: list.clone(),
            hash: h.names_hash,
        });
        Some(list)
    }

    fn keep(&mut self, k: Kept) {
        if !self
            .lists
            .iter()
            .any(|x| x.gen == k.gen && (x.list.epoch, x.list.join) == (k.list.epoch, k.list.join))
        {
            self.lists.push(k);
            self.lists.sort_by_key(|x| (x.list.epoch, x.list.join));
        }
    }

    /// What a stored group kept (`store.load`): lists, removal headers, the step.
    pub fn restore(
        &mut self,
        lists: Vec<Kept>,
        removals: Vec<([u8; 16], SignedHeader)>,
        step: Option<([u8; 16], NamesStepIn)>,
    ) {
        for k in lists {
            if step.as_ref().is_some_and(|(g, s)| {
                *g == k.gen && (k.list.epoch, k.list.join) <= (s.epoch, s.join)
            }) {
                continue;
            }
            self.keep(k);
        }
        self.removals.extend(removals);
        self.removals
            .sort_by_key(|(_, h)| (h.header().epoch, h.header().join));
        self.step = step;
    }

    /// Every list of `gen` this relay holds that `keep` takes by its place, in order, each
    /// with the hash after it: the kept lists, and the headers carrying `removed`, whose
    /// list (`removed` and all, as it steps the hash) stands over a kept one at its place
    /// (a start header that removes seats is both).
    fn merged(
        &self,
        gen: &[u8; 16],
        keep: impl Fn(u32, u32) -> bool,
    ) -> BTreeMap<(u32, u32), (NamesListIn, [u8; 32])> {
        let mut all = BTreeMap::new();
        for k in self.lists.iter().filter(|k| k.gen == *gen) {
            if keep(k.list.epoch, k.list.join) {
                all.insert((k.list.epoch, k.list.join), (k.list.clone(), k.hash));
            }
        }
        for (_, h) in self.removals.iter().filter(|(g, _)| g == gen) {
            let hd = h.header();
            if keep(hd.epoch, hd.join) {
                let list = NamesListIn::from(&NamesList::of(hd));
                all.insert((hd.epoch, hd.join), (list, hd.names_hash));
            }
        }
        all
    }

    /// Every step of `gen`'s hash this relay holds, in order, each with the hash after it.
    fn steps(&self, gen: &[u8; 16]) -> Vec<(NamesList, [u8; 32])> {
        self.merged(gen, |_, _| true)
            .into_values()
            .filter_map(|(l, hash)| Some((NamesList::try_from(&l).ok()?, hash)))
            .collect()
    }

    /// Drops what is older than `NAMES_KEPT` at `now` (unix s), and another generation's;
    /// the step of the newest list dropped that moved the hash is kept for "gone" answers.
    pub fn sweep(&mut self, gen: &[u8; 16], now: u64) {
        let floor = now.saturating_sub(NAMES_KEPT);
        if self.step.as_ref().is_some_and(|(g, _)| g != gen) {
            self.step = None;
        }
        let mut before = self
            .step
            .as_ref()
            .map_or([0; 32], |(_, s)| NamesStep::from(*s).hash());
        let mut made = None;
        for (list, hash) in self.steps(gen) {
            if list.time >= floor {
                break;
            }
            let start = names_start(&list) == hash;
            if start || hash != before {
                let from = if start { [0; 32] } else { before };
                made = Some(NamesStepIn::from(&list.step_from(&from)));
            }
            before = hash;
        }
        self.lists.retain(|k| k.gen == *gen && k.list.time >= floor);
        self.removals
            .retain(|(g, h)| g == gen && h.header().time >= floor);
        if let Some(s) = made {
            self.step = Some((*gen, s));
            self.swept = Some(s);
        }
    }

    /// Where the step before the oldest list kept stands in `gen`: names before it may go
    /// from the database.
    pub fn step_at(&self, gen: &[u8; 16]) -> Option<(u32, u32)> {
        self.step
            .as_ref()
            .filter(|(g, _)| g == gen)
            .map(|(_, s)| (s.epoch, s.join))
    }

    /// The step the last sweep made, once (a stored group keeps it, kind 2).
    pub fn take_swept(&mut self) -> Option<NamesStepIn> {
        self.swept.take()
    }

    /// The lists from `from` to `to`, the openings between that remove seats among them;
    /// "gone" with the step before the oldest kept list when `from` lies before that step
    /// (lists it needs were swept).
    pub fn answer(&self, from: &NamesRef, to: &NamesRef) -> NamesPiece {
        let gone = self
            .step
            .as_ref()
            .filter(|(g, s)| *g == from.gen && (from.epoch, from.join) < (s.epoch, s.join))
            .map(|(_, s)| *s);
        let lists = self.merged(&from.gen, |epoch, join| {
            at(&from.gen, epoch, join, from) && upto(epoch, join, to)
        });
        NamesPiece {
            lists: lists.into_values().map(|(l, _)| l).collect(),
            gone,
            ..NamesPiece::default()
        }
    }
}
