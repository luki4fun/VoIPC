//! Kept history under the group key (part 4): past epochs taken for reading (C1's
//! `take_past`), history rows, and re-sealing self-rows at a seat-key rotation. K1 writes
//! the body; this stub takes no past epoch.

use std::collections::BTreeMap;

use voipc_protocol::gk::{InPiece, SelfRowIn};

use super::member::Member;
use super::{GkCtx, GkEpoch, GkOut, Who};

/// A past epoch's key as a reader of kept history asks for it.
pub enum PastEpoch {
    Ready(GkEpoch),
    /// Asked: `GkOut::past_ready` says when it is in.
    Asked,
    /// Not to be had here.
    Unknown,
}

/// What this connection holds of kept history.
#[derive(Default)]
pub(super) struct Kept {}

impl Kept {
    /// An `EpochIn` with `past`: never a head, the floor never moves for it.
    pub(super) fn past_in(
        &mut self,
        _who: &mut Who,
        _m: &mut Member,
        _p: &InPiece,
        _c: &mut GkCtx,
        _out: &mut GkOut,
    ) {
    }

    /// History rows (and self-rows of an older seat) an `EpochIn` brought.
    pub(super) fn history_rows(
        &mut self,
        _who: &mut Who,
        _m: &mut Member,
        _rows: &[SelfRowIn],
        _out: &mut GkOut,
    ) {
    }

    /// A past epoch the member does not hold.
    pub(super) fn past_epoch(
        &mut self,
        _who: &mut Who,
        _m: &mut Member,
        _gen: [u8; 16],
        _epoch: u32,
    ) -> PastEpoch {
        PastEpoch::Unknown
    }

    /// The account's seat keys rotated: history rows and re-sealed self-rows (§5.11 step 2).
    pub(super) fn seat_keys_changed(
        &mut self,
        _who: &mut Who,
        _groups: &mut BTreeMap<String, Member>,
        _out: &mut GkOut,
    ) {
    }
}
