//! Voice key material from the room's `CK` (part 5, `GkOut::voice`). V1 writes the body; this
//! stub hands out none.

use super::member::Member;
use super::{GkOut, Who};

/// This connection's voice keys.
#[derive(Default)]
pub(super) struct Voice {}

impl Voice {
    /// A header was taken in a room (`m.keys` may have moved).
    pub(super) fn epoch_taken(&mut self, _who: &Who, _m: &Member, _now: u64, _out: &mut GkOut) {}

    /// The room's seats moved (`m.voice_seats`).
    pub(super) fn seats_in(&mut self, _who: &Who, _m: &Member, _out: &mut GkOut) {}
}
