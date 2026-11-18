//! Keyholder duty (3g): volunteering, dues, commits built off the lock and paced out, the
//! keyring. C3c writes the body; this stub holds no keys and builds nothing. Every input
//! and output it needs comes through `GroupKeying` already (mod.rs is not edited after C3b).

use std::collections::BTreeMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use voipc_protocol::messages::{ClientMessage, ServerMessage};

use super::member::Member;
use super::{GkCtx, GkOut, Who};

/// What a keyholder keeps on this device (3d `gk_local.bin`: its pair, the old one until its
/// Replace is done, the seats it sealed that no header named yet).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HolderKeep {}

/// A commit to build off the `SignalState` lock: owned and `Send`.
pub struct BuildJob {
    _job: (),
}

impl BuildJob {
    /// Works on for at most `budget`; the job finished or failed once it says so.
    pub fn step(&mut self, _budget: Duration) -> Option<Built> {
        None
    }
}

/// A finished or failed job, for `GroupKeying::built`.
pub struct Built {
    _built: (),
}

/// This connection's keyholder duty, across its groups.
#[derive(Default)]
pub(super) struct Duty {}

impl Duty {
    /// At `GroupKeys`: a volunteer offers itself (`KeyholdVolunteer`).
    pub(super) fn start(&mut self, _who: &mut Who, _out: &mut GkOut) {}

    /// `EpochDue`, `EpochStale`, `EpochLists`, `KeyringIn`.
    pub(super) fn frame(
        &mut self,
        _who: &mut Who,
        _groups: &mut BTreeMap<String, Member>,
        _msg: &ServerMessage,
        _c: &mut GkCtx,
        _out: &mut GkOut,
    ) {
    }

    /// Whether this device holds keys in `group`: it then reads every name it takes.
    pub(super) fn holds(&self, _group: &str) -> bool {
        false
    }

    /// The `KX` of this device's own entry in `group`, if it holds one.
    pub(super) fn own_kx(&self, _group: &str) -> Option<[u8; 32]> {
        None
    }

    pub(super) fn tick(
        &mut self,
        _who: &mut Who,
        _groups: &mut BTreeMap<String, Member>,
        _c: &mut GkCtx,
        _out: &mut GkOut,
    ) {
    }

    pub(super) fn next_frame(&mut self, _now: u64, _in_call: bool) -> Option<ClientMessage> {
        None
    }

    pub(super) fn take_build(&mut self) -> Option<BuildJob> {
        None
    }

    pub(super) fn built(
        &mut self,
        _who: &mut Who,
        _groups: &mut BTreeMap<String, Member>,
        _b: Built,
        _c: &mut GkCtx,
        _out: &mut GkOut,
    ) {
    }

    pub(super) fn set_volunteer(
        &mut self,
        _who: &mut Who,
        _groups: &mut BTreeMap<String, Member>,
        _on: bool,
        _out: &mut GkOut,
    ) {
    }

    /// The account's seat keys rotated: a desktop keyholder replaces its pair (§5.11).
    pub(super) fn seat_keys_changed(
        &mut self,
        _who: &mut Who,
        _groups: &mut BTreeMap<String, Member>,
        _out: &mut GkOut,
    ) {
    }

    pub(super) fn visibility(
        &mut self,
        _who: &mut Who,
        _groups: &mut BTreeMap<String, Member>,
        _visible: bool,
        _in_call: bool,
        _out: &mut GkOut,
    ) {
    }

    pub(super) fn untrack(&mut self, _group: &str) {}

    pub(super) fn end(&mut self, _who: &mut Who, _out: &mut GkOut) {}
}
