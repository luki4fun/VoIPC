//! Taking a header (§4.4), the rollback floor (§5.7), a writer's fold of the
//! gated names (§4.4 rule 4) and the seed rolls (§5.6), as pure functions
//! over what a member, writer or keyholder holds: its floor, the headers the
//! relay sent, its pins and the highest counters it has seen. Each function
//! is one rule; the client (C3) runs them in order and keeps the state, and
//! the relay's validator (C2) runs the ones it names.
//!
//! What they promise between them, against a relay that sends anything:
//! - no header is taken that its group's keyholders did not sign, that sits
//!   at or below the floor, that runs further in epochs than the elapsed time
//!   allows, that counts guests or names a guest keyholder in a gated group,
//!   that is more than 10 minutes ahead, that changes the seed in a way its
//!   kind may not, that swaps a keyholder entry other than its signer's own,
//!   or that names a keyholder entry with an old counter of an account whose
//!   newer one this device saw before that header was made;
//! - no writer posts in a gated group before every `added` list since its
//!   names floor folds to the head's `names_hash`, each list at its own
//!   header's `time`, `epoch` and `join`, and every entry in them passed the
//!   guest, pin and counter checks as they stood at that time, or was removed
//!   by a later opening header;
//! - no Regenesis is taken sooner after its parent than its set in force
//!   allows (`regenesis_wait`: an hour, or two minutes for a set of
//!   connection entries alone that no Regenesis started in the last hour), or
//!   after a parent that is not genuine and at or above the floor; a device
//!   that holds a floor and cannot see the set in force waits the hour; and
//!   no generation is taken that this device took already, or that began
//!   before it last saw the group.
//!
//! Members take headers without the names (owner, 2026-11-17): only writers
//! fold them, keyholders check each list they take, and every member of a
//! gated voice room folds the Join headers as they come.

use serde::{Deserialize, Serialize};

use super::ctx::{MemberId, SeatRef};
use super::header::{
    AddedSeat, HeaderV1, Keyholder, Kind, NamesList, NamesStep, Removed, SignedHeader,
    MAX_KEYHOLDERS,
};
use super::keys::{Holder, Origin};
use super::merkle::{Leaf, Via};
use super::{
    GkError, CLOCK_SLACK, EPOCH_MIN_GAP, LIVE_WINDOW, MAX_WALK, RECENT_GENS, REGENESIS_FAST_GAP,
    REGENESIS_FAST_WAIT, REGENESIS_WAIT,
};
use crate::group_key::ctx::GroupKind;

/// Why a member refuses a header: what its app tells its user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Rule 1: not the one encoding of a well-formed header.
    Form(&'static str),
    /// Rule 1: another group, or another kind of group.
    WrongGroup,
    /// Rule 1 or 2: `S ≥ ℓ`, or not its signer's signature.
    Signature,
    /// Rule 2: the signer holds no entry in the set it must be in.
    NotKeyholder,
    /// Rule 2: the keyholder set changed in a way its kind does not allow.
    KeyholderChange(&'static str),
    /// An identity key that is not the one pinned for its account.
    Pin(MemberId),
    /// Rule 3: does not follow from its parent.
    Chain(&'static str),
    /// §5.7: at or below the floor within its generation.
    BelowFloor,
    /// Rule 3: a walked header further in epochs than the time allows.
    EpochBound,
    /// Rule 3: the keyholder chain does not lead back to the floor.
    Walk(&'static str),
    /// Rule 4: the lists do not fold from where the fold starts to the
    /// head's `names_hash`, or come out of order. That is the relay's doing
    /// (`fold_names` itself starts afresh where the names floor has no chain
    /// to the head): the writer asks again, and holds its posts meanwhile.
    Names,
    /// Rule 4: a "gone" answer the writer may not take: its names floor is
    /// not more than 90 days old, or the step before the tail is not.
    NamesNotGone,
    /// Rule 5: `CK_e` does not pass `confirm`.
    Confirm,
    /// Rule 6: `gated` changed on a Join header.
    GatedChanged,
    /// Rule 6: a guest seat, or connection seats, in a gated group. It
    /// names the seat where there is one: a keyholder takes the next opening
    /// header that names it in `removed`.
    GuestSeat(Option<SeatRef>),
    /// Rule 6: a guest keyholder in a gated group.
    GuestKeyholder,
    /// Rule 7: more than `CLOCK_SLACK` ahead of this device's clock.
    Ahead,
    /// Rule 8: a counter below the highest seen for that account, in a
    /// header made after that newer endorsement. `own`: the account is this
    /// device's own, and its app warns that an old seat key of this account
    /// was seated.
    OldCounter {
        account: [u8; 16],
        n: u32,
        highest: u32,
        own: bool,
    },
    /// §5.7: a generation this device may not take.
    Generation(&'static str),
    /// §5.9: a voice keyholder that is not among the lowest user ids.
    VoiceKeyholder(u32),
    /// §5.6, the relay's validator: a seed raised where no roll may start.
    Roll(&'static str),
    /// §4.3: bucket versions its kind does not make.
    Versions(&'static str),
}

/// For a log, or an `EpochDecline`'s detail: what broke, never a key.
impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::Form(why) => write!(f, "form: {why}"),
            Refusal::WrongGroup => f.write_str("another group"),
            Refusal::Signature => f.write_str("not its signer's signature"),
            Refusal::NotKeyholder => f.write_str("signed by no keyholder of its set"),
            Refusal::KeyholderChange(why) => write!(f, "keyholders: {why}"),
            Refusal::Pin(_) => f.write_str("an identity key not the one pinned"),
            Refusal::Chain(why) => write!(f, "chain: {why}"),
            Refusal::BelowFloor => f.write_str("at or below the floor"),
            Refusal::EpochBound => f.write_str("further in epochs than the time allows"),
            Refusal::Walk(why) => write!(f, "walk: {why}"),
            Refusal::Names => f.write_str("the names do not fold to the head"),
            Refusal::NamesNotGone => f.write_str("a names answer of gone too early"),
            Refusal::Confirm => f.write_str("the epoch key does not confirm"),
            Refusal::GatedChanged => f.write_str("gated changed on a Join"),
            Refusal::GuestSeat(_) => f.write_str("a guest seat in a gated group"),
            Refusal::GuestKeyholder => f.write_str("a guest keyholder in a gated group"),
            Refusal::Ahead => f.write_str("ahead of this device's clock"),
            Refusal::OldCounter { n, highest, .. } => {
                write!(f, "seat-key counter {n} below the highest seen, {highest}")
            }
            Refusal::Generation(why) => write!(f, "generation: {why}"),
            Refusal::VoiceKeyholder(u) => write!(f, "voice keyholder {u} not among the lowest"),
            Refusal::Roll(why) => write!(f, "seed roll: {why}"),
            Refusal::Versions(why) => write!(f, "versions: {why}"),
        }
    }
}

/// What a member takes but tells its user about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Warning {
    /// Rule 6: a gated group turned open at this opening header.
    GatedTurnedOff,
    /// Rule 8: this device's own account is named with counter `n`, below
    /// its own counter `own`, in a header made after its newer endorsement:
    /// an old seat key of this account was seated.
    OldOwnSeat { n: u32, own: u32 },
}

// ── Floors (§5.7) ─────────────────────────────────────────────────────────

/// A member's floor in one group: the newest header it took.
///
/// §5.7 lists `(gen, gen_time, epoch, join, D, D_e, kh, time)` and the last
/// 8 generation ids. Two more are kept here: `gated`, which rule 6 needs to
/// see a gated group turn open, and each remembered generation's `gen_time`,
/// without which two devices' lists cannot be joined "keeping the newest 8".
/// The names are not in it: a writer keeps its `NamesFloor` beside it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Floor {
    pub gen: [u8; 16],
    pub gen_time: u64,
    pub epoch: u32,
    pub join: u32,
    pub d: [u8; 32],
    pub d_e: [u8; 32],
    pub kh: [u8; 32],
    pub time: u64,
    pub gated: bool,
    /// The last generations taken, newest `gen_time` last, at most 8, the
    /// current one among them.
    pub gens: Vec<([u8; 16], u64)>,
}

impl Floor {
    /// The floor after taking `h`. `gen_time` is the `time` of `h`'s
    /// generation's Genesis: kept from `prev` within one generation. A device
    /// that took a Regenesis on trust never saw the Genesis, and passes the
    /// Regenesis's own `time`, which is no earlier.
    pub fn after(prev: Option<&Floor>, h: &SignedHeader, gen_time: u64) -> Floor {
        let hd = h.header();
        let gen_time = match prev {
            Some(p) if p.gen == hd.gen => p.gen_time,
            _ => gen_time,
        };
        let mut gens = prev.map(|p| p.gens.clone()).unwrap_or_default();
        gens.retain(|(g, _)| *g != hd.gen);
        gens.push((hd.gen, gen_time));
        newest(&mut gens);
        Floor {
            gen: hd.gen,
            gen_time,
            epoch: hd.epoch,
            join: hd.join,
            d: h.d(),
            d_e: h.d_e(),
            kh: h.kh(),
            time: hd.time,
            gated: hd.gated,
            gens,
        }
    }

    /// Whether this floor is above `other` by §5.7's order: the generation
    /// with the later `gen_time`, and within one generation the higher
    /// `(epoch, join)`.
    pub fn above(&self, other: &Floor) -> bool {
        if self.gen == other.gen {
            (self.epoch, self.join) > (other.epoch, other.join)
        } else {
            self.gen_time > other.gen_time
        }
    }

    /// Two devices' floors (or the local and the vault floor) as one: the
    /// higher by `above`, with their generation lists joined and the newest
    /// 8 kept.
    pub fn merge(a: &Floor, b: &Floor) -> Floor {
        let mut out = if b.above(a) { b.clone() } else { a.clone() };
        let mut gens = a.gens.clone();
        for g in &b.gens {
            if !gens.iter().any(|(id, _)| *id == g.0) {
                gens.push(*g);
            }
        }
        newest(&mut gens);
        out.gens = gens;
        out
    }

    pub fn took_gen(&self, gen: &[u8; 16]) -> bool {
        self.gen == *gen || self.gens.iter().any(|(g, _)| g == gen)
    }
}

fn newest(gens: &mut Vec<([u8; 16], u64)>) {
    gens.sort_by_key(|(_, t)| *t);
    let drop = gens.len().saturating_sub(RECENT_GENS);
    gens.drain(..drop);
}

/// This device's clock, and when it last took a header of the group by that
/// clock (`taken`, local floors only).
#[derive(Clone, Copy, Debug)]
pub struct Clock {
    pub now: u64,
    pub taken: Option<u64>,
}

impl Clock {
    /// Whether this device follows the group live: it took a header in the
    /// last 10 minutes.
    fn live(&self) -> bool {
        self.taken
            .is_some_and(|t| t <= self.now && self.now - t <= LIVE_WINDOW)
    }
}

/// Rule 7: `time` at most `CLOCK_SLACK` ahead of this device's clock.
pub fn check_time(h: &HeaderV1, now: u64) -> Result<(), Refusal> {
    if h.time > now.saturating_add(CLOCK_SLACK) {
        Err(Refusal::Ahead)
    } else {
        Ok(())
    }
}

/// Rule 1, `SignedHeader::decode` under its rule's name.
pub fn check_form(
    body: &[u8],
    sig: &[u8],
    kind: GroupKind,
    group: &str,
) -> Result<SignedHeader, Refusal> {
    SignedHeader::decode(body, sig, kind, group)
}

// ── Rule 2: the signer ────────────────────────────────────────────────────

/// The identity keys a pinned account must have.
pub type Pins<'a> = &'a dyn Fn(&[u8; 16]) -> Option<[u8; 32]>;

fn pinned(m: &MemberId, ik: &[u8; 32], pins: Pins) -> Result<(), Refusal> {
    match m.account().and_then(|a| pins(&a)) {
        Some(pin) if pin != *ik => Err(Refusal::Pin(*m)),
        _ => Ok(()),
    }
}

/// The entries of `set` for `m` whose `IK` signed `h`.
fn signed_by(h: &SignedHeader, set: &[Keyholder]) -> Result<[u8; 32], Refusal> {
    let mut entries = set.iter().filter(|k| k.m == h.header().signer).peekable();
    if entries.peek().is_none() {
        return Err(Refusal::NotKeyholder);
    }
    entries
        .find(|k| h.verify(&k.ik))
        .map(|k| k.ik)
        .ok_or(Refusal::Signature)
}

/// Rule 2: who signed `h`, under §4.3's rule for its kind. Returns the
/// signer's `IK`.
///
/// - Genesis and Regenesis: a volunteer, who is in the set it makes. Its
///   `IK` must match its pin where there is one; with none, the caller pins
///   it now (TOFU).
/// - Any other kind: a member of the set of `set`, the header `h.kh_parent`
///   names. A KeyholdersRemove's signer keeps an entry in the new set, and a
///   KeyholdersReplace is signed by the keyholder whose entry it swaps.
///
/// For the kinds that set keyholders the change itself is checked too
/// (`check_keyholder_change`), and every new entry's `IK` against its pin.
///
/// The signer is checked by its `IK` alone, as every header is: a device of
/// the same account, or a thief of its vault, signs as any of the account's
/// entries (§6, §7 Q11). What keeps such a header from doing harm is the
/// pair: the other keyholders open a Replace's keyring welcome only as from
/// the old pair (`Swap::maker`), and take no keyring that hands them a seed
/// or bucket key of its own (`check_carried`).
pub fn check_signer(
    h: &SignedHeader,
    set: Option<&SignedHeader>,
    pins: Pins,
) -> Result<[u8; 32], Refusal> {
    let hd = h.header();
    let ik = if hd.kind.starts_anew() {
        signed_by(h, &hd.keyholders)?
    } else {
        let set = set.ok_or(Refusal::NotKeyholder)?;
        if set.d() != hd.kh_parent || !set.header().kind.sets_keyholders() {
            return Err(Refusal::Chain("kh_parent names another header"));
        }
        let ik = signed_by(h, &set.header().keyholders)?;
        check_keyholder_change(&set.header().keyholders, hd)?;
        ik
    };
    pinned(&hd.signer, &ik, pins)?;
    for k in &hd.keyholders {
        pinned(&k.m, &k.ik, pins)?;
    }
    Ok(ik)
}

/// What a header that sets keyholders may do to the set before it (§4.3,
/// §5.6, §5.11):
/// - a KeyholdersAdd only adds;
/// - a KeyholdersRemove only drops, at least one entry, and its signer keeps
///   an entry: a keyholder never signs its own removal;
/// - a KeyholdersReplace swaps exactly one entry, its signer's own
///   (`replaced_entry`).
///
/// None passes 8.
pub fn check_keyholder_change(old: &[Keyholder], h: &HeaderV1) -> Result<(), Refusal> {
    let new = &h.keyholders;
    let bad = |why| Err(Refusal::KeyholderChange(why));
    if new.len() > MAX_KEYHOLDERS {
        return bad("more than 8 keyholders");
    }
    match h.kind {
        Kind::KeyholdersAdd => {
            if !old.iter().all(|k| new.contains(k)) || new.len() <= old.len() {
                return bad("a KeyholdersAdd only adds");
            }
        }
        Kind::KeyholdersRemove => {
            if !new.iter().all(|k| old.contains(k)) {
                return bad("a KeyholdersRemove only removes");
            }
            if new.len() >= old.len() {
                return bad("a KeyholdersRemove removes an entry");
            }
            if !new.iter().any(|k| k.m == h.signer) {
                return bad("a keyholder never signs its own removal");
            }
        }
        Kind::KeyholdersReplace => {
            replaced_entry(old, h)?;
        }
        _ => {}
    }
    Ok(())
}

/// The entry a KeyholdersReplace swaps out, and the one it puts in its
/// place (§4.3, §5.11).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Swap {
    pub old: Keyholder,
    pub new: Keyholder,
}

impl Swap {
    /// Who the Replace's keyring welcomes come from: the old pair, which
    /// proves to the other keyholders that the signer held it (§4.3). A
    /// keyholder opens its keyring welcome as from this holder and takes the
    /// keyring only if it opens; every other welcome and row, in and after
    /// the Replace, comes from the new pair.
    pub fn maker(&self) -> Result<Holder, GkError> {
        Holder::from_raw(self.old.m, &self.old.kx)
    }

    /// Whether this swap takes out the entry whose `KX` is `kx`. A device
    /// that finds its own entry swapped by a Replace it did not make warns
    /// its user and asks the relay to remove that entry (§5.11).
    pub fn swaps(&self, kx: &[u8; 32]) -> bool {
        self.old.kx == *kx
    }
}

/// §4.3, §5.11: a KeyholdersReplace swaps exactly one entry of the set
/// before it, the one its keyring welcomes name by its old `tag(KX)`, for one
/// with a higher counter and a new pair. Nothing else in the set changes.
///
/// - The swapped entry is the signer's: a keyholder replaces only its own
///   pair.
/// - The new entry keeps the member id, user id, origin and `IK`. §4.3 names
///   the first three; the `IK` is kept too, since a seat-key rotation changes
///   no identity key, and a Replace that brought a new `IK` into the set
///   would be a keyholder no one promoted.
/// - Only a desktop's keyholder pair (origin 0x03) is replaced: connection
///   keyholders do not rotate, their keys end with their connection (§5.11).
/// - The counter rises and both halves of the pair are new.
pub fn replaced_entry(old: &[Keyholder], h: &HeaderV1) -> Result<Swap, Refusal> {
    let bad = |why| Err(Refusal::KeyholderChange(why));
    if h.kind != Kind::KeyholdersReplace {
        return bad("not a KeyholdersReplace");
    }
    let gone: Vec<&Keyholder> = old.iter().filter(|k| !h.keyholders.contains(k)).collect();
    let came: Vec<&Keyholder> = h.keyholders.iter().filter(|k| !old.contains(k)).collect();
    let ([o], [n]) = (gone.as_slice(), came.as_slice()) else {
        return bad("a KeyholdersReplace swaps exactly one entry");
    };
    let (o, n) = (**o, **n);
    if o.m != h.signer {
        return bad("a KeyholdersReplace swaps its signer's own entry");
    }
    if (n.m, n.u, n.origin, n.ik) != (o.m, o.u, o.origin, o.ik) {
        return bad("a swapped entry keeps its member id, user id, origin and IK");
    }
    if o.origin != Origin::Desktop as u8 {
        return bad("only a desktop keyholder pair is replaced");
    }
    if n.n <= o.n {
        return bad("a swapped entry has a higher counter");
    }
    if n.kx == o.kx || n.tag_kk == o.tag_kk {
        return bad("a swapped entry has a new pair");
    }
    Ok(Swap { old: o, new: n })
}

/// §5.9: in a voice group, a KeyholdersAdd or a Genesis whose new keyholder
/// is not among the 4 lowest user ids of this member's own roster is
/// refused. The slack is for rosters that lag.
pub fn check_voice_keyholders(
    h: &HeaderV1,
    old: &[Keyholder],
    roster: &[u32],
) -> Result<(), Refusal> {
    if h.group_kind != GroupKind::Voice || !matches!(h.kind, Kind::Genesis | Kind::KeyholdersAdd) {
        return Ok(());
    }
    let mut lowest = roster.to_vec();
    lowest.sort_unstable();
    lowest.dedup();
    lowest.truncate(4);
    for k in h.keyholders.iter().filter(|k| !old.contains(k)) {
        let u = k.u.unwrap_or(u32::MAX);
        if !lowest.contains(&u) {
            return Err(Refusal::VoiceKeyholder(u));
        }
    }
    Ok(())
}

// ── Rule 3: the chain ─────────────────────────────────────────────────────

/// The `seed` and `seed_floor` a header may carry after its parent's (§4.3
/// "Seed rolls by kind", §5.6). This is the structure every member checks;
/// whether a roll is due and its slot open is the relay's validator's and
/// the keyholders' (`SeedRolls`).
///
/// - A roll starts with `seed = s + 1` and `seed_floor = s`: every older seed
///   leaves the keyring there, also while an earlier roll still runs.
/// - A roll finishes when `seed_floor` rises to `seed`.
/// - A Regenesis always starts one, with its floor at its own new seed:
///   every seat is welcomed anew. A voice room has none: it makes a new
///   Genesis (§5.9).
/// - A Fresh, a KeyholdersAdd or a KeyholdersRemove in a text group may
///   start one, finish one, or do neither.
/// - In a voice group the slot does not apply: a KeyholdersRemove always
///   starts a roll, and a Fresh or a KeyholdersAdd never does (either may
///   finish one).
/// - A Join and a KeyholdersReplace keep both.
fn seeds_follow(p: &HeaderV1, h: &HeaderV1) -> bool {
    let start = p.seed.checked_add(1) == Some(h.seed) && h.seed_floor == p.seed;
    let keep = h.seed == p.seed && (h.seed_floor == p.seed_floor || h.seed_floor == h.seed);
    let same = h.seed == p.seed && h.seed_floor == p.seed_floor;
    match (h.kind, h.group_kind) {
        (Kind::Genesis, _) | (Kind::Regenesis, GroupKind::Voice) => false,
        (Kind::Regenesis, GroupKind::Text) => {
            p.seed.checked_add(1) == Some(h.seed) && h.seed_floor == h.seed
        }
        (Kind::Join | Kind::KeyholdersReplace, _) => same,
        (Kind::KeyholdersRemove, GroupKind::Voice) => start,
        (Kind::Fresh | Kind::KeyholdersAdd, GroupKind::Voice) => keep,
        (Kind::Fresh | Kind::KeyholdersAdd | Kind::KeyholdersRemove, GroupKind::Text) => {
            start || keep
        }
    }
}

/// Rule 3 and the rest of what a header must be after its parent, for a
/// member that holds the parent (and for the relay's validator): one
/// generation; an opening header at `parent.epoch + 1`, a Join at the same
/// epoch with `join + 1` and its `epoch_parent`; `kh_parent` naming the set
/// in force; seeds as `seeds_follow`; `gated` changed only at an opening
/// header; `names_hash` as §11.3 steps it, with the header's own `time`,
/// `epoch` and `join`; `exits_upto` never going back; and a Regenesis at
/// least the wait its set in force allows after its parent
/// (`regenesis_wait`).
///
/// The set in force is the header `kh_parent` names. Here it is seen only
/// where the parent sets keyholders itself; otherwise the Regenesis waits the
/// hour. `check_link_under` takes the set, as a member holds it beside its
/// floor and the relay beside its head.
///
/// The names check here needs only the two headers, which carry their lists;
/// it is no fold. A member that takes headers without the names skips the
/// Join headers and checks none (rule 4).
pub fn check_link(parent: &SignedHeader, h: &SignedHeader) -> Result<Vec<Warning>, Refusal> {
    link_ok(parent, h, SetSeen::Unseen)
}

/// `check_link` under the set in force, `set`: the keyholder header
/// `h.kh_parent` names. A Regenesis waits what `regenesis_wait` says of it.
pub fn check_link_under(
    parent: &SignedHeader,
    h: &SignedHeader,
    set: &SignedHeader,
) -> Result<Vec<Warning>, Refusal> {
    link_ok(parent, h, SetSeen::held(h, set)?)
}

fn link_ok(parent: &SignedHeader, h: &SignedHeader, set: SetSeen) -> Result<Vec<Warning>, Refusal> {
    let (p, hd) = (parent.header(), h.header());
    let bad = |why| Err(Refusal::Chain(why));
    if hd.parent != parent.d() {
        return bad("parent names another header");
    }
    if hd.gen != p.gen || hd.group != p.group || hd.group_kind != p.group_kind {
        return bad("a generation changes only at a Genesis");
    }
    if hd.kind.opens_epoch() {
        if p.epoch.checked_add(1) != Some(hd.epoch) {
            return bad("an opening header is its parent's epoch plus one");
        }
    } else if hd.epoch != p.epoch
        || p.join.checked_add(1) != Some(hd.join)
        || hd.epoch_parent != parent.d_e()
    {
        return bad("a Join header follows in its parent's epoch");
    }
    if hd.kh_parent != parent.kh() {
        return bad("kh_parent is not the set in force");
    }
    if !seeds_follow(p, hd) {
        return bad("the seed does not follow");
    }
    if hd.exits_upto < p.exits_upto {
        return bad("exits_upto went back");
    }
    if hd.kind == Kind::Regenesis {
        let wait = set.wait(Some(p), hd.time);
        if hd.time < p.time.saturating_add(wait) {
            return Err(too_soon(wait));
        }
    }
    let warnings = gated_turn(p.gated, hd)?;
    if super::header::names_hash(Some(p), hd) != hd.names_hash {
        return Err(Refusal::Names);
    }
    Ok(warnings)
}

fn gated_turn(was: bool, h: &HeaderV1) -> Result<Vec<Warning>, Refusal> {
    if was != h.gated && !h.kind.opens_epoch() {
        return Err(Refusal::GatedChanged);
    }
    Ok(if was && !h.gated {
        vec![Warning::GatedTurnedOff]
    } else {
        vec![]
    })
}

/// Rule 3 when `h.parent` is the floor's `D` and the member holds only its
/// floor: everything `check_link` checks that the floor carries. Seeds,
/// `exits_upto` and `names_hash` are not in the floor (§5.7); `check_link`
/// covers them where the parent is held, and a writer's fold covers the
/// names (rule 4).
///
/// The floor carries its keyholder set's `D` (`kh`), not the set: here a
/// Regenesis waits the hour. The member holds that keyholder header beside
/// its floor (§5.7, `LocalFloor.kh`); `check_on_floor_under` takes it, and
/// holds a Regenesis to the wait its set allows.
pub fn check_on_floor(floor: &Floor, h: &SignedHeader) -> Result<Vec<Warning>, Refusal> {
    on_floor_ok(floor, h, SetSeen::Unseen)
}

/// `check_on_floor` under the set in force, `set`: the keyholder header the
/// floor names (`floor.kh`), which the member holds beside it.
pub fn check_on_floor_under(
    floor: &Floor,
    h: &SignedHeader,
    set: &SignedHeader,
) -> Result<Vec<Warning>, Refusal> {
    if set.d() != floor.kh {
        return Err(Refusal::Chain("kh_parent is not the set in force"));
    }
    on_floor_ok(floor, h, SetSeen::held(h, set)?)
}

fn on_floor_ok(floor: &Floor, h: &SignedHeader, set: SetSeen) -> Result<Vec<Warning>, Refusal> {
    let hd = h.header();
    let bad = |why| Err(Refusal::Chain(why));
    if hd.parent != floor.d || hd.gen != floor.gen {
        return bad("parent is not the floor");
    }
    if hd.kind.opens_epoch() {
        if floor.epoch.checked_add(1) != Some(hd.epoch) {
            return bad("an opening header is its parent's epoch plus one");
        }
    } else if hd.epoch != floor.epoch
        || floor.join.checked_add(1) != Some(hd.join)
        || hd.epoch_parent != floor.d_e
    {
        return bad("a Join header follows in its parent's epoch");
    }
    if hd.kh_parent != floor.kh {
        return bad("kh_parent is not the set in force");
    }
    if hd.kind == Kind::Regenesis {
        let wait = set.wait(None, hd.time);
        if hd.time < floor.time.saturating_add(wait) {
            return Err(too_soon(wait));
        }
    }
    gated_turn(floor.gated, hd)
}

/// Whether every entry of a keyholder set is a connection entry (origin
/// 0x02): a browser's or a guest's per-connection pair, which goes with its
/// connection (§2). A desktop's keyholder pair (0x03) is not one. An empty
/// set is none.
pub fn connection_only(set: &[Keyholder]) -> bool {
    !set.is_empty() && set.iter().all(|k| k.origin == Origin::Connection as u8)
}

/// How long a Regenesis dated `time` waits after its parent (§4.3, §5.7),
/// under `set`, the keyholder header its `kh_parent` names (the set in
/// force). "Fast new start" (owner, 2026-11-19):
///
/// - `REGENESIS_FAST_WAIT`, 2 minutes, when every entry of the set is a
///   connection entry (`connection_only`). Such an entry dies with its
///   connection: after the sole browser keyholder's reload, or any relay
///   restart, none can ever come back online, and the hour would only stall
///   the group's joins and exits.
/// - `REGENESIS_WAIT`, the hour, for a set with any other entry: a desktop's
///   pair (0x03) comes back with its device, so its set is not replaced
///   within the hour.
/// - The hour too when the set is one a Regenesis started less than
///   `REGENESIS_FAST_GAP` before `time` (the churn bound): connections that
///   drop again and again, or a relay that drops them, start anew at most
///   once an hour that way.
///
/// What it reads is all in the signed headers, so every member checks it
/// itself. A relay can still drop every connection of such a set and have a
/// volunteer start anew after 2 minutes: a new seed and keyring, no read and
/// no forge.
pub fn regenesis_wait(set: &HeaderV1, time: u64) -> u64 {
    let churn = set.kind == Kind::Regenesis && time < set.time.saturating_add(REGENESIS_FAST_GAP);
    if connection_only(&set.keyholders) && !churn {
        REGENESIS_FAST_WAIT
    } else {
        REGENESIS_WAIT
    }
}

/// What a check sees of the keyholder set in force before a Regenesis.
#[derive(Clone, Copy)]
enum SetSeen<'a> {
    /// The keyholder header `kh_parent` names, as the caller holds it.
    Held(&'a HeaderV1),
    /// Not shown to the check: the hour, unless the parent sets keyholders
    /// itself (then `kh_parent` is its `D`, and it is the set).
    Unseen,
    /// Where a device with no floor starts its walk, on trust (§5.7): the set
    /// before is never shown to it, as none is before a Genesis of any age it
    /// takes the same way. The shortest wait, unless the parent sets
    /// keyholders itself.
    Trust,
}

impl<'a> SetSeen<'a> {
    /// `set` as what `h.kh_parent` names, or the refusal of one that is not.
    fn held(h: &SignedHeader, set: &'a SignedHeader) -> Result<SetSeen<'a>, Refusal> {
        if set.d() != h.header().kh_parent || !set.header().kind.sets_keyholders() {
            return Err(Refusal::Chain("kh_parent is not the set in force"));
        }
        Ok(SetSeen::Held(set.header()))
    }

    /// The wait of a Regenesis dated `time` after `parent` (where the check
    /// holds it).
    fn wait(self, parent: Option<&HeaderV1>, time: u64) -> u64 {
        match (self, parent) {
            (SetSeen::Held(k), _) => regenesis_wait(k, time),
            (_, Some(p)) if p.kind.sets_keyholders() => regenesis_wait(p, time),
            (SetSeen::Unseen, _) => REGENESIS_WAIT,
            (SetSeen::Trust, _) => REGENESIS_FAST_WAIT,
        }
    }
}

/// What a member says of a Regenesis that came before `wait` was out.
fn too_soon(wait: u64) -> Refusal {
    Refusal::Generation(if wait >= REGENESIS_WAIT {
        "a Regenesis comes an hour after its parent"
    } else {
        "a Regenesis comes two minutes after its parent"
    })
}

/// §5.7: within a generation, a header at or below the floor is refused.
pub fn check_above(floor: &Floor, h: &HeaderV1) -> Result<(), Refusal> {
    if h.gen == floor.gen && (h.epoch, h.join) <= (floor.epoch, floor.join) {
        Err(Refusal::BelowFloor)
    } else {
        Ok(())
    }
}

/// Rule 3's epoch bound: `h.epoch ≤ epoch + ⌈(h.time − time + CLOCK_SLACK) /
/// EPOCH_MIN_GAP⌉`, from a floor's (or a generation start's) `epoch` and
/// `time`. A time before it allows no new epoch at all.
pub fn epoch_bound_ok(epoch: u32, time: u64, h: &HeaderV1) -> bool {
    let elapsed = i128::from(h.time) - i128::from(time) + i128::from(CLOCK_SLACK);
    let more = if elapsed <= 0 {
        0
    } else {
        (elapsed + i128::from(EPOCH_MIN_GAP) - 1) / i128::from(EPOCH_MIN_GAP)
    };
    i128::from(h.epoch) <= i128::from(epoch) + more
}

/// One keyholder header on a walk, with its parent where it is a Regenesis
/// (the relay keeps each Regenesis with its parent, §4.4).
#[derive(Clone, Copy)]
pub struct WalkLink<'a> {
    pub header: &'a SignedHeader,
    pub parent: Option<&'a SignedHeader>,
}

/// Where a walk ends.
#[derive(Clone, Copy)]
pub enum WalkTo<'a> {
    /// At the keyholder header the floor names, which the member holds.
    Floor {
        floor: &'a Floor,
        kh: &'a SignedHeader,
    },
    /// At the newest Genesis (or, for a device with no floor, Genesis or
    /// Regenesis): the last link. `floor` is the member's floor in an older
    /// generation, if any.
    Start { floor: Option<&'a Floor> },
}

/// What a walk took on its signers' word: each signer whose `IK` the member
/// pins now if it has no pin for it yet (TOFU), and the start of a new
/// generation where the walk ended at one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Walked {
    pub signers: Vec<(MemberId, [u8; 32])>,
    pub start: Option<SignedHeader>,
}

/// Rule 3's walk, for a header whose parent the member does not hold.
///
/// `links` are the keyholder headers from the one `h.kh_parent` names back,
/// newest first, each naming the next by `kh_parent`. The walk ends at the
/// floor's `kh`, or for a new generation at its Genesis (a device with no
/// floor may also end at a Regenesis). At most 4096 links. Each link is
/// signed by a member of the set before it (rule 2); a Regenesis by the
/// rules of §5.7 with its parent (`regenesis_parent_ok`); a Genesis only
/// where the walk ends.
///
/// Then `(h.epoch, h.join)` is above the floor's, `h.epoch_parent` is the
/// floor's `D_e` in the floor's own epoch, and `h.epoch` keeps within the
/// epoch bound. A walk to a new generation's start bounds the epoch from the
/// start header in the same way: §4.4 states the bound for a floor only, and
/// without one a made-up epoch could reach the end of the u32 range.
///
/// `head` is the header taken; a Regenesis there comes with its parent, as
/// on a link. A Genesis is a start, never a head of a walk.
pub fn check_walk(
    to: WalkTo,
    links: &[WalkLink],
    head: WalkLink,
    clock: Clock,
    pins: Pins,
) -> Result<Walked, Refusal> {
    if links.len() > MAX_WALK {
        return Err(Refusal::Walk("more than 4096 links"));
    }
    let h = head.header;
    let hd = h.header();
    let mut signers = Vec::new();
    // From the oldest end: what each set is checked against.
    let (mut set, mut epoch, mut start, ordered): (Option<&SignedHeader>, u32, _, Vec<&WalkLink>) =
        match to {
            WalkTo::Floor { floor, kh } => {
                if kh.d() != floor.kh
                    || !kh.header().kind.sets_keyholders()
                    || kh.header().gen != floor.gen
                {
                    return Err(Refusal::Walk("the floor's keyholder header is another"));
                }
                (Some(kh), floor.epoch, None, links.iter().rev().collect())
            }
            WalkTo::Start { floor } => {
                let (last, rest) = links
                    .split_last()
                    .ok_or(Refusal::Walk("a new generation is walked to its start"))?;
                let s = last.header;
                match (s.header().kind, floor) {
                    (Kind::Genesis, _) => {
                        check_new_generation(floor, clock, s.header())?;
                        signers.push((s.header().signer, check_signer(s, None, pins)?));
                    }
                    (Kind::Regenesis, None) => {
                        let parent = last
                            .parent
                            .ok_or(Refusal::Walk("a Regenesis needs its parent"))?;
                        regenesis_ok(None, clock, s, parent, SetSeen::Trust)?;
                        signers.push((s.header().signer, check_signer(s, None, pins)?));
                    }
                    _ => return Err(Refusal::Walk("a new generation starts at its Genesis")),
                }
                let ordered = rest.iter().rev().collect();
                (Some(s), s.header().epoch, Some(s.clone()), ordered)
            }
        };
    let gen = set.map(|s| s.header().gen).unwrap_or(hd.gen);
    for link in ordered {
        let l = link.header;
        let prev = set.expect("a walk starts from a set");
        if !l.header().kind.sets_keyholders() || l.header().gen != gen {
            return Err(Refusal::Walk(
                "a link is no keyholder header of this generation",
            ));
        }
        if l.header().kh_parent != prev.d() || l.header().epoch <= epoch {
            return Err(Refusal::Walk("a link does not follow the one before it"));
        }
        match l.header().kind {
            Kind::Regenesis => {
                let parent = link
                    .parent
                    .ok_or(Refusal::Walk("a Regenesis needs its parent"))?;
                let floor = match to {
                    WalkTo::Floor { floor, .. } => Some(floor),
                    WalkTo::Start { .. } => None,
                };
                // The set before it is the walk's own: its wait is that set's
                regenesis_ok(floor, clock, l, parent, SetSeen::held(l, prev)?)?;
                regenesis_parent_ok(to, prev, parent, pins)?;
                signers.push((l.header().signer, check_signer(l, None, pins)?));
            }
            Kind::Genesis => return Err(Refusal::Walk("a Genesis inside a generation")),
            _ => {
                check_signer(l, Some(prev), pins)?;
            }
        }
        check_time(l.header(), clock.now)?;
        set = Some(l);
        epoch = l.header().epoch;
    }
    let last = set.expect("a walk has a set");
    let after = if hd.kind.opens_epoch() {
        hd.epoch > last.header().epoch
    } else {
        hd.epoch >= last.header().epoch
    };
    if hd.gen != gen || hd.kh_parent != last.d() || !after {
        return Err(Refusal::Walk("the header does not follow the chain"));
    }
    match hd.kind {
        Kind::Genesis => return Err(Refusal::Walk("a Genesis is a start, not a head")),
        Kind::Regenesis => {
            let parent = head
                .parent
                .ok_or(Refusal::Walk("a Regenesis needs its parent"))?;
            let floor = match to {
                WalkTo::Floor { floor, .. } => Some(floor),
                WalkTo::Start { .. } => None,
            };
            regenesis_ok(floor, clock, h, parent, SetSeen::held(h, last)?)?;
            regenesis_parent_ok(to, last, parent, pins)?;
            signers.push((hd.signer, check_signer(h, None, pins)?));
        }
        _ => {
            check_signer(h, Some(last), pins)?;
        }
    }
    match to {
        WalkTo::Floor { floor, .. } => {
            check_above(floor, hd)?;
            if hd.epoch == floor.epoch && hd.epoch_parent != floor.d_e {
                return Err(Refusal::Chain("a Join of the floor's epoch names its D_e"));
            }
            if !epoch_bound_ok(floor.epoch, floor.time, hd) {
                return Err(Refusal::EpochBound);
            }
        }
        WalkTo::Start { .. } => {
            let s = start.as_ref().expect("a start");
            if !epoch_bound_ok(s.header().epoch, s.header().time, hd) {
                return Err(Refusal::EpochBound);
            }
        }
    }
    check_time(hd, clock.now)?;
    Ok(Walked {
        signers,
        start: start.take(),
    })
}

/// The parent of a Regenesis taken on a walk (§5.7): the wait a Regenesis
/// keeps (`regenesis_wait`) is measured from its parent's `time`, so the
/// parent must be one the walk stands behind, not any header the relay shows
/// with it.
///
/// - It is signed by the set in force before the Regenesis, `prev`; one that
///   sets keyholders must be `prev` itself.
/// - Walking to a floor, it is the floor or above it, and in the floor's own
///   epoch it names the floor's `D_e`: "its parent is the floor or reachable
///   from it". A real header from below the floor, or one made up, would let
///   a volunteer replace a keyholder set the member saw sign minutes ago.
fn regenesis_parent_ok(
    to: WalkTo,
    prev: &SignedHeader,
    parent: &SignedHeader,
    pins: Pins,
) -> Result<(), Refusal> {
    if parent.header().kind.sets_keyholders() {
        if parent.d() != prev.d() {
            return Err(Refusal::Walk(
                "a Regenesis's parent is not the keyholder set in force",
            ));
        }
    } else {
        check_signer(parent, Some(prev), pins)?;
    }
    if let WalkTo::Floor { floor, .. } = to {
        if parent.d() != floor.d {
            check_above(floor, parent.header())?;
            if parent.header().epoch == floor.epoch && parent.d_e() != floor.d_e {
                return Err(Refusal::Chain("a Join of the floor's epoch names its D_e"));
            }
        }
    }
    Ok(())
}

// ── §5.7: generations ─────────────────────────────────────────────────────

/// Whether a device may take `genesis` as a new generation (§5.7):
/// - its `gen` is none of the last 8 the device took;
/// - its `time` passes rule 7;
/// - with a floor in an older generation, it began after the floor's `time`
///   less `CLOCK_SLACK`: a generation of any age that began after the device
///   last saw the group, never one that began before;
/// - a device that took a header of the group in the last 10 minutes sees a
///   new generation as it starts, so its `time` must be within 10 minutes of
///   the device's clock, either way;
/// - with no floor, nothing else: the device takes it on trust.
pub fn check_new_generation(
    floor: Option<&Floor>,
    clock: Clock,
    genesis: &HeaderV1,
) -> Result<(), Refusal> {
    if genesis.kind != Kind::Genesis {
        return Err(Refusal::Generation("a new generation starts at a Genesis"));
    }
    check_time(genesis, clock.now)?;
    let Some(floor) = floor else {
        return Ok(());
    };
    if floor.took_gen(&genesis.gen) {
        return Err(Refusal::Generation("a generation this device took already"));
    }
    if i128::from(genesis.time) <= i128::from(floor.time) - i128::from(CLOCK_SLACK) {
        return Err(Refusal::Generation(
            "a generation that began before the floor",
        ));
    }
    live_ok(clock, genesis)
}

fn live_ok(clock: Clock, h: &HeaderV1) -> Result<(), Refusal> {
    if clock.live() && h.time.abs_diff(clock.now) > LIVE_WINDOW {
        return Err(Refusal::Generation(
            "a device that follows the group sees a new generation as it starts",
        ));
    }
    Ok(())
}

/// A Regenesis (§5.7, §4.3): after its parent by the wait its set in force
/// allows (`regenesis_wait`), a parent it follows (same generation, the next
/// epoch, the set in force as `kh_parent`, a new seed); rule 7; and, for a
/// device with a floor in its generation that follows the group live, within
/// 10 minutes of the device's clock. Its signer is checked by
/// `check_signer`. Whether the parent is genuine and at or above the floor is
/// the caller's: a member that took the parent holds it, and `check_walk`
/// checks one it walks to.
///
/// The set in force is the header `kh_parent` names. Here it is seen only
/// where the parent sets keyholders itself; otherwise the Regenesis waits the
/// hour. `check_regenesis_under` takes the set, as a member holds it beside
/// its floor. A device with no floor whose walk starts at the Regenesis takes
/// it on trust after the shortest wait (`check_walk`): the set before it is
/// never shown to such a device, as it takes a Genesis of any age.
///
/// A device with a floor in an older generation takes the Genesis first,
/// then the Regenesis on the walk; one with no floor takes it on trust.
pub fn check_regenesis(
    floor: Option<&Floor>,
    clock: Clock,
    regen: &SignedHeader,
    parent: &SignedHeader,
) -> Result<(), Refusal> {
    regenesis_ok(floor, clock, regen, parent, SetSeen::Unseen)
}

/// `check_regenesis` under the set in force, `set`: the keyholder header
/// `regen.kh_parent` names, which a member holds beside its floor (§5.7). The
/// Regenesis waits what `regenesis_wait` says of that set: 2 minutes for one
/// of connection entries alone, else the hour.
pub fn check_regenesis_under(
    floor: Option<&Floor>,
    clock: Clock,
    regen: &SignedHeader,
    parent: &SignedHeader,
    set: &SignedHeader,
) -> Result<(), Refusal> {
    regenesis_ok(floor, clock, regen, parent, SetSeen::held(regen, set)?)
}

fn regenesis_ok(
    floor: Option<&Floor>,
    clock: Clock,
    regen: &SignedHeader,
    parent: &SignedHeader,
    set: SetSeen,
) -> Result<(), Refusal> {
    let (r, p) = (regen.header(), parent.header());
    if r.kind != Kind::Regenesis {
        return Err(Refusal::Generation("not a Regenesis"));
    }
    if r.parent != parent.d()
        || r.gen != p.gen
        || p.epoch.checked_add(1) != Some(r.epoch)
        || r.kh_parent != parent.kh()
        || !seeds_follow(p, r)
    {
        return Err(Refusal::Chain("a Regenesis follows its parent"));
    }
    let wait = set.wait(Some(p), r.time);
    if r.time < p.time.saturating_add(wait) {
        return Err(too_soon(wait));
    }
    check_time(r, clock.now)?;
    if floor.is_some_and(|f| f.gen == r.gen) {
        live_ok(clock, r)?;
    }
    Ok(())
}

// ── §5.6: seed rolls ──────────────────────────────────────────────────────

/// At most one roll start per text group in this many seconds, by header
/// `time` (§5.6).
pub const ROLL_GAP: u64 = 24 * 60 * 60;
/// A text seed's maximum age (§5.6): a roll is due once the current seed's
/// roll started this long ago, by header `time`.
pub const SEED_MAX_AGE: u64 = 30 * 24 * 60 * 60;

/// What the headers say of the next seed roll (§5.6): the `time` of the
/// header that last raised `seed`, and whether a keyholder entry was removed
/// since. A keyholder knows from these that a roll is due, whether the relay
/// asks or not, and the relay's validator checks raises against the same
/// (`check_roll`). Members need neither: they check the structure alone
/// (`check_link`).
///
/// A generation's start counts as the start of its first seed's roll: for
/// the 30-day age, as §5.6 says ("for seed 1, the Genesis"), and for the
/// one-a-day slot too, which §5.6 counts "from the last roll start" without
/// saying what comes before the first. A removal in a generation's first day
/// then waits for the slot like any other, and is still rolled within 24 h.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeedRolls {
    /// `time` of the header that last raised `seed`, or of the Genesis.
    pub raised: u64,
    /// A KeyholdersRemove came after it: a roll is due.
    pub removal: bool,
}

impl SeedRolls {
    /// At a Genesis or a Regenesis.
    pub fn at_start(h: &HeaderV1) -> SeedRolls {
        SeedRolls {
            raised: h.time,
            removal: false,
        }
    }

    /// After taking `h` over its parent `p`. A raise clears whatever was
    /// due: two removals while a roll is due share it. A removal after a
    /// raise, even while that roll still runs, makes the next one due.
    pub fn after(self, p: &HeaderV1, h: &HeaderV1) -> SeedRolls {
        if h.kind == Kind::Genesis || h.seed > p.seed {
            SeedRolls::at_start(h)
        } else if h.kind == Kind::KeyholdersRemove {
            SeedRolls {
                removal: true,
                ..self
            }
        } else {
            self
        }
    }

    /// Whether a roll is due at `time`: a removal since the last raise, or,
    /// in a text group, a seed 30 days old.
    pub fn due(&self, group: GroupKind, time: u64) -> bool {
        self.removal
            || (group == GroupKind::Text && time >= self.raised.saturating_add(SEED_MAX_AGE))
    }

    /// Whether an opening commit of `kind` at `time` starts a roll (§4.3
    /// "Seed rolls by kind", §5.6). A keyholder starts one at its first
    /// opening commit that may, whether the relay asks or not.
    ///
    /// - A Regenesis always does: it is exempt from the 24 h rule. Voice
    ///   rooms have none (`check_shape`): they make a new Genesis.
    /// - In a voice group every KeyholdersRemove does, at once, and nothing
    ///   else.
    /// - In a text group a Fresh, a KeyholdersAdd or a KeyholdersRemove does
    ///   when a roll is due (a KeyholdersRemove makes one due itself) and the
    ///   last raise is at least 24 h before it. A Join and a
    ///   KeyholdersReplace never do.
    pub fn starts(&self, group: GroupKind, kind: Kind, time: u64) -> bool {
        match (kind, group) {
            (Kind::Regenesis, GroupKind::Text) => true,
            (Kind::KeyholdersRemove, GroupKind::Voice) => true,
            (_, GroupKind::Voice) => false,
            (Kind::Fresh | Kind::KeyholdersAdd | Kind::KeyholdersRemove, GroupKind::Text) => {
                let due = kind == Kind::KeyholdersRemove || self.due(group, time);
                due && time >= self.raised.saturating_add(ROLL_GAP)
            }
            _ => false,
        }
    }
}

/// The relay's validator (§9): a commit raises `seed` only where a roll
/// starts (`SeedRolls::starts`), with `rolls` as of its parent `p`. It does
/// not refuse a commit that leaves a due roll for later.
pub fn check_roll(rolls: SeedRolls, p: &HeaderV1, h: &HeaderV1) -> Result<(), Refusal> {
    if h.seed > p.seed && !rolls.starts(h.group_kind, h.kind, h.time) {
        return Err(Refusal::Roll(
            "the seed rises with no roll due, or within 24 h of the last",
        ));
    }
    Ok(())
}

/// Which seed a keyholder makes a row to a seat under (§3.3, §5.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RowSeed {
    /// The newest seed the seat was given a welcome under, still live.
    Row(u32),
    /// The seat is on a seed the head's floor dropped (a roll that had not
    /// finished): it gets its seed welcome under this seed, the head's,
    /// before any row is made to it.
    WelcomeFirst(u32),
}

/// `held` is the newest seed the seat was given a welcome under; `head` the
/// header the rows are made for. At the commit that starts a roll, every seat
/// still holds the old seed, which the new floor keeps, so its rows use it.
pub fn row_seed(held: u32, head: &HeaderV1) -> RowSeed {
    if (head.seed_floor..=head.seed).contains(&held) {
        RowSeed::Row(held)
    } else {
        RowSeed::WelcomeFirst(head.seed)
    }
}

// ── §4.3: the versions each kind makes ────────────────────────────────────

/// The bucket versions a commit of each kind may make (§4.3, "Buckets"),
/// over the leaves of its parent's bucket root (`before`) and its own
/// (`after`): what the relay's validator and a keyholder can check of the
/// rows a commit made.
///
/// - A version kept keeps its leaf exactly: a version id never stands for
///   another key or seat set in a generation (§4.1).
/// - A new version is made by rows, except at a KeyholdersAdd, where it may
///   also be a ratchet of its own bucket's version in `before`, with the
///   same pool and seats (§3.5).
/// - A Join keeps every version and makes new buckets only.
/// - A KeyholdersAdd keeps none: every bucket ratchets in place, or is
///   re-versioned by rows for exits.
/// - A KeyholdersRemove keeps none: every bucket is re-versioned by rows. So
///   does a Regenesis, whose buckets are all new.
/// - A Fresh, and a KeyholdersReplace, which makes the rows a Fresh makes,
///   keep what they do not re-version, and re-version by rows only.
///
/// Which versions a Fresh must re-key (leavers, the refresh slice, versions
/// over 1 h old) needs the exits and the keyring's `made` times: that is the
/// keyholder's own duty (§5.5), not a check on the leaves.
pub fn check_versions(kind: Kind, before: &[Leaf], after: &[Leaf]) -> Result<(), Refusal> {
    let bad = |why| Err(Refusal::Versions(why));
    let keeps_none = matches!(
        kind,
        Kind::KeyholdersAdd | Kind::KeyholdersRemove | Kind::Regenesis
    );
    for l in after {
        match before.iter().find(|o| (o.b, o.v) == (l.b, l.v)) {
            Some(o) if o != l => return bad("a version id stands for another version"),
            Some(_) if keeps_none => return bad("this kind keeps no version"),
            Some(_) => {}
            None => match (l.via, kind) {
                (Via::Row, Kind::Join) if before.iter().any(|o| o.b == l.b) => {
                    return bad("a Join makes new buckets only")
                }
                (Via::Row, _) => {}
                (Via::Ratchet { from }, Kind::KeyholdersAdd) => {
                    let source = before.iter().find(|o| (o.b, o.v) == (l.b, from));
                    if !source.is_some_and(|o| (o.pool, o.seats) == (l.pool, l.seats)) {
                        return bad("a ratchet is of its own bucket's version, seats and all");
                    }
                }
                (Via::Ratchet { .. }, _) => return bad("only a KeyholdersAdd ratchets"),
            },
        }
    }
    if kind == Kind::Join && !before.iter().all(|o| after.contains(o)) {
        return bad("a Join keeps every version");
    }
    Ok(())
}

// ── Rule 4: names ─────────────────────────────────────────────────────────

/// The relay keeps the names for 90 days (§4.4 rule 4): it may answer that
/// the names since a names floor are gone only once that floor's `time` is
/// older than that by the writer's own clock.
pub const NAMES_KEPT: u64 = 90 * 24 * 60 * 60;

/// A writer's names floor (§4.4 rule 4, §5.7): the header it last folded
/// the names to, as `(gen, epoch, join, names_hash, time)`. Kept beside the
/// floor and in the same places; set to the first head the device takes in
/// the group, and moved only by a fold.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamesFloor {
    pub gen: [u8; 16],
    pub epoch: u32,
    pub join: u32,
    pub names_hash: [u8; 32],
    pub time: u64,
}

impl NamesFloor {
    /// At header `h`: where a device with no names floor starts, without
    /// fetching any names before it, and where a fold that passes moves it.
    pub fn of(h: &HeaderV1) -> NamesFloor {
        NamesFloor {
            gen: h.gen,
            epoch: h.epoch,
            join: h.join,
            names_hash: h.names_hash,
            time: h.time,
        }
    }

    fn after(gen: [u8; 16], l: &NamesList, names_hash: [u8; 32]) -> NamesFloor {
        NamesFloor {
            gen,
            epoch: l.epoch,
            join: l.join,
            names_hash,
            time: l.time,
        }
    }
}

/// Whether the relay may say the names since `floor` are gone: its `time`
/// is more than 90 days old by this device's clock.
pub fn names_may_be_gone(floor: &NamesFloor, now: u64) -> bool {
    now > floor.time.saturating_add(NAMES_KEPT)
}

/// Where a writer's fold starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NamesFrom {
    /// Its names floor. One in another generation than the head's, or taken
    /// while the group was open (`names_hash` 0³²), folds as `Start`.
    Floor(NamesFloor),
    /// The generation's Genesis, or the opening header that turned `gated`
    /// on: the first list steps from 0³², even when it is empty. For a writer
    /// whose names floor is in an older generation, or from before the group
    /// turned gated, and for an app that shows every name since the start.
    /// No list is skipped this way: only the real start's chain reaches the
    /// head's `names_hash`.
    Start,
    /// A "gone" answer: the writer's names floor, which must be more than 90
    /// days old, and the step before the relay's 90-day tail, which must be
    /// too, less `CLOCK_SLACK`. The tail of lists then folds on from that
    /// step. It may lie in an older generation than the floor's: a writer
    /// away that long may have missed one.
    Gone { floor: NamesFloor, step: NamesStep },
}

/// What a device knows of an account's pin at a given time (rule 6 at a
/// fold): an entry is checked against the pin as it stood at its header's
/// `time`, where the device knows it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinThen {
    /// No pin for the account: nothing to check.
    None,
    /// The pin as it stood then.
    Pin([u8; 32]),
    /// The pin changed since, and the device does not know the one before:
    /// the entry is shown, not refused (default, 2026-11-17).
    Unknown,
}

/// The pin an account had at a time, as this device knows it.
pub type PinsAt<'a> = &'a dyn Fn(&[u8; 16], u64) -> PinThen;

/// The highest counter this device has seen for an account, with the time
/// that endorsement was made (§11.8): what keyholders, and writers at their
/// fold, keep beside the pins. A device's own account is in it too, at its
/// own counter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Seen {
    pub n: u32,
    pub made: u64,
}

/// The highest counter seen per account.
pub type Counters<'a> = &'a dyn Fn(&[u8; 16]) -> Option<Seen>;

/// Rule 8's time rule (§4.4, §11.8): counter `n` in a header made at `time`
/// is flagged only if it is below the highest seen for its account and the
/// header was made after that newer endorsement's `made` plus `CLOCK_SLACK`.
/// So names from before a rotation do not flag the old seat. Returns the
/// counter it is flagged against.
///
/// The device keeps only the highest counter with its `made`, as §11.8 says:
/// an entry two rotations old, in a header made between the two, is checked
/// against the newer one and not flagged (§7 Q8 asks about this gap).
pub fn counter_flagged(n: u32, time: u64, seen: Option<Seen>) -> Option<u32> {
    seen.filter(|s| n < s.n && time > s.made.saturating_add(CLOCK_SLACK))
        .map(|s| s.n)
}

/// What a writer knows when it folds.
#[derive(Clone, Copy)]
pub struct Known<'a> {
    pub pins: PinsAt<'a>,
    pub counters: Counters<'a>,
    /// This device's own account, if it is signed in: a flagged entry for it
    /// also warns.
    pub own: Option<[u8; 16]>,
    /// This device's clock.
    pub now: u64,
}

/// Why a fold failed: an entry that fails rule 6 or rule 8 (§4.4 rule 4).
/// The writer's app says which.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Held {
    /// A guest seat in a gated group's list.
    Guest(SeatRef),
    /// An `IK` that is not the one pinned for its account at its header's
    /// `time`.
    Pin(SeatRef),
    /// A counter below the highest seen for its account, in a header made
    /// after that newer endorsement.
    Counter { seat: SeatRef, n: u32, highest: u32 },
}

impl Held {
    /// The same failure as a keyholder's refusal of the header.
    fn refusal(self, own: Option<[u8; 16]>) -> Refusal {
        match self {
            Held::Guest(seat) => Refusal::GuestSeat(Some(seat)),
            Held::Pin(seat) => Refusal::Pin(seat.m),
            Held::Counter { seat, n, highest } => {
                let account = seat.m.account().unwrap_or_default();
                Refusal::OldCounter {
                    account,
                    n,
                    highest,
                    own: own == Some(account),
                }
            }
        }
    }
}

/// The new readers a fold shows, up to where it moved the names floor.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Shown {
    /// Every new reader, in order.
    pub named: Vec<AddedSeat>,
    /// Those of `named` whose pin changed since their header, where the
    /// device does not know the old one: shown, not refused.
    pub unchecked: Vec<AddedSeat>,
    /// Entries that failed but a later opening header removed: named and
    /// gone.
    pub gone: Vec<SeatRef>,
    /// The fold began at a "gone" answer: people joined more than 90 days ago
    /// whose names this writer was not shown.
    pub older_unnamed: bool,
}

/// What a fold says (§4.4 rule 4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fold {
    /// Every list folds to the head and every entry passes: the app shows
    /// the new readers and the names floor moves to `floor`, the head.
    Take {
        floor: NamesFloor,
        shown: Shown,
        warnings: Vec<Warning>,
    },
    /// A failed fold: the writer holds its posts in this group, and its app
    /// says why. Its names floor stays before the list that failed: at
    /// `floor`, past every list before it, which passed and whose readers are
    /// in `shown`, so none of them goes unshown. `floor` is the last of those
    /// lists that stepped the hash, since an empty list's place is in no hash
    /// (`None`: before the generation's start, so the writer keeps what it
    /// had). It folds on once an opening header after that list names the
    /// seat in `removed`.
    Hold {
        why: Held,
        floor: Option<NamesFloor>,
        shown: Shown,
        warnings: Vec<Warning>,
    },
}

/// What a check of one `added` entry says.
enum Entry {
    Fine,
    Unchecked,
    Failed(Held),
}

/// Rules 6 and 8 for one `added` entry of a header made at `time`: no guest,
/// the `IK` its pin then (`pin`), and no counter flagged. A flagged entry of
/// this device's own account also warns.
fn check_entry(
    a: &AddedSeat,
    time: u64,
    pin: PinThen,
    counters: Counters,
    own: Option<[u8; 16]>,
    warnings: &mut Vec<Warning>,
) -> Entry {
    let seat = a.seat();
    let Some(account) = a.m.account() else {
        return Entry::Failed(Held::Guest(seat));
    };
    if matches!(pin, PinThen::Pin(p) if p != a.ik) {
        return Entry::Failed(Held::Pin(seat));
    }
    if let Some(highest) = counter_flagged(a.n, time, counters(&account)) {
        if own == Some(account) {
            let w = Warning::OldOwnSeat {
                n: a.n,
                own: highest,
            };
            if !warnings.contains(&w) {
                warnings.push(w);
            }
        }
        return Entry::Failed(Held::Counter {
            seat,
            n: a.n,
            highest,
        });
    }
    if pin == PinThen::Unknown {
        Entry::Unchecked
    } else {
        Entry::Fine
    }
}

/// Whether an opening header after a list at `epoch`, at or before the head
/// and in its generation, names `seat` in `removed`. The writer took each of
/// `removals` as any header (rules 1–3); one that is not such a header here
/// counts for nothing.
fn removed_after(removals: &[SignedHeader], head: &HeaderV1, epoch: u32, seat: &SeatRef) -> bool {
    removals.iter().map(SignedHeader::header).any(|r| {
        r.gen == head.gen
            && r.kind.opens_epoch()
            && r.epoch > epoch
            && r.epoch <= head.epoch
            && matches!(&r.removed, Removed::List(l) if l.contains(seat))
    })
}

/// Rule 4: a writer's fold, before each post in a gated group (and, in a
/// gated voice room, every member's, as the Join headers come).
///
/// `lists` are every `added` list between `from` and `head`, the head the
/// writer posts under, in order, each with its own header's `time`, `epoch`
/// and `join`, from the Join headers or the bare lists (`EpochNamesIn`).
/// `removals` are the opening headers between that carry `removed` lists,
/// which the relay sends after a failed fold.
///
/// - `Err(Names)`: the lists do not fold from `from` to the head's
///   `names_hash`, or are out of order or past the head. A list left out,
///   changed, reordered, or given another header's `time`, `epoch` or `join`
///   is caught here. The writer asks again and holds its posts.
/// - `Err(NamesNotGone)`: a "gone" answer it may not take.
/// - `Ok(Hold)`: they fold, but an entry fails rule 6 or rule 8 at its
///   header's `time` and no later opening header removed it.
/// - `Ok(Take)`: every entry passes, or was removed after its list.
///
/// An open head carries no names: nothing to fold, and the names floor
/// moves to it.
pub fn fold_names(
    from: &NamesFrom,
    lists: &[NamesList],
    removals: &[SignedHeader],
    head: &HeaderV1,
    known: &Known,
) -> Result<Fold, Refusal> {
    if !head.gated {
        return Ok(Fold::Take {
            floor: NamesFloor::of(head),
            shown: Shown::default(),
            warnings: vec![],
        });
    }
    // A names floor in another generation, or taken while the group was
    // open (an open header's `names_hash` is 0³²), has no chain to the head:
    // the writer folds from the start instead (rule 4), here rather than at
    // the caller, so an honest relay's lists never read as tampering.
    let from = match *from {
        NamesFrom::Floor(f) if f.gen != head.gen || f.names_hash == [0; 32] => &NamesFrom::Start,
        _ => from,
    };
    let (start, mut last, before_first) = match *from {
        NamesFrom::Floor(f) => (f.names_hash, Some((f.epoch, f.join)), Some(f)),
        NamesFrom::Start => ([0; 32], None, None),
        NamesFrom::Gone { floor, step } => {
            let old_enough =
                step.time.saturating_add(NAMES_KEPT) < known.now.saturating_add(CLOCK_SLACK);
            if !names_may_be_gone(&floor, known.now) || !old_enough {
                return Err(Refusal::NamesNotGone);
            }
            let at = NamesFloor {
                gen: head.gen,
                epoch: step.epoch,
                join: step.join,
                names_hash: step.hash(),
                time: step.time,
            };
            (at.names_hash, Some((step.epoch, step.join)), Some(at))
        }
    };
    // From the start, the first list is the start header's, stepped even when
    // empty; the hash binds its place, so no other list can stand in for it,
    // and no list at all leaves 0³², which no gated head carries.
    let from_start = matches!(from, NamesFrom::Start);
    let steps = |i: usize, l: &NamesList| (from_start && i == 0) || !l.added.is_empty();
    // The hash after each list: the chain must reach the head's, and each
    // value on the way is then the one its header carries.
    let mut acc = start;
    let mut after = Vec::with_capacity(lists.len());
    for (i, l) in lists.iter().enumerate() {
        let at = (l.epoch, l.join);
        if last.is_some_and(|p| at <= p) || at > (head.epoch, head.join) {
            return Err(Refusal::Names);
        }
        if steps(i, l) {
            acc = l.step_from(&acc).hash();
        }
        after.push(acc);
        last = Some(at);
    }
    if acc != head.names_hash {
        return Err(Refusal::Names);
    }
    let mut shown = Shown {
        older_unnamed: matches!(from, NamesFrom::Gone { .. }),
        ..Shown::default()
    };
    let mut warnings = vec![];
    // Where the names floor stops if a list fails: past the last list before
    // it that stepped the hash. An empty list steps nothing, so its `time`,
    // `epoch` and `join` are in no hash, and a relay could make one up; the
    // floor takes only a place the head's `names_hash` binds.
    let mut held = before_first;
    for (i, l) in lists.iter().enumerate() {
        // What was shown up to the list before this one.
        let upto = (shown.named.len(), shown.unchecked.len(), shown.gone.len());
        for a in &l.added {
            let pin = match a.m.account() {
                Some(account) => (known.pins)(&account, l.time),
                None => PinThen::None,
            };
            match check_entry(a, l.time, pin, known.counters, known.own, &mut warnings) {
                Entry::Fine => shown.named.push(*a),
                Entry::Unchecked => {
                    shown.named.push(*a);
                    shown.unchecked.push(*a);
                }
                Entry::Failed(_) if removed_after(removals, head, l.epoch, &a.seat()) => {
                    shown.gone.push(a.seat());
                }
                Entry::Failed(why) => {
                    shown.named.truncate(upto.0);
                    shown.unchecked.truncate(upto.1);
                    shown.gone.truncate(upto.2);
                    return Ok(Fold::Hold {
                        why,
                        floor: held,
                        shown,
                        warnings,
                    });
                }
            }
        }
        if steps(i, l) {
            held = Some(NamesFloor::after(head.gen, l, after[i]));
        }
    }
    Ok(Fold::Take {
        floor: NamesFloor::of(head),
        shown,
        warnings,
    })
}

// ── Rule 6: gated groups ──────────────────────────────────────────────────

/// Rule 6 as every member checks it: `gated` changes only at an opening
/// header (`was` is the floor's or parent's), and a change to open is
/// reported. In a gated group, `conn_seats` is 0 (§5.10: every member checks
/// the signed count), and no keyholder is a guest (§5.6; §4.4 does not list
/// it among a member's checks, but a keyholder reads everything).
///
/// The `added` entries are not checked here: readers of a text group take
/// headers without the names. A writer checks them at its fold
/// (`fold_names`), a keyholder in every header it takes (`check_added`).
pub fn check_gated(h: &HeaderV1, was: Option<bool>) -> Result<Vec<Warning>, Refusal> {
    let warnings = match was {
        Some(was) => gated_turn(was, h)?,
        None => vec![],
    };
    if !h.gated {
        return Ok(warnings);
    }
    if h.conn_seats != 0 {
        return Err(Refusal::GuestSeat(None));
    }
    if h.keyholders.iter().any(|k| k.m.is_conn()) {
        return Err(Refusal::GuestKeyholder);
    }
    Ok(warnings)
}

/// Rules 6 and 8 as a keyholder checks each `added` entry of a header it
/// takes: no guest, every `IK` this device has a pin for matches it, and no
/// counter flagged at the header's `time`. It refuses the header and says
/// why, and takes the next opening header that names the refused seat in
/// `removed` (§4.4 rule 6). An app that shows the list on demand runs the
/// same check and shows a failed entry as failed. Open groups carry no names.
pub fn check_added(
    h: &HeaderV1,
    pins: Pins,
    counters: Counters,
    own: Option<[u8; 16]>,
) -> Result<(), Refusal> {
    let mut warnings = vec![];
    for a in h.added_list() {
        let pin = match a.m.account().and_then(|account| pins(&account)) {
            Some(p) => PinThen::Pin(p),
            None => PinThen::None,
        };
        if let Entry::Failed(why) = check_entry(a, h.time, pin, counters, own, &mut warnings) {
            return Err(why.refusal(own));
        }
    }
    Ok(())
}

// ── Rule 8: counters ──────────────────────────────────────────────────────

/// Rule 8 as every member checks it: no keyholder entry the parent's set did
/// not hold carries a counter flagged by `counter_flagged` at the header's
/// `time`. A flagged entry is refused; one of this device's own account says
/// so (`own` in the refusal), and the app warns that an old seat key of this
/// account was seated.
pub fn check_counters(
    h: &HeaderV1,
    parent_set: &[Keyholder],
    counters: Counters,
    own: Option<[u8; 16]>,
) -> Result<(), Refusal> {
    for k in h.keyholders.iter().filter(|k| !parent_set.contains(k)) {
        let Some(account) = k.m.account() else {
            continue;
        };
        if let Some(highest) = counter_flagged(k.n, h.time, counters(&account)) {
            return Err(Refusal::OldCounter {
                account,
                n: k.n,
                highest,
                own: own == Some(account),
            });
        }
    }
    Ok(())
}
