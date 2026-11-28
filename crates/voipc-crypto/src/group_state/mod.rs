//! The group epoch key on a client (docs/GROUP-KEY.md, plan part 3): one connection's state
//! for every group it is in, plain state with no I/O, in the style of `ChannelKeying`. The
//! desktop app (network.rs) and the browser (voipc-web) feed it the relay's frames and their
//! own posts, and carry out what it hands back (`GkOut`).
//!
//! - `member`: taking headers (§4.4) and the keys they bring: floors, `BK`, `CK`.
//! - `writer` and `reader`: posts under the epoch key (§5.8).
//! - `names`: a writer's fold of a gated group's names (§4.4 rule 4).
//! - `seat_keys`: the connection's seat pair, and the account's seat keys (§5.11).
//! - `holder` (C3c), `kept` (K1) and `voice` (V1): keyholder duty, kept history, voice keys.
//!
//! Every rule a header must pass is C1's (`group_key::rules`); none is re-implemented here.
//! Times: every `now` here is unix milliseconds; headers carry seconds.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::task::{Context, Poll, Waker};

use libsignal_protocol::IdentityKeyPair;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use voipc_protocol::gk;
use voipc_protocol::messages::{ClientMessage, ServerMessage};
use zeroize::Zeroizing;

use crate::group_key::{
    Floor, GroupKind, MemberId, NamesFloor, PinThen, SeatKeys, Seen, CLOCK_SLACK,
};
use crate::stores::SignalStores;
use crate::sync::{higher_counter, Counter};

pub use crate::sync::Pending;

mod copies;
mod holder;
mod kept;
mod member;
mod names;
mod reader;
pub(crate) mod seat_keys;
mod voice;
mod writer;

#[cfg(test)]
mod tests;

pub use copies::{Copies, Early, EarlyPost, KeptCopy, EARLY_WAIT_MS, JOIN_REFUSED};
pub use holder::{BuildJob, Built, HolderKeep};
pub use kept::PastEpoch;

use member::Member;

// ── What the host hands in ────────────────────────────────────────────────

/// What this app runs on: a keyholder's duty depends on it (§5.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Platform {
    Desktop,
    Phone,
    Browser,
}

impl Platform {
    /// `KeyholdVolunteer.platform`.
    pub fn code(self) -> u8 {
        match self {
            Platform::Desktop => gk::platform::DESKTOP,
            Platform::Phone => gk::platform::PHONE,
            Platform::Browser => gk::platform::BROWSER,
        }
    }
}

/// A stored group's floor in the account's vault (3d), as `AccountSync` has it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VaultFloor {
    /// The pages are not in yet: no header of the group is taken before they are.
    Pending,
    /// None kept, or no vault (a guest, a memory-only group).
    None,
    Some(Box<Floor>, Option<NamesFloor>),
}

/// A connection's start, at `ServerMessage::GroupKeys`.
pub struct GkStart {
    /// The relay uses the group key; with `false` only kept history is read.
    pub on: bool,
    /// The run of this relay's `r:` ids.
    pub run: [u8; 16],
    /// The relay's clock, unix seconds.
    pub relay_clock: u64,
    pub platform: Platform,
    /// "Help hold keys" (U1's switch).
    pub help_hold_keys: bool,
    /// This connection's user id.
    pub user_id: u32,
    /// The account's identity when signed in, else the connection's own.
    pub identity: IdentityKeyPair,
    pub account: Option<[u8; 16]>,
    /// The account's `item.seat_kem` once its vault save settled (`AccountSession::seat_keys`).
    pub seat_keys: Option<SeatKeys>,
    /// What this device kept for this relay and account (native: `gk_local.bin`).
    pub local: Option<LocalGk>,
    /// The page is shown (browser); a native app is always.
    pub visible: bool,
}

/// A channel the connection is in, with its group (`group_id`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GkTrack {
    pub channel_id: u32,
    pub group: String,
    pub kind: GroupKind,
    /// An anonymous room: no name is shown.
    pub anonymous: bool,
    /// Members are hidden but from admins.
    pub hide_members: bool,
    pub viewer_admin: bool,
    pub keeps_history: bool,
}

impl GkTrack {
    /// Whether names may be shown in this room (3h).
    fn shows_names(&self) -> bool {
        !self.anonymous && (!self.hide_members || self.viewer_admin)
    }
}

/// The group id the app derives for a channel (3c): its log's id when it keeps one (`c:`),
/// else `r:<run>:<channel id>`; a voice room is always `r:`. The relay names a stored group
/// by its conversation id the same way (R1 gk/mod.rs `stored_id`).
pub fn group_id(kind: GroupKind, log: &str, run: &[u8; 16], channel_id: u32) -> String {
    if kind == GroupKind::Text && !log.is_empty() {
        return log.to_string();
    }
    format!("r:{}:{channel_id}", voipc_protocol::conv::hex(run))
}

/// What a header and a post are checked against (3d): the account's pins, the time this
/// account first saw each, and the highest seat-key counter seen per account. An account's
/// `AccountSync`, or for a guest a `MemoryPins`. Nothing is asked of it before `ready`.
pub trait GkPins {
    /// Every answer below is in: an account's pins and its group-key pages. Before that no
    /// header is taken, in any group (`Pending`): an empty book would pass an old seat or a
    /// swapped key as never seen.
    fn ready(&self) -> bool;
    /// The identity key pinned for `account`, 32 raw bytes.
    fn pin(&self, account: &[u8; 16]) -> Option<[u8; 32]>;
    /// C1's `PinsAt`: the pin as it stood at `time` (unix seconds), as far as this device knows.
    fn pin_then(&self, account: &[u8; 16], time: u64) -> PinThen;
    /// The highest counter seen for `account`, with its rotation's `made`.
    fn seen(&self, account: &[u8; 16]) -> Option<Seen>;
    /// `account` has no pin, and a signature by `ik` was taken on its word (TOFU).
    fn pin_new(&mut self, account: [u8; 16], ik: [u8; 32], now: u64);
    /// An endorsement of `account` (P3 finding 5): `rotation` for its vault seat (0x01), else a
    /// pair made under that counter whose `made` was checked (`endorsement_time_ok`).
    fn raise(&mut self, account: [u8; 16], seen: Seen, rotation: bool);
}

/// The highest counter seen per account, in memory (a guest's, or `LocalGk::counters`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeenBook(BTreeMap<[u8; 16], Counter>);

impl SeenBook {
    pub fn seen(&self, account: &[u8; 16]) -> Option<Seen> {
        self.0.get(account).map(Counter::seen)
    }

    /// Whether it raised what is held.
    pub fn raise(&mut self, account: [u8; 16], seen: Seen, rotation: bool) -> bool {
        let new = Counter {
            n: seen.n,
            made: seen.made,
            rotation,
        };
        let held = self.0.get(&account).copied();
        let merged = higher_counter(held, Some(new)).expect("one is some");
        if held == Some(merged) {
            return false;
        }
        self.0.insert(account, merged);
        true
    }

    /// Every row of `other` raised into this one, as `raise` takes each (`higher_counter`).
    /// Whether any moved.
    pub fn merge(&mut self, other: &SeenBook) -> bool {
        let mut moved = false;
        for (account, c) in &other.0 {
            moved |= self.raise(*account, c.seen(), c.rotation);
        }
        moved
    }

    /// Once it holds more than `most + slack` accounts, back to `most`: those whose counter
    /// is oldest (`made`) go, as on the vault's counter pages (`sync::gk_floors`). Whether
    /// any went. The slack spares a full book a pass over every row at each new account.
    pub fn bound(&mut self, most: usize, slack: usize) -> bool {
        let over = self.0.len().saturating_sub(most);
        if over <= slack {
            return false;
        }
        let mut ages: Vec<(u64, [u8; 16])> = self.0.iter().map(|(a, c)| (c.made, *a)).collect();
        ages.select_nth_unstable(over - 1);
        for (_, account) in &ages[..over] {
            self.0.remove(account);
        }
        true
    }
}

/// At most this many accounts in `LocalGk::mirror`: about what the vault's 32 counter pages
/// hold (`sync::gk_floors::COUNTER_PAGES`, rows of 25 to 40 bytes on pages of 47 KiB).
const MIRROR_MOST: usize = 32 * 1024;

/// A signed-in account's book (`AccountSync`) as `GroupKeying` checks against it on a
/// device that keeps `LocalGk` (dive 1 F1): every counter the book answers and every one
/// raised in it is copied into `mirror`, and `seen` answers the higher of the two. The
/// book's counters live only in the vault's pages, and a relay that withholds them would
/// otherwise take with them every counter this device met, and rule 8 with them, in folds,
/// keyholder entries and a keyholder's checks alike. Of one `n` the earlier `made` stands, as
/// `higher_counter` keeps it for two pair rows: a book row the relay let start afresh (the
/// pages withheld, the row raised again from a new pair) must not move a counter this device
/// met (review P1).
struct Mirrored<'a> {
    book: &'a mut dyn GkPins,
    /// `seen` takes `&self`, and keeps what the book answered.
    mirror: RefCell<SeenBook>,
    moved: Cell<bool>,
}

impl Mirrored<'_> {
    fn keep(&self, account: [u8; 16], seen: Seen, rotation: bool) {
        if self.mirror.borrow_mut().raise(account, seen, rotation) {
            self.moved.set(true);
        }
    }
}

impl GkPins for Mirrored<'_> {
    fn ready(&self) -> bool {
        self.book.ready()
    }

    fn pin(&self, account: &[u8; 16]) -> Option<[u8; 32]> {
        self.book.pin(account)
    }

    fn pin_then(&self, account: &[u8; 16], time: u64) -> PinThen {
        self.book.pin_then(account, time)
    }

    fn seen(&self, account: &[u8; 16]) -> Option<Seen> {
        let book = self.book.seen(account);
        // What the book answered, whether it was raised here or by another device of the
        // account; a rotation's `made` is not told apart in an answer
        if let Some(s) = book {
            self.keep(*account, s, false);
        }
        let mine = self.mirror.borrow().seen(account);
        match (book, mine) {
            (Some(b), Some(m)) if m.n > b.n => Some(m),
            (Some(b), Some(m)) if m.n == b.n => Some(Seen {
                n: b.n,
                made: b.made.min(m.made),
            }),
            (Some(b), _) => Some(b),
            (None, m) => m,
        }
    }

    fn pin_new(&mut self, account: [u8; 16], ik: [u8; 32], now: u64) {
        self.book.pin_new(account, ik, now);
    }

    fn raise(&mut self, account: [u8; 16], seen: Seen, rotation: bool) {
        self.book.raise(account, seen, rotation);
        self.keep(account, seen, rotation);
    }
}

/// `GkPins` for a guest, or a relay without accounts: pins taken this connection, each from
/// when it was taken.
#[derive(Clone, Debug, Default)]
pub struct MemoryPins {
    pins: HashMap<[u8; 16], ([u8; 32], u64)>,
    pub counters: SeenBook,
}

impl GkPins for MemoryPins {
    fn ready(&self) -> bool {
        true
    }

    fn pin(&self, account: &[u8; 16]) -> Option<[u8; 32]> {
        self.pins.get(account).map(|(ik, _)| *ik)
    }

    fn pin_then(&self, account: &[u8; 16], time: u64) -> PinThen {
        match self.pins.get(account) {
            None => PinThen::None,
            Some((ik, since)) if time > since.saturating_add(CLOCK_SLACK) => PinThen::Pin(*ik),
            Some(_) => PinThen::Unknown,
        }
    }

    fn seen(&self, account: &[u8; 16]) -> Option<Seen> {
        self.counters.seen(account)
    }

    fn pin_new(&mut self, account: [u8; 16], ik: [u8; 32], now: u64) {
        self.pins.entry(account).or_insert((ik, now / 1000));
    }

    fn raise(&mut self, account: [u8; 16], seen: Seen, rotation: bool) {
        self.counters.raise(account, seen, rotation);
    }
}

/// Why an endorsement met in a due (a joiner, a candidate) or a header is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndorsementBad {
    /// Rule 8: a counter below the highest seen for its account, made after that one.
    OldCounter { n: u32, highest: u32 },
    /// A guest's endorsement carries counter 0 (C1 note 2).
    GuestCounter,
    /// A connection or desktop pair (0x02, 0x03) made more than `CLOCK_SLACK` from the header
    /// or join time it comes with (plan 13).
    Time,
}

/// The counter rules for an endorsement this device met, whose signature the caller checked
/// against `account`'s pinned `IK` (or, with no account, the connection's own), at the time
/// `at` (unix seconds) of the header or join it comes with: a guest's counter is 0; a pair
/// (0x02, 0x03) is made within `CLOCK_SLACK` of `at`, since it is made just before its join,
/// and one dated far from it would move a counter's time where rule 8 never, or always,
/// flags; rule 8. One that passes counts toward its account's highest (P3 finding 5): a vault
/// seat's (0x01) `made` is its rotation's, made before it could be met, so one dated after `at`
/// counts from `at`: a rotation dated ahead (a fast clock, or a holder of the account's
/// identity key) would otherwise stop rule 8 flagging the account's lower counters until
/// then (RV q8-q11).
pub fn take_endorsement(
    pins: &mut dyn GkPins,
    account: Option<[u8; 16]>,
    e: &crate::group_key::Endorsement,
    at: u64,
) -> Result<(), EndorsementBad> {
    use crate::group_key::{counter_flagged, Origin};
    let Some(account) = account else {
        return if e.n == 0 {
            Ok(())
        } else {
            Err(EndorsementBad::GuestCounter)
        };
    };
    let rotation = e.origin == Origin::VaultSeat;
    if !rotation && e.made.abs_diff(at) > CLOCK_SLACK {
        return Err(EndorsementBad::Time);
    }
    if let Some(highest) = counter_flagged(e.n, at, pins.seen(&account)) {
        return Err(EndorsementBad::OldCounter { n: e.n, highest });
    }
    let seen = Seen {
        n: e.n,
        made: if rotation { e.made.min(at) } else { e.made },
    };
    pins.raise(account, seen, rotation);
    Ok(())
}

/// What a call needs of the host besides the stores: the book, and the time (ms).
pub struct GkCtx<'a> {
    pub pins: &'a mut dyn GkPins,
    pub now: u64,
}

impl GkCtx<'_> {
    fn secs(&self) -> u64 {
        self.now / 1000
    }
}

/// What this device keeps per relay and account (3d, native: `gk_local.bin`, N1).
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct LocalGk {
    pub floors: BTreeMap<String, LocalFloor>,
    pub counters: SeenBook,
    /// The keyholder's own (C3c).
    pub holder: HolderKeep,
    /// The group id each text channel was last followed under, where one was stored (a
    /// relay that gives a channel another id gets a first generation told as made anew,
    /// dive 1 F6).
    pub channels: BTreeMap<u32, String>,
    /// A signed-in account's: the highest counters this device raised in its book, or read
    /// from it, kept here as well as in the vault's pages (`Mirrored`, dive 1 F1). Bounded
    /// as those pages are (`MIRROR_MOST`). A guest's are `counters`, the host's own book.
    pub mirror: SeenBook,
}

impl LocalGk {
    /// Counters this device kept of the account apart from this `LocalGk` (the browser's,
    /// past a reload) into `mirror`, the higher of each standing, and bounded as it is
    /// (`MIRROR_MOST`). Whether it moved.
    pub fn mirror_in(&mut self, kept: &SeenBook) -> bool {
        let moved = self.mirror.merge(kept);
        self.mirror.bound(MIRROR_MOST, MIRROR_MOST / 16) || moved
    }
}

/// One group's floor as this device keeps it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalFloor {
    pub floor: Floor,
    /// The keyholder header the floor names: body and signature.
    pub kh: Option<(Vec<u8>, Vec<u8>)>,
    /// The floor's own header: body and signature. `EpochFloorAhead` carries it when a
    /// relay restored from an old backup answers below the floor (§5.7).
    #[serde(default)]
    pub head: Option<(Vec<u8>, Vec<u8>)>,
    /// The keyholder headers before `kh`, newest first, back to the generation's start or
    /// its last KeyholdersRemove (at most 8): the sets a welcome's or row's maker may come
    /// from (`Member::maker_ok`), and a KRK welcome's (`holder.rs` `krk_makers`), after a
    /// restart (RV).
    #[serde(default)]
    pub kh_chain: Vec<(Vec<u8>, Vec<u8>)>,
    pub names: Option<NamesFloor>,
    /// When this device took it, by its own clock (unix seconds).
    pub taken: u64,
}

// ── What it hands back ────────────────────────────────────────────────────

/// An epoch's key as a writer of kept history uses it (C4).
#[derive(Clone)]
pub struct GkEpoch {
    pub group: String,
    pub gen: [u8; 16],
    pub epoch: u32,
    pub d_e: [u8; 32],
    pub ck: Zeroizing<[u8; 32]>,
}

/// A post that opened: `TextPost`'s fields, as the app shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenedPost {
    pub channel_id: u32,
    pub group: String,
    pub user_id: u32,
    pub username: String,
    pub account: Option<[u8; 16]>,
    pub is_admin: bool,
    pub is_moderator: bool,
    pub envelope: Vec<u8>,
    pub timestamp: u64,
}

/// Voice key material for one room (V1, `MediaKeyRing` in gk mode).
pub struct VoiceKeys {
    pub channel_id: u32,
    pub group: String,
    pub gen: [u8; 16],
    /// `(e, D_e, CK_e)`, at most two.
    pub epochs: Vec<(u32, [u8; 32], Zeroizing<[u8; 32]>)>,
    pub own: (MemberId, [u8; 8]),
    pub seats: Vec<(u32, MemberId, [u8; 8])>,
    pub switch_at: u64,
    pub new_generation: bool,
}

/// What becomes of our posts in a group (`gk-state`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GkState {
    Ok,
    /// The keys are late; `waiting`: a post of ours waits for them.
    Late {
        waiting: bool,
    },
    /// A fold held our posts.
    Held(HeldWhy),
    NoKeyholder,
    /// The relay refused: its reason.
    Refused(String),
}

/// Why a fold held our posts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeldWhy {
    Guest,
    Pin,
    /// An old key of this account was listed (`None`: not to be named).
    OldCounter(Option<MemberId>),
}

/// Why a held post was given up at `HOLD_MS` (`gk-post-dropped`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dropped {
    NoKeyholder,
    Late,
    Unchecked,
    /// Told by `GkState::Refused`, which goes first.
    Refused,
}

/// `gk-warning` kinds (U1's `WARNINGS`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Warn {
    UnnamedSeats,
    OldSeatKey,
    FloorAhead,
    EntrySwapped,
    LeaverMayHear,
    GatedOpened,
    /// This device's clock is behind the relay's by more than `CLOCK_SLACK` (`n`: minutes).
    ClockSlow,
    /// Ahead of it (`n`: minutes).
    ClockFast,
}

impl Warn {
    fn kind(self) -> &'static str {
        match self {
            Warn::UnnamedSeats => "unnamed_seats",
            Warn::OldSeatKey => "old_seat_key",
            Warn::FloorAhead => "floor_ahead",
            Warn::EntrySwapped => "entry_swapped",
            Warn::LeaverMayHear => "leaver_may_hear",
            Warn::GatedOpened => "gated_opened",
            Warn::ClockSlow => "clock_slow",
            Warn::ClockFast => "clock_fast",
        }
    }
}

/// What the app tells its user (3h), per channel. Member ids, not names: the host knows who
/// goes by what (`GkNames`). A room that hides names never gets one here (`None`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GkEvent {
    State {
        channel_id: u32,
        state: GkState,
    },
    PostDropped {
        channel_id: u32,
        why: Dropped,
    },
    /// New readers a fold showed; `unchecked`: listed with no name to show.
    Readers {
        channel_id: u32,
        named: Vec<MemberId>,
        unchecked: u32,
        older_unnamed: bool,
    },
    /// The keyholder set as it stands; `None` for one not to be named.
    Keyholders {
        channel_id: u32,
        holders: Vec<Option<MemberId>>,
    },
    /// Made anew (a new generation, a Regenesis), by whom where it may be said.
    Anew {
        channel_id: u32,
        by: Option<MemberId>,
    },
    Warning {
        channel_id: u32,
        kind: Warn,
        n: u32,
    },
}

/// Who goes by what here, and who is online: the host's roster.
pub trait GkNames {
    fn name(&self, m: &MemberId) -> Option<String>;
    fn online(&self, m: &MemberId) -> bool;
}

impl GkEvent {
    pub fn channel_id(&self) -> u32 {
        match self {
            GkEvent::State { channel_id, .. }
            | GkEvent::PostDropped { channel_id, .. }
            | GkEvent::Readers { channel_id, .. }
            | GkEvent::Keyholders { channel_id, .. }
            | GkEvent::Anew { channel_id, .. }
            | GkEvent::Warning { channel_id, .. } => *channel_id,
        }
    }

    /// The front end's event (U1's contract), name and payload, as both backends emit it.
    pub fn to_wire(&self, names: &dyn GkNames) -> (&'static str, Value) {
        let name = |m: &Option<MemberId>| m.as_ref().and_then(|m| names.name(m));
        match self {
            GkEvent::State { channel_id, state } => {
                let (s, why, who) = match state {
                    GkState::Ok => ("ok", String::new(), None),
                    GkState::Late { waiting } => {
                        let why = if *waiting { "waiting" } else { "" };
                        ("late", why.to_string(), None)
                    }
                    GkState::Held(HeldWhy::Guest) => ("held", "guest".into(), None),
                    GkState::Held(HeldWhy::Pin) => ("held", "pin".into(), None),
                    GkState::Held(HeldWhy::OldCounter(m)) => {
                        ("held", "old_counter".into(), name(m))
                    }
                    GkState::NoKeyholder => ("no_keyholder", String::new(), None),
                    GkState::Refused(reason) => ("refused", reason.clone(), None),
                };
                let mut v = json!({ "channel_id": channel_id, "state": s, "why": why });
                if let Some(n) = who {
                    v["name"] = n.into();
                }
                ("gk-state", v)
            }
            GkEvent::PostDropped { channel_id, why } => {
                let why = match why {
                    Dropped::NoKeyholder => "no_keyholder",
                    Dropped::Late => "late",
                    Dropped::Unchecked => "unchecked",
                    Dropped::Refused => "refused",
                };
                (
                    "gk-post-dropped",
                    json!({ "channel_id": channel_id, "why": why }),
                )
            }
            GkEvent::Readers {
                channel_id,
                named,
                unchecked,
                older_unnamed,
            } => {
                let shown: Vec<String> = named.iter().filter_map(|m| names.name(m)).collect();
                let more = *unchecked as usize + named.len() - shown.len();
                (
                    "gk-readers",
                    json!({
                        "channel_id": channel_id,
                        "names": shown,
                        "unchecked": more,
                        "older_unnamed": older_unnamed,
                    }),
                )
            }
            GkEvent::Keyholders {
                channel_id,
                holders,
            } => {
                let mut list: Vec<(bool, String)> = holders
                    .iter()
                    .map(|m| {
                        let online = m.as_ref().is_some_and(|m| names.online(m));
                        (online, name(m).unwrap_or_default())
                    })
                    .collect();
                list.sort_by_key(|(online, _)| !*online);
                let holders: Vec<Value> = list
                    .into_iter()
                    .map(|(online, name)| json!({ "name": name, "online": online, "kind": "" }))
                    .collect();
                (
                    "gk-keyholders",
                    json!({ "channel_id": channel_id, "holders": holders }),
                )
            }
            GkEvent::Anew { channel_id, by } => (
                "gk-anew",
                json!({ "channel_id": channel_id, "by": name(by).unwrap_or_default() }),
            ),
            GkEvent::Warning {
                channel_id,
                kind,
                n,
            } => (
                "gk-warning",
                json!({ "channel_id": channel_id, "kind": kind.kind(), "n": n }),
            ),
        }
    }
}

/// What the host does after a call.
#[derive(Default)]
pub struct GkOut {
    pub send: Vec<ClientMessage>,
    pub posts: Vec<OpenedPost>,
    pub events: Vec<GkEvent>,
    /// Floors of stored groups for the vault (`AccountSession::gk_put_floors`).
    pub vault_floors: Vec<(String, Floor, Option<NamesFloor>)>,
    /// `local()` moved: save it (coalesced, but before anything sent under a new head goes).
    pub local_dirty: bool,
    pub voice: Vec<VoiceKeys>,
    /// Past epochs asked by `past_epoch` that are in now (C4).
    pub past_ready: Vec<(String, [u8; 16], u32)>,
    /// Self-rows to keep (`AccountSession::gk_self_rows`, as `SelfRowPut`).
    pub self_rows: Vec<gk::SelfRowIn>,
    /// Held posts that went out now, each under its epoch: file the kept copy (C4) under it.
    pub released: Vec<(u32, [u8; 16], GkEpoch)>,
    /// A keyholder job waits (`take_build`).
    pub build_ready: bool,
    /// The relay holds no seat keys of this account: publish them again
    /// (`AccountSession::seat_keys_wanted`).
    pub seat_keys_wanted: bool,
}

// ── The state ─────────────────────────────────────────────────────────────

/// Who this connection is, as every part needs it.
pub(super) struct Who {
    pub(super) on: bool,
    pub(super) run: [u8; 16],
    /// C3c: a volunteer's platform, and its clock against the relay's (`DECLINE_CLOCK`).
    pub(super) relay_clock: u64,
    pub(super) platform: Platform,
    pub(super) help: bool,
    pub(super) visible: bool,
    pub(super) user_id: u32,
    pub(super) identity: IdentityKeyPair,
    pub(super) account: Option<[u8; 16]>,
    pub(super) seat_keys: Option<SeatKeys>,
    pub(super) conn: seat_keys::ConnSeat,
}

/// One connection's group keys.
#[derive(Default)]
pub struct GroupKeying {
    who: Option<Who>,
    groups: BTreeMap<String, Member>,
    channels: HashMap<u32, String>,
    local: Option<LocalGk>,
    duty: holder::Duty,
    kept: kept::Kept,
    voice: voice::Voice,
    /// The identity key each connection writer (`Conn(u)`) first signed with (§5.8).
    tofu: reader::Tofu,
    /// The relay's clock less this device's at `start`, seconds.
    skew: i64,
    /// Channels told this device's clock is off (`clock_note`).
    clock_told: std::collections::HashSet<u32>,
}

impl GroupKeying {
    /// At `GroupKeys`: a volunteer offers to hold keys (`help_hold_keys`). With `on: false`
    /// only kept history is read. Local floors of `r:` groups of another run go. With no
    /// `local` (the browser, a first run) floors are kept from now in memory (3d), `r:`
    /// groups' too: `local()` hands them to the next connection to the same relay.
    pub fn start(&mut self, s: GkStart) -> GkOut {
        let mut out = GkOut::default();
        self.skew = s.relay_clock as i64 - (crate::time::now_millis() / 1000) as i64;
        self.clock_told.clear();
        let mut local = s.local.unwrap_or_default();
        let run = voipc_protocol::conv::hex(&s.run);
        let before = local.floors.len();
        local.floors.retain(|g, _| match g.strip_prefix("r:") {
            Some(rest) => rest.split(':').next() == Some(run.as_str()),
            None => true,
        });
        out.local_dirty = local.floors.len() != before;
        self.duty.keep_in(&local.holder); // C3c
        self.local = Some(local);
        let mut who = Who {
            on: s.on,
            run: s.run,
            relay_clock: s.relay_clock,
            platform: s.platform,
            help: s.help_hold_keys,
            visible: s.visible,
            user_id: s.user_id,
            identity: s.identity,
            account: s.account,
            seat_keys: s.seat_keys,
            conn: seat_keys::ConnSeat::default(),
        };
        if s.on {
            self.duty.start(&mut who, &mut out);
        }
        self.who = Some(who);
        out
    }

    /// The channel's group, from now. A stored group of a signed-in account takes no header
    /// while its vault floor is `Pending` (`floors_in`). An id of no shape the channel may
    /// have is not tracked: a voice room is always `r:`, and an `r:` id names this run and
    /// this channel (C1 note 3). The same group again (the channel changed otherwise, as at
    /// every `ChannelUpdated`) keeps what it holds: its head, its keys, its held posts.
    pub fn track(&mut self, t: GkTrack, vault: VaultFloor) -> GkOut {
        let out = GkOut::default();
        let Some(run) = self.who.as_ref().map(|w| voipc_protocol::conv::hex(&w.run)) else {
            return out;
        };
        let shaped = crate::group_key::valid_group_id(&t.group)
            && match t.group.strip_prefix("r:") {
                Some(rest) => rest == format!("{run}:{}", t.channel_id),
                None => t.kind == GroupKind::Text,
            };
        if !shaped {
            tracing::warn!(group = %t.group, "not a group id this channel may have");
            return out;
        }
        let same = self.channels.get(&t.channel_id) == Some(&t.group);
        if let Some(m) = self
            .groups
            .get_mut(&t.group)
            .filter(|m| same && m.t.kind == t.kind)
        {
            m.t = t;
            return out;
        }
        // The id this channel was followed under before, this run or (kept locally) earlier.
        // A move to or from a stored id is a new start the user is told of; a memory id's
        // run changing is a relay start, which starts those anew by design
        let before = self.channels.get(&t.channel_id).cloned().or_else(|| {
            self.local
                .as_ref()
                .and_then(|l| l.channels.get(&t.channel_id).cloned())
        });
        let moved = t.kind == GroupKind::Text
            && before.as_ref().is_some_and(|b| {
                *b != t.group && (b.starts_with("c:") || t.group.starts_with("c:"))
            });
        let mut out = self.untrack(t.channel_id);
        let local = self
            .local
            .as_ref()
            .and_then(|l| l.floors.get(&t.group))
            .cloned();
        let group = t.group.clone();
        // `local.channels` takes the new id only once its group holds a floor (`local_floor`):
        // until then a reconnect still finds the old id and tells the move (review A-P1)
        self.channels.insert(t.channel_id, group.clone());
        let fresh = local.is_none();
        let mut m = Member::new(t, local);
        m.group_moved = moved && fresh;
        match vault {
            VaultFloor::Pending => m.vault_pending = true,
            VaultFloor::None => {}
            VaultFloor::Some(f, n) => m.vault_in(*f, n),
        }
        if let Some(who) = self.who.as_mut() {
            m.fetch(who, crate::time::now_millis(), &mut out);
        }
        self.groups.insert(group, m);
        out
    }

    /// The vault's pages came in, or another device raised this group's floor: the floor in
    /// use is the higher of the two. A group not tracked is no business of this.
    pub fn floors_in(&mut self, group: &str, f: Option<(Floor, Option<NamesFloor>)>) -> GkOut {
        let mut out = GkOut::default();
        let (Some(who), Some(m)) = (self.who.as_mut(), self.groups.get_mut(group)) else {
            return out;
        };
        m.vault_pending = false;
        if let Some((floor, names)) = f {
            m.vault_in(floor, names);
        }
        let now = crate::time::now_millis();
        m.fetch(who, now, &mut out);
        out
    }

    /// Out of the channel: posts still held for it are given up (`PostDropped`).
    pub fn untrack(&mut self, channel_id: u32) -> GkOut {
        let mut out = GkOut::default();
        if let Some(group) = self.channels.remove(&channel_id) {
            if let Some(mut m) = self.groups.remove(&group) {
                writer::drop_held(&mut m, &mut out);
            }
            self.duty.untrack(&group);
        }
        self.voice.untrack(channel_id); // V1
        out
    }

    /// A frame from the relay.
    pub fn frame(&mut self, st: &mut SignalStores, msg: &ServerMessage, c: GkCtx) -> GkOut {
        let mut out = self.mirrored(c, |k, c| k.frame_in(st, msg, c));
        self.clock_note(&mut out);
        out
    }

    /// `f` with a signed-in account's book seen through this device's mirror of its counters
    /// (`Mirrored`, dive 1 F1). Every call that checks against the book comes here. What
    /// moved the mirror is saved with the floors (`local_dirty`).
    fn mirrored(&mut self, c: GkCtx, f: impl FnOnce(&mut Self, GkCtx) -> GkOut) -> GkOut {
        let signed_in = self.who.as_ref().is_some_and(|w| w.account.is_some());
        let Some(local) = self.local.as_mut().filter(|_| signed_in) else {
            return f(self, c);
        };
        let mut book = Mirrored {
            book: c.pins,
            mirror: RefCell::new(std::mem::take(&mut local.mirror)),
            moved: Cell::new(false),
        };
        let mut out = f(
            self,
            GkCtx {
                pins: &mut book,
                now: c.now,
            },
        );
        let mut mirror = book.mirror.into_inner();
        let pruned = mirror.bound(MIRROR_MOST, MIRROR_MOST / 16);
        out.local_dirty |= book.moved.get() || pruned;
        if let Some(local) = self.local.as_mut() {
            local.mirror = mirror;
        }
        out
    }

    /// Where keys come late on this device because its clock is more than `CLOCK_SLACK` off
    /// the relay's, the channel is told so, once a connection: rule 7 refuses headers dated
    /// ahead of a slow clock, and a fast one counts every epoch past the writers' 70 min,
    /// and "keys late" alone points at the keyholders (dive 2 F5).
    fn clock_note(&mut self, out: &mut GkOut) {
        let off = self.skew.unsigned_abs();
        if off <= CLOCK_SLACK {
            return;
        }
        let late: Vec<u32> = out
            .events
            .iter()
            .filter_map(|e| match e {
                GkEvent::State {
                    channel_id,
                    state: GkState::Late { .. },
                }
                | GkEvent::PostDropped {
                    channel_id,
                    why: Dropped::Late,
                } => Some(*channel_id),
                _ => None,
            })
            .collect();
        for channel_id in late {
            if self.clock_told.insert(channel_id) {
                out.events.push(GkEvent::Warning {
                    channel_id,
                    // The relay ahead of this device: this device's clock is slow
                    kind: if self.skew > 0 {
                        Warn::ClockSlow
                    } else {
                        Warn::ClockFast
                    },
                    n: u32::try_from(off / 60).unwrap_or(u32::MAX),
                });
            }
        }
    }

    fn frame_in(&mut self, st: &mut SignalStores, msg: &ServerMessage, mut c: GkCtx) -> GkOut {
        let mut out = GkOut::default();
        let Some(who) = self.who.as_mut() else {
            return out;
        };
        let group = match msg {
            ServerMessage::EpochIn { group, .. }
            | ServerMessage::EpochWait { group, .. }
            | ServerMessage::EpochExit { group, .. }
            | ServerMessage::EpochPostIn { group, .. }
            | ServerMessage::EpochBlob { group, .. }
            | ServerMessage::EpochNamesIn { group, .. }
            | ServerMessage::EpochRefused { group, .. }
            | ServerMessage::VoiceSeats { group, .. } => group,
            ServerMessage::EpochDue { .. }
            | ServerMessage::EpochStale { .. }
            | ServerMessage::EpochLists { .. }
            | ServerMessage::KeyringIn { .. } => {
                self.duty
                    .frame(who, &mut self.groups, msg, &mut c, &mut out);
                return out;
            }
            // The host's: it files that post's kept copy (`Copies::taken`)
            ServerMessage::EpochPostTaken { .. } => return out,
            _ => return out,
        };
        let Some(m) = self.groups.get_mut(group) else {
            return out;
        };
        let mut taken = false;
        match msg {
            ServerMessage::EpochIn {
                part, last, piece, ..
            } => {
                if let Some(p) = m.part_in(*part, *last, piece) {
                    m.take_in(who, &mut self.duty, &mut self.kept, p, &mut c, &mut out);
                    taken = true;
                }
            }
            ServerMessage::EpochWait { why, detail, .. } => {
                m.on_wait(who, *why, detail, &mut c, &mut out)
            }
            ServerMessage::EpochExit { gen, seq, .. } => m.writer.exit(*gen, *seq, c.now),
            ServerMessage::EpochPostIn { .. } => {
                reader::post_in(m, who, st, &mut self.tofu, msg, &mut c, &mut out)
            }
            ServerMessage::EpochBlob { .. } => {
                reader::blob_in(m, who, st, &mut self.tofu, msg, &mut c, &mut out)
            }
            ServerMessage::EpochNamesIn {
                part, last, piece, ..
            } => {
                if let Some(pieces) = m.names.part_in(*part, *last, piece) {
                    if let Some(p) = names::names_in(m, pieces) {
                        m.take_in(who, &mut self.duty, &mut self.kept, p, &mut c, &mut out);
                    }
                    taken = true;
                }
            }
            // K1: only ever an `at` entry's answer (kept history)
            ServerMessage::EpochRefused {
                what: gk::refused_what::FETCH,
                why: gk::refused_why::NOT_STORED,
                ..
            } => self.kept.not_stored(who, m, &mut out),
            // K1: the oldest kept frame's while none of it is answered (`Kept::rate`)
            ServerMessage::EpochRefused {
                what: gk::refused_what::FETCH,
                why: gk::refused_why::RATE,
                ..
            } if self.kept.rate(m) => {}
            ServerMessage::EpochRefused {
                what, why, detail, ..
            } => m.on_refused(who, *what, *why, detail, &mut c, &mut out),
            ServerMessage::VoiceSeats {
                part, last, piece, ..
            } if m.voice_part_in(*part, *last, piece) => {
                self.voice.seats_in(who, m, &mut out);
            }
            _ => {}
        }
        if taken {
            self.after_take(group, st, &mut c, &mut out);
        }
        out
    }

    /// After a header was taken: held posts may go, queued posts may open, voice keys move.
    fn after_take(&mut self, group: &str, st: &mut SignalStores, c: &mut GkCtx, out: &mut GkOut) {
        self.duty_saw(group, out); // C3c
        let (Some(who), Some(m)) = (self.who.as_mut(), self.groups.get_mut(group)) else {
            return;
        };
        let moved = m.take_moved();
        // V1: voice keys go out whenever the head epoch's key is new; a gated room folds
        self.voice.after_take(who, m, moved, c, out);
        reader::retry(m, who, st, &mut self.tofu, c, out);
        writer::flush(m, who, st, c, out);
        if moved {
            m.fresh(c.secs(), out);
        }
        if moved && self.local.is_some() {
            self.local_floor(group);
            out.local_dirty = true;
        }
    }

    /// Writes a group's floor into `local`.
    fn local_floor(&mut self, group: &str) {
        let (Some(local), Some(m)) = (self.local.as_mut(), self.groups.get(group)) else {
            return;
        };
        if let Some(f) = m.local_floor() {
            local.floors.insert(group.to_string(), f);
            if m.t.kind == GroupKind::Text && group.starts_with("c:") {
                local.channels.insert(m.t.channel_id, group.to_string());
            }
        }
    }

    /// A post of ours to `channel_id` (`post_id`: the app's, for `released`).
    pub fn post(
        &mut self,
        st: &mut SignalStores,
        channel_id: u32,
        post_id: [u8; 16],
        envelope: &[u8],
        c: GkCtx,
    ) -> GkOut {
        let mut out = self.mirrored(c, |k, c| k.post_in(st, channel_id, post_id, envelope, c));
        self.clock_note(&mut out);
        out
    }

    fn post_in(
        &mut self,
        st: &mut SignalStores,
        channel_id: u32,
        post_id: [u8; 16],
        envelope: &[u8],
        mut c: GkCtx,
    ) -> GkOut {
        let mut out = GkOut::default();
        let Some(group) = self.channels.get(&channel_id) else {
            return out;
        };
        let (Some(who), Some(m)) = (self.who.as_mut(), self.groups.get_mut(group)) else {
            return out;
        };
        m.writer.hold(post_id, envelope.to_vec(), c.now);
        writer::flush(m, who, st, &mut c, &mut out);
        out
    }

    /// Every second or so while connected: what waits goes again, what waited too long is
    /// given up.
    pub fn tick(&mut self, st: &mut SignalStores, c: GkCtx) -> GkOut {
        let mut out = self.mirrored(c, |k, c| k.tick_in(st, c));
        self.clock_note(&mut out);
        out
    }

    fn tick_in(&mut self, st: &mut SignalStores, mut c: GkCtx) -> GkOut {
        let mut out = GkOut::default();
        let groups: Vec<String> = self.groups.keys().cloned().collect();
        for group in groups {
            let (Some(who), Some(m)) = (self.who.as_mut(), self.groups.get_mut(&group)) else {
                continue;
            };
            if let Some(p) = m.waiting.take() {
                m.take_in(who, &mut self.duty, &mut self.kept, p, &mut c, &mut out);
            }
            names::tick(m, &c);
            m.tick(who, &mut c, &mut out);
            writer::tick(m, who, &mut c, &mut out);
            reader::tick(m, c.now);
            self.after_take(&group, st, &mut c, &mut out);
        }
        if let Some(who) = self.who.as_mut() {
            self.duty.tick(who, &mut self.groups, &mut c, &mut out);
        }
        self.keep_out(&mut out); // C3c
        out
    }

    /// The next keyholder upload, paced: at most what the link and a call leave room for.
    pub fn next_frame(&mut self, now: u64, in_call: bool) -> Option<ClientMessage> {
        self.duty.next_frame(now, in_call)
    }

    /// A keyholder job to run off the lock (`BuildJob::step`).
    pub fn take_build(&mut self) -> Option<BuildJob> {
        self.duty.take_build()
    }

    /// A job back, finished or failed.
    pub fn built(&mut self, b: Built, c: GkCtx) -> GkOut {
        self.mirrored(c, |k, mut c| {
            let mut out = GkOut::default();
            if let Some(who) = k.who.as_mut() {
                k.duty.built(who, &mut k.groups, b, &mut c, &mut out);
            }
            out
        })
    }

    /// "Help hold keys" switched while connected.
    pub fn set_volunteer(&mut self, on: bool) -> GkOut {
        let mut out = GkOut::default();
        if let Some(who) = self.who.as_mut() {
            who.help = on;
            self.duty.set_volunteer(who, &mut self.groups, on, &mut out);
        }
        out
    }

    /// The account's seat keys rotated mid-connection (§5.11): welcomes to the new seat open
    /// from now, the old seat's until it goes, and every text group is asked again.
    pub fn seat_keys_changed(&mut self, keys: SeatKeys) -> GkOut {
        let mut out = GkOut::default();
        let Some(who) = self.who.as_mut() else {
            return out;
        };
        who.seat_keys = Some(keys);
        let now = crate::time::now_millis();
        for m in self.groups.values_mut() {
            if m.t.kind == GroupKind::Text {
                m.reseated();
                m.fetch(who, now, &mut out);
            }
        }
        self.kept.seat_keys_changed(who, &mut self.groups, &mut out);
        self.duty.seat_keys_changed(who, &mut self.groups, &mut out);
        out
    }

    /// The browser page was hidden or shown.
    pub fn visibility(&mut self, visible: bool, in_call: bool) -> GkOut {
        let mut out = GkOut::default();
        if let Some(who) = self.who.as_mut() {
            who.visible = visible;
            self.duty
                .visibility(who, &mut self.groups, visible, in_call, &mut out);
        }
        out
    }

    /// The head epoch's key, for a writer of kept history (C4).
    pub fn current_epoch(&self, group: &str) -> Option<GkEpoch> {
        self.groups.get(group)?.current()
    }

    /// A past epoch's key, for a reader of kept history (C4): at once where it is held, else
    /// asked (`GkOut::past_ready` says when it is in).
    pub fn past_epoch(&mut self, group: &str, gen: [u8; 16], epoch: u32) -> PastEpoch {
        let (Some(who), Some(m)) = (self.who.as_mut(), self.groups.get_mut(group)) else {
            return PastEpoch::Unknown;
        };
        if let Some(k) = m.epoch_key(&gen, epoch) {
            return PastEpoch::Ready(k);
        }
        self.kept.past_epoch(who, m, gen, epoch)
    }

    /// What this device keeps for this relay and account (`GkOut::local_dirty`).
    pub fn local(&self) -> Option<&LocalGk> {
        self.local.as_ref()
    }

    /// The connection ended: everything of it goes, posts still held are given up, the
    /// local floors stay.
    pub fn end(&mut self) -> GkOut {
        let mut out = GkOut::default();
        if let Some(who) = self.who.as_mut() {
            self.duty.end(who, &mut out);
        }
        for m in self.groups.values_mut() {
            writer::drop_held(m, &mut out);
        }
        let groups: Vec<String> = self.groups.keys().cloned().collect();
        for g in &groups {
            self.local_floor(g);
        }
        out.local_dirty = self.local.is_some() && !groups.is_empty();
        self.keep_out(&mut out); // C3c
        let local = self.local.take();
        *self = GroupKeying::default();
        self.local = local;
        out
    }

    // C3c: the keyholder's own (`HolderKeep`) from the duty into `local`, where it moved.
    fn keep_out(&mut self, out: &mut GkOut) {
        if let (Some(keep), Some(local)) = (self.duty.take_keep(), self.local.as_mut()) {
            local.holder = keep;
            out.local_dirty = true;
        }
    }

    // C3c: every header the member took, to the duty (a Join of ours named under it, §5.2).
    fn duty_saw(&mut self, group: &str, out: &mut GkOut) {
        if let (Some(who), Some(m)) = (self.who.as_mut(), self.groups.get_mut(group)) {
            self.duty.head_taken(who, m, out);
            m.took.clear();
        }
    }
}

/// The raw 32 bytes of an identity key as a pin holds it (33, type byte first).
pub(crate) fn raw_ik(serialized: &[u8]) -> Option<[u8; 32]> {
    let key = libsignal_protocol::IdentityKey::decode(serialized).ok()?;
    key.public_key().public_key_bytes().try_into().ok()
}

/// The identity key a pin holds, from its 32 raw bytes.
pub(crate) fn ik_serialized(raw: &[u8; 32]) -> Option<Vec<u8>> {
    let key = libsignal_protocol::PublicKey::from_djb_public_key_bytes(raw).ok()?;
    Some(
        libsignal_protocol::IdentityKey::new(key)
            .serialize()
            .into_vec(),
    )
}

/// Stores are in memory, so a libsignal future is ready on its first poll.
fn ready<T>(fut: impl Future<Output = anyhow::Result<T>>) -> anyhow::Result<T> {
    match Box::pin(fut)
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(result) => result,
        Poll::Pending => anyhow::bail!("an in-memory store pended"),
    }
}

// K1: kept history (part 4): the account's re-seal for `AccountSync`, and the past epochs'
// asks for the host.
pub(crate) use kept::Reseal;

impl GroupKeying {
    /// The past epochs `past_epoch` asked for, in `EpochFetch` frames of at most 16 (C4): the
    /// host sends them after its `past_epoch` calls and at every `tick`. A few frames are
    /// out at once per group, the rest go as their answers come in, all paced under the
    /// relay's fetch budget.
    pub fn past_asks(&mut self) -> GkOut {
        let mut out = GkOut::default();
        if let Some(who) = self.who.as_ref() {
            for m in self.groups.values() {
                self.kept.send(who, m, &mut out);
            }
        }
        out
    }
}

// Dive 1 F1: the signed-in account's counters kept on this device too (`Mirrored`).
#[cfg(test)]
mod mirror_tests {
    use super::*;

    const A: [u8; 16] = [0xa1; 16];

    fn seen(n: u32, made: u64) -> Seen {
        Seen { n, made }
    }

    fn book(counters: &[([u8; 16], Seen)]) -> MemoryPins {
        let mut b = MemoryPins::default();
        for (a, s) in counters {
            b.counters.raise(*a, *s, true);
        }
        b
    }

    fn started(account: Option<[u8; 16]>) -> GroupKeying {
        let mut k = GroupKeying::default();
        let _ = k.start(GkStart {
            on: true,
            run: [3; 16],
            relay_clock: crate::time::now_millis() / 1000,
            platform: Platform::Desktop,
            help_hold_keys: false,
            user_id: 1,
            identity: IdentityKeyPair::generate(&mut crate::rng()),
            account,
            seat_keys: None,
            local: None,
            visible: true,
        });
        k
    }

    /// What a check reads of `account` through `k`'s view of `book`, and whether the call
    /// asked for a save.
    fn read(k: &mut GroupKeying, book: &mut MemoryPins, account: [u8; 16]) -> (Option<Seen>, bool) {
        let mut got = None;
        let out = k.mirrored(GkCtx { pins: book, now: 0 }, |_, c| {
            got = c.pins.seen(&account);
            GkOut::default()
        });
        (got, out.local_dirty)
    }

    /// A counter the book answered, and one raised through it, stay with this device when a
    /// later book has neither (the vault's pages withheld); each new one asks for a save.
    #[test]
    fn a_counter_read_or_raised_is_answered_after_the_book_lost_it() {
        let mut k = started(Some([1; 16]));
        let mut b = book(&[(A, seen(5, 100))]);
        assert_eq!(read(&mut k, &mut b, A), (Some(seen(5, 100)), true));
        assert_eq!(
            read(&mut k, &mut b, A),
            (Some(seen(5, 100)), false),
            "kept once"
        );
        let out = k.mirrored(
            GkCtx {
                pins: &mut b,
                now: 0,
            },
            |_, c| {
                c.pins.raise([0xb2; 16], seen(2, 200), true);
                GkOut::default()
            },
        );
        assert!(out.local_dirty);
        assert_eq!(
            b.seen(&[0xb2; 16]),
            Some(seen(2, 200)),
            "raised in the book too"
        );
        let mut withheld = MemoryPins::default();
        assert_eq!(read(&mut k, &mut withheld, A), (Some(seen(5, 100)), false));
        assert_eq!(
            read(&mut k, &mut withheld, [0xb2; 16]).0,
            Some(seen(2, 200))
        );
        assert_eq!(withheld.seen(&A), None, "the book is not written by a read");
    }

    /// Every check takes the higher `n`; of one `n` the book's answer, which merges the
    /// account's devices; a higher one in the book is kept.
    #[test]
    fn a_check_takes_the_higher_counter_and_of_one_n_the_earlier_made() {
        let mut k = started(Some([1; 16]));
        let _ = read(&mut k, &mut book(&[(A, seen(5, 100))]), A);
        // A vault page rolled back to counter 4
        assert_eq!(
            read(&mut k, &mut book(&[(A, seen(4, 50))]), A).0,
            Some(seen(5, 100))
        );
        assert_eq!(
            read(&mut k, &mut book(&[(A, seen(5, 90))]), A).0,
            Some(seen(5, 90))
        );
        // A book row started afresh with a later `made` (the pages withheld): the earlier the
        // mirror holds stands (review P1, P4)
        assert_eq!(
            read(&mut k, &mut book(&[(A, seen(5, 200))]), A).0,
            Some(seen(5, 90)),
            "of one n the earlier made"
        );
        assert_eq!(
            read(&mut k, &mut book(&[(A, seen(6, 300))]), A).0,
            Some(seen(6, 300))
        );
        assert_eq!(
            read(&mut k, &mut MemoryPins::default(), A).0,
            Some(seen(6, 300))
        );
    }

    /// A guest's book is the host's own (`LocalGk::counters`): nothing goes to the mirror.
    #[test]
    fn a_guest_keeps_no_mirror() {
        let mut k = started(None);
        assert_eq!(
            read(&mut k, &mut book(&[(A, seen(5, 100))]), A),
            (Some(seen(5, 100)), false)
        );
        assert_eq!(k.local().unwrap().mirror, SeenBook::default());
    }

    /// The mirror goes back to `most` once past `most + slack`: the oldest `made` first.
    #[test]
    fn the_mirror_drops_its_oldest_counters_past_its_bound() {
        let mut m = SeenBook::default();
        for i in 0..10u8 {
            m.raise([i; 16], seen(1, 1000 - u64::from(i)), true);
        }
        assert!(!m.bound(8, 2), "within the slack");
        m.raise([10; 16], seen(1, 5000), true);
        assert!(m.bound(8, 2));
        let left: Vec<u8> = m.0.keys().map(|a| a[0]).collect();
        assert_eq!(left, vec![0, 1, 2, 3, 4, 5, 6, 10], "made 991 to 993 went");
        assert!(!m.bound(8, 0));
    }

    /// Two books of the account merge row by row as `raise` takes a row: the higher `n`, of
    /// one `n` a rotation's `made` over a pair's, else the earlier; a merge that adds nothing
    /// says so.
    #[test]
    fn two_books_merge_by_the_higher_counter_and_of_one_n_as_raise_does() {
        let mut a = SeenBook::default();
        a.raise(A, seen(5, 100), false);
        a.raise([2; 16], seen(3, 10), true);
        let mut b = SeenBook::default();
        b.raise(A, seen(5, 200), true);
        b.raise([2; 16], seen(2, 5), true);
        b.raise([3; 16], seen(1, 7), true);
        assert!(a.merge(&b));
        assert_eq!(a.seen(&A), Some(seen(5, 200)), "the rotation's made");
        assert_eq!(a.seen(&[2; 16]), Some(seen(3, 10)), "the higher n stays");
        assert_eq!(a.seen(&[3; 16]), Some(seen(1, 7)));
        assert!(!a.merge(&b), "nothing new");
        assert!(!a.merge(&SeenBook::default()));
    }

    /// What a host kept apart goes into the mirror, bounded as the mirror is.
    #[test]
    fn counters_kept_apart_go_into_the_mirror_within_its_bound() {
        let mut local = LocalGk::default();
        local.mirror.raise(A, seen(5, 100), true);
        let mut kept = SeenBook::default();
        kept.raise(A, seen(4, 50), true);
        assert!(!local.mirror_in(&kept), "a lower counter moves nothing");
        for i in 0..(MIRROR_MOST + MIRROR_MOST / 16 + 1) as u32 {
            let mut a = [0u8; 16];
            a[..4].copy_from_slice(&i.to_be_bytes());
            a[15] = 0xee;
            kept.raise(a, seen(1, 1000 + u64::from(i)), true);
        }
        assert!(local.mirror_in(&kept));
        assert_eq!(local.mirror.0.len(), MIRROR_MOST, "back to the bound");
        assert_eq!(
            local.mirror.seen(&A),
            None,
            "the oldest made went first: A's 100"
        );
    }
}
