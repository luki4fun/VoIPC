//! Keyholders on the relay (plan 2d "Keyholders", "Pass-over"): the volunteers among a
//! group's followers and their ranks, the set the head names with each entry's misses,
//! who a due goes to, who is promoted and whose removal is proposed.

use std::collections::{HashMap, VecDeque};

use voipc_crypto::group_key::commit::{Candidate, HolderRef, Joiner, Pair};
use voipc_crypto::group_key::timers::{
    BROWSER_MAX_SEATS, COUNTER_STALE_SECS, KEYHOLDERS_ONLINE_MIN, MAX_GUEST_KEYHOLDERS,
    REMOVAL_AWAY_SECS, REMOVAL_MISSES, REMOVAL_WINDOW_MS,
};
use voipc_crypto::group_key::{GroupKind, Keyholder, MemberId, MAX_KEYHOLDERS};
use voipc_protocol::gk::{origin, platform};
use voipc_protocol::types::UserId;

/// A connection that offered to hold keys (`KeyholdVolunteer`), as the relay checked it.
#[derive(Clone)]
pub struct Volunteer {
    pub sid: UserId,
    /// A `platform` code.
    pub platform: u8,
    /// The account, or `Conn(sid)` for a guest.
    pub m: MemberId,
    /// Its identity key, raw.
    pub ik: [u8; 32],
    /// A desktop's keyholder pair (0x03), or the connection's seat pair (0x02).
    pub pair: Pair,
    /// Its own member seat, for a Genesis: the account's seat keys, or the connection pair.
    pub seat: Option<Joiner>,
}

impl Volunteer {
    /// Lower is better: account desktop, account browser, guest desktop, guest browser.
    /// `None` where it may not hold this kind of group's keys (a phone in text).
    pub fn rank(&self, kind: GroupKind) -> Option<u8> {
        let guest = 2 * u8::from(self.m.is_conn());
        match (kind, self.platform) {
            (_, platform::DESKTOP) => Some(guest),
            (_, platform::BROWSER) => Some(guest + 1),
            (GroupKind::Voice, platform::PHONE) => Some(guest + 1),
            _ => None,
        }
    }

    pub fn by(&self) -> HolderRef {
        HolderRef {
            m: self.m,
            kx: self.pair.kx(),
        }
    }

    pub fn candidate(&self) -> Candidate {
        Candidate {
            m: self.m,
            ik: self.ik,
            pair: self.pair.clone(),
        }
    }

    /// The entry its pair makes in a group of `kind`.
    pub fn entry(&self, kind: GroupKind) -> Option<Keyholder> {
        self.pair.entry(kind, self.m, self.ik)
    }

    fn browser(&self) -> bool {
        self.platform == platform::BROWSER
    }
}

/// One entry's record: misses and declines in the last hour, when it was last asked,
/// since when it is away.
#[derive(Clone, Debug, Default)]
pub struct Stats {
    pub missed: VecDeque<u64>,
    pub declined: VecDeque<u64>,
    pub asked_ms: u64,
    pub away_since: Option<u64>,
}

impl Stats {
    fn trim(&mut self, now: u64) {
        let old = now.saturating_sub(REMOVAL_WINDOW_MS);
        while self.missed.front().is_some_and(|t| *t < old) {
            self.missed.pop_front();
        }
        while self.declined.front().is_some_and(|t| *t < old) {
            self.declined.pop_front();
        }
    }

    /// Misses and declines this hour.
    pub fn count(&self) -> usize {
        self.missed.len() + self.declined.len()
    }
}

/// The set the head names, each entry's pair and record.
#[derive(Default)]
pub struct Holders {
    pub set: Vec<Keyholder>,
    /// By raw KX: the pair each entry holds, for its `KRK` welcome (`DuePiece.pairs`).
    pub pairs: HashMap<[u8; 32], Pair>,
    pub stats: HashMap<[u8; 32], Stats>,
    /// By raw KX: the rank its volunteer had when it was promoted (`Volunteer::rank`), for
    /// a hand-over while it is offline.
    pub rank: HashMap<[u8; 32], u8>,
    /// By raw KX: the device of an account's entry, where its session named one (a device
    /// removed from its account takes its entries with it).
    pub device: HashMap<[u8; 32], Vec<u8>>,
    /// Entries whose removal is proposed outright: their device was removed (plan 2d), or
    /// their account was banned, reset or deleted.
    pub forced: Vec<HolderRef>,
    /// Each account's newest seat-key counter and since when (unix ms): an entry below it
    /// for `COUNTER_STALE_SECS` is proposed for removal.
    pub newest: HashMap<[u8; 16], (u32, u64)>,
}

/// An entry's rank where no online volunteer gives it: what was recorded at its promotion,
/// else what its origin says (an account desktop's 0x03 pair, an account browser's 0x02,
/// a guest's 0x02 as a guest desktop).
fn entry_rank(k: &Keyholder, recorded: Option<u8>) -> u8 {
    recorded.unwrap_or(match (k.origin, k.m.is_conn()) {
        (origin::DESKTOP, _) => 0,
        (_, false) => 1,
        (_, true) => 2,
    })
}

impl Holders {
    /// The set a taken header names; `pairs` gives a new entry's pair.
    pub fn set_to(&mut self, set: Vec<Keyholder>, mut pair: impl FnMut(&[u8; 32]) -> Option<Pair>) {
        for k in &set {
            if let std::collections::hash_map::Entry::Vacant(e) = self.pairs.entry(k.kx) {
                if let Some(p) = pair(&k.kx) {
                    e.insert(p);
                }
            }
            self.stats.entry(k.kx).or_default();
        }
        self.pairs.retain(|kx, _| set.iter().any(|k| k.kx == *kx));
        self.stats.retain(|kx, _| set.iter().any(|k| k.kx == *kx));
        self.rank.retain(|kx, _| set.iter().any(|k| k.kx == *kx));
        self.device.retain(|kx, _| set.iter().any(|k| k.kx == *kx));
        self.forced
            .retain(|r| set.iter().any(|k| HolderRef::of(k) == *r));
        self.set = set;
    }

    pub fn clear(&mut self) {
        self.set.clear();
        self.pairs.clear();
        self.stats.clear();
        self.rank.clear();
        self.device.clear();
        self.forced.clear();
    }

    /// The entries of `account` made on `device`: proposed for removal (plan 2d "device
    /// removed from its account").
    pub fn device_removed(&mut self, account: &[u8; 16], device: &[u8]) {
        for k in &self.set {
            let r = HolderRef::of(k);
            if k.m.account().as_ref() == Some(account)
                && self.device.get(&k.kx).is_some_and(|d| d == device)
                && !self.forced.contains(&r)
            {
                self.forced.push(r);
            }
        }
    }

    /// The entry a volunteer's pair is, if any.
    pub fn entry_of(&self, v: &Volunteer) -> Option<&Keyholder> {
        let kx = v.pair.kx();
        self.set.iter().find(|k| k.kx == kx && k.m == v.m)
    }

    /// Online entries: the volunteers among the followers whose pair is an entry.
    pub fn online<'a>(&self, vols: &'a HashMap<UserId, Volunteer>) -> Vec<&'a Volunteer> {
        let mut on: Vec<&Volunteer> = vols
            .values()
            .filter(|v| self.entry_of(v).is_some())
            .collect();
        on.sort_by_key(|v| v.sid);
        on
    }

    /// Who a due goes to: an online entry not in `skip`, by fewest misses this hour, then
    /// rank, then least recently asked.
    pub fn pick<'a>(
        &mut self,
        kind: GroupKind,
        vols: &'a HashMap<UserId, Volunteer>,
        skip: &[UserId],
        now: u64,
    ) -> Option<&'a Volunteer> {
        for s in self.stats.values_mut() {
            s.trim(now);
        }
        let best = self
            .online(vols)
            .into_iter()
            .filter(|v| !skip.contains(&v.sid))
            .min_by_key(|v| {
                let s = self.stats.get(&v.pair.kx()).cloned().unwrap_or_default();
                (
                    s.count(),
                    v.rank(kind).unwrap_or(u8::MAX),
                    s.asked_ms,
                    v.sid,
                )
            })?;
        self.stats.entry(best.pair.kx()).or_default().asked_ms = now;
        Some(best)
    }

    pub fn missed(&mut self, kx: &[u8; 32], now: u64) {
        self.stats.entry(*kx).or_default().missed.push_back(now);
    }

    pub fn declined(&mut self, kx: &[u8; 32], now: u64) {
        self.stats.entry(*kx).or_default().declined.push_back(now);
    }

    /// Marks who is away from now on (or back).
    pub fn seen(&mut self, vols: &HashMap<UserId, Volunteer>, now: u64) {
        let on: Vec<[u8; 32]> = self.online(vols).iter().map(|v| v.pair.kx()).collect();
        for k in &self.set {
            let s = self.stats.entry(k.kx).or_default();
            if on.contains(&k.kx) {
                s.away_since = None;
            } else if s.away_since.is_none() {
                s.away_since = Some(now);
            }
        }
    }

    /// An entry whose removal the relay proposes now, if any (plan 2d): three misses or
    /// declines this hour, a desktop (0x03) away seven days, a connection pair's entry
    /// (0x02: a guest's or an account browser's, by origin) offline, a browser past 10 000
    /// seats, a guest before the gate turns on, its device removed from its account, its
    /// counter below its account's newest for seven days. Never the last entry. Only an
    /// entry `ok` takes: one another online entry can sign (rule 2 keeps a Remove's signer
    /// in the set), so an entry no other can remove never holds up the dues behind it.
    pub fn removal_where(
        &mut self,
        vols: &HashMap<UserId, Volunteer>,
        seats: usize,
        gate_wanted: bool,
        now: u64,
        ok: impl Fn(&HolderRef) -> bool,
    ) -> Option<HolderRef> {
        if self.set.len() < 2 {
            return None;
        }
        if let Some(r) = self.forced.iter().find(|r| ok(r)) {
            return Some(*r);
        }
        let online = self.online(vols);
        let browser = |k: &Keyholder| online.iter().any(|v| v.pair.kx() == k.kx && v.browser());
        let newest = &self.newest;
        let stale = |k: &Keyholder| {
            k.m.account()
                .and_then(|a| newest.get(&a))
                .is_some_and(|(n, since)| {
                    k.n < *n && now >= since.saturating_add(COUNTER_STALE_SECS * 1000)
                })
        };
        for k in &self.set {
            let s = self.stats.entry(k.kx).or_default();
            s.trim(now);
            let away = s.away_since.map_or(0, |t| now.saturating_sub(t));
            let offline = s.away_since.is_some();
            let conn_pair = k.origin == origin::CONNECTION;
            let r = HolderRef { m: k.m, kx: k.kx };
            if (s.count() >= REMOVAL_MISSES
                || (k.origin == origin::DESKTOP && away >= REMOVAL_AWAY_SECS * 1000)
                || (conn_pair && offline)
                || (browser(k) && seats > BROWSER_MAX_SEATS as usize)
                || (k.m.is_conn() && gate_wanted)
                || stale(k))
                && ok(&r)
            {
                return Some(r);
            }
        }
        None
    }

    /// At eight entries a promotion first removes the one away longest (plan 2d): that
    /// entry, when the set is full, one is away and a volunteer is wanted.
    pub fn swap_out(
        &self,
        kind: GroupKind,
        vols: &HashMap<UserId, Volunteer>,
        gated: bool,
        seats: usize,
    ) -> Option<HolderRef> {
        if self.set.len() < MAX_KEYHOLDERS || self.wanted(kind, vols, gated, seats).is_none() {
            return None;
        }
        self.set
            .iter()
            .filter_map(|k| Some((self.stats.get(&k.kx)?.away_since?, k)))
            .min_by_key(|(t, _)| *t)
            .map(|(_, k)| HolderRef::of(k))
    }

    /// The volunteer to promote, if the set wants one (plan 2d): while fewer than two are
    /// online, or a hand-over, up to eight.
    pub fn promotion<'a>(
        &self,
        kind: GroupKind,
        vols: &'a HashMap<UserId, Volunteer>,
        gated: bool,
        seats: usize,
    ) -> Option<&'a Volunteer> {
        if self.set.len() >= MAX_KEYHOLDERS {
            return None;
        }
        self.wanted(kind, vols, gated, seats)
    }

    /// The best-ranked follower allowed to hold this group's keys that is no entry, when
    /// the set wants one whatever its size: while fewer than two entries are online, or
    /// (text, the hand-over) while every entry ranks below it, so one at a time; the lower
    /// one resigns by its own rules once that promotion is taken.
    fn wanted<'a>(
        &self,
        kind: GroupKind,
        vols: &'a HashMap<UserId, Volunteer>,
        gated: bool,
        seats: usize,
    ) -> Option<&'a Volunteer> {
        if self.set.is_empty() {
            return None;
        }
        let guests = self.set.iter().filter(|k| k.m.is_conn()).count();
        let best = allowed(kind, vols, gated, seats)
            .filter(|v| self.entry_of(v).is_none() && !self.set.iter().any(|k| k.kx == v.pair.kx()))
            .filter(|v| !v.m.is_conn() || guests < MAX_GUEST_KEYHOLDERS)
            .filter(|v| v.entry(kind).is_some())
            .min_by_key(|v| (v.rank(kind), v.sid))?;
        if self.online(vols).len() < KEYHOLDERS_ONLINE_MIN {
            return Some(best);
        }
        let rank = best.rank(kind)?;
        let below = |k: &Keyholder| {
            let on = vols
                .values()
                .find(|v| v.pair.kx() == k.kx && v.m == k.m)
                .and_then(|v| v.rank(kind));
            on.unwrap_or_else(|| entry_rank(k, self.rank.get(&k.kx).copied())) > rank
        };
        (kind == GroupKind::Text && self.set.iter().all(below)).then_some(best)
    }
}

/// The volunteers allowed to hold a group's keys (plan 2d): phones never in text;
/// browsers only with no account desktop online and at most 10 000 seats; guests only in
/// an open group with no account volunteer online.
pub fn allowed(
    kind: GroupKind,
    vols: &HashMap<UserId, Volunteer>,
    gated: bool,
    seats: usize,
) -> impl Iterator<Item = &Volunteer> {
    let desktop = vols
        .values()
        .any(|v| !v.m.is_conn() && v.platform == platform::DESKTOP);
    let account = vols
        .values()
        .any(|v| !v.m.is_conn() && v.rank(kind).is_some());
    vols.values().filter(move |v| {
        v.rank(kind).is_some()
            && (!v.browser() || (!desktop && seats <= BROWSER_MAX_SEATS as usize))
            && (!v.m.is_conn() || (!gated && !account))
    })
}

/// The volunteer asked for a Genesis or Regenesis: the best-ranked allowed one with its
/// own seat at hand.
pub fn starter(
    kind: GroupKind,
    vols: &HashMap<UserId, Volunteer>,
    gated: bool,
) -> Option<&Volunteer> {
    allowed(kind, vols, gated, 0)
        .filter(|v| v.seat.is_some() && v.entry(kind).is_some())
        .min_by_key(|v| (v.rank(kind), v.sid))
}
