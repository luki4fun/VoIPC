//! Dues on the relay (plan 2d "Joins", "Exits", "How dues interleave", 2e): the join and
//! exit batches and when each closes, which due is asked next, and the due out with what
//! it was asked against.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use voipc_crypto::group_key::commit::{Due, DueKind, Exit, HolderRef, Joiner};
use voipc_crypto::group_key::timers::{
    deadline_ms, exit_gap_ms, join_batch_ms, GATED_EXIT_BATCH, JOIN_BATCH_MAX,
};
use voipc_crypto::group_key::{GroupKind, SeatRef};
use voipc_protocol::types::UserId;

/// An open exit batch closes at this many exits in an open group, so that its due stays
/// one 12 MB `EpochDue` (part 13: about 46 B an exit on the wire, 56 B decoded; a gated
/// one closes at `GATED_EXIT_BATCH`).
pub const EXIT_BATCH_MAX: usize = 200_000;

/// The most exits one batch takes.
pub fn exit_cap(gated: bool) -> usize {
    if gated {
        GATED_EXIT_BATCH
    } else {
        EXIT_BATCH_MAX
    }
}

/// An exit with why it happened (`cause`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Leaving {
    pub exit: Exit,
    pub cause: u8,
}

#[derive(Clone, Debug, Default)]
pub struct Batch {
    pub first_ms: u64,
    pub exits: Vec<Leaving>,
}

impl Batch {
    pub fn upto(&self) -> u64 {
        self.exits.last().map_or(0, |l| l.exit.seq)
    }
}

/// Exits by `seq`: the open batch and the closed ones waiting for an opening, oldest
/// first. A due carries the oldest closed batch, so `exits_upto` is always a prefix.
#[derive(Clone, Debug, Default)]
pub struct Exits {
    /// The next exit's `seq`; the first is 1.
    pub next: u64,
    pub open: Option<Batch>,
    pub closed: VecDeque<Batch>,
}

impl Exits {
    pub fn new(next: u64) -> Exits {
        Exits {
            next: next.max(1),
            ..Exits::default()
        }
    }

    /// Whether `seat` already waits to exit.
    pub fn has(&self, seat: &SeatRef) -> bool {
        self.closed
            .iter()
            .chain(self.open.iter())
            .any(|b| b.exits.iter().any(|l| l.exit.seat == *seat))
    }

    /// Enters an exit; its `seq`.
    pub fn add(&mut self, seat: SeatRef, b: u64, cause: u8, now: u64) -> u64 {
        let seq = self.next;
        self.next += 1;
        let open = self.open.get_or_insert_with(|| Batch {
            first_ms: now,
            exits: vec![],
        });
        open.exits.push(Leaving {
            exit: Exit { seq, seat, b },
            cause,
        });
        seq
    }

    /// When the open batch closes, at `seats` seats (2e); at once past its cap.
    pub fn closes_at(&self, kind: GroupKind, seats: u64, gated: bool) -> Option<u64> {
        let open = self.open.as_ref()?;
        if open.exits.len() >= exit_cap(gated) {
            return Some(open.first_ms);
        }
        Some(open.first_ms + exit_gap_ms(kind, seats))
    }

    /// Closes the open batch: into the newest closed one while both fit the cap, else in
    /// batches of the cap (one event can enter more exits than the cap before a tick).
    pub fn close(&mut self, gated: bool) {
        let Some(open) = self.open.take() else {
            return;
        };
        self.push_closed(open.first_ms, open.exits, gated);
    }

    /// Closed batches of `exits` (in `seq` order), none past the cap.
    pub fn push_closed(&mut self, first_ms: u64, exits: Vec<Leaving>, gated: bool) {
        let cap = exit_cap(gated);
        match self.closed.back_mut() {
            Some(last) if last.exits.len() + exits.len() <= cap => last.exits.extend(exits),
            _ => {
                for c in exits.chunks(cap) {
                    self.closed.push_back(Batch {
                        first_ms,
                        exits: c.to_vec(),
                    });
                }
            }
        }
    }

    /// Takes every exit up to `seq` off the closed batches: an opening (or a Genesis or
    /// Regenesis, `Applied.exits_done`) dealt with them.
    pub fn done(&mut self, upto: u64) {
        for b in &mut self.closed {
            b.exits.retain(|l| l.exit.seq > upto);
        }
        self.closed.retain(|b| !b.exits.is_empty());
    }

    /// Keeps only the exits of seats `seated` still holds (after a new start).
    pub fn keep(&mut self, seated: impl Fn(&SeatRef) -> bool) {
        for b in self.closed.iter_mut().chain(self.open.iter_mut()) {
            b.exits.retain(|l| seated(&l.exit.seat));
        }
        self.closed.retain(|b| !b.exits.is_empty());
        if self.open.as_ref().is_some_and(|b| b.exits.is_empty()) {
            self.open = None;
        }
    }

    /// The highest `seq` not dealt with yet, open or closed.
    pub fn pending(&self) -> Option<u64> {
        self.open
            .as_ref()
            .or(self.closed.back())
            .map(Batch::upto)
            .filter(|s| *s > 0)
    }

    pub fn waiting(&self) -> usize {
        self.closed
            .iter()
            .chain(self.open.iter())
            .map(|b| b.exits.len())
            .sum()
    }

    /// Every seat waiting to exit.
    pub fn seats(&self) -> std::collections::HashSet<SeatRef> {
        self.closed
            .iter()
            .chain(self.open.iter())
            .flat_map(|b| b.exits.iter().map(|l| l.exit.seat))
            .collect()
    }
}

/// A joiner waiting for a Join, with the sessions it answers once seated.
#[derive(Clone)]
pub struct Waiting {
    pub joiner: Joiner,
    pub sids: Vec<UserId>,
    pub account: Option<[u8; 16]>,
}

/// Joiners in arrival order, and when the batch opened. Each seat's place is kept beside
/// the queue, the joiners each session waits for, and those no session waits for (eager
/// seats, plan 2d), an account's apart, so queueing one or a session's leave costs no walk
/// of the queue: an account's first seat keys queue up to 100k at once.
#[derive(Clone, Default)]
pub struct Joins {
    pub first_ms: Option<u64>,
    /// By arrival.
    queue: BTreeMap<u64, Waiting>,
    at: HashMap<SeatRef, u64>,
    /// The joiners each session waits for.
    of: HashMap<UserId, Vec<u64>>,
    /// Joiners whose `sids` are empty: an account's, and a guest's or a connection's.
    idle_accounts: HashSet<u64>,
    idle_others: HashSet<u64>,
    next: u64,
}

impl Joins {
    pub fn has(&self, seat: &SeatRef) -> bool {
        self.at.contains_key(seat)
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// The joiners no session waits for.
    pub fn eager(&self) -> usize {
        self.idle_accounts.len() + self.idle_others.len()
    }

    fn idle(&mut self, account: Option<[u8; 16]>) -> &mut HashSet<u64> {
        match account {
            Some(_) => &mut self.idle_accounts,
            None => &mut self.idle_others,
        }
    }

    pub fn add(&mut self, w: Waiting, now: u64) {
        let queued = self.at.get(&w.joiner.seat).copied();
        if let Some((i, q)) = queued.and_then(|i| Some((i, self.queue.get_mut(&i)?))) {
            let was = q.sids.is_empty();
            for s in w.sids {
                if !q.sids.contains(&s) {
                    q.sids.push(s);
                    self.of.entry(s).or_default().push(i);
                }
            }
            if was && !q.sids.is_empty() {
                let account = q.account;
                self.idle(account).remove(&i);
            }
            return;
        }
        self.first_ms.get_or_insert(now);
        let i = self.next;
        self.next += 1;
        for s in &w.sids {
            self.of.entry(*s).or_default().push(i);
        }
        if w.sids.is_empty() {
            self.idle(w.account).insert(i);
        }
        self.at.insert(w.joiner.seat, i);
        self.queue.insert(i, w);
    }

    /// When the batch closes: `JOIN_BATCH_MS` after its first joiner, at once at 256.
    pub fn closes_at(&self, kind: GroupKind) -> Option<u64> {
        let first = self.first_ms?;
        if self.queue.len() >= JOIN_BATCH_MAX {
            return Some(first);
        }
        Some(first + join_batch_ms(kind))
    }

    /// The first 256, for a Join due; they stay queued until it lands.
    pub fn batch(&self) -> Vec<Waiting> {
        self.queue.values().take(JOIN_BATCH_MAX).cloned().collect()
    }

    /// Takes the seats a Join dealt with (seated or refused).
    pub fn done(&mut self, seats: &[SeatRef], now: u64) {
        for s in seats {
            self.take(s);
        }
        self.first_ms = (!self.queue.is_empty()).then_some(now);
    }

    /// Takes `seat` off the queue, if it waits.
    pub fn take(&mut self, seat: &SeatRef) {
        if let Some(i) = self.at.get(seat).copied() {
            self.remove(i);
        }
    }

    fn remove(&mut self, i: u64) {
        let Some(w) = self.queue.remove(&i) else {
            return;
        };
        self.at.remove(&w.joiner.seat);
        for s in &w.sids {
            if let Some(v) = self.of.get_mut(s) {
                v.retain(|x| *x != i);
                if v.is_empty() {
                    self.of.remove(s);
                }
            }
        }
        self.idle(w.account).remove(&i);
    }

    /// Keeps only the joiners `keep` says, in order.
    pub fn retain(&mut self, mut keep: impl FnMut(&Waiting) -> bool) {
        let gone: Vec<u64> = self
            .queue
            .iter()
            .filter(|(_, w)| !keep(w))
            .map(|(i, _)| *i)
            .collect();
        for i in gone {
            self.remove(i);
        }
    }

    pub fn drop_sid(&mut self, sid: UserId) {
        for i in self.of.remove(&sid).unwrap_or_default() {
            let Some(w) = self.queue.get_mut(&i) else {
                continue;
            };
            w.sids.retain(|s| *s != sid);
            if w.sids.is_empty() {
                let account = w.account;
                self.idle(account).insert(i);
            }
        }
    }

    /// Session `sid` is gone: it waits for nothing, and every joiner no session waits for
    /// goes but, with `keep_accounts` (a stored group), an account's eager seat. Costs the
    /// joiners it touches, not the queue.
    pub fn leave(&mut self, sid: UserId, keep_accounts: bool) {
        self.drop_sid(sid);
        let mut gone: Vec<u64> = self.idle_others.drain().collect();
        if !keep_accounts {
            gone.extend(self.idle_accounts.drain());
        }
        for i in gone {
            self.remove(i);
        }
    }
}

/// The due out to one keyholder, and what it was asked against.
pub struct DueOut {
    pub id: u64,
    pub due: Due,
    /// The session asked.
    pub sid: UserId,
    /// Its keyholder entry; a Genesis volunteer's own.
    pub by: HolderRef,
    pub deadline: u64,
    /// The seats on a seed older than the head's at the ask (every other seated seat held
    /// the head's): rule 13 reads seat state as of the ask.
    pub held: HashMap<SeatRef, u32>,
    pub head_seed: u32,
}

impl DueOut {
    /// A 60 s due an exit batch does not wait behind (plan 2d).
    pub fn slow(&self) -> bool {
        deadline_ms(self.due.kind) > deadline_ms(DueKind::Exits) + deadline_ms(DueKind::Join)
    }
}
