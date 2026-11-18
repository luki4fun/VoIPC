//! The group key's floors and counters in an account's vault (docs/GROUP-KEY.md §5.7, §5.11),
//! as `AccountSync` runs them on a relay that keeps group keys. Unwired until C3b: nothing
//! calls it yet.
//!
//! - `item.gk_floors`, in the sign-in frame, is the index: each page's generation.
//! - Pages `gkf.N` (N < 16) hold each stored group's rollback floor and names floor, with the
//!   time this account last used the group. Only `c:` groups: memory-only ones never reach the
//!   vault (§5.12).
//! - Pages `gkc.N` (N < 32) hold per account the highest seat-key counter seen, with its
//!   endorsement's `made`, and when this account first saw that account's pin
//!   (`pinned_since`). `account::Pins` keeps no times, and older apps still read its format.
//!
//! The rules that carry the security are the pins' (`sync::pins`):
//!
//! - Nothing is answered before the pages are in (`Pending`), for any group, voice rooms
//!   too: "not read yet" must never pass for "never seen".
//! - A page missing, or older than this device saw or than the index says, is a
//!   `VaultProblem`, and nothing here is saved over after it. What it holds is still used.
//!   A later connection of the same process reads it again and says so again.
//! - A page goes before the index that names it.
//!
//! Unlike the pins, rows leave the pages when they are full: the group used least recently,
//! the account whose counter is oldest. Like a pin that does not fit, such a row lasts this
//! connection in memory. A device that lost a floor falls back to the rule for no floor
//! (§5.7).
//!
//! Two devices merge per group: `Floor::merge`, and for names floors the later generation,
//! then the higher `(epoch, join)`. Counters keep the higher `n`, and of one `n` the earliest
//! `made`. A pin time belongs to one pin: of the same pin the earliest, else the later.
//!
//! Pin times: every pin the account holds is timed once the pages are in (`pins_held`), so a
//! pin met before group keys is checked from the first sign-in on. A pin made or changed
//! later is timed then (`pin_seen`). No pin time is earlier than the newest header this
//! account took, less a header clock's slack, so a clock running behind cannot date a pin
//! before it was the pin.
//!
//! A floor moving to a new generation is saved at once; anything else at most once a minute.
//! Times are unix seconds, as in headers.

// C3b wires this into `AccountSync`; until then only the tests call it.
#![allow(dead_code)]

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap, HashMap, VecDeque};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use voipc_protocol::messages::{AccountRequest, ClientMessage};
use voipc_protocol::types::VaultBlob;

use super::{ask, Event, LOST_AFTER_TICKS, SLOW_DOWN};
use crate::account::{Vault, VaultError};
use crate::group_key::{
    tag, valid_group_id, Floor, NamesFloor, PinThen, Seen, CLOCK_SLACK, RECENT_GENS,
};

type Id = [u8; 16];
/// Rows by age, the oldest on top.
type Oldest<K> = BinaryHeap<Reverse<(u64, K)>>;

/// The index of the pages, in the main vault.
pub const ITEM_GK_FLOORS: &str = "item.gk_floors";
pub const FLOOR_PAGES: u16 = 16;
pub const COUNTER_PAGES: u16 = 32;
const FLOOR_PREFIX: &str = "gkf.";
const COUNTER_PREFIX: &str = "gkc.";
const INDEX_FORMAT: u16 = 1;
/// What a page holds, under the relay's 48 KiB an item with room for its sealing.
const PAGE_BYTES: usize = 47 * 1024;
/// A page's row count as postcard writes it, at most.
const LIST_BYTES: usize = 3;
/// Saves that are not a new generation wait this long.
const SAVE_EVERY: u64 = 60;
/// A group's last use is written again only when it moved by this much.
const TOUCH_EVERY: u64 = 24 * 60 * 60;
/// Ticks of about two seconds the pages may stay out before the person is told.
const PAGES_SAID_AFTER_TICKS: u32 = 15;

/// A group's rollback floor and names floor.
pub type FloorPair = (Floor, Option<NamesFloor>);

/// The pages are not all in yet (or, for pin times, the pins not yet timed): an empty book
/// would pass an old seat or a swapped key as never seen. The host takes no header that
/// needs the answer, in any group, until it comes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pending;

/// What `item.gk_floors` holds.
#[derive(Default, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GkIndex {
    pub format: u16,
    /// Each `gkf.N` page's generation, by its number.
    pub floor_pages: Vec<u64>,
    /// Each `gkc.N` page's generation.
    pub counter_pages: Vec<u64>,
}

impl GkIndex {
    /// The index, or the problem it is.
    pub fn from_bytes(bytes: &[u8]) -> Result<GkIndex, &'static str> {
        let (format, _) = postcard::take_from_bytes::<u16>(bytes).map_err(|_| "unreadable")?;
        if format > INDEX_FORMAT {
            return Err("newer");
        }
        let index: GkIndex = postcard::from_bytes(bytes).map_err(|_| "unreadable")?;
        let fits = index.format == INDEX_FORMAT
            && index.floor_pages.len() <= FLOOR_PAGES as usize
            && index.counter_pages.len() <= COUNTER_PAGES as usize;
        fits.then_some(index).ok_or("unreadable")
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("an index encodes")
    }
}

/// One stored group, as a `gkf.N` page holds it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FloorRow {
    pub group: String,
    pub floor: Floor,
    pub names: Option<NamesFloor>,
    pub last_used: u64,
}

/// One account, as a `gkc.N` page holds it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CounterRow {
    pub account: Id,
    /// The highest seat-key counter seen, with its endorsement's `made`.
    pub counter: Option<(u32, u64)>,
    /// When this account first saw the account's pin, with `tag` of that pin's `IK`: a time
    /// says nothing of another pin.
    pub pin: Option<(u64, [u8; 8])>,
}

/// The higher of two floor pairs: the local and the vault floor, or two devices'.
pub fn higher(a: &FloorPair, b: &FloorPair) -> FloorPair {
    let floor = Floor::merge(&a.0, &b.0);
    let names = match (a.1, b.1) {
        (Some(x), Some(y)) => Some(later_names(x, y, &floor)),
        (x, None) => x,
        (None, y) => y,
    };
    (floor, names)
}

/// The later generation by its `gen_time` in the merged floor, then the higher `(epoch, join)`.
fn later_names(x: NamesFloor, y: NamesFloor, floor: &Floor) -> NamesFloor {
    if x.gen == y.gen {
        return if (y.epoch, y.join) > (x.epoch, x.join) {
            y
        } else {
            x
        };
    }
    let at = |g: [u8; 16]| floor.gens.iter().find(|(id, _)| *id == g).map(|(_, t)| *t);
    if (at(y.gen), y.time) > (at(x.gen), x.time) {
        y
    } else {
        x
    }
}

/// Only stored groups reach the vault.
fn is_stored(group: &str) -> bool {
    group.starts_with("c:") && valid_group_id(group)
}

fn higher_counter(a: Option<(u32, u64)>, b: Option<(u32, u64)>) -> Option<(u32, u64)> {
    match (a, b) {
        (Some(x), Some(y)) if x.0 == y.0 => Some((x.0, x.1.min(y.1))),
        (Some(x), Some(y)) => Some(if x.0 > y.0 { x } else { y }),
        (x, None) => x,
        (None, y) => y,
    }
}

fn merged_pin(a: Option<(u64, [u8; 8])>, b: Option<(u64, [u8; 8])>) -> Option<(u64, [u8; 8])> {
    match (a, b) {
        (Some(x), Some(y)) if x.1 == y.1 => Some((x.0.min(y.0), x.1)),
        (Some(x), Some(y)) => Some(x.max(y)),
        (x, None) => x,
        (None, y) => y,
    }
}

/// What both kinds of row have in common.
trait Row: Clone + PartialEq + Serialize + DeserializeOwned {
    type Key: Ord + Clone;
    fn key(&self) -> Self::Key;
    /// Ours and theirs as one, the same whichever is which.
    fn merged(&self, theirs: &Self) -> Self;
    /// The lowest drops first once every page is full.
    fn age(&self) -> u64;
    /// What a page may hold.
    fn valid(&self) -> bool;
}

impl Row for FloorRow {
    type Key = String;

    fn key(&self) -> String {
        self.group.clone()
    }

    fn merged(&self, theirs: &FloorRow) -> FloorRow {
        let (floor, names) = higher(
            &(self.floor.clone(), self.names),
            &(theirs.floor.clone(), theirs.names),
        );
        FloorRow {
            group: self.group.clone(),
            floor,
            names,
            last_used: self.last_used.max(theirs.last_used),
        }
    }

    fn age(&self) -> u64 {
        self.last_used
    }

    fn valid(&self) -> bool {
        is_stored(&self.group) && self.floor.gens.len() <= RECENT_GENS
    }
}

impl Row for CounterRow {
    type Key = Id;

    fn key(&self) -> Id {
        self.account
    }

    fn merged(&self, theirs: &CounterRow) -> CounterRow {
        CounterRow {
            account: self.account,
            counter: higher_counter(self.counter, theirs.counter),
            pin: merged_pin(self.pin, theirs.pin),
        }
    }

    /// The counter's `made`; with no counter, the pin's time.
    fn age(&self) -> u64 {
        self.counter
            .map(|(_, made)| made)
            .or(self.pin.map(|(since, _)| since))
            .unwrap_or(0)
    }

    fn valid(&self) -> bool {
        self.counter.is_some() || self.pin.is_some()
    }
}

fn row_size<R: Row>(row: &R) -> usize {
    postcard::to_allocvec(row).expect("a row encodes").len()
}

#[derive(Clone)]
struct Held<R> {
    row: R,
    size: usize,
    page: Option<u16>,
}

/// One page as this device holds it.
#[derive(Clone)]
struct Page {
    gen: u64,
    /// The relay's compare-and-set number.
    version: i64,
    /// What it comes to written, at most.
    bytes: usize,
    /// Holds something the relay does not.
    dirty: bool,
    /// A save wanted it out while a write was in flight: it goes when that settles.
    owed: bool,
    /// The generation of the write out: one at a time.
    writing: Option<u64>,
}

impl Default for Page {
    fn default() -> Page {
        Page {
            gen: 0,
            version: 0,
            bytes: LIST_BYTES,
            dirty: false,
            owed: false,
            writing: None,
        }
    }
}

/// What a page from the relay came to.
struct Took<K> {
    /// The keys whose value moved.
    moved: Vec<K>,
    problem: Option<&'static str>,
    /// Newer than the index says.
    index_due: bool,
    gens_moved: bool,
}

impl<K> Took<K> {
    fn problem(problem: &'static str) -> Took<K> {
        Took {
            moved: Vec::new(),
            problem: Some(problem),
            index_due: false,
            gens_moved: false,
        }
    }

    fn nothing() -> Took<K> {
        Took {
            moved: Vec::new(),
            problem: None,
            index_due: false,
            gens_moved: false,
        }
    }
}

/// One kind of row, on its pages.
#[derive(Clone)]
struct Paged<R: Row> {
    prefix: &'static str,
    most: u16,
    rows: BTreeMap<R::Key, Held<R>>,
    pages: Vec<Page>,
    /// Held on no page: new, grown out of its page, or another device's.
    unplaced: BTreeSet<R::Key>,
    /// Held on no page because every page is full of newer rows: known this connection
    /// only, and tried again once it moves.
    spilled: BTreeSet<R::Key>,
}

impl<R: Row> Paged<R> {
    fn new(prefix: &'static str, most: u16) -> Paged<R> {
        Paged {
            prefix,
            most,
            rows: BTreeMap::new(),
            pages: Vec::new(),
            unplaced: BTreeSet::new(),
            spilled: BTreeSet::new(),
        }
    }

    fn name(&self, n: u16) -> String {
        format!("{}{n}", self.prefix)
    }

    fn number(&self, k: &str) -> Option<u16> {
        let n: u16 = k.strip_prefix(self.prefix)?.parse().ok()?;
        (n < self.most && self.name(n) == k).then_some(n)
    }

    fn page_mut(&mut self, n: u16) -> &mut Page {
        let at = n as usize;
        if self.pages.len() <= at {
            self.pages.resize_with(at + 1, Page::default);
        }
        &mut self.pages[at]
    }

    fn gen_of(&self, n: u16) -> u64 {
        self.pages.get(n as usize).map_or(0, |p| p.gen)
    }

    /// Each page's generation, for the index.
    fn gens(&self) -> Vec<u64> {
        let mut gens: Vec<u64> = self.pages.iter().map(|p| p.gen).collect();
        while gens.last() == Some(&0) {
            gens.pop();
        }
        gens
    }

    /// Pages this device saw, by `LogMemory::vault_gens`.
    fn seen_pages(&self, gens: &HashMap<String, u64>) -> usize {
        gens.keys()
            .filter_map(|k| self.number(k))
            .max()
            .map_or(0, |n| n as usize + 1)
    }

    /// Pages whose generation, by the index or as this device saw it, is past the one held.
    fn behind(&self, listed: &[u64], gens: &HashMap<String, u64>) -> Vec<u16> {
        let pages = listed.len().max(self.seen_pages(gens));
        (0..pages as u16)
            .filter(|n| {
                let at = listed.get(*n as usize).copied().unwrap_or(0);
                let seen = gens.get(&self.name(*n)).copied().unwrap_or(0);
                at.max(seen) > self.gen_of(*n)
            })
            .collect()
    }

    fn settled(&self) -> bool {
        self.pages.iter().all(|p| p.writing.is_none())
    }

    fn news(&self) -> bool {
        !self.unplaced.is_empty() || self.pages.iter().any(|p| p.dirty)
    }

    fn home(&mut self, key: &R::Key, n: u16) {
        self.page_mut(n);
        let Some(h) = self.rows.get_mut(key) else {
            return;
        };
        h.page = Some(n);
        self.pages[n as usize].bytes += h.size;
        self.unplaced.remove(key);
        self.spilled.remove(key);
    }

    fn unhome(&mut self, key: &R::Key) {
        let Some(h) = self.rows.get_mut(key) else {
            return;
        };
        if let Some(n) = h.page.take() {
            let page = &mut self.pages[n as usize];
            page.bytes -= h.size;
            page.dirty = true;
        }
        self.unplaced.insert(key.clone());
    }

    /// Off the pages for want of room, still held: what the pages drop, this connection
    /// still knows (§5.11: the highest counter seen is kept).
    fn spill(&mut self, key: &R::Key) {
        let Some(h) = self.rows.get_mut(key) else {
            return;
        };
        if let Some(n) = h.page.take() {
            let page = &mut self.pages[n as usize];
            page.bytes -= h.size;
            page.dirty = true;
        }
        self.unplaced.remove(key);
        self.spilled.insert(key.clone());
    }

    /// `row` in place of what is held under its key, its page's bytes kept up. No page is
    /// dirtied: the caller says which.
    fn replace(&mut self, row: R) {
        let key = row.key();
        let size = row_size(&row);
        match self.rows.get_mut(&key) {
            Some(h) => {
                if let Some(n) = h.page {
                    let page = &mut self.pages[n as usize];
                    page.bytes = page.bytes - h.size + size;
                }
                h.row = row;
                h.size = size;
            }
            None => {
                self.rows.insert(
                    key.clone(),
                    Held {
                        row,
                        size,
                        page: None,
                    },
                );
                self.unplaced.insert(key);
            }
        }
    }

    /// Ours merged with `row`: whether what is held moved. A row that grew past its page
    /// leaves it, for one with room at the next save.
    fn put(&mut self, row: R) -> bool {
        let key = row.key();
        let merged = match self.rows.get(&key) {
            Some(h) => h.row.merged(&row),
            None => row,
        };
        self.set(merged)
    }

    /// `row` as it is: whether that moved what is held.
    fn set(&mut self, row: R) -> bool {
        let key = row.key();
        if self.rows.get(&key).is_some_and(|h| h.row == row) {
            return false;
        }
        self.replace(row);
        if let Some(n) = self.rows[&key].page {
            self.pages[n as usize].dirty = true;
            if self.pages[n as usize].bytes > PAGE_BYTES {
                self.unhome(&key);
            }
        } else if self.spilled.remove(&key) {
            // Newer now, it may make the pages at the next save
            self.unplaced.insert(key);
        }
        true
    }

    /// Rows off page `n` until it fits: they go on another page at the next save.
    fn fit(&mut self, n: u16) {
        while self.pages[n as usize].bytes > PAGE_BYTES {
            let last = self
                .rows
                .iter()
                .rev()
                .find(|(_, h)| h.page == Some(n))
                .map(|(k, _)| k.clone());
            let Some(key) = last else {
                break;
            };
            self.unhome(&key);
        }
    }

    /// Page `n`'s rows taken in, from the relay or from another device's write: merged with
    /// ours, and held on `n` when held on no page. Page `n` is dirtied when it holds less than
    /// we do there, and another page when its row moved.
    fn take(&mut self, n: u16, rows: Vec<R>) -> Vec<R::Key> {
        self.page_mut(n);
        let mut moved = Vec::new();
        let mut behind = false;
        let mut on_page = BTreeSet::new();
        for theirs in rows {
            let key = theirs.key();
            if !theirs.valid() || !on_page.insert(key.clone()) {
                continue;
            }
            let ours = self.rows.get(&key).map(|h| (h.row.clone(), h.page));
            let merged = match &ours {
                Some((row, _)) => row.merged(&theirs),
                None => theirs.clone(),
            };
            let home = ours.as_ref().and_then(|(_, page)| *page);
            match &ours {
                Some((row, _)) if *row != merged => {
                    moved.push(key.clone());
                    if let Some(m) = home.filter(|m| *m != n) {
                        self.pages[m as usize].dirty = true;
                    }
                }
                Some(_) => {}
                // New here: the host may hold a lower floor of its own for it
                None => moved.push(key.clone()),
            }
            self.replace(merged.clone());
            match home {
                None => {
                    self.home(&key, n);
                    behind |= merged != theirs;
                }
                Some(m) if m == n => behind |= merged != theirs,
                // Held on another page: this copy drops when page `n` is next written
                Some(_) => {}
            }
        }
        behind |= self
            .rows
            .iter()
            .any(|(k, h)| h.page == Some(n) && !on_page.contains(k));
        if behind {
            self.pages[n as usize].dirty = true;
        }
        self.fit(n);
        moved
    }

    /// A page the relay handed over (`VaultPageFound`), `listed` by the index.
    fn found(
        &mut self,
        n: u16,
        listed: u64,
        blob: Option<&VaultBlob>,
        io: &mut Io<'_>,
    ) -> Took<R::Key> {
        let k = self.name(n);
        let seen = io.gens.get(&k).copied().unwrap_or(0);
        let expect = seen.max(listed).max(self.gen_of(n));
        let Some(b) = blob else {
            return if expect == 0 {
                Took::nothing()
            } else {
                Took::problem("missing")
            };
        };
        let item = match io.vault.open_item(std::slice::from_ref(b), &k) {
            Ok(item) => item,
            Err(VaultError::Newer) => return Took::problem("newer"),
            Err(_) => return Took::problem("unreadable"),
        };
        let Ok(rows) = postcard::from_bytes::<Vec<R>>(&item.payload) else {
            return Took::problem("unreadable");
        };
        self.page_mut(n).version = b.version;
        let moved = self.take(n, rows);
        if item.gen < expect {
            // Still of use, as at start: only nothing goes over it
            return Took {
                moved,
                ..Took::problem("older")
            };
        }
        self.page_mut(n).gen = item.gen;
        io.gens.insert(k, item.gen);
        Took {
            moved,
            problem: None,
            index_due: item.gen > listed,
            gens_moved: true,
        }
    }

    /// `VaultConflict` for page `n`: another device wrote it first, and the rows join.
    fn conflict(&mut self, n: u16, theirs: Option<&VaultBlob>, io: &mut Io<'_>) -> Took<R::Key> {
        let k = self.name(n);
        self.page_mut(n).writing = None;
        let seen = io.gens.get(&k).copied().unwrap_or(0).max(self.gen_of(n));
        let Some(b) = theirs else {
            if seen > 0 {
                return Took::problem("missing");
            }
            let page = self.page_mut(n);
            page.version = 0;
            page.dirty = true;
            page.owed = true;
            return Took::nothing();
        };
        let item = match io.vault.open_item(std::slice::from_ref(b), &k) {
            Ok(item) if item.gen < seen => return Took::problem("older"),
            Ok(item) => item,
            Err(VaultError::Newer) => return Took::problem("newer"),
            Err(_) => return Took::problem("unreadable"),
        };
        let Ok(rows) = postcard::from_bytes::<Vec<R>>(&item.payload) else {
            return Took::problem("unreadable");
        };
        let moved = self.take(n, rows);
        io.gens.insert(k, item.gen);
        let page = self.page_mut(n);
        page.gen = item.gen;
        page.version = b.version;
        page.dirty = true;
        page.owed = true;
        Took {
            moved,
            problem: None,
            index_due: false,
            gens_moved: true,
        }
    }

    /// `VaultStored` for page `n`: whether its generation moved.
    fn stored(&mut self, n: u16, version: i64, gens: &mut HashMap<String, u64>) -> bool {
        let k = self.name(n);
        let page = self.page_mut(n);
        page.version = version;
        let Some(gen) = page.writing.take() else {
            return false;
        };
        page.gen = gen;
        gens.insert(k, gen);
        true
    }

    /// Rows onto pages: the first with room, else a new page, else the oldest row on a page
    /// by `age` leaves it, which may be the new one itself. The newest go first. What leaves
    /// is still held (`spilled`). One sort and one heap, so a fold that raised 100k accounts
    /// places them at once.
    fn place(&mut self) {
        let unplaced = std::mem::take(&mut self.unplaced);
        let mut new: Vec<(u64, R::Key)> = unplaced
            .into_iter()
            .filter_map(|k| self.rows.get(&k).map(|h| (h.row.age(), k)))
            .collect();
        new.sort_by_key(|(age, _)| Reverse(*age));
        // The rows on pages, oldest first: made the first time a row finds no room
        let mut on_pages: Option<Oldest<R::Key>> = None;
        for (age, key) in new {
            let size = self.rows[&key].size;
            if size + LIST_BYTES > PAGE_BYTES {
                self.spilled.insert(key);
                continue;
            }
            loop {
                let room = self.pages.len() < self.most as usize;
                let n = self
                    .pages
                    .iter()
                    .position(|p| p.bytes + size <= PAGE_BYTES)
                    .or(room.then_some(self.pages.len()));
                if let Some(n) = n {
                    self.home(&key, n as u16);
                    self.pages[n].dirty = true;
                    if let Some(heap) = on_pages.as_mut() {
                        heap.push(Reverse((age, key)));
                    }
                    break;
                }
                let heap = on_pages.get_or_insert_with(|| {
                    self.rows
                        .iter()
                        .filter(|(_, h)| h.page.is_some())
                        .map(|(k, h)| Reverse((h.row.age(), k.clone())))
                        .collect()
                });
                match heap.peek().map(|Reverse((at, _))| *at) {
                    Some(at) if at < age => {
                        if let Some(Reverse((_, victim))) = heap.pop() {
                            self.spill(&victim);
                        }
                    }
                    _ => {
                        self.spilled.insert(key);
                        break;
                    }
                }
            }
        }
    }

    /// Every page with news (`all`), or only those owed, one write at a time each.
    fn write(
        &mut self,
        vault: &Vault,
        gens: &HashMap<String, u64>,
        all: bool,
    ) -> Vec<ClientMessage> {
        let mut due = vec![false; self.pages.len()];
        for (at, page) in self.pages.iter_mut().enumerate() {
            if !page.dirty || !(all || page.owed) {
                continue;
            }
            if page.writing.is_some() {
                page.owed = true;
                continue;
            }
            due[at] = true;
        }
        if !due.contains(&true) {
            return Vec::new();
        }
        // One pass over the rows for every page due
        let mut lists: Vec<Vec<&R>> = vec![Vec::new(); self.pages.len()];
        for h in self.rows.values() {
            if let Some(n) = h.page.filter(|n| due[*n as usize]) {
                lists[n as usize].push(&h.row);
            }
        }
        let mut out = Vec::new();
        for (at, rows) in lists.iter().enumerate() {
            if !due[at] {
                continue;
            }
            let n = at as u16;
            let bytes = postcard::to_allocvec(rows).expect("rows encode");
            debug_assert!(bytes.len() <= PAGE_BYTES);
            let k = format!("{}{n}", self.prefix);
            let gen = gens.get(&k).copied().unwrap_or(0).max(self.pages[at].gen) + 1;
            let blob = vault.seal_item(&k, gen, &bytes);
            let page = &mut self.pages[at];
            page.dirty = false;
            page.owed = false;
            page.writing = Some(gen);
            out.push(ask(AccountRequest::VaultPut {
                k,
                v: blob.v,
                expect: page.version,
            }));
        }
        out
    }
}

/// What the calls that read or write need of `AccountSync`: its vault, and
/// `LogMemory::vault_gens`.
pub struct Io<'a> {
    pub vault: &'a Vault,
    pub gens: &'a mut HashMap<String, u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Want {
    Floors(u16),
    Counters(u16),
}

/// What one connection of an account hands the next: every row and page, so only pages
/// whose generation moved are read again.
pub struct KeptGkFloors {
    floors: Paged<FloorRow>,
    counters: Paged<CounterRow>,
}

/// The floors and counters of one signed-in account.
pub struct GkFloors {
    floors: Paged<FloorRow>,
    counters: Paged<CounterRow>,
    /// What `item.gk_floors` said, at sign-in or since.
    index: Option<GkIndex>,
    index_version: i64,
    index_writing: Option<u64>,
    index_due: bool,
    /// The relay keeps group keys, and the pages were asked for.
    begun: bool,
    adopted: bool,
    pages_in: bool,
    /// Every pin the account held was timed this connection (`pins_held`).
    pins_timed: bool,
    to_read: VecDeque<Want>,
    asked: Option<Want>,
    idle: u32,
    /// Ticks since this connection began waiting for pages.
    out_ticks: u32,
    /// The relay's copy cannot be used: nothing is saved over it this connection.
    read_only: bool,
    /// The relay has no more room: nothing more this connection.
    full: bool,
    /// Refused for now: goes again at the next tick.
    retry: bool,
    /// A new generation waits to be saved.
    urgent: bool,
    saved_at: u64,
    /// Groups whose vault floor another device raised, after the pages were in.
    raised: BTreeSet<String>,
    later: Vec<Event>,
    memory_changed: bool,
}

impl GkFloors {
    /// At sign-in: `item.gk_floors` from the vault, under the rules `AccountSync::start`
    /// loads every item by.
    pub fn start(vault: &Vault, blobs: &[VaultBlob], gens: &mut HashMap<String, u64>) -> GkFloors {
        let mut s = GkFloors {
            floors: Paged::new(FLOOR_PREFIX, FLOOR_PAGES),
            counters: Paged::new(COUNTER_PREFIX, COUNTER_PAGES),
            index: None,
            index_version: blobs
                .iter()
                .find(|b| b.k == ITEM_GK_FLOORS)
                .map_or(0, |b| b.version),
            index_writing: None,
            index_due: false,
            begun: false,
            adopted: false,
            pages_in: false,
            pins_timed: false,
            to_read: VecDeque::new(),
            asked: None,
            idle: 0,
            out_ticks: 0,
            read_only: false,
            full: false,
            retry: false,
            urgent: false,
            saved_at: 0,
            raised: BTreeSet::new(),
            later: Vec::new(),
            memory_changed: false,
        };
        let seen = gens.get(ITEM_GK_FLOORS).copied().unwrap_or(0);
        match vault.open_item(blobs, ITEM_GK_FLOORS) {
            Ok(item) => match GkIndex::from_bytes(&item.payload) {
                Ok(index) => {
                    if item.gen < seen {
                        s.problem("older");
                    } else {
                        gens.insert(ITEM_GK_FLOORS.to_string(), item.gen);
                        s.memory_changed = true;
                    }
                    s.index = Some(index);
                }
                Err(problem) => s.problem(problem),
            },
            Err(VaultError::Missing) if seen == 0 => {}
            Err(VaultError::Missing) => s.problem("missing"),
            Err(VaultError::Newer) => s.problem("newer"),
            Err(_) => s.problem("unreadable"),
        }
        s
    }

    /// Whether `k` is the index or one of its pages: its vault replies come here.
    pub fn is_ours(k: &str) -> bool {
        k == ITEM_GK_FLOORS || k.starts_with(FLOOR_PREFIX) || k.starts_with(COUNTER_PREFIX)
    }

    /// Told once: nothing here is saved over for this connection.
    fn problem(&mut self, problem: &'static str) {
        if !self.read_only {
            self.read_only = true;
            self.later.push(Event::VaultProblem {
                item: ITEM_GK_FLOORS,
                problem,
            });
        }
    }

    /// Takes over what an earlier connection of this account kept, before `begin`.
    pub fn adopt(&mut self, kept: KeptGkFloors) {
        if self.begun || self.index.is_none() {
            return;
        }
        let KeptGkFloors {
            mut floors,
            mut counters,
        } = kept;
        for page in floors.pages.iter_mut().chain(counters.pages.iter_mut()) {
            if page.writing.take().is_some() {
                page.dirty = true;
                page.owed = true;
            }
        }
        self.floors = floors;
        self.counters = counters;
        self.adopted = true;
    }

    /// What this connection hands the next, once it read the pages.
    pub fn keep(&self) -> Option<KeptGkFloors> {
        self.pages_in.then(|| KeptGkFloors {
            floors: self.floors.clone(),
            counters: self.counters.clone(),
        })
    }

    /// The relay keeps group keys: the pages are read, one at a time. The host starts this
    /// once the pin pages are in, so one `VaultPage` is out at a time.
    pub fn begin(&mut self, gens: &HashMap<String, u64>, now: u64) -> Vec<ClientMessage> {
        if self.begun {
            return Vec::new();
        }
        self.begun = true;
        self.saved_at = now;
        let index = self.index.clone().unwrap_or_default();
        if self.adopted {
            // Only what moved, and the index again if it names less than is held. A page
            // this device saw at a generation the held one is short of (the last connection
            // found it missing or older) is read again, and said again: never written over.
            let floors = self.floors.behind(&index.floor_pages, gens);
            let counters = self.counters.behind(&index.counter_pages, gens);
            self.to_read.extend(floors.into_iter().map(Want::Floors));
            self.to_read
                .extend(counters.into_iter().map(Want::Counters));
            let ahead = |held: &[Page], listed: &[u64]| {
                held.iter()
                    .enumerate()
                    .any(|(n, p)| p.gen > listed.get(n).copied().unwrap_or(0))
            };
            self.index_due |= ahead(&self.floors.pages[..], &index.floor_pages[..])
                || ahead(&self.counters.pages[..], &index.counter_pages[..]);
        } else {
            // And any page this device saw that no index names: saved in a moment that lost
            // the index's write, or a page a relay would rather it forgot
            let floors = index.floor_pages.len().max(self.floors.seen_pages(gens));
            let counters = index
                .counter_pages
                .len()
                .max(self.counters.seen_pages(gens));
            self.to_read.extend((0..floors as u16).map(Want::Floors));
            self.to_read
                .extend((0..counters as u16).map(Want::Counters));
        }
        let out = self.ask_next();
        if !self.reading() {
            self.pages_in = true;
        }
        out
    }

    /// Whether the pages are in: no header of a stored group is taken before.
    pub fn pages_in(&self) -> bool {
        self.pages_in
    }

    /// Whether a `VaultPage` of ours is out: a refusal names no page.
    pub fn asking(&self) -> bool {
        self.asked.is_some()
    }

    fn reading(&self) -> bool {
        self.asked.is_some() || !self.to_read.is_empty()
    }

    fn page_name(&self, w: Want) -> String {
        match w {
            Want::Floors(n) => self.floors.name(n),
            Want::Counters(n) => self.counters.name(n),
        }
    }

    fn want_of(&self, k: &str) -> Option<Want> {
        self.floors
            .number(k)
            .map(Want::Floors)
            .or_else(|| self.counters.number(k).map(Want::Counters))
    }

    fn ask_next(&mut self) -> Vec<ClientMessage> {
        if self.asked.is_some() {
            return Vec::new();
        }
        let Some(w) = self.to_read.pop_front() else {
            return Vec::new();
        };
        self.asked = Some(w);
        self.idle = 0;
        vec![ask(AccountRequest::VaultPage {
            k: self.page_name(w),
        })]
    }

    fn go_on(&mut self, io: &mut Io<'_>) -> Vec<ClientMessage> {
        let mut out = self.ask_next();
        if self.reading() {
            return out;
        }
        self.pages_in = true;
        out.extend(self.save_index_when_settled(io));
        out
    }

    /// What a page from the relay came to, for either kind.
    fn took<K>(&mut self, t: Took<K>) -> Vec<K> {
        if let Some(problem) = t.problem {
            self.problem(problem);
        }
        self.index_due |= t.index_due;
        self.memory_changed |= t.gens_moved;
        t.moved
    }

    fn note_raised(&mut self, moved: Vec<String>) {
        if self.pages_in {
            self.raised.extend(moved);
        }
    }

    /// `VaultPageFound`: a page, or none.
    pub fn on_page(
        &mut self,
        mut io: Io<'_>,
        k: &str,
        blob: Option<&VaultBlob>,
    ) -> Vec<ClientMessage> {
        let Some(want) = self.want_of(k).filter(|w| self.asked == Some(*w)) else {
            return Vec::new();
        };
        self.asked = None;
        let index = self.index.clone().unwrap_or_default();
        let listed = |gens: &[u64], n: u16| gens.get(n as usize).copied().unwrap_or(0);
        match want {
            Want::Floors(n) => {
                let at = listed(&index.floor_pages[..], n);
                let t = self.floors.found(n, at, blob, &mut io);
                let moved = self.took(t);
                self.note_raised(moved);
            }
            Want::Counters(n) => {
                let at = listed(&index.counter_pages[..], n);
                let t = self.counters.found(n, at, blob, &mut io);
                self.took(t);
            }
        }
        self.go_on(&mut io)
    }

    /// `VaultPage` was refused.
    pub fn on_read_refused(&mut self, mut io: Io<'_>, reason: &str) -> Vec<ClientMessage> {
        let Some(w) = self.asked.take() else {
            return Vec::new();
        };
        if reason.contains(SLOW_DOWN) {
            self.to_read.push_front(w);
            return Vec::new();
        }
        self.problem("missing");
        self.go_on(&mut io)
    }

    /// Every couple of seconds while connected: a page lost or refused for now goes again,
    /// and what waits is saved when due.
    pub fn tick(&mut self, mut io: Io<'_>, now: u64) -> Vec<ClientMessage> {
        if !self.begun {
            return Vec::new();
        }
        if self.reading() {
            if !self.pages_in {
                self.out_ticks += 1;
                if self.out_ticks == PAGES_SAID_AFTER_TICKS {
                    self.later.push(Event::VaultProblem {
                        item: ITEM_GK_FLOORS,
                        problem: "withheld",
                    });
                }
            }
            if let Some(w) = self.asked {
                self.idle += 1;
                if self.idle < LOST_AFTER_TICKS {
                    return Vec::new();
                }
                self.asked = None;
                self.to_read.push_front(w);
            }
            return self.ask_next();
        }
        let news = self.floors.news() || self.counters.news();
        if self.urgent || self.retry || (news && now >= self.saved_at.saturating_add(SAVE_EVERY)) {
            return self.flush(io, now);
        }
        self.save_index_when_settled(&mut io)
    }

    /// Everything with news out now: what a new generation or a sign-out asks.
    pub fn flush(&mut self, mut io: Io<'_>, now: u64) -> Vec<ClientMessage> {
        if !self.pages_in || self.reading() || self.read_only || self.full {
            return Vec::new();
        }
        self.saved_at = now;
        self.retry = false;
        self.urgent = false;
        self.floors.place();
        self.counters.place();
        let mut out = self.floors.write(io.vault, io.gens, true);
        out.extend(self.counters.write(io.vault, io.gens, true));
        out.extend(self.save_index_when_settled(&mut io));
        out
    }

    /// Whether a save is due now rather than within the minute: a new generation.
    pub fn save_now(&self) -> bool {
        self.urgent
    }

    /// Whether anything is still on its way. A sign-out waits a moment for this.
    pub fn saved(&self) -> bool {
        !self.begun
            || (self.floors.settled()
                && self.counters.settled()
                && self.index_writing.is_none()
                && !self.index_due)
    }

    fn write_owed(&mut self, io: &mut Io<'_>) -> Vec<ClientMessage> {
        if self.read_only || self.full {
            return Vec::new();
        }
        let mut out = self.floors.write(io.vault, io.gens, false);
        out.extend(self.counters.write(io.vault, io.gens, false));
        out
    }

    pub fn index_bytes(&self) -> Vec<u8> {
        GkIndex {
            format: INDEX_FORMAT,
            floor_pages: self.floors.gens(),
            counter_pages: self.counters.gens(),
        }
        .to_bytes()
    }

    /// The index, once no page is out: it may promise only what the pages hold.
    fn save_index_when_settled(&mut self, io: &mut Io<'_>) -> Vec<ClientMessage> {
        let settled = self.floors.settled() && self.counters.settled() && !self.reading();
        if !self.begun
            || !self.index_due
            || !settled
            || self.read_only
            || self.full
            || self.index_writing.is_some()
        {
            return Vec::new();
        }
        self.index_due = false;
        let gen = io.gens.get(ITEM_GK_FLOORS).copied().unwrap_or(0) + 1;
        self.index_writing = Some(gen);
        let blob = io.vault.seal_item(ITEM_GK_FLOORS, gen, &self.index_bytes());
        vec![ask(AccountRequest::VaultPut {
            k: ITEM_GK_FLOORS.to_string(),
            v: blob.v,
            expect: self.index_version,
        })]
    }

    /// `VaultStored` for the index or a page.
    pub fn on_stored(&mut self, mut io: Io<'_>, k: &str, version: i64) -> Vec<ClientMessage> {
        if k == ITEM_GK_FLOORS {
            self.index_version = version;
            if let Some(gen) = self.index_writing.take() {
                io.gens.insert(k.to_string(), gen);
                self.memory_changed = true;
            }
            return self.save_index_when_settled(&mut io);
        }
        let moved = match self.want_of(k) {
            Some(Want::Floors(n)) => self.floors.stored(n, version, io.gens),
            Some(Want::Counters(n)) => self.counters.stored(n, version, io.gens),
            None => return Vec::new(),
        };
        if moved {
            self.index_due = true;
            self.memory_changed = true;
        }
        let mut out = self.write_owed(&mut io);
        out.extend(self.save_index_when_settled(&mut io));
        out
    }

    /// `VaultConflict` for the index or a page: another device wrote it first.
    pub fn on_conflict(
        &mut self,
        mut io: Io<'_>,
        k: &str,
        theirs: Option<&VaultBlob>,
    ) -> Vec<ClientMessage> {
        if k == ITEM_GK_FLOORS {
            return self.on_index_conflict(io, theirs);
        }
        match self.want_of(k) {
            Some(Want::Floors(n)) => {
                let t = self.floors.conflict(n, theirs, &mut io);
                let moved = self.took(t);
                self.note_raised(moved);
            }
            Some(Want::Counters(n)) => {
                let t = self.counters.conflict(n, theirs, &mut io);
                self.took(t);
            }
            None => return Vec::new(),
        }
        let mut out = self.write_owed(&mut io);
        out.extend(self.save_index_when_settled(&mut io));
        out
    }

    /// Another device's index: the pages that moved are read and joined, and the index goes
    /// again after them.
    fn on_index_conflict(
        &mut self,
        mut io: Io<'_>,
        theirs: Option<&VaultBlob>,
    ) -> Vec<ClientMessage> {
        self.index_writing = None;
        let seen = io.gens.get(ITEM_GK_FLOORS).copied().unwrap_or(0);
        match theirs.map(|b| {
            (
                b,
                io.vault.open_item(std::slice::from_ref(b), ITEM_GK_FLOORS),
            )
        }) {
            None if seen > 0 => self.problem("missing"),
            None => {
                self.index_version = 0;
                self.index_due = true;
            }
            Some((_, Ok(item))) if item.gen < seen => self.problem("older"),
            Some((b, Ok(item))) => match GkIndex::from_bytes(&item.payload) {
                Ok(index) => {
                    io.gens.insert(ITEM_GK_FLOORS.to_string(), item.gen);
                    self.memory_changed = true;
                    self.index_version = b.version;
                    for (n, gen) in index.floor_pages.iter().enumerate() {
                        if *gen > self.floors.gen_of(n as u16) {
                            self.want(Want::Floors(n as u16));
                        }
                    }
                    for (n, gen) in index.counter_pages.iter().enumerate() {
                        if *gen > self.counters.gen_of(n as u16) {
                            self.want(Want::Counters(n as u16));
                        }
                    }
                    self.index = Some(index);
                    self.index_due = true;
                }
                Err(problem) => self.problem(problem),
            },
            Some((_, Err(VaultError::Newer))) => self.problem("newer"),
            Some((_, Err(_))) => self.problem("unreadable"),
        }
        let mut out = self.ask_next();
        out.extend(self.save_index_when_settled(&mut io));
        out
    }

    fn want(&mut self, w: Want) {
        if self.asked != Some(w) && !self.to_read.contains(&w) {
            self.to_read.push_back(w);
        }
    }

    /// A `VaultPut` was refused (the refusal names no item): for now, it goes again;
    /// otherwise the relay has no room, and is not asked again this connection.
    pub fn write_refused(&mut self, reason: &str) {
        let mut ours = false;
        let pages = self
            .floors
            .pages
            .iter_mut()
            .chain(self.counters.pages.iter_mut());
        for page in pages {
            if page.writing.take().is_some() {
                page.dirty = true;
                page.owed = true;
                ours = true;
            }
        }
        if self.index_writing.take().is_some() {
            self.index_due = true;
            ours = true;
        }
        if reason.contains(SLOW_DOWN) {
            self.retry |= ours;
        } else if ours {
            self.full = true;
        }
    }

    // ── floors ──

    /// The vault floor of a stored group, once the pages are in.
    pub fn floor(&self, group: &str) -> Result<Option<FloorPair>, Pending> {
        self.pages_in.then(|| self.held(group)).ok_or(Pending)
    }

    fn held(&self, group: &str) -> Option<FloorPair> {
        self.floors
            .rows
            .get(group)
            .map(|h| (h.row.floor.clone(), h.row.names))
    }

    /// A floor `GroupKeying` took (`GkOut::vault_floors`), merged with what is held. A new
    /// generation is saved at once; the rest within the minute. Memory-only groups are not
    /// kept.
    pub fn put_floor(&mut self, group: &str, floor: Floor, names: Option<NamesFloor>, now: u64) {
        if !is_stored(group) {
            return;
        }
        let gen_of = |s: &GkFloors| s.floors.rows.get(group).map(|h| h.row.floor.gen);
        let was = gen_of(self);
        let row = FloorRow {
            group: group.to_string(),
            floor,
            names,
            last_used: now,
        };
        if self.floors.put(row) && gen_of(self) != was {
            self.urgent = true;
        }
    }

    /// The group was used: what drops when the pages are full is used least recently.
    pub fn touch(&mut self, group: &str, now: u64) {
        let Some(h) = self.floors.rows.get(group) else {
            return;
        };
        if now > h.row.last_used.saturating_add(TOUCH_EVERY) {
            let mut row = h.row.clone();
            row.last_used = now;
            self.floors.set(row);
        }
    }

    /// Groups whose vault floor another device raised since the pages came in: the floor in
    /// use is the higher of the two.
    pub fn take_raised(&mut self) -> Vec<(String, FloorPair)> {
        std::mem::take(&mut self.raised)
            .into_iter()
            .filter_map(|g| self.held(&g).map(|f| (g, f)))
            .collect()
    }

    // ── counters and pin times ──

    /// The highest counter seen for `account`, with its endorsement's `made`, once the pages
    /// are in. C1's `Counters` is only made from an answer.
    pub fn seen(&self, account: &Id) -> Result<Option<Seen>, Pending> {
        let seen = || {
            self.counters
                .rows
                .get(account)
                .and_then(|h| h.row.counter)
                .map(|(n, made)| Seen { n, made })
        };
        self.pages_in.then(seen).ok_or(Pending)
    }

    /// An endorsement seen for `account`: whether it raised what is held.
    pub fn raise(&mut self, account: Id, seen: Seen) -> bool {
        self.counters.put(CounterRow {
            account,
            counter: Some((seen.n, seen.made)),
            pin: None,
        })
    }

    /// Every pin the account holds, once the pages are in, at each connection: a pin with no
    /// time for its key is timed now. So a pin met before group keys, or set by an app that
    /// keeps no times, is checked from the first sign-in that saw it, and a relay seating a
    /// ghost under it after that is caught. Pin times are not answered before this.
    pub fn pins_held(&mut self, pins: impl IntoIterator<Item = (Id, [u8; 32])>, now: u64) -> bool {
        let since = self.vouched(now);
        let mut moved = false;
        for (account, ik) in pins {
            moved |= self.time_pin(account, &ik, since);
        }
        self.pins_timed = true;
        moved
    }

    /// `account`'s pin is `ik` from now: a pin made, changed, or merged in from another
    /// device with a change, during the connection. Not before a check: that would date the
    /// pin by the check, and an honest pin would read as unknown for every older header.
    pub fn pin_seen(&mut self, account: Id, ik: &[u8; 32], now: u64) -> bool {
        let since = self.vouched(now);
        self.time_pin(account, ik, since)
    }

    /// No clock dates a pin before the newest header this account took, less a header
    /// clock's slack: that header passed rule 7 on a device of this account, so the time is
    /// at least that. A clock running behind would date a pin before it was the pin, and
    /// every device of the account would refuse honest older names (§5.7).
    fn vouched(&self, now: u64) -> u64 {
        let newest = self.floors.rows.values().map(|h| h.row.floor.time).max();
        now.max(newest.unwrap_or(0).saturating_sub(CLOCK_SLACK))
    }

    fn time_pin(&mut self, account: Id, ik: &[u8; 32], since: u64) -> bool {
        let t = tag(ik);
        let mut row = match self.counters.rows.get(&account) {
            Some(h) if h.row.pin.is_some_and(|(_, held)| held == t) => return false,
            Some(h) => h.row.clone(),
            None => CounterRow {
                account,
                counter: None,
                pin: None,
            },
        };
        row.pin = Some((since, t));
        self.counters.set(row)
    }

    /// C1's `PinsAt` for one account whose pin is `pin`: the pin from its time on (with the
    /// slack a header's clock has), unknown before it or with no time for this pin. Only
    /// once the pages are in and the pins timed.
    pub fn pin_then(
        &self,
        account: &Id,
        pin: Option<&[u8; 32]>,
        time: u64,
    ) -> Result<PinThen, Pending> {
        if !self.pages_in || !self.pins_timed {
            return Err(Pending);
        }
        let Some(ik) = pin else {
            return Ok(PinThen::None);
        };
        let since = self
            .counters
            .rows
            .get(account)
            .and_then(|h| h.row.pin)
            .filter(|(_, t)| *t == tag(ik))
            .map(|(since, _)| since);
        Ok(match since {
            Some(since) if time > since.saturating_add(CLOCK_SLACK) => PinThen::Pin(*ik),
            _ => PinThen::Unknown,
        })
    }

    // ── for the host ──

    pub fn take_events(&mut self) -> Vec<Event> {
        std::mem::take(&mut self.later)
    }

    /// Whether `LogMemory::vault_gens` moved: the host keeps it again.
    pub fn take_memory_changed(&mut self) -> bool {
        std::mem::take(&mut self.memory_changed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group_key::counter_flagged;
    use std::time::{Duration, Instant};

    const RELAY: [u8; 16] = [3; 16];
    const NOW: u64 = 1_800_000_000;
    const DAY: u64 = 24 * 60 * 60;

    /// Answers for a test whose pages are in.
    impl GkFloors {
        fn floor_in(&self, group: &str) -> Option<FloorPair> {
            self.floor(group).expect("pages in")
        }

        fn seen_in(&self, account: &Id) -> Option<Seen> {
            self.seen(account).expect("pages in")
        }

        fn pin_then_in(&self, account: &Id, pin: Option<&[u8; 32]>, time: u64) -> PinThen {
            self.pin_then(account, pin, time)
                .expect("pages in, pins timed")
        }

        /// Whether `account`'s row is on a page, not only in memory.
        fn counter_stored(&self, account: &Id) -> bool {
            self.counters
                .rows
                .get(account)
                .is_some_and(|h| h.page.is_some())
        }

        fn floor_stored(&self, group: &str) -> bool {
            self.floors
                .rows
                .get(group)
                .is_some_and(|h| h.page.is_some())
        }
    }

    /// The relay's side of the vault: compare-and-set by version.
    #[derive(Default)]
    struct Relay {
        items: BTreeMap<String, VaultBlob>,
    }

    impl Relay {
        fn put(&mut self, k: &str, v: Vec<u8>, expect: i64) -> Result<i64, Option<VaultBlob>> {
            let held = self.items.get(k).map_or(0, |b| b.version);
            if held != expect {
                return Err(self.items.get(k).cloned());
            }
            let version = held + 1;
            self.items.insert(
                k.to_string(),
                VaultBlob {
                    k: k.to_string(),
                    v,
                    version,
                },
            );
            Ok(version)
        }

        /// What a sign-in hands over: the main vault, the index among it.
        fn sign_in(&self) -> Vec<VaultBlob> {
            self.items
                .values()
                .filter(|b| b.k.starts_with("item."))
                .cloned()
                .collect()
        }
    }

    struct Device {
        vault: Vault,
        gens: HashMap<String, u64>,
        book: GkFloors,
    }

    impl Device {
        fn new(vault: &Vault, relay: &Relay, gens: HashMap<String, u64>) -> Device {
            let vault = Vault::from_dek(RELAY, "me", vault.dek());
            let mut gens = gens;
            let book = GkFloors::start(&vault, &relay.sign_in(), &mut gens);
            Device { vault, gens, book }
        }

        fn io(&mut self) -> (&mut GkFloors, Io<'_>) {
            (
                &mut self.book,
                Io {
                    vault: &self.vault,
                    gens: &mut self.gens,
                },
            )
        }

        /// Answers what went out until nothing more does: the keys written, in order.
        fn run(&mut self, relay: &mut Relay, out: Vec<ClientMessage>) -> Vec<String> {
            let mut went = Vec::new();
            let mut queue: VecDeque<ClientMessage> = out.into();
            while let Some(m) = queue.pop_front() {
                let more = match m {
                    ClientMessage::Account(AccountRequest::VaultPut { k, v, expect }) => {
                        went.push(k.clone());
                        let (book, io) = self.io();
                        match relay.put(&k, v, expect) {
                            Ok(version) => book.on_stored(io, &k, version),
                            Err(theirs) => book.on_conflict(io, &k, theirs.as_ref()),
                        }
                    }
                    ClientMessage::Account(AccountRequest::VaultPage { k }) => {
                        let blob = relay.items.get(&k).cloned();
                        let (book, io) = self.io();
                        book.on_page(io, &k, blob.as_ref())
                    }
                    _ => Vec::new(),
                };
                queue.extend(more);
            }
            went
        }

        fn begin(&mut self, relay: &mut Relay) -> Vec<String> {
            let out = self.book.begin(&self.gens, NOW);
            self.run(relay, out)
        }

        fn flush(&mut self, relay: &mut Relay, now: u64) -> Vec<String> {
            let (book, io) = self.io();
            let out = book.flush(io, now);
            self.run(relay, out)
        }

        fn tick(&mut self, relay: &mut Relay, now: u64) -> Vec<String> {
            let (book, io) = self.io();
            let out = book.tick(io, now);
            self.run(relay, out)
        }

        fn problems(&mut self) -> Vec<&'static str> {
            problems(&self.book.take_events())
        }
    }

    fn problems(events: &[Event]) -> Vec<&'static str> {
        events
            .iter()
            .filter_map(|e| match e {
                Event::VaultProblem { item, problem } if *item == ITEM_GK_FLOORS => Some(*problem),
                _ => None,
            })
            .collect()
    }

    fn asks(out: &[ClientMessage]) -> Vec<String> {
        out.iter()
            .filter_map(|m| match m {
                ClientMessage::Account(AccountRequest::VaultPage { k }) => Some(k.clone()),
                _ => None,
            })
            .collect()
    }

    fn puts(out: &[ClientMessage]) -> Vec<String> {
        out.iter()
            .filter_map(|m| match m {
                ClientMessage::Account(AccountRequest::VaultPut { k, .. }) => Some(k.clone()),
                _ => None,
            })
            .collect()
    }

    fn group(n: u32) -> String {
        format!("c:group{n}")
    }

    fn account(n: u32) -> Id {
        let mut id = [0xA0; 16];
        id[12..].copy_from_slice(&n.to_be_bytes());
        id
    }

    /// A floor in generation `gen` (its Genesis at `gen_time`), at `(epoch, join)`.
    fn floor(gen: u8, gen_time: u64, epoch: u32, join: u32) -> Floor {
        Floor {
            gen: [gen; 16],
            gen_time,
            epoch,
            join,
            d: [epoch as u8; 32],
            d_e: [join as u8; 32],
            kh: [gen; 32],
            time: gen_time.saturating_add(2 * epoch as u64),
            gated: false,
            gens: vec![([gen; 16], gen_time)],
        }
    }

    fn names(gen: u8, epoch: u32, join: u32, time: u64) -> NamesFloor {
        NamesFloor {
            gen: [gen; 16],
            epoch,
            join,
            names_hash: [epoch as u8; 32],
            time,
        }
    }

    fn row(n: u32, f: Floor, last_used: u64) -> FloorRow {
        FloorRow {
            group: group(n),
            floor: f,
            names: None,
            last_used,
        }
    }

    fn page_blob<R: Serialize>(
        vault: &Vault,
        k: &str,
        gen: u64,
        version: i64,
        rows: &[R],
    ) -> VaultBlob {
        VaultBlob {
            version,
            ..vault.seal_item(k, gen, &postcard::to_allocvec(rows).unwrap())
        }
    }

    fn index_blob(vault: &Vault, gen: u64, floors: &[u64], counters: &[u64]) -> VaultBlob {
        let index = GkIndex {
            format: INDEX_FORMAT,
            floor_pages: floors.to_vec(),
            counter_pages: counters.to_vec(),
        };
        VaultBlob {
            version: 1,
            ..vault.seal_item(ITEM_GK_FLOORS, gen, &index.to_bytes())
        }
    }

    /// A relay holding an index and the pages given.
    fn relay_with(index: VaultBlob, pages: Vec<VaultBlob>) -> Relay {
        let mut relay = Relay::default();
        relay.items.insert(ITEM_GK_FLOORS.to_string(), index);
        for p in pages {
            relay.items.insert(p.k.clone(), p);
        }
        relay
    }

    /// Until the last page is read nothing is in, so `GroupKeying` takes no header of a stored
    /// group on an empty book; then every floor and counter is there.
    #[test]
    fn no_floor_is_handed_over_before_every_page_is_in() {
        let vault = Vault::create(RELAY, "me");
        let f = floor(1, NOW - 100, 7, 2);
        let floors = page_blob(&vault, "gkf.0", 1, 3, &[row(1, f.clone(), NOW)]);
        let counter = CounterRow {
            account: account(1),
            counter: Some((4, NOW - 50)),
            pin: None,
        };
        let counters = page_blob(&vault, "gkc.0", 1, 3, &[counter]);
        let relay = relay_with(
            index_blob(&vault, 2, &[1], &[1]),
            vec![floors.clone(), counters.clone()],
        );
        let mut d = Device::new(&vault, &relay, HashMap::new());
        assert!(!d.book.pages_in());
        let out = d.book.begin(&d.gens, NOW);
        assert_eq!(asks(&out), ["gkf.0"], "one page at a time");
        assert!(!d.book.pages_in());

        let (book, io) = d.io();
        let out = book.on_page(io, "gkf.0", Some(&floors));
        assert_eq!(asks(&out), ["gkc.0"]);
        assert!(!d.book.pages_in(), "in before the counters");

        let (book, io) = d.io();
        let out = book.on_page(io, "gkc.0", Some(&counters));
        assert!(out.is_empty(), "{out:?}");
        assert!(d.book.pages_in());
        assert_eq!(d.book.floor_in(&group(1)), Some((f, None)));
        assert_eq!(
            d.book.seen_in(&account(1)),
            Some(Seen {
                n: 4,
                made: NOW - 50
            })
        );
        assert!(d.problems().is_empty());
    }

    /// A page the relay answers for that was not asked is not taken.
    #[test]
    fn a_page_nobody_asked_for_is_not_taken() {
        let vault = Vault::create(RELAY, "me");
        let relay = relay_with(index_blob(&vault, 1, &[1], &[]), vec![]);
        let mut d = Device::new(&vault, &relay, HashMap::new());
        let _ = d.book.begin(&d.gens, NOW);
        let other = page_blob(
            &vault,
            "gkc.0",
            1,
            1,
            &[CounterRow {
                account: account(1),
                counter: Some((9, NOW)),
                pin: None,
            }],
        );
        let (book, io) = d.io();
        assert!(book.on_page(io, "gkc.0", Some(&other)).is_empty());
        assert!(!d.book.counters.rows.contains_key(&account(1)));
        assert_eq!(d.book.seen(&account(1)), Err(Pending));
        assert!(d.book.asking());
    }

    /// A page gone is the problem any other item's is, and nothing is written over what the
    /// relay holds; the app goes on, on what it has.
    #[test]
    fn a_missing_floor_page_is_reported_and_never_saved_over() {
        let vault = Vault::create(RELAY, "me");
        let mut relay = relay_with(index_blob(&vault, 2, &[3], &[]), vec![]);
        let mut d = Device::new(&vault, &relay, HashMap::new());
        assert!(d.begin(&mut relay).is_empty());
        assert_eq!(d.problems(), ["missing"]);
        assert!(d.book.pages_in());
        d.book.put_floor(&group(1), floor(1, NOW, 1, 0), None, NOW);
        assert!(d.book.save_now());
        assert!(
            d.flush(&mut relay, NOW).is_empty(),
            "saved over a missing page"
        );
        assert!(d.tick(&mut relay, NOW + 3600).is_empty());
        assert!(!relay.items.contains_key("gkf.0"));
    }

    /// Older than this device saw: refused and not saved over, and still used, since a lower
    /// floor than the one lost is better than none.
    #[test]
    fn an_old_floor_page_is_refused_and_not_saved_over_but_still_used() {
        let vault = Vault::create(RELAY, "me");
        let f = floor(1, NOW - 100, 3, 0);
        let old = page_blob(&vault, "gkf.0", 3, 3, &[row(1, f.clone(), NOW)]);
        let mut relay = relay_with(index_blob(&vault, 2, &[3], &[]), vec![old]);
        let mut gens = HashMap::new();
        gens.insert("gkf.0".to_string(), 5);
        let mut d = Device::new(&vault, &relay, gens);
        d.begin(&mut relay);
        assert_eq!(d.problems(), ["older"]);
        assert_eq!(d.book.floor_in(&group(1)), Some((f, None)));
        d.book.put_floor(&group(2), floor(2, NOW, 1, 0), None, NOW);
        assert!(d.flush(&mut relay, NOW).is_empty());
        assert_eq!(d.gens.get("gkf.0"), Some(&5));
    }

    /// The index's word is sealed, so a device new to the account sees a page older than it too.
    #[test]
    fn a_page_older_than_its_index_is_refused_on_a_new_device() {
        let vault = Vault::create(RELAY, "me");
        let old = page_blob(
            &vault,
            "gkc.0",
            3,
            3,
            &[CounterRow {
                account: account(1),
                counter: Some((1, NOW)),
                pin: None,
            }],
        );
        let mut relay = relay_with(index_blob(&vault, 2, &[], &[4]), vec![old]);
        let mut d = Device::new(&vault, &relay, HashMap::new());
        d.begin(&mut relay);
        assert_eq!(d.problems(), ["older"]);
    }

    #[test]
    fn an_index_older_than_this_device_saw_is_refused() {
        let vault = Vault::create(RELAY, "me");
        let relay = relay_with(index_blob(&vault, 2, &[], &[]), vec![]);
        let mut gens = HashMap::new();
        gens.insert(ITEM_GK_FLOORS.to_string(), 9);
        let mut d = Device::new(&vault, &relay, gens);
        assert_eq!(d.problems(), ["older"]);
        assert_eq!(d.gens.get(ITEM_GK_FLOORS), Some(&9));
    }

    /// An index in a format a newer build wrote is left alone, not read as damage.
    #[test]
    fn an_index_a_newer_build_wrote_is_left_alone() {
        let vault = Vault::create(RELAY, "me");
        let newer = GkIndex {
            format: INDEX_FORMAT + 1,
            ..GkIndex::default()
        };
        let blob = VaultBlob {
            version: 1,
            ..vault.seal_item(ITEM_GK_FLOORS, 1, &newer.to_bytes())
        };
        let mut relay = relay_with(blob, vec![]);
        let mut d = Device::new(&vault, &relay, HashMap::new());
        assert_eq!(d.problems(), ["newer"]);
        d.begin(&mut relay);
        d.book.put_floor(&group(1), floor(1, NOW, 1, 0), None, NOW);
        assert!(d.flush(&mut relay, NOW).is_empty());
        assert_eq!(GkIndex::from_bytes(&[0xff, 0xff, 0x03]), Err("newer"));
        assert_eq!(GkIndex::from_bytes(&[]), Err("unreadable"));
    }

    /// The index is written only once the page it names is kept, so it never promises a
    /// generation no page holds, which would read as a rollback for good.
    #[test]
    fn a_page_goes_before_the_index_that_names_it() {
        let vault = Vault::create(RELAY, "me");
        let mut relay = Relay::default();
        let mut d = Device::new(&vault, &relay, HashMap::new());
        assert!(d.begin(&mut relay).is_empty());
        assert!(d.book.pages_in(), "nothing to read");
        d.book.put_floor(&group(1), floor(1, NOW, 1, 0), None, NOW);
        let (book, io) = d.io();
        let out = book.flush(io, NOW);
        assert_eq!(puts(&out), ["gkf.0"], "the page alone");
        assert!(!d.book.saved());
        assert_eq!(d.run(&mut relay, out), ["gkf.0", ITEM_GK_FLOORS]);
        assert!(d.book.saved());
        let index = relay.items.get(ITEM_GK_FLOORS).unwrap();
        let item = vault
            .open_item(std::slice::from_ref(index), ITEM_GK_FLOORS)
            .unwrap();
        assert_eq!(GkIndex::from_bytes(&item.payload).unwrap().floor_pages, [1]);

        // A later device reads it back
        let mut other = Device::new(&vault, &relay, HashMap::new());
        other.begin(&mut relay);
        assert!(other.problems().is_empty());
        assert_eq!(
            other.book.floor_in(&group(1)).unwrap().0,
            floor(1, NOW, 1, 0)
        );
    }

    /// A cut between a page's write and its index's: the next run still reads what this device
    /// saved, and finishes the index.
    #[test]
    fn a_page_no_index_names_is_read_if_this_device_saw_it() {
        let vault = Vault::create(RELAY, "me");
        let page = page_blob(&vault, "gkf.0", 1, 1, &[row(1, floor(1, NOW, 2, 0), NOW)]);
        let mut relay = Relay::default();
        relay.items.insert("gkf.0".into(), page);
        let mut gens = HashMap::new();
        gens.insert("gkf.0".to_string(), 1);
        let mut d = Device::new(&vault, &relay, gens);
        assert_eq!(
            d.begin(&mut relay),
            [ITEM_GK_FLOORS],
            "the index it did not get to"
        );
        assert!(d.problems().is_empty());
        assert!(d.book.floor_in(&group(1)).is_some());
    }

    /// Both devices write page 0 from the same start: the second's write conflicts, joins the
    /// first's, and both groups are kept, each floor the higher one.
    #[test]
    fn a_page_conflict_joins_both_devices_rows() {
        let vault = Vault::create(RELAY, "me");
        let mut relay = Relay::default();
        let mut a = Device::new(&vault, &relay, HashMap::new());
        let mut b = Device::new(&vault, &relay, HashMap::new());
        a.begin(&mut relay);
        b.begin(&mut relay);
        a.book.put_floor(&group(1), floor(1, NOW, 5, 0), None, NOW);
        b.book.put_floor(&group(1), floor(1, NOW, 3, 0), None, NOW);
        b.book.put_floor(&group(2), floor(2, NOW, 1, 0), None, NOW);
        a.flush(&mut relay, NOW);
        let went = b.flush(&mut relay, NOW);
        assert_eq!(
            went,
            ["gkf.0", "gkf.0", ITEM_GK_FLOORS, ITEM_GK_FLOORS],
            "each meets the other's write first, and joins it"
        );
        assert_eq!(
            b.book.floor_in(&group(1)).unwrap().0.epoch,
            5,
            "theirs was higher"
        );
        assert!(b.problems().is_empty());

        let mut c = Device::new(&vault, &relay, HashMap::new());
        c.begin(&mut relay);
        assert_eq!(c.book.floor_in(&group(1)).unwrap().0.epoch, 5);
        assert!(c.book.floor_in(&group(2)).is_some());
    }

    /// §10: two devices' vault floors merge to the generation with the later `gen_time`, even
    /// over a higher epoch in the older one, and keep both generation lists.
    #[test]
    fn two_devices_floors_merge_to_the_generation_with_the_later_gen_time() {
        let older = floor(1, NOW - 7200, 900, 4);
        let newer = floor(2, NOW - 60, 1, 0);
        for (a, b) in [(&older, &newer), (&newer, &older)] {
            let (f, _) = higher(&(a.clone(), None), &(b.clone(), None));
            assert_eq!(f.gen, newer.gen);
            assert_eq!(f.epoch, 1);
            assert_eq!(f.gens, [([1; 16], NOW - 7200), ([2; 16], NOW - 60)]);
        }

        let vault = Vault::create(RELAY, "me");
        let mut relay = Relay::default();
        let mut a = Device::new(&vault, &relay, HashMap::new());
        let mut b = Device::new(&vault, &relay, HashMap::new());
        a.begin(&mut relay);
        b.begin(&mut relay);
        a.book.put_floor(&group(1), newer.clone(), None, NOW);
        b.book.put_floor(&group(1), older, None, NOW);
        a.flush(&mut relay, NOW);
        b.flush(&mut relay, NOW);
        assert_eq!(b.book.floor_in(&group(1)).unwrap().0.gen, newer.gen);
        assert_eq!(
            b.book.take_raised().len(),
            1,
            "told the floor in use may rise"
        );
    }

    /// Names floors: the later generation by the merged floor's `gen_time`, then the higher
    /// `(epoch, join)`; a side with none takes the other's.
    #[test]
    fn names_floors_merge_to_the_later_generation_then_the_higher_join() {
        let mut f = floor(2, NOW - 60, 4, 0);
        f.gens = vec![([1; 16], NOW - 7200), ([2; 16], NOW - 60)];
        let old_gen = names(1, 900, 9, NOW - 100);
        let new_gen = names(2, 1, 0, NOW - 50);
        let pick = |x, y| {
            higher(&(f.clone(), Some(x)), &(f.clone(), Some(y)))
                .1
                .unwrap()
        };
        assert_eq!(pick(old_gen, new_gen), new_gen);
        assert_eq!(pick(new_gen, old_gen), new_gen);
        let low = names(2, 3, 1, NOW);
        let high = names(2, 3, 2, NOW - 1);
        assert_eq!(pick(low, high), high);
        assert_eq!(pick(high, low), high);
        assert_eq!(
            higher(&(f.clone(), None), &(f.clone(), Some(low))).1,
            Some(low)
        );
        assert_eq!(
            higher(&(f.clone(), Some(low)), &(f.clone(), None)).1,
            Some(low)
        );
    }

    /// A floor that moves to a new generation goes out at once, since a fresh device or a
    /// browser would take that generation's replay otherwise; a step within one waits a minute.
    #[test]
    fn a_generation_change_is_saved_at_once_and_a_step_within_one_waits_a_minute() {
        let vault = Vault::create(RELAY, "me");
        let mut relay = Relay::default();
        let mut d = Device::new(&vault, &relay, HashMap::new());
        d.begin(&mut relay);
        d.book.put_floor(&group(1), floor(1, NOW, 1, 0), None, NOW);
        assert_eq!(
            d.tick(&mut relay, NOW),
            ["gkf.0", ITEM_GK_FLOORS],
            "a group new to the vault"
        );

        d.book
            .put_floor(&group(1), floor(1, NOW, 2, 0), None, NOW + 1);
        assert!(!d.book.save_now());
        assert!(d.tick(&mut relay, NOW + 59).is_empty());
        assert_eq!(d.tick(&mut relay, NOW + 60), ["gkf.0", ITEM_GK_FLOORS]);
        assert!(d.tick(&mut relay, NOW + 200).is_empty(), "nothing new");

        let mut next = floor(2, NOW + 100, 1, 0);
        next.gens.insert(0, ([1; 16], NOW));
        d.book.put_floor(&group(1), next, None, NOW + 201);
        assert!(d.book.save_now());
        assert_eq!(d.tick(&mut relay, NOW + 201), ["gkf.0", ITEM_GK_FLOORS]);
    }

    /// A floor that moved every couple of seconds is written at most once a minute: a write
    /// that settles sends only what a save asked for while it was out.
    #[test]
    fn a_steady_stream_of_floors_is_written_at_most_once_a_minute() {
        let vault = Vault::create(RELAY, "me");
        let mut relay = Relay::default();
        let mut d = Device::new(&vault, &relay, HashMap::new());
        d.begin(&mut relay);
        d.book.put_floor(&group(1), floor(1, NOW, 1, 0), None, NOW);
        let (book, io) = d.io();
        let out = book.flush(io, NOW);
        d.book
            .put_floor(&group(1), floor(1, NOW, 2, 0), None, NOW + 1);
        assert_eq!(d.run(&mut relay, out), ["gkf.0", ITEM_GK_FLOORS]);
        let mut writes = 0;
        for i in 1..60u32 {
            d.book
                .put_floor(&group(1), floor(1, NOW, 2 + i, 0), None, NOW + 2 * i as u64);
            writes += d.tick(&mut relay, NOW + 2 * i as u64).len();
        }
        assert_eq!(writes, 2, "the page and its index once, at the minute");
    }

    /// Memory-only groups never reach the vault (§5.12), so an anonymous room never does.
    #[test]
    fn only_stored_groups_reach_the_vault() {
        let vault = Vault::create(RELAY, "me");
        let mut relay = Relay::default();
        let mut d = Device::new(&vault, &relay, HashMap::new());
        d.begin(&mut relay);
        for g in ["r:00ff:7", "c:", "c:bad id", "x:1"] {
            d.book.put_floor(g, floor(1, NOW, 1, 0), None, NOW);
            assert!(d.book.floor_in(g).is_none(), "{g}");
        }
        assert!(!d.book.save_now());
        assert!(d.flush(&mut relay, NOW).is_empty());
    }

    /// Worst-case rows (the longest `c:` id, 8 generations, a names floor, every number at its
    /// widest varint) still fit one vault item when a page is full.
    #[test]
    fn a_full_page_stays_inside_one_vault_item() {
        const VAULT_MAX_BYTES: usize = 48 * 1024;
        let vault = Vault::create(RELAY, "me");
        let mut relay = Relay::default();
        let mut d = Device::new(&vault, &relay, HashMap::new());
        d.begin(&mut relay);
        let wide = u64::MAX;
        for i in 0..400u32 {
            let mut f = floor(1, wide, u32::MAX, u32::MAX);
            f.time = wide;
            f.gens = (0..RECENT_GENS as u8)
                .map(|g| ([g; 16], wide - g as u64))
                .collect();
            f.gen = [0; 16];
            let id = format!("c:{i:0>64}");
            d.book.put_floor(
                &id,
                f,
                Some(names(0, u32::MAX, u32::MAX, wide)),
                wide - i as u64,
            );
        }
        for i in 0..2000u32 {
            let a = account(i);
            d.book.raise(
                a,
                Seen {
                    n: u32::MAX,
                    made: wide - i as u64,
                },
            );
            d.book.pin_seen(a, &[i as u8; 32], wide);
        }
        d.flush(&mut relay, NOW);
        let per_page = d
            .book
            .floors
            .rows
            .values()
            .filter(|h| h.page == Some(0))
            .count();
        assert!(per_page >= 80, "{per_page} worst-case floors a page");
        let per_page = d
            .book
            .counters
            .rows
            .values()
            .filter(|h| h.page == Some(0))
            .count();
        assert!(per_page >= 900, "{per_page} worst-case accounts a page");
        for blob in relay.items.values() {
            assert!(
                blob.v.len() <= VAULT_MAX_BYTES,
                "{} is {} bytes",
                blob.k,
                blob.v.len()
            );
        }
        let pages = |p: &str| relay.items.keys().filter(|k| k.starts_with(p)).count();
        assert!(pages("gkf.") >= 2 && pages("gkc.") >= 2);
    }

    /// `item.gk_floors` with every page at its widest generation stays about half a kilobyte,
    /// inside the sign-in frame's margin.
    #[test]
    fn the_largest_index_is_about_half_a_kilobyte() {
        let vault = Vault::create(RELAY, "me");
        let index = GkIndex {
            format: INDEX_FORMAT,
            floor_pages: vec![u64::MAX; FLOOR_PAGES as usize],
            counter_pages: vec![u64::MAX; COUNTER_PAGES as usize],
        };
        let sealed = vault
            .seal_item(ITEM_GK_FLOORS, u64::MAX, &index.to_bytes())
            .v
            .len();
        assert!((450..600).contains(&sealed), "{sealed} bytes");
        assert_eq!(GkIndex::from_bytes(&index.to_bytes()), Ok(index.clone()));
        let over = GkIndex {
            floor_pages: vec![1; FLOOR_PAGES as usize + 1],
            ..index
        };
        assert_eq!(GkIndex::from_bytes(&over.to_bytes()), Err("unreadable"));
    }

    /// Past 16 pages the group used least recently leaves the pages, and one used again since
    /// stays. What left is still held this connection; a fresh device does not have it.
    #[test]
    fn past_sixteen_pages_the_least_recently_used_group_drops() {
        let vault = Vault::create(RELAY, "me");
        let mut relay = Relay::default();
        let mut d = Device::new(&vault, &relay, HashMap::new());
        d.begin(&mut relay);
        let big = |g: u8| {
            let mut f = floor(g, NOW, 9, 9);
            f.gens = (0..RECENT_GENS as u8)
                .map(|x| ([x; 16], NOW - x as u64))
                .collect();
            f
        };
        let total = 3000u32;
        for i in 0..total {
            d.book.put_floor(&group(i), big(1), None, NOW + i as u64);
        }
        d.book.touch(&group(0), NOW + 10 * TOUCH_EVERY);
        d.flush(&mut relay, NOW + 10 * TOUCH_EVERY);
        let stored = |d: &Device, i: u32| d.book.floor_stored(&group(i));
        let kept = (0..total).filter(|i| stored(&d, *i)).count() as u32;
        assert_eq!(d.book.floors.pages.len(), FLOOR_PAGES as usize);
        assert!(kept < total, "nothing dropped");
        assert!(stored(&d, 0), "used since");
        assert!(!stored(&d, 1), "used least recently");
        assert!(stored(&d, total - 1));
        let dropped = (1..total).filter(|i| !stored(&d, *i)).max().unwrap();
        assert!((1..dropped).all(|i| !stored(&d, i)), "oldest first");
        assert!(d.book.floors.pages.iter().all(|p| p.bytes <= PAGE_BYTES));
        assert!(
            (0..total).all(|i| d.book.floor_in(&group(i)).is_some()),
            "still held this connection"
        );
        let mut fresh = Device::new(&vault, &relay, HashMap::new());
        fresh.begin(&mut relay);
        assert!(fresh.book.floor_in(&group(1)).is_none());
        assert!(fresh.book.floor_in(&group(total - 1)).is_some());

        // One more drops the next oldest
        d.book
            .put_floor(&group(total), big(1), None, NOW + 20 * TOUCH_EVERY);
        d.flush(&mut relay, NOW + 20 * TOUCH_EVERY);
        assert!(stored(&d, total));
        assert!(!stored(&d, dropped + 1));

        // A group off the pages that is used again goes back on them
        d.book
            .put_floor(&group(1), big(1), None, NOW + 30 * TOUCH_EVERY);
        d.flush(&mut relay, NOW + 30 * TOUCH_EVERY);
        assert!(stored(&d, 1));
    }

    /// Counters raised one batch at a time, each newer than the last, until a row first
    /// finds the pages full: the next account number.
    fn fill_counter_pages(d: &mut Device) -> u32 {
        // Every row the same size, so a page that turned one away has room for none
        let mut n = 0u32;
        while d.book.counters.spilled.is_empty() {
            let batch = if d.book.counters.pages.len() < COUNTER_PAGES as usize {
                1000
            } else {
                50
            };
            for _ in 0..batch {
                d.book.raise(
                    account(n),
                    Seen {
                        n: 2,
                        made: NOW + n as u64,
                    },
                );
                n += 1;
            }
            d.book.counters.place();
        }
        n
    }

    /// Past 32 pages the account whose counter was made longest ago leaves the pages.
    #[test]
    fn past_thirty_two_pages_the_oldest_counter_drops() {
        let vault = Vault::create(RELAY, "me");
        let mut relay = Relay::default();
        let mut d = Device::new(&vault, &relay, HashMap::new());
        d.begin(&mut relay);
        let n = fill_counter_pages(&mut d);
        let stored = (0..n)
            .filter(|i| d.book.counter_stored(&account(*i)))
            .count();
        assert!(stored > 30_000, "{stored} accounts");
        d.book.raise(
            account(n),
            Seen {
                n: 2,
                made: NOW + n as u64,
            },
        );
        d.book.raise(
            account(n + 1),
            Seen {
                n: 2,
                made: NOW - 1,
            },
        );
        d.book.counters.place();
        assert!(d.book.counter_stored(&account(n)), "the newest is stored");
        assert!(
            !d.book.counter_stored(&account(n + 1)),
            "older than all: not stored"
        );
        let first = (0..n)
            .find(|i| d.book.counter_stored(&account(*i)))
            .unwrap();
        assert!(first >= 1, "the oldest made dropped");
        assert!((first..n).all(|i| d.book.counter_stored(&account(i))));
        assert!(d.book.counters.pages.iter().all(|p| p.bytes <= PAGE_BYTES));
        assert_eq!(d.book.counters.pages.len(), COUNTER_PAGES as usize);
    }

    /// The pages hold so many accounts; what they drop this connection still knows, so rule 8
    /// still flags an old seat of an account whose newer counter was seen (§5.11). A later
    /// connection of the process keeps it too; a fresh device has only the pages.
    #[test]
    fn a_counter_off_the_pages_is_still_known_this_connection() {
        let vault = Vault::create(RELAY, "me");
        let mut relay = Relay::default();
        let mut d = Device::new(&vault, &relay, HashMap::new());
        d.begin(&mut relay);
        let n = fill_counter_pages(&mut d);
        let old = account(n);
        d.book.raise(
            old,
            Seen {
                n: 2,
                made: NOW - 1,
            },
        );
        d.flush(&mut relay, NOW);
        assert!(!d.book.counter_stored(&old));
        assert!(!d.book.counter_stored(&account(0)));
        for a in [old, account(0)] {
            let seen = d.book.seen_in(&a);
            assert_eq!(
                counter_flagged(1, NOW + DAY, seen),
                Some(2),
                "still flagged"
            );
        }

        let kept = d.book.keep().unwrap();
        let mut again = Device::new(&vault, &relay, d.gens.clone());
        again.book.adopt(kept);
        let out = again.book.begin(&again.gens, NOW + 10);
        again.run(&mut relay, out);
        assert!(again.book.seen_in(&old).is_some(), "the next connection");

        let mut fresh = Device::new(&vault, &relay, HashMap::new());
        fresh.begin(&mut relay);
        assert_eq!(fresh.book.seen_in(&old), None, "only the pages");
        assert!(fresh.book.seen_in(&account(n - 1)).is_some());

        // Raised past the oldest stored, it goes on the pages again
        d.book.raise(
            old,
            Seen {
                n: 3,
                made: NOW + 10 * n as u64,
            },
        );
        d.flush(&mut relay, NOW + 60);
        assert!(d.book.counter_stored(&old));
    }

    /// A writer's first fold in a 100k group raises every account at once. Placing them is
    /// one sort and a heap, not a scan of every row for each row that does not fit (that
    /// took about 20 s natively, longer in a browser).
    #[test]
    fn a_hundred_thousand_counters_are_placed_at_once() {
        let vault = Vault::create(RELAY, "me");
        let mut relay = Relay::default();
        let mut d = Device::new(&vault, &relay, HashMap::new());
        d.begin(&mut relay);
        let total = 100_000u32;
        for i in 0..total {
            d.book.raise(
                account(i),
                Seen {
                    n: 2,
                    made: NOW + i as u64,
                },
            );
        }
        let started = Instant::now();
        let went = d.flush(&mut relay, NOW);
        let took = started.elapsed();
        // A debug build here takes well under a second; the scan took minutes
        assert!(took < Duration::from_secs(10), "{took:?}");
        assert_eq!(
            went.len(),
            COUNTER_PAGES as usize + 1,
            "every page, then the index"
        );
        let first = (0..total)
            .find(|i| d.book.counter_stored(&account(*i)))
            .unwrap();
        assert!(first > 0, "some dropped");
        assert!(
            (first..total).all(|i| d.book.counter_stored(&account(i))),
            "the newest"
        );
        assert!((0..total).all(|i| d.book.seen_in(&account(i)).is_some()));
        assert!(d.book.counters.pages.iter().all(|p| p.bytes <= PAGE_BYTES));
    }

    /// The higher counter wins, whatever its `made`; of one counter the earliest `made`, since
    /// the counter is known to exist from then.
    #[test]
    fn counters_keep_the_highest_n_with_its_earliest_made() {
        let vault = Vault::create(RELAY, "me");
        let mut relay = Relay::default();
        let mut d = Device::new(&vault, &relay, HashMap::new());
        d.begin(&mut relay);
        let a = account(1);
        assert!(d.book.raise(a, Seen { n: 3, made: NOW }));
        assert!(
            !d.book.raise(
                a,
                Seen {
                    n: 2,
                    made: NOW + 900
                }
            ),
            "lower"
        );
        assert!(
            !d.book.raise(
                a,
                Seen {
                    n: 3,
                    made: NOW + 5
                }
            ),
            "same, later"
        );
        assert!(
            d.book.raise(
                a,
                Seen {
                    n: 3,
                    made: NOW - 5
                }
            ),
            "same, earlier"
        );
        assert_eq!(
            d.book.seen_in(&a),
            Some(Seen {
                n: 3,
                made: NOW - 5
            })
        );
        assert!(d.book.raise(
            a,
            Seen {
                n: 4,
                made: NOW + 10
            }
        ));
        assert_eq!(
            d.book.seen_in(&a),
            Some(Seen {
                n: 4,
                made: NOW + 10
            })
        );
        assert_eq!(d.book.seen_in(&account(2)), None);
        for (x, y) in [((4, 9), (5, 20)), ((5, 20), (4, 9)), ((5, 1), (5, 20))] {
            let want = higher_counter(Some(x), Some(y));
            assert_eq!(want, higher_counter(Some(y), Some(x)), "either way round");
        }
    }

    /// A pin's time checks entries made after it (with a header clock's slack) against the pin;
    /// before it, or for another pin, the device does not know, and the entry is shown.
    #[test]
    fn a_pin_time_counts_only_for_the_pin_it_was_seen_with() {
        let vault = Vault::create(RELAY, "me");
        let mut relay = Relay::default();
        let mut d = Device::new(&vault, &relay, HashMap::new());
        d.begin(&mut relay);
        d.book.pins_held([], NOW);
        let a = account(1);
        let ik = [7; 32];
        assert_eq!(d.book.pin_then_in(&a, None, NOW), PinThen::None);
        assert_eq!(
            d.book.pin_then_in(&a, Some(&ik), NOW),
            PinThen::Unknown,
            "no time yet"
        );
        assert!(d.book.pin_seen(a, &ik, NOW));
        assert!(!d.book.pin_seen(a, &ik, NOW + 500), "first seen stays");
        assert_eq!(d.book.pin_then_in(&a, Some(&ik), NOW - 1), PinThen::Unknown);
        assert_eq!(
            d.book.pin_then_in(&a, Some(&ik), NOW + CLOCK_SLACK),
            PinThen::Unknown
        );
        assert_eq!(
            d.book.pin_then_in(&a, Some(&ik), NOW + CLOCK_SLACK + 1),
            PinThen::Pin(ik)
        );

        // The pin changed, here or on another device the pins came from
        let new = [8; 32];
        assert_eq!(
            d.book.pin_then_in(&a, Some(&new), NOW + 9999),
            PinThen::Unknown
        );
        assert!(d.book.pin_seen(a, &new, NOW + 5000));
        assert_eq!(
            d.book
                .pin_then_in(&a, Some(&new), NOW + 5000 + CLOCK_SLACK + 1),
            PinThen::Pin(new)
        );
        assert_eq!(
            d.book.pin_then_in(&a, Some(&new), NOW + 4000),
            PinThen::Unknown
        );
        assert_eq!(
            d.book.pin_then_in(&a, Some(&ik), NOW + 9999),
            PinThen::Unknown
        );
    }

    /// A pin the account held before group keys has no time on any page. Timed when the
    /// pages are in, a ghost the relay seats under it after that fails a fold (C1 refuses an
    /// entry whose `IK` is not `PinThen::Pin`'s), even when the fold comes seconds later.
    /// The time is kept, so a later sign-in checks headers made while it was away.
    #[test]
    fn a_pin_held_at_sign_in_is_checked_from_then_and_kept() {
        let vault = Vault::create(RELAY, "me");
        let mut relay = Relay::default();
        let mut d = Device::new(&vault, &relay, HashMap::new());
        let x = account(1);
        let ik = [7; 32];
        let ghost = [9; 32];
        d.begin(&mut relay);
        assert_eq!(
            d.book.pin_then(&x, Some(&ik), NOW),
            Err(Pending),
            "not timed yet"
        );
        assert!(d.book.pins_held([(x, ik)], NOW));
        // The ghost is seated at T, the fold comes five seconds later
        let t = NOW + CLOCK_SLACK + 60;
        assert!(
            !d.book.pin_seen(x, &ik, t + 5),
            "already timed: the fold moves nothing"
        );
        let then = d.book.pin_then_in(&x, Some(&ik), t);
        assert_eq!(then, PinThen::Pin(ik));
        assert!(
            matches!(then, PinThen::Pin(p) if p != ghost),
            "the ghost fails"
        );
        d.flush(&mut relay, NOW);

        // Signed in again a day later: a ghost seated while away is still caught
        let mut later = Device::new(&vault, &relay, d.gens.clone());
        later.begin(&mut relay);
        assert!(
            !later.book.pins_held([(x, ik)], NOW + DAY),
            "the time stands"
        );
        assert_eq!(
            later.book.pin_then_in(&x, Some(&ik), NOW + DAY / 2),
            PinThen::Pin(ik)
        );
        // A pin changed by an app that keeps no times is timed again from this sign-in
        let reset = [8; 32];
        assert!(later.book.pins_held([(x, reset)], NOW + DAY));
        assert_eq!(
            later.book.pin_then_in(&x, Some(&reset), NOW + DAY / 2),
            PinThen::Unknown
        );
        assert_eq!(
            later
                .book
                .pin_then_in(&x, Some(&reset), NOW + DAY + CLOCK_SLACK + 1),
            PinThen::Pin(reset)
        );
    }

    /// A phone whose clock runs a year behind cannot date a pin before the newest header this
    /// account took: an honest list from before the pin changed still reads as unknown, not
    /// as the new pin, on every device of the account.
    #[test]
    fn a_clock_running_behind_cannot_date_a_pin_too_early() {
        let vault = Vault::create(RELAY, "me");
        let mut relay = Relay::default();
        let mut a = Device::new(&vault, &relay, HashMap::new());
        a.begin(&mut relay);
        a.book
            .put_floor(&group(1), floor(1, NOW - 100, 3, 0), None, NOW);
        a.flush(&mut relay, NOW);

        let behind = NOW - 365 * DAY;
        let mut phone = Device::new(&vault, &relay, HashMap::new());
        phone.begin(&mut relay);
        let x = account(1);
        let ik1 = [8; 32];
        phone.book.pins_held([(x, ik1)], behind);
        let newest = floor(1, NOW - 100, 3, 0).time;
        let since = phone.book.counters.rows[&x].row.pin.unwrap().0;
        assert_eq!(since, newest - CLOCK_SLACK);
        let three_months_ago = NOW - 90 * DAY;
        assert_eq!(
            phone.book.pin_then_in(&x, Some(&ik1), three_months_ago),
            PinThen::Unknown,
            "an old list with the old key is shown, not refused"
        );
        phone.flush(&mut relay, behind);
        let mut c = Device::new(&vault, &relay, HashMap::new());
        c.begin(&mut relay);
        c.book.pins_held([], NOW);
        assert_eq!(
            c.book.pin_then_in(&x, Some(&ik1), three_months_ago),
            PinThen::Unknown,
            "nor on another device"
        );
    }

    /// Two devices' pin times: of one pin the first sight; of two, the later one, which is the
    /// change. Either way round.
    #[test]
    fn pin_times_merge_to_the_first_sight_of_one_pin_and_the_latest_change() {
        let t = |ik: u8| tag(&[ik; 32]);
        let one = merged_pin(Some((NOW + 10, t(1))), Some((NOW, t(1))));
        assert_eq!(one, Some((NOW, t(1))));
        let changed = merged_pin(Some((NOW, t(1))), Some((NOW + 10, t(2))));
        assert_eq!(changed, Some((NOW + 10, t(2))));
        assert_eq!(
            changed,
            merged_pin(Some((NOW + 10, t(2))), Some((NOW, t(1))))
        );
        assert_eq!(merged_pin(None, Some((NOW, t(1)))), Some((NOW, t(1))));

        // Through the vault: a counter and a pin time from two devices join on one row
        let vault = Vault::create(RELAY, "me");
        let mut relay = Relay::default();
        let mut a = Device::new(&vault, &relay, HashMap::new());
        let mut b = Device::new(&vault, &relay, HashMap::new());
        a.begin(&mut relay);
        b.begin(&mut relay);
        a.book.raise(account(1), Seen { n: 2, made: NOW });
        b.book.pin_seen(account(1), &[1; 32], NOW + 1);
        a.flush(&mut relay, NOW);
        b.flush(&mut relay, NOW);
        let mut c = Device::new(&vault, &relay, HashMap::new());
        c.begin(&mut relay);
        assert_eq!(c.book.seen_in(&account(1)), Some(Seen { n: 2, made: NOW }));
        assert!(!c.book.pins_held([(account(1), [1; 32])], NOW + 100));
        assert_eq!(
            c.book
                .pin_then_in(&account(1), Some(&[1; 32]), NOW + CLOCK_SLACK + 2),
            PinThen::Pin([1; 32])
        );
    }

    /// A relay that hands over no page is told of, once, and the app still takes them later.
    #[test]
    fn pages_withheld_for_half_a_minute_are_told_once() {
        let vault = Vault::create(RELAY, "me");
        let relay = relay_with(index_blob(&vault, 2, &[1], &[]), vec![]);
        let mut d = Device::new(&vault, &relay, HashMap::new());
        assert_eq!(asks(&d.book.begin(&d.gens, NOW)), ["gkf.0"]);
        let mut told = Vec::new();
        let mut asked = 0;
        for i in 0..2 * PAGES_SAID_AFTER_TICKS {
            let (book, io) = d.io();
            asked += asks(&book.tick(io, NOW + 2 * i as u64)).len();
            told.extend(d.problems());
        }
        assert_eq!(told, ["withheld"], "once");
        assert!(asked >= 2, "asked again after a lost answer");
        assert!(!d.book.pages_in());
        assert!(!d.book.read_only, "the pages may yet come");
    }

    /// While a page is out, even one withheld past the warning, nothing is answered: an
    /// empty book would pass an old seat or a swapped key in any group, a voice room too.
    #[test]
    fn nothing_is_answered_before_the_pages_are_in() {
        let vault = Vault::create(RELAY, "me");
        let counter = CounterRow {
            account: account(1),
            counter: Some((9, NOW - 50)),
            pin: Some((NOW - 50, tag(&[7; 32]))),
        };
        let counters = page_blob(&vault, "gkc.0", 1, 1, &[counter]);
        let floors = page_blob(&vault, "gkf.0", 1, 1, &[row(1, floor(1, NOW, 2, 0), NOW)]);
        let relay = relay_with(
            index_blob(&vault, 1, &[1], &[1]),
            vec![floors.clone(), counters.clone()],
        );
        let mut d = Device::new(&vault, &relay, HashMap::new());
        let pending = |d: &Device| {
            assert_eq!(d.book.floor(&group(1)), Err(Pending));
            assert_eq!(d.book.seen(&account(1)), Err(Pending));
            assert_eq!(
                d.book.pin_then(&account(1), Some(&[7; 32]), NOW + DAY),
                Err(Pending)
            );
        };
        pending(&d);
        d.book.begin(&d.gens, NOW);
        d.book.pins_held([(account(1), [7; 32])], NOW);
        let (book, io) = d.io();
        book.on_page(io, "gkf.0", Some(&floors));
        // gkc.0 is withheld past the warning
        for i in 0..2 * PAGES_SAID_AFTER_TICKS {
            let (book, io) = d.io();
            book.tick(io, NOW + 2 * i as u64);
        }
        assert_eq!(d.problems(), ["withheld"]);
        pending(&d);

        let (book, io) = d.io();
        book.on_page(io, "gkc.0", Some(&counters));
        assert!(d.book.pages_in());
        let seen = d.book.seen_in(&account(1));
        assert_eq!(counter_flagged(3, NOW + DAY, seen), Some(9));
        assert_eq!(
            d.book.pin_then_in(&account(1), Some(&[7; 32]), NOW + DAY),
            PinThen::Pin([7; 32])
        );
        assert!(d.book.floor_in(&group(1)).is_some());
    }

    /// A refusal for now asks again at the next tick; any other is a missing page.
    #[test]
    fn a_page_read_refused_for_now_is_asked_again() {
        let vault = Vault::create(RELAY, "me");
        let relay = relay_with(index_blob(&vault, 2, &[1], &[]), vec![]);
        let mut d = Device::new(&vault, &relay, HashMap::new());
        d.book.begin(&d.gens, NOW);
        let (book, io) = d.io();
        assert!(book.on_read_refused(io, "slow down").is_empty());
        let (book, io) = d.io();
        assert_eq!(asks(&book.tick(io, NOW)), ["gkf.0"]);
        let (book, io) = d.io();
        assert!(book.on_read_refused(io, "no such thing").is_empty());
        assert_eq!(d.problems(), ["missing"]);
        assert!(d.book.pages_in());
    }

    /// A write refused for now goes again at the next tick; one refused for room is not asked
    /// again this connection.
    #[test]
    fn a_write_refused_for_now_goes_again_and_one_refused_for_room_stops() {
        let vault = Vault::create(RELAY, "me");
        let mut relay = Relay::default();
        let mut d = Device::new(&vault, &relay, HashMap::new());
        d.begin(&mut relay);
        d.book.put_floor(&group(1), floor(1, NOW, 1, 0), None, NOW);
        let (book, io) = d.io();
        assert_eq!(puts(&book.flush(io, NOW)), ["gkf.0"]);
        d.book.write_refused("slow down");
        assert_eq!(d.tick(&mut relay, NOW + 2), ["gkf.0", ITEM_GK_FLOORS]);

        d.book
            .put_floor(&group(2), floor(2, NOW, 1, 0), None, NOW + 3);
        let (book, io) = d.io();
        assert_eq!(puts(&book.flush(io, NOW + 3)), ["gkf.0"]);
        d.book.write_refused("over quota");
        d.book
            .put_floor(&group(3), floor(3, NOW, 1, 0), None, NOW + 4);
        assert!(d.tick(&mut relay, NOW + 600).is_empty());
        assert!(d.flush(&mut relay, NOW + 600).is_empty());
    }

    /// Another device's index: the pages it moved are read and joined, and the index is
    /// written again after them.
    #[test]
    fn an_index_another_device_wrote_reads_the_pages_that_moved() {
        let vault = Vault::create(RELAY, "me");
        let mut relay = Relay::default();
        let mut a = Device::new(&vault, &relay, HashMap::new());
        let mut b = Device::new(&vault, &relay, HashMap::new());
        a.begin(&mut relay);
        b.begin(&mut relay);
        a.book.raise(account(1), Seen { n: 5, made: NOW });
        a.flush(&mut relay, NOW);
        // b writes another page, and its index meets a's
        b.book.put_floor(&group(1), floor(1, NOW, 1, 0), None, NOW);
        let went = b.flush(&mut relay, NOW);
        assert_eq!(went, ["gkf.0", ITEM_GK_FLOORS, ITEM_GK_FLOORS]);
        assert_eq!(
            b.book.seen_in(&account(1)),
            Some(Seen { n: 5, made: NOW }),
            "read gkc.0"
        );
        let item = vault
            .open_item(
                std::slice::from_ref(&relay.items[ITEM_GK_FLOORS]),
                ITEM_GK_FLOORS,
            )
            .unwrap();
        let index = GkIndex::from_bytes(&item.payload).unwrap();
        assert_eq!((index.floor_pages, index.counter_pages), (vec![1], vec![1]));
    }

    /// A floor that grew past room on its page moves to one with room, and nothing is lost.
    #[test]
    fn a_floor_that_grew_past_its_page_moves_to_one_with_room() {
        let vault = Vault::create(RELAY, "me");
        let mut relay = Relay::default();
        let mut d = Device::new(&vault, &relay, HashMap::new());
        d.begin(&mut relay);
        // Page 0 full, the last one on page 1
        let mut i = 0;
        while d.book.floors.pages.len() < 2 {
            d.book.put_floor(&group(i), floor(1, NOW, 1, 0), None, NOW);
            d.book.floors.place();
            i += 1;
        }
        let mut grown = floor(1, NOW, 2, 0);
        grown.gens = (0..RECENT_GENS as u8)
            .map(|g| ([g + 1; 16], NOW - g as u64))
            .collect();
        d.book
            .put_floor(&group(0), grown.clone(), Some(names(1, 2, 0, NOW)), NOW + 1);
        d.flush(&mut relay, NOW + 1);
        assert_eq!(d.book.floors.rows[&group(0)].page, Some(1));
        assert!(d.book.floors.pages.iter().all(|p| p.bytes <= PAGE_BYTES));
        assert_eq!(d.book.floors.rows.len(), i as usize);
        let mut other = Device::new(&vault, &relay, HashMap::new());
        other.begin(&mut relay);
        assert_eq!(other.book.floors.rows.len(), i as usize);
        assert_eq!(other.book.floor_in(&group(0)).unwrap().0.epoch, 2);
    }

    /// A group on two pages, from two devices placing it at once, is merged to the higher
    /// floor and kept on one page.
    #[test]
    fn a_group_on_two_pages_is_merged_and_kept_on_one() {
        let vault = Vault::create(RELAY, "me");
        let p0 = page_blob(&vault, "gkf.0", 1, 1, &[row(1, floor(1, NOW, 2, 0), NOW)]);
        let p1 = page_blob(&vault, "gkf.1", 1, 1, &[row(1, floor(1, NOW, 6, 0), NOW)]);
        let mut relay = relay_with(index_blob(&vault, 1, &[1, 1], &[]), vec![p0, p1]);
        let mut d = Device::new(&vault, &relay, HashMap::new());
        d.begin(&mut relay);
        assert_eq!(d.book.floor_in(&group(1)).unwrap().0.epoch, 6);
        assert_eq!(d.book.floors.rows[&group(1)].page, Some(0));
        assert!(d.book.floors.pages[0].dirty, "page 0 holds the lower floor");
        assert!(
            !d.book.floors.pages[1].dirty,
            "its copy drops at its next write"
        );
    }

    /// A later connection of the account reads again only the pages whose generation moved.
    #[test]
    fn a_later_connection_reads_again_only_the_pages_that_moved() {
        let vault = Vault::create(RELAY, "me");
        let mut relay = Relay::default();
        let mut a = Device::new(&vault, &relay, HashMap::new());
        a.begin(&mut relay);
        a.book.put_floor(&group(1), floor(1, NOW, 1, 0), None, NOW);
        a.book.raise(account(1), Seen { n: 1, made: NOW });
        a.flush(&mut relay, NOW);
        let kept = a.book.keep().unwrap();

        // Another device moves the counters page meanwhile
        let mut b = Device::new(&vault, &relay, HashMap::new());
        b.begin(&mut relay);
        b.book.raise(
            account(1),
            Seen {
                n: 2,
                made: NOW + 5,
            },
        );
        b.flush(&mut relay, NOW + 5);

        let mut again = Device::new(&vault, &relay, a.gens.clone());
        again.book.adopt(kept);
        let out = again.book.begin(&again.gens, NOW + 10);
        assert_eq!(asks(&out), ["gkc.0"], "only what moved");
        again.run(&mut relay, out);
        assert!(again.book.pages_in());
        assert_eq!(
            again.book.seen_in(&account(1)),
            Some(Seen {
                n: 2,
                made: NOW + 5
            })
        );
        assert!(again.book.floor_in(&group(1)).is_some());
        assert!(again.problems().is_empty());
    }

    /// A page this device saved that the relay no longer hands over is said at every
    /// connection, a later one of the same process too, and never written over as new.
    #[test]
    fn a_later_connection_still_reports_a_page_the_relay_withheld() {
        let vault = Vault::create(RELAY, "me");
        // This device saved gkf.0 at 2; its index write was cut, and the relay dropped the page
        let mut relay = relay_with(index_blob(&vault, 1, &[], &[]), vec![]);
        let gens = HashMap::from([("gkf.0".to_string(), 2), (ITEM_GK_FLOORS.to_string(), 1)]);
        let mut first = Device::new(&vault, &relay, gens.clone());
        first.begin(&mut relay);
        assert_eq!(first.problems(), ["missing"]);
        let kept = first.book.keep().unwrap();

        let mut again = Device::new(&vault, &relay, first.gens.clone());
        again.book.adopt(kept);
        let out = again.book.begin(&again.gens, NOW + 10);
        assert_eq!(asks(&out), ["gkf.0"], "asked again");
        again.run(&mut relay, out);
        assert_eq!(again.problems(), ["missing"], "said again");
        again
            .book
            .put_floor(&group(1), floor(1, NOW, 1, 0), None, NOW + 10);
        assert!(
            again.flush(&mut relay, NOW + 10).is_empty(),
            "nothing over it"
        );
        assert!(!relay.items.contains_key("gkf.0"));
    }

    /// A group another device stored, met first after the pages are in, is handed to the
    /// host: it may hold a lower floor of its own for it.
    #[test]
    fn a_group_another_device_stored_since_is_handed_over() {
        let vault = Vault::create(RELAY, "me");
        let mut relay = Relay::default();
        let mut a = Device::new(&vault, &relay, HashMap::new());
        let mut b = Device::new(&vault, &relay, HashMap::new());
        a.begin(&mut relay);
        b.begin(&mut relay);
        let theirs = floor(2, NOW, 8, 0);
        b.book.put_floor(&group(2), theirs.clone(), None, NOW);
        b.flush(&mut relay, NOW);
        // a writes the same page and meets b's on the conflict
        a.book.put_floor(&group(1), floor(1, NOW, 1, 0), None, NOW);
        a.flush(&mut relay, NOW);
        let raised = a.book.take_raised();
        assert_eq!(raised, [(group(2), (theirs, None))]);
    }
}
