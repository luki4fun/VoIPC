//! An account's pins on a relay at protocol 21, as `AccountSync` runs them. One vault item
//! holds about 560 people, because the vault travels in one frame at sign-in. Past that a
//! named reader's key could be swapped at the next connect with nobody told, so the pins go
//! in pages `pins.N` outside that frame, and `item.pins` says which pages there are and the
//! generation each was last saved at.
//!
//! The rules that carry the security:
//!
//! - No pin decision and no key job before the pages are in (`pins_in`): an empty set of pins
//!   passes any key as new.
//! - A page missing, or older than this device saw or than the index says, is the same
//!   `VaultProblem` as any other item's, and nothing of the pins is saved over after it.
//! - A page goes before the index that names it. So an index never promises a generation
//!   no page holds, which would read as a rollback for good.
//! - Nothing is evicted. A pin that does not fit lasts this connection, and pins of people
//!   met only in open channels stop at half the room, so a relay naming strangers there
//!   cannot use up the room of people this person writes to.
//!
//! Chronological, so a new pin dirties only the newest page. A new pin goes out at most once
//! per `SAVE_EVERY_MS` and at sign-out, since people come one at a time and a save per person
//! is quadratic in the upload: a crash loses those people, who are simply new again.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};
use voipc_protocol::messages::{AccountReply, AccountRequest, ClientMessage};
use voipc_protocol::types::{VaultBlob, PIN_PAGES, VAULT_PAGES_SINCE};

use super::{ask, AccountSync, Event, LOST_AFTER_TICKS, SLOW_DOWN};
use crate::account::{Item, PinCheck, Pins, VaultError, ITEM_PINS};

type Id = [u8; 16];

/// `item.pins` as an index. An older build leaves such an item alone.
pub(super) const PIN_INDEX_FORMAT: u16 = 2;
const SAVE_EVERY_MS: u64 = 300_000;
/// What a page holds, under the relay's 48 KiB an item with room for its sealing.
const PAGE_BYTES: usize = 47 * 1024;
/// One person's pin at most, in bytes. A relay chooses names, and one this long stays in memory.
const PIN_MOST_BYTES: usize = 256;
const OPEN_PAGES: usize = PIN_PAGES as usize / 2;
/// Replies held for the pages: more than the asks that bring them, only from a relay.
const HELD_MOST: usize = 1024;
/// Ticks of about two seconds the pages may stay out before the person is told: all 56 take
/// about 22 s on 1 Mbit.
const PAGES_SAID_AFTER_TICKS: u32 = 15;

/// What `item.pins` holds on such a relay.
#[derive(Default, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct PinIndex {
    /// Each page's generation, by its number.
    pages: Vec<u64>,
}

impl PinIndex {
    pub(super) fn from_bytes(bytes: &[u8]) -> Option<PinIndex> {
        let index: PinIndex = postcard::from_bytes(bytes).ok()?;
        (index.pages.len() <= PIN_PAGES as usize).then_some(index)
    }
}

/// One page as this device holds it.
#[derive(Default, Clone)]
struct Page {
    gen: u64,
    /// The relay's compare-and-set number.
    version: i64,
    bytes: usize,
    /// Holds something the relay does not.
    dirty: bool,
    /// The generation of the write out: one at a time.
    writing: Option<u64>,
}

#[derive(Default, Clone)]
pub(super) struct PinBook {
    pub(super) paged: bool,
    /// What `item.pins` said, once it is an index.
    index: Option<PinIndex>,
    pages: Vec<Page>,
    page_of: HashMap<Id, u16>,
    /// Pins on no page, with the bytes of their names: new, or past their half.
    unplaced: BTreeMap<Id, usize>,
    /// People who keep the half open channels cannot fill: direct conversations, gated
    /// channels, whoever was verified.
    reserved: HashSet<Id>,
    to_read: VecDeque<u16>,
    asked: Option<u16>,
    idle: u32,
    /// Ticks since this connection began waiting for pages.
    out_ticks: u32,
    /// Read so far: taken in together, lowest first, so what was pinned last wins however
    /// the answers came.
    read: BTreeMap<u16, Pins>,
    /// Pins already in hand, which a page that disagrees is a change to.
    warn_on_read: bool,
    held: Vec<AccountReply>,
    /// Holds the old single item, for pages.
    fold: bool,
    index_due: bool,
    /// Refused for now: goes again at the next tick.
    retry: bool,
    /// The relay has no more room: nothing more this connection.
    full: bool,
    saved_at: u64,
}

impl PinBook {
    /// What `item.pins` said at sign-in.
    pub(super) fn reading(index: Option<PinIndex>) -> PinBook {
        PinBook {
            index,
            ..PinBook::default()
        }
    }

    fn settled(&self) -> bool {
        self.asked.is_none()
            && self.to_read.is_empty()
            && self.pages.iter().all(|p| p.writing.is_none())
    }

    pub(super) fn index_bytes(&self) -> Vec<u8> {
        let mut pages: Vec<u64> = self.pages.iter().map(|p| p.gen).collect();
        while pages.last() == Some(&0) {
            pages.pop();
        }
        postcard::to_allocvec(&PinIndex { pages }).expect("an index encodes")
    }

    fn page_mut(&mut self, n: u16) -> &mut Page {
        let at = n as usize;
        if self.pages.len() <= at {
            self.pages.resize(at + 1, Page::default());
        }
        &mut self.pages[at]
    }

    fn taken_in(&mut self, page: &Pins, n: u16) {
        for account in page.accounts() {
            self.page_of.insert(*account, n);
            self.unplaced.remove(account);
        }
    }
}

/// What one connection of an account hands the next: every page, and the pins not saved yet.
pub struct KeptPins {
    pins: Pins,
    book: PinBook,
}

fn page_name(n: u16) -> String {
    format!("pins.{n}")
}

fn page_number(k: &str) -> Option<u16> {
    k.strip_prefix("pins.")?
        .parse()
        .ok()
        .filter(|n| *n < PIN_PAGES)
}

fn slowed_down(reason: &str) -> bool {
    reason.contains(SLOW_DOWN)
}

impl AccountSync {
    /// The relay's protocol. At an older one the old single item stays, and an index there
    /// is pins truly out of reach: the pages are there, and that relay cannot hand them over.
    pub(super) fn pins_on_protocol(&mut self, proto: u32) {
        if proto < VAULT_PAGES_SINCE {
            if self.book.index.is_some() {
                self.pins_problem("hidden");
            }
            return;
        }
        if self.book.paged {
            return;
        }
        self.book.paged = true;
        self.book.saved_at = crate::time::now_millis();
        // And any page this device saw that no index names: saved in a moment that lost the
        // index's write, or a page a relay would rather it forgot
        let listed = self.book.index.as_ref().map_or(0, |i| i.pages.len());
        let seen = self
            .gens
            .keys()
            .filter_map(|k| page_number(k))
            .max()
            .map_or(0, |n| n as usize + 1);
        self.book.to_read = (0..listed.max(seen) as u16).collect();
        if self.book.index.is_none() && !self.pins.is_empty() {
            self.book.fold = true;
            let names = self.pins.name_bytes();
            let accounts: Vec<Id> = self.pins.accounts().copied().collect();
            for a in accounts {
                let bytes = names.get(&a).copied().unwrap_or(0);
                self.book.unplaced.insert(a, bytes);
            }
        }
    }

    /// Whether the pages are in: no pin decision and no key job runs before they are.
    pub fn pins_in(&self) -> bool {
        !self.book.paged
            || (self.book.asked.is_none()
                && self.book.to_read.is_empty()
                && self.book.read.is_empty())
    }

    /// What goes first after sign-in: the pages, or the old item's pins as pages.
    pub fn pins_first(&mut self) -> Vec<ClientMessage> {
        let asks = self.ask_next_page();
        if asks.is_empty() && std::mem::take(&mut self.book.fold) {
            return self.flush_pins();
        }
        asks
    }

    /// Takes over what an earlier connection of this account kept, before `pins_first`. Of
    /// the pages only those whose generation moved are read again.
    pub fn adopt_pins(&mut self, kept: KeptPins) {
        let Some(index) = self.book.index.clone().filter(|_| self.book.paged) else {
            return;
        };
        let KeptPins { pins, mut book } = kept;
        for page in &mut book.pages {
            if page.writing.take().is_some() {
                page.dirty = true;
            }
        }
        book.to_read = (0..index.pages.len())
            .filter(|n| index.pages[*n] > book.pages.get(*n).map_or(0, |p| p.gen))
            .map(|n| n as u16)
            .collect();
        // A page saved in a moment that lost its index's write
        book.index_due = book
            .pages
            .iter()
            .enumerate()
            .any(|(n, p)| p.gen > index.pages.get(n).copied().unwrap_or(0));
        book.index = Some(index);
        book.paged = true;
        book.asked = None;
        book.idle = 0;
        book.out_ticks = 0;
        book.read.clear();
        book.held.clear();
        book.warn_on_read = true;
        book.retry = false;
        book.full = false;
        self.pins = pins;
        self.book = book;
    }

    /// What this connection hands the next, if it is on pages.
    pub fn keep_pins(&self) -> Option<KeptPins> {
        self.book.paged.then(|| KeptPins {
            pins: self.pins.clone(),
            book: self.book.clone(),
        })
    }

    fn ask_next_page(&mut self) -> Vec<ClientMessage> {
        if self.book.asked.is_some() {
            return Vec::new();
        }
        let Some(n) = self.book.to_read.pop_front() else {
            return Vec::new();
        };
        self.book.asked = Some(n);
        self.book.idle = 0;
        vec![ask(AccountRequest::VaultPage { k: page_name(n) })]
    }

    /// A reply that decides pins, while the pages are out: `true` if it waits for them.
    pub(super) fn holds_for_pages(&mut self, reply: &AccountReply) -> bool {
        let decides = matches!(
            reply,
            AccountReply::LogKeysFound { .. } | AccountReply::LogMembersFound { .. }
        );
        if !decides || self.pins_in() {
            return false;
        }
        if self.book.held.len() >= HELD_MOST {
            self.book.held.remove(0);
        }
        self.book.held.push(reply.clone());
        true
    }

    /// Told once: pins that are out of use stay so for this connection, and nothing goes over them.
    pub(super) fn pins_problem(&mut self, problem: &'static str) {
        self.dirty.remove(ITEM_PINS);
        if self.read_only.insert(ITEM_PINS) {
            self.later.push(Event::VaultProblem {
                item: ITEM_PINS,
                problem,
            });
        }
    }

    /// `VaultPageFound`: a page, or none.
    pub(super) fn on_pin_page(
        &mut self,
        k: &str,
        blob: Option<&VaultBlob>,
        out: &mut Vec<ClientMessage>,
        events: &mut Vec<Event>,
    ) {
        let Some(n) = page_number(k).filter(|n| self.book.asked == Some(*n)) else {
            return;
        };
        self.book.asked = None;
        let seen = self.gens.get(k).copied().unwrap_or(0);
        let listed = self
            .book
            .index
            .as_ref()
            .and_then(|i| i.pages.get(n as usize).copied())
            .unwrap_or(0);
        let known = self.book.pages.get(n as usize).map_or(0, |p| p.gen);
        let expect = seen.max(listed).max(known);
        match blob {
            None if expect == 0 => {}
            None => self.pins_problem("missing"),
            Some(b) => match self.vault.open_item(std::slice::from_ref(b), k) {
                Ok(item) => match Pins::from_bytes(&item.payload) {
                    Some(pins) => {
                        // What it holds is still of use for checking, as at `start`: only
                        // nothing goes over it
                        self.book.read.insert(n, pins);
                        let page = self.book.page_mut(n);
                        page.version = b.version;
                        page.bytes = item.payload.len();
                        if item.gen < expect {
                            self.pins_problem("older");
                        } else {
                            self.book.index_due |= item.gen > listed;
                            self.book.page_mut(n).gen = item.gen;
                            self.gens.insert(k.to_string(), item.gen);
                            self.memory_changed = true;
                        }
                    }
                    None => self.pins_problem("unreadable"),
                },
                Err(VaultError::Newer) => self.pins_problem("newer"),
                Err(_) => self.pins_problem("unreadable"),
            },
        }
        self.pages_go_on(out, events);
    }

    /// `VaultPage` was refused.
    pub(super) fn on_page_refused(
        &mut self,
        reason: &str,
        out: &mut Vec<ClientMessage>,
        events: &mut Vec<Event>,
    ) {
        let Some(n) = self.book.asked.take() else {
            return;
        };
        if slowed_down(reason) {
            self.book.to_read.push_front(n);
            return;
        }
        self.pins_problem("missing");
        self.pages_go_on(out, events);
    }

    fn pages_go_on(&mut self, out: &mut Vec<ClientMessage>, events: &mut Vec<Event>) {
        out.extend(self.ask_next_page());
        if self.book.asked.is_some() {
            return;
        }
        let warn = self.book.warn_on_read;
        for (n, page) in std::mem::take(&mut self.book.read) {
            self.book.taken_in(&page, n);
            let changed = self.pins.merge(page);
            if warn {
                self.later
                    .extend(
                        changed
                            .into_iter()
                            .map(|(account, name)| Event::IdentityChanged {
                                account,
                                name,
                                replaced: false,
                            }),
                    );
            }
        }
        self.book.warn_on_read = true;
        // What waited for them, in the order it came
        for reply in std::mem::take(&mut self.book.held) {
            if let Some((send, more)) = self.on_reply(&reply) {
                out.extend(send);
                events.extend(more);
            }
        }
        if std::mem::take(&mut self.book.fold) {
            out.extend(self.flush_pins());
        }
        out.extend(self.save_index_when_settled());
        out.extend(self.flush());
        out.extend(self.answer());
        out.extend(self.advance_waiting());
    }

    /// While the pages are out, every couple of seconds: one lost or refused for now goes again.
    /// A relay can go on not answering for as long as it likes, and nothing pairwise goes
    /// meanwhile, so the person is told once. Nothing is out of use yet: the pages may come.
    pub(super) fn pins_wait_tick(&mut self) -> Vec<ClientMessage> {
        self.book.out_ticks += 1;
        if self.book.out_ticks == PAGES_SAID_AFTER_TICKS {
            self.later.push(Event::VaultProblem {
                item: ITEM_PINS,
                problem: "withheld",
            });
        }
        if let Some(n) = self.book.asked {
            self.book.idle += 1;
            if self.book.idle < LOST_AFTER_TICKS {
                return Vec::new();
            }
            self.book.asked = None;
            self.book.to_read.push_front(n);
        }
        self.ask_next_page()
    }

    /// `check_peer`'s answer, on pages. A warned change goes at once: a crash must not lose
    /// the one thing that says it was told. A new pin waits for the next save.
    pub(super) fn pin_noted(
        &mut self,
        account: &Id,
        name_bytes: usize,
        name_was: Option<Id>,
        check: PinCheck,
    ) -> Vec<ClientMessage> {
        if check == PinCheck::Same {
            return Vec::new();
        }
        let mut touched = vec![*account];
        // A name that moved leaves the page of whose it was
        touched.extend(name_was.filter(|was| was != account));
        for a in touched {
            if let Some(n) = self.book.page_of.get(&a).copied() {
                self.book.page_mut(n).dirty = true;
            }
        }
        if !self.book.page_of.contains_key(account) {
            self.book.unplaced.insert(*account, name_bytes);
        }
        if check.warns() {
            return self.flush_pins();
        }
        Vec::new()
    }

    /// This person's pin keeps the half open channels cannot fill.
    pub fn reserve_pin(&mut self, account: Id) {
        self.book.reserved.insert(account);
    }

    /// The person verified them: kept, and now.
    pub fn verified_pin(&mut self, account: Id) -> Vec<ClientMessage> {
        self.reserve_pin(account);
        self.flush_pins()
    }

    /// Every couple of seconds, once the pages are in.
    pub(super) fn pins_tick(&mut self, now: u64) -> Vec<ClientMessage> {
        if !self.book.paged {
            return Vec::new();
        }
        let waiting = !self.book.unplaced.is_empty() || self.book.pages.iter().any(|p| p.dirty);
        let due = now.saturating_sub(self.book.saved_at) >= SAVE_EVERY_MS;
        if self.book.retry || (waiting && due) {
            return self.flush_pins();
        }
        self.save_index_when_settled()
    }

    /// New pins onto their pages, and every page with news out. At sign-out too.
    pub fn flush_pins(&mut self) -> Vec<ClientMessage> {
        if !self.book.paged
            || !self.pins_in()
            || self.book.full
            || self.read_only.contains(ITEM_PINS)
        {
            return Vec::new();
        }
        self.book.saved_at = crate::time::now_millis();
        self.book.retry = false;
        self.place_new();
        let mut out = self.write_pages();
        out.extend(self.save_index_when_settled());
        out
    }

    /// Whether anything of the pins is still on its way. A sign-out waits a moment for this.
    pub fn pins_saved(&self) -> bool {
        !self.book.paged
            || (self.book.settled() && !self.book.index_due && !self.saving.contains(ITEM_PINS))
    }

    /// Those with a claim on the reserved half first. Whoever does not fit lasts this
    /// connection, and gets another look at the next save: they may have a claim by then.
    fn place_new(&mut self) {
        let book = &mut self.book;
        let (first, then): (Vec<_>, Vec<_>) = book
            .unplaced
            .iter()
            .map(|(a, bytes)| (*a, *bytes))
            .partition(|(a, _)| book.reserved.contains(a));
        for (account, name_bytes) in first.into_iter().chain(then) {
            let Some(key) = self.pins.get(&account) else {
                book.unplaced.remove(&account);
                continue;
            };
            let size = 16 + 1 + key.len() + 1 + name_bytes + 16;
            if size > PIN_MOST_BYTES {
                continue;
            }
            let limit = if book.reserved.contains(&account) {
                PIN_PAGES as usize
            } else {
                OPEN_PAGES
            };
            let n = match book.pages.last() {
                Some(p) if p.bytes + size <= PAGE_BYTES => book.pages.len() - 1,
                _ => book.pages.len(),
            };
            if n >= limit {
                continue;
            }
            let page = book.page_mut(n as u16);
            page.bytes += size;
            page.dirty = true;
            book.page_of.insert(account, n as u16);
            book.unplaced.remove(&account);
        }
    }

    /// Every page with news, each one write at a time. A page that came to too much, from two
    /// devices filling it at once, hands what is over to the next save.
    fn write_pages(&mut self) -> Vec<ClientMessage> {
        let mut out = Vec::new();
        for at in 0..self.book.pages.len() {
            let page = &self.book.pages[at];
            if !page.dirty || page.writing.is_some() {
                continue;
            }
            let n = at as u16;
            let k = page_name(n);
            let page_of = &self.book.page_of;
            let (part, over) = self.pins.part(|a| page_of.get(a) == Some(&n), PAGE_BYTES);
            for account in over {
                self.book.page_of.remove(&account);
                self.book.unplaced.insert(account, 0);
            }
            let bytes = part.to_bytes();
            let gen = self
                .gens
                .get(&k)
                .copied()
                .unwrap_or(0)
                .max(self.book.pages[at].gen)
                + 1;
            let blob = self.vault.seal_item(&k, gen, &bytes);
            let page = &mut self.book.pages[at];
            page.dirty = false;
            page.writing = Some(gen);
            page.bytes = bytes.len();
            out.push(ask(AccountRequest::VaultPut {
                k,
                v: blob.v,
                expect: page.version,
            }));
        }
        out
    }

    /// The index, once no page is out: it may promise only what the pages hold.
    fn save_index_when_settled(&mut self) -> Vec<ClientMessage> {
        if !self.book.paged || !self.book.index_due || !self.book.settled() {
            return Vec::new();
        }
        self.book.index_due = false;
        self.save(ITEM_PINS)
    }

    /// `VaultStored` for a page.
    pub(super) fn on_page_stored(&mut self, k: &str, version: i64) -> Vec<ClientMessage> {
        let Some(n) = page_number(k) else {
            return Vec::new();
        };
        let page = self.book.page_mut(n);
        page.version = version;
        if let Some(gen) = page.writing.take() {
            page.gen = gen;
            self.gens.insert(k.to_string(), gen);
            self.memory_changed = true;
            self.book.index_due = true;
        }
        let mut out = if self.book.full || self.read_only.contains(ITEM_PINS) {
            Vec::new()
        } else {
            self.write_pages()
        };
        out.extend(self.save_index_when_settled());
        out
    }

    /// `VaultConflict` for a page: another device wrote it first, and pins join.
    pub(super) fn on_page_conflict(
        &mut self,
        k: &str,
        theirs: Option<&VaultBlob>,
    ) -> Vec<ClientMessage> {
        let Some(n) = page_number(k) else {
            return Vec::new();
        };
        self.book.page_mut(n).writing = None;
        let seen = self
            .gens
            .get(k)
            .copied()
            .unwrap_or(0)
            .max(self.book.page_mut(n).gen);
        match theirs {
            None if seen > 0 => self.pins_problem("missing"),
            None => {
                let page = self.book.page_mut(n);
                page.version = 0;
                page.dirty = true;
            }
            Some(b) => match self.vault.open_item(std::slice::from_ref(b), k) {
                Ok(item) if item.gen < seen => self.pins_problem("older"),
                Ok(item) => match Pins::from_bytes(&item.payload) {
                    Some(pins) => {
                        self.book.taken_in(&pins, n);
                        for (account, name) in self.pins.merge(pins) {
                            self.later.push(Event::IdentityChanged {
                                account,
                                name,
                                replaced: false,
                            });
                        }
                        self.gens.insert(k.to_string(), item.gen);
                        self.memory_changed = true;
                        let page = self.book.page_mut(n);
                        page.gen = item.gen;
                        page.version = b.version;
                        page.dirty = true;
                    }
                    None => self.pins_problem("unreadable"),
                },
                Err(VaultError::Newer) => self.pins_problem("newer"),
                Err(_) => self.pins_problem("unreadable"),
            },
        }
        let mut out = if self.read_only.contains(ITEM_PINS) {
            Vec::new()
        } else {
            self.write_pages()
        };
        out.extend(self.save_index_when_settled());
        out
    }

    /// `VaultConflict` for `item.pins` itself. An index: the pages that moved are read, and
    /// joined. The old single item, from a device that has not moved yet: joined as it is.
    pub(super) fn on_pins_conflict(&mut self, item: Item) {
        if item.format == PIN_INDEX_FORMAT {
            let Some(index) = PinIndex::from_bytes(&item.payload).filter(|_| self.book.paged)
            else {
                let problem = if self.book.paged {
                    "unreadable"
                } else {
                    "hidden"
                };
                self.pins_problem(problem);
                return;
            };
            for (n, gen) in index.pages.iter().enumerate() {
                let known = self.book.pages.get(n).map_or(0, |p| p.gen);
                if *gen > known {
                    self.book.to_read.push_back(n as u16);
                }
            }
            self.book.index = Some(index);
            self.book.index_due = true;
            return;
        }
        let Some(theirs) = Pins::from_bytes(&item.payload) else {
            return;
        };
        for (account, name) in self.pins.merge(theirs) {
            self.later.push(Event::IdentityChanged {
                account,
                name,
                replaced: false,
            });
        }
        if self.book.paged {
            let names = self.pins.name_bytes();
            let accounts: Vec<Id> = self.pins.accounts().copied().collect();
            for a in accounts {
                if !self.book.page_of.contains_key(&a) {
                    let bytes = names.get(&a).copied().unwrap_or(0);
                    self.book.unplaced.insert(a, bytes);
                }
            }
            self.book.index_due = true;
        } else {
            self.dirty.insert(ITEM_PINS);
        }
    }

    /// A write was refused: for now, it goes again; otherwise the relay has no room, and is
    /// not asked again this connection.
    pub(super) fn pin_write_refused(&mut self, reason: &str) {
        if !self.book.paged {
            return;
        }
        let mut ours = false;
        for page in &mut self.book.pages {
            if page.writing.take().is_some() {
                page.dirty = true;
                ours = true;
            }
        }
        if slowed_down(reason) {
            self.book.retry = true;
            self.book.index_due = true;
        } else if ours {
            self.book.full = true;
        }
    }

    /// After a conflict on the index: the pages that moved, and then the index again.
    pub(super) fn pins_read_more(&mut self) -> Vec<ClientMessage> {
        let mut out = self.ask_next_page();
        out.extend(self.save_index_when_settled());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::{SignedIn, Vault};
    use crate::log::LogKey;
    use crate::sync::{LogMemory, ITEM_LOGKEY};
    use crate::SignalStores;
    use libsignal_protocol::IdentityKeyPair;
    use voipc_protocol::messages::{LogKeyInfo, ServerMessage};

    const RELAY: [u8; 16] = [3; 16];
    const ME: Id = [1; 16];

    fn id(n: u32) -> Id {
        let mut id = [0xB0; 16];
        id[12..].copy_from_slice(&n.to_be_bytes());
        id
    }

    fn name(n: u32) -> String {
        format!("person{n}")
    }

    fn key(n: u32) -> Vec<u8> {
        let mut k = vec![5; 33];
        k[29..].copy_from_slice(&n.to_be_bytes());
        k
    }

    fn pins_of(ns: impl IntoIterator<Item = u32>) -> Pins {
        let mut p = Pins::default();
        for n in ns {
            p.check(&id(n), &name(n), &key(n));
        }
        p
    }

    /// An account whose vault holds `items`, its own log key among them.
    fn signed(items: impl FnOnce(&Vault) -> Vec<VaultBlob>) -> SignedIn {
        let vault = Vault::create(RELAY, "me");
        let logkey = LogKey::generate();
        let mut blobs = vec![VaultBlob {
            version: 1,
            ..vault.seal_item(ITEM_LOGKEY, 1, &logkey.to_bytes())
        }];
        blobs.extend(items(&vault));
        SignedIn {
            relay_id: RELAY,
            name: "me".into(),
            vault,
            identity: IdentityKeyPair::generate(&mut crate::rng()),
            recovery: None,
            blobs,
        }
    }

    fn index(vault: &Vault, gen: u64, pages: &[u64]) -> VaultBlob {
        let payload = postcard::to_allocvec(&PinIndex {
            pages: pages.to_vec(),
        })
        .unwrap();
        VaultBlob {
            version: 7,
            ..vault.seal_item_as(ITEM_PINS, gen, PIN_INDEX_FORMAT, &payload)
        }
    }

    fn page(vault: &Vault, n: u16, gen: u64, pins: &Pins) -> VaultBlob {
        VaultBlob {
            version: 3,
            ..vault.seal_item(&page_name(n), gen, &pins.to_bytes())
        }
    }

    fn sync_on(signed: &SignedIn, memory: LogMemory, proto: u32) -> (AccountSync, Vec<Event>) {
        let (mut s, _) = AccountSync::start(signed, ME, memory, false);
        s.set_protocol(proto);
        let events = std::mem::take(&mut s.later);
        (s, events)
    }

    fn puts(out: &[ClientMessage]) -> Vec<String> {
        out.iter()
            .filter_map(|m| match m {
                ClientMessage::Account(AccountRequest::VaultPut { k, .. }) => Some(k.clone()),
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

    fn found(
        s: &mut AccountSync,
        n: u16,
        blob: Option<VaultBlob>,
    ) -> (Vec<ClientMessage>, Vec<Event>) {
        s.on_reply(&AccountReply::VaultPageFound {
            k: page_name(n),
            blob,
        })
        .unwrap()
    }

    fn problems(events: &[Event]) -> Vec<&'static str> {
        events
            .iter()
            .filter_map(|e| match e {
                Event::VaultProblem { item, problem } if *item == ITEM_PINS => Some(*problem),
                _ => None,
            })
            .collect()
    }

    fn warned(events: &[Event]) -> Vec<Id> {
        events
            .iter()
            .filter_map(|e| match e {
                Event::IdentityChanged { account, .. } => Some(*account),
                _ => None,
            })
            .collect()
    }

    /// Writes answered until nobody has anything more: what went, in order.
    fn store_all(s: &mut AccountSync, mut out: Vec<ClientMessage>) -> Vec<String> {
        let mut went = Vec::new();
        let mut version = 100;
        while let Some(m) = out.pop() {
            if let ClientMessage::Account(AccountRequest::VaultPut { k, .. }) = m {
                version += 1;
                went.push(k.clone());
                let (more, _) = s
                    .on_reply(&AccountReply::VaultStored { k, version })
                    .unwrap();
                out.extend(more);
            }
        }
        went
    }

    /// A relay's list that names `n`, signed by the identity it says, with `identity` under
    /// that person's account.
    fn keys_found(n: u32, identity: &IdentityKeyPair) -> AccountReply {
        let logkey = LogKey::generate();
        AccountReply::LogKeysFound {
            keys: vec![LogKeyInfo {
                account: id(n),
                name: name(n),
                identity: identity.public_key().serialize().to_vec(),
                logkey: logkey.public(),
                sig: logkey.endorse(identity),
            }],
        }
    }

    /// Until the pages are in, a key the relay swapped is neither taken nor warned of; then it
    /// is warned of, which empty pins would have passed as new.
    #[test]
    fn no_pin_decision_before_the_pages_are_in() {
        let them = IdentityKeyPair::generate(&mut crate::rng());
        let liar = IdentityKeyPair::generate(&mut crate::rng());
        let mut pinned = Pins::default();
        pinned.check(&id(1), &name(1), &them.public_key().serialize());
        let signed = signed(|v| vec![index(v, 2, &[1])]);
        let blob = page(&signed.vault, 0, 1, &pinned);
        let (mut s, _) = sync_on(&signed, LogMemory::default(), 21);
        assert!(!s.pins_in());
        assert_eq!(asks(&s.pins_first()), ["pins.0"]);

        // Asked for, as a session asks: it learns no key it did not
        let _ = s.ask_keys(vec![id(1)]);
        let (out, events) = s.on_reply(&keys_found(1, &liar)).unwrap();
        assert!(out.is_empty() && events.is_empty(), "{out:?}");
        assert!(s.pinned(&id(1)).is_none(), "decided on empty pins");
        assert!(s.peers.is_empty(), "a key taken before its pin was read");

        let (_, events) = found(&mut s, 0, Some(blob));
        assert!(s.pins_in());
        assert_eq!(warned(&events), [id(1)], "told once the page came");
        assert!(s.peers.contains_key(&id(1)));
    }

    /// While the pages are out a post asks nobody and a key frame waits, so nothing is handed
    /// to a key its pin was not read for; all of it goes once they are in.
    #[test]
    fn a_key_job_waits_for_the_pages() {
        use crate::channel_state::ChannelKeying as K;
        let identity = IdentityKeyPair::generate(&mut crate::rng());
        let mut stores = SignalStores::new(&identity, 1);
        stores.own_user_id = 5;
        let mut k = K::default();
        k.live_wait_for_pins();
        let out = k.live_post(&mut stores, 9, vec![1, 2], 1000).unwrap();
        assert!(out.send.is_empty(), "a post asked: {:?}", out.send);
        let owed = ServerMessage::KeysOwed {
            channel_id: 9,
            ids: vec![6],
            rows: vec![],
            more: false,
            refused: false,
        };
        let out = k.live_frame(&mut stores, 0, &owed, 1000);
        assert!(out.send.is_empty() && !out.work);
        assert!(k.live_next_frame(&mut stores, 1000, false, 10).is_none());
        assert!(!k.live_has_work());

        let out = k.live_pins_in(&mut stores, 0, 1000);
        assert_eq!(out.send.len(), 1, "the post's check: {:?}", out.send);
        assert!(
            matches!(out.send[0], ClientMessage::KeyCheck { channel_id: 9, .. }),
            "{:?}",
            out.send
        );
    }

    /// A relay that hands over no page is told of, once, and the app still takes them later.
    #[test]
    fn pages_withheld_for_half_a_minute_are_told_once() {
        let signed = signed(|v| vec![index(v, 2, &[3])]);
        let (mut s, _) = sync_on(&signed, LogMemory::default(), 21);
        assert_eq!(asks(&s.pins_first()), ["pins.0"]);
        let mut told = Vec::new();
        for _ in 0..PAGES_SAID_AFTER_TICKS - 1 {
            told.extend(problems(&s.tick().1));
        }
        assert!(told.is_empty(), "too soon: {told:?}");
        for _ in 0..PAGES_SAID_AFTER_TICKS {
            told.extend(problems(&s.tick().1));
        }
        assert_eq!(told, ["withheld"], "once");
        assert!(!s.pins_in(), "still waiting");
        assert!(
            !s.read_only.contains(ITEM_PINS),
            "nothing is out of use: the pages may yet come"
        );
    }

    /// Pages that never come: a post that waited is said to be lost, as behind any answer, and
    /// not left looking sent.
    #[test]
    fn a_post_behind_pages_that_never_come_is_said_to_be_lost() {
        use crate::channel_state::ChannelKeying as K;
        let identity = IdentityKeyPair::generate(&mut crate::rng());
        let mut stores = SignalStores::new(&identity, 1);
        let mut k = K::default();
        k.live_wait_for_pins();
        assert!(k.live_post(&mut stores, 9, vec![1], 1000).is_ok());
        assert!(k.live_tick(&mut stores, 60_999).emit.is_empty());
        let out = k.live_tick(&mut stores, 61_000);
        assert!(
            out.emit
                .iter()
                .any(|(name, _)| *name == "channel-undelivered"),
            "{:?}",
            out.emit
        );
        assert!(k.live_pins_in(&mut stores, 0, 61_000).send.is_empty());
    }

    /// A page gone, or older than this device saw, is the problem any other item's is, and
    /// no pin is written over what the relay holds.
    #[test]
    fn a_missing_pin_page_is_reported_and_never_saved_over() {
        let signed = signed(|v| vec![index(v, 2, &[3])]);
        let (mut s, _) = sync_on(&signed, LogMemory::default(), 21);
        assert_eq!(asks(&s.pins_first()), ["pins.0"]);
        let (out, events) = found(&mut s, 0, None);
        assert_eq!(problems(&events), ["missing"]);
        assert!(puts(&out).is_empty());
        assert!(s.pins_in(), "the app goes on, on what it has");
        let (_, out) = s.check_peer(&id(1), &name(1), &key(1));
        assert!(out.is_empty());
        assert!(s.flush_pins().is_empty(), "saved over a missing page");
        s.book.saved_at = 0;
        assert!(puts(&s.pins_tick(u64::MAX)).is_empty());
        let (_, out) = s.check_peer(&id(1), &name(1), &key(2));
        assert!(puts(&out).is_empty(), "even a warned change");
    }

    #[test]
    fn an_old_pin_page_is_refused_and_not_saved_over() {
        let old = pins_of([1]);
        let mut memory = LogMemory::default();
        memory.vault_gens.insert(page_name(0), 5);
        let signed = signed(|v| vec![index(v, 2, &[3])]);
        let blob = page(&signed.vault, 0, 3, &old);
        let (mut s, _) = sync_on(&signed, memory, 21);
        s.pins_first();
        let (out, events) = found(&mut s, 0, Some(blob));
        assert_eq!(problems(&events), ["older"]);
        assert!(puts(&out).is_empty());
        assert_eq!(
            s.pinned(&id(1)),
            Some(&key(1)[..]),
            "checked against, as at start"
        );
        let (_, out) = s.check_peer(&id(2), &name(2), &key(2));
        assert!(out.is_empty());
        assert!(s.flush_pins().is_empty());
        assert_eq!(s.memory().vault_gens.get(&page_name(0)), Some(&5));
    }

    /// The index's word is sealed, so a device new to the account sees a page older than it too.
    #[test]
    fn a_page_older_than_its_index_is_refused_on_a_new_device() {
        let signed = signed(|v| vec![index(v, 2, &[4])]);
        let blob = page(&signed.vault, 0, 3, &pins_of([1]));
        let (mut s, _) = sync_on(&signed, LogMemory::default(), 21);
        s.pins_first();
        let (_, events) = found(&mut s, 0, Some(blob));
        assert_eq!(problems(&events), ["older"]);
    }

    /// An index that came back older is told about by its own generation.
    #[test]
    fn an_index_older_than_this_device_saw_is_refused() {
        let signed2 = signed(|v| vec![index(v, 2, &[])]);
        let mut memory = LogMemory::default();
        memory.vault_gens.insert(ITEM_PINS.to_string(), 9);
        let (s2, _) = AccountSync::start(&signed2, ME, memory, false);
        assert!(s2.read_only.contains(ITEM_PINS));
    }

    /// A cut between a page's write and its index's: the next run still reads what this device
    /// saved, finishes the index, and takes the page's being gone for what it would be.
    #[test]
    fn a_page_no_index_names_is_read_if_this_device_saw_it() {
        let mut memory = LogMemory::default();
        memory.vault_gens.insert(page_name(0), 1);
        let signed = signed(|_| vec![]);
        let blob = page(&signed.vault, 0, 1, &pins_of([1]));
        let (mut s, _) = sync_on(&signed, memory.clone(), 21);
        assert!(!s.pins_in());
        assert_eq!(asks(&s.pins_first()), ["pins.0"]);
        let (out, events) = found(&mut s, 0, Some(blob));
        assert!(problems(&events).is_empty());
        assert_eq!(puts(&out), [ITEM_PINS], "the index it did not get to");
        assert_eq!(s.pinned(&id(1)), Some(&key(1)[..]));

        let (mut s, _) = sync_on(&signed, memory, 21);
        s.pins_first();
        let (_, events) = found(&mut s, 0, None);
        assert_eq!(problems(&events), ["missing"]);
    }

    /// A page from the page before it or from another account is no page: its name is in
    /// what is sealed.
    #[test]
    fn a_page_under_another_number_does_not_open() {
        let signed = signed(|v| vec![index(v, 2, &[1, 1])]);
        let (mut s, _) = sync_on(&signed, LogMemory::default(), 21);
        s.pins_first();
        let wrong = VaultBlob {
            k: page_name(1),
            ..page(&signed.vault, 1, 1, &pins_of([2]))
        };
        let (out, events) = found(&mut s, 0, Some(wrong));
        assert_eq!(problems(&events), ["unreadable"]);
        assert_eq!(asks(&out), ["pins.1"], "it reads the rest");
    }

    /// Fifty new people cost one write of one page and one of the index, and only when the
    /// five minutes are up. A change the person was told of goes at once.
    #[test]
    fn a_new_pin_saves_once_in_five_minutes_and_only_its_page() {
        let older = pins_of(1000..1100);
        let signed = signed(|v| vec![index(v, 2, &[1])]);
        let blob = page(&signed.vault, 0, 1, &older);
        let (mut s, _) = sync_on(&signed, LogMemory::default(), 21);
        s.pins_first();
        found(&mut s, 0, Some(blob));
        assert!(s.pins_in());

        for n in 0..50 {
            let (_, out) = s.check_peer(&id(n), &name(n), &key(n));
            assert!(out.is_empty(), "a save per person: {out:?}");
        }
        let start = s.book.saved_at;
        assert!(s.pins_tick(start + SAVE_EVERY_MS - 1).is_empty());
        let out = s.pins_tick(start + SAVE_EVERY_MS);
        assert_eq!(puts(&out), ["pins.0"], "only its page");
        assert_eq!(store_all(&mut s, out), ["pins.0", ITEM_PINS]);
        assert!(s.pins_saved());
        assert!(s.pins_tick(u64::MAX / 2).is_empty(), "nothing new");

        // A person's own page goes, not the newest, and at once
        let (_, out) = s.check_peer(&id(1000), &name(1000), &key(1));
        assert_eq!(puts(&out), ["pins.0"], "a warned change waits for nothing");
        assert_eq!(store_all(&mut s, out), ["pins.0", ITEM_PINS]);

        // Nothing new, then the next new one waits its five minutes again
        let (_, out) = s.check_peer(&id(70), &name(70), &key(70));
        assert!(out.is_empty());
        let at = s.book.saved_at;
        assert!(s.pins_tick(at + 1000).is_empty());
    }

    /// A page fills, and the next one starts: the old one is not written again.
    #[test]
    fn a_new_pin_past_a_full_page_dirties_only_the_next() {
        let signed = signed(|_| vec![]);
        let (mut s, _) = sync_on(&signed, LogMemory::default(), 21);
        let mut n = 0;
        while s.book.pages.len() < 2 {
            n += 1;
            s.check_peer(&id(n), &name(n), &key(n));
            s.place_new();
        }
        let out = s.flush_pins();
        assert_eq!(puts(&out), ["pins.0", "pins.1"]);
        assert!(n > 500, "about 560 fit a page: {n}");
        store_all(&mut s, out);
        s.check_peer(&id(n + 1), &name(n + 1), &key(n + 1));
        let out = s.flush_pins();
        assert_eq!(puts(&out), ["pins.1"], "the full page is left alone");
        assert_eq!(store_all(&mut s, out), ["pins.1", ITEM_PINS]);
    }

    /// A page goes before the index that names it, whatever comes back: an index that promised
    /// a generation no page holds would read as a rollback for good.
    #[test]
    fn a_page_is_written_before_the_index_that_names_it() {
        let signed = signed(|_| vec![]);
        let (mut s, _) = sync_on(&signed, LogMemory::default(), 21);
        s.check_peer(&id(1), &name(1), &key(1));
        let out = s.flush_pins();
        assert_eq!(puts(&out), ["pins.0"]);
        // No answer yet: the index stays home
        assert!(s.pins_tick(u64::MAX / 2).is_empty());
        let (out, _) = s
            .on_reply(&AccountReply::VaultStored {
                k: "pins.0".into(),
                version: 1,
            })
            .unwrap();
        assert_eq!(puts(&out), [ITEM_PINS]);
        let ClientMessage::Account(AccountRequest::VaultPut { v, .. }) = &out[0] else {
            unreachable!()
        };
        let item = s
            .vault
            .open_item(
                &[VaultBlob {
                    k: ITEM_PINS.into(),
                    v: v.clone(),
                    version: 1,
                }],
                ITEM_PINS,
            )
            .unwrap();
        assert_eq!(item.format, PIN_INDEX_FORMAT);
        assert_eq!(PinIndex::from_bytes(&item.payload).unwrap().pages, [1]);
    }

    /// Past half the room a person met only in an open channel lasts this connection. Someone
    /// from a direct conversation or a gated channel, or verified, still gets a page, and the
    /// one the open half stopped is placed once they have such a claim.
    #[test]
    fn open_channel_pins_stop_at_half_the_paged_space() {
        let signed = signed(|_| vec![]);
        let (mut s, _) = sync_on(&signed, LogMemory::default(), 21);
        let mut n = 0;
        while s.book.unplaced.is_empty() {
            n += 256;
            for i in n - 256..n {
                s.check_peer(&id(i), &name(i), &key(i));
            }
            s.place_new();
        }
        assert!(n > 15_000, "about 16,000: {n}");
        assert_eq!(s.book.pages.len(), OPEN_PAGES);
        let out = s.flush_pins();
        assert_eq!(puts(&out).len(), OPEN_PAGES);
        store_all(&mut s, out);
        assert!(s.book.pages.iter().all(|p| p.bytes <= PAGE_BYTES));

        // Open: held for this connection, on no page
        let open = id(9_000_000);
        let (_, out) = s.check_peer(&open, &name(9_000_000), &key(1));
        assert!(out.is_empty());
        assert!(
            s.flush_pins().is_empty(),
            "an open channel's pin saved past half"
        );
        assert!(!s.book.page_of.contains_key(&open));
        assert_eq!(s.pinned(&open), Some(&key(1)[..]), "it still warns here");

        // A direct conversation's still saves, on a page past half
        let direct = id(9_100_000);
        s.reserve_pin(direct);
        s.check_peer(&direct, &name(9_100_000), &key(2));
        let out = s.flush_pins();
        let past_half = page_name(OPEN_PAGES as u16);
        assert_eq!(puts(&out), std::slice::from_ref(&past_half));
        store_all(&mut s, out);
        assert_eq!(s.book.page_of.get(&direct), Some(&(OPEN_PAGES as u16)));
        assert!(
            !s.book.page_of.contains_key(&open),
            "that opened no room for them"
        );

        // Verified: at once, and it stays
        let out = s.verified_pin(open);
        assert_eq!(puts(&out), [past_half]);
        assert_eq!(s.book.page_of.get(&open), Some(&(OPEN_PAGES as u16)));
    }

    /// The room for those with a claim runs to the last page, and past it nothing is
    /// evicted: the newcomer lasts this connection, the old ones stay.
    #[test]
    fn past_the_last_page_nothing_is_evicted() {
        let signed = signed(|_| vec![]);
        let (mut s, _) = sync_on(&signed, LogMemory::default(), 21);
        s.book.pages = vec![
            Page {
                bytes: PAGE_BYTES,
                ..Page::default()
            };
            PIN_PAGES as usize
        ];
        s.book.page_of.insert(id(1), 0);
        s.reserve_pin(id(2));
        s.check_peer(&id(2), &name(2), &key(2));
        assert!(s.flush_pins().is_empty());
        assert!(!s.book.page_of.contains_key(&id(2)));
        assert_eq!(s.book.page_of.get(&id(1)), Some(&0));
    }

    /// The old single item reads as ever and becomes pages at the first connect: no one is
    /// new again, and the item's generation goes on, so showing the old item is a rollback.
    #[test]
    fn an_upgrade_folds_the_old_pins_item_in() {
        let old = pins_of([1, 2, 3]);
        let signed = signed(|v| {
            vec![VaultBlob {
                version: 4,
                ..v.seal_item(ITEM_PINS, 5, &old.to_bytes())
            }]
        });
        let mut memory = LogMemory::default();
        memory.vault_gens.insert(ITEM_PINS.to_string(), 5);
        let (mut s, events) = sync_on(&signed, memory, 21);
        assert!(events.is_empty(), "nothing to tell");
        assert!(s.pins_in());
        assert_eq!(s.pinned(&id(2)), Some(&key(2)[..]));
        let out = s.pins_first();
        assert_eq!(puts(&out), ["pins.0"], "at once");
        let ClientMessage::Account(AccountRequest::VaultPut { v, expect, .. }) = &out[0] else {
            unreachable!()
        };
        assert_eq!(*expect, 0);
        let blob = VaultBlob {
            k: "pins.0".into(),
            v: v.clone(),
            version: 1,
        };
        let (out, _) = s
            .on_reply(&AccountReply::VaultStored {
                k: "pins.0".into(),
                version: 1,
            })
            .unwrap();
        let ClientMessage::Account(AccountRequest::VaultPut { k, v, expect }) = &out[0] else {
            unreachable!()
        };
        assert_eq!((k.as_str(), *expect), (ITEM_PINS, 4), "over the old item");
        let index_blob = VaultBlob {
            k: ITEM_PINS.into(),
            v: v.clone(),
            version: 5,
        };
        let (out, _) = s
            .on_reply(&AccountReply::VaultStored {
                k: ITEM_PINS.into(),
                version: 5,
            })
            .unwrap();
        assert!(out.is_empty());
        assert_eq!(s.memory().vault_gens.get(ITEM_PINS), Some(&6));

        // Next sign-in: the index, then the page; nobody is new, and a swap warns
        let again = SignedIn {
            blobs: vec![signed.blobs[0].clone(), index_blob],
            vault: Vault::from_dek(RELAY, "me", signed.vault.dek()),
            relay_id: RELAY,
            name: "me".into(),
            identity: signed.identity,
            recovery: None,
        };
        let (mut s2, events) = sync_on(&again, s.memory(), 21);
        assert!(events.is_empty());
        assert_eq!(asks(&s2.pins_first()), ["pins.0"]);
        found(&mut s2, 0, Some(blob));
        assert_eq!(s2.check_peer(&id(2), &name(2), &key(2)).0, PinCheck::Same);
        assert_eq!(
            s2.check_peer(&id(3), &name(3), &key(9)).0,
            PinCheck::Changed
        );

        // The old item shown again to a device that saw the index is a rollback
        let (s3, events) = sync_on(&signed, s.memory(), 21);
        assert!(s3.read_only.contains(ITEM_PINS));
        assert_eq!(problems(&events), ["older"]);
    }

    /// A relay at 20 keeps the single item, with no notice: nothing is hidden. Pins that went
    /// to pages truly are out of reach there, and only that is told.
    #[test]
    fn an_older_relay_keeps_the_single_item_and_says_nothing() {
        let old = pins_of([1]);
        let signed = signed(|v| {
            vec![VaultBlob {
                version: 4,
                ..v.seal_item(ITEM_PINS, 5, &old.to_bytes())
            }]
        });
        let (mut s, events) = sync_on(&signed, LogMemory::default(), 20);
        assert!(events.is_empty());
        assert!(s.pins_in());
        assert!(s.pins_first().is_empty());
        let (_, out) = s.check_peer(&id(2), &name(2), &key(2));
        assert_eq!(puts(&out), [ITEM_PINS], "at once, as ever");
        let ClientMessage::Account(AccountRequest::VaultPut { v, .. }) = &out[0] else {
            unreachable!()
        };
        let item = s
            .vault
            .open_item(
                &[VaultBlob {
                    k: ITEM_PINS.into(),
                    v: v.clone(),
                    version: 1,
                }],
                ITEM_PINS,
            )
            .unwrap();
        assert_ne!(item.format, PIN_INDEX_FORMAT);
        assert!(Pins::from_bytes(&item.payload)
            .unwrap()
            .get(&id(2))
            .is_some());
    }

    #[test]
    fn an_older_relay_with_pages_says_they_are_hidden_and_saves_nothing() {
        let signed = signed(|v| vec![index(v, 2, &[3])]);
        let (mut s, events) = sync_on(&signed, LogMemory::default(), 20);
        assert_eq!(problems(&events), ["hidden"]);
        assert!(s.pins_in(), "nothing to wait for: no page will come");
        assert!(s.pins_first().is_empty());
        let (_, out) = s.check_peer(&id(2), &name(2), &key(2));
        assert!(puts(&out).is_empty(), "saved over the index");
    }

    /// A build before this one meets the index as a thing a newer VoIPC wrote, and leaves it.
    #[test]
    fn the_index_is_newer_to_an_older_reader() {
        let signed = signed(|_| vec![]);
        let blob = index(&signed.vault, 2, &[1]);
        let item = signed.vault.open_item(&[blob], ITEM_PINS).unwrap();
        assert!(item.format > 1, "an older build's ITEM_FORMAT");
    }

    /// An app that stayed up reads only the page that moved, and writes what it had not
    /// saved. A move that disagrees with what it holds is told.
    #[test]
    fn an_app_that_stayed_up_fetches_only_the_page_that_moved() {
        let them = |v: &Vault| vec![index(v, 2, &[1, 1, 1])];
        let first = signed(them);
        let dek = first.vault.dek();
        let (mut s, _) = sync_on(&first, LogMemory::default(), 21);
        s.pins_first();
        found(&mut s, 0, Some(page(&first.vault, 0, 1, &pins_of([1]))));
        found(&mut s, 1, Some(page(&first.vault, 1, 1, &pins_of([2]))));
        found(&mut s, 2, Some(page(&first.vault, 2, 1, &pins_of([3]))));
        assert!(s.pins_in());
        s.check_peer(&id(4), &name(4), &key(4));
        let kept = s.keep_pins().unwrap();
        let memory = s.memory();

        let vault = Vault::from_dek(RELAY, "me", dek);
        let blobs = vec![index(&vault, 3, &[1, 2, 1])];
        let again = SignedIn {
            blobs,
            vault,
            ..self::signed(|_| vec![])
        };
        let (mut s2, _) = sync_on(&again, memory.clone(), 21);
        s2.adopt_pins(kept);
        assert!(!s2.pins_in());
        assert_eq!(asks(&s2.pins_first()), ["pins.1"], "only what moved");
        let mut moved = pins_of([2]);
        moved.check(&id(2), &name(2), &key(22));
        let (_, events) = found(&mut s2, 1, Some(page(&again.vault, 1, 2, &moved)));
        assert_eq!(warned(&events), [id(2)]);
        assert!(s2.pins_in());
        assert_eq!(s2.pinned(&id(1)), Some(&key(1)[..]));
        assert_eq!(
            s2.pinned(&id(4)),
            Some(&key(4)[..]),
            "not saved yet, and not lost"
        );
        let out = s2.flush_pins();
        assert_eq!(puts(&out), ["pins.2"], "the newest");

        // Nothing moved: nothing to read, and nothing waits at all
        let kept = s2.keep_pins().unwrap();
        let vault = Vault::from_dek(RELAY, "me", dek);
        let blobs = vec![index(&vault, 3, &[1, 2, 1])];
        let again = SignedIn {
            blobs,
            vault,
            ..self::signed(|_| vec![])
        };
        let (mut s3, _) = sync_on(&again, memory, 21);
        s3.adopt_pins(kept);
        assert!(s3.pins_in());
        assert!(asks(&s3.pins_first()).is_empty());
    }

    /// Another device wrote the page first: the two join, and what they disagree on is told.
    #[test]
    fn a_conflict_on_a_page_joins_and_goes_again() {
        let signed = signed(|_| vec![]);
        let (mut s, _) = sync_on(&signed, LogMemory::default(), 21);
        s.check_peer(&id(1), &name(1), &key(1));
        let out = s.flush_pins();
        assert_eq!(puts(&out), ["pins.0"]);
        let mut theirs = pins_of([2]);
        theirs.check(&id(1), &name(1), &key(11));
        let blob = page(&signed.vault, 0, 4, &theirs);
        let (out, events) = s
            .on_reply(&AccountReply::VaultConflict {
                k: "pins.0".into(),
                blob: Some(blob),
            })
            .unwrap();
        assert_eq!(warned(&events), [id(1)]);
        assert_eq!(puts(&out), ["pins.0"]);
        assert_eq!(s.pinned(&id(2)), Some(&key(2)[..]));
        let ClientMessage::Account(AccountRequest::VaultPut { v, expect, .. }) = &out[0] else {
            unreachable!()
        };
        assert_eq!(*expect, 3, "on top of theirs");
        let item = s
            .vault
            .open_item(
                &[VaultBlob {
                    k: "pins.0".into(),
                    v: v.clone(),
                    version: 1,
                }],
                "pins.0",
            )
            .unwrap();
        assert_eq!(item.gen, 5);

        // An older copy in a conflict is a rollback, not a join
        store_all(&mut s, out);
        s.check_peer(&id(3), &name(3), &key(3));
        s.flush_pins();
        let old = page(&signed.vault, 0, 2, &pins_of([9]));
        let (out, events) = s
            .on_reply(&AccountReply::VaultConflict {
                k: "pins.0".into(),
                blob: Some(old),
            })
            .unwrap();
        assert_eq!(problems(&events), ["older"]);
        assert!(puts(&out).is_empty());
        assert!(s.pinned(&id(9)).is_none());
    }

    /// A refusal for now goes again at the next tick, with no word to the person. No room is
    /// said once, and not asked again.
    #[test]
    fn a_refused_write_goes_again_or_stops() {
        let signed = signed(|_| vec![]);
        let (mut s, _) = sync_on(&signed, LogMemory::default(), 21);
        s.check_peer(&id(1), &name(1), &key(1));
        assert_eq!(puts(&s.flush_pins()), ["pins.0"]);
        let (_, events) = s
            .on_reply(&AccountReply::Error {
                request: "VaultPut".into(),
                reason: "Too many requests at once; slow down.".into(),
            })
            .unwrap();
        assert!(events.is_empty());
        let (out, _) = s.tick();
        assert_eq!(puts(&out), ["pins.0"]);
        let (_, events) = s
            .on_reply(&AccountReply::Error {
                request: "VaultPut".into(),
                reason: "The vault is full.".into(),
            })
            .unwrap();
        assert_eq!(events.len(), 1);
        s.book.saved_at = 0;
        let (out, _) = s.tick();
        assert!(puts(&out).is_empty());
    }

    /// One a relay never answers goes again; a refusal for now, at the next tick.
    #[test]
    fn a_lost_or_refused_page_ask_goes_again() {
        let signed = signed(|v| vec![index(v, 2, &[1])]);
        let (mut s, _) = sync_on(&signed, LogMemory::default(), 21);
        assert_eq!(asks(&s.pins_first()), ["pins.0"]);
        let (out, _) = s.tick();
        assert!(asks(&out).is_empty());
        let (out, _) = s.tick();
        assert!(asks(&out).is_empty());
        let (out, _) = s.tick();
        assert_eq!(asks(&out), ["pins.0"], "lost");
        s.on_reply(&AccountReply::Error {
            request: "VaultPage".into(),
            reason: "Too many requests at once; slow down.".into(),
        });
        assert!(!s.pins_in());
        let (out, _) = s.tick();
        assert_eq!(asks(&out), ["pins.0"], "refused for now");
        let (_, events) = s
            .on_reply(&AccountReply::Error {
                request: "VaultPage".into(),
                reason: "No such page.".into(),
            })
            .unwrap();
        assert_eq!(problems(&events), ["missing"]);
        assert!(s.pins_in());
    }

    /// No page, for something its name is too long to save: it stays in memory only, and the
    /// page stays within what the relay takes.
    #[test]
    fn a_name_too_long_for_a_page_stays_in_memory() {
        let signed = signed(|_| vec![]);
        let (mut s, _) = sync_on(&signed, LogMemory::default(), 21);
        let long = "x".repeat(4096);
        s.check_peer(&id(1), &long, &key(1));
        assert!(s.flush_pins().is_empty());
        assert_eq!(s.pinned(&id(1)), Some(&key(1)[..]));
    }

    /// A page that came to too much hands what is over to the next save, and fits.
    #[test]
    fn a_page_too_full_hands_on_what_is_over() {
        let signed = signed(|_| vec![]);
        let (mut s, _) = sync_on(&signed, LogMemory::default(), 21);
        for n in 0..1000 {
            s.pins.check(&id(n), &name(n), &key(n));
            s.book.page_of.insert(id(n), 0);
        }
        s.book.page_mut(0).dirty = true;
        let out = s.write_pages();
        let ClientMessage::Account(AccountRequest::VaultPut { v, .. }) = &out[0] else {
            unreachable!()
        };
        assert!(v.len() <= 48 * 1024);
        assert!(!s.book.unplaced.is_empty());
    }
}
