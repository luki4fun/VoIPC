//! What a keyholder's builds cost in the browser (plan part 6, slice L1b; OPERATING §10a,
//! open choice 28). A relay of its own in the page asks this connection's duty
//! (`GroupKeying`, C3c) real dues, checks each commit with the validator and takes it as
//! gk/group.rs does, and pushes the header back, so every build is the duty's own
//! `BuildJob`. Each due is timed as the page pays for it: the frames the duty takes (the
//! due, the lists it asks) from their bytes as `gkFrame` takes them, the job's steps at the
//! host's budget, `built`, its uploads encoded (`gkNextFrame`), and the pushed header its
//! member takes. Not timed: the account's settling and the events' JSON (gk.rs `Gk::take`,
//! `settle`), which a keyholder's frames hardly use. tools/gk-wasm-bench.mjs runs it in
//! Chromium and Firefox.
//!
//! Only a build made with `VOIPC_GK_BENCH` set runs it (`ON`): the production bundle
//! carries the export as a stub that throws, and none of this code.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::hint::black_box;

use libsignal_protocol::{kem, IdentityKeyPair, KeyPair};
use rand::{Rng, RngCore};
use serde::Serialize;
use serde_json::{json, Value};
use voipc_crypto::group_key::commit::{
    validate, Applied, Candidate, Commit, Due, DueKind, Exit, GroupView, HeadView, HolderRef,
    Joiner, Listed, Pair,
};
use voipc_crypto::group_key::timers::JOIN_BATCH_MAX;
use voipc_crypto::group_key::{
    seat_welcome, wire, Endorsement, Group, GroupKind, Me, MemberId, Origin, SeatPair, SeatPublic,
    SeatRef, SeedRolls, SignedHeader, Them, Version,
};
use voipc_crypto::group_state::{
    group_id, GkCtx, GkOut, GkStart, GkTrack, GroupKeying, MemoryPins, Platform, VaultFloor,
};
use voipc_crypto::time::now_millis;
use voipc_crypto::SignalStores;
use voipc_protocol::gk::{self, DuePiece, EndorsedPair, GkMember, InPiece, VoiceSeatsPiece};
use voipc_protocol::messages::{ClientMessage, ServerMessage};

/// Built with `VOIPC_GK_BENCH` set.
pub const ON: bool = option_env!("VOIPC_GK_BENCH").is_some();

/// This connection's user id.
const USER: u32 = 3;
/// The stored text group's log (`c:`, on a relay with accounts).
const TEXT_ID: &str = "c:gk-bench";
/// A due's part, with room for its lists' lengths to grow.
const PART_MAX: usize = gk::PIECE_MAX_BYTES - 64;

thread_local! {
    static BENCH: RefCell<Option<Bench>> = const { RefCell::new(None) };
}

/// One step of the bench (tools/gk-wasm-bench.mjs), as JSON:
/// - `prim n`: X25519, Kyber1024 encaps/decaps and a seat welcome, per call, median of `n`
///   batches;
/// - `join n`: a Join of `n` accounts into the stored text group (its Genesis first);
/// - `exits n`: an opening of the stored group carrying `n` exits of random seats;
/// - `refresh`: a refresh opening of the stored group;
/// - `cexits n`, `crefresh`: the same built cold, with no row bases (`run_due`);
/// - `seed n`: a seed-welcome page of `n` of its seats under the head's seed;
/// - `mjoin n`, `mexits n`: the same in a memory-only text group of guests, whose Joins make
///   no rows, so its first opening makes every row base anew (a cold re-key);
/// - `voice n`: a Join of `n` guests into the voice room (its Genesis first);
/// - `vexits n`: an opening of the voice room carrying `n` exits;
/// - `vpromote`, `vremove`: a second keyholder for the room, then its leave (`remove`);
///   `cvremove`, the leave built cold;
/// - `reset`: all of it gone.
///
/// The keyholder built every row of the stored group it builds on, so `exits` and `refresh`
/// find a row base for every seat (warm): a keyholder new to the group, or back after a
/// reload (a browser's pair is the connection's, and row bases live in memory), finds none.
/// A build steps at `budget_ms`, as session.ts `gkBuild` asks.
pub fn run(op: &str, arg: u32, budget_ms: f64) -> Result<String, String> {
    if !ON {
        return Err("this build has no group-key bench: build it with VOIPC_GK_BENCH=1".into());
    }
    step(op, arg, budget_ms).map(|v| v.to_string())
}

fn step(op: &str, arg: u32, budget_ms: f64) -> Result<Value, String> {
    match op {
        "prim" => return Ok(prims(arg)),
        "reset" => {
            BENCH.with(|b| b.borrow_mut().take());
            return Ok(json!({ "op": "reset" }));
        }
        _ => {}
    }
    BENCH.with(|b| {
        let mut b = b.borrow_mut();
        let bench = match b.as_mut() {
            Some(bench) => bench,
            None => b.insert(Bench::new()?),
        };
        let budget = budget_ms.max(0.0);
        match op {
            "join" => bench.join(Which::Kept, arg, budget),
            "mjoin" => bench.join(Which::Memory, arg, budget),
            "voice" => bench.join(Which::Voice, arg, budget),
            "exits" => bench.exits(Which::Kept, arg, false, budget),
            "cexits" => bench.exits(Which::Kept, arg, true, budget),
            "mexits" => bench.exits(Which::Memory, arg, false, budget),
            "vexits" => bench.exits(Which::Voice, arg, false, budget),
            "refresh" => bench.refresh(false, budget),
            "crefresh" => bench.refresh(true, budget),
            "vpromote" => bench.promote(budget),
            "vremove" => bench.remove(false, budget),
            "cvremove" => bench.remove(true, budget),
            "seed" => bench.seed_page(arg, budget),
            _ => Err(format!("no bench step {op:?}")),
        }
    })
}

// ── Time ──────────────────────────────────────────────────────────────────

#[cfg(target_arch = "wasm32")]
mod clock {
    use wasm_bindgen::prelude::*;

    #[wasm_bindgen]
    extern "C" {
        #[wasm_bindgen(js_namespace = performance, js_name = now)]
        fn performance_now() -> f64;
    }

    /// Milliseconds, as precise as the page's clock is.
    pub fn ms() -> f64 {
        performance_now()
    }

    /// The module's memory, in 64 KiB pages.
    pub fn pages() -> usize {
        core::arch::wasm32::memory_size::<0>()
    }
}

#[cfg(not(target_arch = "wasm32"))]
mod clock {
    use std::sync::OnceLock;
    use std::time::Instant;

    pub fn ms() -> f64 {
        static START: OnceLock<Instant> = OnceLock::new();
        START.get_or_init(Instant::now).elapsed().as_secs_f64() * 1e3
    }

    /// Natively, no module memory to watch.
    pub fn pages() -> usize {
        0
    }
}

fn r3(x: f64) -> f64 {
    (x * 1000.0).round() / 1000.0
}

/// A timed batch lasts at least this long, so a coarse clock rounds a call's figure by at
/// most its step over the batch: Firefox's clock steps 20 µs by default, 1/50 of a batch.
const BATCH_MS: f64 = 1.0;

/// The median per call of `n` timed batches of `f`, in µs, after three calls to warm up.
fn median_us<T>(n: u32, f: impl FnMut() -> T) -> f64 {
    per_call_us(n, clock::ms, f)
}

/// `median_us` on the clock `now` (ms). A batch is as many calls as last `BATCH_MS`.
fn per_call_us<T>(n: u32, now: impl Fn() -> f64, mut f: impl FnMut() -> T) -> f64 {
    for _ in 0..3 {
        black_box(f());
    }
    let mut batch = |per: u32| {
        let at = now();
        for _ in 0..per {
            black_box(f());
        }
        now() - at
    };
    let mut per = 1u32;
    while per < 1 << 20 && batch(per) < BATCH_MS {
        per *= 2;
    }
    let mut t: Vec<f64> = (0..n.max(1)).map(|_| batch(per) / f64::from(per)).collect();
    t.sort_by(f64::total_cmp);
    r3(t[t.len() / 2] * 1000.0)
}

fn prims(n: u32) -> Value {
    let mut rng = voipc_crypto::rng();
    let a = KeyPair::generate(&mut rng);
    let b = KeyPair::generate(&mut rng);
    let x25519 = median_us(n, || a.private_key.calculate_agreement(&b.public_key));
    let k = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);
    let (_, ct) = k
        .public_key
        .encapsulate(&mut rng)
        .expect("a Kyber1024 key encapsulates");
    let encaps = median_us(n, || k.public_key.encapsulate(&mut rng));
    let decaps = median_us(n, || k.secret_key.decapsulate(&ct));
    let g = Group::new(GroupKind::Text, TEXT_ID, [1; 16]).expect("a group id");
    let (from, to) = (SeatPair::generate(), SeatPair::generate().public());
    let me = Me {
        m: MemberId::Conn(1),
        keys: &from,
    };
    let them = Them {
        m: MemberId::Conn(2),
        keys: &to,
    };
    let at = Version { b: 1, v: 1 };
    let welcome = median_us(n, || {
        seat_welcome(&g, 0, at, &me, &them, &[7; 32], &[9; 32])
    });
    json!({
        "op": "prim",
        "n": n,
        "x25519_us": x25519,
        "kyber_encaps_us": encaps,
        "kyber_decaps_us": decaps,
        "seat_welcome_us": welcome,
    })
}

// ── What a due cost ───────────────────────────────────────────────────────

/// One due, as the page pays for it.
#[derive(Default)]
struct Cost {
    /// The frames the duty took (the due's parts and the lists it asked for), each from its
    /// bytes to what it says to send handed to JS, as `gkFrame` takes them.
    lock_ms: f64,
    lock_max_ms: f64,
    lock_calls: u32,
    steps: u32,
    step_max_ms: f64,
    /// The build's units of work (`build::steps::unit`).
    units: u64,
    /// Steps in which the module's memory grew, and the longest of them and of the others:
    /// a `memory.grow` (and the first touch of its pages) lands in the step that asks it.
    grew_steps: u32,
    grew_max_ms: f64,
    flat_max_ms: f64,
    /// The longest step: which (from 0), and the units it did.
    step_max_at: (u32, u64),
    build_ms: f64,
    built_ms: f64,
    /// The commit's parts and welcome pages, each out of the duty and encoded
    /// (`gkNextFrame`).
    upload_ms: f64,
    upload_max_ms: f64,
    /// The member taking the pushed header.
    take_ms: f64,
}

impl Cost {
    fn lock(&mut self, ms: f64) {
        self.lock_ms += ms;
        self.lock_max_ms = self.lock_max_ms.max(ms);
        self.lock_calls += 1;
    }

    fn upload(&mut self, ms: f64) {
        self.upload_ms += ms;
        self.upload_max_ms = self.upload_max_ms.max(ms);
    }

    fn json(&self) -> Value {
        json!({
            "lock_ms": r3(self.lock_ms),
            "lock_max_ms": r3(self.lock_max_ms),
            "lock_calls": self.lock_calls,
            "steps": self.steps,
            "step_max_ms": r3(self.step_max_ms),
            "units": self.units,
            "grew_steps": self.grew_steps,
            "grew_max_ms": r3(self.grew_max_ms),
            "flat_max_ms": r3(self.flat_max_ms),
            "step_max_at": self.step_max_at.0,
            "step_max_units": self.step_max_at.1,
            "build_ms": r3(self.build_ms),
            "built_ms": r3(self.built_ms),
            "upload_ms": r3(self.upload_ms),
            "upload_max_ms": r3(self.upload_max_ms),
            "take_ms": r3(self.take_ms),
            "page_ms": r3(
                self.lock_ms + self.build_ms + self.built_ms + self.upload_ms + self.take_ms
            ),
        })
    }
}

// ── The keyholder: one connection's GroupKeying ───────────────────────────

struct Kh {
    keying: GroupKeying,
    stores: SignalStores,
    pins: MemoryPins,
    ik: [u8; 32],
    /// The connection's pair it volunteered with (0x02).
    pair: EndorsedPair,
}

impl Kh {
    /// `msg` as the page takes it, timed from the relay's bytes on: decoded (gk.rs
    /// `Gk::frame`), the duty's frame, and what it says to send handed to JS (`to_page`).
    fn call(&mut self, msg: &ServerMessage) -> Result<(GkOut, f64), String> {
        let bytes = postcard::to_allocvec(msg).map_err(|e| format!("a frame encodes: {e}"))?;
        if !crate::gk::is_gk_frame(&bytes) {
            return Err(format!("the page hands no such frame to gkFrame: {msg:?}"));
        }
        let at = clock::ms();
        let msg = voipc_protocol::codec::decode_server_msg(&bytes)
            .map_err(|e| format!("a frame decodes: {e}"))?;
        let c = GkCtx {
            pins: &mut self.pins,
            now: now_millis(),
        };
        let out = self.keying.frame(&mut self.stores, &msg, c);
        to_page(&out.send)?;
        Ok((out, clock::ms() - at))
    }

    /// A frame the duty takes on the page thread.
    fn frame(&mut self, msg: &ServerMessage, cost: &mut Cost) -> Result<GkOut, String> {
        let (out, ms) = self.call(msg)?;
        cost.lock(ms);
        Ok(out)
    }

    fn by(&self) -> HolderRef {
        HolderRef {
            m: MemberId::Conn(USER),
            kx: self.pair.dh[1..].try_into().expect("33 bytes"),
        }
    }

    fn own(&self) -> Result<Pair, String> {
        wire::pair(&self.pair, GkMember::Conn(USER)).map_err(|e| format!("own pair: {e:?}"))
    }
}

/// What a call says to send, as the page gets it: lib.rs `gk_out` (postcard bytes in
/// `Uint8Array`s). Natively, the encoding alone.
fn to_page(send: &[ClientMessage]) -> Result<(), String> {
    #[cfg(target_arch = "wasm32")]
    {
        let out = crate::gk::Out {
            send: send.to_vec(),
            ..Default::default()
        };
        black_box(crate::gk_out(out).map_err(|_| "gk_out failed")?);
    }
    #[cfg(not(target_arch = "wasm32"))]
    for m in send {
        black_box(postcard::to_allocvec(m).map_err(|e| format!("a frame encodes: {e}"))?);
    }
    Ok(())
}

// ── The relay's side of one group ─────────────────────────────────────────

/// A seated seat's pair as the relay holds it; `kem` empty for the members' shared key.
struct Seat {
    pair: EndorsedPair,
    ik: [u8; 32],
}

struct Room {
    kind: GroupKind,
    id: String,
    stored: bool,
    head: Option<SignedHeader>,
    kh: Option<SignedHeader>,
    leaves: Vec<Listed>,
    seats: HashMap<SeatRef, Seat>,
    held: HashMap<SeatRef, u32>,
    used_v: HashSet<u64>,
    rolls: SeedRolls,
    gens: Vec<[u8; 16]>,
    roster: Vec<u32>,
    seq: u64,
    /// A voice room's second keyholder (`vpromote`), and its seat.
    second: Option<(HolderRef, SeatRef)>,
}

impl Room {
    fn new(kind: GroupKind, id: String) -> Room {
        Room {
            kind,
            stored: id.starts_with("c:"),
            id,
            head: None,
            kh: None,
            leaves: vec![],
            seats: HashMap::new(),
            held: HashMap::new(),
            used_v: HashSet::new(),
            rolls: SeedRolls {
                raised: 0,
                removal: false,
            },
            gens: vec![],
            roster: vec![USER],
            seq: 0,
            second: None,
        }
    }

    fn seats_now(&self) -> u32 {
        self.head.as_ref().map_or(0, |h| h.header().seats)
    }

    fn head(&self) -> Result<&SignedHeader, String> {
        self.head.as_ref().ok_or_else(|| "no head yet".into())
    }

    /// The relay's check (gk/group.rs over `commit::validate`).
    fn check(&self, due: &Due, by: HolderRef, c: &Commit) -> Result<Applied, String> {
        let held = |s: &SeatRef| self.held.get(s).copied();
        let used = |v: u64| self.used_v.contains(&v);
        let head = match (&self.head, &self.kh) {
            (Some(head), Some(kh)) => Some(HeadView { head, kh }),
            _ => None,
        };
        let view = GroupView {
            kind: self.kind,
            id: &self.id,
            stored: self.stored,
            head,
            leaves: &self.leaves,
            held: &held,
            due,
            by,
            rolls: self.rolls,
            known_gens: &self.gens,
            used_v: &used,
            now: now_millis() / 1000,
            roster: &self.roster,
            no_keyholder_since: None,
        };
        validate(&view, c).map_err(|bad| format!("the relay refused the commit: {bad}"))
    }

    /// What the relay keeps once it took `a` (the test world's `take`).
    fn take(&mut self, a: Applied, mut joined: HashMap<SeatRef, Seat>) {
        let h = a.header.header();
        if !self.gens.contains(&h.gen) {
            self.gens.push(h.gen);
            self.used_v.clear();
        }
        if h.kind.starts_anew() {
            self.held.clear();
        }
        let gone: HashSet<Version> = a.gone.iter().copied().collect();
        self.leaves.retain(|l| !gone.contains(&l.version()));
        for m in &a.made {
            self.used_v.insert(m.leaf.v);
        }
        self.leaves.extend(a.made);
        self.leaves.sort_by_key(|l| l.leaf.b);
        for (s, _) in &a.seated {
            if let Some(seat) = joined.remove(s) {
                self.seats.insert(*s, seat);
            }
        }
        for s in &a.removed {
            self.held.remove(s);
            self.seats.remove(s);
            // Out of the room: a voice room's roster is who is in it (gk/voice.rs `room_roster`)
            if let MemberId::Conn(u) = s.m {
                self.roster.retain(|r| *r != u);
            }
        }
        for (s, n) in a.held {
            self.held.insert(s, n);
        }
        self.rolls = a.rolls;
        if h.kind.sets_keyholders() {
            self.kh = Some(a.header.clone());
        }
        self.head = Some(a.header);
    }

    /// The relay's `EpochDue` for `d` (gk/group.rs `send_due`), whole.
    fn piece(&self, kind: u8, d: &Due, pairs: Vec<EndorsedPair>) -> DuePiece {
        let held: Vec<(gk::GkSeat, u32)> = match &self.head {
            Some(h) => {
                let s = h.header().seed;
                self.held
                    .iter()
                    .filter(|(_, n)| **n < s)
                    .map(|(seat, n)| ((*seat).into(), *n))
                    .collect()
            }
            None => vec![],
        };
        DuePiece {
            kind,
            parent: self.head.as_ref().map_or([0; 32], SignedHeader::d),
            deadline_ms: 0,
            keyring_at: self
                .head
                .as_ref()
                .map_or((0, 0), |h| (h.header().epoch, h.header().join)),
            joins: d.joiners.iter().map(joiner_in).collect(),
            exits: d
                .exits
                .iter()
                .map(|x| gk::ExitIn {
                    seq: x.seq,
                    seat: x.seat.into(),
                    b: x.b,
                })
                .collect(),
            exits_upto: d.exits_upto,
            promote: d.candidate.as_ref().map(|c| gk::Candidate {
                m: c.m.into(),
                ik: c.ik,
                pair: (&c.pair).into(),
            }),
            remove: d.remove.map(Into::into),
            gated: d.gated,
            roll_due: false,
            seed_seats: vec![],
            finish: held.is_empty(),
            pairs,
            held,
        }
    }

    /// `EpochLists` for `versions`, in frames of `LISTS_PER_FRAME`.
    fn lists(&self, gen: [u8; 16], versions: &[(u64, u64)]) -> Vec<ServerMessage> {
        let lists: Vec<gk::ListIn> = versions
            .iter()
            .filter_map(|&(b, v)| {
                let i = self.leaves.binary_search_by_key(&b, |l| l.leaf.b).ok()?;
                let l = &self.leaves[i];
                (l.leaf.v == v).then(|| gk::ListIn {
                    b,
                    v,
                    seats: l
                        .seats
                        .iter()
                        .map(|s| gk::ListSeat {
                            seat: (*s).into(),
                            dh: self
                                .seats
                                .get(s)
                                .map(|x| x.pair.dh.clone())
                                .unwrap_or_default(),
                        })
                        .collect(),
                })
            })
            .collect();
        let n = lists.len().div_ceil(gk::LISTS_PER_FRAME).max(1);
        let mut frames = Vec::with_capacity(n);
        let mut it = lists.into_iter();
        for i in 0..n {
            let chunk: Vec<gk::ListIn> = it.by_ref().take(gk::LISTS_PER_FRAME).collect();
            frames.push(ServerMessage::EpochLists {
                group: self.id.clone(),
                gen,
                lists: chunk,
                more: i + 1 < n,
            });
        }
        frames
    }
}

fn joiner_in(j: &Joiner) -> gk::Joiner {
    gk::Joiner {
        seat: j.seat.into(),
        ik: j.ik,
        keys: (&Pair {
            keys: j.keys.clone(),
            endorsement: j.endorsement.clone(),
        })
            .into(),
        returning: j.returning,
    }
}

fn size<T: Serialize>(x: &T) -> usize {
    postcard::experimental::serialized_size(x).unwrap_or(usize::MAX)
}

/// Each list item of `items` into the part it fits, as the relay cuts a due (1e).
fn spread<T: Serialize>(
    parts: &mut Vec<DuePiece>,
    used: &mut usize,
    items: Vec<T>,
    list: fn(&mut DuePiece) -> &mut Vec<T>,
) {
    for x in items {
        let n = size(&x);
        if *used + n > PART_MAX {
            parts.push(DuePiece::default());
            *used = size(&DuePiece::default());
        }
        list(parts.last_mut().expect("a part")).push(x);
        *used += n;
    }
}

/// `p` as the relay sends it: parts of at most `PIECE_MAX_BYTES`, the scalars in the first.
fn due_frames(group: &str, due: u64, mut p: DuePiece) -> Vec<ServerMessage> {
    let joins = std::mem::take(&mut p.joins);
    let exits = std::mem::take(&mut p.exits);
    let seed_seats = std::mem::take(&mut p.seed_seats);
    let pairs = std::mem::take(&mut p.pairs);
    let held = std::mem::take(&mut p.held);
    let mut used = size(&p);
    let mut parts = vec![p];
    spread(&mut parts, &mut used, joins, |p| &mut p.joins);
    spread(&mut parts, &mut used, exits, |p| &mut p.exits);
    spread(&mut parts, &mut used, seed_seats, |p| &mut p.seed_seats);
    spread(&mut parts, &mut used, pairs, |p| &mut p.pairs);
    spread(&mut parts, &mut used, held, |p| &mut p.held);
    let n = parts.len();
    parts
        .into_iter()
        .enumerate()
        .map(|(i, piece)| ServerMessage::EpochDue {
            group: group.to_string(),
            due,
            part: i as u16,
            last: i + 1 == n,
            piece: Box::new(piece),
        })
        .collect()
}

// ── The bench ─────────────────────────────────────────────────────────────

/// The bench's groups.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Which {
    /// A stored text group of accounts (`c:`): its Joins make each new seat a row too.
    Kept,
    /// A memory-only text group of guests (`r:`, a relay without accounts).
    Memory,
    Voice,
}

impl Which {
    fn kind(self) -> GroupKind {
        match self {
            Which::Voice => GroupKind::Voice,
            _ => GroupKind::Text,
        }
    }

    fn channel(self) -> u32 {
        match self {
            Which::Kept => 7,
            Which::Memory => 8,
            Which::Voice => 9,
        }
    }
}

struct Bench {
    kh: Kh,
    run: [u8; 16],
    /// Every member's identity and Kyber key: a joiner costs the keyholder the same whoever
    /// holds them, and the page makes 100k seats without 100k Kyber key pairs.
    member_ik: IdentityKeyPair,
    kem: Vec<u8>,
    next_member: u32,
    due: u64,
    rooms: [Option<Room>; 3],
}

impl Bench {
    fn new() -> Result<Bench, String> {
        let mut rng = voipc_crypto::rng();
        let identity = IdentityKeyPair::generate(&mut rng);
        let stores = SignalStores::new(&identity, 1);
        let ik = raw(&identity);
        let mut run = [0u8; 16];
        rng.fill_bytes(&mut run);
        let mut keying = GroupKeying::default();
        // A desktop: a browser declines a text group past 10 000 seats (BROWSER_MAX_SEATS),
        // and the platform changes nothing else in a build
        let out = keying.start(GkStart {
            on: true,
            run,
            relay_clock: now_millis() / 1000,
            platform: Platform::Desktop,
            help_hold_keys: true,
            user_id: USER,
            identity,
            account: None,
            seat_keys: None,
            local: None,
            visible: true,
        });
        let pair = out
            .send
            .into_iter()
            .find_map(|m| match m {
                ClientMessage::KeyholdVolunteer {
                    on: true,
                    pair: Some(p),
                    ..
                } => Some(p),
                _ => None,
            })
            .ok_or("the connection did not volunteer")?;
        Ok(Bench {
            kh: Kh {
                keying,
                stores,
                pins: MemoryPins::default(),
                ik,
                pair,
            },
            run,
            member_ik: IdentityKeyPair::generate(&mut rng),
            kem: SeatPair::generate().public().kem_bytes().into(),
            next_member: 0,
            due: 0,
            rooms: [None, None, None],
        })
    }

    fn room(&mut self, which: Which) -> Result<&mut Room, String> {
        self.rooms[which as usize]
            .as_mut()
            .ok_or_else(|| "no group yet: join first".into())
    }

    /// A member new to the group: an account seat (0x01) in the stored group, a guest's
    /// connection pair (0x02) in the others.
    fn member(&mut self, which: Which) -> (Joiner, Seat) {
        self.next_member += 1;
        let i = self.next_member;
        let (m, origin, n) = if which == Which::Kept {
            let mut a = [0xa0; 16];
            a[12..].copy_from_slice(&i.to_be_bytes());
            (MemberId::Account(a), Origin::VaultSeat, 1)
        } else {
            (MemberId::Conn(1000 + i), Origin::Connection, 0)
        };
        let mut rng = rand::rng();
        let keys = loop {
            let mut dh = [0u8; 33];
            dh[0] = 0x05;
            rng.fill_bytes(&mut dh[1..]);
            if let Ok(k) = SeatPublic::from_bytes(&self.kem, &dh) {
                break k;
            }
        };
        let endorsement =
            Endorsement::sign(&self.member_ik, origin, m, n, now_millis() / 1000, &keys)
                .expect("the origin names the member");
        let joiner = Joiner {
            seat: keys.seat(m),
            ik: raw(&self.member_ik),
            keys,
            endorsement,
            returning: false,
        };
        let mut pair = EndorsedPair::from(&Pair {
            keys: joiner.keys.clone(),
            endorsement: joiner.endorsement.clone(),
        });
        pair.kem = vec![];
        (
            joiner,
            Seat {
                pair,
                ik: raw(&self.member_ik),
            },
        )
    }

    /// The group tracked, and its Genesis built by this keyholder and taken.
    fn open(&mut self, which: Which, budget: f64) -> Result<Value, String> {
        let (kind, channel) = (which.kind(), which.channel());
        let log = if which == Which::Kept { TEXT_ID } else { "" };
        let id = group_id(kind, log, &self.run, channel);
        self.kh.keying.track(
            GkTrack {
                channel_id: channel,
                group: id.clone(),
                kind,
                anonymous: false,
                hide_members: false,
                viewer_admin: false,
                keeps_history: which == Which::Kept,
            },
            VaultFloor::None,
        );
        let own = self.kh.own()?;
        let seat = own.keys.seat(MemberId::Conn(USER));
        if which == Which::Voice {
            // The room's seats as the relay tells them: a Genesis names only a keyholder in it
            self.kh.call(&ServerMessage::VoiceSeats {
                channel_id: channel,
                group: id.clone(),
                part: 0,
                last: true,
                piece: VoiceSeatsPiece {
                    seats: vec![(USER, seat.into())],
                    gone: vec![],
                    whole: true,
                },
            })?;
        }
        let room = Room::new(kind, id);
        let joiner = Joiner {
            seat,
            ik: self.kh.ik,
            keys: own.keys.clone(),
            endorsement: own.endorsement.clone(),
            returning: false,
        };
        let due = Due {
            joiners: vec![joiner],
            volunteer: Some(Candidate {
                m: MemberId::Conn(USER),
                ik: self.kh.ik,
                pair: own,
            }),
            ..Due::of(DueKind::Genesis, false)
        };
        let piece = room.piece(gk::due::GENESIS, &due, vec![]);
        let mut joined = HashMap::new();
        joined.insert(
            seat,
            Seat {
                pair: self.kh.pair.clone(),
                ik: self.kh.ik,
            },
        );
        self.rooms[which as usize] = Some(room);
        self.run_due(
            which,
            "genesis",
            1,
            Some(&due),
            piece,
            joined,
            false,
            budget,
        )
    }

    fn join(&mut self, which: Which, n: u32, budget: f64) -> Result<Value, String> {
        let genesis = match self.rooms[which as usize] {
            Some(_) => None,
            None => Some(self.open(which, budget)?),
        };
        let mut joiners = Vec::with_capacity(n as usize);
        let mut joined = HashMap::new();
        for _ in 0..n.min(JOIN_BATCH_MAX as u32) {
            let (j, seat) = self.member(which);
            if let MemberId::Conn(u) = j.seat.m {
                self.room(which)?.roster.push(u);
            }
            joined.insert(j.seat, seat);
            joiners.push(j);
        }
        let room = self.room(which)?;
        let due = Due {
            joiners,
            ..Due::of(DueKind::Join, room.head()?.header().gated)
        };
        let piece = room.piece(gk::due::JOIN, &due, vec![]);
        let op = match which {
            Which::Kept => "join",
            Which::Memory => "mjoin",
            Which::Voice => "voice",
        };
        let mut r = self.run_due(which, op, n, Some(&due), piece, joined, false, budget)?;
        if let Some(g) = genesis {
            r["genesis"] = g;
        }
        Ok(r)
    }

    /// An opening carrying `n` exits of seats drawn at random (the keyholders' own stay).
    fn exits(&mut self, which: Which, n: u32, cold: bool, budget: f64) -> Result<Value, String> {
        let room = self.room(which)?;
        let own = MemberId::Conn(USER);
        let second = room.second.map(|(_, s)| s);
        let mut all: Vec<(SeatRef, u64)> = room
            .leaves
            .iter()
            .flat_map(|l| {
                l.seats
                    .iter()
                    .filter(|s| s.m != own && Some(**s) != second)
                    .map(move |s| (*s, l.leaf.b))
            })
            .collect();
        let n = (n as usize).min(all.len());
        let mut rng = rand::rng();
        for i in 0..n {
            let j = rng.random_range(i..all.len());
            all.swap(i, j);
        }
        all.truncate(n);
        self.exits_of(which, all, cold, budget)
    }

    /// An opening carrying the exits of `seats`, each with its bucket.
    fn exits_of(
        &mut self,
        which: Which,
        seats: Vec<(SeatRef, u64)>,
        cold: bool,
        budget: f64,
    ) -> Result<Value, String> {
        let pair = self.kh.pair.clone();
        let room = self.room(which)?;
        let n = seats.len();
        let mut exits = Vec::with_capacity(n);
        for (seat, b) in seats {
            room.seq += 1;
            exits.push(Exit {
                seq: room.seq,
                seat,
                b,
            });
        }
        let due = Due {
            exits,
            exits_upto: room.seq,
            ..Due::of(DueKind::Exits, room.head()?.header().gated)
        };
        let piece = room.piece(gk::due::EXITS, &due, vec![pair]);
        let op = match (which, cold) {
            (Which::Kept, false) => "exits",
            (Which::Kept, true) => "cexits",
            (Which::Memory, _) => "mexits",
            (Which::Voice, _) => "vexits",
        };
        self.run_due(
            which,
            op,
            n as u32,
            Some(&due),
            piece,
            HashMap::new(),
            cold,
            budget,
        )
    }

    fn refresh(&mut self, cold: bool, budget: f64) -> Result<Value, String> {
        let pair = self.kh.pair.clone();
        let room = self.room(Which::Kept)?;
        let due = Due::of(DueKind::Refresh, room.head()?.header().gated);
        let piece = room.piece(gk::due::REFRESH, &due, vec![pair]);
        let op = if cold { "crefresh" } else { "refresh" };
        self.run_due(
            Which::Kept,
            op,
            0,
            Some(&due),
            piece,
            HashMap::new(),
            cold,
            budget,
        )
    }

    /// A second keyholder for the voice room: the relay's Add of its lowest seated member
    /// (plan C5). The room's seats go to the duty first (`VoiceSeats`, whole), as a member
    /// takes a new keyholder only from the lowest of its roster.
    fn promote(&mut self, budget: f64) -> Result<Value, String> {
        let (kem, own_pair) = (self.kem.clone(), self.kh.pair.clone());
        let room = self.room(Which::Voice)?;
        if room.second.is_some() {
            return Err("the room has its second keyholder: vremove first".into());
        }
        let mut seats: Vec<(u32, SeatRef)> = room
            .seats
            .keys()
            .filter_map(|s| match s.m {
                MemberId::Conn(u) => Some((u, *s)),
                MemberId::Account(_) => None,
            })
            .collect();
        seats.sort_unstable_by_key(|(u, _)| *u);
        let (_, seat) = *seats
            .iter()
            .find(|(u, _)| *u != USER)
            .ok_or("nobody to promote: voice first")?;
        let s = &room.seats[&seat];
        let mut ep = s.pair.clone();
        ep.kem = kem;
        let pair = wire::pair(&ep, seat.m.into()).map_err(|e| format!("its pair: {e:?}"))?;
        let by = HolderRef {
            m: seat.m,
            kx: ep.dh[1..].try_into().expect("33 bytes"),
        };
        let due = Due {
            candidate: Some(Candidate {
                m: seat.m,
                ik: s.ik,
                pair,
            }),
            ..Due::of(DueKind::Promote, room.head()?.header().gated)
        };
        let piece = room.piece(gk::due::PROMOTE, &due, vec![own_pair, ep]);
        room.second = Some((by, seat));
        let (channel_id, group) = (Which::Voice.channel(), room.id.clone());
        let parts: Vec<_> = seats.chunks(gk::VOICE_SEATS_PER_FRAME).collect();
        for (i, chunk) in parts.iter().enumerate() {
            self.kh.call(&ServerMessage::VoiceSeats {
                channel_id,
                group: group.clone(),
                part: i as u16,
                last: i + 1 == parts.len(),
                piece: VoiceSeatsPiece {
                    seats: chunk.iter().map(|(u, s)| (*u, (*s).into())).collect(),
                    gone: vec![],
                    whole: i == 0,
                },
            })?;
        }
        self.run_due(
            Which::Voice,
            "vpromote",
            1,
            Some(&due),
            piece,
            HashMap::new(),
            false,
            budget,
        )
    }

    /// The voice room's second keyholder leaves (plan C5): its leave closes the exit batch,
    /// and the duty is asked a Remove carrying it, which rolls the seed. The relay sends the
    /// keys of every seat the commit may owe a seed welcome (gk/voice.rs `room_seed_seats`);
    /// here every remaining seat's, and the build welcomes those the rules want.
    fn remove(&mut self, cold: bool, budget: f64) -> Result<Value, String> {
        let (kem, own_pair) = (self.kem.clone(), self.kh.pair.clone());
        let room = self.room(Which::Voice)?;
        let (by, seat) = room
            .second
            .take()
            .ok_or("no second keyholder: vpromote first")?;
        let b = room
            .leaves
            .iter()
            .find(|l| l.seats.contains(&seat))
            .ok_or("the keyholder is not seated")?
            .leaf
            .b;
        room.seq += 1;
        let due = Due {
            exits: vec![Exit {
                seq: room.seq,
                seat,
                b,
            }],
            exits_upto: room.seq,
            remove: Some(by),
            ..Due::of(DueKind::Remove, room.head()?.header().gated)
        };
        let keys = |s: &Seat| {
            let mut keys = s.pair.clone();
            if keys.kem.is_empty() {
                keys.kem = kem.clone();
            }
            keys
        };
        let mut piece = room.piece(
            gk::due::REMOVE,
            &due,
            vec![own_pair, keys(&room.seats[&seat])],
        );
        piece.seed_seats = room
            .seats
            .iter()
            .filter(|(s, _)| **s != seat)
            .map(|(s, x)| gk::SeedSeat {
                seat: (*s).into(),
                ik: x.ik,
                keys: keys(x),
            })
            .collect();
        self.run_due(
            Which::Voice,
            if cold { "cvremove" } else { "vremove" },
            1,
            Some(&due),
            piece,
            HashMap::new(),
            cold,
            budget,
        )
    }

    /// A seed-welcome page of `n` seats under the head's seed (a running roll's page).
    fn seed_page(&mut self, n: u32, budget: f64) -> Result<Value, String> {
        let kem = self.kem.clone();
        let room = self.room(Which::Kept)?;
        let own = MemberId::Conn(USER);
        let seed_seats: Vec<gk::SeedSeat> = room
            .seats
            .iter()
            .filter(|(s, _)| s.m != own)
            .take(n as usize)
            .map(|(s, seat)| {
                let mut keys = seat.pair.clone();
                if keys.kem.is_empty() {
                    keys.kem = kem.clone();
                }
                gk::SeedSeat {
                    seat: (*s).into(),
                    ik: seat.ik,
                    keys,
                }
            })
            .collect();
        let n = seed_seats.len() as u32;
        let mut piece = room.piece(
            gk::due::SEED_WELCOMES,
            &Due::of(DueKind::Join, false),
            vec![],
        );
        piece.seed_seats = seed_seats;
        self.run_due(
            Which::Kept,
            "seed",
            n,
            None,
            piece,
            HashMap::new(),
            false,
            budget,
        )
    }

    /// One due, from the relay's ask to the header taken: every part timed as the page pays
    /// for it. `due` is the relay's for a commit, `None` for a seed-welcome page.
    ///
    /// `cold`: built with no row bases, as by a keyholder new to the group or back after a
    /// reload. A job holds the group's bases from its first step to its end (holder.rs
    /// `Lease`), so the host takes one step of the due's job (as a page midway through a
    /// stepped build does) and the relay asks the due again: the duty's second job finds no
    /// bases, and that one is timed. The first then stops at its next step (its due went)
    /// and its bases go home for the dues after. The page pays the due's frames and lists
    /// once, the first time.
    #[allow(clippy::too_many_arguments)]
    fn run_due(
        &mut self,
        which: Which,
        op: &str,
        n: u32,
        due: Option<&Due>,
        piece: DuePiece,
        joined: HashMap<SeatRef, Seat>,
        cold: bool,
        budget_ms: f64,
    ) -> Result<Value, String> {
        self.due += 2;
        let (id, again) = (self.due - 1, self.due);
        let Bench { kh, rooms, .. } = self;
        let room = rooms[which as usize].as_mut().ok_or("no group")?;
        let group = room.id.clone();
        let before = room.seats_now();
        let mut cost = Cost::default();
        let frames = due_frames(&group, id, piece.clone());
        let lists = until_ready(kh, room, frames, &mut cost, op)?;
        let mut held = None;
        if cold {
            let mut first = kh.keying.take_build().ok_or("no job")?;
            if first.step(std::time::Duration::ZERO).is_some() {
                return Err(format!(
                    "{op}: the build ended in one unit: nothing to time cold"
                ));
            }
            held = Some(first);
            until_ready(
                kh,
                room,
                due_frames(&group, again, piece),
                &mut Cost::default(),
                op,
            )?;
        }
        let mut job = kh.keying.take_build().ok_or("no job")?;
        let b = loop {
            let pages = clock::pages();
            let units = job.units();
            let at = clock::ms();
            let step = job.step(std::time::Duration::from_secs_f64(budget_ms / 1000.0));
            let ms = clock::ms() - at;
            if ms > cost.step_max_ms {
                cost.step_max_at = (cost.steps, job.units() - units);
            }
            cost.steps += 1;
            cost.build_ms += ms;
            cost.step_max_ms = cost.step_max_ms.max(ms);
            if clock::pages() > pages {
                cost.grew_steps += 1;
                cost.grew_max_ms = cost.grew_max_ms.max(ms);
            } else {
                cost.flat_max_ms = cost.flat_max_ms.max(ms);
            }
            if let Some(b) = step {
                break b;
            }
        };
        cost.units = job.units();
        let at = clock::ms();
        let out = kh.keying.built(
            b,
            GkCtx {
                pins: &mut kh.pins,
                now: now_millis(),
            },
        );
        to_page(&out.send)?;
        cost.built_ms = clock::ms() - at;
        if let Some(why) = out.send.iter().find_map(|m| match m {
            ClientMessage::EpochDecline { detail, .. } => Some(detail.clone()),
            _ => None,
        }) {
            return Err(format!("{op}: the build failed: {why}"));
        }
        let mut parts = Vec::new();
        let (mut frames, mut bytes, mut seed_welcomes) = (0, 0, 0);
        loop {
            // `gkNextFrame`: the next upload, as postcard bytes
            let at = clock::ms();
            let Some(m) = kh.keying.next_frame(now_millis(), false) else {
                break;
            };
            let wire = postcard::to_allocvec(&m).map_err(|e| format!("{op}: {e}"))?;
            cost.upload(clock::ms() - at);
            frames += 1;
            bytes += wire.len();
            match m {
                ClientMessage::EpochCommit { piece, .. } => parts.push(piece),
                ClientMessage::EpochWelcomes { welcomes, .. } => seed_welcomes += welcomes.len(),
                _ => {}
            }
        }
        let mut r = json!({
            "op": op,
            "n": n,
            "cold": cold,
            "seats_before": before,
            "frames": frames,
            "bytes": bytes,
            "lists": lists,
        });
        if let Some(due) = due {
            let whole = gk::join_commit(parts).map_err(|e| format!("{op}: {e:?}"))?;
            let c = Commit::try_from(whole).map_err(|e| format!("{op}: {e:?}"))?;
            let rows: usize = c.rows.iter().map(|x| x.rows.len() / 60).sum();
            let (welcomes, seeds) = (c.welcomes.len(), c.seed_welcomes.len());
            // The validator the duty also runs on its own commit, inside its build (`Task::check`)
            let at = clock::ms();
            let a = room.check(due, kh.by(), &c)?;
            r["check_ms"] = r3(clock::ms() - at).into();
            let refused = a.refused.len();
            room.take(a, joined);
            let head = room.head()?;
            let push = ServerMessage::EpochIn {
                group: group.clone(),
                part: 0,
                last: true,
                piece: Box::new(InPiece {
                    chain: vec![gk::HeaderIn {
                        body: head.body().to_vec(),
                        sig: head.sig().to_vec(),
                    }],
                    pushed: true,
                    ..InPiece::default()
                }),
            };
            let (_, ms) = kh.call(&push)?;
            cost.take_ms = ms;
            let h = room.head()?.header();
            r["seats_after"] = h.seats.into();
            r["buckets"] = h.buckets.into();
            r["seed"] = h.seed.into();
            r["welcomes"] = welcomes.into();
            r["rows"] = rows.into();
            r["seed_welcomes"] = seeds.into();
            r["refused"] = refused.into();
        } else {
            r["seats_after"] = before.into();
            r["seed_welcomes"] = seed_welcomes.into();
        }
        if let Some(mut job) = held {
            let b = job
                .step(std::time::Duration::MAX)
                .ok_or("the held job had ended")?;
            let c = GkCtx {
                pins: &mut kh.pins,
                now: now_millis(),
            };
            kh.keying.built(b, c);
        }
        if let (Value::Object(r), Value::Object(c)) = (&mut r, cost.json()) {
            r.extend(c);
        }
        Ok(r)
    }
}

/// The due's `frames` to the duty, and the lists it asks answered, until its job waits for
/// the host: how many lists it asked.
fn until_ready(
    kh: &mut Kh,
    room: &Room,
    frames: Vec<ServerMessage>,
    cost: &mut Cost,
    op: &str,
) -> Result<usize, String> {
    let mut ready = false;
    let mut said = Vec::new();
    for msg in frames {
        let out = kh.frame(&msg, cost)?;
        ready |= out.build_ready;
        said.extend(out.send);
    }
    let mut lists = 0;
    while !ready {
        let mut asked = false;
        for m in std::mem::take(&mut said) {
            match m {
                ClientMessage::EpochDecline { why, detail, .. } => {
                    return Err(format!(
                        "{op}: declined ({}): {detail}",
                        gk::decline::name(why)
                    ))
                }
                ClientMessage::KeyringWanted { .. } => {
                    return Err(format!("{op}: the keyholder holds no keyring at the head"))
                }
                ClientMessage::EpochListsWanted { gen, versions, .. } => {
                    asked = true;
                    lists += versions.len();
                    for msg in room.lists(gen, &versions) {
                        let out = kh.frame(&msg, cost)?;
                        ready |= out.build_ready;
                        said.extend(out.send);
                    }
                }
                _ => {}
            }
        }
        if !asked && !ready {
            return Err(format!("{op}: the duty took no job for the due"));
        }
    }
    Ok(lists)
}

fn raw(ik: &IdentityKeyPair) -> [u8; 32] {
    ik.public_key()
        .public_key_bytes()
        .try_into()
        .expect("an X25519 key is 32 bytes")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(op: &str, arg: u32) -> Value {
        step(op, arg, 2.0).unwrap_or_else(|e| panic!("{op} {arg}: {e}"))
    }

    #[test]
    fn without_the_build_flag_the_export_says_so_and_runs_nothing() {
        if !ON {
            assert!(run("join", 1, 2.0).unwrap_err().contains("VOIPC_GK_BENCH"));
        }
    }

    #[test]
    fn a_primitive_is_timed_in_batches_a_coarse_clock_cannot_round_away() {
        // A call takes 7 µs; the clock steps 20 µs (Firefox's), as `performance.now()` ms
        let t = std::cell::Cell::new(0.0f64);
        let now = || (t.get() / 20.0).floor() * 20.0 / 1000.0;
        let us = per_call_us(51, now, || t.set(t.get() + 7.0));
        assert!((us - 7.0).abs() < 0.1, "{us} µs a call");
    }

    #[test]
    fn a_guest_who_left_the_room_is_off_its_roster_so_the_next_lowest_may_hold_keys() {
        ok("voice", 6);
        // The three lowest guests leave: the fourth is the lowest left, and the relay's
        // roster (the 4 lowest of which a new keyholder must be in) no longer names them
        let low: Vec<(SeatRef, u64)> = BENCH.with(|b| {
            let b = b.borrow();
            let room = b.as_ref().unwrap().rooms[Which::Voice as usize]
                .as_ref()
                .unwrap();
            let mut guests: Vec<(u32, SeatRef, u64)> = room
                .leaves
                .iter()
                .flat_map(|l| l.seats.iter().map(move |s| (s, l.leaf.b)))
                .filter_map(|(s, b)| match s.m {
                    MemberId::Conn(u) if u != USER => Some((u, *s, b)),
                    _ => None,
                })
                .collect();
            guests.sort_unstable_by_key(|g| g.0);
            guests.iter().take(3).map(|g| (g.1, g.2)).collect()
        });
        let out = BENCH.with(|b| {
            let mut b = b.borrow_mut();
            b.as_mut().unwrap().exits_of(Which::Voice, low, false, 2.0)
        });
        assert_eq!(out.unwrap()["seats_after"], 4);
        assert_eq!(ok("vpromote", 0)["seats_after"], 4);
        assert_eq!(ok("vremove", 0)["seats_after"], 3);
    }

    #[test]
    fn every_step_runs_the_duty_s_own_build_and_the_relay_takes_its_commit() {
        let g = ok("join", 200);
        assert_eq!(g["genesis"]["seats_after"], 1, "the keyholder's own seat");
        assert_eq!(g["seats_after"], 201);
        assert_eq!(g["welcomes"], 200);
        assert_eq!(g["refused"], 0);
        assert!(g["steps"].as_u64().unwrap() >= 1);
        // More than one bucket, so an opening has lists to ask for
        let j = ok("join", 256);
        assert_eq!(j["seats_after"], 457);
        let x = ok("exits", 30);
        assert_eq!(x["seats_after"], 427);
        assert!(x["lists"].as_u64().unwrap() > 0, "{x}");
        assert!(x["rows"].as_u64().unwrap() > 0, "{x}");
        // Timed as the page pays: the frames from their bytes, the uploads encoded
        assert!(x["lock_calls"].as_u64().unwrap() > 1, "{x}");
        assert!(x["frames"].as_u64().unwrap() > 0, "{x}");
        assert!(x["upload_ms"].as_f64().unwrap() > 0.0, "{x}");
        let r = ok("refresh", 0);
        assert_eq!(r["seats_after"], 427);
        // Built again with no row bases: the same commits, and the relay takes them
        let cr = ok("crefresh", 0);
        assert_eq!(cr["cold"], true);
        assert_eq!(cr["seats_after"], 427);
        assert!(cr["rows"].as_u64().unwrap() > 0, "{cr}");
        let cx = ok("cexits", 30);
        assert_eq!(cx["cold"], true);
        assert_eq!(cx["seats_after"], 397);
        assert!(cx["rows"].as_u64().unwrap() > 0, "{cx}");
        assert!(cx["lists"].as_u64().unwrap() > 0, "{cx}");
        // and the warm bases came home: the dues after build on as before
        assert_eq!(ok("exits", 7)["seats_after"], 390);
        let s = ok("seed", 40);
        assert_eq!(s["seed_welcomes"], 40);
        // A Join after them all still builds on the head the duty holds
        assert_eq!(ok("join", 3)["seats_after"], 393);
        // At a zero budget, a step a unit: the last step ends the job with none
        let z = step("exits", 3, 0.0).unwrap();
        assert_eq!(z["seats_after"], 390);
        let units = z["units"].as_u64().unwrap();
        assert!(units > z["rows"].as_u64().unwrap(), "{z}");
        assert_eq!(z["steps"].as_u64(), Some(units + 1), "{z}");
        // A memory group's Joins make no rows: its first opening makes them all
        let m = ok("mjoin", 130);
        assert_eq!(m["rows"], 0);
        assert_eq!(m["seats_after"], 131);
        let mx = ok("mexits", 10);
        assert_eq!(mx["seats_after"], 121);
        assert!(mx["rows"].as_u64().unwrap() > 0, "{mx}");
        let v = ok("voice", 5);
        assert_eq!(v["genesis"]["seats_after"], 1);
        assert_eq!(v["seats_after"], 6);
        assert_eq!(ok("voice", 1)["seats_after"], 7);
        assert_eq!(ok("vexits", 2)["seats_after"], 5);
        // A second keyholder, and its leave: a Remove carrying its exit rolls the seed
        let seed = ok("voice", 1)["seed"].as_u64().unwrap();
        assert_eq!(ok("vpromote", 0)["seats_after"], 6);
        let rm = ok("vremove", 0);
        assert_eq!(rm["seats_after"], 5, "{rm}");
        assert_eq!(rm["seed"].as_u64().unwrap(), seed + 1, "{rm}");
        assert_eq!(rm["seed_welcomes"], 0, "no seat behind: {rm}");
        assert!(step("vremove", 0, 2.0).is_err(), "one Remove a keyholder");
        assert_eq!(ok("vpromote", 0)["seats_after"], 5);
        let crm = ok("cvremove", 0);
        assert_eq!(crm["cold"], true);
        assert_eq!(crm["seats_after"], 4);
        assert_eq!(crm["seed"].as_u64().unwrap(), seed + 2, "{crm}");
        assert_eq!(
            crm["seed_welcomes"], 4,
            "every seat behind the last roll: {crm}"
        );
        assert_eq!(ok("voice", 1)["seats_after"], 5);
        let p = ok("prim", 3);
        assert!(p["kyber_encaps_us"].as_f64().unwrap() > 0.0);
        ok("reset", 0);
        assert_eq!(ok("join", 1)["genesis"]["seats_after"], 1, "a new group");
    }
}
