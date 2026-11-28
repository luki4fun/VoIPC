//! Commit builders (§5.1–§5.6, plan 2a): what a keyholder makes for each
//! due, from the keyring it holds and the lists the relay sent. Each builder
//! gives a `Built`: the `Commit` the validator (`commit::validate`) takes,
//! and what the keyholder keeps once the relay takes it (the new keyring,
//! `CK`, `KRK`, and every version it made, for a rebase).
//!
//! - `build_genesis` / `build_regenesis`: a new start, its signer's own
//!   bucket and a new seed, `KRK` and `CK` (§5.1, §4.3).
//! - `build_join`: new buckets of at most 62 for the joiners, a welcome to
//!   each (a row for a returning seat, and in a stored group a row to every
//!   new account seat, open choice 24), seals of the epoch's `CK` to the new
//!   versions, and a keyring delta.
//! - `build_opening`: a Fresh, KeyholdersAdd, KeyholdersRemove or
//!   KeyholdersReplace: exits, merges and repacks (`plan_opening`, §5.3),
//!   the hourly re-key and refresh slice (§5.5), ratchets at a promotion,
//!   seed rolls (§5.6), a new `CK` always, and a new `KRK` where the set
//!   changes.
//! - `build_seed_welcomes`: a seed-welcome page, outside any commit.
//!
//! A rebase (§5.6) is the same builder over the new head with the stale
//! attempt as `reuse`: a version is reused, id and `BK`, only in the same
//! generation, where the winner did not touch its bucket, it is no ratchet,
//! its seats are the same and the winner did not roll the seed. Its rows
//! are reused only where made under the same seeds: an attempt that starts
//! a roll draws its new seed anew, so rows under it are made again. `CK` is
//! drawn anew every attempt.
//!
//! Rows come from `RowBase::keyholder_side_dh` over the list's `dh`, one
//! X25519 per seat and seed (`RowBases`). A welcome shares that agreement
//! (`ss_k`, §3.2) with the seat's row base instead of making it twice.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};

use libsignal_protocol::{IdentityKeyPair, KeyPair};
use zeroize::Zeroizing;

use super::commit::{
    list_order, Candidate, Commit, Exit, HolderRef, Joiner, KrkOut, Make, Refused, RowsOut,
    SealOut, SeedWelcomeOut, VersionOut, WelcomeOut,
};
use super::ctx::{welcome_ctx, Epoch, Group, GroupKind, SeatRef, Version, WelcomeKind};
use super::derive::{confirm, member_secret, seal, RowBase};
use super::header::{
    keyholder_set_digest, names_hash, Added, AddedSeat, HeaderV1, Keyholder, Kind, Removed,
    SignedHeader,
};
use super::keyring::{
    keyring_hash_next, keyring_hash_start, seal_base, seal_delta, Keyring, KeyringBase,
    KeyringBucket, KeyringDelta,
};
use super::keys::{agree, tag, Me, SeatPublic, Them};
use super::merkle::{bucket_root, list_digest, seat_dh, Leaf, Pool, Via, BUCKET_SEATS};
use super::rules::{behind_ok, Refusal, SeedRolls};
use super::timers::{BUCKET_AGE_MAX_SECS, JOIN_BATCH_MAX, REFRESH_SLICE};
use super::welcome::{keyring_welcome, seed_welcome, Drawn};
use super::{GkError, ROW_BYTES};

/// A bucket under this many seats is small (§5.3, as `sync/chains.rs`).
pub const SMALL_SEATS: usize = 16;
/// Once a pool has this many small buckets, all of them merge.
pub const SMALL_BUCKETS: usize = 16;

const FULL: usize = BUCKET_SEATS as usize;

/// Why a builder made nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BuildError {
    /// A key or value would not make or check: a list that is not its
    /// digest's, a seat whose keys are not its tags', a key of low order.
    Key(GkError),
    /// The header would not be one a member takes.
    Header(Refusal),
    /// What the due asks, this keyholder may not sign (it declines).
    Refuse(&'static str),
    /// The due's candidate fails a check only the build can make (it declines `CANDIDATE`,
    /// which counts toward no removal of this keyholder).
    Candidate(&'static str),
}

impl From<GkError> for BuildError {
    fn from(e: GkError) -> BuildError {
        BuildError::Key(e)
    }
}

impl From<Refusal> for BuildError {
    fn from(r: Refusal) -> BuildError {
        BuildError::Header(r)
    }
}

/// One seat of a list as the relay sends it, with its X25519 public key
/// (33 bytes): all a keyholder that did not seat it needs for a row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListSeat {
    pub seat: SeatRef,
    pub dh: Vec<u8>,
}

/// The lists a keyholder fetched (`EpochListsWanted`), by version.
pub type Lists = HashMap<Version, Vec<ListSeat>>;

/// The row bases a keyholder keeps for one group: one X25519 per seat and
/// seed, per keyholder pair (a Replace's new pair makes its own).
#[derive(Default)]
pub struct RowBases {
    map: HashMap<([u8; 16], [u8; 8], SeatRef, u32), RowBase>,
    /// Which draw of each seed number the kept bases were made under, by
    /// `tag` of the seed: a lost attempt that rolled drew its own.
    seeds: HashMap<([u8; 16], u32), [u8; 8]>,
}

impl RowBases {
    pub fn new() -> RowBases {
        RowBases::default()
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Drops the row bases under seeds below `floor`: the keyring dropped
    /// those seeds.
    pub fn forget_below(&mut self, floor: u32) {
        self.map.retain(|k, _| k.3 >= floor);
        self.seeds.retain(|k, _| k.1 >= floor);
    }

    /// Ties seed number `s` of `g`'s generation to `seed` before a build
    /// uses it: bases kept under another draw of `s` are dropped.
    fn bind(&mut self, g: &Group, s: u32, seed: &[u8; 32]) {
        let gen = g.gen();
        let print = tag(seed);
        if self.seeds.insert((gen, s), print) != Some(print) {
            self.map.retain(|k, _| (k.0, k.3) != (gen, s));
        }
    }

    fn key(g: &Group, me: &Me, seat: &SeatRef, s: u32) -> ([u8; 16], [u8; 8], SeatRef, u32) {
        (g.gen(), me.holder_id().tag_kx, *seat, s)
    }

    /// The row base to `seat` under `s`, made from its list `dh` if not kept.
    fn base(
        &mut self,
        g: &Group,
        s: u32,
        me: &Me,
        seat: &SeatRef,
        dh: &[u8],
        s_m: &[u8; 32],
    ) -> Result<&RowBase, GkError> {
        match self.map.entry(RowBases::key(g, me, seat, s)) {
            Entry::Occupied(e) => Ok(e.into_mut()),
            Entry::Vacant(e) => Ok(e.insert(RowBase::keyholder_side_dh(
                g,
                s,
                me,
                &seat.m,
                &seat.tag_sx,
                dh,
                s_m,
            )?)),
        }
    }

    fn put(&mut self, g: &Group, s: u32, me: &Me, seat: &SeatRef, rb: RowBase) -> &RowBase {
        let key = RowBases::key(g, me, seat, s);
        self.map.entry(key).or_insert(rb)
    }
}

/// What a keyholder holds of a group at its head, to build on.
pub struct Holding<'a> {
    pub g: &'a Group,
    pub head: &'a SignedHeader,
    /// The keyholder header the head's `kh` names.
    pub kh: &'a SignedHeader,
    /// Taken under `head` (`take_keyring`).
    pub ring: &'a Keyring,
    pub krk: &'a [u8; 32],
    /// This keyholder's own pair, under its member id.
    pub me: Me<'a>,
    pub ik: &'a IdentityKeyPair,
    /// The lists of the versions the build touches, checked here against
    /// the keyring's digests.
    pub lists: &'a Lists,
    /// The newest seed each seat holds, as the relay said with the due.
    /// `Sync`, so a build in steps (`steps`) stays `Send`.
    pub held: &'a (dyn Fn(&SeatRef) -> Option<u32> + Sync),
    /// The rolls at `head`: `ring`'s own (`KeyringBase::rolls`), and a removal the
    /// relay says is due. What a new keyring seals carries on from these.
    pub rolls: SeedRolls,
    pub stored: bool,
}

/// One version a build made, with what a rebase may reuse.
#[derive(Clone, Debug)]
pub struct Made {
    pub bucket: KeyringBucket,
    pub seats: Vec<SeatRef>,
    /// The leaves it was made from: its bucket's version before, or the
    /// buckets a merge took. None for a Join's new bucket.
    pub from: Vec<Leaf>,
    pub rows: Option<RowsOut>,
    pub welcomes: Vec<WelcomeOut>,
}

/// A commit built, and what its keyholder keeps once the relay takes it.
pub struct Built {
    pub commit: Commit,
    pub header: SignedHeader,
    pub ck: Zeroizing<[u8; 32]>,
    pub krk: Zeroizing<[u8; 32]>,
    /// The keyring at the new head.
    pub ring: Keyring,
    pub made: Vec<Made>,
    /// The parent's `(seed, seed_floor)`: a rebase reuses nothing once the
    /// winner rolled, nor from another generation (`header`'s `gen`).
    pub parent_seeds: (u32, u32),
    /// A Join's newly sealed seats, kept unnamed until a later header
    /// descends from it (§5.2).
    pub sealed_to: Vec<SeatRef>,
}

fn random_u64() -> u64 {
    u64::from_le_bytes(crate::aead::random())
}

/// Ids a build draws: never one its keyring already has (§4.1).
struct Ids {
    b: HashSet<u64>,
    v: HashSet<u64>,
}

impl Ids {
    fn of(ring: Option<&Keyring>) -> Ids {
        let buckets = ring.map_or(&[][..], |r| &r.buckets[..]);
        Ids {
            b: buckets.iter().map(|k| k.b).collect(),
            v: buckets.iter().map(|k| k.v).collect(),
        }
    }

    fn bucket(&mut self) -> u64 {
        loop {
            let b = random_u64();
            if self.b.insert(b) {
                return b;
            }
        }
    }

    fn version(&mut self) -> u64 {
        loop {
            let v = random_u64();
            if self.v.insert(v) {
                return v;
            }
        }
    }
}

/// Whether a stale attempt was built in `head`'s generation on the same
/// seeds: else a rebase reuses nothing of it.
fn same_start(r: &Built, g: &Group, head: &HeaderV1) -> bool {
    r.header.header().gen == g.gen() && r.parent_seeds == (head.seed, head.seed_floor)
}

/// What a rebase may take over from its stale attempt: a version by rows
/// with exactly these seats in this pool, whose source leaves are all still
/// current, whose id the new head does not hold, and that replaces what it
/// replaced before (or is a new bucket still).
fn reusable<'r>(
    reuse: Option<&'r Built>,
    current: &HashSet<Leaf>,
    ring_b: &HashSet<u64>,
    ring_v: &HashSet<u64>,
    seats: &[SeatRef],
    pool: Pool,
    from: &[Leaf],
) -> Option<&'r Made> {
    reuse?.made.iter().find(|m| {
        m.bucket.via == Via::Row
            && m.bucket.pool == pool
            && m.seats == seats
            && m.from == from
            && m.from.iter().all(|f| current.contains(f))
            && !ring_v.contains(&m.bucket.v)
            && (m.from.iter().any(|f| f.b == m.bucket.b) || !ring_b.contains(&m.bucket.b))
    })
}

/// A seat welcome (§3.2) whose `ss_k`, the static X25519 between our `KX`
/// and the seat's `SX`, is already made: the same agreement its row base
/// takes, made once for both (plan part 10).
#[allow(clippy::too_many_arguments)]
fn seat_welcome_agreed(
    g: &Group,
    s: u32,
    at: Version,
    from: &Me,
    to: &Them,
    s_m: &[u8; 32],
    bk: &[u8; 32],
    ss_k: Zeroizing<Vec<u8>>,
) -> Result<Vec<u8>, GkError> {
    let mut rng = crate::rng();
    let (ss_q, ct_q) = to
        .keys
        .kem
        .encapsulate(&mut rng)
        .map_err(|_| GkError::Malformed)?;
    let eph = KeyPair::generate(&mut rng);
    let ss_x = agree(&eph.private_key, &to.keys.dh)?;
    let drawn = Drawn {
        ct_q,
        eph_pub: eph.public_key.serialize(),
        ss: [Zeroizing::new(ss_q.into_vec()), ss_x, ss_k],
    };
    let seat = to.keys.seat(to.m);
    let c = welcome_ctx(g, s, WelcomeKind::Seat { at, to: &seat }, &from.holder_id());
    let p = Zeroizing::new([&s_m[..], &bk[..]].concat());
    Ok(drawn.welcome(&drawn.kek(from, to, &c), &c, &p))
}

/// Every row to `seats` of version `at`, packed in list order, each under
/// the seed `seed_of` gives (which differ by at most one: `RowsOut.up`).
/// A step may stop after each row (its row base made, if not kept).
#[allow(clippy::too_many_arguments)]
async fn rows_to(
    g: &Group,
    at: Version,
    bk: &[u8; 32],
    seats: &[SeatRef],
    seed_of: &[u32],
    seeds: &[(u32, Zeroizing<[u8; 32]>)],
    dh: &HashMap<SeatRef, &[u8]>,
    me: &Me<'_>,
    cache: &mut RowBases,
) -> Result<RowsOut, BuildError> {
    let s = seed_of.iter().copied().min().unwrap_or(0);
    let mut up = 0u64;
    let mut rows = Vec::with_capacity(seats.len() * ROW_BYTES);
    for (i, (seat, &si)) in seats.iter().zip(seed_of).enumerate() {
        match si - s {
            0 => {}
            1 => up |= 1 << i,
            _ => {
                return Err(BuildError::Refuse(
                    "rows of one version span more than two seeds",
                ))
            }
        }
        let seed =
            seeds
                .iter()
                .find(|(n, _)| *n == si)
                .map(|(_, k)| k)
                .ok_or(BuildError::Refuse(
                    "a row under a seed the keyring does not hold",
                ))?;
        let s_m = member_secret(g, si, seed, seat);
        let d = dh
            .get(seat)
            .ok_or(BuildError::Refuse("a seat with no dh in its list"))?;
        rows.extend(cache.base(g, si, me, seat, d, &s_m)?.row(at, bk));
        steps::unit().await;
    }
    Ok(RowsOut {
        b: at.b,
        v: at.v,
        s,
        up,
        rows,
    })
}

/// New buckets for `joiners` (a Join, or a start's own seat): at most 62 a
/// bucket, accounts and connections apart, in list order. Each gets a
/// welcome, or a row when returning; every seat of a version gets a row
/// when one does, and in a stored group every account version does. A step
/// may stop after each seat's agreement and row, and after its welcome.
#[allow(clippy::too_many_arguments)]
async fn seat_joiners(
    g: &Group,
    s: u32,
    seed: &[u8; 32],
    me: &Me<'_>,
    joiners: &[&Joiner],
    stored: bool,
    now: u64,
    ids: &mut Ids,
    cache: &mut RowBases,
    reuse: Option<&Built>,
) -> Result<Vec<Made>, BuildError> {
    if joiners.len() > JOIN_BATCH_MAX {
        return Err(BuildError::Refuse("more than 256 joiners"));
    }
    let by_seat: HashMap<SeatRef, &Joiner> = joiners.iter().map(|j| (j.seat, *j)).collect();
    for j in joiners {
        if j.keys.seat(j.seat.m) != j.seat {
            return Err(GkError::Forged.into());
        }
    }
    let none = HashSet::new();
    let mut out = Vec::new();
    for pool in [Pool::Accounts, Pool::Conns] {
        let mut seats: Vec<SeatRef> = by_seat
            .keys()
            .filter(|s| Pool::of(&s.m) == pool)
            .copied()
            .collect();
        list_order(&mut seats);
        for chunk in seats.chunks(FULL) {
            if let Some(m) = reusable(reuse, &none, &ids.b, &ids.v, chunk, pool, &[]) {
                ids.b.insert(m.bucket.b);
                ids.v.insert(m.bucket.v);
                out.push(m.clone());
                continue;
            }
            let at = Version {
                b: ids.bucket(),
                v: ids.version(),
            };
            let bk = Zeroizing::new(crate::aead::random());
            let with_rows =
                (stored && pool == Pool::Accounts) || chunk.iter().any(|s| by_seat[s].returning);
            let mut welcomes = Vec::new();
            let mut rows = Vec::new();
            for seat in chunk {
                let j = by_seat[seat];
                let s_m = member_secret(g, s, seed, seat);
                let agreed = agree(&me.keys.dh.private_key, &j.keys.dh)?;
                if with_rows {
                    let rb = RowBase::keyholder_side_agreed(
                        g,
                        s,
                        me,
                        &seat.m,
                        &seat.tag_sx,
                        &j.keys.dh_bytes(),
                        &agreed,
                        &s_m,
                    )?;
                    rows.extend(cache.put(g, s, me, seat, rb).row(at, &bk));
                }
                if !j.returning {
                    steps::unit().await;
                    let to = Them {
                        m: seat.m,
                        keys: &j.keys,
                    };
                    let bytes = seat_welcome_agreed(g, s, at, me, &to, &s_m, &bk, agreed)?;
                    welcomes.push(WelcomeOut {
                        seat: *seat,
                        b: at.b,
                        v: at.v,
                        s,
                        bytes,
                    });
                }
                steps::unit().await;
            }
            out.push(Made {
                bucket: KeyringBucket {
                    b: at.b,
                    v: at.v,
                    pool,
                    seats: chunk.len() as u16,
                    list: list_digest(g, at, chunk, |s| seat_dh(&by_seat.get(s)?.keys.dh_bytes()))
                        .ok_or(GkError::Malformed)?,
                    via: Via::Row,
                    bk,
                    made: now,
                },
                seats: chunk.to_vec(),
                from: vec![],
                rows: with_rows.then_some(RowsOut {
                    b: at.b,
                    v: at.v,
                    s,
                    up: 0,
                    rows,
                }),
                welcomes,
            });
        }
    }
    Ok(out)
}

fn version_out(m: &Made, make: Make) -> VersionOut {
    VersionOut {
        b: m.bucket.b,
        v: m.bucket.v,
        pool: m.bucket.pool,
        make,
    }
}

/// The counts and root over a keyring's buckets, sorted by `b`.
fn counts(buckets: &[KeyringBucket]) -> Result<(u32, u32, u32, [u8; 32]), GkError> {
    let leaves: Vec<Leaf> = buckets.iter().map(KeyringBucket::leaf).collect();
    let seats = buckets.iter().map(|b| u32::from(b.seats)).sum();
    let conn = buckets
        .iter()
        .filter(|b| b.pool == Pool::Conns)
        .map(|b| u32::from(b.seats))
        .sum();
    Ok((seats, buckets.len() as u32, conn, bucket_root(&leaves)?))
}

fn seals(g: &Group, ep: &Epoch, ck: &[u8; 32], buckets: &[&KeyringBucket]) -> Vec<SealOut> {
    steps::whole(seals_in_steps(g, ep, ck, buckets))
}

/// `seals`, a step stopping after any seal.
async fn seals_in_steps(
    g: &Group,
    ep: &Epoch,
    ck: &[u8; 32],
    buckets: &[&KeyringBucket],
) -> Vec<SealOut> {
    let mut out = Vec::with_capacity(buckets.len());
    for kb in buckets {
        out.push(SealOut {
            b: kb.b,
            v: kb.v,
            bytes: seal(g, ep, kb.version(), &kb.bk, ck),
        });
        steps::unit().await;
    }
    out
}

fn names(gated: bool, added: Vec<AddedSeat>, removed: Vec<SeatRef>) -> (Added, Removed) {
    if gated {
        (Added::List(added), Removed::List(removed))
    } else {
        (
            Added::Count(added.len() as u32),
            Removed::Count(removed.len() as u32),
        )
    }
}

fn sign(
    mut h: HeaderV1,
    parent: Option<&SignedHeader>,
    ik: &IdentityKeyPair,
) -> Result<SignedHeader, BuildError> {
    h.canonicalize();
    h.names_hash = names_hash(parent.map(SignedHeader::header), &h);
    Ok(SignedHeader::sign(h, ik)?)
}

/// The raw `KX` of a pair, as entries carry it.
fn raw_kx(me: &Me) -> [u8; 32] {
    me.keys.dh.public_key.serialize()[1..]
        .try_into()
        .expect("33 bytes")
}

// ── Genesis and Regenesis ─────────────────────────────────────────────────

/// What a volunteer asked for a Genesis or Regenesis holds.
pub struct Start<'a> {
    pub kind: GroupKind,
    pub id: &'a str,
    /// Its keyholder pair: a desktop's own, or its connection's seat pair.
    pub me: Me<'a>,
    pub ik: &'a IdentityKeyPair,
    /// Its entry, from its endorsed pair (`Pair::entry`).
    pub entry: Keyholder,
    /// The seats the due names: its own seat, for its one bucket.
    pub joiners: &'a [&'a Joiner],
    pub gated: bool,
    pub stored: bool,
    pub now: u64,
}

/// A Genesis (§5.1): a new generation, `seed_1`, `KRK` and `CK_1`, one
/// bucket for the volunteer's own seat, a welcome to it, and the volunteer
/// as the only keyholder.
pub fn build_genesis(st: &Start, cache: &mut RowBases) -> Result<Built, BuildError> {
    build_anew(st, None, cache)
}

/// A Regenesis (§4.3): after an hour with no keyholder online (at once for a
/// set of connection entries alone, `rules::regenesis_wait`), the next epoch
/// of the same generation under a new seed that every seat is welcomed to
/// anew, as Join commits seat them. It is dated at the volunteer's clock, or
/// at its parent's `time` where that is later (as every opening is): a
/// Regenesis never comes before its parent. `exits` is the closed batch the
/// due carries, if any.
pub fn build_regenesis(
    st: &Start,
    head: &SignedHeader,
    exits: &[Exit],
    exits_upto: u64,
    cache: &mut RowBases,
) -> Result<Built, BuildError> {
    build_anew(st, Some((head, exits, exits_upto)), cache)
}

fn build_anew(
    st: &Start,
    parent: Option<(&SignedHeader, &[Exit], u64)>,
    cache: &mut RowBases,
) -> Result<Built, BuildError> {
    if st.entry.kx != raw_kx(&st.me) || st.entry.m != st.me.m {
        return Err(BuildError::Refuse("the entry is not this pair's"));
    }
    let (gen, epoch, s, parent_d, kh_parent, upto, kind, removed, time) = match parent {
        None => (
            crate::aead::random::<16>(),
            1,
            1,
            [0; 32],
            [0; 32],
            0,
            Kind::Genesis,
            vec![],
            st.now,
        ),
        Some((p, exits, upto)) => {
            let ph = p.header();
            // Never before its parent: a volunteer whose clock is behind the parent's maker's
            // dates it at the parent's `time`, now that a set of connection entries alone
            // waits nothing
            let time = st.now.max(ph.time);
            // The wait its set in force allows (`regenesis_wait`, "Fast new start"): known
            // here where the head sets keyholders; else the shortest, none, and the
            // volunteer's own check (`validate`, over the keyholder header in force it holds)
            // holds it to the rest
            let wait = if ph.kind.sets_keyholders() {
                super::regenesis_wait(ph, time)
            } else {
                super::REGENESIS_FAST_WAIT
            };
            if time < ph.time.saturating_add(wait) {
                return Err(BuildError::Refuse(
                    "a Regenesis waits an hour after its parent",
                ));
            }
            let upto = if exits.is_empty() {
                ph.exits_upto
            } else {
                ph.exits_upto.max(upto)
            };
            (
                ph.gen,
                ph.epoch + 1,
                ph.seed + 1,
                p.d(),
                p.kh(),
                upto,
                Kind::Regenesis,
                exits.iter().map(|e| e.seat).collect(),
                time,
            )
        }
    };
    let g = Group::new(st.kind, st.id, gen)?;
    let seed = Zeroizing::new(crate::aead::random());
    let krk = Zeroizing::new(crate::aead::random());
    let ck = Zeroizing::new(crate::aead::random());
    cache.bind(&g, s, &seed);
    let mut ids = Ids::of(None);
    let made = steps::whole(seat_joiners(
        &g, s, &seed, &st.me, st.joiners, st.stored, st.now, &mut ids, cache, None,
    ))?;
    let mut buckets: Vec<KeyringBucket> = made.iter().map(|m| m.bucket.clone()).collect();
    buckets.sort_by_key(|b| b.b);
    let (seats, n_buckets, conn_seats, root) = counts(&buckets)?;
    let set = vec![st.entry];
    let ks = keyholder_set_digest(&set);
    let base = KeyringBase {
        gen,
        epoch,
        join: 0,
        seeds: vec![(s, seed)],
        ck: ck.clone(),
        exits_upto: upto,
        buckets: buckets.clone(),
        rolls: SeedRolls {
            raised: st.now,
            removal: false,
        },
    };
    let sealed = seal_base(&g, s, &ks, &krk, &base);
    let (added, removed) = names(
        st.gated,
        st.joiners.iter().map(|j| j.added()).collect(),
        removed,
    );
    let h = HeaderV1 {
        group_kind: st.kind,
        group: st.id.to_string(),
        gen,
        epoch,
        join: 0,
        kind,
        time,
        parent: parent_d,
        epoch_parent: [0; 32],
        kh_parent,
        signer: st.me.m,
        keyholders: set,
        gated: st.gated,
        seed: s,
        seed_floor: s,
        exits_upto: upto,
        seats,
        buckets: n_buckets,
        conn_seats,
        bucket_root: root,
        keyring_hash: keyring_hash_start(&sealed),
        names_hash: [0; 32],
        added,
        removed,
        confirm: confirm(&g, epoch, 0, &ck),
    };
    let sh = sign(h, parent.map(|p| p.0), st.ik)?;
    let ep = Epoch {
        e: epoch,
        d_e: sh.d(),
    };
    let public = st.me.keys.public();
    let to_self = Them {
        m: st.me.m,
        keys: &public,
    };
    let krk_out = KrkOut {
        to: HolderRef::of(&st.entry),
        from_kx: st.entry.kx,
        bytes: keyring_welcome(&g, s, epoch, &ks, &st.me, &to_self, &krk)?,
    };
    let commit = Commit {
        body: sh.body().to_vec(),
        sig: sh.sig().to_vec(),
        versions: made
            .iter()
            .map(|m| version_out(m, Make::Seats(m.seats.clone())))
            .collect(),
        welcomes: made.iter().flat_map(|m| m.welcomes.clone()).collect(),
        rows: made.iter().filter_map(|m| m.rows.clone()).collect(),
        seals: seals(&g, &ep, &ck, &buckets.iter().collect::<Vec<_>>()),
        keyring: sealed,
        krk: vec![krk_out],
        ..Commit::default()
    };
    let sealed_to = made.iter().flat_map(|m| m.seats.clone()).collect();
    let parent_seeds = parent.map_or((0, 0), |p| (p.0.header().seed, p.0.header().seed_floor));
    Ok(Built {
        commit,
        header: sh,
        ck,
        krk,
        ring: Keyring {
            buckets: base.buckets.clone(),
            base,
        },
        made,
        parent_seeds,
        sealed_to,
    })
}

// ── Join ──────────────────────────────────────────────────────────────────

/// A Join (§5.2) on the head: the joiners the keyholder checked go into new
/// buckets, under the epoch's `CK`; `refused` are the ones it left out.
pub fn build_join(
    hold: &Holding,
    joiners: &[&Joiner],
    refused: Vec<Refused>,
    now: u64,
    cache: &mut RowBases,
    reuse: Option<&Built>,
) -> Result<Built, BuildError> {
    steps::whole(join_in_steps(hold, joiners, refused, now, cache, reuse))
}

/// `build_join` in steps (`steps`): one may stop after each seat's row and
/// its welcome, the bucket root, the signature and each seal.
pub async fn join_in_steps(
    hold: &Holding<'_>,
    joiners: &[&Joiner],
    refused: Vec<Refused>,
    now: u64,
    cache: &mut RowBases,
    reuse: Option<&Built>,
) -> Result<Built, BuildError> {
    let g = hold.g;
    let head = hold.head.header();
    let s = head.seed;
    let seed = hold.ring.seed(s).ok_or(BuildError::Refuse(
        "the keyring does not hold the head's seed",
    ))?;
    cache.bind(g, s, seed);
    let mut ids = Ids::of(Some(hold.ring));
    let reuse = reuse.filter(|r| same_start(r, g, head));
    let made = seat_joiners(
        g,
        s,
        seed,
        &hold.me,
        joiners,
        hold.stored,
        now,
        &mut ids,
        cache,
        reuse,
    )
    .await?;
    let mut new: Vec<KeyringBucket> = made.iter().map(|m| m.bucket.clone()).collect();
    new.sort_by_key(|b| b.b);
    let mut all: Vec<KeyringBucket> = hold.ring.buckets.clone();
    all.extend(new.iter().cloned());
    all.sort_by_key(|b| b.b);
    let (seats, n_buckets, conn_seats, root) = counts(&all)?;
    steps::unit().await;
    let ks = keyholder_set_digest(&hold.kh.header().keyholders);
    let join = head.join + 1;
    let delta = KeyringDelta {
        join,
        buckets: new.clone(),
    };
    let sealed = seal_delta(g, head.epoch, s, &ks, hold.krk, &delta);
    let ck = Zeroizing::new(*hold.ring.ck());
    let (added, removed) = names(
        head.gated,
        joiners.iter().map(|j| j.added()).collect(),
        vec![],
    );
    let h = HeaderV1 {
        epoch: head.epoch,
        join,
        kind: Kind::Join,
        time: now.max(head.time),
        parent: hold.head.d(),
        epoch_parent: hold.head.d_e(),
        kh_parent: hold.head.kh(),
        signer: hold.me.m,
        keyholders: vec![],
        seats,
        buckets: n_buckets,
        conn_seats,
        bucket_root: root,
        keyring_hash: keyring_hash_next(&head.keyring_hash, &sealed),
        added,
        removed,
        confirm: confirm(g, head.epoch, join, &ck),
        ..head.clone()
    };
    let sh = sign(h, Some(hold.head), hold.ik)?;
    steps::unit().await;
    let ep = Epoch {
        e: head.epoch,
        d_e: hold.head.d_e(),
    };
    let seals = seals_in_steps(g, &ep, &ck, &new.iter().collect::<Vec<_>>()).await;
    let commit = Commit {
        body: sh.body().to_vec(),
        sig: sh.sig().to_vec(),
        versions: made
            .iter()
            .map(|m| version_out(m, Make::Seats(m.seats.clone())))
            .collect(),
        welcomes: made.iter().flat_map(|m| m.welcomes.clone()).collect(),
        rows: made.iter().filter_map(|m| m.rows.clone()).collect(),
        seals,
        keyring: sealed,
        refused,
        ..Commit::default()
    };
    Ok(Built {
        commit,
        header: sh,
        ck,
        krk: Zeroizing::new(*hold.krk),
        ring: Keyring {
            base: hold.ring.base.clone(),
            buckets: all,
        },
        sealed_to: made.iter().flat_map(|m| m.seats.clone()).collect(),
        made,
        parent_seeds: (head.seed, head.seed_floor),
    })
}

// ── The planner (§5.3, §5.5) ──────────────────────────────────────────────

/// One current bucket as the planner sees it: from the keyring and the
/// due's exits, no list needed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BucketNow {
    pub b: u64,
    pub v: u64,
    pub pool: Pool,
    pub seats: u16,
    /// Unix seconds, the keyring's `made`.
    pub made: u64,
    /// How many of its seats exit in this commit.
    pub exits: u16,
}

/// What an opening commit does to one bucket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// Kept as it is.
    Same,
    /// A promotion's ratchet in place (§3.5).
    Ratchet,
    /// A new version by rows, without its leavers.
    ReKey,
    /// Nobody left in it.
    Drop,
    /// Its seats go into pack `k`'s new buckets.
    Merge(usize),
}

/// The steps for each bucket, in the order given, and the pools of the
/// packs merges and repacks fill.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    pub steps: Vec<Step>,
    pub packs: Vec<Pool>,
}

impl Plan {
    /// The rows this plan costs: every seat left in a re-keyed or merged
    /// bucket.
    pub fn rows(&self, buckets: &[BucketNow]) -> usize {
        buckets
            .iter()
            .zip(&self.steps)
            .filter(|(_, s)| matches!(s, Step::ReKey | Step::Merge(_)))
            .map(|(b, _)| usize::from(b.seats.saturating_sub(b.exits)))
            .sum()
    }

    /// The buckets whose lists the build needs: every one it changes but
    /// drops (a ratchet names its seats in its new list digest too).
    pub fn lists_needed(&self, buckets: &[BucketNow]) -> Vec<Version> {
        buckets
            .iter()
            .zip(&self.steps)
            .filter(|(_, s)| !matches!(s, Step::Same | Step::Drop))
            .map(|(b, _)| Version { b: b.b, v: b.v })
            .collect()
    }

    /// The buckets after it: those kept or re-versioned, and the packs'.
    pub fn buckets_after(&self, buckets: &[BucketNow]) -> usize {
        let kept = self
            .steps
            .iter()
            .filter(|s| matches!(s, Step::Same | Step::Ratchet | Step::ReKey))
            .count();
        kept + self.pack_buckets(buckets)
    }

    /// The new buckets merges and repacks fill.
    pub fn pack_buckets(&self, buckets: &[BucketNow]) -> usize {
        (0..self.packs.len())
            .map(|k| {
                let seats: usize = buckets
                    .iter()
                    .zip(&self.steps)
                    .filter(|(_, s)| **s == Step::Merge(k))
                    .map(|(b, _)| usize::from(b.seats.saturating_sub(b.exits)))
                    .sum();
                seats.div_ceil(FULL)
            })
            .sum()
    }

    /// The versions it makes by rows: re-keys and the packs' buckets.
    pub fn by_rows(&self, buckets: &[BucketNow]) -> usize {
        self.steps.iter().filter(|s| **s == Step::ReKey).count() + self.pack_buckets(buckets)
    }
}

/// What an opening commit of `kind` does to each bucket (§4.3, §5.3, §5.5):
///
/// - a bucket its exits empty is dropped; one with leavers is re-keyed by
///   rows without them;
/// - a KeyholdersAdd ratchets every other bucket and merges nothing;
/// - in each pool, once 16 or more buckets are small (under 16 seats), all
///   of them merge into new full buckets;
/// - when a pool's bucket count passes `1.5 × N/62 + 16`, its smallest other
///   buckets whose seats fit one are repacked into one, if that takes two;
/// - a KeyholdersRemove re-keys every bucket; any other opening re-keys
///   every version over an hour old;
/// - a refresh re-keys at least the oldest twelfth of the buckets.
pub fn plan_opening(kind: Kind, buckets: &[BucketNow], refresh: bool, now: u64) -> Plan {
    let left = |b: &BucketNow| usize::from(b.seats.saturating_sub(b.exits));
    let mut steps = vec![Step::Same; buckets.len()];
    let mut packs = Vec::new();
    for pool in [Pool::Accounts, Pool::Conns] {
        let mut live = Vec::new();
        for (i, b) in buckets.iter().enumerate().filter(|(_, b)| b.pool == pool) {
            if left(b) == 0 {
                steps[i] = Step::Drop;
            } else {
                live.push(i);
            }
        }
        if kind == Kind::KeyholdersAdd {
            for i in live {
                steps[i] = if buckets[i].exits > 0 {
                    Step::ReKey
                } else {
                    Step::Ratchet
                };
            }
            continue;
        }
        let n: usize = live.iter().map(|&i| left(&buckets[i])).sum();
        let small: Vec<usize> = live
            .iter()
            .copied()
            .filter(|&i| left(&buckets[i]) < SMALL_SEATS)
            .collect();
        let mut rest = live.clone();
        let mut merged = 0;
        if small.len() >= SMALL_BUCKETS {
            let k = packs.len();
            packs.push(pool);
            for &i in &small {
                steps[i] = Step::Merge(k);
                merged += left(&buckets[i]);
            }
            rest.retain(|i| !small.contains(i));
        }
        let count = rest.len() + merged.div_ceil(FULL);
        if count as f64 > 1.5 * n as f64 / FULL as f64 + 16.0 {
            let mut by_size = rest.clone();
            by_size.sort_by_key(|&i| (left(&buckets[i]), buckets[i].b));
            let mut take = Vec::new();
            let mut sum = 0;
            for i in by_size {
                if sum + left(&buckets[i]) > FULL {
                    break;
                }
                sum += left(&buckets[i]);
                take.push(i);
            }
            if take.len() >= 2 {
                let k = packs.len();
                packs.push(pool);
                for &i in &take {
                    steps[i] = Step::Merge(k);
                }
                rest.retain(|i| !take.contains(i));
            }
        }
        for i in rest {
            let b = &buckets[i];
            let old = now.saturating_sub(b.made) > BUCKET_AGE_MAX_SECS;
            if b.exits > 0 || kind == Kind::KeyholdersRemove || old {
                steps[i] = Step::ReKey;
            }
        }
    }
    let mut plan = Plan { steps, packs };
    if refresh && matches!(kind, Kind::Fresh | Kind::KeyholdersReplace) {
        let by_rows = plan.by_rows(buckets);
        let need = plan.buckets_after(buckets).div_ceil(REFRESH_SLICE);
        if by_rows < need {
            let mut same: Vec<usize> = (0..buckets.len())
                .filter(|&i| plan.steps[i] == Step::Same)
                .collect();
            same.sort_by_key(|&i| (buckets[i].made, buckets[i].b));
            for i in same.into_iter().take(need - by_rows) {
                plan.steps[i] = Step::ReKey;
            }
        }
    }
    plan
}

// ── Openings ──────────────────────────────────────────────────────────────

/// A KeyholdersReplace's new pair: every row and welcome but the keyring
/// welcomes comes from it (§4.3).
pub struct Replacing<'a> {
    pub me: Me<'a>,
    pub entry: Keyholder,
}

/// What an opening due asks, and what the keyholder brings to it.
pub struct OpeningAsk<'a> {
    /// Fresh, KeyholdersAdd, KeyholdersRemove or KeyholdersReplace.
    pub kind: Kind,
    pub exits: &'a [Exit],
    pub exits_upto: u64,
    /// A refresh due: at least a twelfth of the buckets re-keyed by rows.
    pub refresh: bool,
    pub gated: bool,
    pub candidate: Option<&'a Candidate>,
    pub remove: Option<HolderRef>,
    pub replace: Option<Replacing<'a>>,
    /// The relay says every seat holds `seed`: a running roll may finish.
    pub finish: bool,
    /// The KEM keys of seats the new floor may drop (`EpochDue.seed_seats`).
    pub seed_seats: &'a HashMap<SeatRef, SeatPublic>,
    /// Every keyholder's pair, for its `KRK` welcome (`Sync`, as `Holding`'s
    /// `held`).
    pub pairs: &'a (dyn Fn(&Keyholder) -> Option<SeatPublic> + Sync),
    pub now: u64,
}

/// A Fresh, KeyholdersAdd, KeyholdersRemove or KeyholdersReplace on the
/// head. A new `CK` every attempt; seeds by §5.6 (a text roll only when none
/// runs, open choice 23); a seat on a seed the new floor drops gets its seed
/// welcome before any row. A text roll ends at the first opening 24 h after
/// its start, whatever the relay says (RV q1-q2:1210): a seat behind it, or
/// already behind the head's floor, gets its seed welcome here where the relay
/// sent its keys, and else its row under the commit's seed, which it opens once
/// the relay's sweep brings the welcome (`behind_ok`).
pub fn build_opening(
    hold: &Holding,
    ask: &OpeningAsk,
    cache: &mut RowBases,
    reuse: Option<&Built>,
) -> Result<Built, BuildError> {
    steps::whole(opening_in_steps(hold, ask, cache, reuse))
}

/// `build_opening` in steps (`steps`): one may stop after each list it
/// checks, each bucket's seats it reads, each row, each ratchet, the
/// keyring's seal, the bucket root, the signature, each `KRK` welcome, each
/// seed welcome and each seal.
pub async fn opening_in_steps(
    hold: &Holding<'_>,
    ask: &OpeningAsk<'_>,
    cache: &mut RowBases,
    reuse: Option<&Built>,
) -> Result<Built, BuildError> {
    let g = hold.g;
    let kind_g = g.kind();
    let head = hold.head.header();
    if !matches!(
        ask.kind,
        Kind::Fresh | Kind::KeyholdersAdd | Kind::KeyholdersRemove | Kind::KeyholdersReplace
    ) {
        return Err(BuildError::Refuse("not an opening this builder makes"));
    }
    let ring = hold.ring;
    let time = ask.now.max(head.time);
    let e = head.epoch + 1;

    // The keyholder set, and whose pair makes rows.
    let own = HolderRef {
        m: hold.me.m,
        kx: raw_kx(&hold.me),
    };
    let old_set = &hold.kh.header().keyholders;
    let new_set: Option<Vec<Keyholder>> = match ask.kind {
        Kind::KeyholdersAdd => {
            let c = ask.candidate.ok_or(BuildError::Refuse("no candidate"))?;
            let entry = c
                .pair
                .entry(kind_g, c.m, c.ik)
                .ok_or(BuildError::Refuse("a candidate pair no keyholder may hold"))?;
            let mut set = old_set.clone();
            set.push(entry);
            Some(set)
        }
        Kind::KeyholdersRemove => {
            let t = ask.remove.ok_or(BuildError::Refuse("no entry to remove"))?;
            if t == own {
                return Err(BuildError::Refuse(
                    "a keyholder never signs its own removal",
                ));
            }
            let set: Vec<Keyholder> = old_set
                .iter()
                .filter(|k| HolderRef::of(k) != t)
                .copied()
                .collect();
            if set.len() + 1 != old_set.len() {
                return Err(BuildError::Refuse("the entry to remove is not in the set"));
            }
            Some(set)
        }
        Kind::KeyholdersReplace => {
            let r = ask
                .replace
                .as_ref()
                .ok_or(BuildError::Refuse("no new pair"))?;
            let set: Vec<Keyholder> = old_set
                .iter()
                .map(|k| if HolderRef::of(k) == own { r.entry } else { *k })
                .collect();
            if !set.contains(&r.entry) || r.entry.kx != raw_kx(&r.me) {
                return Err(BuildError::Refuse("the new pair is not this keyholder's"));
            }
            Some(set)
        }
        _ => None,
    };
    let row_me = match &ask.replace {
        Some(r) if ask.kind == Kind::KeyholdersReplace => &r.me,
        _ => &hold.me,
    };
    let set_now: &[Keyholder] = new_set.as_deref().unwrap_or(old_set);
    if ask.gated && set_now.iter().any(|k| k.m.is_conn()) {
        return Err(BuildError::Refuse("a guest keyholder in a gated group"));
    }

    // Seeds (§5.6).
    let start = ask.kind != Kind::KeyholdersReplace
        && hold.rolls.starts(kind_g, ask.kind, time)
        && (kind_g == GroupKind::Voice || head.seed_floor == head.seed);
    let (s, mut floor) = if start {
        (head.seed + 1, head.seed)
    } else {
        (head.seed, head.seed_floor)
    };
    // §5.6 "24 h to finish": a text roll ends here once it is a day old, by its start
    // as the keyring carries it (RV q1-q2:1210)
    let ends = !start && hold.rolls.ends(head, time);
    if !start && (ends || (ask.finish && ask.kind != Kind::KeyholdersReplace)) {
        floor = s;
    }
    let new_seed = start.then(|| Zeroizing::new(crate::aead::random::<32>()));
    let mut seeds: Vec<(u32, Zeroizing<[u8; 32]>)> = Vec::new();
    for n in floor..=s {
        let k = match (&new_seed, ring.seed(n)) {
            (Some(k), _) if n == s => k.clone(),
            (_, Some(k)) => Zeroizing::new(*k),
            _ => return Err(BuildError::Refuse("the keyring does not hold a live seed")),
        };
        cache.bind(g, n, &k);
        seeds.push((n, k));
    }
    let reuse = reuse.filter(|r| same_start(r, g, head));
    // The seeds this attempt shares with the stale one: rows under any
    // other are made again.
    let same_seeds: HashSet<u32> = seeds
        .iter()
        .filter(|(n, k)| reuse.and_then(|r| r.ring.seed(*n)) == Some(&**k))
        .map(|(n, _)| *n)
        .collect();

    // The plan, and the lists it needs.
    let mut exit_by_b: HashMap<u64, HashSet<SeatRef>> = HashMap::new();
    for x in ask.exits {
        exit_by_b.entry(x.b).or_default().insert(x.seat);
    }
    let now_buckets: Vec<BucketNow> = ring
        .buckets
        .iter()
        .map(|kb| BucketNow {
            b: kb.b,
            v: kb.v,
            pool: kb.pool,
            seats: kb.seats,
            made: kb.made,
            exits: exit_by_b.get(&kb.b).map_or(0, |x| x.len() as u16),
        })
        .collect();
    let plan = plan_opening(ask.kind, &now_buckets, ask.refresh, ask.now);
    let mut lists: HashMap<u64, Vec<SeatRef>> = HashMap::new();
    let mut dh: HashMap<SeatRef, &[u8]> = HashMap::new();
    for at in plan.lists_needed(&now_buckets) {
        let list = hold
            .lists
            .get(&at)
            .ok_or(BuildError::Refuse("a list the build needs is missing"))?;
        let mut seats: Vec<SeatRef> = list.iter().map(|l| l.seat).collect();
        list_order(&mut seats);
        let kb = ring
            .buckets
            .iter()
            .find(|kb| kb.version() == at)
            .expect("planned from the keyring");
        let keys: HashMap<SeatRef, &[u8]> = list.iter().map(|l| (l.seat, &l.dh[..])).collect();
        let digest = list_digest(g, at, &seats, |s| seat_dh(keys.get(s)?));
        if digest != Some(kb.list) || seats.len() != usize::from(kb.seats) {
            return Err(GkError::Sealed.into());
        }
        dh.extend(keys);
        lists.insert(at.b, seats);
        steps::unit().await;
    }
    for x in ask.exits {
        if lists.get(&x.b).is_some_and(|l| !l.contains(&x.seat)) {
            return Err(BuildError::Refuse(
                "an exit names a seat its bucket does not hold",
            ));
        }
    }
    // §5.6: the candidate is seated (RV q4-q5:748). In a gated text group a seat needs a
    // name in `added`, which the relay cannot make, and the promoted pair gets the keyring:
    // a candidate seated nowhere would read every post on the relay's word. A KeyholdersAdd
    // reads every bucket's list but those of buckets every seat leaves, and a seat leaving in
    // this commit is no seat. This binds the candidate's account id, not its `IK`: that is
    // the pin's, or taken on trust where this device has none (`candidate_ok`). (An open
    // group's relay may seat anyone; a voice room's keyholders are its roster's, §5.9.)
    if let (Kind::KeyholdersAdd, Some(c)) = (ask.kind, ask.candidate) {
        let seated = lists.iter().any(|(b, seats)| {
            let exiting = exit_by_b.get(b);
            seats
                .iter()
                .any(|s| s.m == c.m && !exiting.is_some_and(|x| x.contains(s)))
        });
        if kind_g == GroupKind::Text && (ask.gated || head.gated) && !seated {
            return Err(BuildError::Candidate("the candidate is seated nowhere"));
        }
    }

    // Who holds which seed after: seats on a dropped seed get a seed welcome. In a
    // text group a seat behind a roll ending here, or left behind one, gets it only
    // where the relay sent its keys; else its row is under `s` with none (§5.6)
    let held_of = |seat: &SeatRef| (hold.held)(seat);
    let mut seed_welcomed: HashSet<SeatRef> = HashSet::new();
    let mut unwelcomed: HashSet<SeatRef> = HashSet::new();
    for (b, seats) in &lists {
        let exiting = exit_by_b.get(b);
        for seat in seats {
            if exiting.is_some_and(|x| x.contains(seat)) {
                continue;
            }
            match held_of(seat) {
                Some(n) if n >= floor => {}
                Some(n) if behind_ok(head, n, ends) => {
                    if ask.seed_seats.contains_key(seat) {
                        seed_welcomed.insert(*seat);
                    } else {
                        unwelcomed.insert(*seat);
                    }
                }
                Some(_) if start => {
                    seed_welcomed.insert(*seat);
                }
                _ => return Err(BuildError::Refuse("a seat on a seed the floor drops")),
            }
        }
        steps::unit().await;
    }
    let seed_of = |seat: &SeatRef| -> Result<u32, BuildError> {
        if seed_welcomed.contains(seat) || unwelcomed.contains(seat) {
            return Ok(s);
        }
        match held_of(seat) {
            Some(n) if (floor..=s).contains(&n) => Ok(n),
            _ => Err(BuildError::Refuse("no live seed for a seat")),
        }
    };

    // Versions.
    let current: HashSet<Leaf> = ring.buckets.iter().map(KeyringBucket::leaf).collect();
    let ring_b: HashSet<u64> = ring.buckets.iter().map(|k| k.b).collect();
    let ring_v: HashSet<u64> = ring.buckets.iter().map(|k| k.v).collect();
    let rk = Rekeying {
        g,
        seed_of: &seed_of,
        seeds: &seeds,
        same_seeds: &same_seeds,
        dh: &dh,
        me: row_me,
        now: ask.now,
        reuse,
        current: &current,
        ring_b: &ring_b,
        ring_v: &ring_v,
    };
    let mut ids = Ids::of(Some(ring));
    let mut after: Vec<KeyringBucket> = Vec::new();
    let mut made: Vec<Made> = Vec::new();
    let mut versions: Vec<VersionOut> = Vec::new();
    let mut drops: Vec<u64> = Vec::new();
    let mut packs: Vec<(Vec<SeatRef>, Vec<Leaf>)> = vec![(vec![], vec![]); plan.packs.len()];
    let none = HashSet::new();
    for (kb, step) in ring.buckets.iter().zip(&plan.steps) {
        let leaving = exit_by_b.get(&kb.b).unwrap_or(&none);
        let staying = || -> Vec<SeatRef> {
            lists[&kb.b]
                .iter()
                .filter(|s| !leaving.contains(s))
                .copied()
                .collect()
        };
        match step {
            Step::Same => after.push(kb.clone()),
            Step::Drop => drops.push(kb.b),
            Step::Merge(k) => {
                drops.push(kb.b);
                packs[*k].0.extend(staying());
                packs[*k].1.push(kb.leaf());
            }
            Step::Ratchet => {
                let seats = lists[&kb.b].clone();
                let v = ids.version();
                let list = list_digest(g, Version { b: kb.b, v }, &seats, |s| seat_dh(dh.get(s)?))
                    .ok_or(GkError::Sealed)?;
                let nb = kb.ratcheted(g, e, v, list);
                versions.push(VersionOut {
                    b: kb.b,
                    v,
                    pool: kb.pool,
                    make: Make::Ratchet { from_v: kb.v },
                });
                after.push(nb.clone());
                made.push(Made {
                    bucket: nb,
                    seats,
                    from: vec![kb.leaf()],
                    rows: None,
                    welcomes: vec![],
                });
                steps::unit().await;
            }
            Step::ReKey => {
                let all = &lists[&kb.b];
                let seats = staying();
                let mask = all
                    .iter()
                    .enumerate()
                    .filter(|(_, s)| !leaving.contains(s))
                    .fold(0u64, |m, (i, _)| m | (1 << i));
                let m = rk
                    .version(kb.b, kb.pool, &seats, &[kb.leaf()], cache, &mut ids)
                    .await?;
                versions.push(version_out(&m, Make::Keep { from_v: kb.v, mask }));
                after.push(m.bucket.clone());
                made.push(m);
            }
        }
    }
    for ((mut seats, from), pool) in packs.into_iter().zip(&plan.packs) {
        list_order(&mut seats);
        for chunk in seats.chunks(FULL) {
            let b = rk
                .stale(chunk, *pool, &from)
                .map_or_else(|| ids.bucket(), |m| m.bucket.b);
            let m = rk.version(b, *pool, chunk, &from, cache, &mut ids).await?;
            versions.push(version_out(&m, Make::Seats(chunk.to_vec())));
            after.push(m.bucket.clone());
            made.push(m);
        }
    }
    after.sort_by_key(|b| b.b);
    if ask.gated && after.iter().any(|b| b.pool == Pool::Conns) {
        return Err(BuildError::Refuse(
            "a gated header while a connections bucket is left",
        ));
    }

    // The keyring, the header, the seals.
    let krk = if new_set.is_some() {
        Zeroizing::new(crate::aead::random())
    } else {
        Zeroizing::new(*hold.krk)
    };
    let ks = keyholder_set_digest(set_now);
    let ck = Zeroizing::new(crate::aead::random());
    let upto = if ask.exits.is_empty() {
        head.exits_upto
    } else {
        head.exits_upto.max(ask.exits_upto)
    };
    let base = KeyringBase {
        gen: head.gen,
        epoch: e,
        join: 0,
        seeds: seeds.clone(),
        ck: ck.clone(),
        exits_upto: upto,
        buckets: after.clone(),
        rolls: hold.rolls.at(ask.kind, start, time),
    };
    let sealed = seal_base(g, s, &ks, &krk, &base);
    steps::unit().await;
    let (seats_n, n_buckets, conn_seats, root) = counts(&after)?;
    steps::unit().await;
    let (added, removed) = names(
        ask.gated,
        vec![],
        ask.exits.iter().map(|x| x.seat).collect(),
    );
    let h = HeaderV1 {
        epoch: e,
        join: 0,
        kind: ask.kind,
        time,
        parent: hold.head.d(),
        epoch_parent: [0; 32],
        kh_parent: hold.head.kh(),
        signer: hold.me.m,
        keyholders: new_set.clone().unwrap_or_default(),
        gated: ask.gated,
        seed: s,
        seed_floor: floor,
        exits_upto: upto,
        seats: seats_n,
        buckets: n_buckets,
        conn_seats,
        bucket_root: root,
        keyring_hash: keyring_hash_start(&sealed),
        added,
        removed,
        confirm: confirm(g, e, 0, &ck),
        ..head.clone()
    };
    let sh = sign(h, Some(hold.head), hold.ik)?;
    steps::unit().await;
    let ep = Epoch { e, d_e: sh.d() };

    let mut krk_out = Vec::new();
    if let Some(set) = &new_set {
        for entry in set {
            let public = if HolderRef::of(entry) == own {
                hold.me.keys.public()
            } else if let (Some(r), true) = (&ask.replace, ask.kind == Kind::KeyholdersReplace) {
                if *entry == r.entry {
                    r.me.keys.public()
                } else {
                    (ask.pairs)(entry).ok_or(BuildError::Refuse("a keyholder's pair is unknown"))?
                }
            } else if let Some(c) = ask
                .candidate
                .filter(|c| c.m == entry.m && c.pair.kx() == entry.kx)
            {
                c.pair.keys.clone()
            } else {
                (ask.pairs)(entry).ok_or(BuildError::Refuse("a keyholder's pair is unknown"))?
            };
            let ser = public.dh_bytes();
            if ser[1..] != entry.kx || public.tag_kem() != entry.tag_kk {
                return Err(GkError::Forged.into());
            }
            let to = Them {
                m: entry.m,
                keys: &public,
            };
            krk_out.push(KrkOut {
                to: HolderRef::of(entry),
                from_kx: own.kx,
                bytes: keyring_welcome(g, s, e, &ks, &hold.me, &to, &krk)?,
            });
            steps::unit().await;
        }
    }
    let mut seed_welcomes = Vec::new();
    if !seed_welcomed.is_empty() {
        // Under `s`: the seed this commit draws, or the head's at a roll that ends here
        let seed_s = seeds
            .iter()
            .find(|(n, _)| *n == s)
            .map(|(_, k)| k)
            .ok_or(BuildError::Refuse("the keyring does not hold a live seed"))?;
        let mut ordered: Vec<SeatRef> = seed_welcomed.iter().copied().collect();
        list_order(&mut ordered);
        for seat in ordered {
            let keys = ask
                .seed_seats
                .get(&seat)
                .ok_or(BuildError::Refuse("no KEM key for a seat the floor drops"))?;
            if keys.seat(seat.m) != seat {
                return Err(GkError::Forged.into());
            }
            let s_m = member_secret(g, s, seed_s, &seat);
            let to = Them { m: seat.m, keys };
            seed_welcomes.push(SeedWelcomeOut {
                seat,
                bytes: seed_welcome(g, s, row_me, &to, &s_m)?,
            });
            steps::unit().await;
        }
    }
    let seals = seals_in_steps(g, &ep, &ck, &after.iter().collect::<Vec<_>>()).await;
    let commit = Commit {
        body: sh.body().to_vec(),
        sig: sh.sig().to_vec(),
        versions,
        drops,
        rows: made.iter().filter_map(|m| m.rows.clone()).collect(),
        seals,
        seed_welcomes,
        keyring: sealed,
        krk: krk_out,
        ..Commit::default()
    };
    Ok(Built {
        commit,
        header: sh,
        ck,
        krk,
        ring: Keyring {
            buckets: after,
            base,
        },
        made,
        parent_seeds: (head.seed, head.seed_floor),
        sealed_to: vec![],
    })
}

/// What every re-version by rows of one opening shares.
struct Rekeying<'x> {
    g: &'x Group,
    seed_of: &'x (dyn Fn(&SeatRef) -> Result<u32, BuildError> + Sync),
    seeds: &'x [(u32, Zeroizing<[u8; 32]>)],
    /// The seed numbers whose seed the stale attempt drew the same.
    same_seeds: &'x HashSet<u32>,
    dh: &'x HashMap<SeatRef, &'x [u8]>,
    me: &'x Me<'x>,
    now: u64,
    reuse: Option<&'x Built>,
    current: &'x HashSet<Leaf>,
    ring_b: &'x HashSet<u64>,
    ring_v: &'x HashSet<u64>,
}

impl Rekeying<'_> {
    /// The stale attempt's version for these seats, where a rebase may
    /// reuse it.
    fn stale(&self, seats: &[SeatRef], pool: Pool, from: &[Leaf]) -> Option<&Made> {
        reusable(
            self.reuse,
            self.current,
            self.ring_b,
            self.ring_v,
            seats,
            pool,
            from,
        )
    }

    /// A version by rows for `seats` in bucket `b`: reused from the stale
    /// attempt where `reusable` allows (its rows too, if every seat's seed is
    /// the same number and the same draw), else a new id and `BK`. A step
    /// may stop after each row.
    async fn version(
        &self,
        b: u64,
        pool: Pool,
        seats: &[SeatRef],
        from: &[Leaf],
        cache: &mut RowBases,
        ids: &mut Ids,
    ) -> Result<Made, BuildError> {
        let seed_list: Vec<u32> = seats.iter().map(self.seed_of).collect::<Result<_, _>>()?;
        let stale = self.stale(seats, pool, from).filter(|m| m.bucket.b == b);
        let (v, bk, made) = match stale {
            Some(m) => {
                ids.v.insert(m.bucket.v);
                (m.bucket.v, m.bucket.bk.clone(), m.bucket.made)
            }
            None => (
                ids.version(),
                Zeroizing::new(crate::aead::random()),
                self.now,
            ),
        };
        let at = Version { b, v };
        let s0 = seed_list.iter().copied().min().unwrap_or(0);
        let up = seed_list
            .iter()
            .enumerate()
            .filter(|(_, &si)| si > s0)
            .fold(0u64, |u, (i, _)| u | (1 << i));
        let drawn_same = |s: u32| self.same_seeds.contains(&s);
        let rows = match stale.and_then(|m| m.rows.clone()) {
            Some(r)
                if r.s == s0 && r.up == up && drawn_same(s0) && (up == 0 || drawn_same(s0 + 1)) =>
            {
                r
            }
            _ => {
                rows_to(
                    self.g, at, &bk, seats, &seed_list, self.seeds, self.dh, self.me, cache,
                )
                .await?
            }
        };
        Ok(Made {
            bucket: KeyringBucket {
                b,
                v,
                pool,
                seats: seats.len() as u16,
                list: list_digest(self.g, at, seats, |s| seat_dh(self.dh.get(s)?))
                    .ok_or(GkError::Sealed)?,
                via: Via::Row,
                bk,
                made,
            },
            seats: seats.to_vec(),
            from: from.to_vec(),
            rows: Some(rows),
            welcomes: vec![],
        })
    }
}

// ── Seed-welcome pages ────────────────────────────────────────────────────

/// A page of seed welcomes under the head's seed `s` (§5.6,
/// `DUE_SEED_WELCOMES`): outside any commit, they change no bucket.
pub fn build_seed_welcomes(
    g: &Group,
    s: u32,
    seed: &[u8; 32],
    me: &Me,
    seats: &[(SeatRef, SeatPublic)],
) -> Result<Vec<SeedWelcomeOut>, BuildError> {
    steps::whole(seed_welcomes_in_steps(g, s, seed, me, seats))
}

/// `build_seed_welcomes` in steps (`steps`): one may stop after each welcome.
pub async fn seed_welcomes_in_steps(
    g: &Group,
    s: u32,
    seed: &[u8; 32],
    me: &Me<'_>,
    seats: &[(SeatRef, SeatPublic)],
) -> Result<Vec<SeedWelcomeOut>, BuildError> {
    let mut out = Vec::with_capacity(seats.len());
    for (seat, keys) in seats {
        if keys.seat(seat.m) != *seat {
            return Err(GkError::Forged.into());
        }
        let s_m = member_secret(g, s, seed, seat);
        let to = Them { m: seat.m, keys };
        out.push(SeedWelcomeOut {
            seat: *seat,
            bytes: seed_welcome(g, s, me, &to, &s_m)?,
        });
        steps::unit().await;
    }
    Ok(out)
}

/// `tag(KX)` of a raw key, as `KeyholdReplace` names an old pair.
pub fn kx_tag(kx: &[u8; 32]) -> [u8; 8] {
    tag(&[&[0x05u8][..], kx].concat())
}

// ── Builds in steps ───────────────────────────────────────────────────────

pub mod steps {
    //! A build cut into steps (plan 3b): a browser keyholder builds on its
    //! page's thread, where a long build is a frozen page and, in a call, a
    //! gap in its voice. The builders are `async`, and between any two
    //! indivisible units of work (one row and its row base, one welcome's
    //! KEM, one seal, one list's digest, the keyring's seal, the bucket
    //! root, the signature) they pass a `unit()`; `step` polls one with a
    //! budget, and a unit that finds the budget spent ends the step there.
    //! The next step goes on from that unit with everything the build had.
    //!
    //! A build is the same code whole or in steps: `whole` polls it with no
    //! budget, where no unit ever stops it. Nothing in a step waits on
    //! anything; the future is only a way to stop and go on.

    use std::cell::Cell;
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll, Waker};
    use std::time::Duration;

    /// The step running on this thread: when it began and may run to, by
    /// its clock, and the units it did.
    #[derive(Clone, Copy)]
    struct Slice {
        start: f64,
        budget: f64,
        units: u64,
        clock: fn() -> f64,
    }

    thread_local! {
        static SLICE: Cell<Option<Slice>> = const { Cell::new(None) };
    }

    /// Puts back the slice a poll found, also when the build panics.
    struct Restore(Option<Slice>);

    impl Drop for Restore {
        fn drop(&mut self) {
            SLICE.with(|s| s.set(self.0.take()));
        }
    }

    /// The end of one unit of work: a step whose budget is spent stops
    /// here, and the next goes on from here. Outside `step`, nothing.
    pub fn unit() -> Unit {
        Unit { stopped: false }
    }

    /// See `unit`.
    pub struct Unit {
        stopped: bool,
    }

    impl Future for Unit {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
            if self.stopped {
                return Poll::Ready(());
            }
            let spent = SLICE.with(|s| {
                let mut slice = s.get()?;
                slice.units += 1;
                s.set(Some(slice));
                Some((slice.clock)() - slice.start >= slice.budget)
            });
            if spent == Some(true) {
                self.stopped = true;
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        }
    }

    /// Before a block that cannot be cut (the validator over a whole
    /// commit): a step that did any unit stops here, so the block begins a
    /// step of its own rather than adding to a spent one.
    pub fn fresh() -> Fresh {
        Fresh { stopped: false }
    }

    /// See `fresh`.
    pub struct Fresh {
        stopped: bool,
    }

    impl Future for Fresh {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
            if self.stopped {
                return Poll::Ready(());
            }
            if SLICE.with(|s| s.get().is_some_and(|slice| slice.units > 0)) {
                self.stopped = true;
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        }
    }

    /// Runs a build to its end at once: no unit stops it (`build_join` and
    /// the others, and anything a step runs whole inside it).
    pub fn whole<F: Future>(f: F) -> F::Output {
        let _restore = Restore(SLICE.with(|s| s.take()));
        let mut f = std::pin::pin!(f);
        let mut cx = Context::from_waker(Waker::noop());
        loop {
            if let Poll::Ready(out) = f.as_mut().poll(&mut cx) {
                return out;
            }
        }
    }

    /// One step of a build: it runs until a unit finds `budget` spent by
    /// `clock` (milliseconds), or to its end. What it made if it ended, and
    /// the units the step did. A zero budget stops at the first unit, so
    /// every step does at least one, and the build always ends.
    pub fn step_by<F: Future + ?Sized>(
        f: Pin<&mut F>,
        budget: Duration,
        clock: fn() -> f64,
    ) -> (Option<F::Output>, u64) {
        let slice = Slice {
            start: clock(),
            budget: budget.as_secs_f64() * 1e3,
            units: 0,
            clock,
        };
        let restore = Restore(SLICE.with(|s| s.replace(Some(slice))));
        let out = f.poll(&mut Context::from_waker(Waker::noop()));
        let units = SLICE.with(|s| s.get()).map_or(0, |s| s.units);
        drop(restore);
        match out {
            Poll::Ready(out) => (Some(out), units),
            Poll::Pending => (None, units),
        }
    }

    /// `step_by` on this device's clock.
    pub fn step<F: Future + ?Sized>(f: Pin<&mut F>, budget: Duration) -> (Option<F::Output>, u64) {
        step_by(f, budget, clock_ms)
    }

    /// A monotonic clock in milliseconds.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn clock_ms() -> f64 {
        use std::sync::OnceLock;
        use std::time::Instant;
        static START: OnceLock<Instant> = OnceLock::new();
        START.get_or_init(Instant::now).elapsed().as_secs_f64() * 1e3
    }

    /// A monotonic clock in milliseconds: the page's `performance.now()`
    /// (`Instant` panics on wasm32), else its `Date.now()`. One import, read
    /// at every unit.
    #[cfg(target_arch = "wasm32")]
    pub fn clock_ms() -> f64 {
        page::performance_now().unwrap_or_else(|_| js_sys::Date::now())
    }

    #[cfg(target_arch = "wasm32")]
    mod page {
        use js_sys::wasm_bindgen::prelude::wasm_bindgen;
        use js_sys::wasm_bindgen::JsValue;

        #[wasm_bindgen(wasm_bindgen = js_sys::wasm_bindgen)]
        extern "C" {
            #[wasm_bindgen(catch, js_namespace = performance, js_name = now)]
            pub fn performance_now() -> Result<f64, JsValue>;
        }
    }
}

#[cfg(test)]
pub(crate) mod world {
    //! A relay and its keyholders in one, for the tests of the builders, the
    //! validator and past epochs: it asks dues, builds them honestly, checks
    //! them as the relay would, and takes what passes.

    use std::collections::{HashMap, HashSet};

    use libsignal_protocol::IdentityKeyPair;
    use zeroize::Zeroizing;

    use super::*;
    use crate::group_key::commit::{
        validate, Applied, Bad, Candidate, Due, DueKind, Exit, GroupView, HeadView, HolderRef,
        Joiner, Listed, Pair, ReplaceAsk,
    };
    use crate::group_key::ctx::MemberId;
    use crate::group_key::keys::{Endorsement, Origin, SeatPair};

    pub(crate) const T0: u64 = 1_800_000_000;
    pub(crate) const TEXT_ID: &str = "c:lounge-1";
    pub(crate) const VOICE_ID: &str = "r:00112233445566778899aabbccddeeff:7";

    pub(crate) fn same_ik(ik: &IdentityKeyPair) -> IdentityKeyPair {
        IdentityKeyPair::new(*ik.identity_key(), *ik.private_key())
    }

    pub(crate) fn raw_ik(ik: &IdentityKeyPair) -> [u8; 32] {
        ik.public_key().public_key_bytes().try_into().unwrap()
    }

    /// A member: its own seat pair, endorsed by its identity.
    pub(crate) struct Member {
        pub seat: SeatRef,
        pub pair: SeatPair,
        pub ik: IdentityKeyPair,
        pub endorsement: Endorsement,
    }

    impl Member {
        pub(crate) fn account(id: u8) -> Member {
            let m = MemberId::Account([id; 16]);
            Member::with(
                m,
                Origin::VaultSeat,
                m,
                IdentityKeyPair::generate(&mut crate::rng()),
                SeatPair::generate(),
            )
        }

        /// Account number `i`, for groups of more than 255.
        pub(crate) fn numbered(i: u32) -> Member {
            let mut a = [0xa0; 16];
            a[12..].copy_from_slice(&i.to_be_bytes());
            let m = MemberId::Account(a);
            Member::with(
                m,
                Origin::VaultSeat,
                m,
                IdentityKeyPair::generate(&mut crate::rng()),
                SeatPair::generate(),
            )
        }

        pub(crate) fn conn(u: u32) -> Member {
            let m = MemberId::Conn(u);
            Member::with(
                m,
                Origin::Connection,
                m,
                IdentityKeyPair::generate(&mut crate::rng()),
                SeatPair::generate(),
            )
        }

        fn with(
            m: MemberId,
            origin: Origin,
            named: MemberId,
            ik: IdentityKeyPair,
            pair: SeatPair,
        ) -> Member {
            let public = pair.public();
            let endorsement = Endorsement::sign(&ik, origin, named, 1, T0, &public).unwrap();
            Member {
                seat: public.seat(m),
                pair,
                ik,
                endorsement,
            }
        }

        pub(crate) fn ik_raw(&self) -> [u8; 32] {
            raw_ik(&self.ik)
        }

        pub(crate) fn joiner(&self) -> Joiner {
            Joiner {
                seat: self.seat,
                ik: self.ik_raw(),
                keys: self.pair.public(),
                endorsement: self.endorsement.clone(),
                returning: false,
            }
        }

        pub(crate) fn me(&self) -> Me<'_> {
            Me {
                m: self.seat.m,
                keys: &self.pair,
            }
        }
    }

    /// A keyholder: its pair endorsed for its entry, and its own member seat.
    pub(crate) struct Holder {
        pub m: MemberId,
        pub pair: SeatPair,
        pub ik: IdentityKeyPair,
        pub endorsement: Endorsement,
        pub seat: Member,
    }

    impl Holder {
        /// A desktop of account `id`: an 0x03 pair; its seat is the account's.
        pub(crate) fn desktop(id: u8) -> Holder {
            let m = MemberId::Account([id; 16]);
            let ik = IdentityKeyPair::generate(&mut crate::rng());
            let seat = Member::with(m, Origin::VaultSeat, m, same_ik(&ik), SeatPair::generate());
            Holder::with(m, Origin::Desktop, ik, SeatPair::generate(), seat, 1)
        }

        /// A connection keyholder of user `u`, whose seat pair is its
        /// keyholder pair.
        pub(crate) fn conn(u: u32) -> Holder {
            let m = MemberId::Conn(u);
            let ik = IdentityKeyPair::generate(&mut crate::rng());
            let pair = SeatPair::generate();
            let seat = Member::with(m, Origin::Connection, m, same_ik(&ik), pair.clone());
            Holder::with(m, Origin::Connection, ik, pair, seat, 1)
        }

        fn with(
            m: MemberId,
            origin: Origin,
            ik: IdentityKeyPair,
            pair: SeatPair,
            seat: Member,
            n: u32,
        ) -> Holder {
            let endorsement = Endorsement::sign(&ik, origin, m, n, T0, &pair.public()).unwrap();
            Holder {
                m,
                pair,
                ik,
                endorsement,
                seat,
            }
        }

        /// The same desktop after its account's seat-key rotation: a new
        /// pair, a higher counter, the same identity and seat.
        pub(crate) fn rotated(&self) -> Holder {
            let seat = Member {
                seat: self.seat.seat,
                pair: self.seat.pair.clone(),
                ik: same_ik(&self.ik),
                endorsement: self.seat.endorsement.clone(),
            };
            Holder::with(
                self.m,
                self.endorsement.origin,
                same_ik(&self.ik),
                SeatPair::generate(),
                seat,
                self.endorsement.n + 1,
            )
        }

        pub(crate) fn me(&self) -> Me<'_> {
            Me {
                m: self.m,
                keys: &self.pair,
            }
        }

        pub(crate) fn pair(&self) -> Pair {
            Pair {
                keys: self.pair.public(),
                endorsement: self.endorsement.clone(),
            }
        }

        pub(crate) fn candidate(&self) -> Candidate {
            Candidate {
                m: self.m,
                ik: raw_ik(&self.ik),
                pair: self.pair(),
            }
        }

        pub(crate) fn entry(&self, kind: GroupKind) -> Keyholder {
            self.pair().entry(kind, self.m, raw_ik(&self.ik)).unwrap()
        }

        pub(crate) fn by(&self) -> HolderRef {
            HolderRef {
                m: self.m,
                kx: self.pair().kx(),
            }
        }

        /// As a member meets it: what welcomes and rows from it open under.
        pub(crate) fn holder(&self) -> crate::group_key::keys::Holder {
            crate::group_key::keys::Holder::new(self.m, &self.pair.public().dh_bytes()).unwrap()
        }
    }

    pub(crate) struct World {
        pub kind: GroupKind,
        pub id: &'static str,
        pub stored: bool,
        pub g: Group,
        pub head: SignedHeader,
        pub kh: SignedHeader,
        pub leaves: Vec<Listed>,
        pub keys: HashMap<SeatRef, SeatPublic>,
        pub held: HashMap<SeatRef, u32>,
        pub used_v: HashSet<u64>,
        pub rolls: SeedRolls,
        pub gens: Vec<[u8; 16]>,
        pub ring: Keyring,
        pub krk: Zeroizing<[u8; 32]>,
        /// The set's keyholders; the first commits unless a test says.
        pub holders: Vec<Holder>,
        pub cache: RowBases,
        pub now: u64,
        pub roster: Vec<u32>,
        pub no_keyholder_since: Option<u64>,
        pub seq: u64,
        /// Whether an opening due brings the seats' KEM keys (`EpochDue.seed_seats`): an
        /// honest relay sends them with a voice Remove only.
        pub seed_keys: bool,
    }

    pub(crate) fn copy_ring(r: &Keyring) -> Keyring {
        Keyring {
            base: r.base.clone(),
            buckets: r.buckets.clone(),
        }
    }

    impl World {
        /// A text group with one desktop keyholder.
        pub(crate) fn text(stored: bool, gated: bool) -> World {
            World::start(GroupKind::Text, TEXT_ID, stored, gated, Holder::desktop(1))
        }

        /// A voice room with one connection keyholder, user 3.
        pub(crate) fn voice() -> World {
            World::start(GroupKind::Voice, VOICE_ID, false, false, Holder::conn(3))
        }

        pub(crate) fn genesis_due(holder: &Holder, gated: bool) -> Due {
            Due {
                joiners: vec![holder.seat.joiner()],
                volunteer: Some(holder.candidate()),
                ..Due::of(DueKind::Genesis, gated)
            }
        }

        pub(crate) fn build_start(
            holder: &Holder,
            kind: GroupKind,
            id: &str,
            stored: bool,
            due: &Due,
            now: u64,
            parent: Option<&SignedHeader>,
        ) -> Result<Built, BuildError> {
            let joiners: Vec<&Joiner> = due.joiners.iter().collect();
            let st = Start {
                kind,
                id,
                me: holder.me(),
                ik: &holder.ik,
                entry: holder.entry(kind),
                joiners: &joiners,
                gated: due.gated,
                stored,
                now,
            };
            match parent {
                None => build_genesis(&st, &mut RowBases::new()),
                Some(p) => {
                    build_regenesis(&st, p, &due.exits, due.exits_upto, &mut RowBases::new())
                }
            }
        }

        /// The relay's view of a group with no generation yet.
        #[allow(clippy::too_many_arguments)]
        pub(crate) fn check_start(
            kind: GroupKind,
            id: &str,
            stored: bool,
            due: &Due,
            by: HolderRef,
            c: &Commit,
            now: u64,
            roster: &[u32],
        ) -> Result<Applied, Bad> {
            let held = |_: &SeatRef| None;
            let used = |_: u64| false;
            let view = GroupView {
                kind,
                id,
                stored,
                head: None,
                leaves: &[],
                dh: &|_| None,
                held: &held,
                due,
                by,
                rolls: SeedRolls {
                    raised: 0,
                    removal: false,
                },
                known_gens: &[],
                used_v: &used,
                now,
                roster,
                no_keyholder_since: None,
            };
            validate(&view, c)
        }

        pub(crate) fn start(
            kind: GroupKind,
            id: &'static str,
            stored: bool,
            gated: bool,
            holder: Holder,
        ) -> World {
            let due = World::genesis_due(&holder, gated);
            let built = World::build_start(&holder, kind, id, stored, &due, T0, None).unwrap();
            let roster: Vec<u32> = match holder.m {
                MemberId::Conn(u) => vec![u],
                _ => vec![],
            };
            let a = World::check_start(
                kind,
                id,
                stored,
                &due,
                holder.by(),
                &built.commit,
                T0,
                &roster,
            )
            .unwrap();
            let h = a.header.header();
            let mut w = World {
                kind,
                id,
                stored,
                g: Group::new(kind, id, h.gen).unwrap(),
                head: a.header.clone(),
                kh: a.header.clone(),
                leaves: vec![],
                keys: HashMap::new(),
                held: HashMap::new(),
                used_v: HashSet::new(),
                rolls: a.rolls,
                gens: vec![],
                ring: copy_ring(&built.ring),
                krk: built.krk.clone(),
                holders: vec![holder],
                cache: RowBases::new(),
                now: T0,
                roster,
                no_keyholder_since: None,
                seq: 0,
                seed_keys: true,
            };
            w.take(&due, a, &built);
            w
        }

        pub(crate) fn tick(&mut self, secs: u64) {
            self.now += secs;
        }

        pub(crate) fn gated(&self) -> bool {
            self.head.header().gated
        }

        pub(crate) fn due(&self, kind: DueKind) -> Due {
            Due::of(kind, self.gated())
        }

        /// The relay's view of the group, as `validate` takes it.
        pub(crate) fn view_with<R>(
            &self,
            due: &Due,
            by: HolderRef,
            f: impl FnOnce(&GroupView) -> R,
        ) -> R {
            let held = |s: &SeatRef| self.held.get(s).copied();
            let used = |v: u64| self.used_v.contains(&v);
            let view = GroupView {
                kind: self.kind,
                id: self.id,
                stored: self.stored,
                head: Some(HeadView {
                    head: &self.head,
                    kh: &self.kh,
                }),
                leaves: &self.leaves,
                dh: &|s| seat_dh(&self.keys.get(s)?.dh_bytes()),
                held: &held,
                due,
                by,
                rolls: self.rolls,
                known_gens: &self.gens,
                used_v: &used,
                now: self.now,
                roster: &self.roster,
                no_keyholder_since: self.no_keyholder_since,
            };
            f(&view)
        }

        pub(crate) fn check(&self, due: &Due, by: HolderRef, c: &Commit) -> Result<Applied, Bad> {
            self.view_with(due, by, |v| validate(v, c))
        }

        /// What the relay keeps once it took `a`, and the keyholder its keyring.
        pub(crate) fn take(&mut self, due: &Due, a: Applied, b: &Built) {
            let h = a.header.header().clone();
            if !self.gens.contains(&h.gen) {
                self.gens.push(h.gen);
                self.used_v.clear();
                self.g = Group::new(self.kind, self.id, h.gen).unwrap();
                self.cache = RowBases::new();
            }
            let gone: HashSet<Version> = a.gone.iter().copied().collect();
            self.leaves.retain(|l| !gone.contains(&l.version()));
            self.leaves.extend(a.made.iter().cloned());
            self.leaves.sort_by_key(|l| l.leaf.b);
            for j in &due.joiners {
                self.keys.insert(j.seat, j.keys.clone());
            }
            if h.kind.starts_anew() {
                self.held.clear();
            }
            for s in &a.removed {
                self.held.remove(s);
            }
            for (s, n) in &a.held {
                self.held.insert(*s, *n);
            }
            for m in &a.made {
                self.used_v.insert(m.leaf.v);
            }
            self.rolls = a.rolls;
            if h.kind.sets_keyholders() {
                self.kh = a.header.clone();
            }
            self.head = a.header;
            self.ring = copy_ring(&b.ring);
            self.krk = b.krk.clone();
            self.tick(3);
        }

        /// Checks `b` as the relay would for `due`, from holder `i`, and takes it.
        pub(crate) fn step_by(&mut self, i: usize, due: &Due, b: &Built) {
            let a = self
                .check(due, self.holders[i].by(), &b.commit)
                .unwrap_or_else(|bad| panic!("{bad}"));
            self.take(due, a, b);
        }

        pub(crate) fn step(&mut self, due: &Due, b: &Built) {
            self.step_by(0, due, b)
        }

        pub(crate) fn lists(&self) -> Lists {
            self.leaves
                .iter()
                .map(|l| {
                    let seats = l
                        .seats
                        .iter()
                        .map(|s| ListSeat {
                            seat: *s,
                            dh: self.keys[s].dh_bytes().to_vec(),
                        })
                        .collect();
                    (l.version(), seats)
                })
                .collect()
        }

        pub(crate) fn with_holding<R>(
            &mut self,
            i: usize,
            f: impl FnOnce(&Holding, &mut RowBases, &World) -> R,
        ) -> R {
            let mut cache = std::mem::take(&mut self.cache);
            let this: &World = self;
            let lists = this.lists();
            let held = |s: &SeatRef| this.held.get(s).copied();
            let k = &this.holders[i];
            let hold = Holding {
                g: &this.g,
                head: &this.head,
                kh: &this.kh,
                ring: &this.ring,
                krk: &this.krk,
                me: k.me(),
                ik: &k.ik,
                lists: &lists,
                held: &held,
                rolls: this.rolls,
                stored: this.stored,
            };
            let r = f(&hold, &mut cache, this);
            self.cache = cache;
            r
        }

        pub(crate) fn join_due(&self, members: &[&Member]) -> Due {
            Due {
                joiners: members.iter().map(|m| m.joiner()).collect(),
                ..self.due(DueKind::Join)
            }
        }

        pub(crate) fn build_join(
            &mut self,
            due: &Due,
            reuse: Option<&Built>,
        ) -> Result<Built, BuildError> {
            self.with_holding(0, |hold, cache, w| {
                let js: Vec<&Joiner> = due.joiners.iter().collect();
                build_join(hold, &js, vec![], w.now, cache, reuse)
            })
        }

        /// Seats `members` by an honest Join, and gives back what was built.
        pub(crate) fn join(&mut self, members: &[&Member]) -> Built {
            let due = self.join_due(members);
            let b = self.build_join(&due, None).unwrap();
            for m in members {
                if let MemberId::Conn(u) = m.seat.m {
                    self.roster.push(u);
                }
            }
            self.step(&due, &b);
            b
        }

        pub(crate) fn pair_of(&self, k: &Keyholder) -> Option<SeatPublic> {
            self.holders
                .iter()
                .find(|h| h.by() == HolderRef::of(k))
                .map(|h| h.pair.public())
        }

        pub(crate) fn opening_by(
            &mut self,
            i: usize,
            due: &Due,
            finish: bool,
            replacing: Option<&Holder>,
            reuse: Option<&Built>,
        ) -> Result<Built, BuildError> {
            self.opening_with(i, due, finish, replacing, |hold, ask, cache| {
                build_opening(hold, ask, cache, reuse)
            })
        }

        /// `opening_by`'s holding and ask, handed to `run` (a builder whole or in steps).
        pub(crate) fn opening_with<R>(
            &mut self,
            i: usize,
            due: &Due,
            finish: bool,
            replacing: Option<&Holder>,
            run: impl FnOnce(&Holding, &OpeningAsk, &mut RowBases) -> R,
        ) -> R {
            self.with_holding(i, |hold, cache, w| {
                let pairs = |k: &Keyholder| w.pair_of(k);
                let replace = replacing.map(|r| Replacing {
                    me: r.me(),
                    entry: r.entry(w.kind),
                });
                let none = HashMap::new();
                let ask = OpeningAsk {
                    kind: due.kind.header_kind(),
                    exits: &due.exits,
                    exits_upto: due.exits_upto,
                    refresh: due.kind == DueKind::Refresh,
                    gated: due.gated,
                    candidate: due.candidate.as_ref(),
                    remove: due.remove,
                    replace,
                    finish,
                    seed_seats: if w.seed_keys { &w.keys } else { &none },
                    pairs: &pairs,
                    now: w.now,
                };
                run(hold, &ask, cache)
            })
        }

        pub(crate) fn opening(&mut self, due: &Due) -> Result<Built, BuildError> {
            self.opening_by(0, due, false, None, None)
        }

        /// Builds and takes an honest opening for `due`.
        pub(crate) fn open(&mut self, due: &Due) -> Built {
            let b = self.opening(due).unwrap();
            self.step(due, &b);
            b
        }

        pub(crate) fn bucket_of(&self, s: &SeatRef) -> u64 {
            self.leaves
                .iter()
                .find(|l| l.seats.contains(s))
                .expect("seated")
                .leaf
                .b
        }

        /// An opening due of `kind` carrying the exits of `seats`.
        pub(crate) fn exits(&mut self, seats: &[SeatRef], kind: DueKind) -> Due {
            let mut exits = Vec::new();
            for s in seats {
                self.seq += 1;
                exits.push(Exit {
                    seq: self.seq,
                    seat: *s,
                    b: self.bucket_of(s),
                });
            }
            Due {
                exits,
                exits_upto: self.seq,
                ..self.due(kind)
            }
        }

        pub(crate) fn promote_due(&self, cand: &Holder) -> Due {
            Due {
                candidate: Some(cand.candidate()),
                ..self.due(DueKind::Promote)
            }
        }

        /// Promotes `cand` by an honest KeyholdersAdd from holder 0.
        pub(crate) fn promote(&mut self, cand: Holder) -> Built {
            let due = self.promote_due(&cand);
            if let MemberId::Conn(u) = cand.m {
                if !self.roster.contains(&u) {
                    self.roster.push(u);
                }
            }
            let b = self.opening(&due).unwrap();
            self.step(&due, &b);
            self.holders.push(cand);
            b
        }

        pub(crate) fn remove_due(&self, i: usize) -> Due {
            Due {
                remove: Some(self.holders[i].by()),
                ..self.due(DueKind::Remove)
            }
        }

        /// Removes holder `i` by an honest KeyholdersRemove from holder 0.
        pub(crate) fn remove(&mut self, i: usize) -> Built {
            let due = self.remove_due(i);
            let b = self.opening(&due).unwrap();
            self.step(&due, &b);
            self.holders.remove(i);
            b
        }

        pub(crate) fn replace_due(&self, new: &Holder) -> Due {
            Due {
                replace: Some(ReplaceAsk {
                    old: kx_tag(&self.holders[0].by().kx),
                    pair: new.pair(),
                }),
                ..self.due(DueKind::Replace)
            }
        }

        /// Every seat's seed welcome under the head's seed, stored: what the
        /// seed-welcome pages of a running roll end with.
        pub(crate) fn welcome_every_seat(&mut self) {
            let s = self.head.header().seed;
            let seats: Vec<(SeatRef, SeatPublic)> = self
                .held
                .iter()
                .filter(|(_, n)| **n < s)
                .map(|(seat, _)| (*seat, self.keys[seat].clone()))
                .collect();
            let seed = Zeroizing::new(*self.ring.seed(s).unwrap());
            let out =
                build_seed_welcomes(&self.g, s, &seed, &self.holders[0].me(), &seats).unwrap();
            for w in out {
                self.held.insert(w.seat, s);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::world::*;
    use super::*;
    use crate::group_key::commit::{Due, DueKind};
    use crate::group_key::derive::{confirm_ok, open_seal, ratchet};
    use crate::group_key::keyring::take_keyring;
    use crate::group_key::merkle::inclusion_path;
    use crate::group_key::tree::BucketTree;
    use crate::group_key::welcome::{open_keyring_welcome, open_seat_welcome, open_seed_welcome};
    use crate::group_key::{ROLL_GAP, SEED_MAX_AGE};

    fn accounts(from: u32, n: u32) -> Vec<Member> {
        (from..from + n).map(Member::numbered).collect()
    }

    fn refs(ms: &[Member]) -> Vec<&Member> {
        ms.iter().collect()
    }

    #[test]
    fn a_genesis_join_and_exits_build_commits_the_relay_takes() {
        let mut w = World::text(true, false);
        assert_eq!(w.head.header().kind, Kind::Genesis);
        assert_eq!(w.leaves.len(), 1);
        let people = accounts(10, 70);
        let guests: Vec<Member> = (100..103).map(Member::conn).collect();
        let b = w.join(&refs(&people));
        assert_eq!(b.made.len(), 2, "70 accounts make buckets of 62 and 8");
        assert!(
            b.made.iter().all(|m| m.rows.is_some()),
            "a stored Join rows every account"
        );
        w.join(&refs(&guests));
        assert_eq!(w.head.header().seats, 1 + 70 + 3);
        assert_eq!(w.head.header().conn_seats, 3);
        let leaving = [people[0].seat, people[69].seat, guests[1].seat];
        let due = w.exits(&leaving, DueKind::Exits);
        w.open(&due);
        let h = w.head.header();
        assert_eq!(
            (h.kind, h.epoch, h.seats, h.exits_upto),
            (Kind::Fresh, 2, 71, 3)
        );
        assert!(!w
            .leaves
            .iter()
            .any(|l| leaving.iter().any(|s| l.seats.contains(s))));
    }

    #[test]
    fn a_refresh_promotion_removal_and_replacement_build_commits_the_relay_takes() {
        let mut w = World::text(true, false);
        let people = accounts(10, 40);
        w.join(&refs(&people));
        let due = w.due(DueKind::Refresh);
        w.open(&due);
        w.promote(Holder::desktop(2));
        assert_eq!(w.kh.header().keyholders.len(), 2);
        let new = w.holders[0].rotated();
        let due = w.replace_due(&new);
        let b = w.opening_by(0, &due, false, Some(&new), None).unwrap();
        w.step(&due, &b);
        w.holders[0] = new;
        assert_eq!(w.head.header().kind, Kind::KeyholdersReplace);
        w.remove(1);
        assert_eq!(w.kh.header().keyholders.len(), 1);
        assert_eq!(w.head.header().kind, Kind::KeyholdersRemove);
        let due = w.due(DueKind::Exits);
        w.open(&due);
    }

    #[test]
    fn a_regenesis_builds_a_commit_the_relay_takes_after_an_hour() {
        let mut w = World::text(true, false);
        w.join(&refs(&accounts(10, 5)));
        let vol = Holder::desktop(9);
        let due = Due {
            joiners: vec![vol.seat.joiner()],
            volunteer: Some(vol.candidate()),
            ..w.due(DueKind::Regenesis)
        };
        let head = w.head.clone();
        // The set in force holds a desktop's pair, which the builder does not see under a
        // Join head: it makes the commit (the shortest wait, none since J10-B, owner
        // 2026-11-22), and the volunteer's own check refuses it, a minute on or half an hour
        let hour = Some((
            4,
            r#"Generation("a Regenesis comes an hour after its parent")"#.to_string(),
        ));
        w.tick(60);
        let early = World::build_start(&vol, w.kind, w.id, true, &due, w.now, Some(&head)).unwrap();
        w.no_keyholder_since = Some(w.now - 60);
        assert_eq!(
            w.check(&due, vol.by(), &early.commit)
                .err()
                .map(|b| (b.rule, b.detail)),
            hour
        );
        w.tick(1740);
        let early = World::build_start(&vol, w.kind, w.id, true, &due, w.now, Some(&head)).unwrap();
        w.no_keyholder_since = Some(w.now - 1800);
        assert_eq!(
            w.check(&due, vol.by(), &early.commit)
                .err()
                .map(|b| (b.rule, b.detail)),
            hour
        );
        w.tick(1800);
        w.no_keyholder_since = Some(w.now - 3600);
        let b = World::build_start(&vol, w.kind, w.id, true, &due, w.now, Some(&head)).unwrap();
        w.holders = vec![vol];
        w.step(&due, &b);
        let h = w.head.header();
        assert_eq!(
            (h.kind, h.seed, h.seed_floor, h.seats),
            (Kind::Regenesis, 2, 2, 1)
        );
        assert_eq!(
            w.leaves.len(),
            1,
            "everyone else is re-seated as they fetch"
        );
    }

    #[test]
    fn a_voice_room_builds_its_commits_and_a_removal_rolls_the_seed_at_once() {
        let mut w = World::voice();
        let people: Vec<Member> = (10..20).map(Member::conn).collect();
        w.join(&refs(&people));
        w.promote(Holder::conn(4));
        w.remove(1);
        let h = w.head.header();
        assert_eq!(
            (h.seed, h.seed_floor),
            (2, 1),
            "a voice removal starts a roll at once"
        );
        w.promote(Holder::conn(5));
        let b = w.remove(1);
        let h = w.head.header();
        assert_eq!((h.seed, h.seed_floor), (3, 2));
        assert_eq!(
            b.commit.seed_welcomes.len(),
            11,
            "every seat still on seed 1 gets its seed welcome in the commit"
        );
        assert!(w.held.values().all(|&s| s >= 2));
    }

    #[test]
    fn a_gated_group_builds_its_commits_with_their_names() {
        let mut w = World::text(true, true);
        let people = accounts(10, 5);
        let b = w.join(&refs(&people));
        assert_eq!(b.header.header().added_list().len(), 5);
        assert_ne!(w.head.header().names_hash, [0; 32]);
        let due = w.exits(&[people[2].seat], DueKind::Exits);
        let b = w.open(&due);
        assert_eq!(
            b.header.header().removed,
            crate::group_key::header::Removed::List(vec![people[2].seat])
        );
    }

    #[test]
    fn turning_gated_on_is_built_only_once_no_connections_bucket_is_left() {
        let mut w = World::text(true, false);
        let guests: Vec<Member> = (100..104).map(Member::conn).collect();
        w.join(&refs(&accounts(10, 3)));
        w.join(&refs(&guests));
        let gate = Due {
            gated: true,
            ..w.due(DueKind::Gate)
        };
        assert_eq!(
            w.opening(&gate).err(),
            Some(BuildError::Refuse(
                "a gated header while a connections bucket is left"
            ))
        );
        let seats: Vec<SeatRef> = guests.iter().map(|g| g.seat).collect();
        let due = w.exits(&seats, DueKind::Exits);
        w.open(&due);
        w.tick(2);
        w.open(&gate);
        assert!(w.head.header().gated);
        assert_eq!(w.head.header().conn_seats, 0);
    }

    #[test]
    fn members_open_their_welcome_row_ratchet_and_seal_and_confirm_passes() {
        let mut w = World::text(true, false);
        let alice = Member::account(10);
        let joined = w.join(&[&alice]);
        let k = w.holders[0].holder();
        let at_of = |b: &Built| {
            let m = b
                .made
                .iter()
                .find(|m| m.seats.contains(&alice.seat))
                .unwrap();
            m.bucket.version()
        };
        // The welcome, made with the agreement its row base shares.
        let at = at_of(&joined);
        let wel = joined
            .commit
            .welcomes
            .iter()
            .find(|x| x.seat == alice.seat)
            .unwrap();
        let (s_m, bk) = open_seat_welcome(&w.g, 1, at, &alice.me(), &k, &wel.bytes).unwrap();
        let seal_of = |b: &Built, at: Version| {
            b.commit
                .seals
                .iter()
                .find(|s| (s.b, s.v) == (at.b, at.v))
                .unwrap()
                .bytes
                .clone()
        };
        let ep = |b: &Built| crate::group_key::ctx::Epoch {
            e: b.header.header().epoch,
            d_e: b.header.d_e(),
        };
        let ck = open_seal(&w.g, &ep(&joined), at, &bk, &seal_of(&joined, at)).unwrap();
        let h = joined.header.header();
        assert!(confirm_ok(&w.g, h.epoch, h.join, &ck, &h.confirm));
        // The stored Join's row opens to the same key from the member's side.
        let rows = joined
            .made
            .iter()
            .find_map(|m| m.rows.clone().filter(|r| (r.b, r.v) == (at.b, at.v)))
            .unwrap();
        let i = joined
            .made
            .iter()
            .find(|m| m.bucket.version() == at)
            .unwrap()
            .seats
            .iter()
            .position(|s| *s == alice.seat)
            .unwrap();
        let rb = RowBase::member_side(&w.g, 1, &alice.me(), &k, &s_m).unwrap();
        assert_eq!(*rb.open_row(at, rows.row(i).unwrap().0).unwrap(), *bk);
    }

    #[test]
    fn a_ratchet_and_a_rekey_reach_the_member_and_open_the_seal() {
        let mut w = World::text(true, false);
        let alice = Member::account(10);
        let joined = w.join(&[&alice]);
        let k = w.holders[0].holder();
        let at = joined.made[0].bucket.version();
        let wel = &joined.commit.welcomes[0];
        let (s_m, bk) = open_seat_welcome(&w.g, 1, at, &alice.me(), &k, &wel.bytes).unwrap();

        let add = w.promote(Holder::desktop(2));
        let ratcheted = add
            .made
            .iter()
            .find(|m| m.seats.contains(&alice.seat))
            .unwrap();
        let e = add.header.header().epoch;
        let bk2 = ratchet(&w.g, e, at, ratcheted.bucket.v, &bk);
        let at2 = ratcheted.bucket.version();
        let seal = add
            .commit
            .seals
            .iter()
            .find(|s| (s.b, s.v) == (at2.b, at2.v))
            .unwrap();
        let ep = crate::group_key::ctx::Epoch {
            e,
            d_e: add.header.d(),
        };
        let ck = open_seal(&w.g, &ep, at2, &bk2, &seal.bytes).unwrap();
        assert_eq!(*ck, *add.ck);
        assert!(confirm_ok(&w.g, e, 0, &ck, &add.header.header().confirm));

        let rem = w.remove(1);
        let m = rem
            .made
            .iter()
            .find(|m| m.seats.contains(&alice.seat))
            .unwrap();
        let at3 = m.bucket.version();
        let i = m.seats.iter().position(|s| *s == alice.seat).unwrap();
        let (row, s) = m.rows.as_ref().unwrap().row(i).unwrap();
        assert_eq!(s, 1);
        let rb = RowBase::member_side(&w.g, 1, &alice.me(), &k, &s_m).unwrap();
        let bk3 = rb.open_row(at3, row).unwrap();
        let seal = rem
            .commit
            .seals
            .iter()
            .find(|s| (s.b, s.v) == (at3.b, at3.v))
            .unwrap();
        let e3 = rem.header.header().epoch;
        let ep = crate::group_key::ctx::Epoch {
            e: e3,
            d_e: rem.header.d(),
        };
        let ck = open_seal(&w.g, &ep, at3, &bk3, &seal.bytes).unwrap();
        assert!(confirm_ok(&w.g, e3, 0, &ck, &rem.header.header().confirm));
    }

    #[test]
    fn a_keyholder_takes_the_keyring_every_build_uploads() {
        let mut w = World::text(true, false);
        w.join(&refs(&accounts(10, 30)));
        let add = w.promote(Holder::desktop(2));
        let second = &w.holders[1];
        let ks = keyholder_set_digest(&add.header.header().keyholders);
        let welcome = add.commit.krk.iter().find(|k| k.to == second.by()).unwrap();
        let e = add.header.header().epoch;
        let krk = open_keyring_welcome(
            &w.g,
            add.header.header().seed,
            e,
            &ks,
            &second.me(),
            &w.holders[0].holder(),
            &welcome.bytes,
        )
        .unwrap();
        assert_eq!(*krk, *add.krk);
        let ring = take_keyring(
            &w.g,
            &add.header,
            &add.header,
            &krk,
            &add.commit.keyring,
            &[],
        )
        .unwrap();
        assert_eq!(ring.buckets.len(), add.ring.buckets.len());
        assert_eq!(*ring.ck(), *add.ck);
        let joined = w.join(&refs(&accounts(50, 3)));
        let ring = take_keyring(
            &w.g,
            &joined.header,
            &w.kh,
            &krk,
            &add.commit.keyring,
            std::slice::from_ref(&joined.commit.keyring),
        )
        .unwrap();
        assert_eq!(ring.buckets.len(), joined.ring.buckets.len());
    }

    #[test]
    fn merge_and_repack_stay_within_their_bounds() {
        // 165 small buckets of 15 seats: the most that builds up (§5.3).
        let mut buckets: Vec<BucketNow> = (0..165u64)
            .map(|b| BucketNow {
                b,
                v: b + 1000,
                pool: Pool::Accounts,
                seats: 15,
                made: T0,
                exits: 0,
            })
            .collect();
        let plan = plan_opening(Kind::Fresh, &buckets, false, T0);
        assert!(plan.steps.iter().all(|s| *s == Step::Merge(0)));
        assert_eq!(plan.rows(&buckets), 2475, "at most 165 × 15 merge rows");
        assert_eq!(plan.pack_buckets(&buckets), 40);
        // 15 small buckets merge nothing.
        buckets.truncate(15);
        let plan = plan_opening(Kind::Fresh, &buckets, false, T0);
        assert!(plan.steps.iter().all(|s| *s == Step::Same));
        // Too many half-full buckets: one repack of at most 62 rows.
        let half: Vec<BucketNow> = (0..60u64)
            .map(|b| BucketNow {
                b,
                v: b + 1000,
                pool: Pool::Accounts,
                seats: 20 + (b % 5) as u16,
                made: T0,
                exits: 0,
            })
            .collect();
        let plan = plan_opening(Kind::Fresh, &half, false, T0);
        assert!(
            plan.rows(&half) <= 62 && plan.rows(&half) > 0,
            "{}",
            plan.rows(&half)
        );
        assert_eq!(plan.packs.len(), 1);
        assert!(plan.steps.iter().filter(|s| **s == Step::Merge(0)).count() >= 2);
        // A promotion merges nothing and ratchets the rest.
        let plan = plan_opening(Kind::KeyholdersAdd, &half, false, T0);
        assert!(plan.steps.iter().all(|s| *s == Step::Ratchet));
        // Pools never mix.
        let mixed: Vec<BucketNow> = (0..32u64)
            .map(|b| BucketNow {
                b,
                v: b,
                pool: if b % 2 == 0 {
                    Pool::Accounts
                } else {
                    Pool::Conns
                },
                seats: 3,
                made: T0,
                exits: 0,
            })
            .collect();
        let plan = plan_opening(Kind::Fresh, &mixed, false, T0);
        assert_eq!(plan.packs, vec![Pool::Accounts, Pool::Conns]);
    }

    #[test]
    fn a_refresh_rekeys_at_least_a_twelfth_and_every_version_over_an_hour() {
        let buckets: Vec<BucketNow> = (0..30u64)
            .map(|b| BucketNow {
                b,
                v: b,
                pool: Pool::Accounts,
                seats: 62,
                made: T0 + b,
                exits: 0,
            })
            .collect();
        let plan = plan_opening(Kind::Fresh, &buckets, true, T0 + 100);
        assert_eq!(plan.by_rows(&buckets), 3, "⌈30 / 12⌉");
        assert_eq!(&plan.steps[..3], &[Step::ReKey; 3], "the oldest first");
        let plan = plan_opening(Kind::Fresh, &buckets, false, T0 + 100);
        assert_eq!(plan.by_rows(&buckets), 0);
        let plan = plan_opening(Kind::Fresh, &buckets, false, T0 + 3600 + 10);
        assert_eq!(plan.by_rows(&buckets), 10, "versions over an hour old");
        let plan = plan_opening(Kind::KeyholdersRemove, &buckets, false, T0);
        assert_eq!(plan.by_rows(&buckets), 30, "a removal re-keys every bucket");

        // And what the builder makes from it passes the validator's slice.
        let mut w = World::text(true, false);
        for i in 0..4 {
            w.join(&refs(&accounts(10 + i * 62, 62)));
        }
        let due = w.due(DueKind::Refresh);
        let b = w.open(&due);
        let by_rows = b.made.iter().filter(|m| m.rows.is_some()).count();
        assert!(by_rows >= w.leaves.len().div_ceil(12));
        w.tick(3700);
        let due = w.due(DueKind::Exits);
        let b = w.open(&due);
        assert_eq!(
            b.made.len(),
            w.leaves.len(),
            "every version over an hour old"
        );
    }

    #[test]
    fn a_rebase_reuses_only_versions_the_winner_did_not_touch() {
        let mut w = World::text(true, false);
        let a = accounts(10, 62);
        let b = accounts(80, 62);
        w.join(&refs(&a));
        w.join(&refs(&b));
        w.promote(Holder::desktop(2));
        // Both keyholders build an opening for different exits on one head.
        let mine = w.exits(&[a[0].seat], DueKind::Exits);
        let theirs = w.exits(&[b[0].seat], DueKind::Exits);
        let stale = w.opening_by(0, &mine, false, None, None).unwrap();
        let winner = w.opening_by(1, &theirs, false, None, None).unwrap();
        w.step_by(1, &theirs, &winner);
        // Rebase: the exits not yet dealt with, onto the winner's head.
        let again = Due {
            exits_upto: mine.exits_upto,
            ..mine.clone()
        };
        let rebased = w.opening_by(0, &again, false, None, Some(&stale)).unwrap();
        let in_a = |m: &Made| m.seats.contains(&a[1].seat);
        let in_b = |m: &Made| m.seats.contains(&b[1].seat);
        let s_a = stale.made.iter().find(|m| in_a(m)).unwrap();
        let r_a = rebased.made.iter().find(|m| in_a(m)).unwrap();
        assert_eq!(
            s_a.bucket.version(),
            r_a.bucket.version(),
            "untouched: reused"
        );
        assert_eq!(*s_a.bucket.bk, *r_a.bucket.bk);
        assert_eq!(s_a.rows, r_a.rows);
        assert!(
            !rebased.made.iter().any(in_b),
            "the winner re-keyed b already"
        );
        assert_ne!(*rebased.ck, *stale.ck, "a new CK every attempt");
        w.step(&again, &rebased);

        // A promotion's ratchets are never reused: a ratchet binds its epoch.
        let d1 = w.promote_due(&Holder::desktop(3));
        let stale = w.opening_by(0, &d1, false, None, None).unwrap();
        assert!(stale
            .made
            .iter()
            .all(|m| matches!(m.bucket.via, Via::Ratchet { .. })));
        let old: HashSet<u64> = stale.made.iter().map(|m| m.bucket.v).collect();
        let again = w.opening_by(0, &d1, false, None, Some(&stale)).unwrap();
        assert!(again.made.iter().all(|m| !old.contains(&m.bucket.v)));
    }

    #[test]
    fn a_rebase_after_the_winner_rolled_the_seed_makes_everything_again() {
        let mut w = World::text(true, false);
        let a = accounts(10, 20);
        w.join(&refs(&a));
        w.promote(Holder::desktop(2));
        w.promote(Holder::desktop(3));
        w.tick(25 * 3600);
        let mine = w.exits(&[a[0].seat], DueKind::Exits);
        let stale = w.opening_by(0, &mine, false, None, None).unwrap();
        let rm = w.remove_due(2);
        let winner = w.opening_by(1, &rm, false, None, None).unwrap();
        w.step_by(1, &rm, &winner);
        w.holders.remove(2);
        assert_eq!(w.head.header().seed, 2, "the winner rolled");
        let rebased = w.opening_by(0, &mine, false, None, Some(&stale)).unwrap();
        let old: HashSet<u64> = stale.made.iter().map(|m| m.bucket.v).collect();
        assert!(rebased.made.iter().all(|m| !old.contains(&m.bucket.v)));
        w.step(&mine, &rebased);
    }

    #[test]
    fn a_join_rebased_onto_a_new_epoch_names_its_seats_again_with_the_same_welcomes() {
        let mut w = World::text(false, false);
        w.join(&refs(&accounts(10, 3)));
        let late = accounts(40, 4);
        let due = w.join_due(&refs(&late));
        let stale = w.build_join(&due, None).unwrap();
        let fresh = w.due(DueKind::Refresh);
        w.open(&fresh);
        let rebased = w.build_join(&due, Some(&stale)).unwrap();
        assert_eq!(stale.commit.welcomes, rebased.commit.welcomes);
        assert_ne!(
            stale.commit.seals, rebased.commit.seals,
            "sealed to the new epoch's CK"
        );
        assert_eq!(stale.sealed_to, rebased.sealed_to);
        w.step(&due, &rebased);
    }

    /// Each seat a commit gives a seed welcome opens its row under the
    /// `s_m` that welcome carries.
    fn rows_open_under_the_seed_welcomes(w: &World, b: &Built, people: &[Member]) {
        let k = w.holders[0].holder();
        let s = b.header.header().seed;
        let mut opened = 0;
        for p in people {
            let Some(wel) = b.commit.seed_welcomes.iter().find(|x| x.seat == p.seat) else {
                continue;
            };
            let s_m = open_seed_welcome(&w.g, s, &p.me(), &k, &wel.bytes).unwrap();
            let m = b.made.iter().find(|m| m.seats.contains(&p.seat)).unwrap();
            let i = m.seats.iter().position(|x| *x == p.seat).unwrap();
            let (row, under) = m.rows.as_ref().unwrap().row(i).unwrap();
            assert_eq!(under, u64::from(s));
            let rb = RowBase::member_side(&w.g, s, &p.me(), &k, &s_m).unwrap();
            let bk = rb
                .open_row(m.bucket.version(), row)
                .expect("the row opens under the seed its welcome gave");
            assert_eq!(*bk, *m.bucket.bk);
            opened += 1;
        }
        assert!(opened > 0);
    }

    #[test]
    fn an_attempt_that_rolled_makes_its_rows_again_under_the_seed_it_draws_next() {
        // A voice room with a roll running: the next removal starts another,
        // and every seat still on seed 1 gets its seed welcome under 3.
        let mut w = World::voice();
        let first: Vec<Member> = (10..20).map(Member::conn).collect();
        let second: Vec<Member> = (30..40).map(Member::conn).collect();
        w.join(&refs(&first));
        w.join(&refs(&second));
        w.promote(Holder::conn(4));
        w.remove(1);
        w.promote(Holder::conn(5));
        let rm = w.remove_due(1);
        let stale = w.opening_by(0, &rm, false, None, None).unwrap();
        assert_eq!(stale.header.header().seed, 3);
        assert!(!stale.commit.seed_welcomes.is_empty());
        // An exit Fresh from the other keyholder wins.
        let ex = w.exits(&[first[0].seat], DueKind::Exits);
        let winner = w.opening_by(1, &ex, false, None, None).unwrap();
        w.step_by(1, &ex, &winner);
        let everyone: Vec<Member> = first.into_iter().skip(1).chain(second).collect();

        // The rebase reuses the untouched bucket's id and BK, not its rows.
        let rebased = w.opening_by(0, &rm, false, None, Some(&stale)).unwrap();
        assert_ne!(stale.ring.seed(3), rebased.ring.seed(3));
        let who = &everyone[12];
        let find = |b: &Built| {
            b.made
                .iter()
                .find(|m| m.seats.contains(&who.seat))
                .unwrap()
                .clone()
        };
        let (was, now) = (find(&stale), find(&rebased));
        assert_eq!(was.bucket.version(), now.bucket.version());
        assert_eq!(*was.bucket.bk, *now.bucket.bk);
        assert_ne!(was.rows, now.rows);
        w.check(&rm, w.holders[0].by(), &rebased.commit).unwrap();
        rows_open_under_the_seed_welcomes(&w, &rebased, &everyone);

        // A retry with nothing to reuse makes no row from the lost draw,
        // though the keyholder's row bases were made under it.
        let retry = w.opening_by(0, &rm, false, None, None).unwrap();
        w.check(&rm, w.holders[0].by(), &retry.commit).unwrap();
        rows_open_under_the_seed_welcomes(&w, &retry, &everyone);
        w.step(&rm, &retry);
    }

    fn seeds(b: &Built) -> (u32, u32) {
        let h = b.header.header();
        (h.seed, h.seed_floor)
    }

    /// The seeds a commit's rows are under.
    fn rows_under(b: &Built) -> HashSet<u64> {
        b.made
            .iter()
            .filter_map(|m| m.rows.as_ref().map(|r| (r, m.seats.len())))
            .flat_map(|(r, n)| (0..n).map(move |i| r.row(i).unwrap().1))
            .collect()
    }

    /// A text roll that a removal started, with seats 10..80 (two buckets) on seed 1, a
    /// day after the last start; the second keyholder is gone. Gives the start's `time`,
    /// and the people.
    fn roll_held_open(w: &mut World) -> (u64, Vec<Member>) {
        let people = accounts(10, 70);
        w.join(&refs(&people));
        w.promote(Holder::desktop(9));
        w.tick(ROLL_GAP);
        w.remove(1);
        assert_eq!((w.head.header().seed, w.head.header().seed_floor), (2, 1));
        (w.head.header().time, people)
    }

    /// §5.6, RV q1-q2:1210: a text roll ends 24 h after its start, whatever the relay says.
    /// The relay here never says it may finish, names every seat as still on seed 1 and
    /// sends no keys for seed welcomes. Within the 24 h the roll runs as it always did. A
    /// day on, the next opening raises the floor and makes every row under seed 2, and so
    /// does every opening after it; each seat opens its row once the relay's sweep brings
    /// its seed welcome.
    #[test]
    fn a_text_roll_the_relay_holds_open_ends_24_h_after_its_start() {
        let mut w = World::text(true, false);
        w.seed_keys = false;
        let (started, people) = roll_held_open(&mut w);

        w.now = started + ROLL_GAP - 60;
        let due = w.due(DueKind::Refresh);
        let b = w.opening(&due).unwrap();
        assert_eq!(seeds(&b), (2, 1), "within the day the relay's word holds");
        assert_eq!(rows_under(&b), HashSet::from([1]));
        w.step(&due, &b);

        w.now = started + ROLL_GAP;
        let due = w.due(DueKind::Refresh);
        let b = w.opening(&due).unwrap();
        assert_eq!(seeds(&b), (2, 2), "the roll ends at its 24 h");
        assert_eq!(rows_under(&b), HashSet::from([2]), "no row under seed 1");
        assert!(b.commit.seed_welcomes.is_empty(), "the relay sent no keys");
        w.step(&due, &b);
        assert!(w.held.values().any(|n| *n == 1), "seats still behind");

        w.tick(2 * 3600);
        let due = w.due(DueKind::Refresh);
        let b = w.opening(&due).unwrap();
        assert_eq!(seeds(&b), (2, 2));
        assert_eq!(
            rows_under(&b),
            HashSet::from([2]),
            "a seat behind the floor gets its row under the head's seed"
        );
        w.step(&due, &b);

        // The sweep's seed welcome under seed 2 opens each row
        let k = w.holders[0].holder();
        let seed = Zeroizing::new(*w.ring.seed(2).unwrap());
        let mut opened = 0;
        for p in &people {
            let Some(m) = b.made.iter().find(|m| m.seats.contains(&p.seat)) else {
                continue;
            };
            let i = m.seats.iter().position(|x| *x == p.seat).unwrap();
            let (row, under) = m.rows.as_ref().unwrap().row(i).unwrap();
            assert_eq!(under, 2);
            let s_m = member_secret(&w.g, 2, &seed, &p.seat);
            let rb = RowBase::member_side(&w.g, 2, &p.me(), &k, &s_m).unwrap();
            assert_eq!(*rb.open_row(m.bucket.version(), row).unwrap(), *m.bucket.bk);
            opened += 1;
        }
        assert!(opened > 0);
    }

    /// The same with the seats' keys in the due: each seat still on seed 1 that the ending
    /// commit makes a row to gets its seed welcome in it, under seed 2.
    #[test]
    fn a_text_roll_ending_at_its_24_h_gives_seed_welcomes_where_the_keys_came() {
        let mut w = World::text(true, false);
        let (started, people) = roll_held_open(&mut w);
        w.now = started + ROLL_GAP;
        let due = w.due(DueKind::Refresh);
        let b = w.opening(&due).unwrap();
        assert_eq!(seeds(&b), (2, 2));
        assert_eq!(rows_under(&b), HashSet::from([2]));
        assert!(!b.commit.seed_welcomes.is_empty());
        rows_open_under_the_seed_welcomes(&w, &b, &people);
        w.step(&due, &b);
    }

    /// §5.6: a seed the relay keeps in use for 30 days by holding its roll open. The roll
    /// ends at the first opening past its 24 h; the opening after it starts the roll the
    /// seed's age makes due, though the relay never asks for one, and every seat still on
    /// seed 1 gets its row under the new seed.
    #[test]
    fn a_seed_the_relay_keeps_past_30_days_rolls_at_the_opening_after_its_roll_ends() {
        let mut w = World::text(true, false);
        w.seed_keys = false;
        let (started, _) = roll_held_open(&mut w);
        assert!(!w.rolls.removal, "no roll due but by age");
        w.now = started + SEED_MAX_AGE;
        let due = w.due(DueKind::Refresh);
        let b = w.opening(&due).unwrap();
        assert_eq!(seeds(&b), (2, 2));
        w.step(&due, &b);
        w.tick(60);
        let due = w.due(DueKind::Refresh);
        let b = w.opening(&due).unwrap();
        assert_eq!(seeds(&b), (3, 2), "the 30-day roll starts");
        assert_eq!(rows_under(&b), HashSet::from([3]), "every seat was behind");
        w.step(&due, &b);
    }

    /// A KeyholdersReplace past a roll's 24 h ends it too; within them it never does.
    #[test]
    fn a_keyholders_replace_ends_a_roll_only_past_its_24_h() {
        let mut w = World::text(true, false);
        w.seed_keys = false;
        let (started, _) = roll_held_open(&mut w);
        let new = w.holders[0].rotated();
        let due = w.replace_due(&new);
        w.now = started + ROLL_GAP - 60;
        let b = w.opening_by(0, &due, true, Some(&new), None).unwrap();
        assert_eq!(seeds(&b), (2, 1), "in time it finishes nothing");
        w.now = started + ROLL_GAP;
        let b = w.opening_by(0, &due, false, Some(&new), None).unwrap();
        assert_eq!(seeds(&b), (2, 2));
        assert_eq!(rows_under(&b), HashSet::from([2]));
        w.step(&due, &b);
        w.holders[0] = new;
        assert_eq!(w.head.header().kind, Kind::KeyholdersReplace);
    }

    #[test]
    fn a_join_rebased_across_a_new_generation_makes_everything_again() {
        let mut w = World::text(false, false);
        let late = accounts(40, 3);
        let due = w.join_due(&refs(&late));
        let stale = w.build_join(&due, None).unwrap();
        // A new generation with the same seed numbers.
        let gd = World::genesis_due(&w.holders[0], false);
        let gb = World::build_start(&w.holders[0], w.kind, w.id, false, &gd, w.now, None).unwrap();
        let a = w.check(&gd, w.holders[0].by(), &gb.commit).unwrap();
        w.take(&gd, a, &gb);
        assert_eq!(stale.parent_seeds, (1, 1));
        let rebased = w.build_join(&due, Some(&stale)).unwrap();
        let old: HashSet<u64> = stale.made.iter().map(|m| m.bucket.v).collect();
        assert!(rebased.made.iter().all(|m| !old.contains(&m.bucket.v)));
        assert_ne!(stale.commit.welcomes, rebased.commit.welcomes);
        w.step(&due, &rebased);
    }

    #[test]
    fn keyholder_side_dh_gives_the_row_base_keyholder_side_gives() {
        let w = World::text(false, false);
        let alice = Member::account(10);
        let k = &w.holders[0];
        let s_m = [7u8; 32];
        let public = alice.pair.public();
        let them = crate::group_key::keys::Them {
            m: alice.seat.m,
            keys: &public,
        };
        let full = RowBase::keyholder_side(&w.g, 1, &k.me(), &them, &s_m).unwrap();
        let dh = RowBase::keyholder_side_dh(
            &w.g,
            1,
            &k.me(),
            &alice.seat.m,
            &alice.seat.tag_sx,
            &public.dh_bytes(),
            &s_m,
        )
        .unwrap();
        assert_eq!(full.secret(), dh.secret());
        assert_eq!(full.key(), dh.key());
        let other = Member::account(11);
        assert_eq!(
            RowBase::keyholder_side_dh(
                &w.g,
                1,
                &k.me(),
                &alice.seat.m,
                &alice.seat.tag_sx,
                &other.pair.public().dh_bytes(),
                &s_m,
            )
            .err(),
            Some(GkError::Forged),
            "a dh its seat's tag does not name"
        );
        assert_eq!(
            RowBase::keyholder_side_dh(
                &w.g,
                1,
                &k.me(),
                &alice.seat.m,
                &alice.seat.tag_sx,
                &[&[5u8][..], &[0u8; 32]].concat(),
                &s_m,
            )
            .err(),
            Some(GkError::WeakKey),
            "a dh of low order"
        );
    }

    #[test]
    fn a_seed_welcome_page_opens_for_each_seat() {
        let w = World::text(false, false);
        let people = accounts(10, 3);
        let seed = [9u8; 32];
        let seats: Vec<(SeatRef, SeatPublic)> =
            people.iter().map(|p| (p.seat, p.pair.public())).collect();
        let out = build_seed_welcomes(&w.g, 2, &seed, &w.holders[0].me(), &seats).unwrap();
        for (p, sw) in people.iter().zip(&out) {
            let s_m =
                open_seed_welcome(&w.g, 2, &p.me(), &w.holders[0].holder(), &sw.bytes).unwrap();
            assert_eq!(*s_m, *member_secret(&w.g, 2, &seed, &p.seat));
        }
        let wrong = vec![(people[0].seat, people[1].pair.public())];
        assert_eq!(
            build_seed_welcomes(&w.g, 2, &seed, &w.holders[0].me(), &wrong).err(),
            Some(BuildError::Key(GkError::Forged))
        );
    }

    #[test]
    fn a_keyholder_builds_no_removal_of_its_own_entry() {
        let mut w = World::text(false, false);
        w.promote(Holder::desktop(2));
        let due = w.remove_due(0);
        assert_eq!(
            w.opening(&due).err(),
            Some(BuildError::Refuse(
                "a keyholder never signs its own removal"
            ))
        );
    }

    #[test]
    fn a_list_unlike_its_digest_is_refused_before_any_row() {
        let mut w = World::text(false, false);
        let people = accounts(10, 4);
        w.join(&refs(&people));
        let due = w.exits(&[people[0].seat], DueKind::Exits);
        let intruder = Member::account(99);
        w.keys.insert(intruder.seat, intruder.pair.public());
        let b = w.bucket_of(&people[1].seat);
        let l = w.leaves.iter_mut().find(|l| l.leaf.b == b).unwrap();
        l.seats.push(intruder.seat);
        assert_eq!(
            w.opening(&due).err(),
            Some(BuildError::Key(GkError::Sealed))
        );
    }

    #[test]
    fn an_exit_naming_a_seat_its_bucket_does_not_hold_is_refused() {
        let mut w = World::text(false, false);
        let people = accounts(10, 4);
        w.join(&refs(&people));
        let mut due = w.exits(&[people[0].seat], DueKind::Exits);
        due.exits[0].seat = w.holders[0].seat.seat;
        assert_eq!(
            w.opening(&due).err(),
            Some(BuildError::Refuse(
                "an exit names a seat its bucket does not hold"
            ))
        );
    }

    #[test]
    fn a_bucket_tree_of_a_built_head_cuts_the_paths_inclusion_path_gives() {
        let mut w = World::text(false, false);
        for i in 0..3 {
            w.join(&refs(&accounts(10 + i * 50, 50)));
        }
        let leaves: Vec<Leaf> = w.leaves.iter().map(|l| l.leaf).collect();
        let tree = BucketTree::new(&leaves).unwrap();
        assert_eq!(tree.root(), w.head.header().bucket_root);
        for i in 0..leaves.len() {
            assert_eq!(tree.path(i), inclusion_path(&leaves, i));
        }
    }

    // ── Builds in steps (`steps`) ─────────────────────────────────────────

    use std::cell::Cell;
    use std::future::Future;
    use std::time::Duration;

    use crate::group_key::commit::Joiner;
    use crate::group_key::ctx::MemberId;

    /// What a build run in steps did.
    #[derive(Debug, Default)]
    struct Ran {
        steps: u64,
        units: u64,
        /// The most units one step did.
        most: u64,
    }

    /// `f` run in steps of `budget` on `clock`, to its end.
    fn in_steps<F: Future>(f: F, budget: Duration, clock: fn() -> f64) -> (F::Output, Ran) {
        let mut f = std::pin::pin!(f);
        let mut ran = Ran::default();
        loop {
            let (out, units) = steps::step_by(f.as_mut(), budget, clock);
            ran.steps += 1;
            ran.units += units;
            ran.most = ran.most.max(units);
            if let Some(out) = out {
                return (out, ran);
            }
            assert!(ran.steps < 10_000_000, "a build in steps ends");
        }
    }

    /// In steps of a zero budget: one unit each.
    fn unit_steps<F: Future>(f: F) -> (F::Output, Ran) {
        in_steps(f, Duration::ZERO, steps::clock_ms)
    }

    thread_local! {
        static TICKS: Cell<f64> = const { Cell::new(0.0) };
    }

    /// A clock that moves on a millisecond each time it is read: as if each unit took one.
    fn ticking() -> f64 {
        TICKS.with(|t| {
            t.set(t.get() + 1.0);
            t.get()
        })
    }

    /// What a commit makes, less what its build draws at random (the ids of new buckets
    /// and versions, `BK`, `CK`, `KRK`, a new seed, the welcomes' KEM and ephemeral keys):
    /// whole or in steps, the same.
    #[derive(Debug, PartialEq, Eq)]
    struct Shape {
        header: Vec<String>,
        versions: Vec<(String, Pool, Make)>,
        drops: Vec<u64>,
        rows: Vec<(String, u32, u64, usize)>,
        welcomes: Vec<(SeatRef, String, u32)>,
        seed_welcomes: Vec<SeatRef>,
        krk: Vec<(HolderRef, [u8; 32])>,
        seals: Vec<String>,
        refused: Vec<Refused>,
        sealed_to: Vec<SeatRef>,
        made: Vec<(Vec<SeatRef>, Vec<Leaf>, bool)>,
    }

    fn shape(b: &Built) -> Shape {
        let h = b.header.header();
        // A version by the bucket it goes on from, else (a new bucket) by its first seat
        let mut name: HashMap<(u64, u64), String> = HashMap::new();
        for vo in &b.commit.versions {
            let n = match &vo.make {
                Make::Seats(seats) => format!("new {:?}", seats.first()),
                Make::Keep { from_v, .. } | Make::Ratchet { from_v } => {
                    format!("{} from {from_v}", vo.b)
                }
            };
            name.insert((vo.b, vo.v), n);
        }
        let named = |b: u64, v: u64| {
            name.get(&(b, v))
                .cloned()
                .unwrap_or_else(|| format!("{b}.{v} as it was"))
        };
        let mut seals: Vec<String> = b.commit.seals.iter().map(|x| named(x.b, x.v)).collect();
        seals.sort();
        Shape {
            header: vec![
                format!(
                    "{:?}",
                    (h.group_kind, &h.group, h.gen, h.epoch, h.join, h.kind)
                ),
                format!(
                    "{:?}",
                    (h.time, h.parent, h.epoch_parent, h.kh_parent, h.signer)
                ),
                format!(
                    "{:?}",
                    (&h.keyholders, h.gated, h.seed, h.seed_floor, h.exits_upto)
                ),
                format!(
                    "{:?}",
                    (h.seats, h.buckets, h.conn_seats, &h.added, &h.removed)
                ),
                format!("{:?}", h.names_hash),
            ],
            versions: b
                .commit
                .versions
                .iter()
                .map(|vo| (named(vo.b, vo.v), vo.pool, vo.make.clone()))
                .collect(),
            drops: b.commit.drops.clone(),
            rows: b
                .commit
                .rows
                .iter()
                .map(|r| (named(r.b, r.v), r.s, r.up, r.rows.len() / ROW_BYTES))
                .collect(),
            welcomes: b
                .commit
                .welcomes
                .iter()
                .map(|x| (x.seat, named(x.b, x.v), x.s))
                .collect(),
            seed_welcomes: b.commit.seed_welcomes.iter().map(|x| x.seat).collect(),
            krk: b.commit.krk.iter().map(|x| (x.to, x.from_kx)).collect(),
            seals,
            refused: b.commit.refused.clone(),
            sealed_to: b.sealed_to.clone(),
            made: b
                .made
                .iter()
                .map(|m| (m.seats.clone(), m.from.clone(), m.rows.is_some()))
                .collect(),
        }
    }

    /// `whole` and `stepped`, both built for `due` by holder `i` on the same head: the
    /// relay's check takes both, they make the same, and the steps did one unit each, at
    /// least one for each row, welcome and seal.
    fn twins(w: &World, i: usize, due: &Due, whole: &Built, stepped: &Built, ran: &Ran) {
        let by = w.holders[i].by();
        w.check(due, by, &whole.commit)
            .unwrap_or_else(|bad| panic!("whole: {bad}"));
        w.check(due, by, &stepped.commit)
            .unwrap_or_else(|bad| panic!("in steps: {bad}"));
        assert_eq!(shape(whole), shape(stepped));
        let c = &stepped.commit;
        let rows: usize = c.rows.iter().map(|r| r.rows.len() / ROW_BYTES).sum();
        let least = rows + c.welcomes.len() + c.seed_welcomes.len() + c.krk.len() + c.seals.len();
        assert!(
            ran.units >= least as u64,
            "a unit for each row, welcome and seal: {ran:?}, at least {least}"
        );
        assert_eq!(ran.most, 1, "a zero budget does one unit a step: {ran:?}");
        assert_eq!(
            ran.steps,
            ran.units + 1,
            "every step but the last stops at its unit"
        );
    }

    /// A Join of `seats` by holder 0, whole and in steps; the one in steps is taken.
    fn join_twins(w: &mut World, seats: &[&Member]) -> Built {
        let due = w.join_due(seats);
        let whole = w.build_join(&due, None).unwrap();
        let (stepped, ran) = w.with_holding(0, |hold, cache, w| {
            let js: Vec<&Joiner> = due.joiners.iter().collect();
            unit_steps(join_in_steps(hold, &js, vec![], w.now, cache, None))
        });
        let stepped = stepped.unwrap();
        twins(w, 0, &due, &whole, &stepped, &ran);
        for m in seats {
            if let MemberId::Conn(u) = m.seat.m {
                w.roster.push(u);
            }
        }
        w.step(&due, &stepped);
        stepped
    }

    /// An opening for `due` by holder `i`, whole and in steps; the one in steps is taken.
    fn opening_twins(w: &mut World, i: usize, due: &Due, replacing: Option<&Holder>) -> Built {
        let whole = w.opening_by(i, due, false, replacing, None).unwrap();
        let (stepped, ran) = w.opening_with(i, due, false, replacing, |hold, ask, cache| {
            unit_steps(opening_in_steps(hold, ask, cache, None))
        });
        let stepped = stepped.unwrap();
        twins(w, i, due, &whole, &stepped, &ran);
        w.step_by(i, due, &stepped);
        stepped
    }

    #[test]
    fn builds_in_steps_make_what_whole_builds_make_and_the_relay_takes_both() {
        let mut w = World::text(true, false);
        let people = accounts(10, 300);
        let guests: Vec<Member> = (100..120).map(Member::conn).collect();
        // A Join of 300 seats: a due seats 256 at most (`JOIN_BATCH_MAX`)
        join_twins(&mut w, &refs(&people[..256]));
        join_twins(&mut w, &refs(&people[256..]));
        join_twins(&mut w, &refs(&guests));
        assert_eq!(w.head.header().seats, 1 + 300 + 20);
        // Exits from every bucket, and from the guests': re-keys by rows
        let mut leaving: Vec<SeatRef> = people.iter().step_by(9).map(|p| p.seat).collect();
        leaving.push(guests[3].seat);
        let due = w.exits(&leaving, DueKind::Exits);
        let b = opening_twins(&mut w, 0, &due, None);
        assert!(
            b.commit.versions.len() >= 5,
            "re-keys: {:?}",
            b.commit.versions.len()
        );
        // The other guests leave: their bucket is dropped
        let gone: Vec<SeatRef> = guests
            .iter()
            .map(|g| g.seat)
            .filter(|s| *s != guests[3].seat)
            .collect();
        let due = w.exits(&gone, DueKind::Exits);
        let b = opening_twins(&mut w, 0, &due, None);
        assert_eq!(b.commit.drops.len(), 1);
        // A refresh, an hour on: every version over an hour old is re-keyed (Fresh)
        w.tick(3700);
        let due = w.due(DueKind::Refresh);
        let b = opening_twins(&mut w, 0, &due, None);
        assert_eq!(b.header.header().kind, Kind::Fresh);
        assert!(!b.commit.rows.is_empty());
        // A second keyholder's Add (ratchets), its pair replaced, then its Remove (re-keys all)
        let cand = Holder::desktop(2);
        let due = w.promote_due(&cand);
        opening_twins(&mut w, 0, &due, None);
        w.holders.push(cand);
        let new = w.holders[0].rotated();
        let due = w.replace_due(&new);
        opening_twins(&mut w, 0, &due, Some(&new));
        w.holders[0] = new;
        let due = w.remove_due(1);
        let b = opening_twins(&mut w, 0, &due, None);
        w.holders.remove(1);
        assert_eq!(b.header.header().kind, Kind::KeyholdersRemove);
        assert_eq!(b.commit.krk.len(), 1);
    }

    #[test]
    fn a_voice_removal_in_steps_welcomes_every_seat_behind_as_the_whole_one_does() {
        let mut w = World::voice();
        let people: Vec<Member> = (10..40).map(Member::conn).collect();
        join_twins(&mut w, &refs(&people));
        w.promote(Holder::conn(4));
        let due = w.remove_due(1);
        opening_twins(&mut w, 0, &due, None);
        w.holders.remove(1);
        assert_eq!(w.head.header().seed, 2, "a voice removal rolls the seed");
        // Every seat is still on seed 1: the next removal welcomes each to seed 3
        w.promote(Holder::conn(5));
        let due = w.remove_due(1);
        let b = opening_twins(&mut w, 0, &due, None);
        w.holders.remove(1);
        assert_eq!(b.commit.seed_welcomes.len(), 31);
        rows_open_under_the_seed_welcomes(&w, &b, &people);
    }

    #[test]
    fn a_seed_welcome_page_in_steps_gives_each_seat_what_the_whole_page_gives() {
        let w = World::text(false, false);
        let people = accounts(10, 40);
        let seed = [9u8; 32];
        let seats: Vec<(SeatRef, SeatPublic)> =
            people.iter().map(|p| (p.seat, p.pair.public())).collect();
        let me = w.holders[0].me();
        let whole = build_seed_welcomes(&w.g, 2, &seed, &me, &seats).unwrap();
        let (stepped, ran) = unit_steps(seed_welcomes_in_steps(&w.g, 2, &seed, &me, &seats));
        let stepped = stepped.unwrap();
        assert_eq!((ran.units, ran.most, ran.steps), (40, 1, 41));
        let k = w.holders[0].holder();
        for (p, (a, b)) in people.iter().zip(whole.iter().zip(&stepped)) {
            assert_eq!((a.seat, b.seat), (p.seat, p.seat));
            let open =
                |x: &SeedWelcomeOut| open_seed_welcome(&w.g, 2, &p.me(), &k, &x.bytes).unwrap();
            assert_eq!(*open(b), *open(a));
            assert_eq!(*open(b), *member_secret(&w.g, 2, &seed, &p.seat));
        }
    }

    #[test]
    fn a_step_stops_at_the_first_unit_past_its_budget_and_the_next_goes_on_from_there() {
        let mut w = World::text(true, false);
        let people = accounts(10, 100);
        let due = w.join_due(&refs(&people));
        // Each unit takes a millisecond of this clock: a step does `budget` units, the last
        // what is left
        let mut units = None;
        for budget in [1u64, 7, 40] {
            let (b, ran) = w.with_holding(0, |hold, cache, w| {
                let js: Vec<&Joiner> = due.joiners.iter().collect();
                let f = join_in_steps(hold, &js, vec![], w.now, cache, None);
                in_steps(f, Duration::from_millis(budget), ticking)
            });
            w.check(&due, w.holders[0].by(), &b.unwrap().commit)
                .unwrap_or_else(|bad| panic!("{bad}"));
            assert_eq!(ran.most, budget, "{ran:?}");
            assert_eq!(ran.steps, ran.units / budget + 1, "{ran:?}");
            assert_eq!(
                *units.get_or_insert(ran.units),
                ran.units,
                "the same units at any budget"
            );
        }
        // On the real clock, a zero or one-microsecond budget: a step a unit (or few), done
        for budget in [Duration::ZERO, Duration::from_micros(1)] {
            let (b, ran) = w.with_holding(0, |hold, cache, w| {
                let js: Vec<&Joiner> = due.joiners.iter().collect();
                in_steps(
                    join_in_steps(hold, &js, vec![], w.now, cache, None),
                    budget,
                    steps::clock_ms,
                )
            });
            let b = b.unwrap();
            w.check(&due, w.holders[0].by(), &b.commit)
                .unwrap_or_else(|bad| panic!("{bad}"));
            assert!(
                ran.steps > b.commit.welcomes.len() as u64,
                "a step for each welcome at least: {ran:?}"
            );
        }
        // A budget no build spends: one step
        let (_, ran) = w.with_holding(0, |hold, cache, w| {
            let js: Vec<&Joiner> = due.joiners.iter().collect();
            let f = join_in_steps(hold, &js, vec![], w.now, cache, None);
            in_steps(f, Duration::MAX, steps::clock_ms)
        });
        assert_eq!(ran.steps, 1);
        assert_eq!(Some(ran.units), units);
    }

    /// RV r-keyholders:118: a list that gives a seat another X25519 key than the one it was
    /// seated with is not the list the keyring names. The digest binds `ser(SX)` in full, so
    /// the 8-byte `tag_sx` (about 2^64 / N tries to match) is not what keeps the relay from
    /// putting a key of its own into the rows of a re-key.
    #[test]
    fn a_rekey_refuses_a_list_that_gives_a_seat_another_x25519_key() {
        let mut w = World::text(true, false);
        let people = accounts(10, 5);
        w.join(&refs(&people));
        // The relay serves people[1] with a key of its own; the exit makes its bucket re-key
        // to a keyholder that did not seat it (no row base kept from the Join)
        let theirs = crate::group_key::keys::SeatPair::generate().public();
        w.keys.insert(people[1].seat, theirs);
        w.cache = RowBases::new();
        let due = w.exits(&[people[0].seat], DueKind::Exits);
        let r = w.opening_by(0, &due, true, None, None);
        assert_eq!(
            r.err(),
            Some(BuildError::Key(GkError::Sealed)),
            "the list is refused by its digest, before any row"
        );
    }

    /// RV q4-q5:748: in a gated group a KeyholdersAdd promotes only a seated candidate
    /// (§5.6). The candidate's pair gets the keyring and every post from its promotion on,
    /// and a seat there needs a name in `added`, which the relay cannot make; the candidate
    /// is the relay's word. A seat leaving in the same commit is no seat.
    #[test]
    fn a_gated_promotion_of_a_candidate_seated_nowhere_is_refused() {
        let mut w = World::text(true, true);
        w.join(&refs(&accounts(10, 3)));
        let cand = Holder::desktop(9);
        let unseated = w.promote_due(&cand);
        assert_eq!(
            w.opening(&unseated).err(),
            Some(BuildError::Candidate("the candidate is seated nowhere"))
        );
        // Seated by an honest Join, but leaving in the commit that would promote it
        w.join(&[&cand.seat]);
        let leaving = Due {
            candidate: Some(cand.candidate()),
            ..w.exits(&[cand.seat.seat], DueKind::Promote)
        };
        assert_eq!(
            w.opening(&leaving).err(),
            Some(BuildError::Candidate("the candidate is seated nowhere"))
        );
        // Seated and staying: promoted
        let due = w.promote_due(&cand);
        assert!(w.opening(&due).is_ok());
    }

    #[test]
    fn a_whole_run_inside_a_step_never_stops_and_counts_no_unit() {
        let f = async {
            steps::whole(async {
                for _ in 0..10 {
                    steps::unit().await;
                }
            });
            for _ in 0..3 {
                steps::unit().await;
            }
            steps::fresh().await;
        };
        let ((), ran) = unit_steps(f);
        assert_eq!((ran.units, ran.steps, ran.most), (3, 4, 1));
        // `fresh` stops a step that did any unit, before what follows it
        let f = async {
            steps::unit().await;
            steps::fresh().await;
        };
        let ((), ran) = in_steps(f, Duration::MAX, steps::clock_ms);
        assert_eq!((ran.units, ran.steps), (1, 2));
        // Outside a step, nothing stops
        steps::whole(async {
            steps::unit().await;
            steps::fresh().await;
        });
    }
}
