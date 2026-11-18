//! Where a group's material lives (plan 2a, 2g, 2h): `Memory` for `r:` groups and relays
//! without accounts (nothing reaches the database, a restart is a new generation), `Db`
//! over `accounts::gk` for stored `c:` groups. The actor stores a checked commit here
//! before anything is pushed; answers read seat keying, the keyring and `KRK` welcomes.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use anyhow::Result;
use l4f_accounts::store::Store as Db;
use voipc_crypto::group_key::commit::{HolderRef, Joiner, Listed, Pair, RowsOut, WelcomeOut};
use voipc_crypto::group_key::timers::{HOLD_MS, KEYHOLDER_SKEW_SECS, MATERIAL_SWEEP_MARGIN_MS};
use voipc_crypto::group_key::tree::BucketTree;
use voipc_crypto::group_key::{
    seat_record, GroupKind, Kind, Leaf, MemberId, Pool, SeatRef, SignedHeader, Via, MAX_WALK,
};
use voipc_protocol::gk::{
    self, EpochRef, HeaderIn, InPiece, KrkIn, LeafIn, NamesListIn, NamesStepIn, PathIn,
    RatchetStep, SeatKeying, SelfRowIn,
};

use super::due::{Exits, Leaving};
use super::group::{GroupState, Head, Seat, Taken};
use super::names::{starts_names, Kept};
use super::snapshot::{link, Ver};
use crate::accounts::gk as db;

/// Dispatch over the two backends, as accounts.rs's `db!` (which this module cannot see).
macro_rules! on {
    ($store:expr, $pool:ident => $body:block) => {
        match $store {
            Db::Pg(b) => {
                let $pool = &b.0;
                $body
            }
            Db::Lite(b) => {
                let $pool = &b.0;
                $body
            }
        }
    };
}

/// Runs `$q` (one DELETE with `LIMIT $n` as its last bound value) until it takes nothing,
/// a short transaction each (Round C keeps SQLite's writer free); the rows it took.
macro_rules! batched {
    ($store:expr, $q:expr, $($bind:expr),*) => {{
        let mut gone: u64 = 0;
        loop {
            let n = on!($store, pool => {
                sqlx::query($q)$(.bind($bind))*.bind(db::STORE_BATCH as i64).execute(pool).await?.rows_affected()
            });
            gone += n;
            if n == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
        gone
    }};
}

/// Why kept, a bit each (`voipc_gk_headers.keep`).
pub const KEEP_RECENT: u32 = 1;
pub const KEEP_KH: u32 = 2;
pub const KEEP_START: u32 = 4;
pub const KEEP_PARENT: u32 = 8;

/// `voipc_gk_names.kind`: an `added` list (`list` its postcard), a header carrying `removed`
/// (`list` the postcard of its `HeaderIn`), the step before the oldest list kept (`names_hash`
/// the hash before it, `list` its list digest).
pub const NAMES_LIST: u8 = 0;
pub const NAMES_REMOVED: u8 = 1;
pub const NAMES_STEP: u8 = 2;

/// A store write that failed: `Check` is rule 16 (a version id used), anything else is
/// `EpochStale{STORE}`.
#[derive(Debug)]
pub enum Fail {
    Check(String),
    Store(String),
}

/// A memory group's material: welcomes until their `EpochIn` went out, rows of the versions
/// current seats reach their keys by, the head epoch's keyring, each keyholder's `KRK`
/// welcome.
#[derive(Default)]
pub struct Mem {
    welcomes: HashMap<SeatRef, (HolderRef, WelcomeOut)>,
    rows: HashMap<(u64, u64), (HolderRef, RowsOut)>,
    keyring: (u32, Vec<u8>),
    krk: HashMap<[u8; 32], KrkIn>,
    /// A seat's newest seed welcome until it went out whole (2b: pushed to the online
    /// seats, kept for one offline through a roll until its answer took it, §5.6).
    seed: HashMap<SeatRef, gk::SeedWelcomeIn>,
    /// How long a commit takes to store, as Postgres can under load.
    #[cfg(test)]
    commit_ms: u64,
}

pub struct DbStore {
    pub db: l4f_accounts::store::Store,
    /// This database's `gk_incarnation`.
    pub incarnation: [u8; 16],
}

// One a group, made once: the memory variant's size is no matter
#[allow(clippy::large_enum_variant)]
pub enum Store {
    Memory(Mutex<Mem>),
    Db(Arc<DbStore>),
}

/// A seat's base: the seed, the maker, a welcome (`true`) or a row, and its bytes.
pub type Base = (u32, HolderRef, bool, Vec<u8>);

fn maker(h: &HolderRef) -> db::Maker {
    let mut m = [0u8; 49];
    m[..17].copy_from_slice(&h.m.seat_id());
    m[17..].copy_from_slice(&h.kx);
    m
}

fn member_of(id: &[u8]) -> Option<MemberId> {
    match id.first()? {
        0x01 => Some(MemberId::Account(id.get(1..17)?.try_into().ok()?)),
        0x02 => Some(MemberId::Conn(u32::from_be_bytes(
            id.get(13..17)?.try_into().ok()?,
        ))),
        _ => None,
    }
}

fn holder_of(m: &db::Maker) -> Option<HolderRef> {
    Some(HolderRef {
        m: member_of(&m[..17])?,
        kx: m[17..].try_into().ok()?,
    })
}

/// A seat record (§11.5) back to its seat.
pub fn seat_of(rec: &[u8; 33]) -> Option<SeatRef> {
    Some(SeatRef {
        m: member_of(&rec[..17])?,
        tag_sk: rec[17..25].try_into().ok()?,
        tag_sx: rec[25..].try_into().ok()?,
    })
}

fn stream_of(pieces: impl IntoIterator<Item = Vec<u8>>) -> Vec<u8> {
    let mut s = vec![];
    for p in pieces {
        let _ = gk::put_keyring_entry(&mut s, &p);
    }
    s
}

impl Store {
    pub fn memory() -> Store {
        Store::Memory(Mutex::default())
    }

    pub fn stored(&self) -> bool {
        matches!(self, Store::Db(_))
    }

    fn mem(&self) -> Option<std::sync::MutexGuard<'_, Mem>> {
        match self {
            Store::Memory(m) => Some(m.lock().unwrap_or_else(|e| e.into_inner())),
            Store::Db(_) => None,
        }
    }

    /// Writes a checked commit and moves the head (2g); nothing is pushed before this.
    pub async fn commit(&self, g: &GroupState, t: &Taken, now: u64) -> Result<(), Fail> {
        match self {
            Store::Memory(_) => {
                #[cfg(test)]
                {
                    let ms = self.mem().map_or(0, |m| m.commit_ms);
                    tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
                }
                self.commit_mem(t);
                Ok(())
            }
            Store::Db(d) => commit_db(d, g, t, now)
                .await
                .map_err(|e| match e.downcast::<Fail>() {
                    Ok(f) => f,
                    Err(e) => Fail::Store(e.to_string()),
                }),
        }
    }

    fn commit_mem(&self, t: &Taken) {
        let mut m = self.mem().expect("memory");
        let h = t.applied.header.header();
        if h.kind.starts_anew() {
            *m = Mem::default();
        }
        for w in &t.commit.welcomes {
            m.welcomes.insert(w.seat, (t.maker, w.clone()));
        }
        for r in &t.commit.rows {
            m.rows.insert((r.b, r.v), (t.maker, r.clone()));
        }
        if h.kind.opens_epoch() {
            m.keyring = (h.epoch, stream_of([t.commit.keyring.clone()]));
        } else {
            let _ = gk::put_keyring_entry(&mut m.keyring.1, &t.commit.keyring);
        }
        if let Some(set) = &t.applied.keyholders {
            m.krk.retain(|kx, _| set.iter().any(|k| k.kx == *kx));
        }
        for k in &t.commit.krk {
            m.krk.insert(
                k.to.kx,
                KrkIn {
                    from: HolderRef {
                        m: h.signer,
                        kx: k.from_kx,
                    }
                    .into(),
                    bytes: k.bytes.clone(),
                },
            );
        }
    }

    /// Drops a memory group's rows no current version reaches its key by.
    pub fn prune(&self, g: &GroupState) {
        if let Some(mut m) = self.mem() {
            let bases: HashSet<(u64, u64)> =
                g.vers.iter().map(|((b, _), v)| (*b, v.base_v)).collect();
            m.rows.retain(|k, _| bases.contains(k));
            m.welcomes
                .retain(|s, (_, w)| g.seats.contains_key(s) && bases.contains(&(w.b, w.v)));
            m.seed.retain(|s, _| g.seats.contains_key(s));
        }
    }

    /// The welcome or row `seat` reaches `(b, base_v)` by; `index` is its place in the
    /// list.
    pub async fn base(
        &self,
        grp: &str,
        gen: &[u8; 16],
        seat: &SeatRef,
        (b, base_v, index): (u64, u64, usize),
    ) -> Option<Base> {
        match self {
            Store::Memory(_) => {
                let m = self.mem()?;
                if let Some((from, w)) = m
                    .welcomes
                    .get(seat)
                    .filter(|(_, w)| (w.b, w.v) == (b, base_v))
                {
                    return Some((w.s, *from, true, w.bytes.clone()));
                }
                let (from, rows) = m.rows.get(&(b, base_v))?;
                let (row, s) = rows.row(index)?;
                Some((s as u32, *from, false, row.to_vec()))
            }
            Store::Db(d) => {
                let rec = seat_record(seat);
                let welcomes = db::welcomes_of(&d.db, grp, gen, &rec).await.ok()?;
                if let Some(w) = welcomes
                    .into_iter()
                    .find(|w| w.kind == db::WelcomeKind::Seat && w.version == Some((b, base_v)))
                {
                    return Some((w.s, holder_of(&w.maker)?, true, w.bytes));
                }
                let r = db::row(&d.db, grp, gen, b, base_v, &rec).await.ok()??;
                Some((r.s, holder_of(&r.maker)?, false, r.bytes))
            }
        }
    }

    /// Every session of `seat` had its answer queued: a memory group's welcome goes (2b).
    pub fn welcomed(&self, seat: &SeatRef) {
        if let Some(mut m) = self.mem() {
            m.welcomes.remove(seat);
        }
    }

    /// `seat`'s seed welcome under `s` went out whole: a memory group keeps it no longer
    /// (2b, a lost one means the seat re-joins).
    pub fn seed_sent(&self, seat: &SeatRef, s: u32) {
        if let Some(mut m) = self.mem() {
            if m.seed.get(seat).is_some_and(|w| w.s == s) {
                m.seed.remove(seat);
            }
        }
    }

    #[cfg(test)]
    pub fn slow_commits(&self, ms: u64) {
        if let Some(mut m) = self.mem() {
            m.commit_ms = ms;
        }
    }

    #[cfg(test)]
    pub fn seed_kept(&self) -> usize {
        self.mem().map_or(0, |m| m.seed.len())
    }

    /// A memory group's material in bytes, about (Load's `mem_bytes` beside the state's).
    pub fn mem_bytes(&self) -> u64 {
        let Some(m) = self.mem() else {
            return 0;
        };
        let rows: usize = m.rows.values().map(|(_, r)| r.rows.len() + 64).sum();
        let krk: usize = m.krk.values().map(|k| k.bytes.len() + 64).sum();
        (m.welcomes.len() * (gk::SEAT_WELCOME_BYTES + 120)
            + m.seed.len() * (gk::SEED_WELCOME_BYTES + 80)
            + rows
            + krk
            + m.keyring.1.len()) as u64
    }

    /// A seed welcome waiting for `seat` under `s`.
    pub async fn seed_welcome(
        &self,
        grp: &str,
        gen: &[u8; 16],
        seat: &SeatRef,
        s: u32,
    ) -> Option<gk::SeedWelcomeIn> {
        let d = match self {
            Store::Memory(_) => {
                return self.mem()?.seed.get(seat).filter(|w| w.s == s).cloned();
            }
            Store::Db(d) => d,
        };
        let w = db::welcome(
            &d.db,
            grp,
            gen,
            &seat_record(seat),
            db::WelcomeKind::Seed,
            s,
        )
        .await
        .ok()??;
        Some(gk::SeedWelcomeIn {
            s,
            from: holder_of(&w.maker)?.into(),
            bytes: w.bytes,
        })
    }

    /// A seed-welcome page's welcomes under seed `s`, made by `by` (§5.6): each seat holds
    /// `s` from now on. Stored (`voipc_gk_seats.seed` moves with them), or a memory group's
    /// kept for its seat.
    pub async fn seeds(
        &self,
        grp: &str,
        gen: &[u8; 16],
        s: u32,
        by: &HolderRef,
        welcomes: &[(SeatRef, Vec<u8>)],
        now: u64,
    ) -> Result<(), String> {
        match self {
            Store::Memory(_) => {
                let mut m = self.mem().expect("memory");
                for (seat, bytes) in welcomes {
                    let w = gk::SeedWelcomeIn {
                        s,
                        from: (*by).into(),
                        bytes: bytes.clone(),
                    };
                    m.seed.insert(*seat, w);
                }
                Ok(())
            }
            Store::Db(d) => {
                let rows: Vec<db::Welcome> = welcomes
                    .iter()
                    .map(|(seat, bytes)| db::Welcome {
                        seat: seat_record(seat),
                        kind: db::WelcomeKind::Seed,
                        s,
                        version: None,
                        maker: maker(by),
                        bytes: bytes.clone(),
                        made: now,
                    })
                    .collect();
                db::put_seed_welcomes(&d.db, grp, gen, &rows)
                    .await
                    .map_err(|e| e.to_string())
            }
        }
    }

    /// The keyholder entries of a stored group as its actor holds them (2i): each with its
    /// pair, rank, device and when it was last online; an entry no longer in the set goes.
    pub async fn put_holders(&self, g: &GroupState, now: u64) {
        if let Store::Db(d) = self {
            if let Err(e) = put_holders(&d.db, g, now).await {
                tracing::warn!(group = %g.id, "keeping the keyholders failed: {e}");
            }
        }
    }

    /// A live group's own sweep (plan 2e): a stored group's orphans, between its commits,
    /// and its keyholder entries with `last_online` now for those online (a restart counts
    /// an entry away only from when it was last seen, 2i); daily, names past 90 days, with
    /// the step before the oldest kept.
    pub async fn sweep_live(&self, g: &mut GroupState, now: u64, daily: bool) {
        if let Store::Db(d) = self {
            if let Err(e) = db::sweep_orphans(&d.db, &g.id, None).await {
                tracing::warn!(group = %g.id, "sweeping orphans failed: {e}");
            }
            if !g.holders.online(&g.vols).is_empty() {
                self.put_holders(g, now).await;
            }
        }
        let Some(gen) = g.gen().filter(|_| daily) else {
            return;
        };
        g.names.sweep(&gen, now / 1000);
        if let Some(step) = g.names.take_swept() {
            self.names_step(&g.id, &gen, &step).await;
        }
        if let (Store::Db(d), Some(step)) = (self, g.names.step_at(&gen)) {
            if let Err(e) = db::sweep_names(&d.db, &g.id, &gen, step).await {
                tracing::warn!(group = %g.id, "sweeping names failed: {e}");
            }
        }
    }

    /// The head epoch's keyring stream from piece `from_j` on.
    pub async fn keyring(&self, grp: &str, gen: &[u8; 16], epoch: u32, from_j: u32) -> Vec<u8> {
        match self {
            Store::Memory(_) => {
                let m = self.mem().expect("memory");
                if m.keyring.0 != epoch {
                    return vec![];
                }
                gk::keyring_entries(&m.keyring.1)
                    .ok()
                    .and_then(|e| {
                        e.skip(from_j as usize)
                            .map(|x| x.map(<[u8]>::to_vec))
                            .collect::<Result<Vec<_>, _>>()
                            .ok()
                    })
                    .map(stream_of)
                    .unwrap_or_default()
            }
            Store::Db(d) => {
                let mut pieces = db::keyring(&d.db, grp, gen, epoch)
                    .await
                    .unwrap_or_default();
                pieces.sort_by_key(|p| p.j);
                stream_of(
                    pieces
                        .into_iter()
                        .filter(|p| p.j >= from_j)
                        .map(|p| p.bytes),
                )
            }
        }
    }

    /// The `KRK` welcome to the keyholder `kx`, made at `epoch` (the head's keyholder header).
    pub async fn krk(&self, grp: &str, gen: &[u8; 16], epoch: u32, kx: &[u8; 32]) -> Option<KrkIn> {
        match self {
            Store::Memory(_) => self.mem()?.krk.get(kx).cloned(),
            Store::Db(d) => {
                let k = db::krk(&d.db, grp, gen, epoch, kx).await.ok()??;
                Some(KrkIn {
                    from: holder_of(&k.maker)?.into(),
                    bytes: k.bytes,
                })
            }
        }
    }

    /// Exits entered since `from` (`seq`), kept so open batches survive a restart.
    pub async fn exits_entered(&self, grp: &str, g: &GroupState, from: u64, now: u64) {
        let (Store::Db(d), Some(gen)) = (self, g.gen()) else {
            return;
        };
        let new: Vec<db::Exit> = g
            .exits
            .closed
            .iter()
            .chain(g.exits.open.iter())
            .flat_map(|b| b.exits.iter())
            .filter(|l| l.exit.seq >= from)
            .map(|l| db::Exit {
                seq: l.exit.seq,
                gen,
                seat: seat_record(&l.exit.seat),
                cause: l.cause,
                at: now,
            })
            .collect();
        if !new.is_empty() {
            if let Err(e) = db::add_exits(&d.db, grp, &new).await {
                tracing::warn!(group = grp, "keeping exits failed: {e}");
            }
        }
    }

    /// The step before the oldest names list kept, made by a sweep (kind 2): a "gone" answer
    /// after a restart still has it.
    pub async fn names_step(&self, grp: &str, gen: &[u8; 16], step: &NamesStepIn) {
        let Store::Db(d) = self else { return };
        let n = db::Names {
            gen: *gen,
            epoch: step.epoch,
            j: step.join,
            kind: NAMES_STEP,
            time: step.time,
            names_hash: step.before,
            list: step.list.to_vec(),
        };
        if let Err(e) = db::put_names(&d.db, grp, &[n]).await {
            tracing::warn!(group = grp, "keeping a names step failed: {e}");
        }
    }

    /// The self-rows an account keeps for its seat `seat` under seed `s` (§3.11,
    /// `voipc_gk_self` kind 0): a session of the account that has lost `s_m` (a restart, a
    /// second device) opens its seat's row with them. Stored groups only.
    pub async fn self_rows(
        &self,
        grp: &str,
        gen: &[u8; 16],
        seat: &SeatRef,
        s: u32,
    ) -> Vec<gk::SelfRowIn> {
        let (Store::Db(d), Some(account)) = (self, seat.m.account()) else {
            return vec![];
        };
        const Q: &str = "SELECT sealed FROM voipc_gk_self WHERE grp = $1 AND account = $2
             AND gen = $3 AND seed = $4 AND tag_sk = $5 AND tag_sx = $6 AND kind = $7";
        let rows: Result<Vec<Vec<u8>>, sqlx::Error> = match &d.db {
            Db::Lite(b) => {
                sqlx::query_scalar(Q)
                    .bind(grp)
                    .bind(&account[..])
                    .bind(&gen[..])
                    .bind(i64::from(s))
                    .bind(&seat.tag_sk[..])
                    .bind(&seat.tag_sx[..])
                    .bind(i16::from(gk::self_row::SELF_ROW))
                    .fetch_all(&b.0)
                    .await
            }
            Db::Pg(b) => {
                sqlx::query_scalar(Q)
                    .bind(grp)
                    .bind(&account[..])
                    .bind(&gen[..])
                    .bind(i64::from(s))
                    .bind(&seat.tag_sk[..])
                    .bind(&seat.tag_sx[..])
                    .bind(i16::from(gk::self_row::SELF_ROW))
                    .fetch_all(&b.0)
                    .await
            }
        };
        rows.unwrap_or_default()
            .into_iter()
            .map(|sealed| gk::SelfRowIn {
                group: grp.to_string(),
                gen: *gen,
                seed: s,
                sk: seat.tag_sk,
                sx: seat.tag_sx,
                kind: gk::self_row::SELF_ROW,
                sealed,
            })
            .collect()
    }

    /// A stored group as the database holds it, into `g`. An old incarnation's group is
    /// reset and starts a new generation at its next fetch (2i). Every connection seat is
    /// an exit at start: its connection is gone.
    pub async fn load(&self, g: &mut GroupState) -> Result<()> {
        let Store::Db(d) = self else { return Ok(()) };
        let grp = g.id.clone();
        // Material of a commit that never moved the head: this actor is its only writer
        db::sweep_orphans(&d.db, &grp, None).await?;
        let Some(row) = db::group(&d.db, &grp).await? else {
            return Ok(());
        };
        let gens = db::gens(&d.db, &grp).await?;
        g.gens = gens.iter().map(|(gen, _)| *gen).collect();
        if !g.gens.contains(&row.head.gen) {
            g.gens.push(row.head.gen);
        }
        g.exits = Exits::new(row.head.exits_next);
        if row.head.incarnation != d.incarnation {
            while db::reset_step(&d.db, &grp, &row.head.gen).await? > 0 {}
            g.new_gen = true;
            return Ok(());
        }
        let gen = row.head.gen;
        let kind = g.kind;
        let decode = |h: &db::Header| SignedHeader::decode(&h.body, &h.sig, kind, &grp).ok();
        let mut headers: HashMap<[u8; 32], SignedHeader> = HashMap::new();
        for h in db::headers(&d.db, &grp, &gen).await? {
            if let Some(sh) = decode(&h) {
                headers.insert(sh.d(), sh);
            }
        }
        let Some(head) = headers.get(&row.head.d).cloned() else {
            g.new_gen = true;
            return Ok(());
        };
        let hd = head.header();
        let opening = match hd.kind {
            Kind::Join => db::opening(&d.db, &grp, &gen, hd.epoch)
                .await?
                .and_then(|h| decode(&h))
                .unwrap_or_else(|| head.clone()),
            _ => head.clone(),
        };
        let kh = headers
            .get(&head.kh())
            .cloned()
            .unwrap_or_else(|| head.clone());
        let parent_of = |sh: &SignedHeader| {
            (sh.header().kind == Kind::Regenesis)
                .then(|| headers.get(&sh.header().parent).cloned())
                .flatten()
        };
        g.khs = headers
            .values()
            .filter(|h| h.header().kind.sets_keyholders())
            .map(|h| (h.d(), (h.clone(), parent_of(h))))
            .collect();
        let mut recent: Vec<SignedHeader> = headers.values().cloned().collect();
        recent.sort_by_key(|h| (h.header().epoch, h.header().join));
        let from = recent.len().saturating_sub(64);
        g.recent = recent.into_iter().skip(from).collect();
        // Current versions, and how each is reached
        let lists = db::current_lists(&d.db, &grp, &gen).await?;
        let mut leaves = Vec::with_capacity(lists.len());
        for l in &lists {
            let seats: Vec<SeatRef> = l.seats.iter().filter_map(seat_of).collect();
            leaves.push(Listed {
                leaf: Leaf {
                    b: l.b,
                    v: l.v,
                    pool: l.pool,
                    seats: seats.len() as u16,
                    list: l.digest,
                    via: l.via.map_or(Via::Row, |from| Via::Ratchet { from }),
                },
                seats,
            });
            let mut ratchets = vec![];
            let (mut at, mut via, mut e) = (l.v, l.via, l.epoch_made);
            while let Some(from) = via {
                ratchets.push(RatchetStep { e, from, to: at });
                let Some(prev) = db::list(&d.db, &grp, &gen, l.b, from).await? else {
                    break;
                };
                (at, via, e) = (from, prev.via, prev.epoch_made);
            }
            ratchets.reverse();
            g.vers.insert(
                (l.b, l.v),
                Ver {
                    base_v: l.base_v,
                    ratchets,
                    made: (l.epoch_made, 0),
                    maker: HolderRef {
                        m: MemberId::Conn(0),
                        kx: [0; 32],
                    },
                },
            );
            g.used_v.insert(l.v);
        }
        leaves.sort_by_key(|l| l.leaf.b);
        let flat: Vec<Leaf> = leaves.iter().map(|l| l.leaf).collect();
        g.tree = Arc::new(BucketTree::new(&flat)?);
        g.leaves = Arc::new(leaves);
        for s in db::seats(&d.db, &grp, &gen).await? {
            if let Some(seat) = seat_of(&s.seat) {
                g.seats.insert(
                    seat,
                    Seat {
                        b: s.b,
                        seed: s.seed,
                        dh: s.dh,
                        account: s.account,
                    },
                );
            }
        }
        for s in db::seals(&d.db, &grp, &gen, hd.epoch).await? {
            g.seals.insert((s.b, s.v), s.bytes);
        }
        // Exits not dealt with, in batches of the cap; one whose seat no longer sits (a
        // Regenesis since) needs none
        let mut left = vec![];
        for x in db::exits(&d.db, &grp).await? {
            if x.gen != gen {
                continue;
            }
            let Some((seat, s)) = seat_of(&x.seat).and_then(|r| Some((r, g.seats.get(&r)?))) else {
                continue;
            };
            left.push(Leaving {
                exit: voipc_crypto::group_key::commit::Exit {
                    seq: x.seq,
                    seat,
                    b: s.b,
                },
                cause: x.cause,
            });
        }
        left.sort_by_key(|l| l.exit.seq);
        g.exits.push_closed(0, left, hd.gated);
        // A gated group's names: lists, removal headers, the step before the oldest
        let mut lists = vec![];
        let mut removals = vec![];
        let mut step: Option<NamesStepIn> = None;
        for n in db::names(&d.db, &grp, &gen, (0, 0), (hd.epoch, hd.join)).await? {
            match n.kind {
                NAMES_LIST => lists.push(Kept {
                    gen,
                    list: NamesListIn {
                        time: n.time,
                        epoch: n.epoch,
                        join: n.j,
                        added: n.list,
                    },
                    hash: n.names_hash,
                }),
                NAMES_REMOVED => {
                    if let Some(sh) = postcard::from_bytes::<HeaderIn>(&n.list)
                        .ok()
                        .and_then(|h| SignedHeader::decode(&h.body, &h.sig, kind, &grp).ok())
                    {
                        removals.push((gen, sh));
                    }
                }
                NAMES_STEP => {
                    if let Ok(list) = <[u8; 32]>::try_from(n.list.as_slice()) {
                        step = Some(NamesStepIn {
                            before: n.names_hash,
                            time: n.time,
                            epoch: n.epoch,
                            join: n.j,
                            list,
                        });
                    }
                }
                _ => {}
            }
        }
        g.names.restore(lists, removals, step.map(|s| (gen, s)));
        // Keyholder entries with their pairs (a later Add, Remove or Replace makes `KRK`
        // welcomes to offline ones too), ranks, devices, misses and last online (2i)
        let kept = holder_rows(&d.db, &grp).await?;
        g.holders.set_to(kh.header().keyholders.clone(), |kx| {
            kept.iter()
                .find(|r| r.kx == *kx)
                .and_then(|r| r.pair.clone())
        });
        for r in kept {
            if !g.holders.set.iter().any(|k| k.kx == r.kx) {
                continue;
            }
            if r.rank != u8::MAX {
                g.holders.rank.insert(r.kx, r.rank);
            }
            if let Some(dev) = r.device {
                g.holders.device.insert(r.kx, dev);
            }
            let st = g.holders.stats.entry(r.kx).or_default();
            st.away_since = Some(r.last_online);
            st.missed = r.misses.missed.into();
            st.declined = r.misses.declined.into();
        }
        // Each account entry's newest counter: below it seven days, an entry goes (2d)
        let accounts: HashSet<[u8; 16]> =
            g.holders.set.iter().filter_map(|k| k.m.account()).collect();
        for a in accounts {
            if let Some(k) = db::seat_keys(&d.db, &a).await? {
                g.holders.newest.insert(a, (k.n, k.published));
            }
        }
        g.rolls = row.head.rolls;
        g.gen_time = row.head.gen_time;
        g.head = Some(Head {
            parent: parent_of(&head),
            kh,
            opening,
            opened_ms: row.updated,
            sh: head,
        });
        Ok(())
    }
}

async fn commit_db(d: &DbStore, g: &GroupState, t: &Taken, now: u64) -> Result<()> {
    let s = &d.db;
    let grp = g.id.as_str();
    let a = &t.applied;
    let sh = &a.header;
    let h = sh.header();
    let gen = h.gen;
    let maker_b = maker(&t.maker);
    let c = db::begin_commit(s, grp).await?;
    let vids: Vec<(u64, u64)> = a.made.iter().map(|l| (l.leaf.b, l.leaf.v)).collect();
    if let Some(v) = db::put_vids(s, grp, c, &gen, &vids).await? {
        return Err(Fail::Check(format!("rule 16: version id {v} was used")).into());
    }
    let vers: HashMap<(u64, u64), &Ver> = t.vers.iter().map(|(k, v)| (*k, v)).collect();
    let lists: Vec<db::List> = a
        .made
        .iter()
        .map(|l| db::List {
            b: l.leaf.b,
            v: l.leaf.v,
            pool: l.leaf.pool,
            via: match l.leaf.via {
                Via::Ratchet { from } => Some(from),
                Via::Row => None,
            },
            base_v: vers
                .get(&(l.leaf.b, l.leaf.v))
                .map_or(l.leaf.v, |v| v.base_v),
            epoch_made: h.epoch,
            epoch_until: None,
            seats: l.seats.iter().map(seat_record).collect(),
            digest: l.leaf.list,
            current: false,
        })
        .collect();
    if let Some((b, v)) = db::put_lists(s, grp, c, &gen, &lists).await? {
        return Err(Fail::Check(format!("rule 16: version ({b}, {v}) was stored")).into());
    }
    let seated: HashMap<SeatRef, u64> = a.seated.iter().map(|(s, v)| (*s, v.b)).collect();
    let keys: HashMap<SeatRef, [u8; 33]> = t
        .due
        .due
        .joiners
        .iter()
        .map(|j| (j.seat, j.keys.dh_bytes()[..].try_into().unwrap_or([0; 33])))
        .collect();
    let held: HashMap<SeatRef, u32> = a.held.iter().copied().collect();
    let new: Vec<db::Seat> = a
        .seated
        .iter()
        .map(|(seat, v)| db::Seat {
            seat: seat_record(seat),
            dh: keys.get(seat).copied().unwrap_or([0; 33]),
            b: v.b,
            pool: Pool::of(&seat.m),
            seed: held.get(seat).copied().unwrap_or(h.seed),
            last_use: now,
            account: seat.m.account(),
        })
        .collect();
    db::put_new_seats(s, grp, c, &gen, &new).await?;
    let moves: Vec<(db::SeatRec, u64)> = a
        .made
        .iter()
        .flat_map(|l| l.seats.iter().map(move |s| (s, l.leaf.b)))
        .filter(|(s, b)| !seated.contains_key(s) && g.seats.get(s).is_some_and(|x| x.b != *b))
        .map(|(s, b)| (seat_record(s), b))
        .collect();
    db::put_moves(s, grp, c, &gen, &moves).await?;
    let lists_by: HashMap<(u64, u64), &Listed> =
        a.made.iter().map(|l| ((l.leaf.b, l.leaf.v), l)).collect();
    let mut rows = vec![];
    for r in &t.commit.rows {
        let Some(l) = lists_by.get(&(r.b, r.v)) else {
            continue;
        };
        for (i, seat) in l.seats.iter().enumerate() {
            if let Some((bytes, seed)) = r.row(i) {
                rows.push(db::BucketRow {
                    b: r.b,
                    v: r.v,
                    seat: seat_record(seat),
                    s: seed as u32,
                    maker: maker_b,
                    bytes: bytes.to_vec(),
                    epoch_made: h.epoch,
                });
            }
        }
    }
    db::put_rows(s, grp, c, &gen, &rows).await?;
    let welcomes: Vec<db::Welcome> = t
        .commit
        .welcomes
        .iter()
        .map(|w| db::Welcome {
            seat: seat_record(&w.seat),
            kind: db::WelcomeKind::Seat,
            s: w.s,
            version: Some((w.b, w.v)),
            maker: maker_b,
            bytes: w.bytes.clone(),
            made: now,
        })
        .collect();
    db::put_welcomes(s, grp, c, &gen, &welcomes).await?;
    let seals: Vec<db::Seal> = t
        .commit
        .seals
        .iter()
        .map(|x| db::Seal {
            epoch: h.epoch,
            b: x.b,
            v: x.v,
            bytes: x.bytes.clone(),
        })
        .collect();
    db::put_seals(s, grp, c, &gen, &seals).await?;
    db::put_keyring(
        s,
        grp,
        c,
        &gen,
        &[db::KeyringPiece {
            epoch: h.epoch,
            j: h.join,
            bytes: t.commit.keyring.clone(),
        }],
    )
    .await?;
    let krk: Vec<db::Krk> = t
        .commit
        .krk
        .iter()
        .map(|k| db::Krk {
            epoch: h.epoch,
            holder: k.to.kx,
            maker: maker(&HolderRef {
                m: h.signer,
                kx: k.from_kx,
            }),
            bytes: k.bytes.clone(),
        })
        .collect();
    db::put_krk(s, grp, c, &gen, &krk).await?;
    let mut keep = KEEP_RECENT;
    if h.kind.sets_keyholders() {
        keep |= KEEP_KH;
    }
    if h.kind.starts_anew() {
        keep |= KEEP_START;
    }
    let header = db::Header {
        d: sh.d(),
        gen,
        epoch: h.epoch,
        j: h.join,
        kind: h.kind,
        time: h.time,
        body: sh.body().to_vec(),
        sig: sh.sig().to_vec(),
        keep,
    };
    let parent_keep: Vec<([u8; 32], u32)> = t
        .head
        .parent
        .iter()
        .map(|p| (p.d(), KEEP_PARENT | KEEP_RECENT))
        .collect();
    // A gated group's names (2g): the list of a Join and of each header a fold starts from
    // (the gate-on opening is both 0 and 1), and each header carrying a `removed` list
    let was_gated = g
        .head
        .as_ref()
        .is_some_and(|x| x.sh.header().gated && x.sh.header().gen == gen);
    let mut names: Vec<db::Names> = vec![];
    if h.gated && (h.kind == Kind::Join || starts_names(sh, was_gated)) {
        names.push(db::Names {
            gen,
            epoch: h.epoch,
            j: h.join,
            kind: NAMES_LIST,
            time: h.time,
            names_hash: h.names_hash,
            list: postcard::to_allocvec(h.added_list())?,
        });
    }
    if h.gated && matches!(&h.removed, voipc_crypto::group_key::Removed::List(l) if !l.is_empty()) {
        names.push(db::Names {
            gen,
            epoch: h.epoch,
            j: h.join,
            kind: NAMES_REMOVED,
            time: h.time,
            names_hash: h.names_hash,
            list: postcard::to_allocvec(&HeaderIn {
                body: sh.body().to_vec(),
                sig: sh.sig().to_vec(),
            })?,
        });
    }
    let upto = if h.kind.starts_anew() {
        a.exits_done.iter().copied().max().unwrap_or(0)
    } else {
        h.exits_upto
    };
    let head = db::Head {
        kind: g.kind,
        gen,
        gen_time: if t.new_gen { now } else { g.gen_time },
        incarnation: d.incarnation,
        d: sh.d(),
        epoch: h.epoch,
        join: h.join,
        exits_next: g.exits.next,
        rolls: a.rolls,
        gated: h.gated,
    };
    let drops: Vec<u64> = t.commit.drops.clone();
    let moved = db::move_head(
        s,
        grp,
        c,
        &head,
        &db::HeadMove {
            was: t.was,
            headers: &[header],
            keep: &parent_keep,
            drops: &drops,
            retire_all: h.kind == Kind::Regenesis,
            exits_upto: upto,
            names: &names,
        },
    )
    .await?;
    if moved != db::Moved::Done {
        return Err(Fail::Store(format!("{moved:?}")).into());
    }
    // A commit's own seed welcomes (a voice KeyholdersRemove's; a text commit owes none, 2d)
    // go in as a page does, once the head moved: no read takes them before
    let seed: Vec<db::Welcome> = t
        .commit
        .seed_welcomes
        .iter()
        .map(|w| db::Welcome {
            seat: seat_record(&w.seat),
            kind: db::WelcomeKind::Seed,
            s: h.seed,
            version: None,
            maker: maker_b,
            bytes: w.bytes.clone(),
            made: now,
        })
        .collect();
    if !seed.is_empty() {
        db::put_seed_welcomes(s, grp, &gen, &seed).await?;
    }
    Ok(())
}

// ── Keyholder entries (2i) ────────────────────────────────────────────────

/// A keyholder entry as the database keeps it, its pair in a column of its own.
struct HolderRow {
    kx: [u8; 32],
    device: Option<Vec<u8>>,
    rank: u8,
    last_online: u64,
    misses: db::Misses,
    pair: Option<Pair>,
}

async fn holder_rows(store: &Db, grp: &str) -> Result<Vec<HolderRow>> {
    type T = (
        Vec<u8>,
        Vec<u8>,
        Option<Vec<u8>>,
        i16,
        i64,
        Vec<u8>,
        Option<Vec<u8>>,
    );
    let rows: Vec<T> = on!(store, pool => {
        sqlx::query_as("SELECT kx, m, device, rank, last_online, missed, pair FROM voipc_gk_holders WHERE grp = $1")
            .bind(grp)
            .fetch_all(pool)
            .await?
    });
    let mut out = vec![];
    for (kx, m, device, rank, last_online, missed, pair) in rows {
        let Ok(kx) = <[u8; 32]>::try_from(kx) else {
            continue;
        };
        let misses = postcard::from_bytes::<db::Misses>(&missed).unwrap_or_default();
        let pair = pair
            .and_then(|p| postcard::from_bytes::<gk::EndorsedPair>(&p).ok())
            .zip(member_of(&m))
            .and_then(|(p, m)| voipc_crypto::group_key::wire::pair(&p, m.into()).ok());
        out.push(HolderRow {
            kx,
            device,
            rank: u8::try_from(rank).unwrap_or(u8::MAX),
            last_online: u64::try_from(last_online).unwrap_or(0),
            misses,
            pair,
        });
    }
    Ok(out)
}

async fn put_holders(store: &Db, g: &GroupState, now: u64) -> Result<()> {
    let grp = g.id.as_str();
    let online: HashSet<[u8; 32]> = g
        .holders
        .online(&g.vols)
        .iter()
        .map(|v| v.pair.kx())
        .collect();
    const Q: &str =
        "INSERT INTO voipc_gk_holders (grp, kx, m, device, rank, last_online, missed, pair)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (grp, kx) DO UPDATE SET m = excluded.m, device = excluded.device,
         rank = excluded.rank, last_online = excluded.last_online, missed = excluded.missed,
         pair = excluded.pair";
    for k in &g.holders.set {
        let st = g.holders.stats.get(&k.kx);
        let misses = db::Misses {
            missed: st
                .map(|s| s.missed.iter().copied().collect())
                .unwrap_or_default(),
            declined: st
                .map(|s| s.declined.iter().copied().collect())
                .unwrap_or_default(),
        };
        let pair = g
            .holders
            .pairs
            .get(&k.kx)
            .map(|p| postcard::to_allocvec(&gk::EndorsedPair::from(p)))
            .transpose()?;
        let missed = postcard::to_allocvec(&misses)?;
        let last = if online.contains(&k.kx) {
            now
        } else {
            st.and_then(|s| s.away_since).unwrap_or(now)
        };
        let rank = g.holders.rank.get(&k.kx).copied().unwrap_or(u8::MAX);
        let device = g.holders.device.get(&k.kx).cloned();
        on!(store, pool => {
            sqlx::query(Q)
                .bind(grp)
                .bind(&k.kx[..])
                .bind(&k.m.seat_id()[..])
                .bind(device)
                .bind(i16::from(rank))
                .bind(i64::try_from(last)?)
                .bind(missed.as_slice())
                .bind(pair.as_deref())
                .execute(pool)
                .await?;
        });
    }
    for h in db::holders(store, grp).await? {
        if !g.holders.set.iter().any(|k| k.kx == h.kx) {
            db::drop_holder(store, grp, &h.kx).await?;
        }
    }
    Ok(())
}

// ── Seat keys of accounts ─────────────────────────────────────────────────

pub(crate) fn ik_raw(k: &[u8]) -> Option<[u8; 32]> {
    match k {
        [0x05, rest @ ..] if rest.len() == 32 => rest.try_into().ok(),
        k if k.len() == 32 => k.try_into().ok(),
        _ => None,
    }
}

type KeysTuple = (Vec<u8>, i64, Vec<u8>, Vec<u8>, i64, Vec<u8>, Vec<u8>);

/// An account's current seat keys (origin 0x01) with its identity key, as a joiner's pair.
fn keyed(t: KeysTuple) -> Option<([u8; 16], [u8; 32], Pair)> {
    let (a, n, kem, dh, made, sig, ik) = t;
    let a: [u8; 16] = a.try_into().ok()?;
    let wire = gk::EndorsedPair {
        origin: gk::origin::VAULT_SEAT,
        u: 0,
        kem,
        dh,
        n: u32::try_from(n).ok()?,
        made: u64::try_from(made).ok()?,
        sig,
    };
    let pair = voipc_crypto::group_key::wire::pair(&wire, gk::GkMember::Account(a)).ok()?;
    Some((a, ik_raw(&ik)?, pair))
}

/// A page of the eager seats of a stored group's new start (plan 2d): the accounts that keep
/// `conv`'s log with published seat keys and an identity key, after `after`, by account.
pub async fn eager_page(
    store: &Db,
    conv: &str,
    after: Option<&[u8; 16]>,
    limit: u32,
) -> Result<Vec<([u8; 16], Joiner)>> {
    let rows: Vec<KeysTuple> = on!(store, pool => {
        sqlx::query_as(
            "SELECT k.account, k.n, k.kem, k.dh, k.made, k.sig, i.identity_key
             FROM voipc_members m JOIN voipc_gk_seatkeys k ON k.account = m.account AND k.current
             JOIN voipc_identity i ON i.account = m.account
             WHERE m.conv = $1 AND m.account > $2 ORDER BY m.account LIMIT $3",
        )
        .bind(conv)
        .bind(after.map_or(&[][..], |a| &a[..]))
        .bind(i64::from(limit))
        .fetch_all(pool)
        .await?
    });
    // A page is whole even where one account's keys do not decode: the next starts after it
    let mut out = Vec::with_capacity(rows.len());
    for t in rows {
        let last: Option<[u8; 16]> = t.0.clone().try_into().ok();
        match keyed(t) {
            Some((a, ik, pair)) => out.push((
                a,
                Joiner {
                    seat: pair.keys.seat(MemberId::Account(a)),
                    ik,
                    keys: pair.keys,
                    endorsement: pair.endorsement,
                    returning: false,
                },
            )),
            None => tracing::debug!(account = ?last, "seat keys that do not decode"),
        }
    }
    Ok(out)
}

/// The identity keys and current seat keys of `accounts` (a seed-welcome page's KEM keys).
pub async fn seat_kems(
    store: &Db,
    accounts: &[[u8; 16]],
) -> Result<HashMap<[u8; 16], ([u8; 32], Pair)>> {
    let mut out = HashMap::new();
    for part in accounts.chunks(100) {
        let rows: Vec<KeysTuple> = on!(store, pool => {
            let mut q = sqlx::QueryBuilder::new(
                "SELECT k.account, k.n, k.kem, k.dh, k.made, k.sig, i.identity_key
                 FROM voipc_gk_seatkeys k JOIN voipc_identity i ON i.account = k.account
                 WHERE k.current AND k.account IN (",
            );
            let mut sep = q.separated(", ");
            for a in part {
                sep.push_bind(a.to_vec());
            }
            sep.push_unseparated(")");
            q.build_query_as().persistent(false).fetch_all(pool).await?
        });
        out.extend(
            rows.into_iter()
                .filter_map(keyed)
                .map(|(a, ik, p)| (a, (ik, p))),
        );
    }
    Ok(out)
}

/// A page of the conversations `account` keeps the log of (`voipc_members`), after `after`.
pub async fn member_convs(
    store: &Db,
    account: &[u8; 16],
    after: Option<&str>,
    limit: u32,
) -> Result<Vec<String>> {
    Ok(on!(store, pool => {
        sqlx::query_scalar(
            "SELECT conv FROM voipc_members WHERE account = $1 AND conv > $2 ORDER BY conv LIMIT $3",
        )
        .bind(&account[..])
        .bind(after.unwrap_or(""))
        .bind(i64::from(limit))
        .fetch_all(pool)
        .await?
    }))
}

/// Whether `account` keeps `conv`'s log (`voipc_members`): kept reads need no follow.
pub async fn is_member(store: &Db, conv: &str, account: &[u8; 16]) -> Result<bool> {
    let row: Option<i32> = on!(store, pool => {
        sqlx::query_scalar("SELECT 1 FROM voipc_members WHERE conv = $1 AND account = $2")
            .bind(conv)
            .bind(&account[..])
            .fetch_optional(pool)
            .await?
    });
    Ok(row.is_some())
}

// ── Kept history (C4, plan 2d "`at` entries") ─────────────────────────────

/// A leaf a past epoch's opening committed to, with its version's base and when it was made.
struct PastLeaf {
    leaf: Leaf,
    base_v: u64,
    made: u32,
}

fn pool_of(x: i16) -> Option<Pool> {
    match x {
        0 => Some(Pool::Accounts),
        1 => Some(Pool::Conns),
        _ => None,
    }
}

/// The leaves the opening `sh` committed to, and their tree: an opening seals every current
/// version and a Join only those it made, so the seals of the one commit at that epoch
/// whose versions make the header's bucket root are the opening's.
async fn opening_leaves(
    store: &Db,
    grp: &str,
    sh: &SignedHeader,
) -> Result<Option<(Vec<PastLeaf>, BucketTree)>> {
    type T = (i64, i64, i16, Option<i64>, i64, i64, Vec<u8>, i64, i64);
    let h = sh.header();
    let rows: Vec<T> = on!(store, pool => {
        sqlx::query_as(
            "SELECT l.b, l.v, l.pool, l.via, l.base_v, l.epoch_made, l.digest,
               CAST(LENGTH(l.seats) AS BIGINT), s.commit_id
             FROM voipc_gk_seals s JOIN voipc_gk_lists l
               ON l.grp = s.grp AND l.gen = s.gen AND l.b = s.b AND l.v = s.v
             WHERE s.grp = $1 AND s.gen = $2 AND s.epoch = $3
             AND NOT EXISTS (SELECT 1 FROM voipc_gk_pending p WHERE p.grp = s.grp AND p.commit_id = s.commit_id)",
        )
        .bind(grp)
        .bind(&h.gen[..])
        .bind(i64::from(h.epoch))
        .fetch_all(pool)
        .await?
    });
    let mut by: HashMap<i64, Vec<PastLeaf>> = HashMap::new();
    for (b, v, pool, via, base_v, made, digest, n, c) in rows {
        let (Some(pool), Ok(list), Ok(seats)) = (
            pool_of(pool),
            <[u8; 32]>::try_from(digest),
            u16::try_from(n / 33),
        ) else {
            continue;
        };
        by.entry(c).or_default().push(PastLeaf {
            leaf: Leaf {
                b: b as u64,
                v: v as u64,
                pool,
                seats,
                list,
                via: via.map_or(Via::Row, |from| Via::Ratchet { from: from as u64 }),
            },
            base_v: base_v as u64,
            made: u32::try_from(made).unwrap_or(0),
        });
    }
    for (_, mut leaves) in by {
        if leaves.len() != h.buckets as usize {
            continue;
        }
        leaves.sort_by_key(|l| l.leaf.b);
        let flat: Vec<Leaf> = leaves.iter().map(|l| l.leaf).collect();
        if let Ok(tree) = BucketTree::new(&flat) {
            if tree.root() == h.bucket_root {
                return Ok(Some((leaves, tree)));
            }
        }
    }
    Ok(None)
}

/// The welcomes (seat) and rows to any seat of `m` in generation `gen`, by version.
async fn member_bases(
    store: &Db,
    grp: &str,
    gen: &[u8; 16],
    m: &MemberId,
) -> Result<HashMap<(u64, u64), (SeatRef, Base)>> {
    type T = (i64, i64, Vec<u8>, i64, Vec<u8>, Vec<u8>);
    let id = m.seat_id();
    let lo = [&id[..], &[0u8; 16][..]].concat();
    let hi = [&id[..], &[0xffu8; 16][..]].concat();
    let welcomes: Vec<T> = on!(store, pool => {
        sqlx::query_as(
            "SELECT b, v, seat, s, maker, bytes FROM voipc_gk_welcomes w
             WHERE grp = $1 AND gen = $2 AND seat >= $3 AND seat <= $4 AND kind = 0 AND b IS NOT NULL
             AND NOT EXISTS (SELECT 1 FROM voipc_gk_pending p WHERE p.grp = w.grp AND p.commit_id = w.commit_id)",
        )
        .bind(grp)
        .bind(&gen[..])
        .bind(lo.as_slice())
        .bind(hi.as_slice())
        .fetch_all(pool)
        .await?
    });
    let rows: Vec<T> = on!(store, pool => {
        sqlx::query_as(
            "SELECT r.b, r.v, r.seat, r.s, r.maker, r.bytes
             FROM voipc_gk_rows r JOIN voipc_gk_lists l
               ON l.grp = r.grp AND l.gen = r.gen AND l.b = r.b AND l.v = r.v AND l.commit_id = r.commit_id
             WHERE r.grp = $1 AND r.gen = $2 AND r.seat >= $3 AND r.seat <= $4
             AND NOT EXISTS (SELECT 1 FROM voipc_gk_pending p WHERE p.grp = r.grp AND p.commit_id = r.commit_id)",
        )
        .bind(grp)
        .bind(&gen[..])
        .bind(lo.as_slice())
        .bind(hi.as_slice())
        .fetch_all(pool)
        .await?
    });
    let mut out = HashMap::new();
    for (welcome, list) in [(true, welcomes), (false, rows)] {
        for (b, v, seat, s, mk, bytes) in list {
            let (Ok(rec), Ok(mk), Ok(s)) = (
                <[u8; 33]>::try_from(seat),
                <[u8; 49]>::try_from(mk),
                u32::try_from(s),
            ) else {
                continue;
            };
            let (Some(seat), Some(from)) = (seat_of(&rec), holder_of(&mk)) else {
                continue;
            };
            out.entry((b as u64, v as u64))
                .or_insert((seat, (s, from, welcome, bytes)));
        }
    }
    Ok(out)
}

/// One `at` entry's answer (plan 2d, C4): the epoch's opening header (with a Regenesis's
/// parent), the keyholder links back from `anchor` (the member's floor's `kh`) to the one
/// the opening names when `anchor` is a keyholder header at or after it, the member's leaf,
/// path and seal then, its keying (the welcome or row of its version then, or of the
/// version it ratcheted from, with the steps), the seed welcome under that row's seed if
/// one is kept, and its self-rows and history rows for that seed. `None` when the opening,
/// its versions or any seat of `m` in them is not kept.
pub async fn past(
    store: &Db,
    grp: &str,
    m: MemberId,
    at: EpochRef,
    anchor: Option<[u8; 32]>,
) -> Result<Option<InPiece>> {
    let decode = |h: &db::Header| SignedHeader::decode(&h.body, &h.sig, GroupKind::Text, grp).ok();
    let Some(sh) = db::opening(store, grp, &at.gen, at.epoch)
        .await?
        .and_then(|h| decode(&h))
    else {
        return Ok(None);
    };
    let h = sh.header();
    let parent = match h.kind {
        Kind::Regenesis => db::header(store, grp, &h.parent)
            .await?
            .and_then(|x| decode(&x)),
        _ => None,
    };
    let Some((leaves, tree)) = opening_leaves(store, grp, &sh).await? else {
        return Ok(None);
    };
    let bases = member_bases(store, grp, &at.gen, &m).await?;
    let Some((l, (seat, base))) = leaves
        .iter()
        .find_map(|l| bases.get(&(l.leaf.b, l.base_v)).map(|x| (l, x)))
    else {
        return Ok(None);
    };
    let Some(seal) = db::seal(store, grp, &at.gen, at.epoch, l.leaf.b, l.leaf.v).await? else {
        return Ok(None);
    };
    // The ratchet steps from its base to the version it held then, oldest first
    let mut ratchets = vec![];
    let (mut to, mut via, mut e) = (l.leaf.v, l.leaf.via, l.made);
    while let Via::Ratchet { from } = via {
        ratchets.push(RatchetStep { e, from, to });
        let Some(prev) = db::list(store, grp, &at.gen, l.leaf.b, from).await? else {
            return Ok(None);
        };
        to = from;
        via = prev.via.map_or(Via::Row, |f| Via::Ratchet { from: f });
        e = prev.epoch_made;
    }
    ratchets.reverse();
    let (s, from, welcome, bytes) = base.clone();
    let keying = SeatKeying {
        b: l.leaf.b,
        base_v: l.base_v,
        s,
        from: from.into(),
        welcome: welcome.then(|| bytes.clone()),
        row: (!welcome).then_some(bytes),
        ratchets,
    };
    let seed_welcome = if welcome {
        None
    } else {
        let w = db::welcome(
            store,
            grp,
            &at.gen,
            &seat_record(seat),
            db::WelcomeKind::Seed,
            s,
        )
        .await?;
        w.and_then(|w| {
            Some(gk::SeedWelcomeIn {
                s,
                from: holder_of(&w.maker)?.into(),
                bytes: w.bytes,
            })
        })
    };
    let self_rows = match seat.m.account() {
        Some(a) => own_rows(store, grp, &a, &at.gen, seat, s).await?,
        None => vec![],
    };
    // Keyholder links back from the anchor, newest first, to the one the opening names
    let mut walk = vec![];
    if let Some(a) = anchor {
        let ah = db::header(store, grp, &a).await?.and_then(|x| decode(&x));
        if let Some(ah) = ah.filter(|x| {
            let x = x.header();
            x.gen == h.gen && x.kind.sets_keyholders() && (h.epoch <= x.epoch || sh.kh() == a)
        }) {
            let target = sh.kh();
            let mut cur = ah;
            while cur.d() != target && walk.len() < MAX_WALK {
                let want = cur.header().kh_parent;
                let Some(next) = db::header(store, grp, &want)
                    .await?
                    .and_then(|x| decode(&x))
                else {
                    break;
                };
                let p = match next.header().kind {
                    Kind::Regenesis => db::header(store, grp, &next.header().parent)
                        .await?
                        .and_then(|x| decode(&x)),
                    _ => None,
                };
                walk.push(link(&next, p.as_ref()));
                cur = next;
            }
        }
    }
    Ok(Some(InPiece {
        walk,
        head: Some(link(&sh, parent.as_ref())),
        leaf: Some(LeafIn::from(l.leaf)),
        path: tree
            .path_of(l.leaf.b)
            .and_then(|p| PathIn::try_from(p).ok()),
        seal: Some(seal.bytes),
        seat: Some(keying),
        seed_welcome,
        self_rows,
        past: Some(at),
        ..InPiece::default()
    }))
}

/// An account's self-rows and history rows for its seat `seat` under seed `s`.
async fn own_rows(
    store: &Db,
    grp: &str,
    account: &[u8; 16],
    gen: &[u8; 16],
    seat: &SeatRef,
    s: u32,
) -> Result<Vec<SelfRowIn>> {
    let rows: Vec<(i16, Vec<u8>)> = on!(store, pool => {
        sqlx::query_as(
            "SELECT kind, sealed FROM voipc_gk_self WHERE grp = $1 AND account = $2
             AND gen = $3 AND seed = $4 AND tag_sk = $5 AND tag_sx = $6",
        )
        .bind(grp)
        .bind(&account[..])
        .bind(&gen[..])
        .bind(i64::from(s))
        .bind(&seat.tag_sk[..])
        .bind(&seat.tag_sx[..])
        .fetch_all(pool)
        .await?
    });
    Ok(rows
        .into_iter()
        .filter_map(|(kind, sealed)| {
            Some(SelfRowIn {
                group: grp.to_string(),
                gen: *gen,
                seed: s,
                sk: seat.tag_sk,
                sx: seat.tag_sx,
                kind: u8::try_from(kind).ok()?,
                sealed,
            })
        })
        .collect())
}

/// Where a `SelfRowsList` page ends: the next page starts after this row.
type RowsAfter = (String, [u8; 16], u32, [u8; 8], [u8; 8], u8);

/// A `SelfRows` page's rows, under the 64 KiB frame: history rows are up to 16 KiB each.
const SELF_ROWS_PAGE_BYTES: usize = 48 * 1024;

/// A page of `account`'s self-rows and history rows (`SelfRowsList`), every group,
/// generation and seed, after `after` (the `next` of the page before, opaque to the app).
pub async fn rows_of(
    store: &Db,
    account: &[u8; 16],
    after: Option<&[u8]>,
    limit: u16,
) -> Result<(Vec<SelfRowIn>, Option<Vec<u8>>)> {
    type T = (String, Vec<u8>, i64, Vec<u8>, Vec<u8>, i16, Vec<u8>);
    let from: RowsAfter = match after {
        Some(a) => postcard::from_bytes(a)?,
        None => (String::new(), [0; 16], 0, [0; 8], [0; 8], 0),
    };
    // The first page takes the smallest key too
    let first = after.is_none();
    let rows: Vec<T> = on!(store, pool => {
        sqlx::query_as(
            "SELECT grp, gen, seed, tag_sk, tag_sx, kind, sealed FROM voipc_gk_self
             WHERE account = $1 AND ($8 OR (grp, gen, seed, tag_sk, tag_sx, kind) > ($2, $3, $4, $5, $6, $7))
             ORDER BY grp, gen, seed, tag_sk, tag_sx, kind LIMIT $9",
        )
        .bind(&account[..])
        .bind(&from.0)
        .bind(&from.1[..])
        .bind(i64::from(from.2))
        .bind(&from.3[..])
        .bind(&from.4[..])
        .bind(i16::from(from.5))
        .bind(first)
        .bind(i64::from(limit))
        .fetch_all(pool)
        .await?
    });
    let mut out = Vec::with_capacity(rows.len());
    let (mut bytes, mut full) = (0, rows.len() == usize::from(limit));
    for (grp, gen, seed, sk, sx, kind, sealed) in rows {
        bytes += grp.len() + sealed.len() + 64;
        if bytes > SELF_ROWS_PAGE_BYTES && !out.is_empty() {
            full = true;
            break;
        }
        let (Ok(gen), Ok(seed), Ok(sk), Ok(sx), Ok(kind)) = (
            <[u8; 16]>::try_from(gen),
            u32::try_from(seed),
            <[u8; 8]>::try_from(sk),
            <[u8; 8]>::try_from(sx),
            u8::try_from(kind),
        ) else {
            continue;
        };
        out.push(SelfRowIn {
            group: grp,
            gen,
            seed,
            sk,
            sx,
            kind,
            sealed,
        });
    }
    let next = match out.last() {
        Some(r) if full => Some(postcard::to_allocvec(&(
            r.group.clone(),
            r.gen,
            r.seed,
            r.sk,
            r.sx,
            r.kind,
        ))?),
        _ => None,
    };
    Ok((out, next))
}

// ── Sweeps (plan 2e, C4 retention) ────────────────────────────────────────

/// Header kinds by their code in `voipc_gk_headers.kind` (accounts::gk's postcard order).
const KINDS: [Kind; 7] = [
    Kind::Genesis,
    Kind::Regenesis,
    Kind::Fresh,
    Kind::Join,
    Kind::KeyholdersAdd,
    Kind::KeyholdersRemove,
    Kind::KeyholdersReplace,
];

/// A stored group's material no read needs any more (plan 2e, C4 "Retention"), sparing a
/// pending commit's; the rows taken. An epoch's seals, the lists it read and their rows go
/// once the next opening is `HOLD_MS` + 2 min old (by its header's time, less the keyholder
/// clock skew), unless a kept chain (`voipc_gk_chains`) references the epoch; a list stays
/// while a current version ratchets from it; other generations' go unless referenced. Seat
/// welcomes go with their version's list, seed welcomes below the floor or of another
/// generation. Headers keep §4.4's set (`sweep_headers`); keyrings and `KRK` welcomes of
/// earlier epochs and stale seats, version ids and exits go (`sweep_keyrings`, `sweep_stale`).
pub async fn sweep_material(store: &Db, grp: &str, now: u64) -> Result<u64> {
    let Some(row) = db::group(store, grp).await? else {
        return Ok(0);
    };
    sweep_material_from(store, grp, &row, now).await
}

/// The head's generation, read inside each sweep statement (`$1` is the group).
const HEAD_GEN: &str = "(SELECT hg.gen FROM voipc_gk_groups hg WHERE hg.grp = $1)";

/// `sweep_material` from `row`, the group as read when the sweep began. The sweep runs
/// beside the group's actor, which may move the head meanwhile, even to a new generation:
/// so each statement reads the head's generation itself, and `row`'s cut and floor take
/// material of `row`'s generation only. A generation the head moved to keeps all of its.
pub async fn sweep_material_from(
    store: &Db,
    grp: &str,
    row: &db::GroupRow,
    now: u64,
) -> Result<u64> {
    let gen = row.head.gen.to_vec();
    let Some(head) = db::header(store, grp, &row.head.d).await? else {
        return Ok(0);
    };
    let floor = SignedHeader::decode(&head.body, &head.sig, row.head.kind, grp)
        .map_or(0, |sh| sh.header().seed_floor);
    let old = (now.saturating_sub(HOLD_MS + MATERIAL_SWEEP_MARGIN_MS) / 1000)
        .saturating_sub(KEYHOLDER_SKEW_SECS);
    let cut: Option<i64> = on!(store, pool => {
        sqlx::query_scalar(
            "SELECT MAX(epoch) FROM voipc_gk_headers WHERE grp = $1 AND gen = $2 AND j = 0 AND time <= $3",
        )
        .bind(grp)
        .bind(gen.as_slice())
        .bind(i64::try_from(old)?)
        .fetch_one(pool)
        .await?
    });
    let cut = cut.unwrap_or(0);
    let q = format!(
        "DELETE FROM voipc_gk_seals WHERE (grp, gen, epoch, b, v) IN
         (SELECT s.grp, s.gen, s.epoch, s.b, s.v FROM voipc_gk_seals s
          WHERE s.grp = $1 AND (s.gen <> {HEAD_GEN} OR (s.gen = $2 AND s.epoch < $3))
          AND NOT EXISTS (SELECT 1 FROM voipc_gk_chains k WHERE k.grp = s.grp AND k.gen = s.gen AND k.epoch = s.epoch)
          AND NOT EXISTS (SELECT 1 FROM voipc_gk_pending p WHERE p.grp = s.grp AND p.commit_id = s.commit_id)
          LIMIT $4)"
    );
    let mut n = batched!(
        store,
        sqlx::AssertSqlSafe(q.as_str()),
        grp,
        gen.as_slice(),
        cut
    );
    let q = format!(
        "DELETE FROM voipc_gk_lists WHERE (grp, gen, b, v) IN
         (SELECT l.grp, l.gen, l.b, l.v FROM voipc_gk_lists l WHERE l.grp = $1
          AND (l.gen <> {HEAD_GEN} OR (l.gen = $2 AND l.current = FALSE AND l.epoch_until IS NOT NULL AND l.epoch_until <= $3
            AND NOT EXISTS (SELECT 1 FROM voipc_gk_lists c WHERE c.grp = l.grp AND c.gen = l.gen
              AND c.b = l.b AND c.base_v = l.base_v AND c.current)))
          AND NOT EXISTS (SELECT 1 FROM voipc_gk_lists r JOIN voipc_gk_chains k
              ON k.grp = r.grp AND k.gen = r.gen AND k.epoch >= r.epoch_made
              AND (r.epoch_until IS NULL OR k.epoch < r.epoch_until)
            WHERE r.grp = l.grp AND r.gen = l.gen AND r.b = l.b AND r.base_v = l.base_v)
          AND NOT EXISTS (SELECT 1 FROM voipc_gk_pending p WHERE p.grp = l.grp AND p.commit_id = l.commit_id)
          LIMIT $4)"
    );
    n += batched!(
        store,
        sqlx::AssertSqlSafe(q.as_str()),
        grp,
        gen.as_slice(),
        cut
    );
    n += batched!(
        store,
        "DELETE FROM voipc_gk_rows WHERE (grp, gen, b, v, seat) IN
         (SELECT r.grp, r.gen, r.b, r.v, r.seat FROM voipc_gk_rows r WHERE r.grp = $1
          AND NOT EXISTS (SELECT 1 FROM voipc_gk_lists l WHERE l.grp = r.grp AND l.gen = r.gen AND l.b = r.b AND l.v = r.v)
          AND NOT EXISTS (SELECT 1 FROM voipc_gk_pending p WHERE p.grp = r.grp AND p.commit_id = r.commit_id)
          LIMIT $2)",
        grp
    );
    let q = format!(
        "DELETE FROM voipc_gk_welcomes WHERE (grp, gen, seat, kind, s) IN
         (SELECT w.grp, w.gen, w.seat, w.kind, w.s FROM voipc_gk_welcomes w WHERE w.grp = $1
          AND ((w.kind = 0 AND NOT EXISTS (SELECT 1 FROM voipc_gk_lists l
                WHERE l.grp = w.grp AND l.gen = w.gen AND l.b = w.b AND l.v = w.v))
            OR (w.kind = 1 AND (w.gen <> {HEAD_GEN} OR (w.gen = $2 AND w.s < $3))))
          AND NOT EXISTS (SELECT 1 FROM voipc_gk_pending p WHERE p.grp = w.grp AND p.commit_id = w.commit_id)
          LIMIT $4)"
    );
    n += batched!(
        store,
        sqlx::AssertSqlSafe(q.as_str()),
        grp,
        gen.as_slice(),
        i64::from(floor)
    );
    n += sweep_headers(store, grp).await?;
    n += sweep_keyrings(store, grp, &gen, row.head.epoch).await?;
    n += sweep_stale(store, grp).await?;
    Ok(n)
}

/// Keyrings and `KRK` welcomes of epochs before `row`'s head epoch in `row`'s generation
/// (`gen`), and of every generation but the head's as each statement reads it (safe
/// beside a head move).
pub(crate) async fn sweep_keyrings(store: &Db, grp: &str, gen: &[u8], epoch: u32) -> Result<u64> {
    let epoch = i64::from(epoch);
    let mut n = 0;
    for (table, key) in [("voipc_gk_keyring", "j"), ("voipc_gk_krk", "holder")] {
        let q = format!(
            "DELETE FROM {table} WHERE (grp, gen, epoch, {key}) IN
             (SELECT k.grp, k.gen, k.epoch, k.{key} FROM {table} k WHERE k.grp = $1
              AND (k.gen <> {HEAD_GEN} OR (k.gen = $2 AND k.epoch < $3))
              AND NOT EXISTS (SELECT 1 FROM voipc_gk_pending p WHERE p.grp = k.grp AND p.commit_id = k.commit_id)
              LIMIT $4)"
        );
        n += batched!(store, sqlx::AssertSqlSafe(q.as_str()), grp, gen, epoch);
    }
    Ok(n)
}

/// Seats no read returns any more (of a generation not the head's, or of the head's in a
/// bucket with no current version), and other generations' version ids and exits; a
/// pending commit's are spared; the head's generation is read by each statement.
pub(crate) async fn sweep_stale(store: &Db, grp: &str) -> Result<u64> {
    let seats = format!(
        "DELETE FROM voipc_gk_seats WHERE (grp, gen, seat) IN
         (SELECT s.grp, s.gen, s.seat FROM voipc_gk_seats s WHERE s.grp = $1 AND s.next_commit IS NULL
          AND (s.gen <> {HEAD_GEN} OR NOT EXISTS (SELECT 1 FROM voipc_gk_lists l
            WHERE l.grp = s.grp AND l.gen = s.gen AND l.b = s.b AND l.current)) LIMIT $2)"
    );
    let vids = format!(
        "DELETE FROM voipc_gk_vids WHERE (grp, gen, v) IN
         (SELECT x.grp, x.gen, x.v FROM voipc_gk_vids x WHERE x.grp = $1 AND x.gen <> {HEAD_GEN}
          AND NOT EXISTS (SELECT 1 FROM voipc_gk_pending p WHERE p.grp = x.grp AND p.commit_id = x.commit_id) LIMIT $2)"
    );
    let exits = format!(
        "DELETE FROM voipc_gk_exits WHERE (grp, seq) IN
         (SELECT e.grp, e.seq FROM voipc_gk_exits e WHERE e.grp = $1 AND e.gen <> {HEAD_GEN} LIMIT $2)"
    );
    let mut n = 0;
    for q in [seats, vids, exits] {
        n += batched!(store, sqlx::AssertSqlSafe(q.as_str()), grp);
    }
    Ok(n)
}

/// The headers §4.4 keeps, the rest taken: of the head's generation the last 64, the head
/// epoch's, every keyholder-setting one, each Regenesis's parent, the last seed raise's, and
/// the openings kept chains reference; of an older generation, while kept chains reference
/// its epochs, those openings, its keyholder headers and Regenesis parents (C4).
async fn sweep_headers(store: &Db, grp: &str) -> Result<u64> {
    type M = (Vec<u8>, Vec<u8>, i64, i64, i16, i64);
    let metas: Vec<M> = on!(store, pool => {
        sqlx::query_as("SELECT d, gen, epoch, j, kind, time FROM voipc_gk_headers WHERE grp = $1")
            .bind(grp)
            .fetch_all(pool)
            .await?
    });
    // The head as it is after those were read: a head move writes its headers in the same
    // transaction, so every header read is of this head's generation or an older one
    let Some(row) = db::group(store, grp).await? else {
        return Ok(0);
    };
    let refs: Vec<(Vec<u8>, i64)> = on!(store, pool => {
        sqlx::query_as("SELECT DISTINCT gen, epoch FROM voipc_gk_chains WHERE grp = $1")
            .bind(grp)
            .fetch_all(pool)
            .await?
    });
    let refs: HashSet<(Vec<u8>, i64)> = refs.into_iter().collect();
    let head_gen = row.head.gen.to_vec();
    let mut recent: Vec<(i64, i64)> = metas
        .iter()
        .filter(|m| m.1 == head_gen)
        .map(|m| (m.2, m.3))
        .collect();
    recent.sort_unstable();
    let last64: HashSet<(i64, i64)> = recent.iter().rev().take(64).copied().collect();
    let referenced: HashSet<&Vec<u8>> = refs.iter().map(|(g, _)| g).collect();
    let mut keep: HashSet<Vec<u8>> = HashSet::new();
    for (d, gen, epoch, j, kind, time) in &metas {
        let kind = usize::try_from(*kind)
            .ok()
            .and_then(|i| KINDS.get(i).copied());
        let kh = kind.is_some_and(|k| k.sets_keyholders());
        let opening_ref = *j == 0 && refs.contains(&(gen.clone(), *epoch));
        let kept = if *gen == head_gen {
            last64.contains(&(*epoch, *j))
                || *epoch == i64::from(row.head.epoch)
                || kh
                || *time == row.head.rolls.raised as i64
                || opening_ref
        } else {
            referenced.contains(gen) && (kh || opening_ref)
        };
        if !kept {
            continue;
        }
        keep.insert(d.clone());
        if kind == Some(Kind::Regenesis) {
            let parent = db::header(store, grp, &d[..].try_into()?)
                .await?
                .and_then(|h| SignedHeader::decode(&h.body, &h.sig, row.head.kind, grp).ok());
            if let Some(p) = parent {
                keep.insert(p.header().parent.to_vec());
            }
        }
    }
    let mut n = 0;
    for (d, ..) in metas.iter().filter(|m| !keep.contains(&m.0)) {
        n += on!(store, pool => {
            sqlx::query("DELETE FROM voipc_gk_headers WHERE grp = $1 AND d = $2")
                .bind(grp)
                .bind(d.as_slice())
                .execute(pool)
                .await?
                .rows_affected()
        });
    }
    Ok(n)
}

/// Seats of the head's generation unused since `before` (unix ms): they exit (daily sweep).
pub async fn expired(store: &Db, grp: &str, before: u64) -> Result<Vec<SeatRef>> {
    let rows: Vec<Vec<u8>> = on!(store, pool => {
        sqlx::query_scalar(
            "SELECT s.seat FROM voipc_gk_seats s JOIN voipc_gk_groups g ON g.grp = s.grp AND g.gen = s.gen
             WHERE s.grp = $1 AND s.b IS NOT NULL AND s.last_use < $2 LIMIT 10000",
        )
        .bind(grp)
        .bind(i64::try_from(before)?)
        .fetch_all(pool)
        .await?
    });
    Ok(rows
        .into_iter()
        .filter_map(|r| seat_of(&r.try_into().ok()?))
        .collect())
}

impl std::fmt::Display for Fail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Fail::Check(s) | Fail::Store(s) => f.write_str(s),
        }
    }
}

impl std::error::Error for Fail {}
