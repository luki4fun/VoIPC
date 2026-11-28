//! Where a group's material lives (plan 2a, 2g, 2h): `Memory` for `r:` groups and relays
//! without accounts (nothing reaches the database, a restart is a new generation), `Db`
//! over `accounts::gk` for stored `c:` groups. The actor stores a checked commit here
//! before anything is pushed; answers read seat keying, the keyring and `KRK` welcomes.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use anyhow::Result;
use l4f_accounts::store::Store as Db;
use voipc_crypto::group_key::commit::{HolderRef, Joiner, Listed, Pair, RowsOut, WelcomeOut};
use voipc_crypto::group_key::timers::{
    refresh_ms, HOLD_MS, KEYHOLDER_SKEW_SECS, MATERIAL_SWEEP_MARGIN_MS, SEAT_EXPIRY_SECS,
    SEAT_KEYS_ROTATE_SECS,
};
use voipc_crypto::group_key::tree::BucketTree;
use voipc_crypto::group_key::{
    seat_record, GroupKind, Kind, Leaf, MemberId, Pool, SeatRef, SignedHeader, Via, MAX_WALK,
};
use voipc_protocol::gk::{
    self, EpochRef, HeaderIn, InPiece, KrkIn, LeafIn, NamesListIn, NamesStepIn, PathIn,
    RatchetStep, SeatKeying, SelfRowIn,
};

use super::due::{Exits, Leaving};
use super::group::{GroupState, Head, Out, Seat, Taken};
use super::names::{starts_names, Kept};
use super::snapshot::{header_in, link, Ver};
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
            Store::Db(d) => {
                match commit_db(d, g, t, now)
                    .await
                    .map_err(|e| match e.downcast::<Fail>() {
                        Ok(f) => f,
                        Err(e) => Fail::Store(e.to_string()),
                    }) {
                    // A COMMIT whose answer was lost (a connection dropped after the database
                    // applied it): the stored head is this commit's, so it is taken as stored.
                    // Told as failed, the relay would stay a head behind and every later commit
                    // be refused as built on another (dive 4 F3). A stored text commit writes
                    // nothing after its head move (seed welcomes are a voice room's, in memory)
                    Err(Fail::Store(e)) => {
                        // The read that decides can fail as the COMMIT's answer did (a
                        // failover): tried for about 2 s (review C-P4)
                        let mut wait = 100;
                        let landed = loop {
                            match db::group(&d.db, &g.id).await {
                                Ok(Some(row)) => break row.head.d == t.applied.header.d(),
                                Ok(None) => break false,
                                Err(_) if wait <= 800 => {
                                    tokio::time::sleep(std::time::Duration::from_millis(wait))
                                        .await;
                                    wait *= 2;
                                }
                                Err(_) => break false,
                            }
                        };
                        if landed {
                            tracing::warn!(group = %g.id, "a commit's answer was lost, but its head moved: {e}");
                            Ok(())
                        } else {
                            Err(Fail::Store(e))
                        }
                    }
                    r => r,
                }
            }
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
    /// Whether the seat's account holds a self-row for seed `s` here: its member secret under
    /// that seed, which a row needs. A read that fails counts as held (no seat again for it).
    pub async fn self_row_held(&self, grp: &str, gen: &[u8; 16], seat: &SeatRef, s: u32) -> bool {
        let (Store::Db(d), Some(a)) = (self, seat.m.account()) else {
            return false;
        };
        own_rows(&d.db, grp, &a, gen, seat, s)
            .await
            .map_or(true, |rows| !rows.is_empty())
    }

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
    /// pair, rank, device, when it was last online and whether its removal is proposed
    /// outright (`Holders::forced`); an entry no longer in the set goes, its mark with it.
    /// Whether the entries are written (memory: always). One not written is written again at
    /// the actor's next turn (dive 4 F5).
    pub async fn put_holders(&self, g: &GroupState, now: u64) -> bool {
        if let Store::Db(d) = self {
            if let Err(e) = put_holders(&d.db, g, now).await {
                tracing::warn!(group = %g.id, "keeping the keyholders failed: {e}");
                return false;
            }
        }
        true
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

    /// Exits entered since `from` (`seq`), kept so open batches survive a restart. Whether
    /// they are written (or there was nothing to write): one that failed is written again from
    /// `from` at the actor's next turn (rows already there are left as they are), since what a
    /// restart reads of an exit is its row alone (dive 4 F2, F7).
    pub async fn exits_entered(&self, grp: &str, g: &GroupState, from: u64, now: u64) -> bool {
        let (Store::Db(d), Some(gen)) = (self, g.gen()) else {
            return true;
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
                return false;
            }
        }
        true
    }

    /// Exit asks whose exits are written (`settle_exit_asks`): whether they went. A failed
    /// write is said; the actor tries again at its next turn.
    pub async fn exits_settled(&self, grp: &str, asks: &[([u8; 16], u64)]) -> bool {
        let Store::Db(d) = self else { return true };
        if asks.is_empty() {
            return true;
        }
        if let Err(e) = db::settle_exit_asks(&d.db, grp, asks).await {
            tracing::warn!(group = grp, "dropping exits asked failed: {e}");
            return false;
        }
        true
    }

    /// The channel's group id came back to this group: a new generation is due while the
    /// head's stays, here and after a restart (`moved_back`, 0014). A failed write is said:
    /// the live group starts anew all the same.
    pub async fn moved_back(&self, grp: &str) {
        let Store::Db(d) = self else { return };
        if let Err(e) = db::set_moved_back(&d.db, grp).await {
            tracing::warn!(
                group = grp,
                "keeping that the channel moved back failed: {e}"
            );
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

    /// At an actor's start, after `load`: what an account-path change would have done that
    /// never reached the group's actor, or reached it and lived in its memory alone (dive 4
    /// F7). The accounts paths change the database first and tell the group after, so a stop
    /// in between (a crash; a shutdown's drain that ran out) loses the message, and the next
    /// start knows only what the database says:
    /// - a seat or keyholder entry of an account banned now exits or is removed (a ban is
    ///   relay-wide; `OUT_OF_LOGS` took it out of every log in the ban's transaction);
    /// - an account seat whose keys are not its account's current ones exits, as a rotation
    ///   (its current keys are seated eagerly, `on_seat_keys`) or, with none, as a reset;
    /// - a keyholder entry made with an identity its account no longer has is removed;
    /// - an exit asked ahead and not yet written (`voipc_gk_exit_asks`: a log leave, a gate,
    ///   a new password, a kick or leave of the channel) is entered, before the checks below,
    ///   so a later eager ask seats the account again and an earlier one is dropped with its
    ///   membership;
    /// - an eager seat asked and not yet seated (`voipc_gk_eager`) is asked again, while its
    ///   account still keeps the log.
    ///
    /// What this enters is written at once, exits and entries. A read that fails is said and
    /// skipped. The exit asks it entered go once their exits are written; those not (the write
    /// failed) are the actor's to settle, with where its exit writes start again.
    pub async fn reconcile(&self, g: &mut GroupState, now: u64, out: &mut Vec<Out>) -> Reconciled {
        // Stored groups are text groups: a voice seat's keys are its connection's, not its
        // account's published ones
        let (Store::Db(d), GroupKind::Text) = (self, g.kind) else {
            return Reconciled::default();
        };
        // With no head, a new start's eager pages seat the members (`eager_all`), and a new
        // start seats whom it seats anew: an exit asked of the old head has no seat to take
        let Some(gen) = g.gen().filter(|_| !g.new_gen) else {
            if let Err(e) = db::drop_exit_asks(&d.db, &g.id, now).await {
                tracing::warn!(group = %g.id, "dropping exits asked failed: {e}");
            }
            return Reconciled::default();
        };
        let (from, forced) = (g.exits.next, g.holders.forced.clone());
        let asks = match reconcile_db(&d.db, g, &gen, now, out).await {
            Ok(asks) => asks,
            Err(e) => {
                tracing::warn!(group = %g.id, "checking the group against its accounts failed: {e}");
                vec![]
            }
        };
        let written = g.exits.next == from || self.exits_entered(&g.id, g, from, now).await;
        if g.holders.forced != forced {
            self.put_holders(g, now).await;
        }
        let asks: Vec<([u8; 16], u64)> = asks.iter().map(|a| (a.account, a.at)).collect();
        match written {
            true if self.exits_settled(&g.id, &asks).await => Reconciled::default(),
            true => Reconciled {
                unwritten: None,
                asks,
            },
            false => Reconciled {
                unwritten: Some(from),
                asks,
            },
        }
    }

    /// At an actor's start: where the head's new start's eager pages stopped, if a stop (a
    /// crash, a shutdown, a page read that failed) cut them off before all were asked (review
    /// P3): the head's generation and the account to go on after (`None`: from the first). A
    /// read that fails is said, and the pages wait for the next start.
    pub async fn eager_left(&self, g: &GroupState) -> Option<([u8; 16], Option<[u8; 16]>)> {
        let (Store::Db(d), GroupKind::Text) = (self, g.kind) else {
            return None;
        };
        let gen = g.gen().filter(|_| !g.new_gen && g.head.is_some())?;
        match db::eager_after(&d.db, &g.id, &gen).await {
            Ok(left) => left.map(|after| (gen, after)),
            Err(e) => {
                tracing::warn!(group = %g.id, "reading where the eager seats stopped failed: {e}");
                None
            }
        }
    }

    /// Eager seats seated, refused or dropped: their asks go (dive 4 F7). A failed write is
    /// said; the next start finds the ask settled and drops it then.
    pub async fn eager_settled(&self, grp: &str, seats: &[SeatRef]) {
        let Store::Db(d) = self else { return };
        let asks = eager_asks(seats);
        if asks.is_empty() {
            return;
        }
        if let Err(e) = db::drop_eager(&d.db, grp, &asks).await {
            tracing::warn!(group = grp, "dropping eager seats asked failed: {e}");
        }
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
        // The channel moved back onto this generation and no new one is stored since: one is
        // asked, as the live relay asked it (`Groups::on_group_moved`)
        if db::moved_back(&d.db, &grp, &gen).await? {
            g.new_gen = true;
        }
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
                        removed: vec![],
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
        // welcomes to offline ones too), ranks, devices, misses, last online and whether
        // their removal was proposed outright (2i)
        let kept = holder_rows(&d.db, &grp).await?;
        g.holders.set_to(kh.header().keyholders.clone(), |kx| {
            kept.iter()
                .find(|r| r.kx == *kx)
                .and_then(|r| r.pair.clone())
        });
        for r in kept {
            let Some(k) = g.holders.set.iter().find(|k| k.kx == r.kx) else {
                continue;
            };
            // A removal proposed outright before the restart is proposed still (dive 4 F6)
            if r.forced {
                g.holders.forced.push(HolderRef::of(k));
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
        // No entry is online at a start: none has been since the latest any was seen (its
        // `last_online`, written as it went offline, or by the sweep while it was online). The
        // hour before a Regenesis counts from then, not from this start, so restarts (a crash
        // loop, self-updates) do not hold a channel with no keyholder keyless (§5.6); the
        // actor's start keeps its own downtime out of it (`GroupState::restarted`)
        g.no_keyholder_since = g.holders.stats.values().filter_map(|s| s.away_since).max();
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
        // The head epoch's refresh, as the opening that made it set it: a group loaded after
        // a restart or an idle stop is refreshed once that epoch is due, not only at its next
        // exit, so a Join seats nobody into an old epoch (§6 "A newcomer")
        g.next_refresh = Some(
            opening
                .header()
                .time
                .saturating_mul(1000)
                .saturating_add(refresh_ms(hd.buckets)),
        );
        // Seats a roll that ended at its 24 h left behind get their pages after a restart
        // too (GROUP-KEY §5.6)
        g.left_behind = g.seats.values().any(|x| x.seed < hd.seed);
        // And so do the seats owed one under the head seed whose page a restart or an idle
        // stop lost (dive 3 P3)
        for seat in owed_seats(&d.db, &grp, &gen, hd.seed).await? {
            if g.seats.get(&seat).is_some_and(|x| x.seed == hd.seed) {
                g.seed_owed.insert(seat);
            }
        }
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

/// What `Store::reconcile` leaves its actor: the exit asks it entered whose settle waits (each
/// account and its ask's time), and the first exit `seq` whose write failed.
#[derive(Default)]
pub struct Reconciled {
    pub unwritten: Option<u64>,
    pub asks: Vec<([u8; 16], u64)>,
}

/// The asks of `seats`' account seats.
pub fn eager_asks(seats: &[SeatRef]) -> Vec<db::EagerAsk> {
    seats
        .iter()
        .filter_map(|s| {
            Some(db::EagerAsk {
                account: s.m.account()?,
                seat: seat_record(s),
            })
        })
        .collect()
}

/// Rows a start's checks read a page at a time.
const CHECK_PAGE: u32 = 1000;

/// `Store::reconcile` over the database.
async fn reconcile_db(
    store: &Db,
    g: &mut GroupState,
    gen: &[u8; 16],
    now: u64,
    out: &mut Vec<Out>,
) -> Result<Vec<db::ExitAsk>> {
    use super::group::cause;
    let grp = g.id.clone();
    let secs = i64::try_from(now / 1000)?;
    // Banned accounts: their seats exit, their entries are removed (`account_exit`)
    let entries: Vec<[u8; 16]> = g.holders.set.iter().filter_map(|k| k.m.account()).collect();
    let mut banned = banned_seated(store, &grp, gen, secs).await?;
    banned.extend(banned_of(store, &entries, secs).await?);
    for a in &banned {
        g.account_exit(a, cause::BAN, now, out);
    }
    // Exits asked ahead and not written (a log leave, a gate, a new password, a kick or leave
    // of the channel): entered in one pass, before anything here seats an account again (the
    // keys check below skips them; an eager ask made since seats them again)
    let mut exits_asked: Vec<db::ExitAsk> = vec![];
    loop {
        let after = exits_asked.last().map(|a| a.account);
        let page = db::exit_asks_page(store, &grp, after.as_ref(), CHECK_PAGE).await?;
        let full = page.len() == CHECK_PAGE as usize;
        exits_asked.extend(page);
        if !full {
            break;
        }
    }
    let exited: HashMap<[u8; 16], u8> = exits_asked.iter().map(|a| (a.account, a.cause)).collect();
    g.accounts_exit(&exited, now, out);
    // Seats whose keys are not their account's current ones; the current ones are seated in
    // their place if the relay first held them within the seat expiry and a rotation's age
    // (`eager_all`)
    let since = now.saturating_sub((SEAT_EXPIRY_SECS + SEAT_KEYS_ROTATE_SECS) * 1000);
    let mut reset: HashSet<[u8; 16]> = HashSet::new();
    // Each new seat once: an account with two seats on old keys (a second rotation before the
    // first one's opening landed) has one current seat (review P1)
    let mut rotated: Vec<SeatRef> = vec![];
    let mut asked: HashSet<SeatRef> = HashSet::new();
    let mut after: Vec<u8> = vec![];
    loop {
        let page = keys_off(store, &grp, gen, &after, CHECK_PAGE).await?;
        let full = page.len() == CHECK_PAGE as usize;
        for (rec, keys) in &page {
            let Some(seat) = <[u8; 33]>::try_from(rec.as_slice())
                .ok()
                .and_then(|r| seat_of(&r))
                .filter(|s| g.seats.contains_key(s))
            else {
                continue;
            };
            let Some(a) = seat
                .m
                .account()
                .filter(|a| !banned.contains(a) && !exited.contains_key(a))
            else {
                continue;
            };
            match keys {
                Current::Gone => {
                    if reset.insert(a) {
                        g.account_exit(&a, cause::RESET, now, out);
                    }
                }
                Current::Bad => g.exit(seat, cause::ROTATION, now, out),
                Current::Keys(k) if !reset.contains(&a) => {
                    let (ik, pair, published) = &**k;
                    g.exit(seat, cause::ROTATION, now, out);
                    if *published < since {
                        continue;
                    }
                    let joiner = Joiner {
                        seat: pair.keys.seat(MemberId::Account(a)),
                        ik: *ik,
                        keys: pair.keys.clone(),
                        endorsement: pair.endorsement.clone(),
                        returning: false,
                    };
                    let new = joiner.seat;
                    g.eager(joiner, a, now, out);
                    if g.joins.has(&new) && asked.insert(new) {
                        rotated.push(new);
                    }
                }
                Current::Keys(..) => {}
            }
        }
        match page.last() {
            Some((rec, _)) if full => after = rec.clone(),
            _ => break,
        }
    }
    db::put_eager(store, &grp, &eager_asks(&rotated), now).await?;
    // Entries made with an identity their account no longer has (a reset): removed
    for (a, ik) in identities(store, &entries).await? {
        for k in &g.holders.set {
            let r = HolderRef::of(k);
            if k.m.account() == Some(a) && k.ik != ik && !g.holders.forced.contains(&r) {
                g.holders.forced.push(r);
            }
        }
    }
    // Eager seats asked and not seated: asked again while their account keeps the log, with
    // keys as fresh
    let mut after: Option<[u8; 16]> = None;
    loop {
        let page = eager_asked(store, &grp, since, after.as_ref(), CHECK_PAGE).await?;
        let full = page.len() == CHECK_PAGE as usize;
        after = page.last().map(|(ask, _)| ask.account);
        let (mut done, mut moved) = (vec![], vec![]);
        for (ask, joiner) in page {
            let Some(joiner) = joiner.filter(|_| !banned.contains(&ask.account)) else {
                done.push(ask);
                continue;
            };
            let seat = joiner.seat;
            g.eager(joiner, ask.account, now, out);
            if !g.joins.has(&seat) {
                // Seated already, or past `kept_seats`
                done.push(ask);
            } else if seat_record(&seat) != ask.seat {
                // Its keys rotated since: the ask names the seat they make now
                moved.push(seat);
            }
        }
        db::drop_eager(store, &grp, &done).await?;
        db::put_eager(store, &grp, &eager_asks(&moved), now).await?;
        if !full {
            break;
        }
    }
    Ok(exits_asked)
}

/// The accounts with a seat in `grp`'s generation `gen` that a ban in force names (`secs`:
/// now, unix s).
async fn banned_seated(
    store: &Db,
    grp: &str,
    gen: &[u8; 16],
    secs: i64,
) -> Result<HashSet<[u8; 16]>> {
    let rows: Vec<Vec<u8>> = on!(store, pool => {
        sqlx::query_scalar(
            "SELECT DISTINCT s.account FROM voipc_gk_seats s
             WHERE s.grp = $1 AND s.gen = $2 AND s.b IS NOT NULL AND s.account IN
               (SELECT account FROM voipc_bans WHERE account IS NOT NULL
                AND (expires_at IS NULL OR expires_at > $3))",
        )
        .bind(grp)
        .bind(&gen[..])
        .bind(secs)
        .fetch_all(pool)
        .await?
    });
    Ok(rows.into_iter().filter_map(|a| a.try_into().ok()).collect())
}

/// Which of `accounts` a ban in force names.
async fn banned_of(store: &Db, accounts: &[[u8; 16]], secs: i64) -> Result<HashSet<[u8; 16]>> {
    let mut out = HashSet::new();
    for a in accounts {
        let hit: Option<i64> = on!(store, pool => {
            sqlx::query_scalar(
                "SELECT CAST(1 AS BIGINT) FROM voipc_bans WHERE account = $1
                 AND (expires_at IS NULL OR expires_at > $2)",
            )
            .bind(&a[..])
            .bind(secs)
            .fetch_optional(pool)
            .await?
        });
        if hit.is_some() {
            out.insert(*a);
        }
    }
    Ok(out)
}

/// A seat's account's current seat keys, as `keys_off` finds them.
enum Current {
    /// None: an identity reset dropped them.
    Gone,
    /// Keys that do not decode: they seat nobody.
    Bad,
    /// A joiner's identity key and pair, and when the relay first held them (unix ms).
    Keys(Box<([u8; 32], Pair, u64)>),
}

/// A page of `grp`'s account seats in generation `gen` after seat record `after` whose
/// account has an identity and whose keys are not that account's current seat keys: each
/// with what the current keys are. A seat's `dh` is its keys' as the
/// account published them (`commit_db`). An account with no identity is the tombstone
/// sweep's (a deleted account's seats exit with their cause there).
async fn keys_off(
    store: &Db,
    grp: &str,
    gen: &[u8; 16],
    after: &[u8],
    limit: u32,
) -> Result<Vec<(Vec<u8>, Current)>> {
    type T = (
        Vec<u8>,
        Vec<u8>,
        Option<i64>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<i64>,
        Option<Vec<u8>>,
        Vec<u8>,
        Option<i64>,
    );
    let rows: Vec<T> = on!(store, pool => {
        sqlx::query_as(
            "SELECT s.seat, s.account, k.n, k.kem, k.dh, k.made, k.sig, i.identity_key, k.published
             FROM voipc_gk_seats s JOIN voipc_identity i ON i.account = s.account
             LEFT JOIN voipc_gk_seatkeys k ON k.account = s.account AND k.current
             WHERE s.grp = $1 AND s.gen = $2 AND s.seat > $3 AND s.b IS NOT NULL
             AND (k.account IS NULL OR k.dh <> s.dh)
             ORDER BY s.seat LIMIT $4",
        )
        .bind(grp)
        .bind(&gen[..])
        .bind(after)
        .bind(i64::from(limit))
        .fetch_all(pool)
        .await?
    });
    Ok(rows
        .into_iter()
        .map(|(seat, a, n, kem, dh, made, sig, ik, published)| {
            let keys = match (n, kem, dh, made, sig) {
                (Some(n), Some(kem), Some(dh), Some(made), Some(sig)) => {
                    let at = published.and_then(|p| u64::try_from(p).ok()).unwrap_or(0);
                    keyed((a, n, kem, dh, made, sig, ik)).map_or(Current::Bad, |(_, ik, p)| {
                        Current::Keys(Box::new((ik, p, at)))
                    })
                }
                _ => Current::Gone,
            };
            (seat, keys)
        })
        .collect())
}

/// The identity keys of `accounts` that have one, raw.
async fn identities(store: &Db, accounts: &[[u8; 16]]) -> Result<Vec<([u8; 16], [u8; 32])>> {
    let mut out = vec![];
    for a in accounts {
        let k: Option<Vec<u8>> = on!(store, pool => {
            sqlx::query_scalar("SELECT identity_key FROM voipc_identity WHERE account = $1")
                .bind(&a[..])
                .fetch_optional(pool)
                .await?
        });
        if let Some(ik) = k.as_deref().and_then(ik_raw) {
            out.push((*a, ik));
        }
    }
    Ok(out)
}

/// A page of `grp`'s eager seats asked, after account `after`: each with the joiner its
/// account's current seat keys make, `None` where it no longer keeps the log, or has no keys
/// the relay first held at `since` (unix ms) or later.
async fn eager_asked(
    store: &Db,
    grp: &str,
    since: u64,
    after: Option<&[u8; 16]>,
    limit: u32,
) -> Result<Vec<(db::EagerAsk, Option<Joiner>)>> {
    type T = (
        Vec<u8>,
        Vec<u8>,
        Option<Vec<u8>>,
        Option<i64>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<i64>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<i64>,
    );
    // The group id is its conversation's (`stored_id`), as `voipc_members` names it
    let rows: Vec<T> = on!(store, pool => {
        sqlx::query_as(
            "SELECT e.account, e.seat, m.account, k.n, k.kem, k.dh, k.made, k.sig, i.identity_key,
             k.published FROM voipc_gk_eager e
             LEFT JOIN voipc_members m ON m.conv = $2 AND m.account = e.account
             LEFT JOIN voipc_gk_seatkeys k ON k.account = e.account AND k.current
             LEFT JOIN voipc_identity i ON i.account = e.account
             WHERE e.grp = $1 AND e.account > $3 ORDER BY e.account LIMIT $4",
        )
        .bind(grp)
        .bind(grp)
        .bind(after.map_or(&[][..], |a| &a[..]))
        .bind(i64::from(limit))
        .fetch_all(pool)
        .await?
    });
    let mut out = Vec::with_capacity(rows.len());
    let since = i64::try_from(since).unwrap_or(i64::MAX);
    for (a, seat, member, n, kem, dh, made, sig, ik, published) in rows {
        let (Ok(account), Ok(seat)) = (<[u8; 16]>::try_from(a.clone()), <[u8; 33]>::try_from(seat))
        else {
            continue;
        };
        let fresh = published.is_some_and(|p| p >= since);
        let joiner = match (member.filter(|_| fresh), n, kem, dh, made, sig, ik) {
            (Some(_), Some(n), Some(kem), Some(dh), Some(made), Some(sig), Some(ik)) => {
                keyed((a, n, kem, dh, made, sig, ik)).map(|(a, ik, pair)| Joiner {
                    seat: pair.keys.seat(MemberId::Account(a)),
                    ik,
                    keys: pair.keys,
                    endorsement: pair.endorsement,
                    returning: false,
                })
            }
            _ => None,
        };
        out.push((db::EagerAsk { account, seat }, joiner));
    }
    Ok(out)
}

/// A stored group's account seats (records from 0x01 to 0x02) holding seed `s` with no seed
/// welcome under it and no self-row of their account for it: their member secret under `s`
/// is in their seat welcome alone, if anywhere, so each is owed a seed welcome (dive 3 P3).
async fn owed_seats(store: &Db, grp: &str, gen: &[u8; 16], s: u32) -> Result<Vec<SeatRef>> {
    let (lo, hi) = ([0x01u8; 1], [0x02u8; 1]);
    let recs: Vec<Vec<u8>> = on!(store, pool => {
        sqlx::query_scalar(
            "SELECT t.seat FROM voipc_gk_seats t WHERE t.grp = $1 AND t.gen = $2 AND t.seed = $3
             AND t.seat >= $4 AND t.seat < $5
             AND NOT EXISTS (SELECT 1 FROM voipc_gk_welcomes w WHERE w.grp = t.grp AND w.gen = t.gen
               AND w.seat = t.seat AND w.kind = 1 AND w.s = t.seed)
             AND NOT EXISTS (SELECT 1 FROM voipc_gk_self x WHERE x.grp = t.grp AND x.gen = t.gen
               AND x.seed = t.seed AND x.account = substr(t.seat, 2, 16)
               AND x.tag_sk = substr(t.seat, 18, 8) AND x.tag_sx = substr(t.seat, 26, 8))",
        )
        .bind(grp)
        .bind(&gen[..])
        .bind(i64::from(s))
        .bind(&lo[..])
        .bind(&hi[..])
        .fetch_all(pool)
        .await?
    });
    Ok(recs
        .into_iter()
        .filter_map(|r| <[u8; 33]>::try_from(r).ok())
        .filter_map(|r| seat_of(&r))
        .collect())
}

/// Groups whose next head move answers with an error after the database applied it.
#[cfg(test)]
pub static LOSE_ANSWER: std::sync::LazyLock<Mutex<std::collections::HashSet<String>>> =
    std::sync::LazyLock::new(Default::default);

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
    // A start may carry the exit of a seat it seats again (its own volunteer's): memory
    // removes before it seats, so that seat stays (review C-P3)
    let removed: Vec<Vec<u8>> = a
        .removed
        .iter()
        .filter(|r| !a.seated.iter().any(|(s, _)| s == *r))
        .map(|s| seat_record(s).to_vec())
        .collect();
    let holders = new_holders(g, t, now);
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
            removed: &removed,
            names: &names,
            holders: &holders,
        },
    )
    .await?;
    #[cfg(test)]
    if LOSE_ANSWER
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(grp)
    {
        return Err(anyhow::anyhow!("the answer to COMMIT was lost"));
    }
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

/// The entries a commit adds (a promotion's candidate, a Replace's new pair, a start's
/// volunteer; a new start's whole set), each with its pair and, from the session that
/// volunteered it, its rank and device, as `GroupState::apply` takes them: written with the
/// head move (dive 4 F5), a removal marked on a row left from before cleared there.
fn new_holders(g: &GroupState, t: &Taken, now: u64) -> Vec<db::Holder> {
    let Some(set) = &t.applied.keyholders else {
        return vec![];
    };
    // A new start's set is taken whole (`apply` clears what the relay held of the old one):
    // an entry of both starts with no removal marked, as its memory does
    let anew = t.applied.header.header().kind.starts_anew();
    let d = &t.due.due;
    let mut pairs: HashMap<[u8; 32], &Pair> =
        g.vols.values().map(|v| (v.pair.kx(), &v.pair)).collect();
    for c in d.candidate.iter().chain(d.volunteer.iter()) {
        pairs.insert(c.pair.kx(), &c.pair);
    }
    if let Some(r) = &d.replace {
        pairs.insert(r.pair.kx(), &r.pair);
    }
    set.iter()
        .filter(|k| anew || !g.holders.set.iter().any(|o| o.kx == k.kx))
        .filter_map(|k| {
            let pair = pairs.get(&k.kx)?;
            let vol = g.vols.values().find(|v| v.pair.kx() == k.kx);
            Some(db::Holder {
                kx: k.kx,
                m: k.m.seat_id(),
                device: vol.and_then(|v| g.devices.get(&v.sid).cloned()),
                rank: vol.and_then(|v| v.rank(g.kind)).unwrap_or(u8::MAX),
                last_online: now,
                missed: db::Misses::default(),
                pair: Some(gk::EndorsedPair::from(*pair)),
            })
        })
        .collect()
}

/// A keyholder entry as the database keeps it, its pair in a column of its own.
struct HolderRow {
    kx: [u8; 32],
    device: Option<Vec<u8>>,
    rank: u8,
    last_online: u64,
    misses: db::Misses,
    pair: Option<Pair>,
    /// Its removal is proposed outright (`Holders::forced`, 0014).
    forced: bool,
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
        bool,
    );
    let rows: Vec<T> = on!(store, pool => {
        sqlx::query_as("SELECT kx, m, device, rank, last_online, missed, pair, forced FROM voipc_gk_holders WHERE grp = $1")
            .bind(grp)
            .fetch_all(pool)
            .await?
    });
    let mut out = vec![];
    for (kx, m, device, rank, last_online, missed, pair, forced) in rows {
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
            forced,
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
    // A pair the relay lost from memory is not written over: an entry's KX is its pair's. Nor
    // is a removal marked (a device removed, `force_device_holders`) that this memory has not
    // heard of yet: a mark goes only with its row (the entry leaves the set) or when a head
    // move takes the entry in again (`move_head`)
    const Q: &str =
        "INSERT INTO voipc_gk_holders (grp, kx, m, device, rank, last_online, missed, pair, forced)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         ON CONFLICT (grp, kx) DO UPDATE SET m = excluded.m, device = excluded.device,
         rank = excluded.rank, last_online = excluded.last_online, missed = excluded.missed,
         pair = COALESCE(excluded.pair, voipc_gk_holders.pair),
         forced = (voipc_gk_holders.forced OR excluded.forced)";
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
        let forced = g.holders.forced.contains(&HolderRef::of(k));
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
                .bind(forced)
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
/// Only keys the relay first held at `since` (unix ms) or later (`eager_all`).
pub async fn eager_page(
    store: &Db,
    conv: &str,
    since: u64,
    after: Option<&[u8; 16]>,
    limit: u32,
) -> Result<Vec<([u8; 16], Joiner)>> {
    let rows: Vec<KeysTuple> = on!(store, pool => {
        sqlx::query_as(
            "SELECT k.account, k.n, k.kem, k.dh, k.made, k.sig, i.identity_key
             FROM voipc_members m JOIN voipc_gk_seatkeys k ON k.account = m.account AND k.current
             JOIN voipc_identity i ON i.account = m.account
             WHERE m.conv = $1 AND m.account > $2 AND k.published >= $4
             ORDER BY m.account LIMIT $3",
        )
        .bind(conv)
        .bind(after.map_or(&[][..], |a| &a[..]))
        .bind(i64::from(limit))
        .bind(i64::try_from(since).unwrap_or(i64::MAX))
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

/// A leaf a past epoch's header committed to, with its version's base and when it was made.
#[derive(Clone, Copy)]
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

/// Every version sealed at epoch `epoch` of generation `gen` (none of a pending commit's),
/// by the commit that sealed it: the opening's every current version then, each Join's
/// the versions it made.
async fn epoch_seals(
    store: &Db,
    grp: &str,
    gen: &[u8; 16],
    epoch: u32,
) -> Result<HashMap<i64, Vec<PastLeaf>>> {
    type T = (i64, i64, i16, Option<i64>, i64, i64, Vec<u8>, i64, i64);
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
        .bind(&gen[..])
        .bind(i64::from(epoch))
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
    Ok(by)
}

/// `leaves` as the tree of header `sh`, when they are its bucket root's.
fn tree_of(mut leaves: Vec<PastLeaf>, sh: &SignedHeader) -> Option<(Vec<PastLeaf>, BucketTree)> {
    let h = sh.header();
    if leaves.len() != h.buckets as usize {
        return None;
    }
    leaves.sort_by_key(|l| l.leaf.b);
    let flat: Vec<Leaf> = leaves.iter().map(|l| l.leaf).collect();
    let tree = BucketTree::new(&flat).ok()?;
    (tree.root() == h.bucket_root).then_some((leaves, tree))
}

/// The leaves the opening `sh` committed to, and their tree: an opening seals every current
/// version and a Join only those it made, so the seals of the one commit at that epoch
/// whose versions make the header's bucket root are the opening's.
fn opening_leaves(
    by: &HashMap<i64, Vec<PastLeaf>>,
    sh: &SignedHeader,
) -> Option<(Vec<PastLeaf>, BucketTree)> {
    by.values().find_map(|leaves| tree_of(leaves.clone(), sh))
}

/// The leaves the epoch's last Join `sh` committed to, and their tree: every version sealed
/// at its epoch. Its opening sealed every version current then, each Join after it the new
/// buckets it made, and no version of an epoch is replaced within it (§5.3), so the last
/// Join's bucket root covers them all.
fn join_leaves(
    by: &HashMap<i64, Vec<PastLeaf>>,
    sh: &SignedHeader,
) -> Option<(Vec<PastLeaf>, BucketTree)> {
    tree_of(by.values().flatten().copied().collect(), sh)
}

/// A Regenesis's parent, which the relay keeps with it (§4.4); `None` for any other kind.
async fn regenesis_parent(
    store: &Db,
    grp: &str,
    sh: &SignedHeader,
) -> Result<Option<SignedHeader>> {
    if sh.header().kind != Kind::Regenesis {
        return Ok(None);
    }
    Ok(db::header(store, grp, &sh.header().parent)
        .await?
        .and_then(|h| SignedHeader::decode(&h.body, &h.sig, GroupKind::Text, grp).ok()))
}

/// The welcomes (seat) and rows to any seat of `m` in generation `gen`, by version.
async fn member_bases(
    store: &Db,
    grp: &str,
    gen: &[u8; 16],
    m: &MemberId,
) -> Result<HashMap<(u64, u64), (SeatRef, Base, Option<Base>)>> {
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
    let mut out: HashMap<(u64, u64), (SeatRef, Base, Option<Base>)> = HashMap::new();
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
            let base = (s, from, welcome, bytes);
            match out.entry((b as u64, v as u64)) {
                std::collections::hash_map::Entry::Vacant(e) => {
                    e.insert((seat, base, None));
                }
                // The row a Join stores beside its welcome (choice 24): `past` hands it once
                // the account holds the seed's member secret in a self-row
                std::collections::hash_map::Entry::Occupied(mut e) => {
                    let (held, first, row) = e.get_mut();
                    if !welcome && first.2 && row.is_none() && *held == seat {
                        *row = Some(base);
                    }
                }
            }
        }
    }
    Ok(out)
}

/// One `at` entry's answer (plan 2d, C4): the header whose bucket root holds the member's
/// leaf then (§5.10 "a reader opens it from its seat at epoch `e`") in `head`: the epoch's
/// opening header (with a Regenesis's parent), or, for a seat a Join added after it (T1e A),
/// the epoch's last Join with the opening in `opening`. Then the keyholder links back from
/// `anchor` (the member's floor's `kh`) to the one the opening names when `anchor` is a
/// keyholder header at or after it (with no such anchor, for a Join under an opening that
/// sets no keyholders, that one header, so the Join's signer is checked against the set
/// the opening names), the member's leaf, path and seal then, its keying (the welcome or
/// row of its version then, or of the version it ratcheted from, with the steps), the seed
/// welcome under that row's seed if one is kept, and its self-rows and history rows for
/// that seed. `None` when the opening, its versions or any seat of `m` in them is not kept.
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
    let bases = member_bases(store, grp, &at.gen, &m).await?;
    let mine = |leaves: &[PastLeaf]| {
        leaves
            .iter()
            .position(|l| bases.contains_key(&(l.leaf.b, l.base_v)))
    };
    // At the opening when it sealed to a seat of `m`, else at the epoch's last Join. Read
    // twice at most: a Join of the head epoch stored between the two reads
    let mut found = None;
    for _ in 0..2 {
        let by = epoch_seals(store, grp, &at.gen, at.epoch).await?;
        if let Some((leaves, tree)) = opening_leaves(&by, &sh) {
            if let Some(i) = mine(&leaves) {
                found = Some((None, leaves, tree, i));
                break;
            }
        }
        let Some(last) = db::epoch_last(store, grp, &at.gen, at.epoch)
            .await?
            .and_then(|x| decode(&x))
            .filter(|j| j.header().kind == Kind::Join && j.header().epoch_parent == sh.d())
        else {
            break;
        };
        if let Some((leaves, tree)) = join_leaves(&by, &last) {
            if let Some(i) = mine(&leaves) {
                found = Some((Some(last), leaves, tree, i));
            }
            break;
        }
    }
    let Some((join, leaves, tree, i)) = found else {
        return Ok(None);
    };
    let l = &leaves[i];
    let Some((seat, base, beside)) = bases.get(&(l.leaf.b, l.base_v)) else {
        return Ok(None);
    };
    // A seat welcome opens only with the seat keys it went to, which a rotation deletes; the
    // row beside it opens with the member secret, which the account's self-row keeps across
    // rotations. So the row goes where the account holds that self-row (dive 3 F1)
    let mut base = base.clone();
    if let (Some(row), Some(a)) = (beside, seat.m.account()) {
        if !own_rows(store, grp, &a, &at.gen, seat, row.0)
            .await?
            .is_empty()
        {
            base = row.clone();
        }
    }
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
    let (s, from, welcome, bytes) = base;
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
    let walked = match anchor {
        Some(a) => {
            let ah = db::header(store, grp, &a).await?.and_then(|x| decode(&x));
            ah.filter(|x| {
                let x = x.header();
                x.gen == h.gen && x.kind.sets_keyholders() && (h.epoch <= x.epoch || sh.kh() == a)
            })
        }
        None => None,
    };
    if let Some(ah) = walked {
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
            let p = regenesis_parent(store, grp, &next).await?;
            walk.push(link(&next, p.as_ref()));
            cur = next;
        }
    } else if join.is_some() && !h.kind.sets_keyholders() {
        // Taken on the binding alone: the set the opening names, for the Join's signer
        if let Some(set) = db::header(store, grp, &h.kh_parent)
            .await?
            .and_then(|x| decode(&x))
        {
            let p = regenesis_parent(store, grp, &set).await?;
            walk.push(link(&set, p.as_ref()));
        }
    }
    let (head, opening) = match join {
        Some(j) => (link(&j, None), Some(header_in(&sh))),
        None => (
            link(&sh, regenesis_parent(store, grp, &sh).await?.as_ref()),
            None,
        ),
    };
    Ok(Some(InPiece {
        walk,
        head: Some(head),
        opening,
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
    // A seed welcome under a seed below the floor stays while an account seat (records from
    // $4 to $5) has rows under that seed in kept epochs and the account holds no self-row
    // for it: it is the only place that seat's member secret is (dive 3 F3)
    let q = format!(
        "DELETE FROM voipc_gk_welcomes WHERE (grp, gen, seat, kind, s) IN
         (SELECT w.grp, w.gen, w.seat, w.kind, w.s FROM voipc_gk_welcomes w WHERE w.grp = $1
          AND ((w.kind = 0 AND NOT EXISTS (SELECT 1 FROM voipc_gk_lists l
                WHERE l.grp = w.grp AND l.gen = w.gen AND l.b = w.b AND l.v = w.v))
            OR (w.kind = 1 AND (w.gen <> {HEAD_GEN} OR (w.gen = $2 AND w.s < $3
                AND NOT (w.seat >= $4 AND w.seat < $5
                  AND EXISTS (SELECT 1 FROM voipc_gk_rows r
                    WHERE r.grp = w.grp AND r.gen = w.gen AND r.seat = w.seat AND r.s = w.s)
                  AND NOT EXISTS (SELECT 1 FROM voipc_gk_self x
                    WHERE x.grp = w.grp AND x.gen = w.gen AND x.seed = w.s
                    AND x.account = substr(w.seat, 2, 16) AND x.tag_sk = substr(w.seat, 18, 8)
                    AND x.tag_sx = substr(w.seat, 26, 8)))))))
          AND NOT EXISTS (SELECT 1 FROM voipc_gk_pending p WHERE p.grp = w.grp AND p.commit_id = w.commit_id)
          LIMIT $6)"
    );
    let (accounts_lo, accounts_hi) = ([0x01u8; 1], [0x02u8; 1]);
    n += batched!(
        store,
        sqlx::AssertSqlSafe(q.as_str()),
        grp,
        gen.as_slice(),
        i64::from(floor),
        &accounts_lo[..],
        &accounts_hi[..]
    );
    n += sweep_headers(store, grp, cut).await?;
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
/// the openings kept chains reference with each such epoch's last Join (a kept read of a
/// seat a Join added is answered there, `past`); of an older generation, while kept chains
/// reference its epochs, those openings and last Joins, its keyholder headers and Regenesis
/// parents (C4).
async fn sweep_headers(store: &Db, grp: &str, cut: i64) -> Result<u64> {
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
    // Each referenced epoch's last header kept: its last Join, or its opening
    let mut last_j: HashMap<(&Vec<u8>, i64), i64> = HashMap::new();
    for (_, gen, epoch, j, ..) in &metas {
        let at = last_j.entry((gen, *epoch)).or_insert(*j);
        *at = (*at).max(*j);
    }
    let mut keep: HashSet<Vec<u8>> = HashSet::new();
    for (d, gen, epoch, j, kind, time) in &metas {
        let kind = usize::try_from(*kind)
            .ok()
            .and_then(|i| KINDS.get(i).copied());
        let kh = kind.is_some_and(|k| k.sets_keyholders());
        let opening_ref = (*j == 0 || last_j.get(&(gen, *epoch)) == Some(j))
            && refs.contains(&(gen.clone(), *epoch));
        // An epoch whose material is still kept (`cut`, HOLD_MS after the next opening) keeps
        // its opening and last Join too: a kept chain filed late under it reads by them (dive
        // 3 F5)
        let held = *epoch >= cut && (*j == 0 || last_j.get(&(gen, *epoch)) == Some(j));
        let kept = if *gen == head_gen {
            last64.contains(&(*epoch, *j))
                || *epoch == i64::from(row.head.epoch)
                || held
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
