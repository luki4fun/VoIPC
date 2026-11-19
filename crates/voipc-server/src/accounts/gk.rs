//! The group key's tables (migration 0013, docs/GROUP-KEY.md §9): typed reads and writes for the
//! group actor's database store, and the two `voipc_meta` keys of restores and the switch. Only
//! stored groups come here: `c:` ids on a relay with accounts.
//!
//! A commit is stored in two steps, so that SQLite's single writer is never held for long:
//! `begin_commit`, then its material (`put_*`) in transactions of at most `STORE_BATCH` rows,
//! each tagged with the commit's id; then `move_head`, one small transaction of set-wise
//! statements. No read here returns a pending commit's material, and `sweep_orphans` takes the
//! material of a commit that never moved the head.
//!
//! `b`, `v` and commit ids are random u64, bound as i64 by their bits and compared for equality
//! only, never ordered in SQL. Epochs, joins, seeds, exit `seq` and times are counters, refused
//! past i64. Exit `seq` counts from 1, so `exits_upto` 0 is none.

use anyhow::{anyhow, bail, Result};
use l4f_accounts::store::Store;
use serde::{Deserialize, Serialize};
use voipc_crypto::group_key::{seat_record, GroupKind, Kind, MemberId, Pool, SeatRef, SeedRolls};
use voipc_protocol::gk::SelfRowIn;

use super::log::now_ms;

/// Rows one transaction writes or deletes at most (Round C: the writer is soon free again).
pub const STORE_BATCH: usize = 1000;
/// Rows in one INSERT, far under either database's limit on bound values.
const PER_INSERT: usize = 100;
/// Postgres: the first key of `put_seat_keys`'s advisory lock ("gksk"), the second the
/// account's first bytes. Two-key locks never meet l4f's one-key guard.
const SEAT_KEYS_LOCK: i32 = 0x676b_736b;

pub type Gen = [u8; 16];
pub type Digest = [u8; 32];
/// A seat's record (§11.5): kind, id, tag(SK), tag(SX).
pub type SeatRec = [u8; 33];
/// A member's seat id (§11.5): the first 17 bytes of its seats' records.
pub type MemberRec = [u8; 17];
/// A keyholder as a maker: its seat id, then its raw KX.
pub type Maker = [u8; 49];

/// A commit's tag on the material it writes before its head move.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CommitId(pub u64);

/// A stored group's head and generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Head {
    pub kind: GroupKind,
    pub gen: Gen,
    /// When the generation began, as the caller counts it.
    pub gen_time: u64,
    /// The database's `gk_incarnation` when this generation began.
    pub incarnation: [u8; 16],
    pub d: Digest,
    pub epoch: u32,
    pub join: u32,
    /// The next exit's `seq`. A head move never lowers it.
    pub exits_next: u64,
    pub rolls: SeedRolls,
    pub gated: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupRow {
    pub grp: String,
    pub head: Head,
    /// Unix ms of the last head move.
    pub updated: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub d: Digest,
    pub gen: Gen,
    pub epoch: u32,
    pub j: u32,
    pub kind: Kind,
    /// The signer's clock, unix s.
    pub time: u64,
    pub body: Vec<u8>,
    pub sig: Vec<u8>,
    /// Why it is kept, a bit each; 0 and `sweep_headers` takes it.
    pub keep: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seat {
    pub seat: SeatRec,
    pub dh: [u8; 33],
    pub b: u64,
    pub pool: Pool,
    /// The newest seed it holds.
    pub seed: u32,
    pub last_use: u64,
    pub account: Option<[u8; 16]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct List {
    pub b: u64,
    pub v: u64,
    pub pool: Pool,
    /// The version it ratcheted from.
    pub via: Option<u64>,
    /// The version a row or welcome reaches it by.
    pub base_v: u64,
    pub epoch_made: u32,
    /// Set by `move_head`: the epoch it stopped being current in. `put_lists` ignores it.
    pub epoch_until: Option<u32>,
    /// In list order.
    pub seats: Vec<SeatRec>,
    pub digest: Digest,
    /// Set by `move_head`; `put_lists` ignores it.
    pub current: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WelcomeKind {
    /// To a version: it seats a new seat.
    Seat,
    /// To a seat already seated, in a seed roll.
    Seed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Welcome {
    pub seat: SeatRec,
    pub kind: WelcomeKind,
    pub s: u32,
    /// `(b, v)` of a seat welcome; `None` for a seed welcome.
    pub version: Option<(u64, u64)>,
    pub maker: Maker,
    pub bytes: Vec<u8>,
    /// When the relay stored it, unix ms.
    pub made: u64,
}

/// A row to one seat of one version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BucketRow {
    pub b: u64,
    pub v: u64,
    pub seat: SeatRec,
    pub s: u32,
    pub maker: Maker,
    pub bytes: Vec<u8>,
    pub epoch_made: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seal {
    pub epoch: u32,
    pub b: u64,
    pub v: u64,
    pub bytes: Vec<u8>,
}

/// One piece of an epoch's keyring: `j` 0 the sealed base, then a delta per Join.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyringPiece {
    pub epoch: u32,
    pub j: u32,
    pub bytes: Vec<u8>,
}

/// A KRK welcome to the keyholder whose KX is `holder`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Krk {
    pub epoch: u32,
    pub holder: [u8; 32],
    pub maker: Maker,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Exit {
    pub seq: u64,
    pub gen: Gen,
    pub seat: SeatRec,
    pub cause: u8,
    pub at: u64,
}

/// A keyholder's misses and declines (times), postcard in `voipc_gk_holders.missed`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Misses {
    pub missed: Vec<u64>,
    pub declined: Vec<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Holder {
    pub kx: [u8; 32],
    pub m: MemberRec,
    pub device: Option<Vec<u8>>,
    pub rank: u8,
    pub last_online: u64,
    pub missed: Misses,
    /// Its endorsed pair: `KRK` welcomes go to it while it is offline (2i).
    pub pair: Option<voipc_protocol::gk::EndorsedPair>,
}

/// A gated group's names: `kind` 0 an `added` list, 1 a header carrying `removed`, 2 the step
/// before the oldest kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Names {
    pub gen: Gen,
    pub epoch: u32,
    pub j: u32,
    pub kind: u8,
    pub time: u64,
    pub names_hash: Digest,
    pub list: Vec<u8>,
}

/// An account's seat keys (origin 0x01), as published.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeatKeys {
    pub n: u32,
    pub kem: Vec<u8>,
    pub dh: Vec<u8>,
    pub made: u64,
    pub sig: Vec<u8>,
    pub published: u64,
}

/// What a head move changes beside the new head.
#[derive(Clone, Debug, Default)]
pub struct HeadMove<'a> {
    /// The head the commit was built on, as the relay holds it; `None` before a group's first.
    pub was: Option<Digest>,
    /// Headers to keep from now on: the new head, and whatever else the caller keeps.
    pub headers: &'a [Header],
    /// New `keep` bits of headers kept already.
    pub keep: &'a [(Digest, u32)],
    /// Buckets left with no current version (merged away).
    pub drops: &'a [u64],
    /// A Regenesis: every version this commit did not make stops. Its seats are left to
    /// `sweep_stale`, since no read returns a seat whose bucket has no current version.
    pub retire_all: bool,
    /// Every exit of this generation up to it is done, and its seat goes.
    pub exits_upto: u64,
    pub names: &'a [Names],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Moved {
    Done,
    /// The group's head is not `was`: nothing changed.
    OtherHead,
    /// The commit is not pending (swept, or moved already): nothing changed.
    NotPending,
}

// --- conversions ---

/// A random id's bits.
fn bits(x: u64) -> i64 {
    x as i64
}

fn unbits(x: i64) -> u64 {
    x as u64
}

/// A counter or a time, which the database holds only below i64::MAX.
fn count(x: u64, what: &str) -> Result<i64> {
    i64::try_from(x).map_err(|_| anyhow!("{what} {x} is past what the database holds"))
}

fn u64_of(x: i64, what: &str) -> Result<u64> {
    u64::try_from(x).map_err(|_| anyhow!("{what} {x} is negative"))
}

fn u32_of(x: i64, what: &str) -> Result<u32> {
    u32::try_from(x).map_err(|_| anyhow!("{what} {x} is not a u32"))
}

fn u8_of(x: i16, what: &str) -> Result<u8> {
    u8::try_from(x).map_err(|_| anyhow!("{what} {x} is not a u8"))
}

fn fixed<const N: usize>(v: Vec<u8>, what: &str) -> Result<[u8; N]> {
    let len = v.len();
    v.try_into()
        .map_err(|_| anyhow!("{what} is {len} bytes, not {N}"))
}

fn group_kind_code(k: GroupKind) -> i16 {
    match k {
        GroupKind::Text => 0,
        GroupKind::Voice => 1,
    }
}

fn group_kind_of(x: i16) -> Result<GroupKind> {
    match x {
        0 => Ok(GroupKind::Text),
        1 => Ok(GroupKind::Voice),
        _ => bail!("group kind {x} is unknown"),
    }
}

fn pool_code(p: Pool) -> i16 {
    match p {
        Pool::Accounts => 0,
        Pool::Conns => 1,
    }
}

fn pool_of(x: i16) -> Result<Pool> {
    match x {
        0 => Ok(Pool::Accounts),
        1 => Ok(Pool::Conns),
        _ => bail!("pool {x} is unknown"),
    }
}

/// Header kinds by their postcard index.
const KINDS: [Kind; 7] = [
    Kind::Genesis,
    Kind::Regenesis,
    Kind::Fresh,
    Kind::Join,
    Kind::KeyholdersAdd,
    Kind::KeyholdersRemove,
    Kind::KeyholdersReplace,
];

fn kind_code(k: Kind) -> i16 {
    KINDS.iter().position(|x| *x == k).unwrap_or(0) as i16
}

fn kind_of(x: i16) -> Result<Kind> {
    usize::try_from(x)
        .ok()
        .and_then(|i| KINDS.get(i).copied())
        .ok_or_else(|| anyhow!("header kind {x} is unknown"))
}

fn welcome_code(k: WelcomeKind) -> i16 {
    match k {
        WelcomeKind::Seat => 0,
        WelcomeKind::Seed => 1,
    }
}

fn welcome_of(x: i16) -> Result<WelcomeKind> {
    match x {
        0 => Ok(WelcomeKind::Seat),
        1 => Ok(WelcomeKind::Seed),
        _ => bail!("welcome kind {x} is unknown"),
    }
}

fn records(seats: &[SeatRec]) -> Vec<u8> {
    seats.concat()
}

fn records_of(v: &[u8]) -> Result<Vec<SeatRec>> {
    let (whole, rest) = v.as_chunks::<33>();
    if !rest.is_empty() {
        bail!("a seat list of {} bytes is not whole records", v.len());
    }
    Ok(whole.to_vec())
}

fn postcard_of<T: for<'de> Deserialize<'de>>(v: &[u8], what: &str) -> Result<T> {
    postcard::from_bytes(v).map_err(|e| anyhow!("{what} does not decode: {e}"))
}

/// Runs `$q` (one DELETE with `LIMIT $n` as its last bound value) until it takes nothing, a
/// short transaction each; the rows it took.
macro_rules! in_batches {
    ($store:expr, $q:expr, $($bind:expr),*) => {{
        let mut gone: u64 = 0;
        loop {
            let n = db!($store, pool => {
                sqlx::query($q)$(.bind($bind))*.bind(STORE_BATCH as i64).execute(pool).await?.rows_affected()
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

/// A transaction that writes. SQLite takes its write lock at BEGIN: a deferred transaction that
/// reads and then writes fails at once (BUSY) when another writer got in between, where this one
/// waits its turn (l4f's `begin_write`, log.rs's "the write comes first"). Postgres names READ
/// COMMITTED, under which each statement sees what an earlier lock waited for.
macro_rules! write_tx {
    ($store:expr, $tx:ident => $body:block) => {
        match $store {
            Store::Pg(b) => {
                let mut $tx =
                    b.0.begin_with("BEGIN ISOLATION LEVEL READ COMMITTED")
                        .await?;
                $body
            }
            Store::Lite(b) => {
                let mut $tx = b.0.begin_with("BEGIN IMMEDIATE").await?;
                $body
            }
        }
    };
}

/// In a write transaction: material only for a commit pending in this group. A commit swept,
/// moved already or of another group would have it read at once and never swept.
macro_rules! ensure_pending {
    ($tx:ident, $grp:expr, $c:expr) => {{
        let found: Option<i64> = sqlx::query_scalar(
            "SELECT commit_id FROM voipc_gk_pending WHERE grp = $1 AND commit_id = $2",
        )
        .bind($grp)
        .bind(bits($c.0))
        .fetch_optional(&mut *$tx)
        .await?;
        if found.is_none() {
            bail!("commit {:016x} is not pending in {}", $c.0, $grp);
        }
    }};
}

// --- voipc_meta: restores and the switch (plan 2i) ---

async fn meta(store: &Store, k: &str) -> Result<Option<Vec<u8>>> {
    Ok(db!(store, pool => {
        sqlx::query_scalar("SELECT v FROM voipc_meta WHERE k = $1").bind(k).fetch_optional(pool).await?
    }))
}

/// The database's incarnation, made at the first start with the switch on.
pub async fn gk_incarnation(store: &Store) -> Result<Option<[u8; 16]>> {
    meta(store, "gk_incarnation")
        .await?
        .map(|v| fixed(v, "voipc_meta.gk_incarnation"))
        .transpose()
}

/// The switch at the last start.
#[cfg(test)]
pub async fn gk_switch(store: &Store) -> Result<Option<bool>> {
    Ok(meta(store, "gk_switch").await?.map(|v| v == [1]))
}

/// `db new-incarnation`, after a restore with the relay stopped: every stored group starts a
/// new generation when it next starts.
pub async fn new_incarnation(store: &Store) -> Result<[u8; 16]> {
    let fresh: [u8; 16] = rand::random();
    db!(store, pool => {
        sqlx::query("INSERT INTO voipc_meta (k, v) VALUES ('gk_incarnation', $1) ON CONFLICT (k) DO UPDATE SET v = excluded.v")
            .bind(&fresh[..])
            .execute(pool)
            .await?;
    });
    Ok(fresh)
}

/// At start: notes the switch, and with it on gives the incarnation groups are measured
/// against. A start with it on after one with it off makes a new incarnation, since the exits
/// of the off run reached no keyholder (§5.14).
pub async fn gk_start(store: &Store, on: bool) -> Result<Option<[u8; 16]>> {
    let inc: Option<Vec<u8>> = write_tx!(store, tx => {
        let was: Option<Vec<u8>> = sqlx::query_scalar("SELECT v FROM voipc_meta WHERE k = 'gk_switch'")
            .fetch_optional(&mut *tx)
            .await?;
        let mut inc: Option<Vec<u8>> = sqlx::query_scalar("SELECT v FROM voipc_meta WHERE k = 'gk_incarnation'")
            .fetch_optional(&mut *tx)
            .await?;
        if on && (inc.is_none() || was.as_deref() == Some(&[0u8][..])) {
            let fresh: [u8; 16] = rand::random();
            sqlx::query("INSERT INTO voipc_meta (k, v) VALUES ('gk_incarnation', $1) ON CONFLICT (k) DO UPDATE SET v = excluded.v")
                .bind(&fresh[..])
                .execute(&mut *tx)
                .await?;
            inc = Some(fresh.to_vec());
        }
        sqlx::query("INSERT INTO voipc_meta (k, v) VALUES ('gk_switch', $1) ON CONFLICT (k) DO UPDATE SET v = excluded.v")
            .bind(&[u8::from(on)][..])
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        inc
    });
    if !on {
        return Ok(None);
    }
    inc.map(|v| fixed(v, "voipc_meta.gk_incarnation"))
        .transpose()
}

// --- groups ---

type GroupTuple = (
    String,
    i16,
    Vec<u8>,
    i64,
    Vec<u8>,
    Vec<u8>,
    i64,
    i64,
    i64,
    Vec<u8>,
    bool,
    i64,
);

fn group_row(t: GroupTuple) -> Result<GroupRow> {
    let (grp, kind, gen, gen_time, inc, d, epoch, join, exits_next, rolls, gated, updated) = t;
    Ok(GroupRow {
        grp,
        head: Head {
            kind: group_kind_of(kind)?,
            gen: fixed(gen, "gen")?,
            gen_time: u64_of(gen_time, "gen_time")?,
            incarnation: fixed(inc, "incarnation")?,
            d: fixed(d, "head_d")?,
            epoch: u32_of(epoch, "head_epoch")?,
            join: u32_of(join, "head_join")?,
            exits_next: u64_of(exits_next, "exits_next")?,
            rolls: postcard_of(&rolls, "rolls")?,
            gated,
        },
        updated: u64_of(updated, "updated")?,
    })
}

pub async fn group(store: &Store, grp: &str) -> Result<Option<GroupRow>> {
    let row: Option<GroupTuple> = db!(store, pool => {
        sqlx::query_as(
            "SELECT grp, kind, gen, gen_time, incarnation, head_d, head_epoch, head_join, exits_next, rolls, gated, updated
             FROM voipc_gk_groups WHERE grp = $1",
        )
        .bind(grp)
        .fetch_optional(pool)
        .await?
    });
    row.map(group_row).transpose()
}

/// Every stored group's id.
pub async fn groups(store: &Store) -> Result<Vec<String>> {
    Ok(db!(store, pool => {
        sqlx::query_scalar("SELECT grp FROM voipc_gk_groups").fetch_all(pool).await?
    }))
}

/// Every generation the group had, with when each began (unix ms).
pub async fn gens(store: &Store, grp: &str) -> Result<Vec<(Gen, u64)>> {
    let rows: Vec<(Vec<u8>, i64)> = db!(store, pool => {
        sqlx::query_as("SELECT gen, started FROM voipc_gk_gens WHERE grp = $1")
            .bind(grp)
            .fetch_all(pool)
            .await?
    });
    rows.into_iter()
        .map(|(g, t)| Ok((fixed(g, "gen")?, u64_of(t, "started")?)))
        .collect()
}

/// A group of an older incarnation loses what its next generation must not reuse: the keyring,
/// the KRK welcomes and every welcome of `gen`, the generation its head had when the actor found
/// it. One batch of each; called until it takes nothing. A new generation that lands meanwhile
/// keeps its own. What kept history reads (headers, seals, rows, lists) stays for the sweeps.
pub async fn reset_step(store: &Store, grp: &str, gen: &Gen) -> Result<u64> {
    let mut gone = 0;
    for q in [
        "DELETE FROM voipc_gk_keyring WHERE (grp, gen, epoch, j) IN
         (SELECT grp, gen, epoch, j FROM voipc_gk_keyring WHERE grp = $1 AND gen = $2 LIMIT $3)",
        "DELETE FROM voipc_gk_krk WHERE (grp, gen, epoch, holder) IN
         (SELECT grp, gen, epoch, holder FROM voipc_gk_krk WHERE grp = $1 AND gen = $2 LIMIT $3)",
        "DELETE FROM voipc_gk_welcomes WHERE (grp, gen, seat, kind, s) IN
         (SELECT grp, gen, seat, kind, s FROM voipc_gk_welcomes WHERE grp = $1 AND gen = $2 LIMIT $3)",
    ] {
        gone += db!(store, pool => {
            sqlx::query(q).bind(grp).bind(&gen[..]).bind(STORE_BATCH as i64).execute(pool).await?.rows_affected()
        });
    }
    Ok(gone)
}

// --- storing a commit (plan 2g) ---

/// The pending row first: from here the commit's material is invisible until its head moves.
pub async fn begin_commit(store: &Store, grp: &str) -> Result<CommitId> {
    let c = CommitId(rand::random());
    db!(store, pool => {
        sqlx::query("INSERT INTO voipc_gk_pending (grp, commit_id, started) VALUES ($1, $2, $3)")
            .bind(grp)
            .bind(bits(c.0))
            .bind(now_ms())
            .execute(pool)
            .await?;
    });
    Ok(c)
}

/// The version ids a commit makes (rule 16), its first material, each `(b, v)`. `Some(v)`: `v`
/// was used in this generation by a commit that moved the head, or by a stale attempt for
/// another bucket, and the commit fails `CHECK`. An id a commit that never moved the head left
/// for the same bucket is taken over, so a rebase may reuse its stale attempt's versions
/// (`put_lists` then checks they are the same, §4.1).
pub async fn put_vids(
    store: &Store,
    grp: &str,
    c: CommitId,
    gen: &Gen,
    vs: &[(u64, u64)],
) -> Result<Option<u64>> {
    for batch in vs.chunks(STORE_BATCH) {
        let used = write_tx!(store, tx => {
            ensure_pending!(tx, grp, c);
            let mut used = None;
            for (b, v) in batch {
                let n = sqlx::query(
                    "INSERT INTO voipc_gk_vids (grp, gen, v, b, commit_id) VALUES ($1, $2, $3, $4, $5)
                     ON CONFLICT (grp, gen, v) DO UPDATE SET commit_id = excluded.commit_id
                     WHERE voipc_gk_vids.commit_id IS NOT NULL AND voipc_gk_vids.b = excluded.b",
                )
                .bind(grp)
                .bind(&gen[..])
                .bind(bits(*v))
                .bind(bits(*b))
                .bind(bits(c.0))
                .execute(&mut *tx)
                .await?
                .rows_affected();
                if n == 0 {
                    used = Some(*v);
                    break;
                }
            }
            if used.is_none() {
                tx.commit().await?;
            }
            used
        });
        if used.is_some() {
            return Ok(used);
        }
    }
    Ok(None)
}

/// The commit's new versions, not current until its head moves. `Some((b, v))`: that version is
/// stored already, by a commit that moved the head, or by a stale attempt with other seats or as
/// a ratchet, and the commit fails `CHECK` (§4.1: a rebase reuses a version only with the same
/// seats, and never a ratchet). A stale attempt's same version is taken over.
pub async fn put_lists(
    store: &Store,
    grp: &str,
    c: CommitId,
    gen: &Gen,
    lists: &[List],
) -> Result<Option<(u64, u64)>> {
    for batch in lists.chunks(STORE_BATCH) {
        let refused = write_tx!(store, tx => {
            ensure_pending!(tx, grp, c);
            let mut refused = None;
            for part in batch.chunks(PER_INSERT) {
                let mut q = sqlx::QueryBuilder::new(
                    "INSERT INTO voipc_gk_lists (grp, gen, b, v, pool, via, base_v, epoch_made, seats, digest, current, commit_id) ",
                );
                q.push_values(part, |mut t, l| {
                    t.push_bind(grp)
                        .push_bind(&gen[..])
                        .push_bind(bits(l.b))
                        .push_bind(bits(l.v))
                        .push_bind(pool_code(l.pool))
                        .push_bind(l.via.map(bits))
                        .push_bind(bits(l.base_v))
                        .push_bind(i64::from(l.epoch_made))
                        .push_bind(records(&l.seats))
                        .push_bind(&l.digest[..])
                        .push_bind(false)
                        .push_bind(bits(c.0));
                });
                q.push(
                    " ON CONFLICT (grp, gen, b, v) DO UPDATE SET epoch_made = excluded.epoch_made,
                     commit_id = excluded.commit_id
                     WHERE NOT voipc_gk_lists.current AND voipc_gk_lists.via IS NULL AND excluded.via IS NULL
                     AND voipc_gk_lists.pool = excluded.pool AND voipc_gk_lists.base_v = excluded.base_v
                     AND voipc_gk_lists.seats = excluded.seats AND voipc_gk_lists.digest = excluded.digest
                     AND EXISTS (SELECT 1 FROM voipc_gk_pending p
                       WHERE p.grp = voipc_gk_lists.grp AND p.commit_id = voipc_gk_lists.commit_id)",
                );
                let n = q.build().persistent(false).execute(&mut *tx).await?.rows_affected();
                if n == part.len() as u64 {
                    continue;
                }
                // Which one: every list written here is this commit's now
                for l in part {
                    let by: Option<i64> = sqlx::query_scalar(
                        "SELECT commit_id FROM voipc_gk_lists WHERE grp = $1 AND gen = $2 AND b = $3 AND v = $4",
                    )
                    .bind(grp)
                    .bind(&gen[..])
                    .bind(bits(l.b))
                    .bind(bits(l.v))
                    .fetch_optional(&mut *tx)
                    .await?;
                    if by != Some(bits(c.0)) {
                        refused = Some((l.b, l.v));
                        break;
                    }
                }
                if refused.is_none() {
                    bail!("a version of this commit was not stored in {grp}");
                }
                break;
            }
            if refused.is_none() {
                tx.commit().await?;
            }
            refused
        });
        if refused.is_some() {
            return Ok(refused);
        }
    }
    Ok(None)
}

/// Seats a commit seats (each `b` its bucket): not seated until the head moves. A row the seat
/// left behind (an orphan's, or one whose bucket is gone) is written over.
pub async fn put_new_seats(
    store: &Store,
    grp: &str,
    c: CommitId,
    gen: &Gen,
    seats: &[Seat],
) -> Result<()> {
    for s in seats {
        count(s.last_use, "last_use")?;
    }
    for batch in seats.chunks(STORE_BATCH) {
        write_tx!(store, tx => {
            ensure_pending!(tx, grp, c);
            for part in batch.chunks(PER_INSERT) {
                let mut q = sqlx::QueryBuilder::new(
                    "INSERT INTO voipc_gk_seats (grp, gen, seat, dh, b, next_b, next_commit, pool, seed, last_use, account) ",
                );
                q.push_values(part, |mut t, s| {
                    t.push_bind(grp)
                        .push_bind(&gen[..])
                        .push_bind(&s.seat[..])
                        .push_bind(&s.dh[..])
                        .push_bind(None::<i64>)
                        .push_bind(bits(s.b))
                        .push_bind(bits(c.0))
                        .push_bind(pool_code(s.pool))
                        .push_bind(i64::from(s.seed))
                        .push_bind(s.last_use as i64)
                        .push_bind(s.account.as_ref().map(|a| &a[..]));
                });
                q.push(
                    " ON CONFLICT (grp, gen, seat) DO UPDATE SET dh = excluded.dh, next_b = excluded.next_b,
                     next_commit = excluded.next_commit, pool = excluded.pool, seed = excluded.seed,
                     last_use = excluded.last_use, account = excluded.account",
                );
                q.build().persistent(false).execute(&mut *tx).await?;
            }
            tx.commit().await?;
        });
    }
    Ok(())
}

/// Seated seats a commit moves to another bucket (a merge), there once the head moves.
pub async fn put_moves(
    store: &Store,
    grp: &str,
    c: CommitId,
    gen: &Gen,
    moves: &[(SeatRec, u64)],
) -> Result<()> {
    for batch in moves.chunks(STORE_BATCH) {
        write_tx!(store, tx => {
            ensure_pending!(tx, grp, c);
            for (seat, b) in batch {
                let n = sqlx::query(
                    "UPDATE voipc_gk_seats SET next_b = $1, next_commit = $2
                     WHERE grp = $3 AND gen = $4 AND seat = $5 AND b IS NOT NULL",
                )
                .bind(bits(*b))
                .bind(bits(c.0))
                .bind(grp)
                .bind(&gen[..])
                .bind(&seat[..])
                .execute(&mut *tx)
                .await?
                .rows_affected();
                if n == 0 {
                    bail!("a seat this commit moves is not seated in {grp}");
                }
            }
            tx.commit().await?;
        });
    }
    Ok(())
}

/// The commit's rows. Each goes to a version this commit listed (`put_lists` first): a version's
/// rows go with its list, which is how an orphan's are found again without an index by commit.
/// Rows a stale attempt left in a version this commit took over go (they are never read: a row
/// is read only by the commit that owns its version).
pub async fn put_rows(
    store: &Store,
    grp: &str,
    c: CommitId,
    gen: &Gen,
    rows: &[BucketRow],
) -> Result<()> {
    for batch in rows.chunks(STORE_BATCH) {
        let mut versions: Vec<(u64, u64)> = batch.iter().map(|r| (r.b, r.v)).collect();
        versions.sort_unstable();
        versions.dedup();
        write_tx!(store, tx => {
            ensure_pending!(tx, grp, c);
            for (b, v) in &versions {
                let by: Option<i64> = sqlx::query_scalar(
                    "SELECT commit_id FROM voipc_gk_lists WHERE grp = $1 AND gen = $2 AND b = $3 AND v = $4",
                )
                .bind(grp)
                .bind(&gen[..])
                .bind(bits(*b))
                .bind(bits(*v))
                .fetch_optional(&mut *tx)
                .await?;
                if by != Some(bits(c.0)) {
                    bail!("a row to a version this commit did not list in {grp}");
                }
                // At most the version's seats: the takeover checked they are the same
                sqlx::query(
                    "DELETE FROM voipc_gk_rows WHERE grp = $1 AND gen = $2 AND b = $3 AND v = $4 AND commit_id <> $5",
                )
                .bind(grp)
                .bind(&gen[..])
                .bind(bits(*b))
                .bind(bits(*v))
                .bind(bits(c.0))
                .execute(&mut *tx)
                .await?;
            }
            for part in batch.chunks(PER_INSERT) {
                let mut q = sqlx::QueryBuilder::new(
                    "INSERT INTO voipc_gk_rows (grp, gen, b, v, seat, s, maker, bytes, epoch_made, commit_id) ",
                );
                q.push_values(part, |mut t, r| {
                    t.push_bind(grp)
                        .push_bind(&gen[..])
                        .push_bind(bits(r.b))
                        .push_bind(bits(r.v))
                        .push_bind(&r.seat[..])
                        .push_bind(i64::from(r.s))
                        .push_bind(&r.maker[..])
                        .push_bind(r.bytes.as_slice())
                        .push_bind(i64::from(r.epoch_made))
                        .push_bind(bits(c.0));
                });
                q.push(
                    " ON CONFLICT (grp, gen, b, v, seat) DO UPDATE SET s = excluded.s, maker = excluded.maker,
                     bytes = excluded.bytes, epoch_made = excluded.epoch_made, commit_id = excluded.commit_id",
                );
                q.build().persistent(false).execute(&mut *tx).await?;
            }
            tx.commit().await?;
        });
    }
    Ok(())
}

/// The commit's seat welcomes (`WelcomeKind::Seat`, each with its version).
pub async fn put_welcomes(
    store: &Store,
    grp: &str,
    c: CommitId,
    gen: &Gen,
    welcomes: &[Welcome],
) -> Result<()> {
    if welcomes.iter().any(|w| w.kind != WelcomeKind::Seat) {
        bail!("a commit stores seat welcomes only: seed welcomes come in pages");
    }
    write_welcomes(store, grp, Some(c), gen, welcomes).await
}

/// A seed-welcome page, which is no commit: each seat holds `s` from now on.
pub async fn put_seed_welcomes(
    store: &Store,
    grp: &str,
    gen: &Gen,
    welcomes: &[Welcome],
) -> Result<()> {
    if welcomes.iter().any(|w| w.kind != WelcomeKind::Seed) {
        bail!("a seed-welcome page holds seed welcomes only");
    }
    write_welcomes(store, grp, None, gen, welcomes).await
}

async fn write_welcomes(
    store: &Store,
    grp: &str,
    c: Option<CommitId>,
    gen: &Gen,
    welcomes: &[Welcome],
) -> Result<()> {
    for w in welcomes {
        if (w.kind == WelcomeKind::Seat) != w.version.is_some() {
            bail!("a seat welcome names its version, a seed welcome none");
        }
        count(w.made, "made")?;
    }
    for batch in welcomes.chunks(STORE_BATCH) {
        write_tx!(store, tx => {
            if let Some(c) = c {
                ensure_pending!(tx, grp, c);
            }
            for part in batch.chunks(PER_INSERT) {
                let mut q = sqlx::QueryBuilder::new(
                    "INSERT INTO voipc_gk_welcomes (grp, gen, seat, kind, s, b, v, maker, bytes, made, commit_id) ",
                );
                q.push_values(part, |mut t, w| {
                    t.push_bind(grp)
                        .push_bind(&gen[..])
                        .push_bind(&w.seat[..])
                        .push_bind(welcome_code(w.kind))
                        .push_bind(i64::from(w.s))
                        .push_bind(w.version.map(|(b, _)| bits(b)))
                        .push_bind(w.version.map(|(_, v)| bits(v)))
                        .push_bind(&w.maker[..])
                        .push_bind(w.bytes.as_slice())
                        .push_bind(w.made as i64)
                        .push_bind(c.map(|c| bits(c.0)));
                });
                q.push(
                    " ON CONFLICT (grp, gen, seat, kind, s) DO UPDATE SET b = excluded.b, v = excluded.v,
                     maker = excluded.maker, bytes = excluded.bytes, made = excluded.made, commit_id = excluded.commit_id",
                );
                q.build().persistent(false).execute(&mut *tx).await?;
            }
            if c.is_none() {
                for w in batch {
                    sqlx::query(
                        "UPDATE voipc_gk_seats SET seed = CASE WHEN seed < $1 THEN $1 ELSE seed END
                         WHERE grp = $2 AND gen = $3 AND seat = $4",
                    )
                    .bind(i64::from(w.s))
                    .bind(grp)
                    .bind(&gen[..])
                    .bind(&w.seat[..])
                    .execute(&mut *tx)
                    .await?;
                }
            }
            tx.commit().await?;
        });
    }
    Ok(())
}

pub async fn put_seals(
    store: &Store,
    grp: &str,
    c: CommitId,
    gen: &Gen,
    seals: &[Seal],
) -> Result<()> {
    for batch in seals.chunks(STORE_BATCH) {
        write_tx!(store, tx => {
            ensure_pending!(tx, grp, c);
            for part in batch.chunks(PER_INSERT) {
                let mut q = sqlx::QueryBuilder::new(
                    "INSERT INTO voipc_gk_seals (grp, gen, epoch, b, v, bytes, commit_id) ",
                );
                q.push_values(part, |mut t, s| {
                    t.push_bind(grp)
                        .push_bind(&gen[..])
                        .push_bind(i64::from(s.epoch))
                        .push_bind(bits(s.b))
                        .push_bind(bits(s.v))
                        .push_bind(s.bytes.as_slice())
                        .push_bind(bits(c.0));
                });
                q.push(
                    " ON CONFLICT (grp, gen, epoch, b, v) DO UPDATE SET bytes = excluded.bytes, commit_id = excluded.commit_id",
                );
                q.build().persistent(false).execute(&mut *tx).await?;
            }
            tx.commit().await?;
        });
    }
    Ok(())
}

pub async fn put_keyring(
    store: &Store,
    grp: &str,
    c: CommitId,
    gen: &Gen,
    pieces: &[KeyringPiece],
) -> Result<()> {
    write_tx!(store, tx => {
        ensure_pending!(tx, grp, c);
        for p in pieces {
            sqlx::query(
                "INSERT INTO voipc_gk_keyring (grp, gen, epoch, j, bytes, commit_id) VALUES ($1, $2, $3, $4, $5, $6)
                 ON CONFLICT (grp, gen, epoch, j) DO UPDATE SET bytes = excluded.bytes, commit_id = excluded.commit_id",
            )
            .bind(grp)
            .bind(&gen[..])
            .bind(i64::from(p.epoch))
            .bind(i64::from(p.j))
            .bind(p.bytes.as_slice())
            .bind(bits(c.0))
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
    });
    Ok(())
}

pub async fn put_krk(store: &Store, grp: &str, c: CommitId, gen: &Gen, krk: &[Krk]) -> Result<()> {
    write_tx!(store, tx => {
        ensure_pending!(tx, grp, c);
        for k in krk {
            sqlx::query(
                "INSERT INTO voipc_gk_krk (grp, gen, epoch, holder, maker, bytes, commit_id) VALUES ($1, $2, $3, $4, $5, $6, $7)
                 ON CONFLICT (grp, gen, epoch, holder) DO UPDATE SET maker = excluded.maker, bytes = excluded.bytes,
                 commit_id = excluded.commit_id",
            )
            .bind(grp)
            .bind(&gen[..])
            .bind(i64::from(k.epoch))
            .bind(&k.holder[..])
            .bind(&k.maker[..])
            .bind(k.bytes.as_slice())
            .bind(bits(c.0))
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
    });
    Ok(())
}

/// `move_head`: the commit's lists become current, its seats seated, its version ids used.
const LISTS_LAND: &str = "UPDATE voipc_gk_lists SET current = TRUE WHERE (grp, gen, b, v) IN
     (SELECT grp, gen, b, v FROM voipc_gk_lists WHERE grp = $1 AND commit_id = $2)";
const SEATS_LAND: &str = "UPDATE voipc_gk_seats SET b = next_b, next_b = NULL, next_commit = NULL
     WHERE (grp, gen, seat) IN (SELECT grp, gen, seat FROM voipc_gk_seats WHERE grp = $1 AND next_commit = $2)";
const VIDS_LAND: &str = "UPDATE voipc_gk_vids SET commit_id = NULL WHERE (grp, gen, v) IN
     (SELECT grp, gen, v FROM voipc_gk_vids WHERE grp = $1 AND commit_id = $2)";

/// The one small transaction that makes commit `c` the head: the group's row, its headers and
/// names, the lists' `current`/`epoch_until`, its seats, its version ids, the exits it dealt
/// with and their seats, and its pending row. Each step is one statement over many rows, never
/// a statement a row, but for `drops` and `keep`. Only after `Moved::Done` may pushes go out.
///
/// A statement that finds its rows by a secondary index names them by key through a subquery
/// on that index: without ANALYZE, SQLite would rather scan the primary key's `(grp, gen)`
/// prefix, every list or seat the group kept.
pub async fn move_head(
    store: &Store,
    grp: &str,
    c: CommitId,
    head: &Head,
    mv: &HeadMove<'_>,
) -> Result<Moved> {
    let rolls = postcard::to_allocvec(&head.rolls)?;
    let gen_time = count(head.gen_time, "gen_time")?;
    let exits_next = count(head.exits_next, "exits_next")?;
    let exits_upto = count(mv.exits_upto, "exits_upto")?;
    let mut headers = Vec::with_capacity(mv.headers.len());
    for h in mv.headers {
        headers.push((h, count(h.time, "header time")?));
    }
    let mut names = Vec::with_capacity(mv.names.len());
    for n in mv.names {
        names.push((n, count(n.time, "names time")?));
    }
    let epoch = i64::from(head.epoch);
    let now = now_ms();
    let moved = write_tx!(store, tx => {
        let pending = sqlx::query("DELETE FROM voipc_gk_pending WHERE grp = $1 AND commit_id = $2")
            .bind(grp)
            .bind(bits(c.0))
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if pending == 0 {
            return Ok(Moved::NotPending);
        }
        let old: Option<(Vec<u8>, Vec<u8>, i64)> =
            sqlx::query_as("SELECT gen, head_d, head_epoch FROM voipc_gk_groups WHERE grp = $1")
                .bind(grp)
                .fetch_optional(&mut *tx)
                .await?;
        if old.as_ref().map(|o| o.1.as_slice()) != mv.was.as_ref().map(|d| &d[..]) {
            return Ok(Moved::OtherHead);
        }
        // Written only over the head the commit was built on
        let n = sqlx::query(
            "INSERT INTO voipc_gk_groups (grp, kind, gen, gen_time, incarnation, head_d, head_epoch, head_join, exits_next, rolls, gated, updated)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
             ON CONFLICT (grp) DO UPDATE SET kind = excluded.kind, gen = excluded.gen, gen_time = excluded.gen_time,
             incarnation = excluded.incarnation, head_d = excluded.head_d, head_epoch = excluded.head_epoch,
             head_join = excluded.head_join,
             exits_next = CASE WHEN voipc_gk_groups.exits_next > excluded.exits_next THEN voipc_gk_groups.exits_next ELSE excluded.exits_next END,
             rolls = excluded.rolls, gated = excluded.gated, updated = excluded.updated
             WHERE voipc_gk_groups.head_d = $13",
        )
        .bind(grp)
        .bind(group_kind_code(head.kind))
        .bind(&head.gen[..])
        .bind(gen_time)
        .bind(&head.incarnation[..])
        .bind(&head.d[..])
        .bind(epoch)
        .bind(i64::from(head.join))
        .bind(exits_next)
        .bind(rolls.as_slice())
        .bind(head.gated)
        .bind(now)
        .bind(mv.was.as_ref().map_or(&[][..], |d| &d[..]))
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if n != 1 {
            return Ok(Moved::OtherHead);
        }
        sqlx::query("INSERT INTO voipc_gk_gens (grp, gen, started) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING")
            .bind(grp)
            .bind(&head.gen[..])
            .bind(now)
            .execute(&mut *tx)
            .await?;
        // A new generation: the old one's lists stop and its open exits are moot
        if let Some((old_gen, _, old_epoch)) = &old {
            if old_gen.as_slice() != head.gen.as_slice() {
                sqlx::query(
                    "UPDATE voipc_gk_lists SET current = FALSE, epoch_until = $1 WHERE (grp, gen, b, v) IN
                     (SELECT grp, gen, b, v FROM voipc_gk_lists WHERE grp = $2 AND gen = $3 AND current = TRUE)",
                )
                .bind(old_epoch + 1)
                .bind(grp)
                .bind(old_gen.as_slice())
                .execute(&mut *tx)
                .await?;
                sqlx::query("DELETE FROM voipc_gk_exits WHERE grp = $1 AND gen = $2")
                    .bind(grp)
                    .bind(old_gen.as_slice())
                    .execute(&mut *tx)
                    .await?;
            }
        }
        // Versions the commit replaced, and buckets it merged away
        sqlx::query(
            "UPDATE voipc_gk_lists SET current = FALSE, epoch_until = $1
             WHERE grp = $2 AND gen = $3 AND current
             AND b IN (SELECT b FROM voipc_gk_lists WHERE grp = $2 AND commit_id = $4)",
        )
        .bind(epoch)
        .bind(grp)
        .bind(&head.gen[..])
        .bind(bits(c.0))
        .execute(&mut *tx)
        .await?;
        if mv.retire_all {
            sqlx::query(
                "UPDATE voipc_gk_lists SET current = FALSE, epoch_until = $1 WHERE (grp, gen, b, v) IN
                 (SELECT grp, gen, b, v FROM voipc_gk_lists WHERE grp = $2 AND gen = $3 AND current = TRUE)
                 AND commit_id <> $4",
            )
            .bind(epoch)
            .bind(grp)
            .bind(&head.gen[..])
            .bind(bits(c.0))
            .execute(&mut *tx)
            .await?;
        }
        for b in mv.drops {
            sqlx::query(
                "UPDATE voipc_gk_lists SET current = FALSE, epoch_until = $1 WHERE grp = $2 AND gen = $3 AND b = $4 AND current",
            )
            .bind(epoch)
            .bind(grp)
            .bind(&head.gen[..])
            .bind(bits(*b))
            .execute(&mut *tx)
            .await?;
        }
        sqlx::query(LISTS_LAND)
            .bind(grp)
            .bind(bits(c.0))
            .execute(&mut *tx)
            .await?;
        sqlx::query(SEATS_LAND)
        .bind(grp)
        .bind(bits(c.0))
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "DELETE FROM voipc_gk_seats WHERE (grp, gen, seat) IN
             (SELECT grp, gen, seat FROM voipc_gk_exits WHERE grp = $1 AND gen = $2 AND seq <= $3)",
        )
        .bind(grp)
        .bind(&head.gen[..])
        .bind(exits_upto)
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM voipc_gk_exits WHERE grp = $1 AND gen = $2 AND seq <= $3")
            .bind(grp)
            .bind(&head.gen[..])
            .bind(exits_upto)
            .execute(&mut *tx)
            .await?;
        sqlx::query(VIDS_LAND)
            .bind(grp)
            .bind(bits(c.0))
            .execute(&mut *tx)
            .await?;
        for (h, time) in &headers {
            sqlx::query(
                "INSERT INTO voipc_gk_headers (grp, d, gen, epoch, j, kind, time, body, sig, keep) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                 ON CONFLICT (grp, d) DO UPDATE SET keep = excluded.keep",
            )
            .bind(grp)
            .bind(&h.d[..])
            .bind(&h.gen[..])
            .bind(i64::from(h.epoch))
            .bind(i64::from(h.j))
            .bind(kind_code(h.kind))
            .bind(*time)
            .bind(h.body.as_slice())
            .bind(h.sig.as_slice())
            .bind(i64::from(h.keep))
            .execute(&mut *tx)
            .await?;
        }
        for (d, keep) in mv.keep {
            sqlx::query("UPDATE voipc_gk_headers SET keep = $1 WHERE grp = $2 AND d = $3")
                .bind(i64::from(*keep))
                .bind(grp)
                .bind(&d[..])
                .execute(&mut *tx)
                .await?;
        }
        for (n, time) in &names {
            sqlx::query(
                "INSERT INTO voipc_gk_names (grp, gen, epoch, j, kind, time, names_hash, list) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                 ON CONFLICT (grp, gen, epoch, j, kind) DO UPDATE SET time = excluded.time, names_hash = excluded.names_hash,
                 list = excluded.list",
            )
            .bind(grp)
            .bind(&n.gen[..])
            .bind(i64::from(n.epoch))
            .bind(i64::from(n.j))
            .bind(i16::from(n.kind))
            .bind(*time)
            .bind(&n.names_hash[..])
            .bind(n.list.as_slice())
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Moved::Done
    });
    Ok(moved)
}

/// Takes the material of every pending commit of `grp` but `except` (the one being stored, if
/// any), in batches, then its pending row: at actor start, every pending commit is an orphan.
/// The orphans swept.
pub async fn sweep_orphans(store: &Store, grp: &str, except: Option<CommitId>) -> Result<usize> {
    let pending: Vec<i64> = db!(store, pool => {
        sqlx::query_scalar("SELECT commit_id FROM voipc_gk_pending WHERE grp = $1")
            .bind(grp)
            .fetch_all(pool)
            .await?
    });
    let mut swept = 0;
    for c in pending {
        if except.is_some_and(|e| bits(e.0) == c) {
            continue;
        }
        // A version's rows go with its list, so before the lists. A list a rebase took over is
        // the rebase's: rows this one left in it are never read, and go at the rebase's
        // `put_rows` or with its sweep
        in_batches!(
            store,
            // From the commit's lists to their rows (CROSS JOIN keeps that order in SQLite)
            "DELETE FROM voipc_gk_rows WHERE (grp, gen, b, v, seat) IN
             (SELECT r.grp, r.gen, r.b, r.v, r.seat FROM voipc_gk_lists l CROSS JOIN voipc_gk_rows r
              WHERE l.grp = $1 AND l.commit_id = $2
              AND r.grp = l.grp AND r.gen = l.gen AND r.b = l.b AND r.v = l.v LIMIT $3)",
            grp,
            c
        );
        in_batches!(
            store,
            "DELETE FROM voipc_gk_lists WHERE (grp, gen, b, v) IN
             (SELECT grp, gen, b, v FROM voipc_gk_lists WHERE grp = $1 AND commit_id = $2 LIMIT $3)",
            grp,
            c
        );
        in_batches!(
            store,
            "DELETE FROM voipc_gk_welcomes WHERE (grp, gen, seat, kind, s) IN
             (SELECT grp, gen, seat, kind, s FROM voipc_gk_welcomes WHERE grp = $1 AND commit_id = $2 LIMIT $3)",
            grp,
            c
        );
        in_batches!(
            store,
            "DELETE FROM voipc_gk_seals WHERE (grp, gen, epoch, b, v) IN
             (SELECT grp, gen, epoch, b, v FROM voipc_gk_seals WHERE grp = $1 AND commit_id = $2 LIMIT $3)",
            grp,
            c
        );
        in_batches!(
            store,
            "DELETE FROM voipc_gk_vids WHERE (grp, gen, v) IN
             (SELECT grp, gen, v FROM voipc_gk_vids WHERE grp = $1 AND commit_id = $2 LIMIT $3)",
            grp,
            c
        );
        in_batches!(
            store,
            "DELETE FROM voipc_gk_seats WHERE (grp, gen, seat) IN
             (SELECT grp, gen, seat FROM voipc_gk_seats WHERE grp = $1 AND next_commit = $2 AND b IS NULL LIMIT $3)",
            grp,
            c
        );
        write_tx!(store, tx => {
            for q in [
                "UPDATE voipc_gk_seats SET next_b = NULL, next_commit = NULL WHERE (grp, gen, seat) IN
                 (SELECT grp, gen, seat FROM voipc_gk_seats WHERE grp = $1 AND next_commit = $2)",
                "DELETE FROM voipc_gk_keyring WHERE (grp, gen, epoch, j) IN
                 (SELECT grp, gen, epoch, j FROM voipc_gk_keyring WHERE grp = $1 AND commit_id = $2)",
                "DELETE FROM voipc_gk_krk WHERE (grp, gen, epoch, holder) IN
                 (SELECT grp, gen, epoch, holder FROM voipc_gk_krk WHERE grp = $1 AND commit_id = $2)",
                "DELETE FROM voipc_gk_pending WHERE grp = $1 AND commit_id = $2",
            ] {
                sqlx::query(q).bind(grp).bind(c).execute(&mut *tx).await?;
            }
            tx.commit().await?;
        });
        swept += 1;
    }
    Ok(swept)
}

// --- reads (none returns a pending commit's material) ---

type HeaderTuple = (Vec<u8>, Vec<u8>, i64, i64, i16, i64, Vec<u8>, Vec<u8>, i64);

fn header_of(t: HeaderTuple) -> Result<Header> {
    let (d, gen, epoch, j, kind, time, body, sig, keep) = t;
    Ok(Header {
        d: fixed(d, "header d")?,
        gen: fixed(gen, "gen")?,
        epoch: u32_of(epoch, "epoch")?,
        j: u32_of(j, "j")?,
        kind: kind_of(kind)?,
        time: u64_of(time, "time")?,
        body,
        sig,
        keep: u32_of(keep, "keep")?,
    })
}

pub async fn header(store: &Store, grp: &str, d: &Digest) -> Result<Option<Header>> {
    let row: Option<HeaderTuple> = db!(store, pool => {
        sqlx::query_as(
            "SELECT d, gen, epoch, j, kind, time, body, sig, keep FROM voipc_gk_headers WHERE grp = $1 AND d = $2",
        )
        .bind(grp)
        .bind(&d[..])
        .fetch_optional(pool)
        .await?
    });
    row.map(header_of).transpose()
}

/// Every header kept of a generation, by `(epoch, j)`.
pub async fn headers(store: &Store, grp: &str, gen: &Gen) -> Result<Vec<Header>> {
    let rows: Vec<HeaderTuple> = db!(store, pool => {
        sqlx::query_as(
            "SELECT d, gen, epoch, j, kind, time, body, sig, keep FROM voipc_gk_headers WHERE grp = $1 AND gen = $2",
        )
        .bind(grp)
        .bind(&gen[..])
        .fetch_all(pool)
        .await?
    });
    let mut out = rows
        .into_iter()
        .map(header_of)
        .collect::<Result<Vec<_>>>()?;
    out.sort_by_key(|h| (h.epoch, h.j));
    Ok(out)
}

/// An epoch's opening header, if kept.
pub async fn opening(store: &Store, grp: &str, gen: &Gen, epoch: u32) -> Result<Option<Header>> {
    let row: Option<HeaderTuple> = db!(store, pool => {
        sqlx::query_as(
            "SELECT d, gen, epoch, j, kind, time, body, sig, keep FROM voipc_gk_headers WHERE (grp, d) IN
             (SELECT grp, d FROM voipc_gk_headers WHERE grp = $1 AND gen = $2 AND epoch = $3 AND j = 0)",
        )
        .bind(grp)
        .bind(&gen[..])
        .bind(i64::from(epoch))
        .fetch_optional(pool)
        .await?
    });
    row.map(header_of).transpose()
}

/// The last header kept of an epoch: its last Join, or its opening when none followed (a
/// past epoch's last Join holds every version sealed at that epoch, C4).
pub async fn epoch_last(store: &Store, grp: &str, gen: &Gen, epoch: u32) -> Result<Option<Header>> {
    let row: Option<HeaderTuple> = db!(store, pool => {
        sqlx::query_as(
            "SELECT d, gen, epoch, j, kind, time, body, sig, keep FROM voipc_gk_headers
             WHERE grp = $1 AND gen = $2 AND epoch = $3 ORDER BY j DESC LIMIT 1",
        )
        .bind(grp)
        .bind(&gen[..])
        .bind(i64::from(epoch))
        .fetch_optional(pool)
        .await?
    });
    row.map(header_of).transpose()
}

#[cfg(test)]
pub async fn set_keep(store: &Store, grp: &str, d: &Digest, keep: u32) -> Result<bool> {
    Ok(db!(store, pool => {
        sqlx::query("UPDATE voipc_gk_headers SET keep = $1 WHERE grp = $2 AND d = $3")
            .bind(i64::from(keep))
            .bind(grp)
            .bind(&d[..])
            .execute(pool)
            .await?
            .rows_affected()
            == 1
    }))
}

/// Headers with no reason left to stay; the count taken.
#[cfg(test)]
pub async fn sweep_headers(store: &Store, grp: &str) -> Result<u64> {
    Ok(in_batches!(
        store,
        "DELETE FROM voipc_gk_headers WHERE (grp, d) IN
         (SELECT grp, d FROM voipc_gk_headers WHERE grp = $1 AND keep = 0 LIMIT $2)",
        grp
    ))
}

type SeatTuple = (Vec<u8>, Vec<u8>, i64, i16, i64, i64, Option<Vec<u8>>);

fn seat_of(t: SeatTuple) -> Result<Seat> {
    let (seat, dh, b, pool, seed, last_use, account) = t;
    Ok(Seat {
        seat: fixed(seat, "seat")?,
        dh: fixed(dh, "dh")?,
        b: unbits(b),
        pool: pool_of(pool)?,
        seed: u32_of(seed, "seed")?,
        last_use: u64_of(last_use, "last_use")?,
        account: account.map(|a| fixed(a, "account")).transpose()?,
    })
}

/// The generation's seated seats: in a bucket with a current version (a pending commit's seats
/// and moves not yet).
pub async fn seats(store: &Store, grp: &str, gen: &Gen) -> Result<Vec<Seat>> {
    let rows: Vec<SeatTuple> = db!(store, pool => {
        sqlx::query_as(
            "SELECT seat, dh, b, pool, seed, last_use, account FROM voipc_gk_seats s
             WHERE grp = $1 AND gen = $2 AND b IS NOT NULL AND EXISTS (SELECT 1 FROM voipc_gk_lists l
               WHERE l.grp = s.grp AND l.gen = s.gen AND l.b = s.b AND l.current)",
        )
        .bind(grp)
        .bind(&gen[..])
        .fetch_all(pool)
        .await?
    });
    rows.into_iter().map(seat_of).collect()
}

#[cfg(test)]
pub async fn seat(store: &Store, grp: &str, gen: &Gen, seat: &SeatRec) -> Result<Option<Seat>> {
    let row: Option<SeatTuple> = db!(store, pool => {
        sqlx::query_as(
            "SELECT seat, dh, b, pool, seed, last_use, account FROM voipc_gk_seats s
             WHERE grp = $1 AND gen = $2 AND seat = $3 AND b IS NOT NULL AND EXISTS (SELECT 1 FROM voipc_gk_lists l
               WHERE l.grp = s.grp AND l.gen = s.gen AND l.b = s.b AND l.current)",
        )
        .bind(grp)
        .bind(&gen[..])
        .bind(&seat[..])
        .fetch_optional(pool)
        .await?
    });
    row.map(seat_of).transpose()
}

type AccountSeatTuple = (
    String,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    i16,
    i64,
    i64,
    Option<Vec<u8>>,
);

/// An account's seated seats in every stored group (the head's generation of each): where its
/// deletion, a ban or a seat-key rotation makes exits, with its groups' actors stopped or not.
pub async fn seats_of_account(
    store: &Store,
    account: &[u8; 16],
) -> Result<Vec<(String, Gen, Seat)>> {
    let rows: Vec<AccountSeatTuple> = db!(store, pool => {
        sqlx::query_as(
            "SELECT grp, gen, seat, dh, b, pool, seed, last_use, account FROM voipc_gk_seats s
             WHERE account = $1 AND b IS NOT NULL AND EXISTS (SELECT 1 FROM voipc_gk_lists l
               WHERE l.grp = s.grp AND l.gen = s.gen AND l.b = s.b AND l.current)",
        )
        .bind(&account[..])
        .fetch_all(pool)
        .await?
    });
    rows.into_iter()
        .map(|(grp, gen, seat, dh, b, pool, seed, last_use, account)| {
            let s = seat_of((seat, dh, b, pool, seed, last_use, account))?;
            Ok((grp, fixed(gen, "gen")?, s))
        })
        .collect()
}

/// The accounts seated in stored group `grp` now: by a seat in its log or by a live follow
/// alone, which no `voipc_members` row names (plan 2d: a gate or a new password takes both).
pub async fn seated_accounts(store: &Store, grp: &str) -> Result<Vec<[u8; 16]>> {
    let rows: Vec<Vec<u8>> = db!(store, pool => {
        sqlx::query_scalar(
            "SELECT DISTINCT account FROM voipc_gk_seats s
             WHERE grp = $1 AND account IS NOT NULL AND b IS NOT NULL AND EXISTS (SELECT 1 FROM voipc_gk_lists l
               WHERE l.grp = s.grp AND l.gen = s.gen AND l.b = s.b AND l.current)",
        )
        .bind(grp)
        .fetch_all(pool)
        .await?
    });
    rows.into_iter().map(|a| fixed(a, "account")).collect()
}

/// How many seats an account holds in any stored group, of any generation.
pub async fn seats_of(store: &Store, account: &[u8; 16]) -> Result<i64> {
    Ok(db!(store, pool => {
        sqlx::query_scalar("SELECT CAST(COUNT(*) AS BIGINT) FROM voipc_gk_seats WHERE account = $1")
            .bind(&account[..])
            .fetch_one(pool)
            .await?
    }))
}

/// A seat's last use, written by the caller at most once a day per seat.
pub async fn touch_seats(
    store: &Store,
    grp: &str,
    gen: &Gen,
    seats: &[SeatRec],
    at: u64,
) -> Result<()> {
    let at = count(at, "last_use")?;
    for batch in seats.chunks(STORE_BATCH) {
        write_tx!(store, tx => {
            for s in batch {
                sqlx::query("UPDATE voipc_gk_seats SET last_use = $1 WHERE grp = $2 AND gen = $3 AND seat = $4")
                    .bind(at)
                    .bind(grp)
                    .bind(&gen[..])
                    .bind(&s[..])
                    .execute(&mut *tx)
                    .await?;
            }
            tx.commit().await?;
        });
    }
    Ok(())
}

type ListTuple = (
    i64,
    i64,
    i16,
    Option<i64>,
    i64,
    i64,
    Option<i64>,
    Vec<u8>,
    Vec<u8>,
    bool,
);

fn list_of(t: ListTuple) -> Result<List> {
    let (b, v, pool, via, base_v, made, until, seats, digest, current) = t;
    Ok(List {
        b: unbits(b),
        v: unbits(v),
        pool: pool_of(pool)?,
        via: via.map(unbits),
        base_v: unbits(base_v),
        epoch_made: u32_of(made, "epoch_made")?,
        epoch_until: until.map(|u| u32_of(u, "epoch_until")).transpose()?,
        seats: records_of(&seats)?,
        digest: fixed(digest, "digest")?,
        current,
    })
}

/// The head's lists: one per bucket.
pub async fn current_lists(store: &Store, grp: &str, gen: &Gen) -> Result<Vec<List>> {
    let rows: Vec<ListTuple> = db!(store, pool => {
        sqlx::query_as(
            "SELECT b, v, pool, via, base_v, epoch_made, epoch_until, seats, digest, current FROM voipc_gk_lists
             WHERE (grp, gen, b, v) IN (SELECT grp, gen, b, v FROM voipc_gk_lists WHERE grp = $1 AND gen = $2 AND current = TRUE)",
        )
        .bind(grp)
        .bind(&gen[..])
        .fetch_all(pool)
        .await?
    });
    rows.into_iter().map(list_of).collect()
}

pub async fn list(store: &Store, grp: &str, gen: &Gen, b: u64, v: u64) -> Result<Option<List>> {
    let row: Option<ListTuple> = db!(store, pool => {
        sqlx::query_as(
            "SELECT b, v, pool, via, base_v, epoch_made, epoch_until, seats, digest, current FROM voipc_gk_lists l
             WHERE grp = $1 AND gen = $2 AND b = $3 AND v = $4
             AND NOT EXISTS (SELECT 1 FROM voipc_gk_pending p WHERE p.grp = l.grp AND p.commit_id = l.commit_id)",
        )
        .bind(grp)
        .bind(&gen[..])
        .bind(bits(b))
        .bind(bits(v))
        .fetch_optional(pool)
        .await?
    });
    row.map(list_of).transpose()
}

/// `lists_at`: the current lists (`voipc_gk_lists_current`), then those that ended after the
/// epoch (`voipc_gk_lists_until`), each found by key in its index first, never every list the
/// generation kept. A pending list is neither current nor ended.
#[cfg(test)]
const LISTS_AT: &str =
    "SELECT b, v, pool, via, base_v, epoch_made, epoch_until, seats, digest, current
     FROM voipc_gk_lists WHERE (grp, gen, b, v) IN
       (SELECT grp, gen, b, v FROM voipc_gk_lists WHERE grp = $1 AND gen = $2 AND current = TRUE)
     AND epoch_made <= $3
     UNION ALL
     SELECT b, v, pool, via, base_v, epoch_made, epoch_until, seats, digest, current
     FROM voipc_gk_lists WHERE (grp, gen, b, v) IN
       (SELECT grp, gen, b, v FROM voipc_gk_lists WHERE grp = $1 AND gen = $2
        AND epoch_until IS NOT NULL AND epoch_until > $3 AND epoch_made <= $3)";

/// The lists that were current at some point of `epoch`.
#[cfg(test)]
pub async fn lists_at(store: &Store, grp: &str, gen: &Gen, epoch: u32) -> Result<Vec<List>> {
    let rows: Vec<ListTuple> = db!(store, pool => {
        sqlx::query_as(LISTS_AT)
        .bind(grp)
        .bind(&gen[..])
        .bind(i64::from(epoch))
        .fetch_all(pool)
        .await?
    });
    rows.into_iter().map(list_of).collect()
}

type WelcomeTuple = (
    Vec<u8>,
    i16,
    i64,
    Option<i64>,
    Option<i64>,
    Vec<u8>,
    Vec<u8>,
    i64,
);

fn welcome_row(t: WelcomeTuple) -> Result<Welcome> {
    let (seat, kind, s, b, v, maker, bytes, made) = t;
    Ok(Welcome {
        seat: fixed(seat, "seat")?,
        kind: welcome_of(kind)?,
        s: u32_of(s, "s")?,
        version: b.zip(v).map(|(b, v)| (unbits(b), unbits(v))),
        maker: fixed(maker, "maker")?,
        bytes,
        made: u64_of(made, "made")?,
    })
}

pub async fn welcome(
    store: &Store,
    grp: &str,
    gen: &Gen,
    seat: &SeatRec,
    kind: WelcomeKind,
    s: u32,
) -> Result<Option<Welcome>> {
    let row: Option<WelcomeTuple> = db!(store, pool => {
        sqlx::query_as(
            "SELECT seat, kind, s, b, v, maker, bytes, made FROM voipc_gk_welcomes w
             WHERE grp = $1 AND gen = $2 AND seat = $3 AND kind = $4 AND s = $5
             AND NOT EXISTS (SELECT 1 FROM voipc_gk_pending p WHERE p.grp = w.grp AND p.commit_id = w.commit_id)",
        )
        .bind(grp)
        .bind(&gen[..])
        .bind(&seat[..])
        .bind(welcome_code(kind))
        .bind(i64::from(s))
        .fetch_optional(pool)
        .await?
    });
    row.map(welcome_row).transpose()
}

/// Every welcome waiting for a seat.
pub async fn welcomes_of(
    store: &Store,
    grp: &str,
    gen: &Gen,
    seat: &SeatRec,
) -> Result<Vec<Welcome>> {
    let rows: Vec<WelcomeTuple> = db!(store, pool => {
        sqlx::query_as(
            "SELECT seat, kind, s, b, v, maker, bytes, made FROM voipc_gk_welcomes w
             WHERE grp = $1 AND gen = $2 AND seat = $3
             AND NOT EXISTS (SELECT 1 FROM voipc_gk_pending p WHERE p.grp = w.grp AND p.commit_id = w.commit_id)",
        )
        .bind(grp)
        .bind(&gen[..])
        .bind(&seat[..])
        .fetch_all(pool)
        .await?
    });
    rows.into_iter().map(welcome_row).collect()
}

type RowTuple = (i64, i64, Vec<u8>, i64, Vec<u8>, Vec<u8>, i64);

/// A row is read only when the commit that wrote it owns its version's list and is no longer
/// pending: a stale attempt's row in a version its rebase took over is never read.
const ROWS_READ_BY_VERSION: &str = "SELECT r.b, r.v, r.seat, r.s, r.maker, r.bytes, r.epoch_made
     FROM voipc_gk_rows r JOIN voipc_gk_lists l
       ON l.grp = r.grp AND l.gen = r.gen AND l.b = r.b AND l.v = r.v AND l.commit_id = r.commit_id
     WHERE r.grp = $1 AND r.gen = $2 AND r.b = $3 AND r.v = $4 AND r.seat = $5
     AND NOT EXISTS (SELECT 1 FROM voipc_gk_pending p WHERE p.grp = r.grp AND p.commit_id = r.commit_id)";
const ROWS_READ_BY_SEAT: &str = "SELECT r.b, r.v, r.seat, r.s, r.maker, r.bytes, r.epoch_made
     FROM voipc_gk_rows r JOIN voipc_gk_lists l
       ON l.grp = r.grp AND l.gen = r.gen AND l.b = r.b AND l.v = r.v AND l.commit_id = r.commit_id
     WHERE (r.grp, r.gen, r.b, r.v, r.seat) IN
       (SELECT grp, gen, b, v, seat FROM voipc_gk_rows WHERE grp = $1 AND gen = $2 AND seat = $3)
     AND NOT EXISTS (SELECT 1 FROM voipc_gk_pending p WHERE p.grp = r.grp AND p.commit_id = r.commit_id)";

fn bucket_row(t: RowTuple) -> Result<BucketRow> {
    let (b, v, seat, s, maker, bytes, made) = t;
    Ok(BucketRow {
        b: unbits(b),
        v: unbits(v),
        seat: fixed(seat, "seat")?,
        s: u32_of(s, "s")?,
        maker: fixed(maker, "maker")?,
        bytes,
        epoch_made: u32_of(made, "epoch_made")?,
    })
}

pub async fn row(
    store: &Store,
    grp: &str,
    gen: &Gen,
    b: u64,
    v: u64,
    seat: &SeatRec,
) -> Result<Option<BucketRow>> {
    let row: Option<RowTuple> = db!(store, pool => {
        sqlx::query_as(ROWS_READ_BY_VERSION)
        .bind(grp)
        .bind(&gen[..])
        .bind(bits(b))
        .bind(bits(v))
        .bind(&seat[..])
        .fetch_optional(pool)
        .await?
    });
    row.map(bucket_row).transpose()
}

/// Every row to a seat in a generation: its versions, for `at` and rotation.
pub async fn rows_of_seat(
    store: &Store,
    grp: &str,
    gen: &Gen,
    seat: &SeatRec,
) -> Result<Vec<BucketRow>> {
    let rows: Vec<RowTuple> = db!(store, pool => {
        sqlx::query_as(ROWS_READ_BY_SEAT)
        .bind(grp)
        .bind(&gen[..])
        .bind(&seat[..])
        .fetch_all(pool)
        .await?
    });
    rows.into_iter().map(bucket_row).collect()
}

type SealTuple = (i64, i64, i64, Vec<u8>);

fn seal_of(t: SealTuple) -> Result<Seal> {
    Ok(Seal {
        epoch: u32_of(t.0, "epoch")?,
        b: unbits(t.1),
        v: unbits(t.2),
        bytes: t.3,
    })
}

/// An epoch's seals, one per version.
pub async fn seals(store: &Store, grp: &str, gen: &Gen, epoch: u32) -> Result<Vec<Seal>> {
    let rows: Vec<SealTuple> = db!(store, pool => {
        sqlx::query_as(
            "SELECT epoch, b, v, bytes FROM voipc_gk_seals s WHERE grp = $1 AND gen = $2 AND epoch = $3
             AND NOT EXISTS (SELECT 1 FROM voipc_gk_pending p WHERE p.grp = s.grp AND p.commit_id = s.commit_id)",
        )
        .bind(grp)
        .bind(&gen[..])
        .bind(i64::from(epoch))
        .fetch_all(pool)
        .await?
    });
    rows.into_iter().map(seal_of).collect()
}

pub async fn seal(
    store: &Store,
    grp: &str,
    gen: &Gen,
    epoch: u32,
    b: u64,
    v: u64,
) -> Result<Option<Seal>> {
    let row: Option<SealTuple> = db!(store, pool => {
        sqlx::query_as(
            "SELECT epoch, b, v, bytes FROM voipc_gk_seals s WHERE grp = $1 AND gen = $2 AND epoch = $3 AND b = $4 AND v = $5
             AND NOT EXISTS (SELECT 1 FROM voipc_gk_pending p WHERE p.grp = s.grp AND p.commit_id = s.commit_id)",
        )
        .bind(grp)
        .bind(&gen[..])
        .bind(i64::from(epoch))
        .bind(bits(b))
        .bind(bits(v))
        .fetch_optional(pool)
        .await?
    });
    row.map(seal_of).transpose()
}

/// An epoch's keyring pieces in stream order: the base, then each Join's delta.
pub async fn keyring(store: &Store, grp: &str, gen: &Gen, epoch: u32) -> Result<Vec<KeyringPiece>> {
    let rows: Vec<(i64, i64, Vec<u8>)> = db!(store, pool => {
        sqlx::query_as(
            "SELECT epoch, j, bytes FROM voipc_gk_keyring k WHERE grp = $1 AND gen = $2 AND epoch = $3
             AND NOT EXISTS (SELECT 1 FROM voipc_gk_pending p WHERE p.grp = k.grp AND p.commit_id = k.commit_id)",
        )
        .bind(grp)
        .bind(&gen[..])
        .bind(i64::from(epoch))
        .fetch_all(pool)
        .await?
    });
    let mut out = rows
        .into_iter()
        .map(|(e, j, bytes)| {
            Ok(KeyringPiece {
                epoch: u32_of(e, "epoch")?,
                j: u32_of(j, "j")?,
                bytes,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    out.sort_by_key(|p| p.j);
    Ok(out)
}

type KrkTuple = (i64, Vec<u8>, Vec<u8>, Vec<u8>);

fn krk_of(t: KrkTuple) -> Result<Krk> {
    Ok(Krk {
        epoch: u32_of(t.0, "epoch")?,
        holder: fixed(t.1, "holder")?,
        maker: fixed(t.2, "maker")?,
        bytes: t.3,
    })
}

pub async fn krk(
    store: &Store,
    grp: &str,
    gen: &Gen,
    epoch: u32,
    holder: &[u8; 32],
) -> Result<Option<Krk>> {
    let row: Option<KrkTuple> = db!(store, pool => {
        sqlx::query_as(
            "SELECT epoch, holder, maker, bytes FROM voipc_gk_krk k WHERE grp = $1 AND gen = $2 AND epoch = $3 AND holder = $4
             AND NOT EXISTS (SELECT 1 FROM voipc_gk_pending p WHERE p.grp = k.grp AND p.commit_id = k.commit_id)",
        )
        .bind(grp)
        .bind(&gen[..])
        .bind(i64::from(epoch))
        .bind(&holder[..])
        .fetch_optional(pool)
        .await?
    });
    row.map(krk_of).transpose()
}

#[cfg(test)]
pub async fn krks(store: &Store, grp: &str, gen: &Gen, epoch: u32) -> Result<Vec<Krk>> {
    let rows: Vec<KrkTuple> = db!(store, pool => {
        sqlx::query_as(
            "SELECT epoch, holder, maker, bytes FROM voipc_gk_krk k WHERE grp = $1 AND gen = $2 AND epoch = $3
             AND NOT EXISTS (SELECT 1 FROM voipc_gk_pending p WHERE p.grp = k.grp AND p.commit_id = k.commit_id)",
        )
        .bind(grp)
        .bind(&gen[..])
        .bind(i64::from(epoch))
        .fetch_all(pool)
        .await?
    });
    rows.into_iter().map(krk_of).collect()
}

// --- exits ---

/// Exits entering a batch, before `EpochExit` goes out; `exits_next` follows them.
pub async fn add_exits(store: &Store, grp: &str, exits: &[Exit]) -> Result<()> {
    let Some(top) = exits.iter().map(|e| e.seq).max() else {
        return Ok(());
    };
    let next = count(top.saturating_add(1), "exit seq")?;
    for batch in exits.chunks(STORE_BATCH) {
        write_tx!(store, tx => {
            for e in batch {
                sqlx::query(
                    "INSERT INTO voipc_gk_exits (grp, seq, gen, seat, cause, at) VALUES ($1, $2, $3, $4, $5, $6)
                     ON CONFLICT (grp, seq) DO NOTHING",
                )
                .bind(grp)
                .bind(count(e.seq, "exit seq")?)
                .bind(&e.gen[..])
                .bind(&e.seat[..])
                .bind(i16::from(e.cause))
                .bind(count(e.at, "exit time")?)
                .execute(&mut *tx)
                .await?;
            }
            let n = sqlx::query(
                "UPDATE voipc_gk_groups SET exits_next = CASE WHEN exits_next > $1 THEN exits_next ELSE $1 END WHERE grp = $2",
            )
            .bind(next)
            .bind(grp)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if n == 0 {
                bail!("exits in {grp}, which has no head");
            }
            tx.commit().await?;
        });
    }
    Ok(())
}

/// Exits that no longer stand (the seat came back before its batch closed).
#[cfg(test)]
pub async fn drop_exits(store: &Store, grp: &str, seqs: &[u64]) -> Result<()> {
    for batch in seqs.chunks(STORE_BATCH) {
        write_tx!(store, tx => {
            for s in batch {
                sqlx::query("DELETE FROM voipc_gk_exits WHERE grp = $1 AND seq = $2")
                    .bind(grp)
                    .bind(count(*s, "exit seq")?)
                    .execute(&mut *tx)
                    .await?;
            }
            tx.commit().await?;
        });
    }
    Ok(())
}

type ExitTuple = (i64, Vec<u8>, Vec<u8>, i16, i64);

/// The exits no head dealt with yet, by `seq`.
pub async fn exits(store: &Store, grp: &str) -> Result<Vec<Exit>> {
    let rows: Vec<ExitTuple> = db!(store, pool => {
        sqlx::query_as("SELECT seq, gen, seat, cause, at FROM voipc_gk_exits WHERE grp = $1")
            .bind(grp)
            .fetch_all(pool)
            .await?
    });
    let mut out = rows
        .into_iter()
        .map(|(seq, gen, seat, cause, at)| {
            Ok(Exit {
                seq: u64_of(seq, "seq")?,
                gen: fixed(gen, "gen")?,
                seat: fixed(seat, "seat")?,
                cause: u8_of(cause, "cause")?,
                at: u64_of(at, "at")?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    out.sort_by_key(|e| e.seq);
    Ok(out)
}

// --- keyholders ---

type HolderTuple = (
    Vec<u8>,
    Vec<u8>,
    Option<Vec<u8>>,
    i16,
    i64,
    Vec<u8>,
    Option<Vec<u8>>,
);
type GrpHolderTuple = (
    String,
    Vec<u8>,
    Vec<u8>,
    Option<Vec<u8>>,
    i16,
    i64,
    Vec<u8>,
    Option<Vec<u8>>,
);
fn holder_of(t: HolderTuple) -> Result<Holder> {
    let (kx, m, device, rank, last_online, missed, pair) = t;
    Ok(Holder {
        kx: fixed(kx, "kx")?,
        m: fixed(m, "m")?,
        device,
        rank: u8_of(rank, "rank")?,
        last_online: u64_of(last_online, "last_online")?,
        missed: postcard_of(&missed, "missed")?,
        pair: pair.map(|p| postcard_of(&p, "pair")).transpose()?,
    })
}

/// A keyholder entry, written whole.
#[cfg(test)]
pub async fn put_holder(store: &Store, grp: &str, h: &Holder) -> Result<()> {
    let missed = postcard::to_allocvec(&h.missed)?;
    let pair = h.pair.as_ref().map(postcard::to_allocvec).transpose()?;
    let last_online = count(h.last_online, "last_online")?;
    db!(store, pool => {
        sqlx::query(
            "INSERT INTO voipc_gk_holders (grp, kx, m, device, rank, last_online, missed, pair) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             ON CONFLICT (grp, kx) DO UPDATE SET m = excluded.m, device = excluded.device, rank = excluded.rank,
             last_online = excluded.last_online, missed = excluded.missed, pair = excluded.pair",
        )
        .bind(grp)
        .bind(&h.kx[..])
        .bind(&h.m[..])
        .bind(h.device.as_deref())
        .bind(i16::from(h.rank))
        .bind(last_online)
        .bind(missed.as_slice())
        .bind(pair.as_deref())
        .execute(pool)
        .await?;
    });
    Ok(())
}

/// When it was last online and what it missed, on its own.
#[cfg(test)]
pub async fn set_holder_seen(
    store: &Store,
    grp: &str,
    kx: &[u8; 32],
    last_online: u64,
    missed: &Misses,
) -> Result<bool> {
    let missed = postcard::to_allocvec(missed)?;
    let last_online = count(last_online, "last_online")?;
    Ok(db!(store, pool => {
        sqlx::query("UPDATE voipc_gk_holders SET last_online = $1, missed = $2 WHERE grp = $3 AND kx = $4")
            .bind(last_online)
            .bind(missed.as_slice())
            .bind(grp)
            .bind(&kx[..])
            .execute(pool)
            .await?
            .rows_affected()
            == 1
    }))
}

pub async fn drop_holder(store: &Store, grp: &str, kx: &[u8; 32]) -> Result<bool> {
    Ok(db!(store, pool => {
        sqlx::query("DELETE FROM voipc_gk_holders WHERE grp = $1 AND kx = $2")
            .bind(grp)
            .bind(&kx[..])
            .execute(pool)
            .await?
            .rows_affected()
            == 1
    }))
}

pub async fn holders(store: &Store, grp: &str) -> Result<Vec<Holder>> {
    let rows: Vec<HolderTuple> = db!(store, pool => {
        sqlx::query_as("SELECT kx, m, device, rank, last_online, missed, pair FROM voipc_gk_holders WHERE grp = $1")
            .bind(grp)
            .fetch_all(pool)
            .await?
    });
    rows.into_iter().map(holder_of).collect()
}

/// A member's keyholder entries in every group, or only one device's: a rotation's
/// `KeyholdReplace`, a device removed from its account.
pub async fn holders_of(
    store: &Store,
    m: &MemberRec,
    device: Option<&[u8]>,
) -> Result<Vec<(String, Holder)>> {
    let rows: Vec<GrpHolderTuple> = db!(store, pool => {
        match device {
            Some(d) => sqlx::query_as(
                "SELECT grp, kx, m, device, rank, last_online, missed, pair FROM voipc_gk_holders WHERE m = $1 AND device = $2",
            )
            .bind(&m[..])
            .bind(d)
            .fetch_all(pool)
            .await?,
            None => sqlx::query_as(
                "SELECT grp, kx, m, device, rank, last_online, missed, pair FROM voipc_gk_holders WHERE m = $1",
            )
            .bind(&m[..])
            .fetch_all(pool)
            .await?,
        }
    });
    rows.into_iter()
        .map(|(grp, kx, m, device, rank, last_online, missed, pair)| {
            Ok((
                grp,
                holder_of((kx, m, device, rank, last_online, missed, pair))?,
            ))
        })
        .collect()
}

// --- names (gated groups) ---

type NamesTuple = (i64, i64, i16, i64, Vec<u8>, Vec<u8>);

/// Names from `from` to `to` (each `(epoch, j)`, both in), in order.
pub async fn names(
    store: &Store,
    grp: &str,
    gen: &Gen,
    from: (u32, u32),
    to: (u32, u32),
) -> Result<Vec<Names>> {
    let rows: Vec<NamesTuple> = db!(store, pool => {
        sqlx::query_as(
            "SELECT epoch, j, kind, time, names_hash, list FROM voipc_gk_names
             WHERE grp = $1 AND gen = $2 AND epoch >= $3 AND epoch <= $4",
        )
        .bind(grp)
        .bind(&gen[..])
        .bind(i64::from(from.0))
        .bind(i64::from(to.0))
        .fetch_all(pool)
        .await?
    });
    let mut out = Vec::new();
    for (epoch, j, kind, time, hash, list) in rows {
        let n = Names {
            gen: *gen,
            epoch: u32_of(epoch, "epoch")?,
            j: u32_of(j, "j")?,
            kind: u8_of(kind, "kind")?,
            time: u64_of(time, "time")?,
            names_hash: fixed(hash, "names_hash")?,
            list,
        };
        if (n.epoch, n.j) >= from && (n.epoch, n.j) <= to {
            out.push(n);
        }
    }
    out.sort_by_key(|n| (n.epoch, n.j, n.kind));
    Ok(out)
}

/// Names outside a head move: the step before the oldest kept, written before `sweep_names`.
pub async fn put_names(store: &Store, grp: &str, names: &[Names]) -> Result<()> {
    write_tx!(store, tx => {
        for n in names {
            sqlx::query(
                "INSERT INTO voipc_gk_names (grp, gen, epoch, j, kind, time, names_hash, list) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                 ON CONFLICT (grp, gen, epoch, j, kind) DO UPDATE SET time = excluded.time, names_hash = excluded.names_hash,
                 list = excluded.list",
            )
            .bind(grp)
            .bind(&n.gen[..])
            .bind(i64::from(n.epoch))
            .bind(i64::from(n.j))
            .bind(i16::from(n.kind))
            .bind(count(n.time, "names time")?)
            .bind(&n.names_hash[..])
            .bind(n.list.as_slice())
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
    });
    Ok(())
}

/// Every name of the generation before `below` (`(epoch, j)`), steps included, and every name
/// of other generations; the count taken. The step at `below` stays.
pub async fn sweep_names(store: &Store, grp: &str, gen: &Gen, below: (u32, u32)) -> Result<u64> {
    let gen = gen.to_vec();
    Ok(in_batches!(
        store,
        "DELETE FROM voipc_gk_names WHERE (grp, gen, epoch, j, kind) IN
         (SELECT grp, gen, epoch, j, kind FROM voipc_gk_names WHERE grp = $1
          AND (gen <> $2 OR epoch < $3 OR (epoch = $3 AND j < $4)) LIMIT $5)",
        grp,
        gen.as_slice(),
        i64::from(below.0),
        i64::from(below.1)
    ))
}

// --- seat keys (§5.11) ---

type SeatKeysTuple = (i64, Vec<u8>, Vec<u8>, i64, Vec<u8>, i64);

fn seat_keys_of(t: SeatKeysTuple) -> Result<SeatKeys> {
    let (n, kem, dh, made, sig, published) = t;
    Ok(SeatKeys {
        n: u32_of(n, "n")?,
        kem,
        dh,
        made: u64_of(made, "made")?,
        sig,
        published: u64_of(published, "published")?,
    })
}

/// New seat keys, current from now on. `false`: their counter is not above every earlier one
/// of the account, so they are refused (old keys offered again).
pub async fn put_seat_keys(store: &Store, account: &[u8; 16], k: &SeatKeys) -> Result<bool> {
    let made = count(k.made, "made")?;
    let published = count(k.published, "published")?;
    Ok(write_tx!(store, tx => {
        // Postgres: one publish per account at a time, so the check below sees the other's row
        // (SQLite's write lock, taken at BEGIN, does this)
        if matches!(store, Store::Pg(_)) {
            let key = i32::from_be_bytes([account[0], account[1], account[2], account[3]]);
            sqlx::query("SELECT pg_advisory_xact_lock($1, $2)")
                .bind(SEAT_KEYS_LOCK)
                .bind(key)
                .execute(&mut *tx)
                .await?;
        }
        let top: Option<i64> = sqlx::query_scalar("SELECT MAX(n) FROM voipc_gk_seatkeys WHERE account = $1")
            .bind(&account[..])
            .fetch_one(&mut *tx)
            .await?;
        if top.is_some_and(|t| t >= i64::from(k.n)) {
            return Ok(false);
        }
        sqlx::query("UPDATE voipc_gk_seatkeys SET current = FALSE WHERE account = $1 AND current")
            .bind(&account[..])
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO voipc_gk_seatkeys (account, n, kem, dh, made, sig, published, current) VALUES ($1, $2, $3, $4, $5, $6, $7, TRUE)",
        )
        .bind(&account[..])
        .bind(i64::from(k.n))
        .bind(k.kem.as_slice())
        .bind(k.dh.as_slice())
        .bind(made)
        .bind(k.sig.as_slice())
        .bind(published)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        true
    }))
}

/// The account's current seat keys.
pub async fn seat_keys(store: &Store, account: &[u8; 16]) -> Result<Option<SeatKeys>> {
    let row: Option<SeatKeysTuple> = db!(store, pool => {
        sqlx::query_as("SELECT n, kem, dh, made, sig, published FROM voipc_gk_seatkeys WHERE account = $1 AND current")
            .bind(&account[..])
            .fetch_optional(pool)
            .await?
    });
    row.map(seat_keys_of).transpose()
}

#[cfg(test)]
pub async fn seat_keys_at(store: &Store, account: &[u8; 16], n: u32) -> Result<Option<SeatKeys>> {
    let row: Option<SeatKeysTuple> = db!(store, pool => {
        sqlx::query_as("SELECT n, kem, dh, made, sig, published FROM voipc_gk_seatkeys WHERE account = $1 AND n = $2")
            .bind(&account[..])
            .bind(i64::from(n))
            .fetch_optional(pool)
            .await?
    });
    row.map(seat_keys_of).transpose()
}

#[cfg(test)]
pub async fn drop_seat_keys(store: &Store, account: &[u8; 16]) -> Result<u64> {
    Ok(db!(store, pool => {
        sqlx::query("DELETE FROM voipc_gk_seatkeys WHERE account = $1")
            .bind(&account[..])
            .execute(pool)
            .await?
            .rows_affected()
    }))
}

#[cfg(test)]
type MemberKeysTuple = (Vec<u8>, i64, Vec<u8>, Vec<u8>, i64, Vec<u8>, i64);

/// A page of the accounts keeping `conv`'s log that have current seat keys, after `after`, by
/// account id: the eager seats of a new generation (plan 2d).
#[cfg(test)]
pub async fn members_with_seat_keys(
    store: &Store,
    conv: &str,
    after: Option<&[u8; 16]>,
    limit: u32,
) -> Result<Vec<([u8; 16], SeatKeys)>> {
    let rows: Vec<MemberKeysTuple> = db!(store, pool => {
        sqlx::query_as(
            "SELECT k.account, k.n, k.kem, k.dh, k.made, k.sig, k.published
             FROM voipc_members m JOIN voipc_gk_seatkeys k ON k.account = m.account AND k.current
             WHERE m.conv = $1 AND m.account > $2 ORDER BY m.account LIMIT $3",
        )
        .bind(conv)
        .bind(after.map_or(&[][..], |a| &a[..]))
        .bind(i64::from(limit))
        .fetch_all(pool)
        .await?
    });
    rows.into_iter()
        .map(|(a, n, kem, dh, made, sig, published)| {
            Ok((
                fixed(a, "account")?,
                seat_keys_of((n, kem, dh, made, sig, published))?,
            ))
        })
        .collect()
}

// --- an account's own rows (C4, §3.11) ---

/// An account's self-rows and history rows, each kept only for a stored group where the
/// account holds or held that seat under that seed or a later one (its seat, or a row to it),
/// in place of one of the same `(group, gen, seed, seat, kind)`: so at most one each. One
/// already kept is replaced whatever became of its seat: a rotation seals every row
/// `SelfRowsList` gave again, those of seats gone since too. The count kept, replaced ones
/// included (what the app takes as "all stored").
pub async fn put_self_rows(store: &Store, account: &[u8; 16], rows: &[SelfRowIn]) -> Result<u32> {
    let mut kept = 0;
    for r in rows {
        if r.check().is_err() || !r.group.starts_with("c:") {
            continue;
        }
        let replaced = db!(store, pool => {
            sqlx::query(
                "UPDATE voipc_gk_self SET sealed = $1 WHERE grp = $2 AND account = $3 AND gen = $4
                 AND seed = $5 AND tag_sk = $6 AND tag_sx = $7 AND kind = $8",
            )
            .bind(r.sealed.as_slice())
            .bind(&r.group)
            .bind(&account[..])
            .bind(&r.gen[..])
            .bind(i64::from(r.seed))
            .bind(&r.sk[..])
            .bind(&r.sx[..])
            .bind(i16::from(r.kind))
            .execute(pool)
            .await?
            .rows_affected()
        });
        if replaced > 0 {
            kept += 1;
            continue;
        }
        let seat = seat_record(&SeatRef {
            m: MemberId::Account(*account),
            tag_sk: r.sk,
            tag_sx: r.sx,
        });
        let held: Option<i64> = db!(store, pool => {
            sqlx::query_scalar(
                "SELECT CAST(1 AS BIGINT) FROM voipc_gk_seats WHERE grp = $1 AND gen = $2 AND seat = $3 AND seed >= $4
                 UNION ALL SELECT CAST(1 AS BIGINT) FROM voipc_gk_rows WHERE grp = $1 AND gen = $2 AND seat = $3 AND s >= $4
                 LIMIT 1",
            )
            .bind(&r.group)
            .bind(&r.gen[..])
            .bind(&seat[..])
            .bind(i64::from(r.seed))
            .fetch_optional(pool)
            .await?
        });
        if held.is_none() {
            continue;
        }
        db!(store, pool => {
            sqlx::query(
                "INSERT INTO voipc_gk_self (grp, account, gen, seed, tag_sk, tag_sx, kind, sealed) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                 ON CONFLICT (grp, account, gen, seed, tag_sk, tag_sx, kind) DO UPDATE SET sealed = excluded.sealed",
            )
            .bind(&r.group)
            .bind(&account[..])
            .bind(&r.gen[..])
            .bind(i64::from(r.seed))
            .bind(&r.sk[..])
            .bind(&r.sx[..])
            .bind(i16::from(r.kind))
            .bind(r.sealed.as_slice())
            .execute(pool)
            .await?;
        });
        kept += 1;
    }
    Ok(kept)
}

/// What an account's identity endorsed, gone (an identity reset, a deleted account's
/// tombstone): its seat keys and its self-rows. No foreign key takes these (plan 2g). Its
/// seats go by their groups' exits, and its keyholder entries by their groups' Removes: the
/// signed head names them, and their rows tell `Groups::on_account_gone` (in this process or,
/// after the shell's reset, the relay's) where they are; each goes once its Remove lands.
pub async fn forget_account(store: &Store, account: &[u8; 16]) -> Result<()> {
    write_tx!(store, tx => {
        sqlx::query("DELETE FROM voipc_gk_seatkeys WHERE account = $1").bind(&account[..]).execute(&mut *tx).await?;
        sqlx::query("DELETE FROM voipc_gk_self WHERE account = $1").bind(&account[..]).execute(&mut *tx).await?;
        tx.commit().await?;
    });
    Ok(())
}

// --- load ---

/// The bytes a group keeps in the database's big tables, for AdminLoad.
pub async fn stored_bytes(store: &Store, grp: &str) -> Result<u64> {
    let mut total = 0i64;
    for q in [
        "SELECT CAST(COALESCE(SUM(LENGTH(bytes) + LENGTH(maker)), 0) AS BIGINT) FROM voipc_gk_rows WHERE grp = $1",
        "SELECT CAST(COALESCE(SUM(LENGTH(bytes) + LENGTH(maker)), 0) AS BIGINT) FROM voipc_gk_welcomes WHERE grp = $1",
        "SELECT CAST(COALESCE(SUM(LENGTH(bytes)), 0) AS BIGINT) FROM voipc_gk_seals WHERE grp = $1",
        "SELECT CAST(COALESCE(SUM(LENGTH(bytes)), 0) AS BIGINT) FROM voipc_gk_keyring WHERE grp = $1",
        "SELECT CAST(COALESCE(SUM(LENGTH(bytes)), 0) AS BIGINT) FROM voipc_gk_krk WHERE grp = $1",
        "SELECT CAST(COALESCE(SUM(LENGTH(seats)), 0) AS BIGINT) FROM voipc_gk_lists WHERE grp = $1",
        "SELECT CAST(COALESCE(SUM(LENGTH(body) + LENGTH(sig)), 0) AS BIGINT) FROM voipc_gk_headers WHERE grp = $1",
        "SELECT CAST(COALESCE(SUM(LENGTH(list)), 0) AS BIGINT) FROM voipc_gk_names WHERE grp = $1",
    ] {
        let n: i64 = db!(store, pool => {
            sqlx::query_scalar(q).bind(grp).fetch_one(pool).await?
        });
        total += n;
    }
    u64_of(total, "stored bytes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::Relay;
    use crate::config::{AccountsConfig, AccountsMode};
    use l4f_accounts::model::{AccountId, NewUser};

    /// New databases: a SQLite file, and with `VOIPC_TEST_POSTGRES` also one on that server, a
    /// throwaway (`postgres://user@host:port/postgres`).
    struct Databases {
        stores: Vec<Store>,
        file: std::path::PathBuf,
        id: u32,
    }

    impl Drop for Databases {
        fn drop(&mut self) {
            for suffix in ["", "-wal", "-shm", ".lock"] {
                let _ = std::fs::remove_file(format!("{}{suffix}", self.file.display()));
            }
            crate::gk_e2e_tests::drop_pg(&format!("voipc_gk_{:08x}", self.id));
        }
    }

    async fn databases() -> Databases {
        let id = rand::random::<u32>();
        let file = std::env::temp_dir().join(format!("voipc-gk-{id:08x}.db"));
        let url = format!("sqlite://{}?mode=rwc", file.display());
        let mut stores = vec![Store::connect(&url).await.unwrap()];
        if let Ok(server) = std::env::var("VOIPC_TEST_POSTGRES") {
            let name = format!("voipc_gk_{id:08x}");
            let admin = Store::connect(&server).await.unwrap();
            db!(&admin, pool => {
                sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
                    .execute(pool)
                    .await
                    .unwrap();
            });
            let (base, _) = server.rsplit_once('/').unwrap();
            stores.push(Store::connect(&format!("{base}/{name}")).await.unwrap());
        }
        Databases { stores, file, id }
    }

    /// The relay's bookkeeping, as `migrate_relay` keeps it.
    fn relay_migrator(mut m: sqlx::migrate::Migrator) -> sqlx::migrate::Migrator {
        m.dangerous_set_table_name("voipc_migrations");
        m.set_locking(false);
        m
    }

    async fn open(store: &Store) -> Relay {
        let cfg = AccountsConfig {
            mode: AccountsMode::Optional,
            ..Default::default()
        };
        Relay::open_with(&cfg, store.clone(), &[9u8; 32])
            .await
            .unwrap()
    }

    async fn scalar(store: &Store, sql: &'static str) -> i64 {
        db!(store, pool => {
            sqlx::query_scalar::<_, i64>(sql).fetch_one(pool).await.unwrap()
        })
    }

    async fn account(store: &Store, name: &str) -> [u8; 16] {
        let id = AccountId::new();
        let new = NewUser {
            id,
            username: name.into(),
            display_name: name.into(),
            email_pending: None,
            password_hash: None,
            created_at: l4f_accounts::util::now(),
        };
        store.create_user(&new, None).await.unwrap();
        id.0
    }

    const GRP: &str = "c:general";
    const GEN: Gen = [1; 16];
    const GEN2: Gen = [2; 16];
    /// Ids past i64::MAX, which go in by their bits.
    const B1: u64 = u64::MAX - 1;
    const B2: u64 = 1 << 63;
    const V1: u64 = u64::MAX;
    const V2: u64 = (1 << 63) | 5;
    const V3: u64 = 3;

    fn rec(i: u16) -> SeatRec {
        let mut r = [0u8; 33];
        r[0] = 1;
        r[1..3].copy_from_slice(&i.to_be_bytes());
        r[17] = 0xaa;
        r
    }

    fn maker() -> Maker {
        [7; 49]
    }

    fn new_seat(i: u16, b: u64) -> Seat {
        let mut dh = [5u8; 33];
        dh[1..3].copy_from_slice(&i.to_be_bytes());
        Seat {
            seat: rec(i),
            dh,
            b,
            pool: Pool::Accounts,
            seed: 1,
            last_use: 1000,
            account: Some([i as u8; 16]),
        }
    }

    fn version(b: u64, v: u64, epoch: u32, seats: &[SeatRec]) -> List {
        List {
            b,
            v,
            pool: Pool::Accounts,
            via: None,
            base_v: v,
            epoch_made: epoch,
            epoch_until: None,
            seats: seats.to_vec(),
            digest: [v as u8; 32],
            current: false,
        }
    }

    fn row_to(b: u64, v: u64, seat: SeatRec, epoch: u32) -> BucketRow {
        BucketRow {
            b,
            v,
            seat,
            s: 1,
            maker: maker(),
            bytes: vec![0x60; 60],
            epoch_made: epoch,
        }
    }

    fn seat_welcome(seat: SeatRec, b: u64, v: u64) -> Welcome {
        Welcome {
            seat,
            kind: WelcomeKind::Seat,
            s: 1,
            version: Some((b, v)),
            maker: maker(),
            bytes: vec![0x17; 1694],
            made: 5,
        }
    }

    fn header_at(d: u8, gen: Gen, epoch: u32, j: u32, kind: Kind) -> Header {
        Header {
            d: [d; 32],
            gen,
            epoch,
            j,
            kind,
            time: 1_800_000_000 + u64::from(d),
            body: vec![d; 383],
            sig: vec![d; 64],
            keep: 1,
        }
    }

    fn head(d: u8, gen: Gen, epoch: u32, join: u32) -> Head {
        Head {
            kind: GroupKind::Text,
            gen,
            gen_time: 1_800_000_000,
            incarnation: [3; 16],
            d: [d; 32],
            epoch,
            join,
            exits_next: 1,
            rolls: SeedRolls {
                raised: 1_800_000_000,
                removal: false,
            },
            gated: false,
        }
    }

    /// A Genesis by seat 1 with `others` seated beside it in bucket B1: head `[1; 32]`.
    async fn genesis(store: &Store, others: &[u16]) -> CommitId {
        let mut members = vec![rec(1)];
        members.extend(others.iter().map(|i| rec(*i)));
        let c = begin_commit(store, GRP).await.unwrap();
        assert_eq!(
            put_vids(store, GRP, c, &GEN, &[(B1, V1)]).await.unwrap(),
            None
        );
        let made = put_lists(store, GRP, c, &GEN, &[version(B1, V1, 1, &members)]).await;
        assert_eq!(made.unwrap(), None);
        let seats: Vec<Seat> = members
            .iter()
            .map(|r| new_seat(u16::from_be_bytes([r[1], r[2]]), B1))
            .collect();
        put_new_seats(store, GRP, c, &GEN, &seats).await.unwrap();
        let rows: Vec<BucketRow> = members.iter().map(|r| row_to(B1, V1, *r, 1)).collect();
        put_rows(store, GRP, c, &GEN, &rows).await.unwrap();
        put_welcomes(store, GRP, c, &GEN, &[seat_welcome(rec(1), B1, V1)])
            .await
            .unwrap();
        let seal = Seal {
            epoch: 1,
            b: B1,
            v: V1,
            bytes: vec![0x5e; 60],
        };
        put_seals(store, GRP, c, &GEN, &[seal]).await.unwrap();
        let base = KeyringPiece {
            epoch: 1,
            j: 0,
            bytes: vec![0x4b; 147],
        };
        put_keyring(store, GRP, c, &GEN, &[base]).await.unwrap();
        let k = Krk {
            epoch: 1,
            holder: [0x11; 32],
            maker: maker(),
            bytes: vec![0x4b; 1662],
        };
        put_krk(store, GRP, c, &GEN, &[k]).await.unwrap();
        let hs = [header_at(1, GEN, 1, 0, Kind::Genesis)];
        let mv = HeadMove {
            headers: &hs,
            ..Default::default()
        };
        let moved = move_head(store, GRP, c, &head(1, GEN, 1, 0), &mv)
            .await
            .unwrap();
        assert_eq!(moved, Moved::Done);
        c
    }

    /// An opening commit over `was` that re-versions B1 to `v` with `members`.
    async fn open_epoch(
        store: &Store,
        was: u8,
        d: u8,
        epoch: u32,
        v: u64,
        members: &[SeatRec],
        mv: HeadMove<'_>,
    ) -> Moved {
        let c = begin_commit(store, GRP).await.unwrap();
        assert_eq!(
            put_vids(store, GRP, c, &GEN, &[(B1, v)]).await.unwrap(),
            None
        );
        let made = put_lists(store, GRP, c, &GEN, &[version(B1, v, epoch, members)]).await;
        assert_eq!(made.unwrap(), None);
        let hs = [header_at(d, GEN, epoch, 0, Kind::Fresh)];
        let mv = HeadMove {
            was: Some([was; 32]),
            headers: &hs,
            ..mv
        };
        move_head(store, GRP, c, &head(d, GEN, epoch, 0), &mv)
            .await
            .unwrap()
    }

    async fn pending(store: &Store) -> i64 {
        scalar(store, "SELECT COUNT(*) FROM voipc_gk_pending").await
    }

    #[tokio::test]
    async fn migration_13_comes_once_on_top_of_todays_head() {
        // Renumber when another migration lands first (plan, open choice 20)
        let head = sqlx::migrate!("migrations/sqlite")
            .iter()
            .map(|m| m.version)
            .max();
        assert_eq!(head, Some(13));
        let dbs = databases().await;
        for store in &dbs.stores {
            // As 1.12.0 left it, then a start of this build, then another start
            l4f_accounts::migrate::run(store).await.unwrap();
            let shipped = relay_migrator(match store {
                Store::Pg(_) => sqlx::migrate!("migrations/postgres"),
                Store::Lite(_) => sqlx::migrate!("migrations/sqlite"),
            });
            match store {
                Store::Pg(b) => shipped.run_to(12, &b.0).await,
                Store::Lite(b) => shipped.run_to(12, &b.0).await,
            }
            .unwrap();
            let before = "SELECT MAX(version) FROM voipc_migrations";
            assert_eq!(scalar(store, before).await, 12);
            open(store).await;
            open(store).await;
            assert_eq!(scalar(store, before).await, 13);
            assert_eq!(
                scalar(
                    store,
                    "SELECT COUNT(*) FROM voipc_migrations WHERE version = 13"
                )
                .await,
                1
            );
            for t in [
                "SELECT COUNT(*) FROM voipc_gk_groups",
                "SELECT COUNT(*) FROM voipc_gk_gens",
                "SELECT COUNT(*) FROM voipc_gk_headers",
                "SELECT COUNT(*) FROM voipc_gk_seats",
                "SELECT COUNT(*) FROM voipc_gk_lists",
                "SELECT COUNT(*) FROM voipc_gk_vids",
                "SELECT COUNT(*) FROM voipc_gk_names",
                "SELECT COUNT(*) FROM voipc_gk_welcomes",
                "SELECT COUNT(*) FROM voipc_gk_rows",
                "SELECT COUNT(*) FROM voipc_gk_seals",
                "SELECT COUNT(*) FROM voipc_gk_keyring",
                "SELECT COUNT(*) FROM voipc_gk_krk",
                "SELECT COUNT(*) FROM voipc_gk_pending",
                "SELECT COUNT(*) FROM voipc_gk_exits",
                "SELECT COUNT(*) FROM voipc_gk_holders",
                "SELECT COUNT(*) FROM voipc_gk_chains",
                "SELECT COUNT(*) FROM voipc_gk_self",
                "SELECT COUNT(*) FROM voipc_gk_seatkeys",
            ] {
                assert_eq!(scalar(store, t).await, 0, "{t}");
            }
        }
    }

    #[tokio::test]
    async fn an_upgraded_database_keeps_its_rows_and_its_chains_take_group_keys() {
        let dbs = databases().await;
        for store in &dbs.stores {
            // As 1.11.0 left it: the kept log of 0010, a writer with one chain
            l4f_accounts::migrate::run(store).await.unwrap();
            let shipped = relay_migrator(match store {
                Store::Pg(_) => sqlx::migrate!("migrations/postgres"),
                Store::Lite(_) => sqlx::migrate!("migrations/sqlite"),
            });
            match store {
                Store::Pg(b) => shipped.run_to(10, &b.0).await,
                Store::Lite(b) => shipped.run_to(10, &b.0).await,
            }
            .unwrap();
            let ann = account(store, "ann").await;
            let chain: i32 = db!(store, pool => {
                let writer: i32 = sqlx::query_scalar("INSERT INTO voipc_writers (conv, owner) VALUES ($1, $2) RETURNING id")
                    .bind(GRP)
                    .bind(&ann[..])
                    .fetch_one(pool)
                    .await
                    .unwrap();
                sqlx::query_scalar(
                    "INSERT INTO voipc_chains (writer, chain, top, self_wrap, created_at) VALUES ($1, 1, 0, $2, 0) RETURNING id",
                )
                .bind(writer)
                .bind(&[1u8; 40][..])
                .fetch_one(pool)
                .await
                .unwrap()
            });
            // Then every release to today's head, 0013 included
            open(store).await;
            assert_eq!(scalar(store, "SELECT COUNT(*) FROM voipc_chains").await, 1);
            assert_eq!(scalar(store, "SELECT COUNT(*) FROM voipc_writers").await, 1);
            db!(store, pool => {
                sqlx::query("INSERT INTO voipc_gk_chains (chain_id, grp, gen, epoch, idx, sealed) VALUES ($1, $2, $3, 4, 0, $4)")
                    .bind(chain)
                    .bind(GRP)
                    .bind(&GEN[..])
                    .bind(&[2u8; 80][..])
                    .execute(pool)
                    .await
                    .unwrap();
            });
            let keys = SeatKeys {
                n: 1,
                kem: vec![1; 1569],
                dh: vec![2; 33],
                made: 10,
                sig: vec![3; 64],
                published: 11,
            };
            assert!(put_seat_keys(store, &ann, &keys).await.unwrap());
            // A gk chain goes with its chain, seat keys with their account
            db!(store, pool => {
                sqlx::query("DELETE FROM voipc_chains WHERE id = $1").bind(chain).execute(pool).await.unwrap();
                sqlx::query("DELETE FROM acct_users WHERE id = $1").bind(&ann[..]).execute(pool).await.unwrap();
            });
            assert_eq!(
                scalar(store, "SELECT COUNT(*) FROM voipc_gk_chains").await,
                0
            );
            assert_eq!(
                scalar(store, "SELECT COUNT(*) FROM voipc_gk_seatkeys").await,
                0
            );
        }
    }

    #[tokio::test]
    async fn the_switch_and_restores_decide_the_incarnation() {
        let dbs = databases().await;
        for store in &dbs.stores {
            open(store).await;
            assert_eq!(gk_incarnation(store).await.unwrap(), None);
            assert_eq!(gk_switch(store).await.unwrap(), None);
            // Off: nothing made
            assert_eq!(gk_start(store, false).await.unwrap(), None);
            assert_eq!(gk_switch(store).await.unwrap(), Some(false));
            assert_eq!(gk_incarnation(store).await.unwrap(), None);
            // The first start with it on makes one, which the next keeps
            let a = gk_start(store, true).await.unwrap().unwrap();
            assert_eq!(gk_switch(store).await.unwrap(), Some(true));
            assert_eq!(gk_start(store, true).await.unwrap(), Some(a));
            // Off keeps it; back on is a new one (exits of the off run reached nobody)
            assert_eq!(gk_start(store, false).await.unwrap(), None);
            assert_eq!(gk_incarnation(store).await.unwrap(), Some(a));
            let b = gk_start(store, true).await.unwrap().unwrap();
            assert_ne!(a, b);
            // A restore's command
            let c = new_incarnation(store).await.unwrap();
            assert_ne!(b, c);
            assert_eq!(gk_start(store, true).await.unwrap(), Some(c));
        }
    }

    #[tokio::test]
    async fn a_commit_is_read_only_once_its_head_moved() {
        let dbs = databases().await;
        for store in &dbs.stores {
            open(store).await;
            let c = begin_commit(store, GRP).await.unwrap();
            assert_eq!(
                put_vids(store, GRP, c, &GEN, &[(B1, V1)]).await.unwrap(),
                None
            );
            let made = put_lists(store, GRP, c, &GEN, &[version(B1, V1, 1, &[rec(1)])]).await;
            assert_eq!(made.unwrap(), None);
            put_new_seats(store, GRP, c, &GEN, &[new_seat(1, B1)])
                .await
                .unwrap();
            put_rows(store, GRP, c, &GEN, &[row_to(B1, V1, rec(1), 1)])
                .await
                .unwrap();
            put_welcomes(store, GRP, c, &GEN, &[seat_welcome(rec(1), B1, V1)])
                .await
                .unwrap();
            let seal = Seal {
                epoch: 1,
                b: B1,
                v: V1,
                bytes: vec![9; 60],
            };
            put_seals(store, GRP, c, &GEN, std::slice::from_ref(&seal))
                .await
                .unwrap();
            let base = KeyringPiece {
                epoch: 1,
                j: 0,
                bytes: vec![8; 100],
            };
            put_keyring(store, GRP, c, &GEN, std::slice::from_ref(&base))
                .await
                .unwrap();
            let k = Krk {
                epoch: 1,
                holder: [0x11; 32],
                maker: maker(),
                bytes: vec![4; 1662],
            };
            put_krk(store, GRP, c, &GEN, std::slice::from_ref(&k))
                .await
                .unwrap();
            // Written, and nothing reads it
            assert_eq!(group(store, GRP).await.unwrap(), None);
            assert!(current_lists(store, GRP, &GEN).await.unwrap().is_empty());
            assert_eq!(list(store, GRP, &GEN, B1, V1).await.unwrap(), None);
            assert!(lists_at(store, GRP, &GEN, 1).await.unwrap().is_empty());
            assert!(seats(store, GRP, &GEN).await.unwrap().is_empty());
            assert_eq!(seat(store, GRP, &GEN, &rec(1)).await.unwrap(), None);
            let w = welcome(store, GRP, &GEN, &rec(1), WelcomeKind::Seat, 1).await;
            assert_eq!(w.unwrap(), None);
            assert!(welcomes_of(store, GRP, &GEN, &rec(1))
                .await
                .unwrap()
                .is_empty());
            assert_eq!(row(store, GRP, &GEN, B1, V1, &rec(1)).await.unwrap(), None);
            assert!(rows_of_seat(store, GRP, &GEN, &rec(1))
                .await
                .unwrap()
                .is_empty());
            assert!(seals(store, GRP, &GEN, 1).await.unwrap().is_empty());
            assert_eq!(seal_of_none(store).await, None);
            assert!(keyring(store, GRP, &GEN, 1).await.unwrap().is_empty());
            assert_eq!(krk(store, GRP, &GEN, 1, &[0x11; 32]).await.unwrap(), None);
            assert!(krks(store, GRP, &GEN, 1).await.unwrap().is_empty());
            // The head moves, and all of it is there at once
            let hs = [header_at(1, GEN, 1, 0, Kind::Genesis)];
            let mv = HeadMove {
                headers: &hs,
                ..Default::default()
            };
            let h = head(1, GEN, 1, 0);
            assert_eq!(
                move_head(store, GRP, c, &h, &mv).await.unwrap(),
                Moved::Done
            );
            assert_eq!(pending(store).await, 0);
            let g = group(store, GRP).await.unwrap().unwrap();
            assert_eq!(g.head, h);
            assert_eq!(groups(store).await.unwrap(), vec![GRP.to_string()]);
            assert_eq!(gens(store, GRP).await.unwrap().len(), 1);
            let lists = current_lists(store, GRP, &GEN).await.unwrap();
            assert_eq!(lists.len(), 1);
            assert_eq!((lists[0].b, lists[0].v, lists[0].current), (B1, V1, true));
            assert_eq!(lists[0].seats, vec![rec(1)]);
            assert_eq!(
                seats(store, GRP, &GEN).await.unwrap(),
                vec![new_seat(1, B1)]
            );
            touch_seats(store, GRP, &GEN, &[rec(1)], 86_400_000)
                .await
                .unwrap();
            let used = seat(store, GRP, &GEN, &rec(1)).await.unwrap().unwrap();
            assert_eq!(used.last_use, 86_400_000);
            let w = welcome(store, GRP, &GEN, &rec(1), WelcomeKind::Seat, 1).await;
            assert_eq!(w.unwrap(), Some(seat_welcome(rec(1), B1, V1)));
            let r = row(store, GRP, &GEN, B1, V1, &rec(1)).await.unwrap();
            assert_eq!(r, Some(row_to(B1, V1, rec(1), 1)));
            assert_eq!(seals(store, GRP, &GEN, 1).await.unwrap(), vec![seal]);
            assert_eq!(keyring(store, GRP, &GEN, 1).await.unwrap(), vec![base]);
            assert_eq!(krks(store, GRP, &GEN, 1).await.unwrap(), vec![k]);
            assert_eq!(headers(store, GRP, &GEN).await.unwrap(), hs.to_vec());
            assert_eq!(
                opening(store, GRP, &GEN, 1).await.unwrap(),
                Some(hs[0].clone())
            );
            // Once is all
            assert_eq!(
                move_head(store, GRP, c, &h, &mv).await.unwrap(),
                Moved::NotPending
            );
        }
    }

    async fn seal_of_none(store: &Store) -> Option<Seal> {
        seal(store, GRP, &GEN, 1, B1, V1).await.unwrap()
    }

    #[tokio::test]
    async fn a_head_move_over_another_head_changes_nothing() {
        let dbs = databases().await;
        for store in &dbs.stores {
            open(store).await;
            genesis(store, &[]).await;
            // Built on a head this relay never had
            let moved = open_epoch(store, 9, 2, 2, V2, &[rec(1)], HeadMove::default()).await;
            assert_eq!(moved, Moved::OtherHead);
            // Or on none, where there is one
            let c = begin_commit(store, GRP).await.unwrap();
            let h = head(3, GEN, 2, 0);
            let mv = HeadMove::default();
            let moved = move_head(store, GRP, c, &h, &mv).await.unwrap();
            assert_eq!(moved, Moved::OtherHead);
            let g = group(store, GRP).await.unwrap().unwrap();
            assert_eq!(g.head, head(1, GEN, 1, 0));
            let lists = current_lists(store, GRP, &GEN).await.unwrap();
            assert_eq!(lists.iter().map(|l| l.v).collect::<Vec<_>>(), vec![V1]);
            // Both still pending, for the sweep
            assert_eq!(pending(store).await, 2);
            assert_eq!(sweep_orphans(store, GRP, None).await.unwrap(), 2);
            assert_eq!(pending(store).await, 0);
        }
    }

    #[tokio::test]
    async fn an_orphan_is_swept_and_what_moved_the_head_stays() {
        let dbs = databases().await;
        for store in &dbs.stores {
            open(store).await;
            genesis(store, &[2]).await;
            let before = stored_bytes(store, GRP).await.unwrap();
            // A Join of seat 3 into B2 that also moves seat 2 there, never moved
            let c = begin_commit(store, GRP).await.unwrap();
            assert_eq!(
                put_vids(store, GRP, c, &GEN, &[(B2, V2)]).await.unwrap(),
                None
            );
            let made = put_lists(
                store,
                GRP,
                c,
                &GEN,
                &[version(B2, V2, 1, &[rec(2), rec(3)])],
            )
            .await;
            assert_eq!(made.unwrap(), None);
            put_new_seats(store, GRP, c, &GEN, &[new_seat(3, B2)])
                .await
                .unwrap();
            put_moves(store, GRP, c, &GEN, &[(rec(2), B2)])
                .await
                .unwrap();
            put_rows(store, GRP, c, &GEN, &[row_to(B2, V2, rec(3), 1)])
                .await
                .unwrap();
            put_welcomes(store, GRP, c, &GEN, &[seat_welcome(rec(3), B2, V2)])
                .await
                .unwrap();
            let seal = Seal {
                epoch: 1,
                b: B2,
                v: V2,
                bytes: vec![1; 60],
            };
            put_seals(store, GRP, c, &GEN, &[seal]).await.unwrap();
            let delta = KeyringPiece {
                epoch: 1,
                j: 1,
                bytes: vec![2; 119],
            };
            put_keyring(store, GRP, c, &GEN, &[delta]).await.unwrap();
            let k = Krk {
                epoch: 2,
                holder: [0x11; 32],
                maker: maker(),
                bytes: vec![3; 1662],
            };
            put_krk(store, GRP, c, &GEN, &[k]).await.unwrap();
            // The one being stored is spared
            let busy = begin_commit(store, GRP).await.unwrap();
            assert_eq!(sweep_orphans(store, GRP, Some(busy)).await.unwrap(), 1);
            assert_eq!(pending(store).await, 1);
            for t in [
                "SELECT COUNT(*) FROM voipc_gk_lists WHERE seats IS NOT NULL AND epoch_until IS NULL AND NOT current",
                "SELECT COUNT(*) FROM voipc_gk_seats WHERE next_commit IS NOT NULL OR b IS NULL",
            ] {
                assert_eq!(scalar(store, t).await, 0, "{t}");
            }
            assert_eq!(scalar(store, "SELECT COUNT(*) FROM voipc_gk_rows").await, 2);
            assert_eq!(
                scalar(store, "SELECT COUNT(*) FROM voipc_gk_welcomes").await,
                1
            );
            assert_eq!(
                scalar(store, "SELECT COUNT(*) FROM voipc_gk_seals").await,
                1
            );
            assert_eq!(
                scalar(store, "SELECT COUNT(*) FROM voipc_gk_keyring").await,
                1
            );
            assert_eq!(scalar(store, "SELECT COUNT(*) FROM voipc_gk_krk").await, 1);
            assert_eq!(scalar(store, "SELECT COUNT(*) FROM voipc_gk_vids").await, 1);
            assert_eq!(stored_bytes(store, GRP).await.unwrap(), before);
            // Seat 2 stays where the head has it, and the orphan's version id is free again
            assert_eq!(
                seat(store, GRP, &GEN, &rec(2)).await.unwrap().unwrap().b,
                B1
            );
            assert_eq!(seat(store, GRP, &GEN, &rec(3)).await.unwrap(), None);
            assert_eq!(
                put_vids(store, GRP, busy, &GEN, &[(B2, V2)]).await.unwrap(),
                None
            );
        }
    }

    #[tokio::test]
    async fn a_rebase_takes_over_its_stale_attempt_and_never_reads_what_it_left() {
        let dbs = databases().await;
        for store in &dbs.stores {
            open(store).await;
            genesis(store, &[]).await;
            let rows_before = scalar(store, "SELECT COUNT(*) FROM voipc_gk_rows").await;
            // A Join whose store failed: B2 v2 for seats 2 and 3
            let stale = begin_commit(store, GRP).await.unwrap();
            put_vids(store, GRP, stale, &GEN, &[(B2, V2)])
                .await
                .unwrap();
            let both = version(B2, V2, 1, &[rec(2), rec(3)]);
            let made = put_lists(store, GRP, stale, &GEN, std::slice::from_ref(&both)).await;
            assert_eq!(made.unwrap(), None);
            let rows = [row_to(B2, V2, rec(2), 1), row_to(B2, V2, rec(3), 1)];
            put_rows(store, GRP, stale, &GEN, &rows).await.unwrap();
            // Its rebase reuses the version, the same seats, a Join later
            let rebase = begin_commit(store, GRP).await.unwrap();
            let used = put_vids(store, GRP, rebase, &GEN, &[(B2, V2)]).await;
            assert_eq!(used.unwrap(), None);
            let again = List {
                epoch_made: 2,
                ..both
            };
            let made = put_lists(store, GRP, rebase, &GEN, &[again]).await;
            assert_eq!(made.unwrap(), None);
            // The stale attempt goes while the rebase is pending: nothing it wrote is read
            assert_eq!(sweep_orphans(store, GRP, Some(rebase)).await.unwrap(), 1);
            assert_eq!(list(store, GRP, &GEN, B2, V2).await.unwrap(), None);
            for i in [2, 3] {
                let r = row(store, GRP, &GEN, B2, V2, &rec(i)).await.unwrap();
                assert_eq!(r, None, "seat {i}");
                let mine = rows_of_seat(store, GRP, &GEN, &rec(i)).await.unwrap();
                assert!(mine.is_empty(), "seat {i}");
            }
            // Its rows replace what the stale one left in the version, here seat 2's only
            put_rows(store, GRP, rebase, &GEN, &rows[..1])
                .await
                .unwrap();
            let left = scalar(store, "SELECT COUNT(*) FROM voipc_gk_rows").await;
            assert_eq!(left, rows_before + 1);
            let hs = [header_at(2, GEN, 1, 1, Kind::Join)];
            let mv = HeadMove {
                was: Some([1; 32]),
                headers: &hs,
                ..Default::default()
            };
            let h = head(2, GEN, 1, 1);
            let moved = move_head(store, GRP, rebase, &h, &mv).await.unwrap();
            assert_eq!(moved, Moved::Done);
            let landed = list(store, GRP, &GEN, B2, V2).await.unwrap().unwrap();
            assert_eq!((landed.epoch_made, landed.current), (2, true));
            let r = row(store, GRP, &GEN, B2, V2, &rec(2)).await.unwrap();
            assert_eq!(r, Some(rows[0].clone()));
            assert_eq!(row(store, GRP, &GEN, B2, V2, &rec(3)).await.unwrap(), None);
            assert_eq!(scalar(store, "SELECT COUNT(*) FROM voipc_gk_vids").await, 2);
        }
    }

    #[tokio::test]
    async fn a_rebase_reuses_a_version_only_for_its_bucket_and_seats_and_never_a_ratchet() {
        let dbs = databases().await;
        for store in &dbs.stores {
            open(store).await;
            genesis(store, &[]).await;
            // A stale opening: B2 v2 for seats 2 and 3, and B1 ratcheted to v3
            let stale = begin_commit(store, GRP).await.unwrap();
            let used = put_vids(store, GRP, stale, &GEN, &[(B2, V2), (B1, V3)]).await;
            assert_eq!(used.unwrap(), None);
            let both = version(B2, V2, 2, &[rec(2), rec(3)]);
            let ratchet = List {
                via: Some(V1),
                base_v: V1,
                ..version(B1, V3, 2, &[rec(1)])
            };
            let made = put_lists(store, GRP, stale, &GEN, &[both.clone(), ratchet.clone()]).await;
            assert_eq!(made.unwrap(), None);
            let rebase = begin_commit(store, GRP).await.unwrap();
            // The id for another bucket
            let used = put_vids(store, GRP, rebase, &GEN, &[(B1, V2)]).await;
            assert_eq!(used.unwrap(), Some(V2));
            // The version with other seats
            let used = put_vids(store, GRP, rebase, &GEN, &[(B2, V2), (B1, V3)]).await;
            assert_eq!(used.unwrap(), None);
            let fewer = version(B2, V2, 2, &[rec(2)]);
            let made = put_lists(store, GRP, rebase, &GEN, &[fewer]).await;
            assert_eq!(made.unwrap(), Some((B2, V2)));
            // A ratchet, even the same one
            let made = put_lists(store, GRP, rebase, &GEN, &[ratchet]).await;
            assert_eq!(made.unwrap(), Some((B1, V3)));
            // The same seats it may
            let made = put_lists(store, GRP, rebase, &GEN, &[both]).await;
            assert_eq!(made.unwrap(), None);
            // What it was refused is still the stale attempt's, and goes with it
            assert_eq!(sweep_orphans(store, GRP, Some(rebase)).await.unwrap(), 1);
            assert_eq!(
                scalar(store, "SELECT COUNT(*) FROM voipc_gk_lists").await,
                2
            );
        }
    }

    #[tokio::test]
    async fn material_is_stored_only_for_a_commit_pending_in_its_group() {
        let dbs = databases().await;
        for store in &dbs.stores {
            open(store).await;
            let moved = genesis(store, &[2]).await;
            let other = begin_commit(store, "c:other").await.unwrap();
            let seal = Seal {
                epoch: 5,
                b: B2,
                v: V2,
                bytes: vec![1; 60],
            };
            let piece = KeyringPiece {
                epoch: 5,
                j: 0,
                bytes: vec![2; 100],
            };
            let k = Krk {
                epoch: 5,
                holder: [0x33; 32],
                maker: maker(),
                bytes: vec![3; 1662],
            };
            // Another group's commit, and one that moved the head already
            for c in [other, moved] {
                let lists = [version(B2, V2, 5, &[rec(2)])];
                assert!(put_vids(store, GRP, c, &GEN, &[(B2, V2)]).await.is_err());
                assert!(put_lists(store, GRP, c, &GEN, &lists).await.is_err());
                let seats = [new_seat(4, B2)];
                assert!(put_new_seats(store, GRP, c, &GEN, &seats).await.is_err());
                let moves = [(rec(2), B2)];
                assert!(put_moves(store, GRP, c, &GEN, &moves).await.is_err());
                let rows = [row_to(B1, V1, rec(1), 1)];
                assert!(put_rows(store, GRP, c, &GEN, &rows).await.is_err());
                let w = [seat_welcome(rec(4), B2, V2)];
                assert!(put_welcomes(store, GRP, c, &GEN, &w).await.is_err());
                let seals_in = std::slice::from_ref(&seal);
                assert!(put_seals(store, GRP, c, &GEN, seals_in).await.is_err());
                let ring = std::slice::from_ref(&piece);
                assert!(put_keyring(store, GRP, c, &GEN, ring).await.is_err());
                let krk_in = std::slice::from_ref(&k);
                assert!(put_krk(store, GRP, c, &GEN, krk_in).await.is_err());
            }
            // Nothing of it was written
            assert!(seals(store, GRP, &GEN, 5).await.unwrap().is_empty());
            assert!(keyring(store, GRP, &GEN, 5).await.unwrap().is_empty());
            assert_eq!(krk(store, GRP, &GEN, 5, &[0x33; 32]).await.unwrap(), None);
            assert_eq!(list(store, GRP, &GEN, B2, V2).await.unwrap(), None);
            assert_eq!(
                seat(store, GRP, &GEN, &rec(2)).await.unwrap().unwrap().b,
                B1
            );
            for t in [
                "SELECT COUNT(*) FROM voipc_gk_seats",
                "SELECT COUNT(*) FROM voipc_gk_vids",
                "SELECT COUNT(*) FROM voipc_gk_lists",
                "SELECT COUNT(*) FROM voipc_gk_welcomes",
            ] {
                let genesis_wrote = if t.contains("seats") { 2 } else { 1 };
                assert_eq!(scalar(store, t).await, genesis_wrote, "{t}");
            }
        }
    }

    #[tokio::test]
    async fn the_sweeps_spare_a_new_generation_being_stored() {
        let dbs = databases().await;
        for store in &dbs.stores {
            open(store).await;
            genesis(store, &[]).await;
            // A Genesis of GEN2 stored over the old head
            let c = begin_commit(store, GRP).await.unwrap();
            assert_eq!(
                put_vids(store, GRP, c, &GEN2, &[(B2, V1)]).await.unwrap(),
                None
            );
            let lists = [version(B2, V1, 1, &[rec(1)])];
            assert_eq!(put_lists(store, GRP, c, &GEN2, &lists).await.unwrap(), None);
            put_new_seats(store, GRP, c, &GEN2, &[new_seat(1, B2)])
                .await
                .unwrap();
            let base = KeyringPiece {
                epoch: 1,
                j: 0,
                bytes: vec![0x4b; 147],
            };
            put_keyring(store, GRP, c, &GEN2, std::slice::from_ref(&base))
                .await
                .unwrap();
            let k = Krk {
                epoch: 1,
                holder: [0x22; 32],
                maker: maker(),
                bytes: vec![0x4b; 1662],
            };
            put_krk(store, GRP, c, &GEN2, std::slice::from_ref(&k))
                .await
                .unwrap();
            // The 10-minute sweeps, by the head's generation
            crate::gk::store::sweep_keyrings(store, GRP, &GEN, 1)
                .await
                .unwrap();
            crate::gk::store::sweep_stale(store, GRP).await.unwrap();
            let hs = [header_at(5, GEN2, 1, 0, Kind::Genesis)];
            let mv = HeadMove {
                was: Some([1; 32]),
                headers: &hs,
                ..Default::default()
            };
            let h = head(5, GEN2, 1, 0);
            assert_eq!(
                move_head(store, GRP, c, &h, &mv).await.unwrap(),
                Moved::Done
            );
            assert_eq!(keyring(store, GRP, &GEN2, 1).await.unwrap(), vec![base]);
            assert_eq!(
                krk(store, GRP, &GEN2, 1, &[0x22; 32]).await.unwrap(),
                Some(k)
            );
            assert_eq!(seats(store, GRP, &GEN2).await.unwrap().len(), 1);
            let later = begin_commit(store, GRP).await.unwrap();
            let used = put_vids(store, GRP, later, &GEN2, &[(B2, V1)]).await;
            assert_eq!(used.unwrap(), Some(V1));
        }
    }

    #[tokio::test]
    async fn a_reset_leaves_the_generation_that_replaces_it() {
        let dbs = databases().await;
        for store in &dbs.stores {
            open(store).await;
            genesis(store, &[]).await;
            // The new incarnation's Genesis lands before the reset of the old one is done
            let c = begin_commit(store, GRP).await.unwrap();
            put_vids(store, GRP, c, &GEN2, &[(B2, V1)]).await.unwrap();
            let lists = [version(B2, V1, 1, &[rec(1)])];
            assert_eq!(put_lists(store, GRP, c, &GEN2, &lists).await.unwrap(), None);
            put_new_seats(store, GRP, c, &GEN2, &[new_seat(1, B2)])
                .await
                .unwrap();
            let w = seat_welcome(rec(1), B2, V1);
            put_welcomes(store, GRP, c, &GEN2, std::slice::from_ref(&w))
                .await
                .unwrap();
            let base = KeyringPiece {
                epoch: 1,
                j: 0,
                bytes: vec![0x4b; 147],
            };
            put_keyring(store, GRP, c, &GEN2, std::slice::from_ref(&base))
                .await
                .unwrap();
            let hs = [header_at(5, GEN2, 1, 0, Kind::Genesis)];
            let mv = HeadMove {
                was: Some([1; 32]),
                headers: &hs,
                ..Default::default()
            };
            let mut h = head(5, GEN2, 1, 0);
            h.incarnation = [4; 16];
            assert_eq!(
                move_head(store, GRP, c, &h, &mv).await.unwrap(),
                Moved::Done
            );
            while reset_step(store, GRP, &GEN).await.unwrap() > 0 {}
            assert!(keyring(store, GRP, &GEN, 1).await.unwrap().is_empty());
            assert_eq!(krk(store, GRP, &GEN, 1, &[0x11; 32]).await.unwrap(), None);
            assert_eq!(keyring(store, GRP, &GEN2, 1).await.unwrap(), vec![base]);
            let got = welcome(store, GRP, &GEN2, &rec(1), WelcomeKind::Seat, 1).await;
            assert_eq!(got.unwrap(), Some(w));
        }
    }

    #[tokio::test]
    async fn an_accounts_seats_are_found_in_every_group() {
        let dbs = databases().await;
        for store in &dbs.stores {
            open(store).await;
            genesis(store, &[2]).await;
            // Seat 2 also in another group, and a Join of seat 4 not yet the head
            let c = begin_commit(store, "c:other").await.unwrap();
            put_vids(store, "c:other", c, &GEN2, &[(B2, V2)])
                .await
                .unwrap();
            let lists = [version(B2, V2, 1, &[rec(2)])];
            let made = put_lists(store, "c:other", c, &GEN2, &lists).await;
            assert_eq!(made.unwrap(), None);
            put_new_seats(store, "c:other", c, &GEN2, &[new_seat(2, B2)])
                .await
                .unwrap();
            let h = head(9, GEN2, 1, 0);
            let mv = HeadMove::default();
            let moved = move_head(store, "c:other", c, &h, &mv).await.unwrap();
            assert_eq!(moved, Moved::Done);
            let join = begin_commit(store, GRP).await.unwrap();
            let lists = [version(B2, V3, 1, &[rec(4)])];
            put_vids(store, GRP, join, &GEN, &[(B2, V3)]).await.unwrap();
            assert_eq!(
                put_lists(store, GRP, join, &GEN, &lists).await.unwrap(),
                None
            );
            put_new_seats(store, GRP, join, &GEN, &[new_seat(4, B2)])
                .await
                .unwrap();
            let mut two = seats_of_account(store, &[2; 16]).await.unwrap();
            two.sort_by(|a, b| a.0.cmp(&b.0));
            let want = vec![
                ("c:general".to_string(), GEN, new_seat(2, B1)),
                ("c:other".to_string(), GEN2, new_seat(2, B2)),
            ];
            assert_eq!(two, want);
            assert_eq!(seats_of_account(store, &[1; 16]).await.unwrap().len(), 1);
            assert!(seats_of_account(store, &[4; 16]).await.unwrap().is_empty());
        }
    }

    /// SQLite runs without ANALYZE, so it takes the primary key's `(grp, gen)` prefix over a
    /// secondary index unless a statement names its rows by key through that index.
    #[tokio::test]
    async fn the_big_tables_are_read_and_moved_through_their_indexes_on_sqlite() {
        let dbs = databases().await;
        let store = &dbs.stores[0];
        open(store).await;
        let plan = |sql: &'static str| async move {
            // Each `$n` bound, the values aside
            let binds = (1..10).filter(|n| sql.contains(&format!("${n}"))).count();
            let rows: Vec<(i64, i64, i64, String)> = db!(store, pool => {
                let mut q = sqlx::query_as(sqlx::AssertSqlSafe(format!("EXPLAIN QUERY PLAN {sql}")));
                for _ in 0..binds {
                    q = q.bind(0i64);
                }
                q.fetch_all(pool).await.unwrap()
            });
            rows.into_iter().map(|r| r.3).collect::<Vec<_>>()
        };
        let wide = |steps: &[String]| {
            steps.iter().any(|d| {
                d.ends_with("PRIMARY KEY (grp=?)")
                    || d.ends_with("PRIMARY KEY (grp=? AND gen=?)")
                    || d.starts_with("SCAN")
            })
        };
        for (sql, index) in [
            (LISTS_AT, "voipc_gk_lists_until"),
            (LISTS_AT, "voipc_gk_lists_current"),
            (ROWS_READ_BY_SEAT, "voipc_gk_rows_seat"),
            (LISTS_LAND, "voipc_gk_lists_commit"),
            (SEATS_LAND, "voipc_gk_seats_next"),
            (VIDS_LAND, "voipc_gk_vids_pending"),
        ] {
            let steps = plan(sql).await;
            assert!(
                steps.iter().any(|d| d.contains(index)),
                "{index}: {steps:?}"
            );
            assert!(!wide(&steps), "{steps:?}");
        }
    }

    /// Writers beside the store on SQLite's 32 connections (config.rs DB_CONNECTIONS): a
    /// deferred transaction that reads before it writes would fail at once (BUSY) whenever one of
    /// them wrote in between; and two publishes of one account's seat keys at once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_store_writes_beside_other_writers_and_waits_its_turn() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::sync::Arc;
        let dbs = databases().await;
        for store in &dbs.stores {
            open(store).await;
            genesis(store, &[]).await;
            let ann = account(store, "ann").await;
            let stop = Arc::new(AtomicBool::new(false));
            let errors = Arc::new(AtomicUsize::new(0));
            let mut others = Vec::new();
            for i in 0..3u8 {
                let (st, stop, errors) = (store.clone(), stop.clone(), errors.clone());
                others.push(tokio::spawn(async move {
                    let mut n = 0u64;
                    while !stop.load(Ordering::Relaxed) {
                        n += 1;
                        let done = db!(&st, pool => {
                            sqlx::query("INSERT INTO voipc_meta (k, v) VALUES ($1, $2) ON CONFLICT (k) DO UPDATE SET v = excluded.v")
                                .bind(format!("gk-test-{i}"))
                                .bind(n.to_be_bytes().to_vec())
                                .execute(pool)
                                .await
                                .map(|_| ())
                        });
                        if done.is_err() {
                            errors.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }));
            }
            for round in 0..20u64 {
                let c = begin_commit(store, GRP).await.unwrap();
                // 40 versions of 25 seats: one batch of rows checks 40 lists, then writes
                let lists: Vec<List> = (0..40u64)
                    .map(|i| {
                        let seats: Vec<SeatRec> =
                            (0..25u16).map(|s| rec(1000 + i as u16 * 25 + s)).collect();
                        version(
                            10_000 + round * 100 + i,
                            20_000 + round * 100 + i,
                            1,
                            &seats,
                        )
                    })
                    .collect();
                assert_eq!(put_lists(store, GRP, c, &GEN, &lists).await.unwrap(), None);
                let rows: Vec<BucketRow> = lists
                    .iter()
                    .flat_map(|l| l.seats.iter().map(move |s| row_to(l.b, l.v, *s, 1)))
                    .collect();
                put_rows(store, GRP, c, &GEN, &rows).await.unwrap();
                gk_start(store, true).await.unwrap();
                // Two devices of one account publish at once: one wins, neither errs
                let keys = |n: u64| SeatKeys {
                    n: n as u32,
                    kem: vec![1; 1569],
                    dh: vec![2; 33],
                    made: 1,
                    sig: vec![3; 64],
                    published: 1,
                };
                let (one, two) = (keys(2 * round + 1), keys(2 * round + 2));
                let (a, b) = tokio::join!(
                    put_seat_keys(store, &ann, &one),
                    put_seat_keys(store, &ann, &two),
                );
                assert!(a.unwrap() | b.unwrap());
                let now = seat_keys(store, &ann).await.unwrap().unwrap();
                assert!(now.n > 2 * round as u32);
            }
            stop.store(true, Ordering::Relaxed);
            for o in others {
                o.await.unwrap();
            }
            assert_eq!(errors.load(Ordering::Relaxed), 0);
            let current = "SELECT COUNT(*) FROM voipc_gk_seatkeys WHERE current";
            assert_eq!(scalar(store, current).await, 1);
        }
    }

    #[tokio::test]
    async fn a_version_id_is_used_once_a_generation() {
        let dbs = databases().await;
        for store in &dbs.stores {
            open(store).await;
            genesis(store, &[]).await;
            let c = begin_commit(store, GRP).await.unwrap();
            let used = put_vids(store, GRP, c, &GEN, &[(B1, V3), (B1, V1)])
                .await
                .unwrap();
            assert_eq!(used, Some(V1));
            // Another generation may draw it
            assert_eq!(
                put_vids(store, GRP, c, &GEN2, &[(B1, V1)]).await.unwrap(),
                None
            );
            // A stale attempt's id is taken over by its rebase, then used for good
            let stale = begin_commit(store, GRP).await.unwrap();
            assert_eq!(
                put_vids(store, GRP, stale, &GEN, &[(B1, V2)])
                    .await
                    .unwrap(),
                None
            );
            let moved = open_epoch(store, 1, 2, 2, V2, &[rec(1)], HeadMove::default()).await;
            assert_eq!(moved, Moved::Done);
            let later = begin_commit(store, GRP).await.unwrap();
            let used = put_vids(store, GRP, later, &GEN, &[(B1, V2)])
                .await
                .unwrap();
            assert_eq!(used, Some(V2));
            // So is a version already stored
            let landed = list(store, GRP, &GEN, B1, V2).await.unwrap().unwrap();
            let made = put_lists(store, GRP, later, &GEN, &[landed]).await;
            assert_eq!(made.unwrap(), Some((B1, V2)));
        }
    }

    /// A kept read of a seat a Join added (T1e A) is answered at its epoch's last Join: the
    /// last header kept of an epoch is its last Join, or its opening while none followed.
    #[tokio::test]
    async fn an_epochs_last_header_is_its_last_join_or_its_opening() {
        let dbs = databases().await;
        for store in &dbs.stores {
            open(store).await;
            genesis(store, &[]).await;
            let last = |e| async move { epoch_last(store, GRP, &GEN, e).await.unwrap() };
            assert_eq!(last(1).await.map(|h| (h.d, h.j)), Some(([1; 32], 0)));
            assert_eq!(last(2).await, None);
            let mut was = [1u8; 32];
            for (d, epoch, j, kind) in [
                (2u8, 1, 1, Kind::Join),
                (3, 1, 2, Kind::Join),
                (4, 2, 0, Kind::Fresh),
            ] {
                let c = begin_commit(store, GRP).await.unwrap();
                let hs = [header_at(d, GEN, epoch, j, kind)];
                let mv = HeadMove {
                    was: Some(was),
                    headers: &hs,
                    ..Default::default()
                };
                let h = head(d, GEN, epoch, j);
                assert_eq!(
                    move_head(store, GRP, c, &h, &mv).await.unwrap(),
                    Moved::Done
                );
                was = [d; 32];
            }
            let j2 = last(1).await.unwrap();
            assert_eq!((j2.d, j2.j, j2.kind), ([3; 32], 2, Kind::Join));
            let o = last(2).await.unwrap();
            assert_eq!((o.d, o.j, o.kind), ([4; 32], 0, Kind::Fresh));
            assert_eq!(
                opening(store, GRP, &GEN, 1).await.unwrap().map(|h| h.d),
                Some([1; 32])
            );
            assert_eq!(epoch_last(store, GRP, &[9; 16], 1).await.unwrap(), None);
        }
    }

    #[tokio::test]
    async fn an_opening_retires_what_it_replaces_and_a_join_nothing() {
        let dbs = databases().await;
        for store in &dbs.stores {
            open(store).await;
            genesis(store, &[]).await;
            // A Join: seat 2 in a new bucket B2
            let c = begin_commit(store, GRP).await.unwrap();
            put_vids(store, GRP, c, &GEN, &[(B2, V2)]).await.unwrap();
            let made = put_lists(store, GRP, c, &GEN, &[version(B2, V2, 1, &[rec(2)])]).await;
            assert_eq!(made.unwrap(), None);
            put_new_seats(store, GRP, c, &GEN, &[new_seat(2, B2)])
                .await
                .unwrap();
            let hs = [header_at(2, GEN, 1, 1, Kind::Join)];
            let mv = HeadMove {
                was: Some([1; 32]),
                headers: &hs,
                ..Default::default()
            };
            let h = head(2, GEN, 1, 1);
            assert_eq!(
                move_head(store, GRP, c, &h, &mv).await.unwrap(),
                Moved::Done
            );
            let mut vs: Vec<u64> = current_lists(store, GRP, &GEN)
                .await
                .unwrap()
                .iter()
                .map(|l| l.v)
                .collect();
            vs.sort_unstable();
            assert_eq!(vs, vec![V2, V1]);
            // An opening: B1 re-versioned with seat 2 merged in, B2 dropped
            let c = begin_commit(store, GRP).await.unwrap();
            put_vids(store, GRP, c, &GEN, &[(B1, V3)]).await.unwrap();
            let made = put_lists(
                store,
                GRP,
                c,
                &GEN,
                &[version(B1, V3, 2, &[rec(1), rec(2)])],
            )
            .await;
            assert_eq!(made.unwrap(), None);
            put_moves(store, GRP, c, &GEN, &[(rec(2), B1)])
                .await
                .unwrap();
            let hs = [header_at(3, GEN, 2, 0, Kind::Fresh)];
            let mv = HeadMove {
                was: Some([2; 32]),
                headers: &hs,
                drops: &[B2],
                ..Default::default()
            };
            assert_eq!(
                seat(store, GRP, &GEN, &rec(2)).await.unwrap().unwrap().b,
                B2
            );
            let h = head(3, GEN, 2, 0);
            assert_eq!(
                move_head(store, GRP, c, &h, &mv).await.unwrap(),
                Moved::Done
            );
            let now = current_lists(store, GRP, &GEN).await.unwrap();
            assert_eq!(
                now.iter().map(|l| (l.b, l.v)).collect::<Vec<_>>(),
                vec![(B1, V3)]
            );
            assert_eq!(
                seat(store, GRP, &GEN, &rec(2)).await.unwrap().unwrap().b,
                B1
            );
            for (b, v) in [(B1, V1), (B2, V2)] {
                let old = list(store, GRP, &GEN, b, v).await.unwrap().unwrap();
                assert_eq!((old.current, old.epoch_until), (false, Some(2)));
            }
            let mut at1: Vec<u64> = lists_at(store, GRP, &GEN, 1)
                .await
                .unwrap()
                .iter()
                .map(|l| l.v)
                .collect();
            at1.sort_unstable();
            assert_eq!(at1, vec![V2, V1]);
            let at2 = lists_at(store, GRP, &GEN, 2).await.unwrap();
            assert_eq!(at2.iter().map(|l| l.v).collect::<Vec<_>>(), vec![V3]);
            // A Regenesis: the signer's new bucket alone; the others' seats are read no more
            let c = begin_commit(store, GRP).await.unwrap();
            put_vids(store, GRP, c, &GEN, &[(B2, 7)]).await.unwrap();
            let made = put_lists(store, GRP, c, &GEN, &[version(B2, 7, 3, &[rec(1)])]).await;
            assert_eq!(made.unwrap(), None);
            put_moves(store, GRP, c, &GEN, &[(rec(1), B2)])
                .await
                .unwrap();
            let hs = [header_at(4, GEN, 3, 0, Kind::Regenesis)];
            let mv = HeadMove {
                was: Some([3; 32]),
                headers: &hs,
                retire_all: true,
                ..Default::default()
            };
            let h = head(4, GEN, 3, 0);
            assert_eq!(
                move_head(store, GRP, c, &h, &mv).await.unwrap(),
                Moved::Done
            );
            let now = current_lists(store, GRP, &GEN).await.unwrap();
            assert_eq!(
                now.iter().map(|l| (l.b, l.v)).collect::<Vec<_>>(),
                vec![(B2, 7)]
            );
            let left = seats(store, GRP, &GEN).await.unwrap();
            assert_eq!(
                left.iter().map(|s| s.seat).collect::<Vec<_>>(),
                vec![rec(1)]
            );
            assert_eq!(crate::gk::store::sweep_stale(store, GRP).await.unwrap(), 1);
            assert_eq!(
                scalar(store, "SELECT COUNT(*) FROM voipc_gk_seats").await,
                1
            );
        }
    }

    #[tokio::test]
    async fn exits_take_their_seats_at_the_head_that_deals_with_them() {
        let dbs = databases().await;
        for store in &dbs.stores {
            open(store).await;
            genesis(store, &[2, 3, 4]).await;
            let exit = |seq, i| Exit {
                seq,
                gen: GEN,
                seat: rec(i),
                cause: 1,
                at: 50,
            };
            add_exits(store, GRP, &[exit(1, 2), exit(2, 3), exit(3, 4)])
                .await
                .unwrap();
            assert_eq!(group(store, GRP).await.unwrap().unwrap().head.exits_next, 4);
            // Seat 4 came back before its batch closed, then left again
            drop_exits(store, GRP, &[3]).await.unwrap();
            add_exits(store, GRP, &[exit(4, 4)]).await.unwrap();
            let seqs: Vec<u64> = exits(store, GRP)
                .await
                .unwrap()
                .iter()
                .map(|e| e.seq)
                .collect();
            assert_eq!(seqs, vec![1, 2, 4]);
            // The opening that deals with 1 and 2
            let mv = HeadMove {
                exits_upto: 2,
                ..Default::default()
            };
            let moved = open_epoch(store, 1, 2, 2, V2, &[rec(1), rec(4)], mv).await;
            assert_eq!(moved, Moved::Done);
            let mut left: Vec<SeatRec> = seats(store, GRP, &GEN)
                .await
                .unwrap()
                .iter()
                .map(|s| s.seat)
                .collect();
            left.sort_unstable();
            assert_eq!(left, vec![rec(1), rec(4)]);
            assert_eq!(exits(store, GRP).await.unwrap(), vec![exit(4, 4)]);
            // A head move never lowers the count (`head()` says 1)
            assert_eq!(group(store, GRP).await.unwrap().unwrap().head.exits_next, 5);
            // Not in a group with no head
            assert!(add_exits(store, "c:other", &[exit(1, 2)]).await.is_err());
        }
    }

    #[tokio::test]
    async fn a_new_generation_is_known_and_ends_the_old_ones() {
        let dbs = databases().await;
        for store in &dbs.stores {
            open(store).await;
            genesis(store, &[2]).await;
            let exit = Exit {
                seq: 1,
                gen: GEN,
                seat: rec(2),
                cause: 1,
                at: 50,
            };
            add_exits(store, GRP, &[exit]).await.unwrap();
            // A Genesis of GEN2 over the old head (a restore, the switch)
            let c = begin_commit(store, GRP).await.unwrap();
            put_vids(store, GRP, c, &GEN2, &[(B2, V1)]).await.unwrap();
            let made = put_lists(store, GRP, c, &GEN2, &[version(B2, V1, 1, &[rec(1)])]).await;
            assert_eq!(made.unwrap(), None);
            put_new_seats(store, GRP, c, &GEN2, &[new_seat(1, B2)])
                .await
                .unwrap();
            let hs = [header_at(5, GEN2, 1, 0, Kind::Genesis)];
            let mv = HeadMove {
                was: Some([1; 32]),
                headers: &hs,
                ..Default::default()
            };
            let h = head(5, GEN2, 1, 0);
            assert_eq!(
                move_head(store, GRP, c, &h, &mv).await.unwrap(),
                Moved::Done
            );
            let mut known: Vec<Gen> = gens(store, GRP)
                .await
                .unwrap()
                .iter()
                .map(|g| g.0)
                .collect();
            known.sort_unstable();
            assert_eq!(known, vec![GEN, GEN2]);
            assert!(current_lists(store, GRP, &GEN).await.unwrap().is_empty());
            let old = list(store, GRP, &GEN, B1, V1).await.unwrap().unwrap();
            assert_eq!(old.epoch_until, Some(2));
            assert!(exits(store, GRP).await.unwrap().is_empty());
            assert!(seats(store, GRP, &GEN).await.unwrap().is_empty());
            assert_eq!(seats(store, GRP, &GEN2).await.unwrap().len(), 1);
            // What kept history reads stays; the old seats and ids go
            assert_eq!(
                rows_of_seat(store, GRP, &GEN, &rec(2)).await.unwrap().len(),
                1
            );
            assert_eq!(crate::gk::store::sweep_stale(store, GRP).await.unwrap(), 3);
            assert_eq!(
                scalar(store, "SELECT COUNT(*) FROM voipc_gk_seats").await,
                1
            );
            assert_eq!(scalar(store, "SELECT COUNT(*) FROM voipc_gk_vids").await, 1);
        }
    }

    #[tokio::test]
    async fn a_seed_welcome_page_raises_its_seats_seed() {
        let dbs = databases().await;
        for store in &dbs.stores {
            open(store).await;
            genesis(store, &[2]).await;
            let page = |s| Welcome {
                seat: rec(2),
                kind: WelcomeKind::Seed,
                s,
                version: None,
                maker: maker(),
                bytes: vec![s as u8; 1662],
                made: 60,
            };
            put_seed_welcomes(store, GRP, &GEN, &[page(2)])
                .await
                .unwrap();
            assert_eq!(
                seat(store, GRP, &GEN, &rec(2)).await.unwrap().unwrap().seed,
                2
            );
            let w = welcome(store, GRP, &GEN, &rec(2), WelcomeKind::Seed, 2).await;
            assert_eq!(w.unwrap(), Some(page(2)));
            // Never lower
            put_seed_welcomes(store, GRP, &GEN, &[page(1)])
                .await
                .unwrap();
            assert_eq!(
                seat(store, GRP, &GEN, &rec(2)).await.unwrap().unwrap().seed,
                2
            );
            // Each kind where it belongs
            let seat_kind = seat_welcome(rec(2), B1, V1);
            assert!(put_seed_welcomes(store, GRP, &GEN, &[seat_kind])
                .await
                .is_err());
            let c = begin_commit(store, GRP).await.unwrap();
            assert!(put_welcomes(store, GRP, c, &GEN, &[page(3)]).await.is_err());
        }
    }

    #[tokio::test]
    async fn seat_keys_only_move_forward() {
        let dbs = databases().await;
        for store in &dbs.stores {
            open(store).await;
            let ann = account(store, "ann").await;
            let bob = account(store, "bob").await;
            let keys = |n| SeatKeys {
                n,
                kem: vec![n as u8; 1569],
                dh: vec![n as u8; 33],
                made: 100 + u64::from(n),
                sig: vec![3; 64],
                published: 7,
            };
            assert!(put_seat_keys(store, &ann, &keys(2)).await.unwrap());
            assert_eq!(seat_keys(store, &ann).await.unwrap(), Some(keys(2)));
            // Old keys offered again, or the same ones, are refused
            assert!(!put_seat_keys(store, &ann, &keys(2)).await.unwrap());
            assert!(!put_seat_keys(store, &ann, &keys(1)).await.unwrap());
            assert!(put_seat_keys(store, &ann, &keys(3)).await.unwrap());
            assert_eq!(seat_keys(store, &ann).await.unwrap(), Some(keys(3)));
            assert_eq!(seat_keys_at(store, &ann, 2).await.unwrap(), Some(keys(2)));
            assert_eq!(seat_keys(store, &bob).await.unwrap(), None);
            // The eager seats of a channel: its log's members with keys, a page at a time
            assert!(put_seat_keys(store, &bob, &keys(1)).await.unwrap());
            db!(store, pool => {
                for a in [&ann, &bob] {
                    sqlx::query("INSERT INTO voipc_members (conv, account, joined_at) VALUES ($1, $2, 0)")
                        .bind(GRP)
                        .bind(&a[..])
                        .execute(pool)
                        .await
                        .unwrap();
                }
            });
            let first = members_with_seat_keys(store, GRP, None, 1).await.unwrap();
            assert_eq!(first.len(), 1);
            let rest = members_with_seat_keys(store, GRP, Some(&first[0].0), 10)
                .await
                .unwrap();
            assert_eq!(rest.len(), 1);
            let mut found = [(first[0].0, first[0].1.n), (rest[0].0, rest[0].1.n)];
            found.sort_unstable();
            let mut want = [(ann, 3), (bob, 1)];
            want.sort_unstable();
            assert_eq!(found, want);
            assert!(members_with_seat_keys(store, "c:other", None, 10)
                .await
                .unwrap()
                .is_empty());
            assert_eq!(drop_seat_keys(store, &ann).await.unwrap(), 2);
            assert_eq!(seat_keys(store, &ann).await.unwrap(), None);
        }
    }

    #[tokio::test]
    async fn keyholders_are_found_by_member_and_device_and_keep_their_pair_in_a_column_of_its_own()
    {
        let dbs = databases().await;
        for store in &dbs.stores {
            open(store).await;
            let m: MemberRec = [1; 17];
            let holder = |kx: u8, device: &[u8]| Holder {
                kx: [kx; 32],
                m,
                device: Some(device.to_vec()),
                rank: 4,
                last_online: 9,
                missed: Misses::default(),
                pair: None,
            };
            let pair = voipc_protocol::gk::EndorsedPair {
                origin: voipc_protocol::gk::origin::DESKTOP,
                u: 0,
                kem: vec![0x31; 1184],
                dh: vec![0x32; 33],
                n: 3,
                made: 1_800_000_000,
                sig: vec![0x33; 64],
            };
            let one = Holder {
                pair: Some(pair.clone()),
                ..holder(1, b"desk-one-0000000")
            };
            put_holder(store, GRP, &one).await.unwrap();
            put_holder(store, GRP, &holder(2, b"desk-two-0000000"))
                .await
                .unwrap();
            put_holder(store, "c:other", &holder(3, b"desk-one-0000000"))
                .await
                .unwrap();
            assert_eq!(holders(store, GRP).await.unwrap().len(), 2);
            assert_eq!(holders_of(store, &m, None).await.unwrap().len(), 3);
            let one = holders_of(store, &m, Some(b"desk-one-0000000"))
                .await
                .unwrap();
            let mut kx: Vec<u8> = one.iter().map(|(_, h)| h.kx[0]).collect();
            kx.sort_unstable();
            assert_eq!(kx, vec![1, 3]);
            let missed = Misses {
                missed: vec![10, 20],
                declined: vec![15],
            };
            assert!(set_holder_seen(store, GRP, &[1; 32], 99, &missed)
                .await
                .unwrap());
            let h = holders(store, GRP).await.unwrap();
            let h1 = h.iter().find(|h| h.kx == [1; 32]).unwrap();
            assert_eq!((h1.last_online, &h1.missed), (99, &missed));
            // The misses written alone leave the pair as it was
            assert_eq!(h1.pair.as_ref(), Some(&pair));
            let h2 = h.iter().find(|h| h.kx == [2; 32]).unwrap();
            assert_eq!(h2.pair, None);
            assert!(drop_holder(store, GRP, &[1; 32]).await.unwrap());
            assert!(!drop_holder(store, GRP, &[1; 32]).await.unwrap());
            assert_eq!(holders(store, GRP).await.unwrap().len(), 1);
        }
    }

    /// An account seat's record in `GRP`, by its tags.
    fn own_seat(a: &[u8; 16], sk: u8) -> SeatRec {
        seat_record(&SeatRef {
            m: MemberId::Account(*a),
            tag_sk: [sk; 8],
            tag_sx: [2; 8],
        })
    }

    async fn sit(store: &Store, seat: &SeatRec, seed: i64, account: &[u8; 16]) {
        db!(store, pool => {
            sqlx::query(
                "INSERT INTO voipc_gk_seats (grp, gen, seat, dh, b, pool, seed, last_use, account)
                 VALUES ($1, $2, $3, $4, 1, 0, $5, 0, $6)",
            )
            .bind(GRP)
            .bind(&GEN[..])
            .bind(&seat[..])
            .bind(&[5u8; 33][..])
            .bind(seed)
            .bind(&account[..])
            .execute(pool)
            .await
            .unwrap();
        });
    }

    fn self_row(seed: u32, kind: u8, sk: u8, sealed: usize) -> SelfRowIn {
        SelfRowIn {
            group: GRP.into(),
            gen: GEN,
            seed,
            sk: [sk; 8],
            sx: [2; 8],
            kind,
            sealed: vec![9; sealed],
        }
    }

    /// C4 `SelfRowPut`: a row only for a seat the account holds (or a row reaches) under that
    /// seed or a later one, one per key, a second replacing the first and counted all the same
    /// (K1: the count is the rows sent); none for another account's seat or an `r:` group.
    #[tokio::test]
    async fn self_rows_are_kept_only_for_a_seat_the_account_holds_or_held_and_replace_their_own() {
        use voipc_protocol::gk::SELF_ROW_BYTES;
        let dbs = databases().await;
        for store in &dbs.stores {
            open(store).await;
            let a = account(store, "ann").await;
            sit(store, &own_seat(&a, 1), 3, &a).await;
            let rows = [
                self_row(3, 0, 1, SELF_ROW_BYTES),
                self_row(2, 0, 1, SELF_ROW_BYTES),
                self_row(3, 1, 1, 300),
            ];
            assert_eq!(put_self_rows(store, &a, &rows).await.unwrap(), 3);
            let again = self_row(3, 0, 1, SELF_ROW_BYTES);
            let again = SelfRowIn {
                sealed: vec![8; SELF_ROW_BYTES],
                ..again
            };
            assert_eq!(put_self_rows(store, &a, &[again]).await.unwrap(), 1);
            assert_eq!(scalar(store, "SELECT COUNT(*) FROM voipc_gk_self").await, 3);
            let (held, _) = crate::gk::store::rows_of(store, &a, None, 16)
                .await
                .unwrap();
            let replaced = held.iter().find(|r| (r.seed, r.kind) == (3, 0)).unwrap();
            assert_eq!(
                replaced.sealed,
                vec![8; SELF_ROW_BYTES],
                "replaced, not added"
            );
            // A later seed than it holds, a seat of no one's, another account, an `r:` group
            let other = account(store, "bob").await;
            let r_group = SelfRowIn {
                group: "r:00:7".into(),
                ..self_row(3, 0, 1, SELF_ROW_BYTES)
            };
            assert_eq!(
                put_self_rows(
                    store,
                    &a,
                    &[
                        self_row(4, 0, 1, SELF_ROW_BYTES),
                        self_row(3, 0, 5, SELF_ROW_BYTES),
                        r_group
                    ]
                )
                .await
                .unwrap(),
                0
            );
            assert_eq!(
                put_self_rows(store, &other, &[self_row(3, 0, 1, SELF_ROW_BYTES)])
                    .await
                    .unwrap(),
                0
            );
            // A seat gone that a kept row still reaches, under its seed
            db!(store, pool => {
                sqlx::query(
                    "INSERT INTO voipc_gk_rows (grp, gen, b, v, seat, s, maker, bytes, epoch_made, commit_id)
                     VALUES ($1, $2, 1, 1, $3, 6, $4, $5, 1, 1)",
                )
                .bind(GRP)
                .bind(&GEN[..])
                .bind(&own_seat(&a, 7)[..])
                .bind(&maker()[..])
                .bind(&[1u8; 60][..])
                .execute(pool)
                .await
                .unwrap();
            });
            assert_eq!(
                put_self_rows(store, &a, &[self_row(6, 1, 7, 300)])
                    .await
                    .unwrap(),
                1
            );
            // What an identity reset leaves: nothing of the account's
            forget_account(store, &a).await.unwrap();
            assert_eq!(scalar(store, "SELECT COUNT(*) FROM voipc_gk_self").await, 0);
        }
    }

    /// K1 seals every row `SelfRowsList` gave again at a rotation, those of a seat gone since
    /// too (it left, its rows were swept): each replaces its own and is counted, or the app
    /// keeps its old seat keys a week. A new row for a seat gone is still refused.
    #[tokio::test]
    async fn a_rotation_sealing_again_a_row_of_a_seat_gone_since_replaces_it_and_counts() {
        use voipc_protocol::gk::SELF_ROW_BYTES;
        let dbs = databases().await;
        for store in &dbs.stores {
            open(store).await;
            let a = account(store, "ann").await;
            sit(store, &own_seat(&a, 1), 3, &a).await;
            let row = self_row(3, 0, 1, SELF_ROW_BYTES);
            assert_eq!(
                put_self_rows(store, &a, std::slice::from_ref(&row))
                    .await
                    .unwrap(),
                1
            );
            // Its exit: the seat goes, and nothing reaches it any more
            db!(store, pool => {
                sqlx::query("DELETE FROM voipc_gk_seats").execute(pool).await.unwrap();
            });
            let again = SelfRowIn {
                sealed: vec![8; SELF_ROW_BYTES],
                ..row
            };
            assert_eq!(put_self_rows(store, &a, &[again]).await.unwrap(), 1);
            let (held, _) = crate::gk::store::rows_of(store, &a, None, 16)
                .await
                .unwrap();
            assert_eq!(held.len(), 1);
            assert_eq!(held[0].sealed, vec![8; SELF_ROW_BYTES]);
            assert_eq!(
                put_self_rows(store, &a, &[self_row(3, 1, 1, 300)])
                    .await
                    .unwrap(),
                0
            );
        }
    }

    /// `SelfRowsList` (K1): a page stays under the 64 KiB frame however big the history rows
    /// in it, and its `next` goes on from its last row until every one was read.
    #[tokio::test]
    async fn a_self_rows_page_stays_under_a_frame_and_the_pages_read_every_row() {
        use voipc_protocol::gk::HISTORY_ROW_MAX_BYTES;
        let dbs = databases().await;
        for store in &dbs.stores {
            open(store).await;
            let a = account(store, "ann").await;
            sit(store, &own_seat(&a, 1), 20, &a).await;
            let rows: Vec<SelfRowIn> = (0..10)
                .map(|seed| self_row(seed, 1, 1, HISTORY_ROW_MAX_BYTES))
                .collect();
            assert_eq!(put_self_rows(store, &a, &rows).await.unwrap(), 10);
            let (mut read, mut after) = (Vec::new(), None::<Vec<u8>>);
            loop {
                let (page, next) = crate::gk::store::rows_of(store, &a, after.as_deref(), 256)
                    .await
                    .unwrap();
                use voipc_protocol::messages::{AccountReply, ServerMessage};
                let frame = AccountReply::SelfRows {
                    rows: page.clone(),
                    next: next.clone(),
                };
                let frame =
                    voipc_protocol::codec::encode_server_msg(&ServerMessage::Account(frame))
                        .unwrap();
                assert!(frame.len() <= 64 * 1024, "a page of {} bytes", frame.len());
                read.extend(page.into_iter().map(|r| r.seed));
                match next {
                    Some(n) => after = Some(n),
                    None => break,
                }
            }
            assert_eq!(read, (0..10).collect::<Vec<u32>>());
        }
    }

    #[tokio::test]
    async fn a_reset_takes_the_keys_and_leaves_what_history_reads() {
        let dbs = databases().await;
        for store in &dbs.stores {
            open(store).await;
            genesis(store, &[2]).await;
            // More than one batch of welcomes
            let many: Vec<Welcome> = (10..1210)
                .map(|i| Welcome {
                    seat: rec(i),
                    kind: WelcomeKind::Seed,
                    s: 2,
                    version: None,
                    maker: maker(),
                    bytes: vec![1; 100],
                    made: 1,
                })
                .collect();
            put_seed_welcomes(store, GRP, &GEN, &many).await.unwrap();
            let mut steps = 0;
            while reset_step(store, GRP, &GEN).await.unwrap() > 0 {
                steps += 1;
            }
            assert_eq!(steps, 2);
            for t in [
                "SELECT COUNT(*) FROM voipc_gk_keyring",
                "SELECT COUNT(*) FROM voipc_gk_krk",
                "SELECT COUNT(*) FROM voipc_gk_welcomes",
            ] {
                assert_eq!(scalar(store, t).await, 0, "{t}");
            }
            assert_eq!(seals(store, GRP, &GEN, 1).await.unwrap().len(), 1);
            assert_eq!(
                rows_of_seat(store, GRP, &GEN, &rec(2)).await.unwrap().len(),
                1
            );
            assert_eq!(headers(store, GRP, &GEN).await.unwrap().len(), 1);
            assert_eq!(current_lists(store, GRP, &GEN).await.unwrap().len(), 1);
        }
    }

    #[tokio::test]
    async fn names_come_in_order_and_a_sweep_keeps_the_step() {
        let dbs = databases().await;
        for store in &dbs.stores {
            open(store).await;
            let n = |epoch, j, kind| Names {
                gen: GEN,
                epoch,
                j,
                kind,
                time: 1_800_000_000 + u64::from(epoch * 10 + j),
                names_hash: [j as u8; 32],
                list: vec![kind; 40],
            };
            // One with a head move, the rest beside it
            genesis(store, &[]).await;
            let c = begin_commit(store, GRP).await.unwrap();
            let joined = [n(1, 1, 0)];
            let mv = HeadMove {
                was: Some([1; 32]),
                names: &joined,
                ..Default::default()
            };
            let h = head(2, GEN, 1, 1);
            assert_eq!(
                move_head(store, GRP, c, &h, &mv).await.unwrap(),
                Moved::Done
            );
            put_names(
                store,
                GRP,
                &[n(3, 1, 0), n(1, 2, 0), n(2, 0, 1), n(2, 0, 0)],
            )
            .await
            .unwrap();
            let got = names(store, GRP, &GEN, (1, 2), (3, 0)).await.unwrap();
            let at: Vec<(u32, u32, u8)> = got.iter().map(|x| (x.epoch, x.j, x.kind)).collect();
            assert_eq!(at, vec![(1, 2, 0), (2, 0, 0), (2, 0, 1)]);
            // The step before (2, 0), then everything below it goes
            put_names(store, GRP, &[n(2, 0, 2)]).await.unwrap();
            assert_eq!(sweep_names(store, GRP, &GEN, (2, 0)).await.unwrap(), 2);
            let left = names(store, GRP, &GEN, (0, 0), (9, 9)).await.unwrap();
            let at: Vec<(u32, u32, u8)> = left.iter().map(|x| (x.epoch, x.j, x.kind)).collect();
            assert_eq!(at, vec![(2, 0, 0), (2, 0, 1), (2, 0, 2), (3, 1, 0)]);
            assert_eq!(left[3], n(3, 1, 0));
        }
    }

    #[tokio::test]
    async fn headers_with_no_reason_left_are_swept() {
        let dbs = databases().await;
        for store in &dbs.stores {
            open(store).await;
            genesis(store, &[]).await;
            let moved = open_epoch(store, 1, 2, 2, V2, &[rec(1)], HeadMove::default()).await;
            assert_eq!(moved, Moved::Done);
            assert!(set_keep(store, GRP, &[1; 32], 0).await.unwrap());
            assert!(!set_keep(store, GRP, &[9; 32], 0).await.unwrap());
            assert_eq!(sweep_headers(store, GRP).await.unwrap(), 1);
            assert_eq!(header(store, GRP, &[1; 32]).await.unwrap(), None);
            assert!(header(store, GRP, &[2; 32]).await.unwrap().is_some());
            // And the keyrings of epochs before the head's
            assert_eq!(
                crate::gk::store::sweep_keyrings(store, GRP, &GEN, 2)
                    .await
                    .unwrap(),
                2
            );
        }
    }

    #[tokio::test]
    async fn a_big_commit_goes_in_batches_and_lands_whole() {
        let dbs = databases().await;
        for store in &dbs.stores {
            open(store).await;
            genesis(store, &[]).await;
            // 2500 joiners in buckets of 62: past two batches of everything
            let joiners: Vec<SeatRec> = (100..2600).map(rec).collect();
            let buckets: Vec<(u64, u64, &[SeatRec])> = joiners
                .chunks(62)
                .enumerate()
                .map(|(i, s)| (u64::MAX - 100 - i as u64, (1 << 63) | (100 + i as u64), s))
                .collect();
            let c = begin_commit(store, GRP).await.unwrap();
            let vs: Vec<(u64, u64)> = buckets.iter().map(|b| (b.0, b.1)).collect();
            assert_eq!(put_vids(store, GRP, c, &GEN, &vs).await.unwrap(), None);
            let lists: Vec<List> = buckets
                .iter()
                .map(|(b, v, s)| version(*b, *v, 1, s))
                .collect();
            assert_eq!(put_lists(store, GRP, c, &GEN, &lists).await.unwrap(), None);
            let mut seats_in = Vec::new();
            let mut rows_in = Vec::new();
            let mut welcomes_in = Vec::new();
            for (b, v, s) in &buckets {
                for r in *s {
                    let i = u16::from_be_bytes([r[1], r[2]]);
                    seats_in.push(new_seat(i, *b));
                    rows_in.push(row_to(*b, *v, *r, 1));
                    welcomes_in.push(seat_welcome(*r, *b, *v));
                }
            }
            put_new_seats(store, GRP, c, &GEN, &seats_in).await.unwrap();
            put_rows(store, GRP, c, &GEN, &rows_in).await.unwrap();
            put_welcomes(store, GRP, c, &GEN, &welcomes_in)
                .await
                .unwrap();
            let seals_in: Vec<Seal> = buckets
                .iter()
                .map(|(b, v, _)| Seal {
                    epoch: 1,
                    b: *b,
                    v: *v,
                    bytes: vec![1; 60],
                })
                .collect();
            put_seals(store, GRP, c, &GEN, &seals_in).await.unwrap();
            // A row to a version this commit did not list is refused
            let stray = [row_to(B2, V2, rec(5), 1)];
            assert!(put_rows(store, GRP, c, &GEN, &stray).await.is_err());
            let mv = HeadMove {
                was: Some([1; 32]),
                ..Default::default()
            };
            let h = head(2, GEN, 1, 1);
            assert_eq!(
                move_head(store, GRP, c, &h, &mv).await.unwrap(),
                Moved::Done
            );
            assert_eq!(
                current_lists(store, GRP, &GEN).await.unwrap().len(),
                buckets.len() + 1
            );
            assert_eq!(seats(store, GRP, &GEN).await.unwrap().len(), 2501);
            assert_eq!(
                seals(store, GRP, &GEN, 1).await.unwrap().len(),
                buckets.len() + 1
            );
            let (b, v, s) = buckets[40];
            let got = list(store, GRP, &GEN, b, v).await.unwrap().unwrap();
            assert_eq!((got.b, got.v, got.seats.as_slice()), (b, v, s));
            let mine = rows_of_seat(store, GRP, &GEN, &s[0]).await.unwrap();
            assert_eq!(mine, vec![row_to(b, v, s[0], 1)]);
            let w = welcome(store, GRP, &GEN, &s[1], WelcomeKind::Seat, 1)
                .await
                .unwrap();
            assert_eq!(w.unwrap().version, Some((b, v)));
            assert!(stored_bytes(store, GRP).await.unwrap() > 2500 * 1694);
        }
    }
}
