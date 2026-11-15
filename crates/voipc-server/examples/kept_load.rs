// The kept path at a big community's shape, through the relay's own `accounts/log.rs`, on a
// scratch database: rows, bytes a row, disk, and the lines `kept_seats`'s default rests on.
//
//   kept_load <database url> [--seats 2000] [--channels 300] [--pairs 1500] [--chains 20]
//             [--buckets 60] [--window 10000] [--posts-a-day 173000] [--jobs 4] [--lock file]
//             [--fill-only | --measure]
//
// `--pairs` is writers in channels, `--chains` how many each has past its first, `--buckets`
// how many a chain is sealed to. Every seat, chain, step and leave goes through `log`, with
// rows of their true sizes (the relay opens none of them). Entries go in by `append`'s own
// statement in big transactions: a real `append` writes a whole window in hours, and it is
// what is measured afterwards. `--fill-only` stops there, and `--measure` times what an earlier
// fill left, with the same numbers, so a copy of it can be timed again. A run changes what it
// times, so give it a fresh one each time. It exits non-zero if a line does not hold, and stops
// under 15 GiB of free memory. Beside each line it says what the disk had to do with it.

use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use l4f_accounts::model::{AccountId, NewUser, User};
use l4f_accounts::store::{Store, StoreConn};
use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};
use sqlx::AssertSqlSafe;
use tokio::task::JoinSet;
use voipc_crypto::log::{chain_epoch, OWN_ROW_BYTES, ROW_BYTES};
use voipc_protocol::messages::{AccountReply, BucketIn, ChainAsk, ChainRow, ChainSeal, WrapIn};

use log::{ChainFrame, Sharing};

/// Dispatch over the two backends, as `accounts.rs` has it for `log`.
macro_rules! db {
    ($store:expr, $pool:ident => $body:block) => {
        match $store {
            Store::Pg(b) => {
                let $pool = &b.0;
                $body
            }
            Store::Lite(b) => {
                let $pool = &b.0;
                $body
            }
        }
    };
}

// The real file. This run uses part of it.
#[allow(dead_code)]
#[path = "../src/accounts/log.rs"]
mod log;

/// What `log` reads of the real `accounts::Relay`, whose `open` needs the whole server.
pub struct Relay {
    store: Store,
    pub accounts: NoScopes,
    pub cloud: bool,
    pub quota: i64,
    pub retention_ms: i64,
    pub kept_window: i64,
    pub kept_seats: i64,
    pub kept_room: dashmap::DashMap<[u8; 16], (i64, i64)>,
    pub logkey_changes: dashmap::DashMap<[u8; 16], (u32, i64)>,
}

pub struct NoScopes;

impl NoScopes {
    pub async fn effective_scopes(&self, _: &User) -> Result<Vec<String>> {
        Ok(Vec::new())
    }
}

impl Relay {
    pub fn store(&self) -> &Store {
        &self.store
    }

    pub async fn identity(&self, _: AccountId) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }
}

fn refused(request: &str, reason: &str) -> AccountReply {
    AccountReply::Error {
        request: request.into(),
        reason: reason.into(),
    }
}

type Id = [u8; 16];

/// The budget. A post's line is the relay's own part, about 20 posts a second on one core
/// when each is a first count at 5000 seats; with the disk, what a bare commit takes on top.
const POST_P95_MS: f64 = 25.0;
const ROTATION_MS: f64 = 200.0;
const OTHERS_WAIT_MS: f64 = 500.0;
/// Once per person, at their first connect, and it holds up nobody on Postgres.
const NEWCOMER_MS: f64 = 500.0;
/// What the design measured a row at: SQLite, Postgres. A line at a quarter over.
const SEAT_BYTES: (f64, f64) = (101.4, 236.0);
const SEAL_BYTES: (f64, f64) = (83.7, 179.5);
const TEXT_BYTES: (f64, f64) = (391.0, 484.0);
/// Steps a chain takes in the design's model, one direct row to an arrival each.
const STEPS: usize = 4;
/// A writer's app's frame room, and a real first post's bucket (`sync/chains.rs`).
const FRAME_BYTES: usize = 56 * 1024;
const BUCKET_SEATS: usize = 62;
const WRITERS_PER_ACCOUNT: usize = 4;
const GRACE_DAYS: i64 = 3;
const MIN_FREE_GIB: u64 = 15;
/// Accounts past the seats, for the newcomers.
const EXTRA_ACCOUNTS: usize = 40;
/// What fills the default 50 MB quota, at the 250 B a post these rows come to.
const HEAVY_ENTRIES: usize = 200_000;
/// A leave from every channel at a busy hour: each writer's next post is a rotation, and
/// the clone's day comes to 2 posts a second, so ten times that.
const STORM_RATE: u32 = 20;

const TABLES: [&str; 13] = [
    "voipc_members",
    "voipc_log",
    "voipc_writers",
    "voipc_chains",
    "voipc_seats",
    "voipc_seals",
    "voipc_chain_steps",
    "voipc_chain_wraps",
    "voipc_bucket_lists",
    "voipc_bucket_links",
    "voipc_pending",
    "voipc_left",
    "voipc_log_floors",
];

struct Args {
    url: String,
    seats: usize,
    channels: usize,
    pairs: usize,
    chains: usize,
    buckets: usize,
    window: usize,
    posts_a_day: usize,
    jobs: usize,
    lock: Option<String>,
    fill_only: bool,
    measure: bool,
}

impl Args {
    fn parse() -> Result<Args> {
        let mut args = std::env::args().skip(1);
        let url = args
            .next()
            .ok_or_else(|| anyhow!("usage: kept_load <database url> [--seats N] ..."))?;
        let mut a = Args {
            url,
            seats: 2000,
            channels: 300,
            pairs: 1500,
            chains: 20,
            buckets: 60,
            window: 10_000,
            posts_a_day: 173_000,
            jobs: 4,
            lock: None,
            fill_only: false,
            measure: false,
        };
        while let Some(flag) = args.next() {
            if flag == "--fill-only" || flag == "--measure" {
                a.fill_only |= flag == "--fill-only";
                a.measure |= flag == "--measure";
                continue;
            }
            let value = args.next().ok_or_else(|| anyhow!("{flag} needs a value"))?;
            if flag == "--lock" {
                a.lock = Some(value);
                continue;
            }
            let value: usize = value.parse()?;
            match flag.as_str() {
                "--seats" => a.seats = value,
                "--channels" => a.channels = value,
                "--pairs" => a.pairs = value,
                "--chains" => a.chains = value,
                "--buckets" => a.buckets = value,
                "--window" => a.window = value,
                "--posts-a-day" => a.posts_a_day = value,
                "--jobs" => a.jobs = value,
                _ => bail!("unknown flag {flag}"),
            }
        }
        Ok(a)
    }
}

fn free_gib() -> u64 {
    let meminfo = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
    meminfo
        .lines()
        .find_map(|l| l.strip_prefix("MemAvailable:"))
        .and_then(|l| l.trim().trim_end_matches(" kB").parse::<u64>().ok())
        .map_or(u64::MAX, |kb| kb / (1024 * 1024))
}

/// Stops the run, for the machine's sake: a figure is not worth an editor killed. Something
/// else on the machine may be having its moment, so it first gives that ten minutes.
async fn watch_memory() {
    let since = Instant::now();
    while free_gib() < MIN_FREE_GIB {
        if since.elapsed() > Duration::from_secs(600) {
            eprintln!("stopped: under {MIN_FREE_GIB} GiB of memory free for ten minutes");
            std::process::exit(2);
        }
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}

/// Waits for `--lock`'s file, the machine's lane lock, and holds it while timing: browsers
/// and another relay on the same disk are what the figures would otherwise measure.
async fn quiet(lock: Option<String>) -> Result<Option<std::fs::File>> {
    let Some(path) = lock else {
        return Ok(None);
    };
    let file = std::fs::File::open(&path).with_context(|| path.clone())?;
    let file = tokio::task::spawn_blocking(move || file.lock().map(|_| file)).await??;
    Ok(Some(file))
}

fn percentile(values: &mut [f64], p: usize) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.sort_unstable_by(f64::total_cmp);
    values[(values.len() * p / 100).min(values.len() - 1)]
}

fn millis(since: Instant) -> f64 {
    since.elapsed().as_secs_f64() * 1000.0
}

fn bytes(rng: &mut impl RngCore, n: usize) -> Vec<u8> {
    let mut v = vec![0; n];
    rng.fill_bytes(&mut v);
    v
}

/// One writer in one channel, as its app would know itself.
struct Pair {
    conv: String,
    me: Id,
    chain: u32,
    epoch: u32,
    buckets: Vec<Bucket>,
    /// Those who get a step and a row of their own in each chain, as arrivals do.
    arrivals: Vec<Id>,
}

struct Bucket {
    id: u64,
    version: u32,
    seats: Vec<Id>,
}

impl Pair {
    fn new(conv: String, me: Id) -> Pair {
        Pair {
            conv,
            me,
            chain: 0,
            epoch: 0,
            buckets: Vec::new(),
            arrivals: Vec::new(),
        }
    }

    /// A writer's first chain, in the frames `build_chain` makes.
    fn first_post(
        &mut self,
        seats: &[Id],
        bucket_seats: usize,
        rng: &mut StdRng,
    ) -> Vec<ChainFrame> {
        self.chain = 1;
        self.epoch = chain_epoch(self.chain, 0).expect("a chain's number");
        let mut frames = vec![self.frame()];
        frames[0].self_wrap = Some(bytes(rng, ROW_BYTES));
        for chunk in seats.chunks(bucket_seats) {
            let bucket = Bucket {
                id: rng.gen::<u64>() >> 1,
                version: 0,
                seats: chunk.to_vec(),
            };
            let row = bucket_in(self.me, &bucket, None, rng);
            let room: usize = frames.last().map_or(0, |f| {
                f.buckets
                    .iter()
                    .map(|b| 296 + b.list.len() + b.seats.len() * 112)
                    .sum()
            });
            if room + 296 + row.list.len() + row.seats.len() * 112 > FRAME_BYTES {
                frames.push(self.frame());
            }
            let frame = frames.last_mut().expect("a frame");
            frame.seals.push(seal_of(&bucket, rng));
            frame.buckets.push(row);
            self.buckets.push(bucket);
        }
        if let Some(last) = frames.last_mut() {
            last.last = true;
        }
        frames
    }

    /// A new chain, as a leave asks: `gone`'s bucket at a new version, a seal to every bucket.
    fn rotate(&mut self, gone: &Id, rng: &mut StdRng) -> ChainFrame {
        let older = self.chain;
        self.chain += 1;
        self.epoch = chain_epoch(self.chain, 0).expect("a chain's number");
        let mut frame = self.frame();
        frame.self_wrap = Some(bytes(rng, ROW_BYTES));
        frame.link = Some((older, bytes(rng, ROW_BYTES)));
        frame.last = true;
        if let Some(b) = self.buckets.iter_mut().find(|b| b.seats.contains(gone)) {
            b.seats.retain(|s| s != gone);
            let old = b.version;
            b.version += 1;
            frame.buckets.push(bucket_in(
                self.me,
                b,
                Some((old, bytes(rng, ROW_BYTES))),
                rng,
            ));
        }
        frame.seals = self.buckets.iter().map(|b| seal_of(b, rng)).collect();
        frame
    }

    /// The steps of the newest chain, one for each arrival.
    fn steps(&mut self, rng: &mut StdRng) -> Vec<ChainFrame> {
        let arrivals = self.arrivals.clone();
        arrivals
            .iter()
            .enumerate()
            .map(|(i, a)| {
                let index = i as u32 + 1;
                self.epoch = chain_epoch(self.chain, index).expect("a step's index");
                let mut frame = self.frame();
                frame.step = Some(bytes(rng, ROW_BYTES));
                frame.last = true;
                frame.wraps = vec![ChainRow {
                    recipient: *a,
                    index,
                    wrapped: bytes(rng, ROW_BYTES),
                }];
                frame
            })
            .collect()
    }

    fn frame(&self) -> ChainFrame {
        ChainFrame {
            epoch: self.epoch,
            self_wrap: None,
            step: None,
            link: None,
            wraps: Vec::new(),
            buckets: Vec::new(),
            seals: Vec::new(),
            last: false,
        }
    }
}

fn bucket_in(me: Id, b: &Bucket, down: Option<(u32, Vec<u8>)>, rng: &mut StdRng) -> BucketIn {
    let mut seats = vec![WrapIn {
        recipient: me,
        wrapped: bytes(rng, OWN_ROW_BYTES),
    }];
    seats.extend(b.seats.iter().map(|s| WrapIn {
        recipient: *s,
        wrapped: bytes(rng, ROW_BYTES),
    }));
    BucketIn {
        bucket: b.id,
        version: b.version,
        list: bytes(rng, 28 + 24 * b.seats.len()),
        seats,
        down,
    }
}

fn seal_of(b: &Bucket, rng: &mut StdRng) -> ChainSeal {
    ChainSeal {
        bucket: b.id,
        version: b.version,
        index: 0,
        sealed: bytes(rng, ROW_BYTES),
    }
}

async fn put(relay: &Relay, me: Id, conv: &str, frame: ChainFrame) -> Result<()> {
    let sharing = Sharing {
        shares: true,
        may: true,
    };
    let (reply, _) = log::chain_put(relay, AccountId(me), conv, frame, sharing).await?;
    match reply {
        AccountReply::ChainStored { behind: false, .. } => Ok(()),
        other => bail!("{conv}: a chain frame came to {other:?}"),
    }
}

async fn post(relay: &Relay, pair: (&str, Id, u32), ct: &[u8]) -> Result<()> {
    let (conv, me, epoch) = pair;
    let reply = log::append(relay, AccountId(me), conv, epoch, ct, None).await?;
    match reply {
        AccountReply::LogAppended { .. } => Ok(()),
        other => bail!("{conv}: a post came to {other:?}"),
    }
}

async fn migrate(store: &Store) -> Result<()> {
    l4f_accounts::migrate::run(store)
        .await
        .context("account migrations")?;
    fn ours(mut m: sqlx::migrate::Migrator) -> sqlx::migrate::Migrator {
        m.dangerous_set_table_name("voipc_migrations");
        m.set_locking(false);
        m
    }
    let mut held = l4f_accounts::migrate::lock(store).await?;
    let r = match held.conn() {
        StoreConn::Pg(c) => ours(sqlx::migrate!("migrations/postgres")).run(c).await,
        StoreConn::Lite(c) => ours(sqlx::migrate!("migrations/sqlite")).run(c).await,
    };
    l4f_accounts::migrate::unlock(held).await;
    Ok(r?)
}

async fn accounts(store: &Store, n: usize, first: usize, rng: &mut StdRng) -> Result<Vec<Id>> {
    let mut ids = Vec::with_capacity(n);
    for i in first..first + n {
        let id: Id = rng.gen();
        store
            .create_user(
                &NewUser {
                    id: AccountId(id),
                    username: format!("load{i}"),
                    display_name: format!("load{i}"),
                    email_pending: None,
                    password_hash: None,
                    created_at: 1,
                },
                None,
            )
            .await
            .map_err(|e| anyhow!("account {i}: {e:?}"))?;
        ids.push(id);
    }
    Ok(ids)
}

/// Who else is in a channel, by what the relay says, as a writer's first post asks.
async fn members_but(relay: &Relay, me: Id, conv: &str) -> Result<Vec<Id>> {
    let (mut out, mut after) = (Vec::new(), None);
    loop {
        let reply = log::member_ids(relay, AccountId(me), conv, after).await?;
        let AccountReply::LogMemberIdsFound { ids, more, .. } = reply else {
            bail!("{conv}: the members came to {reply:?}");
        };
        after = ids.last().copied();
        out.extend(ids.into_iter().filter(|i| *i != me));
        if !more {
            return Ok(out);
        }
    }
}

/// A commit with next to nothing in it, each: what this disk asks of anything that writes.
async fn bare_commits(store: &Store) -> Result<(f64, f64)> {
    let mut times = Vec::new();
    for i in 0..200 {
        let at = Instant::now();
        let v = (i as i64).to_le_bytes();
        db!(store, pool => {
            sqlx::query(
                "INSERT INTO voipc_meta (k, v) VALUES ('kept_load', $1) ON CONFLICT (k) DO UPDATE SET v = excluded.v",
            )
            .bind(&v[..])
            .execute(pool)
            .await?;
        });
        times.push(millis(at));
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    Ok((percentile(&mut times, 50), percentile(&mut times, 95)))
}

async fn sync_level(store: &Store) -> Result<String> {
    Ok(match store {
        Store::Pg(b) => {
            sqlx::query_scalar("SELECT setting FROM pg_settings WHERE name = 'synchronous_commit'")
                .fetch_one(&b.0)
                .await?
        }
        Store::Lite(b) => {
            let level: i64 = sqlx::query_scalar("SELECT synchronous FROM pragma_synchronous()")
                .fetch_one(&b.0)
                .await?;
            level.to_string()
        }
    })
}

/// What `append` writes, a transaction's worth.
struct EntryRow {
    conv: String,
    sender: Id,
    epoch: u32,
    server_at: i64,
    keep_until: i64,
    ct: Vec<u8>,
}

async fn write_entries(store: &Store, rows: &[EntryRow]) -> Result<()> {
    macro_rules! all {
        ($pool:expr) => {{
            let mut tx = $pool.begin().await?;
            for r in rows {
                sqlx::query(
                    "INSERT INTO voipc_log (conv, sender, epoch, server_at, keep_until, ct) VALUES ($1, $2, $3, $4, $5, $6)",
                )
                .bind(r.conv.as_str())
                .bind(&r.sender[..])
                .bind(i64::from(r.epoch))
                .bind(r.server_at)
                .bind(r.keep_until)
                .bind(r.ct.as_slice())
                .execute(&mut *tx)
                .await?;
            }
            tx.commit().await?;
        }};
    }
    match store {
        Store::Pg(b) => all!(&b.0),
        Store::Lite(b) => all!(&b.0),
    }
    Ok(())
}

/// Every chain and bucket as if made a month ago, or the sweep spares them all as young.
async fn age_keys(store: &Store) -> Result<()> {
    let month = 30 * 86_400i64;
    macro_rules! both {
        ($pool:expr) => {{
            sqlx::query("UPDATE voipc_chains SET created_at = created_at - $1")
                .bind(month)
                .execute($pool)
                .await?;
            sqlx::query("UPDATE voipc_bucket_lists SET created_at = created_at - $1")
                .bind(month)
                .execute($pool)
                .await?;
        }};
    }
    match store {
        Store::Pg(b) => both!(&b.0),
        Store::Lite(b) => both!(&b.0),
    }
    Ok(())
}

async fn table_rows(store: &Store, table: &str) -> Result<i64> {
    let sql = format!("SELECT COUNT(*) FROM {table}");
    Ok(match store {
        Store::Pg(b) => {
            sqlx::query_scalar(AssertSqlSafe(sql))
                .fetch_one(&b.0)
                .await?
        }
        Store::Lite(b) => {
            sqlx::query_scalar(AssertSqlSafe(sql))
                .fetch_one(&b.0)
                .await?
        }
    })
}

/// A table with its indexes on disk, and the whole database.
async fn table_bytes(store: &Store, table: &str) -> Result<i64> {
    Ok(match store {
        Store::Pg(b) => {
            sqlx::query_scalar("SELECT pg_total_relation_size(CAST($1 AS regclass))")
                .bind(table)
                .fetch_one(&b.0)
                .await?
        }
        Store::Lite(b) => {
            sqlx::query_scalar(
                "SELECT CAST(COALESCE(SUM(pgsize), 0) AS BIGINT) FROM dbstat
                  WHERE name IN (SELECT name FROM sqlite_master WHERE tbl_name = $1)",
            )
            .bind(table)
            .fetch_one(&b.0)
            .await?
        }
    })
}

async fn database_bytes(store: &Store) -> Result<i64> {
    Ok(match store {
        Store::Pg(b) => {
            sqlx::query_scalar("SELECT pg_database_size(current_database())")
                .fetch_one(&b.0)
                .await?
        }
        Store::Lite(b) => {
            sqlx::query_scalar(
                "SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()",
            )
            .fetch_one(&b.0)
            .await?
        }
    })
}

struct Sizes {
    rows: Vec<i64>,
    bytes: Vec<i64>,
    total: i64,
}

impl Sizes {
    async fn read(store: &Store) -> Result<Sizes> {
        let (mut rows, mut bytes) = (Vec::new(), Vec::new());
        for t in TABLES {
            rows.push(table_rows(store, t).await?);
            bytes.push(table_bytes(store, t).await?);
        }
        Ok(Sizes {
            rows,
            bytes,
            total: database_bytes(store).await?,
        })
    }

    fn of(&self, table: &str) -> (i64, f64) {
        let i = TABLES.iter().position(|t| *t == table).expect("a table");
        let per = self.bytes[i] as f64 / self.rows[i].max(1) as f64;
        (self.rows[i], per)
    }

    fn print(&self, when: &str) {
        println!("sizes {when}:");
        println!("| table | rows | MB with indexes | bytes a row |");
        for (i, t) in TABLES.iter().enumerate() {
            println!(
                "| {t} | {} | {:.1} | {:.1} |",
                self.rows[i],
                self.bytes[i] as f64 / 1e6,
                self.bytes[i] as f64 / self.rows[i].max(1) as f64
            );
        }
        println!(
            "| whole database | {} | {:.1} | |",
            self.rows.iter().sum::<i64>(),
            self.total as f64 / 1e6
        );
    }
}

/// Runs up to `jobs` at a time, in order given, and stops at the first error.
async fn in_turn<F>(jobs: usize, work: Vec<F>) -> Result<()>
where
    F: std::future::Future<Output = Result<()>> + Send + 'static,
{
    let mut running = JoinSet::new();
    for job in work {
        while running.len() >= jobs {
            running
                .join_next()
                .await
                .expect("a running job")
                .context("a job")??;
            watch_memory().await;
        }
        running.spawn(job);
    }
    while let Some(done) = running.join_next().await {
        done.context("a job")??;
    }
    Ok(())
}

/// Everything but the measuring, through `log`: seats, writers, chains, then entries.
async fn fill(
    args: &Args,
    relay: Arc<Relay>,
    convs: &[String],
    rng: &mut StdRng,
) -> Result<(Vec<Id>, Vec<Pair>)> {
    let started = Instant::now();
    let store = relay.store();
    let present = vec![true; convs.len()];
    let extra = EXTRA_ACCOUNTS;
    let total = args.seats + args.chains;
    let writers_per_channel = args.pairs.div_ceil(args.channels);
    let writer_pool = args.pairs.div_ceil(WRITERS_PER_ACCOUNT).min(args.seats / 2);
    // Accounts: everyone who ends up seated, those who leave on the way, and later ones
    let ids = accounts(store, total + extra, 0, rng).await?;
    println!("accounts: {:.1} s", started.elapsed().as_secs_f64());

    // Seats, through `join_many`, before anyone writes: a real server's writers came later
    // than most of them, and nobody is owed a key this way.
    let phase = Instant::now();
    let mut seating = Vec::new();
    for id in ids.iter().take(total) {
        let (relay, convs, present, id) = (relay.clone(), convs.to_vec(), present.clone(), *id);
        seating.push(async move {
            let (reply, _) = log::join_many(&relay, AccountId(id), &convs, &present).await?;
            match reply {
                AccountReply::LogJoinedMany { joined, .. } if joined.len() == convs.len() => Ok(()),
                other => bail!("seating: {other:?}"),
            }
        });
    }
    in_turn(args.jobs, seating).await?;
    println!(
        "seats: {:.1} s for {} rows",
        phase.elapsed().as_secs_f64(),
        total * convs.len()
    );

    // Writers. A pool of accounts writes in several channels each, as people do
    let leavers: Vec<Id> = ids[args.seats..total].to_vec();
    let arrivals: Vec<Id> = ids[writer_pool..writer_pool + STEPS].to_vec();
    let bucket_seats = (total - 1 - STEPS).div_ceil(args.buckets).max(1);
    let phase = Instant::now();
    let chains_written = Arc::new(AtomicU64::new(0));
    let done_pairs: Arc<Mutex<Vec<Pair>>> = Arc::new(Mutex::new(Vec::new()));
    let mut work = Vec::new();
    for (c, conv) in convs.iter().enumerate() {
        let writers: Vec<Id> = (0..writers_per_channel)
            .map(|w| ids[(c * writers_per_channel + w) % writer_pool])
            .collect();
        let (relay, conv, ids, leavers, arrivals) = (
            relay.clone(),
            conv.clone(),
            ids[..total].to_vec(),
            leavers.clone(),
            arrivals.clone(),
        );
        let (count, done) = (chains_written.clone(), done_pairs.clone());
        let chains = args.chains;
        let seed = 1000 + c as u64;
        work.push(async move {
            let mut rng = StdRng::seed_from_u64(seed);
            let mut pairs = Vec::new();
            for me in &writers {
                let mut pair = Pair::new(conv.clone(), *me);
                pair.arrivals = arrivals.clone();
                let seats: Vec<Id> = ids
                    .iter()
                    .filter(|s| *s != me && !arrivals.contains(s))
                    .copied()
                    .collect();
                for frame in pair.first_post(&seats, bucket_seats, &mut rng) {
                    put(&relay, *me, &conv, frame).await?;
                }
                for frame in pair.steps(&mut rng) {
                    put(&relay, *me, &conv, frame).await?;
                }
                pairs.push(pair);
            }
            // Each chain past the first: someone leaves, every writer there moves on
            for gone in leavers.iter().take(chains) {
                log::remove(relay.store(), &conv, gone).await?;
                for pair in &mut pairs {
                    let frame = pair.rotate(gone, &mut rng);
                    put(&relay, pair.me, &conv, frame).await?;
                    for frame in pair.steps(&mut rng) {
                        put(&relay, pair.me, &conv, frame).await?;
                    }
                }
                count.fetch_add(pairs.len() as u64, Ordering::Relaxed);
            }
            done.lock().expect("pairs").extend(pairs);
            Ok(())
        });
    }
    in_turn(args.jobs, work).await?;
    let mut pairs = std::mem::take(&mut *done_pairs.lock().expect("pairs"));
    pairs.sort_by(|a, b| a.conv.cmp(&b.conv));
    println!(
        "chains: {:.1} s for {} pairs, {} later chains",
        phase.elapsed().as_secs_f64(),
        pairs.len(),
        chains_written.load(Ordering::Relaxed)
    );
    watch_memory().await;

    // Entries. Each channel holds its window, three days it does not count yet, and a day
    // over for the sweep to take, spread back from now at the day's rate
    let phase = Instant::now();
    let posts_a_day_here = (args.posts_a_day / args.channels).max(1);
    let every_ms = 86_400_000 / posts_a_day_here as i64;
    let entries_here = args.window + (GRACE_DAYS as usize + 1) * posts_a_day_here;
    let now = log::now_ms();
    let mut work = Vec::new();
    for (c, conv) in convs.iter().enumerate() {
        let conv = conv.clone();
        let relay = relay.clone();
        let here: Vec<Id> = pairs
            .iter()
            .filter(|p| p.conv == conv)
            .map(|p| p.me)
            .collect();
        let chains = args.chains as u64 + 1;
        let retention = relay.retention_ms;
        let seed = 5000 + c as u64;
        work.push(async move {
            let mut rng = StdRng::seed_from_u64(seed);
            let mut rows = Vec::with_capacity(2000);
            for e in 0..entries_here {
                let chain = 1 + (e as u64 * chains / entries_here as u64) as u32;
                let server_at = now - every_ms * (entries_here - e) as i64;
                let len = rng.gen_range(150..350);
                rows.push(EntryRow {
                    conv: conv.clone(),
                    sender: here[e % here.len()],
                    epoch: chain_epoch(chain, STEPS as u32).expect("a chain"),
                    server_at,
                    keep_until: server_at + retention,
                    ct: bytes(&mut rng, len),
                });
                if rows.len() == 2000 {
                    write_entries(relay.store(), &rows).await?;
                    rows.clear();
                }
            }
            write_entries(relay.store(), &rows).await?;
            Ok(())
        });
    }
    in_turn(args.jobs, work).await?;
    println!(
        "entries: {:.1} s for {} rows",
        phase.elapsed().as_secs_f64(),
        entries_here * convs.len()
    );
    age_keys(store).await?;
    watch_memory().await;

    Ok((ids, pairs))
}

/// What a fill left, as `fill` would have said it.
async fn load(relay: &Relay) -> Result<(Vec<Id>, Vec<Pair>)> {
    let store = relay.store();
    let users: Vec<(Vec<u8>, String)> = db!(store, pool => {
        sqlx::query_as("SELECT id, username FROM acct_users WHERE username LIKE 'load%'")
            .fetch_all(pool)
            .await?
    });
    let mut ids = vec![[0u8; 16]; users.len()];
    for (id, name) in users {
        ids[name[4..].parse::<usize>()?] = id.as_slice().try_into()?;
    }
    let writers: Vec<(i32, String, Vec<u8>, i32)> = db!(store, pool => {
        sqlx::query_as("SELECT id, conv, owner, newest_chain FROM voipc_writers ORDER BY conv, id")
            .fetch_all(pool)
            .await?
    });
    let mut pairs = Vec::with_capacity(writers.len());
    for (writer, conv, owner, newest) in writers {
        let me: Id = owner.as_slice().try_into()?;
        let (chain_id, top): (i32, i16) = db!(store, pool => {
            sqlx::query_as("SELECT id, top FROM voipc_chains WHERE writer = $1 AND chain = $2")
                .bind(writer)
                .bind(newest)
                .fetch_one(pool)
                .await?
        });
        let versions: Vec<(i64, i32)> = db!(store, pool => {
            sqlx::query_as("SELECT bucket, MAX(version) FROM voipc_bucket_lists WHERE writer = $1 GROUP BY bucket")
                .bind(writer)
                .fetch_all(pool)
                .await?
        });
        let seats: Vec<(Vec<u8>, i64, i32)> = db!(store, pool => {
            sqlx::query_as("SELECT recipient, bucket, version FROM voipc_seats WHERE writer = $1")
                .bind(writer)
                .fetch_all(pool)
                .await?
        });
        let arrivals: Vec<Vec<u8>> = db!(store, pool => {
            sqlx::query_scalar("SELECT recipient FROM voipc_chain_wraps WHERE writer = $1 AND chain_id = $2 ORDER BY idx")
                .bind(writer)
                .bind(chain_id)
                .fetch_all(pool)
                .await?
        });
        let mut pair = Pair::new(conv, me);
        pair.chain = newest as u32;
        pair.epoch = chain_epoch(pair.chain, top as u32).ok_or_else(|| anyhow!("an epoch"))?;
        for a in arrivals {
            pair.arrivals.push(a.as_slice().try_into()?);
        }
        for (bucket, version) in versions {
            let mut b = Bucket {
                id: bucket as u64,
                version: version as u32,
                seats: Vec::new(),
            };
            for (who, _, _) in seats.iter().filter(|s| s.1 == bucket && s.2 == version) {
                if who.as_slice() != me {
                    b.seats.push(who.as_slice().try_into()?);
                }
            }
            pair.buckets.push(b);
        }
        pairs.push(pair);
    }
    Ok((ids, pairs))
}

/// Writes all that waits to its place, or a fill's aftermath is what gets timed.
async fn settle(store: &Store) -> Result<()> {
    match store {
        Store::Pg(b) => {
            sqlx::query("VACUUM ANALYZE").execute(&b.0).await?;
            sqlx::query("CHECKPOINT").execute(&b.0).await?;
        }
        Store::Lite(b) => {
            sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
                .execute(&b.0)
                .await?;
        }
    }
    Ok(())
}

/// The same database, with commits that do not wait for the disk: what is left of a line then
/// is the relay's own, and the rest is this machine's fsync.
async fn store_without_sync(url: &str) -> Result<Store> {
    use std::str::FromStr;
    Ok(if url.starts_with("sqlite") {
        let opts = sqlx::sqlite::SqliteConnectOptions::from_str(url)?
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .pragma("secure_delete", "FAST")
            .synchronous(sqlx::sqlite::SqliteSynchronous::Off);
        sqlx::SqlitePool::connect_with(opts).await?.into()
    } else {
        let opts = sqlx::postgres::PgConnectOptions::from_str(url)?
            .options([("synchronous_commit", "off")]);
        sqlx::PgPool::connect_with(opts).await?.into()
    })
}

/// How every line went, for the exit code.
#[derive(Default)]
struct Lines(Vec<String>);

impl Lines {
    /// One line of the budget: `measured` must stay under `limit`.
    fn check(&mut self, what: &str, measured: f64, limit: f64) {
        let held = measured < limit;
        println!(
            "line: {what}: {measured:.2} against {limit:.2}: {}",
            if held { "holds" } else { "DOES NOT HOLD" }
        );
        if !held {
            self.0
                .push(format!("{what}: {measured:.2} against {limit:.2}"));
        }
    }

    fn same(&mut self, what: &str, measured: i64, want: i64) {
        println!("rows: {what}: {measured}, expected {want}");
        if measured != want {
            self.0.push(format!("{what}: {measured} rows, not {want}"));
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse()?;
    let started = Instant::now();
    // A fill is not what is timed, and a commit a row would take it hours on SQLite
    let store = if args.fill_only {
        store_without_sync(&args.url).await?
    } else {
        Store::connect(&args.url)
            .await
            .with_context(|| args.url.clone())?
    };
    migrate(&store).await?;
    let lite = matches!(store, Store::Lite(_));
    let relay = Arc::new(Relay {
        store,
        accounts: NoScopes,
        cloud: true,
        // Above what a quota asks at this shape: it is not what is being measured
        quota: i64::MAX / 2,
        retention_ms: 365 * 86_400_000,
        kept_window: args.window as i64,
        kept_seats: 0,
        kept_room: Default::default(),
        logkey_changes: Default::default(),
    });
    let store = relay.store();
    let mut rng = StdRng::seed_from_u64(21);
    let mut lines = Lines::default();
    println!(
        "{} seats, {} channels, {} pairs, {} chains a pair past the first, {} buckets, window {}, {} posts a day",
        args.seats, args.channels, args.pairs, args.chains, args.buckets, args.window, args.posts_a_day
    );

    let convs: Vec<String> = (0..args.channels).map(|c| format!("c:{c:016x}")).collect();
    let present = vec![true; convs.len()];
    let extra = EXTRA_ACCOUNTS;
    let total = args.seats + args.chains;
    let writers_per_channel = args.pairs.div_ceil(args.channels);
    let writer_pool = args.pairs.div_ceil(WRITERS_PER_ACCOUNT).min(args.seats / 2);
    let (ids, mut pairs) = if args.measure {
        load(relay.as_ref()).await?
    } else {
        fill(&args, relay.clone(), &convs, &mut rng).await?
    };
    settle(store).await?;
    watch_memory().await;

    let filled = Sizes::read(store).await?;
    filled.print("after the fill");
    let frozen = args.chains as i64;
    let seated = (args.seats - 1 - STEPS) as i64;
    let pair_count = pairs.len() as i64;
    let chains = pair_count * (args.chains as i64 + 1);
    let buckets = pairs[0].buckets.len() as i64;
    println!("{buckets} buckets a writer");
    lines.same(
        "seats",
        filled.of("voipc_seats").0,
        pair_count * (seated + buckets + frozen),
    );
    lines.same("seals", filled.of("voipc_seals").0, chains * buckets);
    lines.same("chains", filled.of("voipc_chains").0, chains);
    lines.same(
        "steps",
        filled.of("voipc_chain_steps").0,
        chains * STEPS as i64,
    );
    lines.same(
        "direct rows",
        filled.of("voipc_chain_wraps").0,
        chains * STEPS as i64,
    );
    let (seat_limit, seal_limit, text_limit) = if lite {
        (SEAT_BYTES.0, SEAL_BYTES.0, TEXT_BYTES.0)
    } else {
        (SEAT_BYTES.1, SEAL_BYTES.1, TEXT_BYTES.1)
    };
    lines.check(
        "bytes a seat row",
        filled.of("voipc_seats").1,
        seat_limit * 1.25,
    );
    lines.check(
        "bytes a seal row",
        filled.of("voipc_seals").1,
        seal_limit * 1.25,
    );
    lines.check(
        "bytes a text row",
        filled.of("voipc_log").1,
        text_limit * 1.25,
    );

    if args.fill_only {
        println!("filled, in {:.0} s", started.elapsed().as_secs_f64());
        return Ok(());
    }
    let held = quiet(args.lock.clone()).await?;
    let fast = Relay {
        store: store_without_sync(&args.url).await?,
        accounts: NoScopes,
        cloud: true,
        quota: relay.quota,
        retention_ms: relay.retention_ms,
        kept_window: relay.kept_window,
        kept_seats: relay.kept_seats,
        kept_room: Default::default(),
        logkey_changes: Default::default(),
    };
    let (floor, floor_p95) = bare_commits(store).await?;
    println!(
        "a bare commit on this disk: p50 {floor:.2} ms, p95 {floor_p95:.2} ms, sync level {}; without waiting for the disk: {:.2} ms, level {}",
        sync_level(store).await?,
        bare_commits(fast.store()).await?.0,
        sync_level(fast.store()).await?,
    );

    // A kept post, by writers all over
    let mut times = Vec::new();
    for _ in 0..2000 {
        let p = &pairs[rng.gen_range(0..pairs.len())];
        let ct = bytes(&mut rng, 250);
        let at = Instant::now();
        post(relay.as_ref(), (&p.conv, p.me, p.epoch), &ct).await?;
        times.push(millis(at));
    }
    let post_p95 = percentile(&mut times, 95);
    println!(
        "kept post, 2000 alone: p50 {:.2} ms, p95 {post_p95:.2} ms, max {:.2} ms",
        percentile(&mut times, 50),
        percentile(&mut times, 100)
    );
    lines.check("kept post p95, ms", post_p95, POST_P95_MS + floor_p95);
    let mut times = Vec::new();
    for _ in 0..1000 {
        let p = &pairs[rng.gen_range(0..pairs.len())];
        let ct = bytes(&mut rng, 250);
        let at = Instant::now();
        post(&fast, (&p.conv, p.me, p.epoch), &ct).await?;
        times.push(millis(at));
    }
    println!(
        "kept post, 1000 not waiting for the disk: p50 {:.2} ms, p95 {:.2} ms, max {:.2} ms",
        percentile(&mut times, 50),
        percentile(&mut times, 95),
        percentile(&mut times, 100)
    );
    lines.check(
        "kept post p95 with no disk in it, ms",
        percentile(&mut times, 95),
        POST_P95_MS,
    );
    watch_memory().await;

    // A rotation: one leave, one writer. The leaver goes in a channel of its own for each
    let leaving = ids[writer_pool + STEPS + 10];
    let mut rotations = Vec::new();
    let mut rotations_fast = Vec::new();
    let mut others = Vec::new();
    for (c, conv) in convs.iter().enumerate().take(60) {
        let start = c * writers_per_channel;
        let end = (start + writers_per_channel).min(pairs.len());
        log::remove(store, conv, &leaving).await?;
        for pair in &mut pairs[start..end] {
            let frame = pair.rotate(&leaving, &mut rng);
            let at = Instant::now();
            if c < 40 {
                put(relay.as_ref(), pair.me, conv, frame).await?;
                rotations.push(millis(at));
            } else {
                put(&fast, pair.me, conv, frame).await?;
                rotations_fast.push(millis(at));
            }
            for frame in pair.steps(&mut rng) {
                let at = Instant::now();
                put(relay.as_ref(), pair.me, conv, frame).await?;
                others.push(millis(at));
            }
        }
    }
    let rotation_p95 = percentile(&mut rotations, 95);
    println!(
        "rotation at {} seats, {} alone: p50 {:.2} ms, p95 {rotation_p95:.2} ms, max {:.2} ms; a step after it p95 {:.2} ms",
        args.seats,
        rotations.len(),
        percentile(&mut rotations, 50),
        percentile(&mut rotations, 100),
        percentile(&mut others, 95),
    );
    lines.check("rotation p95, ms", rotation_p95, ROTATION_MS);
    println!(
        "rotation not waiting for the disk, {}: p50 {:.2} ms, p95 {:.2} ms",
        rotations_fast.len(),
        percentile(&mut rotations_fast, 50),
        percentile(&mut rotations_fast, 95),
    );

    // A first post at this size, whole: what the old design's rotation of 2000 was
    let mut firsts = Vec::new();
    let mut frame_ms = Vec::new();
    let first_writers = 5.min(args.channels);
    for c in 0..first_writers {
        let me = ids[writer_pool + STEPS + 20 + c];
        let conv = &convs[args.channels - 1 - c];
        let others = members_but(relay.as_ref(), me, conv).await?;
        let mut pair = Pair::new(conv.clone(), me);
        let frames = pair.first_post(&others, BUCKET_SEATS, &mut rng);
        let at = Instant::now();
        for frame in frames {
            let one = Instant::now();
            put(relay.as_ref(), me, conv, frame).await?;
            frame_ms.push(millis(one));
        }
        firsts.push(millis(at));
    }
    println!(
        "first post to {} seats, {first_writers} whole: p95 {:.1} ms, a frame p95 {:.1} ms, max {:.1} ms",
        args.seats,
        percentile(&mut firsts, 95),
        percentile(&mut frame_ms, 95),
        percentile(&mut frame_ms, 100),
    );
    lines.check(
        "first post, each frame at most, ms",
        percentile(&mut frame_ms, 100),
        ROTATION_MS,
    );
    watch_memory().await;

    // A storm: someone goes from most channels, every writer there moves on at a busy
    // hour's pace, while posts and reads go on elsewhere. Nothing else may wait past the line.
    let leaving = ids[writer_pool + STEPS + 11];
    let storm_channels = (args.channels * 5 / 6).max(1);
    let at = Instant::now();
    for conv in &convs[..storm_channels] {
        log::remove(store, conv, &leaving).await?;
    }
    println!(
        "a leave from {storm_channels} channels: {:.1} ms",
        millis(at)
    );
    let cut = storm_channels * writers_per_channel;
    let bystanders: Vec<Pair> = pairs.split_off(cut.min(pairs.len()));
    let stop = Arc::new(AtomicBool::new(false));
    let waits: Arc<Mutex<Vec<f64>>> = Arc::new(Mutex::new(Vec::new()));
    let failed: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let mut side = JoinSet::new();
    let bystanders: Arc<Vec<Pair>> = Arc::new(bystanders);
    for t in 0..4u64 {
        let (relay, stop, waits, failed, by) = (
            relay.clone(),
            stop.clone(),
            waits.clone(),
            failed.clone(),
            bystanders.clone(),
        );
        side.spawn(async move {
            let mut rng = StdRng::seed_from_u64(9000 + t);
            let reader = by[0].me;
            while !stop.load(Ordering::Relaxed) {
                let p = &by[rng.gen_range(0..by.len())];
                let ct = bytes(&mut rng, 250);
                let at = Instant::now();
                let done = if t % 2 == 0 {
                    post(relay.as_ref(), (&p.conv, p.me, p.epoch), &ct).await
                } else {
                    log::chain_fetch(&relay, AccountId(reader), &p.conv, -200)
                        .await
                        .map(|_| ())
                };
                waits.lock().expect("waits").push(millis(at));
                if let Err(e) = done {
                    failed.lock().expect("failed").push(format!("{e:#}"));
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        });
    }
    let queue: Arc<Mutex<VecDeque<Pair>>> = Arc::new(Mutex::new(pairs.drain(..).collect()));
    let storm_times: Arc<Mutex<Vec<f64>>> = Arc::new(Mutex::new(Vec::new()));
    let moved_on: Arc<Mutex<Vec<Pair>>> = Arc::new(Mutex::new(Vec::new()));
    let phase = Instant::now();
    let mut work = Vec::new();
    for t in 0..2u64 {
        let (relay, queue, times, moved) = (
            relay.clone(),
            queue.clone(),
            storm_times.clone(),
            moved_on.clone(),
        );
        work.push(async move {
            let mut rng = StdRng::seed_from_u64(9100 + t);
            let gap = Duration::from_secs(2) / STORM_RATE;
            loop {
                let next = queue.lock().expect("queue").pop_front();
                let Some(mut pair) = next else {
                    return Ok(());
                };
                let frame = pair.rotate(&leaving, &mut rng);
                let at = Instant::now();
                put(&relay, pair.me, &pair.conv.clone(), frame).await?;
                times.lock().expect("times").push(millis(at));
                moved.lock().expect("moved").push(pair);
                tokio::time::sleep(gap.saturating_sub(at.elapsed())).await;
            }
        });
    }
    in_turn(2, work).await?;
    stop.store(true, Ordering::Relaxed);
    while side.join_next().await.is_some() {}
    let mut storm = std::mem::take(&mut *storm_times.lock().expect("times"));
    let mut waited = std::mem::take(&mut *waits.lock().expect("waits"));
    println!(
        "a storm of {} rotations at {STORM_RATE} a second at most, in {:.1} s: rotation p95 {:.1} ms, max {:.1} ms; {} posts and reads beside it: p95 {:.1} ms, max {:.1} ms",
        storm.len(),
        phase.elapsed().as_secs_f64(),
        percentile(&mut storm, 95),
        percentile(&mut storm, 100),
        waited.len(),
        percentile(&mut waited, 95),
        percentile(&mut waited, 100),
    );
    for e in failed.lock().expect("failed").iter().take(5) {
        println!("beside the storm: {e}");
    }
    lines.check(
        "a rotation in a storm, p95 ms",
        percentile(&mut storm, 95),
        ROTATION_MS,
    );
    lines.check(
        "what else waited past a rotation, most ms",
        percentile(&mut waited, 100),
        OTHERS_WAIT_MS,
    );
    if !failed.lock().expect("failed").is_empty() {
        lines.0.push(format!(
            "{} failed beside a storm",
            failed.lock().unwrap().len()
        ));
    }
    // Back as they were: `Pair`s are no longer needed past the bystanders
    let mut pairs = std::mem::take(&mut *moved_on.lock().expect("moved"));
    pairs.sort_by(|a, b| a.conv.cmp(&b.conv));
    watch_memory().await;

    // A reader: a channel's tail, and the keys of what it read, as a browser's reload asks
    let reader = ids[writer_pool + STEPS + 30];
    let mut page_ms = Vec::new();
    let mut keys_ms = Vec::new();
    let mut whole_ms = Vec::new();
    let mut key_bytes = 0usize;
    for conv in convs.iter().cycle().take(40) {
        let whole = Instant::now();
        let mut after = -500;
        loop {
            let at = Instant::now();
            let reply = log::chain_fetch(relay.as_ref(), AccountId(reader), conv, after).await?;
            page_ms.push(millis(at));
            let AccountReply::ChainPage {
                entries,
                more,
                upto,
                ..
            } = reply
            else {
                bail!("a read: {reply:?}");
            };
            let mut seen = HashSet::new();
            let asks: Vec<ChainAsk> = entries
                .iter()
                .filter(|e| seen.insert((e.sender, e.epoch >> 12)))
                .take(64)
                .map(|e| ChainAsk {
                    owner: e.sender,
                    chain: e.epoch >> 12,
                    from: None,
                })
                .collect();
            let at = Instant::now();
            let keys = log::wraps_page(relay.as_ref(), AccountId(reader), conv, &asks).await?;
            keys_ms.push(millis(at));
            key_bytes += format!("{keys:?}").len() / 4;
            after = upto;
            if !more {
                break;
            }
        }
        whole_ms.push(millis(whole));
    }
    println!(
        "a reader's tail of 500, 40 channels: whole p95 {:.1} ms; a page p95 {:.2} ms; its keys p95 {:.2} ms; about {} KB of keys a channel",
        percentile(&mut whole_ms, 95),
        percentile(&mut page_ms, 95),
        percentile(&mut keys_ms, 95),
        key_bytes / 40 / 1000,
    );
    // A read that finds nothing, what a reconnect sends most: two at it, as two cores' worth
    let phase = Instant::now();
    let reads = Arc::new(AtomicU64::new(0));
    let mut set = JoinSet::new();
    for t in 0..2 {
        let (relay, reads, convs) = (relay.clone(), reads.clone(), convs.clone());
        set.spawn(async move {
            let mut c = t;
            while phase.elapsed() < Duration::from_secs(5) {
                c = (c + 1) % convs.len();
                log::chain_fetch(&relay, AccountId(reader), &convs[c], i64::MAX / 2).await?;
                reads.fetch_add(1, Ordering::Relaxed);
            }
            anyhow::Ok(())
        });
    }
    while let Some(done) = set.join_next().await {
        done??;
    }
    println!(
        "reads with nothing new, two tasks: {:.0} a second",
        reads.load(Ordering::Relaxed) as f64 / phase.elapsed().as_secs_f64()
    );
    watch_memory().await;

    // A writer near the quota: a post sums everything it kept, so this grows with that
    let heavy = &bystanders[0];
    let keep_until = log::now_ms() + relay.retention_ms;
    let mut rows = Vec::with_capacity(2000);
    for e in 0..HEAVY_ENTRIES {
        let len = rng.gen_range(150..350);
        rows.push(EntryRow {
            conv: "c:heavy".to_string(),
            sender: heavy.me,
            epoch: 1 << 12,
            server_at: log::now_ms(),
            keep_until,
            ct: bytes(&mut rng, len),
        });
        if rows.len() == 2000 || e + 1 == HEAVY_ENTRIES {
            write_entries(store, &rows).await?;
            rows.clear();
        }
    }
    settle(store).await?;
    let mut times = Vec::new();
    for _ in 0..200 {
        let ct = bytes(&mut rng, 250);
        let at = Instant::now();
        post(&fast, (&heavy.conv, heavy.me, heavy.epoch), &ct).await?;
        times.push(millis(at));
    }
    println!(
        "kept post by a writer with {HEAVY_ENTRIES} more entries (about the 50 MB quota), not waiting for the disk: p50 {:.2} ms, p95 {:.2} ms",
        percentile(&mut times, 50),
        percentile(&mut times, 95),
    );
    db!(store, pool => {
        sqlx::query("DELETE FROM voipc_log WHERE conv = 'c:heavy'").execute(pool).await?;
    });
    watch_memory().await;

    // A newcomer's seats: every writer that shares is told
    let mut seats_ms = Vec::new();
    let mut seats_fast = Vec::new();
    for (i, id) in ids[total..total + extra].iter().enumerate() {
        let at = Instant::now();
        let on = if i % 2 == 0 { relay.as_ref() } else { &fast };
        let (reply, _) = log::join_many(on, AccountId(*id), &convs, &present).await?;
        if i % 2 == 0 {
            seats_ms.push(millis(at));
        } else {
            seats_fast.push(millis(at));
        }
        if !matches!(&reply, AccountReply::LogJoinedMany { joined, .. } if joined.len() == convs.len())
        {
            bail!("a newcomer: {reply:?}");
        }
    }
    let seats_p95 = percentile(&mut seats_ms, 95);
    println!(
        "a newcomer's {} seats, {extra} of them: p50 {:.1} ms, p95 {seats_p95:.1} ms, max {:.1} ms",
        convs.len(),
        percentile(&mut seats_ms, 50),
        percentile(&mut seats_ms, 100),
    );
    lines.check("a newcomer's seats p95, ms", seats_p95, NEWCOMER_MS);
    println!(
        "a newcomer's seats not waiting for the disk: p50 {:.1} ms, p95 {:.1} ms",
        percentile(&mut seats_fast, 50),
        percentile(&mut seats_fast, 95),
    );
    watch_memory().await;

    // The sweep: a day's worth to take, posts beside it, then a pass with nothing to do
    let by_now = bystanders.clone();
    let stop = Arc::new(AtomicBool::new(false));
    let waits: Arc<Mutex<Vec<f64>>> = Arc::new(Mutex::new(Vec::new()));
    let beside = {
        let (relay, stop, waits) = (relay.clone(), stop.clone(), waits.clone());
        tokio::spawn(async move {
            let mut rng = StdRng::seed_from_u64(9200);
            while !stop.load(Ordering::Relaxed) {
                let p = &by_now[rng.gen_range(0..by_now.len())];
                let ct = bytes(&mut rng, 250);
                let at = Instant::now();
                // A newcomer above waits for this writer's step: its answer is the cost too
                let _ = log::append(&relay, AccountId(p.me), &p.conv, p.epoch, &ct, None).await;
                waits.lock().expect("waits").push(millis(at));
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
    };
    let at = Instant::now();
    let swept = log::sweep(&relay).await?;
    let sweep_ms = millis(at);
    stop.store(true, Ordering::Relaxed);
    beside.await.context("beside the sweep")?;
    let mut sweep_waits = std::mem::take(&mut *waits.lock().expect("waits"));
    println!(
        "a sweep: {:.1} s, {swept} rows; posts beside it: p95 {:.1} ms, max {:.1} ms",
        sweep_ms / 1000.0,
        percentile(&mut sweep_waits, 95),
        percentile(&mut sweep_waits, 100),
    );
    let at = Instant::now();
    let swept = log::sweep(&relay).await?;
    println!(
        "a sweep with nothing new: {:.1} s, {swept} rows",
        millis(at) / 1000.0
    );

    let after = Sizes::read(store).await?;
    after.print("after a sweep");
    println!("whole run: {:.0} s", started.elapsed().as_secs_f64());
    drop((pairs, held));
    if lines.0.is_empty() {
        println!("every line holds");
        Ok(())
    } else {
        for l in &lines.0 {
            println!("line not held: {l}");
        }
        std::process::exit(1)
    }
}
