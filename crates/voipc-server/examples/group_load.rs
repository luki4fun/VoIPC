// The group epoch key (docs/GROUP-KEY.md) at a big community's size (plan part 6, C6): a
// relay this starts itself, and clients over QUIC running the app's own
// `voipc_crypto::group_state` code, the members as the app takes headers and posts, the
// keyholders as C3c's duty ("Help hold keys" on) volunteers, builds, checks and paces.
//
//   group_load storm N [--rate R] [--holders K] [--once] [--offline M]
//     K guest keyholders (2) make the group, then N guests connect R a second (1000) and
//     fetch: how long until every one is seated, by Joins of at most 256, or refused for
//     `RATE` and left unseated (a column of its own: the row's seats are those seated).
//     Then all N drop at once and come back at once (not with `--once`): the reconnect
//     storm, their exits and their Joins together, until the exits' opening is taken.
//
//   group_load exits R [--guests N] [--writers W] [--seconds S] [--offline M] [--lead MS]
//     N guests (2000) seated, W of them (5) posting once a second; for S seconds (120) R
//     guests a second leave and come back 3 s later. Past a third of the way, one of the
//     keyholders resigns MS (300) before the relay's open exit batch closes, so the Remove
//     is out when that batch's opening is asked of another keyholder (gk/group.rs, the
//     slow due's exits); the row counts the openings asked beside a Remove. Posts held
//     and dropped, the openings and the exits each carried.
//
//   `--offline M`: first M offline accounts seated as `seats` seats them, so the guests
//   come to a group of M more seats than this machine could hold connections for.
//
//   group_load seats N [--database URL] [--hold S]
//     N accounts that keep the channel's log, with published seat keys, written into the
//     relay's database (a fresh SQLite file unless URL names an empty Postgres one) and never
//     online: the group's Genesis seats them all eagerly, by Joins of 256 (391 at 100k).
//     How long the re-seat takes against the keyholder's own build time; `--hold S` keeps
//     the group S seconds more for its refreshes.
//
//   group_load --check
//     A few hundred of each, in under a minute, with lines that must hold (commits taken,
//     not only sent; nothing stale, declined, missed or left unseated): the smoke run.
//
// Every mode: [--port P] (29900) [--dir D] (group_load.run) [--relay PATH] (the voipc-server
// beside this example: `cargo build --release -p voipc-server --bins --examples`)
// [--minutes M] (15) [--cpus LIST] (the relay under `taskset -c LIST`). A port already
// taken stops the run before the relay starts. The relay is killed by its pid at the end,
// on SIGINT or SIGTERM, and when free memory falls under 10 GiB or at M minutes.
//
// Keyholders are guest desktops (a group holds at most two of them), each build run whole
// on a blocking thread as the app runs it off the lock. A keyholder's CPU for a commit is
// that build plus what the duty does on the lock: the due's frames (`EpochDue`, the lists
// and keyring it waits for, its joiners' endorsements checked) and `built` (the commit
// cut into frames), timed apart. A commit is taken when a keyholder sees its header pushed
// as the head, or a next due asked on it. Clients pace what they send under the relay's
// budget per connection, as the apps do; a commit's last frame is timed when it is written.
// Clients share the machine with the relay: CPU times of the relay are its own, latencies
// an upper bound. DB time is the relay's SQLite worker threads' CPU, or Postgres's
// `active_time` less this tool's own queries.

#[path = "load_common/mod.rs"]
mod load_common;

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use l4f_accounts::store::Store;
use rand::seq::SliceRandom;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, Notify};
use voipc_crypto::group_key::timers::exit_gap_ms;
use voipc_crypto::group_key::{digest, Endorsement, GroupKind, MemberId, Origin, SeatPair};
use voipc_crypto::group_state::{
    group_id, BuildJob, Built, GkCtx, GkEvent, GkOut, GkStart, GkState, GkTrack, GroupKeying,
    LocalGk, MemoryPins, Platform, VaultFloor,
};
use voipc_crypto::{IdentityKeyPair, SignalStores};
use voipc_protocol::codec::CONTROL_MSGS_PER_SEC;
use voipc_protocol::gk::{due as due_code, refused_what, refused_why, stale};
use voipc_protocol::messages::{ClientMessage, ServerMessage};
use voipc_protocol::types::GroupLoad;

use load_common::{connect_named, enc, next_counted, next_message, Connected, Error};

/// The one text channel, and its log's conversation (a stored group's id on a relay with
/// accounts).
const CHANNEL: &str = "gload";
const CONV: &str = "c:gload";
const ADMIN_TOKEN: &str = "group-load-admin";
const MIN_FREE_GIB: u64 = 10;
/// What a client sends a second, under the relay's per-connection budget.
const SEND_RATE: f64 = CONTROL_MSGS_PER_SEC as f64 * 0.9;
const POST_BYTES: usize = 200;
/// A wait gives up when nobody more was seated for this long.
const STALL: Duration = Duration::from_secs(120);

const USAGE: &str = "usage: group_load storm N [--rate R] [--holders K] [--once] [--offline M] | exits R [--guests N] [--writers W] [--seconds S] [--offline M] [--lead MS] | seats N [--database URL] [--hold S] | --check; each also [--port P] [--dir D] [--relay PATH] [--minutes M] [--cpus LIST]";

/// Dispatch over the two backends, as `accounts.rs` has it.
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

#[tokio::main]
async fn main() -> Result<(), Error> {
    if std::env::var_os("RUST_LOG").is_some() {
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_writer(std::io::stderr)
            .with_ansi(false)
            .init();
    }
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("crypto provider");
    let a = Args(std::env::args().skip(1).collect());
    let opts = Opts {
        port: a.num("--port", 29900.0)? as u16,
        dir: PathBuf::from(a.flag("--dir").unwrap_or("group_load.run")),
        relay: match a.flag("--relay") {
            Some(p) => PathBuf::from(p),
            None => std::env::current_exe()?
                .parent()
                .and_then(Path::parent)
                .ok_or("no directory above this example")?
                .join("voipc-server"),
        },
        cpus: a.flag("--cpus").map(String::from),
        guard: Guard::start(a.num("--minutes", 15.0)? as u64),
    };
    opts.guard.on_signals();
    let offline = a.num("--offline", 0.0)? as usize;
    let rows = match a.0.first().map(String::as_str) {
        Some("storm") => {
            let (n, rate, k) = (
                a.pos(1, 5000)?,
                a.num("--rate", 1000.0)?,
                a.num("--holders", 2.0)?,
            );
            let again = !a.has("--once");
            storm(&opts, "storm", n, rate, k as usize, again, offline).await?
        }
        Some("exits") => {
            let x = Exits {
                rate: a.pos(1, 10)? as f64,
                guests: a.num("--guests", 2000.0)? as usize,
                writers: a.num("--writers", 5.0)? as usize,
                secs: a.num("--seconds", 120.0)? as u64,
                offline,
                lead_ms: a.num("--lead", 300.0)? as u64,
            };
            vec![exits(&opts, "exits", &x).await?]
        }
        Some("seats") => {
            let hold = a.num("--hold", 0.0)? as u64;
            seats(&opts, "seats", a.pos(1, 1000)?, a.flag("--database"), hold).await?
        }
        Some("--check") => check(&opts).await?,
        _ => return Err(USAGE.into()),
    };
    println!("\n| run | seats | wall s | relay RSS MiB (peak) | relay CPU s | DB s | commits × keyholder ms: build (p95) + on the lock; taken | dues missed | load tool MiB (KiB a client) | KB a member | unseated after RATE |");
    println!("|---|---|---|---|---|---|---|---|---|---|---|");
    for r in &rows {
        println!("{}", r.line());
    }
    Ok(())
}

struct Args(Vec<String>);

impl Args {
    fn flag(&self, name: &str) -> Option<&str> {
        let i = self.0.iter().position(|a| a == name)?;
        self.0.get(i + 1).map(String::as_str)
    }

    fn num(&self, name: &str, default: f64) -> Result<f64, Error> {
        Ok(self
            .flag(name)
            .map(str::parse)
            .transpose()?
            .unwrap_or(default))
    }

    fn has(&self, name: &str) -> bool {
        self.0.iter().any(|a| a == name)
    }

    fn pos(&self, i: usize, default: usize) -> Result<usize, Error> {
        Ok(self
            .0
            .get(i)
            .filter(|a| !a.starts_with("--"))
            .map(|a| a.parse())
            .transpose()?
            .unwrap_or(default))
    }
}

struct Opts {
    port: u16,
    dir: PathBuf,
    relay: PathBuf,
    /// `taskset -c` for the relay.
    cpus: Option<String>,
    guard: Guard,
}

fn wall_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("after 1970")
        .as_millis() as u64
}

fn jitter(ms: u64) -> Duration {
    Duration::from_millis(ms / 2 + rand::random::<u64>() % ms.max(1))
}

// ── The machine: memory guard, /proc ─────────────────────────────────────

/// `(RSS in MiB, CPU seconds)` of a process, from /proc.
fn proc_stats(pid: u32) -> Option<(u64, f64)> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let rss_kb: u64 = status
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))?
        .trim()
        .trim_end_matches(" kB")
        .parse()
        .ok()?;
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // After the name, which may hold spaces: utime and stime are the 12th and 13th
    let mut after_name = stat.rsplit(')').next()?.split_whitespace();
    let utime: f64 = after_name.nth(11)?.parse().ok()?;
    let stime: f64 = after_name.next()?.parse().ok()?;
    Some((rss_kb / 1024, (utime + stime) / 100.0))
}

/// CPU seconds of a process's threads whose name starts with `prefix`, from /proc.
fn threads_cpu(pid: u32, prefix: &str) -> f64 {
    let Ok(tasks) = std::fs::read_dir(format!("/proc/{pid}/task")) else {
        return 0.0;
    };
    tasks
        .flatten()
        .filter_map(|t| std::fs::read_to_string(t.path().join("stat")).ok())
        .filter(|stat| {
            stat.split_once('(')
                .is_some_and(|(_, rest)| rest.starts_with(prefix))
        })
        .filter_map(|stat| {
            let mut after_name = stat.rsplit(')').next()?.split_whitespace();
            let utime: f64 = after_name.nth(11)?.parse().ok()?;
            let stime: f64 = after_name.next()?.parse().ok()?;
            Some((utime + stime) / 100.0)
        })
        .sum()
}

fn free_gib() -> u64 {
    std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|m| {
            m.lines()
                .find_map(|l| l.strip_prefix("MemAvailable:"))
                .and_then(|v| v.trim().trim_end_matches(" kB").parse::<u64>().ok())
        })
        .map_or(u64::MAX, |kb| kb / 1_048_576)
}

fn own_mib() -> u64 {
    proc_stats(std::process::id()).map_or(0, |s| s.0)
}

/// Watches free memory and the time each second on a thread of its own: under
/// `MIN_FREE_GIB`, or past the minutes, it kills the relay by its pid and ends this process.
/// It keeps the peaks of both processes' RSS.
struct Guard {
    relay_pid: Arc<AtomicU32>,
    relay_peak: Arc<AtomicU64>,
    own_peak: Arc<AtomicU64>,
}

impl Guard {
    fn start(minutes: u64) -> Guard {
        let g = Guard {
            relay_pid: Arc::new(AtomicU32::new(0)),
            relay_peak: Arc::new(AtomicU64::new(0)),
            own_peak: Arc::new(AtomicU64::new(0)),
        };
        let (pid, relay_peak, own_peak) = (
            g.relay_pid.clone(),
            g.relay_peak.clone(),
            g.own_peak.clone(),
        );
        let started = Instant::now();
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(1));
            let relay = pid.load(Relaxed);
            if let Some((mib, _)) = Some(relay).filter(|p| *p != 0).and_then(proc_stats) {
                relay_peak.fetch_max(mib, Relaxed);
            }
            own_peak.fetch_max(own_mib(), Relaxed);
            let free = free_gib();
            let over = started.elapsed() > Duration::from_secs(minutes * 60);
            if free < MIN_FREE_GIB || over {
                eprintln!(
                    "guard: {} — stopping the run (relay {} MiB, this tool {} MiB at their peaks)",
                    if over {
                        format!("past {minutes} minutes")
                    } else {
                        format!("{free} GiB free")
                    },
                    relay_peak.load(Relaxed),
                    own_peak.load(Relaxed),
                );
                if relay != 0 {
                    let _ = Command::new("kill")
                        .args(["-9", &relay.to_string()])
                        .status();
                }
                std::process::exit(3);
            }
        });
        g
    }

    /// SIGINT and SIGTERM kill the relay by its pid before this process ends, so no relay
    /// stays behind on the port.
    fn on_signals(&self) {
        use tokio::signal::unix::{signal, SignalKind};
        let pid = self.relay_pid.clone();
        tokio::spawn(async move {
            let (Ok(mut int), Ok(mut term)) = (
                signal(SignalKind::interrupt()),
                signal(SignalKind::terminate()),
            ) else {
                return;
            };
            tokio::select! {
                _ = int.recv() => {}
                _ = term.recv() => {}
            }
            let relay = pid.load(Relaxed);
            eprintln!("signalled: the relay ({relay}) is killed, the run ends");
            if relay != 0 {
                let _ = Command::new("kill")
                    .args(["-9", &relay.to_string()])
                    .status();
            }
            std::process::exit(130);
        });
    }
}

/// Whether something holds `port` on 127.0.0.1, by TCP or UDP: a relay left running by an
/// earlier run would answer this run's clients in its stead.
fn port_taken(port: u16) -> bool {
    std::net::TcpListener::bind(("127.0.0.1", port)).is_err()
        || std::net::UdpSocket::bind(("127.0.0.1", port)).is_err()
}

// ── The relay ─────────────────────────────────────────────────────────────

/// A relay of this build, in its own directory, with the group key on and one text channel.
struct Relay {
    bin: PathBuf,
    dir: PathBuf,
    port: u16,
    cpus: Option<String>,
    child: Option<Child>,
    guard_pid: Arc<AtomicU32>,
    /// Its log's length when it last started: what came after is this run's.
    log_from: u64,
    /// The relay's own view of the group, as its `Observer` last heard it.
    view: Arc<Mutex<Option<GroupLoad>>>,
}

impl Relay {
    /// Writes its files: the config (with `[accounts]` on `database`), the channel, a
    /// self-signed certificate.
    async fn new(opts: &Opts, name: &str, database: Option<&str>) -> Result<Relay, Error> {
        let dir = opts.dir.join(name);
        std::fs::create_dir_all(&dir)?;
        let dir = dir.canonicalize()?;
        let port = opts.port;
        let mut config = format!(
            "host = \"127.0.0.1\"\ntcp_port = {port}\nudp_port = {port}\nmax_users = 250000\n\
             group_key = true\ncert_path = \"server.crt\"\nkey_path = \"server.key\"\n\
             admin_token = \"{ADMIN_TOKEN}\"\n"
        );
        if let Some(db) = database {
            config += &format!(
                "\n[accounts]\nmode = \"optional\"\ndatabase = \"{db}\"\nregistration = \"closed\"\n\
                 kept_seats = 0\nkey_file = \"accounts.key\"\n"
            );
        }
        std::fs::write(dir.join("server.toml"), config)?;
        std::fs::write(
            dir.join("channels.json"),
            format!("[{{\"name\": \"{CHANNEL}\", \"text\": true, \"uid\": \"{CHANNEL}\"}}]\n"),
        )?;
        if !dir.join("server.crt").exists() {
            let id = wtransport::Identity::self_signed(["localhost"])?;
            id.certificate_chain()
                .store_pemfile(dir.join("server.crt"))
                .await?;
            id.private_key()
                .store_secret_pemfile(dir.join("server.key"))
                .await?;
        }
        Ok(Relay {
            bin: opts.relay.clone(),
            dir,
            port,
            cpus: opts.cpus.clone(),
            child: None,
            guard_pid: opts.guard.relay_pid.clone(),
            log_from: 0,
            view: Arc::default(),
        })
    }

    fn server(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    fn pid(&self) -> u32 {
        self.child.as_ref().map_or(0, Child::id)
    }

    /// Starts it and waits until a guest gets in: that guest watches it (`Observer`), as an
    /// admin where the relay has no accounts.
    async fn start(&mut self, admin: bool) -> Result<Observer, Error> {
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.join("relay.log"))?;
        self.log_from = log.metadata()?.len();
        *self.view.lock().unwrap() = None;
        if port_taken(self.port) {
            return Err(format!(
                "port {} is taken: a relay left by an earlier run? Kill it by its pid",
                self.port
            )
            .into());
        }
        // taskset execs the relay: the pid stays the relay's
        let mut cmd = match &self.cpus {
            Some(cpus) => {
                let mut c = Command::new("taskset");
                c.args(["-c", cpus]).arg(&self.bin);
                c
            }
            None => Command::new(&self.bin),
        };
        let child = cmd
            .args(["-c", "server.toml", "--channels", "channels.json"])
            .current_dir(&self.dir)
            .env(
                "RUST_LOG",
                std::env::var("RELAY_LOG").unwrap_or_else(|_| "info".into()),
            )
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log)
            .spawn()
            .map_err(|e| format!("starting {}: {e}", self.bin.display()))?;
        self.guard_pid.store(child.id(), Relaxed);
        self.child = Some(child);
        let (started, server) = (Instant::now(), self.server());
        loop {
            let ik = voipc_crypto::generate_identity_key_pair();
            let probe = connect_named(0, &server, "observer#0001", ser(&ik));
            let probe = tokio::time::timeout(Duration::from_secs(5), probe).await;
            // Whoever answered, it is this relay only while this relay runs
            if let Some(status) = self
                .child
                .as_mut()
                .and_then(|c| c.try_wait().ok().flatten())
            {
                return Err(format!(
                    "the relay ended ({status}): see {}/relay.log",
                    self.dir.display()
                )
                .into());
            }
            if let Ok(Ok(c)) = probe {
                return Ok(observe(c, admin, self.view.clone()));
            }
            if started.elapsed() > Duration::from_secs(60) {
                return Err("the relay let nobody in for a minute".into());
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    }

    /// Asks it to stop (SIGINT), then kills it; by its pid either way.
    fn stop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        let _ = Command::new("kill")
            .args(["-INT", &child.id().to_string()])
            .status();
        for _ in 0..100 {
            if child.try_wait().ok().flatten().is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = child.kill();
        let _ = child.wait();
        self.guard_pid.store(0, Relaxed);
    }

    /// Lines of its log since it started that say every keyholder missed a deadline.
    fn logged_misses(&self) -> usize {
        let log = std::fs::read(self.dir.join("relay.log")).unwrap_or_default();
        let since = log.get(self.log_from as usize..).unwrap_or_default();
        String::from_utf8_lossy(since)
            .lines()
            .filter(|l| l.contains("missed its deadline"))
            .count()
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.stop();
    }
}

fn ser(ik: &IdentityKeyPair) -> Vec<u8> {
    ik.identity_key().serialize().to_vec()
}

/// A connection that only answers pings and, as an admin, asks `AdminLoad` each second: the
/// relay's own view of the group (seats, misses, memory).
struct Observer {
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Observer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn observe(c: Connected, admin: bool, seen: Arc<Mutex<Option<GroupLoad>>>) -> Observer {
    let task = tokio::spawn(async move {
        let Connected {
            mut send,
            mut recv,
            mut buf,
            proto,
            connection,
            ..
        } = c;
        let _open = connection;
        let say = |m: &ClientMessage| enc(m, proto).unwrap_or_default();
        if admin {
            let login = ClientMessage::AdminLogin {
                token: ADMIN_TOKEN.into(),
            };
            if send.write_all(&say(&login)).await.is_err() {
                return;
            }
        }
        let mut every = tokio::time::interval(Duration::from_secs(1));
        loop {
            let reply = tokio::select! {
                _ = every.tick(), if admin => say(&ClientMessage::AdminLoad),
                m = next_message(&mut recv, &mut buf, proto) => match m {
                    Ok(ServerMessage::Ping { timestamp }) => say(&ClientMessage::Ping { timestamp }),
                    Ok(ServerMessage::AdminLoad { report }) => {
                        *seen.lock().unwrap() = report.groups.into_iter().next();
                        continue;
                    }
                    Ok(_) => continue,
                    Err(_) => return,
                },
            };
            if send.write_all(&reply).await.is_err() {
                return;
            }
        }
    });
    Observer { task }
}

// ── The clients ───────────────────────────────────────────────────────────

/// What every client adds to. Live gauges (`connected`, `seated`) and a phase's counts,
/// which `reset` starts anew.
#[derive(Default)]
struct Tally {
    connected: AtomicU64,
    seated: AtomicU64,
    /// Connections whose fetch the relay refused for `RATE`, not seated since: the client asks
    /// again only once a post waits (group_state/member.rs `tick`), so a quiet one stays out.
    parked: AtomicU64,
    lost: AtomicU64,
    retries: AtomicU64,
    seat_ms: Mutex<Vec<u64>>,
    posts: AtomicU64,
    opened: AtomicU64,
    open_ms: Mutex<Vec<u64>>,
    dropped: AtomicU64,
    refused: AtomicU64,
    /// Frame bytes the members (not the keyholders) took in.
    member_bytes: AtomicU64,
    holding: Mutex<Holding>,
    /// Each commit sent and not yet seen taken, by its header's digest: its due's kind and
    /// id. Kept over `reset`, so a commit is taken in the phase that sees it land.
    sent: Mutex<HashMap<[u8; 32], (u8, u64)>>,
}

impl Tally {
    fn reset(&self) {
        for c in [
            &self.lost,
            &self.retries,
            &self.posts,
            &self.opened,
            &self.dropped,
            &self.refused,
            &self.member_bytes,
        ] {
            c.store(0, Relaxed);
        }
        self.seat_ms.lock().unwrap().clear();
        self.open_ms.lock().unwrap().clear();
        *self.holding.lock().unwrap() = Holding::default();
    }

    /// Our commits among these header digests, taken, each once: the relay pushed one as a
    /// head, or asked the next due on it.
    fn landed(&self, ds: impl IntoIterator<Item = [u8; 32]>) {
        let hits: Vec<(u8, u64)> = {
            let mut sent = self.sent.lock().unwrap();
            ds.into_iter().filter_map(|d| sent.remove(&d)).collect()
        };
        if !hits.is_empty() {
            let mut h = self.holding.lock().unwrap();
            hits.into_iter().for_each(|(kind, due)| h.taken(kind, due));
        }
    }
}

/// What the keyholders were asked and did, by due kind.
#[derive(Clone, Default)]
struct Holding {
    dues: BTreeMap<u8, Dues>,
    stale: BTreeMap<u8, u64>,
    declined: u64,
    /// The Remove due out, from its ask until its commit is taken or stale.
    remove_out: Option<u64>,
    /// Exit batches that closed while a Remove was out: an exits due asked of another
    /// keyholder (gk/group.rs `ask`, the slow due's exits), or the Remove asked again with
    /// the batch merged when no other keyholder is online (`tick`, plan 2d).
    beside_remove: u64,
    merged_remove: u64,
}

impl Holding {
    /// A commit of ours the relay took, the first time a keyholder sees it.
    fn taken(&mut self, kind: u8, due: u64) {
        self.dues.entry(kind).or_default().taken += 1;
        if self.remove_out == Some(due) {
            self.remove_out = None;
        }
    }

    /// Part 0 of a due.
    fn asked(&mut self, kind: u8, due: u64, now: u64) {
        let d = self.dues.entry(kind).or_default();
        d.asked += 1;
        if d.first == 0 {
            d.first = now;
        }
        match kind {
            due_code::REMOVE => {
                if self.remove_out.replace(due).is_some() {
                    self.merged_remove += 1;
                }
            }
            due_code::EXITS if self.remove_out.is_some() => self.beside_remove += 1,
            _ => {}
        }
    }

    fn stale(&mut self, reason: u8, due: u64) {
        *self.stale.entry(reason).or_default() += 1;
        if self.remove_out == Some(due) {
            self.remove_out = None;
        }
    }
}

#[derive(Clone, Default)]
struct Dues {
    asked: u64,
    joiners: u64,
    exits: u64,
    /// Each build's time, whole, in ms.
    build_ms: Vec<f64>,
    /// ms the duty spent on the lock for these dues: their frames in and `built`.
    lock_ms: f64,
    /// Commits the relay took.
    taken: u64,
    /// Commit frames sent and their bytes.
    frames: u64,
    bytes: u64,
    /// Wall ms of the first ask and of the last commit frame written.
    first: u64,
    last: u64,
}

/// What the run tells one client.
#[derive(Default)]
struct Ctl {
    /// Drop the connection and stay away until cleared.
    away: AtomicBool,
    /// Turn "Help hold keys" off.
    resign: AtomicBool,
    /// It was asked a due: it holds keys.
    holds: AtomicBool,
    stop: AtomicBool,
    wake: Notify,
}

struct Spec {
    index: usize,
    holder: bool,
    post_every: Option<Duration>,
    server: String,
    tally: Arc<Tally>,
    ctl: Arc<Ctl>,
}

enum End {
    Asked,
    Lost(String),
}

/// One client, connection after connection: as an app, it comes back when the relay drops
/// it, and its floors go to the next connection (`local`).
async fn client(spec: Spec) {
    let ik = voipc_crypto::generate_identity_key_pair();
    let mut local = None;
    let mut lives = 0usize;
    loop {
        if spec.ctl.stop.load(Relaxed) {
            return;
        }
        if spec.ctl.away.load(Relaxed) {
            spec.ctl.wake.notified().await;
            continue;
        }
        let started = Instant::now();
        let name = format!("gl{}#{:04}", spec.index, lives % 9999 + 1);
        let conn = tokio::time::timeout(
            Duration::from_secs(20),
            connect_named(spec.index, &spec.server, &name, ser(&ik)),
        )
        .await;
        let conn = match conn {
            Ok(Ok(c)) => c,
            other => {
                if spec.tally.retries.fetch_add(1, Relaxed) < 3 {
                    let why = match other {
                        Ok(Err(e)) => e.to_string(),
                        _ => "timed out".into(),
                    };
                    eprintln!("client {} tries again: {why}", spec.index);
                }
                tokio::time::sleep(jitter(1000)).await;
                continue;
            }
        };
        lives += 1;
        let mut life = Life::new(&spec, ik, conn, local.take(), started);
        let end = life.run().await;
        local = life.end();
        if let End::Lost(e) = end {
            if spec.tally.lost.fetch_add(1, Relaxed) < 3 {
                eprintln!("client {} lost its connection: {e}", spec.index);
            }
            tokio::time::sleep(jitter(1000)).await;
        }
    }
}

/// Sends a connection's frames in order, at most `SEND_RATE` a second, as the apps pace
/// theirs under the relay's budget (codec.rs `CONTROL_MSGS_PER_SEC`). A frame sent with a due
/// kind is a commit's: `written` hears that kind once the frame is written, not queued.
fn sender<W: AsyncWrite + Unpin + Send + 'static>(
    mut send: W,
    written: impl Fn(u8) + Send + 'static,
) -> mpsc::UnboundedSender<(Vec<u8>, Option<u8>)> {
    let (tx, mut rx) = mpsc::unbounded_channel::<(Vec<u8>, Option<u8>)>();
    tokio::spawn(async move {
        let mut tokens = SEND_RATE;
        let mut last = Instant::now();
        while let Some((data, kind)) = rx.recv().await {
            tokens = (tokens + last.elapsed().as_secs_f64() * SEND_RATE).min(SEND_RATE);
            last = Instant::now();
            if tokens < 1.0 {
                tokio::time::sleep(Duration::from_secs_f64((1.0 - tokens) / SEND_RATE)).await;
                tokens = 1.0;
                last = Instant::now();
            }
            tokens -= 1.0;
            if send.write_all(&data).await.is_err() {
                return;
            }
            if let Some(kind) = kind {
                written(kind);
            }
        }
    });
    tx
}

/// One connection of a client.
struct Life<'a> {
    spec: &'a Spec,
    ik: IdentityKeyPair,
    conn: wtransport::Connection,
    recv: wtransport::RecvStream,
    buf: bytes::BytesMut,
    say: mpsc::UnboundedSender<(Vec<u8>, Option<u8>)>,
    proto: u32,
    user_id: u32,
    keying: GroupKeying,
    local: Option<LocalGk>,
    st: SignalStores,
    pins: MemoryPins,
    run: Option<[u8; 16]>,
    channel: Option<(u32, String)>,
    group: Option<String>,
    seated: bool,
    parked: bool,
    started: Instant,
    jobs: VecDeque<BuildJob>,
    /// The due kind of the build running, if one is.
    building: Option<u8>,
    built_tx: mpsc::UnboundedSender<(Built, f64)>,
    built_rx: mpsc::UnboundedReceiver<(Built, f64)>,
    /// Each due's kind, and the kind of the last due in: a build is the latest due's.
    dues: HashMap<u64, u8>,
    last_kind: u8,
    posted: u64,
}

impl<'a> Life<'a> {
    fn new(
        spec: &'a Spec,
        ik: IdentityKeyPair,
        c: Connected,
        local: Option<LocalGk>,
        started: Instant,
    ) -> Life<'a> {
        spec.tally.connected.fetch_add(1, Relaxed);
        let (built_tx, built_rx) = mpsc::unbounded_channel();
        let tally = spec.tally.clone();
        let written = move |kind: u8| {
            let mut h = tally.holding.lock().unwrap();
            h.dues.entry(kind).or_default().last = wall_ms();
        };
        Life {
            spec,
            ik,
            conn: c.connection,
            recv: c.recv,
            buf: c.buf,
            say: sender(c.send, written),
            proto: c.proto,
            user_id: c.user_id,
            keying: GroupKeying::default(),
            local,
            st: SignalStores::new(&ik, c.user_id),
            pins: MemoryPins::default(),
            run: None,
            channel: None,
            group: None,
            seated: false,
            parked: false,
            started,
            jobs: VecDeque::new(),
            building: None,
            built_tx,
            built_rx,
            dues: HashMap::new(),
            last_kind: 0,
            posted: 0,
        }
    }

    async fn run(&mut self) -> End {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let gap = self.spec.post_every.unwrap_or(Duration::from_secs(3600));
        let first = tokio::time::Instant::now() + jitter(gap.as_millis() as u64);
        let mut post = tokio::time::interval_at(first, gap);
        post.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let ctl = self.spec.ctl.clone();
        static HOLDERS_IN: AtomicU64 = AtomicU64::new(0);
        let tally = self.spec.tally.clone();
        let bytes_in = if self.spec.holder {
            &HOLDERS_IN
        } else {
            &tally.member_bytes
        };
        loop {
            tokio::select! {
                biased;
                _ = ctl.wake.notified() => {
                    if ctl.stop.load(Relaxed) || ctl.away.load(Relaxed) {
                        self.conn.close(0u32.into(), b"away");
                        return End::Asked;
                    }
                    if ctl.resign.swap(false, Relaxed) {
                        let out = self.keying.set_volunteer(false);
                        self.took(out);
                    }
                }
                Some((b, ms)) = self.built_rx.recv() => {
                    let kind = self.building.take().unwrap_or(self.last_kind);
                    let c = GkCtx { pins: &mut self.pins, now: wall_ms() };
                    let t = Instant::now();
                    let out = self.keying.built(b, c);
                    let lock = t.elapsed().as_secs_f64() * 1000.0;
                    self.holding(|h| {
                        let d = h.dues.entry(kind).or_default();
                        d.build_ms.push(ms);
                        d.lock_ms += lock;
                    });
                    self.took(out);
                }
                _ = tick.tick() => {
                    let c = GkCtx { pins: &mut self.pins, now: wall_ms() };
                    let out = self.keying.tick(&mut self.st, c);
                    self.took(out);
                }
                _ = post.tick(), if self.spec.post_every.is_some() && self.seated => self.post(),
                m = next_counted(&mut self.recv, &mut self.buf, self.proto, bytes_in) => match m {
                    Ok(m) => if let Err(e) = self.frame(m) {
                        self.conn.close(0u32.into(), b"done");
                        return End::Lost(e);
                    },
                    Err(e) => return End::Lost(e.to_string()),
                },
            }
        }
    }

    fn holding(&self, f: impl FnOnce(&mut Holding)) {
        f(&mut self.spec.tally.holding.lock().unwrap());
    }

    fn landed(&self, ds: impl IntoIterator<Item = [u8; 32]>) {
        self.spec.tally.landed(ds);
    }

    fn frame(&mut self, msg: ServerMessage) -> Result<(), String> {
        match &msg {
            ServerMessage::Ping { timestamp } => {
                self.send(ClientMessage::Ping {
                    timestamp: *timestamp,
                });
                return Ok(());
            }
            ServerMessage::ServerShutdown { reason } => return Err(reason.clone()),
            ServerMessage::GroupKeys { on, run, clock } => {
                if !on {
                    return Err("the relay has the group key off".into());
                }
                self.run = Some(*run);
                let out = self.keying.start(GkStart {
                    on: true,
                    run: *run,
                    relay_clock: *clock,
                    platform: Platform::Desktop,
                    help_hold_keys: self.spec.holder,
                    user_id: self.user_id,
                    identity: self.ik,
                    account: None,
                    seat_keys: None,
                    local: self.local.take(),
                    visible: true,
                });
                self.took(out);
                return Ok(());
            }
            ServerMessage::ChannelList { channels }
            | ServerMessage::ChannelListMore { channels, .. } => {
                if self.channel.is_none() {
                    if let Some(c) = channels.iter().find(|c| c.text && c.name == CHANNEL) {
                        self.channel = Some((c.channel_id, c.log.clone()));
                        self.send(ClientMessage::JoinTextChannels {
                            channels: vec![c.channel_id],
                            quiet: vec![],
                        });
                    }
                }
                return Ok(());
            }
            ServerMessage::TextJoined { joined, refused } => {
                let Some((cid, log)) = self.channel.clone() else {
                    return Ok(());
                };
                if refused.contains(&cid) {
                    return Err("the relay refused the channel".into());
                }
                if self.group.is_none() && joined.iter().any(|r| r.0 == cid) {
                    let run = self.run.ok_or("TextJoined before GroupKeys")?;
                    let group = group_id(GroupKind::Text, &log, &run, cid);
                    self.group = Some(group.clone());
                    let t = GkTrack {
                        channel_id: cid,
                        group,
                        kind: GroupKind::Text,
                        anonymous: false,
                        hide_members: false,
                        viewer_admin: false,
                        keeps_history: false,
                    };
                    let out = self.keying.track(t, VaultFloor::None);
                    self.took(out);
                }
                return Ok(());
            }
            ServerMessage::EpochDue {
                due, part, piece, ..
            } => {
                self.dues.insert(*due, piece.kind);
                self.last_kind = piece.kind;
                self.spec.ctl.holds.store(true, Relaxed);
                if *part == 0 {
                    self.landed([piece.parent]);
                }
                tracing::debug!(
                    client = self.spec.index,
                    due,
                    part,
                    kind = due_code::name(piece.kind),
                    joins = piece.joins.len(),
                    exits = piece.exits.len(),
                    "due"
                );
                self.holding(|h| {
                    if *part == 0 {
                        h.asked(piece.kind, *due, wall_ms());
                    }
                    let d = h.dues.entry(piece.kind).or_default();
                    d.joiners += piece.joins.len() as u64;
                    d.exits += piece.exits.len() as u64;
                });
            }
            ServerMessage::EpochIn { piece, .. } if self.spec.holder => {
                let heads = piece
                    .chain
                    .iter()
                    .chain(piece.head.iter().map(|l| &l.header))
                    .chain(piece.walk.iter().map(|l| &l.header));
                let ds: Vec<[u8; 32]> = heads.map(|h| digest(&h.body)).collect();
                self.landed(ds);
            }
            ServerMessage::EpochStale {
                due,
                reason,
                detail,
                ..
            } => {
                let why = stale::name(*reason);
                tracing::debug!(client = self.spec.index, due, why, detail, "stale");
                self.holding(|h| h.stale(*reason, *due));
            }
            ServerMessage::EpochRefused {
                what: refused_what::FETCH,
                why: refused_why::RATE,
                ..
            } if !self.seated && !self.parked => {
                self.parked = true;
                self.spec.tally.parked.fetch_add(1, Relaxed);
            }
            ServerMessage::EpochWait { why, detail, .. } => {
                let why = voipc_protocol::gk::wait::name(*why);
                tracing::debug!(client = self.spec.index, why, detail, "wait");
            }
            _ => {}
        }
        // What the duty does with a due's frames runs on the lock (the joiners' endorsements
        // checked, the lists and keyring taken): the keyholder's, beside the build
        let duty = match &msg {
            ServerMessage::EpochDue { piece, .. } => Some(piece.kind),
            ServerMessage::EpochLists { .. }
            | ServerMessage::KeyringIn { .. }
            | ServerMessage::EpochStale { .. } => Some(self.last_kind),
            _ => None,
        }
        .filter(|_| self.spec.holder);
        let c = GkCtx {
            pins: &mut self.pins,
            now: wall_ms(),
        };
        let t = Instant::now();
        let out = self.keying.frame(&mut self.st, &msg, c);
        if let Some(kind) = duty {
            let lock = t.elapsed().as_secs_f64() * 1000.0;
            self.holding(|h| h.dues.entry(kind).or_default().lock_ms += lock);
        }
        self.took(out);
        Ok(())
    }

    /// What a call handed back: sent, counted, and a keyholder's builds started.
    fn took(&mut self, out: GkOut) {
        for m in out.send {
            self.send(m);
        }
        let now = wall_ms();
        let t = &self.spec.tally;
        for p in &out.posts {
            if let Some(sent) = p.envelope.get(..8).and_then(|b| b.try_into().ok()) {
                t.opened.fetch_add(1, Relaxed);
                let ms = now.saturating_sub(u64::from_be_bytes(sent));
                t.open_ms.lock().unwrap().push(ms);
            }
        }
        for e in &out.events {
            match e {
                GkEvent::PostDropped { why, .. } => {
                    let before = t.dropped.fetch_add(1, Relaxed);
                    if before < 3 {
                        eprintln!("client {}: a post dropped ({why:?})", self.spec.index);
                    }
                }
                GkEvent::State {
                    state: GkState::Refused(why),
                    ..
                } => {
                    let before = t.refused.fetch_add(1, Relaxed);
                    if before < 3 {
                        eprintln!("client {}: refused: {why}", self.spec.index);
                    }
                }
                _ => {}
            }
        }
        if self.spec.holder {
            while let Some(j) = self.keying.take_build() {
                self.jobs.push_back(j);
            }
            self.next_build();
            while let Some(m) = self.keying.next_frame(now, false) {
                self.send(m);
            }
        }
        if !self.seated
            && self
                .group
                .as_ref()
                .is_some_and(|g| self.keying.current_epoch(g).is_some())
        {
            self.seated = true;
            let t = &self.spec.tally;
            t.seated.fetch_add(1, Relaxed);
            if std::mem::take(&mut self.parked) {
                t.parked.fetch_sub(1, Relaxed);
            }
            let ms = self.started.elapsed().as_millis() as u64;
            t.seat_ms.lock().unwrap().push(ms);
        }
    }

    /// The next build, on a blocking thread, one at a time: as the app runs them off the lock.
    fn next_build(&mut self) {
        if self.building.is_some() {
            return;
        }
        let Some(mut job) = self.jobs.pop_front() else {
            return;
        };
        self.building = Some(self.last_kind);
        let tx = self.built_tx.clone();
        tokio::task::spawn_blocking(move || {
            let t = Instant::now();
            let b = loop {
                if let Some(b) = job.step(Duration::from_millis(8)) {
                    break b;
                }
            };
            let _ = tx.send((b, t.elapsed().as_secs_f64() * 1000.0));
        });
    }

    fn send(&mut self, m: ClientMessage) {
        let bytes = match enc(&m, self.proto) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("client {}: {e}", self.spec.index);
                return;
            }
        };
        let mut commit = None;
        match &m {
            ClientMessage::EpochCommit {
                due,
                part,
                last,
                piece,
                ..
            } => {
                let kind = self.dues.get(due).copied().unwrap_or(self.last_kind);
                commit = Some(kind);
                if *last {
                    tracing::debug!(client = self.spec.index, due, part, "commit sent");
                }
                if let Some(h) = &piece.header {
                    let d = digest(&h.body);
                    self.spec.tally.sent.lock().unwrap().insert(d, (kind, *due));
                }
                let n = bytes.len() as u64;
                self.holding(|h| {
                    let d = h.dues.entry(kind).or_default();
                    d.frames += 1;
                    d.bytes += n;
                });
            }
            ClientMessage::EpochDecline { why, detail, .. } => {
                eprintln!(
                    "client {}: declined a due ({why}): {detail}",
                    self.spec.index
                );
                self.holding(|h| h.declined += 1);
            }
            _ => {}
        }
        let _ = self.say.send((bytes, commit));
    }

    fn post(&mut self) {
        let Some(cid) = self.channel.as_ref().map(|c| c.0) else {
            return;
        };
        self.posted += 1;
        let mut envelope = vec![0u8; POST_BYTES];
        envelope[..8].copy_from_slice(&wall_ms().to_be_bytes());
        let mut id = [0u8; 16];
        id[..8].copy_from_slice(&(self.spec.index as u64).to_be_bytes());
        id[8..].copy_from_slice(&self.posted.to_be_bytes());
        self.spec.tally.posts.fetch_add(1, Relaxed);
        let c = GkCtx {
            pins: &mut self.pins,
            now: wall_ms(),
        };
        let out = self.keying.post(&mut self.st, cid, id, &envelope, c);
        self.took(out);
    }

    /// The connection is over: what it held is given up, the floors stay for the next.
    fn end(mut self) -> Option<LocalGk> {
        let _ = self.keying.end();
        if self.seated {
            self.spec.tally.seated.fetch_sub(1, Relaxed);
        }
        if self.parked {
            self.spec.tally.parked.fetch_sub(1, Relaxed);
        }
        self.spec.tally.connected.fetch_sub(1, Relaxed);
        self.keying.local().cloned()
    }
}

/// The clients of one run, by position; client `i` connects as index `i + 1` (the observer
/// is 0), so each source address holds a few.
struct Crowd {
    server: String,
    tally: Arc<Tally>,
    ctls: Vec<Arc<Ctl>>,
    /// How many of them are members, not volunteers.
    members: u64,
}

impl Crowd {
    fn new(server: String) -> Crowd {
        Crowd {
            server,
            tally: Arc::new(Tally::default()),
            ctls: vec![],
            members: 0,
        }
    }

    fn spawn(&mut self, holder: bool, post_every: Option<Duration>) {
        let ctl = Arc::new(Ctl::default());
        self.members += u64::from(!holder);
        tokio::spawn(client(Spec {
            index: self.ctls.len() + 1,
            holder,
            post_every,
            server: self.server.clone(),
            tally: self.tally.clone(),
            ctl: ctl.clone(),
        }));
        self.ctls.push(ctl);
    }

    /// `n` more members, `rate` a second, the first `writers` posting once a second.
    async fn spawn_many(&mut self, n: usize, rate: f64, writers: usize) {
        let started = Instant::now();
        for i in 0..n {
            let due = Duration::from_secs_f64(i as f64 / rate);
            if let Some(wait) = due.checked_sub(started.elapsed()) {
                tokio::time::sleep(wait).await;
            }
            self.spawn(false, (i < writers).then_some(Duration::from_secs(1)));
        }
    }

    fn away(&self, which: &[usize], away: bool) {
        for &i in which {
            self.ctls[i].away.store(away, Relaxed);
            self.ctls[i].wake.notify_one();
        }
    }

    /// The first client that holds keys resigns; its position.
    fn resign(&self) -> Option<usize> {
        let i = self.ctls.iter().position(|c| c.holds.load(Relaxed))?;
        self.ctls[i].resign.store(true, Relaxed);
        self.ctls[i].wake.notify_one();
        Some(i)
    }

    fn stop(&self) {
        for c in &self.ctls {
            c.stop.store(true, Relaxed);
            c.wake.notify_one();
        }
    }
}

/// Waits until `count` reaches `want`; an error when it did not move for `STALL`.
async fn wait_for(
    label: &str,
    want: u64,
    relay: &Relay,
    crowd: &Crowd,
    mut count: impl AsyncFnMut() -> u64,
) -> Result<f64, Error> {
    let started = Instant::now();
    let (mut best, mut moved, mut said) = (0, Instant::now(), Instant::now());
    loop {
        let now = count().await;
        if now >= want {
            return Ok(started.elapsed().as_secs_f64());
        }
        if now > best {
            (best, moved) = (now, Instant::now());
        }
        if moved.elapsed() > STALL {
            let stall = STALL.as_secs();
            return Err(format!("{label}: {now} of {want}, none more for {stall} s").into());
        }
        if said.elapsed() >= Duration::from_secs(10) {
            said = Instant::now();
            let relay_mib = proc_stats(relay.pid()).map_or(0, |s| s.0);
            let view = relay.view.lock().unwrap().clone().map_or(String::new(), |g| {
                format!(
                    "; relay's group {} seats, {} joins and {} exits waiting, {} of {} keyholders online, {} missed",
                    g.seats, g.joins_waiting, g.exits_waiting, g.keyholders_online, g.keyholders, g.missed_deadlines
                )
            });
            println!(
                "  {:>5.0} s {label}: {now}/{want}, {} connected, {} seated, {} parked, relay {relay_mib} MiB, this tool {} MiB, {} GiB free{view}",
                started.elapsed().as_secs_f64(),
                crowd.tally.connected.load(Relaxed),
                crowd.tally.seated.load(Relaxed),
                crowd.tally.parked.load(Relaxed),
                own_mib(),
                free_gib(),
            );
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// Waits until `want` connections are seated, or parked after a refused fetch: a parked one
/// asks again only once a post waits, so it is counted apart (`Row::parked`), and the row's
/// seats are those seated (`reached`).
async fn seated(label: &str, want: u64, relay: &Relay, crowd: &Crowd) -> Result<f64, Error> {
    let tally = crowd.tally.clone();
    wait_for(label, want, relay, crowd, async || {
        tally.seated.load(Relaxed) + tally.parked.load(Relaxed)
    })
    .await
}

/// The seats a phase reached: the connections seated, and the offline accounts.
fn reached(tally: &Tally, offline: usize) -> u64 {
    tally.seated.load(Relaxed) + offline as u64
}

// ── Reports ───────────────────────────────────────────────────────────────

fn pct<T: Copy + PartialOrd + Default>(v: &mut [T], p: usize) -> T {
    if v.is_empty() {
        return T::default();
    }
    v.sort_by(|a, b| a.partial_cmp(b).expect("no NaN"));
    v[(v.len() * p / 100).min(v.len() - 1)]
}

/// µs this tool spent in its own queries of the relay's database, which Postgres's
/// `active_time` counts with the relay's.
static TOOL_DB_US: AtomicU64 = AtomicU64::new(0);

/// The relay's DB seconds so far: its SQLite worker threads' CPU, or Postgres's
/// `active_time` (flushed by each backend within seconds) less this tool's queries; `None`
/// on a relay without accounts.
async fn db_secs(relay: &Relay, store: Option<&Store>) -> Option<f64> {
    match store? {
        Store::Lite(_) => Some(threads_cpu(relay.pid(), "sqlx-sqlite")),
        Store::Pg(b) => {
            let ms: f64 = sqlx::query_scalar(
                "SELECT COALESCE(active_time, 0) FROM pg_stat_database WHERE datname = current_database()",
            )
            .fetch_one(&b.0)
            .await
            .ok()?;
            Some((ms - TOOL_DB_US.load(Relaxed) as f64 / 1000.0) / 1000.0)
        }
    }
}

/// Where a phase started: the clock, the relay's CPU and its DB time.
struct Mark {
    at: Instant,
    cpu: f64,
    db: Option<f64>,
}

async fn mark(relay: &Relay, store: Option<&Store>) -> Mark {
    Mark {
        at: Instant::now(),
        cpu: proc_stats(relay.pid()).map_or(0.0, |s| s.1),
        db: db_secs(relay, store).await,
    }
}

/// One phase's numbers, for the table and the check.
#[derive(Default)]
struct Row {
    label: String,
    seats: u64,
    wall: f64,
    relay_mib: u64,
    relay_peak: u64,
    relay_cpu: f64,
    /// The relay's DB seconds in the phase (`db_secs`).
    db_s: Option<f64>,
    commits: String,
    missed: u64,
    tool_mib: u64,
    tool_kib_each: u64,
    /// Frame KB each member took in during the phase.
    member_kb: f64,
    parked: u64,
    holding: Holding,
    posts: u64,
    opened: u64,
    dropped: u64,
    lost: u64,
}

impl Row {
    fn line(&self) -> String {
        format!(
            "| {} | {} | {:.1} | {} ({}) | {:.1} | {} | {} | {} | {} ({}) | {:.1} | {} |",
            self.label,
            self.seats,
            self.wall,
            self.relay_mib,
            self.relay_peak,
            self.relay_cpu,
            self.db_s.map_or("-".into(), |s| format!("{s:.1}")),
            self.commits,
            self.missed,
            self.tool_mib,
            self.tool_kib_each,
            self.member_kb,
            self.parked,
        )
    }

    fn taken(&self, kind: u8) -> u64 {
        self.holding.dues.get(&kind).map_or(0, |d| d.taken)
    }
}

/// A phase's numbers, printed and kept.
struct Phase<'a> {
    label: String,
    /// The seats it reached (`reached`, or the stored seats).
    seats: u64,
    wall: f64,
    crowd: &'a Crowd,
    relay: &'a Relay,
    store: Option<&'a Store>,
    mark: &'a Mark,
    guard: &'a Guard,
}

async fn report(p: Phase<'_>) -> Row {
    let t = &p.crowd.tally;
    let holding = t.holding.lock().unwrap().clone();
    let (relay_mib, relay_cpu) =
        proc_stats(p.relay.pid()).map_or((0, 0.0), |s| (s.0, s.1 - p.mark.cpu));
    let db_s = match (db_secs(p.relay, p.store).await, p.mark.db) {
        (Some(now), Some(then)) => Some(now - then),
        _ => None,
    };
    let spent = p.mark.at.elapsed().as_secs_f64();
    println!("\n== {}: {} seats, {:.1} s ==", p.label, p.seats, p.wall);
    let mut seat_ms = t.seat_ms.lock().unwrap().clone();
    if !seat_ms.is_empty() {
        println!(
            "seated {} connections: p50 {} ms, p95 {} ms, max {} ms after their connect began",
            seat_ms.len(),
            pct(&mut seat_ms, 50),
            pct(&mut seat_ms, 95),
            pct(&mut seat_ms, 100),
        );
    }
    let mut commits = vec![];
    for (kind, d) in &holding.dues {
        let mut ms = d.build_ms.clone();
        let total: f64 = ms.iter().sum();
        let n = ms.len().max(1) as f64;
        let (mean, lock) = (total / n, d.lock_ms / n);
        let span = if d.last > d.first && d.first > 0 {
            let s = (d.last - d.first) as f64 / 1000.0;
            format!(", {s:.1} s from the first ask to the last frame written")
        } else {
            String::new()
        };
        println!(
            "{:>13}: {} asked, {} taken, {} joiners, {} exits; {} builds, {mean:.1} ms mean, {:.1} p95, {:.1} max, {:.2} s in all; on the lock {lock:.1} ms a commit, {:.2} s in all; {} frames, {:.1} MB sent{span}",
            due_code::name(*kind),
            d.asked,
            d.taken,
            d.joiners,
            d.exits,
            ms.len(),
            pct(&mut ms, 95),
            pct(&mut ms, 100),
            total / 1000.0,
            d.lock_ms / 1000.0,
            d.frames,
            d.bytes as f64 / 1e6,
        );
        if !ms.is_empty() {
            let p95 = pct(&mut ms, 95);
            commits.push(format!(
                "{} {} × {mean:.1} ({p95:.1}) + {lock:.1}, {} taken",
                due_code::name(*kind),
                ms.len(),
                d.taken,
            ));
        }
    }
    if holding.dues.contains_key(&due_code::REMOVE) {
        println!(
            "exit batches closed while a Remove was out: {} asked of another keyholder, {} merged into the Remove",
            holding.beside_remove, holding.merged_remove
        );
    }
    let stale: Vec<String> = holding
        .stale
        .iter()
        .map(|(r, n)| format!("{} {n}", stale::name(*r)))
        .collect();
    let timed_out = holding.stale.get(&stale::TIMED_OUT).copied().unwrap_or(0);
    let group = p.relay.view.lock().unwrap().clone();
    let missed = group
        .as_ref()
        .map_or(timed_out, |g| u64::from(g.missed_deadlines));
    println!(
        "stale: {}; declined {}; relay: {} missed deadlines, {} log lines of every keyholder missing one",
        if stale.is_empty() { "none".into() } else { stale.join(", ") },
        holding.declined,
        group.as_ref().map_or("no admin view of".into(), |g| g.missed_deadlines.to_string()),
        p.relay.logged_misses(),
    );
    if let Some(g) = &group {
        println!(
            "relay's group: {} seats, {} keyholders ({} online), {} joins and {} exits waiting, {:.1} MB in memory",
            g.seats,
            g.keyholders,
            g.keyholders_online,
            g.joins_waiting,
            g.exits_waiting,
            g.mem_bytes as f64 / 1e6,
        );
    }
    let (posts, opened, dropped) = (
        t.posts.load(Relaxed),
        t.opened.load(Relaxed),
        t.dropped.load(Relaxed),
    );
    if posts > 0 {
        let mut ms = t.open_ms.lock().unwrap().clone();
        println!(
            "posts: {posts} sent, {opened} opened ({:.0} a post), {dropped} dropped held; opened p50 {} ms, p95 {} ms, max {} ms after sending",
            opened as f64 / posts as f64,
            pct(&mut ms, 50),
            pct(&mut ms, 95),
            pct(&mut ms, 100),
        );
    }
    let member_kb = t.member_bytes.load(Relaxed) as f64 / 1e3 / p.crowd.members.max(1) as f64;
    if p.crowd.members > 0 {
        println!(
            "members took {member_kb:.1} KB each in {spent:.0} s ({:.2} MB an hour at this rate)",
            member_kb * 3600.0 / spent.max(0.001) / 1e3,
        );
    }
    let parked = t.parked.load(Relaxed);
    if parked > 0 {
        println!("{parked} connections unseated: their fetch refused for RATE, and nothing to post or read");
    }
    if let Some(db) = db_s {
        println!("relay DB: {db:.1} s in {spent:.0} s");
    }
    let clients = p.crowd.ctls.len().max(1) as u64;
    let tool_mib = own_mib();
    let lost = t.lost.load(Relaxed);
    let (relay_peak, own_peak) = (
        p.guard.relay_peak.load(Relaxed),
        p.guard.own_peak.load(Relaxed),
    );
    println!(
        "relay: {relay_mib} MiB now ({relay_peak} peak), {relay_cpu:.1} CPU s in {spent:.0} s ({:.2} cores); this tool {tool_mib} MiB ({own_peak} peak, {} KiB a client); {lost} connections lost, {} connects tried again",
        relay_cpu / spent.max(0.001),
        tool_mib * 1024 / clients,
        t.retries.load(Relaxed),
    );
    Row {
        label: p.label,
        seats: p.seats,
        wall: p.wall,
        relay_mib,
        relay_peak,
        relay_cpu,
        db_s,
        commits: commits.join("; "),
        missed,
        tool_mib,
        tool_kib_each: tool_mib * 1024 / clients,
        member_kb,
        parked,
        holding,
        posts,
        opened,
        dropped,
        lost,
    }
}

// ── storm ─────────────────────────────────────────────────────────────────

async fn storm(
    opts: &Opts,
    name: &str,
    n: usize,
    rate: f64,
    holders: usize,
    again: bool,
    offline: usize,
) -> Result<Vec<Row>, Error> {
    let (mut relay, store) = relay_for(opts, name, offline).await?;
    let _obs = relay.start(store.is_none()).await?;
    let mut crowd = Crowd::new(relay.server());
    for _ in 0..holders {
        crowd.spawn(true, None);
    }
    seated("keyholders", holders as u64, &relay, &crowd).await?;
    reseated(store.as_ref(), offline + holders, &relay, &crowd).await?;
    println!("{holders} keyholders seated; {n} guests come, {rate} a second");
    crowd.tally.reset();
    let m = mark(&relay, store.as_ref()).await;
    crowd.spawn_many(n, rate, 0).await;
    let all = (holders + n) as u64;
    seated("storm", all, &relay, &crowd).await?;
    let wall = m.at.elapsed().as_secs_f64();
    let phase = |label: String, wall: f64, m| Phase {
        label,
        seats: reached(&crowd.tally, offline),
        wall,
        crowd: &crowd,
        relay: &relay,
        store: store.as_ref(),
        mark: m,
        guard: &opts.guard,
    };
    let mut rows = vec![report(phase(format!("{name} {n}"), wall, &m)).await];
    if again {
        let guests: Vec<usize> = (holders..holders + n).collect();
        crowd.away(&guests, true);
        let started = Instant::now();
        while crowd.tally.connected.load(Relaxed) > holders as u64 {
            if started.elapsed() > STALL {
                return Err("the guests did not all leave".into());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        println!("all {n} away; they come back at once");
        tokio::time::sleep(Duration::from_secs(1)).await;
        crowd.tally.reset();
        let m = mark(&relay, store.as_ref()).await;
        crowd.away(&guests, false);
        let wall = seated("reconnect", all, &relay, &crowd).await?;
        // The opening their exits asked, taken once their batch closes (`exit_gap`, at most
        // 36 s)
        let tally = crowd.tally.clone();
        let exits_taken = async || {
            let h = tally.holding.lock().unwrap();
            u64::from(h.dues.get(&due_code::EXITS).is_some_and(|d| d.taken > 0))
        };
        wait_for("their exits", 1, &relay, &crowd, exits_taken).await?;
        rows.push(report(phase(format!("{name} {n} reconnect"), wall, &m)).await);
    }
    crowd.stop();
    relay.stop();
    Ok(rows)
}

// ── exits ─────────────────────────────────────────────────────────────────

/// `exits R`'s knobs.
struct Exits {
    /// Exits a second.
    rate: f64,
    guests: usize,
    writers: usize,
    secs: u64,
    offline: usize,
    /// How long before a batch closes the keyholder resigns, in ms.
    lead_ms: u64,
}

/// The relay's open exit batch as this run's own exits make it (gk/due.rs `Exits::add` and
/// `closes_at`): opened by the first exit after the last batch closed, closed `gap` ms after
/// that exit.
#[derive(Default)]
struct Batch {
    first: Option<u64>,
}

impl Batch {
    fn exit(&mut self, at: u64, gap: u64) {
        if self.first.is_some_and(|f| at >= f + gap) {
            self.first = None;
        }
        self.first.get_or_insert(at);
    }

    /// When the open batch closes, if one is open at `now`.
    fn closes(&self, now: u64, gap: u64) -> Option<u64> {
        self.first.map(|f| f + gap).filter(|c| *c > now)
    }
}

/// Up to `want` of `churn` that are not away, each once.
fn pick_exits(churn: &[usize], away: &[bool], want: usize) -> Vec<usize> {
    let free: Vec<usize> = churn.iter().copied().filter(|&i| !away[i]).collect();
    free.choose_multiple(&mut rand::thread_rng(), want)
        .copied()
        .collect()
}

async fn exits(opts: &Opts, name: &str, x: &Exits) -> Result<Row, Error> {
    let (rate, n, writers, secs, offline) = (x.rate, x.guests, x.writers, x.secs, x.offline);
    let (mut relay, store) = relay_for(opts, name, offline).await?;
    let _obs = relay.start(store.is_none()).await?;
    let mut crowd = Crowd::new(relay.server());
    // Three volunteers: two hold keys, the third is promoted after the resignation
    const HOLDERS: usize = 3;
    for _ in 0..HOLDERS {
        crowd.spawn(true, None);
    }
    seated("keyholders", HOLDERS as u64, &relay, &crowd).await?;
    reseated(store.as_ref(), offline + HOLDERS, &relay, &crowd).await?;
    crowd.spawn_many(n, 1000.0, writers).await;
    let all = (HOLDERS + n) as u64;
    seated("guests", all, &relay, &crowd).await?;
    println!("{all} seated; {rate} exits a second for {secs} s, {writers} writers");
    crowd.tally.reset();
    let m = mark(&relay, store.as_ref()).await;
    let churn: Vec<usize> = (HOLDERS + writers..HOLDERS + n).collect();
    let mut back: VecDeque<(Instant, usize)> = VecDeque::new();
    let mut away = vec![false; crowd.ctls.len()];
    let mut batch = Batch::default();
    let started = Instant::now();
    let (mut left, mut skipped, mut resigned, mut said) = (0u64, 0u64, false, Instant::now());
    while started.elapsed() < Duration::from_secs(secs) {
        let seats = relay
            .view
            .lock()
            .unwrap()
            .as_ref()
            .map_or(reached(&crowd.tally, offline), |g| u64::from(g.seats));
        let gap = exit_gap_ms(GroupKind::Text, seats);
        let due = (started.elapsed().as_secs_f64() * rate) as u64;
        if left + skipped < due {
            // The rate's exits, of the guests here: none to spare, they are skipped
            let want = (due - left - skipped) as usize;
            let picks = pick_exits(&churn, &away, want);
            skipped += (want - picks.len()) as u64;
            for i in picks {
                away[i] = true;
                crowd.away(&[i], true);
                batch.exit(wall_ms(), gap);
                back.push_back((Instant::now() + Duration::from_secs(3), i));
                left += 1;
            }
        }
        while back.front().is_some_and(|(at, _)| *at <= Instant::now()) {
            let (_, i) = back.pop_front().expect("one is there");
            away[i] = false;
            crowd.away(&[i], false);
        }
        // The resignation just before a batch closes: its Remove is out when the batch's
        // opening is asked (or, failing that, two thirds of the way in)
        let now = wall_ms();
        let closing = batch.closes(now, gap).is_some_and(|c| c - now <= x.lead_ms);
        let third = started.elapsed() >= Duration::from_secs(secs / 3);
        let late = started.elapsed() >= Duration::from_secs(secs * 2 / 3);
        if !resigned && third && (closing || late) {
            resigned = true;
            let closes = batch.closes(now, gap);
            tracing::debug!(now, closes, gap, "resign");
            match crowd.resign() {
                Some(i) => println!(
                    "  {:>4.0} s: keyholder {} resigns, {}",
                    started.elapsed().as_secs_f64(),
                    i + 1,
                    if closing {
                        let before = closes.map_or(0, |c| c - now);
                        format!("{before} ms before the exit batch closes")
                    } else {
                        "no batch closing".into()
                    }
                ),
                None => println!("  no client was asked a due: nobody resigns"),
            }
        }
        if said.elapsed() >= Duration::from_secs(10) {
            said = Instant::now();
            let t = &crowd.tally;
            println!(
                "  {:>4.0} s: {left} exits, {} seated, {} posts, {} opened, {} dropped",
                started.elapsed().as_secs_f64(),
                t.seated.load(Relaxed),
                t.posts.load(Relaxed),
                t.opened.load(Relaxed),
                t.dropped.load(Relaxed),
            );
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    if skipped > 0 {
        println!("{skipped} exits skipped: every guest that could leave was away");
    }
    let back: Vec<usize> = back.into_iter().map(|(_, i)| i).collect();
    crowd.away(&back, false);
    let wall = started.elapsed().as_secs_f64();
    seated("after", all, &relay, &crowd).await?;
    // The last posts and openings land
    tokio::time::sleep(Duration::from_secs((secs / 3).clamp(3, 10))).await;
    let row = report(Phase {
        label: format!("{name} {rate}/s × {secs} s ({left} exits)"),
        seats: reached(&crowd.tally, offline),
        wall,
        crowd: &crowd,
        relay: &relay,
        store: store.as_ref(),
        mark: &m,
        guard: &opts.guard,
    })
    .await;
    crowd.stop();
    relay.stop();
    Ok(row)
}

// ── seats ─────────────────────────────────────────────────────────────────

/// One offline account: its id, name, identity and seat keys, endorsed (origin 0x01).
struct Seed {
    account: [u8; 16],
    name: String,
    ik: Vec<u8>,
    kem: Box<[u8]>,
    dh: Box<[u8]>,
    made: i64,
    sig: Vec<u8>,
}

fn make_seeds(n: usize) -> Vec<Seed> {
    let made = wall_ms() / 1000;
    let threads = std::thread::available_parallelism()
        .map_or(4, |t| t.get())
        .min(16);
    let one = move |i: usize| {
        let ik = voipc_crypto::generate_identity_key_pair();
        let account: [u8; 16] = rand::random();
        let public = SeatPair::generate().public();
        let m = MemberId::Account(account);
        let e = Endorsement::sign(&ik, Origin::VaultSeat, m, 1, made, &public)
            .expect("a vault seat names its account");
        Seed {
            account,
            // Not a guest's `gl<index>`: a guest may not take an account's name
            name: format!("seat{i}"),
            ik: ser(&ik),
            kem: public.kem_bytes(),
            dh: public.dh_bytes(),
            made: made as i64,
            sig: e.sig.to_vec(),
        }
    };
    std::thread::scope(|s| {
        let parts: Vec<_> = (0..threads)
            .map(|t| s.spawn(move || (t..n).step_by(threads).map(one).collect::<Vec<_>>()))
            .collect();
        parts
            .into_iter()
            .flat_map(|p| p.join().expect("a seeding thread"))
            .collect()
    })
}

/// The database, with commits that do not wait for the disk (seeding only).
async fn open_store(url: &str) -> Result<Store, Error> {
    use std::str::FromStr;
    Ok(if url.starts_with("sqlite") {
        let opts = sqlx::sqlite::SqliteConnectOptions::from_str(url)?
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .synchronous(sqlx::sqlite::SqliteSynchronous::Off)
            .busy_timeout(Duration::from_secs(30));
        sqlx::SqlitePool::connect_with(opts).await?.into()
    } else {
        let opts = sqlx::postgres::PgConnectOptions::from_str(url)?
            .options([("synchronous_commit", "off")]);
        sqlx::PgPool::connect_with(opts).await?.into()
    })
}

/// `n` offline accounts keeping `CONV`'s log with current seat keys, as the relay reads
/// those it seats eagerly at a stored group's Genesis (gk/store.rs `eager_page`).
async fn seed(store: &Store, n: usize) -> Result<(), Error> {
    let started = Instant::now();
    let seeds = tokio::task::spawn_blocking(move || make_seeds(n)).await?;
    let made = started.elapsed().as_secs_f64();
    println!("made {n} identities and seat keys in {made:.1} s");
    let started = Instant::now();
    let now = wall_ms() as i64;
    for chunk in seeds.chunks(1000) {
        db!(store, pool => {
            let mut tx = pool.begin().await?;
            let mut q = sqlx::QueryBuilder::new(
                "INSERT INTO acct_users (id, username, display_name, created_at) ",
            );
            q.push_values(chunk, |mut b, s| {
                b.push_bind(&s.account[..])
                    .push_bind(&s.name)
                    .push_bind(&s.name)
                    .push_bind(now);
            });
            q.build().execute(&mut *tx).await?;
            let mut q = sqlx::QueryBuilder::new(
                "INSERT INTO voipc_identity (account, identity_key, updated_at) ",
            );
            q.push_values(chunk, |mut b, s| {
                b.push_bind(&s.account[..]).push_bind(&s.ik[..]).push_bind(now);
            });
            q.build().execute(&mut *tx).await?;
            let mut q = sqlx::QueryBuilder::new(
                "INSERT INTO voipc_gk_seatkeys (account, n, kem, dh, made, sig, published, current) ",
            );
            q.push_values(chunk, |mut b, s| {
                b.push_bind(&s.account[..])
                    .push_bind(1i64)
                    .push_bind(&s.kem[..])
                    .push_bind(&s.dh[..])
                    .push_bind(s.made)
                    .push_bind(&s.sig[..])
                    .push_bind(now)
                    .push_bind(true);
            });
            q.build().execute(&mut *tx).await?;
            let mut q = sqlx::QueryBuilder::new(
                "INSERT INTO voipc_members (conv, account, joined_at) ",
            );
            q.push_values(chunk, |mut b, s| {
                b.push_bind(CONV).push_bind(&s.account[..]).push_bind(now);
            });
            q.build().execute(&mut *tx).await?;
            tx.commit().await?;
        });
    }
    let wrote = started.elapsed().as_secs_f64();
    println!("wrote them into the relay's database in {wrote:.1} s");
    Ok(())
}

async fn seats_stored(store: &Store) -> u64 {
    let _t = ToolQuery(Instant::now());
    let n: Result<i64, sqlx::Error> = db!(store, pool => {
        sqlx::query_scalar("SELECT COUNT(*) FROM voipc_gk_seats WHERE grp = $1")
            .bind(CONV)
            .fetch_one(pool)
            .await
    });
    n.map_or(0, |n| n as u64)
}

async fn db_bytes(store: &Store, dir: &Path) -> u64 {
    let _t = ToolQuery(Instant::now());
    match store {
        Store::Lite(_) => ["relay.db", "relay.db-wal"]
            .iter()
            .filter_map(|f| std::fs::metadata(dir.join(f)).ok())
            .map(|m| m.len())
            .sum(),
        Store::Pg(b) => sqlx::query_scalar::<_, i64>("SELECT pg_database_size(current_database())")
            .fetch_one(&b.0)
            .await
            .map_or(0, |n| n as u64),
    }
}

/// Adds its time to `TOOL_DB_US` when dropped.
struct ToolQuery(Instant);

impl Drop for ToolQuery {
    fn drop(&mut self) {
        TOOL_DB_US.fetch_add(self.0.elapsed().as_micros() as u64, Relaxed);
    }
}

/// A relay with accounts on `database` (a fresh SQLite file when `None`), its tables made
/// and `n` offline accounts in them; not started.
async fn seeded(
    opts: &Opts,
    name: &str,
    n: usize,
    database: Option<&str>,
) -> Result<(Relay, Store, PathBuf), Error> {
    let dir = opts.dir.join(name);
    std::fs::create_dir_all(&dir)?;
    let dir = dir.canonicalize()?;
    let url = match database {
        Some(u) => u.to_string(),
        None => {
            for f in ["relay.db", "relay.db-wal", "relay.db-shm"] {
                let _ = std::fs::remove_file(dir.join(f));
            }
            format!("sqlite://{}/relay.db", dir.display())
        }
    };
    let mut relay = Relay::new(opts, name, Some(&url)).await?;
    // Once to make the tables; the accounts go in while it is stopped
    drop(relay.start(false).await?);
    relay.stop();
    let store = open_store(&url).await?;
    seed(&store, n).await?;
    Ok((relay, store, dir))
}

/// `storm`'s and `exits`'s relay: without accounts, or seeded with `offline` accounts.
async fn relay_for(
    opts: &Opts,
    name: &str,
    offline: usize,
) -> Result<(Relay, Option<Store>), Error> {
    if offline == 0 {
        return Ok((Relay::new(opts, name, None).await?, None));
    }
    let (relay, store, _) = seeded(opts, name, offline, None).await?;
    Ok((relay, Some(store)))
}

/// Waits until `want` seats are stored, when there is a database: the offline accounts'
/// re-seat.
async fn reseated(
    store: Option<&Store>,
    want: usize,
    relay: &Relay,
    crowd: &Crowd,
) -> Result<(), Error> {
    let Some(store) = store else {
        return Ok(());
    };
    let wall = wait_for("re-seat", want as u64, relay, crowd, async || {
        seats_stored(store).await
    })
    .await?;
    println!("{want} seats stored, the offline accounts' in {wall:.1} s");
    Ok(())
}

async fn seats(
    opts: &Opts,
    name: &str,
    n: usize,
    database: Option<&str>,
    hold: u64,
) -> Result<Vec<Row>, Error> {
    let (mut relay, store, dir) = seeded(opts, name, n, database).await?;
    let _obs = relay.start(false).await?;
    let mut crowd = Crowd::new(relay.server());
    let m = mark(&relay, Some(&store)).await;
    const HOLDERS: usize = 2;
    for _ in 0..HOLDERS {
        crowd.spawn(true, None);
    }
    let all = (n + HOLDERS) as u64;
    let wall = wait_for("re-seat", all, &relay, &crowd, async || {
        seats_stored(&store).await
    })
    .await?;
    // The relay stores a Join's seats before its keyholder is told the commit was taken: the
    // phase's numbers wait for that word on every Join asked, or "two Joins" reads one
    wait_for("joins taken", 1, &relay, &crowd, async || {
        let h = crowd.tally.holding.lock().unwrap();
        u64::from(
            h.dues
                .get(&due_code::JOIN)
                .is_none_or(|d| d.taken >= d.asked),
        )
    })
    .await?;
    let phase = |label: String, wall: f64, m| Phase {
        label,
        seats: all,
        wall,
        crowd: &crowd,
        relay: &relay,
        store: Some(&store),
        mark: m,
        guard: &opts.guard,
    };
    let mut rows = vec![report(phase(format!("{name} {n}"), wall, &m)).await];
    println!(
        "database: {:.1} MB",
        db_bytes(&store, &dir).await as f64 / 1e6
    );
    if hold > 0 {
        crowd.tally.reset();
        let m = mark(&relay, Some(&store)).await;
        println!("held {hold} s for the refreshes");
        tokio::time::sleep(Duration::from_secs(hold)).await;
        let row = report(phase(format!("{name} {n} held"), hold as f64, &m)).await;
        let refresh = row
            .holding
            .dues
            .get(&due_code::REFRESH)
            .map_or(0, |d| d.bytes);
        println!(
            "refreshes: {:.1} MB an hour from the keyholders; database {:.1} MB",
            refresh as f64 * 3600.0 / hold as f64 / 1e6,
            db_bytes(&store, &dir).await as f64 / 1e6,
        );
        rows.push(row);
    }
    crowd.stop();
    relay.stop();
    Ok(rows)
}

// ── --check ───────────────────────────────────────────────────────────────

/// The smoke run: a few hundred of each, and the lines that must hold.
async fn check(opts: &Opts) -> Result<Vec<Row>, Error> {
    let mut rows = storm(opts, "check-storm", 200, 400.0, 2, true, 0).await?;
    let x = Exits {
        rate: 10.0,
        guests: 150,
        writers: 3,
        secs: 9,
        offline: 0,
        lead_ms: 300,
    };
    rows.push(exits(opts, "check-exits", &x).await?);
    rows.extend(seats(opts, "check-seats", 300, None, 0).await?);
    let bad = check_failed(&rows);
    if !bad.is_empty() {
        for r in &rows {
            println!("{}", r.line());
        }
        return Err(format!("these did not hold: {}", bad.join("; ")).into());
    }
    println!("\ncheck: every line held");
    Ok(rows)
}

/// The check's lines that did not hold, over its rows: the storm, its reconnect, the exits,
/// the seats. A commit counts once the relay took it, not once it was sent.
fn check_failed(rows: &[Row]) -> Vec<&'static str> {
    let [storm, again, ex, seats] = rows else {
        return vec!["the check has four rows"];
    };
    let lines = [
        (
            "the storm's Joins were taken",
            storm.taken(due_code::JOIN) > 0,
        ),
        (
            "the reconnect storm's exits opening was taken",
            again.taken(due_code::EXITS) > 0,
        ),
        ("exits openings were taken", ex.taken(due_code::EXITS) > 0),
        (
            "the resignation's Remove was taken",
            ex.taken(due_code::REMOVE) > 0,
        ),
        ("posts were opened", ex.posts > 0 && ex.opened > 0),
        ("no post was dropped", ex.dropped == 0),
        ("no connection was lost", rows.iter().all(|r| r.lost == 0)),
        (
            "every connection was seated",
            rows.iter().all(|r| r.parked == 0),
        ),
        (
            "no commit went stale or was declined",
            rows.iter()
                .all(|r| r.holding.stale.is_empty() && r.holding.declined == 0),
        ),
        ("no due was missed", rows.iter().all(|r| r.missed == 0)),
        (
            "300 offline seats took two Joins or more",
            seats.taken(due_code::JOIN) >= 2,
        ),
    ];
    lines
        .iter()
        .filter(|(_, ok)| !ok)
        .map(|(l, _)| *l)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The check's four rows with every line holding.
    fn good_rows() -> Vec<Row> {
        let took = |kinds: &[u8]| {
            let mut h = Holding::default();
            for (due, &kind) in kinds.iter().enumerate() {
                h.asked(kind, due as u64, 1);
                let d = h.dues.get_mut(&kind).unwrap();
                d.frames += 1;
                h.taken(kind, due as u64);
            }
            h
        };
        let row = |holding| Row {
            holding,
            ..Row::default()
        };
        vec![
            row(took(&[due_code::JOIN])),
            row(took(&[due_code::JOIN, due_code::EXITS])),
            Row {
                posts: 20,
                opened: 200,
                ..row(took(&[due_code::EXITS, due_code::REMOVE]))
            },
            row(took(&[due_code::JOIN, due_code::JOIN])),
        ]
    }

    #[test]
    fn check_holds_when_every_commit_was_taken() {
        assert_eq!(check_failed(&good_rows()), Vec::<&str>::new());
    }

    #[test]
    fn check_fails_when_the_reconnect_exits_commit_was_sent_but_never_taken() {
        let mut rows = good_rows();
        let d = rows[1].holding.dues.get_mut(&due_code::EXITS).unwrap();
        d.taken = 0;
        assert_eq!(d.asked, 1);
        assert_eq!(d.frames, 1);
        assert_eq!(
            check_failed(&rows),
            ["the reconnect storm's exits opening was taken"]
        );
    }

    #[test]
    fn check_fails_when_the_remove_was_asked_but_never_taken() {
        let mut rows = good_rows();
        rows[2]
            .holding
            .dues
            .get_mut(&due_code::REMOVE)
            .unwrap()
            .taken = 0;
        assert_eq!(check_failed(&rows), ["the resignation's Remove was taken"]);
    }

    #[test]
    fn check_fails_when_a_guest_stays_unseated_after_rate() {
        let mut rows = good_rows();
        rows[1].parked = 3;
        assert_eq!(check_failed(&rows), ["every connection was seated"]);
    }

    #[test]
    fn check_fails_on_a_stale_commit_a_decline_or_a_missed_due() {
        let mut rows = good_rows();
        rows[2].holding.stale(stale::NOT_DUE, 9);
        assert_eq!(
            check_failed(&rows),
            ["no commit went stale or was declined"]
        );
        let mut rows = good_rows();
        rows[0].holding.declined = 1;
        assert_eq!(
            check_failed(&rows),
            ["no commit went stale or was declined"]
        );
        let mut rows = good_rows();
        rows[3].missed = 1;
        assert_eq!(check_failed(&rows), ["no due was missed"]);
    }

    #[test]
    fn a_commit_is_taken_once_when_a_keyholder_sees_its_header() {
        let t = Tally::default();
        let d = digest(b"a header body");
        t.sent.lock().unwrap().insert(d, (due_code::REMOVE, 7));
        t.holding.lock().unwrap().asked(due_code::REMOVE, 7, 1);
        t.landed([digest(b"another header")]);
        assert_eq!(t.holding.lock().unwrap().remove_out, Some(7));
        // Both keyholders see the push: one take
        t.landed([d]);
        t.landed([d]);
        let h = t.holding.lock().unwrap();
        assert_eq!(h.dues[&due_code::REMOVE].taken, 1);
        assert_eq!(h.remove_out, None);
    }

    #[test]
    fn an_exits_due_asked_while_a_remove_is_out_counts_beside_it() {
        let mut h = Holding::default();
        h.asked(due_code::EXITS, 1, 1);
        h.asked(due_code::REMOVE, 2, 2);
        h.asked(due_code::EXITS, 3, 3);
        h.taken(due_code::REMOVE, 2);
        h.asked(due_code::EXITS, 4, 4);
        assert_eq!(h.beside_remove, 1);
        // No other keyholder: the Remove asked again with the batch merged
        h.asked(due_code::REMOVE, 7, 7);
        h.asked(due_code::REMOVE, 8, 8);
        assert_eq!(h.merged_remove, 1);
        h.taken(due_code::REMOVE, 8);
        // A Remove gone stale is no longer out
        h.asked(due_code::REMOVE, 5, 5);
        h.stale(stale::TIMED_OUT, 5);
        h.asked(due_code::EXITS, 6, 6);
        assert_eq!(h.beside_remove, 1);
    }

    #[test]
    fn an_exit_batch_opens_at_the_first_exit_after_the_last_one_closed() {
        let mut b = Batch::default();
        assert_eq!(b.closes(0, 1000), None);
        b.exit(100, 1000);
        b.exit(900, 1000);
        assert_eq!(b.closes(950, 1000), Some(1100));
        // Closed at 1100 with no exit since
        assert_eq!(b.closes(1100, 1000), None);
        b.exit(1150, 1000);
        assert_eq!(b.closes(1150, 1000), Some(2150));
    }

    #[test]
    fn pick_exits_finds_none_when_every_guest_is_away() {
        assert_eq!(pick_exits(&[0, 1], &[true, true], 5), Vec::<usize>::new());
        assert_eq!(pick_exits(&[], &[], 5), Vec::<usize>::new());
        let mut picks = pick_exits(&[0, 1, 2, 3], &[false, true, false, false], 10);
        picks.sort_unstable();
        assert_eq!(picks, [0, 2, 3]);
    }

    #[test]
    fn the_seats_a_storm_reached_leave_out_the_parked() {
        let t = Tally::default();
        t.seated.store(10, Relaxed);
        t.parked.store(3, Relaxed);
        assert_eq!(reached(&t, 5), 15);
    }

    #[test]
    fn a_port_with_a_socket_on_it_is_taken() {
        let held = std::net::UdpSocket::bind(("127.0.0.1", 0)).unwrap();
        assert!(port_taken(held.local_addr().unwrap().port()));
    }

    #[tokio::test]
    async fn the_paced_sender_times_a_commit_frame_when_written_not_when_queued() {
        let (w, mut r) = tokio::io::duplex(1 << 20);
        let stamps = Arc::new(Mutex::new(vec![]));
        let s = stamps.clone();
        let tx = sender(w, move |kind| {
            s.lock().unwrap().push((kind, Instant::now()))
        });
        let n = SEND_RATE as usize + 15;
        let queued = Instant::now();
        for _ in 0..n {
            tx.send((vec![0u8; 100], Some(due_code::REMOVE))).unwrap();
        }
        let mut sink = vec![0u8; 100 * n];
        tokio::io::AsyncReadExt::read_exact(&mut r, &mut sink)
            .await
            .unwrap();
        let stamps = stamps.lock().unwrap();
        assert_eq!(stamps.len(), n);
        // A burst of SEND_RATE, then the 15 more at SEND_RATE a second
        let last = stamps[n - 1].1 - queued;
        assert!(
            last >= Duration::from_secs_f64(14.0 / SEND_RATE),
            "{last:?}"
        );
        assert!(stamps[0].1 - queued < Duration::from_millis(100));
    }

    #[tokio::test]
    async fn a_commit_frame_the_link_holds_back_is_not_timed_until_written() {
        // A link that takes 64 bytes until its reader reads
        let (w, mut r) = tokio::io::duplex(64);
        let stamps = Arc::new(Mutex::new(vec![]));
        let s = stamps.clone();
        let tx = sender(w, move |kind| s.lock().unwrap().push(kind));
        tx.send((vec![0u8; 1000], Some(due_code::EXITS))).unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(stamps.lock().unwrap().is_empty());
        let mut sink = vec![0u8; 1000];
        tokio::io::AsyncReadExt::read_exact(&mut r, &mut sink)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(*stamps.lock().unwrap(), [due_code::EXITS]);
    }
}
