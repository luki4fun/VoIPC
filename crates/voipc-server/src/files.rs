//! The encrypted file cache (protocol v13, `[files]`).
//!
//! A file posted in chat is sealed by its sender's client
//! (`voipc_crypto::file`), so what the relay holds is a blob it has no key for,
//! under the blob's id: its SHA-256. The control stream only negotiates
//! (`FileUpload`, `FileFetch`); the bytes go over HTTPS on the TLS port,
//! `PUT`/`GET /f/v1/<hash>`, in chunks of at most 1 MiB, with a ticket the
//! control stream handed out. Never over the QUIC connection: its stream
//! readers take one stream at a time and its flow control is shared, so a file
//! there would stall video and chat behind it.
//!
//! - **Who may.** A blob is registered under the conversations it was posted
//!   in, and is handed only to a member of one of them: a channel's current
//!   members, a direct conversation's two parties (by account, else by the
//!   guest's connection; a kept one's account must exist). Whoever holds a
//!   hash, which only its messages carry, may post it again (a forward) and
//!   so fetch it: the check keeps out who never had the message, and the key
//!   was never the relay's to keep. Anyone else is refused before the store
//!   is asked (`resolve`).
//! - **How long.** A fetch keeps a blob for `cache_mins` more, but never past
//!   `max_age_hours` after it arrived. All blobs together stay under
//!   `max_total_mb`: the least recently used goes first. Nothing survives a
//!   restart; blob files are wiped at start.
//! - **When it has gone.** Its registration stays (`REGISTRATION_LIFETIME`).
//!   A fetch then asks the other members online of the asker's conversation,
//!   and of no other (`FileWanted`, which names nobody); a client that holds
//!   the blob and a message referring to it uploads it again, and whoever
//!   waited is served. A member's fetch of a hash not registered in their
//!   conversation (posted before a restart, long ago, or never) asks it the
//!   same way: unknown and elsewhere look alike, and a blob stored for other
//!   conversations waits until a member of theirs posts it there. Each
//!   conversation is asked at most once per `SEEK_TIMEOUT` for a hash. If
//!   nobody starts within `SEEK_TIMEOUT` of a waiter's fetch:
//!   `FileUnavailable`.
//! - **Uploads.** One per blob at a time, one chunk at a time, each checked
//!   before its body is read; another member with the same blob waits, and
//!   hears `FileStored` when it lands. One that stalls passes on
//!   (`UPLOAD_IDLE`; `QUEUED_IDLE` with somebody queued, `FIRST_BYTE` before
//!   its first chunk), and a seek asks with an upload under way too, since
//!   whoever uploads need not hold the blob. A blob is visible only once its
//!   bytes, each chunk on disk before it counts, hash to its id. Its
//!   reservation evicts nothing: cached blobs go for bytes as they arrive.
//! - **Budgets.** Bytes per hour each way, per connection and per address
//!   (`limit_key`), charged when a ticket is handed out; and the control
//!   messages themselves, so a flood of uploads that never finish cannot
//!   crowd out the index.
//! - **Tickets.** 128 random bits, bound to the session, the blob and the
//!   direction; ten minutes, or until the session ends (an upload's slides
//!   with each chunk of `SLIDE_CHUNK` or more, up to `UPLOAD_MAX_LIFE`); compared in constant
//!   time. One that matches nothing counts against the address (`GUESSES`);
//!   one that was good a moment ago hears "gone" and counts for nothing.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use bytes::Bytes;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tracing::{debug, info, warn};
use voipc_protocol::conv::{hex, unhex};
use voipc_protocol::messages::{
    ServerMessage, FILE_BUDGET, FILE_BUSY, FILE_EXPIRED, FILE_FAILED, FILE_MISMATCH, FILE_NOT_HERE,
    FILE_OFF, FILE_PLACES, FILE_RATE, FILE_STALLED, FILE_TOO_LARGE,
};
use voipc_protocol::types::{ChannelId, FileConv, FileLimits, SessionId, UserId};

use crate::config::FilesConfig;
use crate::state::{ServerState, UserSession};
use crate::tcp::send_msg;

const MIB: u64 = 1024 * 1024;
/// Largest body of one request, either way.
pub const MAX_CHUNK: usize = 1024 * 1024;
/// How long a ticket lasts, if its session does not end first.
const TICKET_LIFETIME: Duration = Duration::from_secs(10 * 60);
/// Most download bytes read and not yet sent, across every ticket: a reader
/// that never takes them (an h2 window of zero) holds them until its
/// connection ends.
const GET_BYTES_IN_FLIGHT: usize = 64 * 1024 * 1024;
/// The unit `GET_BYTES_IN_FLIGHT` is counted in.
const KIB: usize = 1024;
/// How long a fetch of a blob that has gone waits for a member to upload it.
const SEEK_TIMEOUT: Duration = Duration::from_secs(60);
/// How long a blob that was stored here stays registered, so a fetch after it
/// has gone can still ask its conversations: the longest message *timer*. A
/// message without one outlives it; a fetch then asks the asker's own
/// conversation, as for a hash never registered (R1-02, R1-17).
const REGISTRATION_LIFETIME: Duration = Duration::from_secs(30 * 24 * 60 * 60);
/// Blobs the index knows at once, stored or not.
const MAX_ENTRIES: usize = 50_000;
/// Conversations one blob may be registered under (a forward adds one).
const MAX_PLACES: usize = 64;
/// How often expiry, tickets and waiters are looked at.
pub const SWEEP_EVERY: Duration = Duration::from_secs(5);
/// Address budgets kept at once before the full ones are dropped.
const MAX_ADDRESS_BUDGETS: usize = 4096;
/// The least an upload is charged, so tiny blobs are not free to send in bulk.
const MIN_CHARGE: u64 = 64 * 1024;
/// An upload with no chunk started or finished for this long ends, and
/// passes to the next member with the file: about 50 kbit/s for a 1 MiB
/// chunk. A client on a slower link sends smaller ones.
const UPLOAD_IDLE: Duration = Duration::from_secs(3 * 60);
/// An upload that has not sent its first byte this long after it began (or
/// its last chunk started) ends: whoever claims a blob they do not hold need
/// not even trickle to keep its holders out for minutes (R1-07).
const FIRST_BYTE: Duration = Duration::from_secs(30);
/// And with a member queued behind it, who has the blob as much as it does,
/// an upload quiet this long passes on.
const QUEUED_IDLE: Duration = Duration::from_secs(30);
/// A chunk at least this long (or the last) moves its upload's ticket to
/// `TICKET_LIFETIME` from now: a slow link that keeps sending gets the time it
/// needs, a trickle of tiny chunks does not.
const SLIDE_CHUNK: u64 = 64 * 1024;
/// However it slides, an upload ends this long after it began.
const UPLOAD_MAX_LIFE: Duration = Duration::from_secs(60 * 60);
/// Tickets kept per blob, each way.
const MAX_TICKETS: usize = 256;

/// The answer to every fetch the asker may not make, and to a hash that is
/// not here: the two must not be told apart.
/// A refusal: its `FileRefused.code`, and the words for people.
type Why = (u16, &'static str);
const NOT_HERE: Why = (FILE_NOT_HERE, "this file is not in a conversation of yours");
const NO_FILES: Why = (FILE_OFF, "this relay keeps no files");

// ── Conversations ─────────────────────────────────────────────────────────

/// One side of a direct conversation: an account, else a guest's connection,
/// by its user id (never handed out twice). Not the guest's name: a later
/// guest who takes it would inherit the conversation's registrations and its
/// `FileWanted` (R1-11, D-6). A guest's E2E identity is per connection anyway.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Party {
    Account([u8; 16]),
    Guest(UserId),
}

/// A conversation as a blob is filed under it: the same for both ends of a
/// direct one, whichever of them names it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Place {
    Channel(ChannelId),
    /// The lower party first.
    Direct(Party, Party),
}

fn direct(a: Party, b: Party) -> Place {
    if a <= b {
        Place::Direct(a, b)
    } else {
        Place::Direct(b, a)
    }
}

fn party_of(session: &UserSession) -> Party {
    match session.account_id() {
        Some(id) => Party::Account(id),
        None => Party::Guest(session.user_id),
    }
}

/// The conversation `conv` names, if the session is in it, and the session's
/// address.
async fn resolve(
    state: &ServerState,
    session_id: SessionId,
    conv: FileConv,
) -> Result<(Place, IpAddr), Why> {
    let (me, ip, user_id) = state
        .sessions
        .get(&session_id)
        .map(|s| (party_of(&s), s.peer_ip, s.user_id))
        .ok_or(NOT_HERE)?;
    let place = match conv {
        FileConv::Channel(id) => {
            // No files in the lobby, and only members. Not chat's announce
            // rule: there, a member who holds a file answers a seek for it by
            // uploading it again, and a blob registered without a message to
            // carry it shows nobody anything (R1-15)
            if id == 0 || !state.is_member(id, user_id).await {
                return Err(NOT_HERE);
            }
            Place::Channel(id)
        }
        FileConv::Direct(uid) => {
            let sid = state.user_to_session.get(&uid).map(|s| *s);
            let other = sid
                .filter(|sid| *sid != session_id)
                .and_then(|sid| state.sessions.get(&sid).map(|s| party_of(&s)))
                .ok_or(NOT_HERE)?;
            if other == me {
                return Err(NOT_HERE);
            }
            direct(me, other)
        }
        FileConv::Account(account) => {
            // A kept conversation is between two accounts that exist: an
            // account named here must be one, or anybody could file a blob
            // under made-up conversations by the dozen
            let other = Party::Account(account);
            if other == me || !matches!(me, Party::Account(_)) {
                return Err(NOT_HERE);
            }
            let Some(relay) = state.accounts.clone() else {
                return Err(NOT_HERE);
            };
            let allowed = state
                .sessions
                .get_mut(&session_id)
                .is_some_and(|mut s| s.account_rate.try_consume());
            let exists = allowed
                && relay
                    .store()
                    .user_by_id(l4f_accounts::model::AccountId(account))
                    .await
                    .is_ok_and(|u| u.is_some());
            if !exists {
                return Err(NOT_HERE);
            }
            direct(me, other)
        }
    };
    Ok((place, ip))
}

// ── Budgets and tickets ───────────────────────────────────────────────────

/// A token bucket over an explicit clock.
pub(crate) struct Bucket {
    left: f64,
    cap: f64,
    per_sec: f64,
    at: Instant,
}

impl Bucket {
    pub(crate) fn new(cap: f64, per_sec: f64, now: Instant) -> Bucket {
        Bucket {
            left: cap,
            cap,
            per_sec,
            at: now,
        }
    }

    fn has(&mut self, n: f64, now: Instant) -> bool {
        let dt = now.saturating_duration_since(self.at).as_secs_f64();
        self.left = (self.left + dt * self.per_sec).min(self.cap);
        self.at = self.at.max(now);
        self.left >= n
    }

    fn full(&mut self, now: Instant) -> bool {
        self.has(self.cap, now)
    }

    /// Spend `n` if there is that much.
    pub(crate) fn take(&mut self, n: f64, now: Instant) -> bool {
        let ok = self.has(n, now);
        if ok {
            self.left -= n;
        }
        ok
    }
}

/// What one connection, or one address, may still do.
struct Budget {
    up: Bucket,
    down: Bucket,
    ops: Bucket,
    /// Tickets that matched nothing (an address's only).
    guesses: Bucket,
}

#[derive(Clone, Copy)]
enum Way {
    Up,
    Down,
}

impl Budget {
    fn new(limits: &Limits, ops: (f64, f64), now: Instant) -> Budget {
        Budget {
            up: Bucket::new(limits.up_per_hour, limits.up_per_hour / 3600.0, now),
            down: Bucket::new(limits.down_per_hour, limits.down_per_hour / 3600.0, now),
            ops: Bucket::new(ops.0, ops.1, now),
            guesses: Bucket::new(GUESSES.0, GUESSES.1, now),
        }
    }

    fn bytes(&mut self, way: Way) -> &mut Bucket {
        match way {
            Way::Up => &mut self.up,
            Way::Down => &mut self.down,
        }
    }

    fn full(&mut self, now: Instant) -> bool {
        self.up.full(now) && self.down.full(now) && self.ops.full(now) && self.guesses.full(now)
    }
}

/// File messages a connection may send: 30 at once, one a second after that.
const SESSION_OPS: (f64, f64) = (30.0, 1.0);
/// And an address, however many connections it opens.
const ADDRESS_OPS: (f64, f64) = (60.0, 3.0);
/// Tickets an address may present that match nothing: 30, then one every 10 s.
/// Its own budget, not the admin token's (`token_guess_allowed`): a whole NAT
/// shares an address, and a stale ticket is not a guess, but neither may
/// lock the other out. A ticket that was good a moment ago is never counted.
const GUESSES: (f64, f64) = (30.0, 0.1);

#[derive(Clone)]
struct Ticket {
    secret: String,
    session: SessionId,
    /// The conversation a download ticket was handed out for: it ends when
    /// its holder leaves that channel (S-021). An upload's names none.
    place: Option<Place>,
    expires: Instant,
    /// Download bytes the ticket may still read: the blob once, plus a
    /// retry's worth. Its budget was charged once, for one read.
    left: u64,
    /// One download request at a time per ticket: the next waits until the
    /// bytes of the one before have been sent or dropped.
    gate: Arc<Semaphore>,
}

impl Ticket {
    fn new(session: SessionId, now: Instant) -> Ticket {
        Ticket {
            secret: hex(&rand::random::<[u8; 16]>()),
            session,
            place: None,
            expires: now + TICKET_LIFETIME,
            left: 0,
            gate: Arc::new(Semaphore::new(1)),
        }
    }

    fn matches(&self, presented: &str, now: Instant) -> bool {
        let same: bool = presented.as_bytes().ct_eq(self.secret.as_bytes()).into();
        same && self.expires > now
    }
}

/// Push `ticket`, keeping at most `MAX_TICKETS`: the oldest goes first, and
/// is handed back.
fn keep(list: &mut Vec<Ticket>, ticket: Ticket) -> Option<Ticket> {
    let oldest = (list.len() >= MAX_TICKETS).then(|| list.remove(0));
    list.push(ticket);
    oldest
}

// ── The store ─────────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
struct Limits {
    max_bytes: u64,
    cache: Duration,
    max_age: Duration,
    max_total: u64,
    up_per_hour: f64,
    down_per_hour: f64,
    animation: (u32, u32),
}

struct Blob {
    size: u64,
    stored: Instant,
    used: Instant,
}

impl Blob {
    fn alive(&self, now: Instant, limits: &Limits) -> bool {
        now.saturating_duration_since(self.used) < limits.cache
            && now.saturating_duration_since(self.stored) < limits.max_age
    }
}

struct Upload {
    id: u64,
    ticket: Ticket,
    size: u64,
    /// Bytes written so far, as the index counts them (`Inner::writing`).
    on_disk: u64,
    /// When a chunk last started or ended: an upload quiet for `UPLOAD_IDLE`
    /// ends, so a reservation cannot be held without sending.
    progress: Instant,
    started: Instant,
    /// A chunk is on its way: one at a time, so an upload never has more
    /// than one body held in memory.
    busy: bool,
    io: Arc<tokio::sync::Mutex<UploadIo>>,
}

/// An upload's file, and the hash of what it holds.
struct UploadIo {
    path: PathBuf,
    file: Option<tokio::fs::File>,
    hasher: Sha256,
}

/// A member waiting behind the upload in progress, with the size they asked
/// to upload: the hash decides which size is the truth.
struct Queued {
    session: SessionId,
    ip: IpAddr,
    size: u64,
}

/// A fetch waiting for an upload, and the conversation it asked in: when the
/// blob lands, a ticket goes only to a waiter still in it.
struct Waiter {
    session: SessionId,
    ip: IpAddr,
    place: Place,
    /// When it began to wait: each waiter gets its own `SEEK_TIMEOUT`, so one
    /// who asks late is not told "unavailable" with the first (R1-09).
    since: Instant,
}

#[derive(Default)]
struct Entry {
    /// Where it was posted, and when it was last registered there.
    places: Vec<(Place, Instant)>,
    blob: Option<Blob>,
    /// Whether a blob was ever stored: only then does the registration
    /// outlive the uploads, so uploads that never finish leave nothing behind.
    ever_stored: bool,
    upload: Option<Upload>,
    queued: Vec<Queued>,
    /// Which conversation was last asked for it, and when: each at most once
    /// per `SEEK_TIMEOUT`, however often its members fetch or cancel.
    asked: Vec<(Place, Instant)>,
    waiters: Vec<Waiter>,
    /// Download tickets. They outlive the blob, so a download cut short by
    /// an eviction hears "gone, fetch again" instead of "bad ticket".
    readers: Vec<Ticket>,
    /// Upload tickets of uploads that ended, for the same reason.
    spent: Vec<Ticket>,
}

impl Entry {
    /// Register `place`; false when the blob is in too many already.
    fn register(&mut self, place: Place, now: Instant) -> bool {
        if let Some(at) = self.places.iter_mut().find(|(p, _)| *p == place) {
            at.1 = now;
            return true;
        }
        if self.places.len() >= MAX_PLACES {
            return false;
        }
        self.places.push((place, now));
        true
    }

    fn idle(&self) -> bool {
        self.blob.is_none()
            && self.upload.is_none()
            && self.queued.is_empty()
            && self.waiters.is_empty()
    }

    fn involves(&self, session: SessionId) -> bool {
        self.readers.iter().any(|t| t.session == session)
            || self.waiters.iter().any(|w| w.session == session)
            || self.queued.iter().any(|q| q.session == session)
            || self
                .upload
                .as_ref()
                .is_some_and(|u| u.ticket.session == session)
    }
}

#[derive(Default)]
struct Inner {
    entries: HashMap<[u8; 32], Entry>,
    /// Bytes of stored blobs.
    stored: u64,
    /// Bytes on disk of the uploads in progress. `stored + writing` stays
    /// within `max_total`: blobs are evicted for bytes as they arrive.
    writing: u64,
    /// The sizes the uploads in progress were started for. Within
    /// `max_total` too, but nothing is evicted for a reservation alone, so an
    /// upload that never sends a byte costs no one their cached file.
    reserved: u64,
    next_id: u64,
    sessions: HashMap<SessionId, Budget>,
    addresses: HashMap<IpAddr, Budget>,
}

/// What a store operation has to say, delivered once its lock is released.
pub(crate) enum Out {
    To(SessionId, ServerMessage),
    /// A ticket for a fetch that waited: sent only if the session is still in
    /// `place`, else the ticket is withdrawn (`deliver`).
    Waited {
        session: SessionId,
        place: Place,
        hash: [u8; 32],
        msg: ServerMessage,
    },
    /// Ask `place`'s members online, except the asker, for the blob.
    Want {
        place: Place,
        hash: [u8; 32],
        except: SessionId,
    },
}

/// Ask `places`' members online, except `except`, for the blob: each place
/// at most once per `SEEK_TIMEOUT`, however often its members fetch or cancel.
fn ask(
    entry: &mut Entry,
    places: Vec<Place>,
    hash: [u8; 32],
    except: SessionId,
    now: Instant,
    out: &mut Vec<Out>,
) {
    entry
        .asked
        .retain(|(_, at)| now.saturating_duration_since(*at) < SEEK_TIMEOUT);
    for place in places {
        if entry.asked.iter().any(|(p, _)| *p == place) {
            continue;
        }
        entry.asked.push((place.clone(), now));
        out.push(Out::Want {
            place,
            hash,
            except,
        });
    }
}

fn refuse(out: &mut Vec<Out>, session: SessionId, hash: [u8; 32], (code, reason): Why) {
    out.push(Out::To(
        session,
        ServerMessage::FileRefused {
            hash,
            code,
            reason: reason.into(),
        },
    ));
}

/// Files to delete once the store's lock is released, so no unlink ever
/// holds up another session's file request.
#[derive(Default)]
struct Trash(Vec<PathBuf>);

impl Trash {
    fn empty(self) {
        for path in self.0 {
            if let Err(e) = std::fs::remove_file(&path) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    warn!("files: deleting {}: {e}", path.display());
                }
            }
        }
    }
}

/// The cache: an index in memory, the blobs in `dir`.
pub struct FileStore {
    dir: PathBuf,
    limits: Limits,
    inner: Mutex<Inner>,
    /// `GET_BYTES_IN_FLIGHT`, in KiB.
    in_flight: Arc<Semaphore>,
}

/// A blob's file name: its hash in hex. An upload in progress, or a blob on
/// its way out, adds `.<id>.part`. Nothing else in the directory is ours to
/// delete.
fn is_ours(name: &str) -> bool {
    match name.split_once('.') {
        None => unhex::<32>(name).is_some(),
        Some((hash, rest)) => {
            unhex::<32>(hash).is_some()
                && rest
                    .strip_suffix(".part")
                    .is_some_and(|id| !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit()))
        }
    }
}

/// Delete every blob file in `dir`, and nothing else: what a run before this
/// one left. Done at every start, with the cache on or off, so turning it
/// off leaves no blob behind.
///
/// One file that cannot be deleted is reported and the rest still go, rather
/// than every old blob staying because of it (R1-12).
pub fn wipe(dir: &Path) -> std::io::Result<usize> {
    let mut wiped = 0;
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e),
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                warn!("files: listing {}: {e}", dir.display());
                continue;
            }
        };
        let ours = entry.file_type().is_ok_and(|t| t.is_file())
            && is_ours(&entry.file_name().to_string_lossy());
        if !ours {
            continue;
        }
        match std::fs::remove_file(entry.path()) {
            Ok(()) => wiped += 1,
            Err(e) => warn!("files: deleting {}: {e}", entry.path().display()),
        }
    }
    Ok(wiped)
}

impl FileStore {
    /// The store in `config.dir`, made if missing, with every blob file left
    /// there by an earlier run wiped, and nothing else touched.
    pub fn open(config: &FilesConfig) -> std::io::Result<FileStore> {
        let dir = PathBuf::from(&config.dir);
        // This user's only, like the database and its key: the names are the
        // hashes, and the sizes show (R1-12)
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder.create(&dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let narrowed = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
            if let Err(e) = narrowed {
                warn!("files: making {} this user's only: {e}", dir.display());
            }
        }
        let wiped = wipe(&dir)?;
        if wiped > 0 {
            info!(wiped, "files: wiped the blobs of the last run");
        }
        Ok(FileStore::new(dir, config))
    }

    fn new(dir: PathBuf, config: &FilesConfig) -> FileStore {
        FileStore {
            dir,
            limits: Limits {
                max_bytes: config.max_size_mb as u64 * MIB,
                cache: Duration::from_secs(config.cache_mins as u64 * 60),
                max_age: Duration::from_secs(config.max_age_hours as u64 * 3600),
                max_total: config.max_total_mb as u64 * MIB,
                up_per_hour: (config.upload_mb_per_hour as u64 * MIB) as f64,
                down_per_hour: (config.download_mb_per_hour as u64 * MIB) as f64,
                animation: (config.animation_side, config.animation_mb),
            },
            inner: Mutex::new(Inner::default()),
            in_flight: Arc::new(Semaphore::new(GET_BYTES_IN_FLIGHT / KIB)),
        }
    }

    /// What `Authenticated` tells clients.
    pub fn limits(&self) -> FileLimits {
        FileLimits {
            max_bytes: self.limits.max_bytes,
            animation_side: self.limits.animation.0,
            animation_mb: self.limits.animation.1,
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn blob_path(&self, hash: &[u8; 32]) -> PathBuf {
        self.dir.join(hex(hash))
    }

    fn part_path(&self, hash: &[u8; 32], id: u64) -> PathBuf {
        self.dir.join(format!("{}.{id}.part", hex(hash)))
    }

    fn address<'a>(&self, inner: &'a mut Inner, ip: IpAddr, now: Instant) -> &'a mut Budget {
        let limits = self.limits;
        inner
            .addresses
            .entry(crate::limit_key(ip))
            .or_insert_with(|| Budget::new(&limits, ADDRESS_OPS, now))
    }

    /// A ticket from `ip` that matched nothing: 401, and one of the address's
    /// wrong tickets spent, or 429 once it has none left. Asked only after the
    /// ticket, so a NAT's good tickets never wait on its wrong ones (S-022);
    /// at 128 bits, testing a ticket past the budget gains a guesser nothing.
    fn guess_failed(&self, ip: IpAddr, now: Instant) -> Reply {
        let mut inner = self.lock();
        let guesses = &mut self.address(&mut inner, ip, now).guesses;
        if !guesses.has(1.0, now) {
            return text(429, "too many wrong tickets");
        }
        guesses.left -= 1.0;
        text(401, "bad ticket")
    }

    /// Whether the session and its address may send one more file message.
    fn op_allowed(&self, inner: &mut Inner, session: SessionId, ip: IpAddr, now: Instant) -> bool {
        let limits = self.limits;
        let mine = inner
            .sessions
            .entry(session)
            .or_insert_with(|| Budget::new(&limits, SESSION_OPS, now));
        if !mine.ops.has(1.0, now) {
            return false;
        }
        let ours = inner
            .addresses
            .entry(crate::limit_key(ip))
            .or_insert_with(|| Budget::new(&limits, ADDRESS_OPS, now));
        if !ours.ops.has(1.0, now) {
            return false;
        }
        mine.ops.left -= 1.0;
        ours.ops.left -= 1.0;
        true
    }

    /// Take `bytes` from the session's budget and its address's, if both
    /// have them.
    fn charge(
        &self,
        inner: &mut Inner,
        session: SessionId,
        ip: IpAddr,
        bytes: u64,
        way: Way,
        now: Instant,
    ) -> bool {
        let limits = self.limits;
        let n = bytes as f64;
        let mine = inner
            .sessions
            .entry(session)
            .or_insert_with(|| Budget::new(&limits, SESSION_OPS, now));
        let ours = inner
            .addresses
            .entry(crate::limit_key(ip))
            .or_insert_with(|| Budget::new(&limits, ADDRESS_OPS, now));
        if !(mine.bytes(way).has(n, now) && ours.bytes(way).has(n, now)) {
            return false;
        }
        mine.bytes(way).left -= n;
        ours.bytes(way).left -= n;
        true
    }

    /// Delete a blob that has outlived its time, before anything asks for it.
    fn expire_if_dead(&self, inner: &mut Inner, hash: &[u8; 32], now: Instant, trash: &mut Trash) {
        let dead = inner
            .entries
            .get(hash)
            .and_then(|e| e.blob.as_ref())
            .is_some_and(|b| !b.alive(now, &self.limits));
        if dead {
            self.drop_blob(inner, hash, trash);
        }
    }

    /// Take a blob out of the index. Its file is renamed under the lock to a
    /// name of its own (`is_ours` wipes those too) and deleted from there
    /// after it: a later copy of the same blob, renamed into place meanwhile,
    /// is then never the one deleted (R1-04).
    fn drop_blob(&self, inner: &mut Inner, hash: &[u8; 32], trash: &mut Trash) {
        let Some(blob) = inner.entries.get_mut(hash).and_then(|e| e.blob.take()) else {
            return;
        };
        inner.stored = inner.stored.saturating_sub(blob.size);
        let doomed = self.part_path(hash, inner.next_id);
        inner.next_id += 1;
        match std::fs::rename(self.blob_path(hash), &doomed) {
            Ok(()) => trash.0.push(doomed),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                // Deleted where it is, then, and still under the lock
                warn!("files: moving a blob out: {e}");
                if let Err(e) = std::fs::remove_file(self.blob_path(hash)) {
                    warn!("files: deleting a blob: {e}");
                }
            }
        }
    }

    /// A blob the index lists whose file is missing (removed by hand, a disk
    /// fault): the index lets go of it, so the next fetch seeks it instead of
    /// answering `FileReady` and then 404 until its age runs out (R1-04).
    /// Checked under the lock, where a new copy is renamed into place.
    fn forget_lost(&self, hash: &[u8; 32]) {
        let mut inner = self.lock();
        let listed = inner.entries.get(hash).is_some_and(|e| e.blob.is_some());
        let lost = matches!(
            std::fs::metadata(self.blob_path(hash)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound
        );
        if listed && lost {
            if let Some(blob) = inner.entries.get_mut(hash).and_then(|e| e.blob.take()) {
                inner.stored = inner.stored.saturating_sub(blob.size);
            }
        }
    }

    /// Room on disk for `n` more bytes of an upload: the least recently used
    /// blobs go, in one sorted pass. Always enough, since every upload's
    /// bytes are within the reservations, and those within `max_total`.
    fn make_room(&self, inner: &mut Inner, n: u64, trash: &mut Trash) {
        if inner.stored + inner.writing + n <= self.limits.max_total {
            return;
        }
        let mut blobs: Vec<(Instant, [u8; 32])> = inner
            .entries
            .iter()
            .filter_map(|(h, e)| e.blob.as_ref().map(|b| (b.used, *h)))
            .collect();
        blobs.sort_unstable();
        for (_, hash) in blobs {
            if inner.stored + inner.writing + n <= self.limits.max_total {
                break;
            }
            self.drop_blob(inner, &hash, trash);
        }
    }

    /// Room in the index for one more blob: when it is full, the idle entry
    /// registered longest ago makes way, else the stored blob used longest ago
    /// that nobody is uploading, waiting for or holding a ticket to. Small
    /// blobs fill the index long before they fill `max_total`, and would
    /// otherwise refuse every new one until they aged out (S-004).
    fn room_for_entry(&self, inner: &mut Inner, now: Instant, trash: &mut Trash) -> bool {
        if inner.entries.len() < MAX_ENTRIES {
            return true;
        }
        let oldest = inner
            .entries
            .iter()
            .filter(|(_, e)| e.idle())
            .map(|(h, e)| (e.places.iter().map(|(_, at)| *at).max(), *h))
            .min();
        if let Some((_, h)) = oldest {
            inner.entries.remove(&h);
            return true;
        }
        let unused = inner
            .entries
            .iter()
            .filter(|(_, e)| {
                e.upload.is_none()
                    && e.queued.is_empty()
                    && e.waiters.is_empty()
                    && e.readers.iter().all(|t| t.expires <= now)
            })
            .filter_map(|(h, e)| e.blob.as_ref().map(|b| (b.used, *h)))
            .min();
        match unused {
            Some((_, h)) => {
                self.drop_blob(inner, &h, trash);
                inner.entries.remove(&h);
                true
            }
            None => false,
        }
    }

    /// Hand `session` the upload of `hash`, if its budget and the
    /// reservations allow.
    fn start_upload(
        &self,
        inner: &mut Inner,
        hash: [u8; 32],
        Queued { session, ip, size }: Queued,
        now: Instant,
        out: &mut Vec<Out>,
    ) -> bool {
        let charge = size.max(MIN_CHARGE);
        let room = {
            let limits = self.limits;
            let mine = inner
                .sessions
                .entry(session)
                .or_insert_with(|| Budget::new(&limits, SESSION_OPS, now));
            let ours = inner
                .addresses
                .entry(crate::limit_key(ip))
                .or_insert_with(|| Budget::new(&limits, ADDRESS_OPS, now));
            mine.up.has(charge as f64, now) && ours.up.has(charge as f64, now)
        };
        if !room {
            refuse(
                out,
                session,
                hash,
                (FILE_BUDGET, "you have sent a lot of files: try again later"),
            );
            return false;
        }
        if inner.reserved + size > self.limits.max_total {
            refuse(
                out,
                session,
                hash,
                (
                    FILE_BUSY,
                    "the relay is busy with other uploads: try again later",
                ),
            );
            return false;
        }
        self.charge(inner, session, ip, charge, Way::Up, now);
        inner.reserved += size;
        let id = inner.next_id;
        inner.next_id += 1;
        let ticket = Ticket::new(session, now);
        let io = UploadIo {
            path: self.part_path(&hash, id),
            file: None,
            hasher: Sha256::new(),
        };
        let entry = inner.entries.entry(hash).or_default();
        entry.upload = Some(Upload {
            id,
            ticket: ticket.clone(),
            size,
            on_disk: 0,
            progress: now,
            started: now,
            busy: false,
            io: Arc::new(tokio::sync::Mutex::new(io)),
        });
        out.push(Out::To(
            session,
            ServerMessage::FileUploadReady {
                hash,
                ticket: ticket.secret,
            },
        ));
        true
    }

    /// Take the upload of `hash` out of the accounts. Its ticket is kept as
    /// spent, so a chunk still on its way hears "gone".
    fn end_upload(&self, inner: &mut Inner, hash: &[u8; 32]) -> Option<Upload> {
        let upload = inner.entries.get_mut(hash)?.upload.take()?;
        inner.reserved = inner.reserved.saturating_sub(upload.size);
        inner.writing = inner.writing.saturating_sub(upload.on_disk);
        if let Some(entry) = inner.entries.get_mut(hash) {
            keep(&mut entry.spent, upload.ticket.clone());
        }
        Some(upload)
    }

    /// End the upload of `hash` without a blob, and hand it to the next
    /// member waiting with the same file.
    fn abort_upload(
        &self,
        inner: &mut Inner,
        hash: [u8; 32],
        now: Instant,
        out: &mut Vec<Out>,
        trash: &mut Trash,
    ) {
        if let Some(upload) = self.end_upload(inner, &hash) {
            trash.0.push(self.part_path(&hash, upload.id));
            self.next_uploader(inner, hash, now, out);
            // Nobody took over, and members still wait: their conversations
            // are asked again (as far as `asked` allows), and the seek starts
            // over, so a holder gets as long to answer as at the first ask.
            // Ended at its deadline, it would otherwise end the waits at once
            // with no holder asked since (S-005).
            let Some(entry) = inner.entries.get_mut(&hash) else {
                return;
            };
            if entry.upload.is_none() && !entry.waiters.is_empty() {
                let mut places: Vec<Place> = Vec::new();
                for w in &mut entry.waiters {
                    w.since = now;
                    if !places.contains(&w.place) {
                        places.push(w.place.clone());
                    }
                }
                ask(entry, places, hash, upload.ticket.session, now, out);
            }
        }
    }

    fn next_uploader(&self, inner: &mut Inner, hash: [u8; 32], now: Instant, out: &mut Vec<Out>) {
        while let Some(next) = inner
            .entries
            .get_mut(&hash)
            .filter(|e| !e.queued.is_empty())
            .map(|e| e.queued.remove(0))
        {
            if self.start_upload(inner, hash, next, now, out) {
                return;
            }
        }
        // Nobody left to upload it: an entry that never held a blob goes
        if inner
            .entries
            .get(&hash)
            .is_some_and(|e| !e.ever_stored && e.idle())
        {
            inner.entries.remove(&hash);
        }
    }

    /// A download ticket for `session`, asking in `place`, if its budget
    /// allows.
    fn ready(
        &self,
        inner: &mut Inner,
        hash: [u8; 32],
        (session, ip, place): (SessionId, IpAddr, &Place),
        size: u64,
        now: Instant,
        out: &mut Vec<Out>,
    ) -> Option<ServerMessage> {
        if !self.charge(inner, session, ip, size, Way::Down, now) {
            refuse(
                out,
                session,
                hash,
                (
                    FILE_BUDGET,
                    "you have fetched a lot of files: try again later",
                ),
            );
            return None;
        }
        let ticket = Ticket {
            left: size.saturating_mul(2),
            place: Some(place.clone()),
            ..Ticket::new(session, now)
        };
        if let Some(entry) = inner.entries.get_mut(&hash) {
            entry.readers.retain(|t| t.expires > now);
            // One pushed out is spent, not unknown: a request still on its
            // way hears "gone", and its address is not charged a guess (S-026)
            if let Some(oldest) = keep(&mut entry.readers, ticket.clone()) {
                keep(&mut entry.spent, oldest);
            }
        }
        Some(ServerMessage::FileReady {
            hash,
            ticket: ticket.secret,
            size,
        })
    }

    /// `FileUpload`.
    pub(crate) fn upload(
        &self,
        hash: [u8; 32],
        place: Place,
        size: u64,
        (session, ip): (SessionId, IpAddr),
        now: Instant,
    ) -> Vec<Out> {
        let mut out = Vec::new();
        let mut trash = Trash::default();
        {
            let mut inner = self.lock();
            self.upload_locked(
                &mut inner,
                hash,
                place,
                size,
                (session, ip),
                now,
                &mut out,
                &mut trash,
            );
        }
        trash.empty();
        out
    }

    #[allow(clippy::too_many_arguments)] // one call site, the lock's
    fn upload_locked(
        &self,
        inner: &mut Inner,
        hash: [u8; 32],
        place: Place,
        size: u64,
        (session, ip): (SessionId, IpAddr),
        now: Instant,
        out: &mut Vec<Out>,
        trash: &mut Trash,
    ) {
        if !self.op_allowed(inner, session, ip, now) {
            return refuse(
                out,
                session,
                hash,
                (FILE_RATE, "too many files at once: slow down"),
            );
        }
        if size == 0 || size > self.limits.max_bytes {
            return refuse(
                out,
                session,
                hash,
                (FILE_TOO_LARGE, "the file is larger than this relay takes"),
            );
        }
        self.expire_if_dead(inner, &hash, now, trash);
        if !inner.entries.contains_key(&hash) && !self.room_for_entry(inner, now, trash) {
            return refuse(
                out,
                session,
                hash,
                (FILE_BUSY, "the relay is busy: try again later"),
            );
        }
        let entry = inner.entries.entry(hash).or_default();
        if !entry.register(place, now) {
            return refuse(
                out,
                session,
                hash,
                (FILE_PLACES, "this file has been posted in too many places"),
            );
        }
        if let Some(blob) = &mut entry.blob {
            // Posted again (a forward, or a member answering a seek in a
            // conversation it was not registered in): it is in use, within its
            // age, and that conversation's waiters may have it now
            blob.used = now;
            let size = blob.size;
            out.push(Out::To(session, ServerMessage::FileStored { hash }));
            return self.serve_waiters(inner, hash, size, now, out);
        }
        if let Some(upload) = &entry.upload {
            if upload.ticket.session == session {
                // Asked again: the same ticket
                out.push(Out::To(
                    session,
                    ServerMessage::FileUploadReady {
                        hash,
                        ticket: upload.ticket.secret.clone(),
                    },
                ));
            } else if !entry.queued.iter().any(|q| q.session == session) {
                entry.queued.push(Queued { session, ip, size });
            }
            return;
        }
        if !self.start_upload(inner, hash, Queued { session, ip, size }, now, out) {
            self.next_uploader(inner, hash, now, out);
        }
    }

    /// `FileFetch`.
    pub(crate) fn fetch(
        &self,
        hash: [u8; 32],
        place: Place,
        (session, ip): (SessionId, IpAddr),
        now: Instant,
    ) -> Vec<Out> {
        let mut out = Vec::new();
        let mut trash = Trash::default();
        {
            let mut inner = self.lock();
            self.fetch_locked(
                &mut inner,
                hash,
                place,
                (session, ip),
                now,
                &mut out,
                &mut trash,
            );
        }
        trash.empty();
        out
    }

    #[allow(clippy::too_many_arguments)] // one call site, the lock's
    fn fetch_locked(
        &self,
        inner: &mut Inner,
        hash: [u8; 32],
        place: Place,
        (session, ip): (SessionId, IpAddr),
        now: Instant,
        out: &mut Vec<Out>,
        trash: &mut Trash,
    ) {
        if !self.op_allowed(inner, session, ip, now) {
            return refuse(
                out,
                session,
                hash,
                (FILE_RATE, "too many files at once: slow down"),
            );
        }
        // The asker is a member of `place` (`resolve`). A hash is sought in
        // `place` alone, registered there or not (posted before a restart, or
        // long ago, or never): only a member holding it and a message there
        // that names it answers. A blob stored for other conversations is
        // never served without that.
        let registered = inner
            .entries
            .get(&hash)
            .is_some_and(|e| e.places.iter().any(|(p, _)| *p == place));
        if !inner.entries.contains_key(&hash) && !self.room_for_entry(inner, now, trash) {
            return refuse(
                out,
                session,
                hash,
                (FILE_BUSY, "the relay is busy: try again later"),
            );
        }
        self.expire_if_dead(inner, &hash, now, trash);
        let entry = inner.entries.entry(hash).or_default();
        if let Some(blob) = entry.blob.as_mut().filter(|_| registered) {
            // A fetch keeps it for another `cache_mins`, within its age
            blob.used = now;
            let size = blob.size;
            if let Some(msg) = self.ready(inner, hash, (session, ip, &place), size, now, out) {
                out.push(Out::To(session, msg));
            }
            return;
        }
        if !entry.waiters.iter().any(|w| w.session == session) {
            entry.waiters.push(Waiter {
                session,
                ip,
                place: place.clone(),
                since: now,
            });
        }
        out.push(Out::To(session, ServerMessage::FileSeeking { hash }));
        // The asker's conversation only, registered or not: the others'
        // members would learn when somebody elsewhere opens the file, and in
        // a direct conversation that is who opens it (R1-10, D-5). Asked with
        // an upload under way too: it may be somebody's who never had the
        // blob, and a holder who answers queues behind it and takes over when
        // it stalls (R1-07).
        ask(entry, vec![place], hash, session, now, out);
    }

    /// `FileCancel`.
    pub(crate) fn cancel(&self, hash: [u8; 32], session: SessionId, now: Instant) -> Vec<Out> {
        let mut out = Vec::new();
        let mut trash = Trash::default();
        {
            let mut inner = self.lock();
            self.cancel_locked(&mut inner, hash, session, now, &mut out, &mut trash);
        }
        trash.empty();
        out
    }

    fn cancel_locked(
        &self,
        inner: &mut Inner,
        hash: [u8; 32],
        session: SessionId,
        now: Instant,
        out: &mut Vec<Out>,
        trash: &mut Trash,
    ) {
        let Some(entry) = inner.entries.get_mut(&hash) else {
            return;
        };
        // Its download tickets are spent, not unknown: a request still on its
        // way hears "gone"
        let (gone, kept): (Vec<Ticket>, Vec<Ticket>) = std::mem::take(&mut entry.readers)
            .into_iter()
            .partition(|t| t.session == session);
        entry.readers = kept;
        for ticket in gone {
            keep(&mut entry.spent, ticket);
        }
        entry.waiters.retain(|w| w.session != session);
        entry.queued.retain(|q| q.session != session);
        if entry
            .upload
            .as_ref()
            .is_some_and(|u| u.ticket.session == session)
        {
            self.abort_upload(inner, hash, now, out, trash);
        }
    }

    /// A member has left a channel (moved on, was kicked, or unsubscribed):
    /// the download tickets it was handed there end, as spent, so a request
    /// on its way hears "gone" (S-021). Its other tickets stay.
    pub(crate) fn left(&self, session: SessionId, place: &Place) {
        let mut inner = self.lock();
        for entry in inner.entries.values_mut() {
            if !entry.readers.iter().any(|t| t.session == session) {
                continue;
            }
            let (gone, kept): (Vec<Ticket>, Vec<Ticket>) = std::mem::take(&mut entry.readers)
                .into_iter()
                .partition(|t| t.session == session && t.place.as_ref() == Some(place));
            entry.readers = kept;
            for ticket in gone {
                keep(&mut entry.spent, ticket);
            }
        }
    }

    /// A ticket handed to a waiter who has left the conversation since.
    fn withdraw(&self, hash: [u8; 32], session: SessionId) {
        if let Some(entry) = self.lock().entries.get_mut(&hash) {
            entry.readers.retain(|t| t.session != session);
        }
    }

    /// A session has ended: its tickets, uploads and waits end with it.
    pub(crate) fn forget_session(&self, session: SessionId, now: Instant) -> Vec<Out> {
        let mut out = Vec::new();
        let mut trash = Trash::default();
        {
            let mut inner = self.lock();
            let hashes: Vec<[u8; 32]> = inner
                .entries
                .iter()
                .filter(|(_, e)| e.involves(session))
                .map(|(h, _)| *h)
                .collect();
            for hash in hashes {
                self.cancel_locked(&mut inner, hash, session, now, &mut out, &mut trash);
            }
            inner.sessions.remove(&session);
        }
        trash.empty();
        out
    }

    /// Expiry, tickets and waiters, every `SWEEP_EVERY`.
    pub(crate) fn sweep(&self, now: Instant) -> Vec<Out> {
        let mut out = Vec::new();
        let mut trash = Trash::default();
        {
            let mut inner = self.lock();
            let hashes: Vec<[u8; 32]> = inner.entries.keys().copied().collect();
            for hash in hashes {
                self.sweep_one(&mut inner, hash, now, &mut out, &mut trash);
            }
            if inner.addresses.len() > MAX_ADDRESS_BUDGETS {
                inner.addresses.retain(|_, b| !b.full(now));
            }
        }
        trash.empty();
        out
    }

    fn sweep_one(
        &self,
        inner: &mut Inner,
        hash: [u8; 32],
        now: Instant,
        out: &mut Vec<Out>,
        trash: &mut Trash,
    ) {
        self.expire_if_dead(inner, &hash, now, trash);
        let entry = inner.entries.get_mut(&hash).expect("listed");
        entry.readers.retain(|t| t.expires > now);
        entry.spent.retain(|t| t.expires > now);
        let idle_for = if entry.queued.is_empty() {
            UPLOAD_IDLE
        } else {
            QUEUED_IDLE
        };
        let ended = entry.upload.as_ref().and_then(|u| {
            let quiet = now.saturating_duration_since(u.progress);
            if u.ticket.expires <= now {
                Some((u.ticket.session, (FILE_EXPIRED, "the upload took too long")))
            } else if !u.busy && (quiet >= idle_for || (u.on_disk == 0 && quiet >= FIRST_BYTE)) {
                Some((u.ticket.session, (FILE_STALLED, "the upload stalled")))
            } else {
                None
            }
        });
        if let Some((session, why)) = ended {
            refuse(out, session, hash, why);
            self.abort_upload(inner, hash, now, out, trash);
        }
        let Some(entry) = inner.entries.get_mut(&hash) else {
            return;
        };
        if entry.upload.is_none() {
            let (timed_out, waiting): (Vec<Waiter>, Vec<Waiter>) =
                std::mem::take(&mut entry.waiters)
                    .into_iter()
                    .partition(|w| now.saturating_duration_since(w.since) >= SEEK_TIMEOUT);
            entry.waiters = waiting;
            for waiter in timed_out {
                out.push(Out::To(
                    waiter.session,
                    ServerMessage::FileUnavailable { hash },
                ));
            }
        }
        entry
            .places
            .retain(|(_, at)| now.saturating_duration_since(*at) < REGISTRATION_LIFETIME);
        let forgotten = entry.places.is_empty() || !entry.ever_stored;
        if entry.idle() && entry.spent.is_empty() && forgotten {
            inner.entries.remove(&hash);
        }
    }

    /// The first half of a `PUT`, before its body is read: the ticket, the
    /// offset, and room for one more chunk on this upload. What comes back
    /// holds the upload's one slot for a chunk until it is dropped.
    fn claim(
        self: &Arc<Self>,
        hash: [u8; 32],
        presented: &str,
        offset: u64,
        now: Instant,
    ) -> Result<Claim, Put> {
        let mut inner = self.lock();
        let Some(entry) = inner.entries.get_mut(&hash) else {
            return Err(Put::Unauthorized);
        };
        let Some(upload) = entry
            .upload
            .as_mut()
            .filter(|u| u.ticket.matches(presented, now))
        else {
            let spent = entry.spent.iter().any(|t| t.matches(presented, now));
            return Err(if spent { Put::Gone } else { Put::Unauthorized });
        };
        if upload.busy {
            return Err(Put::Conflict(upload.on_disk));
        }
        if offset != upload.on_disk || upload.on_disk == upload.size {
            return Err(Put::Conflict(upload.on_disk));
        }
        upload.busy = true;
        upload.progress = now;
        Ok(Claim {
            store: self.clone(),
            hash,
            id: upload.id,
            size: upload.size,
            max_body: (upload.size - upload.on_disk).min(MAX_CHUNK as u64) as usize,
            io: upload.io.clone(),
        })
    }

    fn upload_is(inner: &Inner, hash: &[u8; 32], id: u64) -> bool {
        inner
            .entries
            .get(hash)
            .and_then(|e| e.upload.as_ref())
            .is_some_and(|u| u.id == id)
    }

    /// The second half of a `PUT`: write the chunk, and on the last one,
    /// store the blob if it is the blob.
    pub(crate) async fn put(&self, claim: Claim, body: &[u8], now: Instant) -> (Put, Vec<Out>) {
        let (hash, id, size) = (claim.hash, claim.id, claim.size);
        if body.is_empty() {
            return (Put::Empty, Vec::new());
        }
        if body.len() > claim.max_body {
            return (Put::TooLong, Vec::new());
        }
        let io = claim.io.clone();
        let mut io = io.lock().await;
        let n = body.len() as u64;

        // Room first, and counted before the write: a cancel or an expiry
        // meanwhile takes it out of the accounts again (`end_upload`)
        let mut trash = Trash::default();
        let ours = {
            let mut inner = self.lock();
            let ours = Self::upload_is(&inner, &hash, id);
            if ours {
                self.make_room(&mut inner, n, &mut trash);
                inner.writing += n;
                let upload = inner.entries.get_mut(&hash).and_then(|e| e.upload.as_mut());
                if let Some(upload) = upload {
                    upload.on_disk += n;
                }
            }
            ours
        };
        trash.empty();
        if !ours {
            return (Put::Gone, Vec::new());
        }
        let written = async {
            if io.file.is_none() {
                let mut o = tokio::fs::OpenOptions::new();
                o.write(true).create(true).truncate(true);
                // Mode 0600 from the start, as `fsutil` writes secrets
                #[cfg(unix)]
                o.mode(0o600);
                io.file = Some(o.open(&io.path).await?);
            }
            let file = io.file.as_mut().expect("opened");
            file.write_all(body).await?;
            // tokio's file reports a failed write only at the next operation:
            // flush, so the chunk counts only once it is on disk
            file.flush().await
        }
        .await;
        let mut out = Vec::new();
        let mut trash = Trash::default();
        let mut inner = self.lock();
        if !Self::upload_is(&inner, &hash, id) {
            // Ended while this chunk was written: what it wrote goes too
            io.file = None;
            trash.0.push(io.path.clone());
            drop(inner);
            trash.empty();
            return (Put::Gone, out);
        }
        let upload = inner
            .entries
            .get_mut(&hash)
            .and_then(|e| e.upload.as_mut())
            .expect("ours");
        let uploader = upload.ticket.session;
        let on_disk = upload.on_disk;
        upload.progress = now;
        if let Err(e) = written {
            warn!("files: writing an upload: {e}");
            io.file = None;
            refuse(
                &mut out,
                uploader,
                hash,
                (FILE_FAILED, "the relay could not store the file"),
            );
            self.abort_upload(&mut inner, hash, now, &mut out, &mut trash);
            drop(inner);
            trash.empty();
            return (Put::Failed, out);
        }
        io.hasher.update(body);
        if n >= SLIDE_CHUNK || on_disk == size {
            let upload = inner
                .entries
                .get_mut(&hash)
                .and_then(|e| e.upload.as_mut())
                .expect("ours");
            upload.ticket.expires = (now + TICKET_LIFETIME).min(upload.started + UPLOAD_MAX_LIFE);
        }
        if on_disk < size {
            return (Put::Accepted(on_disk), out);
        }

        // Complete: it becomes the blob only if it is the blob
        io.file = None;
        let digest: [u8; 32] = std::mem::take(&mut io.hasher).finalize().into();
        if digest != hash {
            refuse(
                &mut out,
                uploader,
                hash,
                (
                    FILE_MISMATCH,
                    "the uploaded bytes are not the file it names",
                ),
            );
            self.abort_upload(&mut inner, hash, now, &mut out, &mut trash);
            drop(inner);
            trash.empty();
            return (Put::Mismatch, out);
        }
        // Under the lock: a rename is one metadata write, and outside it a
        // later upload of the same blob could be overwritten or deleted
        if let Err(e) = std::fs::rename(&io.path, self.blob_path(&hash)) {
            warn!("files: storing a blob: {e}");
            refuse(
                &mut out,
                uploader,
                hash,
                (FILE_FAILED, "the relay could not store the file"),
            );
            self.abort_upload(&mut inner, hash, now, &mut out, &mut trash);
            drop(inner);
            trash.empty();
            return (Put::Failed, out);
        }
        self.end_upload(&mut inner, &hash);
        inner.stored += size;
        let entry = inner.entries.get_mut(&hash).expect("ours");
        entry.blob = Some(Blob {
            size,
            stored: now,
            used: now,
        });
        entry.ever_stored = true;
        out.push(Out::To(uploader, ServerMessage::FileStored { hash }));
        for queued in entry.queued.drain(..) {
            out.push(Out::To(queued.session, ServerMessage::FileStored { hash }));
        }
        self.serve_waiters(&mut inner, hash, size, now, &mut out);
        (Put::Stored, out)
    }

    /// Hand the stored blob to its waiters whose conversation it is
    /// registered in. The others wait on for a member of theirs, and the
    /// seek's clock runs on for them.
    fn serve_waiters(
        &self,
        inner: &mut Inner,
        hash: [u8; 32],
        size: u64,
        now: Instant,
        out: &mut Vec<Out>,
    ) {
        let Some(entry) = inner.entries.get_mut(&hash) else {
            return;
        };
        let (served, waiting): (Vec<Waiter>, Vec<Waiter>) = std::mem::take(&mut entry.waiters)
            .into_iter()
            .partition(|w| entry.places.iter().any(|(p, _)| *p == w.place));
        entry.waiters = waiting;
        for waiter in served {
            let who = (waiter.session, waiter.ip, &waiter.place);
            if let Some(msg) = self.ready(inner, hash, who, size, now, out) {
                out.push(Out::Waited {
                    session: waiter.session,
                    place: waiter.place,
                    hash,
                    msg,
                });
            }
        }
    }

    /// `GET /f/v1/<hash>` with `Range`.
    ///
    /// The bytes it answers with hold their ticket's turn and their share of
    /// `GET_BYTES_IN_FLIGHT` until they have been sent or dropped, so a reader
    /// that never takes them holds one chunk per ticket, and a ticket reads
    /// its blob at most twice.
    pub(crate) async fn get(
        &self,
        hash: [u8; 32],
        presented: &str,
        range: Option<&str>,
        now: Instant,
    ) -> Get {
        let (total, gate) = match self.reader(hash, presented, now) {
            Ok(Some(found)) => found,
            Ok(None) => return Get::Gone,
            Err(get) => return get,
        };
        let Some((start, end)) = byte_range(range, total) else {
            return Get::Unsatisfiable(total);
        };
        let len = end - start + 1;
        let Ok(turn) = gate.acquire_owned().await else {
            return Get::Gone;
        };
        {
            // Checked again after the wait: the ticket may have ended, or
            // the blob gone, while an earlier request held the turn
            let mut inner = self.lock();
            let Some(entry) = inner.entries.get_mut(&hash) else {
                return Get::Gone;
            };
            if entry.blob.is_none() {
                return Get::Gone;
            }
            let Some(ticket) = entry.readers.iter_mut().find(|t| t.matches(presented, now)) else {
                return Get::Gone;
            };
            if ticket.left < len {
                return Get::Gone;
            }
            ticket.left -= len;
        }
        let kib = (len as usize).div_ceil(KIB) as u32;
        let Ok(share) = self.in_flight.clone().acquire_many_owned(kib).await else {
            return Get::Gone;
        };
        let read = async {
            let mut file = tokio::fs::File::open(self.blob_path(&hash)).await?;
            file.seek(std::io::SeekFrom::Start(start)).await?;
            let mut data = vec![0u8; len as usize];
            file.read_exact(&mut data).await?;
            std::io::Result::Ok(data)
        };
        match read.await {
            Ok(data) => Get::Bytes {
                start,
                end,
                total,
                data: Bytes::from_owner(Held {
                    data,
                    _permits: (turn, share),
                }),
            },
            // Deleted since the ticket was checked: fetch again
            Err(e) => {
                if e.kind() == std::io::ErrorKind::NotFound {
                    self.forget_lost(&hash);
                }
                Get::Gone
            }
        }
    }

    /// The blob's size and the ticket's turn, for a download ticket that
    /// matches; `None` when its blob has gone.
    #[allow(clippy::type_complexity)]
    fn reader(
        &self,
        hash: [u8; 32],
        presented: &str,
        now: Instant,
    ) -> Result<Option<(u64, Arc<Semaphore>)>, Get> {
        let inner = self.lock();
        let Some(entry) = inner.entries.get(&hash) else {
            return Err(Get::Unauthorized);
        };
        let Some(ticket) = entry.readers.iter().find(|t| t.matches(presented, now)) else {
            let spent = entry.spent.iter().any(|t| t.matches(presented, now));
            return Err(if spent { Get::Gone } else { Get::Unauthorized });
        };
        Ok(entry.blob.as_ref().map(|b| (b.size, ticket.gate.clone())))
    }
}

#[cfg(test)]
impl FileStore {
    /// Claim and write one chunk, as a carrier does.
    pub(crate) async fn put_chunk(
        self: &Arc<Self>,
        hash: [u8; 32],
        ticket: &str,
        offset: u64,
        body: &[u8],
        now: Instant,
    ) -> (Put, Vec<Out>) {
        match self.claim(hash, ticket, offset, now) {
            Ok(claim) => self.put(claim, body, now).await,
            Err(refused) => (refused, Vec::new()),
        }
    }
}

/// An upload's one slot for a chunk, taken by `FileStore::claim` and given
/// back when dropped.
pub(crate) struct Claim {
    store: Arc<FileStore>,
    hash: [u8; 32],
    id: u64,
    size: u64,
    /// The most this chunk may carry: what is left of the upload, at most
    /// `MAX_CHUNK`. A carrier reads no more than this.
    pub(crate) max_body: usize,
    io: Arc<tokio::sync::Mutex<UploadIo>>,
}

impl Drop for Claim {
    fn drop(&mut self) {
        let mut inner = self.store.lock();
        let upload = inner
            .entries
            .get_mut(&self.hash)
            .and_then(|e| e.upload.as_mut())
            .filter(|u| u.id == self.id);
        if let Some(upload) = upload {
            upload.busy = false;
        }
    }
}

pub(crate) enum Put {
    Accepted(u64),
    Stored,
    Conflict(u64),
    Empty,
    TooLong,
    Mismatch,
    Unauthorized,
    Gone,
    Failed,
}

pub(crate) enum Get {
    Bytes {
        start: u64,
        end: u64,
        total: u64,
        data: Bytes,
    },
    Unsatisfiable(u64),
    Unauthorized,
    Gone,
}

/// A download chunk, with the ticket's turn and its share of the bytes in
/// flight: both are given back when the last copy of the chunk is dropped.
struct Held {
    data: Vec<u8>,
    _permits: (OwnedSemaphorePermit, OwnedSemaphorePermit),
}

impl AsRef<[u8]> for Held {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

/// The bytes a `Range` header asks for (inclusive), at most `MAX_CHUNK` of
/// them; none asks from the start. One range of `bytes=a-b` or `bytes=a-`
/// only: nothing here needs more.
fn byte_range(header: Option<&str>, total: u64) -> Option<(u64, u64)> {
    let last = total.checked_sub(1)?;
    let (start, end) = match header {
        None => (0, last),
        Some(h) => {
            let (a, b) = h.trim().strip_prefix("bytes=")?.split_once('-')?;
            let start: u64 = a.trim().parse().ok()?;
            let end: u64 = match b.trim() {
                "" => last,
                b => b.parse().ok()?,
            };
            if start > end || start > last {
                return None;
            }
            (start, end.min(last))
        }
    };
    Some((start, end.min(start + MAX_CHUNK as u64 - 1)))
}

// ── Delivery ──────────────────────────────────────────────────────────────

/// Send what a store operation had to say.
pub(crate) async fn deliver(state: &ServerState, out: Vec<Out>) {
    for item in out {
        match item {
            Out::To(session, msg) => {
                let tx = state.sessions.get(&session).map(|s| s.tcp_tx.clone());
                if let Some(tx) = tx {
                    let _ = send_msg(&tx, &msg).await;
                }
            }
            Out::Waited {
                session,
                place,
                hash,
                msg,
            } => {
                if still_in(state, session, &place).await {
                    let tx = state.sessions.get(&session).map(|s| s.tcp_tx.clone());
                    if let Some(tx) = tx {
                        let _ = send_msg(&tx, &msg).await;
                    }
                } else if let Some(store) = &state.files {
                    store.withdraw(hash, session);
                }
            }
            Out::Want {
                place,
                hash,
                except,
            } => want(state, &place, hash, except).await,
        }
    }
}

/// Whether a session that waited for a blob is still in the conversation
/// it asked in: a channel can be left, a direct conversation cannot.
async fn still_in(state: &ServerState, session: SessionId, place: &Place) -> bool {
    let user_id = state.sessions.get(&session).map(|s| s.user_id);
    match (user_id, place) {
        (None, _) => false,
        (Some(user_id), Place::Channel(id)) => state.is_member(*id, user_id).await,
        (Some(_), Place::Direct(..)) => true,
    }
}

/// The online sessions of one side of a direct conversation. A name is a
/// guest's: an account that took the same name later is somebody else.
fn sessions_of(state: &ServerState, party: &Party) -> Vec<SessionId> {
    let sid = match party {
        Party::Account(id) => state.account_sessions.get(id).map(|s| *s),
        Party::Guest(user_id) => state
            .user_to_session
            .get(user_id)
            .map(|s| *s)
            .filter(|sid| state.sessions.get(sid).is_some_and(|s| s.account.is_none())),
    };
    sid.into_iter().collect()
}

/// How a member names the conversation with `other`: by user id while they
/// are online, by account while they are away. A guest who is away cannot be
/// named at all.
fn conv_for(state: &ServerState, other: &Party) -> Option<FileConv> {
    let online = sessions_of(state, other)
        .first()
        .and_then(|sid| state.sessions.get(sid).map(|s| s.user_id));
    match (online, other) {
        (Some(user_id), _) => Some(FileConv::Direct(user_id)),
        (None, Party::Account(id)) => Some(FileConv::Account(*id)),
        (None, Party::Guest(_)) => None,
    }
}

/// `FileWanted` to `place`'s members online, except the one asking.
async fn want(state: &ServerState, place: &Place, hash: [u8; 32], except: SessionId) {
    let mut sends: Vec<(mpsc::Sender<Vec<u8>>, FileConv)> = Vec::new();
    let mut add = |sid: SessionId, conv: FileConv| {
        if sid != except {
            if let Some(tx) = state.sessions.get(&sid).map(|s| s.tcp_tx.clone()) {
                sends.push((tx, conv));
            }
        }
    };
    match place {
        Place::Channel(id) => {
            let members: Vec<UserId> = state
                .channels
                .read()
                .await
                .get(id)
                .map(|c| c.members.iter().copied().collect())
                .unwrap_or_default();
            for user_id in members {
                if let Some(sid) = state.user_to_session.get(&user_id).map(|s| *s) {
                    add(sid, FileConv::Channel(*id));
                }
            }
        }
        Place::Direct(a, b) => {
            for (me, other) in [(a, b), (b, a)] {
                let Some(conv) = conv_for(state, other) else {
                    continue;
                };
                for sid in sessions_of(state, me) {
                    add(sid, conv);
                }
            }
        }
    }
    for (tx, conv) in sends {
        let _ = send_msg(&tx, &ServerMessage::FileWanted { conv, hash }).await;
    }
}

// ── Control messages ──────────────────────────────────────────────────────

async fn refuse_now(tx: &mpsc::Sender<Vec<u8>>, hash: [u8; 32], (code, reason): Why) {
    let _ = send_msg(
        tx,
        &ServerMessage::FileRefused {
            hash,
            code,
            reason: reason.into(),
        },
    )
    .await;
}

/// `ClientMessage::FileUpload`.
pub(crate) async fn handle_upload(
    state: &Arc<ServerState>,
    session_id: SessionId,
    conv: FileConv,
    size: u64,
    hash: [u8; 32],
    tx: &mpsc::Sender<Vec<u8>>,
) {
    let Some(store) = state.files.clone() else {
        return refuse_now(tx, hash, NO_FILES).await;
    };
    match resolve(state, session_id, conv).await {
        Ok((place, ip)) => {
            let out = store.upload(hash, place, size, (session_id, ip), Instant::now());
            deliver(state, out).await;
        }
        Err(reason) => refuse_now(tx, hash, reason).await,
    }
}

/// `ClientMessage::FileFetch`.
pub(crate) async fn handle_fetch(
    state: &Arc<ServerState>,
    session_id: SessionId,
    conv: FileConv,
    hash: [u8; 32],
    tx: &mpsc::Sender<Vec<u8>>,
) {
    let Some(store) = state.files.clone() else {
        return refuse_now(tx, hash, NO_FILES).await;
    };
    match resolve(state, session_id, conv).await {
        Ok((place, ip)) => {
            let out = store.fetch(hash, place, (session_id, ip), Instant::now());
            deliver(state, out).await;
        }
        Err(reason) => refuse_now(tx, hash, reason).await,
    }
}

/// `ClientMessage::FileCancel`.
pub(crate) async fn handle_cancel(state: &Arc<ServerState>, session_id: SessionId, hash: [u8; 32]) {
    if let Some(store) = state.files.clone() {
        let out = store.cancel(hash, session_id, Instant::now());
        deliver(state, out).await;
    }
}

/// A member left channel `channel_id` (`FileStore::left`).
pub(crate) fn left_channel(state: &ServerState, session_id: SessionId, channel_id: ChannelId) {
    if let Some(store) = state.files.as_ref() {
        store.left(session_id, &Place::Channel(channel_id));
    }
}

/// A session's end (`cleanup_session`).
pub(crate) async fn session_ended(state: &ServerState, session_id: SessionId) {
    if let Some(store) = state.files.clone() {
        let out = store.forget_session(session_id, Instant::now());
        deliver(state, out).await;
    }
}

/// The sweep, for the task main.rs runs every `SWEEP_EVERY`.
pub async fn sweep(state: &ServerState) {
    if let Some(store) = state.files.clone() {
        let out = store.sweep(Instant::now());
        deliver(state, out).await;
    }
}

// ── HTTP ──────────────────────────────────────────────────────────────────

/// An answer to a `/f/` request, for either carrier to write.
pub(crate) struct Reply {
    pub status: u16,
    pub headers: Vec<(&'static str, String)>,
    pub body: Bytes,
}

/// Every `/f/` answer carries these: a page from another relay may fetch
/// here, never with credentials (the ticket is the only one, in a header).
fn with_cors(mut reply: Reply) -> Reply {
    reply
        .headers
        .push(("access-control-allow-origin", "*".into()));
    reply.headers.push((
        "access-control-expose-headers",
        "content-range, upload-offset".into(),
    ));
    reply.headers.push(("cache-control", "no-store".into()));
    reply
}

/// A short answer in words, with the CORS headers.
pub(crate) fn text(status: u16, body: &'static str) -> Reply {
    with_cors(Reply {
        status,
        headers: vec![("content-type", "text/plain; charset=utf-8".into())],
        body: Bytes::from_static(body.as_bytes()),
    })
}

fn at_offset(mut reply: Reply, n: u64) -> Reply {
    reply.headers.push(("upload-offset", n.to_string()));
    reply
}

/// Whether a request belongs here rather than to the tunnel or the page:
/// files, and the server's emotes (emotes.rs), on the same carriers.
pub(crate) fn is_file_path(target: &str) -> bool {
    target.starts_with("/f/") || target.starts_with("/e/")
}

/// A `/f/` request after its head, before its body.
pub(crate) enum Prepared {
    /// Answered already; there is no body to read.
    Reply(Reply),
    /// A chunk to upload: read at most `claim.max_body` bytes, then `finish_put`.
    Put(Claim),
    /// A download: `finish_get`, no body.
    Get { hash: [u8; 32], ticket: String },
    /// An emote's file to upload: read at most `len` bytes, then
    /// `emotes::finish_put`.
    EmotePut(crate::emotes::Upload),
}

/// Everything a `/f/` request can be refused for without its body: the
/// path, the method, the address's wrong tickets, the ticket, the offset, and
/// the upload's one slot for a chunk. No body is read for a request refused
/// here, and a body is never larger than its upload has left.
pub(crate) fn prepare(
    state: &ServerState,
    ip: IpAddr,
    method: &str,
    target: &str,
    authorization: Option<&str>,
) -> Prepared {
    if target.starts_with("/e/") {
        return crate::emotes::prepare(state, method, target, authorization);
    }
    let Some(store) = state.files.as_ref() else {
        return Prepared::Reply(text(404, NO_FILES.1));
    };
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let Some(hash) = path.strip_prefix("/f/v1/").and_then(unhex::<32>) else {
        return Prepared::Reply(text(404, "not found"));
    };
    match method {
        "OPTIONS" => {
            return Prepared::Reply(with_cors(Reply {
                status: 204,
                headers: vec![
                    ("access-control-allow-methods", "GET, HEAD, PUT".into()),
                    (
                        "access-control-allow-headers",
                        "authorization, content-type, range".into(),
                    ),
                    ("access-control-max-age", "600".into()),
                ],
                body: Bytes::new(),
            }))
        }
        "GET" | "HEAD" | "PUT" => {}
        _ => {
            let mut reply = text(405, "method not allowed");
            reply
                .headers
                .push(("allow", "GET, HEAD, PUT, OPTIONS".into()));
            return Prepared::Reply(reply);
        }
    }
    let now = Instant::now();
    let Some(ticket) = authorization.and_then(|v| v.strip_prefix("Bearer ")) else {
        return Prepared::Reply(text(401, "a ticket is needed"));
    };
    if method != "PUT" {
        return Prepared::Get {
            hash,
            ticket: ticket.to_owned(),
        };
    }
    let offset = query
        .split('&')
        .find_map(|kv| kv.strip_prefix("offset="))
        .and_then(|v| v.parse::<u64>().ok());
    let Some(offset) = offset else {
        return Prepared::Reply(text(400, "the offset is missing"));
    };
    match store.claim(hash, ticket, offset, now) {
        Ok(claim) => Prepared::Put(claim),
        Err(Put::Unauthorized) => Prepared::Reply(store.guess_failed(ip, now)),
        Err(Put::Conflict(n)) => {
            Prepared::Reply(at_offset(text(409, "the upload is elsewhere"), n))
        }
        Err(_) => Prepared::Reply(text(404, "the upload has ended")),
    }
}

/// A chunk's body is in: write it.
pub(crate) async fn finish_put(state: &Arc<ServerState>, claim: Claim, body: Bytes) -> Reply {
    let Some(store) = state.files.clone() else {
        return text(404, NO_FILES.1);
    };
    // In a task of its own, awaited: hyper drops a request on a reset stream
    // or at its connection's deadline, and a chunk cut off mid-write had its
    // bytes counted but not hashed, so the upload ended 422 (R1-05). The task
    // writes the chunk and tells whom it concerns whatever becomes of the
    // request; a retry then hears where the upload is.
    let state = state.clone();
    let task = tokio::spawn(async move {
        let (result, out) = store.put(claim, &body, Instant::now()).await;
        deliver(&state, out).await;
        result
    });
    let result = task.await.unwrap_or(Put::Failed);
    match result {
        Put::Accepted(n) => at_offset(text(204, ""), n),
        Put::Stored => text(201, "stored"),
        Put::Conflict(n) => at_offset(text(409, "the upload is elsewhere"), n),
        Put::Empty => text(400, "an empty chunk"),
        Put::TooLong => text(413, "more bytes than the upload has left"),
        Put::Mismatch => text(422, "the bytes are not the file named"),
        Put::Unauthorized | Put::Gone => text(404, "the upload has ended"),
        Put::Failed => text(500, "the relay could not store the file"),
    }
}

/// A download's range.
pub(crate) async fn finish_get(
    state: &ServerState,
    ip: IpAddr,
    hash: [u8; 32],
    ticket: &str,
    range: Option<&str>,
) -> Reply {
    let Some(store) = state.files.clone() else {
        return text(404, NO_FILES.1);
    };
    let now = Instant::now();
    match store.get(hash, ticket, range, now).await {
        Get::Bytes {
            start,
            end,
            total,
            data,
        } => with_cors(Reply {
            status: 206,
            headers: vec![
                ("content-type", "application/octet-stream".into()),
                ("content-range", format!("bytes {start}-{end}/{total}")),
            ],
            body: data,
        }),
        Get::Unsatisfiable(total) => {
            let mut reply = text(416, "outside the file");
            reply
                .headers
                .push(("content-range", format!("bytes */{total}")));
            reply
        }
        Get::Unauthorized => store.guess_failed(ip, now),
        Get::Gone => text(404, "the file has gone: fetch it again"),
    }
}

/// One whole `/f/` request with its body in hand: what tests use.
#[cfg(test)]
pub(crate) async fn http(
    state: &Arc<ServerState>,
    ip: IpAddr,
    method: &str,
    target: &str,
    authorization: Option<&str>,
    range: Option<&str>,
    body: Bytes,
) -> Reply {
    match prepare(state, ip, method, target, authorization) {
        Prepared::Reply(reply) => reply,
        Prepared::Put(claim) if body.len() > claim.max_body => {
            text(413, "more bytes than the upload has left")
        }
        Prepared::Put(claim) => finish_put(state, claim, body).await,
        Prepared::Get { hash, ticket } => finish_get(state, ip, hash, &ticket, range).await,
        Prepared::EmotePut(upload) if body.len() != upload.len => {
            text(400, "the file is not the size it was said to be")
        }
        Prepared::EmotePut(upload) => crate::emotes::finish_put(state, upload, body).await,
    }
}

/// A file connection on HTTP/1.1 (the native clients'): requests one after
/// another, each body at most `MAX_CHUNK` with a `Content-Length`, until the
/// client is done or `CONN_LIFETIME` has passed, and never past
/// `CONN_LIFETIME` and `GRACE`, writes included. Like a page's h2
/// connection, it holds a pre-authentication slot while it lives.
pub(crate) async fn serve_http1<S>(
    mut stream: S,
    head: String,
    buf: Vec<u8>,
    state: Arc<ServerState>,
    peer: SocketAddr,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    const CONN_LIFETIME: Duration = Duration::from_secs(60);
    const GRACE: Duration = Duration::from_secs(30);
    let deadline = Instant::now() + CONN_LIFETIME;
    let mut slot = FileSlot {
        state: &state,
        ip: peer.ip(),
        held: false,
    };
    let served = serve_requests(&mut stream, head, buf, &state, peer, deadline, &mut slot);
    // No request starts after `deadline`, and the one under way gets its own
    // `BODY_TIME`
    if tokio::time::timeout(CONN_LIFETIME + BODY_TIME + GRACE, served)
        .await
        .is_err()
    {
        debug!(%peer, "file connection outlived its time");
    }
    let _ = tokio::time::timeout(Duration::from_secs(2), stream.shutdown()).await;
    debug!(%peer, "file connection closed");
}

/// A file connection's place in the file pool (`ConnLimits::to_files`), given
/// back to the pre pool when the connection ends, however it ends.
struct FileSlot<'a> {
    state: &'a ServerState,
    ip: IpAddr,
    held: bool,
}

impl Drop for FileSlot<'_> {
    fn drop(&mut self) {
        if self.held {
            self.state.limits.from_files(self.ip);
        }
    }
}

/// How long one request's body may take on HTTP/1.1: a 1 MiB chunk needs
/// about 140 kbit/s for it, and a slower link sends smaller chunks.
const BODY_TIME: Duration = Duration::from_secs(60);

async fn serve_requests<S>(
    stream: &mut S,
    head: String,
    mut buf: Vec<u8>,
    state: &Arc<ServerState>,
    peer: SocketAddr,
    deadline: Instant,
    slot: &mut FileSlot<'_>,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut next = Some(head);
    loop {
        let head = match next.take() {
            Some(head) => head,
            None => match tokio::time::timeout(
                crate::tunnel::HEAD_TIMEOUT,
                crate::tunnel::read_head(stream, &mut buf),
            )
            .await
            {
                Ok(crate::tunnel::Head::Got(head)) => head,
                _ => return,
            },
        };
        let Some((method, target)) = request_line(&head).filter(|_| crlf_only(&head)) else {
            let _ = write_reply(stream, &text(400, "bad request"), false, true).await;
            return;
        };
        let header = |name: &str| voipc_protocol::ws::header(&head, name);
        if header("transfer-encoding").is_some() {
            let _ = write_reply(
                stream,
                &text(501, "only Content-Length bodies"),
                false,
                true,
            )
            .await;
            return;
        }
        let Some(len) = content_length(&head) else {
            let _ = write_reply(stream, &text(400, "bad Content-Length"), false, true).await;
            return;
        };
        let closing = header("connection").is_some_and(|v| v.trim().eq_ignore_ascii_case("close"))
            || Instant::now() >= deadline;
        let reply = match prepare(state, peer.ip(), method, target, header("authorization")) {
            // Refused before its body: a body there may be is not read, so the
            // connection cannot carry on past it
            Prepared::Reply(reply) => {
                let _ = write_reply(stream, &reply, method == "HEAD", closing || len > 0).await;
                if len > 0 {
                    linger(stream, &buf, len).await;
                }
                if closing || len > 0 {
                    return;
                }
                continue;
            }
            Prepared::Put(claim) => {
                if len > claim.max_body {
                    let reply = text(413, "more bytes than the upload has left");
                    let _ = write_reply(stream, &reply, false, true).await;
                    linger(stream, &buf, len).await;
                    return;
                }
                // Counted from this request's head, not the connection's
                // start: a chunk on a reused connection gets as long as one on
                // a fresh one
                let body = match tokio::time::timeout(
                    BODY_TIME,
                    read_body(stream, &mut buf, len, BODY_IDLE),
                )
                .await
                {
                    Ok(Ok(body)) => body,
                    _ => return,
                };
                finish_put(state, claim, body).await
            }
            Prepared::Get { hash, ticket } => {
                if len > 0 {
                    let reply = text(400, "a download has no body");
                    let _ = write_reply(stream, &reply, false, true).await;
                    return;
                }
                finish_get(state, peer.ip(), hash, &ticket, header("range")).await
            }
            Prepared::EmotePut(upload) => {
                if len != upload.len {
                    let reply = text(400, "the file is not the size it was said to be");
                    let _ = write_reply(stream, &reply, false, true).await;
                    linger(stream, &buf, len).await;
                    return;
                }
                let body = match tokio::time::timeout(
                    BODY_TIME,
                    read_body(stream, &mut buf, len, BODY_IDLE),
                )
                .await
                {
                    Ok(Ok(body)) => body,
                    _ => return,
                };
                crate::emotes::finish_put(state, upload, body).await
            }
        };
        // A good ticket: out of the pre-authentication pool, which voice
        // joins from this address need, into the file one (`ConnLimits`)
        if !slot.held && reply.status < 300 {
            slot.held = state.limits.to_files(peer.ip());
        }
        if write_reply(stream, &reply, method == "HEAD", closing)
            .await
            .is_err()
            || closing
        {
            return;
        }
    }
}

/// How long a refused request's body is read for before the close.
const LINGER: Duration = Duration::from_secs(5);

/// Before closing on a request whose body was refused unread: read and drop
/// what is left of it, at most `MAX_CHUNK`, for at most `LINGER`. Closed with
/// the body unread, the socket answers it with a reset, and a peer that has
/// not read the answer yet loses it (Windows drops received data on a reset):
/// a 409's `upload-offset` among them, which the resume path depends on
/// (P9-01). `buf` holds what was read past the head already.
async fn linger<S: AsyncRead + Unpin>(stream: &mut S, buf: &[u8], len: usize) {
    let mut left = len.min(MAX_CHUNK).saturating_sub(buf.len());
    let mut chunk = [0u8; 16 * 1024];
    let _ = tokio::time::timeout(LINGER, async {
        while left > 0 {
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => left = left.saturating_sub(n),
            }
        }
    })
    .await;
}

/// Whether every line of a head ends in CRLF. A bare LF is a line break to
/// this parser (`str::lines`) and not to every other one, so a proxy in front
/// could read other headers than we do. There is none, so this is hardening
/// (S-029).
fn crlf_only(head: &str) -> bool {
    let bytes = head.as_bytes();
    bytes.iter().enumerate().all(|(i, &b)| match b {
        b'\n' => i > 0 && bytes[i - 1] == b'\r',
        b'\r' => bytes.get(i + 1) == Some(&b'\n'),
        _ => true,
    })
}

/// The body's length: 0 without a `Content-Length`, `None` for one that is
/// repeated or not plain digits (`+5`, which `parse` takes), the other two
/// ways a proxy and this parser could disagree about where a body ends.
fn content_length(head: &str) -> Option<usize> {
    let mut values = head.lines().skip(1).filter_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("content-length")
            .then(|| value.trim())
    });
    let Some(value) = values.next() else {
        return Some(0);
    };
    if values.next().is_some() || value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

/// `GET /f/v1/… HTTP/1.1` → the method and the target.
fn request_line(head: &str) -> Option<(&str, &str)> {
    let mut parts = head.lines().next()?.split(' ');
    let (method, target, version) = (parts.next()?, parts.next()?, parts.next()?);
    (version.starts_with("HTTP/1.") && parts.next().is_none()).then_some((method, target))
}

/// How long a body may go without a byte: a sender whose connection died (a
/// phone changing networks) would otherwise keep its upload's one chunk slot,
/// and every retry at that offset would hear 409, for all of `BODY_TIME`
/// (P9-02).
const BODY_IDLE: Duration = Duration::from_secs(15);

/// `len` bytes of body, after what `buf` holds already; none for `idle` ends it.
async fn read_body<S: AsyncRead + Unpin>(
    stream: &mut S,
    buf: &mut Vec<u8>,
    len: usize,
    idle: Duration,
) -> std::io::Result<Bytes> {
    let mut chunk = [0u8; 16 * 1024];
    while buf.len() < len {
        let n = tokio::time::timeout(idle, stream.read(&mut chunk))
            .await
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))??;
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let rest = buf.split_off(len);
    Ok(Bytes::from(std::mem::replace(buf, rest)))
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        206 => "Partial Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        413 => "Content Too Large",
        416 => "Range Not Satisfiable",
        422 => "Unprocessable Content",
        429 => "Too Many Requests",
        501 => "Not Implemented",
        _ => "Internal Server Error",
    }
}

async fn write_reply<S: AsyncWrite + Unpin>(
    stream: &mut S,
    reply: &Reply,
    head_only: bool,
    closing: bool,
) -> std::io::Result<()> {
    let mut out = format!("HTTP/1.1 {} {}\r\n", reply.status, reason(reply.status));
    for (name, value) in &reply.headers {
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    if reply.status != 204 {
        out.push_str(&format!("content-length: {}\r\n", reply.body.len()));
    }
    out.push_str(if closing {
        "connection: close\r\n\r\n"
    } else {
        "connection: keep-alive\r\n\r\n"
    });
    let mut bytes = out.into_bytes();
    if !head_only && reply.status != 204 {
        bytes.extend_from_slice(&reply.body);
    }
    stream.write_all(&bytes).await?;
    stream.flush().await
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::config::ServerConfig;
    use crate::settings::ServerSettings;

    /// A directory removed with everything in it when dropped.
    pub(crate) struct TempDir(pub PathBuf);

    impl TempDir {
        pub(crate) fn new() -> TempDir {
            let dir = std::env::temp_dir()
                .join(format!("voipc-files-{}", hex(&rand::random::<[u8; 8]>())));
            std::fs::create_dir_all(&dir).unwrap();
            TempDir(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    pub(crate) fn config_in(dir: &TempDir) -> FilesConfig {
        FilesConfig {
            dir: dir.0.to_string_lossy().into_owned(),
            ..FilesConfig::default()
        }
    }

    /// A server state with a file cache in a fresh directory.
    pub(crate) fn state_with_files(
        tweak: impl FnOnce(&mut FilesConfig),
    ) -> (Arc<ServerState>, TempDir) {
        let dir = TempDir::new();
        let mut files = config_in(&dir);
        tweak(&mut files);
        let mut state = ServerState::new(
            &ServerConfig::default(),
            ServerSettings::default(),
            Vec::new(),
            "test-admin-token".into(),
        );
        state.files = Some(Arc::new(FileStore::open(&files).unwrap()));
        (Arc::new(state), dir)
    }

    /// Bytes that do not repeat, and their blob id.
    pub(crate) fn blob(len: usize, seed: u8) -> (Vec<u8>, [u8; 32]) {
        let bytes: Vec<u8> = (0..len)
            .map(|i| (i as u32).wrapping_mul(2_654_435_761).to_le_bytes()[3] ^ seed)
            .collect();
        let hash = Sha256::digest(&bytes).into();
        (bytes, hash)
    }

    pub(crate) fn path_of(hash: &[u8; 32]) -> String {
        format!("/f/v1/{}", hex(hash))
    }

    /// An upload ticket for `size` bytes of `hash`, as if session 1 had asked.
    pub(crate) fn upload_ticket(state: &ServerState, hash: [u8; 32], size: u64) -> String {
        let store = state.files.as_ref().unwrap();
        let out = store.upload(hash, Place::Channel(1), size, (1, IP), Instant::now());
        out.into_iter()
            .find_map(|o| match o {
                Out::To(_, ServerMessage::FileUploadReady { ticket, .. }) => Some(ticket),
                _ => None,
            })
            .expect("an upload ticket")
    }

    /// A download ticket for `hash`, as if session 2 had asked.
    pub(crate) fn read_ticket(state: &ServerState, hash: [u8; 32]) -> String {
        let store = state.files.as_ref().unwrap();
        let out = store.fetch(hash, Place::Channel(1), (2, IP), Instant::now());
        out.into_iter()
            .find_map(|o| match o {
                Out::To(_, ServerMessage::FileReady { ticket, .. }) => Some(ticket),
                _ => None,
            })
            .expect("a download ticket")
    }

    const IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;

    const A: SessionId = 1;
    const B: SessionId = 2;
    const C: SessionId = 3;
    const D: SessionId = 4;
    const IP_A: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));
    const IP_B: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2));
    const IP_C: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 3));
    const IP_D: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 4));
    const CH: Place = Place::Channel(7);

    fn store(tweak: impl FnOnce(&mut FilesConfig)) -> (Arc<FileStore>, TempDir) {
        let dir = TempDir::new();
        let mut config = config_in(&dir);
        tweak(&mut config);
        (Arc::new(FileStore::open(&config).unwrap()), dir)
    }

    fn messages(out: &[Out], session: SessionId) -> Vec<&ServerMessage> {
        out.iter()
            .filter_map(|o| match o {
                Out::To(s, m)
                | Out::Waited {
                    session: s, msg: m, ..
                } if *s == session => Some(m),
                _ => None,
            })
            .collect()
    }

    fn upload_ticket(out: &[Out], session: SessionId) -> String {
        messages(out, session)
            .into_iter()
            .find_map(|m| match m {
                ServerMessage::FileUploadReady { ticket, .. } => Some(ticket.clone()),
                _ => None,
            })
            .unwrap_or_else(|| panic!("no upload ticket for {session}"))
    }

    fn read_ticket(out: &[Out], session: SessionId) -> (String, u64) {
        messages(out, session)
            .into_iter()
            .find_map(|m| match m {
                ServerMessage::FileReady { ticket, size, .. } => Some((ticket.clone(), *size)),
                _ => None,
            })
            .unwrap_or_else(|| panic!("no download ticket for {session}"))
    }

    fn refusal(out: &[Out], session: SessionId) -> String {
        refusal_with_code(out, session).1
    }

    fn refusal_with_code(out: &[Out], session: SessionId) -> (u16, String) {
        messages(out, session)
            .into_iter()
            .find_map(|m| match m {
                ServerMessage::FileRefused { code, reason, .. } => Some((*code, reason.clone())),
                _ => None,
            })
            .unwrap_or_else(|| panic!("no refusal for {session}"))
    }

    fn says(out: &[Out], session: SessionId, what: fn(&ServerMessage) -> bool) -> bool {
        messages(out, session).into_iter().any(what)
    }

    /// Upload `bytes` whole for `session`, in chunks of 1 MiB.
    async fn upload_all(
        store: &Arc<FileStore>,
        hash: [u8; 32],
        bytes: &[u8],
        place: Place,
        who: (SessionId, IpAddr),
        now: Instant,
    ) -> Vec<Out> {
        let ticket = upload_ticket(
            &store.upload(hash, place, bytes.len() as u64, who, now),
            who.0,
        );
        let mut last = Vec::new();
        for (i, chunk) in bytes.chunks(MAX_CHUNK).enumerate() {
            let (result, out) = store
                .put_chunk(hash, &ticket, (i * MAX_CHUNK) as u64, chunk, now)
                .await;
            assert!(matches!(result, Put::Accepted(_) | Put::Stored));
            last = out;
        }
        last
    }

    async fn download_all(
        store: &Arc<FileStore>,
        hash: [u8; 32],
        ticket: &str,
        size: u64,
        now: Instant,
    ) -> Vec<u8> {
        let mut got = Vec::new();
        while (got.len() as u64) < size {
            let range = format!("bytes={}-", got.len());
            match store.get(hash, ticket, Some(&range), now).await {
                Get::Bytes {
                    start,
                    end,
                    total,
                    data,
                } => {
                    assert_eq!((start, total), (got.len() as u64, size));
                    assert!(end - start < MAX_CHUNK as u64);
                    got.extend_from_slice(&data);
                }
                _ => panic!("no bytes at {}", got.len()),
            }
        }
        got
    }

    #[tokio::test]
    async fn a_blob_goes_up_and_down_in_chunks() {
        let (store, dir) = store(|_| {});
        let now = Instant::now();
        let (bytes, hash) = blob(2 * MAX_CHUNK + 1234, 1);
        let up = upload_ticket(
            &store.upload(hash, CH, bytes.len() as u64, (A, IP_A), now),
            A,
        );
        let mut out = Vec::new();
        for (i, chunk) in bytes.chunks(MAX_CHUNK).enumerate() {
            let (result, o) = store
                .put_chunk(hash, &up, (i * MAX_CHUNK) as u64, chunk, now)
                .await;
            match (i, result) {
                (0 | 1, Put::Accepted(n)) => assert_eq!(n, ((i + 1) * MAX_CHUNK) as u64),
                (2, Put::Stored) => out = o,
                _ => panic!("chunk {i}"),
            }
        }
        assert!(says(&out, A, |m| matches!(
            m,
            ServerMessage::FileStored { .. }
        )));
        assert!(dir.0.join(hex(&hash)).exists(), "stored under its hash");

        let out = store.fetch(hash, CH, (B, IP_B), now);
        let (ticket, size) = read_ticket(&out, B);
        assert_eq!(size, bytes.len() as u64);
        assert_eq!(download_all(&store, hash, &ticket, size, now).await, bytes);

        // No range: the first chunk. Past the end: refused.
        match store.get(hash, &ticket, None, now).await {
            Get::Bytes { start: 0, end, .. } => assert_eq!(end, MAX_CHUNK as u64 - 1),
            _ => panic!("no first chunk"),
        }
        let past = format!("bytes={}-", bytes.len());
        assert!(matches!(
            store.get(hash, &ticket, Some(&past), now).await,
            Get::Unsatisfiable(n) if n == size
        ));
        // The upload ticket is spent: it was never a download ticket, and a
        // chunk sent with it now hears that the upload has ended
        assert!(!matches!(
            store.get(hash, &up, None, now).await,
            Get::Bytes { .. }
        ));
        assert!(matches!(
            store.put_chunk(hash, &up, 0, &bytes[..10], now).await.0,
            Put::Gone
        ));
    }

    #[tokio::test]
    async fn an_upload_resumes_where_the_relay_has_it() {
        let (store, _dir) = store(|_| {});
        let now = Instant::now();
        let (bytes, hash) = blob(MAX_CHUNK + 10, 2);
        let ticket = upload_ticket(
            &store.upload(hash, CH, bytes.len() as u64, (A, IP_A), now),
            A,
        );
        assert!(matches!(
            store
                .put_chunk(hash, &ticket, 0, &bytes[..MAX_CHUNK], now)
                .await
                .0,
            Put::Accepted(_)
        ));
        // The connection dropped; the client sends the first chunk again
        assert!(matches!(
            store.put_chunk(hash, &ticket, 0, &bytes[..MAX_CHUNK], now).await.0,
            Put::Conflict(n) if n == MAX_CHUNK as u64
        ));
        assert!(matches!(
            store
                .put_chunk(hash, &ticket, MAX_CHUNK as u64, &bytes[MAX_CHUNK..], now)
                .await
                .0,
            Put::Stored
        ));
    }

    #[tokio::test]
    async fn the_same_blob_is_stored_once_and_registered_again() {
        let (store, _dir) = store(|_| {});
        let now = Instant::now();
        let (bytes, hash) = blob(5000, 3);
        upload_all(&store, hash, &bytes, CH, (A, IP_A), now).await;
        // A forward into another conversation: no upload, just a registration
        let elsewhere = Place::Channel(8);
        let out = store.upload(hash, elsewhere.clone(), 5000, (B, IP_B), now);
        assert!(says(&out, B, |m| matches!(
            m,
            ServerMessage::FileStored { .. }
        )));
        let (ticket, _) = read_ticket(&store.fetch(hash, elsewhere, (C, IP_C), now), C);
        assert_eq!(download_all(&store, hash, &ticket, 5000, now).await, bytes);
    }

    #[tokio::test]
    async fn one_upload_at_a_time_and_the_others_hear_when_it_lands() {
        let (store, _dir) = store(|_| {});
        let now = Instant::now();
        let (bytes, hash) = blob(3000, 4);
        let ticket = upload_ticket(&store.upload(hash, CH, 3000, (A, IP_A), now), A);
        let waiting = store.upload(hash, CH, 3000, (B, IP_B), now);
        assert!(messages(&waiting, B).is_empty(), "B waits behind A");
        // A asks again: the same ticket
        assert_eq!(
            upload_ticket(&store.upload(hash, CH, 3000, (A, IP_A), now), A),
            ticket
        );
        let (result, out) = store.put_chunk(hash, &ticket, 0, &bytes, now).await;
        assert!(matches!(result, Put::Stored));
        assert!(says(&out, A, |m| matches!(
            m,
            ServerMessage::FileStored { .. }
        )));
        assert!(says(&out, B, |m| matches!(
            m,
            ServerMessage::FileStored { .. }
        )));
    }

    #[tokio::test]
    async fn a_cancelled_or_abandoned_upload_passes_to_the_next_member() {
        let (store, _dir) = store(|_| {});
        let now = Instant::now();
        let (bytes, hash) = blob(3000, 5);
        upload_ticket(&store.upload(hash, CH, 3000, (A, IP_A), now), A);
        store.upload(hash, CH, 3000, (B, IP_B), now);
        store.upload(hash, CH, 3000, (C, IP_C), now);
        let ticket_b = upload_ticket(&store.cancel(hash, A, now), B);
        // B's connection ends: C is next
        let ticket_c = upload_ticket(&store.forget_session(B, now), C);
        assert!(matches!(
            store.put_chunk(hash, &ticket_b, 0, &bytes, now).await.0,
            Put::Gone
        ));
        assert!(matches!(
            store.put_chunk(hash, &ticket_c, 0, &bytes, now).await.0,
            Put::Stored
        ));
    }

    /// A chunk that arrives after its upload was cancelled writes nothing
    /// that stays.
    #[tokio::test]
    async fn a_chunk_racing_a_cancel_leaves_no_file() {
        let (store, dir) = store(|_| {});
        let now = Instant::now();
        let (bytes, hash) = blob(2 * MAX_CHUNK, 23);
        let ticket = upload_ticket(
            &store.upload(hash, CH, bytes.len() as u64, (A, IP_A), now),
            A,
        );
        // The request has the upload's handle when the cancel lands
        let io = store.lock().entries[&hash]
            .upload
            .as_ref()
            .unwrap()
            .io
            .clone();
        let held = io.lock().await;
        let put = store.put_chunk(hash, &ticket, 0, &bytes[..MAX_CHUNK], now);
        let racing = async {
            store.cancel(hash, A, now);
            drop(held);
        };
        let ((result, _), ()) = tokio::join!(put, racing);
        assert!(matches!(result, Put::Gone));
        assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 0);
        let inner = store.lock();
        assert_eq!((inner.stored, inner.writing, inner.reserved), (0, 0, 0));
    }

    #[tokio::test]
    async fn bytes_that_are_not_the_blob_are_refused() {
        let (store, dir) = store(|_| {});
        let now = Instant::now();
        let (bytes, hash) = blob(3000, 6);
        let ticket = upload_ticket(&store.upload(hash, CH, 3000, (A, IP_A), now), A);
        store.upload(hash, CH, 3000, (B, IP_B), now);
        let mut wrong = bytes.clone();
        wrong[0] ^= 1;
        let (result, out) = store.put_chunk(hash, &ticket, 0, &wrong, now).await;
        assert!(matches!(result, Put::Mismatch));
        assert!(refusal(&out, A).contains("not the file"));
        upload_ticket(&out, B);
        assert!(!dir.0.join(hex(&hash)).exists());
        assert_eq!(
            std::fs::read_dir(&dir.0).unwrap().count(),
            0,
            "the part file is gone too"
        );
    }

    #[tokio::test]
    async fn sizes_out_of_bounds_are_refused() {
        let (store, _dir) = store(|c| c.max_size_mb = 1);
        let now = Instant::now();
        let (_, hash) = blob(10, 7);
        assert!(refusal(&store.upload(hash, CH, MIB + 1, (A, IP_A), now), A).contains("larger"));
        assert!(refusal(&store.upload(hash, CH, 0, (A, IP_A), now), A).contains("larger"));
        let ticket = upload_ticket(&store.upload(hash, CH, 10, (A, IP_A), now), A);
        assert!(matches!(
            store.put_chunk(hash, &ticket, 0, &[0; 11], now).await.0,
            Put::TooLong
        ));
    }

    #[tokio::test]
    async fn budgets_are_per_connection_and_per_address() {
        let (store, _dir) = store(|c| {
            c.max_size_mb = 2;
            c.upload_mb_per_hour = 2;
            c.download_mb_per_hour = 2;
        });
        let now = Instant::now();
        let (one, h1) = blob(2 * MAX_CHUNK, 8);
        let (_, h2) = blob(MAX_CHUNK, 9);
        upload_all(&store, h1, &one, CH, (A, IP_A), now).await;
        assert!(refusal(&store.upload(h2, CH, MIB, (A, IP_A), now), A).contains("a lot"));
        // Another connection from the same address shares its budget
        assert!(refusal(&store.upload(h2, CH, MIB, (B, IP_A), now), B).contains("a lot"));
        upload_ticket(&store.upload(h2, CH, MIB, (C, IP_C), now), C);
        // An hour later it has refilled
        let later = now + Duration::from_secs(3600);
        store.cancel(h2, C, later);
        upload_ticket(&store.upload(h2, CH, MIB, (A, IP_A), later), A);

        read_ticket(&store.fetch(h1, CH, (B, IP_B), now), B);
        assert!(refusal(&store.fetch(h1, CH, (B, IP_B), now), B).contains("a lot"));
    }

    #[tokio::test]
    async fn tickets_end_after_ten_minutes_and_with_their_session() {
        let (store, _dir) = store(|_| {});
        let now = Instant::now();
        let (bytes, hash) = blob(3000, 10);
        upload_all(&store, hash, &bytes, CH, (A, IP_A), now).await;
        let (ticket, _) = read_ticket(&store.fetch(hash, CH, (B, IP_B), now), B);
        assert!(matches!(
            store.get(hash, "0123", None, now).await,
            Get::Unauthorized
        ));
        let soon = now + TICKET_LIFETIME - Duration::from_secs(1);
        assert!(matches!(
            store.get(hash, &ticket, None, soon).await,
            Get::Bytes { .. }
        ));
        let late = now + TICKET_LIFETIME;
        assert!(matches!(
            store.get(hash, &ticket, None, late).await,
            Get::Unauthorized
        ));

        // Its session ended: spent, so a request still on its way is told so
        let (ticket, _) = read_ticket(&store.fetch(hash, CH, (B, IP_B), now), B);
        store.forget_session(B, now);
        assert!(matches!(
            store.get(hash, &ticket, None, now).await,
            Get::Gone
        ));
    }

    /// R1-03: a slow link that keeps sending real chunks keeps its upload
    /// (to `UPLOAD_MAX_LIFE`); a trickle of tiny chunks still ends at
    /// `TICKET_LIFETIME`.
    #[tokio::test]
    async fn an_upload_that_keeps_sending_outlives_ten_minutes_and_a_trickle_does_not() {
        let (store, _dir) = store(|_| {});
        let t0 = Instant::now();
        // The first chunk at once, then one every 2.5 min: never stalled,
        // done after 12.5 min
        let (bytes, hash) = blob(6 * SLIDE_CHUNK as usize, 21);
        let ticket = upload_ticket(
            &store.upload(hash, CH, bytes.len() as u64, (A, IP_A), t0),
            A,
        );
        let mut at = t0;
        for (i, chunk) in bytes.chunks(SLIDE_CHUNK as usize).enumerate() {
            if i > 0 {
                at += Duration::from_secs(150);
            }
            assert!(
                messages(&store.sweep(at), A).is_empty(),
                "ended before chunk {i}"
            );
            let off = (i as u64) * SLIDE_CHUNK;
            let (put, out) = store.put_chunk(hash, &ticket, off, chunk, at).await;
            assert!(matches!(put, Put::Accepted(_) | Put::Stored), "chunk {i}");
            if i == 5 {
                assert!(says(&out, A, |m| matches!(
                    m,
                    ServerMessage::FileStored { .. }
                )));
            }
        }

        let (bytes, hash) = blob(4096, 22);
        let ticket = upload_ticket(
            &store.upload(hash, CH, bytes.len() as u64, (B, IP_B), t0),
            B,
        );
        for i in 0..9u64 {
            let at = t0 + Duration::from_secs(60 * (i + 1));
            let (put, _) = store
                .put_chunk(hash, &ticket, i, &bytes[i as usize..][..1], at)
                .await;
            assert!(matches!(put, Put::Accepted(_)));
        }
        let out = store.sweep(t0 + TICKET_LIFETIME);
        assert!(refusal(&out, B).contains("too long"));
    }

    /// S-001: a ticket's budget was charged for one read, so it reads its
    /// blob once and a retry, then hears "gone, fetch it again".
    #[tokio::test]
    async fn a_ticket_reads_its_blob_at_most_twice() {
        let (store, _dir) = store(|_| {});
        let now = Instant::now();
        let (bytes, hash) = blob(3000, 18);
        upload_all(&store, hash, &bytes, CH, (A, IP_A), now).await;
        let (ticket, size) = read_ticket(&store.fetch(hash, CH, (B, IP_B), now), B);
        assert_eq!(download_all(&store, hash, &ticket, size, now).await, bytes);
        assert_eq!(download_all(&store, hash, &ticket, size, now).await, bytes);
        assert!(matches!(
            store.get(hash, &ticket, Some("bytes=0-0"), now).await,
            Get::Gone
        ));
        // A new fetch is a new ticket, charged again
        let (ticket, _) = read_ticket(&store.fetch(hash, CH, (B, IP_B), now), B);
        assert!(matches!(
            store.get(hash, &ticket, None, now).await,
            Get::Bytes { .. }
        ));
    }

    /// S-001: bytes a reader never takes hold their ticket's turn, so one
    /// ticket never has more than one chunk waiting in memory.
    #[tokio::test]
    async fn a_ticket_has_one_request_in_flight_until_its_bytes_are_dropped() {
        let (store, _dir) = store(|_| {});
        let now = Instant::now();
        let (bytes, hash) = blob(3000, 19);
        upload_all(&store, hash, &bytes, CH, (A, IP_A), now).await;
        let (ticket, _) = read_ticket(&store.fetch(hash, CH, (B, IP_B), now), B);
        let Get::Bytes { data: first, .. } = store.get(hash, &ticket, None, now).await else {
            panic!("no bytes");
        };
        let second = store.get(hash, &ticket, None, now);
        tokio::pin!(second);
        let waited = tokio::time::timeout(Duration::from_millis(100), &mut second).await;
        assert!(waited.is_err(), "the second request did not wait");
        drop(first);
        assert!(matches!(second.await, Get::Bytes { .. }));
    }

    #[tokio::test]
    async fn a_blob_lives_while_fetched_but_never_past_its_age() {
        let (store, dir) = store(|c| {
            c.cache_mins = 30;
            c.max_age_hours = 1;
        });
        let t0 = Instant::now();
        let (bytes, hash) = blob(3000, 11);
        upload_all(&store, hash, &bytes, CH, (A, IP_A), t0).await;
        let min = |m: u64| t0 + Duration::from_secs(m * 60);
        // Fetched every 25 minutes: alive past the first 30
        for m in [25, 50] {
            store.sweep(min(m));
            read_ticket(&store.fetch(hash, CH, (B, IP_B), min(m)), B);
        }
        // 61 minutes after it arrived it goes, though fetched 11 minutes ago
        store.sweep(min(61));
        assert!(!dir.0.join(hex(&hash)).exists());
        let out = store.fetch(hash, CH, (B, IP_B), min(61));
        assert!(says(&out, B, |m| matches!(
            m,
            ServerMessage::FileSeeking { .. }
        )));
    }

    #[tokio::test]
    async fn a_blob_nobody_fetches_goes_after_cache_mins() {
        let (store, dir) = store(|c| c.cache_mins = 30);
        let t0 = Instant::now();
        let (bytes, hash) = blob(3000, 12);
        upload_all(&store, hash, &bytes, CH, (A, IP_A), t0).await;
        store.sweep(t0 + Duration::from_secs(29 * 60));
        assert!(dir.0.join(hex(&hash)).exists());
        store.sweep(t0 + Duration::from_secs(30 * 60));
        assert!(!dir.0.join(hex(&hash)).exists());
        assert_eq!(store.lock().stored, 0);
    }

    #[tokio::test]
    async fn a_blob_that_has_gone_is_asked_for_and_the_waiter_is_served() {
        let (store, _dir) = store(|c| c.cache_mins = 30);
        let t0 = Instant::now();
        let (bytes, hash) = blob(3000, 13);
        let dm = direct(Party::Guest(A), Party::Guest(B));
        upload_all(&store, hash, &bytes, CH, (A, IP_A), t0).await;
        store.upload(hash, dm.clone(), 3000, (A, IP_A), t0);
        let gone = t0 + Duration::from_secs(31 * 60);
        store.sweep(gone);

        let out = store.fetch(hash, CH, (C, IP_C), gone);
        assert!(says(&out, C, |m| matches!(
            m,
            ServerMessage::FileSeeking { .. }
        )));
        let mut asked: Vec<Place> = out
            .iter()
            .filter_map(|o| match o {
                Out::Want { place, except, .. } => {
                    assert_eq!(*except, C);
                    Some(place.clone())
                }
                _ => None,
            })
            .collect();
        asked.sort_by_key(|p| format!("{p:?}"));
        // D-5: the asker's conversation, not the direct one it was also
        // posted in
        assert_eq!(asked, vec![CH]);
        // A second fetch waits too, without asking again
        let again = store.fetch(hash, CH, (B, IP_B), gone);
        assert!(!again.iter().any(|o| matches!(o, Out::Want { .. })));

        // A holds it and uploads it again; both waiters get a ticket
        let out = upload_all(&store, hash, &bytes, CH, (A, IP_A), gone).await;
        let (ticket, size) = read_ticket(&out, C);
        read_ticket(&out, B);
        assert_eq!(download_all(&store, hash, &ticket, size, gone).await, bytes);
    }

    // R1-07: a member without the blob claims its re-seed and trickles. The
    // holder is still asked, queues behind it, and takes over once it is
    // quiet for `QUEUED_IDLE`; the waiter is served.
    #[tokio::test]
    async fn a_bogus_upload_does_not_keep_a_blob_from_its_holders() {
        let (store, _dir) = store(|c| c.cache_mins = 30);
        let t0 = Instant::now();
        let (bytes, hash) = blob(3000, 44);
        upload_all(&store, hash, &bytes, CH, (A, IP_A), t0).await;
        let gone = t0 + Duration::from_secs(31 * 60);
        store.sweep(gone);
        let bogus = upload_ticket(&store.upload(hash, CH, 3000, (C, IP_C), gone), C);
        store.put_chunk(hash, &bogus, 0, &[0], gone).await;

        let out = store.fetch(hash, CH, (B, IP_B), gone);
        assert!(
            out.iter()
                .any(|o| matches!(o, Out::Want { place, .. } if *place == CH)),
            "asked with an upload under way"
        );
        assert!(messages(&store.upload(hash, CH, 3000, (A, IP_A), gone), A).is_empty());
        let out = store.sweep(gone + QUEUED_IDLE);
        assert!(refusal(&out, C).contains("stalled"));
        let ticket = upload_ticket(&out, A);
        let (put, out) = store
            .put_chunk(hash, &ticket, 0, &bytes, gone + QUEUED_IDLE)
            .await;
        assert!(matches!(put, Put::Stored));
        read_ticket(&out, B);
    }

    // R1-07: an upload that sends nothing ends after `FIRST_BYTE`.
    #[tokio::test]
    async fn an_upload_that_never_sends_a_byte_ends_soon() {
        let (store, _dir) = store(|_| {});
        let now = Instant::now();
        let (_, hash) = blob(3000, 45);
        upload_ticket(&store.upload(hash, CH, 3000, (C, IP_C), now), C);
        let out = store.sweep(now + FIRST_BYTE - Duration::from_secs(1));
        assert!(messages(&out, C).is_empty());
        assert!(refusal(&store.sweep(now + FIRST_BYTE), C).contains("stalled"));
    }

    // S-005: an upload that stalls with members waiting and nobody behind it.
    // Their conversation is asked again then, and the seek starts over, so
    // nobody hears "unavailable" without a holder asked since.
    #[tokio::test]
    async fn a_stalled_re_seed_asks_again_before_anyone_hears_unavailable() {
        let (store, _dir) = store(|c| c.cache_mins = 30);
        let t0 = Instant::now();
        let (bytes, hash) = blob(3000, 46);
        upload_all(&store, hash, &bytes, CH, (A, IP_A), t0).await;
        let gone = t0 + Duration::from_secs(31 * 60);
        store.sweep(gone);
        let ticket = upload_ticket(&store.upload(hash, CH, 3000, (C, IP_C), gone), C);
        store.put_chunk(hash, &ticket, 0, &bytes[..10], gone).await;
        store.fetch(hash, CH, (B, IP_B), gone);

        let stalled = gone + UPLOAD_IDLE;
        let out = store.sweep(stalled);
        assert!(refusal(&out, C).contains("stalled"));
        assert!(out.iter().any(|o| matches!(
            o,
            Out::Want { place, except, .. } if *place == CH && *except == C
        )));
        let unavailable = |m: &ServerMessage| matches!(m, ServerMessage::FileUnavailable { .. });
        assert!(!says(&out, B, unavailable));
        let out = store.sweep(stalled + SEEK_TIMEOUT - Duration::from_secs(1));
        assert!(!says(&out, B, unavailable));
        assert!(says(&store.sweep(stalled + SEEK_TIMEOUT), B, unavailable));
    }

    // R1-11 / S-020 (D-6): a guest's side of a direct conversation is their
    // connection. A later guest who takes the same name is no party to it:
    // not asked for its files, and their own conversation with the same
    // person is another one.
    #[tokio::test]
    async fn a_later_guest_with_the_same_name_is_no_party_to_a_dm() {
        use crate::state::test_support::add_user;
        let (state, _dir) = state_with_files(|_| {});
        let (_, alice) = add_user(&state, "alice#0001");
        let (bob_uid, bob) = add_user(&state, "bob#0012");
        let (dm, _) = resolve(&state, alice, FileConv::Direct(bob_uid))
            .await
            .unwrap();
        let bob_side = Party::Guest(bob_uid);
        assert_eq!(dm, direct(Party::Guest(alice), bob_side.clone()));
        assert_eq!(sessions_of(&state, &bob_side), vec![bob]);

        state.remove_session(bob).await;
        let (later_uid, _) = add_user(&state, "bob#0012");
        assert!(sessions_of(&state, &bob_side).is_empty());
        assert_eq!(conv_for(&state, &bob_side), None);
        let (theirs, _) = resolve(&state, alice, FileConv::Direct(later_uid))
            .await
            .unwrap();
        assert_ne!(theirs, dm);
    }

    // R1-09: a waiter who asks late gets a whole `SEEK_TIMEOUT` of its own,
    // not what is left of the first one's.
    #[tokio::test]
    async fn a_late_waiter_waits_as_long_as_the_first() {
        let (store, _dir) = store(|c| c.cache_mins = 30);
        let t0 = Instant::now();
        let (bytes, hash) = blob(3000, 47);
        upload_all(&store, hash, &bytes, CH, (A, IP_A), t0).await;
        let gone = t0 + Duration::from_secs(31 * 60);
        store.sweep(gone);
        store.fetch(hash, CH, (B, IP_B), gone);
        let late = gone + SEEK_TIMEOUT - Duration::from_secs(1);
        store.fetch(hash, CH, (C, IP_C), late);
        let unavailable = |m: &ServerMessage| matches!(m, ServerMessage::FileUnavailable { .. });
        let out = store.sweep(gone + SEEK_TIMEOUT);
        assert!(says(&out, B, unavailable));
        assert!(!says(&out, C, unavailable));
        assert!(!says(
            &store.sweep(late + SEEK_TIMEOUT - Duration::from_secs(1)),
            C,
            unavailable
        ));
        assert!(says(&store.sweep(late + SEEK_TIMEOUT), C, unavailable));
    }

    #[tokio::test]
    async fn nobody_with_the_blob_in_time_is_unavailable() {
        let (store, _dir) = store(|c| c.cache_mins = 30);
        let t0 = Instant::now();
        let (bytes, hash) = blob(3000, 14);
        upload_all(&store, hash, &bytes, CH, (A, IP_A), t0).await;
        let gone = t0 + Duration::from_secs(31 * 60);
        store.sweep(gone);
        store.fetch(hash, CH, (C, IP_C), gone);
        assert!(store
            .sweep(gone + SEEK_TIMEOUT - Duration::from_secs(1))
            .is_empty());
        let out = store.sweep(gone + SEEK_TIMEOUT);
        assert!(says(&out, C, |m| matches!(
            m,
            ServerMessage::FileUnavailable { .. }
        )));
        // A later fetch asks again
        let out = store.fetch(hash, CH, (C, IP_C), gone + SEEK_TIMEOUT);
        assert!(out.iter().any(|o| matches!(o, Out::Want { .. })));
    }

    /// R1-02: a hash not registered in the asker's conversation (posted
    /// before a restart, long ago, elsewhere, or never) is sought there, and
    /// only there; a blob stored for other conversations is never handed over
    /// without a member of the asker's posting it there. Unknown and
    /// elsewhere look the same.
    #[tokio::test]
    async fn an_unregistered_hash_is_sought_in_the_askers_conversation_only() {
        let (store, _dir) = store(|_| {});
        let now = Instant::now();
        let nine = Place::Channel(9);
        let (bytes, hash) = blob(3000, 15);
        upload_all(&store, hash, &bytes, CH, (A, IP_A), now).await;
        let (_, unknown) = blob(3000, 16);
        for h in [hash, unknown] {
            let out = store.fetch(h, nine.clone(), (B, IP_B), now);
            assert!(says(&out, B, |m| matches!(
                m,
                ServerMessage::FileSeeking { .. }
            )));
            assert!(!says(&out, B, |m| matches!(
                m,
                ServerMessage::FileReady { .. }
            )));
            let asked: Vec<&Place> = out
                .iter()
                .filter_map(|o| match o {
                    Out::Want { place, .. } => Some(place),
                    _ => None,
                })
                .collect();
            assert_eq!(asked, [&nine]);
        }
        // Asked once per `SEEK_TIMEOUT`, however often its members fetch
        let again = store.fetch(hash, nine.clone(), (C, IP_C), now);
        assert!(!again.iter().any(|o| matches!(o, Out::Want { .. })));

        // A member of channel 9 who holds it posts it there: the waiters are served
        let out = store.upload(hash, nine.clone(), bytes.len() as u64, (D, IP_D), now);
        assert!(says(&out, D, |m| matches!(
            m,
            ServerMessage::FileStored { .. }
        )));
        for who in [B, C] {
            assert!(out
                .iter()
                .any(|o| matches!(o, Out::Waited { session, .. } if *session == who)));
        }

        // Stored through channel 1 meanwhile: channel 9's waiter waits on
        let (bytes, hash) = blob(3000, 23);
        store.fetch(hash, nine.clone(), (B, IP_B), now);
        let out = upload_all(&store, hash, &bytes, CH, (A, IP_A), now).await;
        assert!(!out
            .iter()
            .any(|o| matches!(o, Out::Waited { session, .. } if *session == B)));
        let out = store.sweep(now + SEEK_TIMEOUT);
        assert!(says(&out, B, |m| matches!(
            m,
            ServerMessage::FileUnavailable { .. }
        )));
    }

    /// A program reads the class from the code, never from the words: under
    /// 100 the same request gets the same answer, from 100 a later one may not.
    #[tokio::test]
    async fn a_refusal_says_by_its_code_whether_to_try_again() {
        let (store, _dir) = store(|_| {});
        let now = Instant::now();
        let (_, hash) = blob(3000, 17);
        let (code, _) = refusal_with_code(&store.upload(hash, CH, 0, (A, IP_A), now), A);
        assert_eq!(code, FILE_TOO_LARGE);
        for _ in 0..SESSION_OPS.0 as usize {
            store.fetch(hash, CH, (B, IP_B), now);
        }
        let (code, _) = refusal_with_code(&store.fetch(hash, CH, (B, IP_B), now), B);
        assert_eq!(code, FILE_RATE);
        let finals = [
            FILE_NOT_HERE,
            FILE_OFF,
            FILE_TOO_LARGE,
            FILE_PLACES,
            FILE_MISMATCH,
        ];
        let later = [
            FILE_RATE,
            FILE_BUDGET,
            FILE_BUSY,
            FILE_STALLED,
            FILE_EXPIRED,
            FILE_FAILED,
        ];
        assert!(finals.iter().all(|c| *c < 100) && later.iter().all(|c| *c >= 100));
    }

    // S-004: an index full of small stored blobs still takes a new one. The
    // blob used longest ago that nobody holds a ticket to makes way.
    #[tokio::test]
    async fn an_index_full_of_stored_blobs_still_takes_a_new_one() {
        let (store, _dir) = store(|_| {});
        let now = Instant::now();
        let key = |i: u32| {
            let mut hash = [0u8; 32];
            hash[..4].copy_from_slice(&i.to_be_bytes());
            hash
        };
        {
            let mut inner = store.lock();
            for i in 0..MAX_ENTRIES as u32 {
                // 0 is being read; 1 is the least recently used of the rest
                let used = now + Duration::from_secs(if i < 2 { 1 } else { 2 });
                let mut entry = Entry {
                    blob: Some(Blob {
                        size: 10,
                        stored: now,
                        used: if i == 0 { now } else { used },
                    }),
                    ever_stored: true,
                    ..Entry::default()
                };
                entry.places.push((CH, now));
                if i == 0 {
                    entry.readers.push(Ticket::new(B, now));
                }
                inner.entries.insert(key(i), entry);
                inner.stored += 10;
            }
        }
        let (_, hash) = blob(10, 40);
        let later = now + Duration::from_secs(3);
        upload_ticket(&store.upload(hash, CH, 10, (A, IP_A), later), A);
        let inner = store.lock();
        assert_eq!(inner.entries.len(), MAX_ENTRIES);
        assert!(
            inner.entries.contains_key(&key(0)),
            "a blob being read stays"
        );
        assert!(!inner.entries.contains_key(&key(1)));
        assert_eq!(inner.stored, (MAX_ENTRIES as u64 - 1) * 10);
    }

    // R1-04: a blob dropped while a new copy of it arrives. The unlink runs
    // after the lock, by then the new copy is in place, and it must survive.
    #[tokio::test]
    async fn a_late_unlink_never_deletes_a_newer_copy() {
        let (store, _dir) = store(|_| {});
        let now = Instant::now();
        let (bytes, hash) = blob(5000, 41);
        upload_all(&store, hash, &bytes, CH, (A, IP_A), now).await;
        let mut trash = Trash::default();
        {
            let mut inner = store.lock();
            store.drop_blob(&mut inner, &hash, &mut trash);
        }
        // Uploaded again before the unlink of the old one runs
        upload_all(&store, hash, &bytes, CH, (A, IP_A), now).await;
        trash.empty();
        let (ticket, size) = read_ticket(&store.fetch(hash, CH, (B, IP_B), now), B);
        assert_eq!(download_all(&store, hash, &ticket, size, now).await, bytes);
    }

    // R1-04: a blob whose file has gone from the disk leaves the index at the
    // first read that misses it, so the next fetch seeks it again.
    #[tokio::test]
    async fn a_blob_lost_from_the_disk_is_sought_again() {
        let (store, dir) = store(|_| {});
        let now = Instant::now();
        let (bytes, hash) = blob(5000, 42);
        upload_all(&store, hash, &bytes, CH, (A, IP_A), now).await;
        std::fs::remove_file(dir.0.join(hex(&hash))).unwrap();
        let (ticket, _) = read_ticket(&store.fetch(hash, CH, (B, IP_B), now), B);
        assert!(matches!(
            store.get(hash, &ticket, None, now).await,
            Get::Gone
        ));
        let out = store.fetch(hash, CH, (B, IP_B), now);
        assert!(says(&out, B, |m| matches!(
            m,
            ServerMessage::FileSeeking { .. }
        )));
        assert_eq!(store.lock().stored, 0);
    }

    // R1-05: a PUT dropped while its chunk is written (a reset stream, the
    // connection's deadline). The chunk is finished anyway, so the upload
    // goes on from where the relay has it and ends stored, not 422.
    #[tokio::test]
    async fn a_put_dropped_mid_write_does_not_poison_its_upload() {
        let (state, _dir) = state_with_files(|_| {});
        let (bytes, hash) = blob(MAX_CHUNK + 10, 43);
        let ticket = super::test_support::upload_ticket(&state, hash, bytes.len() as u64);
        let auth = format!("Bearer {ticket}");
        let at = |offset: usize| format!("{}?offset={offset}", path_of(&hash));
        {
            let target = at(0);
            let first = http(
                &state,
                IP_A,
                "PUT",
                &target,
                Some(&auth),
                None,
                Bytes::copy_from_slice(&bytes[..MAX_CHUNK]),
            );
            tokio::pin!(first);
            // One poll, which starts the write, and then the request is gone
            tokio::select! {
                biased;
                _ = &mut first => panic!("the write took no time at all"),
                _ = std::future::ready(()) => {}
            }
        }
        let mut status = 0;
        for _ in 0..200 {
            let rest = Bytes::copy_from_slice(&bytes[MAX_CHUNK..]);
            status = http(&state, IP_A, "PUT", &at(MAX_CHUNK), Some(&auth), None, rest)
                .await
                .status;
            if status != 409 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(status, 201, "the upload ends stored");
    }

    #[tokio::test]
    async fn a_full_cache_makes_room_by_the_least_recently_used() {
        let (store, dir) = store(|c| {
            c.max_size_mb = 1;
            c.max_total_mb = 2;
        });
        let t0 = Instant::now();
        let at = |s: u64| t0 + Duration::from_secs(s);
        let (one, h1) = blob(MAX_CHUNK, 17);
        let (two, h2) = blob(MAX_CHUNK, 18);
        let (three, h3) = blob(MAX_CHUNK, 19);
        upload_all(&store, h1, &one, CH, (A, IP_A), at(0)).await;
        upload_all(&store, h2, &two, CH, (A, IP_A), at(1)).await;
        read_ticket(&store.fetch(h1, CH, (B, IP_B), at(2)), B);
        upload_all(&store, h3, &three, CH, (C, IP_C), at(3)).await;
        assert!(dir.0.join(hex(&h1)).exists(), "fetched last, kept");
        assert!(!dir.0.join(hex(&h2)).exists(), "used least recently, gone");
        assert!(dir.0.join(hex(&h3)).exists());
    }

    #[tokio::test]
    async fn an_upload_that_never_finishes_leaves_nothing_behind() {
        let (store, _dir) = store(|_| {});
        let now = Instant::now();
        let (_, hash) = blob(3000, 20);
        upload_ticket(&store.upload(hash, CH, 3000, (A, IP_A), now), A);
        let out = store.sweep(now + TICKET_LIFETIME);
        assert!(refusal(&out, A).contains("too long"));
        assert!(store.lock().entries.is_empty());
        assert_eq!(store.lock().reserved, 0);
    }

    #[tokio::test]
    async fn a_registration_outlives_its_blob_for_a_while() {
        let (store, _dir) = store(|c| c.cache_mins = 30);
        let t0 = Instant::now();
        let (bytes, hash) = blob(3000, 21);
        upload_all(&store, hash, &bytes, CH, (A, IP_A), t0).await;
        store.sweep(t0 + Duration::from_secs(31 * 60));
        assert!(
            store.lock().entries.contains_key(&hash),
            "so a fetch can still ask"
        );
        store.sweep(t0 + REGISTRATION_LIFETIME);
        assert!(store.lock().entries.is_empty());
    }

    #[tokio::test]
    async fn file_messages_are_rate_limited() {
        let (store, _dir) = store(|_| {});
        let now = Instant::now();
        let (_, hash) = blob(10, 22);
        for _ in 0..SESSION_OPS.0 as usize {
            store.fetch(hash, CH, (A, IP_A), now);
        }
        assert!(refusal(&store.fetch(hash, CH, (A, IP_A), now), A).contains("slow down"));
    }

    /// An upload that has not sent a byte evicts nobody's file: blobs go
    /// for bytes as they arrive, and reservations alone only cap uploads.
    #[tokio::test]
    async fn a_reservation_alone_evicts_nothing() {
        let (store, dir) = store(|c| {
            c.max_size_mb = 2;
            c.max_total_mb = 2;
        });
        let now = Instant::now();
        let (one, h1) = blob(MAX_CHUNK, 24);
        let (two, h2) = blob(MAX_CHUNK, 25);
        upload_all(&store, h1, &one, CH, (A, IP_A), now).await;
        upload_all(&store, h2, &two, CH, (A, IP_A), now).await;
        let (three, h3) = blob(MAX_CHUNK, 26);
        let ticket = upload_ticket(&store.upload(h3, CH, MIB, (B, IP_B), now), B);
        assert!(dir.0.join(hex(&h1)).exists() && dir.0.join(hex(&h2)).exists());
        // Reservations together stay within the cache
        let (_, h4) = blob(10, 27);
        assert!(refusal(&store.upload(h4, CH, 2 * MIB, (C, IP_C), now), C).contains("busy"));
        // The bytes arriving make the room
        assert!(matches!(
            store.put_chunk(h3, &ticket, 0, &three, now).await.0,
            Put::Stored
        ));
        assert_eq!(
            [h1, h2, h3]
                .iter()
                .filter(|h| dir.0.join(hex(&h[..])).exists())
                .count(),
            2
        );
    }

    /// A member queued behind another upload keeps the size it asked for:
    /// one that declared a wrong size cannot hand the next its mistake.
    #[tokio::test]
    async fn a_queued_member_keeps_its_own_size() {
        let (store, _dir) = store(|_| {});
        let now = Instant::now();
        let (bytes, hash) = blob(3000, 28);
        upload_ticket(&store.upload(hash, CH, 1, (A, IP_A), now), A);
        store.upload(hash, CH, 3000, (B, IP_B), now);
        let ticket = upload_ticket(&store.cancel(hash, A, now), B);
        assert!(matches!(
            store.put_chunk(hash, &ticket, 0, &bytes, now).await.0,
            Put::Stored
        ));
    }

    #[tokio::test]
    async fn a_stalled_upload_passes_to_the_next_member() {
        let (store, _dir) = store(|_| {});
        let now = Instant::now();
        let (bytes, hash) = blob(3000, 29);
        let ticket = upload_ticket(&store.upload(hash, CH, 3000, (A, IP_A), now), A);
        store.put_chunk(hash, &ticket, 0, &bytes[..100], now).await;
        // Alone, it may be quiet for `UPLOAD_IDLE`
        let alone = now + UPLOAD_IDLE - Duration::from_secs(1);
        assert!(messages(&store.sweep(alone), A).is_empty());
        // With somebody queued behind it, for `QUEUED_IDLE`
        let (bytes, hash) = blob(3000, 30);
        let ticket = upload_ticket(&store.upload(hash, CH, 3000, (A, IP_A), now), A);
        store.put_chunk(hash, &ticket, 0, &bytes[..100], now).await;
        store.upload(hash, CH, 3000, (B, IP_B), now);
        let out = store.sweep(now + QUEUED_IDLE - Duration::from_secs(1));
        assert!(messages(&out, A).is_empty());
        let out = store.sweep(now + QUEUED_IDLE);
        assert!(refusal(&out, A).contains("stalled"));
        upload_ticket(&out, B);
    }

    /// One chunk at a time per upload, and none past its end: a carrier
    /// never holds more than one body for an upload, or a body larger than
    /// what it has left.
    #[tokio::test]
    async fn an_upload_takes_one_chunk_at_a_time() {
        let (store, _dir) = store(|_| {});
        let now = Instant::now();
        let (bytes, hash) = blob(3000, 30);
        let ticket = upload_ticket(&store.upload(hash, CH, 3000, (A, IP_A), now), A);
        let first = store.claim(hash, &ticket, 0, now).ok().unwrap();
        assert_eq!(first.max_body, 3000);
        assert!(matches!(
            store.claim(hash, &ticket, 0, now),
            Err(Put::Conflict(0))
        ));
        drop(first);
        assert!(matches!(
            store.put_chunk(hash, &ticket, 0, &[], now).await.0,
            Put::Empty
        ));
        assert!(matches!(
            store.put_chunk(hash, &ticket, 0, &bytes, now).await.0,
            Put::Stored
        ));
        assert!(matches!(
            store.claim(hash, &ticket, 3000, now),
            Err(Put::Gone)
        ));
    }

    /// A write that fails ends the upload, and counts nothing.
    #[tokio::test]
    async fn a_failed_write_ends_the_upload() {
        let (store, dir) = store(|_| {});
        let now = Instant::now();
        let (bytes, hash) = blob(3000, 31);
        let out = store.upload(hash, CH, 3000, (A, IP_A), now);
        let ticket = upload_ticket(&out, A);
        // Its part file's name is taken by a directory: it cannot be made
        std::fs::create_dir(dir.0.join(format!("{}.0.part", hex(&hash)))).unwrap();
        let (result, out) = store.put_chunk(hash, &ticket, 0, &bytes, now).await;
        assert!(matches!(result, Put::Failed));
        assert!(refusal(&out, A).contains("could not store"));
        let inner = store.lock();
        assert_eq!((inner.stored, inner.writing, inner.reserved), (0, 0, 0));
    }

    /// A ticket that matched nothing counts against the address; one that
    /// was good a moment ago does not.
    #[tokio::test]
    async fn only_tickets_that_match_nothing_are_guesses() {
        let (state, _dir) = state_with_files(|_| {});
        let store = state.files.clone().unwrap();
        let ip: IpAddr = "10.9.9.9".parse().unwrap();
        let now = Instant::now();
        let (bytes, hash) = blob(3000, 32);
        upload_all(&store, hash, &bytes, CH, (A, IP_A), now).await;
        let (ticket, _) = read_ticket(&store.fetch(hash, CH, (B, IP_B), now), B);
        store.forget_session(B, now);
        let get = |ticket: String| {
            let state = state.clone();
            async move {
                let auth = format!("Bearer {ticket}");
                http(
                    &state,
                    ip,
                    "GET",
                    &path_of(&hash),
                    Some(&auth),
                    None,
                    Bytes::new(),
                )
                .await
                .status
            }
        };
        for _ in 0..50 {
            assert_eq!(get(ticket.clone()).await, 404, "spent: gone, not a guess");
        }
        for _ in 0..GUESSES.0 as usize {
            assert_eq!(get("junk".into()).await, 401);
        }
        assert_eq!(get("junk".into()).await, 429);
        // S-022: a good ticket from the same address is still served
        let (good, _) = read_ticket(&store.fetch(hash, CH, (C, IP_C), now), C);
        assert_eq!(get(good).await, 206);
        // The admin token's budget is untouched
        assert!(state.token_guess_allowed(ip));
    }

    // P9-02: a body that stops arriving ends the request after `BODY_IDLE`,
    // well before `BODY_TIME`, and gives its upload's chunk slot back.
    #[tokio::test]
    async fn a_body_that_stops_arriving_ends_its_request_soon() {
        use tokio::io::AsyncWriteExt as _;
        assert!(BODY_IDLE < BODY_TIME / 2);
        let idle = Duration::from_millis(100);
        let (mut sender, mut relay) = tokio::io::duplex(1 << 16);
        sender.write_all(&[7; 10]).await.unwrap();
        let started = Instant::now();
        let read = read_body(&mut relay, &mut Vec::new(), 100, idle).await;
        assert_eq!(read.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
        assert!(started.elapsed() >= idle);
        // Bytes that keep coming, however slowly, do not trip it
        let (mut sender, mut relay) = tokio::io::duplex(1 << 16);
        let trickle = tokio::spawn(async move {
            for _ in 0..5 {
                sender.write_all(&[7; 20]).await.unwrap();
                tokio::time::sleep(idle / 2).await;
            }
        });
        let body = read_body(&mut relay, &mut Vec::new(), 100, idle).await;
        assert_eq!(body.unwrap().len(), 100);
        trickle.await.unwrap();
    }

    // S-026: a download ticket pushed out by newer ones is spent, not
    // unknown: it hears "gone" (404) and costs its address no guess (401).
    #[tokio::test]
    async fn a_ticket_pushed_out_by_newer_ones_is_gone_not_a_guess() {
        let (state, _dir) = state_with_files(|_| {});
        let store = state.files.clone().unwrap();
        let now = Instant::now();
        let (bytes, hash) = blob(3000, 49);
        upload_all(&store, hash, &bytes, CH, (A, IP_A), now).await;
        let mut tickets = Vec::new();
        for _ in 0..=MAX_TICKETS {
            let mut inner = store.lock();
            match store.ready(&mut inner, hash, (B, IP_B, &CH), 3000, now, &mut Vec::new()) {
                Some(ServerMessage::FileReady { ticket, .. }) => tickets.push(ticket),
                _ => panic!("no ticket"),
            }
        }
        let status = |ticket: &str| {
            let auth = format!("Bearer {ticket}");
            let state = state.clone();
            async move {
                http(
                    &state,
                    IP_B,
                    "GET",
                    &path_of(&hash),
                    Some(&auth),
                    None,
                    Bytes::new(),
                )
                .await
                .status
            }
        };
        assert_eq!(status(&tickets[0]).await, 404);
        assert_eq!(status(&tickets[MAX_TICKETS]).await, 206);
    }

    // S-021: leaving a channel ends the download tickets handed out there; a
    // request still on its way hears "gone". A ticket from elsewhere stays.
    #[tokio::test]
    async fn leaving_a_channel_ends_its_download_tickets() {
        let (store, _dir) = store(|_| {});
        let now = Instant::now();
        let (bytes, hash) = blob(3000, 50);
        let other = Place::Channel(8);
        upload_all(&store, hash, &bytes, CH, (A, IP_A), now).await;
        store.upload(hash, other.clone(), 3000, (A, IP_A), now);
        let (here, _) = read_ticket(&store.fetch(hash, CH, (B, IP_B), now), B);
        let (there, _) = read_ticket(&store.fetch(hash, other, (B, IP_B), now), B);
        store.left(B, &CH);
        assert!(matches!(store.get(hash, &here, None, now).await, Get::Gone));
        assert!(matches!(
            store.get(hash, &there, None, now).await,
            Get::Bytes { .. }
        ));
    }

    // R1-12: the cache directory and its blobs are this user's only.
    #[cfg(unix)]
    #[tokio::test]
    async fn the_cache_is_readable_by_its_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let parent = TempDir::new();
        let config = FilesConfig {
            dir: parent.0.join("files").to_string_lossy().into_owned(),
            ..FilesConfig::default()
        };
        let store = Arc::new(FileStore::open(&config).unwrap());
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&store.dir), 0o700);
        let (bytes, hash) = blob(3000, 48);
        upload_all(&store, hash, &bytes, CH, (A, IP_A), Instant::now()).await;
        assert_eq!(mode(&store.blob_path(&hash)), 0o600);
    }

    #[test]
    fn only_blob_files_are_wiped_at_start() {
        let dir = TempDir::new();
        let hash = hex(&[0xab; 32]);
        for name in [
            "notes.txt".to_string(),
            hash.clone(),
            format!("{hash}.3.part"),
            format!("{hash}.x.part"),
            hash.to_uppercase(),
        ] {
            std::fs::write(dir.0.join(name), b"x").unwrap();
        }
        std::fs::create_dir(dir.0.join(hex(&[0xcd; 32]))).unwrap();
        FileStore::open(&config_in(&dir)).unwrap();
        let mut left: Vec<String> = std::fs::read_dir(&dir.0)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        let mut want = vec![
            "notes.txt".to_string(),
            format!("{hash}.x.part"),
            hash.to_uppercase(),
            hex(&[0xcd; 32]),
        ];
        want.sort();
        assert_eq!(left, want);
    }

    #[test]
    fn ranges() {
        let m = MAX_CHUNK as u64;
        assert_eq!(byte_range(None, 10), Some((0, 9)));
        assert_eq!(byte_range(None, 3 * m), Some((0, m - 1)));
        assert_eq!(byte_range(Some("bytes=2-5"), 10), Some((2, 5)));
        assert_eq!(byte_range(Some("bytes=2-"), 10), Some((2, 9)));
        assert_eq!(byte_range(Some("bytes=2-99"), 10), Some((2, 9)));
        assert_eq!(byte_range(Some("bytes=0-"), 3 * m), Some((0, m - 1)));
        assert_eq!(byte_range(Some("bytes=10-"), 10), None);
        assert_eq!(byte_range(Some("bytes=5-2"), 10), None);
        assert_eq!(byte_range(Some("bytes=-5"), 10), None);
        assert_eq!(byte_range(Some("bytes=0-1,4-5"), 10), None);
        assert_eq!(byte_range(Some("items=0-1"), 10), None);
        assert_eq!(byte_range(None, 0), None);
    }
}
