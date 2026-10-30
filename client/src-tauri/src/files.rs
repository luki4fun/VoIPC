//! Files in chat, the transfer half (protocol v13): `send_file`, `fetch_file`
//! and the cache their blobs stay in.
//!
//! A file is sealed here (`voipc_crypto::file`), and only its blob, which
//! opens with the key in its message alone, leaves the device. The control
//! stream negotiates (`FileUpload`, `FileFetch`; the relay's answers come in
//! through [`Files::on_message`]). The bytes go over HTTPS on the session's
//! own port, `PUT`/`GET /f/v1/<blob id>` on HTTP/1.1, behind the session's
//! pinned certificate (`transport::connect_files`). Never over the session's
//! QUIC connection or tunnel: voice and video would queue behind a file.
//!
//! - **Chunks** are sized to the link: what took about [`CHUNK_TIME`] last
//!   time, from [`MIN_CHUNK`] to the relay's 1 MiB. A request cut off with no
//!   answer goes again from the same offset, smaller. An upload starts at 0
//!   and follows the relay's `upload-offset`. A download whose ticket has gone
//!   (404) fetches again and goes on where it stopped. One request at a time
//!   per ticket: the relay serves a ticket's requests one by one anyway. And
//!   one connection per server, which [`TRANSFERS_AT_ONCE`] transfers take
//!   turns on (the rest wait before they ask): each connection holds one of
//!   the address's places on the relay while it lives.
//! - **In a call** (voice on any server) transfers yield to it: chunks of
//!   [`CALL_CHUNK`], each followed by a pause as long as it took, so a file
//!   takes half of what it measures at most. A FIFO-queued link a file fills
//!   otherwise delays voice behind it. The mode is looked at for each chunk.
//! - **Answers can be lost**: the relay drops what a full queue cannot take.
//!   A request met with a minute of silence is sent again, which the relay
//!   answers as it did the first time.
//! - **The cache** is `<data dir>/files/<blob id>`: blobs as the relay holds
//!   them. Their keys live only in the chat archive. Least recently used goes
//!   first past `file_cache_mb`. The front end drops what no message refers
//!   to any more (`file_cache_retain`), and without an archive the cache is
//!   wiped at start.
//! - **Re-seed.** The relay asks a conversation for a blob it no longer has
//!   (`FileWanted`). Only an ask for a blob cached here reaches the front end,
//!   and the front end answers (`reseed_file`) only when a message in that
//!   conversation refers to it. One re-seed at a time, after up to 2 s of
//!   jitter, with nothing on screen.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};
use tauri::State;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, Notify};
use tracing::{debug, warn};
use voipc_crypto::file::{FileError, FileMeta, MAX_FILE_BLOB, MAX_FILE_PLAIN};
use voipc_protocol::conv::{hex, unhex};
use voipc_protocol::messages::{
    ClientMessage, ServerMessage, FILE_BUSY, FILE_EXPIRED, FILE_RATE, FILE_STALLED,
};
use voipc_protocol::types::{Emote, EmoteAccess, FileConv, FileLimits};
use voipc_protocol::ws;

use crate::app_state::{conn, AppState};
use crate::network::send_tcp_message_sync;

const KIB: u64 = 1024;
const MIB: u64 = 1024 * 1024;
/// The relay's largest chunk, either way.
const MAX_CHUNK: u64 = MIB;
/// The smallest chunk: the least that keeps an upload's ticket sliding.
const MIN_CHUNK: u64 = 64 * KIB;
/// The first chunk, before anything is known about the link.
const FIRST_CHUNK: u64 = 256 * KIB;
/// The chunk while in a call: the floor. Measured on a 20 Mbit/s link with a
/// 200-packet FIFO queue, 10 MiB up while voice ran: 128 and 256 KiB chunks
/// cost 2 voice frames in 200 (each burst queues ahead of voice), 64 KiB 0–1.
const CALL_CHUNK: u64 = MIN_CHUNK;
/// The longest pause after a chunk while in a call.
const CALL_GAP_MAX: Duration = Duration::from_secs(10);
/// What one chunk should take. The relay gives a request body 60 s.
const CHUNK_TIME: Duration = Duration::from_secs(15);
/// The longest one request may take, answer included.
const REQUEST_TIME: Duration = Duration::from_secs(90);
/// How long a transfer goes on trying with nothing moving (requests cut off,
/// a 409 at its own offset, a 429) before it gives up: past the 60 s the
/// relay may still be reading a chunk whose sender has gone.
const STALL_TIME: Duration = Duration::from_secs(2 * 60);
/// A connection the relay has had no request on for this long is not reused:
/// it waits 5 s for the next one.
const IDLE_REUSE: Duration = Duration::from_secs(4);
/// How many times one transfer asks the relay (a ticket that has gone, an
/// upload that ended) before it gives up. A download's ask that brought bytes
/// is not counted (`Asks`).
const MAX_ASKS: u32 = 4;
/// Transfers per server whose requests take turns on its connection at once;
/// the others wait before they ask. So a new upload's first chunk waits
/// behind one other chunk at most (~`CHUNK_TIME`), well inside the 30 s the
/// relay gives it (R3-04).
const TRANSFERS_AT_ONCE: usize = 2;
/// Silence after a request before it is sent again.
const REPLY_WAIT: Duration = Duration::from_secs(60);
/// The same while the relay asks members for the file: each ask may reach
/// them all again, so rarely.
const SEEK_RESEND: Duration = Duration::from_secs(5 * 60);
/// How long to wait before asking again after a refusal that may pass later
/// (`asks_again`).
const RATE_PAUSE: Duration = Duration::from_secs(5);
/// How long an upload waits for its ticket: another member's upload of the
/// same blob may go first, and the relay passes it on after 3 min of nothing.
const UPLOAD_WAIT: Duration = Duration::from_secs(10 * 60);
/// How long a fetch waits for the relay's first answer.
const FETCH_WAIT: Duration = Duration::from_secs(2 * 60);
/// How long a fetch waits once the relay is asking members: it ends the wait
/// itself (`FileUnavailable`), and an upload under way lasts an hour at most.
const SEEK_WAIT: Duration = Duration::from_secs(65 * 60);
/// A cached blob no message refers to stays this long after it was last used,
/// so one just sent outlives the moment before its message is filed.
const RETAIN_GRACE: Duration = Duration::from_secs(10 * 60);
/// The longest answer head the relay writes is well under this.
const MAX_HEAD: usize = 8 * 1024;

const CLOSED: &str = "the connection to the server ended";
const CANCELLED: &str = "cancelled";
const FILES_OFF: &str = "this server keeps no files";
/// What `fetch_file` fails with when nobody online had the file in time.
const UNAVAILABLE: &str = "Nobody online has this file";

/// A conversation as the front end names it: `{"channel": id}`,
/// `{"direct": user id}` or `{"account": hex}` (a kept direct conversation
/// with someone who may be away).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Conv {
    Channel(u32),
    Direct(u32),
    Account(String),
}

impl Conv {
    fn wire(&self) -> Result<FileConv, String> {
        Ok(match self {
            Conv::Channel(id) => FileConv::Channel(*id),
            Conv::Direct(id) => FileConv::Direct(*id),
            Conv::Account(a) => FileConv::Account(unhex::<16>(a).ok_or("invalid account")?),
        })
    }

    fn of(conv: &FileConv) -> Conv {
        match conv {
            FileConv::Channel(id) => Conv::Channel(*id),
            FileConv::Direct(id) => Conv::Direct(*id),
            FileConv::Account(a) => Conv::Account(hex(a)),
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

// ── One connection's transfers ───────────────────────────────────────────

/// Where a connection's file events go: `emit_server` under its server id.
pub type Emit = Box<dyn Fn(&str, serde_json::Value) + Send + Sync>;

/// The file side of one connection.
pub struct Files {
    emit: Emit,
    /// Whether voice is on, on any server: transfers then yield to it.
    in_call: Box<dyn Fn() -> bool + Send + Sync>,
    host: String,
    port: u16,
    accept_invalid_certs: bool,
    /// `Authenticated.files`: `None` when the relay keeps no files.
    limits: Option<FileLimits>,
    tcp_tx: mpsc::UnboundedSender<Vec<u8>>,
    /// The one connection to `/f/`, opened when first needed and again
    /// whenever the relay closes it (it serves one for a minute).
    link: tokio::sync::Mutex<Option<Http<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>>>,
    /// The transfer under way on each blob, and where its answers go. The
    /// relay's answers name only the blob, so there is one per blob at a time.
    waits: Mutex<HashMap<[u8; 32], mpsc::UnboundedSender<ServerMessage>>>,
    /// A blob's transfer has ended.
    freed: Notify,
    /// `TRANSFERS_AT_ONCE` places on `link`; closed with the connection.
    slots: tokio::sync::Semaphore,
    closed: AtomicBool,
    /// `Authenticated.emotes`: `None` when the relay has none (emotes.rs).
    pub(crate) emotes: Option<EmoteAccess>,
    /// Emote adds waiting for the relay's answer: by name and file.
    emote_waits: Mutex<Vec<EmoteWait>>,
}

/// An `EmoteAdd` waiting: a ticket to upload with, `None` when the relay had
/// the file and listed it at once, or why not.
pub(crate) struct EmoteWait {
    pub name: String,
    pub hash: [u8; 32],
    pub done: tokio::sync::oneshot::Sender<Result<Option<String>, String>>,
}

/// A blob's turn: its transfer's answers, until it is dropped.
struct Turn<'a> {
    files: &'a Files,
    hash: [u8; 32],
    rx: mpsc::UnboundedReceiver<ServerMessage>,
    /// Tell the relay this transfer is given up, when it ends without the
    /// relay having ended it: a ticket or a place in the queue is then freed.
    armed: bool,
}

impl Turn<'_> {
    /// The next answer to `ask`, which goes again after each `every` of
    /// silence until `give_up`.
    async fn next(
        &mut self,
        ask: &ClientMessage,
        every: Duration,
        give_up: Instant,
    ) -> Result<ServerMessage, String> {
        loop {
            match tokio::time::timeout(every, self.rx.recv()).await {
                Ok(Some(msg)) => return Ok(msg),
                Ok(None) => return Err(CLOSED.into()),
                Err(_) if Instant::now() < give_up => self.files.send(ask),
                Err(_) => return Err("the server did not answer in time".into()),
            }
        }
    }

    /// It worked: nothing to give up. After a refusal the turn stays armed:
    /// the refusal may be a late one for an earlier ask, and the cancel then
    /// frees what the latest ask started (it touches nothing else).
    fn done<T>(&mut self, value: T) -> Result<T, String> {
        self.armed = false;
        Ok(value)
    }
}

impl Drop for Turn<'_> {
    fn drop(&mut self) {
        if self.armed && !self.files.closed.load(Ordering::Relaxed) {
            self.files
                .send(&ClientMessage::FileCancel { hash: self.hash });
        }
        lock(&self.files.waits).remove(&self.hash);
        self.files.freed.notify_waiters();
    }
}

/// How an upload's chunks ended.
enum Sent {
    Stored,
    /// The upload has ended (404): ask for it again.
    Gone,
}

/// How a download's ranges ended.
enum Got {
    All,
    /// The ticket has gone (404): fetch again, and go on.
    Gone,
}

impl Files {
    // A connection's parts, each its own: a struct for them would only rename them
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        emit: Emit,
        in_call: Box<dyn Fn() -> bool + Send + Sync>,
        host: String,
        port: u16,
        accept_invalid_certs: bool,
        limits: Option<FileLimits>,
        emotes: Option<EmoteAccess>,
        tcp_tx: mpsc::UnboundedSender<Vec<u8>>,
    ) -> Files {
        Files {
            emit,
            in_call,
            host,
            port,
            accept_invalid_certs,
            limits,
            tcp_tx,
            link: tokio::sync::Mutex::new(None),
            waits: Mutex::new(HashMap::new()),
            freed: Notify::new(),
            slots: tokio::sync::Semaphore::new(TRANSFERS_AT_ONCE),
            closed: AtomicBool::new(false),
            emotes,
            emote_waits: Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn send_msg(&self, msg: &ClientMessage) {
        self.send(msg);
    }

    /// Wait for the relay's answer to an `EmoteAdd` about to be sent.
    pub(crate) fn wait_emote(
        &self,
        name: &str,
        hash: [u8; 32],
    ) -> tokio::sync::oneshot::Receiver<Result<Option<String>, String>> {
        let (done, rx) = tokio::sync::oneshot::channel();
        lock(&self.emote_waits).push(EmoteWait {
            name: name.to_owned(),
            hash,
            done,
        });
        rx
    }

    /// One request about an emote's file on the connection to `/e/`.
    pub(crate) async fn emote_request(
        &self,
        method: &str,
        hash: &[u8; 32],
        token: &str,
        body: &[u8],
    ) -> Result<(u16, Vec<u8>), String> {
        let reply = self
            .request(method, &format!("/e/v1/{}", hex(hash)), token, None, body)
            .await?;
        Ok((reply.status, reply.body))
    }

    /// An emote message from the relay: the list goes to the page, and
    /// answers to the adds waiting here.
    fn on_emote_message(&self, msg: ServerMessage) {
        let mut waits = lock(&self.emote_waits);
        // An add that gave up waiting (`emote_add`'s timeout) takes no answer
        waits.retain(|w| !w.done.is_closed());
        let mut answer =
            |pick: &dyn Fn(&EmoteWait) -> bool, out: Result<Option<String>, String>| -> bool {
                match waits.iter().position(pick) {
                    Some(at) => {
                        let _ = waits.remove(at).done.send(out);
                        true
                    }
                    None => false,
                }
            };
        match msg {
            ServerMessage::EmoteList { stickers, emotes } => {
                // An add the relay answered with the list: it had the file
                for e in &emotes {
                    answer(
                        &|w: &EmoteWait| w.name == e.name && w.hash == e.hash,
                        Ok(None),
                    );
                }
                drop(waits);
                let list: Vec<_> = emotes.iter().map(emote_json).collect();
                (self.emit)(
                    "emote-list",
                    serde_json::json!({ "stickers": stickers, "emotes": list }),
                );
            }
            ServerMessage::EmoteTicket { hash, ticket } => {
                answer(&|w: &EmoteWait| w.hash == hash, Ok(Some(ticket)));
            }
            ServerMessage::EmoteError { name, reason }
                if !answer(&|w: &EmoteWait| w.name == name, Err(reason.clone())) =>
            {
                drop(waits);
                (self.emit)(
                    "emote-error",
                    serde_json::json!({ "name": name, "reason": reason }),
                );
            }
            _ => {}
        }
    }

    fn send(&self, msg: &ClientMessage) {
        send_tcp_message_sync(&self.tcp_tx, msg);
    }

    /// The connection has ended: every transfer on it fails now.
    pub fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        lock(&self.waits).clear();
        lock(&self.emote_waits).clear();
        self.freed.notify_waiters();
        self.slots.close();
    }

    /// A file message from the relay (`is_file_message`).
    pub fn on_message(&self, msg: ServerMessage) {
        if matches!(
            msg,
            ServerMessage::EmoteList { .. }
                | ServerMessage::EmoteTicket { .. }
                | ServerMessage::EmoteError { .. }
        ) {
            return self.on_emote_message(msg);
        }
        let hash = match &msg {
            ServerMessage::FileWanted { conv, hash } => {
                if cached(hash) {
                    (self.emit)(
                        "file-wanted",
                        serde_json::json!({ "conv": Conv::of(conv), "hash": hex(hash) }),
                    );
                }
                return;
            }
            ServerMessage::FileUploadReady { hash, .. }
            | ServerMessage::FileStored { hash }
            | ServerMessage::FileReady { hash, .. }
            | ServerMessage::FileRefused { hash, .. }
            | ServerMessage::FileSeeking { hash }
            | ServerMessage::FileUnavailable { hash } => *hash,
            _ => return,
        };
        if let Some(tx) = lock(&self.waits).get(&hash) {
            let _ = tx.send(msg);
        }
    }

    /// Wait until no other transfer of `hash` runs here, then take its turn.
    async fn turn(&self, hash: [u8; 32]) -> Result<Turn<'_>, String> {
        loop {
            // Made before the look, so a turn freed in between still wakes it
            let freed = self.freed.notified();
            {
                let mut waits = lock(&self.waits);
                if self.closed.load(Ordering::Relaxed) {
                    return Err(CLOSED.into());
                }
                if let std::collections::hash_map::Entry::Vacant(free) = waits.entry(hash) {
                    let (tx, rx) = mpsc::unbounded_channel();
                    free.insert(tx);
                    return Ok(Turn {
                        files: self,
                        hash,
                        rx,
                        armed: true,
                    });
                }
            }
            freed.await;
        }
    }

    /// A place among the transfers that take turns on `link`, after this
    /// blob's turn (never the other way round: a slot is not held while
    /// waiting for a turn).
    async fn slot(&self) -> Result<tokio::sync::SemaphorePermit<'_>, String> {
        self.slots.acquire().await.map_err(|_| CLOSED.into())
    }

    fn progress(&self, op: Option<&str>, stage: &str, done: u64, total: u64) {
        if let Some(op) = op {
            (self.emit)(
                "file-progress",
                serde_json::json!({ "op": op, "stage": stage, "done": done, "total": total }),
            );
        }
    }

    fn limits(&self) -> Result<&FileLimits, String> {
        self.limits.as_ref().ok_or_else(|| FILES_OFF.into())
    }

    /// How a moving picture posted here is kept: the relay's numbers, held to
    /// their ranges (`FileLimits::animation`).
    pub(crate) fn motion(&self) -> voipc_media::Motion {
        self.limits
            .as_ref()
            .map_or_else(voipc_media::Motion::default, |l| {
                let (side, mb) = l.animation();
                voipc_media::Motion {
                    side,
                    keep: (mb as usize) << 20,
                }
            })
    }

    /// Store `blob` on the relay for a message in `conv`.
    pub async fn upload(
        &self,
        conv: FileConv,
        hash: [u8; 32],
        blob: &[u8],
        op: Option<&str>,
    ) -> Result<(), String> {
        let limits = self.limits()?;
        if blob.len() as u64 > limits.max_bytes {
            return Err(too_large(limits.max_bytes));
        }
        let mut turn = self.turn(hash).await?;
        // Before the ask: the relay's clock for the first chunk starts at its
        // answer, so the chunk must not then queue behind every other transfer
        let _slot = self.slot().await?;
        let ask = ClientMessage::FileUpload {
            conv,
            size: blob.len() as u64,
            hash,
        };
        let mut asks = Asks::default();
        while asks.next() {
            self.send(&ask);
            let give_up = Instant::now() + UPLOAD_WAIT;
            loop {
                match turn.next(&ask, REPLY_WAIT, give_up).await? {
                    ServerMessage::FileStored { .. } => return turn.done(()),
                    ServerMessage::FileRefused { code, .. } if asks_again(code) => {
                        tokio::time::sleep(RATE_PAUSE).await;
                        break;
                    }
                    ServerMessage::FileRefused { code, reason, .. } => {
                        return Err(refused(code, &reason))
                    }
                    ServerMessage::FileUploadReady { ticket, .. } => {
                        match self.put(&ticket, &hash, blob, op).await? {
                            // The relay says FileStored too; nothing waits for it
                            Sent::Stored => return turn.done(()),
                            Sent::Gone => break,
                        }
                    }
                    _ => {}
                }
            }
        }
        Err("the server kept ending the upload".into())
    }

    /// The blob `hash` of a message in `conv`, as the relay has it. Checked
    /// against its id by whoever opens it (`file::open`).
    pub async fn fetch(
        &self,
        conv: FileConv,
        hash: [u8; 32],
        op: Option<&str>,
    ) -> Result<Vec<u8>, String> {
        self.limits()?;
        let mut turn = self.turn(hash).await?;
        let mut slot = None;
        let mut have = Vec::new();
        let ask = ClientMessage::FileFetch { conv, hash };
        let mut asks = Asks::default();
        while asks.next() {
            if slot.is_none() {
                slot = Some(self.slot().await?);
            }
            self.send(&ask);
            let mut give_up = Instant::now() + FETCH_WAIT;
            let mut every = REPLY_WAIT;
            loop {
                match turn.next(&ask, every, give_up).await? {
                    ServerMessage::FileReady { ticket, size, .. } => {
                        if size > MAX_FILE_BLOB {
                            return Err("the server offers more bytes than any file has".into());
                        }
                        if have.len() as u64 > size {
                            have.clear();
                        }
                        // The one let go of while members were asked
                        if slot.is_none() {
                            slot = Some(self.slot().await?);
                        }
                        let before = have.len();
                        match self.get(&ticket, &hash, size, &mut have, op).await? {
                            Got::All => return turn.done(have),
                            Got::Gone => {
                                if have.len() > before {
                                    asks.moved();
                                }
                                break;
                            }
                        }
                    }
                    ServerMessage::FileSeeking { .. } => {
                        self.progress(op, "seeking", 0, 0);
                        // The relay ends this wait itself, which can take an
                        // hour: the link is the other transfers' meanwhile
                        slot = None;
                        give_up = Instant::now() + SEEK_WAIT;
                        every = SEEK_RESEND;
                    }
                    ServerMessage::FileUnavailable { .. } => return Err(UNAVAILABLE.into()),
                    ServerMessage::FileRefused { code, .. } if asks_again(code) => {
                        tokio::time::sleep(RATE_PAUSE).await;
                        break;
                    }
                    ServerMessage::FileRefused { code, reason, .. } => {
                        return Err(refused(code, &reason))
                    }
                    _ => {}
                }
            }
        }
        Err("the server kept ending the download".into())
    }

    /// Upload `blob` in chunks with `ticket`.
    async fn put(
        &self,
        ticket: &str,
        hash: &[u8; 32],
        blob: &[u8],
        op: Option<&str>,
    ) -> Result<Sent, String> {
        let path = format!("/f/v1/{}", hex(hash));
        let total = blob.len() as u64;
        let mut pace = Pace::default();
        let mut patience = Patience::new();
        let mut offset = 0u64;
        loop {
            if offset >= total {
                // Everything is there but the relay has not said stored:
                // asking again gets FileStored, or a new upload
                return Ok(Sent::Gone);
            }
            let call = (self.in_call)();
            let end = (offset + pace.next(call)).min(total);
            let started = Instant::now();
            let target = format!("{path}?offset={offset}");
            let reply = match self
                .request(
                    "PUT",
                    &target,
                    ticket,
                    None,
                    &blob[offset as usize..end as usize],
                )
                .await
            {
                Ok(reply) => reply,
                Err(e) => {
                    pace.cut();
                    patience.wait(e).await?;
                    continue;
                }
            };
            match reply.status {
                201 => return Ok(Sent::Stored),
                204 | 409 => {
                    let next = reply
                        .header("upload-offset")
                        .and_then(|v| v.parse::<u64>().ok())
                        .filter(|&n| n <= total)
                        .ok_or("the server sent a bad upload offset")?;
                    if reply.status == 204 {
                        pace.took(next.saturating_sub(offset), started.elapsed());
                    }
                    if next == offset {
                        // Our last chunk is still being read there
                        patience.wait("the upload does not move".into()).await?;
                    } else {
                        patience.moved();
                        yield_to_voice(call, started).await;
                    }
                    offset = next;
                    self.progress(op, "up", offset, total);
                }
                404 => return Ok(Sent::Gone),
                429 => patience.wait("the server is too busy".into()).await?,
                413 => return Err("the file is larger than this server takes".into()),
                422 => return Err("the server says the bytes are not this file".into()),
                status => return Err(format!("the server refused the upload ({status})")),
            }
        }
    }

    /// Download the `size`-byte blob with `ticket`, onto what `have` holds.
    async fn get(
        &self,
        ticket: &str,
        hash: &[u8; 32],
        size: u64,
        have: &mut Vec<u8>,
        op: Option<&str>,
    ) -> Result<Got, String> {
        let path = format!("/f/v1/{}", hex(hash));
        have.reserve_exact((size as usize).saturating_sub(have.len()));
        let mut pace = Pace::default();
        let mut patience = Patience::new();
        while (have.len() as u64) < size {
            let start = have.len() as u64;
            let call = (self.in_call)();
            let end = (start + pace.next(call)).min(size) - 1;
            let started = Instant::now();
            let range = format!("bytes={start}-{end}");
            let reply = match self.request("GET", &path, ticket, Some(&range), &[]).await {
                Ok(reply) => reply,
                Err(e) => {
                    pace.cut();
                    patience.wait(e).await?;
                    continue;
                }
            };
            match reply.status {
                206 => {
                    let sent = reply.header("content-range").and_then(content_range);
                    let n = reply.body.len() as u64;
                    if n == 0 || sent != Some((start, start + n - 1, size)) || start + n - 1 > end {
                        return Err("the server sent other bytes than asked for".into());
                    }
                    have.extend_from_slice(&reply.body);
                    pace.took(n, started.elapsed());
                    patience.moved();
                    self.progress(op, "down", have.len() as u64, size);
                    if (have.len() as u64) < size {
                        yield_to_voice(call, started).await;
                    }
                }
                404 => return Ok(Got::Gone),
                429 => patience.wait("the server is too busy".into()).await?,
                status => return Err(format!("the server refused the download ({status})")),
            }
        }
        Ok(Got::All)
    }
}

/// The relay's answers about files, which `Files::on_message` takes.
pub fn is_file_message(msg: &ServerMessage) -> bool {
    matches!(
        msg,
        ServerMessage::FileUploadReady { .. }
            | ServerMessage::FileStored { .. }
            | ServerMessage::FileReady { .. }
            | ServerMessage::FileRefused { .. }
            | ServerMessage::FileWanted { .. }
            | ServerMessage::FileSeeking { .. }
            | ServerMessage::FileUnavailable { .. }
            | ServerMessage::EmoteList { .. }
            | ServerMessage::EmoteTicket { .. }
            | ServerMessage::EmoteError { .. }
    )
}

/// An emote as the page reads it: its hash in hex.
fn emote_json(e: &Emote) -> serde_json::Value {
    serde_json::json!({ "name": e.name, "hash": hex(&e.hash), "sticker": e.sticker, "pack": e.pack })
}

fn too_large(max: u64) -> String {
    format!(
        "the file is larger than this server takes ({} MB at most)",
        max / 1_000_000
    )
}

/// A refusal after which the same ask may pass a little later: too many at
/// once, the relay busy, or an upload it ended as stalled or too long (a
/// first chunk that queued here can be that). The others are final for the
/// file, or (the hourly budget) for longer than a transfer waits (R3-04).
fn asks_again(code: u16) -> bool {
    matches!(code, FILE_RATE | FILE_BUSY | FILE_STALLED | FILE_EXPIRED)
}

/// The asks one transfer has had of the relay: `MAX_ASKS` at most, and one
/// whose ticket brought bytes before it went is not counted, so a slow
/// download outlives any number of tickets while it moves on (R3-05).
#[derive(Default)]
struct Asks(u32);

impl Asks {
    /// Ask once more, if any ask is left.
    fn next(&mut self) -> bool {
        self.0 += 1;
        self.0 <= MAX_ASKS
    }

    /// The last ask moved the transfer on.
    fn moved(&mut self) {
        self.0 = 0;
    }
}

/// `FileRefused` in words. The relay's own are meant for people.
fn refused(code: u16, reason: &str) -> String {
    debug!(code, "file refused: {reason}");
    reason.to_string()
}

/// `bytes a-b/total`.
fn content_range(v: &str) -> Option<(u64, u64, u64)> {
    let (range, total) = v.trim().strip_prefix("bytes ")?.split_once('/')?;
    let (a, b) = range.split_once('-')?;
    Some((a.parse().ok()?, b.parse().ok()?, total.parse().ok()?))
}

/// The pauses between tries that move nothing on: from half a second,
/// doubling to 8 s, until nothing has moved for `STALL_TIME`.
struct Patience {
    since: Instant,
    tries: u32,
}

impl Patience {
    fn new() -> Self {
        Patience {
            since: Instant::now(),
            tries: 0,
        }
    }

    fn moved(&mut self) {
        *self = Patience::new();
    }

    /// Wait before the next try, or give up with `why`.
    async fn wait(&mut self, why: String) -> Result<(), String> {
        if self.since.elapsed() >= STALL_TIME {
            return Err(why);
        }
        let pause = Duration::from_millis(500 << self.tries.min(4));
        self.tries += 1;
        tokio::time::sleep(pause).await;
        Ok(())
    }
}

/// Chunk sizes for the link at hand.
struct Pace {
    chunk: u64,
}

impl Default for Pace {
    fn default() -> Self {
        Pace { chunk: FIRST_CHUNK }
    }
}

impl Pace {
    /// `bytes` went through in `time`: aim the next chunk at `CHUNK_TIME`.
    fn took(&mut self, bytes: u64, time: Duration) {
        // A last short chunk says little about the link
        if bytes < MIN_CHUNK {
            return;
        }
        let rate = bytes as f64 / time.as_secs_f64().max(0.001);
        self.chunk = ((rate * CHUNK_TIME.as_secs_f64()) as u64).clamp(MIN_CHUNK, MAX_CHUNK);
    }

    /// A request was cut off with no answer: smaller next time.
    fn cut(&mut self) {
        self.chunk = (self.chunk / 2).max(MIN_CHUNK);
    }

    /// The next chunk's size: in a call, `CALL_CHUNK`.
    fn next(&self, in_call: bool) -> u64 {
        if in_call {
            CALL_CHUNK
        } else {
            self.chunk
        }
    }
}

/// In a call, pause after a chunk for as long as it took: the file gets half
/// the link at most, and the queue in front of the link drains in between.
/// Never past `CALL_GAP_MAX`: the relay passes an upload 30 s idle to a
/// member queued behind it. shortcut: the pacing factor is a fixed ½;
/// upgrade to delay-based (voice RTT) if a measurement says so.
async fn yield_to_voice(in_call: bool, chunk_started: Instant) {
    if in_call {
        tokio::time::sleep(chunk_started.elapsed().min(CALL_GAP_MAX)).await;
    }
}

// ── HTTP/1.1 ─────────────────────────────────────────────────────────────

impl Files {
    /// One request on the connection to `/f/`, after any other transfer's
    /// request under way on it.
    async fn request(
        &self,
        method: &str,
        target: &str,
        ticket: &str,
        range: Option<&str>,
        body: &[u8],
    ) -> Result<Reply, String> {
        let host = if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        };
        let mut head = format!(
            "{method} {target} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {ticket}\r\n"
        );
        if let Some(range) = range {
            head.push_str(&format!("Range: {range}\r\n"));
        }
        if method == "PUT" {
            head.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        head.push_str("\r\n");
        let mut link = self.link.lock().await;
        // Out while in use: a request dropped half-way (a cancel, the
        // deadline) takes its connection with it, never leaves it to the next
        let held = link.take().filter(|http| http.used.elapsed() < IDLE_REUSE);
        let attempt = async {
            let mut http = match held {
                Some(http) => http,
                None => Http::new(
                    crate::transport::connect_files(
                        &self.host,
                        self.port,
                        self.accept_invalid_certs,
                    )
                    .await?,
                ),
            };
            let reply = http.request(&head, body).await.map_err(|e| e.to_string())?;
            Ok::<_, String>((http, reply))
        };
        let (http, reply) = tokio::time::timeout(REQUEST_TIME, attempt)
            .await
            .unwrap_or_else(|_| Err("the server did not answer in time".into()))?;
        if !reply.close {
            *link = Some(http);
        }
        Ok(reply)
    }
}

/// One answer.
struct Reply {
    status: u16,
    head: String,
    body: Vec<u8>,
    /// The relay closes the connection after it.
    close: bool,
}

impl Reply {
    fn header(&self, name: &str) -> Option<&str> {
        ws::header(&self.head, name)
    }
}

/// HTTP/1.1 requests one after another on `stream`, each with its body in
/// hand, as the relay's `/f/` serves them (`files.rs serve_http1`).
struct Http<S> {
    stream: S,
    buf: Vec<u8>,
    /// When its last answer ended.
    used: Instant,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Http<S> {
    fn new(stream: S) -> Self {
        Http {
            stream,
            buf: Vec::new(),
            used: Instant::now(),
        }
    }

    async fn request(&mut self, head: &str, body: &[u8]) -> std::io::Result<Reply> {
        let wrote = async {
            self.stream.write_all(head.as_bytes()).await?;
            self.stream.write_all(body).await?;
            self.stream.flush().await
        }
        .await;
        // The relay may answer before the body (a ticket that has gone) and
        // close: that answer is still worth reading
        match (wrote, self.answer().await) {
            (Ok(()), Ok(reply)) => Ok(reply),
            // Not all of the body went out: nothing more goes on this one
            (Err(_), Ok(reply)) => Ok(Reply {
                close: true,
                ..reply
            }),
            (Err(e), Err(_)) | (Ok(()), Err(e)) => Err(e),
        }
    }

    async fn answer(&mut self) -> std::io::Result<Reply> {
        let bad =
            |what: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, what.to_string());
        let end = loop {
            if let Some(end) = ws::find_header_end(&self.buf) {
                break end;
            }
            if self.buf.len() > MAX_HEAD {
                return Err(bad("an answer head that does not end"));
            }
            self.fill().await?;
        };
        let head = String::from_utf8_lossy(&self.buf[..end]).into_owned();
        self.buf.drain(..end);
        let status = head
            .lines()
            .next()
            .and_then(|line| line.strip_prefix("HTTP/1.1 "))
            .and_then(|rest| rest.get(..3))
            .and_then(|code| code.parse::<u16>().ok())
            .ok_or_else(|| bad("not an HTTP/1.1 answer"))?;
        let len = match ws::header(&head, "content-length").map(str::parse::<u64>) {
            Some(Ok(n)) => n,
            None if status == 204 => 0,
            _ => return Err(bad("an answer without its length")),
        };
        if len > MAX_CHUNK + 64 * KIB {
            return Err(bad("an answer longer than a chunk"));
        }
        let len = len as usize;
        while self.buf.len() < len {
            self.fill().await?;
        }
        let rest = self.buf.split_off(len);
        let body = std::mem::replace(&mut self.buf, rest);
        self.used = Instant::now();
        let close =
            ws::header(&head, "connection").is_some_and(|v| v.eq_ignore_ascii_case("close"));
        Ok(Reply {
            status,
            head,
            body,
            close,
        })
    }

    async fn fill(&mut self) -> std::io::Result<()> {
        // Straight into the heap buffer: a stack array here is held across the
        // await and lands in every command future, which Android starts on the
        // WebView's small JavaBridge stack (D2-02, a crash on Load)
        self.buf.reserve(16 * 1024);
        let n = self.stream.read_buf(&mut self.buf).await?;
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        Ok(())
    }
}

// ── Staging (Android) ────────────────────────────────────────────────────

/// Bytes the front end staged for `send_file` or `save_file`, by stage id.
/// Android's IPC never carries a raw request body (Tauri reads it only through
/// the custom protocol, which Android's WebView lacks) and would turn a
/// Uint8Array into a JSON array of numbers, so the bytes come over in base64
/// chunks first (D2-03).
static STAGED: LazyLock<Mutex<Vec<Stage>>> = LazyLock::new(Default::default);
/// A stage's id and its bytes so far.
type Stage = (String, Vec<u8>);
/// Stages kept at once; the oldest goes first.
const MAX_STAGED: usize = 4;

/// Append one base64 chunk to stage `id`; the bytes staged so far.
#[tauri::command]
pub fn file_stage(id: String, chunk: String) -> Result<usize, String> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(chunk.as_bytes())
        .map_err(|_| "a staged chunk is not base64".to_string())?;
    stage_append(&id, &bytes)
}

fn stage_append(id: &str, bytes: &[u8]) -> Result<usize, String> {
    let mut staged = lock(&STAGED);
    let at = match staged.iter().position(|(i, _)| i == id) {
        Some(at) => at,
        None => {
            if staged.len() >= MAX_STAGED {
                staged.remove(0);
            }
            staged.push((id.to_owned(), Vec::new()));
            staged.len() - 1
        }
    };
    let buf = &mut staged[at].1;
    if (buf.len() + bytes.len()) as u64 > MAX_FILE_PLAIN {
        staged.remove(at);
        return Err(FileError::TooLarge.to_string());
    }
    buf.extend_from_slice(bytes);
    Ok(buf.len())
}

/// Stage `id`'s bytes, taken out of the store.
fn stage_take(id: &str) -> Option<Vec<u8>> {
    let mut staged = lock(&STAGED);
    let at = staged.iter().position(|(i, _)| i == id)?;
    Some(staged.remove(at).1)
}

/// A command's bytes: its raw body (desktop), or what was staged under the id
/// in `x-voipc-staged` (Android).
pub(crate) fn body_bytes(request: &tauri::ipc::Request<'_>, what: &str) -> Result<Vec<u8>, String> {
    if let tauri::ipc::InvokeBody::Raw(bytes) = request.body() {
        return Ok(bytes.clone());
    }
    let id = request
        .headers()
        .get("x-voipc-staged")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| format!("{what} takes the file's bytes"))?;
    stage_take(id).ok_or_else(|| format!("{what}: nothing was staged under {id}"))
}

// ── Cancel ───────────────────────────────────────────────────────────────

/// Transfers the front end can cancel, by the id it gave them.
static OPS: LazyLock<Mutex<HashMap<String, Arc<Notify>>>> = LazyLock::new(Default::default);

/// `work`, unless `cancel_file(op)` comes first. A cancelled transfer is
/// dropped where it stands; its turn tells the relay.
///
/// Callers pass `work` boxed: an async fn holds its arguments in its own
/// future, and a command's future is started on the WebView's small JavaBridge
/// stack on Android (D2-02), so a transfer's large future must not be in it.
async fn cancellable<T>(
    op: Option<&str>,
    work: std::pin::Pin<Box<dyn Future<Output = Result<T, String>> + Send + '_>>,
) -> Result<T, String> {
    let Some(op) = op else {
        return work.await;
    };
    let stop = Arc::new(Notify::new());
    lock(&OPS).insert(op.to_owned(), stop.clone());
    let out = tokio::select! {
        out = work => out,
        _ = stop.notified() => Err(CANCELLED.into()),
    };
    let mut ops = lock(&OPS);
    // Not another transfer's that took the same id meanwhile
    if ops.get(op).is_some_and(|s| Arc::ptr_eq(s, &stop)) {
        ops.remove(op);
    }
    out
}

// ── Cache ────────────────────────────────────────────────────────────────

pub(crate) fn cache_dir() -> PathBuf {
    crate::config::data_dir().join("files")
}

/// Named only by a blob id, as hex: nothing a message says reaches the path.
fn blob_path(hash: &[u8; 32]) -> PathBuf {
    cache_dir().join(hex(hash))
}

fn cached(hash: &[u8; 32]) -> bool {
    blob_path(hash).is_file()
}

fn cache_read(hash: &[u8; 32]) -> Option<Vec<u8>> {
    let path = blob_path(hash);
    let blob = std::fs::read(&path).ok()?;
    // Used now: the last to go
    if let Ok(f) = std::fs::File::options().write(true).open(&path) {
        let _ = f.set_modified(SystemTime::now());
    }
    Some(blob)
}

fn cache_remove(hash: &[u8; 32]) {
    let _ = std::fs::remove_file(blob_path(hash));
}

/// Keep `blob`, then let the least recently used go until the cache is
/// within `cap` bytes (never `blob` itself).
fn cache_write(hash: &[u8; 32], blob: &[u8], cap: u64) -> std::io::Result<()> {
    let dir = cache_dir();
    std::fs::create_dir_all(&dir)?;
    // Whole or not at all: a blob is only ever read under its id
    let part = dir.join(format!("{}.{:08x}.part", hex(hash), rand::random::<u32>()));
    std::fs::write(&part, blob)?;
    if let Err(e) = std::fs::rename(&part, blob_path(hash)) {
        let _ = std::fs::remove_file(&part);
        return Err(e);
    }
    cache_trim(cap, Some(&hex(hash)));
    Ok(())
}

/// Let the least recently used blobs go until the cache is within `cap`
/// bytes, never `spare`.
fn cache_trim(cap: u64, spare: Option<&str>) {
    let mut all = cache_entries();
    all.sort_by_key(|e| e.last_used);
    let mut total: u64 = all.iter().map(|e| e.bytes).sum();
    for e in all {
        if total <= cap {
            break;
        }
        if spare != Some(e.hash.as_str()) {
            let _ = std::fs::remove_file(cache_dir().join(&e.hash));
            total -= e.bytes;
        }
    }
}

/// A cached blob, for the media manager.
#[derive(Debug, Clone, Serialize)]
pub struct CacheEntry {
    pub hash: String,
    pub bytes: u64,
    /// Unix ms.
    pub last_used: u64,
}

fn is_blob_name(name: &str) -> bool {
    name.len() == 64 && unhex::<32>(name).is_some()
}

fn cache_entries() -> Vec<CacheEntry> {
    let Ok(dir) = std::fs::read_dir(cache_dir()) else {
        return Vec::new();
    };
    dir.flatten()
        .filter_map(|entry| {
            let name = entry.file_name().into_string().ok()?;
            let meta = entry.metadata().ok().filter(|m| m.is_file())?;
            is_blob_name(&name).then(|| CacheEntry {
                hash: name,
                bytes: meta.len(),
                last_used: meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
                    .map_or(0, |d| d.as_millis() as u64),
            })
        })
        .collect()
}

/// Drop every blob not in `keep` that has not been used for `grace`, and
/// any piece of a write that never finished.
fn cache_retain(keep: &HashSet<String>, grace: Duration) {
    let Ok(dir) = std::fs::read_dir(cache_dir()) else {
        return;
    };
    let now = SystemTime::now();
    for entry in dir.flatten() {
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        // A time just ahead of ours (another clock, a coarse one) is no age
        let old = entry
            .metadata()
            .and_then(|m| m.modified())
            .is_ok_and(|t| now.duration_since(t).unwrap_or_default() >= grace);
        if old && !keep.contains(&name) {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// With no chat archive, nothing refers to a blob from an earlier run.
pub fn cache_wipe() {
    match std::fs::remove_dir_all(cache_dir()) {
        Ok(()) => debug!("file cache wiped: no chat archive"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => warn!("could not wipe the file cache: {e}"),
    }
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, String> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| e.to_string())
}

/// The file `meta` names, opened from the copy kept here; `None` without one.
/// A copy that is not the blob `meta` names (cut short by a crash, say) goes,
/// and a fetch brings the right one. Any other error is the message's: its
/// key, size or deflate flag do not open the blob its id names, and never
/// will. That copy stays, for the messages that name it rightly: a message
/// that copies a real file's id must not make a reader drop it (R3-02).
fn open_cached(meta: &FileMeta) -> Result<Option<Vec<u8>>, FileError> {
    let Some(blob) = cache_read(&meta.hash) else {
        return Ok(None);
    };
    match voipc_crypto::file::open(meta, &blob) {
        Ok(plain) => Ok(Some(plain)),
        // `open` looks at the shape before the id, so a copy cut short can
        // fail as `Malformed`: the id is what tells the two apart
        Err(_) if voipc_crypto::file::blob_hash(&blob) != meta.hash => {
            debug!("a cached file is not the blob it is kept as: fetching it again");
            cache_remove(&meta.hash);
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

/// Keep `blob` in the cache, as far as the disk lets it.
async fn keep(state: &AppState, hash: [u8; 32], blob: Vec<u8>) {
    let cap = state.config().file_cache_mb.saturating_mul(MIB);
    match blocking(move || cache_write(&hash, &blob, cap)).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => warn!("could not cache a file: {e}"),
        Err(e) => warn!("could not cache a file: {e}"),
    }
}

// ── Commands ─────────────────────────────────────────────────────────────

pub(crate) async fn files_of(state: &AppState, server: &str) -> Result<Arc<Files>, String> {
    let conns = state.connections.read().await;
    Ok(conn(&conns, server)?.files.clone())
}

/// `send_file`'s `x-voipc-file` header.
#[derive(Deserialize)]
struct SendArgs {
    server: String,
    conv: Conv,
    /// Deflate the file where that helps (everything but images).
    compress: bool,
    op: Option<String>,
}

/// What a file message carries about the file sent (beside its name and type).
#[derive(Debug, Serialize)]
pub struct SentFile {
    hash: String,
    key: String,
    size: u64,
    z: bool,
}

/// Seal the file in the request body and store it on the relay for a
/// message in `conv`; the message itself is the front end's to send.
/// `file-progress` events say how far it is, under `op`.
#[tauri::command]
pub async fn send_file(
    state: State<'_, AppState>,
    request: tauri::ipc::Request<'_>,
) -> Result<SentFile, String> {
    let args: SendArgs = request
        .headers()
        .get("x-voipc-file")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| serde_json::from_str(v).ok())
        .ok_or("send_file needs its x-voipc-file header")?;
    let plain = body_bytes(&request, "send_file")?;
    if plain.len() as u64 > MAX_FILE_PLAIN {
        return Err(FileError::TooLarge.to_string());
    }
    let files = files_of(&state, &args.server).await?;
    let conv = args.conv.wire()?;
    let op = args.op.as_deref();
    let compress = args.compress;
    // A cancel while it seals counts too: the seal's result is then dropped
    let (meta, blob) = cancellable(
        op,
        Box::pin(async {
            let (meta, blob) = blocking(move || voipc_crypto::file::seal(&plain, compress))
                .await?
                .map_err(|e| e.to_string())?;
            files.upload(conv, meta.hash, &blob, op).await?;
            Ok((meta, blob))
        }),
    )
    .await?;
    keep(&state, meta.hash, blob).await;
    Ok(SentFile {
        hash: meta.hash_hex(),
        key: meta.key_hex(),
        size: meta.size,
        z: meta.deflated,
    })
}

/// What a file message says about its file: `fetch_file` takes the message's
/// `file` as it is.
#[derive(Deserialize)]
pub struct FileArg {
    hash: String,
    key: String,
    size: u64,
    z: bool,
}

/// The file a message in `conv` names, opened: from the cache, else from the
/// relay (which may first ask the conversation's members for it).
#[tauri::command]
pub async fn fetch_file(
    state: State<'_, AppState>,
    server: String,
    conv: Conv,
    file: FileArg,
    op: Option<String>,
) -> Result<tauri::ipc::Response, String> {
    let plain = Box::pin(open_file(&state, &server, conv, file, op)).await?;
    Ok(tauri::ipc::Response::new(plain))
}

/// A picture file, as the PNG it may be shown as (`media::sanitize`): the
/// file's own bytes never reach the page this way, and a picture the
/// sanitizer will not read is an error to show, never a fallback.
#[tauri::command]
pub async fn file_image(
    state: State<'_, AppState>,
    server: String,
    conv: Conv,
    file: FileArg,
    profile: u32,
    op: Option<String>,
) -> Result<tauri::ipc::Response, String> {
    let profile = voipc_media::Profile::from_u32(profile).ok_or("no such picture profile")?;
    let motion = files_of(&state, &server)
        .await
        .map_or_else(|_| voipc_media::Motion::default(), |f| f.motion());
    let plain = Box::pin(open_file(&state, &server, conv, file, op)).await?;
    let clean = crate::media::sanitize(plain, profile, profile.max_output(), motion).await?;
    Ok(tauri::ipc::Response::new(clean.png))
}

/// `fetch_file`'s work: the copy kept here, opened, else the relay's.
async fn open_file(
    state: &State<'_, AppState>,
    server: &str,
    conv: Conv,
    file: FileArg,
    op: Option<String>,
) -> Result<Vec<u8>, String> {
    let meta = FileMeta::from_parts(&file.hash, &file.key, file.size, file.z)
        .map_err(|e| e.to_string())?;
    let hash = meta.hash;
    let m = meta.clone();
    if let Some(plain) = blocking(move || open_cached(&m))
        .await?
        .map_err(|e| e.to_string())?
    {
        return Ok(plain);
    }
    let files = files_of(state, server).await?;
    let op = op.as_deref();
    let blob = cancellable(op, Box::pin(files.fetch(conv.wire()?, hash, op))).await?;
    let (opened, blob) = blocking(move || (voipc_crypto::file::open(&meta, &blob), blob)).await?;
    let plain = opened.map_err(|e| e.to_string())?;
    keep(state, hash, blob).await;
    Ok(plain)
}

/// Post the file this device holds as `hash` in `conv` too (a forward): the
/// same blob, with the same key, registered for that conversation. The relay
/// keeps one copy, and answers at once while it still has it; else the copy
/// kept here goes up. The front end loads the file first (`fetch_file`),
/// which keeps it here.
#[tauri::command]
pub async fn forward_file(
    state: State<'_, AppState>,
    server: String,
    conv: Conv,
    hash: String,
    op: Option<String>,
) -> Result<(), String> {
    let hash = unhex::<32>(&hash).ok_or("invalid hash")?;
    let conv = conv.wire()?;
    let files = files_of(&state, &server).await?;
    let blob = blocking(move || {
        let blob = cache_read(&hash)?;
        // A damaged copy is not offered to anyone
        if voipc_crypto::file::blob_hash(&blob) != hash {
            cache_remove(&hash);
            return None;
        }
        Some(blob)
    })
    .await?
    .ok_or("The file is not on this device")?;
    let op = op.as_deref();
    cancellable(op, Box::pin(files.upload(conv, hash, &blob, op))).await
}

/// Give up the transfer the front end started as `op`.
#[tauri::command]
pub fn cancel_file(op: String) {
    if let Some(stop) = lock(&OPS).get(&op) {
        stop.notify_one();
    }
    // A send cancelled while its bytes were still being staged
    stage_take(&op);
}

/// One re-seed at a time, across every server, the others in line.
static RESEED: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
/// Re-seeds in line; past this many, a relay's asks are let go.
static RESEEDS_WAITING: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
const MAX_RESEEDS_WAITING: usize = 16;

/// Answer the relay's `FileWanted` for `hash` in `conv`: the front end found
/// a message there that refers to it.
#[tauri::command]
pub async fn reseed_file(
    state: State<'_, AppState>,
    server: String,
    conv: Conv,
    hash: String,
) -> Result<(), String> {
    let hash = unhex::<32>(&hash).ok_or("invalid hash")?;
    let conv = conv.wire()?;
    let files = files_of(&state, &server).await?;
    if RESEEDS_WAITING.fetch_add(1, Ordering::Relaxed) >= MAX_RESEEDS_WAITING {
        RESEEDS_WAITING.fetch_sub(1, Ordering::Relaxed);
        return Ok(());
    }
    tokio::spawn(async move {
        // In line, not dropped: the relay asks a conversation once a minute
        let _one = RESEED.lock().await;
        RESEEDS_WAITING.fetch_sub(1, Ordering::Relaxed);
        let jitter = Duration::from_millis(rand::random::<u64>() % 2000);
        tokio::time::sleep(jitter).await;
        let read = blocking(move || {
            let blob = cache_read(&hash)?;
            // A damaged copy is not offered to anyone
            if voipc_crypto::file::blob_hash(&blob) != hash {
                cache_remove(&hash);
                return None;
            }
            Some(blob)
        });
        let Ok(Some(blob)) = read.await else {
            return;
        };
        if let Err(e) = files.upload(conv, hash, &blob, None).await {
            debug!("re-seed of a file ended: {e}");
        }
    });
    Ok(())
}

/// Where a file waits on Android for `VoIPCBridge.saveFile` to copy it out
/// (MainActivity.kt takes paths in here only).
#[cfg(target_os = "android")]
fn save_out_dir() -> PathBuf {
    crate::config::data_dir().join("save-out")
}

/// Keep a file the person asked to save, under a name they choose. The
/// desktop asks with a save dialog, writes it and returns where; None when
/// they cancelled. Android has no such dialog here: the file goes to
/// `save_out_dir` and its path comes back, for the front end to hand to
/// `VoIPCBridge.saveFile` (the system's own "save to" picker), which removes
/// it. Never opened or run: there is no such action.
#[tauri::command]
pub async fn save_file(request: tauri::ipc::Request<'_>) -> Result<Option<String>, String> {
    let name: String = request
        .headers()
        .get("x-voipc-save")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| serde_json::from_str(v).ok())
        .ok_or("save_file needs its x-voipc-save header")?;
    let bytes = body_bytes(&request, "save_file")?;
    // The front end cleaned it (`saveName`); a name is still never a path
    let name = std::path::Path::new(&name)
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|n| !n.is_empty())
        .unwrap_or("file")
        .to_string();
    #[cfg(target_os = "android")]
    {
        let dir = save_out_dir();
        let path = dir.join(format!("{:016x}", rand::random::<u64>()));
        let out = path.clone();
        blocking(move || -> std::io::Result<()> {
            std::fs::create_dir_all(&dir)?;
            std::fs::write(&out, &bytes)
        })
        .await?
        .map_err(|e| format!("could not keep the file: {e}"))?;
        let _ = name;
        Ok(Some(path.to_string_lossy().into_owned()))
    }
    #[cfg(not(target_os = "android"))]
    {
        let Some(target) = rfd::AsyncFileDialog::new()
            .set_title("Save file")
            .set_file_name(&name)
            .save_file()
            .await
        else {
            return Ok(None);
        };
        tokio::fs::write(target.path(), bytes)
            .await
            .map_err(|e| format!("could not save the file: {e}"))?;
        #[cfg(windows)]
        if let Err(e) = tokio::fs::write(zone_stream(target.path()), ZONE_INTERNET).await {
            // FAT and exFAT drives keep no alternate streams, nor the mark
            debug!("no mark of the web on {}: {e}", target.path().display());
        }
        Ok(Some(target.path().to_string_lossy().into_owned()))
    }
}

/// What a browser writes beside a download (Windows' Mark of the Web): from
/// the internet, zone 3. SmartScreen and Office then warn before running or
/// opening the file, as they would for any download.
#[cfg_attr(not(windows), allow(dead_code))]
const ZONE_INTERNET: &[u8] = b"[ZoneTransfer]\r\nZoneId=3\r\n";

/// The NTFS stream the mark goes in: `<file>:Zone.Identifier`.
#[cfg_attr(not(windows), allow(dead_code))]
fn zone_stream(path: &std::path::Path) -> std::ffi::OsString {
    let mut stream = path.as_os_str().to_owned();
    stream.push(":Zone.Identifier");
    stream
}

/// What a save on Android left behind when the app went before the picker
/// answered: decrypted files, so they go at start.
#[cfg(target_os = "android")]
pub fn save_out_wipe() {
    let _ = std::fs::remove_dir_all(save_out_dir());
}

/// The blobs this device keeps, and the most it keeps (bytes).
#[derive(Debug, Serialize)]
pub struct CacheState {
    pub cap: u64,
    pub entries: Vec<CacheEntry>,
}

#[tauri::command]
pub async fn file_cache_list(state: State<'_, AppState>) -> Result<CacheState, String> {
    let cap = state.config().file_cache_mb.saturating_mul(MIB);
    let entries = blocking(cache_entries).await?;
    Ok(CacheState { cap, entries })
}

/// Let go of these blobs now (blob ids, hex): the media manager's "remove
/// the copy on this device". A member's ask for one of them goes unanswered
/// from here on.
#[tauri::command]
pub async fn file_cache_remove(hashes: Vec<String>) -> Result<(), String> {
    let gone: Vec<[u8; 32]> = hashes.iter().filter_map(|h| unhex::<32>(h)).collect();
    blocking(move || gone.iter().for_each(cache_remove)).await
}

/// The least and the most `file_cache_mb` takes.
const CACHE_MB: std::ops::RangeInclusive<u64> = 64..=1024 * 1024;

/// Set the file cache's size (MiB), and keep to it now rather than at the
/// next file.
#[tauri::command]
pub async fn set_file_cache_mb(state: State<'_, AppState>, mb: u64) -> Result<(), String> {
    if !CACHE_MB.contains(&mb) {
        return Err(format!(
            "The file cache takes {} to {} MB",
            CACHE_MB.start(),
            CACHE_MB.end()
        ));
    }
    // In effect from here whether or not it is saved, so kept to now either way
    let saved = {
        let mut config = state.config();
        config.file_cache_mb = mb;
        crate::config::save_config(&config)
    };
    blocking(move || cache_trim(mb.saturating_mul(MIB), None)).await?;
    saved
}

/// Let go of every cached blob but these (blob ids, hex): the ones some
/// message still refers to. A blob used in the last few minutes stays
/// regardless, so a file just sent is not lost before its message is filed.
#[tauri::command]
pub async fn file_cache_retain(hashes: Vec<String>) -> Result<(), String> {
    let keep: HashSet<String> = hashes.into_iter().filter(|h| is_blob_name(h)).collect();
    blocking(move || cache_retain(&keep, RETAIN_GRACE)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_saved_file_is_marked_as_from_the_internet_in_its_own_stream() {
        let p = std::path::Path::new(r"C:\Users\a\Downloads\setup.exe");
        assert_eq!(
            zone_stream(p),
            r"C:\Users\a\Downloads\setup.exe:Zone.Identifier"
        );
        assert_eq!(ZONE_INTERNET, b"[ZoneTransfer]\r\nZoneId=3\r\n");
    }

    /// D2-03: Android's bytes come staged in chunks, by id, at most
    /// `MAX_FILE_PLAIN` each and `MAX_STAGED` at once; taking them empties the
    /// stage.
    #[test]
    fn staged_bytes_add_up_and_are_taken_once() {
        assert_eq!(stage_append("t-a", b"hello "), Ok(6));
        assert_eq!(stage_append("t-a", b"world"), Ok(11));
        assert_eq!(stage_take("t-a").as_deref(), Some(&b"hello world"[..]));
        assert_eq!(stage_take("t-a"), None);
        // Over the limit: refused, and what was staged goes
        stage_append("t-b", b"x").unwrap();
        let big = vec![0u8; MAX_FILE_PLAIN as usize];
        assert!(stage_append("t-b", &big).is_err());
        assert_eq!(stage_take("t-b"), None);
        // The oldest stage goes when too many are open
        for i in 0..=MAX_STAGED {
            stage_append(&format!("t-c{i}"), b"x").unwrap();
        }
        assert_eq!(stage_take("t-c0"), None);
        assert!(stage_take(&format!("t-c{MAX_STAGED}")).is_some());
        for i in 1..MAX_STAGED {
            stage_take(&format!("t-c{i}"));
        }
        // file_stage takes base64 only
        assert_eq!(file_stage("t-d".into(), "aGk=".into()), Ok(2));
        assert!(file_stage("t-d".into(), "not base64!".into()).is_err());
        assert_eq!(stage_take("t-d").as_deref(), Some(&b"hi"[..]));
    }

    /// D2-02: Android starts a command's future on the WebView's small
    /// JavaBridge stack, and a 40 KB one overflowed it on Load. A request's
    /// future must not hold a buffer; the transfers are boxed at `cancellable`.
    #[test]
    fn a_request_future_holds_no_buffer() {
        let (client, _relay) = tokio::io::duplex(1024);
        let mut http = Http::new(client);
        let size = std::mem::size_of_val(&http.request("GET / HTTP/1.1\r\n\r\n", b""));
        assert!(size < 4096, "{size} bytes");
        let size = std::mem::size_of_val(&http.fill());
        assert!(size < 1024, "{size} bytes");
    }

    /// The relay's side of one exchange, over a pipe.
    async fn exchange(
        answer: &'static [u8],
        head: &str,
        body: &[u8],
    ) -> (std::io::Result<Reply>, Vec<u8>) {
        let (client, mut relay) = tokio::io::duplex(4 * 1024 * 1024);
        let mut http = Http::new(client);
        let serve = async move {
            let mut got = vec![0u8; head.len() + body.len()];
            relay.read_exact(&mut got).await.unwrap();
            relay.write_all(answer).await.unwrap();
            got
        };
        let (reply, got) = tokio::join!(http.request(head, body), serve);
        (reply, got)
    }

    #[tokio::test]
    async fn an_answer_is_read_with_its_body_and_its_headers() {
        let (reply, got) = exchange(
            b"HTTP/1.1 206 Partial Content\r\ncontent-range: bytes 0-2/10\r\ncontent-length: 3\r\nconnection: keep-alive\r\n\r\nabc",
            "GET /f/v1/x HTTP/1.1\r\n\r\n",
            b"",
        )
        .await;
        let reply = reply.unwrap();
        assert_eq!(got, b"GET /f/v1/x HTTP/1.1\r\n\r\n");
        assert_eq!(
            (reply.status, reply.body.as_slice(), reply.close),
            (206, &b"abc"[..], false)
        );
        assert_eq!(
            reply.header("content-range").and_then(content_range),
            Some((0, 2, 10))
        );
    }

    #[tokio::test]
    async fn a_204_has_no_length_and_a_close_is_noticed() {
        let (reply, got) = exchange(
            b"HTTP/1.1 204 No Content\r\nupload-offset: 5\r\nconnection: close\r\n\r\n",
            "PUT /f/v1/x?offset=0 HTTP/1.1\r\nContent-Length: 5\r\n\r\n",
            b"hello",
        )
        .await;
        let reply = reply.unwrap();
        assert!(got.ends_with(b"\r\n\r\nhello"));
        assert_eq!(
            (reply.status, reply.body.len(), reply.close),
            (204, 0, true)
        );
        assert_eq!(reply.header("upload-offset"), Some("5"));
    }

    #[tokio::test]
    async fn answers_without_a_length_or_too_long_are_refused() {
        let (reply, _) = exchange(b"HTTP/1.1 200 OK\r\n\r\n", "GET / HTTP/1.1\r\n\r\n", b"").await;
        assert!(reply.is_err());
        let (reply, _) = exchange(
            b"HTTP/1.1 206 Partial Content\r\ncontent-length: 99999999\r\n\r\n",
            "GET / HTTP/1.1\r\n\r\n",
            b"",
        )
        .await;
        assert!(reply.is_err());
    }

    #[tokio::test]
    async fn two_answers_on_one_connection_stay_apart() {
        let (client, mut relay) = tokio::io::duplex(64 * 1024);
        let mut http = Http::new(client);
        relay
            .write_all(b"HTTP/1.1 204 No Content\r\nupload-offset: 1\r\n\r\nHTTP/1.1 201 Created\r\ncontent-length: 6\r\n\r\nstored")
            .await
            .unwrap();
        let first = http.request("PUT a\r\n\r\n", b"x").await.unwrap();
        let second = http.request("PUT b\r\n\r\n", b"y").await.unwrap();
        assert_eq!((first.status, second.status), (204, 201));
        assert_eq!(second.body, b"stored");
    }

    #[test]
    fn chunks_follow_the_link_within_their_bounds() {
        let mut pace = Pace::default();
        assert_eq!(pace.chunk, FIRST_CHUNK);
        // 98 kbit/s: 15 s of it is about 180 KiB, well inside the relay's 60 s
        pace.took(
            256 * KIB,
            Duration::from_secs_f64(256.0 * 1024.0 * 8.0 / 98_000.0),
        );
        assert!(
            (175 * KIB..185 * KIB).contains(&pace.chunk),
            "{}",
            pace.chunk
        );
        // 20 kbit/s: under the floor
        pace.took(
            256 * KIB,
            Duration::from_secs_f64(256.0 * 1024.0 * 8.0 / 20_000.0),
        );
        assert_eq!(pace.chunk, MIN_CHUNK);
        // a fast link: the relay's ceiling
        pace.took(MIB, Duration::from_millis(50));
        assert_eq!(pace.chunk, MAX_CHUNK);
        // 1 Mbit/s: about 1.8 MB in 15 s, so the ceiling; 400 kbit/s about 732 KiB
        pace.took(
            MIB,
            Duration::from_secs_f64(1024.0 * 1024.0 * 8.0 / 400_000.0),
        );
        assert!(
            (700 * KIB..760 * KIB).contains(&pace.chunk),
            "{}",
            pace.chunk
        );
        // a short last chunk changes nothing
        let before = pace.chunk;
        pace.took(10, Duration::from_secs(5));
        assert_eq!(pace.chunk, before);
        // in a call: the floor, whatever the link
        assert_eq!(pace.next(true), CALL_CHUNK);
        assert_eq!(pace.next(false), pace.chunk);
        // cut: halve, down to the floor
        pace.cut();
        assert_eq!(pace.chunk, before / 2);
        for _ in 0..10 {
            pace.cut();
        }
        assert_eq!(pace.chunk, MIN_CHUNK);
    }

    #[test]
    fn conversations_cross_as_the_front_end_names_them() {
        let account = "00112233445566778899aabbccddeeff";
        for (json, wire) in [
            (r#"{"channel":3}"#, FileConv::Channel(3)),
            (r#"{"direct":7}"#, FileConv::Direct(7)),
            (
                &format!(r#"{{"account":"{account}"}}"#)[..],
                FileConv::Account(unhex::<16>(account).unwrap()),
            ),
        ] {
            let conv: Conv = serde_json::from_str(json).unwrap();
            assert_eq!(conv.wire().unwrap(), wire);
            assert_eq!(serde_json::to_string(&Conv::of(&wire)).unwrap(), json);
        }
        let bad: Conv = serde_json::from_str(r#"{"account":"00"}"#).unwrap();
        assert!(bad.wire().is_err());
    }

    /// A guest on a live relay with only its file side wired up.
    pub(crate) struct Guest {
        pub user_id: u32,
        pub files: Arc<Files>,
        /// Held: dropping it ends the session.
        pub _conn: crate::transport::Conn,
        tasks: Vec<tokio::task::JoinHandle<()>>,
    }

    impl Drop for Guest {
        fn drop(&mut self) {
            self.tasks.iter().for_each(|t| t.abort());
        }
    }

    /// `VOIPC_FILES_RELAY` (`host:port`, a self-signed relay with files on).
    pub(crate) fn live_relay() -> (String, u16) {
        let addr = std::env::var("VOIPC_FILES_RELAY").expect("VOIPC_FILES_RELAY=host:port");
        let (host, port) = addr.rsplit_once(':').unwrap();
        (host.to_string(), port.parse().unwrap())
    }

    /// What a guest's file side emits.
    type Events = mpsc::UnboundedReceiver<(String, serde_json::Value)>;

    /// Connect and sign in as a guest; everything but file messages is
    /// dropped.
    pub(crate) async fn guest(host: &str, port: u16, name: &str) -> (Guest, Events) {
        use voipc_protocol::codec::{
            decode_server_msg, encode_client_msg, try_decode_frame, APP_VERSION, PROTOCOL_VERSION,
        };
        let (link, _) = crate::transport::connect(host, port, true).await.unwrap();
        let crate::transport::Link {
            conn,
            mut control_send,
            mut control_recv,
        } = link;
        let auth = ClientMessage::Authenticate {
            username: name.into(),
            protocol_version: PROTOCOL_VERSION,
            app_version: APP_VERSION.into(),
            identity_key: None,
            prekey_bundle: None,
            account: None,
        };
        control_send
            .write_all(&encode_client_msg(&auth).unwrap())
            .await
            .unwrap();
        let mut buf = bytes::BytesMut::new();
        let (user_id, limits, emotes) = 'auth: loop {
            control_recv.read_buf(&mut buf).await.unwrap();
            while let Some(payload) = try_decode_frame(&mut buf).unwrap() {
                match decode_server_msg(&payload).unwrap() {
                    ServerMessage::Authenticated {
                        user_id,
                        files,
                        emotes,
                        ..
                    } => break 'auth (user_id, files, emotes),
                    other => assert!(
                        !matches!(other, ServerMessage::AuthError { .. }),
                        "{other:?}"
                    ),
                }
            }
        };
        let (tcp_tx, mut tcp_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (events_tx, events) = mpsc::unbounded_channel();
        // VOIPC_FILES_IN_CALL=1: as if voice were on
        let in_call = std::env::var("VOIPC_FILES_IN_CALL").is_ok_and(|v| v == "1");
        let files = Arc::new(Files::new(
            Box::new(move |event, data| {
                let _ = events_tx.send((event.to_string(), data));
            }),
            Box::new(move || in_call),
            host.to_string(),
            port,
            true,
            limits,
            emotes,
            tcp_tx,
        ));
        let writer = tokio::spawn(async move {
            while let Some(data) = tcp_rx.recv().await {
                if control_send.write_all(&data).await.is_err() {
                    break;
                }
            }
        });
        let reader = tokio::spawn({
            let files = files.clone();
            async move {
                loop {
                    if control_recv.read_buf(&mut buf).await.unwrap_or(0) == 0 {
                        break;
                    }
                    while let Ok(Some(payload)) = try_decode_frame(&mut buf) {
                        let Ok(msg) = decode_server_msg(&payload) else {
                            continue;
                        };
                        if is_file_message(&msg) {
                            files.on_message(msg);
                        }
                    }
                }
                files.close();
            }
        });
        let guest = Guest {
            user_id,
            files,
            _conn: conn,
            tasks: vec![writer, reader],
        };
        (guest, events)
    }

    /// Protocol 14 over the native carrier against a real relay: a guest the
    /// admin token made admin adds an emote (`EmoteAdd`, its ticket, one PUT
    /// on `/e/v1` over HTTP/1.1 behind the pinned certificate); the list comes
    /// to another guest, who fetches the file with its own bearer, checks it
    /// against its hash and sanitizes it as `emote_image` does.
    /// `VOIPC_FILES_RELAY=127.0.0.1:29987 VOIPC_ADMIN_TOKEN=… cargo test -p
    /// voipc-client --lib an_emote_crosses -- --ignored`
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs a relay: VOIPC_FILES_RELAY=host:port and VOIPC_ADMIN_TOKEN"]
    async fn an_emote_crosses_a_live_relay() {
        use crate::emotes::sha256;
        use voipc_protocol::types::Emote;
        let (host, port) = live_relay();
        let token = std::env::var("VOIPC_ADMIN_TOKEN").expect("VOIPC_ADMIN_TOKEN");
        let n = rand::random::<u16>();
        let (admin, _) = guest(&host, port, &format!("emote-admin-{n}")).await;
        let (member, mut member_events) = guest(&host, port, &format!("emote-member-{n}")).await;
        assert!(
            member.files.emotes.is_some(),
            "the relay has emotes, and said so"
        );
        // A real moving picture; the relay handles one session's messages in
        // order, so the login is done before the add
        let file: &[u8] = include_bytes!("../../../crates/voipc-media/tests/fixtures/anim3.webp");
        let hash = sha256(file);
        let name = format!("live_{n}");
        admin.files.send_msg(&ClientMessage::AdminLogin { token });
        let answer = admin.files.wait_emote(&name, hash);
        admin.files.send_msg(&ClientMessage::EmoteAdd {
            emote: Emote {
                name: name.clone(),
                hash,
                sticker: false,
                pack: String::new(),
            },
            len: file.len() as u32,
        });
        let ticket = tokio::time::timeout(Duration::from_secs(10), answer)
            .await
            .expect("an answer")
            .unwrap()
            .expect("added")
            .expect("a ticket: the relay did not have the file");
        let (status, body) = admin
            .files
            .emote_request("PUT", &hash, &ticket, file)
            .await
            .unwrap();
        assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));

        let listed = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let (event, data) = member_events.recv().await.expect("events");
                if event == "emote-list"
                    && data["emotes"]
                        .as_array()
                        .is_some_and(|l| l.iter().any(|e| e["name"] == name.as_str()))
                {
                    return data;
                }
            }
        })
        .await
        .expect("the new list reaches the member");
        assert!(listed["emotes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["hash"] == hex(&hash).as_str()));

        let bearer = member.files.emotes.as_ref().unwrap().token.0.clone();
        let (status, body) = member
            .files
            .emote_request("GET", &hash, &bearer, &[])
            .await
            .unwrap();
        assert_eq!((status, sha256(&body)), (200, hash));
        let p = voipc_media::Profile::Emote;
        let clean = crate::media::sanitize(body, p, p.max_output(), voipc_media::Motion::default())
            .await
            .unwrap();
        assert!(
            clean.frames > 1 && clean.still.is_some(),
            "a moving emote, and its first frame"
        );

        let (status, _) = member
            .files
            .emote_request("PUT", &hash, &bearer, file)
            .await
            .unwrap();
        assert_eq!(status, 401, "a member's bearer uploads nothing");
        admin.files.send_msg(&ClientMessage::EmoteRemove { name });
    }

    /// The whole path against a real relay: seal, `FileUpload`, chunked PUTs
    /// over HTTP/1.1 behind the pinned certificate, `FileFetch`, ranged GETs,
    /// open. `VOIPC_FILES_RELAY=127.0.0.1:29987 cargo test -p voipc-client
    /// --lib a_file_crosses -- --ignored`
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs a relay: VOIPC_FILES_RELAY=host:port"]
    async fn a_file_crosses_a_live_relay() {
        let (host, port) = live_relay();
        let tag = rand::random::<u16>();
        let (alice, _) = guest(&host, port, &format!("alice{tag}")).await;
        let (bob, _) = guest(&host, port, &format!("bob{tag}")).await;
        // VOIPC_FILES_KIB (10000, so it fits the default 10 MiB cap however
        // it seals): 1 MiB of text, then bytes that do not compress
        let kib: usize = std::env::var("VOIPC_FILES_KIB").map_or(10_000, |v| v.parse().unwrap());
        let mut plain = "a line of a log file, again and again\n"
            .repeat(27_000)
            .into_bytes();
        plain.resize(plain.len().min(kib * 1024), 0);
        plain.extend((plain.len()..kib * 1024).map(|_| rand::random::<u8>()));
        // What voice is sent from: a 20 ms tick on the same runtime, and how
        // late it ever ran while the file was sealed, sent, fetched and opened
        let late = Arc::new(Mutex::new(Duration::ZERO));
        let ticker = tokio::spawn({
            let late = late.clone();
            async move {
                let mut tick = tokio::time::interval(Duration::from_millis(20));
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                let mut due = tokio::time::Instant::now();
                loop {
                    tick.tick().await;
                    let now = tokio::time::Instant::now();
                    let mut l = lock(&late);
                    *l = (*l).max(now.saturating_duration_since(due));
                    due = now + Duration::from_millis(20);
                }
            }
        });
        let started = Instant::now();
        let plain = Arc::new(plain);
        let p = plain.clone();
        let (meta, blob) = blocking(move || voipc_crypto::file::seal(&p, true))
            .await
            .unwrap()
            .unwrap();
        alice
            .files
            .upload(FileConv::Direct(bob.user_id), meta.hash, &blob, None)
            .await
            .unwrap();
        let up = started.elapsed();
        // Posting it again is a dedupe: stored at once
        alice
            .files
            .upload(FileConv::Direct(bob.user_id), meta.hash, &blob, None)
            .await
            .unwrap();
        let started = Instant::now();
        let got = bob
            .files
            .fetch(FileConv::Direct(alice.user_id), meta.hash, None)
            .await
            .unwrap();
        let m = meta.clone();
        let opened = blocking(move || voipc_crypto::file::open(&m, &got))
            .await
            .unwrap();
        let down = started.elapsed();
        ticker.abort();
        assert_eq!(opened.unwrap(), *plain);
        eprintln!(
            "{} B blob: seal+up {up:?}, down+open {down:?}; a 20 ms tick ran at most {:?} late",
            blob.len(),
            *lock(&late)
        );
        // A blob nobody holds: the relay asks alice's side, nobody answers
        let nobody = [7u8; 32];
        let started = Instant::now();
        let err = bob
            .files
            .fetch(FileConv::Direct(alice.user_id), nobody, None)
            .await
            .unwrap_err();
        assert_eq!(err, UNAVAILABLE);
        assert!(started.elapsed() >= Duration::from_secs(55));
    }

    /// The re-seed: a blob the relay let go is asked of the conversation's
    /// other side, which holds it, says so to its front end (`file-wanted`),
    /// and uploads it again; whoever waited is served. Needs a relay with
    /// `[files] cache_mins = 1`: `VOIPC_FILES_RELAY=… cargo test -p
    /// voipc-client --lib a_held_file -- --ignored`
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs a relay with cache_mins = 1: VOIPC_FILES_RELAY=host:port"]
    async fn a_held_file_is_seeded_again_once_the_relay_let_go_of_it() {
        let (host, port) = live_relay();
        let tag = rand::random::<u16>();
        let (alice, mut alice_events) = guest(&host, port, &format!("alice{tag}")).await;
        let (bob, mut bob_events) = guest(&host, port, &format!("bob{tag}")).await;
        let plain: Vec<u8> = (0..300 * KIB).map(|_| rand::random::<u8>()).collect();
        let (meta, blob) = voipc_crypto::file::seal(&plain, false).unwrap();
        alice
            .files
            .upload(FileConv::Direct(bob.user_id), meta.hash, &blob, None)
            .await
            .unwrap();
        // What send_file does after the upload: alice holds it now
        cache_write(&meta.hash, &blob, u64::MAX).unwrap();
        // A minute untouched, and the relay's sweep (every 5 s) lets go of it
        tokio::time::sleep(Duration::from_secs(70)).await;
        let fetch = tokio::spawn({
            let files = bob.files.clone();
            let hash = meta.hash;
            let alice_id = alice.user_id;
            async move {
                files
                    .fetch(FileConv::Direct(alice_id), hash, Some("down"))
                    .await
            }
        });
        // The ask reaches alice's front end, naming bob's side of the conversation
        let (event, data) = tokio::time::timeout(Duration::from_secs(20), alice_events.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(event, "file-wanted");
        assert_eq!(data["hash"], hex(&meta.hash));
        let conv: Conv = serde_json::from_value(data["conv"].clone()).unwrap();
        assert_eq!(conv, Conv::Direct(bob.user_id));
        // ...and bob's says the relay is asking
        let (event, data) = bob_events.recv().await.unwrap();
        assert_eq!(
            (event.as_str(), &data["stage"]),
            ("file-progress", &serde_json::json!("seeking"))
        );
        // What reseed_file does once the front end found the message
        let held = cache_read(&meta.hash).unwrap();
        alice
            .files
            .upload(conv.wire().unwrap(), meta.hash, &held, None)
            .await
            .unwrap();
        let got = fetch.await.unwrap().unwrap();
        assert_eq!(voipc_crypto::file::open(&meta, &got).unwrap(), plain);
        cache_remove(&meta.hash);
    }

    #[test]
    fn content_ranges_read_strictly() {
        assert_eq!(content_range("bytes 5-9/20"), Some((5, 9, 20)));
        assert_eq!(content_range("bytes */20"), None);
        assert_eq!(content_range("5-9/20"), None);
    }

    /// The tests that use the one cache directory, one at a time: this one
    /// empties it.
    static CACHE_DIR: Mutex<()> = Mutex::new(());

    #[test]
    fn the_cache_keeps_the_newest_within_its_cap_and_lets_go_of_the_rest() {
        let _one = lock(&CACHE_DIR);
        let _ = std::fs::remove_dir_all(cache_dir());
        let (a, b, c) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        cache_write(&a, &[0; 100], 1000).unwrap();
        // Older by an hour, so it is the first to go
        let old = SystemTime::now() - Duration::from_secs(3600);
        std::fs::File::options()
            .write(true)
            .open(blob_path(&a))
            .unwrap()
            .set_modified(old)
            .unwrap();
        cache_write(&b, &[0; 100], 1000).unwrap();
        assert!(cached(&a) && cached(&b));
        // Past the cap: the least recently used goes, never the one written
        cache_write(&c, &[0; 900], 1000).unwrap();
        assert!(!cached(&a) && cached(&b) && cached(&c));
        // Reading makes it the newest
        assert_eq!(cache_read(&b).unwrap().len(), 100);
        let names: HashSet<String> = cache_entries().into_iter().map(|e| e.hash).collect();
        assert_eq!(names, HashSet::from([hex(&b), hex(&c)]));
        // Retain: what is listed stays; the rest goes once past its grace
        cache_retain(&HashSet::from([hex(&b)]), Duration::from_secs(3600));
        assert!(cached(&b) && cached(&c));
        cache_retain(&HashSet::from([hex(&b)]), Duration::ZERO);
        assert!(cached(&b) && !cached(&c));
        // A smaller cap, set now: the least recently used goes first
        cache_write(&a, &[0; 100], u64::MAX).unwrap();
        std::fs::File::options()
            .write(true)
            .open(blob_path(&a))
            .unwrap()
            .set_modified(old)
            .unwrap();
        cache_trim(150, None);
        assert!(!cached(&a) && cached(&b));
        cache_remove(&b);
        assert!(!cached(&b));
        // Leftover pieces of a write go too; nothing else is ever read
        std::fs::write(cache_dir().join("junk.part"), b"x").unwrap();
        cache_retain(&HashSet::new(), Duration::ZERO);
        assert!(cache_entries().is_empty());
        assert_eq!(std::fs::read_dir(cache_dir()).unwrap().count(), 0);
        cache_wipe();
        assert!(!cache_dir().exists());
    }

    /// R3-02: a message that copies a real file's id with another key (or
    /// size, or deflate flag) does not open, and the good copy stays for
    /// the messages that name it rightly. Only bytes that are not the blob
    /// go, and are fetched again.
    #[test]
    fn a_message_that_does_not_open_a_kept_blob_leaves_it_kept() {
        let _one = lock(&CACHE_DIR);
        let plain = b"the real file".to_vec();
        let (meta, blob) = voipc_crypto::file::seal(&plain, false).unwrap();
        cache_write(&meta.hash, &blob, u64::MAX).unwrap();
        let forged = [
            FileMeta {
                key: [9; 32],
                ..meta.clone()
            },
            FileMeta {
                size: meta.size + 1,
                ..meta.clone()
            },
            FileMeta {
                deflated: !meta.deflated,
                ..meta.clone()
            },
        ];
        for (i, other) in forged.iter().enumerate() {
            assert!(open_cached(other).is_err());
            assert!(cached(&meta.hash), "forged meta {i} made the copy go");
        }
        assert_eq!(open_cached(&meta).unwrap(), Some(plain));
        // A copy cut short is not the blob: it goes, and is fetched again
        cache_write(&meta.hash, &blob[..blob.len() - 1], u64::MAX).unwrap();
        assert_eq!(open_cached(&meta).unwrap(), None);
        assert!(!cached(&meta.hash));
        assert_eq!(open_cached(&meta).unwrap(), None, "nothing kept");
    }

    /// R3-04: a refusal that says a later try may pass is asked again; the
    /// final ones and the hourly budget end the transfer.
    #[test]
    fn a_refusal_that_may_pass_later_is_asked_again() {
        use voipc_protocol::messages::*;
        for code in [FILE_RATE, FILE_BUSY, FILE_STALLED, FILE_EXPIRED] {
            assert!(asks_again(code), "{code}");
        }
        for code in [
            FILE_NOT_HERE,
            FILE_OFF,
            FILE_TOO_LARGE,
            FILE_PLACES,
            FILE_MISMATCH,
            FILE_BUDGET,
            FILE_FAILED,
        ] {
            assert!(!asks_again(code), "{code}");
        }
    }

    /// R3-05: `MAX_ASKS` that brought nothing end a transfer; a ticket that
    /// brought bytes before it went costs no ask, however many it takes.
    #[test]
    fn a_download_that_moves_on_never_runs_out_of_asks() {
        let mut idle = Asks::default();
        assert_eq!((0..10).filter(|_| idle.next()).count(), MAX_ASKS as usize);
        let mut moving = Asks::default();
        for _ in 0..100 {
            assert!(moving.next());
            moving.moved();
        }
        // ...and once it stops moving, the count starts again
        assert_eq!((0..10).filter(|_| moving.next()).count(), MAX_ASKS as usize);
    }
}
