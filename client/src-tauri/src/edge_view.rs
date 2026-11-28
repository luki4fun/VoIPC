//! Watching a share from a media edge (1.15, protocol 26): the native twin of
//! `client/src/web/backend/edge-view.ts`.
//!
//! A relay with an edge pool places some viewers of a big share on an edge. Right after
//! `WatchingScreenShare` it sends `WatchAt { edge: Some(view) }`, and from then on that
//! share's frames come from the edge, not over the session's own connection. This task
//! owns that second link. The control reader hands it an [`EdgeCmd`] for each word of
//! the relay's; it dials the edge (`transport::connect_edge`, trusting only the
//! certificate hashes the relay sent), shows the ticket, waits for `Ready`, and then
//! forwards the edge's video records and screen-audio datagrams into the receiver tasks
//! that read the relay's ([`merged`]). The assembler, the decryption and the jitter
//! buffers are the ones they always were.
//!
//! An edge cannot read a frame or make one: the media key comes from the sharer. What
//! it can do is drop, stall or replay, so the app keeps an eye on it and tells the relay
//! (`ClientMessage::EdgeFailed`), which moves it elsewhere:
//! - at once when the connect, the hello or `Ready` fails, or when the view the relay
//!   sent is not one to dial at all (`valid_edge_view`);
//! - after [`EDGE_SILENT_MS`] with no whole, decrypted frame of the share. The video
//!   receiver stamps `last_good_frame_ms` when one is put together; records, screen
//!   audio and frames that do not decrypt never do, so an edge that forwards audio or
//!   garbage alone is caught too;
//! - [`ENDED_GRACE_MS`] after the edge ended the link itself, if the relay has not said
//!   where to go by then (it usually has: it revoked the ticket first);
//! - and once more every [`EDGE_SILENT_MS`] while the relay does not answer, which it
//!   does not while the share itself sends nothing.
//!
//! A hostile relay can send the app to any host. It is dialled only for a share the
//! person chose to watch, at most once every [`CONNECT_SPACING_MS`], and shown nothing
//! but the ticket the relay gave.

use std::future::Future;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use bytes::Bytes;
use rustls::pki_types::ServerName;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{info, warn};
use wtransport::{Connection, RecvStream, SendStream, VarInt};

use voipc_protocol::messages::ClientMessage;
use voipc_protocol::pool::{
    self, EdgeViewMsg, ViewerMsg, MAX_CERT_HASHES, MAX_POOL_FRAME, MAX_TICKET_BYTES,
};
use voipc_protocol::types::EdgeView;

use crate::network::ControlTx;
use crate::transport::{self, Quic, VideoIn};

/// No whole, decrypted frame of the share for this long from an edge that said `Ready`:
/// the relay is told, and told again after as long once more while it does not answer.
/// A still screen still sends a keyframe every 4 s, so this is over two of them.
pub const EDGE_SILENT_MS: u64 = 10_000;
/// At most one edge connect per this long on a connection. A relay that keeps sending
/// the app elsewhere gets one handshake every 5 s out of it, no more.
pub const CONNECT_SPACING_MS: u64 = 5_000;
/// How long the app waits for the relay's word after an edge ended the link itself.
pub const ENDED_GRACE_MS: u64 = 5_000;
/// Bound for the hello: the ticket out and `Ready` back.
const READY_TIMEOUT: Duration = Duration::from_secs(5);
/// How often the timers are looked at.
const TICK: Duration = Duration::from_millis(250);

/// Milliseconds on this process's monotonic clock, never 0: the clock the video
/// receiver stamps good frames by and the timers here count on.
pub fn now_ms() -> u64 {
    static START: LazyLock<std::time::Instant> = LazyLock::new(std::time::Instant::now);
    START.elapsed().as_millis() as u64 + 1
}

/// What the control reader tells the edge task.
#[derive(Debug)]
pub enum EdgeCmd {
    /// `WatchAt { edge: Some(view) }` for the share being watched: fetch it from there.
    Open {
        sharer: u32,
        placement: u64,
        view: EdgeView,
    },
    /// The share comes over the session again (`WatchAt { edge: None }`), or is not
    /// watched from there any more (`StoppedWatchingScreenShare`, `WatchingScreenShare`).
    Close,
}

/// Whether a view the relay sent is one to dial: a DNS name or a bare IP literal, a
/// port, one to four certificate hashes (32 bytes each, by type) and a ticket of at most
/// `pool::MAX_TICKET_BYTES`. Anything else counts as a failed edge, reported at once.
pub(crate) fn valid_edge_view(view: &EdgeView) -> bool {
    let host = !view.host.is_empty()
        && view.host.len() <= 253
        && ServerName::try_from(view.host.as_str()).is_ok();
    host && view.port != 0
        && (1..=MAX_CERT_HASHES).contains(&view.cert_hashes.len())
        && view.ticket.len() <= MAX_TICKET_BYTES
}

/// Whether the edge in force has gone silent: no whole, decrypted frame of the share for
/// [`EDGE_SILENT_MS`] since `since_ms` (the later of its `Ready` and the last good frame),
/// nor since the last `EdgeFailed` about it, so a relay that does not answer hears it
/// again only after as long once more.
pub(crate) fn edge_failed_due(now_ms: u64, since_ms: u64, failed_ms: Option<u64>) -> bool {
    let quiet_since = failed_ms.map_or(since_ms, |failed| failed.max(since_ms));
    now_ms.saturating_sub(quiet_since) >= EDGE_SILENT_MS
}

// ── The receivers' side ──────────────────────────────────────────────────

/// Media of one kind from the edge links on its way to the receiver task that reads the
/// relay's. Each item carries the generation of the link it came on.
pub struct EdgeIn<T> {
    rx: mpsc::Receiver<(u32, T)>,
    gen: Arc<AtomicU32>,
    watching: Arc<AtomicU32>,
}

impl<T: FromShare> EdgeIn<T> {
    /// The next item of the link in force that belongs to the share being watched;
    /// `None` once the edge task has gone. Items of an older link are dropped here, so
    /// what an edge sent before a new `WatchAt` moved us, or before the link was closed,
    /// never reaches the assembler. Nothing is awaited once an item is taken.
    pub async fn next(&mut self) -> Option<T> {
        loop {
            let (gen, item) = self.rx.recv().await?;
            if gen != self.gen.load(Ordering::Acquire) {
                continue;
            }
            if let Some(item) = item.of_share(self.watching.load(Ordering::Relaxed)) {
                return Some(item);
            }
        }
    }
}

/// What an edge may bring in: the packet types an edge carries, of the watched share.
/// No voice, no pongs, no other share.
pub trait FromShare: Sized {
    fn of_share(self, sharer: u32) -> Option<Self>;
}

/// Video records: 0x13 and 0x14.
impl FromShare for Vec<Vec<u8>> {
    fn of_share(mut self, sharer: u32) -> Option<Self> {
        self.retain(|record| sent_by(record, &[0x13, 0x14], sharer));
        (!self.is_empty()).then_some(self)
    }
}

/// Datagrams: screen audio, 0x15.
impl FromShare for Bytes {
    fn of_share(self, sharer: u32) -> Option<Self> {
        sent_by(&self, &[0x15], sharer).then_some(self)
    }
}

/// Whether a packet is one of `types` from `sharer`: its session id is bytes 1..5, as in
/// every media header.
fn sent_by(packet: &[u8], types: &[u8], sharer: u32) -> bool {
    sharer != 0
        && packet.len() >= 5
        && types.contains(&packet[0])
        && u32::from_be_bytes([packet[1], packet[2], packet[3], packet[4]]) == sharer
}

/// The relay's next item or an edge's, whichever comes first, so a receiver task reads
/// both as one. `None` only when the relay's input ends; an edge task that has gone just
/// stops adding to it.
///
/// Cancel-safe, so a receiver may race it against its own timers, because both reads
/// are: wtransport documents `accept_uni` as cancel-safe, quinn's stream reads are, a
/// datagram is taken off wtransport's queue and returned in the same poll, `VideoIn`
/// keeps the frame stream it is reading in itself, and [`EdgeIn::next`] awaits nothing
/// once it holds an item.
pub async fn merged<T: FromShare>(
    core: impl Future<Output = Option<T>>,
    edge: &mut EdgeIn<T>,
) -> Option<T> {
    tokio::select! {
        item = core => item,
        Some(item) = edge.next() => Some(item),
    }
}

/// Where a link puts what its edge sends, each item tagged with its generation.
#[derive(Clone)]
pub struct Outlets {
    pub(crate) video: mpsc::Sender<(u32, Vec<Vec<u8>>)>,
    pub(crate) datagrams: mpsc::Sender<(u32, Bytes)>,
}

/// The edge task's ends of the edge media and the receivers', made together.
pub struct Pipes {
    pub out: Outlets,
    /// The generation of the link in force, which only the edge task moves.
    pub gen: Arc<AtomicU32>,
    pub video_in: EdgeIn<Vec<Vec<u8>>>,
    pub datagrams_in: EdgeIn<Bytes>,
}

impl Pipes {
    /// `watching`: the share being watched (0: none), the only one taken from an edge.
    pub fn new(watching: Arc<AtomicU32>) -> Self {
        let gen = Arc::new(AtomicU32::new(0));
        // As deep as the relay's own lanes: a frame's records, and a burst of screen audio
        let (video, video_rx) = mpsc::channel(64);
        let (datagrams, datagrams_rx) = mpsc::channel(256);
        Self {
            out: Outlets { video, datagrams },
            video_in: EdgeIn {
                rx: video_rx,
                gen: gen.clone(),
                watching: watching.clone(),
            },
            datagrams_in: EdgeIn {
                rx: datagrams_rx,
                gen: gen.clone(),
                watching,
            },
            gen,
        }
    }
}

// ── The rules, with the clock passed in ──────────────────────────────────

/// What the rules ask of the task, in order.
#[derive(Debug, PartialEq)]
enum Do {
    /// Dial `view` for the share of `sharer`.
    Connect { sharer: u32, view: EdgeView },
    /// Tell the relay the edge of `placement` failed us.
    Fail {
        sharer: u32,
        placement: u64,
        host: String,
    },
    /// End the link in force, if there is one. Its media still queued is dropped.
    Drop,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Phase {
    /// For the connect spacing: dialled once [`CONNECT_SPACING_MS`] have passed.
    Waiting,
    /// Dialling, or the hello not answered yet.
    Connecting,
    /// The edge said `Ready` at `since`.
    Ready { since: u64 },
    /// The edge ended the link at `at`, and the relay has not spoken since.
    Ended { at: u64 },
    /// No link: the relay was told, and its answer is awaited.
    Failed,
}

/// The `WatchAt` in force.
struct Want {
    sharer: u32,
    placement: u64,
    view: EdgeView,
    phase: Phase,
    /// The last `EdgeFailed` about it.
    failed_at: Option<u64>,
}

/// One connection's edge rules: what each word of the relay's, each turn of a link and
/// each tick asks for.
struct Rules {
    tunnel: bool,
    want: Option<Want>,
    last_connect: Option<u64>,
}

impl Rules {
    fn new(tunnel: bool) -> Self {
        Self {
            tunnel,
            want: None,
            last_connect: None,
        }
    }

    fn spaced(&self, now: u64) -> bool {
        self.last_connect
            .is_none_or(|at| now.saturating_sub(at) >= CONNECT_SPACING_MS)
    }

    /// A `WatchAt` with an edge. Whatever came before ends here; a view not to dial, or
    /// a session on the TCP fallback, is reported at once.
    fn open(&mut self, now: u64, sharer: u32, placement: u64, view: EdgeView) -> Vec<Do> {
        let mut todo = vec![Do::Drop];
        let phase = if self.tunnel || !valid_edge_view(&view) {
            todo.push(Do::Fail {
                sharer,
                placement,
                host: view.host.clone(),
            });
            Phase::Failed
        } else if self.spaced(now) {
            self.last_connect = Some(now);
            todo.push(Do::Connect {
                sharer,
                view: view.clone(),
            });
            Phase::Connecting
        } else {
            Phase::Waiting
        };
        let failed_at = (phase == Phase::Failed).then_some(now);
        self.want = Some(Want {
            sharer,
            placement,
            view,
            phase,
            failed_at,
        });
        todo
    }

    /// The share comes over the session again, or is not watched.
    fn close(&mut self) -> Vec<Do> {
        match self.want.take() {
            Some(_) => vec![Do::Drop],
            None => Vec::new(),
        }
    }

    /// The edge took the ticket.
    fn ready(&mut self, now: u64) {
        if let Some(want) = self.want.as_mut().filter(|w| w.phase == Phase::Connecting) {
            want.phase = Phase::Ready { since: now };
        }
    }

    /// The link in force went down by itself: before `Ready` that is a failed edge,
    /// after it the relay usually speaks first.
    fn down(&mut self, now: u64) -> Vec<Do> {
        let Some(want) = self.want.as_mut() else {
            return Vec::new();
        };
        match want.phase {
            Phase::Connecting => {
                want.phase = Phase::Failed;
                want.failed_at = Some(now);
                vec![Do::Fail {
                    sharer: want.sharer,
                    placement: want.placement,
                    host: want.view.host.clone(),
                }]
            }
            Phase::Ready { .. } => {
                want.phase = Phase::Ended { at: now };
                Vec::new()
            }
            _ => Vec::new(),
        }
    }

    /// The timers. `good_frame`: the last whole, decrypted frame of the watched share;
    /// `watching`: the share watched now, which ends the link when it is another or none.
    fn tick(&mut self, now: u64, good_frame: u64, watching: u32) -> Vec<Do> {
        if self.want.as_ref().is_some_and(|w| w.sharer != watching) {
            return self.close();
        }
        let spaced = self.spaced(now);
        let Some(want) = self.want.as_mut() else {
            return Vec::new();
        };
        // At most one EdgeFailed per EDGE_SILENT_MS per WatchAt
        let may_fail = want
            .failed_at
            .is_none_or(|at| now.saturating_sub(at) >= EDGE_SILENT_MS);
        let fail = match want.phase {
            Phase::Waiting if spaced => {
                want.phase = Phase::Connecting;
                self.last_connect = Some(now);
                return vec![Do::Connect {
                    sharer: want.sharer,
                    view: want.view.clone(),
                }];
            }
            Phase::Ready { since } => edge_failed_due(now, since.max(good_frame), want.failed_at),
            Phase::Ended { at } if now.saturating_sub(at) >= ENDED_GRACE_MS && may_fail => {
                want.phase = Phase::Failed;
                true
            }
            Phase::Failed => may_fail,
            _ => false,
        };
        if !fail {
            return Vec::new();
        }
        want.failed_at = Some(now);
        vec![Do::Fail {
            sharer: want.sharer,
            placement: want.placement,
            host: want.view.host.clone(),
        }]
    }
}

// ── The task ─────────────────────────────────────────────────────────────

/// What the edge task works with.
pub struct Ctx {
    /// The session runs over the TCP fallback, where UDP to an edge would not get
    /// through either: every placement is reported at once. The relay never places such
    /// a session; this is the backstop.
    pub tunnel: bool,
    /// For `EdgeFailed`.
    pub tcp_tx: ControlTx,
    pub out: Outlets,
    pub gen: Arc<AtomicU32>,
    /// The share being watched (0: none), as the receivers read it.
    pub watching: Arc<AtomicU32>,
    /// When the video receiver last put a whole, decrypted frame of the watched share
    /// together ([`now_ms`]).
    pub last_good_frame_ms: Arc<AtomicU64>,
    pub emit: Emit,
}

/// The `edge-view` event, for the log and the lanes: sharer, host and `"connecting"`,
/// `"ready"`, `"failed"` or `"closed"`.
pub type Emit = Box<dyn Fn(u32, &str, &str) + Send + Sync>;

/// How a link's task reports back, with its generation.
enum Event {
    Ready,
    Down { why: String },
}

/// The link in force. Dropping it ends its task, and with it the connection.
struct Link {
    gen: u32,
    sharer: u32,
    host: String,
    task: JoinHandle<()>,
}

impl Drop for Link {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// An edge connection, closed however it goes: a link's task aborted at any await, or
/// the whole session torn down. wtransport keeps a driver task of its own on the
/// connection, so a dropped handle alone would leave it up until its idle timeout.
struct Dialled(Quic);

impl Drop for Dialled {
    fn drop(&mut self) {
        self.0.connection.close(VarInt::from_u32(0), b"");
    }
}

/// One connection's edge task: runs until the control reader is gone.
pub async fn run(mut cmds: mpsc::Receiver<EdgeCmd>, ctx: Ctx) {
    let mut rules = Rules::new(ctx.tunnel);
    let (events_tx, mut events) = mpsc::channel::<(u32, Event)>(8);
    let mut link: Option<Link> = None;
    let mut tick = tokio::time::interval(TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        let todo = tokio::select! {
            cmd = cmds.recv() => match cmd {
                Some(EdgeCmd::Open { sharer, placement, view }) => {
                    rules.open(now_ms(), sharer, placement, view)
                }
                Some(EdgeCmd::Close) => rules.close(),
                None => break,
            },
            Some((gen, event)) = events.recv() => {
                // A link dropped since says nothing any more
                if link.as_ref().is_none_or(|l| l.gen != gen) {
                    continue;
                }
                match event {
                    Event::Ready => {
                        if let Some(l) = &link {
                            info!(sharer = l.sharer, host = %shown(&l.host), "watching from an edge");
                            (ctx.emit)(l.sharer, &l.host, "ready");
                        }
                        rules.ready(now_ms());
                        Vec::new()
                    }
                    Event::Down { why } => {
                        if let Some(l) = link.take() {
                            info!(sharer = l.sharer, host = %shown(&l.host), "edge link down: {why}");
                            (ctx.emit)(l.sharer, &l.host, "closed");
                        }
                        rules.down(now_ms())
                    }
                }
            },
            _ = tick.tick() => rules.tick(
                now_ms(),
                ctx.last_good_frame_ms.load(Ordering::Relaxed),
                ctx.watching.load(Ordering::Relaxed),
            ),
        };
        for step in todo {
            match step {
                Do::Connect { sharer, view } => {
                    let gen = ctx.gen.fetch_add(1, Ordering::AcqRel).wrapping_add(1);
                    info!(sharer, host = %shown(&view.host), port = view.port, "connecting to an edge");
                    (ctx.emit)(sharer, &view.host, "connecting");
                    let host = view.host.clone();
                    let task =
                        tokio::spawn(link_task(gen, view, ctx.out.clone(), events_tx.clone()));
                    link = Some(Link {
                        gen,
                        sharer,
                        host,
                        task,
                    });
                }
                Do::Fail {
                    sharer,
                    placement,
                    host,
                } => {
                    warn!(sharer, placement, host = %shown(&host), "the edge failed us, asking the relay for another place");
                    let _ = ctx.tcp_tx.send(&ClientMessage::EdgeFailed {
                        sharer_user_id: sharer,
                        placement,
                    });
                    (ctx.emit)(sharer, &host, "failed");
                }
                Do::Drop => {
                    // Before anything new: what the old link queued is void from here
                    ctx.gen.fetch_add(1, Ordering::AcqRel);
                    if let Some(l) = link.take() {
                        info!(sharer = l.sharer, host = %shown(&l.host), "edge link closed");
                        (ctx.emit)(l.sharer, &l.host, "closed");
                    }
                }
            }
        }
    }
}

/// One edge link: dial, hello, then carry its media until it ends, and say how it went.
async fn link_task(gen: u32, view: EdgeView, out: Outlets, events: mpsc::Sender<(u32, Event)>) {
    let why = match dial(&view).await {
        Err(why) => why,
        Ok((edge, send, recv)) => {
            let _ = events.send((gen, Event::Ready)).await;
            let why = carry(&edge.0.connection, recv, &out, gen).await;
            // Held until here: the edge may read our half's end as the viewer leaving
            drop(send);
            why
        }
    };
    let _ = events.send((gen, Event::Down { why })).await;
}

/// The connect and the hello, each within its own 5 s.
async fn dial(view: &EdgeView) -> Result<(Dialled, SendStream, RecvStream), String> {
    let edge = Dialled(transport::connect_edge(&view.host, view.port, &view.cert_hashes).await?);
    let hello = pool::encode_viewer_msg(&ViewerMsg::Hello {
        ticket: view.ticket.clone(),
    })
    .map_err(|e| format!("could not write the hello: {e}"))?;
    let connection = &edge.0.connection;
    let (send, recv) = tokio::time::timeout(READY_TIMEOUT, async {
        let opening = connection
            .open_bi()
            .await
            .map_err(|e| format!("no hello stream: {e}"))?;
        let (mut send, mut recv) = opening.await.map_err(|e| format!("no hello stream: {e}"))?;
        send.write_all(&hello)
            .await
            .map_err(|e| format!("the hello did not go out: {e}"))?;
        match read_view_msg(&mut recv).await? {
            EdgeViewMsg::Ready => Ok((send, recv)),
            EdgeViewMsg::Ended { reason } => {
                Err(format!("the edge refused the ticket ({})", shown(&reason)))
            }
        }
    })
    .await
    .map_err(|_| "no Ready from the edge within 5 s".to_string())??;
    Ok((edge, send, recv))
}

/// Forward what the edge sends until the link ends: video records in order (a full
/// queue holds the edge back, as it would hold the relay), screen audio as it comes (a
/// full queue drops it, as UDP would), and the edge's own `Ended`. Says why it ended.
async fn carry(connection: &Connection, mut hello: RecvStream, out: &Outlets, gen: u32) -> String {
    let video = async {
        let mut input = VideoIn::quic(connection.clone());
        while let Some(records) = input.next().await {
            if !records.is_empty() && out.video.send((gen, records)).await.is_err() {
                return "the session is gone".to_string();
            }
        }
        "its video streams ended".to_string()
    };
    let datagrams = async {
        loop {
            match connection.receive_datagram().await {
                Ok(datagram) => {
                    let _ = out.datagrams.try_send((gen, datagram.payload()));
                }
                Err(e) => return format!("the connection closed ({e})"),
            }
        }
    };
    let ended = async {
        loop {
            match read_view_msg(&mut hello).await {
                Ok(EdgeViewMsg::Ended { reason }) => {
                    return format!("the edge ended it ({})", shown(&reason))
                }
                Ok(EdgeViewMsg::Ready) => {}
                Err(e) => return e,
            }
        }
    };
    tokio::select! {
        why = video => why,
        why = datagrams => why,
        why = ended => why,
    }
}

/// One `EdgeViewMsg` off the hello stream: a big-endian u32 length, then postcard.
async fn read_view_msg(recv: &mut RecvStream) -> Result<EdgeViewMsg, String> {
    let closed = |_| "the edge closed the hello stream".to_string();
    let mut len = [0u8; 4];
    recv.read_exact(&mut len).await.map_err(closed)?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_POOL_FRAME {
        return Err(format!("the edge sent a {len}-byte answer"));
    }
    let mut payload = vec![0u8; len];
    recv.read_exact(&mut payload).await.map_err(closed)?;
    pool::decode_edge_view_msg(&payload)
        .map_err(|e| format!("the edge's answer does not read: {e}"))
}

/// What a relay or an edge named, fit for a log line: printable and short.
fn shown(text: &str) -> String {
    text.chars().filter(|c| !c.is_control()).take(64).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use voipc_protocol::codec::{decode_client_msg, PROTOCOL_VERSION};
    use voipc_protocol::video::VIDEO_HEADER_SIZE;

    fn view(host: &str) -> EdgeView {
        EdgeView {
            host: host.to_string(),
            port: 9991,
            cert_hashes: vec![[7; 32]],
            ticket: vec![1; 70],
        }
    }

    fn connects(todo: &[Do]) -> usize {
        todo.iter()
            .filter(|d| matches!(d, Do::Connect { .. }))
            .count()
    }

    fn fails(todo: &[Do]) -> Vec<u64> {
        todo.iter()
            .filter_map(|d| match d {
                Do::Fail { placement, .. } => Some(*placement),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn an_edge_view_is_checked_before_it_is_dialled() {
        for host in [
            "edge-1.example.net",
            "203.0.113.9",
            "2001:db8::9",
            "localhost",
        ] {
            assert!(valid_edge_view(&view(host)), "{host}");
        }
        for host in [
            "",
            "[2001:db8::9]",
            "edge one",
            "fe80::1%eth0",
            "a/b",
            &"a".repeat(254),
        ] {
            assert!(!valid_edge_view(&view(host)), "{host:?}");
        }
        let with = |f: fn(&mut EdgeView)| {
            let mut v = view("edge.example.net");
            f(&mut v);
            valid_edge_view(&v)
        };
        assert!(!with(|v| v.port = 0));
        assert!(!with(|v| v.cert_hashes.clear()));
        assert!(with(|v| v.cert_hashes = vec![[1; 32]; MAX_CERT_HASHES]));
        assert!(!with(|v| v.cert_hashes = vec![[1; 32]; MAX_CERT_HASHES + 1]));
        assert!(with(|v| v.ticket = vec![0; MAX_TICKET_BYTES]));
        assert!(!with(|v| v.ticket = vec![0; MAX_TICKET_BYTES + 1]));
    }

    /// The watchdog reads the last whole, decrypted frame only (the video receiver's
    /// stamp; see `only_a_frame_that_decrypts_feeds_the_edge_watchdog` in network.rs),
    /// and a relay that does not answer hears it again after 10 s more.
    #[test]
    fn edge_failed_due_counts_good_frames_only_and_again_after_10_s_more() {
        let ready = 1_000;
        assert!(!edge_failed_due(ready + EDGE_SILENT_MS - 1, ready, None));
        assert!(edge_failed_due(ready + EDGE_SILENT_MS, ready, None));
        // A good frame at 8 s puts it off to 18 s
        let good = 8_000;
        assert!(!edge_failed_due(17_999, good.max(ready), None));
        assert!(edge_failed_due(18_000, good.max(ready), None));
        // Told at 18 s and nothing since: again at 28 s, not before
        assert!(!edge_failed_due(27_999, good, Some(18_000)));
        assert!(edge_failed_due(28_000, good, Some(18_000)));
        // A frame after the word starts the count over from it
        assert!(!edge_failed_due(28_000, 20_000, Some(18_000)));

        // The same through the rules: datagrams and records leave the stamp alone, so
        // only frames keep it quiet
        let mut rules = Rules::new(false);
        rules.open(0, 7, 1, view("edge.example.net"));
        rules.ready(500);
        assert!(fails(&rules.tick(10_499, 0, 7)).is_empty());
        assert_eq!(fails(&rules.tick(10_500, 0, 7)), [1], "silent 10 s");
        assert!(fails(&rules.tick(15_000, 0, 7)).is_empty(), "once");
        assert_eq!(fails(&rules.tick(20_500, 0, 7)), [1], "again 10 s later");
        assert!(
            fails(&rules.tick(30_000, 29_000, 7)).is_empty(),
            "a frame came"
        );
    }

    #[test]
    fn edge_connects_are_spaced_5s() {
        let mut rules = Rules::new(false);
        assert_eq!(connects(&rules.open(0, 7, 1, view("a.example.net"))), 1);
        // The relay moves us at once: the new WatchAt waits for the spacing
        let todo = rules.open(1_000, 7, 2, view("b.example.net"));
        assert_eq!(todo[0], Do::Drop, "the old link ends at once");
        assert_eq!(connects(&todo), 0);
        assert_eq!(connects(&rules.tick(4_999, 0, 7)), 0);
        let todo = rules.tick(5_000, 0, 7);
        assert_eq!(
            todo,
            [Do::Connect {
                sharer: 7,
                view: view("b.example.net")
            }],
            "the WatchAt in force, not the one it replaced"
        );
        assert_eq!(connects(&rules.tick(5_250, 0, 7)), 0, "dialled once");
        // A view not to dial is reported at once and costs no connect
        assert_eq!(fails(&rules.open(6_000, 7, 3, view(""))), [3]);
        assert_eq!(
            connects(&rules.open(10_000, 7, 4, view("c.example.net"))),
            1
        );
    }

    #[test]
    fn a_failed_connect_or_hello_is_reported_at_once_and_a_late_one_never() {
        let mut rules = Rules::new(false);
        rules.open(0, 7, 1, view("edge.example.net"));
        assert_eq!(fails(&rules.down(4_000)), [1]);
        // No answer from the relay: once more 10 s later
        assert!(fails(&rules.tick(13_999, 0, 7)).is_empty());
        assert_eq!(fails(&rules.tick(14_000, 0, 7)), [1]);
        // The relay put us back on itself: nothing more about that edge
        assert_eq!(rules.close(), [Do::Drop]);
        assert!(rules.tick(40_000, 0, 7).is_empty());
        assert!(rules.down(40_000).is_empty());
    }

    #[test]
    fn an_edge_that_ends_the_link_is_reported_5_s_later_unless_the_relay_speaks_first() {
        let mut rules = Rules::new(false);
        rules.open(0, 7, 1, view("edge.example.net"));
        rules.ready(300);
        assert!(rules.down(2_000).is_empty(), "the relay may speak first");
        assert!(fails(&rules.tick(6_999, 2_000, 7)).is_empty());
        assert_eq!(fails(&rules.tick(7_000, 2_000, 7)), [1]);
        assert!(fails(&rules.tick(16_999, 2_000, 7)).is_empty());
        assert_eq!(
            fails(&rules.tick(17_000, 2_000, 7)),
            [1],
            "again 10 s later"
        );

        // The relay's revoke is followed by its WatchAt: no word from us
        let mut rules = Rules::new(false);
        rules.open(0, 7, 1, view("a.example.net"));
        rules.ready(300);
        rules.down(2_000);
        assert!(fails(&rules.open(2_100, 7, 2, view("b.example.net"))).is_empty());
        assert!(fails(&rules.tick(7_100, 2_000, 7)).is_empty());
    }

    #[test]
    fn a_session_on_the_tcp_fallback_reports_every_placement_at_once() {
        let mut rules = Rules::new(true);
        let todo = rules.open(0, 7, 5, view("edge.example.net"));
        assert_eq!(fails(&todo), [5]);
        assert_eq!(connects(&todo), 0);
    }

    #[test]
    fn the_link_closes_when_the_app_stops_watching_or_watches_another() {
        let mut rules = Rules::new(false);
        rules.open(0, 7, 1, view("edge.example.net"));
        rules.ready(100);
        assert!(rules.tick(200, 0, 7).is_empty());
        assert_eq!(rules.tick(300, 0, 0), [Do::Drop], "stopped watching");
        rules.open(6_000, 7, 2, view("edge.example.net"));
        assert_eq!(rules.tick(6_100, 0, 9), [Do::Drop], "watching another");
        assert!(rules.tick(60_000, 0, 9).is_empty(), "and nothing after");
    }

    /// A record or datagram queued by a link that a new `WatchAt` replaced, or that was
    /// closed, must not reach the assembler after the new one's.
    #[tokio::test]
    async fn the_generation_filter_drops_an_old_generations_record() {
        let watching = Arc::new(AtomicU32::new(7));
        let mut pipes = Pipes::new(watching);
        let record = |frame: u8| vec![0x13, 0, 0, 0, 7, frame];
        pipes.gen.store(1, Ordering::Release);
        pipes.out.video.send((1, vec![record(1)])).await.unwrap();
        pipes.out.video.send((1, vec![record(2)])).await.unwrap();
        // A new link: what the old one queued is void
        pipes.gen.store(2, Ordering::Release);
        pipes.out.video.send((2, vec![record(3)])).await.unwrap();
        assert_eq!(pipes.video_in.next().await.unwrap(), [record(3)]);

        pipes
            .out
            .datagrams
            .send((1, Bytes::from(vec![0x15, 0, 0, 0, 7, 1])))
            .await
            .unwrap();
        pipes
            .out
            .datagrams
            .send((2, Bytes::from(vec![0x15, 0, 0, 0, 7, 2])))
            .await
            .unwrap();
        assert_eq!(
            &pipes.datagrams_in.next().await.unwrap()[..],
            [0x15, 0, 0, 0, 7, 2]
        );
    }

    #[tokio::test]
    async fn only_the_watched_shares_video_and_screen_audio_come_in_from_an_edge() {
        let watching = Arc::new(AtomicU32::new(7));
        let mut pipes = Pipes::new(watching.clone());
        pipes.gen.store(1, Ordering::Release);
        let ours = vec![0x14, 0, 0, 0, 7, 1];
        let records = vec![
            vec![0x13, 0, 0, 0, 8, 1], // another share
            vec![0x05, 0, 0, 0, 7, 1], // voice is never an edge's
            vec![0x13, 0, 0, 7],       // too short for a sender
            ours.clone(),
        ];
        pipes.out.video.send((1, records)).await.unwrap();
        assert_eq!(pipes.video_in.next().await.unwrap(), [ours]);
        for packet in [
            vec![0x05, 0, 0, 0, 7, 1],
            vec![0x04, 0, 0, 0, 7, 1],
            vec![0x15, 0, 0, 0, 8, 1],
            vec![0x15, 0, 0, 0, 7, 9],
        ] {
            pipes
                .out
                .datagrams
                .send((1, Bytes::from(packet)))
                .await
                .unwrap();
        }
        assert_eq!(
            &pipes.datagrams_in.next().await.unwrap()[..],
            [0x15, 0, 0, 0, 7, 9]
        );
        // Not watching: nothing at all
        watching.store(0, Ordering::Relaxed);
        pipes
            .out
            .video
            .send((1, vec![vec![0x13, 0, 0, 0, 0, 1]]))
            .await
            .unwrap();
        drop(pipes.out);
        assert!(pipes.video_in.next().await.is_none());
    }

    // ── Against a stand-in edge on loopback ──────────────────────────────

    type Server = wtransport::Endpoint<wtransport::endpoint::endpoint_side::Server>;

    /// A stand-in edge: a self-signed P-256 certificate valid for ten days, as an edge's
    /// own is, served at loopback. Returns its endpoint, port and certificate hash.
    fn stand_in_edge() -> (Server, u16, [u8; 32]) {
        use std::time::{SystemTime, UNIX_EPOCH};
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["edge.invalid".to_string()]).unwrap();
        let now = rcgen::date_time_ymd(1970, 1, 1)
            + SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        params.not_before = now - Duration::from_secs(3_600);
        params.not_after = now + Duration::from_secs(10 * 86_400);
        let cert = params.self_signed(&key).unwrap();
        let hash: [u8; 32] = ring::digest::digest(&ring::digest::SHA256, cert.der())
            .as_ref()
            .try_into()
            .unwrap();
        let identity = wtransport::Identity::new(
            wtransport::tls::CertificateChain::single(
                wtransport::tls::Certificate::from_der(cert.der().to_vec()).unwrap(),
            ),
            wtransport::tls::PrivateKey::from_der_pkcs8(key.serialize_der()),
        );
        let config = wtransport::ServerConfig::builder()
            .with_bind_address("127.0.0.1:0".parse().unwrap())
            .with_identity(identity)
            .build();
        let server = wtransport::Endpoint::server(config).unwrap();
        let port = server.local_addr().unwrap().port();
        (server, port, hash)
    }

    /// One viewer at the stand-in: the session at `pool::VIEW_PATH`, the hello read,
    /// and the ticket it showed.
    async fn take_viewer(server: &Server) -> (Connection, SendStream, Vec<u8>) {
        let request = server.accept().await.await.unwrap();
        assert_eq!(request.path(), pool::VIEW_PATH);
        let connection = request.accept().await.unwrap();
        let (send, mut recv) = connection.accept_bi().await.unwrap();
        let mut len = [0u8; 4];
        recv.read_exact(&mut len).await.unwrap();
        let mut payload = vec![0u8; u32::from_be_bytes(len) as usize];
        recv.read_exact(&mut payload).await.unwrap();
        let ViewerMsg::Hello { ticket } = pool::decode_viewer_msg(&payload).unwrap();
        (connection, send, ticket)
    }

    async fn say(send: &mut SendStream, msg: EdgeViewMsg) {
        send.write_all(&pool::encode_edge_view_msg(&msg).unwrap())
            .await
            .unwrap();
    }

    type States = Arc<std::sync::Mutex<Vec<String>>>;

    /// An edge task for sharer 7: its commands, its pipes' receiving ends, the control
    /// frames it queues and the `edge-view` states it emits.
    struct Task {
        cmds: mpsc::Sender<EdgeCmd>,
        video: EdgeIn<Vec<Vec<u8>>>,
        datagrams: EdgeIn<Bytes>,
        control: mpsc::UnboundedReceiver<Vec<u8>>,
        states: States,
    }

    fn edge_task(tunnel: bool) -> Task {
        let watching = Arc::new(AtomicU32::new(7));
        let pipes = Pipes::new(watching.clone());
        let (tx, control) = mpsc::unbounded_channel();
        let states = States::default();
        let seen = states.clone();
        let (cmds, cmd_rx) = mpsc::channel(8);
        tokio::spawn(run(
            cmd_rx,
            Ctx {
                tunnel,
                tcp_tx: ControlTx::new(tx, PROTOCOL_VERSION),
                out: pipes.out,
                gen: pipes.gen,
                watching,
                last_good_frame_ms: Arc::default(),
                emit: Box::new(move |sharer, _, state| {
                    assert_eq!(sharer, 7);
                    seen.lock().unwrap().push(state.to_string());
                }),
            },
        ));
        Task {
            cmds,
            video: pipes.video_in,
            datagrams: pipes.datagrams_in,
            control,
            states,
        }
    }

    async fn within<T>(what: &str, f: impl Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(5), f)
            .await
            .unwrap_or_else(|_| panic!("no {what} within 5 s"))
    }

    /// The native path no browser lane runs: dialled by its hash, the ticket shown,
    /// `Ready`, then the edge's frame records and screen audio reach the receivers'
    /// ends, and its `Ended` closes the link without a word to the relay yet.
    #[tokio::test]
    async fn a_stand_in_edge_is_dialled_by_its_hash_and_its_media_comes_in() {
        let (server, port, hash) = stand_in_edge();
        let Task {
            cmds,
            mut video,
            mut datagrams,
            mut control,
            states,
        } = edge_task(false);
        cmds.send(EdgeCmd::Open {
            sharer: 7,
            placement: 1,
            view: EdgeView {
                host: "127.0.0.1".into(),
                port,
                cert_hashes: vec![[0; 32], hash],
                ticket: b"a ticket".to_vec(),
            },
        })
        .await
        .unwrap();
        let (connection, mut send, ticket) = within("viewer", take_viewer(&server)).await;
        assert_eq!(ticket, b"a ticket");
        say(&mut send, EdgeViewMsg::Ready).await;

        // Records as long as a video header at least, or the stream reader gives up
        let record = |sharer: u8| {
            let mut record = vec![0x13, 0, 0, 0, sharer];
            record.resize(VIDEO_HEADER_SIZE + 8, 42);
            record
        };
        let ours = record(7);
        let mut frame = connection.open_uni().await.unwrap().await.unwrap();
        for record in [record(8), ours.clone()] {
            frame
                .write_all(&(record.len() as u16).to_be_bytes())
                .await
                .unwrap();
            frame.write_all(&record).await.unwrap();
        }
        frame.finish().await.unwrap();
        assert_eq!(within("record", video.next()).await.unwrap(), [ours]);
        connection.send_datagram([0x15, 0, 0, 0, 7, 3]).unwrap();
        assert_eq!(
            &within("datagram", datagrams.next()).await.unwrap()[..],
            [0x15, 0, 0, 0, 7, 3]
        );

        say(
            &mut send,
            EdgeViewMsg::Ended {
                reason: "revoked".into(),
            },
        )
        .await;
        within("close", async {
            while states.lock().unwrap().last().map(String::as_str) != Some("closed") {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        assert_eq!(*states.lock().unwrap(), ["connecting", "ready", "closed"]);
        assert!(
            control.try_recv().is_err(),
            "the relay may still speak first"
        );
    }

    /// The `EdgeFailed` the task queued, read back.
    async fn edge_failed(control: &mut mpsc::UnboundedReceiver<Vec<u8>>) -> (u32, u64) {
        let frame = within("EdgeFailed", control.recv()).await.unwrap();
        match decode_client_msg(&frame[4..]).unwrap() {
            ClientMessage::EdgeFailed {
                sharer_user_id,
                placement,
            } => (sharer_user_id, placement),
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn a_refused_ticket_is_reported_at_once() {
        let (server, port, hash) = stand_in_edge();
        let Task {
            cmds,
            video: _video,
            datagrams: _datagrams,
            mut control,
            states,
        } = edge_task(false);
        cmds.send(EdgeCmd::Open {
            sharer: 7,
            placement: 4,
            view: EdgeView {
                host: "127.0.0.1".into(),
                port,
                cert_hashes: vec![hash],
                ticket: b"used".to_vec(),
            },
        })
        .await
        .unwrap();
        let (_connection, mut send, _) = within("viewer", take_viewer(&server)).await;
        say(
            &mut send,
            EdgeViewMsg::Ended {
                reason: "ticket refused".into(),
            },
        )
        .await;
        assert_eq!(edge_failed(&mut control).await, (7, 4));
        assert_eq!(*states.lock().unwrap(), ["connecting", "closed", "failed"]);
    }

    /// The relay names the edge's certificate; any other, the right one for another
    /// edge included, is refused before a ticket is shown.
    #[tokio::test]
    async fn an_edge_of_another_certificate_is_refused_and_reported() {
        let (server, port, hash) = stand_in_edge();
        let sessions = Arc::new(AtomicU32::new(0));
        let count = sessions.clone();
        tokio::spawn(async move {
            loop {
                if server.accept().await.await.is_ok() {
                    count.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        assert!(transport::connect_edge("127.0.0.1", port, &[[9; 32]])
            .await
            .is_err());
        let Task {
            cmds,
            video: _video,
            datagrams: _datagrams,
            mut control,
            ..
        } = edge_task(false);
        let mut other = hash;
        other[0] ^= 1;
        cmds.send(EdgeCmd::Open {
            sharer: 7,
            placement: 2,
            view: EdgeView {
                host: "127.0.0.1".into(),
                port,
                cert_hashes: vec![other],
                ticket: b"secret".to_vec(),
            },
        })
        .await
        .unwrap();
        assert_eq!(edge_failed(&mut control).await, (7, 2));
        assert_eq!(
            sessions.load(Ordering::Relaxed),
            0,
            "no session came up, so no ticket was shown"
        );
    }

    #[tokio::test]
    async fn a_tunnel_session_never_dials() {
        let Task {
            cmds,
            video: _video,
            datagrams: _datagrams,
            mut control,
            states,
        } = edge_task(true);
        cmds.send(EdgeCmd::Open {
            sharer: 7,
            placement: 3,
            view: view("127.0.0.1"),
        })
        .await
        .unwrap();
        assert_eq!(edge_failed(&mut control).await, (7, 3));
        assert_eq!(*states.lock().unwrap(), ["failed"]);
    }
}
