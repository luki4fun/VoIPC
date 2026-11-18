// How many screen-share viewers one relay carries, alone or with media edges. K sharers send
// synthetic frames at a set rate (encrypted-type fragments of zeros, which the relay relays
// without reading, one QUIC stream a frame as the apps send them, a keyframe every 4 s and
// whenever the relay asks); V viewers split over them watch, and each second the run says
// what reached them and what it cost the relay, its edges and this process.
//
//   share_load <viewers> <host:port> <relay-pid> [--shares K] [--mbit M] [--fps F] [--secs S]
//              [--rate R] [--edge-pids P1,P2,..] [--first N]
//
// Defaults: 1 share, 7.5 Mbit/s (HD), 30 fps, 30 s, viewers arriving 100 a second. Give the
// relay `[media] share_viewers`, `video_egress_mbit` and `voice_room` above what the run asks
// (all sharers and viewers stand in one room), and `max_users` above V + K.
//
// A viewer the relay places on an edge (`WatchAt` with an edge, protocol 26) connects there
// as the apps do, without checking its certificate, shows its ticket and reads its frames
// from it; one sent back (`WatchAt` without one) reads them from the relay again. The time
// from a moved viewer's last frame to its next, from wherever, is the gap a lost edge cost
// it. `--edge-pids` names the edges' processes, whose CPU and memory are shown beside the
// relay's.
//
// `--shares 0` starts no sharer: the viewers watch the shares a run before this one started
// (another share_load on other CPUs, so one generator is not what the numbers measure), and
// `--first N` keeps their names and addresses apart from its viewers'.

#[path = "load_common/mod.rs"]
mod load_common;

use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::BytesMut;
use tokio::io::AsyncReadExt as _;
use tokio::sync::{mpsc, oneshot, watch};
use wtransport::{Connection, VarInt};

use load_common::{connect, enc, next_message, Connected, Error};
use voipc_protocol::codec::try_decode_frame;
use voipc_protocol::messages::{ClientMessage, ServerMessage};
use voipc_protocol::pool::{
    decode_edge_view_msg, encode_viewer_msg, EdgeViewMsg, ViewerMsg, VIEW_PATH,
};
use voipc_protocol::types::{EdgeView, ProximityMode, VideoCodec};
use voipc_protocol::video::{RecordReader, VideoPacket, MAX_ENCRYPTED_VIDEO_PAYLOAD_SIZE};

/// Names apart from the other load tools'.
const INDEX_BASE: usize = 300_000;
const ROOM: &str = "ShareLoad";
/// Latency is counted in 1 ms steps up to this; anything later in the last.
const LATENCY_MS: usize = 2000;
/// Edges a run tells apart, by the port viewers reach them on.
const EDGES: usize = 8;

struct Args {
    viewers: usize,
    server: String,
    pid: u32,
    shares: usize,
    mbit: f64,
    fps: f64,
    secs: u64,
    rate: f64,
    edge_pids: Vec<u32>,
    first: usize,
}

/// Where a frame came from.
#[derive(Clone, Copy)]
enum Source {
    Relay,
    Edge(usize),
}

struct Latency([AtomicU64; LATENCY_MS + 1]);

impl Latency {
    fn new() -> Self {
        Self(std::array::from_fn(|_| AtomicU64::new(0)))
    }

    fn add(&self, ms: u32) {
        self.0[(ms as usize).min(LATENCY_MS)].fetch_add(1, Ordering::Relaxed);
    }

    /// The `p`th percentile in ms, `None` with nothing counted.
    fn percentile(&self, p: f64) -> Option<usize> {
        let counts: Vec<u64> = self.0.iter().map(|c| c.load(Ordering::Relaxed)).collect();
        let total: u64 = counts.iter().sum();
        if total == 0 {
            return None;
        }
        let want = (total as f64 * p / 100.0).ceil().max(1.0) as u64;
        let mut seen = 0;
        counts.iter().position(|&n| {
            seen += n;
            seen >= want
        })
    }
}

struct Tally {
    watching: AtomicUsize,
    refused: AtomicUsize,
    lost: AtomicUsize,
    /// Viewers whose edge said `Ready` and still serves them.
    on_edges: AtomicUsize,
    /// Edges that refused a ticket, or could not be reached.
    edge_refused: AtomicUsize,
    edge_failed: AtomicUsize,
    /// `WatchAt`s that took a viewer off an edge.
    moved: AtomicUsize,
    bytes: AtomicU64,
    frames: AtomicU64,
    /// Frames that came with all their fragments.
    complete: AtomicU64,
    sent_frames: AtomicU64,
    /// Bytes from the relay, and from each edge by its slot in `edge_ports`.
    relay_bytes: AtomicU64,
    edge_ports: [AtomicU16; EDGES],
    edge_bytes: [AtomicU64; EDGES],
    /// Counted only once every viewer watches.
    steady: AtomicBool,
    relay_latency: Latency,
    edge_latency: Latency,
    /// A moved viewer's wait from its last frame to its next (ms).
    gaps: Mutex<Vec<u64>>,
    /// Every viewer's.
    marks: Mutex<Vec<Arc<Marks>>>,
}

impl Tally {
    fn new() -> Self {
        Self {
            watching: AtomicUsize::new(0),
            refused: AtomicUsize::new(0),
            lost: AtomicUsize::new(0),
            on_edges: AtomicUsize::new(0),
            edge_refused: AtomicUsize::new(0),
            edge_failed: AtomicUsize::new(0),
            moved: AtomicUsize::new(0),
            bytes: AtomicU64::new(0),
            frames: AtomicU64::new(0),
            complete: AtomicU64::new(0),
            sent_frames: AtomicU64::new(0),
            relay_bytes: AtomicU64::new(0),
            edge_ports: std::array::from_fn(|_| AtomicU16::new(0)),
            edge_bytes: std::array::from_fn(|_| AtomicU64::new(0)),
            steady: AtomicBool::new(false),
            relay_latency: Latency::new(),
            edge_latency: Latency::new(),
            gaps: Mutex::new(Vec::new()),
            marks: Mutex::new(Vec::new()),
        }
    }

    /// The slot of the edge on `port`, taken the first time it is seen.
    fn edge_slot(&self, port: u16) -> usize {
        for (i, slot) in self.edge_ports.iter().enumerate() {
            match slot.compare_exchange(0, port, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => return i,
                Err(held) if held == port => return i,
                Err(_) => {}
            }
        }
        EDGES - 1
    }

    fn edges_seen(&self) -> Vec<(usize, u16)> {
        self.edge_ports
            .iter()
            .enumerate()
            .map(|(i, p)| (i, p.load(Ordering::Relaxed)))
            .filter(|(_, p)| *p != 0)
            .collect()
    }
}

/// One viewer's marks for the gap a move cost it (ms on `now_ms`'s clock, 0: none).
#[derive(Default)]
struct Marks {
    last_frame: AtomicU64,
    waiting_since: AtomicU64,
    /// Once the run is steady: the first and last frame id it had whole, and how many, so
    /// a frame lost anywhere on the way counts against it.
    first_id: AtomicU32,
    last_id: AtomicU32,
    got: AtomicU64,
}

fn parse() -> Result<Args, Error> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let usage = "share_load <viewers> <host:port> <relay-pid> [--shares K] [--mbit M] [--fps F] [--secs S] [--rate R] [--edge-pids P1,P2,..] [--first N]";
    let [viewers, server, pid, rest @ ..] = a.as_slice() else {
        return Err(usage.into());
    };
    let value = |name: &str| -> Result<Option<&String>, Error> {
        match rest.iter().position(|x| x == name) {
            Some(i) => Ok(Some(rest.get(i + 1).ok_or(usage)?)),
            None => Ok(None),
        }
    };
    let flag = |name: &str, default: f64| -> Result<f64, Error> {
        Ok(value(name)?
            .map(|v| v.parse())
            .transpose()?
            .unwrap_or(default))
    };
    let edge_pids = match value("--edge-pids")? {
        Some(list) => list
            .split(',')
            .filter(|p| !p.is_empty())
            .map(|p| p.parse::<u32>())
            .collect::<Result<_, _>>()?,
        None => Vec::new(),
    };
    Ok(Args {
        viewers: viewers.parse()?,
        server: server.clone(),
        pid: pid.parse()?,
        shares: flag("--shares", 1.0)? as usize,
        mbit: flag("--mbit", 7.5)?,
        fps: flag("--fps", 30.0)?,
        secs: flag("--secs", 30.0)? as u64,
        rate: flag("--rate", 100.0)?,
        edge_pids,
        first: flag("--first", 0.0)? as usize,
    })
}

/// `(RSS in MiB, CPU seconds)` of a process, from /proc.
fn relay_stats(pid: u32) -> Option<(u64, f64)> {
    stats_of(&pid.to_string())
}

fn stats_of(pid: &str) -> Option<(u64, f64)> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let rss_kb: u64 = status
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))?
        .trim()
        .trim_end_matches(" kB")
        .parse()
        .ok()?;
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let mut after_name = stat.rsplit(')').next()?.split_whitespace();
    let utime: f64 = after_name.nth(11)?.parse().ok()?;
    let stime: f64 = after_name.next()?.parse().ok()?;
    Some((rss_kb / 1024, (utime + stime) / 100.0))
}

/// How many CPUs this process may run on (`taskset`), from /proc.
fn own_cpus() -> usize {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let Some(list) = status
        .lines()
        .find_map(|l| l.strip_prefix("Cpus_allowed_list:"))
    else {
        return 1;
    };
    list.trim()
        .split(',')
        .map(|part| match part.split_once('-') {
            Some((a, b)) => {
                b.trim().parse::<usize>().unwrap_or(0) + 1 - a.trim().parse::<usize>().unwrap_or(0)
            }
            None => 1,
        })
        .sum::<usize>()
        .max(1)
}

/// Datagrams the kernel dropped on sockets bound to `port`.
fn socket_drops(port: u16) -> u64 {
    let mut sum = 0;
    for table in ["/proc/net/udp", "/proc/net/udp6"] {
        for row in std::fs::read_to_string(table)
            .unwrap_or_default()
            .lines()
            .skip(1)
        {
            let cols: Vec<&str> = row.split_whitespace().collect();
            let bound = cols
                .get(1)
                .and_then(|a| a.rsplit(':').next())
                .and_then(|p| u16::from_str_radix(p, 16).ok());
            if bound == Some(port) {
                sum += cols.last().and_then(|d| d.parse::<u64>().ok()).unwrap_or(0);
            }
        }
    }
    sum
}

/// The wall clock in ms, cut to the 32 bits a frame's timestamp has: sharers and viewers
/// in different processes on one machine read the same clock.
fn now_ms() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u32)
}

/// One writer per connection, so a reader answering a ping and a phase sending never meet.
fn writer(mut send: wtransport::SendStream) -> mpsc::UnboundedSender<Vec<u8>> {
    let (out, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(async move {
        while let Some(data) = rx.recv().await {
            if send.write_all(&data).await.is_err() {
                return;
            }
        }
    });
    out
}

/// A sharer: makes the room (the first one), joins it, shares, and sends frames until the end.
async fn sharer(
    k: usize,
    args: Arc<Args>,
    room_tx: watch::Sender<u32>,
    mut room_rx: watch::Receiver<u32>,
    ids: mpsc::UnboundedSender<u32>,
    tally: Arc<Tally>,
    stop: Instant,
) -> Result<(), Error> {
    let c: Connected = connect(INDEX_BASE + k, &args.server).await?;
    let (user_id, session_id, proto) = (c.user_id, c.session_id, c.proto);
    let (connection, mut recv, mut buf) = (c.connection, c.recv, c.buf);
    let out = writer(c.send);
    if k == 0 {
        out.send(enc(
            &ClientMessage::CreateChannel {
                name: ROOM.into(),
                password: None,
                proximity: ProximityMode::Off,
                anonymous: false,
                text: false,
            },
            proto,
        )?)?;
    }
    // What the relay says: pings answered, the room's id passed on, and a keyframe sent
    // next when the relay asks for one (at most one a second for a share), as the apps do:
    // a viewer an edge starts on a keyframe waits for it
    let pings = out.clone();
    let key_wanted = Arc::new(AtomicBool::new(false));
    let wanted = key_wanted.clone();
    tokio::spawn(async move {
        while let Ok(msg) = next_message(&mut recv, &mut buf, proto).await {
            match msg {
                ServerMessage::Ping { timestamp } => {
                    let _ = enc(&ClientMessage::Ping { timestamp }, proto).map(|d| pings.send(d));
                }
                ServerMessage::ChannelCreated { channel } if channel.name == ROOM => {
                    room_tx.send_replace(channel.channel_id);
                }
                ServerMessage::KeyframeRequested => wanted.store(true, Ordering::Relaxed),
                _ => {}
            }
        }
    });
    let room = *room_rx.wait_for(|&id| id != 0).await?;
    out.send(enc(
        &ClientMessage::JoinChannel {
            channel_id: room,
            password: None,
        },
        proto,
    )?)?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    out.send(enc(
        &ClientMessage::StartScreenShare {
            source: "load".into(),
            resolution: 1080,
            codec: VideoCodec::H264,
        },
        proto,
    )?)?;
    ids.send(user_id)?;

    let per = MAX_ENCRYPTED_VIDEO_PAYLOAD_SIZE;
    let frame_bytes = (args.mbit * 1e6 / 8.0 / args.fps) as usize;
    let count = frame_bytes.div_ceil(per).clamp(1, 255);
    let keyframe_every = (args.fps * 4.0).max(1.0) as u32;
    let mut tick = tokio::time::interval(Duration::from_secs_f64(1.0 / args.fps));
    let mut frame_id = 0u32;
    while Instant::now() < stop {
        tick.tick().await;
        frame_id += 1;
        let key = frame_id % keyframe_every == 1 || key_wanted.swap(false, Ordering::Relaxed);
        let ts = now_ms();
        let mut records = Vec::with_capacity(count * (per + 32));
        for i in 0..count {
            let packet = VideoPacket::encrypted_fragment(
                key,
                session_id,
                frame_id,
                i as u8,
                count as u8,
                ts,
                0,
                k as u32,
                vec![0u8; per],
            )
            .to_bytes();
            records.extend_from_slice(&(packet.len() as u16).to_be_bytes());
            records.extend_from_slice(&packet);
        }
        let Ok(opening) = connection.open_uni().await else {
            break;
        };
        let Ok(mut stream) = opening.await else {
            break;
        };
        if stream.write_all(&records).await.is_ok() && stream.finish().await.is_ok() {
            tally.sent_frames.fetch_add(1, Ordering::Relaxed);
        }
    }
    Ok(())
}

/// Every frame stream on `conn`, counted as from `source`: its bytes, whether it came
/// whole, and once the run is steady, how long it took from its sharer.
async fn read_frames(conn: Connection, source: Source, tally: Arc<Tally>, marks: Arc<Marks>) {
    let mut chunk = vec![0u8; 16 * 1024];
    while let Ok(mut stream) = conn.accept_uni().await {
        let mut reader = RecordReader::default();
        let (mut records, mut first) = (0usize, None);
        while let Ok(Some(n)) = stream.read(&mut chunk).await {
            tally.bytes.fetch_add(n as u64, Ordering::Relaxed);
            match source {
                Source::Relay => &tally.relay_bytes,
                Source::Edge(slot) => &tally.edge_bytes[slot],
            }
            .fetch_add(n as u64, Ordering::Relaxed);
            for record in reader.push(&chunk[..n]) {
                records += 1;
                if first.is_none() {
                    first = VideoPacket::from_bytes(&record)
                        .ok()
                        .map(|p| (p.fragment_count, p.timestamp, p.frame_id));
                }
            }
        }
        tally.frames.fetch_add(1, Ordering::Relaxed);
        let Some((count, ts, id)) = first else {
            continue;
        };
        if records != count as usize {
            continue;
        }
        tally.complete.fetch_add(1, Ordering::Relaxed);
        let now = Instant::now();
        let at = START
            .get()
            .map_or(0, |s| now.duration_since(*s).as_millis() as u64);
        marks.last_frame.store(at, Ordering::Relaxed);
        let waiting = marks.waiting_since.swap(0, Ordering::Relaxed);
        if waiting != 0 {
            tally.gaps.lock().unwrap().push(at.saturating_sub(waiting));
        }
        if tally.steady.load(Ordering::Relaxed) {
            let _ = marks
                .first_id
                .compare_exchange(0, id, Ordering::Relaxed, Ordering::Relaxed);
            marks.last_id.fetch_max(id, Ordering::Relaxed);
            marks.got.fetch_add(1, Ordering::Relaxed);
            let ms = now_ms().wrapping_sub(ts);
            match source {
                Source::Relay => tally.relay_latency.add(ms),
                Source::Edge(_) => tally.edge_latency.add(ms),
            }
        }
    }
}

static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

/// A viewer's session with the edge `view` names: the ticket shown, its frames read until
/// `stop` fires or the edge ends it.
async fn watch_on_edge(
    endpoint: Arc<wtransport::Endpoint<wtransport::endpoint::endpoint_side::Client>>,
    view: EdgeView,
    tally: Arc<Tally>,
    marks: Arc<Marks>,
    mut stop: oneshot::Receiver<()>,
) {
    let host = if view.host.contains(':') {
        format!("[{}]", view.host)
    } else {
        view.host.clone()
    };
    let slot = tally.edge_slot(view.port);
    let url = format!("https://{host}:{}{VIEW_PATH}", view.port);
    let conn = match tokio::time::timeout(Duration::from_secs(10), endpoint.connect(url)).await {
        Ok(Ok(conn)) => conn,
        _ => {
            tally.edge_failed.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };
    let hello = edge_hello(&conn, view.ticket);
    let (_send, _recv) = match tokio::time::timeout(Duration::from_secs(10), hello).await {
        Ok(Ok((EdgeViewMsg::Ready, send, recv))) => (send, recv),
        Ok(Ok((EdgeViewMsg::Ended { .. }, ..))) => {
            tally.edge_refused.fetch_add(1, Ordering::Relaxed);
            conn.close(VarInt::from_u32(0), b"");
            return;
        }
        _ => {
            tally.edge_failed.fetch_add(1, Ordering::Relaxed);
            conn.close(VarInt::from_u32(0), b"");
            return;
        }
    };
    tally.on_edges.fetch_add(1, Ordering::Relaxed);
    tokio::select! {
        _ = read_frames(conn.clone(), Source::Edge(slot), tally.clone(), marks) => {}
        _ = &mut stop => {}
    }
    tally.on_edges.fetch_sub(1, Ordering::Relaxed);
    conn.close(VarInt::from_u32(0), b"");
}

/// The ticket shown on the edge's stream, and the edge's answer. The viewer's half of the
/// stream stays open: the edge reads nothing more from it.
async fn edge_hello(
    conn: &Connection,
    ticket: Vec<u8>,
) -> Result<(EdgeViewMsg, wtransport::SendStream, wtransport::RecvStream), Error> {
    let (mut send, mut recv) = conn.open_bi().await?.await?;
    send.write_all(&encode_viewer_msg(&ViewerMsg::Hello { ticket })?)
        .await?;
    let mut buf = BytesMut::new();
    loop {
        if let Some(payload) = try_decode_frame(&mut buf)? {
            return Ok((decode_edge_view_msg(&payload)?, send, recv));
        }
        if recv.read_buf(&mut buf).await? == 0 {
            return Err("the edge closed".into());
        }
    }
}

/// A viewer: joins the room, watches its sharer, and reads every frame stream, from the
/// relay or from the edge the relay sends it to.
async fn viewer(
    i: usize,
    args: Arc<Args>,
    room: u32,
    sharer_id: u32,
    tally: Arc<Tally>,
) -> Result<(), Error> {
    let c: Connected = connect(INDEX_BASE + 10_000 + args.first + i, &args.server).await?;
    let proto = c.proto;
    let endpoint = c.endpoint.clone();
    let (connection, mut recv, mut buf) = (c.connection, c.recv, c.buf);
    let out = writer(c.send);
    out.send(enc(
        &ClientMessage::JoinChannel {
            channel_id: room,
            password: None,
        },
        proto,
    )?)?;
    tokio::time::sleep(Duration::from_millis(300)).await;
    out.send(enc(
        &ClientMessage::WatchScreenShare {
            sharer_user_id: sharer_id,
        },
        proto,
    )?)?;
    let marks = Arc::new(Marks::default());
    tally.marks.lock().unwrap().push(marks.clone());
    tokio::spawn(read_frames(
        connection,
        Source::Relay,
        tally.clone(),
        marks.clone(),
    ));
    // The edge in force: what stops its session
    let mut on_edge: Option<oneshot::Sender<()>> = None;
    loop {
        match next_message(&mut recv, &mut buf, proto).await? {
            ServerMessage::Ping { timestamp } => {
                out.send(enc(&ClientMessage::Ping { timestamp }, proto)?)?;
            }
            ServerMessage::WatchingScreenShare { .. } => {
                tally.watching.fetch_add(1, Ordering::Relaxed);
            }
            ServerMessage::WatchRefused { .. } | ServerMessage::ScreenShareError { .. } => {
                tally.refused.fetch_add(1, Ordering::Relaxed);
            }
            ServerMessage::WatchAt {
                sharer_user_id,
                edge,
                ..
            } if sharer_user_id == sharer_id => {
                if let Some(stop) = on_edge.take() {
                    let _ = stop.send(());
                    tally.moved.fetch_add(1, Ordering::Relaxed);
                    let last = marks.last_frame.load(Ordering::Relaxed);
                    marks.waiting_since.store(last.max(1), Ordering::Relaxed);
                }
                if let Some(view) = edge {
                    let (stop, stopped) = oneshot::channel();
                    on_edge = Some(stop);
                    tokio::spawn(watch_on_edge(
                        endpoint.clone(),
                        view,
                        tally.clone(),
                        marks.clone(),
                        stopped,
                    ));
                }
            }
            _ => {}
        }
    }
}

/// The room and the shares in it, for a run that starts no sharer of its own: a scout joins
/// the room and reads who in it shares. Its name is below the viewers' (`INDEX_BASE + 10_000`
/// on) for any `--first` under 9,000.
async fn find_shares(args: &Args) -> Result<(u32, Vec<u32>), Error> {
    let c = connect(INDEX_BASE + 1_000 + args.first, &args.server).await?;
    let (proto, mut recv, mut buf) = (c.proto, c.recv, c.buf);
    let mut send = c.send;
    let room = loop {
        if let ServerMessage::ChannelList { channels } =
            next_message(&mut recv, &mut buf, proto).await?
        {
            break channels
                .into_iter()
                .find(|ch| ch.name == ROOM)
                .ok_or("no share_load room: start the run with sharers first")?
                .channel_id;
        }
    };
    let join = ClientMessage::JoinChannel {
        channel_id: room,
        password: None,
    };
    send.write_all(&enc(&join, proto)?).await?;
    loop {
        if let ServerMessage::UserList { channel_id, users } =
            next_message(&mut recv, &mut buf, proto).await?
        {
            if channel_id == room {
                let sharers: Vec<u32> = users
                    .into_iter()
                    .filter(|u| u.is_screen_sharing)
                    .map(|u| u.user_id)
                    .collect();
                if sharers.is_empty() {
                    return Err("nobody shares in the share_load room".into());
                }
                return Ok((room, sharers));
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("crypto provider");
    START.get_or_init(Instant::now);
    let args = Arc::new(parse()?);
    let port: u16 = args.server.rsplit(':').next().ok_or("no port")?.parse()?;
    let tally = Arc::new(Tally::new());
    let arrive = Duration::from_secs_f64(args.viewers as f64 / args.rate);
    let stop = Instant::now() + Duration::from_secs(10) + arrive + Duration::from_secs(args.secs);
    println!(
        "{} viewers of {} shares at {} Mbit/s, {} fps; expected at the viewers {:.0} Mbit/s",
        args.viewers,
        if args.shares == 0 {
            "a run's".to_string()
        } else {
            args.shares.to_string()
        },
        args.mbit,
        args.fps,
        args.viewers as f64 * args.mbit
    );

    let (room, sharers) = if args.shares == 0 {
        find_shares(&args).await?
    } else {
        let (room_tx, room_rx) = watch::channel(0u32);
        let (ids_tx, mut ids_rx) = mpsc::unbounded_channel();
        for k in 0..args.shares {
            let (args, room_tx, room_rx, ids_tx, tally) = (
                args.clone(),
                room_tx.clone(),
                room_rx.clone(),
                ids_tx.clone(),
                tally.clone(),
            );
            tokio::spawn(async move {
                if let Err(e) = sharer(k, args, room_tx, room_rx, ids_tx, tally, stop).await {
                    eprintln!("sharer {k}: {e}");
                }
            });
        }
        let mut sharers = Vec::new();
        while sharers.len() < args.shares {
            sharers.push(ids_rx.recv().await.ok_or("a sharer failed")?);
        }
        let room = *room_rx.borrow();
        (room, sharers)
    };
    tokio::time::sleep(Duration::from_secs(1)).await;

    for i in 0..args.viewers {
        let (theirs, tally) = (args.clone(), tally.clone());
        let sharer_id = sharers[i % sharers.len()];
        tokio::spawn(async move {
            if let Err(e) = viewer(i, theirs, room, sharer_id, tally.clone()).await {
                if tally.lost.fetch_add(1, Ordering::Relaxed) < 3 {
                    eprintln!("viewer {i}: {e}");
                }
            }
        });
        tokio::time::sleep(Duration::from_secs_f64(1.0 / args.rate)).await;
    }

    let cpus = own_cpus();
    let (mut bytes_before, mut frames_before, mut complete_before) = (0, 0, 0);
    let mut cpu_before = relay_stats(args.pid).map_or(0.0, |s| s.1);
    let mut edges_before: Vec<f64> = args
        .edge_pids
        .iter()
        .map(|&p| relay_stats(p).map_or(0.0, |s| s.1))
        .collect();
    let mut own_before = stats_of("self").map_or(0.0, |s| s.1);
    let mut relay_bytes_before = 0;
    let drops_at_start = socket_drops(port);
    let mut edge_drops_at_start: Vec<(u16, u64)> = Vec::new();
    #[derive(Default)]
    struct Second {
        mbit: f64,
        fps: f64,
        complete_fps: f64,
        relay: f64,
        relay_mbit: f64,
        edges: Vec<f64>,
        own: f64,
        rss: u64,
        edges_rss: Vec<u64>,
        own_rss: u64,
    }
    let mut steady: Vec<Second> = Vec::new();
    while Instant::now() < stop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let bytes = tally.bytes.load(Ordering::Relaxed);
        let frames = tally.frames.load(Ordering::Relaxed);
        let complete = tally.complete.load(Ordering::Relaxed);
        let relay_bytes = tally.relay_bytes.load(Ordering::Relaxed);
        let (rss, cpu) = relay_stats(args.pid).unwrap_or((0, cpu_before));
        let edges_now: Vec<(u64, f64)> = args
            .edge_pids
            .iter()
            .zip(&edges_before)
            .map(|(&p, &before)| relay_stats(p).unwrap_or((0, before)))
            .collect();
        let (own_rss, own) = stats_of("self").unwrap_or((0, own_before));
        let watching = tally.watching.load(Ordering::Relaxed);
        let mbit = (bytes - bytes_before) as f64 * 8.0 / 1e6;
        let relay_mbit = (relay_bytes - relay_bytes_before) as f64 * 8.0 / 1e6;
        let fps = (frames - frames_before) as f64 / watching.max(1) as f64;
        let complete_fps = (complete - complete_before) as f64 / watching.max(1) as f64;
        for (_, port) in tally.edges_seen() {
            if !edge_drops_at_start.iter().any(|(p, _)| *p == port) {
                edge_drops_at_start.push((port, socket_drops(port)));
            }
        }
        let edge_cpu: Vec<f64> = edges_now
            .iter()
            .zip(&edges_before)
            .map(|((_, now), before)| (now - before) * 100.0)
            .collect();
        let edges_line = if args.edge_pids.is_empty() {
            String::new()
        } else {
            format!(
                "; on edges {}, moved {}, edges {}",
                tally.on_edges.load(Ordering::Relaxed),
                tally.moved.load(Ordering::Relaxed),
                edges_now
                    .iter()
                    .zip(&edge_cpu)
                    .map(|((rss, _), cpu)| format!("{cpu:.0}% {rss} MiB"))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        println!(
            "watching {watching}, refused {}, lost {}: {mbit:.0} Mbit/s at the viewers, {fps:.1} frames/s each; relay {:.0}% of a core, {rss} MiB, socket drops {}{edges_line}; this {:.0}% of its {cpus} CPUs",
            tally.refused.load(Ordering::Relaxed),
            tally.lost.load(Ordering::Relaxed),
            (cpu - cpu_before) * 100.0,
            socket_drops(port) - drops_at_start,
            (own - own_before) * 100.0 / cpus as f64,
        );
        if watching == args.viewers {
            tally.steady.store(true, Ordering::Relaxed);
            steady.push(Second {
                mbit,
                fps,
                complete_fps,
                relay: (cpu - cpu_before) * 100.0,
                relay_mbit,
                edges: edge_cpu,
                own: (own - own_before) * 100.0,
                rss,
                edges_rss: edges_now.iter().map(|e| e.0).collect(),
                own_rss,
            });
        }
        (bytes_before, frames_before, complete_before, cpu_before) = (bytes, frames, complete, cpu);
        relay_bytes_before = relay_bytes;
        edges_before = edges_now.iter().map(|e| e.1).collect();
        own_before = own;
    }
    // The last second ran past the sharers' end
    steady.pop();
    if steady.is_empty() {
        return Ok(());
    }
    let n = steady.len() as f64;
    let mean = |f: &dyn Fn(&Second) -> f64| steady.iter().map(f).sum::<f64>() / n;
    let (m, f, c) = (mean(&|s| s.mbit), mean(&|s| s.fps), mean(&|s| s.relay));
    println!("| viewers | shares | Mbit/s each | expected Mbit/s | got Mbit/s | frames/s each | relay % of a core | socket drops |");
    println!(
        "| {} | {} | {} | {:.0} | {:.0} | {:.1} | {:.0} | {} |",
        args.viewers,
        sharers.len(),
        args.mbit,
        args.viewers as f64 * args.mbit,
        m,
        f,
        c,
        socket_drops(port) - drops_at_start
    );
    // The rest of what each process cost, and where the frames came from
    let max_of = |f: &dyn Fn(&Second) -> u64| steady.iter().map(f).max().unwrap_or(0);
    let pct = |p: Option<usize>| p.map_or("-".to_string(), |ms| ms.to_string());
    let mut gaps = tally.gaps.lock().unwrap().clone();
    gaps.sort_unstable();
    let gap = |q: f64| {
        gaps.get(((gaps.len() as f64 * q).ceil() as usize).saturating_sub(1))
            .map_or("-".to_string(), |ms| ms.to_string())
    };
    let (got, sent) = tally
        .marks
        .lock()
        .unwrap()
        .iter()
        .filter(|m| m.first_id.load(Ordering::Relaxed) != 0)
        .fold((0u64, 0u64), |(got, sent), m| {
            let span = m.last_id.load(Ordering::Relaxed) - m.first_id.load(Ordering::Relaxed) + 1;
            (
                got + m.got.load(Ordering::Relaxed).min(span as u64),
                sent + span as u64,
            )
        });
    println!(
        "frames complete {:.2}% ({got} of the {sent} sent to the viewers while steady); {:.1}% of {} fps; latency from the relay p50/p95 {}/{} ms, from edges {}/{} ms; \
         relay {:.0}% of a core, {} MiB max, {:.0} Mbit/s to its own viewers; \
         this process {:.0}% of a core, {:.0}% of its {cpus} CPUs, {} MiB max",
        got as f64 * 100.0 / sent.max(1) as f64,
        mean(&|s| s.complete_fps) * 100.0 / args.fps,
        args.fps,
        pct(tally.relay_latency.percentile(50.0)),
        pct(tally.relay_latency.percentile(95.0)),
        pct(tally.edge_latency.percentile(50.0)),
        pct(tally.edge_latency.percentile(95.0)),
        c,
        max_of(&|s| s.rss),
        mean(&|s| s.relay_mbit),
        mean(&|s| s.own),
        mean(&|s| s.own) / cpus as f64,
        max_of(&|s| s.own_rss),
    );
    for (i, pid) in args.edge_pids.iter().enumerate() {
        println!(
            "edge pid {pid}: {:.0}% of a core, {} MiB max",
            mean(&|s| s.edges.get(i).copied().unwrap_or(0.0)),
            max_of(&|s| s.edges_rss.get(i).copied().unwrap_or(0)),
        );
    }
    let secs = Instant::now()
        .duration_since(*START.get().unwrap())
        .as_secs_f64();
    for (slot, port) in tally.edges_seen() {
        let drops_then = edge_drops_at_start
            .iter()
            .find(|(p, _)| *p == port)
            .map_or(0, |d| d.1);
        println!(
            "edge on UDP {port}: {:.0} Mbit/s to viewers over the run, socket drops {}",
            tally.edge_bytes[slot].load(Ordering::Relaxed) as f64 * 8.0 / 1e6 / secs,
            socket_drops(port) - drops_then,
        );
    }
    if !args.edge_pids.is_empty() || tally.on_edges.load(Ordering::Relaxed) > 0 {
        println!(
            "on edges at the end {}, refused by the relay {}, by edges {}, edges not reached {}; moved {} (gap from the last frame to the next p50/p95/max {}/{}/{} ms)",
            tally.on_edges.load(Ordering::Relaxed),
            tally.refused.load(Ordering::Relaxed),
            tally.edge_refused.load(Ordering::Relaxed),
            tally.edge_failed.load(Ordering::Relaxed),
            tally.moved.load(Ordering::Relaxed),
            gap(0.5),
            gap(0.95),
            gaps.last().map_or("-".to_string(), |ms| ms.to_string()),
        );
    }
    Ok(())
}
