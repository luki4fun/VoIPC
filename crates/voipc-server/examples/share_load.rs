// How many screen-share viewers one relay carries. K sharers send synthetic frames at a set
// rate (encrypted-type fragments of zeros, which the relay relays without reading, one QUIC
// stream a frame as the apps send them, a keyframe every 4 s); V viewers split over them
// watch, and each second the run says what reached them and what it cost the relay.
//
//   share_load <viewers> <host:port> <relay-pid> [--shares K] [--mbit M] [--fps F] [--secs S] [--rate R]
//
// Defaults: 1 share, 7.5 Mbit/s (HD), 30 fps, 30 s, viewers arriving 100 a second. Give the
// relay `[media] share_viewers`, `video_egress_mbit` and `voice_room` above what the run asks
// (all sharers and viewers stand in one room), and `max_users` above V + K.

#[path = "load_common/mod.rs"]
mod load_common;

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, watch};

use load_common::{connect, enc, next_message, Connected, Error};
use voipc_protocol::messages::{ClientMessage, ServerMessage};
use voipc_protocol::types::{ProximityMode, VideoCodec};
use voipc_protocol::video::{RecordReader, VideoPacket, MAX_ENCRYPTED_VIDEO_PAYLOAD_SIZE};

/// Names apart from the other load tools'.
const INDEX_BASE: usize = 300_000;
const ROOM: &str = "ShareLoad";

struct Args {
    viewers: usize,
    server: String,
    pid: u32,
    shares: usize,
    mbit: f64,
    fps: f64,
    secs: u64,
    rate: f64,
}

#[derive(Default)]
struct Tally {
    watching: AtomicUsize,
    refused: AtomicUsize,
    lost: AtomicUsize,
    bytes: AtomicU64,
    frames: AtomicU64,
    sent_frames: AtomicU64,
}

fn parse() -> Result<Args, Error> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let usage = "share_load <viewers> <host:port> <relay-pid> [--shares K] [--mbit M] [--fps F] [--secs S] [--rate R]";
    let [viewers, server, pid, rest @ ..] = a.as_slice() else {
        return Err(usage.into());
    };
    let flag = |name: &str, default: f64| -> Result<f64, Error> {
        match rest.iter().position(|x| x == name) {
            Some(i) => Ok(rest.get(i + 1).ok_or(usage)?.parse()?),
            None => Ok(default),
        }
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
    })
}

/// `(RSS in MiB, CPU seconds)` of a process, from /proc.
fn relay_stats(pid: u32) -> Option<(u64, f64)> {
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
    // What the relay says: pings answered, the room's id passed on
    let pings = out.clone();
    tokio::spawn(async move {
        while let Ok(msg) = next_message(&mut recv, &mut buf, proto).await {
            match msg {
                ServerMessage::Ping { timestamp } => {
                    let _ = enc(&ClientMessage::Ping { timestamp }, proto).map(|d| pings.send(d));
                }
                ServerMessage::ChannelCreated { channel } if channel.name == ROOM => {
                    room_tx.send_replace(channel.channel_id);
                }
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
    let started = Instant::now();
    let mut frame_id = 0u32;
    while Instant::now() < stop {
        tick.tick().await;
        frame_id += 1;
        let key = frame_id % keyframe_every == 1;
        let ts = started.elapsed().as_millis() as u32;
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

/// A viewer: joins the room, watches its sharer, and reads every frame stream.
async fn viewer(
    i: usize,
    args: Arc<Args>,
    room: u32,
    sharer_id: u32,
    tally: Arc<Tally>,
) -> Result<(), Error> {
    let c: Connected = connect(INDEX_BASE + 10_000 + i, &args.server).await?;
    let proto = c.proto;
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
    let frames = tally.clone();
    tokio::spawn(async move {
        let mut chunk = vec![0u8; 16 * 1024];
        while let Ok(mut stream) = connection.accept_uni().await {
            let mut reader = RecordReader::default();
            while let Ok(Some(n)) = stream.read(&mut chunk).await {
                frames.bytes.fetch_add(n as u64, Ordering::Relaxed);
                reader.push(&chunk[..n]);
            }
            frames.frames.fetch_add(1, Ordering::Relaxed);
        }
    });
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
            _ => {}
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("crypto provider");
    let args = Arc::new(parse()?);
    let port: u16 = args.server.rsplit(':').next().ok_or("no port")?.parse()?;
    let tally = Arc::new(Tally::default());
    let arrive = Duration::from_secs_f64(args.viewers as f64 / args.rate);
    let stop = Instant::now() + Duration::from_secs(10) + arrive + Duration::from_secs(args.secs);
    println!(
        "{} viewers of {} shares at {} Mbit/s, {} fps; expected at the viewers {:.0} Mbit/s",
        args.viewers,
        args.shares,
        args.mbit,
        args.fps,
        args.viewers as f64 * args.mbit
    );

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

    let (mut bytes_before, mut frames_before) = (0, 0);
    let mut cpu_before = relay_stats(args.pid).map_or(0.0, |s| s.1);
    let drops_at_start = socket_drops(port);
    let mut steady = Vec::new();
    while Instant::now() < stop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let bytes = tally.bytes.load(Ordering::Relaxed);
        let frames = tally.frames.load(Ordering::Relaxed);
        let (rss, cpu) = relay_stats(args.pid).unwrap_or((0, cpu_before));
        let watching = tally.watching.load(Ordering::Relaxed);
        let mbit = (bytes - bytes_before) as f64 * 8.0 / 1e6;
        let fps = (frames - frames_before) as f64 / watching.max(1) as f64;
        println!(
            "watching {watching}, refused {}, lost {}: {mbit:.0} Mbit/s at the viewers, {fps:.1} frames/s each; relay {:.0}% of a core, {rss} MiB, socket drops {}",
            tally.refused.load(Ordering::Relaxed),
            tally.lost.load(Ordering::Relaxed),
            (cpu - cpu_before) * 100.0,
            socket_drops(port) - drops_at_start,
        );
        if watching == args.viewers {
            steady.push((mbit, fps, (cpu - cpu_before) * 100.0));
        }
        (bytes_before, frames_before, cpu_before) = (bytes, frames, cpu);
    }
    if !steady.is_empty() {
        let n = steady.len() as f64;
        let (m, f, c) = steady
            .iter()
            .fold((0.0, 0.0, 0.0), |a, s| (a.0 + s.0, a.1 + s.1, a.2 + s.2));
        println!("| viewers | shares | Mbit/s each | expected Mbit/s | got Mbit/s | frames/s each | relay % of a core | socket drops |");
        println!(
            "| {} | {} | {} | {:.0} | {:.0} | {:.1} | {:.0} | {} |",
            args.viewers,
            args.shares,
            args.mbit,
            args.viewers as f64 * args.mbit,
            m / n,
            f / n,
            c / n,
            socket_drops(port) - drops_at_start
        );
    }
    Ok(())
}
