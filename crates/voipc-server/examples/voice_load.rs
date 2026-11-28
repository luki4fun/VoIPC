// Headless voice load generator: N clients connect over QUIC, join one
// channel, and each streams voice-sized packets at 50 packets/sec as media
// datagrams while counting the packets fanned back out to them.
//
// Run against a local server:
//   cargo run -p voipc-server --release --example voice_load -- 30 127.0.0.1:9987
//
// A third argument ends the run after that many seconds, failing unless voice
// came back: the old-relays check (a relay of an older protocol is spoken to
// in its own, as the apps do since 1.6: `voipc_protocol::compat`).
//
// `--rooms R` spreads the clients over R channels, `--speakers S` lets only
// the first S of each room talk (0, the default: everyone). Once every client
// is in, each second's line and the end add the loss: what came back against
// each speaker's packets times the others in its room. The scale gate:
//   voice_load 1000 127.0.0.1:9987 60 --rooms 20 --speakers 3
//
// Expected at N=30: aggregate send ~1500 pkt/s, aggregate recv ~43500 pkt/s
// (each of the 30 clients receives the other 29 streams). The payload is
// encrypted under a random media key the server never sees (it relays
// encrypted voice verbatim), so a real client in the channel receives
// packets it cannot decode — this measures relay throughput only, and no
// Opus encoder is needed to make them.

#[path = "load_common/mod.rs"]
mod load_common;

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use load_common::{connect, enc, next_message, Connected};
use voipc_protocol::messages::{ClientMessage, ServerMessage};
use voipc_protocol::voice::VoicePacket;

/// Names of its own, so it can run beside `community_load`.
const COMMUNITY_LOAD_INDEXES: usize = 100_000;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("crypto provider");

    let mut positional = Vec::new();
    let (mut rooms, mut speakers) = (1usize, 0usize);
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--rooms" => rooms = args.next().ok_or("--rooms N")?.parse()?,
            "--speakers" => speakers = args.next().ok_or("--speakers N")?.parse()?,
            _ => positional.push(a),
        }
    }
    let mut positional = positional.into_iter();
    let num_clients: usize = positional
        .next()
        .map(|a| a.parse())
        .transpose()?
        .unwrap_or(30);
    let server: String = positional.next().unwrap_or_else(|| "127.0.0.1:9987".into());
    let seconds: Option<u64> = positional.next().map(|a| a.parse()).transpose()?;
    let per_room = num_clients.div_ceil(rooms.max(1));
    let rooms: Vec<Arc<Room>> = (0..num_clients.div_ceil(per_room))
        .map(|_| Arc::new(Room::default()))
        .collect();

    let received = Arc::new(AtomicU64::new(0));
    // Clients in their room, or failed before it: the loss window opens when all are one or the other
    let settled = Arc::new(AtomicUsize::new(0));

    let begun = std::time::Instant::now();
    println!(
        "starting {num_clients} load clients against {server}: {} room(s) of {per_room}, {} speaking in each",
        rooms.len(),
        if speakers == 0 { "all".to_string() } else { speakers.to_string() }
    );
    for i in 0..num_clients {
        let server = server.clone();
        let received = received.clone();
        let settled = settled.clone();
        let room = rooms[i / per_room].clone();
        let (number, seat) = (i / per_room, i % per_room);
        let speaks = speakers == 0 || seat < speakers;
        tokio::spawn(async move {
            let in_room = std::sync::atomic::AtomicBool::new(false);
            if let Err(e) = run_client(
                i, &server, number, seat, speaks, &room, received, &settled, &in_room,
            )
            .await
            {
                eprintln!("client {i} failed: {e}");
                if !in_room.load(Ordering::Relaxed) {
                    settled.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        // Stagger connects a little to avoid tripping connection rate limits
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // What came back, and what should have: each speaker's packets reach the others in its room
    let totals = || {
        let sent: u64 = rooms.iter().map(|r| r.sent.load(Ordering::Relaxed)).sum();
        let expected: u64 = rooms
            .iter()
            .map(|r| {
                let others = r.joined.load(Ordering::Relaxed).saturating_sub(1) as u64;
                r.sent.load(Ordering::Relaxed) * others
            })
            .sum();
        (sent, received.load(Ordering::Relaxed), expected)
    };
    let loss = |got: u64, want: u64| {
        if want == 0 {
            0.0
        } else {
            100.0 * (1.0 - got as f64 / want as f64)
        }
    };

    // Stats printer
    let (mut last_sent, mut last_recv, mut last_want) = (0u64, 0u64, 0u64);
    let mut window: Option<(u64, u64)> = None;
    let started = std::time::Instant::now();
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let (s, r, want) = totals();
        // Its first second still holds joins, so a line's loss starts with the next
        let counting = window.is_some();
        if window.is_none() && settled.load(Ordering::Relaxed) >= num_clients {
            window = Some((r, want));
            println!(
                "all {num_clients} settled at {:.1} s: loss counted from here",
                begun.elapsed().as_secs_f64()
            );
        }
        if seconds.is_some_and(|secs| started.elapsed() >= Duration::from_secs(secs)) {
            if s == 0 || r == 0 {
                return Err(format!("no voice came back: sent {s}, received {r}").into());
            }
            match window {
                Some((r0, w0)) => println!(
                    "ok: sent {s}, received {r}; since all settled {} of {} expected, loss {:.3}%",
                    r - r0,
                    want - w0,
                    loss(r - r0, want - w0)
                ),
                None => {
                    println!("ok: sent {s}, received {r}; not everyone settled, no loss counted")
                }
            }
            return Ok(());
        }
        let lost = if counting {
            format!(" | loss {:.2}%", loss(r - last_recv, want - last_want))
        } else {
            String::new()
        };
        println!(
            "sent {:>6} pkt/s | recv {:>7} pkt/s (fan-out){lost} | totals {s}/{r}",
            s - last_sent,
            r - last_recv
        );
        (last_sent, last_recv, last_want) = (s, r, want);
    }
}

/// One channel's clients: its id once its first client has it, who is in, and what they sent.
#[derive(Default)]
struct Room {
    id: tokio::sync::OnceCell<u32>,
    ready: tokio::sync::Notify,
    joined: AtomicUsize,
    sent: AtomicU64,
}

#[allow(clippy::too_many_arguments)]
async fn run_client(
    index: usize,
    server: &str,
    number: usize,
    seat: usize,
    speaks: bool,
    room: &Room,
    received: Arc<AtomicU64>,
    settled: &AtomicUsize,
    in_room: &std::sync::atomic::AtomicBool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // ── QUIC + auth ──
    let Connected {
        endpoint: _endpoint,
        connection,
        mut send,
        mut recv,
        mut buf,
        session_id,
        proto,
        ..
    } = connect(index + COMMUNITY_LOAD_INDEXES, server).await?;

    // ── Channel setup: each room's first client creates (or reuses) its channel ──
    // Room 0 keeps the one name it always had, so older runs' channel is reused
    let name = match number {
        0 => "LoadTest".to_string(),
        n => format!("LoadTest{n}"),
    };
    let channel_id = if seat == 0 {
        send.write_all(&enc(
            &ClientMessage::CreateChannel {
                name: name.clone(),
                password: None,
                proximity: Default::default(),
                anonymous: false,
                text: false,
            },
            proto,
        )?)
        .await?;
        let mut existing: Option<u32> = None;
        let id = loop {
            match next_message(&mut recv, &mut buf, proto).await? {
                ServerMessage::ChannelCreated { channel } if channel.name == name => {
                    break channel.channel_id
                }
                ServerMessage::ChannelList { channels }
                | ServerMessage::ChannelListMore { channels, .. } => {
                    if let Some(c) = channels.iter().find(|c| c.name == name) {
                        existing = Some(c.channel_id);
                    }
                }
                // Creation fails when the channel survived a previous run — reuse it
                ServerMessage::ChannelError { reason } => match existing {
                    Some(id) => break id,
                    None => return Err(reason.into()),
                },
                _ => {}
            }
        };
        let _ = room.id.set(id);
        room.ready.notify_waiters();
        id
    } else {
        loop {
            let ready = room.ready.notified();
            if let Some(&id) = room.id.get() {
                break id;
            }
            ready.await;
        }
    };
    send.write_all(&enc(
        &ClientMessage::JoinChannel {
            channel_id,
            password: None,
        },
        proto,
    )?)
    .await?;
    // In once the relay sends the room's list
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match next_message(&mut recv, &mut buf, proto).await? {
                ServerMessage::UserList { channel_id: c, .. } if c == channel_id => {
                    return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
                }
                ServerMessage::ChannelError { reason } => return Err(reason.into()),
                _ => {}
            }
        }
    })
    .await
    .map_err(|_| "no answer to the join in 30 s")??;
    room.joined.fetch_add(1, Ordering::Relaxed);
    in_room.store(true, Ordering::Relaxed);
    settled.fetch_add(1, Ordering::Relaxed);

    // Keep the control session alive: answer server keepalive pings
    tokio::spawn(async move {
        loop {
            match next_message(&mut recv, &mut buf, proto).await {
                Ok(ServerMessage::Ping { timestamp }) => {
                    let msg = ClientMessage::Ping { timestamp };
                    if let Ok(data) = enc(&msg, proto) {
                        if send.write_all(&data).await.is_err() {
                            return;
                        }
                    }
                }
                Ok(_) => {}
                Err(_) => return,
            }
        }
    });

    // Count everything fanned out to us
    {
        let connection = connection.clone();
        let received = received.clone();
        tokio::spawn(async move {
            while connection.receive_datagram().await.is_ok() {
                received.fetch_add(1, Ordering::Relaxed);
            }
        });
    }

    if !speaks {
        std::future::pending::<()>().await;
    }
    // ── Voice: one 20 ms Opus frame's worth of bytes, encrypted, 50 pkt/s ──
    let key = voipc_crypto::MediaKey::generate(channel_id, 1, index as u32)?;
    // Each simulated client is its own speaker, so each picks its own nonce
    // prefix exactly as a real one does.
    let stream_id = 0x5EED_0000u32 | index as u32;
    let aad = voipc_crypto::build_aad(channel_id, 0x05, session_id);
    // 120 bytes: a 20 ms frame at the client's 48 kbps
    let opus = [index as u8; 120];
    let mut sequence: u32 = 0;
    let mut interval = tokio::time::interval(Duration::from_millis(20));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        let encrypted = voipc_crypto::media_encrypt(&key, stream_id, sequence, 0, &aad, &opus)?;
        let packet =
            VoicePacket::encrypted_voice(session_id, sequence, key.key_id, stream_id, encrypted);
        sequence = sequence.wrapping_add(1);
        connection.send_datagram(packet.to_bytes())?;
        room.sent.fetch_add(1, Ordering::Relaxed);
    }
}
