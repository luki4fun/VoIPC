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
// Expected at N=30: aggregate send ~1500 pkt/s, aggregate recv ~43500 pkt/s
// (each of the 30 clients receives the other 29 streams). The payload is
// encrypted under a random media key the server never sees (it relays
// encrypted voice verbatim), so a real client in the channel receives
// packets it cannot decode — this measures relay throughput only, and no
// Opus encoder is needed to make them.

#[path = "load_common/mod.rs"]
mod load_common;

use std::sync::atomic::{AtomicU64, Ordering};
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

    let mut args = std::env::args().skip(1);
    let num_clients: usize = args.next().map(|a| a.parse()).transpose()?.unwrap_or(30);
    let server: String = args.next().unwrap_or_else(|| "127.0.0.1:9987".into());
    let seconds: Option<u64> = args.next().map(|a| a.parse()).transpose()?;

    let sent = Arc::new(AtomicU64::new(0));
    let received = Arc::new(AtomicU64::new(0));
    let (channel_tx, channel_rx) = tokio::sync::watch::channel(0u32);

    println!("starting {num_clients} load clients against {server}");
    for i in 0..num_clients {
        let server = server.clone();
        let sent = sent.clone();
        let received = received.clone();
        let channel_tx = channel_tx.clone();
        let channel_rx = channel_rx.clone();
        tokio::spawn(async move {
            if let Err(e) = run_client(i, &server, sent, received, channel_tx, channel_rx).await {
                eprintln!("client {i} failed: {e}");
            }
        });
        // Stagger connects a little to avoid tripping connection rate limits
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Stats printer
    let mut last_sent = 0u64;
    let mut last_recv = 0u64;
    let started = std::time::Instant::now();
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        if seconds.is_some_and(|s| started.elapsed() >= Duration::from_secs(s)) {
            let (s, r) = (
                sent.load(Ordering::Relaxed),
                received.load(Ordering::Relaxed),
            );
            if s == 0 || r == 0 {
                return Err(format!("no voice came back: sent {s}, received {r}").into());
            }
            println!("ok: sent {s}, received {r}");
            return Ok(());
        }
        let s = sent.load(Ordering::Relaxed);
        let r = received.load(Ordering::Relaxed);
        println!(
            "sent {:>6} pkt/s | recv {:>7} pkt/s (fan-out) | totals {s}/{r}",
            s - last_sent,
            r - last_recv
        );
        last_sent = s;
        last_recv = r;
    }
}

async fn run_client(
    index: usize,
    server: &str,
    sent: Arc<AtomicU64>,
    received: Arc<AtomicU64>,
    channel_tx: tokio::sync::watch::Sender<u32>,
    mut channel_rx: tokio::sync::watch::Receiver<u32>,
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

    // ── Channel setup: client 0 creates (or reuses) the load channel ──
    let channel_id = if index == 0 {
        send.write_all(&enc(
            &ClientMessage::CreateChannel {
                name: "LoadTest".into(),
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
                ServerMessage::ChannelCreated { channel } if channel.name == "LoadTest" => {
                    break channel.channel_id
                }
                ServerMessage::ChannelList { channels }
                | ServerMessage::ChannelListMore { channels, .. } => {
                    if let Some(c) = channels.iter().find(|c| c.name == "LoadTest") {
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
        channel_tx.send(id)?;
        id
    } else {
        channel_rx.wait_for(|&id| id != 0).await?;
        *channel_rx.borrow()
    };
    send.write_all(&enc(
        &ClientMessage::JoinChannel {
            channel_id,
            password: None,
        },
        proto,
    )?)
    .await?;

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
        sent.fetch_add(1, Ordering::Relaxed);
    }
}
