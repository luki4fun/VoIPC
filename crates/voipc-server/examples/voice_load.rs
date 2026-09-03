// Headless voice load generator: N clients authenticate, join one channel,
// and each streams a real Opus-encoded tone at 50 packets/sec over UDP while
// counting the packets fanned back out to them.
//
// Run against a local server:
//   cargo run -p voipc-server --release --example voice_load -- 30 127.0.0.1:9987
//
// Expected at N=30: aggregate send ~1500 pkt/s, aggregate recv ~43500 pkt/s
// (each of the 30 clients receives the other 29 streams). A real client in
// the same channel should hear a loud-but-clamped mix of all tones.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use voipc_protocol::codec::{
    decode_server_msg, encode_client_msg, try_decode_frame, APP_VERSION, PROTOCOL_VERSION,
};
use voipc_protocol::messages::{ClientMessage, ServerMessage};
use voipc_protocol::voice::{VoicePacket, OPUS_FRAME_SIZE, OPUS_SAMPLE_RATE};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("crypto provider");

    let mut args = std::env::args().skip(1);
    let num_clients: usize = args.next().map(|a| a.parse()).transpose()?.unwrap_or(30);
    let server: String = args.next().unwrap_or_else(|| "127.0.0.1:9987".into());

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
            if let Err(e) =
                run_client(i, &server, sent, received, channel_tx, channel_rx).await
            {
                eprintln!("client {i} failed: {e}");
            }
        });
        // Stagger connects a little to avoid tripping connection rate limits
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Stats printer
    let mut last_sent = 0u64;
    let mut last_recv = 0u64;
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
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
    // ── TCP + TLS + auth ──
    // The server caps connections per IP (DoS guard), so spread the load
    // clients across 127.0.0.0/8 source addresses (4 clients per IP). The
    // UDP socket must bind the same IP — the server validates that the UDP
    // source IP matches the TCP peer IP.
    let server_addr: std::net::SocketAddr = tokio::net::lookup_host(server)
        .await?
        .next()
        .ok_or("cannot resolve server")?;
    let local_ip = std::net::IpAddr::from(std::net::Ipv4Addr::new(
        127,
        0,
        (index / 4 / 250) as u8,
        2 + (index / 4 % 250) as u8,
    ));
    let tcp_socket = tokio::net::TcpSocket::new_v4()?;
    tcp_socket.bind(std::net::SocketAddr::new(local_ip, 0))?;
    let tcp = tcp_socket.connect(server_addr).await?;
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertVerifier))
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let server_name = rustls::pki_types::ServerName::try_from("localhost".to_string())?;
    let mut tls = connector.connect(server_name, tcp).await?;

    let auth = ClientMessage::Authenticate {
        username: format!("load{index}"),
        protocol_version: PROTOCOL_VERSION,
        app_version: APP_VERSION.to_string(),
        identity_key: None,
        prekey_bundle: None,
    };
    tls.write_all(&encode_client_msg(&auth)?).await?;

    let mut buf = bytes::BytesMut::with_capacity(8192);
    let (session_id, udp_token) = loop {
        match next_message(&mut tls, &mut buf).await? {
            ServerMessage::Authenticated {
                session_id,
                udp_token,
                ..
            } => break (session_id, udp_token),
            ServerMessage::AuthError { reason } => return Err(reason.into()),
            _ => {}
        }
    };

    // ── Channel setup: client 0 creates (or reuses) the load channel ──
    let channel_id = if index == 0 {
        tls.write_all(&encode_client_msg(&ClientMessage::CreateChannel {
            name: "LoadTest".into(),
            password: None,
        })?)
        .await?;
        let mut existing: Option<u32> = None;
        let id = loop {
            match next_message(&mut tls, &mut buf).await? {
                ServerMessage::ChannelCreated { channel } if channel.name == "LoadTest" => {
                    break channel.channel_id
                }
                ServerMessage::ChannelList { channels } => {
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
    tls.write_all(&encode_client_msg(&ClientMessage::JoinChannel {
        channel_id,
        password: None,
    })?)
    .await?;

    // Keep the TCP session alive: answer server keepalive pings
    tokio::spawn(async move {
        loop {
            match next_message(&mut tls, &mut buf).await {
                Ok(ServerMessage::Ping { timestamp }) => {
                    let msg = ClientMessage::Ping { timestamp };
                    if let Ok(data) = encode_client_msg(&msg) {
                        if tls.write_all(&data).await.is_err() {
                            return;
                        }
                    }
                }
                Ok(_) => {}
                Err(_) => return,
            }
        }
    });

    // ── UDP voice ──
    let bind_udp = || async {
        let udp = tokio::net::UdpSocket::bind(std::net::SocketAddr::new(local_ip, 0)).await?;
        udp.connect(server_addr).await?;
        udp.send(&VoicePacket::ping(session_id, udp_token, 0).to_bytes())
            .await?;
        Ok::<_, std::io::Error>(Arc::new(udp))
    };
    let spawn_recv = |udp: Arc<tokio::net::UdpSocket>, received: Arc<AtomicU64>| {
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok(_n) = udp.recv(&mut buf).await {
                received.fetch_add(1, Ordering::Relaxed);
            }
        })
    };

    // Set VOICE_LOAD_REBIND_SECS to make each client move to a fresh UDP
    // source port periodically — simulates NAT mapping expiry to exercise
    // the server's validated-rebind path.
    let rebind_every: Option<Duration> = std::env::var("VOICE_LOAD_REBIND_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .map(Duration::from_secs);

    {
        let mut udp = bind_udp().await?;
        let mut recv_task = spawn_recv(udp.clone(), received.clone());
        let mut last_rebind = tokio::time::Instant::now();

        // Sender: 440Hz + per-client offset tone, Opus-encoded, 50 pkt/s
        let mut encoder = voipc_audio::encoder::Encoder::new()?;
        let mut pcm = [0.0f32; OPUS_FRAME_SIZE];
        let freq = 220.0 + 20.0 * index as f32;
        let mut phase = 0.0f32;
        let step = 2.0 * std::f32::consts::PI * freq / OPUS_SAMPLE_RATE as f32;
        let mut sequence: u32 = 0;
        let mut interval = tokio::time::interval(Duration::from_millis(20));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            if let Some(period) = rebind_every {
                if last_rebind.elapsed() >= period {
                    last_rebind = tokio::time::Instant::now();
                    recv_task.abort();
                    udp = bind_udp().await?;
                    recv_task = spawn_recv(udp.clone(), received.clone());
                    println!("client {index}: rebound UDP to {}", udp.local_addr()?);
                }
            }
            for s in pcm.iter_mut() {
                *s = 0.2 * phase.sin();
                phase += step;
            }
            phase %= 2.0 * std::f32::consts::PI;
            let opus = encoder.encode(&pcm)?;
            let packet = VoicePacket::voice(session_id, udp_token, sequence, opus);
            sequence = sequence.wrapping_add(1);
            udp.send(&packet.to_bytes()).await?;
            sent.fetch_add(1, Ordering::Relaxed);
        }
    }
}

async fn next_message(
    tls: &mut tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    buf: &mut bytes::BytesMut,
) -> Result<ServerMessage, Box<dyn std::error::Error + Send + Sync>> {
    loop {
        if let Some(payload) = try_decode_frame(buf)? {
            return Ok(decode_server_msg(&payload)?);
        }
        if tls.read_buf(buf).await? == 0 {
            return Err("server closed connection".into());
        }
    }
}

#[derive(Debug)]
struct NoCertVerifier;

impl rustls::client::danger::ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
        ]
    }
}
