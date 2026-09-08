// Headless voice load generator: N clients connect over QUIC, join one
// channel, and each streams a real Opus-encoded tone at 50 packets/sec as
// media datagrams while counting the packets fanned back out to them.
//
// Run against a local server:
//   cargo run -p voipc-server --release --example voice_load -- 30 127.0.0.1:9987
//
// Expected at N=30: aggregate send ~1500 pkt/s, aggregate recv ~43500 pkt/s
// (each of the 30 clients receives the other 29 streams). The tone is
// encrypted under a random media key the server never sees (it relays
// encrypted voice verbatim), so a real client in the channel receives
// packets it cannot decode — this measures relay throughput only.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt};
use wtransport::config::{DnsLookupFuture, DnsResolver};
use wtransport::{ClientConfig, Endpoint};

use voipc_protocol::codec::{
    decode_server_msg, encode_client_msg, try_decode_frame, APP_VERSION, PROTOCOL_VERSION,
};
use voipc_protocol::messages::{ClientMessage, ServerMessage};
use voipc_protocol::voice::{VoicePacket, OPUS_FRAME_SIZE, OPUS_SAMPLE_RATE};

/// Server name that makes the server present its operator certificate
/// (`crates/voipc-server/src/web.rs::NATIVE_SNI`).
const NATIVE_SNI: &str = "voipc-native";

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
    // ── QUIC + auth ──
    // The server caps connections per IP (DoS guard), so spread the load
    // clients across 127.0.0.0/8 source addresses (4 clients per IP).
    let server_addr: SocketAddr = tokio::net::lookup_host(server)
        .await?
        .next()
        .ok_or("cannot resolve server")?;
    let local_ip = std::net::IpAddr::from(std::net::Ipv4Addr::new(
        127,
        0,
        (index / 4 / 250) as u8,
        2 + (index / 4 % 250) as u8,
    ));
    let mut tls = rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertVerifier))
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let config = ClientConfig::builder()
        .with_bind_address(SocketAddr::new(local_ip, 0))
        .with_custom_tls(tls)
        .keep_alive_interval(Some(Duration::from_secs(10)))
        .dns_resolver(Fixed(server_addr))
        .build();
    let endpoint = Endpoint::client(config)?;
    let connection = endpoint
        .connect(format!("https://{NATIVE_SNI}:{}/voipc", server_addr.port()))
        .await?;
    let (mut send, mut recv) = connection.open_bi().await?.await?;

    let auth = ClientMessage::Authenticate {
        username: format!("load{index}"),
        protocol_version: PROTOCOL_VERSION,
        app_version: APP_VERSION.to_string(),
        identity_key: None,
        prekey_bundle: None,
    };
    send.write_all(&encode_client_msg(&auth)?).await?;

    let mut buf = bytes::BytesMut::with_capacity(8192);
    let session_id = loop {
        match next_message(&mut recv, &mut buf).await? {
            ServerMessage::Authenticated { session_id, .. } => break session_id,
            ServerMessage::AuthError { reason } => return Err(reason.into()),
            _ => {}
        }
    };

    // ── Channel setup: client 0 creates (or reuses) the load channel ──
    let channel_id = if index == 0 {
        send.write_all(&encode_client_msg(&ClientMessage::CreateChannel {
            name: "LoadTest".into(),
            password: None,
            proximity: Default::default(),
        })?)
        .await?;
        let mut existing: Option<u32> = None;
        let id = loop {
            match next_message(&mut recv, &mut buf).await? {
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
    send.write_all(&encode_client_msg(&ClientMessage::JoinChannel {
        channel_id,
        password: None,
    })?)
    .await?;

    // Keep the control session alive: answer server keepalive pings
    tokio::spawn(async move {
        loop {
            match next_message(&mut recv, &mut buf).await {
                Ok(ServerMessage::Ping { timestamp }) => {
                    let msg = ClientMessage::Ping { timestamp };
                    if let Ok(data) = encode_client_msg(&msg) {
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

    // ── Voice: 440Hz + per-client offset tone, Opus-encoded, encrypted, 50 pkt/s ──
    let key = voipc_crypto::MediaKey::generate(channel_id, 1)?;
    let aad = voipc_crypto::build_aad(channel_id, 0x05);
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
        for s in pcm.iter_mut() {
            *s = 0.2 * phase.sin();
            phase += step;
        }
        phase %= 2.0 * std::f32::consts::PI;
        let opus = encoder.encode(&pcm)?;
        let encrypted = voipc_crypto::media_encrypt(&key, session_id, sequence, 0, &aad, &opus)?;
        let packet = VoicePacket::encrypted_voice(session_id, sequence, key.key_id, encrypted);
        sequence = sequence.wrapping_add(1);
        connection.send_datagram(packet.to_bytes())?;
        sent.fetch_add(1, Ordering::Relaxed);
    }
}

async fn next_message<R: AsyncRead + Unpin>(
    recv: &mut R,
    buf: &mut bytes::BytesMut,
) -> Result<ServerMessage, Box<dyn std::error::Error + Send + Sync>> {
    loop {
        if let Some(payload) = try_decode_frame(buf)? {
            return Ok(decode_server_msg(&payload)?);
        }
        if recv.read_buf(buf).await? == 0 {
            return Err("server closed connection".into());
        }
    }
}

/// Resolves any host name to the server address, so the URL can carry
/// `NATIVE_SNI` as the server name while dialing an IP.
#[derive(Debug)]
struct Fixed(SocketAddr);

impl DnsResolver for Fixed {
    fn resolve(&self, _host: &str) -> Pin<Box<dyn DnsLookupFuture>> {
        let addr = self.0;
        Box::pin(async move { Ok(Some(addr)) })
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
