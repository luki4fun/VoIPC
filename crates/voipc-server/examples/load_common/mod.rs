// What the load generators share: a native client's connection, spread over
// loopback addresses, and framing in the relay's own protocol.

// Each example uses a part of this.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt};
use wtransport::config::{DnsLookupFuture, DnsResolver};
use wtransport::{ClientConfig, Connection, Endpoint, RecvStream, SendStream};

use voipc_protocol::codec::{try_decode_frame, APP_VERSION, PROTOCOL_VERSION};
use voipc_protocol::compat::{
    decode_server_msg_from, encode_client_msg_for, OLDEST_RELAY_PROTOCOL,
};
use voipc_protocol::messages::{
    AuthContinue, AuthStep, ClientMessage, ServerMessage, REFUSED_VERSION,
};
use voipc_protocol::types::{AccountStart, PreKeyBundleData, SessionId, UserId};

pub type Error = Box<dyn std::error::Error + Send + Sync>;

/// Server name that makes the server present its operator certificate
/// (`crates/voipc-server/src/web.rs::NATIVE_SNI`).
const NATIVE_SNI: &str = "voipc-native";

pub struct Connected {
    /// Holds the socket open for the connection.
    pub endpoint: Arc<Endpoint<wtransport::endpoint::endpoint_side::Client>>,
    pub connection: Connection,
    pub send: SendStream,
    pub recv: RecvStream,
    pub buf: bytes::BytesMut,
    pub user_id: UserId,
    pub session_id: SessionId,
    pub proto: u32,
}

/// Connects and signs in as guest `load<index>`.
pub async fn connect(index: usize, server: &str) -> Result<Connected, Error> {
    connect_with(index, server, None).await
}

/// `connect`, with the keys a writer on the live path hands out: `(identity, bundle)`.
pub async fn connect_with(
    index: usize,
    server: &str,
    keys: Option<(Vec<u8>, PreKeyBundleData)>,
) -> Result<Connected, Error> {
    // quinn's log lines (its connection drivers start inside this) name the client
    use tracing::Instrument;
    let (identity, bundle) = keys.map_or((None, None), |(i, b)| (Some(i), Some(b)));
    connect_inner(index, server, None, identity, bundle, false)
        .instrument(tracing::info_span!("client", index))
        .await
}

/// Connects as guest `name` (with its tag) holding identity key `identity` and no pre-key
/// bundle, as a client of the group key: its seat is a pair that key endorsed.
pub async fn connect_named(
    index: usize,
    server: &str,
    name: &str,
    identity: Vec<u8>,
) -> Result<Connected, Error> {
    use tracing::Instrument;
    connect_inner(index, server, Some(name), Some(identity), None, false)
        .instrument(tracing::info_span!("client", index))
        .await
}

/// Signs in as seeded account `acct<index>` with its remembered device (`load_device`), as an
/// app does after a restart: the key, then the vault step answered with the account's keys.
/// A failed sign-in is tried again as the app's reconnect does (`reconnectDelay`, after the
/// first): doubling from 1 s to 10 s, spread over half to one and a half times that. Each try
/// counts in `BUSY_RETRIES` when the relay said it was busy, else in `OTHER_RETRIES`.
pub async fn connect_account(index: usize, server: &str) -> Result<Connected, Error> {
    use tracing::Instrument;
    let started = std::time::Instant::now();
    for attempt in 1u32.. {
        match connect_inner(index, server, None, None, None, true)
            .instrument(tracing::info_span!("client", index))
            .await
        {
            Ok(c) => return Ok(c),
            Err(e) if started.elapsed() < Duration::from_secs(300) => {
                let count = if e.to_string().contains("busy") {
                    &BUSY_RETRIES
                } else {
                    &OTHER_RETRIES
                };
                if count.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 3
                    && !e.to_string().contains("busy")
                {
                    eprintln!("client {index} tries again: {e}");
                }
                let base = (1000u64 << (attempt - 1).min(4)).min(10_000) as f64;
                let wait = base * (0.5 + rand::random::<f64>());
                tokio::time::sleep(Duration::from_millis(wait as u64)).await;
            }
            Err(e) => return Err(e),
        }
    }
    unreachable!()
}

/// Sign-ins `connect_account` tried again after the relay said it was busy, and after anything else.
pub static BUSY_RETRIES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
pub static OTHER_RETRIES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// Seeded account `acct<index>`'s device: its id, its key (PKCS#8 v2) and the public key, all
/// from the index, so seeding and signing in share no file.
pub fn load_device(index: usize) -> ([u8; 16], Vec<u8>, Vec<u8>) {
    use ring::signature::KeyPair;
    let h = ring::digest::digest(
        &ring::digest::SHA256,
        format!("voipc-load-device {index}").as_bytes(),
    );
    let seed: [u8; 32] = h.as_ref().try_into().expect("32 bytes");
    let public = ring::signature::Ed25519KeyPair::from_seed_unchecked(&seed)
        .expect("any seed")
        .public_key()
        .as_ref()
        .to_vec();
    // ring's own v2 template: the seed, then the public key
    let mut pkcs8 = hex_bytes("3053020101300506032b657004220420");
    pkcs8.extend_from_slice(&seed);
    pkcs8.extend_from_slice(&hex_bytes("a123032100"));
    pkcs8.extend_from_slice(&public);
    (seed[..16].try_into().expect("16 bytes"), pkcs8, public)
}

fn hex_bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

/// A seeded account's keys as the relay stores them: sized right, never used for a session.
fn account_keys(index: usize) -> (Vec<u8>, PreKeyBundleData) {
    let mut identity = vec![5u8];
    identity.extend_from_slice(
        ring::digest::digest(
            &ring::digest::SHA256,
            format!("voipc-load-identity {index}").as_bytes(),
        )
        .as_ref(),
    );
    let bundle = PreKeyBundleData {
        registration_id: 1,
        device_id: 1,
        identity_key: identity.clone(),
        signed_prekey_id: 1,
        signed_prekey: vec![5; 33],
        signed_prekey_signature: vec![0; 64],
        prekeys: Vec::new(),
        kyber_prekey_id: 1,
        kyber_prekey: vec![8; 1569],
        kyber_prekey_signature: vec![0; 64],
    };
    (identity, bundle)
}

async fn connect_inner(
    index: usize,
    server: &str,
    name: Option<&str>,
    identity_key: Option<Vec<u8>>,
    prekey_bundle: Option<PreKeyBundleData>,
    device: bool,
) -> Result<Connected, Error> {
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
    let endpoint = shared_endpoint(server_addr, local_ip)?;
    // At our protocol first; a relay of an older one names its own
    let mut proto = PROTOCOL_VERSION;
    'attempt: loop {
        let connection = endpoint.connect(native_url(server_addr)).await?;
        let (mut send, mut recv) = connection.open_bi().await?.await?;
        let (device_id, pkcs8, _) = load_device(index);
        let auth = ClientMessage::Authenticate {
            // With a tag: a relay with accounts wants one on a guest's name
            username: match name {
                Some(n) => n.to_string(),
                None if device => format!("acct{index}"),
                None => format!("load{index}#0001"),
            },
            protocol_version: proto,
            app_version: APP_VERSION.to_string(),
            identity_key: identity_key.clone(),
            prekey_bundle: prekey_bundle.clone(),
            account: device.then(|| AccountStart::DeviceKey {
                device_id: device_id.to_vec(),
            }),
        };
        send.write_all(&enc(&auth, proto)?).await?;
        let mut buf = bytes::BytesMut::with_capacity(8192);
        loop {
            match next_message(&mut recv, &mut buf, proto).await? {
                ServerMessage::Authenticated {
                    user_id,
                    session_id,
                    ..
                } => {
                    return Ok(Connected {
                        endpoint,
                        connection,
                        send,
                        recv,
                        buf,
                        user_id,
                        session_id,
                        proto,
                    })
                }
                ServerMessage::AuthStep(AuthStep::DeviceChallenge {
                    challenge,
                    relay_id,
                }) => {
                    let mut binding = [0u8; voipc_crypto::bind::BIND_LEN];
                    connection
                        .export_keying_material(
                            &mut binding,
                            voipc_crypto::bind::EXPORTER_LABEL,
                            &[],
                        )
                        .map_err(|_| "this connection gives no exporter")?;
                    let key =
                        voipc_crypto::account::DeviceKey::from_parts(device_id, pkcs8.clone())
                            .ok_or("a load device key ring refuses")?;
                    let answer = AuthContinue::DeviceSigBound {
                        signature: key.sign(&relay_id, &challenge),
                        bind: key.sign_bound(
                            &relay_id,
                            &challenge,
                            &voipc_crypto::bind::Binding::Tls(binding),
                        ),
                        web: false,
                    };
                    send.write_all(&enc(&ClientMessage::AuthContinue(answer), proto)?)
                        .await?;
                }
                ServerMessage::AuthStep(AuthStep::Vault { .. }) => {
                    let (identity_key, prekey_bundle) = account_keys(index);
                    let keys = AuthContinue::Keys {
                        identity_key,
                        prekey_bundle,
                        reset_identity: false,
                    };
                    send.write_all(&enc(&ClientMessage::AuthContinue(keys), proto)?)
                        .await?;
                }
                ServerMessage::AuthError { reason } => return Err(reason.into()),
                ServerMessage::Refused {
                    code: REFUSED_VERSION,
                    server_protocol,
                    server_version,
                    text,
                } => {
                    if proto != PROTOCOL_VERSION
                        || !(OLDEST_RELAY_PROTOCOL..PROTOCOL_VERSION).contains(&server_protocol)
                    {
                        return Err(text.into());
                    }
                    if index == 0 {
                        println!("the relay runs VoIPC {server_version}: speaking its protocol {server_protocol}");
                    }
                    proto = server_protocol;
                    continue 'attempt;
                }
                _ => {}
            }
        }
    }
}

/// The endpoint of `local_ip`, which its clients and their retries share. With one per
/// attempt, each with its own receive buffers and alive until its connection drained, a
/// 20,000-account storm whose sign-ins were tried again held 28 GiB in this process.
fn shared_endpoint(
    server_addr: SocketAddr,
    local_ip: std::net::IpAddr,
) -> Result<Arc<Endpoint<wtransport::endpoint::endpoint_side::Client>>, Error> {
    type Shared = Arc<Endpoint<wtransport::endpoint::endpoint_side::Client>>;
    static ENDPOINTS: std::sync::LazyLock<dashmap::DashMap<std::net::IpAddr, Shared>> =
        std::sync::LazyLock::new(dashmap::DashMap::new);
    if let Some(e) = ENDPOINTS.get(&local_ip) {
        return Ok(e.clone());
    }
    let made = Arc::new(client_endpoint(server_addr, local_ip)?);
    Ok(ENDPOINTS.entry(local_ip).or_insert(made).clone())
}

/// A native client's endpoint from `local_ip`, trusting whatever the server shows: these only
/// ever talk to a relay on this machine.
pub fn client_endpoint(
    server_addr: SocketAddr,
    local_ip: std::net::IpAddr,
) -> Result<Endpoint<wtransport::endpoint::endpoint_side::Client>, Error> {
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
    Ok(Endpoint::client(config)?)
}

/// Where a native client asks to be let in.
pub fn native_url(server_addr: SocketAddr) -> String {
    format!("https://{NATIVE_SNI}:{}/voipc", server_addr.port())
}

/// A message as a relay of protocol `proto` reads it, its frames together.
pub fn enc(msg: &ClientMessage, proto: u32) -> Result<Vec<u8>, Error> {
    Ok(encode_client_msg_for(msg, proto)?.concat())
}

pub async fn next_message<R: AsyncRead + Unpin>(
    recv: &mut R,
    buf: &mut bytes::BytesMut,
    proto: u32,
) -> Result<ServerMessage, Error> {
    static UNCOUNTED: AtomicU64 = AtomicU64::new(0);
    next_counted(recv, buf, proto, &UNCOUNTED).await
}

/// `next_message`, adding each frame's payload bytes to `bytes`.
pub async fn next_counted<R: AsyncRead + Unpin>(
    recv: &mut R,
    buf: &mut bytes::BytesMut,
    proto: u32,
    bytes: &AtomicU64,
) -> Result<ServerMessage, Error> {
    loop {
        if let Some(payload) = try_decode_frame(buf)? {
            bytes.fetch_add(payload.len() as u64, Ordering::Relaxed);
            return Ok(decode_server_msg_from(&payload, proto)?);
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
