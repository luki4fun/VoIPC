// What the load generators share: a native client's connection, spread over
// loopback addresses, and framing in the relay's own protocol.

// Each example uses a part of this.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt};
use wtransport::config::{DnsLookupFuture, DnsResolver};
use wtransport::{ClientConfig, Connection, Endpoint, RecvStream, SendStream};

use voipc_protocol::codec::{try_decode_frame, APP_VERSION, PROTOCOL_VERSION};
use voipc_protocol::compat::{
    decode_server_msg_from, encode_client_msg_for, OLDEST_RELAY_PROTOCOL,
};
use voipc_protocol::messages::{ClientMessage, ServerMessage, REFUSED_VERSION};
use voipc_protocol::types::{PreKeyBundleData, SessionId, UserId};

pub type Error = Box<dyn std::error::Error + Send + Sync>;

/// Server name that makes the server present its operator certificate
/// (`crates/voipc-server/src/web.rs::NATIVE_SNI`).
const NATIVE_SNI: &str = "voipc-native";

pub struct Connected {
    /// Holds the socket open for the connection.
    pub endpoint: Endpoint<wtransport::endpoint::endpoint_side::Client>,
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
    let endpoint = client_endpoint(server_addr, local_ip)?;
    // At our protocol first; a relay of an older one names its own
    let mut proto = PROTOCOL_VERSION;
    'attempt: loop {
        let connection = endpoint.connect(native_url(server_addr)).await?;
        let (mut send, mut recv) = connection.open_bi().await?.await?;
        let auth = ClientMessage::Authenticate {
            // With a tag: a relay with accounts wants one on a guest's name
            username: format!("load{index}#0001"),
            protocol_version: proto,
            app_version: APP_VERSION.to_string(),
            identity_key: keys.as_ref().map(|k| k.0.clone()),
            prekey_bundle: keys.as_ref().map(|k| k.1.clone()),
            account: None,
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
    loop {
        if let Some(payload) = try_decode_frame(buf)? {
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
