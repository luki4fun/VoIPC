//! QUIC link to the server — the Rust twin of `client/src/web/backend/transport.ts`.
//!
//! One bidirectional stream carries the control channel in the native
//! framing (u32 big-endian length + postcard payload), QUIC datagrams carry
//! voice and screen-audio packets, and each video frame travels on its own
//! unidirectional stream as `[u16 big-endian len][packet]` records — in both
//! directions. Everything rides one UDP flow, so NAT rebinds and address
//! changes are handled by QUIC's connection migration and a blocked UDP path
//! fails the connect instead of leaving a silent session.
//!
//! Certificate trust is what it was on TCP: either TOFU pinning of the
//! operator certificate keyed by `host:port` (`accept_invalid_certs`) or the
//! WebPKI roots. The server presents that certificate when the TLS server
//! name is [`NATIVE_SNI`] (browsers get a rotating hash-pinned one instead),
//! so the URL host is `NATIVE_SNI` and a fixed resolver dials the real address.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tracing::{info, warn};
use wtransport::config::{DnsLookupFuture, DnsResolver};
use wtransport::endpoint::endpoint_side::Client;
use wtransport::{ClientConfig, Connection, Endpoint, RecvStream, SendStream, VarInt};

/// TLS server name that makes the server present its operator certificate
/// (`crates/voipc-server/src/web.rs::NATIVE_SNI`).
pub const NATIVE_SNI: &str = "voipc-native";

/// Bound for each connect phase (resolve, handshake, control stream, auth).
/// Without a deadline a black-holed host keeps the reconnect loop (and its
/// Cancel button) stuck for minutes.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// The QUIC handles that outlive the per-stream tasks.
pub struct Quic {
    pub endpoint: Endpoint<Client>,
    pub connection: Connection,
}

impl Quic {
    /// Close the connection and give the endpoint a moment to put
    /// CONNECTION_CLOSE on the wire, so the server frees the username right
    /// away instead of after its 30 s idle timeout.
    pub async fn close(&self) {
        self.connection.close(VarInt::from_u32(0), b"");
        let _ = tokio::time::timeout(Duration::from_millis(500), self.endpoint.wait_idle()).await;
    }
}

/// An established session: the connection plus the opened control stream.
pub struct Link {
    pub quic: Quic,
    pub control_send: SendStream,
    pub control_recv: RecvStream,
}

/// Resolve `host`, open the QUIC connection and the control stream.
pub async fn connect(host: &str, port: u16, accept_invalid_certs: bool) -> Result<Link, String> {
    let server_addr = tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::lookup_host((host, port)))
        .await
        .map_err(|_| format!("Timed out resolving {host}"))?
        .map_err(|e| format!("Could not resolve {host}: {e}"))?
        .next()
        .ok_or_else(|| format!("No addresses found for {host}"))?;

    let tls = tls_config(host, port, accept_invalid_certs)?;
    // Bind in the server's address family: a v6 wildcard socket is not
    // available everywhere and a v4 one cannot reach a v6 server.
    let bind: SocketAddr = if server_addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    }
    .parse()
    .expect("literal bind address");
    let config = ClientConfig::builder()
        .with_bind_address(bind)
        .with_custom_tls(tls)
        // Keeps NAT mappings alive through silent channels; a vanished
        // server trips the 30 s idle timeout and surfaces as a read error.
        .keep_alive_interval(Some(Duration::from_secs(10)))
        .dns_resolver(Fixed(server_addr))
        .build();
    let endpoint =
        Endpoint::client(config).map_err(|e| format!("Could not create QUIC endpoint: {e}"))?;

    info!("connecting to {server_addr} over QUIC");
    let connection = tokio::time::timeout(
        CONNECT_TIMEOUT,
        endpoint.connect(format!("https://{NATIVE_SNI}:{port}/voipc")),
    )
    .await
    .map_err(|_| format!("Timed out connecting to {host}:{port}"))?
    .map_err(|e| format!("Could not connect to {host}:{port}: {e}"))?;
    info!("QUIC handshake complete (rtt {:?})", connection.rtt());

    let (control_send, control_recv) = tokio::time::timeout(CONNECT_TIMEOUT, async {
        let opening = connection.open_bi().await.map_err(|e| e.to_string())?;
        opening.await.map_err(|e| e.to_string())
    })
    .await
    .map_err(|_| "Timed out opening the control stream".to_string())?
    .map_err(|e| format!("Could not open the control stream: {e}"))?;

    Ok(Link {
        quic: Quic {
            endpoint,
            connection,
        },
        control_send,
        control_recv,
    })
}

fn tls_config(
    host: &str,
    port: u16,
    accept_invalid_certs: bool,
) -> Result<rustls::ClientConfig, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| format!("TLS configuration error: {e}"))?;

    let mut config = if accept_invalid_certs {
        warn!("Using TOFU certificate pinning (self-signed mode)");
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(TofuCertVerifier {
                key: tofu_key(host, port),
            }))
            .with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let inner = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
            .build()
            .map_err(|e| format!("TLS configuration error: {e}"))?;
        let name = if let Ok(ip) = host.parse::<IpAddr>() {
            ServerName::IpAddress(ip.into())
        } else {
            ServerName::try_from(host.to_string())
                .map_err(|e| format!("Invalid server name '{host}': {e}"))?
        };
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(VerifyAs { inner, name }))
            .with_no_client_auth()
    };
    config.alpn_protocols = vec![b"h3".to_vec()];
    Ok(config)
}

/// Resolves any host name to the server address, so the URL can carry
/// [`NATIVE_SNI`] as the server name while dialing what the user typed.
#[derive(Debug)]
struct Fixed(SocketAddr);

impl DnsResolver for Fixed {
    fn resolve(&self, _host: &str) -> Pin<Box<dyn DnsLookupFuture>> {
        let addr = self.0;
        Box::pin(async move { Ok(Some(addr)) })
    }
}

/// WebPKI verification against the real host name: the server name on the
/// wire is [`NATIVE_SNI`], which no public certificate carries.
#[derive(Debug)]
struct VerifyAs {
    inner: Arc<WebPkiServerVerifier>,
    name: ServerName<'static>,
}

impl ServerCertVerifier for VerifyAs {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.inner
            .verify_server_cert(end_entity, intermediates, &self.name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

// ── TOFU certificate pinning ────────────────────────────────────────────

/// TOFU (Trust On First Use) certificate pinning store.
/// Maps `host:port` to the SHA-256 fingerprint of the server's certificate.
/// On first connect, the cert is trusted and stored. On subsequent connects,
/// the cert must match the stored fingerprint or the connection is rejected.
/// Persisted to `tofu_pins.json` in the VoIPC data directory.
static TOFU_STORE: std::sync::LazyLock<std::sync::Mutex<HashMap<String, Vec<u8>>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(tofu_load_from_disk()));

/// Load TOFU pins from disk. Returns empty map on any error.
fn tofu_load_from_disk() -> HashMap<String, Vec<u8>> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let path = crate::config::data_dir().join("tofu_pins.json");
    let Ok(data) = std::fs::read_to_string(&path) else {
        return HashMap::new();
    };
    // Stored as { "host:port": "base64-encoded-fingerprint", ... }
    let Ok(map): Result<HashMap<String, String>, _> = serde_json::from_str(&data) else {
        return HashMap::new();
    };
    map.into_iter()
        .filter_map(|(k, v)| STANDARD.decode(&v).ok().map(|bytes| (k, bytes)))
        .collect()
}

/// Save TOFU pins to disk. Errors are logged but non-fatal.
fn tofu_save_to_disk(store: &HashMap<String, Vec<u8>>) {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let path = crate::config::data_dir().join("tofu_pins.json");
    let b64_map: HashMap<&str, String> = store
        .iter()
        .map(|(k, v)| (k.as_str(), STANDARD.encode(v)))
        .collect();
    match serde_json::to_string_pretty(&b64_map) {
        Ok(json) => {
            if let Err(e) = std::fs::write(&path, json) {
                warn!("Failed to save TOFU pins: {}", e);
            }
        }
        Err(e) => warn!("Failed to serialize TOFU pins: {}", e),
    }
}

/// Pin store key: `host:port`, lowercase. Per port, so two self-signed
/// servers on one box do not read as a MITM of each other.
fn tofu_key(host: &str, port: u16) -> String {
    format!("{}:{}", host.to_lowercase(), port)
}

/// Forget the pinned certificate for a server (after a legitimate cert
/// rotation). The next connect pins the new certificate.
pub fn tofu_forget(host: &str, port: u16) -> bool {
    let mut store = TOFU_STORE.lock().unwrap_or_else(|p| {
        warn!("mutex poisoned, recovering");
        p.into_inner()
    });
    let removed = store.remove(&tofu_key(host, port)).is_some();
    if removed {
        tofu_save_to_disk(&store);
    }
    removed
}

/// Certificate verifier that accepts self-signed certs with TOFU pinning.
/// First connection to a host:port: accept and pin the certificate fingerprint.
/// Subsequent connections: reject if the certificate fingerprint changes.
#[derive(Debug)]
struct TofuCertVerifier {
    key: String,
}

impl ServerCertVerifier for TofuCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // Compute SHA-256 fingerprint of the server's certificate
        use ring::digest;
        let fingerprint = digest::digest(&digest::SHA256, end_entity.as_ref());
        let fp_bytes = fingerprint.as_ref().to_vec();
        let host_key = &self.key;

        let mut store = TOFU_STORE.lock().unwrap_or_else(|p| {
            warn!("mutex poisoned, recovering");
            p.into_inner()
        });

        if let Some(pinned) = store.get(host_key) {
            // We've connected to this host before — verify the fingerprint matches
            if *pinned != fp_bytes {
                warn!(
                    "TOFU: certificate fingerprint changed for {}! Possible MITM attack.",
                    host_key
                );
                // The UI matches on "fingerprint changed" to offer forgetting the pin.
                return Err(rustls::Error::General(format!(
                    "Server certificate fingerprint changed for {}. \
                     This could indicate a man-in-the-middle attack. \
                     Only if you know the server's certificate was replaced, \
                     use \"Forget pinned certificate\" and connect again.",
                    host_key
                )));
            }
            info!("TOFU: certificate fingerprint matches for {}", host_key);
        } else {
            // First connection — pin the certificate and persist to disk
            info!("TOFU: pinning certificate for {} (first connection)", host_key);
            store.insert(host_key.clone(), fp_bytes);
            tofu_save_to_disk(&store);
        }

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
        ]
    }
}
