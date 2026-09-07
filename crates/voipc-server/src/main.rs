use std::fs;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use dashmap::DashMap;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

mod channels;
mod config;
mod media;
mod settings;
mod state;
mod tcp;
mod web;

use config::ServerConfig;
use state::ServerState;
use voipc_protocol::messages::ServerMessage;

#[derive(Parser)]
#[command(name = "voipc-server", about = "VoIPC voice communication server")]
struct Args {
    /// Path to configuration file (TOML)
    #[arg(short, long)]
    config: Option<String>,

    /// Path to TLS certificate file (PEM), overrides config
    #[arg(long)]
    cert: Option<String>,

    /// Path to TLS private key file (PEM), overrides config
    #[arg(long)]
    key: Option<String>,

    /// TCP port (browser page), overrides config
    #[arg(long)]
    tcp_port: Option<u16>,

    /// UDP port (QUIC endpoint for all clients), overrides config
    #[arg(long)]
    udp_port: Option<u16>,

    /// Bind address (IP), overrides config
    #[arg(long)]
    host: Option<String>,

    /// Path to server settings file (JSON)
    #[arg(long)]
    settings: Option<String>,

    /// Path to persistent channels file (JSON)
    #[arg(long)]
    channels: Option<String>,

    /// Admin token (overrides config and VOIPC_ADMIN_TOKEN); unset = generated per start
    #[arg(long)]
    admin_token: Option<String>,
}

/// Connection caps shared by the TCP (page) and QUIC accept loops.
pub struct ConnLimits {
    total: AtomicU32,
    per_ip: DashMap<IpAddr, u32>,
}

impl ConnLimits {
    /// A browser holds two slots (the HTTP/2 page connection and the
    /// QUIC session), a native client one (QUIC only).
    const MAX_PER_IP: u32 = 10;
    const MAX_TOTAL: u32 = 256;

    pub fn new() -> Self {
        Self {
            total: AtomicU32::new(0),
            per_ip: DashMap::new(),
        }
    }

    /// Take a slot for `ip`. On `Err` nothing was taken; the value is the
    /// reason for the log line.
    pub fn acquire(&self, ip: IpAddr) -> Result<(), &'static str> {
        if self.total.load(Ordering::Relaxed) >= Self::MAX_TOTAL {
            return Err("global limit reached");
        }
        {
            let mut count = self.per_ip.entry(ip).or_insert(0);
            if *count >= Self::MAX_PER_IP {
                return Err("per-IP limit reached");
            }
            *count += 1;
        }
        self.total.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    pub fn release(&self, ip: IpAddr) {
        self.total.fetch_sub(1, Ordering::Relaxed);
        if let Some(mut count) = self.per_ip.get_mut(&ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                drop(count);
                self.per_ip.remove(&ip);
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Install the ring crypto provider for rustls
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "voipc_server=info".into()),
        )
        .init();

    let args = Args::parse();

    // Load config
    let mut config = if let Some(config_path) = &args.config {
        let content = fs::read_to_string(config_path)
            .with_context(|| format!("failed to read config file: {}", config_path))?;
        toml::from_str(&content)?
    } else {
        ServerConfig::default()
    };

    // CLI overrides
    if let Some(cert) = args.cert {
        config.cert_path = cert;
    }
    if let Some(key) = args.key {
        config.key_path = key;
    }
    if let Some(port) = args.tcp_port {
        config.tcp_port = port;
    }
    if let Some(port) = args.udp_port {
        config.udp_port = port;
    }
    if let Some(host) = args.host {
        config.host = host;
    }
    if let Some(token) = args
        .admin_token
        .or_else(|| std::env::var("VOIPC_ADMIN_TOKEN").ok())
        .filter(|t| !t.is_empty())
    {
        config.admin_token = Some(token);
    }

    // Load server settings (JSON)
    let server_settings = if let Some(settings_path) = &args.settings {
        settings::ServerSettings::load_from_file(std::path::Path::new(settings_path))
            .with_context(|| format!("failed to load settings: {}", settings_path))?
    } else if std::path::Path::new("server_settings.json").exists() {
        settings::ServerSettings::load_from_file(std::path::Path::new("server_settings.json"))
            .context("failed to load server_settings.json")?
    } else {
        settings::ServerSettings::default()
    };

    // Load persistent channels (JSON)
    let persistent_channels = if let Some(channels_path) = &args.channels {
        channels::load_and_prepare_channels(std::path::Path::new(channels_path))
            .with_context(|| format!("failed to load channels: {}", channels_path))?
    } else if std::path::Path::new("channels.json").exists() {
        channels::load_and_prepare_channels(std::path::Path::new("channels.json"))
            .context("failed to load channels.json")?
    } else {
        Vec::new()
    };

    info!("VoIPC Server starting");
    info!(
        host = %config.host,
        tcp_port = config.tcp_port,
        udp_port = config.udp_port,
        max_users = config.max_users,
        empty_channel_timeout = server_settings.empty_channel_timeout_secs,
        persistent_channels = persistent_channels.len(),
    );

    // Load TLS certificate and key: the QUIC endpoint serves them to native
    // clients (by SNI), the TCP listener to browsers loading the page.
    let certs = load_certs(&config.cert_path)?;
    let key = load_key(&config.key_path)?;

    let mut tls_config =
        rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(certs.clone(), key.clone_key())
            .context("invalid TLS configuration")?;
    // Browsers get the web client over HTTP/2 only; anything offering just
    // http/1.1 fails the handshake. Pre-0.5 native clients send no ALPN and
    // are told to update (tcp::reject_legacy).
    tls_config.alpn_protocols = vec![b"h2".to_vec()];

    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

    // Admin token: configured, or generated for this run and shown once
    // (like a TeamSpeak privilege key). Nothing is persisted.
    let admin_token = match config.admin_token.clone().filter(|t| !t.is_empty()) {
        Some(token) => token,
        None => {
            let token = hex::encode(rand::random::<[u8; 32]>());
            info!("no admin_token configured — admin token for this run: {token}");
            token
        }
    };

    // Create shared state
    let state = Arc::new(ServerState::new(
        &config,
        server_settings,
        persistent_channels,
        admin_token,
    ));

    // Bind TCP listener
    let tcp_listener = TcpListener::bind(format!("{}:{}", config.host, config.tcp_port))
        .await
        .with_context(|| format!("failed to bind TCP on {}:{}", config.host, config.tcp_port))?;

    info!("TCP listener bound on {}:{}", config.host, config.tcp_port);

    let limits = Arc::new(ConnLimits::new());

    // The QUIC endpoint every client connects to, plus the page's /wt.json data
    let web = web::WebTransport::bind(&config, certs, key)?;
    let wt_info = web.info();
    tokio::spawn(web.run(state.clone(), limits.clone()));
    info!(
        "QUIC endpoint bound on UDP {}:{} (web client at https://{}:{}/)",
        config.host, config.udp_port, config.host, config.tcp_port
    );

    // TCP accept loop with connection limits
    info!("server ready, accepting connections");

    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);

    loop {
        let accept_result = tokio::select! {
            result = tcp_listener.accept() => result,
            _ = &mut shutdown => {
                info!("shutdown signal received, stopping accept loop");
                break;
            }
        };

        let (tcp_stream, peer_addr) = match accept_result {
            Ok(result) => result,
            Err(e) => {
                error!("TCP accept error: {}", e);
                continue;
            }
        };

        let peer_ip = peer_addr.ip();

        if state.is_banned(peer_ip) {
            debug!(peer = %peer_addr, "rejecting connection: banned");
            drop(tcp_stream);
            continue;
        }

        if let Err(reason) = limits.acquire(peer_ip) {
            warn!(peer = %peer_addr, "rejecting connection: {reason}");
            drop(tcp_stream);
            continue;
        }

        // Set TCP keepalive to detect dead connections within ~25 seconds
        {
            let sock_ref = socket2::SockRef::from(&tcp_stream);
            let keepalive = socket2::TcpKeepalive::new()
                .with_time(Duration::from_secs(10))
                .with_interval(Duration::from_secs(5))
                .with_retries(3);
            if let Err(e) = sock_ref.set_tcp_keepalive(&keepalive) {
                warn!(peer = %peer_addr, "failed to set TCP keepalive: {}", e);
            }
        }

        let tls_acceptor = tls_acceptor.clone();
        let limits = limits.clone();
        let wt_info = wt_info.clone();

        tokio::spawn(async move {
            // The 5 s auth timeout only starts after TLS completes; without a
            // deadline here an idle TCP socket (no ClientHello) holds one of
            // the 256 slots forever.
            match tokio::time::timeout(Duration::from_secs(10), tls_acceptor.accept(tcp_stream))
                .await
            {
                Ok(Ok(tls_stream)) => {
                    if tls_stream.get_ref().1.alpn_protocol() == Some(&b"h2"[..]) {
                        web::serve_h2(tls_stream, wt_info, peer_addr).await;
                    } else {
                        debug!(peer = %peer_addr, "legacy (pre-0.5) client, telling it to update");
                        tcp::reject_legacy(tls_stream).await;
                    }
                }
                Ok(Err(e)) => {
                    // Browsers open speculative connections and drop them
                    // without a ClientHello; that is normal traffic, not an error.
                    if e.kind() == std::io::ErrorKind::UnexpectedEof {
                        debug!(peer = %peer_addr, "TLS handshake aborted by peer");
                    } else {
                        error!(peer = %peer_addr, "TLS handshake failed: {}", e);
                    }
                }
                Err(_) => {
                    warn!(peer = %peer_addr, "TLS handshake timed out");
                }
            }

            limits.release(peer_ip);
        });
    }

    // Graceful shutdown: notify all connected clients
    info!("broadcasting shutdown to all connected clients");
    let shutdown_msg = ServerMessage::ServerShutdown {
        reason: "server shutting down".into(),
    };
    if let Ok(data) = voipc_protocol::codec::encode_server_msg(&shutdown_msg) {
        state.broadcast_raw_to_all(&data).await;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    info!("server shut down");
    Ok(())
}

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let cert_data = fs::read(path).with_context(|| format!("failed to read cert: {}", path))?;
    let mut reader = std::io::BufReader::new(cert_data.as_slice());
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .context("failed to parse certificates")?;

    if certs.is_empty() {
        anyhow::bail!("no certificates found in {}", path);
    }

    Ok(certs)
}

fn load_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    let key_data = fs::read(path).with_context(|| format!("failed to read key: {}", path))?;
    let mut reader = std::io::BufReader::new(key_data.as_slice());

    loop {
        match rustls_pemfile::read_one(&mut reader)? {
            Some(rustls_pemfile::Item::Pkcs1Key(key)) => return Ok(PrivateKeyDer::Pkcs1(key)),
            Some(rustls_pemfile::Item::Pkcs8Key(key)) => return Ok(PrivateKeyDer::Pkcs8(key)),
            Some(rustls_pemfile::Item::Sec1Key(key)) => return Ok(PrivateKeyDer::Sec1(key)),
            Some(_) => continue, // skip other items
            None => anyhow::bail!("no private key found in {}", path),
        }
    }
}
