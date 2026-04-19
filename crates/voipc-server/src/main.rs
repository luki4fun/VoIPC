use std::fs;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use dashmap::DashMap;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::{TcpListener, UdpSocket};
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

mod channels;
mod config;
mod settings;
mod state;
mod tcp;
mod udp;

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

    /// TCP port, overrides config
    #[arg(long)]
    tcp_port: Option<u16>,

    /// UDP port, overrides config
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

    // Load TLS certificate and key
    let certs = load_certs(&config.cert_path)?;
    let key = load_key(&config.key_path)?;

    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("invalid TLS configuration")?;

    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

    // Create shared state
    let state = Arc::new(ServerState::new(&config, server_settings, persistent_channels));

    // Bind TCP listener
    let tcp_listener = TcpListener::bind(format!("{}:{}", config.host, config.tcp_port))
        .await
        .with_context(|| format!("failed to bind TCP on {}:{}", config.host, config.tcp_port))?;

    info!("TCP listener bound on {}:{}", config.host, config.tcp_port);

    // Bind UDP socket with large buffers to absorb video packet bursts
    let udp_socket = {
        let addr: std::net::SocketAddr = format!("{}:{}", config.host, config.udp_port)
            .parse()
            .with_context(|| format!("invalid UDP address {}:{}", config.host, config.udp_port))?;
        let domain = if addr.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        };
        let sock = socket2::Socket::new(
            domain,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .with_context(|| "failed to create UDP socket")?;
        // Allow dual-stack (IPv4+IPv6) when binding to IPv6
        if addr.is_ipv6() {
            let _ = sock.set_only_v6(false);
        }
        if let Err(e) = sock.set_recv_buffer_size(2 * 1024 * 1024) {
            warn!("failed to set UDP recv buffer to 2MB: {e}");
        }
        if let Err(e) = sock.set_send_buffer_size(2 * 1024 * 1024) {
            warn!("failed to set UDP send buffer to 2MB: {e}");
        }
        sock.bind(&addr.into())
            .with_context(|| format!("failed to bind UDP on {}:{}", config.host, config.udp_port))?;
        sock.set_nonblocking(true)
            .with_context(|| "failed to set non-blocking")?;
        let std_sock: std::net::UdpSocket = sock.into();
        Arc::new(
            UdpSocket::from_std(std_sock)
                .with_context(|| "failed to wrap UDP socket in tokio")?,
        )
    };

    info!("UDP socket bound on {}:{}", config.host, config.udp_port);

    // Spawn UDP voice loop
    let udp_state = state.clone();
    let udp_sock = udp_socket.clone();
    tokio::spawn(async move {
        udp::run_udp_loop(udp_sock, udp_state).await;
    });

    // TCP accept loop with connection limits
    info!("server ready, accepting connections");

    const MAX_CONNECTIONS_PER_IP: u32 = 5;
    const MAX_TOTAL_CONNECTIONS: u32 = 256;

    let active_connections = Arc::new(AtomicU32::new(0));
    let per_ip_connections: Arc<DashMap<IpAddr, u32>> = Arc::new(DashMap::new());

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

        // Global connection limit
        if active_connections.load(Ordering::Relaxed) >= MAX_TOTAL_CONNECTIONS {
            warn!(peer = %peer_addr, "rejecting connection: global limit reached");
            drop(tcp_stream);
            continue;
        }

        // Per-IP connection limit
        {
            let mut count = per_ip_connections.entry(peer_ip).or_insert(0);
            if *count >= MAX_CONNECTIONS_PER_IP {
                warn!(peer = %peer_addr, "rejecting connection: per-IP limit reached");
                drop(tcp_stream);
                continue;
            }
            *count += 1;
        }

        active_connections.fetch_add(1, Ordering::Relaxed);

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
        let state = state.clone();
        let conn_count = active_connections.clone();
        let ip_conns = per_ip_connections.clone();

        tokio::spawn(async move {
            match tls_acceptor.accept(tcp_stream).await {
                Ok(tls_stream) => {
                    tcp::handle_connection(tls_stream, state).await;
                }
                Err(e) => {
                    error!(peer = %peer_addr, "TLS handshake failed: {}", e);
                }
            }

            // Decrement connection counters on task completion
            conn_count.fetch_sub(1, Ordering::Relaxed);
            if let Some(mut count) = ip_conns.get_mut(&peer_ip) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    drop(count);
                    ip_conns.remove(&peer_ip);
                }
            }
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
