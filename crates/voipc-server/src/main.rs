use std::fs;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

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
mod routing;
mod settings;
mod state;
mod tcp;
mod web;

use config::ServerConfig;
use state::{RateLimiter, ServerState};
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

/// One IP's connect budget, and when we last saw it. The timestamp is only
/// there so the map can be swept: the limiter itself carries no clock a
/// sweeper could read.
struct ConnectRate {
    limiter: RateLimiter,
    last_seen: Instant,
}

/// Connection caps shared by the TCP (page) and QUIC accept loops.
pub struct ConnLimits {
    total: AtomicU32,
    /// Ceiling on concurrent connections, derived from `max_users` rather than
    /// fixed: a browser client holds two of these, so a server told to take
    /// 300 users needs room for 600 connections. A constant here was a second,
    /// invisible `max_users` that no configuration could raise.
    max_total: u32,
    /// ...and per address, from `max_connections_per_ip`.
    max_per_ip: u32,
    per_ip: DashMap<IpAddr, u32>,
    /// Connect *attempts* per IP, which the counts above do not bound at all:
    /// a peer that opens a connection and drops it again hands its slot back
    /// every time, so the counts stay at one while it makes us pay for a TLS
    /// handshake as fast as it can dial. This is the only thing standing
    /// between that and the CPU.
    connect_rate: DashMap<IpAddr, ConnectRate>,
    /// When the connect-rate map was last swept. The sweep walks the whole map
    /// under every shard's write lock, so it runs on a timer rather than on
    /// every connect past the threshold — see `take_connect_token`.
    last_sweep: std::sync::Mutex<Instant>,
}

impl ConnLimits {
    /// Deliberately generous, because the thing this protects against is cheap
    /// to survive and the thing it can break is not.
    ///
    /// What it protects against is a dial-and-drop loop making the server pay
    /// for TLS handshakes; five a second per address is already nothing next
    /// to the work one voice channel does. What it can break is ordinary use:
    /// a browser spends several connects opening one session — the page, its
    /// reloads and the WebTransport handshake are separate attempts — and a
    /// whole office sits behind one address, so twenty people reconnecting
    /// after a server restart arrive as one burst from one IP. A tight bucket
    /// turns that into "the app will not connect", which is exactly what
    /// happened when this was first written with a burst of five.
    const CONNECT_BURST: f64 = 60.0;
    const CONNECT_REFILL: f64 = 5.0;
    /// The connect-rate map is the one thing here that a stranger can make
    /// grow: every IP that dials gets an entry, and the entry has to outlive
    /// the connection it refused or the refusal would be undone by the
    /// disconnect that follows it. So it is swept instead — but only once it
    /// is large enough to be worth sweeping, and only of entries whose bucket
    /// has long since refilled to full and therefore says nothing a fresh one
    /// would not.
    const MAX_RATE_ENTRIES: usize = 4096;
    const RATE_ENTRY_TTL: Duration = Duration::from_secs(60);

    /// A browser holds two slots (the HTTP/2 page connection and the QUIC
    /// session), a native client one (QUIC only) — hence the doubling, plus a
    /// little room for the ones mid-handshake.
    pub fn from_config(config: &ServerConfig) -> Self {
        Self::new(
            config.max_users.saturating_mul(2).saturating_add(16),
            config.max_connections_per_ip,
        )
    }

    pub fn new(max_total: u32, max_per_ip: u32) -> Self {
        Self {
            total: AtomicU32::new(0),
            max_total,
            max_per_ip,
            per_ip: DashMap::new(),
            connect_rate: DashMap::new(),
            last_sweep: std::sync::Mutex::new(Instant::now()),
        }
    }

    /// Take a slot for `ip`. On `Err` nothing was taken; the value is the
    /// reason for the log line.
    pub fn acquire(&self, ip: IpAddr) -> Result<(), &'static str> {
        // First, because it is the cheapest refusal and the one that protects
        // the most expensive work.
        if !self.take_connect_token(ip) {
            return Err("connect rate exceeded");
        }
        if self.total.load(Ordering::Relaxed) >= self.max_total {
            return Err("global limit reached");
        }
        {
            let mut count = self.per_ip.entry(ip).or_insert(0);
            if *count >= self.max_per_ip {
                return Err("per-IP limit reached");
            }
            *count += 1;
        }
        self.total.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Spend one of `ip`'s connect tokens. Deliberately not undone by
    /// `release`: what is being paid for is the attempt, not the connection.
    fn take_connect_token(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        if self.connect_rate.len() > Self::MAX_RATE_ENTRIES {
            // At most once a TTL. The sweep is O(entries) and takes every
            // shard's write lock, while the thing that pushes the map past the
            // threshold is a flood of distinct addresses — so sweeping per
            // connect means every accept on the server pays for the flood, and
            // it frees nothing at all while the entries are younger than the
            // TTL. On a timer the map's ceiling is one TTL of arrivals.
            let due = self
                .last_sweep
                .lock()
                .map(|mut last| {
                    let due = now.duration_since(*last) >= Self::RATE_ENTRY_TTL;
                    if due {
                        *last = now;
                    }
                    due
                })
                .unwrap_or(false);
            if due {
                self.connect_rate
                    .retain(|_, e| now.duration_since(e.last_seen) < Self::RATE_ENTRY_TTL);
            }
        }
        let mut entry = self.connect_rate.entry(ip).or_insert_with(|| ConnectRate {
            limiter: RateLimiter::new(Self::CONNECT_BURST, Self::CONNECT_REFILL),
            last_seen: now,
        });
        entry.last_seen = now;
        entry.limiter.try_consume()
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
        // `connect_rate` is untouched on purpose. Evicting the entry here
        // would hand the whole burst back on every disconnect, which is
        // exactly the pattern the budget exists to bound.
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
    // The v6 wildcard is dual-stack (IPV6_V6ONLY off for the TCP listener,
    // Ipv6DualStackConfig::Allow for QUIC), so one bind serves both families.
    // A kernel with IPv6 switched off cannot bind it at all; fall back rather
    // than refuse to start.
    if config.host == "::" && std::net::UdpSocket::bind("[::]:0").is_err() {
        warn!("IPv6 is unavailable on this host — binding 0.0.0.0 instead of ::");
        config.host = "0.0.0.0".into();
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
        max_connections = config.max_users.saturating_mul(2).saturating_add(16),
        max_connections_per_ip = config.max_connections_per_ip,
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
    let tcp_addr = config.bind_addr(config.tcp_port)?;
    let tcp_listener = TcpListener::bind(tcp_addr)
        .await
        .with_context(|| format!("failed to bind TCP on {tcp_addr}"))?;

    info!("TCP listener bound on {}:{}", config.host, config.tcp_port);

    let limits = Arc::new(ConnLimits::from_config(&config));

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
        let http_state = state.clone();

        tokio::spawn(async move {
            // The 5 s auth timeout only starts after TLS completes; without a
            // deadline here an idle TCP socket (no ClientHello) holds one of
            // the 256 slots forever.
            match tokio::time::timeout(Duration::from_secs(10), tls_acceptor.accept(tcp_stream))
                .await
            {
                Ok(Ok(tls_stream)) => {
                    if tls_stream.get_ref().1.alpn_protocol() == Some(&b"h2"[..]) {
                        web::serve_h2(tls_stream, wt_info, http_state, peer_addr).await;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// The connection *counts* are handed back when a connection ends, so on
    /// their own they let one peer dial as fast as it can as long as it hangs
    /// up each time — and every one of those dials costs a TLS handshake.
    #[test]
    fn connects_from_one_ip_are_rate_limited() {
        let limits = ConnLimits::from_config(&ServerConfig::default());
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        for _ in 0..ConnLimits::CONNECT_BURST as usize {
            limits.acquire(ip).expect("the burst is allowed through");
            limits.release(ip);
        }

        assert_eq!(
            limits.acquire(ip),
            Err("connect rate exceeded"),
            "releasing the slots handed the connect budget back"
        );

        // Somebody else's budget is their own: one noisy IP must not be able
        // to shut the server to everybody.
        let other = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        assert!(limits.acquire(other).is_ok());
    }

    /// A server told to hold more users has to be able to hold their
    /// connections. Until 0.9.0 both ceilings were constants, so `max_users`
    /// above 256 — or above 128, for browser clients, which take two slots
    /// each — was a number in a config file that nothing read.
    #[test]
    fn the_connection_ceiling_follows_max_users() {
        let config = ServerConfig {
            max_users: 300,
            max_connections_per_ip: 2,
            ..ServerConfig::default()
        };
        let limits = ConnLimits::from_config(&config);
        assert_eq!(limits.max_total, 616, "two slots per user, plus handshakes");
        assert_eq!(limits.max_per_ip, 2);

        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
        limits.acquire(ip).unwrap();
        limits.acquire(ip).unwrap();
        assert_eq!(limits.acquire(ip), Err("per-IP limit reached"));
    }

    /// The connect-rate map is the one table a stranger can grow, and the
    /// sweep that bounds it walks every entry under every shard's write lock.
    /// Running it per connect past the threshold — which is what a flood of
    /// distinct addresses produces — puts that walk in the path of every accept
    /// on the server, and frees nothing at all while the entries are younger
    /// than the TTL they are swept by.
    #[test]
    fn the_connect_table_is_swept_on_a_timer_not_on_every_connect() {
        let limits = ConnLimits::from_config(&ServerConfig::default());
        for i in 0..=ConnLimits::MAX_RATE_ENTRIES as u32 {
            let ip = IpAddr::V4(Ipv4Addr::from(i.to_be_bytes()));
            let _ = limits.acquire(ip);
        }
        assert!(limits.connect_rate.len() > ConnLimits::MAX_RATE_ENTRIES);

        // Every one of those is fresh, so a sweep would free nothing — and the
        // next connect must not pay for walking them to find that out. The
        // timer was set when the limits were built, so no sweep is due yet.
        let before = *limits.last_sweep.lock().unwrap();
        let _ = limits.acquire(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)));
        assert_eq!(
            *limits.last_sweep.lock().unwrap(),
            before,
            "a sweep ran while the last one was still within its TTL"
        );

        // Once one is due, it runs — and the entries, still fresh, survive it.
        *limits.last_sweep.lock().unwrap() = Instant::now() - ConnLimits::RATE_ENTRY_TTL;
        let _ = limits.acquire(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 8)));
        assert!(*limits.last_sweep.lock().unwrap() > before);
        assert!(limits.connect_rate.len() > ConnLimits::MAX_RATE_ENTRIES);
    }
}
