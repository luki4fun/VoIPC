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

mod accounts;
mod channels;
mod config;
mod fsutil;
mod media;
mod presets;
mod routing;
mod settings;
mod state;
mod tcp;
mod tunnel;
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

    /// Turn on the TCP fallback for clients that cannot reach UDP (tcp_fallback)
    #[arg(long)]
    tcp_fallback: bool,

    /// Accounts: off, optional or required (overrides `[accounts] mode`)
    #[arg(long, value_enum)]
    accounts: Option<config::AccountsMode>,

    /// Accounts database, sqlite://… or postgres://… (overrides `[accounts] database`)
    #[arg(long)]
    database: Option<String>,

    #[command(subcommand)]
    command: Option<Command>,
}

/// Jobs instead of serving.
#[derive(clap::Subcommand)]
enum Command {
    /// Channel presets: list them, or write channels.json from one.
    #[command(subcommand)]
    Channels(presets::ChannelsCommand),
    /// Account administration from the server's own shell.
    #[command(subcommand)]
    Admin(AdminCommand),
    /// The accounts database.
    #[command(subcommand)]
    Db(DbCommand),
}

#[derive(clap::Subcommand)]
enum AdminCommand {
    /// Give an account a role (admin or moderator). It still needs
    /// two-factor codes before the role's rights apply.
    Grant { name: String, role: String },
    /// Take a role away again; the account is signed out everywhere. The last
    /// admin keeps the role.
    Revoke { name: String, role: String },
    /// Remove an account's two-factor and recovery codes, forget its devices
    /// and sign it out everywhere — the way back in for an admin who lost
    /// their phone.
    #[command(name = "reset-2fa")]
    Reset2fa { name: String },
    /// Print a single-use sign-up code (registration = "invite" or "closed").
    Invite {
        /// Only this account name can use it.
        #[arg(long = "for")]
        name: Option<String>,
        /// Days it stays valid (1 to 30).
        #[arg(long, default_value_t = 7)]
        days: i64,
    },
}

#[derive(clap::Subcommand)]
enum DbCommand {
    /// Copy a SQLite accounts database while the server runs (VACUUM INTO).
    /// For Postgres use pg_dump. Keep the key file with the copy.
    Backup { path: String },
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
    /// fixed: a browser client holds two of these (page plus QUIC session or
    /// TCP tunnel), so a server told to take
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

    /// A browser holds two slots (the HTTP/2 page connection and its QUIC
    /// session or TCP tunnel), a native client one (QUIC or tunnel) — hence
    /// the doubling, plus a little room for the ones mid-handshake and for a
    /// client racing QUIC against the tunnel.
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
        let ip = limit_key(ip);
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
        let ip = limit_key(ip);
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

/// Who a connection is counted against: an IPv4 address, or an IPv6 /64.
///
/// One subscriber gets a whole /64 — 2^64 addresses to dial from — so per
/// address, the per-IP ceiling and the connect-rate bucket bounded nothing for
/// anyone on IPv6. Canonical first: a dual-stack socket reports IPv4 peers as
/// `::ffff:a.b.c.d`, and masking that would count every IPv4 client as one.
fn limit_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let prefix = u128::from(v6) & !((1u128 << 64) - 1);
            IpAddr::V6(prefix.into())
        }
        v4 => v4,
    }
}

async fn run_command(config: &ServerConfig, command: Command) -> Result<()> {
    if config.accounts.mode == config::AccountsMode::Off {
        anyhow::bail!("accounts are off: set [accounts] mode, or pass --accounts optional");
    }
    let relay = accounts::Relay::open(&config.accounts).await.context("opening the accounts database")?;
    let store = relay.store();
    // The server's own shell: no signed-in admin acts, the audit rows say so.
    let ctx = relay.ctx(std::net::IpAddr::from([127, 0, 0, 1]), voipc_protocol::codec::APP_VERSION);
    let l4f = |e: l4f_accounts::service::Error| anyhow::anyhow!(e.message());
    let user_named = |name: String| async move {
        let name = name.trim().to_ascii_lowercase();
        store.user_by_username(&name).await?.with_context(|| format!("no account named {name:?}"))
    };
    match command {
        Command::Admin(AdminCommand::Grant { name, role }) => {
            let user = user_named(name).await?;
            if relay.accounts.grant_role_as_host(&ctx, user.id, &role).await.map_err(l4f)? {
                println!("{} now holds {role}; its rights apply once the account has two-factor codes.", user.username);
            } else {
                println!("{} already holds {role}.", user.username);
            }
        }
        Command::Admin(AdminCommand::Revoke { name, role }) => {
            let user = user_named(name).await?;
            if relay.accounts.revoke_role_as_host(&ctx, user.id, &role).await.map_err(l4f)? {
                println!("{} no longer holds {role} and is signed out everywhere (a running server ends its connection within {} minutes).", user.username, accounts::REVALIDATE_MINUTES);
            } else {
                println!("{} does not hold {role}.", user.username);
            }
        }
        Command::Admin(AdminCommand::Reset2fa { name }) => {
            let user = user_named(name).await?;
            if relay.accounts.reset_2fa_as_host(&ctx, user.id).await.map_err(l4f)? {
                println!(
                    "{}: second factors and recovery codes removed, devices forgotten, signed out everywhere (a running server ends its connection within {} minutes).",
                    user.username,
                    accounts::REVALIDATE_MINUTES
                );
            } else {
                println!("{} has no second factor, remembered device or session; nothing changed.", user.username);
            }
        }
        Command::Admin(AdminCommand::Invite { name, days }) => {
            // Closed: only an admin makes accounts, each for a name it picked.
            if config.accounts.registration == config::RegistrationMode::Closed && name.as_deref().is_none_or(|n| n.trim().is_empty()) {
                anyhow::bail!("registration is \"closed\": name the account the code is for with --for <name>");
            }
            let code = relay.accounts.invite_create_as_host(&ctx, name.as_deref(), days).await.map_err(l4f)?;
            // The code alone on stdout, for scripts; the rest is for whoever reads it.
            println!("{code}");
            let bound = name.map(|n| format!(", only for the name {n:?}")).unwrap_or_default();
            eprintln!("One sign-up, valid {} days{bound}: Create account, then this as the invite code.", days.clamp(1, 30));
        }
        Command::Channels(_) => unreachable!("handled before the database is opened"),
        Command::Db(DbCommand::Backup { path }) => match store {
            l4f_accounts::store::Store::Lite(b) => {
                sqlx::query(sqlx::AssertSqlSafe(format!("VACUUM INTO '{}'", path.replace('\'', "''"))))
                    .execute(&b.0)
                    .await
                    .with_context(|| format!("backing up to {path}"))?;
                fsutil::owner_only(std::path::Path::new(&path)).with_context(|| format!("making {path} readable by this user only"))?;
                println!("copied to {path}; keep {} with it", config.accounts.key_file);
            }
            l4f_accounts::store::Store::Pg(_) => anyhow::bail!("this is Postgres: back it up with pg_dump"),
        },
    }
    Ok(())
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

    // Files only, and none of them server.toml: a broken config must not stop
    // the tool that writes channels.json.
    if let Some(Command::Channels(command)) = args.command {
        return presets::run(command, args.channels.as_deref(), args.settings.as_deref());
    }

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
    if args.tcp_fallback {
        config.tcp_fallback = true;
    }
    if let Some(mode) = args.accounts {
        config.accounts.mode = mode;
    }
    if let Some(url) = args.database {
        config.accounts.database = url;
    }
    if let Some(command) = args.command {
        return run_command(&config, command).await;
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
        tcp_fallback = config.tcp_fallback,
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
    // Browsers get the web client over HTTP/2 only. Pre-0.5 native clients
    // send no ALPN and are told to update (tcp::reject_legacy).
    tls_config.alpn_protocols = alpn_protocols(config.tcp_fallback);

    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

    // Admin token: configured, or generated for this run and shown once
    // (like a TeamSpeak privilege key). Nothing is persisted.
    let configured_token = config.admin_token.clone().filter(|t| !t.is_empty());
    let generated_token = configured_token.is_none();
    let admin_token = configured_token.unwrap_or_else(|| hex::encode(rand::random::<[u8; 32]>()));

    // Opt-in accounts: the database is only ever opened (or made) when asked for.
    let relay = if config.accounts.mode == config::AccountsMode::Off {
        None
    } else {
        let relay = Arc::new(accounts::Relay::open(&config.accounts).await.context("opening the accounts database")?);
        info!(
            mode = ?config.accounts.mode,
            registration = ?config.accounts.registration,
            cloud = config.accounts.cloud,
            relay_id = %hex::encode(relay.relay_id),
            "accounts on"
        );
        // Expired sessions, invites, old audit rows and unused device keys.
        let sweeper = relay.clone();
        tokio::spawn(async move {
            let mut every = tokio::time::interval(Duration::from_secs(3600));
            loop {
                every.tick().await;
                if let Err(e) = sweeper.accounts.sweep(l4f_accounts::util::now()).await {
                    warn!("accounts sweep: {e}");
                }
                match accounts::log::sweep(&sweeper).await {
                    Ok(n) if n > 0 => info!(dropped = n, "stored messages past their time"),
                    Ok(_) => {}
                    Err(e) => warn!("stored-message sweep: {e}"),
                }
            }
        });
        Some(relay)
    };

    // The token is shown only where it can still do something: with accounts
    // it makes the first admin, for good, so a log reader must not get one
    // once an admin exists — and the shell can grant the role instead.
    if generated_token {
        match &relay {
            None => info!("no admin_token configured — admin token for this run: {admin_token}"),
            Some(r) if r.store().holders_of_scope_star().await.context("counting admins")? > 0 => {
                info!("this server has an admin account: the admin token is not used here (voipc-server admin grant gives roles)")
            }
            Some(_) => info!(
                "no admin account yet — admin token for this run, which makes the account that enters it the first admin: {admin_token} \
                 (or: voipc-server admin grant <name> admin)"
            ),
        }
    }

    // Create shared state
    let mut state = ServerState::new(&config, server_settings, persistent_channels, admin_token);
    state.accounts = relay;
    let state = Arc::new(state);
    if state.accounts.is_some() {
        accounts::locked_logs_at_boot(&state).await.context("checking the channel logs' passwords")?;
        // What the server's shell changes reaches connections already open.
        let watched = state.clone();
        tokio::spawn(async move {
            let mut every = tokio::time::interval(Duration::from_secs(60 * accounts::REVALIDATE_MINUTES));
            every.tick().await;
            loop {
                every.tick().await;
                accounts::revalidate(&watched).await;
            }
        });
    }

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
    if config.tcp_fallback {
        info!(
            "TCP fallback on: clients that cannot reach UDP {} tunnel through TCP {}",
            config.udp_port, config.tcp_port
        );
    }

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
                Ok(Ok(tls_stream)) => match tls_stream.get_ref().1.alpn_protocol() {
                    Some(b"h2") => web::serve_h2(tls_stream, wt_info, http_state, peer_addr).await,
                    // Only offered with tcp_fallback on
                    Some(b"http/1.1") => {
                        tunnel::tune(tls_stream.get_ref().0, peer_addr);
                        tunnel::serve(tls_stream, http_state, peer_addr).await;
                    }
                    _ => {
                        debug!(peer = %peer_addr, "legacy (pre-0.5) client, telling it to update");
                        tcp::reject_legacy(tls_stream).await;
                    }
                },
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

/// What the TLS listener offers. `h2` comes first because rustls picks in the
/// server's order: a browser loading the page offers both and gets HTTP/2.
/// `http/1.1` is there for one thing only, the TCP fallback's WebSocket
/// (tunnel.rs) — a new WebSocket connection offers nothing else — and without
/// the fallback anything offering just http/1.1 fails the handshake, as before.
fn alpn_protocols(tcp_fallback: bool) -> Vec<Vec<u8>> {
    let mut alpn = vec![b"h2".to_vec()];
    if tcp_fallback {
        alpn.push(b"http/1.1".to_vec());
    }
    alpn
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

    /// A page load must keep getting HTTP/2, and only the fallback may offer
    /// the WebSocket's http/1.1. Through a real handshake, because it is also
    /// what a native client sees on a server with the fallback off: refused
    /// on ALPN before any certificate is looked at, with the alert the client
    /// turns into "this server has no TCP fallback" (transport.rs).
    #[tokio::test]
    async fn http1_is_offered_only_with_the_fallback() {
        use rustls::pki_types::{PrivatePkcs8KeyDer, ServerName};

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let operator = wtransport::Identity::self_signed(["localhost"]).unwrap();
        let cert = CertificateDer::from(operator.certificate_chain().as_slice()[0].der().to_vec());
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            operator.private_key().secret_der().to_vec(),
        ));
        let handshake = |fallback: bool, offer: &'static [u8]| {
            let mut server = rustls::ServerConfig::builder_with_provider(provider.clone())
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![cert.clone()], key.clone_key())
                .unwrap();
            server.alpn_protocols = alpn_protocols(fallback);
            // No roots: a handshake that gets past ALPN fails on the certificate
            let mut client = rustls::ClientConfig::builder_with_provider(provider.clone())
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth();
            client.alpn_protocols = vec![offer.to_vec()];
            async move {
                let (c, s) = tokio::io::duplex(1 << 16);
                tokio::spawn(async move { TlsAcceptor::from(Arc::new(server)).accept(s).await });
                let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
                let name = ServerName::try_from("localhost").unwrap();
                connector.connect(name, c).await.unwrap_err().to_string()
            }
        };

        let refused = handshake(false, b"http/1.1").await;
        assert!(refused.contains("NoApplicationProtocol"), "{refused}");
        let past_alpn = handshake(true, b"http/1.1").await;
        assert!(!past_alpn.contains("NoApplicationProtocol"), "{past_alpn}");
        assert_eq!(alpn_protocols(true)[0], b"h2", "page loads would get HTTP/1.1");
        assert_eq!(alpn_protocols(false), [b"h2".to_vec()]);
    }

    /// The connection *counts* are handed back when a connection ends, so on
    /// their own they let one peer dial as fast as it can as long as it hangs
    /// up each time — and every one of those dials costs a TLS handshake.
    #[test]
    fn ipv6_is_counted_per_64_and_mapped_ipv4_as_ipv4() {
        let v6 = |s: &str| IpAddr::V6(s.parse().unwrap());
        let v4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
        assert_eq!(limit_key(v4), v4);
        assert_eq!(limit_key(v6("::ffff:192.0.2.7")), v4, "a dual-stack socket's IPv4 peer");
        assert_ne!(
            limit_key(v6("::ffff:192.0.2.7")),
            limit_key(v6("::ffff:192.0.2.8")),
            "IPv4 peers must not share one key"
        );
        assert_eq!(limit_key(v6("2001:db8:1:2::1")), limit_key(v6("2001:db8:1:2:ffff::9")));
        assert_ne!(limit_key(v6("2001:db8:1:2::1")), limit_key(v6("2001:db8:1:3::1")));
    }

    /// Rotating through one /64 is the same subscriber dialling again.
    #[test]
    fn the_per_ip_ceiling_holds_across_a_64() {
        let config = ServerConfig {
            max_connections_per_ip: 2,
            ..ServerConfig::default()
        };
        let limits = ConnLimits::from_config(&config);
        let v6 = |s: &str| IpAddr::V6(s.parse().unwrap());
        limits.acquire(v6("2001:db8:1:2::1")).unwrap();
        limits.acquire(v6("2001:db8:1:2::2")).unwrap();
        assert_eq!(limits.acquire(v6("2001:db8:1:2::3")), Err("per-IP limit reached"));
        assert!(limits.acquire(v6("2001:db8:1:3::1")).is_ok(), "the next /64 is somebody else");
        limits.release(v6("2001:db8:1:2::1"));
        assert!(limits.acquire(v6("2001:db8:1:2::4")).is_ok(), "released under the same key");
    }

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
