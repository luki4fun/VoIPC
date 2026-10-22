use std::net::{SocketAddr, ToSocketAddrs};

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;

/// Server configuration, loaded from a TOML file.
#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    /// IP address to bind on (default "::", the dual-stack wildcard: one
    /// listener serves IPv6 and IPv4 clients). Use "0.0.0.0" for IPv4 only.
    /// Set this to the public/VPN IP that clients connect to so that QUIC
    /// packets are sent from the correct source address — but note that a
    /// concrete IPv4 address leaves a published AAAA record unanswered, and
    /// a browser fails on that where the native client still works.
    #[serde(default = "default_host")]
    pub host: String,

    /// TCP port serving the browser client's page (HTTPS, HTTP/2) and, with
    /// `tcp_fallback`, the tunnel for clients that cannot reach UDP.
    #[serde(default = "default_tcp_port")]
    pub tcp_port: u16,

    /// UDP port of the QUIC endpoint every client connects to (native
    /// clients directly, browsers via the page). Keep it equal to `tcp_port`
    /// so one `host:port` reaches both.
    #[serde(default = "default_udp_port")]
    pub udp_port: u16,

    /// Maximum concurrent users.
    #[serde(default = "default_max_users")]
    pub max_users: u32,

    /// How many connections one IP address may hold at once.
    ///
    /// Not the same as users: a browser client holds two (the page and its
    /// QUIC session or TCP tunnel), a native client one. The default allows sixteen browser
    /// users behind one address, because that is what a household, an office
    /// or a school looks like from here — and being refused for sharing a NAT
    /// with your friends is worse than the dial-and-drop loop this bounds,
    /// which `CONNECT_BURST` is the real answer to.
    #[serde(default = "default_max_connections_per_ip")]
    pub max_connections_per_ip: u32,

    /// Let clients that cannot reach the QUIC endpoint — because something
    /// between them and this server drops UDP — tunnel the whole session,
    /// control, voice and video, through a WebSocket on `tcp_port`
    /// (`GET /voipc`, offered as TLS ALPN `http/1.1` next to the page's `h2`).
    /// Clients try QUIC first and fall back by themselves. Off by default:
    /// TCP stalls on every lost packet, so it is for hosts whose UDP is blocked.
    /// Native clients dial the port they were given over TCP as well, so
    /// they need `tcp_port == udp_port` (the default).
    #[serde(default)]
    pub tcp_fallback: bool,

    /// Path to TLS certificate file (PEM).
    pub cert_path: String,

    /// Path to TLS private key file (PEM).
    pub key_path: String,

    /// Token that turns a session into a server admin (`AdminLogin`).
    /// Unset: a random token is generated at startup and written to the log.
    /// With accounts on, it only claims the first admin account (see
    /// `accounts.rs`).
    #[serde(default)]
    pub admin_token: Option<String>,

    /// Opt-in accounts (`[accounts]`). Off by default: no database is made.
    #[serde(default)]
    pub accounts: AccountsConfig,
}

/// Whether guests may stay when the relay has accounts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum AccountsMode {
    /// No accounts, no database: the relay as it always was.
    #[default]
    Off,
    /// Accounts for whoever wants one; guests (with a #tag) still welcome.
    Optional,
    /// Everybody signs in.
    Required,
}

/// Who may make an account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RegistrationMode {
    /// Anyone, behind a proof of work their client solves.
    Open,
    /// With an admin's invite code.
    #[default]
    Invite,
    /// Only with a code an admin made for that one name.
    Closed,
}

/// `[accounts]`. Unknown keys are refused, so a typo fails the start instead
/// of quietly keeping a default.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AccountsConfig {
    pub mode: AccountsMode,
    /// `sqlite://voipc.db` (a file next to the server) or `postgres://…`.
    pub database: String,
    pub registration: RegistrationMode,
    /// Members may keep an encrypted copy of their messages on the relay.
    pub cloud: bool,
    /// How long a stored message stays at most.
    pub retention_days: u32,
    /// Per account: the vault and stored messages together.
    pub quota_mb: u32,
    /// The master key (seals second-factor secrets). Made on first start,
    /// readable by the server's user only; `VOIPC_ACCOUNTS_KEY` wins over it.
    /// Back it up: without it nobody's two-factor codes work.
    pub key_file: String,
}

impl Default for AccountsConfig {
    fn default() -> Self {
        Self {
            mode: AccountsMode::Off,
            database: "sqlite://voipc.db".into(),
            registration: RegistrationMode::Invite,
            cloud: true,
            retention_days: 365,
            quota_mb: 50,
            key_file: "voipc-accounts.key".into(),
        }
    }
}

impl ServerConfig {
    /// Bind address for `port`.
    ///
    /// `host` may be a bare IPv6 literal (`"::"`), which needs brackets
    /// before it parses as a `SocketAddr`, so go through `ToSocketAddrs`
    /// rather than formatting `host:port` into a string.
    pub fn bind_addr(&self, port: u16) -> Result<SocketAddr> {
        (self.host.as_str(), port)
            .to_socket_addrs()
            .with_context(|| format!("invalid bind address {}:{port}", self.host))?
            .next()
            .ok_or_else(|| anyhow!("{} resolves to no address", self.host))
    }
}

fn default_host() -> String {
    "::".into()
}

fn default_tcp_port() -> u16 {
    9987
}

fn default_udp_port() -> u16 {
    9987
}

fn default_max_users() -> u32 {
    64
}

fn default_max_connections_per_ip() -> u32 {
    32
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: default_host(),
            tcp_port: default_tcp_port(),
            udp_port: default_udp_port(),
            max_users: default_max_users(),
            max_connections_per_ip: default_max_connections_per_ip(),
            tcp_fallback: false,
            cert_path: "certs/server.crt".into(),
            key_path: "certs/server.key".into(),
            admin_token: None,
            accounts: AccountsConfig::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_values() {
        let config = ServerConfig::default();
        assert_eq!(config.tcp_port, 9987);
        assert_eq!(config.udp_port, 9987);
        assert_eq!(config.max_users, 64);
        assert_eq!(config.max_connections_per_ip, 32);
        assert!(!config.tcp_fallback, "the TCP fallback is opt-in");
    }

    #[test]
    fn config_toml_deserialization() {
        // web_port is gone since 0.5.0; a 0.4 config file must still load
        let toml = r#"
            tcp_port = 1234
            udp_port = 5678
            web_port = 0
            max_users = 128
            cert_path = "test.crt"
            key_path = "test.key"
        "#;
        let config: ServerConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.tcp_port, 1234);
        assert_eq!(config.udp_port, 5678);
        assert_eq!(config.max_users, 128);
        assert_eq!(config.cert_path, "test.crt");
        assert!(!config.tcp_fallback);

        let config: ServerConfig =
            toml::from_str("tcp_fallback = true\ncert_path = \"c\"\nkey_path = \"k\"").unwrap();
        assert!(config.tcp_fallback);
    }

    #[test]
    fn accounts_are_off_by_default_and_refuse_typos() {
        let config = ServerConfig::default();
        assert_eq!(config.accounts.mode, AccountsMode::Off, "no database unless asked for");
        let config: ServerConfig = toml::from_str(
            "cert_path = \"c\"\nkey_path = \"k\"\n[accounts]\nmode = \"optional\"\nregistration = \"open\"\ndatabase = \"postgres://x/y\"",
        )
        .unwrap();
        assert_eq!(config.accounts.mode, AccountsMode::Optional);
        assert_eq!(config.accounts.registration, RegistrationMode::Open);
        assert_eq!(config.accounts.database, "postgres://x/y");
        assert!(config.accounts.cloud, "the rest keep their defaults");
        let typo = toml::from_str::<ServerConfig>("cert_path = \"c\"\nkey_path = \"k\"\n[accounts]\nmod = \"optional\"");
        assert!(typo.is_err(), "an unknown key fails the start");
    }

    #[test]
    fn bind_addr_handles_bare_ipv6_literals() {
        let mut config = ServerConfig::default();
        assert_eq!(config.host, "::");
        // "::9987" does not parse as a SocketAddr — the bracketless host must
        // still bind, or the dual-stack default refuses to start.
        assert_eq!(config.bind_addr(9987).unwrap().to_string(), "[::]:9987");

        config.host = "0.0.0.0".into();
        assert_eq!(config.bind_addr(9987).unwrap().to_string(), "0.0.0.0:9987");
    }
}
