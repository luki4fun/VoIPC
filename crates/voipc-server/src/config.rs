use std::net::{SocketAddr, ToSocketAddrs};

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;

/// Server configuration, loaded from a TOML file. Unknown keys are refused, so
/// a typo (`tcp_fallbak`) stops the start instead of quietly keeping a default,
/// and an older server refuses a newer config rather than half-applying it.
/// 1.x only ever adds keys.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Gone since 0.5.0 (the page moved to `tcp_port`); still accepted so an
    /// old file starts.
    #[serde(default)]
    #[allow(dead_code)]
    pub(crate) web_port: Option<u16>,

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
    /// (`GET /voipc` over TLS ALPN `http/1.1`, which the relay offers anyway
    /// for files; with this off, that path answers 403).
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

    /// The encrypted file cache (`[files]`). On by default, with caps.
    #[serde(default)]
    pub files: FilesConfig,
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

/// `[files]`: blobs of files posted in chat, which members' clients seal
/// before they upload them, so the relay holds ciphertext it has no key for.
/// A blob is kept while it is fetched, and never longer than `max_age_hours`
/// after it arrived; a member who has the file uploads it again when someone
/// asks after that. Everything here is wiped when the relay starts.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FilesConfig {
    pub enabled: bool,
    /// Largest blob (MiB). A blob is the file, deflated where that helps,
    /// plus 32 bytes and 16 more per 64 KiB. Files go up to 64 MiB, so this
    /// goes up to 65, which carries every one of them.
    pub max_size_mb: u32,
    /// A blob nobody fetched for this long is deleted.
    pub cache_mins: u32,
    /// A blob is deleted this long after it arrived, however often it is
    /// fetched: otherwise anyone holding its id could keep it here for ever.
    pub max_age_hours: u32,
    /// All blobs together (MiB). When full, the least recently used goes.
    pub max_total_mb: u32,
    /// Per connection and per address (an IPv6 /64): a guest can reconnect
    /// for a fresh connection budget, not a fresh address.
    pub upload_mb_per_hour: u32,
    pub download_mb_per_hour: u32,
    /// Relative to the working directory (`/data` in the container). Only
    /// blob files are wiped from it at start, never anything else there.
    pub dir: String,
}

impl Default for FilesConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_size_mb: 10,
            cache_mins: 30,
            max_age_hours: 24,
            max_total_mb: 1024,
            upload_mb_per_hour: 200,
            download_mb_per_hour: 2000,
            dir: "files".into(),
        }
    }
}

impl ServerConfig {
    /// Numbers that would make the server look up but not work: refused at
    /// the start, where the operator sees why (1.0 audit H1-06).
    pub fn validate(&self) -> Result<()> {
        if self.max_users == 0 {
            return Err(anyhow!("max_users must be at least 1"));
        }
        if self.max_connections_per_ip < 2 {
            return Err(anyhow!(
                "max_connections_per_ip must be at least 2 (a browser holds two connections)"
            ));
        }
        if self.accounts.mode != AccountsMode::Off {
            if self.accounts.quota_mb == 0 {
                return Err(anyhow!("[accounts] quota_mb must be at least 1: with 0, a new account's vault cannot be stored"));
            }
            if self.accounts.retention_days == 0 {
                return Err(anyhow!("[accounts] retention_days must be at least 1: with 0, a kept message expires as it arrives"));
            }
        }
        let f = &self.files;
        if f.enabled {
            if !(1..=65).contains(&f.max_size_mb) {
                return Err(anyhow!(
                    "[files] max_size_mb must be 1 to 65: files go up to 64 MiB, a little more sealed"
                ));
            }
            if f.cache_mins == 0 {
                return Err(anyhow!("[files] cache_mins must be at least 1"));
            }
            if (f.max_age_hours as u64) * 60 < f.cache_mins as u64 {
                return Err(anyhow!(
                    "[files] max_age_hours must be at least cache_mins: a blob would go before it could be fetched again"
                ));
            }
            for (key, mb) in [
                ("max_total_mb", f.max_total_mb),
                ("upload_mb_per_hour", f.upload_mb_per_hour),
                ("download_mb_per_hour", f.download_mb_per_hour),
            ] {
                if mb < f.max_size_mb {
                    return Err(anyhow!(
                        "[files] {key} must be at least max_size_mb: a file of the largest size would never fit"
                    ));
                }
            }
            if f.dir.trim().is_empty() {
                return Err(anyhow!("[files] dir must name a directory"));
            }
        }
        Ok(())
    }

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
            web_port: None,
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
            files: FilesConfig::default(),
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
        assert_eq!(
            config.accounts.mode,
            AccountsMode::Off,
            "no database unless asked for"
        );
        let config: ServerConfig = toml::from_str(
            "cert_path = \"c\"\nkey_path = \"k\"\n[accounts]\nmode = \"optional\"\nregistration = \"open\"\ndatabase = \"postgres://x/y\"",
        )
        .unwrap();
        assert_eq!(config.accounts.mode, AccountsMode::Optional);
        assert_eq!(config.accounts.registration, RegistrationMode::Open);
        assert_eq!(config.accounts.database, "postgres://x/y");
        assert!(config.accounts.cloud, "the rest keep their defaults");
        let typo = toml::from_str::<ServerConfig>(
            "cert_path = \"c\"\nkey_path = \"k\"\n[accounts]\nmod = \"optional\"",
        );
        assert!(typo.is_err(), "an unknown key fails the start");
        let top = toml::from_str::<ServerConfig>(
            "cert_path = \"c\"\nkey_path = \"k\"\ntcp_fallbak = true",
        );
        assert!(
            top.unwrap_err().to_string().contains("tcp_fallbak"),
            "a top-level typo fails the start, by name"
        );
    }

    /// H1-06: numbers that would leave a server up but broken stop the start.
    #[test]
    fn numbers_that_would_break_the_server_are_refused() {
        assert!(ServerConfig::default().validate().is_ok());
        let parse = |extra: &str| {
            toml::from_str::<ServerConfig>(&format!("cert_path = \"c\"\nkey_path = \"k\"\n{extra}"))
                .unwrap()
        };
        let quota = parse("[accounts]\nmode = \"optional\"\nquota_mb = 0");
        assert!(quota
            .validate()
            .unwrap_err()
            .to_string()
            .contains("quota_mb"));
        let retention = parse("[accounts]\nmode = \"optional\"\nretention_days = 0");
        assert!(retention
            .validate()
            .unwrap_err()
            .to_string()
            .contains("retention_days"));
        let off = parse("[accounts]\nquota_mb = 0");
        assert!(off.validate().is_ok(), "no accounts, no quota to mind");
        assert!(parse("max_users = 0").validate().is_err());
        assert!(parse("max_connections_per_ip = 1").validate().is_err());
    }

    #[test]
    fn files_are_on_by_default_with_caps_and_refuse_typos() {
        let config = ServerConfig::default();
        assert!(config.files.enabled);
        assert_eq!(config.files.max_size_mb, 10);
        assert_eq!(config.files.cache_mins, 30);
        assert_eq!(config.files.max_age_hours, 24);
        assert_eq!(config.files.max_total_mb, 1024);
        assert_eq!(config.files.dir, "files");
        let parse = |extra: &str| {
            toml::from_str::<ServerConfig>(&format!("cert_path = \"c\"\nkey_path = \"k\"\n{extra}"))
        };
        let off = parse("[files]\nenabled = false").unwrap();
        assert!(!off.files.enabled);
        assert_eq!(off.files.max_size_mb, 10, "the rest keep their defaults");
        assert!(
            parse("[files]\nmax_size = 5").is_err(),
            "a typo fails the start"
        );

        let refused = |extra: &str| parse(extra).unwrap().validate().unwrap_err().to_string();
        assert!(refused("[files]\nmax_size_mb = 0").contains("max_size_mb"));
        assert!(refused("[files]\nmax_size_mb = 66").contains("max_size_mb"));
        assert!(parse("[files]\nmax_size_mb = 65\nmax_total_mb = 65")
            .unwrap()
            .validate()
            .is_ok());
        assert!(refused("[files]\ncache_mins = 0").contains("cache_mins"));
        assert!(refused("[files]\ncache_mins = 120\nmax_age_hours = 1").contains("max_age_hours"));
        assert!(refused("[files]\nmax_total_mb = 5").contains("max_total_mb"));
        assert!(refused("[files]\nupload_mb_per_hour = 5").contains("upload_mb_per_hour"));
        assert!(refused("[files]\ndownload_mb_per_hour = 5").contains("download_mb_per_hour"));
        assert!(refused("[files]\ndir = \" \"").contains("dir"));
        let off = parse("[files]\nenabled = false\nmax_size_mb = 0").unwrap();
        assert!(off.validate().is_ok(), "no cache, no caps to mind");
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
