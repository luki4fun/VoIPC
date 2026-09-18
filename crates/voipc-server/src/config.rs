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

    /// TCP port serving the browser client's page (HTTPS, HTTP/2).
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
    /// Not the same as users: a browser client holds two (the page and the
    /// QUIC session), a native client one. The default allows sixteen browser
    /// users behind one address, because that is what a household, an office
    /// or a school looks like from here — and being refused for sharing a NAT
    /// with your friends is worse than the dial-and-drop loop this bounds,
    /// which `CONNECT_BURST` is the real answer to.
    #[serde(default = "default_max_connections_per_ip")]
    pub max_connections_per_ip: u32,

    /// Path to TLS certificate file (PEM).
    pub cert_path: String,

    /// Path to TLS private key file (PEM).
    pub key_path: String,

    /// Token that turns a session into a server admin (`AdminLogin`).
    /// Unset: a random token is generated at startup and written to the log.
    #[serde(default)]
    pub admin_token: Option<String>,
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
            cert_path: "certs/server.crt".into(),
            key_path: "certs/server.key".into(),
            admin_token: None,
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
