use serde::Deserialize;

/// Server configuration, loaded from a TOML file.
#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    /// IP address to bind on (default "0.0.0.0").
    /// Set this to the public/VPN IP that clients connect to so that QUIC
    /// packets are sent from the correct source address.
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

    /// Path to TLS certificate file (PEM).
    pub cert_path: String,

    /// Path to TLS private key file (PEM).
    pub key_path: String,

    /// Token that turns a session into a server admin (`AdminLogin`).
    /// Unset: a random token is generated at startup and written to the log.
    #[serde(default)]
    pub admin_token: Option<String>,
}

fn default_host() -> String {
    "0.0.0.0".into()
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

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: default_host(),
            tcp_port: default_tcp_port(),
            udp_port: default_udp_port(),
            max_users: default_max_users(),
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
}
