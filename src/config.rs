//! Runtime configuration built directly from CLI arguments.

use anyhow::{Result, bail};
use ipnet::IpNet;
use std::net::IpAddr;

pub const DEFAULT_BIND: &str = "127.0.0.1:1080";
pub const DEFAULT_MAX_CONNECTIONS: usize = 1024;
pub const MAX_CONNECTIONS_LIMIT: usize = 1_000_000;

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub bind: String,
    pub max_connections: usize,
}

#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub username: Option<String>,
    pub password: Option<String>,
    pub bypass_ips: Vec<IpNet>,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub server: ServerConfig,
    pub auth: AuthConfig,
}

#[derive(Debug, Clone)]
pub struct RuntimeOptions {
    pub bind: String,
    pub max_connections: usize,
    pub username: Option<String>,
    pub password: Option<String>,
    pub bypass_ips: Vec<String>,
}

impl Config {
    /// Build and validate runtime configuration from raw CLI options.
    pub fn from_runtime_options(options: RuntimeOptions) -> Result<Self> {
        let username = options.username.filter(|value| !value.is_empty());
        let password = options.password.filter(|value| !value.is_empty());
        let bypass_ips = parse_allowlist_entries(options.bypass_ips)?;

        let cfg = Self {
            server: ServerConfig {
                bind: options.bind,
                max_connections: options.max_connections,
            },
            auth: AuthConfig {
                username,
                password,
                bypass_ips,
            },
        };
        cfg.validate()?;
        Ok(cfg)
    }

    /// Validate server, authentication, and allowlist settings.
    pub fn validate(&self) -> Result<()> {
        if self.server.bind.is_empty() {
            bail!("bind address cannot be empty");
        }
        if self.server.max_connections == 0 {
            bail!("--max-connections must be greater than 0");
        }
        if self.server.max_connections > MAX_CONNECTIONS_LIMIT {
            bail!("--max-connections must be less than or equal to {MAX_CONNECTIONS_LIMIT}");
        }
        let has_credentials = self.auth.username.is_some() && self.auth.password.is_some();
        if !has_credentials && self.auth.bypass_ips.is_empty() {
            bail!("provide --username and --password, or configure --bypass-ip");
        }
        if self.auth.username.is_some() != self.auth.password.is_some() {
            bail!("--username and --password must be provided together");
        }
        Ok(())
    }
}

/// Parse all allowlist entries into CIDR networks.
fn parse_allowlist_entries(entries: Vec<String>) -> Result<Vec<IpNet>> {
    entries
        .into_iter()
        .map(|entry| {
            let entry = entry.trim();
            parse_allowlist_entry(entry)
                .ok_or_else(|| anyhow::anyhow!("invalid bypass IP: {entry}"))
        })
        .collect()
}

/// Parse one IP or CIDR allowlist entry.
fn parse_allowlist_entry(entry: &str) -> Option<IpNet> {
    // Accept bare IPs as single-host networks to keep common local allowlists
    // concise while storing everything internally as CIDR.
    if let Ok(net) = entry.parse::<IpNet>() {
        return Some(net);
    }

    if let Ok(addr) = entry.parse::<IpAddr>() {
        let prefix = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if let Ok(net) = IpNet::new(addr, prefix) {
            return Some(net);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn parse_ipv4_without_cidr_defaults_to_host() {
        let net = parse_allowlist_entry("1.2.3.4").expect("should parse IPv4");
        assert_eq!(net.prefix_len(), 32);
        assert_eq!(net.addr(), IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
    }

    #[test]
    fn parse_ipv4_network_preserves_prefix() {
        let net = parse_allowlist_entry("10.0.0.0/8").expect("should parse IPv4 network");
        assert_eq!(net.prefix_len(), 8);
        assert_eq!(net.addr(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)));
    }

    #[test]
    fn parse_ipv6_network() {
        let net = parse_allowlist_entry("2001:db8::/32").expect("should parse IPv6 network");
        assert_eq!(net.prefix_len(), 32);
        assert_eq!(
            net.addr(),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0))
        );
    }

    #[test]
    fn parse_invalid_entry_returns_none() {
        assert!(parse_allowlist_entry("not-an-ip").is_none());
    }
}
