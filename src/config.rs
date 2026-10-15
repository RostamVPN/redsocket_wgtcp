// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Configuration for the userspace WGTCP client.

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::Path;

fn default_socks_listen() -> String {
    "127.0.0.1:1080".to_string()
}

fn default_mtu() -> usize {
    crate::netstack::TUNNEL_MTU
}

fn default_keepalive() -> u16 {
    25
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Our WireGuard private key (base64 as produced by `wg genkey`, or hex).
    pub private_key: String,

    /// Server's WireGuard public key.
    pub peer_public_key: String,

    /// Optional preshared key for post-quantum-ish hardening.
    #[serde(default)]
    pub preshared_key: Option<String>,

    /// Server carrier endpoint, `host:port` — the TCP listener, not UDP.
    pub endpoint: String,

    /// Our address inside the tunnel, e.g. "10.50.0.2" or "fd00:5ed0:c0de::2". The
    /// family determines the tunnel's inner family.
    pub address: IpAddr,

    /// Tunnel prefix length, e.g. 24.
    #[serde(default = "default_prefix")]
    pub prefix_len: u8,

    /// Peer's tunnel address, used as the default route. Must be the same family as
    /// `address`.
    pub gateway: IpAddr,

    /// Local SOCKS5 listen address.
    #[serde(default = "default_socks_listen")]
    pub socks_listen: String,

    /// Inner MTU.
    #[serde(default = "default_mtu")]
    pub mtu: usize,

    /// WireGuard persistent keepalive, seconds.
    #[serde(default = "default_keepalive")]
    pub persistent_keepalive: u16,
}

fn default_prefix() -> u8 {
    24
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("read config {}", path.display()))?;
        let cfg: Config = toml::from_str(&text).context("parse config TOML")?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Validate a config assembled in memory rather than parsed from a file.
    pub fn validate_public(&self) -> Result<()> {
        self.validate()
    }

    fn validate(&self) -> Result<()> {
        crate::wg::parse_key(&self.private_key).context("private_key")?;
        crate::wg::parse_key(&self.peer_public_key).context("peer_public_key")?;
        if let Some(psk) = &self.preshared_key {
            crate::wg::parse_key(psk).context("preshared_key")?;
        }
        if !self.endpoint.contains(':') {
            return Err(anyhow!(
                "endpoint must be host:port (the server's TCP carrier port)"
            ));
        }

        if self.address.is_ipv4() != self.gateway.is_ipv4() {
            return Err(anyhow!(
                "address {} and gateway {} must be the same address family",
                self.address,
                self.gateway
            ));
        }
        let max_prefix = if self.address.is_ipv4() { 32 } else { 128 };
        if self.prefix_len > max_prefix {
            return Err(anyhow!(
                "prefix_len {} must be <= {} for {}",
                self.prefix_len,
                max_prefix,
                if self.address.is_ipv4() {
                    "IPv4"
                } else {
                    "IPv6"
                }
            ));
        }

        let min_mtu = if self.address.is_ipv6() { 1280 } else { 576 };
        if self.mtu < min_mtu || self.mtu > 65535 {
            return Err(anyhow!(
                "mtu {} out of range ({}..65535)",
                self.mtu,
                min_mtu
            ));
        }
        Ok(())
    }

    pub fn private_key_bytes(&self) -> Result<[u8; 32]> {
        crate::wg::parse_key(&self.private_key)
    }

    pub fn peer_public_key_bytes(&self) -> Result<[u8; 32]> {
        crate::wg::parse_key(&self.peer_public_key)
    }

    pub fn preshared_key_bytes(&self) -> Result<Option<[u8; 32]>> {
        match &self.preshared_key {
            Some(s) if !s.is_empty() => Ok(Some(crate::wg::parse_key(s)?)),
            _ => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_toml() -> String {
        format!(
            r#"
private_key = "{}"
peer_public_key = "{}"
endpoint = "203.0.113.109:51820"
address = "10.50.0.2"
gateway = "10.50.0.1"
"#,
            crate::wg::key_to_base64(&[0x11u8; 32]),
            crate::wg::key_to_base64(&[0x22u8; 32]),
        )
    }

    #[test]
    fn parses_minimal_config_with_defaults() {
        let cfg: Config = toml::from_str(&sample_toml()).unwrap();
        cfg.validate().unwrap();

        assert_eq!(cfg.address, "10.50.0.2".parse::<IpAddr>().unwrap());
        assert_eq!(cfg.gateway, "10.50.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(cfg.prefix_len, 24);
        assert_eq!(cfg.socks_listen, "127.0.0.1:1080");
        assert_eq!(cfg.persistent_keepalive, 25);
        assert_eq!(cfg.mtu, crate::netstack::TUNNEL_MTU);
    }

    #[test]
    fn rejects_endpoint_without_port() {
        let bad = sample_toml().replace("203.0.113.109:51820", "203.0.113.109");
        let cfg: Config = toml::from_str(&bad).unwrap();
        assert!(cfg.validate().is_err(), "endpoint without port must fail");
    }

    #[test]
    fn rejects_malformed_keys() {
        let bad =
            sample_toml().replace(&crate::wg::key_to_base64(&[0x11u8; 32]), "not-a-valid-key");
        let cfg: Config = toml::from_str(&bad).unwrap();
        assert!(cfg.validate().is_err(), "bad key must fail validation");
    }

    #[test]
    fn rejects_out_of_range_mtu() {
        let cfg: Config = toml::from_str(&format!("{}\nmtu = 100\n", sample_toml())).unwrap();
        assert!(cfg.validate().is_err());
    }

    /// An IPv6 tunnel is configured the same way, just with v6 literals.
    #[test]
    fn parses_ipv6_tunnel_config() {
        let v6 = sample_toml()
            .replace("10.50.0.2", "fd00:5ed0:c0de::2")
            .replace("10.50.0.1", "fd00:5ed0:c0de::1")
            + "prefix_len = 64\n";
        let cfg: Config = toml::from_str(&v6).unwrap();
        cfg.validate().expect("a v6 tunnel must validate");
        assert!(cfg.address.is_ipv6());
        assert!(cfg.gateway.is_ipv6());
        assert_eq!(cfg.prefix_len, 64);
    }

    /// A v4 address with a v6 gateway can never route; catching it in validation
    /// turns a silent black hole into a startup error.
    #[test]
    fn rejects_mixed_address_families() {
        let mixed = sample_toml().replace("10.50.0.1", "fd00:5ed0:c0de::1");
        let cfg: Config = toml::from_str(&mixed).unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(
            err.contains("same address family"),
            "mixed families must be rejected, got: {err}"
        );
    }

    /// IPv6 prefixes go up to 128; the old v4-only limit of 32 would have rejected
    /// every realistic v6 tunnel.
    #[test]
    fn accepts_v6_prefix_lengths_above_32() {
        let v6 = sample_toml()
            .replace("10.50.0.2", "fd00:5ed0:c0de::2")
            .replace("10.50.0.1", "fd00:5ed0:c0de::1")
            + "prefix_len = 128\n";
        let cfg: Config = toml::from_str(&v6).unwrap();
        assert!(cfg.validate().is_ok(), "/128 is valid for IPv6");

        let bad = sample_toml()
            .replace("10.50.0.2", "fd00:5ed0:c0de::2")
            .replace("10.50.0.1", "fd00:5ed0:c0de::1")
            + "prefix_len = 129\n";
        let cfg: Config = toml::from_str(&bad).unwrap();
        assert!(cfg.validate().is_err(), "/129 must still be rejected");
    }

    /// IPv6 mandates a 1280-byte minimum MTU, so a value legal for v4 must be
    /// refused on a v6 tunnel rather than producing unsendable packets.
    #[test]
    fn enforces_the_ipv6_minimum_mtu() {
        let v6 = sample_toml()
            .replace("10.50.0.2", "fd00:5ed0:c0de::2")
            .replace("10.50.0.1", "fd00:5ed0:c0de::1")
            + "prefix_len = 64\nmtu = 600\n";
        let cfg: Config = toml::from_str(&v6).unwrap();
        assert!(
            cfg.validate().is_err(),
            "600 is below the IPv6 minimum of 1280"
        );

        let v4: Config = toml::from_str(&format!("{}\nmtu = 600\n", sample_toml())).unwrap();
        assert!(v4.validate().is_ok(), "600 is legal for IPv4");
    }

    #[test]
    fn decodes_key_material() {
        let cfg: Config = toml::from_str(&sample_toml()).unwrap();
        assert_eq!(cfg.private_key_bytes().unwrap(), [0x11u8; 32]);
        assert_eq!(cfg.peer_public_key_bytes().unwrap(), [0x22u8; 32]);
        assert_eq!(cfg.preshared_key_bytes().unwrap(), None);
    }
}
