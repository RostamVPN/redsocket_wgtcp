// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Listener configuration and binding.

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// Carrier transport for a single listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    /// WGTCP: length-delimited records over a long-lived TCP connection.
    Tcp,
    /// Stock WireGuard: one datagram per message, no record header.
    Udp,
}

impl Transport {
    pub fn as_str(&self) -> &'static str {
        match self {
            Transport::Tcp => "tcp",
            Transport::Udp => "udp",
        }
    }
}

/// One configured listener.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenerConfig {
    /// Bind address, `ip:port`. IPv6 uses bracket notation.
    pub address: String,
    pub transport: Transport,
}

impl ListenerConfig {
    pub fn socket_addr(&self) -> Result<SocketAddr> {
        self.address
            .parse::<SocketAddr>()
            .with_context(|| format!("parse listen address {:?}", self.address))
    }
}

/// Validate a set of listeners, rejecting configurations that would fail or
/// silently shadow each other at bind time.
pub fn validate(listeners: &[ListenerConfig]) -> Result<Vec<(SocketAddr, Transport)>> {
    if listeners.is_empty() {
        return Err(anyhow!("at least one [[listen]] entry is required"));
    }

    let mut resolved = Vec::with_capacity(listeners.len());
    for l in listeners {
        resolved.push((l.socket_addr()?, l.transport));
    }

    let mut seen = std::collections::HashSet::new();
    for (addr, transport) in &resolved {
        if !seen.insert((*addr, *transport)) {
            return Err(anyhow!(
                "duplicate listener {}/{}",
                addr,
                transport.as_str()
            ));
        }
    }

    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(address: &str, transport: Transport) -> ListenerConfig {
        ListenerConfig {
            address: address.to_string(),
            transport,
        }
    }

    /// Feature request 1: several address/port pairs on one instance.
    #[test]
    fn accepts_multiple_addresses() {
        let ls = vec![
            cfg("0.0.0.0:443", Transport::Tcp),
            cfg("0.0.0.0:8443", Transport::Tcp),
            cfg("127.0.0.1:9443", Transport::Tcp),
        ];
        let out = validate(&ls).unwrap();
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].0.port(), 443);
        assert_eq!(out[2].0.port(), 9443);
    }

    /// Feature request 2: TCP and UDP at the same time, one instance.
    #[test]
    fn accepts_tcp_and_udp_simultaneously() {
        let ls = vec![
            cfg("0.0.0.0:443", Transport::Tcp),
            cfg("0.0.0.0:51820", Transport::Udp),
        ];
        let out = validate(&ls).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].1, Transport::Tcp);
        assert_eq!(out[1].1, Transport::Udp);
    }

    /// TCP and UDP are separate namespaces, so the same port on both is a
    /// legitimate and useful configuration, not a conflict.
    #[test]
    fn same_port_on_both_transports_is_allowed() {
        let ls = vec![
            cfg("0.0.0.0:443", Transport::Tcp),
            cfg("0.0.0.0:443", Transport::Udp),
        ];
        assert!(validate(&ls).is_ok());
    }

    /// The same address and transport twice would fail at bind with EADDRINUSE
    /// halfway through startup; reject it up front instead.
    #[test]
    fn rejects_exact_duplicates() {
        let ls = vec![
            cfg("0.0.0.0:443", Transport::Tcp),
            cfg("0.0.0.0:443", Transport::Tcp),
        ];
        let err = validate(&ls).unwrap_err().to_string();
        assert!(err.contains("duplicate"), "unexpected error: {err}");
    }

    #[test]
    fn accepts_ipv6_and_dual_stack() {
        let ls = vec![
            cfg("[::]:443", Transport::Tcp),
            cfg("0.0.0.0:443", Transport::Tcp),
        ];
        let out = validate(&ls).unwrap();
        assert!(out[0].0.is_ipv6());
        assert!(out[1].0.is_ipv4());
    }

    #[test]
    fn rejects_empty_and_malformed() {
        assert!(validate(&[]).is_err());
        assert!(validate(&[cfg("not-an-address", Transport::Tcp)]).is_err());

        assert!(validate(&[cfg("10.0.0.1", Transport::Tcp)]).is_err());
    }

    /// The TOML shape users will actually write.
    #[test]
    fn parses_the_documented_toml_form() {
        let toml_src = r#"
[[listen]]
address = "0.0.0.0:443"
transport = "tcp"

[[listen]]
address = "0.0.0.0:51820"
transport = "udp"
"#;
        #[derive(Deserialize)]
        struct Wrapper {
            listen: Vec<ListenerConfig>,
        }
        let w: Wrapper = toml::from_str(toml_src).unwrap();
        assert_eq!(w.listen.len(), 2);
        assert_eq!(w.listen[0].transport, Transport::Tcp);
        assert_eq!(w.listen[1].transport, Transport::Udp);
        validate(&w.listen).unwrap();
    }
}
