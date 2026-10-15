// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! redsocket-wgtcp-server — userspace WireGuard server with a WGTCP carrier.

use anyhow::{Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;

use redsocket_wgtcp::server::addressing;
use redsocket_wgtcp::server::engine::Engine;
use redsocket_wgtcp::server::listener::{self, ListenerConfig};
use redsocket_wgtcp::server::peers::PeerRegistry;
use redsocket_wgtcp::server::run;
use redsocket_wgtcp::wg;

#[derive(Debug, Deserialize, Serialize)]
struct ServerConfig {
    /// Server's WireGuard private key.
    private_key: String,

    /// Every listener. Repeat the block for more addresses or transports.
    listen: Vec<ListenerConfig>,

    /// TUN device name for egress.
    #[serde(default = "default_tun_name")]
    tun_name: String,

    /// Server's address inside the tunnel.
    address: Ipv4Addr,

    /// Tunnel prefix length; defines the client address pool.
    #[serde(default = "default_prefix")]
    prefix_len: u8,

    /// Inner MTU.
    #[serde(default = "default_mtu")]
    mtu: u16,

    /// IPv6 prefix for stateless per-peer addressing.
    #[serde(default)]
    v6_prefix: Option<Ipv6Addr>,

    /// Prefix length for `v6_prefix`. Must be a multiple of 8.
    #[serde(default = "default_v6_prefix_len")]
    v6_prefix_len: u8,

    /// Statically configured peers. A production deployment would push these
    /// through the provisioning API instead.
    #[serde(default)]
    peers: Vec<PeerConfig>,
}

#[derive(Debug, Deserialize, Serialize)]
struct PeerConfig {
    public_key: String,
    /// The inner address for this peer. Omit to derive one from the public key
    /// inside `v6_prefix`, which is the stateless path.
    #[serde(default)]
    allowed_ip: Option<IpAddr>,
    #[serde(default)]
    preshared_key: Option<String>,
}

fn default_tun_name() -> String {
    "wgs0".to_string()
}

fn default_prefix() -> u8 {
    24
}

fn default_mtu() -> u16 {
    1380
}

fn default_v6_prefix_len() -> u8 {
    48
}

#[derive(Parser)]
#[command(
    name = "redsocket-wgtcp-server",
    about = "Userspace WireGuard server: many listeners, TCP and UDP at once"
)]
struct Cli {
    #[arg(short, long)]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cli = Cli::parse();

    let text = std::fs::read_to_string(&cli.config)
        .with_context(|| format!("read {}", cli.config.display()))?;
    let cfg: ServerConfig = toml::from_str(&text).context("parse server config")?;

    let private_key = wg::parse_key(&cfg.private_key).context("private_key")?;
    let registry = Arc::new(PeerRegistry::new(private_key));
    log::info!(
        "server public key: {}",
        wg::key_to_base64(&registry.static_public())
    );

    for p in &cfg.peers {
        let pk = wg::parse_key(&p.public_key)
            .with_context(|| format!("peer public_key {}", p.public_key))?;
        let psk = match &p.preshared_key {
            Some(s) if !s.is_empty() => Some(wg::parse_key(s)?),
            _ => None,
        };

        let ip = match (p.allowed_ip, cfg.v6_prefix) {
            (Some(ip), _) => ip,
            (None, Some(prefix)) => {
                IpAddr::V6(addressing::derive_ipv6(prefix, cfg.v6_prefix_len, &pk))
            }
            (None, None) => {
                return Err(anyhow::anyhow!(
                    "peer {} has no allowed_ip and no v6_prefix is configured \
                     to derive one from",
                    p.public_key
                ));
            }
        };

        let peer = registry.add_peer(pk, ip, psk)?;
        log::info!("peer {} -> {}", peer.label(), ip);
    }
    log::info!("{} peer(s) registered", registry.len());

    let listeners = listener::validate(&cfg.listen)?;
    for (addr, transport) in &listeners {
        log::info!("configured listener {}/{}", addr, transport.as_str());
    }

    let engine = Arc::new(Engine::new(registry));

    let mut tun_cfg = tun::Configuration::default();
    tun_cfg
        .tun_name(&cfg.tun_name)
        .address(cfg.address)
        .netmask(prefix_to_netmask(cfg.prefix_len))
        .mtu(cfg.mtu)
        .up();

    let device = tun::create_as_async(&tun_cfg)
        .with_context(|| format!("create TUN device {} (needs CAP_NET_ADMIN)", cfg.tun_name))?;
    log::info!(
        "TUN {} up at {}/{} mtu {}",
        cfg.tun_name,
        cfg.address,
        cfg.prefix_len,
        cfg.mtu
    );

    if let Some(prefix) = cfg.v6_prefix {
        let cidr = format!("{}/{}", prefix, cfg.v6_prefix_len);
        let status = std::process::Command::new("ip")
            .args(["-6", "addr", "add", &cidr, "dev", &cfg.tun_name])
            .status();
        match status {
            Ok(s) if s.success() => log::info!("TUN {} v6 prefix {}", cfg.tun_name, cidr),
            Ok(s) => log::warn!(
                "could not add v6 prefix {} to {} (exit {}); \
                 IPv6 peers will not be routable",
                cidr,
                cfg.tun_name,
                s
            ),
            Err(e) => log::warn!("could not run `ip -6 addr add`: {e}"),
        }
    }

    let (tun_tx, mut tun_rx) = mpsc::channel::<Vec<u8>>(1024);
    let (mut tun_reader, mut tun_writer) = tokio::io::split(device);

    let to_tun = tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        while let Some(pkt) = tun_rx.recv().await {
            if tun_writer.write_all(&pkt).await.is_err() {
                break;
            }
        }
    });

    let engine_rx = engine.clone();
    let from_tun = tokio::spawn(async move {
        use tokio::io::AsyncReadExt;
        let mut buf = vec![0u8; 65536];
        loop {
            match tun_reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => run::route_to_peer(&engine_rx, buf[..n].to_vec()).await,
            }
        }
    });

    let engine_timers = engine.clone();
    let timers = tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_millis(250));
        loop {
            tick.tick().await;
            let mut out = Vec::new();
            engine_timers.tick_timers(&mut out);
            for (peer, msg) in out {
                if let Some(carrier) = peer.carrier() {
                    let _ = carrier.tx.send(msg).await;
                }
            }
        }
    });

    let result = run::serve(engine, listeners, tun_tx).await;

    to_tun.abort();
    from_tun.abort();
    timers.abort();
    result
}

fn prefix_to_netmask(prefix: u8) -> Ipv4Addr {
    let bits: u32 = if prefix >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix)
    };
    Ipv4Addr::from(bits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_prefix_to_netmask() {
        assert_eq!(prefix_to_netmask(24), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(prefix_to_netmask(16), Ipv4Addr::new(255, 255, 0, 0));
        assert_eq!(prefix_to_netmask(8), Ipv4Addr::new(255, 0, 0, 0));
        assert_eq!(prefix_to_netmask(32), Ipv4Addr::new(255, 255, 255, 255));
    }

    /// The documented multi-listener config must parse, including the simultaneous
    /// TCP+UDP form that motivated this server.
    #[test]
    fn parses_multi_listener_config() {
        let src = r#"
private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
address = "10.50.0.1"

[[listen]]
address = "0.0.0.0:443"
transport = "tcp"

[[listen]]
address = "0.0.0.0:51820"
transport = "udp"

[[peers]]
public_key = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
allowed_ip = "10.50.0.2"
"#;
        let cfg: ServerConfig = toml::from_str(src).unwrap();
        assert_eq!(cfg.listen.len(), 2);
        assert_eq!(cfg.peers.len(), 1);
        assert_eq!(cfg.tun_name, "wgs0");
        assert_eq!(cfg.mtu, 1380);
        listener::validate(&cfg.listen).unwrap();
    }
}
