// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! redsocket-wgtcp — fully userspace WireGuard-over-TCP client.

pub mod carrier;
pub mod config;
pub mod netstack;
pub mod record;
pub mod server;
pub mod socks5;
pub mod wg;

use anyhow::{Context, Result};
use tokio::sync::mpsc;

use carrier::{Carrier, ConnectRequest};
use netstack::{NetStack, to_smoltcp};
use wg::WgPeer;

/// Run the client tunnel until `shutdown` flips to true or a layer fails.
pub async fn run_tunnel(
    cfg: config::Config,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let private_key = cfg.private_key_bytes().context("private_key")?;
    let peer_public = cfg.peer_public_key_bytes().context("peer_public_key")?;
    let psk = cfg.preshared_key_bytes().context("preshared_key")?;

    let peer = WgPeer::new(
        private_key,
        peer_public,
        psk,
        Some(cfg.persistent_keepalive),
    )?;

    carrier::set_tunnel_is_ipv6(cfg.address.is_ipv6());

    let stack = NetStack::new(
        to_smoltcp(cfg.address),
        cfg.prefix_len,
        to_smoltcp(cfg.gateway),
        cfg.mtu,
    );
    log::info!(
        "tunnel address {}/{} via {} ({})",
        cfg.address,
        cfg.prefix_len,
        cfg.gateway,
        if cfg.address.is_ipv6() {
            "IPv6"
        } else {
            "IPv4"
        }
    );

    let (connect_tx, connect_rx) = mpsc::channel::<ConnectRequest>(128);
    let listen: std::net::SocketAddr = cfg
        .socks_listen
        .parse()
        .with_context(|| format!("parse socks_listen {}", cfg.socks_listen))?;

    let carrier = Carrier::new(cfg.endpoint.clone(), peer, stack, connect_rx);

    tokio::select! {
        r = carrier.run() => {
            r.context("carrier loop exited")?;
        }
        r = socks5::serve(listen, connect_tx) => {
            r.context("socks5 listener exited")?;
        }
        _ = shutdown.changed() => {
            log::info!("tunnel shutting down on request");
        }
    }

    Ok(())
}

/// Generate a WireGuard keypair.
pub fn generate_keypair() -> (String, String) {
    use base64::Engine;

    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("OS randomness unavailable");
    let secret = boringtun::x25519::StaticSecret::from(seed);
    let public = boringtun::x25519::PublicKey::from(&secret);
    let b64 = base64::engine::general_purpose::STANDARD;
    (b64.encode(secret.as_bytes()), b64.encode(public.as_bytes()))
}
#[cfg(test)]
mod keygen_tests {
    use super::*;
    use base64::Engine;

    #[test]
    fn generates_a_valid_distinct_keypair() {
        let b64 = base64::engine::general_purpose::STANDARD;
        let (priv1, pub1) = generate_keypair();
        let (priv2, pub2) = generate_keypair();

        assert_eq!(b64.decode(&priv1).unwrap().len(), 32);
        assert_eq!(b64.decode(&pub1).unwrap().len(), 32);

        assert_ne!(priv1, priv2, "two calls produced the same private key");
        assert_ne!(pub1, pub2);

        let mut sk = [0u8; 32];
        sk.copy_from_slice(&b64.decode(&priv1).unwrap());
        let derived = boringtun::x25519::PublicKey::from(&boringtun::x25519::StaticSecret::from(sk));
        assert_eq!(b64.encode(derived.as_bytes()), pub1, "public key does not match private");

        assert_ne!(b64.decode(&pub1).unwrap(), vec![0u8; 32], "generated the all-zero point");
    }
}
