// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The server engine: carriers, peer dispatch, and inner-packet egress.

use anyhow::{Result, anyhow};
use boringtun::noise::handshake::parse_handshake_anon;
use boringtun::noise::{Packet, Tunn, TunnResult};
use boringtun::x25519::PublicKey;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use super::peers::{Peer, PeerRegistry, lock};

pub use super::addressing::{inner_destination, inner_source};

/// Result of feeding one inbound message to the engine.
pub enum Ingress {
    /// Nothing further to do.
    Done,
    /// Send this WireGuard message back to the peer (handshake response, cookie
    /// reply, keepalive).
    Reply(Vec<u8>),
    /// A decrypted inner IP packet to route to the internet.
    Inner { peer: Arc<Peer>, packet: Vec<u8> },
}

/// Hand-written so `Peer` (which holds a `Mutex<Tunn>`) need not be `Debug`,
/// and so decrypted payloads are summarized by length rather than dumped.
impl std::fmt::Debug for Ingress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Ingress::Done => write!(f, "Done"),
            Ingress::Reply(b) => write!(f, "Reply({} bytes)", b.len()),
            Ingress::Inner { peer, packet } => {
                write!(f, "Inner({}, {} bytes)", peer.label(), packet.len())
            }
        }
    }
}

pub struct Engine {
    pub registry: Arc<PeerRegistry>,
    generation: AtomicU64,
    /// Counters, kept as atomics so the stats endpoint never blocks the packet
    /// path.
    pub rx_packets: AtomicU64,
    pub rx_handshakes: AtomicU64,
    pub rx_unknown_peer: AtomicU64,
    pub rx_malformed: AtomicU64,
}

impl Engine {
    pub fn new(registry: Arc<PeerRegistry>) -> Self {
        Self {
            registry,
            generation: AtomicU64::new(1),
            rx_packets: AtomicU64::new(0),
            rx_handshakes: AtomicU64::new(0),
            rx_unknown_peer: AtomicU64::new(0),
            rx_malformed: AtomicU64::new(0),
        }
    }

    pub fn next_generation(&self) -> u64 {
        self.generation.fetch_add(1, Ordering::Relaxed)
    }

    /// Identify which peer an inbound WireGuard message belongs to.
    pub fn identify(&self, datagram: &[u8]) -> Result<Arc<Peer>> {
        let packet = Tunn::parse_incoming_packet(datagram)
            .map_err(|e| anyhow!("malformed WireGuard message: {e:?}"))?;

        match packet {
            Packet::HandshakeInit(ref hi) => {
                let half = parse_handshake_anon(
                    self.registry.static_private(),
                    &PublicKey::from(self.registry.static_public()),
                    hi,
                )
                .map_err(|e| anyhow!("anonymous handshake parse failed: {e:?}"))?;

                self.registry
                    .by_pubkey(&half.peer_static_public)
                    .ok_or_else(|| anyhow!("handshake from unregistered peer"))
            }
            Packet::HandshakeResponse(ref r) => self
                .registry
                .by_receiver_idx(r.receiver_idx)
                .ok_or_else(|| anyhow!("handshake response for unknown index")),
            Packet::PacketCookieReply(ref c) => self
                .registry
                .by_receiver_idx(c.receiver_idx)
                .ok_or_else(|| anyhow!("cookie reply for unknown index")),
            Packet::PacketData(ref d) => self
                .registry
                .by_receiver_idx(d.receiver_idx)
                .ok_or_else(|| anyhow!("data packet for unknown index")),
        }
    }

    /// Feed one inbound WireGuard message from a carrier.
    pub fn ingress(&self, datagram: &[u8]) -> Result<Ingress> {
        self.rx_packets.fetch_add(1, Ordering::Relaxed);

        let is_handshake = matches!(
            Tunn::parse_incoming_packet(datagram),
            Ok(Packet::HandshakeInit(_))
        );
        if is_handshake {
            self.rx_handshakes.fetch_add(1, Ordering::Relaxed);
        }

        let peer = match self.identify(datagram) {
            Ok(p) => p,
            Err(e) => {
                if e.to_string().contains("malformed") {
                    self.rx_malformed.fetch_add(1, Ordering::Relaxed);
                } else {
                    self.rx_unknown_peer.fetch_add(1, Ordering::Relaxed);
                }
                return Err(e);
            }
        };

        let mut scratch = vec![0u8; 65535 + 32];
        let mut tunn = lock(&peer.tunn);

        match tunn.decapsulate(None, datagram, &mut scratch) {
            TunnResult::Done => Ok(Ingress::Done),
            TunnResult::WriteToNetwork(buf) => {
                let reply = buf.to_vec();

                drop(tunn);
                Ok(Ingress::Reply(reply))
            }
            TunnResult::WriteToTunnelV4(buf, src) => {
                let packet = buf.to_vec();
                drop(tunn);
                self.check_source(&peer, std::net::IpAddr::V4(src))?;
                Ok(Ingress::Inner { peer, packet })
            }
            TunnResult::WriteToTunnelV6(buf, src) => {
                let packet = buf.to_vec();
                drop(tunn);
                self.check_source(&peer, std::net::IpAddr::V6(src))?;
                Ok(Ingress::Inner { peer, packet })
            }
            TunnResult::Err(e) => {
                drop(tunn);
                Err(anyhow!("decapsulate: {e:?}"))
            }
        }
    }

    /// Anti-spoofing.
    fn check_source(&self, peer: &Peer, src: std::net::IpAddr) -> Result<()> {
        if src != peer.allowed_ip {
            return Err(anyhow!(
                "peer {} sourced {} but is allocated {}",
                peer.label(),
                src,
                peer.allowed_ip
            ));
        }
        Ok(())
    }

    /// Encrypt an inner IP packet for the peer that owns its destination.
    pub fn egress(&self, peer: &Peer, inner: &[u8]) -> Result<Option<Vec<u8>>> {
        let mut scratch = vec![0u8; 65535 + 32];
        let mut tunn = lock(&peer.tunn);
        match tunn.encapsulate(inner, &mut scratch) {
            TunnResult::Done => Ok(None),
            TunnResult::WriteToNetwork(buf) => Ok(Some(buf.to_vec())),
            TunnResult::Err(e) => Err(anyhow!("encapsulate: {e:?}")),
            _ => Ok(None),
        }
    }

    /// Drive WireGuard timers for every peer. Called on a fixed tick.
    pub fn tick_timers(&self, out: &mut Vec<(Arc<Peer>, Vec<u8>)>) {
        let peers = self.registry.snapshot();
        let mut scratch = vec![0u8; 65535 + 32];
        for peer in peers {
            let mut tunn = lock(&peer.tunn);
            if let TunnResult::WriteToNetwork(buf) = tunn.update_timers(&mut scratch) {
                let msg = buf.to_vec();
                drop(tunn);
                out.push((peer, msg));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wg::WgPeer;
    use boringtun::noise::Tunn;
    use boringtun::x25519::StaticSecret;
    use std::net::{IpAddr, Ipv4Addr};

    fn engine_with_client() -> (Engine, Tunn, [u8; 32]) {
        let server_priv = [0xA1u8; 32];
        let registry = Arc::new(PeerRegistry::new(server_priv));
        let engine = Engine::new(registry.clone());

        let client_priv = [0xB2u8; 32];
        let client_pub = WgPeer::public_key(&client_priv);
        registry
            .add_peer(client_pub, IpAddr::V4(Ipv4Addr::new(10, 50, 0, 2)), None)
            .unwrap();

        let client = Tunn::new(
            StaticSecret::from(client_priv),
            PublicKey::from(registry.static_public()),
            None,
            None,
            0,
            None,
        );
        (engine, client, client_pub)
    }

    /// Drive a full handshake to completion. Returns the initiation so a caller can
    /// assert on it; the client is left with a live session.
    fn handshake(engine: &Engine, client: &mut Tunn) -> Vec<u8> {
        let mut buf = vec![0u8; 2048];
        let init = match client.format_handshake_initiation(&mut buf, false) {
            TunnResult::WriteToNetwork(b) => b.to_vec(),
            other => panic!("expected initiation, got {other:?}"),
        };
        let reply = match engine.ingress(&init).unwrap() {
            Ingress::Reply(r) => r,
            other => panic!("handshake must produce a response, got {other:?}"),
        };
        let mut cbuf = vec![0u8; 2048];
        client.decapsulate(None, &reply, &mut cbuf);
        assert_eq!(reply[0], 2, "must be HANDSHAKE_RESPONSE");
        init
    }

    /// Encrypt an inner packet the way a real client would.
    fn client_send(client: &mut Tunn, inner: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; 2048];
        match client.encapsulate(inner, &mut buf) {
            TunnResult::WriteToNetwork(b) => b.to_vec(),
            other => panic!("expected data packet, got {other:?}"),
        }
    }

    /// The full server-side handshake: an unknown initiator arrives, is identified
    /// anonymously, and receives a valid response.
    #[test]
    fn completes_handshake_with_unknown_initiator() {
        let (engine, mut client, client_pub) = engine_with_client();

        let init = handshake(&engine, &mut client);

        let peer = engine.identify(&init).expect("must identify initiator");
        assert_eq!(peer.public_key, client_pub);
        assert!(
            client.time_since_last_handshake().is_some(),
            "client should consider the handshake complete"
        );
        assert_eq!(engine.rx_handshakes.load(Ordering::Relaxed), 1);
    }

    /// After the handshake, a real inner packet must arrive decrypted.
    #[test]
    fn decrypts_inner_packet_after_handshake() {
        let (engine, mut client, _) = engine_with_client();
        handshake(&engine, &mut client);

        let inner = build_ipv4(Ipv4Addr::new(10, 50, 0, 2), Ipv4Addr::new(1, 1, 1, 1));
        let wire = client_send(&mut client, &inner);

        match engine.ingress(&wire).unwrap() {
            Ingress::Inner { packet, peer } => {
                assert_eq!(packet, inner, "inner packet must survive intact");
                assert_eq!(peer.allowed_ip, Ipv4Addr::new(10, 50, 0, 2));
            }
            other => panic!("expected an inner packet, got {other:?}"),
        }
    }

    /// Anti-spoofing: a peer must not be able to source traffic from another
    /// client's inner address.
    #[test]
    fn rejects_spoofed_inner_source() {
        let (engine, mut client, _) = engine_with_client();
        handshake(&engine, &mut client);

        let spoofed = build_ipv4(Ipv4Addr::new(10, 50, 0, 99), Ipv4Addr::new(1, 1, 1, 1));
        let wire = client_send(&mut client, &spoofed);

        let err = engine.ingress(&wire).unwrap_err().to_string();
        assert!(
            err.contains("sourced"),
            "spoofed source must be rejected, got: {err}"
        );
    }

    #[test]
    fn rejects_handshake_from_unregistered_peer() {
        let server_priv = [0xC3u8; 32];
        let registry = Arc::new(PeerRegistry::new(server_priv));
        let engine = Engine::new(registry.clone());

        let mut stranger = Tunn::new(
            StaticSecret::from([0xD4u8; 32]),
            PublicKey::from(registry.static_public()),
            None,
            None,
            0,
            None,
        );
        let mut buf = vec![0u8; 2048];
        let init = match stranger.format_handshake_initiation(&mut buf, false) {
            TunnResult::WriteToNetwork(b) => b.to_vec(),
            _ => unreachable!(),
        };

        assert!(engine.ingress(&init).is_err());
        assert_eq!(engine.rx_unknown_peer.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn rejects_garbage() {
        let (engine, _, _) = engine_with_client();
        assert!(engine.ingress(&[0xFF; 64]).is_err());
        assert!(engine.ingress(&[]).is_err());
        assert!(engine.rx_malformed.load(Ordering::Relaxed) >= 1);
    }

    #[test]
    fn parses_inner_addresses() {
        let p = build_ipv4(Ipv4Addr::new(10, 50, 0, 2), Ipv4Addr::new(8, 8, 8, 8));
        assert_eq!(
            inner_source(&p),
            Some(IpAddr::V4(Ipv4Addr::new(10, 50, 0, 2)))
        );
        assert_eq!(
            inner_destination(&p),
            Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)))
        );
        assert_eq!(inner_source(&[0u8; 4]), None);
    }

    /// IPv6 inner packets must now be carried, not rejected — and the same anti-
    /// spoof rule must apply to them.
    #[test]
    fn carries_ipv6_inner_packets_and_blocks_v6_spoofing() {
        use std::net::Ipv6Addr;

        let server_priv = [0xE5u8; 32];
        let registry = Arc::new(PeerRegistry::new(server_priv));
        let engine = Engine::new(registry.clone());

        let client_priv = [0xF6u8; 32];
        let client_pub = crate::wg::WgPeer::public_key(&client_priv);

        let prefix: Ipv6Addr = "fd00:5ed0:c0de::".parse().unwrap();
        let allowed = crate::server::addressing::derive_ipv6(prefix, 48, &client_pub);
        registry
            .add_peer(client_pub, IpAddr::V6(allowed), None)
            .unwrap();

        let mut client = Tunn::new(
            StaticSecret::from(client_priv),
            PublicKey::from(registry.static_public()),
            None,
            None,
            0,
            None,
        );
        handshake(&engine, &mut client);

        let inner = build_ipv6(allowed, "2606:4700:4700::1111".parse().unwrap());
        let wire = client_send(&mut client, &inner);
        match engine.ingress(&wire).unwrap() {
            Ingress::Inner { packet, .. } => {
                assert_eq!(packet, inner, "v6 inner packet must survive intact")
            }
            other => panic!("expected an inner packet, got {other:?}"),
        }

        let victim: Ipv6Addr = "fd00:5ed0:c0de:dead:beef::99".parse().unwrap();
        let spoofed = build_ipv6(victim, "2606:4700:4700::1111".parse().unwrap());
        let wire = client_send(&mut client, &spoofed);
        let err = engine.ingress(&wire).unwrap_err().to_string();
        assert!(
            err.contains("sourced"),
            "v6 spoofed source must be rejected, got: {err}"
        );
    }

    fn build_ipv6(src: std::net::Ipv6Addr, dst: std::net::Ipv6Addr) -> Vec<u8> {
        let payload = b"v6-inner";
        let mut p = vec![0u8; 40];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        p[6] = 17;
        p[7] = 64;
        p[8..24].copy_from_slice(&src.octets());
        p[24..40].copy_from_slice(&dst.octets());
        p.extend_from_slice(payload);
        p
    }

    fn build_ipv4(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
        let payload = b"wgtcp-userspace-server";
        let total = (20 + payload.len()) as u16;
        let mut p = Vec::new();
        p.push(0x45);
        p.push(0x00);
        p.extend_from_slice(&total.to_be_bytes());
        p.extend_from_slice(&[0, 0]);
        p.extend_from_slice(&[0x40, 0x00]);
        p.push(64);
        p.push(17);
        p.extend_from_slice(&[0, 0]);
        p.extend_from_slice(&src.octets());
        p.extend_from_slice(&dst.octets());
        p.extend_from_slice(payload);
        p
    }
}
