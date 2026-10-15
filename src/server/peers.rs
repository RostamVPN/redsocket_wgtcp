// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Multi-peer registry for the userspace WGTCP server.

use anyhow::{Result, anyhow};
use boringtun::noise::Tunn;
use boringtun::x25519::{PublicKey, StaticSecret};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

/// Lock without propagating poisoning: the guarded state is plain data, and a
/// panic in another task must not turn every later caller into a second panic.
pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// One configured peer and its WireGuard state machine.
pub struct Peer {
    /// The peer's static public key — its stable identity.
    pub public_key: [u8; 32],
    /// Our local index for this peer; `receiver_idx >> 8` on the wire.
    pub index: u32,
    /// Inner tunnel address this peer is allowed to use (its AllowedIPs). Inbound
    /// inner packets with a different source are dropped, and outbound packets are
    /// routed to the peer owning the destination.
    pub allowed_ip: IpAddr,
    /// The Noise state machine. Mutex-guarded because a peer may be reachable over
    /// several carriers at once (multiple listeners, TCP and UDP), and `Tunn` is a
    /// single-owner state machine.
    pub tunn: Mutex<Tunn>,
    carrier: Mutex<Option<CarrierPath>>,
}

#[derive(Clone)]
pub struct CarrierPath {
    pub remote: std::net::SocketAddr,
    pub transport: crate::server::listener::Transport,
    pub generation: u64,
    pub tx: tokio::sync::mpsc::Sender<Vec<u8>>,
}

impl Peer {
    /// Human-readable identity for logs. Never logs key material beyond the public
    /// key prefix, which is not secret.
    pub fn label(&self) -> String {
        crate::wg::key_label(&self.public_key)
    }

    /// Adopt a carrier as this peer's current path.
    pub fn set_carrier(
        &self,
        remote: std::net::SocketAddr,
        transport: crate::server::listener::Transport,
        tx: tokio::sync::mpsc::Sender<Vec<u8>>,
        generation: u64,
    ) {
        let mut slot = lock(&self.carrier);
        if let Some(existing) = slot.as_ref() {
            if existing.generation > generation {
                return;
            }

            if existing.remote == remote && existing.transport == transport {
                return;
            }
        }
        *slot = Some(CarrierPath {
            remote,
            transport,
            generation,
            tx,
        });
    }

    pub fn carrier(&self) -> Option<CarrierPath> {
        lock(&self.carrier).clone()
    }
}

/// The server's peer table.
pub struct PeerRegistry {
    /// Server static identity, needed to anonymously parse handshakes.
    static_private: StaticSecret,
    static_public: PublicKey,

    by_pubkey: Mutex<HashMap<[u8; 32], Arc<Peer>>>,
    by_index: Mutex<HashMap<u32, Arc<Peer>>>,
    /// Routes inner destination address -> owning peer.
    by_allowed_ip: Mutex<HashMap<IpAddr, Arc<Peer>>>,

    next_index: AtomicU32,
}

impl PeerRegistry {
    pub fn new(static_private: [u8; 32]) -> Self {
        let sk = StaticSecret::from(static_private);
        let pk = PublicKey::from(&sk);
        Self {
            static_private: sk,
            static_public: pk,
            by_pubkey: Mutex::new(HashMap::new()),
            by_index: Mutex::new(HashMap::new()),
            by_allowed_ip: Mutex::new(HashMap::new()),
            next_index: AtomicU32::new(1),
        }
    }

    pub fn static_public(&self) -> [u8; 32] {
        self.static_public.to_bytes()
    }

    pub fn static_private(&self) -> &StaticSecret {
        &self.static_private
    }

    pub fn len(&self) -> usize {
        lock(&self.by_pubkey).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Register a peer. Idempotent on public key: re-adding an existing peer
    /// replaces its allowed IP and resets its session, which is what a provisioning
    /// API wants when a client is reconfigured.
    pub fn add_peer(
        &self,
        public_key: [u8; 32],
        allowed_ip: IpAddr,
        preshared_key: Option<[u8; 32]>,
    ) -> Result<Arc<Peer>> {
        if public_key == self.static_public.to_bytes() {
            return Err(anyhow!("peer public key equals the server's own key"));
        }

        let index = self.next_index.fetch_add(1, Ordering::Relaxed);
        if index >= (1 << 24) {
            return Err(anyhow!(
                "peer index space exhausted (2^24); shard across servers"
            ));
        }

        let tunn = Tunn::new(
            self.static_private.clone(),
            PublicKey::from(public_key),
            preshared_key,

            None,
            index,
            None,
        );

        let peer = Arc::new(Peer {
            public_key,
            index,
            allowed_ip,
            tunn: Mutex::new(tunn),
            carrier: Mutex::new(None),
        });

        self.remove_peer(&public_key);

        lock(&self.by_pubkey).insert(public_key, peer.clone());
        lock(&self.by_index).insert(index, peer.clone());
        lock(&self.by_allowed_ip).insert(allowed_ip, peer.clone());

        Ok(peer)
    }

    /// Remove a peer and every index pointing at it.
    pub fn remove_peer(&self, public_key: &[u8; 32]) -> bool {
        let existing = lock(&self.by_pubkey).remove(public_key);
        match existing {
            Some(peer) => {
                lock(&self.by_index).remove(&peer.index);
                lock(&self.by_allowed_ip).remove(&peer.allowed_ip);
                true
            }
            None => false,
        }
    }

    pub fn by_pubkey(&self, public_key: &[u8; 32]) -> Option<Arc<Peer>> {
        lock(&self.by_pubkey).get(public_key).cloned()
    }

    /// Look up by the wire's `receiver_idx` (the raw 32-bit session index).
    pub fn by_receiver_idx(&self, receiver_idx: u32) -> Option<Arc<Peer>> {
        lock(&self.by_index).get(&(receiver_idx >> 8)).cloned()
    }

    /// Route an inner destination address to the peer that owns it.
    pub fn by_inner_ip(&self, ip: IpAddr) -> Option<Arc<Peer>> {
        lock(&self.by_allowed_ip).get(&ip).cloned()
    }

    /// All peers, for timer ticks and stats. Clones the Arc list rather than
    /// holding the lock across per-peer work.
    pub fn snapshot(&self) -> Vec<Arc<Peer>> {
        lock(&self.by_pubkey).values().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boringtun::noise::handshake::parse_handshake_anon;
    use boringtun::noise::{Packet, Tunn};

    fn server() -> PeerRegistry {
        PeerRegistry::new([0x11u8; 32])
    }

    #[test]
    fn registers_and_looks_up_by_every_key() {
        let reg = server();
        let pk = crate::wg::WgPeer::public_key(&[0x22u8; 32]);
        let ip = IpAddr::V4(std::net::Ipv4Addr::new(10, 50, 0, 2));
        let peer = reg.add_peer(pk, ip, None).unwrap();

        assert_eq!(reg.len(), 1);
        assert_eq!(reg.by_pubkey(&pk).unwrap().index, peer.index);

        assert_eq!(reg.by_receiver_idx(peer.index << 8).unwrap().public_key, pk);
        assert_eq!(reg.by_inner_ip(ip).unwrap().public_key, pk);
    }

    /// A task that panics while holding a peer lock must not turn every later
    /// lock into a second panic.
    #[test]
    fn locking_survives_poisoning() {
        let m = Arc::new(Mutex::new(7u32));
        let poisoner = m.clone();
        let _ = std::thread::spawn(move || {
            let _guard = poisoner.lock().unwrap();
            panic!("poison");
        })
        .join();
        assert!(m.is_poisoned());
        assert_eq!(*lock(&m), 7);
    }

    #[test]
    fn rejects_self_as_peer() {
        let reg = server();
        let own = reg.static_public();
        assert!(
            reg.add_peer(own, IpAddr::V4(std::net::Ipv4Addr::new(10, 50, 0, 9)), None)
                .is_err()
        );
    }

    #[test]
    fn removal_clears_all_indexes() {
        let reg = server();
        let pk = crate::wg::WgPeer::public_key(&[0x33u8; 32]);
        let ip = IpAddr::V4(std::net::Ipv4Addr::new(10, 50, 0, 5));
        let peer = reg.add_peer(pk, ip, None).unwrap();
        let idx = peer.index;

        assert!(reg.remove_peer(&pk));
        assert!(reg.by_pubkey(&pk).is_none());
        assert!(reg.by_receiver_idx(idx << 8).is_none());
        assert!(reg.by_inner_ip(ip).is_none());
        assert!(!reg.remove_peer(&pk), "second removal is a no-op");
    }

    /// Re-adding must not leave the old index or IP resolving to a stale peer.
    #[test]
    fn readding_replaces_without_leaking_stale_indexes() {
        let reg = server();
        let pk = crate::wg::WgPeer::public_key(&[0x44u8; 32]);
        let old_ip = IpAddr::V4(std::net::Ipv4Addr::new(10, 50, 0, 7));
        let new_ip = IpAddr::V4(std::net::Ipv4Addr::new(10, 50, 0, 8));

        let first = reg.add_peer(pk, old_ip, None).unwrap();
        let second = reg.add_peer(pk, new_ip, None).unwrap();

        assert_eq!(reg.len(), 1, "re-add must not duplicate the peer");
        assert_ne!(first.index, second.index, "a fresh index is assigned");
        assert!(
            reg.by_receiver_idx(first.index << 8).is_none(),
            "old index must not resolve"
        );
        assert!(reg.by_inner_ip(old_ip).is_none(), "old IP must not resolve");
        assert_eq!(reg.by_inner_ip(new_ip).unwrap().index, second.index);
    }

    #[test]
    fn assigns_distinct_indexes() {
        let reg = server();
        let mut seen = std::collections::HashSet::new();
        for i in 0..256u16 {
            let pk = crate::wg::WgPeer::public_key(&[(i % 251) as u8 + 1; 32]);
            let mut key = pk;
            key[0] = (i & 0xFF) as u8;
            key[1] = (i >> 8) as u8;
            let ip = IpAddr::V4(std::net::Ipv4Addr::new(
                10,
                50,
                (i >> 8) as u8,
                (i & 0xFF) as u8,
            ));
            let p = reg.add_peer(key, ip, None).unwrap();
            assert!(seen.insert(p.index), "index {} reused", p.index);
        }
    }

    /// Carrier adoption must be monotonic: a delayed packet arriving on a path the
    /// peer already roamed away from must not drag it backwards.
    #[test]
    fn carrier_roaming_ignores_stale_generations() {
        use crate::server::listener::Transport;
        let reg = server();
        let pk = crate::wg::WgPeer::public_key(&[0x99u8; 32]);
        let peer = reg
            .add_peer(pk, IpAddr::V4(std::net::Ipv4Addr::new(10, 50, 0, 3)), None)
            .unwrap();

        assert!(peer.carrier().is_none(), "no carrier before any traffic");

        let (tx1, _r1) = tokio::sync::mpsc::channel(1);
        let (tx2, _r2) = tokio::sync::mpsc::channel(1);
        let (tx3, _r3) = tokio::sync::mpsc::channel(1);

        let a: std::net::SocketAddr = "203.0.113.5:1111".parse().unwrap();
        let b: std::net::SocketAddr = "203.0.113.9:2222".parse().unwrap();
        let stale: std::net::SocketAddr = "203.0.113.1:3333".parse().unwrap();

        peer.set_carrier(a, Transport::Tcp, tx1, 10);
        assert_eq!(peer.carrier().unwrap().remote, a);

        peer.set_carrier(b, Transport::Tcp, tx2, 11);
        assert_eq!(peer.carrier().unwrap().remote, b, "must adopt newer path");

        peer.set_carrier(stale, Transport::Tcp, tx3, 5);
        assert_eq!(
            peer.carrier().unwrap().remote,
            b,
            "stale generation must not displace the current carrier"
        );
    }

    /// A peer may legitimately move between transports (TCP blocked -> UDP).
    #[test]
    fn carrier_can_switch_transport() {
        use crate::server::listener::Transport;
        let reg = server();
        let pk = crate::wg::WgPeer::public_key(&[0xAAu8; 32]);
        let peer = reg
            .add_peer(pk, IpAddr::V4(std::net::Ipv4Addr::new(10, 50, 0, 4)), None)
            .unwrap();

        let (tx1, _r1) = tokio::sync::mpsc::channel(1);
        let (tx2, _r2) = tokio::sync::mpsc::channel(1);
        let addr: std::net::SocketAddr = "203.0.113.7:443".parse().unwrap();

        peer.set_carrier(addr, Transport::Tcp, tx1, 1);
        assert_eq!(peer.carrier().unwrap().transport, Transport::Tcp);

        peer.set_carrier(addr, Transport::Udp, tx2, 2);
        assert_eq!(
            peer.carrier().unwrap().transport,
            Transport::Udp,
            "same address on a different transport is a new path"
        );
    }

    /// The load-bearing server primitive: identify an unknown initiator from a
    /// handshake that carries no cleartext identity. Without this the server cannot
    /// support peers behind NAT with no configured endpoint.
    #[test]
    fn identifies_unknown_initiator_from_anonymous_handshake() {
        let server_priv = [0x55u8; 32];
        let reg = PeerRegistry::new(server_priv);

        let client_priv = [0x66u8; 32];
        let client_pub = crate::wg::WgPeer::public_key(&client_priv);
        reg.add_peer(
            client_pub,
            IpAddr::V4(std::net::Ipv4Addr::new(10, 50, 0, 2)),
            None,
        )
        .unwrap();

        let mut client = Tunn::new(
            StaticSecret::from(client_priv),
            PublicKey::from(reg.static_public()),
            None,
            None,
            0,
            None,
        );
        let mut buf = vec![0u8; 2048];
        let init = match client.format_handshake_initiation(&mut buf, false) {
            boringtun::noise::TunnResult::WriteToNetwork(b) => b.to_vec(),
            other => panic!("expected handshake initiation, got {other:?}"),
        };

        let packet = Tunn::parse_incoming_packet(&init).unwrap();
        let hh = match packet {
            Packet::HandshakeInit(ref hi) => parse_handshake_anon(
                reg.static_private(),
                &PublicKey::from(reg.static_public()),
                hi,
            )
            .expect("anonymous parse must succeed"),
            other => panic!("expected HandshakeInit, got {other:?}"),
        };

        assert_eq!(
            hh.peer_static_public, client_pub,
            "recovered identity must match the real client"
        );
        assert!(
            reg.by_pubkey(&hh.peer_static_public).is_some(),
            "recovered key must resolve to a registered peer"
        );
    }

    /// An initiator we never registered must be identifiable but unresolvable.
    #[test]
    fn unregistered_initiator_does_not_resolve() {
        let reg = PeerRegistry::new([0x77u8; 32]);
        let stranger = crate::wg::WgPeer::public_key(&[0x88u8; 32]);
        assert!(reg.by_pubkey(&stranger).is_none());
    }
}
