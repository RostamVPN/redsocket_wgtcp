// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Userspace WireGuard peer state via boringtun.

use anyhow::{Context, Result, anyhow};
use base64::Engine as _;
use boringtun::noise::{Packet, Tunn, TunnResult};

use boringtun::x25519::{PublicKey, StaticSecret};
use std::time::Duration;

/// WireGuard's maximum transport message: 65535 inner + 32 bytes of framing.
const MAX_WG_MSG: usize = 65535 + 32;

/// Mask for the random sender index: boringtun keeps the low 8 bits as its
/// per-handshake counter, so only the 24 bits above them are ours to pick.
const INDEX_MASK: u32 = 0x00FF_FFFF;

/// Parse a WireGuard key in either base64 (wg format) or hex.
pub fn parse_key(s: &str) -> Result<[u8; 32]> {
    let s = s.trim();
    let bytes = if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        hex::decode(s).context("decode hex key")?
    } else {
        base64::engine::general_purpose::STANDARD
            .decode(s)
            .context("decode base64 key")?
    };
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("key must be 32 bytes, got {}", bytes.len()))?;
    Ok(arr)
}

/// Render a key as base64, matching `wg`'s output format.
pub fn key_to_base64(key: &[u8; 32]) -> String {
    base64::engine::general_purpose::STANDARD.encode(key)
}

/// The first eight characters of a key's base64 form, for logs: enough to tell
/// peers apart without writing a durable identifier.
pub fn key_label(key: &[u8; 32]) -> String {
    format!("{}…", &key_to_base64(key)[..8])
}

/// What the caller must do after feeding the tunnel some input.
pub enum Action {
    /// Nothing to do.
    None,
    /// Write this WireGuard message to the carrier.
    ToCarrier(Vec<u8>),
    /// Deliver this inner IP packet to the local network stack.
    ToStack(Vec<u8>),
}

/// A single WireGuard peer relationship (the server), driven in userspace.
pub struct WgPeer {
    tunn: Tunn,
    /// Scratch for boringtun output. Sized for the largest WireGuard message so
    /// encapsulate/decapsulate can never truncate.
    scratch: Vec<u8>,
    /// Handshakes completed as initiator, so the carrier can tell a fresh one
    /// from a session left over from an earlier connection.
    handshakes: u64,
}

impl WgPeer {
    pub fn new(
        private_key: [u8; 32],
        peer_public_key: [u8; 32],
        preshared_key: Option<[u8; 32]>,
        persistent_keepalive: Option<u16>,
    ) -> Result<Self> {
        let static_private = StaticSecret::from(private_key);
        let peer_static_public = PublicKey::from(peer_public_key);

        let mut index = [0u8; 4];
        getrandom::fill(&mut index).map_err(|e| anyhow!("session index: {e}"))?;

        let tunn = Tunn::new(
            static_private,
            peer_static_public,
            preshared_key,
            persistent_keepalive,
            u32::from_le_bytes(index) & INDEX_MASK,
            None,
        );

        Ok(Self {
            tunn,
            scratch: vec![0u8; MAX_WG_MSG],
            handshakes: 0,
        })
    }

    /// Our public key, for pasting into the server's peer config.
    pub fn public_key(private_key: &[u8; 32]) -> [u8; 32] {
        let secret = StaticSecret::from(*private_key);
        PublicKey::from(&secret).to_bytes()
    }

    /// Force a handshake initiation. Used at startup and after carrier replacement,
    /// where the old session's endpoint is gone.
    pub fn initiate_handshake(&mut self) -> Result<Vec<u8>> {
        match self
            .tunn
            .format_handshake_initiation(&mut self.scratch, true)
        {
            TunnResult::WriteToNetwork(buf) => Ok(buf.to_vec()),
            TunnResult::Err(e) => Err(anyhow!("handshake initiation: {e:?}")),
            _ => Err(anyhow!("handshake initiation produced no packet")),
        }
    }

    /// Feed an inner IP packet from the local stack; get the encrypted WireGuard
    /// message to put on the carrier.
    pub fn encapsulate(&mut self, packet: &[u8]) -> Result<Action> {
        match self.tunn.encapsulate(packet, &mut self.scratch) {
            TunnResult::Done => Ok(Action::None),
            TunnResult::WriteToNetwork(buf) => Ok(Action::ToCarrier(buf.to_vec())),
            TunnResult::Err(e) => Err(anyhow!("encapsulate: {e:?}")),

            _ => Ok(Action::None),
        }
    }

    /// Feed a WireGuard message received from the carrier.
    pub fn decapsulate(&mut self, datagram: &[u8]) -> Result<Action> {
        let is_response = matches!(
            Tunn::parse_incoming_packet(datagram),
            Ok(Packet::HandshakeResponse(_))
        );
        let action = match self.tunn.decapsulate(None, datagram, &mut self.scratch) {
            TunnResult::Done => Action::None,
            TunnResult::WriteToNetwork(buf) => Action::ToCarrier(buf.to_vec()),
            TunnResult::WriteToTunnelV4(buf, _) | TunnResult::WriteToTunnelV6(buf, _) => {
                Action::ToStack(buf.to_vec())
            }
            TunnResult::Err(e) => return Err(anyhow!("decapsulate: {e:?}")),
        };
        if is_response {
            self.handshakes += 1;
        }
        Ok(action)
    }

    /// Handshakes completed as initiator; only a valid response counts.
    pub fn handshakes(&self) -> u64 {
        self.handshakes
    }

    pub fn drain_queued(&mut self, out: &mut Vec<Vec<u8>>) -> Result<()> {
        loop {
            match self.tunn.decapsulate(None, &[], &mut self.scratch) {
                TunnResult::WriteToNetwork(buf) => out.push(buf.to_vec()),
                TunnResult::Done => return Ok(()),
                TunnResult::Err(e) => return Err(anyhow!("drain queued: {e:?}")),
                _ => return Ok(()),
            }
        }
    }

    /// Drive WireGuard's timers: rekeying, keepalives, and handshake retry.
    pub fn update_timers(&mut self) -> Result<Action> {
        match self.tunn.update_timers(&mut self.scratch) {
            TunnResult::Done => Ok(Action::None),
            TunnResult::WriteToNetwork(buf) => Ok(Action::ToCarrier(buf.to_vec())),
            TunnResult::Err(boringtun::noise::errors::WireGuardError::ConnectionExpired) => {
                Err(anyhow!("connection expired"))
            }
            TunnResult::Err(e) => Err(anyhow!("update_timers: {e:?}")),
            _ => Ok(Action::None),
        }
    }

    /// Time since the last completed handshake; `None` before the first one. Used
    /// as the liveness signal for carrier health.
    pub fn time_since_last_handshake(&self) -> Option<Duration> {
        self.tunn.time_since_last_handshake()
    }

    /// `(last_handshake, tx_bytes, rx_bytes, estimated_loss, rtt)`.
    pub fn stats(&self) -> (Option<Duration>, usize, usize, f32, Option<u32>) {
        self.tunn.stats()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_base64_and_hex_keys() {
        let raw = [0x42u8; 32];
        let b64 = key_to_base64(&raw);
        let hexed = hex::encode(raw);

        assert_eq!(parse_key(&b64).unwrap(), raw);
        assert_eq!(parse_key(&hexed).unwrap(), raw);

        assert_eq!(parse_key(&format!("  {b64}\n")).unwrap(), raw);
    }

    #[test]
    fn labels_keys_by_prefix_only() {
        assert_eq!(key_label(&[0x11u8; 32]), "ERERERER…");
    }

    #[test]
    fn rejects_wrong_length_keys() {
        assert!(parse_key("deadbeef").is_err());
        assert!(parse_key("").is_err());
    }

    /// Public key derivation must match `wg pubkey`, otherwise the server rejects
    /// our handshake with no useful diagnostic.
    #[test]
    fn derives_public_key_from_private() {
        let priv_b64 = "zQPL1Tmelil0ONXOkSkK6vfCz5zgp+VhyHUir+mGXDQ=";
        let expect_pub_b64 = "5kTIpNvETFay4qHyWHp4X8WBOrp0Z04VFFXVHPhtxAU=";

        let sk = parse_key(priv_b64).unwrap();
        let pk = WgPeer::public_key(&sk);
        assert_eq!(key_to_base64(&pk), expect_pub_b64);
    }

    /// A fresh peer must produce a well-formed handshake initiation: type 1, 148
    /// bytes (WireGuard's fixed initiation size).
    #[test]
    fn produces_valid_handshake_initiation() {
        let sk = [0x11u8; 32];
        let peer_pk = WgPeer::public_key(&[0x22u8; 32]);
        let mut peer = WgPeer::new(sk, peer_pk, None, Some(25)).unwrap();

        let init = peer.initiate_handshake().unwrap();
        assert_eq!(init.len(), 148, "handshake initiation must be 148 bytes");
        assert_eq!(init[0], 1, "message type must be HANDSHAKE_INITIATION");
        assert_eq!(&init[1..4], &[0, 0, 0], "reserved bytes must be zero");
    }

    /// The sender index in the initiation must not be a constant that a passive
    /// observer can match: two fresh peers with the same keys must differ.
    #[test]
    fn sender_index_is_random_per_peer() {
        let sk = [0x11u8; 32];
        let peer_pk = WgPeer::public_key(&[0x22u8; 32]);
        let index = |peer: &mut WgPeer| {
            let init = peer.initiate_handshake().unwrap();
            u32::from_le_bytes(init[4..8].try_into().unwrap())
        };
        let a = index(&mut WgPeer::new(sk, peer_pk, None, None).unwrap());
        let b = index(&mut WgPeer::new(sk, peer_pk, None, None).unwrap());
        assert_ne!(a, b, "sender index must be random per peer");
    }

    /// Two peers configured with each other's keys must complete a handshake and
    /// then carry an inner packet. This exercises the exact call sequence the
    /// carrier uses, without any sockets.
    #[test]
    fn two_peers_complete_handshake_and_exchange_data() {
        let a_sk = [0x01u8; 32];
        let b_sk = [0x02u8; 32];
        let a_pk = WgPeer::public_key(&a_sk);
        let b_pk = WgPeer::public_key(&b_sk);

        let mut a = WgPeer::new(a_sk, b_pk, None, None).unwrap();
        let mut b = WgPeer::new(b_sk, a_pk, None, None).unwrap();

        let init = a.initiate_handshake().unwrap();
        assert_eq!(
            a.handshakes(),
            0,
            "nothing is completed before the response"
        );
        let resp = match b.decapsulate(&init).unwrap() {
            Action::ToCarrier(buf) => buf,
            _ => panic!("responder should emit a handshake response"),
        };
        assert_eq!(resp[0], 2, "message type must be HANDSHAKE_RESPONSE");

        match a.decapsulate(&resp).unwrap() {
            Action::None | Action::ToCarrier(_) => {}
            Action::ToStack(_) => panic!("response is not tunnel data"),
        }
        assert!(
            a.time_since_last_handshake().is_some(),
            "initiator should have a completed handshake"
        );
        assert_eq!(a.handshakes(), 1, "a valid response completes a handshake");
        assert_eq!(b.handshakes(), 0, "the responder initiated nothing");

        let inner = build_test_ipv4_packet();
        let wire = match a.encapsulate(&inner).unwrap() {
            Action::ToCarrier(buf) => buf,
            _ => panic!("expected an encrypted transport message"),
        };
        assert_eq!(wire[0], 4, "message type must be DATA");

        match b.decapsulate(&wire).unwrap() {
            Action::ToStack(pkt) => assert_eq!(pkt, inner, "inner packet must round-trip"),
            _ => panic!("responder should surface the inner packet"),
        }

        assert!(
            a.decapsulate(&resp).is_err(),
            "a replayed response is refused"
        );
        assert_eq!(a.handshakes(), 1, "a refused response must not count");
    }

    /// Minimal well-formed IPv4 header + payload, since boringtun inspects the
    /// version nibble and total length when routing decapsulated packets.
    fn build_test_ipv4_packet() -> Vec<u8> {
        let payload = b"redsocket-wgtcp";
        let total_len = (20 + payload.len()) as u16;
        let mut p = Vec::new();
        p.push(0x45);
        p.push(0x00);
        p.extend_from_slice(&total_len.to_be_bytes());
        p.extend_from_slice(&[0x00, 0x00]);
        p.extend_from_slice(&[0x40, 0x00]);
        p.push(64);
        p.push(17);
        p.extend_from_slice(&[0x00, 0x00]);
        p.extend_from_slice(&[10, 50, 0, 2]);
        p.extend_from_slice(&[10, 50, 0, 1]);
        p.extend_from_slice(payload);
        p
    }
}
