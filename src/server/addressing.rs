// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Stateless inner-address derivation.

use blake2::Blake2sVar;
use blake2::digest::{Update, VariableOutput};
use std::net::{IpAddr, Ipv6Addr};

/// Derive a peer's inner IPv6 address from its public key.
pub fn derive_ipv6(prefix: Ipv6Addr, prefix_len: u8, public_key: &[u8; 32]) -> Ipv6Addr {
    assert!(
        prefix_len.is_multiple_of(8),
        "prefix_len must be a whole number of bytes"
    );
    assert!(prefix_len <= 96, "prefix must leave at least 32 host bits");

    let prefix_bytes = (prefix_len / 8) as usize;
    let host_bytes = 16 - prefix_bytes;

    let mut hasher = Blake2sVar::new(host_bytes).expect("host_bytes is within BLAKE2s range");
    hasher.update(b"redsocket-wgtcp inner-v6 v1");
    hasher.update(public_key);
    let mut host = vec![0u8; host_bytes];
    hasher
        .finalize_variable(&mut host)
        .expect("output size matches");

    let mut octets = prefix.octets();

    for o in octets.iter_mut().skip(prefix_bytes) {
        *o = 0;
    }
    octets[prefix_bytes..].copy_from_slice(&host);

    let addr = Ipv6Addr::from(octets);

    if octets[prefix_bytes..].iter().all(|b| *b == 0) {
        let mut fixed = octets;
        fixed[15] = 1;
        return Ipv6Addr::from(fixed);
    }

    addr
}

/// Read a 4- or 16-byte address out of an inner IP packet.
fn addr_at(packet: &[u8], v4_at: usize, v6_at: usize) -> Option<IpAddr> {
    match packet.first()? >> 4 {
        4 if packet.len() >= 20 => {
            let o: [u8; 4] = packet[v4_at..v4_at + 4].try_into().ok()?;
            Some(IpAddr::from(o))
        }
        6 if packet.len() >= 40 => {
            let o: [u8; 16] = packet[v6_at..v6_at + 16].try_into().ok()?;
            Some(IpAddr::from(o))
        }
        _ => None,
    }
}

/// Source address of an inner IP packet, either family.
pub fn inner_source(packet: &[u8]) -> Option<IpAddr> {
    addr_at(packet, 12, 8)
}

/// Destination address of an inner IP packet, either family.
pub fn inner_destination(packet: &[u8]) -> Option<IpAddr> {
    addr_at(packet, 16, 24)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn prefix48() -> Ipv6Addr {
        "fd00:5ed0:c0de::".parse().unwrap()
    }

    /// The property the whole design rests on: same key in, same address out,
    /// forever, on any machine. If this ever fails, peers silently lose
    /// reachability after a restart.
    #[test]
    fn derivation_is_deterministic() {
        let pk = [0x42u8; 32];
        let a = derive_ipv6(prefix48(), 48, &pk);
        let b = derive_ipv6(prefix48(), 48, &pk);
        assert_eq!(a, b);
    }

    /// A pinned vector, so an accidental change to the hash input (domain
    /// separator, ordering) is caught rather than silently re-homing every peer in
    /// the fleet.
    #[test]
    fn derivation_matches_pinned_vector() {
        let pk = [0u8; 32];
        let addr = derive_ipv6(prefix48(), 48, &pk);
        assert_eq!(
            addr.to_string(),
            "fd00:5ed0:c0de:a887:e557:e40e:3625:86ef",
            "derivation changed; every existing peer would move address"
        );
    }

    #[test]
    fn address_lands_inside_the_prefix() {
        let pk = [0x99u8; 32];
        let addr = derive_ipv6(prefix48(), 48, &pk);
        let o = addr.octets();
        assert_eq!(
            &o[..6],
            &prefix48().octets()[..6],
            "prefix must be preserved"
        );
    }

    /// Passing a fully-specified address rather than a bare prefix must not leak
    /// the caller's host bits into the result.
    #[test]
    fn ignores_host_bits_in_the_supplied_prefix() {
        let pk = [0x7fu8; 32];
        let bare: Ipv6Addr = "fd00:5ed0:c0de::".parse().unwrap();
        let dirty: Ipv6Addr = "fd00:5ed0:c0de:ffff:ffff:ffff:ffff:ffff".parse().unwrap();
        assert_eq!(derive_ipv6(bare, 48, &pk), derive_ipv6(dirty, 48, &pk));
    }

    /// Different keys must not collide in practice. 100k keys is far too few to hit
    /// the birthday bound at 80 host bits, so any collision here means the
    /// derivation is broken (e.g. ignoring most of the key).
    #[test]
    fn distinct_keys_give_distinct_addresses() {
        let mut seen = HashSet::new();
        for i in 0..100_000u32 {
            let mut pk = [0u8; 32];
            pk[..4].copy_from_slice(&i.to_le_bytes());
            let addr = derive_ipv6(prefix48(), 48, &pk);
            assert!(seen.insert(addr), "collision at key {i}: {addr}");
        }
    }

    /// Every byte of the key must affect the output, or an attacker could find a
    /// second key mapping to a victim's address.
    #[test]
    fn every_key_byte_affects_the_address() {
        let base = [0u8; 32];
        let base_addr = derive_ipv6(prefix48(), 48, &base);
        for i in 0..32 {
            let mut pk = base;
            pk[i] = 1;
            assert_ne!(
                derive_ipv6(prefix48(), 48, &pk),
                base_addr,
                "flipping byte {i} did not change the address"
            );
        }
    }

    #[test]
    fn supports_several_prefix_lengths() {
        let pk = [0x11u8; 32];
        for (p, len) in [
            ("fd00::", 32u8),
            ("fd00:5ed0::", 32),
            ("fd00:5ed0:c0de::", 48),
            ("fd00:5ed0:c0de:1::", 64),
        ] {
            let prefix: Ipv6Addr = p.parse().unwrap();
            let addr = derive_ipv6(prefix, len, &pk);
            let n = (len / 8) as usize;
            assert_eq!(&addr.octets()[..n], &prefix.octets()[..n]);
        }
    }

    #[test]
    fn parses_ipv6_inner_addresses() {
        let src: Ipv6Addr = "fd00:5ed0:c0de::2".parse().unwrap();
        let dst: Ipv6Addr = "2606:4700:4700::1111".parse().unwrap();
        let pkt = build_ipv6(src, dst);
        assert_eq!(inner_source(&pkt), Some(IpAddr::V6(src)));
        assert_eq!(inner_destination(&pkt), Some(IpAddr::V6(dst)));
    }

    /// The v4 path must keep working unchanged, since the tunnel stays dual-stack.
    #[test]
    fn parses_ipv4_inner_addresses() {
        let pkt = build_ipv4(
            std::net::Ipv4Addr::new(10, 50, 0, 2),
            std::net::Ipv4Addr::new(1, 1, 1, 1),
        );
        assert_eq!(
            inner_source(&pkt),
            Some(IpAddr::V4(std::net::Ipv4Addr::new(10, 50, 0, 2)))
        );
        assert_eq!(
            inner_destination(&pkt),
            Some(IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)))
        );
    }

    /// Truncated packets must be rejected rather than read out of bounds — a
    /// 20-byte buffer is a valid IPv4 packet but a truncated IPv6 one.
    #[test]
    fn rejects_truncated_and_unknown_packets() {
        assert_eq!(inner_source(&[]), None);
        assert_eq!(inner_source(&[0x45]), None);
        assert_eq!(
            inner_source(&[0x60; 20]),
            None,
            "short IPv6 must be rejected"
        );
        assert_eq!(
            inner_source(&[0x45; 10]),
            None,
            "short IPv4 must be rejected"
        );
        assert_eq!(inner_source(&[0x35; 64]), None, "version 3 is not IP");
    }

    fn build_ipv6(src: Ipv6Addr, dst: Ipv6Addr) -> Vec<u8> {
        let mut p = vec![0u8; 40];
        p[0] = 0x60;
        p[4] = 0;
        p[5] = 8;
        p[6] = 6;
        p[7] = 64;
        p[8..24].copy_from_slice(&src.octets());
        p[24..40].copy_from_slice(&dst.octets());
        p.extend_from_slice(&[0u8; 8]);
        p
    }

    fn build_ipv4(src: std::net::Ipv4Addr, dst: std::net::Ipv4Addr) -> Vec<u8> {
        let mut p = vec![0x45, 0x00, 0x00, 0x1c, 0, 0, 0x40, 0x00, 64, 6, 0, 0];
        p.extend_from_slice(&src.octets());
        p.extend_from_slice(&dst.octets());
        p.extend_from_slice(&[0u8; 8]);
        p
    }
}
