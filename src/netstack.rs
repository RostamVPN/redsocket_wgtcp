// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Userspace TCP/IP stack driving the tunnel's inner packets.

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Checksum, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{IpAddress, IpCidr, IpEndpoint};
use std::collections::VecDeque;

/// Inner-tunnel MTU.
pub const TUNNEL_MTU: usize = 1380;

/// Per-socket ring sizes.
const TCP_RX_BUF: usize = 256 * 1024;
const TCP_TX_BUF: usize = 256 * 1024;

/// Convert a std address into smoltcp's wire type.
pub fn to_smoltcp(addr: std::net::IpAddr) -> IpAddress {
    match addr {
        std::net::IpAddr::V4(a) => IpAddress::Ipv4(a),
        std::net::IpAddr::V6(a) => IpAddress::Ipv6(a),
    }
}

/// A smoltcp `Device` whose wire is a pair of packet queues.
pub struct TunnelDevice {
    /// Inner packets smoltcp wants sent to the peer (stack -> WireGuard).
    tx: VecDeque<Vec<u8>>,
    /// Inner packets received from the peer (WireGuard -> stack).
    rx: VecDeque<Vec<u8>>,
    mtu: usize,
}

impl TunnelDevice {
    pub fn new(mtu: usize) -> Self {
        Self {
            tx: VecDeque::new(),
            rx: VecDeque::new(),
            mtu,
        }
    }

    /// Queue an inner packet decrypted from the carrier for the stack to read.
    pub fn push_inbound(&mut self, packet: Vec<u8>) {
        self.rx.push_back(packet);
    }

    /// Take the next inner packet the stack wants to transmit.
    pub fn pop_outbound(&mut self) -> Option<Vec<u8>> {
        self.tx.pop_front()
    }

    pub fn has_outbound(&self) -> bool {
        !self.tx.is_empty()
    }
}

impl Device for TunnelDevice {
    type RxToken<'a> = TunnelRxToken;
    type TxToken<'a> = TunnelTxToken<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let buffer = self.rx.pop_front()?;
        Some((TunnelRxToken { buffer }, TunnelTxToken { tx: &mut self.tx }))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(TunnelTxToken { tx: &mut self.tx })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;

        caps.checksum.ipv4 = Checksum::Tx;
        caps.checksum.tcp = Checksum::Tx;
        caps.checksum.udp = Checksum::Tx;
        caps.checksum.icmpv4 = Checksum::Tx;

        caps.checksum.icmpv6 = Checksum::Both;
        caps
    }
}

pub struct TunnelRxToken {
    buffer: Vec<u8>,
}

impl RxToken for TunnelRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buffer)
    }
}

pub struct TunnelTxToken<'a> {
    tx: &'a mut VecDeque<Vec<u8>>,
}

impl TxToken for TunnelTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        self.tx.push_back(buffer);
        result
    }
}

/// The tunnel's network stack: one interface, many TCP sockets.
pub struct NetStack {
    pub iface: Interface,
    pub device: TunnelDevice,
    pub sockets: SocketSet<'static>,
    /// Ephemeral source ports for outbound tunneled connections.
    next_port: u16,
}

impl NetStack {
    /// Build the stack with the tunnel's inner address and the inner MTU.
    pub fn new(address: IpAddress, prefix_len: u8, gateway: IpAddress, mtu: usize) -> Self {
        let mut device = TunnelDevice::new(mtu);

        let config = Config::new(smoltcp::wire::HardwareAddress::Ip);
        let mut iface = Interface::new(config, &mut device, Instant::now());

        iface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(address, prefix_len))
                .expect("interface address list is empty");
        });

        match (address, gateway) {
            (IpAddress::Ipv4(_), IpAddress::Ipv4(gw)) => {
                iface
                    .routes_mut()
                    .add_default_ipv4_route(gw)
                    .expect("route table is empty");
            }
            (IpAddress::Ipv6(_), IpAddress::Ipv6(gw)) => {
                iface
                    .routes_mut()
                    .add_default_ipv6_route(gw)
                    .expect("route table is empty");
            }
            (a, g) => panic!("address {a} and gateway {g} must be the same family"),
        }

        Self {
            iface,
            device,
            sockets: SocketSet::new(Vec::new()),
            next_port: 49152,
        }
    }

    /// Allocate an ephemeral source port from the dynamic range.
    fn alloc_port(&mut self) -> u16 {
        let port = self.next_port;
        self.next_port = if self.next_port == u16::MAX {
            49152
        } else {
            self.next_port + 1
        };
        port
    }

    /// Open a tunneled TCP connection to `dest`.
    pub fn connect(&mut self, dest: IpEndpoint) -> Result<SocketHandle, tcp::ConnectError> {
        let rx_buffer = tcp::SocketBuffer::new(vec![0u8; TCP_RX_BUF]);
        let tx_buffer = tcp::SocketBuffer::new(vec![0u8; TCP_TX_BUF]);
        let mut socket = tcp::Socket::new(rx_buffer, tx_buffer);

        socket.set_timeout(Some(smoltcp::time::Duration::from_secs(30)));
        socket.set_keep_alive(Some(smoltcp::time::Duration::from_secs(15)));

        let local_port = self.alloc_port();
        let handle = self.sockets.add(socket);

        let sock = self.sockets.get_mut::<tcp::Socket>(handle);
        match sock.connect(self.iface.context(), dest, local_port) {
            Ok(()) => Ok(handle),
            Err(e) => {
                self.sockets.remove(handle);
                Err(e)
            }
        }
    }

    /// Run one poll cycle. Returns true if any socket may have changed state.
    pub fn poll(&mut self, timestamp: Instant) -> bool {
        matches!(
            self.iface
                .poll(timestamp, &mut self.device, &mut self.sockets),
            smoltcp::iface::PollResult::SocketStateChanged
        )
    }

    pub fn socket_mut(&mut self, handle: SocketHandle) -> &mut tcp::Socket<'static> {
        self.sockets.get_mut::<tcp::Socket>(handle)
    }

    pub fn remove(&mut self, handle: SocketHandle) {
        self.sockets.remove(handle);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test fixture: the tunnel layout used throughout (10.50.0.2/24 via
    /// 10.50.0.1), parameterized only by the MTU under test.
    fn stack_with_mtu(mtu: usize) -> NetStack {
        NetStack::new(
            to_smoltcp("10.50.0.2".parse().unwrap()),
            24,
            to_smoltcp("10.50.0.1".parse().unwrap()),
            mtu,
        )
    }

    fn test_stack() -> NetStack {
        stack_with_mtu(TUNNEL_MTU)
    }

    /// Anything emitted by the stack must fit the tunnel MTU, or the peer silently
    /// drops oversized inner packets.
    #[test]
    fn device_reports_layer3_capabilities() {
        let dev = TunnelDevice::new(TUNNEL_MTU);
        let caps = dev.capabilities();
        assert_eq!(caps.medium, Medium::Ip);
        assert_eq!(caps.max_transmission_unit, TUNNEL_MTU);

        assert!(matches!(caps.checksum.tcp, Checksum::Tx));
        assert!(matches!(caps.checksum.ipv4, Checksum::Tx));
        assert!(matches!(caps.checksum.udp, Checksum::Tx));

        assert!(matches!(caps.checksum.icmpv6, Checksum::Both));
    }

    #[test]
    fn device_queues_move_packets_in_both_directions() {
        let mut dev = TunnelDevice::new(TUNNEL_MTU);
        assert!(!dev.has_outbound());

        let token = dev.transmit(Instant::now()).unwrap();
        token.consume(4, |buf| buf.copy_from_slice(&[1, 2, 3, 4]));
        assert!(dev.has_outbound());
        assert_eq!(dev.pop_outbound().unwrap(), vec![1, 2, 3, 4]);
        assert!(dev.pop_outbound().is_none());

        dev.push_inbound(vec![9, 8, 7]);
        let (rx, _tx) = dev.receive(Instant::now()).unwrap();
        rx.consume(|buf| assert_eq!(buf, &[9, 8, 7]));
    }

    #[test]
    fn receive_yields_nothing_when_idle() {
        let mut dev = TunnelDevice::new(TUNNEL_MTU);
        assert!(dev.receive(Instant::now()).is_none());
    }

    /// A connect() must actually emit a SYN into the device queue — this is the
    /// seam where the stack meets the tunnel, and a misconfigured route or address
    /// silently produces nothing.
    #[test]
    fn connect_emits_syn_into_tunnel() {
        let mut stack = test_stack();

        let dest = IpEndpoint::new(IpAddress::v4(1, 1, 1, 1), 443);
        stack.connect(dest).expect("connect should queue a SYN");
        stack.poll(Instant::now());

        let pkt = stack
            .device
            .pop_outbound()
            .expect("stack must emit a packet for the tunnel");

        assert_eq!(pkt[0] >> 4, 4, "must be IPv4");
        assert_eq!(pkt[9], 6, "must be TCP");
        assert_eq!(&pkt[12..16], &[10, 50, 0, 2], "source is our tunnel IP");
        assert_eq!(&pkt[16..20], &[1, 1, 1, 1], "destination is the target");
        assert!(pkt.len() <= TUNNEL_MTU, "must fit tunnel MTU");

        let ihl = ((pkt[0] & 0x0F) as usize) * 4;
        let flags = pkt[ihl + 13];
        assert_eq!(flags & 0x02, 0x02, "SYN must be set");
        assert_eq!(flags & 0x10, 0x00, "ACK must be clear on initial SYN");
    }

    /// Default route is what lets us reach destinations outside the tunnel subnet;
    /// without it connect() succeeds but nothing is ever emitted.
    #[test]
    fn routes_offsubnet_traffic_through_gateway() {
        let mut stack = test_stack();

        let dest = IpEndpoint::new(IpAddress::v4(8, 8, 8, 8), 53);
        stack.connect(dest).unwrap();
        stack.poll(Instant::now());
        assert!(
            stack.device.pop_outbound().is_some(),
            "off-subnet destination must still be routed into the tunnel"
        );
    }

    /// The configured MTU must actually reach the device and cap emitted packets.
    #[test]
    fn configured_mtu_reaches_the_device_and_caps_packets() {
        const SMALL_MTU: usize = 1000;
        let mut stack = stack_with_mtu(SMALL_MTU);
        assert_eq!(
            stack.device.capabilities().max_transmission_unit,
            SMALL_MTU,
            "configured MTU must reach the smoltcp device"
        );

        let dest = IpEndpoint::new(IpAddress::v4(1, 1, 1, 1), 443);
        let handle = stack.connect(dest).unwrap();
        stack.poll(Instant::now());
        let _ = stack.socket_mut(handle).send_slice(&[0u8; 8192]);
        stack.poll(Instant::now());

        while let Some(pkt) = stack.device.pop_outbound() {
            assert!(
                pkt.len() <= SMALL_MTU,
                "emitted packet {} exceeds MTU {}",
                pkt.len(),
                SMALL_MTU
            );
        }
    }

    /// The SYN's advertised MSS must follow the configured MTU, since that is what
    /// stops the far end sending us oversized segments.
    #[test]
    fn advertised_mss_follows_configured_mtu() {
        fn mss_for(mtu: usize) -> u16 {
            let mut stack = stack_with_mtu(mtu);
            let dest = IpEndpoint::new(IpAddress::v4(1, 1, 1, 1), 443);
            stack.connect(dest).unwrap();
            stack.poll(Instant::now());
            let pkt = stack.device.pop_outbound().expect("SYN");

            let ihl = ((pkt[0] & 0x0F) as usize) * 4;
            let tcp = &pkt[ihl..];
            let data_off = ((tcp[12] >> 4) as usize) * 4;
            let mut i = 20;
            while i < data_off {
                match tcp[i] {
                    0 => break,
                    1 => i += 1,
                    2 => return u16::from_be_bytes([tcp[i + 2], tcp[i + 3]]),
                    _ => i += tcp[i + 1] as usize,
                }
            }
            panic!("no MSS option in SYN");
        }

        let small = mss_for(1000);
        let large = mss_for(TUNNEL_MTU);
        assert!(small < large, "smaller MTU must advertise a smaller MSS");

        assert_eq!(small, (1000 - 40) as u16);
    }

    /// A v6 tunnel must emit routable IPv6 packets. This is the client-side half of
    /// the stateless v6 addressing the server derives.
    #[test]
    fn v6_stack_emits_ipv6_syn_into_tunnel() {
        let mut stack = NetStack::new(
            to_smoltcp("fd00:5ed0:c0de::2".parse().unwrap()),
            64,
            to_smoltcp("fd00:5ed0:c0de::1".parse().unwrap()),
            TUNNEL_MTU,
        );

        let dest: std::net::IpAddr = "2606:4700:4700::1111".parse().unwrap();
        stack
            .connect(IpEndpoint::new(to_smoltcp(dest), 443))
            .expect("v6 connect should queue a SYN");
        stack.poll(Instant::now());

        let pkt = stack
            .device
            .pop_outbound()
            .expect("v6 stack must emit a packet");

        assert_eq!(pkt[0] >> 4, 6, "must be IPv6");
        assert_eq!(pkt[6], 6, "next header must be TCP");
        let src: std::net::Ipv6Addr = "fd00:5ed0:c0de::2".parse().unwrap();
        let dst: std::net::Ipv6Addr = "2606:4700:4700::1111".parse().unwrap();
        assert_eq!(&pkt[8..24], &src.octets(), "source is our tunnel address");
        assert_eq!(&pkt[24..40], &dst.octets(), "destination is the target");
        assert!(pkt.len() <= TUNNEL_MTU, "must fit tunnel MTU");

        let flags = pkt[40 + 13];
        assert_eq!(flags & 0x02, 0x02, "SYN must be set");
        assert_eq!(flags & 0x10, 0x00, "ACK must be clear on initial SYN");
    }

    /// Off-subnet v6 destinations must still route via the gateway, the same
    /// property the v4 path relies on.
    #[test]
    fn v6_routes_offsubnet_traffic_through_gateway() {
        let mut stack = NetStack::new(
            to_smoltcp("fd00:5ed0:c0de::2".parse().unwrap()),
            64,
            to_smoltcp("fd00:5ed0:c0de::1".parse().unwrap()),
            TUNNEL_MTU,
        );

        let dest: std::net::IpAddr = "2001:4860:4860::8888".parse().unwrap();
        stack
            .connect(IpEndpoint::new(to_smoltcp(dest), 53))
            .unwrap();
        stack.poll(Instant::now());
        assert!(
            stack.device.pop_outbound().is_some(),
            "off-subnet v6 destination must still be routed into the tunnel"
        );
    }

    /// ICMPv6 carries neighbour discovery; without checksum handling a v6 tunnel
    /// fails to resolve its gateway and looks like a dead link.
    #[test]
    fn device_computes_icmpv6_checksums() {
        let dev = TunnelDevice::new(TUNNEL_MTU);
        assert!(matches!(dev.capabilities().checksum.icmpv6, Checksum::Both));
    }

    /// Mixing families can never route, so it must fail loudly at construction
    /// rather than silently dropping every packet.
    #[test]
    #[should_panic(expected = "same family")]
    fn mismatched_address_families_panic() {
        NetStack::new(
            to_smoltcp("10.50.0.2".parse().unwrap()),
            24,
            to_smoltcp("fd00:5ed0:c0de::1".parse().unwrap()),
            TUNNEL_MTU,
        );
    }

    #[test]
    fn allocates_distinct_ephemeral_ports() {
        let mut stack = test_stack();
        let a = stack.alloc_port();
        let b = stack.alloc_port();
        assert_ne!(a, b);
        assert!(a >= 49152, "ports must come from the dynamic range");
    }

    /// The wraparound branch: at u16::MAX the counter must fold back into the
    /// dynamic range rather than overflow. Long-lived clients reach this.
    #[test]
    fn ephemeral_ports_wrap_without_overflow() {
        let mut stack = test_stack();
        stack.next_port = u16::MAX;
        assert_eq!(stack.alloc_port(), u16::MAX, "must hand out the last port");
        assert_eq!(stack.alloc_port(), 49152, "must wrap to the dynamic range");

        for _ in 0..(u16::MAX as u32 - 49152 + 10) {
            let p = stack.alloc_port();
            assert!(p >= 49152, "every port stays in the dynamic range");
        }
    }
}
