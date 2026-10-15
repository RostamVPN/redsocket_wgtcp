<!--
Copyright 2026 Internet Mastering & Company, Inc.
SPDX-License-Identifier: Apache-2.0
-->

# redsocket-wgtcp

Standalone **fully userspace** WireGuard-over-TCP client for the WGTCP
carrier protocol.

No kernel module. No TUN device. No root. The client speaks the same wire
format as the WGTCP kernel module, but WireGuard's crypto runs via boringtun
and the tunnel's TCP/IP stack runs via smoltcp — both in process.

```
app ──SOCKS5──▶ smoltcp stack ──inner IP──▶ boringtun ──WG msg──▶ WGTCP record ──▶ TCP :51820 ──▶ server
     127.0.0.1:1080   (userspace TCP/IP)     (Noise IK)      (8-byte header)      long-lived carrier
```

The server side is unmodified: a stock WGTCP kernel module with
`Transport = tcp`. The client is interoperable with it, not a reimplementation
of both ends.

## Why userspace

The kernel WGTCP module needs matching kernel headers, a rebuild on every
kernel bump, module signing or Secure Boot disabled, and root. That is fine on
a server you operate and a non-starter for a client shipped to users. This
client needs none of it: a single static binary and a config file.

The cost is that traffic is not captured transparently — applications opt in
through the local SOCKS5 listener.

## Source map (`src/`)

| File | Role |
|---|---|
| `record.rs` | WGTCP carrier framing: 8-byte encap header, checksum, streaming parser with resynchronization. Byte-compatible with `kernel/socket.h`. |
| `wg.rs` | boringtun wrapper: Noise IK handshake, session keys, replay window, WireGuard timers. Never touches a socket. |
| `netstack.rs` | smoltcp `Device` over in-memory packet queues + the tunnel's interface, routes, and TCP sockets. |
| `carrier.rs` | The single-threaded event loop coupling carrier TCP ⇄ WireGuard ⇄ stack, plus reconnect with backoff. |
| `socks5.rs` | Local SOCKS5 front-end; turns app connections into tunneled smoltcp sockets. |
| `config.rs` | TOML schema and validation. |
| `main.rs` | CLI: `run`, `genkey`, `pubkey`. |

## Wire format

The carrier record header, matching `struct wg_tcp_encap_header`:

```
 0       4     5      6            8              12
 +-------+-----+------+------------+--------------+----------
 | len   |type |flags | checksum   | [frag hdr]   | payload
 | be32  |u8   |u8    | be16       | id/off be16  | WG message
 +-------+-----+------+------------+--------------+----------
```

`len` counts the header. `type` is always 0 (`WG_TCP_RECORD_DATA`). Bit 0 of
`flags` marks an inner-IPv4 fragment and adds a 4-byte fragment header.

The checksum is not cryptographic — it lets a resynchronizing parser reject
candidate offsets cheaply:

```
ck = rotl16( (len>>16) ^ (len&0xFFFF) ^ (flags<<8 | type), 5 ) ^ 0xA5A5
```

## Build

```bash
cargo build --release
# target/release/redsocket-wgtcp
```

## Configure

Generate a keypair and give the public half to the server:

```bash
redsocket-wgtcp genkey
```

```bash
# on the server
wg set wg0 peer <CLIENT_PUBLIC_KEY> allowed-ips 10.50.0.2/32
```

Then write a config (see `config.example.toml`):

```toml
private_key     = "<client private key>"
peer_public_key = "<server public key>"
endpoint        = "203.0.113.20:51820"   # TCP, not UDP
address         = "10.50.0.2"
gateway         = "10.50.0.1"
socks_listen    = "127.0.0.1:1080"
```

## Run

```bash
redsocket-wgtcp run --config config.toml
curl --socks5-hostname 127.0.0.1:1080 https://api.ipify.org
```

## Server-side requirements

The server needs the WGTCP module with `Transport = tcp`, plus forwarding and
NAT for tunneled traffic. On an nftables host:

```bash
sysctl -w net.ipv4.ip_forward=1
nft add table inet wgtcp
nft add chain inet wgtcp postrouting '{ type nat hook postrouting priority 100; policy accept; }'
nft add rule  inet wgtcp postrouting ip saddr 10.50.0.0/24 oifname "<uplink>" masquerade
```

## Validation

Unit and integration tests: `cargo test`, covering the kernel
checksum golden vectors, byte-at-a-time record reassembly, fragment-header
stripping, resynchronization after injected garbage, a full two-peer
WireGuard handshake and data round trip, SYN emission into the tunnel, and
the SOCKS5 state machine.

## Transport support

Both the outer carrier and the inner traffic are **TCP only**.

| Layer | Supported | Notes |
|---|---|---|
| Outer carrier | TCP | `carrier.rs` uses `TcpStream`; every message is wrapped in a WGTCP record unconditionally. There is no transport selector — the server must run `Transport = tcp`. This does not interoperate with stock UDP WireGuard. |
| Inner traffic | TCP | The stack only creates `smoltcp::socket::tcp`. SOCKS5 accepts `CONNECT` and rejects everything else. |

Inner UDP is not implemented: no `socket::udp` in the stack, no SOCKS5 UDP
ASSOCIATE. That means QUIC, plain-UDP games, and DNS cannot traverse the
tunnel.

## Inner addressing

The tunnel is dual-stack. IPv4 peers take an explicit `allowed_ip`; IPv6
peers can instead have their address **derived from their public key**, which
removes address allocation from the system entirely:

```toml
v6_prefix     = "fd00:5ed0:c0de::"
v6_prefix_len = 48

[[peers]]
public_key = "..."      # no allowed_ip — the address is derived
```

```text
addr = prefix | BLAKE2s("redsocket-wgtcp inner-v6 v1" || pubkey)[..host_bytes]
```

At a /48 there are 80 host bits, so across a 10M-peer population the
probability of *any* collision is ~4e-11. Because the address is a pure
function of identity there is nothing to allocate, recycle, persist, or
reconcile after a restart — a peer's address is recomputable anywhere from
its public key alone, in any language. Provisioning reduces from an
allocator with a lifecycle to an entitlement lookup.

For comparison, IPv4 `10/8` holds 16,777,216 addresses: 1.68x a 10M
population, which forces dense allocation with aggressive reuse and makes a
leaked lease a permanent capacity loss.

Anti-spoofing applies to both families: a peer may only source traffic from
the address it was allocated or derived.

## Measured performance

Two campaigns, answering different questions.

**Single stream, over the real internet** — bounded by the path, not the CPU,
so both implementations tie. Median of 5 runs per size:

| Payload | userspace | kernel module |
|---|---|---|
| 1 MB | 22.9 Mbit/s | 22.6 Mbit/s |
| 5 MB | 30.4 Mbit/s | 29.6 Mbit/s |
| 10 MB | 32.7 Mbit/s | 31.8 Mbit/s |

**Aggregate concurrency, loopback** (`tests/bench_sweep.sh`) — everything on
one 4-core host with no external network, so the CPU is the bottleneck and
the packet path is what is actually measured. Each client is a distinct peer,
so per-peer state and peer lookup are exercised, not one hot session.

| Clients | Streams | userspace | kernel | Δ |
|---|---|---|---|---|
| 1 | 4 | 1745 Mbit/s | 1206 Mbit/s | +44.7% |
| 2 | 8 | 2129 Mbit/s | 1612 Mbit/s | +32.1% |
| 3 | 12 | 2010 Mbit/s | 1808 Mbit/s | +11.2% |
| 7 | 28 | 1878 Mbit/s | 1859 Mbit/s | +1.0% |

Mean across those levels: **1941 vs 1621 Mbit/s, +19.7% for userspace.**
Per unit of CPU the gap is wider — 24–28 Mbit/s per 1% of system busy versus
17–20 for the kernel module, so **1.24–1.59x the throughput per CPU**.

This is the opposite of the expected result and deserves scepticism rather
than celebration. The likely explanation is that the kernel module's TCP
carrier crosses the kernel/user boundary anyway (its sockets are driven from
kernel threads with their own wakeup and copy costs), so it never gets the
usual in-kernel advantage, while the userspace server batches records into
one write per event-loop cycle. The measurement does not isolate that, so it
remains a hypothesis.

Read these numbers with the caveats:

- The load generator shares the same four cores as the server under test.
  That penalises neither side preferentially but caps absolute throughput —
  these are not capacity figures for a dedicated host.
- Some client processes failed to start at higher levels (13/16 and 7/8 came
  up), so the two highest rows compare unequal client counts. Only the
  equal-count levels are used for the mean above.
- Loopback has no loss, no reordering, and no real RTT. TCP-over-TCP
  behaviour under loss — the main risk of this carrier — is not exercised
  here at all.

## Known limitations

- **DNS leaks by default — because inner UDP is not implemented.** SOCKS5
  domain requests are resolved with the system resolver *before* entering the
  tunnel, since there is no UDP socket inside the tunnel to send a query
  through. This is not an independent setting: closing the leak requires
  adding inner UDP support first. Until then, resolve to literal IPs upstream
  if query visibility matters.
- **IPv4 inside the tunnel.** IPv6 SOCKS5 targets are refused with
  `ATYP not supported` rather than silently hanging.
- **TCP only.** No UDP associate; `CONNECT` is the only supported command.
- **TCP-over-TCP.** The carrier is TCP and so is most tunneled traffic.
  Under loss this compounds retransmission and can stall throughput; see
  `docs/TCP_MELTDOWN.md` in the WGTCP tree.
- Both endpoints must run WGTCP. This does not interoperate with stock
  UDP WireGuard.

## Related repositories

| Repository | Contents |
|---|---|
| `redsocket_http` | The exit server (Rust). |
| `rostamvpn-android` | The Android app and the Rust client cores; vendors this crate under `vendor/redsocket_wgtcp`. |
| `rostamvpn-ios` | The iOS app; its WGTCP framework is built from this crate through `rostamvpn-android/wgtcp-android`. |
| `redsocket_pfe` | AF_XDP triangle-routing front-end. |
| `redsocket_proteus` | The server wrapped in Proteus programmable protocols; intended to replace `redsocket_http` once proven. |

## Removed for publication

Infrastructure addresses, validation tables against live hosts, a GPL-licensed
test oracle, narrative comments and dead code. Third-party dependencies are
vendored under `vendor/` and keep their own license files.
