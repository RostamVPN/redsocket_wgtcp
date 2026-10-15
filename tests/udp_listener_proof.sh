#!/usr/bin/env bash
# Copyright 2026 Internet Mastering & Company, Inc.
# SPDX-License-Identifier: Apache-2.0
set -u

IFACE="${IFACE:-wgprobe}"
UDP_ENDPOINT="${UDP_ENDPOINT:-127.0.0.1:8445}"

: "${SERVER_PUB:?set SERVER_PUB to the server public key}"
: "${CLIENT_PRIV:?set CLIENT_PRIV to a private key registered on the server}"

ip link del "$IFACE" 2>/dev/null
ip link add "$IFACE" type wireguard || { echo "FAIL: cannot create wg interface"; exit 1; }

umask 077
printf '%s\n' "$CLIENT_PRIV" > /tmp/probe.key

wg set "$IFACE" private-key /tmp/probe.key transport udp
wg set "$IFACE" peer "$SERVER_PUB" endpoint "$UDP_ENDPOINT" allowed-ips 10.60.0.1/32 persistent-keepalive 5

ip addr add 10.60.0.2/24 dev "$IFACE" 2>/dev/null
ip link set "$IFACE" up

echo "waiting for handshake..."
sleep 6

echo "=== stock UDP WireGuard client -> userspace server UDP listener ==="
wg show "$IFACE"

if wg show "$IFACE" | grep -q "latest handshake"; then
    echo "RESULT: PASS - UDP handshake completed against the userspace server"
    rc=0
else
    echo "RESULT: FAIL - no handshake on the UDP listener"
    rc=1
fi

ip link del "$IFACE" 2>/dev/null
rm -f /tmp/probe.key
exit $rc
