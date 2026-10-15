#!/usr/bin/env bash
# Copyright 2026 Internet Mastering & Company, Inc.
# SPDX-License-Identifier: Apache-2.0
set -u

CLIENT_BIN="${CLIENT_BIN:-./target/release/redsocket-wgtcp}"
KERNEL_CFG="${KERNEL_CFG:-/tmp/bench-kernel.toml}"
USER_CFG="${USER_CFG:-/tmp/bench-user.toml}"
RUNS="${RUNS:-5}"
SIZES="${SIZES:-1000000 5000000 10000000}"

median() { sort -n | awk '{a[NR]=$1} END{print (NR%2==1)? a[(NR+1)/2] : (a[NR/2]+a[NR/2+1])/2}'; }

bench_one() {
    local cfg="$1" port="$2" label="$3"
    "$CLIENT_BIN" run --config "$cfg" >/tmp/bench-client-$label.log 2>&1 &
    local pid=$!
    sleep 8

    if ! curl -s --socks5-hostname 127.0.0.1:$port --max-time 20 https://api.ipify.org >/dev/null; then
        echo "  $label: TUNNEL DOWN - skipping"
        kill $pid 2>/dev/null; wait $pid 2>/dev/null
        return 1
    fi

    for size in $SIZES; do
        local speeds=()
        for _ in $(seq 1 "$RUNS"); do
            s=$(curl -s --socks5-hostname 127.0.0.1:$port --max-time 120 -o /dev/null \
                  -w '%{speed_download}' "https://speed.cloudflare.com/__down?bytes=$size" 2>/dev/null)
            [ -n "$s" ] && speeds+=("$s")
        done
        if [ ${#speeds[@]} -gt 0 ]; then
            med=$(printf '%s\n' "${speeds[@]}" | median)
            mbit=$(awk -v b="$med" 'BEGIN{printf "%.1f", b*8/1000000}')
            mbs=$(awk -v b="$med" 'BEGIN{printf "%.2f", b/1048576}')
            printf '  %-10s %10s bytes  %8s MB/s  %7s Mbit/s  (median of %d)\n' \
                   "$label" "$size" "$mbs" "$mbit" "${#speeds[@]}"
        else
            printf '  %-10s %10s bytes  FAILED\n' "$label" "$size"
        fi
    done

    kill $pid 2>/dev/null; wait $pid 2>/dev/null
}

echo "=== WGTCP throughput: kernel module vs userspace server ==="
echo "runs per size: $RUNS   sizes: $SIZES"
echo
bench_one "$KERNEL_CFG" 1090 "kernel"
echo
bench_one "$USER_CFG" 1091 "userspace"
echo
echo "Note: single-stream through one SOCKS5 connection. Measures per-connection"
echo "throughput, not server aggregate capacity."
