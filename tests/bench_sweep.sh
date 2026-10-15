#!/usr/bin/env bash
# Copyright 2026 Internet Mastering & Company, Inc.
# SPDX-License-Identifier: Apache-2.0
set -u

DUR="${DUR:-20}"
STREAMS="${STREAMS:-4}"
LEVELS="${LEVELS:-1 2 4 8 16}"
OUT="${OUT:-/root/bench-results.jsonl}"

: > "$OUT"
echo "duration=${DUR}s streams_per_client=${STREAMS} levels: ${LEVELS}"
echo

for n in $LEVELS; do
    for mode in userspace kernel; do
        pkill -f redsocket-wgtcp >/dev/null 2>&1
        ip link del wgbench >/dev/null 2>&1

        for _ in $(seq 1 40); do
            if ! ip link show wgbench >/dev/null 2>&1 \
               && ! ss -tln 2>/dev/null | grep -q ":9443 "; then
                break
            fi
            sleep 0.5
        done

        r=$(timeout 300 python3 /root/bench_concurrency.py \
                --mode "$mode" --clients "$n" --streams "$STREAMS" \
                --duration "$DUR" 2>/dev/null | tail -1)

        if [ -n "$r" ]; then
            echo "$r" >> "$OUT"
            echo "$r" | python3 -c '
import json, sys
d = json.load(sys.stdin)
srv = d["server_proc_cpu_pct_one_core"]
srv = ("%6.1f" % srv) if srv is not None else "   n/a"
print("  %-10s clients=%3d streams=%3d  %8.1f Mbit/s  sys=%5.1f%%  srv_cpu=%s%%" % (
    d["mode"], d["clients_up"], d["streams_total"],
    d["mbit_s"], d["system_busy_pct"], srv))'
        else
            echo "  $mode clients=$n FAILED"
        fi
    done
    echo
done

echo "raw results: $OUT"
