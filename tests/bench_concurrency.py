#!/usr/bin/env python3
# Copyright 2026 Internet Mastering & Company, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Aggregate concurrency benchmark: kernel WGTCP module vs userspace server.

The earlier single-stream comparison was bounded by the internet path (~32
Mbit/s), so both implementations tied and the result said nothing about
capacity. This runs everything on one host so the CPU is the bottleneck:

    client procs -> SOCKS5 -> WireGuard -> carrier -> server -> TUN -> local HTTP

No external network is involved, so what is measured is the packet path.
Each client process is a distinct peer, so the run exercises per-peer state
and peer lookup rather than one hot session.

Caveat that matters when reading the output: the load generator and the
server under test share the same four cores. That penalises neither side
preferentially, but it does cap absolute throughput. The comparison between
implementations is the result; the absolute Mbit/s is not a capacity figure
for a dedicated host.

Usage (run on the server, as root):
    bench_concurrency.py --mode userspace --clients 8 --streams 4
    bench_concurrency.py --mode kernel    --clients 8 --streams 4
"""

import argparse

import http.server

import json

import os

import re

import socket

import socketserver

import subprocess

import sys

import threading

import time

from pathlib import Path

BIN = "/root/redsocket_wgtcp/target/release/redsocket-wgtcp"

SERVER_BIN = "/root/redsocket_wgtcp/target/release/redsocket-wgtcp-server"

BLOB = b"x" * (1 << 20)

class Blob(http.server.BaseHTTPRequestHandler):

    protocol_version = "HTTP/1.1"

    def do_GET(self):

        self.send_response(200)

        self.send_header("Content-Length", str(len(BLOB)))

        self.end_headers()

        self.wfile.write(BLOB)

    def log_message(self, format, *args):

        pass

class Threaded(socketserver.ThreadingMixIn, http.server.HTTPServer):

    daemon_threads = True

    allow_reuse_address = True

def cpu_times():

    """(busy, total) jiffies across all cores."""

    with open("/proc/stat") as f:

        p = [int(x) for x in f.readline().split()[1:]]

    return sum(p) - (p[3] + p[4]), sum(p)

def proc_cpu(pids):

    """Aggregate utime+stime jiffies for pids (0 for any that vanished)."""

    total = 0

    for pid in pids:

        try:

            with open(f"/proc/{pid}/stat") as f:

                fields = f.read().rsplit(")", 1)[1].split()

            total += int(fields[11]) + int(fields[12])

        except (OSError, IndexError):

            pass

    return total

def genkey():

    out = subprocess.run([BIN, "genkey"], capture_output=True, text=True,

                         check=True).stdout

    priv = re.search(r"private:\s*(\S+)", out)

    pub = re.search(r"public:\s*(\S+)", out)

    if not priv or not pub:

        raise RuntimeError(f"unexpected genkey output: {out!r}")

    return priv.group(1), pub.group(1)

def wait_port(port, timeout=30):

    end = time.time() + timeout

    while time.time() < end:

        try:

            with socket.create_connection(("127.0.0.1", port), timeout=1):

                return True

        except OSError:

            time.sleep(0.2)

    return False

def puller(socks_port, url, stop, counter, lock):

    """Fetch the blob repeatedly through one SOCKS5 proxy until stopped."""

    while not stop.is_set():

        try:

            out = subprocess.run(

                ["curl", "-s", "--socks5-hostname", f"127.0.0.1:{socks_port}",

                 "--max-time", "30", "-o", "/dev/null", "-w", "%{size_download}",

                 url],

                capture_output=True, text=True, timeout=35).stdout.strip()

            got = int(out) if out.isdigit() else 0

        except (subprocess.TimeoutExpired, ValueError, OSError):

            got = 0

        if got:

            with lock:

                counter[0] += got

def sh(cmd, check=False):

    return subprocess.run(cmd, shell=True, capture_output=True, text=True,

                          check=check)

def reap(procs, timeout=5):

    """Wait for terminated processes, killing any that overstay."""

    for p in procs:

        try:

            p.wait(timeout=timeout)

        except subprocess.TimeoutExpired:

            p.kill()

def setup_kernel(peers, subnet, port):

    """Configure the kernel WGTCP interface with the given peers."""

    sh("ip link del wgbench 2>/dev/null")

    sh("ip link add wgbench type wireguard", check=True)

    priv, pub = genkey()

    Path("/tmp/bench-wg.key").write_text(priv + "\n")

    os.chmod("/tmp/bench-wg.key", 0o600)

    sh(f"wg set wgbench private-key /tmp/bench-wg.key listen-port {port} "

       f"transport tcp", check=True)

    for peer_pub, addr in peers:

        sh(f"wg set wgbench peer {peer_pub} allowed-ips {addr}/32", check=True)

    sh(f"ip addr add {subnet}.1/24 dev wgbench")

    sh("ip link set wgbench up", check=True)

    return pub

def setup_userspace(peers, subnet, port, workdir):

    """Write a config and start the userspace server with the given peers."""

    priv, pub = genkey()

    lines = [f'private_key = "{priv}"',

             f'address = "{subnet}.1"',

             "prefix_len = 24",

             'tun_name = "wgbench"',

             "mtu = 1380",

             "",

             "[[listen]]",

             f'address = "0.0.0.0:{port}"',

             'transport = "tcp"',

             ""]

    for peer_pub, addr in peers:

        lines += ["[[peers]]", f'public_key = "{peer_pub}"',

                  f'allowed_ip = "{addr}"', ""]

    cfg = workdir / "bench-server.toml"

    cfg.write_text("\n".join(lines))

    proc = subprocess.Popen([SERVER_BIN, "--config", str(cfg)],

                            stdout=subprocess.DEVNULL,

                            stderr=subprocess.DEVNULL)

    deadline = time.time() + 30

    while time.time() < deadline:

        if proc.poll() is not None:

            raise RuntimeError(

                f"userspace server exited during startup (rc={proc.returncode})")

        try:

            with socket.create_connection(("127.0.0.1", port), timeout=1):

                return pub, proc

        except OSError:

            time.sleep(0.25)

    proc.kill()

    raise RuntimeError("userspace server did not begin listening within 30s")

def main():

    ap = argparse.ArgumentParser()

    ap.add_argument("--mode", choices=["kernel", "userspace"], required=True)

    ap.add_argument("--clients", type=int, default=8)

    ap.add_argument("--streams", type=int, default=4)

    ap.add_argument("--duration", type=int, default=20)

    ap.add_argument("--port", type=int, default=9443)

    ap.add_argument("--subnet", default="10.70.0")

    args = ap.parse_args()

    workdir = Path("/tmp/wgbench")

    workdir.mkdir(exist_ok=True)

    target_port = 8088

    srv = Threaded(("0.0.0.0", target_port), Blob)

    threading.Thread(target=srv.serve_forever, daemon=True).start()

    url = f"http://{args.subnet}.1:{target_port}/blob"

    peers, cfgs, socks_ports = [], [], []

    for i in range(args.clients):

        priv, pub = genkey()

        addr = f"{args.subnet}.{10 + i}"

        sp = 21000 + i

        cfg = workdir / f"c{i}.toml"

        cfg.write_text(

            f'private_key = "{priv}"\n'

            f'peer_public_key = "__SERVER_PUB__"\n'

            f'endpoint = "127.0.0.1:{args.port}"\n'

            f'address = "{addr}"\n'

            f'gateway = "{args.subnet}.1"\n'

            "prefix_len = 24\n"

            f'socks_listen = "127.0.0.1:{sp}"\n'

            "persistent_keepalive = 25\n")

        peers.append((pub, addr))

        cfgs.append(cfg)

        socks_ports.append(sp)

    server_proc = None

    if args.mode == "kernel":

        server_pub = setup_kernel(peers, args.subnet, args.port)

        server_pids = []

    else:

        server_pub, server_proc = setup_userspace(peers, args.subnet,

                                                  args.port, workdir)

        server_pids = [server_proc.pid]

    for cfg in cfgs:

        cfg.write_text(cfg.read_text().replace("__SERVER_PUB__", server_pub))

    clients = [subprocess.Popen([BIN, "run", "--config", str(c)],

                                stdout=subprocess.DEVNULL,

                                stderr=subprocess.DEVNULL) for c in cfgs]

    up = [p for p in socks_ports if wait_port(p)]

    time.sleep(3)

    counter, lock, stop = [0], threading.Lock(), threading.Event()

    for sp in up:

        for _ in range(args.streams):

            threading.Thread(target=puller,

                             args=(sp, url, stop, counter, lock),

                             daemon=True).start()

    c0, t0 = cpu_times()

    s0 = proc_cpu(server_pids)

    start = time.time()

    time.sleep(args.duration)

    elapsed = time.time() - start

    c1, t1 = cpu_times()

    s1 = proc_cpu(server_pids)

    stop.set()

    with lock:

        total = counter[0]

    hz = os.sysconf("SC_CLK_TCK")

    result = {
        "mode": args.mode,

        "clients_up": len(up),

        "streams_total": len(up) * args.streams,

        "mbit_s": round(total * 8 / elapsed / 1e6, 1),

        "mb_s": round(total / elapsed / 1048576, 2),

        "system_busy_pct": round(100.0 * (c1 - c0) / max(1, t1 - t0), 1),

        "server_proc_cpu_pct_one_core":

            round(100.0 * (s1 - s0) / hz / elapsed, 1) if server_pids else None,

        "cores": os.cpu_count(),

        "seconds": round(elapsed, 1),
    }

    for p in clients:

        p.terminate()

    reap(clients)

    if server_proc:

        server_proc.terminate()

        reap([server_proc])

    else:

        sh("ip link del wgbench 2>/dev/null")

    srv.shutdown()

    print(json.dumps(result))

    return 0

if __name__ == "__main__":

    sys.exit(main())

