// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Server runtime: binds every configured listener and pumps packets.

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;

use super::engine::{Engine, Ingress, inner_destination};
use super::listener::Transport;
use crate::record::{self, RecordParser};

/// Bounded per-carrier queue; applies backpressure instead of unbounded growth
/// when a client's link is slower than its traffic.
const CARRIER_QUEUE: usize = 256;

/// Where to send packets destined for a given peer.
pub type ReplySender = mpsc::Sender<Vec<u8>>;

/// Run every configured listener until one fails.
pub async fn serve(
    engine: Arc<Engine>,
    listeners: Vec<(SocketAddr, Transport)>,
    tun_tx: mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    let mut tasks = Vec::new();

    for (addr, transport) in listeners {
        let engine = engine.clone();
        let tun_tx = tun_tx.clone();
        let task = match transport {
            Transport::Tcp => tokio::spawn(async move { serve_tcp(engine, addr, tun_tx).await }),
            Transport::Udp => tokio::spawn(async move { serve_udp(engine, addr, tun_tx).await }),
        };
        tasks.push(task);
    }

    let (result, _idx, _rest) = futures::future::select_all(tasks).await;
    result.context("listener task panicked")?
}

/// WGTCP carrier: length-delimited records over long-lived TCP.
async fn serve_tcp(
    engine: Arc<Engine>,
    addr: SocketAddr,
    tun_tx: mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind tcp {addr}"))?;
    log::info!("listening on {addr}/tcp (WGTCP records)");

    loop {
        let (sock, remote) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                log::warn!("{addr}/tcp accept failed: {e}");
                continue;
            }
        };
        sock.set_nodelay(true).ok();
        let engine = engine.clone();
        let tun_tx = tun_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_tcp_carrier(engine, sock, remote, tun_tx).await {
                log::debug!("carrier {remote} closed: {e:#}");
            }
        });
    }
}

async fn handle_tcp_carrier(
    engine: Arc<Engine>,
    sock: TcpStream,
    remote: SocketAddr,
    tun_tx: mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    let (mut rd, mut wr) = sock.into_split();
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(CARRIER_QUEUE);

    let writer = tokio::spawn(async move {
        let mut batch = Vec::new();
        while let Some(msg) = rx.recv().await {
            batch.clear();
            if record::encode(&msg, &mut batch).is_err() {
                continue;
            }

            while let Ok(next) = rx.try_recv() {
                let _ = record::encode(&next, &mut batch);
            }
            if wr.write_all(&batch).await.is_err() {
                break;
            }
        }
    });

    let mut parser = RecordParser::new();
    let mut buf = vec![0u8; 65536];

    loop {
        let n = rd.read(&mut buf).await.context("carrier read")?;
        if n == 0 {
            break;
        }
        parser.push(&buf[..n]);

        while let Some(msg) = parser.next_message() {
            dispatch(&engine, &msg, &tx, &tun_tx, remote, Transport::Tcp).await;
        }
    }

    writer.abort();
    Ok(())
}

/// Stock WireGuard carrier: one datagram per message, no record header.
async fn serve_udp(
    engine: Arc<Engine>,
    addr: SocketAddr,
    tun_tx: mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    let sock = Arc::new(
        UdpSocket::bind(addr)
            .await
            .with_context(|| format!("bind udp {addr}"))?,
    );
    log::info!("listening on {addr}/udp (stock WireGuard datagrams)");

    let (tx, mut rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(CARRIER_QUEUE * 4);
    let send_sock = sock.clone();
    tokio::spawn(async move {
        while let Some((msg, dst)) = rx.recv().await {
            let _ = send_sock.send_to(&msg, dst).await;
        }
    });

    let mut buf = vec![0u8; 65536];
    loop {
        let (n, remote) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                log::warn!("{addr}/udp recv failed: {e}");
                continue;
            }
        };

        let (peer_tx, mut peer_rx) = mpsc::channel::<Vec<u8>>(4);
        let out = tx.clone();
        tokio::spawn(async move {
            while let Some(m) = peer_rx.recv().await {
                if out.send((m, remote)).await.is_err() {
                    break;
                }
            }
        });

        dispatch(
            &engine,
            &buf[..n],
            &peer_tx,
            &tun_tx,
            remote,
            Transport::Udp,
        )
        .await;
    }
}

/// Feed one message to the engine and act on the result.
async fn dispatch(
    engine: &Arc<Engine>,
    msg: &[u8],
    reply_tx: &ReplySender,
    tun_tx: &mpsc::Sender<Vec<u8>>,
    remote: SocketAddr,
    transport: Transport,
) {
    match engine.ingress(msg) {
        Ok(Ingress::Done) => {}
        Ok(Ingress::Reply(reply)) => {
            let _ = reply_tx.send(reply).await;
        }
        Ok(Ingress::Inner { peer, packet }) => {
            peer.set_carrier(
                remote,
                transport,
                reply_tx.clone(),
                engine.next_generation(),
            );
            let _ = tun_tx.send(packet).await;
        }
        Err(e) => {
            log::debug!("{remote}/{} dropped: {e:#}", transport.as_str());
        }
    }
}

/// Route a packet coming back from the TUN device to the owning peer.
pub async fn route_to_peer(engine: &Arc<Engine>, packet: Vec<u8>) {
    let dst = match inner_destination(&packet) {
        Some(d) => d,
        None => return,
    };
    let peer = match engine.registry.by_inner_ip(dst) {
        Some(p) => p,
        None => return,
    };
    let carrier = match peer.carrier() {
        Some(c) => c,
        None => return,
    };
    match engine.egress(&peer, &packet) {
        Ok(Some(wire)) => {
            let _ = carrier.tx.send(wire).await;
        }
        Ok(None) => {}
        Err(e) => log::debug!("egress to {}: {e:#}", peer.label()),
    }
}
