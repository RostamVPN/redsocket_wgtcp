// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The WGTCP carrier: a long-lived TCP connection to the server, plus the event
//! loop that couples it to the WireGuard state machine and the smoltcp stack.

use anyhow::{Context, Result, anyhow};
use std::collections::HashMap;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};

use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{IpAddress, IpEndpoint};

use crate::netstack::NetStack;
use crate::record::{self, RecordParser};
use crate::wg::{Action, WgPeer};

/// How often the WireGuard timer state machine is driven.
const TIMER_TICK: Duration = Duration::from_millis(250);

/// How often the smoltcp stack is polled when otherwise idle. smoltcp needs
/// regular polling for retransmission and delayed ACKs even with no I/O.
const POLL_TICK: Duration = Duration::from_millis(10);

/// Reconnect backoff bounds.
const BACKOFF_MIN: Duration = Duration::from_millis(500);
const BACKOFF_MAX: Duration = Duration::from_secs(30);

/// A request from a SOCKS5 connection to open a tunneled stream.
pub struct ConnectRequest {
    pub dest: IpEndpoint,
    /// Returns the per-stream channel pair once the tunnel socket is open.
    pub reply: oneshot::Sender<Result<StreamHandles>>,
}

/// Channels bridging one SOCKS5 connection to its tunneled socket.
pub struct StreamHandles {
    /// Bytes from the local application into the tunnel.
    pub to_tunnel: mpsc::Sender<Vec<u8>>,
    /// Bytes from the tunnel out to the local application.
    pub from_tunnel: mpsc::Receiver<Vec<u8>>,
}

/// Per-stream state owned by the event loop.
struct Stream {
    handle: SocketHandle,
    /// Application bytes waiting for smoltcp send buffer space.
    pending_out: Vec<u8>,
    /// Sends decrypted bytes back to the SOCKS5 task.
    to_app: mpsc::Sender<Vec<u8>>,
    /// Receives bytes from the SOCKS5 task.
    from_app: mpsc::Receiver<Vec<u8>>,
    /// The application closed its side; close the tunnel socket once drained.
    app_closed: bool,
    /// Whether we have observed the socket become established.
    was_active: bool,
}

pub struct Carrier {
    endpoint: String,
    peer: WgPeer,
    stack: NetStack,
    parser: RecordParser,
    streams: HashMap<usize, Stream>,
    next_stream_id: usize,
    connect_rx: mpsc::Receiver<ConnectRequest>,
}

impl Carrier {
    pub fn new(
        endpoint: String,
        peer: WgPeer,
        stack: NetStack,
        connect_rx: mpsc::Receiver<ConnectRequest>,
    ) -> Self {
        Self {
            endpoint,
            peer,
            stack,
            parser: RecordParser::new(),
            streams: HashMap::new(),
            next_stream_id: 0,
            connect_rx,
        }
    }

    /// Run forever, reconnecting the carrier as needed.
    pub async fn run(mut self) -> Result<()> {
        let mut backoff = BACKOFF_MIN;

        loop {
            match self.connect_carrier().await {
                Ok(sock) => {
                    log::info!("carrier established to {}", self.endpoint);
                    CARRIER_UP.store(true, std::sync::atomic::Ordering::Relaxed);
                    backoff = BACKOFF_MIN;
                    if let Err(e) = self.serve(sock).await {
                        log::warn!("carrier lost: {e:#}");
                    }
                    CARRIER_UP.store(false, std::sync::atomic::Ordering::Relaxed);
                }
                Err(e) => {
                    log::warn!("carrier connect failed: {e:#}");
                }
            }

            self.parser = RecordParser::new();

            log::info!("reconnecting in {:?}", backoff);
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(BACKOFF_MAX);
        }
    }

    async fn connect_carrier(&self) -> Result<TcpStream> {
        let sock = tokio::time::timeout(Duration::from_secs(10), dial(&self.endpoint))
            .await
            .map_err(|_| anyhow!("connect timed out"))?
            .with_context(|| format!("connect to {}", self.endpoint))?;

        sock.set_nodelay(true).ok();
        Ok(sock)
    }

    /// Drive one carrier connection until it fails.
    async fn serve(&mut self, sock: TcpStream) -> Result<()> {
        let (mut rd, mut wr) = sock.into_split();

        let init = self.peer.initiate_handshake()?;
        let mut out = Vec::new();
        record::encode(&init, &mut out)?;
        wr.write_all(&out).await.context("write handshake")?;

        let mut read_buf = vec![0u8; 65536];
        let mut timer = tokio::time::interval(TIMER_TICK);
        let mut poller = tokio::time::interval(POLL_TICK);
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        poller.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        let mut wire_out: Vec<Vec<u8>> = Vec::new();

        let mut batch: Vec<u8> = Vec::with_capacity(64 * 1024);

        loop {
            tokio::select! {
                n = rd.read(&mut read_buf) => {
                    let n = n.context("carrier read")?;
                    if n == 0 {
                        return Err(anyhow!("carrier closed by peer"));
                    }
                    self.parser.push(&read_buf[..n]);
                    while let Some(msg) = self.parser.next_message() {
                        match self.peer.decapsulate(&msg) {
                            Ok(Action::ToCarrier(buf)) => wire_out.push(buf),
                            Ok(Action::ToStack(pkt)) => {
                                self.stack.device.push_inbound(pkt);
                            }
                            Ok(Action::None) => {}
                            Err(e) => log::debug!("decapsulate: {e:#}"),
                        }

                        let mut queued = Vec::new();
                        if self.peer.drain_queued(&mut queued).is_ok() {
                            wire_out.extend(queued);
                        }
                    }
                }

                Some(req) = self.connect_rx.recv() => {
                    self.open_stream(req);
                }

                _ = timer.tick() => {
                    match self.peer.update_timers() {
                        Ok(Action::ToCarrier(buf)) => wire_out.push(buf),
                        Ok(_) => {}
                        Err(e) => return Err(anyhow!("wireguard timers: {e:#}")),
                    }
                }

                _ = poller.tick() => {}
            }

            self.pump_streams();
            self.stack.poll(SmolInstant::now());
            self.pump_streams();

            while let Some(pkt) = self.stack.device.pop_outbound() {
                match self.peer.encapsulate(&pkt) {
                    Ok(Action::ToCarrier(buf)) => wire_out.push(buf),
                    Ok(_) => {}
                    Err(e) => log::debug!("encapsulate: {e:#}"),
                }
            }

            if !wire_out.is_empty() {
                batch.clear();
                for msg in wire_out.drain(..) {
                    if let Err(e) = record::encode(&msg, &mut batch) {
                        log::debug!("record encode: {e:#}");
                    }
                }

                wr.write_all(&batch).await.context("carrier write")?;
            }

            self.reap_streams();
        }
    }

    /// Create a tunneled socket for a SOCKS5 request.
    fn open_stream(&mut self, req: ConnectRequest) {
        let handle = match self.stack.connect(req.dest) {
            Ok(h) => h,
            Err(e) => {
                let _ = req.reply.send(Err(anyhow!("tunnel connect: {e:?}")));
                return;
            }
        };

        let (to_tunnel_tx, to_tunnel_rx) = mpsc::channel::<Vec<u8>>(64);
        let (from_tunnel_tx, from_tunnel_rx) = mpsc::channel::<Vec<u8>>(64);

        let id = self.next_stream_id;
        self.next_stream_id += 1;

        self.streams.insert(
            id,
            Stream {
                handle,
                pending_out: Vec::new(),
                to_app: from_tunnel_tx,
                from_app: to_tunnel_rx,
                app_closed: false,
                was_active: false,
            },
        );

        let _ = req.reply.send(Ok(StreamHandles {
            to_tunnel: to_tunnel_tx,
            from_tunnel: from_tunnel_rx,
        }));
    }

    /// Move bytes between the per-stream channels and smoltcp's buffers.
    fn pump_streams(&mut self) {
        for stream in self.streams.values_mut() {
            let sock = self.stack.sockets.get_mut::<tcp::Socket>(stream.handle);

            if sock.is_active() {
                stream.was_active = true;
            }

            loop {
                if stream.pending_out.is_empty() {
                    match stream.from_app.try_recv() {
                        Ok(data) => stream.pending_out = data,
                        Err(mpsc::error::TryRecvError::Empty) => break,
                        Err(mpsc::error::TryRecvError::Disconnected) => {
                            stream.app_closed = true;
                            break;
                        }
                    }
                }
                if !sock.can_send() {
                    break;
                }
                match sock.send_slice(&stream.pending_out) {
                    Ok(0) => break,
                    Ok(n) => {
                        stream.pending_out.drain(..n);
                    }
                    Err(_) => break,
                }
            }

            while sock.can_recv() {
                let permit = match stream.to_app.try_reserve() {
                    Ok(p) => p,
                    Err(_) => break,
                };
                let mut buf = vec![0u8; 16384];
                match sock.recv_slice(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        buf.truncate(n);
                        permit.send(buf);
                    }
                    Err(_) => break,
                }
            }

            if stream.app_closed && stream.pending_out.is_empty() && sock.may_send() {
                sock.close();
            }
        }
    }

    /// Drop streams whose sockets are finished, freeing smoltcp resources.
    fn reap_streams(&mut self) {
        let mut dead = Vec::new();
        for (id, stream) in self.streams.iter() {
            let sock = self.stack.sockets.get::<tcp::Socket>(stream.handle);
            let closed = !sock.is_open() || sock.state() == tcp::State::Closed;

            if closed && (stream.was_active || stream.app_closed) {
                dead.push(*id);
            }

            if stream.to_app.is_closed() && stream.app_closed {
                dead.push(*id);
            }
        }
        dead.sort_unstable();
        dead.dedup();
        for id in dead {
            if let Some(stream) = self.streams.remove(&id) {
                self.stack.remove(stream.handle);
            }
        }
    }
}

/// Whether a carrier connection to the server is currently established.
static CARRIER_UP: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// True once the carrier has connected to the server and not since dropped.
pub fn carrier_is_up() -> bool {
    CARRIER_UP.load(std::sync::atomic::Ordering::Relaxed)
}

/// Hook invoked on every outbound carrier socket before `connect()`.
static PROTECT_HOOK: std::sync::OnceLock<fn(i32)> = std::sync::OnceLock::new();

/// Install the socket-protection hook.
pub fn set_protect_hook(hook: fn(i32)) -> bool {
    PROTECT_HOOK.set(hook).is_ok()
}

/// Dial `endpoint`, applying the protection hook before connect when present.
async fn dial(endpoint: &str) -> Result<TcpStream> {
    let Some(hook) = PROTECT_HOOK.get().copied() else {
        return Ok(TcpStream::connect(endpoint).await?);
    };

    let addr = tokio::net::lookup_host(endpoint)
        .await?
        .next()
        .ok_or_else(|| anyhow!("could not resolve {endpoint}"))?;

    let std_sock = tokio::task::spawn_blocking(move || -> std::io::Result<std::net::TcpStream> {
        let domain = if addr.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        };
        let sock =
            socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;

        use std::os::unix::io::AsRawFd;
        hook(sock.as_raw_fd());

        sock.set_tcp_nodelay(true).ok();
        sock.connect_timeout(&addr.into(), Duration::from_secs(10))?;
        Ok(std::net::TcpStream::from(sock))
    })
    .await
    .map_err(|e| anyhow!("dial task join: {e}"))??;

    std_sock.set_nonblocking(true)?;
    Ok(TcpStream::from_std(std_sock)?)
}

/// Resolve a destination for smoltcp. Domain names are resolved by the local
/// resolver before entering the tunnel; see `socks5` for the caveat.
pub fn endpoint_from_ip(addr: std::net::IpAddr, port: u16) -> IpEndpoint {
    match addr {
        std::net::IpAddr::V4(a) => IpEndpoint::new(IpAddress::Ipv4(a), port),
        std::net::IpAddr::V6(a) => IpEndpoint::new(IpAddress::Ipv6(a), port),
    }
}

/// Whether the running tunnel's inner address is IPv6.
static TUNNEL_IS_IPV6: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn set_tunnel_is_ipv6(v: bool) {
    TUNNEL_IS_IPV6.store(v, std::sync::atomic::Ordering::Relaxed);
}

pub fn tunnel_is_ipv6() -> bool {
    TUNNEL_IS_IPV6.load(std::sync::atomic::Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The protection hook must actually run before connect, and must run on every
    /// carrier dial.
    #[tokio::test]
    async fn protect_hook_runs_before_connect() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static CALLS: AtomicUsize = AtomicUsize::new(0);
        fn hook(fd: i32) {
            assert!(fd >= 0, "hook must receive a real fd");
            CALLS.fetch_add(1, Ordering::SeqCst);
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        assert!(set_protect_hook(hook), "first install must succeed");
        assert!(
            !set_protect_hook(hook),
            "a second install must be refused rather than silently replacing"
        );

        let sock = dial(&addr.to_string()).await.expect("dial must succeed");
        assert_eq!(
            CALLS.load(Ordering::SeqCst),
            1,
            "hook must be invoked exactly once per dial"
        );
        drop(sock);
    }

    /// The readiness flag must start false. An embedder reads it to decide whether
    /// the tunnel is usable, and a default of "up" would reproduce the exact false-
    /// positive this flag exists to prevent.
    #[test]
    fn carrier_starts_down() {
        assert!(
            !carrier_is_up(),
            "must not claim the carrier is up before it has ever connected"
        );
    }

    #[test]
    fn converts_ipv4_endpoints() {
        let ep = endpoint_from_ip("1.1.1.1".parse().unwrap(), 443);
        assert_eq!(ep.port, 443);
        assert_eq!(ep.addr, IpAddress::v4(1, 1, 1, 1));
    }

    /// Backoff must grow but stay bounded, or a long outage turns into an
    /// effectively dead client.
    #[test]
    fn backoff_grows_and_saturates() {
        let mut b = BACKOFF_MIN;
        for _ in 0..20 {
            b = (b * 2).min(BACKOFF_MAX);
        }
        assert_eq!(b, BACKOFF_MAX);
        assert!(BACKOFF_MIN < BACKOFF_MAX);
    }
}
