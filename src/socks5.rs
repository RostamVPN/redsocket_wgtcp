// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Local SOCKS5 front-end.

use anyhow::{Context, Result, anyhow};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};

use crate::carrier::{ConnectRequest, endpoint_from_ip};

const SOCKS_VERSION: u8 = 0x05;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

const REP_SUCCESS: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_HOST_UNREACHABLE: u8 = 0x04;
const REP_CMD_NOT_SUPPORTED: u8 = 0x07;
const REP_ATYP_NOT_SUPPORTED: u8 = 0x08;

/// A parsed SOCKS5 CONNECT target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    V4(Ipv4Addr, u16),
    V6(Ipv6Addr, u16),
    Domain(String, u16),
}

/// Accept SOCKS5 connections and hand them to the carrier event loop.
pub async fn serve(listen: SocketAddr, connect_tx: mpsc::Sender<ConnectRequest>) -> Result<()> {
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("bind SOCKS5 listener on {listen}"))?;
    log::info!("SOCKS5 listening on {listen}");

    loop {
        let (sock, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                log::warn!("accept failed: {e}");
                continue;
            }
        };
        let tx = connect_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(sock, tx).await {
                log::debug!("socks5 {peer}: {e:#}");
            }
        });
    }
}

async fn handle(mut sock: TcpStream, connect_tx: mpsc::Sender<ConnectRequest>) -> Result<()> {
    sock.set_nodelay(true).ok();

    let mut head = [0u8; 2];
    sock.read_exact(&mut head).await.context("read greeting")?;
    if head[0] != SOCKS_VERSION {
        return Err(anyhow!("not SOCKS5 (version {})", head[0]));
    }
    let nmethods = head[1] as usize;
    let mut methods = vec![0u8; nmethods];
    sock.read_exact(&mut methods)
        .await
        .context("read methods")?;

    sock.write_all(&[SOCKS_VERSION, 0x00]).await?;

    let mut req = [0u8; 4];
    sock.read_exact(&mut req).await.context("read request")?;
    if req[0] != SOCKS_VERSION {
        return Err(anyhow!("bad request version"));
    }
    if req[1] != CMD_CONNECT {
        reply(&mut sock, REP_CMD_NOT_SUPPORTED).await?;
        return Err(anyhow!("only CONNECT is supported"));
    }

    let target = match req[3] {
        ATYP_IPV4 => {
            let mut b = [0u8; 6];
            sock.read_exact(&mut b).await?;
            Target::V4(
                Ipv4Addr::new(b[0], b[1], b[2], b[3]),
                u16::from_be_bytes([b[4], b[5]]),
            )
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            sock.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
            sock.read_exact(&mut name).await?;
            let mut port = [0u8; 2];
            sock.read_exact(&mut port).await?;
            Target::Domain(
                String::from_utf8(name).context("domain is not UTF-8")?,
                u16::from_be_bytes(port),
            )
        }
        ATYP_IPV6 => {
            let mut b = [0u8; 18];
            sock.read_exact(&mut b).await?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&b[..16]);
            Target::V6(Ipv6Addr::from(octets), u16::from_be_bytes([b[16], b[17]]))
        }
        other => {
            reply(&mut sock, REP_ATYP_NOT_SUPPORTED).await?;
            return Err(anyhow!("unknown address type {other}"));
        }
    };

    let (addr, port): (IpAddr, u16) = match &target {
        Target::V4(a, p) => (IpAddr::V4(*a), *p),
        Target::V6(a, p) => (IpAddr::V6(*a), *p),
        Target::Domain(name, p) => match resolve(name, *p).await {
            Some(a) => (a, *p),
            None => {
                reply(&mut sock, REP_HOST_UNREACHABLE).await?;
                return Err(anyhow!("cannot resolve {name}"));
            }
        },
    };

    let (reply_tx, reply_rx) = oneshot::channel();
    connect_tx
        .send(ConnectRequest {
            dest: endpoint_from_ip(addr, port),
            reply: reply_tx,
        })
        .await
        .map_err(|_| anyhow!("carrier event loop is gone"))?;

    let handles = match reply_rx.await {
        Ok(Ok(h)) => h,
        Ok(Err(e)) => {
            reply(&mut sock, REP_HOST_UNREACHABLE).await?;
            return Err(e);
        }
        Err(_) => {
            reply(&mut sock, REP_GENERAL_FAILURE).await?;
            return Err(anyhow!("carrier dropped the request"));
        }
    };

    reply(&mut sock, REP_SUCCESS).await?;
    log::debug!("tunneling to {addr}:{port}");

    relay(sock, handles).await
}

/// Send a SOCKS5 reply. The bound address is reported as 0.0.0.0:0 because the
/// real source lives inside the tunnel and is not meaningful locally.
async fn reply(sock: &mut TcpStream, code: u8) -> Result<()> {
    sock.write_all(&[SOCKS_VERSION, code, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
        .await?;
    Ok(())
}

/// Resolve a hostname using the system resolver.
async fn resolve(host: &str, port: u16) -> Option<IpAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(ip);
    }
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port)).await.ok()?.collect();

    let want_v6 = crate::carrier::tunnel_is_ipv6();
    if let Some(a) = addrs
        .iter()
        .find(|a| a.is_ipv6() == want_v6)
        .or_else(|| addrs.first())
    {
        return Some(a.ip());
    }
    None
}

/// Shuttle bytes between the local socket and the tunneled stream.
async fn relay(sock: TcpStream, handles: crate::carrier::StreamHandles) -> Result<()> {
    let (mut rd, mut wr) = sock.into_split();
    let to_tunnel = handles.to_tunnel;
    let mut from_tunnel = handles.from_tunnel;

    let up = tokio::spawn(async move {
        let mut buf = vec![0u8; 16384];
        loop {
            match rd.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if to_tunnel.send(buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    let down = tokio::spawn(async move {
        while let Some(chunk) = from_tunnel.recv().await {
            if wr.write_all(&chunk).await.is_err() {
                break;
            }
        }
        let _ = wr.shutdown().await;
    });

    let _ = tokio::join!(up, down);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    /// Drive a real SOCKS5 handshake against the real handler and confirm the
    /// request that reaches the carrier matches what the client asked for.
    #[tokio::test]
    async fn parses_ipv4_connect_request() {
        let (tx, mut rx) = mpsc::channel::<ConnectRequest>(1);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let _ = handle(sock, tx).await;
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut greet = [0u8; 2];
        client.read_exact(&mut greet).await.unwrap();
        assert_eq!(greet, [0x05, 0x00], "server must select no-auth");

        client
            .write_all(&[0x05, 0x01, 0x00, 0x01, 1, 1, 1, 1, 0x01, 0xBB])
            .await
            .unwrap();

        let req = rx.recv().await.expect("carrier must receive the request");
        assert_eq!(req.dest.port, 443);
        assert_eq!(req.dest.addr, smoltcp::wire::IpAddress::v4(1, 1, 1, 1));
    }

    /// BIND/UDP-ASSOCIATE must be refused with the correct SOCKS5 code rather than
    /// hanging the client.
    #[tokio::test]
    async fn rejects_non_connect_commands() {
        let (tx, _rx) = mpsc::channel::<ConnectRequest>(1);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let _ = handle(sock, tx).await;
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut greet = [0u8; 2];
        client.read_exact(&mut greet).await.unwrap();

        client
            .write_all(&[0x05, 0x02, 0x00, 0x01, 1, 1, 1, 1, 0x01, 0xBB])
            .await
            .unwrap();

        let mut resp = [0u8; 10];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp[1], REP_CMD_NOT_SUPPORTED);
    }

    /// IPv6 targets must now be parsed and forwarded to the tunnel, not refused.
    /// The request carries a v6 literal; the connect request handed to the carrier
    /// must name that exact address.
    #[tokio::test]
    async fn forwards_ipv6_targets_to_the_tunnel() {
        let (tx, mut rx) = mpsc::channel::<ConnectRequest>(1);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let _ = handle(sock, tx).await;
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut greet = [0u8; 2];
        client.read_exact(&mut greet).await.unwrap();

        let target: Ipv6Addr = "2606:4700:4700::1111".parse().unwrap();
        let mut req = vec![0x05, 0x01, 0x00, 0x04];
        req.extend_from_slice(&target.octets());
        req.extend_from_slice(&443u16.to_be_bytes());
        client.write_all(&req).await.unwrap();

        let got = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
            .await
            .expect("connect request must arrive")
            .expect("channel open");
        assert_eq!(got.dest.port, 443);
        assert_eq!(
            got.dest.addr,
            smoltcp::wire::IpAddress::Ipv6(target),
            "the v6 literal must reach the tunnel unchanged"
        );
    }

    /// An unknown address type is still refused, so the ATYP_IPV6 change did not
    /// turn the parser permissive.
    #[tokio::test]
    async fn rejects_unknown_address_types() {
        let (tx, _rx) = mpsc::channel::<ConnectRequest>(1);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let _ = handle(sock, tx).await;
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut greet = [0u8; 2];
        client.read_exact(&mut greet).await.unwrap();

        client.write_all(&[0x05, 0x01, 0x00, 0x07]).await.unwrap();

        let mut resp = [0u8; 10];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp[1], REP_ATYP_NOT_SUPPORTED);
    }

    #[tokio::test]
    async fn resolves_literals_of_both_families_without_dns() {
        assert_eq!(
            resolve("9.9.9.9", 53).await,
            Some(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)))
        );
        let v6: Ipv6Addr = "2606:4700:4700::1111".parse().unwrap();
        assert_eq!(
            resolve("2606:4700:4700::1111", 443).await,
            Some(IpAddr::V6(v6)),
            "a v6 literal must not be sent to DNS"
        );
    }
}
