//! Relay handlers for SOCKS5 TCP CONNECT and UDP ASSOCIATE.
//!
//! The UDP relay is scoped to the lifetime of the TCP control connection, as
//! required by SOCKS5 clients and useful for cleanup.

use anyhow::{Context, Result, bail};
use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, copy_bidirectional_with_sizes};
use tokio::net::{TcpStream, UdpSocket};

use crate::{
    protocol::{Address, encode_udp_datagram, parse_udp_datagram, send_reply},
    stats::Stats,
};

const TCP_COPY_BUFFER: usize = 64 * 1024;
const UDP_BUFFER_SIZE: usize = 65_535;
const MAX_UDP_REMOTE_ENDPOINTS: usize = 1024;

/// Handle a SOCKS5 TCP CONNECT request.
pub async fn handle_connect<S>(inbound: &mut S, addr: Address, stats: &Stats) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let target = addr.to_target_string();
    let mut outbound: TcpStream = TcpStream::connect(&target)
        .await
        .inspect_err(|e| {
            stats.inc_connect_failures();
            stats.record_error(format!("SOCKS connect {target} failed: {e}"));
            println!("connect target {} failed: {}", target, e);
        })
        .context("SocksError::ConnectionFailed")?;
    outbound
        .set_nodelay(true)
        .context("Failed to disable Nagle on outbound stream")?;

    let bound = Address::from_socket_addr(outbound.local_addr()?);
    send_reply(inbound, 0x00, &bound).await?;
    let (up, down) =
        copy_bidirectional_with_sizes(inbound, &mut outbound, TCP_COPY_BUFFER, TCP_COPY_BUFFER)
            .await
            .inspect_err(|err| {
                stats.inc_relay_failures();
                stats.record_error(format!("SOCKS TCP relay failed: {err}"));
            })
            .context("Failed to proxy traffic")?;
    stats.add_tcp_bytes(up, down);
    Ok(())
}

/// Handle a SOCKS5 UDP ASSOCIATE request.
pub async fn handle_udp_associate<S>(
    control: &mut S,
    tcp_peer: SocketAddr,
    relay_bind_ip: IpAddr,
    _client_hint: Address,
    stats: &Stats,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stats.inc_udp_associate_sessions();

    // Bind the UDP relay on the same local IP family used by the TCP listener.
    // The kernel chooses an ephemeral port, which is returned in the SOCKS reply.
    let udp = UdpSocket::bind(SocketAddr::new(relay_bind_ip, 0))
        .await
        .with_context(|| format!("Failed to bind UDP relay on {relay_bind_ip}:0"))?;
    let bound = Address::from_socket_addr(udp.local_addr()?);
    send_reply(control, 0x00, &bound).await?;

    relay_udp(control, udp, tcp_peer, stats).await
}

/// Relay UDP datagrams while the TCP control connection stays open.
async fn relay_udp<S>(
    control: &mut S,
    udp: UdpSocket,
    tcp_peer: SocketAddr,
    stats: &Stats,
) -> Result<()>
where
    S: AsyncRead + Unpin,
{
    let mut udp_buf = vec![0u8; UDP_BUFFER_SIZE];
    let mut control_buf = [0u8; 1];
    let mut client_udp_addr: Option<SocketAddr> = None;
    let mut relayed_targets = HashSet::new();

    loop {
        tokio::select! {
            control_read = control.read(&mut control_buf) => {
                let n = control_read.context("SOCKS UDP control connection read failed")?;
                if n == 0 {
                    return Ok(());
                }
                bail!("SocksError::UnexpectedTcpDataDuringUdpAssociate");
            }
            received = udp.recv_from(&mut udp_buf) => {
                let (len, source) = received
                    .inspect_err(|err| {
                        stats.inc_relay_failures();
                        stats.record_error(format!("SOCKS UDP relay receive failed: {err}"));
                    })
                    .context("SOCKS UDP relay receive failed")?;

                // Before a valid client datagram arrives, only accept packets
                // from the same IP that owns the TCP control connection.
                if Some(source) == client_udp_addr {
                    handle_client_udp_packet(
                        &udp,
                        &udp_buf[..len],
                        source,
                        &mut client_udp_addr,
                        &mut relayed_targets,
                        stats,
                    ).await?;
                    continue;
                }

                if client_udp_addr.is_none() && source.ip() == tcp_peer.ip() {
                    handle_client_udp_packet(
                        &udp,
                        &udp_buf[..len],
                        source,
                        &mut client_udp_addr,
                        &mut relayed_targets,
                        stats,
                    ).await?;
                    continue;
                }

                if let Some(client) = client_udp_addr
                    && relayed_targets.contains(&source)
                {
                    // Only forward replies from destinations that the locked
                    // client has contacted through this relay.
                    stats.add_udp_bytes_in(len as u64);
                    let wrapped = encode_udp_datagram(&Address::from_socket_addr(source), &udp_buf[..len])?;
                    udp.send_to(&wrapped, client)
                        .await
                        .inspect_err(|err| {
                            stats.inc_relay_failures();
                            stats.record_error(format!("SOCKS UDP relay response send failed: {err}"));
                        })
                        .context("SOCKS UDP relay response send failed")?;
                }
            }
        }
    }
}

/// Forward one validated client UDP packet to its target.
async fn handle_client_udp_packet(
    udp: &UdpSocket,
    packet: &[u8],
    source: SocketAddr,
    client_udp_addr: &mut Option<SocketAddr>,
    relayed_targets: &mut HashSet<SocketAddr>,
    stats: &Stats,
) -> Result<()> {
    let datagram = match parse_udp_datagram(packet) {
        Ok(Some(datagram)) => datagram,
        Ok(None) => return Ok(()),
        Err(_) => return Ok(()),
    };

    // Lock the relay to the first valid UDP source that matches the TCP peer IP.
    // This prevents another local process from using the relay after it learns
    // the UDP port.
    if client_udp_addr.is_none() {
        *client_udp_addr = Some(source);
    }

    let target = match datagram.destination.resolve_socket_addr().await {
        Ok(target) => target,
        Err(err) => {
            stats.record_error(format!("SOCKS UDP target resolution failed: {err}"));
            println!("SOCKS UDP target resolution failed: {err}");
            return Ok(());
        }
    };
    if !relayed_targets.contains(&target) && relayed_targets.len() >= MAX_UDP_REMOTE_ENDPOINTS {
        return Ok(());
    }
    relayed_targets.insert(target);

    if let Err(err) = udp
        .send_to(datagram.payload, target)
        .await
        .context("SOCKS UDP relay request send failed")
    {
        stats.inc_relay_failures();
        stats.record_error(format!("SOCKS UDP relay request send failed: {err}"));
        println!("{err}");
        return Ok(());
    }
    stats.add_udp_bytes_out(datagram.payload.len() as u64);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tokio::net::UdpSocket;
    use tokio::time::{Duration, timeout};

    fn udp_datagram(target_port: u16, payload: &[u8]) -> Vec<u8> {
        encode_udp_datagram(
            &Address::V4(Ipv4Addr::new(127, 0, 0, 1).octets(), target_port),
            payload,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn client_udp_packet_increments_stats() {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut client_addr = None;
        let mut allowed = HashSet::new();
        let stats = Stats::default();

        let datagram = udp_datagram(12345, b"hello");
        let source = "127.0.0.1:40000".parse().unwrap();

        handle_client_udp_packet(
            &relay,
            &datagram,
            source,
            &mut client_addr,
            &mut allowed,
            &stats,
        )
        .await
        .unwrap();

        let snap = stats.snapshot();
        assert_eq!(snap.udp_bytes_out, 5);
    }

    #[tokio::test]
    async fn client_udp_packet_ignores_fragment() {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut client_addr = None;
        let mut allowed = HashSet::new();
        let stats = Stats::default();

        // Fragment byte (packet[2]) != 0 triggers Ok(None) in parse_udp_datagram.
        let mut fragment = udp_datagram(12346, b"data");
        fragment[2] = 0x80;

        handle_client_udp_packet(
            &relay,
            &fragment,
            "127.0.0.1:40001".parse().unwrap(),
            &mut client_addr,
            &mut allowed,
            &stats,
        )
        .await
        .unwrap();

        assert_eq!(stats.snapshot().udp_bytes_out, 0);
    }

    #[tokio::test]
    async fn client_udp_packet_drops_unresolvable_domain() {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut client_addr = None;
        let mut allowed = HashSet::new();
        let stats = Stats::default();
        let source: SocketAddr = "127.0.0.1:40005".parse().unwrap();
        let packet =
            encode_udp_datagram(&Address::Domain("bad host".to_string(), 53), b"data").unwrap();

        timeout(
            Duration::from_secs(2),
            handle_client_udp_packet(
                &relay,
                &packet,
                source,
                &mut client_addr,
                &mut allowed,
                &stats,
            ),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(client_addr, Some(source));
        assert!(allowed.is_empty());
        assert_eq!(stats.snapshot().udp_bytes_out, 0);
    }

    #[tokio::test]
    async fn client_udp_packet_sets_client_addr_on_first_call() {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut client_addr = None;
        let mut allowed = HashSet::new();
        let stats = Stats::default();
        let source: SocketAddr = "127.0.0.1:40002".parse().unwrap();

        handle_client_udp_packet(
            &relay,
            &udp_datagram(12347, b"x"),
            source,
            &mut client_addr,
            &mut allowed,
            &stats,
        )
        .await
        .unwrap();

        assert_eq!(client_addr, Some(source));
    }

    #[tokio::test]
    async fn client_udp_packet_adds_target_to_relayed() {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut client_addr = None;
        let mut allowed = HashSet::new();
        let stats = Stats::default();
        let source: SocketAddr = "127.0.0.1:40003".parse().unwrap();

        // The target is 127.0.0.1:12348
        handle_client_udp_packet(
            &relay,
            &udp_datagram(12348, b"a"),
            source,
            &mut client_addr,
            &mut allowed,
            &stats,
        )
        .await
        .unwrap();

        let expected: SocketAddr = "127.0.0.1:12348".parse().unwrap();
        assert!(allowed.contains(&expected));
    }

    #[tokio::test]
    async fn client_udp_packet_respects_max_remote_endpoints() {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut client_addr = None;
        let mut allowed = HashSet::new();
        let stats = Stats::default();
        let source: SocketAddr = "127.0.0.1:40004".parse().unwrap();
        let base_port = 20000u16;

        // Fill up to MAX_UDP_REMOTE_ENDPOINTS.
        for i in 0..MAX_UDP_REMOTE_ENDPOINTS {
            handle_client_udp_packet(
                &relay,
                &udp_datagram(base_port + i as u16, b"x"),
                source,
                &mut client_addr,
                &mut allowed,
                &stats,
            )
            .await
            .unwrap();
        }
        assert_eq!(allowed.len(), MAX_UDP_REMOTE_ENDPOINTS);

        // One more should be silently ignored.
        let snap_before = stats.snapshot();
        handle_client_udp_packet(
            &relay,
            &udp_datagram(base_port + MAX_UDP_REMOTE_ENDPOINTS as u16, b"x"),
            source,
            &mut client_addr,
            &mut allowed,
            &stats,
        )
        .await
        .unwrap();

        assert_eq!(
            allowed.len(),
            MAX_UDP_REMOTE_ENDPOINTS,
            "no new endpoint added"
        );
        assert_eq!(
            stats.snapshot().udp_bytes_out,
            snap_before.udp_bytes_out,
            "no extra UDP bytes sent"
        );
    }
}
