//! SOCKS5 wire-format helpers.
//!
//! TCP requests, replies, and UDP datagram headers are parsed and encoded here
//! so relay code can work with typed addresses instead of raw byte offsets.

use anyhow::{Result, anyhow, bail};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpStream, lookup_host};

use crate::io_timeout::{read_exact_with_timeout, write_all_with_timeout};

pub const SOCKS_VERSION: u8 = 0x05;
pub const SOCKS_AUTH_USER: u8 = 0x02;
pub const SOCKS_NO_AUTH: u8 = 0x00;
pub const SOCKS_CMD_CONNECT: u8 = 0x01;
pub const SOCKS_CMD_UDP_ASSOCIATE: u8 = 0x03;
pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x03;
pub const ATYP_IPV6: u8 = 0x04;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AuthMethod {
    NoAuth,
    UsernamePassword,
}

impl AuthMethod {
    /// Convert an authentication method to its SOCKS5 wire byte.
    fn as_byte(self) -> u8 {
        match self {
            AuthMethod::NoAuth => SOCKS_NO_AUTH,
            AuthMethod::UsernamePassword => SOCKS_AUTH_USER,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Address {
    V4([u8; 4], u16),
    V6([u8; 16], u16),
    Domain(String, u16),
}

#[derive(Debug)]
pub enum Command {
    Connect(Address),
    UdpAssociate(Address),
}

pub struct SocksRequest {
    pub cmd: Command,
}

pub struct UdpDatagram<'a> {
    pub destination: Address,
    pub payload: &'a [u8],
}

/// Wrap an IPv6 address in brackets; pass through everything else.
pub(crate) fn bracket_ipv6(host: &str) -> String {
    if host.parse::<Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

impl Address {
    /// Return the port carried by this address.
    pub fn port(&self) -> u16 {
        match self {
            Address::V4(_, port) | Address::V6(_, port) | Address::Domain(_, port) => *port,
        }
    }

    /// Build a SOCKS address from a concrete socket address.
    pub fn from_socket_addr(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(addr) => Address::V4(addr.ip().octets(), addr.port()),
            SocketAddr::V6(addr) => Address::V6(addr.ip().octets(), addr.port()),
        }
    }

    /// Format the address as a target endpoint for TCP connect.
    pub fn to_target_string(&self) -> String {
        match self {
            Address::V4(ip, port) => {
                SocketAddr::new(IpAddr::V4(Ipv4Addr::from(*ip)), *port).to_string()
            }
            Address::V6(ip, port) => {
                SocketAddr::new(IpAddr::V6(Ipv6Addr::from(*ip)), *port).to_string()
            }
            Address::Domain(domain, port) => {
                format!("{}:{port}", bracket_ipv6(domain))
            }
        }
    }

    /// Resolve this address into one concrete socket address.
    pub async fn resolve_socket_addr(&self) -> Result<SocketAddr> {
        // UDP relay sends to a concrete SocketAddr, so domain targets are
        // resolved here before forwarding the datagram.
        match self {
            Address::V4(ip, port) => Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(*ip)), *port)),
            Address::V6(ip, port) => Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(*ip)), *port)),
            Address::Domain(domain, port) => lookup_host((domain.as_str(), *port))
                .await?
                .next()
                .ok_or_else(|| anyhow!("SocksError::NameResolutionFailed")),
        }
    }
}

/// Perform the SOCKS5 method negotiation handshake.
pub async fn handshake<S>(stream: &mut S, method: AuthMethod) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = [0u8; 2]; // VER NMETHODS
    read_exact_with_timeout(stream, &mut buf, "SOCKS handshake header read").await?;

    if buf[0] != SOCKS_VERSION {
        bail!("SocksError::InvalidProtocol");
    }

    let nmethods = buf[1] as usize;
    let mut methods = vec![0u8; nmethods];
    read_exact_with_timeout(stream, &mut methods, "SOCKS handshake methods read").await?;

    let desired = method.as_byte();
    if !methods.contains(&desired) {
        write_all_with_timeout(
            stream,
            &[SOCKS_VERSION, 0xFF],
            "SOCKS handshake reject method write",
        )
        .await?;
        bail!("SocksError::NoAcceptableAuthMethod");
    }

    write_all_with_timeout(
        stream,
        &[SOCKS_VERSION, desired],
        "SOCKS handshake selected method write",
    )
    .await?;

    Ok(())
}

/// Read and parse one SOCKS5 request.
pub async fn read_request<S>(stream: &mut S) -> Result<SocksRequest>
where
    S: AsyncRead + Unpin,
{
    // VER, CMD, RSV, ATYP. RSV must be zero for all SOCKS5 requests.
    let mut header = [0u8; 4];
    read_exact_with_timeout(stream, &mut header, "SOCKS request header read").await?;

    let ver = header[0];
    let cmd = header[1];
    let rsv = header[2];
    let atyp = header[3];

    if ver != SOCKS_VERSION {
        bail!("SocksError::InvalidProtocol");
    }
    if rsv != 0x00 {
        bail!("SocksError::InvalidProtocol");
    }

    let address = read_address(stream, atyp).await?;

    match cmd {
        SOCKS_CMD_CONNECT => Ok(SocksRequest {
            cmd: Command::Connect(address),
        }),
        SOCKS_CMD_UDP_ASSOCIATE => Ok(SocksRequest {
            cmd: Command::UdpAssociate(address),
        }),
        _ => bail!("SocksError::UnsupportedCommand"),
    }
}

/// Read a SOCKS address body for the given address type.
async fn read_address<S>(stream: &mut S, atyp: u8) -> Result<Address>
where
    S: AsyncRead + Unpin,
{
    match atyp {
        ATYP_IPV4 => {
            let mut ip = [0u8; 4];
            read_exact_with_timeout(stream, &mut ip, "SOCKS IPv4 address read").await?;
            let port = read_port(stream).await?;
            Ok(Address::V4(ip, port))
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            read_exact_with_timeout(stream, &mut len, "SOCKS domain length read").await?;
            if len[0] == 0 {
                bail!("SocksError::InvalidProtocol");
            }

            let mut domain_bytes = vec![0u8; len[0] as usize];
            read_exact_with_timeout(stream, &mut domain_bytes, "SOCKS domain body read").await?;

            let port = read_port(stream).await?;
            let domain = String::from_utf8(domain_bytes)
                .map_err(|_| anyhow!("SocksError::InvalidProtocol"))?;
            Ok(Address::Domain(domain, port))
        }
        ATYP_IPV6 => {
            let mut ip = [0u8; 16];
            read_exact_with_timeout(stream, &mut ip, "SOCKS IPv6 address read").await?;
            let port = read_port(stream).await?;
            Ok(Address::V6(ip, port))
        }
        _ => bail!("SocksError::InvalidProtocol"),
    }
}

/// Read a network-order port from a stream.
async fn read_port<S>(stream: &mut S) -> Result<u16>
where
    S: AsyncRead + Unpin,
{
    let mut buf = [0u8; 2];
    read_exact_with_timeout(stream, &mut buf, "SOCKS port read").await?;
    Ok(u16::from_be_bytes(buf))
}

/// Send a SOCKS5 command reply.
pub async fn send_reply<S>(stream: &mut S, rep: u8, bound: &Address) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let mut reply = Vec::with_capacity(22);
    reply.extend_from_slice(&[SOCKS_VERSION, rep, 0x00]);
    write_address(&mut reply, bound)?;
    write_all_with_timeout(stream, &reply, "SOCKS reply write").await?;
    Ok(())
}

/// Parse a SOCKS5 UDP datagram wrapper.
pub fn parse_udp_datagram(packet: &[u8]) -> Result<Option<UdpDatagram<'_>>> {
    if packet.len() < 4 {
        bail!("SocksError::InvalidUdpPacket");
    }
    if packet[0] != 0 || packet[1] != 0 {
        bail!("SocksError::InvalidUdpPacket");
    }

    // SOCKS5 UDP fragmentation is intentionally not implemented. Dropping
    // fragmented datagrams is safer than forwarding payload bytes without
    // reassembly semantics.
    if packet[2] != 0 {
        return Ok(None);
    }

    let (destination, address_len) = parse_address_bytes(&packet[3..])?;
    Ok(Some(UdpDatagram {
        destination,
        payload: &packet[3 + address_len..],
    }))
}

/// Encode a payload into a SOCKS5 UDP datagram wrapper.
pub fn encode_udp_datagram(source: &Address, payload: &[u8]) -> Result<Vec<u8>> {
    let mut packet = Vec::with_capacity(3 + address_encoded_len(source) + payload.len());
    packet.extend_from_slice(&[0, 0, 0]);
    write_address(&mut packet, source)?;
    packet.extend_from_slice(payload);
    Ok(packet)
}

/// Parse a SOCKS address from raw bytes and return its encoded length.
fn parse_address_bytes(buf: &[u8]) -> Result<(Address, usize)> {
    let atyp = *buf
        .first()
        .ok_or_else(|| anyhow!("SocksError::InvalidUdpPacket"))?;
    match atyp {
        ATYP_IPV4 => {
            if buf.len() < 1 + 4 + 2 {
                bail!("SocksError::InvalidUdpPacket");
            }
            let ip = [buf[1], buf[2], buf[3], buf[4]];
            let port = u16::from_be_bytes([buf[5], buf[6]]);
            Ok((Address::V4(ip, port), 1 + 4 + 2))
        }
        ATYP_DOMAIN => {
            let len = *buf
                .get(1)
                .ok_or_else(|| anyhow!("SocksError::InvalidUdpPacket"))?
                as usize;
            if len == 0 || buf.len() < 1 + 1 + len + 2 {
                bail!("SocksError::InvalidUdpPacket");
            }
            let domain_start = 2;
            let port_start = domain_start + len;
            let domain = std::str::from_utf8(&buf[domain_start..port_start])
                .map_err(|_| anyhow!("SocksError::InvalidUdpPacket"))?
                .to_string();
            let port = u16::from_be_bytes([buf[port_start], buf[port_start + 1]]);
            Ok((Address::Domain(domain, port), 1 + 1 + len + 2))
        }
        ATYP_IPV6 => {
            if buf.len() < 1 + 16 + 2 {
                bail!("SocksError::InvalidUdpPacket");
            }
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&buf[1..17]);
            let port = u16::from_be_bytes([buf[17], buf[18]]);
            Ok((Address::V6(ip, port), 1 + 16 + 2))
        }
        _ => bail!("SocksError::InvalidUdpPacket"),
    }
}

/// Append a SOCKS address encoding to an output buffer.
fn write_address(out: &mut Vec<u8>, address: &Address) -> Result<()> {
    // The same address encoding is used by TCP replies and UDP datagrams.
    match address {
        Address::V4(ip, port) => {
            out.push(ATYP_IPV4);
            out.extend_from_slice(ip);
            out.extend_from_slice(&port.to_be_bytes());
        }
        Address::V6(ip, port) => {
            out.push(ATYP_IPV6);
            out.extend_from_slice(ip);
            out.extend_from_slice(&port.to_be_bytes());
        }
        Address::Domain(domain, port) => {
            let len =
                u8::try_from(domain.len()).map_err(|_| anyhow!("SocksError::DomainTooLong"))?;
            out.push(ATYP_DOMAIN);
            out.push(len);
            out.extend_from_slice(domain.as_bytes());
            out.extend_from_slice(&port.to_be_bytes());
        }
    }
    Ok(())
}

/// Return the encoded length of a SOCKS address.
fn address_encoded_len(address: &Address) -> usize {
    match address {
        Address::V4(_, _) => 1 + 4 + 2,
        Address::V6(_, _) => 1 + 16 + 2,
        Address::Domain(domain, _) => 1 + 1 + domain.len() + 2,
    }
}

/// A stream wrapper that replays an already-read prefix before delegating to the inner stream.
pub struct PrefixedStream {
    prefix: Vec<u8>,
    cursor: usize,
    stream: TcpStream,
}

impl PrefixedStream {
    /// Create a stream that replays a prefix before reading from the socket.
    pub fn new(stream: TcpStream, prefix: Vec<u8>) -> Self {
        Self {
            prefix,
            cursor: 0,
            stream,
        }
    }

    /// Return the local socket address of the wrapped stream.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.stream.local_addr()
    }
}

impl AsyncRead for PrefixedStream {
    /// Read from the prefix first, then from the wrapped stream.
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.cursor < self.prefix.len() && buf.remaining() > 0 {
            let available = &self.prefix[self.cursor..];
            let to_copy = available.len().min(buf.remaining());
            buf.put_slice(&available[..to_copy]);
            self.cursor += to_copy;
            return Poll::Ready(Ok(()));
        }

        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for PrefixedStream {
    /// Write directly to the wrapped stream.
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    /// Flush the wrapped stream.
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    /// Shut down the wrapped stream.
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
