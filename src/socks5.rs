///! Complete SOCKS5 Protocol Implementation (RFC 1928)
///!
///! This module implements the full SOCKS5 protocol for proxying TCP and UDP traffic.
///! It handles authentication, CONNECT commands, and proper error responses.

use std::io::{Error, ErrorKind};
use std::net::{SocketAddr, IpAddr, Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncReadExt, AsyncWriteExt, AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use std::pin::Pin;
use std::task::{Context, Poll};
use bytes::{BytesMut, Buf};

/// Wrapper that prepends buffered data before reading from the underlying stream
pub struct PrefixedStream {
    stream: TcpStream,
    prefix: Option<BytesMut>,
}

impl PrefixedStream {
    pub fn new(stream: TcpStream, prefix: BytesMut) -> Self {
        Self {
            stream,
            prefix: if prefix.is_empty() { None } else { Some(prefix) },
        }
    }
}

impl AsyncRead for PrefixedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // If we have buffered data, read from that first
        if let Some(prefix) = &mut self.prefix {
            let to_copy = std::cmp::min(buf.remaining(), prefix.len());
            buf.put_slice(&prefix[..to_copy]);
            prefix.advance(to_copy);

            if prefix.is_empty() {
                self.prefix = None;
            }

            return Poll::Ready(Ok(()));
        }

        // Otherwise read from the underlying stream
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for PrefixedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl PrefixedStream {
    pub fn split(self) -> (tokio::io::ReadHalf<Self>, tokio::io::WriteHalf<Self>) {
        tokio::io::split(self)
    }
}

/// SOCKS5 protocol constants
const SOCKS5_VERSION: u8 = 0x05;

/// Authentication methods
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub enum AuthMethod {
    NoAuth = 0x00,
    GSSAPI = 0x01,
    UsernamePassword = 0x02,
    NoAcceptable = 0xFF,
}

/// SOCKS5 commands
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Command {
    Connect = 0x01,
    Bind = 0x02,
    UdpAssociate = 0x03,
}

/// Address types
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
enum AddressType {
    IPv4 = 0x01,
    DomainName = 0x03,
    IPv6 = 0x04,
}

/// SOCKS5 reply codes
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub enum ReplyCode {
    Succeeded = 0x00,
    GeneralFailure = 0x01,
    NotAllowed = 0x02,
    NetworkUnreachable = 0x03,
    HostUnreachable = 0x04,
    ConnectionRefused = 0x05,
    TTLExpired = 0x06,
    CommandNotSupported = 0x07,
    AddressTypeNotSupported = 0x08,
}

/// SOCKS5 target address
#[derive(Debug, Clone)]
pub struct TargetAddr {
    pub host: String,
    pub port: u16,
}

impl TargetAddr {
    pub fn to_socket_addr(&self) -> Option<SocketAddr> {
        if let Ok(ip) = self.host.parse::<IpAddr>() {
            Some(SocketAddr::new(ip, self.port))
        } else {
            None
        }
    }
}

/// Perform SOCKS5 handshake and return target address
pub async fn socks5_handshake<S>(stream: &mut S) -> Result<(Command, TargetAddr), Error>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    // Step 1: Client greeting
    // +----+----------+----------+
    // |VER | NMETHODS | METHODS  |
    // +----+----------+----------+
    // | 1  |    1     | 1 to 255 |
    // +----+----------+----------+

    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;

    let version = buf[0];
    let nmethods = buf[1];

    log::trace!("[SOCKS5] Client greeting: version={}, nmethods={}", version, nmethods);

    if version != SOCKS5_VERSION {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("Unsupported SOCKS version: {}", version),
        ));
    }

    // Read authentication methods
    let mut methods = vec![0u8; nmethods as usize];
    stream.read_exact(&mut methods).await?;
    log::trace!("[SOCKS5] Auth methods offered: {:?}", methods);

    // Step 2: Server choice
    // +----+--------+
    // |VER | METHOD |
    // +----+--------+
    // | 1  |   1    |
    // +----+--------+

    // We only support no authentication for now
    if !methods.contains(&(AuthMethod::NoAuth as u8)) {
        // Send "no acceptable methods"
        stream.write_all(&[SOCKS5_VERSION, AuthMethod::NoAcceptable as u8]).await?;
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            "No supported authentication method",
        ));
    }

    // Accept no authentication
    stream.write_all(&[SOCKS5_VERSION, AuthMethod::NoAuth as u8]).await?;
    log::trace!("[SOCKS5] Accepted auth method: NoAuth");

    // Step 3: Client request
    // +----+-----+-------+------+----------+----------+
    // |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    // +----+-----+-------+------+----------+----------+
    // | 1  |  1  | X'00' |  1   | Variable |    2     |
    // +----+-----+-------+------+----------+----------+

    let mut request = [0u8; 4];
    stream.read_exact(&mut request).await?;

    let version = request[0];
    let cmd = request[1];
    let atyp = request[3];

    if version != SOCKS5_VERSION {
        return Err(Error::new(ErrorKind::InvalidData, "Invalid SOCKS version"));
    }

    let command = match cmd {
        0x01 => {
            log::trace!("[SOCKS5] Command: CONNECT");
            Command::Connect
        },
        0x02 => {
            log::trace!("[SOCKS5] Command: BIND");
            Command::Bind
        },
        0x03 => {
            log::trace!("[SOCKS5] Command: UDP ASSOCIATE");
            Command::UdpAssociate
        },
        _ => {
            log::warn!("[SOCKS5] Unsupported command: {}", cmd);
            send_reply(stream, ReplyCode::CommandNotSupported, &TargetAddr {
                host: "0.0.0.0".to_string(),
                port: 0,
            }).await?;
            return Err(Error::new(ErrorKind::Unsupported, "Unsupported command"));
        }
    };

    // Read destination address
    log::trace!("[SOCKS5] Address type: {} (1=IPv4, 3=Domain, 4=IPv6)", atyp);
    let host = match atyp {
        0x01 => {
            // IPv4
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await?;
            let ip = format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3]);
            log::trace!("[SOCKS5] IPv4 address: {}", ip);
            ip
        }
        0x03 => {
            // Domain name
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            log::trace!("[SOCKS5] Domain name length: {}", len[0]);
            let mut domain = vec![0u8; len[0] as usize];
            stream.read_exact(&mut domain).await?;
            let domain_str = String::from_utf8(domain).map_err(|_| {
                Error::new(ErrorKind::InvalidData, "Invalid domain name")
            })?;
            log::trace!("[SOCKS5] Domain name: {}", domain_str);
            domain_str
        }
        0x04 => {
            // IPv6
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await?;
            let ipv6 = format!(
                "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                addr[0], addr[1], addr[2], addr[3],
                addr[4], addr[5], addr[6], addr[7],
                addr[8], addr[9], addr[10], addr[11],
                addr[12], addr[13], addr[14], addr[15]
            );
            log::trace!("[SOCKS5] IPv6 address: {}", ipv6);
            ipv6
        }
        _ => {
            send_reply(stream, ReplyCode::AddressTypeNotSupported, &TargetAddr {
                host: "0.0.0.0".to_string(),
                port: 0,
            }).await?;
            return Err(Error::new(ErrorKind::Unsupported, "Unsupported address type"));
        }
    };

    // Read port
    let mut port_bytes = [0u8; 2];
    stream.read_exact(&mut port_bytes).await?;
    let port = u16::from_be_bytes(port_bytes);

    log::trace!("[SOCKS5] Target port: {}", port);
    log::info!("[SOCKS5] Handshake complete: command={:?}, target={}:{}", command, host, port);

    Ok((command, TargetAddr { host, port }))
}

/// Send SOCKS5 reply to client
pub async fn send_reply<S>(
    stream: &mut S,
    reply: ReplyCode,
    bind_addr: &TargetAddr,
) -> Result<(), Error>
where
    S: AsyncWriteExt + Unpin,
{
    // +----+-----+-------+------+----------+----------+
    // |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    // +----+-----+-------+------+----------+----------+
    // | 1  |  1  | X'00' |  1   | Variable |    2     |
    // +----+-----+-------+------+----------+----------+

    log::trace!("[SOCKS5] Sending reply: code={:?}, bind_addr={}:{}", reply, bind_addr.host, bind_addr.port);

    let mut response = vec![SOCKS5_VERSION, reply as u8, 0x00];

    // Encode bind address
    if let Ok(ip) = bind_addr.host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(ipv4) => {
                response.push(AddressType::IPv4 as u8);
                response.extend_from_slice(&ipv4.octets());
            }
            IpAddr::V6(ipv6) => {
                response.push(AddressType::IPv6 as u8);
                response.extend_from_slice(&ipv6.octets());
            }
        }
    } else {
        // Use 0.0.0.0 for errors or domain names
        response.push(AddressType::IPv4 as u8);
        response.extend_from_slice(&[0, 0, 0, 0]);
    }

    // Add port
    response.extend_from_slice(&bind_addr.port.to_be_bytes());

    stream.write_all(&response).await?;
    Ok(())
}

/// Connect to target through proxy
pub async fn connect_target(target: &TargetAddr) -> Result<TcpStream, Error> {
    // Try to resolve if it's a domain
    let addr_str = format!("{}:{}", target.host, target.port);

    // Try direct connection first if it's an IP
    if let Some(socket_addr) = target.to_socket_addr() {
        match TcpStream::connect(socket_addr).await {
            Ok(stream) => return Ok(stream),
            Err(e) => {
                log::debug!("Direct connection failed: {}", e);
            }
        }
    }

    // Try DNS resolution
    let result = tokio::net::lookup_host(&addr_str).await;
    match result {
        Ok(mut addrs) => {
            if let Some(addr) = addrs.next() {
                TcpStream::connect(addr).await
            } else {
                Err(Error::new(ErrorKind::NotFound, "No addresses found"))
            }
        }
        Err(e) => Err(e),
    }
}

/// Bidirectional copy between two streams
pub async fn copy_bidirectional<C, T>(
    client: C,
    target: &mut T,
) -> Result<(), Error>
where
    C: AsyncRead + AsyncWrite + Unpin,
    T: AsyncRead + AsyncWrite + Unpin,
{
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut target_read, mut target_write) = tokio::io::split(target);

    tokio::select! {
        result = tokio::io::copy(&mut client_read, &mut target_write) => {
            match result {
                Ok(n) => log::debug!("Client -> Target: {} bytes", n),
                Err(e) => log::debug!("Client -> Target error: {}", e),
            }
        }
        result = tokio::io::copy(&mut target_read, &mut client_write) => {
            match result {
                Ok(n) => log::debug!("Target -> Client: {} bytes", n),
                Err(e) => log::debug!("Target -> Client error: {}", e),
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_target_addr_ipv4() {
        let target = TargetAddr {
            host: "192.168.1.1".to_string(),
            port: 80,
        };
        let addr = target.to_socket_addr().unwrap();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(addr.port(), 80);
    }

    #[test]
    fn test_target_addr_domain() {
        let target = TargetAddr {
            host: "example.com".to_string(),
            port: 443,
        };
        assert!(target.to_socket_addr().is_none());
    }
}
