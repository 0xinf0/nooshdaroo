//! UDP SOCKS5 Implementation (RFC 1928 Section 7)
//!
//! Provides UDP ASSOCIATE command support for datagram-based protocols.
//! This is essential for DNS tunneling and other UDP-based transports.

use anyhow::{anyhow, Result};
use std::net::{SocketAddr, Ipv4Addr, Ipv6Addr};
use tokio::net::UdpSocket;
use log::{debug, info, warn};

/// SOCKS5 UDP request/reply header
///
/// ```text
/// +----+------+------+----------+----------+----------+
/// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
/// +----+------+------+----------+----------+----------+
/// | 2  |  1   |  1   | Variable |    2     | Variable |
/// +----+------+------+----------+----------+----------+
/// ```
#[derive(Debug, Clone)]
pub struct UdpSocksHeader {
    /// Fragment number (0x00 = standalone, we don't support fragmentation)
    pub frag: u8,
    /// Address type
    pub atyp: u8,
    /// Destination address
    pub dst_addr: SocketAddr,
}

impl UdpSocksHeader {
    /// Parse SOCKS5 UDP header from packet
    pub fn parse(data: &[u8]) -> Result<(Self, usize)> {
        if data.len() < 10 {
            return Err(anyhow!("UDP SOCKS5 packet too short"));
        }

        // RSV (2 bytes) - must be 0x0000
        if data[0] != 0 || data[1] != 0 {
            return Err(anyhow!("Invalid RSV field"));
        }

        let frag = data[2];
        let atyp = data[3];

        let (dst_addr, offset) = match atyp {
            0x01 => {
                // IPv4
                if data.len() < 10 {
                    return Err(anyhow!("Incomplete IPv4 address"));
                }
                let ip = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
                let port = u16::from_be_bytes([data[8], data[9]]);
                (SocketAddr::from((ip, port)), 10)
            }
            0x04 => {
                // IPv6
                if data.len() < 22 {
                    return Err(anyhow!("Incomplete IPv6 address"));
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&data[4..20]);
                let ip = Ipv6Addr::from(octets);
                let port = u16::from_be_bytes([data[20], data[21]]);
                (SocketAddr::from((ip, port)), 22)
            }
            0x03 => {
                // Domain name
                let len = data[4] as usize;
                if data.len() < 5 + len + 2 {
                    return Err(anyhow!("Incomplete domain name"));
                }
                // For now, we don't resolve domains in UDP SOCKS
                // This would need async resolution
                return Err(anyhow!("Domain names not supported in UDP SOCKS (yet)"));
            }
            _ => return Err(anyhow!("Invalid ATYP: {}", atyp)),
        };

        Ok((
            Self {
                frag,
                atyp,
                dst_addr,
            },
            offset,
        ))
    }

    /// Serialize SOCKS5 UDP header to bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = vec![0u8, 0u8]; // RSV
        buf.push(self.frag);
        buf.push(self.atyp);

        match self.dst_addr {
            SocketAddr::V4(addr) => {
                buf.extend_from_slice(&addr.ip().octets());
                buf.extend_from_slice(&addr.port().to_be_bytes());
            }
            SocketAddr::V6(addr) => {
                buf.extend_from_slice(&addr.ip().octets());
                buf.extend_from_slice(&addr.port().to_be_bytes());
            }
        }

        buf
    }
}

/// UDP SOCKS5 server
pub struct UdpSocksServer {
    /// UDP socket for SOCKS5 UDP ASSOCIATE
    socket: UdpSocket,
    /// Expected client address (from TCP handshake)
    client_addr: SocketAddr,
}

impl UdpSocksServer {
    /// Create new UDP SOCKS5 server
    pub async fn new(bind_addr: SocketAddr, client_addr: SocketAddr) -> Result<Self> {
        let socket = UdpSocket::bind(bind_addr).await?;
        info!("UDP SOCKS5 server listening on {}", bind_addr);

        Ok(Self {
            socket,
            client_addr,
        })
    }

    /// Receive datagram from client (removes SOCKS5 header)
    pub async fn recv_from_client(&self) -> Result<(Vec<u8>, SocketAddr)> {
        let mut buf = vec![0u8; 65535];
        let (n, src) = self.socket.recv_from(&mut buf).await?;
        buf.truncate(n);

        debug!("UDP SOCKS5: Received {} bytes from {}", n, src);

        // Verify it's from our client
        if src.ip() != self.client_addr.ip() {
            warn!("UDP packet from unexpected source: {}", src);
            return Err(anyhow!("Unexpected source address"));
        }

        // Parse SOCKS5 UDP header
        let (header, offset) = UdpSocksHeader::parse(&buf)?;

        if header.frag != 0 {
            return Err(anyhow!("UDP fragmentation not supported"));
        }

        // Extract payload (data after header)
        let payload = buf[offset..].to_vec();

        debug!(
            "UDP SOCKS5: Parsed packet for {} ({} bytes payload)",
            header.dst_addr,
            payload.len()
        );

        Ok((payload, header.dst_addr))
    }

    /// Send datagram to client (adds SOCKS5 header)
    pub async fn send_to_client(&self, data: &[u8], dst_addr: SocketAddr) -> Result<()> {
        // Create SOCKS5 UDP header
        let atyp = match dst_addr {
            SocketAddr::V4(_) => 0x01,
            SocketAddr::V6(_) => 0x04,
        };

        let header = UdpSocksHeader {
            frag: 0,
            atyp,
            dst_addr,
        };

        // Serialize header + data
        let mut packet = header.serialize();
        packet.extend_from_slice(data);

        // Send to client
        self.socket.send_to(&packet, self.client_addr).await?;

        debug!(
            "UDP SOCKS5: Sent {} bytes to {} (for {})",
            packet.len(),
            self.client_addr,
            dst_addr
        );

        Ok(())
    }

    /// Get local address
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.socket.local_addr()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udp_socks_header_parse_ipv4() {
        let data = vec![
            0x00, 0x00, // RSV
            0x00, // FRAG
            0x01, // ATYP (IPv4)
            192, 168, 1, 1, // IP
            0x00, 0x50, // Port 80
            b'H', b'e', b'l', b'l', b'o', // Data
        ];

        let (header, offset) = UdpSocksHeader::parse(&data).unwrap();
        assert_eq!(header.frag, 0);
        assert_eq!(header.atyp, 0x01);
        assert_eq!(offset, 10);
        assert_eq!(header.dst_addr.port(), 80);
    }

    #[test]
    fn test_udp_socks_header_serialize() {
        let header = UdpSocksHeader {
            frag: 0,
            atyp: 0x01,
            dst_addr: "192.168.1.1:80".parse().unwrap(),
        };

        let serialized = header.serialize();
        assert_eq!(serialized[0], 0x00); // RSV
        assert_eq!(serialized[1], 0x00); // RSV
        assert_eq!(serialized[2], 0x00); // FRAG
        assert_eq!(serialized[3], 0x01); // ATYP
        assert_eq!(serialized.len(), 10);
    }
}
