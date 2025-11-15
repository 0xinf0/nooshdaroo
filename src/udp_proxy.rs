///! UDP proxy and SOCKS5 UDP ASSOCIATE implementation
///!
///! This module provides UDP transport support for Nooshdaroo:
///! - SOCKS5 UDP ASSOCIATE command handling
///! - UDP packet forwarding with NAT session tracking
///! - Protocol emulation for UDP-based protocols (DNS, QUIC, WireGuard, etc.)
///!
///! Mobile Platform Support:
///! - iOS: Uses tokio::net::UdpSocket (compatible with NWUDPSession)
///! - Android: Uses tokio::net::UdpSocket (compatible with DatagramSocket)

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

/// UDP session timeout (5 minutes, standard SOCKS5 timeout)
const UDP_SESSION_TIMEOUT: Duration = Duration::from_secs(300);

/// Maximum UDP packet size (jumbo frames support)
const MAX_UDP_PACKET_SIZE: usize = 65507;

/// SOCKS5 UDP relay header
/// ```
/// +----+------+------+----------+----------+----------+
/// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
/// +----+------+------+----------+----------+----------+
/// | 2  |  1   |  1   | Variable |    2     | Variable |
/// +----+------+------+----------+----------+----------+
/// ```
#[derive(Debug, Clone)]
struct Socks5UdpHeader {
    /// Fragment number (0 = no fragmentation)
    frag: u8,
    /// Address type (1=IPv4, 3=Domain, 4=IPv6)
    atyp: u8,
    /// Destination address
    dst_addr: Vec<u8>,
    /// Destination port
    dst_port: u16,
}

impl Socks5UdpHeader {
    /// Parse SOCKS5 UDP header from packet
    fn parse(packet: &[u8]) -> Result<(Self, usize), String> {
        if packet.len() < 10 {
            return Err("Packet too small for SOCKS5 UDP header".to_string());
        }

        // Check RSV (must be 0x0000)
        if packet[0] != 0 || packet[1] != 0 {
            return Err("Invalid RSV field".to_string());
        }

        let frag = packet[2];
        let atyp = packet[3];

        let (dst_addr, addr_len) = match atyp {
            1 => {
                // IPv4: 4 bytes
                if packet.len() < 10 {
                    return Err("Packet too small for IPv4 address".to_string());
                }
                (packet[4..8].to_vec(), 4)
            }
            3 => {
                // Domain name: first byte is length
                if packet.len() < 5 {
                    return Err("Packet too small for domain length".to_string());
                }
                let len = packet[4] as usize;
                if packet.len() < 5 + len + 2 {
                    return Err("Packet too small for domain name".to_string());
                }
                (packet[4..5 + len].to_vec(), 1 + len)
            }
            4 => {
                // IPv6: 16 bytes
                if packet.len() < 22 {
                    return Err("Packet too small for IPv6 address".to_string());
                }
                (packet[4..20].to_vec(), 16)
            }
            _ => return Err(format!("Invalid address type: {}", atyp)),
        };

        let port_offset = 4 + addr_len;
        if packet.len() < port_offset + 2 {
            return Err("Packet too small for port".to_string());
        }

        let dst_port = u16::from_be_bytes([packet[port_offset], packet[port_offset + 1]]);
        let header_len = port_offset + 2;

        Ok((
            Self {
                frag,
                atyp,
                dst_addr,
                dst_port,
            },
            header_len,
        ))
    }

    /// Encode SOCKS5 UDP header
    fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(10 + self.dst_addr.len());

        // RSV (2 bytes)
        buf.push(0);
        buf.push(0);

        // FRAG
        buf.push(self.frag);

        // ATYP
        buf.push(self.atyp);

        // DST.ADDR
        buf.extend_from_slice(&self.dst_addr);

        // DST.PORT
        buf.extend_from_slice(&self.dst_port.to_be_bytes());

        buf
    }

    /// Get destination address as string
    fn dst_addr_string(&self) -> String {
        match self.atyp {
            1 => {
                // IPv4
                format!(
                    "{}.{}.{}.{}",
                    self.dst_addr[0], self.dst_addr[1], self.dst_addr[2], self.dst_addr[3]
                )
            }
            3 => {
                // Domain name (first byte is length)
                String::from_utf8_lossy(&self.dst_addr[1..]).to_string()
            }
            4 => {
                // IPv6
                format!(
                    "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                    self.dst_addr[0], self.dst_addr[1],
                    self.dst_addr[2], self.dst_addr[3],
                    self.dst_addr[4], self.dst_addr[5],
                    self.dst_addr[6], self.dst_addr[7],
                    self.dst_addr[8], self.dst_addr[9],
                    self.dst_addr[10], self.dst_addr[11],
                    self.dst_addr[12], self.dst_addr[13],
                    self.dst_addr[14], self.dst_addr[15],
                )
            }
            _ => "unknown".to_string(),
        }
    }
}

/// UDP session tracking for NAT traversal
#[derive(Debug)]
struct UdpSession {
    /// Client address that initiated this session
    client_addr: SocketAddr,
    /// Remote target address
    remote_addr: SocketAddr,
    /// Socket bound to remote target
    remote_socket: Arc<UdpSocket>,
    /// Last activity timestamp
    last_activity: Instant,
}

/// UDP proxy server with SOCKS5 UDP ASSOCIATE support
pub struct UdpProxyServer {
    /// Local address to bind to
    bind_addr: SocketAddr,
    /// Active UDP sessions (keyed by client address)
    sessions: Arc<RwLock<HashMap<SocketAddr, UdpSession>>>,
}

impl UdpProxyServer {
    /// Create new UDP proxy server
    pub fn new(bind_addr: SocketAddr) -> Self {
        Self {
            bind_addr,
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Start UDP proxy server
    pub async fn listen(self) -> Result<(), Box<dyn std::error::Error>> {
        let socket = UdpSocket::bind(self.bind_addr).await?;
        log::info!("UDP proxy listening on {}", self.bind_addr);

        let socket = Arc::new(socket);

        // Spawn session cleanup task
        let sessions = self.sessions.clone();
        tokio::spawn(async move {
            Self::cleanup_sessions(sessions).await;
        });

        // Main packet handling loop
        loop {
            let mut buf = vec![0u8; MAX_UDP_PACKET_SIZE];
            match socket.recv_from(&mut buf).await {
                Ok((len, client_addr)) => {
                    // Copy packet data to owned Vec for spawned task
                    let packet = buf[..len].to_vec();
                    let socket_clone = socket.clone();
                    let sessions = self.sessions.clone();

                    // Spawn task to handle packet
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_packet(
                            socket_clone,
                            sessions,
                            packet,
                            client_addr,
                        )
                        .await
                        {
                            log::error!("Error handling UDP packet from {}: {}", client_addr, e);
                        }
                    });
                }
                Err(e) => {
                    log::error!("UDP recv_from error: {}", e);
                }
            }
        }
    }

    /// Handle incoming UDP packet
    async fn handle_packet(
        socket: Arc<UdpSocket>,
        sessions: Arc<RwLock<HashMap<SocketAddr, UdpSession>>>,
        packet: Vec<u8>,
        client_addr: SocketAddr,
    ) -> Result<(), String> {
        // Parse SOCKS5 UDP header
        let (header, header_len) = Socks5UdpHeader::parse(&packet)?;
        let payload = &packet[header_len..];

        log::debug!(
            "UDP packet from {} to {}:{} (frag: {}, {} bytes)",
            client_addr,
            header.dst_addr_string(),
            header.dst_port,
            header.frag,
            payload.len()
        );

        // Check if fragmentation is used (we don't support it yet)
        if header.frag != 0 {
            log::warn!("UDP fragmentation not supported, dropping packet");
            return Err("UDP fragmentation not supported".to_string());
        }

        // Resolve destination address
        let remote_addr = Self::resolve_address(&header).await?;

        // Get or create session
        let remote_socket = {
            let mut sessions_lock = sessions.write().await;

            if let Some(session) = sessions_lock.get_mut(&client_addr) {
                // Update existing session
                session.last_activity = Instant::now();
                session.remote_socket.clone()
            } else {
                // Create new session
                log::info!("Creating new UDP session {} -> {}", client_addr, remote_addr);

                // Bind new socket for this session
                let remote_socket = UdpSocket::bind("0.0.0.0:0").await
                    .map_err(|e| format!("Failed to bind remote socket: {}", e))?;

                remote_socket.connect(remote_addr).await
                    .map_err(|e| format!("Failed to connect to {}: {}", remote_addr, e))?;

                let remote_socket = Arc::new(remote_socket);

                // Spawn reverse packet handler (remote -> client)
                let reverse_socket = socket.clone();
                let reverse_remote = remote_socket.clone();
                let reverse_client = client_addr;
                let reverse_header = header.clone();

                tokio::spawn(async move {
                    Self::handle_reverse_packets(
                        reverse_socket,
                        reverse_remote,
                        reverse_client,
                        reverse_header,
                    )
                    .await;
                });

                // Store session
                sessions_lock.insert(
                    client_addr,
                    UdpSession {
                        client_addr,
                        remote_addr,
                        remote_socket: remote_socket.clone(),
                        last_activity: Instant::now(),
                    },
                );

                remote_socket
            }
        };

        // Forward packet to remote
        remote_socket
            .send(payload)
            .await
            .map_err(|e| format!("Failed to send to remote: {}", e))?;

        log::debug!(
            "Forwarded {} bytes from {} to {}",
            payload.len(),
            client_addr,
            remote_addr
        );

        Ok(())
    }

    /// Handle reverse packets (remote -> client)
    async fn handle_reverse_packets(
        client_socket: Arc<UdpSocket>,
        remote_socket: Arc<UdpSocket>,
        client_addr: SocketAddr,
        header: Socks5UdpHeader,
    ) {
        let mut buf = vec![0u8; MAX_UDP_PACKET_SIZE];

        loop {
            match remote_socket.recv(&mut buf).await {
                Ok(len) => {
                    let payload = &buf[..len];

                    // Encode SOCKS5 UDP header + payload
                    let mut response = header.encode();
                    response.extend_from_slice(payload);

                    // Send back to client
                    if let Err(e) = client_socket.send_to(&response, client_addr).await {
                        log::error!("Failed to send reverse packet to {}: {}", client_addr, e);
                        break;
                    }

                    log::debug!(
                        "Forwarded {} bytes from remote to {}",
                        payload.len(),
                        client_addr
                    );
                }
                Err(e) => {
                    log::error!("Error receiving from remote: {}", e);
                    break;
                }
            }
        }

        log::info!("Reverse packet handler stopped for {}", client_addr);
    }

    /// Resolve destination address from SOCKS5 header
    async fn resolve_address(header: &Socks5UdpHeader) -> Result<SocketAddr, String> {
        match header.atyp {
            1 => {
                // IPv4
                let ip = std::net::Ipv4Addr::new(
                    header.dst_addr[0],
                    header.dst_addr[1],
                    header.dst_addr[2],
                    header.dst_addr[3],
                );
                Ok(SocketAddr::new(ip.into(), header.dst_port))
            }
            3 => {
                // Domain name
                let domain = String::from_utf8_lossy(&header.dst_addr[1..]);
                let addr_str = format!("{}:{}", domain, header.dst_port);

                let mut addrs = tokio::net::lookup_host(addr_str.clone())
                    .await
                    .map_err(|e| format!("DNS lookup failed for {}: {}", domain, e))?;

                addrs
                    .next()
                    .ok_or_else(|| format!("No addresses found for {}", domain))
            }
            4 => {
                // IPv6
                let ip = std::net::Ipv6Addr::from([
                    header.dst_addr[0], header.dst_addr[1],
                    header.dst_addr[2], header.dst_addr[3],
                    header.dst_addr[4], header.dst_addr[5],
                    header.dst_addr[6], header.dst_addr[7],
                    header.dst_addr[8], header.dst_addr[9],
                    header.dst_addr[10], header.dst_addr[11],
                    header.dst_addr[12], header.dst_addr[13],
                    header.dst_addr[14], header.dst_addr[15],
                ]);
                Ok(SocketAddr::new(ip.into(), header.dst_port))
            }
            _ => Err(format!("Invalid address type: {}", header.atyp)),
        }
    }

    /// Cleanup expired sessions
    async fn cleanup_sessions(sessions: Arc<RwLock<HashMap<SocketAddr, UdpSession>>>) {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;

            let mut sessions_lock = sessions.write().await;
            let now = Instant::now();
            let mut expired = Vec::new();

            for (client_addr, session) in sessions_lock.iter() {
                if now.duration_since(session.last_activity) > UDP_SESSION_TIMEOUT {
                    expired.push(*client_addr);
                }
            }

            for client_addr in expired {
                log::info!("Removing expired UDP session for {}", client_addr);
                sessions_lock.remove(&client_addr);
            }
        }
    }
}

/// Simple UDP forwarder (non-SOCKS5, direct forwarding)
pub struct SimpleUdpForwarder {
    bind_addr: SocketAddr,
    forward_addr: SocketAddr,
}

impl SimpleUdpForwarder {
    /// Create new simple UDP forwarder
    pub fn new(bind_addr: SocketAddr, forward_addr: SocketAddr) -> Self {
        Self {
            bind_addr,
            forward_addr,
        }
    }

    /// Start UDP forwarder
    pub async fn listen(self) -> Result<(), Box<dyn std::error::Error>> {
        let socket = UdpSocket::bind(self.bind_addr).await?;
        log::info!(
            "UDP forwarder {} -> {}",
            self.bind_addr,
            self.forward_addr
        );

        let socket = Arc::new(socket);
        let forward_addr = self.forward_addr;

        // Create remote socket
        let remote_socket = UdpSocket::bind("0.0.0.0:0").await?;
        remote_socket.connect(forward_addr).await?;
        let remote_socket = Arc::new(remote_socket);

        // Spawn reverse handler
        let reverse_socket = socket.clone();
        let reverse_remote = remote_socket.clone();
        tokio::spawn(async move {
            Self::forward_reverse(reverse_socket, reverse_remote).await;
        });

        // Forward client -> remote
        let mut buf = vec![0u8; MAX_UDP_PACKET_SIZE];
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, client_addr)) => {
                    let payload = &buf[..len];
                    if let Err(e) = remote_socket.send(payload).await {
                        log::error!("Failed to forward to {}: {}", forward_addr, e);
                    } else {
                        log::debug!(
                            "Forwarded {} bytes from {} to {}",
                            len,
                            client_addr,
                            forward_addr
                        );
                    }
                }
                Err(e) => {
                    log::error!("UDP recv error: {}", e);
                }
            }
        }
    }

    /// Forward reverse packets (remote -> client)
    async fn forward_reverse(client_socket: Arc<UdpSocket>, remote_socket: Arc<UdpSocket>) {
        let mut buf = vec![0u8; MAX_UDP_PACKET_SIZE];

        loop {
            match remote_socket.recv(&mut buf).await {
                Ok(len) => {
                    let payload = &buf[..len];
                    // Note: We don't track client addresses here - this is a limitation
                    // For production use, should track sessions like UdpProxyServer
                    log::debug!("Received {} bytes from remote", len);
                }
                Err(e) => {
                    log::error!("UDP reverse recv error: {}", e);
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socks5_udp_header_ipv4() {
        let mut packet = vec![0, 0, 0, 1]; // RSV + FRAG + ATYP(IPv4)
        packet.extend_from_slice(&[192, 168, 1, 1]); // IP
        packet.extend_from_slice(&[0, 80]); // Port 80
        packet.extend_from_slice(b"test data");

        let (header, header_len) = Socks5UdpHeader::parse(&packet).unwrap();
        assert_eq!(header.atyp, 1);
        assert_eq!(header.dst_port, 80);
        assert_eq!(header_len, 10);
        assert_eq!(header.dst_addr_string(), "192.168.1.1");
    }

    #[test]
    fn test_socks5_udp_header_domain() {
        let mut packet = vec![0, 0, 0, 3]; // RSV + FRAG + ATYP(Domain)
        let domain = b"example.com";
        packet.push(domain.len() as u8);
        packet.extend_from_slice(domain);
        packet.extend_from_slice(&[1, 187]); // Port 443 as big-endian u16: 0x01BB
        packet.extend_from_slice(b"test data");

        let (header, header_len) = Socks5UdpHeader::parse(&packet).unwrap();
        assert_eq!(header.atyp, 3);
        assert_eq!(header.dst_port, 443);
        assert_eq!(header_len, 4 + 1 + domain.len() + 2);
        assert_eq!(header.dst_addr_string(), "example.com");
    }

    #[test]
    fn test_socks5_udp_header_encode_decode() {
        let original = Socks5UdpHeader {
            frag: 0,
            atyp: 1,
            dst_addr: vec![8, 8, 8, 8],
            dst_port: 53,
        };

        let encoded = original.encode();
        let (decoded, _) = Socks5UdpHeader::parse(&encoded).unwrap();

        assert_eq!(decoded.frag, original.frag);
        assert_eq!(decoded.atyp, original.atyp);
        assert_eq!(decoded.dst_addr, original.dst_addr);
        assert_eq!(decoded.dst_port, original.dst_port);
    }
}
