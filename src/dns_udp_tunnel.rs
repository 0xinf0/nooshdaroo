///! UDP DNS Tunnel - Complete implementation for Iran censorship bypass
///!
///! This module implements a sophisticated UDP-based DNS tunnel that:
///! - Encodes encrypted Noise protocol data in DNS query labels
///! - Maintains session state over stateless UDP
///! - Multiplexes multiple SOCKS connections over a single UDP tunnel
///! - Handles fragmentation for payloads larger than DNS limits
///! - Passes Iran's DPI by using valid DNS packet structure

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{RwLock, mpsc};
use crate::dns_tunnel::{build_dns_query, build_dns_response, parse_dns_query, parse_dns_response};

/// Session timeout for UDP tunnel (60 seconds)
const SESSION_TIMEOUT: Duration = Duration::from_secs(60);

/// Maximum DNS query payload size (conservative estimate accounting for encoding overhead)
/// DNS QNAME limit is 253 bytes, after base domain and hex encoding we get ~100 bytes of raw data
const MAX_DNS_QUERY_PAYLOAD: usize = 100;

/// Maximum DNS response payload size (accounting for 2x hex encoding + DNS overhead to stay under 512 bytes)
const MAX_DNS_RESPONSE_PAYLOAD: usize = 180;

/// Maximum UDP packet size
const MAX_UDP_PACKET_SIZE: usize = 512; // DNS standard size

/// Session ID type (16-bit identifier)
pub type SessionId = u16;

/// Packet sequence number for fragmentation
pub type SeqNum = u16;

/// Fragment metadata
#[derive(Debug, Clone)]
struct Fragment {
    seq_num: SeqNum,
    total_fragments: u16,
    data: Vec<u8>,
    received_at: Instant,
}

/// UDP tunnel session tracking
#[derive(Debug)]
struct TunnelSession {
    /// Client UDP address
    client_addr: SocketAddr,
    /// Server UDP address (for client-side tracking)
    server_addr: Option<SocketAddr>,
    /// Session ID
    session_id: SessionId,
    /// Last activity timestamp
    last_activity: Instant,
    /// Pending fragments for reassembly
    fragments: HashMap<SeqNum, Fragment>,
    /// Channel to send reassembled packets to handler
    tx: mpsc::UnboundedSender<Vec<u8>>,
}

impl TunnelSession {
    fn new(
        client_addr: SocketAddr,
        server_addr: Option<SocketAddr>,
        session_id: SessionId,
        tx: mpsc::UnboundedSender<Vec<u8>>,
    ) -> Self {
        Self {
            client_addr,
            server_addr,
            session_id,
            last_activity: Instant::now(),
            fragments: HashMap::new(),
            tx,
        }
    }

    fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Add fragment and attempt reassembly
    fn add_fragment(&mut self, fragment: Fragment) -> Option<Vec<u8>> {
        self.fragments.insert(fragment.seq_num, fragment.clone());

        // Check if we have all fragments
        if self.fragments.len() == fragment.total_fragments as usize {
            let mut all_present = true;
            for i in 0..fragment.total_fragments {
                if !self.fragments.contains_key(&i) {
                    all_present = false;
                    break;
                }
            }

            if all_present {
                // Reassemble in order
                let mut reassembled = Vec::new();
                for i in 0..fragment.total_fragments {
                    if let Some(frag) = self.fragments.get(&i) {
                        reassembled.extend_from_slice(&frag.data);
                    }
                }
                // Clear fragments
                self.fragments.clear();
                return Some(reassembled);
            }
        }

        None
    }
}

/// DNS tunnel packet header
/// Format: [session_id:2][seq_num:2][total_frags:2][payload...]
#[derive(Debug, Clone)]
struct DnsTunnelHeader {
    session_id: SessionId,
    seq_num: SeqNum,
    total_fragments: u16,
}

impl DnsTunnelHeader {
    const SIZE: usize = 6;

    fn encode(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..2].copy_from_slice(&self.session_id.to_be_bytes());
        buf[2..4].copy_from_slice(&self.seq_num.to_be_bytes());
        buf[4..6].copy_from_slice(&self.total_fragments.to_be_bytes());
        buf
    }

    fn decode(data: &[u8]) -> Result<Self, String> {
        if data.len() < Self::SIZE {
            return Err("Packet too small for DNS tunnel header".to_string());
        }

        Ok(Self {
            session_id: u16::from_be_bytes([data[0], data[1]]),
            seq_num: u16::from_be_bytes([data[2], data[3]]),
            total_fragments: u16::from_be_bytes([data[4], data[5]]),
        })
    }
}

/// UDP DNS Tunnel Server
pub struct DnsUdpTunnelServer {
    bind_addr: SocketAddr,
    sessions: Arc<RwLock<HashMap<SessionId, TunnelSession>>>,
}

impl DnsUdpTunnelServer {
    pub fn new(bind_addr: SocketAddr) -> Self {
        Self {
            bind_addr,
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Start DNS UDP tunnel server
    pub async fn listen<F, Fut>(self, handler: F) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        F: Fn(SessionId, SocketAddr, Vec<u8>) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<Vec<u8>, String>> + Send + 'static,
    {
        let socket = UdpSocket::bind(self.bind_addr).await?;
        log::info!("DNS UDP tunnel server listening on {}", self.bind_addr);
        let socket = Arc::new(socket);

        // Spawn session cleanup task
        let sessions = self.sessions.clone();
        tokio::spawn(async move {
            Self::cleanup_sessions(sessions).await;
        });

        // Main packet receiving loop
        let mut buf = vec![0u8; MAX_UDP_PACKET_SIZE];
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, client_addr)) => {
                    let packet = buf[..len].to_vec();
                    let socket_clone = socket.clone();
                    let sessions = self.sessions.clone();
                    let handler = &handler;

                    // Process DNS query
                    if let Err(e) = Self::handle_dns_query(
                        socket_clone,
                        sessions,
                        packet,
                        client_addr,
                        handler,
                    )
                    .await
                    {
                        log::error!("Error handling DNS query from {}: {}", client_addr, e);
                    }
                }
                Err(e) => {
                    log::error!("UDP recv_from error: {}", e);
                }
            }
        }
    }

    async fn handle_dns_query<F, Fut>(
        socket: Arc<UdpSocket>,
        sessions: Arc<RwLock<HashMap<SessionId, TunnelSession>>>,
        packet: Vec<u8>,
        client_addr: SocketAddr,
        handler: &F,
    ) -> Result<(), String>
    where
        F: Fn(SessionId, SocketAddr, Vec<u8>) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<Vec<u8>, String>> + Send + 'static,
    {
        // Parse DNS query
        let (transaction_id, payload) = parse_dns_query(&packet)
            .map_err(|e| format!("Failed to parse DNS query: {}", e))?;

        log::debug!(
            "DNS query from {} (tid={:04x}, {} bytes payload)",
            client_addr,
            transaction_id,
            payload.len()
        );

        // Decode tunnel header
        let header = DnsTunnelHeader::decode(&payload)?;
        let fragment_data = payload[DnsTunnelHeader::SIZE..].to_vec();

        log::debug!(
            "Session {:04x}, fragment {}/{}: {} bytes",
            header.session_id,
            header.seq_num + 1,
            header.total_fragments,
            fragment_data.len()
        );

        // Get or create session
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut sessions_lock = sessions.write().await;

        let session = sessions_lock
            .entry(header.session_id)
            .or_insert_with(|| {
                log::info!(
                    "New DNS tunnel session {:04x} from {}",
                    header.session_id,
                    client_addr
                );
                TunnelSession::new(client_addr, None, header.session_id, tx)
            });

        session.touch();

        // Add fragment and check for reassembly
        let fragment = Fragment {
            seq_num: header.seq_num,
            total_fragments: header.total_fragments,
            data: fragment_data,
            received_at: Instant::now(),
        };

        if let Some(reassembled) = session.add_fragment(fragment) {
            log::debug!(
                "Reassembled complete packet for session {:04x}: {} bytes",
                header.session_id,
                reassembled.len()
            );

            // Process reassembled packet through handler
            drop(sessions_lock); // Release lock before async call

            match handler(header.session_id, client_addr, reassembled).await {
                Ok(response) => {
                    // Send response back via DNS
                    Self::send_dns_response(
                        socket,
                        client_addr,
                        transaction_id,
                        header.session_id,
                        response,
                    )
                    .await?;
                }
                Err(e) => {
                    log::error!("Handler error for session {:04x}: {}", header.session_id, e);
                }
            }
        }

        Ok(())
    }

    async fn send_dns_response(
        socket: Arc<UdpSocket>,
        client_addr: SocketAddr,
        transaction_id: u16,
        session_id: SessionId,
        mut payload: Vec<u8>,
    ) -> Result<(), String> {
        // Fragment if necessary
        let fragments = Self::fragment_payload(session_id, &payload);

        for (seq_num, frag_data) in fragments.iter().enumerate() {
            // Build DNS response with fragment
            let response_packet = build_dns_response(
                &[], // Don't need original query
                frag_data,
                transaction_id,
            );

            socket
                .send_to(&response_packet, client_addr)
                .await
                .map_err(|e| format!("Failed to send DNS response: {}", e))?;

            log::debug!(
                "Sent DNS response to {} (session {:04x}, fragment {}/{})",
                client_addr,
                session_id,
                seq_num + 1,
                fragments.len()
            );
        }

        Ok(())
    }

    fn fragment_payload(session_id: SessionId, payload: &[u8]) -> Vec<Vec<u8>> {
        let mut fragments = Vec::new();
        let max_fragment_size = MAX_DNS_RESPONSE_PAYLOAD - DnsTunnelHeader::SIZE;

        let total_fragments = (payload.len() + max_fragment_size - 1) / max_fragment_size;

        for (seq_num, chunk) in payload.chunks(max_fragment_size).enumerate() {
            let header = DnsTunnelHeader {
                session_id,
                seq_num: seq_num as u16,
                total_fragments: total_fragments as u16,
            };

            let mut fragment = header.encode().to_vec();
            fragment.extend_from_slice(chunk);
            fragments.push(fragment);
        }

        fragments
    }

    async fn cleanup_sessions(sessions: Arc<RwLock<HashMap<SessionId, TunnelSession>>>) {
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;

            let mut sessions_lock = sessions.write().await;
            let now = Instant::now();
            let mut expired = Vec::new();

            for (session_id, session) in sessions_lock.iter() {
                if now.duration_since(session.last_activity) > SESSION_TIMEOUT {
                    expired.push(*session_id);
                }
            }

            for session_id in expired {
                log::info!("Removing expired DNS tunnel session {:04x}", session_id);
                sessions_lock.remove(&session_id);
            }
        }
    }
}

/// UDP DNS Tunnel Client
pub struct DnsUdpTunnelClient {
    server_addr: SocketAddr,
    local_bind_addr: SocketAddr,
    session_id: SessionId,
    next_transaction_id: Arc<RwLock<u16>>,
}

impl DnsUdpTunnelClient {
    pub fn new(server_addr: SocketAddr, local_bind_addr: SocketAddr, session_id: SessionId) -> Self {
        Self {
            server_addr,
            local_bind_addr,
            session_id,
            next_transaction_id: Arc::new(RwLock::new(0)),
        }
    }

    /// Send data through DNS tunnel and wait for response
    pub async fn send_and_receive(&self, payload: Vec<u8>) -> Result<Vec<u8>, String> {
        let socket = UdpSocket::bind(self.local_bind_addr)
            .await
            .map_err(|e| format!("Failed to bind UDP socket: {}", e))?;

        socket
            .connect(self.server_addr)
            .await
            .map_err(|e| format!("Failed to connect to {}: {}", self.server_addr, e))?;

        // Fragment payload
        let fragments = Self::fragment_payload(self.session_id, &payload);

        // Get transaction ID
        let transaction_id = {
            let mut tid = self.next_transaction_id.write().await;
            let current = *tid;
            *tid = tid.wrapping_add(1);
            current
        };

        // Send all fragments
        for (seq_num, frag_data) in fragments.iter().enumerate() {
            let query_packet = build_dns_query(frag_data, transaction_id);

            socket
                .send(&query_packet)
                .await
                .map_err(|e| format!("Failed to send DNS query: {}", e))?;

            log::debug!(
                "Sent DNS query fragment {}/{} (session {:04x})",
                seq_num + 1,
                fragments.len(),
                self.session_id
            );
        }

        // Receive response fragments and reassemble
        let mut response_fragments: HashMap<SeqNum, Vec<u8>> = HashMap::new();
        let mut total_fragments = 0u16;
        let mut buf = vec![0u8; MAX_UDP_PACKET_SIZE];

        // TODO: Add timeout mechanism
        while response_fragments.len() < total_fragments as usize || total_fragments == 0 {
            let len = socket
                .recv(&mut buf)
                .await
                .map_err(|e| format!("Failed to receive DNS response: {}", e))?;

            let response_packet = &buf[..len];
            let response_payload = parse_dns_response(response_packet)
                .map_err(|e| format!("Failed to parse DNS response: {}", e))?;

            // Decode tunnel header
            let header = DnsTunnelHeader::decode(&response_payload)?;
            let fragment_data = response_payload[DnsTunnelHeader::SIZE..].to_vec();

            if header.session_id != self.session_id {
                log::warn!(
                    "Received response for wrong session {:04x}, expected {:04x}",
                    header.session_id,
                    self.session_id
                );
                continue;
            }

            total_fragments = header.total_fragments;
            response_fragments.insert(header.seq_num, fragment_data);

            log::debug!(
                "Received response fragment {}/{} (session {:04x})",
                response_fragments.len(),
                total_fragments,
                self.session_id
            );
        }

        // Reassemble response
        let mut reassembled = Vec::new();
        for i in 0..total_fragments {
            if let Some(frag) = response_fragments.get(&i) {
                reassembled.extend_from_slice(frag);
            } else {
                return Err(format!("Missing fragment {} of {}", i, total_fragments));
            }
        }

        Ok(reassembled)
    }

    fn fragment_payload(session_id: SessionId, payload: &[u8]) -> Vec<Vec<u8>> {
        let mut fragments = Vec::new();
        let max_fragment_size = MAX_DNS_QUERY_PAYLOAD - DnsTunnelHeader::SIZE;

        let total_fragments = (payload.len() + max_fragment_size - 1) / max_fragment_size;

        for (seq_num, chunk) in payload.chunks(max_fragment_size).enumerate() {
            let header = DnsTunnelHeader {
                session_id,
                seq_num: seq_num as u16,
                total_fragments: total_fragments as u16,
            };

            let mut fragment = header.encode().to_vec();
            fragment.extend_from_slice(chunk);
            fragments.push(fragment);
        }

        fragments
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tunnel_header_encode_decode() {
        let header = DnsTunnelHeader {
            session_id: 0x1234,
            seq_num: 5,
            total_fragments: 10,
        };

        let encoded = header.encode();
        let decoded = DnsTunnelHeader::decode(&encoded).unwrap();

        assert_eq!(decoded.session_id, header.session_id);
        assert_eq!(decoded.seq_num, header.seq_num);
        assert_eq!(decoded.total_fragments, header.total_fragments);
    }

    #[test]
    fn test_fragmentation() {
        let payload = vec![0x42; 500]; // 500 bytes
        let fragments = DnsUdpTunnelClient::fragment_payload(0x1234, &payload);

        assert!(fragments.len() > 1); // Should be fragmented

        // Reassemble
        let mut reassembled = Vec::new();
        for frag in fragments {
            let header = DnsTunnelHeader::decode(&frag).unwrap();
            reassembled.extend_from_slice(&frag[DnsTunnelHeader::SIZE..]);
        }

        assert_eq!(reassembled, payload);
    }
}
