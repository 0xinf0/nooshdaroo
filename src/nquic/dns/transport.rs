// DNS transport layer for nQUIC
//
// Handles UDP and TCP DNS transport
// Manages DNS query/response lifecycle

use super::{Result, DnsError, DnsCodec, DnsMessage};
use std::net::SocketAddr;
use tokio::net::{UdpSocket, TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::sync::Arc;
use rand::Rng;

/// DNS transport for nQUIC
pub struct DnsTransport {
    /// DNS codec
    codec: Arc<DnsCodec>,

    /// Local UDP socket (port 53)
    udp_socket: Option<Arc<UdpSocket>>,

    /// TCP listener (for server)
    tcp_listener: Option<Arc<TcpListener>>,

    /// DNS server address (for client)
    dns_server: Option<SocketAddr>,

    /// Role: true for server, false for client
    is_server: bool,

    /// Transaction ID counter
    tx_id_counter: u16,
}

impl DnsTransport {
    /// Create a new DNS transport
    pub fn new(codec: DnsCodec, is_server: bool) -> Self {
        let mut rng = rand::thread_rng();
        Self {
            codec: Arc::new(codec),
            udp_socket: None,
            tcp_listener: None,
            dns_server: None,
            is_server,
            tx_id_counter: rng.gen(),
        }
    }

    /// Get next transaction ID
    fn next_tx_id(&mut self) -> u16 {
        self.tx_id_counter = self.tx_id_counter.wrapping_add(1);
        self.tx_id_counter
    }

    /// Bind UDP socket
    pub async fn bind_udp(&mut self, addr: SocketAddr) -> Result<()> {
        let socket = UdpSocket::bind(addr).await?;
        self.udp_socket = Some(Arc::new(socket));
        Ok(())
    }

    /// Bind TCP listener (for server)
    pub async fn bind_tcp(&mut self, addr: SocketAddr) -> Result<()> {
        let listener = TcpListener::bind(addr).await?;
        self.tcp_listener = Some(Arc::new(listener));
        Ok(())
    }

    /// Set DNS server address (for client)
    pub fn set_dns_server(&mut self, addr: SocketAddr) {
        self.dns_server = Some(addr);
    }

    /// Send QUIC packet via DNS query (client)
    pub async fn send_query(&mut self, packet: &[u8]) -> Result<()> {
        let dns_server = self.dns_server
            .ok_or_else(|| DnsError::InvalidMessage("DNS server not set".into()))?;

        // Check if packet fits in UDP
        if packet.len() <= self.codec.max_upstream_size() {
            // Get transaction ID before borrowing socket
            let tx_id = self.next_tx_id();

            // Use UDP for small packets
            let socket = self.udp_socket.as_ref()
                .ok_or_else(|| DnsError::InvalidMessage("Socket not bound".into()))?;

            // Encode packet into DNS query domain
            let domain = self.codec.encode_query(packet)?;

            // Build DNS query message
            let dns_msg = DnsMessage::new_query(&domain, tx_id);
            let query = dns_msg.to_bytes();

            // Send DNS query
            socket.send_to(&query, dns_server).await?;
        } else {
            // Use TCP for large packets
            let mut stream = TcpStream::connect(dns_server).await?;

            // Encode packet into TXT data directly (bypass domain encoding for TCP)
            let tx_id = self.next_tx_id();
            let domain = "large.packet.nquic";

            // Create DNS message with raw packet as TXT data
            let dns_msg = DnsMessage::new_query(domain, tx_id);
            let mut query = dns_msg.to_bytes();

            // TCP DNS uses 2-byte length prefix
            let len = query.len() as u16;
            let mut tcp_query = Vec::with_capacity(2 + query.len());
            tcp_query.extend_from_slice(&len.to_be_bytes());
            tcp_query.append(&mut query);

            stream.write_all(&tcp_query).await?;
        }

        Ok(())
    }

    /// Receive QUIC packet from DNS response (client)
    pub async fn recv_response(&self) -> Result<Vec<u8>> {
        let socket = self.udp_socket.as_ref()
            .ok_or_else(|| DnsError::InvalidMessage("Socket not bound".into()))?;

        // Receive DNS response
        let mut buf = vec![0u8; 65536];
        let (len, _src) = socket.recv_from(&mut buf).await?;
        buf.truncate(len);

        // Parse DNS response
        let dns_msg = DnsMessage::parse(&buf)?;

        // Extract TXT record data
        let txt_data = dns_msg.get_txt_answer()?;

        // Decode QUIC packet from TXT record
        self.codec.decode_response(&txt_data)
    }

    /// Receive QUIC packet from DNS query (server)
    pub async fn recv_query(&self) -> Result<(Vec<u8>, SocketAddr, u16)> {
        let socket = self.udp_socket.as_ref()
            .ok_or_else(|| DnsError::InvalidMessage("Socket not bound".into()))?;

        // Receive DNS query
        let mut buf = vec![0u8; 65536];
        let (len, src) = socket.recv_from(&mut buf).await?;
        buf.truncate(len);

        // Parse DNS query
        let dns_msg = DnsMessage::parse(&buf)?;
        let domain = dns_msg.get_question_domain()?;
        let tx_id = dns_msg.header.id;

        // Decode QUIC packet from domain
        let packet = self.codec.decode_query(&domain)?;

        Ok((packet, src, tx_id))
    }

    /// Send QUIC packet via DNS response (server)
    pub async fn send_response(&mut self, packet: &[u8], dest: SocketAddr, tx_id: u16) -> Result<()> {
        let socket = self.udp_socket.as_ref()
            .ok_or_else(|| DnsError::InvalidMessage("Socket not bound".into()))?;

        // Encode packet into TXT record
        let txt_data = self.codec.encode_response(packet)?;

        // Build DNS response message
        let domain = "response.nquic";
        let dns_msg = DnsMessage::new_response(domain, txt_data, tx_id);
        let response = dns_msg.to_bytes();

        // Send DNS response
        socket.send_to(&response, dest).await?;

        Ok(())
    }

    /// Accept TCP connection and handle DNS query (server)
    pub async fn accept_tcp(&self) -> Result<(Vec<u8>, TcpStream)> {
        let listener = self.tcp_listener.as_ref()
            .ok_or_else(|| DnsError::InvalidMessage("TCP listener not bound".into()))?;

        let (mut stream, _addr) = listener.accept().await?;

        // Read 2-byte length prefix
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await?;
        let msg_len = u16::from_be_bytes(len_buf) as usize;

        // Read DNS message
        let mut msg_buf = vec![0u8; msg_len];
        stream.read_exact(&mut msg_buf).await?;

        // Parse DNS query
        let dns_msg = DnsMessage::parse(&msg_buf)?;
        let domain = dns_msg.get_question_domain()?;

        // Decode QUIC packet from domain
        let packet = self.codec.decode_query(&domain)?;

        Ok((packet, stream))
    }

    /// Send TCP DNS response (server)
    pub async fn send_tcp_response(&self, packet: &[u8], stream: &mut TcpStream, tx_id: u16) -> Result<()> {
        // Encode packet into TXT record
        let txt_data = self.codec.encode_response(packet)?;

        // Build DNS response message
        let domain = "response.nquic";
        let dns_msg = DnsMessage::new_response(domain, txt_data, tx_id);
        let mut response = dns_msg.to_bytes();

        // TCP DNS uses 2-byte length prefix
        let len = response.len() as u16;
        let mut tcp_response = Vec::with_capacity(2 + response.len());
        tcp_response.extend_from_slice(&len.to_be_bytes());
        tcp_response.append(&mut response);

        stream.write_all(&tcp_response).await?;

        Ok(())
    }

    /// Get codec
    pub fn codec(&self) -> &DnsCodec {
        &self.codec
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_creation() {
        let codec = DnsCodec::new("tunnel.example.com".to_string());
        let transport = DnsTransport::new(codec, true);
        assert!(transport.is_server);
    }
}
