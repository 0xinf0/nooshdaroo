//! QUIC-over-DNS Tunnel
//!
//! High-performance DNS tunneling using QUIC protocol
//! Architecture inspired by slipstream (https://endpositive.github.io/slipstream/)
//!
//! ## Design
//! - Upstream (client→server): QUIC packets in base32-encoded DNS queries
//! - Downstream (server→client): QUIC packets in TXT record responses
//! - 24-byte overhead per packet (vs 59 bytes in dnstt)
//! - Parallel queries for maximum throughput

use anyhow::{anyhow, Result};
use base32::{Alphabet, decode as base32_decode, encode as base32_encode};
use bytes::{Bytes, BytesMut};
use quinn::{Endpoint, ServerConfig, ClientConfig, Connection, TransportConfig, AsyncUdpSocket, UdpPoller};
use quinn::udp::{RecvMeta, Transmit};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName as RustlsServerName};
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

/// DNS packet transport for QUIC
/// Implements quinn's AsyncUdpSocket trait to bridge QUIC ↔ DNS
#[derive(Debug)]
pub struct DnsPacketTransport {
    socket: Arc<UdpSocket>,
    server_addr: SocketAddr,
    #[allow(dead_code)]
    rx_queue: mpsc::UnboundedReceiver<(Bytes, SocketAddr)>,
    tx_queue: mpsc::UnboundedSender<(Bytes, SocketAddr)>,
}

impl DnsPacketTransport {
    /// Create client-side DNS transport
    pub async fn new_client(server_addr: SocketAddr) -> Result<Self> {
        let local_addr: SocketAddr = if server_addr.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        }.parse()?;

        let socket = UdpSocket::bind(local_addr).await?;
        let (tx_queue, mut rx_task) = mpsc::unbounded_channel();
        let (tx_task, rx_queue) = mpsc::unbounded_channel();

        // Background task: send DNS queries with QUIC packets
        let socket_clone = Arc::new(socket);
        let send_socket = socket_clone.clone();
        tokio::spawn(async move {
            while let Some((quic_packet, dest)) = rx_task.recv().await {
                // Encode QUIC packet in base32 DNS query
                if let Ok(dns_query) = build_dns_query_with_quic(&quic_packet) {
                    let _ = send_socket.send_to(&dns_query, dest).await;
                }
            }
        });

        // Background task: receive DNS responses and extract QUIC packets
        let recv_socket = socket_clone.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                match recv_socket.recv_from(&mut buf).await {
                    Ok((n, addr)) => {
                        // Extract QUIC packet from DNS TXT response
                        if let Ok(quic_packet) = parse_dns_response_quic(&buf[..n]) {
                            let _ = tx_task.send((Bytes::from(quic_packet), addr));
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(Self {
            socket: socket_clone,
            server_addr,
            rx_queue,
            tx_queue,
        })
    }

    /// Create server-side DNS transport
    pub async fn new_server(listen_addr: SocketAddr) -> Result<Self> {
        let socket = UdpSocket::bind(listen_addr).await?;
        let (tx_queue, mut rx_task) = mpsc::unbounded_channel();
        let (tx_task, rx_queue) = mpsc::unbounded_channel();

        let socket_clone = Arc::new(socket);

        // Background task: send DNS responses with QUIC packets
        let send_socket = socket_clone.clone();
        tokio::spawn(async move {
            while let Some((quic_packet, dest)) = rx_task.recv().await {
                // Wrap QUIC packet in TXT record response
                if let Ok(dns_response) = build_dns_response_with_quic(&quic_packet) {
                    let _ = send_socket.send_to(&dns_response, dest).await;
                }
            }
        });

        // Background task: receive DNS queries and extract QUIC packets
        let recv_socket = socket_clone.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                match recv_socket.recv_from(&mut buf).await {
                    Ok((n, addr)) => {
                        // Extract QUIC packet from base32-encoded query
                        if let Ok(quic_packet) = parse_dns_query_quic(&buf[..n]) {
                            let _ = tx_task.send((Bytes::from(quic_packet), addr));
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(Self {
            socket: socket_clone,
            server_addr: listen_addr,
            rx_queue,
            tx_queue,
        })
    }

    /// Send QUIC packet via DNS
    pub async fn send_quic(&self, packet: &[u8], dest: SocketAddr) -> Result<()> {
        self.tx_queue.send((Bytes::from(packet.to_vec()), dest))
            .map_err(|_| anyhow!("Send queue closed"))?;
        Ok(())
    }

    /// Receive QUIC packet from DNS
    pub async fn recv_quic(&mut self) -> Result<(Bytes, SocketAddr)> {
        self.rx_queue.recv().await
            .ok_or_else(|| anyhow!("Receive queue closed"))
    }
}

/// AsyncUdpSocket implementation for quinn QUIC
impl AsyncUdpSocket for DnsPacketTransport {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(DnsPoller { transport: self })
    }

    fn may_fragment(&self) -> bool {
        false  // DNS has its own fragmentation
    }

    fn max_transmit_segments(&self) -> usize {
        1  // Send one DNS query per QUIC packet
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        // Queue the QUIC packet for DNS transmission
        let packet = transmit.contents.to_vec();
        let dest = transmit.destination;

        self.tx_queue.send((Bytes::from(packet), dest))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "Send queue closed"))?;

        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        metas: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        // Try to receive QUIC packet from DNS
        match self.rx_queue.try_recv() {
            Ok((data, addr)) => {
                if bufs.is_empty() || metas.is_empty() {
                    return Poll::Ready(Ok(0));
                }

                let len = data.len().min(bufs[0].len());
                bufs[0][..len].copy_from_slice(&data[..len]);

                metas[0] = RecvMeta {
                    len,
                    stride: len,
                    addr,
                    ecn: None,
                    dst_ip: None,
                };

                Poll::Ready(Ok(1))
            }
            Err(mpsc::error::TryRecvError::Empty) => {
                // No data available yet
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(mpsc::error::TryRecvError::Disconnected) => {
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "Receive queue closed"
                )))
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}

#[derive(Debug)]
struct DnsPoller {
    transport: Arc<DnsPacketTransport>,
}

impl UdpPoller for DnsPoller {
    fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))  // Always writable (queued)
    }
}

/// Build DNS query with QUIC packet in base32-encoded subdomain
fn build_dns_query_with_quic(quic_packet: &[u8]) -> Result<Vec<u8>> {
    let mut dns_packet = Vec::new();

    // DNS header
    let transaction_id = rand::random::<u16>();
    dns_packet.extend_from_slice(&transaction_id.to_be_bytes());
    dns_packet.extend_from_slice(&[0x01, 0x00]); // Standard query
    dns_packet.extend_from_slice(&[0x00, 0x01]); // 1 question
    dns_packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // No answers/authority/additional

    // QNAME: base32-encoded QUIC packet as subdomain
    let base32_data = base32_encode(Alphabet::RFC4648 { padding: false }, quic_packet);

    // Split into DNS labels (max 63 chars each)
    for chunk in base32_data.as_bytes().chunks(63) {
        dns_packet.push(chunk.len() as u8);
        dns_packet.extend_from_slice(chunk);
    }

    // Append tunnel domain (e.g., tunnel.nooshdaroo.net)
    for label in &["tunnel", "nooshdaroo", "net"] {
        dns_packet.push(label.len() as u8);
        dns_packet.extend_from_slice(label.as_bytes());
    }
    dns_packet.push(0); // Null terminator

    // QTYPE: TXT (0x0010), QCLASS: IN (0x0001)
    dns_packet.extend_from_slice(&[0x00, 0x10, 0x00, 0x01]);

    Ok(dns_packet)
}

/// Parse DNS query and extract QUIC packet from base32 subdomain
fn parse_dns_query_quic(dns_packet: &[u8]) -> Result<Vec<u8>> {
    if dns_packet.len() < 12 {
        return Err(anyhow!("DNS packet too short"));
    }

    // Skip header, parse QNAME
    let mut pos = 12;
    let mut base32_data = String::new();

    while pos < dns_packet.len() && dns_packet[pos] != 0 {
        let len = dns_packet[pos] as usize;
        pos += 1;

        if pos + len > dns_packet.len() {
            return Err(anyhow!("Invalid QNAME"));
        }

        let label = std::str::from_utf8(&dns_packet[pos..pos + len])?;

        // Stop at tunnel domain
        if label == "tunnel" || label == "nooshdaroo" || label == "net" {
            break;
        }

        base32_data.push_str(label);
        pos += len;
    }

    // Decode base32 to get QUIC packet
    let quic_packet = base32_decode(Alphabet::RFC4648 { padding: false }, &base32_data)
        .ok_or_else(|| anyhow!("Base32 decode failed"))?;

    Ok(quic_packet)
}

/// Build DNS response with QUIC packet in TXT record
fn build_dns_response_with_quic(quic_packet: &[u8]) -> Result<Vec<u8>> {
    let mut dns_packet = Vec::new();

    // DNS header
    let transaction_id = rand::random::<u16>();
    dns_packet.extend_from_slice(&transaction_id.to_be_bytes());
    dns_packet.extend_from_slice(&[0x81, 0x80]); // Response flags
    dns_packet.extend_from_slice(&[0x00, 0x01]); // 1 question
    dns_packet.extend_from_slice(&[0x00, 0x01]); // 1 answer
    dns_packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // No authority/additional

    // Question section (minimal)
    for label in &["tunnel", "nooshdaroo", "net"] {
        dns_packet.push(label.len() as u8);
        dns_packet.extend_from_slice(label.as_bytes());
    }
    dns_packet.push(0);
    dns_packet.extend_from_slice(&[0x00, 0x10, 0x00, 0x01]); // TXT, IN

    // Answer section: TXT record with raw QUIC packet
    dns_packet.extend_from_slice(&[0xc0, 0x0c]); // Name pointer
    dns_packet.extend_from_slice(&[0x00, 0x10]); // TYPE: TXT
    dns_packet.extend_from_slice(&[0x00, 0x01]); // CLASS: IN
    dns_packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x3c]); // TTL: 60s

    // RDATA: raw QUIC packet in TXT format
    let mut txt_data = Vec::new();
    for chunk in quic_packet.chunks(255) {
        txt_data.push(chunk.len() as u8);
        txt_data.extend_from_slice(chunk);
    }

    dns_packet.extend_from_slice(&(txt_data.len() as u16).to_be_bytes());
    dns_packet.extend_from_slice(&txt_data);

    Ok(dns_packet)
}

/// Parse DNS response and extract QUIC packet from TXT record
fn parse_dns_response_quic(dns_packet: &[u8]) -> Result<Vec<u8>> {
    if dns_packet.len() < 12 {
        return Err(anyhow!("DNS packet too short"));
    }

    // Check answer count
    let ancount = u16::from_be_bytes([dns_packet[6], dns_packet[7]]);
    if ancount == 0 {
        return Err(anyhow!("No answers"));
    }

    // Skip question section
    let mut pos = 12;
    while pos < dns_packet.len() && dns_packet[pos] != 0 {
        let len = dns_packet[pos] as usize;
        pos += 1 + len;
    }
    pos += 5; // Null + QTYPE + QCLASS

    // Skip answer name (2 bytes if compressed)
    if pos < dns_packet.len() && dns_packet[pos] == 0xc0 {
        pos += 2;
    }

    // Skip TYPE, CLASS, TTL (10 bytes)
    pos += 10;

    // Read RDLENGTH
    if pos + 2 > dns_packet.len() {
        return Err(anyhow!("Truncated response"));
    }
    let rdlength = u16::from_be_bytes([dns_packet[pos], dns_packet[pos + 1]]) as usize;
    pos += 2;

    // Extract TXT data (skip length bytes)
    let txt_end = pos + rdlength;
    if txt_end > dns_packet.len() {
        return Err(anyhow!("RDATA exceeds packet"));
    }

    let mut quic_packet = Vec::new();
    while pos < txt_end {
        let chunk_len = dns_packet[pos] as usize;
        pos += 1;
        if pos + chunk_len > txt_end {
            break;
        }
        quic_packet.extend_from_slice(&dns_packet[pos..pos + chunk_len]);
        pos += chunk_len;
    }

    Ok(quic_packet)
}

/// Skip certificate verification for self-signed certs
struct SkipServerVerification;

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer,
        _intermediates: &[CertificateDer],
        _server_name: &RustlsServerName,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

/// Create optimized QUIC server configuration
pub fn create_server_config() -> Result<ServerConfig> {
    // Generate self-signed certificate
    let cert = rcgen::generate_simple_self_signed(vec!["nooshdaroo.net".into()])?;

    let key_der = PrivateKeyDer::Pkcs8(cert.serialize_private_key_der().into());
    let cert_der = CertificateDer::from(cert.serialize_der()?);

    let mut server_config = ServerConfig::with_single_cert(vec![cert_der], key_der)
        .map_err(|e| anyhow!("Failed to create server config: {}", e))?;

    // Slipstream optimization: Large windows for bandwidth-delay product
    let mut transport = TransportConfig::default();
    transport.max_concurrent_bidi_streams(2048u32.into());
    transport.send_window(15_000_000); // 15MB
    transport.receive_window(15_000_000); // 15MB
    transport.stream_receive_window(10_000_000u32.into());
    transport.keep_alive_interval(Some(Duration::from_secs(5)));

    server_config.transport_config(Arc::new(transport));
    Ok(server_config)
}

/// Create optimized QUIC client configuration
pub fn create_client_config() -> Result<ClientConfig> {
    let crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();

    let mut client_config = ClientConfig::new(Arc::new(crypto));

    // Slipstream optimization: Large windows
    let mut transport = TransportConfig::default();
    transport.max_concurrent_bidi_streams(2048u32.into());
    transport.send_window(15_000_000);
    transport.receive_window(15_000_000);
    transport.stream_receive_window(10_000_000u32.into());
    transport.keep_alive_interval(Some(Duration::from_secs(5)));

    client_config.transport_config(Arc::new(transport));
    Ok(client_config)
}

/// Create QUIC server endpoint over DNS transport
pub async fn create_server_endpoint(listen_addr: SocketAddr) -> Result<Endpoint> {
    let transport = DnsPacketTransport::new_server(listen_addr).await?;
    let server_config = create_server_config()?;

    log::info!("Creating QUIC server endpoint on {}", listen_addr);

    let endpoint = Endpoint::new_with_abstract_socket(
        Default::default(),
        Some(server_config),
        Arc::new(transport),
        Arc::new(quinn::TokioRuntime),
    )
    .map_err(|e| anyhow!("Failed to create QUIC endpoint: {}", e))?;

    Ok(endpoint)
}

/// Create QUIC client endpoint and connect to server via DNS transport
pub async fn create_client_endpoint(server_addr: SocketAddr) -> Result<Connection> {
    let transport = DnsPacketTransport::new_client(server_addr).await?;
    let client_config = create_client_config()?;

    log::info!("Creating QUIC client endpoint to {}", server_addr);

    let mut endpoint = Endpoint::new_with_abstract_socket(
        Default::default(),
        None,
        Arc::new(transport),
        Arc::new(quinn::TokioRuntime),
    )
    .map_err(|e| anyhow!("Failed to create QUIC endpoint: {}", e))?;

    let conn = endpoint
        .connect_with(client_config, server_addr, "nooshdaroo.net")?
        .await
        .map_err(|e| anyhow!("QUIC connection failed: {}", e))?;

    log::info!("QUIC connection established to {}", server_addr);

    Ok(conn)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quic_packet_roundtrip() {
        let quic_data = b"QUIC packet payload test data";

        // Build DNS query with QUIC packet
        let dns_query = build_dns_query_with_quic(quic_data).unwrap();

        // Parse it back
        let extracted = parse_dns_query_quic(&dns_query).unwrap();

        assert_eq!(&extracted, quic_data);
    }

    #[test]
    fn test_response_roundtrip() {
        let quic_data = b"Server QUIC response";

        // Build DNS response
        let dns_response = build_dns_response_with_quic(quic_data).unwrap();

        // Parse it back
        let extracted = parse_dns_response_quic(&dns_response).unwrap();

        assert_eq!(&extracted, quic_data);
    }
}
