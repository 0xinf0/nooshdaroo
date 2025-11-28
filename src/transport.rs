//! Transport Abstraction Layer
//!
//! Provides unified interface for both stream (TCP/TLS) and datagram (UDP/QUIC/WebRTC) transports.
//! This layer respects the fundamental differences between connection-oriented and connectionless protocols.

use anyhow::Result;
use async_trait::async_trait;
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite};

/// Transport semantics - either stream-based or datagram-based
pub enum TransportSemantics {
    /// Connection-oriented, reliable, ordered byte stream
    /// Examples: TCP, TLS over TCP, WebSocket
    Stream(Box<dyn StreamTransport>),

    /// Connectionless, message-oriented datagrams
    /// Examples: UDP, QUIC datagrams, DNS, WebRTC data channels
    Datagram(Box<dyn DatagramTransport>),
}

/// Trait for stream-based transports (TCP-like semantics)
#[async_trait]
pub trait StreamTransport: AsyncRead + AsyncWrite + Unpin + Send + Sync {
    /// Get the remote peer address
    fn peer_addr(&self) -> Result<SocketAddr>;

    /// Close the stream gracefully
    async fn close(&mut self) -> Result<()>;
}

/// Trait for datagram-based transports (UDP-like semantics)
#[async_trait]
pub trait DatagramTransport: Send + Sync {
    /// Send a complete message (not partial)
    /// The transport is responsible for fragmentation if needed
    async fn send(&self, data: &[u8]) -> Result<()>;

    /// Receive a complete message (blocks until full message received)
    async fn recv(&self) -> Result<Vec<u8>>;

    /// Maximum message size this transport can handle
    /// Messages larger than this will be rejected or need fragmentation
    fn max_message_size(&self) -> usize;

    /// Get the remote peer address
    fn peer_addr(&self) -> Result<SocketAddr>;

    /// Close the datagram transport
    async fn close(&mut self) -> Result<()>;
}

/// Transport type identifier for protocol routing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportType {
    /// TCP-based stream transport
    Tcp,
    /// TLS over TCP stream transport
    Tls,
    /// HTTP/2 multiplexed stream
    Http2,
    /// WebSocket stream
    WebSocket,
    /// UDP datagram transport
    Udp,
    /// DNS over UDP datagram transport
    DnsUdp,
    /// QUIC datagram transport
    Quic,
    /// WebRTC data channel transport
    WebRtc,
}

impl TransportType {
    /// Check if this is a stream-based transport
    pub fn is_stream(&self) -> bool {
        matches!(
            self,
            Self::Tcp | Self::Tls | Self::Http2 | Self::WebSocket
        )
    }

    /// Check if this is a datagram-based transport
    pub fn is_datagram(&self) -> bool {
        matches!(
            self,
            Self::Udp | Self::DnsUdp | Self::Quic | Self::WebRtc
        )
    }

    /// Does this transport use UDP SOCKS5?
    pub fn uses_udp_socks(&self) -> bool {
        matches!(
            self,
            Self::Udp | Self::DnsUdp | Self::Quic | Self::WebRtc
        )
    }

    /// Does this transport use TCP SOCKS5?
    pub fn uses_tcp_socks(&self) -> bool {
        matches!(
            self,
            Self::Tcp | Self::Tls | Self::Http2 | Self::WebSocket
        )
    }
}

/// Transport configuration
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// Type of transport to use
    pub transport_type: TransportType,
    /// Server address
    pub server_addr: SocketAddr,
    /// Enable encryption (Noise Protocol)
    pub enable_encryption: bool,
    /// Protocol wrapper ID for DPI evasion
    pub protocol_id: Option<String>,
}
