//! Dual-Transport DNS Tunnel Client
//!
//! Client-side implementation for connecting to DNS tunnel servers
//! over both UDP and TCP with automatic fallback.
//!
//! ## Features
//!
//! - UDP transport for low latency (stateless DNS queries)
//! - TCP transport for reliability (stream-based)
//! - Automatic fallback (UDP → TCP on timeout/errors)
//! - Session management for UDP connections
//! - Full Noise Protocol encryption
//! - PSF wrapping for DPI evasion

use anyhow::{anyhow, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{Mutex, RwLock};

use crate::dns_tunnel::{build_dns_query, build_dns_response, parse_dns_query, parse_dns_response};
use crate::noise_transport::{NoiseConfig, NoiseTransport};
use crate::protocol::ProtocolId;
use crate::protocol_wrapper::{ProtocolWrapper, WrapperRole};

/// Session ID type (16-bit)
pub type SessionId = u16;

/// Transport preference
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportPreference {
    /// Use TCP only
    Tcp,
    /// Use UDP only
    Udp,
    /// Try UDP first, fallback to TCP on errors
    Auto,
}

impl TransportPreference {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "tcp" => Some(TransportPreference::Tcp),
            "udp" => Some(TransportPreference::Udp),
            "auto" => Some(TransportPreference::Auto),
            _ => None,
        }
    }
}

/// UDP transport configuration
#[derive(Debug, Clone)]
pub struct UdpClientConfig {
    /// Maximum retries for UDP packets
    pub max_retries: usize,
    /// Timeout for each retry
    pub retry_timeout: Duration,
    /// Number of failures before switching to TCP
    pub tcp_fallback_threshold: usize,
}

impl Default for UdpClientConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            retry_timeout: Duration::from_secs(1),
            tcp_fallback_threshold: 3,
        }
    }
}

/// Dual-transport DNS tunnel client
///
/// Maintains both UDP and TCP connections with automatic fallback.
/// Uses UDP by default for lower latency, switches to TCP on reliability issues.
pub struct DnsDualTransportClient {
    /// Server address
    server_addr: SocketAddr,

    /// Transport preference
    preference: TransportPreference,

    /// Noise configuration
    noise_config: NoiseConfig,

    /// Protocol ID for PSF wrapping
    protocol_id: ProtocolId,

    /// UDP configuration
    udp_config: UdpClientConfig,

    /// Current session ID for UDP
    session_id: SessionId,

    /// UDP failure counter
    udp_failures: Arc<RwLock<usize>>,

    /// UDP transport state
    udp_state: Arc<Mutex<Option<UdpTransportState>>>,

    /// TCP transport state
    tcp_state: Arc<Mutex<Option<TcpTransportState>>>,

    /// Transaction ID counter
    next_transaction_id: Arc<RwLock<u16>>,
}

/// UDP transport state
struct UdpTransportState {
    socket: UdpSocket,
    noise_transport: NoiseTransport,
    protocol_wrapper: ProtocolWrapper,
}

/// TCP transport state
struct TcpTransportState {
    stream: TcpStream,
    noise_transport: NoiseTransport,
}

impl DnsDualTransportClient {
    /// Create new dual-transport client
    pub fn new(
        server_addr: SocketAddr,
        preference: TransportPreference,
        noise_config: NoiseConfig,
        protocol_id: ProtocolId,
    ) -> Self {
        // Generate random session ID
        let session_id = rand::random::<u16>();

        Self {
            server_addr,
            preference,
            noise_config,
            protocol_id,
            udp_config: UdpClientConfig::default(),
            session_id,
            udp_failures: Arc::new(RwLock::new(0)),
            udp_state: Arc::new(Mutex::new(None)),
            tcp_state: Arc::new(Mutex::new(None)),
            next_transaction_id: Arc::new(RwLock::new(0)),
        }
    }

    /// Set UDP client configuration
    pub fn with_udp_config(mut self, config: UdpClientConfig) -> Self {
        self.udp_config = config;
        self
    }

    /// Set session ID (for testing)
    pub fn with_session_id(mut self, session_id: SessionId) -> Self {
        self.session_id = session_id;
        self
    }

    /// Send data through tunnel and receive response
    pub async fn send_receive(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self.preference {
            TransportPreference::Tcp => self.send_receive_tcp(data).await,
            TransportPreference::Udp => self.send_receive_udp(data).await,
            TransportPreference::Auto => {
                // Check UDP failure count
                let failures = *self.udp_failures.read().await;

                if failures >= self.udp_config.tcp_fallback_threshold {
                    log::warn!(
                        "UDP failures ({}) exceeded threshold, using TCP",
                        failures
                    );
                    self.send_receive_tcp(data).await
                } else {
                    // Try UDP first, fallback to TCP on error
                    match self.send_receive_udp(data).await {
                        Ok(response) => {
                            // Reset failure counter on success
                            *self.udp_failures.write().await = 0;
                            Ok(response)
                        }
                        Err(e) => {
                            log::warn!("UDP send failed, falling back to TCP: {}", e);

                            // Increment failure counter
                            *self.udp_failures.write().await += 1;

                            // Fallback to TCP
                            self.send_receive_tcp(data).await
                        }
                    }
                }
            }
        }
    }

    /// Send/receive over UDP
    async fn send_receive_udp(&self, data: &[u8]) -> Result<Vec<u8>> {
        log::debug!("Sending {} bytes via UDP to {}", data.len(), self.server_addr);

        // Get or create UDP state
        let mut udp_guard = self.udp_state.lock().await;

        if udp_guard.is_none() {
            // Establish UDP connection
            *udp_guard = Some(self.establish_udp().await?);
            log::info!("UDP connection established to {}", self.server_addr);
        }

        let state = udp_guard
            .as_mut()
            .ok_or_else(|| anyhow!("No UDP state"))?;

        // Encrypt data
        let encrypted = state.noise_transport.encrypt(data)?;

        // Wrap with PSF
        let wrapped = state.protocol_wrapper.wrap(&encrypted)?;

        // Prefix with session ID
        let mut payload = Vec::with_capacity(2 + wrapped.len());
        payload.extend_from_slice(&self.session_id.to_be_bytes());
        payload.extend_from_slice(&wrapped);

        // Get transaction ID
        let transaction_id = self.get_next_transaction_id().await;

        // Build DNS query
        let query = build_dns_query(&payload, transaction_id);

        // Send with retries
        let mut attempts = 0;
        let response_payload = loop {
            attempts += 1;

            // Send query
            state.socket.send(&query).await?;
            log::debug!(
                "Sent UDP DNS query (attempt {}, {} bytes)",
                attempts,
                query.len()
            );

            // Receive response with timeout
            let mut buf = vec![0u8; 512];
            match tokio::time::timeout(self.udp_config.retry_timeout, state.socket.recv(&mut buf))
                .await
            {
                Ok(Ok(len)) => {
                    // Parse DNS response
                    let response = &buf[..len];
                    let payload = parse_dns_response(response)
                        .map_err(|e| anyhow!("Failed to parse DNS response: {}", e))?;

                    log::debug!("Received UDP DNS response ({} bytes)", payload.len());
                    break payload;
                }
                Ok(Err(e)) => {
                    return Err(anyhow!("UDP recv error: {}", e));
                }
                Err(_) => {
                    log::warn!("UDP timeout on attempt {}/{}", attempts, self.udp_config.max_retries);

                    if attempts >= self.udp_config.max_retries {
                        return Err(anyhow!(
                            "UDP timeout after {} attempts",
                            self.udp_config.max_retries
                        ));
                    }
                }
            }
        };

        // Extract session ID and encrypted data
        if response_payload.len() < 2 {
            return Err(anyhow!("Response too short"));
        }

        let response_session_id = u16::from_be_bytes([response_payload[0], response_payload[1]]);
        if response_session_id != self.session_id {
            return Err(anyhow!(
                "Session ID mismatch: expected {:04x}, got {:04x}",
                self.session_id,
                response_session_id
            ));
        }

        let encrypted_response = &response_payload[2..];

        // Unwrap PSF
        let unwrapped = state.protocol_wrapper.unwrap(encrypted_response)?;

        // Decrypt
        let plaintext = state.noise_transport.decrypt(&unwrapped)?;

        log::debug!("Decrypted {} bytes from UDP response", plaintext.len());
        Ok(plaintext)
    }

    /// Send/receive over TCP
    async fn send_receive_tcp(&self, data: &[u8]) -> Result<Vec<u8>> {
        log::debug!("Sending {} bytes via TCP to {}", data.len(), self.server_addr);

        // Get or create TCP state
        let mut tcp_guard = self.tcp_state.lock().await;

        if tcp_guard.is_none() {
            // Establish TCP connection
            *tcp_guard = Some(self.establish_tcp().await?);
            log::info!("TCP connection established to {}", self.server_addr);
        }

        let state = tcp_guard
            .as_mut()
            .ok_or_else(|| anyhow!("No TCP state"))?;

        // Write data through Noise transport
        state
            .noise_transport
            .write(&mut state.stream, data)
            .await?;

        log::debug!("Sent {} bytes via TCP", data.len());

        // Read response
        let response = state.noise_transport.read(&mut state.stream).await?;

        log::debug!("Received {} bytes via TCP", response.len());
        Ok(response)
    }

    /// Establish UDP connection with Noise handshake
    async fn establish_udp(&self) -> Result<UdpTransportState> {
        log::info!("Establishing UDP connection to {}", self.server_addr);

        // Bind local UDP socket
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(self.server_addr).await?;

        log::debug!("UDP socket bound to {}", socket.local_addr()?);

        // Create protocol wrapper
        let protocol_wrapper =
            ProtocolWrapper::new(self.protocol_id.clone(), WrapperRole::Client, None);

        // Build Noise initiator
        let params: snow::params::NoiseParams = self.noise_config.pattern.protocol_name().parse()?;
        let mut builder = snow::Builder::new(params);

        // Set remote public key
        if let Some(ref remote_key) = self.noise_config.remote_public_key {
            let key = crate::noise_transport::NoiseKeypair::decode_public_key(remote_key)?;
            builder = builder.remote_public_key(&key);
        }

        // Set local private key if KK pattern
        if self.noise_config.pattern == crate::noise_transport::NoisePattern::KK {
            if let Some(ref local_key) = self.noise_config.local_private_key {
                let key = crate::noise_transport::NoiseKeypair::decode_private_key(local_key)?;
                builder = builder.local_private_key(&key);
            }
        }

        let mut handshake = builder.build_initiator()?;

        // Perform handshake
        let mut buf = vec![0u8; 65535];

        // Send client handshake
        let len = handshake.write_message(&[], &mut buf)?;
        let client_msg = &buf[..len];

        // Prefix with session ID
        let mut payload = Vec::with_capacity(2 + client_msg.len());
        payload.extend_from_slice(&self.session_id.to_be_bytes());
        payload.extend_from_slice(client_msg);

        let transaction_id = self.get_next_transaction_id().await;
        let query = build_dns_query(&payload, transaction_id);

        socket.send(&query).await?;
        log::debug!("Sent UDP handshake message 1");

        // Receive server handshake
        let mut response_buf = vec![0u8; 512];
        let len = tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut response_buf))
            .await??;

        let response_payload = parse_dns_response(&response_buf[..len])
            .map_err(|e| anyhow!("Failed to parse handshake response: {}", e))?;

        // Extract session ID and server message
        if response_payload.len() < 2 {
            return Err(anyhow!("Handshake response too short"));
        }

        let server_msg = &response_payload[2..];

        // Process server handshake
        handshake.read_message(server_msg, &mut buf)?;

        if !handshake.is_handshake_finished() {
            return Err(anyhow!("Handshake not complete after 1-RTT"));
        }

        log::info!("UDP Noise handshake complete");

        // Transition to transport mode
        let transport_state = handshake.into_transport_mode()?;

        // Create NoiseTransport wrapper
        let noise_transport = NoiseTransport::from_transport_state(transport_state)?;

        Ok(UdpTransportState {
            socket,
            noise_transport,
            protocol_wrapper,
        })
    }

    /// Establish TCP connection with Noise handshake
    async fn establish_tcp(&self) -> Result<TcpTransportState> {
        log::info!("Establishing TCP connection to {}", self.server_addr);

        // Connect to server
        let mut stream = TcpStream::connect(self.server_addr).await?;
        stream.set_nodelay(true)?;

        log::debug!("TCP connected to {}", self.server_addr);

        // Create protocol wrapper
        let mut protocol_wrapper =
            ProtocolWrapper::new(self.protocol_id.clone(), WrapperRole::Client, None);

        // Perform Noise handshake
        let noise_transport = NoiseTransport::client_handshake(
            &mut stream,
            &self.noise_config,
            Some(&mut protocol_wrapper),
        )
        .await?;

        log::info!("TCP Noise handshake complete");

        Ok(TcpTransportState {
            stream,
            noise_transport,
        })
    }

    /// Get next transaction ID
    async fn get_next_transaction_id(&self) -> u16 {
        let mut tid = self.next_transaction_id.write().await;
        let current = *tid;
        *tid = tid.wrapping_add(1);
        current
    }

    /// Reset UDP connection (for testing or after errors)
    pub async fn reset_udp(&self) {
        *self.udp_state.lock().await = None;
        log::info!("UDP connection reset");
    }

    /// Reset TCP connection (for testing or after errors)
    pub async fn reset_tcp(&self) {
        *self.tcp_state.lock().await = None;
        log::info!("TCP connection reset");
    }
}

// Extension to NoiseTransport for creating from existing TransportState
impl NoiseTransport {
    fn from_transport_state(transport: snow::TransportState) -> Result<Self> {
        Ok(Self {
            transport,
            read_buffer: vec![0u8; 65535],
            write_buffer: vec![0u8; 65535 + 16],
            tls_layer: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_preference_parsing() {
        assert_eq!(
            TransportPreference::from_str("tcp"),
            Some(TransportPreference::Tcp)
        );
        assert_eq!(
            TransportPreference::from_str("udp"),
            Some(TransportPreference::Udp)
        );
        assert_eq!(
            TransportPreference::from_str("auto"),
            Some(TransportPreference::Auto)
        );
        assert_eq!(TransportPreference::from_str("invalid"), None);
    }

    #[test]
    fn test_udp_config_defaults() {
        let config = UdpClientConfig::default();
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.retry_timeout, Duration::from_secs(1));
        assert_eq!(config.tcp_fallback_threshold, 3);
    }
}
