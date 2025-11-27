//! Dual-Transport DNS Tunnel Server
//!
//! Listens on port 53 for both UDP and TCP with full Noise Protocol encryption
//! and PSF (Protocol Signature Format) wrapping for DPI evasion.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────┐
//! │      Dual Transport Server (Port 53)        │
//! ├──────────────────┬──────────────────────────┤
//! │   UDP Handler    │      TCP Handler         │
//! │ (Stateless DNS)  │  (Stream-based DNS/TLS)  │
//! └────────┬─────────┴────────┬─────────────────┘
//!          │                  │
//!          │ Noise Encryption │
//!          │ PSF Wrapping     │
//!          ▼                  ▼
//!     [App Data]         [App Data]
//! ```

use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::RwLock;

use crate::dns_tunnel::{build_dns_query, build_dns_response, parse_dns_query, parse_dns_response};
use crate::noise_transport::{NoiseConfig, NoiseTransport};
use crate::protocol::ProtocolId;
use crate::protocol_wrapper::{ProtocolWrapper, WrapperRole};

/// Session timeout for UDP connections (60 seconds)
const SESSION_TIMEOUT: Duration = Duration::from_secs(60);

/// Maximum UDP packet size for DNS (RFC 1035)
const MAX_DNS_PACKET_SIZE: usize = 512;

/// Maximum Noise message size (64 KB)
const MAX_NOISE_MESSAGE_SIZE: usize = 65535;

/// Session ID type (16-bit identifier for UDP sessions)
pub type SessionId = u16;

/// Transport mode configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportMode {
    /// TCP only
    Tcp,
    /// UDP only
    Udp,
    /// Both TCP and UDP on same port
    Dual,
}

impl TransportMode {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "tcp" => Some(TransportMode::Tcp),
            "udp" => Some(TransportMode::Udp),
            "dual" | "both" => Some(TransportMode::Dual),
            _ => None,
        }
    }
}

/// UDP session tracking for stateless Noise Protocol over UDP
///
/// Each UDP session maintains:
/// - Noise handshake state (during handshake phase)
/// - Noise transport state (after handshake complete)
/// - Protocol wrapper for PSF wrapping
/// - Activity tracking for timeout cleanup
#[derive(Debug)]
struct UdpSession {
    /// Unique session identifier
    session_id: SessionId,

    /// Client UDP address
    client_addr: SocketAddr,

    /// Noise handshake state (only during handshake)
    handshake_state: Option<snow::HandshakeState>,

    /// Noise transport state (after handshake complete)
    transport_state: Option<snow::TransportState>,

    /// Protocol wrapper for this session
    protocol_wrapper: ProtocolWrapper,

    /// Last activity timestamp
    last_activity: Instant,

    /// Buffers for Noise operations
    read_buffer: Vec<u8>,
    write_buffer: Vec<u8>,
}

impl UdpSession {
    /// Create new UDP session in handshake mode
    fn new(
        session_id: SessionId,
        client_addr: SocketAddr,
        protocol_id: ProtocolId,
        noise_config: &NoiseConfig,
    ) -> Result<Self> {
        // Build Noise responder for server-side handshake
        let params: snow::params::NoiseParams = noise_config.pattern.protocol_name().parse()?;
        let mut builder = snow::Builder::new(params);

        // Set server's private key
        if let Some(ref local_key) = noise_config.local_private_key {
            let key = crate::noise_transport::NoiseKeypair::decode_private_key(local_key)?;
            builder = builder.local_private_key(&key);
        }

        // Set remote public key if KK pattern
        if noise_config.pattern == crate::noise_transport::NoisePattern::KK {
            if let Some(ref remote_key) = noise_config.remote_public_key {
                let key = crate::noise_transport::NoiseKeypair::decode_public_key(remote_key)?;
                builder = builder.remote_public_key(&key);
            }
        }

        let handshake_state = builder.build_responder()?;

        // Create protocol wrapper for PSF wrapping
        let protocol_wrapper = ProtocolWrapper::new(protocol_id, WrapperRole::Server, None);

        Ok(Self {
            session_id,
            client_addr,
            handshake_state: Some(handshake_state),
            transport_state: None,
            protocol_wrapper,
            last_activity: Instant::now(),
            read_buffer: vec![0u8; MAX_NOISE_MESSAGE_SIZE],
            write_buffer: vec![0u8; MAX_NOISE_MESSAGE_SIZE + 16], // +16 for AEAD tag
        })
    }

    /// Update last activity timestamp
    fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Check if session has expired
    fn is_expired(&self) -> bool {
        Instant::now().duration_since(self.last_activity) > SESSION_TIMEOUT
    }

    /// Process handshake message and return response
    fn process_handshake(&mut self, client_msg: &[u8]) -> Result<Vec<u8>> {
        let handshake = self
            .handshake_state
            .as_mut()
            .ok_or_else(|| anyhow!("No handshake state"))?;

        // Read client's handshake message
        handshake.read_message(client_msg, &mut [])?;

        // Generate server's handshake response
        let len = handshake.write_message(&[], &mut self.write_buffer)?;
        let response = self.write_buffer[..len].to_vec();

        // Check if handshake is complete
        if handshake.is_handshake_finished() {
            // Transition to transport mode
            let transport = std::mem::replace(&mut self.handshake_state, None)
                .unwrap()
                .into_transport_mode()?;

            self.transport_state = Some(transport);
            log::info!(
                "UDP session {:04x} handshake complete with {}",
                self.session_id,
                self.client_addr
            );
        }

        Ok(response)
    }

    /// Decrypt and process application data
    fn process_data(&mut self, encrypted: &[u8]) -> Result<Vec<u8>> {
        let transport = self
            .transport_state
            .as_mut()
            .ok_or_else(|| anyhow!("Session not in transport mode"))?;

        // Decrypt Noise message
        let len = transport.read_message(encrypted, &mut self.read_buffer)?;
        Ok(self.read_buffer[..len].to_vec())
    }

    /// Encrypt application data response
    fn encrypt_response(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let transport = self
            .transport_state
            .as_mut()
            .ok_or_else(|| anyhow!("Session not in transport mode"))?;

        // Encrypt with Noise
        let len = transport.write_message(plaintext, &mut self.write_buffer)?;
        Ok(self.write_buffer[..len].to_vec())
    }
}

/// Dual-transport DNS tunnel server
///
/// Supports three modes:
/// - TCP only: Stream-based DNS/TLS transport
/// - UDP only: Stateless DNS queries with session tracking
/// - Dual: Both TCP and UDP on the same port (53)
pub struct DnsDualTransportServer {
    /// Bind address (typically 0.0.0.0:53 or 127.0.0.1:53)
    bind_addr: SocketAddr,

    /// Transport mode (TCP, UDP, or Dual)
    mode: TransportMode,

    /// Noise Protocol configuration
    noise_config: NoiseConfig,

    /// Protocol ID for PSF wrapping (e.g., "dns", "dns-google")
    protocol_id: ProtocolId,

    /// UDP session state (shared between handlers)
    udp_sessions: Arc<RwLock<HashMap<SessionId, UdpSession>>>,
}

impl DnsDualTransportServer {
    /// Create new dual-transport server
    pub fn new(
        bind_addr: SocketAddr,
        mode: TransportMode,
        noise_config: NoiseConfig,
        protocol_id: ProtocolId,
    ) -> Self {
        Self {
            bind_addr,
            mode,
            noise_config,
            protocol_id,
            udp_sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Start listening on configured transport(s)
    pub async fn listen(self) -> Result<()> {
        match self.mode {
            TransportMode::Tcp => {
                log::info!("Starting TCP-only DNS tunnel server on {}", self.bind_addr);
                self.listen_tcp().await
            }
            TransportMode::Udp => {
                log::info!("Starting UDP-only DNS tunnel server on {}", self.bind_addr);
                self.listen_udp().await
            }
            TransportMode::Dual => {
                log::info!(
                    "Starting dual-transport (TCP+UDP) DNS tunnel server on {}",
                    self.bind_addr
                );
                self.listen_dual().await
            }
        }
    }

    /// Listen on TCP only
    async fn listen_tcp(self) -> Result<()> {
        let listener = TcpListener::bind(self.bind_addr).await?;
        log::info!("TCP DNS tunnel listening on {}", self.bind_addr);

        loop {
            let (stream, client_addr) = listener.accept().await?;
            log::debug!("TCP connection from {}", client_addr);

            let noise_config = self.noise_config.clone();
            let protocol_id = self.protocol_id.clone();

            tokio::spawn(async move {
                if let Err(e) =
                    handle_tcp_connection(stream, client_addr, noise_config, protocol_id).await
                {
                    log::error!("TCP connection error from {}: {}", client_addr, e);
                }
            });
        }
    }

    /// Listen on UDP only
    async fn listen_udp(self) -> Result<()> {
        let socket = UdpSocket::bind(self.bind_addr).await?;
        log::info!("UDP DNS tunnel listening on {}", self.bind_addr);

        // Enable SO_REUSEADDR for port reuse
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let fd = socket.as_raw_fd();
            unsafe {
                let optval: libc::c_int = 1;
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_REUSEADDR,
                    &optval as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&optval) as libc::socklen_t,
                );
            }
        }

        let socket = Arc::new(socket);

        // Spawn session cleanup task
        let sessions = self.udp_sessions.clone();
        tokio::spawn(async move {
            cleanup_expired_sessions(sessions).await;
        });

        // Main UDP receive loop
        let mut buf = vec![0u8; MAX_DNS_PACKET_SIZE];
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, client_addr)) => {
                    let packet = buf[..len].to_vec();
                    let socket_clone = socket.clone();
                    let sessions = self.udp_sessions.clone();
                    let noise_config = self.noise_config.clone();
                    let protocol_id = self.protocol_id.clone();

                    tokio::spawn(async move {
                        if let Err(e) = handle_udp_packet(
                            socket_clone,
                            packet,
                            client_addr,
                            sessions,
                            noise_config,
                            protocol_id,
                        )
                        .await
                        {
                            log::debug!("UDP packet error from {}: {}", client_addr, e);
                        }
                    });
                }
                Err(e) => {
                    log::error!("UDP recv_from error: {}", e);
                }
            }
        }
    }

    /// Listen on both TCP and UDP (dual mode)
    async fn listen_dual(self) -> Result<()> {
        // Bind UDP socket first
        let udp_socket = UdpSocket::bind(self.bind_addr).await?;
        log::info!("UDP DNS tunnel bound to {}", self.bind_addr);

        // Enable SO_REUSEADDR and SO_REUSEPORT for dual binding
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let fd = udp_socket.as_raw_fd();
            unsafe {
                let optval: libc::c_int = 1;
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_REUSEADDR,
                    &optval as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&optval) as libc::socklen_t,
                );
                #[cfg(target_os = "linux")]
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_REUSEPORT,
                    &optval as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&optval) as libc::socklen_t,
                );
            }
        }

        // Bind TCP listener on same port (different socket type)
        let tcp_listener = TcpListener::bind(self.bind_addr).await?;
        log::info!("TCP DNS tunnel bound to {}", self.bind_addr);

        let udp_socket = Arc::new(udp_socket);
        let udp_sessions = self.udp_sessions.clone();

        // Spawn session cleanup task
        let sessions_cleanup = udp_sessions.clone();
        tokio::spawn(async move {
            cleanup_expired_sessions(sessions_cleanup).await;
        });

        // Spawn UDP handler
        let udp_noise_config = self.noise_config.clone();
        let udp_protocol_id = self.protocol_id.clone();
        let udp_sessions_clone = udp_sessions.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_DNS_PACKET_SIZE];
            loop {
                match udp_socket.recv_from(&mut buf).await {
                    Ok((len, client_addr)) => {
                        let packet = buf[..len].to_vec();
                        let socket_clone = udp_socket.clone();
                        let sessions = udp_sessions_clone.clone();
                        let noise_config = udp_noise_config.clone();
                        let protocol_id = udp_protocol_id.clone();

                        tokio::spawn(async move {
                            if let Err(e) = handle_udp_packet(
                                socket_clone,
                                packet,
                                client_addr,
                                sessions,
                                noise_config,
                                protocol_id,
                            )
                            .await
                            {
                                log::debug!("UDP packet error from {}: {}", client_addr, e);
                            }
                        });
                    }
                    Err(e) => {
                        log::error!("UDP recv_from error: {}", e);
                    }
                }
            }
        });

        // Spawn TCP handler
        let tcp_noise_config = self.noise_config;
        let tcp_protocol_id = self.protocol_id;
        tokio::spawn(async move {
            loop {
                match tcp_listener.accept().await {
                    Ok((stream, client_addr)) => {
                        log::debug!("TCP connection from {}", client_addr);
                        let noise_config = tcp_noise_config.clone();
                        let protocol_id = tcp_protocol_id.clone();

                        tokio::spawn(async move {
                            if let Err(e) = handle_tcp_connection(
                                stream,
                                client_addr,
                                noise_config,
                                protocol_id,
                            )
                            .await
                            {
                                log::error!("TCP connection error from {}: {}", client_addr, e);
                            }
                        });
                    }
                    Err(e) => {
                        log::error!("TCP accept error: {}", e);
                    }
                }
            }
        });

        // Keep server alive
        std::future::pending::<()>().await;
        Ok(())
    }
}

/// Handle UDP DNS packet
async fn handle_udp_packet(
    socket: Arc<UdpSocket>,
    packet: Vec<u8>,
    client_addr: SocketAddr,
    sessions: Arc<RwLock<HashMap<SessionId, UdpSession>>>,
    noise_config: NoiseConfig,
    protocol_id: ProtocolId,
) -> Result<()> {
    // Parse DNS query
    let (transaction_id, dns_payload) = parse_dns_query(&packet)
        .map_err(|e| anyhow!("Failed to parse DNS query: {}", e))?;

    log::debug!(
        "UDP DNS query from {} (tid={:04x}, {} bytes)",
        client_addr,
        transaction_id,
        dns_payload.len()
    );

    // Extract session ID from first 2 bytes
    if dns_payload.len() < 2 {
        return Err(anyhow!("DNS payload too short for session ID"));
    }

    let session_id = u16::from_be_bytes([dns_payload[0], dns_payload[1]]);
    let encrypted_data = &dns_payload[2..];

    log::debug!("Session ID: {:04x}, {} bytes encrypted data", session_id, encrypted_data.len());

    // Get or create session
    let mut sessions_guard = sessions.write().await;

    let session = sessions_guard.entry(session_id).or_insert_with(|| {
        log::info!("Creating new UDP session {:04x} for {}", session_id, client_addr);
        UdpSession::new(session_id, client_addr, protocol_id.clone(), &noise_config)
            .expect("Failed to create UDP session")
    });

    session.touch();

    // Process based on session state
    let response_data = if session.handshake_state.is_some() {
        // Still in handshake phase
        log::debug!("Processing handshake for session {:04x}", session_id);
        session.process_handshake(encrypted_data)?
    } else {
        // Handshake complete - decrypt and process application data
        log::debug!("Processing application data for session {:04x}", session_id);

        // Unwrap PSF (if applicable)
        let noise_encrypted = session.protocol_wrapper.unwrap(encrypted_data)
            .unwrap_or_else(|_| encrypted_data.to_vec());

        // Decrypt
        let plaintext = session.process_data(&noise_encrypted)?;

        // TODO: Process application data (SOCKS proxy logic)
        // For now, echo back for testing
        log::debug!("Decrypted {} bytes of application data", plaintext.len());

        // Encrypt response
        let encrypted_response = session.encrypt_response(&plaintext)?;

        // Wrap with PSF
        session.protocol_wrapper.wrap(&encrypted_response)
            .unwrap_or(encrypted_response)
    };

    drop(sessions_guard); // Release lock before I/O

    // Build DNS response with session ID prefix
    let mut response_payload = Vec::with_capacity(2 + response_data.len());
    response_payload.extend_from_slice(&session_id.to_be_bytes());
    response_payload.extend_from_slice(&response_data);

    let dns_response = build_dns_response(&packet, &response_payload, transaction_id);

    // Send response
    socket.send_to(&dns_response, client_addr).await?;
    log::debug!(
        "Sent UDP DNS response to {} ({} bytes)",
        client_addr,
        dns_response.len()
    );

    Ok(())
}

/// Handle TCP DNS connection
async fn handle_tcp_connection(
    mut stream: TcpStream,
    client_addr: SocketAddr,
    noise_config: NoiseConfig,
    protocol_id: ProtocolId,
) -> Result<()> {
    log::info!("TCP DNS connection from {}", client_addr);

    // Enable TCP_NODELAY for low latency
    stream.set_nodelay(true)?;

    // Create protocol wrapper
    let mut protocol_wrapper = ProtocolWrapper::new(protocol_id.clone(), WrapperRole::Server, None);

    // Perform Noise handshake
    let mut noise_transport =
        NoiseTransport::server_handshake(&mut stream, &noise_config, Some(&mut protocol_wrapper))
            .await?;

    log::info!("TCP Noise handshake complete with {}", client_addr);

    // Relay loop
    loop {
        // Read from client (Noise-encrypted, PSF-wrapped)
        let data = match noise_transport.read(&mut stream).await {
            Ok(d) if !d.is_empty() => d,
            Ok(_) => {
                log::debug!("TCP client {} closed connection", client_addr);
                break;
            }
            Err(e) => {
                log::debug!("TCP read error from {}: {}", client_addr, e);
                break;
            }
        };

        log::debug!("TCP received {} bytes from {}", data.len(), client_addr);

        // TODO: Process application data (SOCKS proxy logic)
        // For now, echo back for testing
        let response = data;

        // Write response
        if let Err(e) = noise_transport.write(&mut stream, &response).await {
            log::debug!("TCP write error to {}: {}", client_addr, e);
            break;
        }

        log::debug!("TCP sent {} bytes to {}", response.len(), client_addr);
    }

    Ok(())
}

/// Cleanup expired UDP sessions
async fn cleanup_expired_sessions(sessions: Arc<RwLock<HashMap<SessionId, UdpSession>>>) {
    loop {
        tokio::time::sleep(Duration::from_secs(30)).await;

        let mut sessions_guard = sessions.write().await;
        let before_count = sessions_guard.len();

        sessions_guard.retain(|session_id, session| {
            if session.is_expired() {
                log::info!(
                    "Removing expired UDP session {:04x} (inactive for {:?})",
                    session_id,
                    Instant::now().duration_since(session.last_activity)
                );
                false
            } else {
                true
            }
        });

        let removed = before_count - sessions_guard.len();
        if removed > 0 {
            log::debug!("Cleaned up {} expired UDP sessions", removed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_mode_parsing() {
        assert_eq!(TransportMode::from_str("tcp"), Some(TransportMode::Tcp));
        assert_eq!(TransportMode::from_str("udp"), Some(TransportMode::Udp));
        assert_eq!(TransportMode::from_str("dual"), Some(TransportMode::Dual));
        assert_eq!(TransportMode::from_str("both"), Some(TransportMode::Dual));
        assert_eq!(TransportMode::from_str("invalid"), None);
    }

    #[test]
    fn test_session_timeout() {
        let noise_config = NoiseConfig::default();
        let protocol_id = ProtocolId::from("dns");
        let mut session = UdpSession::new(
            0x1234,
            "127.0.0.1:12345".parse().unwrap(),
            protocol_id,
            &noise_config,
        )
        .unwrap();

        // Fresh session should not be expired
        assert!(!session.is_expired());

        // Manually set old timestamp
        session.last_activity = Instant::now() - Duration::from_secs(120);
        assert!(session.is_expired());
    }
}
