/// New DNS Tunnel Implementation - Proper Bidirectional Architecture
///
/// Architecture:
/// - Client sends data + periodic polls (every 50ms)
/// - Server queues responses from target in background task
/// - Each DNS query can either upload data OR download queued response
/// - KCP provides reliability over UDP DNS transport

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use log::{debug, info, error};

use crate::dns_transport::DnsTransportServer;
use crate::noise_transport::{NoiseTransport, NoiseConfig};
use crate::config::NooshdarooConfig;

/// Server-side DNS tunnel session state
pub struct DnsTunnelSession {
    /// Client address
    client_addr: SocketAddr,

    /// Noise transport for encryption
    noise: Arc<Mutex<NoiseTransport>>,

    /// KCP stream (must keep alive to process subsequent packets)
    kcp_stream: Arc<Mutex<crate::reliable_transport::ReliableTransport<crate::proxy::DnsVirtualStream>>>,

    /// Target TCP connection (write half)
    target_writer: Option<tokio::net::tcp::OwnedWriteHalf>,

    /// Response queue from background relay task
    response_queue: Arc<Mutex<Vec<Vec<u8>>>>,

    /// Background task handle
    _relay_task: Option<tokio::task::JoinHandle<()>>,

    /// Last activity timestamp
    last_seen: std::time::Instant,
}

impl DnsTunnelSession {
    /// Create new session after handshake completes
    pub fn new(
        client_addr: SocketAddr,
        noise: NoiseTransport,
        kcp_stream: crate::reliable_transport::ReliableTransport<crate::proxy::DnsVirtualStream>,
    ) -> Self {
        Self {
            client_addr,
            noise: Arc::new(Mutex::new(noise)),
            kcp_stream: Arc::new(Mutex::new(kcp_stream)),
            target_writer: None,
            response_queue: Arc::new(Mutex::new(Vec::new())),
            _relay_task: None,
            last_seen: std::time::Instant::now(),
        }
    }

    /// Handle incoming encrypted data from client
    pub async fn handle_client_data(
        &mut self,
        encrypted_data: &[u8],
        dns_server: &Arc<DnsTransportServer>,
        tx_id: u16,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.last_seen = std::time::Instant::now();

        // Decrypt the data
        let mut noise = self.noise.lock().await;
        let decrypted = noise.decrypt(encrypted_data)?;
        drop(noise);

        debug!("Decrypted {} bytes from {}", decrypted.len(), self.client_addr);

        // Check if this is target connection request
        if self.target_writer.is_none() && !decrypted.is_empty() {
            return self.handle_connect_request(&decrypted, dns_server, tx_id).await;
        }

        // Check if this is a poll request (empty payload)
        if decrypted.is_empty() {
            return self.handle_poll_request(dns_server, tx_id).await;
        }

        // Forward data to target
        if let Some(writer) = &mut self.target_writer {
            writer.write_all(&decrypted).await?;
            debug!("Forwarded {} bytes to target for {}", decrypted.len(), self.client_addr);
        }

        // Always try to send queued response
        self.send_queued_response(dns_server, tx_id).await?;

        Ok(())
    }

    /// Handle connection request to target
    async fn handle_connect_request(
        &mut self,
        target_addr_bytes: &[u8],
        dns_server: &Arc<DnsTransportServer>,
        tx_id: u16,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let target_str = String::from_utf8_lossy(target_addr_bytes);
        info!("DNS tunnel: {} connecting to {}", self.client_addr, target_str);

        // Parse and connect to target
        let target_addr = target_str.to_string();
        match TcpStream::connect(&target_addr).await {
            Ok(mut stream) => {
                stream.set_nodelay(true)?;
                info!("Connected to {} for {}", target_addr, self.client_addr);

                // Split stream
                let (reader, writer) = stream.into_split();
                self.target_writer = Some(writer);

                // Spawn background task to read from target
                let response_queue = Arc::clone(&self.response_queue);
                let client_addr = self.client_addr;

                self._relay_task = Some(tokio::spawn(async move {
                    let mut reader = reader;
                    let mut buf = vec![0u8; 8192];

                    loop {
                        match reader.read(&mut buf).await {
                            Ok(0) => {
                                info!("Target closed for {}", client_addr);
                                break;
                            }
                            Ok(n) => {
                                debug!("Read {} bytes from target for {}", n, client_addr);
                                // Queue the response
                                let mut queue = response_queue.lock().await;
                                queue.push(buf[..n].to_vec());
                                drop(queue);
                            }
                            Err(e) => {
                                error!("Target read error for {}: {}", client_addr, e);
                                break;
                            }
                        }
                    }
                }));

                // Send OK response
                let mut noise = self.noise.lock().await;
                let encrypted = noise.encrypt(b"OK")?;
                drop(noise);

                dns_server.send_response(&encrypted, self.client_addr, tx_id).await?;
                Ok(())
            }
            Err(e) => {
                error!("Failed to connect to {} for {}: {}", target_addr, self.client_addr, e);

                let error_msg = format!("CONNECT_FAILED: {}", e);
                let mut noise = self.noise.lock().await;
                let encrypted = noise.encrypt(error_msg.as_bytes())?;
                drop(noise);

                dns_server.send_response(&encrypted, self.client_addr, tx_id).await?;
                Err(e.into())
            }
        }
    }

    /// Handle poll request (empty packet to retrieve responses)
    async fn handle_poll_request(
        &mut self,
        dns_server: &Arc<DnsTransportServer>,
        tx_id: u16,
    ) -> Result<(), Box<dyn std::error::Error>> {
        debug!("Poll request from {}", self.client_addr);
        self.send_queued_response(dns_server, tx_id).await
    }

    /// Send queued response if available
    async fn send_queued_response(
        &mut self,
        dns_server: &Arc<DnsTransportServer>,
        tx_id: u16,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Check if we have queued responses
        let mut queue = self.response_queue.lock().await;

        if let Some(response_data) = queue.first() {
            // Take first response from queue
            let data = response_data.clone();
            queue.remove(0);
            drop(queue);

            debug!("Sending {} bytes queued response to {}", data.len(), self.client_addr);

            // Encrypt and send
            let mut noise = self.noise.lock().await;
            let encrypted = noise.encrypt(&data)?;
            drop(noise);

            dns_server.send_response(&encrypted, self.client_addr, tx_id).await?;
        } else {
            // No data queued - send empty response to acknowledge poll
            drop(queue);

            let mut noise = self.noise.lock().await;
            let encrypted = noise.encrypt(b"")?;
            drop(noise);

            dns_server.send_response(&encrypted, self.client_addr, tx_id).await?;
        }

        Ok(())
    }
}

/// Session manager for DNS tunnel server
pub struct DnsTunnelSessionManager {
    sessions: Arc<Mutex<HashMap<SocketAddr, DnsTunnelSession>>>,
    dns_server: Arc<DnsTransportServer>,
    noise_config: NoiseConfig,
}

impl DnsTunnelSessionManager {
    pub fn new(dns_server: Arc<DnsTransportServer>, noise_config: NoiseConfig) -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            dns_server,
            noise_config,
        }
    }

    /// Handle incoming DNS query
    pub async fn handle_query(
        &self,
        payload: Vec<u8>,
        client_addr: SocketAddr,
        tx_id: u16,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut sessions = self.sessions.lock().await;

        // Check if session exists
        if let Some(session) = sessions.get_mut(&client_addr) {
            // Existing session - handle data
            drop(sessions); // Release lock during async operations

            // Get session again with lock
            let mut sessions = self.sessions.lock().await;
            let session = sessions.get_mut(&client_addr).unwrap();

            session.handle_client_data(&payload, &self.dns_server, tx_id).await?;
        } else {
            // New session - perform handshake
            info!("New DNS tunnel session from {}", client_addr);

            // Create virtual stream for handshake
            let virtual_stream = crate::proxy::DnsVirtualStream::new(
                Arc::clone(&self.dns_server),
                client_addr,
                tx_id,
                payload.clone(),
            );

            // Wrap with KCP
            let session_id = client_addr.port() as u32;
            let mut kcp_stream = crate::reliable_transport::ReliableTransport::new(
                virtual_stream,
                session_id,
                600,
            )?;

            drop(sessions); // Release during handshake

            // Perform Noise handshake
            match NoiseTransport::server_handshake(&mut kcp_stream, &self.noise_config, None).await {
                Ok(noise) => {
                    info!("Noise handshake completed for {}", client_addr);

                    // Create session
                    let session = DnsTunnelSession::new(client_addr, noise);

                    // Store session
                    let mut sessions = self.sessions.lock().await;
                    sessions.insert(client_addr, session);
                }
                Err(e) => {
                    error!("Noise handshake failed for {}: {}", client_addr, e);
                    self.dns_server.send_response(b"HANDSHAKE_ERROR", client_addr, tx_id).await?;
                    return Err(e.into());
                }
            }
        }

        Ok(())
    }
}
