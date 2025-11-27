// nQUIC endpoint
//
// High-level API for nQUIC connections
// Combines NoiseSession + DnsTransport + Quinn QUIC

use super::crypto::{NoiseSession, NoiseConfig};
use super::dns::{DnsTransport, DnsCodec};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

/// nQUIC endpoint error
#[derive(Debug, thiserror::Error)]
pub enum EndpointError {
    #[error("Crypto error: {0}")]
    CryptoError(#[from] super::crypto::NoiseCryptoError),

    #[error("DNS error: {0}")]
    DnsError(#[from] super::dns::DnsError),

    #[error("Connection error: {0}")]
    ConnectionError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, EndpointError>;

/// nQUIC endpoint
pub struct NquicEndpoint {
    /// Noise crypto configuration
    noise_config: NoiseConfig,

    /// DNS transport
    dns_transport: Arc<Mutex<DnsTransport>>,

    /// Role: true for server, false for client
    is_server: bool,
}

impl NquicEndpoint {
    /// Create a new nQUIC endpoint
    pub fn new(
        noise_config: NoiseConfig,
        base_domain: String,
        is_server: bool,
    ) -> Self {
        let codec = DnsCodec::new(base_domain);
        let dns_transport = DnsTransport::new(codec, is_server);

        Self {
            noise_config,
            dns_transport: Arc::new(Mutex::new(dns_transport)),
            is_server,
        }
    }

    /// Bind to a local address
    pub async fn bind(&self, addr: SocketAddr) -> Result<()> {
        let mut transport = self.dns_transport.lock().await;
        transport.bind_udp(addr).await?;
        Ok(())
    }

    /// Set DNS server (for client)
    pub async fn set_dns_server(&self, addr: SocketAddr) {
        let mut transport = self.dns_transport.lock().await;
        transport.set_dns_server(addr);
    }

    /// Create a new connection (client-side)
    pub async fn connect(&self) -> Result<NquicConnection> {
        if self.is_server {
            return Err(EndpointError::ConnectionError(
                "Server cannot initiate connections".into(),
            ));
        }

        // Create Noise session for this connection
        let mut session = NoiseSession::new(self.noise_config.clone())?;

        // Initialize handshake
        let conn_id = b"nquic_connection"; // TODO: Generate unique connection ID
        session.start_handshake(conn_id)?;

        let mut conn = NquicConnection {
            session: Arc::new(Mutex::new(session)),
            dns_transport: Arc::clone(&self.dns_transport),
            remote_addr: None, // Client doesn't have remote_addr
            tx_id: None,
        };

        // Perform handshake
        conn.handshake().await?;

        Ok(conn)
    }

    /// Accept incoming connection (server-side)
    pub async fn accept(&self) -> Result<NquicConnection> {
        if !self.is_server {
            return Err(EndpointError::ConnectionError(
                "Client cannot accept connections".into(),
            ));
        }

        // Create Noise session for this connection
        let mut session = NoiseSession::new(self.noise_config.clone())?;

        // Initialize handshake
        let conn_id = b"nquic_connection"; // TODO: Extract from packet or generate
        session.start_handshake(conn_id)?;

        let mut conn = NquicConnection {
            session: Arc::new(Mutex::new(session)),
            dns_transport: Arc::clone(&self.dns_transport),
            remote_addr: None, // Will be set during handshake
            tx_id: None,      // Will be set during handshake
        };

        // Perform handshake (will receive client's initial message)
        conn.handshake().await?;

        Ok(conn)
    }
}

/// nQUIC connection
pub struct NquicConnection {
    /// Noise session
    session: Arc<Mutex<NoiseSession>>,

    /// DNS transport
    dns_transport: Arc<Mutex<DnsTransport>>,

    /// Remote address (for server-side connections)
    remote_addr: Option<SocketAddr>,

    /// Transaction ID tracker (for correlating requests/responses)
    tx_id: Option<u16>,
}

impl NquicConnection {
    /// Perform Noise handshake over DNS transport
    pub async fn handshake(&mut self) -> Result<()> {
        let mut session = self.session.lock().await;

        if session.is_server {
            // Server handshake flow
            // 1. Receive client's initial handshake message
            let transport = self.dns_transport.lock().await;
            let (handshake_msg, src, tx_id) = transport.recv_query().await?;
            drop(transport);

            // Store client address and transaction ID for response
            self.remote_addr = Some(src);
            self.tx_id = Some(tx_id);

            // 2. Read client's handshake message
            session.read_handshake(&handshake_msg)?;

            // 3. Write server's response handshake message
            let mut response_msg = Vec::new();
            let complete = session.write_handshake(&mut response_msg)?;

            // 4. Send handshake response to client
            let mut transport = self.dns_transport.lock().await;
            transport.send_response(&response_msg, src, tx_id).await?;

            if !complete {
                return Err(EndpointError::ConnectionError(
                    "Server handshake incomplete after exchange".into(),
                ));
            }
        } else {
            // Client handshake flow
            // 1. Write initial handshake message
            let mut initial_msg = Vec::new();
            session.write_handshake(&mut initial_msg)?;

            // 2. Send to server via DNS
            let mut transport = self.dns_transport.lock().await;
            transport.send_query(&initial_msg).await?;
            drop(transport);

            // 3. Receive server's response
            let transport = self.dns_transport.lock().await;
            let server_msg = transport.recv_response().await?;
            drop(transport);

            // 4. Read server's handshake message
            let complete = session.read_handshake(&server_msg)?;

            if !complete {
                return Err(EndpointError::ConnectionError(
                    "Client handshake incomplete after exchange".into(),
                ));
            }
        }

        Ok(())
    }

    /// Send data over the connection
    pub async fn send(&self, data: &[u8]) -> Result<()> {
        let mut session = self.session.lock().await;

        // Check handshake is complete
        if !session.is_handshake_complete() {
            return Err(EndpointError::ConnectionError(
                "Cannot send data before handshake complete".into(),
            ));
        }

        // Encrypt data with Noise
        let encrypted = session.encrypt_packet(data)?;
        drop(session);

        // Send via DNS
        if let Some(remote) = self.remote_addr {
            // Server-side: send response to specific client
            let mut transport = self.dns_transport.lock().await;
            let tx_id = self.tx_id.unwrap_or(0);
            transport.send_response(&encrypted, remote, tx_id).await?;
        } else {
            // Client-side: send query to server
            let mut transport = self.dns_transport.lock().await;
            transport.send_query(&encrypted).await?;
        }

        Ok(())
    }

    /// Receive data from the connection
    pub async fn recv(&self) -> Result<Vec<u8>> {
        let session = self.session.lock().await;

        // Check handshake is complete
        if !session.is_handshake_complete() {
            return Err(EndpointError::ConnectionError(
                "Cannot receive data before handshake complete".into(),
            ));
        }

        let is_server = session.is_server;
        drop(session);

        // Receive via DNS
        let encrypted = if is_server {
            // Server-side: receive query from client
            let transport = self.dns_transport.lock().await;
            let (packet, _src, _tx_id) = transport.recv_query().await?;
            packet
        } else {
            // Client-side: receive response from server
            let transport = self.dns_transport.lock().await;
            transport.recv_response().await?
        };

        // Decrypt with Noise
        let mut session = self.session.lock().await;
        let data = session.decrypt_packet(&encrypted)?;

        Ok(data)
    }

    /// Check if handshake is complete
    pub async fn is_handshake_complete(&self) -> bool {
        let session = self.session.lock().await;
        session.is_handshake_complete()
    }

    /// Get remote static public key
    pub async fn remote_static_key(&self) -> Option<Vec<u8>> {
        let session = self.session.lock().await;
        session.get_remote_static_key().map(|k| k.to_vec())
    }

    /// Get remote address (server-side only)
    pub fn remote_addr(&self) -> Option<SocketAddr> {
        self.remote_addr
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise_transport::{NoiseKeypair, NoisePattern};
    use std::sync::Arc;
    use snow::Builder;

    #[tokio::test]
    async fn test_endpoint_creation() {
        // Generate keypair using Snow Builder
        let builder = Builder::new(NoisePattern::IK.protocol_name().parse().unwrap());
        let keypair = builder.generate_keypair().unwrap();
        let keys = Arc::new(NoiseKeypair {
            private_key: keypair.private.to_vec(),
            public_key: keypair.public.to_vec(),
        });
        let config = NoiseConfig::server(keys);

        let endpoint = NquicEndpoint::new(
            config,
            "tunnel.example.com".to_string(),
            true,
        );

        assert!(endpoint.is_server);
    }
}
