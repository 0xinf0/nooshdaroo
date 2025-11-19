//! QUIC Transport Implementation
//!
//! Provides QUIC-based datagram transport for low-latency, multiplexed connections.
//! QUIC combines the best of TCP (reliability, congestion control) with UDP (low latency).

use crate::transport::{DatagramTransport, TransportConfig};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

/// QUIC transport client
pub struct QuicTransport {
    /// QUIC connection
    connection: Arc<quinn::Connection>,
    /// Datagram send/recv
    endpoint: Arc<quinn::Endpoint>,
    /// Remote address
    remote_addr: SocketAddr,
    /// Receive buffer
    recv_buf: Arc<Mutex<Option<Vec<u8>>>>,
}

impl QuicTransport {
    /// Create new QUIC transport
    pub async fn connect(config: TransportConfig) -> Result<Self> {
        // Create rustls config with native roots
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_native_certs::load_native_certs().certs {
            roots.add(cert).ok();
        }

        let mut client_crypto = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();

        // Use ALPN to blend in with HTTP/3 for DPI evasion
        client_crypto.alpn_protocols = vec![b"h3".to_vec()];

        // Create quinn client config
        let mut client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)?
        ));

        // Bind to local address
        let endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;

        // Connect to server
        let connection = endpoint
            .connect_with(client_config, config.server_addr, "nooshdaroo")?
            .await?;

        log::info!("QUIC connection established to {}", config.server_addr);

        Ok(Self {
            connection: Arc::new(connection),
            endpoint: Arc::new(endpoint),
            remote_addr: config.server_addr,
            recv_buf: Arc::new(Mutex::new(None)),
        })
    }
}

#[async_trait]
impl DatagramTransport for QuicTransport {
    async fn send(&self, data: &[u8]) -> Result<()> {
        // QUIC datagrams are unreliable, unordered
        // Clone data to satisfy 'static lifetime requirement
        self.connection
            .send_datagram(bytes::Bytes::copy_from_slice(data))?;

        log::debug!("QUIC: Sent {} bytes datagram", data.len());
        Ok(())
    }

    async fn recv(&self) -> Result<Vec<u8>> {
        // Receive QUIC datagram
        let datagram = self.connection
            .read_datagram()
            .await
            .map_err(|e| anyhow!("QUIC recv error: {}", e))?;

        log::debug!("QUIC: Received {} bytes datagram", datagram.len());
        Ok(datagram.to_vec())
    }

    fn max_message_size(&self) -> usize {
        // QUIC can handle larger datagrams than UDP
        // Path MTU minus overhead
        1200
    }

    fn peer_addr(&self) -> Result<SocketAddr> {
        Ok(self.remote_addr)
    }

    async fn close(&mut self) -> Result<()> {
        self.connection.close(0u32.into(), b"goodbye");
        log::info!("QUIC connection closed");
        Ok(())
    }
}

/// QUIC transport server
pub struct QuicTransportServer {
    /// QUIC endpoint (server)
    endpoint: quinn::Endpoint,
}

impl QuicTransportServer {
    /// Create new QUIC server
    pub async fn bind(listen_addr: SocketAddr) -> Result<Self> {
        // Generate self-signed certificate for testing
        // In production, use proper certificates
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
        let cert_der = cert.cert.der().to_vec();
        let priv_key_der = cert.key_pair.serialize_der();

        let cert_chain = vec![rustls::pki_types::CertificateDer::from(cert_der)];
        let priv_key = rustls::pki_types::PrivateKeyDer::try_from(priv_key_der)
            .map_err(|e| anyhow!("Failed to parse private key: {}", e))?;

        let mut server_crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, priv_key)?;

        server_crypto.alpn_protocols = vec![b"h3".to_vec()];

        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?
        ));

        // Configure transport for DPI evasion
        server_config.transport = Arc::new(quinn::TransportConfig::default());

        // Bind QUIC server
        let endpoint = quinn::Endpoint::server(server_config, listen_addr)?;

        log::info!("QUIC server listening on {}", listen_addr);

        Ok(Self { endpoint })
    }

    /// Accept incoming QUIC connection
    pub async fn accept(&mut self) -> Result<quinn::Connection> {
        let connecting = self.endpoint
            .accept()
            .await
            .ok_or_else(|| anyhow!("No incoming connection"))?;

        let connection = connecting.await?;
        log::info!("QUIC: Accepted connection from {}", connection.remote_address());

        Ok(connection)
    }
}
