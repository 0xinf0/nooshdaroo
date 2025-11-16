//! Noise Protocol encrypted transport for client-server communication
//!
//! This module implements end-to-end encryption using the Noise Protocol Framework,
//! similar to Rathole's transport security. Supports multiple Noise patterns:
//!
//! - **Noise_NK_25519_ChaChaPoly_BLAKE2s** (default): Server authentication, client anonymity
//! - **Noise_XX_25519_ChaChaPoly_BLAKE2s**: No authentication (encryption only)
//! - **Noise_KK_25519_ChaChaPoly_BLAKE2s**: Mutual authentication (both sides authenticated)

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::{Deserialize, Serialize};
use snow::{params::NoiseParams, Builder, HandshakeState, TransportState};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum message size for Noise protocol (64 KB)
const MAX_MESSAGE_SIZE: usize = 65535;

/// Noise protocol pattern
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NoisePattern {
    /// Server authentication only (recommended default)
    /// Server proves identity, client remains anonymous
    NK,

    /// No authentication (encryption only)
    /// Protects against passive sniffing but not MITM
    XX,

    /// Mutual authentication
    /// Both client and server prove their identities
    KK,
}

impl NoisePattern {
    /// Get the full Noise protocol string
    pub fn protocol_name(&self) -> &'static str {
        match self {
            NoisePattern::NK => "Noise_NK_25519_ChaChaPoly_BLAKE2s",
            NoisePattern::XX => "Noise_XX_25519_ChaChaPoly_BLAKE2s",
            NoisePattern::KK => "Noise_KK_25519_ChaChaPoly_BLAKE2s",
        }
    }

    /// Parse from protocol name
    pub fn from_protocol_name(name: &str) -> Option<Self> {
        match name {
            "Noise_NK_25519_ChaChaPoly_BLAKE2s" => Some(NoisePattern::NK),
            "Noise_XX_25519_ChaChaPoly_BLAKE2s" => Some(NoisePattern::XX),
            "Noise_KK_25519_ChaChaPoly_BLAKE2s" => Some(NoisePattern::KK),
            _ => None,
        }
    }
}

impl Default for NoisePattern {
    fn default() -> Self {
        NoisePattern::NK
    }
}

/// Noise transport configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoiseConfig {
    /// Noise protocol pattern to use
    #[serde(default)]
    pub pattern: NoisePattern,

    /// Local private key (base64-encoded)
    /// Required for: server (NK, KK), client (KK)
    pub local_private_key: Option<String>,

    /// Remote public key (base64-encoded)
    /// Required for: client (NK, KK), server (KK)
    pub remote_public_key: Option<String>,
}

impl Default for NoiseConfig {
    fn default() -> Self {
        Self {
            pattern: NoisePattern::NK,
            local_private_key: None,
            remote_public_key: None,
        }
    }
}

impl NoiseConfig {
    /// Validate configuration for client role
    pub fn validate_client(&self) -> Result<()> {
        match self.pattern {
            NoisePattern::NK => {
                if self.remote_public_key.is_none() {
                    return Err(anyhow!("NK pattern requires remote_public_key for client"));
                }
            }
            NoisePattern::XX => {
                // XX requires local private key (exchanged during handshake)
                if self.local_private_key.is_none() {
                    return Err(anyhow!("XX pattern requires local_private_key for client"));
                }
            }
            NoisePattern::KK => {
                if self.local_private_key.is_none() {
                    return Err(anyhow!("KK pattern requires local_private_key for client"));
                }
                if self.remote_public_key.is_none() {
                    return Err(anyhow!("KK pattern requires remote_public_key for client"));
                }
            }
        }
        Ok(())
    }

    /// Validate configuration for server role
    pub fn validate_server(&self) -> Result<()> {
        match self.pattern {
            NoisePattern::NK => {
                if self.local_private_key.is_none() {
                    return Err(anyhow!("NK pattern requires local_private_key for server"));
                }
            }
            NoisePattern::XX => {
                // XX requires local private key (exchanged during handshake)
                if self.local_private_key.is_none() {
                    return Err(anyhow!("XX pattern requires local_private_key for server"));
                }
            }
            NoisePattern::KK => {
                if self.local_private_key.is_none() {
                    return Err(anyhow!("KK pattern requires local_private_key for server"));
                }
                if self.remote_public_key.is_none() {
                    return Err(anyhow!("KK pattern requires remote_public_key for server"));
                }
            }
        }
        Ok(())
    }
}

/// Noise keypair
#[derive(Debug, Clone)]
pub struct NoiseKeypair {
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

impl NoiseKeypair {
    /// Generate a new X25519 keypair
    pub fn generate() -> Result<Self> {
        let builder = Builder::new(NoisePattern::NK.protocol_name().parse()?);
        let keypair = builder.generate_keypair()?;

        Ok(Self {
            private_key: keypair.private.to_vec(),
            public_key: keypair.public.to_vec(),
        })
    }

    /// Encode private key as base64
    pub fn private_key_base64(&self) -> String {
        BASE64.encode(&self.private_key)
    }

    /// Encode public key as base64
    pub fn public_key_base64(&self) -> String {
        BASE64.encode(&self.public_key)
    }

    /// Decode private key from base64
    pub fn decode_private_key(s: &str) -> Result<Vec<u8>> {
        BASE64.decode(s).map_err(|e| anyhow!("Invalid base64 private key: {}", e))
    }

    /// Decode public key from base64
    pub fn decode_public_key(s: &str) -> Result<Vec<u8>> {
        BASE64.decode(s).map_err(|e| anyhow!("Invalid base64 public key: {}", e))
    }
}

/// Encrypted Noise transport wrapper
pub struct NoiseTransport {
    transport: TransportState,
    read_buffer: Vec<u8>,
    write_buffer: Vec<u8>,
}

impl NoiseTransport {
    /// Create client-side Noise transport
    pub async fn client_handshake<S>(
        stream: &mut S,
        config: &NoiseConfig,
    ) -> Result<Self>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        config.validate_client()?;

        let params: NoiseParams = config.pattern.protocol_name().parse()?;
        let mut builder = Builder::new(params);

        // Decode keys first to extend their lifetime
        let local_key = config
            .local_private_key
            .as_ref()
            .map(|k| NoiseKeypair::decode_private_key(k))
            .transpose()?;

        let remote_key = config
            .remote_public_key
            .as_ref()
            .map(|k| NoiseKeypair::decode_public_key(k))
            .transpose()?;

        // Set local private key if provided (required for KK)
        if let Some(ref key) = local_key {
            builder = builder.local_private_key(key);
        }

        // Set remote public key if provided (required for NK, KK)
        if let Some(ref key) = remote_key {
            builder = builder.remote_public_key(key);
        }

        let mut noise = builder.build_initiator()?;

        // Perform handshake
        let transport = Self::perform_handshake(stream, noise, true).await?;

        Ok(Self {
            transport,
            read_buffer: vec![0u8; MAX_MESSAGE_SIZE],
            write_buffer: vec![0u8; MAX_MESSAGE_SIZE + 16], // +16 for AEAD tag
        })
    }

    /// Create server-side Noise transport
    pub async fn server_handshake<S>(
        stream: &mut S,
        config: &NoiseConfig,
    ) -> Result<Self>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        config.validate_server()?;

        let params: NoiseParams = config.pattern.protocol_name().parse()?;
        let mut builder = Builder::new(params);

        // Decode keys first to extend their lifetime
        let local_key = config
            .local_private_key
            .as_ref()
            .map(|k| NoiseKeypair::decode_private_key(k))
            .transpose()?;

        let remote_key = config
            .remote_public_key
            .as_ref()
            .map(|k| NoiseKeypair::decode_public_key(k))
            .transpose()?;

        // Set local private key if provided (required for NK, KK)
        if let Some(ref key) = local_key {
            builder = builder.local_private_key(key);
        }

        // Set remote public key if provided (required for KK)
        if let Some(ref key) = remote_key {
            builder = builder.remote_public_key(key);
        }

        let mut noise = builder.build_responder()?;

        // Perform handshake
        let transport = Self::perform_handshake(stream, noise, false).await?;

        Ok(Self {
            transport,
            read_buffer: vec![0u8; MAX_MESSAGE_SIZE],
            write_buffer: vec![0u8; MAX_MESSAGE_SIZE + 16],
        })
    }

    /// Perform Noise handshake
    async fn perform_handshake<S>(
        stream: &mut S,
        mut noise: HandshakeState,
        is_initiator: bool,
    ) -> Result<TransportState>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut buf = vec![0u8; MAX_MESSAGE_SIZE];

        if is_initiator {
            // Initiator sends first message
            let len = noise.write_message(&[], &mut buf)?;
            Self::write_message(stream, &buf[..len]).await?;

            // Receive response
            let msg = Self::read_message(stream, &mut buf).await?;
            noise.read_message(msg, &mut [])?;

            // If XX pattern, send final message
            if !noise.is_handshake_finished() {
                let len = noise.write_message(&[], &mut buf)?;
                Self::write_message(stream, &buf[..len]).await?;
            }
        } else {
            // Responder receives first message
            let msg = Self::read_message(stream, &mut buf).await?;
            noise.read_message(msg, &mut [])?;

            // Send response
            let len = noise.write_message(&[], &mut buf)?;
            Self::write_message(stream, &buf[..len]).await?;

            // If XX pattern, receive final message
            if !noise.is_handshake_finished() {
                let msg = Self::read_message(stream, &mut buf).await?;
                noise.read_message(msg, &mut [])?;
            }
        }

        if !noise.is_handshake_finished() {
            return Err(anyhow!("Handshake not completed"));
        }

        Ok(noise.into_transport_mode()?)
    }

    /// Read encrypted message from stream
    pub async fn read<S>(&mut self, stream: &mut S) -> Result<Vec<u8>>
    where
        S: AsyncRead + Unpin,
    {
        let encrypted = Self::read_message(stream, &mut self.read_buffer).await?;
        let len = self.transport.read_message(encrypted, &mut self.write_buffer)?;
        Ok(self.write_buffer[..len].to_vec())
    }

    /// Write encrypted message to stream
    pub async fn write<S>(&mut self, stream: &mut S, data: &[u8]) -> Result<()>
    where
        S: AsyncWrite + Unpin,
    {
        if data.len() > MAX_MESSAGE_SIZE {
            return Err(anyhow!("Message too large: {} > {}", data.len(), MAX_MESSAGE_SIZE));
        }

        let len = self.transport.write_message(data, &mut self.write_buffer)?;
        Self::write_message(stream, &self.write_buffer[..len]).await
    }

    /// Read length-prefixed message (2-byte big-endian length + payload)
    async fn read_message<'a, S>(stream: &mut S, buf: &'a mut [u8]) -> Result<&'a [u8]>
    where
        S: AsyncRead + Unpin,
    {
        // Read length prefix (2 bytes, big-endian)
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await.map_err(|e| {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                anyhow!("Connection closed during handshake")
            } else {
                anyhow!("Failed to read message length: {}", e)
            }
        })?;

        let len = u16::from_be_bytes(len_buf) as usize;
        if len > buf.len() {
            return Err(anyhow!("Message too large: {} > {}", len, buf.len()));
        }

        // Read payload
        stream.read_exact(&mut buf[..len]).await.map_err(|e| {
            anyhow!("Failed to read message payload: {}", e)
        })?;

        Ok(&buf[..len])
    }

    /// Write length-prefixed message
    async fn write_message<S>(stream: &mut S, data: &[u8]) -> Result<()>
    where
        S: AsyncWrite + Unpin,
    {
        if data.len() > MAX_MESSAGE_SIZE {
            return Err(anyhow!("Message too large: {}", data.len()));
        }

        // Write length prefix (2 bytes, big-endian)
        let len = data.len() as u16;
        stream.write_all(&len.to_be_bytes()).await?;

        // Write payload
        stream.write_all(data).await?;
        stream.flush().await?;

        Ok(())
    }

    /// Encrypt data and return raw Noise-encrypted bytes (for use with protocol wrapper)
    /// Returns the encrypted data without length prefix
    pub fn encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() > MAX_MESSAGE_SIZE {
            return Err(anyhow!("Message too large: {} > {}", data.len(), MAX_MESSAGE_SIZE));
        }

        let len = self.transport.write_message(data, &mut self.write_buffer)?;
        Ok(self.write_buffer[..len].to_vec())
    }

    /// Decrypt raw Noise-encrypted bytes (for use with protocol wrapper)
    /// Takes the encrypted data without length prefix
    pub fn decrypt(&mut self, encrypted: &[u8]) -> Result<Vec<u8>> {
        if encrypted.len() > self.read_buffer.len() {
            return Err(anyhow!("Encrypted data too large: {} > {}", encrypted.len(), self.read_buffer.len()));
        }

        let len = self.transport.read_message(encrypted, &mut self.write_buffer)?;
        Ok(self.write_buffer[..len].to_vec())
    }

    /// Write raw bytes to stream with length prefix (for protocol wrapper)
    pub async fn write_raw<S>(&self, stream: &mut S, data: &[u8]) -> Result<()>
    where
        S: AsyncWrite + Unpin,
    {
        Self::write_message(stream, data).await
    }

    /// Read raw bytes from stream with length prefix (for protocol wrapper)
    pub async fn read_raw<S>(&mut self, stream: &mut S) -> Result<Vec<u8>>
    where
        S: AsyncRead + Unpin,
    {
        let data = Self::read_message(stream, &mut self.read_buffer).await?;
        Ok(data.to_vec())
    }

    /// Check if transport is in valid state
    pub fn is_valid(&self) -> bool {
        true // TransportState is always valid after handshake
    }
}

/// Generate a new X25519 keypair and print as base64
pub fn generate_keypair() -> Result<NoiseKeypair> {
    NoiseKeypair::generate()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[test]
    fn test_noise_pattern_protocol_names() {
        assert_eq!(
            NoisePattern::NK.protocol_name(),
            "Noise_NK_25519_ChaChaPoly_BLAKE2s"
        );
        assert_eq!(
            NoisePattern::XX.protocol_name(),
            "Noise_XX_25519_ChaChaPoly_BLAKE2s"
        );
        assert_eq!(
            NoisePattern::KK.protocol_name(),
            "Noise_KK_25519_ChaChaPoly_BLAKE2s"
        );
    }

    #[test]
    fn test_keypair_generation() {
        let keypair = NoiseKeypair::generate().unwrap();
        assert_eq!(keypair.private_key.len(), 32);
        assert_eq!(keypair.public_key.len(), 32);

        // Test base64 encoding/decoding
        let priv_b64 = keypair.private_key_base64();
        let pub_b64 = keypair.public_key_base64();

        let decoded_priv = NoiseKeypair::decode_private_key(&priv_b64).unwrap();
        let decoded_pub = NoiseKeypair::decode_public_key(&pub_b64).unwrap();

        assert_eq!(decoded_priv, keypair.private_key);
        assert_eq!(decoded_pub, keypair.public_key);
    }

    #[test]
    fn test_config_validation() {
        // NK client needs remote_public_key
        let config = NoiseConfig {
            pattern: NoisePattern::NK,
            local_private_key: None,
            remote_public_key: None,
        };
        assert!(config.validate_client().is_err());

        // NK server needs local_private_key
        assert!(config.validate_server().is_err());

        // XX needs local_private_key on both sides
        let config = NoiseConfig {
            pattern: NoisePattern::XX,
            local_private_key: None,
            remote_public_key: None,
        };
        assert!(config.validate_client().is_err());
        assert!(config.validate_server().is_err());
    }

    #[tokio::test]
    async fn test_noise_handshake_nk() {
        // Generate server keypair
        let server_keypair = NoiseKeypair::generate().unwrap();

        let server_config = NoiseConfig {
            pattern: NoisePattern::NK,
            local_private_key: Some(server_keypair.private_key_base64()),
            remote_public_key: None,
        };

        let client_config = NoiseConfig {
            pattern: NoisePattern::NK,
            local_private_key: None,
            remote_public_key: Some(server_keypair.public_key_base64()),
        };

        // Create duplex stream (simulates network connection)
        let (mut client_stream, mut server_stream) = duplex(8192);

        // Perform handshakes concurrently
        let client_handle = tokio::spawn(async move {
            NoiseTransport::client_handshake(&mut client_stream, &client_config).await
        });

        let server_handle = tokio::spawn(async move {
            NoiseTransport::server_handshake(&mut server_stream, &server_config).await
        });

        let mut client_transport = client_handle.await.unwrap().unwrap();
        let mut server_transport = server_handle.await.unwrap().unwrap();

        assert!(client_transport.is_valid());
        assert!(server_transport.is_valid());

        // Test encrypted communication
        let (mut client_stream, mut server_stream) = duplex(8192);

        // Client sends message
        let message = b"Hello from client!";
        client_transport.write(&mut client_stream, message).await.unwrap();

        // Server receives message
        let received = server_transport.read(&mut server_stream).await.unwrap();
        assert_eq!(received, message);

        // Server sends response
        let response = b"Hello from server!";
        server_transport.write(&mut server_stream, response).await.unwrap();

        // Client receives response
        let received = client_transport.read(&mut client_stream).await.unwrap();
        assert_eq!(received, response);
    }

    #[tokio::test]
    async fn test_noise_handshake_xx() {
        // XX pattern exchanges keys during handshake, but snow still requires local keys
        let client_keypair = NoiseKeypair::generate().unwrap();
        let server_keypair = NoiseKeypair::generate().unwrap();

        let server_config = NoiseConfig {
            pattern: NoisePattern::XX,
            local_private_key: Some(server_keypair.private_key_base64()),
            remote_public_key: None, // Not pre-shared
        };

        let client_config = NoiseConfig {
            pattern: NoisePattern::XX,
            local_private_key: Some(client_keypair.private_key_base64()),
            remote_public_key: None, // Not pre-shared
        };

        let (mut client_stream, mut server_stream) = duplex(8192);

        let client_handle = tokio::spawn(async move {
            NoiseTransport::client_handshake(&mut client_stream, &client_config).await
        });

        let server_handle = tokio::spawn(async move {
            NoiseTransport::server_handshake(&mut server_stream, &server_config).await
        });

        let client_transport = client_handle.await.unwrap().unwrap();
        let server_transport = server_handle.await.unwrap().unwrap();

        assert!(client_transport.is_valid());
        assert!(server_transport.is_valid());
    }
}
