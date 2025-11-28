// Quinn crypto integration for NoiseSession
//
// Implements quinn_proto::crypto traits to integrate Noise Protocol
// with Quinn QUIC implementation.

use super::{NoiseSession, NoiseConfig, Result};
use super::keys::QuicKeys;
use quinn_proto::crypto::{
    self, CryptoError, HeaderKey, PacketKey, Keys, KeyPair as QuinnKeyPair,
    ExportKeyingMaterialError,
};
use quinn_proto::{Side, TransportError, TransportErrorCode, ConnectionId};
use quinn_proto::transport_parameters::TransportParameters;
use std::any::Any;
use ring::aead::{self, LessSafeKey, Nonce, UnboundKey, Aad, CHACHA20_POLY1305, quic};
use std::sync::Arc;

/// NoisePacketKey: Wrapper for QUIC packet encryption using Noise
struct NoisePacketKey {
    key: Arc<LessSafeKey>,
    iv: [u8; 12],
}

impl PacketKey for NoisePacketKey {
    fn encrypt(&self, packet_number: u64, buf: &mut [u8], header_len: usize) {
        // ChaCha20-Poly1305 AEAD encryption
        // QUIC packet structure: [header][payload][tag]
        // We encrypt payload in-place and append the 16-byte tag

        let nonce_bytes = self.make_nonce(packet_number);
        let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
            .expect("Nonce construction failed");

        // Split buffer to avoid overlapping borrows
        let (header, payload) = buf.split_at_mut(header_len);

        // AAD is the packet header (unencrypted)
        let aad = Aad::from(&*header);

        // Encrypt in-place: payload becomes ciphertext + tag
        let payload_len = payload.len();
        self.key.seal_in_place_separate_tag(nonce, aad, payload)
            .map(|tag| {
                // Append tag to the end
                payload[payload_len - tag.as_ref().len()..].copy_from_slice(tag.as_ref());
            })
            .expect("Encryption failed");
    }

    fn decrypt(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &mut bytes::BytesMut,
    ) -> std::result::Result<(), CryptoError> {
        // ChaCha20-Poly1305 AEAD decryption
        let nonce_bytes = self.make_nonce(packet_number);
        let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
            .map_err(|_| CryptoError)?;

        // AAD is the packet header
        let aad = Aad::from(header);

        // Decrypt in-place: ciphertext + tag becomes plaintext
        let plaintext_len = {
            let plaintext = self.key.open_in_place(nonce, aad, payload.as_mut())
                .map_err(|_| CryptoError)?;
            plaintext.len()
        };

        // Truncate to plaintext length (removes tag)
        payload.truncate(plaintext_len);
        Ok(())
    }

    fn tag_len(&self) -> usize {
        16 // Poly1305 tag length
    }

    fn confidentiality_limit(&self) -> u64 {
        // ChaCha20-Poly1305 confidentiality limit
        // RFC 9001 recommends 2^23 packets for ChaCha20-Poly1305
        1 << 23
    }

    fn integrity_limit(&self) -> u64 {
        // Poly1305 integrity limit
        // RFC 9001: 2^52 forged packets
        1u64 << 52
    }
}

impl NoisePacketKey {
    fn make_nonce(&self, packet_number: u64) -> [u8; 12] {
        // XOR packet number with IV to create nonce (QUIC RFC 9001)
        let mut nonce = self.iv;
        let pn_bytes = packet_number.to_be_bytes();
        let offset = nonce.len() - pn_bytes.len();
        for (i, &byte) in pn_bytes.iter().enumerate() {
            nonce[offset + i] ^= byte;
        }
        nonce
    }

    fn new(key: &[u8], iv: &[u8]) -> std::result::Result<Self, String> {
        if key.len() != 32 {
            return Err(format!("Invalid key length: {} (expected 32)", key.len()));
        }
        if iv.len() != 12 {
            return Err(format!("Invalid IV length: {} (expected 12)", iv.len()));
        }

        let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, key)
            .map_err(|_| "Failed to create unbound key")?;
        let less_safe_key = LessSafeKey::new(unbound_key);

        let mut iv_array = [0u8; 12];
        iv_array.copy_from_slice(iv);

        Ok(Self {
            key: Arc::new(less_safe_key),
            iv: iv_array,
        })
    }
}

/// NoiseHeaderKey: Header protection using ChaCha20
struct NoiseHeaderKey {
    key: quic::HeaderProtectionKey,
}

impl HeaderKey for NoiseHeaderKey {
    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        // Extract sample from packet payload (16 bytes starting 4 bytes after pn_offset)
        let sample_offset = pn_offset + 4;
        if packet.len() < sample_offset + self.sample_size() {
            // Not enough data for header protection
            return;
        }

        let (header, sample_and_payload) = packet.split_at_mut(pn_offset);
        let sample = &sample_and_payload[4..4 + self.sample_size()];

        // Generate mask from sample
        let mask = self.key.new_mask(sample)
            .expect("Failed to generate header protection mask");

        // XOR the first byte (packet type + flags) with mask[0]
        // Only the lower 5 bits for long headers, lower 5 bits for short headers
        if header.is_empty() {
            return;
        }
        let mask_bytes = mask.as_ref();

        // Decrypt first byte (protected packet type/flags)
        header[header.len() - 1] ^= mask_bytes[0] & 0x1f;

        // Decrypt packet number bytes (up to 4 bytes)
        let pn_len = 4.min(sample_and_payload.len());
        for (i, byte) in sample_and_payload[..pn_len].iter_mut().enumerate() {
            if i + 1 < mask_bytes.len() {
                *byte ^= mask_bytes[i + 1];
            }
        }
    }

    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        // Extract sample from packet payload (16 bytes starting 4 bytes after pn_offset)
        let sample_offset = pn_offset + 4;
        if packet.len() < sample_offset + self.sample_size() {
            // Not enough data for header protection
            return;
        }

        let (header, sample_and_payload) = packet.split_at_mut(pn_offset);
        let sample = &sample_and_payload[4..4 + self.sample_size()];

        // Generate mask from sample
        let mask = self.key.new_mask(sample)
            .expect("Failed to generate header protection mask");

        // XOR the first byte (packet type + flags) with mask[0]
        if header.is_empty() {
            return;
        }
        let mask_bytes = mask.as_ref();

        // Encrypt first byte (packet type/flags)
        header[header.len() - 1] ^= mask_bytes[0] & 0x1f;

        // Encrypt packet number bytes (up to 4 bytes)
        let pn_len = 4.min(sample_and_payload.len());
        for (i, byte) in sample_and_payload[..pn_len].iter_mut().enumerate() {
            if i + 1 < mask_bytes.len() {
                *byte ^= mask_bytes[i + 1];
            }
        }
    }

    fn sample_size(&self) -> usize {
        // ChaCha20 always uses 16-byte samples for header protection
        16
    }
}

impl NoiseHeaderKey {
    /// Create a new header protection key from the header key material
    fn new(key: &[u8]) -> std::result::Result<Self, String> {
        if key.len() != 32 {
            return Err(format!("Invalid header key length: {} (expected 32)", key.len()));
        }

        // Create ChaCha20 header protection key
        let header_key = quic::HeaderProtectionKey::new(&quic::CHACHA20, key)
            .map_err(|_| "Failed to create header protection key")?;

        Ok(Self { key: header_key })
    }
}

// NOTE: The following trait implementations are commented out until we properly integrate
// with the Quinn 0.11.x API. The crypto::Suite, KeyPair, and Keys traits have changed
// significantly in Quinn 0.11.x. We need to implement quinn_proto::crypto::Session instead.
//
// /// NoiseCryptoSuite: Crypto suite implementation for Quinn
// pub struct NoiseCryptoSuite;
//
// /// NoiseKeyPair: Client/Server key pair for a QUIC encryption level
// struct NoiseKeyPair {
//     local: Arc<NoisePacketKey>,
//     remote: Arc<NoisePacketKey>,
//     local_header: Arc<NoiseHeaderKey>,
//     remote_header: Arc<NoiseHeaderKey>,
// }

/// NoiseKeyPair: Simple wrapper for managing packet and header keys
pub struct NoiseKeyPair {
    pub local: NoisePacketKey,
    pub remote: NoisePacketKey,
    pub local_header: NoiseHeaderKey,
    pub remote_header: NoiseHeaderKey,
}

impl NoiseKeyPair {
    fn from_quic_keys(client: &QuicKeys, server: &QuicKeys, is_server: bool) -> Self {
        let (local_keys, remote_keys) = if is_server {
            (server, client)
        } else {
            (client, server)
        };

        Self {
            local: NoisePacketKey::new(&local_keys.key, &local_keys.iv)
                .expect("Failed to create local packet key"),
            remote: NoisePacketKey::new(&remote_keys.key, &remote_keys.iv)
                .expect("Failed to create remote packet key"),
            local_header: NoiseHeaderKey::new(&local_keys.header_key)
                .expect("Failed to create local header key"),
            remote_header: NoiseHeaderKey::new(&remote_keys.header_key)
                .expect("Failed to create remote header key"),
        }
    }
}

/// NoiseClientConfig: Client crypto configuration for Quinn
pub struct NoiseClientConfig {
    config: NoiseConfig,
}

impl NoiseClientConfig {
    pub fn new(config: NoiseConfig) -> Self {
        Self { config }
    }

    pub fn start_session(&self, server_name: &str) -> Result<NoiseQuinnSession> {
        NoiseQuinnSession::new_client(self.config.clone(), server_name)
    }
}

/// NoiseServerConfig: Server crypto configuration for Quinn
pub struct NoiseServerConfig {
    config: NoiseConfig,
}

impl NoiseServerConfig {
    pub fn new(config: NoiseConfig) -> Self {
        Self { config }
    }

    pub fn start_session(&self) -> Result<NoiseQuinnSession> {
        NoiseQuinnSession::new_server(self.config.clone())
    }
}

/// NoiseQuinnSession: Quinn crypto::Session implementation using NoiseSession
pub struct NoiseQuinnSession {
    /// Underlying Noise session
    session: NoiseSession,

    /// Server name (for client side)
    server_name: Option<String>,
}

impl NoiseQuinnSession {
    pub fn new_client(config: NoiseConfig, server_name: &str) -> Result<Self> {
        let session = NoiseSession::new(config)?;
        Ok(Self {
            session,
            server_name: Some(server_name.to_string()),
        })
    }

    pub fn new_server(config: NoiseConfig) -> Result<Self> {
        let session = NoiseSession::new(config)?;
        Ok(Self {
            session,
            server_name: None,
        })
    }

    /// Get initial keys for QUIC Initial packet encryption
    pub fn initial_keys(&self) -> Option<NoiseKeyPair> {
        self.session.get_initial_keys().map(|(client, server)| {
            NoiseKeyPair::from_quic_keys(client, server, self.session.is_server)
        })
    }

    /// Get handshake keys for QUIC Handshake packet encryption
    pub fn handshake_keys(&self) -> Option<NoiseKeyPair> {
        self.session.get_handshake_keys().map(|(client, server)| {
            NoiseKeyPair::from_quic_keys(client, server, self.session.is_server)
        })
    }

    /// Get application (1-RTT) keys for QUIC Data packet encryption
    pub fn application_keys(&self) -> Option<NoiseKeyPair> {
        self.session.get_application_keys().map(|(client, server)| {
            NoiseKeyPair::from_quic_keys(client, server, self.session.is_server)
        })
    }

    /// Process handshake data from peer
    pub fn read_handshake(&mut self, data: &[u8]) -> Result<bool> {
        self.session.read_handshake(data)
    }

    /// Generate handshake data to send to peer
    pub fn write_handshake(&mut self) -> Result<(Vec<u8>, bool)> {
        let mut buf = Vec::new();
        let done = self.session.write_handshake(&mut buf)?;
        Ok((buf, done))
    }

    /// Check if handshake is complete
    pub fn is_handshake_complete(&self) -> bool {
        self.session.is_handshake_complete()
    }

    /// Export keying material (for QUIC-specific use)
    pub fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<()> {
        // TODO: Implement keying material export using Noise protocol
        // For now, fill with zeros as placeholder
        output.fill(0);
        Ok(())
    }
}

// Quinn Session trait implementation for Noise Protocol
impl crypto::Session for NoiseQuinnSession {
    fn initial_keys(&self, dst_cid: &ConnectionId, _side: Side) -> Keys {
        // Derive initial keys from connection ID
        // Initialize handshake first
        let conn_id_bytes: &[u8] = &*dst_cid;

        // For now, use placeholder derivation - proper implementation will come later
        let (client, server) = super::keys::NoiseKeyDerivation::derive_initial_secrets(conn_id_bytes)
            .expect("Failed to derive initial keys");

        let is_server = self.session.is_server;

        // Convert to Quinn Keys format
        self.make_keys(&client, &server, is_server)
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        // Return handshake completion status once available
        if self.session.is_handshake_complete() {
            Some(Box::new(true))
        } else {
            None
        }
    }

    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        // Return peer's static public key if available
        self.session.get_remote_static_key()
            .map(|key| Box::new(key.to_vec()) as Box<dyn Any>)
    }

    fn early_crypto(&self) -> Option<(Box<dyn HeaderKey>, Box<dyn PacketKey>)> {
        // nQUIC doesn't support 0-RTT for now (could be added later)
        None
    }

    fn early_data_accepted(&self) -> Option<bool> {
        // No 0-RTT support yet
        Some(false)
    }

    fn is_handshaking(&self) -> bool {
        !self.session.is_handshake_complete()
    }

    fn read_handshake(&mut self, buf: &[u8]) -> std::result::Result<bool, TransportError> {
        self.session.read_handshake(buf)
            .map_err(|_| TransportError::from(TransportErrorCode::PROTOCOL_VIOLATION))
    }

    fn transport_parameters(&self) -> std::result::Result<Option<TransportParameters>, TransportError> {
        // Return None since we don't construct TransportParameters manually
        // Quinn doesn't expose TransportParameters::default() because downstream crates
        // should only work with parameters decoded from the peer
        // In a full implementation, we would negotiate these during handshake
        Ok(None)
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys> {
        match self.session.write_handshake(buf) {
            Ok(done) => {
                if done {
                    // Handshake complete - return 1-RTT keys
                    self.session.get_application_keys().map(|(client, server)| {
                        self.make_keys(client, server, self.session.is_server)
                    })
                } else {
                    // Still handshaking - return handshake keys
                    self.session.get_handshake_keys().map(|(client, server)| {
                        self.make_keys(client, server, self.session.is_server)
                    })
                }
            }
            Err(_) => None,
        }
    }

    fn next_1rtt_keys(&mut self) -> Option<QuinnKeyPair<Box<dyn PacketKey>>> {
        // Perform key update for PFS
        if self.session.update_keys().is_ok() {
            self.session.get_application_keys().map(|(client, server)| {
                let is_server = self.session.is_server;
                let (local_keys, remote_keys) = if is_server {
                    (server, client)
                } else {
                    (client, server)
                };

                QuinnKeyPair {
                    local: Box::new(NoisePacketKey::new(&local_keys.key, &local_keys.iv)
                        .expect("Failed to create local packet key")) as Box<dyn PacketKey>,
                    remote: Box::new(NoisePacketKey::new(&remote_keys.key, &remote_keys.iv)
                        .expect("Failed to create remote packet key")) as Box<dyn PacketKey>,
                }
            })
        } else {
            None
        }
    }

    fn is_valid_retry(&self, _orig_dst_cid: &ConnectionId, _header: &[u8], _payload: &[u8]) -> bool {
        // Retry packets not supported in nQUIC (yet)
        false
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> std::result::Result<(), ExportKeyingMaterialError> {
        // For now, use a simple placeholder - proper implementation would derive from Noise session
        // In a full implementation, we would use HKDF with the Noise handshake hash
        let _ = (label, context);
        output.fill(0);
        Ok(())
    }
}

impl NoiseQuinnSession {
    /// Helper to convert QuicKeys to Quinn Keys format
    fn make_keys(&self, client: &QuicKeys, server: &QuicKeys, is_server: bool) -> Keys {
        let (local_keys, remote_keys) = if is_server {
            (server, client)
        } else {
            (client, server)
        };

        Keys {
            header: QuinnKeyPair {
                local: Box::new(NoiseHeaderKey::new(&local_keys.header_key)
                    .expect("Failed to create local header key")) as Box<dyn HeaderKey>,
                remote: Box::new(NoiseHeaderKey::new(&remote_keys.header_key)
                    .expect("Failed to create remote header key")) as Box<dyn HeaderKey>,
            },
            packet: QuinnKeyPair {
                local: Box::new(NoisePacketKey::new(&local_keys.key, &local_keys.iv)
                    .expect("Failed to create local packet key")) as Box<dyn PacketKey>,
                remote: Box::new(NoisePacketKey::new(&remote_keys.key, &remote_keys.iv)
                    .expect("Failed to create remote packet key")) as Box<dyn PacketKey>,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise_transport::{NoiseKeypair, NoisePattern};
    use std::sync::Arc;
    use snow::Builder;

    fn create_test_config() -> (NoiseConfig, NoiseConfig) {
        // Generate server keypair
        let builder = Builder::new(NoisePattern::IK.protocol_name().parse().unwrap());
        let keypair = builder.generate_keypair().unwrap();
        let server_keys = Arc::new(NoiseKeypair {
            private_key: keypair.private.to_vec(),
            public_key: keypair.public.to_vec(),
        });
        let server_pubkey = server_keys.public_key.clone();

        // Generate client keypair
        let builder = Builder::new(NoisePattern::IK.protocol_name().parse().unwrap());
        let keypair = builder.generate_keypair().unwrap();
        let client_keys = Arc::new(NoiseKeypair {
            private_key: keypair.private.to_vec(),
            public_key: keypair.public.to_vec(),
        });

        let server_config = NoiseConfig::server(server_keys);
        let client_config = NoiseConfig::client(client_keys, server_pubkey);

        (client_config, server_config)
    }

    #[test]
    fn test_noise_quinn_session_creation() {
        let (client_config, server_config) = create_test_config();

        let client_session = NoiseQuinnSession::new_client(client_config, "example.com");
        let server_session = NoiseQuinnSession::new_server(server_config);

        assert!(client_session.is_ok());
        assert!(server_session.is_ok());
    }

    #[test]
    fn test_initial_keys_derivation() {
        let (client_config, _server_config) = create_test_config();
        let mut session = NoiseQuinnSession::new_client(client_config, "example.com").unwrap();

        // Start handshake to derive initial keys
        let conn_id = b"test_connection_id";
        session.session.start_handshake(conn_id).unwrap();

        let keys = session.initial_keys();
        assert!(keys.is_some());
    }
}
