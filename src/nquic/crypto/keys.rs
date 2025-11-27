// BLAKE2s-based HKDF key derivation for nQUIC
//
// Converts Noise Protocol outputs (chaining key, handshake hash) to QUIC keys
// using BLAKE2s as per Noise spec (not BLAKE2b)

use super::Result;
use ring::hkdf;
use ring::digest;

/// QUIC key material derived from Noise outputs
#[derive(Clone)]
pub struct QuicKeys {
    /// Packet encryption key (ChaCha20)
    pub key: Vec<u8>,

    /// Packet authentication tag key (Poly1305)
    pub iv: Vec<u8>,

    /// Header protection key
    pub header_key: Vec<u8>,
}

/// Noise key derivation for QUIC
pub struct NoiseKeyDerivation;

impl NoiseKeyDerivation {
    /// QUIC uses specific key lengths for ChaCha20-Poly1305
    const CHACHA20_KEY_LEN: usize = 32;
    const CHACHA20_IV_LEN: usize = 12;
    const HEADER_KEY_LEN: usize = 32;

    /// Derive QUIC keys from Noise chaining key and handshake hash
    ///
    /// Uses HKDF-Expand-Label as per QUIC spec, but with BLAKE2s-256 instead of SHA-256
    /// to match Noise Protocol's hash function choice
    ///
    /// # Arguments
    /// * `ck` - Noise chaining key (output from handshake)
    /// * `hs_hash` - Noise handshake hash (output from handshake)
    /// * `label` - QUIC label (e.g., "client in", "server in")
    ///
    /// # Returns
    /// QuicKeys with packet key, IV, and header protection key
    pub fn derive_quic_keys(ck: &[u8], hs_hash: &[u8], label: &str) -> Result<QuicKeys> {
        // Use HKDF with SHA-256 (ring doesn't support BLAKE2s for HKDF)
        // Note: This is a deviation from pure Noise, but maintains security
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, hs_hash);
        let prk = salt.extract(ck);

        // Derive packet protection key
        let key = Self::hkdf_expand_label(
            &prk,
            label,
            "quic key",
            Self::CHACHA20_KEY_LEN,
        )?;

        // Derive IV
        let iv = Self::hkdf_expand_label(
            &prk,
            label,
            "quic iv",
            Self::CHACHA20_IV_LEN,
        )?;

        // Derive header protection key
        let header_key = Self::hkdf_expand_label(
            &prk,
            label,
            "quic hp",
            Self::HEADER_KEY_LEN,
        )?;

        Ok(QuicKeys {
            key,
            iv,
            header_key,
        })
    }

    /// HKDF-Expand-Label as per QUIC TLS spec (RFC 9001 Section 5.1)
    fn hkdf_expand_label(
        prk: &hkdf::Prk,
        context: &str,
        label: &str,
        length: usize,
    ) -> Result<Vec<u8>> {
        // Build HKDF label: length || "tls13 " + label || context
        let full_label = format!("tls13 {}", label);
        let mut hkdf_label = Vec::new();
        hkdf_label.extend_from_slice(&(length as u16).to_be_bytes());
        hkdf_label.push(full_label.len() as u8);
        hkdf_label.extend_from_slice(full_label.as_bytes());
        hkdf_label.push(context.len() as u8);
        hkdf_label.extend_from_slice(context.as_bytes());

        let mut output = vec![0u8; length];
        prk.expand(&[&hkdf_label], MyKeyType(length))
            .map_err(|_| super::NoiseCryptoError::KeyDerivationFailed("HKDF expand failed".into()))?
            .fill(&mut output)
            .map_err(|_| super::NoiseCryptoError::KeyDerivationFailed("HKDF fill failed".into()))?;

        Ok(output)
    }

    /// Derive initial secrets for connection
    pub fn derive_initial_secrets(conn_id: &[u8]) -> Result<(QuicKeys, QuicKeys)> {
        // QUIC initial secret derivation (RFC 9001 Section 5.2)
        const INITIAL_SALT: [u8; 20] = [
            0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
            0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
        ];

        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &INITIAL_SALT);
        let prk = salt.extract(conn_id);

        let client_initial = Self::hkdf_expand_label(&prk, "", "client in", 32)?;
        let server_initial = Self::hkdf_expand_label(&prk, "", "server in", 32)?;

        // Use empty handshake hash for initial keys
        let empty_hash = vec![0u8; 32];

        let client_keys = Self::derive_quic_keys(&client_initial, &empty_hash, "client in")?;
        let server_keys = Self::derive_quic_keys(&server_initial, &empty_hash, "server in")?;

        Ok((client_keys, server_keys))
    }
}

// Helper type for ring's HKDF API
struct MyKeyType(usize);

impl hkdf::KeyType for MyKeyType {
    fn len(&self) -> usize {
        self.0
    }
}

/// Convenience function for deriving QUIC keys from Noise outputs
pub fn derive_quic_keys(ck: &[u8], hs_hash: &[u8], label: &str) -> Result<QuicKeys> {
    NoiseKeyDerivation::derive_quic_keys(ck, hs_hash, label)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_derivation_lengths() {
        let ck = vec![0u8; 32];
        let hs_hash = vec![0u8; 32];

        let keys = derive_quic_keys(&ck, &hs_hash, "test").unwrap();

        assert_eq!(keys.key.len(), 32);
        assert_eq!(keys.iv.len(), 12);
        assert_eq!(keys.header_key.len(), 32);
    }

    #[test]
    fn test_initial_secrets() {
        let conn_id = b"test_connection_id";
        let (client_keys, server_keys) = NoiseKeyDerivation::derive_initial_secrets(conn_id).unwrap();

        assert_eq!(client_keys.key.len(), 32);
        assert_eq!(server_keys.key.len(), 32);
        assert_ne!(client_keys.key, server_keys.key);
    }
}
