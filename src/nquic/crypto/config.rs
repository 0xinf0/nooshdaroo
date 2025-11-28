// nQUIC Noise configuration
//
// Configuration for Noise Protocol handshake in nQUIC

use crate::noise_transport::{NoisePattern, NoiseKeypair};
use std::sync::Arc;

/// Noise configuration for nQUIC
#[derive(Clone)]
pub struct NoiseConfig {
    /// Noise pattern (IK for nQUIC)
    pub pattern: NoisePattern,

    /// Noise keys (static keypair for server, server's public key for client)
    pub keys: Arc<NoiseKeypair>,

    /// Role: true for server, false for client
    pub is_server: bool,

    /// Remote static public key (for client: server's key, for server: optional client key)
    pub remote_static: Option<Vec<u8>>,
}

impl NoiseConfig {
    /// Create server configuration
    pub fn server(keys: Arc<NoiseKeypair>) -> Self {
        Self {
            pattern: NoisePattern::IK,
            keys,
            is_server: true,
            remote_static: None,
        }
    }

    /// Create client configuration with server's public key
    pub fn client(keys: Arc<NoiseKeypair>, server_pubkey: Vec<u8>) -> Self {
        Self {
            pattern: NoisePattern::IK,
            keys,
            is_server: false,
            remote_static: Some(server_pubkey),
        }
    }

    /// Get protocol name for Noise builder
    pub fn protocol_name(&self) -> &'static str {
        self.pattern.protocol_name()
    }
}
