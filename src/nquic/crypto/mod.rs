// Crypto layer for nQUIC: Noise Protocol integration with Quinn
//
// This module implements the quinn_proto::crypto::Session trait using
// Snow (Noise Protocol) instead of TLS 1.3 for QUIC handshake and encryption.

pub mod noise_session;
pub mod keys;
pub mod config;
pub mod quinn_crypto;

pub use noise_session::NoiseSession;
pub use keys::{derive_quic_keys, NoiseKeyDerivation, QuicKeys};
pub use config::NoiseConfig;
pub use quinn_crypto::{
    NoiseClientConfig, NoiseServerConfig, NoiseQuinnSession,
};

use thiserror::Error;

#[derive(Error, Debug)]
pub enum NoiseCryptoError {
    #[error("Noise handshake failed: {0}")]
    HandshakeFailed(String),

    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),

    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Invalid state: {0}")]
    InvalidState(String),

    #[error("Snow error: {0}")]
    SnowError(#[from] snow::Error),
}

pub type Result<T> = std::result::Result<T, NoiseCryptoError>;
