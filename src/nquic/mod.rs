// nQUIC: Noise-based QUIC transport for DNS tunneling
//
// This module implements QUIC with Noise Protocol handshake instead of TLS 1.3,
// optimized for DNS tunneling with base32 encoding and 24-byte header overhead.
//
// Architecture:
// - crypto: Noise Protocol crypto layer for Quinn (NoiseSession)
// - dns: DNS codec and transport (base32 encoding, TXT records)
// - endpoint: High-level nQUIC endpoint API

pub mod crypto;
pub mod dns;
pub mod endpoint;

#[cfg(test)]
mod tests;

pub use crypto::{NoiseSession, NoiseConfig};
pub use dns::{DnsCodec, DnsTransport};
pub use endpoint::{NquicEndpoint, NquicConnection};

/// nQUIC protocol version
pub const NQUIC_VERSION: u32 = 1;

/// Maximum DNS label length (RFC 1035)
pub const MAX_DNS_LABEL_LEN: usize = 63;

/// Maximum DNS name length (RFC 1035)
pub const MAX_DNS_NAME_LEN: usize = 253;

/// Maximum DNS UDP packet size (RFC 1035)
pub const MAX_DNS_UDP_SIZE: usize = 512;

/// Recommended DNS packet size for DNS tunneling (conservative)
pub const RECOMMENDED_DNS_PACKET_SIZE: usize = 450;

/// Minimum QUIC Initial packet size (reduced from 1200 for DNS)
pub const MIN_INITIAL_PACKET_SIZE: usize = 256;

/// nQUIC header overhead (compared to 59 bytes in dnstt)
pub const NQUIC_HEADER_OVERHEAD: usize = 24;
