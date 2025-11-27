// DNS encoding/decoding for nQUIC
//
// Handles encoding QUIC packets into DNS queries/responses
// using base32 for upstream and TXT records for downstream

pub mod codec;
pub mod protocol;
pub mod transport;

pub use codec::DnsCodec;
pub use protocol::{DnsMessage, DnsQuestion, DnsRecord, DnsHeader};
pub use transport::DnsTransport;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum DnsError {
    #[error("Encoding error: {0}")]
    EncodingError(String),

    #[error("Decoding error: {0}")]
    DecodingError(String),

    #[error("Packet too large: {0} bytes (max: {1})")]
    PacketTooLarge(usize, usize),

    #[error("Invalid DNS message: {0}")]
    InvalidMessage(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, DnsError>;
