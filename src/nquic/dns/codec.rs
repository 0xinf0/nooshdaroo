// DNS codec for nQUIC packets
//
// Encodes QUIC packets into DNS queries (base32 in domain labels)
// and decodes QUIC packets from DNS responses (TXT records)

use super::{Result, DnsError};
use crate::nquic::{MAX_DNS_LABEL_LEN, MAX_DNS_NAME_LEN, RECOMMENDED_DNS_PACKET_SIZE};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

/// DNS codec for nQUIC
pub struct DnsCodec {
    /// Base domain (e.g., "tunnel.example.com")
    base_domain: String,

    /// Maximum packet size for DNS
    max_packet_size: usize,
}

impl DnsCodec {
    /// Create a new DNS codec
    pub fn new(base_domain: String) -> Self {
        Self {
            base_domain,
            max_packet_size: RECOMMENDED_DNS_PACKET_SIZE,
        }
    }

    /// Encode QUIC packet into DNS query domain name (upstream)
    ///
    /// Format: <base32-encoded-packet>.<base-domain>
    /// Each label is limited to 63 characters (base32 encoding)
    pub fn encode_query(&self, packet: &[u8]) -> Result<String> {
        if packet.len() > self.max_upstream_size() {
            return Err(DnsError::PacketTooLarge(
                packet.len(),
                self.max_upstream_size(),
            ));
        }

        // Use base32 encoding for DNS compatibility
        let encoded = self.base32_encode(packet);

        // Split into 63-char labels
        let labels = self.split_into_labels(&encoded);

        // Construct full domain name
        let domain = format!("{}.{}", labels.join("."), self.base_domain);

        if domain.len() > MAX_DNS_NAME_LEN {
            return Err(DnsError::EncodingError(
                format!("Domain name too long: {} bytes", domain.len()),
            ));
        }

        Ok(domain)
    }

    /// Decode QUIC packet from DNS query domain name
    pub fn decode_query(&self, domain: &str) -> Result<Vec<u8>> {
        // Remove base domain suffix
        let prefix = domain.strip_suffix(&format!(".{}", self.base_domain))
            .ok_or_else(|| DnsError::DecodingError("Invalid domain suffix".into()))?;

        // Remove dots between labels
        let encoded = prefix.replace('.', "");

        // Decode from base32
        self.base32_decode(&encoded)
    }

    /// Encode QUIC packet into DNS TXT record (downstream)
    ///
    /// TXT records can contain binary data, so we use base64 for better density
    pub fn encode_response(&self, packet: &[u8]) -> Result<Vec<u8>> {
        if packet.len() > self.max_downstream_size() {
            return Err(DnsError::PacketTooLarge(
                packet.len(),
                self.max_downstream_size(),
            ));
        }

        // For TXT records, we can use raw bytes or base64
        // Using raw bytes for efficiency (similar to slipstream)
        Ok(packet.to_vec())
    }

    /// Decode QUIC packet from DNS TXT record
    pub fn decode_response(&self, txt_data: &[u8]) -> Result<Vec<u8>> {
        // Direct bytes from TXT record
        Ok(txt_data.to_vec())
    }

    /// Calculate maximum upstream packet size (query)
    pub fn max_upstream_size(&self) -> usize {
        // Available space for labels (excluding base domain and dots)
        let base_domain_len = self.base_domain.len() + 1; // +1 for leading dot
        let available = MAX_DNS_NAME_LEN.saturating_sub(base_domain_len);

        // Account for label separators (every 63 chars needs a dot)
        let max_encoded = available * MAX_DNS_LABEL_LEN / (MAX_DNS_LABEL_LEN + 1);

        // Base32 encoding: 5 bytes -> 8 characters
        (max_encoded * 5) / 8
    }

    /// Calculate maximum downstream packet size (response)
    pub fn max_downstream_size(&self) -> usize {
        // TXT records in UDP responses are limited by DNS packet size
        // Leave room for DNS header and other fields
        self.max_packet_size.saturating_sub(100)
    }

    /// Base32 encoding (RFC 4648)
    fn base32_encode(&self, data: &[u8]) -> String {
        // Simple base32 implementation
        // In production, use a proper base32 library
        BASE64.encode(data) // Placeholder: using base64 for now
    }

    /// Base32 decoding
    fn base32_decode(&self, encoded: &str) -> Result<Vec<u8>> {
        BASE64.decode(encoded)
            .map_err(|e| DnsError::DecodingError(format!("Base32 decode failed: {}", e)))
    }

    /// Split encoded string into 63-char labels
    fn split_into_labels<'a>(&self, s: &'a str) -> Vec<&'a str> {
        let mut labels = Vec::new();
        let mut start = 0;

        while start < s.len() {
            let end = (start + MAX_DNS_LABEL_LEN).min(s.len());
            labels.push(&s[start..end]);
            start = end;
        }

        labels
    }

    /// Set maximum packet size
    pub fn set_max_packet_size(&mut self, size: usize) {
        self.max_packet_size = size;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_query() {
        let codec = DnsCodec::new("tunnel.example.com".to_string());
        let packet = b"Hello, nQUIC!";

        let domain = codec.encode_query(packet).unwrap();
        assert!(domain.ends_with(".tunnel.example.com"));

        let decoded = codec.decode_query(&domain).unwrap();
        assert_eq!(decoded, packet);
    }

    #[test]
    fn test_encode_decode_response() {
        let codec = DnsCodec::new("tunnel.example.com".to_string());
        let packet = b"Response from server";

        let encoded = codec.encode_response(packet).unwrap();
        let decoded = codec.decode_response(&encoded).unwrap();

        assert_eq!(decoded, packet);
    }

    #[test]
    fn test_max_sizes() {
        let codec = DnsCodec::new("tunnel.example.com".to_string());

        let max_upstream = codec.max_upstream_size();
        let max_downstream = codec.max_downstream_size();

        assert!(max_upstream > 0);
        assert!(max_downstream > 0);
        assert!(max_downstream > max_upstream); // TXT records can be larger
    }

    #[test]
    fn test_packet_too_large() {
        let codec = DnsCodec::new("tunnel.example.com".to_string());
        let large_packet = vec![0u8; 1000];

        let result = codec.encode_query(&large_packet);
        assert!(result.is_err());
    }
}
