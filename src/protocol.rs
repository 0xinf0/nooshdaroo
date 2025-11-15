//! Protocol metadata and definitions

use serde::{Deserialize, Serialize};
use std::ops::Range;
use std::path::PathBuf;

/// Unique protocol identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProtocolId(String);

impl ProtocolId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for ProtocolId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for ProtocolId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl Default for ProtocolId {
    fn default() -> Self {
        Self("unknown".to_string())
    }
}

impl std::fmt::Display for ProtocolId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Transport layer protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Transport {
    Tcp,
    Udp,
    Both,
}

/// Detection resistance scoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionScore {
    /// How common this protocol is (0.0 - 1.0, higher = more common)
    pub commonality: f64,

    /// How suspicious this protocol might be (0.0 - 1.0, higher = more suspicious)
    pub suspicion: f64,

    /// Implementation complexity (0.0 - 1.0, higher = more complex)
    pub complexity: f64,
}

impl DetectionScore {
    /// Calculate overall detection resistance score
    /// Higher score = better for evasion
    pub fn resistance_score(&self) -> f64 {
        // Common protocols with low suspicion are best
        // Complex protocols might be harder to emulate perfectly
        self.commonality * (1.0 - self.suspicion) * (1.0 - self.complexity * 0.3)
    }
}

/// Protocol metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolMeta {
    /// Unique protocol identifier
    pub id: ProtocolId,

    /// Human-readable name
    pub name: String,

    /// RFC numbers that define this protocol
    pub rfc_numbers: Vec<u16>,

    /// Default port number
    pub default_port: u16,

    /// Transport layer protocol
    pub transport: Transport,

    /// Typical packet size range (min, max)
    pub typical_packet_size: Range<usize>,

    /// Whether protocol requires handshake
    pub handshake_required: bool,

    /// Whether protocol is stateful
    pub stateful: bool,

    /// Whether protocol has native encryption
    pub encryption_native: bool,

    /// Detection resistance metrics
    pub detection: DetectionScore,

    /// Path to PSF specification file
    pub psf_path: PathBuf,

    /// Optional metadata
    pub metadata: ProtocolMetadata,
}

/// Additional protocol metadata
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProtocolMetadata {
    /// Protocol category (e.g., "web", "email", "file-transfer")
    pub category: String,

    /// Typical applications that use this protocol
    pub applications: Vec<String>,

    /// Average inter-packet delay in microseconds
    pub avg_packet_delay: Option<u64>,

    /// Whether protocol is commonly used over TLS
    pub commonly_uses_tls: bool,

    /// Notes about implementation
    pub notes: Option<String>,
}

impl ProtocolMeta {
    /// Create a new protocol metadata entry
    pub fn new(
        id: impl Into<ProtocolId>,
        name: impl Into<String>,
        psf_path: impl Into<PathBuf>,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            rfc_numbers: vec![],
            default_port: 0,
            transport: Transport::Tcp,
            typical_packet_size: 64..1500,
            handshake_required: false,
            stateful: false,
            encryption_native: false,
            detection: DetectionScore {
                commonality: 0.5,
                suspicion: 0.5,
                complexity: 0.5,
            },
            psf_path: psf_path.into(),
            metadata: ProtocolMetadata::default(),
        }
    }

    /// Builder: Add RFC numbers
    pub fn with_rfcs(mut self, rfcs: Vec<u16>) -> Self {
        self.rfc_numbers = rfcs;
        self
    }

    /// Builder: Set default port
    pub fn with_port(mut self, port: u16) -> Self {
        self.default_port = port;
        self
    }

    /// Builder: Set transport
    pub fn with_transport(mut self, transport: Transport) -> Self {
        self.transport = transport;
        self
    }

    /// Builder: Set detection score
    pub fn with_detection(mut self, detection: DetectionScore) -> Self {
        self.detection = detection;
        self
    }

    /// Builder: Set category
    pub fn with_category(mut self, category: impl Into<String>) -> Self {
        self.metadata.category = category.into();
        self
    }

    /// Get overall suitability score for evasion
    pub fn evasion_score(&self) -> f64 {
        self.detection.resistance_score()
    }
}

/// Protocol builder for easier construction
pub struct ProtocolBuilder {
    meta: ProtocolMeta,
}

impl ProtocolBuilder {
    pub fn new(id: &str, name: &str) -> Self {
        Self {
            meta: ProtocolMeta::new(
                id,
                name,
                PathBuf::from(format!("protocols/{}/spec.psf", id)),
            ),
        }
    }

    pub fn rfcs(mut self, rfcs: Vec<u16>) -> Self {
        self.meta.rfc_numbers = rfcs;
        self
    }

    pub fn port(mut self, port: u16) -> Self {
        self.meta.default_port = port;
        self
    }

    pub fn transport(mut self, transport: Transport) -> Self {
        self.meta.transport = transport;
        self
    }

    pub fn packet_size(mut self, min: usize, max: usize) -> Self {
        self.meta.typical_packet_size = min..max;
        self
    }

    pub fn handshake(mut self) -> Self {
        self.meta.handshake_required = true;
        self
    }

    pub fn stateful(mut self) -> Self {
        self.meta.stateful = true;
        self
    }

    pub fn encrypted(mut self) -> Self {
        self.meta.encryption_native = true;
        self
    }

    pub fn detection(mut self, commonality: f64, suspicion: f64, complexity: f64) -> Self {
        self.meta.detection = DetectionScore {
            commonality,
            suspicion,
            complexity,
        };
        self
    }

    pub fn category(mut self, category: &str) -> Self {
        self.meta.metadata.category = category.to_string();
        self
    }

    pub fn psf_path(mut self, path: PathBuf) -> Self {
        self.meta.psf_path = path;
        self
    }

    pub fn build(self) -> ProtocolMeta {
        self.meta
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_builder() {
        let proto = ProtocolBuilder::new("https", "HTTPS")
            .rfcs(vec![2818, 7230])
            .port(443)
            .transport(Transport::Tcp)
            .handshake()
            .stateful()
            .encrypted()
            .detection(1.0, 0.1, 0.3)
            .category("web")
            .build();

        assert_eq!(proto.id.as_str(), "https");
        assert_eq!(proto.default_port, 443);
        assert!(proto.handshake_required);
        assert!(proto.encryption_native);
    }

    #[test]
    fn test_detection_score() {
        let score = DetectionScore {
            commonality: 1.0,
            suspicion: 0.1,
            complexity: 0.2,
        };

        let resistance = score.resistance_score();
        assert!(resistance > 0.8); // Should be high for common, non-suspicious protocol
    }
}
