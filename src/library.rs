//! Protocol library manager

use super::protocol::{ProtocolBuilder, ProtocolId, ProtocolMeta, Transport};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Protocol library containing all available protocol definitions
pub struct ProtocolLibrary {
    protocols: HashMap<ProtocolId, ProtocolMeta>,
    protocol_dir: PathBuf,
}

impl ProtocolLibrary {
    /// Load protocol library from directory
    pub fn load(protocol_dir: &Path) -> Result<Self, crate::NooshdarooError> {
        let mut library = Self {
            protocols: HashMap::new(),
            protocol_dir: protocol_dir.to_path_buf(),
        };

        // Load built-in protocols
        library.load_builtin_protocols();

        // Scan directory for PSF files
        if protocol_dir.exists() {
            library.scan_directory(protocol_dir)?;
        }

        Ok(library)
    }

    /// Get protocol by ID
    pub fn get(&self, id: &ProtocolId) -> Option<&ProtocolMeta> {
        self.protocols.get(id)
    }

    /// Get all protocols
    pub fn all(&self) -> Vec<&ProtocolMeta> {
        self.protocols.values().collect()
    }

    /// Iterate over all protocols (id, meta)
    pub fn iter(&self) -> impl Iterator<Item = (&ProtocolId, &ProtocolMeta)> {
        self.protocols.iter()
    }

    /// Get number of protocols
    pub fn len(&self) -> usize {
        self.protocols.len()
    }

    /// Check if library is empty
    pub fn is_empty(&self) -> bool {
        self.protocols.is_empty()
    }

    /// Get protocols by category
    pub fn by_category(&self, category: &str) -> Vec<&ProtocolMeta> {
        self.protocols
            .values()
            .filter(|p| p.metadata.category == category)
            .collect()
    }

    /// Get protocols suitable for evasion (sorted by score)
    pub fn evasion_candidates(&self, min_score: f64) -> Vec<&ProtocolMeta> {
        let mut candidates: Vec<_> = self
            .protocols
            .values()
            .filter(|p| p.evasion_score() >= min_score)
            .collect();

        candidates.sort_by(|a, b| {
            b.evasion_score()
                .partial_cmp(&a.evasion_score())
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        candidates
    }

    /// Add protocol to library
    pub fn add(&mut self, protocol: ProtocolMeta) {
        self.protocols.insert(protocol.id.clone(), protocol);
    }

    /// Load built-in protocol definitions
    fn load_builtin_protocols(&mut self) {
        // Top 20 protocols for initial implementation

        // 1. HTTPS - Most common encrypted web traffic
        self.add(
            ProtocolBuilder::new("https", "HTTPS")
                .rfcs(vec![2818, 7230, 7231, 7232, 7233, 7234, 7235])
                .port(443)
                .transport(Transport::Tcp)
                .packet_size(100, 1500)
                .handshake()
                .stateful()
                .encrypted()
                .detection(1.0, 0.05, 0.3) // Very common, low suspicion
                .category("web")
                .psf_path(self.protocol_dir.join("http/https.psf"))
                .build(),
        );

        // 2. HTTP/2 - Modern web traffic
        self.add(
            ProtocolBuilder::new("http2", "HTTP/2")
                .rfcs(vec![7540])
                .port(443)
                .transport(Transport::Tcp)
                .packet_size(100, 1500)
                .handshake()
                .stateful()
                .encrypted()
                .detection(0.9, 0.1, 0.4)
                .category("web")
                .psf_path(self.protocol_dir.join("http/http2.psf"))
                .build(),
        );

        // 3. DNS - Universal protocol
        self.add(
            ProtocolBuilder::new("dns", "DNS")
                .rfcs(vec![1034, 1035])
                .port(53)
                .transport(Transport::Both)
                .packet_size(64, 512)
                .detection(1.0, 0.05, 0.2) // Extremely common
                .category("infrastructure")
                .psf_path(self.protocol_dir.join("dns/dns.psf"))
                .build(),
        );

        // 4. DNS over HTTPS (DoH)
        self.add(
            ProtocolBuilder::new("doh", "DNS over HTTPS")
                .rfcs(vec![8484])
                .port(443)
                .transport(Transport::Tcp)
                .packet_size(100, 1500)
                .handshake()
                .stateful()
                .encrypted()
                .detection(0.7, 0.15, 0.35)
                .category("infrastructure")
                .psf_path(self.protocol_dir.join("dns/doh.psf"))
                .build(),
        );

        // 5. TLS 1.3
        self.add(
            ProtocolBuilder::new("tls13", "TLS 1.3")
                .rfcs(vec![8446])
                .port(443)
                .transport(Transport::Tcp)
                .packet_size(100, 1500)
                .handshake()
                .stateful()
                .encrypted()
                .detection(0.95, 0.05, 0.4)
                .category("security")
                .psf_path(self.protocol_dir.join("tls/tls13.psf"))
                .build(),
        );

        // 6. QUIC
        self.add(
            ProtocolBuilder::new("quic", "QUIC")
                .rfcs(vec![9000])
                .port(443)
                .transport(Transport::Udp)
                .packet_size(1200, 1350)
                .handshake()
                .stateful()
                .encrypted()
                .detection(0.75, 0.2, 0.6)
                .category("transport")
                .psf_path(self.protocol_dir.join("quic/quic.psf"))
                .build(),
        );

        // 7. SSH
        self.add(
            ProtocolBuilder::new("ssh", "SSH")
                .rfcs(vec![4251, 4252, 4253, 4254])
                .port(22)
                .transport(Transport::Tcp)
                .packet_size(64, 1500)
                .handshake()
                .stateful()
                .encrypted()
                .detection(0.8, 0.25, 0.45)
                .category("remote")
                .psf_path(self.protocol_dir.join("ssh/ssh.psf"))
                .build(),
        );

        // 8. WebSocket
        self.add(
            ProtocolBuilder::new("websocket", "WebSocket")
                .rfcs(vec![6455])
                .port(443)
                .transport(Transport::Tcp)
                .packet_size(100, 1500)
                .handshake()
                .stateful()
                .detection(0.7, 0.15, 0.35)
                .category("web")
                .psf_path(self.protocol_dir.join("websocket/websocket.psf"))
                .build(),
        );

        // 9. SMTP
        self.add(
            ProtocolBuilder::new("smtp", "SMTP")
                .rfcs(vec![5321])
                .port(25)
                .transport(Transport::Tcp)
                .packet_size(100, 1500)
                .handshake()
                .stateful()
                .detection(0.75, 0.2, 0.3)
                .category("email")
                .psf_path(self.protocol_dir.join("smtp/smtp.psf"))
                .build(),
        );

        // 10. IMAP
        self.add(
            ProtocolBuilder::new("imap", "IMAP")
                .rfcs(vec![3501])
                .port(143)
                .transport(Transport::Tcp)
                .packet_size(100, 1500)
                .handshake()
                .stateful()
                .detection(0.7, 0.2, 0.35)
                .category("email")
                .psf_path(self.protocol_dir.join("smtp/imap.psf"))
                .build(),
        );

        // 11. FTP
        self.add(
            ProtocolBuilder::new("ftp", "FTP")
                .rfcs(vec![959])
                .port(21)
                .transport(Transport::Tcp)
                .packet_size(100, 1500)
                .handshake()
                .stateful()
                .detection(0.5, 0.3, 0.3)
                .category("file-transfer")
                .psf_path(self.protocol_dir.join("ftp/ftp.psf"))
                .build(),
        );

        // 12. NTP
        self.add(
            ProtocolBuilder::new("ntp", "NTP")
                .rfcs(vec![5905])
                .port(123)
                .transport(Transport::Udp)
                .packet_size(48, 90)
                .detection(0.9, 0.1, 0.2)
                .category("infrastructure")
                .psf_path(self.protocol_dir.join("http/ntp.psf"))
                .build(),
        );

        // 13. MQTT
        self.add(
            ProtocolBuilder::new("mqtt", "MQTT")
                .port(1883)
                .transport(Transport::Tcp)
                .packet_size(64, 1024)
                .handshake()
                .stateful()
                .detection(0.6, 0.25, 0.35)
                .category("iot")
                .psf_path(self.protocol_dir.join("http/mqtt.psf"))
                .build(),
        );

        // 14. RTP
        self.add(
            ProtocolBuilder::new("rtp", "RTP")
                .rfcs(vec![3550])
                .port(5004)
                .transport(Transport::Udp)
                .packet_size(160, 1500)
                .detection(0.65, 0.2, 0.4)
                .category("media")
                .psf_path(self.protocol_dir.join("http/rtp.psf"))
                .build(),
        );

        // 15. SIP
        self.add(
            ProtocolBuilder::new("sip", "SIP")
                .rfcs(vec![3261])
                .port(5060)
                .transport(Transport::Both)
                .packet_size(200, 1500)
                .handshake()
                .stateful()
                .detection(0.55, 0.25, 0.45)
                .category("voip")
                .psf_path(self.protocol_dir.join("http/sip.psf"))
                .build(),
        );

        // 16. RTSP
        self.add(
            ProtocolBuilder::new("rtsp", "RTSP")
                .rfcs(vec![7826])
                .port(554)
                .transport(Transport::Tcp)
                .packet_size(200, 1500)
                .handshake()
                .stateful()
                .detection(0.5, 0.3, 0.4)
                .category("media")
                .psf_path(self.protocol_dir.join("http/rtsp.psf"))
                .build(),
        );

        // 17. SNMP
        self.add(
            ProtocolBuilder::new("snmp", "SNMP")
                .rfcs(vec![3411, 3412, 3413, 3414, 3415, 3416, 3417, 3418])
                .port(161)
                .transport(Transport::Udp)
                .packet_size(64, 1500)
                .detection(0.6, 0.2, 0.35)
                .category("management")
                .psf_path(self.protocol_dir.join("http/snmp.psf"))
                .build(),
        );

        // 18. LDAP
        self.add(
            ProtocolBuilder::new("ldap", "LDAP")
                .rfcs(vec![4511])
                .port(389)
                .transport(Transport::Tcp)
                .packet_size(100, 1500)
                .handshake()
                .stateful()
                .detection(0.55, 0.25, 0.4)
                .category("directory")
                .psf_path(self.protocol_dir.join("http/ldap.psf"))
                .build(),
        );

        // 19. BitTorrent
        self.add(
            ProtocolBuilder::new("bittorrent", "BitTorrent")
                .port(6881)
                .transport(Transport::Both)
                .packet_size(100, 16384)
                .handshake()
                .stateful()
                .detection(0.5, 0.6, 0.3) // High suspicion
                .category("p2p")
                .psf_path(self.protocol_dir.join("http/bittorrent.psf"))
                .build(),
        );

        // 20. gRPC
        self.add(
            ProtocolBuilder::new("grpc", "gRPC")
                .port(443)
                .transport(Transport::Tcp)
                .packet_size(100, 1500)
                .handshake()
                .stateful()
                .encrypted()
                .detection(0.6, 0.2, 0.5)
                .category("rpc")
                .psf_path(self.protocol_dir.join("http/grpc.psf"))
                .build(),
        );
    }

    /// Scan directory for PSF files and load protocol metadata
    fn scan_directory(&mut self, dir: &Path) -> Result<(), crate::NooshdarooError> {
        use std::fs;

        // Recursively walk directory tree
        self.scan_directory_recursive(dir)?;
        Ok(())
    }

    /// Recursively scan directory for PSF files
    fn scan_directory_recursive(&mut self, dir: &Path) -> Result<(), crate::NooshdarooError> {
        use std::fs;

        if !dir.is_dir() {
            return Ok(());
        }

        for entry in fs::read_dir(dir).map_err(|e| crate::NooshdarooError::Io(e))? {
            let entry = entry.map_err(|e| crate::NooshdarooError::Io(e))?;
            let path = entry.path();

            if path.is_dir() {
                // Recursively scan subdirectories
                self.scan_directory_recursive(&path)?;
            } else if path.extension().and_then(|s| s.to_str()) == Some("psf") {
                // Load PSF file metadata
                self.load_psf_file(&path)?;
            }
        }

        Ok(())
    }

    /// Load protocol metadata from PSF file
    fn load_psf_file(&mut self, path: &Path) -> Result<(), crate::NooshdarooError> {
        use std::fs;

        // Read PSF file
        let content = fs::read_to_string(path)
            .map_err(|e| crate::NooshdarooError::Io(e))?;

        // Extract protocol name from filename
        let filename = path.file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| crate::NooshdarooError::InvalidConfig("Invalid PSF filename".to_string()))?;

        // Extract category from parent directory
        let category = path.parent()
            .and_then(|p| p.file_name())
            .and_then(|s| s.to_str())
            .unwrap_or("unknown");

        // Parse protocol name from first comment line or filename
        let protocol_name = content.lines()
            .find(|line| line.starts_with('#') && !line.contains("Protocol Signature"))
            .and_then(|line| line.strip_prefix('#').map(|s| s.trim()))
            .filter(|s| !s.is_empty() && !s.contains("(RFC") && !s.contains("Protocol"))
            .unwrap_or(filename);

        // Extract port from @SEGMENT.CRYPTO section
        let default_port = content.lines()
            .skip_while(|line| !line.contains("@SEGMENT.CRYPTO"))
            .take_while(|line| !line.starts_with('@') || line.contains("@SEGMENT.CRYPTO"))
            .find(|line| line.contains("DEFAULT_PORT:"))
            .and_then(|line| line.split(':').nth(1))
            .and_then(|s| s.trim().parse::<u16>().ok())
            .unwrap_or(443);

        // Extract transport type
        let transport = if content.contains("TRANSPORT: TCP") {
            Transport::Tcp
        } else if content.contains("TRANSPORT: UDP") {
            Transport::Udp
        } else if content.contains("TRANSPORT: BOTH") {
            Transport::Both
        } else {
            Transport::Tcp
        };

        // Check if encrypted
        let encrypted = content.contains("CIPHER:") || content.contains("TLS") || content.contains("ENCRYPTION:");

        // Build protocol metadata
        let protocol = ProtocolBuilder::new(filename, protocol_name)
            .port(default_port)
            .transport(transport)
            .packet_size(100, 1500) // Default sizes
            .category(category)
            .psf_path(path.to_path_buf());

        let protocol = if encrypted {
            protocol.encrypted()
        } else {
            protocol
        };

        let protocol = protocol
            .detection(0.7, 0.2, 0.4) // Default detection values
            .build();

        // Add to library (avoid duplicates with built-in protocols)
        if !self.protocols.contains_key(&protocol.id) {
            self.add(protocol);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_library_creation() {
        let library = ProtocolLibrary::load(&PathBuf::from("protocols")).unwrap();
        assert!(library.protocols.len() >= 20);
    }

    #[test]
    fn test_get_protocol() {
        let library = ProtocolLibrary::load(&PathBuf::from("protocols")).unwrap();
        let https = library.get(&ProtocolId::from("https"));
        assert!(https.is_some());
        assert_eq!(https.unwrap().default_port, 443);
    }

    #[test]
    fn test_evasion_candidates() {
        let library = ProtocolLibrary::load(&PathBuf::from("protocols")).unwrap();
        let candidates = library.evasion_candidates(0.6);
        assert!(!candidates.is_empty());

        // First candidate should have highest evasion score
        if candidates.len() > 1 {
            assert!(candidates[0].evasion_score() >= candidates[1].evasion_score());
        }
    }

    #[test]
    fn test_category_filtering() {
        let library = ProtocolLibrary::load(&PathBuf::from("protocols")).unwrap();
        let web_protocols = library.by_category("web");
        assert!(web_protocols.iter().all(|p| p.metadata.category == "web"));
    }
}
