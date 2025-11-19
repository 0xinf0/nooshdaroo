//! Nooshdaroo configuration

use super::strategy::StrategyType;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;

/// Default protocol directory (no longer used since protocols are embedded)
fn default_protocol_dir() -> PathBuf {
    PathBuf::from("protocols")
}

/// Main Nooshdaroo configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NooshdarooConfig {
    /// Mode of operation
    pub mode: NooshdarooMode,

    /// Protocol library directory (deprecated - protocols are now embedded)
    #[serde(default = "default_protocol_dir")]
    pub protocol_dir: PathBuf,

    /// Encryption configuration
    pub encryption: EncryptionConfig,

    /// SOCKS5 configuration (client mode)
    #[serde(default)]
    pub socks: SocksConfig,

    /// Shape-shifting configuration
    pub shapeshift: ShapeShiftConfig,

    /// Traffic shaping configuration
    #[serde(default)]
    pub traffic_shaping: TrafficShapingConfig,

    /// Server configuration (server mode)
    pub server: Option<ServerConfig>,

    /// Detection resistance features
    #[serde(default)]
    pub detection: DetectionConfig,

    /// Transport encryption (Noise Protocol)
    #[serde(default)]
    pub transport: Option<crate::noise_transport::NoiseConfig>,
}

impl Default for NooshdarooConfig {
    fn default() -> Self {
        Self {
            mode: NooshdarooMode::Client,
            protocol_dir: PathBuf::from("protocols"),
            encryption: EncryptionConfig::default(),
            socks: SocksConfig::default(),
            shapeshift: ShapeShiftConfig::default(),
            traffic_shaping: TrafficShapingConfig::default(),
            server: None,
            detection: DetectionConfig::default(),
            transport: None,
        }
    }
}

/// Operating mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NooshdarooMode {
    Client,
    Server,
}

/// Encryption configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionConfig {
    /// Cipher to use
    pub cipher: CipherType,

    /// Key derivation function
    pub key_derivation: KdfType,

    /// Password for key derivation (optional, not currently used by Noise Protocol)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,

    /// Optional salt
    pub salt: Option<String>,
}

impl Default for EncryptionConfig {
    fn default() -> Self {
        Self {
            cipher: CipherType::ChaCha20Poly1305,
            key_derivation: KdfType::Argon2,
            password: None,
            salt: None,
        }
    }
}

/// Cipher types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CipherType {
    ChaCha20Poly1305,
    Aes256Gcm,
}

/// Key derivation function types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KdfType {
    Argon2,
    Pbkdf2,
}

/// SOCKS5 server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocksConfig {
    /// Listen address for SOCKS5 server
    pub listen_addr: SocketAddr,

    /// Remote server address for tunneling (client mode)
    pub server_address: Option<String>,

    /// Require authentication
    pub auth_required: bool,

    /// Username for authentication
    pub username: Option<String>,

    /// Password for authentication
    pub password: Option<String>,
}

impl Default for SocksConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:1080".parse().unwrap(),
            server_address: None,
            auth_required: false,
            username: None,
            password: None,
        }
    }
}

/// Shape-shifting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShapeShiftConfig {
    /// Shape-shifting strategy
    pub strategy: StrategyType,
}

impl Default for ShapeShiftConfig {
    fn default() -> Self {
        Self {
            strategy: StrategyType::default(),
        }
    }
}

/// Traffic shaping configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficShapingConfig {
    /// Enable traffic shaping
    pub enabled: bool,

    /// Packet size distribution
    pub packet_size_distribution: DistributionType,

    /// Mean packet size (bytes)
    pub mean_packet_size: usize,

    /// Standard deviation for packet size
    pub stddev_packet_size: usize,

    /// Mean inter-packet delay (microseconds)
    pub mean_delay: u64,

    /// Standard deviation for delay
    pub stddev_delay: u64,

    /// Enable burst mode
    pub enable_bursts: bool,

    /// Burst size (packets)
    pub burst_size: usize,

    /// Burst probability (0.0 - 1.0)
    pub burst_probability: f64,
}

impl Default for TrafficShapingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            packet_size_distribution: DistributionType::Normal,
            mean_packet_size: 1400,
            stddev_packet_size: 200,
            mean_delay: 50,
            stddev_delay: 20,
            enable_bursts: false,
            burst_size: 5,
            burst_probability: 0.1,
        }
    }
}

/// Statistical distribution types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DistributionType {
    Normal,
    Uniform,
    Exponential,
}

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Listen address
    pub listen_addr: SocketAddr,
}

/// Detection resistance configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionConfig {
    /// Enable fingerprint randomization
    pub enable_fingerprint_randomization: bool,

    /// Enable timing randomization
    pub enable_timing_randomization: bool,

    /// Enable TLS SNI masking
    pub enable_tls_sni_masking: bool,

    /// Enable full TLS session emulation (wraps all data in TLS Application Data records)
    /// This defeats deep packet inspection by making all traffic look like valid TLS 1.3
    #[serde(default = "default_tls_session_emulation")]
    pub enable_tls_session_emulation: bool,

    /// Suspicion threshold for adaptive switching
    pub suspicion_threshold: f64,

    /// Enable decoy traffic
    pub enable_decoy_traffic: bool,

    /// Decoy traffic rate (packets per second)
    pub decoy_traffic_rate: f64,
}

fn default_tls_session_emulation() -> bool {
    true // Enable by default for maximum evasion
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            enable_fingerprint_randomization: true,
            enable_timing_randomization: true,
            enable_tls_sni_masking: false,
            enable_tls_session_emulation: true, // Enabled by default
            suspicion_threshold: 0.7,
            enable_decoy_traffic: false,
            decoy_traffic_rate: 0.1,
        }
    }
}

impl NooshdarooConfig {
    /// Load configuration from TOML file
    pub fn from_file(path: &std::path::Path) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&contents)?;
        Ok(config)
    }

    /// Save configuration to TOML file
    pub fn to_file(&self, path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
        let contents = toml::to_string_pretty(self)?;
        std::fs::write(path, contents)?;
        Ok(())
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<(), String> {
        // Check server config in server mode
        if self.mode == NooshdarooMode::Server && self.server.is_none() {
            return Err("Server configuration required in server mode".to_string());
        }

        // Validate suspicion threshold
        if self.detection.suspicion_threshold < 0.0 || self.detection.suspicion_threshold > 1.0 {
            return Err("Suspicion threshold must be between 0.0 and 1.0".to_string());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = NooshdarooConfig::default();
        assert_eq!(config.mode, NooshdarooMode::Client);
        assert!(config.traffic_shaping.enabled);
    }

    #[test]
    fn test_config_validation() {
        let mut config = NooshdarooConfig::default();

        // Should fail without password
        assert!(config.validate().is_err());

        // Should succeed with password
        config.encryption.password = "test-password".to_string();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_server_mode_validation() {
        let mut config = NooshdarooConfig::default();
        config.mode = NooshdarooMode::Server;
        config.encryption.password = "test".to_string();

        // Should fail without server config
        assert!(config.validate().is_err());

        // Should succeed with server config
        config.server = Some(ServerConfig {
            listen_addr: "0.0.0.0:443".parse().unwrap(),
        });
        assert!(config.validate().is_ok());
    }
}
