//! Nooshdaroo: Protocol Shape-Shifting SOCKS Proxy
//!
//! Nooshdaroo provides dynamic protocol emulation and shape-shifting capabilities,
//! allowing encrypted SOCKS proxy traffic to masquerade as any of 100+ defined
//! network protocols to bypass deep packet inspection and censorship.
//!
//! ## Features
//!
//! - **Multiple Proxy Types**: SOCKS5, HTTP CONNECT, Transparent proxy
//! - **Socat-like Relay**: Bidirectional traffic relay between endpoints
//! - **Mobile-Friendly**: iOS/Android FFI bindings for native integration
//! - **Protocol Shape-Shifting**: 5 strategies for dynamic protocol emulation
//! - **Traffic Shaping**: Timing and size emulation of target protocols
//! - **100+ Protocols**: Pre-defined protocol signatures (HTTPS, SSH, DNS, etc.)
//!
//! ## Quick Start
//!
//! ### As a Library
//!
//! ```rust,no_run
//! use nooshdaroo::{NooshdarooConfig, NooshdarooClient};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = NooshdarooConfig::default();
//!     let client = NooshdarooClient::new(config)?;
//!
//!     // Get current protocol
//!     let protocol = client.current_protocol().await;
//!     println!("Current protocol: {}", protocol.as_str());
//!
//!     // Manually rotate
//!     client.rotate().await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! ### As a Command-Line Tool
//!
//! ```bash
//! # Run as client
//! nooshdaroo client --bind 127.0.0.1:1080 --server example.com:8443
//!
//! # Run as server
//! nooshdaroo server --bind 0.0.0.0:8443
//!
//! # Run as relay (socat mode)
//! nooshdaroo relay --listen 127.0.0.1:8080 --target example.com:443
//! ```
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────┐     ┌──────────────┐     ┌──────────────┐
//! │   Client    │────▶│  Nooshdaroo  │────▶│    Server    │
//! │ Application │     │    Client    │     │   Endpoint   │
//! └─────────────┘     └──────────────┘     └──────────────┘
//!                            │
//!                            │ Shape-Shifting
//!                            ▼
//!                     ┌──────────────┐
//!                     │   Protocol   │
//!                     │   Library    │
//!                     └──────────────┘
//! ```

pub mod app_profiles;
pub mod bandwidth;
pub mod config;
pub mod embedded_keys;
pub mod json_logger;
pub mod library;
pub mod mobile;
pub mod multiport_server;
pub mod netflow_evasion;
pub mod noise_transport;
pub mod profiles;
pub mod protocol;
pub mod proxy;
pub mod psf;
pub mod shapeshift;
pub mod socks5;
pub mod socat;
pub mod strategy;
pub mod tls_record_layer;
pub mod traceroute;
pub mod traffic;
pub mod udp_proxy;
pub mod protocol_wrapper;

// Re-export core types
pub use app_profiles::{ApplicationEmulator, ApplicationProfile, AppCategory};
pub use bandwidth::{
    AdaptiveRateLimiter, BandwidthController, NetworkMetrics, NetworkMonitor, QualityProfile,
    QualityTier,
};
pub use config::{NooshdarooConfig, ShapeShiftConfig, TrafficShapingConfig};
pub use library::ProtocolLibrary;
pub use mobile::{MobileConfigBuilder, NooshdarooMobileConfig};
pub use noise_transport::{
    generate_keypair as generate_noise_keypair, NoiseConfig, NoiseKeypair, NoisePattern,
    NoiseTransport,
};
pub use protocol::{DetectionScore, ProtocolId, ProtocolMeta, Transport};
pub use protocol_wrapper::{ProtocolWrapper, WrapperRole};
pub use proxy::{HttpProxyServer, ProxyType, UnifiedProxyListener};
pub use psf::{PsfInterpreter, ProtocolFrame};
pub use shapeshift::ShapeShiftController;
pub use socat::{Bidirectional, ClientToServer, RelayMode, ServerToClient, SocatBuilder, SocatRelay};
pub use strategy::{ShapeShiftStrategy, StrategyType};
pub use udp_proxy::{SimpleUdpForwarder, UdpProxyServer};
pub use multiport_server::MultiPortServer;
pub use netflow_evasion::{PathTester, MultiPortConfig};

use std::sync::Arc;
use tokio::sync::RwLock;

/// Nooshdaroo client instance for managing shape-shifted connections
///
/// # Example
///
/// ```rust,no_run
/// use nooshdaroo::{NooshdarooConfig, NooshdarooClient};
///
/// # async fn example() -> Result<(), nooshdaroo::NooshdarooError> {
/// let config = NooshdarooConfig::default();
/// let client = NooshdarooClient::new(config)?;
///
/// // Get current protocol
/// let protocol_id = client.current_protocol().await;
/// println!("Using protocol: {}", protocol_id.as_str());
///
/// // Trigger protocol rotation
/// client.rotate().await?;
/// # Ok(())
/// # }
/// ```
pub struct NooshdarooClient {
    config: NooshdarooConfig,
    library: Arc<ProtocolLibrary>,
    pub controller: Arc<RwLock<ShapeShiftController>>,
}

impl NooshdarooClient {
    /// Create a new Nooshdaroo client with the given configuration
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Protocol library cannot be loaded
    /// - Configuration is invalid
    /// - Shape-shift controller initialization fails
    pub fn new(config: NooshdarooConfig) -> Result<Self, NooshdarooError> {
        let library = Arc::new(ProtocolLibrary::load(&config.protocol_dir)?);
        let controller = Arc::new(RwLock::new(ShapeShiftController::new(
            config.shapeshift.clone(),
            Arc::clone(&library),
        )?));

        Ok(Self {
            config,
            library,
            controller,
        })
    }

    /// Get the currently active protocol ID
    pub async fn current_protocol(&self) -> ProtocolId {
        self.controller.read().await.current_protocol()
    }

    /// Manually set the protocol (overrides the configured strategy)
    ///
    /// # Errors
    ///
    /// Returns an error if the protocol ID is not found in the library
    pub async fn set_protocol(&self, protocol_id: ProtocolId) -> Result<(), NooshdarooError> {
        self.controller.write().await.set_protocol(protocol_id)
    }

    /// Get protocol usage statistics
    pub async fn stats(&self) -> ProtocolStats {
        self.controller.read().await.stats()
    }

    /// Trigger protocol rotation based on the configured strategy
    ///
    /// # Errors
    ///
    /// Returns an error if protocol rotation fails
    pub async fn rotate(&self) -> Result<(), NooshdarooError> {
        self.controller.write().await.rotate()
    }

    /// Get reference to the protocol library
    pub fn library(&self) -> &Arc<ProtocolLibrary> {
        &self.library
    }

    /// Get reference to the configuration
    pub fn config(&self) -> &NooshdarooConfig {
        &self.config
    }
}

/// Nooshdaroo server instance for receiving shape-shifted connections
///
/// # Example
///
/// ```rust,no_run
/// use nooshdaroo::{NooshdarooConfig, NooshdarooServer};
///
/// # fn example() -> Result<(), nooshdaroo::NooshdarooError> {
/// let config = NooshdarooConfig::default();
/// let server = NooshdarooServer::new(config)?;
///
/// // Get protocol by ID
/// let protocol = server.get_protocol(&"https".into());
/// # Ok(())
/// # }
/// ```
pub struct NooshdarooServer {
    config: NooshdarooConfig,
    library: Arc<ProtocolLibrary>,
}

impl NooshdarooServer {
    /// Create a new Nooshdaroo server with the given configuration
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Protocol library cannot be loaded
    /// - Configuration is invalid
    pub fn new(config: NooshdarooConfig) -> Result<Self, NooshdarooError> {
        let library = Arc::new(ProtocolLibrary::load(&config.protocol_dir)?);

        Ok(Self { config, library })
    }

    /// Get protocol metadata by ID
    pub fn get_protocol(&self, id: &ProtocolId) -> Option<&ProtocolMeta> {
        self.library.get(id)
    }

    /// Get reference to the protocol library
    pub fn library(&self) -> &Arc<ProtocolLibrary> {
        &self.library
    }

    /// Get reference to the configuration
    pub fn config(&self) -> &NooshdarooConfig {
        &self.config
    }
}

/// Protocol usage statistics
///
/// Contains metrics about protocol usage, switches, and data transfer.
#[derive(Debug, Clone, Default)]
pub struct ProtocolStats {
    /// Currently active protocol ID
    pub current_protocol: ProtocolId,
    /// Total number of protocol switches
    pub total_switches: u64,
    /// Total bytes transferred
    pub bytes_transferred: u64,
    /// Total packets transferred
    pub packets_transferred: u64,
    /// Time since client started
    pub uptime: std::time::Duration,
    /// Time of last protocol switch
    pub last_switch: Option<std::time::Instant>,
}

/// Nooshdaroo error types
#[derive(Debug, thiserror::Error)]
pub enum NooshdarooError {
    /// Protocol not found in library
    #[error("Protocol not found: {0}")]
    ProtocolNotFound(String),

    /// Invalid configuration
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// Library loading error
    #[error("Library error: {0}")]
    LibraryError(String),

    /// Strategy execution error
    #[error("Strategy error: {0}")]
    StrategyError(String),

    /// I/O error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// PSF parsing error
    #[error("PSF parse error: {0}")]
    PsfParse(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_id_creation() {
        let id = ProtocolId::from("https");
        assert_eq!(id.as_str(), "https");
    }

    #[test]
    fn test_protocol_id_equality() {
        let id1 = ProtocolId::from("ssh");
        let id2 = ProtocolId::from("ssh");
        let id3 = ProtocolId::from("http");

        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
    }
}
