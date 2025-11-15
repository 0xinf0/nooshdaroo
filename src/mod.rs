//! Nooshdaroo: Protocol Shape-Shifting SOCKS Proxy
//!
//! Nooshdaroo extends Proteus with dynamic protocol emulation and shape-shifting
//! capabilities, allowing encrypted SOCKS proxy traffic to masquerade as any of
//! 100+ defined network protocols.
//!
//! ## Features
//! - Multiple proxy types: SOCKS5, HTTP CONNECT, Transparent
//! - Socat-like bidirectional relay
//! - Mobile-friendly API (iOS/Android FFI bindings)
//! - Protocol shape-shifting with 5 strategies
//! - Traffic shaping and timing emulation

pub mod config;
pub mod library;
pub mod mobile;
pub mod protocol;
pub mod proxy;
pub mod shapeshift;
pub mod socat;
pub mod strategy;
pub mod traffic;

pub use config::{NooshdarooConfig, ShapeShiftConfig, TrafficShapingConfig};
pub use library::ProtocolLibrary;
pub use mobile::{MobileConfigBuilder, NooshdarooMobileConfig};
pub use protocol::{DetectionScore, ProtocolId, ProtocolMeta, Transport};
pub use proxy::{HttpProxyServer, ProxyType, UnifiedProxyListener};
pub use shapeshift::ShapeShiftController;
pub use socat::{RelayMode, SocatBuilder, SocatRelay};
pub use strategy::{ShapeShiftStrategy, StrategyType};

use std::sync::Arc;
use tokio::sync::RwLock;

/// Nooshdaroo client instance
pub struct NooshdarooClient {
    config: NooshdarooConfig,
    library: Arc<ProtocolLibrary>,
    controller: Arc<RwLock<ShapeShiftController>>,
}

impl NooshdarooClient {
    /// Create a new Nooshdaroo client
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

    /// Get current active protocol
    pub async fn current_protocol(&self) -> ProtocolId {
        self.controller.read().await.current_protocol()
    }

    /// Manually set protocol (overrides strategy)
    pub async fn set_protocol(&self, protocol_id: ProtocolId) -> Result<(), NooshdarooError> {
        self.controller.write().await.set_protocol(protocol_id)
    }

    /// Get protocol statistics
    pub async fn stats(&self) -> ProtocolStats {
        self.controller.read().await.stats()
    }

    /// Trigger protocol rotation
    pub async fn rotate(&self) -> Result<(), NooshdarooError> {
        self.controller.write().await.rotate()
    }
}

/// Nooshdaroo server instance
pub struct NooshdarooServer {
    config: NooshdarooConfig,
    library: Arc<ProtocolLibrary>,
}

impl NooshdarooServer {
    /// Create a new Nooshdaroo server
    pub fn new(config: NooshdarooConfig) -> Result<Self, NooshdarooError> {
        let library = Arc::new(ProtocolLibrary::load(&config.protocol_dir)?);

        Ok(Self { config, library })
    }

    /// Get protocol by ID
    pub fn get_protocol(&self, id: &ProtocolId) -> Option<&ProtocolMeta> {
        self.library.get(id)
    }
}

/// Protocol usage statistics
#[derive(Debug, Clone, Default)]
pub struct ProtocolStats {
    pub current_protocol: ProtocolId,
    pub total_switches: u64,
    pub bytes_transferred: u64,
    pub packets_transferred: u64,
    pub uptime: std::time::Duration,
    pub last_switch: Option<std::time::Instant>,
}

/// Nooshdaroo error types
#[derive(Debug, thiserror::Error)]
pub enum NooshdarooError {
    #[error("Protocol not found: {0}")]
    ProtocolNotFound(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("Library error: {0}")]
    LibraryError(String),

    #[error("Strategy error: {0}")]
    StrategyError(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

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
}
