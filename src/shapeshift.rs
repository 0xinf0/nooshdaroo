//! Shape-shifting controller

use super::config::ShapeShiftConfig;
use super::library::ProtocolLibrary;
use super::protocol::ProtocolId;
use super::strategy::StrategyType;
use super::{NooshdarooError, ProtocolStats};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Controller for protocol shape-shifting
pub struct ShapeShiftController {
    config: ShapeShiftConfig,
    library: Arc<ProtocolLibrary>,
    strategy: StrategyType,
    stats: ProtocolStats,
    start_time: Instant,
}

impl ShapeShiftController {
    /// Create new shape-shift controller
    pub fn new(
        config: ShapeShiftConfig,
        library: Arc<ProtocolLibrary>,
    ) -> Result<Self, NooshdarooError> {
        let strategy = config.strategy.clone();

        // Get initial protocol
        let current_protocol = match &strategy {
            StrategyType::TimeBased(s) => s.current_protocol().unwrap_or_default(),
            StrategyType::TrafficBased(s) => s.current_protocol().unwrap_or_default(),
            StrategyType::Adaptive(s) => s.current_protocol_id().unwrap_or_default(),
            StrategyType::Environment(s) => s.current_protocol_id().unwrap_or_default(),
            StrategyType::Fixed(s) => s.current_protocol(),
        };

        Ok(Self {
            config,
            library,
            strategy,
            stats: ProtocolStats {
                current_protocol,
                total_switches: 0,
                bytes_transferred: 0,
                packets_transferred: 0,
                uptime: Duration::ZERO,
                last_switch: None,
            },
            start_time: Instant::now(),
        })
    }

    /// Get current active protocol
    pub fn current_protocol(&self) -> ProtocolId {
        self.stats.current_protocol.clone()
    }

    /// Manually set protocol (overrides strategy)
    pub fn set_protocol(&mut self, protocol_id: ProtocolId) -> Result<(), NooshdarooError> {
        // Verify protocol exists
        if self.library.get(&protocol_id).is_none() {
            return Err(NooshdarooError::ProtocolNotFound(
                protocol_id.to_string(),
            ));
        }

        self.stats.current_protocol = protocol_id;
        self.stats.total_switches += 1;
        self.stats.last_switch = Some(Instant::now());

        Ok(())
    }

    /// Check if rotation should occur
    pub fn should_rotate(&self) -> bool {
        match &self.strategy {
            StrategyType::TimeBased(s) => s.should_rotate(),
            StrategyType::TrafficBased(s) => s.should_rotate(),
            StrategyType::Adaptive(s) => s.should_rotate(),
            StrategyType::Environment(s) => s.should_rotate(),
            StrategyType::Fixed(s) => s.should_rotate(),
        }
    }

    /// Rotate to next protocol
    pub fn rotate(&mut self) -> Result<(), NooshdarooError> {
        let next_protocol = match &mut self.strategy {
            StrategyType::TimeBased(s) => s.next_protocol(),
            StrategyType::TrafficBased(s) => s.next_protocol(),
            StrategyType::Adaptive(s) => s.next_protocol(),
            StrategyType::Environment(s) => s.next_protocol(),
            StrategyType::Fixed(_) => return Ok(()), // No rotation for fixed
        };

        if let Some(protocol) = next_protocol {
            // Verify protocol exists in library
            if self.library.get(&protocol).is_none() {
                return Err(NooshdarooError::ProtocolNotFound(protocol.to_string()));
            }

            self.stats.current_protocol = protocol;
            self.stats.total_switches += 1;
            self.stats.last_switch = Some(Instant::now());
        }

        Ok(())
    }

    /// Record traffic (for traffic-based strategies)
    pub fn record_traffic(&mut self, bytes: u64, packets: u64) {
        self.stats.bytes_transferred += bytes;
        self.stats.packets_transferred += packets;

        if let StrategyType::TrafficBased(ref mut s) = self.strategy {
            s.record_traffic(bytes, packets);
        }
    }

    /// Update suspicion score (for adaptive strategies)
    pub fn update_suspicion(&mut self, score: f64) {
        if let StrategyType::Adaptive(ref mut s) = self.strategy {
            s.update_suspicion(score);
        }
    }

    /// Get statistics
    pub fn stats(&self) -> ProtocolStats {
        let mut stats = self.stats.clone();
        stats.uptime = self.start_time.elapsed();
        stats
    }

    /// Check and auto-rotate if needed
    pub async fn check_and_rotate(&mut self) -> Result<bool, NooshdarooError> {
        if self.should_rotate() {
            self.rotate()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Get protocol metadata for current protocol
    pub fn current_protocol_meta(&self) -> Option<&super::protocol::ProtocolMeta> {
        self.library.get(&self.stats.current_protocol)
    }

    /// Get evasion score for current protocol
    pub fn current_evasion_score(&self) -> f64 {
        self.current_protocol_meta()
            .map(|m| m.evasion_score())
            .unwrap_or(0.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ShapeShiftConfig;
    use crate::strategy::{FixedStrategy, TimeBasedStrategy};
    use std::path::PathBuf;

    #[test]
    fn test_controller_creation() {
        let library = Arc::new(ProtocolLibrary::load(&PathBuf::from("protocols")).unwrap());
        let config = ShapeShiftConfig {
            strategy: StrategyType::Fixed(FixedStrategy::new(ProtocolId::from("https"))),
        };

        let controller = ShapeShiftController::new(config, library);
        assert!(controller.is_ok());
    }

    #[test]
    fn test_manual_protocol_switch() {
        let library = Arc::new(ProtocolLibrary::load(&PathBuf::from("protocols")).unwrap());
        let config = ShapeShiftConfig {
            strategy: StrategyType::Fixed(FixedStrategy::new(ProtocolId::from("https"))),
        };

        let mut controller = ShapeShiftController::new(config, library).unwrap();

        let result = controller.set_protocol(ProtocolId::from("dns"));
        assert!(result.is_ok());
        assert_eq!(controller.current_protocol().as_str(), "dns");
    }

    #[test]
    fn test_traffic_recording() {
        let library = Arc::new(ProtocolLibrary::load(&PathBuf::from("protocols")).unwrap());
        let config = ShapeShiftConfig {
            strategy: StrategyType::Fixed(FixedStrategy::new(ProtocolId::from("https"))),
        };

        let mut controller = ShapeShiftController::new(config, library).unwrap();

        controller.record_traffic(1000, 10);
        let stats = controller.stats();
        assert_eq!(stats.bytes_transferred, 1000);
        assert_eq!(stats.packets_transferred, 10);
    }
}
