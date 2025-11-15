//! Shape-shifting strategies

use super::protocol::ProtocolId;
use chrono::Timelike;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

/// Strategy type for protocol switching
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum StrategyType {
    /// Switch protocols based on time intervals
    TimeBased(TimeBasedStrategy),

    /// Switch based on traffic volume
    TrafficBased(TrafficBasedStrategy),

    /// Adaptive switching based on detection risk
    Adaptive(AdaptiveStrategy),

    /// Environment-aware protocol selection
    Environment(EnvironmentStrategy),

    /// Fixed protocol (no switching)
    Fixed(FixedStrategy),
}

impl Default for StrategyType {
    fn default() -> Self {
        Self::Fixed(FixedStrategy {
            protocol: ProtocolId::from("https"),
        })
    }
}

/// Time-based rotation strategy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeBasedStrategy {
    /// Time interval between switches
    #[serde(with = "humantime_serde")]
    pub interval: Duration,

    /// Sequence of protocols to rotate through
    pub sequence: Vec<ProtocolId>,

    /// Current index in sequence
    #[serde(skip)]
    pub current_index: usize,

    /// Last switch time
    #[serde(skip)]
    pub last_switch: Option<Instant>,
}

impl TimeBasedStrategy {
    pub fn new(interval: Duration, sequence: Vec<ProtocolId>) -> Self {
        Self {
            interval,
            sequence,
            current_index: 0,
            last_switch: None,
        }
    }

    pub fn should_rotate(&self) -> bool {
        if let Some(last) = self.last_switch {
            last.elapsed() >= self.interval
        } else {
            true
        }
    }

    pub fn next_protocol(&mut self) -> Option<ProtocolId> {
        if self.sequence.is_empty() {
            return None;
        }

        self.current_index = (self.current_index + 1) % self.sequence.len();
        self.last_switch = Some(Instant::now());
        Some(self.sequence[self.current_index].clone())
    }

    pub fn current_protocol(&self) -> Option<ProtocolId> {
        self.sequence.get(self.current_index).cloned()
    }
}

/// Traffic-based rotation strategy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficBasedStrategy {
    /// Switch after this many bytes
    pub bytes_threshold: u64,

    /// Switch after this many packets
    pub packet_threshold: u64,

    /// Pool of protocols to choose from
    pub protocol_pool: Vec<ProtocolId>,

    /// Current protocol index
    #[serde(skip)]
    pub current_index: usize,

    /// Bytes transferred since last switch
    #[serde(skip)]
    pub bytes_since_switch: u64,

    /// Packets sent since last switch
    #[serde(skip)]
    pub packets_since_switch: u64,
}

impl TrafficBasedStrategy {
    pub fn new(
        bytes_threshold: u64,
        packet_threshold: u64,
        protocol_pool: Vec<ProtocolId>,
    ) -> Self {
        Self {
            bytes_threshold,
            packet_threshold,
            protocol_pool,
            current_index: 0,
            bytes_since_switch: 0,
            packets_since_switch: 0,
        }
    }

    pub fn record_traffic(&mut self, bytes: u64, packets: u64) {
        self.bytes_since_switch += bytes;
        self.packets_since_switch += packets;
    }

    pub fn should_rotate(&self) -> bool {
        self.bytes_since_switch >= self.bytes_threshold
            || self.packets_since_switch >= self.packet_threshold
    }

    pub fn next_protocol(&mut self) -> Option<ProtocolId> {
        if self.protocol_pool.is_empty() {
            return None;
        }

        self.current_index = (self.current_index + 1) % self.protocol_pool.len();
        self.bytes_since_switch = 0;
        self.packets_since_switch = 0;
        Some(self.protocol_pool[self.current_index].clone())
    }

    pub fn current_protocol(&self) -> Option<ProtocolId> {
        self.protocol_pool.get(self.current_index).cloned()
    }
}

/// Adaptive strategy based on detection risk
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptiveStrategy {
    /// Current suspicion score (0.0 - 1.0)
    pub suspicion_score: f64,

    /// Threshold to trigger protocol switch
    pub switch_threshold: f64,

    /// Protocols to use when suspicion is high
    pub safe_protocols: Vec<ProtocolId>,

    /// Protocols to use when suspicion is low
    pub normal_protocols: Vec<ProtocolId>,

    /// Current protocol
    #[serde(skip)]
    pub current_protocol: Option<ProtocolId>,
}

impl AdaptiveStrategy {
    pub fn new(
        switch_threshold: f64,
        safe_protocols: Vec<ProtocolId>,
        normal_protocols: Vec<ProtocolId>,
    ) -> Self {
        Self {
            suspicion_score: 0.0,
            switch_threshold,
            safe_protocols,
            normal_protocols,
            current_protocol: None,
        }
    }

    pub fn update_suspicion(&mut self, score: f64) {
        self.suspicion_score = score.clamp(0.0, 1.0);
    }

    pub fn should_rotate(&self) -> bool {
        self.suspicion_score >= self.switch_threshold
    }

    pub fn next_protocol(&mut self) -> Option<ProtocolId> {
        let pool = if self.suspicion_score >= self.switch_threshold {
            &self.safe_protocols
        } else {
            &self.normal_protocols
        };

        if pool.is_empty() {
            return None;
        }

        // Choose random protocol from appropriate pool
        use rand::seq::SliceRandom;
        let mut rng = rand::thread_rng();
        let protocol = pool.choose(&mut rng)?.clone();
        self.current_protocol = Some(protocol.clone());
        Some(protocol)
    }

    pub fn current_protocol_id(&self) -> Option<ProtocolId> {
        self.current_protocol.clone()
    }
}

/// Environment-based strategy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentStrategy {
    /// Protocol mapping by hour of day
    pub time_profiles: Vec<TimeProfile>,

    /// Current protocol
    #[serde(skip)]
    pub current_protocol: Option<ProtocolId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeProfile {
    /// Hour of day (0-23)
    pub hour_start: u8,
    pub hour_end: u8,

    /// Protocols to use during this time
    pub protocols: Vec<ProtocolId>,
}

impl EnvironmentStrategy {
    pub fn new(time_profiles: Vec<TimeProfile>) -> Self {
        Self {
            time_profiles,
            current_protocol: None,
        }
    }

    pub fn should_rotate(&self) -> bool {
        // Check if current time requires different protocol
        let current_hour = chrono::Local::now().hour() as u8;

        if let Some(current) = &self.current_protocol {
            // Check if current protocol is still appropriate
            for profile in &self.time_profiles {
                if current_hour >= profile.hour_start && current_hour < profile.hour_end {
                    return !profile.protocols.contains(current);
                }
            }
        }

        true
    }

    pub fn next_protocol(&mut self) -> Option<ProtocolId> {
        let current_hour = chrono::Local::now().hour() as u8;

        // Find appropriate time profile
        for profile in &self.time_profiles {
            if current_hour >= profile.hour_start && current_hour < profile.hour_end {
                if profile.protocols.is_empty() {
                    continue;
                }

                use rand::seq::SliceRandom;
                let mut rng = rand::thread_rng();
                let protocol = profile.protocols.choose(&mut rng)?.clone();
                self.current_protocol = Some(protocol.clone());
                return Some(protocol);
            }
        }

        None
    }

    pub fn current_protocol_id(&self) -> Option<ProtocolId> {
        self.current_protocol.clone()
    }
}

/// Fixed protocol (no rotation)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixedStrategy {
    pub protocol: ProtocolId,
}

impl FixedStrategy {
    pub fn new(protocol: ProtocolId) -> Self {
        Self { protocol }
    }

    pub fn should_rotate(&self) -> bool {
        false
    }

    pub fn current_protocol(&self) -> ProtocolId {
        self.protocol.clone()
    }
}

/// Shape-shifting strategy interface
pub trait ShapeShiftStrategy: Send + Sync {
    /// Check if protocol should be rotated
    fn should_rotate(&self) -> bool;

    /// Get next protocol
    fn next_protocol(&mut self) -> Option<ProtocolId>;

    /// Get current protocol
    fn current_protocol(&self) -> Option<ProtocolId>;

    /// Record traffic for traffic-based strategies
    fn record_traffic(&mut self, _bytes: u64, _packets: u64) {}

    /// Update suspicion score for adaptive strategies
    fn update_suspicion(&mut self, _score: f64) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time_based_strategy() {
        let mut strategy = TimeBasedStrategy::new(
            Duration::from_secs(60),
            vec![ProtocolId::from("https"), ProtocolId::from("dns")],
        );

        assert!(strategy.should_rotate());
        let proto1 = strategy.next_protocol();
        assert!(proto1.is_some());

        // Should not rotate immediately
        assert!(!strategy.should_rotate());
    }

    #[test]
    fn test_traffic_based_strategy() {
        let mut strategy = TrafficBasedStrategy::new(
            1000,
            10,
            vec![ProtocolId::from("https"), ProtocolId::from("quic")],
        );

        assert!(!strategy.should_rotate());

        strategy.record_traffic(500, 5);
        assert!(!strategy.should_rotate());

        strategy.record_traffic(600, 5);
        assert!(strategy.should_rotate());

        let proto = strategy.next_protocol();
        assert!(proto.is_some());
        assert_eq!(strategy.bytes_since_switch, 0);
    }

    #[test]
    fn test_adaptive_strategy() {
        let mut strategy = AdaptiveStrategy::new(
            0.7,
            vec![ProtocolId::from("https")],
            vec![ProtocolId::from("quic")],
        );

        assert!(!strategy.should_rotate());

        strategy.update_suspicion(0.8);
        assert!(strategy.should_rotate());
    }
}
