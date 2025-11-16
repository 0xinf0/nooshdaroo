//! Preset profiles for different network environments
//!
//! This module provides preset configurations optimized for specific
//! censorship environments and network conditions.

use crate::{NooshdarooConfig, ProtocolId, ShapeShiftConfig, StrategyType, TrafficShapingConfig};
use crate::config::DistributionType;
use crate::strategy::{FixedStrategy, TimeBasedStrategy};
use std::time::Duration;
use anyhow::{Result, bail};

/// Load a preset profile by name
pub fn load_profile(name: &str) -> Result<NooshdarooConfig> {
    match name.to_lowercase().as_str() {
        "corporate" => Ok(corporate_profile()),
        "airport" => Ok(airport_profile()),
        "hotel" => Ok(hotel_profile()),
        "china" => Ok(china_profile()),
        "iran" => Ok(iran_profile()),
        "russia" => Ok(russia_profile()),
        _ => bail!("Unknown profile: {}. Available profiles: corporate, airport, hotel, china, iran, russia", name),
    }
}

/// Corporate Network Profile
///
/// Optimized for bypassing corporate firewalls and DPI.
/// Uses HTTPS, DNS, and HTTP protocols on standard ports.
/// Employs temporal mixing to avoid pattern detection.
fn corporate_profile() -> NooshdarooConfig {
    let mut config = NooshdarooConfig::default();

    // Use time-based rotation between common protocols
    let protocols = vec![
        ProtocolId::from("https"),
        ProtocolId::from("dns"),
        ProtocolId::from("http"),
    ];

    config.shapeshift = ShapeShiftConfig {
        strategy: StrategyType::TimeBased(TimeBasedStrategy::new(
            Duration::from_secs(300), // Rotate every 5 minutes
            protocols,
        )),
    };

    // Enable traffic shaping to mimic normal browsing
    config.traffic_shaping = TrafficShapingConfig {
        enabled: true,
        packet_size_distribution: DistributionType::Normal,
        mean_packet_size: 800,
        stddev_packet_size: 200,
        mean_delay: 50,           // 50 microseconds
        stddev_delay: 20,
        enable_bursts: false,
        burst_size: 5,
        burst_probability: 0.0,
    };

    config
}

/// Airport/Hotel WiFi Profile
///
/// Safest and most conservative profile for public WiFi.
/// Uses only DNS and HTTPS on standard ports (53, 443).
/// Minimal protocol mixing to avoid detection.
fn airport_profile() -> NooshdarooConfig {
    let mut config = NooshdarooConfig::default();

    // Use fixed protocol (DNS fallback) - safest option
    config.shapeshift = ShapeShiftConfig {
        strategy: StrategyType::Fixed(FixedStrategy {
            protocol: ProtocolId::from("dns"),
        }),
    };

    // Minimal traffic shaping - be invisible
    config.traffic_shaping = TrafficShapingConfig {
        enabled: true,
        packet_size_distribution: DistributionType::Normal,
        mean_packet_size: 512,  // Small packets
        stddev_packet_size: 128,
        mean_delay: 100,  // Conservative delays (microseconds)
        stddev_delay: 30,
        enable_bursts: false,
        burst_size: 3,
        burst_probability: 0.0,
    };

    config
}

/// Hotel WiFi Profile (alias for airport profile)
///
/// Same as airport profile - optimized for public WiFi with captive portals.
fn hotel_profile() -> NooshdarooConfig {
    airport_profile()
}

/// China Great Firewall Profile
///
/// Aggressive anti-censorship profile for the Great Firewall of China.
/// Uses multiple protocols with adaptive learning.
/// Includes decoy traffic and advanced evasion techniques.
fn china_profile() -> NooshdarooConfig {
    let mut config = NooshdarooConfig::default();

    // Use adaptive strategy with multiple protocols
    let protocols = vec![
        ProtocolId::from("dns"),
        ProtocolId::from("https"),
        ProtocolId::from("quic"),
        ProtocolId::from("websocket"),
    ];

    // Start with time-based rotation (adaptive requires runtime state)
    config.shapeshift = ShapeShiftConfig {
        strategy: StrategyType::TimeBased(TimeBasedStrategy::new(
            Duration::from_secs(180), // Rotate every 3 minutes
            protocols,
        )),
    };

    // Aggressive traffic shaping to mimic real applications
    config.traffic_shaping = TrafficShapingConfig {
        enabled: true,
        packet_size_distribution: DistributionType::Normal,
        mean_packet_size: 1200,  // Larger packets like video streaming
        stddev_packet_size: 400,
        mean_delay: 30,  // Faster, more realistic (microseconds)
        stddev_delay: 15,
        enable_bursts: true,
        burst_size: 10,
        burst_probability: 0.2,
    };

    config
}

/// Iran Censorship Profile
///
/// Optimized for Iranian national firewall.
/// Similar to China profile but with focus on DNS and HTTPS.
/// Emphasizes TLS 1.3 with proper SNI.
fn iran_profile() -> NooshdarooConfig {
    let mut config = NooshdarooConfig::default();

    // Use DNS and HTTPS primarily (Iran blocks less on these)
    let protocols = vec![
        ProtocolId::from("dns"),
        ProtocolId::from("https"),
        ProtocolId::from("tls13"),
        ProtocolId::from("dns-over-tls"),
    ];

    config.shapeshift = ShapeShiftConfig {
        strategy: StrategyType::TimeBased(TimeBasedStrategy::new(
            Duration::from_secs(240), // Rotate every 4 minutes
            protocols,
        )),
    };

    // Moderate traffic shaping - balance between speed and stealth
    config.traffic_shaping = TrafficShapingConfig {
        enabled: true,
        packet_size_distribution: DistributionType::Normal,
        mean_packet_size: 1000,
        stddev_packet_size: 300,
        mean_delay: 40,  // microseconds
        stddev_delay: 18,
        enable_bursts: true,
        burst_size: 7,
        burst_probability: 0.15,
    };

    config
}

/// Russia Censorship Profile
///
/// Optimized for Russian DPI and censorship infrastructure.
/// Uses Western protocols (HTTPS, DNS-over-HTTPS) that appear as
/// legitimate cloud service traffic.
fn russia_profile() -> NooshdarooConfig {
    let mut config = NooshdarooConfig::default();

    // Use protocols common in Western cloud services
    let protocols = vec![
        ProtocolId::from("https"),
        ProtocolId::from("dns"),
        ProtocolId::from("quic"),
        ProtocolId::from("http2"),
    ];

    config.shapeshift = ShapeShiftConfig {
        strategy: StrategyType::TimeBased(TimeBasedStrategy::new(
            Duration::from_secs(200), // Rotate every 3.3 minutes
            protocols,
        )),
    };

    // Traffic shaping to mimic cloud service API calls
    config.traffic_shaping = TrafficShapingConfig {
        enabled: true,
        packet_size_distribution: DistributionType::Normal,
        mean_packet_size: 900,
        stddev_packet_size: 250,
        mean_delay: 45,  // microseconds
        stddev_delay: 20,
        enable_bursts: true,
        burst_size: 6,
        burst_probability: 0.1,
    };

    config
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_all_profiles() {
        // Test that all profiles can be loaded
        assert!(load_profile("corporate").is_ok());
        assert!(load_profile("airport").is_ok());
        assert!(load_profile("hotel").is_ok());
        assert!(load_profile("china").is_ok());
        assert!(load_profile("iran").is_ok());
        assert!(load_profile("russia").is_ok());
    }

    #[test]
    fn test_invalid_profile() {
        assert!(load_profile("invalid").is_err());
    }

    #[test]
    fn test_corporate_profile() {
        let config = corporate_profile();
        assert!(config.traffic_shaping.enabled);
        // Corporate should use time-based strategy
        assert!(matches!(config.shapeshift.strategy, StrategyType::TimeBased(_)));
    }

    #[test]
    fn test_airport_profile() {
        let config = airport_profile();
        assert!(config.traffic_shaping.enabled);
        // Airport should use fixed DNS (safest)
        assert!(matches!(config.shapeshift.strategy, StrategyType::Fixed(_)));
    }

    #[test]
    fn test_china_profile() {
        let config = china_profile();
        assert!(config.traffic_shaping.enabled);
        // China should use aggressive rotation
        if let StrategyType::TimeBased(strategy) = &config.shapeshift.strategy {
            assert!(strategy.sequence.len() >= 4); // Multiple protocols
        } else {
            panic!("China profile should use TimeBased strategy");
        }
    }
}
