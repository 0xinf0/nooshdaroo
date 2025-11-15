//! Netflow analysis evasion through multi-port and protocol mixing
//!
//! This module implements advanced strategies to defeat netflow analysis by:
//! - Listening on protocol-appropriate ports (HTTPS:443, DNS:53, SSH:22, etc.)
//! - Testing multiple connection paths and selecting the best
//! - Mixing 2+ protocols on successful paths
//! - Using DNS on port 53 as fallback
//! - Randomizing protocol usage patterns to avoid statistical detection

use crate::protocol::{ProtocolId, ProtocolMeta, Transport};
use crate::library::ProtocolLibrary;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Connection path test result
#[derive(Debug, Clone)]
pub struct PathTestResult {
    /// Server address and port tested
    pub addr: SocketAddr,
    /// Protocol used for this path
    pub protocol: ProtocolId,
    /// Connection latency
    pub latency: Duration,
    /// Whether connection succeeded
    pub success: bool,
    /// Packet loss percentage (if measurable)
    pub packet_loss: f64,
    /// Throughput estimate (bytes/sec)
    pub throughput: u64,
    /// Detection risk score (0.0-1.0, lower is better)
    pub detection_risk: f64,
}

impl PathTestResult {
    /// Calculate overall path score (higher is better)
    pub fn score(&self) -> f64 {
        if !self.success {
            return 0.0;
        }

        let latency_score = 1.0 / (1.0 + self.latency.as_millis() as f64 / 100.0);
        let loss_score = 1.0 - self.packet_loss;
        let throughput_score = (self.throughput as f64 / 1_000_000.0).min(1.0); // Normalize to 1 Mbps
        let stealth_score = 1.0 - self.detection_risk;

        // Weighted combination: stealth is most important, then reliability, then performance
        stealth_score * 0.5 + loss_score * 0.2 + latency_score * 0.2 + throughput_score * 0.1
    }
}

/// Multi-port server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiPortConfig {
    /// Base address to bind (e.g., "0.0.0.0")
    pub bind_addr: String,

    /// Port range to use (e.g., 1-65535)
    pub port_range: (u16, u16),

    /// Maximum number of ports to open
    pub max_ports: usize,

    /// Whether to bind to protocol-standard ports
    pub use_standard_ports: bool,

    /// Whether to bind to random high ports as well
    pub use_random_ports: bool,

    /// Protocol-to-port mappings
    pub protocol_ports: HashMap<String, Vec<u16>>,
}

impl Default for MultiPortConfig {
    fn default() -> Self {
        let mut protocol_ports = HashMap::new();

        // Common protocol ports for realistic traffic patterns
        protocol_ports.insert("https".to_string(), vec![443, 8443]);
        protocol_ports.insert("http".to_string(), vec![80, 8080, 8000]);
        protocol_ports.insert("ssh".to_string(), vec![22, 2222]);
        protocol_ports.insert("dns".to_string(), vec![53]); // DNS fallback
        protocol_ports.insert("smtp".to_string(), vec![25, 587, 465]);
        protocol_ports.insert("imap".to_string(), vec![143, 993]);
        protocol_ports.insert("pop3".to_string(), vec![110, 995]);
        protocol_ports.insert("ftp".to_string(), vec![21, 990]);
        protocol_ports.insert("openvpn".to_string(), vec![1194]);
        protocol_ports.insert("wireguard".to_string(), vec![51820]);
        protocol_ports.insert("quic".to_string(), vec![443, 8443]);
        protocol_ports.insert("websocket".to_string(), vec![80, 443, 8080]);

        Self {
            bind_addr: "0.0.0.0".to_string(),
            port_range: (1, 65535),
            max_ports: 20,
            use_standard_ports: true,
            use_random_ports: true,
            protocol_ports,
        }
    }
}

/// Protocol mixing strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MixingStrategy {
    /// Use single best protocol
    Single,
    /// Mix 2 best protocols with random selection
    DualRandom,
    /// Mix 3+ protocols based on time of day
    MultiTemporal,
    /// Mix based on traffic volume thresholds
    VolumeAdaptive,
    /// Mix based on connection success patterns
    AdaptiveLearning,
}

/// Protocol mixer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolMixer {
    /// Mixing strategy
    pub strategy: MixingStrategy,

    /// Primary protocol (highest score)
    pub primary: Option<ProtocolId>,

    /// Secondary protocol (second highest score)
    pub secondary: Option<ProtocolId>,

    /// Tertiary protocol (third highest score)
    pub tertiary: Option<ProtocolId>,

    /// Fallback protocol (DNS on port 53)
    pub fallback: ProtocolId,

    /// Mixing ratio (primary:secondary) e.g., 0.7 means 70% primary, 30% secondary
    pub mixing_ratio: f64,

    /// Minimum connections before protocol rotation
    pub rotation_threshold: u64,

    /// Current connection count
    pub connection_count: u64,
}

impl Default for ProtocolMixer {
    fn default() -> Self {
        Self {
            strategy: MixingStrategy::DualRandom,
            primary: None,
            secondary: None,
            tertiary: None,
            fallback: ProtocolId::from("dns"),
            mixing_ratio: 0.7,
            rotation_threshold: 100,
            connection_count: 0,
        }
    }
}

impl ProtocolMixer {
    /// Select next protocol based on mixing strategy
    pub fn select_protocol(&mut self) -> ProtocolId {
        self.connection_count += 1;

        match self.strategy {
            MixingStrategy::Single => {
                self.primary.clone().unwrap_or_else(|| self.fallback.clone())
            }
            MixingStrategy::DualRandom => {
                if self.primary.is_none() {
                    return self.fallback.clone();
                }

                // Mix primary and secondary based on ratio
                let rand_val: f64 = rand::random();
                if rand_val < self.mixing_ratio {
                    self.primary.clone().unwrap()
                } else {
                    self.secondary.clone().unwrap_or_else(|| self.primary.clone().unwrap())
                }
            }
            MixingStrategy::MultiTemporal => {
                // Use different protocols based on time of day
                use chrono::Timelike;
                let hour = chrono::Local::now().hour();
                match hour {
                    0..=6 => self.tertiary.clone().or(self.secondary.clone()).unwrap_or_else(|| self.fallback.clone()),
                    7..=9 => self.primary.clone().unwrap_or_else(|| self.fallback.clone()),
                    10..=17 => {
                        if rand::random::<f64>() < 0.5 {
                            self.primary.clone().unwrap_or_else(|| self.fallback.clone())
                        } else {
                            self.secondary.clone().unwrap_or_else(|| self.fallback.clone())
                        }
                    }
                    18..=22 => self.secondary.clone().unwrap_or_else(|| self.fallback.clone()),
                    _ => self.fallback.clone(),
                }
            }
            MixingStrategy::VolumeAdaptive => {
                // Switch protocols every N connections
                let cycle = self.connection_count % self.rotation_threshold;
                if cycle < self.rotation_threshold * 7 / 10 {
                    self.primary.clone().unwrap_or_else(|| self.fallback.clone())
                } else if cycle < self.rotation_threshold * 9 / 10 {
                    self.secondary.clone().unwrap_or_else(|| self.fallback.clone())
                } else {
                    self.tertiary.clone().unwrap_or_else(|| self.fallback.clone())
                }
            }
            MixingStrategy::AdaptiveLearning => {
                // Simple learning: adjust ratio based on success patterns
                // This would be enhanced with actual success tracking
                self.select_protocol_by_ratio()
            }
        }
    }

    fn select_protocol_by_ratio(&self) -> ProtocolId {
        let rand_val: f64 = rand::random();
        if rand_val < self.mixing_ratio {
            self.primary.clone().unwrap_or_else(|| self.fallback.clone())
        } else {
            self.secondary.clone().unwrap_or_else(|| self.fallback.clone())
        }
    }
}

/// Path tester for multi-protocol connections
pub struct PathTester {
    /// Protocol library
    library: Arc<ProtocolLibrary>,

    /// Test timeout
    timeout_ms: u64,

    /// Number of test iterations per path
    test_iterations: usize,
}

impl PathTester {
    pub fn new(library: Arc<ProtocolLibrary>) -> Self {
        Self {
            library,
            timeout_ms: 5000,
            test_iterations: 3,
        }
    }

    /// Test connection to a specific server:port with protocol
    pub async fn test_path(
        &self,
        addr: SocketAddr,
        protocol: &ProtocolMeta,
    ) -> PathTestResult {
        let mut latencies = Vec::new();
        let mut successes = 0;

        for _ in 0..self.test_iterations {
            let start = Instant::now();

            match timeout(
                Duration::from_millis(self.timeout_ms),
                TcpStream::connect(addr)
            ).await {
                Ok(Ok(_stream)) => {
                    latencies.push(start.elapsed());
                    successes += 1;
                }
                _ => {}
            }

            // Small delay between tests
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let success = successes > 0;
        let avg_latency = if latencies.is_empty() {
            Duration::from_secs(999)
        } else {
            latencies.iter().sum::<Duration>() / latencies.len() as u32
        };

        let packet_loss = 1.0 - (successes as f64 / self.test_iterations as f64);

        // Calculate detection risk based on protocol and port
        let detection_risk = self.calculate_detection_risk(addr.port(), protocol);

        PathTestResult {
            addr,
            protocol: protocol.id.clone(),
            latency: avg_latency,
            success,
            packet_loss,
            throughput: if success { 1_000_000 } else { 0 }, // Placeholder
            detection_risk,
        }
    }

    /// Test multiple paths and return results sorted by score
    pub async fn test_all_paths(
        &self,
        server_host: &str,
        config: &MultiPortConfig,
    ) -> Vec<PathTestResult> {
        let mut results = Vec::new();

        // Test standard protocol ports
        if config.use_standard_ports {
            for (proto_name, ports) in &config.protocol_ports {
                if let Some(protocol) = self.library.get(&ProtocolId::from(proto_name.as_str())) {
                    for &port in ports {
                        if let Ok(addr) = format!("{}:{}", server_host, port).parse::<SocketAddr>() {
                            let result = self.test_path(addr, protocol).await;
                            results.push(result);
                        }
                    }
                }
            }
        }

        // Sort by score (best first)
        results.sort_by(|a, b| b.score().partial_cmp(&a.score()).unwrap());
        results
    }

    /// Calculate detection risk for a protocol on a given port
    fn calculate_detection_risk(&self, port: u16, protocol: &ProtocolMeta) -> f64 {
        // Lower risk if protocol is on its standard port
        let port_match_bonus = if protocol.default_port == port {
            0.3 // 30% risk reduction for standard port
        } else {
            0.0
        };

        // Base risk from protocol evasion score
        let base_risk = 1.0 - protocol.evasion_score();

        // Port-specific risk factors
        let port_risk = match port {
            53 => 0.1,   // DNS - very common
            80 => 0.1,   // HTTP - very common
            443 => 0.1,  // HTTPS - very common
            22 => 0.2,   // SSH - common but monitored
            25 | 587 | 465 => 0.15, // Email
            1024..=49151 => 0.3, // Registered ports
            _ => 0.5,    // Other ports
        };

        // Combine factors
        ((base_risk + port_risk) / 2.0 - port_match_bonus).max(0.0).min(1.0)
    }
}

/// Build optimal protocol mixer from test results
pub fn build_mixer_from_results(
    results: &[PathTestResult],
    strategy: MixingStrategy,
) -> ProtocolMixer {
    let mut mixer = ProtocolMixer {
        strategy,
        ..Default::default()
    };

    // Get top 3 successful protocols
    let successful: Vec<_> = results.iter().filter(|r| r.success).collect();

    if !successful.is_empty() {
        mixer.primary = Some(successful[0].protocol.clone());
    }
    if successful.len() > 1 {
        mixer.secondary = Some(successful[1].protocol.clone());
    }
    if successful.len() > 2 {
        mixer.tertiary = Some(successful[2].protocol.clone());
    }

    // Calculate optimal mixing ratio based on score difference
    if successful.len() >= 2 {
        let score_diff = successful[0].score() - successful[1].score();
        // If scores are close, mix more evenly
        mixer.mixing_ratio = 0.5 + (score_diff * 0.5).min(0.4);
    }

    mixer
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_result_scoring() {
        let result = PathTestResult {
            addr: "127.0.0.1:443".parse().unwrap(),
            protocol: ProtocolId::from("https"),
            latency: Duration::from_millis(50),
            success: true,
            packet_loss: 0.0,
            throughput: 1_000_000,
            detection_risk: 0.2,
        };

        let score = result.score();
        assert!(score > 0.5);
        assert!(score <= 1.0);
    }

    #[test]
    fn test_mixer_selection() {
        let mut mixer = ProtocolMixer {
            strategy: MixingStrategy::Single,
            primary: Some(ProtocolId::from("https")),
            secondary: Some(ProtocolId::from("ssh")),
            fallback: ProtocolId::from("dns"),
            ..Default::default()
        };

        let selected = mixer.select_protocol();
        assert_eq!(selected.as_str(), "https");
    }

    #[test]
    fn test_dual_random_mixing() {
        let mut mixer = ProtocolMixer {
            strategy: MixingStrategy::DualRandom,
            primary: Some(ProtocolId::from("https")),
            secondary: Some(ProtocolId::from("ssh")),
            mixing_ratio: 0.7,
            ..Default::default()
        };

        let mut https_count = 0;
        let mut ssh_count = 0;

        for _ in 0..1000 {
            let proto = mixer.select_protocol();
            if proto.as_str() == "https" {
                https_count += 1;
            } else if proto.as_str() == "ssh" {
                ssh_count += 1;
            }
        }

        // Should be roughly 70/30 split (with some tolerance)
        let ratio = https_count as f64 / (https_count + ssh_count) as f64;
        assert!(ratio > 0.6 && ratio < 0.8);
    }
}
