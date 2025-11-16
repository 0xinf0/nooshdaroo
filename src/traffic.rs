//! Traffic shaping and timing emulation

use super::config::{DistributionType, TrafficShapingConfig};
use rand::distributions::Distribution;
use rand::rngs::StdRng;
use rand::SeedableRng;
use rand_distr::{Exp, Normal, Uniform};
use std::time::Duration;

/// Traffic shaper for realistic traffic patterns
pub struct TrafficShaper {
    config: TrafficShapingConfig,
    rng: StdRng,
}

impl TrafficShaper {
    /// Create new traffic shaper
    pub fn new(config: TrafficShapingConfig) -> Self {
        Self {
            config,
            rng: StdRng::from_entropy(),
        }
    }

    /// Generate packet size based on configured distribution
    pub fn generate_packet_size(&mut self) -> usize {
        if !self.config.enabled {
            return self.config.mean_packet_size;
        }

        let size = match self.config.packet_size_distribution {
            DistributionType::Normal => {
                let normal = Normal::new(
                    self.config.mean_packet_size as f64,
                    self.config.stddev_packet_size as f64,
                )
                .unwrap_or_else(|_| Normal::new(1400.0, 200.0).unwrap());
                normal.sample(&mut self.rng).max(64.0).min(1500.0) as usize
            }
            DistributionType::Uniform => {
                let min = self.config.mean_packet_size.saturating_sub(self.config.stddev_packet_size);
                let max = self.config.mean_packet_size.saturating_add(self.config.stddev_packet_size);
                let uniform = Uniform::new(min.max(64), max.min(1500));
                uniform.sample(&mut self.rng)
            }
            DistributionType::Exponential => {
                let rate = 1.0 / self.config.mean_packet_size as f64;
                let exp = Exp::new(rate).unwrap_or_else(|_| Exp::new(1.0 / 1400.0).unwrap());
                exp.sample(&mut self.rng).max(64.0).min(1500.0) as usize
            }
        };

        size
    }

    /// Generate inter-packet delay
    pub fn generate_delay(&mut self) -> Duration {
        if !self.config.enabled {
            return Duration::from_micros(self.config.mean_delay);
        }

        let delay_us = {
            let normal = Normal::new(
                self.config.mean_delay as f64,
                self.config.stddev_delay as f64,
            )
            .unwrap_or_else(|_| Normal::new(50.0, 20.0).unwrap());
            normal.sample(&mut self.rng).max(0.0) as u64
        };

        Duration::from_micros(delay_us)
    }

    /// Check if next packet should be part of a burst
    pub fn should_burst(&mut self) -> bool {
        if !self.config.enable_bursts {
            return false;
        }

        use rand::Rng;
        self.rng.gen_bool(self.config.burst_probability)
    }

    /// Get burst size
    pub fn burst_size(&self) -> usize {
        self.config.burst_size
    }

    /// Pad data to target size
    pub fn pad_to_size(&self, mut data: Vec<u8>, target_size: usize) -> Vec<u8> {
        if data.len() < target_size {
            data.resize(target_size, 0);
        }
        data
    }

    /// Split data into chunks with realistic sizes
    pub fn chunk_data(&mut self, data: &[u8]) -> Vec<Vec<u8>> {
        let mut chunks = Vec::new();
        let mut remaining = data;

        while !remaining.is_empty() {
            let chunk_size = self.generate_packet_size().min(remaining.len());
            chunks.push(remaining[..chunk_size].to_vec());
            remaining = &remaining[chunk_size..];
        }

        chunks
    }
}

/// Timing pattern emulator
pub struct TimingEmulator {
    protocol_name: String,
    patterns: Vec<TimingPattern>,
}

#[derive(Debug, Clone)]
pub struct TimingPattern {
    pub name: String,
    pub delays: Vec<Duration>,
    pub repetitions: usize,
}

impl TimingEmulator {
    /// Create timing emulator for specific protocol
    pub fn for_protocol(protocol: &str) -> Self {
        let patterns = match protocol {
            "https" => Self::https_patterns(),
            "dns" => Self::dns_patterns(),
            "ssh" => Self::ssh_patterns(),
            "quic" => Self::quic_patterns(),
            _ => Vec::new(),
        };

        Self {
            protocol_name: protocol.to_string(),
            patterns,
        }
    }

    /// HTTPS timing patterns
    fn https_patterns() -> Vec<TimingPattern> {
        vec![
            TimingPattern {
                name: "TLS handshake".to_string(),
                delays: vec![
                    Duration::from_millis(5),   // ClientHello
                    Duration::from_millis(20),  // ServerHello + certs
                    Duration::from_millis(5),   // ClientKeyExchange
                    Duration::from_millis(5),   // Finished
                ],
                repetitions: 1,
            },
            TimingPattern {
                name: "HTTP request-response".to_string(),
                delays: vec![
                    Duration::from_millis(2),   // Request
                    Duration::from_millis(50),  // Server processing
                    Duration::from_millis(10),  // Response chunks
                ],
                repetitions: 10,
            },
        ]
    }

    /// DNS timing patterns
    fn dns_patterns() -> Vec<TimingPattern> {
        vec![TimingPattern {
            name: "DNS query-response".to_string(),
            delays: vec![
                Duration::from_millis(1),  // Query
                Duration::from_millis(15), // Response
            ],
            repetitions: 1,
        }]
    }

    /// SSH timing patterns
    fn ssh_patterns() -> Vec<TimingPattern> {
        vec![
            TimingPattern {
                name: "SSH handshake".to_string(),
                delays: vec![
                    Duration::from_millis(5),
                    Duration::from_millis(10),
                    Duration::from_millis(5),
                    Duration::from_millis(5),
                ],
                repetitions: 1,
            },
            TimingPattern {
                name: "SSH keepalive".to_string(),
                delays: vec![Duration::from_secs(30)],
                repetitions: 100,
            },
        ]
    }

    /// QUIC timing patterns
    fn quic_patterns() -> Vec<TimingPattern> {
        vec![TimingPattern {
            name: "QUIC 0-RTT".to_string(),
            delays: vec![
                Duration::from_millis(0), // 0-RTT data
                Duration::from_millis(20),
            ],
            repetitions: 1,
        }]
    }

    /// Get timing pattern iterator
    pub fn patterns(&self) -> impl Iterator<Item = &TimingPattern> {
        self.patterns.iter()
    }
}

/// Bandwidth limiter
pub struct BandwidthLimiter {
    max_bytes_per_sec: u64,
    tokens: f64,
    last_update: std::time::Instant,
}

impl BandwidthLimiter {
    /// Create new bandwidth limiter
    pub fn new(max_bytes_per_sec: u64) -> Self {
        Self {
            max_bytes_per_sec,
            tokens: max_bytes_per_sec as f64,
            last_update: std::time::Instant::now(),
        }
    }

    /// Check if bytes can be sent (token bucket algorithm)
    pub fn allow(&mut self, bytes: u64) -> bool {
        self.refill();

        if self.tokens >= bytes as f64 {
            self.tokens -= bytes as f64;
            true
        } else {
            false
        }
    }

    /// Wait until bytes can be sent
    pub async fn wait_for(&mut self, bytes: u64) {
        while !self.allow(bytes) {
            tokio::time::sleep(Duration::from_millis(10)).await;
            self.refill();
        }
    }

    /// Refill token bucket
    fn refill(&mut self) {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.max_bytes_per_sec as f64)
            .min(self.max_bytes_per_sec as f64);
        self.last_update = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_size_generation() {
        let config = TrafficShapingConfig {
            enabled: true,
            packet_size_distribution: DistributionType::Normal,
            mean_packet_size: 1400,
            stddev_packet_size: 200,
            ..Default::default()
        };

        let mut shaper = TrafficShaper::new(config);

        for _ in 0..100 {
            let size = shaper.generate_packet_size();
            assert!(size >= 64 && size <= 1500);
        }
    }

    #[test]
    fn test_delay_generation() {
        let config = TrafficShapingConfig {
            enabled: true,
            mean_delay: 50,
            stddev_delay: 20,
            ..Default::default()
        };

        let mut shaper = TrafficShaper::new(config);

        for _ in 0..100 {
            let delay = shaper.generate_delay();
            assert!(delay.as_micros() < 1000000); // Less than 1 second
        }
    }

    #[test]
    fn test_burst_detection() {
        let config = TrafficShapingConfig {
            enable_bursts: true,
            burst_probability: 0.5,
            burst_size: 5,
            ..Default::default()
        };

        let mut shaper = TrafficShaper::new(config);
        let mut burst_count = 0;

        for _ in 0..1000 {
            if shaper.should_burst() {
                burst_count += 1;
            }
        }

        // Should be roughly 50% with some variance
        assert!(burst_count > 400 && burst_count < 600);
    }

    #[test]
    fn test_data_chunking() {
        let config = TrafficShapingConfig::default();
        let mut shaper = TrafficShaper::new(config);

        let data = vec![0u8; 5000];
        let chunks = shaper.chunk_data(&data);

        assert!(!chunks.is_empty());
        let total_size: usize = chunks.iter().map(|c| c.len()).sum();
        assert_eq!(total_size, 5000);
    }

    #[test]
    fn test_timing_emulator() {
        let emulator = TimingEmulator::for_protocol("https");
        assert_eq!(emulator.protocol_name, "https");
        assert!(!emulator.patterns.is_empty());
    }

    #[tokio::test]
    async fn test_bandwidth_limiter() {
        let mut limiter = BandwidthLimiter::new(1000); // 1KB/s

        // Should allow small amount immediately
        assert!(limiter.allow(100));

        // Should allow waiting for more
        limiter.wait_for(100).await;
        assert!(true); // If we get here, wait worked
    }
}
