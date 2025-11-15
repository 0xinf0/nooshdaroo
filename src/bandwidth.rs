//! Adaptive bandwidth optimization and quality management
//!
//! This module implements intelligent bandwidth adaptation based on network conditions,
//! similar to video streaming ABR (Adaptive Bitrate) algorithms.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::time::{Duration, Instant};
use tokio::time::sleep;

/// Network quality metrics
#[derive(Debug, Clone, Copy)]
pub struct NetworkMetrics {
    /// Round-trip time
    pub rtt: Duration,

    /// Packet loss percentage (0.0-1.0)
    pub packet_loss: f64,

    /// Throughput in bytes per second
    pub throughput: u64,

    /// Jitter (variance in RTT)
    pub jitter: Duration,

    /// Available bandwidth estimate
    pub available_bandwidth: u64,
}

impl NetworkMetrics {
    /// Calculate overall quality score (0.0-1.0, higher is better)
    pub fn quality_score(&self) -> f64 {
        let rtt_score = if self.rtt.as_millis() < 50 {
            1.0
        } else if self.rtt.as_millis() < 150 {
            0.8
        } else if self.rtt.as_millis() < 300 {
            0.5
        } else {
            0.2
        };

        let loss_score = 1.0 - self.packet_loss;

        let throughput_score = (self.throughput as f64 / 10_000_000.0).min(1.0); // 10 Mbps reference

        let jitter_score = if self.jitter.as_millis() < 10 {
            1.0
        } else if self.jitter.as_millis() < 30 {
            0.7
        } else {
            0.4
        };

        // Weighted average
        rtt_score * 0.3 + loss_score * 0.4 + throughput_score * 0.2 + jitter_score * 0.1
    }

    /// Classify network quality
    pub fn quality_tier(&self) -> QualityTier {
        let score = self.quality_score();
        if score >= 0.8 {
            QualityTier::High
        } else if score >= 0.5 {
            QualityTier::Medium
        } else if score >= 0.3 {
            QualityTier::Low
        } else {
            QualityTier::VeryLow
        }
    }
}

/// Quality tier for adaptive streaming
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QualityTier {
    High,
    Medium,
    Low,
    VeryLow,
}

/// Quality profile for each tier
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityProfile {
    /// Quality tier
    pub tier: QualityTier,

    /// Target latency
    pub target_latency: Duration,

    /// Maximum packet size
    pub max_packet_size: usize,

    /// Enable compression
    pub enable_compression: bool,

    /// Compression level (0-9)
    pub compression_level: u32,

    /// Enable packet coalescing
    pub enable_coalescing: bool,

    /// Target throughput (bytes/sec)
    pub target_throughput: u64,

    /// Buffer size
    pub buffer_size: usize,
}

impl QualityProfile {
    /// High quality profile (optimal conditions)
    pub fn high() -> Self {
        Self {
            tier: QualityTier::High,
            target_latency: Duration::from_millis(50),
            max_packet_size: 1400,
            enable_compression: false,
            compression_level: 0,
            enable_coalescing: false,
            target_throughput: 10_000_000, // 10 Mbps
            buffer_size: 65536,
        }
    }

    /// Medium quality profile (good conditions)
    pub fn medium() -> Self {
        Self {
            tier: QualityTier::Medium,
            target_latency: Duration::from_millis(150),
            max_packet_size: 1200,
            enable_compression: true,
            compression_level: 3,
            enable_coalescing: true,
            target_throughput: 5_000_000, // 5 Mbps
            buffer_size: 32768,
        }
    }

    /// Low quality profile (poor conditions)
    pub fn low() -> Self {
        Self {
            tier: QualityTier::Low,
            target_latency: Duration::from_millis(500),
            max_packet_size: 800,
            enable_compression: true,
            compression_level: 6,
            enable_coalescing: true,
            target_throughput: 1_000_000, // 1 Mbps
            buffer_size: 16384,
        }
    }

    /// Very low quality profile (very poor conditions)
    pub fn very_low() -> Self {
        Self {
            tier: QualityTier::VeryLow,
            target_latency: Duration::from_secs(1),
            max_packet_size: 512,
            enable_compression: true,
            compression_level: 9,
            enable_coalescing: true,
            target_throughput: 256_000, // 256 Kbps
            buffer_size: 8192,
        }
    }

    /// Get profile for tier
    pub fn for_tier(tier: QualityTier) -> Self {
        match tier {
            QualityTier::High => Self::high(),
            QualityTier::Medium => Self::medium(),
            QualityTier::Low => Self::low(),
            QualityTier::VeryLow => Self::very_low(),
        }
    }
}

/// Network monitor for tracking connection quality
pub struct NetworkMonitor {
    /// RTT samples (last N measurements)
    rtt_samples: VecDeque<Duration>,

    /// Throughput samples (bytes/sec)
    throughput_samples: VecDeque<u64>,

    /// Packet loss tracking
    packets_sent: u64,
    packets_lost: u64,

    /// Sample window size
    sample_window: usize,

    /// Last update time
    last_update: Instant,

    /// Bytes transferred since last update
    bytes_transferred: u64,
}

impl NetworkMonitor {
    /// Create new network monitor
    pub fn new(sample_window: usize) -> Self {
        Self {
            rtt_samples: VecDeque::with_capacity(sample_window),
            throughput_samples: VecDeque::with_capacity(sample_window),
            packets_sent: 0,
            packets_lost: 0,
            sample_window,
            last_update: Instant::now(),
            bytes_transferred: 0,
        }
    }

    /// Record RTT measurement
    pub fn record_rtt(&mut self, rtt: Duration) {
        if self.rtt_samples.len() >= self.sample_window {
            self.rtt_samples.pop_front();
        }
        self.rtt_samples.push_back(rtt);
    }

    /// Record packet sent
    pub fn record_packet_sent(&mut self, size: usize) {
        self.packets_sent += 1;
        self.bytes_transferred += size as u64;
    }

    /// Record packet lost
    pub fn record_packet_loss(&mut self) {
        self.packets_lost += 1;
    }

    /// Update throughput calculation
    pub fn update_throughput(&mut self) {
        let elapsed = self.last_update.elapsed();
        if elapsed >= Duration::from_secs(1) {
            let throughput = (self.bytes_transferred as f64 / elapsed.as_secs_f64()) as u64;

            if self.throughput_samples.len() >= self.sample_window {
                self.throughput_samples.pop_front();
            }
            self.throughput_samples.push_back(throughput);

            self.bytes_transferred = 0;
            self.last_update = Instant::now();
        }
    }

    /// Get current network metrics
    pub fn metrics(&self) -> NetworkMetrics {
        let rtt = if self.rtt_samples.is_empty() {
            Duration::from_millis(100)
        } else {
            let sum: Duration = self.rtt_samples.iter().sum();
            sum / self.rtt_samples.len() as u32
        };

        let jitter = if self.rtt_samples.len() > 1 {
            let mean = rtt;
            let variance: f64 = self.rtt_samples
                .iter()
                .map(|r| {
                    let diff = r.as_millis() as f64 - mean.as_millis() as f64;
                    diff * diff
                })
                .sum::<f64>()
                / self.rtt_samples.len() as f64;
            Duration::from_millis(variance.sqrt() as u64)
        } else {
            Duration::from_millis(0)
        };

        let throughput = if self.throughput_samples.is_empty() {
            1_000_000 // Assume 1 Mbps default
        } else {
            self.throughput_samples.iter().sum::<u64>() / self.throughput_samples.len() as u64
        };

        let packet_loss = if self.packets_sent == 0 {
            0.0
        } else {
            self.packets_lost as f64 / self.packets_sent as f64
        };

        NetworkMetrics {
            rtt,
            packet_loss,
            throughput,
            jitter,
            available_bandwidth: throughput,
        }
    }

    /// Reset statistics
    pub fn reset(&mut self) {
        self.rtt_samples.clear();
        self.throughput_samples.clear();
        self.packets_sent = 0;
        self.packets_lost = 0;
        self.bytes_transferred = 0;
        self.last_update = Instant::now();
    }
}

/// Adaptive bandwidth controller
pub struct BandwidthController {
    /// Network monitor
    monitor: NetworkMonitor,

    /// Current quality profile
    current_profile: QualityProfile,

    /// Adaptation hysteresis (seconds before switching quality)
    hysteresis_duration: Duration,

    /// Last quality change time
    last_quality_change: Instant,

    /// Quality change cooldown
    cooldown: Duration,
}

impl BandwidthController {
    /// Create new bandwidth controller
    pub fn new() -> Self {
        Self {
            monitor: NetworkMonitor::new(10),
            current_profile: QualityProfile::high(),
            hysteresis_duration: Duration::from_secs(5),
            last_quality_change: Instant::now(),
            cooldown: Duration::from_secs(10),
        }
    }

    /// Record RTT measurement
    pub fn record_rtt(&mut self, rtt: Duration) {
        self.monitor.record_rtt(rtt);
    }

    /// Record packet transmission
    pub fn record_packet(&mut self, size: usize, lost: bool) {
        self.monitor.record_packet_sent(size);
        if lost {
            self.monitor.record_packet_loss();
        }
    }

    /// Update and adapt quality
    pub fn update(&mut self) -> bool {
        self.monitor.update_throughput();

        // Don't change quality too frequently
        if self.last_quality_change.elapsed() < self.cooldown {
            return false;
        }

        let metrics = self.monitor.metrics();
        let target_tier = metrics.quality_tier();

        // Only change if tier is different and hysteresis has passed
        if target_tier != self.current_profile.tier
            && self.last_quality_change.elapsed() >= self.hysteresis_duration
        {
            self.current_profile = QualityProfile::for_tier(target_tier);
            self.last_quality_change = Instant::now();
            log::info!(
                "Quality adapted: {:?} (RTT: {:?}, Loss: {:.2}%, Throughput: {} Mbps)",
                target_tier,
                metrics.rtt,
                metrics.packet_loss * 100.0,
                metrics.throughput / 125_000
            );
            return true;
        }

        false
    }

    /// Get current quality profile
    pub fn current_profile(&self) -> &QualityProfile {
        &self.current_profile
    }

    /// Get current network metrics
    pub fn metrics(&self) -> NetworkMetrics {
        self.monitor.metrics()
    }

    /// Force quality change
    pub fn set_quality(&mut self, tier: QualityTier) {
        self.current_profile = QualityProfile::for_tier(tier);
        self.last_quality_change = Instant::now();
    }
}

impl Default for BandwidthController {
    fn default() -> Self {
        Self::new()
    }
}

/// Adaptive rate limiter using token bucket
pub struct AdaptiveRateLimiter {
    /// Current rate (bytes/sec)
    current_rate: u64,

    /// Tokens available
    tokens: f64,

    /// Last refill time
    last_refill: Instant,

    /// Bandwidth controller
    controller: BandwidthController,
}

impl AdaptiveRateLimiter {
    /// Create new adaptive rate limiter
    pub fn new(initial_rate: u64) -> Self {
        Self {
            current_rate: initial_rate,
            tokens: initial_rate as f64,
            last_refill: Instant::now(),
            controller: BandwidthController::new(),
        }
    }

    /// Try to send bytes (returns true if allowed)
    pub fn try_send(&mut self, bytes: u64) -> bool {
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
        while !self.try_send(bytes) {
            sleep(Duration::from_millis(10)).await;
        }
    }

    /// Refill token bucket
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();

        // Adapt rate based on network conditions
        self.controller.update();
        let target_rate = self.controller.current_profile().target_throughput;

        // Smooth rate transitions
        self.current_rate = self.smooth_rate_transition(self.current_rate, target_rate);

        self.tokens = (self.tokens + elapsed * self.current_rate as f64)
            .min(self.current_rate as f64 * 2.0); // Max 2 seconds of burst
        self.last_refill = now;
    }

    /// Smooth rate transition to avoid sudden changes
    fn smooth_rate_transition(&self, current: u64, target: u64) -> u64 {
        let diff = target as i64 - current as i64;
        let step = (diff / 10).max(-100_000).min(100_000); // Max 100KB/s change

        (current as i64 + step).max(64_000).min(100_000_000) as u64 // 64 Kbps to 100 Mbps
    }

    /// Record network measurement
    pub fn record_rtt(&mut self, rtt: Duration) {
        self.controller.record_rtt(rtt);
    }

    /// Record packet event
    pub fn record_packet(&mut self, size: usize, lost: bool) {
        self.controller.record_packet(size, lost);
    }

    /// Get current rate
    pub fn current_rate(&self) -> u64 {
        self.current_rate
    }

    /// Get network metrics
    pub fn metrics(&self) -> NetworkMetrics {
        self.controller.metrics()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_metrics_scoring() {
        let metrics = NetworkMetrics {
            rtt: Duration::from_millis(30),
            packet_loss: 0.01,
            throughput: 5_000_000,
            jitter: Duration::from_millis(5),
            available_bandwidth: 5_000_000,
        };

        let score = metrics.quality_score();
        assert!(score > 0.7);
        assert_eq!(metrics.quality_tier(), QualityTier::High);
    }

    #[test]
    fn test_quality_profiles() {
        let high = QualityProfile::high();
        let low = QualityProfile::low();

        assert!(high.max_packet_size > low.max_packet_size);
        assert!(high.target_throughput > low.target_throughput);
        assert!(!high.enable_compression);
        assert!(low.enable_compression);
    }

    #[test]
    fn test_network_monitor() {
        let mut monitor = NetworkMonitor::new(10);

        monitor.record_rtt(Duration::from_millis(50));
        monitor.record_rtt(Duration::from_millis(60));
        monitor.record_packet_sent(1400);
        monitor.record_packet_sent(1400);

        let metrics = monitor.metrics();
        assert!(metrics.rtt.as_millis() >= 50);
    }

    #[test]
    fn test_bandwidth_controller_adaptation() {
        let mut controller = BandwidthController::new();

        // Simulate poor network
        for _ in 0..20 {
            controller.record_rtt(Duration::from_millis(500));
            controller.record_packet(1400, true); // Packet loss
        }

        controller.update();
        // Quality should eventually degrade (after cooldown)
    }

    #[tokio::test]
    async fn test_adaptive_rate_limiter() {
        let mut limiter = AdaptiveRateLimiter::new(1_000_000); // 1 Mbps

        // Should allow small amount
        assert!(limiter.try_send(10000));

        // Should wait for larger amount
        limiter.wait_for(100000).await;
    }

    #[test]
    fn test_rate_smoothing() {
        let limiter = AdaptiveRateLimiter::new(1_000_000);

        let new_rate = limiter.smooth_rate_transition(1_000_000, 5_000_000);
        // Should increase gradually, not jump to 5M
        assert!(new_rate > 1_000_000);
        assert!(new_rate < 5_000_000);
    }
}
