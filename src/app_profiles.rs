//! Application-specific traffic profiles for realistic traffic emulation
//!
//! This module provides detailed traffic patterns extracted from real applications
//! to make proxy traffic indistinguishable from legitimate app traffic.

use rand::distributions::Distribution;
use rand_distr::{Normal, Uniform, Exp, WeightedIndex};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Application traffic profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationProfile {
    /// Application name
    pub name: String,

    /// Application category
    pub category: AppCategory,

    /// Upstream (client to server) packet characteristics
    pub upstream: PacketProfile,

    /// Downstream (server to client) packet characteristics
    pub downstream: PacketProfile,

    /// Burst patterns
    pub burst_patterns: Vec<BurstPattern>,

    /// State machine for connection phases
    pub states: Vec<ConnectionState>,

    /// Typical session duration
    pub session_duration: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AppCategory {
    VideoConference,
    VideoStreaming,
    WebBrowsing,
    FileTransfer,
    Gaming,
    Messaging,
    VoIP,
}

/// Packet size and timing characteristics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketProfile {
    /// Packet size distribution
    pub size_distribution: SizeDistribution,

    /// Packet rate (packets per second)
    pub packet_rate: RateDistribution,

    /// Inter-packet delay distribution
    pub delay_distribution: DelayDistribution,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SizeDistribution {
    /// Single mode (most common)
    Normal { mean: usize, stddev: usize },

    /// Two distinct packet sizes (e.g., control vs data)
    Bimodal {
        mode1: usize,
        mode2: usize,
        mode1_weight: f64,
    },

    /// Multiple packet sizes with weights
    Multimodal {
        modes: Vec<(usize, f64)>, // (size, weight)
    },

    /// Uniform distribution
    Uniform { min: usize, max: usize },

    /// Exponential (for bursty traffic)
    Exponential { mean: usize },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateDistribution {
    pub mean: f64,
    pub stddev: f64,
    pub min: f64,
    pub max: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelayDistribution {
    pub mean_ms: u64,
    pub stddev_ms: u64,
}

/// Burst pattern (periodic clusters of packets)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BurstPattern {
    /// Pattern name
    pub name: String,

    /// Interval between bursts
    pub interval: Duration,

    /// Number of packets in burst
    pub packet_count: usize,

    /// Burst packet size
    pub packet_size: usize,

    /// Probability this burst occurs (0.0-1.0)
    pub probability: f64,
}

/// Connection state (for state machine)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionState {
    /// State name
    pub name: String,

    /// Duration in this state
    pub duration: Duration,

    /// Packet pattern during this state
    pub pattern: StatePattern,

    /// Next state (or None for terminal state)
    pub next_state: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StatePattern {
    /// Fixed packet rate
    Steady { rate: f64 },

    /// Increasing rate (ramp up)
    RampUp { start_rate: f64, end_rate: f64 },

    /// Decreasing rate (ramp down)
    RampDown { start_rate: f64, end_rate: f64 },

    /// Bursty pattern
    Bursty { avg_rate: f64, burst_size: usize },

    /// Idle (no packets)
    Idle,
}

/// Pre-defined application profiles based on real traffic analysis
impl ApplicationProfile {
    /// Zoom video conferencing profile
    pub fn zoom() -> Self {
        Self {
            name: "Zoom".to_string(),
            category: AppCategory::VideoConference,
            upstream: PacketProfile {
                size_distribution: SizeDistribution::Bimodal {
                    mode1: 120,      // Audio packets
                    mode2: 1200,     // Video packets
                    mode1_weight: 0.3,
                },
                packet_rate: RateDistribution {
                    mean: 50.0,
                    stddev: 10.0,
                    min: 30.0,
                    max: 100.0,
                },
                delay_distribution: DelayDistribution {
                    mean_ms: 20,
                    stddev_ms: 5,
                },
            },
            downstream: PacketProfile {
                size_distribution: SizeDistribution::Normal {
                    mean: 1350,
                    stddev: 150,
                },
                packet_rate: RateDistribution {
                    mean: 60.0,
                    stddev: 15.0,
                    min: 40.0,
                    max: 120.0,
                },
                delay_distribution: DelayDistribution {
                    mean_ms: 16,  // ~60fps
                    stddev_ms: 3,
                },
            },
            burst_patterns: vec![
                BurstPattern {
                    name: "Video keyframe".to_string(),
                    interval: Duration::from_secs(2),
                    packet_count: 5,
                    packet_size: 1400,
                    probability: 0.95,
                },
                BurstPattern {
                    name: "Screen share update".to_string(),
                    interval: Duration::from_millis(500),
                    packet_count: 3,
                    packet_size: 1200,
                    probability: 0.4,
                },
            ],
            states: vec![
                ConnectionState {
                    name: "Handshake".to_string(),
                    duration: Duration::from_secs(2),
                    pattern: StatePattern::Bursty {
                        avg_rate: 20.0,
                        burst_size: 3,
                    },
                    next_state: Some("Active".to_string()),
                },
                ConnectionState {
                    name: "Active".to_string(),
                    duration: Duration::from_secs(1800), // 30 min
                    pattern: StatePattern::Steady { rate: 55.0 },
                    next_state: Some("Teardown".to_string()),
                },
                ConnectionState {
                    name: "Teardown".to_string(),
                    duration: Duration::from_secs(1),
                    pattern: StatePattern::RampDown {
                        start_rate: 55.0,
                        end_rate: 5.0,
                    },
                    next_state: None,
                },
            ],
            session_duration: Duration::from_secs(1800),
        }
    }

    /// Netflix video streaming profile
    pub fn netflix() -> Self {
        Self {
            name: "Netflix".to_string(),
            category: AppCategory::VideoStreaming,
            upstream: PacketProfile {
                size_distribution: SizeDistribution::Normal {
                    mean: 200,
                    stddev: 50,
                },
                packet_rate: RateDistribution {
                    mean: 5.0,  // Low upstream
                    stddev: 2.0,
                    min: 2.0,
                    max: 10.0,
                },
                delay_distribution: DelayDistribution {
                    mean_ms: 200,
                    stddev_ms: 50,
                },
            },
            downstream: PacketProfile {
                size_distribution: SizeDistribution::Normal {
                    mean: 1450,  // Near MTU for efficiency
                    stddev: 50,
                },
                packet_rate: RateDistribution {
                    mean: 400.0,  // High downstream for video
                    stddev: 100.0,
                    min: 200.0,
                    max: 800.0,
                },
                delay_distribution: DelayDistribution {
                    mean_ms: 2,
                    stddev_ms: 1,
                },
            },
            burst_patterns: vec![
                BurstPattern {
                    name: "Chunk download".to_string(),
                    interval: Duration::from_secs(4),  // 4-second chunks
                    packet_count: 2000,
                    packet_size: 1450,
                    probability: 1.0,
                },
            ],
            states: vec![
                ConnectionState {
                    name: "Initial buffering".to_string(),
                    duration: Duration::from_secs(5),
                    pattern: StatePattern::RampUp {
                        start_rate: 100.0,
                        end_rate: 600.0,
                    },
                    next_state: Some("Streaming".to_string()),
                },
                ConnectionState {
                    name: "Streaming".to_string(),
                    duration: Duration::from_secs(3600), // 1 hour
                    pattern: StatePattern::Bursty {
                        avg_rate: 400.0,
                        burst_size: 2000,
                    },
                    next_state: None,
                },
            ],
            session_duration: Duration::from_secs(3600),
        }
    }

    /// YouTube streaming profile
    pub fn youtube() -> Self {
        Self {
            name: "YouTube".to_string(),
            category: AppCategory::VideoStreaming,
            upstream: PacketProfile {
                size_distribution: SizeDistribution::Bimodal {
                    mode1: 80,   // ACKs
                    mode2: 400,  // Quality change requests
                    mode1_weight: 0.8,
                },
                packet_rate: RateDistribution {
                    mean: 10.0,
                    stddev: 3.0,
                    min: 5.0,
                    max: 20.0,
                },
                delay_distribution: DelayDistribution {
                    mean_ms: 100,
                    stddev_ms: 30,
                },
            },
            downstream: PacketProfile {
                size_distribution: SizeDistribution::Normal {
                    mean: 1400,
                    stddev: 100,
                },
                packet_rate: RateDistribution {
                    mean: 350.0,
                    stddev: 80.0,
                    min: 150.0,
                    max: 700.0,
                },
                delay_distribution: DelayDistribution {
                    mean_ms: 3,
                    stddev_ms: 2,
                },
            },
            burst_patterns: vec![
                BurstPattern {
                    name: "Adaptive chunk".to_string(),
                    interval: Duration::from_secs(2),
                    packet_count: 800,
                    packet_size: 1400,
                    probability: 1.0,
                },
            ],
            states: vec![
                ConnectionState {
                    name: "Buffering".to_string(),
                    duration: Duration::from_secs(3),
                    pattern: StatePattern::RampUp {
                        start_rate: 50.0,
                        end_rate: 500.0,
                    },
                    next_state: Some("Playing".to_string()),
                },
                ConnectionState {
                    name: "Playing".to_string(),
                    duration: Duration::from_secs(2400), // 40 min
                    pattern: StatePattern::Bursty {
                        avg_rate: 350.0,
                        burst_size: 800,
                    },
                    next_state: None,
                },
            ],
            session_duration: Duration::from_secs(2400),
        }
    }

    /// Microsoft Teams profile
    pub fn teams() -> Self {
        Self {
            name: "Teams".to_string(),
            category: AppCategory::VideoConference,
            upstream: PacketProfile {
                size_distribution: SizeDistribution::Multimodal {
                    modes: vec![
                        (100, 0.2),   // Audio
                        (500, 0.3),   // Low-res video
                        (1200, 0.5),  // HD video
                    ],
                },
                packet_rate: RateDistribution {
                    mean: 45.0,
                    stddev: 12.0,
                    min: 25.0,
                    max: 90.0,
                },
                delay_distribution: DelayDistribution {
                    mean_ms: 22,
                    stddev_ms: 6,
                },
            },
            downstream: PacketProfile {
                size_distribution: SizeDistribution::Normal {
                    mean: 1300,
                    stddev: 200,
                },
                packet_rate: RateDistribution {
                    mean: 55.0,
                    stddev: 18.0,
                    min: 30.0,
                    max: 110.0,
                },
                delay_distribution: DelayDistribution {
                    mean_ms: 18,
                    stddev_ms: 4,
                },
            },
            burst_patterns: vec![
                BurstPattern {
                    name: "Gallery view update".to_string(),
                    interval: Duration::from_millis(1000),
                    packet_count: 9,  // 3x3 grid
                    packet_size: 1300,
                    probability: 0.7,
                },
            ],
            states: vec![
                ConnectionState {
                    name: "Connecting".to_string(),
                    duration: Duration::from_secs(3),
                    pattern: StatePattern::Bursty {
                        avg_rate: 15.0,
                        burst_size: 4,
                    },
                    next_state: Some("InMeeting".to_string()),
                },
                ConnectionState {
                    name: "InMeeting".to_string(),
                    duration: Duration::from_secs(3600),
                    pattern: StatePattern::Steady { rate: 50.0 },
                    next_state: None,
                },
            ],
            session_duration: Duration::from_secs(3600),
        }
    }

    /// HTTPS web browsing profile
    pub fn https_browsing() -> Self {
        Self {
            name: "HTTPS Browsing".to_string(),
            category: AppCategory::WebBrowsing,
            upstream: PacketProfile {
                size_distribution: SizeDistribution::Bimodal {
                    mode1: 100,   // GET requests
                    mode2: 800,   // POST with data
                    mode1_weight: 0.85,
                },
                packet_rate: RateDistribution {
                    mean: 8.0,
                    stddev: 4.0,
                    min: 2.0,
                    max: 20.0,
                },
                delay_distribution: DelayDistribution {
                    mean_ms: 150,
                    stddev_ms: 80,
                },
            },
            downstream: PacketProfile {
                size_distribution: SizeDistribution::Normal {
                    mean: 1400,
                    stddev: 250,
                },
                packet_rate: RateDistribution {
                    mean: 50.0,
                    stddev: 30.0,
                    min: 10.0,
                    max: 150.0,
                },
                delay_distribution: DelayDistribution {
                    mean_ms: 20,
                    stddev_ms: 15,
                },
            },
            burst_patterns: vec![
                BurstPattern {
                    name: "Page load".to_string(),
                    interval: Duration::from_secs(30),
                    packet_count: 50,
                    packet_size: 1400,
                    probability: 0.6,
                },
            ],
            states: vec![
                ConnectionState {
                    name: "TLS Handshake".to_string(),
                    duration: Duration::from_millis(200),
                    pattern: StatePattern::Bursty {
                        avg_rate: 10.0,
                        burst_size: 4,
                    },
                    next_state: Some("Browsing".to_string()),
                },
                ConnectionState {
                    name: "Browsing".to_string(),
                    duration: Duration::from_secs(600),
                    pattern: StatePattern::Bursty {
                        avg_rate: 30.0,
                        burst_size: 50,
                    },
                    next_state: None,
                },
            ],
            session_duration: Duration::from_secs(600),
        }
    }

    /// WhatsApp messaging profile
    pub fn whatsapp() -> Self {
        Self {
            name: "WhatsApp".to_string(),
            category: AppCategory::Messaging,
            upstream: PacketProfile {
                size_distribution: SizeDistribution::Multimodal {
                    modes: vec![
                        (80, 0.5),    // Text messages
                        (500, 0.3),   // Images (compressed)
                        (1400, 0.2),  // Video/voice messages
                    ],
                },
                packet_rate: RateDistribution {
                    mean: 2.0,
                    stddev: 1.5,
                    min: 0.5,
                    max: 10.0,
                },
                delay_distribution: DelayDistribution {
                    mean_ms: 500,
                    stddev_ms: 300,
                },
            },
            downstream: PacketProfile {
                size_distribution: SizeDistribution::Multimodal {
                    modes: vec![
                        (100, 0.6),
                        (600, 0.3),
                        (1400, 0.1),
                    ],
                },
                packet_rate: RateDistribution {
                    mean: 3.0,
                    stddev: 2.0,
                    min: 0.5,
                    max: 15.0,
                },
                delay_distribution: DelayDistribution {
                    mean_ms: 400,
                    stddev_ms: 250,
                },
            },
            burst_patterns: vec![],
            states: vec![
                ConnectionState {
                    name: "Active".to_string(),
                    duration: Duration::from_secs(3600),
                    pattern: StatePattern::Bursty {
                        avg_rate: 2.5,
                        burst_size: 5,
                    },
                    next_state: None,
                },
            ],
            session_duration: Duration::from_secs(3600),
        }
    }

    /// Get profile by name
    pub fn get(name: &str) -> Option<Self> {
        match name.to_lowercase().as_str() {
            "zoom" => Some(Self::zoom()),
            "netflix" => Some(Self::netflix()),
            "youtube" => Some(Self::youtube()),
            "teams" => Some(Self::teams()),
            "https" | "browsing" => Some(Self::https_browsing()),
            "whatsapp" => Some(Self::whatsapp()),
            _ => None,
        }
    }

    /// List all available profiles
    pub fn available() -> Vec<String> {
        vec![
            "zoom".to_string(),
            "netflix".to_string(),
            "youtube".to_string(),
            "teams".to_string(),
            "https".to_string(),
            "whatsapp".to_string(),
        ]
    }
}

/// Application traffic emulator
pub struct ApplicationEmulator {
    profile: ApplicationProfile,
    current_state: usize,
    state_start: std::time::Instant,
    rng: rand::rngs::ThreadRng,
}

impl ApplicationEmulator {
    /// Create new emulator for application
    pub fn new(profile: ApplicationProfile) -> Self {
        Self {
            profile,
            current_state: 0,
            state_start: std::time::Instant::now(),
            rng: rand::thread_rng(),
        }
    }

    /// Generate packet size for upstream traffic
    pub fn generate_upstream_size(&mut self) -> usize {
        let dist = self.profile.upstream.size_distribution.clone();
        self.generate_size(&dist)
    }

    /// Generate packet size for downstream traffic
    pub fn generate_downstream_size(&mut self) -> usize {
        let dist = self.profile.downstream.size_distribution.clone();
        self.generate_size(&dist)
    }

    /// Generate inter-packet delay
    pub fn generate_delay(&mut self, upstream: bool) -> Duration {
        let dist = if upstream {
            &self.profile.upstream.delay_distribution
        } else {
            &self.profile.downstream.delay_distribution
        };

        let delay_ms = if dist.stddev_ms > 0 {
            let normal = Normal::new(dist.mean_ms as f64, dist.stddev_ms as f64)
                .unwrap_or_else(|_| Normal::new(50.0, 10.0).unwrap());
            normal.sample(&mut self.rng).max(0.0) as u64
        } else {
            dist.mean_ms
        };

        Duration::from_millis(delay_ms)
    }

    /// Check if should generate burst
    pub fn should_burst(&mut self) -> Option<&BurstPattern> {
        for pattern in &self.profile.burst_patterns {
            if rand::random::<f64>() < pattern.probability {
                return Some(pattern);
            }
        }
        None
    }

    /// Update state machine
    pub fn update_state(&mut self) {
        if self.current_state >= self.profile.states.len() {
            return;
        }

        let state = &self.profile.states[self.current_state];
        if self.state_start.elapsed() >= state.duration {
            if let Some(next) = &state.next_state {
                // Find next state index
                for (i, s) in self.profile.states.iter().enumerate() {
                    if &s.name == next {
                        self.current_state = i;
                        self.state_start = std::time::Instant::now();
                        break;
                    }
                }
            }
        }
    }

    /// Get current state
    pub fn current_state(&self) -> Option<&ConnectionState> {
        self.profile.states.get(self.current_state)
    }

    fn generate_size(&mut self, dist: &SizeDistribution) -> usize {
        match dist {
            SizeDistribution::Normal { mean, stddev } => {
                let normal = Normal::new(*mean as f64, *stddev as f64)
                    .unwrap_or_else(|_| Normal::new(1400.0, 200.0).unwrap());
                normal.sample(&mut self.rng)
                    .max(64.0)
                    .min(1500.0) as usize
            }
            SizeDistribution::Bimodal { mode1, mode2, mode1_weight } => {
                if rand::random::<f64>() < *mode1_weight {
                    *mode1
                } else {
                    *mode2
                }
            }
            SizeDistribution::Multimodal { modes } => {
                let weights: Vec<f64> = modes.iter().map(|(_, w)| *w).collect();
                let dist = WeightedIndex::new(&weights).unwrap();
                modes[dist.sample(&mut self.rng)].0
            }
            SizeDistribution::Uniform { min, max } => {
                let uniform = Uniform::new(*min, *max);
                uniform.sample(&mut self.rng)
            }
            SizeDistribution::Exponential { mean } => {
                let rate = 1.0 / *mean as f64;
                let exp = Exp::new(rate).unwrap_or_else(|_| Exp::new(1.0 / 1400.0).unwrap());
                exp.sample(&mut self.rng)
                    .max(64.0)
                    .min(1500.0) as usize
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zoom_profile() {
        let profile = ApplicationProfile::zoom();
        assert_eq!(profile.category, AppCategory::VideoConference);
        assert!(!profile.burst_patterns.is_empty());
        assert!(!profile.states.is_empty());
    }

    #[test]
    fn test_netflix_profile() {
        let profile = ApplicationProfile::netflix();
        assert_eq!(profile.category, AppCategory::VideoStreaming);
        assert!(profile.session_duration > Duration::from_secs(1800));
    }

    #[test]
    fn test_emulator_packet_generation() {
        let profile = ApplicationProfile::zoom();
        let mut emulator = ApplicationEmulator::new(profile);

        for _ in 0..100 {
            let size = emulator.generate_upstream_size();
            assert!(size >= 64 && size <= 1500);

            let delay = emulator.generate_delay(true);
            assert!(delay < Duration::from_secs(1));
        }
    }

    #[test]
    fn test_state_machine() {
        let profile = ApplicationProfile::zoom();
        let mut emulator = ApplicationEmulator::new(profile);

        let initial_state = emulator.current_state().unwrap();
        assert_eq!(initial_state.name, "Handshake");
    }

    #[test]
    fn test_get_profile() {
        assert!(ApplicationProfile::get("zoom").is_some());
        assert!(ApplicationProfile::get("netflix").is_some());
        assert!(ApplicationProfile::get("unknown").is_none());
    }

    #[test]
    fn test_available_profiles() {
        let available = ApplicationProfile::available();
        assert!(available.contains(&"zoom".to_string()));
        assert!(available.contains(&"netflix".to_string()));
    }
}
