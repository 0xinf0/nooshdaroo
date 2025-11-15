//! Network path tracing and hop discovery
//!
//! This module provides traceroute functionality to discover the network path
//! to the server. This is optional and can be disabled on mobile platforms
//! where ICMP permissions may not be available.

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::process::Command;
use std::time::Duration;

/// A hop in the network path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkHop {
    /// Hop number (TTL)
    pub hop_number: u8,

    /// IP address of this hop (if discovered)
    pub address: Option<IpAddr>,

    /// Hostname (if resolved)
    pub hostname: Option<String>,

    /// Round-trip times in milliseconds
    pub rtts: Vec<f64>,

    /// Whether this hop responded
    pub responded: bool,

    /// ASN (Autonomous System Number) if available
    pub asn: Option<u32>,

    /// ASN organization name if available
    pub asn_org: Option<String>,
}

/// Traceroute result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracerouteResult {
    /// Target address
    pub target: SocketAddr,

    /// Protocol used for the trace
    pub protocol: String,

    /// All discovered hops
    pub hops: Vec<NetworkHop>,

    /// Total hop count
    pub hop_count: usize,

    /// Whether the trace completed successfully
    pub success: bool,

    /// Error message if failed
    pub error: Option<String>,

    /// Trace duration
    pub duration: Duration,
}

/// Traceroute configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracerouteConfig {
    /// Enable traceroute (may require elevated privileges)
    pub enabled: bool,

    /// Maximum TTL / hop count
    pub max_hops: u8,

    /// Timeout per hop in seconds
    pub timeout_secs: u32,

    /// Number of probes per hop
    pub probes_per_hop: u8,

    /// Whether to resolve hostnames
    pub resolve_hostnames: bool,

    /// Whether to lookup ASN information
    pub lookup_asn: bool,
}

impl Default for TracerouteConfig {
    fn default() -> Self {
        Self {
            enabled: true, // Can be disabled on mobile
            max_hops: 30,
            timeout_secs: 5,
            probes_per_hop: 3,
            resolve_hostnames: true,
            lookup_asn: false, // Disabled by default as it requires external API
        }
    }
}

/// Traceroute executor
pub struct Traceroute {
    config: TracerouteConfig,
}

impl Traceroute {
    /// Create a new traceroute executor
    pub fn new(config: TracerouteConfig) -> Self {
        Self { config }
    }

    /// Perform traceroute to target
    pub async fn trace(&self, target: SocketAddr, protocol: &str) -> TracerouteResult {
        if !self.config.enabled {
            return TracerouteResult {
                target,
                protocol: protocol.to_string(),
                hops: Vec::new(),
                hop_count: 0,
                success: false,
                error: Some("Traceroute disabled".to_string()),
                duration: Duration::from_secs(0),
            };
        }

        let start = std::time::Instant::now();

        // Try to use system traceroute command
        match self.system_traceroute(target).await {
            Ok(hops) => TracerouteResult {
                target,
                protocol: protocol.to_string(),
                hop_count: hops.len(),
                hops,
                success: true,
                error: None,
                duration: start.elapsed(),
            },
            Err(e) => TracerouteResult {
                target,
                protocol: protocol.to_string(),
                hops: Vec::new(),
                hop_count: 0,
                success: false,
                error: Some(e),
                duration: start.elapsed(),
            },
        }
    }

    /// Execute system traceroute command
    async fn system_traceroute(&self, target: SocketAddr) -> Result<Vec<NetworkHop>, String> {
        let target_ip = target.ip().to_string();

        // Determine which traceroute command to use
        #[cfg(target_os = "windows")]
        let cmd_name = "tracert";
        #[cfg(not(target_os = "windows"))]
        let cmd_name = "traceroute";

        let output = Command::new(cmd_name)
            .arg("-m")
            .arg(self.config.max_hops.to_string())
            .arg("-w")
            .arg(self.config.timeout_secs.to_string())
            .arg(&target_ip)
            .output()
            .map_err(|e| format!("Failed to execute traceroute: {}", e))?;

        if !output.status.success() {
            return Err("Traceroute command failed".to_string());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        self.parse_traceroute_output(&stdout)
    }

    /// Parse traceroute output
    fn parse_traceroute_output(&self, output: &str) -> Result<Vec<NetworkHop>, String> {
        let mut hops = Vec::new();

        for line in output.lines() {
            if let Some(hop) = self.parse_hop_line(line) {
                hops.push(hop);
            }
        }

        if hops.is_empty() {
            Err("No hops parsed from traceroute output".to_string())
        } else {
            Ok(hops)
        }
    }

    /// Parse a single hop line
    fn parse_hop_line(&self, line: &str) -> Option<NetworkHop> {
        // This is a simplified parser - real implementation would be more robust
        let parts: Vec<&str> = line.split_whitespace().collect();

        if parts.is_empty() {
            return None;
        }

        // Try to parse hop number
        let hop_number = parts[0].trim_end_matches('.').parse::<u8>().ok()?;

        // Check if hop responded
        let responded = !parts.contains(&"*");

        // Try to extract IP address
        let address = parts
            .iter()
            .find_map(|part| {
                if part.starts_with('(') && part.ends_with(')') {
                    part.trim_matches(|c| c == '(' || c == ')').parse::<IpAddr>().ok()
                } else {
                    part.parse::<IpAddr>().ok()
                }
            });

        // Extract RTTs (look for patterns like "1.234" followed by "ms")
        let rtts: Vec<f64> = parts
            .windows(2)
            .filter_map(|window| {
                if window.len() == 2 && window[1] == "ms" {
                    window[0].parse::<f64>().ok()
                } else if window[0].ends_with("ms") {
                    window[0].trim_end_matches("ms").parse::<f64>().ok()
                } else {
                    None
                }
            })
            .collect();

        Some(NetworkHop {
            hop_number,
            address,
            hostname: None, // Could be extracted from output
            rtts,
            responded,
            asn: None,
            asn_org: None,
        })
    }

    /// Perform traceroute on bootstrap (client startup)
    pub async fn bootstrap_trace(
        &self,
        server_addr: SocketAddr,
        protocol: &str,
    ) -> TracerouteResult {
        log::info!("Performing bootstrap traceroute to {} via {}", server_addr, protocol);

        let result = self.trace(server_addr, protocol).await;

        if result.success {
            log::info!("Traceroute completed: {} hops", result.hop_count);

            // Log JSON output for jq parsing
            if let Ok(json) = serde_json::to_string(&result) {
                println!("{}", json);
            }
        } else {
            log::warn!(
                "Traceroute failed: {}",
                result.error.as_deref().unwrap_or("unknown error")
            );
        }

        result
    }
}

/// Check if traceroute is available on the system
pub fn is_traceroute_available() -> bool {
    #[cfg(target_os = "windows")]
    let cmd = "tracert";
    #[cfg(not(target_os = "windows"))]
    let cmd = "traceroute";

    Command::new(cmd)
        .arg("--help")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Auto-detect traceroute config based on platform
pub fn auto_config() -> TracerouteConfig {
    let available = is_traceroute_available();

    TracerouteConfig {
        enabled: available,
        max_hops: 30,
        timeout_secs: if cfg!(target_os = "ios") || cfg!(target_os = "android") {
            2 // Shorter timeout on mobile
        } else {
            5
        },
        probes_per_hop: if cfg!(target_os = "ios") || cfg!(target_os = "android") {
            1 // Fewer probes on mobile to save battery
        } else {
            3
        },
        resolve_hostnames: !cfg!(target_os = "ios") && !cfg!(target_os = "android"), // Disabled on mobile
        lookup_asn: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hop_line_parsing() {
        let tracer = Traceroute::new(TracerouteConfig::default());

        let line = " 1  192.168.1.1 (192.168.1.1)  1.234 ms  1.456 ms  1.678 ms";
        let hop = tracer.parse_hop_line(line);

        assert!(hop.is_some());
        let hop = hop.unwrap();
        assert_eq!(hop.hop_number, 1);
        assert!(hop.responded);
        assert_eq!(hop.rtts.len(), 3);
    }

    #[test]
    fn test_auto_config() {
        let config = auto_config();
        assert!(config.max_hops > 0);
        assert!(config.timeout_secs > 0);
    }

    #[test]
    fn test_disabled_traceroute() {
        let mut config = TracerouteConfig::default();
        config.enabled = false;

        let tracer = Traceroute::new(config);
        let rt = tokio::runtime::Runtime::new().unwrap();

        let result = rt.block_on(async {
            tracer.trace("8.8.8.8:443".parse().unwrap(), "https").await
        });

        assert!(!result.success);
        assert!(result.error.is_some());
    }
}
