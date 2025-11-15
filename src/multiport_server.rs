//! Multi-port server that listens on protocol-appropriate ports
//!
//! This module implements a server that:
//! - Listens on multiple ports simultaneously
//! - Maps each port to appropriate protocol emulation
//! - Provides realistic traffic patterns for netflow evasion

use crate::library::ProtocolLibrary;
use crate::netflow_evasion::MultiPortConfig;
use crate::protocol::{ProtocolId, ProtocolMeta};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;

/// Port binding information
#[derive(Debug, Clone)]
pub struct PortBinding {
    /// Port number
    pub port: u16,
    /// Protocol(s) served on this port
    pub protocols: Vec<ProtocolId>,
    /// Bind address
    pub bind_addr: SocketAddr,
}

/// Multi-port server state
pub struct MultiPortServer {
    /// Protocol library
    library: Arc<ProtocolLibrary>,

    /// Configuration
    config: MultiPortConfig,

    /// Active port bindings
    bindings: Arc<RwLock<Vec<PortBinding>>>,

    /// Port to protocol mapping
    port_protocols: Arc<RwLock<HashMap<u16, Vec<ProtocolId>>>>,

    /// Connection statistics per port
    stats: Arc<RwLock<HashMap<u16, PortStats>>>,
}

/// Statistics for a port
#[derive(Debug, Clone, Default)]
pub struct PortStats {
    /// Total connections accepted
    pub connections: u64,
    /// Bytes transferred
    pub bytes: u64,
    /// Failed connections
    pub failures: u64,
    /// Last connection time
    pub last_connection: Option<std::time::Instant>,
}

impl MultiPortServer {
    /// Create a new multi-port server
    pub fn new(library: Arc<ProtocolLibrary>, config: MultiPortConfig) -> Self {
        Self {
            library,
            config,
            bindings: Arc::new(RwLock::new(Vec::new())),
            port_protocols: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Initialize port bindings based on configuration
    pub async fn initialize(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut bindings = Vec::new();
        let mut port_protocols = HashMap::new();

        // Bind standard protocol ports
        if self.config.use_standard_ports {
            for (proto_name, ports) in &self.config.protocol_ports {
                let proto_id = ProtocolId::from(proto_name.as_str());

                for &port in ports {
                    if bindings.len() >= self.config.max_ports {
                        break;
                    }

                    port_protocols
                        .entry(port)
                        .or_insert_with(Vec::new)
                        .push(proto_id.clone());

                    if !bindings.iter().any(|b: &PortBinding| b.port == port) {
                        bindings.push(PortBinding {
                            port,
                            protocols: vec![proto_id.clone()],
                            bind_addr: format!("{}:{}", self.config.bind_addr, port)
                                .parse()
                                .unwrap(),
                        });
                    }
                }
            }
        }

        // Bind random high ports if configured
        if self.config.use_random_ports {
            let random_ports = Self::generate_random_ports(
                self.config.max_ports - bindings.len(),
                &bindings,
            );

            for port in random_ports {
                // Assign a random protocol from the library
                if let Some(proto) = self.select_random_protocol() {
                    port_protocols
                        .entry(port)
                        .or_insert_with(Vec::new)
                        .push(proto.id.clone());

                    bindings.push(PortBinding {
                        port,
                        protocols: vec![proto.id.clone()],
                        bind_addr: format!("{}:{}", self.config.bind_addr, port)
                            .parse()
                            .unwrap(),
                    });
                }
            }
        }

        *self.bindings.write().await = bindings;
        *self.port_protocols.write().await = port_protocols;

        Ok(())
    }

    /// Start listening on all configured ports
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        let bindings = self.bindings.read().await.clone();

        log::info!("Starting multi-port server on {} ports", bindings.len());

        let mut tasks = Vec::new();

        for binding in bindings {
            let stats = Arc::clone(&self.stats);
            let port_protocols = Arc::clone(&self.port_protocols);

            let task = tokio::spawn(async move {
                if let Err(e) = Self::listen_on_port(binding.clone(), port_protocols, stats).await {
                    log::error!("Error on port {}: {}", binding.port, e);
                }
            });

            tasks.push(task);
        }

        // Wait for all listeners
        for task in tasks {
            let _ = task.await;
        }

        Ok(())
    }

    /// Listen on a single port
    async fn listen_on_port(
        binding: PortBinding,
        port_protocols: Arc<RwLock<HashMap<u16, Vec<ProtocolId>>>>,
        stats: Arc<RwLock<HashMap<u16, PortStats>>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(binding.bind_addr).await?;
        log::info!(
            "Listening on port {} for protocols: {:?}",
            binding.port,
            binding.protocols
        );

        loop {
            match listener.accept().await {
                Ok((socket, peer_addr)) => {
                    log::debug!("Connection on port {} from {}", binding.port, peer_addr);

                    // Update stats
                    {
                        let mut stats_map = stats.write().await;
                        let port_stats = stats_map.entry(binding.port).or_default();
                        port_stats.connections += 1;
                        port_stats.last_connection = Some(std::time::Instant::now());
                    }

                    // Get protocol for this port
                    let protocols = {
                        let map = port_protocols.read().await;
                        map.get(&binding.port).cloned().unwrap_or_default()
                    };

                    // Handle connection (spawn task to avoid blocking)
                    let stats_clone = Arc::clone(&stats);
                    let port = binding.port;
                    let protocols_owned = protocols.clone();
                    tokio::spawn(async move {
                        let result = Self::handle_connection(socket, peer_addr, &protocols_owned).await;

                        // Extract error message before any await points
                        let error_opt = result.err().map(|e| format!("{}", e));

                        if let Some(error_msg) = error_opt {
                            log::error!("Connection handler error on port {}: {}", port, error_msg);

                            // Update failure stats
                            let mut stats_map = stats_clone.write().await;
                            let port_stats = stats_map.entry(port).or_default();
                            port_stats.failures += 1;
                        }
                    });
                }
                Err(e) => {
                    log::error!("Accept error on port {}: {}", binding.port, e);

                    // Update failure stats
                    let mut stats_map = stats.write().await;
                    let port_stats = stats_map.entry(binding.port).or_default();
                    port_stats.failures += 1;
                }
            }
        }
    }

    /// Handle a single connection
    async fn handle_connection(
        mut _socket: tokio::net::TcpStream,
        _peer_addr: SocketAddr,
        _protocols: &[ProtocolId],
    ) -> Result<(), Box<dyn std::error::Error>> {
        // TODO: Implement protocol-specific handling
        // For now, just accept and close
        log::debug!("Handling connection (placeholder)");
        Ok(())
    }

    /// Generate random port numbers avoiding conflicts
    fn generate_random_ports(count: usize, existing: &[PortBinding]) -> Vec<u16> {
        use rand::Rng;

        let mut ports = Vec::new();
        let mut rng = rand::thread_rng();

        let existing_ports: Vec<u16> = existing.iter().map(|b| b.port).collect();

        while ports.len() < count {
            // Use high ports (1024-65535)
            let port = rng.gen_range(1024..=65535);

            if !existing_ports.contains(&port) && !ports.contains(&port) {
                ports.push(port);
            }
        }

        ports
    }

    /// Select a random protocol from the library
    fn select_random_protocol(&self) -> Option<&ProtocolMeta> {
        let protocols = self.library.all();
        if protocols.is_empty() {
            return None;
        }

        let idx = rand::random::<usize>() % protocols.len();
        Some(protocols[idx])
    }

    /// Get current port bindings
    pub async fn get_bindings(&self) -> Vec<PortBinding> {
        self.bindings.read().await.clone()
    }

    /// Get statistics for all ports
    pub async fn get_stats(&self) -> HashMap<u16, PortStats> {
        self.stats.read().await.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_random_port_generation() {
        let existing = vec![PortBinding {
            port: 443,
            protocols: vec![ProtocolId::from("https")],
            bind_addr: "0.0.0.0:443".parse().unwrap(),
        }];

        let random_ports = MultiPortServer::generate_random_ports(10, &existing);

        assert_eq!(random_ports.len(), 10);
        assert!(!random_ports.contains(&443));

        // Check all ports are in valid range
        for port in random_ports {
            assert!(port >= 1024);
        }
    }
}
