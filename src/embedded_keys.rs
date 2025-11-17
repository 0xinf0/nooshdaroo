//! Embedded server public keys for production deployments
//!
//! This module provides compile-time embedded server public keys for mobile
//! and desktop client deployments where configuration files are not practical.
//!
//! ## Benefits:
//! - ✅ No config file dependencies
//! - ✅ Immune to key substitution attacks
//! - ✅ Perfect for iOS/Android apps
//! - ✅ Simpler distribution
//! - ✅ Certificate pinning for Noise keys
//!
//! ## Usage:
//!
//! ### Build-time Key Embedding
//!
//! ```bash
//! # Set server key via environment variable at build time
//! export NOOSHDAROO_SERVER_KEY="ynXDvH7v8yK+tKJPqz9j8F5GqL2QF3r4E8f9cB7J2zM="
//! cargo build --release
//! ```
//!
//! ### Runtime Usage
//!
//! ```rust
//! use nooshdaroo::embedded_keys::{get_production_key, ServerEndpoint};
//!
//! // Get the primary production server key
//! let server_key = get_production_key(ServerEndpoint::Primary);
//!
//! // Or get a specific regional server
//! let eu_key = get_production_key(ServerEndpoint::EuropeWest);
//! ```

use std::collections::HashMap;

/// Server endpoint identifiers
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub enum ServerEndpoint {
    /// Primary production server
    Primary,
    /// Fallback production server
    Fallback,
    /// Europe West region
    EuropeWest,
    /// Asia Pacific region
    AsiaPacific,
    /// North America East region
    NorthAmericaEast,
    /// Development/testing server
    Development,
}

/// Server configuration with embedded key
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Human-readable server name
    pub name: &'static str,
    /// Server address (domain:port)
    pub address: &'static str,
    /// Server's public key (base64-encoded X25519 key)
    pub public_key: &'static str,
    /// Server region/location
    pub region: &'static str,
    /// Is this server recommended for production?
    pub production: bool,
}

/// Get embedded server public key for a specific endpoint
///
/// This function returns compile-time embedded server keys based on build
/// configuration. Keys are defined at compile time using:
///
/// 1. Environment variables (highest priority)
/// 2. Feature flags
/// 3. Default embedded keys
///
/// # Example
///
/// ```rust
/// use nooshdaroo::embedded_keys::{get_production_key, ServerEndpoint};
///
/// let server_key = get_production_key(ServerEndpoint::Primary);
/// assert!(!server_key.is_empty());
/// ```
pub fn get_production_key(endpoint: ServerEndpoint) -> &'static str {
    let config = get_server_config(endpoint);
    config.public_key
}

/// Get full server configuration for an endpoint
///
/// Returns server address, public key, and metadata for a specific endpoint.
///
/// # Example
///
/// ```rust
/// use nooshdaroo::embedded_keys::{get_server_config, ServerEndpoint};
///
/// let config = get_server_config(ServerEndpoint::Primary);
/// println!("Server: {} at {}", config.name, config.address);
/// println!("Key: {}", config.public_key);
/// ```
pub fn get_server_config(endpoint: ServerEndpoint) -> ServerConfig {
    match endpoint {
        ServerEndpoint::Primary => ServerConfig {
            name: "Production Primary",
            address: option_env!("NOOSHDAROO_PRIMARY_SERVER")
                .unwrap_or("vpn.nooshdaroo.com:8443"),
            public_key: option_env!("NOOSHDAROO_PRIMARY_KEY")
                .unwrap_or(DEFAULT_PRIMARY_KEY),
            region: "Global",
            production: true,
        },

        ServerEndpoint::Fallback => ServerConfig {
            name: "Production Fallback",
            address: option_env!("NOOSHDAROO_FALLBACK_SERVER")
                .unwrap_or("vpn-backup.nooshdaroo.com:8443"),
            public_key: option_env!("NOOSHDAROO_FALLBACK_KEY")
                .unwrap_or(DEFAULT_FALLBACK_KEY),
            region: "Global",
            production: true,
        },

        ServerEndpoint::EuropeWest => ServerConfig {
            name: "Europe West",
            address: option_env!("NOOSHDAROO_EU_SERVER")
                .unwrap_or("eu-west.nooshdaroo.com:8443"),
            public_key: option_env!("NOOSHDAROO_EU_KEY")
                .unwrap_or(DEFAULT_EU_KEY),
            region: "Europe (Netherlands)",
            production: true,
        },

        ServerEndpoint::AsiaPacific => ServerConfig {
            name: "Asia Pacific",
            address: option_env!("NOOSHDAROO_AP_SERVER")
                .unwrap_or("ap-east.nooshdaroo.com:8443"),
            public_key: option_env!("NOOSHDAROO_AP_KEY")
                .unwrap_or(DEFAULT_AP_KEY),
            region: "Asia Pacific (Singapore)",
            production: true,
        },

        ServerEndpoint::NorthAmericaEast => ServerConfig {
            name: "North America East",
            address: option_env!("NOOSHDAROO_NA_SERVER")
                .unwrap_or("na-east.nooshdaroo.com:8443"),
            public_key: option_env!("NOOSHDAROO_NA_KEY")
                .unwrap_or(DEFAULT_NA_KEY),
            region: "North America (New York)",
            production: true,
        },

        ServerEndpoint::Development => ServerConfig {
            name: "Development Server",
            address: option_env!("NOOSHDAROO_DEV_SERVER")
                .unwrap_or("localhost:8443"),
            public_key: option_env!("NOOSHDAROO_DEV_KEY")
                .unwrap_or(DEFAULT_DEV_KEY),
            region: "Local",
            production: false,
        },
    }
}

/// Get all available server configurations
///
/// Returns a map of all configured server endpoints with their configurations.
/// Useful for displaying server selection UI in mobile apps.
///
/// # Example
///
/// ```rust
/// use nooshdaroo::embedded_keys::get_all_servers;
///
/// let servers = get_all_servers();
/// for (endpoint, config) in servers {
///     println!("{:?}: {} at {}", endpoint, config.name, config.address);
/// }
/// ```
pub fn get_all_servers() -> HashMap<ServerEndpoint, ServerConfig> {
    let mut servers = HashMap::new();

    for endpoint in &[
        ServerEndpoint::Primary,
        ServerEndpoint::Fallback,
        ServerEndpoint::EuropeWest,
        ServerEndpoint::AsiaPacific,
        ServerEndpoint::NorthAmericaEast,
        ServerEndpoint::Development,
    ] {
        servers.insert(*endpoint, get_server_config(*endpoint));
    }

    servers
}

/// Get production servers only (excludes development)
///
/// Returns only servers marked as production-ready.
pub fn get_production_servers() -> Vec<(ServerEndpoint, ServerConfig)> {
    get_all_servers()
        .into_iter()
        .filter(|(_, config)| config.production)
        .collect()
}

// ============================================================================
// DEFAULT EMBEDDED KEYS (Replace these with your actual production keys!)
// ============================================================================
//
// SECURITY NOTE: These are example keys for demonstration.
//
// For production deployment:
// 1. Generate real server keys: `nooshdaroo genkey`
// 2. Replace these constants with your server's public keys
// 3. Or use environment variables at build time (recommended)
//
// Build with environment variables:
//   export NOOSHDAROO_PRIMARY_KEY="your_actual_base64_key_here"
//   cargo build --release
// ============================================================================

/// Default primary server public key
///
/// **REPLACE WITH YOUR ACTUAL PRODUCTION KEY!**
const DEFAULT_PRIMARY_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// Default fallback server public key
///
/// **REPLACE WITH YOUR ACTUAL PRODUCTION KEY!**
const DEFAULT_FALLBACK_KEY: &str = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

/// Default Europe West server public key
///
/// **REPLACE WITH YOUR ACTUAL PRODUCTION KEY!**
const DEFAULT_EU_KEY: &str = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";

/// Default Asia Pacific server public key
///
/// **REPLACE WITH YOUR ACTUAL PRODUCTION KEY!**
const DEFAULT_AP_KEY: &str = "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD";

/// Default North America server public key
///
/// **REPLACE WITH YOUR ACTUAL PRODUCTION KEY!**
const DEFAULT_NA_KEY: &str = "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE";

/// Default development server public key
///
/// This is safe to keep as a default since it's only for local development
const DEFAULT_DEV_KEY: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_production_key() {
        let key = get_production_key(ServerEndpoint::Primary);
        assert!(!key.is_empty());
    }

    #[test]
    fn test_get_server_config() {
        let config = get_server_config(ServerEndpoint::Primary);
        assert_eq!(config.name, "Production Primary");
        assert!(!config.address.is_empty());
        assert!(!config.public_key.is_empty());
    }

    #[test]
    fn test_get_all_servers() {
        let servers = get_all_servers();
        assert!(servers.len() >= 6); // At least 6 endpoints defined
        assert!(servers.contains_key(&ServerEndpoint::Primary));
        assert!(servers.contains_key(&ServerEndpoint::Development));
    }

    #[test]
    fn test_get_production_servers() {
        let prod_servers = get_production_servers();

        // All production servers should have production flag set
        for (_, config) in &prod_servers {
            assert!(config.production);
        }

        // Development server should not be in production list
        assert!(!prod_servers.iter().any(|(e, _)| *e == ServerEndpoint::Development));
    }

    #[test]
    fn test_server_regions() {
        let eu_config = get_server_config(ServerEndpoint::EuropeWest);
        assert!(eu_config.region.contains("Europe"));

        let ap_config = get_server_config(ServerEndpoint::AsiaPacific);
        assert!(ap_config.region.contains("Asia"));
    }
}
