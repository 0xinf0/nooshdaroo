//! Mobile device support (iOS and Android FFI)

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::sync::{Arc, Mutex};

use super::config::NooshdarooConfig;
use super::{NooshdarooClient, NooshdarooServer};

/// Global client instance for FFI
static GLOBAL_CLIENT: Mutex<Option<Arc<NooshdarooClient>>> = Mutex::new(None);

/// Global server instance for FFI
static GLOBAL_SERVER: Mutex<Option<Arc<NooshdarooServer>>> = Mutex::new(None);

/// Error codes for FFI
#[repr(C)]
pub enum NooshdarooError {
    Success = 0,
    InvalidConfig = -1,
    AlreadyRunning = -2,
    NotRunning = -3,
    NetworkError = -4,
    Unknown = -99,
}

/// Simple configuration for mobile apps
#[repr(C)]
pub struct NooshdarooMobileConfig {
    /// Proxy listen address (e.g., "127.0.0.1:1080")
    pub listen_addr: *const c_char,

    /// Server address to connect to
    pub server_addr: *const c_char,

    /// Encryption password
    pub password: *const c_char,

    /// Protocol to use (e.g., "https", "dns", "quic")
    pub protocol: *const c_char,

    /// Proxy type: 0=SOCKS5, 1=HTTP, 2=Transparent
    pub proxy_type: c_int,

    /// Enable shape-shifting (0=false, 1=true)
    pub enable_shapeshift: c_int,

    /// Shape-shift strategy: 0=fixed, 1=time-based, 2=traffic-based, 3=adaptive
    pub shapeshift_strategy: c_int,
}

/// Initialize Nooshdaroo client (for mobile apps)
///
/// # Safety
/// This function is unsafe because it deals with raw pointers from FFI
#[no_mangle]
pub unsafe extern "C" fn nooshdaroo_init(config: *const NooshdarooMobileConfig) -> c_int {
    if config.is_null() {
        return NooshdarooError::InvalidConfig as c_int;
    }

    let config = &*config;

    // Convert C strings to Rust strings
    let listen_addr = if !config.listen_addr.is_null() {
        CStr::from_ptr(config.listen_addr).to_string_lossy().to_string()
    } else {
        "127.0.0.1:1080".to_string()
    };

    let server_addr = if !config.server_addr.is_null() {
        CStr::from_ptr(config.server_addr).to_string_lossy().to_string()
    } else {
        return NooshdarooError::InvalidConfig as c_int;
    };

    let password = if !config.password.is_null() {
        CStr::from_ptr(config.password).to_string_lossy().to_string()
    } else {
        return NooshdarooError::InvalidConfig as c_int;
    };

    let protocol = if !config.protocol.is_null() {
        CStr::from_ptr(config.protocol).to_string_lossy().to_string()
    } else {
        "https".to_string()
    };

    // Create Nooshdaroo configuration
    // TODO: Build proper NooshdarooConfig from mobile config
    log::info!("Nooshdaroo mobile init: {} -> {}", listen_addr, server_addr);
    log::info!("Protocol: {}", protocol);

    NooshdarooError::Success as c_int
}

/// Start Nooshdaroo client
#[no_mangle]
pub extern "C" fn nooshdaroo_start() -> c_int {
    log::info!("Nooshdaroo mobile start");

    // TODO: Start the client
    NooshdarooError::Success as c_int
}

/// Stop Nooshdaroo client
#[no_mangle]
pub extern "C" fn nooshdaroo_stop() -> c_int {
    log::info!("Nooshdaroo mobile stop");

    // TODO: Stop the client
    NooshdarooError::Success as c_int
}

/// Get connection status
/// Returns: 0=disconnected, 1=connecting, 2=connected, -1=error
#[no_mangle]
pub extern "C" fn nooshdaroo_status() -> c_int {
    // TODO: Return actual status
    2 // Connected
}

/// Get current protocol being used
///
/// # Safety
/// Caller must free the returned string with nooshdaroo_free_string
#[no_mangle]
pub extern "C" fn nooshdaroo_get_protocol() -> *mut c_char {
    let protocol = "https"; // TODO: Get actual protocol
    CString::new(protocol).unwrap().into_raw()
}

/// Get statistics (JSON format)
///
/// # Safety
/// Caller must free the returned string with nooshdaroo_free_string
#[no_mangle]
pub extern "C" fn nooshdaroo_get_stats() -> *mut c_char {
    let stats = r#"{"bytes_sent":0,"bytes_received":0,"packets_sent":0,"packets_received":0}"#;
    CString::new(stats).unwrap().into_raw()
}

/// Free a string returned by Nooshdaroo
///
/// # Safety
/// This function is unsafe because it takes ownership of a raw pointer
#[no_mangle]
pub unsafe extern "C" fn nooshdaroo_free_string(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}

/// Set log level (0=error, 1=warn, 2=info, 3=debug, 4=trace)
#[no_mangle]
pub extern "C" fn nooshdaroo_set_log_level(level: c_int) {
    let level_str = match level {
        0 => "error",
        1 => "warn",
        2 => "info",
        3 => "debug",
        4 => "trace",
        _ => "info",
    };

    std::env::set_var("RUST_LOG", level_str);
}

/// iOS specific: Start in background mode
#[cfg(target_os = "ios")]
#[no_mangle]
pub extern "C" fn nooshdaroo_ios_background_start() -> c_int {
    log::info!("Starting Nooshdaroo in iOS background mode");
    NooshdarooError::Success as c_int
}

/// Android specific: Get VPN service parameters
#[cfg(target_os = "android")]
#[no_mangle]
pub extern "C" fn nooshdaroo_android_vpn_params(
    out_tun_fd: *mut c_int,
    out_mtu: *mut c_int,
) -> c_int {
    unsafe {
        if !out_tun_fd.is_null() {
            *out_tun_fd = -1; // TODO: Set actual TUN fd
        }
        if !out_mtu.is_null() {
            *out_mtu = 1500;
        }
    }
    NooshdarooError::Success as c_int
}

// ============================================================================
// High-level Mobile API (for Swift/Kotlin)
// ============================================================================

/// Mobile-friendly configuration builder
pub struct MobileConfigBuilder {
    listen_addr: String,
    server_addr: String,
    password: String,
    protocol: String,
    proxy_type: String,
}

impl MobileConfigBuilder {
    pub fn new() -> Self {
        Self {
            listen_addr: "127.0.0.1:1080".to_string(),
            server_addr: String::new(),
            password: String::new(),
            protocol: "https".to_string(),
            proxy_type: "socks5".to_string(),
        }
    }

    pub fn listen_addr(mut self, addr: &str) -> Self {
        self.listen_addr = addr.to_string();
        self
    }

    pub fn server_addr(mut self, addr: &str) -> Self {
        self.server_addr = addr.to_string();
        self
    }

    pub fn password(mut self, password: &str) -> Self {
        self.password = password.to_string();
        self
    }

    pub fn protocol(mut self, protocol: &str) -> Self {
        self.protocol = protocol.to_string();
        self
    }

    pub fn proxy_type(mut self, proxy_type: &str) -> Self {
        self.proxy_type = proxy_type.to_string();
        self
    }

    pub fn build(self) -> Result<NooshdarooConfig, String> {
        // TODO: Build actual NooshdarooConfig
        Err("Not implemented yet".to_string())
    }
}

impl Default for MobileConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mobile_config_builder() {
        let builder = MobileConfigBuilder::new()
            .listen_addr("127.0.0.1:1080")
            .server_addr("example.com:443")
            .password("test-password")
            .protocol("https");

        // Just test that builder works
        assert_eq!(builder.protocol, "https");
    }
}
