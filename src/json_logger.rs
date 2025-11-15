//! Structured JSON logging for jq parsing
//!
//! This module provides JSON-formatted logging that can be easily parsed
//! with jq and other JSON tools for analysis and monitoring.

use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// Log level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogLevel::Debug => write!(f, "DEBUG"),
            LogLevel::Info => write!(f, "INFO"),
            LogLevel::Warn => write!(f, "WARN"),
            LogLevel::Error => write!(f, "ERROR"),
        }
    }
}

/// Structured log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// Timestamp (RFC3339)
    pub timestamp: String,

    /// Log level
    pub level: LogLevel,

    /// Component/module name
    pub component: String,

    /// Log message
    pub message: String,

    /// Additional structured data
    #[serde(flatten)]
    pub data: serde_json::Value,
}

impl LogEntry {
    /// Create a new log entry
    pub fn new(
        level: LogLevel,
        component: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            timestamp: humantime::format_rfc3339(SystemTime::now()).to_string(),
            level,
            component: component.into(),
            message: message.into(),
            data: serde_json::Value::Null,
        }
    }

    /// Add structured data
    pub fn with_data(mut self, data: serde_json::Value) -> Self {
        self.data = data;
        self
    }

    /// Add key-value pair to data
    pub fn add_field(mut self, key: &str, value: serde_json::Value) -> Self {
        if let serde_json::Value::Object(ref mut map) = self.data {
            map.insert(key.to_string(), value);
        } else {
            let mut map = serde_json::Map::new();
            map.insert(key.to_string(), value);
            self.data = serde_json::Value::Object(map);
        }
        self
    }

    /// Output as JSON line
    pub fn emit(&self) {
        if let Ok(json) = serde_json::to_string(self) {
            println!("{}", json);
        }
    }
}

/// JSON logger
pub struct JsonLogger;

impl JsonLogger {
    /// Log debug message
    pub fn debug(component: impl Into<String>, message: impl Into<String>) {
        LogEntry::new(LogLevel::Debug, component, message).emit();
    }

    /// Log debug with data
    pub fn debug_data(
        component: impl Into<String>,
        message: impl Into<String>,
        data: serde_json::Value,
    ) {
        LogEntry::new(LogLevel::Debug, component, message)
            .with_data(data)
            .emit();
    }

    /// Log info message
    pub fn info(component: impl Into<String>, message: impl Into<String>) {
        LogEntry::new(LogLevel::Info, component, message).emit();
    }

    /// Log info with data
    pub fn info_data(
        component: impl Into<String>,
        message: impl Into<String>,
        data: serde_json::Value,
    ) {
        LogEntry::new(LogLevel::Info, component, message)
            .with_data(data)
            .emit();
    }

    /// Log warning message
    pub fn warn(component: impl Into<String>, message: impl Into<String>) {
        LogEntry::new(LogLevel::Warn, component, message).emit();
    }

    /// Log warning with data
    pub fn warn_data(
        component: impl Into<String>,
        message: impl Into<String>,
        data: serde_json::Value,
    ) {
        LogEntry::new(LogLevel::Warn, component, message)
            .with_data(data)
            .emit();
    }

    /// Log error message
    pub fn error(component: impl Into<String>, message: impl Into<String>) {
        LogEntry::new(LogLevel::Error, component, message).emit();
    }

    /// Log error with data
    pub fn error_data(
        component: impl Into<String>,
        message: impl Into<String>,
        data: serde_json::Value,
    ) {
        LogEntry::new(LogLevel::Error, component, message)
            .with_data(data)
            .emit();
    }

    /// Log connection event
    pub fn connection(
        component: impl Into<String>,
        peer_addr: &str,
        port: u16,
        protocol: &str,
        success: bool,
    ) {
        let data = serde_json::json!({
            "event_type": "connection",
            "peer_addr": peer_addr,
            "port": port,
            "protocol": protocol,
            "success": success,
        });

        let level = if success {
            LogLevel::Info
        } else {
            LogLevel::Warn
        };

        LogEntry::new(level, component, "Connection attempt")
            .with_data(data)
            .emit();
    }

    /// Log protocol switch
    pub fn protocol_switch(
        component: impl Into<String>,
        from: &str,
        to: &str,
        reason: &str,
    ) {
        let data = serde_json::json!({
            "event_type": "protocol_switch",
            "from_protocol": from,
            "to_protocol": to,
            "reason": reason,
        });

        LogEntry::new(LogLevel::Info, component, "Protocol switched")
            .with_data(data)
            .emit();
    }

    /// Log traffic stats
    pub fn traffic_stats(
        component: impl Into<String>,
        bytes_sent: u64,
        bytes_recv: u64,
        duration_ms: u64,
        protocol: &str,
    ) {
        let data = serde_json::json!({
            "event_type": "traffic_stats",
            "bytes_sent": bytes_sent,
            "bytes_received": bytes_recv,
            "duration_ms": duration_ms,
            "protocol": protocol,
            "throughput_mbps": (bytes_sent + bytes_recv) as f64 / (duration_ms as f64 / 1000.0) / 1_000_000.0,
        });

        LogEntry::new(LogLevel::Info, component, "Traffic statistics")
            .with_data(data)
            .emit();
    }

    /// Log path test result
    pub fn path_test(
        component: impl Into<String>,
        addr: &str,
        protocol: &str,
        latency_ms: u64,
        success: bool,
        score: f64,
    ) {
        let data = serde_json::json!({
            "event_type": "path_test",
            "address": addr,
            "protocol": protocol,
            "latency_ms": latency_ms,
            "success": success,
            "score": score,
        });

        LogEntry::new(LogLevel::Info, component, "Path test result")
            .with_data(data)
            .emit();
    }

    /// Log server startup
    pub fn server_start(
        component: impl Into<String>,
        ports: &[u16],
        protocols: &[String],
    ) {
        let data = serde_json::json!({
            "event_type": "server_start",
            "ports": ports,
            "protocols": protocols,
            "port_count": ports.len(),
        });

        LogEntry::new(LogLevel::Info, component, "Multi-port server started")
            .with_data(data)
            .emit();
    }

    /// Log detection risk
    pub fn detection_risk(
        component: impl Into<String>,
        protocol: &str,
        port: u16,
        risk_score: f64,
        factors: &[String],
    ) {
        let data = serde_json::json!({
            "event_type": "detection_risk",
            "protocol": protocol,
            "port": port,
            "risk_score": risk_score,
            "risk_factors": factors,
        });

        let level = if risk_score > 0.7 {
            LogLevel::Warn
        } else {
            LogLevel::Debug
        };

        LogEntry::new(level, component, "Detection risk assessment")
            .with_data(data)
            .emit();
    }
}

/// Macros for convenient JSON logging
#[macro_export]
macro_rules! jlog_debug {
    ($component:expr, $message:expr) => {
        $crate::json_logger::JsonLogger::debug($component, $message)
    };
    ($component:expr, $message:expr, $data:expr) => {
        $crate::json_logger::JsonLogger::debug_data($component, $message, $data)
    };
}

#[macro_export]
macro_rules! jlog_info {
    ($component:expr, $message:expr) => {
        $crate::json_logger::JsonLogger::info($component, $message)
    };
    ($component:expr, $message:expr, $data:expr) => {
        $crate::json_logger::JsonLogger::info_data($component, $message, $data)
    };
}

#[macro_export]
macro_rules! jlog_warn {
    ($component:expr, $message:expr) => {
        $crate::json_logger::JsonLogger::warn($component, $message)
    };
    ($component:expr, $message:expr, $data:expr) => {
        $crate::json_logger::JsonLogger::warn_data($component, $message, $data)
    };
}

#[macro_export]
macro_rules! jlog_error {
    ($component:expr, $message:expr) => {
        $crate::json_logger::JsonLogger::error($component, $message)
    };
    ($component:expr, $message:expr, $data:expr) => {
        $crate::json_logger::JsonLogger::error_data($component, $message, $data)
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_entry_creation() {
        let entry = LogEntry::new(LogLevel::Info, "test", "Test message");
        assert_eq!(entry.level, LogLevel::Info);
        assert_eq!(entry.component, "test");
        assert_eq!(entry.message, "Test message");
    }

    #[test]
    fn test_log_entry_with_data() {
        let data = serde_json::json!({
            "key": "value",
            "number": 42
        });

        let entry = LogEntry::new(LogLevel::Debug, "test", "Test")
            .with_data(data.clone());

        assert_eq!(entry.data, data);
    }

    #[test]
    fn test_json_serialization() {
        let entry = LogEntry::new(LogLevel::Error, "network", "Connection failed")
            .add_field("port", serde_json::json!(443))
            .add_field("protocol", serde_json::json!("https"));

        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"level\":\"ERROR\""));
        assert!(json.contains("\"component\":\"network\""));
        assert!(json.contains("\"port\":443"));
    }
}
