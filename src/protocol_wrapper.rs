//! Protocol wrapping layer for obfuscating Noise encrypted traffic
//!
//! This module wraps Noise Protocol encrypted frames with protocol-specific
//! headers to make traffic appear as legitimate HTTPS, DNS, SSH, etc.

use std::io::{Error, ErrorKind};
use crate::protocol::ProtocolId;
use crate::traffic::TrafficShaper;
use crate::psf::{PsfInterpreter, ProtocolFrame};

// Embed all PSF files at compile time
const DNS_PSF: &str = include_str!("../protocols/dns/dns.psf");
const HTTPS_PSF: &str = include_str!("../protocols/http/https.psf");
const SSH_PSF: &str = include_str!("../protocols/ssh/ssh.psf");
const WEBSOCKET_PSF: &str = include_str!("../protocols/http/websocket.psf");

/// Wraps Noise encrypted frames with protocol-specific headers
pub struct ProtocolWrapper {
    protocol_id: ProtocolId,
    shaper: Option<TrafficShaper>,
    psf_interpreter: Option<PsfInterpreter>,
    client_frame: Option<ProtocolFrame>,
    server_frame: Option<ProtocolFrame>,
}

/// Map protocol name to embedded PSF content
fn get_psf_content(protocol: &str) -> Option<&'static str> {
    match protocol.to_lowercase().as_str() {
        // TLS/HTTPS
        "https" | "tls" | "tls13" => Some(HTTPS_PSF),

        // DNS
        "dns" => Some(DNS_PSF),

        // SSH
        "ssh" => Some(SSH_PSF),

        // HTTP variants
        "websocket" | "ws" => Some(WEBSOCKET_PSF),

        // Other protocols not yet embedded will use raw Noise frames
        _ => None,
    }
}

impl ProtocolWrapper {
    /// Create a new protocol wrapper
    pub fn new(protocol_id: ProtocolId, shaper: Option<TrafficShaper>) -> Self {
        // Try to load PSF interpreter for this protocol
        let protocol_str = protocol_id.as_str();

        let (psf_interpreter, client_frame, server_frame) = if let Some(psf_content) = get_psf_content(protocol_str) {
            match PsfInterpreter::load_from_string(psf_content) {
                Ok(interpreter) => {
                    let client = interpreter.create_frame("CLIENT", "DATA").ok();
                    let server = interpreter.create_frame("SERVER", "DATA").ok();

                    if client.is_some() && server.is_some() {
                        log::info!("Successfully loaded embedded PSF for protocol: {}", protocol_str);
                        (Some(interpreter), client, server)
                    } else {
                        log::warn!("Failed to create frames for protocol: {}", protocol_str);
                        (None, None, None)
                    }
                }
                Err(e) => {
                    log::warn!("Failed to load embedded PSF for {}: {}", protocol_str, e);
                    (None, None, None)
                }
            }
        } else {
            log::debug!("No embedded PSF content found for protocol: {}", protocol_str);
            (None, None, None)
        };

        Self {
            protocol_id,
            shaper,
            psf_interpreter,
            client_frame,
            server_frame,
        }
    }

    /// Wrap Noise encrypted data with protocol headers
    ///
    /// Takes raw Noise encrypted data (payload + 16-byte Poly1305 MAC)
    /// and wraps it with protocol-specific headers using PSF
    pub fn wrap(&mut self, noise_data: &[u8]) -> Result<Vec<u8>, Error> {
        // For HTTPS/TLS, use hardcoded implementation for compatibility
        // (PSF files define separate auth_tag which conflicts with Noise's built-in MAC)
        match self.protocol_id.as_str() {
            "https" | "tls" => return self.wrap_https(noise_data),
            _ => {}
        }

        // Try PSF-based wrapping for other protocols
        if let Some(ref frame) = self.client_frame {
            match frame.wrap(noise_data) {
                Ok(wrapped) => {
                    log::debug!(
                        "Wrapped {} bytes of Noise data into {} bytes using PSF for {}",
                        noise_data.len(),
                        wrapped.len(),
                        self.protocol_id.as_str()
                    );
                    return Ok(wrapped);
                }
                Err(e) => {
                    log::warn!("PSF wrapping failed for {}: {}", self.protocol_id.as_str(), e);
                }
            }
        }

        // Final fallback: pass through raw for unsupported protocols
        log::warn!("Protocol {} not supported for wrapping, using raw Noise frames", self.protocol_id.as_str());
        Ok(noise_data.to_vec())
    }

    /// Unwrap protocol headers to get raw Noise encrypted data
    pub fn unwrap(&self, wrapped_data: &[u8]) -> Result<Vec<u8>, Error> {
        // For HTTPS/TLS, use hardcoded implementation for compatibility
        // (PSF files define separate auth_tag which conflicts with Noise's built-in MAC)
        match self.protocol_id.as_str() {
            "https" | "tls" => return self.unwrap_https(wrapped_data),
            _ => {}
        }

        // Try PSF-based unwrapping for other protocols
        if let Some(ref frame) = self.server_frame {
            match frame.unwrap(wrapped_data) {
                Ok(unwrapped) => {
                    log::debug!(
                        "Unwrapped {} bytes of protocol data into {} bytes of Noise data using PSF for {}",
                        wrapped_data.len(),
                        unwrapped.len(),
                        self.protocol_id.as_str()
                    );
                    return Ok(unwrapped);
                }
                Err(e) => {
                    log::warn!("PSF unwrapping failed for {}: {}", self.protocol_id.as_str(), e);
                }
            }
        }

        // Final fallback: pass through for unsupported protocols
        Ok(wrapped_data.to_vec())
    }

    /// Wrap as HTTPS/TLS 1.3 Application Data
    ///
    /// Format (from https.psf):
    /// - content_type: u8 = 0x17 (application data)
    /// - version: u16 = 0x0303 (TLS 1.2 for compatibility)
    /// - length: u16 = encrypted_data.len()
    /// - encrypted_data: [u8; length]
    ///
    /// Note: Noise data already includes the Poly1305 MAC at the end
    fn wrap_https(&mut self, noise_data: &[u8]) -> Result<Vec<u8>, Error> {
        if noise_data.len() > 0xFFFF {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Noise data too large for TLS record",
            ));
        }

        let payload_len = noise_data.len() as u16;
        let mut frame = Vec::with_capacity(5 + noise_data.len());

        // TLS Application Data header
        frame.push(0x17); // content_type = application_data
        frame.extend_from_slice(&0x0303u16.to_be_bytes()); // version = TLS 1.2
        frame.extend_from_slice(&payload_len.to_be_bytes()); // length
        frame.extend_from_slice(noise_data); // encrypted payload + MAC

        log::debug!(
            "Wrapped {} bytes of Noise data into {} bytes of TLS Application Data",
            noise_data.len(),
            frame.len()
        );

        Ok(frame)
    }

    /// Unwrap HTTPS/TLS 1.3 Application Data to get Noise encrypted data
    fn unwrap_https(&self, wrapped_data: &[u8]) -> Result<Vec<u8>, Error> {
        if wrapped_data.len() < 5 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "TLS frame too short",
            ));
        }

        // Validate TLS header
        if wrapped_data[0] != 0x17 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Invalid TLS content type: expected 0x17, got 0x{:02x}", wrapped_data[0]),
            ));
        }

        let version = u16::from_be_bytes([wrapped_data[1], wrapped_data[2]]);
        if version != 0x0303 {
            log::warn!("Unexpected TLS version: 0x{:04x}, expected 0x0303", version);
        }

        let length = u16::from_be_bytes([wrapped_data[3], wrapped_data[4]]) as usize;

        if wrapped_data.len() < 5 + length {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("TLS frame incomplete: expected {} bytes, got {}", 5 + length, wrapped_data.len()),
            ));
        }

        // Extract Noise encrypted data (includes MAC)
        let noise_data = &wrapped_data[5..5 + length];

        log::debug!(
            "Unwrapped {} bytes of TLS Application Data into {} bytes of Noise data",
            wrapped_data.len(),
            noise_data.len()
        );

        Ok(noise_data.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_https_wrap_unwrap_roundtrip() {
        let mut wrapper = ProtocolWrapper::new(ProtocolId::from("https"), None);

        // Simulate Noise encrypted data (1000 bytes payload + 16 byte MAC)
        let noise_data = vec![0xAB; 1016];

        // Wrap
        let wrapped = wrapper.wrap(&noise_data).unwrap();

        // Should be 5 bytes header + 1016 bytes data
        assert_eq!(wrapped.len(), 1021);

        // Check TLS header
        assert_eq!(wrapped[0], 0x17); // content_type
        assert_eq!(wrapped[1], 0x03); // version hi
        assert_eq!(wrapped[2], 0x03); // version lo
        assert_eq!(u16::from_be_bytes([wrapped[3], wrapped[4]]), 1016); // length

        // Unwrap
        let unwrapped = wrapper.unwrap(&wrapped).unwrap();

        // Should match original
        assert_eq!(unwrapped, noise_data);
    }

    #[test]
    fn test_https_unwrap_invalid_content_type() {
        let wrapper = ProtocolWrapper::new(ProtocolId::from("https"), None);

        // Invalid content type
        let bad_data = vec![0x16, 0x03, 0x03, 0x00, 0x10];

        let result = wrapper.unwrap(&bad_data);
        assert!(result.is_err());
    }
}
