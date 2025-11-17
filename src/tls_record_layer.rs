//! TLS 1.3 Record Layer Emulation
//!
//! Wraps Noise-encrypted data in proper TLS 1.3 Application Data records
//! to defeat deep packet inspection. This provides full session emulation,
//! not just handshake wrapping.
//!
//! Based on RFC 8446 (TLS 1.3)

use std::io::{Error, ErrorKind};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// TLS Content Type (RFC 8446 §5.1)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TlsContentType {
    /// ChangeCipherSpec (legacy compatibility)
    ChangeCipherSpec = 0x14,
    /// Alert protocol
    Alert = 0x15,
    /// Handshake protocol
    Handshake = 0x16,
    /// Application data (encrypted payload)
    ApplicationData = 0x17,
    /// Heartbeat (optional)
    Heartbeat = 0x18,
}

/// TLS Alert levels
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum TlsAlertLevel {
    Warning = 0x01,
    Fatal = 0x02,
}

/// TLS Alert descriptions
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum TlsAlertDescription {
    CloseNotify = 0x00,
    UnexpectedMessage = 0x0A,
    BadRecordMac = 0x14,
    RecordOverflow = 0x16,
    HandshakeFailure = 0x28,
}

/// Maximum TLS record size (RFC 8446 §5.1)
const MAX_TLS_RECORD_SIZE: usize = 16384; // 2^14 bytes

/// TLS legacy version (appears in record header for compatibility)
const TLS_LEGACY_VERSION: [u8; 2] = [0x03, 0x03]; // TLS 1.2

/// TLS 1.3 Record Layer implementation
pub struct TlsRecordLayer {
    /// Maximum record size for fragmentation
    max_record_size: usize,

    /// Enable random padding
    add_padding: bool,

    /// Min/max padding bytes
    padding_range: (usize, usize),
}

impl Default for TlsRecordLayer {
    fn default() -> Self {
        Self {
            max_record_size: MAX_TLS_RECORD_SIZE,
            add_padding: true,
            padding_range: (0, 64), // 0-64 bytes random padding
        }
    }
}

impl TlsRecordLayer {
    /// Create a new TLS record layer
    pub fn new() -> Self {
        Self::default()
    }

    /// Configure padding
    pub fn with_padding(mut self, min: usize, max: usize) -> Self {
        self.add_padding = true;
        self.padding_range = (min, max);
        self
    }

    /// Disable padding
    pub fn without_padding(mut self) -> Self {
        self.add_padding = false;
        self
    }

    /// Wrap Noise encrypted payload in TLS Application Data record
    pub fn wrap_application_data(&self, noise_payload: &[u8]) -> Vec<u8> {
        // Add optional padding
        let padding_size = if self.add_padding {
            use rand::Rng;
            rand::thread_rng().gen_range(self.padding_range.0..=self.padding_range.1)
        } else {
            0
        };

        let total_payload_size = noise_payload.len() + padding_size;
        let mut record = Vec::with_capacity(5 + total_payload_size);

        // TLS Record Header (5 bytes)
        record.push(TlsContentType::ApplicationData as u8); // Content type
        record.extend_from_slice(&TLS_LEGACY_VERSION);      // Legacy version (0x0303)
        record.extend_from_slice(&(total_payload_size as u16).to_be_bytes()); // Length

        // Payload (Noise encrypted data)
        record.extend_from_slice(noise_payload);

        // Optional padding (zeros)
        if padding_size > 0 {
            record.resize(record.len() + padding_size, 0);
        }

        record
    }

    /// Fragment large payload into multiple TLS records
    pub fn fragment_and_wrap(&self, noise_payload: &[u8]) -> Vec<Vec<u8>> {
        let mut records = Vec::new();
        let mut offset = 0;

        while offset < noise_payload.len() {
            // Calculate this record's size (vary it slightly for realism)
            let remaining = noise_payload.len() - offset;
            let record_size = if remaining > self.max_record_size {
                // Vary record size slightly to avoid patterns
                use rand::Rng;
                let variation = rand::thread_rng().gen_range(0..256);
                (self.max_record_size - variation).min(remaining)
            } else {
                remaining
            };

            let chunk = &noise_payload[offset..offset + record_size];
            records.push(self.wrap_application_data(chunk));
            offset += record_size;
        }

        records
    }

    /// Read and unwrap TLS Application Data record
    pub async fn read_application_data<S>(&self, stream: &mut S) -> Result<Vec<u8>, Error>
    where
        S: AsyncRead + Unpin,
    {
        // Read TLS record header (5 bytes)
        let mut header = [0u8; 5];
        stream.read_exact(&mut header).await?;

        let content_type = header[0];
        let version = &header[1..3];
        let length = u16::from_be_bytes([header[3], header[4]]) as usize;

        // Validate content type
        if content_type != TlsContentType::ApplicationData as u8 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Expected Application Data (0x17), got 0x{:02x}", content_type),
            ));
        }

        // Validate version
        if version != TLS_LEGACY_VERSION {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Invalid TLS version: {:02x}{:02x}", version[0], version[1]),
            ));
        }

        // Validate length
        if length > MAX_TLS_RECORD_SIZE {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Record too large: {} > {}", length, MAX_TLS_RECORD_SIZE),
            ));
        }

        // Read payload
        let mut payload = vec![0u8; length];
        stream.read_exact(&mut payload).await?;

        // Remove padding (if any) - padding is trailing zeros
        // For now, we don't remove padding as Noise data is opaque
        // The receiver doesn't need to know about our padding

        Ok(payload)
    }

    /// Write TLS Application Data records
    pub async fn write_application_data<S>(&self, stream: &mut S, noise_payload: &[u8]) -> Result<(), Error>
    where
        S: AsyncWrite + Unpin,
    {
        // Fragment if needed
        if noise_payload.len() > self.max_record_size {
            let records = self.fragment_and_wrap(noise_payload);
            for record in records {
                stream.write_all(&record).await?;
            }
        } else {
            let record = self.wrap_application_data(noise_payload);
            stream.write_all(&record).await?;
        }

        stream.flush().await?;
        Ok(())
    }

    /// Generate TLS Alert record
    pub fn generate_alert(&self, level: TlsAlertLevel, description: TlsAlertDescription) -> Vec<u8> {
        let mut alert = Vec::with_capacity(7);

        // TLS Record Header
        alert.push(TlsContentType::Alert as u8);
        alert.extend_from_slice(&TLS_LEGACY_VERSION);
        alert.extend_from_slice(&[0x00, 0x02]); // Length = 2

        // Alert payload
        alert.push(level as u8);
        alert.push(description as u8);

        alert
    }

    /// Send close_notify alert (graceful shutdown)
    pub async fn send_close_notify<S>(&self, stream: &mut S) -> Result<(), Error>
    where
        S: AsyncWrite + Unpin,
    {
        let alert = self.generate_alert(TlsAlertLevel::Warning, TlsAlertDescription::CloseNotify);
        stream.write_all(&alert).await?;
        stream.flush().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wrap_application_data() {
        let tls = TlsRecordLayer::new().without_padding();
        let payload = b"Hello, World!";
        let record = tls.wrap_application_data(payload);

        // Check header
        assert_eq!(record[0], TlsContentType::ApplicationData as u8);
        assert_eq!(&record[1..3], &TLS_LEGACY_VERSION);
        assert_eq!(u16::from_be_bytes([record[3], record[4]]), payload.len() as u16);

        // Check payload
        assert_eq!(&record[5..], payload);
    }

    #[test]
    fn test_fragmentation() {
        let tls = TlsRecordLayer::new().without_padding();
        let large_payload = vec![0x42; 20000]; // Larger than max record size
        let records = tls.fragment_and_wrap(&large_payload);

        assert!(records.len() > 1, "Should fragment large payload");

        // Verify each record
        for record in records {
            assert_eq!(record[0], TlsContentType::ApplicationData as u8);
            let length = u16::from_be_bytes([record[3], record[4]]) as usize;
            assert!(length <= MAX_TLS_RECORD_SIZE);
        }
    }

    #[test]
    fn test_alert_generation() {
        let tls = TlsRecordLayer::new();
        let alert = tls.generate_alert(TlsAlertLevel::Warning, TlsAlertDescription::CloseNotify);

        assert_eq!(alert[0], TlsContentType::Alert as u8);
        assert_eq!(&alert[1..3], &TLS_LEGACY_VERSION);
        assert_eq!(alert[5], TlsAlertLevel::Warning as u8);
        assert_eq!(alert[6], TlsAlertDescription::CloseNotify as u8);
    }
}
