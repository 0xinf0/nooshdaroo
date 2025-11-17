//! PSF Interpreter - Loads PSF files and creates runtime protocol frames

use super::parser::Parser;
use super::types::{PsfSpec, ProtocolFrame};
use std::fs;
use std::io::Error;
use std::path::Path;

pub struct PsfInterpreter {
    spec: PsfSpec,
}

impl PsfInterpreter {
    /// Load and parse a PSF file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let content = fs::read_to_string(path)?;
        Self::load_from_string(&content)
    }

    /// Parse PSF from string
    pub fn load_from_string(content: &str) -> Result<Self, Error> {
        let mut parser = Parser::new(content)
            .map_err(|e| Error::new(std::io::ErrorKind::InvalidData, e))?;

        let spec = parser.parse()
            .map_err(|e| Error::new(std::io::ErrorKind::InvalidData, e))?;

        Ok(Self { spec })
    }

    /// Create a protocol frame for a specific role and phase
    pub fn create_frame(&self, role: &str, phase: &str) -> Result<ProtocolFrame, Error> {
        // Find matching sequence rule
        let sequence = self.spec.sequence.iter()
            .find(|s| {
                let role_match = match s.role {
                    super::types::Role::Client => role.to_lowercase() == "client",
                    super::types::Role::Server => role.to_lowercase() == "server",
                };
                role_match && s.phase.to_lowercase() == phase.to_lowercase()
            })
            .ok_or_else(|| Error::new(
                std::io::ErrorKind::NotFound,
                format!("No sequence found for role={} phase={}", role, phase)
            ))?;

        // Get format
        let format = self.spec.formats.get(&sequence.format)
            .ok_or_else(|| Error::new(
                std::io::ErrorKind::NotFound,
                format!("Format '{}' not found", sequence.format)
            ))?;

        // Get semantics for this format
        let semantics = self.spec.semantics.iter()
            .filter(|s| s.format == sequence.format)
            .cloned()
            .collect();

        Ok(ProtocolFrame::new(format.clone(), semantics))
    }

    /// Get spec for inspection
    pub fn spec(&self) -> &PsfSpec {
        &self.spec
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tls13() {
        let psf = r#"
@SEGMENT.FORMATS

  DEFINE Tls13Record
    { NAME: content_type   ; TYPE: u8 },
    { NAME: legacy_version ; TYPE: u16 },
    { NAME: length         ; TYPE: u16 },
    { NAME: encrypted      ; TYPE: [u8; length] };

@SEGMENT.SEMANTICS

  { FORMAT: Tls13Record; FIELD: content_type;   SEMANTIC: FIXED_VALUE(0x17) };
  { FORMAT: Tls13Record; FIELD: legacy_version; SEMANTIC: FIXED_VALUE(0x0303) };
  { FORMAT: Tls13Record; FIELD: length;         SEMANTIC: LENGTH };
  { FORMAT: Tls13Record; FIELD: encrypted;      SEMANTIC: PAYLOAD };

@SEGMENT.SEQUENCE

  { ROLE: CLIENT; PHASE: DATA; FORMAT: Tls13Record };
  { ROLE: SERVER; PHASE: DATA; FORMAT: Tls13Record };
"#;

        let interp = PsfInterpreter::load_from_string(psf).unwrap();
        let frame = interp.create_frame("client", "data").unwrap();

        // Test wrapping
        let noise_data = vec![0xAB; 100];
        let wrapped = frame.wrap(&noise_data).unwrap();

        // Should be 5 bytes header + 100 bytes data
        assert_eq!(wrapped.len(), 105);
        assert_eq!(wrapped[0], 0x17); // content_type
        assert_eq!(wrapped[1], 0x03); // version hi
        assert_eq!(wrapped[2], 0x03); // version lo
        assert_eq!(u16::from_be_bytes([wrapped[3], wrapped[4]]), 100); // length

        // Test unwrapping
        let unwrapped = frame.unwrap(&wrapped).unwrap();
        assert_eq!(unwrapped, noise_data);
    }
}
