//! PSF Type Definitions and AST
//!
//! Data structures representing the parsed PSF specification

use std::collections::HashMap;
use std::io::{Error, ErrorKind};

/// Complete PSF specification parsed from a .psf file
#[derive(Debug, Clone)]
pub struct PsfSpec {
    /// Protocol name
    pub name: String,

    /// Defined message formats
    pub formats: HashMap<String, MessageFormat>,

    /// Semantic rules for fields
    pub semantics: Vec<SemanticRule>,

    /// Protocol sequence (client/server phases)
    pub sequence: Vec<SequenceRule>,

    /// Crypto configuration
    pub crypto: Option<CryptoConfig>,
}

/// Message format definition (e.g., Tls13Record)
#[derive(Debug, Clone)]
pub struct MessageFormat {
    /// Format name
    pub name: String,

    /// Ordered list of fields
    pub fields: Vec<FieldDefinition>,
}

/// Field definition within a format
#[derive(Debug, Clone)]
pub struct FieldDefinition {
    /// Field name
    pub name: String,

    /// Field type
    pub field_type: FieldType,
}

/// Field type enum
#[derive(Debug, Clone, PartialEq)]
pub enum FieldType {
    /// Fixed-size unsigned integer (u8, u16, u24, u32, u64)
    UInt(usize), // size in bytes

    /// Variable-length byte array with explicit length
    ByteArray(usize), // exact size

    /// Variable-length byte array determined by another field
    ByteArrayDynamic(String), // field name containing length

    /// Variable-length string (UTF-8)
    String,

    /// Nested format
    Nested(String), // format name
}

/// Semantic rule for a field
#[derive(Debug, Clone)]
pub struct SemanticRule {
    /// Format this rule applies to
    pub format: String,

    /// Field this rule applies to
    pub field: String,

    /// Semantic type
    pub semantic: SemanticType,
}

/// Semantic type enum
#[derive(Debug, Clone, PartialEq)]
pub enum SemanticType {
    /// Fixed constant value
    FixedValue(u64),

    /// Fixed constant byte array (for SNI, etc.)
    FixedBytes(Vec<u8>),

    /// Length field (specifies how many bytes follow)
    Length,

    /// Payload field (contains the actual encrypted data)
    Payload,

    /// MAC/tag field
    Mac,

    /// Padding field (random padding bytes)
    Padding,

    /// Random bytes (for nonces, randoms, etc.)
    Random,

    /// Command type with enum values
    CommandType(HashMap<String, u64>),
}

/// Sequence rule for protocol state machine
#[derive(Debug, Clone)]
pub struct SequenceRule {
    /// Role (CLIENT or SERVER)
    pub role: Role,

    /// Phase (HANDSHAKE, DATA, etc.)
    pub phase: String,

    /// Format to use in this phase
    pub format: String,
}

/// Protocol role
#[derive(Debug, Clone, PartialEq)]
pub enum Role {
    Client,
    Server,
}

/// Crypto configuration
#[derive(Debug, Clone)]
pub struct CryptoConfig {
    /// Transport protocol (TCP/UDP)
    pub transport: Option<String>,

    /// STARTTLS support
    pub starttls: Option<bool>,

    /// Default port
    pub default_port: Option<u16>,

    /// Password for key derivation
    pub password: Option<String>,

    /// Cipher algorithm
    pub cipher: Option<String>,
}

/// Runtime protocol frame that can wrap/unwrap data
#[derive(Debug, Clone)]
pub struct ProtocolFrame {
    /// The message format to use
    pub format: MessageFormat,

    /// Semantic rules for this format
    pub semantics: Vec<SemanticRule>,

    /// Cached field indices for performance
    payload_field_index: Option<usize>,
    length_field_index: Option<usize>,
    mac_field_index: Option<usize>,
}

impl ProtocolFrame {
    /// Create a new protocol frame from format and semantics
    pub fn new(format: MessageFormat, semantics: Vec<SemanticRule>) -> Self {
        // Find special field indices
        let payload_field_index = semantics.iter()
            .find(|r| r.semantic == SemanticType::Payload)
            .and_then(|r| format.fields.iter().position(|f| f.name == r.field));

        let length_field_index = semantics.iter()
            .find(|r| r.semantic == SemanticType::Length)
            .and_then(|r| format.fields.iter().position(|f| f.name == r.field));

        let mac_field_index = semantics.iter()
            .find(|r| r.semantic == SemanticType::Mac)
            .and_then(|r| format.fields.iter().position(|f| f.name == r.field));

        Self {
            format,
            semantics,
            payload_field_index,
            length_field_index,
            mac_field_index,
        }
    }

    /// Wrap Noise encrypted data into protocol frame
    pub fn wrap(&self, noise_data: &[u8]) -> Result<Vec<u8>, Error> {
        self.wrap_internal(Some(noise_data))
    }

    /// Wrap handshake message (no payload)
    pub fn wrap_handshake(&self) -> Result<Vec<u8>, Error> {
        self.wrap_internal(None)
    }

    /// Internal wrap implementation
    fn wrap_internal(&self, noise_data: Option<&[u8]>) -> Result<Vec<u8>, Error> {
        // For handshake messages, we need to calculate the total message size first
        // to fill in LENGTH fields correctly. We do a two-pass approach.

        // PASS 1: Calculate total size (dry run)
        let mut total_size = 0usize;
        let mut length_fields = Vec::new(); // Track which fields are LENGTH

        for (idx, field) in self.format.fields.iter().enumerate() {
            let semantic = self.semantics.iter()
                .find(|r| r.field == field.name)
                .map(|r| &r.semantic);

            match semantic {
                Some(SemanticType::FixedValue(_)) => {
                    total_size += self.field_size(&field.field_type);
                }
                Some(SemanticType::FixedBytes(bytes)) => {
                    total_size += bytes.len();
                }
                Some(SemanticType::Length) => {
                    length_fields.push((idx, field.name.clone()));
                    total_size += self.field_size(&field.field_type);
                }
                Some(SemanticType::Payload) => {
                    total_size += noise_data.map(|d| d.len()).unwrap_or(0);
                }
                Some(SemanticType::Random) => {
                    total_size += self.field_size(&field.field_type);
                }
                Some(SemanticType::Mac) => {
                    // MAC is part of Noise data - skip
                }
                _ => {
                    total_size += self.field_size(&field.field_type);
                }
            }
        }

        // PASS 2: Write fields with calculated lengths
        let mut output = Vec::new();

        for (idx, field) in self.format.fields.iter().enumerate() {
            // Find semantic rule for this field
            let semantic = self.semantics.iter()
                .find(|r| r.field == field.name)
                .map(|r| &r.semantic);

            match semantic {
                Some(SemanticType::FixedValue(val)) => {
                    // Write fixed value
                    self.write_field_value(&mut output, &field.field_type, *val)?;
                }
                Some(SemanticType::FixedBytes(bytes)) => {
                    // Write fixed byte array (for SNI, etc.)
                    output.extend_from_slice(bytes);
                }
                Some(SemanticType::Length) => {
                    // Calculate length: all bytes that come after this field
                    // This is the TLS/protocol-specific length field calculation
                    let current_offset = output.len();
                    let length_field_size = self.field_size(&field.field_type);
                    let remaining_size = total_size - current_offset - length_field_size;

                    self.write_field_value(&mut output, &field.field_type, remaining_size as u64)?;
                }
                Some(SemanticType::Payload) => {
                    // Write encrypted payload (includes MAC in Noise)
                    if let Some(data) = noise_data {
                        output.extend_from_slice(data);
                    }
                }
                Some(SemanticType::Random) => {
                    // Write random bytes
                    self.write_random(&mut output, &field.field_type)?;
                }
                Some(SemanticType::Mac) => {
                    // MAC is already part of Noise data (last 16 bytes)
                    // Noise Protocol includes it in the encrypted output
                    // Skip writing separately - it's already in the payload
                }
                _ => {
                    // Unknown field - write zeros for now
                    self.write_zeros(&mut output, &field.field_type)?;
                }
            }
        }

        Ok(output)
    }

    /// Unwrap protocol frame to get Noise encrypted data
    pub fn unwrap(&self, wrapped_data: &[u8]) -> Result<Vec<u8>, Error> {
        let mut offset = 0;

        // Validate fixed fields and find payload
        for (i, field) in self.format.fields.iter().enumerate() {
            let semantic = self.semantics.iter()
                .find(|r| r.field == field.name)
                .map(|r| &r.semantic);

            match semantic {
                Some(SemanticType::FixedValue(expected)) => {
                    let actual = self.read_field_value(wrapped_data, &mut offset, &field.field_type)?;
                    if actual != *expected {
                        return Err(Error::new(
                            ErrorKind::InvalidData,
                            format!(
                                "Invalid {} field: expected 0x{:x}, got 0x{:x}",
                                field.name, expected, actual
                            ),
                        ));
                    }
                }
                Some(SemanticType::Length) => {
                    // Read but don't validate length for now
                    let _ = self.read_field_value(wrapped_data, &mut offset, &field.field_type)?;
                }
                Some(SemanticType::Payload) => {
                    // Extract payload (rest of data)
                    if Some(i) == self.payload_field_index {
                        let payload = &wrapped_data[offset..];
                        return Ok(payload.to_vec());
                    }
                }
                _ => {
                    // Skip unknown fields
                    self.skip_field(wrapped_data, &mut offset, &field.field_type)?;
                }
            }
        }

        Err(Error::new(
            ErrorKind::InvalidData,
            "No payload field found in format",
        ))
    }

    /// Write a field value in big-endian format
    fn write_field_value(&self, output: &mut Vec<u8>, field_type: &FieldType, value: u64) -> Result<(), Error> {
        match field_type {
            FieldType::UInt(size) => {
                match size {
                    1 => output.push(value as u8),
                    2 => output.extend_from_slice(&(value as u16).to_be_bytes()),
                    3 => {
                        // u24 - 3 bytes big-endian
                        output.push(((value >> 16) & 0xFF) as u8);
                        output.push(((value >> 8) & 0xFF) as u8);
                        output.push((value & 0xFF) as u8);
                    }
                    4 => output.extend_from_slice(&(value as u32).to_be_bytes()),
                    8 => output.extend_from_slice(&value.to_be_bytes()),
                    _ => return Err(Error::new(ErrorKind::InvalidInput, format!("Unsupported integer size: {}", size))),
                }
                Ok(())
            }
            _ => Err(Error::new(ErrorKind::InvalidInput, "Can only write integer values")),
        }
    }

    /// Read a field value in big-endian format
    fn read_field_value(&self, data: &[u8], offset: &mut usize, field_type: &FieldType) -> Result<u64, Error> {
        match field_type {
            FieldType::UInt(size) => {
                if *offset + size > data.len() {
                    return Err(Error::new(ErrorKind::UnexpectedEof, "Incomplete field"));
                }

                let value = match size {
                    1 => data[*offset] as u64,
                    2 => u16::from_be_bytes([data[*offset], data[*offset + 1]]) as u64,
                    3 => {
                        ((data[*offset] as u64) << 16)
                            | ((data[*offset + 1] as u64) << 8)
                            | (data[*offset + 2] as u64)
                    }
                    4 => u32::from_be_bytes([
                        data[*offset],
                        data[*offset + 1],
                        data[*offset + 2],
                        data[*offset + 3],
                    ]) as u64,
                    8 => u64::from_be_bytes([
                        data[*offset],
                        data[*offset + 1],
                        data[*offset + 2],
                        data[*offset + 3],
                        data[*offset + 4],
                        data[*offset + 5],
                        data[*offset + 6],
                        data[*offset + 7],
                    ]),
                    _ => return Err(Error::new(ErrorKind::InvalidInput, format!("Unsupported integer size: {}", size))),
                };

                *offset += size;
                Ok(value)
            }
            _ => Err(Error::new(ErrorKind::InvalidInput, "Can only read integer values")),
        }
    }

    /// Skip a field
    fn skip_field(&self, data: &[u8], offset: &mut usize, field_type: &FieldType) -> Result<(), Error> {
        match field_type {
            FieldType::UInt(size) => {
                *offset += size;
                Ok(())
            }
            FieldType::ByteArray(size) => {
                *offset += size;
                Ok(())
            }
            FieldType::ByteArrayDynamic(ref_field) => {
                // For dynamic arrays, we need to read the length from the referenced field first
                // This is complex - for now, just take remaining data for PAYLOAD fields
                // Non-PAYLOAD dynamic fields shouldn't be skipped anyway
                Ok(())  // Allow skip but don't advance offset - caller handles PAYLOAD extraction
            }
            _ => Err(Error::new(ErrorKind::InvalidInput, "Cannot skip variable-length field")),
        }
    }

    /// Write zeros for unknown field
    fn write_zeros(&self, output: &mut Vec<u8>, field_type: &FieldType) -> Result<(), Error> {
        match field_type {
            FieldType::UInt(size) | FieldType::ByteArray(size) => {
                output.extend_from_slice(&vec![0u8; *size]);
                Ok(())
            }
            _ => Ok(()), // Skip variable-length fields
        }
    }

    /// Write random bytes for RANDOM semantic
    fn write_random(&self, output: &mut Vec<u8>, field_type: &FieldType) -> Result<(), Error> {
        use rand::Rng;
        match field_type {
            FieldType::ByteArray(size) => {
                let mut rng = rand::thread_rng();
                let random_bytes: Vec<u8> = (0..*size).map(|_| rng.gen()).collect();
                output.extend_from_slice(&random_bytes);
                Ok(())
            }
            _ => Err(Error::new(ErrorKind::InvalidInput, "RANDOM semantic requires byte array type")),
        }
    }

    /// Get the size of a field type in bytes
    fn field_size(&self, field_type: &FieldType) -> usize {
        match field_type {
            FieldType::UInt(size) => *size,
            FieldType::ByteArray(size) => *size,
            FieldType::ByteArrayDynamic(_) => 0, // Dynamic size - can't determine statically
            FieldType::String => 0, // Variable length
            FieldType::Nested(_) => 0, // Complex nested structure
        }
    }
}
