// Minimal DNS protocol implementation for nQUIC transport
//
// Implements just enough of the DNS protocol to:
// - Build DNS queries (A/TXT records)
// - Parse DNS responses (TXT records)
// - Handle transaction IDs

use super::{Result, DnsError};
use bytes::{Buf, BufMut, BytesMut};
use std::io::Cursor;

/// DNS message header (12 bytes)
#[derive(Debug, Clone)]
pub struct DnsHeader {
    pub id: u16,              // Transaction ID
    pub flags: u16,           // Flags
    pub qdcount: u16,         // Question count
    pub ancount: u16,         // Answer count
    pub nscount: u16,         // Authority count
    pub arcount: u16,         // Additional count
}

impl DnsHeader {
    /// Create a new query header
    pub fn new_query(id: u16) -> Self {
        Self {
            id,
            flags: 0x0100,    // Standard query, recursion desired
            qdcount: 1,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        }
    }

    /// Create a new response header
    pub fn new_response(id: u16, ancount: u16) -> Self {
        Self {
            id,
            flags: 0x8180,    // Response, no error, recursion available
            qdcount: 1,
            ancount,
            nscount: 0,
            arcount: 0,
        }
    }

    /// Parse header from bytes
    pub fn parse(buf: &mut Cursor<&[u8]>) -> Result<Self> {
        if buf.remaining() < 12 {
            return Err(DnsError::InvalidMessage("Header too short".into()));
        }

        Ok(Self {
            id: buf.get_u16(),
            flags: buf.get_u16(),
            qdcount: buf.get_u16(),
            ancount: buf.get_u16(),
            nscount: buf.get_u16(),
            arcount: buf.get_u16(),
        })
    }

    /// Write header to buffer
    pub fn write(&self, buf: &mut BytesMut) {
        buf.put_u16(self.id);
        buf.put_u16(self.flags);
        buf.put_u16(self.qdcount);
        buf.put_u16(self.ancount);
        buf.put_u16(self.nscount);
        buf.put_u16(self.arcount);
    }

    /// Check if this is a response
    pub fn is_response(&self) -> bool {
        (self.flags & 0x8000) != 0
    }
}

/// DNS question record type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum DnsQType {
    A = 1,
    TXT = 16,
}

/// DNS question record class
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum DnsQClass {
    IN = 1,
}

/// DNS question
#[derive(Debug, Clone)]
pub struct DnsQuestion {
    pub qname: String,
    pub qtype: DnsQType,
    pub qclass: DnsQClass,
}

impl DnsQuestion {
    /// Create a new TXT query
    pub fn new_txt(domain: &str) -> Self {
        Self {
            qname: domain.to_string(),
            qtype: DnsQType::TXT,
            qclass: DnsQClass::IN,
        }
    }

    /// Parse question from bytes
    pub fn parse(buf: &mut Cursor<&[u8]>) -> Result<Self> {
        let qname = read_domain_name(buf)?;

        if buf.remaining() < 4 {
            return Err(DnsError::InvalidMessage("Question too short".into()));
        }

        let qtype = match buf.get_u16() {
            1 => DnsQType::A,
            16 => DnsQType::TXT,
            _ => return Err(DnsError::InvalidMessage("Unsupported question type".into())),
        };

        let qclass = match buf.get_u16() {
            1 => DnsQClass::IN,
            _ => return Err(DnsError::InvalidMessage("Unsupported question class".into())),
        };

        Ok(Self { qname, qtype, qclass })
    }

    /// Write question to buffer
    pub fn write(&self, buf: &mut BytesMut) {
        write_domain_name(&self.qname, buf);
        buf.put_u16(self.qtype as u16);
        buf.put_u16(self.qclass as u16);
    }
}

/// DNS resource record (answer)
#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
}

impl DnsRecord {
    /// Create a new TXT record
    pub fn new_txt(domain: &str, txt_data: Vec<u8>, ttl: u32) -> Self {
        Self {
            name: domain.to_string(),
            rtype: DnsQType::TXT as u16,
            rclass: DnsQClass::IN as u16,
            ttl,
            rdata: txt_data,
        }
    }

    /// Parse record from bytes
    pub fn parse(buf: &mut Cursor<&[u8]>) -> Result<Self> {
        let name = read_domain_name(buf)?;

        if buf.remaining() < 10 {
            return Err(DnsError::InvalidMessage("Record too short".into()));
        }

        let rtype = buf.get_u16();
        let rclass = buf.get_u16();
        let ttl = buf.get_u32();
        let rdlen = buf.get_u16() as usize;

        if buf.remaining() < rdlen {
            return Err(DnsError::InvalidMessage("Truncated record data".into()));
        }

        let mut rdata = vec![0u8; rdlen];
        buf.copy_to_slice(&mut rdata);

        Ok(Self { name, rtype, rclass, ttl, rdata })
    }

    /// Write record to buffer
    pub fn write(&self, buf: &mut BytesMut) {
        write_domain_name(&self.name, buf);
        buf.put_u16(self.rtype);
        buf.put_u16(self.rclass);
        buf.put_u32(self.ttl);
        buf.put_u16(self.rdata.len() as u16);
        buf.put_slice(&self.rdata);
    }

    /// Get TXT record data (strips length bytes)
    pub fn get_txt_data(&self) -> Result<Vec<u8>> {
        if self.rtype != DnsQType::TXT as u16 {
            return Err(DnsError::DecodingError("Not a TXT record".into()));
        }

        // TXT records have length-prefixed strings
        // We'll extract all data after length bytes
        let mut result = Vec::new();
        let mut cursor = Cursor::new(&self.rdata[..]);

        while cursor.has_remaining() {
            if cursor.remaining() < 1 {
                break;
            }
            let len = cursor.get_u8() as usize;

            if cursor.remaining() < len {
                return Err(DnsError::DecodingError("Truncated TXT data".into()));
            }

            let mut chunk = vec![0u8; len];
            cursor.copy_to_slice(&mut chunk);
            result.extend_from_slice(&chunk);
        }

        Ok(result)
    }
}

/// DNS message (complete query or response)
#[derive(Debug)]
pub struct DnsMessage {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
}

impl DnsMessage {
    /// Create a new TXT query
    pub fn new_query(domain: &str, id: u16) -> Self {
        Self {
            header: DnsHeader::new_query(id),
            questions: vec![DnsQuestion::new_txt(domain)],
            answers: Vec::new(),
        }
    }

    /// Create a new TXT response
    pub fn new_response(domain: &str, txt_data: Vec<u8>, id: u16) -> Self {
        Self {
            header: DnsHeader::new_response(id, 1),
            questions: vec![DnsQuestion::new_txt(domain)],
            answers: vec![DnsRecord::new_txt(domain, txt_data, 60)],
        }
    }

    /// Parse DNS message from bytes
    pub fn parse(data: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(data);

        let header = DnsHeader::parse(&mut cursor)?;

        let mut questions = Vec::new();
        for _ in 0..header.qdcount {
            questions.push(DnsQuestion::parse(&mut cursor)?);
        }

        let mut answers = Vec::new();
        for _ in 0..header.ancount {
            answers.push(DnsRecord::parse(&mut cursor)?);
        }

        Ok(Self { header, questions, answers })
    }

    /// Serialize DNS message to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(512);

        self.header.write(&mut buf);

        for q in &self.questions {
            q.write(&mut buf);
        }

        for a in &self.answers {
            a.write(&mut buf);
        }

        buf.to_vec()
    }

    /// Get the domain name from the first question
    pub fn get_question_domain(&self) -> Result<String> {
        self.questions.first()
            .map(|q| q.qname.clone())
            .ok_or_else(|| DnsError::InvalidMessage("No questions in message".into()))
    }

    /// Get TXT data from first answer
    pub fn get_txt_answer(&self) -> Result<Vec<u8>> {
        self.answers.first()
            .ok_or_else(|| DnsError::InvalidMessage("No answers in message".into()))?
            .get_txt_data()
    }
}

/// Read a domain name from DNS message (handles DNS compression)
fn read_domain_name(buf: &mut Cursor<&[u8]>) -> Result<String> {
    let mut labels = Vec::new();
    let mut max_labels = 63; // Prevent infinite loops

    loop {
        if max_labels == 0 {
            return Err(DnsError::InvalidMessage("Too many labels".into()));
        }
        max_labels -= 1;

        if !buf.has_remaining() {
            return Err(DnsError::InvalidMessage("Truncated domain name".into()));
        }

        let len = buf.get_u8();

        // Check for end of name
        if len == 0 {
            break;
        }

        // Check for compression pointer (not implemented for simplicity)
        if (len & 0xC0) == 0xC0 {
            // Compression pointer - skip for now
            if buf.has_remaining() {
                buf.get_u8(); // Skip second byte of pointer
            }
            break;
        }

        // Read label
        let label_len = len as usize;
        if buf.remaining() < label_len {
            return Err(DnsError::InvalidMessage("Truncated label".into()));
        }

        let mut label = vec![0u8; label_len];
        buf.copy_to_slice(&mut label);

        labels.push(String::from_utf8(label)
            .map_err(|_| DnsError::InvalidMessage("Invalid UTF-8 in domain name".into()))?);
    }

    Ok(labels.join("."))
}

/// Write a domain name to DNS message
fn write_domain_name(domain: &str, buf: &mut BytesMut) {
    for label in domain.split('.') {
        let bytes = label.as_bytes();
        buf.put_u8(bytes.len() as u8);
        buf.put_slice(bytes);
    }
    buf.put_u8(0); // End of name
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_query_construction() {
        let msg = DnsMessage::new_query("tunnel.example.com", 0x1234);
        let bytes = msg.to_bytes();

        assert!(bytes.len() > 12);
        assert_eq!(&bytes[0..2], &[0x12, 0x34]); // Transaction ID
    }

    #[test]
    fn test_dns_response_construction() {
        let txt_data = b"Hello, World!".to_vec();
        let msg = DnsMessage::new_response("tunnel.example.com", txt_data.clone(), 0x1234);
        let bytes = msg.to_bytes();

        assert!(bytes.len() > 12);

        // Parse it back
        let parsed = DnsMessage::parse(&bytes).unwrap();
        assert_eq!(parsed.header.id, 0x1234);
        assert_eq!(parsed.header.ancount, 1);
    }

    #[test]
    fn test_domain_name_encoding() {
        let mut buf = BytesMut::new();
        write_domain_name("example.com", &mut buf);

        let mut cursor = Cursor::new(&buf[..]);
        let domain = read_domain_name(&mut cursor).unwrap();

        assert_eq!(domain, "example.com");
    }

    #[test]
    fn test_txt_record_data() {
        let data = b"Test data".to_vec();
        let record = DnsRecord::new_txt("example.com", data.clone(), 300);

        let extracted = record.get_txt_data().unwrap();
        assert_eq!(extracted, data);
    }
}
