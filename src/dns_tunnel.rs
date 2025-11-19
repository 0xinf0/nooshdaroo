///! UDP DNS Tunneling
///! Encodes encrypted data in DNS query labels for censorship bypass
///! Format: ab3d-01f7-c9e2-498b.tunnel.example.com

use std::net::SocketAddr;

/// Maximum bytes per DNS label (RFC 1035)
const MAX_LABEL_LEN: usize = 63;

/// Maximum total QNAME length
const MAX_QNAME_LEN: usize = 253;

/// Base domains for tunnel queries (rotated for variety)
/// Using top domains from 1.1.1.1 DNS traffic in Iran
const TUNNEL_DOMAINS: &[&str] = &[
    "api.gstatic.com",
    "update.googleapis.com",
];

/// Get a tunnel domain (rotates based on transaction ID for variety)
fn get_tunnel_domain(transaction_id: u16) -> &'static str {
    TUNNEL_DOMAINS[(transaction_id as usize) % TUNNEL_DOMAINS.len()]
}

/// Encode payload data into a valid DNS QNAME
///
/// Takes encrypted data and encodes it as hex in subdomain labels:
/// Input: [0xab, 0x3d, 0x01, 0xf7, 0xc9, 0xe2]
/// Output: \x06ab3d01\x06f7c9e2\x06challenges\x10cloudflare\x03com\x00
///
/// Each label is:
/// - Length byte (1-63)
/// - Data bytes (hex encoded payload chunk)
/// - Terminated with \x00
pub fn encode_qname(payload: &[u8], transaction_id: u16) -> Vec<u8> {
    let mut qname = Vec::new();

    // Hex encode the payload
    let hex_payload = hex::encode(payload);

    // Split into chunks that fit in DNS labels (max 63 chars)
    let chunks: Vec<&str> = hex_payload
        .as_bytes()
        .chunks(MAX_LABEL_LEN)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect();

    // Encode each chunk as a DNS label
    for chunk in chunks {
        qname.push(chunk.len() as u8);
        qname.extend_from_slice(chunk.as_bytes());
    }

    // Append base domain (cdn-api.services.net or update.akamaiedge.net)
    let tunnel_domain = get_tunnel_domain(transaction_id);
    for part in tunnel_domain.split('.') {
        qname.push(part.len() as u8);
        qname.extend_from_slice(part.as_bytes());
    }

    // Null terminator
    qname.push(0);

    qname
}

/// Decode DNS QNAME back to payload
///
/// Extracts hex-encoded data from subdomain labels
pub fn decode_qname(qname: &[u8]) -> Result<Vec<u8>, String> {
    let mut hex_data = String::new();
    let mut pos = 0;

    // Read labels until we hit the base domain
    while pos < qname.len() {
        let len = qname[pos] as usize;
        if len == 0 {
            break; // End of QNAME
        }

        pos += 1;
        if pos + len > qname.len() {
            return Err("Invalid QNAME length".to_string());
        }

        let label = &qname[pos..pos + len];
        let label_str = std::str::from_utf8(label)
            .map_err(|e| format!("Invalid UTF-8 in label: {}", e))?;

        // Check if this is part of the base domain (api.gstatic.com or update.googleapis.com)
        if label_str == "api" || label_str == "gstatic" || label_str == "com" ||
           label_str == "update" || label_str == "googleapis" {
            break; // Reached base domain
        }

        // Accumulate hex data
        hex_data.push_str(label_str);
        pos += len;
    }

    // Decode hex to bytes
    hex::decode(&hex_data).map_err(|e| format!("Hex decode error: {}", e))
}

/// Build a complete DNS query packet
pub fn build_dns_query(payload: &[u8], transaction_id: u16) -> Vec<u8> {
    let mut packet = Vec::new();

    // Header (12 bytes)
    packet.extend_from_slice(&transaction_id.to_be_bytes()); // Transaction ID
    packet.extend_from_slice(&[0x01, 0x00]); // Flags: standard query
    packet.extend_from_slice(&[0x00, 0x01]); // QDCOUNT: 1 question
    packet.extend_from_slice(&[0x00, 0x00]); // ANCOUNT: 0 answers
    packet.extend_from_slice(&[0x00, 0x00]); // NSCOUNT: 0 authority
    packet.extend_from_slice(&[0x00, 0x00]); // ARCOUNT: 0 additional

    // Question section (use real domains: challenges.cloudflare.com or www.google.com)
    let qname = encode_qname(payload, transaction_id);
    packet.extend_from_slice(&qname);

    // QTYPE: A record (0x0001)
    packet.extend_from_slice(&[0x00, 0x01]);

    // QCLASS: IN (0x0001)
    packet.extend_from_slice(&[0x00, 0x01]);

    packet
}

/// Build a DNS response packet with TXT record containing payload
pub fn build_dns_response(
    query: &[u8],
    payload: &[u8],
    transaction_id: u16,
) -> Vec<u8> {
    let mut packet = Vec::new();

    // Header (12 bytes)
    packet.extend_from_slice(&transaction_id.to_be_bytes()); // Transaction ID
    packet.extend_from_slice(&[0x81, 0x80]); // Flags: standard response
    packet.extend_from_slice(&[0x00, 0x01]); // QDCOUNT: 1 question
    packet.extend_from_slice(&[0x00, 0x01]); // ANCOUNT: 1 answer
    packet.extend_from_slice(&[0x00, 0x00]); // NSCOUNT: 0
    packet.extend_from_slice(&[0x00, 0x00]); // ARCOUNT: 0

    // Echo the question section from query (skip header)
    if query.len() > 12 {
        let question_start = 12;
        let mut question_end = question_start;

        // Find end of QNAME (null terminator)
        while question_end < query.len() && query[question_end] != 0 {
            let len = query[question_end] as usize;
            question_end += 1 + len;
        }
        question_end += 1; // Include null terminator
        question_end += 4; // Include QTYPE and QCLASS

        if question_end <= query.len() {
            packet.extend_from_slice(&query[question_start..question_end]);
        }
    } else {
        // If no query provided, create a minimal question section
        // QNAME: cdn-api.services.net or update.akamaiedge.net
        let tunnel_domain = get_tunnel_domain(transaction_id);
        for part in tunnel_domain.split('.') {
            packet.push(part.len() as u8);
            packet.extend_from_slice(part.as_bytes());
        }
        packet.push(0); // Null terminator
        packet.extend_from_slice(&[0x00, 0x10]); // QTYPE: TXT
        packet.extend_from_slice(&[0x00, 0x01]); // QCLASS: IN
    }

    // Answer section
    packet.extend_from_slice(&[0xc0, 0x0c]); // NAME: pointer to question
    packet.extend_from_slice(&[0x00, 0x10]); // TYPE: TXT record
    packet.extend_from_slice(&[0x00, 0x01]); // CLASS: IN
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x3c]); // TTL: 60 seconds

    // RDLENGTH and RDATA (TXT record with hex-encoded payload)
    let hex_payload = hex::encode(payload);
    let hex_bytes = hex_payload.as_bytes();

    // TXT record format: length byte + data (max 255 per string)
    let mut txt_data = Vec::new();
    for chunk in hex_bytes.chunks(255) {
        txt_data.push(chunk.len() as u8);
        txt_data.extend_from_slice(chunk);
    }

    packet.extend_from_slice(&(txt_data.len() as u16).to_be_bytes()); // RDLENGTH
    packet.extend_from_slice(&txt_data); // RDATA

    packet
}

/// Parse DNS query and extract payload
pub fn parse_dns_query(packet: &[u8]) -> Result<(u16, Vec<u8>), String> {
    if packet.len() < 12 {
        return Err("Packet too short".to_string());
    }

    // Extract transaction ID
    let transaction_id = u16::from_be_bytes([packet[0], packet[1]]);

    // Find QNAME (starts at byte 12)
    let qname_start = 12;
    let mut qname_end = qname_start;

    while qname_end < packet.len() && packet[qname_end] != 0 {
        let len = packet[qname_end] as usize;
        qname_end += 1 + len;
    }
    qname_end += 1; // Include null terminator

    if qname_end > packet.len() {
        return Err("Invalid QNAME".to_string());
    }

    let qname = &packet[qname_start..qname_end];
    let payload = decode_qname(qname)?;

    Ok((transaction_id, payload))
}

/// Parse DNS response and extract payload from TXT record
pub fn parse_dns_response(packet: &[u8]) -> Result<Vec<u8>, String> {
    if packet.len() < 12 {
        return Err("Packet too short".to_string());
    }

    // Check ANCOUNT
    let ancount = u16::from_be_bytes([packet[6], packet[7]]);
    if ancount == 0 {
        return Err("No answers in response".to_string());
    }

    // Skip question section
    let mut pos = 12;
    while pos < packet.len() && packet[pos] != 0 {
        let len = packet[pos] as usize;
        pos += 1 + len;
    }
    pos += 1; // Null terminator
    pos += 4; // QTYPE + QCLASS

    // Read answer section
    if pos + 10 > packet.len() {
        return Err("Answer section too short".to_string());
    }

    // Skip NAME (2 bytes if compressed pointer)
    if packet[pos] == 0xc0 {
        pos += 2;
    }

    // Skip TYPE, CLASS, TTL (8 bytes)
    pos += 8;

    // Read RDLENGTH
    let rdlength = u16::from_be_bytes([packet[pos], packet[pos + 1]]) as usize;
    pos += 2;

    // Read RDATA (TXT record)
    if pos + rdlength > packet.len() {
        return Err("RDATA exceeds packet length".to_string());
    }

    let txt_data = &packet[pos..pos + rdlength];

    // Decode TXT record (skip length bytes, concatenate strings)
    let mut hex_str = String::new();
    let mut i = 0;
    while i < txt_data.len() {
        let len = txt_data[i] as usize;
        i += 1;
        if i + len > txt_data.len() {
            break;
        }
        hex_str.push_str(std::str::from_utf8(&txt_data[i..i + len]).unwrap_or(""));
        i += len;
    }

    // Decode hex to bytes
    hex::decode(&hex_str).map_err(|e| format!("Hex decode error: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qname_encoding() {
        let payload = b"Hello, World!";
        let qname = encode_qname(payload);

        // Should be: \x1a48656c6c6f2c20576f726c6421\x06tunnel\x07example\x03com\x00
        assert!(qname.len() > payload.len());
        assert_eq!(qname.last(), Some(&0)); // Null terminated

        // Decode should match original
        let decoded = decode_qname(&qname).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_dns_query_building() {
        let payload = b"test data";
        let packet = build_dns_query(payload, 0x1234);

        // Should start with transaction ID
        assert_eq!(&packet[0..2], &[0x12, 0x34]);

        // Should have valid DNS header
        assert_eq!(packet.len() > 12, true);

        // Parse it back
        let (tid, decoded) = parse_dns_query(&packet).unwrap();
        assert_eq!(tid, 0x1234);
        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_dns_response_building() {
        let query_payload = b"query";
        let query = build_dns_query(query_payload, 0xabcd);

        let response_payload = b"response data";
        let response = build_dns_response(&query, response_payload, 0xabcd);

        // Should have transaction ID
        assert_eq!(&response[0..2], &[0xab, 0xcd]);

        // Parse response
        let decoded = parse_dns_response(&response).unwrap();
        assert_eq!(decoded, response_payload);
    }

    #[test]
    fn test_large_response_fragment() {
        // Test with a fragment-sized payload (what the server actually sends)
        // DnsTunnelHeader is 8 bytes + ~170 bytes of data = ~178 bytes
        let payload = vec![0x42; 178];

        println!("Payload size: {} bytes", payload.len());
        println!("Hex encoded size: {} bytes", hex::encode(&payload).len());

        // Build response without original query (like server does)
        let response = build_dns_response(&[], &payload, 0x1234);
        println!("DNS response packet size: {} bytes", response.len());

        // Parse it back
        let decoded = parse_dns_response(&response).unwrap();
        assert_eq!(decoded, payload);
    }
}
