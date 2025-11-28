///! UDP DNS Tunneling
///! Encodes encrypted data in DNS query labels for censorship bypass
///! Uses base32 encoding for better efficiency (1.6x expansion vs 2x for hex)
///! Format: mfrggzdfmy.tunnel.example.com

// Using hex encoding for DNS labels (2x expansion, but more reliable/tested)

/// Maximum bytes per DNS label (RFC 1035)
const MAX_LABEL_LEN: usize = 63;

/// Maximum total QNAME length
const MAX_QNAME_LEN: usize = 253;

/// Popular domains for tunnel queries (rotated to blend with legitimate traffic)
const TUNNEL_DOMAINS: &[&str] = &[
    "google.com",
    "apple.com",
    "challenges.cloudflare.com",
];

/// Get a tunnel domain based on a seed (for consistent encoding/decoding)
fn get_tunnel_domain(seed: u8) -> &'static str {
    TUNNEL_DOMAINS[(seed as usize) % TUNNEL_DOMAINS.len()]
}

/// Encode payload data into a valid DNS QNAME
///
/// Takes encrypted data and encodes it as hex in subdomain labels:
/// Input: [0xab, 0x3d, 0x01, 0xf7, 0xc9, 0xe2], seed: 0
/// Output: \x06ab3d01\x06f7c9e2\x06google\x03com\x00
///
/// Each label is:
/// - Length byte (1-63)
/// - Data bytes (base32 encoded payload chunk)
/// - Terminated with \x00
pub fn encode_qname_with_seed(payload: &[u8], seed: u8) -> Vec<u8> {
    let mut qname = Vec::new();

    // Hex encode the payload (2x expansion)
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

    // Append base domain (rotated based on seed)
    let domain = get_tunnel_domain(seed);
    for part in domain.split('.') {
        qname.push(part.len() as u8);
        qname.extend_from_slice(part.as_bytes());
    }

    // Null terminator
    qname.push(0);

    qname
}

/// Encode payload with default seed (for backwards compatibility)
pub fn encode_qname(payload: &[u8]) -> Vec<u8> {
    // Use first byte of payload as seed for domain rotation
    let seed = payload.first().copied().unwrap_or(0);
    encode_qname_with_seed(payload, seed)
}

/// Known domain parts that indicate end of payload data
const DOMAIN_PARTS: &[&str] = &[
    "google", "apple", "challenges", "cloudflare", "com",
];

/// Check if a label is part of a base domain (not payload data)
fn is_domain_part(label: &str) -> bool {
    DOMAIN_PARTS.contains(&label)
}

/// Decode DNS QNAME back to payload
///
/// Extracts base32-encoded data from subdomain labels
pub fn decode_qname(qname: &[u8]) -> Result<Vec<u8>, String> {
    let mut encoded_data = String::new();
    let mut pos = 0;

    // Read labels until we hit a base domain part
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

        // Check if this is part of a base domain
        if is_domain_part(label_str) {
            break; // Reached base domain
        }

        // Accumulate base32 data
        encoded_data.push_str(label_str);
        pos += len;
    }

    // Decode hex to bytes
    hex::decode(&encoded_data).map_err(|e| format!("Hex decode error: {}", e))
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

/// Maximum UDP DNS packet size (RFC 1035)
const MAX_DNS_UDP_SIZE: usize = 512;

/// Per-TXT-record overhead: 2 NAME ptr + 2 TYPE + 2 CLASS + 4 TTL + 2 RDLENGTH = 12 bytes
const TXT_RECORD_OVERHEAD: usize = 12;

/// Marker prefix for data TXT records (looks like version record, e.g., SPF "v=spf1")
const DATA_MARKER_BUILD: &str = "v=";

/// Decoy TXT records that look like legitimate DNS TXT records
/// These help fool DPI by making the response look like normal DNS traffic
/// IMPORTANT: None should start with "v=" to avoid confusion with data marker
const DECOY_TXT_RECORDS: &[&str] = &[
    "google-site-verification=abc123xyz",
    "MS=ms12345678",
    "docusign=a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "facebook-domain-verification=abc123def456",
];

/// Build a DNS response packet with multiple TXT records for maximum payload
///
/// RFC 1035 allows multiple answer records. We use this to pack more data
/// into the 512-byte UDP limit. Each TXT record has 12 bytes overhead.
///
/// Strategy: First TXT record is a decoy (legitimate-looking), subsequent
/// records contain data prefixed with "v=" marker.
pub fn build_dns_response(
    query: &[u8],
    payload: &[u8],
    transaction_id: u16,
) -> Vec<u8> {
    let mut packet = Vec::new();

    // Header (12 bytes) - ANCOUNT will be updated later
    packet.extend_from_slice(&transaction_id.to_be_bytes()); // Transaction ID
    packet.extend_from_slice(&[0x81, 0x80]); // Flags: standard response
    packet.extend_from_slice(&[0x00, 0x01]); // QDCOUNT: 1 question
    packet.extend_from_slice(&[0x00, 0x00]); // ANCOUNT: placeholder (will update)
    packet.extend_from_slice(&[0x00, 0x00]); // NSCOUNT: 0
    packet.extend_from_slice(&[0x00, 0x00]); // ARCOUNT: 0

    // Echo the question section from query (skip header)
    let question_section_len;
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
            question_section_len = question_end - question_start;
        } else {
            question_section_len = 0;
        }
    } else {
        // If no query provided, create a minimal question section
        // Use the first domain from TUNNEL_DOMAINS
        let domain = get_tunnel_domain(0);
        let start_len = packet.len();
        for part in domain.split('.') {
            packet.push(part.len() as u8);
            packet.extend_from_slice(part.as_bytes());
        }
        packet.push(0); // Null terminator
        packet.extend_from_slice(&[0x00, 0x10]); // QTYPE: TXT
        packet.extend_from_slice(&[0x00, 0x01]); // QCLASS: IN
        question_section_len = packet.len() - start_len;
    }

    let mut answer_count = 0u16;

    // Add decoy TXT record first (looks like site verification or SPF)
    // Use transaction_id to rotate decoys for variety
    let decoy = DECOY_TXT_RECORDS[(transaction_id as usize) % DECOY_TXT_RECORDS.len()];
    let decoy_bytes = decoy.as_bytes();

    // Only add decoy if it fits
    if packet.len() + TXT_RECORD_OVERHEAD + 1 + decoy_bytes.len() < MAX_DNS_UDP_SIZE {
        packet.extend_from_slice(&[0xc0, 0x0c]); // NAME: pointer to question
        packet.extend_from_slice(&[0x00, 0x10]); // TYPE: TXT record
        packet.extend_from_slice(&[0x00, 0x01]); // CLASS: IN
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x3c]); // TTL: 60 seconds

        let rdlength = (1 + decoy_bytes.len()) as u16;
        packet.extend_from_slice(&rdlength.to_be_bytes());
        packet.push(decoy_bytes.len() as u8);
        packet.extend_from_slice(decoy_bytes);
        answer_count += 1;
    }

    // Hex encode payload (marker added only to first record)
    let hex_payload = hex::encode(payload);
    let hex_bytes = hex_payload.as_bytes();

    // Add data TXT records
    let mut hex_offset = 0;
    let mut is_first_data_record = true;

    while hex_offset < hex_bytes.len() && packet.len() < MAX_DNS_UDP_SIZE {
        // How much space left?
        let space_left = MAX_DNS_UDP_SIZE.saturating_sub(packet.len());

        // Need at least overhead + 1 length byte + marker + some data
        let marker_len = if is_first_data_record { DATA_MARKER_BUILD.len() } else { 0 };
        if space_left < TXT_RECORD_OVERHEAD + 1 + marker_len + 1 {
            break;
        }

        // Max data we can fit in this record (accounting for overhead, length byte, and marker)
        let max_txt_data = (space_left - TXT_RECORD_OVERHEAD - 1 - marker_len).min(255 - marker_len);
        let remaining_hex = hex_bytes.len() - hex_offset;
        let txt_data_len = remaining_hex.min(max_txt_data);

        if txt_data_len == 0 {
            break;
        }

        // Write TXT record
        packet.extend_from_slice(&[0xc0, 0x0c]); // NAME: pointer to question
        packet.extend_from_slice(&[0x00, 0x10]); // TYPE: TXT record
        packet.extend_from_slice(&[0x00, 0x01]); // CLASS: IN
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x3c]); // TTL: 60 seconds

        // RDLENGTH = 1 (length byte) + marker (if first) + data length
        let total_txt_len = marker_len + txt_data_len;
        let rdlength = (1 + total_txt_len) as u16;
        packet.extend_from_slice(&rdlength.to_be_bytes());

        // TXT RDATA: length byte + marker (if first) + data
        packet.push(total_txt_len as u8);
        if is_first_data_record {
            packet.extend_from_slice(DATA_MARKER_BUILD.as_bytes());
            is_first_data_record = false;
        }
        packet.extend_from_slice(&hex_bytes[hex_offset..hex_offset + txt_data_len]);

        hex_offset += txt_data_len;
        answer_count += 1;
    }

    // Update ANCOUNT in header (bytes 6-7)
    let ancount_bytes = answer_count.to_be_bytes();
    packet[6] = ancount_bytes[0];
    packet[7] = ancount_bytes[1];

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
        // Validate label length doesn't exceed packet bounds
        if qname_end + 1 + len > packet.len() {
            return Err(format!("Invalid QNAME: label at pos {} claims length {} but only {} bytes remain",
                qname_end, len, packet.len() - qname_end - 1));
        }
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

/// Marker prefix for data TXT records (distinguishes from decoy records)
const DATA_MARKER: &str = "v=";

/// Parse DNS response and extract payload from multiple TXT records
///
/// Supports multiple answer records (ANCOUNT > 1) and filters out decoy records.
/// The first data record is identified by the "v=" prefix marker.
/// Subsequent data records (hex-only) are continuation records.
pub fn parse_dns_response(packet: &[u8]) -> Result<Vec<u8>, String> {
    if packet.len() < 12 {
        return Err("Packet too short".to_string());
    }

    // Check ANCOUNT
    let ancount = u16::from_be_bytes([packet[6], packet[7]]) as usize;
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

    // Collect hex data from all TXT answer records
    let mut encoded_str = String::new();
    let mut found_data_start = false;

    for _ in 0..ancount {
        if pos + 10 > packet.len() {
            break; // Not enough data for another record
        }

        // Skip NAME (2 bytes if compressed pointer, otherwise read labels)
        if packet[pos] >= 0xc0 {
            pos += 2; // Compressed pointer
        } else {
            // Uncompressed name - skip labels
            while pos < packet.len() && packet[pos] != 0 {
                let len = packet[pos] as usize;
                pos += 1 + len;
            }
            pos += 1; // Null terminator
        }

        if pos + 10 > packet.len() {
            break;
        }

        // Read TYPE (2 bytes)
        let rtype = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
        pos += 2;

        // Skip CLASS (2 bytes) + TTL (4 bytes)
        pos += 6;

        // Read RDLENGTH
        if pos + 2 > packet.len() {
            break;
        }
        let rdlength = u16::from_be_bytes([packet[pos], packet[pos + 1]]) as usize;
        pos += 2;

        // Read RDATA
        if pos + rdlength > packet.len() {
            break;
        }

        // Only process TXT records (type 16)
        if rtype == 0x0010 {
            let txt_data = &packet[pos..pos + rdlength];

            // Decode TXT record (character strings with length prefixes)
            let mut i = 0;
            while i < txt_data.len() {
                let len = txt_data[i] as usize;
                i += 1;
                if i + len > txt_data.len() {
                    break;
                }

                let txt_str = std::str::from_utf8(&txt_data[i..i + len]).unwrap_or("");

                // Check if this is a data record
                if txt_str.starts_with(DATA_MARKER) {
                    // First data record - strip marker and append hex data
                    encoded_str.push_str(&txt_str[DATA_MARKER.len()..]);
                    found_data_start = true;
                } else if found_data_start && is_hex_string(txt_str) {
                    // Continuation record - pure hex data
                    encoded_str.push_str(txt_str);
                }
                // else: decoy record or garbage, skip it

                i += len;
            }
        }

        pos += rdlength;
    }

    if encoded_str.is_empty() {
        return Err("No data TXT records found".to_string());
    }

    // Decode hex to bytes
    hex::decode(&encoded_str).map_err(|e| format!("Hex decode error: {}", e))
}

/// Check if a string contains only valid hexadecimal characters
fn is_hex_string(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit())
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
        // Test with a fragment-sized payload that fits in 512 bytes
        // With hex encoding (2x) + decoy (~50 bytes) + overhead
        // Max payload ~180 bytes raw = 360 hex + 2 marker + 50 decoy + overhead
        let payload = vec![0x42; 180];

        println!("Payload size: {} bytes", payload.len());
        println!("Hex encoded size: {} bytes", hex::encode(&payload).len());

        // Build response without original query (like server does)
        let response = build_dns_response(&[], &payload, 0x1234);
        println!("DNS response packet size: {} bytes", response.len());
        assert!(response.len() <= 512, "Response exceeds 512 byte UDP limit");

        // Parse it back
        let decoded = parse_dns_response(&response).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_multi_txt_response() {
        // Test that multi-TXT responses work correctly
        let payload = vec![0xAB; 100];
        let response = build_dns_response(&[], &payload, 0x5678);

        // Check ANCOUNT is > 1 (decoy + data records)
        let ancount = u16::from_be_bytes([response[6], response[7]]);
        println!("ANCOUNT: {}", ancount);
        assert!(ancount >= 2, "Should have at least decoy + 1 data record");

        // Parse should still work
        let decoded = parse_dns_response(&response).unwrap();
        assert_eq!(decoded, payload);

        // Verify packet is valid size
        println!("Response size: {} bytes", response.len());
        assert!(response.len() <= 512);
    }

    #[test]
    fn test_decoy_filtering() {
        // Test that decoy records are properly filtered out
        let payload = b"secret data";
        let response = build_dns_response(&[], payload, 0x9999);

        // Parse should only return payload, not decoy content
        let decoded = parse_dns_response(&response).unwrap();
        assert_eq!(decoded.as_slice(), payload);

        // Verify decoy is present by checking ANCOUNT
        let ancount = u16::from_be_bytes([response[6], response[7]]);
        assert!(ancount >= 2, "Should have decoy + data record");
    }

    #[test]
    fn test_max_response_payload_200_bytes() {
        // Test the 200-byte payload limit used in production
        // This is the MAX_DNS_RESPONSE_PAYLOAD value from dns_udp_tunnel.rs
        let payload = vec![0x42; 200];

        println!("Payload size: {} bytes", payload.len());
        println!("Hex encoded size: {} bytes", hex::encode(&payload).len());

        let response = build_dns_response(&[], &payload, 0x1234);
        println!("DNS response packet size: {} bytes", response.len());

        // Must fit in 512 bytes
        assert!(response.len() <= 512, "Response {} bytes exceeds 512 byte UDP limit", response.len());

        // Parse it back
        let decoded = parse_dns_response(&response).unwrap();
        assert_eq!(decoded.len(), payload.len(), "Decoded length mismatch");
        assert_eq!(decoded, payload, "Payload content mismatch");

        // Verify ANCOUNT
        let ancount = u16::from_be_bytes([response[6], response[7]]);
        println!("ANCOUNT: {}", ancount);
        assert!(ancount >= 2, "Should have decoy + at least 1 data record");
    }

    #[test]
    fn test_tunnel_header_roundtrip() {
        // Test that DnsTunnelHeader survives encoding through DNS response
        // This is what actually gets sent over the wire

        let session_id: u16 = 0xABCD;
        let seq_num: u16 = 0;
        let total_fragments: u16 = 1;

        // Create a header + payload like the actual tunnel does
        let mut packet = Vec::new();
        packet.extend_from_slice(&session_id.to_be_bytes());
        packet.extend_from_slice(&seq_num.to_be_bytes());
        packet.extend_from_slice(&total_fragments.to_be_bytes());
        packet.extend_from_slice(b"test payload data");

        println!("Original packet ({} bytes): {:02x?}", packet.len(), &packet[..6]);

        // Encode as DNS response
        let response = build_dns_response(&[], &packet, 0x5678);
        println!("DNS response size: {} bytes", response.len());

        // Parse DNS response
        let decoded = parse_dns_response(&response).unwrap();
        println!("Decoded packet ({} bytes): {:02x?}", decoded.len(), &decoded[..6.min(decoded.len())]);

        assert_eq!(decoded.len(), packet.len(), "Length mismatch");
        assert_eq!(decoded, packet, "Content mismatch");

        // Verify the header fields decode correctly
        let decoded_session_id = u16::from_be_bytes([decoded[0], decoded[1]]);
        let decoded_seq_num = u16::from_be_bytes([decoded[2], decoded[3]]);
        let decoded_total_frags = u16::from_be_bytes([decoded[4], decoded[5]]);

        assert_eq!(decoded_session_id, session_id, "Session ID mismatch");
        assert_eq!(decoded_seq_num, seq_num, "Seq num mismatch");
        assert_eq!(decoded_total_frags, total_fragments, "Total fragments mismatch");
    }
}
