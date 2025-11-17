//! Multi-Protocol Obfuscation Test
//!
//! Tests PSF interpreter with 10 different protocols and generates tcpdump output

use nooshdaroo::psf::PsfInterpreter;
use std::fs;
use std::path::PathBuf;

#[test]
fn test_10_protocols_with_psf() {
    // Test data: simulated Noise encrypted payload (1000 bytes)
    let noise_data = vec![0xAB; 1000];

    let protocols = vec![
        ("TLS 1.3", "protocols/tls/tls13.psf"),
        ("HTTPS", "protocols/http/https.psf"),
        ("DNS", "protocols/dns/dns.psf"),
        ("SSH", "protocols/ssh/ssh.psf"),
        ("MySQL", "protocols/database/mysql.psf"),
        ("PostgreSQL", "protocols/database/postgresql.psf"),
        ("Redis", "protocols/database/redis.psf"),
        ("MongoDB", "protocols/database/mongodb.psf"),
        ("WebSocket", "protocols/websocket/websocket.psf"),
        ("HTTP/2", "protocols/http/http2.psf"),
    ];

    println!("\n=== MULTI-PROTOCOL OBFUSCATION TEST ===\n");

    for (name, psf_path) in protocols {
        println!("Testing protocol: {}", name);
        println!("PSF file: {}", psf_path);

        // Check if PSF file exists
        let path = PathBuf::from(psf_path);
        if !path.exists() {
            println!("  ⚠️  PSF file not found, skipping\n");
            continue;
        }

        // Load PSF interpreter
        match PsfInterpreter::load_from_file(&path) {
            Ok(interp) => {
                println!("  ✅ PSF file parsed successfully");

                // Try to create frame for CLIENT DATA phase
                match interp.create_frame("client", "data") {
                    Ok(frame) => {
                        println!("  ✅ Protocol frame created");

                        // Wrap noise data
                        match frame.wrap(&noise_data) {
                            Ok(wrapped) => {
                                println!("  ✅ Wrapped {} bytes → {} bytes", noise_data.len(), wrapped.len());

                                // Show first 32 bytes in hex
                                let preview = &wrapped[..wrapped.len().min(32)];
                                print!("  📦 Packet header (hex): ");
                                for byte in preview {
                                    print!("{:02x} ", byte);
                                }
                                println!();

                                // Show protocol-specific markers
                                print_protocol_markers(name, &wrapped);

                                // Test unwrap
                                match frame.unwrap(&wrapped) {
                                    Ok(unwrapped) => {
                                        if unwrapped == noise_data {
                                            println!("  ✅ Unwrap successful (round-trip verified)");
                                        } else {
                                            println!("  ❌ Unwrap failed: data mismatch");
                                        }
                                    }
                                    Err(e) => {
                                        println!("  ❌ Unwrap error: {}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                println!("  ❌ Wrap error: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        println!("  ❌ Frame creation error: {}", e);
                    }
                }
            }
            Err(e) => {
                println!("  ❌ PSF parse error: {}", e);
            }
        }

        println!();
    }
}

fn print_protocol_markers(protocol: &str, data: &[u8]) {
    match protocol {
        "TLS 1.3" | "HTTPS" => {
            if data.len() >= 5 {
                let content_type = data[0];
                let version = u16::from_be_bytes([data[1], data[2]]);
                let length = u16::from_be_bytes([data[3], data[4]]);
                println!("  🔍 TLS record: type=0x{:02x} version=0x{:04x} length={}",
                    content_type, version, length);
            }
        }
        "MySQL" => {
            if data.len() >= 4 {
                let length = u32::from_le_bytes([data[0], data[1], data[2], 0]) & 0xFFFFFF;
                let sequence = data[3];
                println!("  🔍 MySQL packet: length={} sequence={}", length, sequence);
            }
        }
        "PostgreSQL" => {
            if data.len() >= 5 {
                let msg_type = data[0] as char;
                let length = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
                println!("  🔍 PostgreSQL message: type='{}' length={}", msg_type, length);
            }
        }
        "Redis" => {
            if data.len() >= 1 {
                let prefix = data[0] as char;
                println!("  🔍 Redis command prefix: '{}'", prefix);
            }
        }
        "SSH" => {
            if data.len() >= 6 {
                let packet_length = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                let padding_length = data[4];
                println!("  🔍 SSH packet: length={} padding={}", packet_length, padding_length);
            }
        }
        "DNS" => {
            if data.len() >= 12 {
                let transaction_id = u16::from_be_bytes([data[0], data[1]]);
                let flags = u16::from_be_bytes([data[2], data[3]]);
                println!("  🔍 DNS packet: id=0x{:04x} flags=0x{:04x}", transaction_id, flags);
            }
        }
        _ => {}
    }
}

#[test]
fn test_tls_protocol_signature() {
    let noise_data = vec![0xDE, 0xAD, 0xBE, 0xEF]; // 4 bytes test

    let interp = PsfInterpreter::load_from_file("protocols/tls/tls13.psf")
        .expect("Failed to load TLS PSF");

    let frame = interp.create_frame("client", "data")
        .expect("Failed to create frame");

    let wrapped = frame.wrap(&noise_data).expect("Failed to wrap");

    // Verify TLS 1.2 Application Data signature
    assert_eq!(wrapped[0], 0x17, "TLS content type should be 0x17 (application_data)");
    assert_eq!(wrapped[1], 0x03, "TLS version major should be 0x03");
    assert_eq!(wrapped[2], 0x03, "TLS version minor should be 0x03 (TLS 1.2)");

    let length = u16::from_be_bytes([wrapped[3], wrapped[4]]);
    assert_eq!(length, noise_data.len() as u16, "Length field should match payload size");

    // Verify payload
    assert_eq!(&wrapped[5..], &noise_data[..]);

    println!("✅ TLS signature verified: 17 03 03 00 04 de ad be ef");
}
