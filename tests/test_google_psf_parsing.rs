use nooshdaroo::psf::{PsfInterpreter, ProtocolFrame};

#[test]
fn test_https_google_psf_parsing() {
    // Load and parse HTTPS Google PSF
    let interp = PsfInterpreter::load_from_file("protocols/http/https_google_com.psf")
        .expect("Failed to load https_google_com.psf");

    let spec = interp.spec();
    println!("Loaded HTTPS Google PSF");
    println!("  Formats: {:?}", spec.formats.keys().collect::<Vec<_>>());
    println!("  Semantics: {} rules", spec.semantics.len());
    println!("  Sequence: {} steps", spec.sequence.len());

    // Try to create handshake frame
    let client_handshake = interp.create_frame("CLIENT", "HANDSHAKE");
    assert!(client_handshake.is_ok(), "Failed to create CLIENT HANDSHAKE frame");

    let frame = client_handshake.unwrap();

    // Try to generate handshake message
    let handshake_msg = frame.wrap_handshake();
    match &handshake_msg {
        Ok(msg) => {
            println!("✓ Generated ClientHello: {} bytes", msg.len());

            // Look for SNI in the output
            let msg_str = msg.iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>();

            // Check for "www.google.com" in hex (77 77 77 2e 67 6f 6f 67 6c 65 2e 63 6f 6d)
            if msg_str.contains("7777772e676f6f676c652e636f6d") {
                println!("✓ SNI 'www.google.com' found in handshake");
            } else {
                // Print hex dump for debugging
                println!("Hex dump of handshake:");
                for (i, chunk) in msg.chunks(16).enumerate() {
                    print!("{:04x}: ", i * 16);
                    for byte in chunk {
                        print!("{:02x} ", byte);
                    }
                    println!();
                }
            }

            assert!(msg.len() > 100, "Handshake message too small");
        }
        Err(e) => {
            println!("✗ Failed to generate handshake: {}", e);
            panic!("Handshake generation failed: {}", e);
        }
    }
}

#[test]
fn test_dns_google_psf_parsing() {
    // Load and parse DNS Google PSF
    let interp = PsfInterpreter::load_from_file("protocols/dns/dns_google_com.psf")
        .expect("Failed to load dns_google_com.psf");

    let spec = interp.spec();
    println!("Loaded DNS Google PSF");
    println!("  Formats: {:?}", spec.formats.keys().collect::<Vec<_>>());
    println!("  Semantics: {} rules", spec.semantics.len());
    println!("  Sequence: {} steps", spec.sequence.len());

    // Try to create data frame
    let client_query = interp.create_frame("CLIENT", "DATA");
    assert!(client_query.is_ok(), "Failed to create CLIENT DATA frame");

    let frame = client_query.unwrap();

    // Try to wrap some test data
    let test_data = vec![0x42; 100]; // 100 bytes of test data
    let wrapped = frame.wrap(&test_data);

    match &wrapped {
        Ok(msg) => {
            println!("✓ Generated DNS query: {} bytes", msg.len());

            // Look for "google.com" in the output
            // DNS label format: 0x06 "google" 0x03 "com" 0x00
            // Hex: 06 67 6f 6f 67 6c 65 03 63 6f 6d 00
            let msg_str = msg.iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>();

            if msg_str.contains("06676f6f676c6503636f6d00") {
                println!("✓ DNS query for 'google.com' found");
            }

            assert!(msg.len() > test_data.len(), "Wrapped message should be larger than payload");
        }
        Err(e) => {
            println!("✗ Failed to wrap DNS query: {}", e);
            panic!("DNS wrapping failed: {}", e);
        }
    }
}
