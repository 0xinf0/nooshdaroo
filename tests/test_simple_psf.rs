use nooshdaroo::psf::PsfInterpreter;

#[test]
fn test_simple_psf_byte_arrays() {
    let interp = PsfInterpreter::load_from_file("test_simple.psf")
        .expect("Failed to load test_simple.psf");

    let spec = interp.spec();
    println!("✓ Loaded test_simple.psf");
    println!("  Formats: {}", spec.formats.len());
    println!("  Semantics: {} rules", spec.semantics.len());

    // Print each semantic rule
    for (i, sem) in spec.semantics.iter().enumerate() {
        println!("  Semantic {}: {}.{} = {:?}", i+1, sem.format, sem.field, sem.semantic);
    }

    assert!(spec.semantics.len() > 0, "Should have semantic rules");

    // Try to create frame
    let frame = interp.create_frame("CLIENT", "DATA")
        .expect("Failed to create frame");

    // Try to wrap handshake
    let msg = frame.wrap_handshake()
        .expect("Failed to wrap handshake");

    println!("\n✓ Generated message: {} bytes", msg.len());
    println!("Hex: {}", msg.iter().map(|b| format!("{:02x}", b)).collect::<String>());

    // Should be: 42 DEADBEEF 1234
    if msg.len() >= 7 {
        assert_eq!(msg[0], 0x42, "Header should be 0x42");
        assert_eq!(&msg[1..5], &[0xDE, 0xAD, 0xBE, 0xEF], "Data bytes should match");
        assert_eq!(u16::from_be_bytes([msg[5], msg[6]]), 0x1234, "Tail should be 0x1234");
        println!("✓ All fields match expected values!");
    }
}
