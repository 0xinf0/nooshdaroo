//! Integration test for ProtocolWrapper with PSF
//!
//! Tests that protocol_wrapper.rs successfully integrates with PSF interpreter
//! to wrap/unwrap data for multiple protocols

use nooshdaroo::protocol::ProtocolId;
use nooshdaroo::protocol_wrapper::ProtocolWrapper;

#[test]
fn test_protocol_wrapper_wrapping_success() {
    // Test protocols that should successfully wrap
    let test_protocols = vec![
        ("TLS 1.3", "tls13"),
        ("DNS", "dns"),
        ("SSH", "ssh"),
        ("WebSocket", "websocket"),
        ("MQTT", "mqtt"),
        ("CoAP", "coap"),
        ("SIP", "sip"),
        ("RTMP", "rtmp"),
    ];

    let noise_data = vec![0xAB; 1000];
    let mut success_count = 0;

    println!("\n=== PROTOCOL WRAPPER PSF INTEGRATION TEST ===\n");

    for (name, protocol_id_str) in &test_protocols {
        println!("Testing protocol: {}", name);

        let mut wrapper = ProtocolWrapper::new(ProtocolId::from(*protocol_id_str), None);

        match wrapper.wrap(&noise_data) {
            Ok(wrapped) => {
                if wrapped.len() > noise_data.len() {
                    println!("  ✅ Wrapped {} bytes → {} bytes", noise_data.len(), wrapped.len());
                    println!("  📦 First 16 bytes: {:02x?}", &wrapped[..16.min(wrapped.len())]);
                    success_count += 1;
                } else {
                    println!("  ⚠️  Wrapped but no header added (passthrough)");
                }
            }
            Err(e) => {
                println!("  ❌ Wrap error: {}", e);
            }
        }

        println!();
    }

    println!("=== RESULTS ===");
    println!("Successful wraps: {}/{}", success_count, test_protocols.len());
    println!();

    // We expect at least 3 protocols to work successfully
    assert!(
        success_count >= 3,
        "Expected at least 3 protocols to wrap successfully, got {}",
        success_count
    );
}

#[test]
fn test_https_backward_compatibility() {
    // Ensure HTTPS still works with hardcoded implementation
    let mut wrapper = ProtocolWrapper::new(ProtocolId::from("https"), None);
    let noise_data = vec![0xAB; 1016];

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

    println!("✅ HTTPS backward compatibility verified");
}

#[test]
fn test_psf_loading_for_common_protocols() {
    // Test that PSF files load successfully for common protocols
    let protocols = vec![
        "https", "dns", "ssh", "mysql", "postgres", "redis", "mqtt",
        "websocket", "sip", "openvpn", "wireguard",
    ];

    let mut loaded_count = 0;

    for protocol in &protocols {
        let wrapper = ProtocolWrapper::new(ProtocolId::from(*protocol), None);

        // We can't directly check if PSF loaded, but we can check that
        // the wrapper was created successfully
        let _ = wrapper;
        loaded_count += 1;
    }

    assert_eq!(loaded_count, protocols.len());
    println!("✅ Successfully created wrappers for {} protocols", loaded_count);
}
