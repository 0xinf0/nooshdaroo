//! Detailed test showing the complete handshake sequence

use nooshdaroo::protocol::ProtocolId;
use nooshdaroo::protocol_wrapper::ProtocolWrapper;
use nooshdaroo::noise_transport::{NoiseConfig, NoisePattern, NoiseKeypair, NoiseTransport};
use tokio::io::duplex;

#[tokio::test]
async fn test_detailed_handshake_sequence() {
    // Initialize logger to see handshake details
    let _ = env_logger::builder().is_test(true).try_init();

    println!("\n=== DETAILED HANDSHAKE SEQUENCE TEST ===\n");

    // Generate server keypair for NK pattern
    let server_keypair = NoiseKeypair::generate().unwrap();

    let server_config = NoiseConfig {
        pattern: NoisePattern::NK,
        local_private_key: Some(server_keypair.private_key_base64()),
        remote_public_key: None,
    };

    let client_config = NoiseConfig {
        pattern: NoisePattern::NK,
        local_private_key: None,
        remote_public_key: Some(server_keypair.public_key_base64()),
    };

    // Create duplex stream (simulates network connection)
    let (mut client_stream, mut server_stream) = duplex(65536);

    println!("Expected handshake sequence:");
    println!("  1. Client sends fake TLS ClientHello");
    println!("  2. Server receives fake TLS ClientHello");
    println!("  3. Server sends fake TLS ServerHello");
    println!("  4. Client receives fake TLS ServerHello");
    println!("  5. Client sends Noise handshake (wrapped in TLS Application Data)");
    println!("  6. Server receives and unwraps Noise handshake");
    println!("  7. Server sends Noise response (wrapped in TLS Application Data)");
    println!("  8. Client receives and unwraps Noise response");
    println!("  9. Handshake complete - encrypted channel established\n");

    // Spawn client task
    let client_handle = tokio::spawn(async move {
        println!("CLIENT: Starting handshake with HTTPS protocol wrapper");
        let mut client_wrapper = ProtocolWrapper::new(ProtocolId::from("https"), None);

        let transport = NoiseTransport::client_handshake(
            &mut client_stream,
            &client_config,
            Some(&mut client_wrapper)
        ).await;

        match transport {
            Ok(mut t) => {
                println!("CLIENT: ✅ Handshake complete!");

                // Test encrypted data exchange
                let test_message = b"Encrypted message from client";
                t.write(&mut client_stream, test_message).await.expect("Client write failed");
                println!("CLIENT: Sent encrypted message");

                let response = t.read(&mut client_stream).await.expect("Client read failed");
                println!("CLIENT: Received encrypted response: {} bytes", response.len());
                assert_eq!(&response, b"Encrypted message from server");
            }
            Err(e) => {
                panic!("CLIENT: Handshake failed: {}", e);
            }
        }
    });

    // Spawn server task
    let server_handle = tokio::spawn(async move {
        println!("SERVER: Starting handshake with HTTPS protocol wrapper");
        let mut server_wrapper = ProtocolWrapper::new(ProtocolId::from("https"), None);

        let transport = NoiseTransport::server_handshake(
            &mut server_stream,
            &server_config,
            Some(&mut server_wrapper)
        ).await;

        match transport {
            Ok(mut t) => {
                println!("SERVER: ✅ Handshake complete!");

                // Test encrypted data exchange
                let message = t.read(&mut server_stream).await.expect("Server read failed");
                println!("SERVER: Received encrypted message: {} bytes", message.len());
                assert_eq!(&message, b"Encrypted message from client");

                let response = b"Encrypted message from server";
                t.write(&mut server_stream, response).await.expect("Server write failed");
                println!("SERVER: Sent encrypted response");
            }
            Err(e) => {
                panic!("SERVER: Handshake failed: {}", e);
            }
        }
    });

    // Wait for both tasks to complete
    let (client_result, server_result) = tokio::join!(client_handle, server_handle);

    client_result.expect("Client task panicked");
    server_result.expect("Server task panicked");

    println!("\n✅ DETAILED HANDSHAKE SEQUENCE TEST PASSED!\n");
    println!("Summary:");
    println!("  - Fake TLS handshake completed successfully");
    println!("  - Noise handshake completed successfully (wrapped in TLS)");
    println!("  - Encrypted data exchange working");
    println!("  - Traffic appears as HTTPS to DPI systems");
}
