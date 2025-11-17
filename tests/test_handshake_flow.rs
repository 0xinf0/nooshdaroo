//! Test complete handshake flow with Noise transport and protocol wrapper

use nooshdaroo::protocol::ProtocolId;
use nooshdaroo::protocol_wrapper::ProtocolWrapper;
use nooshdaroo::noise_transport::{NoiseConfig, NoisePattern, NoiseKeypair, NoiseTransport};
use tokio::io::duplex;

#[tokio::test]
async fn test_https_handshake_flow() {
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

    // Spawn client task
    let client_handle = tokio::spawn(async move {
        let mut client_wrapper = ProtocolWrapper::new(ProtocolId::from("https"), None);

        let mut transport = NoiseTransport::client_handshake(
            &mut client_stream,
            &client_config,
            Some(&mut client_wrapper)
        ).await.expect("Client handshake should succeed");

        // Test sending encrypted data
        let test_message = b"Hello from client!";
        transport.write(&mut client_stream, test_message).await.expect("Client write should succeed");

        // Read server response
        let response = transport.read(&mut client_stream).await.expect("Client read should succeed");
        assert_eq!(&response, b"Hello from server!");

        println!("✅ Client test passed");
    });

    // Spawn server task
    let server_handle = tokio::spawn(async move {
        let mut server_wrapper = ProtocolWrapper::new(ProtocolId::from("https"), None);

        let mut transport = NoiseTransport::server_handshake(
            &mut server_stream,
            &server_config,
            Some(&mut server_wrapper)
        ).await.expect("Server handshake should succeed");

        // Read client message
        let message = transport.read(&mut server_stream).await.expect("Server read should succeed");
        assert_eq!(&message, b"Hello from client!");

        // Send response
        let response = b"Hello from server!";
        transport.write(&mut server_stream, response).await.expect("Server write should succeed");

        println!("✅ Server test passed");
    });

    // Wait for both tasks to complete
    let (client_result, server_result) = tokio::join!(client_handle, server_handle);

    client_result.expect("Client task should not panic");
    server_result.expect("Server task should not panic");

    println!("✅ Full HTTPS handshake flow test passed!");
}

#[test]
fn test_https_handshake_generation() {
    // Test that HTTPS protocol can generate handshakes
    let wrapper = ProtocolWrapper::new(ProtocolId::from("https"), None);

    assert!(wrapper.has_handshake_support(), "HTTPS should support handshake");

    // Generate client handshake
    let client_hello = wrapper.generate_client_handshake().expect("Should generate ClientHello");
    assert!(client_hello.len() > 0, "ClientHello should not be empty");
    assert_eq!(client_hello[0], 0x16, "ClientHello should start with 0x16 (Handshake)");
    assert_eq!(client_hello[1], 0x03, "ClientHello should have TLS version 0x03");
    assert_eq!(client_hello[2], 0x03, "ClientHello should have TLS version 0x03");

    // Generate server handshake
    let server_hello = wrapper.generate_server_handshake().expect("Should generate ServerHello");
    assert!(server_hello.len() > 0, "ServerHello should not be empty");
    assert_eq!(server_hello[0], 0x16, "ServerHello should start with 0x16 (Handshake)");
    assert_eq!(server_hello[1], 0x03, "ServerHello should have TLS version 0x03");
    assert_eq!(server_hello[2], 0x03, "ServerHello should have TLS version 0x03");

    println!("✅ HTTPS handshake generation test passed");
    println!("   ClientHello: {} bytes", client_hello.len());
    println!("   ServerHello: {} bytes", server_hello.len());
}
