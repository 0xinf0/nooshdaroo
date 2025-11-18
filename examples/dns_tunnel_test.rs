//! Simple DNS UDP Tunnel Test
//! Tests the DNS tunnel by sending a message from client to server and back

use nooshdaroo::dns_udp_tunnel::{DnsUdpTunnelServer, DnsUdpTunnelClient, SessionId};
use std::net::SocketAddr;
use tokio::time::{timeout, Duration};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    println!("=== DNS UDP Tunnel Test ===\n");

    // Start server in background (use port 15353 to avoid conflict with mDNS on 5353)
    let server_addr: SocketAddr = "127.0.0.1:15353".parse()?;
    let server = DnsUdpTunnelServer::new(server_addr);

    println!("Starting DNS tunnel server on {}", server_addr);

    let server_handle = tokio::spawn(async move {
        server
            .listen(|session_id, client_addr, payload| async move {
                println!(
                    "[SERVER] Session {:04x} from {}: received {} bytes",
                    session_id,
                    client_addr,
                    payload.len()
                );
                println!("[SERVER] Payload: {}", String::from_utf8_lossy(&payload));

                // Echo back with prefix
                let response = format!("ECHO: {}", String::from_utf8_lossy(&payload));
                Ok(response.as_bytes().to_vec())
            })
            .await
    });

    // Wait for server to start
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Create client
    let client_bind_addr: SocketAddr = "127.0.0.1:0".parse()?;
    let session_id: SessionId = 0x1234;
    let client = DnsUdpTunnelClient::new(server_addr, client_bind_addr, session_id);

    println!("\n[CLIENT] Sending test message...");
    let test_message = b"Hello from DNS tunnel!";

    match timeout(
        Duration::from_secs(5),
        client.send_and_receive(test_message.to_vec()),
    )
    .await
    {
        Ok(Ok(response)) => {
            println!("[CLIENT] Received response: {}", String::from_utf8_lossy(&response));
            println!("\n✅ TEST PASSED - DNS tunnel working!");
        }
        Ok(Err(e)) => {
            println!("[CLIENT] Error: {}", e);
            println!("\n❌ TEST FAILED");
        }
        Err(_) => {
            println!("[CLIENT] Timeout waiting for response");
            println!("\n❌ TEST FAILED");
        }
    }

    // Test with larger payload (requires fragmentation)
    println!("\n[CLIENT] Testing large payload (fragmentation)...");
    let large_payload = vec![0x42; 500]; // 500 bytes

    match timeout(
        Duration::from_secs(5),
        client.send_and_receive(large_payload.clone()),
    )
    .await
    {
        Ok(Ok(response)) => {
            // Response should be "ECHO: " + payload
            let expected_len = 6 + large_payload.len(); // "ECHO: ".len() + payload
            println!("[CLIENT] Received {} bytes (expected ~{})", response.len(), expected_len);

            if response.starts_with(b"ECHO: ") {
                println!("✅ Fragmentation test PASSED");
            } else {
                println!("❌ Fragmentation test FAILED - wrong response");
            }
        }
        Ok(Err(e)) => {
            println!("[CLIENT] Error: {}", e);
            println!("❌ Fragmentation test FAILED");
        }
        Err(_) => {
            println!("[CLIENT] Timeout");
            println!("❌ Fragmentation test FAILED");
        }
    }

    println!("\n=== Test Complete ===");

    // Cancel server
    server_handle.abort();

    Ok(())
}
