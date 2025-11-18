//! Standalone DNS UDP Tunnel Server
//!
//! Receives DNS tunnel connections and proxies them to actual destinations:
//! Client DNS Tunnel → Server (UDP DNS on port 53) → Internet

use nooshdaroo::dns_udp_tunnel::{DnsUdpTunnelServer, SessionId};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    env_logger::init();

    // Parse command line arguments
    let args: Vec<String> = std::env::args().collect();
    let listen_addr = if args.len() >= 2 {
        args[1].parse()?
    } else {
        "0.0.0.0:53".parse()?
    };

    println!("=== DNS UDP Tunnel Server ===");
    println!("Listening on: {}", listen_addr);
    println!();

    // Session connections: SessionId → TcpStream
    let sessions: Arc<Mutex<HashMap<SessionId, TcpStream>>> = Arc::new(Mutex::new(HashMap::new()));

    let server = DnsUdpTunnelServer::new(listen_addr);

    server
        .listen(move |session_id, client_addr, payload| {
            let sessions = sessions.clone();

            async move {
                let payload_str = String::from_utf8_lossy(&payload);
                println!(
                    "[DNS] Session {:04x} from {}: {}",
                    session_id,
                    client_addr,
                    payload_str.chars().take(100).collect::<String>()
                );

                // Check if this is a CONNECT request
                if payload_str.starts_with("CONNECT ") {
                    // Parse "CONNECT host:port"
                    let parts: Vec<&str> = payload_str.split_whitespace().collect();
                    if parts.len() != 2 {
                        return Ok(b"ERROR: Invalid CONNECT format".to_vec());
                    }

                    let dest = parts[1];
                    println!("[SERVER] Session {:04x} connecting to {}", session_id, dest);

                    // Connect to destination
                    match TcpStream::connect(dest).await {
                        Ok(stream) => {
                            // Store connection
                            sessions.lock().await.insert(session_id, stream);
                            println!("[SERVER] Session {:04x} connected to {}", session_id, dest);
                            Ok(b"OK: Connected".to_vec())
                        }
                        Err(e) => {
                            eprintln!(
                                "[SERVER] Session {:04x} failed to connect: {}",
                                session_id, e
                            );
                            Ok(format!("ERROR: {}", e).into_bytes())
                        }
                    }
                } else if payload_str == "PING" {
                    // Keepalive ping
                    Ok(b"PONG".to_vec())
                } else {
                    // Data packet - forward to destination
                    let mut sessions_lock = sessions.lock().await;

                    if let Some(stream) = sessions_lock.get_mut(&session_id) {
                        match stream.write_all(&payload).await {
                            Ok(_) => {
                                println!("[→DEST] Session {:04x} sent {} bytes", session_id, payload.len());

                                // Try to read response
                                let mut buf = vec![0u8; 4096];
                                match tokio::time::timeout(
                                    tokio::time::Duration::from_millis(100),
                                    stream.read(&mut buf),
                                )
                                .await
                                {
                                    Ok(Ok(n)) if n > 0 => {
                                        println!("[←DEST] Session {:04x} received {} bytes", session_id, n);
                                        Ok(buf[0..n].to_vec())
                                    }
                                    _ => Ok(b"".to_vec()), // No data yet
                                }
                            }
                            Err(e) => {
                                eprintln!("[SERVER] Session {:04x} write error: {}", session_id, e);
                                sessions_lock.remove(&session_id);
                                Ok(format!("ERROR: {}", e).into_bytes())
                            }
                        }
                    } else {
                        Ok(b"ERROR: No active connection".to_vec())
                    }
                }
            }
        })
        .await?;

    Ok(())
}
