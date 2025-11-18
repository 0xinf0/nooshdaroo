//! Standalone DNS UDP Tunnel SOCKS5 Proxy Client
//!
//! This bridges SOCKS5 connections to a DNS UDP tunnel:
//! Browser/App → SOCKS5 (127.0.0.1:1080) → DNS UDP Tunnel → Server

use nooshdaroo::dns_udp_tunnel::{DnsUdpTunnelClient, SessionId};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const SOCKS_LISTEN: &str = "127.0.0.1:1080";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    // Parse command line arguments
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <dns-server-ip:port>", args[0]);
        eprintln!("Example: {} 23.128.36.101:53", args[0]);
        std::process::exit(1);
    }

    let dns_server_addr: SocketAddr = args[1].parse()?;

    println!("=== DNS UDP Tunnel SOCKS5 Proxy ===");
    println!("SOCKS5 Listener: {}", SOCKS_LISTEN);
    println!("DNS Server: {}", dns_server_addr);
    println!();

    // Start SOCKS5 listener
    let listener = TcpListener::bind(SOCKS_LISTEN).await?;
    println!("[SOCKS] Listening on {}", SOCKS_LISTEN);

    // Session ID counter
    let session_counter = Arc::new(std::sync::atomic::AtomicU16::new(0x1000));

    loop {
        let (socket, client_addr) = listener.accept().await?;
        println!("[SOCKS] New connection from {}", client_addr);

        let dns_server = dns_server_addr;
        let session_id = session_counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        tokio::spawn(async move {
            if let Err(e) = handle_socks_connection(socket, dns_server, session_id).await {
                eprintln!("[SOCKS] Error handling connection: {}", e);
            }
        });
    }
}

async fn handle_socks_connection(
    mut socket: TcpStream,
    dns_server: SocketAddr,
    session_id: SessionId,
) -> Result<(), Box<dyn std::error::Error>> {
    // SOCKS5 handshake
    let mut buf = [0u8; 512];

    // Read greeting
    socket.read_exact(&mut buf[0..2]).await?;
    if buf[0] != 0x05 {
        return Err("Not SOCKS5".into());
    }

    let nmethods = buf[1] as usize;
    socket.read_exact(&mut buf[0..nmethods]).await?;

    // Send auth method: no auth
    socket.write_all(&[0x05, 0x00]).await?;

    // Read request
    socket.read_exact(&mut buf[0..4]).await?;
    if buf[0] != 0x05 || buf[1] != 0x01 {
        return Err("Invalid SOCKS5 request".into());
    }

    let atyp = buf[3];
    let (dest_addr, dest_port) = match atyp {
        0x01 => {
            // IPv4
            socket.read_exact(&mut buf[0..6]).await?;
            let addr = format!("{}.{}.{}.{}", buf[0], buf[1], buf[2], buf[3]);
            let port = u16::from_be_bytes([buf[4], buf[5]]);
            (addr, port)
        }
        0x03 => {
            // Domain
            socket.read_exact(&mut buf[0..1]).await?;
            let len = buf[0] as usize;
            socket.read_exact(&mut buf[0..len + 2]).await?;
            let domain = String::from_utf8_lossy(&buf[0..len]).to_string();
            let port = u16::from_be_bytes([buf[len], buf[len + 1]]);
            (domain, port)
        }
        _ => return Err("Unsupported address type".into()),
    };

    println!(
        "[SOCKS] Session {:04x} → {}:{}",
        session_id, dest_addr, dest_port
    );

    // Send SOCKS5 success reply
    socket
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;

    // Now bridge SOCKS connection to DNS tunnel
    let client_bind: SocketAddr = "0.0.0.0:0".parse()?;
    let dns_client = DnsUdpTunnelClient::new(dns_server, client_bind, session_id);

    // Encode destination as "CONNECT dest:port"
    let connect_msg = format!("CONNECT {}:{}", dest_addr, dest_port);
    println!("[DNS] Sending connect request: {}", connect_msg);

    // Send connect request through DNS tunnel
    match dns_client
        .send_and_receive(connect_msg.as_bytes().to_vec())
        .await
    {
        Ok(response) => {
            let response_str = String::from_utf8_lossy(&response);
            println!("[DNS] Connect response: {}", response_str);

            if !response_str.starts_with("OK") {
                return Err(format!("Connection failed: {}", response_str).into());
            }
        }
        Err(e) => {
            return Err(format!("DNS tunnel connect failed: {}", e).into());
        }
    }

    println!("[SOCKS] Session {:04x} established", session_id);

    // Now relay data bidirectionally
    let (mut socks_read, mut socks_write) = socket.into_split();

    let dns_client_send = Arc::new(dns_client);
    let dns_client_recv = dns_client_send.clone();

    // Spawn task to read from SOCKS and send to DNS tunnel
    let send_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            match socks_read.read(&mut buf).await {
                Ok(0) => break, // EOF
                Ok(n) => {
                    println!("[→DNS] Sending {} bytes", n);
                    if let Err(e) = dns_client_send.send_and_receive(buf[0..n].to_vec()).await {
                        eprintln!("[DNS] Send error: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    eprintln!("[SOCKS] Read error: {}", e);
                    break;
                }
            }
        }
    });

    // Receive from DNS tunnel and write to SOCKS
    let recv_task = tokio::spawn(async move {
        loop {
            // Poll for data from DNS tunnel
            // Note: DnsUdpTunnelClient doesn't have a receive-only method,
            // so we send a keepalive and get response
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

            match dns_client_recv.send_and_receive(b"PING".to_vec()).await {
                Ok(data) if data.len() > 0 && data != b"PONG" => {
                    println!("[←DNS] Received {} bytes", data.len());
                    if let Err(e) = socks_write.write_all(&data).await {
                        eprintln!("[SOCKS] Write error: {}", e);
                        break;
                    }
                }
                Ok(_) => {} // Empty or PONG, continue
                Err(e) => {
                    eprintln!("[DNS] Receive error: {}", e);
                    break;
                }
            }
        }
    });

    // Wait for either task to finish
    tokio::select! {
        _ = send_task => println!("[SOCKS] Send task finished"),
        _ = recv_task => println!("[SOCKS] Receive task finished"),
    }

    Ok(())
}
