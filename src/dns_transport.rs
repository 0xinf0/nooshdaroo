//! DNS UDP Tunnel Transport
//!
//! Provides DNS tunneling as a transport layer for Nooshdaroo proxy.
//! Encodes Noise-encrypted data in DNS queries/responses for censorship bypass.
//!
//! ## Architecture
//!
//! ```text
//! Client App → SOCKS5 → Nooshdaroo → Noise → DNS Transport → Server
//! ```
//!
//! ## Usage
//!
//! Client config:
//! ```toml
//! [client]
//! protocol = "dns-udp-tunnel"
//! server_address = "nooshdaroo.net:53"
//! ```

use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};

use crate::dns_tunnel::{
    build_dns_query, build_dns_response, parse_dns_query, parse_dns_response,
};

/// DNS tunnel transport for client-side
pub struct DnsTransportClient {
    socket: Arc<UdpSocket>,
    server_addr: SocketAddr,
    session_id: u16,
}

impl DnsTransportClient {
    /// Create new DNS transport client
    pub async fn connect(server_addr: SocketAddr) -> Result<Self> {
        // Bind to random local port - match server's interface for localhost
        let local_addr: SocketAddr = if server_addr.is_ipv4() {
            if server_addr.ip().is_loopback() {
                "127.0.0.1:0"  // Match loopback interface for localhost servers
            } else {
                "0.0.0.0:0"    // For remote servers
            }
        } else {
            if server_addr.ip().is_loopback() {
                "[::1]:0"      // IPv6 loopback
            } else {
                "[::]:0"
            }
        }
        .parse()?;

        let socket = UdpSocket::bind(local_addr).await?;

        // Connect the UDP socket to server (like WireGuard) for NAT traversal
        // This creates a "connected" UDP socket that NAT routers handle bidirectionally
        socket.connect(server_addr).await?;

        let session_id = rand::random::<u16>();

        log::info!(
            "DNS transport client bound to {} → server {}",
            socket.local_addr()?,
            server_addr
        );

        Ok(Self {
            socket: Arc::new(socket),
            server_addr,
            session_id,
        })
    }

    /// Send data through DNS tunnel
    pub async fn send(&self, data: &[u8]) -> Result<()> {
        // Build DNS query with payload
        let transaction_id = self.session_id;
        let dns_query = build_dns_query(data, transaction_id);

        log::debug!(
            "DNS transport sending {} bytes (DNS packet: {} bytes)",
            data.len(),
            dns_query.len()
        );

        // Send UDP packet (using send() not send_to() since socket is connected)
        self.socket.send(&dns_query).await?;

        Ok(())
    }

    /// Receive data from DNS tunnel
    pub async fn receive(&self) -> Result<Vec<u8>> {
        // Wait for DNS response (using recv() not recv_from() since socket is connected)
        let mut buf = vec![0u8; 4096];

        let n = timeout(Duration::from_secs(10), self.socket.recv(&mut buf))
            .await
            .map_err(|_| anyhow!("DNS receive timeout"))?
            .map_err(|e| anyhow!("DNS receive error: {}", e))?;

        log::debug!("DNS transport received {} bytes", n);

        // Parse DNS response to extract payload
        let payload = parse_dns_response(&buf[..n])
            .map_err(|e| anyhow!("Failed to parse DNS response: {}", e))?;

        Ok(payload)
    }

    /// Send data and wait for response
    pub async fn send_and_receive(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.send(data).await?;
        self.receive().await
    }
}

/// DNS tunnel transport for server-side
pub struct DnsTransportServer {
    socket: Arc<UdpSocket>,
    sessions: Arc<Mutex<HashMap<SocketAddr, Session>>>,
}

struct Session {
    last_seen: std::time::Instant,
    transaction_id: u16,
}

impl DnsTransportServer {
    /// Create new DNS transport server
    pub async fn bind(listen_addr: SocketAddr) -> Result<Self> {
        let socket = UdpSocket::bind(listen_addr).await?;

        log::info!("DNS transport server listening on UDP {}", listen_addr);

        Ok(Self {
            socket: Arc::new(socket),
            sessions: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Receive DNS query from client
    pub async fn receive_query(&self) -> Result<(Vec<u8>, SocketAddr, u16)> {
        let mut buf = vec![0u8; 4096];

        // Receive UDP packet
        let (n, src_addr) = self.socket.recv_from(&mut buf).await?;

        log::debug!("DNS transport received {} bytes from {}", n, src_addr);

        // Parse DNS query
        let (transaction_id, payload) = parse_dns_query(&buf[..n])
            .map_err(|e| anyhow!("Failed to parse DNS query: {}", e))?;

        // Track session
        self.sessions.lock().await.insert(
            src_addr,
            Session {
                last_seen: std::time::Instant::now(),
                transaction_id,
            },
        );

        Ok((payload, src_addr, transaction_id))
    }

    /// Send DNS response to client
    pub async fn send_response(
        &self,
        data: &[u8],
        client_addr: SocketAddr,
        transaction_id: u16,
    ) -> Result<()> {
        // Build DNS response
        let dns_response = build_dns_response(&[], data, transaction_id);

        log::debug!(
            "DNS transport sending {} bytes to {} (DNS packet: {} bytes)",
            data.len(),
            client_addr,
            dns_response.len()
        );

        // Send UDP packet
        self.socket.send_to(&dns_response, client_addr).await?;

        Ok(())
    }

    /// Clean up old sessions
    pub async fn cleanup_sessions(&self, max_age: Duration) {
        let now = std::time::Instant::now();
        let mut sessions = self.sessions.lock().await;

        sessions.retain(|_addr, session| now.duration_since(session.last_seen) < max_age);
    }
}

/// DNS Transport Stream Adapter
///
/// Makes DnsTransportClient compatible with AsyncRead/AsyncWrite traits
/// by buffering data internally since DNS uses discrete packet operations.
pub struct DnsStream {
    client: Arc<DnsTransportClient>,
    read_buf: Arc<Mutex<Vec<u8>>>,
    write_buf: Arc<Mutex<Vec<u8>>>,
    receiving: Arc<Mutex<bool>>,  // Track if receive task is in progress
}

impl DnsStream {
    /// Create new DNS stream from transport client
    pub fn new(client: DnsTransportClient) -> Self {
        Self {
            client: Arc::new(client),
            read_buf: Arc::new(Mutex::new(Vec::new())),
            write_buf: Arc::new(Mutex::new(Vec::new())),
            receiving: Arc::new(Mutex::new(false)),
        }
    }

    /// Get reference to underlying client
    pub fn client(&self) -> &Arc<DnsTransportClient> {
        &self.client
    }
}

impl AsyncRead for DnsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let client = Arc::clone(&self.client);
        let read_buf = Arc::clone(&self.read_buf);

        let mut read_buf_guard = match read_buf.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };

        // If we have buffered data, copy to output buffer
        if !read_buf_guard.is_empty() {
            let to_copy = std::cmp::min(buf.remaining(), read_buf_guard.len());
            buf.put_slice(&read_buf_guard[..to_copy]);
            read_buf_guard.drain(..to_copy);
            return Poll::Ready(Ok(()));
        }

        // Check if a receive is already in progress
        let receiving = Arc::clone(&self.receiving);
        let mut receiving_guard = match receiving.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                // Already receiving, just wait (spawned task will wake us)
                return Poll::Pending;
            }
        };

        if *receiving_guard {
            // Already receiving, just wait (spawned task will wake us)
            return Poll::Pending;
        }

        // Mark that we're starting a receive
        *receiving_guard = true;
        drop(receiving_guard);

        // Spawn ONE task to receive data via DNS
        let waker = cx.waker().clone();
        let read_buf_clone = Arc::clone(&read_buf);
        let receiving_clone = Arc::clone(&receiving);

        tokio::spawn(async move {
            // Try to receive multiple fragments with timeout
            // Keep receiving until timeout (no more fragments available)
            let mut fragments = Vec::new();

            loop {
                match tokio::time::timeout(
                    tokio::time::Duration::from_millis(50),  // Increased timeout for fragmented messages
                    client.receive()
                ).await {
                    Ok(Ok(data)) => {
                        fragments.push(data);
                    }
                    Ok(Err(_)) => {
                        // Receive error
                        break;
                    }
                    Err(_) => {
                        // Timeout - no more fragments available
                        break;
                    }
                }
            }

            // Reassemble fragments into buffer
            if !fragments.is_empty() {
                let mut buf = read_buf_clone.lock().await;
                for fragment in fragments {
                    buf.extend_from_slice(&fragment);
                }
            }

            // Mark receive as complete
            *receiving_clone.lock().await = false;
            waker.wake();
        });

        Poll::Pending
    }
}

impl AsyncWrite for DnsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let write_buf = Arc::clone(&self.write_buf);

        let mut write_buf_guard = match write_buf.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };

        // Just buffer the data - don't send until flush
        write_buf_guard.extend_from_slice(buf);
        let len = buf.len();

        Poll::Ready(Ok(len))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let client = Arc::clone(&self.client);
        let write_buf = Arc::clone(&self.write_buf);

        let mut write_buf_guard = match write_buf.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };

        if write_buf_guard.is_empty() {
            return Poll::Ready(Ok(()));
        }

        let data_to_send = write_buf_guard.clone();
        write_buf_guard.clear();

        let waker = cx.waker().clone();
        tokio::spawn(async move {
            // Fragment large payloads to fit in DNS packets
            // Based on DNSTT: 1232 bytes is safe for most resolvers (RFC 6891 EDNS0)
            // DNS encoding adds ~2x overhead, so limit payload to 600 bytes
            const MAX_CHUNK_SIZE: usize = 600;

            if data_to_send.len() <= MAX_CHUNK_SIZE {
                // Small enough, send as single packet
                let _ = client.send(&data_to_send).await;
            } else {
                // Need to fragment - send in chunks
                for chunk in data_to_send.chunks(MAX_CHUNK_SIZE) {
                    if let Err(e) = client.send(chunk).await {
                        log::error!("Failed to send DNS fragment: {}", e);
                        break;
                    }
                    // Small delay between fragments to avoid overwhelming receiver
                    tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
                }
            }
            waker.wake();
        });

        Poll::Pending
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // DNS UDP has no shutdown concept
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dns_transport_basic() -> Result<()> {
        // Start server
        let server_addr: SocketAddr = "127.0.0.1:15353".parse()?;
        let server = DnsTransportServer::bind(server_addr).await?;

        // Start client
        let client = DnsTransportClient::connect(server_addr).await?;

        // Test data
        let test_data = b"Hello, DNS tunnel!";

        // Send in background
        let client_send = client.clone();
        let send_handle = tokio::spawn(async move {
            client_send.send(test_data).await
        });

        // Receive on server
        let (payload, client_addr, tx_id) = server.receive_query().await?;

        assert_eq!(payload, test_data);

        // Send response
        let response_data = b"Response from server";
        server.send_response(response_data, client_addr, tx_id).await?;

        // Receive response on client
        let response = client.receive().await?;

        assert_eq!(response, response_data);

        send_handle.await??;

        Ok(())
    }
}
