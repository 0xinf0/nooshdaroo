//! KCP Reliability Layer for Unreliable Transports
//!
//! Provides reliable, ordered delivery over unreliable transports (DNS UDP, ICMP).
//! Sits between Noise encryption and transport encoding layers.
//!
//! ## Architecture
//!
//! ```text
//! Noise Encryption
//!     ↓
//! KCP Reliability Layer  ← This module
//!     ↓
//! DNS/ICMP Transport
//! ```
//!
//! ## Features
//!
//! - Sequence numbers for packet ordering
//! - ACK/NACK for retransmission
//! - Sliding window flow control
//! - Congestion control
//! - Fast retransmit (don't wait for timeout)

use anyhow::{anyhow, Result};
use kcp::Kcp;
use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Mutex;
use tokio::time::{Duration, Instant};

/// KCP-based reliable transport wrapper
///
/// Provides AsyncRead/AsyncWrite interface over unreliable transport
pub struct ReliableTransport<T> {
    /// KCP protocol state
    kcp: Arc<Mutex<Kcp<KcpOutput<T>>>>,
    /// Read buffer for received data
    read_buf: Arc<Mutex<VecDeque<u8>>>,
    /// Last update time
    last_update: Arc<Mutex<Instant>>,
}

/// Output callback for KCP - sends packets to underlying transport
struct KcpOutput<T> {
    transport: Arc<Mutex<T>>,
    write_buf: Arc<Mutex<Vec<u8>>>,
}

impl<T> ReliableTransport<T>
where
    T: AsyncWrite + AsyncRead + Unpin + Send + 'static,
{
    /// Create new reliable transport with KCP
    ///
    /// # Arguments
    ///
    /// * `transport` - Underlying unreliable transport (DNS, ICMP, etc.)
    /// * `conv_id` - Conversation ID (session identifier)
    /// * `mtu` - Maximum transmission unit (should match transport fragment size)
    pub fn new(transport: T, conv_id: u32, mtu: usize) -> Result<Self> {
        let transport = Arc::new(Mutex::new(transport));
        let write_buf = Arc::new(Mutex::new(Vec::new()));

        let output = KcpOutput {
            transport: Arc::clone(&transport),
            write_buf: Arc::clone(&write_buf),
        };

        let mut kcp = Kcp::new(conv_id, output);

        // Configure KCP for low latency (matching DNSTT settings)
        // nodelay: 1 = enable
        // interval: 10ms update interval
        // resend: 2 = fast resend (resend after 2 ACKs)
        // nc: 1 = disable congestion control for low latency
        kcp.set_nodelay(1, 10, 2, 1);

        // Set window sizes (send and receive)
        kcp.set_wndsize(128, 128);

        // Set MTU to match transport fragment size
        kcp.set_mtu(mtu).map_err(|e| anyhow!("Failed to set MTU: {:?}", e))?;

        let kcp = Arc::new(Mutex::new(kcp));
        let read_buf = Arc::new(Mutex::new(VecDeque::new()));
        let last_update = Arc::new(Mutex::new(Instant::now()));

        // Start KCP update task
        let kcp_update = Arc::clone(&kcp);
        let last_update_clone = Arc::clone(&last_update);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(10)).await;

                let mut kcp_guard = kcp_update.lock().await;
                let current = Instant::now();
                let elapsed = current.duration_since(*last_update_clone.lock().await);

                kcp_guard.update(elapsed.as_millis() as u32).ok();
                *last_update_clone.lock().await = current;
            }
        });

        Ok(Self {
            kcp,
            read_buf,
            last_update,
        })
    }

    /// Send data through KCP
    pub async fn send(&self, data: &[u8]) -> Result<usize> {
        let mut kcp = self.kcp.lock().await;
        kcp.send(data).map_err(|e| anyhow!("KCP send error: {:?}", e))
    }

    /// Receive data from KCP
    pub async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        let mut kcp = self.kcp.lock().await;

        match kcp.recv(buf) {
            Ok(n) => Ok(n),
            Err(kcp::Error::RecvQueueEmpty) => Ok(0),  // No data available
            Err(e) => Err(anyhow!("KCP recv error: {:?}", e)),
        }
    }

    /// Input received packet into KCP
    pub async fn input(&self, data: &[u8]) -> Result<()> {
        let mut kcp = self.kcp.lock().await;
        kcp.input(data).map_err(|e| anyhow!("KCP input error: {:?}", e))
    }

    /// Check how many bytes can be read
    pub async fn peek_size(&self) -> Result<usize> {
        let kcp = self.kcp.lock().await;
        Ok(kcp.peeksize().unwrap_or(0))
    }

    /// Flush pending data
    pub async fn flush_kcp(&self) -> Result<()> {
        let mut kcp = self.kcp.lock().await;
        kcp.flush().map_err(|e| anyhow!("KCP flush error: {:?}", e))
    }
}

impl<T> kcp::KcpOutput for KcpOutput<T>
where
    T: AsyncWrite + Unpin + Send,
{
    fn output(&mut self, data: &[u8]) -> kcp::KcpResult<()> {
        // Store data to write buffer - will be written by async task
        let mut buf = match self.write_buf.try_lock() {
            Ok(guard) => guard,
            Err(_) => return Err(kcp::Error::UserBufNotEnough),
        };

        buf.extend_from_slice(data);
        Ok(())
    }
}

impl<T> AsyncRead for ReliableTransport<T>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Try to get lock on KCP
        let mut kcp = match this.kcp.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };

        // Check if KCP has data available
        let peek_size = kcp.peeksize().unwrap_or(0);

        if peek_size > 0 {
            // Read from KCP into buffer
            let mut temp_buf = vec![0u8; buf.remaining()];
            match kcp.recv(&mut temp_buf) {
                Ok(n) => {
                    buf.put_slice(&temp_buf[..n]);
                    return Poll::Ready(Ok(()));
                }
                Err(kcp::Error::RecvQueueEmpty) => {
                    // No data yet, need to wait
                }
                Err(e) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("KCP recv error: {:?}", e),
                    )));
                }
            }
        }

        // No data available, return pending
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl<T> AsyncWrite for ReliableTransport<T>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        // Try to get lock on KCP
        let mut kcp = match this.kcp.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "KCP lock busy",
                )));
            }
        };

        // Send through KCP
        match kcp.send(buf) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(e) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Other,
                format!("KCP send error: {:?}", e),
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Try to get lock on KCP
        let mut kcp = match this.kcp.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "KCP lock busy",
                )));
            }
        };

        // Flush KCP buffers
        match kcp.flush() {
            Ok(_) => Poll::Ready(Ok(())),
            Err(e) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Other,
                format!("KCP flush error: {:?}", e),
            ))),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // KCP doesn't have explicit shutdown
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_reliable_transport_basic() -> Result<()> {
        // Create mock transport (Vec<u8> implements AsyncRead/AsyncWrite)
        let mock_transport = Vec::new();

        let mut reliable = ReliableTransport::new(mock_transport, 1, 600)?;

        // Test write
        let test_data = b"Hello, KCP!";
        reliable.write_all(test_data).await?;
        reliable.flush().await?;

        Ok(())
    }
}
