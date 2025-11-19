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
    /// Channel receiver for decoded data from KCP
    read_rx: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    /// Channel sender for decoded data (used by background task)
    _read_tx: Arc<tokio::sync::mpsc::UnboundedSender<Vec<u8>>>,
    /// Last update time
    last_update: Arc<Mutex<Instant>>,
    /// Buffer for partially read data
    partial_buf: Vec<u8>,
    partial_pos: usize,
}

/// Output callback for KCP - sends packets to underlying transport
struct KcpOutput<T> {
    transport: Arc<Mutex<T>>,
    write_buf: Arc<Mutex<VecDeque<Vec<u8>>>>,
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
        let write_buf = Arc::new(Mutex::new(VecDeque::new()));

        let output = KcpOutput {
            transport: Arc::clone(&transport),
            write_buf: Arc::clone(&write_buf),
        };

        let mut kcp = Kcp::new(conv_id, output);

        // Configure KCP for low latency (matching DNSTT settings)
        // nodelay: true = enable
        // interval: 10ms update interval
        // resend: 2 = fast resend (resend after 2 ACKs)
        // nc: true = disable congestion control for low latency
        kcp.set_nodelay(true, 10, 2, true);

        // Set window sizes (send and receive)
        kcp.set_wndsize(128, 128);

        // Set MTU to match transport fragment size
        kcp.set_mtu(mtu).map_err(|e| anyhow!("Failed to set MTU: {:?}", e))?;

        // Perform initial update (KCP requires at least one update call before use)
        kcp.update(0).ok();

        let kcp = Arc::new(Mutex::new(kcp));
        let last_update = Arc::new(Mutex::new(Instant::now()));

        // Create channel for decoded data from KCP
        let (read_tx, read_rx) = tokio::sync::mpsc::unbounded_channel();
        let read_tx = Arc::new(read_tx);

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

        // Start write task - send buffered KCP output to underlying transport
        let transport_write = Arc::clone(&transport);
        let write_buf_task = Arc::clone(&write_buf);
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;

            loop {
                tokio::time::sleep(Duration::from_millis(5)).await;

                // Check if there's data to write
                let packet = {
                    let mut buf = write_buf_task.lock().await;
                    buf.pop_front()
                };

                if let Some(data) = packet {
                    log::debug!("Write task: dequeued {} bytes, writing to transport", data.len());
                    // Write to underlying transport
                    let mut transport = transport_write.lock().await;
                    if let Err(e) = transport.write_all(&data).await {
                        log::error!("Failed to write KCP output to transport: {}", e);
                    } else {
                        log::debug!("Write task: successfully wrote to transport");
                    }
                    if let Err(e) = transport.flush().await {
                        log::error!("Failed to flush transport: {}", e);
                    }
                }
            }
        });

        // Start read task - feed transport data into KCP
        let transport_read = Arc::clone(&transport);
        let kcp_input = Arc::clone(&kcp);
        let read_tx_task = Arc::clone(&read_tx);
        tokio::spawn(async move {
            use tokio::io::AsyncReadExt;

            let mut buf = vec![0u8; 2048];
            loop {
                // Read from underlying transport
                let n = {
                    let mut transport = transport_read.lock().await;
                    match transport.read(&mut buf).await {
                        Ok(0) => {
                            log::debug!("Transport closed");
                            break;
                        }
                        Ok(n) => n,
                        Err(e) => {
                            log::error!("Failed to read from transport: {}", e);
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            continue;
                        }
                    }
                };

                // Feed into KCP
                {
                    let mut kcp_guard = kcp_input.lock().await;
                    if let Err(e) = kcp_guard.input(&buf[..n]) {
                        log::error!("KCP input error: {:?}", e);
                        continue;
                    }
                }

                // Extract all decoded data from KCP and send to channel
                loop {
                    let peek_size = {
                        let kcp_guard = kcp_input.lock().await;
                        kcp_guard.peeksize().unwrap_or(0)
                    };

                    if peek_size == 0 {
                        break;
                    }

                    // Read decoded data from KCP
                    let mut temp_buf = vec![0u8; peek_size];
                    let received = {
                        let mut kcp_guard = kcp_input.lock().await;
                        match kcp_guard.recv(&mut temp_buf) {
                            Ok(n) => Some(n),
                            Err(kcp::Error::RecvQueueEmpty) => None,
                            Err(e) => {
                                log::error!("KCP recv error: {:?}", e);
                                None
                            }
                        }
                    };

                    if let Some(n) = received {
                        // Send decoded data to channel (automatically wakes reader)
                        temp_buf.truncate(n);
                        if read_tx_task.send(temp_buf).is_err() {
                            log::debug!("Read channel closed");
                            return;
                        }
                    } else {
                        break;
                    }

                    // Yield to prevent busy loop
                    tokio::task::yield_now().await;
                }
            }
        });

        Ok(Self {
            kcp,
            read_rx,
            _read_tx: read_tx,
            last_update,
            partial_buf: Vec::new(),
            partial_pos: 0,
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
        kcp.input(data).map(|_| ()).map_err(|e| anyhow!("KCP input error: {:?}", e))
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

impl<T> std::io::Write for KcpOutput<T>
where
    T: AsyncWrite + Unpin + Send,
{
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        // Queue packet to write buffer - will be written by async task
        log::debug!("KCP output callback: writing {} bytes to write_buf", data.len());
        let mut buf = match self.write_buf.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                log::error!("KCP output callback: write_buf locked!");
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "Write buffer locked"
                ));
            }
        };

        // Store as separate packet in queue
        buf.push_back(data.to_vec());
        log::debug!("KCP output callback: queued packet, queue size now: {}", buf.len());
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
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

        // If we have partial data from previous read, use it first
        if this.partial_pos < this.partial_buf.len() {
            let remaining = this.partial_buf.len() - this.partial_pos;
            let to_copy = std::cmp::min(buf.remaining(), remaining);
            buf.put_slice(&this.partial_buf[this.partial_pos..this.partial_pos + to_copy]);
            this.partial_pos += to_copy;

            // Clear partial buffer if fully consumed
            if this.partial_pos >= this.partial_buf.len() {
                this.partial_buf.clear();
                this.partial_pos = 0;
            }

            return Poll::Ready(Ok(()));
        }

        // Try to receive new data from channel (with built-in waker support)
        match this.read_rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let to_copy = std::cmp::min(buf.remaining(), data.len());
                buf.put_slice(&data[..to_copy]);

                // If we couldn't copy all data, store remainder for next read
                if to_copy < data.len() {
                    this.partial_buf = data;
                    this.partial_pos = to_copy;
                }

                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => {
                // Channel closed - EOF
                Poll::Ready(Ok(()))
            }
            Poll::Pending => {
                // No data available yet - waker already registered by poll_recv
                Poll::Pending
            }
        }
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
        let result = match kcp.send(buf) {
            Ok(n) => n,
            Err(e) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("KCP send error: {:?}", e),
                )));
            }
        };

        // Flush immediately to trigger output callback
        if let Err(e) = kcp.flush() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Other,
                format!("KCP flush after send error: {:?}", e),
            )));
        }

        Poll::Ready(Ok(result))
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
