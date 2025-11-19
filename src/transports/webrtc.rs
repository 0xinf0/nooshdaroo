//! WebRTC Transport Implementation
//!
//! Provides WebRTC DataChannel transport for NAT traversal and browser compatibility.
//! WebRTC is particularly useful for censorship circumvention due to its ubiquity.

use crate::transport::{DatagramTransport, TransportConfig};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

/// WebRTC transport using DataChannels
pub struct WebRtcTransport {
    /// Data channel for sending/receiving
    data_channel: Arc<webrtc::data_channel::RTCDataChannel>,
    /// Peer connection
    peer_connection: Arc<webrtc::peer_connection::RTCPeerConnection>,
    /// Remote address (signaling server)
    remote_addr: SocketAddr,
    /// Receive channel (wrapped in Mutex for interior mutability)
    recv_rx: Arc<Mutex<mpsc::UnboundedReceiver<Vec<u8>>>>,
}

impl WebRtcTransport {
    /// Create new WebRTC transport
    pub async fn connect(config: TransportConfig) -> Result<Self> {
        // Create WebRTC configuration
        let rtc_config = webrtc::peer_connection::configuration::RTCConfiguration {
            ice_servers: vec![
                // Use public STUN servers to blend in with normal WebRTC traffic
                webrtc::ice_transport::ice_server::RTCIceServer {
                    urls: vec!["stun:stun.l.google.com:19302".to_owned()],
                    ..Default::default()
                },
            ],
            ..Default::default()
        };

        // Create API
        let api = webrtc::api::APIBuilder::new().build();

        // Create peer connection
        let peer_connection = Arc::new(
            api.new_peer_connection(rtc_config)
                .await
                .map_err(|e| anyhow!("Failed to create peer connection: {}", e))?,
        );

        log::info!("WebRTC: Created peer connection");

        // Create data channel
        let data_channel = peer_connection
            .create_data_channel("nooshdaroo", None)
            .await
            .map_err(|e| anyhow!("Failed to create data channel: {}", e))?;

        log::info!("WebRTC: Created data channel");

        // Set up receive channel
        let (recv_tx, recv_rx) = mpsc::unbounded_channel();
        let recv_tx = Arc::new(recv_tx);

        // Handle incoming messages
        let recv_tx_clone = recv_tx.clone();
        data_channel.on_message(Box::new(move |msg| {
            let recv_tx = recv_tx_clone.clone();
            Box::pin(async move {
                if recv_tx.send(msg.data.to_vec()).is_err() {
                    log::error!("WebRTC: Failed to send to recv channel");
                }
            })
        }));

        // TODO: Implement signaling exchange with server
        // This would involve:
        // 1. Create offer
        // 2. Send offer to signaling server
        // 3. Receive answer from signaling server
        // 4. Set remote description
        // 5. Exchange ICE candidates

        Ok(Self {
            data_channel,  // Already Arc'd from create_data_channel
            peer_connection,
            remote_addr: config.server_addr,
            recv_rx: Arc::new(Mutex::new(recv_rx)),
        })
    }
}

#[async_trait]
impl DatagramTransport for WebRtcTransport {
    async fn send(&self, data: &[u8]) -> Result<()> {
        // Send via WebRTC data channel
        self.data_channel
            .send(&bytes::Bytes::copy_from_slice(data))
            .await
            .map_err(|e| anyhow!("WebRTC send error: {}", e))?;

        log::debug!("WebRTC: Sent {} bytes", data.len());
        Ok(())
    }

    async fn recv(&self) -> Result<Vec<u8>> {
        // Receive from channel (lock mutex for interior mutability)
        self.recv_rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| anyhow!("WebRTC: Channel closed"))
    }

    fn max_message_size(&self) -> usize {
        // WebRTC data channels support up to 64KB messages by default
        65535
    }

    fn peer_addr(&self) -> Result<SocketAddr> {
        Ok(self.remote_addr)
    }

    async fn close(&mut self) -> Result<()> {
        self.data_channel.close().await?;
        self.peer_connection.close().await?;
        log::info!("WebRTC: Connection closed");
        Ok(())
    }
}

/// WebRTC signaling message types
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub enum SignalingMessage {
    /// SDP offer
    Offer(String),
    /// SDP answer
    Answer(String),
    /// ICE candidate
    IceCandidate(String),
}
