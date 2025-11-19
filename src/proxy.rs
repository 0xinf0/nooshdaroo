//! Multi-protocol proxy servers (HTTP, SOCKS, Transparent)

use bytes::BytesMut;
use std::net::SocketAddr;
use std::sync::Arc;
use std::collections::HashMap;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{RwLock, Mutex};
use tokio::time::Duration;
use crate::noise_transport::{NoiseTransport, NoiseConfig};
use crate::config::NooshdarooConfig;
use crate::dns_transport::{DnsTransportClient, DnsTransportServer, DnsStream};
use std::pin::Pin;
use std::task::{Context, Poll};

#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;

#[cfg(target_os = "linux")]
use std::mem;

/// Server stream that can be either TCP or DNS tunnel
enum ServerStream {
    Tcp(TcpStream),
    Dns(DnsStream),
}

impl tokio::io::AsyncRead for ServerStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            ServerStream::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
            ServerStream::Dns(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for ServerStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut *self {
            ServerStream::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
            ServerStream::Dns(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            ServerStream::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            ServerStream::Dns(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            ServerStream::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
            ServerStream::Dns(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

/// Proxy type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ProxyType {
    /// SOCKS5 proxy (existing implementation)
    Socks5,
    /// HTTP/HTTPS CONNECT proxy
    Http,
    /// Transparent proxy (iptables/pf redirect)
    Transparent,
}

/// Unified proxy listener that handles multiple proxy protocols
#[allow(dead_code)]
pub struct UnifiedProxyListener {
    listen_addr: SocketAddr,
    proxy_types: Vec<ProxyType>,
    server_addr: Option<SocketAddr>,
    noise_config: Option<crate::noise_transport::NoiseConfig>,
    protocol_id: crate::ProtocolId,
    controller: Option<Arc<RwLock<crate::ShapeShiftController>>>,
    config: Arc<crate::NooshdarooConfig>,
}

impl UnifiedProxyListener {
    /// Create new unified proxy listener
    pub fn new(listen_addr: SocketAddr, proxy_types: Vec<ProxyType>, protocol_id: crate::ProtocolId, config: Arc<crate::NooshdarooConfig>) -> Self {
        Self {
            listen_addr,
            proxy_types,
            server_addr: None,
            noise_config: None,
            protocol_id,
            controller: None,
            config,
        }
    }

    /// Set server address for tunneling mode
    pub fn with_server(mut self, addr: SocketAddr, noise_config: crate::noise_transport::NoiseConfig) -> Self {
        self.server_addr = Some(addr);
        self.noise_config = Some(noise_config);
        self
    }

    /// Set ShapeShiftController for dynamic protocol rotation
    pub fn with_controller(mut self, controller: Arc<RwLock<crate::ShapeShiftController>>) -> Self {
        self.controller = Some(controller);
        self
    }

    /// Start listening and accept connections (both TCP and UDP for dns-udp-tunnel)
    pub async fn listen(self) -> Result<(), Box<dyn std::error::Error>> {
        // Check if we need UDP listener for DNS tunneling
        let needs_udp = self.protocol_id.as_str() == "dns-udp-tunnel"
            || self.protocol_id.as_str() == "dns_udp_tunnel"
            || self.protocol_id.as_str() == "quic";

        // Spawn UDP listener if needed (SERVER MODE ONLY)
        // If server_addr is Some(), we're in CLIENT mode - don't start UDP server
        // If server_addr is None, we're in SERVER mode - start UDP server
        if needs_udp && self.server_addr.is_none() {
            let udp_addr = self.listen_addr;
            let noise_config = self.noise_config.clone();
            let config = self.config.clone();

            tokio::spawn(async move {
                if let Err(e) = run_udp_dns_server(udp_addr, noise_config, config).await {
                    log::error!("UDP DNS server error: {}", e);
                }
            });

            log::info!("Nooshdaroo server listening on {} (TCP + UDP for DNS tunnel)", self.listen_addr);
        } else {
            log::info!("Nooshdaroo unified proxy listening on {} (TCP only)", self.listen_addr);
        }

        // Start TCP listener (always needed for backward compatibility)
        let listener = TcpListener::bind(self.listen_addr).await?;

        loop {
            let (socket, peer_addr) = listener.accept().await?;
            log::debug!("Accepted TCP connection from {}", peer_addr);

            let proxy_types = self.proxy_types.clone();
            let server_addr = self.server_addr;
            let noise_config = self.noise_config.clone();
            let protocol_id = self.protocol_id.clone();

            let controller_clone = self.controller.clone();
            let config = self.config.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_connection(socket, peer_addr, proxy_types, server_addr, noise_config, protocol_id, controller_clone, config).await {
                    log::error!("TCP connection error from {}: {}", peer_addr, e);
                }
            });
        }
    }
}

/// Handle incoming connection with auto-detection
async fn handle_connection(
    mut socket: TcpStream,
    peer_addr: SocketAddr,
    supported_types: Vec<ProxyType>,
    server_addr: Option<SocketAddr>,
    noise_config: Option<crate::noise_transport::NoiseConfig>,
    protocol_id: crate::ProtocolId,
    controller: Option<Arc<RwLock<crate::ShapeShiftController>>>,
    config: Arc<crate::NooshdarooConfig>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Peek at first bytes to detect protocol
    let mut buf = BytesMut::with_capacity(4096);

    log::debug!("Reading protocol detection bytes from {}", peer_addr);

    // Read until we have at least 1 byte for protocol detection
    loop {
        let n = socket.read_buf(&mut buf).await?;
        log::debug!("Read {} bytes from {}, total buffer: {}", n, peer_addr, buf.len());

        if n == 0 {
            log::debug!("Connection closed by {} before protocol detection", peer_addr);
            return Ok(());
        }

        // Need at least 1 byte to detect protocol (SOCKS5 only needs first byte = 0x05)
        if !buf.is_empty() {
            log::debug!("Got {} bytes for protocol detection from {}", buf.len(), peer_addr);
            break;
        }
    }

    // Detect proxy protocol
    let preview_len = std::cmp::min(buf.len(), 4);
    log::debug!("Attempting to detect protocol from {} (first {} bytes: {:02x?})", peer_addr, preview_len, &buf[..preview_len]);
    let proxy_type = detect_proxy_type(&buf, &supported_types)?;
    log::debug!("Detected {:?} proxy from {}", proxy_type, peer_addr);

    match proxy_type {
        ProxyType::Socks5 => handle_socks5(socket, buf, peer_addr, server_addr, noise_config, protocol_id, controller, config).await,
        ProxyType::Http => handle_http(socket, buf, peer_addr).await,
        ProxyType::Transparent => handle_transparent(socket, buf, peer_addr).await,
    }
}

/// Detect proxy type from initial bytes
fn detect_proxy_type(
    buf: &BytesMut,
    supported: &[ProxyType],
) -> Result<ProxyType, Box<dyn std::error::Error>> {
    if buf.is_empty() {
        return Err("Not enough data to detect protocol".into());
    }

    // SOCKS5: First byte is 0x05 (version)
    // Only need 1 byte to detect SOCKS5
    if buf[0] == 0x05 && supported.contains(&ProxyType::Socks5) {
        return Ok(ProxyType::Socks5);
    }

    // HTTP: Starts with HTTP method (GET, POST, CONNECT, etc.)
    if supported.contains(&ProxyType::Http) {
        let prefix = String::from_utf8_lossy(&buf[..std::cmp::min(buf.len(), 16)]);
        if prefix.starts_with("CONNECT ")
            || prefix.starts_with("GET ")
            || prefix.starts_with("POST ")
            || prefix.starts_with("PUT ")
            || prefix.starts_with("HEAD ")
        {
            return Ok(ProxyType::Http);
        }
    }

    // Transparent: No proxy protocol, direct connection
    if supported.contains(&ProxyType::Transparent) {
        return Ok(ProxyType::Transparent);
    }

    Err("Unable to detect supported proxy protocol".into())
}

/// Handle SOCKS5 proxy connection with complete RFC 1928 implementation
async fn handle_socks5(
    socket: TcpStream,
    buf: BytesMut,
    peer_addr: SocketAddr,
    server_addr: Option<SocketAddr>,
    noise_config: Option<crate::noise_transport::NoiseConfig>,
    protocol_id: crate::ProtocolId,
    controller: Option<Arc<RwLock<crate::ShapeShiftController>>>,
    config: Arc<crate::NooshdarooConfig>,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::socks5::{socks5_handshake, connect_target, send_reply, copy_bidirectional, Command, ReplyCode, PrefixedStream};
    use crate::noise_transport::NoiseTransport;
    use crate::protocol_wrapper::ProtocolWrapper;

    log::debug!("SOCKS5 connection from {}", peer_addr);

    // Wrap socket with already-read data
    let mut socket = PrefixedStream::new(socket, buf);

    // Perform complete SOCKS5 handshake
    let (command, target) = match socks5_handshake(&mut socket).await {
        Ok(result) => result,
        Err(e) => {
            log::error!("SOCKS5 handshake failed from {}: {}", peer_addr, e);
            return Err(e.into());
        }
    };

    log::info!("SOCKS5 {:?} request to {}:{} from {}", command, target.host, target.port, peer_addr);

    match command {
        Command::Connect => {
            // Check if we should tunnel through server or connect directly
            if let (Some(server_addr), Some(noise_config)) = (server_addr, noise_config) {
                // TUNNEL MODE: Connect to server via Noise encryption
                log::info!("Tunneling to {}:{} via server {}", target.host, target.port, server_addr);

                // Connect to server - use DNS tunnel if protocol is dns-udp-tunnel
                let mut server_stream = if protocol_id.as_str() == "dns-udp-tunnel"
                    || protocol_id.as_str() == "dns_udp_tunnel"
                    || protocol_id.as_str() == "dnsudptunnel" {
                    // DNS UDP Tunnel mode
                    match DnsTransportClient::connect(server_addr).await {
                        Ok(dns_client) => {
                            log::info!("DNS UDP tunnel connected to {}", server_addr);
                            ServerStream::Dns(DnsStream::new(dns_client))
                        }
                        Err(e) => {
                            log::error!("Failed to connect DNS tunnel to {}: {}", server_addr, e);
                            send_reply(&mut socket, ReplyCode::GeneralFailure, &target).await?;
                            return Err(e.into());
                        }
                    }
                } else {
                    // TCP mode (HTTPS, HTTP, etc.)
                    match TcpStream::connect(server_addr).await {
                        Ok(stream) => {
                            // Enable TCP_NODELAY for low latency (critical for HTTP/2)
                            stream.set_nodelay(true)?;
                            log::debug!("TCP connected to server {}", server_addr);
                            ServerStream::Tcp(stream)
                        }
                        Err(e) => {
                            log::error!("Failed to connect to server {}: {}", server_addr, e);
                            send_reply(&mut socket, ReplyCode::GeneralFailure, &target).await?;
                            return Err(e.into());
                        }
                    }
                };

                // Create protocol wrapper for handshake wrapping
                // NOTE: DNS protocol doesn't need wrapper - DNS format IS the protocol wrapping
                let is_dns = protocol_id.as_str() == "dns-udp-tunnel"
                    || protocol_id.as_str() == "dns_udp_tunnel"
                    || protocol_id.as_str() == "dnsudptunnel";

                let mut protocol_wrapper = if !is_dns {
                    Some(ProtocolWrapper::new(protocol_id.clone(), crate::WrapperRole::Client, None))
                } else {
                    None
                };
                log::debug!("Using protocol: {} (wrapper: {})", protocol_id.as_str(), protocol_wrapper.is_some());

                // Perform Noise handshake with protocol wrapping (if applicable)
                let (mut noise_transport, use_tls_emulation) = match NoiseTransport::client_handshake(&mut server_stream, &noise_config, protocol_wrapper.as_mut()).await {
                    Ok(mut transport) => {
                        log::debug!("Noise handshake completed with server using {}", protocol_id.as_str());

                        // Enable TLS session emulation if configured AND protocol is TLS-based
                        let is_tls_protocol = protocol_id.as_str().starts_with("https") ||
                                              protocol_id.as_str().starts_with("tls") ||
                                              protocol_id.as_str() == "dns" || // DNS over TLS
                                              protocol_id.as_str() == "dns-google";

                        // Check if we should enable TLS session emulation
                        let use_tls_emulation = config.detection.enable_tls_session_emulation && is_tls_protocol;
                        if use_tls_emulation {
                            transport.enable_tls_wrapping();
                            log::info!("Full TLS session emulation enabled for protocol: {}", protocol_id.as_str());
                        }

                        (transport, use_tls_emulation)
                    }
                    Err(e) => {
                        log::error!("Noise handshake failed: {}", e);
                        send_reply(&mut socket, ReplyCode::GeneralFailure, &target).await?;
                        return Err(e.into());
                    }
                };

                // Send target info to server through encrypted tunnel
                // IPv6 addresses must be wrapped in brackets: [2a00:800::1]:80
                let target_info = if target.host.contains(':') {
                    // IPv6 address - wrap in brackets
                    format!("[{}]:{}", target.host, target.port)
                } else {
                    // IPv4 or hostname
                    format!("{}:{}", target.host, target.port)
                };
                // Use write_raw() for DNS (no length prefix needed for UDP)
                let write_result = if is_dns {
                    noise_transport.write_raw(&mut server_stream, target_info.as_bytes()).await
                } else {
                    noise_transport.write(&mut server_stream, target_info.as_bytes()).await
                };
                match write_result {
                    Ok(_) => {
                        log::debug!("Sent target info to server: {}", target_info);
                    }
                    Err(e) => {
                        log::error!("Failed to send target info: {}", e);
                        send_reply(&mut socket, ReplyCode::GeneralFailure, &target).await?;
                        return Err(e.into());
                    }
                }

                // Wait for server's connection confirmation
                // Use read_raw() for DNS (no length prefix), read() for TCP
                let response = if is_dns {
                    match noise_transport.read_raw(&mut server_stream).await {
                        Ok(data) => data,
                        Err(e) => {
                            log::error!("Failed to receive server response (DNS): {}", e);
                            send_reply(&mut socket, ReplyCode::GeneralFailure, &target).await?;
                            return Err(e.into());
                        }
                    }
                } else {
                    match noise_transport.read(&mut server_stream).await {
                        Ok(data) => data,
                        Err(e) => {
                            log::error!("Failed to receive server response: {}", e);
                            send_reply(&mut socket, ReplyCode::GeneralFailure, &target).await?;
                            return Err(e.into());
                        }
                    }
                };

                let response_str = String::from_utf8_lossy(&response);
                if response_str != "OK" {
                    log::error!("Server returned error: {}", response_str);
                    let reply = if response_str.contains("refused") {
                        ReplyCode::ConnectionRefused
                    } else if response_str.contains("unreachable") {
                        ReplyCode::HostUnreachable
                    } else {
                        ReplyCode::GeneralFailure
                    };
                    send_reply(&mut socket, reply, &target).await?;
                    return Err(format!("Server error: {}", response_str).into());
                }

                // Send success reply to SOCKS5 client
                send_reply(&mut socket, ReplyCode::Succeeded, &target).await?;
                log::info!("Tunnel established to {}:{} via server", target.host, target.port);

                // Relay data bidirectionally through encrypted tunnel
                log::debug!("Starting encrypted relay for {}:{}", target.host, target.port);

                // DNS uses UDP (no length prefix), TLS emulation uses built-in wrapping
                if is_dns {
                    // Use DNS-specific relay (no length prefix for UDP)
                    log::debug!("Using DNS transport layer (UDP, no length prefix)");
                    if let Err(e) = relay_dns_tunnel(socket, server_stream, noise_transport).await {
                        log::debug!("Tunnel relay ended for {}:{}: {}", target.host, target.port, e);
                    } else {
                        log::debug!("Tunnel relay completed successfully for {}:{}", target.host, target.port);
                    }
                } else if use_tls_emulation {
                    // Use NoiseTransport's built-in TLS wrapping (no protocol wrapper)
                    log::debug!("Using TLS session emulation (no protocol wrapper)");
                    if let Err(e) = relay_with_noise_only(socket, server_stream, noise_transport).await {
                        log::debug!("Tunnel relay ended for {}:{}: {}", target.host, target.port, e);
                    } else {
                        log::debug!("Tunnel relay completed successfully for {}:{}", target.host, target.port);
                    }
                } else {
                    // Use protocol wrapper for obfuscation
                    let wrapper = crate::ProtocolWrapper::new(protocol_id.clone(), crate::WrapperRole::Client, None);
                    log::debug!("Created {} protocol wrapper for traffic obfuscation", protocol_id.as_str());
                    if let Err(e) = relay_through_noise_tunnel(socket, server_stream, noise_transport, wrapper, controller).await {
                        log::debug!("Tunnel relay ended for {}:{}: {}", target.host, target.port, e);
                    } else {
                        log::debug!("Tunnel relay completed successfully for {}:{}", target.host, target.port);
                    }
                }
            } else {
                // NO SERVER CONFIGURED: Refuse connection for security
                log::error!("No server configured - refusing direct connection to {}:{} for security", target.host, target.port);
                send_reply(&mut socket, ReplyCode::NotAllowed, &target).await?;
                return Err("Direct connections not allowed - server configuration required".into());
            }
            /*
            // REMOVED: Direct connection fallback is a security risk
            // If tunnel fails, connections should be blocked, not leaked
            } else {
                let mut target_stream = match connect_target(&target).await {
                    Ok(stream) => {
                        send_reply(&mut socket, ReplyCode::Succeeded, &target).await?;
                        stream
                    }
                    Err(e) => {
                        send_reply(&mut socket, ReplyCode::GeneralFailure, &target).await?;
                        return Err(e.into());
                    }
                };
                log::debug!("Starting bidirectional relay for {}:{}", target.host, target.port);
                if let Err(e) = copy_bidirectional(socket, &mut target_stream).await {
                    log::debug!("Relay ended for {}:{}: {}", target.host, target.port, e);
                } else {
                    log::debug!("Relay completed successfully for {}:{}", target.host, target.port);
                }
            }
            */
        }
        Command::Bind => {
            log::warn!("SOCKS5 BIND command not supported");
            send_reply(&mut socket, ReplyCode::CommandNotSupported, &target).await?;
        }
        Command::UdpAssociate => {
            log::info!("[UDP] SOCKS5 UDP ASSOCIATE request received for target {}:{}", target.host, target.port);
            log::warn!("[UDP] SOCKS5 UDP ASSOCIATE command not yet integrated - DNS queries will fail");
            send_reply(&mut socket, ReplyCode::CommandNotSupported, &target).await?;
        }
    }

    Ok(())
}

/// Relay data through Noise-encrypted tunnel with protocol wrapping and dynamic rotation
/// Relay using NoiseTransport only (for TLS session emulation)
async fn relay_with_noise_only(
    mut client: impl AsyncReadExt + AsyncWriteExt + Unpin,
    mut server: impl AsyncReadExt + AsyncWriteExt + Unpin,
    mut noise: NoiseTransport,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut client_buf = vec![0u8; 8192];
    let mut client_closed = false;
    let mut server_closed = false;

    loop {
        tokio::select! {
            // Read from client, encrypt+wrap with TLS, send to server
            result = client.read(&mut client_buf), if !client_closed => {
                match result {
                    Ok(0) => {
                        // Client closed write half - shutdown server write, but keep reading
                        log::debug!("Client closed connection, shutting down server write");
                        client_closed = true;
                        if server_closed {
                            break;
                        }
                    }
                    Ok(n) => {
                        // NoiseTransport.write() handles encryption AND TLS wrapping
                        noise.write(&mut server, &client_buf[..n]).await?;
                    }
                    Err(e) => {
                        log::debug!("Client read error: {}", e);
                        client_closed = true;
                        if server_closed {
                            break;
                        }
                    }
                }
            }
            // Read from server (TLS-wrapped), unwrap+decrypt, send to client
            result = noise.read(&mut server), if !server_closed => {
                match result {
                    Ok(data) if !data.is_empty() => {
                        // NoiseTransport.read() handles TLS unwrapping AND decryption
                        client.write_all(&data).await?;
                        client.flush().await?;
                    }
                    Ok(_) => {
                        // Server closed connection
                        log::debug!("Server closed connection");
                        server_closed = true;
                        if client_closed {
                            break;
                        }
                    }
                    Err(e) => {
                        log::debug!("Noise read error: {}", e);
                        server_closed = true;
                        if client_closed {
                            break;
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

/// Relay function for DNS/UDP transports (no length-prefixed framing)
async fn relay_dns_tunnel(
    mut client: impl AsyncReadExt + AsyncWriteExt + Unpin,
    mut server: impl AsyncReadExt + AsyncWriteExt + Unpin,
    mut noise: NoiseTransport,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut client_buf = vec![0u8; 8192];
    let mut client_closed = false;
    let mut server_closed = false;

    loop {
        tokio::select! {
            // Read from client, encrypt without length prefix, send to server
            result = client.read(&mut client_buf), if !client_closed => {
                match result {
                    Ok(0) => {
                        log::debug!("Client closed connection, shutting down server write");
                        client_closed = true;
                        if server_closed {
                            break;
                        }
                    }
                    Ok(n) => {
                        // Use write_raw() for DNS - no length prefix
                        noise.write_raw(&mut server, &client_buf[..n]).await?;
                    }
                    Err(e) => {
                        log::debug!("Client read error: {}", e);
                        client_closed = true;
                        if server_closed {
                            break;
                        }
                    }
                }
            }
            // Read from server, decrypt without expecting length prefix, send to client
            result = noise.read_raw(&mut server), if !server_closed => {
                match result {
                    Ok(data) if !data.is_empty() => {
                        // read_raw() handles decryption without length prefix
                        client.write_all(&data).await?;
                        client.flush().await?;
                    }
                    Ok(_) => {
                        log::debug!("Server closed connection");
                        server_closed = true;
                        if client_closed {
                            break;
                        }
                    }
                    Err(e) => {
                        log::debug!("Noise read error: {}", e);
                        server_closed = true;
                        if client_closed {
                            break;
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

async fn relay_through_noise_tunnel(
    mut client: impl AsyncReadExt + AsyncWriteExt + Unpin,
    mut server: impl AsyncReadExt + AsyncWriteExt + Unpin,
    mut noise: NoiseTransport,
    mut wrapper: crate::ProtocolWrapper,
    controller: Option<Arc<RwLock<crate::ShapeShiftController>>>,
) -> Result<(), Box<dyn std::error::Error>> {
    use tokio::io::AsyncWriteExt;
    let mut client_buf = vec![0u8; 8192];

    loop {
        // Check if rotation is needed (if controller exists)
        if let Some(ref ctrl) = controller {
            if let Ok(mut guard) = ctrl.try_write() {
                if guard.should_rotate() {
                    if guard.rotate().is_ok() {
                        let new_protocol = guard.stats().current_protocol.clone();
                        log::info!("Protocol rotation triggered: switching to {}", new_protocol.as_str());
                        wrapper = crate::ProtocolWrapper::new(new_protocol, crate::WrapperRole::Client, None);
                        log::debug!("Protocol wrapper updated for rotation");
                    }
                }
            }
        }

        tokio::select! {
            // Read from client, encrypt, wrap, send to server
            result = client.read(&mut client_buf) => {
                match result {
                    Ok(0) => break, // EOF
                    Ok(n) => {
                        // Encrypt with Noise
                        let encrypted = noise.encrypt(&client_buf[..n])?;
                        log::debug!("Encrypted {} bytes to {} bytes", n, encrypted.len());

                        // Wrap with protocol headers (do this before await)
                        let wrapped = wrapper.wrap(&encrypted)?;
                        let wrapped_len = wrapped.len();
                        log::debug!("Wrapped {} bytes to {} bytes with protocol obfuscation", encrypted.len(), wrapped_len);

                        // Write wrapped data to server
                        noise.write_raw(&mut server, &wrapped).await?;
                    }
                    Err(e) => {
                        log::debug!("Client read error: {}", e);
                        break;
                    }
                }
            }
            // Read from server (wrapped), unwrap, decrypt, send to client
            result = noise.read_raw(&mut server) => {
                match result {
                    Ok(wrapped) if !wrapped.is_empty() => {
                        let wrapped_len = wrapped.len();

                        // Unwrap protocol headers (do this before decrypt which needs &mut wrapper)
                        let encrypted = wrapper.unwrap(&wrapped)?;
                        let encrypted_len = encrypted.len();
                        log::debug!("Unwrapped {} bytes to {} bytes", wrapped_len, encrypted_len);

                        // Decrypt with Noise
                        let data = noise.decrypt(&encrypted)?;
                        log::debug!("Decrypted {} bytes to {} bytes", encrypted_len, data.len());

                        // Send to client
                        client.write_all(&data).await?;
                    }
                    Ok(_) => break, // Empty read = EOF
                    Err(e) => {
                        log::debug!("Noise read error: {}", e);
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

/// Handle HTTP CONNECT proxy
async fn handle_http(
    mut socket: TcpStream,
    mut buf: BytesMut,
    peer_addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    // Read complete HTTP request
    loop {
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        socket.readable().await?;
        socket.try_read_buf(&mut buf)?;
    }

    let request = String::from_utf8_lossy(&buf);
    log::debug!("HTTP request from {}: {}", peer_addr, request.lines().next().unwrap_or(""));

    // Parse CONNECT request
    let target = parse_http_connect(&request)?;
    log::info!("HTTP CONNECT to {} from {}", target, peer_addr);

    // Send success response
    socket
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;

    // TODO: Connect to target through Nooshdaroo encryption/obfuscation
    // For now, just acknowledge
    log::info!("HTTP CONNECT established for {}", target);

    Ok(())
}

/// Handle transparent proxy connection
async fn handle_transparent(
    socket: TcpStream,
    _buf: BytesMut,
    peer_addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    // Get original destination (requires SO_ORIGINAL_DST socket option)
    let orig_dest = get_original_destination(&socket)?;
    log::info!("Transparent proxy: {} -> {}", peer_addr, orig_dest);

    // TODO: Connect to original destination through Nooshdaroo
    Ok(())
}

/// Parse HTTP CONNECT target
fn parse_http_connect(request: &str) -> Result<String, Box<dyn std::error::Error>> {
    let first_line = request.lines().next().ok_or("Empty request")?;
    let parts: Vec<&str> = first_line.split_whitespace().collect();

    if parts.len() < 2 {
        return Err("Invalid CONNECT request".into());
    }

    if parts[0] != "CONNECT" {
        return Err("Not a CONNECT request".into());
    }

    Ok(parts[1].to_string())
}

/// Get original destination for transparent proxy
fn get_original_destination(socket: &TcpStream) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    #[cfg(target_os = "linux")]
    {

        // SO_ORIGINAL_DST = 80 on Linux
        const SO_ORIGINAL_DST: libc::c_int = 80;

        let fd = socket.as_raw_fd();
        let mut addr: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let mut addr_len: libc::socklen_t = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;

        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::IPPROTO_IP,
                SO_ORIGINAL_DST,
                &mut addr as *mut _ as *mut libc::c_void,
                &mut addr_len,
            )
        };

        if ret != 0 {
            return Err("Failed to get original destination".into());
        }

        // Convert to SocketAddr
        let addr_family = unsafe { (*((&addr) as *const _ as *const libc::sockaddr)).sa_family };

        match addr_family as i32 {
            libc::AF_INET => {
                let addr_in = unsafe { *((&addr) as *const _ as *const libc::sockaddr_in) };
                let ip = std::net::Ipv4Addr::from(u32::from_be(addr_in.sin_addr.s_addr));
                let port = u16::from_be(addr_in.sin_port);
                Ok(SocketAddr::new(ip.into(), port))
            }
            libc::AF_INET6 => {
                let addr_in6 = unsafe { *((&addr) as *const _ as *const libc::sockaddr_in6) };
                let ip = std::net::Ipv6Addr::from(addr_in6.sin6_addr.s6_addr);
                let port = u16::from_be(addr_in6.sin6_port);
                Ok(SocketAddr::new(ip.into(), port))
            }
            _ => Err("Unknown address family".into()),
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        // For macOS, use PF (packet filter) or fallback
        Err("Transparent proxy not supported on this platform".into())
    }
}

/// HTTP proxy server (standalone)
#[allow(dead_code)]
pub struct HttpProxyServer {
    listen_addr: SocketAddr,
}

impl HttpProxyServer {
    pub fn new(listen_addr: SocketAddr) -> Self {
        Self { listen_addr }
    }

    pub async fn listen(self) -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(self.listen_addr).await?;
        log::info!("HTTP proxy listening on {}", self.listen_addr);

        loop {
            let (socket, peer_addr) = listener.accept().await?;
            tokio::spawn(async move {
                if let Err(e) = handle_http_connection(socket, peer_addr).await {
                    log::error!("HTTP proxy error: {}", e);
                }
            });
        }
    }
}

async fn handle_http_connection(
    mut socket: TcpStream,
    peer_addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut buf = BytesMut::with_capacity(8192);

    // Read request
    loop {
        socket.readable().await?;
        socket.try_read_buf(&mut buf)?;

        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    let request = String::from_utf8_lossy(&buf);
    let first_line = request.lines().next().unwrap_or("");

    log::debug!("HTTP request from {}: {}", peer_addr, first_line);

    if first_line.starts_with("CONNECT ") {
        // CONNECT method for HTTPS
        socket
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        // TODO: Tunnel through Nooshdaroo
    } else {
        // Regular HTTP request
        // TODO: Proxy through Nooshdaroo
        socket
            .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            .await?;
    }

    Ok(())
}

/// Session state for each DNS client
struct DnsSession {
    last_seen: std::time::Instant,
    noise_transport: Option<NoiseTransport>,
    target_conn: Option<TcpStream>,
    pending_response: Vec<u8>,
    handshake_complete: bool,
}

/// UDP DNS server for dns-udp-tunnel protocol
pub async fn run_udp_dns_server(
    addr: SocketAddr,
    noise_config: Option<NoiseConfig>,
    config: Arc<NooshdarooConfig>,
) -> Result<(), Box<dyn std::error::Error>> {
    let dns_server = Arc::new(DnsTransportServer::bind(addr).await?);
    log::info!("UDP DNS server listening on {}", addr);

    let sessions: Arc<Mutex<HashMap<SocketAddr, DnsSession>>> =
        Arc::new(Mutex::new(HashMap::new()));

    // Spawn cleanup task
    let sessions_cleanup = Arc::clone(&sessions);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
            let mut sessions = sessions_cleanup.lock().await;
            let now = std::time::Instant::now();
            sessions.retain(|addr, session| {
                let keep = now.duration_since(session.last_seen) < Duration::from_secs(300);
                if !keep {
                    log::debug!("Cleaning up stale DNS session for {}", addr);
                }
                keep
            });
        }
    });

    // Main loop: receive and handle DNS queries
    loop {
        match dns_server.receive_query().await {
            Ok((payload, client_addr, tx_id)) => {
                log::debug!(
                    "DNS query from {}: {} bytes, tx_id={}",
                    client_addr,
                    payload.len(),
                    tx_id
                );

                let dns_server = Arc::clone(&dns_server);
                let sessions = Arc::clone(&sessions);
                let noise_config = noise_config.clone();
                let config = Arc::clone(&config);

                tokio::spawn(async move {
                    if let Err(e) = handle_dns_query(
                        dns_server,
                        payload,
                        client_addr,
                        tx_id,
                        sessions,
                        noise_config,
                        config,
                    )
                    .await
                    {
                        log::error!("DNS query handler error for {}: {}", client_addr, e);
                    }
                });
            }
            Err(e) => {
                log::error!("Failed to receive DNS query: {}", e);
            }
        }
    }
}

/// Handle a single DNS query
async fn handle_dns_query(
    dns_server: Arc<DnsTransportServer>,
    payload: Vec<u8>,
    client_addr: SocketAddr,
    tx_id: u16,
    sessions: Arc<Mutex<HashMap<SocketAddr, DnsSession>>>,
    noise_config: Option<NoiseConfig>,
    config: Arc<NooshdarooConfig>,
) -> Result<(), Box<dyn std::error::Error>> {
    log::debug!(
        "Handling DNS query from {}: {} bytes (tx_id={})",
        client_addr,
        payload.len(),
        tx_id
    );

    // Get or create session
    let mut sessions_guard = sessions.lock().await;
    let session = sessions_guard
        .entry(client_addr)
        .or_insert_with(|| {
            log::info!("Creating new DNS tunnel session for {}", client_addr);
            DnsSession {
                last_seen: std::time::Instant::now(),
                noise_transport: None,
                target_conn: None,
                pending_response: Vec::new(),
                handshake_complete: false,
            }
        });
    session.last_seen = std::time::Instant::now();

    // Check if we need to perform Noise handshake
    if session.noise_transport.is_none() {
        if let Some(ref noise_cfg) = noise_config {
            log::info!("Starting Noise handshake for DNS session from {}", client_addr);

            // Create virtual stream from DNS transport
            // We'll use a memory buffer to simulate a bidirectional stream for the handshake
            let mut virtual_stream = DnsVirtualStream::new(
                Arc::clone(&dns_server),
                client_addr,
                tx_id,
                payload.clone(),
            );

            // NOTE: Do NOT use protocol wrapper here!
            // The DNS format parsing (parse_dns_query) already extracts the payload,
            // so the protocol wrapping/unwrapping is handled by the DNS layer itself.
            // Using a protocol wrapper here would cause double-unwrapping and corrupt the data.

            // Perform server-side Noise handshake WITHOUT protocol wrapper
            match NoiseTransport::server_handshake(&mut virtual_stream, noise_cfg, None).await {
                Ok(transport) => {
                    log::info!("Noise handshake completed for {}", client_addr);
                    session.noise_transport = Some(transport);
                    session.handshake_complete = true;

                    // Handshake generates responses - they're already sent by virtual_stream
                    drop(sessions_guard);
                    return Ok(());
                }
                Err(e) => {
                    log::error!("Noise handshake failed for {}: {}", client_addr, e);
                    drop(sessions_guard);

                    // Send error response
                    dns_server
                        .send_response(b"HANDSHAKE_ERROR", client_addr, tx_id)
                        .await?;
                    return Err(e.into());
                }
            }
        } else {
            log::error!("No Noise config provided for DNS tunnel server");
            drop(sessions_guard);
            return Err("Noise encryption required for DNS tunnel".into());
        }
    }

    // At this point, we have an established Noise session
    let noise_transport = session.noise_transport.as_mut().unwrap();

    // Decrypt the payload
    let decrypted = match noise_transport.decrypt(&payload) {
        Ok(data) => {
            log::debug!(
                "Decrypted {} bytes -> {} bytes for {}",
                payload.len(),
                data.len(),
                client_addr
            );
            data
        }
        Err(e) => {
            log::error!("Failed to decrypt DNS payload from {}: {}", client_addr, e);
            drop(sessions_guard);

            // Send error response
            let error_encrypted = vec![0xFF]; // Error marker
            dns_server
                .send_response(&error_encrypted, client_addr, tx_id)
                .await?;
            return Err(e.into());
        }
    };

    // Check if this is the initial target connection request
    if session.target_conn.is_none() {
        // Parse target address (format: "host:port" or "[ipv6]:port")
        let target_str = String::from_utf8_lossy(&decrypted);
        log::info!("DNS tunnel connection request from {}: target={}", client_addr, target_str);

        // Parse target address
        let target_addr = parse_target_address(&target_str)?;

        // Connect to target
        match TcpStream::connect(&target_addr).await {
            Ok(mut stream) => {
                stream.set_nodelay(true)?;
                log::info!(
                    "Connected to target {} for DNS client {}",
                    target_addr,
                    client_addr
                );
                session.target_conn = Some(stream);

                // Send success response
                let success_msg = b"OK";
                let encrypted = noise_transport.encrypt(success_msg)?;
                drop(sessions_guard); // Release lock before async operation

                dns_server
                    .send_response(&encrypted, client_addr, tx_id)
                    .await?;

                log::debug!("Sent OK response to {}", client_addr);
            }
            Err(e) => {
                log::error!(
                    "Failed to connect to target {} for {}: {}",
                    target_addr,
                    client_addr,
                    e
                );

                // Send error response
                let error_msg = format!("CONNECTION_FAILED: {}", e);
                let encrypted = noise_transport.encrypt(error_msg.as_bytes())?;
                drop(sessions_guard);

                dns_server
                    .send_response(&encrypted, client_addr, tx_id)
                    .await?;

                return Err(e.into());
            }
        }
    } else {
        // This is application data - forward to target
        let target_conn = session.target_conn.as_mut().unwrap();

        log::debug!(
            "Forwarding {} bytes from {} to target",
            decrypted.len(),
            client_addr
        );

        // Write data to target
        if let Err(e) = target_conn.write_all(&decrypted).await {
            log::error!("Failed to write to target for {}: {}", client_addr, e);

            // Send error response (encrypt before dropping guard)
            let error_msg = b"TARGET_WRITE_ERROR";
            let encrypted = noise_transport.encrypt(error_msg)?;
            drop(sessions_guard);

            dns_server
                .send_response(&encrypted, client_addr, tx_id)
                .await?;
            return Err(e.into());
        }

        // Read response from target (non-blocking with timeout)
        let mut response_buf = vec![0u8; 8192];
        let response_data = match tokio::time::timeout(
            Duration::from_millis(100),
            target_conn.read(&mut response_buf)
        )
        .await
        {
            Ok(Ok(0)) => {
                log::info!("Target closed connection for {}", client_addr);
                // Connection closed
                session.target_conn = None;
                b"CONNECTION_CLOSED"
            }
            Ok(Ok(n)) => {
                log::debug!("Read {} bytes from target for {}", n, client_addr);
                &response_buf[..n]
            }
            Ok(Err(e)) => {
                log::error!("Error reading from target for {}: {}", client_addr, e);
                session.target_conn = None;
                b"TARGET_READ_ERROR"
            }
            Err(_) => {
                // Timeout - no data available yet
                // Send empty response to acknowledge receipt
                b""
            }
        };

        // Encrypt and send response
        let encrypted = noise_transport.encrypt(response_data)?;
        drop(sessions_guard);

        dns_server
            .send_response(&encrypted, client_addr, tx_id)
            .await?;

        log::debug!(
            "Sent {} bytes response to {} (encrypted: {} bytes)",
            response_data.len(),
            client_addr,
            encrypted.len()
        );
    }

    Ok(())
}

/// Parse target address from string (handles IPv4, IPv6, and hostnames)
fn parse_target_address(addr_str: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Check for IPv6 format: [ipv6]:port
    if addr_str.starts_with('[') {
        if let Some(end_bracket) = addr_str.find(']') {
            if addr_str.len() > end_bracket + 1 && &addr_str[end_bracket + 1..end_bracket + 2] == ":" {
                // Valid IPv6 format
                return Ok(addr_str.to_string());
            }
        }
        return Err("Invalid IPv6 address format".into());
    }

    // IPv4 or hostname format: host:port
    if addr_str.contains(':') {
        Ok(addr_str.to_string())
    } else {
        Err("Invalid target address format (missing port)".into())
    }
}

/// Virtual stream adapter for Noise handshake over DNS transport
/// This allows us to use NoiseTransport's handshake methods with DNS packets
struct DnsVirtualStream {
    dns_server: Arc<DnsTransportServer>,
    client_addr: SocketAddr,
    tx_id: u16,
    read_buffer: Vec<u8>,
    read_pos: usize,
    pending_writes: Vec<Vec<u8>>,
}

impl DnsVirtualStream {
    fn new(
        dns_server: Arc<DnsTransportServer>,
        client_addr: SocketAddr,
        tx_id: u16,
        initial_data: Vec<u8>,
    ) -> Self {
        Self {
            dns_server,
            client_addr,
            tx_id,
            read_buffer: initial_data,
            read_pos: 0,
            pending_writes: Vec::new(),
        }
    }
}

impl AsyncRead for DnsVirtualStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // Read from buffered data
        if self.read_pos < self.read_buffer.len() {
            let remaining = &self.read_buffer[self.read_pos..];
            let to_copy = std::cmp::min(buf.remaining(), remaining.len());
            buf.put_slice(&remaining[..to_copy]);
            self.read_pos += to_copy;
            Poll::Ready(Ok(()))
        } else {
            // No more data available - for handshake, this means we need to wait for next packet
            // In a real implementation, this would block until the next DNS packet arrives
            Poll::Ready(Ok(())) // Return EOF for now
        }
    }
}

impl AsyncWrite for DnsVirtualStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        // Buffer writes - they'll be sent when flush is called
        self.pending_writes.push(buf.to_vec());
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // Send all pending writes as DNS responses
        if !self.pending_writes.is_empty() {
            let dns_server = Arc::clone(&self.dns_server);
            let client_addr = self.client_addr;
            let tx_id = self.tx_id;
            let writes = std::mem::take(&mut self.pending_writes);

            let waker = cx.waker().clone();
            tokio::spawn(async move {
                for data in writes {
                    if let Err(e) = dns_server.send_response(&data, client_addr, tx_id).await {
                        log::error!("Failed to send DNS handshake response: {}", e);
                    }
                }
                waker.wake();
            });

            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BufMut;

    #[test]
    fn test_detect_socks5() {
        let mut buf = BytesMut::new();
        buf.put_u8(0x05); // SOCKS version
        buf.put_u8(0x01); // Number of methods
        buf.put_u8(0x00); // No auth
        buf.put_u8(0x00); // Padding to meet 4-byte minimum

        let result = detect_proxy_type(&buf, &[ProxyType::Socks5, ProxyType::Http]);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ProxyType::Socks5);
    }

    #[test]
    fn test_detect_http() {
        let mut buf = BytesMut::new();
        buf.put_slice(b"CONNECT example.com:443 HTTP/1.1\r\n");

        let result = detect_proxy_type(&buf, &[ProxyType::Socks5, ProxyType::Http]);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ProxyType::Http);
    }

    #[test]
    fn test_parse_http_connect() {
        let request = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let result = parse_http_connect(request);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "example.com:443");
    }
}
