//! Multi-protocol proxy servers (HTTP, SOCKS, Transparent)

use bytes::BytesMut;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use crate::noise_transport::NoiseTransport;

#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;

#[cfg(target_os = "linux")]
use std::mem;

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
}

impl UnifiedProxyListener {
    /// Create new unified proxy listener
    pub fn new(listen_addr: SocketAddr, proxy_types: Vec<ProxyType>, protocol_id: crate::ProtocolId) -> Self {
        Self {
            listen_addr,
            proxy_types,
            server_addr: None,
            noise_config: None,
            protocol_id,
            controller: None,
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

    /// Start listening and accept connections
    pub async fn listen(self) -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(self.listen_addr).await?;
        log::info!("Nooshdaroo unified proxy listening on {}", self.listen_addr);

        loop {
            let (socket, peer_addr) = listener.accept().await?;
            log::debug!("Accepted connection from {}", peer_addr);

            let proxy_types = self.proxy_types.clone();
            let server_addr = self.server_addr;
            let noise_config = self.noise_config.clone();
            let protocol_id = self.protocol_id.clone();

            let controller_clone = self.controller.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_connection(socket, peer_addr, proxy_types, server_addr, noise_config, protocol_id, controller_clone).await {
                    log::error!("Connection error from {}: {}", peer_addr, e);
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
) -> Result<(), Box<dyn std::error::Error>> {
    // Peek at first bytes to detect protocol
    let mut buf = BytesMut::with_capacity(4096);

    // Read until we have at least 4 bytes for protocol detection
    loop {
        let n = socket.read_buf(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }

        // Need at least 4 bytes to detect protocol
        if buf.len() >= 4 {
            break;
        }
    }

    // Detect proxy protocol
    let proxy_type = detect_proxy_type(&buf, &supported_types)?;
    log::debug!("Detected {:?} proxy from {}", proxy_type, peer_addr);

    match proxy_type {
        ProxyType::Socks5 => handle_socks5(socket, buf, peer_addr, server_addr, noise_config, protocol_id, controller).await,
        ProxyType::Http => handle_http(socket, buf, peer_addr).await,
        ProxyType::Transparent => handle_transparent(socket, buf, peer_addr).await,
    }
}

/// Detect proxy type from initial bytes
fn detect_proxy_type(
    buf: &BytesMut,
    supported: &[ProxyType],
) -> Result<ProxyType, Box<dyn std::error::Error>> {
    if buf.len() < 4 {
        return Err("Not enough data to detect protocol".into());
    }

    // SOCKS5: First byte is 0x05 (version)
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

                // Connect to server
                let mut server_stream = match TcpStream::connect(server_addr).await {
                    Ok(stream) => {
                        log::debug!("Connected to server {}", server_addr);
                        stream
                    }
                    Err(e) => {
                        log::error!("Failed to connect to server {}: {}", server_addr, e);
                        send_reply(&mut socket, ReplyCode::GeneralFailure, &target).await?;
                        return Err(e.into());
                    }
                };

                // Create protocol wrapper for handshake wrapping
                let mut protocol_wrapper = ProtocolWrapper::new(protocol_id.clone(), None);
                log::debug!("Using protocol: {}", protocol_id.as_str());

                // Perform Noise handshake with protocol wrapping
                let mut noise_transport = match NoiseTransport::client_handshake(&mut server_stream, &noise_config, Some(&mut protocol_wrapper)).await {
                    Ok(transport) => {
                        log::debug!("Noise handshake completed with server using {}", protocol_id.as_str());
                        transport
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
                match noise_transport.write(&mut server_stream, target_info.as_bytes()).await {
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
                let response = match noise_transport.read(&mut server_stream).await {
                    Ok(data) => data,
                    Err(e) => {
                        log::error!("Failed to receive server response: {}", e);
                        send_reply(&mut socket, ReplyCode::GeneralFailure, &target).await?;
                        return Err(e.into());
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

                // Create protocol wrapper using configured protocol
                let wrapper = crate::ProtocolWrapper::new(protocol_id.clone(), None);
                log::debug!("Created {} protocol wrapper for traffic obfuscation", protocol_id.as_str());

                // Relay data bidirectionally through encrypted tunnel
                log::debug!("Starting encrypted relay for {}:{}", target.host, target.port);
                if let Err(e) = relay_through_noise_tunnel(socket, server_stream, noise_transport, wrapper, controller).await {
                    log::debug!("Tunnel relay ended for {}:{}: {}", target.host, target.port, e);
                } else {
                    log::debug!("Tunnel relay completed successfully for {}:{}", target.host, target.port);
                }
            } else {
                // DIRECT MODE: Connect directly to target (local mode)
                log::debug!("Direct connection mode (no server configured)");

                let mut target_stream = match connect_target(&target).await {
                    Ok(stream) => {
                        log::info!("Connected to target {}:{}", target.host, target.port);
                        send_reply(&mut socket, ReplyCode::Succeeded, &target).await?;
                        stream
                    }
                    Err(e) => {
                        log::error!("Failed to connect to {}:{}: {}", target.host, target.port, e);
                        let reply = match e.kind() {
                            std::io::ErrorKind::ConnectionRefused => ReplyCode::ConnectionRefused,
                            std::io::ErrorKind::NotFound | std::io::ErrorKind::TimedOut => ReplyCode::HostUnreachable,
                            _ => ReplyCode::GeneralFailure,
                        };
                        send_reply(&mut socket, reply, &target).await?;
                        return Err(e.into());
                    }
                };

                // Bidirectionally forward traffic between client and target
                log::debug!("Starting bidirectional relay for {}:{}", target.host, target.port);
                if let Err(e) = copy_bidirectional(socket, &mut target_stream).await {
                    log::debug!("Relay ended for {}:{}: {}", target.host, target.port, e);
                } else {
                    log::debug!("Relay completed successfully for {}:{}", target.host, target.port);
                }
            }
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
async fn relay_through_noise_tunnel(
    mut client: impl AsyncReadExt + AsyncWriteExt + Unpin,
    mut server: TcpStream,
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
                        wrapper = crate::ProtocolWrapper::new(new_protocol, None);
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
