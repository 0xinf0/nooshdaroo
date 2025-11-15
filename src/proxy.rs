//! Multi-protocol proxy servers (HTTP, SOCKS, Transparent)

use bytes::{Buf, BufMut, BytesMut};
use std::mem;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;

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
}

impl UnifiedProxyListener {
    /// Create new unified proxy listener
    pub fn new(listen_addr: SocketAddr, proxy_types: Vec<ProxyType>) -> Self {
        Self {
            listen_addr,
            proxy_types,
        }
    }

    /// Start listening and accept connections
    pub async fn listen(self) -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(self.listen_addr).await?;
        log::info!("Nooshdaroo unified proxy listening on {}", self.listen_addr);

        loop {
            let (socket, peer_addr) = listener.accept().await?;
            log::debug!("Accepted connection from {}", peer_addr);

            let proxy_types = self.proxy_types.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_connection(socket, peer_addr, proxy_types).await {
                    log::error!("Connection error from {}: {}", peer_addr, e);
                }
            });
        }
    }
}

/// Handle incoming connection with auto-detection
async fn handle_connection(
    socket: TcpStream,
    peer_addr: SocketAddr,
    supported_types: Vec<ProxyType>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Peek at first bytes to detect protocol
    let mut buf = BytesMut::with_capacity(4096);
    socket.readable().await?;

    let n = socket.try_read_buf(&mut buf)?;
    if n == 0 {
        return Ok(());
    }

    // Detect proxy protocol
    let proxy_type = detect_proxy_type(&buf, &supported_types)?;
    log::debug!("Detected {:?} proxy from {}", proxy_type, peer_addr);

    match proxy_type {
        ProxyType::Socks5 => handle_socks5(socket, buf, peer_addr).await,
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

/// Handle SOCKS5 proxy connection
async fn handle_socks5(
    _socket: TcpStream,
    _buf: BytesMut,
    _peer_addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    // TODO: Integrate with existing Proteus SOCKS5 implementation
    log::info!("SOCKS5 handler - integration pending");
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

    #[test]
    fn test_detect_socks5() {
        let mut buf = BytesMut::new();
        buf.put_u8(0x05); // SOCKS version
        buf.put_u8(0x01); // Number of methods
        buf.put_u8(0x00); // No auth

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
