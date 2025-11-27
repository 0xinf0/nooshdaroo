# Dual-Transport DNS Tunnel Design

## Architecture Overview

This design implements a DNS tunnel server that listens on **both UDP:53 and TCP:53** with full Noise Protocol encryption and PSF (Protocol Signature Format) wrapping.

```
┌─────────────────────────────────────────────────────────────────┐
│                    Client Application (SOCKS5)                  │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Nooshdaroo Client                           │
│  ┌──────────────────────┐        ┌──────────────────────────┐  │
│  │   TCP Connection     │   OR   │   UDP Connection         │  │
│  │   (Stateful)         │        │   (Stateless Sessions)   │  │
│  └──────────┬───────────┘        └──────────┬───────────────┘  │
└─────────────┼──────────────────────────────┼───────────────────┘
              │                              │
              │ [1] App Data                │ [1] App Data
              ▼                              ▼
      ┌──────────────┐              ┌──────────────┐
      │ Noise Encrypt│              │ Noise Encrypt│
      └──────┬───────┘              └──────┬───────┘
             │                              │
             │ [2] Encrypted                │ [2] Encrypted
             ▼                              ▼
      ┌──────────────┐              ┌──────────────┐
      │  PSF Wrapper │              │  PSF Wrapper │
      │  (TLS/DNS)   │              │  (DNS)       │
      └──────┬───────┘              └──────┬───────┘
             │                              │
             │ [3] Protocol Frame           │ [3] DNS Packet
             ▼                              ▼
      ┌──────────────┐              ┌──────────────┐
      │   TCP:53     │              │   UDP:53     │
      └──────┬───────┘              └──────┬───────┘
             │                              │
             └──────────────┬───────────────┘
                            ▼
              ┌──────────────────────────┐
              │  Dual Transport Server   │
              │  (Port 53 - Both Proto)  │
              └──────────────────────────┘
```

## Key Technical Challenges & Solutions

### 1. **Port 53 Binding for Both Protocols**

**Challenge**: Bind both UDP socket and TCP listener to the same port 53.

**Solution**:
- On Linux/macOS, different socket types (SOCK_DGRAM vs SOCK_STREAM) can bind to the same port
- Use `SO_REUSEADDR` and `SO_REUSEPORT` socket options
- Bind UDP socket first, then TCP listener

```rust
// UDP socket
let udp_socket = UdpSocket::bind("0.0.0.0:53").await?;
socket2::SockRef::from(&udp_socket).set_reuse_address(true)?;

// TCP listener (same port - different socket type)
let tcp_listener = TcpListener::bind("0.0.0.0:53").await?;
```

### 2. **Noise Handshake over UDP (Stateless)**

**Challenge**: Noise Protocol is designed for stream-based transports (TCP). UDP requires session tracking.

**Solution**: Implement session-based Noise handshake for UDP:

```
Client                                Server
  │                                     │
  │  [1] DNS Query (ClientHello)       │
  │  ─────────────────────────────────▶│
  │     SessionID: 0x1234               │  ← Create session
  │     Noise Msg 1 (→e)                │     Store handshake state
  │                                     │
  │  [2] DNS Response (ServerHello)    │
  │  ◀─────────────────────────────────│
  │     SessionID: 0x1234               │
  │     Noise Msg 2 (←e, ee, s, es)    │
  │                                     │
  │  [3] All future packets             │
  │  ──────────────────────────────────▶
  │     SessionID: 0x1234               │
  │     Encrypted data                  │
```

**Session Management**:
- Map: `SessionID -> NoiseTransportState`
- Timeout: 60 seconds of inactivity
- Cleanup: Background task removes expired sessions

### 3. **PSF Framing over UDP**

**Challenge**: PSF assumes stream-based transport with length prefixes. UDP is datagram-based.

**Solution**: Adapt PSF wrapping for UDP:

**For TCP (current behavior)**:
```
[2-byte length prefix][PSF-wrapped Noise data]
```

**For UDP (new behavior)**:
```
[PSF-wrapped Noise data]  ← No length prefix (packet boundary is datagram)
```

**DNS Packet Structure**:
```
DNS Query:
┌──────────────────────────────────────────┐
│ DNS Header (12 bytes)                    │
├──────────────────────────────────────────┤
│ QNAME: <hex-encoded-payload>.tunnel.com  │
│   Format: session_id(4) + encrypted(N)   │
├──────────────────────────────────────────┤
│ QTYPE: A (0x0001)                        │
│ QCLASS: IN (0x0001)                      │
└──────────────────────────────────────────┘

DNS Response:
┌──────────────────────────────────────────┐
│ DNS Header (12 bytes)                    │
├──────────────────────────────────────────┤
│ Question (echo)                          │
├──────────────────────────────────────────┤
│ Answer (TXT record)                      │
│   RDATA: hex-encoded response payload    │
└──────────────────────────────────────────┘
```

### 4. **Concurrent UDP/TCP Handling**

**Solution**: Use tokio tasks for concurrent processing:

```rust
// Main server loop
tokio::spawn(async move {
    udp_listener(socket, sessions).await
});

tokio::spawn(async move {
    tcp_listener(listener, sessions).await
});

// Shared state
Arc<RwLock<HashMap<SessionId, UdpSession>>>
```

## Implementation Components

### File: `src/dns_dual_transport.rs`

```rust
pub struct DnsDualTransportServer {
    bind_addr: SocketAddr,
    noise_config: NoiseConfig,
    protocol_id: ProtocolId,

    // Shared state between UDP and TCP handlers
    udp_sessions: Arc<RwLock<HashMap<SessionId, UdpSession>>>,
}

pub struct UdpSession {
    session_id: SessionId,
    client_addr: SocketAddr,

    // Noise handshake state (during handshake)
    handshake_state: Option<HandshakeState>,

    // Noise transport (after handshake complete)
    transport: Option<TransportState>,

    // PSF wrapper for this session
    protocol_wrapper: ProtocolWrapper,

    // Activity tracking
    last_activity: Instant,
}

impl DnsDualTransportServer {
    pub async fn listen(self) -> Result<()> {
        // Bind UDP socket
        let udp_socket = self.bind_udp().await?;
        let udp_sessions = self.udp_sessions.clone();

        // Bind TCP listener
        let tcp_listener = self.bind_tcp().await?;

        // Spawn UDP handler
        tokio::spawn(async move {
            handle_udp_loop(udp_socket, udp_sessions, ...).await
        });

        // Spawn TCP handler
        tokio::spawn(async move {
            handle_tcp_loop(tcp_listener, ...).await
        });

        // Spawn session cleanup
        tokio::spawn(async move {
            cleanup_sessions(self.udp_sessions).await
        });

        // Keep alive
        std::future::pending().await
    }
}
```

### UDP Handshake Flow

```rust
async fn handle_udp_packet(
    socket: &UdpSocket,
    packet: &[u8],
    client_addr: SocketAddr,
    sessions: Arc<RwLock<HashMap<SessionId, UdpSession>>>,
) -> Result<()> {
    // [1] Parse DNS query
    let (transaction_id, dns_payload) = parse_dns_query(packet)?;

    // [2] Decode session header
    let session_id = u16::from_be_bytes([dns_payload[0], dns_payload[1]]);
    let encrypted_data = &dns_payload[2..];

    // [3] Get or create session
    let mut sessions_guard = sessions.write().await;
    let session = sessions_guard.entry(session_id)
        .or_insert_with(|| UdpSession::new(session_id, client_addr));

    // [4] Process based on session state
    if let Some(ref mut hs) = session.handshake_state {
        // Still in handshake - process handshake message
        let mut buf = vec![0u8; 65535];
        hs.read_message(encrypted_data, &mut buf)?;

        if hs.is_handshake_finished() {
            // Handshake complete - transition to transport mode
            session.transport = Some(hs.into_transport_mode()?);
            session.handshake_state = None;
        }

        // Send handshake response
        let response_len = hs.write_message(&[], &mut buf)?;
        let dns_response = build_dns_response(&buf[..response_len], transaction_id);
        socket.send_to(&dns_response, client_addr).await?;

    } else if let Some(ref mut transport) = session.transport {
        // Handshake complete - decrypt and process data

        // [5] Unwrap PSF
        let noise_encrypted = session.protocol_wrapper.unwrap(encrypted_data)?;

        // [6] Decrypt with Noise
        let mut plaintext = vec![0u8; 65535];
        let len = transport.read_message(&noise_encrypted, &mut plaintext)?;
        let app_data = &plaintext[..len];

        // [7] Process application data (forward to target)
        let response_data = process_socks_data(app_data).await?;

        // [8] Encrypt response
        let encrypted = transport.write_message(&response_data, &mut plaintext)?;

        // [9] Wrap with PSF
        let wrapped = session.protocol_wrapper.wrap(&encrypted[..encrypted])?;

        // [10] Send DNS response
        let dns_response = build_dns_response(&wrapped, transaction_id);
        socket.send_to(&dns_response, client_addr).await?;
    }

    Ok(())
}
```

### TCP Handler (Existing Pattern)

```rust
async fn handle_tcp_connection(
    mut stream: TcpStream,
    noise_config: NoiseConfig,
    protocol_id: ProtocolId,
) -> Result<()> {
    // Create PSF wrapper
    let mut wrapper = ProtocolWrapper::new(
        protocol_id.clone(),
        WrapperRole::Server,
        None
    );

    // Perform Noise handshake (wrapped in PSF)
    let mut noise = NoiseTransport::server_handshake(
        &mut stream,
        &noise_config,
        Some(&mut wrapper)
    ).await?;

    // Relay loop (existing code)
    loop {
        // Read from client
        let data = noise.read(&mut stream).await?;

        // Process...
        let response = process_socks_data(&data).await?;

        // Write response
        noise.write(&mut stream, &response).await?;
    }
}
```

## Configuration Changes

### Add transport mode selection:

```toml
[server]
bind_addr = "0.0.0.0:53"
transport_mode = "dual"  # Options: "tcp", "udp", "dual"

[transport]
pattern = "nk"
local_private_key = "base64..."
```

### Transport Modes:

1. **TCP Only** (`transport_mode = "tcp"`):
   - Listen only on TCP:53
   - Stream-based Noise handshake
   - PSF wrapping with length prefixes

2. **UDP Only** (`transport_mode = "udp"`):
   - Listen only on UDP:53
   - Session-based Noise handshake
   - PSF wrapping without length prefixes
   - DNS packet framing

3. **Dual** (`transport_mode = "dual"`):
   - Listen on both TCP:53 and UDP:53
   - Client can choose transport
   - Shared Noise keys
   - Different session management per transport

## Protocol Wrapper Adaptation

### Modify `ProtocolWrapper::wrap()`:

```rust
pub enum WrapMode {
    Stream,    // TCP: with length prefix
    Datagram,  // UDP: no length prefix
}

impl ProtocolWrapper {
    pub fn wrap_with_mode(&self, data: &[u8], mode: WrapMode) -> Result<Vec<u8>> {
        let wrapped = match self.protocol_id.as_str() {
            "dns" | "dns-google" => self.wrap_dns(data)?,
            "https" | "tls" => self.wrap_tls(data)?,
            _ => data.to_vec(),
        };

        match mode {
            WrapMode::Stream => {
                // Add 2-byte length prefix for TCP
                let mut framed = Vec::with_capacity(2 + wrapped.len());
                framed.extend_from_slice(&(wrapped.len() as u16).to_be_bytes());
                framed.extend_from_slice(&wrapped);
                Ok(framed)
            }
            WrapMode::Datagram => {
                // No length prefix for UDP (packet boundary = datagram)
                Ok(wrapped)
            }
        }
    }
}
```

## Session Management

### UDP Session Lifecycle:

```rust
struct SessionManager {
    sessions: Arc<RwLock<HashMap<SessionId, UdpSession>>>,
    timeout: Duration,
}

impl SessionManager {
    async fn cleanup_loop(&self) {
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;

            let mut sessions = self.sessions.write().await;
            let now = Instant::now();

            sessions.retain(|id, session| {
                let elapsed = now.duration_since(session.last_activity);
                if elapsed > self.timeout {
                    log::info!("Removing expired UDP session: {:04x}", id);
                    false
                } else {
                    true
                }
            });
        }
    }
}
```

## Performance Considerations

### UDP Optimizations:

1. **Avoid lock contention**: Use per-session locks instead of global lock
2. **Pre-allocate buffers**: Reuse buffers for DNS parsing/building
3. **Zero-copy where possible**: Use `bytes::Bytes` for shared references
4. **Batch operations**: Process multiple packets before lock release

### TCP Optimizations:

1. **TCP_NODELAY**: Already enabled for low latency
2. **Connection pooling**: Reuse TCP connections for multiple SOCKS requests
3. **Async I/O**: Leverage tokio's efficient I/O

## Testing Strategy

### Unit Tests:

1. **Noise handshake over UDP**: Verify session creation and state transitions
2. **PSF wrapping modes**: Test stream vs datagram wrapping
3. **Session timeout**: Verify cleanup of expired sessions
4. **DNS packet parsing**: Test with various payload sizes

### Integration Tests:

1. **TCP-only mode**: Existing functionality regression test
2. **UDP-only mode**: Full handshake and data transfer
3. **Dual mode**: Concurrent TCP and UDP connections
4. **Protocol switching**: Client switches between TCP and UDP mid-session

### Load Tests:

1. **Concurrent UDP sessions**: 1000+ simultaneous sessions
2. **Packet loss simulation**: Verify retransmission handling
3. **Mixed traffic**: 50% TCP, 50% UDP on same port

## Migration Path

### Phase 1: Core Infrastructure
- Implement `UdpSession` and session management
- Add UDP-specific Noise handshake logic
- Modify `ProtocolWrapper` for datagram mode

### Phase 2: UDP Server
- Implement `handle_udp_loop()`
- Add DNS packet framing
- Test UDP-only mode

### Phase 3: Dual Transport
- Implement `bind_both()` for port 53
- Add transport mode configuration
- Concurrent UDP/TCP handling

### Phase 4: Client Support
- Add UDP transport to client
- Implement automatic fallback (TCP → UDP)
- Add latency-based transport selection

## Security Considerations

1. **Replay Attack Prevention**:
   - Noise Protocol's built-in replay protection via nonce counter
   - Session IDs should be cryptographically random

2. **DPI Evasion**:
   - DNS packets must be valid per RFC 1035
   - Timing patterns should match real DNS queries
   - Packet sizes should be randomized within DNS constraints

3. **Active Probing Defense**:
   - Invalid sessions return valid DNS NXDOMAIN
   - Rate limiting per client IP
   - Honeypot responses for probes

4. **Session Hijacking**:
   - Noise Protocol's authentication prevents session hijacking
   - Session IDs bound to client IP address (optional)

## File Structure

```
src/
  dns_dual_transport.rs      ← New: Dual transport server
  dns_session_manager.rs     ← New: UDP session management
  noise_transport.rs         ← Modify: Add datagram mode
  protocol_wrapper.rs        ← Modify: Add WrapMode
  dns_tunnel.rs              ← Existing: DNS packet encoding
  proxy.rs                   ← Modify: Add dual transport option
```

## Next Steps

1. Implement `src/dns_dual_transport.rs` with dual server
2. Add `WrapMode` to `ProtocolWrapper`
3. Implement UDP session manager
4. Add configuration options
5. Write comprehensive tests
6. Add client-side UDP transport support
