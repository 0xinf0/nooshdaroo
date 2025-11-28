# DNS Tunnel Integration Plan for Nooshdaroo

## Executive Summary

This document outlines the plan to integrate the standalone DNS UDP tunnel into the main Nooshdaroo proxy as a transport option alongside HTTPS, HTTP, and other protocols.

**Current Status:**
- ✅ Standalone DNS tunnel working (dns-socks-server, dns-socks-client)
- ✅ Tested with blocked sites (YouTube)
- ✅ Library code exists (`src/dns_udp_tunnel.rs`)
- ⏳ Integration into main proxy needed

## Integration Approach

There are **two viable approaches** for integration:

### Approach 1: DNS Tunnel as Transport Layer (Recommended)
Integrate DNS tunnel at the transport layer, similar to how TLS wrapping works.

**Architecture:**
```
Client App → SOCKS5 → Nooshdaroo Client → DNS UDP Tunnel → Nooshdaroo Server → Internet
```

**Advantages:**
- ✅ Cleaner separation of concerns
- ✅ Can combine with Noise encryption
- ✅ Reuses existing proxy infrastructure
- ✅ Consistent with Nooshdaroo's protocol-agnostic design

**Implementation:**
- Add DNS tunnel as a transport option in config
- Wrap TCP connections from proxy core in DNS tunnel
- Server unwraps DNS tunnel and forwards to destinations

### Approach 2: DNS Tunnel as Standalone Mode (Current)
Keep DNS tunnel as separate binaries, users choose one or the other.

**Architecture:**
```
Client App → SOCKS5 → DNS SOCKS Client → DNS Server → Internet
              (OR)
Client App → SOCKS5 → Nooshdaroo Client → Nooshdaroo Server → Internet
```

**Advantages:**
- ✅ Already implemented and working
- ✅ No integration complexity
- ✅ Independent testing and deployment

**Disadvantages:**
- ❌ Duplicate SOCKS5 implementation
- ❌ Cannot combine DNS tunnel with Noise encryption
- ❌ Separate binaries to maintain

## Recommended Plan: Hybrid Approach

**Keep both options available:**
1. **Standalone mode** (current) - for quick deployment and testing
2. **Integrated mode** (new) - for production use with full features

This gives users flexibility:
- **Simple use case**: Use standalone DNS tunnel binaries
- **Advanced use case**: Use main Nooshdaroo with `transport = "dns"` option

## Implementation Steps

### Phase 1: Configuration Support ✅ (Low effort)

**Goal**: Add DNS tunnel as a transport option in Nooshdaroo config

**Changes needed:**

1. **Update `src/config.rs`** - Add DNS transport option:
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Https,
    Http,
    Dns,  // NEW
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportConfig {
    #[serde(default = "default_transport")]
    pub transport: Transport,

    // DNS-specific settings
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_port: Option<u16>,  // Default: 53
}
```

2. **Create example config** - `examples/client-dns-transport.toml`:
```toml
[client]
server_address = "nooshdaroo.net:53"
local_address = "127.0.0.1:1080"
transport = "dns"

[transport]
dns_port = 53
```

**Effort**: 1-2 hours
**Risk**: Low
**Benefit**: Clear configuration interface

### Phase 2: Transport Layer Integration 🔨 (Medium effort)

**Goal**: Use DNS tunnel to transport proxy traffic

**Changes needed:**

1. **Update `src/proxy/mod.rs`** - Add DNS transport handling:
```rust
match config.transport {
    Transport::Https => {
        // Existing HTTPS logic
        establish_tls_connection(server_addr).await?
    }
    Transport::Dns => {
        // NEW: DNS tunnel transport
        establish_dns_tunnel(server_addr, session_id).await?
    }
    _ => { /* other transports */ }
}
```

2. **Create `src/proxy/dns_transport.rs`** - DNS tunnel transport layer:
```rust
use crate::dns_udp_tunnel::{DnsUdpTunnelClient, DnsUdpTunnelServer};

pub struct DnsTransport {
    client: DnsUdpTunnelClient,
    server_addr: SocketAddr,
    session_id: u16,
}

impl DnsTransport {
    pub async fn connect(server_addr: SocketAddr) -> Result<Self> {
        // Initialize DNS tunnel client
        let client_bind: SocketAddr = "0.0.0.0:0".parse()?;
        let session_id = rand::random::<u16>();
        let client = DnsUdpTunnelClient::new(server_addr, client_bind, session_id);

        Ok(Self { client, server_addr, session_id })
    }

    pub async fn send(&self, data: &[u8]) -> Result<()> {
        self.client.send_and_receive(data.to_vec()).await?;
        Ok(())
    }

    pub async fn receive(&self) -> Result<Vec<u8>> {
        // Poll for data with PING
        let response = self.client.send_and_receive(b"PING".to_vec()).await?;
        Ok(response)
    }
}
```

3. **Update server** - Handle DNS tunnel on server side:
```rust
// In src/proxy/server.rs or similar
match config.transport {
    Transport::Dns => {
        // Start DNS UDP tunnel server
        let dns_server = DnsUdpTunnelServer::new(listen_addr);
        dns_server.listen(handle_dns_tunnel_session).await?;
    }
    _ => { /* other transports */ }
}
```

**Effort**: 4-6 hours
**Risk**: Medium (need to handle async properly)
**Benefit**: Full integration with Nooshdaroo features

### Phase 3: Fix Bidirectional Flow ⚠️ (Critical)

**Goal**: Fix the current limitation where response data isn't properly returned to client

**Current Issue:**
- Server receives response from destination (775 bytes from example.com)
- Response not properly written back through DNS tunnel to client
- Client's receive loop polls with PING but doesn't handle response data correctly

**Root Cause Analysis:**

Looking at `src/bin/dns_socks_client.rs:168-190`, the receive task:
```rust
let recv_task = tokio::spawn(async move {
    loop {
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
```

**Problem**: This logic assumes all response data comes back in response to PING, but the server returns response data in response to the *original data packet*, not the PING.

**Solution Options:**

**Option A: Queue-based approach** (Recommended)
1. Server queues response data for each session
2. Client polls with PING
3. Server returns queued data when PING received
4. Requires server-side session queue

**Option B: Immediate response**
1. Server returns response data immediately in DNS response to data packet
2. Client waits for response after sending data
3. Simpler but higher latency

**Option C: Bidirectional channel**
1. Use two separate DNS "channels" (different subdomains)
2. One for client→server data
3. One for server→client data
4. More complex but cleaner separation

**Recommended**: **Option A** - Add queue on server side

**Implementation:**

```rust
// Server side: src/bin/dns_socks_server.rs
struct SessionData {
    stream: TcpStream,
    response_queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
}

// In handle_dns_request:
if payload_str == "PING" {
    // Check if there's queued response data
    let mut queue = session.response_queue.lock().await;
    if let Some(data) = queue.pop_front() {
        return Ok(data);
    } else {
        return Ok(b"PONG".to_vec());
    }
} else {
    // Data packet
    stream.write_all(&payload).await?;

    // Try to read response
    let mut buf = vec![0u8; 4096];
    match tokio::time::timeout(
        tokio::time::Duration::from_millis(100),
        stream.read(&mut buf)
    ).await {
        Ok(Ok(n)) if n > 0 => {
            // Queue response data for next PING
            session.response_queue.lock().await.push_back(buf[0..n].to_vec());
            Ok(b"ACK".to_vec())  // Acknowledge receipt
        }
        _ => Ok(b"ACK".to_vec())
    }
}
```

**Effort**: 3-4 hours
**Risk**: Medium
**Benefit**: Critical - makes DNS tunnel fully functional

### Phase 4: Add Encryption Layer 🔒 (Important for stealth)

**Goal**: Encrypt DNS tunnel payloads before encoding in DNS packets

**Why needed:**
- Current DNS tunnel sends hex-encoded data in DNS queries
- Plaintext hex data looks suspicious
- Adding encryption makes it look like random data
- Harder to detect with DPI

**Implementation:**

Use ChaCha20-Poly1305 (same as Noise protocol):

```rust
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::{Aead, NewAead};

pub struct EncryptedDnsTunnel {
    cipher: ChaCha20Poly1305,
    nonce_counter: u64,
}

impl EncryptedDnsTunnel {
    pub fn new(key: &[u8; 32]) -> Self {
        let key = Key::from_slice(key);
        let cipher = ChaCha20Poly1305::new(key);
        Self { cipher, nonce_counter: 0 }
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.get_nonce();
        let ciphertext = self.cipher.encrypt(&nonce, plaintext)
            .map_err(|e| Error::msg("Encryption failed"))?;
        Ok(ciphertext)
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.get_nonce();
        let plaintext = self.cipher.decrypt(&nonce, ciphertext)
            .map_err(|e| Error::msg("Decryption failed"))?;
        Ok(plaintext)
    }

    fn get_nonce(&mut self) -> Nonce {
        let nonce_bytes = self.nonce_counter.to_le_bytes();
        self.nonce_counter += 1;
        // Pad to 12 bytes for ChaCha20Poly1305
        let mut nonce = [0u8; 12];
        nonce[0..8].copy_from_slice(&nonce_bytes);
        Nonce::from(nonce)
    }
}
```

**Key Exchange**: Reuse Nooshdaroo's existing Noise protocol handshake to establish shared key.

**Effort**: 2-3 hours
**Risk**: Low (well-tested crypto)
**Benefit**: Significantly improves stealth

### Phase 5: Testing & Validation ✅

**Test Cases:**

1. **Unit Tests** (already exist):
   - DNS packet encoding/decoding
   - Fragmentation logic
   - Encryption/decryption

2. **Integration Tests** (new):
   ```rust
   #[tokio::test]
   async fn test_dns_transport_http_request() {
       // Start DNS tunnel server
       // Connect DNS tunnel client
       // Send HTTP request through tunnel
       // Verify response received
   }

   #[tokio::test]
   async fn test_dns_transport_large_payload() {
       // Test >4KB payload (requires fragmentation)
   }

   #[tokio::test]
   async fn test_dns_transport_concurrent_sessions() {
       // Test multiple concurrent sessions
   }
   ```

3. **End-to-End Tests**:
   - Test with blocked sites (YouTube, Twitter, etc.)
   - Test from actual censored network
   - Capture tcpdump and verify DNS packets
   - Performance benchmarks (throughput, latency)

4. **Deployment Tests**:
   - Deploy server on nooshdaroo.net:53
   - Test client from various locations
   - Monitor server logs
   - Check for DNS query patterns

**Effort**: 4-5 hours
**Risk**: Low
**Benefit**: Confidence in production readiness

### Phase 6: Documentation 📚

**Documents to Create/Update:**

1. **README.md** - Add DNS tunnel section:
   ```markdown
   ## DNS Tunnel Mode

   For maximum censorship resistance, Nooshdaroo supports tunneling through DNS:

   ### Server Setup
   ```bash
   # Using integrated mode
   ./nooshdaroo --config server-dns.toml server

   # Using standalone mode (simpler)
   ./dns-socks-server 0.0.0.0:53
   ```

   ### Client Setup
   ```bash
   # Using integrated mode
   ./nooshdaroo --config client-dns.toml client

   # Using standalone mode
   ./dns-socks-client nooshdaroo.net:53
   ```

   ### Configuration
   ```toml
   [client]
   transport = "dns"
   dns_port = 53
   ```
   ```

2. **DNS_TUNNEL_GUIDE.md** - Comprehensive guide:
   - How DNS tunneling works
   - When to use DNS vs HTTPS
   - Performance considerations
   - Troubleshooting
   - tcpdump examples

3. **DEPLOYMENT.md** - Production deployment:
   - Server requirements (port 53 requires root)
   - Firewall configuration
   - Monitoring and logs
   - Security hardening

**Effort**: 2-3 hours
**Risk**: Low
**Benefit**: Users can actually deploy it

## Timeline & Effort Estimate

| Phase | Task | Effort | Dependencies |
|-------|------|--------|--------------|
| 1 | Configuration support | 1-2 hrs | None |
| 2 | Transport layer integration | 4-6 hrs | Phase 1 |
| 3 | Fix bidirectional flow | 3-4 hrs | None (can be done in parallel) |
| 4 | Add encryption | 2-3 hrs | Phase 3 |
| 5 | Testing & validation | 4-5 hrs | Phase 2, 3, 4 |
| 6 | Documentation | 2-3 hrs | Phase 5 |
| **Total** | **End-to-end integration** | **16-23 hrs** | |

**Critical Path**: Phase 3 (fix bidirectional flow) must be done before Phase 5 (testing).

## Migration Path

**For existing users:**

### Option 1: Use Standalone Binaries (Immediate)
```bash
# Server
./dns-socks-server 0.0.0.0:53

# Client
./dns-socks-client nooshdaroo.net:53
```

**Pros**: Works today, no changes needed
**Cons**: Limited features, separate binaries

### Option 2: Wait for Integration (Future)
```bash
# Server config: server-dns.toml
[server]
listen_address = "0.0.0.0:53"
transport = "dns"

# Client config: client-dns.toml
[client]
server_address = "nooshdaroo.net:53"
transport = "dns"
```

**Pros**: Full Nooshdaroo features, single binary
**Cons**: Requires waiting for integration

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Bidirectional flow fix fails | Medium | High | Thorough testing, fallback to polling |
| Performance too slow | Low | Medium | Optimize fragment size, reduce polling interval |
| DPI detection | Medium | High | Add encryption layer, randomize timing |
| Port 53 blocked | Low | Medium | Allow custom port, use DoH as fallback |
| Integration breaks existing features | Low | High | Comprehensive testing, feature flags |

## Success Criteria

**Minimum Viable Product (MVP):**
- ✅ DNS tunnel works end-to-end (request + response)
- ✅ Can access blocked sites through DNS tunnel
- ✅ Integrated into main Nooshdaroo binary
- ✅ Configuration documented
- ✅ Tested from censored network

**Full Production:**
- ✅ All of MVP
- ✅ Encryption layer added
- ✅ Performance acceptable (>100 KB/s)
- ✅ Multiple concurrent sessions supported
- ✅ Comprehensive documentation
- ✅ Deployed and battle-tested

## Recommendation

**Start with Phase 3** (Fix bidirectional flow) because:
1. It's the current blocker for standalone mode
2. Can be done independently
3. Immediately makes DNS tunnel usable
4. Provides learnings for integration

**Then proceed with Phase 1 & 2** (Integration) to:
1. Bring DNS tunnel into main binary
2. Enable use with Noise encryption
3. Provide unified user experience

**Timeline:**
- Week 1: Fix bidirectional flow (Phase 3)
- Week 2: Configuration + Integration (Phase 1 & 2)
- Week 3: Encryption + Testing (Phase 4 & 5)
- Week 4: Documentation + Deployment (Phase 6)

---

**Created**: 2025-11-17
**Status**: READY FOR IMPLEMENTATION
**Priority**: HIGH (censorship bypass is core mission)
