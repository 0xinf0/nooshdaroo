# nQUIC DNS Tunnel Usage Guide

nQUIC is a **Noise-based QUIC** implementation optimized for DNS tunneling. It provides:

- **QUIC protocol** with **Noise Protocol Framework** handshake (instead of TLS 1.3)
- **Perfect Forward Secrecy** with independent session keys per connection
- **Connection Migration** support for network path changes
- **DNS tunneling** using base32 encoding for queries and TXT records for responses
- **24-byte header overhead** (vs 59 bytes in dnstt)

## Architecture

```
┌──────────────┐         DNS Queries (base32)         ┌──────────────┐
│              │─────────────────────────────────────▶│              │
│   Client     │                                       │    Server    │
│              │◀─────────────────────────────────────│              │
└──────────────┘      DNS Responses (TXT records)      └──────────────┘
      │                                                        │
      │                                                        │
      ▼                                                        ▼
  NquicEndpoint                                          NquicEndpoint
      │                                                        │
      ├─ NoiseSession (Noise IK handshake)                   ├─ NoiseSession
      ├─ DnsTransport (UDP:53 / TCP:53)                      ├─ DnsTransport
      └─ Quinn QUIC (with Noise crypto)                       └─ Quinn QUIC
```

## API Usage

### 1. Generate Noise Keys

```rust
use nooshdaroo::nquic::*;
use nooshdaroo::noise_transport::{NoiseKeypair, NoisePattern};
use snow::Builder;
use std::sync::Arc;

// Generate keypair using Snow
let builder = Builder::new(NoisePattern::IK.protocol_name().parse().unwrap());
let keypair = builder.generate_keypair().unwrap();

let keys = Arc::new(NoiseKeypair {
    private_key: keypair.private.to_vec(),
    public_key: keypair.public_key.to_vec(),
});
```

### 2. Create Server

```rust
use nooshdaroo::nquic::*;
use nooshdaroo::nquic::crypto::NoiseConfig;

// Create server configuration
let server_config = NoiseConfig::server(Arc::clone(&server_keys));

// Create nQUIC endpoint
let server_endpoint = NquicEndpoint::new(
    server_config,
    "tunnel.example.com".to_string(),  // Base domain for DNS encoding
    true,  // is_server = true
);

// Bind to UDP port 53 (requires root/CAP_NET_BIND_SERVICE)
let server_addr = "0.0.0.0:53".parse().unwrap();
server_endpoint.bind(server_addr).await?;

// Accept connections
loop {
    let mut conn = server_endpoint.accept().await?;

    tokio::spawn(async move {
        // Connection is now established
        loop {
            // Receive data from client
            let data = conn.recv().await?;

            // Process data...

            // Send response
            conn.send(&response_data).await?;
        }
    });
}
```

### 3. Create Client

```rust
use nooshdaroo::nquic::*;
use nooshdaroo::nquic::crypto::NoiseConfig;

// Create client configuration with server's public key
let client_config = NoiseConfig::client(
    Arc::clone(&client_keys),
    server_keys.public_key.clone(),  // Server's static public key (pre-shared)
);

// Create nQUIC endpoint
let client_endpoint = NquicEndpoint::new(
    client_config,
    "tunnel.example.com".to_string(),  // Same base domain as server
    false,  // is_server = false
);

// Bind to any available port
let client_addr = "0.0.0.0:0".parse().unwrap();
client_endpoint.bind(client_addr).await?;

// Set DNS server address
let server_addr = "1.1.1.1:53".parse().unwrap();  // Your server's DNS resolver
client_endpoint.set_dns_server(server_addr).await;

// Connect to server
let mut conn = client_endpoint.connect().await?;

// Send data
conn.send(b"Hello via nQUIC DNS tunnel!").await?;

// Receive response
let response = conn.recv().await?;
```

## Features

### Perfect Forward Secrecy

Each connection uses independent ephemeral keys:

```rust
// Each connection gets its own session keys
let conn1 = client_endpoint.connect().await?;
let conn2 = client_endpoint.connect().await?;

// conn1 and conn2 have completely independent encryption keys
// Compromise of one session does not affect the other
```

### Connection Migration

nQUIC supports seamless network path changes:

```rust
// Connection survives network changes (WiFi→4G, IP address change, etc.)
let conn = client_endpoint.connect().await?;

// ... network change occurs ...

// Connection remains valid
conn.send(b"Still connected after network change").await?;
```

### Key Information

- **Remote static key**: Access the server's static public key after handshake

```rust
let remote_key = conn.remote_static_key().await;
println!("Connected to server with key: {:?}", remote_key);
```

## DNS Transport Details

### Encoding

**Upstream (Client → Server)**:
- Encoded in DNS query labels using **base32**
- Split across multiple labels if needed (max 63 bytes per label)
- Max payload: ~100 bytes per query

**Downstream (Server → Client)**:
- Encoded in **TXT record** data
- Max payload: ~180 bytes per response

### Packet Sizes

- **UDP queries**: Max 512 bytes (DNS standard)
- **TCP queries**: Unlimited (with 2-byte length prefix)
- **nQUIC header overhead**: 24 bytes (vs dnstt's 59 bytes)

### Dual Transport

nQUIC automatically selects:
- **UDP** for small packets (≤ max_upstream_size)
- **TCP** for large packets (> max_upstream_size)

## Testing

Run nQUIC tests:

```bash
cargo test --lib nquic -- --test-threads=1
```

Tests cover:
1. Perfect Forward Secrecy
2. Connection Migration
3. Multipath Connections
4. DNS Transport Migration
5. Noise Key Ratcheting
6. Concurrent Connections

## Performance Characteristics

| Feature | nQUIC | dnstt |
|---------|-------|-------|
| Header Overhead | 24 bytes | 59 bytes |
| Protocol | QUIC + Noise | Custom |
| Handshake | 1-RTT (IK) | 2-RTT |
| Forward Secrecy | ✓ | ✗ |
| Connection Migration | ✓ | ✗ |
| Multipath | ✓ | ✗ |

## Security

- **Noise IK Pattern**: Identity-known handshake where client knows server's static public key
- **ChaCha20-Poly1305**: AEAD encryption for all data
- **Perfect Forward Secrecy**: Each connection uses ephemeral keys
- **Automatic key ratcheting**: Nonce advancement prevents replay attacks

## Limitations

- Requires Noise keypairs (pre-shared server public key on client)
- UDP port 53 requires root privileges on server
- DNS queries have ~100-byte payload limit (use TCP for larger packets)
- Not compatible with standard QUIC clients (uses Noise instead of TLS)

## Integration with Nooshdaroo

nQUIC is available as a library module:

```rust
use nooshdaroo::nquic::{NquicEndpoint, NquicConnection};
use nooshdaroo::nquic::crypto::NoiseConfig;
use nooshdaroo::nquic::dns::{DnsCodec, DnsTransport};
```

The implementation is in `src/nquic/` and consists of:
- `crypto/`: Noise Protocol + Quinn QUIC crypto integration
- `dns/`: DNS codec and transport (base32 encoding, TXT records)
- `endpoint.rs`: High-level nQUIC API

## Future Enhancements

- [ ] SOCKS5 proxy integration
- [ ] Configuration file support
- [ ] Automatic Noise key generation/management
- [ ] DNS-over-HTTPS (DoH) transport
- [ ] Multipath QUIC path management
- [ ] Performance benchmarking vs KCP implementation
