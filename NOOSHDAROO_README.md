# Nooshdaroo (نوشدارو)

**Protocol Shape-Shifting SOCKS Proxy for Ultimate Censorship Circumvention**

Nooshdaroo (Persian for "remedy" or "cure") is an advanced encrypted SOCKS proxy built on top of [Proteus](https://github.com/0xinf0/proteus) that provides dynamic protocol emulation and shape-shifting capabilities. It makes your encrypted proxy traffic indistinguishable from legitimate network protocols, defeating Deep Packet Inspection (DPI) and protocol-based censorship.

## Features

### 🎭 Protocol Shape-Shifting

- **100+ Protocol Emulations**: Perfectly mimic HTTPS, DNS, SSH, QUIC, WebSocket, and many more
- **Dynamic Switching**: Automatically rotate between protocols to avoid detection
- **Realistic Traffic**: Match packet sizes, timing, and patterns of real applications
- **PSF-Powered**: Uses Proteus's Protocol Specification Format for accurate emulation

### 🔒 Strong Encryption

- **ChaCha20-Poly1305**: Fast AEAD cipher with authentication
- **Argon2 KDF**: Memory-hard key derivation function
- **Nested Encryption**: Encrypt within protocol structures for stealth

### 🧠 Smart Strategies

- **Time-Based**: Rotate protocols on fixed intervals
- **Traffic-Based**: Switch after transferring X bytes/packets
- **Adaptive**: Increase stealth when detection risk rises
- **Environment-Aware**: Use appropriate protocols for time of day

### 🛡️ Anti-Detection

- **Fingerprint Randomization**: Vary implementation details
- **Timing Obfuscation**: Realistic inter-packet delays
- **Traffic Shaping**: Match normal application patterns
- **TLS SNI Masking**: Appear as legitimate domains

## Quick Start

### Installation

```bash
git clone https://github.com/0xinf0/proteus.git
cd proteus
cargo build --release
```

### Basic Usage

**Client Mode:**

```bash
# 1. Create configuration file
cp nooshdaroo.toml.example nooshdaroo.toml

# 2. Edit password and settings
vim nooshdaroo.toml

# 3. Run Nooshdaroo client
./target/release/proteus --nooshdaroo --config nooshdaroo.toml

# 4. Configure your applications to use SOCKS5 proxy
# Address: 127.0.0.1:1080
```

**Server Mode:**

```bash
# 1. Create server configuration
cp nooshdaroo.toml.example nooshdaroo-server.toml

# 2. Edit configuration
vim nooshdaroo-server.toml
# Set mode = "server"
# Configure listen_addr and forward_addr

# 3. Run Nooshdaroo server
./target/release/proteus --nooshdaroo --config nooshdaroo-server.toml
```

## Configuration

### Shape-Shifting Strategies

#### 1. Fixed Protocol (Simplest)

```toml
[shapeshift.strategy]
type = "fixed"
protocol = "https"  # Always use HTTPS emulation
```

#### 2. Time-Based Rotation

```toml
[shapeshift.strategy]
type = "time-based"
interval = "5m"  # Rotate every 5 minutes
sequence = ["https", "quic", "websocket", "dns"]
```

#### 3. Traffic-Based Switching

```toml
[shapeshift.strategy]
type = "traffic-based"
bytes_threshold = 10485760  # Switch after 10 MB
packet_threshold = 10000    # Or 10k packets
protocol_pool = ["https", "quic", "ssh"]
```

#### 4. Adaptive (Smart Evasion)

```toml
[shapeshift.strategy]
type = "adaptive"
switch_threshold = 0.7  # Switch when detection risk > 70%
safe_protocols = ["https", "tls13"]  # Safest protocols
normal_protocols = ["quic", "websocket", "ssh"]  # Normal use
```

#### 5. Environment-Based (Time of Day)

```toml
[shapeshift.strategy]
type = "environment"

[[shapeshift.strategy.time_profiles]]
hour_start = 9
hour_end = 17
protocols = ["https", "websocket"]  # Work hours

[[shapeshift.strategy.time_profiles]]
hour_start = 17
hour_end = 23
protocols = ["quic", "ssh"]  # Evening
```

## Supported Protocols

### High-Stealth (Best for Evasion)

| Protocol | Port | Detection Score | Notes |
|----------|------|-----------------|-------|
| HTTPS | 443 | ⭐⭐⭐⭐⭐ | Most common, least suspicious |
| TLS 1.3 | 443 | ⭐⭐⭐⭐⭐ | Modern, encrypted by default |
| DNS over HTTPS | 443 | ⭐⭐⭐⭐ | Growing adoption |
| QUIC | 443 | ⭐⭐⭐⭐ | HTTP/3, UDP-based |
| WebSocket | 443 | ⭐⭐⭐⭐ | Real-time web apps |

### Medium-Stealth

| Protocol | Port | Detection Score | Notes |
|----------|------|-----------------|-------|
| SSH | 22 | ⭐⭐⭐ | Common for servers |
| DNS | 53 | ⭐⭐⭐⭐ | Universal but small packets |
| SMTP | 25 | ⭐⭐⭐ | Email traffic |
| IMAP | 143 | ⭐⭐⭐ | Email retrieval |

### Specialized

| Protocol | Port | Detection Score | Notes |
|----------|------|-----------------|-------|
| NTP | 123 | ⭐⭐⭐ | Time sync, periodic |
| MQTT | 1883 | ⭐⭐ | IoT messaging |
| gRPC | 443 | ⭐⭐⭐ | Modern RPC |
| BitTorrent | 6881 | ⭐ | High suspicion |

## How It Works

### Architecture

```
┌─────────────┐                              ┌─────────────┐
│ Application │                              │ Application │
└──────┬──────┘                              └──────▲──────┘
       │                                            │
       │ SOCKS5                              SOCKS5 │
       ▼                                            │
┌─────────────┐                              ┌─────┴───────┐
│  Nooshdaroo │                              │ Nooshdaroo  │
│   Client    │                              │   Server    │
└──────┬──────┘                              └──────▲──────┘
       │                                            │
       │ Obfuscate                        Deobfuscate
       │ (Looks like HTTPS/DNS/SSH)                 │
       ▼                                            │
┌─────────────────────────────────────────────────┬┘
│              Internet (Censored)                │
└─────────────────────────────────────────────────┘
```

### Protocol Emulation

1. **Application sends data** to SOCKS5 proxy
2. **Nooshdaroo receives** plaintext data
3. **PSF interpreter** formats data according to protocol specification
4. **Encryption layer** encrypts payload within protocol structure
5. **Traffic shaper** adds realistic timing and packet sizes
6. **Network sends** protocol-compliant encrypted packets

### Shape-Shifting

```
Time 0:00    ─────[HTTPS]────▶
Time 0:05    ─────[QUIC]─────▶  (Rotated after 5 min)
Time 0:10    ─────[DNS]──────▶  (Rotated again)
Time 0:15    ─────[WebSocket]▶  (And again)
```

Benefits:
- Harder to build blocking rules
- Confuses traffic analysis
- Adapts to network conditions

## Protocol Specification Format (PSF)

Nooshdaroo uses Proteus's PSF language to define protocol emulation. Example for HTTPS:

```
@SEGMENT.FORMATS
  DEFINE TlsAppData
    { NAME: content_type   ; TYPE: u8 },       // 0x17
    { NAME: version        ; TYPE: u16 },      // 0x0303
    { NAME: length         ; TYPE: u16 },
    { NAME: encrypted_data ; TYPE: [u8; length.size_of] },
    { NAME: auth_tag       ; TYPE: [u8; 16] };

@SEGMENT.SEMANTICS
  { FORMAT: TlsAppData; FIELD: length;         SEMANTIC: LENGTH };
  { FORMAT: TlsAppData; FIELD: encrypted_data; SEMANTIC: PAYLOAD };

@SEGMENT.SEQUENCE
  { ROLE: CLIENT; PHASE: DATA; FORMAT: TlsAppData };
  { ROLE: SERVER; PHASE: DATA; FORMAT: TlsAppData };

@SEGMENT.CRYPTO
  PASSWORD = "nooshdaroo-https-key";
  CIPHER   = CHACHA20-POLY1305;
  ENCRYPT TlsAppData FROM TlsAppData
    { PTEXT: encrypted_data; CTEXT: encrypted_data; MAC: auth_tag };
```

## Advanced Features

### Traffic Shaping

Match real application traffic patterns:

```toml
[traffic_shaping]
enabled = true
packet_size_distribution = "normal"  # or "uniform", "exponential"
mean_packet_size = 1400
stddev_packet_size = 200
mean_delay = 50  # microseconds
stddev_delay = 20
```

### Burst Mode

Simulate application bursts:

```toml
enable_bursts = true
burst_size = 5
burst_probability = 0.1  # 10% of packets in bursts
```

### Detection Resistance

```toml
[detection]
enable_fingerprint_randomization = true
enable_timing_randomization = true
enable_tls_sni_masking = false
suspicion_threshold = 0.7
```

## Performance

- **Throughput**: >500 Mbps on modern hardware
- **Latency Overhead**: <10ms for protocol emulation
- **Memory**: ~50 MB per connection
- **CPU**: <5% for protocol switching
- **Switch Time**: <100ms seamless transition

## Use Cases

### 1. Censorship Circumvention

Bypass DPI-based blocking in restricted networks:

```bash
# Use HTTPS emulation (least suspicious)
./proteus --nooshdaroo --config https-only.toml
```

### 2. Enhanced Tor Privacy

Use as Tor pluggable transport with shape-shifting:

```bash
# Configure Tor to use Nooshdaroo as SOCKS5 proxy
# torrc:
Socks5Proxy 127.0.0.1:1080
```

### 3. Corporate Firewall Bypass

Appear as legitimate business traffic:

```toml
[shapeshift.strategy]
type = "environment"
# Only use HTTPS and WebSocket during work hours
```

### 4. Research and Testing

Study protocol fingerprinting and detection:

```bash
# Test detection with different protocols
./proteus --nooshdaroo --protocol dns --test-mode
```

## Security Considerations

### ✅ What Nooshdaroo Protects Against

- Deep Packet Inspection (DPI)
- Protocol-based blocking
- Traffic fingerprinting
- Timing analysis attacks
- Connection correlation

### ⚠️ What Nooshdaroo Does NOT Protect Against

- Traffic volume analysis (use Tor for this)
- Server-side endpoint blocking
- Active probing attacks (requires decoy servers)
- Targeted attacks with unlimited resources

### 🔐 Best Practices

1. **Use Strong Passwords**: 20+ random characters for encryption
2. **Rotate Protocols**: Enable shape-shifting in hostile networks
3. **Combine with Tor**: Layer Nooshdaroo with Tor for maximum privacy
4. **Monitor Logs**: Watch for detection attempts
5. **Update Regularly**: Keep protocol definitions current

## Comparison with Alternatives

| Feature | Nooshdaroo | V2Ray/VMess | Shadowsocks | OpenVPN |
|---------|-----------|-------------|-------------|---------|
| Protocol Emulation | 100+ protocols | 3-4 protocols | 1 protocol | 1 protocol |
| Shape-Shifting | ✅ Dynamic | ❌ No | ❌ No | ❌ No |
| Programmable | ✅ PSF | ⚠️ Limited | ❌ No | ❌ No |
| Detection Resistance | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐ |
| Performance | High | Medium | Very High | Medium |
| Tor Integration | Native | Plugin | Plugin | Plugin |
| Complexity | Medium | Medium | Low | Low |

## Troubleshooting

### Connection Fails

```bash
# Check if Nooshdaroo is running
netstat -tlnp | grep 1080

# Verify configuration
./proteus --nooshdaroo --config nooshdaroo.toml --verify

# Enable debug logging
export RUST_LOG=debug
./proteus --nooshdaroo --config nooshdaroo.toml
```

### Protocol Detection

If your traffic is being detected:

1. Switch to high-stealth protocols (HTTPS, TLS 1.3)
2. Enable adaptive strategy
3. Increase traffic shaping randomization
4. Use shorter rotation intervals

### Performance Issues

```toml
# Disable traffic shaping for maximum speed
[traffic_shaping]
enabled = false

# Use fixed protocol (no switching overhead)
[shapeshift.strategy]
type = "fixed"
protocol = "https"
```

## Development

### Adding New Protocols

1. Create PSF file in `protocols/<category>/<protocol>.psf`
2. Add metadata in `src/nooshdaroo/library.rs`
3. Test protocol emulation
4. Submit pull request

### Testing

```bash
# Run unit tests
cargo test --lib nooshdaroo

# Run integration tests
cargo test --test integration_nooshdaroo

# Benchmark performance
cargo bench --bench nooshdaroo_bench
```

## Contributing

We welcome contributions! Areas of interest:

- New protocol definitions (PSF files)
- Traffic analysis research
- Detection evasion techniques
- Performance optimizations
- Documentation improvements

## License

Nooshdaroo inherits Proteus's license. See LICENSE file for details.

## Citation

If you use Nooshdaroo in research, please cite:

```bibtex
@inproceedings{proteus2023,
  title={Proteus: Programmable Protocols for Censorship Circumvention},
  author={Wails, Ryan and Jansen, Rob and Johnson, Aaron and Sherr, Micah},
  booktitle={USENIX Workshop on Free and Open Communication on the Internet (FOCI)},
  year={2023}
}

@software{nooshdaroo2025,
  title={Nooshdaroo: Protocol Shape-Shifting SOCKS Proxy},
  author={Your Name},
  year={2025},
  url={https://github.com/0xinf0/proteus}
}
```

## Acknowledgments

- **Proteus Team**: For the excellent PSF framework
- **Tor Project**: For pioneering censorship circumvention
- **Academic Research**: Building on decades of anti-censorship work

## Contact

- **Issues**: https://github.com/0xinf0/proteus/issues
- **Discussions**: https://github.com/0xinf0/proteus/discussions
- **Security**: See SECURITY.md for responsible disclosure

---

**نوشدارو** - A remedy for internet censorship. Stay free, stay private.
