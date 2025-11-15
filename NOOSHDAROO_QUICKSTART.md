# Nooshdaroo Quick Start Guide

Get started with Nooshdaroo in 5 minutes!

## Installation

```bash
git clone https://github.com/sinarabbaani/Nooshdaroo.git
cd Nooshdaroo
cargo build --release
```

Binary location: `./target/release/nooshdaroo`

## Basic Usage

### 1. SOCKS5 Proxy (Simplest)

```bash
# Create config
cat > nooshdaroo.toml <<EOF
mode = "client"
protocol_dir = "protocols"

[encryption]
password = "my-secure-password"

[socks]
listen_addr = "127.0.0.1:1080"

[shapeshift.strategy]
type = "fixed"
protocol = "https"
EOF

# Start proxy
./target/release/proteus --config nooshdaroo.toml

# Use with curl
curl -x socks5://127.0.0.1:1080 https://example.com
```

### 2. HTTP Proxy

```bash
# Config with HTTP proxy type
[socks]
listen_addr = "127.0.0.1:8080"
proxy_type = "http"  # HTTP CONNECT proxy

# Use with browsers
# Firefox: Settings → Network → Manual Proxy → HTTP Proxy: 127.0.0.1:8080
```

### 3. Socat Mode (Port Forwarding)

```bash
# Forward local port 8080 to remote server with HTTPS protocol emulation
nooshdaroo socat \
  TCP-LISTEN:8080,fork \
  NOOSHDAROO:server.com:443 \
  https

# Now any app connecting to localhost:8080 goes through encrypted tunnel
```

### 4. Mobile App Integration

**iOS (Swift):**
```swift
let config = NooshdarooConfig()
config.serverAddr = "server.com:443"
config.password = "password"

let client = NooshdarooClient(config: config)
try await client.start()
```

**Android (Kotlin):**
```kotlin
val config = Config.Builder()
    .serverAddr("server.com:443")
    .password("password")
    .build()

val client = Client(config)
client.start()
```

## Common Configurations

### Maximum Stealth (Censored Networks)

```toml
[shapeshift.strategy]
type = "adaptive"
switch_threshold = 0.5  # Aggressive protocol switching
safe_protocols = ["https", "dns", "websocket"]

[detection]
enable_fingerprint_randomization = true
enable_timing_randomization = true
```

### Maximum Performance (Speed Priority)

```toml
[shapeshift.strategy]
type = "fixed"
protocol = "quic"  # Fast UDP-based protocol

[traffic_shaping]
enabled = false  # Disable for max speed
```

### Battery Optimized (Mobile)

```toml
[shapeshift.strategy]
type = "fixed"
protocol = "https"  # No switching overhead

[traffic_shaping]
enabled = false

[detection]
enable_fingerprint_randomization = false
enable_timing_randomization = false
```

## Proxy Type Comparison

| Type | Use Case | Compatibility | Setup Difficulty |
|------|----------|---------------|------------------|
| **SOCKS5** | Best for apps | Most apps | Easy |
| **HTTP** | Best for browsers | Web browsers | Easy |
| **Transparent** | System-wide | All traffic | Hard (needs root) |

## Protocol Comparison

| Protocol | Speed | Stealth | Best For |
|----------|-------|---------|----------|
| **HTTPS** | ★★★★ | ★★★★★ | General use, most common |
| **QUIC** | ★★★★★ | ★★★★ | Mobile, lossy networks |
| **DNS** | ★★ | ★★★★★ | Maximum stealth |
| **SSH** | ★★★ | ★★★ | Server environments |
| **WebSocket** | ★★★★ | ★★★★ | Real-time apps |

## Command Examples

### Socat Examples

```bash
# Simple TCP relay
nooshdaroo socat TCP-LISTEN:8080,fork TCP:example.com:80

# Encrypted relay with DNS protocol
nooshdaroo socat \
  TCP-LISTEN:8080,fork \
  NOOSHDAROO:server.com:53 \
  dns

# File transfer
nooshdaroo socat FILE:/path/to/file NOOSHDAROO:server.com:443 https

# Multi-protocol auto-detect
nooshdaroo socat AUTO-LISTEN:1080,fork NOOSHDAROO:server.com:443 adaptive
```

### Browser Configuration

**Firefox:**
1. Settings → Network Settings → Manual Proxy
2. SOCKS5: 127.0.0.1, Port: 1080
3. ✓ Proxy DNS when using SOCKS v5

**Chrome:**
```bash
chrome --proxy-server="socks5://127.0.0.1:1080"
```

**System-wide (macOS):**
```bash
networksetup -setsocksfirewallproxy Wi-Fi 127.0.0.1 1080
```

**System-wide (Linux):**
```bash
export ALL_PROXY=socks5://127.0.0.1:1080
```

## Troubleshooting

### Connection Refused

```bash
# Check if Nooshdaroo is running
netstat -tlnp | grep 1080

# Check logs
export RUST_LOG=debug
./target/release/proteus --config nooshdaroo.toml
```

### Slow Connection

```toml
# Disable traffic shaping
[traffic_shaping]
enabled = false

# Use fixed protocol
[shapeshift.strategy]
type = "fixed"
protocol = "https"
```

### Detection Issues

```toml
# More aggressive evasion
[shapeshift.strategy]
type = "adaptive"
switch_threshold = 0.4  # Lower = more sensitive

safe_protocols = ["https", "tls13", "dns"]
```

## Next Steps

- Read [NOOSHDAROO_README.md](NOOSHDAROO_README.md) for full documentation
- Read [NOOSHDAROO_MOBILE.md](NOOSHDAROO_MOBILE.md) for mobile integration
- Read [NOOSHDAROO_DESIGN.md](NOOSHDAROO_DESIGN.md) for architecture details
- Check `examples/` directory for more configurations
- Join discussions at https://github.com/sinarabbaani/Nooshdaroo/discussions

## Support

- **Issues**: https://github.com/sinarabbaani/Nooshdaroo/issues
- **Discussions**: https://github.com/sinarabbaani/Nooshdaroo/discussions
- **Security**: See SECURITY.md for responsible disclosure

---

**نوشدارو** - A remedy for internet censorship. Quick, simple, powerful. 🚀
