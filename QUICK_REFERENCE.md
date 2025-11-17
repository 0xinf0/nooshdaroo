# Nooshdaroo Quick Reference Card

**One-page command reference for common operations**

---

## Installation & Setup

```bash
# Build from source
git clone https://github.com/sinarabbaani/Nooshdaroo.git
cd Nooshdaroo
cargo build --release

# Binary location
./target/release/nooshdaroo
```

---

## Key Generation

```bash
# Generate keypair and configs
nooshdaroo genkey \
    --server-config server.toml \
    --client-config client.toml \
    --server-addr myserver.com:8443

# Manual generation (output to terminal)
nooshdaroo genkey
```

---

## Server Operations

```bash
# Basic server
nooshdaroo server --bind 0.0.0.0:8443

# With config file
nooshdaroo server --config server.toml

# Multi-port mode
nooshdaroo server --multi-port --max-ports 20

# Verbose logging
nooshdaroo -vv server --config server.toml
```

---

## Client Operations

```bash
# Basic SOCKS5 client
nooshdaroo client --bind 127.0.0.1:1080 --server myserver.com:8443

# With config file
nooshdaroo client --config client.toml

# HTTP proxy mode
nooshdaroo client --bind 127.0.0.1:8080 --server myserver.com:8443 --proxy-type http

# Using preset profiles
nooshdaroo client --profile china --server myserver.com:8443
nooshdaroo client --profile airport --server myserver.com:8443
nooshdaroo client --profile corporate --server myserver.com:8443

# Auto-select best protocol
nooshdaroo client --auto-protocol --server myserver.com:8443
```

---

## Testing

```bash
# Test all connection paths
nooshdaroo test-paths --server myserver.com --format json

# Use the proxy
curl --socks5 127.0.0.1:1080 https://example.com
curl --proxy http://127.0.0.1:8080 https://example.com

# Test with wget
wget -e use_proxy=yes -e http_proxy=127.0.0.1:8080 https://example.com
```

---

## Protocol Selection

```bash
# Fixed protocol
nooshdaroo client --protocol https --server myserver.com:8443

# Override server port
nooshdaroo client --server myserver.com --port 53 --protocol dns
```

---

## Logging Levels

```bash
# Warnings only (default)
nooshdaroo client --config client.toml

# Info level
nooshdaroo -v client --config client.toml

# Debug level
nooshdaroo -vv client --config client.toml

# Trace level (Nooshdaroo only)
nooshdaroo -vvv client --config client.toml

# Trace level (all modules)
nooshdaroo -vvvv client --config client.toml
```

---

## Minimal Configurations

### Server (server.toml)
```toml
[server]
bind = "0.0.0.0:8443"

[transport]
pattern = "nk"
local_private_key = "YOUR_PRIVATE_KEY_HERE"
```

### Client (client.toml)
```toml
[client]
bind_address = "127.0.0.1:1080"
server_address = "myserver.com:8443"

[transport]
pattern = "nk"
remote_public_key = "SERVER_PUBLIC_KEY_HERE"

[shapeshift.strategy]
type = "fixed"
protocol = "https"
```

---

## Preset Profiles

| Profile | Use Case | Protocols | Notes |
|---------|----------|-----------|-------|
| `corporate` | Office networks | https, dns, tls13 | Multi-temporal mixing |
| `airport` | Public WiFi | dns, https | Conservative, DNS fallback |
| `hotel` | Hotel networks | dns, https | Very conservative |
| `china` | Great Firewall | dns, https, quic, tls13 | Adaptive learning |
| `iran` | Iranian filtering | dns, https, ssh | DNS emphasis |
| `russia` | Russian filtering | https, quic, ssh, dns | Rotation enabled |

---

## Application Profiles

| Profile | Type | Use Case | Bandwidth |
|---------|------|----------|-----------|
| `zoom` | Video Conference | Real-time calls | Medium |
| `netflix` | Streaming | Large downloads | High |
| `youtube` | Streaming | Video streaming | Medium-High |
| `teams` | Video Conference | Group calls | Medium |
| `whatsapp` | Messaging | Text/media | Low |
| `https` | Web Browsing | General web | Medium |

---

## Common Use Cases

### Basic Tunnel
```bash
# Server (VPS)
nooshdaroo server --config server.toml

# Client (local)
nooshdaroo client --config client.toml

# Use it
curl --socks5 127.0.0.1:1080 https://example.com
```

### China/Iran Deployment
```bash
# Client
nooshdaroo client --profile china --server myserver.com:53 --protocol dns

# Configuration
[shapeshift.strategy]
type = "adaptive"
safe_protocols = ["dns", "https"]

[traffic]
application_profile = "whatsapp"  # Low bandwidth
```

### High-Performance Streaming
```bash
# Configuration
[traffic]
application_profile = "netflix"

[bandwidth]
adaptive_quality = true
initial_quality = "high"

[shapeshift.strategy]
type = "fixed"
protocol = "https"
```

---

## Troubleshooting

```bash
# Check server is running
nc -zv myserver.com 8443

# Check client is running
netstat -an | grep 1080

# Test connectivity without proxy
curl https://example.com

# Test with proxy
curl --socks5 127.0.0.1:1080 https://example.com

# Enable debug logging
nooshdaroo -vv client --config client.toml 2>&1 | tee client.log
```

---

## Performance Tuning

### Low Latency (Gaming, VoIP)
```toml
[shapeshift.strategy]
type = "fixed"
protocol = "quic"

[traffic]
enabled = false  # Disable shaping for minimum latency
```

### Maximum Stealth
```toml
[shapeshift.strategy]
type = "adaptive"
switch_threshold = 0.5
safe_protocols = ["dns", "https", "tls_simple"]

[traffic]
enabled = true

[bandwidth]
initial_quality = "low"
```

### High Throughput
```toml
[shapeshift.strategy]
type = "fixed"
protocol = "https"

[traffic]
application_profile = "netflix"

[bandwidth]
initial_quality = "high"
```

---

## Documentation

- **Complete Reference:** NOOSHDAROO_TECHNICAL_REFERENCE.md
- **This Card:** QUICK_REFERENCE.md
- **Consolidation Info:** CONSOLIDATION_SUMMARY.md

---

**For complete documentation, see: NOOSHDAROO_TECHNICAL_REFERENCE.md**
