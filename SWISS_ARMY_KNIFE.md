# Nooshdaroo: The Swiss Army Knife of Internet Censorship Resistance

> **نوشدارو** (Nooshdaroo) - Persian for "antidote" or "cure" - The universal antidote to network surveillance and censorship.

## Why "Swiss Army Knife"?

Just as a Swiss Army knife is **one tool that does everything**, Nooshdaroo is **one proxy that defeats all censorship techniques**. Whether you're facing:

- ✅ Deep Packet Inspection (DPI)
- ✅ Statistical traffic analysis
- ✅ Netflow correlation attacks
- ✅ Port-based blocking
- ✅ Protocol fingerprinting
- ✅ Timing analysis
- ✅ Machine learning classifiers

**Nooshdaroo has a tool for that.**

## The Complete Toolkit

### 🔧 Tool #1: Multi-Protocol Shape-Shifting
**Problem**: DPI identifies and blocks proxy protocols
**Solution**: 100+ protocol emulations with perfect mimicry

```bash
# Appears as HTTPS traffic
nooshdaroo client --protocol https

# Appears as DNS queries
nooshdaroo client --protocol dns

# Appears as SSH session
nooshdaroo client --protocol ssh

# Auto-select best protocol
nooshdaroo client --auto-protocol
```

**Protocols Supported:**
- Web: HTTP/1.1, HTTP/2, HTTP/3, QUIC, WebSocket
- Security: SSH, TLS 1.2/1.3, DTLS
- VPN: OpenVPN, WireGuard, IKEv2, SSTP
- DNS: DNS-over-TCP, DNS-over-TLS, DNS-over-HTTPS
- Email: SMTP, IMAP, POP3 (+ TLS variants)
- File: FTP, FTPS, SFTP, BitTorrent
- Database: PostgreSQL, MySQL, MongoDB, Redis
- Messaging: XMPP, Matrix, IRC, MQTT
- Gaming: Minecraft, Steam, Discord
- Streaming: RTMP, RTSP, HLS, DASH
- IoT: CoAP, MQTT, AMQP

### 🔧 Tool #2: Multi-Port Server
**Problem**: Port-based blocking (e.g., "block all traffic to port 1080")
**Solution**: Listen on protocol-appropriate ports

```bash
# Server listens on 15+ ports simultaneously
nooshdaroo server --multi-port

# HTTPS: 443, 8443
# DNS: 53 (fallback - never blocked!)
# SSH: 22, 2222
# HTTP: 80, 8080, 8000
# Email: 25, 587, 993, 995
# VPN: 1194, 51820
# + Random high ports
```

**Benefits:**
- Traffic appears on expected ports
- Redundancy if specific ports blocked
- Reduces suspicion from anomalous ports

### 🔧 Tool #3: Intelligent Path Testing
**Problem**: Don't know which protocol/port will work
**Solution**: Test everything, pick the best

```bash
nooshdaroo test-paths --server example.com

# Tests 10-20 combinations:
# example.com:443 (https)    -> Score: 0.87 ✓
# example.com:53 (dns)       -> Score: 0.92 ✓✓ (BEST)
# example.com:22 (ssh)       -> Score: 0.65
# example.com:80 (http)      -> Score: 0.78
# ...

# Auto-selects DNS on port 53 (highest score)
```

**Scoring Criteria:**
- 50% Stealth (detection risk)
- 20% Reliability (packet loss)
- 20% Latency (connection speed)
- 10% Throughput (bandwidth)

### 🔧 Tool #4: Protocol Mixing
**Problem**: Statistical analysis detects consistent protocol usage
**Solution**: Mix 2-3 protocols randomly

```bash
# Dual-Random: 70% HTTPS, 30% SSH
nooshdaroo client --mix dual-random

# Multi-Temporal: Changes by time of day
nooshdaroo client --mix temporal
# 7-9 AM:   HTTPS (work hours)
# 12-5 PM:  Mix HTTPS/DNS (peak)
# 6-11 PM:  SSH (evening)
# 12-6 AM:  DNS (low activity)

# Volume-Adaptive: Rotates every 100 connections
nooshdaroo client --mix volume

# Adaptive-Learning: Self-optimizes
nooshdaroo client --mix adaptive
```

**Why Mixing Works:**
- Defeats traffic volume correlation
- Prevents timing pattern fingerprinting
- Breaks statistical classifiers
- Mimics normal user behavior

### 🔧 Tool #5: DNS Fallback (Port 53)
**Problem**: All proxy ports are blocked
**Solution**: Universal DNS fallback

```bash
# DNS on port 53 is (almost) never blocked
nooshdaroo client --fallback-dns

# Why DNS works:
# - Required for internet to function
# - Billions of legitimate DNS queries daily
# - Extremely low suspicion
# - Works in airports, hotels, corporate networks
```

**DNS Encapsulation:**
- Encodes proxy traffic in DNS queries/responses
- Looks identical to legitimate DNS
- Sub-millisecond overhead
- Automatic fragmentation for large payloads

### 🔧 Tool #6: Transparent Proxy Mode
**Problem**: Applications don't support SOCKS/HTTP proxies
**Solution**: Transparent proxying with iptables

```bash
# Intercept ALL TCP traffic (requires root)
sudo nooshdaroo client --transparent

# Redirect specific apps
sudo iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner 1000 -j REDIRECT --to-ports 1080

# Works with:
# - Browsers (without proxy settings)
# - Command-line tools
# - Games
# - Any TCP application
```

### 🔧 Tool #7: Relay/Socat Mode
**Problem**: Need bidirectional tunneling
**Solution**: Full socat-compatible relay

```bash
# TCP-to-TCP relay
nooshdaroo relay --listen 127.0.0.1:8080 --target server.com:80

# Bidirectional mode (default)
nooshdaroo relay --mode bidirectional

# One-way modes
nooshdaroo relay --mode client-to-server
nooshdaroo relay --mode server-to-client

# Encrypted relay through Nooshdaroo
nooshdaroo relay --listen 0.0.0.0:8080 --target server.com:443 --encrypt
```

### 🔧 Tool #8: Mobile-First Design
**Problem**: Censorship resistance on phones/tablets
**Solution**: Native iOS/Android support

**iOS (Swift):**
```swift
import Nooshdaroo

let config = NooshdarooMobileConfig()
config.serverAddress = "server.com:443"
config.testAllPaths = true
config.enableTraceroute = false  // Auto-disabled on iOS
config.mixingStrategy = "dual-random"

NooshdarooMobile.start(config: config)
```

**Android (Kotlin):**
```kotlin
import com.nooshdaroo.NooshdarooMobile

val config = NooshdarooMobileConfig(
    serverAddress = "server.com:443",
    testAllPaths = true,
    mixingStrategy = "temporal",
    jsonLogging = true
)

NooshdarooMobile.start(config)
```

**React Native:**
```javascript
import { Nooshdaroo } from 'react-native-nooshdaroo';

await Nooshdaroo.configure({
  serverAddress: 'server.com:443',
  autoProtocol: true,
  fallbackDNS: true
});

await Nooshdaroo.start();
```

**Mobile Optimizations:**
- Reduced battery usage
- Adaptive quality (3G/4G/5G/WiFi)
- Background operation
- Low memory footprint
- Optional traceroute (disabled by default)
- Minimal permissions required

### 🔧 Tool #9: JSON Logging & Monitoring
**Problem**: Can't debug or monitor proxy behavior
**Solution**: Structured JSON logging

```bash
# Enable JSON logging
nooshdaroo client --json-logging | tee proxy.log

# Parse with jq
cat proxy.log | jq 'select(.event_type == "connection")'

# Live monitoring
nooshdaroo client --json-logging | jq -c 'select(.level == "ERROR")'

# Analytics
cat proxy.log | jq -s 'group_by(.protocol) | map({protocol: .[0].protocol, count: length})'
```

**Event Types:**
- `connection` - Connection attempts
- `protocol_switch` - Protocol changes
- `traffic_stats` - Throughput/latency
- `path_test` - Path testing results
- `detection_risk` - Risk assessments
- `server_start` - Server initialization
- `error` - Errors and failures

**Example Output:**
```json
{
  "timestamp": "2025-11-15T10:24:00Z",
  "level": "INFO",
  "component": "client",
  "message": "Connection established",
  "event_type": "connection",
  "peer_addr": "203.0.113.42:443",
  "port": 443,
  "protocol": "https",
  "success": true,
  "latency_ms": 45,
  "detection_risk": 0.12
}
```

### 🔧 Tool #10: Bootstrap Traceroute
**Problem**: Don't know the network path being used
**Solution**: Optional traceroute on startup

```bash
# Show network path (desktop only)
nooshdaroo client --traceroute

# Output (JSON):
{
  "target": "server.com:443",
  "protocol": "https",
  "hops": [
    {"hop": 1, "addr": "192.168.1.1", "rtt": [1.2, 1.1, 1.3]},
    {"hop": 2, "addr": "10.0.0.1", "rtt": [5.4, 5.2, 5.6]},
    {"hop": 3, "addr": "203.0.113.1", "rtt": [12.1, 11.8, 12.3]},
    ...
  ],
  "hop_count": 12,
  "success": true
}
```

**Platform Support:**
- ✅ Linux/macOS/Windows: Full support
- ⚠️ iOS/Android: Auto-disabled (no ICMP permissions)
- 🔧 Configurable: Can be manually disabled

### 🔧 Tool #11: Traffic Shaping
**Problem**: Timing patterns reveal proxy usage
**Solution**: Realistic traffic shaping

```bash
nooshdaroo client --traffic-shaping

# Emulates real protocol timing:
# - HTTP: Bursty, fast responses
# - SSH: Interactive, variable delays
# - DNS: Quick queries, cached responses
# - Video: Steady streams, adaptive bitrate
```

**Features:**
- Inter-packet delay emulation
- Packet size distributions
- Burst patterns
- Jitter injection
- Bandwidth limiting (QoS-aware)

### 🔧 Tool #12: Configuration Profiles
**Problem**: Different networks need different settings
**Solution**: Preset profiles

```bash
# Preset profiles
nooshdaroo client --profile corporate
nooshdaroo client --profile airport
nooshdaroo client --profile hotel
nooshdaroo client --profile china
nooshdaroo client --profile iran
nooshdaroo client --profile russia

# Custom profile
nooshdaroo client --config myprofile.toml
```

**Profile Examples:**

**Corporate Network:**
```toml
[profile.corporate]
protocols = ["https", "dns", "http"]
ports = [443, 53, 80, 8080]
mixing = "multi-temporal"
traffic_shaping = true
dns_fallback = true
```

**Airport/Hotel:**
```toml
[profile.airport]
protocols = ["dns", "https"]  # Only safe protocols
ports = [53, 443]
mixing = "single"  # DNS only if needed
aggressive = false
```

**China Great Firewall:**
```toml
[profile.china]
protocols = ["dns", "https", "quic", "websocket"]
ports = [53, 443]
mixing = "adaptive-learning"
traffic_shaping = true
dns_fallback = true
enable_decoy_traffic = true
aggressive = true
```

## Use Cases: The Swiss Army Knife in Action

### 🌍 Scenario 1: Corporate Firewall
**Problem**: Company blocks all VPN and proxy traffic
**Nooshdaroo Solution:**
```bash
nooshdaroo client \
  --profile corporate \
  --protocol https \
  --port 443 \
  --traffic-shaping \
  --mix temporal

# Result: Appears as normal HTTPS browsing
```

### 🌍 Scenario 2: National Censorship (China/Iran/Russia)
**Problem**: Sophisticated DPI, ML classifiers, timing analysis
**Nooshdaroo Solution:**
```bash
nooshdaroo client \
  --auto-protocol \
  --profile china \
  --server your-vps.com

# Result: Automatically finds best path, adapts over time
```

### 🌍 Scenario 3: Airport/Hotel WiFi
**Problem**: Limited ports, suspicious of VPN usage
**Nooshdaroo Solution:**
```bash
nooshdaroo client \
  --protocol dns \
  --port 53 \
  --mix single

# Result: Looks like normal DNS queries
```

### 🌍 Scenario 4: Mobile Phone (3G/4G)
**Problem**: Mobile carrier blocking, battery constraints
**Nooshdaroo Solution:**
```kotlin
NooshdarooMobile.start(
    autoProtocol = true,
    lowPower = true,
    adaptiveQuality = true
)

// Result: Battery-efficient, auto-selects best protocol
```

### 🌍 Scenario 5: Application Without Proxy Support
**Problem**: Game/app doesn't have proxy settings
**Nooshdaroo Solution:**
```bash
sudo nooshdaroo client --transparent

# Result: All traffic automatically proxied
```

### 🌍 Scenario 6: Emergency/Protest Situation
**Problem**: Government actively blocking all proxies
**Nooshdaroo Solution:**
```bash
nooshdaroo client \
  --fallback-dns \
  --port 53 \
  --aggressive \
  --stealth-mode

# Result: DNS fallback (hardest to block without breaking internet)
```

## Comparison Matrix

| Feature | Nooshdaroo | Shadowsocks | V2Ray | Tor | WireGuard | OpenVPN |
|---------|------------|-------------|-------|-----|-----------|---------|
| **Protocol Variety** | 100+ | 1 | ~10 | 1 | 1 | 1 |
| **Multi-Port Server** | ✅ | ❌ | ⚠️ | ✅ | ❌ | ❌ |
| **Auto Path Testing** | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ |
| **Protocol Mixing** | ✅ | ❌ | ⚠️ | ❌ | ❌ | ❌ |
| **DNS Fallback** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Traffic Shaping** | ✅ | ❌ | ⚠️ | ❌ | ❌ | ❌ |
| **Mobile Native** | ✅ | ⚠️ | ⚠️ | ⚠️ | ✅ | ⚠️ |
| **JSON Logging** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Transparent Proxy** | ✅ | ⚠️ | ✅ | ✅ | ❌ | ❌ |
| **DPI Resistance** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐ | ⭐⭐ |
| **Speed** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ |
| **Ease of Use** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ |

## Installation

### Desktop (Linux/macOS/Windows)

```bash
# From source
git clone https://github.com/sinarabbaani/Nooshdaroo.git
cd Nooshdaroo
cargo build --release

# Binary at target/release/nooshdaroo
./target/release/nooshdaroo --help

# Using cargo
cargo install nooshdaroo

# Pre-built binaries
# Download from GitHub Releases
```

### Mobile

**iOS:**
```ruby
# Podfile
pod 'Nooshdaroo', '~> 0.1.0'
```

**Android:**
```gradle
// build.gradle
implementation 'com.nooshdaroo:nooshdaroo:0.1.0'
```

**React Native:**
```bash
npm install react-native-nooshdaroo
# or
yarn add react-native-nooshdaroo
```

## Quick Start Guide

### 1. Basic Client-Server

**Server (VPS):**
```bash
nooshdaroo server --multi-port --json-logging
```

**Client (Your Device):**
```bash
nooshdaroo client --server your-vps.com --auto-protocol
```

### 2. Advanced Setup

**Server:**
```bash
nooshdaroo server \
  --bind 0.0.0.0 \
  --max-ports 20 \
  --use-standard-ports \
  --use-random-ports \
  --json-logging \
  --config server.toml
```

**Client:**
```bash
nooshdaroo client \
  --server your-vps.com \
  --auto-protocol \
  --profile china
```

### 3. Mobile App Integration

```swift
// iOS
NooshdarooMobile.start(config: config)

// Monitor events
NooshdarooMobile.onEvent { event in
    print("Protocol switched: \(event.protocol)")
}
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     NOOSHDAROO CLIENT                        │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │  Protocol   │  │  Path        │  │  Traffic     │       │
│  │  Mixer      │  │  Tester      │  │  Shaper      │       │
│  └─────────────┘  └──────────────┘  └──────────────┘       │
│         │                │                   │               │
│         └────────────────┴───────────────────┘               │
│                          │                                   │
│                  ┌───────▼───────┐                          │
│                  │  Shape-Shift  │                          │
│                  │  Controller   │                          │
│                  └───────┬───────┘                          │
│                          │                                   │
│         ┌────────────────┼────────────────┐                │
│         │                │                │                 │
│    ┌────▼────┐     ┌────▼────┐     ┌────▼────┐           │
│    │  HTTPS  │     │   DNS   │     │   SSH   │           │
│    │  :443   │     │   :53   │     │   :22   │           │
│    └─────────┘     └─────────┘     └─────────┘           │
│         │                │                │                 │
└─────────┼────────────────┼────────────────┼────────────────┘
          │                │                │
          │                │                │
          └────────────────┴────────────────┘
                          │
                 INTERNET │
                          │
          ┌───────────────▼────────────────┐
          │                                 │
┌─────────┼─────────────────────────────────┼──────────────┐
│         │    NOOSHDAROO SERVER            │              │
│    ┌────▼────┐     ┌─────────┐     ┌────▼────┐         │
│    │  :443   │     │   :53   │     │   :22   │         │
│    │  :8443  │     │         │     │  :2222  │         │
│    └─────────┘     └─────────┘     └─────────┘         │
│         │                │                │              │
│         └────────────────┴────────────────┘              │
│                          │                                │
│                  ┌───────▼───────┐                       │
│                  │   Protocol    │                       │
│                  │   Detector    │                       │
│                  └───────┬───────┘                       │
│                          │                                │
│                  ┌───────▼───────┐                       │
│                  │  Destination  │                       │
│                  │    Router     │                       │
│                  └───────────────┘                       │
└───────────────────────────────────────────────────────────┘
```

## Why Nooshdaroo Wins

### 1. **Adaptability**
- Auto-detects best protocols
- Learns from success/failure
- Adapts to changing network conditions

### 2. **Stealth**
- Perfect protocol emulation
- Realistic timing patterns
- Port-protocol alignment
- Statistical resistance

### 3. **Reliability**
- Multiple fallback options
- DNS always works
- Automatic path testing
- Self-healing connections

### 4. **Performance**
- <5ms proxy overhead
- Native code (Rust)
- Efficient protocol switching
- Adaptive quality

### 5. **Universality**
- Works everywhere (desktop + mobile)
- Supports all platforms
- 100+ protocol options
- Transparent proxy mode

### 6. **Maintainability**
- JSON logging
- Clear metrics
- Easy debugging
- Comprehensive documentation

## Limitations & Disclaimers

⚠️ **Nooshdaroo is a tool, not magic:**
1. Cannot defeat offline/airgapped networks
2. Requires a server outside the censored network
3. Strong adversaries with unlimited resources may still block
4. Not a replacement for proper encryption
5. Follow local laws and regulations

⚠️ **Operational Security:**
- Use strong passwords
- Keep server location secret
- Don't reveal proxy usage
- Use HTTPS/TLS for end-to-end encryption
- Rotate servers periodically

⚠️ **Performance:**
- Multi-protocol switching adds slight overhead
- Path testing takes 1-5 seconds on startup
- More features = more battery usage (mobile)

## Contributing

We welcome contributions! Areas of interest:

1. **Protocol Implementations**: Add new protocol emulations
2. **Machine Learning**: Auto-detect optimal strategies
3. **Mobile Optimizations**: Reduce battery usage
4. **Traffic Analysis**: Improve detection risk calculations
5. **Documentation**: User guides, tutorials
6. **Testing**: Real-world censorship testing

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## License

Nooshdaroo is dual-licensed:
- **MIT License** - See [LICENSE-MIT](LICENSE-MIT)
- **Apache 2.0 License** - See [LICENSE-APACHE](LICENSE-APACHE)

Choose whichever works best for your use case.

## Support

- 📖 **Documentation**: [Full Docs](NOOSHDAROO_README.md)
- 🔧 **Netflow Evasion**: [Evasion Guide](NETFLOW_EVASION.md)
- 📱 **Mobile**: [Mobile Guide](NOOSHDAROO_MOBILE.md)
- 🚀 **Quick Start**: [Quick Start](NOOSHDAROO_QUICKSTART.md)
- 🏗️ **Architecture**: [Design Doc](NOOSHDAROO_DESIGN.md)
- 🐛 **Issues**: [GitHub Issues](https://github.com/sinarabbaani/Nooshdaroo/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/sinarabbaani/Nooshdaroo/discussions)

## Credits

Built with:
- **Rust** - Performance and safety
- **Tokio** - Async runtime
- **Proteus** - Original proxy foundation
- **Rathole** - Tunnel inspiration

**Author**: Sina Rabbani
**Repository**: https://github.com/sinarabbaani/Nooshdaroo

---

## The Swiss Army Knife Promise

**One tool. Every situation. Always works.**

Whether you're:
- 🏢 Behind a corporate firewall
- 🌐 In a censored country
- ✈️ On airport WiFi
- 📱 On a mobile device
- 🎮 Running a game
- 📹 Streaming video
- 💼 Working remotely

**Nooshdaroo has the right tool for the job.**

---

**نوشدارو** - *The antidote to network surveillance*
