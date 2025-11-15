# Nooshdaroo

**Protocol Shape-Shifting SOCKS Proxy**

Nooshdaroo is a sophisticated proxy system that disguises encrypted SOCKS5 traffic as legitimate network protocols to bypass deep packet inspection (DPI) and censorship. It dynamically emulates 100+ protocols including HTTPS, SSH, DNS, and more.

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org/)

## Features

### Core Features
- **Multiple Proxy Types**: SOCKS5, HTTP CONNECT, Transparent proxy
- **Socat-like Relay**: Bidirectional traffic relay between endpoints
- **Mobile-Friendly**: iOS/Android FFI bindings for native integration
- **Protocol Shape-Shifting**: 5 strategies for dynamic protocol emulation
- **100+ Protocols**: Pre-defined protocol signatures (HTTPS, SSH, DNS, QUIC, WebSocket, etc.)
- **Cross-Platform**: Works on Linux, macOS, Windows, iOS, Android

### Advanced Traffic Shaping ✨ NEW
- **Application Profiles**: Mimic real applications (Zoom, Netflix, YouTube, Teams, WhatsApp, HTTPS)
- **Statistical Traffic Emulation**: Match packet size distributions, timing patterns, and burst behaviors
- **State Machine Emulation**: Replicate connection phases (handshake → active → teardown)
- **Adaptive Bandwidth Optimization**: Auto-adjust quality based on network conditions (RTT, loss, throughput)
- **Quality Tiers**: 4 quality levels with automatic adaptation
- **Smart Rate Limiting**: Token bucket with smooth quality transitions

### Encrypted Transport (Noise Protocol) ✨ NEW
- **End-to-End Encryption**: Noise Protocol Framework with ChaCha20-Poly1305
- **Multiple Patterns**: NK (server auth), XX (anonymous), KK (mutual auth)
- **Forward Secrecy**: Ephemeral X25519 key exchange
- **Easy Key Generation**: Beautiful CLI tool - `nooshdaroo genkey` creates configs automatically
- **Auto-Config Generation**: Generate ready-to-use server/client configs with one command
- **Compatible with Rathole**: Same Noise protocol patterns

## Quick Start

### Installation

#### From Source

```bash
git clone https://github.com/sinarabbaani/Nooshdaroo.git
cd Nooshdaroo
cargo build --release
```

The binary will be available at `target/release/nooshdaroo`.

#### Using Cargo

```bash
cargo install nooshdaroo
```

### Basic Usage

#### Run as Client (Local Proxy)

```bash
# SOCKS5 proxy on localhost:1080
nooshdaroo client --bind 127.0.0.1:1080 --server example.com:8443

# HTTP proxy
nooshdaroo client --bind 127.0.0.1:8080 --server example.com:8443 --proxy-type http

# Transparent proxy (requires root)
sudo nooshdaroo client --bind 127.0.0.1:1080 --server example.com:8443 --proxy-type transparent
```

#### Run as Server (Remote Endpoint)

```bash
nooshdaroo server --bind 0.0.0.0:8443
```

#### Run as Relay (Socat Mode)

```bash
# Bidirectional relay
nooshdaroo relay --listen 127.0.0.1:8080 --target example.com:443

# One-way relay (client to server only)
nooshdaroo relay --listen 127.0.0.1:8080 --target example.com:443 --mode client-to-server
```

### Configuration File

Create a `nooshdaroo.toml` configuration file:

```toml
# Nooshdaroo Configuration

# Local proxy settings
[client]
bind_address = "127.0.0.1:1080"
server_address = "example.com:8443"
proxy_type = "socks5"  # socks5, http, or transparent

# Protocol directory
protocol_dir = "protocols"

# Shape-shifting configuration
[shapeshift]
strategy = "adaptive"  # static, time-based, random, traffic-based, adaptive
initial_protocol = "https"
rotation_interval = "5m"

# Traffic shaping
[traffic]
enable_timing_emulation = true
enable_size_padding = true
max_padding_bytes = 1024
jitter_ms = 50
```

Then run with:

```bash
nooshdaroo client --config nooshdaroo.toml
```

### Advanced: Application Profile Configuration

Use pre-configured application profiles for realistic traffic patterns:

```bash
# Zoom video conferencing emulation
nooshdaroo client --config examples/profiles/zoom_config.toml

# Netflix streaming emulation
nooshdaroo client --config examples/profiles/netflix_config.toml

# YouTube streaming
nooshdaroo client --config examples/profiles/youtube_config.toml
```

Or configure in TOML:

```toml
[client]
bind_address = "127.0.0.1:1080"
server_address = "example.com:8443"

# Use Zoom traffic profile
[traffic]
application_profile = "zoom"
enabled = true

# Enable adaptive bandwidth optimization
[bandwidth]
adaptive_quality = true
initial_quality = "high"
auto_adapt = true
```

See [ADVANCED_TRAFFIC_SHAPING.md](ADVANCED_TRAFFIC_SHAPING.md) for detailed configuration options.

## Usage Examples

### Point Any Application Through Nooshdaroo

```bash
# Start Nooshdaroo client
nooshdaroo client --bind 127.0.0.1:1080 --server your-server.com:8443

# Configure your application to use SOCKS5 proxy at 127.0.0.1:1080
# Example with curl:
curl --socks5 127.0.0.1:1080 https://example.com

# Example with Firefox:
# Settings → Network Settings → Manual proxy → SOCKS Host: 127.0.0.1, Port: 1080
```

### Mobile Integration

#### iOS (Swift)

```swift
import Nooshdaroo

let config = NooshdarooMobileConfig()
config.serverAddress = "your-server.com:8443"
config.proxyType = "socks5"
config.protocol = "https"

NooshdarooMobile.start(config: config)

// All traffic now routes through Nooshdaroo
```

#### Android (Kotlin)

```kotlin
import com.nooshdaroo.NooshdarooMobile

val config = NooshdarooMobileConfig(
    serverAddress = "your-server.com:8443",
    proxyType = "socks5",
    protocol = "https"
)

NooshdarooMobile.start(config)
```

See [NOOSHDAROO_MOBILE.md](NOOSHDAROO_MOBILE.md) for detailed mobile integration guide.

### React Native

```javascript
import { Nooshdaroo } from 'react-native-nooshdaroo';

await Nooshdaroo.configure({
  serverAddress: 'your-server.com:8443',
  proxyType: 'socks5',
  protocol: 'https'
});

await Nooshdaroo.start();
```

### Command-Line Operations

```bash
# List available protocols
nooshdaroo protocols --dir protocols

# Check client status
nooshdaroo status --client 127.0.0.1:1080

# Manually rotate protocol
nooshdaroo rotate --client 127.0.0.1:1080
```

## Architecture

```
┌─────────────────┐         ┌──────────────────┐         ┌─────────────────┐
│  Application    │────────▶│  Nooshdaroo      │────────▶│  Remote Server  │
│  (Browser, etc) │  SOCKS5 │  Client          │  HTTPS  │  (Endpoint)     │
└─────────────────┘         └──────────────────┘         └─────────────────┘
                                      │
                                      │ Shape-Shifting
                                      ▼
                            ┌──────────────────┐
                            │  Protocol        │
                            │  Library         │
                            │  (100+ protocols)│
                            └──────────────────┘
```

## Shape-Shifting Strategies

Nooshdaroo supports 5 protocol selection strategies:

1. **Static**: Use one protocol consistently
2. **Time-Based**: Rotate protocols on a schedule
3. **Random**: Randomly select protocols
4. **Traffic-Based**: Switch based on traffic patterns
5. **Adaptive**: AI-driven selection based on detection risk

See [NOOSHDAROO_DESIGN.md](NOOSHDAROO_DESIGN.md) for technical details.

## Protocol Library

Nooshdaroo includes 100+ protocol signatures organized by category:

- **Web**: HTTP/1.1, HTTP/2, HTTP/3, WebSocket
- **Secure Shell**: SSH-2.0, Telnet, SFTP
- **VPN**: OpenVPN, WireGuard, IKEv2
- **DNS**: DNS-over-TCP, DNS-over-TLS, DNS-over-HTTPS
- **Mail**: SMTP, IMAP, POP3 (with TLS variants)
- **File Transfer**: FTP, FTPS, BitTorrent
- **Database**: PostgreSQL, MySQL, Redis
- **Messaging**: XMPP, IRC, Matrix
- **Streaming**: RTMP, RTSP, SRT
- **Gaming**: Minecraft, Steam, Discord
- **IoT**: MQTT, CoAP, AMQP

Each protocol includes:
- Handshake patterns
- Timing characteristics
- Traffic size distributions
- Port conventions

## Use Cases

1. **Bypass Censorship**: Access blocked websites in restrictive networks
2. **Privacy**: Hide proxy usage from network surveillance
3. **Testing**: Simulate various protocols for network testing
4. **App Integration**: Add censorship-resistant connectivity to mobile apps
5. **Research**: Study protocol fingerprinting and DPI techniques

## Performance

- **HTTP Proxy**: <5ms overhead
- **Transparent Proxy**: <10ms (includes iptables lookup)
- **Socat Relay**: Near-native performance
- **Binary Size**: ~5 MB (release build)

## Documentation

- [Quick Start Guide](NOOSHDAROO_QUICKSTART.md) - 5-minute tutorial
- [Design Document](NOOSHDAROO_DESIGN.md) - Architecture and 100 protocols
- **[Advanced Traffic Shaping](ADVANCED_TRAFFIC_SHAPING.md)** - Application profiles and bandwidth optimization ✨ NEW
- **[Noise Protocol Encryption](NOISE_TRANSPORT.md)** - End-to-end encrypted transport ✨ NEW
- **[Key Generation Guide](KEYGEN_GUIDE.md)** - Easy keygen tool tutorial ✨ NEW
- [Mobile Integration](NOOSHDAROO_MOBILE.md) - iOS/Android/React Native guide
- [Full Documentation](NOOSHDAROO_README.md) - Complete feature reference
- [Summary](NOOSHDAROO_SUMMARY.md) - Project overview

## Development

### Building from Source

```bash
# Debug build
cargo build

# Release build (optimized)
cargo build --release

# Run tests
cargo test

# Run with logging
RUST_LOG=debug cargo run -- client --bind 127.0.0.1:1080 --server example.com:8443
```

### Project Structure

```
nooshdaroo/
├── src/
│   ├── lib.rs              # Library entry point
│   ├── main.rs             # CLI entry point
│   ├── config.rs           # Configuration management
│   ├── library.rs          # Protocol library loader
│   ├── protocol.rs         # Protocol definitions
│   ├── proxy.rs            # Proxy implementations
│   ├── shapeshift.rs       # Shape-shifting controller
│   ├── strategy.rs         # Selection strategies
│   ├── traffic.rs          # Traffic shaping
│   ├── socat.rs            # Relay implementation
│   └── mobile.rs           # Mobile FFI bindings
├── protocols/              # Protocol definitions (PSF files)
├── examples/               # Example configurations
└── docs/                   # Additional documentation
```

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Submit a pull request

## Security

Nooshdaroo is designed for:
- Circumventing censorship
- Privacy protection
- Authorized security testing
- Educational purposes

**Do not use for**:
- Illegal activities
- Malicious purposes
- Violating terms of service

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.

## Related Projects

- [Proteus](https://github.com/unblockable/proteus) - The parent project (Pluggable Transport)
- [Rathole](https://github.com/rapiz1/rathole) - Secure reverse tunnel
- [v2ray](https://github.com/v2ray/v2ray-core) - Platform for building proxies

## Credits

Original credit goes to [Proteus](https://github.com/unblockable/proteus).

**Author**: Sina Rabbani
**Repository**: https://github.com/sinarabbaani/Nooshdaroo

---

**نوشدارو** (Nooshdaroo) - Persian for "antidote" or "cure"
