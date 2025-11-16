# Nooshdaroo

**Protocol Shape-Shifting SOCKS Proxy**

Nooshdaroo (نوشدارو, Persian for "antidote") disguises encrypted SOCKS5 traffic as legitimate network protocols to bypass censorship and deep packet inspection.

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org/)

## 📘 Complete Documentation

**→ [NOOSHDAROO TECHNICAL REFERENCE](NOOSHDAROO_TECHNICAL_REFERENCE.md)** - Everything you need to know about Nooshdaroo: architecture, deployment, API reference, and configuration.

**→ [QUICK REFERENCE](QUICK_REFERENCE.md)** - One-page command cheatsheet and common operations.

---

## Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/sinarabbaani/Nooshdaroo.git
cd Nooshdaroo

# Build from source
cargo build --release

# Binary at target/release/nooshdaroo
```

### Basic Usage

```bash
# 1. Generate keys and configs
./target/release/nooshdaroo genkey --server-config server.toml --client-config client.toml

# 2. Run server (on VPS)
./target/release/nooshdaroo server --config server.toml

# 3. Run client (on local machine)
./target/release/nooshdaroo client --config client.toml

# 4. Use the proxy
curl --socks5 127.0.0.1:1080 https://example.com
```

### Using Preset Profiles

```bash
# Corporate network
./target/release/nooshdaroo client --profile corporate --server vps.example.com:8443

# Airport/Hotel WiFi
./target/release/nooshdaroo client --profile airport --server vps.example.com:8443

# High-censorship environments
./target/release/nooshdaroo client --profile china --server vps.example.com:8443
./target/release/nooshdaroo client --profile iran --server vps.example.com:8443
./target/release/nooshdaroo client --profile russia --server vps.example.com:8443
```

Available profiles: `corporate`, `airport`, `hotel`, `china`, `iran`, `russia`

---

## Features

### Core Capabilities
- **121 Protocol Emulations**: HTTPS, DNS, SSH, QUIC, WebSocket, gaming protocols, database protocols, and more
- **Noise Protocol Encryption**: ChaCha20-Poly1305 AEAD with X25519 key exchange (forward secrecy)
- **Multiple Proxy Modes**: SOCKS5, HTTP CONNECT, Transparent proxy
- **Traffic Shaping**: Emulate real applications (Zoom, Netflix, YouTube, Microsoft Teams, WhatsApp)
- **Adaptive Bandwidth**: Automatic quality adjustment based on network conditions (4 quality tiers)
- **Preset Profiles**: 6 environment-specific configurations for different censorship scenarios
- **Multi-Port Server**: Listen on multiple protocol-appropriate ports simultaneously
- **Path Testing**: Automatically find the best protocol/port combination for your network

### Advanced Features
- **Application Profile Emulation**: Statistical emulation of 6 popular applications
- **State Machine Emulation**: Replicate connection lifecycle (handshake → active → teardown)
- **Token Bucket Rate Limiting**: Smart bandwidth control with smooth quality transitions
- **Protocol Wrapper System**: PSF (Protocol Signature Format) for accurate protocol mimicry
- **Socat-like Relay Mode**: Bidirectional traffic relay between endpoints

---

## Architecture Overview

```
┌──────────────┐
│ Application  │  curl, browser, ssh, etc.
└──────┬───────┘
       │ SOCKS5/HTTP/Transparent
┌──────▼───────────────────────────────────────┐
│  Nooshdaroo Client                           │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐     │
│  │ Proxy   │  │ Traffic │  │ Shape-  │     │
│  │ Engine  │  │ Shaper  │  │ Shift   │     │
│  └────┬────┘  └────┬────┘  └────┬────┘     │
│       └────────────┴────────────┘           │
│  ┌───────────────▼──────────────┐           │
│  │ Protocol Wrapper (PSF)       │           │
│  └───────────────┬──────────────┘           │
│  ┌───────────────▼──────────────┐           │
│  │ Noise Protocol Encryption    │           │
│  │ (ChaCha20-Poly1305)          │           │
│  └───────────────┬──────────────┘           │
└──────────────────┼──────────────────────────┘
                   │ Encrypted, Protocol-Wrapped
                   ▼
         ╔═════════════════╗
         ║    Internet     ║
         ╚═════════════════╝
                   │
┌──────────────────▼──────────────────────────┐
│  Nooshdaroo Server                          │
│  ┌───────────────┬──────────────┐           │
│  │ Protocol Unwrapper           │           │
│  └───────────────┬──────────────┘           │
│  ┌───────────────▼──────────────┐           │
│  │ Noise Protocol Decryption    │           │
│  └───────────────┬──────────────┘           │
│  ┌───────────────▼──────────────┐           │
│  │ Destination Router           │           │
│  └───────────────┬──────────────┘           │
└──────────────────┼──────────────────────────┘
                   │
                   ▼
         ┌──────────────┐
         │ Destination  │
         │ (Internet)   │
         └──────────────┘
```

---

## Documentation

- **[NOOSHDAROO_TECHNICAL_REFERENCE.md](NOOSHDAROO_TECHNICAL_REFERENCE.md)** - Complete technical documentation
- **[QUICK_REFERENCE.md](QUICK_REFERENCE.md)** - Command cheatsheet
- **[SWISS_ARMY_KNIFE.md](SWISS_ARMY_KNIFE.md)** - Multi-function capabilities guide
- **[CHANGELOG.md](CHANGELOG.md)** - Version history
- **[CONTRIBUTING.md](CONTRIBUTING.md)** - Contribution guidelines

---

## Use Cases

### 1. Censorship Circumvention
Bypass DPI-based blocking in restrictive networks (Great Firewall of China, Iran national firewall, corporate firewalls).

### 2. Privacy Protection
Hide proxy usage from network surveillance and traffic analysis.

### 3. Protocol Research
Research and testing of protocol fingerprinting and DPI evasion techniques.

### 4. Secure Communications
Encrypted tunneling with forward secrecy for sensitive communications.

---

## Performance

- **Throughput**: ~800 Mbps on modern hardware
- **Latency Overhead**: <5ms for encryption
- **Protocol Switching**: <1ms overhead
- **Memory Usage**: ~50MB baseline, +10MB per concurrent connection
- **CPU Usage**: <5% on modern CPU for typical loads

See [Performance Characteristics](NOOSHDAROO_TECHNICAL_REFERENCE.md#10-performance-characteristics) for detailed benchmarks.

---

## Security

### Cryptographic Guarantees
- **Confidentiality**: ChaCha20-Poly1305 authenticated encryption (256-bit keys)
- **Forward Secrecy**: Ephemeral X25519 key exchange
- **Authentication**: Noise Protocol Framework patterns (NK, XX, KK)
- **Integrity**: Poly1305 MAC prevents tampering

### Limitations
- Cannot defeat offline/airgapped networks
- Requires a server outside the censored network
- Strong adversaries with unlimited resources may still detect/block
- Not a replacement for end-to-end encryption (use HTTPS/TLS)

See [Security Analysis](NOOSHDAROO_TECHNICAL_REFERENCE.md#11-security-analysis) for threat model and detailed security properties.

---

## Project Origins

Nooshdaroo builds on the [Proteus project](https://github.com/unblockable/proteus) (approximately 70% of core TCP proxy architecture). Key enhancements include:

- UDP protocol support with NAT session tracking
- Noise Protocol encryption
- Expanded protocol library (121 vs. ~20)
- Application traffic profile emulation
- Adaptive bandwidth optimization
- Production deployment infrastructure

**Development:** Orchestrated by Sina Rabbani through context engineering with Claude Code (Anthropic).

---

## License

Dual-licensed under:
- **MIT License** - See [LICENSE-MIT](LICENSE-MIT)
- **Apache 2.0 License** - See [LICENSE-APACHE](LICENSE-APACHE)

Choose whichever works best for your use case.

---

## Credits

- **Author**: Sina Rabbani
- **Repository**: https://github.com/sinarabbaani/Nooshdaroo
- **Based on**: [Proteus](https://github.com/unblockable/proteus) by Unblockable
- **Inspiration**: [Rathole](https://github.com/rapiz1/rathole) for Noise Protocol implementation

---

## Contributing

Contributions welcome! Areas of interest:
1. Protocol implementations (add new .psf files)
2. Mobile optimizations (iOS/Android FFI bindings)
3. Traffic analysis improvements (detection risk calculations)
4. Testing (real-world censorship testing)
5. Documentation (user guides, tutorials)

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

---

**نوشدارو** - *The Antidote to Network Censorship*
