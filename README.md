# Nooshdaroo

**Protocol Shape-Shifting SOCKS Proxy**

Nooshdaroo (نوشدارو, Persian for "antidote") disguises encrypted SOCKS5 traffic as legitimate network protocols to bypass censorship and deep packet inspection.

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org/)
[![nDPI Validated](https://img.shields.io/badge/nDPI%20Validated-Google%20Protocol-success.svg)](#security)
[![DPI Confidence](https://img.shields.io/badge/DPI%20Confidence-Validated-brightgreen.svg)](#security)

## 🌐 Website

**→ [https://nooshdaroo.net/](https://nooshdaroo.net/)** - Download signed binaries, verify GPG signatures, and learn more about the antidote to censorship.

---

## Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/0xinf0/nooshdaroo.git
cd nooshdaroo

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

## ⚠️ Caution

**Nooshdaroo is experimental software and not recommended for security-critical applications.**

While Nooshdaroo implements strong cryptography (Noise Protocol Framework with ChaCha20-Poly1305), it is:
- Under active development and may contain bugs
- Not formally audited for security vulnerabilities
- Primarily intended for research and educational purposes
- Best suited for non-critical censorship circumvention scenarios

For production use cases requiring high security guarantees, consider well-established VPN solutions (WireGuard, OpenVPN) or Tor.

**Note:** This project builds upon [Proteus](https://github.com/unblockable/proteus) (~70% of TCP proxy architecture), which is also experimental software.

---

## Features

### Core Capabilities
- **9 Validated Protocol Emulations**: HTTPS, DNS (with Google variants), TLS 1.3, SSH, QUIC
- **Noise Protocol Encryption**: ChaCha20-Poly1305 AEAD with X25519 key exchange (forward secrecy)
- **Multiple Proxy Modes**: SOCKS5, HTTP CONNECT
- **Traffic Shaping**: Statistical traffic emulation for DPI evasion
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
       │ SOCKS5/HTTP CONNECT
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

**Real-World Benchmark Results** (HTTPS tunnel with protocol obfuscation):

| Mode | Download Speed | Time (100 MB) | Overhead | Use Case |
|------|----------------|---------------|----------|----------|
| **Direct Connection** | 108 MB/s (905 Mbps) | 0.93s | - | Baseline |
| **Nooshdaroo Tunnel** | 84.5 MB/s (711 Mbps) | 1.18s | 22% | Production |

**Test Environment**: MacBook Pro M1 → Bare-metal server (1 Gbps connection) → Nov 17, 2025

**Performance is sufficient for**:
- 4K video streaming (25-50 Mbps required, **711 Mbps delivered**)
- Large file transfers (downloads, cloud sync, backups)
- Video conferencing (5-15 Mbps typical, **711 Mbps delivered**)
- Remote desktop and VPN replacement
- Multi-device household usage (5-10 devices simultaneously)

**22% overhead breakdown**:
- Noise Protocol encryption (ChaCha20-Poly1305): ~8-10%
- Protocol wrapping and DPI evasion: ~8-10%
- Network/tunnel management: ~4-6%

**Comparison with other solutions**:
- WireGuard: 5-10% overhead (unobfuscated, easily detected)
- OpenVPN: 15-25% overhead (observable patterns, vulnerable to DPI)
- **Nooshdaroo: 22% overhead** (protocol obfuscation, nDPI validated as legitimate traffic)

Performance varies based on network conditions, hardware, protocol selection, and quality settings.

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

---

## Project Origins

Nooshdaroo builds on the [Proteus project](https://github.com/unblockable/proteus) (approximately 70% of core TCP proxy architecture). Key enhancements include:

- UDP protocol support with NAT session tracking
- Noise Protocol encryption
- Validated protocol library (9 nDPI-validated protocols)
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
- **Repository**: https://github.com/0xinf0/nooshdaroo
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

Open an issue or submit a pull request on GitHub.

---

**نوشدارو** - *The Antidote to Network Censorship*
