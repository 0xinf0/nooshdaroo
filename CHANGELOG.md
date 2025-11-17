# Changelog

All notable changes to Nooshdaroo will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2025-11-17

### Added
- **IPv6 Support** - Full support for IPv6 destinations through SOCKS5 proxy
  - Client formats IPv6 addresses with RFC-compliant bracket notation `[ipv6]:port`
  - Server parses both IPv4 `host:port` and IPv6 `[host]:port` formats
  - Tested with real-world IPv6 endpoints (httpbin.org resolves to IPv6)
  - Large file transfer validation: 100 MB download at 711 Mbps through IPv6-enabled tunnel
- **Performance Benchmarks** - Real-world performance metrics documented in NOOSHDAROO_TECHNICAL_REFERENCE.md
  - Direct connection baseline: 108 MB/s (905 Mbps)
  - Nooshdaroo HTTPS tunnel: 84.5 MB/s (711 Mbps)
  - Overhead: 22% (acceptable for encrypted tunnel with protocol obfuscation)
  - Sufficient for 4K streaming, large file transfers, and remote work
- **nDPI Baseline Testing** - Comprehensive end-to-end validation against nDPI (Network Deep Packet Inspection)
  - HTTPS traffic successfully classified as "Google" protocol by nDPI 4.15.0 with DPI confidence
  - Automated multi-protocol test suite for validating protocol evasion
  - Test documentation in NDPI_BASELINE_SUCCESS.md
- **Multi-Protocol Test Suite** - `test_all_protocols_ndpi.sh` for automated testing of HTTPS, DNS, and other protocols
- **`server_address` field in `[socks]` configuration** - Clients can now specify server address in config file instead of only via CLI `--server` flag
- **Operating Modes documentation** - Added comprehensive documentation explaining Tunnel Mode vs Direct Mode in README.md and WHITEPAPER.md
- **Mobile example configurations** - Updated all mobile integration examples to include server address configuration

### Changed
- **`--server` CLI flag now optional** - Server address can be specified in config file under `[socks]` section, making `--server` flag optional when using config files
- **Configuration format** - Updated all example configs to use new `[shapeshift.strategy]` format with `type` field
- **Client startup behavior** - Client now clearly indicates whether it's running in Tunnel Mode or Direct Mode with appropriate log messages

### Fixed
- **CRITICAL: PSF Parser Double-Advance Bug** - Fixed parser bug that prevented semantic rules from loading
  - **Issue**: `expect_token()` already advances parser position, but explicit `self.advance()` calls caused double-advancement
  - **Impact**: 0 semantic rules loaded → all FIXED_VALUE and FIXED_BYTES fields generated as zeros → nDPI classified traffic as "Unknown"
  - **Fix**: Removed unnecessary `self.advance()` calls in FIXED_VALUE and FIXED_BYTES parsers (`src/psf/parser.rs:488-493, 554-592`)
  - **Result**: 75 semantic rules now load correctly → valid TLS 1.3 ClientHello generation → nDPI classifies traffic as "Google" protocol
  - **Validation**: End-to-end nDPI test passed (34 packets, 2885 bytes, DPI confidence, "Acceptable" status)
- **Critical bypass bug** - Fixed issue where client would bypass the proxy server and connect directly to targets when using config files
  - Root cause: `server_address` was only read from CLI arguments, not from config file
  - Impact: Traffic was not encrypted or tunneled, defeating the entire purpose of the proxy
  - Resolution: Added `server_address` field to `SocksConfig` struct and updated client initialization logic
- **Configuration validation** - Client now validates that either `--server` flag or `server_address` in config is provided, preventing accidental direct mode operation
- **Error handling** - Improved error messages when server connection fails (no longer falls back to direct connections)

### Security
- **Protocol Evasion Validated** - nDPI baseline test confirms traffic masquerades as legitimate Google/Web traffic
  - Test Date: November 16, 2025
  - nDPI Version: 4.15.0-5577-75db1a8
  - Classification: Google protocol (not Unknown)
  - Confidence: DPI (Deep Packet Inspection)
  - Risk Flags: Expected cosmetic warnings (non-standard port, IP mismatch) - do not affect core evasion
- **No fallback to direct mode** - Client will now fail with an error if server is unreachable, instead of silently bypassing the tunnel (previous behavior was a security risk)
- **Explicit mode warnings** - Added warning logs when running in Direct Mode to prevent accidental exposure of unencrypted traffic

## [0.1.0] - 2025-11-15

### Added
- Initial release
- 121 protocol signatures for shape-shifting
- Noise Protocol Framework integration
- Multiple proxy types (SOCKS5, HTTP, Transparent)
- Mobile platform support (iOS, Android)
- Adaptive protocol rotation strategies
- Traffic shaping and timing emulation
- Application profile emulation (Zoom, Netflix, etc.)
- NetFlow evasion techniques
- Comprehensive documentation and whitepaper

### Security Features
- ChaCha20-Poly1305 authenticated encryption
- X25519 key exchange
- Forward secrecy
- Deep packet inspection bypass
- Protocol obfuscation

---

## Migration Guide

### Updating from versions without `server_address` field

If you're using config files without the `server_address` field:

**Before:**
```toml
[socks]
listen_addr = "127.0.0.1:1080"
```

**After:**
```toml
[socks]
listen_addr = "127.0.0.1:1080"
server_address = "your-server.com:8443"  # Add this line
```

**Or** continue using CLI flags:
```bash
nooshdaroo --config client.toml client --server your-server.com:8443
```

### Updating shapeshift strategy format

If using old strategy format:

**Before:**
```toml
[shapeshift.strategy.Fixed]
protocol = "https"
```

**After:**
```toml
[shapeshift.strategy]
type = "fixed"
protocol = "https"
```

---

## Contributors

- Sina Rabbani - Initial development and architecture
- Claude (Anthropic) - Code review and bug fixes

---

## Links

- [GitHub Repository](https://github.com/yourusername/nooshdaroo)
- [Documentation](./README.md)
- [Whitepaper](./WHITEPAPER.md)
- [Security Advisories](./SECURITY.md)
