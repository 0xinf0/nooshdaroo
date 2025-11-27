# nQUIC Implementation Status

## Overview
nQUIC (Noise-based QUIC) for Nooshdaroo DNS tunneling - replacing TLS 1.3 with Noise Protocol IK pattern.

**Target:** 60% header overhead reduction (24 bytes vs 59 bytes compared to dnstt)

## Completed ✓

### 1. Module Structure (9 files, ~1,500 lines)
```
src/nquic/
├── mod.rs                      # Main module, constants (NQUIC_HEADER_OVERHEAD = 24)
├── crypto/
│   ├── mod.rs                  # Crypto exports
│   ├── config.rs               # NoiseConfig (IK pattern)
│   ├── keys.rs                 # BLAKE2s HKDF (Noise → QUIC keys)
│   ├── noise_session.rs        # Core handshake logic (~310 lines)
│   └── quinn_crypto.rs         # Quinn integration (~330 lines)
├── dns/
│   ├── codec.rs                # Base32 queries, TXT responses
│   └── transport.rs            # Dual UDP:53/TCP:53 placeholder
└── endpoint.rs                 # nQUIC endpoint placeholder
```

### 2. Key Components
- **NoiseSession**: Handshake state management, key derivation framework
- **NoiseKeypair Integration**: Extended existing X25519 keys for IK pattern
- **BLAKE2s HKDF**: Framework for deriving QUIC keys from Noise outputs
- **Quinn Traits**: PacketKey, HeaderKey implementations (placeholders)
- **DNS Codec**: Base32 encoding for queries, raw bytes for TXT responses

### 3. Build Status
- ✅ All code compiles successfully
- ✅ No errors, only expected warnings for unused code
- ✅ Dependencies added: quinn 0.11, quinn-proto 0.11, ring 0.17

## Remaining Work

### Critical Path Items

#### 1. Quinn Session Trait (High Priority)
**File:** `src/nquic/crypto/quinn_crypto.rs`

Implement `quinn_proto::crypto::Session` for `NoiseQuinnSession`:
```rust
impl quinn_proto::crypto::Session for NoiseQuinnSession {
    // Required methods from Quinn 0.11.x API
    // Need to research exact trait definition
}
```

**Research Needed:** Quinn 0.11.x Session trait API surface

#### 2. Snow CK/HS Extraction (Blocker)
**File:** `src/nquic/crypto/noise_session.rs:152-155`

Current placeholder:
```rust
let ck = vec![0u8; 32]; // TODO: Extract from Snow
let hs_hash = vec![0u8; 32]; // TODO: Extract from Snow
```

**Challenge:** Snow 0.9.x doesn't expose internal state (CK, HS) directly
**Options:**
- Fork Snow and expose needed fields
- Use alternative: `noise-protocol` crate
- Implement custom Noise handshake

#### 3. ChaCha20-Poly1305 AEAD
**File:** `src/nquic/crypto/quinn_crypto.rs:19-54`

```rust
impl PacketKey for NoisePacketKey {
    fn encrypt(&self, packet_number: u64, buf: &mut [u8], header_len: usize) {
        // TODO: Use ring::aead::ChaCha20Poly1305
        // Nonce = IV XOR packet_number
        // ring::aead::seal_in_place(...)
    }

    fn decrypt(...) -> Result<(), CryptoError> {
        // TODO: ring::aead::open_in_place(...)
    }
}
```

**Dependencies:** `ring = "0.17"` (already added)

#### 4. Header Protection
**File:** `src/nquic/crypto/quinn_crypto.rs:75-93`

```rust
impl HeaderKey for NoiseHeaderKey {
    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        // TODO: ChaCha20 for header protection
        // Sample: packet[pn_offset + 4..pn_offset + 20]
    }

    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        // TODO: ChaCha20 header deprotection
    }
}
```

#### 5. DNS Transport Layer
**File:** `src/nquic/dns/transport.rs`

Implement dual DNS transport:
- UDP:53 for queries/responses
- TCP:53 for fragmented packets
- Connection multiplexing
- Packet fragmentation/reassembly

### Secondary Features

#### 6. Integration with Existing Keys
Ensure nQUIC uses existing `noise_transport.rs` key infrastructure

#### 7. Testing Suite
- Unit tests for key derivation
- Integration tests for handshake
- PFS verification
- Connection migration tests
- Multipath QUIC tests

#### 8. Performance Benchmarks
Compare vs current KCP implementation:
- Latency
- Throughput
- Overhead per packet
- CPU usage

## Technical Decisions Made

1. **Noise Pattern:** IK (Identity Known) - server's static key known to client
2. **Crypto Suite:** ChaCha20-Poly1305 + BLAKE2s (matches existing Noise transport)
3. **Key Derivation:** BLAKE2s-based HKDF adapting QUIC TLS patterns
4. **DNS Encoding:** Base32 for queries (63-char labels), raw bytes for TXT responses
5. **Quinn Version:** 0.11.x (latest stable)

## Known Limitations

### Current Placeholders
1. **Encryption/Decryption:** NoisePacketKey encrypt/decrypt are stubs
2. **Header Protection:** NoiseHeaderKey operations are stubs
3. **Key Extraction:** Cannot extract CK/HS from Snow's internal state
4. **Session Trait:** quinn_proto::crypto::Session not implemented
5. **DNS Transport:** Dual UDP/TCP not implemented

### Architectural TODOs
1. Map Noise handshake phases to QUIC encryption levels:
   - Initial keys from connection ID
   - Handshake keys from Noise handshake
   - Application keys from Noise transport
2. Implement key update mechanism for PFS
3. Handle connection migration (QUIC feature)
4. Support multipath QUIC

## Next Immediate Steps

1. **Research Quinn Session API**
   - Generate docs: `cargo doc --package quinn-proto --open`
   - Study trait requirements
   - Understand encryption level mapping

2. **Solve Snow CK/HS Extraction**
   - Evaluate `noise-protocol` crate as alternative
   - Consider forking Snow
   - Or implement minimal Noise IK manually

3. **Implement Ring-based Encryption**
   - ChaCha20-Poly1305 in NoisePacketKey
   - ChaCha20 in NoiseHeaderKey
   - Test vectors for validation

4. **Complete Session Integration**
   - Implement all required Session methods
   - Handle QUIC encryption levels
   - Test with actual Quinn endpoint

## File Reference

**Main Implementation:**
- `src/nquic/mod.rs` - Module definition
- `src/nquic/crypto/noise_session.rs` - Core crypto logic
- `src/nquic/crypto/quinn_crypto.rs` - Quinn integration
- `src/nquic/crypto/keys.rs` - Key derivation

**Configuration:**
- `src/nquic/crypto/config.rs` - NoiseConfig
- `Cargo.toml` - Dependencies

**Encoding:**
- `src/nquic/dns/codec.rs` - DNS packet encoding

## Build Commands

```bash
# Build library
cargo build --lib

# Generate documentation
cargo doc --package quinn-proto --open

# Run tests (when implemented)
cargo test --package nooshdaroo --lib nquic

# Check compilation
cargo check --lib
```

## Success Criteria

- [ ] Complete Noise IK handshake between client/server
- [ ] Derive proper QUIC keys from Noise outputs
- [ ] Encrypt/decrypt QUIC packets with ChaCha20-Poly1305
- [ ] Protect/deprotect QUIC headers
- [ ] Successfully establish nQUIC connection over DNS
- [ ] Verify 24-byte header overhead
- [ ] Achieve <100ms handshake latency
- [ ] Match or exceed KCP throughput

---

**Status:** Foundation complete, crypto implementation 30% done
**Blockers:** Snow CK/HS extraction, Quinn Session trait research
**Next:** Implement ChaCha20-Poly1305 encryption layer
