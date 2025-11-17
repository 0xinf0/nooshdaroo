# Proposal: Full TLS Session Emulation for Nooshdaroo

## Executive Summary

Currently, Nooshdaroo only wraps the Noise Protocol handshake in TLS/HTTPS format, leaving subsequent data frames as raw length-prefixed encrypted payloads. This proposal outlines the implementation of **full TLS session emulation** to wrap all traffic in proper TLS 1.3 Application Data records, providing complete protocol obfuscation throughout the entire connection lifecycle.

## Current State Analysis

### What Works Now
- ✅ Noise Protocol provides strong end-to-end encryption
- ✅ Initial handshake wrapped in TLS ClientHello/ServerHello (PSF-based)
- ✅ Passes initial DPI classification as HTTPS
- ✅ Multiple protocol emulations available (HTTPS, DNS, SSH, etc.)

### Current Limitations
- ❌ **Data frames exposed**: After handshake, traffic is raw Noise frames with 2-byte length prefix
- ❌ **Session analysis fails**: DPI with session inspection sees non-TLS record structure
- ❌ **Wireshark detection**: Traffic classified as "TCP" instead of "TLS" after handshake
- ❌ **Pattern analysis vulnerable**: Length-prefix pattern (2-byte big-endian) is distinctive
- ❌ **No TLS features**: Missing ChangeCipherSpec, Application Data records, alerts, etc.

### Security Implications
```
[Current Flow]
Client -> Server: TLS ClientHello (PSF wrapped)     ✅ Looks like HTTPS
Server -> Client: TLS ServerHello (PSF wrapped)     ✅ Looks like HTTPS
Client <-> Server: [len][noise_data][len][noise_data]... ❌ DETECTED: Not TLS!
```

Modern DPI systems:
- **Checkpoint, Palo Alto, Fortinet**: Perform full session reconstruction
- **Deep Packet Inspection**: Analyze entire flow, not just first packet
- **Behavioral analysis**: Detect anomalous patterns in "TLS" sessions
- **Statistical analysis**: Measure entropy, timing, packet sizes

## Proposed Solution: Full TLS 1.3 Record Layer Emulation

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Data                          │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│              Noise Protocol Encryption                       │
│  (Maintains current strong cryptographic guarantees)         │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│           TLS 1.3 Record Layer Wrapper (NEW)                 │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Record Header (5 bytes)                              │   │
│  │ - Content Type (0x17 = Application Data)            │   │
│  │ - TLS Version (0x0303 = TLS 1.2 for compatibility)  │   │
│  │ - Length (2 bytes)                                   │   │
│  ├─────────────────────────────────────────────────────┤   │
│  │ Encrypted Payload (Noise encrypted data)             │   │
│  ├─────────────────────────────────────────────────────┤   │
│  │ Optional: TLS 1.3 Padding                            │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
                  TCP Socket
```

### Implementation Phases

#### Phase 1: Core TLS Record Layer (2-3 days)
**Scope**: Implement basic TLS 1.3 record wrapping/unwrapping

**New Module**: `src/tls_record_layer.rs`

```rust
/// TLS 1.3 Record Layer implementation for protocol obfuscation
pub struct TlsRecordLayer {
    /// Maximum TLS record size (16KB per RFC 8446)
    max_record_size: usize,

    /// Fragment large payloads across multiple records
    fragmentation_enabled: bool,

    /// Add random padding to records (TLS 1.3 feature)
    padding_strategy: PaddingStrategy,

    /// Statistics for realistic timing
    stats: TlsStats,
}

pub enum PaddingStrategy {
    None,
    Random { min: usize, max: usize },
    Traffic { target_size: usize },
}

impl TlsRecordLayer {
    /// Wrap Noise encrypted data in TLS Application Data record
    pub fn wrap_application_data(&self, noise_payload: &[u8]) -> Vec<u8>;

    /// Unwrap TLS record and extract Noise encrypted data
    pub fn unwrap_application_data(&self, tls_record: &[u8]) -> Result<Vec<u8>>;

    /// Fragment large payloads into multiple TLS records
    pub fn fragment_payload(&self, payload: &[u8]) -> Vec<Vec<u8>>;

    /// Generate TLS alert for graceful shutdown
    pub fn generate_alert(&self, alert: TlsAlert) -> Vec<u8>;
}
```

**TLS Record Structure**:
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |   Version     |            Length             |
|    (0x17)     |   (0x0303)    |         (2 bytes)             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|             Encrypted Payload (Noise data)                    |
|                         ...                                   |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Optional Padding                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Key Features**:
- TLS record type: `0x17` (Application Data)
- Legacy version: `0x0303` (TLS 1.2 for compatibility)
- Max record size: 16,384 bytes (RFC 8446 §5.1)
- Fragmentation: Split large Noise frames across multiple TLS records
- Padding: Add random padding to defeat traffic analysis

#### Phase 2: Integration with NoiseTransport (1-2 days)
**Scope**: Modify NoiseTransport to use TLS record layer for all I/O

**Modified**: `src/noise_transport.rs`

```rust
pub struct NoiseTransport {
    transport: TransportState,
    read_buffer: Vec<u8>,
    write_buffer: Vec<u8>,

    // NEW: TLS record layer wrapper
    tls_layer: Option<TlsRecordLayer>,
}

impl NoiseTransport {
    /// Write data with full TLS record wrapping
    pub async fn write<S>(
        &mut self,
        stream: &mut S,
        data: &[u8]
    ) -> Result<()>
    where
        S: AsyncWrite + Unpin,
    {
        // Step 1: Noise encrypt the payload
        let noise_len = self.transport.write_message(data, &mut self.write_buffer)?;
        let noise_payload = &self.write_buffer[..noise_len];

        // Step 2: Wrap in TLS record (NEW)
        if let Some(ref tls) = self.tls_layer {
            let tls_records = tls.fragment_payload(noise_payload);
            for record in tls_records {
                stream.write_all(&record).await?;
            }
        } else {
            // Fallback: Original length-prefix method
            Self::write_message(stream, noise_payload).await?;
        }

        Ok(())
    }

    /// Read data with full TLS record unwrapping
    pub async fn read<S>(
        &mut self,
        stream: &mut S
    ) -> Result<Vec<u8>>
    where
        S: AsyncRead + Unpin,
    {
        // Step 1: Read TLS record (NEW)
        let noise_payload = if let Some(ref tls) = self.tls_layer {
            tls.read_application_data(stream).await?
        } else {
            // Fallback: Original length-prefix method
            Self::read_message(stream, &mut self.read_buffer).await?.to_vec()
        };

        // Step 2: Noise decrypt the payload
        let len = self.transport.read_message(&noise_payload, &mut self.read_buffer)?;
        Ok(self.read_buffer[..len].to_vec())
    }
}
```

#### Phase 3: Enhanced TLS Features (2-3 days)
**Scope**: Add TLS session management features for deeper emulation

**Features**:

1. **TLS Alerts**
   ```rust
   pub enum TlsAlert {
       CloseNotify,           // Graceful shutdown
       UnexpectedMessage,     // Protocol error
       BadRecordMac,          // Integrity failure
       RecordOverflow,        // Too large record
       HandshakeFailure,      // Negotiation failed
   }
   ```

2. **ChangeCipherSpec**
   - Send between handshake and Application Data
   - Makes session look more authentic to DPI

3. **Heartbeat Extension (Optional)**
   - Periodic keep-alive messages
   - Mimics real TLS sessions

4. **Session Tickets (Optional)**
   - Fake TLS session resumption
   - Advanced DPI evasion

#### Phase 4: Traffic Shaping Integration (1-2 days)
**Scope**: Integrate with existing TrafficShaper for realistic TLS behavior

```rust
pub struct TlsTrafficProfile {
    /// Typical TLS record sizes from real HTTPS traffic
    record_size_distribution: Vec<(usize, f64)>,  // (size, probability)

    /// Inter-record timing (milliseconds)
    timing_profile: TimingProfile,

    /// Burst patterns (e.g., video streaming, file download)
    burst_behavior: BurstBehavior,
}

impl TlsRecordLayer {
    /// Shape traffic to match real TLS patterns
    pub fn apply_traffic_profile(&mut self, profile: &TlsTrafficProfile) {
        // Adjust record sizes to match distribution
        // Add timing delays between records
        // Implement burst patterns
    }
}
```

**Real-world TLS patterns to emulate**:
- **HTTPS browsing**: Small records (200-1500 bytes), bursty
- **Video streaming**: Large records (16KB), steady stream
- **File download**: Maximum size records (16KB), continuous
- **API calls**: Medium records (1-8KB), request-response pattern

#### Phase 5: Testing & Validation (2-3 days)

**Test Suite**:

1. **Unit Tests**
   ```bash
   cargo test tls_record_layer
   ```
   - Record wrapping/unwrapping correctness
   - Fragmentation logic
   - Padding strategies
   - Alert generation

2. **Integration Tests**
   ```bash
   cargo test --test tls_emulation
   ```
   - End-to-end encrypted session
   - Large file transfers
   - Connection interruption/recovery
   - Graceful shutdown with alerts

3. **DPI Detection Tests**
   ```bash
   ./test_tls_emulation_ndpi.sh
   ```
   - **nDPI validation**: Must classify as TLS.SSL
   - **Wireshark validation**: Must show as TLS protocol
   - **Session reconstruction**: Full TLS session visible

4. **Protocol Conformance**
   ```bash
   tshark -r capture.pcap -Y "tls" -T fields -e tls.record.content_type
   ```
   - Verify all records are type 0x17 (Application Data)
   - Check record sizes within RFC limits
   - Validate TLS version bytes

5. **Performance Benchmarks**
   ```bash
   cargo bench --bench tls_overhead
   ```
   - Measure wrapping/unwrapping overhead
   - Compare throughput: baseline vs TLS-wrapped
   - Memory usage analysis
   - Latency impact measurement

**Expected Results**:
- ✅ nDPI: `TLS.SSL` classification
- ✅ Wireshark: Shows as TLS protocol throughout session
- ✅ Throughput: <5% overhead vs current implementation
- ✅ Latency: <1ms additional per record
- ✅ Memory: <100KB additional per connection

### Configuration Interface

**New Config Section**: `nooshdaroo.toml`

```toml
[tls_emulation]
# Enable full TLS session emulation
enabled = true

# TLS version to emulate (for record headers)
version = "1.2"  # Options: "1.2", "1.3"

# Maximum record size (bytes, RFC max: 16384)
max_record_size = 16384

# Fragmentation strategy
fragmentation = "auto"  # Options: "auto", "fixed", "random"

# Padding strategy for traffic analysis resistance
[tls_emulation.padding]
enabled = true
min_bytes = 0
max_bytes = 256
strategy = "random"  # Options: "none", "random", "traffic-shaping"

# Traffic profile emulation
[tls_emulation.traffic_profile]
enabled = true
profile = "https-browsing"  # Options: "https-browsing", "video-stream", "file-download", "api-calls"

# TLS features
[tls_emulation.features]
send_alerts = true          # Send TLS alerts on errors/shutdown
heartbeat = false           # Periodic heartbeat messages (optional)
session_tickets = false     # Fake session resumption (optional)
```

**Backward Compatibility**:
```toml
[tls_emulation]
# Disabled by default - opt-in feature
enabled = false

# When disabled, falls back to current length-prefix behavior
```

### Migration Path

**Phase 1: Parallel Implementation** (Weeks 1-2)
- Implement TLS record layer alongside existing code
- No breaking changes
- Feature flag: `--enable-tls-emulation`

**Phase 2: Testing & Validation** (Week 3)
- Extensive testing with real-world scenarios
- Performance benchmarking
- DPI validation (nDPI, Wireshark, Suricata)

**Phase 3: Gradual Rollout** (Week 4)
- Default: OFF (backward compatible)
- Documentation for early adopters
- Collect feedback

**Phase 4: Make Default** (Week 5+)
- Enable by default after validation
- Keep fallback option for debugging
- Remove old code in v1.0

## Technical Challenges & Solutions

### Challenge 1: Performance Overhead
**Problem**: TLS record wrapping adds CPU overhead and larger packet sizes

**Solution**:
- **Zero-copy design**: Wrap in-place when possible
- **Buffer pooling**: Reuse buffers to reduce allocations
- **Batching**: Combine multiple writes into single TLS record
- **Benchmarking target**: <5% throughput impact

### Challenge 2: Fragmentation Complexity
**Problem**: Large Noise frames must be split across multiple TLS records

**Solution**:
```rust
// Smart fragmentation algorithm
fn fragment_noise_frame(noise_data: &[u8]) -> Vec<TlsRecord> {
    let mut records = Vec::new();
    let mut offset = 0;

    while offset < noise_data.len() {
        // Vary record sizes to look natural
        let record_size = calculate_realistic_size(noise_data.len() - offset);
        let chunk = &noise_data[offset..offset + record_size];

        records.push(TlsRecord::application_data(chunk));
        offset += record_size;
    }

    records
}

fn calculate_realistic_size(remaining: usize) -> usize {
    // Use traffic profile distribution
    // Avoid suspicious patterns (all same size)
    // Respect TLS max record size (16KB)
}
```

### Challenge 3: Noise + TLS Layering
**Problem**: Two encryption layers seems redundant

**Clarification**:
- **Noise Protocol**: Provides actual encryption/authentication
- **TLS Records**: Provides protocol obfuscation only
- TLS wrapping does NOT re-encrypt (just framing)

```
[Application Data]
       ↓
[Noise Encrypt] ← Real encryption happens here
       ↓
[TLS Record Wrap] ← Just adds 5-byte header (no encryption)
       ↓
   [Network]
```

### Challenge 4: Connection Lifecycle
**Problem**: TLS has specific shutdown sequence

**Solution**:
```rust
impl NoiseTransport {
    /// Graceful TLS shutdown
    pub async fn shutdown<S>(&mut self, stream: &mut S) -> Result<()> {
        if let Some(ref tls) = self.tls_layer {
            // Send close_notify alert
            let alert = tls.generate_alert(TlsAlert::CloseNotify);
            stream.write_all(&alert).await?;

            // Wait for peer's close_notify (with timeout)
            let _ = timeout(Duration::from_secs(5),
                tls.read_application_data(stream)).await;
        }

        Ok(())
    }
}
```

### Challenge 5: Error Handling
**Problem**: TLS errors vs Noise errors vs network errors

**Solution**:
```rust
pub enum TransportError {
    // Noise Protocol errors
    NoiseHandshakeFailed(String),
    NoiseDecryptionFailed(String),

    // TLS layer errors
    TlsInvalidRecord(String),
    TlsFragmentationError(String),
    TlsAlertReceived(TlsAlert),

    // Network errors
    IoError(std::io::Error),
    ConnectionClosed,
}
```

## Performance Analysis

### Overhead Calculation

**Current Implementation**:
```
Noise frame: [2-byte length][encrypted_payload]
Overhead: 2 bytes per message
```

**Proposed TLS Implementation**:
```
TLS record: [5-byte header][encrypted_payload][0-256 bytes padding]
Overhead: 5-261 bytes per record (avg: ~50 bytes with random padding)
```

**Impact Analysis**:

| Metric | Current | With TLS | Overhead |
|--------|---------|----------|----------|
| Header size | 2 bytes | 5 bytes | +3 bytes |
| Padding (avg) | 0 bytes | 50 bytes | +50 bytes |
| **Total per 1KB payload** | 2 bytes (0.2%) | 55 bytes (5.4%) | +5.2% |
| **Total per 16KB payload** | 2 bytes (0.01%) | 55 bytes (0.3%) | +0.3% |

**Throughput Impact**:
- Small messages (1KB): ~5% overhead
- Large messages (16KB): <1% overhead
- **Bulk transfers**: Negligible impact

**CPU Impact**:
- TLS wrapping: ~100ns per record (modern CPU)
- Fragmentation: ~1µs per 16KB payload
- **Total**: <0.1% CPU overhead for typical workloads

### Memory Footprint

**Per Connection**:
```
Current:
  read_buffer: 65KB
  write_buffer: 65KB + 16 bytes
  Total: ~130KB

With TLS:
  read_buffer: 65KB
  write_buffer: 65KB + 16 bytes
  tls_read_buffer: 16KB (max record size)
  tls_write_buffer: 16KB
  Total: ~162KB (+24%)
```

**Impact**: +32KB per connection (acceptable for modern systems)

## Security Considerations

### Threat Model

**What TLS Emulation Protects Against**:
- ✅ **Passive DPI**: Protocol identification, session classification
- ✅ **Active DPI**: Deep packet inspection, payload analysis
- ✅ **Statistical analysis**: Traffic patterns, timing analysis
- ✅ **Protocol fingerprinting**: TLS version detection, cipher suite analysis

**What TLS Emulation Does NOT Protect Against**:
- ❌ **Certificate validation**: We're not doing real TLS handshake
- ❌ **Active MitM**: Attacker can still see it's not real TLS if they intercept
- ❌ **Side channels**: Timing attacks, traffic analysis still possible

### Defense in Depth

TLS emulation is **one layer** in a defense-in-depth strategy:

```
Layer 1: Noise Protocol (cryptographic security)
Layer 2: TLS Emulation (protocol obfuscation)
Layer 3: Traffic Shaping (behavioral obfuscation)
Layer 4: Protocol Switching (adaptive evasion)
Layer 5: Multi-hop Routing (attribution resistance)
```

### Cryptographic Notes

**Important**: TLS record layer is NOT providing encryption
- Noise Protocol provides all cryptographic security
- TLS wrapping is purely cosmetic (protocol mimicry)
- Security depends entirely on Noise Protocol implementation

**No reduction in security**:
- Same cryptographic guarantees as current implementation
- No additional attack surface (just framing)
- Noise keys/handshake unchanged

## Success Metrics

### Technical Metrics
- ✅ **DPI Detection**: nDPI classifies as TLS.SSL (not TCP/Unknown)
- ✅ **Wireshark Display**: Shows TLS protocol in packet list
- ✅ **Session Reconstruction**: Full TLS session visible in analysis
- ✅ **Performance**: <5% throughput degradation
- ✅ **Memory**: <50MB additional for 1000 concurrent connections

### Operational Metrics
- ✅ **Backward Compatibility**: No breaking changes for existing deployments
- ✅ **Configuration**: Simple on/off toggle in config file
- ✅ **Documentation**: Clear migration guide
- ✅ **Testing**: >95% code coverage for new TLS module

### Evasion Metrics
- ✅ **Commercial DPI**: Tested against Checkpoint, Palo Alto, Fortinet
- ✅ **Open Source DPI**: Passes Suricata, Zeek, nDPI
- ✅ **Statistical Analysis**: Entropy, timing, size distributions match real TLS

## Timeline & Resources

### Development Timeline

| Phase | Duration | Developer Days | Deliverables |
|-------|----------|----------------|--------------|
| 1. Core TLS Record Layer | 2-3 days | 3 days | `src/tls_record_layer.rs`, unit tests |
| 2. NoiseTransport Integration | 1-2 days | 2 days | Modified `noise_transport.rs`, integration tests |
| 3. Enhanced TLS Features | 2-3 days | 3 days | Alerts, ChangeCipherSpec, graceful shutdown |
| 4. Traffic Shaping Integration | 1-2 days | 2 days | TLS traffic profiles |
| 5. Testing & Validation | 2-3 days | 3 days | Full test suite, DPI validation |
| 6. Documentation | 1 day | 1 day | Migration guide, config examples |
| **Total** | **~2 weeks** | **14 days** | Production-ready TLS emulation |

### Resource Requirements

**Developer Skills**:
- Rust async programming (Tokio)
- TLS protocol knowledge (RFC 8446)
- Network protocol analysis (Wireshark)
- DPI evasion techniques

**Testing Infrastructure**:
- Wireshark/tshark for protocol validation
- nDPI for classification testing
- Network simulator for performance testing
- Commercial DPI appliances (optional, for validation)

## Alternatives Considered

### Alternative 1: Use Real TLS Library (rustls/openssl)
**Pros**:
- Full TLS implementation
- Certificate validation
- Industry standard

**Cons**:
- ❌ Adds complexity (cert management)
- ❌ Performance overhead (double encryption)
- ❌ Larger attack surface
- ❌ Not flexible for obfuscation
- ❌ Defeats purpose of Noise Protocol

**Decision**: Rejected - overengineered for our use case

### Alternative 2: HTTP/2 Framing
**Pros**:
- More modern protocol
- Better multiplexing

**Cons**:
- ❌ More complex than TLS records
- ❌ Requires HPACK compression
- ❌ Less universal support
- ❌ Still needs TLS underneath

**Decision**: Rejected - TLS is simpler and more universal

### Alternative 3: QUIC/UDP
**Pros**:
- Modern transport
- Built-in encryption

**Cons**:
- ❌ Major architecture change (TCP → UDP)
- ❌ Complex protocol
- ❌ May be blocked by firewalls
- ❌ Out of scope for this proposal

**Decision**: Rejected - consider for future work

### Alternative 4: Custom Protocol Obfuscation
**Pros**:
- Maximum flexibility
- Optimized for Nooshdaroo

**Cons**:
- ❌ Easy to fingerprint (unique to Nooshdaroo)
- ❌ No real-world traffic to blend into
- ❌ Higher development cost
- ❌ Harder to validate

**Decision**: Rejected - TLS mimicry is better strategy

## Future Enhancements

### Post-MVP Features

1. **TLS 1.3 0-RTT Resumption**
   - Fake session tickets
   - Faster reconnection appearance
   - Advanced DPI evasion

2. **ALPN Protocol Negotiation**
   - Advertise HTTP/2, HTTP/3 in handshake
   - More realistic TLS sessions
   - Protocol switching signals

3. **TLS Extension Randomization**
   - Vary extensions to avoid fingerprinting
   - Mimic different TLS clients (browsers, apps)
   - User-agent emulation

4. **Encrypted SNI (ESNI)**
   - Hide destination hostname
   - Additional privacy layer
   - Censorship resistance

5. **Multi-Protocol Sessions**
   - Start with TLS, switch to HTTP/2 framing
   - Long-lived connections with protocol evolution
   - Deeper behavioral mimicry

## Conclusion

Full TLS session emulation is a **high-value, medium-complexity** enhancement that significantly improves Nooshdaroo's DPI evasion capabilities. By wrapping all traffic in proper TLS records, we achieve:

1. **Complete protocol mimicry**: Entire session looks like HTTPS
2. **DPI resistance**: Passes deep packet inspection
3. **Minimal overhead**: <5% performance impact
4. **Backward compatible**: Opt-in feature, no breaking changes
5. **Production ready**: 2-week implementation timeline

**Recommendation**: ✅ **APPROVE** - Implement in next development cycle

The benefits significantly outweigh the costs, and the feature can be delivered incrementally without disrupting existing deployments.

---

## Appendix A: TLS Record Format Reference

```
TLS Record Format (RFC 8446 §5.1):

struct {
    ContentType type;           // 1 byte  (0x17 = application_data)
    ProtocolVersion legacy_record_version;  // 2 bytes (0x0303 = TLS 1.2)
    uint16 length;              // 2 bytes (max 2^14 = 16384)
    opaque fragment[TLSPlaintext.length];
} TLSPlaintext;

Content Types:
  - 0x14: change_cipher_spec
  - 0x15: alert
  - 0x16: handshake
  - 0x17: application_data ← We use this
  - 0x18: heartbeat (optional)
```

## Appendix B: Example Wireshark Capture

**Before (Current Implementation)**:
```
Frame 1: TCP [SYN]
Frame 2: TCP [SYN, ACK]
Frame 3: TCP [ACK]
Frame 4: TLS Client Hello (PSF wrapped handshake)
Frame 5: TLS Server Hello (PSF wrapped handshake)
Frame 6: TCP Data [Unknown protocol] ← DPI FAILS HERE
Frame 7: TCP Data [Unknown protocol]
...
```

**After (Full TLS Emulation)**:
```
Frame 1: TCP [SYN]
Frame 2: TCP [SYN, ACK]
Frame 3: TCP [ACK]
Frame 4: TLS Client Hello (PSF wrapped handshake)
Frame 5: TLS Server Hello (PSF wrapped handshake)
Frame 6: TLS Application Data ← LOOKS LIKE HTTPS
Frame 7: TLS Application Data ← LOOKS LIKE HTTPS
Frame 8: TLS Application Data ← LOOKS LIKE HTTPS
...
Frame N: TLS Alert (close_notify)
```

## Appendix C: Code Size Estimate

```
src/tls_record_layer.rs         ~800 lines
src/noise_transport.rs changes   ~200 lines (modifications)
tests/tls_emulation_tests.rs    ~400 lines
benches/tls_overhead.rs         ~200 lines
docs/TLS_EMULATION.md           ~300 lines
Total new code:                ~1,900 lines
```

Estimated impact: +5% to codebase size (currently ~38,000 lines)

---

**Document Version**: 1.0
**Date**: 2025-11-17
**Author**: Claude (Anthropic)
**Status**: PROPOSAL - Pending Review
