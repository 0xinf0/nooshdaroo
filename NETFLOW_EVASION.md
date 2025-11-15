# Netflow Evasion Enhancements

## Overview

Nooshdaroo now includes advanced netflow analysis evasion capabilities designed to defeat traffic inspection and correlation attacks. These enhancements make it extremely difficult for network defenders to identify and block proxy traffic.

## Key Features

### 1. Multi-Port Server Architecture

The server now listens on **multiple ports simultaneously**, each mapped to protocol-appropriate ports:

- **HTTPS**: 443, 8443
- **DNS**: 53 (fallback)
- **SSH**: 22, 2222
- **HTTP**: 80, 8080, 8000
- **Email**: SMTP (25, 587, 465), IMAP (143, 993), POP3 (110, 995)
- **VPN**: OpenVPN (1194), WireGuard (51820)
- **Other**: QUIC, WebSocket, FTP, etc.

**Benefits:**
- Traffic appears on expected ports for each protocol
- Reduces suspicion from port-based filtering
- Provides redundancy if certain ports are blocked

### 2. Connection Path Testing & Scoring

Clients automatically test multiple connection paths and select the best based on:

```rust
pub struct PathTestResult {
    pub latency: Duration,        // Connection speed
    pub packet_loss: f64,         // Reliability
    pub throughput: u64,          // Bandwidth
    pub detection_risk: f64,      // Stealth score
}
```

**Scoring Formula:**
```
score = stealth(50%) + reliability(20%) + latency(20%) + throughput(10%)
```

**Testing Strategy:**
1. Test top 10-20 protocol:port combinations
2. Perform 3 connection attempts per path
3. Measure latency, packet loss, and success rate
4. Calculate detection risk based on port/protocol match
5. Sort by composite score
6. Select top 2-3 paths for mixing

### 3. Protocol Mixing Strategies

Instead of using a single protocol, Nooshdaroo **mixes 2+ protocols** to avoid statistical fingerprinting:

#### MixingStrategy::DualRandom
- 70% primary protocol (best scored)
- 30% secondary protocol (second best)
- Random selection per connection

#### MixingStrategy::MultiTemporal
- Changes protocols based on time of day
- Mimics normal user behavior patterns:
  - 0-6 AM: Tertiary protocol (low activity)
  - 7-9 AM: Primary (morning peak)
  - 10-17: Mix of primary/secondary (work hours)
  - 18-22: Secondary (evening)
  - 23-24: Fallback

#### MixingStrategy::VolumeAdaptive
- Rotates protocols every N connections
- Prevents traffic volume correlation

#### MixingStrategy::AdaptiveLearning
- Adjusts mixing ratio based on success rates
- Self-optimizes over time

### 4. DNS Fallback (Port 53)

DNS on port 53 serves as the **universal fallback**:
- Almost never blocked (required for internet)
- Extremely common traffic
- Low suspicion factor
- Works even in highly restrictive networks

### 5. Detection Risk Calculation

```rust
fn calculate_detection_risk(port: u16, protocol: &ProtocolMeta) -> f64 {
    let port_match_bonus = if protocol.default_port == port {
        0.3  // 30% risk reduction
    } else {
        0.0
    };

    let base_risk = 1.0 - protocol.evasion_score();
    let port_risk = match port {
        53 => 0.1,    // DNS - very safe
        80 => 0.1,    // HTTP - very safe
        443 => 0.1,   // HTTPS - very safe
        22 => 0.2,    // SSH - monitored
        1024..=49151 => 0.3,  // Registered
        _ => 0.5,     // Suspicious
    };

    ((base_risk + port_risk) / 2.0 - port_match_bonus).clamp(0.0, 1.0)
}
```

### 6. JSON Structured Logging

All events are logged in JSON format for easy parsing with `jq`:

```json
{
  "timestamp": "2025-11-15T10:24:00Z",
  "level": "INFO",
  "component": "path_tester",
  "message": "Path test result",
  "event_type": "path_test",
  "address": "example.com:443",
  "protocol": "https",
  "latency_ms": 45,
  "success": true,
  "score": 0.87
}
```

**Example jq queries:**

```bash
# Get all successful paths sorted by score
./nooshdaroo test-paths | jq 'select(.success == true) | .score' | sort -rn

# Average latency by protocol
./nooshdaroo run | jq -s 'group_by(.protocol) | map({protocol: .[0].protocol, avg_latency: (map(.latency_ms) | add / length)})'

# Detection risk analysis
./nooshdaroo run | jq 'select(.event_type == "detection_risk") | {protocol, port, risk_score}'
```

### 7. Optional Bootstrap Traceroute

On client startup, optionally perform traceroute to visualize the network path:

```json
{
  "target": "server.example.com:443",
  "protocol": "https",
  "hops": [
    {
      "hop_number": 1,
      "address": "192.168.1.1",
      "rtts": [1.2, 1.3, 1.1],
      "responded": true
    },
    {
      "hop_number": 2,
      "address": "10.0.0.1",
      "rtts": [5.4, 5.2, 5.6],
      "responded": true
    }
  ],
  "hop_count": 12,
  "success": true
}
```

**Configuration:**
```rust
let config = TracerouteConfig {
    enabled: true,  // Disable on mobile
    max_hops: 30,
    timeout_secs: 5,
    probes_per_hop: 3,
    resolve_hostnames: true,
    lookup_asn: false,  // Requires external API
};
```

**Platform Detection:**
- Auto-disabled on iOS/Android (no ICMP permissions)
- Reduced timeout and probes on mobile
- Graceful fallback if unavailable

## Netflow Evasion Techniques

### Defeating Statistical Analysis

1. **Traffic Volume Mixing**
   - Vary connection volumes per protocol
   - Mimic normal application patterns
   - Avoid consistent ratios

2. **Timing Randomization**
   - Random delays between protocol switches
   - Temporal distribution matching real usage
   - Burst avoidance

3. **Port Hopping**
   - Multiple valid ports per protocol
   - Server listens on 10-20 ports
   - Client tests and selects best

### Defeating DPI (Deep Packet Inspection)

1. **Protocol Emulation**
   - Real protocol handshakes
   - Authentic packet structures
   - Timing and size patterns

2. **Port-Protocol Alignment**
   - HTTPS on 443 (not 8080)
   - DNS on 53 (not 5353)
   - SSH on 22 (not 2222)
   - Reduces DPI suspicion

### Defeating Flow Correlation

1. **Connection Diversity**
   - Different protocols to same destination
   - Varying source ports
   - Mixed traffic types

2. **Decoy Traffic**
   - Legitimate connections interspersed
   - Background DNS queries
   - Normal browsing patterns

## Usage Examples

### Server Side

```bash
# Start multi-port server
nooshdaroo server \
  --bind 0.0.0.0 \
  --max-ports 15 \
  --use-standard-ports \
  --use-random-ports \
  --json-logging

# Output (JSON):
{
  "timestamp": "2025-11-15T10:24:00Z",
  "level": "INFO",
  "component": "multiport_server",
  "message": "Multi-port server started",
  "event_type": "server_start",
  "ports": [53, 22, 80, 443, 8080, 8443, ...],
  "protocols": ["dns", "ssh", "http", "https", ...],
  "port_count": 15
}
```

### Client Side

```bash
# Test all paths and auto-select best
nooshdaroo client \
  --server example.com \
  --test-paths \
  --mixing-strategy dual-random \
  --enable-traceroute \
  --json-logging

# Manual path selection
nooshdaroo client \
  --server example.com:443 \
  --protocol https \
  --fallback-protocol dns \
  --fallback-port 53
```

### Monitoring

```bash
# Live connection monitoring
nooshdaroo run | jq -c 'select(.event_type == "connection")'

# Protocol switching analysis
nooshdaroo run | jq 'select(.event_type == "protocol_switch") | {from, to, reason}'

# Traffic statistics
nooshdaroo run | jq 'select(.event_type == "traffic_stats") | {protocol, throughput_mbps, duration_ms}'

# Detection risk over time
nooshdaroo run | jq -c 'select(.event_type == "detection_risk") | {time: .timestamp, protocol, risk_score}'
```

## Configuration

### Full Example

```toml
# nooshdaroo.toml

[multiport]
bind_addr = "0.0.0.0"
port_range = [1, 65535]
max_ports = 20
use_standard_ports = true
use_random_ports = true

[multiport.protocol_ports]
https = [443, 8443]
dns = [53]
ssh = [22, 2222]
http = [80, 8080, 8000]

[mixing]
strategy = "dual-random"  # or: single, multi-temporal, volume-adaptive, adaptive-learning
mixing_ratio = 0.7
rotation_threshold = 100

[path_testing]
enabled = true
timeout_ms = 5000
test_iterations = 3

[traceroute]
enabled = true
max_hops = 30
timeout_secs = 5
probes_per_hop = 3
resolve_hostnames = true
lookup_asn = false

[logging]
format = "json"  # or: text
level = "info"   # debug, info, warn, error
```

## Security Considerations

1. **This is not a replacement for encryption** - Always use strong encryption
2. **Evades detection, not blocking** - Sophisticated adversaries may still block all proxies
3. **Requires operational security** - Don't reveal proxy usage through other means
4. **Mobile limitations** - Some features unavailable without root/permissions
5. **Resource usage** - Multi-port and testing consume more bandwidth/CPU

## Performance Impact

- **Multi-port server**: Minimal overhead (~1-2% CPU per port)
- **Path testing**: 1-5 seconds on startup (one-time)
- **Protocol mixing**: <1ms switching overhead
- **JSON logging**: ~5% slower than binary logging
- **Traceroute**: 5-30 seconds (optional, bootstrap only)

## Future Enhancements

1. **Machine Learning**: Auto-detect optimal protocols per network
2. **Traffic Shaping**: Mimic specific application patterns
3. **Peer Discovery**: Distributed server discovery
4. **Bandwidth Optimization**: Adaptive quality based on connection
5. **Censorship Resistance**: Active evasion of blocking

## References

- See `src/netflow_evasion.rs` for implementation
- See `src/multiport_server.rs` for multi-port server
- See `src/json_logger.rs` for structured logging
- See `src/traceroute.rs` for path tracing

---

**Nooshdaroo** - The antidote to network surveillance
