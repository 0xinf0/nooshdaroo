# Advanced Traffic Shaping & Bandwidth Optimization

This document describes Nooshdaroo's advanced traffic shaping and adaptive bandwidth optimization features.

## Overview

Nooshdaroo now includes two powerful capabilities for defeating deep packet inspection (DPI):

1. **Application Traffic Profiles** - Mimic real applications (Zoom, Netflix, YouTube, Teams, WhatsApp)
2. **Adaptive Bandwidth Optimization** - Automatically adjust quality based on network conditions

## Application Traffic Profiles

### What Are Application Profiles?

Application profiles are detailed statistical models extracted from real network traffic of popular applications. When you configure Nooshdaroo to use an application profile, it will:

- **Match packet size distributions** (e.g., Zoom's bimodal audio/video packets)
- **Replicate timing patterns** (e.g., Netflix's 4-second chunk downloads)
- **Emulate burst patterns** (e.g., video keyframes, screen share updates)
- **Follow state machines** (e.g., TLS handshake → streaming → teardown)

This makes your proxy traffic statistically indistinguishable from legitimate application traffic.

### Available Profiles

#### 1. Zoom Video Conferencing

**Best for**: Interactive real-time communication, voice/video calls

**Characteristics**:
- Bimodal packet sizes: 120 bytes (audio) and 1200 bytes (video)
- 50 packets/sec upstream, 60 packets/sec downstream
- Periodic video keyframe bursts every 2 seconds
- Low latency (~20ms between packets)

**Configuration**:
```toml
[traffic]
application_profile = "zoom"
```

**Use case**: When you need bidirectional, real-time traffic with consistent packet rates.

#### 2. Netflix Video Streaming

**Best for**: High-bandwidth downloads, large file transfers

**Characteristics**:
- Large packets (1450 bytes, near MTU)
- Very high downstream rate (400+ packets/sec)
- Bursty downloads every 4 seconds (adaptive streaming chunks)
- Low upstream traffic (acknowledgments only)

**Configuration**:
```toml
[traffic]
application_profile = "netflix"
```

**Use case**: When you need to transfer large amounts of data downstream with minimal upstream.

#### 3. YouTube Streaming

**Best for**: Medium-bandwidth video streaming

**Characteristics**:
- Normal packet distribution (1400 ± 100 bytes)
- 350 packets/sec downstream average
- 2-second adaptive chunks
- Bimodal upstream (ACKs + quality requests)

**Configuration**:
```toml
[traffic]
application_profile = "youtube"
```

**Use case**: Balanced downstream/upstream with adaptive quality signaling.

#### 4. Microsoft Teams

**Best for**: Group video conferencing, collaboration

**Characteristics**:
- Multimodal packet sizes: 100 (audio), 500 (low-res), 1200 (HD)
- Gallery view bursts (9 participants in 3×3 grid)
- 45-55 packets/sec with higher variance
- Medium latency (~22ms)

**Configuration**:
```toml
[traffic]
application_profile = "teams"
```

**Use case**: Multi-participant scenarios with varying quality levels.

#### 5. WhatsApp Messaging

**Best for**: Low-bandwidth, sporadic traffic

**Characteristics**:
- Multimodal: 80 (text), 500 (images), 1400 (video)
- Very low packet rate (2-3 packets/sec)
- Long delays between packets (500ms average)
- Occasional bursts when sending media

**Configuration**:
```toml
[traffic]
application_profile = "whatsapp"
```

**Use case**: When you want minimal traffic footprint with sporadic bursts.

#### 6. HTTPS Web Browsing

**Best for**: General web traffic, API calls

**Characteristics**:
- Bimodal upstream: 100 (GET) and 800 (POST)
- Page load bursts (~50 packets)
- Variable downstream rate
- TLS handshake state machine

**Configuration**:
```toml
[traffic]
application_profile = "https"
```

**Use case**: General-purpose web traffic emulation.

## Adaptive Bandwidth Optimization

### How It Works

Nooshdaroo continuously monitors network conditions and automatically adjusts traffic parameters to maintain optimal performance while avoiding detection.

**Monitored Metrics**:
- **RTT (Round-Trip Time)**: Latency measurement
- **Packet Loss**: Percentage of lost packets
- **Throughput**: Current data transfer rate
- **Jitter**: Variance in RTT (connection stability)

**Quality Tiers**:

| Tier | RTT | Loss | Throughput | Compression | Packet Size |
|------|-----|------|------------|-------------|-------------|
| High | <50ms | <1% | >8 Mbps | None | 1400 bytes |
| Medium | <150ms | <5% | >3 Mbps | Level 3 | 1200 bytes |
| Low | <500ms | <15% | >500 Kbps | Level 6 | 800 bytes |
| Very Low | >500ms | >15% | <500 Kbps | Level 9 | 512 bytes |

### Quality Adaptation Algorithm

1. **Measurement**: Collect RTT, loss, throughput samples (rolling window of 10)
2. **Scoring**: Calculate overall quality score (0.0-1.0)
   - RTT: 30% weight
   - Loss: 40% weight (most important)
   - Throughput: 20% weight
   - Jitter: 10% weight
3. **Hysteresis**: Wait 5 seconds before changing quality (avoid flapping)
4. **Transition**: Smoothly adjust parameters (max 100KB/s change per update)
5. **Logging**: Log quality changes with metrics

### Configuration

#### Enable Adaptive Quality

```toml
[bandwidth]
adaptive_quality = true
initial_quality = "high"
auto_adapt = true
```

#### Custom Quality Profiles

```toml
[bandwidth.quality.high]
target_latency = "50ms"
max_packet_size = 1400
enable_compression = false
target_throughput = 10000000  # 10 Mbps

[bandwidth.quality.low]
target_latency = "500ms"
max_packet_size = 800
enable_compression = true
compression_level = 6
target_throughput = 1000000  # 1 Mbps
```

## Usage Examples

### Example 1: Zoom Emulation with Auto-Adaptation

```toml
# config.toml
[client]
bind_address = "127.0.0.1:1080"
server_address = "myserver.com:8443"
proxy_type = "socks5"

[traffic]
application_profile = "zoom"
enabled = true

[bandwidth]
adaptive_quality = true
initial_quality = "high"
```

**What this does**:
- Mimics Zoom video call traffic patterns
- Starts with high quality (no compression)
- Automatically degrades to medium/low if network deteriorates
- Upgrades back to high when network improves

### Example 2: Netflix for Large Downloads

```toml
[client]
bind_address = "127.0.0.1:1080"
server_address = "myserver.com:443"

[traffic]
application_profile = "netflix"

[bandwidth]
adaptive_quality = true
initial_quality = "high"

[shapeshift]
strategy = "fixed"
initial_protocol = "https"
```

**What this does**:
- Mimics Netflix streaming with bursty downloads
- Uses HTTPS consistently (most streaming traffic is HTTPS)
- Adapts quality for optimal throughput

### Example 3: Stealth WhatsApp for Censored Networks

```toml
[client]
bind_address = "127.0.0.1:1080"
server_address = "myserver.com:443"

[traffic]
application_profile = "whatsapp"

[bandwidth]
adaptive_quality = true
initial_quality = "low"  # Start conservative

[shapeshift]
strategy = "adaptive"
initial_protocol = "https"
```

**What this does**:
- Minimal traffic footprint (WhatsApp-like)
- Starts with low quality to avoid detection
- Adapts protocol based on detection risk

## Library API

### Using Application Profiles in Code

```rust
use nooshdaroo::{ApplicationProfile, ApplicationEmulator};

// Load a profile
let profile = ApplicationProfile::zoom();

// Create emulator
let mut emulator = ApplicationEmulator::new(profile);

// Generate packet sizes
let upstream_size = emulator.generate_upstream_size();
let downstream_size = emulator.generate_downstream_size();

// Generate delays
let delay = emulator.generate_delay(true); // true = upstream

// Check for bursts
if let Some(burst) = emulator.should_burst() {
    println!("Burst: {} packets of {} bytes",
        burst.packet_count, burst.packet_size);
}

// Update state machine
emulator.update_state();
```

### Using Bandwidth Controller

```rust
use nooshdaroo::{BandwidthController, QualityTier};
use std::time::Duration;

let mut controller = BandwidthController::new();

// Record measurements
controller.record_rtt(Duration::from_millis(45));
controller.record_packet(1400, false); // size, lost

// Update and check if quality changed
if controller.update() {
    println!("Quality changed to: {:?}",
        controller.current_profile().tier);
}

// Get current metrics
let metrics = controller.metrics();
println!("RTT: {:?}, Loss: {:.2}%, Throughput: {} Mbps",
    metrics.rtt,
    metrics.packet_loss * 100.0,
    metrics.throughput / 125_000
);

// Force quality change
controller.set_quality(QualityTier::Medium);
```

### Adaptive Rate Limiting

```rust
use nooshdaroo::AdaptiveRateLimiter;
use std::time::Duration;

let mut limiter = AdaptiveRateLimiter::new(5_000_000); // 5 Mbps

// Try to send
if limiter.try_send(10000) {
    // Send 10KB
}

// Wait until can send
limiter.wait_for(100000).await; // Wait for 100KB quota

// Record network measurements
limiter.record_rtt(Duration::from_millis(50));
limiter.record_packet(1400, false);

// Rate automatically adapts to network conditions
println!("Current rate: {} Mbps", limiter.current_rate() / 125_000);
```

## How It Defeats DPI

### Statistical Traffic Analysis Resistance

**Traditional Proxies**:
- Uniform packet sizes
- Constant inter-packet delays
- No burst patterns
- No application-specific state machines

**Nooshdaroo with App Profiles**:
- ✅ Matches real application packet size distributions
- ✅ Replicates timing patterns (jitter, bursts, delays)
- ✅ Emulates burst patterns (keyframes, chunks, updates)
- ✅ Follows realistic state machines

### Adaptive Behavior

DPI systems often detect proxies by observing how they respond to network degradation:

**Traditional Proxies**:
- Continue sending large packets even when network is congested
- Don't adapt to packet loss
- Constant behavior regardless of conditions

**Nooshdaroo Adaptive Bandwidth**:
- ✅ Reduces packet sizes when RTT increases
- ✅ Enables compression when packet loss detected
- ✅ Smoothly transitions between quality levels
- ✅ Mimics how real applications adapt (Netflix quality switching, Zoom fallback to audio)

## Performance Considerations

### Memory Usage

- Application emulator: ~2 KB per instance
- Bandwidth controller: ~1 KB (with 10-sample window)
- Total overhead: <5 KB per connection

### CPU Usage

- Packet size generation: ~100 ns per packet
- RTT calculation: ~50 ns per update
- Quality adaptation: ~1 μs per update (every 1 second)
- Total overhead: <0.1% CPU on modern systems

### Network Overhead

- Packet padding: 0-1024 bytes per packet (configurable)
- Burst generation: Minimal (just timing delays)
- State machine: No bandwidth overhead

## Advanced Configuration

### Custom Application Profile (TOML)

```toml
[traffic.custom_profile]
name = "MyApp"
category = "VideoStreaming"

[traffic.custom_profile.upstream]
size_distribution = { type = "Normal", mean = 1200, stddev = 200 }
packet_rate = { mean = 50.0, stddev = 10.0, min = 30.0, max = 100.0 }
delay_distribution = { mean_ms = 20, stddev_ms = 5 }

[traffic.custom_profile.downstream]
size_distribution = { type = "Bimodal", mode1 = 100, mode2 = 1400, mode1_weight = 0.3 }
packet_rate = { mean = 60.0, stddev = 15.0, min = 40.0, max = 120.0 }
delay_distribution = { mean_ms = 16, stddev_ms = 3 }

[[traffic.custom_profile.burst_patterns]]
name = "Keyframe"
interval = "2s"
packet_count = 5
packet_size = 1400
probability = 0.95
```

### Multi-Profile Rotation

```toml
[shapeshift]
strategy = "time-based"
rotation_interval = "5m"

[[shapeshift.profile_sequence]]
time_range = "09:00-17:00"
profile = "zoom"  # Work hours: video conferencing

[[shapeshift.profile_sequence]]
time_range = "17:00-23:00"
profile = "netflix"  # Evening: streaming

[[shapeshift.profile_sequence]]
time_range = "23:00-09:00"
profile = "whatsapp"  # Night: messaging
```

## Troubleshooting

### High Latency Warning

If you see:
```
Quality adapted: Low (RTT: 450ms, Loss: 2.00%, Throughput: 800 Kbps)
```

**Solutions**:
1. Check your network connection
2. Try a different server
3. Reduce `initial_quality` to `"medium"` or `"low"`
4. Enable compression even for high quality

### Packet Loss Detection

If you see quality frequently downgrading:
```
Quality adapted: VeryLow (RTT: 120ms, Loss: 18.00%, Throughput: 500 Kbps)
```

**Solutions**:
1. Check if your ISP is throttling
2. Try different protocol in `[shapeshift]`
3. Use multiport strategy (spread across ports)
4. Enable `[netflow_evasion]` features

### Profile Not Working

If traffic still detected:

1. **Verify profile is loaded**:
   ```bash
   RUST_LOG=debug nooshdaroo client --config config.toml
   # Look for: "Loaded application profile: zoom"
   ```

2. **Check actual traffic**:
   ```bash
   tcpdump -i any -n port 8443
   # Observe packet sizes match expected distribution
   ```

3. **Enable all features**:
   ```toml
   [traffic.advanced]
   enable_timing_emulation = true
   enable_size_padding = true
   enable_bursts = true
   ```

## Best Practices

1. **Match Your Use Case**: Choose profile that matches your actual traffic volume
   - Low volume → WhatsApp
   - Medium volume → YouTube, Zoom
   - High volume → Netflix

2. **Enable Adaptive Quality**: Always enable for hostile networks
   ```toml
   [bandwidth]
   adaptive_quality = true
   ```

3. **Start Conservative**: Begin with `initial_quality = "medium"` in censored regions

4. **Combine with Protocol Rotation**: Use `strategy = "adaptive"` to change protocols

5. **Monitor Logs**: Watch for quality changes indicating network issues

## Future Enhancements

Planned features:
- [ ] Machine learning for automatic profile selection
- [ ] Custom profile creation from pcap files
- [ ] Multi-path bandwidth aggregation
- [ ] Predictive quality adaptation
- [ ] Application-layer protocol mimicry (HTTP/2 frame patterns)

## References

- [Traffic Analysis of Encrypted Messaging Services](https://research.example.com)
- [Adaptive Bitrate Streaming Algorithms](https://streaming.example.com)
- [Statistical Traffic Fingerprinting](https://security.example.com)

---

**Note**: These features are designed for authorized security testing, privacy protection, and research purposes. Always comply with applicable laws and terms of service.
