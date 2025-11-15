# Nooshdaroo: Protocol Shape-Shifting SOCKS Proxy

## Overview

Nooshdaroo (نوشدارو - Persian for "remedy/cure") is an advanced encrypted SOCKS proxy built on top of Proteus that provides dynamic protocol emulation and shape-shifting capabilities. It leverages Proteus's existing PSF (Protocol Specification Format) engine to mimic the traffic patterns of legitimate protocols, making proxy traffic indistinguishable from normal application traffic.

## Core Concept

Unlike traditional proxies that use a single protocol signature, Nooshdaroo can:

1. **Emulate** - Perfectly mimic any defined protocol's packet structure and timing
2. **Shape-Shift** - Dynamically switch between protocol emulations during a session
3. **Encrypt** - Maintain end-to-end encryption while appearing as legitimate traffic
4. **Adapt** - Respond to network conditions and detection attempts

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      NOOSHDAROO CLIENT                       │
├─────────────────────────────────────────────────────────────┤
│  Application Layer                                          │
│    ├─ SOCKS5 Server (existing Proteus)                     │
│    └─ Protocol Selection API                                │
├─────────────────────────────────────────────────────────────┤
│  Protocol Emulation Engine                                  │
│    ├─ PSF Interpreter (existing Proteus)                   │
│    ├─ Protocol Library (100 protocol definitions)          │
│    ├─ Shape-Shift Controller                               │
│    └─ Traffic Pattern Analyzer                             │
├─────────────────────────────────────────────────────────────┤
│  Encryption Layer                                           │
│    ├─ ChaCha20-Poly1305 (existing)                         │
│    ├─ Noise Protocol                                        │
│    └─ TLS 1.3 Support                                       │
├─────────────────────────────────────────────────────────────┤
│  Transport Layer                                            │
│    ├─ TCP/UDP Support                                       │
│    └─ WebSocket Support                                     │
└─────────────────────────────────────────────────────────────┘
```

## Top 100 Network Protocols (by Layer)

### Application Layer (L7) - 40 protocols

1. **HTTP/1.1** (RFC 2616, 7230-7235) - Web traffic
2. **HTTP/2** (RFC 7540) - Binary HTTP
3. **HTTP/3** (RFC 9114) - HTTP over QUIC
4. **HTTPS** (RFC 2818) - Secure HTTP
5. **DNS** (RFC 1034, 1035) - Domain Name System
6. **DNS over HTTPS (DoH)** (RFC 8484)
7. **DNS over TLS (DoT)** (RFC 7858)
8. **SMTP** (RFC 5321) - Email transmission
9. **POP3** (RFC 1939) - Email retrieval
10. **IMAP** (RFC 3501) - Email access
11. **FTP** (RFC 959) - File transfer
12. **FTPS** (RFC 4217) - FTP over TLS
13. **SFTP** (RFC 913, SSH-based)
14. **SSH** (RFC 4251-4254) - Secure shell
15. **Telnet** (RFC 854) - Remote terminal
16. **DHCP** (RFC 2131) - Dynamic host config
17. **TFTP** (RFC 1350) - Trivial FTP
18. **NTP** (RFC 5905) - Network Time Protocol
19. **SNMP** (RFC 3411-3418) - Network management
20. **LDAP** (RFC 4511) - Directory access
21. **SIP** (RFC 3261) - Session Initiation Protocol
22. **RTP** (RFC 3550) - Real-time Transport
23. **RTSP** (RFC 7826) - Real-time Streaming
24. **RTMP** - Real-Time Messaging Protocol
25. **WebSocket** (RFC 6455) - Full-duplex web
26. **MQTT** (RFC pending) - IoT messaging
27. **CoAP** (RFC 7252) - Constrained Application Protocol
28. **XMPP** (RFC 6120) - Jabber/messaging
29. **IRC** (RFC 1459) - Internet Relay Chat
30. **SMB/CIFS** - Server Message Block
31. **NFS** (RFC 7530) - Network File System
32. **RDP** - Remote Desktop Protocol
33. **VNC** - Virtual Network Computing
34. **BitTorrent** - P2P file sharing
35. **QUIC** (RFC 9000) - Quick UDP Internet Connections
36. **gRPC** - Google RPC (HTTP/2-based)
37. **AMQP** (RFC 6520) - Message queuing
38. **Kafka Protocol** - Apache Kafka
39. **Redis Protocol** - Redis database
40. **Memcached Protocol** - Memcached

### Presentation/Session Layer (L5-6) - 15 protocols

41. **TLS 1.2** (RFC 5246) - Transport Layer Security
42. **TLS 1.3** (RFC 8446) - Latest TLS
43. **SSL 3.0** (deprecated) - Secure Sockets Layer
44. **DTLS** (RFC 6347) - Datagram TLS
45. **SRTP** (RFC 3711) - Secure RTP
46. **NetBIOS** (RFC 1001, 1002)
47. **SOCKS4** (RFC 1928 predecessor)
48. **SOCKS5** (RFC 1928) - Socket proxy
49. **PPTP** (RFC 2637) - Point-to-Point Tunneling
50. **L2TP** (RFC 2661) - Layer 2 Tunneling
51. **SPDY** - Google predecessor to HTTP/2
52. **WebRTC** - Real-time communication
53. **SCTP** (RFC 4960) - Stream Control Transmission
54. **Noise Protocol** - Cryptographic handshake
55. **WireGuard** - Modern VPN protocol

### Transport Layer (L4) - 10 protocols

56. **TCP** (RFC 793) - Transmission Control Protocol
57. **UDP** (RFC 768) - User Datagram Protocol
58. **DCCP** (RFC 4340) - Datagram Congestion Control
59. **RUDP** - Reliable UDP
60. **UDT** - UDP-based Data Transfer
61. **MPTCP** (RFC 6824) - Multipath TCP
62. **µTP** - Micro Transport Protocol (BitTorrent)
63. **SCTP** (RFC 4960) - Stream Control
64. **RSVP** (RFC 2205) - Resource Reservation
65. **GRE** (RFC 2784) - Generic Routing Encapsulation

### Network Layer (L3) - 15 protocols

66. **IPv4** (RFC 791) - Internet Protocol v4
67. **IPv6** (RFC 8200) - Internet Protocol v6
68. **ICMP** (RFC 792) - Internet Control Message
69. **ICMPv6** (RFC 4443) - ICMP for IPv6
70. **IPsec** (RFC 4301) - IP Security
71. **IKEv2** (RFC 7296) - Internet Key Exchange
72. **AH** (RFC 4302) - Authentication Header
73. **ESP** (RFC 4303) - Encapsulating Security Payload
74. **IGMP** (RFC 3376) - Internet Group Management
75. **OSPF** (RFC 2328) - Open Shortest Path First
76. **BGP** (RFC 4271) - Border Gateway Protocol
77. **RIP** (RFC 2453) - Routing Information Protocol
78. **IS-IS** (ISO 10589) - Intermediate System
79. **VRRP** (RFC 5798) - Virtual Router Redundancy
80. **MPLS** (RFC 3031) - Multiprotocol Label Switching

### Data Link Layer (L2) - 10 protocols

81. **Ethernet** (IEEE 802.3)
82. **Wi-Fi** (IEEE 802.11)
83. **PPP** (RFC 1661) - Point-to-Point Protocol
84. **PPPoE** (RFC 2516) - PPP over Ethernet
85. **ARP** (RFC 826) - Address Resolution Protocol
86. **RARP** (RFC 903) - Reverse ARP
87. **LLDP** (IEEE 802.1AB) - Link Layer Discovery
88. **VLAN** (IEEE 802.1Q) - Virtual LAN
89. **STP** (IEEE 802.1D) - Spanning Tree Protocol
90. **LACP** (IEEE 802.3ad) - Link Aggregation

### VPN & Tunneling Protocols - 10 protocols

91. **OpenVPN** - SSL/TLS-based VPN
92. **IPsec/IKEv2** - Combined VPN solution
93. **WireGuard** - Modern fast VPN
94. **Shadowsocks** - Proxy protocol
95. **V2Ray/VMess** - Advanced proxy
96. **Trojan** - Proxy protocol
97. **SSTP** (RFC draft) - Secure Socket Tunneling
98. **IKEv1** (RFC 2409) - Internet Key Exchange v1
99. **GRE over IPsec** - Tunneling combination
100. **VXLAN** (RFC 7348) - Virtual Extensible LAN

## Protocol Shape-Shifting Strategies

### 1. Time-Based Rotation
```rust
pub struct TimeBasedStrategy {
    interval: Duration,           // How often to switch
    protocol_sequence: Vec<ProtocolId>,
    current_index: usize,
}
```

### 2. Traffic-Based Switching
```rust
pub struct TrafficBasedStrategy {
    bytes_threshold: u64,         // Switch after N bytes
    packet_threshold: u64,        // Switch after N packets
    protocol_pool: Vec<ProtocolId>,
}
```

### 3. Detection-Aware Adaptation
```rust
pub struct AdaptiveStrategy {
    suspicion_score: f64,         // Estimated detection risk
    fallback_protocols: Vec<ProtocolId>,
    safe_protocols: Vec<ProtocolId>,
}
```

### 4. Environment-Based Selection
```rust
pub struct EnvironmentStrategy {
    time_of_day: TimeProfile,     // Different protocols for different times
    location: GeoProfile,          // Region-appropriate protocols
    network_type: NetworkType,     // WiFi vs cellular vs enterprise
}
```

## Key Features

### 1. Protocol Emulation Accuracy
- **Packet Structure**: Exact byte-level formatting per RFC
- **Timing Patterns**: Realistic inter-packet delays
- **State Machine**: Correct handshake sequences
- **Error Behavior**: Protocol-compliant error responses

### 2. Encryption Modes
- **Nested**: Encrypt within emulated protocol
- **Transparent**: Emulated protocol appears unencrypted but payload is encrypted
- **Steganographic**: Hide encrypted data in protocol-specific fields

### 3. Traffic Shaping
- **Packet Size**: Match typical size distributions
- **Burst Patterns**: Mimic application behavior
- **Directionality**: Maintain realistic upload/download ratios
- **Periodicity**: Match protocol-specific periodic traffic

### 4. Anti-Detection Features
- **Fingerprint Randomization**: Vary implementation details
- **TLS SNI Masking**: Match emulated protocol
- **Certificate Pinning**: Use legitimate-looking certificates
- **MTU Optimization**: Avoid suspicious packet sizes

## Implementation Plan

### Phase 1: Core Infrastructure
1. Extend Proteus PSF compiler for protocol library
2. Create protocol metadata system (RFC numbers, typical ports, etc.)
3. Build protocol selector with strategy pattern
4. Implement basic shape-shifting controller

### Phase 2: Protocol Library
1. Create PSF files for top 100 protocols
2. Add protocol-specific timing profiles
3. Build traffic pattern generators
4. Implement protocol validators

### Phase 3: Shape-Shifting Engine
1. Session management for protocol transitions
2. Smooth handoff between protocols
3. State preservation across switches
4. Error recovery mechanisms

### Phase 4: Advanced Features
1. Machine learning-based protocol selection
2. Real-time network condition analysis
3. Automatic fallback on detection
4. Multi-path routing support

### Phase 5: Integration & Testing
1. SOCKS5 API extensions
2. Configuration management
3. Performance benchmarking
4. Security auditing

## Configuration Format

```toml
[nooshdaroo]
mode = "client"  # or "server"

[nooshdaroo.encryption]
cipher = "chacha20-poly1305"
key_derivation = "argon2"
password = "your-secure-password"

[nooshdaroo.socks]
listen_addr = "127.0.0.1:1080"
auth_required = true

[nooshdaroo.protocols]
# Define available protocols
enabled = [
    "http",
    "https",
    "dns",
    "ssh",
    "tls",
    "quic",
    "websocket",
]

# Default protocol on connection start
default = "https"

[nooshdaroo.shape_shift]
# Shape-shifting strategy
strategy = "traffic-based"  # time-based, traffic-based, adaptive, environment

# Strategy-specific settings
bytes_threshold = 10485760  # 10 MB
packet_threshold = 10000
time_interval = "5m"

# Protocol rotation sequence (for time-based)
sequence = ["https", "quic", "websocket", "dns"]

[nooshdaroo.traffic_shaping]
# Match legitimate traffic patterns
packet_size_distribution = "normal"
mean_packet_size = 1400
stddev_packet_size = 200

# Inter-packet delay (microseconds)
mean_delay = 50
stddev_delay = 20

[nooshdaroo.server]
listen_addr = "0.0.0.0:443"
forward_addr = "127.0.0.1:9050"  # Tor SOCKS port

[nooshdaroo.detection]
# Anti-detection features
enable_fingerprint_randomization = true
enable_timing_randomization = true
enable_tls_sni_masking = true
suspicion_threshold = 0.7  # Switch protocols if detection risk > 70%
```

## Protocol Metadata Schema

```rust
pub struct ProtocolMeta {
    pub id: ProtocolId,
    pub name: String,
    pub rfc_numbers: Vec<u16>,
    pub default_port: u16,
    pub transport: Transport,  // TCP, UDP, or Both
    pub typical_packet_size: Range<usize>,
    pub handshake_required: bool,
    pub stateful: bool,
    pub encryption_native: bool,
    pub detection_resistance: DetectionScore,
    pub psf_path: PathBuf,
}

pub struct DetectionScore {
    pub commonality: f64,      // How common (1.0 = very common)
    pub suspicion: f64,        // How suspicious (0.0 = not suspicious)
    pub complexity: f64,       // Implementation complexity
}
```

## API Extensions

### Protocol Selection API
```rust
// Set protocol for current connection
socks5_username = "psf=/protocols/https.psf;mode=shapshift;strategy=adaptive"

// Programmatic API
impl NooshdarooClient {
    pub fn set_protocol(&mut self, protocol: ProtocolId) -> Result<()>;
    pub fn set_strategy(&mut self, strategy: ShapeShiftStrategy) -> Result<()>;
    pub fn get_current_protocol(&self) -> ProtocolId;
    pub fn get_protocol_stats(&self) -> ProtocolStats;
}
```

## Security Considerations

1. **Protocol Fingerprinting**: Each protocol implementation must be indistinguishable from legitimate implementations
2. **Timing Attacks**: Randomize timing patterns to avoid correlation attacks
3. **Traffic Analysis**: Maintain realistic traffic distributions
4. **Deep Packet Inspection**: Ensure encrypted payloads are properly hidden within protocol structures
5. **Certificate Validation**: When emulating TLS, use valid certificates for cover domains

## Performance Targets

- **Throughput**: >500 Mbps on modern hardware
- **Latency Overhead**: <10ms for protocol emulation
- **Memory Footprint**: <50 MB per connection
- **CPU Usage**: <5% for protocol switching
- **Protocol Switch Time**: <100ms seamless transition

## Use Cases

1. **Censorship Circumvention**: Evade DPI and protocol-based blocking
2. **Privacy Enhancement**: Make proxy traffic indistinguishable from normal traffic
3. **Tor Integration**: Enhanced pluggable transport with dynamic adaptation
4. **Research**: Study protocol fingerprinting and detection
5. **Testing**: Simulate various network protocols for development

## Advantages Over Existing Solutions

| Feature | Nooshdaroo | V2Ray | Shadowsocks | OpenVPN |
|---------|-----------|-------|-------------|---------|
| Protocol Emulation | 100+ protocols | Limited | 1 protocol | 1 protocol |
| Shape-Shifting | Dynamic | No | No | No |
| Programmable | Yes (PSF) | Limited | No | No |
| Detection Resistance | Very High | High | Medium | Low |
| Performance | High | Medium | Very High | Medium |
| Tor Integration | Native | Via plugin | Via plugin | Via plugin |

## Future Enhancements

1. **AI-Driven Selection**: Machine learning for optimal protocol selection
2. **Decoy Traffic**: Generate realistic decoy traffic to confuse analyzers
3. **Multi-Hop**: Route through multiple protocols in sequence
4. **Blockchain Integration**: Distributed protocol definition sharing
5. **Hardware Acceleration**: GPU-accelerated encryption and pattern matching
6. **Mobile Support**: Optimized for battery and bandwidth constraints
7. **Plugin System**: Third-party protocol definitions

## Development Roadmap

- **Q1 2025**: Core infrastructure and protocol library (Phases 1-2)
- **Q2 2025**: Shape-shifting engine and advanced features (Phases 3-4)
- **Q3 2025**: Integration, testing, and security audit (Phase 5)
- **Q4 2025**: Public release and documentation

## Contributing

Protocol definitions should be submitted as PSF files with accompanying metadata. Each protocol must include:
- Complete PSF specification
- RFC reference numbers
- Typical traffic patterns
- Test cases
- Detection resistance analysis

## License

Nooshdaroo inherits Proteus's license and adds protocol definition library under compatible terms.
