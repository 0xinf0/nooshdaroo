# Mobile Platform Network Transport Capabilities

## Overview

This document outlines the network transport protocols available to Nooshdaroo when running as a mobile application on iOS and Android platforms **without requiring root/jailbreak**.

---

## Supported Transports (No Root Required)

### ✅ TCP (Transmission Control Protocol)
- **iOS**: Full support via `URLSession`, `NWConnection`, or BSD sockets
- **Android**: Full support via standard Java/Kotlin networking APIs
- **Use Cases**: HTTPS, SSH, HTTP, TLS, most application protocols
- **Nooshdaroo Status**: ✅ **Fully Implemented**

### ✅ UDP (User Datagram Protocol)
- **iOS**: Full support via `NWConnection.udp`, `NWUDPSession`, or BSD sockets
- **Android**: Full support via `DatagramSocket` or native sockets
- **Use Cases**: DNS, QUIC, WireGuard, VoIP (SIP/RTP), gaming protocols
- **Nooshdaroo Status**: ⚠️ **Needs Implementation** (protocol metadata exists, socket handling missing)

### ✅ ICMP (Internet Control Message Protocol) - Limited
- **iOS**: **YES** via `SimplePing` / CFSocket using special non-privileged ICMP socket
  - Apple provides special facility for unprivileged ICMP
  - Uses `CFSocket` with `IPPROTO_ICMP` and `SOCK_DGRAM`
  - No root required - iOS-specific feature
- **Android**: **Partial** - requires workarounds
  - Raw sockets (`SOCK_RAW`) banned for security
  - ICMP datagram sockets (`SOCK_DGRAM` + `IPPROTO_ICMP`) available since Linux kernel 2011
  - Restricted by `/proc/sys/net/ipv4/ping_group_range` (default: "1 0" = nobody)
  - Some Android versions/manufacturers disable this entirely
  - Alternative: Use system `ping` command via shell (requires `INTERNET` permission)
- **Use Cases**: Network diagnostics, latency measurement, keepalive
- **Nooshdaroo Status**: ❌ **Not Implemented** (optional feature)

---

## iOS Network Extension Capabilities

When implementing a VPN/proxy using `NEPacketTunnelProvider`:

### Available Methods

```swift
// UDP session creation
func createUDPSession(to: NWEndpoint, from: NWHostEndpoint?) -> NWUDPSession

// TCP session creation
func createTCPConnection(to: NWEndpoint, enableTLS: Bool, tlsParameters: NWTLSParameters?, delegate: Any?) -> NWTCPConnection
```

### Protocol Support
- ✅ **TCP**: Fully supported via `NWTCPConnection`
- ✅ **UDP**: Fully supported via `NWUDPSession`
- ✅ **TLS/DTLS**: Built-in support via `enableTLS` and `tlsParameters`
- ✅ **IP Layer**: Can tunnel raw IP packets via `packetFlow`
- ❌ **Raw Sockets**: Not available in sandboxed apps

### Recommendations from Apple (WWDC 2024/2025)
- **UDP preferred for VPN protocols** (OpenVPN, WireGuard) - faster, lower overhead
- **Network Relays** (new API) for TCP/UDP tunneling to specific apps
- **IP-based VPN** (NEPacketTunnelProvider) for full IP packet tunneling

---

## Android VPN Service Capabilities

When implementing a VPN using `VpnService`:

### Available Methods

```java
// File descriptor for VPN interface
ParcelFileDescriptor establish()

// Protect socket from VPN routing
boolean protect(Socket socket)
boolean protect(DatagramSocket socket)
```

### Protocol Support
- ✅ **TCP**: Yes - read from TUN interface, parse IP packets
- ✅ **UDP**: Yes - read from TUN interface, parse IP packets
- ✅ **IP Layer**: Full control over IP packet routing
- ❌ **Raw Sockets**: Restricted by `CONFIG_ANDROID_PARANOID_NETWORK`
- ⚠️ **ICMP**: Limited - requires special group membership

### Implementation Notes
- Must parse IP packets from TUN interface
- Must handle TCP connection state machine manually (or use libraries like `lwIP`)
- UDP is simpler - stateless forwarding
- Requires `BIND_VPN_SERVICE` permission

---

## Nooshdaroo Transport Strategy

### Priority 1: TCP Support ✅
- **Status**: Implemented
- **Protocols**: HTTPS, SSH, HTTP/2, HTTP/3 (over TCP), TLS, OpenVPN (TCP mode)
- **Mobile Compatibility**: 100% - works on all platforms

### Priority 2: UDP Support ⚠️
- **Status**: Protocol metadata exists, socket implementation needed
- **Protocols**: WireGuard, QUIC, DNS, DNS-over-HTTPS, SIP, RTP, OpenVPN (UDP mode)
- **Mobile Compatibility**: 100% - fully supported on iOS and Android
- **Implementation Required**:
  - [ ] Add `tokio::net::UdpSocket` support
  - [ ] Implement SOCKS5 UDP ASSOCIATE command
  - [ ] UDP packet forwarding and NAT handling
  - [ ] Test on iOS (`NWUDPSession`) and Android (`DatagramSocket`)

### Priority 3: ICMP Support (Optional) ❌
- **Status**: Not implemented
- **Use Case**: Network diagnostics, latency probing, keepalive
- **Mobile Compatibility**:
  - iOS: Good (SimplePing / CFSocket)
  - Android: Poor (requires group permissions or shell access)
- **Recommendation**: Low priority - use UDP for keepalive instead

---

## Implementation Checklist

### For Full Mobile Support

- [x] TCP socket support (client and server)
- [x] TLS/Noise encryption over TCP
- [x] SOCKS5 TCP CONNECT
- [ ] UDP socket support (client and server)
- [ ] UDP NAT traversal and session tracking
- [ ] SOCKS5 UDP ASSOCIATE
- [ ] iOS Network Extension integration
- [ ] Android VPN Service integration
- [ ] Test on real iOS/Android devices

### Mobile-Specific Testing

- [ ] Test TCP performance on 4G/5G networks
- [ ] Test UDP performance on cellular (packet loss, NAT)
- [ ] Verify background operation on iOS (Network Extension)
- [ ] Verify background operation on Android (VPN Service foreground service)
- [ ] Test protocol switching on mobile networks
- [ ] Measure battery impact

---

## Technical Constraints

### What Works Without Root

| Transport | iOS | Android | Notes |
|-----------|-----|---------|-------|
| TCP       | ✅  | ✅      | Full support, no restrictions |
| UDP       | ✅  | ✅      | Full support, no restrictions |
| ICMP      | ✅  | ⚠️      | iOS: SimplePing works; Android: limited |
| Raw IP    | ❌  | ❌      | Requires root/jailbreak |
| Raw Sockets | ❌ | ❌     | Blocked for security |

### What Requires Root/Jailbreak

- Raw sockets (`SOCK_RAW`)
- Custom IP protocols (not TCP/UDP/ICMP)
- Direct packet injection
- Bypassing system firewall
- Modifying routing tables (outside VPN service)

---

## Recommendations for Nooshdaroo

### 1. Implement UDP Support (High Priority)
UDP is **fully supported** on both platforms and essential for:
- Modern VPN protocols (WireGuard)
- Low-latency applications (gaming, VoIP)
- Protocols that require UDP (QUIC, DNS)
- Better performance on mobile networks

### 2. Use iOS Network Extension
- Provides system-level VPN integration
- Supports both TCP and UDP via `NWConnection`
- Handles VPN lifecycle management
- Required for App Store distribution of VPN apps

### 3. Use Android VPN Service
- System-level VPN integration
- TUN interface for packet-level control
- Requires parsing IP packets (use `lwIP` or similar)
- Foreground service for background operation

### 4. Skip ICMP for Now
- Limited utility compared to UDP
- Platform-specific implementations
- Can use UDP for keepalive/diagnostics instead

---

## Performance Considerations

### TCP on Mobile Networks
- Works well but suffers from head-of-line blocking
- Can optimize with TCP tuning (window size, congestion control)
- Expected: 10-25% faster downloads with proper 4G/5G tuning

### UDP on Mobile Networks
- Better for real-time applications
- More resilient to packet loss
- Requires application-level reliability if needed
- Better battery efficiency (no connection state)

### Cellular Network Characteristics
- 4G: 10-40 Mbps typical
- 5G: 80-600 Mbps typical
- High latency variance (20-200ms)
- Frequent IP address changes (handoffs)
- NAT traversal challenges

---

## Conclusion

**Nooshdaroo should implement UDP support immediately** - it's fully available on both iOS and Android without root, essential for modern protocols (WireGuard, QUIC), and provides better mobile network performance.

ICMP is optional and platform-specific - can be added later for diagnostics.

**Current Support Matrix:**

| Feature | Desktop | iOS | Android |
|---------|---------|-----|---------|
| TCP | ✅ | ✅ | ✅ |
| UDP | ❌ | ⚠️ (platform supports) | ⚠️ (platform supports) |
| ICMP | ❌ | ⚠️ (SimplePing available) | ⚠️ (limited) |
| Protocol Emulation | ✅ (121 protocols) | ✅ (121 protocols) | ✅ (121 protocols) |

**Target Support Matrix After UDP Implementation:**

| Feature | Desktop | iOS | Android |
|---------|---------|-----|---------|
| TCP | ✅ | ✅ | ✅ |
| UDP | ✅ | ✅ | ✅ |
| ICMP | ❌ | ⚠️ | ⚠️ |
| Protocol Emulation | ✅ | ✅ | ✅ |
