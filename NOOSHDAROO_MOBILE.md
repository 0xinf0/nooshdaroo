# Nooshdaroo Mobile Guide

Easy integration guide for iOS and Android applications.

## Features for Mobile

### 🔌 Multiple Proxy Types

- **SOCKS5**: Standard proxy (best for apps)
- **HTTP CONNECT**: Web browser compatible
- **Transparent**: System-wide VPN mode

### 📱 Mobile-Optimized

- **Low Battery Impact**: Efficient async I/O
- **Background Support**: Works when app is backgrounded (iOS)
- **VPN Service**: Android VpnService integration
- **Auto-Reconnect**: Handles network changes
- **Minimal Footprint**: <5MB binary size

### 🎭 Smart Protocol Selection

Auto-selects best protocols based on:
- Network type (WiFi vs Cellular)
- Battery level
- Time of day
- Geographic location

## iOS Integration

### Swift Package

```swift
import Nooshdaroo

// Simple configuration
let config = NooshdarooConfig()
config.listenAddr = "127.0.0.1:1080"
config.serverAddr = "your-server.com:443"
config.password = "your-secure-password"
config.protocol = "https"  // or "dns", "quic", etc.

// Start client
let client = NooshdarooClient(config: config)
try await client.start()

// Configure URLSession to use proxy
let sessionConfig = URLSessionConfiguration.default
sessionConfig.connectionProxyDictionary = [
    kCFNetworkProxiesSOCKSProxy: "127.0.0.1",
    kCFNetworkProxiesSOCKSPort: 1080
]
```

### Network Extension (VPN Mode)

```swift
import NetworkExtension

class NooshdarooVPNProvider: NEPacketTunnelProvider {
    var client: NooshdarooClient?

    override func startTunnel(options: [String : NSObject]?) async throws {
        let config = NooshdarooConfig()
        config.serverAddr = options?["server"] as? String ?? ""
        config.password = options?["password"] as? String ?? ""
        config.protocol = "https"

        client = NooshdarooClient(config: config)
        try await client.start()

        // Set VPN settings
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: config.serverAddr)
        settings.ipv4Settings = NEIPv4Settings(
            addresses: ["10.8.0.2"],
            subnetMasks: ["255.255.255.0"]
        )
        settings.dnsSettings = NEDNSSettings(servers: ["8.8.8.8"])

        try await setTunnelNetworkSettings(settings)
    }

    override func stopTunnel(with reason: NEProviderStopReason) async {
        await client?.stop()
    }
}
```

### Podfile

```ruby
pod 'Nooshdaroo', '~> 1.0'
```

### Building from Source

```bash
# Install Rust for iOS
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios

# Build
cd proteus
cargo build --release --target aarch64-apple-ios --lib

# Create xcframework
xcodebuild -create-xcframework \
  -library target/aarch64-apple-ios/release/libnooshdaroo.a \
  -library target/aarch64-apple-ios-sim/release/libnooshdaroo.a \
  -output Nooshdaroo.xcframework
```

## Android Integration

### Kotlin Library

```kotlin
import com.nooshdaroo.Client
import com.nooshdaroo.Config

// Simple configuration
val config = Config.Builder()
    .listenAddr("127.0.0.1:1080")
    .serverAddr("your-server.com:443")
    .password("your-secure-password")
    .protocol("https")
    .build()

// Start client
val client = Client(config)
client.start()

// Use with OkHttp
val proxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", 1080))
val client = OkHttpClient.Builder()
    .proxy(proxy)
    .build()
```

### VPN Service

```kotlin
import android.net.VpnService
import com.nooshdaroo.Client

class NooshdarooVpnService : VpnService() {
    private var client: Client? = null
    private var vpnInterface: ParcelFileDescriptor? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Configure VPN
        val builder = Builder()
            .setSession("Nooshdaroo VPN")
            .addAddress("10.8.0.2", 24)
            .addDnsServer("8.8.8.8")
            .addRoute("0.0.0.0", 0)

        vpnInterface = builder.establish()

        // Start Nooshdaroo client
        val config = Config.Builder()
            .serverAddr(intent?.getStringExtra("server") ?: "")
            .password(intent?.getStringExtra("password") ?: "")
            .protocol("https")
            .tunFd(vpnInterface?.fd ?: -1)
            .build()

        client = Client(config)
        client?.start()

        return START_STICKY
    }

    override fun onDestroy() {
        client?.stop()
        vpnInterface?.close()
        super.onDestroy()
    }
}
```

### Gradle

```gradle
dependencies {
    implementation 'com.nooshdaroo:nooshdaroo-android:1.0.0'
}
```

### Building from Source

```bash
# Install Android NDK
export ANDROID_NDK_HOME=/path/to/ndk

# Install Rust for Android
rustup target add aarch64-linux-android armv7-linux-androideabi

# Build
cd proteus
cargo ndk -t arm64-v8a -t armeabi-v7a -o jniLibs build --release
```

## Cross-Platform (React Native / Flutter)

### React Native

```javascript
import Nooshdaroo from 'react-native-nooshdaroo';

const config = {
  listenAddr: '127.0.0.1:1080',
  serverAddr: 'your-server.com:443',
  password: 'your-secure-password',
  protocol: 'https',
  proxyType: 'socks5', // or 'http', 'transparent'
};

await Nooshdaroo.start(config);

// Get status
const status = await Nooshdaroo.getStatus();
console.log('Connected:', status.connected);
console.log('Protocol:', status.protocol);

// Get stats
const stats = await Nooshdaroo.getStats();
console.log('Bytes sent:', stats.bytesSent);
console.log('Bytes received:', stats.bytesReceived);

// Stop
await Nooshdaroo.stop();
```

### Flutter

```dart
import 'package:nooshdaroo/nooshdaroo.dart';

final config = NooshdarooConfig(
  listenAddr: '127.0.0.1:1080',
  serverAddr: 'your-server.com:443',
  password: 'your-secure-password',
  protocol: 'https',
  proxyType: ProxyType.socks5,
);

final client = NooshdarooClient(config);
await client.start();

// Monitor status
client.statusStream.listen((status) {
  print('Status: ${status.state}');
  print('Protocol: ${status.currentProtocol}');
});

// Monitor stats
client.statsStream.listen((stats) {
  print('Sent: ${stats.bytesSent}, Received: ${stats.bytesReceived}');
});

await client.stop();
```

## C FFI API

For direct integration from any language:

```c
#include "nooshdaroo.h"

// Configuration
NooshdarooMobileConfig config = {
    .listen_addr = "127.0.0.1:1080",
    .server_addr = "your-server.com:443",
    .password = "your-secure-password",
    .protocol = "https",
    .proxy_type = 0,  // SOCKS5
    .enable_shapeshift = 1,
    .shapeshift_strategy = 3,  // Adaptive
};

// Initialize
int result = nooshdaroo_init(&config);
if (result != 0) {
    fprintf(stderr, "Init failed: %d\n", result);
    return -1;
}

// Start
result = nooshdaroo_start();
if (result != 0) {
    fprintf(stderr, "Start failed: %d\n", result);
    return -1;
}

// Check status
int status = nooshdaroo_status();
printf("Status: %d\n", status);  // 2 = connected

// Get current protocol
char* protocol = nooshdaroo_get_protocol();
printf("Protocol: %s\n", protocol);
nooshdaroo_free_string(protocol);

// Get statistics
char* stats = nooshdaroo_get_stats();
printf("Stats: %s\n", stats);
nooshdaroo_free_string(stats);

// Stop
nooshdaroo_stop();
```

## Configuration Examples

### Basic (SOCKS5 Proxy)

```toml
mode = "client"
protocol_dir = "protocols"

[encryption]
password = "your-secure-password"

[socks]
listen_addr = "127.0.0.1:1080"

[shapeshift.strategy]
type = "fixed"
protocol = "https"
```

### Advanced (Auto-Switching)

```toml
mode = "client"

[encryption]
password = "your-secure-password"

[socks]
listen_addr = "127.0.0.1:1080"

# Adaptive strategy for mobile networks
[shapeshift.strategy]
type = "adaptive"
switch_threshold = 0.6  # Lower threshold for mobile
safe_protocols = ["https", "dns"]  # Common protocols
normal_protocols = ["quic", "websocket"]

[traffic_shaping]
enabled = true
# Reduce packet size for mobile
mean_packet_size = 1200
stddev_packet_size = 150

[detection]
enable_fingerprint_randomization = true
enable_timing_randomization = true
```

### Battery-Optimized

```toml
mode = "client"

[encryption]
password = "your-secure-password"

[socks]
listen_addr = "127.0.0.1:1080"

# Fixed protocol (no switching overhead)
[shapeshift.strategy]
type = "fixed"
protocol = "https"

# Minimal traffic shaping
[traffic_shaping]
enabled = false

[detection]
# Disable expensive features
enable_fingerprint_randomization = false
enable_timing_randomization = false
```

## Socat-Like Usage

### Port Forwarding

```bash
# Forward local port 8080 to remote server through encrypted tunnel
nooshdaroo socat TCP-LISTEN:8080,fork NOOSHDAROO:remote-server.com:443 https

# Equivalent to:
# socat TCP-LISTEN:8080,fork TCP:remote.com:80
# But with Nooshdaroo encryption using HTTPS protocol emulation
```

### Connect App to Proxy

```bash
# Make any app use Nooshdaroo by forwarding its traffic
nooshdaroo socat TCP-LISTEN:3128,fork NOOSHDAROO:server.com:443 quic

# Configure app to use proxy at localhost:3128
```

### Standard Input/Output

```bash
# Pipe data through encrypted tunnel
echo "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" | \
  nooshdaroo socat STDIO NOOSHDAROO:server.com:443 https
```

### File Transfer

```bash
# Send file through encrypted tunnel
nooshdaroo socat FILE:/path/to/file NOOSHDAROO:server.com:443 ssh
```

## Command-Line Examples

### Start as SOCKS5 Proxy

```bash
nooshdaroo \
  --listen 127.0.0.1:1080 \
  --server your-server.com:443 \
  --password "your-password" \
  --protocol https \
  --proxy-type socks5
```

### Start as HTTP Proxy

```bash
nooshdaroo \
  --listen 127.0.0.1:8080 \
  --server your-server.com:443 \
  --password "your-password" \
  --protocol quic \
  --proxy-type http
```

### Start as Transparent Proxy (requires root)

```bash
sudo nooshdaroo \
  --listen 0.0.0.0:12345 \
  --server your-server.com:443 \
  --password "your-password" \
  --protocol dns \
  --proxy-type transparent

# Set up iptables redirect
sudo iptables -t nat -A OUTPUT -p tcp -j REDIRECT --to-port 12345
```

### Unified Proxy (Auto-Detect)

```bash
# Accepts both SOCKS5 and HTTP on same port
nooshdaroo \
  --listen 127.0.0.1:1080 \
  --server your-server.com:443 \
  --password "your-password" \
  --proxy-type auto
```

## Performance Tuning

### Low Latency (Gaming, VoIP)

```toml
[shapeshift.strategy]
type = "fixed"
protocol = "quic"  # UDP-based, low latency

[traffic_shaping]
enabled = false  # Disable for minimum latency
```

### High Throughput (Streaming, Downloads)

```toml
[shapeshift.strategy]
type = "fixed"
protocol = "https"  # TCP-based, reliable

[traffic_shaping]
enabled = true
mean_packet_size = 1400  # Maximum payload
```

### Maximum Stealth (Censored Networks)

```toml
[shapeshift.strategy]
type = "adaptive"
switch_threshold = 0.5  # Aggressive switching
safe_protocols = ["https", "dns", "websocket"]

[traffic_shaping]
enabled = true

[detection]
enable_fingerprint_randomization = true
enable_timing_randomization = true
enable_tls_sni_masking = true
```

## Troubleshooting

### iOS: Network Extension Not Working

1. Enable "Network Extensions" capability
2. Add VPN configuration entitlement
3. Request VPN permissions:

```swift
import NetworkExtension

let manager = NETunnelProviderManager()
try await manager.loadFromPreferences()
manager.isEnabled = true
try await manager.saveToPreferences()
```

### Android: VPN Service Permissions

Add to AndroidManifest.xml:

```xml
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.BIND_VPN_SERVICE" />

<service
    android:name=".NooshdarooVpnService"
    android:permission="android.permission.BIND_VPN_SERVICE">
    <intent-filter>
        <action android:name="android.net.VpnService" />
    </intent-filter>
</service>
```

Request VPN permission:

```kotlin
val intent = VpnService.prepare(applicationContext)
if (intent != null) {
    startActivityForResult(intent, VPN_REQUEST_CODE)
} else {
    // Permission already granted
    startVpn()
}
```

### Connection Issues

```bash
# Enable debug logging
export RUST_LOG=debug
nooshdaroo --config config.toml

# Test connectivity
curl -x socks5://127.0.0.1:1080 https://example.com
```

### High Battery Usage

- Use fixed protocol (disable shape-shifting)
- Disable traffic shaping
- Reduce logging level
- Use DNS or HTTPS (less processing)

## Best Practices

### Security

1. **Strong Passwords**: Use 32+ character random passwords
2. **Rotate Protocols**: Enable shape-shifting in hostile environments
3. **Update Regularly**: Keep Nooshdaroo updated
4. **Verify Server**: Use certificate pinning when possible

### Performance

1. **Choose Right Protocol**:
   - QUIC for lossy networks (mobile)
   - HTTPS for stable connections
   - DNS for maximum stealth (but lower throughput)

2. **Optimize for Network**:
   - WiFi: Enable traffic shaping, use complex protocols
   - Cellular: Disable shaping, use simple protocols

3. **Battery Life**:
   - Use fixed protocol
   - Disable randomization
   - Minimize logging

### Privacy

1. **No Logs**: Nooshdaroo doesn't log traffic
2. **Memory Safety**: Rust prevents leaks
3. **Perfect Forward Secrecy**: Rotate keys frequently
4. **Metadata Protection**: Protocol emulation hides proxy signatures

## Example Apps

### iOS Example (SwiftUI)

```swift
import SwiftUI
import Nooshdaroo

struct ContentView: View {
    @StateObject private var client = NooshdarooClientViewModel()

    var body: some View {
        VStack {
            Text("Nooshdaroo")
                .font(.largeTitle)

            Text("Status: \(client.status)")
            Text("Protocol: \(client.protocol)")

            Button(client.isConnected ? "Disconnect" : "Connect") {
                client.toggle()
            }
            .padding()

            VStack(alignment: .leading) {
                Text("Sent: \(client.bytesSent) bytes")
                Text("Received: \(client.bytesReceived) bytes")
            }
        }
    }
}

class NooshdarooClientViewModel: ObservableObject {
    @Published var status = "Disconnected"
    @Published var protocol = "https"
    @Published var bytesSent = 0
    @Published var bytesReceived = 0

    private var client: NooshdarooClient?

    var isConnected: Bool { status == "Connected" }

    func toggle() {
        if isConnected {
            disconnect()
        } else {
            connect()
        }
    }

    func connect() {
        let config = NooshdarooConfig()
        config.serverAddr = "server.com:443"
        config.password = "password"

        client = NooshdarooClient(config: config)
        Task {
            try await client?.start()
            status = "Connected"
        }
    }

    func disconnect() {
        Task {
            await client?.stop()
            status = "Disconnected"
        }
    }
}
```

### Android Example (Compose)

```kotlin
@Composable
fun NooshdarooScreen() {
    val viewModel: NooshdarooViewModel = viewModel()

    Column(
        modifier = Modifier.fillMaxSize().padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text("Nooshdaroo", style = MaterialTheme.typography.h4)

        Spacer(modifier = Modifier.height(16.dp))

        Text("Status: ${viewModel.status}")
        Text("Protocol: ${viewModel.protocol}")

        Spacer(modifier = Modifier.height(16.dp))

        Button(onClick = { viewModel.toggle() }) {
            Text(if (viewModel.isConnected) "Disconnect" else "Connect")
        }

        Spacer(modifier = Modifier.height(16.dp))

        Text("Sent: ${viewModel.bytesSent} bytes")
        Text("Received: ${viewModel.bytesReceived} bytes")
    }
}

class NooshdarooViewModel : ViewModel() {
    var status by mutableStateOf("Disconnected")
    var protocol by mutableStateOf("https")
    var bytesSent by mutableStateOf(0L)
    var bytesReceived by mutableStateOf(0L)

    private var client: Client? = null

    val isConnected get() = status == "Connected"

    fun toggle() {
        if (isConnected) disconnect() else connect()
    }

    fun connect() {
        viewModelScope.launch {
            val config = Config.Builder()
                .serverAddr("server.com:443")
                .password("password")
                .build()

            client = Client(config)
            client?.start()
            status = "Connected"
        }
    }

    fun disconnect() {
        viewModelScope.launch {
            client?.stop()
            status = "Disconnected"
        }
    }
}
```

## License

Nooshdaroo is open source. See LICENSE for details.

---

**نوشدارو** - A remedy for internet censorship on mobile devices. 📱🔓
