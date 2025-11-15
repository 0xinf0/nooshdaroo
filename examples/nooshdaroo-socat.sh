#!/bin/bash
# Nooshdaroo Socat Examples

# Example 1: Simple TCP relay through encrypted tunnel
# Forward local port 8080 to remote server
nooshdaroo socat \
  TCP-LISTEN:8080,fork \
  TCP:remote-server.com:80

# Example 2: Encrypted relay using HTTPS protocol emulation
# Same as above but with Nooshdaroo encryption
nooshdaroo socat \
  NOOSHDAROO-LISTEN:8080,fork \
  TCP:remote-server.com:80 \
  https

# Example 3: SOCKS5 proxy to encrypted relay
# Accept SOCKS5 connections and forward through encrypted tunnel
nooshdaroo socat \
  SOCKS5-LISTEN:1080,fork \
  NOOSHDAROO:server.com:443 \
  quic

# Example 4: HTTP proxy to encrypted relay
# Accept HTTP CONNECT and forward through DNS protocol emulation
nooshdaroo socat \
  HTTP-LISTEN:8080,fork \
  NOOSHDAROO:server.com:53 \
  dns

# Example 5: Standard input/output relay
# Pipe data through encrypted SSH protocol emulation
echo "Hello World" | nooshdaroo socat \
  STDIO \
  NOOSHDAROO:server.com:22 \
  ssh

# Example 6: File transfer through encrypted tunnel
# Send file using WebSocket protocol emulation
nooshdaroo socat \
  FILE:/path/to/large-file.dat \
  NOOSHDAROO:server.com:443 \
  websocket

# Example 7: Bidirectional relay with auto-protocol switching
# Use adaptive strategy to switch protocols based on detection
nooshdaroo socat \
  TCP-LISTEN:3128,fork \
  NOOSHDAROO:server.com:443 \
  adaptive

# Example 8: Transparent proxy mode (requires root)
# Intercept all TCP traffic and forward through encrypted tunnel
sudo nooshdaroo socat \
  TRANSPARENT-LISTEN:12345 \
  NOOSHDAROO:server.com:443 \
  tls13

# Then set up iptables:
# sudo iptables -t nat -A OUTPUT -p tcp -j REDIRECT --to-port 12345

# Example 9: Multi-protocol listener
# Accept both SOCKS5 and HTTP on same port (auto-detect)
nooshdaroo socat \
  AUTO-LISTEN:1080,fork \
  NOOSHDAROO:server.com:443 \
  https

# Example 10: Chain multiple hops
# Client -> Local Relay (HTTPS) -> Middle Server (QUIC) -> Destination
nooshdaroo socat \
  TCP-LISTEN:8080,fork \
  NOOSHDAROO:middle-server.com:443 \
  https &

nooshdaroo socat \
  TCP-LISTEN:9090,fork \
  NOOSHDAROO:final-server.com:443 \
  quic &

# Configure apps to use localhost:8080
