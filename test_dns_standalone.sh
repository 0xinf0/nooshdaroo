#!/bin/bash
#
# Test script for standalone DNS UDP tunnel
# This demonstrates that DNS queries are being sent over UDP port 53/15353
#

echo "=== Standalone DNS UDP Tunnel Test ==="
echo ""
echo "1. Building binaries..."
cargo build --release --bin dns-socks-server --bin dns-socks-client || exit 1

echo ""
echo "2. Starting DNS server on port 15353..."
./target/release/dns-socks-server 127.0.0.1:15353 2>&1 | head -10 &
SERVER_PID=$!
sleep 2

echo ""
echo "3. Starting DNS SOCKS client..."
./target/release/dns-socks-client 127.0.0.1:15353 2>&1 | head -10 &
CLIENT_PID=$!
sleep 2

echo ""
echo "4. Testing HTTP request through DNS tunnel..."
curl -x socks5h://127.0.0.1:1080 http://www.example.com/ \
  -w '\nHTTP Status: %{http_code}\nSize: %{size_download} bytes\n' \
  -o /dev/null -s --max-time 10

echo ""
echo "5. Cleaning up..."
kill $CLIENT_PID $SERVER_PID 2>/dev/null

echo ""
echo "=== Test Complete ===\"
echo ""
echo "To test on production:"
echo "  Server: ./target/release/dns-socks-server 0.0.0.0:53"
echo "  Client: ./target/release/dns-socks-client <server-ip>:53"
