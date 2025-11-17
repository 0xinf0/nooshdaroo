#!/bin/bash
#
# Simple Relay Mode vs SOCKS5 Benchmark
# Direct comparison of throughput with and without Nooshdaroo tunnel
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}   Nooshdaroo Relay Benchmark${NC}"
echo -e "${BLUE}========================================${NC}"
echo

# Configuration
SERVER="23.128.36.42"
RELAY_PORT="9999"
IPERF_PORT="5201"
TEST_SIZE_MB=100

#========================================
# Test 1: Direct iperf3 Baseline
#========================================
echo -e "${BLUE}Test 1: Direct iperf3 Baseline${NC}"
echo "Testing raw network throughput without proxy..."
echo

# Download test
echo "Download (10 seconds)..."
iperf3 -c $SERVER -t 10 2>&1 | grep -E "receiver|sender" | tail -2
echo

# Upload test
echo "Upload (10 seconds)..."
iperf3 -c $SERVER -t 10 -R 2>&1 | grep -E "receiver|sender" | tail -2
echo

#========================================
# Setup: Start relay on server
#========================================
echo -e "${BLUE}Setup: Starting relay on server${NC}"
echo "Starting relay: 127.0.0.1:${RELAY_PORT} -> 127.0.0.1:${IPERF_PORT}..."

# Kill any existing relay
ssh $SERVER "pkill -f 'relay.*${RELAY_PORT}' 2>/dev/null; pkill -f 'python.*SimpleHTTPServer' 2>/dev/null; pkill -f 'python.*http.server' 2>/dev/null" || true
sleep 2

# Start relay on server that forwards to local iperf3
ssh $SERVER "cd /root/Nooshdaroo && nohup ./target/release/nooshdaroo relay --listen 127.0.0.1:${RELAY_PORT} --target 127.0.0.1:${IPERF_PORT} > /tmp/relay.log 2>&1 &" &
sleep 3

# Verify relay is running
RELAY_PID=$(ssh $SERVER "pgrep -f 'relay.*${RELAY_PORT}' || echo 'none'")
if [ "$RELAY_PID" = "none" ]; then
    echo -e "${RED}Error: Relay failed to start${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Relay running (PID: $RELAY_PID)${NC}"
echo

#========================================
# Test 2: Through Nooshdaroo Tunnel
#========================================
echo -e "${BLUE}Test 2: Through Nooshdaroo SOCKS5 Tunnel${NC}"
echo "Testing throughput through tunnel to relay..."
echo

# Check if SOCKS proxy is running
if ! nc -z 127.0.0.1 1080 2>/dev/null; then
    echo -e "${RED}Error: Nooshdaroo client not running on port 1080${NC}"
    echo "Start client with: ./target/release/nooshdaroo client --config client.toml --server $SERVER:8443 --protocol https"
    exit 1
fi
echo -e "${GREEN}✓ SOCKS5 proxy is running${NC}"

# Create 100MB test file on server
echo "Creating ${TEST_SIZE_MB}MB test file on server..."
ssh $SERVER "dd if=/dev/zero of=/tmp/${TEST_SIZE_MB}mb.dat bs=1M count=${TEST_SIZE_MB} 2>/dev/null"

# Start simple HTTP server on relay port
echo "Starting HTTP server on relay port..."
ssh $SERVER "cd /tmp && nohup python3 -m http.server ${RELAY_PORT} > /dev/null 2>&1 &" &
sleep 3

# Download through SOCKS5 tunnel
echo "Downloading ${TEST_SIZE_MB}MB through tunnel (this may take a while)..."
START_TIME=$(date +%s)
curl -x socks5://127.0.0.1:1080 \
     http://127.0.0.1:${RELAY_PORT}/${TEST_SIZE_MB}mb.dat \
     --max-time 120 \
     --silent \
     --output /dev/null 2>&1
END_TIME=$(date +%s)

ELAPSED=$((END_TIME - START_TIME))
MBPS=$(echo "scale=2; (${TEST_SIZE_MB} * 8) / $ELAPSED" | bc)

echo -e "${GREEN}✓ Download complete${NC}"
echo -e "  Time: ${ELAPSED} seconds"
echo -e "  Speed: ${MBPS} Mbps"
echo

#========================================
# Cleanup
#========================================
echo "Cleaning up..."
ssh $SERVER "pkill -f 'relay.*${RELAY_PORT}' 2>/dev/null; pkill -f 'python.*http.server' 2>/dev/null; rm -f /tmp/${TEST_SIZE_MB}mb.dat" || true

#========================================
# Summary
#========================================
echo
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}              SUMMARY${NC}"
echo -e "${BLUE}========================================${NC}"
echo
echo "Tunneled Performance: ${MBPS} Mbps"
echo
echo "Next Steps:"
echo "  1. Compare this to the direct iperf3 results above"
echo "  2. Calculate overhead: 100 - (tunnel_speed / direct_speed * 100)"
echo "  3. Compare to WireGuard's typical 5-10% overhead"
echo
echo -e "${GREEN}Benchmark complete!${NC}"
