#!/bin/bash
#
# Nooshdaroo vs Direct Connection Comparison
# Tests iperf3 performance with and without Nooshdaroo tunnel
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}==========================================${NC}"
echo -e "${BLUE}  Nooshdaroo Performance Comparison${NC}"
echo -e "${BLUE}==========================================${NC}"
echo

# Configuration
SERVER="23.128.36.42"
RELAY_PORT="9999"
IPERF_PORT="5201"
TEST_DURATION=10

#========================================
# Test 1: Direct iperf3 Baseline
#========================================
echo -e "${BLUE}Test 1: Direct Connection (Baseline)${NC}"
echo "Testing direct iperf3 to server..."
echo

echo "Direct download (10s)..."
DIRECT_DOWN=$(iperf3 -c $SERVER -t $TEST_DURATION 2>&1 | grep "receiver" | awk '{print $7, $8}')
DIRECT_DOWN_VAL=$(iperf3 -c $SERVER -t $TEST_DURATION -J 2>&1 | grep -o '"bits_per_second":[0-9.]*' | head -1 | cut -d: -f2)
DIRECT_DOWN_MBPS=$(echo "scale=2; $DIRECT_DOWN_VAL / 1000000" | bc)

echo -e "  ${GREEN}${DIRECT_DOWN_MBPS} Mbps${NC}"

echo "Direct upload (10s)..."
DIRECT_UP=$(iperf3 -c $SERVER -t $TEST_DURATION -R 2>&1 | grep "receiver" | awk '{print $7, $8}')
DIRECT_UP_VAL=$(iperf3 -c $SERVER -t $TEST_DURATION -R -J 2>&1 | grep -o '"bits_per_second":[0-9.]*' | head -1 | cut -d: -f2)
DIRECT_UP_MBPS=$(echo "scale=2; $DIRECT_UP_VAL / 1000000" | bc)

echo -e "  ${GREEN}${DIRECT_UP_MBPS} Mbps${NC}"
echo

#========================================
# Setup: Start relay on server
#========================================
echo -e "${BLUE}Setup: Starting iperf3 relay on server${NC}"
echo "Starting relay: localhost:$RELAY_PORT -> localhost:$IPERF_PORT..."

# Start relay on server that forwards to local iperf3
ssh $SERVER "pkill -f 'relay.*$RELAY_PORT' 2>/dev/null; cd /root/Nooshdaroo && ./target/release/nooshdaroo relay --listen 127.0.0.1:$RELAY_PORT --target 127.0.0.1:$IPERF_PORT 2>&1 > /tmp/relay.log &" &
sleep 3

# Verify relay is running
ssh $SERVER "pgrep -f 'relay.*$RELAY_PORT' > /dev/null && echo 'Relay running' || echo 'Relay failed'"
echo

#========================================
# Test 2: Through Nooshdaroo Tunnel
#========================================
echo -e "${BLUE}Test 2: Through Nooshdaroo Tunnel${NC}"
echo "Testing iperf3 through SOCKS5 tunnel to relay..."
echo

# Check if SOCKS proxy is running
if ! nc -z 127.0.0.1 1080 2>/dev/null; then
    echo -e "${RED}Error: Nooshdaroo client not running on port 1080${NC}"
    exit 1
fi

# We'll use proxychains or similar to route iperf3 through SOCKS5
# Since iperf3 doesn't support SOCKS directly, we'll test with curl instead
echo "Testing throughput through tunnel with large file download..."

# Download test through proxy (using a local relay)
TUNNEL_START=$(date +%s%N)
# Create a 100MB test file on server
ssh $SERVER "dd if=/dev/zero of=/tmp/100mb.dat bs=1M count=100 2>/dev/null"

# Start simple HTTP server on relay port
ssh $SERVER "pkill -f 'python.*SimpleHTTPServer'; cd /tmp && python3 -m http.server $RELAY_PORT 2>&1 > /dev/null &" &
sleep 2

echo "Downloading 100MB through tunnel..."
curl -x socks5://127.0.0.1:1080 \
     http://127.0.0.1:$RELAY_PORT/100mb.dat \
     --max-time 60 \
     --silent \
     --output /dev/null 2>&1

TUNNEL_END=$(date +%s%N)
TUNNEL_TIME=$(echo "scale=3; ($TUNNEL_END - $TUNNEL_START) / 1000000000" | bc)
TUNNEL_MBPS=$(echo "scale=2; (100 * 8) / $TUNNEL_TIME" | bc)

echo -e "  ${GREEN}${TUNNEL_MBPS} Mbps${NC} (100 MB in ${TUNNEL_TIME}s)"
echo

#========================================
# Test 3: Calculate Overhead
#========================================
echo -e "${BLUE}Test 3: Performance Analysis${NC}"
echo

# Calculate average direct speed
AVG_DIRECT=$(echo "scale=2; ($DIRECT_DOWN_MBPS + $DIRECT_UP_MBPS) / 2" | bc)

# Calculate overhead
OVERHEAD_PCT=$(echo "scale=2; 100 - ($TUNNEL_MBPS / $AVG_DIRECT * 100)" | bc)
EFFICIENCY=$(echo "scale=2; ($TUNNEL_MBPS / $AVG_DIRECT * 100)" | bc)

echo -e "  Direct average:      ${GREEN}${AVG_DIRECT} Mbps${NC}"
echo -e "  Tunneled:            ${GREEN}${TUNNEL_MBPS} Mbps${NC}"
echo -e "  Overhead:            ${YELLOW}${OVERHEAD_PCT}%${NC}"
echo -e "  Efficiency:          ${GREEN}${EFFICIENCY}%${NC}"
echo

#========================================
# Cleanup
#========================================
echo "Cleaning up..."
ssh $SERVER "pkill -f 'relay.*$RELAY_PORT' 2>/dev/null; pkill -f 'python.*SimpleHTTPServer' 2>/dev/null; rm -f /tmp/100mb.dat"

#========================================
# Summary
#========================================
echo
echo -e "${BLUE}==========================================${NC}"
echo -e "${BLUE}              SUMMARY${NC}"
echo -e "${BLUE}==========================================${NC}"
echo

echo "Direct Connection (iperf3):"
echo "  ├─ Download: ${DIRECT_DOWN_MBPS} Mbps"
echo "  └─ Upload:   ${DIRECT_UP_MBPS} Mbps"
echo

echo "Through Nooshdaroo Tunnel:"
echo "  └─ Download: ${TUNNEL_MBPS} Mbps"
echo

echo "Performance Impact:"
echo "  ├─ Efficiency: ${EFFICIENCY}%"
echo "  └─ Overhead:   ${OVERHEAD_PCT}%"
echo

echo -e "${YELLOW}Comparison:${NC}"
echo -e "${YELLOW}  - WireGuard overhead: ~5-10%${NC}"
echo -e "${YELLOW}  - Nooshdaroo overhead: ~${OVERHEAD_PCT}%${NC}"
echo

echo -e "${GREEN}Benchmark complete!${NC}"
echo
