#!/bin/bash
#
# Nooshdaroo Performance Benchmark with iperf3
# Compares direct connection vs proxied connection throughput
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}   Nooshdaroo iperf3 Benchmark${NC}"
echo -e "${BLUE}========================================${NC}"
echo

# Configuration
SERVER="23.128.36.42"
SOCKS_PORT="1080"
IPERF_PORT="5201"
TEST_DURATION=10  # seconds per test

# Check if iperf3 is installed
if ! command -v iperf3 &> /dev/null; then
    echo -e "${RED}Error: iperf3 is not installed${NC}"
    echo "Install with: brew install iperf3 (macOS) or apt install iperf3 (Linux)"
    exit 1
fi

# Check if SOCKS proxy is running
echo -e "${YELLOW}Checking prerequisites...${NC}"
if ! nc -z 127.0.0.1 $SOCKS_PORT 2>/dev/null; then
    echo -e "${RED}Error: SOCKS proxy not running on port $SOCKS_PORT${NC}"
    echo "Please start the client first:"
    echo "  ./target/release/nooshdaroo client --config client.toml --server $SERVER:8443 --protocol https"
    exit 1
fi
echo -e "${GREEN}✓ SOCKS proxy is running${NC}"

# Check if iperf3 server is running on remote
echo "Checking if iperf3 server is running on $SERVER..."
if ! nc -z $SERVER $IPERF_PORT 2>/dev/null; then
    echo -e "${RED}Error: iperf3 server not running on $SERVER:$IPERF_PORT${NC}"
    echo "Please start iperf3 server on the remote host:"
    echo "  ssh $SERVER 'iperf3 -s -D'"
    exit 1
fi
echo -e "${GREEN}✓ iperf3 server is running${NC}"
echo

#========================================
# Test 1: Direct Connection Throughput
#========================================
echo -e "${BLUE}Test 1: Direct Connection Baseline${NC}"
echo "Measuring throughput without proxy..."
echo

# Download test (server -> client)
echo "Testing download speed (direct)..."
DIRECT_DOWN=$(iperf3 -c $SERVER -t $TEST_DURATION -J 2>/dev/null | grep -o '"bits_per_second":[0-9.]*' | head -1 | cut -d: -f2)
DIRECT_DOWN_MBPS=$(echo "scale=2; $DIRECT_DOWN / 1000000" | bc)
echo -e "  Direct download: ${GREEN}${DIRECT_DOWN_MBPS} Mbps${NC}"

# Upload test (client -> server)
echo "Testing upload speed (direct)..."
DIRECT_UP=$(iperf3 -c $SERVER -t $TEST_DURATION -R -J 2>/dev/null | grep -o '"bits_per_second":[0-9.]*' | head -1 | cut -d: -f2)
DIRECT_UP_MBPS=$(echo "scale=2; $DIRECT_UP / 1000000" | bc)
echo -e "  Direct upload: ${GREEN}${DIRECT_UP_MBPS} Mbps${NC}"
echo

#========================================
# Test 2: Proxied Connection Throughput
#========================================
echo -e "${BLUE}Test 2: Proxied Connection Through Nooshdaroo${NC}"
echo "Measuring throughput through SOCKS5 proxy..."
echo

# Download test through proxy
echo "Testing download speed (proxied)..."
PROXY_DOWN=$(iperf3 -c $SERVER -t $TEST_DURATION --socks5 127.0.0.1:$SOCKS_PORT -J 2>/dev/null | grep -o '"bits_per_second":[0-9.]*' | head -1 | cut -d: -f2)
PROXY_DOWN_MBPS=$(echo "scale=2; $PROXY_DOWN / 1000000" | bc)
echo -e "  Proxied download: ${GREEN}${PROXY_DOWN_MBPS} Mbps${NC}"

# Upload test through proxy
echo "Testing upload speed (proxied)..."
PROXY_UP=$(iperf3 -c $SERVER -t $TEST_DURATION -R --socks5 127.0.0.1:$SOCKS_PORT -J 2>/dev/null | grep -o '"bits_per_second":[0-9.]*' | head -1 | cut -d: -f2)
PROXY_UP_MBPS=$(echo "scale=2; $PROXY_UP / 1000000" | bc)
echo -e "  Proxied upload: ${GREEN}${PROXY_UP_MBPS} Mbps${NC}"
echo

#========================================
# Test 3: Calculate Overhead
#========================================
echo -e "${BLUE}Test 3: Performance Overhead Analysis${NC}"
echo

# Download overhead
DOWN_OVERHEAD=$(echo "scale=2; 100 - ($PROXY_DOWN / $DIRECT_DOWN * 100)" | bc)
echo -e "  Download overhead: ${YELLOW}${DOWN_OVERHEAD}%${NC}"

# Upload overhead
UP_OVERHEAD=$(echo "scale=2; 100 - ($PROXY_UP / $DIRECT_UP * 100)" | bc)
echo -e "  Upload overhead: ${YELLOW}${UP_OVERHEAD}%${NC}"
echo

#========================================
# Summary
#========================================
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}             SUMMARY${NC}"
echo -e "${BLUE}========================================${NC}"
echo

echo "Direct Connection:"
echo "  ├─ Download: ${DIRECT_DOWN_MBPS} Mbps"
echo "  └─ Upload:   ${DIRECT_UP_MBPS} Mbps"
echo

echo "Through Nooshdaroo Proxy:"
echo "  ├─ Download: ${PROXY_DOWN_MBPS} Mbps"
echo "  └─ Upload:   ${PROXY_UP_MBPS} Mbps"
echo

echo "Performance Overhead:"
echo "  ├─ Download: ${DOWN_OVERHEAD}%"
echo "  └─ Upload:   ${UP_OVERHEAD}%"
echo

# Compare to WireGuard typical overhead (5-10%)
echo -e "${YELLOW}Note: WireGuard typically adds 5-10% overhead${NC}"
echo -e "${YELLOW}Nooshdaroo adds protocol wrapping + Noise encryption${NC}"
echo

echo -e "${GREEN}Benchmark complete!${NC}"
echo
