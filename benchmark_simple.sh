#!/bin/bash
#
# Simple Nooshdaroo Performance Benchmark
# Tests actual throughput with direct comparison
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}   Nooshdaroo Performance Benchmark${NC}"
echo -e "${BLUE}========================================${NC}"
echo

# Configuration
SERVER="23.128.36.42"
TEST_SIZE_MB=50

#========================================
# Test 1: Direct iperf3 Baseline
#========================================
echo -e "${BLUE}Test 1: Direct Connection Baseline (iperf3)${NC}"
echo "Measuring throughput without any proxy..."
echo

# Download test (server -> client)
echo "Download test (10 seconds)..."
DIRECT_DOWN=$(iperf3 -c $SERVER -t 10 2>&1 | grep "receiver" | awk '{print $(NF-2), $(NF-1)}')
echo -e "  Direct download: ${GREEN}${DIRECT_DOWN}${NC}"

# Upload test (client -> server)
echo "Upload test (10 seconds)..."
DIRECT_UP=$(iperf3 -c $SERVER -t 10 -R 2>&1 | grep "receiver" | awk '{print $(NF-2), $(NF-1)}')
echo -e "  Direct upload: ${GREEN}${DIRECT_UP}${NC}"
echo

#========================================
# Test 2: Proxied Transfer Test
#========================================
echo -e "${BLUE}Test 2: Proxied Transfer (via Nooshdaroo)${NC}"
echo "Testing large file transfer through SOCKS5 proxy..."
echo

# Check if proxy is running
if ! nc -z 127.0.0.1 1080 2>/dev/null; then
    echo -e "${RED}Error: SOCKS proxy not running on port 1080${NC}"
    exit 1
fi

# Test download speed through proxy using curl
echo "Testing download speed (${TEST_SIZE_MB}MB)..."
PROXY_DOWN_START=$(date +%s%N)
curl -x socks5://127.0.0.1:1080 \
     http://speedtest.tele2.net/50MB.zip \
     --max-time 120 \
     --silent \
     --output /dev/null 2>&1
PROXY_DOWN_END=$(date +%s%N)
PROXY_DOWN_TIME=$(echo "scale=3; ($PROXY_DOWN_END - $PROXY_DOWN_START) / 1000000000" | bc)
PROXY_DOWN_MBPS=$(echo "scale=2; (${TEST_SIZE_MB} * 8) / $PROXY_DOWN_TIME" | bc)

echo -e "  Proxied download: ${GREEN}${PROXY_DOWN_MBPS} Mbps${NC} (${TEST_SIZE_MB} MB in ${PROXY_DOWN_TIME}s)"

#========================================
# Test 3: Latency Comparison
#========================================
echo
echo -e "${BLUE}Test 3: Latency Comparison${NC}"
echo

# Direct latency (ping)
echo "Direct latency (ping)..."
DIRECT_LAT=$(ping -c 5 $SERVER 2>&1 | tail -1 | awk -F'/' '{print $5}' | awk '{print $1}')
echo -e "  Direct ping: ${GREEN}${DIRECT_LAT} ms${NC}"

# Proxied latency (HTTP request)
echo "Proxied HTTP request latency..."
PROXY_LATS=()
for i in {1..5}; do
    START=$(date +%s%N)
    curl -x socks5://127.0.0.1:1080 \
         http://httpbin.org/uuid \
         --max-time 10 \
         --silent \
         --output /dev/null 2>&1
    END=$(date +%s%N)
    LAT=$(echo "scale=2; ($END - $START) / 1000000" | bc)
    PROXY_LATS+=($LAT)
    printf "."
done
echo

PROXY_AVG=$(printf '%s\n' "${PROXY_LATS[@]}" | awk '{sum+=$1} END {printf "%.2f", sum/NR}')
echo -e "  Proxied avg: ${GREEN}${PROXY_AVG} ms${NC}"

#========================================
# Summary
#========================================
echo
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}             SUMMARY${NC}"
echo -e "${BLUE}========================================${NC}"
echo

echo "Direct Connection (iperf3):"
echo "  ├─ Download: ${DIRECT_DOWN}"
echo "  └─ Upload:   ${DIRECT_UP}"
echo

echo "Proxied Through Nooshdaroo:"
echo "  └─ Download: ${PROXY_DOWN_MBPS} Mbps"
echo

echo "Latency:"
echo "  ├─ Direct ping:   ${DIRECT_LAT} ms"
echo "  └─ Proxied HTTP:  ${PROXY_AVG} ms"
echo

echo -e "${YELLOW}Note: These benchmarks test different scenarios:${NC}"
echo -e "${YELLOW}  - iperf3 measures pure network throughput${NC}"
echo -e "${YELLOW}  - Proxied tests measure real-world HTTP performance${NC}"
echo -e "${YELLOW}  - Results depend heavily on network conditions${NC}"
echo

echo -e "${GREEN}Benchmark complete!${NC}"
echo
