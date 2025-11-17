#!/bin/bash
#
# Nooshdaroo Performance Benchmark Suite
# Tests throughput, latency, CPU, and memory usage
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
SERVER="23.128.36.42:8443"
SOCKS_PORT="1080"
PROTOCOL="https"
TEST_DURATION=30  # seconds for throughput test
CLIENT_CONFIG="client.toml"

# Check if server is reachable
echo -e "${YELLOW}Checking test prerequisites...${NC}"
if ! nc -z 127.0.0.1 $SOCKS_PORT 2>/dev/null; then
    echo -e "${RED}Error: SOCKS proxy not running on port $SOCKS_PORT${NC}"
    echo "Please start the client first:"
    echo "  ./target/release/nooshdaroo client --config $CLIENT_CONFIG --server $SERVER --protocol $PROTOCOL"
    exit 1
fi
echo -e "${GREEN}✓ SOCKS proxy is running${NC}"
echo

#========================================
# Test 1: Throughput Test
#========================================
echo -e "${BLUE}Test 1: Throughput Measurement${NC}"
echo "Testing data transfer speed through the proxy..."
echo

# Create a test file (10MB)
TEST_FILE="/tmp/nooshdaroo_test_10mb.dat"
dd if=/dev/urandom of=$TEST_FILE bs=1M count=10 2>/dev/null

# Upload throughput test (using httpbin.org)
echo "Measuring upload throughput..."
UPLOAD_START=$(date +%s%N)
curl -x socks5://127.0.0.1:$SOCKS_PORT \
     -X POST \
     -F "file=@$TEST_FILE" \
     http://httpbin.org/post \
     --max-time 60 \
     --silent \
     --output /dev/null 2>&1
UPLOAD_END=$(date +%s%N)
UPLOAD_TIME=$(echo "scale=3; ($UPLOAD_END - $UPLOAD_START) / 1000000000" | bc)
UPLOAD_MBPS=$(echo "scale=2; (10 * 8) / $UPLOAD_TIME" | bc)

echo -e "  Upload: ${GREEN}${UPLOAD_MBPS} Mbps${NC} (10 MB in ${UPLOAD_TIME}s)"

# Download throughput test
echo "Measuring download throughput..."
DOWNLOAD_START=$(date +%s%N)
curl -x socks5://127.0.0.1:$SOCKS_PORT \
     http://httpbin.org/stream-bytes/10485760 \
     --max-time 60 \
     --silent \
     --output /dev/null 2>&1
DOWNLOAD_END=$(date +%s%N)
DOWNLOAD_TIME=$(echo "scale=3; ($DOWNLOAD_END - $DOWNLOAD_START) / 1000000000" | bc)
DOWNLOAD_MBPS=$(echo "scale=2; (10 * 8) / $DOWNLOAD_TIME" | bc)

echo -e "  Download: ${GREEN}${DOWNLOAD_MBPS} Mbps${NC} (10 MB in ${DOWNLOAD_TIME}s)"
echo

#========================================
# Test 2: Latency Measurement
#========================================
echo -e "${BLUE}Test 2: Latency Measurement${NC}"
echo "Testing round-trip time through the proxy..."
echo

# Measure latency with 20 requests
LATENCIES=()
for i in {1..20}; do
    START=$(date +%s%N)
    curl -x socks5://127.0.0.1:$SOCKS_PORT \
         http://httpbin.org/uuid \
         --max-time 10 \
         --silent \
         --output /dev/null 2>&1
    END=$(date +%s%N)
    LATENCY=$(echo "scale=2; ($END - $START) / 1000000" | bc)  # Convert to milliseconds
    LATENCIES+=($LATENCY)
    printf "."
done
echo

# Calculate statistics
MIN_LAT=$(printf '%s\n' "${LATENCIES[@]}" | sort -n | head -1)
MAX_LAT=$(printf '%s\n' "${LATENCIES[@]}" | sort -n | tail -1)
AVG_LAT=$(printf '%s\n' "${LATENCIES[@]}" | awk '{sum+=$1} END {printf "%.2f", sum/NR}')

echo -e "  Min latency: ${GREEN}${MIN_LAT} ms${NC}"
echo -e "  Max latency: ${YELLOW}${MAX_LAT} ms${NC}"
echo -e "  Avg latency: ${GREEN}${AVG_LAT} ms${NC}"
echo

#========================================
# Test 3: Memory Usage
#========================================
echo -e "${BLUE}Test 3: Memory Usage${NC}"
echo "Measuring client process memory consumption..."
echo

# Find the nooshdaroo client process
CLIENT_PID=$(pgrep -f "nooshdaroo.*client" | head -1)
if [ -z "$CLIENT_PID" ]; then
    echo -e "${RED}Error: Could not find client process${NC}"
else
    # Get memory usage (RSS - Resident Set Size)
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        MEM_KB=$(ps -o rss= -p $CLIENT_PID)
        MEM_MB=$(echo "scale=2; $MEM_KB / 1024" | bc)
    else
        # Linux
        MEM_KB=$(ps -o rss= -p $CLIENT_PID)
        MEM_MB=$(echo "scale=2; $MEM_KB / 1024" | bc)
    fi
    echo -e "  Client baseline memory: ${GREEN}${MEM_MB} MB${NC}"

    # Test with concurrent connections
    echo "  Testing with 10 concurrent connections..."
    for i in {1..10}; do
        curl -x socks5://127.0.0.1:$SOCKS_PORT http://httpbin.org/delay/2 --max-time 30 --silent --output /dev/null &
    done
    sleep 1

    if [[ "$OSTYPE" == "darwin"* ]]; then
        MEM_LOAD_KB=$(ps -o rss= -p $CLIENT_PID)
        MEM_LOAD_MB=$(echo "scale=2; $MEM_LOAD_KB / 1024" | bc)
    else
        MEM_LOAD_KB=$(ps -o rss= -p $CLIENT_PID)
        MEM_LOAD_MB=$(echo "scale=2; $MEM_LOAD_KB / 1024" | bc)
    fi
    echo -e "  With 10 connections: ${GREEN}${MEM_LOAD_MB} MB${NC}"

    # Wait for background jobs to finish
    wait
fi
echo

#========================================
# Test 4: CPU Usage
#========================================
echo -e "${BLUE}Test 4: CPU Usage${NC}"
echo "Measuring client process CPU utilization..."
echo

if [ -z "$CLIENT_PID" ]; then
    echo -e "${RED}Error: Could not find client process${NC}"
else
    # Get CPU usage
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS - get CPU percentage
        CPU_IDLE=$(ps -p $CLIENT_PID -o %cpu= | awk '{print $1}')
        echo -e "  Idle CPU usage: ${GREEN}${CPU_IDLE}%${NC}"

        # Generate load
        echo "  Generating load with concurrent transfers..."
        for i in {1..5}; do
            curl -x socks5://127.0.0.1:$SOCKS_PORT http://httpbin.org/stream-bytes/1048576 --max-time 30 --silent --output /dev/null &
        done
        sleep 2
        CPU_LOAD=$(ps -p $CLIENT_PID -o %cpu= | awk '{print $1}')
        echo -e "  Under load CPU usage: ${GREEN}${CPU_LOAD}%${NC}"
        wait
    else
        # Linux
        CPU_IDLE=$(ps -p $CLIENT_PID -o %cpu= | awk '{print $1}')
        echo -e "  Idle CPU usage: ${GREEN}${CPU_IDLE}%${NC}"

        echo "  Generating load with concurrent transfers..."
        for i in {1..5}; do
            curl -x socks5://127.0.0.1:$SOCKS_PORT http://httpbin.org/stream-bytes/1048576 --max-time 30 --silent --output /dev/null &
        done
        sleep 2
        CPU_LOAD=$(ps -p $CLIENT_PID -o %cpu= | awk '{print $1}')
        echo -e "  Under load CPU usage: ${GREEN}${CPU_LOAD}%${NC}"
        wait
    fi
fi
echo

#========================================
# Test 5: Protocol Overhead
#========================================
echo -e "${BLUE}Test 5: Protocol Overhead${NC}"
echo "Comparing direct vs proxied connection..."
echo

# Direct connection latency
echo "Measuring direct connection latency..."
DIRECT_START=$(date +%s%N)
curl http://httpbin.org/uuid --max-time 10 --silent --output /dev/null 2>&1
DIRECT_END=$(date +%s%N)
DIRECT_LAT=$(echo "scale=2; ($DIRECT_END - $DIRECT_START) / 1000000" | bc)

# Proxied connection latency
echo "Measuring proxied connection latency..."
PROXY_START=$(date +%s%N)
curl -x socks5://127.0.0.1:$SOCKS_PORT http://httpbin.org/uuid --max-time 10 --silent --output /dev/null 2>&1
PROXY_END=$(date +%s%N)
PROXY_LAT=$(echo "scale=2; ($PROXY_END - $PROXY_START) / 1000000" | bc)

OVERHEAD=$(echo "scale=2; $PROXY_LAT - $DIRECT_LAT" | bc)

echo -e "  Direct latency: ${GREEN}${DIRECT_LAT} ms${NC}"
echo -e "  Proxied latency: ${GREEN}${PROXY_LAT} ms${NC}"
echo -e "  Overhead: ${YELLOW}${OVERHEAD} ms${NC}"
echo

#========================================
# Summary
#========================================
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}             SUMMARY${NC}"
echo -e "${BLUE}========================================${NC}"
echo
echo "Throughput:"
echo "  ├─ Upload:   $UPLOAD_MBPS Mbps"
echo "  └─ Download: $DOWNLOAD_MBPS Mbps"
echo
echo "Latency:"
echo "  ├─ Average: $AVG_LAT ms"
echo "  ├─ Min:     $MIN_LAT ms"
echo "  └─ Max:     $MAX_LAT ms"
echo
if [ ! -z "$CLIENT_PID" ]; then
    echo "Resource Usage (Client):"
    echo "  ├─ Memory (baseline):      $MEM_MB MB"
    echo "  ├─ Memory (10 connections): $MEM_LOAD_MB MB"
    echo "  ├─ CPU (idle):             $CPU_IDLE%"
    echo "  └─ CPU (under load):       $CPU_LOAD%"
    echo
fi
echo "Protocol Overhead:"
echo "  └─ Added latency: $OVERHEAD ms"
echo
echo -e "${GREEN}Benchmark complete!${NC}"
echo

# Cleanup
rm -f $TEST_FILE
