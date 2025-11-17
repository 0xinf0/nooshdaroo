#!/bin/bash
#
# Comprehensive nDPI Protocol Test Suite
# Tests multiple protocols (HTTPS, DNS, SSH, QUIC) against nDPI
#
# Usage: ./test_all_protocols_ndpi.sh
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

SERVER="23.128.36.42:8443"
CLIENT_IP="76.219.237.144"

echo "========================================="
echo "  Nooshdaroo nDPI Protocol Test Suite"
echo "========================================="
echo "Date: $(date)"
echo "Server: $SERVER"
echo

# Kill any running processes
echo "[1/5] Cleaning up..."
pkill -9 -f "nooshdaroo" 2>/dev/null || true
ssh red-s-0001 'sudo pkill -9 nooshdaroo; sudo pkill tcpdump; sudo pkill ndpiReader' 2>/dev/null || true
sleep 2
echo -e "${GREEN}✓${NC} Cleanup complete"
echo

# Test function
test_protocol() {
    local PROTOCOL=$1
    local EXPECTED=$2

    echo "--------------------"
    echo "Testing: $PROTOCOL"
    echo "--------------------"

    # Start server
    echo "  [1/5] Starting server..."
    ssh red-s-0001 "cd /root/Nooshdaroo && ./target/release/nooshdaroo -vv --config server.toml server" > /tmp/server_${PROTOCOL}.log 2>&1 &
    sleep 4

    # Start packet capture
    echo "  [2/5] Starting packet capture..."
    ssh red-s-0001 "rm -f /tmp/${PROTOCOL}_test.pcap && sudo tcpdump -i enp1s0f1np1 -s 0 -w /tmp/${PROTOCOL}_test.pcap 'port 8443 and host $CLIENT_IP'" > /tmp/tcpdump_${PROTOCOL}.log 2>&1 &
    sleep 2

    # Start client and generate traffic
    echo "  [3/5] Generating traffic..."
    ./target/release/nooshdaroo -vv --config client.toml client --server $SERVER --protocol $PROTOCOL > /tmp/client_${PROTOCOL}.log 2>&1 &
    sleep 5
    curl -x socks5://127.0.0.1:1080 http://httpbin.org/uuid --max-time 10 > /dev/null 2>&1 || true
    sleep 2

    # Stop capture
    echo "  [4/5] Stopping capture..."
    ssh red-s-0001 'sudo pkill tcpdump' || true
    sleep 1

    # Analyze with nDPI
    echo "  [5/5] Analyzing with nDPI..."
    RESULT=$(ssh red-s-0001 "cd /root/nDPI/example && sudo ./ndpiReader -i /tmp/${PROTOCOL}_test.pcap 2>&1 | grep 'Detected protocols:' -A 1 | tail -1")

    # Check result
    if echo "$RESULT" | grep -q "$EXPECTED"; then
        echo -e "  ${GREEN}✓ PASS${NC} - Detected as: $EXPECTED"
        echo "$RESULT"
        echo "1" > /tmp/test_${PROTOCOL}_result.txt
    else
        echo -e "  ${RED}✗ FAIL${NC} - Expected: $EXPECTED, Got: $RESULT"
        echo "0" > /tmp/test_${PROTOCOL}_result.txt
    fi

    # Cleanup
    pkill -f "nooshdaroo.*client" 2>/dev/null || true
    ssh red-s-0001 'sudo pkill -9 nooshdaroo' 2>/dev/null || true
    sleep 2
    echo
}

# Run tests
echo "Running protocol tests..."
echo

test_protocol "https" "Google"
test_protocol "dns" "DNS"
# test_protocol "ssh" "SSH"  # If you have SSH protocol
# test_protocol "quic" "QUIC" # If you have QUIC protocol

# Summary
echo "========================================="
echo "  Test Summary"
echo "========================================="

TOTAL=0
PASSED=0

for RESULT_FILE in /tmp/test_*_result.txt; do
    if [ -f "$RESULT_FILE" ]; then
        TOTAL=$((TOTAL + 1))
        RESULT=$(cat "$RESULT_FILE")
        if [ "$RESULT" = "1" ]; then
            PASSED=$((PASSED + 1))
        fi
    fi
done

echo "Total Tests: $TOTAL"
echo -e "Passed: ${GREEN}$PASSED${NC}"
echo "Failed: $((TOTAL - PASSED))"

if [ $PASSED -eq $TOTAL ]; then
    echo -e "\n${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "\n${RED}Some tests failed${NC}"
    exit 1
fi
