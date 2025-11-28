#!/bin/bash
# Nooshdaroo Protocol Benchmark Script
# Tests all supported protocols with 100MB file download
# Server and client bind to 127.0.0.1

set -e

# Keys for testing
PRIVATE_KEY="FPuZ4N2FhEg6VF7PzgSup2+87gnhpiEG0/4/Fhw9akw="
PUBLIC_KEY="+jIjeirgxTa1QGiujHnlMN2dr3Ks6xYzhnpuZ/E+NmY="

# Test URL - 100MB file from nooshdaroo.net
TEST_URL="https://nooshdaroo.net/100MB"
SOCKS_PORT=10080
SERVER_PORT=18443

RESULTS_FILE="benchmark_results.txt"

echo "=== Nooshdaroo Protocol Benchmark ===" | tee $RESULTS_FILE
echo "Date: $(date)" | tee -a $RESULTS_FILE
echo "Test URL: $TEST_URL" | tee -a $RESULTS_FILE
echo "" | tee -a $RESULTS_FILE

# List of protocols to test (TCP-based only)
PROTOCOLS=(
    "https"
    "https_google_com"
    "tls_simple"
    "tls13_complete"
    "ssh"
    "tls13"
)

# Function to create server config
create_server_config() {
    local protocol=$1
    cat > server-bench.toml << EOF
mode = "server"

[encryption]
cipher = "cha-cha20-poly1305"
key_derivation = "argon2"

[socks]
listen_addr = "127.0.0.1:$SOCKS_PORT"
auth_required = false

[shapeshift]
strategy = { type = "fixed", protocol = "$protocol" }

[server]
listen_addr = "127.0.0.1:$SERVER_PORT"

[transport]
local_private_key = "$PRIVATE_KEY"
EOF
}

# Function to create client config
create_client_config() {
    local protocol=$1
    cat > client-bench.toml << EOF
mode = "client"

[encryption]
cipher = "cha-cha20-poly1305"
key_derivation = "argon2"

[socks]
listen_addr = "127.0.0.1:$SOCKS_PORT"
server_address = "127.0.0.1:$SERVER_PORT"
auth_required = false

[shapeshift]
strategy = { type = "fixed", protocol = "$protocol" }

[transport]
remote_public_key = "$PUBLIC_KEY"
EOF
}

# Function to run benchmark
run_benchmark() {
    local protocol=$1

    echo "Testing protocol: $protocol" | tee -a $RESULTS_FILE

    # Create configs
    create_server_config "$protocol"
    create_client_config "$protocol"

    # Kill any existing processes
    pkill -9 nooshdaroo 2>/dev/null || true
    sleep 1

    # Start server
    ./target/release/nooshdaroo -c server-bench.toml server &
    SERVER_PID=$!
    sleep 2

    # Start client
    ./target/release/nooshdaroo -c client-bench.toml client &
    CLIENT_PID=$!
    sleep 3

    # Run download test (3 runs)
    echo "  Running 3 downloads..." | tee -a $RESULTS_FILE

    total_speed=0
    for i in 1 2 3; do
        speed=$(curl -x socks5h://127.0.0.1:$SOCKS_PORT -o /dev/null -w "%{speed_download}" "$TEST_URL" 2>/dev/null || echo "0")
        speed_mb=$(echo "scale=2; $speed / 1048576" | bc)
        echo "    Run $i: ${speed_mb} MB/s" | tee -a $RESULTS_FILE
        total_speed=$(echo "$total_speed + $speed" | bc)
    done

    avg_speed=$(echo "scale=2; $total_speed / 3 / 1048576" | bc)
    echo "  Average: ${avg_speed} MB/s" | tee -a $RESULTS_FILE
    echo "" | tee -a $RESULTS_FILE

    # Cleanup
    kill $SERVER_PID $CLIENT_PID 2>/dev/null || true
    sleep 1
}

# First, get baseline (direct connection)
echo "=== Baseline (Direct Connection) ===" | tee -a $RESULTS_FILE
total_speed=0
for i in 1 2 3; do
    speed=$(curl -o /dev/null -w "%{speed_download}" "$TEST_URL" 2>/dev/null || echo "0")
    speed_mb=$(echo "scale=2; $speed / 1048576" | bc)
    echo "  Run $i: ${speed_mb} MB/s" | tee -a $RESULTS_FILE
    total_speed=$(echo "$total_speed + $speed" | bc)
done
baseline_avg=$(echo "scale=2; $total_speed / 3 / 1048576" | bc)
echo "Baseline Average: ${baseline_avg} MB/s" | tee -a $RESULTS_FILE
echo "" | tee -a $RESULTS_FILE

# Run tests for each protocol
echo "=== Protocol Tests ===" | tee -a $RESULTS_FILE
for protocol in "${PROTOCOLS[@]}"; do
    run_benchmark "$protocol"
done

# Cleanup
pkill -9 nooshdaroo 2>/dev/null || true
rm -f server-bench.toml client-bench.toml

echo "=== Benchmark Complete ===" | tee -a $RESULTS_FILE
echo "Results saved to $RESULTS_FILE"
