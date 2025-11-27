#!/usr/bin/env python3
"""
DNS Tunnel Test Script
Generates keys, creates configs, runs server + client, and tests with curl
"""

import subprocess
import time
import signal
import sys
import os
import tempfile

# ANSI colors for better output
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
BLUE = '\033[94m'
RESET = '\033[0m'

class DnsTunnelTester:
    def __init__(self):
        self.server_process = None
        self.client_process = None
        self.private_key = None
        self.public_key = None
        self.temp_dir = tempfile.mkdtemp()
        self.server_config_path = os.path.join(self.temp_dir, 'server.toml')
        self.client_config_path = os.path.join(self.temp_dir, 'client.toml')

    def log(self, msg, color=BLUE):
        print(f"{color}[DNS-TEST]{RESET} {msg}")

    def generate_keys(self):
        """Generate fresh Noise Protocol keypair"""
        self.log("Generating fresh Noise Protocol keypair...", YELLOW)

        result = subprocess.run(
            ['./target/release/nooshdaroo', 'genkey'],
            capture_output=True,
            text=True
        )

        # Try both stdout and stderr
        output = result.stdout + result.stderr

        for line in output.strip().split('\n'):
            if 'private key:' in line:
                self.private_key = line.split('private key:')[1].strip()
            elif 'public key:' in line:
                self.public_key = line.split('public key:')[1].strip()

        if not self.private_key or not self.public_key:
            self.log(f"Failed to generate keys! Output was: {output}", RED)
            sys.exit(1)

        self.log(f"Private key: {self.private_key[:20]}...", GREEN)
        self.log(f"Public key: {self.public_key[:20]}...", GREEN)

    def create_server_config(self):
        """Create server config with generated keys"""
        self.log(f"Creating server config: {self.server_config_path}", YELLOW)

        config = f"""mode = "server"

[encryption]
cipher = "cha-cha20-poly1305"
key_derivation = "argon2"
password = "test-dns-tunnel"

[shapeshift.strategy]
type = "fixed"
protocol = "dns-udp-tunnel"

[server]
listen_addr = "127.0.0.1:15353"

[transport]
pattern = "nk"
local_private_key = "{self.private_key}"

[detection]
enable_fingerprint_randomization = false
enable_timing_randomization = false
enable_tls_sni_masking = false
suspicion_threshold = 0.7
enable_decoy_traffic = false
decoy_traffic_rate = 0.1
enable_tls_session_emulation = true
"""

        with open(self.server_config_path, 'w') as f:
            f.write(config)

        self.log(f"Server config created", GREEN)

    def create_client_config(self):
        """Create client config with generated keys"""
        self.log(f"Creating client config: {self.client_config_path}", YELLOW)

        config = f"""mode = "client"

[encryption]
cipher = "cha-cha20-poly1305"
key_derivation = "argon2"
password = "test-dns-tunnel"

[shapeshift.strategy]
type = "fixed"
protocol = "dns-udp-tunnel"

[socks]
listen_addr = "127.0.0.1:1080"
server_address = "127.0.0.1:15353"
auth_required = false

[transport]
pattern = "nk"
remote_public_key = "{self.public_key}"

[detection]
enable_fingerprint_randomization = false
enable_timing_randomization = false
enable_tls_sni_masking = false
suspicion_threshold = 0.7
enable_decoy_traffic = false
decoy_traffic_rate = 0.1
enable_tls_session_emulation = true
"""

        with open(self.client_config_path, 'w') as f:
            f.write(config)

        self.log(f"Client config created", GREEN)

    def start_server(self):
        """Start DNS tunnel server"""
        self.log("Starting DNS tunnel server on UDP 127.0.0.1:15353...", YELLOW)

        self.server_process = subprocess.Popen(
            ['./target/release/nooshdaroo', '--config', self.server_config_path, 'server'],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        # Give server time to start
        time.sleep(2)

        if self.server_process.poll() is not None:
            self.log("Server failed to start!", RED)
            sys.exit(1)

        self.log("Server started successfully", GREEN)

    def start_client(self):
        """Start DNS tunnel client"""
        self.log("Starting DNS tunnel client (SOCKS5 on 127.0.0.1:1080)...", YELLOW)

        self.client_process = subprocess.Popen(
            ['./target/release/nooshdaroo', '--config', self.client_config_path, 'client'],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        # Give client time to connect
        time.sleep(3)

        if self.client_process.poll() is not None:
            self.log("Client failed to start!", RED)
            sys.exit(1)

        self.log("Client started successfully", GREEN)

    def test_tunnel(self):
        """Test DNS tunnel with curl"""
        self.log("Testing DNS tunnel with curl through SOCKS5 proxy...", YELLOW)

        result = subprocess.run(
            ['curl', '-x', 'socks5h://127.0.0.1:1080', 'https://www.google.com/',
             '-o', '/dev/null', '-s', '-w', 'HTTP Status: %{http_code}\\nSize: %{size_download} bytes\\nTime: %{time_total}s\\n',
             '--max-time', '15'],
            capture_output=True,
            text=True
        )

        self.log("=== Test Results ===", BLUE)
        print(result.stdout)

        if '200' in result.stdout:
            self.log("DNS tunnel test PASSED!", GREEN)
            return True
        else:
            self.log("DNS tunnel test FAILED!", RED)
            return False

    def cleanup(self):
        """Kill server and client processes"""
        self.log("Cleaning up processes...", YELLOW)

        if self.client_process:
            self.client_process.terminate()
            self.client_process.wait(timeout=5)
            self.log("Client stopped", GREEN)

        if self.server_process:
            self.server_process.terminate()
            self.server_process.wait(timeout=5)
            self.log("Server stopped", GREEN)

        # Clean up temp configs
        try:
            os.unlink(self.server_config_path)
            os.unlink(self.client_config_path)
            os.rmdir(self.temp_dir)
            self.log("Temporary configs cleaned up", GREEN)
        except Exception as e:
            self.log(f"Cleanup warning: {e}", YELLOW)

    def run(self):
        """Run complete test"""
        try:
            self.log("=== Starting DNS Tunnel Test ===", BLUE)
            self.log("Using 127.0.0.1 for all connections", BLUE)
            print()

            # Generate fresh keys
            self.generate_keys()
            print()

            # Create configs
            self.create_server_config()
            self.create_client_config()
            print()

            # Start server and client
            self.start_server()
            self.start_client()
            print()

            # Test tunnel
            success = self.test_tunnel()
            print()

            return success

        except KeyboardInterrupt:
            self.log("\\nTest interrupted by user", YELLOW)
            return False
        except Exception as e:
            self.log(f"Test failed with error: {e}", RED)
            import traceback
            traceback.print_exc()
            return False
        finally:
            self.cleanup()

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    print(f"\\n{YELLOW}[DNS-TEST]{RESET} Interrupted, cleaning up...")
    sys.exit(0)

if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)

    tester = DnsTunnelTester()
    success = tester.run()

    sys.exit(0 if success else 1)
