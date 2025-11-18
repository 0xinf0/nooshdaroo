#!/usr/bin/env python3
"""
Protocol Tester Client
Sends different protocol packets from Iran VM to analyze blocking patterns
"""

import socket
import time
import sys
import struct
import os

def test_protocol(host, port, proto, packet_type, data, timeout=5):
    """Send a test packet and measure response"""
    result = {
        'port': port,
        'proto': proto,
        'type': packet_type,
        'sent_bytes': len(data),
        'status': 'UNKNOWN',
        'recv_bytes': 0,
        'time_ms': 0
    }

    try:
        start = time.time()

        if proto == 'tcp':
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            sock.sendall(data)
            try:
                response = sock.recv(4096)
                result['recv_bytes'] = len(response)
                result['status'] = 'SUCCESS'
            except socket.timeout:
                result['status'] = 'NO_RESPONSE'
            sock.close()

        else:  # UDP
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(data, (host, port))
            try:
                response, addr = sock.recvfrom(4096)
                result['recv_bytes'] = len(response)
                result['status'] = 'SUCCESS'
            except socket.timeout:
                result['status'] = 'NO_RESPONSE'
            sock.close()

        result['time_ms'] = int((time.time() - start) * 1000)

    except ConnectionRefusedError:
        result['status'] = 'REFUSED'
    except socket.timeout:
        result['status'] = 'TIMEOUT'
    except Exception as e:
        result['status'] = f'ERROR:{str(e)[:30]}'

    return result

def make_dns_query(domain="google.com"):
    """Create a valid DNS query"""
    tid = os.urandom(2)
    flags = b'\x01\x00'  # Standard query
    qdcount = b'\x00\x01'  # 1 question
    ancount = b'\x00\x00'
    nscount = b'\x00\x00'
    arcount = b'\x00\x00'

    # Encode domain
    labels = domain.split('.')
    qname = b''
    for label in labels:
        qname += bytes([len(label)]) + label.encode()
    qname += b'\x00'

    qtype = b'\x00\x01'  # A record
    qclass = b'\x00\x01'  # IN class

    return tid + flags + qdcount + ancount + nscount + arcount + qname + qtype + qclass

def make_ssh_banner():
    """Create SSH protocol banner"""
    return b'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n'

def make_https_clienthello():
    """Create minimal TLS ClientHello"""
    # Simplified TLS 1.2 ClientHello
    content_type = b'\x16'  # Handshake
    version = b'\x03\x01'  # TLS 1.0 (for compatibility)
    length = b'\x00\x40'  # 64 bytes

    handshake_type = b'\x01'  # ClientHello
    hs_length = b'\x00\x00\x3c'  # 60 bytes
    client_version = b'\x03\x03'  # TLS 1.2
    random = os.urandom(32)
    session_id_len = b'\x00'
    cipher_suites_len = b'\x00\x02'
    cipher_suites = b'\x00\x2f'  # TLS_RSA_WITH_AES_128_CBC_SHA
    compression_methods_len = b'\x01'
    compression_methods = b'\x00'  # No compression

    handshake = handshake_type + hs_length + client_version + random + session_id_len + cipher_suites_len + cipher_suites + compression_methods_len + compression_methods

    return content_type + version + length + handshake[:64]

def run_tests(host):
    """Run comprehensive protocol tests"""
    print("="*70)
    print(f"Protocol Analysis from Iran VM to {host}")
    print("="*70)

    tests = []

    # DNS Tests
    print("\n[1] DNS Protocol Tests")
    dns_query = make_dns_query()
    dns_tcp = struct.pack('!H', len(dns_query)) + dns_query  # Add length prefix for TCP

    tests.append(('DNS TCP', test_protocol(host, 53, 'tcp', 'DNS_QUERY', dns_tcp)))
    time.sleep(0.5)
    tests.append(('DNS UDP', test_protocol(host, 53, 'udp', 'DNS_QUERY', dns_query)))
    time.sleep(0.5)
    tests.append(('DNS TCP (random)', test_protocol(host, 53, 'tcp', 'RANDOM', os.urandom(64))))
    time.sleep(0.5)
    tests.append(('DNS UDP (random)', test_protocol(host, 53, 'udp', 'RANDOM', os.urandom(64))))
    time.sleep(0.5)

    # SSH Tests
    print("\n[2] SSH Protocol Tests")
    ssh_banner = make_ssh_banner()
    tests.append(('SSH:22 TCP', test_protocol(host, 22, 'tcp', 'SSH_BANNER', ssh_banner)))
    time.sleep(0.5)
    tests.append(('SSH:22 (random)', test_protocol(host, 22, 'tcp', 'RANDOM', os.urandom(64))))
    time.sleep(0.5)
    tests.append(('SSH:2222 TCP', test_protocol(host, 2222, 'tcp', 'SSH_BANNER', ssh_banner)))
    time.sleep(0.5)

    # HTTPS Tests
    print("\n[3] HTTPS Protocol Tests")
    tls_hello = make_https_clienthello()
    tests.append(('HTTPS:443', test_protocol(host, 443, 'tcp', 'TLS_HELLO', tls_hello)))
    time.sleep(0.5)
    tests.append(('HTTPS:443 (random)', test_protocol(host, 443, 'tcp', 'RANDOM', os.urandom(64))))
    time.sleep(0.5)
    tests.append(('HTTPS:8443', test_protocol(host, 8443, 'tcp', 'TLS_HELLO', tls_hello)))
    time.sleep(0.5)

    # Print Results
    print("\n" + "="*70)
    print("RESULTS SUMMARY")
    print("="*70)
    print(f"{'Protocol':<20} {'Status':<15} {'Sent':<8} {'Recv':<8} {'Time(ms)':<10}")
    print("-"*70)

    success_count = 0
    for name, result in tests:
        status_color = result['status']
        if result['status'] == 'SUCCESS':
            success_count += 1

        print(f"{name:<20} {result['status']:<15} {result['sent_bytes']:<8} {result['recv_bytes']:<8} {result['time_ms']:<10}")

    print("="*70)
    print(f"Success Rate: {success_count}/{len(tests)} ({100*success_count//len(tests)}%)")

    # Analysis
    print("\n" + "="*70)
    print("ANALYSIS")
    print("="*70)

    dns_tcp_works = tests[0][1]['status'] == 'SUCCESS'
    dns_udp_works = tests[1][1]['status'] == 'SUCCESS'
    dns_tcp_rand = tests[2][1]['status'] == 'SUCCESS'

    if dns_udp_works and not dns_tcp_works:
        print("✓ DNS UDP works, TCP DNS fails → Iran blocks TCP on port 53")
    elif dns_tcp_works and not dns_tcp_rand:
        print("✓ Valid DNS works, random fails → DPI validates DNS packet structure")
    elif dns_tcp_works and dns_tcp_rand:
        print("✓ Both valid and random DNS work → Port 53 TCP is open")

    ssh_works = tests[4][1]['status'] == 'SUCCESS'
    ssh_rand = tests[5][1]['status'] == 'SUCCESS'

    if ssh_works and not ssh_rand:
        print("✓ SSH banner works, random fails → DPI validates SSH protocol")
    elif ssh_works and ssh_rand:
        print("✓ Both SSH banner and random work → Port 22 TCP is open")

    https_works = tests[7][1]['status'] == 'SUCCESS'
    https_rand = tests[8][1]['status'] == 'SUCCESS'

    if https_works and not https_rand:
        print("✓ TLS hello works, random fails → DPI validates TLS handshake")
    elif https_works and https_rand:
        print("✓ Both TLS and random work → Port 443 TCP is open")

    # Save results
    log_file = f"/tmp/protocol_test_{int(time.time())}.log"
    with open(log_file, 'w') as f:
        f.write("protocol,status,sent_bytes,recv_bytes,time_ms\n")
        for name, result in tests:
            f.write(f"{name},{result['status']},{result['sent_bytes']},{result['recv_bytes']},{result['time_ms']}\n")

    print(f"\nResults saved to: {log_file}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 protocol_tester_client.py <server_ip>")
        sys.exit(1)

    run_tests(sys.argv[1])
