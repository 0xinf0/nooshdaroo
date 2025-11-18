#!/usr/bin/env python3
"""
DNS Blocking Analysis Tool
Tests various DNS traffic patterns to reverse-engineer Iran's DPI blocking
"""

import socket
import time
import sys
import struct

def test_tcp_echo(host, port=53):
    """Test 1: Raw TCP connection - can we even connect?"""
    print(f"\n[TEST 1] Raw TCP Echo Test to {host}:{port}")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        start = time.time()
        sock.connect((host, port))
        connect_time = time.time() - start
        print(f"✓ TCP connection established ({connect_time:.3f}s)")

        # Send simple data
        sock.sendall(b"HELLO_WORLD_TEST\n")
        print("✓ Sent 17 bytes")

        # Try to receive
        sock.settimeout(3)
        try:
            data = sock.recv(1024)
            print(f"✓ Received {len(data)} bytes: {data[:50]}")
        except socket.timeout:
            print("✗ No response received (timeout)")

        sock.close()
        return True
    except Exception as e:
        print(f"✗ Connection failed: {e}")
        return False

def test_real_dns_query(host, port=53):
    """Test 2: Send a legitimate DNS query over TCP"""
    print(f"\n[TEST 2] Real DNS Query (TCP) to {host}:{port}")
    try:
        # Construct DNS query for google.com A record
        transaction_id = b'\xaa\xbb'
        flags = b'\x01\x00'  # Standard query
        questions = b'\x00\x01'  # 1 question
        answers = b'\x00\x00'  # 0 answers
        authority = b'\x00\x00'  # 0 authority
        additional = b'\x00\x00'  # 0 additional

        # QNAME: google.com
        qname = b'\x06google\x03com\x00'
        qtype = b'\x00\x01'  # A record
        qclass = b'\x00\x01'  # IN class

        dns_query = transaction_id + flags + questions + answers + authority + additional + qname + qtype + qclass

        # TCP DNS requires 2-byte length prefix
        tcp_dns_query = struct.pack('!H', len(dns_query)) + dns_query

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        print(f"✓ Connected")

        sock.sendall(tcp_dns_query)
        print(f"✓ Sent valid DNS query ({len(tcp_dns_query)} bytes)")

        # Try to receive response
        sock.settimeout(3)
        try:
            length_data = sock.recv(2)
            if len(length_data) == 2:
                response_length = struct.unpack('!H', length_data)[0]
                print(f"✓ Received length prefix: {response_length} bytes expected")
                response = sock.recv(response_length)
                print(f"✓ Received DNS response: {len(response)} bytes")
                print(f"  Response data: {response[:20].hex()}")
        except socket.timeout:
            print("✗ No DNS response (timeout)")

        sock.close()
        return True
    except Exception as e:
        print(f"✗ Failed: {e}")
        return False

def test_fake_dns_query(host, port=53):
    """Test 3: Send DNS-looking query with random payload"""
    print(f"\n[TEST 3] Fake DNS Query (random payload) to {host}:{port}")
    try:
        # DNS header with random payload
        transaction_id = b'\xde\xad'
        flags = b'\x01\x00'
        questions = b'\x00\x01'
        answers = b'\x00\x00'
        authority = b'\x00\x00'
        additional = b'\x00\x00'

        # Random payload disguised as QNAME
        fake_qname = b'\x20' + b'A' * 32 + b'\x00'  # Suspiciously long label
        qtype = b'\x00\x01'
        qclass = b'\x00\x01'

        dns_query = transaction_id + flags + questions + answers + authority + additional + fake_qname + qtype + qclass
        tcp_dns_query = struct.pack('!H', len(dns_query)) + dns_query

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        print(f"✓ Connected")

        sock.sendall(tcp_dns_query)
        print(f"✓ Sent fake DNS query ({len(tcp_dns_query)} bytes)")

        sock.settimeout(3)
        try:
            data = sock.recv(1024)
            print(f"✓ Received response: {len(data)} bytes")
        except socket.timeout:
            print("✗ No response (timeout)")

        sock.close()
        return True
    except Exception as e:
        print(f"✗ Failed: {e}")
        return False

def test_encrypted_payload(host, port=53):
    """Test 4: Send encrypted-looking data"""
    print(f"\n[TEST 4] Encrypted Payload Test to {host}:{port}")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        print(f"✓ Connected")

        # Send high-entropy data (looks encrypted)
        import os
        encrypted_data = os.urandom(256)
        sock.sendall(encrypted_data)
        print(f"✓ Sent {len(encrypted_data)} bytes of random data")

        sock.settimeout(3)
        try:
            data = sock.recv(1024)
            print(f"✓ Received response: {len(data)} bytes")
        except socket.timeout:
            print("✗ No response (timeout)")

        sock.close()
        return True
    except Exception as e:
        print(f"✗ Failed: {e}")
        return False

def test_udp_dns(host, port=53):
    """Test 5: Real DNS query over UDP"""
    print(f"\n[TEST 5] Real DNS Query (UDP) to {host}:{port}")
    try:
        # Same DNS query as before, but no length prefix for UDP
        transaction_id = b'\xcc\xdd'
        flags = b'\x01\x00'
        questions = b'\x00\x01'
        answers = b'\x00\x00'
        authority = b'\x00\x00'
        additional = b'\x00\x00'

        qname = b'\x06google\x03com\x00'
        qtype = b'\x00\x01'
        qclass = b'\x00\x01'

        dns_query = transaction_id + flags + questions + answers + authority + additional + qname + qtype + qclass

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)

        sock.sendto(dns_query, (host, port))
        print(f"✓ Sent UDP DNS query ({len(dns_query)} bytes)")

        try:
            data, addr = sock.recvfrom(1024)
            print(f"✓ Received UDP response: {len(data)} bytes from {addr}")
            print(f"  Response data: {data[:20].hex()}")
        except socket.timeout:
            print("✗ No UDP response (timeout)")

        sock.close()
        return True
    except Exception as e:
        print(f"✗ Failed: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 test_dns_blocking.py <server_ip>")
        sys.exit(1)

    server_ip = sys.argv[1]

    print("="*60)
    print("DNS Blocking Analysis - Reverse Engineering Iran's DPI")
    print("="*60)
    print(f"Target: {server_ip}:53")
    print(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")

    results = {}

    # Run all tests
    results['tcp_echo'] = test_tcp_echo(server_ip)
    time.sleep(1)

    results['real_dns_tcp'] = test_real_dns_query(server_ip)
    time.sleep(1)

    results['fake_dns'] = test_fake_dns_query(server_ip)
    time.sleep(1)

    results['encrypted'] = test_encrypted_payload(server_ip)
    time.sleep(1)

    results['udp_dns'] = test_udp_dns(server_ip)

    # Summary
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    for test, success in results.items():
        status = "✓ PASS" if success else "✗ FAIL"
        print(f"{test:20s}: {status}")

    print("\nAnalysis:")
    if results['tcp_echo'] and not results['real_dns_tcp']:
        print("→ TCP connection works, but real DNS queries fail")
        print("  Likely: DPI inspecting DNS packet format")
    elif results['real_dns_tcp'] and not results['fake_dns']:
        print("→ Real DNS works, fake DNS fails")
        print("  Likely: DPI validating DNS packet structure")
    elif results['real_dns_tcp'] and not results['encrypted']:
        print("→ DNS works, encrypted data fails")
        print("  Likely: DPI detecting high entropy / encryption")
    elif results['udp_dns'] and not results['real_dns_tcp']:
        print("→ UDP DNS works, TCP DNS fails")
        print("  Likely: Iran blocks TCP on port 53 (expects UDP)")
    else:
        print("→ See test results above for patterns")
