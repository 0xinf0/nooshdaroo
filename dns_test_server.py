#!/usr/bin/env python3
"""
DNS Test Server - Echoes back different types of traffic
Helps identify what Iran's DPI blocks
"""

import socket
import threading
import time
import struct

def handle_tcp_client(conn, addr, test_name):
    """Handle TCP client connection"""
    try:
        print(f"[{test_name}] TCP connection from {addr}")
        data = conn.recv(4096)
        print(f"[{test_name}] Received {len(data)} bytes")
        print(f"[{test_name}] First 50 bytes (hex): {data[:50].hex()}")

        # Echo back
        conn.sendall(b"ECHO:" + data)
        print(f"[{test_name}] Echoed back {len(data) + 5} bytes")

    except Exception as e:
        print(f"[{test_name}] Error: {e}")
    finally:
        conn.close()

def tcp_echo_server(port=5353):
    """Simple TCP echo server"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', port))
    sock.listen(5)
    print(f"[TCP-ECHO] Listening on port {port}")

    while True:
        conn, addr = sock.accept()
        threading.Thread(target=handle_tcp_client, args=(conn, addr, f"TCP-ECHO:{port}")).start()

def dns_tcp_server(port=53):
    """TCP server that responds to DNS queries"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', port))
    sock.listen(5)
    print(f"[DNS-TCP] Listening on port {port}")

    while True:
        conn, addr = sock.accept()
        threading.Thread(target=handle_dns_tcp, args=(conn, addr)).start()

def handle_dns_tcp(conn, addr):
    """Handle TCP DNS query"""
    try:
        print(f"[DNS-TCP] Connection from {addr}")

        # Read 2-byte length prefix
        length_data = conn.recv(2)
        if len(length_data) != 2:
            print(f"[DNS-TCP] Invalid length prefix")
            conn.close()
            return

        query_length = struct.unpack('!H', length_data)[0]
        print(f"[DNS-TCP] Expecting {query_length} bytes")

        # Read query
        query = conn.recv(query_length)
        print(f"[DNS-TCP] Received {len(query)} bytes")
        print(f"[DNS-TCP] Query (hex): {query[:50].hex()}")

        # Send back a simple DNS response
        # Copy transaction ID
        transaction_id = query[:2]
        response_flags = b'\x81\x80'  # Standard response, no error
        questions = b'\x00\x01'
        answers = b'\x00\x01'  # 1 answer
        authority = b'\x00\x00'
        additional = b'\x00\x00'

        # Echo back the question
        question_section = query[12:]  # Skip header

        # Answer: google.com A 172.217.14.206 (TTL 300)
        answer = (
            b'\xc0\x0c'  # Name pointer to question
            b'\x00\x01'  # Type A
            b'\x00\x01'  # Class IN
            b'\x00\x00\x01\x2c'  # TTL 300
            b'\x00\x04'  # RDLENGTH 4
            b'\xac\xd9\x0e\xce'  # 172.217.14.206
        )

        response = transaction_id + response_flags + questions + answers + authority + additional + question_section + answer

        # Send with length prefix
        conn.sendall(struct.pack('!H', len(response)) + response)
        print(f"[DNS-TCP] Sent response: {len(response)} bytes")

    except Exception as e:
        print(f"[DNS-TCP] Error: {e}")
    finally:
        conn.close()

def dns_udp_server(port=53):
    """UDP server that responds to DNS queries"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', port))
    print(f"[DNS-UDP] Listening on port {port}")

    while True:
        try:
            data, addr = sock.recvfrom(512)
            print(f"[DNS-UDP] Query from {addr}: {len(data)} bytes")
            print(f"[DNS-UDP] Query (hex): {data[:50].hex()}")

            # Send back a simple response
            transaction_id = data[:2]
            response_flags = b'\x81\x80'
            questions = b'\x00\x01'
            answers = b'\x00\x01'
            authority = b'\x00\x00'
            additional = b'\x00\x00'

            question_section = data[12:]

            answer = (
                b'\xc0\x0c'
                b'\x00\x01'
                b'\x00\x01'
                b'\x00\x00\x01\x2c'
                b'\x00\x04'
                b'\xac\xd9\x0e\xce'
            )

            response = transaction_id + response_flags + questions + answers + authority + additional + question_section + answer

            sock.sendto(response, addr)
            print(f"[DNS-UDP] Sent response to {addr}: {len(response)} bytes")

        except Exception as e:
            print(f"[DNS-UDP] Error: {e}")

if __name__ == "__main__":
    print("="*60)
    print("DNS Test Server - Multi-Protocol Listener")
    print("="*60)

    # Start servers in threads
    servers = [
        threading.Thread(target=tcp_echo_server, args=(5353,), daemon=True),
        threading.Thread(target=dns_tcp_server, args=(53,), daemon=True),
        threading.Thread(target=dns_udp_server, args=(53,), daemon=True),
    ]

    for server in servers:
        server.start()

    print("\nAll servers running. Press Ctrl+C to stop.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down...")
