#!/usr/bin/env python3
"""
Multi-Port Protocol Analyzer
Listens on multiple ports (DNS 53, SSH 22/2222, HTTPS 443/8443)
and logs all received traffic for DPI analysis
"""

import socket
import threading
import time
import sys
from datetime import datetime

# Global log for all connections
connection_log = []
lock = threading.Lock()

def log_connection(port, protocol, client_addr, data_len, data_hex, status):
    """Thread-safe connection logging"""
    with lock:
        entry = {
            'timestamp': datetime.now().isoformat(),
            'port': port,
            'protocol': protocol,
            'client': str(client_addr),
            'data_len': data_len,
            'data_hex': data_hex,
            'status': status
        }
        connection_log.append(entry)
        print(f"[{entry['timestamp']}] {protocol}:{port} from {client_addr} | {data_len}B | {status}")
        if data_len > 0:
            print(f"  Data (first 64B): {data_hex[:128]}")

def tcp_listener(port, protocol_name):
    """Generic TCP listener"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', port))
        sock.listen(10)
        print(f"[{protocol_name}] TCP Listening on port {port}")

        while True:
            try:
                conn, addr = sock.accept()
                threading.Thread(target=handle_tcp, args=(conn, addr, port, protocol_name), daemon=True).start()
            except Exception as e:
                print(f"[{protocol_name}:{port}] Accept error: {e}")
    except Exception as e:
        print(f"[{protocol_name}:{port}] Bind error: {e}")

def handle_tcp(conn, addr, port, protocol_name):
    """Handle TCP connection"""
    try:
        # Set timeout
        conn.settimeout(5)

        # Read first chunk
        data = conn.recv(4096)
        data_hex = data.hex() if data else ""

        log_connection(port, f"TCP-{protocol_name}", addr, len(data), data_hex, "RECEIVED")

        # Send echo response
        if data:
            response = f"ECHO:{protocol_name}:".encode() + data
            conn.sendall(response)
            log_connection(port, f"TCP-{protocol_name}", addr, len(response), "", "SENT_ECHO")

    except socket.timeout:
        log_connection(port, f"TCP-{protocol_name}", addr, 0, "", "TIMEOUT")
    except Exception as e:
        log_connection(port, f"TCP-{protocol_name}", addr, 0, "", f"ERROR:{e}")
    finally:
        conn.close()

def udp_listener(port, protocol_name):
    """Generic UDP listener"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('0.0.0.0', port))
        print(f"[{protocol_name}] UDP Listening on port {port}")

        while True:
            try:
                data, addr = sock.recvfrom(4096)
                data_hex = data.hex() if data else ""

                log_connection(port, f"UDP-{protocol_name}", addr, len(data), data_hex, "RECEIVED")

                # Send echo response
                if data:
                    response = f"ECHO:{protocol_name}:".encode() + data
                    sock.sendto(response, addr)
                    log_connection(port, f"UDP-{protocol_name}", addr, len(response), "", "SENT_ECHO")

            except Exception as e:
                print(f"[{protocol_name}:{port}] UDP error: {e}")
    except Exception as e:
        print(f"[{protocol_name}:{port}] UDP bind error: {e}")

def dump_stats():
    """Dump statistics every 30 seconds"""
    while True:
        time.sleep(30)
        with lock:
            print("\n" + "="*60)
            print(f"STATISTICS - {len(connection_log)} total connections")
            print("="*60)

            # Group by protocol:port
            stats = {}
            for entry in connection_log:
                key = f"{entry['protocol']}:{entry['port']}"
                if key not in stats:
                    stats[key] = {'count': 0, 'bytes': 0, 'clients': set()}
                stats[key]['count'] += 1
                stats[key]['bytes'] += entry['data_len']
                stats[key]['clients'].add(entry['client'])

            for key, data in sorted(stats.items()):
                print(f"{key:25s}: {data['count']:4d} conn, {data['bytes']:8d} bytes, {len(data['clients'])} clients")

            print("="*60 + "\n")

if __name__ == "__main__":
    print("="*60)
    print("Multi-Port Protocol Analyzer")
    print("Testing DNS, SSH, HTTPS protocols against Iran DPI")
    print("="*60)

    # Define ports to listen on
    ports = [
        # DNS
        (53, 'DNS', 'tcp'),
        (53, 'DNS', 'udp'),
        # SSH
        (22, 'SSH', 'tcp'),
        (2222, 'SSH-ALT', 'tcp'),
        # HTTPS
        (443, 'HTTPS', 'tcp'),
        (8443, 'HTTPS-ALT', 'tcp'),
        # Test ports
        (5353, 'TEST-DNS', 'tcp'),
        (5353, 'TEST-DNS', 'udp'),
    ]

    # Start all listeners
    threads = []
    for port, name, proto in ports:
        if proto == 'tcp':
            t = threading.Thread(target=tcp_listener, args=(port, name), daemon=True)
        else:
            t = threading.Thread(target=udp_listener, args=(port, name), daemon=True)
        t.start()
        threads.append(t)
        time.sleep(0.1)

    # Start stats dumper
    stats_thread = threading.Thread(target=dump_stats, daemon=True)
    stats_thread.start()

    print(f"\nAll {len(ports)} listeners started. Waiting for connections...")
    print("Press Ctrl+C to stop and save log.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\nShutting down...")

        # Save detailed log
        with lock:
            log_file = f"/tmp/multiport_analysis_{int(time.time())}.log"
            with open(log_file, 'w') as f:
                f.write("timestamp,port,protocol,client,data_len,data_hex,status\n")
                for entry in connection_log:
                    f.write(f"{entry['timestamp']},{entry['port']},{entry['protocol']},{entry['client']},{entry['data_len']},{entry['data_hex']},{entry['status']}\n")

            print(f"Log saved to: {log_file}")
            print(f"Total connections logged: {len(connection_log)}")
