#!/bin/bash
# DNS Tunnel Server Deployment Script
# Run this on your external server (outside Iran)

set -e

echo "═══════════════════════════════════════════════════"
echo "  Nooshdaroo DNS Tunnel - Server Deployment"
echo "═══════════════════════════════════════════════════"
echo ""

# Check if running as root (needed for port 53)
if [ "$EUID" -ne 0 ]; then
    echo "⚠️  Warning: Not running as root."
    echo "   Port 53 requires root privileges."
    echo "   Run with: sudo ./deploy-dns-server.sh"
    echo "   Or use a higher port (edit server-dns-iran.toml)"
    echo ""
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Check if binary exists
if [ ! -f "./nooshdaroo" ]; then
    echo "❌ Error: nooshdaroo binary not found in current directory"
    echo "   Please copy the binary here first:"
    echo "   scp target/release/nooshdaroo user@server:~/"
    exit 1
fi

# Check if config exists
if [ ! -f "./server-dns-iran.toml" ]; then
    echo "❌ Error: server-dns-iran.toml not found"
    echo "   Please copy the config here first:"
    echo "   scp server-dns-iran.toml user@server:~/"
    exit 1
fi

# Get server's public IP
PUBLIC_IP=$(curl -s ifconfig.me || echo "unknown")
echo "📍 Server public IP: $PUBLIC_IP"
echo ""

# Check if port 53 is available
if command -v netstat &> /dev/null; then
    if netstat -tuln | grep -q ":53 "; then
        echo "⚠️  Port 53 is already in use!"
        echo "   You may need to stop the existing DNS service:"
        echo "   sudo systemctl stop systemd-resolved"
        echo ""
    fi
fi

# Check firewall status
echo "🔥 Firewall check..."
if command -v ufw &> /dev/null; then
    if ufw status | grep -q "Status: active"; then
        echo "   UFW is active. Allowing UDP port 53..."
        ufw allow 53/udp
    fi
fi

echo ""
echo "✅ Ready to start DNS tunnel server!"
echo ""
echo "Server will listen on: 0.0.0.0:53 (UDP)"
echo "Protocol: dns-udp-tunnel"
echo "Encryption: Noise Protocol (ChaCha20-Poly1305)"
echo ""
echo "─────────────────────────────────────────────────"
echo "Client configuration (for Iran VM):"
echo "─────────────────────────────────────────────────"
echo "server_address = \"$PUBLIC_IP:53\""
echo "─────────────────────────────────────────────────"
echo ""

read -p "Start server now? (Y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    echo ""
    echo "🚀 Starting Nooshdaroo DNS tunnel server..."
    echo "   Press Ctrl+C to stop"
    echo ""

    # Run in foreground with logs
    ./nooshdaroo -c server-dns-iran.toml server
fi
