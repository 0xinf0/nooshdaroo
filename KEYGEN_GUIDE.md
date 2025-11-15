# Nooshdaroo Key Generation Guide

Simple guide to generating encryption keys for Nooshdaroo's encrypted transport.

## Quick Start (3 Easy Steps)

### Step 1: Generate Keys

```bash
nooshdaroo genkey
```

This displays:
- 🔒 Private key (keep secret!)
- ✅ Public key (share with peers)
- 📋 Ready-to-copy configuration examples

### Step 2: Copy Configuration

Copy the displayed server and client configs to your TOML files.

### Step 3: Run Nooshdaroo

```bash
# On server
nooshdaroo server --config server.toml

# On client
nooshdaroo client --config client.toml
```

**Done!** Your traffic is now encrypted end-to-end.

---

## Automatic Config Generation

Generate ready-to-use configuration files automatically:

```bash
nooshdaroo genkey \
  --server-config server.toml \
  --client-config client.toml \
  --server-addr myserver.com:8443
```

This creates:
- `server.toml` with private key (permissions: 600)
- `client.toml` with server's public key

Then just run:
```bash
# Server
nooshdaroo server --config server.toml

# Client
nooshdaroo client --config client.toml
```

---

## Command Options

### Basic Usage

```bash
nooshdaroo genkey
```

Generates a keypair and displays configuration examples.

### Save to Files

```bash
nooshdaroo genkey \
  --server-config server.toml \
  --client-config client.toml
```

Automatically creates both config files.

### Customize Addresses

```bash
nooshdaroo genkey \
  --server-config server.toml \
  --client-config client.toml \
  --server-bind "0.0.0.0:9000" \
  --client-bind "127.0.0.1:1080" \
  --server-addr "vpn.example.com:9000"
```

### Choose Encryption Pattern

```bash
nooshdaroo genkey \
  --pattern kk \
  --server-config server.toml \
  --client-config client.toml
```

Available patterns:
- `nk` - Server authentication (recommended)
- `xx` - Anonymous encryption
- `kk` - Mutual authentication

---

## Examples

### Example 1: Development Setup

```bash
# Generate configs for local testing
nooshdaroo genkey \
  --server-config dev-server.toml \
  --client-config dev-client.toml \
  --server-addr "localhost:8443"

# Run server
nooshdaroo server --config dev-server.toml

# Run client (in another terminal)
nooshdaroo client --config dev-client.toml
```

### Example 2: Production Deployment

```bash
# On your local machine
nooshdaroo genkey \
  --server-config production-server.toml \
  --client-config production-client.toml \
  --server-addr "vpn.mycompany.com:8443" \
  --pattern nk

# Securely copy server config to production server
scp production-server.toml user@vpn.mycompany.com:/etc/nooshdaroo/server.toml

# On production server
sudo nooshdaroo server --config /etc/nooshdaroo/server.toml

# On your laptop
nooshdaroo client --config production-client.toml
```

### Example 3: Mutual Authentication

```bash
# Generate server keys
nooshdaroo genkey \
  --server-config server.toml \
  --pattern kk

# Save server's public key
SERVER_PUB=$(grep remote_public_key server.toml | cut -d'"' -f2)

# Generate client keys
nooshdaroo genkey \
  --client-config client.toml \
  --pattern kk

# Save client's public key
CLIENT_PUB=$(grep remote_public_key client.toml | cut -d'"' -f2)

# Manually add keys to configs
# Add CLIENT_PUB to server.toml's remote_public_key
# Add SERVER_PUB to client.toml's remote_public_key
```

---

## Security Best Practices

### ✅ DO

- ✅ **Keep private keys secret** - Never share or commit to git
- ✅ **Use 600 permissions** - `chmod 600 server.toml`
- ✅ **Different keys per environment** - Separate dev/staging/prod keys
- ✅ **Rotate keys regularly** - Every 90 days recommended
- ✅ **Backup keys securely** - Encrypted storage only
- ✅ **Use strong patterns** - Prefer NK or KK over XX

### ❌ DON'T

- ❌ **Don't commit to git** - Add `*.toml` to `.gitignore`
- ❌ **Don't reuse keys** - Generate new keys for each deployment
- ❌ **Don't use HTTP** - Always transfer configs over SSH/HTTPS
- ❌ **Don't use weak patterns** - XX is vulnerable to MITM
- ❌ **Don't share private keys** - Even with "trusted" people

---

## Troubleshooting

### "Permission denied" when reading config

**Problem**: Config file has wrong permissions

**Solution**:
```bash
chmod 600 server.toml
```

### "Failed to write config"

**Problem**: No write permission in directory

**Solution**:
```bash
# Write to home directory instead
nooshdaroo genkey \
  --server-config ~/server.toml \
  --client-config ~/client.toml
```

### Keys don't match between server and client

**Problem**: Used different keypairs for server and client

**Solution**: Generate once and use same keys:
```bash
# Generate keys
nooshdaroo genkey > keys.txt

# Extract and use in both configs
# Private key → server.toml
# Public key → client.toml
```

### Need to regenerate keys

**Problem**: Lost keys or need to rotate

**Solution**:
```bash
# Generate new keys
nooshdaroo genkey \
  --server-config new-server.toml \
  --client-config new-client.toml

# Replace old configs
mv new-server.toml server.toml
mv new-client.toml client.toml

# Restart services
```

---

## Advanced Usage

### Generate Multiple Keypairs

```bash
# For production
nooshdaroo genkey --server-config prod-server.toml \
                  --client-config prod-client.toml \
                  --server-addr "prod.example.com:8443"

# For staging
nooshdaroo genkey --server-config staging-server.toml \
                  --client-config staging-client.toml \
                  --server-addr "staging.example.com:8443"

# For development
nooshdaroo genkey --server-config dev-server.toml \
                  --client-config dev-client.toml \
                  --server-addr "localhost:8443"
```

### Extract Keys for Scripting

```bash
# Generate and extract keys
OUTPUT=$(nooshdaroo genkey)

# Extract private key (for server)
PRIVATE_KEY=$(echo "$OUTPUT" | grep "PRIVATE KEY" -A 2 | tail -1 | tr -d '│ ')

# Extract public key (for client)
PUBLIC_KEY=$(echo "$OUTPUT" | grep "PUBLIC KEY" -A 2 | tail -1 | tr -d '│ ')

# Use in scripts
echo "Server key: $PRIVATE_KEY"
echo "Client key: $PUBLIC_KEY"
```

### Verify Generated Configs

```bash
# Generate configs
nooshdaroo genkey \
  --server-config server.toml \
  --client-config client.toml

# Test server config (dry-run)
nooshdaroo server --config server.toml --help

# Test client config
nooshdaroo client --config client.toml --help
```

---

## Integration with CI/CD

### GitHub Actions Example

```yaml
name: Deploy Nooshdaroo

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Generate keys
        run: |
          nooshdaroo genkey \
            --server-config server.toml \
            --client-config client.toml \
            --server-addr ${{ secrets.SERVER_ADDR }}

      - name: Deploy server config
        run: |
          scp server.toml ${{ secrets.SSH_USER }}@${{ secrets.SERVER_IP }}:/etc/nooshdaroo/

      - name: Store client config
        uses: actions/upload-artifact@v3
        with:
          name: client-config
          path: client.toml
```

### Docker Example

```dockerfile
FROM nooshdaroo:latest

# Generate keys at build time
RUN nooshdaroo genkey \
    --server-config /etc/nooshdaroo/server.toml \
    --pattern nk

CMD ["nooshdaroo", "server", "--config", "/etc/nooshdaroo/server.toml"]
```

---

## FAQ

**Q: Can I use the same key for multiple clients?**

A: With NK pattern, yes - the server's public key can be shared with all clients. But each client connects anonymously.

**Q: How do I rotate keys without downtime?**

A: Not yet supported. Plan for brief downtime during key rotation.

**Q: What if I lose my private key?**

A: You must generate new keys. There's no recovery - this is by design for security.

**Q: Can I manually create keys?**

A: Not recommended. Use `nooshdaroo genkey` to ensure proper format and encoding.

**Q: How long are the keys?**

A: 32 bytes (256 bits) encoded as 44-character base64 strings.

---

## Help

For more information:
- 📖 Read **NOISE_TRANSPORT.md** for encryption details
- 🔍 Check **examples/** directory for sample configs
- 💬 Report issues at https://github.com/sinarabbaani/Nooshdaroo/issues

---

**Generated keys are cryptographically secure and ready for production use!** 🔒
