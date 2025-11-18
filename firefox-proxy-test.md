# Firefox SOCKS5 Proxy Configuration for Nooshdaroo

## Critical Settings

Firefox needs these exact settings to work with the SOCKS5 proxy:

### Method 1: Firefox Settings UI
1. Open Firefox Settings → General → Network Settings
2. Select "Manual proxy configuration"
3. **SOCKS Host**: `127.0.0.1`
4. **Port**: `1080`
5. **SOCKS v5**: ✓ (checked)
6. **Proxy DNS when using SOCKS v5**: ✓ **CRITICAL - MUST BE CHECKED**
7. Leave HTTP/HTTPS/FTP proxy fields EMPTY

### Method 2: about:config (Recommended for verification)
1. Navigate to `about:config` in Firefox
2. Search and verify these settings:

```
network.proxy.type = 1 (manual proxy)
network.proxy.socks = 127.0.0.1
network.proxy.socks_port = 1080
network.proxy.socks_version = 5
network.proxy.socks_remote_dns = true  ← CRITICAL FOR CENSORSHIP BYPASS
```

## Common Issues

### Issue 1: DNS Leaks
**Symptom**: YouTube doesn't load, but curl works
**Cause**: `network.proxy.socks_remote_dns = false`
**Fix**: Set it to `true` in about:config

### Issue 2: Firefox Using System Proxy
**Symptom**: Inconsistent behavior
**Cause**: Firefox set to "Use system proxy settings"
**Fix**: Set to "Manual proxy configuration"

### Issue 3: HTTPS-Only Mode Conflicts
**Symptom**: Some sites don't load
**Cause**: Firefox HTTPS-only mode interfering with proxy
**Fix**: Disable HTTPS-only mode or add exceptions

## Testing Steps

1. **Verify proxy is running**:
   ```bash
   lsof -i :1080
   # Should show: nooshdaro (client process)
   ```

2. **Test with curl** (known working):
   ```bash
   curl -x socks5h://127.0.0.1:1080 https://www.youtube.com/ -I
   # Should return HTTP 200 OK
   ```

3. **Test in Firefox**:
   - Visit: `https://www.youtube.com`
   - Check browser console (F12) for errors
   - Check Network tab for failed requests

4. **Verify DNS is going through proxy**:
   ```bash
   # In client logs, you should see:
   # "Connecting to target: www.youtube.com:443"
   # NOT an IP address (which would indicate local DNS resolution)
   ```

## Debugging Firefox

If YouTube still doesn't load:

1. Open Firefox Developer Tools (F12)
2. Go to Network tab
3. Try to load YouTube
4. Look for:
   - **DNS errors**: "NS_ERROR_UNKNOWN_HOST" → DNS not going through proxy
   - **Connection refused**: Proxy not running or wrong port
   - **Certificate errors**: MITM/DPI interference (should not happen with Noise)
   - **Timeout**: Server unreachable or blocked

## Expected Behavior

When working correctly:
- Client logs show: `Connecting to target: www.youtube.com:443` (domain, not IP)
- Server logs show: `Successfully connected to www.youtube.com:443`
- Firefox loads YouTube normally
- No DNS resolution happens locally

## Current Status Check

Run this to see if Firefox is actually using the proxy:

```bash
# Monitor client connections
tail -f /path/to/client/logs

# You should see connection attempts when Firefox tries to load YouTube
# If you don't see ANY traffic when Firefox tries to load the page,
# then Firefox is NOT using the SOCKS5 proxy
```
