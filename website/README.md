# Nooshdaroo Website

Modern, responsive website for nooshdaroo.net showcasing the protocol shape-shifting SOCKS proxy.

## Overview

This website provides:
- Project overview and features
- Signed binary downloads for multiple platforms
- GPG verification instructions
- Technical documentation
- Quick start guides

## Files

- `index.html` - Main website page with all content
- `style.css` - Modern dark-themed CSS styling
- `dist/` - Symlink to release binaries directory

## Local Preview

To preview the website locally:

```bash
# Using Python's built-in server
cd website
python3 -m http.server 8000

# Open in browser
open http://localhost:8000
```

## Deployment

For production deployment to nooshdaroo.net:

### Option 1: Static Hosting (Recommended)

Deploy to any static hosting service:

**Netlify:**
```bash
cd website
netlify deploy --prod
```

**Vercel:**
```bash
cd website
vercel --prod
```

**GitHub Pages:**
```bash
# Push website directory to gh-pages branch
git subtree push --prefix website origin gh-pages
```

### Option 2: Traditional Web Server

**Nginx:**
```nginx
server {
    listen 80;
    server_name nooshdaroo.net;
    root /var/www/nooshdaroo/website;
    index index.html;

    # Redirect HTTP to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name nooshdaroo.net;
    root /var/www/nooshdaroo/website;
    index index.html;

    ssl_certificate /etc/letsencrypt/live/nooshdaroo.net/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/nooshdaroo.net/privkey.pem;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Cache static assets
    location ~* \.(css|js|jpg|jpeg|png|gif|ico|svg)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }

    # Binary downloads
    location /dist/ {
        add_header Content-Disposition "attachment";
    }
}
```

**Apache:**
```apache
<VirtualHost *:80>
    ServerName nooshdaroo.net
    DocumentRoot /var/www/nooshdaroo/website

    # Redirect to HTTPS
    RewriteEngine On
    RewriteCond %{HTTPS} off
    RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
</VirtualHost>

<VirtualHost *:443>
    ServerName nooshdaroo.net
    DocumentRoot /var/www/nooshdaroo/website

    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/nooshdaroo.net/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/nooshdaroo.net/privkey.pem

    <Directory /var/www/nooshdaroo/website>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    # Binary downloads
    <Directory /var/www/nooshdaroo/website/dist>
        Header set Content-Disposition "attachment"
    </Directory>
</VirtualHost>
```

## Release Process

When creating a new release:

1. Build binaries for all platforms
2. Generate SHA256 checksums and GPG signatures
3. Update version numbers in `index.html`
4. Update download links in `index.html`
5. Test locally
6. Deploy to production

## DNS Configuration

Point your domain to the hosting provider:

```dns
# For static hosting (Netlify/Vercel)
nooshdaroo.net.    A    192.0.2.1  ; Replace with provider's IP
www.nooshdaroo.net. CNAME nooshdaroo.net.

# For traditional server
nooshdaroo.net.    A    your.server.ip.address
www.nooshdaroo.net. CNAME nooshdaroo.net.
```

## Security

- All binaries are GPG-signed
- SHA256 checksums provided for verification
- Website served over HTTPS
- Security headers configured
- No client-side JavaScript dependencies

## GPG Signing Key

**Fingerprint:** `F6DF BB06 92DE F57F 970B 982E 2966 5CE0 835F ADAC`
**Email:** sina@redteam.net

Import the key:
```bash
gpg --recv-keys F6DFBB0692DEF57F970B982E29665CE0835FADAC
```

## License

Website content: CC BY 4.0
Nooshdaroo software: MIT License

## Support

- GitHub Issues: https://github.com/your-org/nooshdaroo/issues
- Documentation: See website #docs section
- Security: sina@redteam.net
