# WeAll Web UI — Deployment Notes

This UI is a Vite + React SPA that talks to a WeAll node HTTP API.

## Recommended topology (production)

Serve the UI and the API behind the same origin:

- `https://weall.example.com/` → UI
- `https://weall.example.com/v1/*` → API (reverse-proxied to your node)

Benefits:
- simplest CORS story (none)
- you can tighten CSP connect-src to 'self'
- fewer mixed-content issues

---

## Build

From `web/`:

```bash
npm ci
npm run build

Output is in dist/.

## Shipped and tested Nginx production configuration

The repository ships `web/deploy/nginx.conf.template` as the mechanically tested Nginx production path. It serves the built `dist/` SPA, proxies `/v1/` to the local node API, and emits the production security headers including CSP.

The template contains a single `__DIST_ROOT__` placeholder. Replace it with the absolute path to the built `web/dist` directory before starting Nginx. Web CI performs that substitution, starts Nginx with this exact template, requests the real HTTP response headers, verifies the CSP boundary, verifies `/v1/readyz` through the proxy, and runs a Chromium smoke against the built app.

The Nginx block below mirrors that shipped template for reviewer readability. The checked-in template is the deployment/test authority.

Reverse proxy examples
Nginx (UI + API under one origin)
server {
  listen 443 ssl;
  server_name weall.example.com;

  # Serve UI build
  root /var/www/weall-web/dist;
  index index.html;

  # Security headers (keep aligned with index.html CSP)
  add_header X-Content-Type-Options "nosniff" always;
  add_header Referrer-Policy "no-referrer" always;
  add_header X-Frame-Options "DENY" always;
  add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
  add_header Content-Security-Policy "default-src 'self'; base-uri 'self'; frame-ancestors 'none'; object-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: http: https:; font-src 'self' data:; media-src 'self' blob: http: https:; connect-src 'self' http: https: ws: wss:; frame-src 'self' http://127.0.0.1:* http://localhost:*;" always;

  # SPA: send any unknown path to index.html
  location / {
    try_files $uri $uri/ /index.html;
  }

  # API proxy
  location /v1/ {
    proxy_pass http://127.0.0.1:8000;
    proxy_http_version 1.1;

    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

    # If your node uses websockets later:
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
  }
}

Caddy (UI + API under one origin)
weall.example.com {
  root * /var/www/weall-web/dist
  encode zstd gzip

  header {
    X-Content-Type-Options "nosniff"
    Referrer-Policy "no-referrer"
    X-Frame-Options "DENY"
    Permissions-Policy "geolocation=(), microphone=(), camera=()"
    Content-Security-Policy "default-src 'self'; base-uri 'self'; frame-ancestors 'none'; object-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: http: https:; font-src 'self' data:; media-src 'self' blob: http: https:; connect-src 'self' http: https: ws: wss:; frame-src 'self' http://127.0.0.1:* http://localhost:*;"
  }

  # API proxy
  reverse_proxy /v1/* 127.0.0.1:8000

  # SPA fallback
  try_files {path} /index.html
  file_server
}

native PoH verification

Tier 1 native async verification routes through the active WeAll API target and protocol-native PoH surfaces. The frontend does not load a third-party challenge widget or external identity-provider endpoint for the primary PoH path.

The production examples above mechanically emit the same script-execution boundary used by Vite preview: `script-src 'self'` and `object-src 'none'`. Operators that change API/media origins must deliberately adjust `connect-src`, `img-src`, or `media-src` without weakening the script policy.
