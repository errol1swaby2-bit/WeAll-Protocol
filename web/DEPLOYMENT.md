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
  }

  # API proxy
  reverse_proxy /v1/* 127.0.0.1:8000

  # SPA fallback
  try_files {path} /index.html
  file_server
}

Turnstile + CSP

The UI ships with a CSP in index.html that permits Cloudflare Turnstile:

script-src https://challenges.cloudflare.com

frame-src https://challenges.cloudflare.com

If you deploy with custom CSP headers at the proxy, keep those allowances.

Caching
Suggested caching approach

Cache static assets aggressively (/assets/*) with immutable caching

Do NOT cache index.html (or keep it short-lived), so users pick up new builds quickly.

Nginx example:

location /assets/ {
  expires 365d;
  add_header Cache-Control "public, max-age=31536000, immutable";
}
location = /index.html {
  expires -1;
  add_header Cache-Control "no-cache";
}

Node selection

This UI supports switching API base URLs inside the UI.
For production, prefer same-origin proxying and keep the UI base fixed.

E2E smoke tests (Playwright)

Install:

npm i -D @playwright/test
npx playwright install --with-deps chromium


Run:

npm run dev
npx playwright test


If your dev server runs on a different port:

PLAYWRIGHT_PORT=5174 npx playwright test
