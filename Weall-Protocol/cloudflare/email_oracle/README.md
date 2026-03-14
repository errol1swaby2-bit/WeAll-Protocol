# WeAll Email Oracle (Cloudflare Worker)

Contract endpoints:
- POST /start
- POST /verify

Local dev:
- npm install
- npm run dev

Deploy:
- wrangler secret put RESEND_API_KEY
- wrangler secret put TURNSTILE_SECRET
- npm run deploy

CORS:
- Controlled via EMAIL_ORACLE_ALLOWED_ORIGINS (comma-separated) or "*" for dev.
