# WeAll Email Issuer (Cloudflare Worker)

This worker provides 2 endpoints:

- POST /start  { "email": "user@example.com" }
  - generates a 6-digit code
  - stores only a SHA-256 hash in a Durable Object (no raw code persisted)
  - sends the email via MailChannels
  - returns { ok:true, sent:true, expires_ts_ms }

- POST /verify { "email": "...", "code": "123456", "turnstile_token": "...", "remoteip": "..." }
  - verifies Turnstile server-side
  - checks one-time code hash + expiry + attempt limit
  - returns { ok:true } or { ok:false, error:"..." }

No private keys are stored. Only Cloudflare secrets used:
- TURNSTILE_SECRET

## Deploy

From this directory:
- wrangler login
- wrangler secret put TURNSTILE_SECRET
- wrangler deploy

## MailChannels notes

MailChannels requires your FROM domain to be set up correctly (SPF/DKIM/DMARC and any MailChannels-specific DNS steps).
Use FROM_EMAIL=no-reply@weallprotocol.xyz (or another address you control).
