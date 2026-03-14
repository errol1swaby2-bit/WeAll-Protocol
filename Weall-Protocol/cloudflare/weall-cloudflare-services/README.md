# WeAll Cloudflare Services (Split)

This folder contains **two separate Cloudflare Workers**:

## 1) Gateway + Directory (`gateway-directory/`)
- Public gateway for clients.
- Node heartbeat ingest.
- Durable Object directory for node liveness + basic penalty/downrank.
- Issues short-lived sticky routing tokens.

## 2) Email Oracle (`email-oracle/`)
- Email verification / attestation service.
- Turnstile-gated by default.
- Uses a Durable Object for challenge state, replay protection, and rate limiting.
- Can send verification codes via Resend (optional).

## Quick start

```bash
npm install

npm run dev:gateway
npm run dev:email

---

## 3) Gateway worker metadata (rename + keep your code)

In **`cloudflare/weall-cloudflare-services/gateway-directory/`**, replace these files with:

### `gateway-directory/package.json`
```json
{
  "name": "weall-gateway-directory",
  "private": true,
  "version": "1.0.0",
  "type": "module",
  "scripts": {
    "dev": "wrangler dev",
    "deploy": "wrangler deploy",
    "typecheck": "tsc -p tsconfig.json"
  },
  "devDependencies": {
    "@cloudflare/workers-types": "^4.20260206.0",
    "typescript": "^5.7.3",
    "wrangler": "^3.109.0"
  }
}
