// File: projects/Weall-Protocol/cloudflare/weall-cloudflare-services/email-oracle/src/index.ts
// Cloudflare Worker: Email verification oracle (issues signed, short-lived assertions).
//
// Production notes:
// - Prefer Ed25519 (JWS EdDSA) via ORACLE_SIGNING_JWK/ORACLE_PUBLIC_JWK.
// - HS256 fallback exists for local/dev compatibility (ISSUER_JWT_SECRET).

export interface Env {
  // Optional CORS allowlist (comma-separated origins)
  WEALL_CORS_ORIGINS?: string;

  // Mail & anti-bot
  ISSUER_RESEND_API_KEY: string;
  ISSUER_RESEND_FROM_EMAIL: string;
  ISSUER_TURNSTILE_SECRET_KEY: string;

  // Signing (preferred)
  ORACLE_SIGNING_JWK?: string; // private key JWK JSON (Ed25519)
  ORACLE_PUBLIC_JWK?: string; // public key JWK JSON (Ed25519)
  ORACLE_KID?: string; // key id to advertise

  // Signing (legacy fallback)
  ISSUER_JWT_SECRET?: string; // HS256 secret (dev fallback)

  // Timing
  ISSUER_JWT_EXPIRES_IN?: string; // seconds (default 300)
  ISSUER_SESSION_EXPIRES_IN?: string; // seconds (default 600)

  // Rate limiting
  ISSUER_RATE_LIMIT_PER_IP?: string; // default 5
  ISSUER_RATE_LIMIT_WINDOW_SECONDS?: string; // default 3600

  // Durable Objects
  ISSUER_ORACLE: DurableObjectNamespace;
}

type Json = Record<string, unknown>;

function json(body: unknown, status = 200, headers: Record<string, string> = {}) {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...headers,
    },
  });
}

function text(body: string, status = 200, headers: Record<string, string> = {}) {
  return new Response(body, {
    status,
    headers: {
      "content-type": "text/plain; charset=utf-8",
      "cache-control": "no-store",
      ...headers,
    },
  });
}

function envInt(v: string | undefined, def: number): number {
  if (!v) return def;
  const n = Number(v);
  return Number.isFinite(n) ? Math.trunc(n) : def;
}

function nowMs(): number {
  return Date.now();
}

function base64UrlEncode(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  const b64 = btoa(s);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlDecode(s: string): Uint8Array {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const b64 = (s + pad).replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function getCorsHeaders(req: Request, env: Env): Record<string, string> {
  const raw = (env.WEALL_CORS_ORIGINS || "").trim();
  if (!raw) return {};
  const origin = req.headers.get("origin") || "";
  const allow = raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (!origin || !allow.includes(origin)) return {};
  return {
    "access-control-allow-origin": origin,
    "access-control-allow-credentials": "true",
    "access-control-allow-methods": "GET,POST,OPTIONS",
    "access-control-allow-headers": "content-type,authorization",
    "access-control-max-age": "600",
    vary: "origin",
  };
}

function reqIp(req: Request): string {
  // Cloudflare adds cf-connecting-ip; fall back to x-forwarded-for.
  const cf = (req.headers.get("cf-connecting-ip") || "").trim();
  if (cf) return cf;
  const xff = (req.headers.get("x-forwarded-for") || "").split(",")[0]?.trim();
  return xff || "unknown";
}

function normalizeEmail(email: string): string {
  return (email || "").trim().toLowerCase();
}

function isValidEmail(email: string): boolean {
  if (!email) return false;
  // Intentionally simple validation (avoid rejecting valid-but-rare forms).
  // Ensure at least local@domain.tld and no spaces.
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

async function sha256Hex(data: Uint8Array): Promise<string> {
  const dig = await crypto.subtle.digest("SHA-256", data);
  const bytes = new Uint8Array(dig);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function hmacSha256Hex(key: string, data: string): Promise<string> {
  const enc = new TextEncoder();
  const k = await crypto.subtle.importKey("raw", enc.encode(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", k, enc.encode(data));
  const bytes = new Uint8Array(sig);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let out = 0;
  for (let i = 0; i < a.length; i++) out |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return out === 0;
}

type OracleKeyCache = {
  kid: string;
  publicJwk: Json | null;
  publicKey: CryptoKey | null;
  privateKey: CryptoKey | null;
};

let ORACLE_KEYS: OracleKeyCache | null = null;

async function loadOracleKeys(env: Env): Promise<OracleKeyCache> {
  if (ORACLE_KEYS) return ORACLE_KEYS;

  const kid = (env.ORACLE_KID || "weall-oracle-1").trim() || "weall-oracle-1";

  const pubRaw = (env.ORACLE_PUBLIC_JWK || "").trim();
  const privRaw = (env.ORACLE_SIGNING_JWK || "").trim();

  let publicJwk: Json | null = null;
  let publicKey: CryptoKey | null = null;
  let privateKey: CryptoKey | null = null;

  // Prefer Ed25519 if JWKs are configured.
  try {
    if (pubRaw) {
      publicJwk = JSON.parse(pubRaw) as Json;
      publicKey = await crypto.subtle.importKey("jwk", publicJwk as JsonWebKey, { name: "Ed25519" }, false, ["verify"]);
    }
  } catch {
    publicJwk = null;
    publicKey = null;
  }

  try {
    if (privRaw) {
      const privJwk = JSON.parse(privRaw) as Json;
      privateKey = await crypto.subtle.importKey("jwk", privJwk as JsonWebKey, { name: "Ed25519" }, false, ["sign"]);

      // If public not provided, derive a public JWK if present in private JWK (x).
      if (!publicJwk && typeof (privJwk as any)?.x === "string") {
        publicJwk = {
          kty: "OKP",
          crv: "Ed25519",
          x: (privJwk as any).x,
          kid,
          alg: "EdDSA",
          use: "sig",
        } as Json;
        publicKey = await crypto.subtle.importKey("jwk", publicJwk as JsonWebKey, { name: "Ed25519" }, false, ["verify"]);
      }
    }
  } catch {
    privateKey = null;
  }

  ORACLE_KEYS = { kid, publicJwk, publicKey, privateKey };
  return ORACLE_KEYS;
}

async function jwsEdDSA(env: Env, payload: Json): Promise<string> {
  const keys = await loadOracleKeys(env);
  if (!keys.privateKey) throw new Error("ed25519_not_configured");

  const header: Json = { alg: "EdDSA", typ: "JWT", kid: keys.kid };

  const enc = new TextEncoder();
  const headerB64 = base64UrlEncode(enc.encode(JSON.stringify(header)));
  const payloadB64 = base64UrlEncode(enc.encode(JSON.stringify(payload)));
  const signingInput = `${headerB64}.${payloadB64}`;

  const sigBuf = await crypto.subtle.sign({ name: "Ed25519" }, keys.privateKey, enc.encode(signingInput));
  const sigB64 = base64UrlEncode(new Uint8Array(sigBuf));
  return `${signingInput}.${sigB64}`;
}

async function verifyJwsEdDSA(env: Env, token: string): Promise<Json | null> {
  const keys = await loadOracleKeys(env);
  if (!keys.publicKey) return null;

  const parts = token.split(".");
  if (parts.length !== 3) return null;

  const [h, p, s] = parts;
  try {
    const header = JSON.parse(new TextDecoder().decode(base64UrlDecode(h))) as any;
    if (!header || header.alg !== "EdDSA") return null;

    const enc = new TextEncoder();
    const ok = await crypto.subtle.verify({ name: "Ed25519" }, keys.publicKey, base64UrlDecode(s), enc.encode(`${h}.${p}`));
    if (!ok) return null;

    const payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(p)));
    if (!payload || typeof payload !== "object") return null;
    return payload as Json;
  } catch {
    return null;
  }
}

async function signLegacyHmac(env: Env, payload: Json): Promise<string> {
  const secret = (env.ISSUER_JWT_SECRET || "").trim();
  if (!secret) throw new Error("hmac_not_configured");

  // Minimal compact token: base64url(json).hex(hmac(body)).
  const enc = new TextEncoder();
  const body = base64UrlEncode(enc.encode(JSON.stringify(payload)));
  const sig = await hmacSha256Hex(secret, body);
  return `${body}.${sig}`;
}

async function verifyLegacyHmac(env: Env, token: string): Promise<Json | null> {
  const secret = (env.ISSUER_JWT_SECRET || "").trim();
  if (!secret) return null;

  const parts = token.split(".");
  if (parts.length !== 2) return null;
  const [body, sig] = parts;
  const expect = await hmacSha256Hex(secret, body);
  if (!timingSafeEqual(sig, expect)) return null;
  try {
    const payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(body)));
    if (!payload || typeof payload !== "object") return null;
    return payload as Json;
  } catch {
    return null;
  }
}

function issueTimestamps(env: Env): { iat_ms: number; exp_ms: number } {
  const now = nowMs();
  const ttlS = envInt(env.ISSUER_JWT_EXPIRES_IN, 300);
  const exp = now + Math.max(30, ttlS) * 1000;
  return { iat_ms: now, exp_ms: exp };
}

function isExpired(payload: any): boolean {
  const exp = Number(payload?.exp_ms ?? 0);
  if (!Number.isFinite(exp) || exp <= 0) return true;
  return nowMs() > exp;
}

async function verifyTurnstile(env: Env, token: string, ip: string): Promise<boolean> {
  const secret = (env.ISSUER_TURNSTILE_SECRET_KEY || "").trim();
  if (!secret) return false;

  const form = new FormData();
  form.set("secret", secret);
  form.set("response", token);
  if (ip && ip !== "unknown") form.set("remoteip", ip);

  const resp = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
    method: "POST",
    body: form,
  });

  const out = (await resp.json().catch(() => null)) as any;
  return !!out?.success;
}

async function sendEmail(env: Env, to: string, subject: string, html: string): Promise<void> {
  const apiKey = (env.ISSUER_RESEND_API_KEY || "").trim();
  const from = (env.ISSUER_RESEND_FROM_EMAIL || "").trim();
  if (!apiKey || !from) throw new Error("resend_not_configured");

  const resp = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      authorization: `Bearer ${apiKey}`,
      "content-type": "application/json",
      accept: "application/json",
    },
    body: JSON.stringify({ from, to, subject, html }),
  });

  if (!resp.ok) {
    const t = await resp.text().catch(() => "");
    throw new Error(`resend_error:${resp.status}:${t.slice(0, 120)}`);
  }
}

export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const cors = getCorsHeaders(req, env);

    if (req.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: cors });
    }

    const url = new URL(req.url);

    if (url.pathname === "/health") {
      return json({ ok: true }, 200, cors);
    }

    // Publish current public key material for verifiers.
    if (url.pathname === "/v1/keys") {
      const keys = await loadOracleKeys(env);
      if (!keys.publicJwk) {
        return json({ ok: false, error: "no_public_key_configured" }, 503, cors);
      }
      return json(
        {
          ok: true,
          kid: keys.kid,
          jwk: keys.publicJwk,
        },
        200,
        cors,
      );
    }

    // Issue verification session
    if (url.pathname === "/v1/session" && req.method === "POST") {
      const ip = reqIp(req);
      const body = (await req.json().catch(() => null)) as any;

      const email = normalizeEmail(String(body?.email || ""));
      const turnstile = String(body?.turnstile_token || "");

      if (!isValidEmail(email)) return json({ ok: false, error: "invalid_email" }, 400, cors);
      if (!turnstile) return json({ ok: false, error: "missing_turnstile_token" }, 400, cors);

      const okTurnstile = await verifyTurnstile(env, turnstile, ip);
      if (!okTurnstile) return json({ ok: false, error: "turnstile_failed" }, 403, cors);

      const rateLimitPerIp = envInt(env.ISSUER_RATE_LIMIT_PER_IP, 5);
      const rateWindowS = envInt(env.ISSUER_RATE_LIMIT_WINDOW_SECONDS, 3600);

      const id = env.ISSUER_ORACLE.idFromName(ip);
      const stub = env.ISSUER_ORACLE.get(id);

      // Rate limit is enforced in the DO keyed by IP.
      const rl = await stub.fetch("https://do/rate", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ max: rateLimitPerIp, window_s: rateWindowS }),
      });
      const rlOut = (await rl.json().catch(() => null)) as any;
      if (!rl.ok || !rlOut?.ok) {
        return json({ ok: false, error: "rate_limited" }, 429, cors);
      }

      // Create a one-time session code stored in DO
      const sessionTtlS = envInt(env.ISSUER_SESSION_EXPIRES_IN, 600);
      const sessionResp = await stub.fetch("https://do/session", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email, ttl_s: sessionTtlS }),
      });
      if (!sessionResp.ok) return json({ ok: false, error: "session_failed" }, 500, cors);

      const sess = (await sessionResp.json().catch(() => null)) as any;
      const code = String(sess?.code || "");
      const session_id = String(sess?.session_id || "");
      if (!code || !session_id) return json({ ok: false, error: "session_failed" }, 500, cors);

      // Send email
      const subject = "WeAll verification code";
      const html = `
        <div style="font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif">
          <p>Your verification code is:</p>
          <p style="font-size: 24px; font-weight: 700; letter-spacing: 2px">${code}</p>
          <p>This code expires soon. If you didn't request this, you can ignore this message.</p>
        </div>
      `.trim();

      try {
        await sendEmail(env, email, subject, html);
      } catch {
        return json({ ok: false, error: "email_send_failed" }, 502, cors);
      }

      return json({ ok: true, session_id }, 200, cors);
    }

    // Redeem code -> return signed assertion
    if (url.pathname === "/v1/redeem" && req.method === "POST") {
      const ip = reqIp(req);
      const body = (await req.json().catch(() => null)) as any;

      const email = normalizeEmail(String(body?.email || ""));
      const session_id = String(body?.session_id || "");
      const code = String(body?.code || "").trim();

      if (!isValidEmail(email)) return json({ ok: false, error: "invalid_email" }, 400, cors);
      if (!session_id || !code) return json({ ok: false, error: "missing_fields" }, 400, cors);

      const id = env.ISSUER_ORACLE.idFromName(ip);
      const stub = env.ISSUER_ORACLE.get(id);

      const resp = await stub.fetch("https://do/redeem", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email, session_id, code }),
      });

      const out = (await resp.json().catch(() => null)) as any;
      if (!resp.ok || !out?.ok) {
        return json({ ok: false, error: out?.error || "redeem_failed" }, resp.status || 400, cors);
      }

      const { iat_ms, exp_ms } = issueTimestamps(env);
      const payload: Json = {
        iss: "weall-email-oracle",
        aud: "weall",
        typ: "email_verified",
        email,
        email_sha256: await sha256Hex(new TextEncoder().encode(email)),
        iat_ms,
        exp_ms,
      };

      // Prefer Ed25519 JWS; fallback to legacy HMAC token if configured.
      let token: string;
      try {
        token = await jwsEdDSA(env, payload);
      } catch {
        token = await signLegacyHmac(env, payload);
      }

      return json({ ok: true, token, exp_ms }, 200, cors);
    }

    // Verify token (convenience endpoint)
    if (url.pathname === "/v1/verify" && req.method === "POST") {
      const body = (await req.json().catch(() => null)) as any;
      const token = String(body?.token || "").trim();
      if (!token) return json({ ok: false, error: "missing_token" }, 400, cors);

      let payload: Json | null = await verifyJwsEdDSA(env, token);
      if (!payload) payload = await verifyLegacyHmac(env, token);
      if (!payload) return json({ ok: false, error: "invalid_token" }, 401, cors);
      if (isExpired(payload)) return json({ ok: false, error: "token_expired" }, 401, cors);

      return json({ ok: true, payload }, 200, cors);
    }

    return json({ ok: false, error: "not_found" }, 404, cors);
  },
} satisfies ExportedHandler<Env>;

// Durable Object for per-IP rate limiting + email session issuance
export class IssuerOracle {
  private state: DurableObjectState;

  constructor(state: DurableObjectState) {
    this.state = state;
  }

  async fetch(req: Request): Promise<Response> {
    const url = new URL(req.url);

    if (url.pathname === "/rate") {
      const body = (await req.json().catch(() => null)) as any;
      const max = Number(body?.max ?? 5);
      const windowS = Number(body?.window_s ?? 3600);

      const now = nowMs();
      const key = "rate";
      const cur = ((await this.state.storage.get(key)) as any) || { count: 0, window_start_ms: now };

      const winMs = Math.max(60, Math.trunc(windowS)) * 1000;
      if (now - cur.window_start_ms > winMs) {
        cur.count = 0;
        cur.window_start_ms = now;
      }

      cur.count += 1;
      await this.state.storage.put(key, cur);

      if (cur.count > Math.max(1, Math.trunc(max))) {
        return json({ ok: false, error: "rate_limited" }, 429);
      }

      return json({ ok: true, count: cur.count });
    }

    if (url.pathname === "/session") {
      const body = (await req.json().catch(() => null)) as any;
      const email = normalizeEmail(String(body?.email || ""));
      const ttlS = Math.max(60, Math.trunc(Number(body?.ttl_s ?? 600)));
      if (!isValidEmail(email)) return json({ ok: false, error: "invalid_email" }, 400);

      const session_id = crypto.randomUUID();
      const code = String(Math.floor(100000 + Math.random() * 900000)); // 6 digits

      await this.state.storage.put(`sess:${session_id}`, { email, code, exp_ms: nowMs() + ttlS * 1000 }, { expirationTtl: ttlS });
      return json({ ok: true, session_id, code });
    }

    if (url.pathname === "/redeem") {
      const body = (await req.json().catch(() => null)) as any;
      const email = normalizeEmail(String(body?.email || ""));
      const session_id = String(body?.session_id || "");
      const code = String(body?.code || "").trim();

      if (!isValidEmail(email) || !session_id || !code) return json({ ok: false, error: "missing_fields" }, 400);

      const rec = (await this.state.storage.get(`sess:${session_id}`)) as any;
      if (!rec) return json({ ok: false, error: "session_not_found" }, 404);
      if (rec.email !== email) return json({ ok: false, error: "email_mismatch" }, 403);
      if (nowMs() > Number(rec.exp_ms || 0)) return json({ ok: false, error: "session_expired" }, 403);
      if (String(rec.code) !== code) return json({ ok: false, error: "bad_code" }, 403);

      // One-time use
      await this.state.storage.delete(`sess:${session_id}`);
      return json({ ok: true });
    }

    return json({ ok: false, error: "not_found" }, 404);
  }
}
