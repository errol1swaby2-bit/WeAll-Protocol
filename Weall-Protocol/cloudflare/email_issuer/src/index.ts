export interface Env {
  EMAIL_CODES: DurableObjectNamespace;
  TURNSTILE_SECRET: string;

  CODE_TTL_SECONDS: string;
  MAX_ATTEMPTS: string;

  FROM_EMAIL: string;
  FROM_NAME: string;
  SUBJECT: string;
}

type StartReq = { email: string };
type VerifyReq = { email: string; code: string; turnstile_token: string; remoteip?: string | null };

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

function normalizeEmail(email: string): string {
  return (email || "").trim().toLowerCase();
}

function isEmailish(email: string): boolean {
  return email.includes("@") && email.includes(".");
}

function random6(): string {
  const n = Math.floor(Math.random() * 1_000_000);
  return n.toString().padStart(6, "0");
}

async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", data);
  const bytes = new Uint8Array(digest);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

async function turnstileVerify(env: Env, token: string, remoteip?: string | null): Promise<boolean> {
  const form = new URLSearchParams();
  form.set("secret", env.TURNSTILE_SECRET);
  form.set("response", token);
  if (remoteip) form.set("remoteip", remoteip);

  const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: form.toString(),
  });

  const data = (await r.json()) as any;
  return !!data?.success;
}

/**
 * MailChannels transactional send:
 * https://api.mailchannels.net/tx/v1/send
 *
 * No private keys stored. You will need to align DNS/auth for your FROM domain.
 */
async function sendMail(env: Env, toEmail: string, code: string): Promise<void> {
  const ttlMin = Math.max(1, Math.floor(parseInt(env.CODE_TTL_SECONDS || "900", 10) / 60));
  const bodyText =
    "Your WeAll verification code is:\n\n" +
    `${code}\n\n` +
    `This code expires in ${ttlMin} minutes.\n` +
    "If you did not request this, you can ignore this email.\n";

  const payload = {
    personalizations: [{ to: [{ email: toEmail }] }],
    from: { email: env.FROM_EMAIL, name: env.FROM_NAME },
    subject: env.SUBJECT,
    content: [{ type: "text/plain", value: bodyText }],
  };

  const resp = await fetch("https://api.mailchannels.net/tx/v1/send", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });

  if (!resp.ok) {
    const t = await resp.text().catch(() => "");
    throw new Error(`mailchannels_failed status=${resp.status} body=${t.slice(0, 300)}`);
  }
}

type CodeRec = {
  code_hash: string;
  expires_ts_ms: number;
  attempts: number;
};

export class EmailCodes implements DurableObject {
  private state: DurableObjectState;
  private env: Env;

  constructor(state: DurableObjectState, env: Env) {
    this.state = state;
    this.env = env;
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === "POST" && path === "/start") return this.handleStart(request);
    if (request.method === "POST" && path === "/verify") return this.handleVerify(request);

    return json({ ok: false, error: "not_found" }, 404);
  }

  private async handleStart(request: Request): Promise<Response> {
    const ttlS = Math.max(60, parseInt(this.env.CODE_TTL_SECONDS || "900", 10));
    const now = Date.now();

    let body: any;
    try {
      body = await request.json();
    } catch {
      return json({ ok: false, error: "bad_json" }, 400);
    }

    const email = normalizeEmail((body as StartReq)?.email || "");
    if (!email || !isEmailish(email)) return json({ ok: false, error: "invalid_email" }, 400);

    const code = random6();
    const codeHash = await sha256Hex(code);
    const expires = now + ttlS * 1000;

    const rec: CodeRec = { code_hash: codeHash, expires_ts_ms: expires, attempts: 0 };
    await this.state.storage.put("rec", rec);

    // Send email (MailChannels)
    await sendMail(this.env, email, code);

    return json({ ok: true, sent: true, expires_ts_ms: expires });
  }

  private async handleVerify(request: Request): Promise<Response> {
    const maxAttempts = Math.max(1, parseInt(this.env.MAX_ATTEMPTS || "5", 10));
    const now = Date.now();

    let body: any;
    try {
      body = await request.json();
    } catch {
      return json({ ok: false, error: "bad_json" }, 400);
    }

    const email = normalizeEmail((body as VerifyReq)?.email || "");
    const code = String((body as VerifyReq)?.code || "").trim();
    const token = String((body as VerifyReq)?.turnstile_token || "").trim();
    const remoteip = (body as VerifyReq)?.remoteip || null;

    if (!email || !isEmailish(email)) return json({ ok: false, error: "email_required" }, 400);
    if (!code) return json({ ok: false, error: "code_required" }, 400);
    if (!token) return json({ ok: false, error: "turnstile_required" }, 400);

    const ok = await turnstileVerify(this.env, token, remoteip);
    if (!ok) return json({ ok: false, error: "turnstile_failed" }, 403);

    const rec = (await this.state.storage.get<CodeRec>("rec")) || null;
    if (!rec) return json({ ok: false, error: "no_pending_verification" }, 403);

    if (rec.expires_ts_ms <= 0 || now > rec.expires_ts_ms) {
      await this.state.storage.delete("rec");
      return json({ ok: false, error: "expired" }, 403);
    }

    if (rec.attempts >= maxAttempts) {
      return json({ ok: false, error: "too_many_attempts" }, 429);
    }

    const got = await sha256Hex(code);
    if (got !== rec.code_hash) {
      rec.attempts += 1;
      await this.state.storage.put("rec", rec);
      return json({ ok: false, error: "invalid_code" }, 403);
    }

    // One-time use: delete on success
    await this.state.storage.delete("rec");
    return json({ ok: true });
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // Route everything to a single DO instance per email (deterministic keying)
    if (url.pathname === "/start" || url.pathname === "/verify") {
      if (request.method !== "POST") return json({ ok: false, error: "method_not_allowed" }, 405);

      let body: any;
      try {
        body = await request.clone().json();
      } catch {
        return json({ ok: false, error: "bad_json" }, 400);
      }

      const email = normalizeEmail(body?.email || "");
      if (!email || !isEmailish(email)) return json({ ok: false, error: "invalid_email" }, 400);

      const id = env.EMAIL_CODES.idFromName(email);
      const stub = env.EMAIL_CODES.get(id);

      // Forward original request body to DO
      return stub.fetch(new Request(`https://do.local${url.pathname}`, request));
    }

    return json({ ok: false, error: "not_found" }, 404);
  },
};
