import nacl from "tweetnacl";

export interface Env {
  DB: D1Database;

  TURNSTILE_SECRET_KEY: string;
  RESEND_API_KEY: string;
  RELAY_SIGNING_SECRET: string;
  EMAIL_CHALLENGE_SALT: string;

  EMAIL_ORACLE_ALLOWED_ORIGINS?: string;
  EMAIL_FROM?: string;
  REQUIRE_TURNSTILE_ON_START?: string;
  ALLOW_TURNSTILE_BYPASS?: string;
  TURNSTILE_BYPASS_TOKEN?: string;
  CHALLENGE_TTL_SECONDS?: string;
  MAX_VERIFY_ATTEMPTS?: string;
  RELAY_ACCOUNT_ID?: string;
}

type StartBody = {
  account_id?: string;
  operator_account_id?: string;
  email?: string;
  turnstile_token?: string;
};

type VerifyBody = {
  challenge_id?: string;
  code?: string;
};

type RelayCompletionPayload = {
  version: 1;
  type: "email_challenge_completed";
  challenge_id: string;
  account_id: string;
  operator_account_id: string | null;
  relay_account_id: string;
  relay_pubkey: string;
  email_commitment: string;
  issued_at_ms: number;
  expires_at_ms: number;
};

function envBool(value: string | undefined, fallback: boolean): boolean {
  if (!value) return fallback;
  const v = value.trim().toLowerCase();
  return v === "1" || v === "true" || v === "yes" || v === "on";
}

function envInt(value: string | undefined, fallback: number): number {
  const n = Number.parseInt(String(value ?? ""), 10);
  return Number.isFinite(n) ? n : fallback;
}

function nowMs(): number {
  return Date.now();
}

function json(data: unknown, init?: ResponseInit): Response {
  return new Response(JSON.stringify(data, null, 2), {
    ...init,
    headers: {
      "content-type": "application/json; charset=utf-8",
      ...(init?.headers ?? {}),
    },
  });
}

function parseAllowedOrigins(raw: string | undefined): string[] {
  return String(raw ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function corsHeaders(origin: string | null, env: Env): Record<string, string> {
  const allowed = parseAllowedOrigins(env.EMAIL_ORACLE_ALLOWED_ORIGINS);
  const allowOrigin = origin && allowed.includes(origin) ? origin : allowed[0] ?? "*";
  return {
    "access-control-allow-origin": allowOrigin,
    "access-control-allow-methods": "GET,POST,OPTIONS",
    "access-control-allow-headers": "content-type",
    "access-control-max-age": "86400",
    vary: "Origin",
  };
}

function badRequest(env: Env, origin: string | null, error: string, details?: unknown): Response {
  return json(
    { ok: false, error, details: details ?? null },
    { status: 400, headers: corsHeaders(origin, env) },
  );
}

function forbidden(env: Env, origin: string | null, error: string, details?: unknown): Response {
  return json(
    { ok: false, error, details: details ?? null },
    { status: 403, headers: corsHeaders(origin, env) },
  );
}

function serverError(env: Env, origin: string | null, error: string, details?: unknown): Response {
  return json(
    { ok: false, error, details: details ?? null },
    { status: 500, headers: corsHeaders(origin, env) },
  );
}

function normalizeEmail(value: string): string {
  return value.trim().toLowerCase();
}

function maskEmail(email: string): string {
  const [local, domain] = email.split("@");
  if (!local || !domain) return email;
  const head = local.slice(0, 2);
  return `${head}${"*".repeat(Math.max(1, local.length - 2))}@${domain}`;
}

function randomDigits(length: number): string {
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  let out = "";
  for (let i = 0; i < length; i += 1) out += String(bytes[i] % 10);
  return out;
}

function timingSafeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", data);
  const bytes = new Uint8Array(digest);
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function sha256Bytes(input: Uint8Array): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest("SHA-256", input);
  return new Uint8Array(digest);
}

function hexOfBytes(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function deriveRelayKeypair(env: Env): Promise<{ pubkeyHex: string; secretKey: Uint8Array }> {
  const seed = await sha256Bytes(
    new TextEncoder().encode(String(env.RELAY_SIGNING_SECRET || "")),
  );
  const kp = nacl.sign.keyPair.fromSeed(seed);
  const pubkeyHex = hexOfBytes(Uint8Array.from(kp.publicKey));
  return { pubkeyHex, secretKey: Uint8Array.from(kp.secretKey) };
}

function canonicalRelayPayload(payload: RelayCompletionPayload): string {
  return JSON.stringify({
    version: payload.version,
    type: payload.type,
    challenge_id: payload.challenge_id,
    account_id: payload.account_id,
    operator_account_id: payload.operator_account_id,
    relay_account_id: payload.relay_account_id,
    relay_pubkey: payload.relay_pubkey,
    email_commitment: payload.email_commitment,
    issued_at_ms: payload.issued_at_ms,
    expires_at_ms: payload.expires_at_ms,
  });
}

async function signRelayCompletionToken(
  env: Env,
  payload: Omit<RelayCompletionPayload, "relay_account_id" | "relay_pubkey">,
): Promise<{ payload: RelayCompletionPayload; signature: string }> {
  const relay_account_id = String(env.RELAY_ACCOUNT_ID || "@weall-relay").trim();
  const kp = await deriveRelayKeypair(env);
  const full: RelayCompletionPayload = {
    ...payload,
    relay_account_id,
    relay_pubkey: kp.pubkeyHex,
  };
  const msg = new TextEncoder().encode(canonicalRelayPayload(full));
  const sig = nacl.sign.detached(msg, kp.secretKey);
  const signature = hexOfBytes(Uint8Array.from(sig));
  return { payload: full, signature };
}

async function verifyTurnstile(
  env: Env,
  token: string,
  remoteIp?: string | null,
): Promise<{ success: boolean; body: unknown }> {
  const form = new FormData();
  form.set("secret", env.TURNSTILE_SECRET_KEY);
  form.set("response", token);
  if (remoteIp) form.set("remoteip", remoteIp);

  const res = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
    method: "POST",
    body: form,
  });
  const body = await res.json<unknown>();
  const success =
    typeof body === "object" &&
    body !== null &&
    "success" in body &&
    (body as { success?: boolean }).success === true;

  return { success, body };
}

async function sendVerificationEmail(
  env: Env,
  email: string,
  code: string,
  accountId: string,
): Promise<{ id?: string | null }> {
  const from = String(env.EMAIL_FROM ?? "").trim();
  if (!from) throw new Error("missing_EMAIL_FROM");

  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      authorization: `Bearer ${env.RESEND_API_KEY}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      from,
      to: [email],
      subject: "Your WeAll verification code",
      html: `
        <div style="font-family: Arial, sans-serif; line-height: 1.5;">
          <p>Your WeAll verification code for <strong>${accountId}</strong> is:</p>
          <h2 style="letter-spacing: 4px;">${code}</h2>
          <p>This code expires in 10 minutes.</p>
        </div>
      `,
    }),
  });

  const body = (await res.json()) as { id?: string | null; message?: string };
  if (!res.ok) {
    throw new Error(`resend_send_failed:${JSON.stringify(body)}`);
  }
  return { id: body.id ?? null };
}

function requireString(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const v = value.trim();
  return v ? v : null;
}

async function handleStart(request: Request, env: Env): Promise<Response> {
  const origin = request.headers.get("Origin");

  let body: StartBody;
  try {
    body = (await request.json()) as StartBody;
  } catch {
    return badRequest(env, origin, "invalid_json");
  }

  const accountId = requireString(body.account_id);
  const operatorAccountId = requireString(body.operator_account_id);
  const emailRaw = requireString(body.email);
  const turnstileToken = requireString(body.turnstile_token);

  if (!accountId) return badRequest(env, origin, "missing_account_id");
  if (!emailRaw) return badRequest(env, origin, "missing_email");

  const email = normalizeEmail(emailRaw);
  const requireTurnstile = envBool(env.REQUIRE_TURNSTILE_ON_START, true);
  const allowBypass = envBool(env.ALLOW_TURNSTILE_BYPASS, false);
  const bypassToken = String(env.TURNSTILE_BYPASS_TOKEN ?? "");

  if (requireTurnstile) {
    const bypassAllowed = allowBypass && turnstileToken === bypassToken;
    if (!bypassAllowed) {
      if (!turnstileToken) {
        return badRequest(env, origin, "missing_turnstile_token");
      }
      const remoteIp = request.headers.get("CF-Connecting-IP");
      const checked = await verifyTurnstile(env, turnstileToken, remoteIp);
      if (!checked.success) {
        return forbidden(env, origin, "turnstile_invalid", checked.body);
      }
    }
  }

  const challengeId = crypto.randomUUID();
  const code = randomDigits(6);
  const createdAt = nowMs();
  const ttlSeconds = Math.max(60, envInt(env.CHALLENGE_TTL_SECONDS, 600));
  const expiresAt = createdAt + ttlSeconds * 1000;

  const codeHash = await sha256Hex(
    `${challengeId}:${accountId}:${email}:${code}:${env.EMAIL_CHALLENGE_SALT}`,
  );

  let resendId: string | null = null;
  try {
    const sent = await sendVerificationEmail(env, email, code, accountId);
    resendId = sent.id ?? null;
  } catch (error) {
    return serverError(env, origin, "email_send_failed", String(error));
  }

  try {
    await env.DB.prepare(
      `
      INSERT INTO email_challenges (
        challenge_id,
        account_id,
        operator_account_id,
        email,
        code_hash,
        status,
        attempts,
        created_at_ms,
        expires_at_ms,
        verified_at_ms,
        resend_id
      ) VALUES (?, ?, ?, ?, ?, 'pending', 0, ?, ?, NULL, ?)
      `,
    )
      .bind(
        challengeId,
        accountId,
        operatorAccountId,
        email,
        codeHash,
        createdAt,
        expiresAt,
        resendId,
      )
      .run();
  } catch (error) {
    return serverError(env, origin, "challenge_store_failed", String(error));
  }

  return json(
    {
      ok: true,
      challenge_id: challengeId,
      email_masked: maskEmail(email),
      expires_at_ms: expiresAt,
      provider: "resend",
      resend_id: resendId,
    },
    { status: 200, headers: corsHeaders(origin, env) },
  );
}

async function handleVerify(request: Request, env: Env): Promise<Response> {
  const origin = request.headers.get("Origin");

  let body: VerifyBody;
  try {
    body = (await request.json()) as VerifyBody;
  } catch {
    return badRequest(env, origin, "invalid_json");
  }

  const challengeId = requireString(body.challenge_id);
  const code = requireString(body.code);

  if (!challengeId) return badRequest(env, origin, "missing_challenge_id");
  if (!code) return badRequest(env, origin, "missing_code");

  let row:
    | {
        challenge_id: string;
        account_id: string;
        operator_account_id: string | null;
        email: string;
        code_hash: string;
        status: string;
        attempts: number;
        created_at_ms: number;
        expires_at_ms: number;
      }
    | null = null;

  try {
    row = await env.DB.prepare(
      `
      SELECT challenge_id, account_id, operator_account_id, email, code_hash, status, attempts, created_at_ms, expires_at_ms
      FROM email_challenges
      WHERE challenge_id = ?
      LIMIT 1
      `,
    )
      .bind(challengeId)
      .first<{
        challenge_id: string;
        account_id: string;
        operator_account_id: string | null;
        email: string;
        code_hash: string;
        status: string;
        attempts: number;
        created_at_ms: number;
        expires_at_ms: number;
      }>();
  } catch (error) {
    return serverError(env, origin, "challenge_lookup_failed", String(error));
  }

  if (!row) return badRequest(env, origin, "unknown_challenge");

  const now = nowMs();
  if (row.status !== "pending") {
    return badRequest(env, origin, "challenge_not_pending", { status: row.status });
  }
  if (now > row.expires_at_ms) {
    await env.DB.prepare(
      `UPDATE email_challenges SET status = 'expired' WHERE challenge_id = ?`,
    )
      .bind(challengeId)
      .run();
    return badRequest(env, origin, "challenge_expired");
  }

  const maxAttempts = Math.max(1, envInt(env.MAX_VERIFY_ATTEMPTS, 8));
  if (row.attempts >= maxAttempts) {
    await env.DB.prepare(
      `UPDATE email_challenges SET status = 'failed' WHERE challenge_id = ?`,
    )
      .bind(challengeId)
      .run();
    return badRequest(env, origin, "max_attempts_exceeded");
  }

  const candidateHash = await sha256Hex(
    `${row.challenge_id}:${row.account_id}:${row.email}:${code}:${env.EMAIL_CHALLENGE_SALT}`,
  );

  if (!timingSafeEqualHex(candidateHash, row.code_hash)) {
    await env.DB.prepare(
      `UPDATE email_challenges SET attempts = attempts + 1 WHERE challenge_id = ?`,
    )
      .bind(challengeId)
      .run();
    return badRequest(env, origin, "invalid_code");
  }

  const verifiedAt = nowMs();
  try {
    await env.DB.prepare(
      `
      UPDATE email_challenges
      SET status = 'verified',
          verified_at_ms = ?,
          attempts = attempts + 1
      WHERE challenge_id = ?
      `,
    )
      .bind(verifiedAt, challengeId)
      .run();
  } catch (error) {
    return serverError(env, origin, "challenge_update_failed", String(error));
  }

  const emailCommitment = await sha256Hex(`${row.email}:${env.EMAIL_CHALLENGE_SALT}`);
  const token = await signRelayCompletionToken(env, {
    version: 1,
    type: "email_challenge_completed",
    challenge_id: row.challenge_id,
    account_id: row.account_id,
    operator_account_id: row.operator_account_id,
    email_commitment: emailCommitment,
    issued_at_ms: verifiedAt,
    expires_at_ms: row.expires_at_ms,
  });

  return json(
    {
      ok: true,
      challenge_id: row.challenge_id,
      completed: true,
      relay_token: token,
    },
    { status: 200, headers: corsHeaders(origin, env) },
  );
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const origin = request.headers.get("Origin");
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(origin, env) });
    }

    if (request.method === "GET" && url.pathname === "/healthz") {
      const relay_account_id = String(env.RELAY_ACCOUNT_ID || "@weall-relay").trim();
      const kp = await deriveRelayKeypair(env);
      return json(
        {
          ok: true,
          service: "weall-email-relay",
          relay_account_id,
          relay_pubkey: kp.pubkeyHex,
        },
        { headers: corsHeaders(origin, env) },
      );
    }

    if (request.method === "POST" && url.pathname === "/start") {
      return handleStart(request, env);
    }

    if (request.method === "POST" && url.pathname === "/verify") {
      return handleVerify(request, env);
    }

    return json({ ok: false, error: "not_found" }, { status: 404, headers: corsHeaders(origin, env) });
  },
};
