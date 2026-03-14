export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method !== "POST") return json({ ok: false, error: "method" }, 405);

    if (url.pathname === "/start") return await handleStart(request, env);
    if (url.pathname === "/verify") return await handleVerify(request, env);

    return json({ ok: false, error: "not_found" }, 404);
  },
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function normEmail(email) {
  return String(email || "").trim().toLowerCase();
}

async function sha256Hex(str) {
  const enc = new TextEncoder().encode(str);
  const hash = await crypto.subtle.digest("SHA-256", enc);
  return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function randomCode6() {
  const n = crypto.getRandomValues(new Uint32Array(1))[0] % 1000000;
  return String(n).padStart(6, "0");
}

async function verifyTurnstile(env, token, ip) {
  const form = new FormData();
  form.append("secret", env.TURNSTILE_SECRET);
  form.append("response", token);
  if (ip) form.append("remoteip", ip);

  const resp = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
    method: "POST",
    body: form,
  });
  const data = await resp.json();
  return !!data.success;
}

async function sendWithResend(env, toEmail, code) {
  const payload = {
    from: env.FROM_EMAIL,
    to: [toEmail],
    subject: "WeAll Testnet Email Verification",
    text: `Your WeAll verification code is: ${code}\n\nIt expires in 15 minutes.`,
  };

  const resp = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.RESEND_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  if (!resp.ok) {
    const t = await resp.text();
    throw new Error(`resend_failed: ${resp.status} ${t}`);
  }
}

async function handleStart(request, env) {
  const ip = request.headers.get("CF-Connecting-IP") || "";
  const body = await request.json().catch(() => null);
  if (!body || typeof body !== "object") return json({ ok: false, error: "bad_json" }, 400);

  const email = normEmail(body.email);
  const turnstileToken = String(body.turnstile_token || "").trim();

  if (!email || !email.includes("@")) return json({ ok: false, error: "invalid_email" }, 400);
  if (!turnstileToken) return json({ ok: false, error: "missing_turnstile" }, 400);

  const ok = await verifyTurnstile(env, turnstileToken, ip);
  if (!ok) return json({ ok: false, error: "turnstile_failed" }, 403);

  const code = randomCode6();
  const codeHash = await sha256Hex(code);
  const expiresMs = Date.now() + 15 * 60 * 1000;

  const key = `v1:${email}`;
  await env.WEALL_EMAIL_CODES.put(
    key,
    JSON.stringify({ code_hash: codeHash, expires_ms: expiresMs }),
    { expirationTtl: 15 * 60 }
  );

  await sendWithResend(env, email, code);
  return json({ ok: true, sent: true, expires_ms: expiresMs });
}

async function handleVerify(request, env) {
  const ip = request.headers.get("CF-Connecting-IP") || "";
  const body = await request.json().catch(() => null);
  if (!body || typeof body !== "object") return json({ ok: false, error: "bad_json" }, 400);

  const email = normEmail(body.email);
  const code = String(body.code || "").trim();
  const turnstileToken = String(body.turnstile_token || "").trim();

  if (!email || !email.includes("@")) return json({ ok: false, error: "invalid_email" }, 400);
  if (!code || code.length < 4) return json({ ok: false, error: "invalid_code" }, 400);
  if (!turnstileToken) return json({ ok: false, error: "missing_turnstile" }, 400);

  const ok = await verifyTurnstile(env, turnstileToken, ip);
  if (!ok) return json({ ok: false, error: "turnstile_failed" }, 403);

  const key = `v1:${email}`;
  const raw = await env.WEALL_EMAIL_CODES.get(key);
  if (!raw) return json({ ok: false, error: "no_record" }, 403);

  const rec = JSON.parse(raw);
  if (Date.now() > Number(rec.expires_ms || 0)) return json({ ok: false, error: "expired" }, 403);

  const codeHash = await sha256Hex(code);
  if (codeHash !== rec.code_hash) return json({ ok: false, error: "mismatch" }, 403);

  // One-time use
  await env.WEALL_EMAIL_CODES.delete(key);

  return json({ ok: true, verified: true });
}
