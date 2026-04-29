/* global fetch, console, process, URL, AbortController, setTimeout, clearTimeout */

/**
 * Frontend↔Backend Contract Check
 *
 * Usage:
 *   API_BASE=http://127.0.0.1:8000 node scripts/contract_check.mjs
 *   (or via npm run contract-check)
 *
 * Optional:
 *   ACCOUNT=@alice SESSION_KEY=... to test account-private endpoints
 */

const API_BASE = (process.env.API_BASE || process.env.VITE_WEALL_API_BASE || "").replace(/\/+$/, "");
const ACCOUNT = (process.env.ACCOUNT || "").trim();
const SESSION_KEY = (process.env.SESSION_KEY || "").trim();

const TIMEOUT_MS = Number(process.env.TIMEOUT_MS || 8000);

function url(path) {
  const normalizedPath = path.startsWith("/") ? path : `/${path}`;
  const base = API_BASE || "http://127.0.0.1:8000";
  return new URL(normalizedPath, `${base}/`).toString();
}

function headers(extra = {}) {
  const h = { Accept: "application/json", ...extra };
  if (ACCOUNT) h["X-WeAll-Account"] = ACCOUNT;
  if (SESSION_KEY) h["X-WeAll-Session-Key"] = SESSION_KEY;
  return h;
}

async function fetchJson(path, opts = {}) {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url(path), {
      method: opts.method || "GET",
      headers: headers(opts.headers),
      body: opts.body ? JSON.stringify(opts.body) : undefined,
      signal: controller.signal,
    });

    const ct = res.headers.get("content-type") || "";
    const isJson = ct.includes("application/json");
    const body = isJson ? await res.json().catch(() => null) : await res.text().catch(() => "");

    return { ok: res.ok, status: res.status, body };
  } finally {
    clearTimeout(t);
  }
}

function fail(msg) {
  console.error(`❌ ${msg}`);
  process.exitCode = 1;
}

function pass(msg) {
  console.log(`✅ ${msg}`);
}

function assertOk(name, r) {
  if (!r.ok) {
    fail(`${name} -> HTTP ${r.status}: ${typeof r.body === "string" ? r.body : JSON.stringify(r.body)}`);
    return false;
  }
  pass(`${name} -> OK`);
  return true;
}

function assertHas(obj, keyPath, name) {
  const parts = keyPath.split(".");
  let cur = obj;
  for (const p of parts) {
    if (!cur || typeof cur !== "object" || !(p in cur)) {
      fail(`${name} missing field: ${keyPath}`);
      return false;
    }
    cur = cur[p];
  }
  pass(`${name} has ${keyPath}`);
  return true;
}

async function main() {
  console.log("WeAll Web Contract Check");
  console.log(`API_BASE: ${API_BASE || "(same-origin / relative)"}`);
  if (ACCOUNT) console.log(`ACCOUNT: ${ACCOUNT}`);
  if (SESSION_KEY) console.log("SESSION_KEY: (provided)");
  console.log("");

  {
    const r = await fetchJson("/v1/status");
    if (assertOk("GET /v1/status", r)) {
      if (r.body && typeof r.body === "object") assertHas(r.body, "ok", "status body");
    }
  }

  {
    const r = await fetchJson("/v1/readyz");
    assertOk("GET /v1/readyz", r);
  }

  {
    const r = await fetchJson("/v1/state/snapshot");
    if (assertOk("GET /v1/state/snapshot", r)) {
      if (!r.body || typeof r.body !== "object") fail("snapshot body is not JSON object");
      else pass("snapshot body is JSON object");
    }
  }

  {
    const r = await fetchJson("/v1/feed");
    if (assertOk("GET /v1/feed", r)) {
      if (r.body && typeof r.body === "object") {
        if ("items" in r.body) pass("feed body has items");
        else pass("feed body shape tolerated (no items key)");
      }
    }
  }

  {
    const r = await fetchJson("/v1/groups");
    assertOk("GET /v1/groups", r);
  }

  {
    const r = await fetchJson("/v1/gov/proposals?limit=5");
    assertOk("GET /v1/gov/proposals", r);
  }

  if (ACCOUNT) {
    {
      const r = await fetchJson(`/v1/accounts/${encodeURIComponent(ACCOUNT)}`);
      if (assertOk(`GET /v1/accounts/${ACCOUNT}`, r)) {
        if (r.body && typeof r.body === "object") {
          assertHas(r.body, "ok", "account body");
          assertHas(r.body, "state", "account body");
        }
      }
    }

    {
      const r = await fetchJson(`/v1/accounts/${encodeURIComponent(ACCOUNT)}/feed?limit=5&visibility=public`);
      assertOk(`GET /v1/accounts/${ACCOUNT}/feed (public)`, r);
    }

    if (SESSION_KEY) {
      const r = await fetchJson(`/v1/accounts/${encodeURIComponent(ACCOUNT)}/feed?limit=5&visibility=private`);
      assertOk(`GET /v1/accounts/${ACCOUNT}/feed (private)`, r);
    } else {
      pass("Skipping private account feed (set SESSION_KEY to test)");
    }
  } else {
    pass("Skipping account checks (set ACCOUNT to test)");
  }

  console.log("");
  if (process.exitCode) {
    console.error("Contract check FAILED.");
    process.exit(process.exitCode);
  } else {
    console.log("Contract check PASSED.");
  }
}

main().catch((e) => {
  fail(`Unexpected error: ${e?.message || String(e)}`);
  process.exit(1);
});
