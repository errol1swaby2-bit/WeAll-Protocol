/* global fetch, console, process, URL, AbortController, setTimeout, clearTimeout */

/**
 * Frontend↔Backend Contract Check
 *
 * Usage:
 *   API_BASE=http://127.0.0.1:8000 node scripts/contract_check.mjs
 *   (or via npm run contract-check)
 *
 * Optional:
 *   ACCOUNT=@alice SESSION_KEY=... to test account-sensitive endpoints
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
    console.log("\nNode/operator readiness surfaces");
    const endpoints = [
      ["GET /v1/status/operator", "/v1/status/operator"],
      ["GET /v1/status/consensus", "/v1/status/consensus"],
      ["GET /v1/status/mempool", "/v1/status/mempool"],
      ["GET /v1/storage/ipfs/ops", "/v1/storage/ipfs/ops"],
      ["GET /v1/chain/head", "/v1/chain/head"],
      ["GET /v1/chain/identity", "/v1/chain/identity"],
      ["GET /v1/status/testnet-capabilities", "/v1/status/testnet-capabilities"],
      ["GET /v1/consensus/block-production/readiness", "/v1/consensus/block-production/readiness"],
      ["GET /v1/status/helper/readiness", "/v1/status/helper/readiness"],
      ["GET /v1/net/self", "/v1/net/self"],
      ["GET /v1/nodes/seeds", "/v1/nodes/seeds"],
      ["GET /v1/nodes/validators", "/v1/nodes/validators"],
      ["GET /v1/observer/edge/status", "/v1/observer/edge/status"],
    ];
    for (const [label, path] of endpoints) {
      const r = await fetchJson(path);
      if (assertOk(label, r)) {
        if (!r.body || typeof r.body !== "object") fail(`${label} body is not JSON object`);
        else assertHas(r.body, "ok", `${label} body`);
      }
    }
  }

  {
    const r = await fetchJson("/v1/gov/proposals?limit=5");
    assertOk("GET /v1/gov/proposals", r);
  }

  {
    const contractTxId = "contract-check-nonexistent-tx";
    const r = await fetchJson(`/v1/tx/status/${encodeURIComponent(contractTxId)}`);
    if (assertOk("GET /v1/tx/status/:tx_id", r)) {
      if (!r.body || typeof r.body !== "object") {
        fail("tx status body is not JSON object");
      } else {
        assertHas(r.body, "status", "tx status body");
        const allowed = new Set(["confirmed", "pending", "unknown", "failed", "rejected"]);
        const status = String(r.body.status || "").trim().toLowerCase();
        if (!allowed.has(status)) {
          fail(`tx status body has unsupported lifecycle status: ${status || "(empty)"}`);
        } else {
          pass(`tx status lifecycle status is explicit: ${status}`);
        }
      }
    }
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
      const r = await fetchJson(`/v1/accounts/${encodeURIComponent(ACCOUNT)}/reviewer-status`);
      if (assertOk(`GET /v1/accounts/${ACCOUNT}/reviewer-status`, r)) {
        if (r.body && typeof r.body === "object") {
          assertHas(r.body, "ok", "reviewer status body");
          assertHas(r.body, "reviewer", "reviewer status body");
        }
      }
    }

    {
      const r = await fetchJson(`/v1/accounts/${encodeURIComponent(ACCOUNT)}/feed?limit=5&visibility=public`);
      assertOk(`GET /v1/accounts/${ACCOUNT}/feed (public)`, r);
    }

    {
      const r = await fetchJson(`/v1/accounts/${encodeURIComponent(ACCOUNT)}/feed?limit=5&visibility=all`);
      assertOk(`GET /v1/accounts/${ACCOUNT}/feed (public all)`, r);
    }
  } else {
    pass("Skipping account checks and reviewer-status contract check (set ACCOUNT to test)");
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
  const message = e?.message || String(e);
  fail(`Unexpected error: ${message}`);
  console.error(
    "Hint: contract-check is an integration check. Start the backend API first, then run " +
      "API_BASE=http://127.0.0.1:8000 npm run contract-check"
  );
  process.exit(1);
});
