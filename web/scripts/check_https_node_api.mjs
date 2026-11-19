#!/usr/bin/env node
/**
 * Read-only operator verification for browser-facing WeAll HTTPS node APIs.
 *
 * A passing result proves TLS/client CORS/readiness response configuration at
 * the instant of testing. It does not validate seed-registry ML-DSA signatures,
 * consensus safety, PoH sessions, P2P ports or actual Cloudflare deployment.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const COMMITMENTS = ["chain_id", "genesis_hash", "tx_index_hash", "protocol_profile_hash"];
function originOf(raw, role) {
  const url = new URL(String(raw || ""));
  assert.equal(url.protocol, "https:", role + "_must_be_https");
  assert.ok(url.hostname && !url.username && !url.password, role + "_invalid_host");
  assert.ok(!url.search && !url.hash && (url.pathname === "/" || url.pathname === ""), role + "_must_be_origin");
  const host = url.hostname.toLowerCase();
  assert.ok(
    !["localhost", "127.0.0.1", "[::1]", "0.0.0.0"].includes(host) &&
    !/[.](test|example|invalid|local|localhost)$/.test(host),
    role + "_must_be_non_placeholder",
  );
  return url.origin;
}

function jsonObject(payload, path) {
  assert.ok(payload && typeof payload === "object" && !Array.isArray(payload), "invalid_json_object:" + path);
  return payload;
}

function verifyCors(response, frontendOrigin, method) {
  const allowed = response.headers.get("access-control-allow-origin");
  assert.equal(allowed, frontendOrigin, "cors_frontend_origin_mismatch");
  if (method === "OPTIONS") {
    assert.equal(response.headers.get("access-control-allow-credentials"), "true", "cors_credentials_policy_mismatch");
    const headers = String(response.headers.get("access-control-allow-headers") || "").toLowerCase().split(",").map((x) => x.trim());
    for (const required of ["x-weall-account", "x-weall-session-key", "content-type"]) {
      assert.ok(headers.includes(required), "cors_missing_auth_header:" + required);
    }
  }
}

async function requestJson(fetchImpl, base, path, origin, timeoutMs) {
  const response = await fetchImpl(base + path, {
    method: "GET",
    headers: { Accept: "application/json", Origin: origin },
    redirect: "error",
    credentials: "omit",
    signal: AbortSignal.timeout(timeoutMs),
  });
  assert.equal(response.status, 200, "endpoint_non_200:" + path);
  verifyCors(response, origin, "GET");
  return jsonObject(await response.json(), path);
}

export async function checkHttpsNodeApi(
  { apiBase, frontendOrigin, commitments, timeoutMs = 5000 },
  fetchImpl = fetch,
) {
  const base = originOf(apiBase, "node_api");
  const origin = originOf(frontendOrigin, "frontend");
  assert.ok(commitments && typeof commitments === "object", "pinned_commitments_required");
  for (const key of COMMITMENTS) {
    assert.ok(typeof commitments[key] === "string" && commitments[key].trim(), "missing_pinned_" + key);
  }
  const timeout = Math.max(1000, Math.min(15000, Number(timeoutMs) || 5000));
  const [status, ready, identity] = await Promise.all([
    requestJson(fetchImpl, base, "/v1/status", origin, timeout),
    requestJson(fetchImpl, base, "/v1/readyz", origin, timeout),
    requestJson(fetchImpl, base, "/v1/chain/identity", origin, timeout),
  ]);
  assert.equal(status.ok, true, "status_not_healthy");
  assert.equal(ready.ok, true, "readyz_not_healthy");
  assert.equal(identity.ok, true, "chain_identity_not_healthy");

  const manifest = jsonObject(identity.chain_manifest, "chain_manifest");
  const observed = {
    chain_id: identity.chain_id || status.chain_id,
    genesis_hash: manifest.genesis_hash,
    tx_index_hash: identity.tx_index_hash || status.tx_index_hash,
    protocol_profile_hash: identity.protocol_profile_hash || status.protocol_profile_hash,
  };
  for (const key of COMMITMENTS) {
    assert.equal(observed[key], commitments[key], "pinned_network_mismatch:" + key);
  }

  for (const [path, method] of [
    ["/v1/session/me", "GET"],
    ["/v1/tx/submit", "POST"],
  ]) {
    const response = await fetchImpl(base + path, {
      method: "OPTIONS",
      headers: {
        Origin: origin,
        "Access-Control-Request-Method": method,
        "Access-Control-Request-Headers": "x-weall-account,x-weall-session-key,content-type",
      },
      redirect: "error",
      credentials: "omit",
      signal: AbortSignal.timeout(timeout),
    });
    assert.equal(response.status, 200, "cors_preflight_non_200:" + path);
    verifyCors(response, origin, "OPTIONS");
    const allowedMethods = String(response.headers.get("access-control-allow-methods") || "");
    assert.ok(allowedMethods.split(",").map((x) => x.trim()).includes(method), "cors_method_not_allowed:" + method);
  }

  return {
    ok: true,
    api_base: base,
    frontend_origin: origin,
    observed_chain_id: observed.chain_id,
    readiness_and_identity: true,
    tls_browser_fetch_and_cors: true,
    browser_auth_headers_preflight: true,
    public_testnet_ready: false,
    registry_signature_verified: false,
    live_poh_verified: false,
    p2p_verified: false,
  };
}

async function main() {
  const args = process.argv.slice(2);
  const flags = new Map();
  for (let i = 0; i < args.length; i += 2) {
    if (!args[i]?.startsWith("--") || !args[i + 1]) throw new Error("invalid_cli_arguments");
    flags.set(args[i], args[i + 1]);
  }
  const apiBase = flags.get("--api-base");
  const frontendOrigin = flags.get("--frontend-origin");
  const commitmentsFile = flags.get("--commitments");
  if (!apiBase || !frontendOrigin || !commitmentsFile) {
    throw new Error("usage: node scripts/check_https_node_api.mjs --api-base https://api.host --frontend-origin https://app.host --commitments ../Weall-Protocol/configs/public_testnet_chain_commitments.json");
  }
  const commitments = JSON.parse(readFileSync(resolve(commitmentsFile), "utf8"));
  const outcome = await checkHttpsNodeApi({ apiBase, frontendOrigin, commitments });
  process.stdout.write(JSON.stringify(outcome, null, 2) + "\n");
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  main().catch((error) => {
    // Do not print endpoints' raw responses, body data or any session keys.
    process.stderr.write("HTTPS_NODE_API_CHECK_FAILED: " + String(error?.message || "verification_failed") + "\n");
    process.exitCode = 1;
  });
}
