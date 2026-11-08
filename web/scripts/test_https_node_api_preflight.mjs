#!/usr/bin/env node
import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import { checkHttpsNodeApi } from "./check_https_node_api.mjs";

const pins = {
  chain_id: "weall-testnet-v1",
  genesis_hash: "pinned-genesis",
  tx_index_hash: "pinned-tx",
  protocol_profile_hash: "pinned-profile",
};
const origin = "https://weall.example.org";
const api = "https://api.weall.example.org";

function mockFetch(options = {}) {
  const calls = [];
  const fakeFetch = async (url, init) => {
    calls.push({ url, init });
    const path = new URL(url).pathname;
    const isPreflight = init.method === "OPTIONS";
    const cors = {
      "access-control-allow-origin": options.badCors ? "https://attacker.example.org" : origin,
      "access-control-allow-credentials": "true",
      "access-control-allow-methods": "GET, POST, OPTIONS",
      "access-control-allow-headers": options.missingSessionHeader
        ? "Content-Type,X-WeAll-Account"
        : "Content-Type,X-WeAll-Account,X-WeAll-Session-Key",
    };
    if (isPreflight) return new Response(null, { status: 200, headers: cors });
    let payload;
    if (path === "/v1/status") {
      payload = { ok: true, chain_id: pins.chain_id, tx_index_hash: pins.tx_index_hash, protocol_profile_hash: pins.protocol_profile_hash };
    } else if (path === "/v1/readyz") {
      payload = { ok: options.unready ? false : true };
    } else if (path === "/v1/chain/identity") {
      payload = { ok: true, ...pins, chain_manifest: { genesis_hash: options.wrongGenesis ? "attacker-genesis" : pins.genesis_hash } };
    } else {
      return new Response(null, { status: 404, headers: cors });
    }
    return new Response(JSON.stringify(payload), { status: 200, headers: { ...cors, "content-type": "application/json" } });
  };
  return { calls, fakeFetch };
}

test("HTTPS checker validates public TLS URLs, exact frontend CORS and pinned chain", async () => {
  const { fakeFetch, calls } = mockFetch();
  const result = await checkHttpsNodeApi({ apiBase: api, frontendOrigin: origin, commitments: pins }, fakeFetch);
  assert.equal(result.ok, true);
  assert.equal(result.public_testnet_ready, false);
  assert.equal(result.registry_signature_verified, false);
  assert.equal(result.live_poh_verified, false);
  assert.equal(result.p2p_verified, false);
  assert.equal(calls.filter(({ init }) => init.method === "OPTIONS").length, 2);
  assert.ok(calls.every(({ init }) => init.redirect === "error" && init.credentials === "omit"));
  assert.ok(calls.some(({ init }) => init.method === "OPTIONS" && init.headers["Access-Control-Request-Headers"].includes("x-weall-session-key")));
});

test("rejects public HTTP and placeholder node API before any fetch", async () => {
  const { fakeFetch, calls } = mockFetch();
  for (const invalid of ["http://api.weall.example.org", "https://localhost", "https://api.invalid", "https://user:secret@api.weall.example.org"]) {
    await assert.rejects(checkHttpsNodeApi({ apiBase: invalid, frontendOrigin: origin, commitments: pins }, fakeFetch));
  }
  assert.equal(calls.length, 0);
});

test("rejects mismatched genesis commitment even if status/readyz are healthy", async () => {
  await assert.rejects(
    checkHttpsNodeApi({ apiBase: api, frontendOrigin: origin, commitments: pins }, mockFetch({ wrongGenesis: true }).fakeFetch),
    /pinned_network_mismatch:genesis_hash/,
  );
});

test("rejects inaccurate, missing or insufficiently scoped CORS responses", async () => {
  await assert.rejects(
    checkHttpsNodeApi({ apiBase: api, frontendOrigin: origin, commitments: pins }, mockFetch({ badCors: true }).fakeFetch),
    /cors_frontend_origin_mismatch/,
  );
  await assert.rejects(
    checkHttpsNodeApi({ apiBase: api, frontendOrigin: origin, commitments: pins }, mockFetch({ missingSessionHeader: true }).fakeFetch),
    /cors_missing_auth_header:x-weall-session-key/,
  );
});

test("rejects unready nodes and missing operator pins", async () => {
  await assert.rejects(
    checkHttpsNodeApi({ apiBase: api, frontendOrigin: origin, commitments: pins }, mockFetch({ unready: true }).fakeFetch),
    /readyz_not_healthy/,
  );
  await assert.rejects(
    checkHttpsNodeApi({ apiBase: api, frontendOrigin: origin, commitments: { ...pins, tx_index_hash: "" } }, mockFetch().fakeFetch),
    /missing_pinned_tx_index_hash/,
  );
});

test("public API TLS template keeps local secrets blocked and node authority separate", () => {
  const caddy = readFileSync(new URL("../deploy/Caddyfile.public-api.example", import.meta.url), "utf8");
  assert.ok(caddy.includes("{$WEALL_PUBLIC_API_DOMAIN}"), "operator must select actual HTTPS hostname");
  assert.ok(caddy.includes("{$WEALL_NODE_API_UPSTREAM}"), "upstream must be explicitly configured");
  assert.ok(caddy.includes("@api path /v1/*"), "API proxy must not forward arbitrary request paths");
  for (const blocked of ["/v1/dev/*", "/v1/observer/edge/*", "/v1/admin/*", "/v1/debug/*"]) {
    assert.ok(caddy.includes(blocked), "sensitive API path must be denied: " + blocked);
  }
  assert.ok(caddy.includes('respond @forbidden "Not found" 404'));
  assert.ok(!caddy.includes("tls_insecure_skip_verify"), "TLS bypass is forbidden");
  assert.ok(!caddy.includes("Access-Control-Allow-Origin *"), "CORS must remain backend-controlled");
});
