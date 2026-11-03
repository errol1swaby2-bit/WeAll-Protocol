#!/usr/bin/env node
// Executable public-testnet discovery and authenticated browser session regression.
// Runs actual TypeScript modules; browser storage/network/API responses are mocked.
import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const chain = {
  chain_id: "weall-testnet-v1",
  genesis_hash: "genesis-1",
  tx_index_hash: "transactions-1",
  protocol_profile_hash: "profile-1",
};
const config = {
  publicTestnet: true,
  defaultApiBase: "/",
  seedsUrl: "/seeds.json",
  expectedChainId: chain.chain_id,
  expectedGenesisHash: chain.genesis_hash,
  expectedTxIndexHash: chain.tx_index_hash,
  expectedProtocolProfileHash: chain.protocol_profile_hash,
};
let selected = "/";
let changes = 0;
let localSession = null;
const live = new Set(["healthy.test", "backup.test", "wrong.test", "notready.test", "unlisted.test"]);
const recognized = new Set(["healthy.test"]);
const sessionCalls = [];

const validateApiBaseInput = (value) => {
  if (value === "/") return { ok: true, normalized: "/" };
  try {
    const url = new URL(value);
    if (url.protocol !== "https:") return { ok: false, reason: "https required" };
    return { ok: true, normalized: url.origin };
  } catch {
    return { ok: false, reason: "invalid URL" };
  }
};
const api = {
  getApiBaseUrl: () => selected,
  setApiBaseUrl: (next) => {
    const valid = validateApiBaseInput(next);
    assert.ok(valid.ok, "invalid public URL must not be selected");
    selected = valid.normalized;
    changes += 1;
    return selected;
  },
  validateApiBaseInput,
};
const response = (payload, status = 200) => new Response(JSON.stringify(payload), {
  status,
  headers: { "content-type": "application/json" },
});
async function fakeFetch(input, init = {}) {
  const url = String(input);
  if (url === "/seeds.json") {
    return response({
      ...chain,
      nodes: [
        { label: "Healthy seed", api_base: "https://healthy.test" },
        { label: "Backup seed", api_base: "https://backup.test" },
        { label: "Wrong network", api_base: "https://wrong.test" },
        { label: "Not ready", api_base: "https://notready.test" },
        { label: "Insecure", api_base: "http://insecure.test" },
      ],
    });
  }
  if (url === "/v1/nodes/seeds") return response({}, 404);
  if (url.startsWith("https://") && url.endsWith("/v1/nodes/seeds")) {
    return response({ nodes: [{ base_url: "https://unlisted.test" }] });
  }
  if (url === "https://seed.test/v1/nodes/seeds") {
    return response({ nodes: [{ base_url: "https://healthy.test" }] });
  }
  if (!url.startsWith("https://")) return response({}, 404);
  const host = new URL(url).hostname;
  if (!live.has(host)) return response({}, 503);
  if (url.endsWith("/v1/session/me")) {
    sessionCalls.push({ host, headers: new Headers(init.headers), init });
    const requestedAccount = new Headers(init.headers).get("X-WeAll-Account");
    return response({
      ok: true,
      authenticated: recognized.has(host),
      account: requestedAccount,
      session: { active: recognized.has(host), expired: false, device_id: "browser:fixture" },
    });
  }
  const identity = host === "wrong.test"
    ? { ...chain, chain_id: "other-network" }
    : chain;
  const { genesis_hash, ...statusIdentity } = identity;
  if (url.endsWith("/v1/status")) return response({ ok: true, ...statusIdentity, height: 42 });
  if (url.endsWith("/v1/chain/identity")) {
    return response({ ok: true, ...statusIdentity, chain_manifest: { genesis_hash } });
  }
  if (url.endsWith("/v1/readyz")) return response({ ok: host !== "notready.test" });
  return response({ ok: true, ...statusIdentity });
}

const fakeWindow = { setTimeout, clearTimeout, dispatchEvent: () => true };
const MockEvent = class {
  constructor(name, opts) { this.type = name; this.detail = opts?.detail; }
};
function loadTypeScriptModule(relative, dependencyMap) {
  const source = readFileSync(resolve(root, relative), "utf8");
  const js = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
    reportDiagnostics: true,
  });
  assert.deepEqual(js.diagnostics, [], "TypeScript transpilation must succeed");
  const exports = {};
  const require = (name) => {
    assert.ok(Object.hasOwn(dependencyMap, name), "unmocked import: " + name);
    return dependencyMap[name];
  };
  const run = new Function(
    "require", "exports", "window", "fetch", "performance", "AbortController", "CustomEvent",
    js.outputText,
  );
  run(require, exports, fakeWindow, fakeFetch, performance, AbortController, MockEvent);
  return exports;
}
const browserSession = loadTypeScriptModule("src/lib/browserNodeSession.ts", {});
const manager = loadTypeScriptModule("src/lib/nodeConnectionManager.ts", {
  "./config": { config },
  "../api/weall": api,
});
const connector = loadTypeScriptModule("src/lib/connectPublicTestnetBrowser.ts", {
  "../auth/session": { getSession: () => localSession },
  "./browserNodeSession": browserSession,
  "./config": { config },
  "./nodeConnectionManager": manager,
});
function reset() {
  selected = "/";
  changes = 0;
  localSession = null;
  sessionCalls.length = 0;
  live.clear();
  for (const host of ["healthy.test", "backup.test", "wrong.test", "notready.test", "unlisted.test"]) live.add(host);
  recognized.clear();
  recognized.add("healthy.test");
  browserSession.clearApprovedBrowserSession();
}

test("bootstrap reads base_url and rejects non-HTTPS, wrong-chain and unready candidates", async () => {
  reset();
  const backendHints = await manager.loadBackendSeedNodes("https://seed.test");
  assert.deepEqual(backendHints.map((item) => item.url), ["https://unlisted.test"],
    "actual backend base_url schema must be parsed");
  // Backend gossip is only available once the current API is a real node.
  selected = "https://healthy.test";
  const probes = await manager.discoverNodeProbes();
  assert.equal(probes.find((x) => x.baseUrl === "https://healthy.test")?.phase, "healthy");
  assert.equal(probes.find((x) => x.baseUrl === "https://healthy.test")?.genesisHash, chain.genesis_hash);
  assert.equal(probes.find((x) => x.baseUrl === "https://wrong.test")?.phase, "incompatible");
  assert.equal(probes.find((x) => x.baseUrl === "https://notready.test")?.phase, "syncing");
  assert.ok(!probes.some((x) => x.baseUrl.startsWith("http://")));
  const discoveredOnly = probes.find((x) => x.baseUrl === "https://unlisted.test");
  assert.equal(discoveredOnly?.listedInSeedManifest, false);
  assert.equal(manager.canSwitchToNode(discoveredOnly), false,
    "backend-suggested candidate is a hint, not session credential trust");

  selected = "/";
  const first = await connector.connectPublicTestnetBrowser();
  assert.deepEqual(first, { state: "connected", baseUrl: "https://healthy.test", changed: true });
  assert.equal(selected, "https://healthy.test");
  assert.equal(changes, 1);
  const again = await connector.connectPublicTestnetBrowser();
  assert.deepEqual(again, { state: "connected", baseUrl: "https://healthy.test", changed: false });
  assert.equal(changes, 1);
  live.clear();
  const down = await connector.connectPublicTestnetBrowser();
  assert.deepEqual(down, { state: "unavailable", reason: "no_compatible_node" });
  assert.equal(changes, 1, "offline nodes never change the saved access base");
  assert.equal(selected, "https://healthy.test");
});

test("session bearer only goes to compatible, published HTTPS candidates", async () => {
  reset();
  localSession = { version: 1, account: "@alice", sessionKey: "fake-bearer", expiresAtMs: Date.now() + 60_000 };
  const connected = await connector.connectPublicTestnetBrowser();
  assert.deepEqual(connected, { state: "connected", baseUrl: "https://healthy.test", changed: true });
  assert.equal(browserSession.isBrowserSessionApproved(selected, "@alice", "fake-bearer"), true);
  assert.ok(sessionCalls.length > 0);
  assert.ok(sessionCalls.every((call) => call.host !== "unlisted.test" && call.host !== "wrong.test"));
  assert.ok(sessionCalls.every((call) => call.init.credentials === "omit" && call.init.redirect === "error"));
  assert.ok(sessionCalls.every((call) => call.headers.get("X-WeAll-Session-Key") === "fake-bearer"));
  assert.equal(
    browserSession.isBrowserSessionApproved(selected, "@bob", "fake-bearer"), false,
    "approval is bound to an account and session key",
  );
});

test("session-aware failover selects a published node only after remote recognition", async () => {
  reset();
  selected = "https://healthy.test";
  localSession = { account: "@alice", sessionKey: "fake-bearer", expiresAtMs: Date.now() + 60_000 };
  recognized.clear();
  recognized.add("backup.test");
  const migrated = await connector.connectPublicTestnetBrowser();
  assert.deepEqual(migrated, { state: "connected", baseUrl: "https://backup.test", changed: true });
  assert.equal(selected, "https://backup.test");
  assert.equal(browserSession.isBrowserSessionApproved(selected, "@alice", "fake-bearer"), true);
  assert.ok(!sessionCalls.some((call) => call.host === "unlisted.test"));
});

test("active session remains locked if no compatible node recognizes it", async () => {
  reset();
  selected = "https://healthy.test";
  localSession = { account: "@alice", sessionKey: "fake-bearer", expiresAtMs: Date.now() + 60_000 };
  recognized.clear();
  const result = await connector.connectPublicTestnetBrowser();
  assert.deepEqual(result, { state: "unavailable", reason: "session_not_recognized" });
  assert.equal(selected, "https://healthy.test", "do not silently switch account context");
  assert.equal(changes, 0);
  assert.equal(browserSession.isBrowserSessionApproved(selected, "@alice", "fake-bearer"), false);
  assert.ok(!sessionCalls.some((call) => call.host === "unlisted.test"));
});

test("independent browser bearer cannot borrow another browser session's approval", async () => {
  reset();
  const first = await browserSession.verifyBrowserSessionOnNode(
    "https://healthy.test", "@alice", "tab-1-key", { attempts: 1 },
  );
  assert.equal(first, "verified");
  assert.equal(browserSession.isBrowserSessionApproved("https://healthy.test", "@alice", "tab-1-key"), true);
  assert.equal(browserSession.isBrowserSessionApproved("https://healthy.test", "@alice", "tab-2-key"), false);
  assert.equal(browserSession.isBrowserSessionApproved("https://backup.test", "@alice", "tab-1-key"), false);
  assert.equal(await browserSession.verifyBrowserSessionOnNode(
    "http://127.0.0.1:8000", "@alice", "tab-1-key",
  ), "unavailable");
  assert.ok(!sessionCalls.some((call) => call.host === "unlisted.test"));
});
