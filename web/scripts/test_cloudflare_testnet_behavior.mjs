#!/usr/bin/env node
// Executable browser-node selection regression using the actual TS modules.
// Only the browser environment and node network responses are mocked.
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

const available = { healthy: true };
let selected = "/";
let changes = 0;
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
    selected = validateApiBaseInput(next).normalized;
    changes += 1;
    return selected;
  },
  validateApiBaseInput,
};
const response = (payload, status = 200) => new Response(JSON.stringify(payload), {
  status,
  headers: { "content-type": "application/json" },
});

async function fakeFetch(input) {
  const url = String(input);
  if (url === "/seeds.json") {
    return response({
      ...chain,
      nodes: [
        { label: "Healthy seed", api_base: "https://healthy.test" },
        { label: "Wrong network", api_base: "https://wrong.test" },
        { label: "Not ready", api_base: "https://notready.test" },
      ],
    });
  }
  if (url === "https://seed.test/v1/nodes/seeds") {
    return response({ nodes: [{ base_url: "https://healthy.test" }] });
  }
  if (url === "/v1/nodes/seeds") return response({}, 404);
  if (url.startsWith("https://") && url.endsWith("/v1/nodes/seeds")) {
    return response({ nodes: [] });
  }

  const host = url.startsWith("/") ? "unavailable" : new URL(url).hostname;
  if (host === "unavailable") return response({}, 404);
  if (host === "healthy.test" && !available.healthy) return response({}, 503);
  if (host === "wrong.test" || host === "notready.test" || host === "healthy.test") {
    const identity = host === "wrong.test" ? { ...chain, chain_id: "other-network" } : chain;
    // Match the real backend: /v1/status has chain/tx/profile, while
    // /v1/chain/identity carries the genesis hash in chain_manifest.
    const { genesis_hash, ...statusIdentity } = identity;
    if (url.endsWith("/v1/status")) {
      return response({ ok: true, ...statusIdentity, height: 42 });
    }
    if (url.endsWith("/v1/chain/identity")) {
      return response({ ok: true, ...statusIdentity, chain_manifest: { genesis_hash } });
    }
    if (url.endsWith("/v1/readyz")) {
      return response({ ok: host !== "notready.test" });
    }
    return response({ ok: true, ...statusIdentity });
  }
  return response({}, 404);
}

const fakeWindow = {
  setTimeout,
  clearTimeout,
  dispatchEvent: () => true,
};
const MockEvent = class {
  constructor(name, opts) {
    this.type = name;
    this.detail = opts?.detail;
  }
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
const manager = loadTypeScriptModule("src/lib/nodeConnectionManager.ts", {
  "./config": { config },
  "../api/weall": api,
});
const connector = loadTypeScriptModule("src/lib/connectPublicTestnetBrowser.ts", {
  "./config": { config },
  "./nodeConnectionManager": manager,
});

test("hosted public testnet discovery only selects healthy, compatible nodes", async () => {
  const backendHints = await manager.loadBackendSeedNodes("https://seed.test");
  assert.deepEqual(backendHints.map((item) => item.url), ["https://healthy.test"],
    "actual backend base_url schema must be parsed");

  const unready = await manager.probeNode({ url: "https://notready.test" });
  assert.equal(unready.phase, "syncing", "status ok must not override failed readyz");
  assert.equal(unready.ready, false);

  const probes = await manager.discoverNodeProbes();
  assert.equal(probes.find((x) => x.baseUrl === "https://healthy.test")?.phase, "healthy");
  assert.equal(probes.find((x) => x.baseUrl === "https://healthy.test")?.genesisHash, chain.genesis_hash,
    "the compatible genesis hash must be read from /v1/chain/identity");
  assert.equal(probes.find((x) => x.baseUrl === "https://wrong.test")?.phase, "incompatible");
  assert.equal(probes.find((x) => x.baseUrl === "https://notready.test")?.phase, "syncing");

  const first = await connector.connectPublicTestnetBrowser();
  assert.deepEqual(first, { state: "connected", baseUrl: "https://healthy.test", changed: true });
  assert.equal(selected, "https://healthy.test");
  assert.equal(changes, 1);

  const again = await connector.connectPublicTestnetBrowser();
  assert.deepEqual(again, { state: "connected", baseUrl: "https://healthy.test", changed: false });
  assert.equal(changes, 1, "healthy current selection must be preserved");

  available.healthy = false;
  const down = await connector.connectPublicTestnetBrowser();
  assert.deepEqual(down, { state: "unavailable" });
  assert.equal(changes, 1, "never fall back to incompatible, syncing, or unreachable nodes");
  assert.equal(selected, "https://healthy.test", "do not silently alter persisted account/API state");
});
