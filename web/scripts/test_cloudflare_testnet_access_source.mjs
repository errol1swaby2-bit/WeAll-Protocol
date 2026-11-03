#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const webRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const readWeb = (relative) => readFileSync(resolve(webRoot, relative), "utf8");

const manager = readWeb("src/lib/nodeConnectionManager.ts");
const startup = readWeb("src/main.tsx");
const connector = readWeb("src/lib/connectPublicTestnetBrowser.ts");
const buildScript = resolve(webRoot, "scripts/buildCloudflareTestnet.mjs");
const build = readWeb("scripts/buildCloudflareTestnet.mjs");
const headers = readWeb("public/_headers");

// Regression: public backend seed registry advertises base_url, not only
// the legacy static manifest's api_base.
assert.ok(manager.includes("rec.base_url"), "backend base_url seed field must be supported");
assert.ok(manager.includes("loadBackendSeedNodes(current)"), "backend discovery must remain supported");
assert.ok(manager.includes("loadSeedNodes()"), "static bootstrap manifest must remain supported");

// Browser startup may select an access node, never grant protocol authority.
assert.ok(startup.includes("if (config.publicTestnet)"), "autoselection must be public-testnet-only");
assert.ok(startup.includes("connectPublicTestnetBrowser()"), "first-visit browser discovery missing");
assert.ok(startup.indexOf("connectPublicTestnetBrowser()") < startup.indexOf("root.render(app);"), "discovery must precede app initialization");
assert.ok(connector.includes("if (!config.publicTestnet) return"), "non-public builds must not auto-connect");
assert.ok(connector.includes("canSwitchToNode(probe)"), "only classified healthy nodes can be selected");
assert.ok(connector.includes('current?.phase === "healthy"'), "keep healthy selected node");
assert.ok(connector.includes('state: "unavailable"'), "missing compatible nodes must fail closed");

// No Cloudflare gateway. Testnet launch fails when registry is unsigned/stale.
assert.ok(build.includes("seed_registry_rotation_required"), "rotation gate missing");
assert.ok(build.includes("pq_resign_required_before_public_testnet"), "re-sign gate missing");
assert.ok(build.includes("seed_registry_signature"), "signature presence gate missing");
assert.ok(build.includes("trustRoots.seed_registry_pubkeys.includes(registry.seed_registry_signer)"), "signer pin gate missing");
assert.ok(build.includes('VITE_WEALL_API_BASE: "/"'), "host must not assume same-origin API proxy");
assert.ok(build.includes('resolve(webRoot, "dist/seeds.json")'), "dist seed manifest replacement required");
assert.ok(headers.includes("connect-src 'self' https: wss:"), "remote HTTPS node access must be allowed");
assert.ok(!/camera=\\(\\)|microphone=\\(\\)/.test(headers), "live PoH devices must not be disabled");
execFileSync(process.execPath, ["--check", buildScript], { stdio: "pipe" });
console.log("Cloudflare testnet frontend integration source checks passed");
