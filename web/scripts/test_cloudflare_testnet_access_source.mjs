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

// Account and bearer custody are local, but hosted API access also requires
// the destination node to recognize the active canonical session.
const app = readWeb("src/App.tsx");
const session = readWeb("src/auth/session.ts");
const recognition = readWeb("src/lib/browserNodeSession.ts");
const originPolicy = readWeb("src/lib/publicApiOrigin.ts");
assert.ok(manager.includes('from "./publicApiOrigin"'), "node discovery must use the shared HTTPS origin validator");
assert.ok(recognition.includes('from "./publicApiOrigin"'), "session consent must use the shared HTTPS origin validator");
assert.ok(originPolicy.includes("export function isPublicApiOrigin("), "shared HTTPS origin validator missing");
assert.ok(!recognition.includes("function isSecureApiOrigin("), "duplicated session origin validator must stay removed");
const panel = readWeb("src/components/NodeConnectionPanel.tsx");
const settings = readWeb("src/pages/Settings.tsx");
assert.ok(session.includes("SS_SESSION_BEARER"), "bearer must remain in tab-scoped storage");
assert.ok(session.includes("sessionStorage.setItem("), "session key custody cannot regress to persistent localStorage");
assert.ok(session.includes("isBrowserSessionApproved(getApiBaseUrl()"), "protected auth headers must require per-node session recognition");
assert.ok(session.includes('state: "node_unverified"'), "missing node recognition must remain visible");
assert.ok(app.includes('sessionHealth.state !== "node_unverified"'), "protected app routes must remain unavailable until node recognizes session");
assert.ok(recognition.includes('"/v1/session/me"'), "read-only canonical session challenge must be present");
assert.ok(recognition.includes('credentials: "omit"'), "cross-origin node session probing must avoid unrelated cookies");
assert.ok(recognition.includes('redirect: "error"'), "session bearer must not follow node redirects");
assert.ok(recognition.includes("rememberManualNodeConsent("), "explicit tab-scoped node consent must be available");
assert.ok(recognition.includes("sessionStorage.setItem(MANUAL_NODE_CONSENT_KEY"), "unlisted node consent must be tab-scoped");
assert.ok(connector.includes("hasManualNodeConsent(current.baseUrl)"), "explicit current manual node choice should survive same-tab reload");
assert.ok(panel.includes("window.confirm(") && panel.includes("rememberManualNodeConsent("), "unlisted user-selected nodes require informed opt-in");
assert.ok(settings.includes("window.confirm(") && settings.includes("applyCompatibilityBaseline([raw], baseline)"), "raw manual URL must be checked against pinned commitments before opt-in");
assert.ok(connector.includes("verifyBrowserSessionOnNode("), "automatic failover must be session-aware");
assert.ok(connector.includes("current.listedInSeedManifest"), "current node cannot bypass manifest restriction");
assert.ok(manager.includes("probe.listedInSeedManifest === true"), "public switching must require published endpoints");
assert.ok(panel.includes("verifyBrowserSessionOnNode("), "manual connection changes must check session recognition");
assert.ok(settings.includes("discoverNodeProbes(") && settings.includes("verifyBrowserSessionOnNode("),
  "Settings raw URL selection must not bypass HTTPS/session validation");
assert.ok(readWeb("scripts/check_https_node_api.mjs").includes("cors_frontend_origin_mismatch"),
  "HTTPS/CORS operator preflight must exist");

// No Cloudflare gateway. Testnet launch fails when registry is unsigned/stale.
assert.ok(build.includes("seed_registry_rotation_required"), "rotation gate missing");
assert.ok(build.includes("pq_resign_required_before_public_testnet"), "re-sign gate missing");
assert.ok(build.includes("seed_registry_signature"), "signature presence gate missing");
assert.ok(build.includes("trustRoots.seed_registry_pubkeys.includes(registry.seed_registry_signer)"), "signer pin gate missing");
assert.ok(build.includes('VITE_WEALL_API_BASE: "/"'), "host must not assume same-origin API proxy");
assert.ok(build.includes('resolve(webRoot, "dist/seeds.json")'), "dist seed manifest replacement required");
assert.ok(headers.includes("connect-src 'self' https: wss:"), "remote HTTPS node access must be allowed");
assert.ok(!headers.includes("camera=()") && !headers.includes("microphone=()"), "live PoH devices must not be disabled");
execFileSync(process.execPath, ["--check", buildScript], { stdio: "pipe" });
console.log("Cloudflare testnet frontend integration source checks passed");
