import { readFileSync } from "node:fs";

function read(path) {
  return readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
}

function assertIncludes(src, needle, label) {
  if (!src.includes(needle)) {
    throw new Error(`${label}: missing ${needle}`);
  }
}

const app = read("src/App.tsx");
const router = read("src/lib/router.ts");
const prefetch = read("src/lib/routePrefetch.ts");
const api = read("src/api/weall.ts");
const node = read("src/pages/NodeDashboard.tsx");
const contract = read("scripts/contract_check.mjs");

assertIncludes(app, "./pages/NodeDashboard", "App lazy-loads node dashboard");
assertIncludes(app, `case "/node":`, "App renders /node route");
assertIncludes(router, `{ path: "/node" }`, "router match type includes /node");
assertIncludes(router, `href: "/node"`, "normal navigation exposes /node");
if (router.includes("/operator")) {
  throw new Error("legacy /operator alias must not remain in router");
}
assertIncludes(prefetch, "../pages/NodeDashboard", "route prefetch includes node dashboard");

for (const method of [
  "operatorStatus",
  "consensusStatus",
  "mempoolStatus",
  "storageIpfsOps",
  "chainHead",
  "chainIdentity",
  "testnetCapabilities",
  "blockProductionReadiness",
  "helperReadiness",
  "netSelf",
]) {
  assertIncludes(api, `${method}(base?: string`, `API exposes ${method}`);
}

for (const needle of [
  "STORAGE_PREF_KEY",
  "storagePreferenceError",
  "Offer storage from this node",
  "Pause storage contribution",
  "Resume storage contribution",
  "capacity proof",
  "browser cannot grant storage authority",
]) {
  assertIncludes(node, needle, "node dashboard storage controls");
}

for (const endpoint of [
  "/v1/status/operator",
  "/v1/status/mempool",
  "/v1/storage/ipfs/ops",
  "/v1/chain/head",
  "/v1/status/helper/readiness",
]) {
  assertIncludes(contract, endpoint, "contract check covers node dashboard endpoint");
}

console.log("node dashboard source checks passed");
