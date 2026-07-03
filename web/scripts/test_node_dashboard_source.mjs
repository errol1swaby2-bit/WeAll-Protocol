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
const capabilitySurface = read("../Weall-Protocol/src/weall/runtime/testnet_capabilities.py");
const txPage = read("src/pages/TransactionsPage.tsx");
const txTimeline = read("src/components/TxPropagationTimeline.tsx");
const connectionPanel = read("src/components/NodeConnectionPanel.tsx");
const contract = read("scripts/contract_check.mjs");

assertIncludes(app, "./pages/NodeDashboard", "App lazy-loads node dashboard");
assertIncludes(app, `case "/node":`, "App renders /node route");
assertIncludes(router, `{ path: "/node" }`, "router match type includes /node");
assertIncludes(router, `href: "/node"`, "normal navigation exposes /node");
assertIncludes(router, `"/node": {`, "route registry includes node route");
assertIncludes(router, `public: true,
    authRequired: false,
    requiresReady: false,`, "node dashboard is available before account setup");
assertIncludes(router, `href: "/node", label: "Personal Node", description: "Local node health, readiness, and storage controls.", icon: "⬡", public: true`, "normal navigation exposes public node route");
for (const legacyOperatorAlias of ['href: "/operator"', 'path: "/operator"', `case "/operator":`]) {
  if (router.includes(legacyOperatorAlias)) {
    throw new Error(`legacy /operator alias must not remain in router: ${legacyOperatorAlias}`);
  }
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
  "publicSeeds",
  "publicValidators",
  "observerEdgeStatus",
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
  "Seed, validator, and tx propagation visibility",
  "local tx acceptance is shown separately from upstream validator acceptance",
  "Active validators",
  "Verified validator endpoints",
  "Observer tx propagation",
  "Reachable validators",
  "Fresh validator endpoints",
  "Peer / NAT recovery",
  "Read-only observer view",
  "Set up account operator path",
  "Set up account before operator actions",
  "Validator promotion path",
  "Governance lifecycle clock",
  "Dispute lifecycle clock",
  "Reviewer civic loop",
  "Reviewer route map",
  "Minimum civic loop entrypoints",
  "Reviewer API evidence map",
  "Canonical API surfaces for the civic loop",
  "Full API route coverage is checked against the generated v1.5 API contract map",
  "Decisions / governance",
  "Reports / disputes",
  "Legacy /proposals and /disputes aliases remain removed",
  "governance-parent bound",
  "no wall-clock protocol mutation",
  "private identity evidence protected",
]) {
  assertIncludes(node, needle, "node dashboard storage controls");
}

for (const needle of [
  '"governance": "/decisions"',
  '"governance_create": "/decisions/create"',
  '"disputes": "/reports"',
  '"api_evidence_surfaces"',
  '"GET /v1/status/testnet-capabilities"',
  '"GET /v1/economics/status"',
  '"canonical_route_boundary"',
  '"legacy_aliases_removed": ["/proposals", "/disputes"]',
]) {
  assertIncludes(capabilitySurface, needle, "testnet capability surface canonical reviewer route map");
}

for (const duplicateKey of [
  'primaryObject: "Report",\n      primaryObject: "Report"',
  'blockingDependencies: ["Account session", "Live verification case", "Self-hosted room transport", "Signed attendance/verdict state"],\n      blockingDependencies:',
]) {
  if (router.includes(duplicateKey)) {
    throw new Error(`router contract contains duplicate object key: ${duplicateKey}`);
  }
}

for (const needle of [
  "Browser API access node",
  "local mesh node",
  "validator connectivity",
  "signing authority remain controlled",
]) {
  assertIncludes(connectionPanel, needle, "connection manager public observer copy");
}

for (const needle of [
  "TxPropagationTimeline",
  "Accepted locally",
  "Forwarded to verified upstream",
  "Upstream validator accepted",
  "Gossiped / pending",
  "Included in block",
  "Local observer synced confirmed block",
  "Removed from mempool",
]) {
  assertIncludes(txPage, needle, "transactions page propagation timeline");
}

for (const needle of [
  "Propagation lifecycle",
  "Pending evidence",
  "Observed",
]) {
  assertIncludes(txTimeline, needle, "tx propagation timeline component");
}

for (const endpoint of [
  "/v1/status/operator",
  "/v1/status/mempool",
  "/v1/storage/ipfs/ops",
  "/v1/chain/head",
  "/v1/status/helper/readiness",
  "/v1/nodes/seeds",
  "/v1/nodes/validators",
  "/v1/observer/edge/status",
]) {
  assertIncludes(contract, endpoint, "contract check covers node dashboard endpoint");
}

console.log("node dashboard source checks passed");
