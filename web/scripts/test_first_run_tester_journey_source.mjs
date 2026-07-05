import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

const webRoot = resolve(process.cwd());
const repoRoot = resolve(process.cwd(), "..");

function readWeb(rel) {
  return readFileSync(resolve(webRoot, rel), "utf8");
}

function readRepo(rel) {
  return readFileSync(resolve(repoRoot, rel), "utf8");
}

function assertIncludes(src, needle, label) {
  if (!src.includes(needle)) {
    throw new Error(`${label}: missing ${needle}`);
  }
}

function assertNotIncludes(src, needle, label) {
  if (src.includes(needle)) {
    throw new Error(`${label}: forbidden overclaim ${needle}`);
  }
}

const home = readWeb("src/pages/Home.tsx");
const protocolSummary = readWeb("src/components/ProtocolStatusSummary.tsx");
const statusLib = readWeb("src/lib/status.ts");
const packageJson = readWeb("package.json");
const statusRoute = readRepo("Weall-Protocol/src/weall/api/routes_public_parts/status.py");
const first15Path = resolve(repoRoot, "Weall-Protocol/docs/testnet/FIRST_15_MINUTES.md");
if (!existsSync(first15Path)) {
  throw new Error("docs/testnet/FIRST_15_MINUTES.md must exist");
}
const first15 = readFileSync(first15Path, "utf8");

for (const needle of [
  "First 15 minutes",
  "Guided tester journey",
  "Confirm node and chain",
  "chain_id, block height, finalized height, and authority level",
  "Create or restore account",
  "Verify participation level",
  "Read the public civic loop",
  "Submit carefully, then track status",
  "Submitted, locally accepted, pending, included, finalized, and rejected are different states.",
]) {
  assertIncludes(home, needle, "Home first-run guided journey");
}

for (const needle of [
  "Role boundaries",
  "Observer",
  "User",
  "Node operator",
  "Validator candidate",
  "Validator",
  "Browser state, frontend buttons, local scripts, seed hints, and node switching never create validator, economics, helper, storage, or upgrade authority by themselves.",
  "public multi-validator BFT remains unclaimed",
]) {
  assertIncludes(home, needle, "Home role authority boundaries");
}

for (const needle of [
  "Current node",
  "Chain truth",
  "Authority level",
  "chain_id",
  "finalized height",
  "Frontend state and node switching never grant validator, economics, helper, storage, or upgrade authority.",
]) {
  assertIncludes(protocolSummary, needle, "Protocol status first-run summary");
}

for (const needle of [
  "finalizedHeight",
  "raw?.finalized_height",
  "validator candidate / fail-closed",
  "observer / read-sync-forward",
  "unknown; treat as read-only until proven by protocol state",
]) {
  assertIncludes(statusLib, needle, "frontend node summary must expose bounded authority and finalized height");
}

assertIncludes(statusRoute, '"finalized_height"', "normal /v1/status payload should expose finalized height for first-run testers");
assertIncludes(packageJson, "test:first-run-tester-journey-source", "package script must expose first-run source check");

for (const needle of [
  "# First 15 minutes on the bounded public observer / controlled testnet",
  "current node / API target",
  "Frontend buttons, browser state, seed hints, local scripts, node switching, and environment flags must never be treated as protocol authority.",
  "WEALL_PUBLIC_TESTNET=1 bash scripts/boot_public_observer_testnet.sh",
  "Home → Account → Verification → Feed → Groups → Decisions → Reports → Review Center → Activity → Transactions → Personal Node",
  "A transaction is only final when the backend reports inclusion/finalization or a specific rejected terminal state.",
  "Ready for controlled internal/public-observer rehearsal candidate, with public beta readiness still blocked by explicit external evidence gates.",
]) {
  assertIncludes(first15, needle, "first 15 minutes doc");
}

const checked = [home, protocolSummary, statusLib, first15].join("\n");
for (const forbidden of [
  "Public beta ready",
  "Mainnet ready",
  "public multi-validator BFT ready",
  "live economics ready",
  "automatic protocol upgrades enabled",
  "production helper execution ready",
  "legal approval granted",
  "mempool acceptance is confirmed",
  "local acceptance is confirmation",
]) {
  assertNotIncludes(checked, forbidden, "first-run journey surfaces must not overclaim readiness or confirmation");
}

console.log("OK: first-run tester journey source checks passed");
