import { readFileSync } from "node:fs";

function read(path) {
  return readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
}

function assertIncludes(src, needle, label) {
  if (!src.includes(needle)) {
    throw new Error(`${label}: missing ${needle}`);
  }
}

function assertNotIncludes(src, needle, label) {
  if (src.includes(needle)) {
    throw new Error(`${label}: forbidden ${needle}`);
  }
}

const node = read("src/pages/NodeDashboard.tsx");
const operatorWizard = read("src/components/OperatorCommandWizard.tsx");
const incidentTimeline = read("src/components/OperatorIncidentTimeline.tsx");
const txPage = read("src/pages/TransactionsPage.tsx");
const txTimeline = read("src/components/TxPropagationTimeline.tsx");

for (const needle of [
  "OperatorCommandWizard",
  "OperatorIncidentTimeline",
  "operatorModeLabel",
  "incidentItems",
  "safeStatusCurl",
  "safeMempoolCurl",
  "safeOperatorCurl",
]) {
  assertIncludes(node, needle, "node dashboard wires Step 9 UX surfaces");
}

for (const needle of [
  "Operator wizard",
  "Safe guided commands",
  "current node mode",
  "observer, node operator, validator-candidate, and validator authority",
  "script execution or copied commands never grant authority by themselves",
  "diagnostic-only / read-only",
  "local-only / diagnostic-only",
  "observer-only / diagnostic-only",
  "requires protocol state before use",
  "requires protocol state / fail-closed",
  "Copy command",
  "Commands marked local-only, observer-only, diagnostic-only, or requires protocol state",
]) {
  assertIncludes(operatorWizard, needle, "operator wizard source gate");
}

for (const needle of [
  "Operator incident timeline",
  "Unified diagnostics",
  "node mode, chain identity, peer and seed status, mempool backlog, block/finalized height, BFT/validator authority, storage/helper/economics/protocol-upgrade blockers",
  "Read-only diagnostics",
  "build_operator_incident_report.py",
  "run_operator_incident_lane.py",
]) {
  assertIncludes(incidentTimeline, needle, "operator incident timeline source gate");
}

for (const needle of [
  "Submitted",
  "Locally accepted",
  "Queued / pending",
  "Forwarded / gossiped",
  "Included in block",
  "Finalized / confirmed",
  "Rejected",
  "Removed from mempool",
  "not confirmed yet",
  "unknown/unavailable",
  "do not infer from local acceptance",
]) {
  assertIncludes(txPage, needle, "transaction lifecycle source gate");
}

for (const needle of [
  "Propagation lifecycle separates local submission, local acceptance, queued/pending, forwarded/gossiped, included in block, finalized/confirmed, rejected, and removed from mempool",
  "Pending evidence",
]) {
  assertIncludes(txTimeline, needle, "tx propagation timeline explanatory boundary");
}

const checked = [node, operatorWizard, incidentTimeline, txPage, txTimeline].join("\n");
for (const forbidden of [
  "Public beta ready",
  "Mainnet ready",
  "public multi-validator BFT ready",
  "live economics ready",
  "automatic protocol upgrades enabled",
  "script execution grants authority",
  "copied commands grant authority",
  "mempool acceptance is confirmed",
  "local acceptance is confirmation",
]) {
  assertNotIncludes(checked, forbidden, "Step 9 surfaces must not overclaim readiness or confirmation");
}

console.log("OK: Step 9 P2 UX source checks passed");
