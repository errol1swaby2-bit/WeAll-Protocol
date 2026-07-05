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

const dashboard = read("src/pages/NodeDashboard.tsx");
const connectionPanel = read("src/components/NodeConnectionPanel.tsx");
const commandWizard = read("src/components/OperatorCommandWizard.tsx");
const incidentTimeline = read("src/components/OperatorIncidentTimeline.tsx");
const first15 = read("../Weall-Protocol/docs/testnet/FIRST_15_MINUTES.md");
const readinessDoc = read("../Weall-Protocol/docs/testnet/NODE_OPERATOR_JOURNEY_AND_INCIDENT_RESPONSE.md");
const incidentDoc = read("../Weall-Protocol/docs/operators/INCIDENT_RESPONSE.md");
const packageJson = read("package.json");

for (const needle of [
  "Mode matrix and incident response",
  "observer, node operator, validator-candidate, and validator authority",
  "Safe next action",
  "Diagnostics first: capture status, readyz, chain head, mempool, peer/seed, and operator output before changing settings.",
  "External evidence gate",
  "Incident boundary:",
  "chain mismatch, stale validator endpoints, mempool backlog, missing readyz, storage/helper/economics/protocol-upgrade blockers",
  "Backend readiness endpoint",
  "safeReadyzCurl",
  "Incident response packet:",
  "/v1/status",
  "/readyz",
  "/v1/chain/head",
  "/v1/status/mempool",
  "/v1/nodes/seeds",
  "/v1/nodes/validators",
  "/v1/status/operator",
]) {
  assertIncludes(dashboard, needle, "node dashboard pass 19 source");
}

for (const needle of [
  "Chain mismatch warnings block switching",
  "a browser target change is not a validator or operator role change",
  "Switching rule:",
  "only healthy compatible nodes may be selected",
  "Incompatible chain id, genesis hash, tx index hash, or protocol profile hash should be treated as a chain mismatch incident",
]) {
  assertIncludes(connectionPanel, needle, "node connection panel pass 19 source");
}

for (const needle of [
  "Operator incident evidence bundle",
  "diagnostic-only / evidence capture",
  "Public observer launch transcript helper",
  "external transcript / read-only",
  "A local transcript does not close independent external evidence gates.",
  "external transcript or evidence capture also stay non-authoritative",
  "save the output in the incident response packet",
]) {
  assertIncludes(commandWizard, needle, "operator command wizard pass 19 source");
}

for (const needle of [
  "Treat warnings as evidence to capture first",
  "not as permission to flip local flags",
  "Escalate only after capturing mode, chain id, finalized height, peer/seed status, mempool backlog, validator authority, and blocker state.",
]) {
  assertIncludes(incidentTimeline, needle, "operator incident timeline pass 19 source");
}

for (const needle of [
  "NODE_OPERATOR_JOURNEY_AND_INCIDENT_RESPONSE.md",
  "Personal Node screenshot, including mode matrix, safe next action, seed/peer status, validator endpoint freshness, mempool/backlog status, and incident timeline",
  "local commands, node switching, or environment flags grant validator/operator authority",
  "chain mismatch, stale validator endpoint, missing readyz, or mempool backlog warnings",
  "### Node/operator journey and incident response",
]) {
  assertIncludes(first15, needle, "first 15 minutes pass 19 doc");
}

for (const needle of [
  "# Node/operator journey and incident response readiness",
  "Mode and authority matrix",
  "Expected dashboard evidence",
  "Safe command rule",
  "Chain mismatch response",
  "Mempool/backlog response",
  "Validator and BFT boundary",
  "Storage, helper, economics, and upgrade boundary",
  "Incident packet",
  "Allowed statement after this pass",
]) {
  assertIncludes(readinessDoc, needle, "node/operator readiness doc");
}

for (const needle of [
  "# Operator incident response runbook",
  "Incident classes",
  "Evidence commands",
  "Stop rules",
  "Recovery order",
  "External evidence still required",
  "local script grants validator authority",
  "mempool acceptance means final confirmation",
]) {
  assertIncludes(incidentDoc, needle, "operator incident response doc");
}

for (const forbidden of [
  "public beta ready",
  "mainnet ready",
  "automatic upgrades enabled",
  "production helper execution enabled",
  "local script grants validator authority",
  "node switching grants validator authority",
]) {
  assertNotIncludes(dashboard + connectionPanel + commandWizard + incidentTimeline, forbidden, "pass 19 overclaim guard");
}

assertIncludes(packageJson, "test:node-operator-journey-incident-response-source", "package script registration");

console.log("node/operator journey incident-response source checks passed");
