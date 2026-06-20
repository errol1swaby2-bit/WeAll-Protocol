#!/usr/bin/env node
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const src = readFileSync(resolve(here, "../src/lib/nodeConnectionManager.ts"), "utf8");

const required = [
  "export type NodeCompatibilityBaseline",
  "buildCompatibilityBaseline",
  "compatibilityErrors",
  "applyCompatibilityBaseline",
  "incompatible:chain_id_mismatch",
  "incompatible:tx_index_hash_mismatch",
  "incompatible:protocol_profile_hash_mismatch",
  "expectedChainId",
  "publicTestnetBaselineErrors",
  "public_testnet_config_missing:pinned_commitments_required",
  "public_testnet_config_missing:genesis_hash",
  "incompatible:genesis_hash_mismatch",
  "expectedGenesisHash",
  "genesisHash",
  "config.publicTestnet",
  "expectedTxIndexHash",
  "expectedProtocolProfileHash",
  "compatibilitySourceBaseUrl",
  "buildConfiguredCompatibilityBaseline",
  "loadExpectedCompatibilityBaseline",
  "loadBackendSeedCompatibilityBaseline",
  "loadBackendSeedNodes",
  "/v1/nodes/seeds",
  "baselineFromPayload",
  "source: \"build\"",
  "source: \"seed-manifest\"",
  "source: \"current-node\"",
  "const explicitBaseline = await loadExpectedCompatibilityBaseline();",
  "const probes = applyCompatibilityBaseline(rawProbes, explicitBaseline === null && !config.publicTestnet ? undefined : explicitBaseline);",
];

for (const token of required) {
  assert.ok(src.includes(token), `missing node manager classification token: ${token}`);
}

const expectedOrdering = [
  "const currentBase = displayBase(getApiBaseUrl());",
  "const explicitBaseline = await loadExpectedCompatibilityBaseline();",
  "const rawProbes = await Promise.all",
  "const probes = applyCompatibilityBaseline(rawProbes, explicitBaseline === null && !config.publicTestnet ? undefined : explicitBaseline);",
  "return probes.sort",
];

let previous = -1;
for (const token of expectedOrdering) {
  const next = src.indexOf(token);
  assert.ok(next > previous, `expected ${token} after prior token`);
  previous = next;
}

console.log("node connection manager source classification checks passed");
