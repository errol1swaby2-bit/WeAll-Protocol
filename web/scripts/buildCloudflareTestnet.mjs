#!/usr/bin/env node
// Static Cloudflare Pages build. This never operates a WeAll API gateway.
// The existing operator workflow must cryptographically verify the signed
// registry before publication; this script checks release structure/pins.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const webRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const configRoot = resolve(webRoot, "../Weall-Protocol/configs");
const readJson = (name) => JSON.parse(readFileSync(resolve(configRoot, name), "utf8"));

function requireHttpsEndpoint(value) {
  const url = new URL(String(value));
  assert.equal(url.protocol, "https:", "public browser seed must use HTTPS");
  assert.ok(url.hostname && !url.username && !url.password, "seed must be a public URL without credentials");
  assert.ok(!/^(localhost|127[.]|0[.]|.*[.]example)$/i.test(url.hostname), "placeholder or loopback seed not allowed");
  assert.ok(!url.search && !url.hash, "seed must not contain query or fragment");
  const normalized = url.toString();
  return normalized.endsWith("/") ? normalized.slice(0, -1) : normalized;
}

function main() {
  const commitments = readJson("public_testnet_chain_commitments.json");
  const trustRoots = readJson("public_testnet_trust_roots.json");
  const registry = readJson("public_testnet_seed_registry.json");

  for (const field of ["network_id", "chain_id", "genesis_hash", "protocol_profile_hash", "tx_index_hash"]) {
    assert.ok(String(commitments[field] || ""), `missing pinned ${field}`);
    assert.equal(registry[field], commitments[field], `registry ${field} differs from pinned chain`);
    assert.equal(trustRoots[field], commitments[field], `trust root ${field} differs from pinned chain`);
  }
  assert.equal(registry.resettable_testnet, true, "only resettable testnet supported");
  assert.equal(registry.economics_active, false, "public observer economics must remain disabled");
  assert.equal(registry.active_signature_profile, "pq-mldsa-v1", "ML-DSA registry required");
  assert.equal(registry.seed_registry_rotation_required, false, "registry rotation pending; fail closed");
  assert.equal(registry.pq_resign_required_before_public_testnet, false, "registry re-signing pending; fail closed");
  assert.ok(String(registry.seed_registry_signature || "").trim(), "signed public registry required");
  assert.ok(
    Array.isArray(trustRoots.seed_registry_pubkeys) &&
      trustRoots.seed_registry_pubkeys.includes(registry.seed_registry_signer),
    "registry signing key is not pinned in trust roots",
  );

  // Avoid treating signed P2P endpoints as browser-accessible HTTP APIs.
  const rawEndpoints = [
    ...(Array.isArray(registry.seed_api_urls) ? registry.seed_api_urls : []),
    ...(Array.isArray(registry.nodes) ? registry.nodes.map((node) => node.base_url || node.api_base).filter(Boolean) : []),
  ];
  const seeds = [...new Set(rawEndpoints.map(requireHttpsEndpoint))];
  assert.ok(seeds.length > 0, "no public HTTPS API seeds in signed registry");

  const env = {
    ...process.env,
    VITE_WEALL_PUBLIC_TESTNET: "true",
    VITE_WEALL_API_BASE: "/",
    VITE_WEALL_SEED_MANIFEST_URL: "/seeds.json",
    VITE_WEALL_ENABLE_DEV_TOOLS: "0",
    VITE_WEALL_ENABLE_DEV_BOOTSTRAP: "0",
    VITE_WEALL_EXPECTED_CHAIN_ID: commitments.chain_id,
    VITE_WEALL_EXPECTED_GENESIS_HASH: commitments.genesis_hash,
    VITE_WEALL_EXPECTED_TX_INDEX_HASH: commitments.tx_index_hash,
    VITE_WEALL_EXPECTED_PROTOCOL_PROFILE_HASH: commitments.protocol_profile_hash,
  };

  // Vite copies web/public/seeds.json (the local-dev fixture) into dist.
  // Overwrite only the generated artifact, leaving the tracked fixture intact.
  execFileSync(process.platform === "win32" ? "npm.cmd" : "npm", ["run", "build"], {
    cwd: webRoot,
    env,
    stdio: "inherit",
  });

  const manifest = {
    version: 1,
    network_id: commitments.network_id,
    chain_id: commitments.chain_id,
    genesis_hash: commitments.genesis_hash,
    tx_index_hash: commitments.tx_index_hash,
    protocol_profile_hash: commitments.protocol_profile_hash,
    resettable_testnet: true,
    economics_active: false,
    nodes: seeds.map((api_base, index) => ({
      label: `Public testnet seed ${index + 1}`,
      api_base,
      description: "Candidate HTTPS node; browser performs network compatibility and readiness checks.",
    })),
  };
  writeFileSync(resolve(webRoot, "dist/seeds.json"), JSON.stringify(manifest, null, 2) + "\n");
  console.log(`Cloudflare static frontend prepared with ${seeds.length} HTTPS seed(s).`);
  console.log("Registry signature verification remains an operator-side prerequisite; no cryptographic verification was performed by this build script.");
}

main();
