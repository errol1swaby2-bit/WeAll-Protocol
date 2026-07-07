import { expect, test } from "@playwright/test";

const now = 1_800_000_000_000;
const observerAccount = "@observer";
const zeroPubkeyB64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const zeroSecretKeyB64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";

async function mockPublicObserverApi(page: import("@playwright/test").Page) {
  await page.route("**/v1/status/operator", async (route) => route.fulfill({ json: { ok: true, operator: { startup_posture: { observer_mode: true }, authority_contract: { validator_effective: false, helper_effective: false }, profile_compatibility: { ok: true } }, net: { peer_counts: { connected_peers: 2 } }, block_loop: {}, consensus: {} } }));
  await page.route("**/v1/status/consensus", async (route) => route.fulfill({ json: { ok: true, phase: "observer" } }));
  await page.route("**/v1/status/mempool", async (route) => route.fulfill({ json: { ok: true, size: 1 } }));
  await page.route("**/v1/storage/ipfs/ops", async (route) => route.fulfill({ json: { ok: true, durability: {}, pin_status_counts: {}, enabled_operators: [] } }));
  await page.route("**/v1/chain/head", async (route) => route.fulfill({ json: { ok: true, height: 42, state_root: "state-root-demo" } }));
  await page.route("**/v1/chain/identity", async (route) => route.fulfill({ json: { ok: true, chain_id: "weall-testnet-v1", genesis_hash: "genesis-demo", protocol_profile_hash: "profile-demo", tx_index_hash: "tx-index-demo", height: 42 } }));
  await page.route("**/v1/status/launch-matrix", async (route) => route.fulfill({ json: { ok: true, public_beta_ready: false, live_economics: false } }));
  await page.route("**/v1/status/testnet-capabilities", async (route) => route.fulfill({ json: { ok: true, capabilities: {} } }));
  await page.route("**/v1/consensus/block-production/readiness", async (route) => route.fulfill({ json: { ok: true } }));
  await page.route("**/v1/status/helper/readiness", async (route) => route.fulfill({ json: { ok: true, summary: {} } }));
  await page.route("**/v1/net/self", async (route) => route.fulfill({ json: { ok: true, peers: [{ peer_id: "seed" }, { peer_id: "validator" }], net: { advertise_uri: "tls://observer.example:30303", seed_discovery: { refresh_ms: 60000, last_ok: true, last_error: "" } }, nat: { recommended_profile: "public_inbound", inbound_reachable_claim: true, advertise: { configured: true, status: "public_or_dns", host_kind: "dns" }, relay: { client_enabled: false, client_ready: false, authority: "transport_only" }, warnings: [], recovery_actions: [], authority: "network_transport_only" } } }));
  await page.route("**/v1/status", async (route) => route.fulfill({ json: { ok: true, chain_id: "weall-testnet-v1", height: 42 } }));
  await page.route("**/v1/readyz", async (route) => route.fulfill({ json: { ok: true } }));
  await page.route("**/v1/accounts/**", async (route) => route.fulfill({ json: { ok: true, state: { account: observerAccount, nonce: 0, poh_tier: 2, banned: false, locked: false, reputation: 10 } } }));
  await page.route("**/v1/account/*/operator/status", async (route) => route.fulfill({ json: { ok: true, node_operator: { status: "observer", storage: {}, validator: { status: "not_opted_in" }, helper: {} } } }));
  await page.route("**/v1/nodes/seeds", async (route) => route.fulfill({ json: { ok: true, public_testnet: true, network_id: "weall-public-observer-testnet-v1", chain_id: "weall-testnet-v1", genesis_hash: "genesis-demo", seed_p2p_urls: ["tcp://seed.example:30303"], seed_registry_signature_status: { verified: true, trust: "pinned" }, registry_source_kind: "file", nodes: [{ base_url: "https://seed.example", role: "seed" }] } }));
  await page.route("**/v1/nodes/validators", async (route) => route.fulfill({ json: { ok: true, public_testnet: true, active_validator_count: 1, verified_endpoint_count: 1, verified_fresh_endpoint_count: 1, stale_verified_endpoint_count: 0, active_validators_missing_verified_fresh_endpoint_count: 0, all_active_validators_have_verified_fresh_endpoint: true, endpoint_freshness_policy: { max_age_ms: 3600000 }, validators: [{ account_id: "@validator", node_pubkey: "pub", active_in_protocol_state: true, verified_endpoint_count: 1, verified_fresh_endpoint_count: 1, stale_verified_endpoint_count: 0, has_verified_fresh_endpoint: true, endpoint_records: [{ account_id: "@validator", api_base_url: "https://validator.example", p2p_url: "tcp://validator.example:30303", verified: true, freshness: { fresh: true, proof_timestamp_ms: now } }] }], registry: { seed_registry_signature_status: { verified: true } } } }));
  await page.route("**/v1/observer/edge/status", async (route) => route.fulfill({ json: { ok: true, observer_edge_mode: true, verified_upstream_count: 1, local_tx_queue_count: 1, upstream_accepted_count: 1, upstream_confirmed_count: 0 } }));
}

test("public observer dashboard renders discovery, validator freshness, and recovery guidance", async ({ page }) => {
  await mockPublicObserverApi(page);
  await page.addInitScript(({ account, pubkeyB64, secretKeyB64 }) => {
    window.localStorage.setItem("weall.account", account);
    window.localStorage.setItem(
      "weall_session_v1",
      JSON.stringify({
        version: 1,
        account,
        sessionKey: "rendered-public-observer-session",
        expiresAtMs: Date.now() + 60 * 60 * 1000,
      }),
    );
    window.localStorage.setItem(
      `weall_keypair::${account}`,
      JSON.stringify({ version: 2, publicKey: pubkeyB64, pubkeyB64, hasSecret: false }),
    );
    window.sessionStorage.setItem(`weall_secret::${account}`, secretKeyB64);
  }, { account: observerAccount, pubkeyB64: zeroPubkeyB64, secretKeyB64: zeroSecretKeyB64 });
  await page.goto("/#/node");

  await expect(page.getByText(/Seed, validator, and tx propagation visibility/i)).toBeVisible();
  await expect(page.getByText(/Fresh validator endpoints/i)).toBeVisible();
  await expect(page.getByText(/NAT \/ firewall posture/i)).toBeVisible();
  await expect(page.getByText(/Recommended network profile/i)).toBeVisible();
  await expect(page.getByText(/Registry source/i)).toBeVisible();
  await expect(page.getByText(/Direct P2P priority/i)).toBeVisible();
  await expect(page.getByText(/Peer \/ NAT recovery/i)).toBeVisible();
  await expect(page.getByText(/Validator promotion path/i)).toBeVisible();
  await expect(page.getByText(/local tx acceptance is shown separately from upstream validator acceptance/i)).toBeVisible();
});


test("public observer node dashboard is readable before account setup", async ({ page }) => {
  await mockPublicObserverApi(page);
  await page.goto("/#/node");

  await expect(page).toHaveURL(/#\/node$/);
  await expect(page.getByText(/Seed, validator, and tx propagation visibility/i)).toBeVisible();
  await expect(page.getByText(/NAT \/ firewall posture/i)).toBeVisible();
  await expect(page.getByText(/Validator promotion path/i)).toBeVisible();
  await expect(page.getByText(/Sign in to unlock account actions/i)).toBeVisible();
});
