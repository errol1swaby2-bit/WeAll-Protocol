# Public Observer Testnet Quickstart

Batch 626 adds the fail-closed discovery layer required for a public, open-download observer testnet. This document is intentionally conservative: it does not claim public beta or production readiness by itself.

## Safety boundary

- Observer access is open once the public seed registry is published.
- Validator activation is protocol-gated.
- Validator signing authority is not automatic.
- Tier 2 promotion, validation opt-in, storage provider roles, juror roles, governance authority, and reputation-sensitive roles remain controlled by protocol state.
- This is a resettable public testnet.
- Tokens and economic balances have no real-world value.
- Bugs or upgrades may reset state; users must not rely on persistence across resets.

## Required public configuration

A public observer node must be started with an explicit seed registry:

```bash
export WEALL_PUBLIC_TESTNET=1
export WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PATH=/path/to/public_testnet_seed_registry.json
```

The registry must include:

- `network_id`
- `chain_id`
- `genesis_hash`
- `protocol_profile_hash`
- `tx_index_hash`
- `seed_api_urls`
- `seed_p2p_urls`
- `resettable_testnet: true`
- `economics_active: false`

Use `configs/public_testnet_seed_registry.example.json` as the schema example. Do not publish a public observer build with fake seed URLs or placeholder hashes.

## Clean-clone observer boot

```bash
git clone <repo-url> WeAll-Protocol
cd WeAll-Protocol/Weall-Protocol
python -m venv .venv
source .venv/bin/activate
pip install -e .

export WEALL_MODE=prod
export WEALL_API_MODE=node
export WEALL_OBSERVER_MODE=1
export WEALL_OBSERVER_EDGE_MODE=1
export WEALL_PUBLIC_TESTNET=1
export WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PATH=/absolute/path/to/public_testnet_seed_registry.json

python -m weall.api
```

Verify the local observer sees the public seed commitments:

```bash
curl -s http://127.0.0.1:8000/v1/nodes/seeds | python -m json.tool
curl -s http://127.0.0.1:8000/v1/nodes/validators | python -m json.tool
curl -s http://127.0.0.1:8000/v1/chain/identity | python -m json.tool
```

Expected results:

- `/v1/nodes/seeds` returns `public_testnet: true` and the pinned chain/genesis/profile commitments.
- `/v1/nodes/validators` returns active validator accounts from protocol state and separates verified endpoints from unverified hints.
- `/v1/chain/identity` matches the seed registry commitments.

## Frontend public observer build

Public observer web builds must pin expected commitments:

```bash
VITE_WEALL_PUBLIC_TESTNET=true
VITE_WEALL_SEED_MANIFEST_URL=/seeds.json
VITE_WEALL_EXPECTED_CHAIN_ID=<public-chain-id>
VITE_WEALL_EXPECTED_GENESIS_HASH=<public-genesis-hash>
VITE_WEALL_EXPECTED_TX_INDEX_HASH=<public-tx-index-hash>
VITE_WEALL_EXPECTED_PROTOCOL_PROFILE_HASH=<public-profile-hash>
```

In public testnet mode the frontend must not use the first reachable node as the compatibility baseline. Missing commitments should render a configuration error instead of marking a node healthy.

## Public observer launch gate

Before claiming public observer launch readiness, capture an external transcript showing:

1. Clean clone.
2. Public seed registry configured.
3. Observer boot.
4. `/v1/nodes/seeds` public commitments match pinned values.
5. `/v1/nodes/validators` active validators and verified endpoints render correctly.
6. Frontend shows browser API access node separately from local mesh status.
7. Observer tx forwarding either relays to a verified upstream or fails with `PUBLIC_TESTNET_NO_VERIFIED_TX_UPSTREAM` without creating false propagation success.
