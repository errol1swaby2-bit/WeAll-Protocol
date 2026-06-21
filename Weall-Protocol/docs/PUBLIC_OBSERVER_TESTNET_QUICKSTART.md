# Public Observer Testnet Quickstart

Batch 629 keeps the public observer path fail-closed around signed discovery and adds launch transcript, validator endpoint churn, rendered frontend, and registry signer operation evidence gates. This document is still conservative: it does not claim public beta, public validator, mainnet, or production readiness by itself.

## Safety boundary

- Observer access is open once the public seed registry is published.
- Validator activation is protocol-gated.
- Validator signing authority is not automatic.
- Tier 2 promotion, validation opt-in, storage provider roles, juror roles, governance authority, and reputation-sensitive roles remain controlled by protocol state.
- This is a resettable public testnet.
- Tokens and economic balances have no real-world value.
- Bugs or upgrades may reset state; users must not rely on persistence across resets.

## Public discovery trust model

Public observer mode uses the backend public seed registry as the source of truth. The frontend may still read `/seeds.json` as a compatibility fallback, but the node dashboard and connection manager now prefer backend `/v1/nodes/seeds` and `/v1/nodes/validators`.

A production public observer registry must include a valid Ed25519 registry signature and a pinned registry signer:

```bash
export WEALL_PUBLIC_TESTNET=1
export WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PUBKEY=<published-registry-public-key>
```

The registry is loaded from the first available source:

1. `WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PATH`
2. `WEALL_PUBLIC_SEED_REGISTRY_PATH`
3. `WEALL_PUBLIC_TESTNET_DEFAULT_SEED_REGISTRY_PATH`
4. `./public_testnet_seed_registry.json`
5. `./config/public_testnet_seed_registry.json`
6. `./configs/public_testnet_seed_registry.json`
7. `./Weall-Protocol/config/public_testnet_seed_registry.json`
8. `./Weall-Protocol/configs/public_testnet_seed_registry.json`

The registry must include:

- `network_id`
- `chain_id`
- `genesis_hash`
- `protocol_profile_hash`
- `tx_index_hash`
- `seed_api_urls`
- `seed_p2p_urls`
- `seed_registry_signer`
- `seed_registry_signature`
- `resettable_testnet: true`
- `economics_active: false`

Only `tcp://` and `tls://` P2P URIs are accepted because those are the transports the net loop can dial. Placeholder schemes such as `p2p://`, `weall://`, or `libp2p://` must not be published until the runtime actually supports them.

Validator endpoint advertisements are separate from validator authority. A validator endpoint is treated as verified only when its endpoint signature validates against the registry commitments. Endpoint hints never grant validator status; protocol state remains the authority.

Use `configs/public_testnet_seed_registry.example.json` as the schema example. Do not publish a public observer build with fake seed URLs, placeholder hashes, unsigned production registries, or unverified validator endpoints.

## Signing and publishing the registry

The checked-in `configs/public_testnet_seed_registry.example.json` is a schema example only. It contains placeholder values and must not be renamed into a launch registry. Build the real unsigned registry from the live testnet commitments, then sign it with the registry signing key:

```bash
cd Weall-Protocol
export WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PRIVKEY=<registry-private-key-kept-out-of-git>
export WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PUBKEY=<published-registry-public-key>
PYTHONPATH=src python scripts/sign_public_seed_registry_v1_5.py \
  --input /secure/path/public_testnet_seed_registry.unsigned.json \
  --output configs/public_testnet_seed_registry.json
PYTHONPATH=src WEALL_PUBLIC_TESTNET=1 python scripts/sign_public_seed_registry_v1_5.py \
  --input /secure/path/public_testnet_seed_registry.unsigned.json \
  --output configs/public_testnet_seed_registry.json \
  --check
```

The signer pin published to observers must match `seed_registry_signer`. Rotate or revoke this signer through release notes before changing it; a registry signed by an unpinned key must fail closed.

## Clean-clone observer boot

```bash
git clone <repo-url> WeAll-Protocol
cd WeAll-Protocol/Weall-Protocol
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.lock
pip install -e .

export WEALL_MODE=prod
export WEALL_API_MODE=node
export WEALL_OBSERVER_MODE=1
export WEALL_OBSERVER_EDGE_MODE=1
export WEALL_PUBLIC_TESTNET=1
export WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PUBKEY=<published-registry-public-key>
# Optional if the release does not bundle ./public_testnet_seed_registry.json:
export WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PATH=/absolute/path/to/public_testnet_seed_registry.json

bash scripts/boot_public_observer_testnet.sh
```

The boot script verifies the signed registry, exports observer-safe defaults, prints the seed/validator/observer status URLs, and then starts `python -m weall.api`. Manual `python -m weall.api` boot remains supported after the same environment variables are set.

Verify the local observer sees signed public commitments:

```bash
curl -s http://127.0.0.1:8000/v1/nodes/seeds | python -m json.tool
curl -s http://127.0.0.1:8000/v1/nodes/validators | python -m json.tool
curl -s http://127.0.0.1:8000/v1/observer/edge/status | python -m json.tool
curl -s http://127.0.0.1:8000/v1/chain/identity | python -m json.tool
```

Expected results:

- `/v1/nodes/seeds` returns `public_testnet: true`, signed registry status, and the pinned chain/genesis/profile commitments.
- `/v1/nodes/validators` returns active validator accounts from protocol state and separates verified endpoints from unverified hints.
- `/v1/observer/edge/status` separates local outbox state from upstream validator acceptance/confirmation.
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

The Node Dashboard must show:

- seed registry signature status
- seed API and P2P counts
- active validators from `/v1/nodes/validators`
- verified validator endpoint counts
- observer-edge upstream count
- local outbox count
- upstream accepted and confirmed counts

## Public observer launch gate

Before claiming public observer launch readiness, capture an external transcript showing:

1. Clean clone.
2. Dependency install from `requirements.lock`.
3. Public seed registry loaded from the default path or explicit path.
4. Registry signature verified against the pinned public key.
5. Observer boot.
6. Registry seed P2P URIs merged into the local peer store.
7. Verified validator P2P URIs merged into the local peer store.
8. `/v1/nodes/seeds` public commitments match pinned values.
9. `/v1/nodes/validators` active validators and verified endpoints render correctly.
10. Frontend shows browser API access node separately from local mesh status.
11. Observer tx forwarding either relays to a verified upstream or fails with `PUBLIC_TESTNET_NO_VERIFIED_TX_UPSTREAM` without creating false propagation success.
12. Observer mode cannot activate validator signing or BFT authority before committed protocol state makes the validator effective.
13. Validator endpoint churn is visible: stale or missing verified endpoint advertisements must appear as warnings before claiming connection to all current validators.
14. NAT/firewall/relay recovery steps are captured if peer counts remain low despite fresh endpoint advertisements.


## Runtime launch transcript

After publishing a real signed `configs/public_testnet_seed_registry.json`, capture the runtime transcript before making a public observer launch claim:

```bash
cd Weall-Protocol
source .venv/bin/activate
export WEALL_PUBLIC_TESTNET=1
export WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PUBKEY=<published-registry-public-key>

bash scripts/run_public_observer_launch_rehearsal_v1_5.sh \
  --api-base https://<public-seed-api> \
  --registry configs/public_testnet_seed_registry.json \
  --out generated/public_observer_launch_runtime_transcript_v1_5.json
```

Static launch-evidence contracts are tracked in `generated/public_*_v1_5.json`; they remain conservative and keep `public_observer_launch_ready=false` until the runtime transcript is attached. See `docs/PUBLIC_OBSERVER_LAUNCH_TRANSCRIPTS.md` and `docs/PUBLIC_REGISTRY_SIGNER_OPERATIONS.md`.
