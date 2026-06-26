# Public Observer Launch Transcript Evidence

This runbook describes the launch transcript required before claiming a public observer testnet is open for arbitrary new users.

The repository may contain source-level gates, generated schemas, and local rehearsals before launch. A public observer launch claim requires a real runtime transcript against the published signed registry and reachable seed/validator APIs.

## Required runtime transcript

Run after `configs/public_testnet_seed_registry.json` exists and the published signer pin is available:

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

The runtime transcript is intentionally separate from tracked static artifacts because it binds to live endpoints, timestamps, current validators, and operator environment.

## What must be proven

The transcript must show:

- registry signature verified and signer pinned
- registry commitments are non-placeholder and match `/v1/chain/identity`
- `/v1/nodes/seeds` returns the same signed discovery root
- `/v1/nodes/validators` reports current active validators
- active validators have verified fresh endpoint records, or any missing endpoints are explicit warnings
- `/v1/observer/edge/status` separates local tx queue, upstream acceptance, and confirmed state
- observer can sync to the trusted anchor/current head and preserve posture across restart
- the frontend rendered public observer journey is run in the same release environment

## Static tracked artifacts

The following artifacts are tracked as contracts/gates, not as launch claims:

- `generated/public_seed_registry_signature_verification_v1_5.json`
- `generated/public_observer_clean_clone_bootstrap_transcript_v1_5.json`
- `generated/public_observer_auto_discovery_proof_v1_5.json`
- `generated/public_observer_state_sync_trusted_anchor_proof_v1_5.json`
- `generated/public_validator_endpoint_churn_proof_v1_5.json`
- `generated/public_frontend_operator_journey_v1_5.json`
- `generated/public_registry_signer_operations_v1_5.json`

Each keeps `public_observer_launch_ready=false` until the runtime evidence is attached.
