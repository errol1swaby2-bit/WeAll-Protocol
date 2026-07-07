# Public Observer Evidence Runbook

This runbook captures proof for the public observer testnet gate. It does not prove broader public validator beta or production readiness.

## Evidence to capture

- Public seed registry file and digest.
- Public frontend pinned commitment env values.
- Clean clone transcript.
- Observer boot transcript.
- `/v1/nodes/seeds` output.
- `/v1/nodes/validators` output.
- `/v1/chain/identity` output from observer and seed.
- Frontend screenshot/transcript showing observer status, public seed status, active validators, and resettable non-economic warning.
- Tx forwarding proof: verified upstream accepted, or `PUBLIC_TESTNET_NO_VERIFIED_TX_UPSTREAM` returned with no false propagation success.
- Validator signing disabled proof for observer mode.

## Suggested transcript commands

```bash
git status --short
python --version
curl -s http://127.0.0.1:8000/v1/nodes/seeds | tee evidence-public-nodes-seeds.json
curl -s http://127.0.0.1:8000/v1/nodes/validators | tee evidence-public-validator-endpoints.json
curl -s http://127.0.0.1:8000/v1/chain/identity | tee evidence-public-chain-identity-local.json
curl -s <seed-api>/v1/chain/identity | tee evidence-public-chain-identity-seed.json
```

## Classification rule

Claim `D. Ready for public observer testnet with gated validator activation` only after a fresh external machine can clean-clone, boot observer mode, verify pinned public commitments, discover active validators/endpoints, and observe mempool/block propagation without validator authority bypass.
