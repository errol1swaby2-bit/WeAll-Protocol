# Public Observer Open-Download Transcript

This checklist prepares `AUD-628-P1-001`. It does not close the blocker by itself.

The transcript must be captured from a clean clone on a machine not controlled by the founder. Local founder-run transcripts may improve the runbook, but they must remain classified as local rehearsal evidence.

## What to capture

1. External machine/operator metadata.
2. Repository URL, branch, commit, and clean `git status --short` before local edits.
3. Dependency install transcript.
4. Pinned trust-root / registry signer source.
5. Signed seed registry verification and registry digest.
6. Observer boot transcript.
7. `/v1/status`, `/v1/chain/identity`, `/v1/chain/head`, `/v1/nodes/seeds`, `/v1/nodes/validators`, and `/v1/observer/edge/status` snapshots.
8. State sync proof, or an honest fail-closed state-sync result.
9. Frontend rendered journey showing Home, Personal Node, Account/Profile, Transactions, Feed, Groups, Governance, and Disputes.
10. Transaction forwarding behavior, or an honest fail-closed tx-forwarding response.
11. Explicit non-claims: no public beta, mainnet, public validator safety, live economics, automatic upgrades, production helpers, legal approval, or storage-market readiness.

## Capture script

```bash
cd WeAll-Protocol
source .venv/bin/activate
export WEALL_PUBLIC_TESTNET=1
export WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PUBKEY=<published-registry-signer-public-key>

bash scripts/capture_public_observer_open_download_transcript_v1_5.sh \
  --api-base https://<public-seed-or-genesis-api> \
  --registry configs/public_testnet_seed_registry.json \
  --out-dir docs/proofs/public-observer-open-download/<yyyy-mm-dd>/<operator-or-host>/ \
  --frontend-url http://127.0.0.1:5173
```

The script writes a manifest and route snapshots, but a reviewer still needs to confirm externality, commit binding, rendered frontend evidence, and claim boundaries.

## Closure rule

Keep `AUD-628-P1-001` open until the completed transcript package exists and is reviewed. Do not set `public_beta_ready=true` from this script or template.
