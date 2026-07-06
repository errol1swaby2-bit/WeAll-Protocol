# Observer proof posture and evidence capture

Status: **runbook and local proof posture; first external observer readiness remains unclaimed until a fresh remote/signed run is captured**.

WeAll is a pre-public-testnet protocol implementation under active hardening. Observer evidence is tiered because local scripts, same-machine dual-node runs, and remote two-machine signed observer runs prove different things.

## Observer proof tiers

| Tier | Proof name | What it can show | What it cannot claim | Evidence destination |
|---|---|---|---|---|
| 1 | Local observer proof | A local checkout can verify chain identity/trust roots, boot observer mode, expose status, and keep launch claims disabled. | Does not prove external reproducibility or first external observer readiness. | `audit-metadata/reviewer-evidence-YYYY-MM-DD/local-observer-*.log` |
| 2 | Same-machine dual-node proof | Two local nodes can exercise controlled-devnet flows on one machine and compare local evidence. | Does not prove independent network/operator reproducibility. | `audit-metadata/reviewer-evidence-YYYY-MM-DD/same-machine-dual-node-*.log` |
| 3 | Remote two-machine signed observer proof | A fresh external machine/operator can clone/open-download, verify registry/chain identity, boot observer, sync/replay as specified, and bind outputs to a commit and operator signature. | Still not public mainnet, public BFT, live economics, or public beta by itself. | `audit-metadata/reviewer-evidence-YYYY-MM-DD/remote-signed-observer-*.log` |

## Required capture commands

Use the date-specific bundle path for the commit under review:

```bash
BUNDLE="audit-metadata/reviewer-evidence-$(date -u +%F)"
mkdir -p "$BUNDLE/transcripts"

{
  date -u +%Y-%m-%dT%H:%M:%SZ
  git rev-parse HEAD
  git status --short
  python --version
  node --version || true
  npm --version || true
} | tee "$BUNDLE/transcripts/commit-environment.txt"

{
  PYTHONPATH=src:scripts python scripts/gen_final_public_observer_controlled_testnet_go_gate_v1_5.py --check
  PYTHONPATH=src:scripts python scripts/gen_public_beta_blocker_report_v1_5.py --check
  PYTHONPATH=src python scripts/check_v15_public_readiness_artifacts.py
} 2>&1 | tee "$BUNDLE/transcripts/local-observer-readiness-gates.log"

{
  WEALL_PUBLIC_TESTNET=1 bash scripts/boot_public_observer_testnet.sh
} 2>&1 | tee "$BUNDLE/transcripts/local-observer-boot.log"
```

For the first external observer proof, capture the same commands on the remote machine and add:

```bash
{
  hostname || true
  uname -a || true
  sha256sum generated/tx_index.json generated/public_beta_blocker_report_v1_5.json
  curl -s http://127.0.0.1:8000/v1/readyz | python3 -m json.tool
  curl -s http://127.0.0.1:8000/v1/status | python3 -m json.tool
  curl -s http://127.0.0.1:8000/v1/chain/identity | python3 -m json.tool
  curl -s http://127.0.0.1:8000/v1/observer/edge/status | python3 -m json.tool
} 2>&1 | tee "$BUNDLE/transcripts/remote-signed-observer-status.log"
```

The transcript must state the operator, machine ownership, commit hash, whether any secrets were manually supplied, whether the seed registry signature verified, and whether the node remained observer-only.

## Authority lock

Observer nodes remain non-authoritative. Observer paths must not enable validator signing, grant validator set membership, bypass PoH/role/readiness gates, or convert frontend state into protocol authority. Use:

```bash
PYTHONPATH=src python -m pytest -q \
  tests/prod/test_observer_cannot_enable_validator_signing.py \
  tests/prod/test_observer_bundle_contains_no_authority_secrets.py \
  tests/prod/test_external_observer_signed_onboarding_tx_e2e.py
```

## Reviewer wording

Allowed before remote proof is captured:

```text
Local observer proof posture exists; first external observer readiness remains blocked until a fresh remote/signed observer proof is run and captured.
```

Forbidden before remote proof is captured:

```text
First external observer readiness is complete.
External observer proof is closed.
Public beta observer readiness is proven.
```
