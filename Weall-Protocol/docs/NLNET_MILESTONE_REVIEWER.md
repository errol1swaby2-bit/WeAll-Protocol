# WeAll NLnet External Observer Milestone Reviewer Guide

Status: pre-production reviewer guide. This document is intentionally narrow. It does not claim mainnet readiness, public validator readiness, or a fully self-bootstrapped Proof-of-Humanity network.

## Milestone claim this repo is moving toward

WeAll is a free/open-source deterministic coordination protocol with a reproducible fresh-clone demo, a documented external observer node path, protocol-native human verification architecture, deterministic civic receipts, governance/review primitives, and a human-readable frontend suitable for external review.

## What is implemented enough to review

- Transaction canon artifacts are generated and checked by `scripts/check_tx_canon_artifacts.py`.
- Production-like runtime posture is guarded by `scripts/prod_node_preflight.sh` and `scripts/run_node_prod.sh`.
- A public observer/operator bundle can be verified with `scripts/verify_node_operator_onboarding_bundle.py`.
- A second machine can run a connectivity/identity rehearsal with `scripts/rehearse_external_observer_two_machine.sh`.
- The live observer gate submits signed onboarding/account/networking/native-async-PoH transactions with `scripts/external_observer_live_gate.sh`.
- The frontend builds and uses human-facing language for account verification, decisions, reports, reviews, and advanced technical records.

## Commands for an outside reviewer

From the backend root `Weall-Protocol/`:

```bash
python3 -S scripts/check_tx_canon_artifacts.py
bash scripts/secret_guard.sh
bash scripts/verify_release_dependencies.sh
bash scripts/verify_release_tree.sh
```

For the bounded reviewer smoke suite:

```bash
bash scripts/nlnet_reviewer_check.sh
```

For frontend-only checks from the outer repo root:

```bash
cd web
npm ci
npm run typecheck
npm run build
npm run production-safety-check
```

The frontend/backend contract check requires a running backend API:

```bash
API_BASE=http://127.0.0.1:8000 npm run contract-check
# or, from the outer repo root:
bash scripts/run_frontend_contract_check.sh
```

## Two-machine observer evidence path

On the genesis machine, boot the node with the production-like runbook and expose the intended API endpoint to the observer. On the observer machine:

```bash
export WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE=/path/to/public-observer-bundle.json
export WEALL_CHAIN_MANIFEST_PATH=/path/to/weall-genesis.json
export WEALL_GENESIS_API_BASE=http://GENESIS_HOST:8000
export WEALL_ALLOW_PRIVATE_GENESIS_API=1   # only for private LAN rehearsals

bash scripts/rehearse_external_observer_two_machine.sh "$WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE"
bash scripts/external_observer_live_gate.sh "$WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE"
```

The rehearsal proves reachability, bundle/manifest identity, safe observer posture, and optional relay transport-only status. The live gate is the proof that signed observer onboarding/account/networking/native-async-PoH transactions can be submitted and confirmed.

## What must be captured before grant submission

Save command transcripts for:

1. `git rev-parse --abbrev-ref HEAD`, `git rev-parse HEAD`, and `git status --short`.
2. Backend canon/secret/dependency/release-tree checks.
3. Frontend typecheck/build/production-safety checks.
4. Two-machine observer rehearsal.
5. Two-machine observer live gate.
6. Any frontend/backend contract check against the running API.

## Authority boundaries

The backend/chain state is authoritative. The frontend explains and guides only. Helpers, relay, rendezvous, gossip, IPFS/media/content storage, and UI state are non-authoritative unless deterministic protocol state commits the relevant hash, receipt, role, badge, assignment, or transaction result.
