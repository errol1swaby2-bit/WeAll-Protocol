# Reviewer Production-Readiness Milestone

Status: bounded production-readiness milestone for reviewer submission.

This milestone must be presented as a bounded reviewer-readiness package, not as a finished public mainnet.

This repository should be reviewed as a serious implementation seeking support to complete public-testnet readiness. It is not a finished public mainnet, not public multi-validator BFT ready, and not live-economics ready.

See also:

- `docs/TRUTH_BOUNDARY.md`
- `docs/REVIEWER_EVIDENCE_INDEX.md`
- `docs/REVIEWER_MILESTONE_GUIDE.md`

## What is proven today

The current repository can provide evidence for the following bounded claims when the commands pass on the submitted commit:

- Transaction canon and generated artifacts are synchronized.
- Release tree hygiene, dependency locks, and secret guard checks are available.
- The targeted reviewer readiness suite passes.
- Frontend typecheck passes after clean dependency installation.
- Account custody and recovery-file frontend flows exist.
- Native Proof-of-Humanity verification, posting, group activity, reporting/review, governance, and encrypted direct-message body flows exist as implemented/testnet surfaces.
- Local observer readiness and observer authority-lock gates exist.
- Local block-production proof can commit root-bearing local block evidence.
- Tokenomics, wallet, tips, transfers, treasury allocation, and reward accounting exist as visible/locked mechanics and tested invariants.

## What is not proven today

This milestone does not claim:

- public mainnet readiness;
- public multi-validator BFT readiness;
- public validator authority readiness;
- live economics;
- production-grade public encrypted messaging;
- fully complete constitutional governance;
- signed remote external observer onboarding unless the full remote/signed first-external-observer gate has been run and captured.

## Reviewer command

From `Weall-Protocol/`:

```bash
bash scripts/reviewer_production_readiness_gate.sh
```

The command is intentionally targeted. Full pytest may still be run separately by reviewers from a clean dependency environment:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.lock
PYTHONPATH=src pytest
```

The block-production check in the reviewer gate is local evidence only. Public multi-validator BFT and production validator authority require separate future proof.

## Evidence commands

From `Weall-Protocol/`:

```bash
python3 -B -S scripts/check_tx_canon_artifacts.py
bash scripts/secret_guard.sh
bash scripts/verify_release_dependencies.sh
bash scripts/verify_release_tree.sh
bash scripts/local_observer_readiness_gate.sh
bash scripts/external_observer_authority_lock_gate.sh
PYTHONPATH=src python3 scripts/production_block_production_rehearsal_gate.py
```

From the outer repo root:

```bash
cd web
npm ci
npm run typecheck
```

After frontend checks, clean generated artifacts before running release-tree hygiene:

```bash
rm -rf node_modules dist tsconfig.tsbuildinfo
```

## First external observer boundary

Local observer checks are not enough to claim first trusted external observer readiness.

That claim requires:

```bash
export WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE=/path/to/public-observer-bundle.json
export WEALL_CHAIN_MANIFEST_PATH=/path/to/weall-genesis.json
export WEALL_GENESIS_API_BASE=http://GENESIS_HOST:8000
export WEALL_ALLOW_PRIVATE_GENESIS_API=1
export WEALL_RUN_TWO_MACHINE_OBSERVER_PREFLIGHT=1
export WEALL_RUN_SIGNED_OBSERVER_ONBOARDING=1
bash scripts/first_external_observer_reproducibility_gate.sh "$WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE"
```

If the remote/signed path has not been run, the correct statement is:

> Local observer preconditions and authority lock pass. Signed remote external observer onboarding remains the next proof before claiming first trusted external observer readiness.

## What this milestone prepares

This milestone prepares the project for a fundable public-testnet readiness path:

1. Clean clone and external observer onboarding hardening.
2. Account custody, PoH verification, and onboarding UX.
3. Content, groups, dispute/review, appeals, and governance testnet flows.
4. Locked tokenomics, wallet, tips, treasury, and reward accounting proof.
5. Deterministic block progression, validator promotion, and multi-node/BFT testnet readiness.
6. Documentation, reproducibility, security hardening, and external tester reporting.

## Funder-facing summary

WeAll has crossed from specification into a serious, reviewable implementation with reproducible local/reviewer gates and private/external-observer rehearsal evidence. Funding will move it into a documented public testnet with external observers, Proof-of-Humanity verification, content/groups, dispute/review, governance, locked testnet tokenomics, deterministic block progression, validator promotion, and eventually adversarial multi-validator BFT readiness.
