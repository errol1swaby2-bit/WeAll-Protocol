# WeAll reviewer Evidence Index

Status: reviewer-facing evidence index for external review.

Last reviewed: 2026-06-04.

This document lists the evidence that should be captured for the reviewer submission package and the truth boundary for each item. It is intentionally conservative: it records what the repository can prove without claiming public mainnet, public multi-validator BFT, or live economics.

## Submission identity

Before submitting, capture these from the actual Git checkout, not from a zip export:

```bash
git rev-parse --abbrev-ref HEAD
git rev-parse HEAD
git status --short
git log --oneline -10
```

Attach or paste the output into the reviewer evidence bundle.

If the repository is being reviewed from a zip/export, note that Git commit identity is unavailable and must be supplied from the source checkout.

## Evidence summary

| Evidence item | Command | Expected result | Truth boundary |
|---|---|---|---|
| Tx canon sync | `python3 -B -S scripts/check_tx_canon_artifacts.py` | Pass; tx canon artifacts synchronized | Proves generated tx artifacts match the repo; does not prove every runtime flow is externally testnet-ready. |
| Secret guard | `bash scripts/secret_guard.sh` | Pass | Scans release-relevant files/tree; does not prove git history has no secrets unless run in the real git checkout/history review. |
| Release tree hygiene | `bash scripts/verify_release_tree.sh` | Pass | Proves no known release-blocking generated/runtime artifacts in the current tree. |
| Dependency locks | `bash scripts/verify_release_dependencies.sh` | Pass | Proves lockfiles are present/pinned/hashed. |
| Reviewer gate | `bash scripts/reviewer_production_readiness_gate.sh` | Pass targeted reviewer suite | Targeted readiness gate, not a public-mainnet proof. |
| Expected reviewer path: same-machine dual-node controlled devnet | `WEALL_DEVNET_SUITE_RUN_TIER2=1 WEALL_DEVNET_SUITE_RUN_LIVE=1 bash scripts/devnet_controlled_readiness_suite.sh` | Pass | Runs a controlled genesis node and joining node on one machine; proves local convergence/restart rehearsal, not public multi-validator adversarial readiness. |
| Targeted backend tests | reviewer gate or targeted `pytest` list | Pass | Bounded suite; full pytest should be run from a clean dependency environment. |
| Frontend install | `cd ../web && npm ci` | Pass, 0 vulnerabilities reported at install time | Creates `node_modules`; remove before release-tree check. |
| Frontend typecheck | `cd ../web && npm run typecheck` | Pass | Type safety only; not browser E2E proof. |
| Account custody source check | `node web/scripts/test_batch469_account_custody_source.mjs` from outer root | Pass | Source-level guard; browser restore E2E is still recommended. |
| Wallet/tipping source check | `node web/scripts/test_batch482_wallet_tipping_source.mjs` from outer root | Pass | Source-level guard; economics remain locked by default. |
| Constitutional procedure UI source check | `node web/scripts/test_constitutional_procedure_ui_source.mjs` from outer root | Pass | Source-level guard; public governance testnet still requires integrated E2E proof. |
| Local observer readiness | `bash scripts/local_observer_readiness_gate.sh` | Pass | Local precondition only; does not prove remote signed observer onboarding. |
| Observer authority lock | `bash scripts/external_observer_authority_lock_gate.sh` | Pass | Proves local observer authority lock posture; does not promote observer to validator. |
| First external observer full proof | `bash scripts/first_external_observer_reproducibility_gate.sh` with remote and signed env enabled | Must pass before claiming first trusted external observer readiness | If remote/signed portions are skipped, the claim remains local-precondition only. |
| Local block-production proof | `PYTHONPATH=src python3 scripts/production_block_production_rehearsal_gate.py` | Pass with root-bearing local block evidence | Local block evidence only; public multi-validator BFT remains future proof. |

## Evidence freshness policy

Evidence in this document must be treated as a command checklist, not as a
permanent transcript archive.

For reviewer submission, capture fresh output from the exact Git commit being submitted. Do not reuse stale audit-export output, sandbox output, or
sample pass counts as proof of the current repository state.

A valid evidence bundle must include:

1. the exact branch and commit hash;
2. clean or explained `git status --short` output;
3. fresh command output from the current checkout;
4. the command that produced each transcript;
5. the truth boundary for each result;
6. a note when a command was skipped, failed, or was run only in a local/sandbox
   environment.

Do not present full pytest, frontend typecheck, remote observer onboarding,
public testnet readiness, public multi-validator BFT readiness, or live
economics as passed unless the matching command has passed on the submitted
commit and the transcript is included.

## Fresh evidence commands

Run these from `Weall-Protocol/` unless noted otherwise.

### Git identity

    git rev-parse --abbrev-ref HEAD
    git rev-parse HEAD
    git status --short
    git log --oneline -10

Truth boundary: proves which commit was tested. It does not prove the commit is
deployed or that later commits share the same evidence.

### Tx canon artifact check

    python3 -B -S scripts/check_tx_canon_artifacts.py

Truth boundary: proves generated tx canon artifacts match the current checkout.
It does not prove every transaction flow is externally testnet-ready.

### Secret guard

    bash scripts/secret_guard.sh

Truth boundary: scans release-relevant files in the current checkout. It does
not replace full git-history secret review.

### Release tree hygiene

    bash scripts/verify_release_tree.sh

Truth boundary: proves no known release-blocking generated/runtime artifacts are
present in the current tree at the time of the check.

### Dependency lock verification

    bash scripts/verify_release_dependencies.sh

Truth boundary: proves backend and frontend dependency lockfiles are present and
pinned for this checkout. It does not prove all dependencies are vulnerability
free forever.

### Reviewer readiness gate

    bash scripts/reviewer_production_readiness_gate.sh

Truth boundary: targeted reviewer gate. It is not a public-mainnet proof and not
a substitute for the specific remote/multi-node/BFT gates.

### Full pytest

    python3 -m venv .venv
    . .venv/bin/activate
    python3 -m pip install -r requirements-dev.lock
    PYTHONPATH=src pytest

Truth boundary: may be claimed only when the command passes on the submitted
commit and the full transcript is captured. If the command is skipped, partially
run, or fails due to environment/dependency issues, say so explicitly.

### Frontend install and typecheck

Run from the outer repository root:

    cd web
    npm ci
    npm run typecheck

After frontend checks, remove generated frontend artifacts before release hygiene
checks:

    rm -rf node_modules dist tsconfig.tsbuildinfo

Truth boundary: type safety only. This is not browser E2E proof for account
recovery, PoH, content, dispute/review, governance, or wallet flows.

### Same-machine dual-node controlled-devnet proof

    WEALL_DEVNET_SUITE_RUN_TIER2=1 \
    WEALL_DEVNET_SUITE_RUN_LIVE=1 \
    bash scripts/devnet_controlled_readiness_suite.sh

Truth boundary: runs a controlled genesis node and joining node on one machine, exercises native async/live PoH and convergence/restart behavior through protocol paths, and intentionally avoids `/v1/dev/demo-seed`. It does not prove public multi-validator adversarial readiness.

### Local observer readiness

    bash scripts/local_observer_readiness_gate.sh

Truth boundary: local precondition only. It does not prove remote signed observer
onboarding.

### Observer authority lock

    bash scripts/external_observer_authority_lock_gate.sh

Truth boundary: proves local observer authority-lock posture. It does not
promote the observer to validator and does not prove public network safety.

### Disposable reviewer Genesis and artifact-pull rehearsal

Genesis machine:

    bash scripts/reviewer_lan_genesis_rehearsal.sh \
      --lan-ip <GENESIS_LAN_IP> \
      --wsl-ip <WSL_OR_LOCAL_IP>

Observer machine:

    bash scripts/reviewer_observer_rehearsal.sh \
      --genesis-api-base http://<GENESIS_LAN_IP>:8000 \
      --pull-reviewer-artifacts \
      --allow-private-genesis-api

Truth boundary: controlled LAN/reviewer rehearsal only. It does not prove public
mainnet readiness, public multi-validator BFT readiness, live economics, or a
public HTTPS deployment.

### Local block-production proof

    PYTHONPATH=src python3 scripts/production_block_production_rehearsal_gate.py

Truth boundary: local block evidence only. Public multi-validator BFT remains a
separate adversarial proof.

## Required before claiming first trusted external observer readiness

Run the following against a real genesis API and public observer bundle:

```bash
export WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE=/path/to/public-observer-bundle.json
export WEALL_CHAIN_MANIFEST_PATH=/path/to/weall-genesis.json
export WEALL_GENESIS_API_BASE=http://GENESIS_HOST:8000
export WEALL_ALLOW_PRIVATE_GENESIS_API=1
export WEALL_RUN_TWO_MACHINE_OBSERVER_PREFLIGHT=1
export WEALL_RUN_SIGNED_OBSERVER_ONBOARDING=1
bash scripts/first_external_observer_reproducibility_gate.sh "$WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE"
```

If either remote preflight or signed onboarding is skipped, say:

> Local observer preconditions passed. First trusted external observer readiness is not claimed yet because the remote signed observer onboarding proof has not been captured.

## Required before claiming public observer testnet readiness

- One clean-clone tester boot transcript.
- One real signed observer onboarding transcript.
- One remote sync/readiness transcript.
- One frontend account/recovery/onboarding proof.
- One PoH async/live proof.
- One content/group proof after tier unlock.
- One report/dispute/review/finalization proof.
- One governance proposal/comment/vote/finalization proof.
- Public deployment boundary docs: HTTPS, CORS, operator tokens, rate limits, request sizes, known limits, and reporting path.

## Required before claiming public multi-validator BFT readiness

- Multi-validator HotStuff/BFT convergence proof.
- Validator promotion proof.
- Equivocation/adversarial validator tests.
- Partition/rejoin tests.
- Restart/replay deterministic convergence tests.
- State-root equality across validators.
- Long-running soak evidence.

## Required before claiming live economics

- Governance-approved economics activation path.
- Proof that activation cannot bypass the Genesis lock.
- Activated test-state accounting proof.
- Reward mint/distribution conservation proof.
- Treasury authorization proof.
- UI truth-sync for locked, unknown, pending, and confirmed states.
- Confirmation that civic/social/governance actions remain fee-free.

## Recommended evidence archive layout

Use this folder layout outside runtime state and attach it to the reviewer package or keep it as reviewer support material:

```text
audit-metadata/reviewer-evidence-YYYY-MM-DD/
  00_git_identity.txt
  01_tx_canon.txt
  02_secret_guard.txt
  03_release_tree.txt
  04_dependencies.txt
  05_reviewer_gate.txt
  06_frontend_typecheck.txt
  07_local_observer_readiness.txt
  08_observer_authority_lock.txt
  09_block_production_proof.txt
  10_first_external_observer_remote_signed.txt
  11_known_limitations_snapshot.md
  12_truth_boundary_snapshot.md
```

Only include `10_first_external_observer_remote_signed.txt` after the remote signed proof has actually passed.

## v1.5 public-readiness evidence and guardrails

The following artifacts were added to keep the full-scope v1.5 audit aligned with current code without overclaiming public beta, public BFT, live economics, automatic upgrades, or legal approval.

| Evidence item | Command | Expected result | Truth boundary |
|---|---|---|---|
| v1.5 implementation evidence map | `cat docs/V15_IMPLEMENTATION_EVIDENCE_MAP.md` | Current resolved/gap map is present | Planning/evidence artifact only. |
| v1.5 gap register | `cat generated/v15_implementation_gap_register.json` | Recent tokenomics/runtime config drift marked resolved; remaining P0/P1 gaps listed | Does not prove the gaps are closed unless status says resolved. |
| API contract map | `python3 scripts/gen_api_contract_map.py && pytest tests/test_batch494_api_contract_map_v15.py` | Generated route inventory is deterministic and complete for current public route decorators | Static map only; response schema vector pack remains future work. |
| Launch-disabled matrix | `pytest tests/test_batch495_launch_disabled_matrix_v15.py` | High-risk features remain disabled across current phases | Matrix is a guardrail; apply/admission code remains authoritative. |
| Protocol-upgrade record-only boundary | `pytest tests/test_batch496_protocol_upgrade_record_only_boundary.py` | Upgrade txs record metadata and expose no auto-apply/migration/rollback execution | Automatic protocol upgrades are not implemented. |
| Legal/compliance draft pack | `pytest tests/test_batch497_public_readiness_artifacts_v15.py` | Counsel-review-pending docs are present | Non-lawyer draft only, not legal approval. |
| Public validator/BFT proof plan | `cat docs/public_validator/PUBLIC_VALIDATOR_BFT_PROOF_PLAN.md` | Required public-validator adversarial proof matrix exists | Plan only; public multi-validator readiness is not claimed. |

### Batch 626 public observer discovery note

Public observer launch evidence now requires the fail-closed seed registry flow documented in `PUBLIC_OBSERVER_TESTNET_QUICKSTART.md`, recovery guidance in `PUBLIC_TESTNET_NAT_FIREWALL_TLS_RECOVERY.md`, and external transcript capture from `PUBLIC_OBSERVER_EVIDENCE_RUNBOOK.md`. A public observer can be open-download only after real public seed URLs and pinned commitments are configured; validator activation remains protocol-gated.
