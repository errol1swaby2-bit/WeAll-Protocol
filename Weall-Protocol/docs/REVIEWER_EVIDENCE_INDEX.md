# WeAll reviewer Evidence Index

Status: funder-facing evidence index for reviewer submission.

Last reviewed: 2026-05-29.

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

## Captured command results from latest audit export

These results were captured from the 2026-05-29 audit export environment. Re-run them in the actual Git checkout before final submission and replace this section with fresh commit-bound output.

### Tx canon artifact check

```text
✅ tx canon artifacts are synchronized (231 tx types, version 1.25.0)
```

### Secret guard

```text
[secret-guard] scanning release-relevant files…
[secret-guard] WARN: not a git work tree; scanning exported tree instead.
[secret-guard] OK
```

In the real Git checkout, the warning should disappear or be replaced by git-aware scanning output.

### Release tree hygiene

```text
[verify] repo: /mnt/data/weall_audit/Weall-Protocol
[verify] OK: no Python bytecode files
[verify] OK: no __pycache__ directories
[verify] OK: no .pytest_cache directories
[verify] OK: no Python egg-info directories
[verify] OK: no TypeScript build info files
[verify] OK: no node_modules directories
[verify] OK: no frontend dist directories
[verify] OK: no outer web TypeScript build info files
[verify] OK: no outer web node_modules directories
[verify] OK: no outer web dist directories
[verify] OK: outer web package script targets exist
[verify] OK: no provider local state directories
[verify] OK: no .env files
[verify] OK: no .env.local files
[verify] OK: no secrets directory present
[verify] OK: no local devnet runtime directories
[verify] OK: no local WeAll runtime directories
[verify] OK: no runtime data directories
[verify] OK: no SQLite database files
[verify] OK: no SQLite WAL files
[verify] OK: no SQLite shared-memory files
[verify] OK: no SQLite files
[verify] OK: no JSON secret artifacts
[verify] OK: no demo bootstrap result artifacts
[verify] OK: no aux sqlite files
[verify] OK: no BFT journal jsonl files
[verify] OK: no helper lane temp directories
[verify] OK: found generated/tx_index.json
[verify] OK: found generated/helper_contract_map.json
[verify] OK: found generated/tx_contract_map.json
✅ tx canon artifacts are synchronized (231 tx types, version 1.25.0)
[verify] OK: tx canon generated artifacts are synchronized
[verify] release tree check passed
```

### Dependency lock verification

```text
OK: lockfiles are present, pinned, and hashed.
[deps] OK: backend and frontend release dependency locks are present
```

### Targeted backend reviewer tests

```text
93 passed in 20.31s
```

A later targeted reviewer-gate run from the export showed the split reviewer target set passing as:

```text
66 passed in 17.84s
2 passed in 0.53s
1 passed in 0.51s
2 passed in 0.46s
1 passed in 0.44s
1 passed in 0.47s
```

### Full pytest truth boundary

A plain full pytest run in the audit sandbox did not complete because the sandbox environment did not have `nacl` importable:

```text
ModuleNotFoundError: No module named 'nacl'
```

This should be handled in the real checkout by creating a clean dependency environment first:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.lock
PYTHONPATH=src pytest
```

Do not present full pytest as passed unless this command has passed in the actual checkout.

### Frontend clean install and typecheck

```text
added 77 packages, and audited 78 packages in 10s
found 0 vulnerabilities

> weall-web@0.1.0 typecheck
> tsc -b --pretty false
```

After running frontend checks, remove generated frontend artifacts before release hygiene checks:

```bash
rm -rf ../web/node_modules ../web/dist ../web/tsconfig.tsbuildinfo
```

### Local observer readiness

```text
OK: local observer bundle is public-only and observer-safe
OK: local observer readiness gate passed
- tx canon synchronized
- production chain manifest pinned
- public observer bundle generated and verified
- observer preflight forces observer-only mode
- validator signing, BFT, helper authority, and block loop are disabled
- no authority, validator, node private key, external identity-provider, or legacy oracle secret is required

This is not a substitute for scripts/rehearse_external_observer_two_machine.sh.
It is the local precondition that should pass before the real second-machine rehearsal.
```

### External observer authority lock

```text
OK: external observer authority lock gate passed
- production preflight accepted the manifest and rejected authority secrets
- observer mode is forced on
- validator signing, BFT, helper mode, and block-loop autostart are forced off
- validator/service authority roles are absent from the local observer environment
```

### Local block-production proof

```text
OK: local block-production proof {
  'ok': True,
  'has_committed_block': True,
  'height': 1,
  'has_root_evidence': True,
  'state_ancestry_only': False,
  'claim': 'Latest committed local block evidence only; public multi-validator BFT still requires a separate adversarial proof.',
  'readiness': {
    'ok': True,
    'height': 1,
    'mode': 'dev',
    'observer_mode': False,
    'block_loop': {
      'running': True,
      'unhealthy': False,
      'last_error': '',
      'consecutive_failures': 0
    },
    'authority': {
      'validator_signing_enabled': True,
      'bft_enabled': False,
      'observer_cannot_produce': False
    },
    'can_locally_produce': True,
    'production_profile_candidate': False,
    'public_multi_validator_bft_ready': False,
    'claim': 'This is read-only block production posture evidence. It does not grant authority or prove public multi-validator BFT.'
  }
}
```

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
audit-metadata/reviewer-resubmission-YYYY-MM-DD/
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
