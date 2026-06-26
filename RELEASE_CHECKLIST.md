# External Tester Release Checklist

Use this checklist before publishing the repository for external testers.


## Reviewer-surface hygiene gate

Before sending the repository to reviewers or operators, run the lightweight presentation and release-hygiene gate from a clean checkout:

```bash
cd Weall-Protocol
PYTHONPATH=src python -m compileall -q src/weall
bash scripts/secret_guard.sh
PYTHONPATH=src python scripts/check_v15_public_readiness_artifacts.py
PYTHONPATH=src python scripts/check_release_hygiene_v1_5.py
PYTHONPATH=src python -m pytest -q tests/test_public_only_protocol_redesign.py
cd ../web
npm run -s test:public-only-protocol-source
```

A passing hygiene gate means the checked-in release evidence is fresh, public-only frontend/backend source contracts still hold, and release-relevant tracked files do not include obvious secrets. It does not prove public mainnet readiness, economic activation readiness, or external security-audit completion.

Reviewer entrypoints:

- `README.md` for the current posture and safe first commands;
- `Weall-Protocol/docs/GENERATED_ARTIFACTS.md` for generated evidence governance;
- `Weall-Protocol/docs/ARCHITECTURE_DECISIONS/` for public-only and operator-safety decisions;
- `Weall-Protocol/docs/PROFESSIONALIZATION_BACKLOG.md` for known batch-era and oversized-module cleanup that should not be hidden.


## Public observer testnet launch gate

Before publishing an open-download public observer testnet build, verify all of the following from a clean clone:

- `pip install -r requirements.lock` succeeds before `pip install -e .`; this keeps PyNaCl/cryptography dependencies present for signed observer and registry tests.
- `WEALL_PUBLIC_TESTNET=1` is set.
- The public seed registry is found through the default bundled path or `WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PATH`.
- `WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PUBKEY` or `WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PUBKEYS` pins the expected registry signer.
- `/v1/nodes/seeds` reports `seed_registry_signature_status.verified: true`.
- `/v1/nodes/validators` reports active validators from protocol state and verified endpoint counts from signed endpoint advertisements.
- The net loop peer store contains registry seed P2P URIs and signed validator P2P URIs; unsigned hints must not be auto-dialed.
- `/v1/observer/edge/status` is visible in the local frontend and clearly separates local tx queue state from upstream acceptance and confirmation.
- A process-level startup test proves validator/BFT loops are not constructed when raw env requests signing but the runtime authority contract does not make validator authority effective.
- Public warnings are visible: resettable testnet, non-economic balances, open observer access, protocol-gated validator activation, no persistence guarantee across resets.

Targeted gate command:

```bash
cd Weall-Protocol
source .venv/bin/activate
PYTHONPATH=src:scripts python -m pytest -q \
  tests/prod/test_public_observer_default_registry_and_placeholder_gate.py \
  tests/prod/test_public_observer_seed_discovery.py \
  tests/prod/test_public_validator_endpoint_discovery.py \
  tests/prod/test_public_observer_tx_upstream_from_verified_seeds.py \
  tests/prod/test_public_observer_registry_auto_dial.py \
  tests/prod/test_public_testnet_v1_chain_identity.py \
  tests/prod/test_public_observer_boot_and_evidence_scripts.py \
  tests/prod/test_public_observer_launch_transcript_artifacts.py \
  tests/prod/test_observer_cannot_enable_validator_signing.py \
  tests/test_api_startup_authority_contract.py
PYTHONPATH=src:scripts python scripts/gen_public_observer_launch_evidence_requirements_v1_5.py --check
PYTHONPATH=src:scripts python scripts/gen_public_observer_launch_transcript_v1_5.py --check
PYTHONPATH=src:scripts python scripts/gen_public_validator_endpoint_churn_proof_v1_5.py --check
PYTHONPATH=src:scripts python scripts/gen_public_frontend_operator_journey_v1_5.py --check
PYTHONPATH=src:scripts python scripts/gen_public_registry_signer_operations_v1_5.py --check
cd ../web
npm run typecheck
node scripts/test_node_dashboard_source.mjs
node scripts/test_node_connection_manager_source.mjs
```

Runtime launch transcript command, after publishing the real signed registry and seed API:

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

## 0. Fresh clone validation

Before publishing, validate from a clean directory that does not contain founder-local state. For public observer testnet readiness, the clean-clone path is:

```bash
git clone <repo-url> weall-fresh-test
cd weall-fresh-test/Weall-Protocol
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.lock
pip install -e .
WEALL_PUBLIC_TESTNET=1 bash scripts/boot_public_observer_testnet.sh
```

For the local demo/reviewer path, `./scripts/quickstart_tester.sh`, frontend `npm ci`, and `./scripts/demo_bootstrap_tester.sh` remain useful, but they are not substitutes for the public observer boot script and signed registry checks. Do not treat an in-place founder checkout as sufficient validation.

## 1. Clean founder-local artifacts

Run:

```bash
cd Weall-Protocol
./scripts/clean_local_artifacts.sh
```

Confirm none of these are staged:

- `Weall-Protocol/.env`
- `Weall-Protocol/.venv*`
- `Weall-Protocol/data/`
- `Weall-Protocol/generated/` runtime leftovers
- `Weall-Protocol/secrets/*`
- `web/.env.local`
- `.weall-dev/`
- `Weall-Protocol/.weall-devnet/`

## 2. Verify canonical startup path still works

Preferred full-stack path from the repository root:

```bash
./scripts/dev_boot_full_stack.sh
```

Manual backend path from the repository root:

```bash
./scripts/quickstart_tester.sh
```

Frontend, with the backend running at `http://127.0.0.1:8000` for contract verification:

```bash
cd web
cp .env.example .env.local
npm ci
npm run typecheck
API_BASE=http://127.0.0.1:8000 npm run contract-check
npm run build
npm run dev -- --host 127.0.0.1 --port 5173
```

Demo bootstrap:

```bash
cd Weall-Protocol
./scripts/demo_bootstrap_tester.sh
```

Controlled-devnet same-machine non-seeded readiness proof:

```bash
cd Weall-Protocol
source .venv/bin/activate

pytest -q
WEALL_DEVNET_SUITE_RUN_TIER2=1 \
WEALL_DEVNET_SUITE_RUN_LIVE=1 \
bash scripts/devnet_controlled_readiness_suite.sh
```

## 3. Verify browser-visible demo

Confirm all of the following:

- `http://127.0.0.1:8000/v1/readyz` returns success
- `http://127.0.0.1:8000/docs` loads
- `http://127.0.0.1:5173` loads
- the printed demo account exists in the UI
- the printed demo post body is visible in the feed

## 4. Verify documentation matches reality

Check that these files all describe the same startup path and current proof posture:

- `README.md`
- `Weall-Protocol/README.md`
- `Weall-Protocol/docs/testnet_runbook.md`

The root README should only reference files that are actually tracked in this repository.

## 5. Verify environment templates are present

Confirm these files exist and are current:

- `Weall-Protocol/configs/production.env.example`
- `web/.env.example`

Local override files such as `.env`, `Weall-Protocol/.env`, and `web/.env.local` should remain untracked.

## 6. Verify public trust files are present

Confirm these files exist before broad external review:

- `LICENSE`
- `SECURITY.md`
- `CONTRIBUTING.md`
- `CODE_OF_CONDUCT.md`

## 7. Verify CI coverage

Confirm the repository has active GitHub Actions coverage for:

- backend lint, dependency audit, lockfile verification, canon lint, generated-artifact check, tx coverage report, and pytest
- web `npm ci`, typecheck, contract check, and production build using committed `web/package-lock.json`
- Native async/live PoH checks, including no required email, SMTP, DNS, named hosting-provider, input_queue, or external identity provider path

## 8. Known release policy

For external testers, the supported walkthrough is:

- backend via Docker Compose
- frontend via Vite dev server
- demo state via `scripts/demo_bootstrap_tester.sh` or the repository root `scripts/dev_boot_full_stack.sh`

For protocol reviewers, the expected non-seeded readiness proof is:

- `Weall-Protocol/scripts/devnet_controlled_readiness_suite.sh` for the same-machine dual-node controlled-devnet proof
- `Weall-Protocol/scripts/devnet_full_onboarding_e2e.sh` for the fuller onboarding path

Browser onboarding and PoH verification are named-provider-free, email-free, and routed through the active WeAll API plus native async/live PoH surfaces. The controlled-devnet proof is the preferred same-machine reviewer rehearsal because it runs a controlled genesis node and a joining node without using the seeded demo shortcut. The default general tester flow may still use deterministic demo bootstrap for speed.

## 9. Current validated checkpoint

The current release checkpoint for this snapshot is:

- recorded full backend suite checkpoint: `3636 passed, 3 warnings`; rerun locally before release and update evidence before making a fresh claim
- tx canon artifacts: `234 tx types, version 1.25.0`
- production consensus profile: `2026.03-prod.6` / `7f014fb5ff451081b56cc1bd818a820cf7460c00be854adfb6118f082032a991`
- `scripts/secret_guard.sh`: passed
- `scripts/verify_release_tree.sh`: passed
- `scripts/verify_release_dependencies.sh`: passed
- backend locks: `requirements.lock` and `requirements-dev.lock` are present, pinned, and hashed
- frontend lock: `web/package-lock.json` is present and `npm ci`/typecheck/contract/build were verified
- Native PoH cleanup: primary path validated without email, SMTP, DNS, named hosting-provider, relay-token completion, or external identity-provider env aliases
- Public-validator posture: validator service/signing requires BFT enabled; observer mode and signing cannot be mixed
- Public API posture: snapshots and unauthenticated account reads redact sensitive session/device/evidence internals
- SYSTEM tx posture: follower-side block replay rejects mutating SYSTEM txs that do not match deterministic scheduler output
- Helper posture: helper execution metadata is committed by `helper_execution_root` when present

Before publishing, rerun:

```bash
cd Weall-Protocol
source .venv/bin/activate
pytest
python3 -S scripts/check_tx_canon_artifacts.py
bash scripts/secret_guard.sh
bash scripts/verify_release_tree.sh
bash scripts/verify_release_dependencies.sh
```

<!-- WEALL_RELEASE_TRUTH_CHECKPOINT_START -->
## Release truth checkpoint

- Current transaction canon checkpoint: **234 transaction types**, canon version **1.25.0**.
- Proof-of-Humanity model: **Tier 0 = account only**, **Tier 1 = native async verified human**, **Tier 2 = native live verified human**.
- Live PoH uses adaptive integer quorum with up to **10 jurors**, up to **3 active reviewers**, and up to **7 watchers**.
- There is no required user-facing Tier 3.
- No required email, SMTP, DNS, or named hosting provider is part of PoH authority.
- Production validator posture must **fail closed** unless BFT is enabled and effective for validator/service signing.
- Production tx payload limits are **profile-pinned** and local payload env overrides must not change consensus validity.
- Public API redaction is required for public snapshots and unauthenticated account reads.
- SYSTEM txs received in blocks must be scheduler-bound before apply.
- Helper execution metadata is committed by `helper_execution_root` when present.
- Release safety requires tx canon artifact verification, secret guard, release tree verification, and dependency-lock verification.
<!-- WEALL_RELEASE_TRUTH_CHECKPOINT_END -->


## Clean external tester export

From the outer repository root, build the clean staged release archive:

```bash
bash scripts/build_clean_release_export.sh
```

This is the preferred external-tester packaging gate because it includes the backend, frontend, and top-level scripts while excluding runtime/cache/build artifacts from a staged copy.


## Public beta evidence boundary

Current release posture remains: controlled multi-node testnet candidate.
Do not claim public beta, mainnet, public validator enablement, live economics,
production helper execution, public storage-market readiness, or legal/compliance
readiness until the external transcript requirements in
`Weall-Protocol/generated/external_operator_transcript_requirements_v1_5.json`
and `Weall-Protocol/docs/PUBLIC_BETA_EXTERNAL_EVIDENCE_RUNBOOK.md` are satisfied.

## Public observer discovery gate

Before any public observer testnet announcement:

- [ ] `WEALL_PUBLIC_TESTNET=1` finds a real signed registry through a default path such as `Weall-Protocol/configs/public_testnet_seed_registry.json`, or through `WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PATH`.
- [ ] Public seed registry contains pinned chain/genesis/profile commitments, has no placeholder values, and passes `scripts/sign_public_seed_registry_v1_5.py --check`.
- [ ] Public frontend build sets `VITE_WEALL_PUBLIC_TESTNET=true` and all expected commitment env values.
- [ ] `/v1/nodes/seeds` returns public commitments and verified seeds.
- [ ] `/v1/nodes/validators` separates protocol-active validators from endpoint hints.
- [ ] Observer tx forwarding uses explicit or verified seed-derived upstreams, otherwise fails with `PUBLIC_TESTNET_NO_VERIFIED_TX_UPSTREAM`.
- [ ] Public warning copy states resettable, non-economic, no real-world value, and no persistence reliance.
- [ ] External clean-clone observer evidence is captured using `Weall-Protocol/docs/PUBLIC_OBSERVER_EVIDENCE_RUNBOOK.md` and the tracked gates in `generated/public_observer_launch_evidence_requirements_v1_5.json`.

Current tx canon checkpoint: 234 tx types, version 1.25.0.
