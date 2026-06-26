# WeAll Protocol Backend

This directory contains the backend node, runtime, API, Docker Compose stack, tests, and backend-facing scripts for the current WeAll local tester flow.

## Backend purpose in the dev flow

The backend quickstart is responsible for:

- generating the canonical tx index
- bringing up Kubo, the API, and the producer stack
- exposing readiness and status surfaces
- supporting the deterministic demo bootstrap
- serving the frontend against a real local node

## Canonical backend quickstart

From the repository root:

```bash
./scripts/quickstart_tester.sh
```

From this backend directory:

```bash
./scripts/quickstart_tester.sh
```

That helper should:

- verify required local ports are available
- create local runtime directories
- generate `generated/tx_index.json`
- start `docker compose up -d --build`
- wait for API readiness
- print the main health and operator URLs

## Canonical all-in-one dev flow

Most testers should use the repository root full-stack command instead:

```bash
cd ..
./scripts/dev_boot_full_stack.sh
```

That root-level flow wraps backend startup, demo bootstrap, frontend startup, and local session bootstrap into one path.

## Recorded verification snapshot

This backend snapshot includes the following recorded checkpoint. Rerun the release gates before making a fresh readiness claim:

- **Transaction canon:** 234 tx types, version 1.25.0
- **Recorded full backend test checkpoint:** 3,636 passed, 3 warnings


## Expected reviewer path: controlled-devnet same-machine readiness proof

For protocol-review sessions, the expected backend path is the existing non-seeded dual-node controlled-devnet readiness suite that runs on one machine:

```bash
cd Weall-Protocol
source .venv/bin/activate

pytest -q
WEALL_DEVNET_SUITE_RUN_TIER2=1 \
WEALL_DEVNET_SUITE_RUN_LIVE=1 \
bash scripts/devnet_controlled_readiness_suite.sh
```

This flow uses normal public transaction submission paths. It verifies direct API permission gating, auto-starts a controlled genesis node and a joining node on the same machine, resets stale controlled-devnet state when auto-starting, creates a fresh account, verifies Tier-1 native async PoH through protocol commitments, syncs node 2, submits a Tier-1-gated action from node 2, syncs node 1 back from node 2, completes Tier-2 live PoH, proves both nodes converge on the same tip and state root, and verifies restart/catch-up.

The readiness suite intentionally never calls `/v1/dev/demo-seed`.

## Important URLs

When the backend is healthy, these should work:

- `http://127.0.0.1:8000/v1/readyz`
- `http://127.0.0.1:8000/v1/status`
- `http://127.0.0.1:8000/docs`

## Docker diagnostics

```bash
docker compose ps
docker compose logs weall_api --tail 200
docker compose logs weall_producer --tail 200
docker compose logs kubo --tail 200
docker inspect weall-protocol-weall_api-1 --format '{{json .State.Health}}'
```

## Useful backend checks

```bash
bash scripts/api_smoke.sh
python scripts/check_generated.py
```

## Deterministic demo bootstrap

After the backend is ready, the canonical demo bootstrap is:

```bash
./scripts/demo_bootstrap_tester.sh
```

It writes:

- `generated/demo_bootstrap_result.json`

That artifact is then used by the root dev flow to create `web/public/dev-bootstrap.json` for the frontend.

## Environment expectations

The local tester path assumes these effective values:

- `WEALL_MODE=dev`
- `WEALL_CHAIN_ID=weall-dev`
- `WEALL_POH_BOOTSTRAP_OPEN=1`
- `WEALL_IPFS_API_BASE=http://kubo:5001`
- `WEALL_ALLOW_UNSIGNED_TXS=0`

The Compose stack provides these defaults for the local quickstart.

## Backend dependency note

The backend declares `python-dotenv` as a direct runtime dependency because `src/weall/env.py` supports `.env` loading. Keeping this dependency explicit avoids relying on accidental transitive installs in fresh clones, CI, or tester environments.

Release dependency locks are now part of the public packaging contract:

- `requirements.lock`
- `requirements-dev.lock`
- `../web/package-lock.json`

Before publishing operator-facing changes, run:

```bash
bash scripts/verify_lockfiles.sh
bash scripts/verify_release_dependencies.sh
```

## Runtime posture summary

This repository currently targets:

- HotStuff-style BFT finality
- deterministic execution
- fail-closed startup posture
- deterministic mempool, scheduler-bound SYSTEM tx replay, and block application rules
- controlled-devnet onboarding and convergence proof paths
- helper execution strictly subordinate to canonical consensus and committed through `helper_execution_root` when helper metadata is present
- explicit bootstrap-registration to production-service promotion

## Local cleanup

To scrub local runtime artifacts before packaging or pushing:

```bash
./scripts/clean_local_artifacts.sh
```

<!-- WEALL_RELEASE_TRUTH_CHECKPOINT_START -->
## Release truth checkpoint

- Current transaction canon checkpoint: **234 transaction types**, canon version **1.25.0**.
- Latest full backend test checkpoint: **3636 passed, 3 warnings**.
- Proof-of-Humanity model: **Tier 0 = account only**, **Tier 1 = native async verified human**, **Tier 2 = native live verified human**.
- Live PoH uses adaptive integer quorum with up to **10 jurors**, up to **3 active reviewers**, and up to **7 watchers**.
- There is no required user-facing Tier 3.
- No required email, no required SMTP, no required DNS, and no required named hosting provider are part of PoH authority.
- Production validator posture must **fail closed** unless BFT is enabled and effective for validator/service signing.
- SYSTEM txs received in blocks must be scheduler-bound before apply.
- Helper execution metadata is committed by `helper_execution_root` when present.
- Production tx payload limits are **profile-pinned** and local payload env overrides must not change consensus validity.
- Public API redaction is required for public snapshots and unauthenticated account reads.
- Release safety requires tx canon artifact verification, secret guard, release tree verification, and dependency-lock verification.
- Release/export safety now fails closed on raw `secrets/` material; external testers must receive only public manifests and public observer bundles, never local node keys.
<!-- WEALL_RELEASE_TRUTH_CHECKPOINT_END -->

Current tx canon checkpoint: 234 tx types, version 1.25.0.
