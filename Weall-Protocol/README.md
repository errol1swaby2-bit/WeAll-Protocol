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

## Controlled-devnet onboarding proof

For protocol-review sessions, the backend also includes a non-seeded two-node onboarding proof:

```bash
cd Weall-Protocol
source .venv/bin/activate

PYTHONPATH=src pytest -q tests/test_devnet_email_tier1_harness_batch210.py
WEALL_EMAIL="you@example.com" bash scripts/devnet_full_onboarding_e2e.sh
```

This flow uses normal public transaction submission paths. It auto-starts a controlled genesis node and a joining node, resets stale controlled-devnet state when auto-starting, creates a fresh account, verifies Tier-1 email PoH through an opaque commitment, syncs node 2, submits a Tier-1-gated action from node 2, syncs node 1 back from node 2, then completes Tier-2 async PoH and proves both nodes converge on the same tip and state root.

This script intentionally never calls `/v1/dev/demo-seed`.

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

## Backend dependency audit result

The runtime dependency set in `requirements.in` is almost complete, but one direct import used by the backend was missing from the runtime requirements list:

- `python-dotenv`

The backend imports it through `src/weall/env.py` when `.env` loading is enabled, so it should be treated as a first-class runtime dependency rather than an accidental transitive dependency.

## Runtime posture summary

This repository currently targets:

- HotStuff-style BFT finality
- deterministic execution
- fail-closed startup posture
- deterministic mempool and block application rules
- helper execution strictly subordinate to canonical consensus
- explicit bootstrap-registration to production-service promotion

## Local cleanup

To scrub local runtime artifacts before packaging or pushing:

```bash
./scripts/clean_local_artifacts.sh
```
