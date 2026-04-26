# Local Tester Runbook

This runbook is the operator-facing version of the external tester quickstart.

## Canonical conference/demo path

For live review, prefer the repository root full-stack boot path:

```bash
./scripts/dev_boot_full_stack.sh
```

That path starts the backend, runs the deterministic demo bootstrap, writes the frontend bootstrap manifest, and starts the Vite frontend.

## Manual split path

Use this sequence when you want the backend, frontend, and demo bootstrap in separate terminals:

1. from the repository root run `./scripts/quickstart_tester.sh`
2. from `web/` run the Vite frontend
3. from `Weall-Protocol/` run `./scripts/demo_bootstrap_tester.sh`

## Commands

Backend from the repository root:

```bash
./scripts/quickstart_tester.sh
```

Frontend in a second terminal:

```bash
cd web
cp .env.example .env.local
npm ci
npm run dev -- --host 127.0.0.1 --port 5173
```

Demo bootstrap in a third terminal:

```bash
cd Weall-Protocol
./scripts/demo_bootstrap_tester.sh
```

## Non-seeded controlled-devnet readiness proof

Use this path when the reviewer wants to see protocol-native onboarding and cross-node convergence without seeded demo state:

```bash
cd Weall-Protocol
source .venv/bin/activate

pytest -q
WEALL_EMAIL="you@example.com" \
WEALL_DEVNET_SUITE_RUN_TIER2=1 \
WEALL_DEVNET_SUITE_RUN_TIER3=1 \
bash scripts/devnet_controlled_readiness_suite.sh
```

This proof covers direct API permission gating, fresh account registration, Tier-1 email PoH, joining-node trusted-anchor sync, cross-node account and tx-status parity, a Tier-1-gated node-2 transaction, node-1 catch-up from node 2, Tier-2 async PoH review, Tier-3 protocol-native live PoH review, final cross-node convergence, and restart/catch-up.

## Verification

Check all of the following:

- `curl http://127.0.0.1:8000/v1/readyz`
- `curl http://127.0.0.1:8000/v1/status`
- open `http://127.0.0.1:8000/docs`
- open `http://127.0.0.1:5173`
- confirm the printed demo post appears in the feed
- confirm the printed demo account appears in the UI

## Notes

- the deterministic demo bootstrap is the fastest reviewer path
- the controlled-devnet readiness suite is the deeper protocol-native path
- email-oracle onboarding remains optional for general testers, but it is now documented and testable through `scripts/devnet_controlled_readiness_suite.sh` and `scripts/devnet_full_onboarding_e2e.sh`
- `generated/tx_index.json` is created automatically by the backend helper
- founder-local files must be removed before release with `Weall-Protocol/scripts/clean_local_artifacts.sh`
