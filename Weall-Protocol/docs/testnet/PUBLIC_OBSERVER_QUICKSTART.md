# Public Observer Quickstart

This quickstart is for a bounded public-observer rehearsal candidate. It is not a public beta, mainnet, public validator, live-economics, automatic-upgrade, or production-helper launch guide.

## 1. Clean clone

```bash
git clone <repo-url> WeAll-Protocol
cd WeAll-Protocol/Weall-Protocol
```

Record:

```bash
git rev-parse HEAD
git branch --show-current
git status --short --untracked-files=all
```

## 2. Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.lock
pip install -e .
```

## 3. Verify repository-side gates

```bash
PYTHONPATH=src:scripts python scripts/gen_final_public_observer_controlled_testnet_go_gate_v1_5.py --check
PYTHONPATH=src:scripts python scripts/gen_public_beta_blocker_report_v1_5.py --check
PYTHONPATH=src python scripts/check_v15_public_readiness_artifacts.py
PYTHONPATH=src python scripts/check_release_hygiene_v1_5.py
```

Expected boundary: `public_beta_ready=false` and final go-gate verdict `GO` only for controlled internal/public-observer rehearsal candidate.

## 4. Boot observer mode

```bash
export WEALL_MODE=prod
export WEALL_API_MODE=node
export WEALL_OBSERVER_MODE=1
export WEALL_OBSERVER_EDGE_MODE=1
export WEALL_PUBLIC_TESTNET=1
export WEALL_CHAIN_MANIFEST_PATH=./configs/chains/weall-testnet-v1.json
export WEALL_CHAIN_ID=weall-testnet-v1

bash scripts/boot_public_observer_testnet.sh
```

## 5. Capture status evidence

In another shell:

```bash
curl -s http://127.0.0.1:8000/v1/status | python3 -m json.tool
curl -s http://127.0.0.1:8000/v1/chain/identity | python3 -m json.tool
curl -s http://127.0.0.1:8000/v1/nodes/seeds | python3 -m json.tool
curl -s http://127.0.0.1:8000/v1/nodes/validators | python3 -m json.tool
curl -s http://127.0.0.1:8000/v1/observer/edge/status | python3 -m json.tool
```

## 6. Frontend check

```bash
cd ../web
npm install
npm run typecheck
npm run build
```

Open the frontend and capture the first-run journey using `docs/testnet/FIRST_15_MINUTES.md`.

## 7. Evidence warning

This local quickstart does not close `AUD-628-P1-001`. Closure requires the external open-download transcript package described in `docs/testnet/PUBLIC_OBSERVER_OPEN_DOWNLOAD_TRANSCRIPT.md`.

## Go/no-go boundary

GO: controlled internal/public-observer rehearsal candidate.

NO-GO: public beta readiness, public mainnet readiness, public validator safety, live economics readiness, automatic protocol upgrade readiness, production helper execution readiness, legal/compliance approval, and public storage-market readiness.
