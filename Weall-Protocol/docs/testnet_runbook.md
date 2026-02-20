# WeAll Protocol — Testnet / Operator Runbook

This runbook focuses on **operating a node** and verifying the protocol’s **non-economic Genesis phase**
behavior.

## 1) Genesis Constitutional Phase (economics disabled)

At genesis launch:

- fees = OFF
- rewards = OFF
- treasury spending = OFF
- identity, PoH, governance, and social features = ON

There is a hard time lock:

- `economic_unlock_time = genesis_time + 90 days`

If `now < economic_unlock_time`, governance proposals that try to enable/modify any economics
(fees/rewards/treasury/economic params) MUST be rejected.

Full details: `docs/genesis_phase.md`.

---

## 2) Start / restart (docker compose)

From `Weall-Protocol/`:

```bash
docker compose down -v
docker compose up -d --build
Smoke:

bash
bash scripts/api_smoke.sh
3) Validate canon + generated artifacts
bash
python -m tooling.canon_lint
python scripts/check_generated.py
pytest -q
Notes:

If you’re running from a zip export (no .git), check_generated.py falls back to a non-git byte-compare.

secret_guard.sh is designed for git-tracked scanning and may skip outside a git checkout.

4) Genesis-phase behavior checks (operator expectations)
During the Genesis phase:

Civic actions should remain fee-free and functional.

Economic features remain disabled.

Any governance proposal attempting to enable fees/rewards/treasury spending must fail deterministically.

After unlock:

economics may be enabled via ECONOMICS_ACTIVATION

only economic transfers may be metered with governance-controlled integer fees

civic actions remain fee-free

5) Troubleshooting checklist
If the node won’t start under docker:

ensure mounted data volumes are writable

remove old volumes: docker compose down -v

If CI passes but local fails:

verify python version

reinstall: pip install -e ".[test]"

yaml

---

## `projects/Weall-Protocol/docs/quickstart.md` (REPLACE)
```md
# WeAll Protocol — Quickstart

This doc gets you from zero to running locally, while aligning expectations with the
**non-economic Genesis Constitutional Phase**.

For the Genesis-phase model details: `docs/genesis_phase.md`.

## 1) Requirements

- Python 3.12+
- Docker + Docker Compose (recommended)
- Node 22+ (for web/oracle)

## 2) Backend (local dev)

```bash
cd Weall-Protocol
python -m venv .venv
source .venv/bin/activate
pip install -e ".[test]"
pytest -q
python -m tooling.canon_lint
python scripts/check_generated.py
uvicorn weall.api.main:app --reload --host 127.0.0.1 --port 8000
3) Backend (docker compose)
bash
cd Weall-Protocol
docker compose down -v
docker compose up -d --build
bash scripts/api_smoke.sh
4) What you should see at genesis
Node runs as a production protocol (identity/governance/social live)

Economics is disabled

No fees/rewards/treasury spending during the lock window

5) Web front-end
bash
Copy code
cd ../web
npm ci
npm run dev
Configure API base URL via the web env example file in web/.

6) Email oracle
bash
Copy code
cd ../weall-email-oracle
npm ci
npm run check
yaml

---

## `projects/README.md` (REPLACE)
```md
# WeAll Projects Bundle

This repository bundles:

- **Weall-Protocol/** — Python backend node + API + deterministic ledger runtime
- **web/** — Vite/React web front-end
- **weall-email-oracle/** — email oracle service (Node)

## Genesis launch model (non-economic)

WeAll launches as a production protocol with economics disabled:

- no transaction fees
- no rewards
- no treasury payouts/spending
- identity, PoH, governance, and social features are live

Hard time lock:

- `economic_unlock_time = genesis_time + 90 days`

Before unlock, governance cannot enable/modify any economic parameters.
After unlock, economics is enabled via `ECONOMICS_ACTIVATION`.
Civic actions remain permanently fee-free; only economic transfers may have governance-controlled integer fees.

See: `Weall-Protocol/docs/genesis_phase.md`

## Quick starts

### Backend (local)
```bash
cd Weall-Protocol
python -m venv .venv
source .venv/bin/activate
pip install -e ".[test]"
pytest -q
uvicorn weall.api.main:app --reload --host 127.0.0.1 --port 8000
Backend (docker)
bash
cd Weall-Protocol
docker compose down -v
docker compose up -d --build
bash scripts/api_smoke.sh
Web
bash
cd web
npm ci
npm run dev
Email oracle
bash
cd weall-email-oracle
npm ci
npm run check
