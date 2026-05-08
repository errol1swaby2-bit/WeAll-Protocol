# Batch 316 — CI and Export Hygiene

Batch 316 closes the remaining public-validator-beta packaging gaps found after the protocol hardening passes.

## Purpose

The protocol safety blockers were already closed by prior batches:

- adaptive Live PoH quorum
- follower-side SYSTEM transaction replay binding
- helper execution root commitment
- backend and frontend dependency lockfiles
- documentation truth sync

Batch 316 focuses on release pipeline truth:

1. Web CI must start a backend before running the frontend/backend contract check.
2. Backend CI must prove the locked dependency install path.
3. Release hygiene must catch local frontend TypeScript build artifacts outside the inner protocol tree.
4. Audit archives must include dependency lockfiles while excluding local build/runtime artifacts.

## Web CI contract check

`web/scripts/contract_check.mjs` calls the backend API, defaulting to `http://127.0.0.1:8000`.

Batch 316 updates Web CI to:

- install backend runtime dependencies from `Weall-Protocol/requirements.lock` using `--require-hashes`
- install the backend package with `--no-deps`
- start `uvicorn weall.api.app:app` on `127.0.0.1:8000`
- wait for `/v1/readyz`
- run `API_BASE=http://127.0.0.1:8000 npm run contract-check`

This prevents CI from failing due to `fetch failed` when no backend is running.

## Backend locked install path

Batch 316 adds a dedicated backend CI step that creates a temporary virtual environment and installs:

```bash
pip install --require-hashes -r requirements-dev.lock
pip install -e . --no-deps
```

The main CI environment still installs `.[test,ci]` so tools such as `ruff` and `pip-audit` remain available until they are included in the locked dev dependency set.

## Release tree hygiene

`Weall-Protocol/scripts/verify_release_tree.sh` now checks the outer `web/` tree for:

- `*.tsbuildinfo`
- `*.egg-info/`
- `node_modules/`
- `dist/`

This prevents audit/release exports from silently including local frontend build artifacts such as `web/tsconfig.tsbuildinfo`.

## Audit archive creation

Use the root helper:

```bash
cd ~/WeAll-Protocol
bash scripts/create_audit_archive.sh /mnt/c/Users/Errol/Downloads
```

The archive excludes local runtime/build artifacts but intentionally keeps release lockfiles:

- `Weall-Protocol/requirements.lock`
- `Weall-Protocol/requirements-dev.lock`
- `web/package-lock.json`

Do not exclude `*.lock` or `*package-lock.json` from production-readiness audit exports.

## Acceptance checks

```bash
cd Weall-Protocol
python3 -S scripts/check_tx_canon_artifacts.py
bash scripts/secret_guard.sh
bash scripts/verify_release_tree.sh
bash scripts/verify_release_dependencies.sh
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH=src pytest -q tests/test_release_hygiene_batch257.py
```
