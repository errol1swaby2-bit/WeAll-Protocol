# WeAll Protocol

WeAll is a custom Layer 1 protocol focused on deterministic execution, HotStuff-style BFT finality, decentralized identity, governance, social content, groups, treasury flows, and operator-safe bootstrap-to-production lifecycle gating.

This repository is organized so a tester can go from a fresh clone to a working full-stack demo with one canonical dev boot command.

## Repository layout

- `scripts/` — repo-level bootstrap helpers, including the full dev flow
- `Weall-Protocol/` — backend node, runtime, API, Docker Compose stack, tests, and operator scripts
- `web/` — Vite + React frontend
- `.weall-dev/` — transient local frontend runtime state created by the dev boot flow

## Canonical local dev flow

From the repository root:

```bash
./scripts/dev_boot_full_stack.sh
```

That command is the preferred tester path. It is designed to:

- self-heal local port conflicts on `8000` and `5173`
- normalize backend runtime directory permissions
- reset deterministic local dev state
- start the backend quickstart path
- wait for backend readiness
- run the canonical demo bootstrap
- write the frontend dev bootstrap manifest
- start the frontend dev server

When it succeeds, the expected local URLs are:

- Frontend: `http://127.0.0.1:5173`
- Backend readyz: `http://127.0.0.1:8000/v1/readyz`
- Backend status: `http://127.0.0.1:8000/v1/status`
- API docs: `http://127.0.0.1:8000/docs`

## What the full dev boot command produces

The dev flow also runs a deterministic demo bootstrap for `@demo_tester` so a fresh tester does not need to hand-create a usable account before exploring the product surface.

Artifacts written by the flow include:

- `Weall-Protocol/generated/demo_bootstrap_result.json`
- `web/public/dev-bootstrap.json`
- `.weall-dev/frontend.log`

These artifacts let the frontend auto-repair the local dev browser session and surface the tester credentials in the UI.

## Manual split flow

If you want to run the pieces separately instead of using the all-in-one script:

### 1) Backend quickstart

From the repository root:

```bash
./scripts/quickstart_tester.sh
```

Or from the backend directory:

```bash
cd Weall-Protocol
./scripts/quickstart_tester.sh
```

### 2) Demo bootstrap

```bash
cd Weall-Protocol
./scripts/demo_bootstrap_tester.sh
```

### 3) Frontend only

```bash
cd web
cp .env.example .env.local
npm ci
npm run dev -- --host 127.0.0.1 --port 5173
```

## Dev environment requirements

### Backend

- Python 3.12
- Docker Desktop / Docker Engine with Compose
- local access to ports `8000`, `5001`, and `8080`

### Frontend

- Node.js 20+
- npm
- local access to port `5173`

## Common troubleshooting

### Port already in use

The dev boot script attempts automatic cleanup. If a port still remains busy, run:

```bash
lsof -i :8000 -P -n
lsof -i :5173 -P -n
ss -ltnp | grep -E ':8000|:5173'
ps aux | grep -E 'vite|npm run dev|node.*5173' | grep -v grep
docker ps --format 'table {{.ID}}\t{{.Names}}\t{{.Ports}}'
```

### Backend container health issues

```bash
cd Weall-Protocol
docker compose ps
docker compose logs weall_api --tail 200
docker compose logs weall_producer --tail 200
docker inspect weall-protocol-weall_api-1 --format '{{json .State.Health}}'
```

### Reset local backend state

```bash
cd Weall-Protocol
docker compose down -v
rm -f data/weall.db data/weall.db-shm data/weall.db-wal
rm -f data/weall.aux.sqlite data/weall.aux.sqlite-shm data/weall.aux.sqlite-wal
rm -f data/weall.aux_helper_lanes data/weall.db.bft_journal.jsonl
rm -f generated/demo_bootstrap_result.json
```

### Blank white frontend screen during dev

A common cause is a frontend module import failure. Check the browser console first. The current codebase had a dev bootstrap import path expecting an exported session helper that was not actually exported, which causes Vite to render a blank page until fixed.

## Release hygiene before pushing to GitHub

Before publishing a fresh repo snapshot:

```bash
cd Weall-Protocol
./scripts/clean_local_artifacts.sh
```

Also make sure:

- the frontend is not carrying stale `.env.local` values you do not want committed
- generated local demo artifacts are excluded
- Docker runtime files are not being accidentally tracked
- updated docs match the current dev flow, not an older manual setup path

## Consensus posture at a glance

The current repository posture is:

- HotStuff-style BFT
- deterministic validator normalization
- deterministic round-robin leader selection
- fail-closed runtime posture
- helper execution beneath canonical consensus, never instead of it
- deterministic bootstrap-to-production authority gating

## Current developer guidance

Use the repository root `README.md` for the tester-facing full-stack flow.

Use `Weall-Protocol/README.md` for backend-specific quickstart, runtime details, and operator diagnostics.
