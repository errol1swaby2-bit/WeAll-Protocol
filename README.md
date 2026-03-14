# WeAll Protocol

A decentralized social-governance protocol combining identity, content publishing, and on-chain governance.

This repository contains everything required for an external tester to run a local WeAll stack and verify a basic end-to-end protocol flow without founder-specific setup.

## External tester quickstart policy

For this release, there is exactly one supported local startup path:

1. `./scripts/quickstart_tester.sh`
2. `cd web && cp .env.example .env.local && npm ci && npm run dev -- --host 127.0.0.1 --port 5173`
3. `cd Weall-Protocol && ./scripts/demo_bootstrap_tester.sh`

Do not use the other compose files, production files, tunnel files, or older helper scripts for the external tester quickstart.

## Repository structure

```text
.
├── Weall-Protocol/        # Backend node + API + Docker Compose + demo scripts
├── web/                   # Frontend application (Vite / React)
├── scripts/               # Repo-level helper scripts
├── RELEASE_CHECKLIST.md   # Final release checklist for Monday push
└── README.md
```

## Prerequisites

Install:

- Git
- Docker + Docker Compose
- Node.js 20+
- Python 3.12+

Verify:

```bash
docker --version
docker compose version
node --version
python3 --version
```

## Clone

```bash
git clone https://github.com/errol1swaby2-bit/WeAll-Protocol.git
cd WeAll-Protocol
```

## Quickstart for external testers

This release supports one local startup path on a clean machine.

### 1. Start the backend

From the repository root:

```bash
./scripts/quickstart_tester.sh
```

Wait until the script reports backend readiness.

You can verify manually:

```bash
curl http://127.0.0.1:8000/v1/readyz
curl http://127.0.0.1:8000/v1/status
```

### 2. Start the frontend

Open a second terminal:

```bash
cd web
cp .env.example .env.local
npm ci
npm run dev -- --host 127.0.0.1 --port 5173
```

Then open:

```text
http://127.0.0.1:5173
```

### 3. Create demo state

Open a third terminal:

```bash
cd Weall-Protocol
./scripts/demo_bootstrap_tester.sh
```

That script creates reproducible local demo state for the browser walkthrough.

### 4. Verify the demo in the browser

After the demo bootstrap script succeeds:

1. open `http://127.0.0.1:5173`
2. refresh the feed or home view once
3. confirm the printed demo post body is visible
4. confirm the printed demo account exists
5. optionally open `http://127.0.0.1:8000/docs`

## Where configuration lives

This repo contains separate backend and frontend environment templates:

- backend: `Weall-Protocol/.env.example`
- frontend: `web/.env.example`

For the standard tester walkthrough, the backend compose file already provides local defaults. The only file a tester normally needs to create is:

- `web/.env.local` from `web/.env.example`

## Local tester environment variables

### Backend

The canonical compose path already provides local defaults. Testers should not need to hand-edit backend environment values for the standard walkthrough.

Important backend values used by the local stack:

- `WEALL_MODE=dev`
- `WEALL_CHAIN_ID=weall-dev`
- `WEALL_DB_PATH=./data/weall.db`
- `WEALL_TX_INDEX_PATH=./generated/tx_index.json`
- `WEALL_POH_BOOTSTRAP_OPEN=1`
- `WEALL_IPFS_API_BASE=http://kubo:5001`
- `WEALL_ALLOW_UNSIGNED_TXS=0`

### Frontend

The required local frontend value is:

- `VITE_WEALL_API_BASE=http://127.0.0.1:8000`

Optional frontend values are documented in `web/.env.example`.

## Common failure points

If startup fails, check these first:

- Docker Desktop or Docker Engine is not running
- port `8000` is already in use
- port `5173` is already in use
- IPFS ports `4001`, `5001`, or `8080` are already in use
- `npm ci` was not run inside `web/`
- Python `3.12+` is missing
- an old `Weall-Protocol/.env` file is overriding local defaults
- stale containers from a previous run are still present

Useful commands:

```bash
cd Weall-Protocol
docker compose ps
docker compose logs weall_api --tail 200
docker compose logs weall_producer --tail 200
docker compose logs kubo --tail 200
```

## Unsupported local paths for external testers

These files are not part of the Monday tester quickstart:

- `dev_up.sh`
- `Weall-Protocol/docker-compose.genesis.yml`
- `Weall-Protocol/docker-compose.prod.yml`
- `Weall-Protocol/docker-compose.ipfs.yml`
- `Weall-Protocol/docker-compose.tunnel.prod.yml`

They may be useful for operator or production work later, but they are not the supported fresh-clone path for external testers.

## Shutdown and reset

Stop services:

```bash
cd Weall-Protocol
docker compose down
```

Reset local runtime state:

```bash
cd Weall-Protocol
docker compose down -v
rm -rf data generated
mkdir -p data generated data/ipfs
```

## Release hygiene before pushing

Run:

```bash
cd Weall-Protocol
./scripts/clean_local_artifacts.sh
```

Then review:

- `git status`
- `RELEASE_CHECKLIST.md`

## Additional docs

- backend quickstart: `Weall-Protocol/README.md`
- local operator runbook: `Weall-Protocol/docs/testnet_runbook.md`
- release checklist: `RELEASE_CHECKLIST.md`
