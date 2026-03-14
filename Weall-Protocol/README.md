# WeAll Protocol Backend

This directory contains the backend node, HTTP API, block producer, runtime scripts, and operator docs for the local external tester release.

The goal of this backend quickstart is simple:

- a new tester clones the repository
- starts the backend with Docker Compose
- starts the frontend from `../web`
- runs one demo bootstrap script
- sees the protocol working end to end without founder-specific setup

## What is in this directory

- `src/weall/` — backend application, runtime, and protocol logic
- `docker-compose.yml` — canonical local tester backend startup path
- `Dockerfile` — backend image used by the local compose stack
- `scripts/golden_path_full_stack.py` — end-to-end API walkthrough
- `scripts/demo_bootstrap_tester.sh` — deterministic tester-facing demo bootstrap wrapper
- `scripts/quickstart_tester.sh` — one-command backend startup helper for testers
- `../scripts/quickstart_tester.sh` — repo-level wrapper so testers can start from the repository root
- `docs/testnet_runbook.md` — operator-oriented local runbook

## Canonical startup path for external testers

For the tester release, use only this path:

1. backend with `./scripts/quickstart_tester.sh` from the repository root
2. frontend with `npm run dev` from `../web`
3. demo bootstrap with `scripts/demo_bootstrap_tester.sh`

Do not use the production compose files, tunnel compose files, or older ad hoc scripts for the external tester quickstart.

If anything in this file conflicts with the repository root `README.md`, follow the root `README.md` for the external tester release.

## Backend quickstart

Preferred path, from the repository root:

```bash
./scripts/quickstart_tester.sh
```

Equivalent backend-only path, from this directory:

```bash
./scripts/quickstart_tester.sh
```

That helper will:

- create any missing local runtime directories
- generate `generated/tx_index.json` if needed
- start the backend stack with `docker compose up -d --build`
- wait for the API to become ready
- print the health URLs
- print the frontend startup commands
- print the demo bootstrap command

## Frontend startup

In a second terminal, from the repository root:

```bash
cd web
cp .env.example .env.local
npm ci
npm run dev -- --host 127.0.0.1 --port 5173
```

Open:

```text
http://127.0.0.1:5173
```

## End-to-end demo walkthrough

In a third terminal, from the repository root:

```bash
cd Weall-Protocol
./scripts/demo_bootstrap_tester.sh
```

That wrapper script creates or reuses `.venv-release-check`, installs the backend package, runs the full golden path, writes `generated/demo_bootstrap_result.json`, and prints exact browser verification steps.

## Environment variables used by the local tester path

These are the important backend variables for the local compose flow.

| Variable | Local tester value | Purpose |
|---|---|---|
| `WEALL_MODE` | `dev` | Enables local development behavior |
| `WEALL_CHAIN_ID` | `weall-dev` | Local chain identifier |
| `WEALL_NODE_ID` | `genesis-api` / `genesis-producer` | Local node identity label |
| `WEALL_DB_PATH` | `./data/weall.db` | SQLite database path inside the container |
| `WEALL_TX_INDEX_PATH` | `./generated/tx_index.json` | Generated transaction index used by runtime code |
| `WEALL_POH_BOOTSTRAP_OPEN` | `1` | Allows local bootstrap flows for testers |
| `WEALL_IPFS_API_BASE` | `http://kubo:5001` | Internal IPFS API address |
| `WEALL_ALLOW_UNSIGNED_TXS` | `0` | Keeps tx signing checks on |

The compose file already provides these values, so a tester does not need to hand-edit `.env` for the default local quickstart.

## Troubleshooting

Check service status:

```bash
docker compose ps
```

Show recent logs:

```bash
docker compose logs weall_api --tail 200
docker compose logs weall_producer --tail 200
docker compose logs kubo --tail 200
```

Reset local runtime state:

```bash
docker compose down -v
rm -rf data generated
mkdir -p data generated data/ipfs
```

## Scope of this release

This quickstart is for local external testing of the backend, frontend, and end-to-end demo flow. It is not the production deployment path.
