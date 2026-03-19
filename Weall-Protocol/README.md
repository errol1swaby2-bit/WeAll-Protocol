# WeAll Protocol Backend

This directory contains the backend node, HTTP API, block producer, runtime scripts, and operator docs for the local external tester release.

The goal of this backend quickstart is simple:

- a new tester clones the repository
- starts the backend with Docker Compose
- starts the frontend from `../web`
- runs one demo bootstrap script
- sees the protocol working end to end without founder-specific setup

## Canonical consensus contract

Batch 1 freezes the production consensus contract described by this repository.
All operator-facing docs and runtime surfaces should now describe the same rules:

- **Consensus family:** HotStuff-style BFT
- **Validator normalization:** active validators are canonicalized by sort + de-dup
- **Leader selection:** deterministic round-robin over the normalized validator set
- **Leader formula:** `normalize(validators)[view % n]`
- **Quorum threshold:** `ceil(2n/3)`
- **Finality rule:** HotStuff 3-chain finalization
- **Safety rule:** a validator must not equivocate within a single view

This repository does **not** implement random proposer selection.
This repository does **not** use a 60% quorum rule.
Any older language suggesting either of those behaviors is obsolete and should not be used for validator operations, audits, or future client implementations.

## What is in this directory

- `src/weall/` — backend application, runtime, and protocol logic
- `docker-compose.yml` — canonical local tester backend startup path
- `Dockerfile` — backend image used by the local compose stack
- `scripts/golden_path_full_stack.py` — end-to-end API walkthrough
- `scripts/demo_bootstrap_tester.sh` — deterministic tester-facing demo bootstrap wrapper
- `scripts/quickstart_tester.sh` — one-command backend startup helper for testers
- `../scripts/quickstart_tester.sh` — repo-level wrapper so testers can start from the repository root
- `docs/testnet_runbook.md` — operator-oriented local runbook
- `docs/PRODUCTION_RUNBOOK_VALIDATORS.md` — public-network validator runbook

## Canonical startup path for external testers

For the tester release, use only this path:

1. backend with `./scripts/quickstart_tester.sh` from the repository root
2. frontend with `npm run dev` from `../web`
3. demo bootstrap with `scripts/demo_bootstrap_tester.sh`

Do not use the production compose files, tunnel compose files, or older ad hoc scripts for the external tester quickstart.

If anything in this file conflicts with the repository root `README.md`, follow the repository root `README.md` for the external tester release and this file for backend-specific runtime details.

## Backend quickstart

Preferred path, from the repository root:

```bash
./scripts/quickstart_tester.sh

Equivalent backend-only path, from this directory:

./scripts/quickstart_tester.sh

That helper will:

create any missing local runtime directories

generate generated/tx_index.json if needed

start the backend stack with docker compose up -d --build

wait for the API to become ready

print the health URLs

print the frontend startup commands

print the demo bootstrap command

Frontend startup

In a second terminal, from the repository root:

cd web
cp .env.example .env.local
npm ci
npm run dev -- --host 127.0.0.1 --port 5173

Open:

http://127.0.0.1:5173
End-to-end demo walkthrough

In a third terminal, from the repository root:

cd Weall-Protocol
./scripts/demo_bootstrap_tester.sh

That wrapper script creates or reuses .venv-release-check, installs the backend package, runs the full golden path, writes generated/demo_bootstrap_result.json, and prints exact browser verification steps.

Environment variables used by the local tester path

These are the important backend variables for the local compose flow.

Variable	Local tester value	Purpose
WEALL_MODE	dev	Enables local development behavior
WEALL_CHAIN_ID	weall-dev	Local chain identifier
WEALL_NODE_ID	genesis-api / genesis-producer	Local node identity label
WEALL_DB_PATH	./data/weall.db	SQLite database path inside the container
WEALL_TX_INDEX_PATH	./generated/tx_index.json	Generated transaction index used by runtime code
WEALL_POH_BOOTSTRAP_OPEN	1	Allows local bootstrap flows for testers
WEALL_IPFS_API_BASE	http://kubo:5001	Internal IPFS API address
WEALL_ALLOW_UNSIGNED_TXS	0	Keeps tx signing checks on

The compose file already provides these values, so a tester does not need to hand-edit .env for the default local quickstart.

Runtime consensus diagnostics

The API exposes consensus contract information so operators can verify they are on the same ruleset:

GET /v1/status

GET /v1/status/consensus

GET /v1/status/operator

Each endpoint now reports the canonical leader-selection rule, quorum rule, and normalized validator-set summary used by the runtime.

Troubleshooting

Check service status:

docker compose ps

Show recent logs:

docker compose logs weall_api --tail 200
docker compose logs weall_producer --tail 200
docker compose logs kubo --tail 200

Reset local runtime state:

docker compose down -v
rm -rf data generated
mkdir -p data generated data/ipfs
Scope of this release

This quickstart is for local external testing of the backend, frontend, and end-to-end demo flow. It is not the production deployment path.


---

## 4) `docs/testnet_runbook.md`

```markdown
# Local Tester Runbook

This runbook is the operator-facing version of the external tester quickstart.

## Canonical path

Use only this sequence for the tester release:

1. from the repository root run `./scripts/quickstart_tester.sh`
2. from `web/` run the Vite frontend
3. from `Weall-Protocol/` run `./scripts/demo_bootstrap_tester.sh`

## Canonical consensus rules for tester validation

Even in the local tester flow, consensus expectations should match the real runtime contract.
The current implementation uses:

- HotStuff-style BFT
- deterministic round-robin proposer selection over the sorted active validator set
- quorum threshold `ceil(2n/3)`
- HotStuff 3-chain finality

Local testing should not assume random proposer selection or a 60% quorum threshold.
If any older notes, screenshots, or whitepaper text suggest otherwise, use the runtime and this runbook as the source of truth for the codebase in this repository.

## Commands

Backend from the repository root:

```bash
./scripts/quickstart_tester.sh

Frontend in a second terminal:

cd web
cp .env.example .env.local
npm ci
npm run dev -- --host 127.0.0.1 --port 5173

Demo bootstrap in a third terminal:

cd Weall-Protocol
./scripts/demo_bootstrap_tester.sh
Verification

Check all of the following:

curl http://127.0.0.1:8000/v1/readyz

curl http://127.0.0.1:8000/v1/status

curl http://127.0.0.1:8000/v1/status/consensus

open http://127.0.0.1:8000/docs

open http://127.0.0.1:5173

confirm the printed demo post appears in the feed

confirm the printed demo account appears in the UI

confirm /v1/status/consensus shows a deterministic leader and a ceil(2n/3) quorum threshold

Notes

email-oracle onboarding is optional and not part of the required tester path

generated/tx_index.json is created automatically by the backend helper

founder-local files must be removed before release with Weall-Protocol/scripts/clean_local_artifacts.sh


---

## 5) `docs/PRODUCTION_RUNBOOK_VALIDATORS.md`

```markdown
# Independent Validator Production Runbook

## Purpose
This runbook is for independent validator operators running a public WeAll network.
It assumes validator-set epochs, proposal authentication, and consensus contract alignment are all safety-critical.

## Canonical consensus contract

Before running a validator, treat the following as the authoritative protocol rules for this repository build:

- **Consensus family:** HotStuff-style BFT
- **Validator normalization:** sort + de-dup the active validator set before leader derivation
- **Leader selection:** deterministic round-robin over the normalized validator set
- **Leader formula:** `normalize(validators)[view % n]`
- **Quorum threshold:** `ceil(2n/3)` for both QCs and timeout-driven view progress
- **Finality rule:** HotStuff 3-chain finalization
- **Vote safety:** a validator must not sign conflicting blocks in the same view

Do not rely on any document, whitepaper excerpt, or operator note that describes random proposer selection or a 60% quorum rule for this codebase.

## Preflight
- Verify repository commit hash and release tag.
- Verify `generated/tx_index.json` hash matches the release manifest.
- Verify chain ID from genesis config.
- Verify validator account and validator pubkey have been registered on-chain before enabling signing.
- Verify local node clock is synchronized with NTP.
- Verify database path is on reliable local storage.
- Verify `/v1/status/consensus` reports the same consensus contract expected by the release.

## Required secrets
- `WEALL_VALIDATOR_ACCOUNT`
- `WEALL_NODE_PUBKEY`
- `WEALL_NODE_PRIVKEY`

Store keys outside shell history and outside the repo.

## Startup checklist
1. Clone the exact tagged release.
2. Create a fresh virtual environment.
3. Install locked dependencies only.
4. Verify `generated/tx_index.json` exists and matches the published hash.
5. Start the node in observer mode first.
6. Confirm `/v1/status`, `/v1/status/consensus`, and `/v1/status/operator` are healthy.
7. Confirm the reported normalized validator set, leader rule, and quorum threshold match the release contract.
8. Only then enable validator signing.

## Safety invariants
A validator must not sign if any of the following are true:
- local chain ID differs from the network chain ID
- local tx index hash differs from the release hash
- local validator account is not in the active validator set
- proposal view leader does not match the deterministic local leader schedule when proposing
- validator epoch in inbound proposals differs from local state
- validator-set hash in inbound proposals differs from local state
- `/v1/status/consensus` reports a consensus contract that differs from the release manifest

## Crash recovery
After a crash:
1. Restart in observer mode.
2. Inspect the latest committed height and finalized block ID.
3. Inspect any `bft_pending_fetch` entries.
4. Confirm the node catches up to the latest height.
5. Confirm `/v1/status/consensus` shows the expected leader/quorum contract.
6. Re-enable validator signing only after catch-up.

## Stalled consensus checklist
- Check active validator set and validator epoch.
- Check the current view and last progress timestamp.
- Check whether a pending QC exists for a block the node does not have.
- Check whether the local validator believes it is the current leader under the deterministic round-robin schedule.
- Check peer connectivity and timeout emission.
- Check whether peers appear to be using the same quorum threshold and validator-set hash.

## Upgrade procedure
- Never mix binaries from different protocol releases on the same validator.
- Upgrade only at an announced epoch boundary.
- Stop signing before the upgrade.
- Confirm post-upgrade validator epoch and set hash match peers before resuming.
- Confirm `/v1/status/consensus` still reports the expected consensus contract after upgrade.
