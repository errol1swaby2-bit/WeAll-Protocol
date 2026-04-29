# WeAll Protocol

WeAll is a custom Layer 1 protocol for social coordination, governance, decentralized identity, groups, dispute resolution, treasury flows, storage participation, and operator-safe network growth.

Its core design goal is simple:

**every honest node should deterministically reach the same result from the same ordered block input.**

The current implementation is built around:

- **HotStuff-style BFT finality**
- **deterministic execution**
- **deterministic validator normalization and leader selection**
- **fail-closed runtime posture**
- **bootstrap-to-production authority gating**
- **helper-assisted execution beneath consensus, never instead of it**

The current audited transaction canon contains **215 transaction types across 21 domains**.

---

## Why WeAll exists

Most platforms centralize identity, moderation, governance, and social coordination behind a private operator.

WeAll takes a different path.

It aims to make social and civic coordination part of the protocol itself:

- identity is part of the state machine
- governance is part of the state machine
- moderation and disputes are part of the state machine
- groups and treasury flows are part of the state machine
- operator authority is explicitly gated rather than assumed

This repo is the current implementation of that protocol.

---

## What is working now

The current codebase already supports a real local full-stack demo flow with:

- account registration and session flows
- Proof-of-Humanity onboarding paths
- content posting and interaction flows
- governance proposal and vote flows
- dispute intake, review, and juror flows
- group creation and group role flows
- deterministic mempool admission and block application
- HotStuff-style consensus infrastructure
- helper-safety posture beneath canonical consensus
- local tester bootstrapping through a single canonical dev flow

The current controlled-devnet readiness proof also runs without demo-seed shortcuts:

- fresh account registration through normal tx submission
- bounded Tier-1 email-oracle attestation using an opaque email commitment
- joining-node sync from a trusted anchor
- cross-node account, tx-status, tip, and state-root parity checks
- a Tier-1-gated transaction submitted on node 2 and synced back to node 1
- Tier-2 async PoH request, juror accept, review, finalization, and cross-node convergence
- Tier-3 protocol-native live PoH request, reviewer assignment, attendance, verdicts, finalization, and cross-node convergence

This is not a slide deck or mock frontend.  
It is a working protocol + node + frontend repository.

---

## Current protocol posture

WeAll currently targets the following implementation contract:

- **Consensus family:** HotStuff-style BFT
- **Leader selection:** deterministic round-robin over normalized validator set
- **Execution model:** deterministic ordered state transition
- **Replay protection:** canonical tx identity plus nonce discipline
- **Mempool posture:** persistent and deterministic for proposal/build rules
- **State commitment:** canonical receipts root and state root
- **Helper posture:** deterministic parallel-execution layer subordinate to HotStuff
- **Lifecycle posture:** bootstrap registration → explicit production promotion
- **Production posture:** fail-closed configuration with trusted verification enabled

Helpers are treated as a throughput optimization layer, not as a second consensus family.

---

## Repository layout

- `.github/workflows/` — backend, web, and auxiliary CI checks
- `scripts/` — repo-level bootstrap helpers, including the canonical full demo flow
- `Weall-Protocol/` — backend node, runtime, API, Docker Compose stack, tests, generated artifacts, and operator tooling
- `web/` — Vite + React frontend
- `.weall-dev/` — transient local frontend/runtime state produced by the local dev flow

---

## Demo in 5 minutes

From the repository root:

```bash
./scripts/dev_boot_full_stack.sh
```

This is the **canonical local demo path**.

It is designed to:

- self-heal common local port conflicts
- normalize backend runtime directories
- reset deterministic local dev state
- start the backend quickstart path
- wait for backend readiness
- run the canonical demo bootstrap
- write the frontend bootstrap manifest
- start the frontend dev server

When successful, the main local URLs are:

- **Frontend:** `http://127.0.0.1:5173`
- **Backend readyz:** `http://127.0.0.1:8000/v1/readyz`
- **Backend status:** `http://127.0.0.1:8000/v1/status`
- **API docs:** `http://127.0.0.1:8000/docs`

---

## Controlled-devnet readiness proof

For a deeper protocol-native proof that does not rely on the deterministic demo seed route, run the backend controlled-devnet readiness suite:

```bash
cd Weall-Protocol
source .venv/bin/activate

pytest -q
WEALL_EMAIL="you@example.com" \
WEALL_DEVNET_SUITE_RUN_TIER2=1 \
WEALL_DEVNET_SUITE_RUN_TIER3=1 \
bash scripts/devnet_controlled_readiness_suite.sh
```

This suite is the non-seeded proof path. It covers direct API permission gating, controlled two-node onboarding, Tier-1 email PoH, cross-node account and tx-status parity, node-2 transaction submission and convergence, Tier-2 async PoH finalization, Tier-3 protocol-native live PoH finalization, cross-node convergence, and restart/catch-up.

The latest backend verification checkpoint for this snapshot was a green full pytest run: **2,514 passed, 1 warning**, followed by a green controlled-devnet readiness suite.

---

## What the demo boot flow gives you

The full dev flow is designed so a fresh tester can explore the product surface quickly without first hand-assembling a usable local account state.

The flow also runs a deterministic demo bootstrap and writes artifacts such as:

- `Weall-Protocol/generated/demo_bootstrap_result.json`
- `web/public/dev-bootstrap.json`
- `.weall-dev/frontend.log`

These artifacts help the frontend auto-repair local demo session state and surface the tester path in the UI.

---

## What to look at first in the demo

Once the stack is up, a reviewer should be able to explore the protocol client in this order:

1. **Account / session state**
2. **Proof-of-Humanity flows**
3. **Feed and content posting**
4. **Governance proposals and voting**
5. **Disputes and juror work**
6. **Groups and role-gated actions**
7. **Node status / protocol awareness surfaces**

That sequence gives the clearest picture of what makes WeAll different:  
it is not just a social app UI attached to a chain — the coordination rules themselves are protocol-native.

---

## What makes WeAll different

### 1. Social coordination is protocol-native

WeAll does not treat governance, moderation, identity, and social interaction as off-chain product logic sitting beside a token.

They are modeled as part of the protocol state machine.

### 2. Production authority is gated, not assumed

A fresh node is allowed to be useful immediately, but not authoritative immediately.

The lifecycle is intentionally split between:

- **bootstrap registration**
- **explicit promotion into production service**

That reduces accidental authority and keeps the trust posture fail-closed.

### 3. Determinism is a first-class design constraint

The protocol is built around the requirement that canonical ordering, validity, and final post-state must not depend on local machine timing, random choices, or non-canonical iteration behavior.

### 4. Helper execution is subordinate to consensus

Parallel execution is only acceptable if it preserves canonical results.

The helper model is explicitly constrained by deterministic assignment, deterministic laneing, canonical merge rules, replay-safe receipts, and serial equivalence requirements.

---

## Current capability map

The current audited transaction surface spans 21 domains, including:

- identity
- Proof of Humanity
- content
- social
- groups
- governance
- disputes
- treasury
- roles
- consensus
- rewards
- economics
- storage
- networking
- notifications
- indexing

Total current transaction types: **215**.

---

## Manual split flow

If you want to run the pieces separately instead of the all-in-one path:

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

---

## Dev environment requirements

### Backend

- Python 3.12
- Docker Desktop / Docker Engine with Compose
- local access to ports `8000`, `5001`, and `8080`

### Frontend

- Node.js 20+
- npm
- local access to port `5173`

---

## Public-facing architecture summary

At a high level, the current execution path is:

```text
API submit
→ tx admission
→ persistent mempool
→ block assembly
→ block admission
→ deterministic domain execution
→ receipts + state root
→ atomic commit
```

Consensus remains the canonical ordering and finality layer.

Helpers, where used, must preserve the same result as the serial reference executor.

---

## Current safety posture

The current implementation posture is intentionally conservative:

- fail closed rather than guess
- validate before admit
- re-validate before block inclusion
- apply atomically
- bind consensus messages to chain and validator context
- keep helper execution beneath canonical consensus
- require explicit lifecycle promotion before production authority

This is deliberate.  
The goal is not just to make the system run — it is to make it hard for honest nodes to disagree.

---

## Repository documentation

For deeper implementation detail, use these repository-tracked files:

- `Weall-Protocol/README.md` — backend quickstart, runtime notes, and operator diagnostics
- `Weall-Protocol/docs/testnet_runbook.md` — local tester, conference, and protocol-review runbook
- `RELEASE_CHECKLIST.md` — external tester release checklist
- `CONTRIBUTING.md` — contribution workflow and review expectations
- `SECURITY.md` — security reporting and supported security posture

---

## Common troubleshooting

### Port already in use

The dev boot script attempts automatic cleanup. If a port remains busy, run:

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

A common cause is a frontend module import failure. Check the browser console first, then confirm the backend is healthy and the frontend bootstrap artifacts were written successfully.

---

## Release hygiene before pushing to GitHub

Before publishing a fresh repo snapshot:

```bash
cd Weall-Protocol
./scripts/clean_local_artifacts.sh
```

Also verify that:

- stale local demo artifacts are excluded
- unwanted frontend `.env.local` values are not tracked
- Docker runtime files are not being committed
- docs still match the actual current demo path

---

## License

WeAll Protocol is licensed under the **Mozilla Public License 2.0**. See `LICENSE`.

---

## Status note

This repository is already suitable for serious technical review and live local demonstration.

It is **not** claiming that every future production feature is already enabled.

The current posture is better described as:

**real protocol implementation, real local demo, safety-first production path still being hardened**

That distinction matters and is intentional.

---

## Backend-specific guidance

Use the repository root `README.md` for the main conference/demo path.

Use `Weall-Protocol/README.md` for backend-specific quickstart, diagnostics, runtime notes, and operator-facing details.
