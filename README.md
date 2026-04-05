# WeAll Protocol

![Python](https://img.shields.io/badge/python-3.12-blue)
![License](https://img.shields.io/badge/license-MPL%202.0-purple)
![Status](https://img.shields.io/badge/status-genesis--ready-brightgreen)

WeAll is a custom Layer 1 protocol for decentralized social coordination, identity, governance, and validator-operated public infrastructure.

This public baseline is designed around deterministic execution, canonical hashing, fail-closed production posture, persistent mempool ordering, strict transaction handling, and HotStuff-style BFT finality. Helper-assisted execution is being brought in as a deterministic acceleration layer beneath the existing finality contract, not as an alternate consensus family. 

## Current release posture

This repository is now in a **Genesis-ready** state for public review and continued hardening.

Current implementation priorities:
- deterministic state transition behavior
- canonical block, receipt, and state commitments
- HotStuff-style BFT with deterministic leader rotation
- strict transaction schema and transaction canon handling
- fail-closed production startup profile
- helper execution safety under serial-equivalence constraints
- validator, restart, replay, and crash-recovery hardening

Important current constraint:
- **Economics are intentionally disabled during the Genesis phase** and should remain locked until the protocol’s activation path is intentionally exercised through governance and release discipline.

## Protocol contract at a glance

The synchronized protocol spec describes the current contract this way:
- HotStuff-style BFT consensus
- deterministic round-robin proposer selection over the normalized validator set
- quorum rule `ceil(2n/3)`
- canonical JSON commitments for transaction identity, receipts, blocks, and state
- handshake binding on `chain_id`, `schema_version`, and `tx_index_hash`, with stricter production matching available for protocol profile, validator epoch, and validator-set hash
- fail-closed production profile requiring signature verification, trusted anchors, profile matching, and monotonic block timestamp discipline

For helper-assisted execution, the production-readiness plan keeps the boundary explicit:
- HotStuff remains the sole source of canonical ordering and finality
- helpers may improve throughput, but must not create a new path for honest nodes to disagree on block validity, receipts root, state root, or finality
- helper planning, laneing, merge, fallback, replay handling, and restart behavior must remain deterministic and serial-equivalent

## Repository layout

Top-level layout:

- `.github/` — CI and repository automation
- `Weall-Protocol/` — core backend, runtime, consensus, tests, docs, generated canon files
- `web/` — frontend client
- `scripts/` — outer convenience and environment helpers
- `tools/` — auxiliary tooling

Core backend layout inside `Weall-Protocol/`:

- `src/weall/runtime/` — consensus, executor, block admission, mempool, helper execution, safety surfaces
- `src/weall/net/` — networking, handshake, state sync, transport
- `src/weall/api/` — public and node-facing HTTP surfaces
- `src/weall/ledger/` — deterministic ledger access model
- `tests/` — protocol, adversarial, restart, helper, validator, and production-hardening tests
- `generated/` — tracked generated protocol artifacts, including the tx canon index and contract maps
- `specs/tx_canon/` — transaction canon source material
- `docs/` — operational and production posture documentation

## What is implemented today

The current codebase includes:

- deterministic executor and commit pipeline
- block admission safety gates
- persistent mempool and SQLite-backed durability
- HotStuff-style BFT state machine
- validator epoch and validator-set binding in consensus traffic
- state sync with trusted-anchor posture
- Proof-of-Humanity and governance surfaces inside the deterministic state machine
- helper-assisted execution safety scaffolding, receipts, fallback, replay guards, and stress/adversarial coverage
- release hygiene scripts for cleaning, verification, and packaging

## Quickstart

### 1) Clone the repo

```bash
git clone git@github.com:errol1swaby2-bit/WeAll-Protocol.git
cd WeAll-Protocol
```

### 2) Backend quickstart

```bash
cd Weall-Protocol
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.lock
pytest -q
```

### 3) Frontend quickstart

```bash
cd ../web
npm ci
cp .env.example .env.local
npm run dev -- --host 127.0.0.1 --port 5173
```

### 4) Full-stack local flow

From the backend repo:

```bash
cd ../Weall-Protocol
./scripts/start_full_stack.sh
```

## Running the node

Backend node launcher:

```bash
cd Weall-Protocol
./scripts/run_node.sh
```

Production-oriented launcher:

```bash
cd Weall-Protocol
./scripts/run_node_prod.sh
```

The production posture expects node identity and related secrets to come from environment variables or secret files, with secret-file-based flows preferred for real deployments.

## Release hygiene

Before publishing or packaging a release from the backend repo:

```bash
cd Weall-Protocol
./scripts/clean_repo.sh
./scripts/verify_release_tree.sh
./scripts/release_package.sh
```

These scripts are intended to keep local artifacts such as bytecode, cache directories, build outputs, node modules, Wrangler local state, and environment files out of release packages.

## Fresh-clone verification

A fresh-clone reproducibility check is strongly recommended after major pushes.

Use the helper script in this batch:

```bash
./scripts/fresh_clone_smoke.sh
```

By default it:
- clones the public repo into `/tmp`
- creates a fresh Python virtual environment
- installs backend dependencies from `requirements.lock`
- regenerates `generated/tx_index.json`
- runs `pytest -q`
- optionally runs frontend install and build if Node is available

## Architecture notes

### Consensus

WeAll currently uses a HotStuff-style BFT engine with deterministic proposer selection and explicit validator epoch / validator-set binding.

### Deterministic execution

Consensus-critical objects are canonically encoded before hashing or signing. Block validity, state roots, receipts roots, and replay behavior are expected to be stable across honest nodes and across restart.

### Helper execution

Helpers are currently treated as a deterministic parallel execution layer beneath the finality contract. The safety standard is serial equivalence, deterministic planning, deterministic merge, replay resistance, and crash-safe restart behavior.

### Storage and recovery

The runtime uses a single durable SQLite database for ledger state, block metadata, queues, and mempool-like persistence. The production posture strongly prefers WAL mode and aims for atomic commit behavior.

## Documentation worth reading first

Inside `Weall-Protocol/docs/`:

- `PRODUCTION_POSTURE.md`
- `PRODUCTION_RUNBOOK_VALIDATORS.md`
- `production_node_bootstrap.md`
- `helper_spec.md`
- `STATE_ROOT_COMMITMENT_CONTRACT.md`
- `THREAT_MODEL_CHECKLIST.md`
- `runtime_consensus_profile_snapshot_2026-03-prod.4.md`

Reference documents in the broader project context:
- code-synchronized protocol spec
- helper production-readiness plan

## Current status guidance

This repository should be read as a **production-hardened public baseline**, not as a finished endpoint.

The next strongest stream after this release is long-running multinode end-to-end simulation with:
- mixed transaction load
- helper-enabled and helper-degraded rounds
- restart churn
- sync / rejoin pressure
- state-consistency checks across nodes

## Contributing

Contributions are most valuable in:
- distributed systems
- consensus and protocol safety
- adversarial testing
- backend/runtime engineering
- frontend integration and operator UX
- infrastructure and validator tooling

Please preserve deterministic behavior and fail-closed posture when proposing changes.

## License

Mozilla Public License 2.0
