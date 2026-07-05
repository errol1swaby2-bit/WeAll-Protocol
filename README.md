# WeAll Protocol

WeAll is an experimental public civic protocol and social coordination application. The repository contains the backend node/runtime, public API, frontend, operator scripts, generated evidence artifacts, and test surfaces needed to review the current public-testnet implementation.

The public repository should be read as a maintained protocol implementation under active hardening, not as a public mainnet claim. The current safety posture is explicit:

- protocol-native social, civic, governance, moderation, dispute, group, reputation, validator/operator, and protocol-state activity is publicly inspectable;
- protocol-native encrypted direct messages, private social groups, member-only-readable group posts, and opaque consensus-affecting social payloads are unsupported;
- group membership may gate posting, commenting, voting, moderation, invitation, or administration, but not read visibility of protocol-native group content;
- observer mode and validator mode are separate operational postures; validator authority remains protocol-gated and cannot be granted by a local environment variable alone;
- production economics are locked unless an explicitly governed activation path and release evidence say otherwise;
- public-testnet discovery uses signed/pinned seed-registry and endpoint evidence, not hosting-provider trust.

## Current Repository Status

The repository currently supports three reviewer/operator paths:

1. **Local development demo** — boots a local backend/frontend demo with deterministic seeded state for fast UI inspection.
2. **Controlled local protocol rehearsal** — exercises the genesis-to-observer-to-promoted-validator path on one machine without treating demo seed state as protocol proof.
3. **Public observer testnet preparation** — checks signed seed discovery, validator endpoint evidence, public-only frontend/backend coherence, secret/export safety, and release-hygiene gates.

This is not a claim of public mainnet readiness, security-audited deployment, irreversible governance readiness, or economic activation. Before any external network claim, rerun the release gates in `RELEASE_CHECKLIST.md` from a clean clone and keep the resulting evidence.

## Reviewer Starting Point

Start here before diving into batch-era or generated files:

1. `Weall-Protocol/docs/TRUTH_BOUNDARY.md` — current claim boundaries and non-claims.
2. `Weall-Protocol/docs/PUBLIC_ONLY_PROTOCOL.md` — public-only protocol rule and enforcement posture.
3. `Weall-Protocol/docs/GENERATED_ARTIFACTS.md` — generated evidence index and regeneration commands.
4. `Weall-Protocol/docs/PROFESSIONALIZATION_BACKLOG.md` — known presentation/debt backlog that was intentionally not folded into this patch.
5. `Weall-Protocol/docs/ARCHITECTURE_DECISIONS/` — concise ADRs for public-only policy, messaging removal, group visibility, observer promotion, seed discovery, and secret/export hygiene.
6. `RELEASE_CHECKLIST.md` — clean-clone and release-hygiene gates.

## Public Observer Testnet Gate

Public observer mode is explicit (`WEALL_PUBLIC_TESTNET=1`). A public observer should accept seed and validator endpoint discovery only through the configured public-testnet chain commitments, a signed seed registry, pinned registry signer material, and signed validator endpoint advertisements. Endpoint advertisements are connection hints and freshness evidence; they do not grant validator status.

Use these files and commands before making a public observer readiness claim:

```bash
cd Weall-Protocol
PYTHONPATH=src python -m compileall -q src/weall
bash scripts/secret_guard.sh
PYTHONPATH=src python scripts/check_v15_public_readiness_artifacts.py
PYTHONPATH=src python scripts/check_release_hygiene_v1_5.py
PYTHONPATH=src python -m pytest -q tests/test_public_only_protocol_redesign.py

cd ../web
npm run -s test:public-only-protocol-source
```

Operator-facing public observer startup remains:

```bash
git clone <repo-url> WeAll-Protocol
cd WeAll-Protocol/Weall-Protocol
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.lock
pip install -e .
WEALL_PUBLIC_TESTNET=1 bash scripts/boot_public_observer_testnet.sh
```

The boot path is documented in `Weall-Protocol/docs/PUBLIC_OBSERVER_TESTNET_QUICKSTART.md`. The checked-in `configs/public_testnet_seed_registry.json`, `configs/public_testnet_trust_roots.json`, and `configs/public_testnet_chain_commitments.json` must all match `configs/chains/weall-testnet-v1.json`; otherwise observer boot fails closed.

For launch transcript rehearsals, use `Weall-Protocol/scripts/run_public_observer_launch_rehearsal_v1_5.sh` only after the real signed registry and seed API are published.

## What Works in the Local Demo

The local demo can show:

- a pre-seeded demo account;
- account verification state;
- a social feed and media-backed posts;
- post detail pages and public comments;
- public group content with member-gated participation;
- reporting, review assignment, review outcome, and public activity surfaces;
- community decisions and responsibility/role surfaces;
- frontend/backend session handoff;
- deterministic demo bootstrap output.

The demo is intended to make the current architecture inspectable and easier to test. It is not a substitute for controlled-devnet or public-testnet evidence.

## What Is Intentionally Unsupported

This repository intentionally does not support:

- protocol-native encrypted DMs or private message threads;
- private groups or member-only-readable protocol-native group content;
- opaque encrypted protocol payloads that affect social, civic, governance, moderation, dispute, group, reputation, validator/operator, or protocol-state outcomes;
- production economics activation by default;
- validator authority based only on local configuration;
- public-mainnet readiness claims without release evidence and external review.

## Project Direction

WeAll is being designed as a familiar social application with deterministic protocol state underneath.

The product goal is to support:

- social posting
- media upload
- groups
- public activity notifications
- community decisions
- reports and reviews
- account verification
- trusted responsibilities

The frontend is intentionally moving toward plain human language rather than crypto-native dashboard language.

For normal users, the target experience is closer to:

> a social app with built-in verification, community decisions, community review, and trusted responsibilities

rather than:

> a blockchain dashboard with social features

---

## Identity and Verification Direction

WeAll has moved away from the previous three-tier identity model that included email verification.

The current target direction is a protocol-native two-tier human verification model:

- **Tier 1** — async Turing-style verification
- **Tier 2** — live Turing-style verification

The intent is to avoid required dependency on centralized identity infrastructure.

The target model does **not** require:

- email verification
- email-provider account control
- DNS verification
- SMTP infrastructure
- CAPTCHA
- OAuth
- KYC providers
- government ID providers
- centralized identity providers as required gates

The goal is to make human verification part of the protocol process itself through challenge, evidence commitment, juror review, threshold finalization, receipts, and deterministic state transitions.

This area is implemented as the current protocol-native direction and remains under active review and hardening.

---


## Requirements

For the local demo path, you should have:

- Linux or WSL-like development environment
- Git
- Docker and Docker Compose
- Python 3.12+
- Node.js and npm
- network access for dependency downloads and Docker image pulls

The boot script is designed to rebuild the local development environment from a fresh clone.

---

## Fresh Clone Demo

Clone the repository:

```bash
git clone git@github.com:errol1swaby2-bit/WeAll-Protocol.git WeAll-Protocol
cd WeAll-Protocol
```

Run the full local demo boot:

```bash
bash scripts/dev_boot_full_stack.sh
```

Expected successful markers include:

```text
✅ FULL STACK GOLDEN PATH PASSED
[dev-full-surface] seeded demo reviewer role persisted
[dev-full-surface] dev full-surface environment ready
frontend=http://127.0.0.1:5173
backend=http://127.0.0.1:8000
```

Then open:

```text
http://127.0.0.1:5173
```

The demo account should be surfaced through the local dev bootstrap flow.

---

## Expected Reviewer Path: Dual-Node Same-Machine Rehearsal

The expected same-machine reviewer proof is the existing controlled-devnet readiness suite. It starts a controlled genesis node and a joining node on the same machine, uses normal public transaction submission paths, verifies native async/live PoH, syncs both nodes, checks same tip and state root convergence, and verifies restart/catch-up behavior. It intentionally does not rely on `/v1/dev/demo-seed`.

Run from the backend directory:

```bash
cd Weall-Protocol
source .venv/bin/activate
pytest -q
WEALL_DEVNET_SUITE_RUN_TIER2=1 \
WEALL_DEVNET_SUITE_RUN_LIVE=1 \
bash scripts/devnet_controlled_readiness_suite.sh
```

Truth boundary: this is a local two-node rehearsal on one machine. It is stronger than the seeded browser demo, but it is not a public multi-validator adversarial network proof.

---

## Useful Local URLs

Backend:

```text
http://127.0.0.1:8000
```

Frontend:

```text
http://127.0.0.1:5173
```

Backend readiness:

```text
http://127.0.0.1:8000/v1/readyz
```

Backend status:

```text
http://127.0.0.1:8000/v1/status
```

API docs, when enabled by the local backend:

```text
http://127.0.0.1:8000/docs
```

---

## Demo Surfaces to Check

After the fresh-clone boot completes, useful frontend routes include:

```text
/feed
/activity
/decisions
/reviews
/account-verification
/profile
```

Suggested manual smoke test:

1. Open the frontend.
2. Load the demo tester session.
3. Open the feed.
4. Confirm the seeded demo post is visible.
5. Open the public activity notices.
6. Open decisions.
7. Open reviews.
8. Report content from the feed.
9. Open the assigned review.
10. Accept the review assignment.
11. Test Keep Post / Remove Post behavior.

---

## Development Checks

From the backend directory:

```bash
cd Weall-Protocol

pytest
python3 -S scripts/check_tx_canon_artifacts.py
bash scripts/secret_guard.sh
bash scripts/verify_release_tree.sh
bash scripts/verify_release_dependencies.sh
```

From the frontend directory, with the backend running at `http://127.0.0.1:8000` for the contract check:

```bash
cd web
npm ci
API_BASE=http://127.0.0.1:8000 npm run contract-check
npm run typecheck
npm run build
```

These checks should pass before committing release-relevant changes.

---

## Cleaning Local Runtime Artifacts

The local demo creates runtime state, generated demo files, containers, and temporary development artifacts.

To stop the backend containers:

```bash
cd Weall-Protocol
docker compose down --remove-orphans
```

Before committing, remove local runtime artifacts and re-run release checks.

Common files that should not be committed include:

- local SQLite databases
- local BFT journal files
- local helper lane directories
- local dev bootstrap secrets
- frontend build artifacts
- `node_modules`
- `.venv`
- `.env`
- `.env.local`
- generated demo bootstrap secrets

---

## Repository Layout

High-level structure:

```text
.
├── scripts/
│   └── dev_boot_full_stack.sh
├── web/
│   ├── src/
│   └── public/
└── Weall-Protocol/
    ├── src/weall/
    ├── scripts/
    ├── specs/
    ├── generated/
    ├── tests/
    └── docker-compose.yml
```

The repository currently contains both protocol/backend code and frontend application code.

---

## Protocol Areas Under Active Work

Current active areas include:

- deterministic transaction execution
- transaction canon synchronization
- account/session handling
- protocol-native human verification
- role and responsibility gating
- content posting and media declaration
- reporting and review flows
- decision/governance flows
- local full-stack reproducibility
- frontend human-readable UX
- production-readiness audits

---

## Frontend Direction

The frontend should avoid exposing protocol internals to ordinary users by default.

Preferred user-facing language includes:

- Account Verification
- Verified Person
- Trusted Verified Person
- Decisions
- Reports
- Reviews
- Trusted Responsibilities
- Community Reviewer

Advanced protocol details may still be available for developers, reviewers, and operators, but they should not dominate normal social flows.

---

## Security and Production Notes

This repository is still under active development.

Do not use this code to run production funds, public validator infrastructure, or irreversible public governance without additional review.

Before any public production deployment, the project still needs deeper validation, including:

- additional multi-node public-validator beta testing
- adversarial consensus review
- persistence and restart rehearsals
- role/gate bypass testing
- frontend/backend authority review
- privacy review
- deployment rehearsals in a fresh operator environment
- operator documentation review
- external security review

---

## License

WeAll Protocol is licensed under the Mozilla Public License 2.0. See `LICENSE`.

---

## Current Summary

WeAll currently has a working local fresh-clone demo path and a production-candidate backend posture with synchronized transaction canon, release-hygiene gates, dependency locks, adaptive Live PoH, scheduler-bound SYSTEM tx replay, and helper execution root commitment.

That means the project can now be cloned, booted, inspected, and audited as a running deterministic social coordination protocol prototype.

The next major work is a final public-validator beta readiness rehearsal: fresh-clone operator packaging, multi-node launch practice, documentation review, and external security review before any public production network claims.



## Public beta evidence boundary

Current release posture remains: controlled multi-node testnet candidate.
Do not claim public beta, mainnet, public validator enablement, live economics,
production helper execution, public storage-market readiness, or legal/compliance
readiness until the external transcript requirements in
`Weall-Protocol/generated/external_operator_transcript_requirements_v1_5.json`
and `Weall-Protocol/docs/PUBLIC_BETA_EXTERNAL_EVIDENCE_RUNBOOK.md` are satisfied.

Current tx canon checkpoint: 236 tx types, version 1.25.0.
