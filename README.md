# WeAll Protocol

WeAll is an experimental deterministic coordination protocol and social application prototype.

The current repository demonstrates a local, fresh-clone, one-command development flow that boots a full local demo environment, seeds a demo account, and shows core social coordination surfaces in the frontend.

WeAll is **not production-ready yet**. This repository should currently be treated as a local development and demo environment, not as a public validator network or production social platform.

---

## Current Status

The current development milestone proves that a fresh clone can:

- create the local backend environment
- install required dependencies
- build the Docker backend stack
- start the local node services
- start IPFS/Kubo
- generate the transaction index
- run the golden-path bootstrap
- create a pre-seeded demo account
- upload media
- create a post
- seed demo social, decision, review, and messaging state
- start the frontend
- show core demo flows in the browser

This is a reproducibility milestone for local development and demonstration.

It is **not** a claim of production validator readiness, public network readiness, security-audited deployment, or adversarial multi-node safety.

---

## Project Direction

WeAll is being designed as a familiar social application with deterministic protocol state underneath.

The product goal is to support:

- social posting
- media upload
- groups
- messaging
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
- inbox control
- DNS verification
- SMTP infrastructure
- CAPTCHA
- OAuth
- KYC providers
- government ID providers
- centralized identity providers as required gates

The goal is to make human verification part of the protocol process itself through challenge, evidence commitment, juror review, threshold finalization, receipts, and deterministic state transitions.

This area is still under active implementation and review.

---

## What Works in the Local Demo

The current local demo can show:

- a pre-seeded demo account
- account verification state
- a social feed
- media-backed posts
- post detail pages
- reporting content
- review assignment flow
- review outcome flow
- community decisions
- messaging surfaces
- frontend/backend session handoff
- deterministic demo bootstrap output

The demo is intended to make the current architecture inspectable and easier to test.

---

## What Is Not Claimed Yet

This repository does **not** currently claim:

- production readiness
- public validator readiness
- adversarial multi-node readiness
- full security audit completion
- economic activation readiness
- public mainnet readiness
- stable public API guarantees
- final protocol semantics
- complete frontend product maturity

Those require additional testing, review, hardening, documentation, and operational validation.

---

## Current Verification Checkpoint

This repository snapshot is synchronized at:

- **Transaction canon:** 225 tx types, version 1.24.0
- **Current posture:** local development/demo prototype, not production validator readiness
- **Release checks:** tx canon synchronization, secret guard, and release-tree hygiene should pass before publishing changes

This checkpoint is included so reviewers can compare the public README against the generated transaction-canon artifacts without treating the repository as production-ready.

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
/messages
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
5. Open messages.
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

python3 -S scripts/check_tx_canon_artifacts.py
bash scripts/secret_guard.sh
bash scripts/verify_release_tree.sh
```

From the frontend directory:

```bash
cd web
npm run build
```

These checks should pass before committing changes.

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

- multi-node testing
- adversarial consensus testing
- persistence and restart testing
- role/gate bypass testing
- frontend/backend authority review
- privacy review
- deployment hardening
- operator documentation
- external security review

---

## License

WeAll Protocol is licensed under the Mozilla Public License 2.0. See `LICENSE`.

---

## Current Summary

WeAll currently has a working local fresh-clone demo path.

That means the project can now be cloned, booted, and inspected as a running social coordination prototype from scratch.

The next major work is to keep hardening the protocol, frontend, testing, and operator path without overstating production readiness.

