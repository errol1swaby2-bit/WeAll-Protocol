# WeAll Protocol

## Public observer testnet discovery gate

Batch 626 adds a fail-closed public observer discovery layer. Public observer mode is explicit (`WEALL_PUBLIC_TESTNET=1`) and requires a valid public seed registry with pinned `network_id`, `chain_id`, `genesis_hash`, `protocol_profile_hash`, `tx_index_hash`, seed API URLs, seed P2P URLs, `resettable_testnet: true`, and `economics_active: false`.

Use `Weall-Protocol/configs/public_testnet_seed_registry.example.json` and `Weall-Protocol/docs/PUBLIC_OBSERVER_TESTNET_QUICKSTART.md` before claiming public observer launch readiness. The testnet remains resettable and non-economic; observer access can be open, but validator activation, signing authority, storage provider status, juror roles, governance authority, and reputation-sensitive roles remain protocol-gated.


WeAll is an experimental deterministic coordination protocol and social application prototype.

The current repository demonstrates a local, fresh-clone, one-command development flow that boots a full local demo environment, seeds a demo account, and shows core social coordination surfaces in the frontend.

WeAll is **production-candidate protocol software under active hardening**, with a working local demo and green release checks. It should still not be treated as a public mainnet, public user launch, or irreversible production governance system without a final public-validator beta rehearsal and external security review.

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

This area is implemented as the current protocol-native direction and remains under active review and hardening.

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

- public mainnet readiness
- public user/social launch readiness
- full external security audit completion
- economic activation readiness
- stable public API guarantees
- final protocol semantics
- complete frontend product maturity

Those require additional testing, review, hardening, documentation, and operational validation.

---

## Current Verification Checkpoint

This repository snapshot is synchronized at:

- **Transaction canon:** 236 tx types, version 1.25.0
- **Latest full backend test checkpoint:** `3405 passed, 2 warnings`
- **PoH posture:** two-tier native async/live human verification; no required email, Cloudflare, SMTP, DNS, CAPTCHA, OAuth, KYC provider, or government ID provider
- **Live PoH quorum:** adaptive integer `n-of-m` threshold, up to 10 jurors, up to 3 active reviewers, up to 7 watchers
- **Consensus authority hardening:** follower-side SYSTEM tx replay binding is enforced against deterministic scheduler output before apply
- **Helper hardening:** helper execution metadata is block-header committed through `helper_execution_root`
- **Dependency posture:** backend lockfiles and frontend `package-lock.json` are present and release-verified
- **Release checks:** tx canon synchronization, secret guard, release-tree hygiene, and dependency-lock verification should pass before publishing changes

This checkpoint is included so reviewers can compare the public README against generated artifacts without treating the repository as public-mainnet-ready.

---

## Reviewer Starting Point

For architecture and readiness review, start with these documents:

1. `Weall-Protocol/docs/TRUTH_BOUNDARY.md` — current claim boundaries and what is not yet claimed.
2. `Weall-Protocol/docs/REVIEWER_MILESTONE_GUIDE.md` — milestone-oriented review guide and remaining proof path.
3. `Weall-Protocol/docs/REVIEWER_EVIDENCE_INDEX.md` — command evidence checklist and transcript expectations.
4. `RELEASE_CHECKLIST.md` — release and external tester packaging checks.
5. `Weall-Protocol/docs/EXECUTOR_REFACTOR_MODULE_BOUNDARIES.md` — runtime/executor refactor boundary map.

The expected reviewer path for protocol-native verification is the controlled-devnet same-machine rehearsal below. The seeded demo path remains useful for fast UI review, but it is not the primary protocol proof path.

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



## Batch 620 public-beta evidence boundary

Current release posture remains: controlled multi-node private testnet candidate.
Do not claim public beta, mainnet, public validator enablement, live economics,
production helper execution, public storage-market readiness, or legal/compliance
readiness until the external transcript requirements in
`Weall-Protocol/generated/external_operator_transcript_requirements_v1_5.json`
and `Weall-Protocol/docs/PUBLIC_BETA_EXTERNAL_EVIDENCE_RUNBOOK.md` are satisfied.
