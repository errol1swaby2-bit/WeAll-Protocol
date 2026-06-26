# WeAll Protocol Truth Boundary

Status: reviewer submission and external-review truth boundary.

Last reviewed: 2026-05-29.

This document defines what the current repository may claim, what it must not claim, and what remains milestone work. It is intended to prevent accidental overclaiming during reviewer review, external observer onboarding, public testnet preparation, and future production-readiness work.

## Current posture

WeAll should currently be described as:

> A free/open-source Layer 1 coordination protocol implementation that has reached private/local and external-observer rehearsal readiness, with release hygiene gates, tx canon coverage, account custody flows, Proof-of-Humanity verification flows, content/group/review/governance surfaces, local block-production proof, observer authority locking, and locked tokenomics/wallet/reward/tipping invariants.

WeAll should **not** currently be described as:

- public mainnet ready;
- public multi-validator BFT ready;
- public adversarial validator ready;
- live-economics ready;
- protocol-native non-public social surfaces removed; public activity notifications only;
- a public user launch;
- a finalized constitutional governance deployment;
- a complete self-bootstrapped public Proof-of-Humanity network.

## What can be claimed now

The following claims are acceptable when backed by fresh command output from the current commit.

| Area | Safe claim | Required evidence |
|---|---|---|
| Transaction canon | Tx canon artifacts are synchronized and generated tx contract coverage exists. | `python3 -B -S scripts/check_tx_canon_artifacts.py` |
| Release hygiene | The exported/release tree can be checked for generated artifacts, local runtime state, SQLite files, secrets directories, frontend build artifacts, and other release blockers. | `bash scripts/verify_release_tree.sh` |
| Secret hygiene | Release-relevant files can be scanned for committed secret material. | `bash scripts/secret_guard.sh` |
| Dependency locks | Backend and frontend lockfiles are present, pinned, and hashed. | `bash scripts/verify_release_dependencies.sh` |
| Reviewer gate | The targeted production-readiness reviewer gate exercises the bounded reviewer suite. | `bash scripts/reviewer_production_readiness_gate.sh` |
| Frontend type safety | The web frontend typechecks after clean dependency installation. | `cd ../web && npm ci && npm run typecheck` |
| Account custody | The frontend has local key generation, recovery-file creation, recovery verification, restore handling, and signed transaction session wiring. | `web/src/auth/*`, `web/src/pages/LoginPage.tsx`, `web/scripts/test_account_custody_source.mjs` |
| Proof of Humanity | Async/live PoH txs, APIs, frontend surfaces, review/finalization flows, and tier-gated follow-up flows exist and are test-covered in bounded suites. | PoH tests, reviewer tests, API/frontend source checks |
| Content and groups | Posting, media surfaces, feed visibility, group creation, and group membership are implemented for rehearsal/testnet flows. | content/group tests, frontend source checks, local rehearsal evidence |
| Dispute/review/governance | Dispute, review, appeal/procedure, proposal, comment, vote, finalization, and constitutional-clock surfaces exist for testnet review. | dispute/governance/procedure tests and docs |
| Local block production | A local block-production proof can commit root-bearing local block evidence. | `PYTHONPATH=src python3 scripts/production_block_production_rehearsal_gate.py` |
| Observer safety | Local observer preconditions and authority lock gates disable validator signing, BFT, helper authority, and block-loop authority for observer posture. | `bash scripts/local_observer_readiness_gate.sh`; `bash scripts/external_observer_authority_lock_gate.sh` |
| Locked tokenomics | Wallet, transfers, tips, reward mint/distribution, treasury allocation, cap/halving policy, and economics activation gates exist as locked/testnet-safe mechanics. | tokenomics/economics tests and docs |

## What is visible or implemented but locked

The following areas may be described as **visible/locked**, **implemented/locked**, or **test-state only**. They must not be described as live production economics.

| Area | Correct status phrase |
|---|---|
| `ECONOMICS_ACTIVATION` | Implemented activation path, locked before governance/testnet activation. |
| `BALANCE_TRANSFER` | Implemented transfer contract, blocked before economics activation. |
| Content tipping | Implemented as locked/testnet-safe transfer purpose and tip index, blocked before economics activation. |
| Reward mint/distribution | Implemented and gated; not live before economics activation. |
| Treasury reward allocation | Present in reward accounting; not live treasury spending. |
| Wallet balances | Display/read-model surface exists; UI must distinguish confirmed, unknown, and locked states. |
| Fee policy | Civic/social/governance actions must remain fee-free; economic fees are not live by default. |

## What cannot be claimed yet

The following claims require additional proof before they appear in public-facing or funder-facing language.

| Claim not allowed yet | Proof required first |
|---|---|
| First trusted external observer readiness | `scripts/first_external_observer_reproducibility_gate.sh` must pass with both remote preflight and signed observer onboarding enabled against a real genesis API. |
| Public observer testnet readiness | Clean clone boot, signed remote observer onboarding, hosted genesis posture, tester runbook, reporting loop, and repeatable sync evidence. |
| Public multi-validator BFT readiness | Multi-validator HotStuff/BFT convergence, validator churn, equivocation resistance, partition/rejoin, restart/replay, and adversarial tests. |
| Mainnet readiness | Public BFT, public governance, security review, external tester cycle, economics launch governance, operator runbook, and incident response proof. |
| Live economics | Governance-approved economics activation after the protocol lock, accounting proof, UI truth-sync, and public testnet economics rehearsal. |
| Production helper execution | Serial-equivalence, deterministic helper assignment, deterministic lane partitioning, canonical ordering, verifiable receipts, deterministic merge, crash safety, Byzantine helper rejection, and multinode adversarial tests. |

## External observer truth boundary

Passing `scripts/local_observer_readiness_gate.sh` means local preconditions are ready.

Passing `scripts/external_observer_authority_lock_gate.sh` means observer posture disables validator/service authority locally.

Passing `scripts/first_external_observer_reproducibility_gate.sh` without remote environment variables proves only local preconditions. It does **not** prove signed remote observer onboarding.

The first trusted external observer readiness claim requires all of the following:

```bash
export WEALL_RUN_TWO_MACHINE_OBSERVER_PREFLIGHT=1
export WEALL_RUN_SIGNED_OBSERVER_ONBOARDING=1
export WEALL_GENESIS_API_BASE=http://GENESIS_HOST:8000
export WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE=/path/to/public-observer-bundle.json
bash scripts/first_external_observer_reproducibility_gate.sh "$WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE"
```

For a LAN rehearsal, `WEALL_ALLOW_LAN_GENESIS_API=1` may be used only when the documentation clearly says this is not a public HTTPS deployment.

## Block production and BFT truth boundary

The local block-production proof is meaningful but narrow.

It can prove:

- local block-loop operation;
- committed local height evidence;
- block ID/hash evidence;
- state root evidence;
- receipt root evidence.

It does not prove:

- public multi-validator BFT;
- production validator authority safety;
- adversarial network safety;
- public validator onboarding;
- public mainnet readiness.

Any local block-production evidence must preserve this language:

> Local block-production evidence only; public multi-validator BFT still requires a separate adversarial proof.

## Documentation language rules

Use these phrases:

- private/external-observer rehearsal readiness;
- local block-production proof;
- visible/locked tokenomics;
- locked/testnet-safe economics;
- public-testnet milestone work;
- BFT readiness remains future milestone work;
- mainnet readiness is not claimed.

Avoid these phrases unless they are directly negated or marked future work:

- mainnet ready;
- public BFT ready;
- live economics;
- production-ready governance;
- public launch ready;
- fully decentralized moderation complete;
- complete HotStuff deployment.

## reviewer framing

The correct reviewer framing is:

> WeAll has crossed from specification into a serious, reviewable implementation with reproducible local/reviewer gates and private/external-observer rehearsal evidence. Funding will move it into a documented public testnet with external observers, Proof-of-Humanity verification, content/groups, dispute/review, governance, locked testnet tokenomics, deterministic block progression, validator promotion, and eventually adversarial multi-validator BFT readiness.

## Work-after-submission boundary

After reviewer submission, development may continue safely if the submitted evidence is versioned and the application remains honest about which commit was submitted.

Required practice:

1. Tag or record the exact submitted commit.
2. Save the evidence transcripts used in the application.
3. Continue work on normal branches or main after submission.
4. Do not rewrite the submitted evidence after the fact.
5. If reviewer asks for clarification, state which improvements happened after the submitted commit.

This lets the project keep moving quickly without confusing reviewers about what was true at submission time.
