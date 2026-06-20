# Batch 315 — Final Production Truth Sync

## Purpose

Batch 315 synchronizes public-facing documentation with the current post-hardening repository state after Batches 309 through 314. This file has also been truth-synced after the later executor/runtime refactor evidence pass.

## Current checkpoint

- Transaction canon: 233 tx types, version 1.25.0
- Latest full backend test checkpoint: 3636 passed, 3 warnings
- Backend release locks: `requirements.lock`, `requirements-dev.lock`
- Frontend release lock: `web/package-lock.json`
- Frontend checks verified: `npm ci`, contract check against local backend, typecheck, production build
- Release gates verified: tx canon sync, secret guard, release tree, dependency locks

## Protocol hardening now reflected in docs

### Adaptive Live PoH quorum

Live PoH uses deterministic integer quorum logic that can bootstrap from a small genesis reviewer set and scale to a full panel:

- up to 10 total jurors
- up to 3 active reviewers
- up to 7 watchers
- default threshold uses integer `n-of-m` arithmetic

### SYSTEM tx replay binding

Follower-side block replay rejects mutating SYSTEM txs that are not bound to deterministic scheduler output before apply.

### Helper execution root

Helper execution metadata is committed by `helper_execution_root` when present, preventing uncommitted helper metadata from being changed without changing the block/header commitment.

### Dependency locking

Backend and frontend dependency locks are now part of the release posture and must pass `scripts/verify_release_dependencies.sh`.

## Production posture after this sync

The repository is production-candidate protocol software suitable for local demo, controlled devnet review, and public-validator beta preparation.

It does not yet claim public mainnet readiness. Final public production launch still requires:

- fresh-clone operator rehearsal on a clean host
- public-validator beta drill
- multi-node launch rehearsal
- external security review
- final incident-response and operator documentation review
