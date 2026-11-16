# PR #93 — A03 read-only V2 semantic reconciliation increment

**Pinned source commit before change:** `ec52b0d770eb9485df446b84f57da6347c90925f`. **Status: review triage only; no accepted semantic-review changes, no constitutional approval, no network activation.**

## Exact-head evidence

At commit `ec52b0d770eb9485df446b84f57da6347c90925f`, the strict V2 compiler used by Backend CI and Reviewer Readiness still fails with `route semantic-review inventory does not exactly cover current rows` ([Backend CI](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/43940932756), [Reviewer Readiness](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/43940932524)). The previously registered `GET /v1/public-lobby/comments` has source identity `ROUTE-63E26182B51EAFCB` but no corresponding accepted route semantic-review entry. The previous 20 transaction review drifts remain a *separate* review gate; existing PR88 and PR77 review packets contain the source-dependent authority and failure-code holds.

This increment adds a **read-only** inventory that scans actual API route ASTs, canonical transaction handlers, the archived generated route map, and existing semantic-review records. It enumerates missing route reviews, stale digests, identity mismatches, orphaned reviews, duplicate stable IDs, and newly added route implementations, without generating or accepting a digest.

## Command

```bash
cd Weall-Protocol
PYTHONPATH=src:scripts python scripts/pr93_v2_semantic_review_inventory.py
PYTHONPATH=src:scripts python -m pytest -q tests/test_pr93_v2_semantic_review_inventory.py
```

The report's `candidate_digest_not_approved` is a **review input**, not an authorization. `accepted_reviews_modified`, `historical_replay_proven`, and `constitutional_or_release_authority_granted` must remain `false`.

## Unresolved reviewer decisions

1. Establish exact public-lobby anonymous read, malformed target/cursor, visibility/moderation, pagination and rate-limit semantics before a named maintainer accepts the route contract.
2. Independently adjudicate every transaction whose static digest differs from the checked-in accepted record, particularly `DISPUTE_OPEN` indirect validation, severe sanctions, voter/emissary state transitions, and branch-specific role/reviewer eligibility.
3. Keep `specs/v2/source/semantic_reviews.json` and `generated/v2/` untouched until decisions are individually recorded and the real compiler is rerun from a clean checkout.
4. Do not weaken the compiler's fail-closed inventory check or equate local `confirmed` inclusion with independently verified BFT finality.

The P0 acceptance gate is **still open**. Existing proof/contract tests remain required; no external review or constitutional launch decision is claimed.
