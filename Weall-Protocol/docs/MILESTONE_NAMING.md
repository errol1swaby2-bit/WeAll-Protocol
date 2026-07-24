# WeAll Milestone Naming and Closure Status

Status: canonical milestone identifier guide.

Last updated: 2026-07-24.

## Why this document exists

The repository historically used overlapping milestone numbers for two
different work programs:

1. specification-control work packages; and
2. reviewer and implementation readiness tracks.

Unqualified references such as "Milestone 1" are therefore ambiguous.
Repository documentation, pull requests, reports, and public statements
must use the identifiers below.

## Canonical identifiers

### Spec-M1 / W1.1 — v2 specification-control plane

This is the specification milestone closed through the W1.1 validation
and provenance controls.

Its scope includes the retained and hash-bound v2 specification PDF,
structured registers and schemas, semantic-review bindings, stable-ID
history, provenance, generated derivatives, and clean-checkout
reproduction.

Spec-M1 is closed within its recorded truth boundary. It does not claim
runtime completion, independent launch review, public-testnet
authorization, or Mainnet authorization.

### R-M1 — reviewer observer-onboarding track

This is the reviewer-roadmap milestone for clean-clone observer
preparation, observer authority locking, and real remote signed observer
onboarding.

R-M1 is distinct from Spec-M1. R-M1 remains open until the real remote
signed observer gate is captured against an actual genesis API.

### M2 / R-M2 — account custody, recovery, and Proof-of-Humanity onboarding

This is the controlled-testnet implementation milestone covering:

- account custody and recovery-file flows;
- account recovery and reversal;
- async Tier 1 Proof-of-Humanity;
- live Tier 2 Proof-of-Humanity;
- restricted evidence lifecycle;
- reviewer replacement and runbooks;
- restart/replay, two-node equality, and observer catch-up;
- outside-tester onboarding evidence.

M2 is closed only through the two-commit implementation-freeze and
evidence-only protocol documented in
`docs/production_readiness/M2_CLOSURE_PROCESS.md`.

The authoritative current closure binding is
`artifacts/m2-closure/M2_EVIDENCE_MANIFEST.json`.

### R-M3 through R-M6 — later reviewer-readiness tracks

These identifiers cover the later social/governance, economics,
validator/BFT, and documentation/external-review work described in
`docs/REVIEWER_MILESTONE_GUIDE.md`.

They are not included in Spec-M1 or M2 closure.

## Closure language

Use:

- "Spec-M1 / W1.1 is closed."
- "M2 / R-M2 is closed at the implementation freeze recorded in the
  current M2 evidence manifest."
- "R-M1 remote signed observer onboarding remains open."

Do not use the unqualified statement "Milestone 1 is closed" because it
does not identify whether the statement refers to Spec-M1 or R-M1.

## Roll-forward rule

A valid historical evidence pair remains valid for its recorded freeze.

When source, configuration, tests, specifications, generated canon, or
closure-relevant documentation changes after that freeze, claiming
closure for the newer tree requires a new implementation-freeze commit
and a new evidence-only direct child.

A later merge commit may represent the same closed tree only when:

- the evidence-only commit remains in its ancestry;
- the merge introduces no additional tree changes; and
- the merge tree is byte-for-byte equal to the evidence-only commit.
