# M1–M3 Testing Architecture

## Principles

1. Runtime code and controlling specifications are authoritative; generated files are derivatives.
2. Source readiness and formal evidence closure are separate truth states.
3. Security-sensitive tests traverse schema, canonical admission, apply, state mutation, receipt, and replay.
4. Fixtures declare provenance and ownership.
5. Check-only commands never modify the tree.
6. Live evidence is fresh, freeze-bound, signed, and never copied from another freeze.

## Levels

### Level A — Static contract checks

Canonical transaction synchronization, strict schema structure, generated freshness, semantic-review digests, requirement path validity, public-only policy, failure-code registry, secret scanning, and evidence-path scope.

### Level B — Unit tests

Normalization, gate atoms, membership modes, authority storage, deterministic helpers, serialization, migration functions, and rollback boundaries.

### Level C — Admission plus apply

Every security-sensitive transaction asserts schema verdict, gate verdict, signer eligibility, apply result, state mutation, receipt fields, nonce/replay behavior, and deterministic rejection code.

### Level D — Stateful workflows

Group creation/membership, dispute and appeal, governance frozen electorates, reviewer qualification, duplicate/replacement/revocation attempts, and required negative subjects.

### Level E — Cross-node and replay

State roots, mempool/block convergence, restart replay, observer reconciliation, helper serial equivalence, and upgrade-boundary replay.

### Level F — Clean checkout

Locked dependencies, no ambient files, no ignored private fixtures, deterministic generation, frontend typecheck/build, and closure commands from an isolated worktree.

### Level G — Signed evidence

Fresh private actors, real signatures, authentic transaction IDs, live state assertions, public transcript, private custody checkpoint, freeze binding, checksums, and evidence-only commit validation.

## Fixture ownership

- Unit fixtures live with tests and contain no private keys.
- Deterministic migration fixtures include declared source/target versions and canonical hashes.
- Live actor manifests remain outside Git and contain custody references, not public evidence copies.
- Public evidence contains only redacted actor identifiers, transaction IDs, public keys where intended, receipts, and checksums.
- Historical evidence is immutable and never overlaid into a replacement-freeze claim.

## Worktree behavior

Source and evidence stages run in isolated worktrees. Commands resolve repository paths from their own script location, never the caller’s current directory. Formal stages require exact HEAD equality, clean status, and an evidence-free implementation tree. Cleanup traps remove only temporary worktrees created by the current process.

## Generated artifacts

Generators declare sources, outputs, check mode, and regeneration order. Semantic changes require explicit review records; line-binding-only changes remain distinguishable. Check mode compares bytes and never writes. A generated artifact may prove internal consistency but cannot override runtime behavior or the controlling specification.

## Upgrade tests

Migration tests are copy-on-write and deterministic. Production activation remains record-only until an explicit offline migration executor is implemented. Required future integration tests cover old-state/new-code startup, unsupported-new-state rejection by old code, pre/post activation transaction behavior, failed migration atomicity, multi-node convergence, protocol negotiation, operator receipts, and rollback limits.

## Closure stages

1. Read-only identity and inventory.
2. Source audit and contradiction register.
3. Narrow source correction.
4. Semantic review and deterministic regeneration.
5. Targeted then broad source tests.
6. Upgrade and migration tests.
7. Clean-checkout backend/frontend rehearsal.
8. Source commit and implementation freeze record.
9. Fresh actor qualification and signed M3 journey.
10. Evidence construction and validation.
11. Cumulative M1–M3 closure.
12. Direct-child evidence-only commit and committed validation.

## Failure classification

Every gate emits one primary class: source defect, test defect, fixture defect, stale generated artifact, missing evidence, environment/dependency failure, or operator prerequisite failure. Secondary failures must not obscure the root cause.
