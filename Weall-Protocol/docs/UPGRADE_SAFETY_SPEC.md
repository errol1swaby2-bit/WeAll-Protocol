# WeAll Upgrade Safety Specification

## Authority boundary

Governance may declare and schedule an upgrade. A protocol transaction does not fetch binaries, execute code, migrate state, restart a process, or roll back software. Operators install a reviewed release whose manifest is bound to the approved target.

## Version domains

The release manifest must distinguish protocol version, transaction-canon version/hash, persisted state version, database schema version, consensus-profile hash, frontend contract version, and evidence schema version. Compatibility must be evaluated per domain rather than by one ambiguous version string.

## Compatibility rules

- New code may read an older state only through a registered deterministic migration path.
- Old code must reject a newer unsupported state before participating in consensus.
- Pre-activation transactions use the old canon and remain replayable after migration.
- Post-upgrade transactions are rejected before activation.
- Explicit compatibility breaks require a release declaration, activation boundary, migration plan, and operator acknowledgement.
- Observers may remain read-compatible only when their state and message decoders explicitly support the active version.

## Migration rules

- Migrations operate on a deep copy and never mutate caller state on success or failure.
- Each step advances exactly one state version.
- Inputs and outputs are canonical-serialized and hashed.
- A failed step writes nothing.
- Migration fixtures are immutable and include source hash, target hash, step list, and expected receipt.
- The production migration executor must run in one exclusive offline transaction after an immutable backup.
- State-root changes caused by migration are recorded as an operator/release event and cannot masquerade as a normal block transition.

## Activation rules

- Declaration identifies target version, artifact digest, compatibility statement, required migration, earliest activation height, and rollback boundary.
- Activation is scheduled in the future and is idempotent only for an identical record.
- Nodes advertise supported protocol, canon, state, and message versions before activation.
- A node unable to support the target must stop signing before the activation boundary.
- Software switches behavior only at the finalized activation boundary defined by the release implementation.

## Failed upgrade behavior

- Preflight failure leaves the old node and state authoritative.
- Migration failure leaves the original database untouched.
- Partial network readiness does not change the finalized validator set automatically.
- A node with unsupported persisted state fails closed before mempool, proposal, voting, or block production.

## Rollback boundaries

Rollback may restore an immutable pre-migration checkpoint only before any finalized post-upgrade block depends on the new semantics. After that boundary, recovery requires a new governed upgrade or replay from a valid checkpoint. On-chain activation metadata does not itself execute rollback.

## Required receipts

Release manifest receipt, artifact-digest verification, preflight compatibility receipt, backup checkpoint receipt, migration input/output receipt, activation-boundary receipt, first-finalized-block receipt, cross-node convergence receipt, and rollback/recovery disposition.

## Required tests

1. Old state loaded by new code through explicit migration rehearsal.
2. Unsupported new state rejected by old code.
3. Pre-upgrade transactions replay after migration.
4. Post-upgrade transactions rejected before activation.
5. Failed migration leaves original bytes unchanged.
6. Repeated migration produces identical bytes and hashes.
7. Cross-node convergence after activation.
8. Upgrade receipts are complete and canonical.
9. Rollback boundary is enforced.
10. Generated specs and semantic reviews remain synchronized.
11. Old/new node protocol negotiation is deterministic.
12. Observer decoding remains compatible or fails explicitly.

## Current implementation disposition

Record-only governance activation and deterministic migration unit tests exist. Migration copy-on-write and exact version advancement are enforced. Production ledger loading does not currently execute the migration registry, and no approved offline migration executor exists. Automatic execution remains disabled.
