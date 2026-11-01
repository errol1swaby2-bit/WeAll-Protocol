# PR77 full DISPUTE_VOTE_SUBMIT legacy-vote migration differential

Status: **synthetic, independent-executor comparison; no semantic approval**.

The A02 fixture sets up a valid accepted juror, then a controlled-devnet
strict ballot profile (not a public activation). In the adversarial arm, an
older attributable vote by another account contains a nested resolution.
The next real `DISPUTE_VOTE_SUBMIT` transaction triggers the handler's
legacy-vote migration. The same transaction executes through the actual
bounded-rollback and deepcopy entry points.

The negative control has no legacy vote and is required to have parity.
The legacy-resolution arm requires parity but is marked strict expected-failure
until adjudicated: an XFAIL documents an unresolved consensus-sensitive difference,
not a passed readiness gate. An XPASS must fail for explicit review.

This test is not a preserved historical ledger, authentic old software replay,
cross-node proof, or permission to rewrite any past commitment. No production
gate, V1.5 generated lifecycle manifest, V2 semantic digest or consensus hash
implementation is changed.

Closure needs the exact changed state paths, commitment hashes and old-version
compatibility analysis, preferably using retained blocks and an authorized
protocol-version boundary before modifying canonical hash inputs.

## Observed complete-transaction divergence and rejected-transaction rollback failure

The controlled-devnet synthetic legacy vote run under commit
`28ec8f380be2cffe623554f825f2cd24c4dae71d` returned identical
metadata but different successful-transaction commitments:

- bounded resolution-option digest: `93ed8c5475857d7e8321813b57ed98ac0914ab5870f0121bc9af55028b677188`
- reference resolution-option digest: `9756a362c87fc522082b580733c75ba12c19cbce058ffc9429ec47f8cfa8ee7`
- bounded final root: `14d51e19acbd321713141d2359541d67c2a13cc61ad1a8a47751e21f0f9e87c3`
- reference final root: `547a9561d9b9e93af8c293eeaa56c7470a5775f24db2647a3ec3130c31178ac6`

A second scenario seeds a legacy vote **by the submitting juror**. Both
executors reject this duplicate with `dispute_ballot_already_final`. However
on bounded rollback, `/disputes_by_id/a/votes/@juror1` disappears after
rejection; the entire pre-state is restored under deepcopy reference execution.
Synthetic pre-state root:
`7aca4b6b4772dba5e751258f42b3ff9ecf50bf5d9f7c8b980f722fe3bd1c2645`.
Bounded post-rejection root:
`37295c3f80404d45e3ea0992e6d9440bfa19466d79cfa63cbb6504a632fdb8cb`.
Deepcopy post-rejection root equals the pre-state root.

A minimal independent journal regression clears a child dictionary, replaces
the containing parent entry, then raises. It is marked strict XFAIL pending
review. The probable mechanism is a late parent snapshot of the cleared child,
which is later restored by identity-disconnected deepcopy while earlier child
undo operations restore the original detached object. Treat this explanation
as a targeted hypothesis until the minimal regression and CI confirm it.

**NO-GO is stronger than before:** These are both successful-apply and
failed-apply state-root concerns. Do not silently normalize hash inputs or
adjust journal restoration, even if such changes appear correct under
current fixtures. They can change replay outcomes for previously committed
blocks containing matching paths. Obtain pinned archived blocks and old
executor policy, select and review a chain-committed version/activation
boundary if required, and verify both success and failure receipts and
post-height state roots. Keep the full-transaction rollback CI check red
until the state is restored exactly.
