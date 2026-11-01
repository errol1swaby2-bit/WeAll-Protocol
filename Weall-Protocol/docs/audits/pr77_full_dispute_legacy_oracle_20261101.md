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
