# PR77 — DISPUTE_OPEN V2 semantic attribution investigation (no review accepted)

All three red PR77 CI workflows currently fail at the same V2 semantic-review
digest: `DISPUTE_OPEN`. Backend CI also attempts to upload a P0 assurance
artifact after the compilation step has failed.

**Verified source comparison:** `def dispute_open` and `def apply_dispute`
in `src/weall/runtime/apply/dispute.py` are textually identical between
`main` and PR77 at `3de576f5ce0bb1efd628a8f2086300a3867be07d`.

**Root-cause candidate:** `tx_appliers.json` bound `DISPUTE_OPEN` to the
generic `apply_dispute` dispatcher, while all sibling dispute transactions
had direct bindings to their actual handlers. The V2 static analyzer only
prefers `apply_*`/`_apply_*` callees during dispatch branch extraction and
otherwise transitively visits up to 24 local functions, potentially
attributing unrelated severe-sanction and appeal code changes to
`DISPUTE_OPEN`. This patch fixes the *source registry* to bind directly to
`dispute_open` and adds a static analyzer regression test.

**No review digest was altered.** The V2 compiler must still report stale
accepted material until the new, narrowly scoped contract fields are
inspected against the previous generated contract and explicitly accepted by
the authorized reviewer. The diagnostic workflow reports all stale review
types and exact field differences without changing review or derivative
files. Another failure may be revealed after DISPUTE_OPEN acceptance.

The correction to the V2 source registry is analytical only. It does not
change runtime transaction dispatch, constitutional authority, activated
protocol behavior or ACCOUNT_BAN fail-closed gates. PR77 remains Draft.

## Diagnostic pipeline repair

The first read-only diagnostic run found that a complete V2 compilation
could not be used for discovery: after temporarily substituting non-authority
review placeholders, state-index construction stopped on the unregistered
`Dispute:assignment_blocked_reason` state token. That does **not** authorize
automatically allocating a new stable ID.

The source-only AST diagnostic now calls the compiler's existing
`_scan_transaction_contracts` routine without running later signed,
semantic-review, stable-ID or release gates. It reports *every* mismatched
transaction review and *every* missing state stable ID without changing
the accepted registries. Source-only diagnostic output is not equivalent
to a passing V2 compiler. Focused binding tests passed (3 of 3); this
checkpoint triggers the exact-HEAD read-only CI inspection.

## Complete non-authoritative drift inventory

The source-only CI diagnostic at run `41350028387` succeeded and found
**15 stale transaction semantics** and **21 missing source-observed state
stable IDs**. The compiler's first-error failure had obscured the backlog.

The review queue is:
`DISPUTE_OPEN`, `DISPUTE_VOTE_SUBMIT`, `DISPUTE_RESOLVE`,
`DISPUTE_APPEAL`, `DISPUTE_FINAL_RECEIPT`, `ACCOUNT_BAN`,
`ROLE_JUROR_ENROLL`, `ROLE_JUROR_ACTIVATE`,
`ROLE_JUROR_REINSTATE`, `ROLE_VALIDATOR_ACTIVATE`,
`ROLE_NODE_OPERATOR_ACTIVATE`, `ROLE_EMISSARY_SEAT`,
`ROLE_GOV_EXECUTOR_SET`, `REVIEWER_LANE_OPT_IN`, and
`REVIEWER_LANE_OPT_OUT`.

An explicit, append-only set of 21 `STATE-<SHA256 key prefix>` rows
was registered in `specs/v2/source/stable_ids.json` (commit
`e1ef34b8bf00e1f698cb27cba9cfedad021d12af`). These are
compiler-derived state-access *labels*, not an amendment to the
constitution, a declaration of production readiness, or proof that a
user-facing field is semantically sound. Original IDs and tombstones
are preserved. Seven of the new IDs belong to `Roles`, three to
`Reputation` and eleven to `Dispute`.

The current read-only V2 diagnostic independently checks that every
source-observed state token resolves to an existing stable ID. New
regression tests verify that result and the hash-derived identities.
All 15 stale *transaction* semantics still require item-by-item
review and an **authorized maintainer decision**. No digest was
replaced; no independent review was claimed. PR77 remains Draft.
