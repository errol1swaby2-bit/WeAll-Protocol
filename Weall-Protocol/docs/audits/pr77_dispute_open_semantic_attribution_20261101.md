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

## Multi-contract fail-closed error reporting

The original V2 semantic check raised at the *first* stale transaction.
That hid fourteen additional changed transaction reviews behind
`DISPUTE_OPEN`. The compiler now enumerates **every stale TX type**
in one deterministic validation error; no stale digest is accepted,
no review disposition is changed, and the independent route review
check remains fail-closed. Focused tests verify the complete error list,
no partial transaction-row mutation when stale, and retained route
rejection.

This is a diagnostic usability repair, **not** a gate bypass.


## Exact-head DISPUTE_OPEN execution adjudication (2026-11-01 continuation)

**Disposition: RUNTIME EVIDENCE IDENTIFIED; NEW SEMANTIC APPROVAL STILL NO-GO.**

The prior/current comparison is anchored to the current read-only V2 packet: `DISPUTE_OPEN` (stable ID `TX-0200`) had the *accepted historical* function `apply_dispute`, but the current source registry now names the actual `dispute_open` function. Its changes are the six review-material fields `implementation_source`, `failure_codes`, `receipt_contract`, `state_reads`, `state_writes`, and `system_followups`. The prior generated material digest matches the on-record accepted digest; the present digest **does not**, and remains unsigned.

A fresh GitHub comparison of the full `def dispute_open` and `def apply_dispute` function bodies between `main` and current Draft PR77 on 2026-11-01 found **byte-identical function text**, even though the full `dispute.py` file differs elsewhere. This is strong source-attribution evidence for the scanner rebind, **not proof** that all called helper semantics, registry behavior, final receipts or historical chain replay are unchanged.

### Newly identified static-analysis overclaim: unreachable proposal paths

The current `dispute_open` first invokes `_validate_dispute_target_type`, which rejects target types absent from `_ALLOWED_DISPUTE_TARGET_TYPES` **before** the proposal-status section. That allowlist currently contains:

`account`, `comment`, `content`, `group`, `membership`, `moderator`, `poh`, `post`, `reviewer`.

It **does not contain** any of `proposal`, `governance`, or `governance_proposal`. Nonetheless `dispute_open` has later code that would raise `not_found:proposal_not_found` and `forbidden:active_proposal_dispute_protected` for those targets. These later branches are unreachable through this handler in the current version. The V2 scanner's new `DISPUTE_OPEN` `failure_codes` includes both reasons because it does not prove control-flow reachability. They must not be signed off as **currently exercisable denial receipts**.

The full synthetic direct-handler/dispatcher comparison added in `tests/test_pr77_dispute_open_semantic_adjudication.py` exercises both constitutional-clock on/off modes, success for permitted targets, absent target, unverified signer, duplicate opening, unsupported target, and all three proposal aliases across existing/missing/finalized targets. No synthetic `SYSTEM` envelope is claimed to be authenticated. The comparison is about exact current execution semantics, not live network admission or a real old-ledger replay.

**Impact:** it is not currently possible to open a proposal-targeted dispute *using this `DISPUTE_OPEN` path*. This does **not** prove that all governance correction mechanisms are absent elsewhere in the protocol, nor is it evidence that allowing disputes against live proposals would be constitutional. It presents a real design decision: how final governance/proposal outcomes are challenged without permitting active-proposal suppression.

### Proposed decision, not a code activation

1. Keep the current target allowlist and legacy historical execution unchanged until the constitutionally appropriate scope, finality boundary and appeal authority are specified.
2. If proposal challenges are meant to use `DISPUTE_OPEN`, define a **chain-committed versioned** eligibility rule: terminal governance outcomes may be challengeable, active proposals require a separate, explicitly authorized protection/review policy. Authenticate the target's finalized status at consensus height.
3. If proposal challenges belong exclusively to another existing mechanism, formally identify that mechanism and remove/make explicit the dead code and scanner-only code/reason observations in a reviewed source-contract revision. Do not make this decision from an AST diff alone.
4. Verify the actual upstream source, helper reachability, all success/denial cases and historical height-by-height roots using authentic pre-change ledger and software. An independent reviewer must accept each new V2 digest before generated derivatives change.
5. Continue to reject `ACCOUNT_BAN` without authenticated severe-appeal evidence; changes here confer no sanction power.

**No alteration to runtime behavior, accepted `semantic_reviews.json`, state root, governance activation, or V2 reviewer identity is made by this review.**
