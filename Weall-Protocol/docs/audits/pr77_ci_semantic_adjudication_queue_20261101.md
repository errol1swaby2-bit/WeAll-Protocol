# PR #77 — CI semantic adjudication queue (2026-11-01)

**Disposition: BLOCKED — requires authorized maintainer semantic decisions.**
This document is an evidence inventory, not an acceptance certificate. No
human/independent review is being impersonated; the PR remains Draft.

## What failed

On reviewed head `3de576f5ce0bb1efd628a8f2086300a3867be07d`,
Backend CI, A01–A20 P1 Revalidation and Reviewer Readiness were all red
because `compile_v2_spec.py` stopped at the first stale transaction
semantic review, `DISPUTE_OPEN`. Backend CI then attempted a P0 assurance
artifact upload although its P0 producer never ran.

The backend workflow now conditionally uploads P0 evidence when that
producer actually executes. Failure evidence from a *run* P0 gate remains
uploadable. This removes a false secondary failure without bypassing V2.

## Exact source-bound discovery

The previous `DISPUTE_OPEN` V2 registry used the broad
`apply_dispute` dispatcher, whose static call traversal mixed unrelated
dispute transaction handlers. `dispute_open` itself and
`apply_dispute` were independently compared with `main` and found
**textually unchanged**. Its registry now binds the actual
`dispute_open` handler; current extracted contract fields now
describe that transaction rather than a cross-transaction aggregate.

Read-only source diagnostic run `41350028387` enumerated 15
stale transaction reviews and 21 missing static state-access IDs.
The 21 new `STATE-` IDs are explicitly registered, hash-derived
from their canonical keys, and append-only (11 Dispute, 3 Reputation,
7 Roles). Validation run `41350375547` passed the four focused tests,
found **zero remaining missing state stable IDs**, and uploaded
`pr77-v2-semantic-drift-diagnostic`. It still found 15 review
mismatches. No semantic-review digest was replaced.

The compiler has also been changed to **report all stale TX
reviews in one fail-closed error**, rather than stopping at the first
name. Route-review enforcement and existing reviewed digests remain
mandatory.

## Transaction-level adjudication

| Review group | Transaction(s) | Exact change to consider |
|---|---|---|
| Source attribution | `DISPUTE_OPEN` | Broad dispatcher review was narrowed to actual handler: unrelated dispute failures, read/write fields, return fields, and inferred SYSTEM follow-ups are removed from this TX contract. No change to actual `dispute_open` code was found. |
| Initial/appeal decisions | `DISPUTE_VOTE_SUBMIT`, `DISPUTE_RESOLVE`, `DISPUTE_APPEAL` | New rejection reasons for unverified independent appeal panel, severe 20/25 first-stage approval, initial outcome mismatch, and duplicate/overlapping automatic panel assignment. These change denial semantics and may affect replay. |
| Finality | `DISPUTE_FINAL_RECEIPT` | New fail-closed denial `severe_sanction_automatic_appeal_unimplemented`. A synthetic panel/result must not be mistaken for authorization. |
| Account sanction | `ACCOUNT_BAN` | Adds `conflicting_receipt:duplicate_ban_receipt_conflict` and `forbidden:severe_sanction_authorization_unimplemented`, and additional read-model fields. The existing ban-execution NO-GO must remain. |
| Role/reviewer eligibility | `ROLE_JUROR_ENROLL`, `ROLE_JUROR_ACTIVATE`, `ROLE_JUROR_REINSTATE`, `ROLE_VALIDATOR_ACTIVATE`, `ROLE_NODE_OPERATOR_ACTIVATE`, `ROLE_EMISSARY_SEAT`, `ROLE_GOV_EXECUTOR_SET`, `REVIEWER_LANE_OPT_IN`, `REVIEWER_LANE_OPT_OUT` | Shared role activation logic now calls `role_activation_reputation_decision` with versioned gate metadata. Previous direct `forbidden` failure reasons are no longer statically visible at this handler level, and the compiler now sees dynamic `RolesApplyError:runtime_apply_failure`. This may be a static analyzer visibility gap *and* a real versioned policy change; test each relevant role under legacy and gated profiles before acceptance. |

The source-only tool reports changed fields from the last committed V2
`tx_contract_matrix.json`; it does **not** prove complete runtime behavior,
authenticated juror ballot lineage, correct reputation policy, or safe
historical replay. The aggregate CI error improves visibility but
does not waive any approval.

## Required closure sequence

1. Review each of the 15 changed transactions against the implementation,
   originally accepted source contracts, constitutional target and
   actual success/rejection cases, not merely its digest.
2. Resolve the shared roles gate v1/v2 policy and ensure exact error
   contracts remain appropriately represented. Address the existing
   `ACCOUNT_BAN` producer/appeal/provenance NO-GO separately.
3. Run focused adversarial tests plus full backend and fresh-clone replay.
   Confirm any committed stable ID additions preserve the baseline.
4. Obtain authorized maintainer signoff for each *actual* semantic change
   and only then update the corresponding V2 review rows and generated
   derivatives. Do not invent reviewer identity or declare
   `independent_review: true`.
5. Complete V2 provenance C1/C2 and clean-checkout validation. Even a
   successful specification compiler is not public-testnet launch
   authorization; eight public-beta blockers remain outstanding.

**No merge or network activation on the current draft PR.**

## Exact-head inventory update (2026-11-02)

The preceding 15-row inventory records the earlier November 1 diagnostic. On current Draft head `ca9a4717a727fcd19e88b72777a223dd109514f6`, the compiler and exact-head CI logs report **17 stale transaction semantic-review digests**:

`DISPUTE_OPEN`, `DISPUTE_JUROR_ASSIGN`, `DISPUTE_JUROR_ACCEPT`, `DISPUTE_VOTE_SUBMIT`, `DISPUTE_RESOLVE`, `DISPUTE_APPEAL`, `DISPUTE_FINAL_RECEIPT`, `ACCOUNT_BAN`, `ROLE_JUROR_ENROLL`, `ROLE_JUROR_ACTIVATE`, `ROLE_JUROR_REINSTATE`, `ROLE_VALIDATOR_ACTIVATE`, `ROLE_NODE_OPERATOR_ACTIVATE`, `ROLE_EMISSARY_SEAT`, `ROLE_GOV_EXECUTOR_SET`, `REVIEWER_LANE_OPT_IN`, and `REVIEWER_LANE_OPT_OUT`.

The two additions beyond the older inventory are `DISPUTE_JUROR_ASSIGN` and `DISPUTE_JUROR_ACCEPT`. Their source-bound material now includes the reporter-recusal denial `forbidden:juror_conflict_reporter` and reads of reporter identity fields. `DISPUTE_VOTE_SUBMIT` also now includes reporter-recusal drift in addition to the severe-appeal guard. These are review inputs, not acceptance decisions.

The read-only review-packet generator and tests are being aligned to this 17-row inventory so new stale rows are not incorrectly treated as an unexpected-inventory defect. This bookkeeping correction does **not** modify `specs/v2/source/semantic_reviews.json`, accept any current digest, assert historical replay, or weaken the compiler gate. Each affected row remains unsigned for the current digest and unproven for historical compatibility.

Exact-head evidence: Backend CI run [41538354386](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/41538354386), Reviewer Readiness run [41538354435](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/41538354435), A01–A20 P1 Revalidation run [41538354663](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/41538354663), and read-only semantic-drift diagnostic run [41538354489](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/41538354489). The first three remain failed at the V2 review gate; the diagnostic reports zero missing state stable IDs. The P1 run recorded 411 passing tests and one failure at clean-checkout V2 compilation; Backend CI skipped the full backend pytest step after its early compile failure.

## Technical adjudication snapshot (2026-11-02; no semantic sign-off)

Reviewed runtime source and focused regression evidence at implementation head `3df8d67bd00b2c6e1d0c50bb86275c8196833211`. This section records technical conclusions only. It does not authorize, sign, or update any accepted semantic-review digest.

### Source-backed behavior supported by focused tests

- `DISPUTE_JUROR_ASSIGN`, `DISPUTE_JUROR_ACCEPT`, and `DISPUTE_VOTE_SUBMIT`: `_require_dispute_reviewer_lane` checks target-owner and report-party conflicts using identity variants across `reported_by`, `flagged_by`, and `reporter`. The integration test verifies the reporter remains unassigned and that a reporter's signed accept rejection leaves both scratch and canonical state unchanged. The vote path separately rejects an unverified severe appeal panel before vote mutation.
- `DISPUTE_RESOLVE`: the implementation binds constitutional severe resolution to the verified initial 20-of-25 threshold, rejects a system-supplied outcome that disagrees with the stored verdict, and rejects a conflicting automatic-appeal record when the experimental flow is active. Focused tests exercise all three denial reasons and the legacy-clock boundary.
- `DISPUTE_APPEAL`: the implementation records a valid appeal as `appeal_pending_panel` when the strict fresh-panel pool is insufficient, clears live jury duty, and preserves the original panel snapshots. It rejects replacement of an already recorded automatic severe appeal. `DISPUTE_FINAL_RECEIPT` blocks pending appeals and blocks constitutional severe-sanction finality while automatic appeal authorization is unimplemented.
- `ACCOUNT_BAN`: under the enabled constitutional policy, the applier rejects the transaction with `severe_sanction_authorization_unimplemented`; the legacy/dev path remains separate. The same-nonce dedupe path rejects a conflicting receipt instead of silently deduping it.

These are supported implementation findings, not a declaration that the protocol is deployable. In particular, the severe-account path remains deliberately fail-closed and does not establish an operational automatic-appeal or sanction-authority system.

### Contract-accuracy holds before digest acceptance

- `DISPUTE_OPEN`: the handler binding to `dispute_open` is the correct transaction-specific source, and direct-call/dispatcher parity tests cover success and rejection in both clock modes. However, `dispute_open` calls `_validate_dispute_target_type` before its proposal-specific status branch. The allowlist currently rejects `proposal`, `governance`, and `governance_proposal`, so the generated current contract's `proposal_not_found` and `active_proposal_dispute_protected` failure entries, plus `key:gov_proposals_by_id`, describe currently unreachable branches. The branch may be future defense-in-depth, but the review packet must not treat these as currently reachable runtime outcomes without an explicit adjudication note.
- The eight activation/opt-in rows—`ROLE_JUROR_ENROLL`, `ROLE_JUROR_ACTIVATE`, `ROLE_JUROR_REINSTATE`, `ROLE_VALIDATOR_ACTIVATE`, `ROLE_NODE_OPERATOR_ACTIVATE`, `ROLE_EMISSARY_SEAT`, `ROLE_GOV_EXECUTOR_SET`, and `REVIEWER_LANE_OPT_IN`—call `_require_role_activation_eligible`, which delegates to `role_activation_reputation_decision` and raises dynamic `RolesApplyError(code, reason, details)`. The compiler's literal-only `_extract_failures` therefore emits `RolesApplyError:runtime_apply_failure` and misses the actual dynamic reason set. The runtime tests cover default/v1/v2 behavior, banned/locked accounts, PoH tier, manual revocation, scalar reputation, malformed versions, and canonical penalties for mapped juror/validator roles. The generated delta is not proof that the old runtime rejections disappeared.
- `REVIEWER_LANE_OPT_OUT`: this transaction calls the shared `_apply_reviewer_lane_update(..., active=False)` branch. That branch does not call the activation predicate; it permits the withdrawal operation even if the activation predicate would reject. Tests explicitly verify this for banned, Tier-1, revoked, and malformed-version states. Public admission separately blocks banned/locked signers before apply. The current generated role-gate delta is therefore a shared-function/static-analysis artifact, not a runtime change to the opt-out path.

### Verification at this head

- The read-only review-packet workflow passed: 459 tests, Ruff checks and formatting passed, `pending_count=17`, no unexpected stale rows, no missing stable IDs, and no packet-integrity blockers. Its output explicitly remains NO-GO for semantic approval.
- The separate `DISPUTE_OPEN` semantic-drift diagnostic passed, as did the focused severe-appeal threshold, initial 20-vote guard, and severe-account finality fail-closed workflows.
- Backend CI, Reviewer Readiness, and A01–A20 P1 Revalidation still fail at the V2 semantic-review gate for the same 17 transaction types. In the P1 run, 411 tests passed and one clean-checkout compiler test failed on the stale-digest gate; Backend CI stops before the full backend pytest step.

### Next admissible action

Do not regenerate or accept all 17 digests as a batch. First resolve the two contract-accuracy holds above in the review record (either improve the source-derived contract material or explicitly adjudicate the known scanner limitations), then request explicit maintainer acceptance for the exact current digest of each row. Keep PR #77 Draft and unmerged until the required compiler, readiness, and P1 gates pass.

