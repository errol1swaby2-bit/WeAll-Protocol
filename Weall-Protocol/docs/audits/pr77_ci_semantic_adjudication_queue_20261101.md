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
