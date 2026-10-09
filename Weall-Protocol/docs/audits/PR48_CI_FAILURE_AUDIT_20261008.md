# PR #48 — CI failure audit and bounded repairs (2026-10-08)

**State:** draft PR, not ready to merge. This record is not an acceptance
of transaction semantics, an independent review, or production authorization.

## Scope and exact starting evidence

Pull request: https://github.com/errol1swaby2-bit/WeAll-Protocol/pull/48

Initial audited branch HEAD:
`0baec8e65d7f11b84a6e3199e059376e57bf7889`.

| PR check | GitHub Actions run | Actual result |
| --- | --- | --- |
| Backend CI | [#37875199647](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/37875199647) | `Check generated artifacts` failed at `ACCOUNT_REGISTER` stale semantic-review digest. An unconditional P0 evidence upload also errored because the earlier compiler failure skipped its artifact producers. |
| Reviewer Readiness Gate | [#37875199661](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/37875199661) | `reviewer_production_readiness_gate.sh` stopped on the same compiler digest. Other later checks in this gate were not executed and cannot be claimed green. |
| A01-A20 P1 Revalidation | [#37875199685](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/37875199685) | 411 tests passed, one failed: `test_a17_f001_archive_reproducible_v2_gate_executes` expects the clean-archive spec checker to succeed, but the current pending semantic review correctly blocks it. |
| Web CI | [#37875199632](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/37875199632) | Passed. |
| Secrets Guard | [#37875199665](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/37875199665) | Passed. |

The actual primary failure is the **transaction semantic acceptance gate**,
not a stale generated artifact that should be rebuilt automatically. The
compiler fails on the first unapproved changed contract,
`ACCOUNT_REGISTER`. The read-only audit inventory identifies **eight**
pending types: `ACCOUNT_REGISTER`, `BALANCE_TRANSFER`,
`BLOCK_REWARD_DISTRIBUTE`, `BLOCK_REWARD_MINT`,
`CREATOR_REWARD_ALLOCATE`, `FEE_PAY`, `FORFEITURE_APPLY`,
and `TREASURY_REWARD_ALLOCATE`.

## Repairs applied; what remained deliberately enforced

In `.github/workflows/backend-ci.yml`:

1. Added stable IDs to the A15 evidence and P0 assurance producer steps.
   The P0 artifact upload retains `if-no-files-found: error`, but now
   runs only when at least one relevant evidence producer **executed**.
   When an upstream gate skips both producers, the upload itself is
   skipped rather than producing a misleading, second failure.
   When a producer runs and no artifact is available, missing evidence
   is still a hard failure.
2. Added a read-only pending transaction semantic review reporter,
   conditioned on the generated-artifact gate failing. It invokes
   `scripts/report_pending_tx_semantic_reviews.py` and uploads the
   candidate report as `pending-tx-semantic-review-candidates`.
   It does **not** update `specs/v2/source/semantic_reviews.json`,
   change the compiler, or claim a reviewer approval.
3. Preserved the full `compile_v2_spec.py --check` and
   `check_v2_spec_clean_checkout.py` gates, the P1 expectation, the
   reviewer readiness gate, and production/reward activation guards.

**Verified GitHub run:** [Backend CI #37875586265](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/37875586265)
at CI-repair commit `3497308da40b9061fc9cc47a0c491eff4a67c2b5`.

- `Check generated artifacts`: **failure** (deliberate semantic review gate).
- Read-only review report creation: **success**.
- Review artifact upload: **success**, GitHub artifact ID `11591869884`.
- P0 property/assurance producer: **skipped** after upstream gate.
- P0 evidence upload: **skipped**, not an independent failure.
- Tx coverage report artifact: successfully uploaded.
- Therefore Backend CI has **one failing step**, rather than the original
  stale-digest failure plus a misleading missing-P0-artifact failure.

## Full suite visibility and explicit limitations

A separate, temporary diagnostic attempted `pytest -q` on the
entire backend suite ahead of the unchanged compiler gate
([Backend CI #37875819057](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/37875819057),
temporary diagnostic commit
`b0802936677d6a6c8194d68b7ff57a240221122e`).
It did not complete or publish a test result before the temporary CI
step was removed in
`2254fc0958e0c0d41561e540bd1cf603a3575510`.
**Do not claim the full backend suite passed, failed, or reproduced a
particular test count on that diagnostic.** The complete backend
suite and gated reviewer commands remain to be verified at an
approved exact commit.

The P1 suite's **one failure** remains intentionally unmodified
because its expectation is still required for actual release readiness.
Changing the test to skip or accept the unapproved semantic digest
would hide the pending review.

## Required next actions to obtain legitimate green readiness gates

- Review each of the eight compiler-derived transaction-semantic
  `material_for_review` records and its exact implementation delta.
  Record a truthful **ACCEPT / REVISE / REJECT** disposition, responsible
  authorized maintainer, evidence, and historical replay consequences.
  See [eight-contract review matrix](FEE_REWARD_EIGHT_CONTRACT_REVIEW_MATRIX_20261008.md).
- Address any rejected contract semantics with code and tests.
  Only accepted reviewed contracts may update their corresponding
  accepted digest using the prescribed repository procedure.
  Do not bulk-refresh digests, edit test expectations, or disable gates
  just to make CI green.
- After real acceptance, rerun Backend CI, Reviewer Readiness Gate,
  A01-A20 P1 Revalidation and the full backend suite at the exact
  same commit. Complete the separate BFT/restart/governance safety review
  before merging or activating fee-backed rewards.

**Disposition:** the independently fixable CI artifact/reporting defect
was repaired. The remaining red checks correctly identify an
outstanding semantic approval dependency and must remain red until
that dependency is genuinely resolved.
