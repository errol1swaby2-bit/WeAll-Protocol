# PR #88 — V2 semantic-review triage (2026-11-11)

Status: **review preparation only — NOT an approval, refresh, independent assessment, or authorization to activate a network.**

This document identifies a separate V2 source/review consistency blocker alongside the production BFT regression evidence. The passing four-process consensus tests do not certify the semantics of all transaction families.

## Current exact-head failure

The **A01–A20 P1 Revalidation** workflow fails `test_p1_a17_reviewer_repro_contract.py::test_a17_f001_archive_reproducible_v2_gate_executes`, because the strict clean-archive compiler rejects 20 stale transaction semantic-review digests. The **Reviewer Readiness Gate** stops on the same validation. This is independent of the B528, B534, and B567 source-bound proof freshness checks.

The diagnostic workflow **PR77 V2 semantic field drift diagnostic (no approval)** generated [per-transaction candidate digests and field-change evidence](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/43111338188/artifacts/13896501577). Its recorded status is `diagnostic_only_not_approval`, with `stale_count=20` and `semantic_review_records_modified=false`.

### Transactions requiring bounded review

| Domain | Stale transaction contracts |
| --- | --- |
| Dispute and adjudication | `DISPUTE_OPEN`, `DISPUTE_JUROR_ASSIGN`, `DISPUTE_JUROR_ACCEPT`, `DISPUTE_VOTE_SUBMIT`, `DISPUTE_RESOLVE`, `DISPUTE_APPEAL`, `DISPUTE_FINAL_RECEIPT` |
| Content and account enforcement | `CONTENT_FLAG`, `ACCOUNT_BAN` |
| Juror and validator authority | `ROLE_JUROR_ENROLL`, `ROLE_JUROR_ACTIVATE`, `ROLE_JUROR_REINSTATE`, `ROLE_VALIDATOR_ACTIVATE`, `ROLE_NODE_OPERATOR_ACTIVATE` |
| Emissary and governance authority | `ROLE_EMISSARY_SEAT`, `ROLE_GOV_EXECUTOR_SET`, `GROUP_EMISSARY_ELECTION_CREATE`, `GROUP_EMISSARY_ELECTION_FINALIZE` |
| Reviewer participation | `REVIEWER_LANE_OPT_IN`, `REVIEWER_LANE_OPT_OUT` |

This inventory is the actual compiler failure inventory, not an assertion that each transaction's behavior changed. The precise field-level comparisons are in the diagnostic evidence.

## Review requirements before any semantic digest refresh

1. Inspect each diagnostic row's `changed_fields_against_checked_in_contract`, `candidate_digest_not_approved`, and owning implementation source.
2. Compare signer/authority, PoH and role gates, conflict rules, state reads/writes, system follow-ups, receipt and failure contracts, replay behavior, activation, and migration treatment against the source implementation and normative requirements. Do not infer equivalence from a passing test count or a changed filename alone.
3. Resolve every substantive mismatch through an explicit source/spec correction and targeted regression, or record an explicit human-maintainer semantic acceptance of the *actual* current behavior. Do not silently preserve a stale old acceptance statement.
4. Only after a named review decision, use the existing explicit per-transaction semantic-review refresh procedure; keep its `independent_review=false` posture until actual independent review and approval are documented. Regenerate and verify V2 derivatives from a clean archive afterward.
5. Keep the independent launch gate, confidential ballot requirements, genesis approval, public-validator activation, economics, helpers, and mainnet authorization **disabled** until their separate approvals are met.

## Proofs already regenerated separately

The source-bound B528–B532, B534–B538, and B567–B571 completion proofs were independently regenerated and reexecuted with `--check` and `--verify-live`. Their diagnostic comparisons reported only `freshness` changes; the locked/public-release boundaries were unchanged. Their refreshed generated JSON files do **not** constitute V2 semantic review or release approval.

## Acceptance boundary

Do not mark A17, Reviewer Readiness, Backend CI, or the V2 clean-checkout gate as passed without an **exact-head successful workflow**. This note must never itself change `specs/v2/source/semantic_reviews.json`, generated V2 registries, stable IDs, or activation authority.
