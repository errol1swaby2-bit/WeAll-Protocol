# PR #93 — Final merge-gate closure docket

**Baseline candidate:** `1cc2a2e03ec971e0b0221a5341d30ce2bb471c2c` as inspected on 2026-11-16. **PR:** #93, draft, targeting `main`.
**Disposition:** **NO-GO / do not merge** until all required exact-head checks and substantive approvals are complete.

The intended milestone is a **repository integration baseline**, *not* Genesis activation, a public testnet, independent BFT finality, or production validator authorization. Tests that run actual executor methods are not a substitute for authentic network operation.

## Exact-head gate ledger at the inspected source commit

| Gate | Evidence / result | Required closure |
| --- | --- | --- |
| Web CI | PASS, run 43979933056 | Re-run on final source tree |
| M4.1 two-browser / one-node custody | PASS, run 43979933023 | Ensure scope limitation is preserved: one node, not independent consensus |
| M4.2 signed social reads | PASS, run 43979933002 | Re-run on final head |
| F1b two-process rejected-receipt | PASS, run 43979932913 | Re-run on final head; two processes do not prove physically independent nodes |
| Secrets Guard | PASS, run 43979932974 | Re-run on final head |
| A03 public-lobby shadow index | PASS, run 43979932958 | Offline only; do not claim active read-route cutover |
| B5xx proof diagnostic | PASS, run 43979932861 | Freshness-only evidence, no constitutional approval |
| Backend CI | **FAIL**, run 43979932999 | V2 route semantic-review inventory does not cover current routes; preserve strict review semantics |
| A01–A20 P1 | **FAIL**, run 43979932950 | 411 tests passed and one failed at V2 clean-checkout gate for same route inventory mismatch |
| Reviewer Readiness | **FAIL**, run 43979932954 | Aborts at strict V2 compilation, before downstream checks; success of later checks is **not established** |
| Pull-request source approval | **PENDING** (zero submitted reviews at inspection) | Obtain explicit relevant reviewer/maintainer decisions and satisfy branch protection |

This table is a snapshot. All checks must be repeated after changes; older green checks are not proof of the final head.

## Root of the current hard failures

`scripts/compile_v2_spec.py` invokes `apply_semantic_reviews`, which requires the **exact set of current route stable IDs** to equal the set of recorded route semantic-review IDs. The current strict error is:

```text
v2 spec compile failed: route semantic-review inventory does not exactly cover current rows
```

The generated route contract map currently has 159 rows, while `specs/v2/source/semantic_reviews.json` has 161 recorded route reviews. The current route AST must be scanned to obtain the actual set; comparing these two historical counts does **not** establish which reviews are missing or orphaned.

A read-only semantic inventory already exists in `scripts/pr93_v2_semantic_review_inventory.py`, and the PR77 field-drift workflow uploads it. The workflow now also prints **exact pending route identities and reasons to CI logs and job summary** to make adjudication actionable.

The existing diagnostic reports **20 drifted transaction reviews** (from 236 registered transaction types):

- Disputes: `DISPUTE_OPEN`, `DISPUTE_JUROR_ASSIGN`, `DISPUTE_JUROR_ACCEPT`, `DISPUTE_VOTE_SUBMIT`, `DISPUTE_RESOLVE`, `DISPUTE_APPEAL`, `DISPUTE_FINAL_RECEIPT`.
- Content and sanctions: `CONTENT_FLAG`, `ACCOUNT_BAN`.
- Roles: `ROLE_JUROR_ENROLL`, `ROLE_JUROR_ACTIVATE`, `ROLE_JUROR_REINSTATE`, `ROLE_VALIDATOR_ACTIVATE`, `ROLE_NODE_OPERATOR_ACTIVATE`, `ROLE_EMISSARY_SEAT`, `ROLE_GOV_EXECUTOR_SET`.
- Groups: `GROUP_EMISSARY_ELECTION_CREATE`, `GROUP_EMISSARY_ELECTION_FINALIZE`.
- Reviewer lane: `REVIEWER_LANE_OPT_IN`, `REVIEWER_LANE_OPT_OUT`.

**These are substantive semantic-contract reviews.** A compiler hash can be updated only after inspecting source behavior, failure/retry/replay contracts, signed regression evidence, and any relevant independence or constitutionally significant constraints. Do not remove the gate, fake reviewer fields, or bulk-accept generated candidate digests.

## Required path to merge

1. Classify exact current, missing, changed and orphaned route stable IDs; review source behavior and preserve explicit pending/blocked decisions until adjudicated.
2. Complete the 20 transaction semantic adjudications by domain with source-to-contract traces and behavior regression tests, paying particular attention to severe sanctions, dispute finality, state transitions, and role eligibility. Separate compiler/maintainer semantic acceptance from any independent release or Genesis authorization.
3. Reconcile PR #82 guided fail-closed PoH page against the preserved PR #88 v1.6 page, verifying that every relevant signed flow, profile, navigation and recovery safeguard survives integration. Document the explicit resolution.
4. Run strict V2 clean-checkout regeneration/validation without silently accepting substantive contract changes; then run Backend CI, A01–A20, Reviewer Readiness and other required workflows at the **same final head**.
5. Execute the bounded from-fresh-clone independent-process controlled-devnet acceptance rehearsal and attach provenance. This establishes only the tested scope; do not conflate controlled relay or localhost with autonomous independent hardware.
6. Obtain source review and required branch protection approvals. Only then remove draft status, merge PR #93 into `main` using the repository's permitted merge strategy, verify the merge commit's required checks, and declare that exact `main` commit as the new **development baseline**.

**Do not** activate Genesis, switch off constitutional safety gates or mutate production secrets/keys to make this merge pass.

## 2026-11-16 exact route inventory registered, **not accepted**

The V2 source route registry now contains a **pending review record** for `ROUTE-63E26182B51EAFCB` (`GET /v1/public-lobby/comments`). Its SHA-256 candidate material digest, `8f04ac4404952d23ca7a0cf8d03bd547f337e228155fb17b041752584a3e3a7f`, was extracted from the untouched compiler's live route AST by [run 43989991600](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/43989991600). It is **not an approved digest**. The record has `disposition=review_required`, `reviewer=null`, `reviewed_at=null`, and `independent_review=false`. No signer, maintainer approval, or historical replay authority is claimed.

### Observed source-contract boundary requiring reviewer adjudication

- Anonymous GET, no account session; request `thread_id` must start `public-lobby:`, max UTF-8 length 2048; optional `limit` clamped to 1–50 and optional cursor bounded to 4096 bytes of string length and validated before state access. Invalid requests raise the standard 400 error envelope.
- The live handler invokes `_required_public_lobby_snapshot()`: executor absence, exception, or malformed snapshot yields 503 rather than an apparently empty page.
- The current **compatibility** implementation examines all global comments, rejects >10,000; rejects >2048 dispute records or >4096 dispute target index entries; stops after 512 visibility evaluations and returns explicit 503 instead of silently truncating.
- Filters requested synthetic thread ID, exact `comment_id` map-key identity, `surface=public_lobby`, deleted/nonpublic state, canonical moderation and dispute visibility. It orders eligible comments by descending (created_nonce, comment_id), emits up to limit records with one-record lookahead for a next cursor, and exposes only public comment fields.
- The SQLite A03 candidate and incremental shadow prototype are **not active on this production route**. The source remains an O(global comment records) compatibility scan and can be unavailable at larger loads.
- The source-vs-frontend authority and dispute policy need explicit maintainer review before `review_required` can change to `accepted_current_semantic_contract`. A candidate digest or test pass is not signoff.

**Outcome of this increment:** the strict review inventory's missing-route-ID failure is resolved by registering the actual route *as pending*. The compiler is still expected to fail closed, now on the **20 stale transaction semantic digests**, and then on this route's unaccepted disposition if those drift reviews are resolved. No merge readiness is implied.
