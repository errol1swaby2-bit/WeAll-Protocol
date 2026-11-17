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

## PR #82/#88/#92 PoH frontend source-level integration review (candidate)

A bounded conflict-parity regression now pins the actual route and component split. In `App.tsx`, `/verification` and the guided async/live stage routes render `PohPage`, which wraps the **active** `AccountVerificationPage` imported from PR #82's guided flow. The preserved v1.6 `AccountVerificationPageV16Preserved` is not routed.

The preserved v1.6 page's local `registerAccount` method was intentionally replaced by navigation to `/onboarding/register`, with separate signed registration intent persistence. Content review opt-in/out and Tier-2 visibility moved into `TrustedResponsibilitiesPanel` and remain bound to the active parent's signed `REVIEWER_LANE_OPT_IN/OUT` action. Verification cases, live sessions and technical records moved to the read-only `VerificationHistoryPanel`, which refuses to call an unavailable history a confirmed zero-case state. The active page retains the new URL-stage guard, unresolved-submission journal, exact-case identity matching, and reviewer evidence-access repair.

A new **source-level regression** (`web/scripts/test_pr93_poh_merge_parity_source.mjs`) is included in Web CI. Its source checks are evidence of intended wiring, **not** proof of every rendered or network-driven user journey. Full human visual parity acceptance, controlled-devnet interrupted-retry verification, and active source review remain additional merge conditions.

### V2 route-count inventory reconciled without semantic authorization

The compiler's historical `expected_counts.routes` was **161**, while source AST diagnostics from run 43989991600 found **162** unique current routes, now all 162 identities represented in `semantic_reviews.json` (one explicitly `review_required`). This increment updates **only** the manifest's expected route count to 162 and adds a read-only equality regression against the scanned AST and review inventory. The previously generated V2 map still has 159 rows and cannot be regenerated/accepted while the 20 transaction reviews and one route review are unresolved. The new count is descriptive inventory, not maintainer signoff or release authority.

### Role/reviewer semantic extraction — source-level correction (pending acceptance)

Eight activation operations reach the same versioned predicate in `reputation_role_gate.py`: juror enroll/activate/reinstate, validator activate, node-operator activate, emissary seat, governance executor set, and reviewer-lane opt-in. The runtime predicate returns typed `not_found:account_not_found`, legacy `forbidden` restrictions (account restriction, live verification, scalar reputation, manual revocation), and `forbidden:policy_unknown` for malformed policy versions. Only explicitly version-2 mapped juror/validator gates can additionally deny `canonical_role_reputation_ineligible`.

The compiler now publishes these typed denials through a narrowly scoped source-bound table rather than substituting a generic runtime error marker for the shared bridge. The gate module's normalized SHA-256 is pinned to this inspected source; a change requires explicit reinspection of the table. Two new failure identities are derived from their canonical keys. Both reviewer lanes are specialized against the actual literal dispatcher branch: opt-in does not require prior enrollment, whereas withdrawal does not invoke activation eligibility. The tests also exercise fresh enrollment and missing-account error details via atomic domain application.

No runtime authorization has been changed. A domain applier permitting withdrawal does not make banned/locked users admissible through public ingress. System-origin role appointments still require their existing parent/action authorization; default governance allowlist exclusions remain. The source-bound compiler inventory is not a complete execution proof, and all nine digest decisions remain pending. Independent replay, explicit maintainer acceptance and broader merge gates are not waived.

### Dispute and sanction technical adjudication (review candidate)

The current `DISPUTE_OPEN` handler validates targets before reaching its proposal-status branch. All three proposal aliases are excluded by the immutable literal allowlist; the previous generated contract incorrectly included two unreachable proposal errors and the corresponding read of the governance proposal map. The narrow compiler correction now excludes this proven-dead branch, retains the actual `unsupported_dispute_target_type` denial, and stops if the validator, allowlist, ordering, or binding changes. No production handler or consensus behavior was altered.

The disposition of the seven dispute contracts, `CONTENT_FLAG`, and `ACCOUNT_BAN` must preserve the following distinctions:

- `DISPUTE_JUROR_ASSIGN`, `DISPUTE_JUROR_ACCEPT`, and `DISPUTE_VOTE_SUBMIT`: reporter recusal remains operative; broad material-conflict rejection requires explicit strict V2. Legacy direct-applier paths do not guarantee material-conflict exclusion. The review packet now marks that version boundary for all three transactions.
- `DISPUTE_RESOLVE` and `DISPUTE_APPEAL`: current behavior includes the severe initial twenty-vote check and fresh-panel/automatic-panel conflict restrictions, with pending appeal when fresh reviewers are insufficient. Neither synthetic panel counts nor a SYSTEM envelope constitute independently authenticated severe authority.
- `DISPUTE_FINAL_RECEIPT` and `ACCOUNT_BAN`: the severe constitutional path remains explicitly fail-closed; queue binding does not authorize it. The separate reputation-floor automatic ban remains operative even with the constitutional clock enabled, so these two guards do not establish universal ban prevention or completed due process.
- `CONTENT_FLAG`: the collision rejection and accepted-flag provenance contract require explicit height activation, with legacy overwrite semantics preserved. Existing focused tests exercise reporter and parent forgery and scheduler repair. The current consumer binds flag identity, target ID, reporter, parent, and SYSTEM origin; that does not by itself authenticate all possible metadata or prove historic replay.

The focused review workflow now includes the actual existing provenance, material-conflict, queue binding, reputation-floor and dispute-open execution regressions rather than merely testing summary claims. These are technical review inputs, not independent review or signed maintainer approval. Do not conflate acceptance of an accurate current-development contract with activation of constitutional sanctions or a public network.

### Pending content-escalation retry regression correction

The expanded source adjudication run [44147229988](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/44147229988) returned **627 passed, 1 failed**. The failing synthetic fixture provided only flags and a pending escalation, whereas `repair_pending_content_escalations` always calls `_pending_escalation_root`, which historically initializes empty content roots. The retry was not due, the pending record and original accepted flag did not change, and no enqueue was attempted. Changing the scheduler to bypass that normalization would be a potential consensus/replay change and is not authorized here.

The revised regression checks legacy and activated profiles with both initialized and partial states: zero enqueue attempts (recorded even if exceptions are swallowed), exact preservation of all pending/accepted-flag data, only the enumerated historical empty-root additions for the partial fixture, exact state equality for initialized state, and idempotent subsequent invocations. This is a characterization of implementation behavior, not a new protocol rule or semantic approval. No production runtime source changed.
