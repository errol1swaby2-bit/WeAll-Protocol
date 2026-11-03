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


### Batch A — reporter provenance and panel-selection adjudication (2026-11-03; no sign-off)

- **Intended semantic identity:** `flagged_by` and `reported_by` denote the same reporting party for a content complaint; `opened_by` denotes the actor that opens the dispute and may be `SYSTEM` during automatic escalation. They are not independent complainant authorities. Conflicting alias values must not be allowed to choose which reviewer is recused.
- **Verified producer:** `_apply_content_flag` records `content.flags[flag_id].by = env.signer`, queues `CONTENT_ESCALATE_TO_DISPUTE` with `flagged_by = env.signer`, and records that signer in `content.pending_escalations[flag_id]`. `repair_pending_content_escalations` requeues from that pending record. `ContentEscalateToDisputePayload` accepts `flag_id` and `flagged_by` as scheduler provenance; `DisputeOpenPayload` does not accept user-supplied reporter aliases.
- **Verified consumer:** `_apply_content_escalate_to_dispute` constructs an internal `DISPUTE_OPEN` envelope and copies `flagged_by` to both reporter aliases, then calls `dispute_open` directly. The escalation path subsequently selects a content-review panel using the reporter alias as an exclusion. The strict schema of a normal `DISPUTE_OPEN` transaction does not independently validate this internal call.
- **Existing regression:** `test_flag_escalation_is_admitted_by_strict_block_schema` proves a genuine signed-flag-derived escalation is admitted and retains the reporter; `test_flag_escalation_strict_block_schema_rejects_unknown_fields` rejects unknown payload keys. Neither test proves rejection of a schema-valid SYSTEM escalation whose `flagged_by` disagrees with the accepted original flag.
- **Unresolved safety boundary — HOLD:** At the consumer boundary, require that `flag_id`, `target_id`, reporter identity, and `parent = CONTENT_FLAG:<flag_id>` are bound to the accepted original flag (or a deterministically authenticated equivalent), before deduplication, dispute creation, or panel selection. An escalation with a substituted reporter or inconsistent provenance must fail closed without canonical-state mutation. Confirm compatibility with persisted historical queue/replay records and explicitly version any consensus-semantic change; do not silently reinterpret historical blocks.
- **Required proof:** Add adversarial regression cases for reporter substitution, mismatched target/flag, missing or incorrect parent, and replay/restart; verify state immutability on rejection and genuine scheduler/repair success. Check SYSTEM authorization at block admission separately. Do not accept the Batch A semantic digests based on the current happy-path test alone.


### Batch B — resolution, appeal, final receipt, and account ban (2026-11-03; no sign-off)

- **Normative review boundary:** A SYSTEM-origin envelope is not itself constitutional authorization to impose a severe sanction. Resolution must be bound to a verified jury verdict; appeal and finality must be bound to independent review and the applicable appeal clock. A severe account ban must not execute solely from asserted metadata or a final receipt.
- **`DISPUTE_RESOLVE` verified:** `_apply_dispute_resolve` requires SYSTEM authority. In constitutional-clock mode for explicit severe account sanctions it requires strict governance and the verified initial 20-of-25 result; it rejects a supplied outcome other than `report_upheld` and a conflicting pre-existing automatic appeal record in the experimental path. It stores an appealable resolution rather than immediately granting finality in constitutional mode. This does not authenticate a complete severe automatic-appeal lifecycle.
- **`DISPUTE_APPEAL` verified:** `_apply_dispute_appeal` rejects a conflicting automatic appeal, duplicate filings by the same identity, closed/out-of-stage appeals, and ineligible appellants before constructing fresh-panel selection. Independent fresh-panel availability and preservation of original panel snapshots remain necessary to prove full appeal behavior.
- **`DISPUTE_FINAL_RECEIPT` verified:** `_apply_dispute_final_receipt` blocks severe finality via `requires_severe_sanction_finality_hold`, including receipt-carried `ACCOUNT_BAN` without an explicit severity label, and blocks `appeal_pending_panel`. This is fail-closed, not proof of completed appeal finalization.
- **`ACCOUNT_BAN` verified:** `src/weall/runtime/apply/reputation.py::_apply_account_ban` requires SYSTEM and unconditionally rejects with `severe_sanction_authorization_unimplemented` when `policy_from_state(state).enabled`. Legacy/dev execution is intentionally separate; same-nonce conflicting ban receipts are rejected there. Thus a successful constitutional severe ban cannot currently be demonstrated.
- **Semantic disposition — HOLD (all four rows):** Preserve the fail-closed constitutional restriction. Do not bless stale generated digests as normative behavior, remove guards merely to make CI green, or describe the severe sanction lifecycle as complete. Before approval, prove source-backed authority from the initial verdict through fresh independent appeal (or a constitutionally authorized waiver), deterministic final receipt, and ban execution, including replay/restart and attempted metadata forgery. Document activation/versioning and legacy replay compatibility explicitly. Distinguish currently unreachable success paths from executable failures in the compiler contract.
- **Audit scope:** Source inspection only in this pass; no tests or CI were run. The existing review queue records focused regression evidence from earlier workflows, which is not a substitute for a fresh proof at the present head.


### Batch B — complete audit work scope and acceptance matrix (2026-11-03)

**Objective and boundary.** This is a scoped closure plan, not authorization to activate severe sanctions. All four transactions remain on semantic HOLD until exact-commit executable evidence and constitutional authorization are established. Preserve deterministic replay and explicitly version any changed consensus semantics.

| Lane | Source and assertion | Adversarial proof needed | Exit criterion |
| --- | --- | --- | --- |
| B1: resolution | `dispute.py::_apply_dispute_resolve`, strict-governance verdict and 20-of-25 predicate | SYSTEM-signed false verdict, forged counts, mismatched outcome, missing quorum, duplicate/conflicting resolution, clock boundary | Only the stored authenticated qualifying verdict can authorize resolution; rejected tx has no canonical mutation |
| B2: appeal | `dispute.py::_apply_dispute_appeal`, actor eligibility, deadline, prior panel snapshots, fresh independent panel | Ineligible/duplicate appellant, late filing, original juror reused, inadequate fresh pool, conflicting automatic appeal, replay/restart | Valid appeals persist deterministically and cannot be bypassed; insufficient pools remain pending without unauthorized finality |
| B3: finality | `dispute.py::_apply_dispute_final_receipt`, `requires_severe_sanction_finality_hold`, enforcement allowlist | Premature receipt, appeal pending, receipt-carried `ACCOUNT_BAN` disguised as ordinary action, forged waiver/appeal metadata, duplicate conflicting receipt | No enforcement before a verifiable final outcome; severe cases remain blocked until an authorized mechanism exists |
| B4: sanction | `reputation.py::_apply_account_ban`, `policy_from_state(state).enabled` | SYSTEM-origin forged authorization, mismatched account, fabricated appeal receipt, repeated/conflicting nonce, alternate direct execution path | Constitutional mode remains fail-closed pending genuine source-backed sanction authority; legacy behavior explicitly replay-scoped |
| B5: integration | SYSTEM queue producer, admission, dispatch, journaled rollback, persisted restart | Cross-domain parent substitution, queue tampering, partial apply failure, two-node deterministic execution, snapshot/replay | End-to-end evidence ties a precise commit, canonical state roots, replay outputs, and admission decisions |
| B6: spec and compiler | Canonical constitution/policy, V2 semantic source, generated failure/state digest and review packet | Unreachable generated outcomes, dynamic failure reasons, historic version mismatch, scanner omission | Each row's contract describes reachable current behavior and separately marks future normative intent; explicit maintainer sign-off only after proof |

**Evidence deliverables:** test matrix with positive and negative cases; pre/post canonical state hashes on rejection; same-block and restart replay; SYSTEM provenance and receipt-binding checks; independent panel and threshold evidence; historical-version compatibility notes; exact-commit CI run IDs; a transaction-by-transaction semantic-review decision. Do not equate a passing compiler with constitutional sign-off.

**Dependency ordering:** First freeze normative authority/waiver rules and activation height; then verify B1 verdict binding; implement and prove B2 automatic independent appeal or authorized waiver; bind B3 finality to that proof; only then consider enabling B4 execution. Run B5 and B6 after each consensus-affecting change. Until then, preserve the B3/B4 fail-closed guards.

### Batch C — role eligibility and authority source inspection (2026-11-03; no sign-off)

- **Common gate:** `roles.py::_require_role_activation_eligible` delegates to `role_activation_reputation_decision`, preserving legacy v1 when the version parameter is absent. Its `RolesApplyError` uses dynamic `decision["code"]` and `decision["reason"]`; a compiler that only recognizes literal raises cannot claim those rejection reasons disappeared. V2 needs explicit chain-committed activation, not inferred adoption.
- **Juror enrollment and activation:** `ROLE_JUROR_ENROLL` requires the signer to enroll their own account and invokes the shared gate. `ROLE_JUROR_ACTIVATE` allows self or SYSTEM, requires enrollment, and invokes the gate. `ROLE_JUROR_REINSTATE` delegates to activation, not a separate bypass.
- **Validator activation:** `ROLE_VALIDATOR_ACTIVATE` requires SYSTEM, the shared reputation gate, an active node operator, active verified/ready validator responsibility, unexpired readiness, and a registered node key when one is supplied. These checks are additional to the reputation gate.
- **Node-operator activation:** `ROLE_NODE_OPERATOR_ACTIVATE` requires SYSTEM, enrollment, and the shared gate. For suspended operators, it requires a nonempty parent reference before clearing suspension; whether the parent is authenticated as reinstatement authority requires separate producer/admission verification.
- **Emissary seating:** `ROLE_EMISSARY_SEAT` requires SYSTEM and the shared gate, then seats the account and synchronizes protocol treasury membership. The source inspected here does not independently prove a governance proposal/election authorization for the SYSTEM envelope; verify producer/parent binding before approving the row.
- **Governance executor:** `ROLE_GOV_EXECUTOR_SET` requires SYSTEM and the shared gate, then replaces the current executor. Source inspected here does not independently prove the proposal authority for that replacement; verify the SYSTEM producer and canonical governance receipt.
- **Reviewer opt-in:** `REVIEWER_LANE_OPT_IN` requires the signer to update their own account, an allowed lane, and the shared gate; content-review opt-in may assign previously unassigned reviews. Opt-out follows the same function with `active=False` but does not invoke the activation predicate; do not conflate the two paths.
- **Contract-accuracy HOLD (all seven Batch C rows):** Verify exact gate-version/reputation policy, producer and SYSTEM authority, rollback on failed activation after preliminary `_touch` operations, replay, and emitted failure reasons. In particular, require proposal/election evidence for emissary and executor authority, not merely a SYSTEM marker. Do not approve stale digests or silently weaken role checks.
- **Scope of this pass:** Read-only source inspection plus audit-record update; no tests executed or semantic approvals granted.
