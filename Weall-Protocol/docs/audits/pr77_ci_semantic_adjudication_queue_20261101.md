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

### Batch C — producer and governance authority trace (2026-11-03; no sign-off)

**Concrete producers found.** `node_operator_scheduler.schedule_node_operator_system_txs` deterministically queues `ROLE_NODE_OPERATOR_ACTIVATE` after `evaluate_baseline_node_operator` reports eligibility, and queues `VALIDATOR_READINESS_VERIFY` / `ROLE_VALIDATOR_ACTIVATE` after validator responsibility and readiness checks. Those are SYSTEM transactions with `parent=None` by design; their canonical tx definitions declare SYSTEM, block context, Validator gate, and do **not** require `GOV_EXECUTE` parent. Thus do not incorrectly impose governance parent requirements on automatic baseline operator/validator activation.

**Governance appointments discrepancy.** `specs/tx_canon/tx_canon.yaml` declares `ROLE_EMISSARY_SEAT` and `ROLE_GOV_EXECUTOR_SET` as SYSTEM, `gate: GovExecutor`, `receipt_only: true`, `parent: GOV_EXECUTE`, and `via_gov_execute: true`. `apply/governance.py::_apply_gov_execute` verifies a tallied, passed proposal, matches approved actions against supplied actions, checks the action allowlist and electorate scope, and queues action txs with the execution parent reference. **But `DEFAULT_GOV_ACTION_ALLOWLIST` does not include either appointment transaction.** `params.gov_action_allowlist` may override defaults. Under default parameters these appointments cannot be emitted by normal `GOV_EXECUTE` action execution. This is a concrete spec-vs-reachability discrepancy; do not claim the appointments are currently operational.

**Authority hold.** `roles.py::_apply_role_emissary_seat` and `_apply_role_gov_executor_set` enforce SYSTEM and role eligibility but do not themselves verify a governance approval record. Confirm admission/queue lineage witness enforcement, including a real `GOV_EXECUTE` parent with approved matching action/payload, rather than merely a nonempty `env.parent`. Test both default and configured allowlists, tampered queue/parent, direct `apply_roles` invocation, block admission, and restart/replay. Do not change the allowlist or activation rules without normative authorization and historical versioning.

**Pre-mutation rollback hold.** Several role handlers call `_ensure_roles` and `_touch` before the eligibility predicate can reject. Their safety depends on the canonical executor's journaled rollback for failed transactions; direct applier mutation on failure is a separate test surface. Require negative tests comparing canonical state roots before/after failed activation (including nested records) and replay equivalence, not just exception assertions.

**Batch C proof matrix.** Juror: self-enrollment, activation/reinstatement, tier/reputation/version failures. Validator: operator enrollment, readiness receipt, expiry, registered node key, SYSTEM producer. Node operator: scheduler eligibility and parentless automatic activation; suspended reinstatement parent provenance. Emissary: vote/nomination support vs approved governance appointment and treasury signer sync. Gov executor: governance appointment scope and replacement authorization. Reviewer opt-in: self-authorization, eligibility, previously unassigned review assignment, failed transaction rollback. For all seven pending rows: dynamic `RolesApplyError` rejection extraction, exact-commit positive/negative tests, deterministic two-node/restart replay, and explicit semantic-review acceptance after blockers close.

**Current result:** No proven unauthorized appointment from this inspection, but default appointment-path unreachability and unproven approval-to-application binding remain explicit HOLDs. Source inspection only; no runtime tests executed.

## Batch A–D consolidated PR #77 execution runbook (2026-11-03)

**Status: OPEN / HOLD.** This is the controlling remaining-work queue for Draft PR #77, not semantic acceptance, constitutional activation, or permission to merge. Preserve all previous source findings and exact-head evidence above. User-directed design intent is not proof of implemented runtime behavior.

### Confirmed user-directed architecture

1. **Severe appeal jurisdiction:** select the independent appeal panel from the **protocol-wide juror electorate**, never solely from the electorate of the group where the infraction occurred. This is a selected juror panel, not a referendum of the entire electorate. Retain the current working 25 jurors plus five substitutes, disjoint from the original panel and substitutes; preserve the existing verified **initial** 20-of-25 rule. The appeal vote threshold, finality and waiver policy still require explicit normative decisions.
2. **Governance election method:** **STV (Single Transferable Vote)** for multi-seat ranked ballots, not single-winner instant runoff or the existing multi-option plurality. The required pipeline is candidate nomination, candidate qualification polling, ranked multi-selection ballots, deterministic STV tally, election certification, then exact approved governance appointment. Quota, transfer arithmetic, ties, exhausted ballots, electorate, nomination/qualification thresholds, seats and timing are not yet frozen.
3. **Reviewer withdrawal:** opting out of a reviewer lane must automatically case-withdraw the reviewer from **all open/nonfinal cases attributed or assigned to that reviewer in the affected lane(s)**, not unrelated lanes. Process deterministically and atomically, initiate substitute/replacement or pending state, preserve committed votes and applicable accountability. The current case-specific withdrawal path rejects post-vote withdrawal; define its reconciliation with automatic opt-out before implementing.
4. **Do not conflate authority:** SYSTEM queue binding proves deterministic emission, not constitutional sanction or appointment authority. Preserve parentless canonical node-operator/validator scheduler activations. Do not relax fail-closed severe-ban and final-receipt guards.

### Bounded work packages

| ID | Batch | Priority | Work and code surface | Exit proof | Disposition |
| --- | --- | --- | --- | --- | --- |
| WP-01 | A | P0 | Content flag provenance in apply/content.py; dispute opening/recusal in apply/dispute.py. Bind accepted flag ID, target, original reporter and CONTENT_FLAG parent **before dedup or state mutation**. | Forged reporter/target/parent rejected without state-root change; genuine queue and repair, restart/replay. | HOLD |
| WP-02 | B | P0 | Initial verdict and appeal selection in apply/dispute.py. Fresh 25+5 appeal panel drawn from protocol-wide juror electorate, independently of originating group. | Verified initial 20/25; candidate-pool provenance; disjoint panel; conflicts excluded; insufficient pool pending; deterministic replay. | HOLD |
| WP-03 | B | P0 | Final receipt in apply/dispute.py and ACCOUNT_BAN in apply/reputation.py. Authenticated verdict -> independent appeal or constitutionally authorized waiver -> finality -> exact sanction. | No forged SYSTEM/waiver/receipt; correct target; no premature ban; legacy replay; explicit activation. | HOLD — constitutional ban remains disabled |
| WP-04A | C | P0 dependency | Nomination, qualification polling, ranked multi-selection ballot; governance/ballot schema. Existing binary/plurality flow is not STV. | Eligibility, ballot uniqueness, deterministic shortlist, poll thresholds, replay. | SPEC NEEDED |
| WP-04B | C | P0 dependency | Multi-seat STV tally and certification; GOV_EXECUTE-to-ROLE_EMISSARY_SEAT/ROLE_GOV_EXECUTOR_SET authority; default allowlist/canon alignment. | Exact quota/transfer/tie specification, deterministic certified winners, protocol-scope election, proposal-to-queue-to-appointment payload binding. | SPEC NEEDED |
| WP-05 | D | P1 | Automatic open-case withdrawal on REVIEWER_LANE_OPT_OUT in apply/roles.py, dispute/content assignments and reviewer_responsibilities.py. | Every affected case withdrawn or explicitly blocked under defined policy; no unauthorized further votes; penalties/replacements; atomicity/replay. | HOLD |
| WP-06 | A–D | P1 | tx_schema, tx_canon, V2 semantic compiler/review packet, CI. Fix unreachable DISPUTE_OPEN contract branches and dynamic role rejection extraction. | 17 separately adjudicated contracts, no missing stable IDs, exact-commit focused/full CI and two-node replay. | HOLD |

**Scope control:** WP-04A/B are election-system architectural dependencies, potentially larger than the original PR #77 semantic-review repair. Do not silently expand PR #77 into an unbounded election implementation. If separately tracked, keep dependent appointment reviews on HOLD and record the blocking reference here.

### Batch A execution checklist

- [ ] A1: Pin exact current HEAD, file blobs, canonical parameters, test baseline, historical fixtures.
- [ ] A2: Define invariant: original signed flag reporter equals queued escalation reporter equals dispute reporter; SYSTEM opener is not the complainant.
- [ ] A3: Authenticate flag ID, target, reporter and parent before escalation dedup, dispute creation, reviewer selection or receipt mutation.
- [ ] A4: Negative tests for substituted reporter, mismatched flag/target, missing/wrong parent; positive queue/repair; fail-atomic state roots; recusal across open/assign/accept/vote.
- [ ] A5: Verify activation and historical replay; record each affected semantic-review disposition, without approving dependent digests prematurely.

### Batch B execution checklist

- [ ] B1: Specify and verify protocol-wide juror candidate source for severe appeal; preserve disjoint original and appeal 25+5 panels and conflict exclusions.
- [ ] B2: Verify authenticated original ballots, 20-of-25 initial approval, and resolution outcome binding; reject forged tallies and false SYSTEM resolutions.
- [ ] B3: Freeze appeal voting threshold, finality, panel shortage retry and any waiver policy; complete authenticated mandatory independent appeal. Existing default-off experimental automatic appeal is **not** constitutional authorization.
- [ ] B4: Bind exact final receipt and sanction target to final appeal result; retain severe_sanction_automatic_appeal_unimplemented and severe_sanction_authorization_unimplemented until replacement proven.
- [ ] B5: Test duplicate/conflicting receipts, SYSTEM metadata forgery, queue/parent substitution, legacy replay, restart and independent two-node state roots.

### Batch C execution checklist

- [ ] C1: Test role activation v1/v2, explicit chain activation, dynamic RolesApplyError reasons and rollback after preliminary role-state touches.
- [ ] C2: Prove parentless scheduler-origin node-operator/validator activations and authenticated suspended reinstatement; preserve readiness/identity gates.
- [ ] C3: Freeze STV normative choices: electorate, nomination/qualification polling, seats, Droop-or-other quota, surplus transfer and arithmetic, ties, exhausted ballots, nullifiers, deadlines and certification.
- [ ] C4: Implement/test ranked multi-selection ballots, deterministic STV tally, certified winner-to-exact approved governance action, SYSTEM queue/parent and appointment binding.
- [ ] C5: Verify group-scope appointment denial, fabricated election certificate, candidate substitution, default/overridden action allowlist, treasury signer synchronization and replay.
- [ ] C6: Keep ROLE_EMISSARY_SEAT and ROLE_GOV_EXECUTOR_SET on HOLD until certification and execution authority are real; do not mistake existing multi-option plurality for STV.

### Batch D execution checklist

- [ ] D1: Inventory all open dispute/content case assignment surfaces, accepted duty, substitutes, existing votes and legacy inferred lane consent.
- [ ] D2: Define exact open-case attribution and automatic withdrawal semantics for each affected lane; process stable sorted case IDs in one canonical atomic transaction.
- [ ] D3: Resolve post-vote withdrawal, safe/late reputation penalty and replacement/insufficient-pool behavior without erasing committed ballots.
- [ ] D4: Test multiple lanes/cases, no open cases, post-vote cases, unavailable replacements, admission for banned/locked signer versus apply-time opt-out, rollback and restart.
- [ ] D5: Verify withdrawn reviewers cannot receive new affected-lane assignments or submit unauthorized later votes; preserve unrelated lanes and juror role.

### Seventeen transaction review ledger

| Transaction | Batch / package | Acceptance focus | Status |
| --- | --- | --- | --- |
| DISPUTE_OPEN | A / WP-01,06 | Accepted reporter provenance, recusal, reachable error contract | HOLD |
| DISPUTE_JUROR_ASSIGN | A,B / WP-01,02 | Conflict-free authenticated assignment, panel commitment | HOLD |
| DISPUTE_JUROR_ACCEPT | A,B / WP-01,02 | Assigned actor, reporter recusal, fail-atomic rejection | HOLD |
| DISPUTE_VOTE_SUBMIT | A,B / WP-01,02 | Unique valid juror and panel/round-bound vote | HOLD |
| DISPUTE_RESOLVE | B / WP-02,03 | Verified original 20/25 and exact outcome | HOLD |
| DISPUTE_APPEAL | B / WP-02 | Protocol-wide independent panel, deadline, pending pool | HOLD |
| DISPUTE_FINAL_RECEIPT | B / WP-03 | Authenticated finality; no hidden severe sanction | HOLD |
| ACCOUNT_BAN | B / WP-03 | Exact authorized sanction; constitutional fail-closed until proven | HOLD |
| ROLE_JUROR_ENROLL | C / WP-06 | Self-enrollment and versioned eligibility | HOLD |
| ROLE_JUROR_ACTIVATE | C / WP-06 | Enrollment, gate and rollback | HOLD |
| ROLE_JUROR_REINSTATE | C / WP-06 | Authorized reinstatement | HOLD |
| ROLE_VALIDATOR_ACTIVATE | C / WP-06 | Scheduler, operator, readiness and identity | HOLD |
| ROLE_NODE_OPERATOR_ACTIVATE | C / WP-06 | Scheduler authority and suspended reinstatement | HOLD |
| ROLE_EMISSARY_SEAT | C / WP-04B,06 | Certified STV winner, exact GOV_EXECUTE authority | HOLD |
| ROLE_GOV_EXECUTOR_SET | C / WP-04B,06 | Certified appointment, exact GOV_EXECUTE authority | HOLD |
| REVIEWER_LANE_OPT_IN | C,D / WP-05,06 | Exact lane consent, eligibility and assignment | HOLD |
| REVIEWER_LANE_OPT_OUT | D / WP-05,06 | All open affected cases auto-withdrawn, accountable replacement | HOLD |

### Runbook gates — mandatory after each package

1. **Baseline:** exact commit, branch, blob SHAs, policy flags, canonical state root and prior evidence.
2. **Normative freeze:** separate user-directed intent, source-observed behavior and unresolved decisions; version all consensus-semantic changes.
3. **Minimal implementation:** only bounded package changes; no blanket digest refresh, guard bypass or unsupported election/sanction claims.
4. **Focused proof:** positive and adversarial tests, precise errors, fail-atomicity, queue/receipt provenance, duplicates and malformed state.
5. **Replay proof:** historical pre-activation equivalence, activated restart/snapshot, independent two-node matching state roots.
6. **Evidence log:** exact commit, test commands, outputs, CI run IDs, environment, state hashes and remaining gaps.
7. **Semantic adjudication:** review each of 17 current reachable contracts separately; authorized maintainer acceptance before updating its digest and derivatives.
8. **Final gate:** full V2 compiler, Backend CI, Reviewer Readiness, A01–A20 P1, clean checkout and two-node rehearsal; Draft/no merge until all PR closure requirements are met. Public-beta blockers are separate.

### Decisions still open — do not infer

- Severe appeal vote threshold and finality, waiver authority if any, and indefinite insufficient protocol-wide juror pool.
- STV seat count, candidate nomination/polling thresholds, electorate, quota, transfer arithmetic, ties, exhaustion, invalid ballots and certification.
- Auto opt-out for already-voted cases, case-specific penalties, substitute ordering and legacy inferred-consent migration.
- Activation height/version and historical replay/migration for every consensus-affecting change.

**Next action:** A1 exact-head baseline; update this runbook after each bounded step. Do not accept stale digests or merge PR #77 solely because this documentation was updated.

### A1 exact-head baseline evidence (2026-11-03)

- **Pinned commit:** `737d4842d8b2bd0b52bdf7b798aa915a9436c934` on `review/pr70-pr75-pr76-consolidation-stage23-20261031`. GitHub commit metadata shows only this audit document changed in that commit; no runtime patch.
- **Source blob inventory at pinned commit:** `apply/content.py` `07b043cd103d3e6b323fc3ebfd514aba8456038f`; `apply/dispute.py` `f9014e936c45d627cdd9c39ea27d5c884755c8ef`; `apply/roles.py` `4d50b798317279ebb273bed2079dacfcc859eb51`; `apply/governance.py` `5e6bd68522f0c903572dcbd520c75f146a773313`; `apply/reputation.py` `c788f9711a6a45b6c3f20ce02fe9d00d2dfb376c`; `runtime/tx_schema.py` `73989607ae1e3f59b770b29c5dc9faf1038fdc52`; `runtime/system_tx_engine.py` `6138c87fc4dfdfc6c276b1b5e4630507dd873383`; `specs/tx_canon/tx_canon.yaml` `8d530c835b77b47401120bfe5003d89de0b136a6`.
- **Audit blob at baseline:** `f4a30fbd3450fefd11d7fe1aa28c71661948f281` (prior to this A1 evidence append).
- **Completed GitHub Actions for pinned commit:** Backend CI `41671591479` **failure**; Reviewer Readiness `41671591117` **failure**; A01–A20 P1 Revalidation `41671591046` **failure**; Web CI `41671591017` **success**; PR77 severe appeal threshold/fresh-panel safety `41671591151` **success**; severe-account finality fail-closed validation `41671591173` **success**; V2 DISPUTE_OPEN semantic-drift diagnostic `41671591019` **success**. These are observed workflow conclusions, not proof of why a failed workflow failed.
- **Outstanding baseline capture:** workflow failure logs and exact stale-digest count at this head; chain-committed policy parameters and activation flags; prior canonical state roots, historical replay fixture hashes, independent two-node evidence. Do not mark A1 complete until these are captured or explicitly recorded as unavailable.
- **Disposition:** A1 **IN PROGRESS**, no code modification, no semantic digest acceptance. Next action: inspect failing workflow logs and baseline config/fixture evidence, then advance to A2.

### A1 CI triage and forward-only sequencing (2026-11-03)

**User instruction:** If CI is blocked only by generated/review artifacts, continue the next substantive fix before regenerating or resetting; never waive semantic authorization.

**Exact baseline workflow logs inspected:**
- Backend CI run `41671591479`, job `126041088375`: fails at **Ruff changed Python files**, specifically `ruff format --check` after a `ruff format --diff` that reports formatting differences. This is a separate source-formatting failure, **not** merely stale generated artifacts. Full backend pytest did not run in this job.
- Reviewer Readiness run `41671591117`, job `126041087066`: transaction canon is synchronized (`236` tx types, `1.25.0`); fails V2 compiler because **17 semantic-review digests are stale** (the exact 17-row ledger above). This is an authorization/review hold, not permission to regenerate or accept all digests.
- A01–A20 P1 Revalidation run `41671591046`, job `126041086063`: **411 passed, 1 failed** (`test_a17_f001_archive_reproducible_v2_gate_executes`), because clean-checkout V2 compilation encounters the same 17 stale digests. Canon lint, tx index, V1.5 semantic vectors and lifecycle vectors passed their current-artifact checks.

**Disposition:** No evidence of an independent new functional failure in the P1 test set, but this does not establish complete backend health because Backend CI stopped at Ruff and V2 compilation remains blocked. The Ruff formatting defect is independently actionable. Do **not** reset semantic digests, regenerate them as acceptance, or declare green CI. Proceed to **Batch A2 reporter provenance invariant and WP-01 bounded correction** while retaining the CI failures as tracked closure items. Format the affected Python files as a separately evidenced cleanup before the final CI gate.

**A2 acceptance invariant (normative design, not yet implemented):** accepted signed content flag reporter must equal escalation reporter and dispute reporter; the SYSTEM scheduler opener is distinct from the complainant. Consumer must bind accepted `flag_id`, `target_id`, reporter and `CONTENT_FLAG:<flag_id>` parent before deduplication or any state mutation. Preserve historical queue/replay compatibility and version any consensus behavior change.

**Next step:** inspect exact producer/consumer branches and existing adversarial tests, then implement a minimal provenance correction and focused tests only after determining compatibility and activation boundary. Keep all 17 semantic reviews on HOLD.

### A2 producer/consumer inspection — source findings (2026-11-03)

**Observed (not fixed):**
- `apply/content.py::_apply_content_flag` writes `content.flags[flag_id]` with signer-derived `by`, `target_id`, `reason`, nonce and queues `CONTENT_ESCALATE_TO_DISPUTE` with `flag_id`, `flagged_by`, `target_id` and `parent=CONTENT_FLAG:<flag_id>`. Queue failure creates a pending repair record with the same copied reporter.
- `repair_pending_content_escalations` reconstructs escalation payload from pending record; it does not independently compare pending `flagged_by` and `target_id` against the accepted flag. Both queue producers therefore require consumer-side authenticated flag comparison, including repair and historical records.
- `_apply_content_escalate_to_dispute` currently deduplicates on `moderation_targets[target_id].dispute_id` **before** authenticating any accepted flag; later forwards `payload.flagged_by`/`reported_by` into `dispute_open` and writes that same unverified reporter onto dispute fields and panel exclusions. `dispute_open` stores reporter from payload while `opened_by` remains SYSTEM. This is a confirmed missing provenance check, not proof of a successful unauthorized transaction through the full block admission pipeline.
- `validate_system_tx_queue_binding` verifies queue ID, tx type, parent, signer, phase, due height and payload hash, but a queue item constructed from a corrupted or historically inconsistent pending record can still have internally consistent queue binding. Queue authenticity alone is not original-flag provenance.

**Minimal correction design, pending implementation:** introduce a single fail-closed accepted-flag provenance validator before the escalation dedup branch. For a flagged escalation, require nonempty flag ID, canonical flag record, matching target ID and original `by` reporter, and exact `CONTENT_FLAG:<flag_id>` parent; check payload aliases consistently and reject mismatches. Explicitly define how pre-activation unflagged/historical queued escalations replay without silently changing old blocks. Avoid reading `_mod_targets` or `_ensure_root` for mutation before rejection; rely on canonical transaction rollback and test direct-applier failure atomicity separately.

**Adversarial matrix to implement:** genuine first escalation; genuine already-escalated dedup; forged reporter with valid queue binding; substituted flag ID; mismatched target; wrong parent; missing flag; `reported_by` versus `flagged_by` disagreement; corrupted pending repair record; duplicate flag ID/replayed queue; historical pre-activation replay; post-activation two-node state root and restart equality.

**Disposition:** A2 source inspection complete; A3 runtime fix **NOT APPLIED**. Existing 17 semantic-review holds and Ruff cleanup remain tracked.

### A3 implementation checkpoint (2026-11-03)

- Runtime source commit `16418a0d91804c2e31e5737f0d89616d0c624df2` modifies only `src/weall/runtime/apply/content.py`: adds `_content_escalation_provenance_active` and `_verify_content_escalation_provenance`, called **before** the existing escalation dedup. The new validator checks original accepted flag record, target, signer-derived reporter, both reporter aliases when present, SYSTEM status and exact `CONTENT_FLAG:<flag_id>` parent. It uses read-only lookups before rejection.
- Test commit `fe3d92b27f7126bb1b93b233a0aa8e67e839306e` adds `tests/test_pr77_content_escalation_flag_provenance.py` with gate, genuine binding, forged reporter/flag/target/parent, and dedup-bypass negative tests.
- **Activation:** new opt-in `params.content_escalation_provenance_v1_activation_height` integer, default absent/inactive. **No governance activation or canonical policy version is approved**. Existing replay semantics remain when unset. This is a staged patch, **not** completed WP-01 closure.
- **Validation status:** GitHub source writes succeeded. Focused tests, Ruff and CI have **not yet been executed or verified** for these commits. In particular verify actual content-root layout, acceptance of legitimate queue envelopes, schema/canon compatibility, legacy replay, direct and canonical rollback, pending repair corruption, two-node equality and post-activation behavior. Do not claim test pass.
- **Disposition:** A3 IMPLEMENTED / UNVERIFIED, A4 adversarial matrix partially authored but not executed; WP-01 HOLD. The 17 semantic digests remain untouched. Next action: inspect new CI run results, fix any test or formatting failure, extend repair/restart tests, and freeze/authorize activation boundary before closing WP-01.

### A4 adversarial regression expansion (2026-11-03)

- Test extension commit `ed02b956535e7a06a904c77f49ef64187bd807e1`: corrected dedup fixture to the actual `content.moderation.targets` surface, added genuine dedup after provenance validation, accepted flag-record ID tampering rejection, and explicit pre-activation legacy dedup compatibility. Earlier negative tests cover forged reporter aliases, missing/substituted flag, target mismatch and wrong parent.
- At the time of inspection, GitHub Actions for the prior audit head `e364468ded2584abd3ba7b29de24505678968cf7` had Backend CI run `41673949983` **in progress**, A01–A20 P1 run `41673949952` **in progress**, Reviewer Readiness run `41673949947` **pending**. No pass/fail can be claimed for the new test-extension commit. Recheck exact latest head after CI completes.
- Remaining A4 work: execute focused pytest with exact command and environment, add queue-produced genuine escalation and pending-repair corruption tests, check direct-applier and canonical fail atomicity, Ruff format/check, versioned activation boundary, historical replay and independent two-node equality. Do not treat test presence as passing evidence.
- **Disposition:** A4 TESTS EXPANDED / EXECUTION PENDING. WP-01 HOLD; 17 semantic digests untouched; no PR merge authorization.

