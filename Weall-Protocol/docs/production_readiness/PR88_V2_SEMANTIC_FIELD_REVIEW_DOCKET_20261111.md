# PR #88 — Source-bound V2 semantic field review docket

**Date:** 2026-11-11
**Status:** REQUIRES MAINTAINER SEMANTIC REVIEW — NOT APPROVED
**Diagnostic source:** [PR77 V2 semantic field drift, no approval, run 43111338188](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/43111338188/artifacts/13896501577) (`changed_fields.json`, `summary.json`, 20 transaction rows).
**Reference branch HEAD before this docket:** `f5aa2c37201931ca2eef2d736fd6c97c7a39b78c`.

This docket summarizes *actual current-versus-checked-in* field differences reported by the static V2 derivation. A changed field is not necessarily a runtime behavior change; conversely a static derivation is not sufficient evidence that all indirect runtime behavior has been captured. Nothing here confers independent review, semantic acceptance, genesis authorization, confidential-ballot approval, or release permission.

## Priority findings and extraction limitations

**P0 — Dynamic role eligibility errors are not literal error codes.** Nine role/reviewer transactions report a new `RolesApplyError:runtime_apply_failure` pair and omit several previously tracked explicit eligibility errors. In `src/weall/runtime/apply/roles.py::_require_role_activation_eligible`, actual errors are built from `str(decision["code"])` and `str(decision["reason"])`, where `decision` comes from `reputation_role_gate.role_activation_reputation_decision`. The static `scripts/compile_v2_spec.py::_extract_failures` extractor falls back to the *exception class name* when its arguments are not literal strings. Therefore this new pair is an **unresolved static-analysis placeholder, not a proven canonical error code**. Required: derive actual reason matrix through the pure predicate and caller tests, and either improve extractor coverage conservatively or explicitly represent unresolved dynamic failure semantics. Do **not** approve the placeholder as a complete failure contract.

**P0 — `DISPUTE_OPEN` analysis scope shifted.** `src/weall/runtime/apply/dispute.py::apply_dispute` delegates `DISPUTE_OPEN` to `dispute_open`. The current static derivation now attaches the dedicated handler, while the checked-in acceptance was bound to the broad dispatcher: reported receipt keys **24 → 2**, read keys **87 → 17**, write keys **78 → 16**, failure pairs **25 → 5**, and named system follow-ups **15 → 3**. Much of this shrinkage can reflect more precise transaction scoping, but it also raises coverage questions for indirect helpers (panel selection, PoH, target owners, follow-up enqueue and rollback). Required: verify the effective receipt, state mutation, rejection, and queued follow-up behavior from end-to-end tests and the normative spec before changing the accepted digest.

**P0 — Severe sanctions and appeal authorization.** Newly reported conditions include `severe_appeal_fresh_panel_unverified`, `severe_sanction_initial_outcome_mismatch`, `severe_sanction_initial_twenty_votes_unverified`, `automatic_severe_appeal_already_assigned`, `appeal_pending_panel`, `severe_sanction_automatic_appeal_unimplemented`, and `severe_sanction_authorization_unimplemented`. Review fail-closed behavior, required vote counts, independence/conflict exclusions, and final-receipt side effects; no approval from a digest update alone.

**P0 — Group-emissary quorum and signer authority.** `GROUP_EMISSARY_ELECTION_CREATE` adds electorate source, eligible-voter count, quorum activation height, policy version and required votes to the write contract. `GROUP_EMISSARY_ELECTION_FINALIZE` adds quorum status/no-decision metadata and three receipt fields (`eligible_voter_count`, `required_votes`, `quorum_met`), plus `unsupported_group_emissary_quorum_version`. Review the 3-of-5 no-decision and 4-of-5 successful election outcomes, retained treasury signers, replay/restart consistency and the separate **public ballot identity/ranking privacy blocker**.

## All twenty drift rows

The columns enumerate fields that changed in `changed_fields_against_checked_in_contract`. The failure-condition column lists newly reported reasons, *not necessarily newly introduced runtime behavior*.

| Transaction | Changed semantic fields | New candidate failure reason(s) / review concern |
| --- | --- | --- |
| `DISPUTE_OPEN` | failure_codes, implementation_source, receipt_contract, state_reads, state_writes, system_followups | `dispute_id_exists`, `active_proposal_dispute_protected`, `tier1_required_for_dispute`, `missing_target`, `proposal_not_found`; also huge removal of broad-dispatcher records |
| `DISPUTE_JUROR_ASSIGN` | failure_codes, state_reads | `juror_conflict_reporter`; verify reporter/conflict identity aliases |
| `DISPUTE_JUROR_ACCEPT` | failure_codes, state_reads | `juror_conflict_reporter`; verify no conflict can accept a panel seat |
| `DISPUTE_VOTE_SUBMIT` | failure_codes, state_reads | `juror_conflict_reporter`, `severe_appeal_fresh_panel_unverified`; verify vote nullifier and fresh panel |
| `DISPUTE_RESOLVE` | failure_codes, state_reads | `automatic_severe_appeal_already_assigned`, `severe_sanction_initial_outcome_mismatch`, `severe_sanction_initial_twenty_votes_unverified` |
| `DISPUTE_APPEAL` | failure_codes, state_reads, state_writes | Adds `automatic_severe_appeal_already_assigned`; drops tracked `insufficient_fresh_appeal_panel`; writes shift from ballot fields to blocked/pending panel fields |
| `DISPUTE_FINAL_RECEIPT` | failure_codes, state_reads | `appeal_pending_panel`, `severe_sanction_automatic_appeal_unimplemented`; verify no premature enforcement |
| `CONTENT_FLAG` | failure_codes | `duplicate_flag_id`; verify idempotent receipts and no double enforcement |
| `ACCOUNT_BAN` | failure_codes, state_reads | `duplicate_ban_receipt_conflict`, `severe_sanction_authorization_unimplemented`; verify authorization and duplicate handling |
| `ROLE_JUROR_ENROLL` | failure_codes, state_reads, state_writes | Dynamic `RolesApplyError` placeholder; read `gate_version`/canonical gate reasons |
| `ROLE_JUROR_ACTIVATE` | failure_codes, state_reads, state_writes | Same dynamic eligibility-code limitation; verify reputation and live PoH |
| `ROLE_JUROR_REINSTATE` | failure_codes, state_reads, state_writes | Same; verify prior revocation and reinstatement boundary |
| `ROLE_VALIDATOR_ACTIVATE` | failure_codes, state_reads, state_writes | Same; verifier authority must stay generation-bound and fail-closed |
| `ROLE_NODE_OPERATOR_ACTIVATE` | failure_codes, state_reads, state_writes | Same; operator responsibility cannot bypass versioned activation |
| `ROLE_EMISSARY_SEAT` | failure_codes, state_reads, state_writes | Same; verify election/signer and role gate separation |
| `ROLE_GOV_EXECUTOR_SET` | failure_codes, state_reads, state_writes | Same; verify governance approval and executor authority |
| `GROUP_EMISSARY_ELECTION_CREATE` | failure_codes, state_writes | `no_eligible_group_electorate`, electorate/quorum snapshot fields |
| `GROUP_EMISSARY_ELECTION_FINALIZE` | failure_codes, receipt_contract, state_reads, state_writes | `unsupported_group_emissary_quorum_version`, quorum/no-decision receipt fields |
| `REVIEWER_LANE_OPT_IN` | failure_codes, state_reads, state_writes | Same dynamic eligibility-code limitation; verify scope and non-escalation |
| `REVIEWER_LANE_OPT_OUT` | failure_codes, state_reads, state_writes | Same placeholder; verify withdrawal without whole-juror deactivation |

**Additional specific comparison:** The appeal candidate adds `appeal_panel_available_candidate_count`, `appeal_panel_blocked_reason`, `appeal_panel_required_size`, `appeal_pending_since_height`, and `appeal_substitute_required_count`, while the tracked derivation included five ballot-mutation keys now absent from that static transaction slice. This is a material boundary to review, not an assertion that appeal voting was removed from runtime.

## Follow-up: dynamic-error AST extraction correction

The compiler's `_extract_failures` previously treated a dynamic first
argument to `RolesApplyError` as the literal canonical failure code
`RolesApplyError`. This is not the code emitted by
`_require_role_activation_eligible`: the typed runtime exception receives
`decision["code"]` and `decision["reason"]` from the operative pure
predicate. The narrow reviewed correction maps **only** these unresolved
dynamic `RolesApplyError` call sites to the existing registered static
fallback `runtime_apply_error:see_handler`. It does not fabricate individual
runtime failure codes or constitute semantic acceptance.

A proposed generic dynamic-first-argument correction was observed in CI to
expand stale review digests from 20 to 43 transactions, including 23 additional
PoH transactions. That broad change was not accepted in this increment.
Other dynamic error families remain an explicit **future static-analysis
audit task**; their earlier reports must not be assumed complete or
independently verified. The 11 predicate/exception propagation runtime tests
and the four AST extractor regressions are evidence, not authorization to
refresh any reviewed digest.

## Bounded transitive target-validation extraction evidence (subsequent increment)

The dedicated `DISPUTE_OPEN` handler calls
`_validate_dispute_target_type` before it initializes or writes the dispute.
That helper raises `DisputeApplyError("forbidden",
"unsupported_dispute_target_type", ...)` for unrecognized target types.
The compiler's preexisting local-call prefix allowlist omitted this
`_validate_` helper and therefore omitted the operative rejection from the
static `DISPUTE_OPEN` failure index.

The V2 traversal is now extended **only for the direct edge from
`dispute_open` to `_validate_dispute_target_type` in `DISPUTE_OPEN`**.
A focused source-regression checks both the dedicated entrypoint and the
shared dispatcher entrypoint, while the existing direct-versus-dispatched
runtime rejection tests cover the actual error tuple and prevent phantom
dispute, account or queue effects. This is extraction-evidence hardening,
not proof that the static analysis is exhaustive: it still misses some
indirect helper reads/writes, cannot determine branch reachability, and
does not establish independent semantic acceptance. In particular, the
static proposal-specific error paths are currently unreachable behind the
target allowlist. No acceptance digest or generated V2 derivative was
refreshed or approved by this correction.

## Append-only group-election state IDs (separate bounded follow-up)

A strict source-registry coverage regression exposed eight unregistered
`Groups:` state tokens in the already-implemented emissary quorum/election
read/write projection: `electorate_source`, `eligible_voter_count`,
`n_ballots`, `no_decision_reason`, `quorum_activation_height`,
`quorum_met`, `quorum_policy_version` and `required_votes`.
These are now registered as **new deterministic `STATE-` IDs** in the
existing append-only `stable_ids.json` source registry; no existing
entry, alias, ID or tombstone was changed. A focused test independently
recomputes the IDs from their canonical `Groups:` names. This is registry
coverage, **not** review or approval of quorum semantics, elected signer
authority, ballot confidentiality, or canonical receipt correctness.
Accepted semantic digests and V2 generated derivatives remain untouched.

## Constitutional-clock final receipt vs. pending appeal adjudication (bounded follow-up)

Source inspection of `runtime/dispute_engine.py::tick_dispute_lifecycle`
found that a successfully decided ordinary appeal is queued for final receipt
only after its stored panel result reports a reached decision and the scheduler
moves the case from `appeal_resolved` to `finalizing`. Before this increment,
`apply/dispute.py::_apply_dispute_final_receipt` held
`appeal_pending_panel` but did **not** hold `appealed` or `appeal_review`:
a synthetic SYSTEM envelope containing an arbitrary
`appeal_resolution` could bypass the panel and finalize a non-severe
appeal in the direct applier. This does not prove that an external attacker
can manufacture an admitted canonical SYSTEM transaction; queue-origin and
signed-block admission must be verified separately.

The constitutional-clock handler now rejects final receipts for appealed
cases unless their state is already `finalizing` (or already `finalized`
for historical receipt deduplication), the persisted
`appeal_panel_result` has `reached=True` and a nonempty resolution, and
a supplied `appeal_resolution` exactly matches the stored decision.
A supplied base `resolution` cannot replace the source resolution for
an appealed case. This check executes before the receipt root or juror
accountability is written; `appeal_pending_panel` continues to produce
its original rejection. All new reasons remain **unapproved V2 semantic
changes** until independent review. Legacy-clock paths are unchanged.
Synthetic direct-applier tests cover unresolved stages, forged
`finalizing`, conflicting claimed decisions, base-resolution override,
and a matching stored reached decision. They do not prove authenticated
SYSTEM parent lineage, historical replay, or constitutional sanction
authority. The preexisting severe-S4 automatic-appeal NO-GO remains intact.

## V2 static state-token coverage for appeal guard (source-only)

The current compiler treats two literal source keys in the new receipt
precondition, `Dispute:reached` (persisted panel-result read) and
`Dispute:appeal_resolution` (incoming receipt-payload read), as state-index
tokens. Both now have new deterministic append-only `STATE-` IDs in the
V2 source registry. These identifiers do not imply that a payload key is a
new persisted state object, validate the provenance of a SYSTEM receipt,
or accept a changed semantic-review digest.

## Synthetic account-reinstatement characterization under tightened appeal guard

The existing `test_pr77_account_reinstatement_state_consistency.py` used
`DISPUTE_FINAL_RECEIPT` with a fabricated SYSTEM marker, synthetic
`appeal_resolution`, and a dispute still in `appealed`. The new
constitutional-clock guard correctly rejects that direct executor input
before account, ban-index, receipt or juror-accountability mutations.
The characterization tests now distinguish these modes explicitly:
**constitutional-clock execution must fail closed and roll back in both
bounded and deepcopy atomic executors; legacy-clock execution still
demonstrates its preexisting account-vs-ban-index inconsistency**.
No earlier legacy behavior was quietly relabeled as a verified appeal.
The inconsistency remains an independent historical/state-reconciliation
review item rather than justification to relax constitutional enforcement.

## Appeal-finalization SYSTEM queue provenance (bounded synthetic integration)

The ordinary `appeal_resolved` scheduler path emits a pre-phase
`DISPUTE_FINAL_RECEIPT` with a deterministic parent reference,
case-specific receipt ID, exact due height, and payload copied from the
persisted reached panel decision. The SYSTEM queue commits these fields in
its deterministic `queue_id`. The common
`validate_system_tx_queue_binding` checks the emitted transaction's
payload, signer, parent, due height, phase and TxType against that queue
record; the canonical block replay path invokes this check before
application and independently derives expected pre-phase SYSTEM queue IDs.

The new **synthetic queue-provenance regressions** exercise a reached
appeal through `tick_dispute_lifecycle` and the production
`system_tx_emitter`, validate its exact queue binding, compare
independently recomputed scheduler/emitter states and state roots,
and reject mismatched queue IDs, parent, signer, receipt ID, decision,
TxType, phase or due height. A mutated stored queue record also fails
its deterministic ID validation. No receipt is scheduled if the panel
result is not reached. These tests use synthetic adjudication state,
do **not** replay a signed block or independently authenticate panel
ballots, and do not establish that a fabricated scheduler state can
arise through valid signed transactions. A queue ID proves consistency
with the *current deterministic queue*, not constitutional authority,
jury independence, or authentic verdict provenance. No V2 semantic
digest has been accepted or regenerated for these results.

## Synthetic production candidate and independent follower replay attempt

A follow-up integration regression stages the same synthetic reached
`appeal_resolved` state into independent `WeAllExecutor` instances
and exercises the production block candidate builder and `apply_block`
replay with one due pre-phase `DISPUTE_FINAL_RECEIPT`. This is a
candidate/replay composition check for queue scheduling, admitted SYSTEM
envelope metadata and matching state roots; it deliberately seeds
the original appeal-panel result instead of pretending that independent
jurors, signed votes, historical blocks or BFT finality created it.
Only successful exact-head CI constitutes a passing result for this test.

## Signed ordinary appeal ballots through persisted final receipt (new exact-head test)

The existing signed strict-appeal SQLite fixture is extended **without
seeding an appealed-case resolution or editing a committed stage**. It
creates independent synthetic reviewer accounts using the controlled
dev-bootstrap and their deterministic test signing keys, records the
initial verdict through signed juror votes, and commits a signed
`DISPUTE_APPEAL`. It then requires each fresh-panel voter to issue
a separately signed `DISPUTE_JUROR_ACCEPT` and
`DISPUTE_VOTE_SUBMIT` with `appeal_decision=reverse` until the
on-chain appeal threshold is reached.

The next user-empty block must generate its `DISPUTE_FINAL_RECEIPT`
through the production scheduler and SYSTEM queue rather than through a
fixture-injected receipt. The persisted original SQLite executor must
restart at the resulting head, and an independent SQLite executor must
replay every committed block from the synthetic genesis, including
the signed appeal ballots and final SYSTEM receipt, with matching
state roots and finalized appeal state. This is an explicit
**signed synthetic development-chain test**, not external humanity
verification, juror independence, autonomous peer-to-peer HotStuff
finality, a historically approved consensus upgrade or S4 sanction
permission. It has no implied CI success until the exact commit is tested.

## Persisted appeal-finalization JSON projection invariant (diagnosed regression)

A newly extended, signed synthetic ordinary appeal fixture **failed** on the
first actual final-receipt block: the in-memory candidate and post-commit
state roots matched the block header, but reopening the SQLite snapshot
failed `db_invariant_violation: snapshot state_root does not match persisted
tip block state_root`. A read-only `_canon_json` round-trip comparison
isolated a single difference at
`dispute_receipts/<receipt>/resolution/tally/no`. The final-receipt helper
used `dict(original)` (a shallow copy) on a resolution that can carry a
nested rollback-journal proxy. Its inherited raw storage and live view
can serialize differently, so the committed block-root preimage was not
the persisted JSON representation.

The bounded source repair makes `_final_receipt_resolution` detach nested
journal-backed input structures with the existing
`materialize_journaled` helper, including the copied original resolution
and appeal-resolution fallback, before writing canonical receipt state.
This avoids changing vote threshold, finality authority, appeal outcome or
legacy semantics to mask the mismatch. The signed fixture retains explicit
candidate/header, JSON-round-trip, post-commit, durable SQLite and restarted
executor root checks. It must be validated on the exact patched head;
**do not regard a source-only fix as a passing durability proof**.

## Intermittent authenticated TCP restart: captured ban failure, diagnostic-only change

The dependent repeat of the 98/98 group-election/BFT primary regression
at [run 43132035627](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/43132035627)
**failed** when the intended height-2 validator restart could not
reauthenticate. The restarted `@v1` reported eight localhost TCP peer
records with `banned=true`, three strikes each, no verified identity,
and zero established sessions; three surviving validators were still
authenticated. This disproves treating the intermittent strike/ban as a
resolved issue, even though earlier recovery repetitions passed. The
worker already records bounded `NetNode._strike` callsite/exception/
message/session traces in worker-only memory, but this earlier failure
site dumped only peer status, omitting the actual strike reasons.

The bounded regression amendment adds **`peer_strike_debug` on the
existing failure path** at the initial restart check, using the same
worker-only trace collector already exposed for the later rejoin path.
It does not change production peer security keys, session admission,
strike weights, ban thresholds or cooldowns. The transport-host grouping
of localhost endpoints is a candidate for investigation, not an
established cause. A captured failing run with callsites/reasons is
required before proposing an authentication-policy correction.

## Bounded next review actions

1. **Dispute lane:** walk dedicated handler calls and helper effects against actual live receipts, rejection-path atomics and severe-sanction gate tests. Confirm that the new narrower `DISPUTE_OPEN` derivation includes all consequences it claims and distinguishes external effects deliberately excluded from direct function analysis.
2. **Role lane:** inspect `role_activation_reputation_decision` and role-specific caller branches. Enumerate and test the concrete `(code, reason)` outcomes for legacy and activated gate versions; fix or explicitly qualify dynamic static-analysis gaps before accepting any associated review digest.
3. **Group election lane:** prove quorum policy versioning, 3/5 no-decision, 4/5 success, signer retention/change, restart replay and receipt fields. Preserve the confidential-ballot NO-GO independently.
4. **Review record update:** only after human-maintainer semantic acceptance of the exact current contracts, run the existing *explicit per-transaction* `refresh_v2_semantic_reviews.py` procedure with an actual identified reviewer and appropriate review method. Never insert a fictitious reviewer, auto-update all 20, or claim independent authorization. Regenerate and verify all V2 derivatives from the exact clean checkout.
5. **Release decision:** P1, Reviewer Readiness, Backend CI, privacy and constitutional/genesis gates remain **NO-GO** until the real checks pass on the exact HEAD.

This docket records the separately bounded append-only group state ID registration, but does not authorize changes to `semantic_reviews.json`, accepted semantic digests or generated V2 derivatives.
