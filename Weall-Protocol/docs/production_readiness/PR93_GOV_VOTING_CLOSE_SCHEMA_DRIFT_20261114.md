# PR #93: canonical GOV_VOTING_CLOSE payload schema mismatch

**Date:** 2026-11-14  
**Status:** Candidate compatibility repair, **not a constitutional or release approval**.

The reinstated independent F1b regression exposed a full signed Tier-2 governance replay failure after 146 focused checks passed. The producer failed closed while constructing a committed block: `system_tx_apply_post_failed:invalid_tx:system_tx_admission_failed`. A read-only wrapper around the exact production `block_builder.admit_tx` call narrowed the failure to `GOV_VOTING_CLOSE`, `invalid_payload:schema_validation_failed`, not an invalid signature or failed QC.

## Source-level discrepancy and bounded repair

- `src/weall/runtime/apply/governance.py` queues `GOV_VOTING_CLOSE` with `proposal_id` plus deterministic `close_reason`: `poll_threshold_reached` or `quorum_reached`. The same handler consumes `close_reason` when recording the electorate round.
- `src/weall/runtime/tx_schema.py::GovVotingClosePayload` previously allowed only `proposal_id`, while `_StrictModel` forbids extras. Block admission strips only internal underscore-prefixed queue binding fields, and rightly rejected the public `close_reason` field.
- The candidate adds one **optional, nonempty string** `close_reason` to the canonical strict payload shape. No new signing rights, SYSTEM bypass, queue-binding bypass, new transaction type, or client-supplied authority is added.
- The full source-integrated signed governance and QC rehearsals remain necessary; a model-only check is not sufficient to assert end-to-end closure.
- Other unrelated fields remain forbidden. New tests cover both emitted `close_reason` values and unknown-field rejection.

This correction is **consensus-affecting payload admission behavior**. It must receive the normal protocol compatibility/source review before any release or activation. It does not resolve the separate 20 stale V2 semantic-review digests, two unregistered dispute state tokens, real-world independence proof, PoH production gating, or genesis authorization. Source-bound B5xx rehearsal proofs require a new exact-head regeneration and substantive comparison before acceptance.

## Additional queued tally payload drift detected from the same source

The same `apply/governance.py` function constructs a deterministic `GOV_TALLY_PUBLISH` payload containing `vote_window`, `vote_model`, `eligible_validator_count`, `required_votes`, `yes`, `no`, `abstain` and optional multi-option selection/tie fields. Those public fields were not listed in the previous strict `GovTallyPublishPayload` model, even though the runtime emits and consumes them. The bounded candidate aligns this schema with only those explicit emitted shapes, preserves unknown-field rejection and numeric nonnegativity, and adds strict tests for binary and multi-option receipts. It does **not** relax SYSTEM origin authorization or justify an automatic governance activation. Full F1b/Backend CI and substantive protocol-change approval remain mandatory.
