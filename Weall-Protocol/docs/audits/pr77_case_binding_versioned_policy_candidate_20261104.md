# PR77 CASE-binding versioned conflict policy — review candidate (2026-11-04)

**PROPOSED ONLY. No activation, no semantic sign-off, no historical compatibility proof, no public-testnet authorization.** This is a source-grounded policy decision packet, not consensus code.

## Observed current behavior and evidence boundary

- `src/weall/runtime/apply/dispute.py::_apply_case_receipt` first calls `_require_system_env` and `_ensure_cases`. For `CASE_BIND_TO_DISPUTE`, it stores a binding only if the case ID is absent, yet returns a success-shaped result with the newly requested dispute ID on a conflicting duplicate.
- `tests/test_pr77_case_synthetic_executor_replay.py` reproduces a block with two successful conflicting synthetic SYSTEM requests. The first binding remains stored; producer, follower and restarted executors have matching roots. The block's `ok` receipt does not contain a `dispute_id`; the semantic discrepancy is between the successful second transaction payload and durable state, *not* a fabricated receipt field.
- Canonical rejection for malformed queued CASE requests has been tested fail-atomic, including restart excluding the documented local crash marker. Raw handler mutation before rejection is not the same as committed mutation.
- `src/weall/runtime/apply/governance.py::DEFAULT_GOV_ACTION_ALLOWLIST` excludes CASE binding. A manually set `params.gov_action_allowlist` passes one gate only; this does not prove a lawful governance proposal or a real scheduler/parent path.
- Current focused evidence: [26/26 tests, run 41742740513](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/41742740513). See `docs/audits/pr77_case_receipts_source_adjudication_20261103.md` for details and limitations.

## Proposed new-version semantics, subject to approval

| Input | Proposed action after approved activation | Before activation |
| --- | --- | --- |
| Valid first `case_id` → `dispute_id` | Persist once and acknowledge with authenticated provenance | Existing legacy first-write-wins |
| Same case, same dispute | Idempotent acknowledgment **only after** confirming canonical payload/action equivalence and valid origin; do not rewrite initial record | Existing legacy response and state |
| Same case, different dispute | Stable deterministic conflict rejection (proposed `conflict:case_dispute_binding_immutable`); no successful acknowledgment and no replacement | Existing legacy acknowledgment/first binding |
| Missing/invalid identifiers | Reject atomically without committed state mutation | Preserve old execution semantics/roots |
| Unknown/malformed activation information | Fail closed in future version-selector logic | Never treat arbitrary fields as approval |

The exact definition of payload equivalence, authenticated case/parent/signer binding, required dispute existence, a valid rebinding/migration action if ever permitted, direct handler error shape, and block-level receipt codes are **review questions**, not settled specifications. `CASE_TYPE_REGISTER` has a separate potentially conflicting first-write-wins behavior and must be adjudicated independently.

## Version and history requirements

1. The symbolic label `CASE_BINDING_V2` is not an active protocol setting. Never interpret an untrusted `params.case_binding_policy_version`, client flag, SYSTEM boolean, timestamp or claimed authorization as activation.
2. A constitutional/protocol process must establish a signed, finalized, **chain-committed** policy/code/receipt commitment and deterministic height `H_activate`. Replaying every block at `h < H_activate` must use the original semantics, regardless of local software version. Blocks at `h >= H_activate` may use the new rules only after their authenticated parent history proves activation. Define explicitly whether activation takes effect the following block.
3. Do not rewrite old receipts, existing immutable case bindings, historical block roots or accepted review digests. Require a retained pre-activation ledger corpus, old implementation pin, per-height old-vs-new replay/receipt/root evidence, and snapshot-bootstrap compatibility.
4. A conflicting queued mandatory SYSTEM action may cause block construction to fail. Specify deterministic scheduling/preflight plus resolution of pending backlog and retry loops **before activation**. Never silently drop a committed/scheduled action or treat liveness recovery as authorization.
5. Test proposer/follower/restart, old/new boundary, same-block duplicates, out-of-order queue events, malformed state, unknown selectors, parent mismatch and partition/rejoin; verify full historical replay and explicit reviewer acceptance.
6. The 18 other stale semantic-review contracts and all release NO-GO gates remain binding. Do not alter `semantic_reviews.json`, the executor, scheduler, default governance action allowlist, or public claims as part of this candidate.

## Machine-checkable read-only aid

`tooling/case_binding_policy_candidate.py::review_case_binding_candidate` classifies `UNBOUND`, `IDENTICAL_TARGET`, `CONFLICTING_TARGET` and malformed state. Its output is explicitly unauthorized, non-mutating and non-activating. The paired stdlib tests and optional dedicated CI check neither repair consensus nor claim real scheduler reachability.

**Decision requested from maintainers:** approve/refine the future idempotency/conflict/replay/liveness requirements, then authorize separate implementation and cross-version evidence. **Current status: REVIEW HOLD / NO-GO.**
