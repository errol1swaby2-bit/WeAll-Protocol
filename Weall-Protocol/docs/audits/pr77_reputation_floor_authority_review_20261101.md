# PR #77 — Reputation-floor exclusion and V2 sanction-authority boundary (review-only)

**Disposition: CONSTITUTIONAL AUTHORITY NOT ESTABLISHED; NO SEMANTIC APPROVAL, NO MERGE, NO ACTIVATION.**

Source pin: PR #77 at `ed4cba72eb1fd3f7fd4a7a4bb2d016c9a7e14859` (2026-11-01). The GitHub Actions V2 semantic packet from run `41366661463`, artifact `13107696435`, reports **15 stale review digests**, 236 unique transaction records, zero missing `STATE-` IDs, and archived compiled contracts matching previously approved digests for all 15. It does **not** prove runtime behavior, replay compatibility, independent review, or human approval.

## Source-observed gap (separate from `TX-0904 / ACCOUNT_BAN`)

`src/weall/runtime/apply/reputation.py` has **two distinct mutation routes to account exclusion**:

1. `_apply_account_ban` rejects `ACCOUNT_BAN` when `policy_from_state(state).enabled` is true, before changing account or ban state. Its rejection is `forbidden:severe_sanction_authorization_unimplemented`.
2. `_apply_rep_delta_and_autoban` sets `accounts[account_id]["banned"] = True` and `reputation["bans"][account_id]` with `auto=True` when a reputation delta reaches the hard minimum. The helper contains **no constitutional-clock guard and no severe-case proof check**. Its two present call sites are `_apply_reputation_delta_apply` (SYSTEM-envelope transaction) and exported `apply_reputation_delta_system` (in-process system penalty helper). The module documents the legacy rule as reputation clamped to `[-100, 100]`, with automatic ban at `-100`.

The direct `ACCOUNT_BAN` no-go and the ordinary dispute-enforcement action filter **do not cover the floor-triggered mutation**. A sufficient negative reputation delta in an otherwise admitted SYSTEM flow can yield a banned account without executing `ACCOUNT_BAN`. This is a **source-derived enforcement-boundary finding**, NOT a claim that a remote user can forge SYSTEM envelopes or obtain such a delta through the network. Producer reachability, provenance, permitted slashing paths and authentic multi-node execution remain unproven in this review.

**Normative conflict requiring explicit decision:** The *draft* Genesis Constitution (Article II §4; Article II §7; Article VI §§3–4; Article VII §§2–4) requires due process, reviewability and correction of significant sanctions. The v2.0 *First Draft*, Part V §§32, 34–35 and `DSP-210`, `SAN-005`, `SAN-006`, requires an automatic fresh-panel appeal for severe sanctions and independent evidence/appeal/restoration for indefinite exclusion. A reputation floor can be a numerical eligibility threshold, but it is **not by itself authenticated proof of an S4 decision**. The architecture must distinguish ordinary reputation consequences and temporary capability restrictions from durable protocol-wide exclusion.

### Bounded characterization test

`tests/test_pr77_reputation_floor_ban_boundary_characterization.py` records current behavior, not a desired normative outcome. It compares bounded-rollback and deepcopy execution for synthetic `REPUTATION_DELTA_APPLY` floor crossings in clock-disabled and clock-enabled states; it also checks the exported system-delta helper in both states. It asserts the documented `auto=True` ban record and matching roots. Passing this test must **not** be described as a constitutional safety PASS. The tests cannot establish that SYSTEM actors, ballots, or penalty events were authenticated or replay-safe.

## Further consistency concern (requires separate test)

`src/weall/runtime/apply/dispute.py::_apply_inline_content_enforcement`, for an `ACCOUNT_REINSTATE` action, clears `accounts[account_id]["banned"]` but does not update `reputation["bans"]`. By contrast, the canonical `src/weall/runtime/apply/reputation.py::_apply_account_reinstate` updates both structures. This may leave a disagreement between current account flags and the ban audit map following an inline dispute remedy. Whether either is consulted as authoritative by downstream admission, read models, and replays must be traced before proposing a fix. This is a **source-level consistency concern**, not a demonstrated live exploit.

## Required adjudication before authorizing code changes

1. **Define sanction classes and their authority:** Is the `-100` automatic ban merely an account capability restriction, a temporary exclusion, or an indefinite S4 sanction? Specify rights preserved while excluded, notice/appeal, and restoration authority.
2. **Trace every ban-state writer:** Include direct `ACCOUNT_BAN`, reputation-floor crossing, slashing/helper calls, other `accounts[*].banned` mutations, inline reinstatement, and migration/init paths. Bind each to a real producer and authenticated authorization proof, not a self-asserted SYSTEM flag.
3. **Preserve historical replay:** Characterize legacy behavior at every gate version. Do not silently alter the floor behavior, historical blocks, or receipts until authentic retained old-height replay and versioned activation semantics are proven.
4. **Build fail-closed production authorization:** If the target distinguishes reputation thresholds from indefinite exclusion, implement behind an explicit consensus gate with correct dispute lineage, canonical classification, replay-safe receipts, pre-mutation checks and denial tests. Keep protected participation separate from service-role eligibility.
5. **Reconcile the full V2 review queue:** A new versioned change to `REPUTATION_DELTA_APPLY` could introduce a 16th stale semantic contract. No compiler-digest refresh, independent-review flag or reviewer signoff may be automatic. The nine role/reviewer contracts' static `RolesApplyError:runtime_apply_failure` expansion also needs runtime error-contract analysis.

**Release consequence:** PR #77 remains Draft; the 15 existing V2 reviews, old-version ledger replay, the authenticated severe-sanction producer, and independent two-machine validation remain blockers. This note adds a separate P0-candidate source-level authority gap; it is not a newly verified network attack, not a runtime patch, and not an approval of any V2 review.
