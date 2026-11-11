# Group emissary election quorum v1 — activation-gated consensus compatibility

**Status:** IMPLEMENTED BEHIND UNSET GOVERNANCE PARAMETER · NO ACTIVATION AUTHORIZED · DRAFT / NO-GO

## Policy clarified by protocol architect

Emissary elections require a participation **quorum just like ordinary governance**, before they can change emissary or group treasury signer authority. The ordinary governance default is integer `ceil(2n/3)` of the eligible snapshot (see `apply/governance.py::_electorate_required_votes` and `bft_hotstuff.quorum_threshold`). This patch applies that **default**, without inventing policy-specific overrides. For 20 eligible group members, participation by 14 distinct eligible voters is required.

The full-weight successive ranked preference redistribution remains WeAll's intended tally rule. A quorum counts voters who cast **valid canonical ballots**, not repeated entries in a ranking or multiple legacy replacements by the same account.

## Explicit activation gate: not enabled by this PR

A governance-whitelisted numeric param `params.group_emissary_quorum_activation_height` may be set to a **positive height** in a separately constitutionally authorized process. It is **absent by default**; this PR does not set it or enact a governance decision. It is not legal or sufficient for UI code or a node operator to infer approval from these tests.

The canonical group election **create** path checks the current applying height against that param. Only elections created on or after activation persist `quorum_policy_version=1`, frozen `eligible_voter_count` and `required_votes`. Elections created before activation or with no approved parameter stay on their historical semantics **even when finalized later**. Changing the param later cannot retroactively change existing election snapshots.

For version 1, the finalizer recomputes the required threshold from the frozen electorate and checks that it matches persisted metadata. Any mismatch fails closed as an invalid state. Successful ballots are counted from the appropriate canonical legacy vote map or strict aggregate ballot-box counts.

- If `n_ballots < required_votes`, the finalizer commits `no_decision` (reason `quorum_unmet`, or `no_valid_ballots` at zero), records the threshold and tally, and **does not mutate group emissaries, signers or treasury signers**. Repeated finalize remains deduped and preserves the original reason.
- If participation reaches quorum, the existing deterministic full-weight ranked redistribution runs and existing group/treasury authority update path is unchanged.
- Public election projections show only aggregate quorum fields and an outcome reason, not voter IDs, per-voter ballots or nullifiers. The public frontend still cannot submit confidential ballots.

## Electorate eligibility parity remains an activation blocker

The **quorum arithmetic** matches ordinary governance, but **eligible voter selection does not yet match**: ordinary group governance calls `_active_group_member_ids`, which filters by active membership, resolved account record, default PoH Tier 2, and banned/locked/suspended status. Existing emissary elections freeze `_group_member_snapshot` from the group's membership map. This version 1 patch intentionally preserves that electorate snapshot for historical compatibility; it does **not** claim parity with regular governance's group electorate eligibility. The new focused negative test demonstrates that five members could yield five emissary-snapshot voters but just one governance-eligible Tier 2 voter.

**Do not activate** this version until the electorate definition is constitutionally confirmed and either reconciled with group governance through a separately reviewed versioned policy or expressly distinguished. A threshold calculated from the wrong denominator cannot be treated as equivalent constitutional quorum even if it uses the same fraction.

## Tests, scope and outstanding release work

Synthetic canonical-apply regressions compare default regular-governance thresholds (1, 2, 3, 5, 20 eligible participants), verify strict/legacy fail-close with 13 of 20 voters, threshold success with 14 of 20, zero ballots, underfilled legacy turnout, invalid snapshot metadata, and governance whitelist bounds. They are **not** full signed transaction admission or replay proof across two production nodes.

Required before enabling the activation param: constitutional acceptance of the eligible electorate definition and default quorum, exact protocol version/activation proposal, reviewer approval, historical replay and independent two-node state-root equality, and closure of existing Backend/P1/Reviewer release gates. The existing signed ballot still includes identifiable signer and plaintext ranking; encrypted or anonymous voting is **not implemented**.

**PR #88 remains draft and NO-GO. Do not merge or set the activation parameter based on these tests alone.**
