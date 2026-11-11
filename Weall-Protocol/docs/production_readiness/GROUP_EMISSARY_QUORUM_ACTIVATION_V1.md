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

## Governance electorate selection now aligned for newly activated elections

**Version 1 at creation** invokes the *same production* `_active_group_member_ids` predicate as group governance, with its default PoH Tier 2 threshold and active-account/membership checks. It freezes the resulting canonically normalized account IDs, required votes, and `electorate_source=group_governance_active_group_members_tier2`. An empty eligible electorate rejects election creation instead of producing an election with an impossible or zero quorum. Finalization requires the frozen snapshot to be sorted, unique, nonempty and correctly source-labeled before granting signer authority. This is source-code predicate reuse, not a separately approximated rule.

**Existing and pre-activation elections** continue to use their historical unfiltered member snapshot. The voter eligibility snapshot is immutable after election creation; account or membership changes made afterward do not silently recompute its denominator. Additional transaction admission/reputation/PoH gates may still reject transactions even when the signer belongs to the frozen snapshot.

**Still requiring review:** constitutionally confirm that default Tier 2 group-governance eligibility is appropriate for emissary elections and assess whether governance-specific override rules, account alias canonicalization and active-account changes should have additional election-specific rules. No quorum activation is authorized by this PR.

## Tests, scope and outstanding release work

Synthetic canonical-apply regressions compare default regular-governance thresholds (1, 2, 3, 5, 20 eligible participants), verify strict/legacy fail-close with 13 of 20 voters, threshold success with 14 of 20, zero ballots, underfilled legacy turnout, invalid snapshot metadata, governance whitelist bounds, exact Tier 2/banned/locked/suspended/inactive/missing-account filtering, snapshot freeze, no eligible voters and tampered electorate source. They are **not** full signed transaction admission or replay proof across two production nodes.

Required before enabling the activation param: constitutional acceptance of the eligible electorate definition and default quorum, exact protocol version/activation proposal, reviewer approval, historical replay and independent two-node state-root equality, and closure of existing Backend/P1/Reviewer release gates. The existing signed ballot still includes identifiable signer and plaintext ranking; encrypted or anonymous voting is **not implemented**.

**PR #88 remains draft and NO-GO. Do not merge or set the activation parameter based on these tests alone.**

## Signed block-context admission and process-isolated replay (test evidence pending)

`tests/test_group_emissary_signed_quorum_replay.py` creates **real deterministic test-only ML-DSA signed** election-create, ballot and finalize envelopes and checks `admit_tx(..., context="block")`. It executes accepted envelopes through the canonical bounded-rollback transaction apply wrapper, compares turnout outcomes at 3/5 and 4/5, rejects a signature-invalid altered ranking, and compares deterministic state roots from two fresh interpreter processes with different hash seeds. Accounts and group membership are seeded synthetic fixtures.

**Scope is explicitly narrower than genuine independent-node replay:** no real block construction/commit, validator QC, persisted DB recovery, network transport or constitutional activation is exercised. The underlying signed ballot still exposes the signer and plaintext ranking. This gate does not replace Backend CI, P1, Reviewer Readiness or any cryptographic ballot review.

## Committed-block producer/follower and durable restart rehearsal (pending CI)

`tests/test_group_emissary_committed_block_rehearsal.py` seeds identical synthetic pre-first-block accounts and group membership in two separately persisted `WeAllExecutor` stores. The producer submits test-key ML-DSA signed election-create, ballot and finalize transactions through public HTTP-context admission, builds real block candidates, and commits each with `commit_block_candidate`. The follower verifies each committed block through `apply_block`; the test requires identical state roots and successful transaction receipts, then reconstructs the follower from SQLite and checks all persisted block receipts and election/treasury signer state.

Cases: 3/5 after test-only activation (no decision, authority unchanged); 4/5 (finalized); and one historical ballot with activation unset (legacy behavior retained). The activation parameter is injected **only into synthetic test genesis**.

**Limits:** fixture members did not perform actual PoH/registration; these are local independently persisted executor instances, not network-separated machines. A locally committed block is not a multi-validator QC or HotStuff BFT finality certificate. Neither this test nor passing CI authorizes private ballot transport, a production activation, or merging the draft.

## Four-validator HotStuff QC-certified election-create boundary (focused CI pending)

`tests/test_p0_03_production_composition.py::test_four_validator_qc_finalizes_signed_emissary_election_creation` reuses the production BFT lifecycle composition fixture, seeded with test-only activated group membership and account keys **before** the canonical bootstrap boundary block. A real ML-DSA-signed election creation transaction enters the leader via HTTP-context admission and is included in the first four-validator BFT proposal. Independent validator votes form QCs over that proposal and its two successors, giving the first proposal the production three-chain finality required for commitment. All four persisted executors must agree on the finalized height, exact election snapshot, 4-of-5 quorum metadata and state root. One restarted follower must recover its committed block receipt from disk.

**Scope:** QC-certified **election creation**, not ballots or election finalization. Validator authority, membership, account registration and quorum activation exist only in the synthetic height-zero fixture. This does not imply constitutional activation, public secret-ballot availability, or independently running networked nodes.
