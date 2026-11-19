# PR #77 — Ban-state authority and versioned reinstatement contract (candidate v0)

**Status: PROPOSAL / NO-GO. Not approved constitutional policy, not an implemented consensus transition, and not historical replay proof.**

This is a substantive source-grounded decision candidate for the constitutional and consensus reviewers; it is deliberately not an automatic semantic approval. It follows the verified [SYSTEM and ban-index trace](pr77_system_reputation_producer_and_reinstatement_trace_20261101.md) and the existing source-bound 15-TX V2 review packet. The repository remains Draft/unmerged.

## Source authority versus execution truth

- **Draft 2 Constitution, Article II §§1, 4, 7; Article VI §3; Article VII §§2, 4:** Basic civic rights are not erased by reputation, sanctions require due process, serious sanctions require appeal/correction, and reputational exile must not become permanent. The constitution does **not** prescribe an exact storage key or make a particular status field an authentic authorization record.
- **V2 First Draft, §32 / DSP-210 / SAN-005 / SAN-006:** Severe account sanction target calls for a 25-member initial panel with 20 approvals and a fresh automatic appeal panel (or a narrowly valid waiver after full reasoned outcome delivery); the repo documents this as **target not operative authority**.
- **Current runtime:** `tx_admission._reputation_and_flags_ok` treats `accounts[id].banned` as an operative account admission denial. Canonical reputation `ACCOUNT_BAN` writes that flag and **overwrites** `reputation.bans[id]`. `ACCOUNT_REINSTATE` writes both status surfaces. Inline dispute `ACCOUNT_REINSTATE` writes the account flag only. Thus `reputation.bans` is at most a **mutable latest-status record**; it is not an immutable append-only history and does not independently prove sanction authority.
- **Alternate exclusion:** `_apply_rep_delta_and_autoban` automatically marks the account banned at the -100 floor, including in constitutional-clock mode. The old content-maturity SYSTEM producer is retired and a current live producer has not been proven. Synthetic execution is still a consensus-semantic risk if such a transaction is validly emitted.
- **Reinstatement re-ban cycle:** the new diagnostic follows a full synthetic `DISPUTE_FINAL_RECEIPT` + inline `ACCOUNT_REINSTATE` with a zero `REPUTATION_DELTA_APPLY` at the -100 floor. The scalar score need not fall further: because the account flag was cleared, the legacy helper can **re-ban** at the same floor. This is synthetic producer reachability only, not a valid real block or constitutional adjudication.

## Proposed separation of concerns (requires explicit acceptance)

1. **Effective account exclusion:** a future authenticated, finalized, replayable sanction-status projection, not an unverified score value or arbitrary SYSTEM flag. A loss of optional role eligibility is different from loss of basic account standing. The current `accounts[id].banned` flag remains the operative legacy admission bit until a versioned rule is actually activated.
2. **Evidence and history:** append-only sanction decision and correction events with case/subject binding, constitutional panel and appeal outcomes, reason/evidence commitments (not gratuitous private evidence), chain-selected policy version and final receipt identity. `reputation.bans` alone is not that log; it is overwritten today.
3. **Dispute and provenance:** no ban, reinstatement, or other severe final sanction may be inferred from reputation floor, an asserted `SYSTEM` signer, purported juror totals, or an unauthenticated final receipt. The exact signer, causal receipt, old-version transition, approved ballots and appeal finality must be independently verified.
4. **Repairability:** a genuine reversal/restoration should clear active exclusion consistently while preserving historically auditable events, but should not itself erase unrelated earned/penalized reputation history. A new penalty after restoration must have its own constitutional basis rather than automatically repeating a previously reversed exclusion.

## Candidate activation contract — *NOT implemented*

A potential future explicitly chain-committed `sanction_authority_version` policy must be reviewed, and may require a constitutional proposal. Until then, there is **no new version selector and no runtime activation**. The following table is a candidate to adjudicate, not a claim of operative rules.

| Scenario | Present unmodified legacy execution | Candidate future rule after approved activation |
|---|---|---|
| Selector absent / historical heights | Existing semantics, preserving original roots | No change to old heights, no implicit activation |
| Reputation delta reaches -100 | Scalar score updated and account can be auto-banned | Score may update, but no independent irreversible account-wide ban; any capability consequence separately reviewed |
| Severe `ACCOUNT_BAN` | Legacy SYSTEM receipt possible when clock disabled; clock-enabled path NO-GO | Require authenticated final initial 25/20, independently selected automatic fresh appeal 25/20 or permitted waiver, and deterministic parent/receipt binding |
| Full finalized `ACCOUNT_REINSTATE` | Direct reputation handler updates both; inline dispute remedy may diverge | Proven final restoration updates status projection and materialized flags atomically and writes a separately auditable correction event |
| Subsequent delta after reversal | Can re-ban if still at floor | Do not turn an unchanged score into a new account ban absent new authorized case and appeal |
| Old snapshot has conflicting flags | No automatic reconciliation | Classify as legacy divergence; resolve only through an authenticated, replay-checked transition, never blind overwriting |
| Unknown policy version or malformed state | No new candidate gate | Fail closed; never guess an activation date or treat arbitrary state fields as a governance vote |

**Compatibility rule:** Do **not** insert an unversioned `reputation.bans` update into current inline receipts, stop the legacy -100 auto-ban, or add an automatic repair on state load. Every one of those changes can alter an old finalized state root. A future activated transition must be proven with actual old-version ledger/blocks, exact commit-anchored old software and old-vs-new per-height receipts/roots, not just current synthetic oracle parity.

## New non-authoritative audit implementation

`tooling/ban_state_contract_candidate.py::review_ban_state_candidate` examines the two state surfaces and reports one of:

- `CONSISTENT_ACTIVE`, `CONSISTENT_CLEAR`
- `DIVERGENT_ACCOUNT_CLEAR_INDEX_ACTIVE`, `DIVERGENT_ACCOUNT_ACTIVE_INDEX_CLEAR`
- `INDEX_ABSENT_ACCOUNT_ACTIVE`, `INDEX_ABSENT_ACCOUNT_CLEAR`
- `ACCOUNT_NOT_FOUND`, or explicit malformed-state categories.

It neither changes state nor computes/accepts constitutional authority, **even when all records are plausible or the snapshot claims an approved case**. Outputs always report `constitutional_authorization=NOT_ESTABLISHED`, `may_apply_transition=false`, `may_enqueue_system_tx=false`, and `may_activate_new_policy=false`. The artifact is explicitly **outside the dispatcher, BFT replay, public API and scheduler**. Its test coverage checks both mismatch directions, missing/malformed data, pure/repeatable output and forged-looking approval fields.

The full-TX characterization extends `tests/test_pr77_account_reinstatement_state_consistency.py` to compare bounded rollback and deepcopy across constitutional-clock on/off for a subsequent synthetic reputation-delta re-ban. A passing result confirms the current behavior and **does not approve it**.

## Explicit unresolved decisions and acceptance requirements

1. Constitutional maintainer/reviewer must decide whether any reputation floor may affect **basic access**, or only scoped eligibility, and specify the emergency temporary restriction process and correction rights.
2. Define a canonical append-only sanction-event/appeal record and deterministic effective status derivation, including exact idempotency, no-op, duplicate conflicting receipt, invalid/unknown selector, restart and retained-ledger replay rules.
3. Define authenticated enrollment/selection, conflict clearance, ballot verification, panel quorum, fresh appeal, waiver and reason-delivery proofs; never authorize an action based solely on matching copied state fields.
4. Build and verify valid producer -> queue item -> parent -> final receipt -> block commitment -> follower replay and simultaneous two-node convergence. A receipt cannot authorize itself.
5. Gather authentic old-height database/block/receipt snapshots and original implementation for replay. Compare historical states and roots, then obtain independent semantic signoff for all affected V2 transactions and any newly changed contract.
6. Maintain all existing stale-review and public-beta fail-closed gates. No auto-signoff, status flag, schema digest rewrite or unapproved activation.

**Disposition: NO-GO for active v2 sanction/reinstatement execution, merge or release.** This is a candidate for explicit constitutional adjudication, and the tests deliberately characterize existing defects rather than silently fixing consensus behavior.
