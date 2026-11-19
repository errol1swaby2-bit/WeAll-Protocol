# PR77 — severe-case origin and decision provenance candidate (review-only; 2026-11-02)

**Status: candidate field-binding tests only. Not a source-authenticated S4 admission, not a transaction, not approval to enforce.**

## Observed actual runtime boundary

- `src/weall/runtime/apply/dispute.py:dispute_open` writes `id`, `opened_by`, `opened_at_height`, `opened_at_nonce`, `target_type` and `target_id` but neither verifies nor persists an S4 classifier; caller-provided `severity` and `sanction_class` do not create constitutional classification.
- `src/weall/runtime/severe_sanction_boundary.py` detects explicit severe/S4 labels and ACCOUNT_BAN intent only for a **finality hold**, not for authority.
- `src/weall/runtime/dispute_engine.py:tick_dispute_lifecycle` keeps recognized severe final receipts held.
- `src/weall/runtime/apply/reputation.py:_apply_account_ban` rejects constitutional-clock bans as `forbidden:severe_sanction_authorization_unimplemented`, even from plausible SYSTEM envelopes. Legacy replay remains distinct.
- `src/weall/runtime/system_tx_engine.py:enqueue_system_tx` hashes exact queue fields; it cannot itself establish a legitimate source decision.

The V2.0 First Draft `DSP-210` demands automatic fresh-panel appeal finality or a valid post-reasoned-outcome waiver. `SAN-005` demands independently reviewed proven severe harm, reasoned outcome, remedies and restoration. `SAN-006` describes S4 as clear and convincing evidence of intentional catastrophic harm. The first draft alone does not establish a deterministic classifier or signer/decision authority.

## Proposed data flow (not an activation path)

1. A future trusted chain adapter must retrieve the **finalized** opening `DISPUTE_OPEN` transaction, verify its canonical ID, chain ID, block height, signer, nonce, payload, signature, and the resulting current case record. **This adapter does not exist in this patch.**
2. A separate, policy-versioned, independently authorized admission/decision producer must link the *same* case and exact target to an evidence snapshot, policy digest, reasoned finding, and declared S4 harm class. **No such producer or registered classification TX exists.**
3. The read-only `tooling/severe_case_origin_candidate.py` compares alleged opening, case and classification shapes. When consistent, it computes a domain-separated *review fingerprint*. Any party can forge the inputs and recompute that fingerprint. It is neither a signature nor authentication.
4. Only after approval of real chain proof, admissibility rules, authenticated juror/appeal outcomes, constitutional waiver, final receipt, replay activation and SYSTEM queue parent verification could a separate, explicitly versioned implementation request enforcement. **The current candidate cannot perform that step.**

The candidate record kind `weall.candidate.severe-case-admission.v0` is a **proposed review schema, not a registered protocol transaction or a claim about deployed implementation**. Allegation labels alone are never canonical S4 classification. The source of authority, independent-review quorum, harmful-action taxonomy, role/conflict exclusions, treatment of SYSTEM-opened cases, evidence snapshot rules, verified identity alias normalization, constitutional activation height and historical compatibility are unresolved.

## Adversarial regressions

`tests/test_pr77_severe_case_origin_candidate.py` checks the structurally plausible but forgeable record; untrusted case/payload severity labels; spoofed signature-verification booleans; cross-case, cross-chain, target, signer, nonce and height swaps; malformed or same-ID commitments; S3 vs S4; missing reasons/records; type confusion with booleans; deterministic pure processing; and review fingerprint changes when alleged evidence changes. Tests never pass a value that can set `may_classify_canonical_case` or `may_enqueue_account_ban` to true.

**Authority floor:** `constitutional_authorization=NOT_ESTABLISHED`, `may_classify_canonical_case=false`, `may_enqueue_account_ban=false`. Existing negative severe-appeal tests, 15 pending V2 semantic reviews, authentic old-height replay, fresh-clone two-node rehearsal, and independent maintainer approval remain release blockers. Keep PR77 **Draft/unmerged and NO-GO**.
