# PR77 — signed dispute-opening source boundary, non-authoritative (2026-11-02)

**Status: review-only; no canonical S4 classifier, no authenticated BFT finality proof, no production transition.**

## Source-backed reason for this increment

The V2.0 First Draft requirements DSP-201, DSP-206 to DSP-210, SAN-005 and SAN-006 demand reasoned significant sanction, independent review, non-overlapping appeal panel, original/appeal thresholds, committed evidence of intentional catastrophic harm, and appeal or post-outcome waiver. They **do not define** a fully executable, authorized S4 classification producer or cryptographically authenticated decision certificate. An allegation of harm or a client-provided S4 field is not a constitutional finding.

The existing protocol has concrete primitives that can be reused:
- `weall.runtime.tx_id.compute_tx_id_from_dict` computes the canonical `tx:<sha256>` identity.
- `weall.runtime.block_commitment_validation.validate_complete_block_commitments` checks body transaction IDs, ordered header IDs, receipts root, block identity/hash and duplicate header fields without claiming BFT finality.
- `weall.crypto.sig.verify_tx_sig_against_any_key` cryptographically verifies the ML-DSA transaction message against keys from a supplied ledger state. Unlike a permissive dev-mode transaction gate, the candidate additionally requires `params.require_signatures is True`, an exact signer account key record, and an explicit matching chain/network context.

## Review-only implementation

`tooling/severe_case_signed_opening_review.py` accepts a **caller-supplied** prior state, a stored-block-shaped object, a case, chain ID and claimed opening TX ID. It checks the canonical opening identity, complete block self-commitments, predecessor state tip/height, actual ML-DSA signature against provided prior keys, one successful receipt, and the case transition's signer/target/nonce/height.

Its positive result means only: **the supplied records are internally consistent and the supplied key snapshot verifies the transaction signature**. An adversary could provide their own key snapshot and sign a new internally consistent block. No trusted checkpoint, independently replayed prior state, authenticated consensus QC or finalized chain anchor has been supplied. In particular, this code does not verify PoH standing, juror signatures, S4 violation proofs, decision authority, evidence authenticity, constitutional remedies, automatic appeal or waiver.

The API returns `constitutional_authorization=NOT_ESTABLISHED`, `may_classify_canonical_case=false` and `may_enqueue_account_ban=false` for all inputs, even where every observed check is true. It is neither called nor imported from consensus, executor, admission, scheduler, domain appliers or SYSTEM emission. Existing constitutional-clock `ACCOUNT_BAN` rejection remains unchanged.

## Evidence/tests

`tests/test_pr77_severe_case_signed_opening_review.py` uses a real generated ML-DSA-65 keypair and WeAll's signing helpers, then recomputes block identity, hash and receipt root through production primitives. Tests include positive signature observations with explicit no-authority, mismatched block ID/hash, pre-state height/tip/chain, case target/signer/nonce, wrong key, invalid signature under unsigned-dev override, fake signature-verification flags, failed/duplicate receipts, tampered signed payload, network mismatch and forged-finality flags. Focused workflow installs the existing pinned dev dependencies, runs Ruff and the tests, and asserts no sanction activation.

## Next (NOT implemented)

A future trusted adapter must retrieve pinned, independently replayed **historical pre-state**, verify actual persisted block and consensus finalized ancestry/QC at a named height, bind the accepted opening receipt and then apply an **approved** versioned constitutional S4 admission rule and signed decision certificate. The admission authority, objective evidence taxonomy mapping to SAN-006, identity/conflict rules, reasoned decisions, appeal finality, restoration and activation/replay semantics all require explicit approval.

This incremental verification does not refresh the 15 stale V2 semantic reviews or change network consensus. Keep PR #77 Draft/unmerged and release NO-GO.
