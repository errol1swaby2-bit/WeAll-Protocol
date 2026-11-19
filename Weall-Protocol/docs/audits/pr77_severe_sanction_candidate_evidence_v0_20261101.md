# PR77 severe-sanction candidate inventory — review-only v0

## Purpose and authority limitation

This is a **read-only, deterministic evidence inventory** for the V2 first-draft severe-sanction work. Its implementation lives in `tooling/severe_sanction_candidate_review.py` and is **not imported, called, or activated** by the domain dispatcher, dispute scheduler, SYSTEM queue, reputation handler, or consensus engine.

Normative targets: V2 first-draft §32 and DSP-210 (25 jurors, 20 approvals; one automatic fresh appeal before enforcement or an authenticated explicit waiver after the full reasoned outcome); SAN-005 and SAN-006 (evidence, independent review, constitutional remedy and restoration rules). The static result is **not proof these requirements are fulfilled**.

## What it can observe

The inventory reports purely syntactic clues from a supplied state mapping: case-to-account binding, severity, panel sizes and uniqueness, initial and appeal tallies, disjoint fresh panels, declared commitments, automatic-appeal marker, public reason field, and linked final-receipt-shaped record.

Such fields **can be forged in a synthetic mapping**. The tool does not validate the cryptographic commitments, authenticated ballots, juror eligibility/conflicts, evidence, automatic appeal scheduling, beneficiary identity, appeal waiver authority, receipt provenance, BFT finality, or historical replay. No reported observation is authorization.

Even if every observation is true, output is always `BLOCKED_UNAUTHENTICATED_SEVERE_SANCTION_EVIDENCE`, `constitutional_authorization=NOT_ESTABLISHED`, and `may_enqueue_account_ban=false`.

## Work still required for the canonical producer

1. Define the source-authenticated severe-sanction decision contract and juror eligibility / conflict / outcome proofs, then verify its 25/20 rules.
2. Deterministically trigger one independent fresh 25/20 appeal; otherwise verify a genuinely authenticated explicit waiver only after the full reasoned outcome was received.
3. Bind the final sanction action to the exact case, target identity, reasoned decision, finalization receipt, SYSTEM queue entry, parent and block height without trusting payload claims.
4. Reconcile account-ban receipt idempotency, historical state/replay, activation profile, and full V2 semantic evidence before authorizing any execution.
5. Integrate behind an explicit consensus protocol activation and obtain complete testnet/independent review evidence.

**No go:** This tool MUST NOT be used as a condition to enqueue `ACCOUNT_BAN` or flip the current clock-mode fail-closed guard.
