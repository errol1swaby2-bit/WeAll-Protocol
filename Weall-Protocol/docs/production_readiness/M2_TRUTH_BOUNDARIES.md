# Milestone 2 truth boundaries

Milestone 2 is complete only when the implementation-freeze commit and the evidence-only closure commit both pass the canonical closure runner.

## Supported claims after closure

- A human can create an ML-DSA account in a browser, save independent recovery material, restart the browser, restore custody, and submit a confirmed protected action.
- A registered offline recovery key can atomically replace account authority. The previous active key cannot replace the recovery authority or veto a valid independent recovery.
- A Tier 2 continuity panel can recover an account when the offline recovery authority is unavailable, and a fresh larger panel can reverse a disputed recovery during the restriction window.
- Async Tier 1 and live Tier 2 verification use signed canonical transactions; media transport is never civic authority.
- Raw PoH and recovery evidence is encrypted before provider upload. Canonical state exposes commitments and ciphertext identifiers, not plaintext media.
- Reviewer access is case-scoped, envelope-gated, and revoked at case closure. Retention, deletion retries, provider attestations, and erasure receipts are deterministic protocol state.
- Tier 2 has an exact validity term, five canonical reminders, a real reverification case, Tier 1 fallback, and safe transition of Tier-2-only responsibilities.
- The complete journey is reproducible across restart, replay, two nodes, and an observer catch-up rehearsal.

## Unsupported claims

Milestone 2 does not establish:

- Mainnet readiness.
- Independent cryptographic, privacy, or smart-contract audit.
- Guaranteed deletion from storage systems outside the protocol's provider set.
- Institutional identity or institutional representative authority.
- Permissionless reviewer diversity at global public-network scale.
- That a CI fake camera proves a real person was present; it proves transport and signed workflow behavior only.

## Evidence boundary

Source tests and unit tests prove implementation properties. They are not substitutes for external browser, multi-node, and observer transcripts. A closure claim requires both:

1. An implementation-freeze commit containing code, tests, runbooks, and deterministic generators.
2. A later evidence-only commit containing generated transcripts and a manifest bound to the freeze commit.

No code or specification behavior may change in the evidence-only commit.
