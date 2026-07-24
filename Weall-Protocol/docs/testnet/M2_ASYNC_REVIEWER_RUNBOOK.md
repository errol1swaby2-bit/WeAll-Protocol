# Milestone 2 async Tier 1 reviewer runbook

## Preconditions

- Use the exact implementation-freeze commit recorded in the M2 evidence manifest.
- The reviewer controls a Tier 2 human account with active async-review responsibility.
- The applicant and every reviewer use separate browser profiles or devices.
- The public testnet seed registry has completed the ML-DSA rotation ceremony and passes `scripts/check_public_testnet_seed_registry_rotation.py`.

## Applicant journey

1. Create the account and verify the recovery file.
2. Register the active ML-DSA key, independent recovery ML-DSA key, and ML-KEM evidence key.
3. Record the async challenge.
4. Encrypt the evidence locally with AES-256-GCM.
5. Upload only ciphertext.
6. Submit evidence commitments and provider identifiers.
7. Wait for deterministic reviewer assignment.
8. Wrap the case key to the subject and assigned reviewers' registered ML-KEM keys.
9. Bind the envelopes to the case.

The case is not reviewable before both declaration and binding are confirmed.

## Reviewer journey

1. Open the reviewer dashboard in the reviewer's own browser profile.
2. Confirm the assignment is visible only to the assigned reviewer.
3. Accept or decline. A decline must trigger deterministic replacement.
4. After accepting, open the encrypted evidence through the case-scoped grant.
5. Submit `approve`, `reject`, or `needs_followup` with a review commitment.
6. For follow-up, verify the applicant can add a new encrypted evidence round, rebind envelopes, and resume review.
7. Confirm the final receipt and the applicant's Tier 1 account state.

## Failure checks

- An unassigned account cannot retrieve evidence metadata or a key envelope.
- A reviewer cannot accept without its own envelope.
- Plaintext CID/URI fields are rejected.
- Closing the case removes reviewer envelopes.
- Refresh or backend restart does not change reviewer assignment or final result.

## Evidence capture

Capture sanitized transaction IDs, case ID, assignment list, final receipt, applicant Tier 1 state, node state roots, and restart/replay result. Never include raw evidence, decrypted frames, secret keys, or key-envelope plaintext in public artifacts.
