# Milestone 2 account recovery runbook

## Purpose

This runbook covers the canonical human-account recovery paths in the Milestone 2 implementation candidate:

1. Offline recovery-key replacement.
2. Tier 2 continuity recovery when the offline key is unavailable.
3. Reversal of a disputed recovery during the restriction window.

A browser recovery file restores the existing account authority locally. Protocol recovery replaces lost or compromised authority on chain. These are separate operations.

## Safety rules

- Generate active, offline-recovery, and evidence-encryption secrets in the browser or another trusted local environment.
- Never upload raw private keys to a node, reviewer, storage provider, log, or closure artifact.
- Never reuse an active authority key as an offline recovery key.
- Never reuse any current or previously revoked active/recovery key as a replacement key.
- Encrypt continuity and reversal evidence before provider upload.
- Public artifacts may include commitments, ciphertext identifiers, reviewer assignments, decisions, and receipts only.

## 1. Establish recovery at account creation

Pinned v2 genesis state requires the account-registration payload to include:

```json
{
  "pubkey": "<active-ML-DSA-public-key>",
  "sig_profile": "pq-mldsa-v1",
  "recovery_pubkey": "<independent-offline-ML-DSA-public-key>",
  "recovery_sig_profile": "pq-mldsa-v1",
  "evidence_kem_pubkey": "<ML-KEM-768-public-key-base64>",
  "evidence_kem_algorithm": "ml-kem-768"
}
```

Confirm committed state contains an offline recovery record and evidence-encryption public key. The active key cannot later replace the registered recovery authority by itself.

Legacy accounts that predate this activation may use the one-time migration path when no recovery authority has ever been registered. That compatibility path is not a substitute for v2 account-creation binding.

## 2. Rotate the offline recovery key while the account is healthy

Rotation is authorized by the currently registered offline recovery authority, not the ordinary active key. Submit `ACCOUNT_RECOVERY_CONFIG_SET` with:

```json
{
  "recovery_pubkey": "<fresh-offline-recovery-public-key>",
  "recovery_sig_profile": "pq-mldsa-v1",
  "current_recovery_generation": 1,
  "authorization": "offline_key",
  "recovery_key_commitment": "sha256:<optional-public-commitment>"
}
```

Sign the canonical transaction envelope with the currently registered offline recovery secret. Confirm the generation increments and the prior recovery authority appears only in retired history.

## 3. Offline-key recovery

Prepare two fresh independent ML-DSA keypairs:

- Replacement active authority.
- Replacement offline recovery authority.

Submit `ACCOUNT_RECOVERY_REQUEST`, signed by the currently registered offline recovery key:

```json
{
  "request_id": "<unique-request-id>",
  "target": "@alice",
  "method": "offline_key",
  "recovery_generation": 1,
  "new_pubkey": "<fresh-active-public-key>",
  "new_sig_profile": "pq-mldsa-v1",
  "new_recovery_pubkey": "<fresh-offline-recovery-public-key>",
  "new_recovery_sig_profile": "pq-mldsa-v1",
  "new_recovery_key_commitment": "sha256:<optional-public-commitment>"
}
```

After commitment:

- The request is independently authorized.
- The target account is locked against ordinary actions.
- The prior active key cannot cancel, delay, or veto the request.
- The deterministic scheduler finalizes the replacement.

## 4. Continuity recovery

Use continuity recovery only when the offline recovery authority is unavailable.

The request must include:

- A fresh active authority and fresh offline recovery authority.
- At least two independent evidence-class commitments.
- At least one strong continuity anchor commitment.
- Encrypted evidence objects for the declared evidence classes.
- Provider identifiers and exact ciphertext commitments.
- An evidence-policy version.

The protocol deterministically assigns 15 qualified reviewers. The subject binds case-scoped key envelopes for the subject and assigned reviewers. Reviewers must accept before receiving decrypting envelopes. Ten approvals are required.

Reviewer selection excludes the target, declared conflicts, prior-case conflicts, and ineligible reviewers. The full envelope material is removed when the case closes.

## 5. Atomic finalization and restriction

Successful offline or continuity finalization atomically:

- Revokes every prior active authority.
- Revokes all registered devices and sessions.
- Installs one fresh active authority.
- Installs one fresh independent offline recovery authority.
- Increments the recovery generation.
- Seals recovery evidence.
- Starts an 8,640-finalized-block high-risk restriction.
- Emits a public receipt.

During the restriction, high-risk content, governance, transfer, treasury, representative, reviewer, juror, validator, operator, helper, and storage authority actions are rejected. Reading and the explicit low-risk security/social allowlist remain available.

## 6. Recovery reversal

During the restriction window, a displaced owner may open one `method=reversal` request referencing the challenged finalized request.

The reversal must provide:

- Another fresh active authority.
- Another fresh offline recovery authority.
- The continuity evidence package and strong anchor.
- `challenged_request_id` identifying the disputed recovery.

A deterministic fresh 25-reviewer panel is selected. Reviewers from the challenged recovery are excluded. Twenty approvals are required. Opening reversal extends the restriction while the challenge is unresolved.

Success installs the new fresh authority, revokes the disputed recovered authority, seals evidence, and emits restoration and incident history. No previously revoked key is reactivated.

## 7. Failed attempts and rate limits

Failed continuity or reversal outcomes produce canonical failure receipts and update the rolling failure history. The protocol enforces:

- One active recovery attempt.
- The configured request cooldown.
- A maximum of three failed attempts in the 129,600-block rolling window.

These records survive restart, replay, and snapshot import because they are consensus state.

## 8. Evidence retention and deletion

At case closure, evidence becomes sealed and reviewer decrypting envelopes are removed. At the retention due height, providers must submit signed deletion attestations and the key-erasure commitment. The protocol records retries every 180 blocks and a deadline-missed receipt if completion exceeds 4,320 blocks. The final receipt binds the providers, ciphertext commitment, erasure commitment, retry count, and completion height.

The controlled local encrypted-object store is for deterministic testnet/browser rehearsal only. Production storage must be operated by accountable provider identities.

## 9. Validation checklist

Confirm all of the following:

- The prior active key cannot rotate the recovery authority.
- The prior active key cannot cancel independent recovery.
- Replacement active and recovery keys are fresh and distinct.
- Old active keys, devices, and sessions fail after finalization.
- The restriction starts at the committed finalization height.
- Continuity uses 15 reviewers and requires 10 approvals.
- Reversal uses 25 fresh reviewers and requires 20 approvals.
- Closed cases expose only public commitments, assignments, decisions, and receipts.
- Provider deletion and erasure receipts reach final state.
- Restart and multi-node replay produce the same state root.

## Common errors

- `recovery_rotation_requires_offline_key`: rotation was signed by ordinary active authority.
- `recovery_generation_mismatch`: reload committed state and use the current generation.
- `independent_recovery_not_cancellable`: the request is already independently authorized and cannot be vetoed by the prior active key.
- `recovery_key_must_be_independent`: a recovery key equals or was used as account authority.
- `recovery_key_must_be_fresh`: a retired recovery key was reused.
- `recovered_authority_key_must_be_fresh`: a current or previously revoked key was reused.
- `recovery_evidence_classes_insufficient`: continuity/reversal lacks two independent classes.
- `recovery_strong_anchor_required`: no strong continuity anchor was supplied.
- `active_recovery_request_exists`: finish the current request before opening another.
- `recovery_request_cooldown`: wait until the reported height.
- `recovery_attempt_limit_reached`: the rolling failed-attempt limit is active.
- `guardian_recovery_retired`: new guardian recovery admission is disabled on v2 chains.
