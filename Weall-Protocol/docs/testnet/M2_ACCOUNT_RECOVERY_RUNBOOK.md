# Milestone 2 Account Recovery Runbook

## Purpose

This runbook exercises the protocol-native offline recovery path added by the Milestone 2 recovery patch. The browser recovery file restores the existing account authority locally; the protocol recovery path replaces compromised or lost active authority with a new authority and a newly rotated offline recovery key.

## Safety requirements

- Generate the offline recovery key on a disconnected or otherwise trusted device.
- Never register the offline recovery secret as an ordinary account key.
- Never reuse the active account key as the offline recovery key.
- Prepare both a new active authority key and a new offline recovery key before opening recovery.
- Preserve the recovery generation shown in committed account state.

## 1. Register an offline recovery key

Submit `ACCOUNT_RECOVERY_CONFIG_SET` with the active account authority:

```json
{
  "tx_type": "ACCOUNT_RECOVERY_CONFIG_SET",
  "signer": "@alice",
  "nonce": 2,
  "payload": {
    "recovery_pubkey": "<ML-DSA-65-public-key>",
    "recovery_sig_profile": "pq-mldsa-v1",
    "recovery_key_commitment": "sha256:<optional-commitment>"
  },
  "sig_profile": "pq-mldsa-v1"
}
```

Confirm committed state contains:

```text
accounts/@alice/recovery/mode = offline_key
accounts/@alice/recovery/offline_key/generation = <generation>
```

## 2. Prepare replacement keys

Generate two independent ML-DSA-65 keypairs:

- Replacement active authority.
- Replacement offline recovery authority.

Do not submit either secret key to the node.

## 3. Open recovery

Sign the complete canonical transaction envelope with the currently registered offline recovery key:

```json
{
  "tx_type": "ACCOUNT_RECOVERY_REQUEST",
  "signer": "@alice",
  "nonce": "<current-account-nonce-plus-one>",
  "payload": {
    "request_id": "<unique-request-id>",
    "target": "@alice",
    "method": "offline_key",
    "recovery_generation": "<current-generation>",
    "new_pubkey": "<replacement-active-public-key>",
    "new_sig_profile": "pq-mldsa-v1",
    "new_recovery_pubkey": "<replacement-recovery-public-key>",
    "new_recovery_sig_profile": "pq-mldsa-v1",
    "new_recovery_key_commitment": "sha256:<optional-new-commitment>"
  },
  "sig_profile": "pq-mldsa-v1"
}
```

The signer account is deliberately the target account, but signature verification uses the purpose-limited offline recovery public key.

After commitment, confirm:

```text
request status = approved
account locked = true
```

## 4. Deterministic finalization

The core scheduler enqueues `ACCOUNT_RECOVERY_FINALIZE` at the next eligible height. After finalization, confirm:

- The replacement active public key is the sole active authority.
- Every previous authority key is revoked.
- Every registered device is revoked.
- Every active session key is revoked.
- The offline recovery key has rotated.
- `authority_generation` has incremented.
- `restriction_until_height` is present.
- The account is unlocked.

The scheduler then enqueues `ACCOUNT_RECOVERY_RECEIPT` on the following eligible height.

## 5. Restriction validation

During the 8,640-block restriction window:

- A content post or governance action must be rejected with `account_recovery_restriction_active`.
- Account-security maintenance and the explicit low-risk allowlist may proceed.
- The old active key, old devices, and old session keys must not authenticate.

At the first candidate height after `restriction_until_height`, ordinary transaction admission resumes.

## 6. Cancel before finalization

While the account is locked, the owner can submit `ACCOUNT_RECOVERY_CANCEL` using a still-valid active account key. The cancellation path is the only user transaction admitted solely to escape the recovery lock. Once offline recovery finalizes and prior authority is revoked, cancellation is no longer available through the displaced key.

## Failure handling

- `recovery_generation_mismatch`: Reload committed account state and use the current generation.
- `offline_recovery_not_configured`: Register an offline recovery key before loss of active authority.
- `active_recovery_request_exists`: Cancel or finish the existing request.
- `recovery_request_cooldown`: Wait until the reported next height.
- `account_recovery_restriction_active`: The requested action is outside the low-risk restriction allowlist.
- `guardian_recovery_retired`: The chain disables new guardian recovery admission; use the v2 offline or future continuity path.
