# Messaging End-to-End Encryption

Status: Batch 430 testnet-readiness hardening.

Direct messages are now designed as client-side encrypted payloads. The frontend encrypts message plaintext before submitting `DIRECT_MESSAGE_SEND`. Consensus state and backend APIs store only an encrypted envelope:

- `encryption = WEALL_E2EE_V1`
- `ciphertext_b64`
- `iv_b64`
- sender/recipient messaging encryption public keys
- sender/recipient messaging encryption key IDs

Plaintext `body` and plaintext message `cid` fields are rejected by the messaging apply path. The backend remains authoritative for membership, session access, nonce/signature checks, transaction commitment, and message indexing, but it is not the plaintext message reader.

## Current limitations

- This is browser/device E2EE for the current frontend key store. A user must keep the same messaging encryption private key on the device to read old messages.
- The messaging public key is published through account security policy state.
- The private messaging key is local device material and must not be sent to the backend.
- This does not yet include multi-device encrypted key backup, encrypted attachment bundles, key rotation UX, or safety-number verification.

## Audit rule

A future audit must fail if `DIRECT_MESSAGE_SEND` accepts plaintext `body` or plaintext `cid` into consensus state.
