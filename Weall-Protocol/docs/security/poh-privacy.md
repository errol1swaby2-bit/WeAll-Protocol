# PoH Privacy Requirements

WeAll uses chain-verified eligibility, not surveillance identity.

## Hard requirements

- No raw email on-chain.
- No raw email in receipts.
- No raw email in public snapshots.
- No plaintext verification code in chain state.
- No oracle private key in logs.
- No mailbox data in protocol state.

## Commitment model

The email oracle may compute:

```text
email_hash = H(normalized_email || salt || account_id)
domain_hash = H(domain || salt || account_id)
proof_commitment = H(canonical_attestation_payload_without_signature)
```

Only commitments are submitted to chain state.
