# WeAll PoH Email Oracle

This service is the Cloudflare-free Tier 1 Proof-of-Humanity email-control oracle path.

The oracle owns challenge generation, challenge storage, email delivery, code validation, and signing of `email_control_attestation_v1`. The chain owns final eligibility by verifying the attestation against chain state and the on-chain oracle registry.

## Critical boundary

Stalwart is mail transport only. Cloudflare is not required. Neither Stalwart nor Cloudflare decides PoH tier.

Normal nodes verify signed attestations and do not need SMTP, Stalwart, Cloudflare credentials, or oracle private keys.

## Flow

1. Frontend requests an email challenge.
2. Oracle generates a challenge and sends a verification email through the selected transport.
3. User enters the code shown in the email.
4. Oracle verifies the code and signs `email_control_attestation_v1`.
5. Frontend submits `POH_EMAIL_ATTESTATION_SUBMIT`.
6. Chain verifies the oracle registry, signature, replay indexes, expiry height, and account binding.
7. Chain commits canonical Tier 1 `AccountPoHStatus`.

## Required production invariants

- No raw email is written to chain state.
- No raw email is written to receipts or snapshots.
- No SMTP, DNS, Stalwart, Cloudflare, HTTP, or environment lookup happens during transaction execution.
- Oracle authority is chain state, not process-local env.
- Attestation expiry is height-based during execution.
- Challenge generation and wall-clock expiry are off-chain oracle concerns only.
