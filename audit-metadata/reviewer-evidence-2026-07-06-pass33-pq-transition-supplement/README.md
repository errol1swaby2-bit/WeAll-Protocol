# Pass 33 PQ transition supplement evidence

This supplement covers the reviewer-visible crypto profile/status additions after the Pass 33 fail-closed post-quantum signature-profile scaffolding patch.

WeAll is a pre-public-testnet protocol implementation under active hardening. This supplement does not claim public mainnet readiness, live economics, public multi-validator BFT readiness, production constitutional governance readiness, completed cryptographic audit, quantum-proof security, production post-quantum security, or public beta readiness.

## Supplement scope

- Exposes `/v1/status.crypto_profile` for normal observer/front-end review.
- Adds rendered/source UI copy for the active crypto profile.
- Updates generated API/reviewer artifacts to explicitly carry the crypto profile gate.
- Keeps the final claim boundary at fail-closed scaffolding because real ML-DSA is not available in this environment.
