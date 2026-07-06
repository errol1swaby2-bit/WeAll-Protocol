
## Post-quantum transition boundary

WeAll is a pre-public-testnet protocol implementation under active hardening. The controlled-testnet target signing profile is `pq-mldsa-v1`; Ed25519 is treated as `legacy-ed25519-v1` for dev/local/transitional flows unless explicitly allowed by chain configuration. This improves the crypto-agility posture, but it is not a completed production cryptographic audit and does not imply mainnet readiness, live economics, public multi-validator BFT readiness, or production constitutional governance readiness.

WeAll is public-only. The post-quantum priority is protocol identity and authority signing, not private message encryption.
