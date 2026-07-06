
## Post-quantum transition boundary

WeAll is a pre-public-testnet protocol implementation under active hardening. The controlled-testnet signing profile has transitioned to profile-aware `pq-mldsa-v1` ML-DSA signing for protocol authority surfaces covered by this pass; Ed25519 is treated as `legacy-ed25519-v1` for dev/local/transitional flows unless explicitly allowed by chain configuration. This improves quantum-resistance posture, but it is not a completed production cryptographic audit and does not imply mainnet readiness, live economics, public multi-validator BFT readiness, production helper execution readiness, or production constitutional governance readiness.

WeAll is public-only. The post-quantum priority is protocol identity and authority signing, not private message encryption.
