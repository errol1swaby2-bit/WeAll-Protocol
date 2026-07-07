# Remaining crypto blockers

1. Integrate a reproducible, pinned real ML-DSA implementation with positive and negative verification tests.
2. Re-sign seed registry and public trust-root materials with `pq-mldsa-v1`.
3. Migrate account recovery and key rotation flows to profile-aware key records.
4. Migrate validator/operator, block, BFT/QC, peer, gossip, relay, and observer evidence signatures end-to-end.
5. Expose and/or implement frontend/client signing support without implying ML-DSA is the future testnet profile.
6. Add a documented ML-KEM transport/key-establishment path where node transport or local backup flows require it.
7. Obtain external cryptographic review before any long-lived public network or mainnet claim.
