
## Pass 33 cryptographic gates

- [x] `pq-mldsa-v1` signer/verifier dependency is reproducibly pinned and tested through pyca/cryptography ML-DSA-65.
- [ ] Fresh closed-testnet observer/registry/tx/block/validator/gossip/relay evidence has been rerun after the ML-DSA transition.
- [ ] Public seed registry and trust roots are re-signed with the active profile.
- [ ] Legacy Ed25519 is disabled in closed/public testnet chain configs except explicit migration fixtures.
- [ ] Account recovery, validator/operator, block, BFT/QC, peer, gossip, relay, observer evidence, and frontend signing paths are profile-aware.
- [ ] External cryptographic review is attached before any long-lived public network or mainnet claim.
