# Pass 34 live local two-node post-PQ rehearsal evidence

WeAll is a pre-public-testnet protocol implementation under active hardening.

This bundle records a live local controlled-devnet two-node rehearsal after the controlled-testnet signing profile transitioned away from classical-only Ed25519 and toward profile-aware ML-DSA signing.

Scope:
- boots local genesis backend on 127.0.0.1:8001
- boots local joining/observer-edge backend on 127.0.0.1:8002
- submits signed transactions through normal public APIs
- verifies cross-node convergence
- verifies chain identity/state-root parity after bidirectional sync
- preserves local logs for node 1, node 2, and the convergence probe
- checks post-PQ crypto profile/artifact/truth gates

Not in scope:
- external two-machine observer/operator evidence
- public observer launch against a real public seed endpoint
- public beta readiness
- public multi-validator BFT readiness
- public mainnet readiness
- live economics
- production post-quantum security
- completed cryptographic audit

This is live local two-node rehearsal evidence only.
