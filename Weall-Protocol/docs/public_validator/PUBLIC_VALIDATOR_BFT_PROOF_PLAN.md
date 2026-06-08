# Public validator and BFT proof plan

Status: required proof plan; public multi-validator readiness is not claimed.

The local block-production proof is meaningful but narrow. Public validator/BFT readiness requires a separate adversarial proof package.

## Required proof matrix

1. Clean clone validator bootstrap on at least four independent processes.
2. Matching chain manifest, tx index hash, protocol profile hash, and validator set hash.
3. Multi-validator proposal/vote/QC/finality convergence.
4. Validator churn: add, suspend, remove, and rejoin paths.
5. Equivocation attempts rejected and surfaced in diagnostics.
6. Network partition/rejoin without state divergence.
7. Crash/restart/replay at proposer, voter, and catch-up nodes.
8. Cold node state sync from trusted anchor.
9. Mempool replay and duplicate suppression across restart.
10. Operator incident report generated from failure cases.
11. No observer can produce blocks or sign as validator.
12. Helper execution remains serial-equivalent or disabled.

## Required artifacts

- command transcript;
- commit hash;
- chain manifest hash;
- validator identities;
- final height and state root from each node;
- BFT evidence dump;
- incident report if any failure occurs;
- explicit truth boundary.

Passing this proof would support a future public-validator testnet claim. It would still not imply mainnet readiness or live economics.
