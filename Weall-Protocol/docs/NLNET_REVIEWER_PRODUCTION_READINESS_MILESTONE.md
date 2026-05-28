# NLnet Reviewer Production-Readiness Milestone

This repository should be reviewed as a serious implementation seeking support to complete production-oriented private testnet readiness, not as a finished public mainnet.

## What is proven today

- Transaction canon and generated artifacts are checked.
- Release tree, dependency locks, and secret guard are available.
- Local multi-node/two-frontend rehearsal exists.
- Native verification, posting, group activity, reporting/review, and encrypted direct-message body flows exist.
- Recent batches improved review read-model truth, group reporting, messaging convergence, and live-room diagnostics.

## What this milestone will complete

1. Production-profile block production proof.
2. Locked tokenomics/economics model and UI truth-sync.
3. Full local production-oriented rehearsal completion.
4. Reviewer/CI reproducibility evidence.
5. Production-gated P2P encrypted messaging roadmap and testnet-safe E2EE v1 hardening.

## Reviewer command

```bash
cd Weall-Protocol
bash scripts/reviewer_production_readiness_gate.sh
```

The command is intentionally targeted. Full pytest may still be run separately by reviewers with more time.
