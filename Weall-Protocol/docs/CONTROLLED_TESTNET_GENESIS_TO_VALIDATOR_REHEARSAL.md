# Controlled Testnet Genesis to Promoted Validator Rehearsal

Batch 615 adds a single controlled rehearsal for the production-readiness path that previously required separate manual checks:

1. boot a local Genesis executor with a stable chain identity;
2. boot a clean observer executor with validator signing disabled;
3. install a chain-backed promoted validator account, node operator, readiness proof, and active validator record;
4. prove observer block production remains forbidden;
5. submit valid account transactions to different nodes in different arrival orders;
6. prove canonical mempool selection converges before commit;
7. reject duplicate replay, wrong-chain gossip, and same-signer nonce conflicts;
8. produce a block on Genesis;
9. apply the block on observer and promoted validator nodes;
10. prove all nodes have the same canonical height, block root, state root, and empty mempool after commit;
11. restart all nodes and prove the same convergence still holds.

The rehearsal is intentionally local and deterministic. It is a production-readiness gate for the lifecycle and mempool mechanics, not a claim that public validator/BFT or mainnet readiness is complete.

## One-command rehearsal

From the backend root:

```bash
cd Weall-Protocol
PYTHONPATH=src python scripts/rehearse_genesis_observer_promoted_validator_mempool_v1_5.py --json
```

To write a report:

```bash
cd Weall-Protocol
PYTHONPATH=src python scripts/rehearse_genesis_observer_promoted_validator_mempool_v1_5.py \
  --json \
  --write-report /tmp/weall-batch615-rehearsal.json
```

Expected high-level report values:

- `ok: true`
- `observer_mode: true`
- `validator_signing_permitted: false`
- `observer_can_produce_block: false`
- `canonical_converged_before_commit: true`
- `duplicate_replay_ignored: true`
- `invalid_wrong_chain_rejected: true`
- `nonce_conflict_rejected: true`
- `mempools_empty_after_commit: true`
- `mempools_empty_after_restart: true`
- `promotion_preflight_passed: true`

## Clean-clone gate

From the repository root:

```bash
scripts/run_clean_clone_go_gate_v1_5.sh
```

For local development smoke runs where dependencies are already installed and the current working tree is intentionally dirty:

```bash
scripts/run_clean_clone_go_gate_v1_5.sh \
  --skip-install \
  --no-full-pytest \
  --skip-frontend \
  --allow-dirty
```

A release-evidence run must not use `--allow-dirty`. The gate fails if generated checks or test execution leave a dirty worktree.

## Scope boundary

This rehearsal proves the current local Genesis -> observer -> promoted-validator lifecycle and mempool convergence path. It does not replace external multi-machine evidence. Public beta, public validator/BFT, helper production execution, live economics, and mainnet claims remain blocked by their respective generated readiness artifacts and release gates.
