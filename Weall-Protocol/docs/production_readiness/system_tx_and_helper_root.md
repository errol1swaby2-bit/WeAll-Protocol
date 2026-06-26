# Batch 310/311 — SYSTEM Tx Scheduler Binding and Helper Root Commitment

## Purpose

This batch closes two production-readiness gaps identified during the protocol audit:

1. Mutating SYSTEM transactions included in a block must be bound to deterministic scheduler output, not proposer discretion.
2. Helper execution metadata included with a block must be committed by the block header/hash so peers cannot relay the same block with different helper metadata.

## Batch 310 — SYSTEM transaction scheduler binding

A block SYSTEM transaction is now validated against the replicated `system_queue` before apply.

For a queued SYSTEM tx to be valid, replay must prove:

- payload contains `_system_queue_id`
- payload contains `_due_height`
- the queue item exists in replicated state
- queue item `tx_type` matches the envelope tx type
- queue item `due_height` matches the block height
- queue item `phase` matches the replay phase
- signer matches the deterministic system signer
- parent reference matches the deterministic emitter output
- payload matches the exact deterministic emitter output

This prevents a malicious proposer from inventing protocol-authority txs such as hand-picked Live PoH juror assignments or premature finalization txs.

## Batch 311 — helper execution root commitment

When a block carries `helper_execution` metadata, the block header now carries:

```text
helper_execution_root = sha256(canonical_json(helper_execution))
```

Follower replay rejects:

- helper metadata without `helper_execution_root`
- mismatched helper metadata/root
- a helper root without helper metadata
- header changes that do not match the block hash

Helpers still do not become consensus authorities. This commitment only guarantees that helper metadata attached to a block is the exact metadata the block hash commits to.

## Tests

Added tests:

- `tests/test_system_tx_scheduler_binding.py`
- `tests/test_helper_execution_root_commitment.py`

Targeted verification run:

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH=src pytest -q \
  tests/test_system_tx_scheduler_binding.py \
  tests/test_helper_execution_root_commitment.py \
  tests/test_block_commitments_required.py \
  tests/test_helper_executor_metadata_plan.py \
  tests/test_helper_release_gate.py \
  tests/test_helper_multinode_divergence_guards.py \
  tests/test_helper_fallback_equivalence.py \
  tests/test_poh_live_adaptive_quorum.py \
  tests/test_poh_scheduler_determinism.py \
  tests/test_apply_poh_tier2_flows_mvp.py
```

Release hygiene gates should remain green:

```bash
python3 -S scripts/check_tx_canon_artifacts.py
bash scripts/secret_guard.sh
bash scripts/verify_release_tree.sh
```
