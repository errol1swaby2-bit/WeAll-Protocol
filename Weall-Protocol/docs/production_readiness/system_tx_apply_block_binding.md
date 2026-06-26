# Batch 312 — Follower-Side SYSTEM Transaction Binding

## Purpose

Batch 312 completes the SYSTEM transaction authority boundary by enforcing deterministic `system_queue` binding during follower-side block replay.

Prior hardening validated scheduler binding during local block candidate construction. Batch 312 extends the same rule to `Executor.apply_block()`, which is the critical public-validator boundary: honest nodes must reject received blocks containing proposer-synthesized SYSTEM transactions.

## Production rule

Every mutating `system=True` transaction included in a block must match deterministic scheduler output before domain apply.

The follower validates:

```text
_system_queue_id
_due_height
tx_type
queue phase
signer
parent ref
canonical payload hash
emitted height
```

If the SYSTEM transaction is not present in the locally recomputed queue, the block is rejected before receipts or state roots can hide the authority violation.

## Live PoH impact

This specifically protects adaptive Live PoH from proposer discretion. A proposer cannot replace the deterministic juror panel with a hand-picked set of jurors by forging `POH_LIVE_JUROR_ASSIGN`; follower replay rejects the payload mismatch.

## Metadata and schema validation

Block SYSTEM transactions carry internal queue-binding fields in their payload:

```text
_system_queue_id
_due_height
_parent_ref
```

These fields are validated by the scheduler-binding layer. For Pydantic payload schema validation, block-level SYSTEM envelopes strip only these internal underscore fields from the validation copy. The original envelope remains unchanged for tx identity, binding, and domain apply.

## Acceptance coverage

`tests/test_system_tx_apply_block_binding.py` verifies:

```text
exact scheduler-emitted SYSTEM tx is accepted
missing _system_queue_id is rejected
unknown _system_queue_id is rejected
proposer-chosen Live PoH jurors are rejected
```
