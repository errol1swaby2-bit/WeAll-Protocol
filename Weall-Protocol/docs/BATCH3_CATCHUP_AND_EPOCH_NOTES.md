# Batch 3 — Missing-block catch-up staging and epoch guards

This batch adds two production-oriented hardening steps:

1. **Bounded missing-block QC tracking**
   - If a node receives a valid QC for a block it does not yet have, it now records the block ID in a bounded pending-fetch queue instead of silently dropping the event.
   - This is not the full network fetch implementation yet. It is the staging surface needed for a follow-up network sync path.

2. **Validator epoch / set-hash guardrails**
   - Incoming BFT proposals and QCs can now be rejected when they carry validator epoch or validator-set hash metadata that does not match the node's local active validator epoch/hash.
   - Leader proposals emitted locally are stamped with the current validator epoch and validator-set hash.

## Files in this batch

- `src/weall/runtime/block_admission.py`
- `src/weall/runtime/executor.py`
- `tests/test_bft_catchup_and_epoch_batch3.py`

## Remaining work after this batch

- Add actual network fetch/replay of missing proposals and parent chains.
- Carry epoch / set-hash inside signed vote, timeout, and QC canonical payloads.
- Enforce proposer-leader authentication for proposals.
- Add multi-node partition/rejoin adversarial tests.
