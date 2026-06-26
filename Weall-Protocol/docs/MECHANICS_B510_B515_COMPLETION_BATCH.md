# WeAll v1.5 Mechanics Completion Batch 510-515

This batch intentionally prioritizes executable mechanics over additional reviewer-only gates. It keeps the existing locked boundaries intact while moving several v1.5 domains from static proof scaffolding into deterministic runtime behavior and one-command completion rehearsal coverage.

## Truth boundaries preserved

- Public validator promotion remains disabled.
- Live economics remains disabled.
- Automatic protocol upgrade apply/migration/rollback remains disabled.
- Production helper execution remains disabled.

## Batch 510 — Controlled validator network completion rehearsal

Adds `scripts/rehearse_controlled_validator_network_completion_v1_5.py`.

The rehearsal exercises:

- 4-validator quorum finality.
- Minority partition finality rejection.
- Validator candidate registration and governance/system approval.
- Epoch-bound validator set activation.
- Slash execution to non-economic validator accountability.
- Explicit validator suspension and epoch-bound active-set removal.
- Restart-stable state-root equality.

This does not enable public validator promotion. It proves controlled validator mechanics and activation boundaries.

## Batch 511 — PoH and dispute enforcement completion

Runtime changes:

- Successful post-challenge reverification now updates the original PoH challenge record to `resolved_reverified` and records the completing case id.
- Dispute final receipts can apply deterministic non-content enforcement actions:
  - `ACCOUNT_RESTRICTION_SET`
  - `GROUP_MEMBERSHIP_RESTRICT`

These enforcement actions are internal dispute-resolution effects, not public arbitrary transaction types.

## Batch 512 — Governance execution audit vectors

Runtime changes:

- `GOV_EXECUTE` now records deterministic execution audit rows under `state["governance_execution_audit"]`.
- Each emitted governance action records:
  - action index
  - tx type
  - canonical payload hash
  - system queue id
  - due height
- The proposal execution row and return payload include a deterministic `execution_hash`.

This makes governance execution externally reviewable without turning governance into a broad admin backdoor.

## Batch 513 — Storage durability reassignment

Runtime changes:

- Failed `IPFS_PIN_CONFIRM` receipts now deterministically mark the failed operator and attempt spare-target reassignment.
- If a spare operator exists, the pin target set is updated to a deterministic replacement and marked `reassignment_pending_confirmation`.
- If no spare target exists, the pin is marked degraded instead of falsely considered durable.

## Batch 514 — Fresh-node state sync completion rehearsal

Adds `scripts/rehearse_fresh_node_sync_completion_v1_5.py`.

The rehearsal proves:

- A source state produces a trusted finalized anchor.
- A fresh node obtains a snapshot from that anchor.
- The response verifies under state-sync rules.
- The fresh node reaches the same state root and height as the source.

## Batch 515 — Integrated completion proof artifact

Adds:

- `scripts/gen_b510_b515_completion_proof_v1_5.py`
- `scripts/rehearse_v15_completion_batch_510_515.py`
- `scripts/rehearse_b510_b515.sh`
- `generated/b510_b515_completion_proof_v1_5.json`
- `tests/test_batch510_515_completion_mechanics.py`

The generated artifact is derived from executable mechanics, not static claims.

## Verification

Run:

```bash
PYTHONPATH=src bash scripts/rehearse_b510_b515.sh
```

Expected:

```text
7 passed
[mechanics] OK: Batches 510-515 completion mechanics gate passed
```
