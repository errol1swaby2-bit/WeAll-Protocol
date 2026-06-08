# WeAll v1.5 Mechanics Batch 505-509

This batch strengthens the executable mechanics proof layer without enabling public validators, live economics, production helper execution, or automatic protocol upgrades.

## Included mechanics

- **Batch 505:** BFT adversarial proof harness for equivocation detection, partition quorum limits, and restart-stable proposer/set calculations.
- **Batch 506:** Fresh-node state-sync adversarial checks for invalid anchors, corrupted snapshots, and stale anchors.
- **Batch 507:** Challenge-driven PoH revocation now has a deterministic completion mechanic: a fresh successful native PoH finalization closes the pending reverification requirement.
- **Batch 508:** Dispute appeal review can now derive a final appeal decision from panel votes submitted through the existing `DISPUTE_VOTE_SUBMIT` path.
- **Batch 509:** Governance execution vector pack proves a proposal can deterministically emit, execute, receipt, and finalize a safe allowlisted action.

## Truth boundaries

This batch does not claim public validator readiness. The BFT harness is an adversarial proof artifact, not a public validator enablement switch.

This batch does not activate live economics, validator rewards, public treasury spend, or economic slashing.

This batch does not implement automatic software upgrades.

This batch does not enable production helper execution.

## Gate

Run:

```bash
PYTHONPATH=src bash scripts/rehearse_b505_b509.sh
```

Expected result:

```text
[mechanics] OK: Batches 505-509 adversarial mechanics gate passed
```
