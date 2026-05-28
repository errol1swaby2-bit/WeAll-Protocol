# Block Production Proof Gate

Status: local production-profile proof implemented; public multi-validator BFT not claimed.

The proof gate boots a fresh isolated node, starts the existing block producer loop,
waits for a committed block, and verifies that `/v1/consensus/block-production/proof`
exposes the committed block hash, state root, and receipts root.

Acceptance command:

```bash
python3 scripts/production_block_production_rehearsal_gate.py
```

This proves the local block production loop can commit root-bearing blocks in a
controlled environment. It does not prove public multi-validator BFT, adversarial
network safety, validator promotion, or public testnet readiness.
