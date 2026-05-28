# Block Production Proof Gate

Status: local block-production evidence implemented; production-profile validator/BFT readiness is not claimed; public multi-validator BFT not claimed.

The proof gate boots a fresh isolated local node, starts the existing block producer loop, waits for a committed block, and verifies that `/v1/consensus/block-production/proof` exposes the committed block hash, state root, and receipts root.

Acceptance command:

```bash
python3 scripts/production_block_production_rehearsal_gate.py
```

This proves the local block production loop can commit root-bearing blocks in a controlled environment. It does **not** prove production validator authority, public multi-validator BFT, adversarial network safety, validator promotion, external observer readiness, or public testnet readiness.

If `WEALL_MODE=prod` is already set, this gate refuses to run rather than silently presenting local non-BFT evidence as a production-profile validator proof. A future production validator/BFT proof must use a separate gate with on-chain validator authority, BFT enabled, node identity keys, and a validator set satisfying the production consensus rules.
