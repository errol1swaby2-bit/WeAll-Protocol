# WeAll v1.5 Completion Mechanics Batch 534-538

This batch moves the latest v1.5 rehearsal layer closer to the paths an outside tester will exercise while preserving all locked launch boundaries.

## Scope

- **534** — Full node-process private validator rehearsal using FastAPI/Uvicorn subprocesses, real localhost ports, readyz probes, vote/commit/sync rehearsal endpoints, restart, rejoin, observer rejection, and matching roots.
- **535** — Real DB/block-commit replay sync using durable SQLite tables (`blocks`, `block_hash_index`, `ledger_state`), receipt-root checks, block-hash checks, interrupted resume, and corrupt-block rejection.
- **536** — API-driven lifecycle rehearsal that uses actual public API reads around direct deterministic state transitions: session, feed, group, group feed, messages, dispute, PoH challenge/reverification, storage, economics-locked rejection, and protocol upgrade record-only proof.
- **537** — Remedy/reinstatement mechanics for dispute final receipts, including `ACCOUNT_REINSTATE`, `ROLE_ELIGIBILITY_SET`, and `ROLE_JUROR_REINSTATE` as deterministic appeal-remedy enforcement actions.
- **538** — Storage operator durability rehearsal: pin assignment, failed operator confirmation, deterministic reassignment, replacement confirmation, and retrieval proof.

## Preserved truth boundaries

This batch does **not** enable or claim:

- public validator promotion
- public multi-validator BFT readiness
- live economics
- automatic protocol upgrade application
- protocol migrations/rollback execution
- production helper execution
- mainnet readiness

## Verification

Run:

```bash
PYTHONPATH=src:scripts bash scripts/rehearse_b534_b538.sh
```

The generated proof artifact is:

```text
generated/b534_b538_completion_proof_v1_5.json
```

The artifact is intentionally scoped as local/private full-node-process rehearsal, not public beta or mainnet readiness.
