# WeAll v1.5 Mechanics Batch 499-503

This batch moves the v1.5 mechanics roadmap from static gap evidence into executable proof harnesses and deterministic lifecycle consequences.

## Truth boundaries preserved

- Public validator promotion remains disabled.
- Public multi-validator BFT readiness is not claimed.
- Live economics remains locked.
- Automatic software upgrade application remains disabled.
- Production helper execution remains unclaimed.

## Batch 499 — Public BFT multi-process proof harness

Adds `scripts/rehearse_public_bft_multi_process_v1_5.py`.

The harness spawns four independent Python processes. Each process computes the same validator set hash, quorum threshold, and leader for the same BFT view, while producing validator-specific vote-message hashes. This is not a public validator activation. It is an executable deterministic-process proof that the local BFT primitives agree across process boundaries.

## Batch 500 — Fresh-node state sync proof

Adds `scripts/rehearse_fresh_node_state_sync_v1_5.py`.

The harness builds a trusted-anchor snapshot response, verifies it, materializes a fresh-node state from the response, compares state roots, and proves that a tampered trusted anchor is rejected.

## Batch 501 — Validator slash/accountability consequence expansion

`SLASH_EXECUTE` now records non-economic validator accountability and, when the target is active, queues an epoch-bound `VALIDATOR_SUSPEND` system receipt. No token/stake slashing is enabled.

## Batch 502 — PoH challenge revocation/reverification lifecycle

An upheld `POH_CHALLENGE_RESOLVE` still revokes the account's PoH status and now also records a deterministic `poh.reverification.by_account[account_id]` lifecycle entry with status `required`.

## Batch 503 — Dispute appeal enforcement lifecycle

`DISPUTE_FINAL_RECEIPT` now applies delayed content enforcement in constitutional-clock mode once the appeal window is final, or once an explicit appeal decision is provided. Appealed disputes without an appeal decision remain in `appeal_review` and do not silently enforce.

## Gate

Run:

```bash
PYTHONPATH=src bash scripts/rehearse_b499_b503.sh
```

Expected result:

```text
[mechanics] OK: Batches 499-503 executable mechanics gate passed
```
