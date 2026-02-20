# WeAll Protocol — Testnet Flow (End-to-End)

This document explains the expected “happy path” lifecycle:

1) **User submits tx** → enters mempool
2) **Producer makes a block** → includes mempool txs
3) **Nodes attest** → threshold is met
4) **Finalize** → receipt-only finalize tx applied to prior tip

## Key concepts

- **Mempool** holds USER-context txs that are valid against the current ledger view.
- **Block production** packages txs + block-context receipts.
- **Attestations** confirm block acceptance across nodes.
- **Finalization** applies receipt-only finalize logic once the attestation threshold is met.

## Single-node (threshold=1) expectation

In single-node testnet mode, the node may auto-self-attest during production so finalization can proceed without peers.

## Notes

- Receipt-only txs must never be accepted directly into mempool.
- Block-context txs are applied by the executor in block execution context.
- Finalization is a block-context receipt-only step that should only run when the threshold condition is satisfied.
