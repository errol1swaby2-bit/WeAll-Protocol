# PR77 retained-history replay intake — NOT COMPLETE

Status: **BLOCKED until authentic retained chain data is supplied.** This is an
offline review tool, not an assertion that historical or two-node consensus
equivalence has been established. No production database is opened by CI.

Source requirements:
- Supply a **quiesced, independently preserved OFFLINE copy** of a node SQLite
  ledger. Never pass the live DB or a symlink to it.
- Require a trustworthy source-chain identity, captured source SHA-256, and
  pinned checkout SHA and tx-index SHA-256. Preserve provenance externally.
- The input must contain the native SQLite `blocks` and `ledger_state`
  tables, with all blocks from height 1 through the retained tip.
- No SQLite WAL/SHM sidecars. If an active node uses WAL, create a proper
  SQLite backup after quiescence; do not simply discard WAL files.

On the exact PR77 checkout, from `Weall-Protocol/` with locked dependencies
installed, create a **new empty scratch directory** (not a symlink) and run:

```bash
python scripts/pr77_retained_history_replay.py \
  --offline-source-db /path/to/verified-offline-copy.sqlite \
  --source-sha256 '<externally-captured-source-sha256>' \
  --chain-id '<historical-chain-id>' \
  --scratch-dir /path/to/new-empty-scratch-dir \
  --tx-index generated/tx_index.json \
  --tx-index-sha256 '<pinned-index-sha256>' \
  --expected-commit '<full-checkout-sha>' \
  --report /path/to/replay-report.json
```

The tool opens the source with SQLite `mode=ro&immutable=1`, validates the
archive and rejects gaps, missing commitments, branch/index mismatches and
different chain identity. It creates a **new** scratch executor and compares
every re-applied block/header commitment and calculated state root to the
retained committed block, failing at the first mismatch. On success, it emits
a per-height transcript of block ID, block hash, state root and receipts root
for comparison with separately pinned historical/external runs. The scratch
directory must be empty, and the optional report must be a new file, never
the source SQLite ledger or pinned transaction index. Canonical state
and receipt roots are validated within the block `header`, not as
nonexistent top-level block fields.

A PASS means only single-revision replay against the supplied stored
commitments succeeded. The report deliberately sets the fields for historical
provenance, old-version compatibility, and independent two-node convergence
to false. Record old-executor replay separately on pinned historical software,
compare receipts and state-root timelines and investigate any first divergent
height. Validate independent two-node catch-up afterwards. Do not update V2
semantic review attestations or treat this tool as merge authorization.

The repository tracks no suitable old SQLite ledger in its tracked-file
inventory. The dedicated CI workflow tests offline-intake guards and a short, **synthetic** three-block replay through the actual executor. It is **not** historical replay evidence.

## Separate single-runner two-node rehearsal (not historical proof)

The `.github/workflows/pr77-local-two-node-restart-catchup.yml` workflow
runs the existing `scripts/devnet_restart_catchup_live.sh` on an ephemeral
GitHub Actions runner. It boots two **local** controlled-devnet processes
with separate databases, exercises signed transactions and verified state
sync, restarts each process from persisted state, and checks state-root parity
after each restart. It uploads comparison/sync logs only, not the node
databases or generated operator key files.

A green run demonstrates the single-runner devnet path, **not** historical
compatibility, machine independence, a third-party attestation, decentralized
validator consensus or public testnet readiness. It cannot close either the
retained-history archive prerequisite or external two-machine review gate.
