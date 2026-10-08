# External Cross-Machine Replay Transcript Template — 2026-07-05

Status: TEMPLATE ONLY — not completed external evidence.

This folder prepares the evidence package for `AUD-618-P1-003`. It does not
close the blocker and must not be described as public beta readiness.

A valid package must be produced from two external or physical machines running
the same commit and same generated vector artifacts. The final transcript must
prove identical state roots and identical tx-index hashes, then be reviewed as
external evidence.

## Expected package layout

```text
docs/proofs/external-cross-machine-replay/<date>/<external-operator>/
  README.md
  TRANSCRIPT.json
  machine-a/
    LOCAL_MACHINE_REPLAY_EVIDENCE.json
    manifest.json
    artifacts/replay_consistency_audit.json
    artifacts/fresh_node_replay_sync.json
    artifacts/db_backed_fresh_node_replay_sync.json
    artifacts/a04_cross_machine_determinism_probe.json
    artifacts/hashseed-1-lifecycle.json
    artifacts/hashseed-7-lifecycle.json
    artifacts/hashseed-31337-lifecycle.json
    logs/hashseed-1-determinism-pytest.stdout.txt
    logs/hashseed-7-determinism-pytest.stdout.txt
    logs/hashseed-31337-determinism-pytest.stdout.txt
    logs/check_tx_canon_artifacts.stdout.txt
  machine-b/
    LOCAL_MACHINE_REPLAY_EVIDENCE.json
    manifest.json
    artifacts/replay_consistency_audit.json
    artifacts/fresh_node_replay_sync.json
    logs/check_tx_canon_artifacts.stdout.txt
```

## Forbidden claims

This package must not claim public beta readiness, mainnet readiness, public
validator safety, public multi-validator BFT readiness, live economics,
automatic protocol upgrade readiness, production helper execution, legal
approval, or public storage-market readiness.


## A04 breadth requirement

Each machine packet must execute and bind the 236 canonical lifecycle vectors,
including successful admission/apply expectations, failure vectors, receipts,
duplicate/replay expectations, and restart/persistence requirements. It must also
prove stable lifecycle generation across multiple `PYTHONHASHSEED` values,
mapping insertion-order invariance, scheduler/order permutations, helper serial
equivalence, failed-receipt replay, DB-backed replay, and fresh-node state sync.

These repository-side checks strengthen each packet but do **not** replace the
two-external/physical-machine requirement.
