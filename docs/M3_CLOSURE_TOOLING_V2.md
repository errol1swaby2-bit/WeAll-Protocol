# M3 Closure Tooling v2

This tooling is a separate control plane for current-freeze M3 closure. It does
not change protocol consensus behavior and must not be merged into an
evidence-only closure commit.

## Design boundaries

- **Typed evidence:** direct transactions, embedded attendance evidence, and
  inline system transitions are parsed as distinct action types.
- **Rate-limit safety:** live status verification is sequential by default,
  observes `Retry-After`, applies bounded exponential backoff, and records each
  request attempt.
- **Deterministic process ownership:** process records bind a PID to the exact
  `/proc/<pid>/cmdline` hash before the harness may signal a process group.
- **Resumable stages:** every passed stage has a hashed receipt bound to its
  inputs and output-file hashes.
- **Explicit paths:** closure inputs and outputs are arguments or manifest
  fields. Historical private assets are never inferred from broad directory
  searches during an execution stage.
- **No evidence mutation:** inline scheduler evidence is verified through its
  persisted trigger transaction. The harness never fabricates a synthetic
  SQLite `tx_index` row.

## Initial commands

```bash
scripts/run_m3_closure_v2.sh validate-transcript   --transcript /absolute/path/m3-transaction-transcript.json   --out /absolute/path/transcript-validation.json

scripts/run_m3_closure_v2.sh verify-status   --api-base http://127.0.0.1:18411   --transcript /absolute/path/m3-transaction-transcript.json   --out /absolute/path/status-verification.json
```

The initial branch establishes and tests the foundation. Follow-up commits add
the canonical closure stage graph: immutable-input preflight, isolated replay
stack, browser overlay, restart replay, two-node equality, observer catch-up,
privacy scan, evidence assembly, and evidence-only commit verification.
