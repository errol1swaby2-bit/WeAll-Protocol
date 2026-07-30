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


## Backend-only isolated replay-status gate

The first integration stage uses an explicit JSON configuration and performs no
browser or evidence-generation work. It:

1. verifies the source repository remains at the exact implementation freeze;
2. extracts the canonical transcript from the immutable evidence commit;
3. creates a consistent private SQLite backup;
4. starts the current backend under a command-line-bound process record;
5. validates the strict controlled-testnet ballot profile;
6. verifies all typed transcript actions with sequential pacing, bounded retries,
   and `Retry-After` support;
7. stops the backend and writes a hashed resumable receipt.

Example configuration:

```json
{
  "source_repo": "/home/errol/WeAll-Protocol",
  "source_branch": "closure/m1-m3-current-main-rollforward",
  "implementation_freeze_commit": "664db5baba36b0df29d82a31ceda5c4bca69cfb0",
  "implementation_tree": "c79fd147a9ac37f42dfaccb24259d84a96edbebd",
  "historical_freeze_commit": "4ca0e13e1e4838b8816e977e33f8dd82fae3b7c5",
  "evidence_commit": "72b9122e1d67b216cc8d678f921951a5a52175ad",
  "evidence_transcript_path": "artifacts/m3-closure/browser/civic/transaction-transcript.json",
  "preserved_database": "/home/errol/.local/share/weall/m3-live-4ca0e13e1e48/node1/weall.db",
  "output_root": "/home/errol/.local/share/weall/m3-closure-v2/<run-id>",
  "backend_port": 18411,
  "minimum_request_interval_s": 0.35,
  "max_request_attempts": 10
}
```

Run with:

```bash
scripts/run_m3_closure_v2.sh verify-replay-status \
  --config /absolute/path/replay-status-config.json
```
