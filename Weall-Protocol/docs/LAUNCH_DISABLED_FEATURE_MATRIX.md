# Launch-disabled feature matrix

Status: v1.5 public-readiness guardrail.

The canonical machine-readable matrix is:

```text
generated/launch_disabled_matrix_v1_5.json
```

The runtime helper is:

```text
src/weall/runtime/launch_matrix.py
```

## Current truth boundary

The following high-risk features remain disabled for current rehearsal, external-observer, controlled-validator and public-beta-candidate phases unless a later batch implements and proves a narrower activation path:

- live economics;
- balance transfers;
- reward issuance as a live economy;
- treasury spending;
- public validator promotion;
- public multi-validator BFT claim;
- automatic protocol upgrade application;
- protocol migration execution;
- protocol rollback execution;
- emergency safety controls;
- production helper execution.

This matrix does not by itself enforce every consensus rule. Runtime apply/admission code remains authoritative. The matrix exists to prevent documentation, API capability responses, frontend labels, and reviewer claims from drifting ahead of implemented safety.
