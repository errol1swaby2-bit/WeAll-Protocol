# Protocol upgrade record-only boundary

Status: v1.5 safety boundary.

`PROTOCOL_UPGRADE_DECLARE` and `PROTOCOL_UPGRADE_ACTIVATE` currently record upgrade metadata for auditability. They do **not** fetch, verify, stage, apply, migrate, restart, or roll back node software.

The apply path stores explicit `record_only_boundary` metadata on declarations and activations so upgrade records cannot be mistaken for an automatic upgrade delivery system.

## Not implemented yet

Before automatic protocol upgrades can exist, the protocol needs:

1. signed release artifacts;
2. release manifest verification;
3. artifact hash/domain separation;
4. staged compatibility windows;
5. deterministic migration vectors;
6. deterministic rollback semantics;
7. multi-node upgrade rehearsal;
8. operator opt-in/coordination policy;
9. public incident/rollback runbook.

Until those gates exist, any payload fields such as `auto_apply`, `artifact_url`, `migration`, or `rollback` are audit metadata only and must not execute software changes.
