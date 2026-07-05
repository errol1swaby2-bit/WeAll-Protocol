# Protocol upgrade record-only boundary

Status: v1.5 safety boundary.

`PROTOCOL_UPGRADE_DECLARE` and `PROTOCOL_UPGRADE_ACTIVATE` currently record governance upgrade metadata for auditability. They do **not** fetch, verify, stage, apply, migrate, restart, or roll back node software.

The apply path stores explicit `record_only_boundary` metadata on declarations and activations so upgrade records cannot be mistaken for an automatic upgrade delivery system. Activation records now also carry a deterministic future `activation_height`; governance approval schedules public compatibility metadata, not immediate software mutation.

## Activation record semantics

A governance-passed protocol upgrade may create a `governance_activation_record`. That record means only:

- governance recorded intent/activation metadata;
- the record has a known future `activation_height`;
- unsupported targets can be rejected deterministically when `supported_upgrade_targets` is configured in protocol/meta state;
- operators may need to review the record;
- future software delivery is still manual and out of band unless a later audited mechanism exists.

The record explicitly preserves these fields:

```json
{
  "status": "scheduled",
  "activation_height": 12345,
  "software_applied": false,
  "artifact_fetched": false,
  "migration_executed": false,
  "rollback_available": false,
  "operator_action_required": true,
  "automatic_upgrade_supported": false,
  "economics_activation_allowed": false
}
```

`protocol.active` is retained as a compatibility read model, but it must be interpreted as a governance activation record, not as proof that software has been applied. `protocol.scheduled_upgrades` is the clearer reviewer-facing read model for scheduled record-only upgrade metadata.

## Deterministic lifecycle added in this hardening pass

- Declarations must include an explicit `version`, `target_version`, or `rule_target`.
- If `protocol.supported_upgrade_targets`, `meta.supported_upgrade_targets`, or `meta.supported_protocol_versions` is configured, declarations and activations reject unknown targets deterministically.
- Activations must schedule a future `activation_height`, either explicitly or through a deterministic default delay.
- Repeated activation txs for the same upgrade id are idempotent and do not rewrite scheduled state.
- Activation target mismatch is rejected.
- Activation records explicitly preserve `software_applied=false`, `migration_executed=false`, `rollback_available=false`, and `economics_activation_allowed=false`.

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

The full future-hardening checklist is tracked in `docs/testnet/UPGRADE_EXECUTION_HARDENING_PLAN.md` and the generated `generated/protocol_upgrade_execution_hardening_plan_v1_5.json` artifact. That plan keeps `AUD-618-P0-003` open until signed artifacts, compatibility windows, deterministic migration vectors, rollback/forward-repair semantics, operator approval policy, multi-node staged rollout, crash/restart evidence, and strict external transcript validation exist.

Until those gates exist, any payload fields such as `auto_apply`, `artifact_url`, `artifact_cid`, `signed_manifest`, `migration`, `migration_vector_hash`, `execute_migration`, `rollback`, `rollback_vector_hash`, `execute_rollback`, `compatibility_window`, `operator_approval_policy`, `staged_rollout_plan`, or `restart_node` are audit metadata only and must not execute software changes.
