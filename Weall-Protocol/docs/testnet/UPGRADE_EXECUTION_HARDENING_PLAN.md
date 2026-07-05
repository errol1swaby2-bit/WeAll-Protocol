# Upgrade execution hardening plan

Status: **future mainnet-readiness hardening plan**.

This document prepares `AUD-618-P0-003` for future closure. It is not an execution implementation, not a public beta claim, and not a public mainnet claim.

Current WeAll v1.5 behavior remains record-only:

- `PROTOCOL_UPGRADE_DECLARE` records public governance metadata.
- `PROTOCOL_UPGRADE_ACTIVATE` records scheduled block-height activation metadata.
- `CONSTITUTION_UPGRADE_DECLARE` records public constitution version/hash metadata.
- `CONSTITUTION_UPGRADE_ACTIVATE` records scheduled block-height constitution metadata.
- None of these transactions fetch artifacts, apply software, execute migrations, roll back migrations, restart nodes, activate economics, or grant validator authority.

## Why this blocker remains open

`AUD-618-P0-003` requires proof that executable protocol upgrade staging and rollback are safe across a real multi-node environment. The repository currently proves the opposite boundary: upgrades are public records and reviewer/operator signals only.

The blocker can close only after a future patch provides all of the following evidence:

1. **Signed artifacts** — release artifacts must be signed by an allowed release key, bound to `chain_id`, `network_id`, protocol version, artifact digest, tx-canon digest, migration digest, rollback digest, and compatibility window.
2. **Compatibility window** — every node must deterministically know when a release may be staged, when it may be activated, and when old/new versions are allowed to interoperate.
3. **Deterministic migration vectors** — migrations must have replayable fixtures with before/after state roots, tx-index hash, receipt roots, and failure semantics.
4. **Rollback semantics** — rollback must be defined by deterministic rollback vectors or by forward-only compensating migrations; partial rollback must be rejected or formally modeled.
5. **Operator approval policy** — staging/activation must require explicit operator policy and governance/release gates; local scripts and UI state must not grant authority.
6. **Multi-node staged rollout** — leader, follower, observer, fresh node, and restarted node must converge across staged upgrade and rollback scenarios.
7. **Incident response** — failed staging, failed migration, rollback request, incompatible binary, and mismatched artifact hash must have public incident records.
8. **External transcript** — a transcript must bind the exact commit, machines, operators, command output, artifacts, state roots, and signatures.

## Future execution phases

A future executable upgrade mechanism should be split into explicit phases:

| Phase | Future purpose | Current v1.5 status |
| --- | --- | --- |
| Declaration | Record intended target version, artifact manifest digest, compatibility window, and migration/rollback vector digests. | Record-only metadata only. |
| Staging | Download/verify artifacts into an inert staging area. | Disabled; no artifact fetch occurs. |
| Operator review | Operators inspect signed manifest, risks, compatibility, and replay vectors. | Manual/out-of-band only. |
| Governance activation record | Governance schedules activation at a deterministic future block height. | Record-only block-height metadata. |
| Pre-activation rehearsal | Nodes verify migration vector against current state and readiness policy. | Not implemented. |
| Migration execution | State migration executes deterministically at activation boundary. | Disabled. |
| Post-activation verification | All nodes compare state roots, receipt roots, tx-index hash, and version status. | Not implemented. |
| Rollback or compensating migration | Deterministic rollback or forward repair executes under governance/operator policy. | Disabled. |

## Required signed artifact manifest fields

A future executable manifest should include at least:

```json
{
  "schema": "weall.protocol_upgrade.executable_manifest.v1",
  "chain_id": "weall-testnet-v1",
  "network_id": "weall-public-observer-testnet-v1",
  "upgrade_id": "upgrade:example",
  "target_version": "v1.6.0",
  "artifact_sha256": "sha256:<64 hex>",
  "tx_index_sha256": "sha256:<64 hex>",
  "migration_vector_sha256": "sha256:<64 hex>",
  "rollback_vector_sha256": "sha256:<64 hex>",
  "compatibility_window": {
    "stage_after_height": 1000,
    "activate_not_before_height": 1200,
    "old_binary_supported_until_height": 1800
  },
  "operator_policy": {
    "explicit_operator_approval_required": true,
    "local_script_authority": false,
    "frontend_authority": false
  },
  "claim_boundaries": {
    "automatic_protocol_upgrades": false,
    "live_economics": false,
    "public_beta_ready": false
  }
}
```

## Required migration vector evidence

Each migration vector must include:

- pre-migration state root;
- post-migration state root;
- input block height and activation height;
- tx-index hash;
- receipt root;
- deterministic error for incompatible state;
- replay output from at least leader/follower/observer/fresh-node contexts;
- crash/restart recovery proof;
- no hidden wall-clock or local filesystem dependency.

## Required rollback semantics

A future rollback design must choose one of two models:

1. **Deterministic reverse rollback** — every mutated key has a bounded reversible journal, and rollback vectors prove identical restored roots across nodes.
2. **Forward-only repair** — rollback is forbidden; repair occurs through a new signed compensating migration with its own state-root vectors.

Until that choice is implemented and tested, UI/docs must keep using the phrase:

```text
Automatic software apply, migration execution, and rollback execution remain disabled.
```

## Tests that must exist before closure

Future closure requires tests covering:

- signed manifest domain separation and signer allowlist;
- artifact digest mismatch rejection;
- wrong chain/network rejection;
- compatibility window enforcement;
- deterministic migration vector replay;
- crash during staging;
- crash during migration;
- stale binary refusal;
- rollback or compensating migration semantics;
- operator approval policy;
- UI/read-model claim boundaries;
- external multi-node transcript validation.

## Current acceptance criteria

For this pass, the correct result is:

```text
AUD-618-P0-003 is better specified but still open. Protocol and constitution upgrades remain record-only. Automatic apply, migration, rollback, restart, economics activation, and public beta readiness remain unclaimed.
```
