# Healthy Node Access

Status: Batch 429 operational design note.

WeAll is designed so normal users can connect through healthy compatible nodes without being forced to run personal node infrastructure. Running a node remains important for operators, communities, validators, and advanced users, but basic civic participation should not depend on owning always-on hardware.

## What node switching changes

Switching nodes changes the backend API this browser uses for:

- reading public protocol state
- loading feeds, groups, messages, proposals, and verification state
- submitting signed actions
- checking status and readiness

Switching nodes does **not** change:

- the user's local account key
- the user's account identity
- the user's Proof-of-Humanity status
- group memberships
- governance rights
- reputation records
- protocol receipts
- canonical chain history

Those records belong to protocol state, not to the frontend or the access node.

## Compatibility checks

A node may be reachable but still unsafe or confusing for a user to switch to. The frontend healthy-node manager should compare candidate nodes against the current/expected chain identity.

A candidate node should be marked incompatible when it reports a different:

- `chain_id`
- `tx_index_hash`
- `protocol_profile_hash`

A node that is merely lagging or missing readiness details should be shown as syncing/degraded, not incompatible. A node that cannot be reached should be shown as offline.

## User-facing principles

The frontend should make these facts clear:

1. The chain/backend remains authoritative.
2. The frontend does not grant roles, verification, treasury authority, or governance power.
3. A healthy node is an access path, not an owner of the user's civic presence.
4. Switching nodes should be reversible and visible.
5. Stale or incompatible nodes should not silently appear equivalent to healthy compatible nodes.

## Audit targets

Future recursive audits should verify:

- `/seeds.json` can advertise candidate access nodes.
- The node manager probes `/v1/status`, `/v1/readyz`, and consensus/profile status where available.
- Candidate nodes are ranked by health, readiness, latency, and compatibility.
- Chain/profile mismatches are surfaced before switching.
- Account/session identity remains local and unchanged by node switching.
- User copy avoids implying that a node owns or controls the account.

## Batch 430 fail-closed rule

For normal users, the switch button must only be shown for candidate nodes classified as `healthy` and compatible with the expected chain identity. A reachable node with a missing `chain_id`, missing `tx_index_hash`, missing `protocol_profile_hash`, mismatched `tx_index_hash`, or mismatched `protocol_profile_hash` is not a safe equivalent access node. It may be shown for diagnostics, but normal switching must remain blocked.
