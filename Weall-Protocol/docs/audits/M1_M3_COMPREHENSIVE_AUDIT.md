# WeAll Protocol M1–M3 Comprehensive Audit

## Executive summary

The supplied artifact is a reduced source export, not a Git worktree. It can support source inspection, deterministic artifact checks, and targeted tests, but it cannot support a formal implementation freeze or evidence-only commit. Branch, commit, tree, worktree inventory, cleanliness, ancestry, and direct-child evidence binding are unavailable and must not be inferred.

The audit confirmed the reported M3 membership contradiction. The original runtime auto-accepted every public-group request, did not retain a pending request, created groups without an explicit membership mode, and left the canonical top-level moderator list empty. Because `GROUP_MEMBERSHIP_DECIDE` is gated by `GroupModerator`, the required separately signed request and acceptance journey was impossible through canonical admission.

The isolated implementation copy now contains a narrow correction: `membership_mode` is normalized to `open` or `approval_required`; public readability remains independent of participation; the creator receives canonical initial moderator authority; approval-required requests remain pending; decisions require and consume a matching request; accept and reject remain distinct; and the API uses the schema field `note`. The first targeted gate passed 110 tests, the current golden source gate passes 20 membership/M3 tests plus 79 group-schema tests, and generated v2 and v1.5 artifacts are current.

The M3 traceability system was also corrected so source readiness and formal evidence closure are distinct states. Source-only validation passes 24 requirements, 11 mechanisms, 6 deliverables, and 278 repository paths. Formal validation still fails, correctly, when the replacement-freeze evidence manifest is absent.

Upgrade testing is stronger but remains bounded. Migration functions are now copy-on-write, reject malformed version declarations, require exact one-version advancement, and cannot partially mutate caller state after a failed step. Fifty-five upgrade/migration tests pass after the new cases. On-chain upgrade transactions remain record-only and do not fetch software, execute migrations, restart processes, or perform rollback. Production ledger loading still does not invoke the migration registry; that is a documented release blocker rather than an automatically enabled behavior.

Formal M1–M3 closure is not declared.

## Repository identity and evidence boundary

- Uploaded archive SHA-256: `800c2beebdbc73baa351a333bc3821ae6cc054d62bf195dd89c3fa22a1f68c0d`.
- Repository mode: source export.
- Branch: unavailable.
- Implementation commit: unavailable.
- Implementation tree: unavailable.
- Worktrees: unavailable.
- Clean status: unverifiable.
- Prior freeze `16bb81df09fddf8ef1005d82530b2f39ae3869fb`: not present in the export.
- Prior tree `ad8579cd183b28b4e2fc4a0d1a87d3c447b93443`: not present in the export.
- Replacement-freeze M3 evidence: absent.

No historical evidence has been copied or rebound to the corrected source snapshot.

## M1 status

The v2 compiler reports 755 requirements and 42 deterministic derivatives. The generated requirement register remains explicitly specification-defined and implementation-not-verified; this audit does not convert those rows into runtime closure claims. Compiler check mode passes after regeneration. The current compiler summary reports 236 current transactions, 78 mechanisms, 162 routes, 94 state contracts, 512 failure contracts, 236 receipt contracts, 1,883 vectors, and 1,112 runtime-state inventory rows.

Disposition: source-control and generated-contract integrity pass; formal M1 closure requires a real implementation commit/tree and the repository’s controlling M1 closure evidence.

## M2 status

The M2 traceability checker passes for 27 P0/P1/P2 requirements, 5 milestone deliverables, and 36 account/key/PoH requirements. The reduced export contains a historical M2 manifest bound to a different historical freeze, but 16 files declared by that manifest are omitted. The package therefore cannot be independently revalidated as a complete historical evidence tree, nor can it establish current-head closure.

Disposition: source traceability passes; current replacement-freeze M2 evidence and Git ancestry remain unproven.

## M3 status

### Corrected source behavior

- `GROUP_CREATE` accepts and persists `membership_mode`.
- Allowed modes are exactly `open` and `approval_required`.
- Public read visibility is retained under both modes.
- The creator is a canonical member, signer, and top-level moderator.
- Open-mode requests preserve immediate-join compatibility.
- Approval-required requests produce a pending record and do not create membership.
- Duplicate pending requests are deterministic and do not create multiple applications.
- `GROUP_MEMBERSHIP_DECIDE` requires approval mode and an existing pending request.
- Acceptance creates membership and consumes the request.
- Rejection consumes the request without creating membership.
- API join text is emitted as `note`, matching the strict schema.
- Frontend group creation exposes the mode explicitly.

### Source-readiness truth state

All 24 M3 requirements now use `implemented_requires_integrated_evidence` rather than unsupported `closed` labels. The six M3 crosswalk deliverables use the same boundary. Source-only traceability passes; formal traceability fails when the freeze-bound evidence manifest is unavailable.

### Formal M3 blockers

The archive cannot produce fresh keys, authentic signatures, live transaction IDs, reviewer qualification, original and appeal pools, signed ballots, rejected attempts, restart/two-node/observer equality, a public transcript, a private custody checkpoint, or a direct-child evidence commit. Those must be generated in the real repository at the new implementation freeze.

## Critical defects resolved

1. Approval-required membership journey was impossible.
2. Creator lacked canonical moderator authority.
3. Decision apply accepted targets with no pending request.
4. API emitted `message` while the schema required `note`.
5. M3 traceability conflated implementation readiness with formal evidence closure.
6. Public-only artifact generator `--help`/`--json` behavior could mutate output.
7. Migration functions mutated caller objects and accepted malformed version declarations.
8. Migration steps were not required to advance exactly one version.
9. Closure operation lacked a small, separated golden-path command set.

## Remaining defects and blockers

### Group removal authority conflict

`/v1/groups/leave` describes and emits self-removal signed by the leaving member. Canonical `GROUP_MEMBERSHIP_REMOVE` admission requires `GroupModerator`. The Constitution and v2 specification establish protocol-recognized group permissions but do not resolve whether this transaction is moderator removal, voluntary leave, or both. The conflict is documented and intentionally not “fixed” by guessing. A controlling requirement must select one of: a distinct voluntary-leave transaction, a signer-or-moderator gate with exact target binding, or a moderator-only API.

### Migration integration gap

`migrate_state_dict()` is not called by the production `SqliteLedgerStore.read()` or executor startup path. Automatically wiring it into reads would silently change state roots and could bypass upgrade activation. The safe next design is an explicit offline, transactional migration command that:

1. verifies the implementation release manifest and migration plan;
2. takes an immutable backup/checkpoint;
3. migrates a deep copy;
4. verifies deterministic old/new hashes and exact version steps;
5. writes atomically only after all checks pass;
6. emits an operator-signed migration receipt;
7. causes the new binary to fail closed if the persisted version remains unsupported.

### Environment and clean-checkout blockers

The ambient Python environment has `cryptography 46.0.4`; lockfiles require `48.0.1` for ML-DSA. Full pytest collection stops with 81 import errors that share this root cause. A fresh virtual environment could not be completed because the available package mirror did not provide locked `annotated-doc==0.0.4` or `cryptography==48.0.1`. Ruff is also absent. These are environment failures and must not be misreported as source-test failures.

The frontend has no `node_modules`; typecheck and production build therefore remain unexecuted in this snapshot.

## Testing-system assessment

Strengths include strict schemas, generated-contract freshness checks, extensive stateful governance/dispute tests, replay and multi-node scaffolding, evidence-only commit validators, and explicit signed M3 actor contracts.

Weaknesses include duplicated closure runners, inconsistent shell safety (`set -uo pipefail` in major legacy runners), historical-evidence overlays in cumulative source gates, tests that can preserve semantically incorrect behavior, slow subprocess-heavy tests that obscure root causes, missing source-only/formal separation in the original M3 checker, and environment assumptions that are not validated before full collection.

The new entry points separate read-only audit, source tests, upgrade tests, formal journey, evidence build, closure check, and orchestration. They use secure temporary directories, explicit roots, `set -Eeuo pipefail`, help output, check-only modes where meaningful, machine-readable summaries, and fail-closed freeze validation.

## Upgrade assessment

Current record-only upgrade transactions correctly refuse to become software authority. Existing tests cover declaration, future activation height, supported targets, duplicate/idempotent behavior, replay equality, governance parent binding, ignored execution fields, economics-smuggling resistance, constitution upgrade scheduling, and bounded rollback equivalence.

New migration tests add copy-on-write success, no caller mutation after failure, strict version parsing, and exact version advancement. The major missing production capability is an explicit transactional migration executor and old-node/new-node network negotiation across an activation boundary.

## Evidence-integrity assessment

The evidence validators have strong intended boundaries: exact freeze commit/tree, clean implementation tree, evidence outside the source freeze, direct-child evidence-only commit, approved path prefixes, checksums, and no private material. The reduced export cannot exercise those guarantees. Historical M3 evidence must remain historical; the corrected source invalidates the prior implementation freeze for formal M3 closure.

## Test results recorded in this audit

- Original targeted regression set: 102 passed.
- Corrected membership targeted set: 110 passed.
- Current membership/M3 source gate: 20 passed.
- Group transaction schema: 79 passed.
- M3 broader selection: 145 passed; 2 environment failures caused by missing Git metadata.
- Public-only redesign suite: 25 passed in the earlier isolated run.
- v2 compiler tests: 29 passed, 1 skipped in the isolated run.
- Upgrade/migration baseline: 50 passed.
- New migration tests: 13 passed for the migration files; aggregate upgrade gate passes.
- Generated v2 compiler check: pass.
- v1.5 public-readiness artifact check: pass.
- M2 traceability: pass.
- M3 source-only traceability: pass.
- M3 formal traceability: expected fail because replacement evidence is absent.
- Complete backend suite: environment-blocked during collection by locked ML-DSA dependency mismatch.
- Frontend source checks: group flow, public-only, and embedded-attendance checks pass.
- Frontend typecheck/build: not run; dependencies absent.

## Claim boundary

This package is an audited source correction and redesigned closure mechanism. It is not a release, implementation freeze, signed M3 evidence package, evidence commit, or final M1–M3 closure.
