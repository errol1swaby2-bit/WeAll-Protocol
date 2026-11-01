# PR77 — Shared role eligibility: baseline-v1 compatibility adjudication

**Status: BOUNDED V1 COMPATIBILITY REPAIRED; V2 SEMANTIC ACCEPTANCE STILL BLOCKED.**

## Source and exact scope

Compared the existing main-branch `_require_role_activation_eligible` predicate
against the proposed shared, state-rooted
`role_activation_reputation_decision` adapter in:
- `src/weall/runtime/apply/roles.py`
- `src/weall/runtime/reputation_role_gate.py`
- `tests/test_issue72_versioned_role_gate.py`

The main-branch predicate rejects absent account, banned/locked account,
PoH tier below two, explicit manual role revocation, and scalar reputation
below the role-specific threshold, in that order. Role-specific checks
(e.g. validator readiness and operator status) follow separately.
It returns the mutable account record to the surrounding applier only on
success; its rejection is not an invitation to mutate roles.

## Independent old/new behavior matrix

The new differential test defines the original main-branch rejection rules
as an independent oracle, then compares *exact* code, reason and details
with the new shared adapter for:

- five operative roles: juror, validator, node operator, governance executor,
  emissary;
- missing version (the required historical default) and explicitly pinned
  version 1;
- eight cases each: eligible, absent account, banned, locked, insufficient
  PoH tier, manual revocation, insufficient scalar reputation, and multiple
  simultaneous restrictions.

This covers **80 differential v1 cases**. The first run exposed a real
error-contract drift on *all five roles under both legacy version forms*:
`account_not_found` included an extra `role` detail in the new adapter.
Commit `a8dd4e0876942c2b53d011423b67023c855c22b7` restores exact
historical `{"account_id": ...}` details for that rejection without
changing the permission decision, global role policy, the original
decision order, or any normal denied role.

Additional tests confirm:
- explicit v2 canonical enforcement applies only to the mapped juror and
  validator roles and cannot grant any unrelated node-operator,
  emissary or governance-executor permission;
- the other role-specific authorization requirements remain separate;
- payload/account annotations claiming v2 cannot select the consensus
  policy: only `state.params.reputation_role_gate_version` is consulted;
- malformed/unknown policy versions remain fail closed;
- default-v1 and explicitly selected v2 predicate evaluations leave
  consensus state unchanged.

## Pinned test evidence

GitHub Actions `Issue72 Reputation Matrix focused projection` run
`41351850918`: **SUCCESS — 121 focused tests passed** (Ruff formatting
and lint; Python reputation-matrix tests; frontend projection source check).
The pre-fix run `41351762619` failed **10 of 121** tests, all showing the
same missing-account error-details drift; after the production fix the
same suite passed.

This verification is bounded. It checks the helper's observable return
and failure contract, version selection, and matrix projection. It does
**not** prove a complete fresh-clone / two-node replay, every surrounding
transaction applier, BFT-certified policy activation, independent review,
or historical equivalence of all state transitions.

## Remaining V2 semantic adjudication

The V2 transaction analyzer currently extracts a generic
`RolesApplyError:runtime_apply_failure` from the dynamic adapter's
`RolesApplyError(str(decision["code"]), str(decision["reason"]), details)`.
That static extractor does not recover the pure predicate's versioned
error rules, so its changed failure-code inventory must not be
interpreted as evidence that the former legacy rejection reasons
were removed at runtime.

The nine affected role/reviewer TX reviews remain stale, alongside
`DISPUTE_OPEN`, `DISPUTE_VOTE_SUBMIT`, `DISPUTE_RESOLVE`,
`DISPUTE_APPEAL`, `DISPUTE_FINAL_RECEIPT` and `ACCOUNT_BAN`.
They require item-by-item authorized semantic adjudication and validated
V2 provenance before the failing CI gates can truthfully pass.
**No semantic-review digest was edited in this increment.**

PR77 stays Draft. Both public-chain v2 activation and sanctions remain
unauthorized; public-beta blockers remain open. No merge or launch.

## Exact bounded derivative refresh after the runtime repair

The production v1 error-contract repair changed source-bound V1.5
completion proof hashes; Backend CI briefly stopped at
`b528 artifact input digest is stale; rerun generator`. This was a
genuine derivation freshness issue, not an invitation to suppress the gate.

The existing bounded refresh workflow was taught to watch
`src/weall/runtime/apply/roles.py` and
`tests/test_issue72_versioned_role_gate.py`. Run
`41352161279` **PASS: 148 focused tests, Ruff lint/format, six updated
source-bound artifacts, release-hygiene checks**. GitHub Actions bot
commit `c52514124453d17bd03f9d14fb48c3f2788e269c` modified only:

- `generated/b528_b532_completion_proof_v1_5.json`
- `generated/b534_b538_completion_proof_v1_5.json`
- `generated/b567_b571_autonomous_mechanics_proof_v1_5.json`
- `generated/failure_code_registry_v1_5.json`
- `generated/public_beta_blocker_report_v1_5.json`
- `generated/release_evidence_manifest_v1_5.json`

Neither `specs/v2/source/semantic_reviews.json` nor any V2 compiler
derivatives were modified. The role policy v2 gate remains
**not activated**, and the 15 semantically stale review transactions are
still deliberately blocked pending authorization. GitHub PR77 remains
Draft.
