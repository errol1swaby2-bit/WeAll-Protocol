# Production Helper Topology Hardening Plan v1.5

Status: **future mainnet-readiness hardening plan only**. This document does not claim public beta readiness, mainnet readiness, production helper execution readiness, public validator readiness, live economics readiness, automatic upgrade readiness, or public storage-market readiness.

Tracked blocker: `AUD-618-P1-005` — production helper topology enablement gate.

## Current v1.5 boundary

Production helper execution remains disabled in every current launch phase. Helper-related code, rehearsals, diagnostics, readiness reports, source tests, and generated artifacts are evidence surfaces only. They do not grant protocol authority, require helper receipts for block validity, activate helper execution in production topology, or let local scripts/frontends override consensus.

Current boundary that must remain true:

- production helper execution is disabled by the launch-disabled matrix;
- helper readiness reports are diagnostic and do not activate helper execution;
- helper mode requests do not grant protocol authority;
- local scripts and frontend state cannot enable helper production execution;
- missing helpers must not halt block production;
- serial execution/fallback remains the safe baseline;
- helper receipts, when tested, must be context-bound and rejected deterministically if malformed;
- public beta/mainnet/helper-readiness claims remain forbidden until external topology proof exists.

## Future enablement path

A future production helper topology proposal must pass all of the following before any claim of production helper readiness:

1. deterministic helper assignment from canonical validator/helper set, lane ID, block height/view, chain ID, and validator epoch;
2. deterministic lane partitioning for every supported transaction family;
3. canonical ordering of transactions before helper execution;
4. signed helper receipts with domain separation, chain/network binding, block/view binding, helper identity binding, and lane/result commitments;
5. deterministic merge ordering with `helper_execution_root` commitment when helper metadata is present;
6. serial-versus-helper equivalence corpus across all supported transaction families;
7. missing-helper timeout and serial fallback proof;
8. Byzantine helper output rejection, wrong-root rejection, replay rejection, and misbehavior proof;
9. crash/restart replay equivalence across helper-enabled nodes;
10. multi-node helper topology transcript with staggered helper failures, slow helpers, overcommit, duplicate receipts, and network instability;
11. helper operator identity, key rotation, revocation, and accountability policy;
12. governance/release gate that explicitly transitions the launch matrix from disabled to enabled only after evidence is attached;
13. public incident-response runbook and rollback/disable plan;
14. strict external transcript validation before public claims.

## Evidence that closes `AUD-618-P1-005`

`AUD-618-P1-005` can close only when a future release contains real topology evidence, not this plan alone. The closure package must include:

- signed helper topology manifest;
- helper set hash and validator set hash;
- lane partition hash;
- serial-equivalence corpus digest;
- Byzantine rejection matrix digest;
- restart/replay vector digest;
- capacity/overcommit and slow-helper transcript;
- multi-node helper topology transcript;
- operator policy and signatures;
- finalized governance/release gate record;
- launch-matrix transition review;
- strict validation output.

## Reviewer commands

```bash
cd ~/WeAll-Protocol/Weall-Protocol
source .venv/bin/activate

PYTHONPATH=src:scripts python scripts/gen_production_helper_topology_hardening_plan_v1_5.py --check
PYTHONPATH=src:scripts python scripts/gen_public_beta_blocker_report_v1_5.py --check
PYTHONPATH=src python scripts/check_v15_public_readiness_artifacts.py
PYTHONPATH=src python -m pytest -q tests/prod/test_production_helper_topology_hardening_plan.py
```

## Forbidden claims

Do not claim:

- production helper execution readiness;
- public beta readiness;
- mainnet readiness;
- helper receipts are required for public block validity;
- helper mode is active in public topology;
- local scripts, UI state, or diagnostics can enable helpers;
- public validator/BFT readiness;
- live economics readiness.
