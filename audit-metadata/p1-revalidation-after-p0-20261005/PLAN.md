# Post-P0 P1 revalidation plan

## Objective

Revalidate and, only where necessary, repair the complete known r20 P1 finding set against the repository state produced by the merged P0 closure PR #38.

This is a closure/revalidation effort, not a feature-development sprint. Historical P1 patches and evidence are regression oracles only. They are not proof that the findings remain closed after the later P2/P0/runtime changes.

## Authoritative baseline

- repository: `errol1swaby2-bit/WeAll-Protocol`
- base branch: `main`
- base commit: `61b1a81f624e7f5c81808aa4b580e3c2f8d55a06`
- base tree: `a6b0a6e3506e6ff9f38fbf42454b4770ac7ac9a7`
- base commit meaning: merge of PR #38, the consolidated A01-A20 HIGH/P0 closure

The current working branch for this revalidation is `p1-revalidation-after-p0-20261005`.

## Historical P1 closure reference only

The prior complete P1 remediation was merged in PR #27 and final evidence was attached by PR #28.

Historical implementation freeze:

- commit: `06694e0d14ca318d6a9ffa1cad6253cedae38a10`
- tree: `bcda576f9ae44792d86ca949863233b4e6693745`

Historical evidence reported all 12 findings as `patched_and_proven`, with targeted regressions, canonical-account-key compatibility, restart/replay/convergence checks, a full backend suite, a 12-finding source-invariant scan, and merge-commit CI.

That evidence remains useful for defining the intended invariants and regression tests, but closure must now be reproven on the post-P0 source tree.

## Known P1 set and invariant to preserve

1. `P1-NET-001` — a replayable unauthenticated/non-session-bound hello identity must not acquire another account's durable peer-security namespace.
2. `P1-SEC-002` — account key revocation schema and runtime handler must use the same canonical `key_id` identity.
3. `P1-CONS-003` — validator lifecycle changes must share the same future-epoch guard across all relevant transition paths.
4. `P1-CONS-004` — consensus-visible reputation/system-scheduler payloads must remain deterministic integer/fixed-point data; floats must not enter consensus admission.
5. `P1-CONS-005` — equivocation evidence must not synthesize an automatic slash authority path that bypasses the required governance/authorization boundary.
6. `P1-ECON-001` — self-transfer must not mint, duplicate, or otherwise distort balances/economic state.
7. `P1-CONTENT-001` — content media/target mutations must be authorized against the stored owner/author rather than caller-supplied identifiers alone.
8. `P1-DISPUTE-001` — coarse dispute/ballot resolution must not inherit arbitrary juror-supplied execution actions.
9. `P1-GROUP-001` — scoped group operations must verify the stored group's scope/authority rather than trusting a mismatched caller-provided scope.
10. `P1-TREAS-001` — treasury spend mutation/cancellation must remain bound to the stored treasury scope.
11. `P1-ROLE-001` — node-operator suspension must be durable and consumed by activation/scheduler logic so automatic scheduling cannot silently reactivate a suspended operator.
12. `P1-STOR-001` — user-created storage offers must bind the operator identity to the signer and must not allow a caller to create an offer on behalf of another operator.

## Revalidation rule

For each finding, one of only three final adjudications is allowed:

- `already_closed_and_proven` — current post-P0 source still enforces the invariant and exact-head executable evidence proves it;
- `patched_and_proven` — the invariant regressed or the proof surface was insufficient, a root-cause patch was applied, and exact-head evidence proves closure;
- `open` — closure has not been proven. The PR must remain draft/not merge-ready.

No finding may be marked closed solely because PR #27/#28 once closed it.

## Existing executable regression contract to reuse

The historical P1 evidence manifest defines the minimum reusable regression surface:

```bash
pytest -q \
  tests/test_p1_remaining_complete_remediation.py \
  tests/p0/test_p1_cons003_future_validator_epochs.py \
  tests/test_balance_transfer_self_transfer_regression.py \
  tests/test_p1_group001_scoped_reference_authority.py \
  tests/test_consensus_equivocation_slash_execute.py

pytest -q tests/test_priority0_account_key_normalization.py

pytest -q \
  tests/test_feed_persists_order_after_restart_api.py \
  tests/test_priority1_replay_schedule_consistency.py \
  tests/test_priority2_state_replay_determinism.py \
  tests/test_e2e_two_node_convergence.py
```

These tests are necessary but not sufficient. Each finding must also be re-traced through the current production path and challenged for bypasses introduced by later changes.

## Post-P0 overlap review

The P0 merge substantially changed or revalidated network authentication, transaction admission/replay, consensus/HotStuff behavior, governance, economics, group authority, system scheduling, persistence, API authorization, and generated claim/evidence machinery. Therefore:

- `P1-NET-001`, `P1-CONS-003`, `P1-CONS-004`, and `P1-CONS-005` require full path re-traces, not only unit-test reruns.
- `P1-ECON-001`, `P1-GROUP-001`, and `P1-TREAS-001` must be checked against the strengthened governance/economics scope boundaries.
- `P1-SEC-002`, `P1-CONTENT-001`, `P1-DISPUTE-001`, `P1-ROLE-001`, and `P1-STOR-001` require current-source invariant and admission/apply boundary checks because shared transaction/admission infrastructure changed after the historical P1 freeze.

A later P0 hardening change may strengthen a P1 invariant; that should be recorded as `already_closed_and_proven`, not redundantly patched.

## Required per-finding closure evidence

For each of the 12 findings:

1. identify the current ingress/admission/apply/persistence or scheduler path;
2. state the security/consensus invariant in executable terms;
3. attempt the original exploit class and at least one adjacent bypass variant;
4. confirm restart/replay behavior where durable state is involved;
5. add or strengthen a regression only if the existing regression does not discriminate the failure;
6. record the exact test(s), current source boundary, and final adjudication.

For consensus-visible findings, add two-node/replay/convergence evidence when the failure could create divergent state or ordering.

## Whole-PR closure gates

The final candidate is not merge-ready until all of the following pass on the exact final source tree:

1. all 12 P1 findings have a non-`open` adjudication with current evidence;
2. the historical targeted P1 regression matrix passes;
3. canonical account-key compatibility tests pass;
4. restart/replay/two-node convergence tests pass;
5. a regenerated 12-P1 source-invariant scan passes against current source;
6. dependency audit passes;
7. canon lint and generated-artifact/current-claim checks pass;
8. the complete backend test suite passes;
9. Reviewer Readiness passes;
10. Web CI passes;
11. Secrets Guard passes;
12. evidence is bound to the exact final commit and Git tree;
13. the worktree/release tree is clean and no temporary closure workflow remains in the final tree.

## Evidence-truth requirements

- Do not reuse the September `P1_EVIDENCE_MANIFEST.json` as current proof.
- Historical artifacts must remain clearly labeled by their historical implementation commit/tree.
- Run-specific logs should be treated as CI/run artifacts unless a deterministic same-tree artifact is intentionally generated and freshness-checked.
- Any current P1 closure summary must name the exact implementation commit/tree it certifies.
- A source change after final evidence invalidates that evidence and requires revalidation.

## Suggested remediation order

1. network/security identity boundaries — `P1-NET-001`, `P1-SEC-002`
2. consensus/determinism/authorization — `P1-CONS-003`, `P1-CONS-004`, `P1-CONS-005`
3. economics and scoped authority — `P1-ECON-001`, `P1-GROUP-001`, `P1-TREAS-001`
4. content/dispute/roles/storage authority — `P1-CONTENT-001`, `P1-DISPUTE-001`, `P1-ROLE-001`, `P1-STOR-001`
5. restart/replay/convergence and full regression
6. exact-head evidence/claim reconciliation and permanent CI

## Scope boundary

Closing this effort means the **known r20 P1 set** is revalidated as closed against the post-P0 implementation. It does not itself claim public mainnet, public beta, live economics, public governance, production multi-validator BFT launch authorization, global Proof-of-Human uniqueness, independent cryptographic review, or closure of unrelated P2/P3/new findings.
