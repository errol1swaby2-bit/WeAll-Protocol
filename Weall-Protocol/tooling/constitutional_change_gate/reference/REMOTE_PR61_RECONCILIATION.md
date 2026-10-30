# PR #61 — independent read-only GitHub artifact inspection (2026-10-28)

**Reference commit:** `d10674253b5fb3cc765ec66442f3eaf5558cb81b` (PR #61, still draft). **Comparison base:** `48cbc1cbf36fa3c573d0f5903c2afb80d6d93344` (PR #60). The GitHub compare endpoint reports **16 commits, 33 changed paths**. The exact path inventory is in `PR61_changed_files.json`. The bulk of changed paths are generated v2 derivatives; source code also changes `Weall-Protocol/src/weall/runtime/tx_schema.py` and adds one admission regression test.

The following are **observations made with connected GitHub**, not a live backend run, not verification of the uploaded v2 draft's ratification, and not a substitute for executing the isolated PR checkout.

## Register reconciliation observed

| Evidence dimension | Observed |
| --- | ---: |
| Canonical TX names | 236 |
| v2 `tx_contract_matrix.json` rows | 236 |
| Missing/extra transaction names | 0 |
| Numeric-ID position differences vs canonical `by_id` | 0 |
| v2 implementation-source path vs current registered handler path | 236/236 path matches at handler-module level |
| v2 transaction semantic `independent_review` marked true | 0/236 |
| v2 `requirement_traceability.json` rows | 755 unique IDs |
| Requirements with implementation test runs recorded | 0/755 |
| Requirements with implementation commit pinned per row | 0/755 |
| Requirements with activation receipts recorded per row | 0/755 |
| Requirements with any `contract_ids` | 20/755 |
| Requirements explicitly linked to canonical `TX-NNNN` stable IDs | **0/755** |

The 20 `contract_ids` refer to `SYS_GOV_EXECUTE_DUE` (12 governance execution requirements) or `MECHANISM-COVERAGE` (8 mechanism requirements). Those are **not necessarily invalid**: they identify additional non-transaction mechanisms, but they cannot satisfy the missing one-to-many requirement-to-transaction crosswalk.

**V2 derivative provenance:** implementation commit `1dedcaa5463f1fe230be35d90a610569a82c87dc`, which differs from PR #61's `d10674253b5fb3cc765ec66442f3eaf5558cb81b`. Both derivatives declare normative status `V2_0_FIRST_DRAFT_NOT_AUTHORIZED`; their PDF SHA-256 is `c15d51574c5402fd8b57bc571df971be80c0c26963180f58306f2a57dc5e740a`. They are extensive planning/evidence derivatives, **not current proof of all runtime authority or independent review**.

## What PR #61 changed paths activate

Because `tx_schema.py` is a shared consensus/transaction interface, **all 236 canonical TX contracts / all 20 TX domains conservatively require impact review**, not just juror assignments and escalation receipts. This is an intentionally overinclusive source-level trigger, not a claim all 236 semantics actually changed.

In the full 755-row register, direct implementation-path matching to PR #61's 33 changed paths selects **12 candidate requirements**:

- `TX-FREEZE-001` through `TX-FREEZE-008`, from `src/weall/runtime/tx_schema.py`.
- `API-001`, `API-002`, `UX-001`, `UX-002`, from `web/src/`.

The remaining **743 requirements have no direct implementation-path match to those 33 paths**. This does **not** establish that those requirements are unaffected; code dependencies, SYSTEM queues, constitutional sanctions, governance scopes and migration rules may be semantically implicated without any path match. In particular the 755-row register currently lacks direct canonical TX stable-ID joins.

## Actionable remediation requirements

1. **Establish a new versioned relationship register:** `requirement ID` → `{canonical TX stable IDs, non-TX mechanism IDs, affected state namespaces, runtime authorization functions, tests, direct/indirect relationship, source clause, reviewer}`. Do not overwrite the 755-row source register.
2. **Distinguish proposed vs independently verified links:** source-path-based candidates do not count as authorized semantic mappings. Unknown dependencies remain pending review.
3. **Separate consensus and governance change activation:** an ordinary merge cannot retroactively alter already committed ledger interpretation. A versioned deterministic replay/activation plan must accompany any runtime protocol change.
4. **Provide exact commit-bound test evidence:** especially height-280→281+ persisted SYSTEM queue, juror accept/decline/completed state preservation, malformed and unrelated-target sanctions, replay on follower node, and unchanged source-bound canon.
5. **Use trusted-base CI:** a PR must not be able to reduce obligations or edit away its own gate independently of the constitutional requirements.

## Verification boundary

The package's v0.2 `reconcile_v2.py` parses **all 236 + 755 full rows from the user's checked-out repository** when executed in an isolated clone. It produces a 236-row implementation join and 755-row candidate requirement report. It refuses to authorize merging: even a successful structural join exits 2 with a blocked decision. The current ChatGPT environment has no complete local Git checkout and cannot perform that repo-level run here; this report comes from separately fetched GitHub blobs.
