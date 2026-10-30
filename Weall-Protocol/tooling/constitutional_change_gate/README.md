# WeAll — Constitutional Change-Impact Matrix v0.2

**2026-10-28 · OFFLINE REVIEW CANDIDATE · NO PR · NOT RELEASE-AUTHORIZED**

Target: `errol1swaby2-bit/WeAll-Protocol` PR #61 at `d10674253b5fb3cc765ec66442f3eaf5558cb81b` compared to PR #60 head `48cbc1cbf36fa3c573d0f5903c2afb80d6d93344`.

This is the **next integration stage of v0.1**, not an independent transaction canon. It aligns code changes with the existing one-to-one canonical transaction and handler matrices, reads the **entire** existing v2 236-row transaction matrix and 755-row requirement register, and produces conservative proposed requirement-impact links. The protocol runtime must continue to enforce authority independently of this development-time gate.

## Confirmed structural results from connected GitHub

See [`reference/REMOTE_PR61_RECONCILIATION.md`](reference/REMOTE_PR61_RECONCILIATION.md) and `reference/REMOTE_RECONCILIATION_OBSERVATIONS.json`. The connected GitHub blob reader successfully parsed both v2 matrices (1,063,895 and 1,642,699 bytes). All 236 names, numeric indexes and registered handler module paths align at source level; **this does not prove implementation semantics or completeness of each transaction's state effects**. The v2 derivatives are pinned to an **older implementation commit** `1dedcaa5463f1fe230be35d90a610569a82c87dc` and declare the v2.0 draft **not authorized**. All 236 TX contracts lack an affirmative independent-review bit; all 755 requirement rows lack recorded test runs, per-row implementation commits and activation receipts. Requirements list 20 `contract_ids`, but those refer to two non-TX mechanism identifiers, not to the canonical `TX-NNNN` IDs.

PR #61 changes 33 files; `tx_schema.py` is shared, so the conservative review touches all 236 TX types and 20 domains. Twelve v2 requirement rows have direct source path matches to the changed files (`TX-FREEZE-001`–`008`, `API-001`–`002`, `UX-001`–`002`). The other 743 remain **unlinked by that criterion, not proven unaffected**. The new code produces the complete candidate inventory from the user's actual checkout.

## Contents

- `weall_change_gate.py`: v0.1 core with **additional conservative classification for generated artifacts and compilers**; existing unchanged behavior for all other paths.
- `reconcile_v2.py`: validates full canonical ↔ v2 TX joins, exact numeric IDs vs hashed identifiers, source provenance and schema; processes all 755 requirements as direct source-path candidates, explicit canonical-contract links, or unresolved.
- `policies/requirements.json`: **unapproved candidate** domain-to-requirements dependency policy. No modification of constitution or transaction canon.
- `reference/PR61_changed_files.json`: exact 33-file connected GitHub comparison list.
- `reference/REMOTE_PR61_RECONCILIATION.md`: inspected source facts, limitations and resolution tasks.
- `reference/LOCAL_TEST_RESULTS.txt`: 31 isolated tests passed; no full backend tests or two-node execution.
- `validate_pr61_isolated.sh`: temporary **local clone** validation runner; source repository and `.weall-devnet` are not altered.
- `tests/`: 15 original + 16 new tests for unique joins, provenance, unsafe paths, ambiguous refs, generated paths, expected blocked verdict.

## Run on Windows 11 + WSL Ubuntu

Unzip this package. Locate the **actual Git repository root** containing `Weall-Protocol/`, not the inner backend folder, then run:

```bash
PKG="/mnt/c/Users/errol/Downloads/weall-tx-change-gate-v0.2"
SRC="/absolute/path/to/your/WeAll-Protocol"
"$PKG/validate_pr61_isolated.sh" "$SRC" /tmp/weall-v2-pr61-isolated-review
```

`validate_pr61_isolated.sh`:

1. Validates that `SRC` is a WeAll Git root. Creates a **temporary local clone** (`git clone --shared --no-checkout`) without checking out, resetting, or modifying the source. The ignored `.weall-devnet` ledger is not copied into the clone.
2. Checks out PR #61's **exact pinned commit in the temporary clone**, fetching missing PR commits from GitHub into that clone only if necessary. It never pushes, writes PR comments, merges, or updates the main repository. Requires network only if those Git objects are not present locally.
3. Verifies the local Git diff `PR60...PR61` matches the GitHub-observed 33 paths, runs the stand-alone tests, generates `impact.*`, reconciles **all actual v2 register rows**, and emits `v2_reconciliation.json`, `.md`, `v2_tx_join.csv` and `v2_requirement_impact_candidates.csv` outside the repository.
4. **Intentionally fails closed** with the decision `BLOCKED_PENDING_AUTHORIZED_TRACEABILITY_AND_EXACT_COMMIT_EVIDENCE`. A passing structural join is NOT merge approval.

The program `reconcile_v2.py` may alternatively be executed against an *already detached and immutable* test checkout at the exact SHA, using `--repo ... --out ...`. It refuses to treat another SHA as validated PR #61.

## Link semantics and safety boundary

- **Canonical TX name** and **append-only canonical numeric index** join to the v2 TX stable ID and runtime handler. The 16-character canonical TX hash (`tx_index.json`'s `id`) is *not* the same thing as the numeric ID or the `TX-NNNN` stable ID. These are stored separately.
- **Source path match** = candidate affected requirement, not proof that the requirement is satisfied or that dependencies are complete. A direct contract reference only binds a TX if it explicitly references a known `TX-NNNN` stable ID. `SYS_GOV_EXECUTE_DUE` and `MECHANISM-COVERAGE` remain non-TX mechanisms until independently mapped.
- The *full* requirements register remains intact; no invented or missing requirements are silently synthesized. New links must preserve the source row and cite the exact constitutional/spec clause and reviewer adjudication.
- **No inference of approval** from green CI, compiler completeness, maintainer review, mock evidence manifests, a prior commit, or the v2 first-draft status. Code changing the gate needs trusted-base CI and human constitutional review.
- **Consensus activation is separate.** Any new runtime authorization constraint must be versioned, deterministic, and compatible with historical replay; do not rewrite or wipe the persistent height-280/281 ledger to make tests pass.

## Not yet performed

This ChatGPT runtime has **no complete local Git checkout**, and its container cannot resolve public GitHub hosts directly, so it **has not executed** the full AST mapping against real PR #61 source or the two-node network. The upstream repo facts above were retrieved and parsed with the connected GitHub app; the isolated runner is for the user's existing checkout. No backend integration test, real historical replay, constitutional activation, or independent review has occurred in this stage. This package does not open a PR.

## Focus for the next repository-level inspection

After running the isolated script, scrutinize `v2_tx_join.csv` for stale/delegated implementation paths and `v2_requirement_impact_candidates.csv` for missing semantic relations. For the original audit findings require separately demonstrated: follow-up SYSTEM payload admission at height 281+, juror assignment idempotence after accept/decline, unauthorized account/group sanction rejection, strict and non-strict vote paths, exact height-boundary restart and equal follower roots. Until those tests and requirements are fulfilled, PR #61 remains a draft and any additional remediation remains an offline candidate.
