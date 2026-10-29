# PR #62 — Constitutional change-impact gate v0.2 (draft)

**Status: REVIEW CANDIDATE — NOT RELEASE/AUTHORITY APPROVED**

This directory contains the exact source from the offline v0.2 package prepared on 2026-10-28 (see `SHA256SUMS.txt`). It is stacked on PR #61 at commit `d10674253b5fb3cc765ec66442f3eaf5558cb81b`. No consensus runtime code or ledger data is modified here.

## Scope

- One-to-one canonical 236-TX identity/index ↔ static schema/handler mapping.
- Read-only reconciliation with existing v2 236-TX contract matrix and 755-requirement register.
- Conservative domain and dependency impact selection, with fail-closed handling for unmapped files and incomplete evidence.
- 31 standalone synthetic tests, a historical PR #61 changed-file snapshot, and read-only local isolated-checkout instructions.
- Historical artifacts and observations remain pinned to PR #61; they are **not** current independent verification of PR #62.

## Repository verification

From the root of a checked-out PR #62 branch:

```bash
cd Weall-Protocol/tooling/constitutional_change_gate
sha256sum -c SHA256SUMS.txt
python3 -m unittest discover -s tests -v
python3 -m py_compile weall_change_gate.py reconcile_v2.py
```

The v0.2 runner `validate_pr61_isolated.sh` is deliberately a **PR #61 archival checker**, not the active PR #62 acceptance gate. It checks the parent PR head and does not certify this PR. A future cross-PR gate must bind fresh evidence to each new commit and baseline, and run only against authorized normative requirements.

## Findings / blockers

- The v2 derivatives are from an older implementation commit and label the source draft as **not authorized**.
- The requirements register has 755 rows, but only 20 list contract references, none mapping to one of the 236 canonical TX stable IDs; most requirements therefore remain unlinked by explicit transaction ID.
- No independent review for the 236 TX contract rows, and no actual test run receipts for the 755 requirement rows, were recorded in the source registers as inspected.
- Indirect cross-domain effects remain review candidates; source-path matching is *not proof of semantic dependency closure*.
- Runtime authorization (including cross-domain dispute enforcement), consensus replay, and preserved two-node restart are separate release blockers; this PR does not fix them.

Do **not** merge based solely on synthetic tests, a readable matrix, or a green candidate workflow. The workflow deliberately has no signing/approval authority. No existing protected branch or workflow requirements are weakened.

## Prior commits

- Parent PR #61: `d10674253b5fb3cc765ec66442f3eaf5558cb81b`.
- Compared parent PR #60: `48cbc1cbf36fa3c573d0f5903c2afb80d6d93344`.
- V2 generated derivatives declared implementation commit `1dedcaa5463f1fe230be35d90a610569a82c87dc`.

See [README.md](README.md) for the exact offline package behavior and limitations.

## Current incremental implementation: candidate graph

The reconciliation now produces explicit and handler-path-based **candidate-only**
requirement↔TX edges, a reverse per-TX graph, and a five-file report set including
`v2_tx_requirement_candidates.csv` with every canonical TX represented. Links
are clearly marked unverified. Missing links do not mean unaffected.
This does not establish authoritative many-to-many constitutional mappings,
semantic effects, proof of passing tests, independent review, or safe activation.
Historical PR #61 snapshots remain pinned and unchanged.

## Incremental source tracing — v0.3 candidate (not authorization)

The new read-only `tx_effect_candidates.json` (written **outside** the checkout
with the existing build command) inventories each registered TX handler anchor,
bounded same-file call paths (maximum depth 2 / 32 functions), directly
observed `state["root"]` / `state.get("root")` / `state.setdefault("root")`
candidates, imported-call references, potentially mutable aliases, and
authority-name signals. It separately inventories leader/replay scheduler
function call sites, without asserting TX↔scheduler causality. Dynamic
dispatch, imported callee effects, mutations through aliases and deeper
functions are **not proven**, nor are deterministic replay and authorization.
A passing exact-checkout 236-TX smoke test means only that the static
inventory completes, not that every runtime effect is traced.
The original normative and ledger release blockers remain intact.

## v0.4 one-hop imported helper and alias root candidates

The new static source inventory recognizes direct `state` handoffs to
top-level imported Python functions within `weall.runtime` and records
direct state-root and mutable-alias candidates in those callees, without
executing code. It does **not** claim resolution of transitive imports,
dynamic method dispatch, conditional paths, shadowed names, or callback
effects. The optional `--v2-effect-links` build flag emits v2 reconciliation
with source-matched imported candidates, identified by the distinct
`TRACED_IMPORT_SOURCE_PATH_UNREVIEWED` reason. The source-level
relationship is not proof of specification compliance, authorizations or
TX execution. Review remains mandatory and the gate stays BLOCKED.

## v0.5 scanned-source commit pin and second imported edge (candidate only)

The static candidate report now records SHA-256 digests for every source
file actually parsed and an optional strict Git HEAD pin. A strict pin checks
that **every scanned file** is tracked and unchanged at HEAD; it does not
certify files outside the scanned set, test results, effects at runtime, or
a constitutional decision. The v2 effect-link path requires the strict pin
and rejects a mismatched checkout commit. Exploratory builds without a
strict pin identify themselves as `UNVERIFIED_WORKTREE`.

A second imported-helper edge (depth 2; maximum 32 transitive candidate
edges per transaction) is now scanned for direct state-parameter handoffs.
Candidates contain parent source/target, target source, state-root access
signals, and an unresolved status for missing, ambiguous, or cyclic links.
The `TRANSITIVE_IMPORT_SOURCE_PATH_UNREVIEWED` link reason remains separate
from first-hop source evidence. There is **no** assertion of transitive
dependency closure, sound alias analysis, actual execution, state-root
agreement, independently reviewed semantics, or release eligibility.
