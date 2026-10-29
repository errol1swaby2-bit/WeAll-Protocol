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

## v0.6 authority-sensitive write review inventory — unverified

The offline `tx_effect_candidates.json` now includes exact-key, **non-normative**
review signals for potentially authority-relevant state roots, such as accounts,
PoH, reputation, disputes, proposals/votes, validator sets, groups and the
system queue. An observed write to these roots is NOT proof that authority was
conferred, exercised, revoked, or improperly changed. Many such writes are
ordinary receipts, nonces, bookkeeping, or legitimate state transitions.
Unclassified and dynamic-root/alias writes remain explicitly reported; no
"unaffected" or "safe" conclusion follows from an empty sensitive-candidate list.

The optional effect-linked reconciliation produces a sixth report,
`v2_authority_write_review_candidates.csv`, with each candidate's TX, root,
classification, call depth, source path/function, write signal, v2 requirement
IDs matching that source path, and **existing** requirement test-run and
verification fields. A missing requirement path remains an unresolved gap, not
a finding of irrelevance. This is a source-path intersection, not a semantic
mapping or independent constitutional review.

The taxonomy is a bounded human-review aid; it is not derived from a ratified
mapping of constitutional rights to state storage keys. The existing 755-row
requirement register is unchanged and no test outcome or authorization is
fabricated. Gate verdict remains BLOCKED; no consensus code is altered.

## v0.7 open authority review queue and untrusted submissions

The offline v2 candidate report now emits `v2_authority_review_queue.json`
and `v2_authority_review_queue.csv`. Each source-root write observation has a
deterministic `AWC-...` key based on its TX, root, source path, function, import
depth and write signal. Duplicate observations receive one queue entry but are
counted. Entries distinguish missing **declared implementation-path matches**
from existing but **unverified** requirement-path matches. A missing path is
neither proof of a missing constitutional rule nor proof that the write is
unconstitutional.

Each entry includes the exact inspected checkout SHA and the scanned source
file's SHA-256 when available; the review queue cannot be closed automatically.
Its listed evidence obligations are: exact-source effect analysis, human
constitutional requirement adjudication, independently verified reviewer
identity, reproducible targeted test logs, and consensus/replay checks when
relevant. These are requirements for *future review*, not claims of completion.

For external review preparation, an operator may provide an external JSON
manifest to the existing offline `weall_change_gate.py` build via the
`--v2-effect-links --authority-review-submissions <path>` options. Input schema
`weall.v2.authority-review-submissions.v0.1` requires `source_commit` and
`records`. Each record must contain the current `review_key`,
`source_file_sha256`, a declared `reviewer_id`, a `review_decision` from
`EFFECT_CLAIMED`, `NO_EFFECT_CLAIMED`, `FALSE_POSITIVE_CLAIMED`,
`MORE_EVIDENCE_REQUESTED`, a rationale, an `evidence_ref`, SHA-256 of the
referenced evidence, and `requirement_ids` from the existing source-matched
candidate set. Duplicate/stale/unmapped claims fail closed. External manifests
are never read as instructions, used to update the checkout, or treated as
signatures.

**Critical:** The tool does not verify identity, log contents or
constitutional authority from such metadata; it records the submission as
`RECORDED_UNAUTHENTICATED_NOT_ADJUDICATED`. Every queue item remains OPEN,
`review_complete=false` and `constitutional_authorization=NOT_ESTABLISHED`.
The release gate stays BLOCKED even when someone claims no effect or supplies
a digest. Human review must independently retrieve/verify the evidence and
authorize each normative mapping through WeAll's constitutional process.
