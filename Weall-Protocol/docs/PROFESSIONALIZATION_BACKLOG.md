# Professionalization Backlog

This backlog records presentation and maintainability issues that remain after the reviewer-surface hygiene pass. These items are intentionally not fixed in one broad patch because they touch many tests, generated manifests, or consensus-sensitive modules.

## P0 — reviewer-facing cleanup before broad external review

1. **Function-level batch names**
   - Current signal: active pytest filenames and reviewer-facing test references have been professionalized, but many internal test function names still include batch-era identifiers.
   - Measured debt after the filename pass: 1,514 batch-era test function names across 434 pytest files.
   - Risk of fixing all at once: medium to high. Function renames affect failure-history searchability, external notes, and reviewer transcripts.
   - Preferred approach: rename function names by domain cluster after file-level review lands; keep assertion bodies untouched and run targeted tests for each cluster.

2. **Command-surface consolidation**
   - Current signal: root, backend, and frontend script directories are mostly coherent, but duplicated basenames remain.
   - Current canonical intent:
     - root `scripts/` = user/operator entrypoints;
     - `Weall-Protocol/scripts/` = backend/internal node/runtime scripts;
     - `web/scripts/` = frontend-only source/contract checks.
   - Known duplicate basenames:
     - `run_clean_clone_go_gate_v1_5.sh` — root is canonical; backend copy is wrapper.
     - `run_frontend_contract_check_with_backend.sh` — root is canonical; backend copy is wrapper.
     - `quickstart_tester.sh` — root and backend currently differ; do not collapse without a dedicated operator-flow test.

3. **Release docs wording audit**
   - Remove remaining checkpoint wording that reads like a batch transcript instead of a release state summary.
   - Keep exact test counts only when tied to current evidence and a rerun date.

## P1 — generated evidence governance

1. **Domain-name historical generated artifacts**
   - Current signal: generated files such as `b499_b503_*` and docs such as `MECHANICS_B*_B*_*.md` still look batch-accumulated.
   - Preferred approach: keep historical artifacts under an indexed historical section until domain-named replacements are generated and tests/docs refer to the replacements.

2. **Artifact producer map**
   - Current `docs/GENERATED_ARTIFACTS.md` explains canonical artifacts, but not every historical proof has a one-line producer mapping.
   - Add a small machine-checkable manifest later if needed: artifact path, generator path, check command, release-blocking flag, historical flag.

## P2 — oversized module refactors

The following modules/functions exceed professional readability thresholds. Most are consensus- or state-sensitive and should not be refactored without focused tests.

### Files over 1,000 lines

- `src/weall/runtime/apply/poh.py`
- `src/weall/api/routes_public_parts/poh.py`
- `src/weall/runtime/executor.py`
- `src/weall/runtime/tx_schema.py`
- `src/weall/net/net_loop.py`
- `src/weall/runtime/apply/dispute.py`
- `src/weall/api/routes_public_parts/tx.py`
- `src/weall/runtime/apply/roles.py`
- `src/weall/runtime/apply/consensus.py`
- `src/weall/runtime/fault_injection.py`
- `src/weall/runtime/apply/groups.py`
- `src/weall/runtime/apply/content.py`
- `src/weall/runtime/apply/governance.py`
- `src/weall/api/routes_public_parts/status.py`
- `src/weall/runtime/bft_runtime_adapter.py`
- `src/weall/net/node.py`
- `src/weall/runtime/apply/storage.py`
- `src/weall/runtime/bft_hotstuff.py`
- `src/weall/runtime/bft_pending_frontier_impl.py`
- `src/weall/api/routes_public_parts/media.py`
- `src/weall/runtime/apply/identity.py`
- `src/weall/runtime/parallel_execution.py`
- `src/weall/api/routes_public_parts/content.py`
- `src/weall/api/public_seed_registry.py`
- `src/weall/runtime/apply/economics.py`

### Long functions/classes to split only with dedicated tests

- `src/weall/runtime/block_replay.py::apply_block`
- `src/weall/runtime/block_builder.py::build_block_candidate`
- `src/weall/runtime/executor.py::WeAllExecutor.__init__`
- `src/weall/runtime/mempool.py::PersistentMempool.add`
- `src/weall/runtime/block_admission.py::admit_bft_block`
- `src/weall/runtime/parallel_execution.py::merge_helper_lane_results`
- `src/weall/api/routes_public_parts/tx.py::tx_submit`
- `src/weall/runtime/executor.py::WeAllExecutor`
- `src/weall/net/net_loop.py::NetMeshLoop`
- `src/weall/net/node.py::NetNode`

Safe extraction candidates for later patches: response formatting helpers in API route files, repeated error construction, non-mutating view builders, and frontend component splits. Avoid changing consensus order, mutation order, hashing, serialization, replay, admission, or scheduler behavior in a presentation-only cleanup.

## P3 — frontend naming clarity

Live verification still uses internal `p2p` variable/class names because the implementation uses WebRTC peer connections. User-facing copy should consistently call this “live media transport” or “case-scoped browser media,” not private messaging. Rename internal identifiers only if tests cover the full live-verification path.
