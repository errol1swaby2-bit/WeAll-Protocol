# WeAll v1.5 Block-Schedule Survivability Audit

Status: audit harness and budget artifact added. This report is intentionally conservative: passing unit tests are not treated as proof that public testnet block cadence survives realistic or adversarial load.

## Verdict

The repository has a deterministic block-construction path and bounded count-based mempool admission, but the snapshot did not contain a dedicated block-cadence stress harness, an explicit per-phase 20 second budget, or execution-cost-weighted admission defaults before this audit. The largest discovered survivability risk is that `src/weall/runtime/domain_apply.py::apply_tx_atomic_meta` deep-copies the full state for every transaction. That makes even cheap public social transactions grow with total ledger state size, and it means `WEALL_BLOCK_MAX_TXS`/`max_txs` is not enough by itself to protect the target cadence as the state grows.

Public testnet should start with conservative block-size/load limits and should require the new rehearsal evidence to pass before raising limits.

## Phase 0 — block-production-critical codebase map

| Area | Real files/functions | Cadence relevance |
|---|---|---|
| Transaction catalog | `generated/tx_index.json`, `src/weall/runtime/supported_txs.py::load_supported_tx_types` | The generated tx index currently exposes hundreds of canonical transaction names. The stress harness loads the generated index rather than a hand-made subset. |
| Public transaction admission | `src/weall/runtime/executor.py::WeAllExecutor.submit_tx`, `src/weall/runtime/tx_admission.py::admit_tx`, `src/weall/runtime/mempool.py::PersistentMempool.add` | User/API transactions are validated before mempool insertion. Malformed spam must be rejected here, before block execution. |
| Mempool validation/backpressure | `src/weall/runtime/mempool.py::PersistentMempool.__init__`, `add`, `compute_tx_id`, `pending_max_nonce` | Default hard caps are count-based: `max_items=50000`, `max_per_signer=2000`, optional `max_per_tx_type=0` disabled. These prevent infinite rows but do not bound execution cost per block. |
| Mempool ordering | `src/weall/runtime/mempool.py::fetch_for_block`, `_selection_key`, `selection_policy` | Candidate selection uses canonical ordering by chain, nonce, signer, tx type, and tx id. Block construction passes a candidate height. |
| Block proposal construction | `src/weall/runtime/block_builder.py::produce_block`, `build_block_candidate` | Leader path selects mempool rows, deep-copies state, runs pre-schedulers, validates block txs, executes txs, runs post-schedulers, computes receipts root, state root, block id, and helper metadata. |
| Consensus proposal/vote/commit | `src/weall/consensus/hotstuff.py`, `src/weall/runtime/block_replay.py::apply_block`, `src/weall/runtime/block_commit.py::commit_block_candidate` | Followers replay and validate the proposed block; commits persist block rows, tx index rows, mempool deletes, and ledger state atomically. |
| Transaction execution | `src/weall/runtime/domain_apply.py::apply_tx_atomic_meta`, `src/weall/runtime/domain_dispatch.py::apply_tx`, `src/weall/runtime/apply/*.py` | Every successful tx takes the atomic apply path. The full-state copy in `apply_tx_atomic_meta` is the main execution-cost risk. |
| Helper / parallel execution | `src/weall/runtime/helper_execution_runtime.py::_build_helper_execution_metadata`, `src/weall/runtime/parallel_execution.py::plan_parallel_execution`, `canonical_lane_plan_fingerprint` | Helper metadata is built after serial execution in the current leader path. Helpers can accelerate/audit, but the serial state root remains authoritative. |
| Lane partitioning/conflicts | `src/weall/runtime/parallel_execution.py::_effective_parallel_lane_id`, `_access_conflicts`, `build_lane_plans` | Lane planning uses canonical descriptors/access sets and downgrades to serial on mismatch/conflict. |
| Receipt generation | `src/weall/runtime/block_builder.py::build_block_candidate`, `src/weall/runtime/block_replay.py::apply_block`, `src/weall/ledger/state.py::compute_receipts_root` | Receipts are generated during apply, committed into the block, and replay-checked. They must not be dropped for speed. |
| State root calculation | `src/weall/ledger/state.py::compute_state_root`, callers in `block_builder.py` and `block_replay.py` | State-root hashing is mandatory for convergence and now timed by the rehearsal harness. |
| Persistence writes | `src/weall/runtime/block_commit.py::commit_block_candidate` | SQLite write transaction inserts block/index rows, deletes mempool txs, and writes the state snapshot. This is timed separately by the harness. |
| Peer gossip / propagation | `src/weall/net/node.py`, `src/weall/runtime/block_replay.py::apply_block` | Real network latency is not measured by the local harness; the network profile replays blocks through follower/slow-observer paths and records convergence. |
| API read freshness | `src/weall/api/routes_public_parts/tx.py::tx_submit`, `tx_status`, `account_nonce_status`, `src/weall/api/routes_public_parts/feed.py` or content/feed routes | The API exposes accepted/pending/confirmed status and nonce cursors, but stale reads and retry storms still need load testing with a running frontend. |
| Frontend confirmation path | `web/src/api/weall.ts`, `web/src/pages/Group.tsx`, feed/governance/dispute pages | Frontend must show durable acceptance and confirmed inclusion separately; this audit flags that as a UX rehearsal requirement rather than assuming it from backend tests. |

## Phase 1 — block-time budget

The configured production target is 20 seconds. The budget is now machine-readable in `specs/block_schedule_survivability_budget_v1_5.json`.

| Phase | Budget ms | Evidence/owner |
|---|---:|---|
| Mempool selection | 500 | `PersistentMempool.fetch_for_block` |
| Proposal construction/canonicalization | 400 | `build_block_candidate` wrapper residual |
| Block admission validation | 800 | `admit_block_txs` timing |
| Transaction execution | 10000 | `RuntimeContext.tx_execution_set.apply_tx_atomic_meta` timing |
| Helper planning, non-authoritative | 750 | `_build_helper_execution_metadata` timing |
| Deterministic merge | 250 | helper merge lane budget; zero when no helper receipts are present |
| State/receipts root | 1500 | `compute_state_root` timing plus receipts-root path |
| Persistence commit | 1000 | `commit_block_candidate` timing |
| Consensus/network propagation | 4000 | must be measured in real multinode/public testnet rehearsals |
| API/index refresh | 500 | tx index/status/feed freshness budget |
| Safety buffer | 300 | remaining slack |

## Phase 2 — transaction cost inventory

Cheap expected paths: `PROFILE_UPDATE`, `FOLLOW_SET`, `CONTENT_REACTION_SET`, account key/session updates, simple validator heartbeat/status updates. These should touch one account/profile/edge/reaction key plus nonce/receipt data, but the current atomic wrapper still copies full state.

Medium expected paths: `CONTENT_POST_CREATE`, `CONTENT_COMMENT_CREATE`, `GROUP_MEMBERSHIP_REQUEST`, `GOV_PROPOSAL_COMMENT`, `GOV_VOTE_CAST`, profile/media metadata declaration. These add indexed social/governance objects and may update reputation accrual queues or feed/materialized indexes.

Expensive expected paths: `GROUP_CREATE`, `GOV_PROPOSAL_CREATE`, `DISPUTE_OPEN`, `DISPUTE_VOTE_SUBMIT`, content flag/escalation, validator/operator lifecycle changes, storage challenge/proof paths, and any transaction that schedules follow-up system transactions.

Potentially unbounded paths discovered:

* `src/weall/runtime/domain_apply.py::apply_tx_atomic_meta` copies the full state per tx. Cost grows with total users, content, groups, proposals, disputes, validators, reputation records, and persisted indexes.
* Governance electorate helpers such as `src/weall/runtime/apply/governance.py::_proposal_eligible_validator_ids` can scale with validator/account state.
* Dispute juror selection/eligibility paths in `src/weall/runtime/apply/dispute.py` can scale with juror/account state.
* Feed/index materialization must remain paginated. Any route that scans all posts/comments/groups/proposals under load is a frontend/API risk even when consensus continues producing blocks.

## Phase 3 — load modeling

The new harness implements four profiles:

* `light`: 5–10 user launch behavior; profile updates, posts, comments, reactions, follows.
* `active`: 50–100 user civic behavior; posts, comments, group membership, group creation, governance proposals/comments/votes, content flags.
* `adversarial`: valid expensive transaction mix plus malformed envelopes rejected through admission.
* `network`: follower and delayed observer replay while the leader continues producing blocks.

## Phase 4 — measurement harness

Added `scripts/rehearse_block_schedule_survivability_v1_5.py`. It records per block:

* txs admitted/rejected;
* txs included;
* type mix selected/included;
* mempool backlog before/after;
* candidate/proposal time;
* block admission time;
* exact apply function execution time through the runtime context;
* helper planning time where enabled;
* state root time;
* persistence time;
* total block production time;
* target interval miss flag;
* follower/slow-observer state-root convergence.

The harness emits JSON under `rehearsal-evidence/` or a caller-specified `--out` path.

## Phase 5 — helper / parallel execution safety

The code path currently builds helper metadata through `src/weall/runtime/helper_execution_runtime.py::_build_helper_execution_metadata` after serial execution. Lane planning lives in `src/weall/runtime/parallel_execution.py` and fingerprints canonical lane plans. This is consistent with the safety invariant that helpers are not consensus authorities. The audit still requires helper-enabled vs helper-disabled convergence rehearsals before enabling a public testnet helper fast path.

## Phase 6 — mempool backpressure

Current bounded controls are deterministic but coarse:

* `PersistentMempool(max_items=50000)`;
* `max_per_signer=2000`;
* optional per-type cap disabled by default;
* canonical selection order;
* duplicate signer/nonce conflict rejection.

Risk: the mempool can be full of expensive but valid transactions, and a block can select too many for the 20 second cadence if `max_txs` is too high or state has grown. Recommended public-testnet starting cap: no more than 250 txs per block until active/adversarial evidence passes on target hardware and network.

## Phase 7 — worst-case execution paths

Slow-path candidates to trace first:

1. `domain_apply.py::apply_tx_atomic_meta`: full-state deep copy and rollback wrapper.
2. `apply/dispute.py::DISPUTE_OPEN` and `DISPUTE_VOTE_SUBMIT`: juror eligibility, explicit assignment, resolution side effects, reputation events, scheduled system follow-ups.
3. `apply/governance.py::GOV_PROPOSAL_CREATE` and `GOV_VOTE_CAST`: electorate discovery, proposal lifecycle, auto-progress scheduling.
4. `apply/groups.py::GROUP_CREATE`: treasury signer/wallet creation and public group authority metadata.
5. `apply/content.py::CONTENT_FLAG` and escalation paths: dispute scheduling and moderation target indexes.
6. `block_commit.py::commit_block_candidate`: block row, tx index, mempool delete, and full state snapshot persistence.

## Phase 8 — multinode block-cadence rehearsal

The local rehearsal creates a leader, follower, and delayed observer. The leader uses the same block-builder/commit path as production runtime. Followers replay with `apply_block` and compare state roots. This is not a WAN/BFT substitute, but it closes the local convergence gap and produces machine-readable evidence.

## Phase 9 — frontend/API UX under load

Backend status surfaces exist in `src/weall/api/routes_public_parts/tx.py::tx_submit`, `tx_status`, and `account_nonce_status`. UX risks that still need browser-level load rehearsal:

* submission UI must not say “confirmed” after mere mempool acceptance;
* rejected txs must show stable failure codes;
* pending and confirmed states must be visually distinct;
* stale API reads must not trigger retry storms;
* group/governance/dispute pages must remain paginated;
* local observer tx queue reconciliation must stay bounded.

## Phase 10 — commands

Run the fast regression gate:

```bash
cd ~/WeAll-Protocol/Weall-Protocol
PYTHONPATH=src pytest -q tests/test_block_schedule_survivability_harness.py
```

Run measured rehearsals:

```bash
cd ~/WeAll-Protocol/Weall-Protocol
PYTHONPATH=src WEALL_MODE=dev WEALL_UNSAFE_DEV=1 \
  python scripts/rehearse_block_schedule_survivability_v1_5.py \
  --profile light --blocks 4 --users 10 --max-txs-per-block 40

PYTHONPATH=src WEALL_MODE=dev WEALL_UNSAFE_DEV=1 \
  python scripts/rehearse_block_schedule_survivability_v1_5.py \
  --profile active --blocks 6 --users 75 --max-txs-per-block 160

PYTHONPATH=src WEALL_MODE=dev WEALL_UNSAFE_DEV=1 \
  python scripts/rehearse_block_schedule_survivability_v1_5.py \
  --profile adversarial --blocks 5 --users 50 --max-txs-per-block 120

PYTHONPATH=src WEALL_MODE=dev WEALL_UNSAFE_DEV=1 \
  python scripts/rehearse_block_schedule_survivability_v1_5.py \
  --profile network --blocks 5 --users 25 --max-txs-per-block 80
```

Run all profiles into one evidence artifact:

```bash
cd ~/WeAll-Protocol/Weall-Protocol
PYTHONPATH=src WEALL_MODE=dev WEALL_UNSAFE_DEV=1 \
  python scripts/rehearse_block_schedule_survivability_v1_5.py \
  --profile all --out rehearsal-evidence/block_schedule_survivability_all.json
```

## Remaining uncertainty

* Real WAN latency and HotStuff vote timing are not proven by the local rehearsal.
* Public-testnet hardware differences may move p95/p99 significantly.
* The full-state copy in `apply_tx_atomic_meta` can dominate as state grows even if light tests pass now.
* Helper-enabled serial equivalence should be tested against mixed high-cost transactions before enabling helpers beyond metadata/audit mode.
* Frontend retry behavior needs a Playwright/browser-level load rehearsal, not only backend status checks.

## Local sample evidence from this audit workspace

The following measurements were produced in the audit sandbox on the uploaded repository snapshot. They prove the harness works and show local single-machine behavior, but they are not a substitute for a real public-testnet WAN/BFT run.

| Profile | Users / blocks / max txs | Avg ms | Max ms | p95 ms | p99 ms | Target misses | Converged |
|---|---:|---:|---:|---:|---:|---:|---|
| light | 10 / 4 / 40 | 47.029 | 53.235 | 52.805 | 53.149 | 0 | yes |
| active sample | 40 / 3 / 100 | 417.737 | 632.230 | 608.296 | 627.443 | 0 | yes |
| active 75-user short run | 75 / 2 / 160 | 674.341 | 749.618 | 742.090 | 748.112 | 0 | yes |
| adversarial sample | 30 / 3 / 80 | 131.876 | 177.852 | 175.267 | 177.335 | 0 | yes |
| network sample | 20 / 3 / 60 | 91.670 | 98.980 | 97.948 | 98.774 | 0 | yes |

Important observation: the active profiles generated many `bad_nonce` rejections under repeated `GROUP_MEMBERSHIP_REQUEST` behavior. The relevant code path is `src/weall/runtime/apply/groups.py::_apply_group_membership_request`: when `account in members`, it returns a successful dedupe receipt without the group applier touching nonce state; the outer atomic wrapper normally consumes nonce after success, but this path still deserves a targeted replay/admission test because the load model surfaced visible nonce/backlog churn. Do not fix this in a cadence-only patch without a separate consensus-safety review.

A default active profile run with 75 users / 6 blocks / 160 txs per block was attempted in the sandbox and exceeded the 300 second tool timeout before writing an artifact. That is treated as uncertainty/risk, not as a passing result.
