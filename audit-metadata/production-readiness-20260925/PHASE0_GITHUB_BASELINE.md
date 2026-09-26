# WeAll Protocol Production Readiness Audit — Phase 0 GitHub Baseline

Status: IN PROGRESS — repository-index checkpoint only. This document is not a production-readiness or defect-closure claim.

## Authority and exact subject

This remediation effort uses the GitHub repository as the implementation source of truth.

- Repository: `errol1swaby2-bit/WeAll-Protocol`
- Base branch: `main`
- Baseline commit: `69cce170829ded30ebb030669f05c387df6a3ddb`
- Baseline Git tree: `6badceb25a9d209ac54b6066a2e4a4844abe74ab`
- Audit/remediation branch: `production-readiness-audit-20260925`

Historical audit documents, prior patches, local worktrees, generated proof artifacts, and prior pass/fail statements are evidence inputs only. A historical finding is not considered open or closed for this PR until it is revalidated against this exact GitHub source.

## Repository inventory

The recursive Git tree at the baseline commit contains 2,443 total tree entries and 2,325 blobs. Of those, 1,955 blobs are under `Weall-Protocol/`. The protocol subtree includes 1,003 Python test files, 182 Python runtime modules, 44 Python API modules, 19 Python networking modules, 5 Python crypto modules, 101 generated artifacts, 28 specification files, 197 documentation files, and 309 inner protocol scripts.

The repository also contains top-level `artifacts/`, `audit-metadata/`, `scripts/`, `web/`, release documentation, and operator/development scripts. Those surfaces remain in scope where they affect reproducibility, release claims, production posture, CI, or reviewer interpretation.

## CI and reviewer gates

The baseline has four GitHub Actions workflows: `backend-ci.yml`, `reviewer-readiness.yml`, `secrets-guard.yml`, and `web-ci.yml`.

Backend CI uses Python 3.12, locked dependency installation with hashes, changed-file Ruff checks, dependency audit, canon lint, generated-artifact/spec checks, public-readiness and claim-freshness checks, historical M2/M3 evidence restoration, full `pytest -q`, and generation of a transaction coverage report.

Reviewer readiness verifies the release tree before dependency installation, installs locked backend and frontend dependencies, restores historical evidence, and runs `scripts/reviewer_production_readiness_gate.sh`.

Audit note: changed-file-only Ruff is not by itself whole-tree lint proof. The reviewer gate and release tooling must be traced before this is classified as a gap.

## Canonical execution surface

The authoritative transaction canon is `Weall-Protocol/specs/tx_canon/tx_canon.yaml`. The repository currently describes a generated canonical transaction count of 236 at canon version `1.25.0`; this is treated as a generated structural fact to be independently checked, not as proof of semantic correctness.

Primary execution chain to trace:

`specs/tx_canon/tx_canon.yaml` → `src/weall/tx/canon.py` → generated transaction index/contract artifacts → `runtime/tx_schema.py` → `runtime/tx_admission.py` → `runtime/tx_contracts.py` / `runtime/domain_dispatch.py` → `runtime/apply/<domain>.py` → leader construction or follower replay → state-root computation → atomic block/state persistence.

Primary state domains include consensus, content, dispute, economics, governance, groups, identity, indexing, networking, notifications, PoH, protocol, reputation, rewards, roles, social, storage, and treasury.

## Consensus / BFT surface

Primary modules include `runtime/bft_hotstuff.py`, `runtime/bft_runtime_adapter.py`, `runtime/bft_finality_bridge.py`, `runtime/bft_journal.py`, `runtime/bft_outbound.py`, `runtime/bft_outbox_store.py`, `runtime/bft_pending_frontier.py`, `runtime/bft_votecheck.py`, `runtime/ancestry.py`, `runtime/commitments.py`, `runtime/block_admission.py`, `runtime/block_builder.py`, `runtime/block_replay.py`, and `runtime/block_commit.py`.

The current implementation explicitly identifies HotStuff BFT, deterministic round-robin leader selection over the normalized validator set, quorum `ceil(2n/3)`, and three-chain finality. These implementation facts must be tested against alternate authority and compatibility paths.

The implementation distinguishes solo bootstrap, multi-validator bootstrap, and BFT-active phases and currently reports a minimum of four validators for its BFT-ready posture.

## State, persistence, restart, and sync

Primary modules include `runtime/state_hash.py`, `runtime/sqlite_db.py`, `runtime/block_commit.py`, `runtime/executor.py`, `runtime/executor_boot.py`, `runtime/bounded_rollback.py`, `net/state_sync.py`, and `api/routes_public_parts/state.py`.

The state-root implementation is path-aware: it excludes known top-level ephemeral fields, projects top-level `state["meta"]` to an explicit consensus-semantic key set, commits nested structures normally, sorts dictionary keys, and preserves list order.

SQLite remains the canonical persistence substrate for ledger/state paths. Persistence review must cover configuration-sensitive durability, transaction boundaries, restart identity, DB consistency, mempool interaction, auxiliary-state separation, failure handling, and crash/recovery behavior. State synchronization must be audited across every adapter, not only the ordinary P2P path.

## Networking and peer identity

Primary modules include `net/node.py`, `net/net_loop.py`, `net/router.py`, `net/gossip.py`, `net/handshake.py`, `net/peer_identity.py`, `net/peer_store.py`, `net/peer_list_store.py`, `net/transport_tcp.py`, `net/transport_tls.py`, and `net/state_sync.py`.

Review priorities include authenticated identity binding, replay resistance, durable peer-abuse attribution, session establishment, packet admission ordering, BFT sender attribution, rate limiting, deduplication, transport identity vs account identity, reconnect/restart behavior, and state-sync trust.

## Helper / parallel execution

Primary modules include `runtime/parallel_execution.py`, `runtime/helper_apply.py`, `runtime/helper_assignment.py`, `runtime/helper_capabilities.py`, `runtime/helper_capacity.py`, `runtime/helper_certificates.py`, `runtime/helper_assembly_gate.py`, `runtime/execution_lanes.py`, `runtime/lane_assignment.py`, `runtime/lane_identity.py`, and `runtime/read_write_sets.py`.

A critical source-level boundary is explicit in `parallel_execution.py`: `SerialHelperEquivalenceReport` is a receipt/order equivalence report and does not prove post-state equality.

Therefore production helper safety cannot be inferred from receipt/order equivalence. Activation requires complete serial/post-state equivalence, deterministic planning and merge, context-bound authenticated helper evidence, restart safety, deterministic fallback, and adversarial multinode behavior.

The current generated claim register explicitly says production helper execution is not claimed/enabled. That boundary must remain truthful unless this PR actually satisfies and proves stronger activation gates.

## API / runtime authority

Primary bootstrap is `src/weall/api/app.py`, with runtime authority derived from chain/runtime configuration and executor lifecycle state. Current production startup logic has explicit fail-closed checks for strict runtime authority refusal, ineffective requested validator/BFT posture, production CORS wildcard rejection, single-worker requirements for network/BFT/block-loop runtime, production networking/BFT identity keys, and incompatible BFT/local block-loop topology.

These checks are safety relevant but are not assumed complete until alternate entrypoints, scripts, constructors, environment variables, and direct runtime APIs are traced.

## Claim boundary

`docs/CURRENT_VERIFIED_CLAIMS.md` currently states that public beta readiness, mainnet readiness, production helper execution, public multi-validator BFT, completed production cryptographic audit, and a current scalar TPS claim are not established. `docs/KNOWN_LIMITATIONS.md` similarly describes the project as pre-production and not a public mainnet or production multi-validator network.

These are claim surfaces, not proofs. They must be checked against implementation, generated artifacts, README/release material, scripts, API status surfaces, and CI output before merge.

## Phase 0 invariant families

1. Canonical transaction authority: every admitted canonical transaction has exactly one authoritative schema/handler/semantics path.
2. Signature and identity binding: transaction, block, validator, peer, helper, and state-sync authority is cryptographically and contextually bound.
3. Nonce/order determinism: consensus-visible transaction selection/execution does not depend on local arrival or wall-clock behavior.
4. Leader/replay equivalence: leader construction and follower replay produce the same receipts and full consensus-visible post-state.
5. State-root completeness: every execution-affecting state field is committed under stable canonical serialization.
6. Atomic persistence: durable block/state/index/mempool effects cross coherent commit boundaries and restart reproduces canonical state.
7. BFT authority/finality: only current authenticated validator authority can advance consensus, durable safety evidence survives restart, and finality is monotonic.
8. State-sync trust: all state-installation adapters enforce the same configured trust model.
9. SYSTEM determinism: scheduler and SYSTEM transaction authority is deterministic, replayable, and lineage/context bound.
10. Helper serial equivalence: helper execution cannot change consensus-visible outcome relative to canonical serial execution.
11. Production configuration fail-closed behavior: unsafe or contradictory production settings are rejected before authority is acquired.
12. Claim truthfulness: documentation and generated evidence must not describe a stronger property than the exact implementation and exact-head evidence support.

## Next pass

Phase 1 starts with source-level end-to-end traces for user transaction submission and durable restart; received-block replay; validator/BFT proposal-vote-QC-finality; peer identity and durable peer security; snapshot/delta state sync; helper execution vs serial execution; governance/SYSTEM execution into live runtime parameter consumers; and identity key/session/recovery controls.

Historical findings will be cross-checked during those traces. No runtime patch is accepted solely because it matches a historical recommended repair.
