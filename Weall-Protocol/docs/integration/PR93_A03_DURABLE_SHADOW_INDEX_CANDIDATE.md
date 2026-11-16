# PR #93 — A03 durable public-lobby shadow-index candidate

**Status: OFFLINE PROTOTYPE / DRAFT / NO-GO.** No production route, executor, BFT commit, state-sync, parameter, PoH, reward, reputation, or constitutional authorization change is introduced.

## Exact source to projection boundary

- The candidate lives in src/weall/api/public_lobby_index_candidate.py, with regression tests in tests/test_pr93_public_lobby_index_candidate.py.
- Its input is a caller-supplied state object, chain identifier, block height/id, and exact computed canonical state root. The builder rejects mismatched declarations. It does **not** independently establish that a supplied state is final or that its tip is the current durable ledger head.
- The candidate deliberately imports the existing content read route's canonical lobby identity, moderation/dispute visibility, and field serialization helpers. This avoids silently defining a second moderation policy during the experiment.
- Rows are organized by thread and descending (created_nonce, comment_id), with a composite SQLite page index and limit+1 cursor semantics. Hidden, deleted, private, wrong-surface and malformed-index-identity records cannot enter the materialized output.
- Rebuild atomically replaces metadata and rows in a SQLite transaction. Reading metadata and the page occurs within one SQLite read transaction. The read fails closed on absent, changed, or version-incompatible source bindings, including an empty thread.
- Tests compare the candidate with the existing anonymous public-lobby endpoint, including equal-nonce pagination; cover dispute suppression and DB restart; reject stale or tampered roots; and inject a projection failure without publishing a partial replacement.

## Nonclaims and important missing work

1. **Not production integrated.** There is no API feature flag and no automatic call from block commit, rollback, checkpoint installation, restart, or state sync. A production handler MUST NOT use this candidate as a source of truth.
2. **No authoritative source check at read time.** The page method requires a head/root binding supplied independently by its caller. Supplying the index's own previous binding would allow stale content; integrating an authenticated durable current-head/root check and atomic update/invalidation is mandatory.
3. **Full offline rebuild, not scalable updates.** Projection currently walks all global comment records and reuses the canonical visibility predicate, which may rescan disputes. It has a bounded 50,000-comment offline build budget; this is not production-scale incremental indexing and is not run during consensus commit.
4. **Fork and crash policy is unproven.** Same-height conflicting rebuilds fail closed; there is no reviewed reorg/join/recovery policy or verified checkpoint replay. Tests prove basic SQLite restart and transaction atomicity, not complete chain replay, P2P finality, or BFT equivalence.
5. **No HTTP response change.** The live endpoint still uses the earlier 10,000-record/512-visibility-evaluation temporary guards and can return 503 at large scale. The accepted V2 public-lobby route semantic review and 20 stale transaction semantic reviews remain separate blockers.
6. **No throughput evidence.** No hard latency, memory, disk-amplification, or adversarial long-history guarantees follow from these tests; query explain plans, bounded background rebuild scheduling, and live two-node replay parity are still required.

## Next acceptance increment

Implement an independently authenticated committed-head read binding that does not deserialize state_json; define fail-closed projection invalidation on every state transition path (block commits, checkpoint installation, rollback/reorg, restart, and state-sync); then test each transition with durable SQLite history. Only after exact-head source and CI verification, adversarial parity/replay tests, and explicit semantic approval should the live route be considered for cutover. PR #93 remains DRAFT / NO-GO.

## Follow-up candidate: opt-in commit-bound invalidation (2026-11-16)

- attach_commit_invalidation() creates three durable SQLite triggers on the **same main ledger database** (ledger_state INSERT/UPDATE/DELETE) only when explicitly invoked. It invalidates shadow metadata atomically inside every transaction that changes the ledger snapshot. Production does **not** invoke this opt-in function.
- rebuild_from_local_ledger() reads persisted snapshot JSON offline, recomputes its root, verifies the complete stored tip block and state-root commitment, and checks the same ledger height/block ID again under the final writer lock before publishing derived rows. This is self-consistent **local** persisted history, not independently verified BFT finality.
- page_from_local_ledger() reads the durable ledger head and matching shadow metadata within the **same SQLite read transaction** as the page rows. If the index is absent or invalidated, it fails closed; it does not parse global state_json.
- The tests exercise real WeAllExecutor SQLite block commits and restart, an injected uncommitted block-write rollback, and the real storage-layer checkpoint replacement. Checkpoint installation is invoked directly for storage-layer evidence, **not** as proof that production state-sync authenticated a remote checkpoint.
- The index remains a full-snapshot, 50,000-comment capped **offline** rebuild. No automatic reindex worker, catchup, fork reconciliation, production API switch, or measured production-scale throughput is claimed. A node can still return HTTP 503 on the existing live route.

**Safety boundary:** SQLite trigger installation is opt-in diagnostic instrumentation and is not a reviewed activation mechanism. It is not a constitutional authorization and cannot be used to infer production runtime or validator signing readiness.

## Exact-source validation evidence for commit 4d61498eb101

- Source commit: 4d61498eb101c5f23f24a30a5db3b41f25ec5194; focused A03 shadow-index [workflow run 43975717692](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/43975717692) **passed** with pinned Ruff and **20 total tests** (new shadow-index candidates plus original public-lobby regressions).
- The three full B528/B534/B567 diagnostic regeneration harnesses [run 43975718647](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/43975718647) **passed**. The output proved semantically unchanged compared with the previous JSON; only deterministic input fingerprints changed.
- Reviewer Readiness and A01–A20 remain non-green. Passing A03 and B5xx diagnostics is neither a semantic-review signature nor approval of this candidate for public API, BFT finality, production network, Genesis or beta.
- All generated evidence files in the next commit are strictly source-bound to the **implementation input commit**, not an automatic assertion that the evidence-only follow-up commit's CI passed.


## Negative verification hardening after evidence refresh

An attached local-ledger index now refuses the bare caller-supplied rebuild path. Only the verified local committed-tip rebuild may publish rows once durable ledger invalidation triggers are present. Added fault injection changes canonical state_json directly while preserving its old tip height and block ID. The next rebuild must detect that the persisted tip block's state-root commitment no longer matches and must refuse to publish the forged content. Trigger invalidation also prevents serving the previously published rows. This is storage-integrity testing, not independent historical finality.

## Latest exact-source A03 checks (ee10cdcd470ac1b7f8ecd4cdae3df20ef5f44051)

- [A03 shadow-index parity run 43976622579](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/43976622579): **passed**, pinned Ruff and **21** focused regression cases. Includes the attached-index unverified-rebuild denial and direct SQLite snapshot-tampering test.
- [B528/B534/B567 full-harness run 43976622371](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/43976622371): **passed**; resulting checked-in proof JSON differs solely in source-freshness inputs, not execution claims, test outcomes, or locked authorization boundaries.
- The regeneration is bound to this exact implementation source, not a human V2 semantic approval or production authorization. The subsequent evidence-only commit requires a fresh exact-head CI run.
- Automatic incremental maintenance, production read-route cutover, fork recovery, externally authenticated finality, 20 remaining transaction semantic adjudications, and public Genesis remain unresolved.


## One-block incremental shadow reconciliation — diagnostic only

A new companion component, `public_lobby_incremental_candidate.py`, introduces an **opt-in, post-commit** row-delta experiment. The existing durable ledger_state triggers continue invalidating served metadata as part of each block or checkpoint transaction. The experimental reconciler records a prior verified local block/height/root anchor, checks one locally stored canonical parent→child block link and both source-state root commitments, compares an explicit prior state against the next durable state, and atomically updates only changed lobby-comment rows before publishing the new matching index binding. Every unrecognized moderation/dispute/content policy change, missing anchor, source mismatch, gap, or excessive comment delta fails closed and requires a full verified rebuild.

This is **not** constant-time commit mutation tracking: identifying changed comments currently compares both full in-memory comment maps, and the proof also parses durable full state_json during post-commit reconciliation. The real production API remains unchanged and its temporary 503 limits still apply. Production-wide automatic hooks, proof-complete change journaling, asynchronous catchup, multi-commit replay, state-sync checkpoint recovery, and BFT finality are NOT established.

The targeted tests use the real executor and follower `apply_block` over two local SQLite databases, proving the empty-block one-step reconciliation and follower restart metadata parity, but not physically isolated operators or authenticated P2P transport.

### Restart invalidation discovered by exact-head CI

The first two-node regression passed commit/replay and one-step reconciliation but correctly failed its original expectation that the index remains readable immediately after restarting the follower. Executor startup performs same-height ledger_state writes for local runtime/BFT persistence, so the installed SQLite triggers invalidate the projection even when the canonical content has not changed. The corrected regression requires fail-closed unavailability after restart, followed by verified full rebuild and re-arming before parity can be claimed. This is a safety-preserving limitation and underscores why efficient restart catchup is still open.
