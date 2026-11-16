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
