# Executor Refactor Module Boundaries

This refactor turns `src/weall/runtime/executor.py` into a smaller runtime facade and moves consensus-adjacent responsibilities behind explicit module boundaries.

The patch is intentionally structural first: it preserves public executor methods and protocol behavior while making future semantic corrections easier to review.

## New boundaries

- `runtime_env.py` — runtime mode, env parsing, bounded local cache helpers, production fail-closed helper surface.
- `runtime_time.py` — wall-clock wrapper and block timestamp policy surface.
- `scheduler_pipeline.py` — centralized scheduler/emitter/prune call ordering for leader and replay paths.
- `genesis_bootstrap.py` — genesis profile, initial state construction, and bootstrap grant delegates.
- `runtime_posture.py` — node lifecycle, observer mode, validator signing posture, and startup safety delegates.
- `block_builder.py` — leader-side `produce_block()` and `build_block_candidate()` logic.
- `block_replay.py` — follower-side received block replay and root verification logic.
- `block_commit.py` — atomic block/state/tx-index/mempool commit boundary.
- `helper_execution_runtime.py` — helper lane planning metadata, helper diagnostics profile, and helper root/certificate delegate.
- `bft_runtime_adapter.py` — BFT proposal/vote/QC/timeout/pending-artifact/cache adapter surface.
- `diagnostics.py` — runtime diagnostics delegates.

## Preserved behavior

The patch keeps the `WeAllExecutor` public API stable. Existing callers should still use methods on `WeAllExecutor`; those methods now delegate to the extracted modules.

The extraction deliberately avoids changing:

- tx admission/application semantics
- block ID, block hash, receipts root, and state root construction
- block timestamp validation policy
- system tx scheduler ordering
- mempool cleanup behavior
- tx index writes
- helper serial fallback behavior
- BFT proposal/vote/QC handling
- production fail-closed posture

## Important review note

The first pass uses thin delegates that operate on the executor instance. Some extracted modules lazily bind executor-level imports to keep the patch behavior-preserving and avoid a larger semantic rewrite in the same step. The next cleanup pass should replace those lazy bindings with explicit context/data classes once the regression suite is green on the extracted structure.

## Regression gate used for this patch

The following focused regression checks passed locally with `PYTHONPATH=src`:

```bash
pytest -q tests/test_block_id_content_addressed.py tests/test_tx_index_consistency.py tests/test_block_timestamp_policy.py tests/test_state_root_ephemeral_contract.py
pytest -q tests/test_helper_serial_equivalence_fallback_batch12.py tests/test_helper_fallback_equivalence_batch107.py tests/test_helper_execution_root_commitment_batch311.py tests/test_mempool_clears_only_committed_txs.py tests/test_pending_tx_survives_failed_commit.py
pytest -q tests/test_bft_hotstuff.py tests/test_bft_proposal_vote_safety_integration.py tests/test_bft_epoch_binding_strict.py
pytest -q tests/test_block_candidate_selection_is_deterministic.py tests/test_block_id_is_stable_for_same_candidate_inputs.py tests/test_block_commitments_required.py tests/test_block_timestamp_validation_received.py tests/test_config_fail_closed_batch11.py tests/test_production_consensus_profile.py tests/test_node_lifecycle_production_preflight_batch119.py tests/test_mixed_node_posture_fail_closed_batch43.py tests/test_priority1_replay_equivalence_batch70.py tests/test_priority2_state_replay_determinism_batch109.py
```

Total focused result: 52 passing tests across block identity, state roots, timestamps, helper fallback, commit/mempool behavior, BFT, replay determinism, production profile, and node posture.

## Next correction pass after this patch

After applying this patch and running the wider suite, the next pass should focus on:

1. Replacing lazy module global binding with explicit context objects.
2. Collapsing leader/replay scheduler profiles only if replay/root tests prove behavior is unchanged or intentionally corrected.
3. Moving the remaining executor initialization wiring into a dedicated boot/context constructor without changing startup semantics.
4. Deleting compatibility wrappers once all API routes/tests import the new stable interfaces directly.
