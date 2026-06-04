from __future__ import annotations

"""Thin public BFT pending-frontier facade.

The implementation lives in ``bft_pending_frontier_impl`` so reviewers can
separate the public adapter surface from the larger pending block/QC replay
state machine.  Keep these wrappers stable; they preserve the historical
function names used by ``bft_runtime_adapter`` and tests.
"""

from weall.runtime import bft_pending_frontier_impl as _impl

def _persist_pending_bft_artifact(self, *args, **kwargs):
    return _impl._persist_pending_bft_artifact(self, *args, **kwargs)

def _delete_pending_bft_artifact(self, *args, **kwargs):
    return _impl._delete_pending_bft_artifact(self, *args, **kwargs)

def _restore_pending_bft_frontier(self, *args, **kwargs):
    return _impl._restore_pending_bft_frontier(self, *args, **kwargs)

def _prune_pending_bft_artifacts_on_local_validator_transition(self, *args, **kwargs):
    return _impl._prune_pending_bft_artifacts_on_local_validator_transition(self, *args, **kwargs)

def _cache_known_block_hash(self, *args, **kwargs):
    return _impl._cache_known_block_hash(self, *args, **kwargs)

def _lookup_committed_block_hash_index(self, *args, **kwargs):
    return _impl._lookup_committed_block_hash_index(self, *args, **kwargs)

def _lookup_committed_block_id_by_hash(self, *args, **kwargs):
    return _impl._lookup_committed_block_id_by_hash(self, *args, **kwargs)

def _known_block_hash_for_id(self, *args, **kwargs):
    return _impl._known_block_hash_for_id(self, *args, **kwargs)

def _known_block_id_for_hash(self, *args, **kwargs):
    return _impl._known_block_id_for_hash(self, *args, **kwargs)

def _is_conflicted_block_id(self, *args, **kwargs):
    return _impl._is_conflicted_block_id(self, *args, **kwargs)

def _is_conflicted_block_hash(self, *args, **kwargs):
    return _impl._is_conflicted_block_hash(self, *args, **kwargs)

def _drop_pending_candidate_artifacts(self, *args, **kwargs):
    return _impl._drop_pending_candidate_artifacts(self, *args, **kwargs)

def _mark_block_id_conflict(self, *args, **kwargs):
    return _impl._mark_block_id_conflict(self, *args, **kwargs)

def _mark_block_hash_conflict(self, *args, **kwargs):
    return _impl._mark_block_hash_conflict(self, *args, **kwargs)

def _qc_identity_conflicts(self, *args, **kwargs):
    return _impl._qc_identity_conflicts(self, *args, **kwargs)

def _block_identity_conflicts(self, *args, **kwargs):
    return _impl._block_identity_conflicts(self, *args, **kwargs)

def _block_height_hint(self, *args, **kwargs):
    return _impl._block_height_hint(self, *args, **kwargs)

def _has_local_block(self, *args, **kwargs):
    return _impl._has_local_block(self, *args, **kwargs)

def _index_pending_remote_block(self, *args, **kwargs):
    return _impl._index_pending_remote_block(self, *args, **kwargs)

def _index_quarantined_remote_block(self, *args, **kwargs):
    return _impl._index_quarantined_remote_block(self, *args, **kwargs)

def _quarantine_remote_block(self, *args, **kwargs):
    return _impl._quarantine_remote_block(self, *args, **kwargs)

def _drop_quarantined_remote_artifacts(self, *args, **kwargs):
    return _impl._drop_quarantined_remote_artifacts(self, *args, **kwargs)

def _put_pending_remote_block(self, *args, **kwargs):
    return _impl._put_pending_remote_block(self, *args, **kwargs)

def _promote_quarantined_remote_block(self, *args, **kwargs):
    return _impl._promote_quarantined_remote_block(self, *args, **kwargs)

def _index_pending_candidate(self, *args, **kwargs):
    return _impl._index_pending_candidate(self, *args, **kwargs)

def _index_pending_missing_qc(self, *args, **kwargs):
    return _impl._index_pending_missing_qc(self, *args, **kwargs)

def _put_pending_missing_qc(self, *args, **kwargs):
    return _impl._put_pending_missing_qc(self, *args, **kwargs)

def _drop_pending_missing_qc_aliases(self, *args, **kwargs):
    return _impl._drop_pending_missing_qc_aliases(self, *args, **kwargs)

def _remove_pending_missing_qc(self, *args, **kwargs):
    return _impl._remove_pending_missing_qc(self, *args, **kwargs)

def _pending_missing_qc_json(self, *args, **kwargs):
    return _impl._pending_missing_qc_json(self, *args, **kwargs)

def _pending_missing_qc_entries(self, *args, **kwargs):
    return _impl._pending_missing_qc_entries(self, *args, **kwargs)

def _drop_pending_hash_aliases(self, *args, **kwargs):
    return _impl._drop_pending_hash_aliases(self, *args, **kwargs)

def _pending_block_identity_tuple(self, *args, **kwargs):
    return _impl._pending_block_identity_tuple(self, *args, **kwargs)

def _ordered_pending_block_ids(self, *args, **kwargs):
    return _impl._ordered_pending_block_ids(self, *args, **kwargs)

def _drop_pending_remote_artifacts(self, *args, **kwargs):
    return _impl._drop_pending_remote_artifacts(self, *args, **kwargs)

def _bft_speculative_blocks_map(self, *args, **kwargs):
    return _impl._bft_speculative_blocks_map(self, *args, **kwargs)

def _bft_pending_block_json(self, *args, **kwargs):
    return _impl._bft_pending_block_json(self, *args, **kwargs)

def _bft_pending_block_json_by_hash(self, *args, **kwargs):
    return _impl._bft_pending_block_json_by_hash(self, *args, **kwargs)

def _resolve_pending_block_identity(self, *args, **kwargs):
    return _impl._resolve_pending_block_identity(self, *args, **kwargs)

def _bft_pending_artifact_matches_current_epoch(self, *args, **kwargs):
    return _impl._bft_pending_artifact_matches_current_epoch(self, *args, **kwargs)

def _prune_pending_bft_artifacts(self, *args, **kwargs):
    return _impl._prune_pending_bft_artifacts(self, *args, **kwargs)

def _bft_block_is_applyable_finalized_descendant(self, *args, **kwargs):
    return _impl._bft_block_is_applyable_finalized_descendant(self, *args, **kwargs)

def _bft_parent_ready_for_apply(self, *args, **kwargs):
    return _impl._bft_parent_ready_for_apply(self, *args, **kwargs)

def bft_try_apply_pending_remote_blocks(self, *args, **kwargs):
    return _impl.bft_try_apply_pending_remote_blocks(self, *args, **kwargs)

def _bft_try_apply_pending_remote_blocks_followup(self, *args, **kwargs):
    return _impl._bft_try_apply_pending_remote_blocks_followup(self, *args, **kwargs)

def bft_cache_remote_block(self, *args, **kwargs):
    return _impl.bft_cache_remote_block(self, *args, **kwargs)

