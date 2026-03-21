from types import MethodType

from weall.runtime.executor import WeAllExecutor


def _make_executor() -> WeAllExecutor:
    ex = WeAllExecutor.__new__(WeAllExecutor)
    ex._max_pending_remote_blocks = 2
    ex._max_quarantined_remote_blocks = 2
    ex._max_pending_missing_qcs = 2
    ex._pending_remote_blocks = {}
    ex._pending_remote_block_ids_by_hash = {}
    ex._quarantined_remote_blocks = {}
    ex._quarantined_remote_block_ids_by_hash = {}
    ex._pending_missing_qcs = {}
    ex._pending_missing_qcs_by_hash = {}
    ex._pending_candidates = {}
    ex._pending_candidate_ids_by_hash = {}
    ex._persisted = []
    ex._deleted = []
    ex._persist_pending_bft_artifact = MethodType(
        lambda self, *, kind, block_id, payload: self._persisted.append((kind, str(block_id))), ex
    )
    ex._delete_pending_bft_artifact = MethodType(
        lambda self, *, kind, block_id: self._deleted.append((kind, str(block_id))), ex
    )
    return ex


def _block(block_id: str) -> dict:
    prev = "" if block_id == "A" else chr(ord(block_id) - 1)
    return {
        "chain_id": "batch101",
        "block_id": block_id,
        "block_hash": f"{block_id}-h",
        "prev_block_id": prev,
        "height": ord(block_id) - 64,
    }


def _qc(block_id: str) -> dict:
    prev = "" if block_id == "A" else chr(ord(block_id) - 1)
    return {
        "chain_id": "batch101",
        "view": ord(block_id) - 60,
        "block_id": block_id,
        "block_hash": f"{block_id}-h",
        "parent_id": prev,
        "votes": [],
    }


def test_pending_remote_block_cap_evicts_oldest_and_cleans_aliases_batch101() -> None:
    ex = _make_executor()

    ex._put_pending_remote_block(block_id="A", block=_block("A"))
    ex._put_pending_remote_block(block_id="B", block=_block("B"))
    ex._put_pending_remote_block(block_id="C", block=_block("C"))

    assert list(ex._pending_remote_blocks.keys()) == ["B", "C"]
    assert ex._pending_remote_block_ids_by_hash.get("A-h") is None
    assert ex._pending_remote_block_ids_by_hash.get("B-h") == "B"
    assert ex._pending_remote_block_ids_by_hash.get("C-h") == "C"
    assert ("pending_remote_block", "A") in ex._deleted


def test_pending_missing_qc_cap_evicts_oldest_and_cleans_hash_aliases_batch101() -> None:
    ex = _make_executor()

    ex._put_pending_missing_qc(_qc("A"))
    ex._put_pending_missing_qc(_qc("B"))
    ex._put_pending_missing_qc(_qc("C"))

    assert list(ex._pending_missing_qcs.keys()) == ["B", "C"]
    assert ex._pending_missing_qcs_by_hash.get("A-h") is None
    assert ex._pending_missing_qcs_by_hash.get("B-h", {}).get("block_id") == "B"
    assert ex._pending_missing_qcs_by_hash.get("C-h", {}).get("block_id") == "C"
    assert ("pending_missing_qc", "A") in ex._deleted


def test_quarantine_cap_evicts_oldest_and_preserves_newest_batch101() -> None:
    ex = _make_executor()

    ex._quarantine_remote_block(_block("A"))
    ex._quarantine_remote_block(_block("B"))
    ex._quarantine_remote_block(_block("C"))

    assert list(ex._quarantined_remote_blocks.keys()) == ["B", "C"]
    assert ex._quarantined_remote_block_ids_by_hash.get("A-h") is None
    assert ex._quarantined_remote_block_ids_by_hash.get("B-h") == "B"
    assert ex._quarantined_remote_block_ids_by_hash.get("C-h") == "C"
