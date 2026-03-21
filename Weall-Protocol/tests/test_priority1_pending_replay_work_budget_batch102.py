from __future__ import annotations

from collections import OrderedDict
from types import MethodType, SimpleNamespace

from weall.runtime.executor import ExecutorMeta, WeAllExecutor


def _block(block_id: str, prev_block_id: str, height: int) -> dict:
    return {
        'chain_id': 'batch102',
        'block_id': block_id,
        'block_hash': f'{block_id}-h',
        'prev_block_id': prev_block_id,
        'height': height,
    }


def _make_executor() -> WeAllExecutor:
    ex = WeAllExecutor.__new__(WeAllExecutor)
    ex.state = {'tip': 'A'}
    ex._bft = SimpleNamespace(finalized_block_id='')
    ex._pending_remote_blocks = OrderedDict()
    ex._pending_remote_block_ids_by_hash = {}
    ex._quarantined_remote_blocks = OrderedDict()
    ex._quarantined_remote_block_ids_by_hash = {}
    ex._pending_candidates = OrderedDict()
    ex._pending_candidate_ids_by_hash = {}
    ex._pending_missing_qcs = OrderedDict()
    ex._pending_missing_qcs_by_hash = {}
    ex._pending_replay_cursor = ''
    ex._max_pending_replay_scans_per_call = 3
    ex._max_pending_replay_applies_per_call = 1
    ex._prune_pending_bft_artifacts = MethodType(lambda self: None, ex)
    ex._bft_phase_allows_artifact_processing = MethodType(lambda self: True, ex)
    ex._has_local_block = MethodType(lambda self, bid: False, ex)
    ex._block_height_hint = MethodType(lambda self, blk: int(blk.get('height') or 0), ex)
    ex._bft_pending_block_json = MethodType(
        lambda self, bid: dict(self._pending_remote_blocks.get(str(bid), {}))
        if str(bid) in self._pending_remote_blocks
        else None,
        ex,
    )
    ex._bft_block_is_applyable_finalized_descendant = MethodType(lambda self, blk, finalized: True, ex)
    ex._pending_missing_qc_json = MethodType(
        lambda self, *, block_id='', block_hash='': {
            'chain_id': 'batch102',
            'view': 1,
            'block_id': str(block_id or '').strip() or 'X',
            'block_hash': str(block_hash or '').strip() or 'X-h',
            'parent_id': '',
            'votes': [],
        },
        ex,
    )
    ex._drops = []
    ex._drop_pending_candidate_artifacts = MethodType(
        lambda self, bid: (self._drops.append(str(bid)), self._pending_remote_blocks.pop(str(bid), None)),
        ex,
    )
    ex._applied = []
    ex.apply_block = MethodType(
        lambda self, blk: (self._applied.append(str(blk.get('block_id') or '')), ExecutorMeta(ok=True, block_id=str(blk.get('block_id') or '')))[1],
        ex,
    )
    return ex


def test_pending_replay_scan_budget_caps_work_per_call_batch102(monkeypatch) -> None:
    monkeypatch.setenv('WEALL_MODE', 'dev')
    ex = _make_executor()
    ex._max_pending_replay_scans_per_call = 3
    for idx in range(6):
        bid = chr(ord('B') + idx)
        prev = 'A' if idx == 0 else chr(ord('B') + idx - 1)
        ex._pending_remote_blocks[bid] = _block(bid, prev, idx + 2)

    calls: list[str] = []

    def _parent_ready(self, blk: dict) -> bool:
        calls.append(str(blk.get('block_id') or ''))
        return False

    ex._bft_parent_ready_for_apply = MethodType(_parent_ready, ex)

    metas = ex.bft_try_apply_pending_remote_blocks()

    assert metas == []
    assert calls == ['B', 'C', 'D']
    assert ex._pending_replay_cursor == 'D'


def test_pending_replay_cursor_rotates_after_budget_exhaustion_batch102(monkeypatch) -> None:
    monkeypatch.setenv('WEALL_MODE', 'dev')
    ex = _make_executor()
    ex._max_pending_replay_scans_per_call = 2
    ex._max_pending_replay_applies_per_call = 1
    ex._pending_remote_blocks['B'] = _block('B', 'A', 2)
    ex._pending_remote_blocks['C'] = _block('C', 'B', 3)
    ex._pending_remote_blocks['D'] = _block('D', 'A', 4)
    ex._pending_remote_blocks['E'] = _block('E', 'D', 5)

    seen: list[str] = []

    def _parent_ready(self, blk: dict) -> bool:
        bid = str(blk.get('block_id') or '')
        seen.append(bid)
        return bid == 'D'

    ex._bft_parent_ready_for_apply = MethodType(_parent_ready, ex)

    first = ex.bft_try_apply_pending_remote_blocks()
    second = ex.bft_try_apply_pending_remote_blocks()

    assert first == []
    assert len(second) == 1
    assert second[0].block_id == 'D'
    assert ex._applied == ['D']
    assert 'D' in ex._drops
    assert seen == ['B', 'C', 'D']
