from __future__ import annotations

import runpy
from pathlib import Path

from weall.runtime import bft_votecheck, block_builder, block_replay
from weall.runtime.bft_finality_bridge import finalized_target_from_justify_qc
from weall.runtime.executor import WeAllExecutor


_orig_seed = bft_votecheck._seed_spec_exec_to_parent
_orig_replay_schedule = block_replay.schedule_bft_finality_receipt
_orig_builder_schedule = block_builder.schedule_bft_finality_receipt


def _canon_finalized(state):
    raw = state.get("finalized") if isinstance(state, dict) else None
    return dict(raw) if isinstance(raw, dict) else None


def _queue_ids(state):
    root = state.get("system_queue") if isinstance(state, dict) else None
    if not isinstance(root, list):
        return []
    return [
        str(item.get("queue_id") or "")
        for item in root
        if isinstance(item, dict) and str(item.get("queue_id") or "")
    ]


def _block_path(state, block_id, limit=8):
    blocks = state.get("blocks") if isinstance(state, dict) else None
    if not isinstance(blocks, dict):
        return []
    out = []
    cur = str(block_id or "")
    seen = set()
    while cur and cur not in seen and len(out) < limit:
        seen.add(cur)
        rec = blocks.get(cur)
        out.append(
            {
                "id": cur,
                "height": int(rec.get("height") or 0) if isinstance(rec, dict) else None,
                "prev": str(rec.get("prev_block_id") or "") if isinstance(rec, dict) else None,
            }
        )
        if not isinstance(rec, dict):
            break
        cur = str(rec.get("prev_block_id") or "")
    return out


def _traced_seed(self, clone, parent_id):
    result = _orig_seed(self, clone, parent_id)
    print(
        "P0FINALITY_SEED",
        {
            "node": str(getattr(self, "node_id", "") or ""),
            "parent": str(parent_id or ""),
            "result": bool(result),
            "height": int(clone.state.get("height") or 0),
            "tip": str(clone.state.get("tip") or ""),
            "canonical_finalized": _canon_finalized(clone.state),
            "bft_finalized": str(getattr(clone._bft, "finalized_block_id", "") or ""),
            "queue_ids": _queue_ids(clone.state),
            "path": _block_path(clone.state, parent_id),
        },
        flush=True,
    )
    return result


def _trace_schedule(label, original, state, *args, **kwargs):
    justify = kwargs.get("justify_qc")
    target = None
    target_error = ""
    try:
        target = finalized_target_from_justify_qc(state, justify)
    except Exception as exc:
        target_error = f"{type(exc).__name__}:{exc}"
    before = {
        "height": int(state.get("height") or 0),
        "tip": str(state.get("tip") or ""),
        "canonical_finalized": _canon_finalized(state),
        "queue_ids": _queue_ids(state),
        "target": target,
        "target_error": target_error,
        "qc_block": str(justify.get("block_id") or "") if isinstance(justify, dict) else "",
        "qc_parent": str(justify.get("parent_id") or "") if isinstance(justify, dict) else "",
        "path": _block_path(
            state,
            str(justify.get("block_id") or "") if isinstance(justify, dict) else "",
        ),
    }
    qid = original(state, *args, **kwargs)
    print(
        "P0FINALITY_SCHEDULE",
        {
            "surface": label,
            "before": before,
            "qid": str(qid or ""),
            "after_finalized": _canon_finalized(state),
            "after_queue_ids": _queue_ids(state),
        },
        flush=True,
    )
    return qid


def _replay_schedule(state, *args, **kwargs):
    return _trace_schedule("replay", _orig_replay_schedule, state, *args, **kwargs)


def _builder_schedule(state, *args, **kwargs):
    return _trace_schedule("builder", _orig_builder_schedule, state, *args, **kwargs)


def _borrow_spec_exec_slot(self):
    slot = self._acquire_spec_exec_slot()
    return self._reset_spec_exec_slot(slot), slot


bft_votecheck._seed_spec_exec_to_parent = _traced_seed
block_replay.schedule_bft_finality_receipt = _replay_schedule
block_builder.schedule_bft_finality_receipt = _builder_schedule
if not hasattr(WeAllExecutor, "_borrow_spec_exec_slot"):
    WeAllExecutor._borrow_spec_exec_slot = _borrow_spec_exec_slot

runpy.run_path(
    str(Path(__file__).with_name("tmp-p0-03-follower-diagnostic.py")),
    run_name="__main__",
)
