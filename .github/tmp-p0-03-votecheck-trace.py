from __future__ import annotations

import runpy
from pathlib import Path

from weall.runtime import bft_votecheck
from weall.runtime.executor import WeAllExecutor


_orig_seed = bft_votecheck._seed_spec_exec_to_parent
_orig_apply = WeAllExecutor.apply_block


def _traced_seed(self, clone, parent_id):
    try:
        result = _orig_seed(self, clone, parent_id)
        print(
            "P0DIAG_SEED_RESULT",
            {
                "node": str(getattr(self, "node_id", "") or ""),
                "parent_id": str(parent_id or ""),
                "result": bool(result),
                "clone_height": int(clone.state.get("height") or 0),
                "clone_tip": str(clone.state.get("tip") or ""),
            },
            flush=True,
        )
        return result
    except Exception as exc:
        print(
            "P0DIAG_SEED_EXCEPTION",
            {
                "node": str(getattr(self, "node_id", "") or ""),
                "parent_id": str(parent_id or ""),
                "type": type(exc).__name__,
                "error": repr(exc),
            },
            flush=True,
        )
        raise


def _traced_apply(self, block):
    meta = _orig_apply(self, block)
    if meta is None or not bool(getattr(meta, "ok", False)):
        print(
            "P0DIAG_APPLY_FAILURE",
            {
                "node": str(getattr(self, "node_id", "") or ""),
                "block_id": str(block.get("block_id") or "") if isinstance(block, dict) else "",
                "height": int(block.get("height") or 0) if isinstance(block, dict) else 0,
                "error": "<none>" if meta is None else str(getattr(meta, "error", "") or ""),
                "state_height": int(getattr(self, "state", {}).get("height") or 0),
                "state_tip": str(getattr(self, "state", {}).get("tip") or ""),
            },
            flush=True,
        )
    return meta


bft_votecheck._seed_spec_exec_to_parent = _traced_seed
WeAllExecutor.apply_block = _traced_apply

runpy.run_path(
    str(Path(__file__).with_name("tmp-p0-03-follower-diagnostic.py")),
    run_name="__main__",
)
