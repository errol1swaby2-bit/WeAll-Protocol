#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    path = repo_root / "src" / "weall" / "runtime" / "fault_injection.py"
    text = path.read_text(encoding="utf-8")

    old_helper = """def _build_committed_block(ex: WeAllExecutor, *, force_ts_ms: int) -> Json:
    blk, st2, applied_ids, invalid_ids, err = ex.build_block_candidate(
        max_txs=0, allow_empty=True, force_ts_ms=force_ts_ms
    )
    if err:
        raise RuntimeError(f"build_block_candidate failed: {err}")
    if not isinstance(blk, dict) or not isinstance(st2, dict):
        raise RuntimeError("build_block_candidate returned malformed result")
    meta = ex.commit_block_candidate(
        block=blk, new_state=st2, applied_ids=applied_ids, invalid_ids=invalid_ids
    )
    if meta.ok is not True:
        raise RuntimeError(f"commit_block_candidate failed: {meta.error}")
    return blk
"""

    new_helper = """def _build_committed_block(ex: WeAllExecutor, *, force_ts_ms: int) -> Json:
    blk, st2, applied_ids, invalid_ids, err = ex.build_block_candidate(
        max_txs=0, allow_empty=True, force_ts_ms=force_ts_ms
    )
    if err:
        raise RuntimeError(f"build_block_candidate failed: {err}")
    if not isinstance(blk, dict) or not isinstance(st2, dict):
        raise RuntimeError("build_block_candidate returned malformed result")
    meta = ex.commit_block_candidate(
        block=blk, new_state=st2, applied_ids=applied_ids, invalid_ids=invalid_ids
    )
    if meta.ok is not True:
        raise RuntimeError(f"commit_block_candidate failed: {meta.error}")
    return blk


def _next_force_ts_ms(ex: WeAllExecutor, *, view: int) -> int:
    st = ex.read_state()
    chain_floor = int(st.get("tip_ts_ms") or 0)
    # Keep timestamps deterministic for the harness while always staying strictly
    # above the current chain-time floor so larger / longer topologies do not trip
    # invalid_block_ts:before_chain_floor during synthetic block construction.
    return max(int(view * 1000), chain_floor + 1)
"""

    if old_helper not in text and "def _next_force_ts_ms(" not in text:
        raise SystemExit("expected _build_committed_block helper block not found")

    if old_helper in text:
        text = text.replace(old_helper, new_helper, 1)

    old_call = "            blk = dict(_build_committed_block(leader, force_ts_ms=int(view * 1000)))\n"
    new_call = (
        "            blk = dict(\n"
        "                _build_committed_block(leader, force_ts_ms=_next_force_ts_ms(leader, view=view))\n"
        "            )\n"
    )

    if old_call not in text and "_next_force_ts_ms(leader, view=view)" not in text:
        raise SystemExit("expected force_ts_ms call site not found")

    if old_call in text:
        text = text.replace(old_call, new_call, 1)

    path.write_text(text, encoding="utf-8")
    print(f"patched {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
