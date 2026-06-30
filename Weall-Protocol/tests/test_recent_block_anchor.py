from __future__ import annotations

import copy
from pathlib import Path

from weall.runtime.block_hash import compute_recent_block_anchor, recent_block_ids_from_state
from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _make_executor(tmp_path: Path, name: str, *, chain_id: str = "anchor-chain") -> WeAllExecutor:
    return WeAllExecutor(
        db_path=str(tmp_path / f"{name}.db"),
        node_id=f"@{name}",
        chain_id=chain_id,
        tx_index_path=str(_repo_root() / "generated" / "tx_index.json"),
    )


def _build_empty_block(ex: WeAllExecutor, *, ts_ms: int) -> tuple[dict, dict, list[str], list[str]]:
    block, new_state, applied_ids, invalid_ids, err = ex.build_block_candidate(
        max_txs=0,
        allow_empty=True,
        force_ts_ms=ts_ms,
    )
    assert err == ""
    assert isinstance(block, dict)
    assert isinstance(new_state, dict)
    return block, new_state, applied_ids, invalid_ids


def _commit_empty_block(ex: WeAllExecutor, *, ts_ms: int) -> dict:
    block, new_state, applied_ids, invalid_ids = _build_empty_block(ex, ts_ms=ts_ms)
    meta = ex.commit_block_candidate(
        block=block,
        new_state=new_state,
        applied_ids=applied_ids,
        invalid_ids=invalid_ids,
    )
    assert meta.ok is True
    return block


def _anchor(block: dict) -> str:
    header = block.get("header")
    assert isinstance(header, dict)
    return str(header.get("recent_block_anchor") or "")


def test_recent_block_anchor_startup_and_window_are_deterministic(tmp_path: Path) -> None:
    ex = _make_executor(tmp_path, "leader")

    block1 = _commit_empty_block(ex, ts_ms=1_000)
    block2 = _commit_empty_block(ex, ts_ms=2_000)
    block3 = _commit_empty_block(ex, ts_ms=3_000)
    block4 = _commit_empty_block(ex, ts_ms=4_000)

    id1 = str(block1["block_id"])
    id2 = str(block2["block_id"])
    id3 = str(block3["block_id"])

    assert _anchor(block1) == compute_recent_block_anchor(block_ids=[])
    assert _anchor(block2) == compute_recent_block_anchor(block_ids=[id1])
    assert _anchor(block3) == compute_recent_block_anchor(block_ids=[id2, id1])
    assert _anchor(block4) == compute_recent_block_anchor(block_ids=[id3, id2, id1])

    assert recent_block_ids_from_state(state=ex.read_state()) == [
        str(block4["block_id"]),
        id3,
        id2,
    ]
    assert {str(b["header"]["chain_id"]) for b in (block1, block2, block3, block4)} == {
        "anchor-chain"
    }


def test_recent_block_anchor_replay_accepts_correct_and_rejects_wrong_anchor(
    tmp_path: Path,
) -> None:
    leader = _make_executor(tmp_path, "leader", chain_id="anchor-rx")
    follower = _make_executor(tmp_path, "follower", chain_id="anchor-rx")

    block1 = _commit_empty_block(leader, ts_ms=1_000)
    block2 = _commit_empty_block(leader, ts_ms=2_000)

    ok1 = follower.apply_block(copy.deepcopy(block1))
    assert ok1.ok is True

    wrong = copy.deepcopy(block2)
    wrong_header = dict(wrong.get("header") or {})
    wrong_header["recent_block_anchor"] = compute_recent_block_anchor(
        block_ids=["not-the-canonical-parent"]
    )
    wrong["header"] = wrong_header

    bad = follower.apply_block(wrong)
    assert bad.ok is False
    assert bad.error == "bad_block:recent_block_anchor_mismatch"
    assert int(follower.read_state().get("height") or 0) == 1

    ok2 = follower.apply_block(copy.deepcopy(block2))
    assert ok2.ok is True
    assert int(follower.read_state().get("height") or 0) == 2


def test_recent_block_anchor_distinguishes_forked_recent_history(tmp_path: Path) -> None:
    base = _make_executor(tmp_path, "base", chain_id="anchor-fork")
    block1 = _commit_empty_block(base, ts_ms=1_000)
    block2 = _commit_empty_block(base, ts_ms=2_000)

    id1 = str(block1["block_id"])
    id2 = str(block2["block_id"])
    fork_a = compute_recent_block_anchor(block_ids=["fork-a", id2, id1])
    fork_b = compute_recent_block_anchor(block_ids=["fork-b", id2, id1])

    assert fork_a != fork_b
    assert compute_recent_block_anchor(block_ids=[id2, id1]) == _anchor(
        _build_empty_block(base, ts_ms=3_000)[0]
    )
