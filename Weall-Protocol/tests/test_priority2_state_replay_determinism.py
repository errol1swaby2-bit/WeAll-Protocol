from __future__ import annotations

import copy
from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _make_executor(tmp_path: Path, name: str) -> WeAllExecutor:
    return WeAllExecutor(
        db_path=str(tmp_path / f"{name}.db"),
        node_id=name,
        chain_id="batch109-replay",
        tx_index_path=str(_repo_root() / "generated" / "tx_index.json"),
    )


def _run_chain(tmp_path: Path, name: str) -> dict:
    ex = _make_executor(tmp_path, name)
    for ts in (1000, 2000, 3000):
        blk, st2, applied_ids, invalid_ids, err = ex.build_block_candidate(
            max_txs=0, allow_empty=True, force_ts_ms=ts
        )
        assert err == ""
        meta = ex.commit_block_candidate(
            block=blk,
            new_state=st2,
            applied_ids=applied_ids,
            invalid_ids=invalid_ids,
        )
        assert meta.ok is True
    return copy.deepcopy(ex.read_state())


def test_replay_determinism_batch109(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "testnet")
    state1 = _run_chain(tmp_path, "node-a")
    state2 = _run_chain(tmp_path, "node-b")
    assert state1 == state2
