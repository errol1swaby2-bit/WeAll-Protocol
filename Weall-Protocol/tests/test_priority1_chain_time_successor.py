from __future__ import annotations

from pathlib import Path

import pytest

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _make_executor(tmp_path: Path, *, node_id: str, chain_id: str) -> WeAllExecutor:
    tx_index_path = str(_repo_root() / "generated" / "tx_index.json")
    db_path = str(tmp_path / f"{node_id.strip('@')}.db")
    return WeAllExecutor(
        db_path=db_path, node_id=node_id, chain_id=chain_id, tx_index_path=tx_index_path
    )


def test_build_block_candidate_ignores_wall_clock_for_proposal_timestamp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WEALL_UNSAFE_DEV", "1")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")

    ex = _make_executor(tmp_path, node_id="@leader", chain_id="chain-time-successor")

    monkeypatch.setattr("weall.runtime.executor._now_ms", lambda: 9_999_999_999_999)
    blk1, _st1, _applied1, _invalid1, err1 = ex.build_block_candidate(allow_empty=True)
    assert err1 == ""
    assert blk1 is not None
    assert int(blk1.get("block_ts_ms") or 0) == 1

    monkeypatch.setattr("weall.runtime.executor._now_ms", lambda: 1)
    blk2, _st2, _applied2, _invalid2, err2 = ex.build_block_candidate(allow_empty=True)
    assert err2 == ""
    assert blk2 is not None
    assert int(blk2.get("block_ts_ms") or 0) == 1


def test_produced_block_timestamp_advances_by_one_over_chain_floor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WEALL_UNSAFE_DEV", "1")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")

    ex = _make_executor(tmp_path, node_id="@leader", chain_id="chain-time-successor-2")

    monkeypatch.setattr("weall.runtime.executor._now_ms", lambda: 500_000_000_000)
    blk1, st1, _applied1, _invalid1, err1 = ex.build_block_candidate(allow_empty=True)
    assert err1 == ""
    assert blk1 is not None
    assert st1 is not None
    assert int(blk1.get("block_ts_ms") or 0) == 1

    meta1 = ex.commit_block_candidate(block=blk1, new_state=st1, applied_ids=[], invalid_ids=[])
    assert meta1.ok is True

    monkeypatch.setattr("weall.runtime.executor._now_ms", lambda: 42)
    blk2, _st2, _applied2, _invalid2, err2 = ex.build_block_candidate(allow_empty=True)
    assert err2 == ""
    assert blk2 is not None
    assert int(blk2.get("block_ts_ms") or 0) == 2


def test_bft_diagnostics_surface_next_chain_time_successor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WEALL_UNSAFE_DEV", "1")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")

    ex = _make_executor(tmp_path, node_id="@leader", chain_id="chain-time-successor-3")
    diag0 = ex.bft_diagnostics()
    assert diag0["timestamp_rule"] == "chain_time_successor_only"
    assert int(diag0["proposed_next_ts_ms"]) == 1

    blk1, st1, _applied1, _invalid1, err1 = ex.build_block_candidate(
        allow_empty=True, force_ts_ms=5_000
    )
    assert err1 == ""
    assert blk1 is not None
    assert st1 is not None
    meta1 = ex.commit_block_candidate(block=blk1, new_state=st1, applied_ids=[], invalid_ids=[])
    assert meta1.ok is True

    diag1 = ex.bft_diagnostics()
    assert diag1["timestamp_rule"] == "chain_time_successor_only"
    assert int(diag1["chain_time_floor_ms"]) == 5_000
    assert int(diag1["proposed_next_ts_ms"]) == 5_001
