from __future__ import annotations

import time
from pathlib import Path

import pytest

from weall.runtime.executor import WeAllExecutor


def _canon_path() -> str:
    repo_root = Path(__file__).resolve().parents[1]
    return str(repo_root / "generated" / "tx_index.json")


def test_pending_remote_blocks_is_bounded_strict(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_UNSAFE_DEV", "1")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")
    monkeypatch.setenv("WEALL_MAX_PENDING_REMOTE_BLOCKS", "25")

    ex = WeAllExecutor(
        db_path=str(tmp_path / "db.sqlite"),
        node_id="n1",
        chain_id="test-chain",
        tx_index_path=_canon_path(),
    )

    for i in range(250):
        proposal = {
            "block_id": f"b{i}",
            "header": {
                "chain_id": "test-chain",
                "height": i + 1,
                "prev_block_hash": "00" * 32,
                "block_ts_ms": 1_700_000_000_000 + i,
                "tx_ids": [],
                "receipts_root": "",
            },
        }
        ex.bft_on_proposal(proposal)

    assert len(ex._pending_remote_blocks) <= 25  # type: ignore[attr-defined]


def test_pending_candidates_is_bounded_strict(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_UNSAFE_DEV", "1")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")
    monkeypatch.setenv("WEALL_MAX_PENDING_CANDIDATES", "10")

    ex = WeAllExecutor(
        db_path=str(tmp_path / "db.sqlite"),
        node_id="n1",
        chain_id="test-chain",
        tx_index_path=_canon_path(),
    )

    # Produce multiple candidates; allow_empty=True is used internally.
    for _ in range(80):
        ex.bft_leader_propose(max_txs=0)
        time.sleep(0.001)

    assert len(ex._pending_candidates) <= 10  # type: ignore[attr-defined]
