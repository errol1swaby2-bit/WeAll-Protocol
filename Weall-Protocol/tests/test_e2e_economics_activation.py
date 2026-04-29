# tests/test_e2e_economics_activation.py
from __future__ import annotations

from pathlib import Path

import pytest

from weall.runtime.executor import WeAllExecutor


def _repo_root():
    import pathlib

    return pathlib.Path(__file__).resolve().parents[1]


def test_blocks_are_append_only_and_height_monotonic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Economics activation is handled elsewhere; for SQLite migration we preserve core chain invariants."""
    monkeypatch.setenv("WEALL_UNSAFE_DEV", "1")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")

    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    ex = WeAllExecutor(
        db_path=db_path, node_id="@alice", chain_id="monotonic", tx_index_path=tx_index_path
    )

    for i in range(5):
        assert (
            ex.submit_tx(
                {
                    "tx_type": "ACCOUNT_REGISTER",
                    "signer": f"@user{i:03d}",
                    "nonce": 1,
                    "payload": {"pubkey": f"k:user{i:03d}"},
                }
            )["ok"]
            is True
        )

    heights = []
    for _ in range(5):
        meta = ex.produce_block(max_txs=1)
        assert meta.ok is True
        heights.append(meta.height)

    assert heights == sorted(heights)
    assert len(set(heights)) == len(heights)
