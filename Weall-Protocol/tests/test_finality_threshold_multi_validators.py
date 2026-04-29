# tests/test_finality_threshold_multi_validators.py
from __future__ import annotations

from pathlib import Path

import pytest

from weall.runtime.executor import WeAllExecutor


def _repo_root():
    import pathlib

    return pathlib.Path(__file__).resolve().parents[1]


def test_multiple_signers_can_apply_in_one_chain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Basic multi-signer apply invariant."""
    monkeypatch.setenv("WEALL_UNSAFE_DEV", "1")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")

    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    ex = WeAllExecutor(
        db_path=db_path, node_id="@alice", chain_id="multi-signer", tx_index_path=tx_index_path
    )

    for i in range(3):
        assert (
            ex.submit_tx(
                {
                    "tx_type": "ACCOUNT_REGISTER",
                    "signer": f"@user{i:03d}",
                    "nonce": 1,
                    "payload": {"pubkey": f"k:u{i:03d}"},
                }
            )["ok"]
            is True
        )

    for _ in range(3):
        assert ex.produce_block(max_txs=1).ok is True

    st = ex.read_state()
    assert int(st.get("height", 0)) == 3
