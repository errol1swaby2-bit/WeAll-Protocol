from __future__ import annotations

from pathlib import Path

import pytest

from weall.runtime.executor import ExecutorError, WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_chain_id_fail_closed_api(tmp_path: Path) -> None:
    """
    Chain mismatch must fail closed.

    Validates:
      - a DB initialized under one chain_id cannot be reopened under another
      - previously committed state remains intact after the failed reopen
    """
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    ex1 = WeAllExecutor(
        db_path=db_path,
        node_id="@alice",
        chain_id="chain-A",
        tx_index_path=tx_index_path,
    )

    sub = ex1.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@chaina",
            "nonce": 1,
            "payload": {"pubkey": "k:chaina"},
        }
    )
    assert sub["ok"] is True
    tx_id = str(sub["tx_id"])

    meta = ex1.produce_block(max_txs=1)
    assert meta.ok is True
    assert meta.height == 1

    st1 = ex1.read_state()
    assert int(st1["height"]) == 1
    assert str(st1["tip"])

    # Reopening same DB under a different chain_id must fail closed.
    with pytest.raises(ExecutorError):
        WeAllExecutor(
            db_path=db_path,
            node_id="@alice",
            chain_id="chain-B",
            tx_index_path=tx_index_path,
        )

    # Original chain_id must still be readable and intact.
    ex2 = WeAllExecutor(
        db_path=db_path,
        node_id="@alice",
        chain_id="chain-A",
        tx_index_path=tx_index_path,
    )

    st2 = ex2.read_state()
    assert int(st2["height"]) == 1
    assert str(st2["tip"]) == str(st1["tip"])

    status = ex2.get_tx_status(tx_id)
    assert status["ok"] is True
    assert status["status"] == "confirmed"
    assert int(status["height"]) == 1
