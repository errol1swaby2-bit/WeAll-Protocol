from __future__ import annotations

import json
from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_tx_status_persistence(tmp_path: Path) -> None:
    """
    Verify tx lifecycle and persistence.

    Flow:
      submit tx -> pending
      produce block -> confirmed
      restart executor -> still confirmed
    """

    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    ex = WeAllExecutor(
        db_path=db_path,
        node_id="@alice",
        chain_id="tx-status-test",
        tx_index_path=tx_index_path,
    )

    submit = ex.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@alice",
            "nonce": 1,
            "payload": {"pubkey": "k:alice"},
        }
    )

    assert submit["ok"] is True
    tx_id = submit["tx_id"]

    # pending before block
    status = ex.get_tx_status(tx_id)
    assert status["status"] == "pending"

    meta = ex.produce_block(max_txs=1)
    assert meta.ok is True

    status = ex.get_tx_status(tx_id)
    assert status["status"] == "confirmed"
    assert status["height"] == 1

    # restart executor
    ex2 = WeAllExecutor(
        db_path=db_path,
        node_id="@alice",
        chain_id="tx-status-test",
        tx_index_path=tx_index_path,
    )

    status2 = ex2.get_tx_status(tx_id)

    assert status2["status"] == "confirmed"
    assert status2["height"] == 1


def test_tx_status_unknown(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")

    ex = WeAllExecutor(
        db_path=str(tmp_path / "weall.db"),
        node_id="@alice",
        chain_id="tx-status-test",
        tx_index_path=tx_index_path,
    )

    status = ex.get_tx_status("tx:does_not_exist")

    assert status["status"] == "unknown"
