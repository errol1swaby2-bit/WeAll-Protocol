from __future__ import annotations

from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_restart_api_and_producer_recovery(tmp_path: Path) -> None:
    """
    Restart safety smoke for the persisted executor database.

    Validates:
      - blocks persist across restart
      - tip/height survive restart
      - new txs can still be submitted and confirmed after restart
      - tx status for old and new txs remains correct
    """
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    ex1 = WeAllExecutor(
        db_path=db_path,
        node_id="@alice",
        chain_id="restart-recovery",
        tx_index_path=tx_index_path,
    )

    submitted_tx_ids: list[str] = []

    for i in range(3):
        sub = ex1.submit_tx(
            {
                "tx_type": "ACCOUNT_REGISTER",
                "signer": f"@user{i}",
                "nonce": 1,
                "payload": {"pubkey": f"k:{i}"},
            }
        )
        assert sub["ok"] is True
        submitted_tx_ids.append(str(sub["tx_id"]))

        meta = ex1.produce_block(max_txs=1)
        assert meta.ok is True

    st1 = ex1.read_state()
    h1 = int(st1["height"])
    tip1 = str(st1["tip"])

    assert h1 == 3
    assert tip1

    for tx_id in submitted_tx_ids:
        status = ex1.get_tx_status(tx_id)
        assert status["ok"] is True
        assert status["status"] == "confirmed"

    # "Restart" by constructing a new executor against the same db.
    ex2 = WeAllExecutor(
        db_path=db_path,
        node_id="@alice",
        chain_id="restart-recovery",
        tx_index_path=tx_index_path,
    )

    st2 = ex2.read_state()
    assert int(st2["height"]) == h1
    assert str(st2["tip"]) == tip1

    for tx_id in submitted_tx_ids:
        status = ex2.get_tx_status(tx_id)
        assert status["ok"] is True
        assert status["status"] == "confirmed"

    # Ensure the restarted executor can continue making progress.
    sub4 = ex2.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@user3",
            "nonce": 1,
            "payload": {"pubkey": "k:3"},
        }
    )
    assert sub4["ok"] is True

    pending = ex2.get_tx_status(str(sub4["tx_id"]))
    assert pending["ok"] is True
    assert pending["status"] == "pending"

    meta4 = ex2.produce_block(max_txs=1)
    assert meta4.ok is True
    assert meta4.height == 4

    confirmed = ex2.get_tx_status(str(sub4["tx_id"]))
    assert confirmed["ok"] is True
    assert confirmed["status"] == "confirmed"
    assert int(confirmed["height"]) == 4

    st3 = ex2.read_state()
    assert int(st3["height"]) == 4
