from __future__ import annotations

from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_invalid_tx_is_not_exposed_as_pending(tmp_path: Path) -> None:
    """
    If submit_tx rejects a tx, it must not appear later as pending in tx-status.
    """
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")

    ex = WeAllExecutor(
        db_path=str(tmp_path / "weall.db"),
        node_id="@alice",
        chain_id="tx-invalid-pending",
        tx_index_path=tx_index_path,
    )

    bad = ex.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            # signer intentionally omitted
            "nonce": 1,
            "payload": {"pubkey": "k:oops"},
        }
    )
    assert bad["ok"] is False

    tx_id = bad.get("tx_id")
    if isinstance(tx_id, str) and tx_id:
        status = ex.get_tx_status(tx_id)
        assert status["status"] == "unknown"
    else:
        status = ex.get_tx_status("tx:definitely_missing")
        assert status["status"] == "unknown"
