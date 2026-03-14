from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_pending_tx_survives_failed_commit(tmp_path: Path) -> None:
    """
    If commit fails after a tx is selected for block production, that tx must
    remain pending and not disappear from mempool.
    """
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    ex = WeAllExecutor(
        db_path=db_path,
        node_id="@alice",
        chain_id="pending-survives-failed-commit",
        tx_index_path=tx_index_path,
    )

    sub = ex.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@user1",
            "nonce": 1,
            "payload": {"pubkey": "k:user1"},
        }
    )
    assert sub["ok"] is True
    tx_id = sub["tx_id"]

    original_write_tx = ex._db.write_tx

    @contextmanager
    def broken_write_tx():
        with original_write_tx() as con:
            raise RuntimeError("forced_commit_failure_for_test")
            yield con

    ex._db.write_tx = broken_write_tx  # type: ignore[assignment]
    try:
        meta = ex.produce_block(max_txs=1)
    finally:
        ex._db.write_tx = original_write_tx  # type: ignore[assignment]

    assert meta.ok is False
    assert str(meta.error) == "commit_failed:RuntimeError"

    mp = ex.read_mempool()
    ids = {item["tx_id"] for item in mp}
    assert tx_id in ids

    st = ex.read_state()
    assert int(st["height"]) == 0
