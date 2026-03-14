from __future__ import annotations

import shutil
from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_restored_db_remains_writable(tmp_path: Path) -> None:
    """
    After copying/restoring the SQLite DB file, the restored DB should still boot
    cleanly and accept new blocks.
    """
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")

    original_db = str(tmp_path / "original.db")
    restored_db = str(tmp_path / "restored.db")

    ex = WeAllExecutor(
        db_path=original_db,
        node_id="@alice",
        chain_id="restore-write",
        tx_index_path=tx_index_path,
    )

    assert ex.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@alice",
            "nonce": 1,
            "payload": {"pubkey": "k:alice"},
        }
    )["ok"] is True
    assert ex.produce_block(max_txs=1).ok is True

    shutil.copy2(original_db, restored_db)

    ex2 = WeAllExecutor(
        db_path=restored_db,
        node_id="@alice",
        chain_id="restore-write",
        tx_index_path=tx_index_path,
    )

    st = ex2.read_state()
    assert int(st["height"]) == 1

    assert ex2.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@bob",
            "nonce": 1,
            "payload": {"pubkey": "k:bob"},
        }
    )["ok"] is True
    assert ex2.produce_block(max_txs=1).ok is True

    st2 = ex2.read_state()
    assert int(st2["height"]) == 2
