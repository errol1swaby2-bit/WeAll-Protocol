from __future__ import annotations

import shutil
from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_backup_restore_smoke(tmp_path: Path) -> None:
    """
    Backup/restore smoke for the persisted executor database.

    Validates:
      - a copied DB file can be restored into a fresh location
      - restored state preserves height/tip/tx statuses
      - restored executor can continue confirming new txs
    """
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")

    original_db = str(tmp_path / "weall.db")
    backup_db = str(tmp_path / "weall.backup.db")
    restored_db = str(tmp_path / "weall.restored.db")

    ex1 = WeAllExecutor(
        db_path=original_db,
        node_id="@alice",
        chain_id="backup-restore",
        tx_index_path=tx_index_path,
    )

    tx_ids: list[str] = []
    post_restart_expected_height = 0

    for i in range(2):
        sub = ex1.submit_tx(
            {
                "tx_type": "ACCOUNT_REGISTER",
                "signer": f"@backup{i}",
                "nonce": 1,
                "payload": {"pubkey": f"k:backup{i}"},
            }
        )
        assert sub["ok"] is True
        tx_ids.append(str(sub["tx_id"]))

        meta = ex1.produce_block(max_txs=1)
        assert meta.ok is True
        post_restart_expected_height = meta.height

    st1 = ex1.read_state()
    assert int(st1["height"]) == 2
    assert str(st1["tip"])

    shutil.copy2(original_db, backup_db)
    shutil.copy2(backup_db, restored_db)

    ex2 = WeAllExecutor(
        db_path=restored_db,
        node_id="@alice",
        chain_id="backup-restore",
        tx_index_path=tx_index_path,
    )

    st2 = ex2.read_state()
    assert int(st2["height"]) == int(st1["height"])
    assert str(st2["tip"]) == str(st1["tip"])

    for tx_id in tx_ids:
        status = ex2.get_tx_status(tx_id)
        assert status["ok"] is True
        assert status["status"] == "confirmed"

    # Ensure restored executor can keep building on restored state.
    sub3 = ex2.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@backup2",
            "nonce": 1,
            "payload": {"pubkey": "k:backup2"},
        }
    )
    assert sub3["ok"] is True

    pending = ex2.get_tx_status(str(sub3["tx_id"]))
    assert pending["ok"] is True
    assert pending["status"] == "pending"

    meta3 = ex2.produce_block(max_txs=1)
    assert meta3.ok is True
    assert meta3.height == post_restart_expected_height + 1

    confirmed = ex2.get_tx_status(str(sub3["tx_id"]))
    assert confirmed["ok"] is True
    assert confirmed["status"] == "confirmed"
    assert int(confirmed["height"]) == 3

    st3 = ex2.read_state()
    assert int(st3["height"]) == 3
