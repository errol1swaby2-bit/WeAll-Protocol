from __future__ import annotations

import sqlite3
from pathlib import Path

from weall.runtime.executor import WeAllExecutor
from weall.runtime.sqlite_db import derive_aux_db_path
from weall.storage.ipfs_pin_worker import IpfsPinWorker, IpfsPinWorkerConfig


def _tx_index_path() -> str:
    return str(Path("generated/tx_index.json").resolve())


def test_executor_moves_attestation_pool_to_aux_db_by_default(tmp_path: Path) -> None:
    main_db = str(tmp_path / "node.sqlite")
    ex = WeAllExecutor(
        db_path=main_db,
        node_id="@v1",
        chain_id="bft-live",
        tx_index_path=_tx_index_path(),
    )

    att = {"block_id": "blk:1", "validator": "@v2", "sig": "sig:1"}
    added = ex._att_pool.add(dict(att))
    assert added["ok"] is True

    aux_db = derive_aux_db_path(main_db)
    assert Path(aux_db).exists()

    main_con = sqlite3.connect(main_db)
    aux_con = sqlite3.connect(aux_db)
    try:
        main_n = int(main_con.execute("SELECT COUNT(1) FROM attestations;").fetchone()[0])
        aux_n = int(aux_con.execute("SELECT COUNT(1) FROM attestations;").fetchone()[0])
    finally:
        main_con.close()
        aux_con.close()

    assert main_n == 0
    assert aux_n == 1


def test_ipfs_worker_defaults_to_aux_db_path(tmp_path: Path) -> None:
    main_db = str(tmp_path / "node.sqlite")
    worker = IpfsPinWorker(
        IpfsPinWorkerConfig(
            db_path=main_db,
            operator_account="@operator",
            dry_run=True,
        )
    )

    expected = derive_aux_db_path(main_db)
    assert worker.db.path == expected
    assert Path(expected).exists()
