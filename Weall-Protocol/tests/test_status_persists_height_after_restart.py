from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from weall.api.app import create_app
from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_status_persists_height_after_restart(tmp_path: Path) -> None:
    """
    /v1/status should reflect persisted chain height after executor restart.
    """
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    ex1 = WeAllExecutor(
        db_path=db_path,
        node_id="@api-node",
        chain_id="status-restart",
        tx_index_path=tx_index_path,
    )

    assert (
        ex1.submit_tx(
            {
                "tx_type": "ACCOUNT_REGISTER",
                "signer": "@user1",
                "nonce": 1,
                "payload": {"pubkey": "k:user1"},
            }
        )["ok"]
        is True
    )
    assert ex1.produce_block(max_txs=1).ok is True

    ex2 = WeAllExecutor(
        db_path=db_path,
        node_id="@api-node",
        chain_id="status-restart",
        tx_index_path=tx_index_path,
    )

    app = create_app(boot_runtime=False)
    app.state.executor = ex2
    client = TestClient(app)

    r = client.get("/v1/status")
    assert r.status_code == 200

    body = r.json()
    assert body["ok"] is True
    assert int(body["height"]) == 1
    assert body["chain_id"] == "status-restart"
