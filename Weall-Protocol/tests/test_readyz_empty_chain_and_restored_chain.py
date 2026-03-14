from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from weall.api.app import create_app
from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_readyz_empty_chain_and_restored_chain(tmp_path: Path) -> None:
    """
    /v1/readyz should return a stable healthy shape for both a fresh empty chain
    and a restarted/restored chain with persisted height.
    """
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    fresh = WeAllExecutor(
        db_path=db_path,
        node_id="@ready-node",
        chain_id="readyz-restart-shape",
        tx_index_path=tx_index_path,
    )

    app1 = create_app(boot_runtime=False)
    app1.state.executor = fresh
    client1 = TestClient(app1)

    r1 = client1.get("/v1/readyz")
    assert r1.status_code == 200
    b1 = r1.json()
    assert b1["ok"] is True
    assert b1["chain_id"] == "readyz-restart-shape"

    assert fresh.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@user1",
            "nonce": 1,
            "payload": {"pubkey": "k:user1"},
        }
    )["ok"] is True
    assert fresh.produce_block(max_txs=1).ok is True

    restored = WeAllExecutor(
        db_path=db_path,
        node_id="@ready-node",
        chain_id="readyz-restart-shape",
        tx_index_path=tx_index_path,
    )

    app2 = create_app(boot_runtime=False)
    app2.state.executor = restored
    client2 = TestClient(app2)

    r2 = client2.get("/v1/readyz")
    assert r2.status_code == 200
    b2 = r2.json()
    assert b2["ok"] is True
    assert b2["chain_id"] == "readyz-restart-shape"
    assert int(b2["height"]) == 1
