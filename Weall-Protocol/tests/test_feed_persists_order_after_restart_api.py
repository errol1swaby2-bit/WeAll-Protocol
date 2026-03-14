from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from weall.api.app import create_app
from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_feed_persists_order_after_restart_api(tmp_path: Path) -> None:
    """
    Public feed should preserve persisted item ordering after restart.

    This test seeds a posting-capable account into persisted state, then creates
    two posts, restarts the executor, and verifies feed order through the API.
    """
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    ex1 = WeAllExecutor(
        db_path=db_path,
        node_id="@feed-node",
        chain_id="feed-restart-api",
        tx_index_path=tx_index_path,
    )

    st = ex1.read_state()
    accounts = dict(st.get("accounts") or {})
    accounts["@alice"] = {
        "banned": False,
        "devices": {"by_id": {}},
        "keys": {
            "by_id": {
                "k:alice": {
                    "key_type": "main",
                    "pubkey": "k:alice",
                    "revoked": False,
                    "revoked_at": None,
                }
            }
        },
        "locked": False,
        "nonce": 1,
        "poh_tier": 3,
        "recovery": {"config": None, "proposals": {}},
        "reputation": 0,
        "session_keys": {},
    }
    st["accounts"] = accounts

    # Persist through the executor's ledger-store alias used in this repo.
    ex1._store.write_state_snapshot(st)  # type: ignore[attr-defined]

    assert ex1.submit_tx(
        {
            "tx_type": "CONTENT_POST_CREATE",
            "signer": "@alice",
            "nonce": 2,
            "payload": {
                "body": "first post",
                "visibility": "public",
                "tags": ["one"],
                "media": [],
            },
        }
    )["ok"] is True
    assert ex1.produce_block(max_txs=1).ok is True

    assert ex1.submit_tx(
        {
            "tx_type": "CONTENT_POST_CREATE",
            "signer": "@alice",
            "nonce": 3,
            "payload": {
                "body": "second post",
                "visibility": "public",
                "tags": ["two"],
                "media": [],
            },
        }
    )["ok"] is True
    assert ex1.produce_block(max_txs=1).ok is True

    ex2 = WeAllExecutor(
        db_path=db_path,
        node_id="@feed-node",
        chain_id="feed-restart-api",
        tx_index_path=tx_index_path,
    )

    app = create_app(boot_runtime=False)
    app.state.executor = ex2
    client = TestClient(app)

    r = client.get("/v1/feed")
    assert r.status_code == 200

    body = r.json()
    assert body["ok"] is True
    items = body["items"]
    assert len(items) >= 2

    assert items[0]["body"] == "second post"
    assert items[1]["body"] == "first post"
