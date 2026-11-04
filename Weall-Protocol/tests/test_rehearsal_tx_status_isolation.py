"""Bounded status-truth tests for PR81 Genesis/observer queue isolation.

This test suite uses synthetic locally committed tx-index state and a real,
stale observer queue file. It is not evidence of BFT, external consensus,
or live two-machine PoH verification.
"""

from __future__ import annotations

import json
from pathlib import Path

from weall.api.routes_public_parts import tx as tx_routes

TX_ID = "tx:synthetic-committed-account-register"
INDEX = {
    "tx_id": TX_ID,
    "height": 3,
    "block_id": "test-block-3",
    "included_ts_ms": 60000,
    "apply_ok": True,
    "tx_type": "ACCOUNT_REGISTER",
    "signer": "@applicant",
}


def _setup_queue(tmp_path: Path, monkeypatch) -> Path:
    path = tmp_path / "observer_tx_queue.json"
    path.write_text(
        json.dumps(
            {
                "version": 2,
                "records": [
                    {
                        "tx_id": TX_ID,
                        "chain_id": "weall-controlled-devnet",
                        "created_ms": 1,
                        "updated_ms": 1,
                        "upstream_status": "accepted",
                        "local_state_synced": False,
                        "confirmed_height": 0,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("WEALL_TX_QUEUE_PATH", str(path))
    monkeypatch.setattr(tx_routes, "_tx_index_lookup", lambda _req, _txid: dict(INDEX))
    return path


def test_genesis_canonical_confirmation_ignores_stale_observer_queue(
    tmp_path: Path, monkeypatch
) -> None:
    path = _setup_queue(tmp_path, monkeypatch)
    monkeypatch.setenv("WEALL_OBSERVER_EDGE_MODE", "0")
    monkeypatch.setenv("WEALL_OBSERVER_MODE", "0")
    monkeypatch.delenv("WEALL_NODE_LIFECYCLE_STATE", raising=False)

    def forbidden_reconcile(_txid: str):
        raise AssertionError("Genesis must not reconcile an observer queue")

    monkeypatch.setattr(tx_routes, "_reconcile_tx_queue_confirmation", forbidden_reconcile)
    original = path.read_bytes()
    status = tx_routes.tx_status(object(), TX_ID)

    assert status["ok"] is True
    assert status["status"] == "confirmed"
    assert status["height"] == 3
    assert status["block_id"] == "test-block-3"
    assert status["local_state_synced"] is True
    assert status["outbound_propagation"] == {}
    assert path.read_bytes() == original


def test_observer_local_index_does_not_prove_upstream_confirmation(
    tmp_path: Path, monkeypatch
) -> None:
    _setup_queue(tmp_path, monkeypatch)
    monkeypatch.setenv("WEALL_OBSERVER_EDGE_MODE", "1")
    monkeypatch.setattr(
        tx_routes,
        "_reconcile_tx_queue_confirmation",
        lambda _txid: {"upstream_status": "accepted", "local_state_synced": False},
    )
    result = tx_routes.tx_status(object(), TX_ID)
    assert result["status"] == "local_confirmed"
    assert result["source"] == "observer_local_confirmed_not_upstream_synced"
    assert result["local_state_synced"] is False


def test_upstream_confirmation_alone_does_not_prove_observer_local_sync(
    tmp_path: Path, monkeypatch
) -> None:
    _setup_queue(tmp_path, monkeypatch)
    monkeypatch.setenv("WEALL_OBSERVER_EDGE_MODE", "1")
    monkeypatch.setattr(
        tx_routes,
        "_reconcile_tx_queue_confirmation",
        lambda _txid: {
            "upstream_status": "confirmed",
            "local_state_synced": False,
            "confirmed_height": 3,
            "confirmed_block_id": "test-block-3",
        },
    )
    result = tx_routes.tx_status(object(), TX_ID)
    assert result["status"] == "confirmed"
    assert result["local_state_synced"] is False
    assert result["outbound_propagation"]["confirmed_height"] == 3


def test_launcher_isolates_genesis_queue_but_keeps_observer_reconcile_worker() -> None:
    root = Path(__file__).resolve().parents[1]
    source = (root / "scripts" / "devnet_local_two_frontend_rehearsal.sh").read_text(
        encoding="utf-8"
    )
    genesis = source.split('echo "==> Booting genesis backend ${NODE1_API}"', 1)[1].split(
        'echo "==> Booting observer backend ${NODE2_API}"', 1
    )[0]
    observer = source.split('echo "==> Booting observer backend ${NODE2_API}"', 1)[1].split(
        'echo "==> Starting observer reconcile worker"', 1
    )[0]
    worker = source.split('echo "==> Starting observer reconcile worker"', 1)[1].split(
        'echo "==> Starting genesis-to-observer downstream sync worker"', 1
    )[0]
    assert 'GENESIS_TX_QUEUE_PATH="${RUNTIME_DIR}/genesis_tx_queue.json"' in source
    assert 'export WEALL_TX_QUEUE_PATH="${GENESIS_TX_QUEUE_PATH}"' in genesis
    assert 'export WEALL_TX_QUEUE_PATH="${TX_QUEUE_PATH}"' not in genesis
    assert 'export WEALL_TX_QUEUE_PATH="${TX_QUEUE_PATH}"' in observer
    assert 'export WEALL_TX_QUEUE_PATH="${TX_QUEUE_PATH}"' in worker
    assert "observer and Genesis queue paths must be distinct" in source
