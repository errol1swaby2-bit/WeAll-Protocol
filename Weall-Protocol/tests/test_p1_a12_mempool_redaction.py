from __future__ import annotations

from fastapi.testclient import TestClient

from weall.api.app import create_app


class _LeakProbeMempool:
    def __init__(self) -> None:
        self._items = [
            {
                "tx_id": "tx:secret-probe",
                "tx_type": "CONTENT_POST_CREATE",
                "signer": "@alice",
                "nonce": 7,
                "payload": {"body": "A12-PRIVATE-PENDING-MARKER"},
                "sig": "A12-SECRET-SIGNATURE",
                "received_ms": 1234,
                "expires_ms": 5678,
                "mempool_admitted_height": 10,
                "mempool_expires_height": 20,
            }
        ]

    def size(self) -> int:
        return len(self._items)

    def peek(self, *, limit: int = 50):
        return self._items[:limit]


class _LeakProbeExecutor:
    def __init__(self) -> None:
        self.mempool = _LeakProbeMempool()

    def mempool_selection_diagnostics(self, *, preview_limit: int = 10):
        return {
            "policy": "canonical",
            "preview_limit": int(preview_limit),
            "size": 1,
            "items": [
                {
                    "tx_id": "tx:secret-probe",
                    "tx_type": "CONTENT_POST_CREATE",
                    "signer": "@alice",
                    "nonce": 7,
                    "received_ms": 1234,
                    "mempool_admitted_height": 10,
                    "mempool_expires_height": 20,
                    "order_key": ["chain", 7, "@alice", "CONTENT_POST_CREATE", "tx:secret-probe"],
                }
            ],
            "last_candidate": {
                "policy": "canonical",
                "requested_limit": 10,
                "fetched_count": 1,
                "selected_count": 1,
                "invalid_count": 0,
                "rejected_count": 0,
                "selected_tx_ids": ["tx:secret-probe"],
            },
        }


def test_a12_f002_public_mempool_status_redacts_pending_payload_and_signature() -> None:
    app = create_app(boot_runtime=False)
    app.state.executor = _LeakProbeExecutor()
    client = TestClient(app)

    response = client.get("/v1/status/mempool")

    assert response.status_code == 200
    body = response.json()
    serialized = response.text

    assert body["ok"] is True
    assert body["size"] == 1
    assert body["items"] == [
        {
            "tx_id": "tx:secret-probe",
            "tx_type": "CONTENT_POST_CREATE",
            "signer": "@alice",
            "nonce": 7,
            "received_ms": 1234,
            "mempool_admitted_height": 10,
            "mempool_expires_height": 20,
        }
    ]
    assert "A12-PRIVATE-PENDING-MARKER" not in serialized
    assert "A12-SECRET-SIGNATURE" not in serialized
    assert "payload" not in body["items"][0]
    assert "sig" not in body["items"][0]
    assert body["selection_diagnostics"]["last_candidate"]["selected_count"] == 1
