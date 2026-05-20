from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi.testclient import TestClient

from weall.api.app import create_app
from weall.crypto.sig import sign_tx_envelope_dict
from weall.runtime.executor import WeAllExecutor
from weall.runtime.mempool import compute_tx_id

ROOT = Path(__file__).resolve().parents[1]


class _FakeResponse:
    def __init__(self, payload: dict[str, Any]) -> None:
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False

    def read(self, _limit: int | None = None) -> bytes:
        return json.dumps(self.payload, sort_keys=True).encode("utf-8")


def _signed_account_register(account: str, *, chain_id: str = "weall-observer-361") -> dict[str, Any]:
    seed = bytes.fromhex("61" * 32)
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    pubkey = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    tx = {
        "tx_type": "ACCOUNT_REGISTER",
        "signer": account,
        "nonce": 1,
        "chain_id": chain_id,
        "payload": {"pubkey": pubkey},
    }
    return sign_tx_envelope_dict(tx=tx, privkey=seed.hex())


def _client(tmp_path: Path) -> TestClient:
    app = create_app(boot_runtime=False)
    app.state.executor = WeAllExecutor(
        db_path=str(tmp_path / "observer-361.db"),
        node_id="observer-361",
        chain_id="weall-observer-361",
        tx_index_path=str(ROOT / "generated" / "tx_index.json"),
    )
    app.state.net_node = None
    return TestClient(app, raise_server_exceptions=False)


def _read_outbox(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def test_observer_submit_is_nonblocking_and_queues_outbox_batch361(tmp_path: Path, monkeypatch) -> None:
    outbox = tmp_path / "outbox.json"
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_OBSERVER_EDGE_MODE", "1")
    monkeypatch.setenv("WEALL_TX_UPSTREAM_URLS", "https://genesis.example.test")
    monkeypatch.setenv("WEALL_TX_UPSTREAM_REQUIRED", "1")
    monkeypatch.setenv("WEALL_TX_OUTBOX_PATH", str(outbox))

    def should_not_call(_req, timeout=0):  # noqa: ANN001
        raise AssertionError("submit should not synchronously contact upstream by default")

    monkeypatch.setattr("weall.api.routes_public_parts.tx.urllib.request.urlopen", should_not_call)
    tx = _signed_account_register("@observer_361_nonblocking")
    tx_id = compute_tx_id(tx, chain_id="weall-observer-361")

    with _client(tmp_path) as client:
        res = client.post("/v1/tx/submit", json=tx)

    assert res.status_code == 200, res.text
    body = res.json()
    assert body["tx_id"] == tx_id
    assert body["upstream_propagation"]["mode"] == "durable_outbox"
    assert body["upstream_propagation"]["attempted"] is False

    stored = _read_outbox(outbox)
    assert len(stored["records"]) == 1
    assert stored["records"][0]["tx_id"] == tx_id
    assert stored["records"][0]["attempts"] == 0


def test_observer_operator_routes_require_token_and_redact_outbox_path_batch361(tmp_path: Path, monkeypatch) -> None:
    outbox = tmp_path / "outbox.json"
    monkeypatch.setenv("WEALL_OBSERVER_EDGE_MODE", "1")
    monkeypatch.setenv("WEALL_TX_UPSTREAM_URLS", "https://genesis.example.test")
    monkeypatch.setenv("WEALL_TX_OUTBOX_PATH", str(outbox))
    monkeypatch.setenv("WEALL_OPERATOR_TOKEN", "edge-secret")

    with _client(tmp_path) as client:
        denied = client.get("/v1/observer/edge/status")
        assert denied.status_code == 403
        allowed = client.get("/v1/observer/edge/status", headers={"X-WeAll-Operator-Token": "edge-secret"})
        assert allowed.status_code == 200, allowed.text
        outbox_status = allowed.json()["outbox"]
        assert "path" not in outbox_status
        assert "count" in outbox_status


def test_observer_drain_verifies_upstream_identity_before_forwarding_batch361(tmp_path: Path, monkeypatch) -> None:
    outbox = tmp_path / "outbox.json"
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_OBSERVER_EDGE_MODE", "1")
    monkeypatch.setenv("WEALL_TX_UPSTREAM_URLS", "https://genesis.example.test")
    monkeypatch.setenv("WEALL_TX_UPSTREAM_REQUIRED", "1")
    monkeypatch.setenv("WEALL_TX_OUTBOX_PATH", str(outbox))
    monkeypatch.setenv("WEALL_OPERATOR_TOKEN", "edge-secret")

    tx = _signed_account_register("@observer_361_identity")
    tx_id = compute_tx_id(tx, chain_id="weall-observer-361")

    with _client(tmp_path) as client:
        assert client.post("/v1/tx/submit", json=tx).status_code == 200

    calls: list[str] = []

    def fake_urlopen(req, timeout=0):  # noqa: ANN001
        calls.append(req.full_url)
        if req.full_url.endswith("/v1/chain/identity"):
            return _FakeResponse({"ok": True, "chain_id": "wrong-chain"})
        raise AssertionError("tx submit should not happen after identity mismatch")

    monkeypatch.setattr("weall.api.routes_public_parts.tx.urllib.request.urlopen", fake_urlopen)
    with _client(tmp_path) as client:
        drained = client.post("/v1/observer/edge/outbox/drain", headers={"X-WeAll-Operator-Token": "edge-secret"})

    assert drained.status_code == 200, drained.text
    result = drained.json()["result"]["results"][0]["results"][0]
    assert result["error"] == "upstream_chain_id_mismatch"
    assert calls == ["https://genesis.example.test/v1/chain/identity"]
    stored = _read_outbox(outbox)
    assert stored["records"][0]["tx_id"] == tx_id
    assert stored["records"][0]["upstream_status"] == "pending"


def test_observer_outbox_quarantines_corrupt_json_batch361(tmp_path: Path, monkeypatch) -> None:
    outbox = tmp_path / "outbox.json"
    outbox.write_text("{not-json", encoding="utf-8")
    monkeypatch.setenv("WEALL_OBSERVER_EDGE_MODE", "1")
    monkeypatch.setenv("WEALL_TX_OUTBOX_PATH", str(outbox))
    monkeypatch.setenv("WEALL_OPERATOR_TOKEN", "edge-secret")

    with _client(tmp_path) as client:
        res = client.get("/v1/observer/edge/status", headers={"X-WeAll-Operator-Token": "edge-secret"})

    assert res.status_code == 200, res.text
    assert res.json()["outbox"]["count"] == 0
    quarantined = list(tmp_path.glob("outbox.json.corrupt.*"))
    assert quarantined, "corrupt outbox should be quarantined instead of silently reused"


def test_observer_outbox_prunes_to_configured_record_limit_batch361(tmp_path: Path, monkeypatch) -> None:
    outbox = tmp_path / "outbox.json"
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_OBSERVER_EDGE_MODE", "1")
    monkeypatch.setenv("WEALL_TX_UPSTREAM_REQUIRED", "0")
    monkeypatch.setenv("WEALL_TX_OUTBOX_MAX_RECORDS", "2")
    monkeypatch.setenv("WEALL_TX_OUTBOX_PATH", str(outbox))

    with _client(tmp_path) as client:
        for idx in range(3):
            res = client.post("/v1/tx/submit", json=_signed_account_register(f"@observer_361_prune_{idx}"))
            assert res.status_code == 200, res.text

    stored = _read_outbox(outbox)
    assert len(stored["records"]) == 2
    assert {r["tx_id"] for r in stored["records"]}
