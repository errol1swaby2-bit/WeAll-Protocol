from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi.testclient import TestClient

from weall.api.app import app
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


def _signed_account_register(account: str, *, chain_id: str = "weall-observer-edge") -> dict[str, Any]:
    seed = bytes.fromhex("57" * 32)
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


def _attach_executor(tmp_path: Path) -> WeAllExecutor:
    ex = WeAllExecutor(
        db_path=str(tmp_path / "observer-edge.db"),
        node_id="local-observer-edge",
        chain_id="weall-observer-edge",
        tx_index_path=str(ROOT / "generated" / "tx_index.json"),
    )
    app.state.executor = ex
    app.state.net_node = None
    return ex


def test_local_observer_tx_submit_forwards_signed_envelope_to_upstream_batch357(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_OBSERVER_MODE", "1")
    monkeypatch.setenv("WEALL_OBSERVER_EDGE_MODE", "1")
    monkeypatch.setenv("WEALL_TX_UPSTREAM_URLS", "https://genesis.example.test")
    monkeypatch.setenv("WEALL_TX_UPSTREAM_REQUIRED", "1")
    monkeypatch.setenv("WEALL_TX_UPSTREAM_SYNC_ON_SUBMIT", "1")
    monkeypatch.setenv("WEALL_TX_UPSTREAM_VERIFY_IDENTITY", "0")
    monkeypatch.setenv("WEALL_TX_OUTBOX_PATH", str(tmp_path / "outbox.json"))

    _attach_executor(tmp_path)
    tx = _signed_account_register("@observer_edge_user")
    tx_id = compute_tx_id(tx, chain_id="weall-observer-edge")
    captured: list[dict[str, Any]] = []

    def fake_urlopen(req, timeout=0):  # noqa: ANN001 - urllib-compatible test double
        captured.append(
            {
                "url": req.full_url,
                "timeout": timeout,
                "headers": dict(req.header_items()),
                "body": json.loads(req.data.decode("utf-8")),
            }
        )
        return _FakeResponse({"ok": True, "tx_id": tx_id, "status": "accepted"})

    monkeypatch.setattr("weall.api.routes_public_parts.tx.urllib.request.urlopen", fake_urlopen)

    with TestClient(app, raise_server_exceptions=False) as client:
        res = client.post("/v1/tx/submit", json=tx)

    assert res.status_code == 200, res.text
    body = res.json()
    assert body["ok"] is True
    assert body["status"] == "accepted"
    assert body["upstream_propagation"]["attempted"] is True
    assert body["upstream_propagation"]["accepted"] is True
    assert captured and captured[0]["url"] == "https://genesis.example.test/v1/tx/submit"
    assert captured[0]["body"] == tx
    assert captured[0]["headers"].get("X-weall-observer-forwarded") == "1"


def test_forwarded_observer_tx_does_not_loop_back_to_upstream_batch357(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_OBSERVER_EDGE_MODE", "1")
    monkeypatch.setenv("WEALL_TX_UPSTREAM_URLS", "https://genesis.example.test")
    monkeypatch.setenv("WEALL_TX_UPSTREAM_REQUIRED", "0")
    monkeypatch.setenv("WEALL_TX_OUTBOX_PATH", str(tmp_path / "outbox.json"))

    _attach_executor(tmp_path)
    tx = _signed_account_register("@observer_forwarded_user")

    def fake_urlopen(_req, timeout=0):  # noqa: ANN001 - should not be called
        raise AssertionError("forwarded tx should not be re-forwarded")

    monkeypatch.setattr("weall.api.routes_public_parts.tx.urllib.request.urlopen", fake_urlopen)

    with TestClient(app, raise_server_exceptions=False) as client:
        res = client.post("/v1/tx/submit", json=tx, headers={"X-WeAll-Observer-Forwarded": "1"})

    assert res.status_code == 200, res.text
    body = res.json()
    assert body["upstream_propagation"]["attempted"] is False
    assert body["upstream_propagation"]["skipped"] == "already_forwarded"


def test_required_upstream_failure_is_visible_to_local_frontend_batch357(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_OBSERVER_EDGE_MODE", "1")
    monkeypatch.setenv("WEALL_TX_UPSTREAM_URLS", "https://genesis.example.test")
    monkeypatch.setenv("WEALL_TX_UPSTREAM_REQUIRED", "1")
    monkeypatch.setenv("WEALL_TX_OUTBOX_PATH", str(tmp_path / "outbox.json"))

    _attach_executor(tmp_path)
    tx = _signed_account_register("@observer_edge_upstream_down")

    def fake_urlopen(_req, timeout=0):  # noqa: ANN001 - urllib-compatible test double
        raise OSError("simulated upstream outage")

    monkeypatch.setattr("weall.api.routes_public_parts.tx.urllib.request.urlopen", fake_urlopen)

    with TestClient(app, raise_server_exceptions=False) as client:
        res = client.post("/v1/tx/submit", json=tx)

    assert res.status_code == 200, res.text
    body = res.json()
    assert body["ok"] is True
    assert body["upstream_propagation"]["accepted"] is False
    assert body["upstream_propagation"]["queued"] >= 1


def test_observer_edge_status_surfaces_upstream_posture_batch357(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_OBSERVER_EDGE_MODE", "1")
    monkeypatch.setenv("WEALL_TX_UPSTREAM_URLS", "https://genesis.example.test,https://peer.example.test/")
    monkeypatch.setenv("WEALL_TX_UPSTREAM_REQUIRED", "1")
    monkeypatch.setenv("WEALL_OPERATOR_TOKEN", "edge-token")

    with TestClient(app, raise_server_exceptions=False) as client:
        res = client.get("/v1/observer/edge/status", headers={"X-WeAll-Operator-Token": "edge-token"})

    assert res.status_code == 200, res.text
    body = res.json()
    assert body["ok"] is True
    assert body["observer_edge_mode"] is True
    assert body["upstream_required"] is True
    assert body["upstream_count"] == 2
    assert "https://genesis.example.test" in body["upstreams"]
    assert "outbox" in body
    assert "path" not in body["outbox"]


def test_onboarding_boot_wrapper_enables_local_observer_edge_mode_batch357() -> None:
    script = (ROOT / "scripts" / "boot_onboarding_node.sh").read_text(encoding="utf-8")
    assert 'WEALL_OBSERVER_EDGE_MODE="${WEALL_OBSERVER_EDGE_MODE:-1}"' in script
    assert "WEALL_TX_UPSTREAM_URLS" in script
    assert 'WEALL_TX_UPSTREAM_REQUIRED="${WEALL_TX_UPSTREAM_REQUIRED:-1}"' in script
    assert "durably queued, and retried to configured upstreams" in script
