from __future__ import annotations

import hmac
import hashlib
import json
import time
from pathlib import Path

from fastapi.testclient import TestClient

from weall.api.app import create_app

ROOT = Path(__file__).resolve().parents[1]
OUTER = ROOT.parent
WEB = OUTER / "web"


class DummyExecutor:
    def __init__(self, state: dict):
        self._state = state

    def read_state(self) -> dict:
        return self._state


def _session(active: bool = True) -> dict:
    return {"active": active, "issued_at_ts": 1, "ttl_s": 100, "device_id": "browser:test"}


def _state() -> dict:
    return {
        "chain_id": "weall-controlled-devnet",
        "height": 7,
        "time": 10,
        "accounts": {
            "@alice": {"nonce": 0, "poh_tier": 1, "banned": False, "locked": False, "session_keys": {"sk-alice": _session()}},
            "@j1": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False, "session_keys": {"sk-j1": _session()}},
        },
        "poh": {
            "live_cases": {
                "live:alice:1": {
                    "account_id": "@alice",
                    "status": "init",
                    "session_commitment": "sc1",
                    "room_commitment": "room1",
                    "prompt_commitment": "prompt1",
                    "jurors": {"@j1": {"role": "interacting", "accepted": True}},
                }
            },
            "live_sessions": {
                "session:live:alice:1": {
                    "case_id": "live:alice:1",
                    "status": "active",
                    "session_commitment": "sc1",
                    "room_commitment": "room1",
                    "prompt_commitment": "prompt1",
                }
            },
            "live_session_participants": {},
        },
    }


def _client(state: dict | None = None) -> TestClient:
    app = create_app(boot_runtime=False)
    app.state.executor = DummyExecutor(state or _state())
    return TestClient(app)


def _now_ms() -> int:
    return int(time.time() * 1000)


def test_bridge_import_rejects_stale_signed_replay_window(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_CHAIN_ID", "weall-controlled-devnet")
    monkeypatch.setenv("WEALL_P2P_SIGNAL_TTL_MS", "10000")
    monkeypatch.setenv(
        "WEALL_WEBRTC_SIGNAL_PEERS_JSON",
        json.dumps([
            {
                "node_id": "observer",
                "url": "http://127.0.0.1:8002",
                "chain_id": "weall-controlled-devnet",
                "bridge_secret": "bridge-hmac-secret",
            }
        ]),
    )
    c = _client()
    session_id = "session:live:alice:1"
    signal = {
        "signal_id": "webrtc:observer:stale",
        "session_id": session_id,
        "from_account": "@alice",
        "to_account": "@j1",
        "type": "offer",
        "sdp": "v=0\no=- 1 1 IN IP4 127.0.0.1",
        "ts_ms": _now_ms() - 60_000,
    }
    payload = {"source_node": "observer", "source_chain_id": "weall-controlled-devnet", "signal": signal}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sig = hmac.new(b"bridge-hmac-secret", canonical, hashlib.sha256).hexdigest()

    res = c.post(
        f"/v1/poh/live/session/{session_id}/webrtc/signals/import",
        json={**payload, "signature": sig},
    )

    assert res.status_code == 403
    assert res.json()["error"]["message"] == "webrtc_bridge_signal_replay_window_expired"


def test_bridge_import_requires_present_fresh_source_timestamp(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_WEBRTC_SIGNAL_BRIDGE_TOKEN", "bridge-secret")
    monkeypatch.setenv("WEALL_WEBRTC_SIGNAL_ALLOWED_SOURCE_NODE_IDS", "observer")
    c = _client()
    session_id = "session:live:alice:1"

    res = c.post(
        f"/v1/poh/live/session/{session_id}/webrtc/signals/import",
        headers={"x-weall-webrtc-signal-bridge-token": "bridge-secret"},
        json={
            "source_node": "observer",
            "source_chain_id": "weall-controlled-devnet",
            "signal": {
                "signal_id": "webrtc:observer:missing-ts",
                "session_id": session_id,
                "from_account": "@alice",
                "to_account": "@j1",
                "type": "offer",
                "sdp": "v=0",
            },
        },
    )

    assert res.status_code == 400
    assert res.json()["error"]["message"] == "webrtc_bridge_signal_ts_required"


def test_tx_queue_rows_do_not_persist_peer_bridge_token() -> None:
    src = (ROOT / "src" / "weall" / "api" / "routes_public_parts" / "poh.py").read_text(encoding="utf-8")

    assert '"peer_bridge_token"' not in src
    assert "_bridge_peer_token(spec or {})" in src
    assert "peer_node_id" in src
    assert "store only peer_node_id" not in src or "peer_bridge_token" not in src


def test_json_turn_ice_credentials_are_short_lived_in_prod() -> None:
    src = (ROOT / "src" / "weall" / "api" / "routes_public_parts" / "poh.py").read_text(encoding="utf-8")

    assert "def _validate_webrtc_turn_credential_expiry" in src
    assert "credential_expires_ms" in src
    assert "row.get(\"credential_expires_ms\")" in src
    assert "prod_webrtc_turn_credentials_must_be_short_lived" in src
    assert "_validate_webrtc_turn_credential_expiry(expires_ms, has_credential=bool(credential), urls=url_list)" in src


def test_stale_tx_queue_pruning_increments_diagnostics() -> None:
    src = (ROOT / "src" / "weall" / "api" / "routes_public_parts" / "poh.py").read_text(encoding="utf-8")

    assert "stale_tx_queue_pruned += 1" in src
    assert 'diag["stale_tx_queue_pruned"] = int(diag.get("stale_tx_queue_pruned") or 0) + stale_tx_queue_pruned' in src
    assert "overflow_pruned" in src
