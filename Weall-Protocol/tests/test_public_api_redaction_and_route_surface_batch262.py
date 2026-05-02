from __future__ import annotations

from fastapi.testclient import TestClient

from weall.api.app import create_app


class _FakeExecutor:
    def __init__(self, state: dict) -> None:
        self._state = state

    def read_state(self) -> dict:
        return self._state

    def snapshot(self) -> dict:
        return self._state

    def tx_index_hash(self) -> str:
        return "txindexhash-redaction"


def _state() -> dict:
    return {
        "chain_id": "weall-redaction-test",
        "height": 7,
        "time": 1_700_000_000,
        "accounts": {
            "@alice": {
                "nonce": 3,
                "poh_tier": 2,
                "banned": False,
                "locked": False,
                "keys": {"by_id": {"k:1": {"pubkey": "pub", "revoked": False}}},
                "session_keys": {
                    "bearer-secret-session": {
                        "active": True,
                        "issued_at_ts": 1_700_000_000,
                        "ttl_s": 3600,
                    }
                },
                "devices": {
                    "by_id": {
                        "browser:@alice:private-device": {
                            "device_id": "browser:@alice:private-device",
                            "device_type": "browser",
                            "revoked": False,
                            "fingerprint": "private-device-fingerprint",
                        },
                        "node:@alice:1": {
                            "device_id": "node:@alice:1",
                            "device_type": "node",
                            "revoked": True,
                        },
                    }
                },
            }
        },
        "poh": {
            "async_cases": {
                "case:1": {
                    "account_id": "@alice",
                    "status": "open",
                    "raw_response": "do-not-expose",
                    "email_hash": "do-not-expose",
                    "private_notes": "do-not-expose",
                    "evidence_commitments": ["commitment:ok"],
                }
            }
        },
        "content": {"media": {"cid:ok": {"cid": "cid:ok", "status": "available"}}},
    }


def _client(state: dict) -> TestClient:
    app = create_app(boot_runtime=False)
    app.state.executor = _FakeExecutor(state)
    return TestClient(app, raise_server_exceptions=False)


def test_public_state_snapshot_redacts_session_device_and_private_poh_fields() -> None:
    client = _client(_state())

    res = client.get("/v1/state/snapshot")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["ok"] is True
    alice = body["state"]["accounts"]["@alice"]

    assert "session_keys" not in alice
    assert alice["devices"]["redacted"] is True
    assert alice["devices"]["summary"] == {
        "total": 2,
        "active": 1,
        "revoked": 1,
        "node": 1,
        "browser": 1,
    }
    assert alice["devices"]["by_id"] == {}

    case = body["state"]["poh"]["async_cases"]["case:1"]
    assert case["evidence_commitments"] == ["commitment:ok"]
    assert case["raw_response"] == {"redacted": True}
    assert case["email_hash"] == {"redacted": True}
    assert case["private_notes"] == {"redacted": True}
    assert "bearer-secret-session" not in str(body)
    assert "private-device-fingerprint" not in str(body)
    assert "do-not-expose" not in str(body)


def test_public_account_lookup_redacts_session_keys_but_owner_lookup_can_reveal_private_state() -> None:
    state = _state()
    client = _client(state)

    public_res = client.get("/v1/accounts/@alice")
    assert public_res.status_code == 200, public_res.text
    public_state = public_res.json()["state"]
    assert "session_keys" not in public_state
    assert public_state["devices"]["redacted"] is True
    assert "bearer-secret-session" not in str(public_state)

    owner_res = client.get(
        "/v1/accounts/@alice",
        headers={
            "x-weall-account": "@alice",
            "x-weall-session-key": "bearer-secret-session",
        },
    )
    assert owner_res.status_code == 200, owner_res.text
    owner_state = owner_res.json()["state"]
    assert owner_state["session_keys"]["bearer-secret-session"]["active"] is True
    assert "browser:@alice:private-device" in owner_state["devices"]["by_id"]


def test_production_openapi_hides_devnet_sync_apply_and_net_debug_routes(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.delenv("WEALL_ENABLE_DEVNET_SYNC_APPLY_ROUTE", raising=False)
    monkeypatch.delenv("WEALL_ENABLE_STATE_SYNC_HTTP_REQUEST_ROUTE", raising=False)
    monkeypatch.delenv("WEALL_ENABLE_PUBLIC_DEBUG", raising=False)

    app = create_app(boot_runtime=False)
    paths = set((app.openapi().get("paths") or {}).keys())

    assert "/v1/sync/apply" not in paths
    assert "/v1/sync/request" not in paths
    assert "/v1/net/peers" not in paths
    assert "/v1/dev/demo-seed" not in paths
    assert "/v1/state/snapshot" in paths


def test_disabled_sensitive_routes_still_fail_closed_at_call_time(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.delenv("WEALL_ENABLE_DEVNET_SYNC_APPLY_ROUTE", raising=False)
    monkeypatch.delenv("WEALL_ENABLE_STATE_SYNC_HTTP_REQUEST_ROUTE", raising=False)
    monkeypatch.delenv("WEALL_ENABLE_PUBLIC_DEBUG", raising=False)

    client = _client(_state())

    sync_apply = client.post("/v1/sync/apply", json={"response": {}})
    assert sync_apply.status_code == 403
    assert sync_apply.json()["detail"]["code"] == "disabled"

    sync_request = client.post("/v1/sync/request", json={})
    assert sync_request.status_code == 403
    assert sync_request.json()["detail"]["code"] == "disabled"

    net_debug = client.get("/v1/net/peers")
    assert net_debug.status_code == 404
