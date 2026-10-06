from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from weall.api.routes_public_parts import state as state_routes


class _SnapshotExecutor:
    def __init__(self) -> None:
        self.read_count = 0

    def read_state(self) -> dict:
        self.read_count += 1
        return {
            "height": 7,
            "accounts": {
                "@alice": {
                    "balance": 1,
                    "session_keys": {"secret": {"key": "never-public"}},
                }
            },
        }


def _request(executor: _SnapshotExecutor):
    return SimpleNamespace(
        app=SimpleNamespace(state=SimpleNamespace(executor=executor)),
    )


def test_a15_f005_production_snapshot_fails_before_full_state_read(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_PUBLIC_STATE_SNAPSHOT_ENABLED", "1")
    executor = _SnapshotExecutor()

    with pytest.raises(HTTPException) as caught:
        state_routes.state_snapshot(_request(executor))

    assert caught.value.status_code == 403
    assert caught.value.detail["code"] == "public_state_snapshot_disabled"
    assert executor.read_count == 0


def test_a15_f005_dev_snapshot_remains_available_and_redacted(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "test")
    executor = _SnapshotExecutor()

    body = state_routes.state_snapshot(_request(executor))

    assert body["ok"] is True
    assert body["state"]["height"] == 7
    assert "session_keys" not in body["state"]["accounts"]["@alice"]
    assert executor.read_count == 1
