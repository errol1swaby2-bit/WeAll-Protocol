from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient


class _FakeExecutor(SimpleNamespace):
    """Minimal executor stub for API lifecycle tests."""


def test_create_app_boot_runtime_false_does_not_attach_executor() -> None:
    from weall.api.app import create_app

    app = create_app(boot_runtime=False)
    assert getattr(app.state, "executor", None) is None

    # App should still be startable for route/middleware tests.
    with TestClient(app) as _client:
        pass


def test_create_app_boot_runtime_true_attaches_executor(monkeypatch: pytest.MonkeyPatch) -> None:
    from weall.api import app as api_app

    def _fake_build_executor():
        return _FakeExecutor(chain_id="weall-test")

    monkeypatch.setattr(api_app, "build_executor", _fake_build_executor)

    app = api_app.create_app(boot_runtime=True)
    assert getattr(app.state, "executor", None) is not None
    assert getattr(app.state.executor, "chain_id", "") == "weall-test"

    with TestClient(app) as _client:
        pass
