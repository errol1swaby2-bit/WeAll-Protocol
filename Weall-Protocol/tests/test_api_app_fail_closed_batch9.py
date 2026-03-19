from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient


class _FakeExecutor(SimpleNamespace):
    pass


class _FakeBlockLoop:
    def __init__(self, *, executor, mempool, attestation_pool):
        self.executor = executor
        self.mempool = mempool
        self.attestation_pool = attestation_pool

    def start(self) -> bool:
        return False

    def stop(self) -> None:
        return None


class _FakeNetLoop:
    def __init__(self, *, executor, mempool):
        self.executor = executor
        self.mempool = mempool
        self.node = None

    def start(self) -> bool:
        return False

    def stop(self) -> None:
        return None


def test_prod_block_loop_autostart_fails_closed_when_start_returns_false(monkeypatch: pytest.MonkeyPatch) -> None:
    from weall.api import app as api_app

    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_BLOCK_LOOP_AUTOSTART", "1")
    monkeypatch.setenv("WEALL_NET_LOOP_AUTOSTART", "0")

    ex = _FakeExecutor(chain_id="weall-test", mempool=object(), attestation_pool=object())
    monkeypatch.setattr(api_app, "build_executor", lambda: ex)
    monkeypatch.setattr(api_app, "BlockProducerLoop", _FakeBlockLoop)

    app = api_app.create_app(boot_runtime=True)
    with pytest.raises(api_app.ApiRuntimeLifecycleError, match="api_block_loop_start_failed:start_returned_false"):
        with TestClient(app):
            pass


def test_prod_net_loop_autostart_fails_closed_when_start_returns_false(monkeypatch: pytest.MonkeyPatch) -> None:
    from weall.api import app as api_app

    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_BLOCK_LOOP_AUTOSTART", "0")
    monkeypatch.setenv("WEALL_NET_LOOP_AUTOSTART", "1")

    ex = _FakeExecutor(chain_id="weall-test", mempool=object(), attestation_pool=object())
    monkeypatch.setattr(api_app, "build_executor", lambda: ex)
    monkeypatch.setattr(api_app, "NetMeshLoop", _FakeNetLoop)

    app = api_app.create_app(boot_runtime=True)
    with pytest.raises(api_app.ApiRuntimeLifecycleError, match="api_net_loop_start_failed:start_returned_false"):
        with TestClient(app):
            pass


def test_dev_block_loop_autostart_still_degrades_open_for_testability(monkeypatch: pytest.MonkeyPatch) -> None:
    from weall.api import app as api_app

    monkeypatch.setenv("WEALL_MODE", "dev")
    monkeypatch.setenv("WEALL_BLOCK_LOOP_AUTOSTART", "1")
    monkeypatch.setenv("WEALL_NET_LOOP_AUTOSTART", "0")

    ex = _FakeExecutor(chain_id="weall-test", mempool=object(), attestation_pool=object())
    monkeypatch.setattr(api_app, "build_executor", lambda: ex)
    monkeypatch.setattr(api_app, "BlockProducerLoop", _FakeBlockLoop)

    app = api_app.create_app(boot_runtime=True)
    with TestClient(app) as client:
        assert client.app.state.block_loop is None


def test_prod_block_loop_autostart_fails_closed_when_runtime_dependencies_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    from weall.api import app as api_app

    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_BLOCK_LOOP_AUTOSTART", "1")
    monkeypatch.setenv("WEALL_NET_LOOP_AUTOSTART", "0")

    ex = _FakeExecutor(chain_id="weall-test", mempool=object(), attestation_pool=None)
    monkeypatch.setattr(api_app, "build_executor", lambda: ex)

    app = api_app.create_app(boot_runtime=True)
    with pytest.raises(api_app.ApiRuntimeLifecycleError, match="api_block_loop_start_failed:missing_runtime_dependencies"):
        with TestClient(app):
            pass
