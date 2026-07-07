from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


class _FakeExecutor:
    def __init__(self, *, chain_id: str, mempool: object | None, attestation_pool: object | None) -> None:
        self.chain_id = chain_id
        self.mempool = mempool
        self.attestation_pool = attestation_pool


class _FakeBlockLoop:
    def __init__(self, *args, **kwargs) -> None:
        pass

    def start(self, *args, **kwargs) -> bool:
        return False


class _FakeNetLoop:
    def __init__(self, *args, **kwargs) -> None:
        pass

    def start(self, *args, **kwargs) -> bool:
        return False


def test_prod_block_loop_autostart_fails_closed_when_start_returns_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from weall.api import app as api_app

    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_CHAIN_ID", "weall-test")
    monkeypatch.setenv("WEALL_BLOCK_LOOP_AUTOSTART", "1")
    monkeypatch.setenv("WEALL_NET_LOOP_AUTOSTART", "0")

    ex = _FakeExecutor(chain_id="weall-test", mempool=object(), attestation_pool=object())
    monkeypatch.setattr(api_app, "build_executor", lambda: ex)
    monkeypatch.setattr(api_app, "BlockProducerLoop", _FakeBlockLoop)

    app = api_app.create_app(boot_runtime=True)
    with pytest.raises(Exception, match="api_block_loop_start_failed:start_returned_false"):
        with TestClient(app):
            pass


def test_prod_net_loop_autostart_fails_closed_when_start_returns_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from weall.api import app as api_app

    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_CHAIN_ID", "weall-test")
    monkeypatch.setenv("WEALL_BLOCK_LOOP_AUTOSTART", "0")
    monkeypatch.setenv("WEALL_NET_LOOP_AUTOSTART", "1")

    ex = _FakeExecutor(chain_id="weall-test", mempool=object(), attestation_pool=object())
    monkeypatch.setattr(api_app, "build_executor", lambda: ex)
    monkeypatch.setattr(api_app, "NetMeshLoop", _FakeNetLoop)

    app = api_app.create_app(boot_runtime=True)
    with pytest.raises(Exception, match="api_net_loop_start_failed:start_returned_false"):
        with TestClient(app):
            pass


def test_prod_runtime_boot_attaches_executor_state(monkeypatch: pytest.MonkeyPatch) -> None:
    from weall.api import app as api_app

    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_CHAIN_ID", "weall-test")
    monkeypatch.setenv("WEALL_BLOCK_LOOP_AUTOSTART", "0")
    monkeypatch.setenv("WEALL_NET_LOOP_AUTOSTART", "0")

    ex = _FakeExecutor(chain_id="weall-test", mempool=object(), attestation_pool=object())
    monkeypatch.setattr(api_app, "build_executor", lambda: ex)

    app = api_app.create_app(boot_runtime=True)
    assert app.state.executor is ex


def test_prod_block_loop_autostart_fails_closed_when_runtime_dependencies_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from weall.api import app as api_app

    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_CHAIN_ID", "weall-test")
    monkeypatch.setenv("WEALL_BLOCK_LOOP_AUTOSTART", "1")
    monkeypatch.setenv("WEALL_NET_LOOP_AUTOSTART", "0")

    ex = _FakeExecutor(chain_id="weall-test", mempool=object(), attestation_pool=None)
    monkeypatch.setattr(api_app, "build_executor", lambda: ex)

    app = api_app.create_app(boot_runtime=True)
    with pytest.raises(Exception, match="api_block_loop_start_failed:missing_runtime_dependencies"):
        with TestClient(app):
            pass
