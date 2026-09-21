from __future__ import annotations

from types import SimpleNamespace

import pytest

from weall.runtime import bft_outbound


def _executor() -> SimpleNamespace:
    return SimpleNamespace(mempool=object(), attestation_pool=object())


def test_block_loop_constructor_internal_typeerror_is_not_retried(monkeypatch) -> None:
    from weall.api import app as api_app

    calls = 0

    class FailingBlockLoop:
        def __init__(self, *, executor, mempool, attestation_pool) -> None:
            nonlocal calls
            calls += 1
            raise TypeError("internal_block_constructor_typeerror")

    monkeypatch.setattr(api_app, "BlockProducerLoop", FailingBlockLoop)
    with pytest.raises(TypeError, match="internal_block_constructor_typeerror"):
        api_app._construct_block_loop(_executor())
    assert calls == 1


def test_block_loop_start_internal_typeerror_is_not_retried() -> None:
    class FailingLoop:
        def __init__(self) -> None:
            self.calls = 0

        def start(self) -> bool:
            self.calls += 1
            raise TypeError("internal_block_start_typeerror")

    from weall.api import app as api_app

    loop = FailingLoop()
    with pytest.raises(TypeError, match="internal_block_start_typeerror"):
        api_app._start_block_loop(loop, _executor())
    assert loop.calls == 1


def test_net_loop_constructor_internal_typeerror_is_not_retried(monkeypatch) -> None:
    from weall.api import app as api_app

    calls = 0

    class FailingNetLoop:
        def __init__(self, *, executor, mempool) -> None:
            nonlocal calls
            calls += 1
            raise TypeError("internal_net_constructor_typeerror")

    monkeypatch.setattr(api_app, "NetMeshLoop", FailingNetLoop)
    with pytest.raises(TypeError, match="internal_net_constructor_typeerror"):
        api_app._construct_net_loop(object(), _executor())
    assert calls == 1


def test_net_loop_start_internal_typeerror_is_not_retried() -> None:
    class FailingLoop:
        def __init__(self) -> None:
            self.calls = 0

        def start(self) -> bool:
            self.calls += 1
            raise TypeError("internal_net_start_typeerror")

    from weall.api import app as api_app

    loop = FailingLoop()
    with pytest.raises(TypeError, match="internal_net_start_typeerror"):
        api_app._start_net_loop(loop, object(), _executor())
    assert loop.calls == 1


def test_bft_restart_fails_closed_when_authoritative_outbox_read_fails() -> None:
    class Journal:
        def bootstrap_state(self):
            return {"last_view": 3}

    class FailingOutbox:
        def pending(self):
            raise RuntimeError("simulated_outbox_read_failure")

    ex = SimpleNamespace(
        _bft_journal=Journal(),
        _bft=SimpleNamespace(view=1, last_timeout_view=-1),
        _bft_outbox_store=FailingOutbox(),
    )

    with pytest.raises(RuntimeError, match="bft_restart_outbox_read_failed") as excinfo:
        bft_outbound._restore_bft_restart_hints(ex)
    assert isinstance(excinfo.value.__cause__, RuntimeError)
    assert str(excinfo.value.__cause__) == "simulated_outbox_read_failure"


def test_bft_restart_fails_closed_on_malformed_pending_timeout_view() -> None:
    class Journal:
        def bootstrap_state(self):
            return {"last_view": 3}

    class Outbox:
        def pending(self):
            return [SimpleNamespace(kind="timeout", payload={"view": "not-an-int"})]

    ex = SimpleNamespace(
        _bft_journal=Journal(),
        _bft=SimpleNamespace(view=1, last_timeout_view=-1),
        _bft_outbox_store=Outbox(),
    )

    with pytest.raises(RuntimeError, match="bft_restart_outbox_timeout_invalid"):
        bft_outbound._restore_bft_restart_hints(ex)
