"""Network shutdown must not clear peer sessions under a live packet loop."""

from __future__ import annotations

import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from weall.net.net_loop import NetLoopConfig, NetMeshLoop


class _CloseProbe:
    def __init__(self, finished: threading.Event) -> None:
        self.finished = finished
        self.closed = threading.Event()
        self.calls = 0
        self.raced = False

    def close(self) -> None:
        self.calls += 1
        self.raced |= not self.finished.is_set()
        self.closed.set()


def _loop(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> NetMeshLoop:
    monkeypatch.setenv("WEALL_PEERS_FILE", str(tmp_path / "peers.json"))
    return NetMeshLoop(
        executor=SimpleNamespace(),
        mempool=SimpleNamespace(),
        cfg=NetLoopConfig(
            enabled=False, bind_host="127.0.0.1", bind_port=30303, tick_ms=25, schema_version="1"
        ),
    )


def test_stop_waits_until_active_network_iteration_finishes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    entered = threading.Event()
    release = threading.Event()
    finished = threading.Event()
    stop_returned = threading.Event()
    loop = _loop(tmp_path, monkeypatch)
    probe = _CloseProbe(finished)
    loop.node = probe
    loop._started = True

    def blocked_iteration() -> None:
        entered.set()
        release.wait(timeout=4.0)
        finished.set()

    monkeypatch.setattr(loop, "_run", blocked_iteration)
    worker = threading.Thread(target=loop._thread_main, name="active-poll-test")
    loop._t = worker
    worker.start()
    assert entered.wait(timeout=2.0)

    def request_stop() -> None:
        try:
            loop.stop()
        finally:
            stop_returned.set()

    stopper = threading.Thread(target=request_stop, name="stop-controller")
    stopper.start()
    try:
        assert loop._stop.wait(timeout=2.0)
        # Before this correction, stop() returned and closed the node even
        # while the test's in-flight packet iteration was still blocked.
        assert not stop_returned.wait(timeout=0.1)
        assert not probe.closed.is_set()
    finally:
        release.set()
        stopper.join(timeout=5.0)
        loop.join(timeout=5.0)

    assert not stopper.is_alive()
    assert not worker.is_alive()
    assert stop_returned.is_set()
    assert probe.closed.is_set()
    assert probe.calls == 1
    assert probe.raced is False
    assert loop._started is False
    loop.stop()
    assert probe.calls == 1


def test_stop_without_thread_remains_idempotent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    loop = _loop(tmp_path, monkeypatch)
    finished = threading.Event()
    finished.set()
    probe = _CloseProbe(finished)
    loop.node = probe
    loop.stop()
    loop.stop()
    assert probe.closed.is_set()
    assert probe.calls == 1
    assert probe.raced is False


def test_network_thread_self_stop_defers_close_until_finalizer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    loop = _loop(tmp_path, monkeypatch)
    finished = threading.Event()
    probe = _CloseProbe(finished)
    loop.node = probe
    loop._started = True
    requested = threading.Event()

    def request_stop_in_loop() -> None:
        loop.stop()
        assert not probe.closed.is_set()
        finished.set()
        requested.set()

    monkeypatch.setattr(loop, "_run", request_stop_in_loop)
    worker = threading.Thread(target=loop._thread_main, name="self-stop-test")
    loop._t = worker
    worker.start()
    loop.join(timeout=3.0)
    assert not worker.is_alive()
    assert requested.is_set()
    assert probe.closed.is_set()
    assert probe.calls == 1
    assert not probe.raced
