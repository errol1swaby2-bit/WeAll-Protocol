from __future__ import annotations

import threading
import time

import pytest

from weall.net.messages import BftVoteMsg, MsgType, StateSyncRequestMsg, WireHeader
from weall.net.net_loop import NetLoopConfig, NetMeshLoop
from weall.net.node import NetConfig, NetNode
from weall.net.state_sync import (
    DEFAULT_STATE_SYNC_MAX_RESPONSE_BYTES,
    StateSyncService,
    StateSyncVerifyError,
)
from weall.net.transport_memory import InMemoryTransport


def _header(mtype: str, corr_id: str = "corr-1") -> WireHeader:
    return WireHeader(
        type=mtype,
        chain_id="test",
        schema_version="1",
        tx_index_hash="deadbeef",
        corr_id=corr_id,
    )


def _request(
    corr_id: str,
    *,
    mode: str = "snapshot",
    selector: dict | None = None,
    from_height: int = 0,
    to_height: int | None = None,
) -> StateSyncRequestMsg:
    return StateSyncRequestMsg(
        header=_header(MsgType.STATE_SYNC_REQUEST, corr_id),
        mode=mode,  # type: ignore[arg-type]
        selector=selector,
        from_height=from_height,
        to_height=to_height,
    )


def _cfg(peer_id: str = "server") -> NetConfig:
    return NetConfig(
        chain_id="test",
        schema_version="1",
        tx_index_hash="deadbeef",
        peer_id=peer_id,
    )


def _established(node: NetNode, peer_id: str):
    rec = node._ensure_peer(peer_id)
    rec.router.handshake.status = "ESTABLISHED"
    rec.router.handshake.session_id = f"session-{peer_id}"
    return rec


def test_missing_trusted_anchor_rejects_before_state_materialization() -> None:
    calls = 0

    def _state_provider():
        nonlocal calls
        calls += 1
        raise AssertionError("state provider must not run")

    service = StateSyncService(
        chain_id="test",
        schema_version="1",
        tx_index_hash="deadbeef",
        state_provider=_state_provider,
        require_trusted_anchor=True,
    )
    response = service.handle_request(_request("missing-anchor"))

    assert response.ok is False
    assert response.reason == "trusted_anchor_required"
    assert calls == 0


def test_malformed_trusted_anchor_rejects_before_state_materialization() -> None:
    calls = 0

    def _state_provider():
        nonlocal calls
        calls += 1
        raise AssertionError("state provider must not run")

    service = StateSyncService(
        chain_id="test",
        schema_version="1",
        tx_index_hash="deadbeef",
        state_provider=_state_provider,
        require_trusted_anchor=True,
    )
    response = service.handle_request(
        _request("bad-anchor", selector={"trusted_anchor": {"height": -1}})
    )

    assert response.ok is False
    assert response.reason == "trusted_anchor_invalid"
    assert calls == 0


def test_bad_delta_range_rejects_before_state_materialization() -> None:
    calls = 0

    def _state_provider():
        nonlocal calls
        calls += 1
        raise AssertionError("state provider must not run")

    service = StateSyncService(
        chain_id="test",
        schema_version="1",
        tx_index_hash="deadbeef",
        state_provider=_state_provider,
        block_provider=lambda _height: None,
    )
    response = service.handle_request(
        _request("bad-range", mode="delta", from_height=10, to_height=9)
    )

    assert response.ok is False
    assert response.reason == "bad_height_range"
    assert calls == 0


def test_production_response_caps_are_finite(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    service = StateSyncService(
        chain_id="test",
        schema_version="1",
        tx_index_hash="deadbeef",
        state_provider=lambda: {},
    )
    assert 0 < service.max_snapshot_bytes <= DEFAULT_STATE_SYNC_MAX_RESPONSE_BYTES
    assert 0 < service.max_delta_bytes <= DEFAULT_STATE_SYNC_MAX_RESPONSE_BYTES

    monkeypatch.setenv("WEALL_SYNC_MAX_SNAPSHOT_BYTES", "0")
    with pytest.raises(StateSyncVerifyError, match="unsafe_sync_snapshot_cap_unbounded"):
        StateSyncService(
            chain_id="test",
            schema_version="1",
            tx_index_hash="deadbeef",
            state_provider=lambda: {},
        )


def test_production_network_profile_cannot_disable_trusted_anchor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_SYNC_REQUIRE_TRUSTED_ANCHOR", "0")
    with pytest.raises(StateSyncVerifyError, match="unsafe_sync_trusted_anchor_disabled"):
        StateSyncService(
            chain_id="test",
            schema_version="1",
            tx_index_hash="deadbeef",
            state_provider=lambda: {},
            require_trusted_anchor=True,
        )


def test_snapshot_response_has_finite_service_cap() -> None:
    state = {"height": 0, "accounts": {"alice": {"blob": "x" * 8_192}}}
    service = StateSyncService(
        chain_id="test",
        schema_version="1",
        tx_index_hash="deadbeef",
        state_provider=lambda: state,
        max_snapshot_bytes=512,
    )
    response = service.handle_request(_request("oversize"))
    assert response.ok is False
    assert response.reason == "snapshot_too_large"
    assert response.snapshot is None


def test_valid_state_sync_work_does_not_block_bft_router_progress() -> None:
    started = threading.Event()
    release = threading.Event()
    vote_seen = threading.Event()

    def _slow_state_provider():
        started.set()
        assert release.wait(2.0)
        return {"height": 0, "accounts": {}}

    service = StateSyncService(
        chain_id="test",
        schema_version="1",
        tx_index_hash="deadbeef",
        state_provider=_slow_state_provider,
    )
    node = NetNode(
        cfg=_cfg(),
        sync_service=service,
        transport=InMemoryTransport(),
        on_bft_vote=lambda _peer_id, _msg: vote_seen.set(),
    )
    rec = _established(node, "peer-a")

    begin = time.monotonic()
    response = rec.router.handle_message(_request("slow-sync"))
    assert response is None
    assert time.monotonic() - begin < 0.5
    assert started.wait(1.0)

    vote = BftVoteMsg(
        header=_header(MsgType.BFT_VOTE, "vote-1"),
        view=1,
        vote={"block_id": "b1"},
    )
    begin = time.monotonic()
    rec.router.handle_message(vote)
    assert vote_seen.is_set()
    assert time.monotonic() - begin < 0.5

    release.set()
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline and node.sync_work_debug()["outstanding"]:
        node.tick(max_packets=0)
        time.sleep(0.01)
    assert node.sync_work_debug()["outstanding"] == 0
    node.close()


def test_state_sync_worker_has_global_and_per_peer_work_budgets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WEALL_NET_SYNC_WORK_MAX", "2")
    monkeypatch.setenv("WEALL_NET_SYNC_WORK_PER_PEER_MAX", "1")
    started = threading.Event()
    release = threading.Event()

    def _slow_state_provider():
        started.set()
        assert release.wait(2.0)
        return {"height": 0, "accounts": {}}

    service = StateSyncService(
        chain_id="test",
        schema_version="1",
        tx_index_hash="deadbeef",
        state_provider=_slow_state_provider,
    )
    node = NetNode(cfg=_cfg(), sync_service=service, transport=InMemoryTransport())
    peer_a = _established(node, "peer-a")
    peer_b = _established(node, "peer-b")
    peer_c = _established(node, "peer-c")

    assert peer_a.router.handle_message(_request("a-1")) is None
    assert started.wait(1.0)

    same_peer = peer_a.router.handle_message(_request("a-2"))
    assert same_peer is not None
    assert same_peer.reason == "sync_busy"

    assert peer_b.router.handle_message(_request("b-1")) is None
    global_busy = peer_c.router.handle_message(_request("c-1"))
    assert global_busy is not None
    assert global_busy.reason == "sync_busy"
    assert node.sync_work_debug()["outstanding"] == 2

    release.set()
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline and node.sync_work_debug()["outstanding"]:
        node.tick(max_packets=0)
        time.sleep(0.01)
    assert node.sync_work_debug()["outstanding"] == 0
    node.close()


def test_net_loop_builds_state_sync_with_profile_trusted_anchor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("weall.net.net_loop._is_prod", lambda: True)

    class _Executor:
        chain_id = "test"
        tx_index = None

        def tx_index_hash(self):
            return "deadbeef"

        def _schema_version(self):
            return "1"

        def read_state(self):
            return {"height": 0}

        def get_block_by_height(self, _height):
            return None

    class _Mempool:
        pass

    loop = NetMeshLoop(
        executor=_Executor(),
        mempool=_Mempool(),
        cfg=NetLoopConfig(
            enabled=False,
            bind_host="127.0.0.1",
            bind_port=0,
            tick_ms=25,
            schema_version="1",
        ),
    )
    node = loop._build_node()
    assert node.sync_service is not None
    assert node.sync_service.require_trusted_anchor is True
    node.close()


def test_state_sync_result_drain_is_bounded_per_tick(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WEALL_NET_SYNC_WORK_MAX", "2")
    monkeypatch.setenv("WEALL_NET_SYNC_WORK_PER_PEER_MAX", "2")
    monkeypatch.setenv("WEALL_NET_SYNC_RESULTS_PER_TICK", "1")

    service = StateSyncService(
        chain_id="test",
        schema_version="1",
        tx_index_hash="deadbeef",
        state_provider=lambda: {"height": 0, "accounts": {}},
    )
    node = NetNode(cfg=_cfg(), sync_service=service, transport=InMemoryTransport())
    peer = _established(node, "peer-a")

    assert peer.router.handle_message(_request("drain-1")) is None
    assert peer.router.handle_message(_request("drain-2")) is None

    deadline = time.monotonic() + 2.0
    before = node.sync_work_debug()
    while time.monotonic() < deadline:
        before = node.sync_work_debug()
        if before["completed_waiting"] == 2:
            break
        time.sleep(0.01)

    assert before["outstanding"] == 2
    assert before["completed_waiting"] == 2
    node.tick(max_packets=0)
    after_one = node.sync_work_debug()
    assert after_one["completed_waiting"] == 1
    assert after_one["outstanding"] == 1
    node.tick(max_packets=0)
    after_two = node.sync_work_debug()
    assert after_two["completed_waiting"] == 0
    assert after_two["outstanding"] == 0
    node.close()
