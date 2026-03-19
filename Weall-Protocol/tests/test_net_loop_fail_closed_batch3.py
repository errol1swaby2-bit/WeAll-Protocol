from __future__ import annotations

from types import SimpleNamespace

import pytest

from weall.net.net_loop import (
    BftFetchDescriptorError,
    BftOutboundReplayError,
    NetLoopConfig,
    NetMeshLoop,
)


class _FakeNode:
    def __init__(self) -> None:
        self.cfg = SimpleNamespace(
            peer_id="local-peer", chain_id="chain-A", schema_version="1", tx_index_hash="deadbeef"
        )
        self.calls = []

    def broadcast_message(self, msg, exclude_peer_id: str = "") -> int:
        self.calls.append((msg, exclude_peer_id))
        return 1


class _FakeExecutorBadOutbound:
    def bft_pending_outbound_messages(self):
        return [{"kind": "vote", "payload": "bad-payload"}]


class _FakeExecutorResolverBoom:
    def bft_pending_fetch_request_descriptors(self):
        return [{"block_id": "block-1", "block_hash": "", "reason": "missing_qc_block"}]

    def bft_resolve_fetch_request_descriptor(self, desc):
        raise ValueError("boom")


class _FakeExecutorCacheBoom:
    def bft_pending_fetch_request_descriptors(self):
        return [{"block_id": "block-1", "block_hash": "", "reason": "missing_qc_block"}]

    def bft_resolve_fetch_request_descriptor(self, desc):
        return desc

    def bft_cache_remote_block(self, block_json):
        raise ValueError("cache boom")


class _FakeMempool:
    def read_all(self):
        return []


def _mk_loop(executor) -> NetMeshLoop:
    loop = NetMeshLoop(
        executor=executor,
        mempool=_FakeMempool(),
        cfg=NetLoopConfig(
            enabled=False, bind_host="127.0.0.1", bind_port=30303, tick_ms=25, schema_version="1"
        ),
    )
    loop.node = _FakeNode()
    loop._bft_enabled = True
    loop._bft_fetch_sources = ["http://peer1"]
    return loop


def test_outbound_bft_tick_prod_fails_closed_on_corrupt_pending_outbound(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    loop = _mk_loop(_FakeExecutorBadOutbound())
    with pytest.raises(BftOutboundReplayError, match="invalid_payload"):
        loop._outbound_bft_tick()


def test_bft_fetch_tick_prod_fails_closed_on_descriptor_resolution_error(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    loop = _mk_loop(_FakeExecutorResolverBoom())
    with pytest.raises(BftFetchDescriptorError, match="descriptor_resolution_failed"):
        loop._bft_fetch_tick()


def test_bft_fetch_tick_prod_fails_closed_on_cache_remote_block_error(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    loop = _mk_loop(_FakeExecutorCacheBoom())

    import weall.net.net_loop as net_loop_mod

    monkeypatch.setattr(
        net_loop_mod,
        "_http_get_json",
        lambda url, *, timeout_s=2.0: {
            "ok": True,
            "block": {"block_id": "block-1", "header": {"block_hash": "abc"}},
        },
    )
    with pytest.raises(BftFetchDescriptorError, match="cache_remote_block_failed"):
        loop._bft_fetch_tick()
