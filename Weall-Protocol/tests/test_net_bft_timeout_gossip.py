from __future__ import annotations

from weall.net.messages import BftTimeoutMsg, MsgType, WireHeader
from weall.net.net_loop import NetMeshLoop, net_loop_config_from_env


class _FakeNode:
    def __init__(self) -> None:
        self.calls: list[tuple[object, str]] = []

    def broadcast_message(self, msg, exclude_peer_id: str = "") -> int:
        self.calls.append((msg, exclude_peer_id))
        return 1


class _FakeExecutor:
    def bft_on_timeout(self, payload):
        # net loop expects a dict or empty
        return {}


class _FakeMempool:
    def read_all(self):
        return []


def test_net_loop_gossips_bft_timeout_with_dedupe(monkeypatch):
    # Keep TTL large to make dedupe deterministic.
    cfg = net_loop_config_from_env()
    loop = NetMeshLoop(executor=_FakeExecutor(), mempool=_FakeMempool(), cfg=cfg)
    loop.node = _FakeNode()
    loop._bft_timeout_seen_ttl_ms = 999999

    hdr = WireHeader(type=MsgType.BFT_TIMEOUT, chain_id="test", schema_version="1", tx_index_hash="deadbeef")
    msg = BftTimeoutMsg(
        header=hdr,
        view=7,
        timeout={"t": "TIMEOUT", "view": 7, "high_qc_id": "x", "signer": "@a", "pubkey": "p", "sig": "s"},
    )

    loop._on_bft_timeout("peer1", msg)
    assert len(loop.node.calls) == 1
    m0, ex0 = loop.node.calls[0]
    assert m0 == msg
    assert ex0 == "peer1"

    # Second delivery should be deduped and not re-broadcast.
    loop._on_bft_timeout("peer2", msg)
    assert len(loop.node.calls) == 1
