from __future__ import annotations

from types import SimpleNamespace

from weall.net.messages import BftProposalMsg, BftQcMsg, BftVoteMsg, MsgType, WireHeader
from weall.net.net_loop import NetMeshLoop, net_loop_config_from_env


class _FakeNode:
    def __init__(self) -> None:
        self.calls: list[tuple[object, str]] = []
        self.cfg = SimpleNamespace(
            peer_id="local-peer",
            chain_id="test-chain",
            schema_version="1",
            tx_index_hash="deadbeef",
        )

    def broadcast_message(self, msg, exclude_peer_id: str = "") -> int:
        self.calls.append((msg, exclude_peer_id))
        return 1


class _FakeExecutor:
    def __init__(self) -> None:
        self.vote_payloads: list[dict] = []

    def bft_current_view(self) -> int:
        return 11

    def bft_leader_propose(self):
        return {
            "block_id": "b11",
            "height": 11,
            "prev_block_id": "b10",
            "view": 11,
            "header": {
                "chain_id": "test-chain",
                "height": 11,
                "prev_block_hash": "00" * 32,
                "block_ts_ms": 1_700_000_000_011,
                "tx_ids": [],
                "receipts_root": "11" * 32,
                "state_root": "22" * 32,
            },
            "justify_qc": {"block_id": "b10", "view": 10, "votes": []},
        }

    def bft_on_vote(self, payload):
        self.vote_payloads.append(payload)
        return {
            "chain_id": "test-chain",
            "view": int(payload.get("view") or 0),
            "block_id": str(payload.get("block_id") or ""),
            "parent_id": str(payload.get("parent_id") or ""),
            "votes": [payload],
        }


class _FakeMempool:
    def read_all(self):
        return []


def test_outbound_bft_tick_broadcasts_proposal(monkeypatch):
    monkeypatch.setenv("WEALL_NET_ENABLED", "1")
    cfg = net_loop_config_from_env()
    loop = NetMeshLoop(executor=_FakeExecutor(), mempool=_FakeMempool(), cfg=cfg)
    loop.node = _FakeNode()
    loop._bft_enabled = True
    loop._bft_propose_interval_ms = 0
    loop._outbound_bft_tick()

    assert len(loop.node.calls) == 1
    msg, excluded = loop.node.calls[0]
    assert excluded == ""
    assert isinstance(msg, BftProposalMsg)
    assert msg.header.type == MsgType.BFT_PROPOSAL
    assert msg.view == 11
    assert msg.proposer == "local-peer"
    assert msg.block["block_id"] == "b11"
    assert isinstance(msg.justify_qc, dict)
    assert msg.justify_qc["block_id"] == "b10"


def test_on_bft_vote_broadcasts_qc_once(monkeypatch):
    monkeypatch.setenv("WEALL_NET_ENABLED", "1")
    cfg = net_loop_config_from_env()
    ex = _FakeExecutor()
    loop = NetMeshLoop(executor=ex, mempool=_FakeMempool(), cfg=cfg)
    loop.node = _FakeNode()
    loop._bft_enabled = True
    loop._bft_msg_seen_ttl_ms = 999999

    hdr = WireHeader(
        type=MsgType.BFT_VOTE, chain_id="test-chain", schema_version="1", tx_index_hash="deadbeef"
    )
    msg = BftVoteMsg(
        header=hdr,
        view=11,
        vote={
            "t": "VOTE",
            "chain_id": "test-chain",
            "view": 11,
            "block_id": "b11",
            "parent_id": "b10",
            "signer": "@v1",
            "pubkey": "pub",
            "sig": "sig",
        },
    )

    loop._on_bft_vote("peer-a", msg)
    assert len(ex.vote_payloads) == 1
    assert len(loop.node.calls) == 1
    out, excluded = loop.node.calls[0]
    assert excluded == "peer-a"
    assert isinstance(out, BftQcMsg)
    assert out.header.type == MsgType.BFT_QC
    assert out.qc["block_id"] == "b11"

    loop._on_bft_vote("peer-b", msg)
    assert len(ex.vote_payloads) == 1
    assert len(loop.node.calls) == 1
