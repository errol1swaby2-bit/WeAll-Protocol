from __future__ import annotations

from types import SimpleNamespace

from weall.net.messages import BftProposalMsg, MsgType, WireHeader
from weall.net.net_loop import NetLoopConfig, NetMeshLoop
from weall.runtime import metrics as metrics_mod


class _Exec:
    chain_id = "weall-dev"

    def __init__(self) -> None:
        self.proposals: list[dict] = []
        self._diag = {
            "pending_remote_blocks": ["b1", "b2"],
            "pending_missing_qcs": ["b3"],
            "pending_fetch_requests": ["b4", "b5", "b6"],
        }

    def snapshot(self):
        return {"height": 0}

    def tx_index_hash(self):
        return "0"

    def _schema_version(self):
        return "1"

    def bft_on_proposal(self, proposal: dict):
        self.proposals.append(dict(proposal))
        return {"view": int(proposal.get("view") or 0), "block_id": str((proposal.get("block") or {}).get("block_id") or "b1")}

    def bft_diagnostics(self):
        return dict(self._diag)


class _Mempool:
    pass


class _Peers:
    def __init__(self, peers: list[str]) -> None:
        self._peers = list(peers)

    def read_list(self):
        return list(self._peers)


class _Node:
    def __init__(self) -> None:
        self.cfg = SimpleNamespace(chain_id="weall-dev", schema_version="1", tx_index_hash="0", peer_id="n1")
        self.broadcasts = []

    def broadcast_message(self, msg, exclude_peer_id: str = "") -> None:
        self.broadcasts.append((msg, exclude_peer_id))



def _reset_metrics() -> None:
    metrics_mod._counters.clear()
    metrics_mod._gauges.clear()



def _loop() -> NetMeshLoop:
    loop = NetMeshLoop(
        executor=_Exec(),
        mempool=_Mempool(),
        cfg=NetLoopConfig(enabled=False, bind_host="127.0.0.1", bind_port=30303, tick_ms=25, schema_version="1"),
    )
    loop.node = _Node()
    loop._bft_enabled = True
    loop._peers_store = _Peers(["tcp://1", "tcp://2", "tcp://3"])
    return loop



def _proposal_msg(*, block: dict, proposer: str = "n2", view: int = 1) -> BftProposalMsg:
    return BftProposalMsg(
        header=WireHeader(type=MsgType.BFT_PROPOSAL, chain_id="weall-dev", schema_version="1", tx_index_hash="0"),
        view=view,
        proposer=proposer,
        block=block,
        justify_qc=None,
    )



def test_oversize_bft_proposal_is_rejected_before_executor() -> None:
    _reset_metrics()
    loop = _loop()
    loop._bft_proposal_max_bytes = 128
    msg = _proposal_msg(block={"block_id": "b1", "height": 1, "view": 1, "blob": "x" * 512})

    loop._on_bft_proposal("peer-a", msg)

    assert loop._executor.proposals == []
    snap = metrics_mod.snapshot()
    assert int(snap["counters"].get("net_bft_proposal_rejected", 0)) >= 1
    assert int(snap["counters"].get("net_bft_proposal_reject_oversize", 0)) >= 1



def test_duplicate_bft_proposal_is_deduped_and_counted() -> None:
    _reset_metrics()
    loop = _loop()
    msg = _proposal_msg(block={"block_id": "b1", "height": 1, "view": 1})

    loop._on_bft_proposal("peer-a", msg)
    loop._on_bft_proposal("peer-a", msg)

    assert len(loop._executor.proposals) == 1
    snap = metrics_mod.snapshot()
    assert int(snap["counters"].get("net_bft_proposal_duplicate", 0)) >= 1



def test_network_metric_gauges_reflect_executor_backlog() -> None:
    _reset_metrics()
    loop = _loop()

    loop._record_net_metric_gauges()

    snap = metrics_mod.snapshot()
    gauges = snap["gauges"]
    assert int(gauges.get("net_bft_pending_remote_blocks", 0)) == 2
    assert int(gauges.get("net_bft_pending_missing_qcs", 0)) == 1
    assert int(gauges.get("net_bft_pending_fetch_requests", 0)) == 3
    assert int(gauges.get("net_peers_configured", 0)) == 3



def test_bft_fetch_sources_are_deduped_and_capped() -> None:
    loop = _loop()
    loop._bft_fetch_sources = ["http://a", "http://a", "http://b", "http://c"]
    loop._bft_fetch_sources_max = 2

    assert loop._bft_fetch_base_urls() == ["http://a", "http://b"]
