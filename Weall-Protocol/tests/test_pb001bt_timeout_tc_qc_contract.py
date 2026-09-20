from __future__ import annotations

from types import SimpleNamespace

from weall.net.messages import BftTimeoutMsg, MsgType, WireHeader
from weall.net.net_loop import NetLoopConfig, NetMeshLoop
from weall.runtime import bft_runtime_adapter


class _RuntimeThresholdStub:
    def bft_handle_timeout(self, timeout):
        return 8


class _FakeNode:
    def __init__(self) -> None:
        self.cfg = SimpleNamespace(
            peer_id="local-peer",
            chain_id="chain-A",
            schema_version="1",
            tx_index_hash="deadbeef",
        )
        self.calls: list[tuple[object, str]] = []

    def broadcast_message(self, msg, exclude_peer_id: str = "") -> int:
        self.calls.append((msg, exclude_peer_id))
        return 1


class _FakeMempool:
    def read_all(self):
        return []


class _LegacyQcLikeTimeoutExecutor:
    def __init__(self) -> None:
        self.applied_qcs: list[dict] = []

    def bft_on_timeout(self, timeout):
        return {
            "t": "QC",
            "chain_id": "chain-A",
            "view": int(timeout.get("view") or 0),
            "block_id": str(timeout.get("high_qc_id") or ""),
            "parent_id": "b5",
            "votes": [{"signer": str(timeout.get("signer") or "")}],
        }

    def bft_timeout_was_accepted(self, timeout):
        return True

    def bft_on_qc(self, qc):
        self.applied_qcs.append(dict(qc))
        return {"ok": True}


def _timeout_msg() -> BftTimeoutMsg:
    return BftTimeoutMsg(
        header=WireHeader(
            type=MsgType.BFT_TIMEOUT,
            chain_id="chain-A",
            schema_version="1",
            tx_index_hash="deadbeef",
        ),
        view=7,
        timeout={
            "t": "TIMEOUT",
            "chain_id": "chain-A",
            "view": 7,
            "high_qc_id": "b6",
            "signer": "@v1",
            "pubkey": "pub",
            "sig": "sig",
        },
    )


def test_timeout_threshold_returns_new_view_without_qc_serialization() -> None:
    out = bft_runtime_adapter.bft_on_timeout(_RuntimeThresholdStub(), {"t": "TIMEOUT"})
    assert out == 8
    assert isinstance(out, int)


def test_timeout_result_is_never_reinterpreted_as_qc_by_network() -> None:
    ex = _LegacyQcLikeTimeoutExecutor()
    loop = NetMeshLoop(
        executor=ex,
        mempool=_FakeMempool(),
        cfg=NetLoopConfig(
            enabled=False,
            bind_host="127.0.0.1",
            bind_port=30303,
            tick_ms=25,
            schema_version="1",
        ),
    )
    loop.node = _FakeNode()
    loop._bft_enabled = True

    loop._on_bft_timeout("peer-a", _timeout_msg())

    assert ex.applied_qcs == []
    assert len(loop.node.calls) == 1
