from __future__ import annotations

from pathlib import Path

from weall.runtime.executor import WeAllExecutor
from weall.net.net_loop import NetMeshLoop, NetLoopConfig


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


class _DummyNode:
    def __init__(self, chain_id: str) -> None:
        self.cfg = type("Cfg", (), {"chain_id": chain_id, "schema_version": "1", "tx_index_hash": "0"})()


def test_executor_resolves_fetch_descriptor_to_canonical_block_id(tmp_path: Path) -> None:
    ex = WeAllExecutor(
        db_path=str(tmp_path / "ledger.sqlite"),
        chain_id="weall:test",
        node_id="@node",
        tx_index_path=str(_repo_root() / "generated" / "tx_index.json"),
    )
    ex._known_block_ids_by_hash["hash-1"] = "canonical-id"
    ex.bft_pending_fetch_request_descriptors = lambda: [  # type: ignore[method-assign]
        {"block_id": "alias-id", "block_hash": "hash-1", "reason": "missing_parent"},
        {"block_id": "canonical-id", "block_hash": "hash-1", "reason": "missing_qc_block"},
    ]

    descs = ex.bft_resolved_pending_fetch_request_descriptors()
    assert descs == [
        {
            "block_id": "canonical-id",
            "block_hash": "hash-1",
            "reason": "missing_parent",
            "requested_block_id": "alias-id",
        }
    ]
    assert ex.bft_pending_fetch_requests() == ["canonical-id"]


def test_net_loop_prefers_resolved_fetch_descriptors(tmp_path: Path, monkeypatch) -> None:
    ex = WeAllExecutor(
        db_path=str(tmp_path / "ledger.sqlite"),
        chain_id="weall:test",
        node_id="@node",
        tx_index_path=str(_repo_root() / "generated" / "tx_index.json"),
    )
    ex.bft_resolved_pending_fetch_request_descriptors = lambda: [  # type: ignore[method-assign]
        {"block_id": "canonical-id", "block_hash": "hash-1", "reason": "missing_parent", "requested_block_id": "alias-id"}
    ]
    loop = NetMeshLoop(executor=ex, mempool=object(), cfg=NetLoopConfig(enabled=False, bind_host="127.0.0.1", bind_port=30303, tick_ms=25, schema_version="1"))
    loop.node = _DummyNode("weall:test")
    loop._bft_enabled = True
    loop._bft_fetch_enabled = True
    loop._bft_fetch_interval_ms = 1
    loop._bft_fetch_cooldown_ms = 1
    loop._bft_fetch_sources = ["http://peer1"]

    seen = []
    def _fake_fetch(base: str, bid: str):
        seen.append((base, bid))
        return None

    monkeypatch.setattr(loop, "_fetch_committed_block", _fake_fetch)
    loop._bft_fetch_tick()
    assert seen == [("http://peer1", "canonical-id")]
