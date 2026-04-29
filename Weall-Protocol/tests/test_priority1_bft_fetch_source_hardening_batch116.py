from __future__ import annotations

from weall.net.net_loop import NetLoopConfig, NetMeshLoop


class _DummyExecutor:
    def __init__(self, wants: list[dict]) -> None:
        self.chain_id = "bft-live"
        self._wants = [dict(item) for item in wants]
        self.cached: list[dict] = []

    def snapshot(self) -> dict:
        return {}

    def bft_resolved_pending_fetch_request_descriptors(self) -> list[dict]:
        return [dict(item) for item in self._wants]

    def bft_cache_remote_block(self, blk: dict) -> bool:
        self.cached.append(dict(blk))
        return False


class _DummyNode:
    def __init__(self, chain_id: str) -> None:
        self.cfg = type(
            "Cfg", (), {"chain_id": chain_id, "schema_version": "1", "tx_index_hash": "0"}
        )()


def _make_loop(executor: _DummyExecutor) -> NetMeshLoop:
    loop = NetMeshLoop(
        executor=executor,
        mempool=object(),
        cfg=NetLoopConfig(
            enabled=False,
            bind_host="127.0.0.1",
            bind_port=30303,
            tick_ms=25,
            schema_version="1",
        ),
    )
    loop.node = _DummyNode("bft-live")
    loop._bft_enabled = True
    loop._bft_fetch_enabled = True
    loop._bft_fetch_interval_ms = 1
    loop._bft_fetch_cooldown_ms = 1
    loop._bft_fetch_batch = 8
    return loop


def test_bft_fetch_source_penalty_skips_recent_mismatch_source_batch116(monkeypatch) -> None:
    ex = _DummyExecutor(
        [{"block_id": "wanted-parent", "block_hash": "", "reason": "missing_parent"}]
    )
    loop = _make_loop(ex)
    loop._bft_fetch_sources = ["http://peer1", "http://peer2"]
    loop._bft_fetch_source_penalty_ms = 1_000

    now = {"value": 10_000}
    calls: list[str] = []

    def _fake_now_ms() -> int:
        return int(now["value"])

    def _fake_get(url: str, *, timeout_s: float = 2.0):
        calls.append(url)
        if url.startswith("http://peer1/"):
            return {
                "ok": True,
                "block": {
                    "block_id": "evil-other",
                    "height": 1,
                    "prev_block_id": "genesis",
                    "txs": [],
                    "receipts": [],
                },
            }
        return None

    import weall.net.net_loop as net_loop_mod

    monkeypatch.setattr(net_loop_mod, "_now_ms", _fake_now_ms)
    monkeypatch.setattr(net_loop_mod, "_http_get_json", _fake_get)

    loop._bft_fetch_tick()
    assert calls == [
        "http://peer1/v1/state/block/wanted-parent",
        "http://peer2/v1/state/block/wanted-parent",
    ]
    assert loop._bft_fetch_source_cooldowns["http://peer1"] == 11_000

    calls.clear()
    now["value"] = 10_002
    loop._bft_fetch_tick()
    assert calls == ["http://peer2/v1/state/block/wanted-parent"]


def test_bft_fetch_source_rotation_advances_per_request_batch116(monkeypatch) -> None:
    ex = _DummyExecutor(
        [
            {"block_id": "missing-a", "block_hash": "", "reason": "missing_parent"},
            {"block_id": "missing-b", "block_hash": "", "reason": "missing_parent"},
        ]
    )
    loop = _make_loop(ex)
    loop._bft_fetch_sources = ["http://peer1", "http://peer2", "http://peer3"]

    now = {"value": 50_000}
    calls: list[str] = []

    def _fake_now_ms() -> int:
        return int(now["value"])

    def _fake_get(url: str, *, timeout_s: float = 2.0):
        calls.append(url)
        return None

    import weall.net.net_loop as net_loop_mod

    monkeypatch.setattr(net_loop_mod, "_now_ms", _fake_now_ms)
    monkeypatch.setattr(net_loop_mod, "_http_get_json", _fake_get)

    loop._bft_fetch_tick()

    assert calls[:3] == [
        "http://peer1/v1/state/block/missing-a",
        "http://peer2/v1/state/block/missing-a",
        "http://peer3/v1/state/block/missing-a",
    ]
    assert calls[3:6] == [
        "http://peer2/v1/state/block/missing-b",
        "http://peer3/v1/state/block/missing-b",
        "http://peer1/v1/state/block/missing-b",
    ]
