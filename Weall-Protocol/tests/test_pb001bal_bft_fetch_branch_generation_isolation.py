from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest

from weall.net.net_loop import NetLoopConfig, NetMeshLoop
from weall.runtime.executor import WeAllExecutor


class _Mempool:
    def read_all(self):
        return []


class _Node:
    def __init__(self) -> None:
        self.cfg = SimpleNamespace(
            peer_id="local",
            chain_id="chain-A",
            schema_version="1",
            tx_index_hash="deadbeef",
        )


class _FetchExecutor:
    def __init__(self) -> None:
        self.chain_id = "chain-A"
        self.generation = 0
        self.cached: list[tuple[dict, str, int | None]] = []

    def read_state(self) -> dict:
        return {}

    def snapshot(self) -> dict:
        return {}

    def bft_branch_generation(self) -> int:
        return int(self.generation)

    def bft_resolved_pending_fetch_request_descriptors(self) -> list[dict]:
        return [
            {
                "block_id": "branch-a-parent",
                "block_hash": "hash-branch-a",
                "reason": "missing_parent",
            }
        ]

    def bft_cache_remote_block(
        self,
        block: dict,
        *,
        expected_block_hash: str = "",
        expected_branch_generation: int | None = None,
    ) -> bool:
        self.cached.append((dict(block), str(expected_block_hash), expected_branch_generation))
        if expected_branch_generation is not None:
            return int(expected_branch_generation) == int(self.generation)
        return True


def _loop(executor: _FetchExecutor) -> NetMeshLoop:
    loop = NetMeshLoop(
        executor=executor,
        mempool=_Mempool(),
        cfg=NetLoopConfig(
            enabled=False,
            bind_host="127.0.0.1",
            bind_port=30303,
            tick_ms=25,
            schema_version="1",
        ),
    )
    loop.node = _Node()
    loop._bft_enabled = True
    loop._bft_fetch_enabled = True
    loop._bft_fetch_interval_ms = 1
    loop._bft_fetch_cooldown_ms = 60_000
    loop._bft_fetch_batch = 8
    loop._bft_fetch_sources = ["http://peer-a"]
    return loop


def test_branch_reset_clears_fetch_request_cooldown_but_preserves_source_penalty() -> None:
    ex = _FetchExecutor()
    loop = _loop(ex)

    loop._bft_fetch_cooldowns = {"branch-a-parent": 99_000}
    loop._bft_fetch_source_cooldowns = {"http://peer-a": 88_000}
    loop._last_bft_fetch_ms = 77_000

    ex.generation = 1

    assert loop._sync_bft_branch_generation() is True
    assert loop._bft_fetch_cooldowns == {}
    assert loop._last_bft_fetch_ms == 0
    assert loop._bft_fetch_source_cooldowns == {"http://peer-a": 88_000}


def test_inflight_fetch_cannot_cache_branch_a_descriptor_after_branch_b_reset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ex = _FetchExecutor()
    loop = _loop(ex)

    monkeypatch.setattr("weall.net.net_loop._now_ms", lambda: 10_000)
    monkeypatch.setattr(
        loop, "_candidate_bft_fetch_sources", lambda *, now_ms=None: ["http://peer-a"]
    )

    def _fetch(_base: str, _block_id: str) -> dict:
        # Simulate a destructive checkpoint completing while the HTTP request is
        # in flight. The fetched body is still exactly the branch-A descriptor.
        ex.generation += 1
        return {
            "block_id": "branch-a-parent",
            "block_hash": "hash-branch-a",
        }

    monkeypatch.setattr(loop, "_fetch_committed_block", _fetch)

    loop._bft_fetch_tick()

    assert ex.cached == []
    assert ex.generation == 1
    # Branch change during the HTTP round trip discards the stale response and
    # re-arms branch-B fetches immediately.
    assert loop._bft_fetch_cooldowns == {}


def test_executor_revalidates_fetch_descriptor_generation_under_branch_lock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ex = WeAllExecutor.__new__(WeAllExecutor)
    ex._bft_branch_lock = threading.RLock()
    ex._bft_branch_generation = 4

    calls: list[tuple[dict, str]] = []

    def _cache(_ex, block_json: dict, *, expected_block_hash: str = "") -> bool:
        calls.append((dict(block_json), str(expected_block_hash)))
        return True

    monkeypatch.setattr("weall.runtime.bft_runtime_adapter.bft_cache_remote_block", _cache)

    stale = ex.bft_cache_remote_block(
        {"block_id": "b4"},
        expected_block_hash="hash-b4",
        expected_branch_generation=3,
    )
    assert stale is False
    assert calls == []

    current = ex.bft_cache_remote_block(
        {"block_id": "b4"},
        expected_block_hash="hash-b4",
        expected_branch_generation=4,
    )
    assert current is True
    assert calls == [({"block_id": "b4"}, "hash-b4")]
