from __future__ import annotations

from types import SimpleNamespace

import pytest

from weall.net import net_loop as net_loop_module
from weall.net.net_loop import NetMeshLoop
from weall.runtime import bft_hotstuff
from weall.runtime import bft_runtime_adapter as adapter
from weall.runtime.bft_hotstuff import HotStuffBFT


class _RollbackExecutor:
    def __init__(self) -> None:
        self._bft = HotStuffBFT(chain_id="pbz")
        self._bft.view = 2
        self._bft.timeout_base_ms = 1_000
        self._bft.timeout_backoff_exp = 0
        self._bft.timeout_backoff_cap = 4
        self._bft.last_progress_ms = 10_000
        self.timeout_calls = 0
        self.persist_calls = 0

    def _local_validator_account(self) -> str:
        return "v2"

    def _active_validators(self) -> list[str]:
        return ["v1", "v2", "v3", "v4"]

    def bft_make_timeout(self, *, view: int):
        self.timeout_calls += 1
        self._bft.note_timeout_emitted(view=int(view))
        return {"t": "TIMEOUT", "view": int(view), "signer": "v2"}

    def bft_handle_timeout(self, _timeout_json):
        return None

    def _persist_bft_state(self) -> None:
        self.persist_calls += 1


def test_restored_pacemaker_anchor_must_rebase_to_current_clock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(bft_hotstuff, "_now_ms", lambda: 5_000)
    hs = HotStuffBFT(chain_id="pbz")
    hs.load_from_state({"bft": {"last_progress_ms": 90_000}})
    assert hs.last_progress_ms == 5_000


def test_live_clock_rollback_must_rebase_then_wait_one_full_timeout() -> None:
    ex = _RollbackExecutor()

    assert adapter.bft_timeout_check(ex, now_ms=5_000) is None
    assert ex._bft.last_progress_ms == 5_000
    assert ex.persist_calls == 1
    assert ex.timeout_calls == 0

    assert adapter.bft_timeout_check(ex, now_ms=5_999) is None
    assert ex.timeout_calls == 0

    out = adapter.bft_timeout_check(ex, now_ms=6_000)
    assert isinstance(out, dict)
    assert out["view"] == 2
    assert ex.timeout_calls == 1


def _rollback_loop() -> tuple[NetMeshLoop, dict[str, int]]:
    counts = {"proposal": 0, "drive": 0, "timeout": 0}
    executor = SimpleNamespace(
        bft_pending_outbound_messages=lambda: [],
        bft_leader_propose=lambda: counts.__setitem__("proposal", counts["proposal"] + 1),
        bft_drive_timeouts=lambda _now: counts.__setitem__("drive", counts["drive"] + 1) or [],
        bft_timeout_check=lambda: counts.__setitem__("timeout", counts["timeout"] + 1),
    )
    loop = object.__new__(NetMeshLoop)
    loop.node = object()
    loop._executor = executor
    loop._bft_propose_interval_ms = 250
    loop._bft_vote_interval_ms = 250
    loop._bft_timeout_interval_ms = 250
    loop._last_bft_propose_ms = 10_000
    loop._last_bft_vote_ms = 10_000
    loop._last_bft_timeout_ms = 10_000
    loop._broadcast_bft_vote = lambda _payload: None
    loop._broadcast_bft_timeout = lambda _payload: None
    loop._broadcast_bft_proposal = lambda _payload: None
    return loop, counts


def test_outbound_bft_scheduler_must_rearm_after_wall_clock_rollback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(net_loop_module, "_now_ms", lambda: 5_000)
    loop, counts = _rollback_loop()

    loop._outbound_bft_tick()

    assert counts == {"proposal": 1, "drive": 1, "timeout": 1}
    assert loop._last_bft_propose_ms == 5_000
    assert loop._last_bft_vote_ms == 5_000
    assert loop._last_bft_timeout_ms == 5_000


def test_bft_fetch_scheduler_must_rearm_after_wall_clock_rollback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(net_loop_module, "_now_ms", lambda: 5_000)
    loop = object.__new__(NetMeshLoop)
    loop._bft_fetch_enabled = True
    loop._bft_fetch_interval_ms = 500
    loop._last_bft_fetch_ms = 10_000
    loop._executor = SimpleNamespace(bft_resolved_pending_fetch_request_descriptors=lambda: [])
    calls = {"gauges": 0}
    loop._record_net_metric_gauges = lambda: calls.__setitem__("gauges", calls["gauges"] + 1)

    loop._bft_fetch_tick()

    assert loop._last_bft_fetch_ms == 5_000
    assert calls["gauges"] == 1


def test_missing_block_fetch_cooldown_must_rearm_after_clock_rollback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(net_loop_module, "_now_ms", lambda: 5_000)
    loop = object.__new__(NetMeshLoop)
    loop._bft_fetch_enabled = True
    loop._bft_fetch_interval_ms = 500
    loop._last_bft_fetch_ms = 0
    loop._bft_fetch_batch = 8
    loop._bft_fetch_cooldown_ms = 1_000
    loop._bft_fetch_cooldowns = {"block-1": 10_000}
    loop._executor = SimpleNamespace(
        bft_resolved_pending_fetch_request_descriptors=lambda: [{"block_id": "block-1"}]
    )
    loop._bft_fetch_base_urls = lambda: ["http://peer-a"]
    loop._candidate_bft_fetch_sources = lambda *, now_ms=None: ["http://peer-a"]
    calls = {"fetch": 0}
    loop._fetch_committed_block = lambda _base, _bid: calls.__setitem__("fetch", calls["fetch"] + 1)
    loop._record_net_metric_gauges = lambda: None

    loop._bft_fetch_tick()

    assert calls["fetch"] == 1
    assert loop._bft_fetch_cooldowns["block-1"] == 6_000


def test_bft_fetch_source_penalty_must_not_blackhole_source_after_clock_rollback() -> None:
    loop = object.__new__(NetMeshLoop)
    loop._bft_fetch_source_cursor = 0
    loop._bft_fetch_source_penalty_ms = 1_000
    loop._bft_fetch_source_cooldowns = {"http://peer-a": 10_000}
    loop._bft_fetch_base_urls = lambda: ["http://peer-a"]

    assert loop._candidate_bft_fetch_sources(now_ms=5_000) == ["http://peer-a"]
    assert "http://peer-a" not in loop._bft_fetch_source_cooldowns


def test_normal_fetch_source_penalty_remains_enforced() -> None:
    loop = object.__new__(NetMeshLoop)
    loop._bft_fetch_source_cursor = 0
    loop._bft_fetch_source_penalty_ms = 1_000
    loop._bft_fetch_source_cooldowns = {"http://peer-a": 10_000}
    loop._bft_fetch_base_urls = lambda: ["http://peer-a"]

    assert loop._candidate_bft_fetch_sources(now_ms=9_500) == []
    assert loop._bft_fetch_source_cooldowns["http://peer-a"] == 10_000
