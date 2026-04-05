from __future__ import annotations

from weall.runtime.helper_dispatch import HelperCertificateStore, HelperDispatchContext
from weall.runtime.helper_replay_guard import HelperRateBudget, HelperReplayGuard


def test_replay_guard_budget_duplicate_and_conflict_paths_batch11() -> None:
    guard = HelperReplayGuard(budget=HelperRateBudget(per_helper_per_window=3, per_plan_total=10, window_ms=5_000))

    first = {
        "receipt_id": "r1",
        "helper_id": "h1",
        "plan_id": "p1",
        "lane_id": "L1",
        "descriptor_hash": "d1",
    }
    second = {
        "receipt_id": "r2",
        "helper_id": "h1",
        "plan_id": "p1",
        "lane_id": "L1",
        "descriptor_hash": "d1",
    }
    conflict = {
        "receipt_id": "r3",
        "helper_id": "h1",
        "plan_id": "p1",
        "lane_id": "L1",
        "descriptor_hash": "DIFFERENT",
    }

    assert guard.observe_artifact(first, now_ms=1000).reason == "accepted"
    assert guard.observe_artifact({**first}, now_ms=1001).reason == "duplicate_artifact"
    assert guard.observe_artifact(second, now_ms=1002).reason == "accepted"
    assert guard.observe_artifact(conflict, now_ms=1003).reason == "conflicting_artifact_for_same_helper_lane"


def test_replay_guard_budget_rate_limit_then_window_recovery_batch11() -> None:
    guard = HelperReplayGuard(budget=HelperRateBudget(per_helper_per_window=2, per_plan_total=10, window_ms=100))

    def artifact(i: int) -> dict[str, str]:
        return {
            "receipt_id": f"r{i}",
            "helper_id": "h1",
            "plan_id": "p1",
            "lane_id": f"L{i}",
            "descriptor_hash": f"d{i}",
        }

    assert guard.observe_artifact(artifact(1), now_ms=1000).accepted is True
    assert guard.observe_artifact(artifact(2), now_ms=1050).accepted is True
    limited = guard.observe_artifact(artifact(3), now_ms=1099)
    assert limited.accepted is False
    assert limited.reason == "helper_rate_budget_exceeded"

    recovered = guard.observe_artifact(artifact(4), now_ms=1201)
    assert recovered.accepted is True
    assert recovered.reason == "accepted"


def test_certificate_store_budget_window_and_plan_total_fail_closed_batch11() -> None:
    store = HelperCertificateStore(
        context=HelperDispatchContext(
            chain_id="c1",
            block_height=1,
            view=1,
            leader_id="v1",
            validator_epoch=1,
            validator_set_hash="vh",
            plan_id="plan-1",
        ),
        budget=HelperRateBudget(per_helper_per_window=10, per_plan_total=2, window_ms=5_000),
        helper_timeout_ms=50,
    )

    not_started = store.accept_certificate(
        {"receipt_id": "r1", "helper_id": "h1", "plan_id": "plan-1", "lane_id": "L1", "descriptor_hash": "d1"},
        now_ms=1000,
    )
    assert not_started.reason == "plan_window_not_started"

    store.open_plan_window(plan_id="plan-1", now_ms=1000)
    assert store.accept_certificate(
        {"receipt_id": "r1", "helper_id": "h1", "plan_id": "plan-1", "lane_id": "L1", "descriptor_hash": "d1"},
        now_ms=1001,
    ).reason == "accepted"
    assert store.accept_certificate(
        {"receipt_id": "r2", "helper_id": "h2", "plan_id": "plan-1", "lane_id": "L2", "descriptor_hash": "d2"},
        now_ms=1002,
    ).reason == "accepted"

    capped = store.accept_certificate(
        {"receipt_id": "r3", "helper_id": "h3", "plan_id": "plan-1", "lane_id": "L3", "descriptor_hash": "d3"},
        now_ms=1003,
    )
    assert capped.reason == "plan_total_budget_exceeded"

    closed = store.accept_certificate(
        {"receipt_id": "r4", "helper_id": "h4", "plan_id": "plan-1", "lane_id": "L4", "descriptor_hash": "d4"},
        now_ms=1050,
    )
    assert closed.reason == "plan_window_closed"
