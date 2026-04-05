
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Set


@dataclass(frozen=True)
class HelperNode:
    node_id: str
    capabilities: frozenset[str]
    max_lanes: int
    current_lanes: int = 0
    healthy: bool = True
    helper_enabled: bool = True


def select_helpers_for_lane(
    *,
    validator_ids: Iterable[str],
    helpers: Dict[str, HelperNode],
    lane_id: str,
    required_capabilities: Set[str],
    exclude_node_id: str | None = None,
    allow_overcommit: bool = False,
) -> List[str]:
    ordered = sorted(dict.fromkeys(validator_ids))
    eligible: List[HelperNode] = []
    for node_id in ordered:
        if exclude_node_id is not None and node_id == exclude_node_id:
            continue
        helper = helpers.get(node_id)
        if helper is None:
            continue
        if not helper.healthy or not helper.helper_enabled:
            continue
        if not required_capabilities.issubset(set(helper.capabilities)):
            continue
        if not allow_overcommit and helper.current_lanes >= helper.max_lanes:
            continue
        eligible.append(helper)
    eligible.sort(key=lambda h: (h.current_lanes, h.node_id))
    return [h.node_id for h in eligible]


def test_helper_selection_is_stable_under_validator_order_permutations() -> None:
    validators_a = ["val-c", "val-a", "val-b"]
    validators_b = ["val-b", "val-c", "val-a"]
    helpers = {
        "val-a": HelperNode("val-a", frozenset({"content", "storage"}), max_lanes=2, current_lanes=1),
        "val-b": HelperNode("val-b", frozenset({"content", "storage"}), max_lanes=2, current_lanes=0),
        "val-c": HelperNode("val-c", frozenset({"content"}), max_lanes=0, current_lanes=0),
    }

    picked_a = select_helpers_for_lane(
        validator_ids=validators_a,
        helpers=helpers,
        lane_id="lane-content-1",
        required_capabilities={"content", "storage"},
        exclude_node_id="leader-1",
    )
    picked_b = select_helpers_for_lane(
        validator_ids=validators_b,
        helpers=helpers,
        lane_id="lane-content-1",
        required_capabilities={"content", "storage"},
        exclude_node_id="leader-1",
    )

    assert picked_a == ["val-b", "val-a"]
    assert picked_b == picked_a


def test_capability_mismatch_fails_closed_instead_of_silently_assigning() -> None:
    validators = ["val-a", "val-b", "val-c"]
    helpers = {
        "val-a": HelperNode("val-a", frozenset({"content"}), max_lanes=2),
        "val-b": HelperNode("val-b", frozenset({"social"}), max_lanes=2),
        "val-c": HelperNode("val-c", frozenset({"governance"}), max_lanes=2),
    }

    picked = select_helpers_for_lane(
        validator_ids=validators,
        helpers=helpers,
        lane_id="lane-storage-1",
        required_capabilities={"storage"},
        exclude_node_id=None,
    )

    assert picked == []


def test_capacity_limit_excludes_full_helpers_when_overcommit_disabled() -> None:
    validators = ["val-a", "val-b", "val-c"]
    helpers = {
        "val-a": HelperNode("val-a", frozenset({"content"}), max_lanes=1, current_lanes=1),
        "val-b": HelperNode("val-b", frozenset({"content"}), max_lanes=3, current_lanes=2),
        "val-c": HelperNode("val-c", frozenset({"content"}), max_lanes=2, current_lanes=0),
    }

    picked = select_helpers_for_lane(
        validator_ids=validators,
        helpers=helpers,
        lane_id="lane-content-2",
        required_capabilities={"content"},
        exclude_node_id=None,
        allow_overcommit=False,
    )

    assert picked == ["val-c", "val-b"]
    assert "val-a" not in picked


def test_overcommit_posture_is_explicit_and_deterministic() -> None:
    validators = ["val-c", "val-a", "val-b"]
    helpers = {
        "val-a": HelperNode("val-a", frozenset({"content"}), max_lanes=1, current_lanes=1),
        "val-b": HelperNode("val-b", frozenset({"content"}), max_lanes=1, current_lanes=1),
        "val-c": HelperNode("val-c", frozenset({"content"}), max_lanes=1, current_lanes=1),
    }

    picked = select_helpers_for_lane(
        validator_ids=validators,
        helpers=helpers,
        lane_id="lane-content-3",
        required_capabilities={"content"},
        exclude_node_id="leader-1",
        allow_overcommit=True,
    )

    assert picked == ["val-a", "val-b", "val-c"]


def test_leader_is_excluded_even_when_otherwise_best_candidate() -> None:
    validators = ["leader-1", "val-a", "val-b"]
    helpers = {
        "leader-1": HelperNode("leader-1", frozenset({"content"}), max_lanes=10, current_lanes=0),
        "val-a": HelperNode("val-a", frozenset({"content"}), max_lanes=10, current_lanes=1),
        "val-b": HelperNode("val-b", frozenset({"content"}), max_lanes=10, current_lanes=2),
    }

    picked = select_helpers_for_lane(
        validator_ids=validators,
        helpers=helpers,
        lane_id="lane-content-4",
        required_capabilities={"content"},
        exclude_node_id="leader-1",
    )

    assert picked == ["val-a", "val-b"]
