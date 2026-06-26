from __future__ import annotations

from weall.runtime.helper_assignment import choose_helper_from_candidates


def test_choose_helper_from_candidates_uses_integer_ratio_tiebreak_batch36() -> None:
    chosen = choose_helper_from_candidates(
        ("h1", "h2"),
        assignment_counts={"h1": 0, "h2": 0},
        assignment_load_units={"h1": 2, "h2": 3},
        helper_capacity_by_helper={"h1": 3, "h2": 5},
        lane_cost=1,
        allow_overcommit=True,
    )
    assert chosen == "h2"


def test_choose_helper_from_candidates_prefers_non_overloaded_helper_batch36() -> None:
    chosen = choose_helper_from_candidates(
        ("h1", "h2"),
        assignment_counts={"h1": 0, "h2": 0},
        assignment_load_units={"h1": 5, "h2": 1},
        helper_capacity_by_helper={"h1": 4, "h2": 3},
        lane_cost=1,
        allow_overcommit=True,
    )
    assert chosen == "h2"
