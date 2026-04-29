from weall.runtime.helper_assignment import assign_helper_for_lane, normalize_validators


def test_deterministic_helper_selection():
    validators = normalize_validators(["a", "b", "c", "d"])
    h1 = assign_helper_for_lane(validators, 10, "LANE_X", "a")
    h2 = assign_helper_for_lane(validators, 10, "LANE_X", "a")

    assert h1 == h2


def test_excludes_leader():
    validators = normalize_validators(["a", "b", "c"])
    helper = assign_helper_for_lane(validators, 1, "LANE_X", "a")

    assert helper != "a"


def test_insufficient_validators():
    validators = normalize_validators(["a"])
    helper = assign_helper_for_lane(validators, 1, "LANE_X", "a")

    assert helper is None
