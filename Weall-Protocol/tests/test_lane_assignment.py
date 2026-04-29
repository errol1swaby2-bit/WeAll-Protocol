from weall.runtime.lane_assignment import assign_execution_lane
from weall.runtime.execution_lanes import LANE_SERIAL, LANE_PARALLEL_IDENTITY


def test_deterministic_assignment():
    tx = {
        "type": "IDENTITY_CREATE",
        "touched_prefixes": ["identity:user:123"]
    }

    lane1 = assign_execution_lane(tx, {})
    lane2 = assign_execution_lane(tx, {})

    assert lane1 == lane2


def test_identity_lane():
    tx = {
        "type": "IDENTITY_UPDATE",
        "touched_prefixes": ["identity:user:abc"]
    }

    assert assign_execution_lane(tx, {}) == LANE_PARALLEL_IDENTITY


def test_cross_domain_goes_serial():
    tx = {
        "type": "IDENTITY_UPDATE",
        "touched_prefixes": ["identity:user:abc", "treasury:balance"]
    }

    assert assign_execution_lane(tx, {}) == LANE_SERIAL


def test_missing_type_goes_serial():
    tx = {
        "touched_prefixes": ["identity:user:abc"]
    }

    assert assign_execution_lane(tx, {}) == LANE_SERIAL
