from __future__ import annotations

from weall.runtime.execution_lanes import LANE_PARALLEL_IDENTITY, LANE_SERIAL
from weall.runtime.lane_assignment import assign_execution_lane



def test_same_tx_always_maps_to_same_lane_batch1() -> None:
    tx = {
        "tx_type": "IDENTITY_CREATE",
        "state_prefixes": ["identity:user:alice"],
    }
    assert assign_execution_lane(tx, {}) == LANE_PARALLEL_IDENTITY
    assert assign_execution_lane(tx, {}) == LANE_PARALLEL_IDENTITY



def test_ambiguous_scope_goes_serial_batch1() -> None:
    tx = {
        "tx_type": "IDENTITY_CREATE",
        "state_prefixes": ["unknown"],
    }
    assert assign_execution_lane(tx, {}) == LANE_SERIAL



def test_cross_domain_goes_serial_batch1() -> None:
    tx = {
        "tx_type": "IDENTITY_CREATE",
        "state_prefixes": ["identity:user:alice", "treasury:acct:main"],
    }
    assert assign_execution_lane(tx, {}) == LANE_SERIAL



def test_governance_family_forced_serial_batch1() -> None:
    tx = {
        "tx_type": "GOV_PROPOSAL_CREATE",
        "state_prefixes": ["governance:proposal:p1"],
    }
    assert assign_execution_lane(tx, {}) == LANE_SERIAL
