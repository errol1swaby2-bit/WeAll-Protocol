from __future__ import annotations

from pathlib import Path

from weall.runtime.execution_lanes import ALL_LANES, LANE_SERIAL
from weall.runtime.helper_contracts import (
    build_helper_contract_map,
    helper_contract_for_tx,
)


ROOT = Path(__file__).resolve().parents[1]
TX_INDEX = ROOT / "generated" / "tx_index.json"


def test_every_canon_tx_has_helper_contract_batch3() -> None:
    contract_map = build_helper_contract_map(TX_INDEX)
    summary = contract_map["summary"]
    assert summary["tx_count"] == 214
    assert summary["duplicate_name_count"] == 0
    assert summary["unknown_family_count"] == 0


def test_helper_contracts_only_emit_known_effective_lanes_batch3() -> None:
    contract_map = build_helper_contract_map(TX_INDEX)
    allowed = set(ALL_LANES)
    for item in contract_map["contracts"]:
        assert item["effective_lane_id"] in allowed
        assert item["execution_lane_id"] in allowed
        assert item["planner_lane_hint"]
        assert item["reason"]


def test_parallel_contracts_require_parallel_planner_and_execution_batch3() -> None:
    contract_map = build_helper_contract_map(TX_INDEX)
    for item in contract_map["contracts"]:
        if not item["helper_eligible"]:
            continue
        assert item["effective_lane_id"] != LANE_SERIAL
        assert item["execution_lane_id"] != LANE_SERIAL
        assert item["planner_lane_hint"] != "SERIAL"
        assert item["degraded_to_serial"] is False


def test_planner_parallel_execution_serial_mismatches_are_explicitly_fail_closed_batch3() -> None:
    contract_map = build_helper_contract_map(TX_INDEX)
    degraded = [item for item in contract_map["contracts"] if item["degraded_to_serial"]]
    assert degraded, "expected at least one known degraded-to-serial tx in current snapshot"
    for item in degraded:
        assert item["helper_eligible"] is False
        assert item["effective_lane_id"] == LANE_SERIAL
        assert item["execution_lane_id"] == LANE_SERIAL
        assert item["planner_lane_hint"] != "SERIAL"
        assert item["reason"] == "execution_lane_serial"


def test_helper_contract_for_tx_is_deterministic_batch3() -> None:
    tx = {
        "tx_type": "CONTENT_POST_CREATE",
        "payload": {"post_id": "post-1", "account_id": "@alice"},
        "state_prefixes": ["content:post:post-1"],
        "received_ms": 123,
    }
    c1 = helper_contract_for_tx(tx)
    c2 = helper_contract_for_tx(dict(tx))
    assert c1 == c2
