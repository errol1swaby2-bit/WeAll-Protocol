from __future__ import annotations

from pathlib import Path

from weall.runtime.helper_contracts import (
    build_helper_contract_map,
    build_helper_instance_contract_map,
)
from weall.runtime.helper_instance_corpus import DEFAULT_HELPER_INSTANCE_CORPUS

ROOT = Path(__file__).resolve().parents[1]
TX_INDEX = ROOT / "generated" / "tx_index.json"


def test_helper_instance_corpus_is_nonempty() -> None:
    assert len(DEFAULT_HELPER_INSTANCE_CORPUS) == 13


def test_helper_instance_contract_summary() -> None:
    instance_map = build_helper_instance_contract_map()
    summary = instance_map["summary"]
    assert summary["sample_count"] == 13
    assert summary["proven_helper_eligible_count"] == 12
    assert summary["helper_eligible_count"] == 12
    assert summary["degraded_to_serial_count"] == 1
    assert summary["instance_required_count"] == 0
    assert summary["placeholder_parallel_count"] == 0


def test_helper_instance_contracts_have_no_placeholder_parallel_keys() -> None:
    instance_map = build_helper_instance_contract_map()
    for item in instance_map["contracts"]:
        if item["helper_eligible"]:
            assert item["uses_placeholder_keys"] is False


def test_helper_instance_corpus_retains_cross_lane_fail_closed_vector() -> None:
    instance_map = build_helper_instance_contract_map()
    degraded = {
        item["tx_type"]: item
        for item in instance_map["contracts"]
        if item["degraded_to_serial"]
    }
    assert set(degraded) == {"CONTENT_SHARE_CREATE"}
    row = degraded["CONTENT_SHARE_CREATE"]
    assert row["planner_lane_hint"] == "SOCIAL"
    assert row["execution_lane_id"] == "PARALLEL_CONTENT"
    assert row["effective_lane_id"] == "SERIAL"
    assert row["reason"] == "planner_execution_lane_mismatch"
    assert row["proven_helper_eligible"] is False


def test_helper_contract_map_embeds_instance_summary() -> None:
    contract_map = build_helper_contract_map(TX_INDEX)
    instance_summary = contract_map["instance_summary"]
    assert instance_summary["sample_count"] == 13
    assert instance_summary["proven_helper_eligible_count"] == 12
    assert instance_summary["degraded_to_serial_count"] == 1
