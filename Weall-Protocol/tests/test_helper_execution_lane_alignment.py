from __future__ import annotations

from pathlib import Path

from weall.runtime.helper_contracts import build_helper_contract_map, helper_contract_for_tx

ROOT = Path(__file__).resolve().parents[1]
TX_INDEX = ROOT / "generated" / "tx_index.json"


def test_concrete_identity_instances_promote_to_parallel() -> None:
    for tx in (
        {"tx_type": "ACCOUNT_REGISTER", "payload": {"account_id": "@alice"}},
        {"tx_type": "ACCOUNT_KEY_ADD", "payload": {"account_id": "@alice", "key_id": "key-main"}},
    ):
        contract = helper_contract_for_tx(tx)
        assert contract.helper_eligible is True
        assert contract.degraded_to_serial is False
        assert contract.effective_lane_id == "PARALLEL_IDENTITY"


def test_concrete_economy_instances_promote_to_parallel() -> None:
    for tx in (
        {
            "tx_type": "BALANCE_TRANSFER",
            "payload": {"from_account_id": "@alice", "to_account_id": "@bob"},
        },
        {"tx_type": "FEE_PAY", "payload": {"from_account_id": "@alice", "to_account_id": "@fees"}},
    ):
        contract = helper_contract_for_tx(tx)
        assert contract.helper_eligible is True
        assert contract.degraded_to_serial is False
        assert contract.effective_lane_id == "PARALLEL_ECONOMY"


def test_tx_type_only_placeholders_stay_fail_closed() -> None:
    for tx_type in ("ACCOUNT_REGISTER", "ACCOUNT_KEY_ADD", "BALANCE_TRANSFER", "FEE_PAY"):
        contract = helper_contract_for_tx({"tx_type": tx_type})
        assert contract.helper_eligible is False
        assert contract.reason == "global_authority_placeholder"


def test_cross_family_account_receipts_degrade_on_planner_execution_lane_mismatch() -> None:
    for tx_type in ("ACCOUNT_BAN", "ACCOUNT_REINSTATE"):
        contract = helper_contract_for_tx({"tx_type": tx_type})
        assert contract.planner_lane_hint == "SOCIAL"
        assert contract.execution_lane_id == "PARALLEL_IDENTITY"
        assert contract.helper_eligible is False
        assert contract.degraded_to_serial is True
        assert contract.effective_lane_id == "SERIAL"
        assert contract.reason == "planner_execution_lane_mismatch"
        assert contract.proven_helper_eligible is False


def test_cross_lane_content_share_instance_degrades_to_serial() -> None:
    contract = helper_contract_for_tx(
        {
            "tx_type": "CONTENT_SHARE_CREATE",
            "payload": {"account_id": "@alice", "share_id": "share-001"},
        }
    )
    assert contract.planner_lane_hint == "SOCIAL"
    assert contract.execution_lane_id == "PARALLEL_CONTENT"
    assert contract.helper_eligible is False
    assert contract.degraded_to_serial is True
    assert contract.effective_lane_id == "SERIAL"
    assert contract.reason == "planner_execution_lane_mismatch"
    assert contract.proven_helper_eligible is False


def test_every_helper_eligible_contract_matches_planner_execution_lane() -> None:
    expected_lane_by_hint = {
        "IDENTITY": "PARALLEL_IDENTITY",
        "SOCIAL": "PARALLEL_SOCIAL",
        "CONTENT": "PARALLEL_CONTENT",
        "STORAGE": "PARALLEL_CONTENT",
        "ECONOMICS": "PARALLEL_ECONOMY",
    }
    contract_map = build_helper_contract_map(TX_INDEX)
    for item in contract_map["contracts"]:
        if not bool(item["helper_eligible"]):
            continue
        planner_hint = str(item["planner_lane_hint"])
        assert planner_hint in expected_lane_by_hint
        expected_lane = expected_lane_by_hint[planner_hint]
        assert item["execution_lane_id"] == expected_lane
        assert item["effective_lane_id"] == expected_lane


def test_helper_instance_summary_fails_closed_for_cross_lane_sample() -> None:
    contract_map = build_helper_contract_map(TX_INDEX)
    summary = contract_map["instance_summary"]
    assert summary["sample_count"] == 13
    assert summary["proven_helper_eligible_count"] == 12
    assert summary["helper_eligible_count"] == 12
    assert summary["degraded_to_serial_count"] == 1


def test_canon_map_eliminates_global_authority_parallel_false_positives() -> None:
    contract_map = build_helper_contract_map(TX_INDEX)
    summary = contract_map["summary"]
    assert summary["global_authority_parallel_count"] == 0
