from __future__ import annotations

from pathlib import Path

from weall.runtime.helper_contracts import build_helper_contract_map, helper_contract_for_tx

ROOT = Path(__file__).resolve().parents[1]
TX_INDEX = ROOT / "generated" / "tx_index.json"


def test_concrete_identity_instances_promote_to_parallel_batch6() -> None:
    for tx in (
        {"tx_type": "ACCOUNT_REGISTER", "payload": {"account_id": "@alice"}},
        {"tx_type": "ACCOUNT_KEY_ADD", "payload": {"account_id": "@alice", "key_id": "key-main"}},
    ):
        contract = helper_contract_for_tx(tx)
        assert contract.helper_eligible is True
        assert contract.degraded_to_serial is False
        assert contract.effective_lane_id == "PARALLEL_IDENTITY"


def test_concrete_economy_instances_promote_to_parallel_batch6() -> None:
    for tx in (
        {"tx_type": "BALANCE_TRANSFER", "payload": {"from_account_id": "@alice", "to_account_id": "@bob"}},
        {"tx_type": "FEE_PAY", "payload": {"from_account_id": "@alice", "to_account_id": "@fees"}},
    ):
        contract = helper_contract_for_tx(tx)
        assert contract.helper_eligible is True
        assert contract.degraded_to_serial is False
        assert contract.effective_lane_id == "PARALLEL_ECONOMY"


def test_tx_type_only_placeholders_stay_fail_closed_batch6() -> None:
    for tx_type in ("ACCOUNT_REGISTER", "ACCOUNT_KEY_ADD", "BALANCE_TRANSFER", "FEE_PAY"):
        contract = helper_contract_for_tx({"tx_type": tx_type})
        assert contract.helper_eligible is False
        assert contract.reason == "global_authority_placeholder"


def test_helper_instance_summary_promotes_all_corpus_samples_batch6() -> None:
    contract_map = build_helper_contract_map(TX_INDEX)
    summary = contract_map["instance_summary"]
    assert summary["sample_count"] == 13
    assert summary["proven_helper_eligible_count"] == 13
    assert summary["degraded_to_serial_count"] == 0


def test_canon_map_eliminates_global_authority_parallel_false_positives_batch6() -> None:
    contract_map = build_helper_contract_map(TX_INDEX)
    summary = contract_map["summary"]
    assert summary["global_authority_parallel_count"] == 0
