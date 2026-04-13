from __future__ import annotations

from pathlib import Path

from weall.runtime.helper_contracts import build_helper_contract_map, helper_contract_for_tx


ROOT = Path(__file__).resolve().parents[1]
TX_INDEX = ROOT / "generated" / "tx_index.json"


def test_every_canon_tx_has_helper_proof_status_batch4() -> None:
    contract_map = build_helper_contract_map(TX_INDEX)
    summary = contract_map["summary"]
    assert summary["tx_count"] == len(contract_map["contracts"])
    assert summary["duplicate_name_count"] == 0
    for item in contract_map["contracts"]:
        assert item["proof_status"]


def test_proven_parallel_subset_is_strict_batch4() -> None:
    contract_map = build_helper_contract_map(TX_INDEX)
    proven = [item for item in contract_map["contracts"] if item["proven_helper_eligible"]]
    assert proven, "expected at least one proven helper-eligible tx in current snapshot"
    for item in proven:
        assert item["helper_eligible"] is True
        assert item["uses_placeholder_keys"] is False
        assert item["has_global_barrier_authority"] is False
        assert item["proof_status"] == "PROVEN_PARALLEL_SAFE"


def test_placeholder_parallel_contracts_require_concrete_instances_batch4() -> None:
    contract_map = build_helper_contract_map(TX_INDEX)
    placeholder_parallel = [
        item
        for item in contract_map["contracts"]
        if item["helper_eligible"] and item["uses_placeholder_keys"]
    ]
    assert placeholder_parallel, "expected helper-eligible txs that still require concrete instance coverage"
    for item in placeholder_parallel:
        assert item["proven_helper_eligible"] is False
        assert item["requires_concrete_instance"] is True
        assert item["proof_status"] == "INSTANCE_REQUIRED"
        assert item["placeholder_key_count"] > 0


def test_helper_eligible_contracts_have_no_global_barrier_authority_batch4() -> None:
    contract_map = build_helper_contract_map(TX_INDEX)
    summary = contract_map["summary"]
    risky = [
        item
        for item in contract_map["contracts"]
        if item["helper_eligible"] and item["has_global_barrier_authority"]
    ]
    assert summary["global_authority_parallel_count"] == 0
    assert not risky, (
        "helper-eligible txs must not retain global barrier authority "
        "after execution lane alignment"
    )



def test_global_authority_placeholders_fail_closed_to_serial_batch4() -> None:
    contract_map = build_helper_contract_map(TX_INDEX)
    placeholders = [
        item
        for item in contract_map["contracts"]
        if item["reason"] == "global_authority_placeholder"
    ]
    assert placeholders, "expected placeholder global-authority txs to remain visible in the audit map"
    for item in placeholders:
        assert item["helper_eligible"] is False
        assert item["proven_helper_eligible"] is False
        assert item["has_global_barrier_authority"] is True
        assert item["effective_lane_id"] == "SERIAL"
        assert item["proof_status"] in {"SERIAL_ONLY", "DEGRADED_TO_SERIAL", "DEGRADED_INSTANCE_REQUIRED"}


def test_helper_proof_contract_for_concrete_tx_is_deterministic_batch4() -> None:
    tx = {
        "tx_type": "NOTIFICATION_SUBSCRIBE",
        "payload": {"channel": "announcements", "account_id": "@alice"},
        "read_set": ["notifications:subscription:@alice:announcements"],
        "write_set": ["notifications:subscription:@alice:announcements"],
        "subject_set": ["notifications:subscription:@alice:announcements"],
    }
    c1 = helper_contract_for_tx(tx)
    c2 = helper_contract_for_tx(dict(tx))
    assert c1 == c2
    assert c1.proven_helper_eligible is True
    assert c1.proof_status == "PROVEN_PARALLEL_SAFE"
