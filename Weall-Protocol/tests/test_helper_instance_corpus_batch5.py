from __future__ import annotations

from pathlib import Path

from weall.runtime.helper_contracts import build_helper_contract_map, build_helper_instance_contract_map
from weall.runtime.helper_instance_corpus import DEFAULT_HELPER_INSTANCE_CORPUS


ROOT = Path(__file__).resolve().parents[1]
TX_INDEX = ROOT / "generated" / "tx_index.json"


def test_helper_instance_corpus_is_nonempty_batch5() -> None:
    assert len(DEFAULT_HELPER_INSTANCE_CORPUS) == 13


def test_helper_instance_contract_summary_batch5() -> None:
    instance_map = build_helper_instance_contract_map()
    summary = instance_map["summary"]
    assert summary["sample_count"] == 13
    assert summary["proven_helper_eligible_count"] == 13
    assert summary["degraded_to_serial_count"] == 0
    assert summary["instance_required_count"] == 0
    assert summary["placeholder_parallel_count"] == 0


def test_helper_instance_contracts_have_no_placeholder_parallel_keys_batch5() -> None:
    instance_map = build_helper_instance_contract_map()
    for item in instance_map["contracts"]:
        if item["helper_eligible"]:
            assert item["uses_placeholder_keys"] is False


def test_helper_instance_corpus_has_no_remaining_degraded_txs_batch5() -> None:
    instance_map = build_helper_instance_contract_map()
    degraded = {item["tx_type"] for item in instance_map["contracts"] if item["degraded_to_serial"]}
    assert degraded == set()


def test_helper_contract_map_embeds_instance_summary_batch5() -> None:
    contract_map = build_helper_contract_map(TX_INDEX)
    instance_summary = contract_map["instance_summary"]
    assert instance_summary["sample_count"] == 13
    assert instance_summary["proven_helper_eligible_count"] == 13
