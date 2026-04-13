from __future__ import annotations

from pathlib import Path

from weall.runtime.parallel_execution import LanePlan, merge_helper_lane_results
from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _tx_index_path() -> str:
    return str(_repo_root() / "generated" / "tx_index.json")


def _serial_executor(txs, _leader_context):
    return ([{"tx_id": str(tx.get("tx_id") or ""), "ok": True, "path": "serial"} for tx in list(txs or [])], {})


def test_merge_helper_lane_results_rejects_missing_signature_when_enforced_batch117() -> None:
    tx = {"tx_id": "tx1", "tx_type": "CONTENT_POST_CREATE"}
    lane = LanePlan(
        lane_id="lane-a",
        helper_id="helper-1",
        txs=(tx,),
        tx_ids=("tx1",),
        namespace_prefixes=("content:post:tx1",),
    )
    cert = {
        "chain_id": "batch117",
        "block_height": 7,
        "view": 9,
        "leader_id": "@leader",
        "helper_id": "helper-1",
        "validator_epoch": 3,
        "validator_set_hash": "vset",
        "lane_id": "lane-a",
        "tx_ids": ["tx1"],
        "tx_order_hash": "d701ef20f57aac468ed22504a38c2bc0817b90320503d772a0445d7c2b30ce6f",
        "receipts_root": "",
        "write_set_hash": "",
        "read_set_hash": "",
        "lane_delta_hash": "",
        "namespace_hash": "8a3f6143aacbf59de055797d978e2ae0741ef700121ae48cbbdf3860297ce969",
        "helper_signature": "",
    }
    result = merge_helper_lane_results(
        canonical_txs=[tx],
        lane_plans=(lane,),
        helper_certificates={lane.lane_id: cert},
        serial_executor=_serial_executor,
        leader_context={
            "chain_id": "batch117",
            "block_height": 7,
            "view": 9,
            "leader_id": "@leader",
            "validator_epoch": 3,
            "validator_set_hash": "vset",
            "helper_receipts": {lane.lane_id: [{"tx_id": "tx1", "ok": True, "path": "helper"}]},
            "enforce_helper_signature": True,
            "enforce_helper_namespace_hash": True,
            "enforce_helper_tx_order_hash": True,
        },
    )
    assert result.receipts == [{"tx_id": "tx1", "ok": True, "path": "serial"}]
    assert result.lane_decisions[0].fallback_reason == "helper_signature_missing"


def test_helper_execution_profile_pins_strict_flags_batch117(tmp_path) -> None:
    ex = WeAllExecutor(
        db_path=str(tmp_path / "helper_profile_flags.db"),
        node_id="@node",
        chain_id="batch117-profile",
        tx_index_path=_tx_index_path(),
    )
    profile = (ex.read_state().get("meta") or {}).get("helper_execution_profile")
    assert profile == {
        "helper_mode_enabled": False,
        "helper_fast_path_enabled": False,
        "helper_timeout_ms": 5000,
        "enforce_helper_signature": True,
        "enforce_helper_certificate_consistency": True,
        "enforce_helper_tx_order_hash": True,
        "enforce_helper_namespace_hash": True,
        "enforce_helper_receipts_root": True,
    }
