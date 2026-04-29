from __future__ import annotations

from helper_audit_testkit import signed_lane_certificate
from weall.runtime.parallel_execution import LanePlan, merge_helper_lane_results


def _serial_executor(txs, _leader_context):
    return ([{"tx_id": str(tx.get("tx_id") or "")} for tx in list(txs or [])], {})


def test_merge_falls_back_when_helper_signature_invalid_batch36() -> None:
    tx = {"tx_id": "t1", "tx_type": "CONTENT_POST_CREATE"}
    lane_plan = LanePlan(
        lane_id="L1",
        helper_id="h1",
        txs=(tx,),
        tx_ids=("t1",),
        namespace_prefixes=("content:post:t1",),
    )
    cert, pub = signed_lane_certificate(lane_plan=lane_plan, seed_byte=17, helper_id="h1")
    tampered = {**cert.to_json(), "helper_signature": "00" * 64}

    merged = merge_helper_lane_results(
        canonical_txs=[tx],
        lane_plans=(lane_plan,),
        helper_certificates={"L1": tampered},
        serial_executor=_serial_executor,
        leader_context={
            "chain_id": "c1",
            "block_height": 22,
            "view": 7,
            "leader_id": "v1",
            "validator_epoch": 9,
            "validator_set_hash": "vhash",
            "helper_pubkeys": {"h1": pub},
            "helper_receipts": {"L1": [{"tx_id": "t1"}]},
            "enforce_helper_signature": True,
        },
    )

    assert merged.receipts == [{"tx_id": "t1"}]
    assert merged.lane_decisions[0].used_helper is False
    assert merged.lane_decisions[0].fallback_reason == "helper_signature_invalid"


def test_merge_can_skip_signature_enforcement_when_explicitly_disabled_batch36() -> None:
    tx = {"tx_id": "t1", "tx_type": "CONTENT_POST_CREATE"}
    lane_plan = LanePlan(
        lane_id="L1",
        helper_id="h1",
        txs=(tx,),
        tx_ids=("t1",),
        namespace_prefixes=("content:post:t1",),
    )
    cert, _pub = signed_lane_certificate(lane_plan=lane_plan, seed_byte=19, helper_id="h1")
    tampered = {**cert.to_json(), "helper_signature": "00" * 64}

    merged = merge_helper_lane_results(
        canonical_txs=[tx],
        lane_plans=(lane_plan,),
        helper_certificates={"L1": tampered},
        serial_executor=_serial_executor,
        leader_context={
            "chain_id": "c1",
            "block_height": 22,
            "view": 7,
            "leader_id": "v1",
            "validator_epoch": 9,
            "validator_set_hash": "vhash",
            "helper_receipts": {"L1": [{"tx_id": "t1"}]},
            "enforce_helper_signature": False,
        },
    )

    assert merged.receipts == [{"tx_id": "t1"}]
    assert merged.lane_decisions[0].used_helper is True
    assert merged.lane_decisions[0].fallback_reason is None
