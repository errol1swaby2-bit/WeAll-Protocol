from __future__ import annotations

from pathlib import Path

from weall.runtime.helper_certificates import make_namespace_hash, sign_helper_certificate
from weall.runtime.parallel_execution import LanePlan, merge_helper_lane_results
from weall.runtime.read_write_sets import TxAccessSet


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_new_style_helper_certificate_defaults_issued_ms_to_zero_batch112() -> None:
    cert = sign_helper_certificate(
        chain_id="batch112",
        height=7,
        validator_epoch=3,
        validator_set_hash="vset",
        parent_block_id="parent",
        lane_id="lane-a",
        helper_id="helper-1",
        lane_tx_ids=("tx1",),
        descriptor_hash="desc",
        plan_id="plan-1",
        shared_secret="secret",
    )
    assert cert["issued_ms"] == 0


def test_merge_helper_lane_results_rejects_tx_order_hash_mismatch_by_default_batch112() -> None:
    tx = {"tx_id": "tx1", "tx_type": "ACCOUNT_REGISTER", "signer": "@alice", "nonce": 1}
    lane_plan = LanePlan(
        lane_id="lane-a",
        helper_id="helper-1",
        txs=(tx,),
        tx_ids=("tx1",),
        access_sets=(
            TxAccessSet(
                tx_id="tx1",
                lane_hint="IDENTITY",
                reads=(),
                writes=("accounts/@alice",),
                fail_closed_serial=False,
                family="IDENTITY",
                barrier_class="identity",
            ),
        ),
        namespace_prefixes=("accounts/@alice",),
        descriptor_hash="desc",
    )
    cert = {
        "chain_id": "batch112",
        "block_height": 7,
        "view": 9,
        "leader_id": "@leader",
        "helper_id": "helper-1",
        "validator_epoch": 3,
        "validator_set_hash": "vset",
        "lane_id": "lane-a",
        "tx_ids": ["tx1"],
        "tx_order_hash": "bad",
        "receipts_root": "",
        "write_set_hash": "",
        "read_set_hash": "",
        "lane_delta_hash": "",
        "namespace_hash": make_namespace_hash(lane_plan.namespace_prefixes),
        "helper_signature": "",
    }
    receipt = {"tx_id": "tx1", "ok": True}

    merged = merge_helper_lane_results(
        canonical_txs=[tx],
        lane_plans=[lane_plan],
        helper_certificates={"lane-a": cert},
        serial_executor=lambda txs, _ctx: ([dict(receipt) for _ in txs], {}),
        leader_context={
            "chain_id": "batch112",
            "block_height": 7,
            "view": 9,
            "leader_id": "@leader",
            "validator_epoch": 3,
            "validator_set_hash": "vset",
            "helper_receipts": {"lane-a": [receipt]},
        },
    )

    assert len(merged.lane_decisions) == 1
    assert merged.lane_decisions[0].used_helper is False
    assert merged.lane_decisions[0].fallback_reason == "helper_certificate_inconsistent"
