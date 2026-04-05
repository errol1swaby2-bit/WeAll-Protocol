from __future__ import annotations

from typing import Any, Mapping

import pytest

from weall.runtime.helper_certificates import (
    HelperExecutionCertificate,
    hash_receipts,
    hash_state_delta_ops,
    make_namespace_hash,
)
from weall.runtime.parallel_execution import (
    LanePlan,
    canonical_lane_plan_fingerprint,
    verify_serial_helper_equivalence,
    plan_parallel_execution,
)


Json = dict[str, Any]


def _serial_executor(txs: list[dict], _leader_context: dict | None = None) -> tuple[list[dict], dict]:
    receipts = []
    for tx in txs:
        receipts.append(
            {
                "tx_id": str(tx.get("tx_id") or ""),
                "tx_type": str(tx.get("tx_type") or ""),
                "ok": True,
                "path": "serial",
            }
        )
    return receipts, {"count": len(receipts)}


def _tx(tx_id: str, tx_type: str, *, read_set: list[str] | None = None, write_set: list[str] | None = None, state_prefixes: list[str] | None = None) -> Json:
    row: Json = {"tx_id": tx_id, "tx_type": tx_type}
    if read_set is not None:
        row["read_set"] = list(read_set)
    if write_set is not None:
        row["write_set"] = list(write_set)
    if state_prefixes is not None:
        row["state_prefixes"] = list(state_prefixes)
    return row


CORPUS: tuple[tuple[str, list[Json]], ...] = (
    (
        "content_identity_social_governance_economics",
        [
            _tx("t1", "CONTENT_CREATE", write_set=["content:post:1"], state_prefixes=["content:post:1"]),
            _tx("t2", "CONTENT_CREATE", write_set=["content:post:2"], state_prefixes=["content:post:2"]),
            _tx("t3", "IDENTITY_UPDATE", read_set=["identity:user:alice"], write_set=["identity:user:alice"], state_prefixes=["identity:user:alice"]),
            _tx("t4", "SOCIAL_FOLLOW", write_set=["social:follow:@alice:@bob"], state_prefixes=["social:follow:@alice:@bob"]),
            _tx("t5", "GROUP_MEMBERSHIP_REQUEST", write_set=["group:membership:g1:@alice"], state_prefixes=["group:membership:g1:@alice"]),
            _tx("t6", "TREASURY_SPEND_PROPOSE", write_set=["treasury:proposal:tr1:p1"], state_prefixes=["treasury:proposal:tr1:p1"]),
        ],
    ),
    (
        "storage_notifications_roles_rewards",
        [
            _tx("u1", "STORAGE_PROOF_SUBMIT", read_set=["storage:lease:l1"], write_set=["storage:proof:l1:1"], state_prefixes=["storage:lease:l1", "storage:proof:l1:1"]),
            _tx("u2", "STORAGE_CHALLENGE_RESPOND", read_set=["storage:challenge:c1"], write_set=["storage:challenge:c1:response"], state_prefixes=["storage:challenge:c1", "storage:challenge:c1:response"]),
            _tx("u3", "NOTIFICATION_SUBSCRIBE", write_set=["notification:topic:governance:@alice"], state_prefixes=["notification:topic:governance:@alice"]),
            _tx("u4", "ROLE_GRANT", write_set=["role:group:g1:moderator:@alice"], state_prefixes=["role:group:g1:moderator:@alice"]),
            _tx("u5", "REWARDS_CLAIM", read_set=["rewards:claimable:@alice"], write_set=["rewards:claimed:@alice:1"], state_prefixes=["rewards:claimable:@alice", "rewards:claimed:@alice:1"]),
        ],
    ),
)


def _lane_receipts(plan: LanePlan) -> list[Json]:
    return [
        {
            "tx_id": str(tx.get("tx_id") or ""),
            "tx_type": str(tx.get("tx_type") or ""),
            "ok": True,
            "path": "serial",
        }
        for tx in plan.txs
    ]


def _lane_delta_ops(plan: LanePlan) -> list[Json]:
    return [
        {
            "op": "put",
            "path": prefix,
            "value": f"applied:{tx_id}",
        }
        for tx_id, prefix in zip(plan.tx_ids, plan.namespace_prefixes)
    ]


def _mk_cert(plan: LanePlan, *, block_height: int, view: int, validator_epoch: int, validator_set_hash: str, plan_id: str) -> HelperExecutionCertificate:
    receipts = _lane_receipts(plan)
    delta_ops = _lane_delta_ops(plan)
    return HelperExecutionCertificate(
        chain_id="c1",
        block_height=block_height,
        view=view,
        leader_id="v1",
        helper_id=str(plan.helper_id or ""),
        validator_epoch=validator_epoch,
        validator_set_hash=validator_set_hash,
        lane_id=plan.lane_id,
        tx_ids=plan.tx_ids,
        tx_order_hash="order",
        receipts_root=hash_receipts(receipts),
        write_set_hash="w",
        read_set_hash="r",
        lane_delta_hash=hash_state_delta_ops(delta_ops),
        namespace_hash=make_namespace_hash(plan.namespace_prefixes),
        plan_id=plan_id,
    )


@pytest.mark.parametrize(("_name", "txs"), CORPUS)
def test_helper_serial_equivalence_corpus_under_mixed_lane_pressure_batch12(_name: str, txs: list[Json]) -> None:
    lane_plans = plan_parallel_execution(
        txs=list(txs),
        validators=["v1", "v2", "v3", "v4"],
        validator_set_hash="vh",
        view=21,
        leader_id="v1",
    )
    assert len(lane_plans) >= 3
    assert any(plan.helper_id for plan in lane_plans)

    plan_id = canonical_lane_plan_fingerprint(lane_plans)
    helper_certificates: dict[str, HelperExecutionCertificate] = {}
    helper_receipts: dict[str, list[Mapping[str, Any]]] = {}
    helper_state_deltas: dict[str, list[Mapping[str, Any]]] = {}
    for plan in lane_plans:
        if not plan.helper_id:
            continue
        helper_certificates[plan.lane_id] = _mk_cert(
            plan,
            block_height=44,
            view=21,
            validator_epoch=7,
            validator_set_hash="vh",
            plan_id=plan_id,
        )
        helper_receipts[plan.lane_id] = _lane_receipts(plan)
        helper_state_deltas[plan.lane_id] = _lane_delta_ops(plan)

    report = verify_serial_helper_equivalence(
        canonical_txs=txs,
        lane_plans=lane_plans,
        helper_certificates=helper_certificates,
        helper_receipts_by_lane=helper_receipts,
        serial_executor=_serial_executor,
        leader_context={
            "chain_id": "c1",
            "block_height": 44,
            "view": 21,
            "leader_id": "v1",
            "validator_epoch": 7,
            "validator_set_hash": "vh",
            "plan_id": plan_id,
            "helper_state_deltas": helper_state_deltas,
            "enforce_helper_receipts_root": True,
            "enforce_helper_state_delta_hash": True,
        },
    )

    assert report.ok is True
    assert report.reason == "ok"
    assert report.serial_tx_ids == tuple(tx["tx_id"] for tx in txs)
    assert report.helper_tx_ids == tuple(tx["tx_id"] for tx in txs)
