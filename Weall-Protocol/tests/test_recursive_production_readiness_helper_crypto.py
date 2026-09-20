from __future__ import annotations

import pytest

pytest.importorskip("cryptography.hazmat.primitives.asymmetric.mldsa")

from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey

from weall.runtime.helper_block_validation import validate_received_helper_execution
from weall.runtime.helper_certificates import (
    HelperExecutionCertificate,
    make_namespace_hash,
    make_tx_order_hash,
    sign_helper_certificate,
)
from weall.runtime.parallel_execution import (
    canonical_helper_execution_plan_fingerprint,
    canonical_lane_plan_fingerprint,
    plan_parallel_execution,
)


def _pub_hex_from_seed(seed_hex: str) -> str:
    key = MLDSA65PrivateKey.from_seed_bytes(bytes.fromhex(seed_hex))
    return key.public_key().public_bytes_raw().hex()


def test_received_helper_execution_rederives_plan_and_reverifies_full_mldsa_certificate() -> None:
    validators = ["v1", "v2", "v3"]
    validator_set_hash = "vhash"
    validator_epoch = 9
    view = 7
    leader = "v1"
    height = 22
    block_ts_ms = 1_000
    chain_id = "c1"
    txs = [
        {
            "tx_id": "c1",
            "tx_type": "CONTENT_CREATE",
            "state_prefixes": ["content:post:1"],
        }
    ]
    planning_metadata = {
        "validator_epoch": validator_epoch,
        "quarantined_helper_ids": [],
        "helper_capacity_by_helper": {},
        "helper_capabilities_by_helper": {},
        "helper_planning_inputs_source": "state_root",
        "allow_helper_overcommit": True,
    }
    plans = plan_parallel_execution(
        txs=txs,
        validators=validators,
        validator_set_hash=validator_set_hash,
        view=view,
        leader_id=leader,
        state_snapshot_metadata=planning_metadata,
    )
    helper_plan = next(plan for plan in plans if str(plan.helper_id or ""))
    plan_id = canonical_lane_plan_fingerprint(plans)

    lane_rows = [
        {
            "lane_id": str(plan.lane_id),
            "helper_id": str(plan.helper_id or ""),
            "tx_ids": list(plan.tx_ids),
            "descriptor_hash": str(plan.descriptor_hash),
            "plan_id": plan_id,
        }
        for plan in plans
    ]
    assert canonical_helper_execution_plan_fingerprint(lane_rows) == plan_id

    seed = (bytes([37]) * 32).hex()
    helper_pubkey = _pub_hex_from_seed(seed)
    cert = sign_helper_certificate(
        HelperExecutionCertificate(
            chain_id=chain_id,
            block_height=height,
            view=view,
            leader_id=leader,
            helper_id=str(helper_plan.helper_id),
            validator_epoch=validator_epoch,
            validator_set_hash=validator_set_hash,
            lane_id=str(helper_plan.lane_id),
            tx_ids=helper_plan.tx_ids,
            tx_order_hash=make_tx_order_hash(helper_plan.tx_ids),
            receipts_root="receipts-root",
            write_set_hash="write-set",
            read_set_hash="read-set",
            lane_delta_hash="lane-delta",
            namespace_hash=make_namespace_hash(helper_plan.namespace_prefixes),
            plan_id=plan_id,
        ),
        privkey=seed,
    )

    block = {
        "height": height,
        "view": view,
        "proposer": leader,
        "block_ts_ms": block_ts_ms,
        "txs": txs,
        "helper_execution": {
            "plan_id": plan_id,
            "view": view,
            "validator_epoch": validator_epoch,
            "validator_set_hash": validator_set_hash,
            "coordinator_id": leader,
            "lanes": lane_rows,
            "accepted_certificates": [
                {
                    "lane_id": str(helper_plan.lane_id),
                    "helper_id": str(helper_plan.helper_id),
                    "accepted": True,
                    "code": "accepted",
                    "plan_id": plan_id,
                    "certificate": cert.to_json(),
                }
            ],
            "helper_reputation": {
                "transition_policy": "diagnostic_only_v1",
                "state_committed": False,
            },
        },
    }
    state = {
        "helper_reputation": {},
        "helper_capacity_by_helper": {},
        "helper_capabilities_by_helper": {},
    }

    ok, reason = validate_received_helper_execution(
        block=block,
        state=state,
        chain_id=chain_id,
        validators=validators,
        validator_pubkeys={str(helper_plan.helper_id): helper_pubkey},
        validator_epoch=validator_epoch,
        validator_set_hash=validator_set_hash,
    )
    assert ok is True
    assert reason == "ok"

    tampered = cert.to_json()
    original_signature = str(tampered["helper_signature"])
    assert len(original_signature) >= 2
    tampered["helper_signature"] = (
        f"{int(original_signature[:2], 16) ^ 0x01:02x}" + original_signature[2:]
    )
    assert tampered["helper_signature"] != original_signature
    block["helper_execution"]["accepted_certificates"][0]["certificate"] = tampered
    ok, reason = validate_received_helper_execution(
        block=block,
        state=state,
        chain_id=chain_id,
        validators=validators,
        validator_pubkeys={str(helper_plan.helper_id): helper_pubkey},
        validator_epoch=validator_epoch,
        validator_set_hash=validator_set_hash,
    )
    assert ok is False
    assert reason == "helper_execution_certificate_signature_invalid"
