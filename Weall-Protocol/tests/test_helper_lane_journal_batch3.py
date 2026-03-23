from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from weall.runtime.helper_certificates import (
    HelperExecutionCertificate,
    make_namespace_hash,
    sign_helper_certificate,
)
from weall.runtime.helper_dispatch import HelperCertificateStore, HelperDispatchContext
from weall.runtime.helper_lane_journal import HelperLaneJournal
from weall.runtime.parallel_execution import plan_parallel_execution


def _pub_hex_from_seed(seed_hex: str) -> str:
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
    return key.public_key().public_bytes_raw().hex()


def test_helper_journal_recovers_accepted_certificate_batch3(tmp_path) -> None:
    journal = HelperLaneJournal(str(tmp_path / "helper_lane.jsonl"))
    txs = [{"tx_id": "t1", "tx_type": "CONTENT_CREATE", "state_prefixes": ["content:post:1"]}]
    lane_plans = plan_parallel_execution(
        txs=txs,
        validators=["v1", "v2", "v3"],
        validator_set_hash="vhash",
        view=7,
        leader_id="v1",
    )
    lane_plan = next(plan for plan in lane_plans if plan.lane_id == "PARALLEL_CONTENT")
    seed = (bytes([9]) * 32).hex()
    pub = _pub_hex_from_seed(seed)
    cert = sign_helper_certificate(
        HelperExecutionCertificate(
            chain_id="c1",
            block_height=22,
            view=7,
            leader_id="v1",
            helper_id=lane_plan.helper_id,
            validator_epoch=9,
            validator_set_hash="vhash",
            lane_id=lane_plan.lane_id,
            tx_ids=lane_plan.tx_ids,
            tx_order_hash="order",
            receipts_root="receipts",
            write_set_hash="writes",
            read_set_hash="reads",
            lane_delta_hash="delta",
            namespace_hash=make_namespace_hash(["content:post:1"]),
        ),
        privkey=seed,
    )

    store1 = HelperCertificateStore(
        context=HelperDispatchContext(
            chain_id="c1",
            block_height=22,
            view=7,
            leader_id="v1",
            validator_epoch=9,
            validator_set_hash="vhash",
        ),
        lane_plans=lane_plans,
        helper_pubkeys={lane_plan.helper_id: pub},
        journal=journal,
    )
    store1.start_request(lane_id=lane_plan.lane_id, started_ms=1000)
    accepted = store1.ingest_certificate(cert=cert, peer_id=lane_plan.helper_id)
    assert accepted.accepted is True

    store2 = HelperCertificateStore(
        context=HelperDispatchContext(
            chain_id="c1",
            block_height=22,
            view=7,
            leader_id="v1",
            validator_epoch=9,
            validator_set_hash="vhash",
        ),
        lane_plans=lane_plans,
        helper_pubkeys={lane_plan.helper_id: pub},
        journal=journal,
    )
    recovered = store2.accepted_certificates()
    assert lane_plan.lane_id in recovered
    assert recovered[lane_plan.lane_id].helper_signature == cert.helper_signature
