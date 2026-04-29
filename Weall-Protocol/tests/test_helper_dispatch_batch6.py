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


def _lane_setup():
    txs = [{"tx_id": "t1", "tx_type": "CONTENT_CREATE", "state_prefixes": ["content:post:1"]}]
    lane_plans = plan_parallel_execution(
        txs=txs,
        validators=["v1", "v2", "v3"],
        validator_set_hash="vhash",
        view=7,
        leader_id="v1",
    )
    lane_plan = next(plan for plan in lane_plans if plan.lane_id == "PARALLEL_CONTENT")
    return lane_plans, lane_plan


def _mk_signed_cert(*, helper_id: str, lane_id: str, tx_ids: tuple[str, ...], seed_byte: int, receipts_root: str = "receipts"):
    seed = (bytes([seed_byte]) * 32).hex()
    pub = _pub_hex_from_seed(seed)
    cert = sign_helper_certificate(
        HelperExecutionCertificate(
            chain_id="c1",
            block_height=22,
            view=7,
            leader_id="v1",
            helper_id=helper_id,
            validator_epoch=9,
            validator_set_hash="vhash",
            lane_id=lane_id,
            tx_ids=tx_ids,
            tx_order_hash="order",
            receipts_root=receipts_root,
            write_set_hash="writes",
            read_set_hash="reads",
            lane_delta_hash="delta",
            namespace_hash=make_namespace_hash(["content:post:1"]),
        ),
        privkey=seed,
    )
    return cert, pub


def _context():
    return HelperDispatchContext(
        chain_id="c1",
        block_height=22,
        view=7,
        leader_id="v1",
        validator_epoch=9,
        validator_set_hash="vhash",
    )


def test_helper_store_rejects_conflicting_certificate_after_accept_batch6() -> None:
    lane_plans, lane_plan = _lane_setup()
    cert1, pub = _mk_signed_cert(
        helper_id=lane_plan.helper_id,
        lane_id=lane_plan.lane_id,
        tx_ids=lane_plan.tx_ids,
        seed_byte=5,
        receipts_root="receipts-a",
    )
    cert2, _ = _mk_signed_cert(
        helper_id=lane_plan.helper_id,
        lane_id=lane_plan.lane_id,
        tx_ids=lane_plan.tx_ids,
        seed_byte=6,
        receipts_root="receipts-b",
    )

    store = HelperCertificateStore(
        context=_context(),
        lane_plans=lane_plans,
        helper_pubkeys={lane_plan.helper_id: pub},
    )
    first = store.ingest_certificate(cert=cert1, peer_id=lane_plan.helper_id)
    second = store.ingest_certificate(cert=cert2, peer_id=lane_plan.helper_id)

    assert first.accepted is True
    assert second.accepted is False
    assert second.code == "conflicting_certificate"
    accepted = store.accepted_certificates()
    assert accepted[lane_plan.lane_id].receipts_root == "receipts-a"


def test_helper_store_rejects_conflicting_certificate_after_restart_batch6(tmp_path) -> None:
    lane_plans, lane_plan = _lane_setup()
    journal = HelperLaneJournal(str(tmp_path / "helper_lane.jsonl"))
    cert1, pub1 = _mk_signed_cert(
        helper_id=lane_plan.helper_id,
        lane_id=lane_plan.lane_id,
        tx_ids=lane_plan.tx_ids,
        seed_byte=7,
        receipts_root="receipts-a",
    )
    cert2, pub2 = _mk_signed_cert(
        helper_id=lane_plan.helper_id,
        lane_id=lane_plan.lane_id,
        tx_ids=lane_plan.tx_ids,
        seed_byte=8,
        receipts_root="receipts-b",
    )

    store1 = HelperCertificateStore(
        context=_context(),
        lane_plans=lane_plans,
        helper_pubkeys={lane_plan.helper_id: pub1},
        journal=journal,
    )
    first = store1.ingest_certificate(cert=cert1, peer_id=lane_plan.helper_id)
    assert first.accepted is True

    store2 = HelperCertificateStore(
        context=_context(),
        lane_plans=lane_plans,
        helper_pubkeys={lane_plan.helper_id: pub2},
        journal=journal,
    )
    second = store2.ingest_certificate(cert=cert2, peer_id=lane_plan.helper_id)
    assert second.accepted is False
    assert second.code == "conflicting_certificate"
    recovered = store2.accepted_certificates()
    assert recovered[lane_plan.lane_id].receipts_root == "receipts-a"


def test_helper_store_timeout_recovery_survives_restart_batch6(tmp_path) -> None:
    lane_plans, lane_plan = _lane_setup()
    journal = HelperLaneJournal(str(tmp_path / "helper_lane.jsonl"))

    store1 = HelperCertificateStore(
        context=_context(),
        lane_plans=lane_plans,
        journal=journal,
        helper_timeout_ms=50,
    )
    store1.start_request(lane_id=lane_plan.lane_id, started_ms=1000)

    store2 = HelperCertificateStore(
        context=_context(),
        lane_plans=lane_plans,
        journal=journal,
        helper_timeout_ms=50,
    )
    assert store2.timed_out_lanes(now_ms=1049) == ()
    assert store2.timed_out_lanes(now_ms=1050) == (lane_plan.lane_id,)
