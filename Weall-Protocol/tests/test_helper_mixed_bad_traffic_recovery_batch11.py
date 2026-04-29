from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from weall.runtime.helper_certificates import HelperExecutionCertificate, make_namespace_hash, sign_helper_certificate
from weall.runtime.helper_dispatch import HelperCertificateStore, HelperDispatchContext
from weall.runtime.parallel_execution import canonical_lane_plan_fingerprint, plan_parallel_execution


def _pub_hex_from_seed(seed_hex: str) -> str:
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
    return key.public_key().public_bytes_raw().hex()


def _make_store_and_plan():
    txs = [{"tx_id": "t1", "tx_type": "CONTENT_CREATE", "state_prefixes": ["content:post:1"]}]
    lane_plans = plan_parallel_execution(
        txs=txs,
        validators=["v1", "v2", "v3"],
        validator_set_hash="vhash",
        view=7,
        leader_id="v1",
    )
    lane_plan = next(plan for plan in lane_plans if plan.lane_id == "PARALLEL_CONTENT")
    plan_id = canonical_lane_plan_fingerprint(lane_plans)
    seed = (bytes([41]) * 32).hex()
    pub = _pub_hex_from_seed(seed)
    store = HelperCertificateStore(
        context=HelperDispatchContext(
            chain_id="c1",
            block_height=22,
            view=7,
            leader_id="v1",
            validator_epoch=9,
            validator_set_hash="vhash",
            plan_id=plan_id,
        ),
        lane_plans=lane_plans,
        helper_pubkeys={str(lane_plan.helper_id): pub},
        helper_timeout_ms=50,
    )
    return lane_plan, plan_id, seed, store


def _signed_cert(*, lane_plan, plan_id: str, seed: str, view: int = 7, block_height: int = 22, helper_id: str | None = None):
    return sign_helper_certificate(
        HelperExecutionCertificate(
            chain_id="c1",
            block_height=block_height,
            view=view,
            leader_id="v1",
            helper_id=str(helper_id or lane_plan.helper_id),
            validator_epoch=9,
            validator_set_hash="vhash",
            lane_id=str(lane_plan.lane_id),
            tx_ids=lane_plan.tx_ids,
            tx_order_hash="order",
            receipts_root="receipts",
            write_set_hash="writes",
            read_set_hash="reads",
            lane_delta_hash="delta",
            namespace_hash=make_namespace_hash(lane_plan.namespace_prefixes),
            plan_id=plan_id,
        ),
        privkey=seed,
    )


def test_mixed_stale_then_valid_then_duplicate_recovers_canonically_batch11() -> None:
    lane_plan, plan_id, seed, store = _make_store_and_plan()
    store.start_request(lane_id=lane_plan.lane_id, started_ms=1000)

    stale = _signed_cert(lane_plan=lane_plan, plan_id=plan_id, seed=seed, view=6)
    stale_status = store.ingest_certificate(cert=stale, peer_id=str(lane_plan.helper_id), now_ms=1001)
    assert stale_status.accepted is False
    assert stale_status.code == "stale_certificate"

    valid = _signed_cert(lane_plan=lane_plan, plan_id=plan_id, seed=seed)
    valid_status = store.ingest_certificate(cert=valid, peer_id=str(lane_plan.helper_id), now_ms=1002)
    assert valid_status.accepted is True
    assert valid_status.code == "accepted"

    duplicate_status = store.ingest_certificate(cert=valid, peer_id=str(lane_plan.helper_id), now_ms=1003)
    assert duplicate_status.accepted is False
    assert duplicate_status.code == "duplicate_certificate"


def test_mixed_plan_mismatch_then_valid_helper_certificate_still_accepts_batch11() -> None:
    lane_plan, plan_id, seed, store = _make_store_and_plan()
    store.start_request(lane_id=lane_plan.lane_id, started_ms=1000)

    wrong_plan_cert = _signed_cert(lane_plan=lane_plan, plan_id="wrong-plan", seed=seed)
    wrong_plan = store.ingest_certificate(cert=wrong_plan_cert, peer_id=str(lane_plan.helper_id), now_ms=1001)
    assert wrong_plan.accepted is False
    assert wrong_plan.code == "plan_id_mismatch"

    valid = _signed_cert(lane_plan=lane_plan, plan_id=plan_id, seed=seed)
    valid_status = store.ingest_certificate(cert=valid, peer_id=str(lane_plan.helper_id), now_ms=1002)
    assert valid_status.accepted is True
    assert valid_status.code == "accepted"


def test_expired_window_then_later_valid_message_stays_fail_closed_batch11() -> None:
    lane_plan, plan_id, seed, store = _make_store_and_plan()
    store.start_request(lane_id=lane_plan.lane_id, started_ms=1000)

    valid = _signed_cert(lane_plan=lane_plan, plan_id=plan_id, seed=seed)
    expired = store.ingest_certificate(cert=valid, peer_id=str(lane_plan.helper_id), now_ms=1050)
    assert expired.accepted is False
    assert expired.code == "request_window_closed"

    later_retry = store.ingest_certificate(cert=valid, peer_id=str(lane_plan.helper_id), now_ms=1051)
    assert later_retry.accepted is False
    assert later_retry.code == "duplicate_certificate"
