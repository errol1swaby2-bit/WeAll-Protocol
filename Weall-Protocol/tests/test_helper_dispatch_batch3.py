from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from weall.runtime.helper_assignment import assign_helper_for_lane
from weall.runtime.helper_certificates import (
    HelperExecutionCertificate,
    make_namespace_hash,
    sign_helper_certificate,
)
from weall.runtime.helper_dispatch import (
    HelperCertificateStore,
    HelperDispatchContext,
)
from weall.runtime.parallel_execution import plan_parallel_execution


def _pub_hex_from_seed(seed_hex: str) -> str:
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
    return key.public_key().public_bytes_raw().hex()


def _mk_cert(*, helper_id: str, lane_id: str, tx_ids: tuple[str, ...], epoch: int = 9, vset_hash: str = "vhash", view: int = 7, block_height: int = 22) -> HelperExecutionCertificate:
    cert = HelperExecutionCertificate(
        chain_id="c1",
        block_height=block_height,
        view=view,
        leader_id="v1",
        helper_id=helper_id,
        validator_epoch=epoch,
        validator_set_hash=vset_hash,
        lane_id=lane_id,
        tx_ids=tx_ids,
        tx_order_hash="order",
        receipts_root="receipts",
        write_set_hash="writes",
        read_set_hash="reads",
        lane_delta_hash="delta",
        namespace_hash=make_namespace_hash(["content:post:1"]),
    )
    return cert


def test_helper_store_rejects_wrong_peer_batch3() -> None:
    txs = [{"tx_id": "t1", "tx_type": "CONTENT_CREATE", "state_prefixes": ["content:post:1"]}]
    validators = ["v1", "v2", "v3"]
    lane_plans = plan_parallel_execution(
        txs=txs,
        validators=validators,
        validator_set_hash="vhash",
        view=7,
        leader_id="v1",
    )
    lane_plan = next(plan for plan in lane_plans if plan.lane_id == "PARALLEL_CONTENT")
    store = HelperCertificateStore(
        context=HelperDispatchContext(
            chain_id="c1",
            block_height=22,
            view=7,
            leader_id="v1",
            validator_epoch=9,
            validator_set_hash="vhash",
        ),
        lane_plans=lane_plans,
    )
    cert = _mk_cert(helper_id=lane_plan.helper_id, lane_id=lane_plan.lane_id, tx_ids=lane_plan.tx_ids)
    status = store.ingest_certificate(cert=cert, peer_id="intruder")
    assert status.accepted is False
    assert status.code == "wrong_peer"


def test_helper_store_rejects_stale_epoch_batch3() -> None:
    txs = [{"tx_id": "t1", "tx_type": "CONTENT_CREATE", "state_prefixes": ["content:post:1"]}]
    lane_plans = plan_parallel_execution(
        txs=txs,
        validators=["v1", "v2", "v3"],
        validator_set_hash="vhash",
        view=7,
        leader_id="v1",
    )
    lane_plan = next(plan for plan in lane_plans if plan.lane_id == "PARALLEL_CONTENT")
    store = HelperCertificateStore(
        context=HelperDispatchContext(
            chain_id="c1",
            block_height=22,
            view=7,
            leader_id="v1",
            validator_epoch=9,
            validator_set_hash="vhash",
        ),
        lane_plans=lane_plans,
    )
    cert = _mk_cert(helper_id=lane_plan.helper_id, lane_id=lane_plan.lane_id, tx_ids=lane_plan.tx_ids, epoch=8)
    status = store.ingest_certificate(cert=cert, peer_id=lane_plan.helper_id)
    assert status.accepted is False
    assert status.code == "epoch_mismatch"


def test_helper_store_rejects_duplicate_batch3() -> None:
    txs = [{"tx_id": "t1", "tx_type": "CONTENT_CREATE", "state_prefixes": ["content:post:1"]}]
    lane_plans = plan_parallel_execution(
        txs=txs,
        validators=["v1", "v2", "v3"],
        validator_set_hash="vhash",
        view=7,
        leader_id="v1",
    )
    lane_plan = next(plan for plan in lane_plans if plan.lane_id == "PARALLEL_CONTENT")
    seed = (bytes([5]) * 32).hex()
    pub = _pub_hex_from_seed(seed)
    cert = sign_helper_certificate(
        _mk_cert(helper_id=lane_plan.helper_id, lane_id=lane_plan.lane_id, tx_ids=lane_plan.tx_ids),
        privkey=seed,
    )
    store = HelperCertificateStore(
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
    )
    first = store.ingest_certificate(cert=cert, peer_id=lane_plan.helper_id)
    second = store.ingest_certificate(cert=cert, peer_id=lane_plan.helper_id)
    assert first.accepted is True
    assert second.accepted is False
    assert second.code == "duplicate_certificate"


def test_helper_store_times_out_missing_lane_batch3() -> None:
    txs = [{"tx_id": "t1", "tx_type": "CONTENT_CREATE", "state_prefixes": ["content:post:1"]}]
    lane_plans = plan_parallel_execution(
        txs=txs,
        validators=["v1", "v2", "v3"],
        validator_set_hash="vhash",
        view=7,
        leader_id="v1",
    )
    lane_plan = next(plan for plan in lane_plans if plan.lane_id == "PARALLEL_CONTENT")
    store = HelperCertificateStore(
        context=HelperDispatchContext(
            chain_id="c1",
            block_height=22,
            view=7,
            leader_id="v1",
            validator_epoch=9,
            validator_set_hash="vhash",
        ),
        lane_plans=lane_plans,
        helper_timeout_ms=50,
    )
    store.start_request(lane_id=lane_plan.lane_id, started_ms=1000)
    assert store.timed_out_lanes(now_ms=1049) == ()
    assert store.timed_out_lanes(now_ms=1050) == (lane_plan.lane_id,)


def test_helper_store_rejects_malicious_tx_subset_batch3() -> None:
    txs = [{"tx_id": "t1", "tx_type": "CONTENT_CREATE", "state_prefixes": ["content:post:1"]}]
    lane_plans = plan_parallel_execution(
        txs=txs,
        validators=["v1", "v2", "v3"],
        validator_set_hash="vhash",
        view=7,
        leader_id="v1",
    )
    lane_plan = next(plan for plan in lane_plans if plan.lane_id == "PARALLEL_CONTENT")
    store = HelperCertificateStore(
        context=HelperDispatchContext(
            chain_id="c1",
            block_height=22,
            view=7,
            leader_id="v1",
            validator_epoch=9,
            validator_set_hash="vhash",
        ),
        lane_plans=lane_plans,
    )
    cert = _mk_cert(helper_id=lane_plan.helper_id, lane_id=lane_plan.lane_id, tx_ids=("evil",))
    status = store.ingest_certificate(cert=cert, peer_id=lane_plan.helper_id)
    assert status.accepted is False
    assert status.code == "tx_id_subset_mismatch"
