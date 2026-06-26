from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from weall.runtime.helper_certificates import HelperExecutionCertificate, make_namespace_hash, sign_helper_certificate
from weall.runtime.helper_dispatch import HelperDispatchContext
from weall.runtime.helper_proposal_orchestrator import HelperProposalOrchestrator
from weall.runtime.helper_replay_guard import HelperReplayGuard
from weall.runtime.parallel_execution import canonical_lane_plan_fingerprint, plan_parallel_execution


def _pub_hex_from_seed(seed_hex: str) -> str:
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
    return key.public_key().public_bytes_raw().hex()


def test_helper_message_disorder_batch_ingest_is_deterministic_batch35() -> None:
    txs = [
        {"tx_id": "c1", "tx_type": "CONTENT_CREATE", "state_prefixes": ["content:post:1"]},
        {"tx_id": "i1", "tx_type": "IDENTITY_UPDATE", "state_prefixes": ["identity:user:alice"]},
    ]
    lane_plans = plan_parallel_execution(
        txs=txs,
        validators=["v1", "v2", "v3"],
        validator_set_hash="vhash",
        view=7,
        leader_id="v1",
    )
    helper_lanes = tuple(plan for plan in lane_plans if plan.helper_id)
    assert len(helper_lanes) >= 2
    plan_id = canonical_lane_plan_fingerprint(lane_plans)

    helper_pubkeys = {}
    certs = []
    for idx, lane_plan in enumerate(sorted(helper_lanes, key=lambda item: item.lane_id), start=1):
        seed = (bytes([20 + idx]) * 32).hex()
        helper_pubkeys[str(lane_plan.helper_id)] = _pub_hex_from_seed(seed)
        cert = sign_helper_certificate(
            HelperExecutionCertificate(
                chain_id="c1",
                block_height=22,
                view=7,
                leader_id="v1",
                helper_id=str(lane_plan.helper_id),
                validator_epoch=9,
                validator_set_hash="vhash",
                lane_id=str(lane_plan.lane_id),
                tx_ids=lane_plan.tx_ids,
                tx_order_hash="order",
                receipts_root=f"receipts-{idx}",
                write_set_hash=f"writes-{idx}",
                read_set_hash=f"reads-{idx}",
                lane_delta_hash=f"delta-{idx}",
                namespace_hash=make_namespace_hash(lane_plan.namespace_prefixes),
                plan_id=plan_id,
            ),
            privkey=seed,
        )
        certs.append((cert, str(lane_plan.helper_id)))

    orchestrator = HelperProposalOrchestrator(
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
        helper_pubkeys=helper_pubkeys,
        helper_timeout_ms=50,
    )
    orchestrator.start_collection(started_ms=1000)
    replay = HelperReplayGuard(orchestrator=orchestrator)

    outcomes = replay.ingest_certificates_batch(certificates=list(reversed(certs)))
    assert len(outcomes) == len(certs)
    assert all(item.accepted for item in outcomes)
    assert replay.resolved_lanes() == tuple(sorted(plan.lane_id for plan in helper_lanes))

    duplicate = replay.ingest_certificate(cert=certs[0][0], peer_id=certs[0][1])
    assert duplicate.accepted is False
    assert duplicate.code == "duplicate_replay"
