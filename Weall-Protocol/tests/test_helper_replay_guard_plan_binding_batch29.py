from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from weall.runtime.helper_certificates import HelperExecutionCertificate, make_namespace_hash, sign_helper_certificate
from weall.runtime.helper_dispatch import HelperDispatchContext
from weall.runtime.helper_lane_journal import HelperLaneJournal
from weall.runtime.helper_proposal_orchestrator import HelperProposalOrchestrator
from weall.runtime.helper_replay_guard import HelperReplayGuard
from weall.runtime.parallel_execution import canonical_lane_plan_fingerprint, plan_parallel_execution


def _pub_hex_from_seed(seed_hex: str) -> str:
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
    return key.public_key().public_bytes_raw().hex()


def test_replay_guard_rejects_wrong_plan_id_batch29(tmp_path) -> None:
    txs = [{"tx_id": "t1", "tx_type": "CONTENT_CREATE", "state_prefixes": ["content:post:1"]}]
    lane_plans = plan_parallel_execution(txs=txs, validators=["v1", "v2", "v3"], validator_set_hash="vhash", view=7, leader_id="v1")
    lane_plan = next(plan for plan in lane_plans if plan.lane_id == "PARALLEL_CONTENT")
    plan_id = canonical_lane_plan_fingerprint(lane_plans)
    seed = (bytes([7]) * 32).hex()
    pub = _pub_hex_from_seed(seed)
    cert = sign_helper_certificate(
        HelperExecutionCertificate(
            chain_id="c1", block_height=22, view=7, leader_id="v1", helper_id=lane_plan.helper_id, validator_epoch=9, validator_set_hash="vhash", lane_id=lane_plan.lane_id, tx_ids=lane_plan.tx_ids, tx_order_hash="order", receipts_root="receipts", write_set_hash="writes", read_set_hash="reads", lane_delta_hash="delta", namespace_hash=make_namespace_hash(["content:post:1"]), plan_id="other-plan",
        ),
        privkey=seed,
    )
    journal = HelperLaneJournal(str(tmp_path / "helper_lane.jsonl"))
    orchestrator = HelperProposalOrchestrator(
        context=HelperDispatchContext(chain_id="c1", block_height=22, view=7, leader_id="v1", validator_epoch=9, validator_set_hash="vhash", plan_id=plan_id),
        lane_plans=lane_plans,
        helper_pubkeys={lane_plan.helper_id: pub},
        journal=journal,
        helper_timeout_ms=50,
    )
    guard = HelperReplayGuard(orchestrator=orchestrator, journal=journal)
    outcome = guard.ingest_certificate(cert=cert, peer_id=lane_plan.helper_id)
    assert outcome.accepted is False
    assert outcome.code == "plan_id_mismatch"
