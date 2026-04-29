from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from weall.runtime.helper_assembly_gate import HelperAssemblyProfile
from weall.runtime.helper_certificates import (
    HelperExecutionCertificate,
    make_namespace_hash,
    sign_helper_certificate,
)
from weall.runtime.helper_dispatch import HelperDispatchContext
from weall.runtime.helper_lane_journal import HelperLaneJournal
from weall.runtime.helper_merge_admission import (
    canonical_receipts_root,
    canonical_state_delta_hash,
)
from weall.runtime.helper_proposal_orchestrator import HelperProposalOrchestrator
from weall.runtime.helper_restart_replay import build_helper_restart_snapshot
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


def _mk_signed_cert(*, helper_id: str, lane_id: str, tx_ids: tuple[str, ...], seed_byte: int, receipts_root: str = "receipts", lane_delta_hash: str = "delta"):
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
            lane_delta_hash=lane_delta_hash,
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


def test_helper_restart_snapshot_matches_after_helper_acceptance_batch10(tmp_path) -> None:
    lane_plans, lane_plan = _lane_setup()
    journal = HelperLaneJournal(str(tmp_path / "helper_lane.jsonl"))
    receipts = [{"tx_id": "t1", "status": "ok"}]
    delta = {"balances:alice": 5}
    cert, pub = _mk_signed_cert(
        helper_id=lane_plan.helper_id,
        lane_id=lane_plan.lane_id,
        tx_ids=lane_plan.tx_ids,
        seed_byte=7,
        receipts_root=canonical_receipts_root(receipts),
        lane_delta_hash=canonical_state_delta_hash(delta),
    )

    orch = HelperProposalOrchestrator(
        context=_context(),
        lane_plans=lane_plans,
        helper_pubkeys={lane_plan.helper_id: pub},
        journal=journal,
        helper_timeout_ms=50,
    )
    orch.start_collection(started_ms=1000)
    status = orch.ingest_certificate(cert=cert, peer_id=lane_plan.helper_id)
    assert status.accepted is True

    profile = HelperAssemblyProfile(helper_mode_enabled=True)
    lane_results_by_id = {
        lane_plan.lane_id: {
            "receipts": receipts,
            "state_delta": delta,
        }
    }

    before = build_helper_restart_snapshot(
        profile=profile,
        context=_context(),
        lane_plans=lane_plans,
        lane_results_by_id=lane_results_by_id,
        journal=journal,
        helper_pubkeys={lane_plan.helper_id: pub},
        helper_timeout_ms=50,
        serial_equivalence_fn=lambda candidates: True,
    )
    after = build_helper_restart_snapshot(
        profile=profile,
        context=_context(),
        lane_plans=lane_plans,
        lane_results_by_id=lane_results_by_id,
        journal=journal,
        helper_pubkeys={lane_plan.helper_id: pub},
        helper_timeout_ms=50,
        serial_equivalence_fn=lambda candidates: True,
    )

    assert before.to_json() == after.to_json()
    assert before.snapshot_hash() == after.snapshot_hash()
    assert before.assembly_mode == "helper_assisted"
    assert before.assembly_accepted is True


def test_helper_restart_snapshot_matches_after_fallback_batch10(tmp_path) -> None:
    lane_plans, lane_plan = _lane_setup()
    journal = HelperLaneJournal(str(tmp_path / "helper_lane.jsonl"))
    orch = HelperProposalOrchestrator(
        context=_context(),
        lane_plans=lane_plans,
        journal=journal,
        helper_timeout_ms=50,
    )
    orch.start_collection(started_ms=1000)
    orch.finalize_timeouts(now_ms=1050)

    profile = HelperAssemblyProfile(
        helper_mode_enabled=True,
        require_serial_equivalence=False,
    )
    lane_results_by_id = {
        lane_plan.lane_id: {
            "receipts": [{"tx_id": "t1", "status": "ok"}],
            "state_delta": {"balances:alice": 5},
        }
    }

    before = build_helper_restart_snapshot(
        profile=profile,
        context=_context(),
        lane_plans=lane_plans,
        lane_results_by_id=lane_results_by_id,
        journal=journal,
        helper_timeout_ms=50,
    )
    after = build_helper_restart_snapshot(
        profile=profile,
        context=_context(),
        lane_plans=lane_plans,
        lane_results_by_id=lane_results_by_id,
        journal=journal,
        helper_timeout_ms=50,
    )

    assert before.to_json() == after.to_json()
    assert before.snapshot_hash() == after.snapshot_hash()
    assert before.finalized_modes == ((lane_plan.lane_id, "fallback"),)
    assert before.assembly_mode == "helper_assisted"
    assert before.assembly_accepted is True


def test_helper_restart_snapshot_surfaces_serial_fallback_equivalence_batch10(tmp_path) -> None:
    lane_plans, lane_plan = _lane_setup()
    journal = HelperLaneJournal(str(tmp_path / "helper_lane.jsonl"))
    orch = HelperProposalOrchestrator(
        context=_context(),
        lane_plans=lane_plans,
        journal=journal,
        helper_timeout_ms=50,
    )
    orch.start_collection(started_ms=1000)
    orch.finalize_timeouts(now_ms=1050)

    profile = HelperAssemblyProfile(
        helper_mode_enabled=True,
        require_serial_equivalence=True,
        fail_closed_on_helper_error=False,
    )
    lane_results_by_id = {
        lane_plan.lane_id: {
            "receipts": [{"tx_id": "t1", "status": "ok"}],
            "state_delta": {"balances:alice": 5},
        }
    }

    snapshot = build_helper_restart_snapshot(
        profile=profile,
        context=_context(),
        lane_plans=lane_plans,
        lane_results_by_id=lane_results_by_id,
        journal=journal,
        helper_timeout_ms=50,
        serial_equivalence_fn=lambda candidates: False,
    )
    assert snapshot.assembly_mode == "serial_only"
    assert snapshot.assembly_code == "serial_fallback:serial_equivalence_failed"
    assert snapshot.assembly_accepted is True
