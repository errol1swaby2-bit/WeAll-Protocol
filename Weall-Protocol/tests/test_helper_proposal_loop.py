from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from weall.runtime.helper_certificates import (
    HelperExecutionCertificate,
    make_namespace_hash,
    sign_helper_certificate,
)
from weall.runtime.helper_dispatch import HelperDispatchContext
from weall.runtime.helper_event_driver import HelperEvent
from weall.runtime.helper_lane_journal import HelperLaneJournal
from weall.runtime.helper_merge_admission import (
    canonical_receipts_root,
    canonical_state_delta_hash,
)
from weall.runtime.helper_proposal_loop import (
    HelperProposalCycleInput,
    run_helper_proposal_loop,
)
from weall.runtime.parallel_execution import plan_parallel_execution


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


def _pub_hex_from_seed(seed_hex: str) -> str:
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
    return key.public_key().public_bytes_raw().hex()


def _mk_signed_cert(
    *,
    block_height: int,
    helper_id: str,
    lane_id: str,
    tx_ids: tuple[str, ...],
    seed_byte: int,
    receipts_root: str,
    lane_delta_hash: str,
):
    seed = (bytes([seed_byte]) * 32).hex()
    pub = _pub_hex_from_seed(seed)
    cert = sign_helper_certificate(
        HelperExecutionCertificate(
            chain_id="c1",
            block_height=int(block_height),
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


def _base_context():
    return HelperDispatchContext(
        chain_id="c1",
        block_height=0,
        view=7,
        leader_id="v1",
        validator_epoch=9,
        validator_set_hash="vhash",
    )


def _journal_factory(tmp_path: Path):
    def factory(idx: int):
        return HelperLaneJournal(str(tmp_path / f"helper_loop_{idx}.jsonl"))
    return factory


def test_helper_proposal_loop_mixed_cycles_batch14(tmp_path) -> None:
    lane_plans, lane_plan = _lane_setup()

    receipts_ok = [{"tx_id": "t1", "status": "ok"}]
    delta_ok = {"balances:alice": 5}
    receipts_root_ok = canonical_receipts_root(receipts_ok)
    delta_hash_ok = canonical_state_delta_hash(delta_ok)

    # Use the same helper key across cycles for the same helper_id.
    cert_101, pub = _mk_signed_cert(
        block_height=101,
        helper_id=lane_plan.helper_id,
        lane_id=lane_plan.lane_id,
        tx_ids=lane_plan.tx_ids,
        seed_byte=5,
        receipts_root=receipts_root_ok,
        lane_delta_hash=delta_hash_ok,
    )
    cert_103, _ = _mk_signed_cert(
        block_height=103,
        helper_id=lane_plan.helper_id,
        lane_id=lane_plan.lane_id,
        tx_ids=lane_plan.tx_ids,
        seed_byte=5,
        receipts_root=receipts_root_ok,
        lane_delta_hash=delta_hash_ok,
    )

    cycles = (
        HelperProposalCycleInput(
            block_height=101,
            events=(
                HelperEvent(kind="start", started_ms=1000),
                HelperEvent(kind="cert", cert=cert_101, peer_id=lane_plan.helper_id),
            ),
            lane_results_by_id={
                lane_plan.lane_id: {"receipts": receipts_ok, "state_delta": delta_ok}
            },
            require_serial_equivalence=True,
            fail_closed_on_helper_error=True,
        ),
        HelperProposalCycleInput(
            block_height=102,
            events=(
                HelperEvent(kind="start", started_ms=2000),
                HelperEvent(kind="timeout", now_ms=2050),
            ),
            lane_results_by_id={
                lane_plan.lane_id: {"receipts": receipts_ok, "state_delta": delta_ok}
            },
            require_serial_equivalence=False,
            fail_closed_on_helper_error=True,
        ),
        HelperProposalCycleInput(
            block_height=103,
            events=(
                HelperEvent(kind="start", started_ms=3000),
                HelperEvent(kind="cert", cert=cert_103, peer_id=lane_plan.helper_id),
            ),
            lane_results_by_id={
                lane_plan.lane_id: {"receipts": receipts_ok, "state_delta": delta_ok}
            },
            require_serial_equivalence=True,
            fail_closed_on_helper_error=False,
        ),
    )

    summary = run_helper_proposal_loop(
        base_context=_base_context(),
        lane_plans=lane_plans,
        cycles=cycles,
        helper_pubkeys={lane_plan.helper_id: pub},
        journal_factory=_journal_factory(tmp_path),
        helper_timeout_ms=50,
        serial_equivalence_fn=lambda candidates: True,
    )

    assert summary.cycle_count == 3
    assert summary.accepted_heights() == (101, 102, 103)
    assert summary.helper_assisted_heights() == (101, 102, 103)
    assert summary.results[0].finalized_modes == ((lane_plan.lane_id, "helper"),)
    assert summary.results[1].finalized_modes == ((lane_plan.lane_id, "fallback"),)
    assert summary.results[2].finalized_modes == ((lane_plan.lane_id, "helper"),)


def test_helper_proposal_loop_degrades_to_serial_when_allowed_batch14(tmp_path) -> None:
    lane_plans, lane_plan = _lane_setup()

    receipts_ok = [{"tx_id": "t1", "status": "ok"}]
    delta_ok = {"balances:alice": 5}
    receipts_root_ok = canonical_receipts_root(receipts_ok)
    delta_hash_ok = canonical_state_delta_hash(delta_ok)
    cert_ok, pub = _mk_signed_cert(
        block_height=201,
        helper_id=lane_plan.helper_id,
        lane_id=lane_plan.lane_id,
        tx_ids=lane_plan.tx_ids,
        seed_byte=7,
        receipts_root=receipts_root_ok,
        lane_delta_hash=delta_hash_ok,
    )

    cycles = (
        HelperProposalCycleInput(
            block_height=201,
            events=(
                HelperEvent(kind="start", started_ms=1000),
                HelperEvent(kind="cert", cert=cert_ok, peer_id=lane_plan.helper_id),
            ),
            lane_results_by_id={
                lane_plan.lane_id: {"receipts": receipts_ok, "state_delta": delta_ok}
            },
            require_serial_equivalence=True,
            fail_closed_on_helper_error=False,
        ),
    )

    summary = run_helper_proposal_loop(
        base_context=_base_context(),
        lane_plans=lane_plans,
        cycles=cycles,
        helper_pubkeys={lane_plan.helper_id: pub},
        journal_factory=_journal_factory(tmp_path),
        helper_timeout_ms=50,
        serial_equivalence_fn=lambda candidates: False,
    )

    result = summary.results[0]
    assert result.assembly_accepted is True
    assert result.assembly_mode == "serial_only"
    assert result.assembly_code == "serial_fallback:serial_equivalence_failed"
    assert result.finalized_modes == ((lane_plan.lane_id, "helper"),)


def test_helper_proposal_loop_fail_closed_on_helper_error_batch14(tmp_path) -> None:
    lane_plans, lane_plan = _lane_setup()

    receipts_ok = [{"tx_id": "t1", "status": "ok"}]
    delta_ok = {"balances:alice": 5}
    bad_cert, pub = _mk_signed_cert(
        block_height=301,
        helper_id=lane_plan.helper_id,
        lane_id=lane_plan.lane_id,
        tx_ids=lane_plan.tx_ids,
        seed_byte=8,
        receipts_root="wrong-root",
        lane_delta_hash=canonical_state_delta_hash(delta_ok),
    )

    cycles = (
        HelperProposalCycleInput(
            block_height=301,
            events=(
                HelperEvent(kind="start", started_ms=1000),
                HelperEvent(kind="cert", cert=bad_cert, peer_id=lane_plan.helper_id),
            ),
            lane_results_by_id={
                lane_plan.lane_id: {"receipts": receipts_ok, "state_delta": delta_ok}
            },
            require_serial_equivalence=False,
            fail_closed_on_helper_error=True,
        ),
    )

    summary = run_helper_proposal_loop(
        base_context=_base_context(),
        lane_plans=lane_plans,
        cycles=cycles,
        helper_pubkeys={lane_plan.helper_id: pub},
        journal_factory=_journal_factory(tmp_path),
        helper_timeout_ms=50,
    )

    result = summary.results[0]
    assert result.assembly_accepted is False
    assert result.assembly_mode == "helper_assisted"
    assert result.assembly_code == "receipts_root_mismatch"


def test_helper_proposal_loop_restart_reuse_across_cycles_batch14(tmp_path) -> None:
    lane_plans, lane_plan = _lane_setup()

    receipts_ok = [{"tx_id": "t1", "status": "ok"}]
    delta_ok = {"balances:alice": 5}
    receipts_root_ok = canonical_receipts_root(receipts_ok)
    delta_hash_ok = canonical_state_delta_hash(delta_ok)
    cert_ok, pub = _mk_signed_cert(
        block_height=401,
        helper_id=lane_plan.helper_id,
        lane_id=lane_plan.lane_id,
        tx_ids=lane_plan.tx_ids,
        seed_byte=9,
        receipts_root=receipts_root_ok,
        lane_delta_hash=delta_hash_ok,
    )

    shared = HelperLaneJournal(str(tmp_path / "shared_loop.jsonl"))

    summary1 = run_helper_proposal_loop(
        base_context=_base_context(),
        lane_plans=lane_plans,
        cycles=(
            HelperProposalCycleInput(
                block_height=401,
                events=(
                    HelperEvent(kind="start", started_ms=1000),
                    HelperEvent(kind="cert", cert=cert_ok, peer_id=lane_plan.helper_id),
                ),
                lane_results_by_id={
                    lane_plan.lane_id: {"receipts": receipts_ok, "state_delta": delta_ok}
                },
                require_serial_equivalence=False,
                fail_closed_on_helper_error=True,
            ),
        ),
        helper_pubkeys={lane_plan.helper_id: pub},
        journal_factory=lambda idx: shared,
        helper_timeout_ms=50,
    )

    summary2 = run_helper_proposal_loop(
        base_context=_base_context(),
        lane_plans=lane_plans,
        cycles=(
            HelperProposalCycleInput(
                block_height=401,
                events=(
                    HelperEvent(kind="cert", cert=cert_ok, peer_id=lane_plan.helper_id),
                ),
                lane_results_by_id={
                    lane_plan.lane_id: {"receipts": receipts_ok, "state_delta": delta_ok}
                },
                require_serial_equivalence=False,
                fail_closed_on_helper_error=True,
            ),
        ),
        helper_pubkeys={lane_plan.helper_id: pub},
        journal_factory=lambda idx: shared,
        helper_timeout_ms=50,
    )

    first = summary1.results[0]
    second = summary2.results[0]
    assert first.finalized_modes == second.finalized_modes
    assert second.event_codes == ("duplicate_replay",)
