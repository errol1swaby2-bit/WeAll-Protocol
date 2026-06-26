from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

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
from weall.runtime.helper_soak_harness import (
    HelperSoakPlan,
    run_helper_soak,
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


def _mk_signed_cert(*, block_height: int, helper_id: str, lane_id: str, tx_ids: tuple[str, ...], seed_byte: int, receipts_root: str, lane_delta_hash: str):
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
        return HelperLaneJournal(str(tmp_path / f"helper_soak_{idx}.jsonl"))
    return factory


def test_helper_soak_mixed_helper_and_fallback_rounds_batch15(tmp_path) -> None:
    lane_plans, lane_plan = _lane_setup()
    receipts_ok = [{"tx_id": "t1", "status": "ok"}]
    delta_ok = {"balances:alice": 5}
    receipts_root_ok = canonical_receipts_root(receipts_ok)
    delta_hash_ok = canonical_state_delta_hash(delta_ok)

    helper_certs = {}
    pub = None
    for height in (500, 502, 504):
        cert, pub = _mk_signed_cert(
            block_height=height,
            helper_id=lane_plan.helper_id,
            lane_id=lane_plan.lane_id,
            tx_ids=lane_plan.tx_ids,
            seed_byte=5,
            receipts_root=receipts_root_ok,
            lane_delta_hash=delta_hash_ok,
        )
        helper_certs[height] = cert

    summary = run_helper_soak(
        base_context=_base_context(),
        lane_plans=lane_plans,
        start_height=500,
        helper_cert_by_height=helper_certs,
        lane_results_by_id={
            lane_plan.lane_id: {"receipts": receipts_ok, "state_delta": delta_ok}
        },
        plan=HelperSoakPlan(rounds=6, helper_every_n=2, require_serial_equivalence=False),
        helper_pubkeys={lane_plan.helper_id: pub},
        journal_factory=_journal_factory(tmp_path),
        helper_timeout_ms=50,
    )

    assert summary.rounds == 6
    assert summary.accepted_heights == (500, 501, 502, 503, 504, 505)
    assert summary.helper_assisted_heights == (500, 501, 502, 503, 504, 505)
    assert summary.fallback_heights == (501, 503, 505)
    assert summary.failed_heights == ()


def test_helper_soak_fail_closed_marks_bad_helper_round_failed_batch15(tmp_path) -> None:
    lane_plans, lane_plan = _lane_setup()
    receipts_ok = [{"tx_id": "t1", "status": "ok"}]
    delta_ok = {"balances:alice": 5}
    receipts_root_ok = canonical_receipts_root(receipts_ok)
    delta_hash_ok = canonical_state_delta_hash(delta_ok)

    good_cert, pub = _mk_signed_cert(
        block_height=600,
        helper_id=lane_plan.helper_id,
        lane_id=lane_plan.lane_id,
        tx_ids=lane_plan.tx_ids,
        seed_byte=6,
        receipts_root=receipts_root_ok,
        lane_delta_hash=delta_hash_ok,
    )
    bad_cert, _ = _mk_signed_cert(
        block_height=602,
        helper_id=lane_plan.helper_id,
        lane_id=lane_plan.lane_id,
        tx_ids=lane_plan.tx_ids,
        seed_byte=6,
        receipts_root="wrong-root",
        lane_delta_hash=delta_hash_ok,
    )

    summary = run_helper_soak(
        base_context=_base_context(),
        lane_plans=lane_plans,
        start_height=600,
        helper_cert_by_height={600: good_cert, 602: bad_cert},
        lane_results_by_id={
            lane_plan.lane_id: {"receipts": receipts_ok, "state_delta": delta_ok}
        },
        plan=HelperSoakPlan(rounds=4, helper_every_n=2, require_serial_equivalence=False, fail_closed_on_helper_error=True),
        helper_pubkeys={lane_plan.helper_id: pub},
        journal_factory=_journal_factory(tmp_path),
        helper_timeout_ms=50,
    )

    assert 602 in summary.failed_heights
    assert (600, "accepted") in summary.cycle_codes
    assert (602, "receipts_root_mismatch") in summary.cycle_codes


def test_helper_soak_can_degrade_to_serial_when_allowed_batch15(tmp_path) -> None:
    lane_plans, lane_plan = _lane_setup()
    receipts_ok = [{"tx_id": "t1", "status": "ok"}]
    delta_ok = {"balances:alice": 5}
    receipts_root_ok = canonical_receipts_root(receipts_ok)
    delta_hash_ok = canonical_state_delta_hash(delta_ok)

    helper_certs = {}
    pub = None
    for height in (700, 702):
        cert, pub = _mk_signed_cert(
            block_height=height,
            helper_id=lane_plan.helper_id,
            lane_id=lane_plan.lane_id,
            tx_ids=lane_plan.tx_ids,
            seed_byte=7,
            receipts_root=receipts_root_ok,
            lane_delta_hash=delta_hash_ok,
        )
        helper_certs[height] = cert

    summary = run_helper_soak(
        base_context=_base_context(),
        lane_plans=lane_plans,
        start_height=700,
        helper_cert_by_height=helper_certs,
        lane_results_by_id={
            lane_plan.lane_id: {"receipts": receipts_ok, "state_delta": delta_ok}
        },
        plan=HelperSoakPlan(rounds=4, helper_every_n=2, require_serial_equivalence=True, fail_closed_on_helper_error=False),
        helper_pubkeys={lane_plan.helper_id: pub},
        journal_factory=_journal_factory(tmp_path),
        helper_timeout_ms=50,
        serial_equivalence_fn=lambda candidates: False,
    )

    # With require_serial_equivalence=True and degrade-to-serial enabled,
    # both helper-resolved and fallback-resolved rounds degrade to serial_only
    # when the equivalence function returns False.
    assert summary.serial_only_heights == (700, 701, 702, 703)
    assert summary.failed_heights == ()
