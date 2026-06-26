from __future__ import annotations

from weall.runtime.helper_assembly_gate import (
    HelperAssemblyProfile,
    decide_helper_block_assembly,
)
from weall.runtime.helper_merge_admission import (
    canonical_receipts_root,
    canonical_state_delta_hash,
)
from weall.runtime.helper_proposal_orchestrator import HelperLaneResolution


class _Cert:
    def __init__(self, receipts_root: str = "", lane_delta_hash: str = "") -> None:
        self.receipts_root = receipts_root
        self.lane_delta_hash = lane_delta_hash


def _resolution(
    *,
    lane_id: str,
    helper_id: str = "helper-1",
    mode: str = "helper",
    receipts_root: str = "",
    lane_delta_hash: str = "",
):
    cert = None
    if receipts_root or lane_delta_hash:
        cert = _Cert(receipts_root=receipts_root, lane_delta_hash=lane_delta_hash)
    return HelperLaneResolution(
        lane_id=lane_id,
        helper_id=helper_id,
        mode=mode,
        certificate=cert,
    )


def test_helper_assembly_gate_uses_serial_when_disabled_batch9() -> None:
    decision = decide_helper_block_assembly(
        profile=HelperAssemblyProfile(helper_mode_enabled=False),
        resolutions=(),
        lane_results_by_id={},
    )
    assert decision.accepted is True
    assert decision.mode == "serial_only"
    assert decision.code == "helper_mode_disabled"


def test_helper_assembly_gate_accepts_helper_path_when_merge_admission_passes_batch9() -> None:
    receipts = [{"tx_id": "t1", "status": "ok"}]
    delta = {"balances:alice": 5}
    decision = decide_helper_block_assembly(
        profile=HelperAssemblyProfile(helper_mode_enabled=True),
        resolutions=(
            _resolution(
                lane_id="lane-a",
                receipts_root=canonical_receipts_root(receipts),
                lane_delta_hash=canonical_state_delta_hash(delta),
            ),
        ),
        lane_results_by_id={
            "lane-a": {
                "receipts": receipts,
                "state_delta": delta,
            }
        },
        serial_equivalence_fn=lambda candidates: True,
    )
    assert decision.accepted is True
    assert decision.mode == "helper_assisted"
    assert decision.code == "accepted"
    assert decision.merge_decision is not None
    assert decision.merge_decision.accepted is True


def test_helper_assembly_gate_fail_closed_when_enabled_and_merge_fails_batch9() -> None:
    receipts = [{"tx_id": "t1", "status": "ok"}]
    delta = {"balances:alice": 5}
    decision = decide_helper_block_assembly(
        profile=HelperAssemblyProfile(
            helper_mode_enabled=True,
            require_serial_equivalence=True,
            fail_closed_on_helper_error=True,
        ),
        resolutions=(
            _resolution(
                lane_id="lane-a",
                receipts_root=canonical_receipts_root(receipts),
                lane_delta_hash=canonical_state_delta_hash(delta),
            ),
        ),
        lane_results_by_id={
            "lane-a": {
                "receipts": receipts,
                "state_delta": delta,
            }
        },
        serial_equivalence_fn=lambda candidates: False,
    )
    assert decision.accepted is False
    assert decision.mode == "helper_assisted"
    assert decision.code == "serial_equivalence_failed"


def test_helper_assembly_gate_can_degrade_to_serial_when_allowed_batch9() -> None:
    receipts = [{"tx_id": "t1", "status": "ok"}]
    delta = {"balances:alice": 5}
    decision = decide_helper_block_assembly(
        profile=HelperAssemblyProfile(
            helper_mode_enabled=True,
            require_serial_equivalence=True,
            fail_closed_on_helper_error=False,
        ),
        resolutions=(
            _resolution(
                lane_id="lane-a",
                receipts_root=canonical_receipts_root(receipts),
                lane_delta_hash=canonical_state_delta_hash(delta),
            ),
        ),
        lane_results_by_id={
            "lane-a": {
                "receipts": receipts,
                "state_delta": delta,
            }
        },
        serial_equivalence_fn=lambda candidates: False,
    )
    assert decision.accepted is True
    assert decision.mode == "serial_only"
    assert decision.code == "serial_fallback:serial_equivalence_failed"


def test_helper_assembly_gate_rejects_merge_conflict_batch9() -> None:
    res_a = _resolution(lane_id="lane-a")
    res_b = _resolution(lane_id="lane-b", mode="fallback")
    decision = decide_helper_block_assembly(
        profile=HelperAssemblyProfile(helper_mode_enabled=True),
        resolutions=(res_a, res_b),
        lane_results_by_id={
            "lane-a": {
                "receipts": [{"tx_id": "t1"}],
                "state_delta": {"balances:alice": 5},
            },
            "lane-b": {
                "receipts": [{"tx_id": "t2"}],
                "state_delta": {"balances:alice": 7},
            },
        },
        serial_equivalence_fn=lambda candidates: True,
    )
    assert decision.accepted is False
    assert decision.code == "merge_conflict:balances:alice"
