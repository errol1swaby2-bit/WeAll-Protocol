from __future__ import annotations

from weall.runtime.helper_preflight_gate import (
    ProductionPreflightInput,
    decide_production_preflight,
)
from weall.runtime.helper_release_gate import build_helper_release_gate_report


def _all_green_report():
    return build_helper_release_gate_report(
        deterministic_replay_ok=True,
        timeout_fallback_ok=True,
        conflicting_replay_ok=True,
        restart_recovery_ok=True,
        merge_admission_ok=True,
        fail_closed_ok=True,
        serial_degrade_ok=True,
        soak_ok=True,
    )


def _one_red_report():
    return build_helper_release_gate_report(
        deterministic_replay_ok=True,
        timeout_fallback_ok=True,
        conflicting_replay_ok=False,
        restart_recovery_ok=True,
        merge_admission_ok=True,
        fail_closed_ok=True,
        serial_degrade_ok=True,
        soak_ok=True,
    )


def test_preflight_accepts_serial_only_without_helper_gate_batch17() -> None:
    decision = decide_production_preflight(
        preflight=ProductionPreflightInput(
            helper_mode_enabled=False,
            helper_release_gate=None,
        )
    )
    assert decision.accepted is True
    assert decision.code == "preflight_ready_serial_only"
    assert decision.helper_required is False
    assert decision.helper_ready is False


def test_preflight_rejects_enabled_helper_mode_without_gate_batch17() -> None:
    decision = decide_production_preflight(
        preflight=ProductionPreflightInput(
            helper_mode_enabled=True,
            helper_release_gate=None,
        )
    )
    assert decision.accepted is False
    assert decision.code == "helper_release_gate_missing"
    assert decision.helper_required is True


def test_preflight_accepts_enabled_helper_mode_when_release_gate_passes_batch17() -> None:
    decision = decide_production_preflight(
        preflight=ProductionPreflightInput(
            helper_mode_enabled=True,
            helper_release_gate=_all_green_report(),
        )
    )
    assert decision.accepted is True
    assert decision.code == "preflight_ready_with_helpers"
    assert decision.helper_required is True
    assert decision.helper_ready is True
    assert decision.release_score == 100


def test_preflight_rejects_enabled_helper_mode_when_release_gate_fails_batch17() -> None:
    decision = decide_production_preflight(
        preflight=ProductionPreflightInput(
            helper_mode_enabled=True,
            helper_release_gate=_one_red_report(),
        )
    )
    assert decision.accepted is False
    assert decision.code == "helper_release_gate_failed"
    assert decision.helper_required is True
    assert decision.helper_ready is False
    assert decision.release_score == 87


def test_preflight_rejects_core_runtime_prereq_before_helper_consideration_batch17() -> None:
    decision = decide_production_preflight(
        preflight=ProductionPreflightInput(
            chain_id_ok=True,
            protocol_profile_ok=False,
            validator_set_ok=True,
            trusted_anchor_ok=True,
            sqlite_wal_ok=True,
            helper_mode_enabled=True,
            helper_release_gate=_all_green_report(),
        )
    )
    assert decision.accepted is False
    assert decision.code == "protocol_profile_not_ready"
    assert decision.helper_required is True
