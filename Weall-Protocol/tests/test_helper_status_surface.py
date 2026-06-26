from __future__ import annotations

from weall.runtime.helper_operator_diagnostics import build_helper_operator_diagnostic
from weall.runtime.helper_release_gate import build_helper_release_gate_report
from weall.runtime.helper_startup_integration import (
    HelperStartupConfig,
    evaluate_helper_startup,
)
from weall.runtime.helper_status_surface import build_helper_status_surface


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


def _not_ready_report():
    return build_helper_release_gate_report(
        deterministic_replay_ok=True,
        timeout_fallback_ok=True,
        conflicting_replay_ok=True,
        restart_recovery_ok=True,
        merge_admission_ok=False,
        fail_closed_ok=True,
        serial_degrade_ok=True,
        soak_ok=True,
    )


def test_helper_status_surface_serial_only_batch20() -> None:
    status = evaluate_helper_startup(
        config=HelperStartupConfig(helper_mode_requested=False),
        helper_release_gate=None,
    )
    diagnostic = build_helper_operator_diagnostic(status=status)
    surface = build_helper_status_surface(diagnostic=diagnostic)

    payload = surface.to_json()
    assert payload["helper_status"] == "serial_only"
    assert payload["helper_severity"] == "warning"
    assert payload["helper_summary"] == "startup ready in serial-only mode; helper mode inactive"
    assert payload["helper_startup"]["startup_mode"] == "serial_only"
    assert payload["helper_startup"]["helper_mode_active"] is False


def test_helper_status_surface_helper_enabled_batch20() -> None:
    status = evaluate_helper_startup(
        config=HelperStartupConfig(helper_mode_requested=True),
        helper_release_gate=_all_green_report(),
    )
    diagnostic = build_helper_operator_diagnostic(status=status)
    surface = build_helper_status_surface(diagnostic=diagnostic)

    payload = surface.to_json()
    assert payload["helper_status"] == "helper_enabled"
    assert payload["helper_severity"] == "info"
    assert payload["helper_summary"] == "startup ready with helper mode enabled"
    assert payload["helper_startup"]["helper_release_score"] == 100
    assert payload["helper_startup"]["helper_mode_active"] is True


def test_helper_status_surface_blocked_batch20() -> None:
    status = evaluate_helper_startup(
        config=HelperStartupConfig(helper_mode_requested=True),
        helper_release_gate=_not_ready_report(),
    )
    diagnostic = build_helper_operator_diagnostic(status=status)
    surface = build_helper_status_surface(diagnostic=diagnostic)

    payload = surface.to_json()
    assert payload["helper_status"] == "blocked"
    assert payload["helper_severity"] == "error"
    assert payload["helper_summary"] == "startup blocked: helper_release_gate_failed"
    assert payload["helper_startup"]["startup_allowed"] is False
    assert payload["helper_startup"]["helper_mode_active"] is False
