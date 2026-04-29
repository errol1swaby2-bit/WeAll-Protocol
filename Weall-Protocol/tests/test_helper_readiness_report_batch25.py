from __future__ import annotations

from weall.runtime.helper_operator_diagnostics import build_helper_operator_diagnostic
from weall.runtime.helper_preflight_gate import (
    ProductionPreflightInput,
    decide_production_preflight,
)
from weall.runtime.helper_readiness_report import build_helper_readiness_report
from weall.runtime.helper_release_gate import build_helper_release_gate_report
from weall.runtime.helper_startup_integration import (
    HelperStartupConfig,
    evaluate_helper_startup,
)


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
        conflicting_replay_ok=False,
        restart_recovery_ok=True,
        merge_admission_ok=True,
        fail_closed_ok=True,
        serial_degrade_ok=True,
        soak_ok=True,
    )


def test_helper_readiness_report_ready_with_helpers_batch25() -> None:
    release = _all_green_report()
    preflight = decide_production_preflight(
        preflight=ProductionPreflightInput(
            helper_mode_enabled=True,
            helper_release_gate=release,
        )
    )
    startup = evaluate_helper_startup(
        config=HelperStartupConfig(helper_mode_requested=True),
        helper_release_gate=release,
    )
    diagnostic = build_helper_operator_diagnostic(status=startup)

    report = build_helper_readiness_report(
        preflight_decision=preflight,
        startup_status=startup,
        operator_diagnostic=diagnostic,
        release_gate_report=release,
    ).to_json()

    assert report["overall_status"] == "ready"
    assert report["overall_summary"] == "helper mode ready and active"
    assert report["preflight"]["accepted"] is True
    assert report["startup"]["startup_mode"] == "helper_enabled"
    assert report["operator"]["severity"] == "info"
    assert report["release_gate"]["readiness_score"] == 100


def test_helper_readiness_report_serial_only_batch25() -> None:
    preflight = decide_production_preflight(
        preflight=ProductionPreflightInput(
            helper_mode_enabled=False,
            helper_release_gate=None,
        )
    )
    startup = evaluate_helper_startup(
        config=HelperStartupConfig(helper_mode_requested=False),
        helper_release_gate=None,
    )
    diagnostic = build_helper_operator_diagnostic(status=startup)

    report = build_helper_readiness_report(
        preflight_decision=preflight,
        startup_status=startup,
        operator_diagnostic=diagnostic,
        release_gate_report=None,
    ).to_json()

    assert report["overall_status"] == "serial_only"
    assert report["overall_summary"] == "node ready in serial-only mode; helper mode inactive"
    assert report["preflight"]["accepted"] is True
    assert report["startup"]["startup_mode"] == "serial_only"
    assert report["release_gate"] is None


def test_helper_readiness_report_blocked_batch25() -> None:
    release = _not_ready_report()
    preflight = decide_production_preflight(
        preflight=ProductionPreflightInput(
            helper_mode_enabled=True,
            helper_release_gate=release,
        )
    )
    startup = evaluate_helper_startup(
        config=HelperStartupConfig(helper_mode_requested=True),
        helper_release_gate=release,
    )
    diagnostic = build_helper_operator_diagnostic(status=startup)

    report = build_helper_readiness_report(
        preflight_decision=preflight,
        startup_status=startup,
        operator_diagnostic=diagnostic,
        release_gate_report=release,
    ).to_json()

    assert report["overall_status"] == "blocked"
    assert report["overall_summary"] == "helper startup blocked: helper_release_gate_failed"
    assert report["preflight"]["accepted"] is False
    assert report["startup"]["startup_allowed"] is False
    assert report["operator"]["severity"] == "error"
    assert report["release_gate"]["passed_gates"] == 7
