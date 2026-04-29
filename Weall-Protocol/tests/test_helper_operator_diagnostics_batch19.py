from __future__ import annotations

from weall.runtime.helper_operator_diagnostics import build_helper_operator_diagnostic
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
        conflicting_replay_ok=True,
        restart_recovery_ok=True,
        merge_admission_ok=False,
        fail_closed_ok=True,
        serial_degrade_ok=True,
        soak_ok=True,
    )


def test_helper_operator_diagnostic_for_serial_only_startup_batch19() -> None:
    status = evaluate_helper_startup(
        config=HelperStartupConfig(helper_mode_requested=False),
        helper_release_gate=None,
    )
    diagnostic = build_helper_operator_diagnostic(status=status)

    assert diagnostic.startup_allowed is True
    assert diagnostic.startup_mode == "serial_only"
    assert diagnostic.helper_mode_active is False
    assert diagnostic.severity == "warning"
    assert diagnostic.summary == "startup ready in serial-only mode; helper mode inactive"


def test_helper_operator_diagnostic_for_helper_enabled_startup_batch19() -> None:
    status = evaluate_helper_startup(
        config=HelperStartupConfig(helper_mode_requested=True),
        helper_release_gate=_all_green_report(),
    )
    diagnostic = build_helper_operator_diagnostic(status=status)

    assert diagnostic.startup_allowed is True
    assert diagnostic.startup_mode == "helper_enabled"
    assert diagnostic.helper_mode_active is True
    assert diagnostic.severity == "info"
    assert diagnostic.helper_release_score == 100
    assert diagnostic.summary == "startup ready with helper mode enabled"


def test_helper_operator_diagnostic_for_blocked_startup_batch19() -> None:
    status = evaluate_helper_startup(
        config=HelperStartupConfig(helper_mode_requested=True),
        helper_release_gate=_not_ready_report(),
    )
    diagnostic = build_helper_operator_diagnostic(status=status)

    assert diagnostic.startup_allowed is False
    assert diagnostic.startup_mode == "blocked"
    assert diagnostic.helper_mode_active is False
    assert diagnostic.severity == "error"
    assert diagnostic.helper_release_score == 87
    assert diagnostic.summary == "startup blocked: helper_release_gate_failed"


def test_helper_operator_diagnostic_for_core_runtime_block_batch19() -> None:
    status = evaluate_helper_startup(
        config=HelperStartupConfig(
            helper_mode_requested=False,
            trusted_anchor_ok=False,
        ),
        helper_release_gate=None,
    )
    diagnostic = build_helper_operator_diagnostic(status=status)

    assert diagnostic.startup_allowed is False
    assert diagnostic.startup_mode == "blocked"
    assert diagnostic.severity == "error"
    assert diagnostic.summary == "startup blocked: trusted_anchor_not_ready"
