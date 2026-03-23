from __future__ import annotations

from weall.runtime.helper_operator_diagnostics import build_helper_operator_diagnostic
from weall.runtime.helper_release_gate import build_helper_release_gate_report
from weall.runtime.helper_startup_integration import (
    HelperStartupConfig,
    evaluate_helper_startup,
)
from weall.runtime.helper_status_endpoint_integration import (
    build_node_status_envelope,
    build_readyz_envelope,
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


def _surface_from_status(status):
    diagnostic = build_helper_operator_diagnostic(status=status)
    return build_helper_status_surface(diagnostic=diagnostic)


def test_node_status_envelope_serial_only_batch21() -> None:
    status = evaluate_helper_startup(
        config=HelperStartupConfig(helper_mode_requested=False),
        helper_release_gate=None,
    )
    surface = _surface_from_status(status)

    envelope = build_node_status_envelope(
        chain_id="weall",
        base_ok=True,
        base_mode="validator",
        helper_surface=surface,
    ).to_json()

    assert envelope["ok"] is True
    assert envelope["chain_id"] == "weall"
    assert envelope["mode"] == "validator"
    assert envelope["helper"]["helper_status"] == "serial_only"
    assert envelope["helper"]["helper_severity"] == "warning"


def test_node_status_envelope_helper_enabled_batch21() -> None:
    status = evaluate_helper_startup(
        config=HelperStartupConfig(helper_mode_requested=True),
        helper_release_gate=_all_green_report(),
    )
    surface = _surface_from_status(status)

    envelope = build_node_status_envelope(
        chain_id="weall",
        base_ok=True,
        base_mode="validator",
        helper_surface=surface,
    ).to_json()

    assert envelope["helper"]["helper_status"] == "helper_enabled"
    assert envelope["helper"]["helper_severity"] == "info"
    assert envelope["helper"]["helper_startup"]["helper_mode_active"] is True


def test_readyz_envelope_passes_when_base_ready_and_helper_serial_only_batch21() -> None:
    status = evaluate_helper_startup(
        config=HelperStartupConfig(helper_mode_requested=False),
        helper_release_gate=None,
    )
    surface = _surface_from_status(status)

    readyz = build_readyz_envelope(
        chain_id="weall",
        base_ready=True,
        helper_surface=surface,
    ).to_json()

    assert readyz["ready"] is True
    assert readyz["helper_status"] == "serial_only"
    assert readyz["helper_severity"] == "warning"


def test_readyz_envelope_fails_when_helper_startup_blocked_batch21() -> None:
    status = evaluate_helper_startup(
        config=HelperStartupConfig(helper_mode_requested=True),
        helper_release_gate=_not_ready_report(),
    )
    surface = _surface_from_status(status)

    readyz = build_readyz_envelope(
        chain_id="weall",
        base_ready=True,
        helper_surface=surface,
    ).to_json()

    assert readyz["ready"] is False
    assert readyz["helper_status"] == "blocked"
    assert readyz["helper_severity"] == "error"
    assert readyz["helper_summary"] == "startup blocked: helper_release_gate_failed"


def test_readyz_envelope_fails_when_base_not_ready_even_if_helper_green_batch21() -> None:
    status = evaluate_helper_startup(
        config=HelperStartupConfig(helper_mode_requested=True),
        helper_release_gate=_all_green_report(),
    )
    surface = _surface_from_status(status)

    readyz = build_readyz_envelope(
        chain_id="weall",
        base_ready=False,
        helper_surface=surface,
    ).to_json()

    assert readyz["ready"] is False
    assert readyz["helper_status"] == "helper_enabled"
