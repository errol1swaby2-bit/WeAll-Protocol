from __future__ import annotations

from weall.runtime.helper_operator_diagnostics import build_helper_operator_diagnostic
from weall.runtime.helper_release_gate import build_helper_release_gate_report
from weall.runtime.helper_startup_integration import (
    HelperStartupConfig,
    evaluate_helper_startup,
)
from weall.runtime.helper_status_route_adapter import build_api_status_response_shape
from weall.runtime.helper_status_surface import build_helper_status_surface


def _blocked_release_gate():
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


def test_blocked_helper_forces_readyz_false_and_surfaces_same_reason_batch45() -> None:
    startup = evaluate_helper_startup(
        config=HelperStartupConfig(helper_mode_requested=True),
        helper_release_gate=_blocked_release_gate(),
    )
    diagnostic = build_helper_operator_diagnostic(status=startup)
    helper_surface = build_helper_status_surface(diagnostic=diagnostic)

    merged = build_api_status_response_shape(
        chain_id="weall",
        base_ok=True,
        base_mode="prod",
        base_ready=True,
        base_status_payload={"ok": True, "chain_id": "weall"},
        base_readyz_payload={"ok": True, "chain_id": "weall", "ready": True},
        helper_surface=helper_surface,
    ).to_json()

    status_payload = merged["status_payload"]
    readyz_payload = merged["readyz_payload"]

    assert status_payload["helper"]["helper_status"] == "blocked"
    assert status_payload["helper"]["helper_severity"] == "error"
    assert status_payload["helper"]["helper_summary"] == "startup blocked: helper_release_gate_failed"

    assert readyz_payload["helper_status"] == "blocked"
    assert readyz_payload["helper_severity"] == "error"
    assert readyz_payload["helper_summary"] == "startup blocked: helper_release_gate_failed"
    assert readyz_payload["ready"] is False
