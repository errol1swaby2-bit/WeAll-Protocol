from __future__ import annotations

from weall.runtime.helper_operator_diagnostics import build_helper_operator_diagnostic
from weall.runtime.helper_release_gate import build_helper_release_gate_report
from weall.runtime.helper_startup_integration import (
    HelperStartupConfig,
    evaluate_helper_startup,
)
from weall.runtime.helper_status_route_adapter import (
    build_api_status_response_shape,
    merge_helper_surface_into_readyz_payload,
    merge_helper_surface_into_status_payload,
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


def test_status_route_adapter_merges_helper_into_existing_status_payload_batch22() -> None:
    status = evaluate_helper_startup(
        config=HelperStartupConfig(helper_mode_requested=False),
        helper_release_gate=None,
    )
    surface = _surface_from_status(status)

    merged = merge_helper_surface_into_status_payload(
        base_status_payload={
            "ok": True,
            "chain_id": "weall",
            "mode": "validator",
            "height": 42,
        },
        helper_surface=surface,
    )

    assert merged["ok"] is True
    assert merged["chain_id"] == "weall"
    assert merged["mode"] == "validator"
    assert merged["height"] == 42
    assert merged["helper"]["helper_status"] == "serial_only"
    assert merged["helper"]["helper_severity"] == "warning"


def test_status_route_adapter_forces_ready_false_when_helper_blocked_batch22() -> None:
    status = evaluate_helper_startup(
        config=HelperStartupConfig(helper_mode_requested=True),
        helper_release_gate=_not_ready_report(),
    )
    surface = _surface_from_status(status)

    merged = merge_helper_surface_into_readyz_payload(
        base_readyz_payload={
            "ready": True,
            "chain_id": "weall",
        },
        helper_surface=surface,
    )

    assert merged["ready"] is False
    assert merged["chain_id"] == "weall"
    assert merged["helper_status"] == "blocked"
    assert merged["helper_severity"] == "error"


def test_status_route_adapter_builds_full_status_and_readyz_shapes_batch22() -> None:
    status = evaluate_helper_startup(
        config=HelperStartupConfig(helper_mode_requested=True),
        helper_release_gate=_all_green_report(),
    )
    surface = _surface_from_status(status)

    shape = build_api_status_response_shape(
        chain_id="weall",
        base_ok=True,
        base_mode="validator",
        base_ready=True,
        base_status_payload={
            "height": 99,
            "peers": 8,
        },
        base_readyz_payload={
            "checks": ["db", "network"],
        },
        helper_surface=surface,
    ).to_json()

    status_payload = shape["status_payload"]
    readyz_payload = shape["readyz_payload"]

    assert status_payload["ok"] is True
    assert status_payload["chain_id"] == "weall"
    assert status_payload["mode"] == "validator"
    assert status_payload["height"] == 99
    assert status_payload["peers"] == 8
    assert status_payload["helper"]["helper_status"] == "helper_enabled"

    assert readyz_payload["ready"] is True
    assert readyz_payload["chain_id"] == "weall"
    assert readyz_payload["checks"] == ["db", "network"]
    assert readyz_payload["helper_status"] == "helper_enabled"
    assert readyz_payload["helper_severity"] == "info"
