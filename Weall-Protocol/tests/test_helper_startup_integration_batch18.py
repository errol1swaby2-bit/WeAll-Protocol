from __future__ import annotations

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


def test_helper_startup_allows_serial_only_without_helper_request_batch18() -> None:
    status = evaluate_helper_startup(
        config=HelperStartupConfig(helper_mode_requested=False),
        helper_release_gate=None,
    )
    assert status.startup_allowed is True
    assert status.startup_mode == "serial_only"
    assert status.helper_mode_active is False
    assert status.code == "preflight_ready_serial_only"


def test_helper_startup_blocks_requested_helper_mode_without_release_gate_batch18() -> None:
    status = evaluate_helper_startup(
        config=HelperStartupConfig(helper_mode_requested=True),
        helper_release_gate=None,
    )
    assert status.startup_allowed is False
    assert status.startup_mode == "blocked"
    assert status.helper_mode_active is False
    assert status.code == "helper_release_gate_missing"


def test_helper_startup_enables_helpers_when_release_gate_passes_batch18() -> None:
    status = evaluate_helper_startup(
        config=HelperStartupConfig(helper_mode_requested=True),
        helper_release_gate=_all_green_report(),
    )
    assert status.startup_allowed is True
    assert status.startup_mode == "helper_enabled"
    assert status.helper_mode_active is True
    assert status.helper_release_score == 100
    assert status.code == "preflight_ready_with_helpers"


def test_helper_startup_blocks_helper_mode_when_release_gate_fails_batch18() -> None:
    status = evaluate_helper_startup(
        config=HelperStartupConfig(helper_mode_requested=True),
        helper_release_gate=_not_ready_report(),
    )
    assert status.startup_allowed is False
    assert status.startup_mode == "blocked"
    assert status.helper_mode_active is False
    assert status.code == "helper_release_gate_failed"
    assert status.helper_release_score == 87


def test_helper_startup_blocks_on_core_runtime_failure_even_without_helpers_batch18() -> None:
    status = evaluate_helper_startup(
        config=HelperStartupConfig(
            helper_mode_requested=False,
            protocol_profile_ok=False,
        ),
        helper_release_gate=None,
    )
    assert status.startup_allowed is False
    assert status.startup_mode == "blocked"
    assert status.code == "protocol_profile_not_ready"
