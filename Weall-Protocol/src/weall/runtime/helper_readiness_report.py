from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from weall.runtime.helper_operator_diagnostics import HelperOperatorDiagnostic
from weall.runtime.helper_preflight_gate import ProductionPreflightDecision
from weall.runtime.helper_release_gate import HelperReleaseGateReport
from weall.runtime.helper_startup_integration import HelperStartupStatus


Json = dict[str, Any]


@dataclass(frozen=True, slots=True)
class HelperReadinessReport:
    preflight: Json
    startup: Json
    operator: Json
    release_gate: Json | None
    overall_status: str  # ready | serial_only | blocked
    overall_summary: str

    def to_json(self) -> Json:
        return {
            "preflight": dict(self.preflight),
            "startup": dict(self.startup),
            "operator": dict(self.operator),
            "release_gate": dict(self.release_gate) if isinstance(self.release_gate, dict) else None,
            "overall_status": self.overall_status,
            "overall_summary": self.overall_summary,
        }


def build_helper_readiness_report(
    *,
    preflight_decision: ProductionPreflightDecision,
    startup_status: HelperStartupStatus,
    operator_diagnostic: HelperOperatorDiagnostic,
    release_gate_report: HelperReleaseGateReport | None = None,
) -> HelperReadinessReport:
    """
    Repo-native consolidated helper readiness report.

    This is intended as the final operator-facing summary layer over the helper
    gating stack:
    - production preflight decision
    - startup status
    - operator diagnostic
    - consolidated release-gate bundle, if present
    """
    if not bool(startup_status.startup_allowed):
        overall_status = "blocked"
        overall_summary = f"helper startup blocked: {startup_status.code}"
    elif bool(startup_status.helper_mode_active):
        overall_status = "ready"
        overall_summary = "helper mode ready and active"
    else:
        overall_status = "serial_only"
        overall_summary = "node ready in serial-only mode; helper mode inactive"

    return HelperReadinessReport(
        preflight={
            "accepted": bool(preflight_decision.accepted),
            "code": str(preflight_decision.code),
            "helper_required": bool(preflight_decision.helper_required),
            "helper_ready": bool(preflight_decision.helper_ready),
            "release_score": int(preflight_decision.release_score),
        },
        startup={
            "startup_allowed": bool(startup_status.startup_allowed),
            "startup_mode": str(startup_status.startup_mode),
            "code": str(startup_status.code),
            "helper_mode_active": bool(startup_status.helper_mode_active),
            "helper_release_score": int(startup_status.helper_release_score),
        },
        operator=operator_diagnostic.to_json(),
        release_gate=(
            {
                "deterministic_replay_ok": bool(release_gate_report.deterministic_replay_ok),
                "timeout_fallback_ok": bool(release_gate_report.timeout_fallback_ok),
                "conflicting_replay_ok": bool(release_gate_report.conflicting_replay_ok),
                "restart_recovery_ok": bool(release_gate_report.restart_recovery_ok),
                "merge_admission_ok": bool(release_gate_report.merge_admission_ok),
                "fail_closed_ok": bool(release_gate_report.fail_closed_ok),
                "serial_degrade_ok": bool(release_gate_report.serial_degrade_ok),
                "soak_ok": bool(release_gate_report.soak_ok),
                "total_gates": int(release_gate_report.total_gates),
                "passed_gates": int(release_gate_report.passed_gates),
                "readiness_score": int(release_gate_report.readiness_score),
            }
            if release_gate_report is not None
            else None
        ),
        overall_status=overall_status,
        overall_summary=overall_summary,
    )
