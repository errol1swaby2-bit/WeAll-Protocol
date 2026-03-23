from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from weall.runtime.helper_startup_integration import HelperStartupStatus


Json = dict[str, Any]


@dataclass(frozen=True, slots=True)
class HelperOperatorDiagnostic:
    startup_allowed: bool
    startup_mode: str
    code: str
    helper_mode_active: bool
    helper_release_score: int
    severity: str  # info | warning | error
    summary: str

    def to_json(self) -> Json:
        return {
            "startup_allowed": self.startup_allowed,
            "startup_mode": self.startup_mode,
            "code": self.code,
            "helper_mode_active": self.helper_mode_active,
            "helper_release_score": self.helper_release_score,
            "severity": self.severity,
            "summary": self.summary,
        }


def build_helper_operator_diagnostic(
    *,
    status: HelperStartupStatus,
) -> HelperOperatorDiagnostic:
    """
    Repo-native operator-facing helper startup diagnostic.

    This translates startup status into a clear operator surface:
    - serial_only: node started safely without helper mode
    - helper_enabled: node started with helper mode active
    - blocked: node must not continue until the reported cause is fixed
    """
    if not bool(status.startup_allowed):
        return HelperOperatorDiagnostic(
            startup_allowed=False,
            startup_mode=str(status.startup_mode),
            code=str(status.code),
            helper_mode_active=False,
            helper_release_score=int(status.helper_release_score),
            severity="error",
            summary=f"startup blocked: {status.code}",
        )

    if str(status.startup_mode) == "helper_enabled":
        return HelperOperatorDiagnostic(
            startup_allowed=True,
            startup_mode="helper_enabled",
            code=str(status.code),
            helper_mode_active=True,
            helper_release_score=int(status.helper_release_score),
            severity="info",
            summary="startup ready with helper mode enabled",
        )

    return HelperOperatorDiagnostic(
        startup_allowed=True,
        startup_mode="serial_only",
        code=str(status.code),
        helper_mode_active=False,
        helper_release_score=int(status.helper_release_score),
        severity="warning",
        summary="startup ready in serial-only mode; helper mode inactive",
    )
