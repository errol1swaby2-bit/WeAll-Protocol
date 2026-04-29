from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from weall.runtime.helper_operator_diagnostics import HelperOperatorDiagnostic


Json = dict[str, Any]


@dataclass(frozen=True, slots=True)
class HelperStatusSurface:
    helper_startup: Json
    helper_status: str  # serial_only | helper_enabled | blocked
    helper_severity: str  # info | warning | error
    helper_summary: str

    def to_json(self) -> Json:
        return {
            "helper_startup": dict(self.helper_startup),
            "helper_status": self.helper_status,
            "helper_severity": self.helper_severity,
            "helper_summary": self.helper_summary,
        }


def build_helper_status_surface(
    *,
    diagnostic: HelperOperatorDiagnostic,
) -> HelperStatusSurface:
    """
    Repo-native helper status surface for ready/status style endpoints.

    This keeps the helper surface small and explicit:
    - helper_startup: raw operator diagnostic payload
    - helper_status: normalized high-level state
    - helper_severity: normalized severity for dashboards/alerts
    - helper_summary: concise human-readable message
    """
    payload = diagnostic.to_json()
    return HelperStatusSurface(
        helper_startup=payload,
        helper_status=str(diagnostic.startup_mode),
        helper_severity=str(diagnostic.severity),
        helper_summary=str(diagnostic.summary),
    )
