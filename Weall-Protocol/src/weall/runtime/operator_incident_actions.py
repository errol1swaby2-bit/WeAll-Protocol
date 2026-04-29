from __future__ import annotations

from typing import Any

Json = dict[str, Any]


def evaluate_incident_actions(report: Json) -> Json:
    summary = report.get("summary", {})
    severity = summary.get("severity", "ok")

    actions = []

    if severity == "critical":
        actions.append("HALT_BLOCK_PRODUCTION")
        actions.append("REQUEST_PEER_REPORTS")
    elif severity == "warning":
        actions.append("REQUEST_PEER_REPORTS")

    return {
        "severity": severity,
        "actions": actions,
        "action_count": len(actions),
    }
