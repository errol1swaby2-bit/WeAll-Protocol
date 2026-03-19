from __future__ import annotations

from typing import Any

Json = dict[str, Any]


def safe_mode_gate(*, report: Json, actions: Json | None = None) -> Json:
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    severity = str(summary.get("severity") or "ok").strip().lower()

    action_list: list[str] = []
    if isinstance(actions, dict):
        raw = actions.get("actions")
        if isinstance(raw, list):
            action_list = [str(x) for x in raw]

    halt_block_production = severity == "critical" or "HALT_BLOCK_PRODUCTION" in action_list
    request_peer_reports = (
        severity in {"warning", "critical"} or "REQUEST_PEER_REPORTS" in action_list
    )

    mode = "normal"
    if halt_block_production:
        mode = "halted"
    elif request_peer_reports:
        mode = "observe"

    return {
        "mode": mode,
        "severity": severity,
        "halt_block_production": bool(halt_block_production),
        "allow_block_production": not bool(halt_block_production),
        "request_peer_reports": bool(request_peer_reports),
    }


def should_halt_block_production(*, report: Json, actions: Json | None = None) -> bool:
    gate = safe_mode_gate(report=report, actions=actions)
    return bool(gate["halt_block_production"])
