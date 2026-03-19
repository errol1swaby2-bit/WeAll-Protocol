from __future__ import annotations

import json
from typing import Any, Dict

Json = Dict[str, Any]


def serialize_incident_report(report: Json) -> str:
    return json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def deserialize_incident_report(payload: str) -> Json:
    data = json.loads(payload)
    if not isinstance(data, dict):
        raise RuntimeError("incident payload must be object")
    return data


def build_gossip_envelope(report: Json, *, node_id: str) -> Json:
    return {
        "type": "INCIDENT_REPORT",
        "node_id": node_id,
        "report": report,
        "report_hash": report.get("report_hash"),
    }
