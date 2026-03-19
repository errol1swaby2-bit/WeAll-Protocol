from __future__ import annotations

from typing import Any, Dict, Iterable, List

Json = Dict[str, Any]


def evaluate_recovery_readiness(*, peer_reports: Iterable[Json], min_agreeing_peers: int = 2) -> Json:
    reports: List[Json] = [r for r in peer_reports if isinstance(r, dict)]
    healthy = 0
    agreeing = 0

    reference = None
    for report in reports:
        summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
        severity = str(summary.get("severity") or "ok").strip().lower()
        snapshot = report.get("snapshot") if isinstance(report.get("snapshot"), dict) else {}
        fingerprint = report.get("startup_fingerprint") if isinstance(report.get("startup_fingerprint"), dict) else {}
        key = (
            str(snapshot.get("height") or ""),
            str(snapshot.get("tip_hash") or ""),
            str(fingerprint.get("chain_id") or ""),
        )
        if severity == "ok":
            healthy += 1
        if reference is None:
            reference = key
            agreeing = 1
        elif key == reference:
            agreeing += 1

    ready = healthy >= min_agreeing_peers and agreeing >= min_agreeing_peers
    return {
        "ready_to_resume": bool(ready),
        "healthy_peer_count": int(healthy),
        "agreeing_peer_count": int(agreeing),
        "min_agreeing_peers": int(min_agreeing_peers),
    }


def network_resume_decision(*, local_report: Json, peer_reports: Iterable[Json], min_agreeing_peers: int = 2) -> Json:
    summary = local_report.get("summary") if isinstance(local_report.get("summary"), dict) else {}
    local_severity = str(summary.get("severity") or "ok").strip().lower()

    readiness = evaluate_recovery_readiness(
        peer_reports=peer_reports,
        min_agreeing_peers=min_agreeing_peers,
    )

    allow_resume = local_severity != "critical" and bool(readiness["ready_to_resume"])
    return {
        "allow_resume": bool(allow_resume),
        "local_severity": local_severity,
        "recovery_readiness": readiness,
    }
