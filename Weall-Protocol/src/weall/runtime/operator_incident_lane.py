from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from weall.runtime.chain_config import ChainConfig
from weall.runtime.operator_incident_actions import evaluate_incident_actions
from weall.runtime.operator_incident_diff import diff_operator_incident_reports
from weall.runtime.operator_incident_report import build_operator_incident_report
from weall.runtime.operator_safe_mode import safe_mode_gate

Json = dict[str, Any]


def _canon_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _coerce_json_object(value: Any) -> Json:
    return value if isinstance(value, dict) else {}


def _severity_rank(level: str) -> int:
    order = {"ok": 0, "warning": 1, "critical": 2}
    return order.get(str(level or "").strip().lower(), 0)


def _max_severity(levels: Iterable[str]) -> str:
    best = "ok"
    for level in levels:
        if _severity_rank(level) > _severity_rank(best):
            best = str(level or "ok").strip().lower() or "ok"
    return best


def _load_peer_reports(paths: Iterable[Path] | None) -> list[Json]:
    loaded: list[Json] = []
    if not paths:
        return loaded
    for path in paths:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise RuntimeError(f"peer report must be a JSON object: {path}")
        loaded.append(data)
    return loaded


def summarize_peer_reports(*, local_report: Json, peer_reports: Iterable[Json]) -> Json:
    diffs: list[Json] = []
    peer_severities: list[str] = []
    divergence_count = 0
    for idx, peer in enumerate(peer_reports):
        diff = diff_operator_incident_reports(local_report, peer)
        diff["peer_index"] = idx
        diffs.append(diff)
        peer_summary = _coerce_json_object(peer.get("summary"))
        peer_severities.append(str(peer_summary.get("severity") or "ok").strip().lower() or "ok")
        if not bool(diff.get("ok", False)):
            divergence_count += 1

    max_peer_severity = _max_severity(peer_severities) if peer_severities else "ok"
    consensus_divergence = divergence_count > 0
    summary_severity = _max_severity(
        [max_peer_severity, "critical" if consensus_divergence else "ok"]
    )
    return {
        "count": len(diffs),
        "peer_max_severity": max_peer_severity,
        "divergence_count": divergence_count,
        "consensus_divergence": consensus_divergence,
        "severity": summary_severity,
        "diffs": diffs,
    }


def _augment_actions(*, actions: Json, peer_summary: Json) -> Json:
    base_actions = actions.get("actions") if isinstance(actions.get("actions"), list) else []
    deduped = [str(x) for x in base_actions]
    if (
        bool(peer_summary.get("consensus_divergence", False))
        and "REQUEST_PEER_REPORTS" not in deduped
    ):
        deduped.append("REQUEST_PEER_REPORTS")
    if (
        bool(peer_summary.get("consensus_divergence", False))
        and "HALT_BLOCK_PRODUCTION" not in deduped
    ):
        deduped.append("HALT_BLOCK_PRODUCTION")
    return {
        "severity": str(actions.get("severity") or "ok"),
        "actions": deduped,
        "action_count": len(deduped),
        "peer_consensus_divergence": bool(peer_summary.get("consensus_divergence", False)),
    }


def build_operator_incident_lane(
    *,
    cfg: ChainConfig,
    db_path: Path,
    tx_index_path: Path,
    remote_forensics: Json | None = None,
    peer_reports: Iterable[Json] | None = None,
) -> Json:
    local_report = build_operator_incident_report(
        cfg=cfg,
        db_path=db_path,
        tx_index_path=tx_index_path,
        remote_forensics=remote_forensics,
    )
    peer_summary = summarize_peer_reports(
        local_report=local_report, peer_reports=list(peer_reports or [])
    )

    overall_severity = _max_severity(
        [
            str(_coerce_json_object(local_report.get("summary")).get("severity") or "ok"),
            str(peer_summary.get("severity") or "ok"),
        ]
    )

    effective_report: Json = {
        **local_report,
        "summary": {
            **_coerce_json_object(local_report.get("summary")),
            "severity": overall_severity,
            "peer_consensus_divergence": bool(peer_summary.get("consensus_divergence", False)),
            "peer_reports_count": int(peer_summary.get("count") or 0),
            "peer_divergence_count": int(peer_summary.get("divergence_count") or 0),
            "peer_max_severity": str(peer_summary.get("peer_max_severity") or "ok"),
        },
    }

    base_actions = evaluate_incident_actions(effective_report)
    actions = _augment_actions(actions=base_actions, peer_summary=peer_summary)
    safe_mode = safe_mode_gate(report=effective_report, actions=actions)

    next_steps: list[str] = []
    if safe_mode.get("halt_block_production"):
        next_steps.append("stop local proposal/production loop and remain observer-only")
    if safe_mode.get("request_peer_reports"):
        next_steps.append("collect peer incident reports and compare startup fingerprints")
    if peer_summary.get("consensus_divergence"):
        next_steps.append(
            "investigate divergent tip/validator-set/startup-fingerprint before rejoining"
        )
    if not next_steps:
        next_steps.append("continue normal operation")

    lane_hash = _canon_json(
        {
            "report_hash": effective_report.get("report_hash"),
            "actions": actions,
            "safe_mode": safe_mode,
            "peer_divergence_count": peer_summary.get("divergence_count"),
        }
    )

    return {
        "ok": bool(effective_report.get("ok", False))
        and not bool(peer_summary.get("consensus_divergence", False)),
        "report": effective_report,
        "actions": actions,
        "safe_mode": safe_mode,
        "peer_summary": peer_summary,
        "next_steps": next_steps,
        "lane_hash": lane_hash,
    }


def build_operator_incident_lane_summary(lane: Json) -> Json:
    report = _coerce_json_object(lane.get("report"))
    summary = _coerce_json_object(report.get("summary"))
    safe_mode = _coerce_json_object(lane.get("safe_mode"))
    peer_summary = _coerce_json_object(lane.get("peer_summary"))
    actions = _coerce_json_object(lane.get("actions"))
    next_steps_raw = lane.get("next_steps") if isinstance(lane.get("next_steps"), list) else []
    next_steps = [str(step) for step in next_steps_raw]
    authority_contract = _coerce_json_object(report.get("authority_contract"))
    return {
        "ok": bool(lane.get("ok", False)),
        "severity": str(summary.get("severity") or "ok"),
        "safe_mode": str(safe_mode.get("mode") or "normal"),
        "halt_block_production": bool(safe_mode.get("halt_block_production", False)),
        "request_peer_reports": bool(safe_mode.get("request_peer_reports", False)),
        "peer_consensus_divergence": bool(peer_summary.get("consensus_divergence", False)),
        "peer_divergence_count": int(peer_summary.get("divergence_count") or 0),
        "action_count": int(actions.get("action_count") or 0),
        "next_steps": next_steps,
        "lane_hash": str(lane.get("lane_hash") or ""),
        "authority_contract": authority_contract,
    }


__all__ = [
    "build_operator_incident_lane",
    "build_operator_incident_lane_summary",
    "summarize_peer_reports",
    "_load_peer_reports",
]
