from __future__ import annotations

import json
from typing import Any

Json = dict[str, Any]


def _canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _as_dict(value: Any) -> Json:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def diff_operator_incident_reports(left: Json, right: Json) -> Json:
    left_summary = _as_dict(left.get("summary"))
    right_summary = _as_dict(right.get("summary"))
    left_snapshot = _as_dict(left.get("snapshot"))
    right_snapshot = _as_dict(right.get("snapshot"))
    left_validator = _as_dict(left.get("validator_set"))
    right_validator = _as_dict(right.get("validator_set"))
    left_fp = _as_dict(left.get("startup_fingerprint"))
    right_fp = _as_dict(right.get("startup_fingerprint"))
    left_bootstrap = _as_dict(left.get("bootstrap_report"))
    right_bootstrap = _as_dict(right.get("bootstrap_report"))

    changed_summary = {}
    for key in sorted(set(left_summary) | set(right_summary)):
        if left_summary.get(key) != right_summary.get(key):
            changed_summary[key] = {
                "left": left_summary.get(key),
                "right": right_summary.get(key),
            }

    changed_snapshot = {}
    for key in sorted(set(left_snapshot) | set(right_snapshot)):
        if left_snapshot.get(key) != right_snapshot.get(key):
            changed_snapshot[key] = {
                "left": left_snapshot.get(key),
                "right": right_snapshot.get(key),
            }

    changed_validator = {}
    for key in sorted(set(left_validator) | set(right_validator)):
        if left_validator.get(key) != right_validator.get(key):
            changed_validator[key] = {
                "left": left_validator.get(key),
                "right": right_validator.get(key),
            }

    changed_startup = {}
    for key in sorted(set(left_fp) | set(right_fp)):
        if left_fp.get(key) != right_fp.get(key):
            changed_startup[key] = {
                "left": left_fp.get(key),
                "right": right_fp.get(key),
            }

    left_bootstrap_issues = _as_list(left_bootstrap.get("issues"))
    right_bootstrap_issues = _as_list(right_bootstrap.get("issues"))
    left_remote = _as_dict(left.get("remote_forensics"))
    right_remote = _as_dict(right.get("remote_forensics"))

    concerns: list[str] = []
    if left_summary.get("severity") != right_summary.get("severity"):
        concerns.append("severity_changed")
    if left_snapshot.get("tip_hash") != right_snapshot.get("tip_hash"):
        concerns.append("tip_hash_changed")
    if left_snapshot.get("height") != right_snapshot.get("height"):
        concerns.append("height_changed")
    if left_validator.get("validator_set_hash") != right_validator.get("validator_set_hash"):
        concerns.append("validator_set_hash_changed")
    if left_fp != right_fp:
        concerns.append("startup_fingerprint_changed")
    if _canon(left_bootstrap_issues) != _canon(right_bootstrap_issues):
        concerns.append("bootstrap_issues_changed")
    if bool(left_remote.get("stalled", False)) != bool(right_remote.get("stalled", False)):
        concerns.append("remote_stall_changed")

    divergence = {
        "severity_mismatch": left_summary.get("severity") != right_summary.get("severity"),
        "tip_mismatch": left_snapshot.get("tip_hash") != right_snapshot.get("tip_hash"),
        "height_mismatch": left_snapshot.get("height") != right_snapshot.get("height"),
        "validator_set_mismatch": left_validator.get("validator_set_hash")
        != right_validator.get("validator_set_hash"),
        "startup_fingerprint_mismatch": _canon(left_fp) != _canon(right_fp),
    }

    return {
        "ok": not any(divergence.values()),
        "divergence": divergence,
        "changed_summary": changed_summary,
        "changed_snapshot": changed_snapshot,
        "changed_validator_set": changed_validator,
        "changed_startup_fingerprint": changed_startup,
        "bootstrap_issues": {
            "left": left_bootstrap_issues,
            "right": right_bootstrap_issues,
        },
        "remote_forensics": {
            "left": left_remote,
            "right": right_remote,
        },
        "concerns": concerns,
        "comparison_hash": _canon(
            {
                "divergence": divergence,
                "changed_summary": changed_summary,
                "changed_snapshot": changed_snapshot,
                "changed_validator_set": changed_validator,
                "changed_startup_fingerprint": changed_startup,
            }
        ),
    }
