from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from weall.runtime.bootstrap_manifest import (
    expected_startup_fingerprint,
    read_db_state,
    release_manifest_path,
    release_pubkey,
    validator_epoch_and_hash,
    verify_local_manifest,
)
from weall.runtime.chain_config import ChainConfig, production_bootstrap_report
from weall.runtime.node_runtime_config import resolve_node_runtime_config_from_env
from weall.runtime.runtime_authority import authority_contract_from_lifecycle

Json = dict[str, Any]


def _canon_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _coerce_json_object(value: Any) -> Json:
    return value if isinstance(value, dict) else {}


def _severity_rank(level: str) -> int:
    order = {"ok": 0, "warning": 1, "critical": 2}
    return order.get(str(level or "").strip().lower(), 0)


def _max_severity(a: str, b: str) -> str:
    return a if _severity_rank(a) >= _severity_rank(b) else b


def classify_local_severity(*, bootstrap_report: Json, manifest_report: Json | None = None) -> str:
    issues = bootstrap_report.get("issues")
    if isinstance(issues, list) and issues:
        return "critical"
    manifest = _coerce_json_object(
        (manifest_report or {})
        if manifest_report is not None
        else bootstrap_report.get("release_manifest")
    )
    manifest_issues = manifest.get("issues")
    if isinstance(manifest_issues, list) and manifest_issues:
        return "critical"
    compatibility_contract = _coerce_json_object(manifest.get("compatibility_contract"))
    if compatibility_contract and not bool(compatibility_contract.get("ok", True)):
        return "critical"
    return "ok"


def classify_remote_severity(*, remote_forensics: Json) -> str:
    if not remote_forensics:
        return "ok"
    if not bool(remote_forensics.get("ok", True)):
        return "critical"
    stalled = bool(remote_forensics.get("stalled", False))
    pending_fetch = int(remote_forensics.get("pending_fetch_requests_count") or 0)
    recent = _coerce_json_object(remote_forensics.get("recent_rejection_summary"))
    rejection_count = int(recent.get("count") or 0)
    if stalled and pending_fetch > 0:
        return "critical"
    if stalled or rejection_count > 0:
        return "warning"
    return "ok"


def build_operator_incident_report(
    *,
    cfg: ChainConfig,
    db_path: Path,
    tx_index_path: Path,
    remote_forensics: Json | None = None,
) -> Json:
    state, meta = read_db_state(db_path)
    state_meta = _coerce_json_object(state.get("meta"))
    validator_epoch, validator_set_hash_value, normalized_validators = validator_epoch_and_hash(
        state
    )

    startup_fingerprint = expected_startup_fingerprint(
        cfg_chain_id=str(cfg.chain_id or ""),
        cfg_node_id=str(cfg.node_id or ""),
        tx_index_hash=str(state_meta.get("tx_index_hash") or ""),
        schema_version=str(meta.get("schema_version") or state_meta.get("schema_version") or "1"),
        validator_epoch=int(validator_epoch),
        validator_set_hash_value=str(validator_set_hash_value or ""),
    )

    bootstrap = production_bootstrap_report(cfg)
    manifest_report: Json = {}
    manifest_path_raw = str(release_manifest_path() or "").strip()
    if manifest_path_raw:
        manifest_report = verify_local_manifest(
            cfg=cfg,
            manifest_path=Path(manifest_path_raw).resolve(),
            expected_pubkey=str(release_pubkey() or "").strip(),
        )
    remote = _coerce_json_object(remote_forensics)
    runtime_cfg = resolve_node_runtime_config_from_env()
    state_lifecycle = _coerce_json_object(state_meta.get("node_lifecycle"))
    authority_contract = authority_contract_from_lifecycle(state_lifecycle, runtime_cfg, source="runtime")
    local_severity = classify_local_severity(
        bootstrap_report=bootstrap, manifest_report=manifest_report
    )
    remote_severity = classify_remote_severity(remote_forensics=remote)
    overall = _max_severity(local_severity, remote_severity)

    snapshot = {
        "chain_id": str(state.get("chain_id") or ""),
        "height": int(state.get("height") or 0),
        "tip": str(state.get("tip") or ""),
        "tip_hash": str(state.get("tip_hash") or ""),
        "finalized": _coerce_json_object(state.get("finalized")),
        "schema_version": str(
            meta.get("schema_version") or state_meta.get("schema_version") or "1"
        ),
        "tx_index_hash": str(state_meta.get("tx_index_hash") or ""),
    }

    compatibility_contract = _coerce_json_object(manifest_report.get("compatibility_contract"))
    if not compatibility_contract:
        compatibility_contract = {
            "ok": True,
            "mismatches": [],
            "field_status": {},
            "local": {},
            "manifest": {},
            "trusted_anchor_mismatches": [],
        }

    summary = {
        "severity": overall,
        "local_severity": local_severity,
        "remote_severity": remote_severity,
        "bootstrap_ok": bool(bootstrap.get("ok", False)),
        "remote_ok": bool(remote.get("ok", True)) if remote else True,
        "remote_stalled": bool(remote.get("stalled", False)) if remote else False,
        "pending_fetch_requests_count": int(remote.get("pending_fetch_requests_count") or 0)
        if remote
        else 0,
        "recent_rejections_count": int(
            _coerce_json_object(remote.get("recent_rejection_summary")).get("count") or 0
        )
        if remote
        else 0,
        "compatibility_contract_ok": bool(compatibility_contract.get("ok", True)),
        "compatibility_contract_mismatches": list(compatibility_contract.get("mismatches") or []),
        "strict_runtime_authority_mode": bool(authority_contract.get("strict_runtime_authority_mode", False)),
        "validator_effective": bool(authority_contract.get("validator_effective", False)),
        "helper_effective": bool(authority_contract.get("helper_effective", False)),
    }

    return {
        "ok": overall != "critical",
        "summary": summary,
        "config": {
            "mode": str(cfg.mode or ""),
            "chain_id": str(cfg.chain_id or ""),
            "node_id": str(cfg.node_id or ""),
            "db_path": str(db_path),
            "tx_index_path": str(tx_index_path),
        },
        "snapshot": snapshot,
        "validator_set": {
            "epoch": int(validator_epoch),
            "validator_set_hash": str(validator_set_hash_value or ""),
            "validators": list(normalized_validators),
            "count": int(len(normalized_validators)),
        },
        "startup_fingerprint": startup_fingerprint,
        "bootstrap_report": bootstrap,
        "release_manifest": manifest_report,
        "compatibility_contract": compatibility_contract,
        "authority_contract": authority_contract,
        "remote_forensics": remote,
        "report_hash": _canon_json(
            {
                "summary": summary,
                "snapshot": snapshot,
                "startup_fingerprint": startup_fingerprint,
            }
        ),
    }
