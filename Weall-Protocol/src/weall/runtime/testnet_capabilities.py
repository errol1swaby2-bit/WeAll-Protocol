from __future__ import annotations

"""Launch-matrix bound testnet capability/readiness surface.

This module does not activate features. It turns the conservative launch matrix
plus generated proof artifacts into a deterministic, reviewer-readable status
payload that frontends and docs can use to avoid overclaiming public beta,
validators, live economics, protocol upgrades, or helper production execution.
"""

from pathlib import Path
from typing import Any, Mapping
import json

from weall.runtime.launch_matrix import (
    FEATURE_AUTO_PROTOCOL_UPGRADE,
    FEATURE_BALANCE_TRANSFER,
    FEATURE_HELPER_PRODUCTION_EXECUTION,
    FEATURE_LIVE_ECONOMICS,
    FEATURE_PUBLIC_BFT,
    FEATURE_REWARD_ISSUANCE,
    FEATURE_TREASURY_SPEND,
    FEATURE_VALIDATOR_PROMOTION,
    feature_status,
    normalize_launch_phase,
)

ROOT = Path(__file__).resolve().parents[3]
Json = dict[str, Any]

_CAPABILITY_TO_FEATURE = {
    "live_transfers": FEATURE_BALANCE_TRANSFER,
    "live_rewards": FEATURE_REWARD_ISSUANCE,
    "treasury_spend": FEATURE_TREASURY_SPEND,
    "live_economics": FEATURE_LIVE_ECONOMICS,
    "public_validator_join": FEATURE_VALIDATOR_PROMOTION,
    "public_multi_validator_bft": FEATURE_PUBLIC_BFT,
    "automatic_protocol_upgrade_apply": FEATURE_AUTO_PROTOCOL_UPGRADE,
    "production_helper_execution": FEATURE_HELPER_PRODUCTION_EXECUTION,
}

_REQUIRED_ARTIFACTS = {
    "api_contract": "generated/api_contract_map_v1_5.json",
    "failure_code_registry": "generated/failure_code_registry_v1_5.json",
    "api_response_vectors": "generated/api_response_vectors_v1_5.json",
    "launch_disabled_matrix": "generated/launch_disabled_matrix_v1_5.json",
    "state_root_vectors": "generated/state_root_vectors_v1_5.json",
    "tokenomics_simulation": "generated/tokenomics_simulation_v1_5.json",
    "public_validator_preflight": "generated/public_validator_bft_preflight_matrix_v1_5.json",
    "b582_b586_proof": "generated/b582_b586_readiness_truth_and_proof_v1_5.json",
    "b587_b594_mechanism_completion": "generated/b587_b594_testnet_mechanism_completion_v1_5.json",
    "public_beta_blocker_report": "generated/public_beta_blocker_report_v1_5.json",
}


def _load_artifact(rel: str) -> Json:
    path = ROOT / rel
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return value if isinstance(value, dict) else {}


def build_testnet_capability_surface(state: Mapping[str, Any] | None = None, *, phase: str | None = None) -> Json:
    st = state if isinstance(state, Mapping) else {}
    params = st.get("params") if isinstance(st.get("params"), Mapping) else {}
    selected_phase = normalize_launch_phase(phase or str(params.get("launch_phase") or params.get("network_phase") or "public_beta_candidate"))
    capabilities: Json = {}
    for cap, feature in _CAPABILITY_TO_FEATURE.items():
        status = feature_status(selected_phase, feature)
        capabilities[cap] = {
            "enabled": bool(status.enabled),
            "feature": feature,
            "phase": status.phase,
            "blocked_by_launch_matrix": not bool(status.enabled),
            "disabled_reason": status.disabled_reason,
            "truth_boundary": status.truth_boundary,
        }

    artifacts: Json = {}
    for name, rel in _REQUIRED_ARTIFACTS.items():
        payload = _load_artifact(rel)
        artifacts[name] = {
            "path": rel,
            "present": bool(payload),
            "ok": bool(payload.get("ok", True)) if payload else False,
            "schema": payload.get("schema", "") if payload else "",
        }

    blockers = [
        key for key, record in capabilities.items() if bool(record.get("blocked_by_launch_matrix"))
    ]
    artifact_blockers = [key for key, record in artifacts.items() if not bool(record.get("present")) or not bool(record.get("ok"))]
    blocker_report = _load_artifact("generated/public_beta_blocker_report_v1_5.json")
    return {
        "schema": "weall.v1_5.testnet_capability_surface",
        "phase": selected_phase,
        "capabilities": capabilities,
        "required_artifacts": artifacts,
        "blocked_capabilities": blockers,
        "artifact_blockers": artifact_blockers,
        "public_beta_blocker_report": {
            "present": bool(blocker_report),
            "ok": bool(blocker_report.get("ok", False)) if blocker_report else False,
            "public_beta_ready": bool(blocker_report.get("public_beta_ready", False)) if blocker_report else False,
            "mainnet_ready": bool(blocker_report.get("mainnet_ready", False)) if blocker_report else False,
            "blocker_count": int(blocker_report.get("blocker_count") or 0) if blocker_report else 0,
            "remaining_blocker_count": int(blocker_report.get("remaining_blocker_count") or 0) if blocker_report else 0,
            "next_allowed_claim": blocker_report.get("next_allowed_claim", "") if blocker_report else "",
        },
        "mechanism_completion_scope": "controlled_testnet_mechanisms_and_rehearsal_gates",
        "controlled_testnet_mechanisms_complete": not artifact_blockers,
        "public_beta_ready_claimed": False,
        "truth_boundaries": {
            "launch_matrix_is_guardrail_not_consensus": True,
            "live_economics_enabled": False,
            "public_validator_enabled": False,
            "automatic_protocol_upgrades_enabled": False,
            "production_helper_execution_enabled": False,
            "legal_compliance_ready_claimed": False,
        },
    }


__all__ = ["build_testnet_capability_surface"]
