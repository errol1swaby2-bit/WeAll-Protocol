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
    "external_operator_transcript_requirements": "generated/external_operator_transcript_requirements_v1_5.json",
}

# These artifacts are intentionally self-referential or public-beta-blocker
# inventories. They must be present and reviewer-readable, but they must not
# make the controlled-testnet mechanism surface fail merely because the repo is
# truthfully *not* public-beta ready yet. Public-beta claim safety is enforced by
# the blocker summary and launch matrix below.
_CONTROLLED_MECHANISM_ADVISORY_ARTIFACTS = {
    "b587_b594_mechanism_completion",
    "public_beta_blocker_report",
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
    controlled_mechanism_artifact_blockers = [
        key
        for key, record in artifacts.items()
        if key not in _CONTROLLED_MECHANISM_ADVISORY_ARTIFACTS
        and (not bool(record.get("present")) or not bool(record.get("ok")))
    ]
    blocker_report = _load_artifact("generated/public_beta_blocker_report_v1_5.json")
    public_beta_blocker_inventory_ok = bool(
        blocker_report
        and blocker_report.get("schema") == "weall.v1_5.public_beta_blocker_report"
        and blocker_report.get("public_beta_ready") is False
        and int(blocker_report.get("blocker_count") or 0) >= 12
    )
    return {
        "schema": "weall.v1_5.testnet_capability_surface",
        "phase": selected_phase,
        "capabilities": capabilities,
        "required_artifacts": artifacts,
        "blocked_capabilities": blockers,
        "artifact_blockers": artifact_blockers,
        "controlled_mechanism_artifact_blockers": controlled_mechanism_artifact_blockers,
        "advisory_artifacts_not_counted_as_controlled_mechanism_blockers": sorted(_CONTROLLED_MECHANISM_ADVISORY_ARTIFACTS),
        "public_beta_blocker_report": {
            "present": bool(blocker_report),
            "ok": public_beta_blocker_inventory_ok,
            "public_beta_ready": bool(blocker_report.get("public_beta_ready", False)) if blocker_report else False,
            "mainnet_ready": bool(blocker_report.get("mainnet_ready", False)) if blocker_report else False,
            "blocker_count": int(blocker_report.get("blocker_count") or 0) if blocker_report else 0,
            "remaining_blocker_count": int(blocker_report.get("remaining_blocker_count") or 0) if blocker_report else 0,
            "next_allowed_claim": blocker_report.get("next_allowed_claim", "") if blocker_report else "",
        },
        "protocol_upgrade_lifecycle": {
            "public_record_state": True,
            "declaration_tx": "PROTOCOL_UPGRADE_DECLARE",
            "scheduled_activation_tx": "PROTOCOL_UPGRADE_ACTIVATE",
            "required_parent_boundary": "SYSTEM queue / receipt-only governance parent reference",
            "activation_clock": "block_height",
            "activation_record_only": True,
            "automatic_software_apply_enabled": False,
            "migration_execution_enabled": False,
            "rollback_execution_enabled": False,
            "economics_activation_enabled_by_upgrade": False,
            "reviewer_surface": "GET /v1/status/testnet-capabilities",
            "truth_boundary": "Upgrade records are public deterministic metadata. They require governance parent/system-queue provenance and do not fetch artifacts, restart nodes, execute migrations, or activate economics.",
        },
        "governance_lifecycle": {
            "public_record_state": True,
            "progression_clock": "block_height",
            "scheduler": "tick_governance_lifecycle",
            "manual_wall_clock_protocol_state_allowed": False,
            "ui_time_estimates_only": True,
            "deterministic_receipt_txs": [
                "GOV_STAGE_SET",
                "GOV_VOTING_CLOSE",
                "GOV_TALLY_PUBLISH",
                "GOV_EXECUTE",
                "GOV_PROPOSAL_FINALIZE",
            ],
            "reviewer_surface": "GET /v1/status/testnet-capabilities",
            "truth_boundary": "Governance procedure truth is block-height based; UI may render approximate human time but must not mutate protocol state from local wall-clock time.",
        },
        "dispute_lifecycle": {
            "public_record_state": True,
            "progression_clock": "block_height",
            "scheduler": "tick_dispute_lifecycle",
            "manual_wall_clock_protocol_state_allowed": False,
            "ui_time_estimates_only": True,
            "deterministic_receipt_txs": [
                "DISPUTE_JUROR_TIMEOUT",
                "DISPUTE_FINAL_RECEIPT",
            ],
            "private_identity_evidence_publicly_exposed": False,
            "reviewer_surface": "GET /v1/status/testnet-capabilities",
            "truth_boundary": "Dispute windows, juror deadlines, appeal closure, and public outcomes are block-height bound; raw PoH/private identity evidence remains restricted.",
        },
        "minimum_reviewer_civic_loop": {
            "public_only_visibility": True,
            "economics_locked_by_default": True,
            "steps": [
                "account_identity_state",
                "human_verification_state",
                "public_posting_or_social_activity",
                "public_group_read_with_member_gated_participation",
                "governance_create_vote_finalize",
                "dispute_review_outcome_visibility",
                "reputation_outcome_visibility",
                "protocol_upgrade_record_lifecycle",
                "observer_node_status",
                "economics_locked_status",
            ],
            "frontend_entrypoints": {
                "account": "/profile",
                "account_detail_template": "/account/:account",
                "identity_verification": "/verification",
                "feed": "/feed",
                "create_post": "/create",
                "groups": "/groups",
                "group_detail_template": "/groups/:id",
                "governance": "/decisions",
                "governance_create": "/decisions/create",
                "governance_detail_template": "/decisions/:id",
                "disputes": "/reports",
                "dispute_detail_template": "/reports/:id",
                "review_center": "/reviews",
                "review_detail_template": "/reviews/:id",
                "reputation_visibility": "/activity",
                "node_status": "/node",
                "economics": "/economics",
            },
            "canonical_route_boundary": {
                "governance_label": "Decisions",
                "governance_route": "/decisions",
                "dispute_label": "Reports",
                "dispute_route": "/reports",
                "legacy_aliases_removed": ["/proposals", "/disputes"],
            },
            "truth_boundary": "This is a reviewer navigation map using current canonical frontend routes, not proof that public beta/mainnet gates are closed. Templates with ':' require a concrete public identifier before navigation.",
        },
        "mechanism_completion_scope": "controlled_testnet_mechanisms_and_rehearsal_gates_not_public_beta_readiness",
        "controlled_testnet_mechanisms_complete": not controlled_mechanism_artifact_blockers,
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
