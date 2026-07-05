#!/usr/bin/env python3
from __future__ import annotations

"""Generate the v1.5 public-beta blocker/evidence-gate report.

This artifact is deliberately conservative. It closes mechanism *tracking* gaps by
binding every remaining public-beta blocker to an evidence gate, transcript
schema, and verification command, while preserving the truth boundary that public
beta, mainnet, public validators, production helper execution, live economics,
and automatic protocol upgrades are not enabled by this repository state.
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from gen_api_response_vectors_v1_5 import build as build_api_vectors
from gen_external_operator_transcript_requirements_v1_5 import build as build_external_transcript_requirements
from gen_release_evidence_manifest_v1_5 import build as build_release_evidence_manifest
from rehearse_external_multimachine_validator_harness_b590_v1_5 import run_harness as run_validator_harness
from rehearse_helper_block_path_adversarial_b593_v1_5 import run_harness as run_helper_harness
from rehearse_multimachine_storage_ipfs_durability_b591_v1_5 import run_harness as run_storage_harness
from rehearse_protocol_upgrade_signed_staging_b589_v1_5 import run_harness as run_protocol_upgrade_harness
from weall.runtime.testnet_capabilities import build_testnet_capability_surface

OUT = ROOT / "generated" / "public_beta_blocker_report_v1_5.json"
Json = dict[str, Any]


def _canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _digest(obj: Any) -> str:
    return hashlib.sha256(_canon(obj).encode("utf-8")).hexdigest()


def _load_json(rel: str) -> Json:
    try:
        value = json.loads((ROOT / rel).read_text(encoding="utf-8"))
    except Exception:
        return {}
    return value if isinstance(value, dict) else {}


def _artifact_summary(rel: str) -> Json:
    payload = _load_json(rel)
    return {
        "path": rel,
        "present": bool(payload),
        "ok": bool(payload.get("ok", True)) if payload else False,
        "schema": str(payload.get("schema") or "") if payload else "",
        "digest": _digest(payload) if payload else "",
    }


def _state_root_summary() -> Json:
    payload = _load_json("generated/state_root_vectors_v1_5.json")
    vectors = payload.get("vectors") if isinstance(payload.get("vectors"), list) else []
    capture_script = ROOT / "scripts" / "capture_external_cross_machine_replay_transcript_v1_5.sh"
    transcript_template = ROOT / "docs" / "proofs" / "external-cross-machine-replay" / "2026-07-05" / "TRANSCRIPT_TEMPLATE.json"
    runbook = ROOT / "docs" / "testnet" / "EXTERNAL_CROSS_MACHINE_REPLAY_TRANSCRIPT.md"
    return {
        "ok": bool(payload.get("schema") == "weall.v1_5.state_root_vectors" and len(vectors) >= 8),
        "vector_count": len(vectors),
        "cross_machine_replay_exported": True,
        "external_cross_machine_attestation_required": True,
        "external_cross_machine_transcript_capture_script_present": capture_script.exists(),
        "external_cross_machine_transcript_template_present": transcript_template.exists(),
        "external_cross_machine_replay_runbook_present": runbook.exists(),
        "capture_script": "scripts/capture_external_cross_machine_replay_transcript_v1_5.sh",
        "template": "docs/proofs/external-cross-machine-replay/2026-07-05/TRANSCRIPT_TEMPLATE.json",
        "validation_command": "PYTHONPATH=src:scripts python scripts/validate_external_operator_transcript_v1_5.py --kind external_cross_machine_replay_transcript --strict-release --path <transcript.json>",
        "artifact_digest": _digest(payload) if payload else "",
    }


def _clean_clone_gate_summary() -> Json:
    root_gate = ROOT.parent / "scripts" / "run_clean_clone_go_gate_v1_5.sh"
    backend_gate = ROOT / "scripts" / "run_clean_clone_go_gate_v1_5.sh"
    frontend_gate = ROOT.parent / "scripts" / "run_frontend_contract_check_with_backend.sh"
    return {
        "ok": root_gate.exists() and backend_gate.exists() and frontend_gate.exists(),
        "root_gate_path": "scripts/run_clean_clone_go_gate_v1_5.sh",
        "backend_wrapper_path": "Weall-Protocol/scripts/run_clean_clone_go_gate_v1_5.sh",
        "frontend_contract_gate_path": "scripts/run_frontend_contract_check_with_backend.sh",
        "root_gate_present": root_gate.exists(),
        "backend_wrapper_present": backend_gate.exists(),
        "frontend_contract_gate_present": frontend_gate.exists(),
        "root_gate_executable_in_this_checkout": root_gate.exists() and root_gate.stat().st_mode & 0o111 != 0,
        "requires_fresh_checkout_transcript_after_commit": True,
    }


def _legal_summary() -> Json:
    return {
        "ok": True,
        "legal_compliance_ready": False,
        "counsel_review_attached": False,
        "public_claims_require_counsel_review": True,
        "required_attestations": [
            "token/economics claims reviewed by counsel",
            "governance and treasury claims reviewed by counsel",
            "public-beta jurisdictional risk checklist completed",
            "marketing/docs checked against launch-disabled matrix",
        ],
    }


def _frontend_p2_ux_summary() -> Json:
    frontend = ROOT.parent / "web"
    files = {
        "node_dashboard": frontend / "src" / "pages" / "NodeDashboard.tsx",
        "operator_wizard": frontend / "src" / "components" / "OperatorCommandWizard.tsx",
        "incident_timeline": frontend / "src" / "components" / "OperatorIncidentTimeline.tsx",
        "tx_page": frontend / "src" / "pages" / "TransactionsPage.tsx",
        "tx_timeline": frontend / "src" / "components" / "TxPropagationTimeline.tsx",
        "source_test": frontend / "scripts" / "test_step9_p2_ux_source.mjs",
        "node_dashboard_source_test": frontend / "scripts" / "test_node_dashboard_source.mjs",
    }

    def read(key: str) -> str:
        path = files[key]
        try:
            return path.read_text(encoding="utf-8")
        except Exception:
            return ""

    contents = {key: read(key) for key in files}
    combined = "\n".join(contents.values())
    checks = {
        "operator_wizard_surface_present": all(
            needle in contents["operator_wizard"]
            for needle in (
                "Safe guided commands",
                "current node mode",
                "observer, node operator, validator-candidate, and validator authority",
                "script execution or copied commands never grant authority by themselves",
                "diagnostic-only / read-only",
                "local-only / diagnostic-only",
                "observer-only / diagnostic-only",
                "requires protocol state before use",
            )
        ) and "OperatorCommandWizard" in contents["node_dashboard"],
        "tx_lifecycle_timeline_present": all(
            needle in contents["tx_page"]
            for needle in (
                "Submitted",
                "Locally accepted",
                "Queued / pending",
                "Forwarded / gossiped",
                "Included in block",
                "Finalized / confirmed",
                "Rejected",
                "Removed from mempool",
                "not confirmed yet",
                "unknown/unavailable",
            )
        ) and "Propagation lifecycle separates local submission" in contents["tx_timeline"],
        "operator_incident_timeline_present": all(
            needle in contents["incident_timeline"]
            for needle in (
                "Operator incident timeline",
                "Unified diagnostics",
                "Read-only diagnostics",
                "node mode, chain identity, peer and seed status, mempool backlog, block/finalized height, BFT/validator authority, storage/helper/economics/protocol-upgrade blockers",
                "build_operator_incident_report.py",
            )
        ) and "OperatorIncidentTimeline" in contents["node_dashboard"],
        "source_contract_test_present": all(
            needle in contents["source_test"]
            for needle in (
                "Step 9 P2 UX source checks passed",
                "mempool acceptance is confirmed",
                "Public beta ready",
                "automatic protocol upgrades enabled",
            )
        ),
        "node_dashboard_source_contract_updated": all(
            needle in contents["node_dashboard_source_test"]
            for needle in (
                "Step 9 P2 UX surfaces",
                "Step 9 operator wizard source contract",
                "Step 9 operator incident timeline source contract",
            )
        ),
    }
    forbidden_phrases = [
        "Public beta ready",
        "Mainnet ready",
        "public multi-validator BFT ready",
        "live economics ready",
        "automatic protocol upgrades enabled",
        "script execution grants authority",
        "copied commands grant authority",
        "mempool acceptance is confirmed",
        "local acceptance is confirmation",
    ]
    # The source test intentionally contains the forbidden strings as guard data; exclude it from product copy checks.
    product_combined = "\n".join(value for key, value in contents.items() if key != "source_test")
    checks["no_readiness_or_confirmation_overclaim_in_product_copy"] = not any(phrase in product_combined for phrase in forbidden_phrases)
    ok = all(checks.values()) and all(path.exists() for path in files.values())
    return {
        "ok": ok,
        "source_gate": "web/scripts/test_step9_p2_ux_source.mjs",
        "node_dashboard_source_gate": "web/scripts/test_node_dashboard_source.mjs",
        "checks": checks,
        "artifact_digest": _digest({"checks": checks, "files": sorted(str(path.relative_to(ROOT.parent)) for path in files.values())}),
    }


def _classify_blocker(
    *,
    severity: str,
    gate_status: str,
    remaining_external_evidence: list[str],
    can_be_closed_by_code_only: bool,
) -> Json:
    if gate_status.startswith("closed"):
        category = "closed_by_artifact_or_docs"
        disposition = "closed_in_repository"
        safe_before_first_round = True
    elif remaining_external_evidence:
        category = "external_evidence_required"
        disposition = "keep_open_and_frame_as_mainnet_readiness_hardening"
        safe_before_first_round = False
    elif gate_status.startswith("tracked_as_frontend") or gate_status.startswith("partially_closed"):
        category = "ux_or_observability_follow_up"
        disposition = "safe_to_reduce_with_bounded_frontend_docs_or_tests"
        safe_before_first_round = True
    elif can_be_closed_by_code_only:
        category = "code_or_test_hardening"
        disposition = "safe_to_reduce_only_with_fresh_tests_and_artifacts"
        safe_before_first_round = severity not in {"P0"}
    else:
        category = "manual_attestation_required"
        disposition = "keep_open_until_external_attestation"
        safe_before_first_round = False
    return {
        "blocker_category": category,
        "nlnet_first_round_disposition": disposition,
        "safe_to_close_before_nlnet_first_round_with_current_repo_evidence": safe_before_first_round and gate_status.startswith("closed"),
        "safe_to_reduce_before_nlnet_first_round": safe_before_first_round,
    }


def _blocker(
    blocker_id: str,
    severity: str,
    blocks: list[str],
    current_behavior: str,
    expected_behavior: str,
    evidence_gate: str,
    gate_status: str,
    can_be_closed_by_code_only: bool,
    remaining_external_evidence: list[str] | None = None,
) -> Json:
    remaining = remaining_external_evidence or []
    classification = _classify_blocker(
        severity=severity,
        gate_status=gate_status,
        remaining_external_evidence=remaining,
        can_be_closed_by_code_only=can_be_closed_by_code_only,
    )
    return {
        "id": blocker_id,
        "severity": severity,
        "blocks": blocks,
        "current_behavior": current_behavior,
        "expected_production_behavior": expected_behavior,
        "evidence_gate": evidence_gate,
        "gate_status": gate_status,
        "can_be_closed_by_code_only": can_be_closed_by_code_only,
        "remaining_external_evidence": remaining,
        **classification,
    }


def build() -> Json:
    validator = run_validator_harness()
    storage = run_storage_harness()
    protocol_upgrade = run_protocol_upgrade_harness()
    helper = run_helper_harness()
    api_vectors = build_api_vectors()
    capabilities = build_testnet_capability_surface({"params": {"launch_phase": "public_beta_candidate"}})
    state_roots = _state_root_summary()
    clean_clone = _clean_clone_gate_summary()
    legal = _legal_summary()
    external_requirements = build_external_transcript_requirements()
    public_observer_launch = _artifact_summary("generated/public_observer_launch_evidence_requirements_v1_5.json")
    release_evidence = build_release_evidence_manifest()
    frontend_p2_ux = _frontend_p2_ux_summary()

    high_risk_disabled = all(
        record.get("enabled") is False
        for record in (capabilities.get("capabilities") or {}).values()
        if isinstance(record, dict)
    )
    api_vector_count = int(api_vectors.get("vector_count") or 0)

    blockers = [
        _blocker(
            "AUD-618-P0-001",
            "P0",
            ["public_beta", "mainnet"],
            "Public validator readiness remains explicitly false and operator proof is simulated/local unless externally attested.",
            "Independent multi-process/operator BFT proof with churn, equivocation, partition/rejoin, restart/replay, and transcript digest.",
            "public_validator_operator_transcript_schema",
            "gate_present_external_attestation_required" if validator.get("ok") and external_requirements.get("ok") else "gate_failed",
            False,
            ["independently operated validator run", "operator-signed transcript", "fresh checkout replay of transcript digest"],
        ),
        _blocker(
            "AUD-618-P0-002",
            "P0",
            ["public_beta", "mainnet"],
            "Legal/compliance pack is not counsel-attested.",
            "Counsel-reviewed public claims, token/economic/governance language, and jurisdictional risk review.",
            "legal_attestation_schema",
            "manual_counsel_attestation_required",
            False,
            legal["required_attestations"],
        ),
        _blocker(
            "AUD-618-P0-003",
            "P0",
            ["public_beta", "mainnet"],
            "Protocol upgrades are record-only and auto-apply remains disabled.",
            "Signed artifact manifests, deterministic migration vectors, rollback semantics, and staged multi-node rehearsal before execution.",
            "signed_protocol_upgrade_staging_gate",
            "staging_gate_present_execution_still_disabled" if protocol_upgrade.get("ok") else "gate_failed",
            True,
            ["future production execution gate", "operator approval policy", "multi-node rollback transcript"],
        ),
        _blocker(
            "AUD-618-P1-001",
            "P1",
            ["public_beta"],
            "API response vectors were limited to a small high-risk set.",
            "Expanded response vectors cover production-critical route families and auth/error boundaries.",
            "expanded_api_response_vector_pack",
            "closed_as_artifact_gate" if api_vectors.get("ok") and api_vector_count >= 24 else "needs_more_vectors",
            True,
        ),
        _blocker(
            "AUD-618-P1-002",
            "P1",
            ["public_beta"],
            "Launch-disabled matrix exists; final frontend/API public blocker snapshot was missing.",
            "Evidence bundle proves public UI/API blocks live economics, public validator join, helper execution, and protocol upgrades.",
            "frontend_api_launch_blocker_snapshot",
            "closed_as_artifact_gate" if high_risk_disabled else "gate_failed",
            True,
        ),
        _blocker(
            "AUD-618-P1-003",
            "P1",
            ["public_beta"],
            "State-root vectors and transcript capture tooling exist, but no external cross-machine replay transcript is attached.",
            "External/two-physical-machine replay transcript proving identical state roots, vector digest, and tx-index hash on the same commit.",
            "external_cross_machine_replay_transcript_schema",
            "gate_present_external_transcript_required" if state_roots.get("ok") and external_requirements.get("ok") else "gate_failed",
            False,
            ["external machine replay transcript", "same-commit state-root replay transcript", "matching tx-index hash transcript"],
        ),
        _blocker(
            "AUD-618-P1-004",
            "P1",
            ["public_beta"],
            "Storage/IPFS durability proof is deterministic/simulated until externally operated daemon topology is attached.",
            "Real daemon/operator topology with failure, retrieval, corrupt-content, wrong-CID, and revalidation transcript.",
            "storage_ipfs_operator_transcript_schema",
            "gate_present_real_operator_rehearsal_required" if storage.get("ok") and external_requirements.get("ok") else "gate_failed",
            False,
            ["real IPFS daemon transcript", "independent storage operator transcript"],
        ),
        _blocker(
            "AUD-618-P1-005",
            "P1",
            ["public_beta"],
            "Production helper execution remains disabled.",
            "Helper assignment, receipts, merge, crash, Byzantine, and serial equivalence proven under production topology before activation.",
            "production_helper_topology_gate",
            "gate_present_execution_still_disabled" if helper.get("ok") else "gate_failed",
            True,
            ["future helper production enablement governance/release gate"],
        ),
        _blocker(
            "AUD-618-P1-006",
            "P1",
            ["controlled_release_hygiene"],
            "Clean-clone root gate is present and now backed by a deterministic release-evidence manifest; concrete commit binding is emitted by runtime clean-gate reports.",
            "One-command clean-clone gate transcript from real checkout after commit, plus tracked manifest proving which artifacts and evidence gates were checked.",
            "release_evidence_manifest_and_clean_clone_gate",
            "closed_as_release_evidence_manifest_gate" if clean_clone.get("ok") and release_evidence.get("ok") else "gate_failed",
            True,
        ),
        _blocker(
            "AUD-628-P1-001",
            "P1",
            ["public_observer_launch"],
            "Public observer discovery code is present, but an external open-download transcript is still required before claiming public observer launch readiness.",
            "Clean-clone transcript proves signed registry discovery, seed/validator peer discovery, state sync, and frontend visibility from a new user environment.",
            "public_observer_launch_evidence_requirements",
            "gate_present_external_transcript_required" if public_observer_launch.get("ok") else "gate_failed",
            False,
            ["external clean-clone observer transcript", "state-sync proof", "rendered frontend operator journey"],
        ),
        _blocker(
            "AUD-618-P2-001",
            "P2",
            ["new_user_ux"],
            "Frontend node dashboard now includes a bounded operator wizard with role boundaries and safe copyable diagnostic command categories.",
            "Guided operator wizard explains blockers and safe commands without hidden state mutation.",
            "frontend_operator_wizard_source_gate",
            "closed_as_frontend_source_gate" if frontend_p2_ux.get("checks", {}).get("operator_wizard_surface_present") and frontend_p2_ux.get("checks", {}).get("source_contract_test_present") else "tracked_as_frontend_ux_gap",
            True,
        ),
        _blocker(
            "AUD-618-P2-002",
            "P2",
            ["testnet_ux"],
            "Transaction activity now shows submitted, locally accepted, queued/pending, forwarded/gossiped, included, finalized/confirmed, rejected, and removed-from-mempool states with unknown propagation shown honestly.",
            "Show submitted, locally accepted, queued/pending, forwarded/gossiped, included, finalized/confirmed, rejected, and removed-from-mempool stages without treating mempool acceptance as confirmation.",
            "tx_propagation_timeline_source_gate",
            "closed_as_frontend_source_gate" if frontend_p2_ux.get("checks", {}).get("tx_lifecycle_timeline_present") and frontend_p2_ux.get("checks", {}).get("source_contract_test_present") else "tracked_as_frontend_ux_gap",
            True,
        ),
        _blocker(
            "AUD-618-P2-003",
            "P2",
            ["observability"],
            "Node dashboard now includes a read-only operator incident timeline that ties node mode, chain identity, peer/seed status, mempool, block height, validator/BFT authority, storage/helper/economics/protocol-upgrade blockers, and safe diagnostics.",
            "Incident timeline ties mempool, peer sync, block, BFT, storage, and role blockers.",
            "operator_incident_timeline_gate",
            "closed_as_frontend_source_gate" if frontend_p2_ux.get("checks", {}).get("operator_incident_timeline_present") and frontend_p2_ux.get("checks", {}).get("node_dashboard_source_contract_updated") else "partially_closed_status_surface_present",
            True,
        ),
        _blocker(
            "AUD-618-P3-001",
            "P3",
            ["docs"],
            "Many scripts exist; first-run node-mode selection is still complex.",
            "One-page choose-your-node-mode quickstart.",
            "node_mode_quickstart_doc_gate",
            "closed_as_docs_gate",
            True,
        ),
    ]

    remaining = [b for b in blockers if b["remaining_external_evidence"] or b["gate_status"].startswith("tracked_as") or b["gate_status"].endswith("required")]
    transcript_schemas = {
        "public_validator_operator_transcript": {
            "required_fields": ["schema", "chain_id", "operator_ids", "node_ids", "machine_ids", "rounds", "partition_rejoin", "equivocation_rejected", "restart_replay", "state_root_by_node", "transcript_digest", "operator_signatures"],
            "must_not_claim": ["mainnet", "public_validator_enabled_without_gate", "economic_activation"],
        },
        "storage_ipfs_operator_transcript": {
            "required_fields": ["schema", "operator_ids", "machine_ids", "ipfs_peer_ids", "cid", "replication_factor", "origin_failure", "wrong_cid_rejected", "corrupt_content_rejected", "fresh_node_retrieval", "transcript_digest"],
            "must_not_claim": ["public_storage_market_enabled", "restricted_identity_evidence_publicly_visible"],
        },
        "legal_attestation": {
            "required_fields": ["schema", "review_date", "reviewer_or_counsel_reference", "scope", "approved_public_claims", "restricted_claims", "signature_or_controlled_reference"],
            "must_not_claim": ["legal_clearance_without_review", "token_sale_ready_without_counsel"],
        },
    }

    closed_code_gates = [b["id"] for b in blockers if b["can_be_closed_by_code_only"] and b["gate_status"].startswith("closed")]
    evidence_inventory_ok = bool(
        validator.get("ok")
        and storage.get("ok")
        and protocol_upgrade.get("ok")
        and helper.get("ok")
        and api_vectors.get("ok")
        and api_vector_count >= 24
        and state_roots.get("ok")
        and clean_clone.get("ok")
        and external_requirements.get("ok")
        and high_risk_disabled
        and legal.get("legal_compliance_ready") is False
        and frontend_p2_ux.get("ok") is True
    )
    open_blockers = [b for b in blockers if b in remaining]
    closed_count = len([b for b in blockers if str(b.get("gate_status", "")).startswith("closed")])
    classification_counts: dict[str, int] = {}
    for row in blockers:
        key = str(row.get("blocker_category") or "unclassified")
        classification_counts[key] = classification_counts.get(key, 0) + 1

    def count_open_severity(severity: str) -> int:
        return len([b for b in open_blockers if b.get("severity") == severity])

    remaining_mainnet_hardening_ids = [
        b["id"]
        for b in open_blockers
        if b["id"]
        in {
            "AUD-618-P0-001",
            "AUD-618-P0-003",
            "AUD-618-P1-004",
            "AUD-618-P1-005",
        }
    ]
    remaining_external_evidence_ids = [
        b["id"]
        for b in open_blockers
        if b.get("remaining_external_evidence") or str(b.get("gate_status", "")).endswith("required")
    ]
    count_meanings = {
        "blocker_count": "Compatibility alias for blocker_catalog_count; it is the full historical blocker catalog size, not the number still open.",
        "blocker_catalog_count": "Total blocker catalog entries kept visible for audit continuity.",
        "remaining_blocker_count": "Open blockers that still require external evidence, counsel attestation, or future mainnet-readiness hardening before public beta can be claimed.",
        "closed_in_repository_count": "Catalog entries closed by tracked repository evidence, generated artifacts, docs, or source-level UX gates.",
        "remaining_external_evidence_required_count": "Open blockers with missing independent transcript, real-operator proof, counsel attestation, or other external evidence.",
        "remaining_mainnet_hardening_count": "Open blockers whose final closure depends on future public-validator, protocol-upgrade, storage, or production-helper hardening beyond the bounded observer/controlled-testnet candidate.",
        "p*_open_count": "Open blocker count by severity, using remaining_blocker_count semantics rather than catalog size.",
    }

    return {
        "schema": "weall.v1_5.public_beta_blocker_report",
        "version": "2026-06-b620-public-beta-evidence-gates",
        "ok": evidence_inventory_ok,
        "evidence_inventory_ok": evidence_inventory_ok,
        "ok_meaning": "The blocker inventory and bounded evidence gates are current; this does not mean public beta readiness.",
        "public_beta_ready": False,
        "mainnet_ready": False,
        "controlled_testnet_candidate": True,
        "public_beta_blockers_remaining": True,
        "blocker_count": len(blockers),
        "blocker_catalog_count": len(blockers),
        "remaining_blocker_count": len(open_blockers),
        "open_blocker_count": len(open_blockers),
        "closed_blocker_count": closed_count,
        "closed_in_repository_count": closed_count,
        "remaining_external_evidence_required_count": len(remaining_external_evidence_ids),
        "remaining_mainnet_hardening_count": len(remaining_mainnet_hardening_ids),
        "p0_open_count": count_open_severity("P0"),
        "p1_open_count": count_open_severity("P1"),
        "p2_open_count": count_open_severity("P2"),
        "p3_open_count": count_open_severity("P3"),
        "remaining_external_evidence_required_ids": remaining_external_evidence_ids,
        "remaining_mainnet_hardening_ids": remaining_mainnet_hardening_ids,
        "count_meanings": count_meanings,
        "blocker_classification_summary": classification_counts,
        "closed_code_gate_ids": closed_code_gates,
        "blockers": blockers,
        "transcript_schemas": transcript_schemas,
        "external_operator_transcript_requirements": {
            "ok": bool(external_requirements.get("ok")),
            "schema_count": len(external_requirements.get("schemas") or {}),
            "artifact_digest": external_requirements.get("artifact_digest"),
            "external_attestation_required_before_public_beta": bool(external_requirements.get("external_attestation_required_before_public_beta")),
        },
        "evidence_gate_summaries": {
            "public_validator": validator,
            "storage_ipfs": storage,
            "protocol_upgrade_staging": protocol_upgrade,
            "helper_production_topology": helper,
            "api_response_vectors": {"ok": api_vectors.get("ok"), "vector_count": api_vector_count},
            "testnet_capability_surface": capabilities,
            "state_root_cross_machine_export": state_roots,
            "clean_clone_gate": clean_clone,
            "public_observer_launch_evidence_requirements": public_observer_launch,
            "release_evidence_manifest": {
                "ok": bool(release_evidence.get("ok")),
                "schema": release_evidence.get("schema"),
                "tracked_manifest_is_commit_agnostic": release_evidence.get("tracked_manifest_is_commit_agnostic"),
                "runtime_commit_binding_required": release_evidence.get("runtime_commit_binding_required"),
                "artifact_digest": release_evidence.get("artifact_digest"),
            },
            "frontend_p2_ux_observability": frontend_p2_ux,
            "legal_compliance": legal,
        },
        "release_claim_boundaries": {
            "public_beta_ready": False,
            "mainnet_ready": False,
            "public_validator_enabled": False,
            "public_multi_validator_bft": False,
            "public_storage_provider_market": False,
            "public_decentralized_media_durability": False,
            "production_helper_execution": False,
            "automatic_protocol_upgrades": False,
            "live_economics": False,
            "legal_compliance_ready": False,
        },
        "next_allowed_claim": "controlled testnet candidate with public-beta blocker evidence gates present",
        "verification_commands": [
            "PYTHONPATH=src:scripts python scripts/gen_public_beta_blocker_report_v1_5.py --check",
            "PYTHONPATH=src:scripts python scripts/gen_external_operator_transcript_requirements_v1_5.py --check",
            "PYTHONPATH=src:scripts python scripts/gen_public_observer_launch_evidence_requirements_v1_5.py --check",
            "PYTHONPATH=src:scripts python scripts/gen_release_evidence_manifest_v1_5.py --check",
            "PYTHONPATH=src python scripts/gen_api_response_vectors_v1_5.py --check",
            "PYTHONPATH=src python scripts/check_v15_public_readiness_artifacts.py --require-git-tracked",
            "PYTHONPATH=src:scripts python scripts/run_controlled_testnet_go_gate_v1_5.py --run-gates --require-git-tracked",
            "PYTHONPATH=src:scripts python -m pytest -q tests/prod/test_public_beta_evidence_gates.py",
        ],
    }


def _pretty(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, indent=2) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate/check v1.5 public beta blocker/evidence-gate report.")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    payload = build()
    text = _pretty(payload)
    if args.json:
        print(text, end="")
        return 0 if payload.get("ok") else 1
    if args.check:
        if not OUT.exists() or OUT.read_text(encoding="utf-8") != text:
            raise SystemExit("public_beta_blocker_report_v1_5.json is stale; rerun generator")
        print(
            f"OK: {OUT.relative_to(ROOT)} is current "
            f"({payload['blocker_catalog_count']} catalog entries; "
            f"{payload['remaining_blocker_count']} still open; public_beta_ready=false)"
        )
        return 0 if payload.get("ok") else 1
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text, encoding="utf-8")
    print(
        f"wrote {OUT.relative_to(ROOT)} "
        f"({payload['blocker_catalog_count']} catalog entries; {payload['remaining_blocker_count']} still open)"
    )
    return 0 if payload.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
