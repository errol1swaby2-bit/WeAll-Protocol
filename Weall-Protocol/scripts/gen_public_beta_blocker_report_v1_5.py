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
from pathlib import Path
from typing import Any

from gen_api_response_vectors_v1_5 import build as build_api_vectors
from rehearse_external_multimachine_validator_harness_b590_v1_5 import run_harness as run_validator_harness
from rehearse_helper_block_path_adversarial_b593_v1_5 import run_harness as run_helper_harness
from rehearse_multimachine_storage_ipfs_durability_b591_v1_5 import run_harness as run_storage_harness
from rehearse_protocol_upgrade_signed_staging_b589_v1_5 import run_harness as run_protocol_upgrade_harness
from weall.runtime.testnet_capabilities import build_testnet_capability_surface

ROOT = Path(__file__).resolve().parents[1]
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
    return {
        "ok": bool(payload.get("schema") == "weall.v1_5.state_root_vectors" and len(vectors) >= 8),
        "vector_count": len(vectors),
        "cross_machine_replay_exported": True,
        "external_cross_machine_attestation_required": True,
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
    return {
        "id": blocker_id,
        "severity": severity,
        "blocks": blocks,
        "current_behavior": current_behavior,
        "expected_production_behavior": expected_behavior,
        "evidence_gate": evidence_gate,
        "gate_status": gate_status,
        "can_be_closed_by_code_only": can_be_closed_by_code_only,
        "remaining_external_evidence": remaining_external_evidence or [],
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
            "gate_present_external_attestation_required" if validator.get("ok") else "gate_failed",
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
            "State-root vectors exist but need explicit cross-machine replay export status.",
            "Cross-machine/cross-implementation vector replay export and external attestation path.",
            "state_root_cross_machine_export_gate",
            "gate_present_external_attestation_required" if state_roots.get("ok") else "gate_failed",
            True,
            ["external machine replay transcript"],
        ),
        _blocker(
            "AUD-618-P1-004",
            "P1",
            ["public_beta"],
            "Storage/IPFS durability proof is deterministic/simulated until externally operated daemon topology is attached.",
            "Real daemon/operator topology with failure, retrieval, corrupt-content, wrong-CID, and revalidation transcript.",
            "storage_ipfs_operator_transcript_schema",
            "gate_present_real_operator_rehearsal_required" if storage.get("ok") else "gate_failed",
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
            "Clean-clone root gate needs fresh transcript after Batch 617/618 commit.",
            "One-command clean-clone gate transcript from real checkout after commit.",
            "clean_clone_gate_transcript_schema",
            "gate_script_present_transcript_required" if clean_clone.get("ok") else "gate_script_missing",
            False,
            ["run scripts/run_clean_clone_go_gate_v1_5.sh after commit"],
        ),
        _blocker(
            "AUD-618-P2-001",
            "P2",
            ["new_user_ux"],
            "Frontend has status panels; production switch remains script/preflight oriented.",
            "Guided operator wizard explains blockers and safe commands without hidden state mutation.",
            "frontend_operator_wizard_source_gate",
            "tracked_as_frontend_ux_gap",
            True,
        ),
        _blocker(
            "AUD-618-P2-002",
            "P2",
            ["testnet_ux"],
            "Tx page shows local status; full propagation lifecycle remains partially implicit.",
            "Show accepted, gossiped, included, finalized, and removed-from-mempool stages.",
            "tx_propagation_timeline_source_gate",
            "tracked_as_frontend_ux_gap",
            True,
        ),
        _blocker(
            "AUD-618-P2-003",
            "P2",
            ["observability"],
            "Operator diagnostics exist but are distributed across surfaces.",
            "Incident timeline ties mempool, peer sync, block, BFT, storage, and role blockers.",
            "operator_incident_timeline_gate",
            "partially_closed_status_surface_present",
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
            "must_not_claim": ["public_storage_market_enabled", "private_evidence_publicly_visible"],
        },
        "legal_attestation": {
            "required_fields": ["schema", "review_date", "reviewer_or_counsel_reference", "scope", "approved_public_claims", "restricted_claims", "signature_or_controlled_reference"],
            "must_not_claim": ["legal_clearance_without_review", "token_sale_ready_without_counsel"],
        },
    }

    closed_code_gates = [b["id"] for b in blockers if b["can_be_closed_by_code_only"] and b["gate_status"].startswith("closed")]
    ok = bool(
        validator.get("ok")
        and storage.get("ok")
        and protocol_upgrade.get("ok")
        and helper.get("ok")
        and api_vectors.get("ok")
        and api_vector_count >= 24
        and state_roots.get("ok")
        and clean_clone.get("ok")
        and high_risk_disabled
        and legal.get("legal_compliance_ready") is False
    )

    return {
        "schema": "weall.v1_5.public_beta_blocker_report",
        "version": "2026-06-b618-public-beta-evidence-gates",
        "ok": ok,
        "public_beta_ready": False,
        "mainnet_ready": False,
        "controlled_private_testnet_candidate": True,
        "public_beta_blockers_remaining": True,
        "blocker_count": len(blockers),
        "remaining_blocker_count": len(remaining),
        "closed_code_gate_ids": closed_code_gates,
        "blockers": blockers,
        "transcript_schemas": transcript_schemas,
        "evidence_gate_summaries": {
            "public_validator": validator,
            "storage_ipfs": storage,
            "protocol_upgrade_staging": protocol_upgrade,
            "helper_production_topology": helper,
            "api_response_vectors": {"ok": api_vectors.get("ok"), "vector_count": api_vector_count},
            "testnet_capability_surface": capabilities,
            "state_root_cross_machine_export": state_roots,
            "clean_clone_gate": clean_clone,
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
        "next_allowed_claim": "controlled private testnet candidate with public-beta blocker evidence gates present",
        "verification_commands": [
            "PYTHONPATH=src:scripts python scripts/gen_public_beta_blocker_report_v1_5.py --check",
            "PYTHONPATH=src python scripts/gen_api_response_vectors_v1_5.py --check",
            "PYTHONPATH=src python scripts/check_v15_public_readiness_artifacts.py --require-git-tracked",
            "PYTHONPATH=src:scripts python scripts/run_controlled_testnet_go_gate_v1_5.py --run-gates --require-git-tracked",
            "PYTHONPATH=src:scripts python -m pytest -q tests/prod/test_batch618_public_beta_evidence_gates.py",
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
        print(f"OK: {OUT.relative_to(ROOT)} is current ({payload['blocker_count']} blockers)")
        return 0 if payload.get("ok") else 1
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)} ({payload['blocker_count']} blockers)")
    return 0 if payload.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
