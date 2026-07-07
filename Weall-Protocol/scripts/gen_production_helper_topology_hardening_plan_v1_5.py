#!/usr/bin/env python3
from __future__ import annotations

"""Generate the v1.5 production-helper topology hardening plan artifact.

This artifact keeps AUD-618-P1-005 open. It documents the future proof needed
before helper-based execution can be enabled in production topology while
preserving the current boundary: helper production execution is disabled by the
launch matrix and no governance/release path enables it in v1.5.
"""

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from weall.runtime.launch_matrix import (
    FEATURE_HELPER_PRODUCTION_EXECUTION,
    LAUNCH_PHASES,
    feature_status,
)

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "generated" / "production_helper_topology_hardening_plan_v1_5.json"
Json = dict[str, Any]


def _canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _digest(obj: Any) -> str:
    return hashlib.sha256(_canon(obj).encode("utf-8")).hexdigest()


def _exists(rel: str) -> bool:
    return (ROOT / rel).is_file()


def _launch_matrix_disabled_by_phase() -> Json:
    return {
        phase: feature_status(phase, FEATURE_HELPER_PRODUCTION_EXECUTION).as_dict()
        for phase in LAUNCH_PHASES
    }


def build() -> Json:
    docs = {
        "hardening_plan": "docs/testnet/PRODUCTION_HELPER_TOPOLOGY_HARDENING_PLAN.md",
        "proof_slot": "docs/proofs/production-helper-topology-hardening/2026-07-05/README.md",
        "plan_template": "docs/proofs/production-helper-topology-hardening/2026-07-05/PLAN_TEMPLATE.json",
        "helper_safety_spec": "docs/PRODUCTION_POSTURE.md",
    }
    current_boundary = {
        "production_helper_execution_enabled": False,
        "helper_mode_grants_protocol_authority": False,
        "frontend_state_authority": False,
        "local_script_authority": False,
        "governance_enablement_path_live": False,
        "release_manifest_enablement_path_live": False,
        "helper_receipts_required_for_block_validity": False,
        "missing_helpers_can_halt_block_production": False,
        "serial_fallback_required": True,
        "launch_matrix_blocks_all_current_phases": all(
            not bool(row.get("enabled")) for row in _launch_matrix_disabled_by_phase().values()
        ),
    }
    future_required_evidence = [
        "deterministic_helper_assignment_from_canonical_inputs",
        "deterministic_lane_partitioning_for_all_tx_families",
        "canonical_ordering_before_helper_execution",
        "receipt_signature_domain_separation_and_context_binding",
        "deterministic_merge_order_and_root_commitment",
        "serial_vs_helper_equivalence_corpus_for_all_supported_tx_types",
        "missing_helper_timeout_and_serial_fallback_proof",
        "byzantine_helper_output_rejection_and_misbehavior_proof",
        "crash_restart_replay_equivalence_across_helper_enabled_nodes",
        "multi_node_staggered_helper_topology_transcript",
        "operator_helper_identity_and_key_rotation_policy",
        "capacity_budget_overcommit_and_slow_helper_backpressure_proof",
        "governance_release_gate_with_launch_matrix_transition",
        "public_incident_response_and_forensics_runbook",
        "strict_external_transcript_validation_before_any_public_claim",
    ]
    disabled_execution_tests = [
        "tests/test_launch_disabled_matrix_v15.py",
        "tests/test_helper_release_gate.py",
        "tests/test_helper_readiness_report.py",
        "tests/prod/test_production_helper_topology_hardening_plan.py",
    ]
    launch_status = _launch_matrix_disabled_by_phase()
    payload: Json = {
        "schema": "weall.v1_5.production_helper_topology_hardening_plan",
        "version": "2026-07-pass26-production-helper-topology-hardening-plan",
        "ok": all(_exists(path) for path in docs.values())
        and all(not bool(row.get("enabled")) for row in launch_status.values()),
        "blocker": "AUD-618-P1-005",
        "blocker_status": "open_future_mainnet_hardening",
        "public_beta_ready": False,
        "mainnet_ready": False,
        "production_helper_execution_ready": False,
        "production_helper_execution_enabled": False,
        "current_boundary": current_boundary,
        "launch_matrix_status_by_phase": launch_status,
        "future_required_evidence": future_required_evidence,
        "future_enablement_phases": [
            "helper_topology_declaration_record",
            "serial_equivalence_expansion",
            "byzantine_helper_rejection_rehearsal",
            "multi_node_helper_capacity_rehearsal",
            "operator_identity_and_key_policy_review",
            "governance_release_gate_record",
            "launch_matrix_transition_proposal",
            "controlled_activation_rehearsal",
            "public_incident_response_rehearsal",
        ],
        "required_manifest_fields": [
            "schema",
            "chain_id",
            "network_id",
            "helper_topology_id",
            "validator_set_hash",
            "helper_set_hash",
            "lane_partition_hash",
            "tx_order_hash",
            "serial_equivalence_corpus_sha256",
            "byzantine_rejection_matrix_sha256",
            "restart_replay_vector_sha256",
            "capacity_budget",
            "operator_policy",
            "governance_record_tx_id",
            "release_gate_digest",
            "signer_id",
            "signature",
        ],
        "must_remain_disabled_until": [
            "all_future_required_evidence_attached",
            "external_transcript_validated",
            "release_gate_digest_published",
            "launch_matrix_transition_reviewed",
            "governance_record_finalized",
            "operator_runbook_and_incident_response_rehearsed",
        ],
        "docs": docs,
        "docs_present": {key: _exists(path) for key, path in docs.items()},
        "disabled_execution_tests": disabled_execution_tests,
        "claim_boundaries": {
            "public_beta_ready": False,
            "mainnet_ready": False,
            "production_helper_execution": False,
            "helper_mode_authority": False,
            "public_validator_enabled": False,
            "live_economics": False,
            "automatic_protocol_upgrades": False,
            "storage_market_ready": False,
        },
    }
    payload["artifact_digest"] = _digest({k: v for k, v in payload.items() if k != "artifact_digest"})
    return payload


def _pretty(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, indent=2) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate/check v1.5 production-helper topology hardening plan artifact.")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    payload = build()
    text = _pretty(payload)
    if args.json:
        print(text, end="")
        return 0 if payload.get("ok") else 1
    if args.check:
        if not OUT.exists() or OUT.read_text(encoding="utf-8") != text:
            raise SystemExit("production_helper_topology_hardening_plan_v1_5.json is stale; rerun generator")
        print(f"OK: {OUT.relative_to(ROOT)} is current (AUD-618-P1-005 open; production_helper_execution_enabled=false)")
        return 0 if payload.get("ok") else 1
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)} (AUD-618-P1-005 open; production_helper_execution_enabled=false)")
    return 0 if payload.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
