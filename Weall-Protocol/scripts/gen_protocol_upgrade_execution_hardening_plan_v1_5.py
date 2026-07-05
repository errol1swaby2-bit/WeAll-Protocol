#!/usr/bin/env python3
from __future__ import annotations

"""Generate the v1.5 protocol-upgrade execution hardening plan artifact.

This artifact keeps AUD-618-P0-003 open. It documents the future proof needed for
executable protocol/constitution upgrades while preserving the current record-only
boundary: no artifact fetch, software apply, migration, rollback, restart, or
live-economics activation happens in v1.5.
"""

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "generated" / "protocol_upgrade_execution_hardening_plan_v1_5.json"
Json = dict[str, Any]


def _canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _digest(obj: Any) -> str:
    return hashlib.sha256(_canon(obj).encode("utf-8")).hexdigest()


def _exists(rel: str) -> bool:
    return (ROOT / rel).is_file()


def build() -> Json:
    docs = {
        "record_only_boundary": "docs/PROTOCOL_UPGRADE_RECORD_ONLY_BOUNDARY.md",
        "hardening_plan": "docs/testnet/UPGRADE_EXECUTION_HARDENING_PLAN.md",
        "proof_slot": "docs/proofs/protocol-upgrade-execution-hardening/2026-07-05/README.md",
        "plan_template": "docs/proofs/protocol-upgrade-execution-hardening/2026-07-05/PLAN_TEMPLATE.json",
    }
    current_boundary = {
        "protocol_upgrade_records_only": True,
        "constitution_upgrade_records_only": True,
        "artifact_fetch_enabled": False,
        "software_apply_enabled": False,
        "migration_execution_enabled": False,
        "rollback_execution_enabled": False,
        "node_restart_enabled": False,
        "automatic_protocol_upgrades": False,
        "economics_activation_enabled": False,
        "frontend_state_authority": False,
        "local_script_authority": False,
    }
    future_evidence = [
        "signed_artifact_manifest_with_chain_network_version_and_digest_binding",
        "release_signer_allowlist_and_signature_verification",
        "compatibility_window_stage_activate_and_old_binary_support_heights",
        "deterministic_migration_vectors_with_before_after_state_roots",
        "rollback_or_forward_only_repair_semantics_with_vectors",
        "explicit_operator_approval_policy",
        "multi_node_staged_rollout_transcript",
        "crash_restart_during_staging_and_migration_transcript",
        "fresh_node_catchup_after_upgrade_transcript",
        "public_incident_and_rollback_runbook",
        "strict_release_external_transcript_validation",
    ]
    disabled_execution_tests = [
        "tests/test_protocol_upgrade_record_only_boundary.py",
        "tests/test_protocol_upgrade_height_scheduled_lifecycle.py",
        "tests/test_constitution_upgrade_height_scheduled_lifecycle.py",
        "tests/prod/test_protocol_upgrade_execution_hardening_plan.py",
    ]
    payload: Json = {
        "schema": "weall.v1_5.protocol_upgrade_execution_hardening_plan",
        "version": "2026-07-pass25-upgrade-execution-hardening-plan",
        "ok": all(_exists(path) for path in docs.values()),
        "blocker": "AUD-618-P0-003",
        "blocker_status": "open_future_mainnet_hardening",
        "public_beta_ready": False,
        "mainnet_ready": False,
        "automatic_protocol_upgrades_ready": False,
        "execution_enabled": False,
        "current_boundary": current_boundary,
        "future_required_evidence": future_evidence,
        "future_execution_phases": [
            "declaration_record",
            "signed_artifact_staging",
            "operator_review",
            "governance_activation_record",
            "pre_activation_rehearsal",
            "deterministic_migration_execution",
            "post_activation_verification",
            "rollback_or_forward_repair",
        ],
        "required_manifest_fields": [
            "schema",
            "chain_id",
            "network_id",
            "upgrade_id",
            "target_version",
            "artifact_sha256",
            "tx_index_sha256",
            "migration_vector_sha256",
            "rollback_vector_sha256",
            "compatibility_window",
            "operator_policy",
            "signer_id",
            "signature",
        ],
        "rollback_semantics_allowed_future_models": [
            "deterministic_reverse_rollback_with_vectors",
            "forward_only_compensating_migration_with_vectors",
        ],
        "rollback_semantics_current_model": "disabled_not_available",
        "docs": docs,
        "docs_present": {key: _exists(path) for key, path in docs.items()},
        "disabled_execution_tests": disabled_execution_tests,
        "claim_boundaries": {
            "public_beta_ready": False,
            "mainnet_ready": False,
            "automatic_protocol_upgrades": False,
            "protocol_migrations": False,
            "protocol_rollbacks": False,
            "live_economics": False,
            "public_validator_enabled": False,
            "production_helper_execution": False,
        },
    }
    payload["artifact_digest"] = _digest({k: v for k, v in payload.items() if k != "artifact_digest"})
    return payload


def _pretty(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, indent=2) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate/check v1.5 protocol-upgrade execution hardening plan artifact.")
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
            raise SystemExit("protocol_upgrade_execution_hardening_plan_v1_5.json is stale; rerun generator")
        print(f"OK: {OUT.relative_to(ROOT)} is current (AUD-618-P0-003 open; execution_enabled=false)")
        return 0 if payload.get("ok") else 1
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)} (AUD-618-P0-003 open; execution_enabled=false)")
    return 0 if payload.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
