#!/usr/bin/env python3
from __future__ import annotations

"""Generate the final bounded public observer / controlled-testnet go-gate package.

This artifact is intentionally conservative. It packages the repository-side
readiness evidence after Pass 27, but it does not close external evidence,
counsel, storage, helper, validator, replay, or executable-upgrade blockers.
"""

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "generated" / "final_public_observer_controlled_testnet_go_gate_v1_5.json"
Json = dict[str, Any]

REQUIRED_DOCS = {
    "reviewer_evidence_index": "docs/reviewer/EVIDENCE_INDEX.md",
    "current_readiness_statement": "docs/reviewer/CURRENT_READINESS_STATEMENT.md",
    "current_testnet_readiness_statement": "docs/reviewer/CURRENT_TESTNET_READINESS_STATEMENT.md",
    "public_beta_blocker_status": "docs/reviewer/PUBLIC_BETA_BLOCKER_STATUS.md",
    "public_observer_quickstart": "docs/testnet/PUBLIC_OBSERVER_QUICKSTART.md",
    "testnet_launch_checklist": "docs/testnet/TESTNET_LAUNCH_CHECKLIST.md",
    "final_go_gate_runbook": "docs/testnet/FINAL_PUBLIC_OBSERVER_CONTROLLED_TESTNET_GO_GATE.md",
    "first_15_minutes": "docs/testnet/FIRST_15_MINUTES.md",
    "external_observer_transcript": "docs/testnet/PUBLIC_OBSERVER_OPEN_DOWNLOAD_TRANSCRIPT.md",
    "external_replay_transcript": "docs/testnet/EXTERNAL_CROSS_MACHINE_REPLAY_TRANSCRIPT.md",
    "storage_ipfs_transcript": "docs/testnet/REAL_STORAGE_IPFS_OPERATOR_TRANSCRIPT.md",
    "validator_operator_transcript": "docs/testnet/INDEPENDENT_CONTROLLED_VALIDATOR_OPERATOR_TRANSCRIPT.md",
    "legal_evidence_pack": "docs/testnet/LEGAL_COMPLIANCE_EVIDENCE_PACK.md",
    "upgrade_hardening_plan": "docs/testnet/UPGRADE_EXECUTION_HARDENING_PLAN.md",
    "helper_hardening_plan": "docs/testnet/PRODUCTION_HELPER_TOPOLOGY_HARDENING_PLAN.md",
}

REQUIRED_GENERATED = {
    "public_beta_blocker_report": "generated/public_beta_blocker_report_v1_5.json",
    "controlled_testnet_go_gate": "generated/controlled_testnet_go_gate_v1_5.json",
    "b587_b594_mechanism_completion": "generated/b587_b594_testnet_mechanism_completion_v1_5.json",
    "public_observer_launch_requirements": "generated/public_observer_launch_evidence_requirements_v1_5.json",
    "external_operator_transcript_requirements": "generated/external_operator_transcript_requirements_v1_5.json",
    "protocol_upgrade_hardening_plan": "generated/protocol_upgrade_execution_hardening_plan_v1_5.json",
    "production_helper_topology_hardening_plan": "generated/production_helper_topology_hardening_plan_v1_5.json",
    "release_evidence_manifest": "generated/release_evidence_manifest_v1_5.json",
    "crypto_inventory": "generated/crypto_inventory_v1_5.json",
    "signature_profile_registry": "generated/signature_profile_registry_v1_5.json",
    "quantum_resistance_readiness": "generated/quantum_resistance_readiness_v1_5.json",
}

FLOW_DOCS = {
    "first_run_tester_onboarding": "docs/testnet/FIRST_15_MINUTES.md",
    "account_profile": "docs/testnet/ACCOUNT_PROFILE_READINESS.md",
    "public_social": "docs/testnet/PUBLIC_SOCIAL_FLOW_READINESS.md",
    "groups": "docs/testnet/GROUP_FLOW_READINESS.md",
    "governance": "docs/testnet/GOVERNANCE_RENDERED_JOURNEY.md",
    "disputes": "docs/testnet/DISPUTE_REVIEW_RENDERED_JOURNEY.md",
    "transaction_lifecycle": "docs/testnet/TRANSACTION_LIFECYCLE_RENDERED_EVIDENCE.md",
    "node_operator": "docs/testnet/NODE_OPERATOR_JOURNEY_AND_INCIDENT_RESPONSE.md",
}


def _canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _digest(obj: Any) -> str:
    return hashlib.sha256(_canon(obj).encode("utf-8")).hexdigest()


def _read_json(rel: str) -> Json:
    try:
        value = json.loads((ROOT / rel).read_text(encoding="utf-8"))
    except Exception:
        return {}
    return value if isinstance(value, dict) else {}


def _exists_map(items: dict[str, str]) -> dict[str, bool]:
    return {key: (ROOT / rel).is_file() for key, rel in items.items()}


def _artifact_summary(rel: str) -> Json:
    payload = _read_json(rel)
    return {
        "path": rel,
        "present": bool(payload),
        "schema": str(payload.get("schema") or "") if payload else "",
        "ok": bool(payload.get("ok", True)) if payload else False,
    }


def _blocker_counts() -> Json:
    blocker = _read_json("generated/public_beta_blocker_report_v1_5.json")
    return {
        "public_beta_ready": blocker.get("public_beta_ready"),
        "blocker_catalog_count": blocker.get("blocker_catalog_count"),
        "closed_in_repository_count": blocker.get("closed_in_repository_count"),
        "remaining_blocker_count": blocker.get("remaining_blocker_count"),
        "remaining_external_evidence_required_count": blocker.get("remaining_external_evidence_required_count"),
        "remaining_mainnet_hardening_count": blocker.get("remaining_mainnet_hardening_count"),
        "p0_open_count": blocker.get("p0_open_count"),
        "p1_open_count": blocker.get("p1_open_count"),
        "remaining_external_evidence_required_ids": blocker.get("remaining_external_evidence_required_ids") or [],
        "remaining_mainnet_hardening_ids": blocker.get("remaining_mainnet_hardening_ids") or [],
    }


def build() -> Json:
    docs_present = _exists_map(REQUIRED_DOCS)
    generated_present = _exists_map(REQUIRED_GENERATED)
    flow_docs_present = _exists_map(FLOW_DOCS)
    blocker_counts = _blocker_counts()
    generated_artifacts = {key: _artifact_summary(rel) for key, rel in REQUIRED_GENERATED.items()}

    remaining_ids = list(blocker_counts.get("remaining_external_evidence_required_ids") or [])
    expected_remaining = {
        "AUD-618-P0-001",
        "AUD-618-P0-002",
        "AUD-618-P0-003",
        "AUD-618-P1-003",
        "AUD-618-P1-004",
        "AUD-618-P1-005",
        "AUD-628-P1-001",
        "AUD-633-P0-004",
    }
    quantum = _read_json("generated/quantum_resistance_readiness_v1_5.json")
    real_mldsa_ready = bool(quantum.get("real_mldsa_implemented_in_this_environment"))
    external_blockers_still_open = set(remaining_ids) == expected_remaining
    repo_package_ready = all(docs_present.values()) and all(generated_present.values()) and all(flow_docs_present.values())
    artifact_consistent = repo_package_ready and external_blockers_still_open and blocker_counts.get("public_beta_ready") is False
    bounded_rehearsal_candidate = artifact_consistent and real_mldsa_ready
    controlled_verdict = "GO" if bounded_rehearsal_candidate else "NO_GO_PQ_SIGNING_PROFILE_INCOMPLETE"

    payload: Json = {
        "schema": "weall.v1_5.final_public_observer_controlled_testnet_go_gate",
        "version": "2026-07-pass27-final-bounded-testnet-go-gate",
        "ok": artifact_consistent,
        "controlled_rehearsal_candidate_ready": bounded_rehearsal_candidate,
        "repo_package_ready": repo_package_ready,
        "go_no_go_verdict": {
            "controlled_internal_public_observer_rehearsal_candidate": controlled_verdict,
            "bounded_public_observer_launch_claim": "NO_GO_EXTERNAL_EVIDENCE_PENDING",
            "public_beta_claim": "NO_GO_PUBLIC_BETA_BLOCKERS_OPEN",
            "public_mainnet_claim": "NO_GO_UNCLAIMED",
            "public_validator_bft_claim": "NO_GO_UNCLAIMED",
            "live_economics_claim": "NO_GO_DISABLED",
            "automatic_upgrade_claim": "NO_GO_RECORD_ONLY",
            "production_helper_claim": "NO_GO_DISABLED",
        },
        "allowed_claim": "Pre-public-testnet implementation under active hardening. The controlled-testnet signing profile has transitioned to profile-aware pq-mldsa-v1 ML-DSA signing for protocol authority surfaces covered by this pass. Fresh post-transition observer/testnet evidence and external cryptographic review remain required before any long-lived public network or mainnet claim.",
        "forbidden_claims": [
            "public beta readiness",
            "public mainnet readiness",
            "public multi-validator BFT readiness",
            "public validator safety",
            "live economics readiness",
            "automatic protocol upgrade readiness",
            "executable migration readiness",
            "rollback execution readiness",
            "production helper execution readiness",
            "legal/compliance approval",
            "public storage-market readiness",
            "completed production cryptographic audit",
            "production post-quantum security",
            "quantum-proof security",
            "complete anti-Sybil/collusion detection",
            "complete public identity infrastructure",
        ],
        "blocker_counts": blocker_counts,
        "external_evidence_still_required": True,
        "external_blockers_still_open": external_blockers_still_open,
        "remaining_open_blockers": sorted(expected_remaining),
        "real_mldsa_implemented_in_this_environment": real_mldsa_ready,
        "quantum_resistance_readiness_summary": {
            "path": "generated/quantum_resistance_readiness_v1_5.json",
            "real_mldsa_implemented_in_this_environment": real_mldsa_ready,
            "remaining_crypto_blockers": quantum.get("remaining_crypto_blockers") or [],
            "production_crypto_audit_complete": bool(quantum.get("production_crypto_audit_complete")),
        },
        "required_external_evidence_before_public_beta_or_public_observer_claim": {
            "AUD-628-P1-001": "external clean-clone/open-download/state-sync/frontend rendered journey transcript",
            "AUD-618-P1-003": "external/two-machine replay transcript proving identical state roots, vector digest, and tx-index hash",
            "AUD-618-P1-004": "real storage/IPFS daemon/operator transcript",
            "AUD-618-P0-001": "independent controlled validator/operator transcript",
            "AUD-618-P0-002": "real counsel or controlled legal/compliance attestation",
            "AUD-618-P0-003": "future executable upgrade staging/rollback proof",
            "AUD-618-P1-005": "future production helper topology proof",
            "AUD-633-P0-004": "fresh profile-aware post-transition rehearsal evidence, browser/local signing boundary review, helper/evidence signing production gate, and external cryptographic review",
        },
        "readiness_package_docs": REQUIRED_DOCS,
        "readiness_package_docs_present": docs_present,
        "flow_readiness_docs": FLOW_DOCS,
        "flow_readiness_docs_present": flow_docs_present,
        "generated_artifacts": generated_artifacts,
        "launch_check_commands": [
            "PYTHONPATH=src python -m compileall -q src/weall",
            "bash scripts/secret_guard.sh",
            "PYTHONPATH=src:scripts python scripts/gen_final_public_observer_controlled_testnet_go_gate_v1_5.py --check",
            "PYTHONPATH=src:scripts python scripts/gen_public_beta_blocker_report_v1_5.py --check",
            "PYTHONPATH=src python scripts/check_v15_public_readiness_artifacts.py",
            "PYTHONPATH=src python scripts/check_release_hygiene_v1_5.py",
            "PYTHONPATH=src python -m pytest -q tests/prod/test_final_public_observer_controlled_testnet_go_gate.py",
            "cd ../web && npm run typecheck && npm run build",
        ],
        "claim_boundaries": {
            "public_beta_ready": False,
            "mainnet_ready": False,
            "public_validator_enabled": False,
            "public_multi_validator_bft": False,
            "public_storage_provider_market": False,
            "production_crypto_audit_complete": False,
            "production_post_quantum_security": False,
            "production_helper_execution": False,
            "automatic_protocol_upgrades": False,
            "live_economics": False,
            "legal_compliance_ready": False,
        },
    }
    payload["artifact_digest"] = _digest({k: v for k, v in payload.items() if k != "artifact_digest"})
    return payload


def _pretty(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, indent=2) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate/check final bounded public observer / controlled-testnet go-gate package.")
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
            raise SystemExit("final_public_observer_controlled_testnet_go_gate_v1_5.json is stale; rerun generator")
        print("OK: generated/final_public_observer_controlled_testnet_go_gate_v1_5.json is current (bounded controlled verdict; NO-GO public beta)")
        return 0 if payload.get("ok") else 1
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text, encoding="utf-8")
    print("wrote generated/final_public_observer_controlled_testnet_go_gate_v1_5.json (bounded controlled verdict; NO-GO public beta)")
    return 0 if payload.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
