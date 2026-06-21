#!/usr/bin/env python3
from __future__ import annotations

"""Generate the public-observer open-download launch evidence requirements.

This artifact is a launch gate, not a launch claim.  It records the exact
transcripts required before the repository may claim that an arbitrary new user
can clone, boot a public observer, auto-discover seed/validator peers, sync, and
understand status from the local frontend.
"""

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "generated" / "public_observer_launch_evidence_requirements_v1_5.json"
Json = dict[str, Any]


def _canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _pretty(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, indent=2) + "\n"


def build() -> Json:
    gates: list[Json] = [
        {
            "id": "public_registry_signed_and_pinned",
            "required_before_public_observer_launch": True,
            "evidence_type": "signed_registry_json_plus_signer_pin",
            "required_fields": [
                "network_id",
                "chain_id",
                "genesis_hash",
                "protocol_profile_hash",
                "tx_index_hash",
                "seed_api_urls",
                "seed_p2p_urls",
                "seed_registry_signer",
                "seed_registry_signature",
                "resettable_testnet",
                "economics_active",
            ],
            "validation_command": "PYTHONPATH=src WEALL_PUBLIC_TESTNET=1 WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PUBKEY=<pubkey> python scripts/sign_public_seed_registry_v1_5.py --input <unsigned.json> --output configs/public_testnet_seed_registry.json --check",
        },
        {
            "id": "clean_clone_public_observer_boot",
            "required_before_public_observer_launch": True,
            "evidence_type": "external_transcript",
            "required_steps": [
                "fresh git clone",
                "pip install -r requirements.lock",
                "pip install -e .",
                "scripts/boot_public_observer_testnet.sh starts with signed registry",
                "/v1/nodes/seeds verifies registry signature",
                "/v1/nodes/validators reports active validators and verified endpoint counts",
                "/v1/observer/edge/status separates local outbox from upstream acceptance",
            ],
        },
        {
            "id": "public_observer_state_sync",
            "required_before_public_observer_launch": True,
            "evidence_type": "state_sync_transcript",
            "required_observations": [
                "chain identity matches registry commitments",
                "observer catches up from genesis/current trusted head",
                "state root matches seed/validator reported root",
                "restart preserves synced posture",
            ],
        },
        {
            "id": "validator_endpoint_churn_visibility",
            "required_before_public_observer_launch": True,
            "evidence_type": "validator_set_churn_transcript",
            "required_observations": [
                "new validator appears in /v1/nodes/validators from protocol state",
                "missing/stale endpoint is surfaced as not fully reachable",
                "signed fresh endpoint advertisement clears the warning",
                "unsigned endpoint hint is not auto-dialed",
            ],
        },
        {
            "id": "rendered_public_observer_frontend",
            "required_before_public_observer_launch": True,
            "evidence_type": "rendered_frontend_e2e",
            "validation_command": "cd web && npm run test:public-observer-rendered",
            "required_surfaces": [
                "seed registry signature status",
                "seed API and P2P counts",
                "active validators",
                "verified and fresh endpoint counts",
                "observer edge outbox/upstream/confirmed counts",
                "peer connectivity and NAT/relay recovery guidance",
                "backend-derived validator promotion checklist",
                "transaction propagation timeline",
            ],
        },
        {
            "id": "registry_signer_rotation_and_revocation",
            "required_before_public_observer_launch": True,
            "evidence_type": "signer_operations_runbook",
            "validation_command": "PYTHONPATH=src:scripts python scripts/gen_public_registry_signer_operations_v1_5.py --check",
            "required_operations": [
                "offline registry signing key custody",
                "pinned signer publication",
                "runtime validation before registry publication",
                "rotation overlap window",
                "emergency compromised-signer revocation",
            ],
        },
        {
            "id": "tracked_launch_transcript_artifacts",
            "required_before_public_observer_launch": True,
            "evidence_type": "static_transcript_contracts_plus_runtime_attachment",
            "validation_command": "PYTHONPATH=src:scripts python scripts/gen_public_observer_launch_transcript_v1_5.py --check",
            "required_artifacts": [
                "generated/public_seed_registry_signature_verification_v1_5.json",
                "generated/public_observer_clean_clone_bootstrap_transcript_v1_5.json",
                "generated/public_observer_auto_discovery_proof_v1_5.json",
                "generated/public_observer_state_sync_trusted_anchor_proof_v1_5.json",
            ],
        },
    ]
    payload: Json = {
        "schema": "weall.v1_5.public_observer_launch_evidence_requirements",
        "version": "2026-06-b628-public-observer-launch-evidence",
        "ok": True,
        "public_observer_launch_ready": False,
        "public_beta_ready": False,
        "mainnet_ready": False,
        "purpose": "tracked launch-evidence contract for open-download public observer readiness",
        "required_gate_count": len(gates),
        "gates": gates,
        "claim_boundaries": {
            "public_observer_launch_ready": False,
            "public_beta_ready": False,
            "mainnet_ready": False,
            "public_validator_enabled": False,
            "public_multi_validator_bft": False,
            "live_economics": False,
            "production_helper_execution": False,
            "legal_compliance_ready": False,
        },
        "recommended_artifacts_before_launch": [
            "generated/public_seed_registry_signature_verification_v1_5.json",
            "generated/public_observer_clean_clone_bootstrap_transcript_v1_5.json",
            "generated/public_observer_auto_discovery_proof_v1_5.json",
            "generated/public_observer_state_sync_trusted_anchor_proof_v1_5.json",
            "generated/public_validator_endpoint_churn_proof_v1_5.json",
            "generated/public_frontend_operator_journey_v1_5.json",
            "generated/public_registry_signer_operations_v1_5.json",
            "generated/public_observer_launch_runtime_transcript_v1_5.json",
        ],
        "verification_commands": [
            "PYTHONPATH=src:scripts python scripts/gen_public_observer_launch_evidence_requirements_v1_5.py --check",
            "PYTHONPATH=src:scripts python scripts/gen_public_observer_launch_transcript_v1_5.py --check",
            "PYTHONPATH=src:scripts python scripts/gen_public_validator_endpoint_churn_proof_v1_5.py --check",
            "PYTHONPATH=src:scripts python scripts/gen_public_frontend_operator_journey_v1_5.py --check",
            "PYTHONPATH=src:scripts python scripts/gen_public_registry_signer_operations_v1_5.py --check",
            "PYTHONPATH=src python -m pytest -q tests/prod/test_public_observer_default_registry_and_placeholder_gate.py tests/prod/test_public_observer_registry_auto_dial.py tests/prod/test_public_validator_endpoint_discovery.py",
            "bash scripts/boot_public_observer_testnet.sh",
        ],
    }
    payload["artifact_digest"] = hashlib.sha256(_canon({"schema": payload["schema"], "gates": gates}).encode("utf-8")).hexdigest()
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate/check public observer launch evidence requirements.")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    payload = build()
    text = _pretty(payload)
    if args.json:
        print(text, end="")
        return 0
    if args.check:
        if not OUT.exists() or OUT.read_text(encoding="utf-8") != text:
            raise SystemExit("public_observer_launch_evidence_requirements_v1_5.json is stale; rerun generator")
        print(f"OK: {OUT.relative_to(ROOT)} is current ({payload['required_gate_count']} gates)")
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)} ({payload['required_gate_count']} gates)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
