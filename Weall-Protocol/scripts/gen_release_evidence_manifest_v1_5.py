#!/usr/bin/env python3
from __future__ import annotations

"""Generate the v1.5 release evidence manifest.

The tracked manifest is deterministic and records which release evidence gates are
required before public beta. It deliberately does not embed the current git HEAD,
because a tracked artifact cannot stably contain the commit hash that contains
it. Use --runtime-json to emit a runtime manifest with the concrete HEAD, branch,
worktree status, and optional clean-gate report digest for an exported release.
"""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "generated" / "release_evidence_manifest_v1_5.json"
Json = dict[str, Any]

_TRACKED_ARTIFACTS = [
    "generated/api_contract_map_v1_5.json",
    "generated/failure_code_registry_v1_5.json",
    "generated/public_only_protocol_audit_v1_5.json",
    "generated/api_response_vectors_v1_5.json",
    "generated/state_root_vectors_v1_5.json",
    "generated/tokenomics_simulation_v1_5.json",
    "generated/public_validator_bft_preflight_matrix_v1_5.json",
    "generated/b582_b586_readiness_truth_and_proof_v1_5.json",
    "generated/b587_b594_testnet_mechanism_completion_v1_5.json",
    "generated/external_operator_transcript_requirements_v1_5.json",
    "generated/public_observer_launch_evidence_requirements_v1_5.json",
    "generated/public_discovery_provider_independence_v1_5.json",
    "generated/public_seed_registry_signature_verification_v1_5.json",
    "generated/public_observer_clean_clone_bootstrap_transcript_v1_5.json",
    "generated/public_observer_auto_discovery_proof_v1_5.json",
    "generated/public_observer_state_sync_trusted_anchor_proof_v1_5.json",
    "generated/public_validator_endpoint_churn_proof_v1_5.json",
    "generated/public_frontend_operator_journey_v1_5.json",
    "generated/public_registry_signer_operations_v1_5.json",
]


def _canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _pretty(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, indent=2) + "\n"


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    try:
        return _sha256_bytes(path.read_bytes())
    except Exception:
        return ""


def _load_json(rel: str) -> Json:
    try:
        value = json.loads((ROOT / rel).read_text(encoding="utf-8"))
    except Exception:
        return {}
    return value if isinstance(value, dict) else {}


def _artifact(rel: str) -> Json:
    payload = _load_json(rel)
    return {
        "path": rel,
        "present": bool(payload),
        "schema": str(payload.get("schema") or "") if payload else "",
        "ok": bool(payload.get("ok", True)) if payload else False,
        "file_sha256": _sha256_file(ROOT / rel),
    }


def _run_git(args: list[str]) -> str:
    proc = subprocess.run(["git", *args], cwd=ROOT.parent, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)
    return proc.stdout.strip() if proc.returncode == 0 else ""


def build() -> Json:
    artifacts = {rel: _artifact(rel) for rel in _TRACKED_ARTIFACTS}
    all_artifacts_ok = all(item["present"] and item["ok"] and item["file_sha256"] for item in artifacts.values())
    return {
        "schema": "weall.v1_5.release_evidence_manifest",
        "version": "2026-06-b621-release-evidence-hardening",
        "ok": all_artifacts_ok,
        "public_beta_ready": False,
        "mainnet_ready": False,
        "controlled_testnet_candidate": True,
        "tracked_manifest_is_commit_agnostic": True,
        "runtime_commit_binding_required": True,
        "why_commit_head_is_not_tracked_here": "A generated file cannot stably contain the commit hash of the commit that contains it; concrete HEAD binding is emitted by --runtime-json and clean-clone gate reports.",
        "tracked_artifacts": artifacts,
        "recursive_release_artifacts_checked_by_go_gate_but_not_hashed_here": [
            "generated/controlled_testnet_go_gate_v1_5.json",
            "generated/public_beta_blocker_report_v1_5.json",
            "generated/release_evidence_manifest_v1_5.json"
        ],
        "release_evidence_gates": {
            "clean_clone_go_gate": {
                "required_before_public_beta": True,
                "script": "scripts/run_clean_clone_go_gate_v1_5.sh",
                "runtime_report_required": True,
                "tracked_manifest_only": True,
            },
            "public_observer_open_download_transcript": {
                "required_before_public_observer_launch": True,
                "requirements_artifact": "generated/public_observer_launch_evidence_requirements_v1_5.json",
                "runtime_report_required": True,
                "validator": "PYTHONPATH=src:scripts python scripts/gen_public_observer_launch_evidence_requirements_v1_5.py --check && PYTHONPATH=src:scripts python scripts/gen_public_discovery_provider_independence_v1_5.py --check && PYTHONPATH=src:scripts python scripts/gen_public_observer_launch_transcript_v1_5.py --check",
                "tracked_static_artifacts": [
                    "generated/public_seed_registry_signature_verification_v1_5.json",
                    "generated/public_observer_clean_clone_bootstrap_transcript_v1_5.json",
                    "generated/public_observer_auto_discovery_proof_v1_5.json",
                    "generated/public_observer_state_sync_trusted_anchor_proof_v1_5.json"
                ],
            },
            "public_validator_endpoint_churn_proof": {
                "required_before_public_observer_launch": True,
                "runtime_report_required": True,
                "validator": "PYTHONPATH=src:scripts python scripts/gen_public_validator_endpoint_churn_proof_v1_5.py --check",
            },
            "public_frontend_operator_journey": {
                "required_before_public_observer_launch": True,
                "runtime_report_required": True,
                "validator": "PYTHONPATH=src:scripts python scripts/gen_public_frontend_operator_journey_v1_5.py --check && cd web && npm run test:public-observer-rendered",
            },
            "public_registry_signer_operations": {
                "required_before_public_observer_launch": True,
                "runtime_report_required": False,
                "validator": "PYTHONPATH=src:scripts python scripts/gen_public_registry_signer_operations_v1_5.py --check",
            },
            "external_validator_operator_transcript": {
                "required_before_public_beta": True,
                "required_before_controlled_validator_rehearsal_claim": True,
                "blocker": "AUD-618-P0-001",
                "capture_script": "scripts/capture_independent_controlled_validator_operator_transcript_v1_5.sh",
                "template": "docs/proofs/independent-controlled-validator-operator/2026-07-05/TRANSCRIPT_TEMPLATE.json",
                "validator": "PYTHONPATH=src:scripts python scripts/validate_external_operator_transcript_v1_5.py --kind public_validator_operator_transcript --strict-release --path <transcript.json>",
                "sample_transcripts_are_rejected_in_strict_release": True,
            },
            "external_cross_machine_replay_transcript": {
                "required_before_public_beta": True,
                "required_before_public_observer_launch": True,
                "blocker": "AUD-618-P1-003",
                "capture_script": "scripts/capture_external_cross_machine_replay_transcript_v1_5.sh",
                "template": "docs/proofs/external-cross-machine-replay/2026-07-05/TRANSCRIPT_TEMPLATE.json",
                "validator": "PYTHONPATH=src:scripts python scripts/validate_external_operator_transcript_v1_5.py --kind external_cross_machine_replay_transcript --strict-release --path <transcript.json>",
                "sample_transcripts_are_rejected_in_strict_release": True,
            },
            "storage_ipfs_operator_transcript": {
                "required_before_public_beta": True,
                "required_before_public_storage_claims": True,
                "blocker": "AUD-618-P1-004",
                "capture_script": "scripts/capture_real_storage_ipfs_operator_transcript_v1_5.sh",
                "template": "docs/proofs/real-storage-ipfs-operator/2026-07-05/TRANSCRIPT_TEMPLATE.json",
                "validator": "PYTHONPATH=src:scripts python scripts/validate_external_operator_transcript_v1_5.py --kind storage_ipfs_operator_transcript --strict-release --path <transcript.json>",
                "sample_transcripts_are_rejected_in_strict_release": True,
            },
            "legal_compliance_attestation": {
                "required_before_public_beta": True,
                "validator": "PYTHONPATH=src:scripts python scripts/validate_external_operator_transcript_v1_5.py --kind legal_compliance_attestation --strict-release --path <attestation.json>",
                "counsel_or_control_attestation_required": True,
            },
            "rendered_operator_journey": {
                "required_before_public_beta": True,
                "required_before_public_observer_launch": True,
                "command": "cd web && npm run test:rendered-operator-journey",
                "clean_gate_default": "reported_not_run_unless_--run-rendered-frontend_or_WEALL_RUN_RENDERED_FRONTEND=1",
            },
        },
        "claim_boundaries": {
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
        "artifact_digest": hashlib.sha256(_canon({"artifacts": artifacts, "version": "2026-06-b621-release-evidence-hardening"}).encode("utf-8")).hexdigest(),
    }


def build_runtime(clean_gate_report: Path | None = None) -> Json:
    payload = build()
    status = _run_git(["status", "--short", "--untracked-files=all"])
    runtime: Json = {
        **payload,
        "schema": "weall.v1_5.release_evidence_runtime_manifest",
        "git_head": _run_git(["rev-parse", "HEAD"]),
        "git_branch": _run_git(["branch", "--show-current"]),
        "latest_commit": _run_git(["log", "--oneline", "-1"]),
        "git_status_short": status,
        "worktree_clean": status == "",
        "runtime_manifest_not_for_tracked_artifact_check": True,
    }
    if clean_gate_report is not None:
        runtime["clean_gate_report_path"] = str(clean_gate_report)
        runtime["clean_gate_report_sha256"] = _sha256_file(clean_gate_report)
    return runtime


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate/check v1.5 release evidence manifest.")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--runtime-json", action="store_true", help="emit concrete git HEAD/worktree/runtime metadata; not suitable as tracked artifact")
    parser.add_argument("--clean-gate-report", help="optional clean-gate report file to digest in --runtime-json")
    args = parser.parse_args()
    if args.runtime_json:
        report = Path(args.clean_gate_report).resolve() if args.clean_gate_report else None
        print(_pretty(build_runtime(report)), end="")
        return 0
    payload = build()
    text = _pretty(payload)
    if args.json:
        print(text, end="")
        return 0 if payload.get("ok") else 1
    if args.check:
        if not OUT.exists() or OUT.read_text(encoding="utf-8") != text:
            raise SystemExit("release_evidence_manifest_v1_5.json is stale; rerun generator")
        print(f"OK: {OUT.relative_to(ROOT)} is current ({len(payload['tracked_artifacts'])} artifacts)")
        return 0 if payload.get("ok") else 1
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)} ({len(payload['tracked_artifacts'])} artifacts)")
    return 0 if payload.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
