#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from gen_api_response_vectors_v1_5 import build as build_api_response_vectors
from gen_public_beta_blocker_report_v1_5 import build as build_public_beta_blocker_report
from gen_external_operator_transcript_requirements_v1_5 import build as build_external_operator_transcript_requirements
from gen_release_evidence_manifest_v1_5 import build as build_release_evidence_manifest
from gen_b587_b594_testnet_mechanism_completion_v1_5 import build as build_b587_b594
from rehearse_external_multimachine_validator_harness_b590_v1_5 import run_harness as run_validator_harness
from rehearse_multimachine_storage_ipfs_durability_b591_v1_5 import run_harness as run_storage_harness
from weall.runtime.testnet_capabilities import build_testnet_capability_surface

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "generated" / "controlled_testnet_go_gate_v1_5.json"
RUNTIME_OUT = ROOT / "generated" / "controlled_testnet_go_gate_runtime_v1_5.json"
Json = dict[str, Any]


_REQUIRED_TRACKED_ARTIFACTS = [
    "generated/api_contract_map_v1_5.json",
    "generated/launch_disabled_matrix_v1_5.json",
    "generated/v15_implementation_gap_register.json",
    "generated/state_root_vectors_v1_5.json",
    "generated/tokenomics_simulation_v1_5.json",
    "generated/failure_code_registry_v1_5.json",
    "generated/public_validator_bft_preflight_matrix_v1_5.json",
    "generated/api_response_vectors_v1_5.json",
    "generated/b582_b586_readiness_truth_and_proof_v1_5.json",
    "generated/b587_b594_testnet_mechanism_completion_v1_5.json",
    "generated/controlled_testnet_go_gate_v1_5.json",
    "generated/public_beta_blocker_report_v1_5.json",
    "generated/external_operator_transcript_requirements_v1_5.json",
    "generated/release_evidence_manifest_v1_5.json",
]

_CHECK_COMMANDS = [
    ["python", "scripts/gen_api_contract_map.py", "--check"],
    ["python", "scripts/gen_failure_code_registry_v1_5.py", "--check"],
    ["python", "scripts/gen_api_response_vectors_v1_5.py", "--check"],
    ["python", "scripts/gen_state_root_vectors_v1_5.py", "--check"],
    ["python", "scripts/gen_tokenomics_simulation_v1_5.py", "--check"],
    ["python", "scripts/gen_public_validator_bft_preflight_matrix_v1_5.py", "--check"],
    ["python", "scripts/gen_b582_b586_readiness_truth_and_proof_v1_5.py", "--check"],
    ["python", "scripts/gen_b587_b594_testnet_mechanism_completion_v1_5.py", "--check"],
    ["python", "scripts/gen_public_beta_blocker_report_v1_5.py", "--check"],
    ["python", "scripts/gen_external_operator_transcript_requirements_v1_5.py", "--check"],
    ["python", "scripts/gen_release_evidence_manifest_v1_5.py", "--check"],
]

_FORBIDDEN_CLAIMS = {
    "automatic_protocol_upgrades": False,
    "complete_anti_sybil_resistance": False,
    "legal_compliance_ready": False,
    "live_economics": False,
    "mainnet_readiness": False,
    "production_helper_execution": False,
    "public_beta_readiness": False,
    "public_decentralized_media_durability": False,
    "public_multi_validator_bft": False,
    "public_storage_provider_market": False,
    "public_validator_readiness": False,
    "protocol_private_activity": False,
}


def _load_json(rel: str) -> Json:
    path = ROOT / rel
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return value if isinstance(value, dict) else {}


def _artifact_summary(rel: str) -> Json:
    payload = _load_json(rel)
    return {
        "path": rel,
        "present": bool(payload),
        "schema": str(payload.get("schema") or "") if payload else "",
        "ok": bool(payload.get("ok", True)) if payload else False,
    }


def _summarize_b587(payload: Json) -> Json:
    boundaries = payload.get("claim_boundaries") if isinstance(payload.get("claim_boundaries"), dict) else {}
    return {
        "present": bool(payload),
        "ok": bool(payload.get("ok")),
        "controlled_testnet_mechanisms_complete": bool(payload.get("controlled_testnet_mechanisms_complete")),
        "controlled_testnet_ready_candidate": bool(payload.get("controlled_testnet_ready_candidate")),
        "public_beta_ready": bool(payload.get("public_beta_ready")),
        "unsafe_claims_false": all(boundaries.get(k, False) is False for k in (
            "live_economics",
            "public_validator_readiness",
            "production_helper_execution",
            "automatic_protocol_upgrades",
        )),
    }


def build() -> Json:
    b587 = build_b587_b594()
    api_vectors = build_api_response_vectors()
    public_beta_blockers = build_public_beta_blocker_report()
    external_transcripts = build_external_operator_transcript_requirements()
    release_evidence = build_release_evidence_manifest()
    capabilities = build_testnet_capability_surface({"params": {"launch_phase": "public_beta_candidate"}})
    validator = run_validator_harness()
    storage = run_storage_harness()

    artifact_summaries = {rel: _artifact_summary(rel) for rel in _REQUIRED_TRACKED_ARTIFACTS if rel != OUT.relative_to(ROOT).as_posix()}
    high_risk_blocked = all(
        capabilities.get("capabilities", {}).get(key, {}).get("enabled") is False
        for key in (
            "live_transfers",
            "live_rewards",
            "treasury_spend",
            "live_economics",
            "public_validator_join",
            "public_multi_validator_bft",
            "automatic_protocol_upgrade_apply",
            "production_helper_execution",
        )
    )
    deterministic_go_gate_ready = all([
        bool(api_vectors.get("ok")),
        bool(public_beta_blockers.get("ok")),
        bool(external_transcripts.get("ok")),
        bool(release_evidence.get("ok")),
        bool(b587.get("ok")),
        bool(capabilities.get("controlled_testnet_mechanisms_complete")),
        bool(validator.get("ok")),
        bool(storage.get("ok")),
        high_risk_blocked,
    ])

    return {
        "schema": "weall.v1_5.controlled_testnet_go_gate",
        "batch": "595",
        "ok": deterministic_go_gate_ready,
        "controlled_testnet_go_gate_ready_to_run": deterministic_go_gate_ready,
        "controlled_private_testnet_candidate": deterministic_go_gate_ready,
        "controlled_testnet_ready_claimed_by_repo": False,
        "public_beta_ready": False,
        "public_readiness_claim_requires_external_evidence": True,
        "deterministic_tracked_manifest": True,
        "artifact_inputs": artifact_summaries,
        "b587_b594_mechanism_completion_summary": _summarize_b587(b587),
        "api_response_vector_summary": {
            "ok": bool(api_vectors.get("ok")),
            "vector_count": int(api_vectors.get("vector_count") or 0),
            "truth_boundaries": api_vectors.get("truth_boundaries", {}),
        },

        "public_beta_blocker_report_summary": {
            "ok": bool(public_beta_blockers.get("ok")),
            "public_beta_ready": bool(public_beta_blockers.get("public_beta_ready")),
            "mainnet_ready": bool(public_beta_blockers.get("mainnet_ready")),
            "blocker_count": int(public_beta_blockers.get("blocker_count") or 0),
            "remaining_blocker_count": int(public_beta_blockers.get("remaining_blocker_count") or 0),
            "next_allowed_claim": public_beta_blockers.get("next_allowed_claim"),
        },
        "external_operator_transcript_requirements_summary": {
            "ok": bool(external_transcripts.get("ok")),
            "schema_count": len(external_transcripts.get("schemas") or {}),
            "public_beta_ready": bool(external_transcripts.get("public_beta_ready")),
            "mainnet_ready": bool(external_transcripts.get("mainnet_ready")),
            "external_attestation_required_before_public_beta": bool(external_transcripts.get("external_attestation_required_before_public_beta")),
        },
        "release_evidence_manifest_summary": {
            "ok": bool(release_evidence.get("ok")),
            "schema": release_evidence.get("schema"),
            "public_beta_ready": bool(release_evidence.get("public_beta_ready")),
            "mainnet_ready": bool(release_evidence.get("mainnet_ready")),
            "runtime_commit_binding_required": bool(release_evidence.get("runtime_commit_binding_required")),
            "tracked_manifest_is_commit_agnostic": bool(release_evidence.get("tracked_manifest_is_commit_agnostic")),
        },
        "launch_matrix_capability_snapshot": {
            "phase": capabilities.get("phase"),
            "blocked_capabilities": capabilities.get("blocked_capabilities", []),
            "artifact_blockers": capabilities.get("artifact_blockers", []),
            "truth_boundaries": capabilities.get("truth_boundaries", {}),
        },
        "validator_go_gate_snapshot": {
            "ok": bool(validator.get("ok")),
            "node_count": validator.get("node_count"),
            "machine_count": validator.get("machine_count"),
            "threshold": validator.get("threshold"),
            "partition_rejoin_exercised": validator.get("partition_rejoin_exercised"),
            "minority_partition_cannot_finalize": validator.get("minority_partition_cannot_finalize"),
            "fresh_node_catchup_exercised": validator.get("fresh_node_catchup_exercised"),
            "equivocation_rejected": validator.get("equivocation_rejected"),
            "observer_vote_rejected": validator.get("observer_vote_rejected"),
            "state_roots_match": validator.get("state_roots_match"),
            "transcript_digest": validator.get("transcript_digest"),
            "requires_independent_operator_run": validator.get("requires_independent_operator_run"),
            "public_validator_readiness_claimed": validator.get("public_validator_readiness_claimed"),
        },
        "storage_go_gate_snapshot": {
            "ok": bool(storage.get("ok")),
            "machine_count": storage.get("machine_count"),
            "origin_failure_exercised": storage.get("origin_failure_exercised"),
            "replication_factor_after_reassignment": storage.get("replication_factor_after_reassignment"),
            "retrieval_from_non_origin_machine": storage.get("retrieval_from_non_origin_machine"),
            "fresh_node_retrieval_path_exercised": storage.get("fresh_node_retrieval_path_exercised"),
            "wrong_cid_rejected": storage.get("wrong_cid_rejected"),
            "corrupt_content_rejected_by_hash": storage.get("corrupt_content_rejected_by_hash"),
            "requires_real_operator_rehearsal": storage.get("requires_real_operator_rehearsal"),
            "public_decentralized_media_durability_claimed": storage.get("public_decentralized_media_durability_claimed"),
        },
        "required_manual_or_runtime_evidence_before_public_beta": [
            "full pytest suite output from repo virtualenv",
            "artifact freshness gate with --require-git-tracked inside the real git checkout",
            "validator go-gate transcript from independently operated machines or isolated containers",
            "storage/IPFS durability transcript from real daemon/operator topology",
            "public-beta blocker report with transcript schemas and claim boundaries",
            "external operator transcript requirements artifact and validator",
            "release evidence manifest with runtime commit binding report",
            "frontend/API capability snapshot showing launch-matrix blockers in public UX surfaces",
            "legal/compliance counsel review before public token/governance/economic claims",
        ],
        "recommended_gate_commands": [
            "PYTHONPATH=src:scripts python scripts/run_controlled_testnet_go_gate_v1_5.py --run-gates --require-git-tracked",
            "PYTHONPATH=src:scripts python -m pytest -q",
            "PYTHONPATH=src:scripts python scripts/check_v15_public_readiness_artifacts.py --require-git-tracked",
        ],
        "artifact_freshness_commands": [" ".join(cmd) for cmd in _CHECK_COMMANDS],
        "claim_boundaries": dict(_FORBIDDEN_CLAIMS),
        "next_allowed_claim_if_runtime_go_gate_passes": "controlled private testnet candidate evidence captured",
        "claims_still_forbidden_after_this_gate": [key for key, enabled in _FORBIDDEN_CLAIMS.items() if enabled is False],
    }


def _canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, indent=2) + "\n"


def _read_tail(path: Path, limit: int = 2000) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")[-limit:]
    except Exception:
        return ""


def _run(cmd: list[str]) -> Json:
    normalized = [sys.executable if part == "python" else part for part in cmd]
    # Use temporary files instead of subprocess.PIPE. Some rehearsal checks spawn
    # short-lived grandchildren; if a grandchild inherits a pipe, communicate()
    # can wait for EOF after the direct child has exited. File redirection keeps
    # the go-gate deterministic and prevents clean-clone evidence runs from
    # hanging on inherited descriptors.
    with tempfile.TemporaryDirectory(prefix="weall_gate_cmd_") as tmp:
        stdout_path = Path(tmp) / "stdout.txt"
        stderr_path = Path(tmp) / "stderr.txt"
        with stdout_path.open("w", encoding="utf-8") as stdout, stderr_path.open("w", encoding="utf-8") as stderr:
            proc = subprocess.run(normalized, cwd=ROOT, text=True, stdout=stdout, stderr=stderr, check=False)
        return {
            "cmd": " ".join(cmd),
            "returncode": proc.returncode,
            "ok": proc.returncode == 0,
            "stdout_tail": _read_tail(stdout_path),
            "stderr_tail": _read_tail(stderr_path),
        }


def _check_required_tracked_artifacts() -> Json:
    missing: list[str] = []
    for rel in _REQUIRED_TRACKED_ARTIFACTS:
        proc = subprocess.run(
            ["git", "ls-files", "--error-unmatch", rel],
            cwd=ROOT,
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            check=False,
        )
        if proc.returncode != 0:
            missing.append(rel)
    return {
        "cmd": "embedded required tracked artifact check",
        "returncode": 0 if not missing else 1,
        "ok": not missing,
        "stdout_tail": "all required release artifacts are tracked/staged in git index" if not missing else "",
        "stderr_tail": "" if not missing else "missing tracked artifacts: " + ", ".join(missing),
    }


def run_runtime_gates(*, require_git_tracked: bool = False, include_full_pytest: bool = False) -> Json:
    commands = list(_CHECK_COMMANDS)
    if not require_git_tracked:
        commands = [cmd if cmd[1] != "scripts/check_v15_public_readiness_artifacts.py" else ["python", "scripts/check_v15_public_readiness_artifacts.py"] for cmd in commands]
    if include_full_pytest:
        commands.append(["python", "-m", "pytest", "-q"])
    results = [_run(cmd) for cmd in commands]
    if require_git_tracked:
        results.append(_check_required_tracked_artifacts())
    payload = {
        "schema": "weall.v1_5.controlled_testnet_go_gate_runtime_report",
        "ok": all(bool(r["ok"]) for r in results),
        "include_full_pytest": include_full_pytest,
        "require_git_tracked": require_git_tracked,
        "results": results,
        "tracked_manifest": build(),
    }
    RUNTIME_OUT.parent.mkdir(parents=True, exist_ok=True)
    RUNTIME_OUT.write_text(_canon(payload), encoding="utf-8")
    return payload


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate/check/run the v1.5 controlled-testnet go-gate evidence manifest.")
    ap.add_argument("--check", action="store_true", help="check the tracked deterministic manifest is fresh")
    ap.add_argument("--run-gates", action="store_true", help="run readiness gates and write a local runtime report")
    ap.add_argument("--require-git-tracked", action="store_true", help="when running gates, require release artifacts to be tracked in git")
    ap.add_argument("--include-full-pytest", action="store_true", help="when running gates, include the full pytest suite")
    args = ap.parse_args()

    if args.run_gates:
        report = run_runtime_gates(require_git_tracked=args.require_git_tracked, include_full_pytest=args.include_full_pytest)
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report.get("ok") else 1

    payload = build()
    text = _canon(payload)
    if args.check:
        if not OUT.exists() or OUT.read_text(encoding="utf-8") != text:
            raise SystemExit("controlled_testnet_go_gate_v1_5.json is stale; rerun scripts/run_controlled_testnet_go_gate_v1_5.py")
        print(f"OK: {OUT.relative_to(ROOT)} is fresh")
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text, encoding="utf-8")
    print(str(OUT))
    return 0 if payload.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
