#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

RELEASE_ARTIFACTS = [
    Path("generated/api_contract_map_v1_5.json"),
    Path("generated/launch_disabled_matrix_v1_5.json"),
    Path("generated/v15_implementation_gap_register.json"),
    Path("generated/state_root_vectors_v1_5.json"),
    Path("generated/tokenomics_simulation_v1_5.json"),
    Path("generated/failure_code_registry_v1_5.json"),
    Path("generated/public_validator_bft_preflight_matrix_v1_5.json"),
    Path("generated/api_response_vectors_v1_5.json"),
    Path("generated/b587_b594_testnet_mechanism_completion_v1_5.json"),
    Path("generated/controlled_testnet_go_gate_v1_5.json"),
    Path("generated/public_beta_blocker_report_v1_5.json"),
    Path("generated/public_only_protocol_audit_v1_5.json"),
    Path("generated/public_discovery_provider_independence_v1_5.json"),
    Path("generated/external_operator_transcript_requirements_v1_5.json"),
    Path("generated/public_observer_launch_evidence_requirements_v1_5.json"),
    Path("generated/public_seed_registry_signature_verification_v1_5.json"),
    Path("generated/public_observer_clean_clone_bootstrap_transcript_v1_5.json"),
    Path("generated/public_observer_auto_discovery_proof_v1_5.json"),
    Path("generated/public_observer_state_sync_trusted_anchor_proof_v1_5.json"),
    Path("generated/public_validator_endpoint_churn_proof_v1_5.json"),
    Path("generated/public_frontend_operator_journey_v1_5.json"),
    Path("generated/public_registry_signer_operations_v1_5.json"),
    Path("generated/protocol_upgrade_execution_hardening_plan_v1_5.json"),
    Path("generated/release_evidence_manifest_v1_5.json"),
    Path("generated/reputation_event_registry_v1_5.json"),
    Path("generated/reputation_matrix_contract_v1_5.json"),
    Path("generated/reputation_flow_coverage_map_v1_5.json"),
    Path("generated/reputation_invariant_report_v1_5.json"),
    Path("generated/reputation_api_contract_map_v1_5.json"),
]
GITIGNORE_EXCEPTIONS = [f"!{path.as_posix()}" for path in RELEASE_ARTIFACTS]


def _load_json(rel: Path) -> dict:
    path = ROOT / rel
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SystemExit(f"invalid json artifact {rel}: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"json artifact root must be an object: {rel}")
    return value


def _check_gitignore() -> list[str]:
    errors: list[str] = []
    text = (ROOT / ".gitignore").read_text(encoding="utf-8")
    for line in GITIGNORE_EXCEPTIONS:
        if line not in text.splitlines():
            errors.append(f"missing .gitignore exception: {line}")
    return errors


def _check_api_contract() -> list[str]:
    errors: list[str] = []
    from gen_api_contract_map import build_payload as build_api_contract_map

    payload = _load_json(Path("generated/api_contract_map_v1_5.json"))
    if payload != build_api_contract_map():
        errors.append("api_contract_map_v1_5.json is stale; rerun generator")
    if payload.get("schema") != "weall.api_contract_map.v1_5":
        errors.append("api contract map schema mismatch")
    routes = payload.get("routes")
    if not isinstance(routes, list) or len(routes) < 120:
        errors.append("api contract map route list missing or unexpectedly small")
    return errors


def _check_launch_matrix() -> list[str]:
    errors: list[str] = []
    from weall.runtime.launch_matrix import launch_matrix_payload

    artifact = _load_json(Path("generated/launch_disabled_matrix_v1_5.json"))
    runtime = launch_matrix_payload()
    if artifact != runtime:
        errors.append("launch_disabled_matrix_v1_5.json is stale; regenerate from weall.runtime.launch_matrix.launch_matrix_payload()")
    return errors


def _read_tail(path: Path, limit: int = 4000) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")[-limit:]
    except Exception:
        return ""


def _run_check(script: str) -> list[str]:
    # Use files instead of PIPE so short-lived generator grandchildren cannot
    # inherit a pipe and keep communicate() waiting for EOF after the direct
    # child exits. This mirrors the controlled go-gate subprocess policy.
    with tempfile.TemporaryDirectory(prefix="weall_v15_check_") as tmp:
        stdout_path = Path(tmp) / "stdout.txt"
        stderr_path = Path(tmp) / "stderr.txt"
        with stdout_path.open("w", encoding="utf-8") as stdout, stderr_path.open("w", encoding="utf-8") as stderr:
            result = subprocess.run(
                [sys.executable, f"scripts/{script}", "--check"],
                cwd=ROOT,
                text=True,
                stdout=stdout,
                stderr=stderr,
                check=False,
                timeout=180,
            )
        if result.returncode != 0:
            return [(_read_tail(stdout_path) + _read_tail(stderr_path)).strip() or f"{script} check failed"]
    return []


def _check_gap_register() -> list[str]:
    errors: list[str] = []
    payload = _load_json(Path("generated/v15_implementation_gap_register.json"))
    if payload.get("schema") != "weall.v15_implementation_gap_register":
        errors.append("v15 implementation gap register schema mismatch")
    for key in ("resolved_since_prior_evidence_map", "remaining_p0_p1_gaps"):
        if not isinstance(payload.get(key), list) or not payload.get(key):
            errors.append(f"v15 gap register missing non-empty {key}")
    return errors




def _check_state_root_vectors() -> list[str]:
    errors: list[str] = []
    from gen_state_root_vectors_v1_5 import build_payload as build_state_root_vectors

    payload = _load_json(Path("generated/state_root_vectors_v1_5.json"))
    if payload != build_state_root_vectors():
        errors.append("state_root_vectors_v1_5.json is stale; rerun generator")
    if payload.get("schema") != "weall.v1_5.state_root_vectors":
        errors.append("state root vectors schema mismatch")
    vectors = payload.get("vectors")
    if not isinstance(vectors, list) or len(vectors) < 8:
        errors.append("state root vector pack missing expanded domain fixtures")
    return errors


def _check_tokenomics_simulation() -> list[str]:
    errors: list[str] = []
    from gen_tokenomics_simulation_v1_5 import build_payload as build_tokenomics_simulation

    payload = _load_json(Path("generated/tokenomics_simulation_v1_5.json"))
    if payload != build_tokenomics_simulation():
        errors.append("tokenomics_simulation_v1_5.json is stale; rerun generator")
    if payload.get("schema") != "weall.v1_5.tokenomics_simulation":
        errors.append("tokenomics simulation schema mismatch")
    boundaries = payload.get("truth_boundaries") if isinstance(payload.get("truth_boundaries"), dict) else {}
    if boundaries.get("live_economics_enabled") is not False:
        errors.append("tokenomics simulation must preserve live_economics_enabled=false")
    if not isinstance(payload.get("activation_blockade_checklist"), list) or not payload.get("activation_blockade_checklist"):
        errors.append("tokenomics simulation missing activation blockade checklist")
    return errors


def _check_failure_code_registry() -> list[str]:
    errors: list[str] = []
    from gen_failure_code_registry_v1_5 import build_payload as build_failure_code_registry

    payload = _load_json(Path("generated/failure_code_registry_v1_5.json"))
    if payload != build_failure_code_registry():
        errors.append("failure_code_registry_v1_5.json is stale; rerun generator")
    if payload.get("schema") != "weall.v1_5.failure_code_registry":
        errors.append("failure-code registry schema mismatch")
    if int(payload.get("unique_code_count") or 0) < 20:
        errors.append("failure-code registry unexpectedly small")
    return errors



def _check_api_response_vectors() -> list[str]:
    errors: list[str] = []
    from gen_api_response_vectors_v1_5 import build as build_api_response_vectors

    payload = _load_json(Path("generated/api_response_vectors_v1_5.json"))
    if payload != build_api_response_vectors():
        errors.append("api_response_vectors_v1_5.json is stale; rerun generator")
    if payload.get("schema") != "weall.v1_5.api_response_vectors":
        errors.append("api response vector schema mismatch")
    if int(payload.get("vector_count") or 0) < 8:
        errors.append("api response vector pack unexpectedly small")
    boundaries = payload.get("truth_boundaries") if isinstance(payload.get("truth_boundaries"), dict) else {}
    if boundaries.get("public_beta_ready") is not False:
        errors.append("api response vectors must not claim public beta readiness")
    return errors


def _check_b587_b594_mechanisms() -> list[str]:
    errors: list[str] = []
    from gen_b587_b594_testnet_mechanism_completion_v1_5 import build as build_b587_b594_mechanisms

    payload = _load_json(Path("generated/b587_b594_testnet_mechanism_completion_v1_5.json"))
    if payload != build_b587_b594_mechanisms():
        errors.append("b587_b594_testnet_mechanism_completion_v1_5.json is stale; rerun generator")
    if payload.get("schema") != "weall.v1_5.batch587_594.testnet_mechanism_completion":
        errors.append("B587-B594 mechanism artifact schema mismatch")
    if payload.get("controlled_testnet_mechanisms_complete") is not True:
        errors.append("B587-B594 artifact must complete controlled testnet mechanisms")
    if payload.get("public_beta_ready") is not False:
        errors.append("B587-B594 artifact must not claim public beta readiness")
    boundaries = payload.get("claim_boundaries") if isinstance(payload.get("claim_boundaries"), dict) else {}
    for key in ("live_economics", "public_validator_readiness", "production_helper_execution", "automatic_protocol_upgrades"):
        if boundaries.get(key) is not False:
            errors.append(f"B587-B594 boundary must keep {key}=false")
    return errors


def _check_controlled_testnet_go_gate() -> list[str]:
    errors = _run_check("run_controlled_testnet_go_gate_v1_5.py")
    payload = _load_json(Path("generated/controlled_testnet_go_gate_v1_5.json"))
    if payload.get("schema") != "weall.v1_5.controlled_testnet_go_gate":
        errors.append("controlled testnet go-gate schema mismatch")
    if payload.get("controlled_testnet_go_gate_ready_to_run") is not True:
        errors.append("controlled testnet go-gate must be ready to run")
    if payload.get("public_beta_ready") is not False:
        errors.append("controlled testnet go-gate must not claim public beta readiness")
    boundaries = payload.get("claim_boundaries") if isinstance(payload.get("claim_boundaries"), dict) else {}
    for key in (
        "live_economics",
        "public_validator_readiness",
        "production_helper_execution",
        "automatic_protocol_upgrades",
        "legal_compliance_ready",
    ):
        if boundaries.get(key) is not False:
            errors.append(f"controlled testnet go-gate boundary must keep {key}=false")
    return errors

def _check_public_beta_blocker_report() -> list[str]:
    errors = _run_check("gen_public_beta_blocker_report_v1_5.py")
    payload = _load_json(Path("generated/public_beta_blocker_report_v1_5.json"))
    if payload.get("schema") != "weall.v1_5.public_beta_blocker_report":
        errors.append("public beta blocker report schema mismatch")
    if payload.get("public_beta_ready") is not False:
        errors.append("public beta blocker report must keep public_beta_ready=false")
    if payload.get("mainnet_ready") is not False:
        errors.append("public beta blocker report must keep mainnet_ready=false")
    if int(payload.get("blocker_count") or 0) < 12:
        errors.append("public beta blocker report missing expected blocker inventory")
    boundaries = payload.get("release_claim_boundaries") if isinstance(payload.get("release_claim_boundaries"), dict) else {}
    for key in (
        "public_validator_enabled",
        "production_helper_execution",
        "automatic_protocol_upgrades",
        "live_economics",
        "legal_compliance_ready",
    ):
        if boundaries.get(key) is not False:
            errors.append(f"public beta blocker report must keep {key}=false")
    return errors



def _check_public_only_protocol_audit() -> list[str]:
    errors: list[str] = []
    from gen_public_only_protocol_audit_v1_5 import build_payload as build_public_only_protocol_audit

    payload = _load_json(Path("generated/public_only_protocol_audit_v1_5.json"))
    if payload != build_public_only_protocol_audit():
        errors.append("public_only_protocol_audit_v1_5.json is stale; rerun generator")
    if payload.get("schema") != "weall.public_only_protocol_audit.v1_5":
        errors.append("public-only protocol audit schema mismatch")
    if payload.get("group_model", {}).get("read_visibility") != "public":
        errors.append("public-only audit must preserve public group read visibility")
    if payload.get("actionable_retired_communication_findings") != []:
        errors.append("public-only audit has actionable retired communication findings")
    return errors


def _check_public_discovery_provider_independence() -> list[str]:
    errors: list[str] = []
    from gen_public_discovery_provider_independence_v1_5 import build as build_public_discovery_provider_independence

    payload = _load_json(Path("generated/public_discovery_provider_independence_v1_5.json"))
    if payload != build_public_discovery_provider_independence():
        errors.append("public_discovery_provider_independence_v1_5.json is stale; rerun generator")
    if payload.get("schema") != "weall.v1_5.public_discovery_provider_independence":
        errors.append("public discovery provider independence schema mismatch")
    if payload.get("provider_authority") is not False:
        errors.append("public discovery provider independence must keep provider_authority=false")
    if payload.get("checked_in_registry_fallback") is not True:
        errors.append("public discovery provider independence must keep checked_in_registry_fallback=true")
    return errors

def _check_external_operator_transcript_requirements() -> list[str]:
    errors: list[str] = []
    from gen_external_operator_transcript_requirements_v1_5 import build as build_external_operator_transcript_requirements

    payload = _load_json(Path("generated/external_operator_transcript_requirements_v1_5.json"))
    expected = build_external_operator_transcript_requirements()
    if payload != expected:
        errors.append("external_operator_transcript_requirements_v1_5.json is stale; rerun generator")
    if payload.get("schema") != "weall.v1_5.external_operator_transcript_requirements":
        errors.append("external operator transcript requirements schema mismatch")
    if payload.get("public_beta_ready") is not False:
        errors.append("external operator transcript requirements must keep public_beta_ready=false")
    if payload.get("mainnet_ready") is not False:
        errors.append("external operator transcript requirements must keep mainnet_ready=false")
    schemas = payload.get("schemas") if isinstance(payload.get("schemas"), dict) else {}
    for key in ("public_validator_operator_transcript", "storage_ipfs_operator_transcript", "legal_compliance_attestation"):
        if key not in schemas:
            errors.append(f"external operator transcript requirements missing {key}")
    boundaries = payload.get("release_claim_boundaries") if isinstance(payload.get("release_claim_boundaries"), dict) else {}
    for key in ("public_validator_enabled", "public_storage_provider_market", "production_helper_execution", "automatic_protocol_upgrades", "live_economics", "legal_compliance_ready"):
        if boundaries.get(key) is not False:
            errors.append(f"external operator transcript requirements must keep {key}=false")
    return errors





def _check_public_observer_launch_evidence_requirements() -> list[str]:
    errors: list[str] = []
    from gen_public_observer_launch_evidence_requirements_v1_5 import build as build_public_observer_launch_evidence_requirements

    payload = _load_json(Path("generated/public_observer_launch_evidence_requirements_v1_5.json"))
    expected = build_public_observer_launch_evidence_requirements()
    if payload != expected:
        errors.append("public_observer_launch_evidence_requirements_v1_5.json is stale; rerun generator")
    if payload.get("schema") != "weall.v1_5.public_observer_launch_evidence_requirements":
        errors.append("public observer launch evidence requirements schema mismatch")
    if payload.get("public_observer_launch_ready") is not False:
        errors.append("public observer launch requirements must not claim launch readiness")
    if payload.get("public_beta_ready") is not False:
        errors.append("public observer launch requirements must keep public_beta_ready=false")
    gates = payload.get("gates") if isinstance(payload.get("gates"), list) else []
    if len(gates) < 5:
        errors.append("public observer launch requirements missing expected gates")
    boundaries = payload.get("claim_boundaries") if isinstance(payload.get("claim_boundaries"), dict) else {}
    for key in ("public_validator_enabled", "production_helper_execution", "live_economics", "legal_compliance_ready"):
        if boundaries.get(key) is not False:
            errors.append(f"public observer launch requirements must keep {key}=false")
    return errors



def _check_public_observer_launch_transcripts() -> list[str]:
    errors: list[str] = []
    from gen_public_observer_launch_transcript_v1_5 import _default_contracts as build_public_observer_launch_transcript_contracts

    contracts = build_public_observer_launch_transcript_contracts()
    expected_text = {
        Path("generated/public_seed_registry_signature_verification_v1_5.json"): contracts["registry"],
        Path("generated/public_observer_clean_clone_bootstrap_transcript_v1_5.json"): contracts["clean_clone"],
        Path("generated/public_observer_auto_discovery_proof_v1_5.json"): contracts["auto_discovery"],
        Path("generated/public_observer_state_sync_trusted_anchor_proof_v1_5.json"): contracts["state_sync"],
    }
    for rel, expected_payload in expected_text.items():
        if _load_json(rel) != expected_payload:
            errors.append(f"{rel.as_posix()} is stale; rerun generator")
    expected = {
        Path("generated/public_seed_registry_signature_verification_v1_5.json"): "weall.v1_5.public_seed_registry_signature_verification",
        Path("generated/public_observer_clean_clone_bootstrap_transcript_v1_5.json"): "weall.v1_5.public_observer_clean_clone_bootstrap_transcript",
        Path("generated/public_observer_auto_discovery_proof_v1_5.json"): "weall.v1_5.public_observer_auto_discovery_proof",
        Path("generated/public_observer_state_sync_trusted_anchor_proof_v1_5.json"): "weall.v1_5.public_observer_state_sync_trusted_anchor_proof",
    }
    for rel, schema in expected.items():
        payload = _load_json(rel)
        if payload.get("schema") != schema:
            errors.append(f"{rel.as_posix()} schema mismatch")
        if payload.get("public_observer_launch_ready") is not False:
            errors.append(f"{rel.as_posix()} must keep public_observer_launch_ready=false until runtime transcript is attached")
    return errors


def _check_public_validator_endpoint_churn_proof() -> list[str]:
    errors: list[str] = []
    from gen_public_validator_endpoint_churn_proof_v1_5 import build as build_public_validator_endpoint_churn_proof

    payload = _load_json(Path("generated/public_validator_endpoint_churn_proof_v1_5.json"))
    expected = build_public_validator_endpoint_churn_proof()
    if payload != expected:
        errors.append("public_validator_endpoint_churn_proof_v1_5.json is stale; rerun generator")
    if payload.get("schema") != "weall.v1_5.public_validator_endpoint_churn_proof":
        errors.append("public validator endpoint churn proof schema mismatch")
    if payload.get("public_observer_launch_ready") is not False:
        errors.append("public validator endpoint churn proof must keep launch readiness false until runtime transcript")
    checks = payload.get("source_checks") if isinstance(payload.get("source_checks"), dict) else {}
    if not checks or not all(bool(v) for v in checks.values()):
        errors.append("public validator endpoint churn proof source checks are not all satisfied")
    return errors


def _check_public_frontend_operator_journey() -> list[str]:
    errors: list[str] = []
    from gen_public_frontend_operator_journey_v1_5 import build as build_public_frontend_operator_journey

    payload = _load_json(Path("generated/public_frontend_operator_journey_v1_5.json"))
    expected = build_public_frontend_operator_journey()
    if payload != expected:
        errors.append("public_frontend_operator_journey_v1_5.json is stale; rerun generator")
    if payload.get("schema") != "weall.v1_5.public_frontend_operator_journey":
        errors.append("public frontend operator journey schema mismatch")
    if payload.get("public_observer_launch_ready") is not False:
        errors.append("public frontend operator journey must keep launch readiness false until rendered run")
    if payload.get("rendered_e2e_available") is not True:
        errors.append("public frontend operator journey must include a rendered e2e spec")
    return errors


def _check_public_registry_signer_operations() -> list[str]:
    errors: list[str] = []
    from gen_public_registry_signer_operations_v1_5 import build as build_public_registry_signer_operations

    payload = _load_json(Path("generated/public_registry_signer_operations_v1_5.json"))
    expected = build_public_registry_signer_operations()
    if payload != expected:
        errors.append("public_registry_signer_operations_v1_5.json is stale; rerun generator")
    if payload.get("schema") != "weall.v1_5.public_registry_signer_operations":
        errors.append("public registry signer operations schema mismatch")
    checks = payload.get("source_checks") if isinstance(payload.get("source_checks"), dict) else {}
    if not checks or not all(bool(v) for v in checks.values()):
        errors.append("public registry signer operations source checks are not all satisfied")
    return errors

def _check_protocol_upgrade_execution_hardening_plan() -> list[str]:
    errors: list[str] = []
    from gen_protocol_upgrade_execution_hardening_plan_v1_5 import build as build_upgrade_hardening_plan

    payload = _load_json(Path("generated/protocol_upgrade_execution_hardening_plan_v1_5.json"))
    expected = build_upgrade_hardening_plan()
    if payload != expected:
        errors.append("protocol_upgrade_execution_hardening_plan_v1_5.json is stale; rerun generator")
    if payload.get("schema") != "weall.v1_5.protocol_upgrade_execution_hardening_plan":
        errors.append("protocol upgrade execution hardening plan schema mismatch")
    if payload.get("blocker") != "AUD-618-P0-003":
        errors.append("protocol upgrade execution hardening plan must bind AUD-618-P0-003")
    if payload.get("execution_enabled") is not False:
        errors.append("protocol upgrade execution hardening plan must keep execution_enabled=false")
    if payload.get("automatic_protocol_upgrades_ready") is not False:
        errors.append("protocol upgrade execution hardening plan must keep automatic_protocol_upgrades_ready=false")
    boundaries = payload.get("claim_boundaries") if isinstance(payload.get("claim_boundaries"), dict) else {}
    for key in ("public_beta_ready", "mainnet_ready", "automatic_protocol_upgrades", "protocol_migrations", "protocol_rollbacks", "live_economics"):
        if boundaries.get(key) is not False:
            errors.append(f"protocol upgrade execution hardening plan must keep {key}=false")
    return errors

def _check_release_evidence_manifest() -> list[str]:
    errors: list[str] = []
    from gen_release_evidence_manifest_v1_5 import build as build_release_evidence_manifest

    payload = _load_json(Path("generated/release_evidence_manifest_v1_5.json"))
    expected = build_release_evidence_manifest()
    if payload != expected:
        errors.append("release_evidence_manifest_v1_5.json is stale; rerun generator")
    if payload.get("schema") != "weall.v1_5.release_evidence_manifest":
        errors.append("release evidence manifest schema mismatch")
    if payload.get("public_beta_ready") is not False:
        errors.append("release evidence manifest must keep public_beta_ready=false")
    if payload.get("mainnet_ready") is not False:
        errors.append("release evidence manifest must keep mainnet_ready=false")
    if payload.get("runtime_commit_binding_required") is not True:
        errors.append("release evidence manifest must require runtime commit binding")
    gates = payload.get("release_evidence_gates") if isinstance(payload.get("release_evidence_gates"), dict) else {}
    for key in ("clean_clone_go_gate", "external_validator_operator_transcript", "storage_ipfs_operator_transcript", "legal_compliance_attestation", "rendered_operator_journey"):
        if key not in gates:
            errors.append(f"release evidence manifest missing gate: {key}")
    boundaries = payload.get("claim_boundaries") if isinstance(payload.get("claim_boundaries"), dict) else {}
    for key in ("public_validator_enabled", "production_helper_execution", "automatic_protocol_upgrades", "live_economics", "legal_compliance_ready"):
        if boundaries.get(key) is not False:
            errors.append(f"release evidence manifest must keep {key}=false")
    return errors

def _check_public_validator_preflight() -> list[str]:
    errors: list[str] = []
    from gen_public_validator_bft_preflight_matrix_v1_5 import build_payload as build_public_validator_preflight

    payload = _load_json(Path("generated/public_validator_bft_preflight_matrix_v1_5.json"))
    if payload != build_public_validator_preflight():
        errors.append("public_validator_bft_preflight_matrix_v1_5.json is stale; rerun generator")
    if payload.get("schema") != "weall.v1_5.public_validator_bft_preflight_matrix":
        errors.append("public validator preflight matrix schema mismatch")
    boundaries = payload.get("truth_boundaries") if isinstance(payload.get("truth_boundaries"), dict) else {}
    if boundaries.get("public_validator_enabled") is not False:
        errors.append("public validator preflight must preserve public_validator_enabled=false")
    if boundaries.get("artifact_is_readiness_plan_not_proof") is not True:
        errors.append("public validator preflight must remain plan-not-proof")
    return errors




def _check_reputation_artifacts() -> list[str]:
    errors: list[str] = []
    from weall.runtime.reputation_events import (
        api_contract_payload,
        flow_coverage_payload,
        invariant_report_payload,
        matrix_contract_payload,
        registry_payload,
    )

    expected = {
        Path("generated/reputation_event_registry_v1_5.json"): registry_payload(),
        Path("generated/reputation_matrix_contract_v1_5.json"): matrix_contract_payload(),
        Path("generated/reputation_flow_coverage_map_v1_5.json"): flow_coverage_payload(),
        Path("generated/reputation_invariant_report_v1_5.json"): invariant_report_payload(),
        Path("generated/reputation_api_contract_map_v1_5.json"): api_contract_payload(),
    }
    for rel, payload in expected.items():
        expected_text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
        path = ROOT / rel
        if not path.is_file() or path.read_text(encoding="utf-8") != expected_text:
            errors.append(f"{rel.as_posix()} is stale; rerun generator")
    return errors

def _check_git_tracked() -> list[str]:
    errors: list[str] = []
    if not (ROOT / ".git").exists() and not (ROOT.parent / ".git").exists():
        return ["cannot verify git tracking because this checkout has no .git directory"]
    for rel in RELEASE_ARTIFACTS:
        result = subprocess.run(
            ["git", "ls-files", "--error-unmatch", rel.as_posix()],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            errors.append(f"release artifact is not tracked/staged in git index: {rel.as_posix()}")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check v1.5 public-readiness generated artifacts are release-safe and fresh.")
    parser.add_argument("--require-git-tracked", action="store_true", help="also require generated artifacts to already be tracked/staged in git")
    args = parser.parse_args(argv)

    errors: list[str] = []
    for rel in RELEASE_ARTIFACTS:
        if not (ROOT / rel).is_file():
            errors.append(f"missing release artifact: {rel.as_posix()}")
    errors.extend(_check_gitignore())
    if not errors:
        errors.extend(_check_api_contract())
        errors.extend(_check_launch_matrix())
        errors.extend(_check_gap_register())
        errors.extend(_check_state_root_vectors())
        errors.extend(_check_tokenomics_simulation())
        errors.extend(_check_failure_code_registry())
        errors.extend(_check_public_validator_preflight())
        errors.extend(_check_api_response_vectors())
        errors.extend(_check_b587_b594_mechanisms())
        errors.extend(_check_public_beta_blocker_report())
        errors.extend(_check_public_only_protocol_audit())
        errors.extend(_check_public_discovery_provider_independence())
        errors.extend(_check_external_operator_transcript_requirements())
        errors.extend(_check_public_observer_launch_evidence_requirements())
        errors.extend(_check_public_observer_launch_transcripts())
        errors.extend(_check_public_validator_endpoint_churn_proof())
        errors.extend(_check_public_frontend_operator_journey())
        errors.extend(_check_public_registry_signer_operations())
        errors.extend(_check_protocol_upgrade_execution_hardening_plan())
        errors.extend(_check_release_evidence_manifest())
        errors.extend(_check_controlled_testnet_go_gate())
        errors.extend(_check_reputation_artifacts())
    if args.require_git_tracked:
        errors.extend(_check_git_tracked())
    if errors:
        for err in errors:
            print(f"[v15-artifacts] FAIL: {err}", file=sys.stderr)
        return 1
    print("[v15-artifacts] OK: v1.5 public-readiness artifacts are present, fresh, and release-safe")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
