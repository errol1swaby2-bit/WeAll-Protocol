from __future__ import annotations

from typing import Any

Json = dict[str, Any]

EXPECTED_SCHEMAS = {
    "generated/api_contract_map_v1_5.json": "weall.api_contract_map.v1_5",
    "generated/api_response_vectors_v1_5.json": "weall.v1_5.api_response_vectors",
    "generated/b582_b586_readiness_truth_and_proof_v1_5.json": "weall.v1_5.batch582_586.readiness_truth_and_proof",
    "generated/b587_b594_testnet_mechanism_completion_v1_5.json": "weall.v1_5.batch587_594.testnet_mechanism_completion",
    "generated/crypto_inventory_v1_5.json": "weall.crypto_inventory.v1_5",
    "generated/external_operator_transcript_requirements_v1_5.json": "weall.v1_5.external_operator_transcript_requirements",
    "generated/failure_code_registry_v1_5.json": "weall.v1_5.failure_code_registry",
    "generated/final_public_observer_controlled_testnet_go_gate_v1_5.json": "weall.v1_5.final_public_observer_controlled_testnet_go_gate",
    "generated/production_helper_topology_hardening_plan_v1_5.json": "weall.v1_5.production_helper_topology_hardening_plan",
    "generated/protocol_upgrade_execution_hardening_plan_v1_5.json": "weall.v1_5.protocol_upgrade_execution_hardening_plan",
    "generated/public_discovery_provider_independence_v1_5.json": "weall.v1_5.public_discovery_provider_independence",
    "generated/public_frontend_operator_journey_v1_5.json": "weall.v1_5.public_frontend_operator_journey",
    "generated/public_observer_auto_discovery_proof_v1_5.json": "weall.v1_5.public_observer_auto_discovery_proof",
    "generated/public_observer_clean_clone_bootstrap_transcript_v1_5.json": "weall.v1_5.public_observer_clean_clone_bootstrap_transcript",
    "generated/public_observer_launch_evidence_requirements_v1_5.json": "weall.v1_5.public_observer_launch_evidence_requirements",
    "generated/public_observer_state_sync_trusted_anchor_proof_v1_5.json": "weall.v1_5.public_observer_state_sync_trusted_anchor_proof",
    "generated/public_only_protocol_audit_v1_5.json": "weall.public_only_protocol_audit.v1_5",
    "generated/public_registry_signer_operations_v1_5.json": "weall.v1_5.public_registry_signer_operations",
    "generated/public_seed_registry_signature_verification_v1_5.json": "weall.v1_5.public_seed_registry_signature_verification",
    "generated/public_validator_bft_preflight_matrix_v1_5.json": "weall.v1_5.public_validator_bft_preflight_matrix",
    "generated/public_validator_endpoint_churn_proof_v1_5.json": "weall.v1_5.public_validator_endpoint_churn_proof",
    "generated/quantum_resistance_readiness_v1_5.json": "weall.quantum_resistance_readiness.v1_5",
    "generated/signature_profile_registry_v1_5.json": "weall.signature_profile_registry.v1_5",
    "generated/state_root_vectors_v1_5.json": "weall.v1_5.state_root_vectors",
    "generated/tokenomics_simulation_v1_5.json": "weall.v1_5.tokenomics_simulation",
    "generated/public_beta_blocker_report_v1_5.json": "weall.v1_5.public_beta_blocker_report",
    "generated/controlled_testnet_go_gate_v1_5.json": "weall.v1_5.controlled_testnet_go_gate",
    "generated/release_evidence_manifest_v1_5.json": "weall.v1_5.release_evidence_manifest",
}
NO_OK_ARTIFACTS = {
    "generated/public_only_protocol_audit_v1_5.json",
    "generated/failure_code_registry_v1_5.json",
    "generated/quantum_resistance_readiness_v1_5.json",
    "generated/signature_profile_registry_v1_5.json",
    "generated/crypto_inventory_v1_5.json",
    "generated/state_root_vectors_v1_5.json",
    "generated/tokenomics_simulation_v1_5.json",
    "generated/public_validator_bft_preflight_matrix_v1_5.json",
    "generated/api_contract_map_v1_5.json",
}


def _non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _exact_bool(payload: Json, key: str) -> bool:
    return isinstance(payload.get(key), bool)


def artifact_contract_valid(rel: str, payload: Json) -> bool:
    if not isinstance(payload, dict) or not payload:
        return False
    expected_schema = EXPECTED_SCHEMAS.get(rel)
    if expected_schema is None or payload.get("schema") != expected_schema:
        return False

    if rel not in NO_OK_ARTIFACTS:
        return isinstance(payload.get("ok"), bool)
    if "ok" in payload:
        return False

    if rel.endswith("crypto_inventory_v1_5.json"):
        backend = payload.get("mldsa_backend_status")
        return bool(
            _non_empty_string(payload.get("active_signature_profile"))
            and _exact_bool(payload, "real_mldsa_implemented_in_this_environment")
            and _exact_bool(payload, "production_crypto_audit_complete")
            and isinstance(backend, dict)
            and _exact_bool(backend, "available")
        )

    if rel.endswith("signature_profile_registry_v1_5.json"):
        return bool(
            _non_empty_string(payload.get("active_signature_profile"))
            and _exact_bool(payload, "classical_signature_profiles_removed_from_authority")
            and _exact_bool(payload, "production_crypto_audit_complete")
            and isinstance(payload.get("profiles"), list)
            and bool(payload.get("profiles"))
        )

    if rel.endswith("quantum_resistance_readiness_v1_5.json"):
        bool_fields = (
            "real_mldsa_implemented_in_this_environment",
            "production_crypto_audit_complete",
            "public_beta_ready",
            "public_mainnet_ready",
            "public_multi_validator_bft_ready",
            "live_economics",
        )
        return bool(
            _non_empty_string(payload.get("active_signature_profile"))
            and all(_exact_bool(payload, key) for key in bool_fields)
        )

    # Deterministic descriptive artifacts may intentionally omit an aggregate
    # readiness `ok`. Their acceptance is still explicit: known path + exact schema.
    return True


def artifact_reported_ok(payload: Json) -> bool | None:
    value = payload.get("ok")
    return value if isinstance(value, bool) else None


def explicit_true(payload: Json, key: str) -> bool:
    return payload.get(key) is True
