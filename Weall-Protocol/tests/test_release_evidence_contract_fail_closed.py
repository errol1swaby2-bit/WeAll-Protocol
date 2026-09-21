from __future__ import annotations

from release_evidence_contracts import (
    EXPECTED_SCHEMAS,
    NO_OK_ARTIFACTS,
    artifact_contract_valid,
    artifact_reported_ok,
    explicit_true,
)


def test_unknown_or_wrong_schema_artifact_fails_closed() -> None:
    assert (
        artifact_contract_valid("generated/unknown.json", {"schema": "example.v1", "ok": True})
        is False
    )
    rel = "generated/api_contract_map_v1_5.json"
    assert rel in EXPECTED_SCHEMAS
    assert artifact_contract_valid(rel, {"schema": "wrong.schema", "ok": True}) is False


def test_regular_artifact_requires_typed_ok_but_validity_is_not_readiness() -> None:
    rel = next(rel for rel in EXPECTED_SCHEMAS if rel not in NO_OK_ARTIFACTS)
    schema = EXPECTED_SCHEMAS[rel]
    assert artifact_contract_valid(rel, {"schema": schema}) is False
    assert artifact_contract_valid(rel, {"schema": schema, "ok": "true"}) is False
    assert artifact_contract_valid(rel, {"schema": schema, "ok": True}) is True
    assert artifact_contract_valid(rel, {"schema": schema, "ok": False}) is True
    assert artifact_reported_ok({"ok": False}) is False
    assert artifact_reported_ok({}) is None


def test_recursive_release_artifacts_have_explicit_schema_contracts() -> None:
    recursive = {
        "generated/public_beta_blocker_report_v1_5.json": "weall.v1_5.public_beta_blocker_report",
        "generated/controlled_testnet_go_gate_v1_5.json": "weall.v1_5.controlled_testnet_go_gate",
        "generated/release_evidence_manifest_v1_5.json": "weall.v1_5.release_evidence_manifest",
    }
    for rel, schema in recursive.items():
        assert EXPECTED_SCHEMAS[rel] == schema
        assert artifact_contract_valid(rel, {"schema": schema, "ok": False}) is True
        assert artifact_contract_valid(rel, {"schema": schema, "ok": "false"}) is False


def test_crypto_inventory_uses_explicit_shape_contract() -> None:
    rel = "generated/crypto_inventory_v1_5.json"
    valid = {
        "schema": "weall.crypto_inventory.v1_5",
        "active_signature_profile": "pq-mldsa-v1",
        "real_mldsa_implemented_in_this_environment": True,
        "production_crypto_audit_complete": False,
        "mldsa_backend_status": {"available": True},
    }
    assert artifact_contract_valid(rel, valid) is True
    assert artifact_contract_valid(rel, {"junk": "nonempty"}) is False
    bad = dict(valid)
    bad["real_mldsa_implemented_in_this_environment"] = "false"
    assert artifact_contract_valid(rel, bad) is False


def test_signature_registry_requires_schema_and_typed_fields() -> None:
    rel = "generated/signature_profile_registry_v1_5.json"
    valid = {
        "schema": "weall.signature_profile_registry.v1_5",
        "active_signature_profile": "pq-mldsa-v1",
        "classical_signature_profiles_removed_from_authority": True,
        "production_crypto_audit_complete": False,
        "profiles": [{"profile_id": "pq-mldsa-v1"}],
    }
    assert artifact_contract_valid(rel, valid) is True
    bad = dict(valid)
    bad["schema"] = "wrong.schema"
    assert artifact_contract_valid(rel, bad) is False


def test_quantum_readiness_requires_exact_boolean_types() -> None:
    rel = "generated/quantum_resistance_readiness_v1_5.json"
    valid = {
        "schema": "weall.quantum_resistance_readiness.v1_5",
        "active_signature_profile": "pq-mldsa-v1",
        "real_mldsa_implemented_in_this_environment": True,
        "production_crypto_audit_complete": False,
        "public_beta_ready": False,
        "public_mainnet_ready": False,
        "public_multi_validator_bft_ready": False,
        "live_economics": False,
    }
    assert artifact_contract_valid(rel, valid) is True
    bad = dict(valid)
    bad["public_beta_ready"] = 0
    assert artifact_contract_valid(rel, bad) is False


def test_explicit_true_rejects_truthy_non_boolean_values() -> None:
    assert explicit_true({"flag": True}, "flag") is True
    assert explicit_true({"flag": "false"}, "flag") is False
    assert explicit_true({"flag": 1}, "flag") is False
