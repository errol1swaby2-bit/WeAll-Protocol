from pathlib import Path
import json

ROOT = Path(__file__).resolve().parents[1]
PROTO = ROOT / "Weall-Protocol"


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected exactly one target in {path}, found {count}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


baseline_manifest = json.loads(
    (PROTO / "generated" / "release_evidence_manifest_v1_5.json").read_text(encoding="utf-8")
)
tracked = baseline_manifest.get("tracked_artifacts")
if not isinstance(tracked, dict) or not tracked:
    raise SystemExit("baseline release evidence manifest missing tracked_artifacts")

expected_schemas: dict[str, str] = {}
no_ok_artifacts: set[str] = set()
for rel, summary in tracked.items():
    if not isinstance(rel, str) or not isinstance(summary, dict):
        raise SystemExit("malformed baseline tracked_artifacts entry")
    schema = summary.get("schema")
    if not isinstance(schema, str) or not schema.strip():
        raise SystemExit(f"baseline artifact {rel} missing schema")
    expected_schemas[rel] = schema
    payload = json.loads((PROTO / rel).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise SystemExit(f"baseline artifact root must be object: {rel}")
    if "ok" not in payload:
        no_ok_artifacts.add(rel)

contracts = PROTO / "scripts" / "release_evidence_contracts.py"
contracts.write_text(
    f'''from __future__ import annotations\n\nfrom typing import Any\n\nJson = dict[str, Any]\n\nEXPECTED_SCHEMAS = {expected_schemas!r}\nNO_OK_ARTIFACTS = {no_ok_artifacts!r}\n\n\ndef _non_empty_string(value: Any) -> bool:\n    return isinstance(value, str) and bool(value.strip())\n\n\ndef _exact_bool(payload: Json, key: str) -> bool:\n    return isinstance(payload.get(key), bool)\n\n\ndef artifact_contract_ok(rel: str, payload: Json) -> bool:\n    if not isinstance(payload, dict) or not payload:\n        return False\n    expected_schema = EXPECTED_SCHEMAS.get(rel)\n    if expected_schema is None or payload.get("schema") != expected_schema:\n        return False\n\n    if rel not in NO_OK_ARTIFACTS:\n        return isinstance(payload.get("ok"), bool) and payload.get("ok") is True\n    if "ok" in payload:\n        return False\n\n    if rel.endswith("crypto_inventory_v1_5.json"):\n        backend = payload.get("mldsa_backend_status")\n        return bool(\n            _non_empty_string(payload.get("active_signature_profile"))\n            and _exact_bool(payload, "real_mldsa_implemented_in_this_environment")\n            and _exact_bool(payload, "production_crypto_audit_complete")\n            and isinstance(backend, dict)\n            and _exact_bool(backend, "available")\n        )\n\n    if rel.endswith("signature_profile_registry_v1_5.json"):\n        return bool(\n            _non_empty_string(payload.get("active_signature_profile"))\n            and _exact_bool(payload, "classical_signature_profiles_removed_from_authority")\n            and _exact_bool(payload, "production_crypto_audit_complete")\n            and isinstance(payload.get("profiles"), list)\n            and bool(payload.get("profiles"))\n        )\n\n    if rel.endswith("quantum_resistance_readiness_v1_5.json"):\n        bool_fields = (\n            "real_mldsa_implemented_in_this_environment",\n            "production_crypto_audit_complete",\n            "public_beta_ready",\n            "public_mainnet_ready",\n            "public_multi_validator_bft_ready",\n            "live_economics",\n        )\n        return bool(\n            _non_empty_string(payload.get("active_signature_profile"))\n            and all(_exact_bool(payload, key) for key in bool_fields)\n        )\n\n    # Some deterministic descriptive artifacts intentionally have no aggregate\n    # `ok` field. Their admission is therefore an explicit per-path schema\n    # contract rather than an optimistic missing-key default.\n    return True\n\n\ndef explicit_true(payload: Json, key: str) -> bool:\n    return payload.get(key) is True\n''',
    encoding="utf-8",
)

release = PROTO / "scripts" / "gen_release_evidence_manifest_v1_5.py"
replace_once(
    release,
    "from typing import Any\n",
    "from typing import Any\n\nfrom release_evidence_contracts import artifact_contract_ok\n",
)
replace_once(
    release,
    '    artifact_ok = bool(payload.get("ok", True)) if payload else False\n',
    '    artifact_ok = artifact_contract_ok(rel, payload)\n',
)

controlled = PROTO / "scripts" / "run_controlled_testnet_go_gate_v1_5.py"
replace_once(
    controlled,
    "from typing import Any\n",
    "from typing import Any\n\nfrom release_evidence_contracts import artifact_contract_ok, explicit_true\n",
)
replace_once(
    controlled,
    '        "ok": bool(payload.get("ok", True)) if payload else False,\n',
    '        "ok": artifact_contract_ok(rel, payload),\n',
)
replace_once(
    controlled,
    '    real_mldsa_ready = bool(quantum_readiness.get("real_mldsa_implemented_in_this_environment"))\n',
    '    real_mldsa_ready = explicit_true(\n        quantum_readiness, "real_mldsa_implemented_in_this_environment"\n    )\n',
)

final_gate = PROTO / "scripts" / "gen_final_public_observer_controlled_testnet_go_gate_v1_5.py"
replace_once(
    final_gate,
    "from typing import Any\n",
    "from typing import Any\n\nfrom release_evidence_contracts import artifact_contract_ok, explicit_true\n",
)
replace_once(
    final_gate,
    '        "ok": bool(payload.get("ok", True)) if payload else False,\n',
    '        "ok": artifact_contract_ok(rel, payload),\n',
)
replace_once(
    final_gate,
    '    repo_package_ready = (\n        all(docs_present.values())\n        and all(generated_present.values())\n        and all(flow_docs_present.values())\n    )\n',
    '    repo_package_ready = (\n        all(docs_present.values())\n        and all(generated_present.values())\n        and all(flow_docs_present.values())\n        and all(\n            item.get("present") is True and item.get("ok") is True\n            for item in generated_artifacts.values()\n        )\n    )\n',
)
replace_once(
    final_gate,
    '    real_mldsa_ready = bool(quantum.get("real_mldsa_implemented_in_this_environment"))\n',
    '    real_mldsa_ready = explicit_true(\n        quantum, "real_mldsa_implemented_in_this_environment"\n    )\n',
)


test = PROTO / "tests" / "test_release_evidence_contract_fail_closed.py"
test.write_text(
    '''from __future__ import annotations\n\nfrom scripts.release_evidence_contracts import (\n    EXPECTED_SCHEMAS,\n    artifact_contract_ok,\n    explicit_true,\n)\n\n\ndef test_unknown_or_wrong_schema_artifact_fails_closed() -> None:\n    assert artifact_contract_ok("generated/unknown.json", {"schema": "example.v1", "ok": True}) is False\n    rel = "generated/api_contract_map_v1_5.json"\n    assert rel in EXPECTED_SCHEMAS\n    assert artifact_contract_ok(rel, {"schema": "wrong.schema", "ok": True}) is False\n\n\ndef test_regular_artifact_requires_explicit_ok_true() -> None:\n    rel = "generated/api_contract_map_v1_5.json"\n    schema = EXPECTED_SCHEMAS[rel]\n    assert artifact_contract_ok(rel, {"schema": schema}) is False\n    assert artifact_contract_ok(rel, {"schema": schema, "ok": "true"}) is False\n    assert artifact_contract_ok(rel, {"schema": schema, "ok": True}) is True\n\n\ndef test_crypto_inventory_uses_explicit_shape_contract() -> None:\n    rel = "generated/crypto_inventory_v1_5.json"\n    valid = {\n        "schema": "weall.crypto_inventory.v1_5",\n        "active_signature_profile": "pq-mldsa-v1",\n        "real_mldsa_implemented_in_this_environment": True,\n        "production_crypto_audit_complete": False,\n        "mldsa_backend_status": {"available": True},\n    }\n    assert artifact_contract_ok(rel, valid) is True\n    assert artifact_contract_ok(rel, {"junk": "nonempty"}) is False\n    bad = dict(valid)\n    bad["real_mldsa_implemented_in_this_environment"] = "false"\n    assert artifact_contract_ok(rel, bad) is False\n\n\ndef test_signature_registry_requires_schema_and_typed_fields() -> None:\n    rel = "generated/signature_profile_registry_v1_5.json"\n    valid = {\n        "schema": "weall.signature_profile_registry.v1_5",\n        "active_signature_profile": "pq-mldsa-v1",\n        "classical_signature_profiles_removed_from_authority": True,\n        "production_crypto_audit_complete": False,\n        "profiles": [{"profile_id": "pq-mldsa-v1"}],\n    }\n    assert artifact_contract_ok(rel, valid) is True\n    bad = dict(valid)\n    bad["schema"] = "wrong.schema"\n    assert artifact_contract_ok(rel, bad) is False\n\n\ndef test_quantum_readiness_requires_exact_boolean_types() -> None:\n    rel = "generated/quantum_resistance_readiness_v1_5.json"\n    valid = {\n        "schema": "weall.quantum_resistance_readiness.v1_5",\n        "active_signature_profile": "pq-mldsa-v1",\n        "real_mldsa_implemented_in_this_environment": True,\n        "production_crypto_audit_complete": False,\n        "public_beta_ready": False,\n        "public_mainnet_ready": False,\n        "public_multi_validator_bft_ready": False,\n        "live_economics": False,\n    }\n    assert artifact_contract_ok(rel, valid) is True\n    bad = dict(valid)\n    bad["public_beta_ready"] = 0\n    assert artifact_contract_ok(rel, bad) is False\n\n\ndef test_explicit_true_rejects_truthy_non_boolean_values() -> None:\n    assert explicit_true({"flag": True}, "flag") is True\n    assert explicit_true({"flag": "false"}, "flag") is False\n    assert explicit_true({"flag": 1}, "flag") is False\n''',
    encoding="utf-8",
)
