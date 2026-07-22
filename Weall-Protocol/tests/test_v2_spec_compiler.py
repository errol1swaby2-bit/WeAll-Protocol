from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_ROOT = ROOT.parent
EXACT_PDF_SHA256 = "c15d51574c5402fd8b57bc571df971be80c0c26963180f58306f2a57dc5e740a"
EXACT_PDF_TITLE = (
    "WeAll Full-Scope Product and Protocol Specification - Version 2.0 First Draft"
)
EXACT_PDF_VERSION = "2.0 First Draft - Complete Pre-Testnet Design Blueprint"
EXACT_PDF_AUTHORITY = "V2_0_FIRST_DRAFT_NOT_AUTHORIZED"
EXACT_PDF_PAGES = 390
EXPECTED_REGISTER_FINGERPRINTS = {
    "requirements": {
        "count": 755,
        "ids_sha256": "4b91ee45a7b8717a50b09a9a42f64c9d0ce4f5f87531c735d5130b49192e1fc4",
        "rows_sha256": "b5f1dee8ddf7b6431a9d935121c45b36c5f61381110facb0b79b8ee0d7d1ac0d"
    },
    "parameters": {
        "count": 215,
        "ids_sha256": "06c5d4e290c66165f18e783a6d6531e21209ff965c93aeac41ca7f1de918e007",
        "rows_sha256": "4757a5390888ece261016dceb50dd9291b4b7d6df7ea3109636c9069b1e04d60"
    },
    "mechanisms": {
        "count": 78,
        "ids_sha256": "aeaba8e5d82678f537d2cbd24c9f9c7a130afc61961c16b819d1ccc603f21574",
        "rows_sha256": "b30435676ceb8156d20f0eabb82d0c92dd976682927bc7c0a8f4ca68b954adf3"
    },
    "state_objects": {
        "count": 94,
        "ids_sha256": "b46a3d02453e14366e14b81bdaa2d152e044f45ce8b6cbabd2e0ddb6733d5de8",
        "rows_sha256": "faa40db5ed10375cf42dd3f7fdf981e8f0e4c9b272fb5f1f0a65618c023762b2"
    },
    "target_contracts": {
        "count": 150,
        "ids_sha256": "910797b1ab403db5a539de0b348baf5e0fed03cb4c207a6be160f993418fb92f",
        "rows_sha256": "7b5d2a16aaef3f5c85cee83701d5a037f859cd1cfb7d78d02a6a4d816dcbcd38"
    },
    "target_failures": {
        "count": 98,
        "ids_sha256": "af3295d47a061c3f9e5baf4506b14c51a3aa98bcb3371f478220a304d83e8b23",
        "rows_sha256": "3ff5525e83c6f3778a3c7822df380bd3c2a68cea9176476af0a06450a89e8b5d"
    }
}


def _read(relative: str, root: Path = ROOT) -> dict:
    value = json.loads((root / relative).read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _write(relative: str, payload: dict, root: Path) -> None:
    path = root / relative
    temporary = path.with_name(path.name + ".tmp-test-write")
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def _compact_digest(value: object) -> str:
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _run_compiler(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = "src"
    return subprocess.run(
        [sys.executable, "scripts/compile_v2_spec.py", *args],
        cwd=root,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def _copy_workspace(tmp_path: Path) -> Path:
    target = tmp_path / "WeAll-Protocol"
    shutil.copytree(
        WORKSPACE_ROOT,
        target,
        ignore=shutil.ignore_patterns(
            ".git",
            ".venv",
            "node_modules",
            "__pycache__",
            ".pytest_cache",
        ),
        copy_function=os.link,
    )
    return target / "Weall-Protocol"


def _validate_schema(value: object, schema: dict, path: str = "$") -> None:
    raw_type = schema.get("type")
    allowed = raw_type if isinstance(raw_type, list) else [raw_type] if raw_type else []
    type_checks = {
        "null": lambda item: item is None,
        "string": lambda item: isinstance(item, str),
        "integer": lambda item: isinstance(item, int) and not isinstance(item, bool),
        "boolean": lambda item: isinstance(item, bool),
        "array": lambda item: isinstance(item, list),
        "object": lambda item: isinstance(item, dict),
    }
    if allowed and not any(type_checks[item](value) for item in allowed):
        raise AssertionError(f"{path}: expected {allowed}, found {type(value).__name__}")
    if value is None:
        return
    if isinstance(value, str):
        if len(value) < int(schema.get("minLength", 0)):
            raise AssertionError(f"{path}: string shorter than minLength")
        pattern = schema.get("pattern")
        if pattern and re.search(str(pattern), value) is None:
            raise AssertionError(f"{path}: string does not match {pattern}")
        enum = schema.get("enum")
        if enum is not None and value not in enum:
            raise AssertionError(f"{path}: value not in enum")
    if isinstance(value, int) and not isinstance(value, bool):
        if "minimum" in schema and value < int(schema["minimum"]):
            raise AssertionError(f"{path}: integer below minimum")
    if isinstance(value, list):
        if len(value) < int(schema.get("minItems", 0)):
            raise AssertionError(f"{path}: array shorter than minItems")
        if schema.get("uniqueItems") and len(
            {json.dumps(item, sort_keys=True) for item in value}
        ) != len(value):
            raise AssertionError(f"{path}: array items are not unique")
        item_schema = schema.get("items") or {}
        for index, item in enumerate(value):
            _validate_schema(item, item_schema, f"{path}[{index}]")
    if isinstance(value, dict):
        required = schema.get("required") or []
        missing = [field for field in required if field not in value]
        if missing:
            raise AssertionError(f"{path}: missing required fields {missing}")
        properties = schema.get("properties") or {}
        if schema.get("additionalProperties") is False:
            extra = sorted(set(value) - set(properties))
            if extra:
                raise AssertionError(f"{path}: unexpected fields {extra}")
        for field, item in value.items():
            if field in properties:
                _validate_schema(item, properties[field], f"{path}.{field}")


def test_v2_spec_derivatives_are_current() -> None:
    manifest = _read("specs/v2/source/manifest.json")
    result = _run_compiler(ROOT, "--check")
    assert result.returncode == 0, result.stdout + result.stderr
    assert f"OK: {len(manifest['outputs'])} v2 specification derivatives are current" in result.stdout


def test_exact_uploaded_first_draft_pdf_is_retained_and_validated() -> None:
    identity = _read("specs/v2/source/pdf_identity.json")
    provenance = _read("specs/v2/source/provenance.json")
    generated_identity = _read("generated/v2/pdf_identity_manifest.json")
    source_pdf = ROOT / provenance["normative_specification"]["path"]
    generated_pdf = ROOT / "generated/v2" / provenance["normative_specification"]["filename"]
    raw = source_pdf.read_bytes()

    assert raw.startswith(b"%PDF-")
    assert len(re.findall(rb"/Type\s*/Page\b", raw)) == EXACT_PDF_PAGES
    assert EXACT_PDF_TITLE.encode("utf-8") in raw
    assert hashlib.sha256(raw).hexdigest() == EXACT_PDF_SHA256
    assert generated_pdf.read_bytes() == raw
    assert identity["sha256"] == EXACT_PDF_SHA256
    assert identity["page_count"] == EXACT_PDF_PAGES
    assert identity["version"] == EXACT_PDF_VERSION
    assert identity["authority_status"] == EXACT_PDF_AUTHORITY
    assert generated_identity["validation_result"] == "PASS_EXACT_UPLOADED_PDF_IDENTITY"
    assert generated_identity["validated_sha256"] == EXACT_PDF_SHA256
    assert provenance["normative_specification"]["validation_policy"] == (
        "exact_uploaded_pdf_identity_plus_pinned_signed_extraction_attestation"
    )


def test_non_pdf_bytes_fail_even_when_attacker_updates_hashes(tmp_path: Path) -> None:
    protocol_root = _copy_workspace(tmp_path)
    spec_path = protocol_root / "specs/v2/source/WeAll.v2.0.Full-Scope.Product.and.Protocol.Specification.pdf"
    raw = b"NOT_A_PDF_BUT_HASH_PINNED"
    spec_path.unlink()
    spec_path.write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()
    for filename in ("pdf_identity.json", "provenance.json", "manifest.json"):
        payload = _read(f"specs/v2/source/{filename}", protocol_root)
        if filename == "pdf_identity.json":
            payload["sha256"] = digest
        elif filename == "provenance.json":
            payload["normative_specification"]["sha256"] = digest
        else:
            payload["normative_specification"]["sha256"] = digest
        _write(f"specs/v2/source/{filename}", payload, protocol_root)
    extraction = _read("specs/v2/source/pdf_extraction_manifest.json", protocol_root)
    extraction["pdf_sha256"] = digest
    _write("specs/v2/source/pdf_extraction_manifest.json", extraction, protocol_root)
    result = _run_compiler(protocol_root)
    assert result.returncode != 0
    assert "not a PDF file" in result.stderr


def test_full_scope_register_counts_and_pdf_fingerprints() -> None:
    fingerprints = _read("generated/v2/register_fingerprint_manifest.json")
    assert fingerprints["pdf_sha256"] == EXACT_PDF_SHA256
    assert fingerprints["validation_result"] == "PASS_PINNED_SIGNED_PDF_EXTRACTION_ATTESTATION"
    for name, expected in EXPECTED_REGISTER_FINGERPRINTS.items():
        assert fingerprints[name] == expected

    manifest = _read("generated/v2/spec_compilation_manifest.json")
    coverage = manifest["coverage"]
    assert coverage["requirements"] == 755
    assert coverage["parameters"] == 215
    assert coverage["mechanisms"] == 78
    assert coverage["state_contracts"] == 94
    assert coverage["target_transactions"] == 27
    assert coverage["target_contracts"] == 150
    assert coverage["target_failures"] == 98
    assert coverage["human_machine_register_equality"] is True
    assert coverage["exact_uploaded_pdf_identity"] is True
    assert coverage["signed_pdf_extraction_attestation"] is True
    assert coverage["structured_schema_definitions_complete"] is True
    assert coverage["stable_id_history_complete"] is True
    assert coverage["mechanism_evidence_paths_valid"] is True


def test_human_machine_register_mutation_fails_closed(tmp_path: Path) -> None:
    protocol_root = _copy_workspace(tmp_path)
    payload = _read("specs/v2/source/requirements.json", protocol_root)
    payload["requirements"][0]["normative_sentence"] += " unauthorized mutation"
    _write("specs/v2/source/requirements.json", payload, protocol_root)
    result = _run_compiler(protocol_root)
    assert result.returncode != 0
    assert "signed PDF extraction mismatch for requirements" in result.stderr


def test_controlled_status_enum_is_enforced_independently_of_fingerprint(tmp_path: Path) -> None:
    protocol_root = _copy_workspace(tmp_path)
    payload = _read("specs/v2/source/requirements.json", protocol_root)
    payload["requirements"][0]["status"] = "banana_not_controlled"
    _write("specs/v2/source/requirements.json", payload, protocol_root)
    result = _run_compiler(protocol_root)
    assert result.returncode != 0
    assert "uncontrolled status values" in result.stderr


def test_pass_evidence_requires_commit_run_timestamp_and_independent_reviewer(tmp_path: Path) -> None:
    protocol_root = _copy_workspace(tmp_path)
    payload = _read("specs/v2/source/requirements.json", protocol_root)
    row = payload["requirements"][0]
    row["verification_result"] = "PASS"
    row["implementation_commit"] = None
    row["verification_timestamp"] = None
    row["test_run_id"] = "NOT_RUN"
    row["reviewer"] = "PENDING_INDEPENDENT_REVIEW"
    _write("specs/v2/source/requirements.json", payload, protocol_root)
    result = _run_compiler(protocol_root)
    assert result.returncode != 0
    assert "PASS requirement" in result.stderr
    assert "pinned implementation commit" in result.stderr


def test_requirements_are_complete_and_not_falsely_marked_pass() -> None:
    rows = _read("generated/v2/requirement_traceability.json")["rows"]
    ids = {row["id"] for row in rows}
    assert len(rows) == 755
    assert {f"GOV-EXEC-{number:03d}" for number in range(1, 13)} <= ids
    assert {f"MEC-{number:03d}" for number in range(1, 9)} <= ids
    assert {f"ACC-{number:03d}" for number in range(1, 23)} <= ids
    assert all(row["verification_result"] != "PASS" for row in rows)
    assert all(row["test_run_id"] == "NOT_RUN" for row in rows)
    assert all(row["implementation_commit"] is None for row in rows)
    assert all(row["verification_timestamp"] is None for row in rows)


def test_exact_parameter_and_mechanism_id_sets() -> None:
    parameters = _read("generated/v2/parameter_registry.json")["rows"]
    mechanisms = _read("generated/v2/mechanism_registry.json")["rows"]
    assert len(parameters) == 215
    assert {row["id"] for row in mechanisms} == {
        f"M-{number:03d}" for number in range(1, 79)
    }
    assert len({row["id"] for row in parameters}) == 215
    assert {f"V20-P-{number:03d}" for number in range(1, 6)} <= {
        row["id"] for row in parameters
    }


def test_current_and_target_transaction_canons_are_separate_and_fail_closed() -> None:
    current = _read("generated/v2/current_tx_canon.json")
    target = _read("generated/v2/target_tx_canon.json")
    full_target = _read("generated/v2/target_contract_canon.json")
    assert current["count"] == 236
    assert current["authority_status"] == "compatibility_runtime_not_mainnet_target_canon"
    assert target["count"] == 27
    assert target["authority_status"] == "normative_target_launch_gated"
    assert full_target["counts"] == {"MSG": 9, "RCP": 75, "SYS": 39, "TX": 27}
    assert full_target["count"] == 150
    assert {row["tx_type"] for row in current["rows"]}.isdisjoint(
        {row["id"] for row in target["rows"]}
    )


def test_exact_state_contracts_are_separate_from_runtime_inventory() -> None:
    exact = _read("generated/v2/state_contract_index.json")
    runtime = _read("generated/v2/runtime_state_inventory.json")
    assert exact["count"] == 94
    assert runtime["count"] == 972
    assert len({row["canonical_name"] for row in exact["rows"]}) == 94
    for row in exact["rows"]:
        assert row["stable_id"].startswith("STATE-FS-")
        assert row["schema_id"].startswith("weall.state.")
        assert len(row["contract_fingerprint"]) == 64
        assert re.fullmatch(r"M-\d{3}", row["primary_mechanism_id"])
        assert row["vector_ids"]
        definition = row["value_schema_definition"]
        assert definition["encoding"] == "deterministic_cbor"
        assert definition["unknown_fields"] == "reject"
        assert definition["duplicate_keys"] == "reject"
        assert row["field_count"] == len(definition["fields"])
        assert [field["key"] for field in definition["fields"]] == sorted(field["key"] for field in definition["fields"])


def test_target_msg_sys_rcp_failure_contracts_have_exact_schemas_and_vectors() -> None:
    contracts = _read("generated/v2/target_contract_canon.json")["rows"]
    schemas = _read("generated/v2/target_contract_schema_index.json")["rows"]
    failures = _read("generated/v2/target_failure_contract_index.json")["rows"]
    vectors = {row["id"] for row in _read("generated/v2/vector_registry.json")["rows"]}
    schema_by_contract = {row["contract_id"]: row for row in schemas}

    assert len(contracts) == 150
    assert len(schemas) == 150
    assert len(failures) == 98
    for row in contracts:
        schema = schema_by_contract[row["id"]]
        assert len(schema["schema_fingerprint"]) == 64
        assert schema["contract_fingerprint"] == row["contract_fingerprint"]
        assert schema["receipt_schema_definition"]["encoding"] == "deterministic_cbor"
        assert schema["receipt_schema_definition"]["unknown_fields"] == "reject"
        if row["namespace"] != "RCP":
            assert schema["payload_schema_definition"]["fields"]
        assert set(row["vector_ids"]) <= vectors
        assert len(row["vector_ids"]) >= 4
    for row in failures:
        assert len(row["contract_fingerprint"]) == 64
        assert row["failure_schema_definition"]["encoding"] == "deterministic_cbor"
        assert len(row["failure_schema_definition"]["fields"]) == 8
        assert set(row["vector_ids"]) <= vectors
        assert len(row["vector_ids"]) >= 3


def test_v2_transaction_contract_matrix_has_complete_structural_coverage() -> None:
    payload = _read("generated/v2/tx_contract_matrix.json")
    required = set(payload["required_fields"])
    rows = payload["rows"]
    assert payload["transaction_count"] == 236
    assert len(rows) == 236
    assert len({row["stable_id"] for row in rows}) == 236
    assert len({row["numeric_id"] for row in rows}) == 236
    for row in rows:
        assert required.issubset(row), row["tx_type"]
        assert row["state_reads"] and row["state_writes"] and row["failure_codes"]
        assert re.fullmatch(r"M-\d{3}", row["primary_mechanism_id"])
        assert row["activation"]["profiles"]["public_testnet"] == "disabled_pending_activation_receipt"
        assert row["activation"]["profiles"]["mainnet"] == "disabled_pending_activation_receipt"
        assert row["semantic_precision"] == "explicit_maintainer_reviewed_contract"
        assert len(row["semantic_review"]["review_digest"]) == 64
    assert payload["semantic_review_complete"] is True


def test_v2_route_contract_map_covers_all_route_implementations() -> None:
    payload = _read("generated/v2/route_contract_map.json")
    rows = payload["routes"]
    assert payload["route_count"] == 159
    assert payload["unique_method_path_count"] == 155
    assert payload["duplicate_route_implementation_count"] == 8
    assert len({row["stable_id"] for row in rows}) == 159
    assert all(row["primary_mechanism_id"] == "M-069" for row in rows)
    assert all(row["semantic_precision"] == "explicit_maintainer_reviewed_contract" for row in rows)
    assert all(len(row["semantic_review"]["review_digest"]) == 64 for row in rows)
    assert payload["semantic_review_complete"] is True


def test_v2_source_coverage_is_explicit_and_fail_closed() -> None:
    payload = _read("generated/v2/source_coverage_map.json")
    paths = {row["path"] for row in payload["files"]}
    assert payload["file_count"] >= 1780
    assert payload["unmapped_count"] == 0
    assert payload["unmapped"] == []
    assert all(row["mappings"] for row in payload["files"])
    assert all(re.fullmatch(r"M-\d{3}", row["primary_mechanism_id"]) for row in payload["files"])
    assert "configs/chains/weall-testnet-v1.json" in paths
    assert "../.github/workflows/backend-ci.yml" in paths
    assert "pyproject.toml" in paths
    assert "requirements.lock" in paths


def test_unmapped_authoritative_source_fails(tmp_path: Path) -> None:
    protocol_root = _copy_workspace(tmp_path)
    candidate = protocol_root / "src/weall/runtime/unreviewed_authority_switch.py"
    candidate.write_text(
        "AUTHORITY_THRESHOLD = 2\n\ndef select_authority(candidates):\n    return candidates[0]\n",
        encoding="utf-8",
    )
    result = _run_compiler(protocol_root)
    assert result.returncode != 0
    assert "unmapped source files" in result.stderr
    assert "unreviewed_authority_switch.py" in result.stderr


def test_ambient_evidence_artifact_fails_until_declared(tmp_path: Path) -> None:
    protocol_root = _copy_workspace(tmp_path)
    ambient = protocol_root / "generated/ambient_untracked_evidence.json"
    ambient.write_text('{"claim": "not declared"}\n', encoding="utf-8")
    result = _run_compiler(protocol_root)
    assert result.returncode != 0
    assert "unmapped source files" in result.stderr
    assert "ambient_untracked_evidence.json" in result.stderr


def test_compiler_is_hermetic_static_analysis() -> None:
    source = (ROOT / "scripts/compile_v2_spec.py").read_text(encoding="utf-8")
    handler_section = source.split("def _handler_runtime_info", 1)[1].split(
        "def _tx_function_analysis", 1
    )[0]
    assert "from weall" not in handler_section
    assert "import inspect" not in source
    registry = _read("specs/v2/source/protocol_registry.json")
    assert registry["parameters"]["compiler_mode"] == "hermetic_static_analysis"


def test_stable_identifier_registry_covers_current_and_target_contracts() -> None:
    source = _read("specs/v2/source/stable_ids.json")
    ids = {row["stable_id"] for row in source["entries"]}
    assert len(ids) == len(source["entries"])
    required: set[str] = set()
    for filename, key, field in (
        ("tx_contract_matrix.json", "rows", "stable_id"),
        ("route_contract_map.json", "routes", "stable_id"),
        ("state_contract_index.json", "rows", "stable_id"),
        ("message_contract_index.json", "rows", "stable_id"),
        ("scheduler_contract_index.json", "rows", "stable_id"),
        ("receipt_contract_index.json", "rows", "stable_id"),
        ("failure_contract_index.json", "rows", "stable_id"),
        ("target_contract_canon.json", "rows", "id"),
        ("target_failure_contract_index.json", "rows", "stable_id"),
        ("requirement_traceability.json", "rows", "id"),
        ("parameter_registry.json", "rows", "id"),
        ("mechanism_registry.json", "rows", "id"),
    ):
        required.update(row[field] for row in _read(f"generated/v2/{filename}")[key])
    assert required <= ids


def test_generated_schemas_are_closed_typed_and_validate_rows() -> None:
    targets = [
        ("tx_contract", "tx_contract_matrix.json", "rows"),
        ("route_contract", "route_contract_map.json", "routes"),
        ("state_contract", "state_contract_index.json", "rows"),
        ("message_contract", "message_contract_index.json", "rows"),
        ("scheduler_contract", "scheduler_contract_index.json", "rows"),
        ("receipt_contract", "receipt_contract_index.json", "rows"),
        ("failure_contract", "failure_contract_index.json", "rows"),
        ("parameter", "parameter_registry.json", "rows"),
        ("requirement", "requirement_traceability.json", "rows"),
        ("mechanism", "mechanism_registry.json", "rows"),
        ("evidence", "evidence_index.json", "rows"),
        ("source_coverage", "source_coverage_map.json", "files"),
        ("target_contract", "target_contract_canon.json", "rows"),
        ("target_failure", "target_failure_contract_index.json", "rows"),
    ]
    for schema_name, payload_name, row_key in targets:
        schema = _read(f"generated/v2/schemas/{schema_name}.schema.json")
        assert schema["additionalProperties"] is False
        rows = _read(f"generated/v2/{payload_name}")[row_key]
        for row in rows:
            _validate_schema(row, schema)
        invalid = dict(rows[0])
        invalid[schema["required"][0]] = None
        with pytest.raises(AssertionError):
            _validate_schema(invalid, schema)


def test_message_register_includes_active_network_package() -> None:
    rows = _read("generated/v2/message_contract_index.json")["rows"]
    keys = {(row["source"], row["name"]) for row in rows}
    assert ("src/weall/net/messages.py", "WireMessage") in keys
    assert ("src/weall/net/codec.py", "encode_message") in keys
    assert ("src/weall/net/relay.py", "make_relay_envelope") in keys


def test_compilation_manifest_preserves_fail_closed_truth_boundary() -> None:
    payload = _read("generated/v2/spec_compilation_manifest.json")
    coverage = payload["coverage"]
    assert coverage["transactions"] == 236
    assert coverage["routes"] == 159
    assert coverage["unmapped_source_files"] == 0
    assert coverage["tx_semantic_review_complete"] is True
    assert coverage["route_semantic_review_complete"] is True
    assert payload["activation_boundary"] == {
        "mainnet": "disabled_pending_activation_receipt",
        "mechanism_coverage_is_not_production_readiness": True,
        "normative_pdf_authority": EXACT_PDF_AUTHORITY,
        "public_testnet": "disabled_pending_activation_receipt",
    }


def test_generated_frontend_status_is_fail_closed_and_consumed() -> None:
    generated = WORKSPACE_ROOT / "web/src/generated/protocolStatus.ts"
    text = generated.read_text(encoding="utf-8")
    consumer = (WORKSPACE_ROOT / "web/src/components/ProtocolStatusSummary.tsx").read_text(
        encoding="utf-8"
    )
    assert "Generated by scripts/compile_v2_spec.py" in text
    assert '"publicBetaReady": false' in text
    assert '"mainnetReady": false' in text
    assert '"authorityTimeSource": "finalized_block_height"' in text
    assert "WEALL_PROTOCOL_STATUS" in consumer
    assert "../generated/protocolStatus" in consumer



def test_attacker_cannot_rebind_register_and_signed_extraction_manifest(tmp_path: Path) -> None:
    protocol_root = _copy_workspace(tmp_path)
    requirements = _read("specs/v2/source/requirements.json", protocol_root)
    requirements["requirements"][0]["normative_sentence"] += " coordinated unauthorized mutation"
    _write("specs/v2/source/requirements.json", requirements, protocol_root)

    extraction = _read("specs/v2/source/pdf_extraction_manifest.json", protocol_root)
    rows = requirements["requirements"]
    extraction["registers"]["requirements"] = {
        "count": len(rows),
        "ids_sha256": _compact_digest(sorted(row["id"] for row in rows)),
        "rows_sha256": _compact_digest(rows),
    }
    _write("specs/v2/source/pdf_extraction_manifest.json", extraction, protocol_root)
    result = _run_compiler(protocol_root)
    assert result.returncode != 0
    assert "attestation payload digest mismatch" in result.stderr or "signature verification failed" in result.stderr


def test_normative_rows_are_clean_and_mechanism_paths_are_typed() -> None:
    forbidden = (
        "WEALL PROTOCOL | FULL-SCOPE SPECIFICATION |",
        "WEALL PROTOCOL | FULL-SCOPE PRODUCT AND PROTOCOL SPECIFICATION |",
        "| Repository snapshot 63629d71a244 | Page",
        "V2.0 FIRST DRAFT V2.0 FIRST DRAFT",
    )
    for filename, key in (
        ("requirements.json", "requirements"),
        ("mechanisms.json", "mechanisms"),
        ("state_objects.json", "rows"),
        ("target_contracts.json", "rows"),
        ("target_failures.json", "rows"),
    ):
        rows = _read(f"specs/v2/source/{filename}")[key]
        assert all(not any(marker in json.dumps(row) for marker in forbidden) for row in rows)
    mechanisms = _read("specs/v2/source/mechanisms.json")["mechanisms"]
    for row in mechanisms:
        assert row["repository_evidence"]
        for item in row["repository_evidence"]:
            assert item["kind"] in {
                "current_path", "current_glob", "planned_target_path",
                "planned_target_glob", "planned_target_reference",
            }
            if item["kind"].startswith("current_"):
                assert " " not in item["path"]


def test_stable_id_release_baseline_and_tombstones_are_immutable(tmp_path: Path) -> None:
    protocol_root = _copy_workspace(tmp_path)
    current = _read("specs/v2/source/stable_ids.json", protocol_root)
    sentinel = next(row for row in current["tombstones"] if row["stable_id"] == "LEGACY-W1-UNSCOPED-0001")
    current["tombstones"].remove(sentinel)
    _write("specs/v2/source/stable_ids.json", current, protocol_root)
    result = _run_compiler(protocol_root)
    assert result.returncode != 0
    assert "released stable-ID tombstones were removed" in result.stderr


def test_w1_closure_manifest_records_release_attestation_boundary() -> None:
    closure = _read("generated/v2/w1_closure_validation_manifest.json")
    assert closure["validation_result"] == "PASS_W1_TECHNICAL_CLOSURE_RELEASE_ATTESTATION_REQUIRED"
    assert closure["pdf_extraction_attestation"]["validation_result"] == "PASS_PINNED_SIGNED_PDF_EXTRACTION_ATTESTATION"
    assert closure["structured_schemas"]["state_schema_count"] == 94
    assert closure["structured_schemas"]["target_contract_schema_count"] == 150
    assert closure["semantic_reviews"]["transaction_reviews"] == 236
    assert closure["semantic_reviews"]["route_reviews"] == 159
    assert closure["semantic_reviews"]["independent_review_complete"] is False
    assert closure["release_export_attestation_required"] is True
    assert closure["provenance_binding"]["binding_policy"] == "PASS_NON_CIRCULAR_TWO_COMMIT_BINDING"
    assert closure["provenance_binding"]["release_export_attestation_required"] is True
    provenance = _read("specs/v2/source/provenance.json")
    assert re.fullmatch(r"[0-9a-f]{40}", provenance["repository"]["implementation_commit"])
    assert (ROOT / "scripts/finalize_v2_spec_provenance.py").is_file()
    assert (ROOT / "scripts/export_v2_spec_release.py").is_file()

def test_clean_checkout_reproducibility_gate() -> None:
    probe = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=WORKSPACE_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if probe.returncode != 0 or probe.stdout.strip():
        pytest.skip("clean-checkout test runs only from a clean committed Git tree")
    result = subprocess.run(
        [sys.executable, "scripts/check_v2_spec_clean_checkout.py"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "clean Git archive reproduces" in result.stdout


def test_target_receipt_contracts_are_canonically_bound_to_source_contracts() -> None:
    payload = _read("specs/v2/source/target_contracts.json")
    rows = payload["rows"]
    by_id = {row["id"]: row for row in rows}
    receipts = [row for row in rows if row["namespace"] == "RCP"]
    assert len(receipts) == 75
    assert len({row["source_contract"] for row in receipts}) == 75
    for row in receipts:
        source = by_id[row["source_contract"]]
        source_name = source["name"]
        expected_name = (
            source_name if source_name.endswith("_RECEIPT") else f"{source_name}_RECEIPT"
        )
        expected_schema = f"weall.rcp.{source_name.lower()}.receipt.v1"
        assert row["name"] == expected_name
        assert row["schema"] == expected_schema
        assert row["receipt_schema_definition"]["schema_id"] == expected_schema
        assert re.search(r"\\b(?:TX|MSG|SYS):C310:", row["name"]) is None


def test_invalid_provenance_commit_binding_fails_closed(tmp_path: Path) -> None:
    protocol_root = _copy_workspace(tmp_path)
    provenance = _read("specs/v2/source/provenance.json", protocol_root)
    provenance["repository"]["implementation_commit"] = "not-a-commit"
    _write("specs/v2/source/provenance.json", provenance, protocol_root)
    result = _run_compiler(protocol_root)
    assert result.returncode != 0
    assert "W1 provenance lacks a valid 40-hex implementation commit" in result.stderr
