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
        "rows_sha256": "223ed330d79d6318da6748355698c4036105cec7e938301491ae9154d06e85a2",
    },
    "parameters": {
        "count": 215,
        "ids_sha256": "06c5d4e290c66165f18e783a6d6531e21209ff965c93aeac41ca7f1de918e007",
        "rows_sha256": "4757a5390888ece261016dceb50dd9291b4b7d6df7ea3109636c9069b1e04d60",
    },
    "mechanisms": {
        "count": 78,
        "ids_sha256": "aeaba8e5d82678f537d2cbd24c9f9c7a130afc61961c16b819d1ccc603f21574",
        "rows_sha256": "18f6e3cb27ad5e33e3f24e3c7238d77e6c0aea3c1956d5d78954d25cb4eeb348",
    },
    "state_objects": {
        "count": 94,
        "ids_sha256": "b46a3d02453e14366e14b81bdaa2d152e044f45ce8b6cbabd2e0ddb6733d5de8",
        "rows_sha256": "34cc8be4f50f0b57e8e51ba219677ad3e7ded94e9c7a2cec926bb5a3856562ac",
    },
    "target_contracts": {
        "count": 150,
        "ids_sha256": "910797b1ab403db5a539de0b348baf5e0fed03cb4c207a6be160f993418fb92f",
        "rows_sha256": "c20c6096a7c9a695a3bfb9ffdfd44d1e66ff852748f5880b7a4a00eae141897d",
    },
    "target_failures": {
        "count": 98,
        "ids_sha256": "af3295d47a061c3f9e5baf4506b14c51a3aa98bcb3371f478220a304d83e8b23",
        "rows_sha256": "c7c7cd1b27c3b5cc002d6e053aeb08df20ee83abe31c1b34e4b65698c3dd6165",
    },
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


def _rebind_register_fingerprint(root: Path, register: str, rows: list[dict], id_field: str) -> None:
    payload = _read("specs/v2/source/pdf_register_fingerprints.json", root)
    payload[register] = {
        "count": len(rows),
        "ids_sha256": _compact_digest(sorted(str(row[id_field]) for row in rows)),
        "rows_sha256": _compact_digest(rows),
    }
    _write("specs/v2/source/pdf_register_fingerprints.json", payload, root)


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
        "exact_uploaded_pdf_identity_and_register_fingerprints"
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
    fingerprints = _read("specs/v2/source/pdf_register_fingerprints.json", protocol_root)
    fingerprints["pdf_sha256"] = digest
    _write("specs/v2/source/pdf_register_fingerprints.json", fingerprints, protocol_root)
    result = _run_compiler(protocol_root)
    assert result.returncode != 0
    assert "not a PDF file" in result.stderr


def test_full_scope_register_counts_and_pdf_fingerprints() -> None:
    fingerprints = _read("generated/v2/register_fingerprint_manifest.json")
    assert fingerprints["pdf_sha256"] == EXACT_PDF_SHA256
    assert fingerprints["validation_result"] == "PASS_HUMAN_MACHINE_REGISTER_EQUALITY"
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


def test_human_machine_register_mutation_fails_closed(tmp_path: Path) -> None:
    protocol_root = _copy_workspace(tmp_path)
    payload = _read("specs/v2/source/requirements.json", protocol_root)
    payload["requirements"][0]["normative_sentence"] += " unauthorized mutation"
    _write("specs/v2/source/requirements.json", payload, protocol_root)
    result = _run_compiler(protocol_root)
    assert result.returncode != 0
    assert "human-machine register mismatch for requirements" in result.stderr


def test_controlled_status_enum_is_enforced_independently_of_fingerprint(tmp_path: Path) -> None:
    protocol_root = _copy_workspace(tmp_path)
    payload = _read("specs/v2/source/requirements.json", protocol_root)
    payload["requirements"][0]["status"] = "banana_not_controlled"
    _write("specs/v2/source/requirements.json", payload, protocol_root)
    _rebind_register_fingerprint(
        protocol_root,
        "requirements",
        payload["requirements"],
        "id",
    )
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
    _rebind_register_fingerprint(
        protocol_root,
        "requirements",
        payload["requirements"],
        "id",
    )
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
        assert set(row["vector_ids"]) <= vectors
        assert len(row["vector_ids"]) >= 4
    for row in failures:
        assert len(row["contract_fingerprint"]) == 64
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
    assert payload["semantic_review_complete"] is False


def test_v2_route_contract_map_covers_all_route_implementations() -> None:
    payload = _read("generated/v2/route_contract_map.json")
    rows = payload["routes"]
    assert payload["route_count"] == 159
    assert payload["unique_method_path_count"] == 155
    assert payload["duplicate_route_implementation_count"] == 8
    assert len({row["stable_id"] for row in rows}) == 159
    assert all(row["primary_mechanism_id"] == "M-069" for row in rows)
    assert payload["semantic_review_complete"] is False


def test_v2_source_coverage_is_explicit_and_fail_closed() -> None:
    payload = _read("generated/v2/source_coverage_map.json")
    paths = {row["path"] for row in payload["files"]}
    assert payload["file_count"] >= 1750
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
    assert coverage["tx_semantic_review_complete"] is False
    assert coverage["route_semantic_review_complete"] is False
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
