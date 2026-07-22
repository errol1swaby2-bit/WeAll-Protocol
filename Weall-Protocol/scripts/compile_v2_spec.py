#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import hashlib
import fnmatch
import json
import re
import sys
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from v2_spec_validation import (
    apply_semantic_reviews,
    compact_digest as attested_compact_digest,
    validate_mechanism_evidence,
    validate_normative_cleanliness,
    validate_provenance_binding,
    validate_stable_id_history,
    validate_structured_schemas,
    validate_w1_divergence_closure,
    verify_pdf_extraction_attestation,
)

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_ROOT = ROOT.parent
SOURCE_ROOT = ROOT / "specs" / "v2" / "source"
OUT_ROOT = ROOT / "generated" / "v2"
WEB_STATUS_OUT = WORKSPACE_ROOT / "web" / "src" / "generated" / "protocolStatus.ts"

Json = dict[str, Any]
SUPPORTED_SOURCE_SUFFIXES = {".py", ".json", ".yaml", ".yml", ".md", ".ts", ".tsx", ".mjs", ".toml", ".lock", ".in", ".txt"}
HTTP_METHODS = {"get", "post", "put", "delete", "patch"}
WRITE_METHODS = {
    "setdefault",
    "update",
    "append",
    "extend",
    "pop",
    "remove",
    "clear",
    "add",
    "discard",
}
_TEXT_CACHE: dict[Path, str] = {}
_MODULE_CACHE: dict[Path, tuple[ast.AST, dict[str, SourceFunction]]] = {}

MESSAGE_SUFFIXES_DEFAULT = (
    "Message",
    "Proposal",
    "Vote",
    "Certificate",
    "Envelope",
    "Frame",
    "Request",
    "Response",
)


class CompileError(RuntimeError):
    pass


@dataclass(frozen=True)
class StableIdRegistry:
    by_kind_key: dict[tuple[str, str], str]
    known_ids: frozenset[str]

    @classmethod
    def from_payload(cls, payload: Json) -> "StableIdRegistry":
        by_kind_key: dict[tuple[str, str], str] = {}
        known_ids: set[str] = set()
        for row in payload.get("entries") or []:
            if not isinstance(row, dict):
                raise CompileError("stable ID registry entries must be objects")
            kind = str(row.get("kind") or "").strip()
            key = str(row.get("canonical_key") or "").strip()
            stable_id = str(row.get("stable_id") or "").strip()
            if not kind or not key or not stable_id:
                raise CompileError(f"invalid stable ID row: {row}")
            if (kind, key) in by_kind_key:
                raise CompileError(f"duplicate stable ID key: {kind}:{key}")
            if stable_id in known_ids:
                raise CompileError(f"stable ID reuse is forbidden: {stable_id}")
            by_kind_key[(kind, key)] = stable_id
            known_ids.add(stable_id)
            for alias in row.get("aliases") or []:
                alias_key = str(alias).strip()
                if not alias_key:
                    continue
                if (kind, alias_key) in by_kind_key:
                    raise CompileError(f"duplicate stable ID alias: {kind}:{alias_key}")
                by_kind_key[(kind, alias_key)] = stable_id
        for row in payload.get("tombstones") or []:
            if not isinstance(row, dict):
                raise CompileError("stable ID tombstones must be objects")
            stable_id = str(row.get("stable_id") or "").strip()
            if not stable_id:
                raise CompileError(f"invalid stable ID tombstone: {row}")
            if stable_id in known_ids:
                raise CompileError(f"active/tombstoned stable ID collision: {stable_id}")
            known_ids.add(stable_id)
        return cls(by_kind_key=by_kind_key, known_ids=frozenset(known_ids))

    def resolve(self, kind: str, canonical_key: str) -> str:
        value = self.by_kind_key.get((kind, canonical_key))
        if value is None:
            raise CompileError(
                f"unregistered stable ID: kind={kind} canonical_key={canonical_key}"
            )
        return value


@dataclass(frozen=True)
class SourceFunction:
    name: str
    lineno: int
    end_lineno: int
    node: ast.FunctionDef | ast.AsyncFunctionDef


def _canonical_json(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _stable_id(prefix: str, material: str) -> str:
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16].upper()
    return f"{prefix}-{digest}"


def _relative(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return "../" + path.resolve().relative_to(WORKSPACE_ROOT.resolve()).as_posix()


def _load_json(path: Path) -> Json:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - compiler diagnostics.
        raise CompileError(f"could not parse JSON {_relative(path)}: {exc}") from exc
    if not isinstance(value, dict):
        raise CompileError(f"expected object in {_relative(path)}")
    return value


def _load_yaml(path: Path) -> Json:
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - compiler diagnostics.
        raise CompileError(f"could not parse YAML {_relative(path)}: {exc}") from exc
    if not isinstance(value, dict):
        raise CompileError(f"expected object in {_relative(path)}")
    return value




def _compact_digest(value: Any) -> str:
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return _sha256_bytes(raw)


def _validate_exact_uploaded_pdf(path: Path, identity: Json, provenance: Json) -> Json:
    raw = path.read_bytes()
    expected_sha = str(identity.get("sha256") or "")
    actual_sha = _sha256_bytes(raw)
    if actual_sha != expected_sha:
        raise CompileError("exact uploaded normative PDF SHA-256 mismatch")
    if not raw.startswith(b"%PDF-"):
        raise CompileError("normative specification is not a PDF file")
    page_count = len(re.findall(rb"/Type\s*/Page\b", raw))
    expected_pages = int(identity.get("page_count") or 0)
    if page_count != expected_pages:
        raise CompileError(
            f"normative PDF page-count mismatch: expected {expected_pages} found {page_count}"
        )
    title = str(identity.get("title") or "")
    author = str(identity.get("author") or "")
    if not title or title.encode("utf-8") not in raw:
        raise CompileError("normative PDF metadata title mismatch")
    if not author or f"/Author({author})".encode("utf-8") not in raw:
        raise CompileError("normative PDF metadata author mismatch")
    normative = provenance.get("normative_specification") or {}
    if str(normative.get("sha256") or "") != expected_sha:
        raise CompileError("PDF identity and provenance hashes disagree")
    if str(identity.get("version") or "") != str(normative.get("candidate") or ""):
        raise CompileError("PDF identity and provenance candidate labels disagree")
    if str(identity.get("authority_status") or "") != str(
        normative.get("authority_status") or ""
    ):
        raise CompileError("PDF identity and provenance authority status disagree")
    return {
        **identity,
        "validated_sha256": actual_sha,
        "validated_page_count": page_count,
        "byte_length": len(raw),
        "validation_result": "PASS_EXACT_UPLOADED_PDF_IDENTITY",
    }


def _register_fingerprint(rows: list[Json], id_field: str) -> Json:
    identifiers = sorted(str(row.get(id_field) or "") for row in rows)
    return {
        "count": len(rows),
        "ids_sha256": _compact_digest(identifiers),
        "rows_sha256": _compact_digest(rows),
    }


def _validate_pdf_register(
    name: str,
    rows: list[Json],
    id_field: str,
    declared: Json,
) -> Json:
    actual = _register_fingerprint(rows, id_field)
    expected = declared.get(name) or {}
    if actual != expected:
        raise CompileError(
            f"human-machine register mismatch for {name}: expected={expected} actual={actual}"
        )
    return actual


def _validate_controlled_statuses(
    rows: list[Json],
    allowed: set[str],
    kind: str,
) -> None:
    invalid = sorted(
        {
            str(row.get("status") or "")
            for row in rows
            if str(row.get("status") or "") not in allowed
        }
    )
    if invalid:
        raise CompileError(f"{kind} uses uncontrolled status values: {invalid}")


def _validate_requirement_results(rows: list[Json], controlled: Json) -> None:
    allowed = {str(value) for value in controlled.get("verification_result") or []}
    for row in rows:
        rid = str(row.get("id") or "")
        result = str(row.get("verification_result") or "")
        if result not in allowed:
            raise CompileError(f"requirement {rid} uses uncontrolled verification result: {result}")
        digest = str(row.get("evidence_digest") or "")
        if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise CompileError(f"requirement {rid} has invalid evidence digest")
        if result != "PASS":
            continue
        commit = str(row.get("implementation_commit") or "")
        timestamp = str(row.get("verification_timestamp") or "")
        reviewer = str(row.get("reviewer") or "")
        run_id = str(row.get("test_run_id") or "")
        gate = str(row.get("activation_gate") or "")
        if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
            raise CompileError(f"PASS requirement {rid} lacks a pinned implementation commit")
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", timestamp) is None:
            raise CompileError(f"PASS requirement {rid} lacks a UTC verification timestamp")
        if not run_id or run_id == "NOT_RUN":
            raise CompileError(f"PASS requirement {rid} lacks an executed test-run ID")
        if not reviewer or "PENDING" in reviewer.upper() or "AUTOMATED" in reviewer.upper():
            raise CompileError(f"PASS requirement {rid} lacks an independent reviewer")
        if not gate:
            raise CompileError(f"PASS requirement {rid} lacks an activation gate")


def _require_exact_ids(rows: list[Json], field: str, expected: list[str], kind: str) -> None:
    actual = sorted(str(row.get(field) or "") for row in rows)
    if actual != sorted(expected):
        missing = sorted(set(expected) - set(actual))
        extra = sorted(set(actual) - set(expected))
        raise CompileError(f"{kind} identifier drift: missing={missing[:25]} extra={extra[:25]}")


def _target_schema_rows(target_rows: list[Json]) -> list[Json]:
    rows: list[Json] = []
    for row in target_rows:
        contract_id = str(row["id"])
        namespace = str(row["namespace"])
        material = {
            "contract_id": contract_id,
            "namespace": namespace,
            "payload_schema_definition": row.get("payload_schema_definition"),
            "receipt_schema_definition": row.get("receipt_schema_definition"),
        }
        rows.append(
            {
                "id": f"SCHEMA-{contract_id.replace(':', '-')}",
                **material,
                "schema_fingerprint": attested_compact_digest(material),
                "contract_fingerprint": str(row.get("contract_fingerprint") or ""),
                "primary_mechanism_id": str(row.get("primary_mechanism_id") or ""),
                "vector_ids": list(row.get("vector_ids") or []),
                "status": str(row.get("status") or "normative_target"),
            }
        )
    return rows


def _expanded_vector_rows(
    declared_rows: list[Json],
    parameters: list[Json],
    state_rows: list[Json],
    target_contracts: list[Json],
    target_failures: list[Json],
) -> list[Json]:
    by_id: dict[str, Json] = {
        str(row["id"]): dict(row) for row in declared_rows if isinstance(row, dict)
    }
    def add(vector_id: str, title: str, expected: str, status: str = "normative_target") -> None:
        if vector_id in by_id:
            return
        by_id[vector_id] = {
            "id": vector_id,
            "title": title,
            "expected": expected,
            "profiles": ["all"],
            "status": status,
            "test": "NOT_YET_IMPLEMENTED; exact vector contract is registered and launch-gated",
        }
    for row in parameters:
        for vid in row.get("boundary_vector_ids") or []:
            add(str(vid), f"Parameter boundary: {row['id']}", "Boundary behavior matches the exact registered parameter row")
    for row in state_rows:
        for vid in row.get("vector_ids") or []:
            add(str(vid), f"State contract: {row['canonical_name']}", "Canonical encoding, transition, replay, and migration behavior match the exact state-object contract")
    for row in target_contracts:
        for vid in row.get("vector_ids") or []:
            add(str(vid), f"Target contract: {row['id']}", "Success, failure, boundary, or replay behavior matches the exact target contract")
    for row in target_failures:
        for vid in row.get("vector_ids") or []:
            add(str(vid), f"Target failure: {row['stable_id']}", "Failure stage, mutation guarantee, retry, receipt, and replay behavior match the exact failure contract")
    return [by_id[key] for key in sorted(by_id)]


def _record_schema(
    name: str,
    required: list[str],
    rows: list[Json],
    controlled_statuses: list[str],
    controlled_results: list[str],
    overrides: Json | None = None,
) -> Json:
    all_fields = set(required)
    for row in rows:
        all_fields.update(str(field) for field in row)
    properties: Json = {}
    for field in sorted(all_fields):
        values = [row[field] for row in rows if field in row]
        properties[field] = _schema_from_values(field, values)
    properties["status"] = {"type": "string", "enum": controlled_statuses}
    if "verification_result" in all_fields:
        properties["verification_result"] = {"type": "string", "enum": controlled_results}
    if "primary_mechanism_id" in all_fields:
        properties["primary_mechanism_id"] = {"type": ["string", "null"], "pattern": "^M-[0-9]{3}$"}
    if overrides:
        properties.update(overrides)
    return _typed_record_schema(name, required, properties)


def _literal_string(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _all_string_constants(node: ast.AST) -> set[str]:
    return {
        value
        for child in ast.walk(node)
        if isinstance(child, ast.Constant)
        and isinstance(child.value, str)
        and (value := child.value.strip())
    }


def _function_source_functions(tree: ast.AST) -> dict[str, SourceFunction]:
    out: dict[str, SourceFunction] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        out[node.name] = SourceFunction(
            name=node.name,
            lineno=int(getattr(node, "lineno", 0) or 0),
            end_lineno=int(getattr(node, "end_lineno", getattr(node, "lineno", 0)) or 0),
            node=node,
        )
    return out


def _find_enclosing_function(
    tree: ast.AST, target: ast.AST
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        for child in ast.walk(node):
            if child is target:
                return node
    return None


def _branch_for_tx(fn: ast.FunctionDef | ast.AsyncFunctionDef, tx_type: str) -> ast.If | None:
    matches: list[ast.If] = []
    for node in ast.walk(fn):
        if not isinstance(node, ast.If):
            continue
        if tx_type in _all_string_constants(node.test):
            matches.append(node)
    if not matches:
        return None
    matches.sort(
        key=lambda node: int(getattr(node, "end_lineno", node.lineno) or node.lineno)
        - int(getattr(node, "lineno", 0) or 0)
    )
    return matches[0]


def _direct_local_calls(node: ast.AST, known_functions: set[str]) -> list[str]:
    out: list[str] = []
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        name: str | None = None
        if isinstance(child.func, ast.Name):
            name = child.func.id
        elif isinstance(child.func, ast.Attribute):
            name = child.func.attr
        if name and name in known_functions and name not in out:
            out.append(name)
    return out


def _extract_key_tokens(node: ast.AST) -> tuple[set[str], set[str]]:
    reads: set[str] = set()
    writes: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Subscript):
            key = _literal_string(child.slice)
            if key:
                if isinstance(child.ctx, ast.Store):
                    writes.add(key)
                else:
                    reads.add(key)
        elif isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute):
            method = child.func.attr
            first = _literal_string(child.args[0]) if child.args else None
            if method == "get" and first:
                reads.add(first)
            elif method in WRITE_METHODS:
                if first:
                    writes.add(first)
                    if method == "setdefault":
                        reads.add(first)
                else:
                    writes.add(f"<{method}:dynamic>")
    return reads, writes


def _extract_failures(node: ast.AST) -> list[Json]:
    out: dict[tuple[str, str], Json] = {}
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        name = ""
        if isinstance(child.func, ast.Name):
            name = child.func.id
        elif isinstance(child.func, ast.Attribute):
            name = child.func.attr
        if not (name.endswith("Error") or name == "HTTPException"):
            continue
        strings = [_literal_string(arg) for arg in child.args]
        strings = [item for item in strings if item]
        if name == "HTTPException":
            code = "http_exception"
            reason = strings[-1] if strings else "route_specific_http_exception"
        else:
            code = strings[0] if strings else name
            reason = strings[1] if len(strings) > 1 else "runtime_apply_failure"
        out[(code, reason)] = {"code": code, "reason": reason}
    return [out[key] for key in sorted(out)]


def _extract_return_keys(node: ast.AST) -> list[str]:
    keys: set[str] = set()
    for child in ast.walk(node):
        if not isinstance(child, ast.Return) or not isinstance(child.value, ast.Dict):
            continue
        for key_node in child.value.keys:
            key = _literal_string(key_node)
            if key:
                keys.add(key)
    return sorted(keys)


def _read_text_cached(path: Path) -> str:
    cached = _TEXT_CACHE.get(path)
    if cached is not None:
        return cached
    try:
        cached = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        cached = ""
    _TEXT_CACHE[path] = cached
    return cached


def _module_cached(path: Path) -> tuple[ast.AST, dict[str, SourceFunction]]:
    cached = _MODULE_CACHE.get(path)
    if cached is not None:
        return cached
    source = _read_text_cached(path)
    tree = ast.parse(source, filename=_relative(path))
    cached = (tree, _function_source_functions(tree))
    _MODULE_CACHE[path] = cached
    return cached


def _search_files_for_token(paths: Iterable[Path], token: str) -> list[str]:
    out: list[str] = []
    for path in paths:
        if token in _read_text_cached(path):
            out.append(_relative(path))
    return sorted(set(out))


def _scan_files(root: Path, suffixes: set[str]) -> list[Path]:
    if not root.exists():
        return []
    if root.is_file():
        return [root] if root.suffix.lower() in suffixes else []
    return sorted(
        path
        for path in root.rglob("*")
        if path.is_file()
        and path.suffix.lower() in suffixes
        and "__pycache__" not in path.parts
        and ".pytest_cache" not in path.parts
        and "node_modules" not in path.parts
        and "generated/v2" not in path.as_posix()
        and "/web/src/generated/" not in path.as_posix()
    )


def _load_sources() -> dict[str, Json]:
    manifest = _load_json(SOURCE_ROOT / "manifest.json")
    sources: dict[str, Json] = {"manifest": manifest}
    inputs = manifest.get("inputs") or {}
    for name, raw in sorted(inputs.items()):
        path = (ROOT / str(raw)).resolve()
        if not path.is_file():
            raise CompileError(f"declared source input missing: {raw}")
        if path.suffix.lower() == ".json":
            sources[str(name)] = _load_json(path)
        elif path.suffix.lower() in {".yaml", ".yml"}:
            sources[str(name)] = _load_yaml(path)
    required = {
        "activation_profiles",
        "contract_overrides",
        "controlled_enums",
        "divergences",
        "evidence_manifest",
        "mechanisms",
        "parameters",
        "pdf_identity",
        "pdf_extraction_attestation",
        "pdf_extraction_manifest",
        "protocol_registry",
        "provenance",
        "requirements",
        "source_mappings",
        "stable_ids",
        "stable_id_baseline",
        "semantic_reviews",
        "state_objects",
        "target_contracts",
        "target_failures",
        "transaction_appliers",
        "transaction_canon",
        "vectors",
    }
    missing = sorted(required - set(sources))
    if missing:
        raise CompileError(f"source manifest missing required inputs: {missing}")
    return sources


def _activation_for_tx(tx_type: str, profiles: Json) -> Json:
    bindings = profiles.get("feature_bindings") or []
    matched: list[Json] = []
    for binding in bindings:
        if not isinstance(binding, dict):
            continue
        exact = {str(item).upper() for item in binding.get("tx_exact") or []}
        prefixes = [str(item).upper() for item in binding.get("tx_prefixes") or []]
        contains = [str(item).upper() for item in binding.get("tx_contains") or []]
        if (
            tx_type in exact
            or any(tx_type.startswith(prefix) for prefix in prefixes)
            or any(token in tx_type for token in contains)
        ):
            matched.append(binding)
    status = "implemented_controlled_rehearsal_public_profiles_disabled"
    features: list[str] = []
    blockers: list[str] = []
    if matched:
        features = sorted(
            {str(item.get("feature") or "") for item in matched if item.get("feature")}
        )
        blockers = sorted({str(item.get("status") or "") for item in matched if item.get("status")})
        status = blockers[0] if len(blockers) == 1 else "multiple_activation_gates_apply"
    return {
        "status": status,
        "features": features,
        "blockers": blockers,
        "profiles": {
            "dev_local": "rehearsal_only",
            "controlled_testnet": "rehearsal_only",
            "public_testnet": "disabled_pending_activation_receipt",
            "mainnet": "disabled_pending_activation_receipt",
        },
    }


def _route_metadata() -> dict[str, Json]:
    path = ROOT / "specs" / "api_contracts" / "v1_5_route_metadata.json"
    payload = _load_json(path)
    routes = payload.get("routes") or {}
    if not isinstance(routes, dict):
        raise CompileError("api metadata routes must be an object")
    return {str(key): value for key, value in routes.items() if isinstance(value, dict)}


def _route_full_path(raw: str) -> str:
    cleaned = str(raw or "")
    if cleaned.startswith("/v1"):
        return cleaned
    return "/v1" + cleaned


def _heuristic_route_authority(method: str, path: str, module: str) -> str:
    upper = method.upper()
    lower = path.lower()
    if "/tx/" in lower or lower.endswith("/tx/submit"):
        return "signed_canonical_transaction_or_route_specific_skeleton"
    if "/session/" in lower:
        return "local_session_authority_not_consensus_authority"
    if "/observer/edge" in lower or "/sync/" in lower or "relay" in module:
        return "node_or_observer_transport_authority_not_user_governance_authority"
    if upper == "GET":
        return "public_or_session_scoped_read_projection"
    return "route_specific_runtime_authority"


def _scan_route_contracts(
    tx_names: set[str],
    frontend_files: list[Path],
    test_files: list[Path],
    overrides: Json,
    stable_ids: StableIdRegistry,
) -> list[Json]:
    metadata = _route_metadata()
    override_map = overrides.get("routes") or {}
    rows: list[Json] = []
    for path in _scan_files(ROOT / "src" / "weall" / "api", {".py"}):
        try:
            tree, _functions = _module_cached(path)
        except (OSError, SyntaxError) as exc:
            raise CompileError(f"could not scan route source {_relative(path)}: {exc}") from exc
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            for decorator in node.decorator_list:
                if not isinstance(decorator, ast.Call):
                    continue
                func = decorator.func
                if not (
                    isinstance(func, ast.Attribute)
                    and isinstance(func.value, ast.Name)
                    and func.value.id == "router"
                    and func.attr in HTTP_METHODS
                ):
                    continue
                raw_path = _literal_string(decorator.args[0]) if decorator.args else ""
                method = func.attr.upper()
                full_path = _route_full_path(raw_path or "")
                route_key = f"{method} {full_path}"
                identity_key = f"{route_key}|{_relative(path)}|{node.name}"
                body_constants = _all_string_constants(node)
                mappings = sorted(tx_names.intersection(body_constants))
                if not mappings and "/tx/submit" in full_path.lower():
                    mappings = ["TX:*"]
                auth = _heuristic_route_authority(method, full_path, path.stem)
                meta = metadata.get(route_key) or {}
                authority = str(meta.get("auth") or auth)
                error_model = str(
                    meta.get("error_model")
                    or "standard_api_error_envelope_or_route_specific_failure_payload"
                )
                rate_limit = str(
                    meta.get("rate_limit_policy")
                    or "global_request_size_and_rate_limit_middleware_plus_route_specific_bounds"
                )
                frontend_hits = _search_files_for_token(frontend_files, full_path)
                if not frontend_hits:
                    frontend_hits = _search_files_for_token(frontend_files, raw_path or full_path)
                test_hits = _search_files_for_token(test_files, full_path)
                test_hits.extend(_search_files_for_token(test_files, node.name))
                row: Json = {
                    "stable_id": stable_ids.resolve("route", identity_key),
                    "route_key": route_key,
                    "method": method,
                    "path": full_path,
                    "authority_source": authority,
                    "canonical_mappings": mappings,
                    "local_or_service_status": (
                        "canonical_transaction_submission"
                        if mappings
                        else "service_projection_or_local_control_surface"
                    ),
                    "security_policy": {
                        "auth": authority,
                        "rate_limit": rate_limit,
                        "cache": str(
                            meta.get("cache_policy") or "no_store_dynamic_protocol_surface"
                        ),
                        "idempotency": str(
                            meta.get("idempotency")
                            or (
                                "canonical_tx_id_deduplication"
                                if mappings
                                else "route_specific_no_general_claim"
                            )
                        ),
                    },
                    "request_limits": rate_limit,
                    "failure_contract": error_model,
                    "frontend_consumers": sorted(set(frontend_hits)),
                    "tests": sorted(set(test_hits)) or ["tests/test_v2_spec_compiler.py"],
                    "implementation_source": {
                        "path": _relative(path),
                        "function": node.name,
                        "line": int(getattr(node, "lineno", 0) or 0),
                    },
                    "metadata_source": (
                        "specs/api_contracts/v1_5_route_metadata.json"
                        if route_key in metadata
                        else "compiler_static_inference"
                    ),
                    "semantic_precision": (
                        "explicit_metadata" if route_key in metadata else "static_route_inference"
                    ),
                    "primary_mechanism_id": "M-069",
                    "vector_ids": ["VEC-W1-COMPILER"],
                    "activation": {
                        "public_testnet": "disabled_pending_activation_receipt",
                        "mainnet": "disabled_pending_activation_receipt",
                    },
                }
                if isinstance(override_map, dict) and isinstance(override_map.get(route_key), dict):
                    row.update(override_map[route_key])
                rows.append(row)
    rows.sort(
        key=lambda item: (
            str(item["path"]),
            str(item["method"]),
            str(item["implementation_source"]["path"]),
            str(item["implementation_source"]["function"]),
        )
    )
    keys = [f"{row['method']} {row['path']}" for row in rows]
    counts: dict[str, int] = defaultdict(int)
    for key in keys:
        counts[key] += 1
    for row in rows:
        row["duplicate_route_key"] = counts[f"{row['method']} {row['path']}"] > 1
    return rows


def _handler_runtime_info(
    tx_type: str, txdef: Json, applier_rows: dict[str, Json]
) -> tuple[str, Path, str, str]:
    row = applier_rows.get(tx_type)
    if row is None:
        raise CompileError(f"canonical transaction has no declared applier: {tx_type}")
    numeric_id = int(txdef.get("id") or 0)
    if int(row.get("numeric_id") or 0) != numeric_id:
        raise CompileError(f"transaction applier numeric ID mismatch: {tx_type}")
    if str(row.get("domain") or "") != str(txdef.get("domain") or ""):
        raise CompileError(f"transaction applier domain mismatch: {tx_type}")
    handler = str(row.get("handler") or "").strip()
    source_path = (ROOT / str(row.get("path") or "")).resolve()
    dispatch_name = str(row.get("dispatch_function") or "").strip()
    mechanism_id = str(row.get("primary_mechanism_id") or "").strip()
    if not handler or not source_path.is_file() or not dispatch_name or not mechanism_id:
        raise CompileError(f"invalid transaction applier declaration: {tx_type}")
    _tree, functions = _module_cached(source_path)
    if dispatch_name not in functions:
        raise CompileError(
            f"declared transaction applier function missing: {tx_type} -> "
            f"{_relative(source_path)}#{dispatch_name}"
        )
    return handler, source_path, dispatch_name, mechanism_id


def _tx_function_analysis(
    tx_type: str,
    source_path: Path,
    dispatch_name: str,
    tx_names: set[str],
    system_tx_names: set[str],
    domain_fallback: list[str],
) -> Json:
    tree, functions = _module_cached(source_path)
    dispatch = functions.get(dispatch_name)
    if dispatch is None:
        candidates = [fn for fn in functions.values() if tx_type in _all_string_constants(fn.node)]
        candidates.sort(key=lambda fn: fn.end_lineno - fn.lineno)
        dispatch = candidates[0] if candidates else None
    if dispatch is None:
        return {
            "function": dispatch_name,
            "line": 0,
            "state_reads": [f"namespace:{item}" for item in domain_fallback],
            "state_writes": [f"namespace:{item}" for item in domain_fallback],
            "failure_codes": [{"code": "runtime_apply_error", "reason": "see_handler"}],
            "return_keys": [],
            "system_followups": [],
            "semantic_precision": "domain_scope_fallback",
        }

    branch = _branch_for_tx(dispatch.node, tx_type)
    target = dispatch
    if branch is not None:
        calls = _direct_local_calls(branch, set(functions))
        preferred = [
            name
            for name in calls
            if name != dispatch.name and (name.startswith("apply_") or name.startswith("_apply_"))
        ]
        if preferred:
            target = functions[preferred[0]]

    queue = [target.name]
    visited: set[str] = set()
    nodes: list[ast.AST] = []
    while queue and len(visited) < 24:
        name = queue.pop(0)
        if name in visited or name not in functions:
            continue
        visited.add(name)
        fn = functions[name]
        nodes.append(fn.node)
        for called in _direct_local_calls(fn.node, set(functions)):
            if called in visited:
                continue
            if called.startswith(
                (
                    "apply_",
                    "_apply_",
                    "_require_",
                    "_open_",
                    "_close_",
                    "_finalize_",
                    "_snapshot_",
                    "_normalized_",
                    "_find_",
                    "_ensure_",
                )
            ):
                queue.append(called)

    reads: set[str] = set()
    writes: set[str] = set()
    failures: dict[tuple[str, str], Json] = {}
    return_keys: set[str] = set()
    referenced_txs: set[str] = set()
    for node in nodes:
        node_reads, node_writes = _extract_key_tokens(node)
        reads.update(node_reads)
        writes.update(node_writes)
        for failure in _extract_failures(node):
            failures[(str(failure["code"]), str(failure["reason"]))] = failure
        return_keys.update(_extract_return_keys(node))
        referenced_txs.update(tx_names.intersection(_all_string_constants(node)))

    if not reads:
        reads.update(f"namespace:{item}" for item in domain_fallback)
    if not writes:
        writes.update(f"namespace:{item}" for item in domain_fallback)
    if not failures:
        failures[("runtime_apply_error", "see_handler")] = {
            "code": "runtime_apply_error",
            "reason": "see_handler",
        }
    precision = "tx_specific_static" if target.name != dispatch.name else "function_static"
    if all(item.startswith("namespace:") for item in reads | writes):
        precision = "domain_scope_fallback"
    return {
        "function": target.name,
        "line": target.lineno,
        "state_reads": sorted(
            f"key:{item}" if not item.startswith("namespace:") else item for item in reads
        ),
        "state_writes": sorted(
            f"key:{item}" if not item.startswith("namespace:") else item for item in writes
        ),
        "failure_codes": [failures[key] for key in sorted(failures)],
        "return_keys": sorted(return_keys),
        "system_followups": sorted((referenced_txs - {tx_type}).intersection(system_tx_names)),
        "semantic_precision": precision,
    }


def _gate_fields(gate: str) -> tuple[str, str]:
    cleaned = str(gate or "").strip()
    if cleaned.startswith("Tier"):
        return cleaned, "none"
    return "none", cleaned or "none"


def _scan_transaction_contracts(
    tx_canon: Json,
    profiles: Json,
    registry: Json,
    overrides: Json,
    routes: list[Json],
    frontend_files: list[Path],
    test_files: list[Path],
    stable_ids: StableIdRegistry,
    tx_appliers: Json,
) -> list[Json]:
    raw_txs = tx_canon.get("txs") or []
    if not isinstance(raw_txs, list):
        raise CompileError("transaction canon txs must be a list")
    tx_defs = [row for row in raw_txs if isinstance(row, dict)]
    tx_names = {str(row.get("name") or "").strip().upper() for row in tx_defs}
    system_tx_names = {
        str(row.get("name") or "").strip().upper()
        for row in tx_defs
        if str(row.get("origin") or "").strip().upper() == "SYSTEM"
    }
    applier_rows = {
        str(row.get("tx_type") or "").strip().upper(): row
        for row in tx_appliers.get("rows") or []
        if isinstance(row, dict)
    }
    if set(applier_rows) != tx_names:
        raise CompileError(
            "transaction applier registry drift: "
            f"missing={sorted(tx_names - set(applier_rows))} "
            f"extra={sorted(set(applier_rows) - tx_names)}"
        )
    children_by_parent: dict[str, list[str]] = defaultdict(list)
    for row in tx_defs:
        parent = str(row.get("parent") or "").strip().upper()
        name = str(row.get("name") or "").strip().upper()
        if parent and name:
            children_by_parent[parent].append(name)
    route_by_tx: dict[str, list[str]] = defaultdict(list)
    for route in routes:
        key = f"{route['method']} {route['path']}"
        for mapping in route.get("canonical_mappings") or []:
            if mapping in tx_names:
                route_by_tx[str(mapping)].append(key)
    state_namespaces = registry.get("state_namespaces") or {}
    migration_default = str(
        registry.get("migration_default") or "explicit_versioned_migration_required"
    )
    override_map = overrides.get("transactions") or {}
    rows: list[Json] = []
    for txdef in sorted(tx_defs, key=lambda item: int(item.get("id") or 0)):
        tx_type = str(txdef.get("name") or "").strip().upper()
        numeric_id = int(txdef.get("id") or 0)
        domain = str(txdef.get("domain") or "")
        origin = str(txdef.get("origin") or "").strip().upper()
        context = str(txdef.get("context") or "")
        gate = str(txdef.get("gate") or txdef.get("subject_gate") or "")
        handler, source_path, dispatch_name, mechanism_id = _handler_runtime_info(
            tx_type, txdef, applier_rows
        )
        fallback = [str(item) for item in state_namespaces.get(domain, [])]
        analysis = _tx_function_analysis(
            tx_type,
            source_path,
            dispatch_name,
            tx_names,
            system_tx_names,
            fallback or [domain.lower()],
        )
        poh_gate, role_gate = _gate_fields(gate)
        signer = (
            "SYSTEM"
            if origin == "SYSTEM"
            else ("validator_envelope_signer" if origin == "VALIDATOR" else "envelope_signer")
        )
        authority = (
            "canonical_scheduler_or_parent_bound_system_authority"
            if origin == "SYSTEM"
            else f"origin:{origin};subject_gate:{gate or 'none'};runtime_handler:{handler}"
        )
        system_followups = sorted(
            set(analysis["system_followups"]) | set(children_by_parent.get(tx_type, []))
        )
        frontend_hits = _search_files_for_token(frontend_files, tx_type)
        test_hits = _search_files_for_token(test_files, tx_type)
        if not test_hits:
            test_hits = ["tests/test_tx_contract_coverage.py", "tests/test_v2_spec_compiler.py"]
        receipt_kind = (
            "receipt_only_parent_bound"
            if bool(txdef.get("receipt_only", False))
            else ("system_apply_result" if origin == "SYSTEM" else "user_transaction_apply_result")
        )
        row: Json = {
            "stable_id": stable_ids.resolve("transaction", tx_type),
            "numeric_id": numeric_id,
            "tx_type": tx_type,
            "domain": domain,
            "origin": origin,
            "context": context,
            "signer": signer,
            "authority": authority,
            "poh_gate": poh_gate,
            "role_gate": role_gate,
            "conflict_rules": {
                "source": "src/weall/runtime/tx_conflicts.py#build_conflict_descriptor",
                "family": handler,
                "requirement": (
                    "descriptor_must_be_deterministic_for_identical_canonical_envelopes"
                ),
            },
            "state_reads": analysis["state_reads"],
            "state_writes": analysis["state_writes"],
            "system_followups": system_followups,
            "receipt_contract": {
                "stable_id": stable_ids.resolve("receipt", tx_type),
                "kind": receipt_kind,
                "parent": str(txdef.get("parent") or "") or None,
                "return_fields": analysis["return_keys"],
            },
            "failure_codes": analysis["failure_codes"],
            "replay_behavior": (
                "block_only_parent_and_context_bound_deterministic_replay"
                if context == "block"
                else "mempool_admission_then_block_revalidation_with_nonce_and_tx_id_deduplication"
            ),
            "api_routes": sorted(set(route_by_tx.get(tx_type, []))),
            "frontend_surfaces": frontend_hits,
            "tests": sorted(set(test_hits)),
            "activation": _activation_for_tx(tx_type, profiles),
            "migration_treatment": migration_default,
            "implementation_source": {
                "handler": handler,
                "path": _relative(source_path),
                "function": analysis["function"],
                "line": analysis["line"],
            },
            "schema_source": "src/weall/runtime/tx_schema.py#model_for_tx_type",
            "semantic_precision": analysis["semantic_precision"],
            "primary_mechanism_id": mechanism_id,
            "vector_ids": ["VEC-W1-COMPILER"],
        }
        if isinstance(override_map, dict) and isinstance(override_map.get(tx_type), dict):
            row.update(override_map[tx_type])
        rows.append(row)
    return rows


def _state_index(
    tx_rows: list[Json], registry: Json, stable_ids: StableIdRegistry
) -> list[Json]:
    usage: dict[tuple[str, str], Json] = {}
    declared = registry.get("state_namespaces") or {}
    mechanism_by_domain = {
        str(row["domain"]): str(row["primary_mechanism_id"]) for row in tx_rows
    }
    for domain, namespaces in declared.items():
        for namespace in namespaces or []:
            key = (str(domain), str(namespace))
            usage[key] = {
                "domain": str(domain),
                "token": str(namespace),
                "reads_by": set(),
                "writes_by": set(),
                "mutators": set(),
                "source": "specs/v2/source/protocol_registry.json",
                "precision": "declared_namespace",
            }
    for row in tx_rows:
        domain = str(row["domain"])
        source = row["implementation_source"]
        for access, field in (("reads_by", "state_reads"), ("writes_by", "state_writes")):
            for token in row.get(field) or []:
                clean = str(token).split(":", 1)[-1]
                key = (domain, clean)
                rec = usage.setdefault(
                    key,
                    {
                        "domain": domain,
                        "token": clean,
                        "reads_by": set(),
                        "writes_by": set(),
                        "mutators": set(),
                        "source": str(source["path"]),
                        "precision": str(row["semantic_precision"]),
                    },
                )
                rec[access].add(str(row["stable_id"]))
                if access == "writes_by":
                    rec["mutators"].add(f"{source['path']}#{source['function']}")
    rows: list[Json] = []
    for (domain, token), rec in sorted(usage.items()):
        key = f"{domain}:{token}"
        rows.append(
            {
                "stable_id": stable_ids.resolve("state", key),
                "domain": domain,
                "state_key_or_namespace": token,
                "key_encoding": "canonical_utf8_namespace_or_runtime_declared_composite_key",
                "value_schema": "runtime_state_schema_current_snapshot; exact versioned schema review required",
                "creation_contracts": sorted(rec["writes_by"]),
                "transition_contracts": sorted(rec["writes_by"]),
                "reads_by": sorted(rec["reads_by"]),
                "writes_by": sorted(rec["writes_by"]),
                "mutators": sorted(rec["mutators"]),
                "invariants": [
                    "identical_pre_state_and_canonical_input_produce_identical_post_state",
                    "failed_transition_must_not_leave_partial_state",
                ],
                "failure_semantics": "typed_transaction_failure_with_atomic_rollback",
                "migration_behavior": "versioned_migration_or_forward_repair_required_for_shape_change",
                "replay_behavior": "canonical_block_replay_must_reproduce_identical_value_bytes",
                "vector_ids": ["VEC-W1-COMPILER"],
                "primary_mechanism_id": mechanism_by_domain.get(domain, "M-012"),
                "source": rec["source"],
                "semantic_precision": rec["precision"],
                "status": "current_partial",
            }
        )
    return rows


def _message_index(
    registry: Json, stable_ids: StableIdRegistry, source_mappings: Json
) -> list[Json]:
    cfg = registry.get("message_scan") or {}
    suffixes = tuple(str(item) for item in cfg.get("class_suffixes") or MESSAGE_SUFFIXES_DEFAULT)
    function_tokens = tuple(str(item).lower() for item in cfg.get("function_tokens") or [])
    mapping_by_path = {
        str(row.get("path") or ""): str(row.get("primary_mechanism_id") or "")
        for row in source_mappings.get("mappings") or []
        if isinstance(row, dict)
    }
    rows: dict[tuple[str, str, str], Json] = {}
    for raw_root in cfg.get("roots") or []:
        root = ROOT / str(raw_root)
        if not root.exists():
            continue
        for path in _scan_files(root, {".py"}):
            try:
                tree, _functions = _module_cached(path)
            except (OSError, SyntaxError):
                continue
            for node in ast.walk(tree):
                kind = ""
                fields: list[str] = []
                if isinstance(node, ast.ClassDef) and node.name.endswith(suffixes):
                    kind = "class_contract"
                    fields = sorted(
                        {
                            child.target.id
                            for child in node.body
                            if isinstance(child, ast.AnnAssign)
                            and isinstance(child.target, ast.Name)
                        }
                    )
                elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                    lowered = node.name.lower()
                    if function_tokens and any(token in lowered for token in function_tokens):
                        kind = "message_builder_or_handler"
                        fields = _extract_return_keys(node)
                if not kind:
                    continue
                rel = _relative(path)
                key = (rel, node.name, kind)
                canonical_key = ":".join(key)
                rows[key] = {
                    "stable_id": stable_ids.resolve("message", canonical_key),
                    "name": node.name,
                    "kind": kind,
                    "source": rel,
                    "line": int(getattr(node, "lineno", 0) or 0),
                    "fields": fields,
                    "wire_encoding": "canonical_json_or_declared_binary_profile_at_source",
                    "authority_boundary": "transport_or_consensus_message; validity derives from exact verification rules, not delivery source",
                    "replay_rules": "domain_context_sender_and_logical_position_binding_required",
                    "idempotency_rules": "duplicate delivery must not create duplicate canonical effects",
                    "failure_semantics": "malformed_or_unverifiable_message_rejected_without_state_divergence",
                    "vector_ids": ["VEC-W1-COMPILER"],
                    "primary_mechanism_id": mapping_by_path.get(rel, "M-018"),
                    "status": "current_partial",
                }
    return [rows[key] for key in sorted(rows)]


def _scheduler_index(
    registry: Json,
    tx_rows: list[Json],
    stable_ids: StableIdRegistry,
    source_mappings: Json,
) -> list[Json]:
    cfg = registry.get("scheduler_scan") or {}
    tokens = tuple(str(item).lower() for item in cfg.get("function_tokens") or [])
    system_names = {
        str(row["tx_type"]) for row in tx_rows if str(row.get("origin") or "") == "SYSTEM"
    }
    mapping_by_path = {
        str(row.get("path") or ""): str(row.get("primary_mechanism_id") or "")
        for row in source_mappings.get("mappings") or []
        if isinstance(row, dict)
    }
    rows: dict[tuple[str, str], Json] = {}
    for raw_root in cfg.get("roots") or []:
        root = ROOT / str(raw_root)
        if not root.exists():
            continue
        for path in _scan_files(root, {".py"}):
            try:
                tree, _functions = _module_cached(path)
            except (OSError, SyntaxError):
                continue
            for node in ast.walk(tree):
                if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                    continue
                lowered = node.name.lower()
                emitted = sorted(system_names.intersection(_all_string_constants(node)))
                if not emitted and not any(token in lowered for token in tokens):
                    continue
                rel = _relative(path)
                key = (rel, node.name)
                canonical_key = ":".join(key)
                rows[key] = {
                    "stable_id": stable_ids.resolve("scheduler", canonical_key),
                    "name": node.name,
                    "source": rel,
                    "line": int(getattr(node, "lineno", 0) or 0),
                    "emitted_system_transactions": emitted,
                    "due_predicate": "source_bound_finalized_state_and_height_predicate",
                    "ordering_contract": "canonical_scheduler_pipeline_order_then_stable_identifier_order",
                    "idempotency_key": "stable_sys_id_plus_due_height_plus_subject_or_parent_identity",
                    "idempotency_contract": "identical_finalized_state_and_height_must_derive_identical_due_work",
                    "replay_behavior": "replay_derives_or_validates_identical_parent_bound_work_without_operator_discretion",
                    "retry_behavior": "failed_due_work_remains explicit_or_emits_typed_failure_without_silent_drop",
                    "failure_semantics": "typed_scheduler_or_system_transaction_failure",
                    "vector_ids": ["VEC-W1-COMPILER"],
                    "primary_mechanism_id": mapping_by_path.get(rel, "M-012"),
                    "semantic_precision": "static_function_inventory",
                    "status": "current_partial",
                }
    return [rows[key] for key in sorted(rows)]


def _failure_index(
    tx_rows: list[Json], route_rows: list[Json], stable_ids: StableIdRegistry
) -> list[Json]:
    usage: dict[tuple[str, str], Json] = {}
    for row in tx_rows:
        for failure in row.get("failure_codes") or []:
            code = str(failure.get("code") or "runtime_apply_error")
            reason = str(failure.get("reason") or "runtime_apply_failure")
            key = (code, reason)
            rec = usage.setdefault(key, {"tx": set(), "routes": set()})
            rec["tx"].add(str(row["stable_id"]))
    for route in route_rows:
        contract = str(route.get("failure_contract") or "route_specific_failure")
        key = ("api_failure_contract", contract)
        rec = usage.setdefault(key, {"tx": set(), "routes": set()})
        rec["routes"].add(str(route["stable_id"]))
    rows: list[Json] = []
    for (code, reason), rec in sorted(usage.items()):
        canonical_key = f"{code}:{reason}"
        rows.append(
            {
                "stable_id": stable_ids.resolve("failure", canonical_key),
                "code": code,
                "reason_or_contract": reason,
                "category": "api" if code == "api_failure_contract" else "canonical_transaction",
                "retryable": False,
                "severity": "request_or_transaction_rejection",
                "state_mutation_guarantee": "no_partial_canonical_state_on_failure",
                "http_mapping": "route_specific" if code == "api_failure_contract" else None,
                "transactions": sorted(rec["tx"]),
                "routes": sorted(rec["routes"]),
                "vector_ids": ["VEC-W1-COMPILER"],
                "primary_mechanism_id": "M-012",
                "status": "current_partial",
            }
        )
    return rows


def _evidence_index(
    evidence_manifest: Json, stable_ids: StableIdRegistry
) -> list[Json]:
    rows: list[Json] = []
    seen_paths: set[str] = set()
    seen_ids: set[str] = set()
    for declared in evidence_manifest.get("entries") or []:
        if not isinstance(declared, dict):
            raise CompileError("evidence manifest entries must be objects")
        rel = str(declared.get("path") or "").strip()
        if not rel or rel in seen_paths:
            raise CompileError(f"invalid or duplicate evidence path: {rel}")
        path = (ROOT / rel).resolve()
        if not path.is_file():
            raise CompileError(f"declared evidence artifact missing: {rel}")
        declared_id = str(declared.get("id") or "").strip()
        if declared_id.startswith("EVD-W1-"):
            stable_id = stable_ids.resolve("evidence", declared_id)
        else:
            stable_id = stable_ids.resolve("evidence", rel)
            if declared_id and declared_id != stable_id:
                raise CompileError(f"evidence stable ID mismatch: {rel}")
        if stable_id in seen_ids:
            raise CompileError(f"duplicate evidence stable ID: {stable_id}")
        seen_paths.add(rel)
        seen_ids.add(stable_id)
        rows.append(
            {
                "stable_id": stable_id,
                "path": rel,
                "sha256": _sha256_file(path),
                "kind": str(declared.get("kind") or "evidence_artifact"),
                "claim": str(declared.get("claim") or "scoped implementation evidence"),
                "reviewer": str(declared.get("reviewer") or "IMPLEMENTATION_REVIEW_PENDING"),
                "activation_receipt": declared.get("activation_receipt"),
                "required_external_review": bool(
                    declared.get("required_external_review", False)
                ),
                "activation_authority": False,
                "primary_mechanism_id": "M-076",
                "truth_boundary": "Evidence supports a scoped claim only; it does not activate protocol authority by itself.",
                "status": "current_implemented",
            }
        )
    return sorted(rows, key=lambda row: str(row["stable_id"]))


def _source_category(path: Path) -> str:
    rel = _relative(path)
    if rel.startswith("src/weall/runtime/"):
        return "runtime"
    if rel.startswith("src/weall/api/"):
        return "api"
    if rel.startswith("src/weall/crypto/"):
        return "crypto"
    if rel.startswith("src/weall/"):
        return "protocol_library"
    if rel.startswith("scripts/") or rel.startswith("tooling/"):
        return "tooling"
    if rel.startswith("tests/"):
        return "test"
    if rel.startswith("../web/src/"):
        return "frontend"
    if rel.startswith("../web/scripts/") or rel.startswith("../web/tests/"):
        return "frontend_test_or_tooling"
    if rel.startswith("generated/"):
        return "evidence"
    if rel.startswith("docs/"):
        return "documentation"
    return "unmapped"


def _source_coverage(
    manifest: Json,
    tx_rows: list[Json],
    route_rows: list[Json],
    state_rows: list[Json],
    message_rows: list[Json],
    scheduler_rows: list[Json],
    evidence_rows: list[Json],
    source_mappings: Json,
) -> Json:
    roots = manifest.get("scan_roots") or {}
    files: list[Path] = []
    for values in roots.values():
        for raw in values or []:
            base = (ROOT / str(raw)).resolve()
            if base.exists():
                files.extend(_scan_files(base, SUPPORTED_SOURCE_SUFFIXES))
    files = sorted(set(files))
    excluded_rows = [
        row
        for row in source_mappings.get("excluded_local_artifacts") or []
        if isinstance(row, dict)
    ]
    excluded_local: dict[str, Json] = {}
    for row in excluded_rows:
        rel = str(row.get("path") or "").strip()
        if not rel or rel in excluded_local:
            raise CompileError(f"invalid or duplicate local-artifact exclusion: {rel}")
        if not rel.startswith("generated/") or rel.startswith("generated/v2/"):
            raise CompileError(
                f"local-artifact exclusions are restricted to non-v2 generated outputs: {rel}"
            )
        excluded_local[rel] = row
    exact = {
        str(row.get("path") or ""): row
        for row in source_mappings.get("mappings") or []
        if isinstance(row, dict)
    }
    rules = [
        row
        for row in source_mappings.get("explicit_non_protocol_rules") or []
        if isinstance(row, dict)
    ]
    declared_evidence = {str(row.get("path") or ""): row for row in evidence_rows}
    tx_by_source: dict[str, list[str]] = defaultdict(list)
    for row in tx_rows:
        tx_by_source[str(row["implementation_source"]["path"])].append(str(row["stable_id"]))
        for test in row.get("tests") or []:
            tx_by_source[str(test)].append(str(row["stable_id"]))
        for frontend in row.get("frontend_surfaces") or []:
            tx_by_source[str(frontend)].append(str(row["stable_id"]))
    route_by_source: dict[str, list[str]] = defaultdict(list)
    for row in route_rows:
        route_by_source[str(row["implementation_source"]["path"])].append(str(row["stable_id"]))
        for test in row.get("tests") or []:
            route_by_source[str(test)].append(str(row["stable_id"]))
        for frontend in row.get("frontend_consumers") or []:
            route_by_source[str(frontend)].append(str(row["stable_id"]))
    extra_by_source: dict[str, list[str]] = defaultdict(list)
    for collection in (state_rows, message_rows, scheduler_rows, evidence_rows):
        for row in collection:
            source = str(row.get("source") or row.get("path") or "")
            if source:
                extra_by_source[source].append(str(row["stable_id"]))
    rows: list[Json] = []
    unmapped: list[str] = []
    excluded_declared = sorted(
        [
            {
                "path": rel,
                "classification": str(
                    row.get("classification")
                    or "ignored_local_generated_artifact"
                ),
                "reason": str(row.get("reason") or ""),
            }
            for rel, row in excluded_local.items()
        ],
        key=lambda row: str(row["path"]),
    )
    for path in files:
        rel = _relative(path)
        if rel in excluded_local:
            continue
        explicit = exact.get(rel)
        classification = ""
        mechanism_id = ""
        affected_registers: list[str] = []
        if explicit is not None:
            classification = str(explicit.get("classification") or "")
            mechanism_id = str(explicit.get("primary_mechanism_id") or "")
            affected_registers = sorted(
                {str(item) for item in explicit.get("affected_registers") or []}
            )
        elif rel.startswith("specs/v2/source/"):
            classification = "singular_specification_source"
            mechanism_id = "M-076"
            affected_registers = ["all_generated_derivatives"]
        elif rel in declared_evidence:
            classification = "declared_evidence"
            mechanism_id = "M-076"
            affected_registers = ["evidence"]
        else:
            for rule in rules:
                pattern = str(rule.get("glob") or "")
                if pattern and fnmatch.fnmatch(rel, pattern):
                    classification = str(rule.get("classification") or "explicit_utility")
                    mechanism_id = str(rule.get("primary_mechanism_id") or "")
                    affected_registers = ["non_protocol_utility"]
                    break
        mappings = sorted(
            set(tx_by_source.get(rel, []))
            | set(route_by_source.get(rel, []))
            | set(extra_by_source.get(rel, []))
        )
        if mechanism_id:
            mappings.append(mechanism_id)
        mappings = sorted(set(mappings))
        if not classification or not mechanism_id or not mappings:
            unmapped.append(rel)
        rows.append(
            {
                "source_id": _stable_id("SRC", rel),
                "path": rel,
                "classification": classification or "unmapped",
                "primary_mechanism_id": mechanism_id or None,
                "affected_registers": affected_registers,
                "sha256": _sha256_file(path),
                "mappings": mappings,
            }
        )
    missing_exact = sorted(
        rel for rel in exact if not (ROOT / rel).resolve().is_file()
    )
    if missing_exact:
        raise CompileError(f"stale exact source mappings: {missing_exact[:25]}")
    return {
        "schema": "weall.v2.source_coverage_map",
        "version": str(manifest.get("version") or ""),
        "file_count": len(rows),
        "unmapped_count": len(unmapped),
        "unmapped": sorted(unmapped),
        "excluded_local_artifacts": excluded_declared,
        "files": rows,
    }


def _schema_for(name: str, required: list[str]) -> Json:
    string = {"type": "string", "minLength": 1}
    string_array = {"type": "array", "items": string, "uniqueItems": True}
    object_value = {"type": "object"}
    common: dict[str, Json] = {
        "stable_id": {"type": "string", "pattern": "^[A-Z][A-Z0-9-]+$"},
        "id": {"type": "string", "pattern": "^[A-Z][A-Z0-9-]+$"},
        "numeric_id": {"type": "integer", "minimum": 1},
        "tx_type": {"type": "string", "pattern": "^[A-Z0-9_]+$"},
        "domain": string,
        "method": {"type": "string", "enum": sorted(method.upper() for method in HTTP_METHODS)},
        "path": string,
        "authority_source": string,
        "canonical_mappings": string_array,
        "local_or_service_status": string,
        "security_policy": object_value,
        "request_limits": string,
        "failure_contract": string,
        "frontend_consumers": string_array,
        "tests": string_array,
        "implementation_source": {
            "type": "object",
            "required": ["path", "function", "line"],
            "properties": {
                "path": string,
                "function": string,
                "line": {"type": "integer", "minimum": 0},
                "handler": string,
            },
            "additionalProperties": False,
        },
        "signer": string,
        "authority": string,
        "poh_gate": string,
        "role_gate": string,
        "conflict_rules": object_value,
        "state_reads": string_array,
        "state_writes": string_array,
        "system_followups": string_array,
        "receipt_contract": object_value,
        "failure_codes": {"type": "array", "items": object_value},
        "replay_behavior": string,
        "api_routes": string_array,
        "frontend_surfaces": string_array,
        "activation": object_value,
        "migration_treatment": string,
        "semantic_precision": string,
        "semantic_derivation": string,
        "semantic_review": object_value,
        "primary_mechanism_id": {"type": "string", "pattern": "^M-[0-9]{3}$"},
        "vector_ids": {"type": "array", "items": {"type": "string", "pattern": "^VEC-"}, "minItems": 1, "uniqueItems": True},
    }
    properties = {field: common.get(field, {}) for field in required}
    if name == "tx_contract":
        properties.update({
            "origin": string,
            "context": string,
            "schema_source": string,
        })
    elif name == "route_contract":
        properties.update({
            "route_key": string,
            "metadata_source": string,
            "semantic_precision": string,
            "duplicate_route_key": {"type": "boolean"},
        })
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"https://weall.example/spec/v2/{name}.schema.json",
        "title": name,
        "type": "object",
        "required": required,
        "additionalProperties": False,
        "properties": properties,
    }


def _render_frontend_status(
    profiles: Json, manifest: Json, provenance: Json, source_tree_digest: str
) -> bytes:
    status = dict(profiles.get("frontend_status") or {})
    status["normativePdfSha256"] = str(
        provenance.get("normative_specification", {}).get("sha256") or ""
    )
    status["repositorySnapshot"] = str(
        provenance.get("repository", {}).get("specification_snapshot") or ""
    )
    status["sourceTreeDigest"] = source_tree_digest
    lines = [
        "// Generated by scripts/compile_v2_spec.py. Do not edit by hand.",
        f'export const WEALL_SPEC_VERSION = {json.dumps(str(manifest.get("version") or ""))} as const;',
        "export const WEALL_PROTOCOL_STATUS = "
        + json.dumps(status, indent=2, sort_keys=True)
        + " as const;",
        "export type WeAllProtocolStatus = typeof WEALL_PROTOCOL_STATUS;",
        "",
    ]
    return "\n".join(lines).encode("utf-8")


def _render_derivative(
    manifest: Json,
    provenance: Json,
    register_counts: dict[str, int],
    tx_rows: list[Json],
    route_rows: list[Json],
    coverage: Json,
    source_tree_digest: str,
) -> bytes:
    fallback_txs = sum(1 for row in tx_rows if row["semantic_precision"] == "domain_scope_fallback")
    explicit_routes = sum(
        1 for row in route_rows if row["semantic_precision"] == "explicit_metadata"
    )
    spec = provenance.get("normative_specification") or {}
    repo = provenance.get("repository") or {}
    lines = [
        "# WeAll v2 machine-readable specification derivative",
        "",
        f"Compiler source version: `{manifest.get('version')}`",
        f"Normative candidate: `{spec.get('candidate')}`",
        f"Normative PDF SHA-256: `{spec.get('sha256')}`",
        f"Repository: `{repo.get('url')}`",
        f"Specification snapshot: `{repo.get('specification_snapshot')}`",
        f"Source-tree digest: `{source_tree_digest}`",
        "",
        "This derivative is generated from the singular source tree. It proves W1 mechanism coverage and derivative consistency only; it is not a production-readiness or runtime-correctness certificate.",
        "",
        "## Registers",
        "",
    ]
    for name, count in sorted(register_counts.items()):
        lines.append(f"- {name.replace('_', ' ').title()}: **{count}**")
    lines.extend(
        [
            f"- Covered source files: **{coverage['file_count']}**",
            f"- Unmapped source files: **{coverage['unmapped_count']}**",
            "",
            "## Semantic-review boundary",
            "",
            f"- Transaction rows using domain-scope fallback: **{fallback_txs}**",
            f"- Routes backed by explicit route metadata: **{explicit_routes}**",
            "- Complete register shape does not assert that every runtime mechanism already matches the production target.",
            "- Public testnet and mainnet authority remain disabled pending explicit activation receipts and applicable independent review.",
            "",
        ]
    )
    return "\n".join(lines).encode("utf-8")


def _validate_required_fields(rows: list[Json], required: list[str], kind: str) -> None:
    missing: list[str] = []
    for row in rows:
        identity = str(row.get("tx_type") or f"{row.get('method')} {row.get('path')}")
        for field in required:
            if field not in row:
                missing.append(f"{identity}:{field}")
    if missing:
        raise CompileError(f"{kind} rows missing required fields: {missing[:25]}")


def _source_input_hashes(manifest: Json) -> dict[str, str]:
    out: dict[str, str] = {}
    inputs = manifest.get("inputs") or {}
    for name, raw in sorted(inputs.items()):
        path = (ROOT / str(raw)).resolve()
        if not path.is_file():
            raise CompileError(f"declared source input missing: {raw}")
        out[str(name)] = _sha256_file(path)
    return out


def _source_tree_digest(coverage: Json) -> str:
    material = [
        {"path": row["path"], "sha256": row["sha256"]}
        for row in coverage.get("files") or []
    ]
    return _sha256_bytes(_canonical_json(material))


def _receipt_index(tx_rows: list[Json]) -> list[Json]:
    rows: list[Json] = []
    for tx in tx_rows:
        receipt = tx["receipt_contract"]
        rows.append(
            {
                "stable_id": receipt["stable_id"],
                "transaction_id": tx["stable_id"],
                "tx_type": tx["tx_type"],
                "kind": receipt["kind"],
                "parent": receipt.get("parent"),
                "fields": receipt.get("return_fields") or [],
                "domain_separation": "chain_id_protocol_profile_tx_type_parent_or_block_context",
                "replay_binding": tx["replay_behavior"],
                "failure_representation": "typed_failure_contract_reference_or_success_payload",
                "primary_mechanism_id": tx["primary_mechanism_id"],
                "vector_ids": tx["vector_ids"],
                "status": "current_partial",
            }
        )
    return rows


def _validate_registry_ids(rows: list[Json], field: str, kind: str) -> None:
    values = [str(row.get(field) or "") for row in rows]
    if any(not value for value in values):
        raise CompileError(f"{kind} rows contain empty identifiers")
    if len(values) != len(set(values)):
        raise CompileError(f"{kind} identifiers are not unique")


def _typed_record_schema(name: str, required: list[str], properties: Json) -> Json:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"https://weall.example/spec/v2/{name}.schema.json",
        "title": name,
        "type": "object",
        "required": required,
        "additionalProperties": False,
        "properties": properties,
    }


def _field_schema(field: str) -> Json:
    nonempty_string = {"type": "string", "minLength": 1}
    string_array = {
        "type": "array",
        "items": nonempty_string,
        "uniqueItems": True,
    }
    array_fields = {
        "affected_registers",
        "closure_evidence",
        "contract_ids",
        "creation_contracts",
        "dependencies",
        "emitted_system_transactions",
        "evidence_ids",
        "fields",
        "implementation_paths",
        "invariants",
        "mappings",
        "mutators",
        "profiles",
        "repository_evidence_paths",
        "required_evidence",
        "routes",
        "specification_sections",
        "tests",
        "transactions",
        "transition_contracts",
        "vector_ids",
    }
    boolean_fields = {
        "activation_authority",
        "required_external_review",
        "retryable",
    }
    integer_fields = {"line", "numeric_id"}
    nullable_string_fields = {"activation_receipt", "http_mapping", "parent"}
    object_fields = {
        "activation_boundary",
        "coverage",
        "input_hashes",
        "output_hashes",
        "provenance",
        "registers",
        "requirements",
    }
    if field in array_fields:
        return string_array
    if field in boolean_fields:
        return {"type": "boolean"}
    if field in integer_fields:
        return {"type": "integer", "minimum": 0}
    if field in nullable_string_fields:
        return {"type": ["string", "null"]}
    if field == "value":
        return {"type": ["string", "integer", "boolean", "array", "object", "null"]}
    if field in object_fields:
        return {"type": "object"}
    if field == "sha256":
        return {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    if field in {"id", "stable_id", "source_id"}:
        return {"type": "string", "pattern": "^[A-Z][A-Z0-9-]+$"}
    if field == "primary_mechanism_id":
        return {"type": ["string", "null"], "pattern": "^M-[0-9]{3}$"}
    return nonempty_string


def _schema_from_values(field: str, values: list[Any]) -> Json:
    non_null = [value for value in values if value is not None]
    allows_null = len(non_null) != len(values)
    if not non_null:
        return {"type": ["string", "null"]}
    if all(isinstance(value, bool) for value in non_null):
        return {"type": ["boolean", "null"] if allows_null else "boolean"}
    if all(isinstance(value, int) and not isinstance(value, bool) for value in non_null):
        return {
            "type": ["integer", "null"] if allows_null else "integer",
            "minimum": 0,
        }
    if all(isinstance(value, str) for value in non_null):
        schema = _field_schema(field)
        if any(value == "" for value in non_null):
            schema = dict(schema)
            schema.pop("minLength", None)
        if allows_null:
            schema = dict(schema)
            schema["type"] = ["string", "null"]
        return schema
    if all(isinstance(value, list) for value in non_null):
        items = [item for value in non_null for item in value]
        item_schema: Json = {"type": "string", "minLength": 1}
        if items and all(isinstance(item, dict) for item in items):
            item_schema = {"type": "object"}
        elif items and all(isinstance(item, int) and not isinstance(item, bool) for item in items):
            item_schema = {"type": "integer"}
        schema = {"type": "array", "items": item_schema}
        if all(len(value) == len({json.dumps(item, sort_keys=True) for item in value}) for value in non_null):
            schema["uniqueItems"] = True
        return schema
    if all(isinstance(value, dict) for value in non_null):
        return {"type": ["object", "null"] if allows_null else "object"}
    return _field_schema(field)


def compile_artifacts() -> tuple[dict[Path, bytes], Json]:
    sources = _load_sources()
    manifest = sources["manifest"]
    profiles = sources["activation_profiles"]
    registry = sources["protocol_registry"]
    overrides = sources["contract_overrides"]
    tx_canon = sources["transaction_canon"]
    stable_ids_payload = sources["stable_ids"]
    stable_ids = StableIdRegistry.from_payload(stable_ids_payload)
    stable_id_history = validate_stable_id_history(
        stable_ids_payload, sources["stable_id_baseline"]
    )
    provenance = sources["provenance"]
    provenance_binding = validate_provenance_binding(provenance)
    source_mappings = sources["source_mappings"]
    controlled = sources["controlled_enums"]
    controlled_statuses = [str(value) for value in controlled.get("status_category") or []]
    controlled_results = [str(value) for value in controlled.get("verification_result") or []]
    allowed_statuses = set(controlled_statuses)

    normative = provenance.get("normative_specification") or {}
    normative_path = (ROOT / str(normative.get("path") or "")).resolve()
    if not normative_path.is_file():
        raise CompileError("pinned normative PDF is missing")
    pdf_identity = _validate_exact_uploaded_pdf(
        normative_path,
        sources["pdf_identity"],
        provenance,
    )
    normative_hash = str(pdf_identity["validated_sha256"])

    requirement_rows = [dict(row) for row in sources["requirements"].get("requirements") or [] if isinstance(row, dict)]
    parameter_rows = [dict(row) for row in sources["parameters"].get("parameters") or [] if isinstance(row, dict)]
    mechanism_rows = [dict(row) for row in sources["mechanisms"].get("mechanisms") or [] if isinstance(row, dict)]
    state_rows = [dict(row) for row in sources["state_objects"].get("rows") or [] if isinstance(row, dict)]
    target_contract_rows = [dict(row) for row in sources["target_contracts"].get("rows") or [] if isinstance(row, dict)]
    target_failure_rows = [dict(row) for row in sources["target_failures"].get("rows") or [] if isinstance(row, dict)]

    expected = manifest.get("expected_counts") or {}
    exact_counts = {
        "requirements": len(requirement_rows),
        "parameters": len(parameter_rows),
        "mechanisms": len(mechanism_rows),
        "state_objects": len(state_rows),
        "target_tx": sum(row.get("namespace") == "TX" for row in target_contract_rows),
        "target_msg": sum(row.get("namespace") == "MSG" for row in target_contract_rows),
        "target_sys": sum(row.get("namespace") == "SYS" for row in target_contract_rows),
        "target_rcp": sum(row.get("namespace") == "RCP" for row in target_contract_rows),
        "target_failures": len(target_failure_rows),
    }
    for key, actual in exact_counts.items():
        wanted = int(expected.get(key) or 0)
        if actual != wanted:
            raise CompileError(f"{key} count mismatch: expected {wanted} found {actual}")

    _require_exact_ids(mechanism_rows, "id", [f"M-{number:03d}" for number in range(1, 79)], "mechanism")
    _require_exact_ids(
        target_contract_rows,
        "id",
        [f"TX:C310:{number:04d}" for number in range(1, 28)]
        + [f"MSG:C310:{number:04d}" for number in range(1, 10)]
        + [f"SYS:C310:{number:04d}" for number in range(1, 40)]
        + [f"RCP:C310:{number:04d}" for number in range(1, 76)],
        "target contract",
    )
    _require_exact_ids(target_failure_rows, "failure_id", [str(number) for number in range(1, 99)], "target failure")

    # Validate controlled row semantics before the immutable extraction oracle so
    # diagnostics remain specific even when an attacker also edits source rows.
    for rows, kind in (
        (requirement_rows, "requirement"),
        (parameter_rows, "parameter"),
        (mechanism_rows, "mechanism"),
        (state_rows, "state object"),
        (target_contract_rows, "target contract"),
        (target_failure_rows, "target failure"),
    ):
        _validate_controlled_statuses(rows, allowed_statuses, kind)
    _validate_requirement_results(requirement_rows, controlled)

    try:
        register_fingerprints = verify_pdf_extraction_attestation(
            extraction_manifest=sources["pdf_extraction_manifest"],
            attestation=sources["pdf_extraction_attestation"],
            pdf_sha256=normative_hash,
            registers={
                "requirements": (requirement_rows, "id"),
                "parameters": (parameter_rows, "id"),
                "mechanisms": (mechanism_rows, "id"),
                "state_objects": (state_rows, "stable_id"),
                "target_contracts": (target_contract_rows, "id"),
                "target_failures": (target_failure_rows, "stable_id"),
            },
            stable_baseline=sources["stable_id_baseline"],
        )
        extraction_cleanliness = validate_normative_cleanliness(
            {
                "requirements": requirement_rows,
                "mechanisms": mechanism_rows,
                "state_objects": state_rows,
                "target_contracts": target_contract_rows,
                "target_failures": target_failure_rows,
            }
        )
        structured_schema_validation = validate_structured_schemas(
            state_rows, target_contract_rows, target_failure_rows
        )
        mechanism_evidence_validation = validate_mechanism_evidence(
            ROOT, mechanism_rows
        )
    except ValueError as exc:
        raise CompileError(str(exc)) from exc

    tx_defs = [row for row in tx_canon.get("txs") or [] if isinstance(row, dict)]
    tx_names = {str(row.get("name") or "").strip().upper() for row in tx_defs}
    frontend_files = _scan_files(WORKSPACE_ROOT / "web" / "src", {".ts", ".tsx"})
    test_files = _scan_files(ROOT / "tests", {".py"})
    route_rows = _scan_route_contracts(tx_names, frontend_files, test_files, overrides, stable_ids)
    tx_rows = _scan_transaction_contracts(
        tx_canon,
        profiles,
        registry,
        overrides,
        route_rows,
        frontend_files,
        test_files,
        stable_ids,
        sources["transaction_appliers"],
    )
    try:
        semantic_review_validation = apply_semantic_reviews(
            tx_rows, route_rows, sources["semantic_reviews"]
        )
    except ValueError as exc:
        raise CompileError(str(exc)) from exc
    runtime_state_rows = _state_index(tx_rows, registry, stable_ids)
    message_rows = _message_index(registry, stable_ids, source_mappings)
    scheduler_rows = _scheduler_index(registry, tx_rows, stable_ids, source_mappings)
    receipt_rows = _receipt_index(tx_rows)
    failure_rows = _failure_index(tx_rows, route_rows, stable_ids)
    evidence_rows = _evidence_index(sources["evidence_manifest"], stable_ids)

    if len(tx_rows) != int(expected.get("transactions") or 0):
        raise CompileError(f"transaction count mismatch: expected {expected.get('transactions')} found {len(tx_rows)}")
    if len(route_rows) != int(expected.get("routes") or 0):
        raise CompileError(f"route count mismatch: expected {expected.get('routes')} found {len(route_rows)}")

    _validate_required_fields(tx_rows, [str(item) for item in manifest.get("required_transaction_fields") or []], "transaction")
    _validate_required_fields(route_rows, [str(item) for item in manifest.get("required_route_fields") or []], "route")

    evidence_by_id = {str(row["stable_id"]): row for row in evidence_rows}
    for requirement in requirement_rows:
        missing_evidence = [
            evidence_id for evidence_id in requirement.get("evidence_ids") or []
            if evidence_id not in evidence_by_id
        ]
        if missing_evidence:
            raise CompileError(f"requirement {requirement.get('id')} references missing evidence: {missing_evidence}")

    mechanism_ids = {str(row.get("id") or "") for row in mechanism_rows}
    mapped_paths: dict[str, list[str]] = defaultdict(list)
    for row in source_mappings.get("mappings") or []:
        if isinstance(row, dict):
            mapped_paths[str(row.get("primary_mechanism_id") or "")].append(str(row.get("path") or ""))
    for row in mechanism_rows:
        row["repository_evidence_paths"] = sorted(
            set(row.get("repository_evidence_paths") or [])
            | set(mapped_paths.get(str(row.get("id") or ""), []))
        )

    all_contract_rows = (
        tx_rows + route_rows + runtime_state_rows + state_rows + message_rows
        + scheduler_rows + receipt_rows + failure_rows + target_contract_rows
        + target_failure_rows
    )
    unknown_mechanisms = sorted({
        str(row.get("primary_mechanism_id") or "")
        for row in all_contract_rows
        if str(row.get("primary_mechanism_id") or "") not in mechanism_ids
    })
    if unknown_mechanisms:
        raise CompileError(f"contracts reference unknown mechanisms: {unknown_mechanisms}")

    coverage = _source_coverage(
        manifest,
        tx_rows,
        route_rows,
        runtime_state_rows,
        message_rows,
        scheduler_rows,
        evidence_rows,
        source_mappings,
    )
    if coverage["unmapped_count"]:
        raise CompileError(f"unmapped source files: {coverage['unmapped'][:50]}")

    divergence_rows = [dict(row) for row in sources["divergences"].get("divergences") or [] if isinstance(row, dict)]
    allowed_divergence_statuses = {
        str(value) for value in controlled.get("divergence_status") or []
    }
    invalid_divergence_statuses = sorted(
        {str(row.get("status") or "") for row in divergence_rows}
        - allowed_divergence_statuses
    )
    if invalid_divergence_statuses:
        raise CompileError(
            f"divergence rows use uncontrolled statuses: {invalid_divergence_statuses}"
        )
    try:
        divergence_closure_validation = validate_w1_divergence_closure(divergence_rows)
    except ValueError as exc:
        raise CompileError(str(exc)) from exc
    target_schema_rows = _target_schema_rows(target_contract_rows)
    vector_rows = _expanded_vector_rows(
        [dict(row) for row in sources["vectors"].get("vectors") or [] if isinstance(row, dict)],
        parameter_rows,
        state_rows,
        target_contract_rows,
        target_failure_rows,
    )

    for rows, field, kind in (
        (tx_rows, "stable_id", "transaction"),
        (route_rows, "stable_id", "route"),
        (runtime_state_rows, "stable_id", "runtime state inventory"),
        (state_rows, "stable_id", "state contract"),
        (message_rows, "stable_id", "message"),
        (scheduler_rows, "stable_id", "scheduler"),
        (receipt_rows, "stable_id", "receipt"),
        (failure_rows, "stable_id", "failure"),
        (target_contract_rows, "id", "target contract"),
        (target_failure_rows, "stable_id", "target failure"),
        (target_schema_rows, "id", "target contract schema"),
        (evidence_rows, "stable_id", "evidence"),
        (parameter_rows, "id", "parameter"),
        (requirement_rows, "id", "requirement"),
        (mechanism_rows, "id", "mechanism"),
        (divergence_rows, "id", "divergence"),
        (vector_rows, "id", "vector"),
    ):
        _validate_registry_ids(rows, field, kind)

    source_tree_digest = _source_tree_digest(coverage)
    common = {
        "version": manifest.get("version"),
        "truth_boundary": manifest.get("truth_boundary"),
        "provenance": {
            "normative_pdf_sha256": normative_hash,
            "normative_candidate": normative.get("candidate"),
            "normative_authority_status": normative.get("authority_status"),
            "repository_url": provenance.get("repository", {}).get("url"),
            "repository_snapshot": provenance.get("repository", {}).get("specification_snapshot"),
            "implementation_commit": provenance.get("repository", {}).get("implementation_commit"),
            "compiler_identity": provenance.get("compiler", {}).get("identity"),
            "compiler_version": provenance.get("compiler", {}).get("version"),
            "active_profile_set": provenance.get("active_profile_set") or [],
            "source_tree_digest": source_tree_digest,
        },
    }

    tx_payload = {
        "schema": "weall.v2.tx_contract_matrix", **common,
        "transaction_count": len(tx_rows),
        "required_fields": manifest.get("required_transaction_fields") or [],
        "semantic_review_complete": all(
            row.get("semantic_precision") == "explicit_maintainer_reviewed_contract"
            and isinstance(row.get("semantic_review"), dict)
            for row in tx_rows
        ),
        "rows": tx_rows,
    }
    route_payload = {
        "schema": "weall.v2.route_contract_map", **common,
        "route_count": len(route_rows),
        "unique_method_path_count": len({f"{row['method']} {row['path']}" for row in route_rows}),
        "duplicate_route_implementation_count": sum(1 for row in route_rows if row.get("duplicate_route_key")),
        "required_fields": manifest.get("required_route_fields") or [],
        "semantic_review_complete": all(
            row.get("semantic_precision") == "explicit_maintainer_reviewed_contract"
            and isinstance(row.get("semantic_review"), dict)
            for row in route_rows
        ),
        "routes": route_rows,
    }
    current_tx_canon = {
        "schema": "weall.v2.current_compatibility_tx_canon", **common,
        "authority_status": "compatibility_runtime_not_mainnet_target_canon",
        "count": len(tx_rows), "rows": tx_rows,
    }
    target_tx_rows = [row for row in target_contract_rows if row.get("namespace") == "TX"]
    target_tx_canon = {
        "schema": "weall.v2.target_tx_canon", **common,
        "authority_status": "normative_target_launch_gated",
        "count": len(target_tx_rows), "rows": target_tx_rows,
    }
    target_contract_canon = {
        "schema": "weall.v2.target_contract_canon", **common,
        "authority_status": "normative_target_launch_gated",
        "counts": {
            namespace: sum(row.get("namespace") == namespace for row in target_contract_rows)
            for namespace in ("TX", "MSG", "SYS", "RCP")
        },
        "count": len(target_contract_rows), "rows": target_contract_rows,
    }

    register_payloads: dict[str, Json] = {
        "current_tx_canon": current_tx_canon,
        "target_tx_canon": target_tx_canon,
        "target_contract_canon": target_contract_canon,
        "target_contract_schema_index": {"schema": "weall.v2.target_contract_schema_index", **common, "count": len(target_schema_rows), "rows": target_schema_rows},
        "target_failure_contract_index": {"schema": "weall.v2.target_failure_contract_index", **common, "count": len(target_failure_rows), "rows": target_failure_rows},
        "runtime_state_inventory": {"schema": "weall.v2.runtime_state_inventory", **common, "count": len(runtime_state_rows), "rows": runtime_state_rows},
        "tx_contract_matrix": tx_payload,
        "route_contract_map": route_payload,
        "source_coverage_map": coverage,
        "state_contract_index": {"schema": "weall.v2.state_contract_index", **common, "count": len(state_rows), "rows": state_rows},
        "message_contract_index": {"schema": "weall.v2.message_contract_index", **common, "count": len(message_rows), "rows": message_rows},
        "scheduler_contract_index": {"schema": "weall.v2.scheduler_contract_index", **common, "count": len(scheduler_rows), "rows": scheduler_rows},
        "receipt_contract_index": {"schema": "weall.v2.receipt_contract_index", **common, "count": len(receipt_rows), "rows": receipt_rows},
        "failure_contract_index": {"schema": "weall.v2.failure_contract_index", **common, "count": len(failure_rows), "rows": failure_rows},
        "parameter_registry": {"schema": "weall.v2.parameter_registry", **common, "count": len(parameter_rows), "rows": parameter_rows},
        "requirement_traceability": {"schema": "weall.v2.requirement_traceability", **common, "count": len(requirement_rows), "rows": requirement_rows},
        "mechanism_registry": {"schema": "weall.v2.mechanism_registry", **common, "count": len(mechanism_rows), "rows": mechanism_rows},
        "divergence_registry": {"schema": "weall.v2.divergence_registry", **common, "count": len(divergence_rows), "rows": divergence_rows},
        "vector_registry": {"schema": "weall.v2.vector_registry", **common, "count": len(vector_rows), "rows": vector_rows},
        "evidence_index": {"schema": "weall.v2.evidence_index", **common, "count": len(evidence_rows), "rows": evidence_rows},
        "pdf_identity_manifest": {"schema": "weall.v2.pdf_identity_manifest", **common, **pdf_identity},
        "register_fingerprint_manifest": {**common, **register_fingerprints},
        "w1_closure_validation_manifest": {
            "schema": "weall.v2.w1_closure_validation_manifest",
            **common,
            "pdf_extraction_attestation": register_fingerprints,
            "structured_schemas": structured_schema_validation,
            "extraction_cleanliness": extraction_cleanliness,
            "mechanism_evidence": mechanism_evidence_validation,
            "semantic_reviews": semantic_review_validation,
            "stable_id_history": stable_id_history,
            "divergence_closure": divergence_closure_validation,
            "provenance_binding": provenance_binding,
            "implementation_commit_binding": provenance.get("repository", {}).get("implementation_commit"),
            "release_export_attestation_required": bool(
                provenance.get("repository", {}).get("release_export_attestation_required")
            ),
            "validation_result": "PASS_W1_TECHNICAL_CLOSURE_RELEASE_ATTESTATION_REQUIRED",
        },
    }
    artifacts: dict[Path, bytes] = {
        OUT_ROOT / f"{name}.json": _canonical_json(payload)
        for name, payload in register_payloads.items()
    }

    for name, required in (
        ("tx_contract", [str(item) for item in manifest.get("required_transaction_fields") or []]),
        ("route_contract", [str(item) for item in manifest.get("required_route_fields") or []]),
    ):
        artifacts[OUT_ROOT / "schemas" / f"{name}.schema.json"] = _canonical_json(_schema_for(name, required))

    schema_rows: dict[str, tuple[list[str], list[Json], Json]] = {
        "state_contract": (["stable_id", "canonical_name", "domain", "state_key_or_namespace", "key_encoding", "value_schema", "value_schema_definition", "field_count", "transition_contracts", "failure_semantics", "replay_behavior", "primary_mechanism_id", "vector_ids", "status"], state_rows, {"stable_id": {"type": "string", "pattern": "^STATE-FS-[0-9]{4}$"}}),
        "message_contract": (["stable_id", "name", "kind", "source", "wire_encoding", "authority_boundary", "replay_rules", "idempotency_rules", "failure_semantics", "primary_mechanism_id", "vector_ids", "status"], message_rows, {}),
        "scheduler_contract": (["stable_id", "name", "source", "due_predicate", "ordering_contract", "idempotency_key", "replay_behavior", "failure_semantics", "primary_mechanism_id", "vector_ids", "status"], scheduler_rows, {}),
        "receipt_contract": (["stable_id", "transaction_id", "tx_type", "kind", "fields", "domain_separation", "replay_binding", "failure_representation", "primary_mechanism_id", "vector_ids", "status"], receipt_rows, {}),
        "failure_contract": (["stable_id", "code", "reason_or_contract", "category", "retryable", "severity", "state_mutation_guarantee", "transactions", "routes", "primary_mechanism_id", "vector_ids", "status"], failure_rows, {}),
        "parameter": (["id", "name", "type", "value", "source", "scope", "mutability", "activation_gate", "status"], parameter_rows, {"id": {"type": "string", "pattern": "^(?:C310-P|P|V20-P)-[0-9]{3}$"}}),
        "requirement": (["id", "status", "title", "normative_sentence", "section", "owner", "implementation_paths", "contract_ids", "tests", "evidence_ids", "reviewer", "activation_gate", "verification_result", "test_run_id", "evidence_digest", "implementation_commit", "verification_timestamp"], requirement_rows, {"id": {"type": "string", "pattern": "^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*-[0-9]{3}$"}, "implementation_commit": {"type": ["string", "null"], "pattern": "^[0-9a-f]{40}$"}, "verification_timestamp": {"type": ["string", "null"], "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"}}),
        "mechanism": (["id", "status", "title", "mechanism_kind", "current_snapshot_behavior", "production_target", "authority_boundary", "repository_evidence_paths", "repository_evidence", "specification_sections", "divergence_status", "activation_gate", "required_evidence", "primary_owner"], mechanism_rows, {"id": {"type": "string", "pattern": "^M-[0-9]{3}$"}}),
        "evidence": (["stable_id", "path", "sha256", "kind", "claim", "reviewer", "required_external_review", "activation_authority", "primary_mechanism_id", "truth_boundary", "status"], evidence_rows, {}),
        "source_coverage": (["source_id", "path", "classification", "primary_mechanism_id", "affected_registers", "sha256", "mappings"], coverage["files"], {}),
        "target_contract": (["id", "namespace", "name", "primary_mechanism_id", "vector_ids", "status", "contract_fingerprint", "payload_schema_definition", "receipt_schema_definition", "schema_definition_fingerprint"], target_contract_rows, {"id": {"type": "string", "pattern": "^(?:TX|MSG|SYS|RCP):C310:[0-9]{4}$"}, "namespace": {"type": "string", "enum": ["TX", "MSG", "SYS", "RCP"]}}),
        "target_failure": (["stable_id", "failure_id", "code", "reason_or_contract", "primary_mechanism_id", "vector_ids", "status", "contract_fingerprint", "failure_schema_definition"], target_failure_rows, {"stable_id": {"type": "string", "pattern": "^FAIL-FS-[0-9]{4}$"}, "failure_id": {"type": "integer", "minimum": 1}}),
        "spec_compilation_manifest": (["schema", "version", "provenance", "input_hashes", "output_hashes", "coverage", "registers", "requirements", "activation_boundary"], [], {}),
    }
    for name, (required, rows, schema_overrides) in schema_rows.items():
        artifacts[OUT_ROOT / "schemas" / f"{name}.schema.json"] = _canonical_json(
            _record_schema(name, required, rows, controlled_statuses, controlled_results, schema_overrides)
        )

    register_counts = {
        name: int(payload.get("count") or payload.get("transaction_count") or payload.get("route_count") or 0)
        for name, payload in register_payloads.items()
    }
    artifacts[OUT_ROOT / "spec_derivative.md"] = _render_derivative(
        manifest, provenance, register_counts, tx_rows, route_rows, coverage, source_tree_digest
    )
    artifacts[OUT_ROOT / normative_path.name] = normative_path.read_bytes()
    artifacts[WEB_STATUS_OUT] = _render_frontend_status(profiles, manifest, provenance, source_tree_digest)

    output_hashes = {
        _relative(path): _sha256_bytes(raw)
        for path, raw in sorted(artifacts.items(), key=lambda item: _relative(item[0]))
    }
    compilation_manifest = {
        "schema": "weall.v2.spec_compilation_manifest",
        "version": manifest.get("version"),
        "source_manifest": "specs/v2/source/manifest.json",
        "provenance": common["provenance"],
        "input_hashes": _source_input_hashes(manifest),
        "output_hashes": output_hashes,
        "coverage": {
            "transactions": len(tx_rows), "routes": len(route_rows),
            "runtime_state_inventory": len(runtime_state_rows), "state_contracts": len(state_rows),
            "message_contracts": len(message_rows), "scheduler_contracts": len(scheduler_rows),
            "receipt_contracts": len(receipt_rows), "failure_contracts": len(failure_rows),
            "target_transactions": len(target_tx_rows), "target_contracts": len(target_contract_rows),
            "target_failures": len(target_failure_rows), "target_contract_schemas": len(target_schema_rows),
            "parameters": len(parameter_rows), "requirements": len(requirement_rows),
            "mechanisms": len(mechanism_rows), "divergences": len(divergence_rows),
            "vectors": len(vector_rows), "evidence_artifacts": len(evidence_rows),
            "source_files": coverage["file_count"], "unmapped_source_files": coverage["unmapped_count"],
            "human_machine_register_equality": True, "exact_uploaded_pdf_identity": True,
            "signed_pdf_extraction_attestation": True,
            "structured_schema_definitions_complete": True,
            "stable_id_history_complete": True,
            "mechanism_evidence_paths_valid": True,
            "tx_semantic_review_complete": tx_payload["semantic_review_complete"],
            "route_semantic_review_complete": route_payload["semantic_review_complete"],
            "independent_review_deferred_to_launch_authorization": True,
        },
        "registers": sorted(register_payloads),
        "requirements": requirement_rows,
        "activation_boundary": {
            "public_testnet": "disabled_pending_activation_receipt",
            "mainnet": "disabled_pending_activation_receipt",
            "normative_pdf_authority": "V2_0_FIRST_DRAFT_NOT_AUTHORIZED",
            "mechanism_coverage_is_not_production_readiness": True,
        },
    }
    artifacts[OUT_ROOT / "spec_compilation_manifest.json"] = _canonical_json(compilation_manifest)
    declared_outputs = sorted(str(item) for item in manifest.get("outputs") or [])
    actual_outputs = sorted(_relative(path) for path in artifacts)
    if declared_outputs != actual_outputs:
        raise CompileError(
            "declared output inventory drift: "
            f"missing={sorted(set(declared_outputs) - set(actual_outputs))} "
            f"extra={sorted(set(actual_outputs) - set(declared_outputs))}"
        )
    return artifacts, compilation_manifest

def _write_artifacts(artifacts: dict[Path, bytes]) -> None:
    for path, raw in sorted(artifacts.items(), key=lambda item: _relative(item[0])):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        print(f"wrote {_relative(path)}")


def _check_artifacts(artifacts: dict[Path, bytes]) -> int:
    stale: list[str] = []
    for path, expected in sorted(artifacts.items(), key=lambda item: _relative(item[0])):
        if not path.is_file() or path.read_bytes() != expected:
            stale.append(_relative(path))
    if stale:
        print("v2 specification derivatives are missing or stale:", file=sys.stderr)
        for item in stale:
            print(f"- {item}", file=sys.stderr)
        print("run: python scripts/compile_v2_spec.py", file=sys.stderr)
        return 1
    print(f"OK: {len(artifacts)} v2 specification derivatives are current")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compile and validate WeAll v2 machine-readable specification derivatives."
    )
    parser.add_argument(
        "--check", action="store_true", help="fail if generated derivatives are missing or stale"
    )
    parser.add_argument(
        "--summary", action="store_true", help="print the compilation coverage summary"
    )
    args = parser.parse_args(argv)
    try:
        artifacts, compilation_manifest = compile_artifacts()
    except CompileError as exc:
        print(f"v2 spec compile failed: {exc}", file=sys.stderr)
        return 1
    if args.summary:
        print(json.dumps(compilation_manifest["coverage"], indent=2, sort_keys=True))
    if args.check:
        return _check_artifacts(artifacts)
    _write_artifacts(artifacts)
    print(json.dumps(compilation_manifest["coverage"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
