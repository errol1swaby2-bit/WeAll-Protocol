from __future__ import annotations

import base64
import glob
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

Json = dict[str, Any]

# Immutable trust root for the offline W1.1 PDF extraction attestation. A new
# normative PDF requires an independently reviewed attestation and an explicit
# trust-root rotation in code review; editing nearby JSON cannot rebind it.
PDF_EXTRACTION_PUBLIC_KEY_SHA256 = (
    "ac5d32db0cecc7bece1b78b4a87ccec4cf602c219257bbac116736353e56d480"
)

FORBIDDEN_EXTRACTION_MARKERS = (
    "WEALL PROTOCOL | FULL-SCOPE SPECIFICATION |",
    "WEALL PROTOCOL | FULL-SCOPE PRODUCT AND PROTOCOL SPECIFICATION |",
    "| Repository snapshot 63629d71a244 | Page",
    "V2.0 FIRST DRAFT V2.0 FIRST DRAFT",
)


def canonical_compact_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def compact_digest(value: Any) -> str:
    return hashlib.sha256(canonical_compact_bytes(value)).hexdigest()


def register_fingerprint(rows: list[Json], id_field: str) -> Json:
    identifiers = sorted(str(row.get(id_field) or "") for row in rows)
    return {
        "count": len(rows),
        "ids_sha256": compact_digest(identifiers),
        "rows_sha256": compact_digest(rows),
    }


def verify_pdf_extraction_attestation(
    *,
    extraction_manifest: Json,
    attestation: Json,
    pdf_sha256: str,
    registers: dict[str, tuple[list[Json], str]],
    stable_baseline: Json,
) -> Json:
    if str(extraction_manifest.get("pdf_sha256") or "") != pdf_sha256:
        raise ValueError("signed extraction manifest is not bound to the exact uploaded PDF")
    payload_sha = hashlib.sha256(canonical_compact_bytes(extraction_manifest)).hexdigest()
    if str(attestation.get("signed_payload_sha256") or "") != payload_sha:
        raise ValueError("PDF extraction attestation payload digest mismatch")
    try:
        public_raw = base64.b64decode(
            str(attestation.get("public_key_base64") or ""), validate=True
        )
        signature = base64.b64decode(str(attestation.get("signature_base64") or ""), validate=True)
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"invalid PDF extraction attestation encoding: {exc}") from exc
    public_digest = hashlib.sha256(public_raw).hexdigest()
    if public_digest != PDF_EXTRACTION_PUBLIC_KEY_SHA256:
        raise ValueError("PDF extraction attestation public key is not the pinned W1.1 trust root")
    try:
        Ed25519PublicKey.from_public_bytes(public_raw).verify(
            signature,
            canonical_compact_bytes(extraction_manifest),
        )
    except (ValueError, InvalidSignature) as exc:
        raise ValueError("PDF extraction attestation signature verification failed") from exc

    declared_registers = extraction_manifest.get("registers") or {}
    actual: dict[str, Json] = {}
    for name, (rows, id_field) in registers.items():
        fingerprint = register_fingerprint(rows, id_field)
        if fingerprint != declared_registers.get(name):
            raise ValueError(
                f"signed PDF extraction mismatch for {name}: "
                f"expected={declared_registers.get(name)} actual={fingerprint}"
            )
        actual[name] = fingerprint
    baseline_digest = compact_digest(stable_baseline)
    if baseline_digest != str(extraction_manifest.get("stable_id_baseline_sha256") or ""):
        raise ValueError(
            "stable-ID release baseline is not covered by the signed extraction attestation"
        )
    return {
        "schema": "weall.v2.register_fingerprint_manifest",
        "pdf_sha256": pdf_sha256,
        "attestation_payload_sha256": payload_sha,
        "attestation_public_key_sha256": public_digest,
        "attestation_signer": str(attestation.get("signer") or ""),
        "validation_result": "PASS_PINNED_SIGNED_PDF_EXTRACTION_ATTESTATION",
        **actual,
    }


def validate_provenance_binding(provenance: Json) -> Json:
    repository = provenance.get("repository") or {}
    implementation_commit = str(repository.get("implementation_commit") or "")
    integration_base_commit = str(repository.get("integration_base_commit") or "")
    if re.fullmatch(r"[0-9a-f]{40}", implementation_commit) is None:
        raise ValueError("W1 provenance lacks a valid 40-hex implementation commit")
    if re.fullmatch(r"[0-9a-f]{40}", integration_base_commit) is None:
        raise ValueError("W1 provenance lacks a valid 40-hex integration base commit")
    if repository.get("release_export_attestation_required") is not True:
        raise ValueError("W1 provenance must require a detached release-export attestation")
    policy = str(repository.get("closure_commit_binding_policy") or "")
    if policy != (
        "two_commit_non_circular_attestation: commit implementation first, "
        "then bind that commit in an evidence-only finalization commit"
    ):
        raise ValueError("W1 provenance uses an unsupported commit-binding policy")

    finalization = repository.get("closure_finalization")
    finalization_complete = False
    if finalization is not None:
        if not isinstance(finalization, dict):
            raise ValueError("W1 closure_finalization must be an object")
        if str(finalization.get("implementation_commit") or "") != implementation_commit:
            raise ValueError("W1 closure finalization is not bound to implementation_commit")
        timestamp = str(finalization.get("verification_timestamp") or "")
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", timestamp) is None:
            raise ValueError("W1 closure finalization lacks a UTC verification timestamp")
        for field in ("test_run_id", "reviewer"):
            if not str(finalization.get(field) or "").strip():
                raise ValueError(f"W1 closure finalization lacks {field}")
        if str(finalization.get("authority_effect") or "") != (
            "none; public testnet and Mainnet remain disabled"
        ):
            raise ValueError(
                "W1 closure finalization must preserve the fail-closed authority boundary"
            )
        finalization_complete = True

    return {
        "implementation_commit": implementation_commit,
        "integration_base_commit": integration_base_commit,
        "binding_policy": "PASS_NON_CIRCULAR_TWO_COMMIT_BINDING",
        "release_export_attestation_required": True,
        "closure_finalization_present": finalization_complete,
    }


def validate_stable_id_history(current: Json, baseline: Json) -> Json:
    def active_map(payload: Json) -> dict[str, tuple[str, str]]:
        out: dict[str, tuple[str, str]] = {}
        for row in payload.get("entries") or []:
            sid = str(row.get("stable_id") or "")
            out[sid] = (str(row.get("kind") or ""), str(row.get("canonical_key") or ""))
        return out

    def tombstone_map(payload: Json) -> dict[str, Json]:
        return {
            str(row.get("stable_id") or ""): row
            for row in payload.get("tombstones") or []
            if isinstance(row, dict)
        }

    baseline_active = active_map(baseline)
    current_active = active_map(current)
    baseline_tombstones = tombstone_map(baseline)
    current_tombstones = tombstone_map(current)

    rebound = sorted(
        sid
        for sid, identity in baseline_active.items()
        if sid in current_active and current_active[sid] != identity
    )
    if rebound:
        raise ValueError(f"released stable IDs were rebound: {rebound[:25]}")

    missing: list[str] = []
    for sid, (kind, canonical_key) in baseline_active.items():
        if sid in current_active:
            continue
        tombstone = current_tombstones.get(sid)
        if tombstone is None:
            missing.append(sid)
            continue
        if str(tombstone.get("kind") or "") != kind:
            raise ValueError(f"stable-ID tombstone kind drift: {sid}")
        if str(tombstone.get("canonical_key") or "") != canonical_key:
            raise ValueError(f"stable-ID tombstone canonical-key drift: {sid}")
        for field in ("removed_in_version", "removed_reason", "migration_contract"):
            if not str(tombstone.get(field) or "").strip():
                raise ValueError(f"stable-ID tombstone {sid} lacks {field}")
    if missing:
        raise ValueError(f"released stable IDs were removed without tombstones: {missing[:25]}")

    removed_tombstones = sorted(set(baseline_tombstones) - set(current_tombstones))
    if removed_tombstones:
        raise ValueError(f"released stable-ID tombstones were removed: {removed_tombstones[:25]}")
    changed_tombstones = sorted(
        sid for sid, row in baseline_tombstones.items() if current_tombstones.get(sid) != row
    )
    if changed_tombstones:
        raise ValueError(f"released stable-ID tombstones are immutable: {changed_tombstones[:25]}")

    return {
        "baseline_active": len(baseline_active),
        "baseline_tombstones": len(baseline_tombstones),
        "current_active": len(current_active),
        "current_tombstones": len(current_tombstones),
        "validation_result": "PASS_APPEND_ONLY_STABLE_ID_HISTORY",
    }


def _validate_field_definition(field: Json, owner: str) -> None:
    key = field.get("key")
    if not isinstance(key, int) or isinstance(key, bool) or key <= 0:
        raise ValueError(f"{owner} contains an invalid integer field key")
    name = str(field.get("name") or "")
    if re.fullmatch(r"[a-z][a-z0-9_]*", name) is None:
        raise ValueError(f"{owner} contains an invalid field name: {name}")
    presence = str(field.get("presence") or "")
    if presence not in {"required", "conditional"}:
        raise ValueError(f"{owner}.{name} contains an invalid presence rule")
    if field.get("cbor_null_allowed") is not False:
        raise ValueError(f"{owner}.{name} must reject CBOR null")
    descriptor = field.get("type")
    if not isinstance(descriptor, dict) or not str(descriptor.get("kind") or ""):
        raise ValueError(f"{owner}.{name} lacks a structured type descriptor")


def validate_schema_definition(schema: Json, owner: str, *, allow_empty: bool = False) -> None:
    if not isinstance(schema, dict):
        raise ValueError(f"{owner} lacks a structured schema definition")
    if not str(schema.get("schema_id") or ""):
        raise ValueError(f"{owner} lacks schema_id")
    if schema.get("encoding") != "deterministic_cbor":
        raise ValueError(f"{owner} must use deterministic_cbor")
    if schema.get("container") != "integer_keyed_map":
        raise ValueError(f"{owner} must use an integer-keyed map")
    if schema.get("unknown_fields") != "reject" or schema.get("duplicate_keys") != "reject":
        raise ValueError(f"{owner} must reject unknown and duplicate fields")
    if schema.get("floating_point") != "forbidden":
        raise ValueError(f"{owner} must forbid floating point")
    fields = schema.get("fields")
    if not isinstance(fields, list) or (not fields and not allow_empty):
        raise ValueError(f"{owner} contains no structured fields")
    keys: list[int] = []
    names: list[str] = []
    for field in fields:
        if not isinstance(field, dict):
            raise ValueError(f"{owner} contains a non-object field")
        _validate_field_definition(field, owner)
        keys.append(int(field["key"]))
        names.append(str(field["name"]))
    if keys != sorted(keys) or len(keys) != len(set(keys)):
        raise ValueError(f"{owner} field keys must be unique and ascending")
    if len(names) != len(set(names)):
        raise ValueError(f"{owner} field names must be unique")


def validate_structured_schemas(
    state_rows: list[Json],
    target_contracts: list[Json],
    target_failures: list[Json],
) -> Json:
    for row in state_rows:
        validate_schema_definition(
            row.get("value_schema_definition"),
            f"state:{row.get('stable_id')}",
        )
        fields = row["value_schema_definition"]["fields"]
        if int(row.get("field_count") or 0) != len(fields):
            raise ValueError(f"state:{row.get('stable_id')} field_count mismatch")
    for row in target_contracts:
        cid = str(row.get("id") or "")
        namespace = str(row.get("namespace") or "")
        if namespace == "RCP":
            if row.get("payload_schema_definition") is not None:
                raise ValueError(f"{cid} receipt contract must not define a payload schema")
        else:
            validate_schema_definition(row.get("payload_schema_definition"), f"{cid}:payload")
        validate_schema_definition(row.get("receipt_schema_definition"), f"{cid}:receipt")
        material = {
            "id": cid,
            "namespace": namespace,
            "name": row.get("name"),
            "payload_schema_definition": row.get("payload_schema_definition"),
            "receipt_schema_definition": row.get("receipt_schema_definition"),
            "authority": row.get("authority"),
            "replay": row.get("replay"),
            "primary_mechanism_id": row.get("primary_mechanism_id"),
            "vector_ids": row.get("vector_ids"),
            "status": row.get("status"),
        }
        if compact_digest(material) != str(row.get("schema_definition_fingerprint") or ""):
            raise ValueError(f"{cid} structured schema fingerprint mismatch")
    for row in target_failures:
        sid = str(row.get("stable_id") or "")
        validate_schema_definition(row.get("failure_schema_definition"), f"{sid}:failure")
    return {
        "state_schema_count": len(state_rows),
        "target_contract_schema_count": len(target_contracts),
        "target_failure_schema_count": len(target_failures),
        "validation_result": "PASS_EXECUTABLE_STRUCTURED_SCHEMA_DEFINITIONS",
    }


def validate_normative_cleanliness(collections: dict[str, list[Json]]) -> Json:
    contaminated: list[str] = []
    for name, rows in collections.items():
        for row in rows:
            raw = json.dumps(row, ensure_ascii=False)
            if any(marker in raw for marker in FORBIDDEN_EXTRACTION_MARKERS):
                identity = str(row.get("id") or row.get("stable_id") or "unknown")
                contaminated.append(f"{name}:{identity}")
    if contaminated:
        raise ValueError(
            f"normative rows contain PDF header/footer contamination: {contaminated[:25]}"
        )
    return {
        "checked_rows": sum(len(rows) for rows in collections.values()),
        "forbidden_marker_count": 0,
        "validation_result": "PASS_NORMALIZED_PDF_EXTRACTION_ROWS",
    }


def validate_mechanism_evidence(root: Path, rows: list[Json]) -> Json:
    current = 0
    planned = 0
    for row in rows:
        mid = str(row.get("id") or "")
        evidence = row.get("repository_evidence")
        if not isinstance(evidence, list) or not evidence:
            raise ValueError(f"mechanism {mid} lacks typed repository evidence")
        for item in evidence:
            if not isinstance(item, dict):
                raise ValueError(f"mechanism {mid} has invalid typed evidence")
            kind = str(item.get("kind") or "")
            if kind in {"current_path", "current_glob"}:
                rel = str(item.get("path") or "")
                if not rel or " " in rel:
                    raise ValueError(f"mechanism {mid} has malformed current evidence path: {rel}")
                resolved = (root / rel).resolve()
                exists = (
                    bool(glob.glob(str(resolved))) if kind == "current_glob" else resolved.exists()
                )
                if not exists:
                    raise ValueError(
                        f"mechanism {mid} current evidence path does not resolve: {rel}"
                    )
                current += 1
            elif kind in {"planned_target_path", "planned_target_glob", "planned_target_reference"}:
                planned += 1
            else:
                raise ValueError(f"mechanism {mid} has uncontrolled evidence kind: {kind}")
    return {
        "current_evidence_entries": current,
        "planned_target_entries": planned,
        "validation_result": "PASS_TYPED_MECHANISM_EVIDENCE_PATHS",
    }


def tx_review_material(row: Json) -> Json:
    keys = (
        "stable_id",
        "numeric_id",
        "tx_type",
        "domain",
        "origin",
        "context",
        "signer",
        "authority",
        "poh_gate",
        "role_gate",
        "conflict_rules",
        "state_reads",
        "state_writes",
        "system_followups",
        "receipt_contract",
        "failure_codes",
        "replay_behavior",
        "activation",
        "migration_treatment",
        "implementation_source",
        "primary_mechanism_id",
    )
    return {key: row.get(key) for key in keys}


def route_review_material(row: Json) -> Json:
    keys = (
        "stable_id",
        "route_key",
        "method",
        "path",
        "authority_source",
        "canonical_mappings",
        "local_or_service_status",
        "security_policy",
        "request_limits",
        "failure_contract",
        "implementation_source",
        "metadata_source",
        "primary_mechanism_id",
        "activation",
        "duplicate_route_key",
    )
    return {key: row.get(key) for key in keys}


def apply_semantic_reviews(
    tx_rows: list[Json],
    route_rows: list[Json],
    reviews: Json,
) -> Json:
    tx_reviews = {
        str(row.get("stable_id") or ""): row
        for row in reviews.get("transactions") or []
        if isinstance(row, dict)
    }
    route_reviews = {
        str(row.get("stable_id") or ""): row
        for row in reviews.get("routes") or []
        if isinstance(row, dict)
    }
    if set(tx_reviews) != {str(row["stable_id"]) for row in tx_rows}:
        raise ValueError(
            "transaction semantic-review inventory does not exactly cover current rows"
        )
    if set(route_reviews) != {str(row["stable_id"]) for row in route_rows}:
        raise ValueError("route semantic-review inventory does not exactly cover current rows")
    for row in tx_rows:
        review = tx_reviews[str(row["stable_id"])]
        if compact_digest(tx_review_material(row)) != str(review.get("review_digest") or ""):
            raise ValueError(f"transaction semantic-review digest is stale: {row['tx_type']}")
        if review.get("disposition") != "accepted_current_semantic_contract":
            raise ValueError(f"transaction semantic review not accepted: {row['tx_type']}")
        row["semantic_derivation"] = row.get("semantic_precision")
        row["semantic_precision"] = "explicit_maintainer_reviewed_contract"
        row["semantic_review"] = {
            "review_digest": review["review_digest"],
            "reviewer": review["reviewer"],
            "reviewed_at": review["reviewed_at"],
            "review_method": review["review_method"],
            "independent_review": bool(review.get("independent_review")),
            "authority_effect": review["authority_effect"],
        }
    for row in route_rows:
        review = route_reviews[str(row["stable_id"])]
        if compact_digest(route_review_material(row)) != str(review.get("review_digest") or ""):
            raise ValueError(f"route semantic-review digest is stale: {row['route_key']}")
        if review.get("disposition") != "accepted_current_semantic_contract":
            raise ValueError(f"route semantic review not accepted: {row['route_key']}")
        row["semantic_derivation"] = row.get("semantic_precision")
        row["semantic_precision"] = "explicit_maintainer_reviewed_contract"
        row["semantic_review"] = {
            "review_digest": review["review_digest"],
            "reviewer": review["reviewer"],
            "reviewed_at": review["reviewed_at"],
            "review_method": review["review_method"],
            "independent_review": bool(review.get("independent_review")),
            "authority_effect": review["authority_effect"],
        }
    return {
        "transaction_reviews": len(tx_rows),
        "route_reviews": len(route_rows),
        "independent_review_complete": False,
        "independent_review_gate": "deferred_to_launch_authorization",
        "validation_result": "PASS_COMPLETE_MAINTAINER_SEMANTIC_REVIEW_BINDINGS",
    }


def validate_w1_divergence_closure(rows: list[Json]) -> Json:
    by_id = {str(row.get("id") or ""): row for row in rows}
    for did in ("DIV-W1-TX-SEMANTIC", "DIV-W1-ROUTE-SEMANTIC"):
        if str(by_id.get(did, {}).get("status") or "") != "closed":
            raise ValueError(f"W1 semantic divergence is not closed: {did}")
    external = by_id.get("DIV-W1-EXTERNAL-REVIEW") or {}
    if str(external.get("status") or "") != "deferred_to_launch_authorization":
        raise ValueError("independent review must be explicitly deferred to launch authorization")
    if str(external.get("activation_gate") or "") != "disabled_pending_independent_review":
        raise ValueError("independent review launch gate must remain fail closed")
    return {
        "semantic_divergences_closed": 2,
        "external_review_deferred_to_launch": True,
        "validation_result": "PASS_W1_DIVERGENCE_CLOSURE_BOUNDARY",
    }
