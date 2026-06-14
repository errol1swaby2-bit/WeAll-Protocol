#!/usr/bin/env python3
from __future__ import annotations

"""Validate external operator transcript JSON against the v1.5 release schemas.

Default validation checks the deterministic shape of a transcript. Strict release
validation is intentionally stronger: it rejects scaffold/sample transcripts,
placeholder identities/signatures, digest drift, and missing external attestation
markers so no local scaffold can be attached as public-beta evidence.
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

from gen_external_operator_transcript_requirements_v1_5 import build as build_requirements

Json = dict[str, Any]
_PLACEHOLDER_RE = re.compile(r"(sample|placeholder|external[-_ ]?signature[-_ ]?required|required|todo|example|dummy)", re.IGNORECASE)
_SAMPLE_ID_RE = re.compile(r"^(operator-[a-d]|machine-[a-d]|v-[a-d]|storage-operator-[a-c]|storage-machine-[a-c]|12D3KooWsample[A-Z]?)$")


def _canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _stable_digest(payload: Json) -> str:
    return __import__("hashlib").sha256(_canon({k: v for k, v in payload.items() if k != "transcript_digest"}).encode("utf-8")).hexdigest()


def _get_path(payload: Json, dotted: str) -> Any:
    cur: Any = payload
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _count(value: Any) -> int:
    if isinstance(value, (list, tuple, set, dict)):
        return len(value)
    if isinstance(value, int):
        return value
    return 0


def _as_strings(value: Any) -> list[str]:
    if isinstance(value, dict):
        return [str(k) for k in value.keys()] + [str(v) for v in value.values()]
    if isinstance(value, (list, tuple, set)):
        return [str(v) for v in value]
    if value in (None, ""):
        return []
    return [str(value)]


def _has_placeholder(value: Any) -> bool:
    return any(_PLACEHOLDER_RE.search(item) for item in _as_strings(value))


def _has_sample_identity(value: Any) -> bool:
    return any(_SAMPLE_ID_RE.match(item) or _PLACEHOLDER_RE.search(item) for item in _as_strings(value))


def validate(kind: str, payload: Json, *, strict_release: bool = False) -> list[str]:
    req = build_requirements()
    schemas = req.get("schemas") if isinstance(req.get("schemas"), dict) else {}
    schema = schemas.get(kind)
    if not isinstance(schema, dict):
        return [f"unknown transcript kind: {kind}"]
    errors: list[str] = []
    for field in schema.get("required_fields", []):
        if _get_path(payload, str(field)) in (None, "", []):
            errors.append(f"missing required field: {field}")
    for dotted, expected in (schema.get("required_truths") or {}).items():
        actual = _get_path(payload, str(dotted))
        if actual != expected:
            errors.append(f"required truth failed: {dotted} expected {expected!r}, got {actual!r}")
    for field, minimum in (schema.get("minimum_counts") or {}).items():
        actual_count = _count(_get_path(payload, str(field)))
        if actual_count < int(minimum):
            errors.append(f"minimum count failed: {field} expected >= {minimum}, got {actual_count}")
    boundaries = payload.get("claim_boundaries") if isinstance(payload.get("claim_boundaries"), dict) else {}
    for forbidden in schema.get("forbidden_claims", []):
        if boundaries.get(str(forbidden)) is True or payload.get(str(forbidden)) is True:
            errors.append(f"forbidden claim asserted: {forbidden}")
    digest = payload.get("transcript_digest")
    if not isinstance(digest, str) or len(digest) < 32:
        errors.append("transcript_digest must be a stable digest string")
    elif strict_release and digest != _stable_digest(payload):
        errors.append("transcript_digest does not match canonical transcript payload")

    if strict_release:
        errors.extend(_strict_release_errors(kind, payload))
    return errors


def _strict_release_errors(kind: str, payload: Json) -> list[str]:
    errors: list[str] = []
    if payload.get("sample_transcript_only") is True:
        errors.append("strict release mode rejects sample_transcript_only=true")
    if payload.get("external_attestation_required") is True:
        errors.append("strict release mode rejects external_attestation_required=true; attach actual external_attestation instead")
    if payload.get("real_daemon_topology_required") is True:
        errors.append("strict release mode rejects real_daemon_topology_required=true; attach actual real_daemon_topology evidence")
    if payload.get("external_attestation_attached") is not True and kind != "legal_compliance_attestation":
        errors.append("strict release mode requires external_attestation_attached=true")

    for field in ("operator_ids", "node_ids", "machine_ids", "ipfs_peer_ids"):
        value = payload.get(field)
        items = _as_strings(value)
        if items and len(items) != len(set(items)):
            errors.append(f"strict release mode requires distinct {field}")
        if _has_sample_identity(value):
            errors.append(f"strict release mode rejects sample/placeholder identities in {field}")

    if "operator_signatures" in payload:
        signatures = _as_strings(payload.get("operator_signatures"))
        if any(len(sig) < 24 for sig in signatures):
            errors.append("strict release mode requires non-trivial operator signatures")
        if _has_placeholder(signatures):
            errors.append("strict release mode rejects placeholder operator signatures")

    if kind == "public_validator_operator_transcript":
        if payload.get("operator_attestation") not in ("external_operator_signed", "independent_operator_signed"):
            errors.append("public validator strict release transcript requires operator_attestation=external_operator_signed or independent_operator_signed")
        if payload.get("machine_isolation") not in ("independent_machines", "isolated_containers_with_operator_attestation"):
            errors.append("public validator strict release transcript requires machine_isolation proof")
    elif kind == "storage_ipfs_operator_transcript":
        if payload.get("real_daemon_topology") is not True:
            errors.append("storage/IPFS strict release transcript requires real_daemon_topology=true")
        if payload.get("operator_attestation") not in ("external_storage_operator_signed", "independent_operator_signed"):
            errors.append("storage/IPFS strict release transcript requires external storage operator attestation")
    elif kind == "legal_compliance_attestation":
        for field in ("reviewer_or_counsel_reference", "signature_or_controlled_reference"):
            if _has_placeholder(payload.get(field)):
                errors.append(f"strict release mode rejects placeholder {field}")
        if payload.get("counsel_or_control_attestation_attached") is not True:
            errors.append("legal strict release transcript requires counsel_or_control_attestation_attached=true")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate an external operator transcript against v1.5 release schemas.")
    parser.add_argument("--kind", required=True, choices=sorted(build_requirements()["schemas"].keys()))
    parser.add_argument("--path", required=True)
    parser.add_argument("--strict-release", action="store_true", help="reject scaffold/sample evidence and require external attestation fields")
    args = parser.parse_args(argv)
    path = Path(args.path)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"invalid transcript json: {exc}", file=sys.stderr)
        return 2
    if not isinstance(payload, dict):
        print("transcript root must be a JSON object", file=sys.stderr)
        return 2
    errors = validate(args.kind, payload, strict_release=args.strict_release)
    if errors:
        for err in errors:
            print(f"[external-transcript] FAIL: {err}", file=sys.stderr)
        return 1
    mode = "strict release" if args.strict_release else "shape"
    print(f"OK: {args.kind} transcript satisfies v1.5 {mode} requirements")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
