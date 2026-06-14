#!/usr/bin/env python3
from __future__ import annotations

"""Validate external operator transcript JSON against the v1.5 release schemas."""

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from gen_external_operator_transcript_requirements_v1_5 import build as build_requirements

Json = dict[str, Any]


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


def validate(kind: str, payload: Json) -> list[str]:
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
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate an external operator transcript against v1.5 release schemas.")
    parser.add_argument("--kind", required=True, choices=sorted(build_requirements()["schemas"].keys()))
    parser.add_argument("--path", required=True)
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
    errors = validate(args.kind, payload)
    if errors:
        for err in errors:
            print(f"[external-transcript] FAIL: {err}", file=sys.stderr)
        return 1
    print(f"OK: {args.kind} transcript satisfies v1.5 requirements")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
