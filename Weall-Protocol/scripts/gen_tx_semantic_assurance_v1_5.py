#!/usr/bin/env python3
"""Generate the A16-F006 all-canon semantic assurance vector manifest.

This generator deliberately does not claim that a schema or handler registration
alone proves transaction semantics.  Each canonical transaction receives:

* a deterministic schema-valid baseline payload;
* a required-field-removal or unknown-field adversarial mutation;
* a coercion probe when a primitive baseline field is available;
* executable semantic properties consumed by
  tests/test_a16_f006_all_tx_semantic_assurance.py.

The executable test, not this manifest by itself, is the closure gate.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from weall.runtime.tx_contracts import handler_name_for_tx_type, load_default_tx_index
from weall.runtime.tx_schema import model_for_tx_type

Json = dict[str, Any]

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "generated" / "tx_semantic_assurance_v1_5.json"

_VALID_CID = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3pt5a3u4ct6shwrdfl5f5d4ii"
_HEX32 = "00" * 32


def _resolve(schema: Json, defs: Json) -> Json:
    current = schema
    seen: set[str] = set()
    while isinstance(current, dict) and isinstance(current.get("$ref"), str):
        ref = str(current["$ref"])
        if ref in seen or not ref.startswith("#/$defs/"):
            break
        seen.add(ref)
        current = defs.get(ref.split("/")[-1], {})
    if not isinstance(current, dict):
        return {}
    return current


def _string_sample(name: str, schema: Json) -> str:
    if isinstance(schema.get("const"), str):
        return str(schema["const"])
    enum = schema.get("enum")
    if isinstance(enum, list):
        for value in enum:
            if isinstance(value, str):
                return value

    n = name.lower()
    if "cid" in n:
        return _VALID_CID
    if any(token in n for token in ("hash", "root", "digest", "commitment")):
        return _HEX32
    if "pubkey" in n or "public_key" in n:
        return "11" * 32
    if "sig_profile" in n:
        return "pq-mldsa-v1"
    if "algorithm" in n or n.endswith("_alg"):
        return "ml-kem-768"
    if "url" in n or "uri" in n:
        return "https://example.invalid/a16"
    if "mime" in n:
        return "application/octet-stream"
    if "old_juror" in n:
        return "@juror_old"
    if "new_juror" in n:
        return "@juror_new"
    if "juror" in n:
        return "@juror1"
    if "validator" in n:
        return "@validator1"
    if n in {"account_id", "owner_id", "member_id", "author_id", "creator_id"}:
        return "@tester"
    if n in {"target_account_id", "reference_account_id"}:
        return "@target"
    if n == "target":
        return "@target"
    if "treasury_id" in n:
        return "treasury-a16"
    if "group_id" in n:
        return "group-a16"
    if "proposal_id" in n:
        return "proposal-a16"
    if "case_id" in n:
        return "case-a16"
    if "challenge_id" in n:
        return "challenge-a16"
    if "request_id" in n:
        return "request-a16"
    if "receipt_id" in n:
        return "receipt-a16"
    if "spend_id" in n:
        return "spend-a16"
    if "post_id" in n:
        return "post-a16"
    if "comment_id" in n:
        return "comment-a16"
    if "content_id" in n:
        return "content-a16"
    if "media_id" in n:
        return "media-a16"
    if "evidence_id" in n:
        return "evidence-a16"
    if "device_id" in n:
        return "device-a16"
    if "session" in n and "id" in n:
        return "session-a16"
    if "key_id" in n:
        return "key-a16"
    if "transfer_id" in n:
        return "transfer-a16"
    if n in {"verdict", "decision", "resolution"}:
        return "approve"
    if "visibility" in n:
        return "public"
    if n == "stage":
        return "voting"
    if n == "role":
        return "member"
    if n == "method":
        return "continuity"
    if n == "status":
        return "active"
    if n == "kind":
        return "generic"
    if n == "currency":
        return "WE"
    min_len = schema.get("minLength")
    size = max(1, int(min_len)) if isinstance(min_len, int) else 1
    return "a" * size


def _sample(schema: Json, defs: Json, name: str = "value") -> Any:
    schema = _resolve(schema, defs)

    if "const" in schema:
        return schema["const"]
    enum = schema.get("enum")
    if isinstance(enum, list) and enum:
        for value in enum:
            if value is not None:
                return value

    variants = schema.get("anyOf")
    if not isinstance(variants, list):
        variants = schema.get("oneOf")
    if isinstance(variants, list):
        choices = []
        for candidate in variants:
            resolved = _resolve(candidate if isinstance(candidate, dict) else {}, defs)
            if resolved.get("type") == "null":
                continue
            choices.append(resolved)
        if choices:
            return _sample(choices[0], defs, name)

    typ = schema.get("type")
    if isinstance(typ, list):
        non_null = [item for item in typ if item != "null"]
        typ = non_null[0] if non_null else "null"

    if (
        typ == "string"
        or typ is None
        and ("minLength" in schema or "maxLength" in schema or "pattern" in schema)
    ):
        return _string_sample(name, schema)

    if typ == "integer":
        minimum = schema.get("minimum")
        exclusive = schema.get("exclusiveMinimum")
        value = 1
        if isinstance(minimum, (int, float)):
            value = max(value, int(minimum))
        if isinstance(exclusive, (int, float)):
            value = max(value, int(exclusive) + 1)
        maximum = schema.get("maximum")
        if isinstance(maximum, (int, float)):
            value = min(value, int(maximum))
        return int(value)

    if typ == "number":
        minimum = schema.get("minimum")
        value = 1.0
        if isinstance(minimum, (int, float)):
            value = max(value, float(minimum))
        maximum = schema.get("maximum")
        if isinstance(maximum, (int, float)):
            value = min(value, float(maximum))
        return value

    if typ == "boolean":
        return True

    if typ == "array":
        items = schema.get("items") if isinstance(schema.get("items"), dict) else {}
        min_items = schema.get("minItems")
        count = max(1, int(min_items)) if isinstance(min_items, int) else 1
        if "juror" in name.lower():
            return [f"@juror{i + 1}" for i in range(count)]
        return [_sample(items, defs, f"{name}_item_{i}") for i in range(count)]

    if typ == "object" or isinstance(schema.get("properties"), dict):
        properties = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
        required = schema.get("required") if isinstance(schema.get("required"), list) else []
        return {
            field: _sample(properties.get(field, {}), defs, str(field))
            for field in required
            if isinstance(field, str)
        }

    return {}


def _baseline_payload(model: Any) -> Json:
    schema = model.model_json_schema()
    defs = schema.get("$defs") if isinstance(schema.get("$defs"), dict) else {}
    properties = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
    required = schema.get("required") if isinstance(schema.get("required"), list) else []
    payload = {
        field: _sample(properties.get(field, {}), defs, str(field))
        for field in required
        if isinstance(field, str)
    }

    try:
        parsed = model.model_validate(payload)
    except (ValidationError, ValueError):
        # Some transaction schemas intentionally express semantic "one of these
        # optional fields must be present" rules through model validators. Build
        # a deterministic baseline by enriching the required-only payload with
        # optional fields in a stable preference order until the model accepts.
        preferred_tokens = (
            "vote",
            "verdict",
            "decision",
            "resolution",
            "status",
            "method",
            "active",
            "accepted",
            "enabled",
            "action",
            "kind",
        )
        optional_fields = [
            field for field in properties if isinstance(field, str) and field not in set(required)
        ]
        optional_fields.sort(
            key=lambda field: (
                next(
                    (
                        index
                        for index, token in enumerate(preferred_tokens)
                        if token in field.lower()
                    ),
                    len(preferred_tokens),
                ),
                field,
            )
        )

        working = dict(payload)
        last_error: Exception | None = None
        for field in optional_fields:
            working[field] = _sample(properties.get(field, {}), defs, field)
            try:
                parsed = model.model_validate(working)
            except (ValidationError, ValueError) as exc:
                last_error = exc
                continue
            payload = working
            break
        else:
            if last_error is not None:
                raise last_error
            raise

    dumped = parsed.model_dump(exclude_none=True)
    if not isinstance(dumped, dict):
        raise RuntimeError("payload_model_dump_not_object")
    return payload


def _required_mutation(model: Any, baseline: Json) -> Json:
    schema = model.model_json_schema()
    required = schema.get("required") if isinstance(schema.get("required"), list) else []
    for field in required:
        if isinstance(field, str) and field in baseline:
            mutated = dict(baseline)
            mutated.pop(field, None)
            try:
                model.model_validate(mutated)
            except (ValidationError, ValueError):
                return {
                    "kind": "drop_required_field",
                    "field": field,
                    "payload": mutated,
                    "expected": "schema_reject",
                }
            raise RuntimeError(f"required_field_mutation_accepted:{field}")

    mutated = dict(baseline)
    mutated["__a16_unknown_field__"] = 1
    try:
        model.model_validate(mutated)
    except (ValidationError, ValueError):
        return {
            "kind": "add_unknown_field",
            "field": "__a16_unknown_field__",
            "payload": mutated,
            "expected": "schema_reject",
        }
    raise RuntimeError("unknown_field_mutation_accepted")


def _coercion_value(value: Any) -> Any | None:
    if isinstance(value, bool):
        return "false" if value else "true"
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, float):
        return str(value)
    if isinstance(value, str):
        return 1
    if isinstance(value, list):
        return "not-a-list"
    if isinstance(value, dict):
        return ["not", "an", "object"]
    return None


def _coercion_probe(model: Any, baseline: Json) -> Json:
    for field, value in baseline.items():
        mutated_value = _coercion_value(value)
        if mutated_value is None:
            continue
        mutated = dict(baseline)
        mutated[field] = mutated_value
        try:
            parsed = model.model_validate(mutated)
        except (ValidationError, ValueError):
            return {
                "kind": "type_coercion_probe",
                "field": field,
                "payload": mutated,
                "schema_outcome": "reject",
            }
        normalized = parsed.model_dump(exclude_none=True)
        return {
            "kind": "type_coercion_probe",
            "field": field,
            "payload": mutated,
            "schema_outcome": "accept",
            "normalized_payload": normalized,
        }
    return {
        "kind": "no_primitive_field",
        "field": None,
        "payload": dict(baseline),
        "schema_outcome": "not_applicable",
    }


def build_manifest() -> Json:
    idx = load_default_tx_index()
    rows: list[Json] = []
    for tx_type in sorted(idx.list_types()):
        model = model_for_tx_type(tx_type)
        if model is None:
            raise RuntimeError(f"missing_payload_model:{tx_type}")
        handler = handler_name_for_tx_type(tx_type)
        if not handler:
            raise RuntimeError(f"missing_handler:{tx_type}")

        baseline = _baseline_payload(model)
        mutation = _required_mutation(model, baseline)
        coercion = _coercion_probe(model, baseline)
        txdef = idx.get(tx_type, {})
        txdef = txdef if isinstance(txdef, dict) else {}

        rows.append(
            {
                "tx_type": tx_type,
                "domain": str(txdef.get("domain") or ""),
                "origin": str(txdef.get("origin") or ""),
                "context": str(txdef.get("context") or ""),
                "receipt_only": bool(txdef.get("receipt_only", False)),
                "handler": handler,
                "schema_model": model.__name__,
                "baseline_payload": baseline,
                "required_mutation": mutation,
                "coercion_probe": coercion,
                "properties": [
                    "baseline_schema_valid",
                    "adversarial_schema_mutation_rejected",
                    "raw_vs_normalized_execution_semantic_parity",
                    "bounded_vs_deepcopy_execution_parity",
                    "rejection_rolls_back_state_exactly",
                ],
            }
        )

    return {
        "schema": "weall.v1_5.tx_semantic_assurance_manifest",
        "finding": "A16-F006",
        "tx_count": len(rows),
        "all_canon_types_have_executable_vectors": len(rows) == len(idx.list_types()),
        "rows": rows,
    }


def _canon_text(payload: Json) -> str:
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--out", default=str(OUT))
    args = parser.parse_args(argv)

    payload = build_manifest()
    if payload["tx_count"] != 236:
        raise SystemExit(f"unexpected_canon_tx_count:{payload['tx_count']}")

    text = _canon_text(payload)
    path = Path(args.out)
    if args.check:
        if not path.exists():
            raise SystemExit(f"missing_semantic_manifest:{path}")
        if path.read_text(encoding="utf-8") != text:
            raise SystemExit(f"stale_semantic_manifest:{path}")
        print(f"OK: {payload['tx_count']} transaction semantic vectors are current")
        return 0

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    print(f"wrote {path} ({payload['tx_count']} transaction semantic vectors)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
