from __future__ import annotations

"""Canonical deterministic commitment primitives shared across runtime domains."""

import hashlib
import json
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from weall.runtime.json_tools import canonical_json_str


def canonical_json_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_str(value).encode("utf-8")).hexdigest()


def canonical_json_sha256_ascii(value: Any) -> str:
    """Hash the historic ensure_ascii=True canonical JSON encoding."""
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def normalize_validator_ids(validators: Iterable[str]) -> list[str]:
    normalized: set[str] = set()
    for value in validators:
        if not isinstance(value, (str, int, float)):
            continue
        item = str(value).strip()
        if item:
            normalized.add(item)
    return sorted(normalized)


def value_sha256(value: Any) -> str:
    """Preserve the protocol's historic raw-string / canonical-object hash rule."""
    if isinstance(value, str):
        return hashlib.sha256(value.encode("utf-8")).hexdigest()
    return canonical_json_sha256(value)


def validator_set_hash(validators: Iterable[str]) -> str:
    return canonical_json_sha256(normalize_validator_ids(validators))


def receipts_root(receipts: Sequence[Mapping[str, Any]]) -> str:
    return canonical_json_sha256([dict(item) for item in receipts])
