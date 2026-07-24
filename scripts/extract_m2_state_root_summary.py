#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

FIELDS = (
    "chain_id",
    "height",
    "tip_hash",
    "state_root",
    "schema_version",
    "tx_index_hash",
    "protocol_profile_hash",
)


def _decode_object(lines: list[str], start: int) -> tuple[dict[str, Any], int]:
    decoder = json.JSONDecoder()
    text = "\n".join(lines[start:])
    stripped = text.lstrip()
    leading = len(text) - len(stripped)
    value, end = decoder.raw_decode(stripped)
    if not isinstance(value, dict):
        raise ValueError("state_root_summary_object_not_dict")
    consumed = text[: leading + end].count("\n") + 1
    return value, start + consumed


def _pairs(text: str) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    lines = text.splitlines()
    pairs: list[tuple[dict[str, Any], dict[str, Any]]] = []
    index = 0
    while index < len(lines):
        if lines[index].strip() != "==> Node 1":
            index += 1
            continue
        try:
            left, after_left = _decode_object(lines, index + 1)
        except Exception:
            index += 1
            continue
        marker = after_left
        while marker < len(lines) and lines[marker].strip() != "==> Node 2":
            marker += 1
        if marker >= len(lines):
            break
        try:
            right, after_right = _decode_object(lines, marker + 1)
        except Exception:
            index = marker + 1
            continue
        pairs.append((left, right))
        index = after_right
    return pairs


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--gate", required=True)
    args = parser.parse_args()

    source = Path(args.input).resolve()
    out = Path(args.out).resolve()
    pairs = _pairs(source.read_text(encoding="utf-8", errors="replace"))
    if not pairs:
        raise SystemExit(f"m2_state_root_pair_missing:{source}")
    left, right = pairs[-1]
    left_view = {field: left.get(field) for field in FIELDS}
    right_view = {field: right.get(field) for field in FIELDS}
    if any(left_view[field] in (None, "") for field in ("chain_id", "height", "tip_hash", "state_root")):
        raise SystemExit(f"m2_state_root_fields_missing:{source}")
    if left_view != right_view:
        raise SystemExit(
            "m2_state_root_pair_mismatch:" + json.dumps(
                {"node1": left_view, "node2": right_view}, sort_keys=True
            )
        )
    payload = {
        "schema_version": 1,
        "gate": str(args.gate),
        "source_log": source.name,
        "equal": True,
        "final": left_view,
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
