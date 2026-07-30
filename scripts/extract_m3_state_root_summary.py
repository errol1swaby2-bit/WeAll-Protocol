#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
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


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--gate", required=True)
    parser.add_argument("--implementation-freeze", required=True)
    parser.add_argument("--implementation-tree", required=True)
    parser.add_argument("--node1-id", required=True)
    parser.add_argument("--node2-id", required=True)
    parser.add_argument("--observer", action="store_true")
    args = parser.parse_args()

    if args.node1_id == args.node2_id:
        raise SystemExit("m3_state_summary_node_ids_not_distinct")

    source = Path(args.input).resolve()
    out = Path(args.out).resolve()
    pairs = _pairs(source.read_text(encoding="utf-8", errors="replace"))
    if not pairs:
        raise SystemExit(f"m3_state_root_pair_missing:{source}")
    left, right = pairs[-1]
    left_view = {field: left.get(field) for field in FIELDS}
    right_view = {field: right.get(field) for field in FIELDS}
    for field in ("chain_id", "height", "tip_hash", "state_root", "tx_index_hash", "protocol_profile_hash"):
        if left_view.get(field) in (None, ""):
            raise SystemExit(f"m3_state_root_field_missing:{field}:{source}")
    if left_view != right_view:
        raise SystemExit(
            "m3_state_root_pair_mismatch:"
            + json.dumps({"node1": left_view, "node2": right_view}, sort_keys=True)
        )

    payload: dict[str, Any] = {
        "schema_version": 2,
        "gate": str(args.gate),
        "implementation_freeze_commit": str(args.implementation_freeze),
        "implementation_tree": str(args.implementation_tree),
        "source_log": source.name,
        "source_log_sha256": _sha256(source),
        "equal": True,
        "distinct_processes": True,
        "distinct_datastores": True,
        "comparison_fields": list(FIELDS),
        "nodes": [
            {"node_id": args.node1_id, "role": "canonical_producer", **left_view},
            {
                "node_id": args.node2_id,
                "role": "observer" if args.observer else "joining_node",
                **right_view,
            },
        ],
        "final": left_view,
    }
    if args.observer:
        payload["observer_authority"] = {
            "observer_mode": True,
            "validator_signing_enabled": False,
            "bft_signing_authority": False,
            "helper_authority": False,
            "treasury_or_governance_authority": False,
        }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
