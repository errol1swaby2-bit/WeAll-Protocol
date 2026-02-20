#!/usr/bin/env python3
"""
Generate deterministic tx_index.json from specs/tx_canon/tx_canon.yaml.

This index is used by runtime code + tests to:
- enforce canon coverage (every tx type must be claimed)
- locate tx metadata quickly (domain, context, gates, etc.)
- keep deterministic ordering and stable ids
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class TxEntry:
    id: str
    name: str
    domain: str
    context: str
    origin: str
    receipt_only: bool
    payload: dict[str, Any] | None
    gates: dict[str, Any] | None


REPO_ROOT = Path(__file__).resolve().parents[1]
CANON_PATH = REPO_ROOT / "specs" / "tx_canon" / "tx_canon.yaml"
OUT_PATH = REPO_ROOT / "generated" / "tx_index.json"


def _load_yaml(p: Path) -> dict[str, Any]:
    try:
        with p.open("r", encoding="utf-8") as f:
            d = yaml.safe_load(f)
    except Exception as e:  # noqa: BLE001
        raise SystemExit(f"❌ Failed to read YAML: {p} ({e})") from e
    if not isinstance(d, dict):
        raise SystemExit(f"❌ Canon root must be a mapping: {p}")
    return d


def _require(obj: dict[str, Any], key: str, ctx: str) -> Any:
    if key not in obj:
        raise SystemExit(f"❌ Missing required key '{key}' in {ctx}")
    return obj[key]


def _as_str(x: Any) -> str:
    return "" if x is None else str(x)


def _as_bool(x: Any) -> bool:
    if isinstance(x, bool):
        return x
    s = _as_str(x).strip().lower()
    return s in {"1", "true", "yes", "y", "on"}


def _stable_id(name: str, domain: str) -> str:
    h = hashlib.sha256(f"{domain}:{name}".encode("utf-8")).hexdigest()
    return h[:16]


def _validate_and_collect(canon: dict[str, Any]) -> tuple[dict[str, Any], list[TxEntry]]:
    version = _require(canon, "version", "canon root")
    law = _require(canon, "law", "canon root")
    txs = _require(canon, "txs", "canon root")

    if not isinstance(version, (str, int, float)):
        raise SystemExit("❌ canon.version must be scalar")
    if not isinstance(law, (str, int, float)):
        raise SystemExit("❌ canon.law must be scalar")
    if not isinstance(txs, list):
        raise SystemExit("❌ canon.txs must be a list")

    meta: dict[str, Any] = {
        "version": _as_str(version),
        "law": _as_str(law),
    }

    seen_names: set[str] = set()
    entries: list[TxEntry] = []

    for idx, t in enumerate(txs):
        if not isinstance(t, dict):
            raise SystemExit(f"❌ tx[{idx}] must be a mapping")

        name = _as_str(_require(t, "name", f"tx[{idx}]")).strip()
        domain = _as_str(_require(t, "domain", f"tx[{idx}]")).strip()
        context = _as_str(t.get("context", "")).strip()
        origin = _as_str(t.get("origin", "")).strip()
        receipt_only = _as_bool(t.get("receipt_only"))

        if not name:
            raise SystemExit(f"❌ tx[{idx}].name is empty")
        if name in seen_names:
            raise SystemExit(f"❌ duplicate tx name: {name}")
        seen_names.add(name)

        if not domain:
            raise SystemExit(f"❌ tx[{idx}].domain is empty")

        payload = t.get("payload")
        if payload is not None and not isinstance(payload, dict):
            raise SystemExit(f"❌ tx[{idx}].payload must be a mapping if present")

        gates = t.get("gates")
        if gates is not None and not isinstance(gates, dict):
            raise SystemExit(f"❌ tx[{idx}].gates must be a mapping if present")

        entries.append(
            TxEntry(
                id=_stable_id(name, domain),
                name=name,
                domain=domain,
                context=context,
                origin=origin,
                receipt_only=receipt_only,
                payload=payload,
                gates=gates,
            )
        )

    return meta, entries


def _emit_json(
    meta: dict[str, Any],
    entries: list[TxEntry],
    canon_path: Path,
    out_path: Path,
) -> dict[str, Any]:
    entries_sorted = sorted(entries, key=lambda e: e.id)

    by_id: dict[str, Any] = {}
    by_name: dict[str, int] = {}

    for i, e in enumerate(entries_sorted):
        rec: dict[str, Any] = {
            "id": e.id,
            "name": e.name,
            "domain": e.domain,
            "context": e.context,
            "origin": e.origin,
            "receipt_only": e.receipt_only,
        }
        if e.payload is not None:
            rec["payload"] = e.payload
        if e.gates is not None:
            rec["gates"] = e.gates

        by_id[e.id] = rec
        by_name[e.name] = i

    out: dict[str, Any] = {
        "meta": {
            **meta,
            "canon_path": str(canon_path),
            "generated_by": os.path.basename(__file__),
        },
        "tx_types": [by_id[e.id] for e in entries_sorted],
        "by_id": by_id,
        "by_name": by_name,
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--canon", default=str(CANON_PATH), help="Path to tx_canon.yaml")
    ap.add_argument("--out", default=str(OUT_PATH), help="Output path for tx_index.json")
    args = ap.parse_args()

    canon_path = Path(args.canon).resolve()
    out_path = Path(args.out).resolve()

    canon = _load_yaml(canon_path)
    meta, entries = _validate_and_collect(canon)
    out = _emit_json(meta, entries, canon_path=canon_path, out_path=out_path)

    print(f"✅ wrote {out_path} ({len(out['tx_types'])} tx types)")


if __name__ == "__main__":
    main()
