#!/usr/bin/env python3
"""
Generate deterministic tx_index.json from specs/tx_canon/tx_canon.yaml.

This index is used by runtime code + tests to:
- enforce canon coverage (every tx type must be claimed)
- locate tx metadata quickly (domain, context, gates, etc.)
- keep deterministic ordering and stable ids

Important compatibility note
----------------------------
Older tx_canon entries used a single string field:

  gate: Tier3+

The runtime admission layer (weall.runtime.tx_admission) expects the per-tx
record to expose a *top-level* field:

  subject_gate: "Tier3+"

Newer/extended records may use a mapping:

  gates:
    subject_gate: Tier3+
    ... (future)

This generator supports BOTH:
- If `gates` is present (mapping), it is preserved and `subject_gate` is
  mirrored from `gates.subject_gate` when provided.
- If legacy `gate` is present (string), it is upgraded to `subject_gate` and
  also mirrored into `gates.subject_gate` (unless gates already specifies it).

"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

Json = Dict[str, Any]


@dataclass(frozen=True)
class TxEntry:
    id_num: int
    name: str
    domain: str
    origin: str
    gate: str
    context: str
    receipt_only: bool
    gates: Optional[Dict[str, Any]]


def _stable_id_hex(name: str) -> str:
    # Stable, deterministic id for a tx name.
    return hashlib.sha256(name.encode("utf-8")).hexdigest()[:16]


def _load_yaml(path: Path) -> Json:
    obj = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise SystemExit("❌ tx_canon.yaml must be a mapping")
    return obj


def _parse_entries(spec: Json) -> List[TxEntry]:
    txs = spec.get("txs")
    if not isinstance(txs, list) or not txs:
        raise SystemExit("❌ tx_canon.yaml must have non-empty list field: txs")

    out: List[TxEntry] = []
    for idx, t in enumerate(txs):
        if not isinstance(t, dict):
            raise SystemExit(f"❌ tx[{idx}] must be a mapping")

        try:
            id_num = int(t.get("id"))
        except Exception:
            raise SystemExit(f"❌ tx[{idx}].id must be an int")

        name = str(t.get("name") or "").strip()
        if not name:
            raise SystemExit(f"❌ tx[{idx}].name missing")

        domain = str(t.get("domain") or "").strip() or "Unknown"
        origin = str(t.get("origin") or "USER").strip() or "USER"
        context = str(t.get("context") or "mempool").strip() or "mempool"
        receipt_only = bool(t.get("receipt_only") is True)

        # Legacy + modern gates
        legacy_gate = str(t.get("gate") or "").strip()
        gates = t.get("gates")
        if gates is not None and not isinstance(gates, dict):
            raise SystemExit(f"❌ tx[{idx}].gates must be a mapping if present")

        merged_gates: Optional[Dict[str, Any]] = dict(gates) if isinstance(gates, dict) else None

        # Compute subject gate preference order:
        # 1) gates.subject_gate (if present)
        # 2) legacy gate (if present)
        subject_gate = ""
        if isinstance(merged_gates, dict) and str(merged_gates.get("subject_gate") or "").strip():
            subject_gate = str(merged_gates.get("subject_gate") or "").strip()
        elif legacy_gate:
            subject_gate = legacy_gate

        # Mirror subject_gate into merged_gates for observability
        if subject_gate:
            if merged_gates is None:
                merged_gates = {}
            merged_gates.setdefault("subject_gate", subject_gate)

        out.append(
            TxEntry(
                id_num=id_num,
                name=name,
                domain=domain,
                origin=origin,
                gate=subject_gate,
                context=context,
                receipt_only=receipt_only,
                gates=merged_gates,
            )
        )

    # ensure unique ids + names
    ids = [e.id_num for e in out]
    if len(ids) != len(set(ids)):
        raise SystemExit("❌ duplicate tx ids in tx_canon.yaml")

    names = [e.name for e in out]
    if len(names) != len(set(names)):
        raise SystemExit("❌ duplicate tx names in tx_canon.yaml")

    # deterministic ordering by id
    out.sort(key=lambda e: e.id_num)
    return out


def _emit(entries: List[TxEntry], *, spec: Json) -> Json:
    tx_types: List[Json] = []
    by_id: Dict[str, int] = {}
    by_name: Dict[str, int] = {}

    for e in entries:
        rec: Json = {
            "name": e.name,
            "domain": e.domain,
            "origin": e.origin,
            "context": e.context,
            "receipt_only": bool(e.receipt_only),
            "id": _stable_id_hex(e.name),
        }
        if e.gate:
            # Admission reads this field.
            rec["subject_gate"] = e.gate
        if e.gates is not None:
            rec["gates"] = e.gates

        tx_types.append(rec)
        by_id[str(e.id_num)] = e.id_num
        by_name[e.name] = e.id_num

    meta = {
        "version": spec.get("version"),
        "source": spec.get("source"),
        "law": spec.get("law"),
    }

    return {
        "meta": meta,
        "by_id": by_id,
        "by_name": by_name,
        "tx_types": tx_types,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--spec", default="specs/tx_canon/tx_canon.yaml")
    ap.add_argument("--out", default="generated/tx_index.json")
    args = ap.parse_args()

    spec_path = Path(args.spec)
    out_path = Path(args.out)

    if not spec_path.exists():
        raise SystemExit(f"❌ spec not found: {spec_path}")

    spec = _load_yaml(spec_path)
    entries = _parse_entries(spec)
    obj = _emit(entries, spec=spec)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"✅ wrote {out_path} ({len(entries)} tx types)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
