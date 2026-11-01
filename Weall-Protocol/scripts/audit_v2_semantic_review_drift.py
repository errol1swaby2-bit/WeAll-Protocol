#!/usr/bin/env python3
"""Inspect V2 transaction semantic drift without modifying or accepting reviews.

Outputs changed contract fields versus last committed generated contract rows
when available. This is diagnostic evidence only; never a review approval.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import refresh_v2_semantic_reviews as refresh  # noqa: E402

Json = dict[str, Any]


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _prior_rows() -> tuple[list[Json], str]:
    path = ROOT / "generated/v2/tx_contract_matrix.json"
    data = _load(path)
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)], "list"
    if isinstance(data, dict):
        for key in ("rows", "transactions", "contracts", "entries"):
            items = data.get(key)
            if isinstance(items, list):
                return [r for r in items if isinstance(r, dict)], key
    return [], "not_found"


def main() -> int:
    compiler, validation, rows = refresh._derive_transaction_rows()
    del compiler
    reviews = _load(ROOT / "specs/v2/source/semantic_reviews.json")
    previous, previous_shape = _prior_rows()
    previous_by_type = {
        str(x.get("tx_type") or ""): x for x in previous
    }
    accepted = {
        str(x.get("tx_type") or ""): x for x in reviews.get("transactions", [])
        if isinstance(x, dict)
    }
    changed: list[Json] = []
    for row in rows:
        tx_type = str(row.get("tx_type") or "")
        prior = accepted.get(tx_type, {})
        material = validation.tx_review_material(row)
        current_digest = validation.compact_digest(material)
        reviewed_digest = str(prior.get("review_digest") or "")
        if current_digest == reviewed_digest:
            continue
        older = previous_by_type.get(tx_type)
        old_material = (
            validation.tx_review_material(older)
            if isinstance(older, dict) else None
        )
        fields = []
        if old_material is not None:
            for key in sorted(set(old_material) | set(material)):
                if old_material.get(key) != material.get(key):
                    fields.append({
                        "field": key,
                        "committed": old_material.get(key),
                        "current": material.get(key),
                    })
        changed.append({
            "tx_type": tx_type,
            "reviewed_digest": reviewed_digest,
            "current_digest": current_digest,
            "previous_material_available": old_material is not None,
            "changed_review_fields": fields,
            "current_implementation_source": material.get("implementation_source"),
            "current_failure_codes": material.get("failure_codes"),
            "review_accepted": prior.get("disposition") == (
                "accepted_current_semantic_contract"
            ),
        })
    print(json.dumps({
        "status": "DIAGNOSTIC_ONLY_NOT_SEMANTIC_REVIEW",
        "prior_generated_shape": previous_shape,
        "mismatched_transaction_reviews": len(changed),
        "details": changed,
    }, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
