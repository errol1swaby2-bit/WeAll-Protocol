#!/usr/bin/env python3
"""Report V2 semantic drift and missing IDs, never accept reviews or write files.

The diagnostic deliberately runs only the source AST transaction scanner.
Later pipeline gates are authoritative and must still pass independently.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import compile_v2_spec as compiler  # noqa: E402
import v2_spec_validation as validation  # noqa: E402

Json = dict[str, Any]


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _prior_rows() -> tuple[list[Json], str]:
    data = _load(ROOT / "generated/v2/tx_contract_matrix.json")
    if isinstance(data, list):
        return [row for row in data if isinstance(row, dict)], "list"
    if isinstance(data, dict):
        for key in ("rows", "transactions", "contracts", "entries"):
            rows = data.get(key)
            if isinstance(rows, list):
                return [row for row in rows if isinstance(row, dict)], key
    return [], "not_found"


def _current_rows() -> tuple[list[Json], Any, Json]:
    sources = compiler._load_sources()
    stable_ids = compiler.StableIdRegistry.from_payload(sources["stable_ids"])
    tx_canon = sources["transaction_canon"]
    tx_defs = [row for row in tx_canon["txs"] if isinstance(row, dict)]
    tx_types = {str(row["name"]).upper() for row in tx_defs}
    frontend = compiler._scan_files(compiler.WORKSPACE_ROOT / "web" / "src", {".ts", ".tsx"})
    tests = compiler._scan_files(compiler.ROOT / "tests", {".py"})
    routes = compiler._scan_route_contracts(
        tx_types, frontend, tests, sources["contract_overrides"], stable_ids
    )
    rows = compiler._scan_transaction_contracts(
        tx_canon,
        sources["activation_profiles"],
        sources["protocol_registry"],
        sources["contract_overrides"],
        routes,
        frontend,
        tests,
        stable_ids,
        sources["transaction_appliers"],
    )
    return rows, stable_ids, sources


def _missing_state_ids(rows: list[Json], stable_ids: Any, sources: Json) -> list[str]:
    usage = {
        f"{row['domain']}:{str(token).split(':', 1)[-1]}"
        for row in rows
        for field in ("state_reads", "state_writes")
        for token in row.get(field) or []
    }
    declared = sources["protocol_registry"].get("state_namespaces") or {}
    for domain, namespaces in declared.items():
        usage.update(f"{domain}:{value}" for value in namespaces or [])
    missing = []
    for key in sorted(usage):
        try:
            stable_ids.resolve("state", key)
        except compiler.CompileError:
            missing.append(key)
    return missing


def main() -> int:
    rows, stable_ids, sources = _current_rows()
    reviews = _load(ROOT / "specs/v2/source/semantic_reviews.json")
    previous, previous_shape = _prior_rows()
    previous_by_type = {str(row.get("tx_type") or ""): row for row in previous}
    accepted = {
        str(row.get("tx_type") or ""): row
        for row in reviews.get("transactions", [])
        if isinstance(row, dict)
    }
    changed = []
    for row in rows:
        tx_type = str(row.get("tx_type") or "")
        review = accepted.get(tx_type, {})
        material = validation.tx_review_material(row)
        current_digest = validation.compact_digest(material)
        reviewed_digest = str(review.get("review_digest") or "")
        if current_digest == reviewed_digest:
            continue
        old = previous_by_type.get(tx_type)
        previous_material = validation.tx_review_material(old) if isinstance(old, dict) else None
        fields = []
        if previous_material is not None:
            for key in sorted(set(previous_material) | set(material)):
                if previous_material.get(key) != material.get(key):
                    fields.append(
                        {
                            "field": key,
                            "committed": previous_material.get(key),
                            "current": material.get(key),
                        }
                    )
        changed.append(
            {
                "tx_type": tx_type,
                "reviewed_digest": reviewed_digest,
                "current_digest": current_digest,
                "previous_material_available": previous_material is not None,
                "changed_review_fields": fields,
                "current_implementation_source": material.get("implementation_source"),
                "current_failure_codes": material.get("failure_codes"),
                "review_accepted": review.get("disposition")
                == "accepted_current_semantic_contract",
            }
        )
    print(
        json.dumps(
            {
                "status": "DIAGNOSTIC_ONLY_NOT_SEMANTIC_REVIEW",
                "previous_generated_shape": previous_shape,
                "mismatched_transaction_reviews": len(changed),
                "missing_state_stable_ids": _missing_state_ids(rows, stable_ids, sources),
                "details": changed,
            },
            indent=2,
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
