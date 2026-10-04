from __future__ import annotations

import datetime as dt
import hashlib
import importlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
SOURCE = ROOT / "specs" / "v2" / "source"
REGISTRY = SOURCE / "stable_ids.json"
SEMANTIC_REVIEWS = SOURCE / "semantic_reviews.json"

Json = dict[str, Any]

CANONICAL_KEY = (
    "GET /v1/accounts/registration-work-policy|"
    "src/weall/api/routes_public_parts/accounts.py|"
    "v1_account_registration_work_policy"
)
ROUTE_KEY = "GET /v1/accounts/registration-work-policy"
EXPECTED_ID = "ROUTE-" + hashlib.sha256(CANONICAL_KEY.encode("utf-8")).hexdigest()[:16].upper()


def _load(path: Path) -> Json:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SystemExit(f"expected_json_object:{path}")
    return value


def _write(path: Path, value: Json) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _register_route_id() -> None:
    if EXPECTED_ID != "ROUTE-DFFE9C9CDC3D8793":
        raise SystemExit(f"unexpected_route_stable_id:{EXPECTED_ID}")

    payload = _load(REGISTRY)
    entries = payload.get("entries")
    if not isinstance(entries, list):
        raise SystemExit("stable_ids_entries_not_list")

    by_key = {
        (str(row.get("kind") or ""), str(row.get("canonical_key") or "")): row
        for row in entries
        if isinstance(row, dict)
    }
    existing = by_key.get(("route", CANONICAL_KEY))
    if existing is not None:
        if str(existing.get("stable_id") or "") != EXPECTED_ID:
            raise SystemExit("existing_route_stable_id_mismatch")
        print(f"already registered: {EXPECTED_ID}")
        return

    used_ids = {
        str(row.get("stable_id") or "")
        for row in entries
        if isinstance(row, dict)
    }
    used_ids.update(
        str(row.get("stable_id") or "")
        for row in payload.get("tombstones") or []
        if isinstance(row, dict)
    )
    if EXPECTED_ID in used_ids:
        raise SystemExit("derived_route_stable_id_collision")

    entries.append(
        {
            "aliases": [],
            "canonical_key": CANONICAL_KEY,
            "kind": "route",
            "stable_id": EXPECTED_ID,
            "status": "active",
        }
    )
    entries.sort(key=lambda row: str(row.get("stable_id") or ""))
    _write(REGISTRY, payload)
    print(f"registered: {EXPECTED_ID}")


def _derive_route_row() -> tuple[object, object, Json]:
    sys.path.insert(0, str(SCRIPTS))
    compiler = importlib.import_module("compile_v2_spec")
    validation = importlib.import_module("v2_spec_validation")

    captured_routes: list[Json] = []
    original = compiler.apply_semantic_reviews

    def capture(tx_rows: list[Json], route_rows: list[Json], reviews: Json) -> Json:
        del reviews
        captured_routes.extend(dict(row) for row in route_rows)
        for row in tx_rows:
            row["semantic_derivation"] = row.get("semantic_precision")
            row["semantic_review"] = {
                "review_digest": "A15_F003_DISCOVERY_ONLY",
                "reviewer": "A15_F003_DISCOVERY_ONLY",
                "reviewed_at": "1970-01-01T00:00:00Z",
                "review_method": "A15_F003_DISCOVERY_ONLY",
                "independent_review": False,
                "authority_effect": "A15_F003_DISCOVERY_ONLY",
            }
        for row in route_rows:
            row["semantic_derivation"] = row.get("semantic_precision")
            row["semantic_review"] = {
                "review_digest": "A15_F003_DISCOVERY_ONLY",
                "reviewer": "A15_F003_DISCOVERY_ONLY",
                "reviewed_at": "1970-01-01T00:00:00Z",
                "review_method": "A15_F003_DISCOVERY_ONLY",
                "independent_review": False,
                "authority_effect": "A15_F003_DISCOVERY_ONLY",
            }
        return {
            "transaction_review_count": 0,
            "route_review_count": 0,
            "independent_transaction_reviews": 0,
            "independent_route_reviews": 0,
            "validation_result": "A15_F003_DISCOVERY_ONLY",
        }

    compiler.apply_semantic_reviews = capture
    try:
        compiler.compile_artifacts()
    finally:
        compiler.apply_semantic_reviews = original

    matches = [row for row in captured_routes if str(row.get("stable_id") or "") == EXPECTED_ID]
    if len(matches) != 1:
        raise SystemExit(f"expected_one_derived_route_row:found={len(matches)}")
    row = matches[0]
    if str(row.get("route_key") or "") != ROUTE_KEY:
        raise SystemExit("derived_route_key_mismatch")
    return compiler, validation, row


def _upsert_semantic_review(validation: object, route_row: Json) -> str:
    payload = _load(SEMANTIC_REVIEWS)
    rows = payload.get("routes")
    if not isinstance(rows, list):
        raise SystemExit("semantic_reviews_routes_not_list")

    digest = validation.compact_digest(validation.route_review_material(route_row))
    reviewed_at = dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    review = {
        "authority_effect": "none; does not activate public testnet or Mainnet",
        "disposition": "accepted_current_semantic_contract",
        "independent_review": False,
        "review_digest": digest,
        "review_method": "row_by_row_semantic_snapshot_bound_to_stable_implementation_identity",
        "reviewed_at": reviewed_at,
        "reviewer": (
            "WeAll Protocol Maintainer acceptance snapshot (AI-assisted); "
            "independent launch review deferred"
        ),
        "route_key": ROUTE_KEY,
        "stable_id": EXPECTED_ID,
    }

    existing = [row for row in rows if str(row.get("stable_id") or "") == EXPECTED_ID]
    if len(existing) > 1:
        raise SystemExit("duplicate_semantic_review_for_new_route")
    if existing:
        existing[0].clear()
        existing[0].update(review)
    else:
        rows.append(review)
    rows.sort(key=lambda row: str(row.get("stable_id") or ""))
    _write(SEMANTIC_REVIEWS, payload)
    print(f"semantic review bound: {EXPECTED_ID} digest={digest}")
    return digest


def main() -> int:
    _register_route_id()
    compiler, validation, route_row = _derive_route_row()
    _upsert_semantic_review(validation, route_row)

    # A full compile must now pass every existing semantic binding plus the new
    # route binding before any V2 derivative is written.
    artifacts, _manifest = compiler.compile_artifacts()
    compiler._write_artifacts(artifacts)
    print("V2 derivatives regenerated after exact route semantic binding")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
