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
MANIFEST = SOURCE / "manifest.json"

Json = dict[str, Any]

CANONICAL_KEY = (
    "GET /v1/accounts/registration-work-policy|"
    "src/weall/api/routes_public_parts/accounts.py|"
    "v1_account_registration_work_policy"
)
ROUTE_KEY = "GET /v1/accounts/registration-work-policy"
REGISTER_ROUTE_KEY = "POST /v1/accounts/tx/register"
ACCOUNT_REGISTER_TYPE = "ACCOUNT_REGISTER"
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


def _bind_route_inventory() -> None:
    payload = _load(MANIFEST)
    counts = payload.get("expected_counts")
    if not isinstance(counts, dict):
        raise SystemExit("v2_manifest_expected_counts_not_object")

    current = counts.get("routes")
    if isinstance(current, bool) or not isinstance(current, int):
        raise SystemExit(f"v2_manifest_routes_not_integer:{current!r}")
    if current not in {162, 163}:
        raise SystemExit(f"unexpected_v2_route_inventory:{current}")
    if current == 163:
        print("V2 route inventory already bound: 163")
        return

    counts["routes"] = 163
    _write(MANIFEST, payload)
    print("V2 route inventory updated: 162 -> 163")


def _derive_contract_rows() -> tuple[object, object, Json, Json, Json | None]:
    sys.path.insert(0, str(SCRIPTS))
    compiler = importlib.import_module("compile_v2_spec")
    validation = importlib.import_module("v2_spec_validation")

    captured_txs: list[Json] = []
    captured_routes: list[Json] = []
    original = compiler.apply_semantic_reviews

    def capture(tx_rows: list[Json], route_rows: list[Json], reviews: Json) -> Json:
        del reviews
        captured_txs.extend(dict(row) for row in tx_rows)
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

    route_matches = [
        row for row in captured_routes if str(row.get("stable_id") or "") == EXPECTED_ID
    ]
    if len(route_matches) != 1:
        raise SystemExit(f"expected_one_derived_route_row:found={len(route_matches)}")
    policy_route = route_matches[0]
    if str(policy_route.get("route_key") or "") != ROUTE_KEY:
        raise SystemExit("derived_route_key_mismatch")

    tx_matches = [
        row for row in captured_txs if str(row.get("tx_type") or "") == ACCOUNT_REGISTER_TYPE
    ]
    if len(tx_matches) != 1:
        raise SystemExit(f"expected_one_account_register_row:found={len(tx_matches)}")
    account_register = tx_matches[0]

    register_route_matches = [
        row for row in captured_routes if str(row.get("route_key") or "") == REGISTER_ROUTE_KEY
    ]
    if len(register_route_matches) > 1:
        raise SystemExit("duplicate_register_route_rows")
    register_route = register_route_matches[0] if register_route_matches else None

    return compiler, validation, policy_route, account_register, register_route


def _base_review() -> Json:
    return {
        "authority_effect": "none; does not activate public testnet or Mainnet",
        "disposition": "accepted_current_semantic_contract",
        "independent_review": False,
        "review_method": "row_by_row_semantic_snapshot_bound_to_stable_implementation_identity",
        "reviewed_at": dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "reviewer": (
            "WeAll Protocol Maintainer acceptance snapshot (AI-assisted); "
            "independent launch review deferred"
        ),
    }


def _upsert_semantic_reviews(
    validation: object,
    policy_route: Json,
    account_register: Json,
    register_route: Json | None,
) -> None:
    payload = _load(SEMANTIC_REVIEWS)
    route_rows = payload.get("routes")
    tx_rows = payload.get("transactions")
    if not isinstance(route_rows, list):
        raise SystemExit("semantic_reviews_routes_not_list")
    if not isinstance(tx_rows, list):
        raise SystemExit("semantic_reviews_transactions_not_list")

    now = _base_review()

    allowed_routes = [policy_route]
    if register_route is not None:
        allowed_routes.append(register_route)

    for derived in allowed_routes:
        stable_id = str(derived.get("stable_id") or "")
        route_key = str(derived.get("route_key") or "")
        digest = validation.compact_digest(validation.route_review_material(derived))
        existing = [row for row in route_rows if str(row.get("stable_id") or "") == stable_id]
        if len(existing) > 1:
            raise SystemExit(f"duplicate_route_semantic_review:{stable_id}")
        if existing and str(existing[0].get("review_digest") or "") == digest:
            print(f"route semantic review already current: {route_key}")
            continue
        review = dict(existing[0]) if existing else {}
        review.update(now)
        review.update(
            {
                "review_digest": digest,
                "route_key": route_key,
                "stable_id": stable_id,
            }
        )
        if existing:
            existing[0].clear()
            existing[0].update(review)
        else:
            route_rows.append(review)
        print(f"route semantic review bound: {route_key} digest={digest}")

    tx_stable_id = str(account_register.get("stable_id") or "")
    tx_digest = validation.compact_digest(validation.tx_review_material(account_register))
    tx_existing = [
        row for row in tx_rows if str(row.get("stable_id") or "") == tx_stable_id
    ]
    if len(tx_existing) != 1:
        raise SystemExit(f"expected_one_account_register_semantic_review:found={len(tx_existing)}")
    if str(tx_existing[0].get("review_digest") or "") != tx_digest:
        review = dict(tx_existing[0])
        review.update(now)
        review.update(
            {
                "review_digest": tx_digest,
                "stable_id": tx_stable_id,
                "tx_type": ACCOUNT_REGISTER_TYPE,
            }
        )
        tx_existing[0].clear()
        tx_existing[0].update(review)
        print(f"transaction semantic review rebound: {ACCOUNT_REGISTER_TYPE} digest={tx_digest}")
    else:
        print(f"transaction semantic review already current: {ACCOUNT_REGISTER_TYPE}")

    route_rows.sort(key=lambda row: str(row.get("stable_id") or ""))
    tx_rows.sort(key=lambda row: str(row.get("stable_id") or ""))
    _write(SEMANTIC_REVIEWS, payload)


def main() -> int:
    _register_route_id()
    _bind_route_inventory()
    compiler, validation, policy_route, account_register, register_route = _derive_contract_rows()
    _upsert_semantic_reviews(validation, policy_route, account_register, register_route)

    artifacts, _manifest = compiler.compile_artifacts()
    compiler._write_artifacts(artifacts)
    print("V2 derivatives regenerated after bounded A15-F003 semantic binding")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
