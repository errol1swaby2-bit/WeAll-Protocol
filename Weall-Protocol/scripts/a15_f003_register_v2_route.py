from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "specs" / "v2" / "source" / "stable_ids.json"

CANONICAL_KEY = (
    "GET /v1/accounts/registration-work-policy|"
    "src/weall/api/routes_public_parts/accounts.py|"
    "v1_account_registration_work_policy"
)
EXPECTED_ID = "ROUTE-" + hashlib.sha256(CANONICAL_KEY.encode("utf-8")).hexdigest()[:16].upper()


def main() -> int:
    if EXPECTED_ID != "ROUTE-DFFE9C9CDC3D8793":
        raise SystemExit(f"unexpected_route_stable_id:{EXPECTED_ID}")

    payload = json.loads(REGISTRY.read_text(encoding="utf-8"))
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
        return 0

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
    REGISTRY.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"registered: {EXPECTED_ID}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
