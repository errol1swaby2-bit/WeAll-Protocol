#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STABLE_IDS_PATH = ROOT / "specs" / "v2" / "source" / "stable_ids.json"

R20_ADDITIONAL_STATE_IDS = {
    "Roles:helper_reputation_required_milli": "STATE-F7E1B65C56D84E6E",
}


def main() -> int:
    payload = json.loads(STABLE_IDS_PATH.read_text(encoding="utf-8"))
    entries = payload.get("entries")
    if not isinstance(entries, list):
        raise SystemExit("stable_ids.json entries must be a list")

    by_key = {
        (str(row.get("kind") or ""), str(row.get("canonical_key") or "")): row
        for row in entries
        if isinstance(row, dict)
    }
    by_id = {
        str(row.get("stable_id") or ""): row
        for row in entries
        if isinstance(row, dict) and str(row.get("stable_id") or "")
    }

    changed = False
    for canonical_key, stable_id in R20_ADDITIONAL_STATE_IDS.items():
        expected_id = (
            "STATE-"
            + hashlib.sha256(canonical_key.encode("utf-8")).hexdigest()[:16].upper()
        )
        if stable_id != expected_id:
            raise SystemExit(
                f"r20 state stable-id derivation mismatch: {canonical_key}: "
                f"{stable_id} != {expected_id}"
            )

        existing = by_key.get(("state", canonical_key))
        if existing is not None:
            if str(existing.get("stable_id") or "") != stable_id:
                raise SystemExit(
                    "r20 state key already registered to unexpected ID: "
                    f"{canonical_key}: {existing.get('stable_id')}"
                )
            print(f"stable ID already registered: {canonical_key} -> {stable_id}")
            continue

        collision = by_id.get(stable_id)
        if collision is not None:
            raise SystemExit(
                "r20 deterministic state ID collision: "
                f"{stable_id} already belongs to "
                f"{collision.get('kind')}:{collision.get('canonical_key')}"
            )

        row = {
            "aliases": [],
            "canonical_key": canonical_key,
            "kind": "state",
            "stable_id": stable_id,
            "status": "active",
        }
        entries.append(row)
        by_key[("state", canonical_key)] = row
        by_id[stable_id] = row
        changed = True
        print(f"registered stable ID: {canonical_key} -> {stable_id}")

    if changed:
        STABLE_IDS_PATH.write_text(
            json.dumps(payload, indent=2) + "\n",
            encoding="utf-8",
        )

    Path(__file__).unlink()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
