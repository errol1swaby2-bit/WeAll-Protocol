# scripts/migrate_roles_schema.py
from __future__ import annotations

import json
import sys
from pathlib import Path

from weall.ledger.roles_schema import ensure_roles_schema, migrate_legacy_role_shapes


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: python -m scripts.migrate_roles_schema <path_to_ledger.json>")
        return 2

    path = Path(sys.argv[1]).expanduser().resolve()
    if not path.exists():
        print(f"ledger not found: {path}")
        return 2

    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        print("ledger must be a JSON object")
        return 2

    ensure_roles_schema(data)
    changes, notes = migrate_legacy_role_shapes(data)

    path.write_text(json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")

    print(f"ok: roles schema ensured. changes={changes}")
    for n in notes[:50]:
        print(f" - {n}")
    if len(notes) > 50:
        print(f" - ... {len(notes)-50} more")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
