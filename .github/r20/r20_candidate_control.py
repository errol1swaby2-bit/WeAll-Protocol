#!/usr/bin/env python3
from __future__ import annotations

import json
import runpy
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
PROJECT_ROOT = REPO_ROOT / "Weall-Protocol"
PREVIOUS_COMMIT = "b797ce2dcfa9175e0eef4069d1154af5d05af3f8"
PREVIOUS_REL = ".github/r20/r20_candidate_control.py"
PREVIOUS_BLOB = "280e8fbb09a552cb95d2e1e3b33388cc06a1a8a2"
TEMP_PREVIOUS = HERE / ".r20_candidate_control_marker_surface.py"


def _load_previous_main():
    actual_blob = subprocess.check_output(
        ["git", "rev-parse", f"{PREVIOUS_COMMIT}:{PREVIOUS_REL}"],
        cwd=REPO_ROOT,
        text=True,
    ).strip()
    if actual_blob != PREVIOUS_BLOB:
        raise SystemExit(
            f"known marker-surface controller blob drift: {actual_blob} != {PREVIOUS_BLOB}"
        )
    source = subprocess.check_output(
        ["git", "show", f"{PREVIOUS_COMMIT}:{PREVIOUS_REL}"],
        cwd=REPO_ROOT,
    )
    TEMP_PREVIOUS.write_bytes(source)
    namespace = runpy.run_path(
        str(TEMP_PREVIOUS), run_name="r20_candidate_control_marker_surface"
    )
    previous_main = namespace.get("main")
    if not callable(previous_main):
        raise SystemExit("known marker-surface controller has no callable main()")
    return previous_main


def _encapsulate_pin_marker_lookup() -> None:
    storage_path = PROJECT_ROOT / "src" / "weall" / "runtime" / "apply" / "storage.py"
    storage = storage_path.read_text(encoding="utf-8")

    helper_anchor = '''def _pin_accounting_marker_set(state: Json, marker: str) -> bool:\n'''
    if storage.count(helper_anchor) != 1:
        raise SystemExit(
            "pin accounting marker helper anchor mismatch: "
            f"{storage.count(helper_anchor)}"
        )
    helper = '''def _pin_accounting_marker_exists(state: Json, marker: str) -> bool:\n    s = _ensure_storage(state)\n    return bool(_as_dict(s.get("pin_accounting_markers")).get(marker))\n\n\n'''
    if helper not in storage:
        storage = storage.replace(helper_anchor, helper + helper_anchor, 1)

    direct = '''        prior_non_success = bool(\n            _as_dict(s.get("pin_accounting_markers")).get(released_marker)\n        )\n'''
    abstracted = '''        prior_non_success = _pin_accounting_marker_exists(state, released_marker)\n'''
    if storage.count(direct) != 1:
        raise SystemExit(
            "direct pin accounting marker lookup mismatch: "
            f"{storage.count(direct)}"
        )
    storage = storage.replace(direct, abstracted, 1)
    compile(storage, str(storage_path), "exec")
    storage_path.write_text(storage, encoding="utf-8")

    stable_ids_path = PROJECT_ROOT / "specs" / "v2" / "source" / "stable_ids.json"
    stable_ids = json.loads(stable_ids_path.read_text(encoding="utf-8"))
    entries = stable_ids.get("entries")
    if not isinstance(entries, list):
        raise SystemExit("stable_ids.json entries must be a list")
    canonical_key = "Storage:pin_accounting_markers"
    stable_id = "STATE-D726415CAADC0B5D"
    matches = [
        row
        for row in entries
        if isinstance(row, dict)
        and str(row.get("kind") or "") == "state"
        and str(row.get("canonical_key") or "") == canonical_key
    ]
    if len(matches) != 1 or str(matches[0].get("stable_id") or "") != stable_id:
        raise SystemExit(
            f"unexpected temporary marker stable-id registration: {matches!r}"
        )
    stable_ids["entries"] = [row for row in entries if row is not matches[0]]
    stable_ids_path.write_text(
        json.dumps(stable_ids, indent=2) + "\n",
        encoding="utf-8",
    )
    print(
        "encapsulated pin-accounting marker lookup and removed temporary direct-state ID"
    )


def main() -> int:
    command = sys.argv[1] if len(sys.argv) > 1 else ""
    try:
        previous_main = _load_previous_main()
        rc = previous_main()
        if rc not in (None, 0):
            raise SystemExit(f"known marker-surface controller failed: {rc}")
        if command == "post-apply":
            _encapsulate_pin_marker_lookup()
        return 0
    finally:
        try:
            TEMP_PREVIOUS.unlink()
        except FileNotFoundError:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
