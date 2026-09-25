#!/usr/bin/env python3
from __future__ import annotations

import runpy
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
PREVIOUS_COMMIT = "6c926cfa60aa448916b34c66509b680ba6172411"
PREVIOUS_REL = ".github/r20/r20_candidate_control.py"
PREVIOUS_BLOB = "70f68506fee6177d384a4d22c0880edf8211dd8e"
TEMP_PREVIOUS = HERE / ".r20_candidate_control_storage_v1.py"


def _load_previous_namespace() -> dict[str, object]:
    actual_blob = subprocess.check_output(
        ["git", "rev-parse", f"{PREVIOUS_COMMIT}:{PREVIOUS_REL}"],
        cwd=REPO_ROOT,
        text=True,
    ).strip()
    if actual_blob != PREVIOUS_BLOB:
        raise SystemExit(
            f"known storage-fix controller blob drift: {actual_blob} != {PREVIOUS_BLOB}"
        )
    source = subprocess.check_output(
        ["git", "show", f"{PREVIOUS_COMMIT}:{PREVIOUS_REL}"],
        cwd=REPO_ROOT,
    )
    TEMP_PREVIOUS.write_bytes(source)
    return runpy.run_path(str(TEMP_PREVIOUS), run_name="r20_candidate_control_storage_v1")


def main() -> int:
    namespace = _load_previous_namespace()
    original_replace = namespace.get("_replace_once")
    previous_main = namespace.get("main")
    if not callable(original_replace) or not callable(previous_main):
        raise SystemExit("previous storage-fix controller contract missing")

    def guarded_replace(text: str, old: str, new: str, *, label: str) -> str:
        if label != "storage-retrieval-requires-replica-policy" or text.count(old) == 1:
            return original_replace(text, old, new, label=label)

        start = "        if retrieval_ok:\n"
        end = "    else:\n        confirmations.pop(operator_id, None)\n"
        if text.count(start) != 1 or text.count(end) != 1:
            raise SystemExit(
                f"{label}: fallback anchors are not unique: "
                f"start={text.count(start)} end={text.count(end)}"
            )
        start_at = text.index(start)
        end_at = text.index(end, start_at)
        if end_at <= start_at:
            raise SystemExit(f"{label}: malformed fallback span")
        return text[:start_at] + new + text[end_at:]

    namespace["_replace_once"] = guarded_replace
    try:
        rc = previous_main()
        return int(rc or 0)
    finally:
        TEMP_PREVIOUS.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
