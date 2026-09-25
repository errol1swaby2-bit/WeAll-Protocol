#!/usr/bin/env python3
from __future__ import annotations

import runpy
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
PROJECT_ROOT = REPO_ROOT / "Weall-Protocol"
PREVIOUS_COMMIT = "f62030327a179410920e235fd68a79b006804913"
PREVIOUS_REL = ".github/r20/r20_candidate_control.py"
PREVIOUS_BLOB = "27414653715ff4764ba00b60e858e59a2d79b7cd"
TEMP_PREVIOUS = HERE / ".r20_candidate_control_rf2_v1.py"


def _load_previous_main():
    actual_blob = subprocess.check_output(
        ["git", "rev-parse", f"{PREVIOUS_COMMIT}:{PREVIOUS_REL}"],
        cwd=REPO_ROOT,
        text=True,
    ).strip()
    if actual_blob != PREVIOUS_BLOB:
        raise SystemExit(f"known RF2 controller blob drift: {actual_blob} != {PREVIOUS_BLOB}")
    source = subprocess.check_output(
        ["git", "show", f"{PREVIOUS_COMMIT}:{PREVIOUS_REL}"],
        cwd=REPO_ROOT,
    )
    TEMP_PREVIOUS.write_bytes(source)
    namespace = runpy.run_path(str(TEMP_PREVIOUS), run_name="r20_candidate_control_rf2_v1")
    previous_main = namespace.get("main")
    if not callable(previous_main):
        raise SystemExit("known RF2 controller has no callable main()")
    return previous_main


def _replace_once(text: str, old: str, new: str, *, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one source match, found {count}")
    return text.replace(old, new, 1)


def _repair_b528_storage_rehearsal_format_tolerant() -> None:
    path = PROJECT_ROOT / "scripts" / "rehearse_api_driven_full_lifecycle_v1_5.py"
    text = path.read_text(encoding="utf-8")

    text = _replace_once(
        text,
        '    _enable_storage_responsibility(state, "opA", capacity=1000)\n    _enable_storage_responsibility(state, "opB", capacity=1000)\n',
        '    _enable_storage_responsibility(state, "opA", capacity=1000)\n    _enable_storage_responsibility(state, "opB", capacity=1000)\n    _enable_storage_responsibility(state, "opC", capacity=1000)\n',
        label="b528-add-third-storage-operator",
    )

    pin_marker = 'state["storage"].setdefault("pins", {})["pin-api"]'
    marker_at = text.find(pin_marker)
    if marker_at < 0 or text.find(pin_marker, marker_at + 1) >= 0:
        raise SystemExit("b528-pin-record-anchor-not-unique")
    line_at = text.rfind("\n", 0, marker_at) + 1
    op_c_mirror = '''    state["storage"]["operators"]["opC"] = {\n        "enabled": True,\n        "capacity_bytes": 1000,\n        "used_bytes": 0,\n        "allocated_bytes": 0,\n    }\n'''
    text = text[:line_at] + op_c_mirror + text[line_at:]

    text = _replace_once(
        text,
        '"targets": ["opA"],',
        '"targets": ["opA", "opB"],',
        label="b528-establish-two-original-rf2-targets",
    )

    failed_at = text.find("    failed_pin = apply_storage(")
    if failed_at < 0:
        raise SystemExit("b528-failed-pin-anchor-missing")
    success_at = text.find("    apply_storage(", failed_at + 1)
    econ_at = text.find("    econ_rejected = False", success_at)
    if success_at < 0 or econ_at < 0 or econ_at <= success_at:
        raise SystemExit("b528-success-span-anchors-invalid")

    success_block = '''    replacement = (\n        failed_pin.get("reassignment", {}).get("replacement_operator_id")\n        if isinstance(failed_pin, dict)\n        else None\n    )\n    if replacement != "opC":\n        raise RuntimeError(f"storage_rehearsal_expected_opC_replacement:{replacement}")\n    for storage_nonce, operator_id in ((9, "opB"), (10, replacement)):\n        apply_storage(\n            state,\n            _env(\n                "IPFS_PIN_CONFIRM",\n                "SYSTEM",\n                storage_nonce,\n                {\n                    "pin_id": "pin-api",\n                    "cid": CID_A,\n                    "operator_id": operator_id,\n                    "ok": True,\n                    "retrieval_ok": True,\n                },\n                system=True,\n                parent="storage:pin-api",\n            ),\n        )\n'''
    text = text[:success_at] + success_block + text[econ_at:]
    path.write_text(text, encoding="utf-8")
    print("repaired B528 RF2 rehearsal using format-tolerant structural anchors")


def main() -> int:
    try:
        previous_main = _load_previous_main()
        previous_main.__globals__["_repair_b528_storage_rehearsal"] = (
            _repair_b528_storage_rehearsal_format_tolerant
        )
        rc = previous_main()
        return int(rc or 0)
    finally:
        TEMP_PREVIOUS.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
