#!/usr/bin/env python3
from __future__ import annotations

import runpy
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
PROJECT_ROOT = REPO_ROOT / "Weall-Protocol"
PREVIOUS_COMMIT = "48fe26319bbed428019c291e1576ff19b8360eb6"
PREVIOUS_REL = ".github/r20/r20_candidate_control.py"
PREVIOUS_BLOB = "54dc9f9eb10f1f59b4029424777e91ead58746de"
TEMP_PREVIOUS = HERE / ".r20_candidate_control_tx0801_rebind.py"


def _load_previous_main():
    actual_blob = subprocess.check_output(
        ["git", "rev-parse", f"{PREVIOUS_COMMIT}:{PREVIOUS_REL}"],
        cwd=REPO_ROOT,
        text=True,
    ).strip()
    if actual_blob != PREVIOUS_BLOB:
        raise SystemExit(
            f"known TX-0801 rebind controller blob drift: {actual_blob} != {PREVIOUS_BLOB}"
        )
    source = subprocess.check_output(
        ["git", "show", f"{PREVIOUS_COMMIT}:{PREVIOUS_REL}"],
        cwd=REPO_ROOT,
    )
    TEMP_PREVIOUS.write_bytes(source)
    namespace = runpy.run_path(str(TEMP_PREVIOUS), run_name="r20_candidate_control_tx0801_rebind")
    previous_main = namespace.get("main")
    if not callable(previous_main):
        raise SystemExit("known TX-0801 rebind controller has no callable main()")
    return previous_main


def _replace_once(text: str, old: str, new: str, *, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one source match, found {count}")
    return text.replace(old, new, 1)


def _repair_b528_storage_rehearsal() -> None:
    path = PROJECT_ROOT / "scripts" / "rehearse_api_driven_full_lifecycle_v1_5.py"
    text = path.read_text(encoding="utf-8")
    text = _replace_once(
        text,
        '    _enable_storage_responsibility(state, "opA", capacity=1000)\n    _enable_storage_responsibility(state, "opB", capacity=1000)\n',
        '    _enable_storage_responsibility(state, "opA", capacity=1000)\n    _enable_storage_responsibility(state, "opB", capacity=1000)\n    _enable_storage_responsibility(state, "opC", capacity=1000)\n',
        label="b528-add-third-storage-operator",
    )
    text = _replace_once(
        text,
        '''    state["storage"]["operators"]["opB"] = {\n        "enabled": True,\n        "capacity_bytes": 1000,\n        "used_bytes": 0,\n        "allocated_bytes": 0,\n    }\n    state["storage"].setdefault("pins", {})["pin-api"] = {\n''',
        '''    state["storage"]["operators"]["opB"] = {\n        "enabled": True,\n        "capacity_bytes": 1000,\n        "used_bytes": 0,\n        "allocated_bytes": 0,\n    }\n    state["storage"]["operators"]["opC"] = {\n        "enabled": True,\n        "capacity_bytes": 1000,\n        "used_bytes": 0,\n        "allocated_bytes": 0,\n    }\n    state["storage"].setdefault("pins", {})["pin-api"] = {\n''',
        label="b528-add-third-storage-mirror",
    )
    text = _replace_once(
        text,
        '        "targets": ["opA"],\n        "size_bytes": 10,\n        "replication_factor": 2,\n',
        '        "targets": ["opA", "opB"],\n        "size_bytes": 10,\n        "replication_factor": 2,\n',
        label="b528-establish-two-original-rf2-targets",
    )
    old_success = '''    apply_storage(\n        state,\n        _env(\n            "IPFS_PIN_CONFIRM",\n            "SYSTEM",\n            9,\n            {\n                "pin_id": "pin-api",\n                "cid": CID_A,\n                "operator_id": "opB",\n                "ok": True,\n                "retrieval_ok": True,\n            },\n            system=True,\n            parent="storage:pin-api",\n        ),\n    )\n'''
    new_success = '''    replacement = (\n        failed_pin.get("reassignment", {}).get("replacement_operator_id")\n        if isinstance(failed_pin, dict)\n        else None\n    )\n    if replacement != "opC":\n        raise RuntimeError(f"storage_rehearsal_expected_opC_replacement:{replacement}")\n    for storage_nonce, operator_id in ((9, "opB"), (10, replacement)):\n        apply_storage(\n            state,\n            _env(\n                "IPFS_PIN_CONFIRM",\n                "SYSTEM",\n                storage_nonce,\n                {\n                    "pin_id": "pin-api",\n                    "cid": CID_A,\n                    "operator_id": operator_id,\n                    "ok": True,\n                    "retrieval_ok": True,\n                },\n                system=True,\n                parent="storage:pin-api",\n            ),\n        )\n'''
    text = _replace_once(
        text,
        old_success,
        new_success,
        label="b528-prove-both-current-rf2-replicas",
    )
    path.write_text(text, encoding="utf-8")
    print("repaired B528 storage lifecycle rehearsal to prove two-current-replica retrieval")


def main() -> int:
    command = sys.argv[1] if len(sys.argv) > 1 else ""
    try:
        previous_main = _load_previous_main()
        rc = previous_main()
        if rc not in (None, 0):
            raise SystemExit(f"known TX-0801 rebind controller failed: {rc}")
        if command == "post-apply":
            _repair_b528_storage_rehearsal()
        return 0
    finally:
        TEMP_PREVIOUS.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
