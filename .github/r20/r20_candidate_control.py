#!/usr/bin/env python3
from __future__ import annotations

import runpy
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
PROJECT_ROOT = REPO_ROOT / "Weall-Protocol"
PREVIOUS_COMMIT = "14d7b35d8dbd9ecf30619cf4e51c7bf408dbdb75"
PREVIOUS_REL = ".github/r20/r20_candidate_control.py"
PREVIOUS_BLOB = "00d26aa84bbcd07ad13fcc0f336cdd8ac62da73a"
TEMP_PREVIOUS = HERE / ".r20_candidate_control_b558.py"


def _load_previous_main():
    actual_blob = subprocess.check_output(
        ["git", "rev-parse", f"{PREVIOUS_COMMIT}:{PREVIOUS_REL}"],
        cwd=REPO_ROOT,
        text=True,
    ).strip()
    if actual_blob != PREVIOUS_BLOB:
        raise SystemExit(f"known B558 controller blob drift: {actual_blob} != {PREVIOUS_BLOB}")
    source = subprocess.check_output(
        ["git", "show", f"{PREVIOUS_COMMIT}:{PREVIOUS_REL}"],
        cwd=REPO_ROOT,
    )
    TEMP_PREVIOUS.write_bytes(source)
    namespace = runpy.run_path(str(TEMP_PREVIOUS), run_name="r20_candidate_control_b558")
    previous_main = namespace.get("main")
    if not callable(previous_main):
        raise SystemExit("known B558 controller has no callable main()")
    return previous_main


def _repair_b569_multiprocess_storage_rehearsal() -> None:
    path = PROJECT_ROOT / "scripts" / "rehearse_multiprocess_ipfs_operator_durability_v1_5.py"
    text = path.read_text(encoding="utf-8")

    start = '            input_queuees[replacement].put({"op": "add_pin", "cid": cid, "data_hex": data.hex()})\n'
    end = '            final_pin = state["storage"]["pins"][pin_id]\n'
    if text.count(start) != 1 or text.count(end) != 1:
        raise SystemExit(
            "b569-current-target-process-proof-span-not-unique:"
            f"start={text.count(start)} end={text.count(end)}"
        )
    start_at = text.index(start)
    end_at = text.index(end, start_at)
    if end_at <= start_at:
        raise SystemExit("b569-current-target-process-proof-span-invalid")

    proof_block = '''            current_target_results: dict[str, dict[str, Any]] = {}\n            confirm_receipts: dict[str, dict[str, Any]] = {}\n            confirm_nonce = 3\n            for current_target in reassigned:\n                if not procs[current_target].is_alive():\n                    raise RuntimeError(f"current_storage_target_process_not_alive:{current_target}")\n                input_queuees[current_target].put(\n                    {"op": "add_pin", "cid": cid, "data_hex": data.hex()}\n                )\n                add_result = _recv(tx_queue)\n                if add_result.get("operator_id") != current_target or add_result.get("op") != "add_pin":\n                    raise RuntimeError(\n                        f"unexpected_storage_add_result:{current_target}:{add_result}"\n                    )\n                input_queuees[current_target].put({"op": "cat", "cid": cid})\n                cat_result = _recv(tx_queue)\n                if cat_result.get("operator_id") != current_target or cat_result.get("op") != "cat":\n                    raise RuntimeError(\n                        f"unexpected_storage_cat_result:{current_target}:{cat_result}"\n                    )\n                read_ok = cat_result.get("data_hex") == data.hex()\n                receipt = apply_storage(\n                    state,\n                    _env(\n                        "IPFS_PIN_CONFIRM",\n                        "SYSTEM",\n                        confirm_nonce,\n                        {\n                            "pin_id": pin_id,\n                            "cid": cid,\n                            "operator_id": current_target,\n                            "ok": bool(add_result.get("ok")) and read_ok,\n                            "retrieval_ok": read_ok,\n                            "proof_hash": cat_result.get("sha256"),\n                        },\n                        system=True,\n                        parent="storage",\n                    ),\n                )\n                current_target_results[current_target] = {\n                    "add_result": add_result,\n                    "cat_result": {k: v for k, v in cat_result.items() if k != "data_hex"},\n                    "read_ok": read_ok,\n                }\n                confirm_receipts[current_target] = receipt\n                confirm_nonce += 1\n\n            replacement_result = current_target_results[replacement]\n            replacement_confirm = confirm_receipts[replacement]\n'''
    text = text[:start_at] + proof_block + text[end_at:]

    old_ok = '''                    add_res.get("ok")\n                    and cat_res.get("data_hex") == data.hex()\n                    and final_pin.get("availability_status") == "available"\n'''
    new_ok = '''                    all(\n                        result["add_result"].get("ok")\n                        for result in current_target_results.values()\n                    )\n                    and all(result["read_ok"] for result in current_target_results.values())\n                    and len(current_target_results) == len(reassigned) == 2\n                    and final_pin.get("confirmed_target_count") == 2\n                    and final_pin.get("availability_status") == "available"\n                    and final_pin.get("durability_status") == "retrieval_confirmed"\n'''
    if text.count(old_ok) != 1:
        raise SystemExit(f"b569-ok-contract-anchor-count:{text.count(old_ok)}")
    text = text.replace(old_ok, new_ok, 1)

    old_result = '''                "replacement_add_result": add_res,\n                "replacement_cat_result": {k: v for k, v in cat_res.items() if k != "data_hex"},\n                "confirm_receipt": confirm,\n                "retrieval_confirmed": final_pin.get("durability_status") == "retrieval_confirmed",\n'''
    new_result = '''                "replacement_add_result": replacement_result["add_result"],\n                "replacement_cat_result": replacement_result["cat_result"],\n                "confirm_receipt": replacement_confirm,\n                "current_target_results": current_target_results,\n                "current_target_confirm_receipts": confirm_receipts,\n                "all_current_targets_retrieval_confirmed": all(\n                    result["read_ok"] for result in current_target_results.values()\n                ),\n                "confirmed_target_count": final_pin.get("confirmed_target_count"),\n                "retrieval_confirmed": final_pin.get("durability_status") == "retrieval_confirmed",\n'''
    if text.count(old_result) != 1:
        raise SystemExit(f"b569-result-contract-anchor-count:{text.count(old_result)}")
    text = text.replace(old_result, new_result, 1)

    path.write_text(text, encoding="utf-8")
    print("repaired batch 569 multiprocess storage rehearsal to prove every live RF2 target")


def _repair_storage_lifecycle_regressions() -> None:
    storage_path = PROJECT_ROOT / "src" / "weall" / "runtime" / "apply" / "storage.py"
    storage = storage_path.read_text(encoding="utf-8")

    guard_anchor = "    if operator_id not in targets:\n        raise StorageApplyError(\n"
    if storage.count(guard_anchor) != 1:
        raise SystemExit(
            "storage current-target structural guard mismatch: "
            f"{storage.count(guard_anchor)}"
        )
    replacement = '''    request_ok = payload.get("ok")
    request_ok_bool = bool(request_ok) if isinstance(request_ok, (bool, int)) else False
    if "ok" not in payload:
        request_ok_bool = True

    if operator_id not in targets:
        prior_non_success = any(
            isinstance(item, dict)
            and str(item.get("pin_id") or "").strip() == pin_id
            and str(item.get("operator_id") or "").strip() == operator_id
            and not bool(item.get("ok"))
            for item in s.get("pin_confirms", [])
        )
        if request_ok_bool or not prior_non_success:
            raise StorageApplyError(
'''
    storage = storage.replace(guard_anchor, replacement, 1)
    compile(storage, str(storage_path), "exec")
    storage_path.write_text(storage, encoding="utf-8")

    test_path = PROJECT_ROOT / "tests" / "test_storage_pin_lifecycle_adversarial.py"
    tests = test_path.read_text(encoding="utf-8")
    old_expect = 'pytest.raises(StorageApplyError, match="operator_not_current_pin_target")'
    if tests.count(old_expect) != 3:
        raise SystemExit(
            "storage adversarial exception expectation count mismatch: "
            f"{tests.count(old_expect)}"
        )
    tests = tests.replace(
        old_expect,
        'pytest.raises(ApplyError, match="operator_not_current_pin_target")',
    )
    if "from weall.runtime.errors import ApplyError\n" not in tests:
        anchor = "import pytest\n"
        if tests.count(anchor) != 1:
            raise SystemExit(
                "storage adversarial pytest import anchor mismatch: "
                f"{tests.count(anchor)}"
            )
        tests = tests.replace(anchor, anchor + "\nfrom weall.runtime.errors import ApplyError\n", 1)

    standalone = "from weall.runtime.apply.storage import StorageApplyError\n"
    if standalone in tests:
        tests = tests.replace(standalone, "", 1)
    mixed = "from weall.runtime.apply.storage import StorageApplyError, "
    if mixed in tests:
        tests = tests.replace(mixed, "from weall.runtime.apply.storage import ", 1)

    compile(tests, str(test_path), "exec")
    test_path.write_text(tests, encoding="utf-8")
    print("repaired storage lifecycle idempotence and public exception boundary")


def main() -> int:
    command = sys.argv[1] if len(sys.argv) > 1 else ""
    try:
        previous_main = _load_previous_main()
        rc = previous_main()
        if rc not in (None, 0):
            raise SystemExit(f"known B558 controller failed: {rc}")
        if command == "post-apply":
            _repair_b569_multiprocess_storage_rehearsal()
            _repair_storage_lifecycle_regressions()
        return 0
    finally:
        TEMP_PREVIOUS.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
