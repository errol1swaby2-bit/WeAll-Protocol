#!/usr/bin/env python3
from __future__ import annotations

import runpy
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
PROJECT_ROOT = REPO_ROOT / "Weall-Protocol"
PREVIOUS_COMMIT = "06ca382577241cd0fbc0acfb5910fa0faa9c8f66"
PREVIOUS_REL = ".github/r20/r20_candidate_control.py"
PREVIOUS_BLOB = "a7f174d6a2b3268e220bfd63490123dd391d8b56"
TEMP_PREVIOUS = HERE / ".r20_candidate_control_b564.py"


def _load_previous_main():
    actual_blob = subprocess.check_output(
        ["git", "rev-parse", f"{PREVIOUS_COMMIT}:{PREVIOUS_REL}"],
        cwd=REPO_ROOT,
        text=True,
    ).strip()
    if actual_blob != PREVIOUS_BLOB:
        raise SystemExit(f"known B564 controller blob drift: {actual_blob} != {PREVIOUS_BLOB}")
    source = subprocess.check_output(
        ["git", "show", f"{PREVIOUS_COMMIT}:{PREVIOUS_REL}"],
        cwd=REPO_ROOT,
    )
    TEMP_PREVIOUS.write_bytes(source)
    namespace = runpy.run_path(str(TEMP_PREVIOUS), run_name="r20_candidate_control_b564")
    previous_main = namespace.get("main")
    if not callable(previous_main):
        raise SystemExit("known B564 controller has no callable main()")
    return previous_main


def _repair_b558_multi_operator_storage_rehearsal() -> None:
    path = PROJECT_ROOT / "scripts" / "rehearse_multi_operator_storage_workers_v1_5.py"
    text = path.read_text(encoding="utf-8")

    start = "        replacement_written = workers[replacement].pin(cid, data)\n"
    end = '        final_pin = state["storage"]["pins"][pin_id]\n'
    if text.count(start) != 1 or text.count(end) != 1:
        raise SystemExit(
            "b558-current-target-proof-span-not-unique:"
            f"start={text.count(start)} end={text.count(end)}"
        )
    start_at = text.index(start)
    end_at = text.index(end, start_at)
    if end_at <= start_at:
        raise SystemExit("b558-current-target-proof-span-invalid")

    replacement_block = '''        current_target_results: dict[str, dict[str, Any]] = {}\n        confirm_receipts: dict[str, dict[str, Any]] = {}\n        confirm_nonce = 3\n        for current_target in reassigned_targets:\n            written = workers[current_target].pin(cid, data)\n            read_back = workers[current_target].cat(cid)\n            read_ok = read_back == data\n            receipt = apply_storage(\n                state,\n                _env(\n                    "IPFS_PIN_CONFIRM",\n                    "SYSTEM",\n                    confirm_nonce,\n                    {\n                        "pin_id": pin_id,\n                        "cid": cid,\n                        "operator_id": current_target,\n                        "ok": written and read_ok,\n                        "retrieval_ok": read_ok,\n                        "proof_hash": hashlib.sha256(read_back or b"").hexdigest(),\n                    },\n                    system=True,\n                    parent="storage",\n                ),\n            )\n            current_target_results[current_target] = {\n                "written": written,\n                "read_ok": read_ok,\n            }\n            confirm_receipts[current_target] = receipt\n            confirm_nonce += 1\n\n        replacement_written = bool(current_target_results[replacement]["written"])\n        replacement_read_ok = bool(current_target_results[replacement]["read_ok"])\n        replacement_confirm = confirm_receipts[replacement]\n'''
    text = text[:start_at] + replacement_block + text[end_at:]

    old_ok = '''                and replacement_written\n                and replacement_read == data\n                and final_pin.get("availability_status") == "available"\n                and final_pin.get("durability_status") == "retrieval_confirmed"\n'''
    new_ok = '''                and replacement_written\n                and replacement_read_ok\n                and all(result["written"] for result in current_target_results.values())\n                and all(result["read_ok"] for result in current_target_results.values())\n                and len(current_target_results) == len(reassigned_targets) == 2\n                and final_pin.get("confirmed_target_count") == 2\n                and final_pin.get("availability_status") == "available"\n                and final_pin.get("durability_status") == "retrieval_confirmed"\n'''
    if text.count(old_ok) != 1:
        raise SystemExit(f"b558-ok-contract-anchor-count:{text.count(old_ok)}")
    text = text.replace(old_ok, new_ok, 1)

    old_result = '''            "replacement_confirm_receipt": ok_confirm,\n            "retrieval_confirmed": final_pin.get("durability_status") == "retrieval_confirmed",\n'''
    new_result = '''            "replacement_confirm_receipt": replacement_confirm,\n            "current_target_results": current_target_results,\n            "current_target_confirm_receipts": confirm_receipts,\n            "all_current_targets_retrieval_confirmed": all(\n                result["read_ok"] for result in current_target_results.values()\n            ),\n            "confirmed_target_count": final_pin.get("confirmed_target_count"),\n            "retrieval_confirmed": final_pin.get("durability_status") == "retrieval_confirmed",\n'''
    if text.count(old_result) != 1:
        raise SystemExit(f"b558-result-anchor-count:{text.count(old_result)}")
    text = text.replace(old_result, new_result, 1)

    path.write_text(text, encoding="utf-8")
    print("repaired batch 558 storage rehearsal to prove every current RF2 target")


def main() -> int:
    command = sys.argv[1] if len(sys.argv) > 1 else ""
    try:
        previous_main = _load_previous_main()
        rc = previous_main()
        if rc not in (None, 0):
            raise SystemExit(f"known B564 controller failed: {rc}")
        if command == "post-apply":
            _repair_b558_multi_operator_storage_rehearsal()
        return 0
    finally:
        TEMP_PREVIOUS.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
