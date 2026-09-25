#!/usr/bin/env python3
from __future__ import annotations

import runpy
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
PROJECT_ROOT = REPO_ROOT / "Weall-Protocol"
PREVIOUS_COMMIT = "1a490893f20dd41f6bf17e4aafb857e723c33f34"
PREVIOUS_REL = ".github/r20/r20_candidate_control.py"
PREVIOUS_BLOB = "a2bc91bfed0e63c9cec53386d468121ddfdd5ce4"
TEMP_PREVIOUS = HERE / ".r20_candidate_control_rf2_b528.py"


def _load_previous_main():
    actual_blob = subprocess.check_output(
        ["git", "rev-parse", f"{PREVIOUS_COMMIT}:{PREVIOUS_REL}"],
        cwd=REPO_ROOT,
        text=True,
    ).strip()
    if actual_blob != PREVIOUS_BLOB:
        raise SystemExit(
            f"known B528 RF2 controller blob drift: {actual_blob} != {PREVIOUS_BLOB}"
        )
    source = subprocess.check_output(
        ["git", "show", f"{PREVIOUS_COMMIT}:{PREVIOUS_REL}"],
        cwd=REPO_ROOT,
    )
    TEMP_PREVIOUS.write_bytes(source)
    namespace = runpy.run_path(str(TEMP_PREVIOUS), run_name="r20_candidate_control_rf2_b528")
    previous_main = namespace.get("main")
    if not callable(previous_main):
        raise SystemExit("known B528 RF2 controller has no callable main()")
    return previous_main


def _repair_b564_storage_retry_rehearsal() -> None:
    path = PROJECT_ROOT / "scripts" / "rehearse_storage_worker_failure_retry_loop_v1_5.py"
    text = path.read_text(encoding="utf-8")

    start = "        replacement_attempts: list[bool] = []\n"
    end = '        final_pin = state["storage"]["pins"][pin_id]\n'
    if text.count(start) != 1 or text.count(end) != 1:
        raise SystemExit(
            "b564-current-target-proof-span-not-unique:"
            f"start={text.count(start)} end={text.count(end)}"
        )
    start_at = text.index(start)
    end_at = text.index(end, start_at)
    if end_at <= start_at:
        raise SystemExit("b564-current-target-proof-span-invalid")

    replacement = '''        current_target_results: dict[str, dict[str, Any]] = {}\n        confirm_receipts: dict[str, dict[str, Any]] = {}\n        confirm_nonce = 3\n        for current_target in reassigned_targets:\n            attempts: list[bool] = []\n            while True:\n                ok = workers[current_target].pin(cid, data)\n                attempts.append(ok)\n                if ok or len(attempts) >= 3:\n                    break\n            read_back = workers[current_target].cat(cid)\n            read_ok = read_back == data\n            receipt = apply_storage(\n                state,\n                _env(\n                    "IPFS_PIN_CONFIRM",\n                    "SYSTEM",\n                    confirm_nonce,\n                    {\n                        "pin_id": pin_id,\n                        "cid": cid,\n                        "operator_id": current_target,\n                        "ok": read_ok,\n                        "retrieval_ok": read_ok,\n                        "proof_hash": hashlib.sha256(read_back or b"").hexdigest(),\n                    },\n                    system=True,\n                    parent="storage",\n                ),\n            )\n            current_target_results[current_target] = {\n                "attempts": attempts,\n                "read_ok": read_ok,\n            }\n            confirm_receipts[current_target] = receipt\n            confirm_nonce += 1\n\n        replacement_attempts = current_target_results[replacement]["attempts"]\n        replacement_read_ok = bool(current_target_results[replacement]["read_ok"])\n        replacement_confirm = confirm_receipts[replacement]\n'''
    text = text[:start_at] + replacement + text[end_at:]

    old_ok = '''                and any(replacement_attempts)\n                and replacement_read == data\n                and final_pin.get("availability_status") == "available"\n'''
    new_ok = '''                and any(replacement_attempts)\n                and replacement_read_ok\n                and all(result["read_ok"] for result in current_target_results.values())\n                and len(current_target_results) == len(reassigned_targets) == 2\n                and final_pin.get("confirmed_target_count") == 2\n                and final_pin.get("availability_status") == "available"\n'''
    if text.count(old_ok) != 1:
        raise SystemExit(f"b564-ok-contract-anchor-count:{text.count(old_ok)}")
    text = text.replace(old_ok, new_ok, 1)

    old_result = '''            "replacement_confirm_receipt": replacement_confirm,\n            "reassignment_recorded": replacement in reassigned_targets,\n'''
    new_result = '''            "replacement_confirm_receipt": replacement_confirm,\n            "current_target_results": current_target_results,\n            "current_target_confirm_receipts": confirm_receipts,\n            "all_current_targets_retrieval_confirmed": all(\n                result["read_ok"] for result in current_target_results.values()\n            ),\n            "reassignment_recorded": replacement in reassigned_targets,\n'''
    if text.count(old_result) != 1:
        raise SystemExit(f"b564-result-anchor-count:{text.count(old_result)}")
    text = text.replace(old_result, new_result, 1)

    path.write_text(text, encoding="utf-8")
    print("repaired batch 564 retry rehearsal to prove every current RF2 target")


def main() -> int:
    command = sys.argv[1] if len(sys.argv) > 1 else ""
    try:
        previous_main = _load_previous_main()
        rc = previous_main()
        if rc not in (None, 0):
            raise SystemExit(f"known B528 RF2 controller failed: {rc}")
        if command == "post-apply":
            _repair_b564_storage_retry_rehearsal()
        return 0
    finally:
        TEMP_PREVIOUS.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
