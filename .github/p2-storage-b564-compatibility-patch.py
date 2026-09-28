from pathlib import Path

path = Path("Weall-Protocol/scripts/rehearse_storage_worker_failure_retry_loop_v1_5.py")
text = path.read_text(encoding="utf-8")

start = "        replacement_attempts: list[bool] = []\n"
end = '            "batch": "564",\n'
start_at = text.find(start)
if start_at < 0:
    raise SystemExit("B564 replacement retry block start marker missing")
end_at = text.find(end, start_at)
if end_at < 0:
    raise SystemExit("B564 return block end marker missing")

replacement = '''        surviving = next(op for op in initial_targets if op != failing)
        surviving_attempts: list[bool] = []
        while True:
            ok = workers[surviving].pin(cid, data)
            surviving_attempts.append(ok)
            if ok or len(surviving_attempts) >= 3:
                break
        surviving_read = workers[surviving].cat(cid)
        surviving_confirm = apply_storage(
            state,
            _env(
                "IPFS_PIN_CONFIRM",
                "SYSTEM",
                3,
                {
                    "pin_id": pin_id,
                    "cid": cid,
                    "operator_id": surviving,
                    "ok": bool(surviving_read == data),
                    "retrieval_ok": surviving_read == data,
                    "proof_hash": hashlib.sha256(surviving_read or b"").hexdigest(),
                },
                system=True,
                parent="storage",
            ),
        )
        replacement_attempts: list[bool] = []
        while True:
            ok = workers[replacement].pin(cid, data)
            replacement_attempts.append(ok)
            if ok or len(replacement_attempts) >= 3:
                break
        replacement_read = workers[replacement].cat(cid)
        replacement_confirm = apply_storage(
            state,
            _env(
                "IPFS_PIN_CONFIRM",
                "SYSTEM",
                4,
                {
                    "pin_id": pin_id,
                    "cid": cid,
                    "operator_id": replacement,
                    "ok": bool(replacement_read == data),
                    "retrieval_ok": replacement_read == data,
                    "proof_hash": hashlib.sha256(replacement_read or b"").hexdigest(),
                },
                system=True,
                parent="storage",
            ),
        )
        final_pin = state["storage"]["pins"][pin_id]
        return {
            "ok": bool(
                local_retry_results == [False, False]
                and any(surviving_attempts)
                and surviving_read == data
                and any(replacement_attempts)
                and replacement_read == data
                and final_pin.get("availability_status") == "available"
                and final_pin.get("durability_status") == "retrieval_confirmed"
            ),
'''
text = text[:start_at] + replacement + text[end_at:]

old = '            "failed_operator": failing,\n'
new = (
    '            "failed_operator": failing,\n'
    '            "surviving_operator": surviving,\n'
    '            "surviving_attempt_results": surviving_attempts,\n'
    '            "surviving_confirm_receipt": surviving_confirm,\n'
)
if text.count(old) != 1:
    raise SystemExit(f"B564 failed_operator field count: {text.count(old)}")
text = text.replace(old, new, 1)

path.write_text(text, encoding="utf-8")
