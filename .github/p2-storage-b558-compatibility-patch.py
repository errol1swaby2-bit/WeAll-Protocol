from pathlib import Path

path = Path("Weall-Protocol/scripts/rehearse_multi_operator_storage_workers_v1_5.py")
text = path.read_text(encoding="utf-8")

start = "        replacement_written = workers[replacement].pin(cid, data)\n"
end = '            "batch": "558",\n'
start_at = text.find(start)
if start_at < 0:
    raise SystemExit("B558 replacement-confirmation block start marker missing")
end_at = text.find(end, start_at)
if end_at < 0:
    raise SystemExit("B558 return block end marker missing")

replacement = '''        secondary_written = workers[secondary].pin(cid, data)
        secondary_read = workers[secondary].cat(cid)
        secondary_confirm = apply_storage(
            state,
            _env(
                "IPFS_PIN_CONFIRM",
                "SYSTEM",
                3,
                {
                    "pin_id": pin_id,
                    "cid": cid,
                    "operator_id": secondary,
                    "ok": True,
                    "retrieval_ok": secondary_read == data,
                    "proof_hash": hashlib.sha256(secondary_read or b"").hexdigest(),
                },
                system=True,
                parent="storage",
            ),
        )
        replacement_written = workers[replacement].pin(cid, data)
        replacement_read = workers[replacement].cat(cid)
        ok_confirm = apply_storage(
            state,
            _env(
                "IPFS_PIN_CONFIRM",
                "SYSTEM",
                4,
                {
                    "pin_id": pin_id,
                    "cid": cid,
                    "operator_id": replacement,
                    "ok": True,
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
                not primary_written
                and secondary_written
                and secondary_read == data
                and replacement_written
                and replacement_read == data
                and final_pin.get("availability_status") == "available"
                and final_pin.get("durability_status") == "retrieval_confirmed"
            ),
'''
text = text[:start_at] + replacement + text[end_at:]

old = '            "failed_operator": primary,\n'
new = (
    '            "failed_operator": primary,\n'
    '            "surviving_operator": secondary,\n'
)
if text.count(old) != 1:
    raise SystemExit(f"B558 failed_operator field count: {text.count(old)}")
text = text.replace(old, new, 1)

old = '            "replacement_confirm_receipt": ok_confirm,\n'
new = (
    '            "surviving_replica_written": secondary_written,\n'
    '            "surviving_replica_read_ok": secondary_read == data,\n'
    '            "surviving_confirm_receipt": secondary_confirm,\n'
    '            "replacement_confirm_receipt": ok_confirm,\n'
)
if text.count(old) != 1:
    raise SystemExit(f"B558 replacement confirmation field count: {text.count(old)}")
text = text.replace(old, new, 1)

path.write_text(text, encoding="utf-8")
