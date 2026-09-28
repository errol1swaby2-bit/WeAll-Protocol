from pathlib import Path

public_path = Path("Weall-Protocol/scripts/rehearse_public_api_write_lifecycle_v1_5.py")
text = public_path.read_text(encoding="utf-8")
start = '''            simulated.setdefault("storage", {}).setdefault("operators", {})["op-a"] = {
'''
end = '''            apply_protocol(
                simulated,
'''
start_at = text.find(start)
if start_at < 0:
    raise SystemExit("public API storage fixture start marker missing")
end_at = text.find(end, start_at)
if end_at < 0:
    raise SystemExit("public API storage fixture end marker missing")

replacement = '''            simulated.setdefault("params", {})["ipfs_replication_factor"] = 2
            roles = (
                simulated.setdefault("roles", {})
                if isinstance(simulated.get("roles"), dict)
                else {}
            )
            simulated["roles"] = roles
            node_ops = (
                roles.setdefault("node_operators", {})
                if isinstance(roles.get("node_operators"), dict)
                else {}
            )
            roles["node_operators"] = node_ops
            active_set = (
                node_ops.setdefault("active_set", [])
                if isinstance(node_ops.get("active_set"), list)
                else []
            )
            node_ops["active_set"] = active_set
            by_id = (
                node_ops.setdefault("by_id", {})
                if isinstance(node_ops.get("by_id"), dict)
                else {}
            )
            node_ops["by_id"] = by_id
            accounts = (
                simulated.setdefault("accounts", {})
                if isinstance(simulated.get("accounts"), dict)
                else {}
            )
            simulated["accounts"] = accounts
            storage = (
                simulated.setdefault("storage", {})
                if isinstance(simulated.get("storage"), dict)
                else {}
            )
            simulated["storage"] = storage
            storage_ops = (
                storage.setdefault("operators", {})
                if isinstance(storage.get("operators"), dict)
                else {}
            )
            storage["operators"] = storage_ops

            for operator_id in ("op-a", "op-b", "op-c"):
                node_pubkey = f"{operator_id}-node"
                account = accounts.setdefault(operator_id, {})
                account["poh_tier"] = 2
                account["reputation_milli"] = 2000
                devices = (
                    account.setdefault("devices", {})
                    if isinstance(account.get("devices"), dict)
                    else {}
                )
                account["devices"] = devices
                device_by_id = (
                    devices.setdefault("by_id", {})
                    if isinstance(devices.get("by_id"), dict)
                    else {}
                )
                devices["by_id"] = device_by_id
                device_by_id[node_pubkey] = {
                    "device_type": "node",
                    "pubkey": node_pubkey,
                    "revoked": False,
                }
                if operator_id not in active_set:
                    active_set.append(operator_id)
                by_id[operator_id] = {
                    "account_id": operator_id,
                    "status": "active",
                    "active": True,
                    "enrolled": True,
                    "node_pubkey": node_pubkey,
                    "responsibilities": {
                        "storage": {
                            "opted_in": True,
                            "active": True,
                            "proof_status": "verified",
                            "declared_capacity_bytes": 1000,
                            "reserved_capacity_bytes": 1000,
                            "probed_capacity_bytes": 1000,
                            "proven_capacity_bytes": 1000,
                            "allocated_capacity_bytes": 0,
                            "used_capacity_bytes": 0,
                            "proof_expires_height": 10000,
                            "availability_score_milli": 1000,
                            "failed_challenge_count": 0,
                            "missed_challenge_count": 0,
                        }
                    },
                }
                storage_ops[operator_id] = {
                    "enabled": True,
                    "capacity_bytes": 1000,
                    "used_bytes": 0,
                    "allocated_bytes": 0,
                }

            apply_storage(
                simulated,
                _env(
                    "IPFS_PIN_REQUEST",
                    "@alice",
                    5,
                    {
                        "pin_id": "pin-api",
                        "cid": "QmYwAPJzv5CZsnAzt8auVTLuRtKfXVDRzi4PhN6dZm8D8h",
                        "size_bytes": 10,
                    },
                ),
            )
            pin = simulated["storage"]["pins"]["pin-api"]
            initial_targets = list(pin.get("targets") or [])
            if len(initial_targets) != 2:
                raise AssertionError(
                    f"expected two deterministic initial storage targets: {initial_targets!r}"
                )
            failed_operator = str(initial_targets[0])
            surviving_operator = str(initial_targets[1])

            failed = apply_storage(
                simulated,
                _env(
                    "IPFS_PIN_CONFIRM",
                    "SYSTEM",
                    5,
                    {
                        "pin_id": "pin-api",
                        "operator_id": failed_operator,
                        "ok": False,
                    },
                    system=True,
                    parent="pin-api",
                ),
            )
            reassignment = (
                failed.get("reassignment", {}) if isinstance(failed, dict) else {}
            )
            replacement_operator = str(
                reassignment.get("replacement_operator_id") or ""
            )
            if (
                not bool(reassignment.get("reassigned"))
                or not replacement_operator
                or replacement_operator in initial_targets
            ):
                raise AssertionError(f"unexpected storage reassignment: {reassignment!r}")

            apply_storage(
                simulated,
                _env(
                    "IPFS_PIN_CONFIRM",
                    "SYSTEM",
                    6,
                    {
                        "pin_id": "pin-api",
                        "operator_id": surviving_operator,
                        "ok": True,
                        "retrieval_ok": True,
                    },
                    system=True,
                    parent="pin-api",
                ),
            )
            apply_storage(
                simulated,
                _env(
                    "IPFS_PIN_CONFIRM",
                    "SYSTEM",
                    7,
                    {
                        "pin_id": "pin-api",
                        "operator_id": replacement_operator,
                        "ok": True,
                        "retrieval_ok": True,
                    },
                    system=True,
                    parent="pin-api",
                ),
            )
'''
text = text[:start_at] + replacement + text[end_at:]
public_path.write_text(text, encoding="utf-8")

test_path = Path("Weall-Protocol/tests/test_v2_spec_compiler.py")
test_text = test_path.read_text(encoding="utf-8")
old = '    assert runtime["count"] == 1122'
new = '    assert runtime["count"] == 1127'
if test_text.count(old) != 1:
    raise SystemExit(f"runtime inventory expectation count: {test_text.count(old)}")
test_path.write_text(test_text.replace(old, new, 1), encoding="utf-8")
